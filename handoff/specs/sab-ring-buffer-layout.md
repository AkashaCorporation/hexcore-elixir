# SharedArrayBuffer Zero-Copy Ring Buffer — Binary Layout Spec

## Purpose

Phase 4 of HexCore Elixir (Interceptor + Stalker) needs a **zero-copy event pipeline** from the Unicorn CODE hook callback (which runs on the emulation worker thread) to the JavaScript agent runtime (which runs on the Node.js main thread). Using ThreadSafeFunction (TSFN) for every hook fire is too slow and lossy — the reference implementation measured ~35% delivery rate under load and a ~2–3× throughput regression versus the SAB path.

This spec defines the binary layout of the ring buffer that Elixir's Stalker writes to from C++ and reads from in TypeScript. It is derived from `extensions/hexcore-common/src/sharedRingBuffer.ts` in the HexCore monorepo.

## Design goals

1. **Single-producer, single-consumer (SPSC)** — the C++ emulation thread is the only writer, the JS main thread is the only reader
2. **Lock-free** — no mutexes, no atomics beyond head/tail pointers
3. **Zero-allocation per event** — fixed-size records, bump-advance head pointer
4. **Drop-nothing** — if the buffer fills, the writer backs off (the hook becomes a no-op for that instruction) rather than blocking the emulation worker
5. **Binary-compatible across languages** — the C++ writer and TS reader must agree on byte layout exactly

## The ring buffer header

A SharedArrayBuffer starts with a 64-byte aligned header, then the record area:

```
Offset  Size  Field
------  ----  -----------------------------------------------------------
0x00    8     magic           — ASCII 'ELXRING\0' (0x474E495258584C45)
0x08    4     version         — uint32, current value = 1
0x0C    4     record_size     — uint32, bytes per record (typically 32 or 40)
0x10    4     capacity        — uint32, total number of records
0x14    4     _padding        — keep alignment
0x18    8     head            — uint64, writer position (monotonically increasing)
0x20    8     tail            — uint64, reader position (monotonically increasing)
0x28    4     drop_count      — uint32, number of records dropped due to backpressure
0x2C    4     overflow_count  — uint32, writer back-off count
0x30    16    _reserved
0x40+   ...   record area (capacity × record_size bytes)
```

- All multi-byte fields are **little-endian**
- `head` and `tail` are **monotonically increasing absolute indices**, not modulo-capacity. Compute the slot via `slot = index % capacity`. This avoids the classic "head == tail means both full and empty" ambiguity.
- `head` is written ONLY by the producer; `tail` is written ONLY by the consumer
- Both are read by both sides, but the producer only CARES about the difference `head - tail` (to detect full), and the consumer only cares about `head - tail` (to detect empty)

## Record format (32 bytes — CODE hook)

For a basic-block / instruction trace event, the 32-byte record is:

```
Offset  Size  Field
------  ----  -------------------------------
0x00    8     pc                — instruction pointer at the time of the hook
0x08    4     instr_size        — size of the current instruction in bytes
0x0C    4     flags             — bitfield (see below)
0x10    8     aux0              — auxiliary payload slot 0 (e.g. rax snapshot, or target of a call)
0x18    8     aux1              — auxiliary payload slot 1 (e.g. rsp, or source of a return)
```

### Flags bitfield (32 bits)

```
Bit 0: is_block_start     (1 if this record is the first instruction of a basic block)
Bit 1: is_call            (the current instruction is a CALL)
Bit 2: is_ret             (the current instruction is a RET)
Bit 3: is_branch          (the current instruction is a conditional or unconditional branch)
Bit 4: is_sysenter        (the current instruction is SYSCALL/SYSENTER/INT)
Bit 5: is_sab_hooked      (this event was captured via the fast SAB path, not TSFN fallback)
Bits 6–15: arch_flags     (architecture-specific flags)
Bits 16–31: reserved
```

## Record format (40 bytes — Interceptor onEnter event)

For Interceptor `attach(target, { onEnter })` events, a larger 40-byte record carries more state:

```
Offset  Size  Field
------  ----  -------------------------------
0x00    8     pc                — function entry point (= target passed to attach)
0x08    4     event_type        — 0=onEnter, 1=onLeave
0x0C    4     flags             — same bitfield as 32-byte record
0x10    8     thread_id         — unique ID of the emulator thread
0x18    8     timestamp         — host monotonic clock (ns since emulation start)
0x20    8     context_ptr       — pointer into the record area to a 128-byte CPU context snapshot
```

The `context_ptr` points at the next record slot (or slots) which contain a full register dump. The reader knows to advance past both the 40-byte Interceptor record and the N record slots containing the context.

## Writer protocol (C++ / Rust side)

```
int64_t head = load_relaxed(&header->head);
int64_t tail = load_acquire(&header->tail);

// Backpressure check: is the buffer full?
if ((head - tail) >= header->capacity) {
    atomic_fetch_add_relaxed(&header->overflow_count, 1);
    return;  // drop this event, do not block
}

// Write into the record area
uint64_t slot = head % header->capacity;
uint8_t* record = header_base + 0x40 + (slot * header->record_size);
write_record_fields(record, pc, instr_size, flags, aux0, aux1);

// Release the record: the store to head synchronizes-with the reader's acquire load
store_release(&header->head, head + 1);
```

The `store_release` on `head` is the critical memory ordering: it ensures that all the record field writes above it become visible to the reader BEFORE the reader sees the new head value. Without this, the reader could observe `head = N+1` but read stale zeros from slot N because the record writes were still buffered in the CPU store queue.

### Unicorn hook signature (C++)

The hook callback registered with `uc_hook_add(UC_HOOK_CODE, ...)` should be tiny and self-contained. No N-API calls. No heap allocation. Example shape:

```cpp
static void ElixirStalkerCodeHook(uc_engine* uc, uint64_t pc, uint32_t size, void* user_data) {
    auto* ring = reinterpret_cast<SabRing*>(user_data);
    
    // Read head and tail
    int64_t head = ring->header->head.load(std::memory_order_relaxed);
    int64_t tail = ring->header->tail.load(std::memory_order_acquire);
    
    if (head - tail >= ring->header->capacity) {
        ring->header->overflow_count.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    
    // Read aux registers quickly without taking the Unicorn lock
    // (The CODE hook runs WITH the lock held, so uc_reg_read is safe here.)
    uint64_t rax, rsp;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    
    // Write the record
    uint64_t slot = head % ring->header->capacity;
    ElixirRecord* rec = &ring->records[slot];
    rec->pc = pc;
    rec->instr_size = size;
    rec->flags = 0;  // TODO: compute from instruction classification
    rec->aux0 = rax;
    rec->aux1 = rsp;
    
    // Release the slot to the reader
    ring->header->head.store(head + 1, std::memory_order_release);
}
```

## Reader protocol (TypeScript / JS side)

```typescript
class ElixirSabReader {
    private sab: SharedArrayBuffer;
    private header: DataView;       // view over the first 0x40 bytes
    private records: DataView;      // view over the record area
    private recordSize: number;
    private capacity: number;
    
    constructor(sab: SharedArrayBuffer) {
        this.sab = sab;
        this.header = new DataView(sab, 0, 0x40);
        
        // Verify magic
        const magicLo = this.header.getUint32(0, true);
        const magicHi = this.header.getUint32(4, true);
        if (magicLo !== 0x58584C45 || magicHi !== 0x474E4952) { // 'ELXR' + 'RING'
            throw new Error('Invalid ELXRING header');
        }
        
        this.recordSize = this.header.getUint32(0x0C, true);
        this.capacity = this.header.getUint32(0x10, true);
        this.records = new DataView(sab, 0x40, this.recordSize * this.capacity);
    }
    
    * drain(): Generator<ElixirRecord> {
        // Use Int32Array for Atomics access (SAB requires it)
        const headArr = new BigInt64Array(this.sab, 0x18, 1);
        const tailArr = new BigInt64Array(this.sab, 0x20, 1);
        
        let tail = Atomics.load(tailArr, 0);
        const head = Atomics.load(headArr, 0);
        
        while (tail < head) {
            const slot = Number(tail % BigInt(this.capacity));
            const offset = slot * this.recordSize;
            
            yield {
                pc:          this.records.getBigUint64(offset + 0x00, true),
                instrSize:   this.records.getUint32(offset + 0x08, true),
                flags:       this.records.getUint32(offset + 0x0C, true),
                aux0:        this.records.getBigUint64(offset + 0x10, true),
                aux1:        this.records.getBigUint64(offset + 0x18, true),
            };
            
            tail++;
        }
        
        // Publish new tail
        Atomics.store(tailArr, 0, tail);
    }
}
```

The reader uses `Atomics.load` and `Atomics.store` on the head/tail indices. The record body reads do not need Atomics because the release/acquire ordering on head guarantees visibility.

## Performance targets

The reference implementation measured:
- **Throughput**: 1.34× improvement vs legacy TSFN path
- **Delivery rate**: 100% (no drops) up to the buffer capacity
- **Legacy TSFN**: ~35% delivery, drops at ~500k events/sec
- **SAB**: 0% drops, sustained >500k events/sec on the Stalker follow benchmark

For Elixir's Phase 4 gate, the Stalker follow benchmark must:
- Process ≥500k events/sec with zero drops
- Match the 1.34× throughput multiple or better
- Round-trip an event (C++ write → JS read → JS write tail) in <2 µs median

## Buffer sizing

A typical Elixir emulation run:
- Capacity: 65,536 records (2^16)
- Record size: 32 bytes
- Total SAB size: 0x40 (header) + 65,536 × 32 = 2,097,216 bytes (~2 MB)

This comfortably handles bursts of ~65k events while the reader catches up on the main thread's next event loop tick (~16 ms on Node.js). At 500k events/sec, 65k records is ~130 ms of headroom — well beyond the 16 ms event loop cadence.

## Integration with Unicorn's CODE hook

The split-path architecture:

1. `uc_hook_add(UC_HOOK_CODE, ElixirStalkerCodeHook, ring_ptr, start, end)` — installs on every instruction in the configured range
2. When the hook fires, the C++ handler checks:
   - Is this address on the "watched list" (breakpoints, API stubs, manual Interceptor targets)?
   - If YES: route through the legacy TSFN path for full JS callback semantics (onEnter/onLeave can call `emulator.stop()`, etc.)
   - If NO: write a 32-byte record to the SAB and return immediately. No TSFN, no allocation, no lock.
3. The reader drains the SAB from JS during the Node.js event loop tick, processes events, and calls user agent callbacks

This preserves the `emulator.stop()` semantics for the slow path while getting SAB speed for the fast path.

## Gotchas

1. **Integer overflow on head/tail**: at 10 MHz event rate, 64-bit head/tail wraps after ~58,000 years. Don't worry about it.
2. **False sharing**: the `head` and `tail` fields are in the same cache line (0x18 and 0x20). This causes cache-line ping-pong between producer and consumer. **Fix**: pad `tail` to its own 64-byte cache line. Adjust layout if benchmark shows contention.
3. **SharedArrayBuffer requires COOP/COEP headers on web**: not relevant for Node.js, but document it for any future browser port
4. **`Atomics.load` is not free**: it compiles to a memory barrier. Batch drains — don't load head once per record read

## Reference origin

Binary layout derived from `extensions/hexcore-common/src/sharedRingBuffer.ts` in the HexCore monorepo. The reference implementation is in TypeScript with Atomics; Elixir's C++ implementation must produce a byte-identical layout so that Elixir's agent runtime can share a SAB with any consumer that follows this spec — including, eventually, the main HexCore IDE's existing tools that already speak this format.

The SharedRingBuffer was shipped in Wave 2 Phase 1–4 (early April 2026) as the zero-copy IPC foundation for HexCore's emulation pipeline. Phase 5 (moving the actual CPU state block into a typed SAB for 10M+ insns/sec) is deferred to HexCore v4.0.0 and is not required for Elixir Phase 4 gate.
