# Fix: `get_api_calls()` retorna stub — implementar coleção real

**Status**: TODO declarado no código (`crates/hexcore-elixir/src/lib.rs:258`).
**Prioridade**: P0 — bloqueia análise dinâmica real (emulateHeadless virou só contador).
**Escopo**: trabalho limitado às 3 camadas Elixir (C++ engine → C FFI → Rust NAPI). Não toca no main repo vscode-main.

## Sintoma

Pipeline Azoth rodando notepad.exe retorna:

```json
{
  "apiCallCount": 10,
  "apiCalls": [{ "address": "0x0", "name": "api_log_count_10", "returnValue": "0xa" }],
  "apiCallsTotal": 1
}
```

Engine viu 10 calls (`apiCallCount: 10`), mas expõe 1 stub literal `api_log_count_10`. Os 10 nomes/endereços/retornos reais nunca chegam ao wrapper TS.

O legacy debugger produz `{functionName, library, arguments[], returnValue, pcAddress, timestamp}` por call — esse é o shape que o IDE consome em downstream.

## Raiz — 3 camadas, 3 arquivos

### 1. C++ — dado existe mas é raso

`engine/include/elixir/win32_hooks.h:53`

```cpp
std::vector<std::pair<std::string, uint64_t>> api_log_;  // {name, retval} — falta addr + args
```

Accessor já existe em `:77`:

```cpp
const std::vector<std::pair<std::string, uint64_t>>& api_log() const { return api_log_; }
```

**O que falta**: enriquecer o record com `pc_address` (endereço do stub), `args[]` (pelo menos os primeiros 4-8 conforme x64 Microsoft CC — rcx/rdx/r8/r9 + shadow), e opcionalmente `module` (DLL da IAT lookup). Sugestão de struct:

```cpp
struct ApiLogEntry {
    std::string name;
    std::string module;   // IAT origin DLL
    uint64_t pc_address;  // stub addr where hook fired
    std::vector<uint64_t> args;
    uint64_t return_value;
    uint64_t timestamp_ns;  // optional, monotonic clock
};

std::vector<ApiLogEntry> api_log_;
```

Os pontos onde `api_log_.emplace_back(...)` hoje precisam virar o novo shape. Todo handler em `engine/src/os/windows/api_hooks.cpp` já lê args via `read_args(N)` — é só capturar o vector antes do `do_return`.

### 2. FFI C — expor iteração ou snapshot

`engine/include/elixir/elixir.h:98` hoje tem:

```c
ELIXIR_EXPORT uint64_t elixir_api_log_count(ElixirContext* ctx);
```

Adicionar API pra transferir o log cross-FFI. Duas opções razoáveis:

**(A) — Snapshot como JSON/MessagePack** (mais simples, uma alocação)

```c
// Serializa api_log_ em JSON UTF-8 alocado pelo engine.
// Caller deve liberar com elixir_api_log_free().
ELIXIR_EXPORT const char* elixir_api_log_to_json(ElixirContext* ctx, size_t* out_len);
ELIXIR_EXPORT void elixir_api_log_free(const char* ptr);
```

Rust lê o blob e desserializa com `serde_json::from_slice::<Vec<ApiLogEntry>>`. Mesma malloc-dance que o `snapshot_save`/`snapshot_free` já usa.

**(B) — Iteração por índice** (mais pedaços, zero heap no engine)

```c
ELIXIR_EXPORT int elixir_api_log_entry(
    ElixirContext* ctx,
    size_t index,
    char* name_buf, size_t name_buf_len,
    char* module_buf, size_t module_buf_len,
    uint64_t* out_pc, uint64_t* out_retval,
    uint64_t* args_out, size_t args_cap, size_t* args_len
);
```

Rust itera `0..api_log_count()`. Mais chatinho mas evita alocação transitória.

**Recomendado**: (A). O log vai pra IPC NAPI → Node → JSON output arquivo. Serializar uma vez no engine economiza uma passada de conversão.

### 3. Rust NAPI wrapper — substituir o stub

`crates/hexcore-elixir/src/lib.rs:258-272`

```rust
/// Get API call log (returns count for now as summary).
/// TODO: Return detailed per-call records when API is available.
#[napi]
pub fn get_api_calls(&mut self) -> Result<Vec<JsApiCall>> {
    self.check_disposed()?;
    let inner = self.inner.as_ref().unwrap();
    let count = inner.api_log_count();

    // Return a single summary entry for now
    // Future: iterate actual API call records
    Ok(vec![JsApiCall {
        name: format!("api_log_count_{}", count),
        address: BigInt::from(0i64),
        return_value: BigInt::from(count as i64),
    }])
}
```

Com a opção (A) fica:

```rust
#[napi]
pub fn get_api_calls(&mut self) -> Result<Vec<JsApiCall>> {
    self.check_disposed()?;
    let inner = self.inner.as_ref().unwrap();
    let entries = inner.api_log_snapshot()
        .map_err(|e| Error::from_reason(format!("api_log_snapshot: {}", e)))?;
    Ok(entries.into_iter().map(JsApiCall::from).collect())
}
```

E estender `JsApiCall` em `crates/hexcore-elixir/src/lib.rs` (mesmo arquivo, topo do módulo) pra bater com o shape consumido pelo wrapper TS (`extensions/hexcore-elixir/src/extension.ts:19`):

```rust
#[napi(object)]
pub struct JsApiCall {
    pub name: String,
    pub module: String,
    pub address: BigInt,        // pc
    pub return_value: BigInt,
    pub arguments: Vec<BigInt>, // <= requires Vec<BigInt>, NAPI-RS supports this
}
```

O wrapper TS em `extension.ts:20-25` já espera esse shape (`arguments: bigint[]`), então zero mudança no main repo uma vez que o engine preencha.

## Arquivos a tocar (ordenado)

1. `engine/include/elixir/win32_hooks.h` — novo `ApiLogEntry` struct + trocar `std::vector<pair<...>>` por `std::vector<ApiLogEntry>`
2. `engine/src/os/windows/api_hooks.cpp` — atualizar todos os `api_log_.emplace_back(name, retval)` pra capturar pc/args/module
3. `engine/include/elixir/elixir.h` — declarar `elixir_api_log_to_json` + `elixir_api_log_free`
4. `engine/src/core/engine.cpp` — implementar as duas novas FFI functions (malloc + serialize)
5. `crates/elixir-core/src/ffi.rs` — `extern "C"` bindings das novas FFI
6. `crates/elixir-core/src/emulator.rs` — método `api_log_snapshot() -> ElixirResult<Vec<ApiLogEntry>>`
7. `crates/hexcore-elixir/src/lib.rs:260` — trocar o stub + estender `JsApiCall`

Rebuild: `npm run build` no repo Elixir → copia `.node` pra `extensions/hexcore-elixir/` no main repo (ou espera o postinstall hook pegar da Release).

## Teste de validação

Tem 3 parity gates em `crates/elixir-core/tests/parity_gate_g*.rs` que já chamam `api_log_count()`. Adiciona um novo:

```rust
// parity_gate_api_log_detail.rs
#[test]
fn api_log_returns_detailed_entries() {
    let emu = /* carrega ashaka v3 ou notepad x64 */;
    let count = emu.api_log_count();
    let entries = emu.api_log_snapshot().unwrap();
    assert_eq!(entries.len() as u64, count);
    assert!(entries.iter().any(|e| e.name == "GetSystemTimeAsFileTime"));
    assert!(entries.iter().all(|e| e.pc_address != 0));
    assert!(entries.iter().all(|e| !e.name.starts_with("api_log_count_")));  // regression guard
}
```

## Pra depois (não-blocking)

- `timestamp_ns` via `std::chrono::steady_clock::now()` — bate com o `timestamp` que o legacy debugger produz
- Módulo source via lookup reverso no IAT (já temos `stub_to_import_` no `Win32HookTable`)
- Snapshot threshold: se `api_log_.size() > 100k`, serialize direto pra arquivo no engine (mmap) e retorna path, não JSON em memória
