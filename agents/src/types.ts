// Elixir Agent — Type Definitions

/** Context passed to onEnter/onLeave callbacks */
export interface InvocationContext {
    /** Return address */
    returnAddress: bigint;
    /** Thread ID */
    threadId: number;
    /** Read a register by name */
    readRegister(name: string): bigint;
    /** Write a register by name */
    writeRegister(name: string, value: bigint): void;
    /** Function arguments (by index) */
    args: bigint[];
    /** Return value (only in onLeave) */
    returnValue?: bigint;
}

/** A contiguous memory range */
export interface MemoryRange {
    base: bigint;
    size: number;
    protection: string; // "rwx", "r-x", etc.
}

/** Info about a loaded module */
export interface ModuleInfo {
    name: string;
    base: bigint;
    size: number;
    path: string;
    imports: Array<{ name: string; module: string; address: bigint }>;
    exports: Array<{ name: string; address: bigint }>;
}

/** Hook callback types */
export type OnEnterCallback = (ctx: InvocationContext) => void;
export type OnLeaveCallback = (ctx: InvocationContext) => void;

/** Stalker event types */
export interface StalkerBlockEvent {
    type: 'block';
    address: bigint;
    size: number;
}

export interface StalkerCallEvent {
    type: 'call';
    from: bigint;
    to: bigint;
}

export type StalkerEvent = StalkerBlockEvent | StalkerCallEvent;
