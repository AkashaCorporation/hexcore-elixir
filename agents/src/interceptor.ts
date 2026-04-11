// Elixir Agent — Interceptor API
//
// Frida-style function hooking. In Elixir, hooks are installed at the
// emulation layer (Unicorn code hooks), not via code patching.

import type { OnEnterCallback, OnLeaveCallback } from './types.js';

export interface InterceptorAttachOptions {
    onEnter?: OnEnterCallback;
    onLeave?: OnLeaveCallback;
}

export class Interceptor {
    /**
     * Attach hooks to a function at the given address.
     * Returns a listener handle that can be passed to detach().
     */
    static attach(target: bigint, callbacks: InterceptorAttachOptions): number {
        // TODO: Bridge to native engine via NAPI
        throw new Error('Not yet implemented — engine bridge pending');
    }

    /** Detach a previously attached hook */
    static detach(listenerId: number): void {
        throw new Error('Not yet implemented');
    }

    /** Replace a function entirely */
    static replace(target: bigint, replacement: bigint): void {
        throw new Error('Not yet implemented');
    }

    /** Detach all hooks */
    static detachAll(): void {
        throw new Error('Not yet implemented');
    }
}
