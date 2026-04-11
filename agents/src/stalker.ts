// Elixir Agent — Stalker API
//
// Basic block tracing. Records every block executed during emulation.

import type { StalkerEvent } from './types.js';

export class Stalker {
    /** Start tracing the current thread */
    static follow(): void {
        throw new Error('Not yet implemented');
    }

    /** Stop tracing */
    static unfollow(): void {
        throw new Error('Not yet implemented');
    }

    /** Drain collected events */
    static drain(): StalkerEvent[] {
        throw new Error('Not yet implemented');
    }

    /** Flush events to a callback without draining */
    static flush(callback: (events: StalkerEvent[]) => void): void {
        throw new Error('Not yet implemented');
    }
}
