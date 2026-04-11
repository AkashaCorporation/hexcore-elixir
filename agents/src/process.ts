// Elixir Agent — Process API
//
// Query information about the emulated process.

import type { ModuleInfo } from './types.js';

export class Process {
    /** Get the main module */
    static get mainModule(): ModuleInfo {
        throw new Error('Not yet implemented');
    }

    /** List all loaded modules */
    static enumerateModules(): ModuleInfo[] {
        throw new Error('Not yet implemented');
    }

    /** Find a module by name */
    static findModuleByName(name: string): ModuleInfo | null {
        throw new Error('Not yet implemented');
    }

    /** Find which module contains an address */
    static findModuleByAddress(address: bigint): ModuleInfo | null {
        throw new Error('Not yet implemented');
    }

    /** Get the architecture string */
    static get arch(): string {
        throw new Error('Not yet implemented');
    }

    /** Get the OS string */
    static get os(): string {
        throw new Error('Not yet implemented');
    }
}
