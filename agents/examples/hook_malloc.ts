// Example: Hook malloc/free to track heap allocations
//
// Usage: elixir_tool run target_bin --os linux --script hook_malloc.ts

import { Interceptor, Process, Memory } from '../src/index.js';
import type { InvocationContext } from '../src/types.js';

const libc = Process.findModuleByName('libc.so.6');
if (!libc) {
    console.log('[!] libc not found');
} else {
    const malloc = libc.exports.find(e => e.name === 'malloc');
    const free = libc.exports.find(e => e.name === 'free');

    if (malloc) {
        Interceptor.attach(malloc.address, {
            onEnter(ctx: InvocationContext) {
                console.log(`[malloc] size = ${ctx.args[0]}`);
            },
            onLeave(ctx: InvocationContext) {
                console.log(`[malloc] => 0x${ctx.returnValue!.toString(16)}`);
            }
        });
    }

    if (free) {
        Interceptor.attach(free.address, {
            onEnter(ctx: InvocationContext) {
                console.log(`[free] ptr = 0x${ctx.args[0].toString(16)}`);
            }
        });
    }
}
