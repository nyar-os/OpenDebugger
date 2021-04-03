import { defineConfig } from '@vmz/vmz';

/**
 * WebView2 loads the local static delivery from packages/open-debugger/dist/gui.
 * Builtin profile `static` → assembly `web-static`.
 */
export default defineConfig({
    delivery: {
        default: 'static',
        profiles: {
            static: {
                host: 'browser',
                assembly: 'web-static',
            },
        },
    },
});
