/**
 * Build configuration for OpenDebugger, consumed by `wae native build` and
 * `wae native stage`. Pure data: no imports, no logic.
 */
export default {
    native: {
        crate: 'open-debugger-napi',
        cdylib: 'open_debugger_napi',
        targetEnv: 'OPEN_DEBUGGER_TARGET',
        targets: [
            {
                platform: 'win32',
                arch: 'x64',
                triple: 'x86_64-pc-windows-msvc',
                package: '@wae/open-debugger-win32-x64',
                nodeFile: 'open-debugger.win32-x64.node',
                dir: 'packages/open-debugger-win32-x64',
            },
        ],
    },
    packages: [
        {
            name: '@wae/open-debugger-win32-x64',
            dir: 'packages/open-debugger-win32-x64',
            os: ['win32'],
            cpu: ['x64'],
            main: 'open-debugger.win32-x64.node',
        },
    ],
    window: { mode: 'single', secondLaunch: 'focus' },
};
