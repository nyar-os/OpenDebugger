/**
 * Build and release configuration for OpenDebugger.
 *
 * This file is pure data so it can be parsed statically. `wae build` reads it
 * to order native → TypeScript → UI → skills validation → staging.
 */
export default {
    native: {
        crate: 'open-debugger-napi',
        target: 'win32-x64',
        cdylib: 'open_debugger_napi',
        artifact: 'open-debugger.win32-x64.node',
        platformPackage: '@wae/open-debugger-win32-x64',
    },
    packages: {
        native: {
            dir: 'packages/open-debugger-win32-x64',
            os: ['win32'],
            cpu: ['x64'],
        },
    },
    build: {
        order: ['native', 'typescript', 'ui', 'skills'],
    },
    skills: {
        dir: 'packages/open-debugger-skills/skills',
        check: 'scripts/check-skills.ts',
    },
    release: {
        packages: ['@wae/open-debugger', '@wae/open-debugger-skills', '@wae/open-debugger-win32-x64'],
        tag: 'vX.Y.Z',
    },
    ci: {
        workflows: ['check-rust.yml', 'check-typescript.yml'],
    },
    window: { mode: 'single', secondLaunch: 'focus' },
};
