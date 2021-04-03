import path from 'node:path';

export type Platform = 'win32';
export type Arch = 'x64';

export type Target = {
    platform: Platform;
    arch: Arch;
    triple: string;
};

/**
 * OpenDebugger ships for Windows x64 only. There is no placeholder entry for a
 * platform we do not build, so an unsupported host fails here instead of
 * producing a package that cannot work.
 */
const TARGETS: Record<string, Target> = {
    'x86_64-pc-windows-msvc': { platform: 'win32', arch: 'x64', triple: 'x86_64-pc-windows-msvc' },
};

function hostTriple(): string {
    const host = `${process.platform}-${process.arch}`;
    if (host !== 'win32-x64') {
        throw new Error(`Unsupported host ${host}. OpenDebugger builds only for win32-x64.`);
    }
    return TARGETS['x86_64-pc-windows-msvc'].triple;
}

/**
 * `OPEN_DEBUGGER_TARGET` selects an explicit Rust target triple. Only the
 * Windows x64 triple is known.
 */
export function resolveTarget(): Target {
    const triple = process.env.OPEN_DEBUGGER_TARGET ?? hostTriple();
    const target = TARGETS[triple];
    if (!target) {
        throw new Error(`Unsupported Rust target ${triple}. Supported targets: ${Object.keys(TARGETS).join(', ')}`);
    }
    return target;
}

export function usesExplicitTarget(): boolean {
    return Boolean(process.env.OPEN_DEBUGGER_TARGET);
}

export function packageName(target: Target): string {
    return `open-debugger-${target.platform}-${target.arch}`;
}

export function packageDir(root: string, target: Target): string {
    return path.join(root, 'packages', packageName(target));
}

export function nodeFileName(target: Target): string {
    return `open-debugger.${target.platform}-${target.arch}.node`;
}

export function cdylibName(): string {
    return 'open_debugger_napi.dll';
}

export function releaseDir(root: string, target: Target): string {
    return usesExplicitTarget() ? path.join(root, 'target', target.triple, 'release') : path.join(root, 'target', 'release');
}
