#!/usr/bin/env node
/** cargo build open-debugger-napi → stage into the matching platform package */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { type Target, cdylibName, nodeFileName, packageDir, resolveTarget, releaseDir, usesExplicitTarget } from './platform.ts';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * The only native artifact lookup in this repository. `stage-native.ts`, root
 * scripts and CI must call this instead of rebuilding a candidate list.
 */
export function resolveNapiArtifact(root: string, target: Target): string {
    const base = releaseDir(root, target);
    const candidates = [path.join(base, cdylibName()), path.join(base, 'open_debugger_napi.node')];
    const found = candidates.find((candidate) => fs.existsSync(candidate));
    if (!found) {
        throw new Error(`native artifact not found for ${target.triple}. Tried:\n${candidates.map((p) => `  - ${p}`).join('\n')}`);
    }
    return found;
}

export function stageNative(root: string, target: Target): { src: string; dest: string } {
    const src = resolveNapiArtifact(root, target);
    const destDir = packageDir(root, target);
    fs.mkdirSync(destDir, { recursive: true });
    const dest = path.join(destDir, nodeFileName(target));
    fs.copyFileSync(src, dest);
    return { src, dest };
}

function isEntrypoint(): boolean {
    const entry = process.argv[1];
    return Boolean(entry) && path.resolve(entry) === fileURLToPath(import.meta.url);
}

function buildAndStage(): void {
    const target = resolveTarget();
    const args = ['build', '-p', 'open-debugger-napi', '--release'];
    if (usesExplicitTarget()) {
        args.push('--target', target.triple);
    }
    // Avoid shell:true — Node 22+ warns DEP0190 when args + shell are combined.
    const result = spawnSync('cargo', args, { cwd: root, stdio: 'inherit', shell: false });
    if ((result.status ?? 1) !== 0) {
        process.exit(result.status ?? 1);
    }
    const { src, dest } = stageNative(root, target);
    console.log(`staged ${src} -> ${dest}`);
}

if (isEntrypoint()) {
    buildAndStage();
}
