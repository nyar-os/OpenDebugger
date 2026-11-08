import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
    defaultGuiContentDir,
    loadNative,
    type AuditConfigureOptions,
    type AuditQueryOptions,
    type AuditRecord,
    type AnalysisTimings,
    type BugcheckInfo,
    type Capabilities,
    type CrashGroup,
    type DumpReport,
    type OpenGuiOptions,
    type ReportWrite,
    type WriteReportOptions,
} from './native.js';

export type {
    ActorKind,
    AnalysisTimings,
    AuditActor,
    AuditConfigureOptions,
    AuditQueryOptions,
    AuditRecord,
    BugcheckInfo,
    BugcheckSummary,
    Capabilities,
    CapabilityCode,
    CapabilityEntry,
    CrashGroup,
    CrashObservation,
    CrashOccurrence,
    DumpFormat,
    DumpReport,
    DumpType,
    ExceptionInfo,
    MissingSymbol,
    ModuleInfo,
    OpenGuiOptions,
    PhysicalPage,
    ReportWrite,
    StackFrame,
    StackFrameSource,
    StackReference,
    SymbolDiagnostics,
    SystemInfo,
    ThreadInfo,
    WriteReportOptions,
} from './native.js';
export { supportedPlatforms } from './native.js';

/** Parse a Windows minidump or kernel dump and return the report model. */
export function analyzeDump(options: { path: string }): DumpReport {
    return loadNative().analyzeDump(options);
}

/** Resolve a bugcheck code against the built-in table. Unknown codes return `known: false`. */
export function lookupBugcheck(options: { code: number | string }): BugcheckInfo {
    return loadNative().lookupBugcheck(options);
}

/**
 * Group dumps from one machine by bugcheck code and by the first module outside the kernel
 * and HAL that owns a trusted frame or appears as a stack base.
 */
export function correlateDumps(paths: string[]): CrashGroup[] {
    return loadNative().correlateDumps(...paths);
}

/**
 * Analyze a dump and write the schema-tagged report document through the audited
 * `report-write` capability. With `dryRun` the dump is still parsed but nothing is written.
 */
export function writeReport(options: WriteReportOptions): ReportWrite {
    return loadNative().writeReport(options);
}

/** Report which sinks are available on the current build target. */
export function capabilities(): Capabilities {
    return loadNative().capabilities();
}

export function version(): string {
    return loadNative().version();
}

/**
 * Read `window.policy.secondLaunch` from the contract `wae build` writes next
 * to the CLI entry. A missing or unreadable contract means the default policy:
 * focus the existing window instead of opening a second one.
 */
function secondLaunchFromContract(): 'focus' | 'reject' {
    try {
        const url = new URL('./wae-runtime.json', import.meta.url);
        const value: unknown = JSON.parse(fs.readFileSync(fileURLToPath(url), 'utf8'));
        if (typeof value !== 'object' || value === null || Array.isArray(value)) return 'focus';
        const window = (value as { window?: unknown }).window;
        if (typeof window !== 'object' || window === null) return 'focus';
        const policy = (window as { policy?: unknown }).policy;
        if (typeof policy !== 'object' || policy === null) return 'focus';
        return (policy as { secondLaunch?: unknown }).secondLaunch === 'reject' ? 'reject' : 'focus';
    }
    catch {
        return 'focus';
    }
}

export function openGui(options: OpenGuiOptions = {}): void {
    const native = loadNative();
    native.openGui({
        title: options.title ?? 'OpenDebugger',
        contentDir: options.contentDir ?? (options.url ? undefined : defaultGuiContentDir()),
        url: options.url,
        width: options.width,
        height: options.height,
        secondLaunch: options.secondLaunch ?? secondLaunchFromContract(),
    });
}

/** Pump the host message loop. Returns false when the GUI has closed. */
export function pumpEvents(): boolean {
    return loadNative().pumpEvents();
}

export function closeGui(): void {
    loadNative().closeGui();
}

export function isGuiOpen(): boolean {
    return loadNative().isGuiOpen();
}

/**
 * Tag subsequent capability calls with an explicit actor. Without an override
 * `WAE_ACTOR_KIND` / `WAE_ACTOR_ID` / `WAE_ACTOR_SOURCE` supply the identity.
 */
export function configureAudit(options: AuditConfigureOptions = {}): void {
    loadNative().configureAudit(options);
}

/** Read the append-only capability history written by the shared auditor. */
export function auditQuery(options: AuditQueryOptions = {}): AuditRecord[] {
    return loadNative().auditQuery(options);
}

export function runGui(options: OpenGuiOptions = {}, intervalMs = 16): Promise<void> {
    openGui(options);
    return new Promise((resolve, reject) => {
        let frames = 0;
        const timer = setInterval(() => {
            try {
                frames += 1;
                if (frames === 1 && !isGuiOpen()) {
                    clearInterval(timer);
                    reject(new Error('GUI failed to stay open after openGui()'));
                    return;
                }
                if (!pumpEvents()) {
                    clearInterval(timer);
                    resolve();
                }
            }
            catch (err) {
                clearInterval(timer);
                reject(err);
            }
        }, intervalMs);
    });
}
