import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export type DumpFormat = 'minidump' | 'kernel-dump-64' | 'kernel-dump-32';

export type DumpType = 'full' | 'summary' | 'header' | 'triage' | 'bitmap-full' | 'bitmap-kernel' | 'automatic' | 'unknown';

export type SystemInfo = {
    architecture: string;
    osVersion: string;
    buildNumber: number;
    processorCount: number;
    productType: string;
};

export type ModuleInfo = {
    name: string;
    baseAddress: string;
    sizeBytes: number;
    timestamp: number;
};

export type ThreadInfo = {
    threadId: number;
};

export type StackFrameSource = 'context' | 'call-site' | 'scan';

/** One frame recovered from a kernel triage dump, resolved to a `MODULE+offset` pair. */
export type StackFrame = {
    address: string;
    module?: string;
    offsetInModule?: string;
    /** Function that contains the address, present only when a local symbol store resolved it. */
    function?: string;
    functionOffset?: string;
    source: StackFrameSource;
};

/** A loaded module whose base address appears as a word on the crash stack. */
export type StackReference = {
    address: string;
    module: string;
};

/** A bugcheck page frame number and its `MMPFN` database entry. */
export type PhysicalPage = {
    pfn: number;
    databaseEntry?: string;
    /** Raw bytes at the start of the `MMPFN` entry, not decoded into fields. */
    entryBytes?: string;
    /** False when the triage dump does not map the PFN database page. */
    inDump: boolean;
};

export type ExceptionInfo = {
    threadId: number;
    code: string;
    codeValue: number;
    address: string;
    parameters: string[];
};

export type BugcheckSummary = {
    code: number;
    codeHex: string;
    known: boolean;
    name?: string;
    summary?: string;
    commonCauses: string[];
    parameters: string[];
    /** Labels for the four parameters in argument order. */
    parameterLabels: string[];
    /** Documented meaning of a parameter value, aligned with `parameters`. */
    parameterNotes: (string | null)[];
};

export type DumpReport = {
    format: DumpFormat;
    dumpType?: DumpType | null;
    sizeBytes: number;
    capturedAt?: string | null;
    system?: SystemInfo;
    bugcheck?: BugcheckSummary;
    exception?: ExceptionInfo;
    modules: ModuleInfo[];
    threads: ThreadInfo[];
    /** Frames from the faulting context and crash stack, kernel triage dumps only. */
    stack: StackFrame[];
    /** Module bases observed on the crash stack, deduplicated. */
    stackModuleBases: StackReference[];
    physicalPage?: PhysicalPage | null;
    processId?: number;
    warnings: string[];
};

export type BugcheckInfo = {
    code: number;
    codeHex: string;
    known: boolean;
    name?: string;
    summary?: string;
    commonCauses: string[];
    parameterLabels: string[];
};

export type CapabilityCode = 'unsupported_platform' | 'not_implemented' | 'dependency_blocked';

export type CapabilityEntry = {
    capability: string;
    available: boolean;
    code?: CapabilityCode;
    detail: string;
};

export type Capabilities = {
    platform: string;
    architecture: string;
    entries: CapabilityEntry[];
};

/** Result of the audited `report-write` capability. */
export type ReportWrite = {
    path: string;
    bytes: number;
    dryRun: boolean;
    report: DumpReport;
};

export type WriteReportOptions = {
    /** Dump to analyze before writing. */
    dumpPath: string;
    /** Target report file. */
    path: string;
    /** Validate the request and parse the dump without touching the filesystem. */
    dryRun?: boolean;
};

export type OpenGuiOptions = {
    title?: string;
    /** Local folder containing index.html (served via https://app.local/). */
    contentDir?: string;
    /** Escape hatch; prefer contentDir. */
    url?: string;
    width?: number;
    height?: number;
};

export type ActorKind = 'user' | 'agent';

export type AuditActor = {
    kind: ActorKind;
    id: string;
    source: string;
};

/** One append-only record from the shared `wae.audit/v0` history. */
export type AuditRecord = {
    schema: string;
    timestampMs: number;
    actor: AuditActor;
    app: string;
    appVersion: string;
    capability: string;
    mode: 'dry_run' | 'execute';
    params: unknown;
    targets: {
        count: number;
        summary: string;
    };
    result: 'success' | 'failure' | 'rejected';
    errorCode?: string;
    durationMs: number;
    host: string;
    session: string;
};

export type AuditConfigureOptions = {
    actorKind?: ActorKind;
    actorId?: string;
    actorSource?: string;
    session?: string;
    host?: string;
};

export type AuditQueryOptions = {
    actorKind?: ActorKind;
    actorId?: string;
    /** Inclusive lower bound, Unix milliseconds. */
    fromMs?: number;
    /** Inclusive upper bound, Unix milliseconds. */
    toMs?: number;
    capability?: string;
    limit?: number;
};

type NativeBinding = {
    analyzeDump(options: { path: string }): DumpReport;
    lookupBugcheck(options: { code: number | string }): BugcheckInfo;
    writeReport(options: WriteReportOptions): ReportWrite;
    capabilities(): Capabilities;
    version(): string;
    openGui(options?: OpenGuiOptions): void;
    pumpEvents(): boolean;
    closeGui(): void;
    isGuiOpen(): boolean;
    configureAudit(options?: AuditConfigureOptions): void;
    auditQuery(options?: AuditQueryOptions): AuditRecord[];
};

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));

type PlatformArch = 'win32-x64';

/**
 * OpenDebugger ships for Windows x64 only. Any other host is rejected with the
 * shared `unsupported_platform` code before a native lookup is attempted.
 */
const PLATFORM_PACKAGES: Record<PlatformArch, string> = {
    'win32-x64': '@wae/open-debugger-win32-x64',
};

export function supportedPlatforms(): PlatformArch[] {
    return Object.keys(PLATFORM_PACKAGES) as PlatformArch[];
}

function currentPlatformArch(): PlatformArch | null {
    const key = `${process.platform}-${process.arch}`;
    return (Object.hasOwn(PLATFORM_PACKAGES, key) ? key : null) as PlatformArch | null;
}

function candidateNodePaths(): string[] {
    const pa = currentPlatformArch();
    if (!pa) {
        throw new Error(
            `unsupported_platform: OpenDebugger native addon targets ${supportedPlatforms().join(', ')}, ` +
                `current host is ${process.platform}-${process.arch}. No compatibility build exists.`,
        );
    }

    const pkg = PLATFORM_PACKAGES[pa];
    const fileName = `open-debugger.${pa}.node`;
    const paths: string[] = [];

    try {
        const pkgJson = require.resolve(`${pkg}/package.json`);
        const root = path.dirname(pkgJson);
        paths.push(path.join(root, fileName));
    }
    catch {
        // optional dependency may be missing during monorepo dev
    }

    // packages/open-debugger/dist → ../../open-debugger-<platform>-<arch>
    paths.push(path.resolve(here, `../../open-debugger-${pa}/${fileName}`), path.resolve(here, '../../../target/release/open_debugger_napi.node'));
    return paths;
}

let cached: NativeBinding | null = null;

export function loadNative(): NativeBinding {
    if (cached) return cached;
    const tried: string[] = [];
    for (const candidate of candidateNodePaths()) {
        tried.push(candidate);
        if (!fs.existsSync(candidate)) continue;
        cached = require(candidate) as NativeBinding;
        return cached;
    }
    throw new Error(
        `Failed to load open-debugger native addon. Tried:\n${tried.map((p) => `  - ${p}`).join('\n')}`,
    );
}

/** GUI assets ship inside the published/built `dist/gui` tree. */
export function defaultGuiContentDir(): string {
    const dir = path.resolve(here, 'gui');
    if (!fs.existsSync(path.join(dir, 'index.html'))) {
        throw new Error(`GUI folder missing at ${dir} (expected packages/open-debugger/dist/gui)`);
    }
    return dir;
}
