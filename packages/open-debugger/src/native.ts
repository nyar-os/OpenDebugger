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

export type StackFrameSource = 'context' | 'call-site' | 'frame-pointer' | 'scan';

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

/** Milliseconds spent in each analysis phase for this exact run. */
export type AnalysisTimings = {
    /** Header fields and the faulting context. */
    header: number;
    /** Module record table scan. */
    moduleTable: number;
    /** Captured memory block table scan. */
    blockTable: number;
    /** Stack read, frame scan and call-site checks. */
    stack: number;
    /** Image and PDB lookup plus `dbghelp` symbol resolution. */
    symbols: number;
    total: number;
};

/** A loaded module whose base address appears as a word on the crash stack. */
export type StackReference = {
    address: string;
    module: string;
};

/** A module whose image or PDB could not be used to name its frames. */
export type MissingSymbol = {
    module: string;
    timestamp: number;
    size: number;
    /** Why the module could not be named. */
    reason: string;
    /** Store path for the image, or the path the image must occupy. */
    imagePath?: string;
    /** PDB name recorded by the module image. */
    pdbName?: string;
    /** `<GUID><age>` key that names the PDB directory in the symbol store. */
    pdbKey?: string;
    pdbPath?: string;
    /** Command that prefetches the image and PDB with Debugging Tools. */
    fetchCommand?: string;
};

/** Symbol store state for one analysis. */
export type SymbolDiagnostics = {
    store?: string;
    /** True when `dbghelp` was bound and accepted the store. */
    engine: boolean;
    /** Modules whose image or PDB is missing, each with a prefetch command when one can be formed. */
    missing: MissingSymbol[];
    warnings: string[];
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
    /** Stack words that resolve into modules but cannot be verified. Never mixed into `stack`. */
    stackGuesses: StackFrame[];
    /** Module bases observed on the crash stack, deduplicated. */
    stackModuleBases: StackReference[];
    /** Symbol store state, including modules whose image or PDB is missing. */
    symbols: SymbolDiagnostics;
    /** Phase durations for this exact run. */
    timings: AnalysisTimings;
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

/** What one dump contributes to cross-dump grouping. */
export type CrashObservation = {
    path: string;
    capturedAt?: string;
    bugcheck?: number;
    bugcheckName?: string;
    /** Modules outside the kernel and HAL that own a trusted frame or appear as a stack base. */
    triggerModules: string[];
};

/** One dump inside a `CrashGroup`. */
export type CrashOccurrence = {
    path: string;
    capturedAt?: string;
};

/** Crashes that share a bugcheck code and a trigger module. */
export type CrashGroup = {
    bugcheck?: number;
    bugcheckHex?: string;
    bugcheckName?: string;
    /** Module the group is keyed by, absent when the dump names none. */
    module?: string;
    /** Every non-platform module seen across the grouped dumps. */
    modules: string[];
    count: number;
    dumps: CrashOccurrence[];
};

type NativeBinding = {
    analyzeDump(options: { path: string }): DumpReport;
    lookupBugcheck(options: { code: number | string }): BugcheckInfo;
    correlateDumps(...paths: string[]): CrashGroup[];
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

/**
 * Specifiers to try: the optional platform package (via `package.json#main`),
 * then the sibling checkout package directory. Never concatenate the `.node`
 * filename — that lives only in the platform package's `main`.
 */
function candidateSpecifiers(): string[] {
    const pa = currentPlatformArch();
    if (!pa) {
        throw new Error(
            `unsupported_platform: OpenDebugger native addon targets ${supportedPlatforms().join(', ')}, ` +
                `current host is ${process.platform}-${process.arch}. No compatibility build exists.`,
        );
    }

    const pkg = PLATFORM_PACKAGES[pa];
    // packages/open-debugger/dist → ../../open-debugger-<platform>-<arch>
    return [pkg, path.resolve(here, `../../open-debugger-${pa}`)];
}

let cached: NativeBinding | null = null;

export function loadNative(): NativeBinding {
    if (cached) return cached;
    const tried: string[] = [];
    for (const candidate of candidateSpecifiers()) {
        tried.push(candidate);
        try {
            cached = require(candidate) as NativeBinding;
            return cached;
        }
        catch {
            // try the next specifier
        }
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
