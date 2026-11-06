#!/usr/bin/env node
/**
 * OpenDebugger CLI — Windows crash dump analysis via `@wae/commander`.
 *
 * Exit codes are stable for automation:
 * - 0: success
 * - 1: runtime failure
 * - 2: usage / argument failure (raised by the framework)
 * - 3: capability unavailable (`unsupported_platform`, `not_implemented`, `dependency_blocked`)
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCli, type ParsedOptions } from '@wae/commander';
import { analyzeDump, auditQuery, capabilities, configureAudit, lookupBugcheck, runGui, version, writeReport } from './index.js';
import type { ActorKind, BugcheckInfo, DumpReport } from './index.js';

const EXIT_OK = 0;
const EXIT_FAILURE = 1;
const EXIT_USAGE = 2;
const EXIT_CAPABILITY = 3;

const CAPABILITY_CODES = ['unsupported_platform', 'not_implemented', 'dependency_blocked'];

const here = path.dirname(fileURLToPath(import.meta.url));
const localesDir = path.join(here, '..', 'locales');

const cli = createCli('open-debugger')
    .locales(localesDir)
    .intro('cli.intro')
    .option('--actor <id>', 'cli.opt.actor')
    .option('--actor-kind <kind>', 'cli.opt.actorKind')
    .option('--actor-source <source>', 'cli.opt.actorSource');

function text(options: ParsedOptions, key: string): string | undefined {
    const value = options[key];
    return typeof value === 'string' ? value : undefined;
}

/** Attribute every capability call in this run to an explicit actor. */
function applyActor(options: ParsedOptions): void {
    const kindRaw = text(options, 'actor-kind');
    const actorKind: ActorKind | undefined = kindRaw === 'user' || kindRaw === 'agent' ? kindRaw : undefined;
    configureAudit({
        actorId: text(options, 'actor'),
        actorKind,
        actorSource: text(options, 'actor-source') ?? 'cli',
    });
}

function errorText(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

function exitCodeFor(error: unknown): number {
    const message = errorText(error);
    if (CAPABILITY_CODES.some((code) => message.includes(code))) return EXIT_CAPABILITY;
    return EXIT_FAILURE;
}

function reportError(error: unknown): number {
    console.error(errorText(error));
    return exitCodeFor(error);
}

function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
    return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

/** Reports the honest capability gap recorded for a dump feature, if any. */
function featureGap(report: DumpReport, feature: string): string | undefined {
    return report.warnings.find((warning) => warning.startsWith(`not_implemented: ${feature}:`));
}

function describeParameter(value: string, label: string | undefined, note: string | null | undefined): string {
    const detail = note ?? label;
    return detail ? `${value} (${detail})` : value;
}

function printDumpReport(report: DumpReport, limit: number): void {
    console.log(`format: ${report.format}`);
    if (report.dumpType) console.log(`dump type: ${report.dumpType}`);
    console.log(`size: ${formatBytes(report.sizeBytes)}`);
    if (report.capturedAt) console.log(`captured at: ${report.capturedAt}`);
    if (report.system) {
        console.log(
            `system: ${report.system.architecture} ${report.system.osVersion} build ${report.system.buildNumber}, ` +
                `${report.system.processorCount} processors, ${report.system.productType}`,
        );
    }
    if (report.bugcheck) {
        const name = report.bugcheck.name ?? 'unknown bugcheck';
        console.log(`bugcheck: ${report.bugcheck.codeHex} ${name}`);
        if (report.bugcheck.summary) console.log(`  ${report.bugcheck.summary}`);
        if (report.bugcheck.parameters.length > 0) {
            const labels = report.bugcheck.parameterLabels ?? [];
            const notes = report.bugcheck.parameterNotes ?? [];
            const described = report.bugcheck.parameters.map((value, index) =>
                describeParameter(value, labels[index], notes[index]),
            );
            console.log(`  parameters: ${described.join(', ')}`);
        }
    }
    if (report.exception) {
        console.log(`exception: ${report.exception.code} at ${report.exception.address} (thread ${report.exception.threadId})`);
    }
    console.log(`modules: ${featureGap(report, 'module-list') ? 'not_implemented' : report.modules.length}`);
    for (const module of report.modules.slice(0, limit)) {
        console.log(`  ${module.baseAddress}  ${String(module.sizeBytes).padStart(9)}  ${module.name}`);
    }
    if (report.modules.length > limit) console.log(`  ... ${report.modules.length - limit} more (use --limit or --json)`);
    console.log(`threads: ${featureGap(report, 'thread-list') ? 'not_implemented' : report.threads.length}`);
    for (const warning of report.warnings) console.log(`warning: ${warning}`);
}

function printBugcheck(info: BugcheckInfo): void {
    if (!info.known) {
        console.log(`${info.codeHex} unknown bugcheck code`);
        return;
    }
    console.log(`${info.codeHex} ${info.name}`);
    if (info.summary) console.log(info.summary);
    for (const cause of info.commonCauses) console.log(`- ${cause}`);
    for (const [index, label] of (info.parameterLabels ?? []).entries()) {
        console.log(`parameter ${index + 1}: ${label}`);
    }
}

const limitOption = {
    coerce: (raw: string | boolean | string[]): unknown => {
        const n = Number(raw);
        if (!Number.isFinite(n) || n < 1) throw new Error(`invalid --limit: ${String(raw)}`);
        return String(Math.floor(n));
    },
};

cli.command('analyze', 'cli.cmd.analyze')
    .option('--json', 'cli.opt.json')
    .option('--limit <n>', 'cli.opt.limit', limitOption)
    .actionCtx(async (options, args) => {
        applyActor(options);
        const dump = args[0];
        if (!dump) {
            console.error('usage: open-debugger analyze <dump> [--json] [--limit <n>]');
            return EXIT_USAGE;
        }
        const limitRaw = text(options, 'limit');
        const limit = limitRaw ? Number(limitRaw) : 20;
        try {
            const report = analyzeDump({ path: dump });
            if (options.json === true) console.log(JSON.stringify(report, null, 2));
            else printDumpReport(report, limit);
            return EXIT_OK;
        }
        catch (error) {
            return reportError(error);
        }
    });

cli.command('bugcheck', 'cli.cmd.bugcheck')
    .option('--json', 'cli.opt.json')
    .actionCtx(async (options, args) => {
        applyActor(options);
        const code = args[0];
        if (!code) {
            console.error('usage: open-debugger bugcheck <code> [--json]');
            return EXIT_USAGE;
        }
        try {
            const info = lookupBugcheck({ code });
            if (options.json === true) console.log(JSON.stringify(info, null, 2));
            else printBugcheck(info);
            return EXIT_OK;
        }
        catch (error) {
            return reportError(error);
        }
    });

cli.command('capabilities', 'cli.cmd.capabilities').actionCtx(async (options) => {
    applyActor(options);
    try {
        console.log(JSON.stringify(capabilities(), null, 2));
        return EXIT_OK;
    }
    catch (error) {
        return reportError(error);
    }
});

cli.command('report', 'cli.cmd.report')
    .option('--out <path>', 'cli.opt.out', { required: true })
    .option('--json', 'cli.opt.json')
    .option('--dry-run', 'cli.opt.dryRun')
    .actionCtx(async (options, args) => {
        applyActor(options);
        const dump = args[0];
        if (!dump) {
            console.error('usage: open-debugger report <dump> --out <path> [--dry-run] [--json]');
            return EXIT_USAGE;
        }
        const out = text(options, 'out');
        if (!out) {
            console.error('report requires --out <path>');
            return EXIT_USAGE;
        }
        try {
            const dryRun = options['dry-run'] === true;
            const result = writeReport({ dumpPath: dump, path: out, dryRun });
            if (options.json === true) console.log(JSON.stringify(result.report, null, 2));
            else if (result.dryRun) {
                console.log(`dry_run: would write ${result.bytes} bytes to ${result.path}`);
                const modules = featureGap(result.report, 'module-list') ? 'not_implemented' : `${result.report.modules.length} modules`;
                const threads = featureGap(result.report, 'thread-list') ? 'not_implemented' : `${result.report.threads.length} threads`;
                console.log(`summary: ${result.report.format}, ${modules}, ${threads}`);
            }
            else console.log(`wrote report to ${result.path} (${result.bytes} bytes)`);
            return EXIT_OK;
        }
        catch (error) {
            return reportError(error);
        }
    });

cli.command('audit', 'cli.cmd.audit')
    .option('--actor <id>', 'cli.opt.actorFilter')
    .option('--capability <name>', 'cli.opt.capability')
    .option('--limit <n>', 'cli.opt.auditLimit', limitOption)
    .actionCtx(async (options) => {
        applyActor(options);
        const limitRaw = text(options, 'limit');
        try {
            const entries = auditQuery({
                actorId: text(options, 'actor'),
                capability: text(options, 'capability'),
                limit: limitRaw ? Number(limitRaw) : undefined,
            });
            for (const entry of entries) console.log(JSON.stringify(entry));
            return EXIT_OK;
        }
        catch (error) {
            return reportError(error);
        }
    });

cli.command('gui', 'cli.cmd.gui')
    .option('--title <text>', 'cli.opt.title', { default: 'OpenDebugger' })
    .option('--content-dir <path>', 'cli.opt.contentDir')
    .actionCtx(async (options) => {
        applyActor(options);
        const title = typeof options.title === 'string' ? options.title : 'OpenDebugger';
        try {
            await runGui({ title, contentDir: text(options, 'content-dir') });
            return EXIT_OK;
        }
        catch (error) {
            return reportError(error);
        }
    });

cli.command('version', 'cli.cmd.version').actionCtx(async (options) => {
    applyActor(options);
    try {
        console.log(version());
        return EXIT_OK;
    }
    catch (error) {
        return reportError(error);
    }
});

const code = await cli.parse(process.argv);
process.exitCode = code;
