---
name: analyze-crash-dump
description: Inspect a Windows crash dump with OpenDebugger and summarize the bugcheck, exception address and loaded modules before proposing any repair.
---

# Analyze a Windows crash dump

Use this skill when a user provides a Windows memory dump or kernel dump and
asks why the machine bugchecked.

## Workflow

1. Confirm what the current build can actually do: `open-debugger capabilities`
2. Parse the dump without symbols: `open-debugger analyze <dump-path> --json`
3. Resolve a code that is not in the dump: `open-debugger bugcheck <code> --json`
4. Preview the durable report before writing it: `open-debugger report <dump-path> --out <report-path> --dry-run`

## Reading the result

- `dump-parse`, `kernel-dump`, `bugcheck-lookup` and `module-list` are portable
  and report `available: true` on every build target.
- `symbol-resolve`, `stack-unwind` and `live-attach` report `not_implemented`
  on Windows and `unsupported_platform` elsewhere. Do not present a stack trace
  or a blamed driver as fact when those capabilities are unavailable.
- A minidump normally has no `bugcheck` field. Kernel dumps carry the code and
  four parameters in the header.
- Module names show what was loaded, not what failed. Correlate the bugcheck
  cause with the exception address and the module ranges before naming a
  suspect.

## Safety

- `analyze` is read-only. It never writes to the dump or to the filesystem.
- `report` must be previewed with `--dry-run` first. Only run it without
  `--dry-run` after the user explicitly confirms the output path.
- The tool writes exactly the file named by `--out`. It never deletes,
  overwrites a directory, or sweeps other paths.
- Never ask for elevated privileges, driver installation, or a live debugger
  attachment in a read-only investigation.
- Never perform recursive deletion, cleanup, or registry edits as part of dump
  analysis. Report findings and stop.
