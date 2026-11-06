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
5. When the user provides several dumps from one machine, group them first:
   `open-debugger correlate <dump>... --json`

## Reading the result

- `dump-parse`, `kernel-dump`, `bugcheck-lookup` and `module-list` are portable
  and report `available: true` on every build target. `kernel-module-list` is
  available on Windows only.
- `symbol-resolve` is available on Windows when a local symbol store, set
  through `OPEN_DEBUGGER_SYMBOL_STORE` or the Windows Kits debugger `sym`
  directory, holds the module image and PDB for the recorded timestamp and
  size. Frames then carry `function` and `functionOffset`. `stack-unwind` and
  `live-attach` still report `not_implemented`.
- A kernel triage dump reports trusted frames as `MODULE+offset` with a `source`
  of `context`, `call-site` or `frame-pointer`. Stack words that cannot be
  verified appear in a separate `stackGuesses` list: treat them as unverified
  candidates and never name them as the cause. A frame without `function` is
  not a missing report field to invent: its module image or PDB is absent from
  the local store.
- `symbols.missing` lists every module that could not be named, with its
  `reason`, the expected `imagePath` and `pdbPath`, the PDB `pdbName` and
  `<GUID><age>` `pdbKey`, and a `fetchCommand`. Report those fields to the user
  and run the `symchk` command only after they agree to populate a local store
  with a symbol server.
- `correlate` keys each group by the bugcheck code plus the first non-platform
  module. Groups show co-occurrence, not causation: a module that merely appears
  on the stack can put unrelated root causes in one group, so confirm against
  the exception address and frame arguments before naming a driver.
- `stackModuleBases` lists image references that appear as words on the crash
  stack. They show what was being handled, not what failed.
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
