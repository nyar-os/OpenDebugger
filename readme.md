# OpenDebugger

Analyze Windows crash dumps without a debugger session. OpenDebugger reads minidump and
kernel dump containers, resolves bugcheck codes, lists modules and threads, and writes
schema-tagged JSON reports. A WebView2 interface ships alongside the command line.

## Features

- Minidump (`MDMP`) containers and kernel dump headers
- Bugcheck code lookup with the built-in code table
- Module list and thread records read from the dump
- Report output under `open-debugger.report/v0`
- Audited file writes and capability queries
- Agent skills for dump analysis and bugcheck lookup

## Install

```bash
npm install -g @wae/open-debugger
```

The native addon is published for Windows x64. Other hosts have no binary and are not
expected to run the tool.

## Commands

| Command | Purpose |
|---|---|
| `open-debugger analyze <dump>` | Print a dump summary as text or `--json` |
| `open-debugger bugcheck <code>` | Resolve a bugcheck code |
| `open-debugger capabilities` | List capability states for this build |
| `open-debugger report <dump> --out <path>` | Write a JSON report (`--dry-run` previews) |
| `open-debugger audit` | Query the audit log |
| `open-debugger gui` | Open the WebView2 interface |
| `open-debugger version` | Print the package version |

`analyze`, `bugcheck` and `report` print machine-readable output with `--json`, every
command accepts `--actor` for audit attribution, and exit codes are stable: `0` success,
`1` runtime failure, `2` usage error, `3` capability unavailable.

## Capability states

Capabilities are reported as available, or blocked with one of `unsupported_platform`,
`not_implemented` or `dependency_blocked`.

| Capability | State |
|---|---|
| `dump-parse` | available |
| `kernel-dump` | available, verified against a real Windows triage dump |
| `bugcheck-lookup` | available |
| `module-list` | available |
| `kernel-module-list` | available on Windows, `unsupported_platform` elsewhere |
| `report-write` | available |
| `gui` | available on Windows |
| `symbol-resolve` | `not_implemented` on Windows, `unsupported_platform` elsewhere |
| `stack-unwind` | `not_implemented` on Windows, `unsupported_platform` elsewhere |
| `live-attach` | `not_implemented` on Windows, `unsupported_platform` elsewhere |

## Platform

OpenDebugger is a Windows-bound tool. Its dump formats, bugcheck semantics and GUI host
target Windows, and the build ships for `win32-x64` only. It does not simulate those
capabilities on macOS, Linux or Arm hosts, and there is no portable dump or symbol
implementation behind a compatibility facade.

Kernel triage dumps are read without page tables: the descriptor area yields the loaded
module table, the crash stack block and the faulting context, and stack frames are reported
as `MODULE+offset` with their source marked as `context`, `call-site` or `scan`. A triage
dump carries no unwind metadata, so frames are not a metadata-driven unwind.

Function names need a `dbgeng` or `dbghelp` binding, which this crate does not call yet.
The engine libraries, headers and a local symbol cache exist on a machine with Windows
Debugging Tools installed, and `cdb` there resolves the same dump, but the local cache and
the network availability of `msdl` are outside this tool's contract.

## License

[`License.md`](./License.md), Apache-2.0.
