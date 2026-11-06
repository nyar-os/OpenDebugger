# `@wae/open-debugger`

Command line front end for OpenDebugger. It reads Windows crash dumps, resolves bugcheck
codes, lists modules, writes reports and opens the WebView2 interface.

## Install

```bash
npm install -g @wae/open-debugger
```

A native addon is required. The published addon targets Windows x64
(`@wae/open-debugger-win32-x64`), so the CLI runs on Windows x64 hosts only.

## Commands

```bash
open-debugger analyze <dump> [--json] [--limit <n>]
open-debugger bugcheck <code> [--json]
open-debugger capabilities
open-debugger report <dump> --out <path> [--dry-run] [--json]
open-debugger audit [--actor <name>] [--capability <name>] [--limit <n>]
open-debugger gui [--title <text>] [--content-dir <path>]
open-debugger version
```

- `analyze` prints a dump summary. `--limit` caps the module rows that are printed.
- `bugcheck` accepts decimal or hexadecimal codes such as `0x000000EF`.
- `capabilities` prints the state of every capability for the current host as JSON.
- `report` writes `open-debugger.report/v0` JSON. `--dry-run` encodes the document and
  reports its size without writing a file.
- `audit` prints one JSON record per line for the shared audit log. Global `--actor`,
  `--actor-kind` and `--actor-source` attach attribution to audited operations.
- `gui` opens the WebView2 window and serves the staged UI from `dist/gui` by default.
- `version` prints the package version.

Commands never prompt. `analyze`, `bugcheck` and `report` support `--json` for
machine-readable output. Output locale follows `locales/locales.json`: `en-US` (default)
and `zh-CN`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Runtime failure, such as an unreadable dump or a failed write |
| `2` | Usage error reported by the command framework |
| `3` | Capability unavailable, reported as `unsupported_platform`, `not_implemented` or `dependency_blocked` |

## Capabilities

`open-debugger capabilities --json` prints the same data the GUI shows:

| Capability | Windows x64 |
|---|---|
| `dump-parse` | available |
| `kernel-dump` | available, verified against a real Windows triage dump |
| `bugcheck-lookup` | available |
| `module-list` | available |
| `kernel-module-list` | available |
| `report-write` | available |
| `gui` | available |
| `symbol-resolve` | available when a local symbol store holds the module image and PDB |
| `stack-unwind` | `not_implemented` |
| `live-attach` | `not_implemented` |

Non-Windows hosts report `unsupported_platform` for the platform-bound capabilities. No
capability returns synthetic data when it is unavailable.

## Platform limits

OpenDebugger is Windows-bound by design. The package does not emulate dump parsing,
symbol handling or a GUI on other platforms, and no portable fallback is provided. Live
attach is not implemented yet on any platform.

Kernel triage dumps resolve loaded modules and stack frames to `MODULE+offset`. Frames
carry a `source` of `context`, `call-site` or `scan` because a triage dump has no unwind
metadata. Function names are added from `dbghelp` when a local symbol store, set through
`OPEN_DEBUGGER_SYMBOL_STORE` or the Windows Kits debugger `sym` directory, holds the module
image and PDB for the recorded timestamp and size. Uncached modules keep the offset form
and the report names the missing module.

## Agent skills

`@wae/open-debugger-skills` contains skills for dump analysis and bugcheck lookup. Each
skill documents the same capability limits and requires `--dry-run` before a write and
explicit confirmation before acting.

## License

Apache-2.0. See `License.md`.
