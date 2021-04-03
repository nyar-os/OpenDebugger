# open-debugger-skills

Agent skills for OpenDebugger, packaged as plain Markdown so they can be copied into any
assistant that reads `SKILL.md` frontmatter.

| Skill | Purpose |
|-------|---------|
| `analyze-crash-dump` | Parse a Windows crash dump, read the bugcheck summary, and emit a JSON report |
| `lookup-bugcheck` | Explain a bugcheck code and its common causes |

Every skill is written against the real CLI surface of `open-debugger`. The commands and flags
referenced in `SKILL.md` are validated by `scripts/check-skills.ts` against `--help` output, so a
skill cannot drift into documenting options that do not exist.

The tool only runs on `win32-x64`. On other hosts the CLI exits with
`unsupported_platform`, and the skills instruct the agent to report that instead of fabricating
dump contents.
