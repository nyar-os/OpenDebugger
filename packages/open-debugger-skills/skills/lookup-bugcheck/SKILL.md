---
name: lookup-bugcheck
description: Resolve a Windows blue screen bugcheck code to its symbolic name, meaning and common causes with OpenDebugger.
---

# Look up a bugcheck code

Use this skill when the user reports a blue screen code such as `0x1A` or
`0x00000133` and wants to know what it means.

## Workflow

1. Check the local build state: `open-debugger capabilities`
2. Resolve the code: `open-debugger bugcheck <code> --json`

## Interpretation

- Codes are hexadecimal with or without a `0x` prefix.
- `known: false` means the code is outside the built-in table. Say so plainly
  and do not invent a name or a cause.
- Common causes are candidate explanations, not a diagnosis. Correlate them
  with a dump through the analyze-crash-dump workflow before recommending a
  change.

## Safety

- The lookup is read-only and offline. No network request is made.
- Do not present the common causes as a confirmed root cause.
- Do not modify drivers, registry values, or system files based on a code alone.
- Never perform recursive deletion or cleanup while investigating a crash.
