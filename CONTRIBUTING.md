# Contributing

Thanks for helping improve SteadyPC.

## Development setup

```bash
npm install
npm run electron:dev
```

Before opening a pull request:

```bash
npm run typecheck
npm test
npm run build
```

## Rules for changes

- Do not add network calls, telemetry, analytics, or account features.
- Do not add registry cleaners, RAM cleaners, Prefetch deletion, or other placebo optimizations.
- Every new action must be added to `electron/commands.js` with an explicit risk, admin requirement, and rollback where possible.
- Every new finding must include a clear explanation, evidence, and a preset list.
- Keep comments short and explain intent, not the obvious code.
- Avoid emoji and marketing language in source code and UI.

## Commit style

Use short imperative messages, for example:

```text
Add SSD media type detection
Fix rollback for HKLM startup entries
Remove unused dependencies
```
