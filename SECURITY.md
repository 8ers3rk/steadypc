# Security policy

SteadyPC changes Windows settings. Treat it as a system utility.

## Supported versions

Only the latest released version receives fixes.

## Reporting a vulnerability

If you find a security issue, open a private security advisory in the repository or contact the maintainers directly. Please include:

- Steps to reproduce.
- Windows version and build.
- Whether the issue requires administrator privileges.
- The affected SteadyPC version.

Do not publish exploit details before a fix is available.

## Safety expectations

- Commands must come from the fixed registry in `electron/commands.js`.
- Renderer code must never be able to execute arbitrary commands.
- Every argument crossing the preload bridge is validated in `electron/validation.js` against an allowlist or strict schema.
- The renderer is restricted by Content Security Policy; external scripts, frames, objects and network destinations are blocked.
- Every destructive operation must have an explicit risk level and, where possible, a rollback.
- The application must not perform network requests.
- Logs and exports stay on the local machine. Exported HTML escapes untrusted text and loads no external resources.
- Risk indicators are advisory only: SteadyPC never deletes files, terminates processes or quarantines objects.
- Builds are currently unsigned; verify SHA-256 checksums from the official release before running them.
