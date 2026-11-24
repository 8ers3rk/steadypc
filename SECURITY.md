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
- Every destructive operation must have an explicit risk level and, where possible, a rollback.
- The application must not perform network requests.
