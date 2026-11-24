# Changelog

## [1.1.0] - 2026-11-24

### Added

- Eight offline risk-indicator checks for miners, suspicious processes, startup entries, scheduled tasks and built-in protection state.
- A built-in signature list with an optional manual override at `%APPDATA%\SteadyPC\security-signatures.json`; no network is used.
- Safe actions on indicator cards: reveal the file, copy evidence and open Task Manager.
- An in-app FAQ in Russian and English with no external links or product names.
- Tests for signature merging, heuristic confidence rules, score isolation and FAQ content.

### Changed

- Risk indicators are diagnostic only: they do not affect the health score, cannot be applied as changes and never trigger removal, process termination or quarantine.

## 1.0.0

- Rewritten as SteadyPC: offline diagnostics with detailed, evidence-based findings.
- Added real collectors for startup, storage, power, processes, network, visual effects, updates, and privacy.
- Added selectable change plans with presets as recommendations.
- Added command registry, journal, and rollback for reversible actions.
- Added before/after comparison after applying changes.
- Added an all-checks view with status, measured values, and thresholds for every collector.
- Added a Tools tab with manual access to every operation, guarded by media type and admin checks.
- Fixed temporary file reporting: total size and old-file counts were previously calculated incorrectly.
- Added transparent scoring with per-category breakdown.
- Added light and dark themes plus Russian and English UI.
- Removed Supabase, network fonts, demo mode, and unused dependencies.
- Removed placebo optimizations such as Prefetch deletion and registry cleaning.
- Added tests and GitHub Actions workflow.
- Added application icon and unsigned NSIS/portable builds.
