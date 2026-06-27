# ADR-0001: Incremental strangler-fig migration

Status: Accepted · Date: 2026-06-27

## Context
XUI is ~26k LOC, 255 files, deeply coupled to the external ForgeRock Commons UI artifact. A running product depends on it. We must modernize without a long no-ship window or high regression risk.

## Decision
Migrate incrementally (strangler-fig): stand up a new React/Vite/TS app and move the legacy app into it feature-by-feature. Old and new coexist until the legacy app is empty, then delete it.

## Consequences
- Ships value continuously; risk is bounded per slice.
- Requires a dual-stack maintenance window (months–quarters) — legacy is frozen except security fixes.
- Requires a runtime coexistence mechanism (see ADR-0004) and a live route-ownership map.

## Alternatives considered
- **Big-bang rewrite** — cleanest end state, no dual-stack tax, but ~13.4k LOC of admin must reach parity before anything ships; long no-ship window; late regressions. Rejected as too risky.
- **Tooling-first only** (swap Grunt→Vite, keep Backbone) — fast DX win but leaves the framework/Commons-UI debt in place; not a real migration. Rejected.
