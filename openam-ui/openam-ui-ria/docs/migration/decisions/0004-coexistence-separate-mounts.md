# ADR-0004: Separate mounts (temporary `/EUI` + `/XUI`) + full-page handoff, final path `/XUI`

Status: Accepted · Date: 2026-06-27 · Updated: 2026-06-27 (final path is `/XUI`, not `/EUI`) · Updated: 2026-07-02 (basename clause corrected to reflect the ADR-0011 HashRouter decision)

## Context
During the strangler migration the new and legacy apps run simultaneously in the deployed OpenAM webapp. Links across the migrated/unmigrated boundary must work and preserve the session. **Hard end-state requirement: the new UI must ultimately be served at the canonical `/XUI` path** (external systems, bookmarks, AM config, and OAuth2 redirect URIs reference `/XUI`). See ADR-0011 for URL backward-compat.

## Decision
- **During coexistence:** serve the new app at a **temporary `/EUI`** mount; legacy XUI keeps the canonical **`/XUI`** untouched. Crossing the boundary is a normal full-page navigation. A **route-ownership map** (`route-ownership.yml`) records which paths each app owns; cross-boundary links are plain `<a>`/redirects.
- **At cutover:** delete legacy and **deploy the new app's build output to `/XUI`**. `/EUI` is retired (optionally kept as an alias redirecting to `/XUI`). The canonical path never changes for the outside world — there is exactly **one swap, at the end**.
- **Build requirement (consequence):** the new app must be **path-relocatable** — the *same* build serves from `/EUI` during coexistence and `/XUI` after, with no rebuild. Vite `base` relative/injected at serve time (not hardcoded `/EUI`); router is `HashRouter`, no `basename` (ADR-0011); relocatability = relative Vite `base` + host-rewritten `<base href>`; all internal links relative; no absolute `/EUI/...` strings.

## Consequences
- No iframe, no dual-runtime loader, no shared-globals juggling — the simplest mechanism.
- AM auth is cookie-based (`iPlanetDirectoryPro`), so the session survives the full-page reload across the boundary.
- Legacy's canonical `/XUI` URLs keep working for the entire migration; only the final cutover swap touches `/XUI`.
- Cost: a reload when crossing the boundary; the route-ownership map must be kept honest (no silent gaps); the new build must never assume its mount path.

## Alternatives considered
- **New app at `/XUI` from day one, legacy relocated to `/XUI-legacy` + routing shim** — final path correct immediately, but you must repoint every legacy reference and run a per-route shim for the entire migration. More moving parts throughout vs. one swap at the end. Rejected.
- **Single mount, bootstrap chooses bundle per route** — seamless single URL space but both runtimes can co-reside; loader is finicky. Rejected.
- **New shell hosts legacy in an iframe** — unified chrome early but iframe nav/resize/deep-link/session glue is fragile and ships a visible seam. Rejected.
