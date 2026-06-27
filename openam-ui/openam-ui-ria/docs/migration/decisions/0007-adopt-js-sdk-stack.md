# ADR-0007: Target a modern React / Vite / TypeScript stack

Status: Accepted · Date: 2026-06-27 · Updated: 2026-06-27 (de-coupled from `openam-ui-js-sdk`)

## Context
"Migrate to a modern stack" needs a concrete, named target so Phase 0 isn't a bikeshed. The choice should stand on the current state of the front-end ecosystem and the needs of this app (SPA, REST against AM, schema-driven admin screens, long-lived), **not** on copying another module. `openam-ui-js-sdk` happens to use a similar stack, but it is an independent example — we do not template, clone, or depend on it.

## Decision
Build the new app on **React 19, react-router 7, Vite 7, TypeScript 5.x (strict), Vitest, ESLint 9 (flat config), Sass** — current stable, widely-supported choices at scaffolding time. Scaffold fresh from the standard Vite React-TS template and configure it for this app's needs; do not copy another module's config.

## Consequences
- Mainstream, well-documented baseline with a large hiring/knowledge pool and active upgrade path.
- Vite + Vitest give fast dev/test loops; TS strict gives type-safety across the new reusable core (`commons-ui-next`).
- We own our toolchain config outright — no implicit coupling to another module's choices or upgrade cadence.
- Pin versions at scaffold time and manage upgrades deliberately.

## Alternatives considered
- **Copy `openam-ui-js-sdk`'s setup** — rejected: it is an independent module; coupling our config to it creates a false dependency and drags its constraints into ours.
- **Vue** — an empty `src/main/vue` directory exists but has no files and no git history; not a real direction. Rejected.
- **Angular / other** — heavier, no reuse with the rest of the new front-end direction. Rejected.
- **Keep Backbone/RequireJS, modernize tooling only** — covered and rejected in ADR-0001.
