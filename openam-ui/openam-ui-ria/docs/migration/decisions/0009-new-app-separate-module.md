# ADR-0009: New app as a separate Maven module `openam-ui-eui`

Status: Accepted · Date: 2026-06-27

## Context
The new app needs a home relative to the legacy `openam-ui-ria` module. Options weighed: (A) same module + shared `package.json`; (B) same module + separate `package.json` in a subdir; (C) its own Maven module. The legacy `openam-ui-ria/package.json` carries only Grunt/RequireJS/Karma/Babel devDependencies (runtime libs come from Maven `commons.ui.libs:*`), so sharing one manifest would entangle two ESLint majors, two lockfile strategies, and collide build scripts — and force a surgical teardown later. The repo already has a per-module precedent (`openam-ui-ria`, `openam-ui-js-sdk`, `openam-ui-api` are each their own module).

## Decision
Build the new app as its **own Maven module `openam-ui/openam-ui-eui`** (sibling to `openam-ui-ria`), added to the `openam-ui` reactor. It has its own `package.json` (app name `eui`), its own Vite/TS/Vitest/ESLint-9 toolchain, and its own `pom.xml` wiring `frontend-maven-plugin` (`vite build`) + assembly to emit into the webapp (`/EUI` during coexistence, `/XUI` at cutover — ADR-0004).

The reusable core `commons-ui-next` stays a separate package consumed by `eui`. Introduce an **npm workspace at `openam-ui/`** (members: `openam-ui-eui`, `commons-ui-next`) so `eui` resolves `commons-ui-next` via `workspace:*` locally until it is extracted upstream (ADR-0002).

The placeholder name **`app-next` is renamed to `eui`** everywhere.

## Consequences
- Clean toolchain isolation — no shared install/lockfile/lint with the frozen legacy module.
- Independent build/release; teardown at cutover = delete the `openam-ui-ria` module, not untangle two stacks in one tree.
- Cost: a new `pom.xml` + reactor entry, and a new `openam-ui/package.json` workspace root (none exists today).
- The migration docs/ADRs continue to live in `openam-ui-ria/docs/migration/` (the module being strangled); the `eui` module links back to them.

## Alternatives considered
- **(A) Same module, shared `package.json`** — lowest setup but entangles lint/scripts/lockfile across two incompatible toolchains and needs a dirty teardown. Rejected.
- **(B) Same module, separate `package.json` in a subdir** — isolates toolchains and keeps one artifact, but co-locates active + frozen code in one module and one `target/`. Reasonable, but a separate module is cleaner and matches the repo pattern. Rejected in favor of C.
