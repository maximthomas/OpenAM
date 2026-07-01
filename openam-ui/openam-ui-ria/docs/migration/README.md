# XUI Migration — documentation index

Living source of truth for migrating `openam-ui-ria` (XUI) from RequireJS/Backbone/Grunt to React/Vite/TypeScript via an incremental strangler-fig.

| File | Purpose |
|------|---------|
| [`../../MIGRATION.md`](../../MIGRATION.md) | The full narrative plan (stack, roadmap, risks) |
| [`context.md`](context.md) | **Start here in a new session** — fast orientation: current state, where things live, conventions |
| [`tasks.yml`](tasks.yml) | Structured, phased task tracker with status + dependencies |
| [`route-ownership.yml`](route-ownership.yml) | **Strangler route map** — which URLs are served by `/EUI` (new) vs `/XUI` (legacy). Update on every slice |
| [`decisions/`](decisions/) | ADRs — one per locked architectural decision |
| [`reference/`](reference/) | Reference inventories — `eui-foundation.md` (new-app API surface), `legacy-login.md` (legacy login feature map, feeds P1-5b) |
| [`glossary.md`](glossary.md) | Domain/stack terms (XUI, Commons UI, realm, rjsf, strangler-fig, …) |

## How to use this across sessions
Load on demand — don't bulk-read everything:
1. Read `context.md` first; it's the digest and usually all you need.
2. Then load **only** the doc your task calls for: `route-ownership.yml` to scope a slice / see what's migrated; `tasks.yml` for status or picking the next task; a **single** ADR (pick via [`decisions/README.md`](decisions/README.md)) before changing an architectural choice; `../../MIGRATION.md` only for the full roadmap.
3. If you change an architectural choice, supersede the ADR — don't silently diverge.
4. Update `tasks.yml` status and `route-ownership.yml` as slices land.
