# XUI Migration — documentation index

Living source of truth for migrating `openam-ui-ria` (XUI) from RequireJS/Backbone/Grunt to React/Vite/TypeScript via an incremental strangler-fig.

| File | Purpose |
|------|---------|
| [`../../MIGRATION.md`](../../MIGRATION.md) | The full narrative plan (stack, roadmap, risks) |
| [`context.md`](context.md) | **Start here in a new session** — fast orientation: current state, where things live, conventions |
| [`tasks.yml`](tasks.yml) | Structured, phased task tracker with status + dependencies |
| [`route-ownership.yml`](route-ownership.yml) | **Strangler route map** — which URLs are served by `/EUI` (new) vs `/XUI` (legacy). Update on every slice |
| [`decisions/`](decisions/) | ADRs — one per locked architectural decision |
| [`glossary.md`](glossary.md) | Domain/stack terms (XUI, Commons UI, realm, rjsf, strangler-fig, …) |

## How to use this across sessions
1. Read `context.md` and `tasks.yml` first.
2. Check `route-ownership.yml` to see what's already migrated.
3. Consult the relevant ADR before changing an architectural choice — if you change one, supersede the ADR, don't silently diverge.
4. Update `tasks.yml` status and `route-ownership.yml` as slices land.
