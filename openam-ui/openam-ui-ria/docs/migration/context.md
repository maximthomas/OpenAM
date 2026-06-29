# Migration context — read first

Fast orientation for a fresh session picking up the XUI migration. For the full plan see [`../../MIGRATION.md`](../../MIGRATION.md); for decisions see [`decisions/`](decisions/).

## What we're doing
Migrating `openam-ui-ria` (the OpenAM **XUI** SPA) off RequireJS/Backbone/Grunt onto **React 19 + Vite 7 + TypeScript (strict) + react-router 7 + Vitest**, via an **incremental strangler-fig**. During coexistence the new app mounts at a **temporary `/EUI`**; legacy stays at `/XUI`; they run side by side until legacy is empty. **At cutover the new app is deployed to the canonical `/XUI`** (legacy deleted) — `/EUI` is temporary, `/XUI` is the final path (ADR-0004, ADR-0008). The new build must be **path-relocatable** (same build serves `/EUI` then `/XUI`).

## The two facts that drive everything
1. **The target stack is a deliberate modern baseline.** React 19 + Vite 7 + TypeScript (strict) + react-router 7 + Vitest, chosen on its own merits (see ADR-0007). This app is self-contained — do **not** treat `openam-ui-js-sdk` (or any other module) as a template to copy; build the scaffold fresh.
2. **The hard knot is the external Commons UI dependency.** XUI references **45 distinct `org.forgerock/commons/...` modules** (Router, EventManager, SessionManager, ProcessConfiguration, Constants, base views) from the Maven artifact `org.openidentityplatform.commons.ui:user`, unpacked at build time. The new app must **not** depend on it — we reimplement the minimal needed primitives in a workspace package `commons-ui-next` and **extract it to the commons project later**.

## Current-state inventory (measured)
- ~26k LOC, 255 files: 209 AMD `.js`, 31 `.jsm`, 15 React `.jsx`.
- Backbone in 43 files; React already in 18; small Redux store under `src/main/js/store/`.
- 187 Handlebars templates under `src/main/resources`.
- Area sizes: **admin 13.4k LOC** (the bulk), **user 5.3k**, **common 3.8k**.

## Where things live
- Legacy app: `src/main/js/` (AMD) + `src/main/resources/` (templates/locales/css). Entry: `src/main/js/main.js`. Bootstrap manifest: `config/AppConfiguration.js`. Routes: `config/routes/`. Event handlers: `config/process/AMConfig.js`.
- Legacy tests: `src/test/js/**/*Test.js` (Karma/Mocha).
- Build: `Gruntfile.js`, `pom.xml` (frontend-maven-plugin runs the npm/Grunt build).
- New app (to be created): its **own Maven module** `openam-ui/openam-ui-eui/` (app name `eui`), sibling to this module (ADR-0009). Reusable core: `openam-ui/commons-ui-next/`, consumed via an npm workspace at `openam-ui/`.
- These migration docs/ADRs stay here in `openam-ui-ria/docs/migration/` (the module being strangled).

## Conventions for new code
- TypeScript strict; ES modules; React function components + hooks.
- Server data via **TanStack Query** (`useQuery`/`useMutation` over AM `/json/...`); client/session state via Context or Zustand. **No Redux, no Backbone, no jQuery.**
- UI: **react-bootstrap 5 + Sass** (parity with legacy during coexistence). Grids: **TanStack Table**. JSON-schema forms: **rjsf** (`@rjsf/core` + ajv8).
- Tests: **Vitest + Testing Library + MSW** (mock AM REST). Don't port Karma/RequireJS scaffolding.
- **Run without OpenAM (ADR-0010):** one shared set of MSW AM-REST handlers powers Vitest, the EUI browser worker (`npm run dev:mock`), and a standalone mock server. The legacy XUI also runs in-browser with no AM (static serve + proxy to the mock). Add new endpoints to the shared handlers as each slice needs them.
- Reusable primitives (session/http/i18n/shell) go in `commons-ui-next` with **no app-specific imports**, so later extraction is a move-and-publish.
- Preserve the CDDL license header on files.

## Status
See [`tasks.yml`](tasks.yml). **Phase 0 is in progress**: P0-0 through P0-8 are done — the `openam-ui/openam-ui-eui` Maven module, the `openam-ui/` npm workspace, the `eui` app scaffold, the `commons-ui-next` package, the Maven build wiring, the route-ownership map + `<CrossLink>` helper, CI lint/test, the `/XUI` URL audit, the shared MSW AM-REST handlers (`commons-ui-next/src/mock`), and the EUI browser mock mode (`npm run dev:mock`) are all in place. Remaining: P0-9 (standalone mock server + legacy XUI no-AM harness).

## Watch out for
- **Final path is `/XUI`, not `/EUI`** — `/EUI` is only the coexistence mount. Never hardcode `/EUI` in the new app (Vite `base` relative/injected, react-router `basename` from runtime config). Legacy `/XUI` deep links (hash-routed: `#login`, `#dashboard/`, password-reset/register regexes) must keep resolving — build a route-compat/redirect map (ADR-0008).
- **rjsf vs legacy `jsoneditor` parity** — most admin config screens are JSON-schema-generated; do a gap analysis in Phase 2 before the admin bulk.
- **Session/CSRF/realm header semantics** — nail in `commons-ui-next/http` in Phase 1; everything depends on it.
- AM auth is **cookie-based** (`iPlanetDirectoryPro`), which is why cross-app full-page handoff is safe.
