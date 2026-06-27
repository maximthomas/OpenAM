# XUI Migration Plan — Modern Tech Stack

Migration of `openam-ui-ria` (the OpenAM **XUI** admin/end-user SPA) from RequireJS/Backbone/Grunt to a modern React/Vite/TypeScript stack, using an **incremental strangler-fig** approach.

This plan was produced by analyzing the current code and confirming each consequential decision. The target stack (React 19 + Vite 7 + TypeScript strict + Vitest) is a deliberate modern baseline chosen on its own merits — see ADR-0007. The sibling module `openam-ui-js-sdk` happens to use a similar stack but is treated as an **independent example only**: not a template, reference, or dependency for this migration.

---

## 1. Decisions (locked)

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| 1 | Migration strategy | **Incremental strangler-fig** | Ships value continuously, lowest risk; old and new coexist until legacy is empty |
| 2 | ForgeRock Commons UI coupling | **Self-contained new app**; reusable core isolated as a workspace package (`commons-ui-next`), **extracted upstream to the commons project later** | No AMD↔ESM bridge; prove primitives in one real consumer before promoting them |
| 3 | First slice | **Login / auth flow** | Forces building the reusable core (session, http, i18n, shell) that everything reuses; self-contained against AM auth REST; least Commons-coupled |
| 4 | Runtime coexistence | **Separate mounts** (temporary `/EUI` new, `/XUI` legacy) + **full-page handoff**; **final path `/XUI`** (new app deployed there at cutover, legacy deleted) | AM cookie session (`iPlanetDirectoryPro`) survives reloads, so no iframe, no dual-runtime loader; canonical `/XUI` URLs unchanged for the outside world |
| 8 | URL backward-compat | **Preserve legacy `/XUI` deep links** via a route-compat/redirect map | Bookmarks, AM config, OAuth2 redirect URIs reference `/XUI`; legacy is hash-routed, new app is history-routed (ADR-0008) |
| 5 | Data / client state | **TanStack Query** (server state) + **Context/Zustand** (client state); drop Redux | Admin is mostly REST CRUD; caching/dedup/invalidation for free |
| 6 | UI / styling | **react-bootstrap 5 + Sass**; **TanStack Table** for grids; **rjsf** for JSON-schema forms | Visual parity with legacy during the side-by-side period; defer any redesign |
| 7 | Language | **TypeScript (strict)** | Type-safety across the new reusable core; mainstream modern baseline |
| 9 | App packaging | **Separate Maven module `openam-ui-eui`** (sibling to `openam-ui-ria`); app renamed `app-next` → `eui`; npm workspace at `openam-ui/` | Clean toolchain/lockfile isolation from the frozen legacy module; teardown = delete the legacy module; matches the repo's per-module pattern (ADR-0009) |

---

## 2. Target stack

| Concern | Legacy | Target |
|---------|--------|--------|
| Language | ES5/ES6 `.js`/`.jsm`/`.jsx` | **TypeScript 5.8 (strict)** |
| Modules | RequireJS AMD | **ES modules** |
| Framework | Backbone + partial React | **React 19** |
| Routing | Commons UI `Router` | **react-router 7** |
| Build | Grunt + r.js + Babel | **Vite 7** |
| Styling | LESS + Bootstrap 3.3.5 | **Sass + Bootstrap 5 / react-bootstrap** |
| Templates | 187 Handlebars `.html` | **JSX** |
| Data grids | `backgrid` | **TanStack Table** |
| Schema forms | `jsoneditor` | **rjsf** (`@rjsf/core` + ajv8 validator) |
| Server data | Backbone models + small Redux | **TanStack Query** |
| Client state | Redux | **Context / Zustand** |
| i18n | i18next **1.7.3** | **i18next (latest) + react-i18next** |
| Tests | Karma + Mocha + Chai + Sinon | **Vitest + Testing Library** |
| Lint | eslint-config-forgerock | **ESLint 9 (flat) + typescript-eslint** |
| DOM lib | jQuery 3.7 | **removed** (React) |

---

## 3. Current-state inventory (measured)

- **~26k LOC, 255 files**: 209 AMD `.js`, 31 `.jsm` (ES-module-authored), 15 React `.jsx`.
- **Backbone** in 43 files; **React** already in 18 files; small **Redux** store under `store/`.
- **187 Handlebars templates** under `src/main/resources`.
- **45 distinct ForgeRock Commons UI modules** referenced (`Router`, `EventManager`, `SessionManager`, `ProcessConfiguration`, `Constants`, base views, …) — these come from the external `org.openidentityplatform.commons.ui:user` artifact, unpacked at build time.
- Area sizes: **admin = 13.4k LOC** (the bulk), **user = 5.3k**, **common = 3.8k**.
- Admin areas (`org/forgerock/openam/ui/admin/views/`): `realms`, `configuration` (global + authentication + scripting), `deployment`, `api`, `common`. Some already use React `.jsx` (sessions, agents, scripting, api).
- User areas: `login`, `anonymousProcess` (password reset / self-register / forgot username), `dashboard`, `oauth2`, `uma`, `services` (incl. `KBADelegate`).

---

## 4. New architecture

The new app is its **own Maven module** (`openam-ui/openam-ui-eui`), sibling to the legacy `openam-ui-ria` (ADR-0009). An **npm workspace** at `openam-ui/` lets the `eui` app consume the local `commons-ui-next` package via `workspace:*` until it is extracted upstream.

```
openam-ui/
  package.json                     ← npm workspace root (members: openam-ui-eui, commons-ui-next)   [new]
  pom.xml                          ← Maven reactor: add <module>openam-ui-eui</module>
  commons-ui-next/                 ← new modern "Commons", local workspace package
    package.json                     name: "@openidentityplatform/commons-ui-next"
    src/
      session/   SessionService — AM /json/authenticate (callbacks), /json/sessions
      http/      fetch client — realm path, CSRF/auth headers, error normalization
      constants/ endpoints, config keys
      i18n/      i18next + react-i18next setup, namespace loading
      shell/     AppShell, Header, Footer, RealmSwitcher, nav (generic pieces)
      routing/   route-ownership helpers, cross-boundary <CrossLink>
  openam-ui-eui/                   ← NEW Maven module: the new Vite/React/TS app   [new]
    package.json                     name: "eui" (workspace member)
    pom.xml                          frontend-maven-plugin → vite build; assembly → webapp (/EUI, then /XUI)
    src/
      main.tsx, router.tsx           path-relocatable (base/basename from runtime config)
      features/{login,dashboard,realms,...}
      compat/    legacy /XUI hash-route → new-route redirect map (ADR-0008)
      imports "@openidentityplatform/commons-ui-next"
  openam-ui-ria/                   ← the legacy app (frozen except security fixes, deleted at the end)
    src/ (legacy XUI)
    docs/migration/                  ← migration plan + ADRs live here
```

**Why its own module:** independent build/release, its own `package.json`/toolchain (no entanglement with the legacy Grunt/RequireJS manifest), and teardown at cutover is "delete the `openam-ui-ria` module" rather than untangling two stacks in one tree — matching the repo's existing per-module pattern (ADR-0009).

**Why a workspace package now, extraction later:** the reusable core (session, http, i18n, shell) is built behind a clean boundary with **no app-specific imports** from day one. "Extract to commons" then becomes _move the folder into the commons repo + publish + flip the import from `workspace:*` to the published version_ — not a refactor. The legacy XUI keeps consuming the **old** `commons.ui:user` artifact untouched throughout.

### Coexistence / deployment

- **Final path is `/XUI`.** During coexistence the new app is served at a **temporary `/EUI`**; legacy XUI keeps the canonical **`/XUI`** untouched. At cutover the new build is deployed to **`/XUI`** and legacy is deleted — one swap at the end (ADR-0004).
- **Path-relocatable build:** the *same* build serves `/EUI` then `/XUI`, no rebuild. Vite `base` relative/injected (not hardcoded `/EUI`); react-router `basename` from runtime config; internal links relative; no absolute `/EUI/...` strings.
- Built by `frontend-maven-plugin` running `vite build`, packaged into the webapp (at `/EUI` during coexistence, `/XUI` at cutover).
- A **route-ownership map** records which paths are migrated. Legacy nav links to migrated areas point at `/EUI/...`; new-app links to not-yet-migrated areas point at `/XUI/...`. Crossing the boundary is a normal full-page navigation — the **AM cookie keeps the session alive**, so no bridge/iframe/dual-runtime.
- **Preserve legacy `/XUI` deep links:** legacy is hash-routed (`#login`, `#dashboard/`, password-reset/register regexes); existing URLs (bookmarks, AM config, OAuth2 redirect URIs) must keep resolving. The new app ships a **route-compat/redirect map** (ADR-0008), grown per slice.
- Cutover = deploy the new app to `/XUI`, retire `/EUI` (or alias it to `/XUI`), then delete legacy.

---

## 5. Phased roadmap

### Phase 0 — Foundation (the rails)
- Create the **`openam-ui-eui` Maven module** + npm workspace at `openam-ui/`; scaffold the `eui` app (Vite + React 19 + TS strict + react-router 7 + Vitest + ESLint 9) fresh from the standard Vite React-TS template.
- Create `commons-ui-next` workspace package skeleton.
- Wire `frontend-maven-plugin` to `vite build` `/EUI` into the packaged webapp; keep the legacy Grunt build running in parallel.
- Establish the route-ownership map + `<CrossLink>` helper.
- **Mock AM backend (ADR-0010):** shared MSW handlers for AM REST → run the **new EUI** in-browser (`npm run dev:mock`, service worker) and the **legacy XUI** in-browser (static serve + proxy to a standalone mock server), both **without OpenAM**.
- CI: `eslint` + `vitest` for the new app.

### Phase 1 — Login / auth slice (proves the whole pattern)
- Build the reusable core: **SessionService** (`/json/authenticate` callback flow, `/json/sessions`), **http client** (realm path, CSRF/auth headers, error normalization), **i18n**, **shell** skeleton (header/footer/nav), error handling.
- Migrate: `RESTLoginView` + login dialog, `anonymousProcess` (password reset, self-registration, forgot username).
- Deploy `/EUI` side by side; legacy `/XUI` login redirects to `/EUI/login`.
- Lock in testing patterns (Vitest + Testing Library + MSW for AM REST mocking).

### Phase 2 — User self-service (~5.3k LOC)
- `dashboard`, `oauth2` token views, `uma` sharing, profile/KBA (`services/KBADelegate`).
- First real CRUD: establishes TanStack Query + first **rjsf** schema-form usage.

### Phase 3 — Admin (~13.4k LOC, the bulk — split into sub-slices)
Order by isolation/value; each sub-slice is independently shippable behind the route map:
1. **Realms**: realm list, create, overview.
2. **Authentication**: chains/modules/trees, services.
3. **Applications / Agents** (some `.jsx` exists — reuse), **Data Stores**.
4. **Sessions** (already React), **Scripting** (already React), **API/OAuth2** views.
5. **Global configuration** + `deployment`.

Admin is schema-driven config — **rjsf + TanStack Table heavy**. Do an **rjsf gap analysis early** (custom `jsoneditor` widgets, conditional schemas, inline validation) before committing screen-by-screen.

### Phase 4 — Cutover & cleanup
- Migrate remaining edges; **deploy the new app to the canonical `/XUI`**, retire `/EUI` (or alias it to `/XUI`).
- Verify the **URL-compat map** covers all must-preserve `/XUI` deep links (from the Phase 0 audit).
- Relocate `docs/migration/` out of `openam-ui-ria` (into `openam-ui-eui` or archive) — they live in the legacy module.
- **Delete the whole `openam-ui-ria` module** and remove it from the reactor (ADR-0009): legacy `src/` (Backbone, Handlebars, RequireJS `main.js`), Grunt/r.js/Karma/Babel, the `org.openidentityplatform.commons.ui:user` dependency, and the `target/` compose pipeline all go with it.

### Phase 5 — Extract `commons-ui-next` upstream
- Move the workspace package into the Open Identity Platform commons repo; publish it (npm package + optional Maven `www` zip to match current packaging conventions).
- Flip the `eui` app's import from `workspace:*` to the published version. No consumer code changes.

---

## 6. Cross-cutting concerns

- **JSON-schema forms** are the riskiest parity item: most AM admin config screens are auto-generated from JSON schema via `jsoneditor`. rjsf covers the common case; budget for custom widgets/templates and AM's conditional/`enum`-driven schemas. Validate in Phase 2 before the admin bulk.
- **i18n**: migrate `src/main/resources/locales` to modern i18next namespaces; the 1.7.3 → latest jump changes the API.
- **Session/CSRF/realm semantics**: nail header/cookie/realm-path handling in `commons-ui-next/http` in Phase 1 — every later slice depends on it.
- **Maven/packaging**: the new build must drop assets where the webapp expects them; configure `frontend-maven-plugin` + assembly to emit into `/EUI` during coexistence and `/XUI` at cutover. Keep the build path-relocatable so this is a deploy-location change, not a rebuild.
- **URL backward-compat**: legacy `/XUI` is hash-routed; preserve externally-referenced deep links (auth/OAuth2 flows especially) via the route-compat/redirect map (ADR-0008), grown per slice.
- **Testing**: Vitest + Testing Library + MSW (mock AM REST). Port the 17 legacy specs' intent where still relevant; don't port Karma/RequireJS scaffolding.
- **Local dev without OpenAM (ADR-0010)**: one set of MSW handlers models the AM REST contract and runs in three modes — Vitest (node), the EUI browser worker (`dev:mock`), and a standalone `@mswjs/http-middleware` server. The legacy XUI runs against the standalone server via a dev proxy (static assets, no `OPENAM_HOME`/Tomcat). Handlers grow per slice; seed fixtures by recording real AM responses to limit drift.

---

## 7. Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| Commons UI surface bigger than the 45 referenced modules suggest | Reimplement **only what a slice actually imports**, lazily; don't port commons wholesale |
| rjsf can't match `jsoneditor` custom widgets / conditional schemas | Gap analysis in Phase 2, before the admin bulk; build a small custom-widget set in `commons-ui-next` |
| Admin breadth (13.4k LOC) stalls the migration | Keep the route-ownership map honest — **`log`/track every unmigrated route**, no silent gaps; ship sub-slices independently |
| Dual-maintenance tax during coexistence | Freeze legacy XUI except security fixes; all new work lands in `/EUI` |
| Visual seam between `/EUI` and `/XUI` | react-bootstrap 5 keeps parity; defer any redesign until after cutover |
| Breaking external `/XUI` deep links at cutover | Audit `/XUI` references in Phase 0; ship a route-compat/redirect map (ADR-0008); keep the new build path-relocatable so `/XUI` is reused, not changed |

---

## 8. Definition of done

- **New UI served at the canonical `/XUI`**; the temporary `/EUI` retired (or aliased to `/XUI`).
- Must-preserve legacy `/XUI` deep links still resolve (URL-compat map verified).
- Legacy Backbone/RequireJS/Grunt/Karma/Handlebars deleted; `commons.ui:user` dependency dropped.
- `commons-ui-next` extracted to the commons project and consumed as a published artifact.
- Test + lint green in CI on the new stack.
</content>
