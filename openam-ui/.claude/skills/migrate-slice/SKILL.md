---
name: migrate-slice
description: >-
  Use when migrating a route/feature from the legacy OpenAM XUI (openam-ui-ria, RequireJS/Backbone)
  to the new EUI app (openam-ui-eui, React/Vite/TS). Drives the full strangler-fig loop for one slice:
  pick the route, build only the needed reusable primitives, mock the AM endpoints, implement in EUI,
  preserve the legacy /XUI URL, test against the mock, and update the route-ownership map. Trigger on
  requests like "migrate the login slice", "port the dashboard to EUI", "move <route> off Backbone".
---

# Migrate one slice (legacy XUI → new EUI)

This skill executes the incremental strangler-fig migration for **one route/feature**. The committed
plan is the source of truth — **read it, do not re-derive**. Paths below are relative to the **OpenAM
repo root**.

## 0. Orient (always do this first)
1. Read `openam-ui/openam-ui-ria/docs/migration/context.md` (start-here orientation).
2. Read `openam-ui/openam-ui-ria/docs/migration/route-ownership.yml` and `tasks.yml` (current status).
3. Skim the ADRs you'll touch in `openam-ui/openam-ui-ria/docs/migration/decisions/`:
   ADR-0002 (commons-ui-next boundary), 0004 (mounts/path-relocatable), 0005 (state), 0006 (UI libs),
   0008 (URL compat), 0009 (module layout), 0010 (mock server).

## 1. Pick & scope the slice
- Identify the target route. If unspecified, choose the next `status: planned` route in
  `route-ownership.yml`, respecting `slice`/phase order and `depends_on`.
- Find the legacy implementation: legacy views live under
  `openam-ui/openam-ui-ria/src/main/js/org/forgerock/openam/ui/...`; routes in
  `openam-ui/openam-ui-ria/src/main/js/config/routes/`. Note the AM REST endpoints it calls and the
  legacy hash URL(s) it answers.
- Set the route `status: in_progress` in `route-ownership.yml`.

## 2. Build only the primitives this slice needs (commons-ui-next)
- Implement reusable pieces (session, http, i18n, shell, routing) in
  `openam-ui/commons-ui-next/` **with NO app-specific imports** (ADR-0002). Reimplement *only* what this
  slice actually uses — do not port Commons UI wholesale.

## 3. Mock the AM endpoints (ADR-0010)
- Add/extend the **shared MSW handlers** (the single source of truth) for every AM REST call this slice
  makes (`/json/authenticate`, `/json/serverinfo/*`, `/json/sessions`, realm-scoped CRUD, …).
- Seed realistic fixtures (record from a real AM if available). These same handlers must serve Vitest,
  the EUI browser worker, and the standalone mock server — keep them in sync.

## 4. Implement in the EUI app (openam-ui-eui)
- Apply the **scaffold-eui** conventions for all new code (stack rules, file layout, query keys).
- **Server state → TanStack Query**; client/session/UI state → Context or Zustand. No Redux, Backbone,
  jQuery, or RequireJS (ADR-0005).
- **UI:** react-bootstrap 5 + Sass; grids → TanStack Table; JSON-schema forms → rjsf (ADR-0006).
- **Path-relocatable:** never hardcode `/EUI`; basename from runtime config; internal links relative
  (ADR-0004).
- i18n via react-i18next; migrate the slice's locale strings.

## 5. Preserve the legacy /XUI URL (ADR-0008)
- Add the legacy hash route(s) for this slice to the **route-compat/redirect map** in
  `openam-ui-eui` (e.g. `#login` → `/login`), preserving query/fragment params the flow depends on.

## 6. Test
- Write **Vitest + Testing Library** tests against the MSW handlers from step 3. Cover the legacy
  spec's intent where still relevant; do not port Karma/RequireJS scaffolding.
- Manually verify in a browser via `npm run dev:mock` (EUI, no OpenAM). If a parity question arises,
  use the `webapp-testing` skill against old vs new through the mock.

## 7. Land & record
- During coexistence: legacy `/XUI` links to this area redirect to `/EUI/...`; EUI links to
  not-yet-migrated areas point at `/XUI/...` (full-page handoff — the AM cookie keeps the session).
- Set the route `status: migrated` in `route-ownership.yml`; update the matching task in `tasks.yml`.
- Run lint + tests; summarize what moved and what endpoints were mocked.

## Guardrails (hard rules)
- No new Backbone / RequireJS / jQuery / Redux / Handlebars anywhere.
- No hardcoded `/EUI` path — the build must serve `/EUI` then `/XUI` unchanged.
- commons-ui-next stays free of app-specific imports.
- Preserve the CDDL license header + "Portions copyright [year]" pattern on any legacy file you touch.
- If a decision isn't covered by an ADR, ask — don't invent; if you change a decision, supersede the ADR.
