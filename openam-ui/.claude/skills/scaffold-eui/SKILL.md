---
name: scaffold-eui
description: >-
  Use when creating new code in the new OpenAM EUI app (openam-ui-eui) or the commons-ui-next package —
  components, routes, hooks, services, forms, tables, or tests. Enforces the locked stack conventions:
  React 19 + TypeScript strict, react-bootstrap 5 + Sass, TanStack Query for server state, TanStack
  Table, rjsf, react-i18next, Vitest + MSW, path-relocatable routing, and NO Backbone/jQuery/Redux/
  RequireJS. Trigger on "add a component/page/hook/service to EUI", "scaffold a new EUI feature".
---

# Scaffold new EUI code (conventions enforcer)

Apply these conventions to all new code in `openam-ui/openam-ui-eui` and `openam-ui/commons-ui-next`.
Authoritative decisions: ADRs in `openam-ui/openam-ui-ria/docs/migration/decisions/` (paths relative to
the OpenAM repo root). When unsure of a pattern, read `context.md` there first.

## Stack (non-negotiable)
- **React 19** function components + hooks only. **TypeScript strict** — no `any` escape hatches; type
  AM REST responses.
- **react-router 7**, history routing. **Path-relocatable:** read `basename` from runtime config; never
  hardcode `/EUI` or `/XUI`; all internal links relative (ADR-0004).
- **No** Backbone, jQuery, Redux, RequireJS, Handlebars, or AMD. ES modules only.

## State (ADR-0005)
- **Server state → TanStack Query** (`useQuery`/`useMutation`) over AM `/json/...`. No fetching in
  effects-by-hand.
  - Query keys: stable, hierarchical arrays, realm-scoped — e.g. `['realm', realmId, 'sessions', params]`.
  - Centralize the fetch client in `commons-ui-next/http` (realm path, CSRF/auth headers, error
    normalization); don't re-implement fetch per feature.
- **Client/session/UI state → React Context or Zustand.** Keep it small.

## UI & forms (ADR-0006)
- **Components:** react-bootstrap 5. **Styling:** Sass (component-scoped); no LESS.
- **Data grids:** TanStack Table (not backgrid).
- **JSON-schema forms:** rjsf (`@rjsf/core` + ajv8). Custom widgets live in `commons-ui-next`.
- **i18n:** react-i18next; no hardcoded user-facing strings — use translation keys/namespaces.

## File layout
- App features: `openam-ui-eui/src/features/<feature>/` (components, hooks, queries, tests co-located).
- Reusable, app-agnostic primitives (session/http/i18n/shell/routing): `commons-ui-next/src/...` with
  **no app-specific imports** (ADR-0002), so later extraction is move-and-publish.
- Legacy `/XUI` URL redirects: `openam-ui-eui/src/compat/` (ADR-0008).

## Tests (ADR-0010)
- **Vitest + Testing Library**; mock AM REST with the **shared MSW handlers** (single source of truth —
  the same handlers run in Vitest, the `dev:mock` browser worker, and the standalone mock server). Add
  new endpoints to the shared handler set, not a one-off mock.
- Test behavior/accessibility, not implementation details.

## Checklist before finishing
- [ ] TS strict passes; no `any` / `@ts-ignore`.
- [ ] Server data via TanStack Query with a realm-scoped key; no Redux/Backbone.
- [ ] No hardcoded `/EUI` or `/XUI`; basename from config; links relative.
- [ ] Reusable bits placed in commons-ui-next with no app imports.
- [ ] Strings localized (react-i18next).
- [ ] Vitest tests added against MSW handlers; lint clean.
- [ ] CDDL license header present on new source files (match the repo's "Portions copyright [year]" style).
