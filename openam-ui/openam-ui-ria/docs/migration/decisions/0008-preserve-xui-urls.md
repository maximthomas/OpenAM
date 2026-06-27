# ADR-0008: New UI served at `/XUI`, preserving legacy deep-link URLs

Status: Accepted · Date: 2026-06-27

## Context
The new UI must end up at the canonical `/XUI` path (ADR-0004). Beyond the base path, **existing `/XUI` deep links must keep resolving after cutover** — bookmarks, AM server config, OAuth2 redirect URIs, and docs reference specific URLs. Legacy XUI is **hash-routed**: route tables (`config/routes/*.js`) map patterns like `login`, `dashboard/`, `oauth2/tokens`, `confirmLogin/`, and regexes such as `/continuePasswordReset(\/[^&]*)(&.+)?/` against the URL fragment (`/XUI#login`, `/XUI#dashboard/...`). react-router 7 uses history (path) routing by default, so the URL shape changes unless we bridge it.

## Decision
The new app owns `/XUI` after cutover and ships a **URL backward-compat layer**:
- A **route-compat map** translating legacy hash routes to the new app's routes (e.g. `#login` -> `/login`, `#dashboard/` -> `/dashboard`, `#!/...` forms, and the regex/anonymous-process URLs like password reset / self-registration / logout / login failure / session expired).
- On load, if a legacy-style fragment/URL is present, **redirect to the new equivalent** (client-side, preserving query/fragment params the flows depend on).
- Cover the full legacy route inventory from `config/routes/AMRoutesConfig.js`, `config/routes/admin/*`, `config/routes/user/*` (plus the Commons UI base routes). The route-ownership map is the checklist.

## Consequences
- External references to `/XUI` deep links keep working — no coordinated change to AM config, OAuth2 clients, bookmarks, or docs.
- One-time cost: build and maintain the compat map; it must stay in sync as routes migrate (each slice adds its legacy->new mappings).
- Decide per route whether the legacy URL keeps redirecting **permanently** or only through a deprecation window — default to permanent for externally-referenced URLs (auth/OAuth2 flows), best-effort for internal admin deep links.

## Open / to confirm during Phase 0–1
- **Audit who actually references `/XUI` URLs** (AM config, OAuth2 redirect URIs, docs, integrations) to size the must-preserve set vs. best-effort.
- Confirm whether any consumer depends on the literal `#` fragment form vs. just the `/XUI` base — affects whether we need fragment-parsing or only path redirects.

## Alternatives considered
- **Reuse `/XUI` base path only, let old deep links break** — simplest, but breaks bookmarks/AM config/OAuth2 redirects. Rejected per requirement.
- **Keep hash routing in the new app to mirror legacy URLs 1:1** — perfect URL parity but locks the modern app into a legacy routing style and HashRouter's limitations. Rejected in favor of a compat/redirect map onto clean history routes.
