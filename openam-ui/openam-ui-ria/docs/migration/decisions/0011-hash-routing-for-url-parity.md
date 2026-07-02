# ADR-0011: New app uses HashRouter for `/XUI` URL parity

Status: Accepted · Date: 2026-07-02 · Supersedes: ADR-0008

## Context
ADR-0008 chose history (path) routing for the new app and planned a route-compat/redirect map to translate legacy `/XUI` hash-form deep links (`#login`, `#dashboard/`, etc.) to the new history-routed paths (`/login`, `/dashboard/`). This works technically but introduces friction:

- Bookmarks, AM config, and OAuth2 redirect URIs all use the `#`-fragment form; the compat map must translate every one of them.
- The server must handle direct navigation to sub-paths (e.g. `/EUI/login`) returning the SPA root document — a deploy-time concern that hash routing avoids entirely.
- The compat map grows per slice, creating sustained maintenance cost throughout the migration.

Since the legacy `/XUI` is itself hash-routed and the goal is maximum backward compatibility with minimal operational surface, switching to `HashRouter` (react-router 7) closes the loop: both apps share the same `#`-fragment URL convention.

## Decision
The new app uses **`HashRouter`** (react-router 7) instead of `BrowserRouter`.

Key consequences of this change:

1. **No router `basename`.** With `HashRouter` the mount path (`/EUI`, `/XUI`) lives in the real URL path, not the hash; react-router sees only the fragment (`/login`, `/dashboard`). The `basename` prop is therefore unused and the `getBasename()`/`runtime.ts` machinery is removed.

2. **Asset relocatability is unchanged.** Path-relocatability for assets still comes from Vite `base: './'` anchored by the host-rewritten `<base href>` in `index.html` — independent of the router. No rebuild is needed to move from `/EUI` to `/XUI`.

3. **URL form.** react-router's `HashRouter` produces `#/login` (with a leading slash in the fragment), while legacy uses `#login` (no leading slash). Legacy bookmarks using the no-slash form are bridged by the hash-spelling normalization map (P1-10), which now handles only this normalization rather than a full hash→history translation.

4. **No server-side deep-link handling needed.** The server always serves the SPA root document for the mount path; client-side routing is entirely in the fragment.

## Consequences
- Legacy `/XUI` deep links (`#login`, `#!/...`, regex-pattern routes) continue to resolve after cutover with only the `#login` → `#/login` spelling difference handled by the compat map (P1-10).
- The compat map (P1-10) is substantially simpler: no hash→history translation, only `#login`/`#!/...` normalization to `#/login`.
- `src/config/runtime.ts` and its test `runtime.test.ts` are deleted (dead code once `basename` is unused).
- The P0-1 scaffold note about "react-router basename from runtime config" and the P0-4 cross-link note referencing ADR-0008 are updated to reflect hash routing.
- The three-test `crossLink.test.tsx` suite retains the same assertions; the basename-specific test is reframed as "same-app link renders the resolver href, not a mount-prefixed cross-boundary URL."

## Alternatives considered
- **Keep history routing + full compat map (ADR-0008)** — handled every case but required translating the entire legacy hash-route inventory per slice and added a server deep-path concern. Superseded by this ADR.
- **Custom `createHashHistory` with `hashType: 'noslash'` to emit `#login`** — exact URL parity, but non-idiomatic for react-router 7, fragile, and the `#/login` form is equally usable. Rejected; compat map is the right place to handle legacy spellings.
