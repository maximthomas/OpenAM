# P1-5k — Login parity (GATE): session-timeout re-auth dialog + monitor + guard

**Depends on:** P1-5f, P1-5j, P1-5h, P1-5i · **Parity gate** · Read [`README.md`](README.md) (shared research) first.

> **Split (2026-07-03).** Carved out of the original P1-5f (see [`P1-5f-error-logout-views.md`](P1-5f-error-logout-views.md)).
> This sub-task inherits the **parity gate**: the session-timeout re-auth dialog is a legacy login feature, so login
> is not at parity until it lands. When this lands (and only then), flip `route-ownership.yml` login → `status: migrated`
> and keep the TS mirror (`openam-ui-eui/src/config/routeOwnership.ts`) in sync — in one atomic commit, together with the
> ancillary auth routes.
>
> **Gate preconditions** (all must be `done` before the flip): **P1-5f** (return/logout views + failure-nav),
> **P1-5j** (remember-me), **P1-5h** (serverinfo `zeroPageLogin` contract fix + referrer whitelist), **P1-5i**
> (RedirectCallback return-leg resume). P1-5h and P1-5i are already `done`. P1-5g (ScriptTextOutput) is **not** a gate
> precondition (deferred as security-sensitive).

## Goal

The session-timeout re-authentication modal and the background monitor that triggers it, plus the parity-gate
route-ownership flip. This is the last login-parity sub-task.

## Legacy reference
- **RESTLoginDialog.js** (46) + **AMConfig.js** 271–309 (`EVENT_SHOW_LOGIN_DIALOG`) — sets
  `Configuration.backgroundLogin = true`, `SessionToken.remove()` (clears the stale token), re-renders `RESTLoginView`
  inside a non-closable `BootstrapDialog` titled `common.form.sessionExpired`. **Role branch** in `AMConfig`:
  `loggedUser.hasRole("ui-self-service-user")` → full `logout()` + route to SessionExpired; **else (admin/unknown)
  → modal re-auth**. `RESTLoginView.js:74` reads `Configuration.backgroundLogin` to render inside the dialog.
- The dialog reuses the **same login engine** as the full-page flow (just hosted in a modal) — no separate auth path.

## Locked decisions (planning, 2026-07)
- **Trigger = a `useSessionMonitor` hook** polling `isSessionValid`/`getTimeLeft` against `getToken()`, run in the
  authenticated shell. On expiry: self-service role → navigate `/sessionExpired` (P1-5f's view); else (admin/unknown)
  → open the modal. **No transport-level 401 interceptor** (the transport returns raw Responses; EUI has no data
  surface to intercept yet).
- **Role source** — `isSelfServiceUser(sessionInfo)` **defaults false → modal** (legacy `else` fallback). Real role
  wiring lands with the user/profile slice (**P2-4**); documented limitation until then. `AmSessionInfo` surfaces no
  role field yet.

## Current state (reuse, don't duplicate)
- `commons-ui-next/session`: `isSessionValid(transport, token)`, `getTimeLeft(transport, token)`,
  `logout(transport, token)`, `getToken`/`setToken`/`clearToken`, `createSessionService(transport)`.
  `AmSessionInfo` = `{username, universalId, realm, properties, latestAccessTime, maxSessionExpirationTime,
  maxIdleExpirationTime}` — **no role field**.
- `commons-ui-next/auth`: `useAuthenticationFlow` is an **eui** hook (`useLogin.ts`) — reuse it directly for the
  modal; `CallbackForm` is the commons renderer. Failure is a value; only network errors throw.
- eui `App.tsx`: full-chrome `AppShell` group wraps `/` (Home); auth-shell group wraps `/login`+`/confirmLogin`
  (+ `/failedLogin`/`/sessionExpired`/`/logout` once P1-5f lands). `amTransport` in `src/config/transport.ts`.
- Mock (`commons-ui-next/src/mock/sessions.ts`): GET/`getSessionInfo` → `DEMO_SESSION` (valid `DEMO_TOKEN_ID`) or 401;
  `POST …?_action=logout` → `LOGOUT_RESULT`. Needs an **expiring-session** scenario for the monitor test (see step 4).
- Drift guard (`routeOwnership.test.ts`) checks **path/owner only, not status** — the yaml status flip needs no TS
  change for `login` (owner already `eui`); the ancillary-route `owner` flips do need matching TS-mirror edits.

## Implementation steps (ordered, each independently testable)

1. **`useSessionMonitor.ts`** (eui `features/auth/`) — interval poll of `isSessionValid`/`getTimeLeft` against
   `getToken()`; fires `onExpiry` once; pauses when there is no token; clears its timer on unmount.
2. **`SessionTimeoutDialog.tsx`** (eui `features/auth/`) — non-closable react-bootstrap `Modal`
   (`backdrop="static"`, no close button) reusing `useAuthenticationFlow` + `CallbackForm`; title
   `common.form.sessionExpired`. On success: `setToken(tokenId)` + `onResume()` (close, **no navigation** — the user
   stays on the page they were on). Clears the stale token before re-auth (legacy `SessionToken.remove()`).
3. **`SessionGuard.tsx`** (eui `features/auth/`) — runs `useSessionMonitor` for authenticated routes; on expiry:
   `isSelfServiceUser(sessionInfo)` → navigate `/sessionExpired`, else open `SessionTimeoutDialog`. `isSelfServiceUser`
   defaults **false → modal** (documented limitation; real role wiring → P2-4). Mount inside the full-chrome
   `AppShell` group in `App.tsx` (wrap the app-variant routes).
4. **Mock** — add an expiring-session scenario to `commons-ui-next/src/mock/sessions.ts` (e.g. a token whose
   `getTimeLeft` returns ~0 / `isSessionValid` flips to false) so the monitor test can drive expiry deterministically.
5. **Tests:** session-timeout — expiry with the default (admin) role → modal appears, `demo/changeit` re-auth
   restores the token and closes the modal without navigating; expiry with a self-service role → navigates
   `/sessionExpired`; monitor pauses with no token and clears its timer on unmount.
6. **Parity GATE flip** (one atomic commit) — in `route-ownership.yml` **and** the TS mirror
   `openam-ui-eui/src/config/routeOwnership.ts`: `login` → `status: migrated`; `confirmLogin` → `status: migrated`
   (owner already `eui`); `logout`, `failedLogin`, `sessionExpired` → `owner: eui, status: migrated` (matching TS
   `owner` edits). Confirm `routeOwnership.test.ts` passes. **Only once P1-5f, P1-5j, P1-5h, P1-5i are all done.**
7. **Docs:** update `reference/eui-foundation.md` (session-timeout dialog/monitor/guard; move them out of "Not yet
   built"); `tasks.yml` P1-5k → done, **P1-5 → done** (login parity complete), and note `route-ownership.yml`
   login → `status: migrated`. Note routes for P1-10's hash-compat map (`#logout/` etc.).

## Files
- **New (eui `openam-ui-eui/src/features/auth/`):** `useSessionMonitor.ts`, `SessionTimeoutDialog.tsx`,
  `SessionGuard.tsx` (+ tests). `isSelfServiceUser` helper (co-located or in `commons-ui-next/session` if kept
  app-agnostic).
- **Edit:** eui `App.tsx` (wrap the app-variant routes in `SessionGuard`), `commons-ui-next/src/mock/sessions.ts`
  (+ fixtures) for the expiring-session scenario, `docs/migration/route-ownership.yml`,
  `openam-ui-eui/src/config/routeOwnership.ts`, `reference/eui-foundation.md`, `tasks.yml`.
- **Conventions:** CDDL header, TS strict, 2-space/single-quote, react-bootstrap 5, no Backbone/jQuery/RequireJS;
  no app-specific imports into `commons-ui-next` (ADR-0002); no hardcoded `/EUI`/`/XUI` (ADR-0004/0011). Use
  `scaffold-eui`.

## Out of scope
Real role wiring for `isSelfServiceUser` (→ **P2-4**; defaults to the admin/modal branch until then).
ScriptTextOutput exec (P1-5g). Everything already landed by P1-5f (views/failure-nav) and P1-5j (remember-me).

## Verification
`npm run test:run` + `npm run lint` + typecheck for `openam-ui-eui` and `commons-ui-next`; **route-ownership drift
test still passes after the status/owner flip**; `dev:mock` walk of a session-timeout modal re-auth (admin default)
that restores the session on `demo/changeit` without leaving the page. Confirm P1-5f + P1-5j + P1-5h + P1-5i are all
`done` before performing step 6.
