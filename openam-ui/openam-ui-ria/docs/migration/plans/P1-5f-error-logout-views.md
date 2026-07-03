# P1-5f — Login parity: return-to-login views (Failure / SessionExpired / Logout) + failure navigation

**Depends on:** P1-5b · Read [`README.md`](README.md) (shared research) first.

> **Split (2026-07-03).** The original P1-5f ("session dialog + error/expired/logout views + remember-me",
> the parity gate) was carved 3-way — too big for one task (~9 new files across three distinct concerns):
> - **P1-5f** (this file) — the return-to-login views + failure navigation.
> - **[P1-5j](P1-5j-remember-me.md)** — remember-me.
> - **[P1-5k](P1-5k-session-timeout-dialog.md)** — session-timeout re-auth dialog + monitor + guard. **This is now
>   the parity gate**; the `route-ownership.yml` flip and the `[P1-5h, P1-5i]` gate preconditions moved there.
>
> This task is **not** the gate: it must not flip `route-ownership.yml` login → `migrated`. It adds three
> standalone routes (`/failedLogin`, `/sessionExpired`, `/logout`) but leaves `route-ownership.yml` untouched —
> the single atomic ownership flip stays with the gate (P1-5k).

## Goal

The ancillary return-to-login views (`LoginFailure`, `SessionExpired`, `Logout`), the shared centered
"return to login" partial, param recall across those views, and failure navigation (`gotoOnFail` +
`detail.failureUrl`). Remember-me is P1-5j; the session-timeout modal is P1-5k.

## Legacy reference
- **LoginFailureView** (`login/LoginFailureView.js`, 41) — shown when `AuthNService.getRequirements()` itself
  rejects (server unreachable/bad params). `SessionToken.remove()` + `AuthenticationToken.remove()`; preserves the
  current fragment query string; renders `ReturnToLoginTemplate.html` with title `openam.authentication.unavailable`.
- **SessionExpiredView** (`login/SessionExpiredView.js`, 54) — post-logout. Recovers prior params from
  `Configuration.globalData.auth.fullLoginURL` via `getSuccessfulLoginUrlParams()` + `filterUrlParams()`; deletes
  `fullLoginURL` + `Configuration.gotoURL`; emits anonymous mode; renders `ReturnToLoginTemplate.html`
  (title `templates.user.SessionExpiredTemplate.sessionExpired`).
- **RESTLogoutView** (`login/RESTLogoutView.js`, 55) + `logout.jsm` — `POST /json/sessions?_action=logout[&tokenId=…]`
  (only if session valid), clears the session token regardless, then renders `ReturnToLoginTemplate.html`
  (title `templates.user.RestLogoutTemplate.loggedOut`).
- **ReturnToLoginTemplate.html** (`templates/openam/`) — shared centered `{{title}}` + one return-to-login link
  (`routeTo('login') + params`, text `common.user.returnToLoginPage`); used by ConfirmLogin/Failure/Expired/Logout.
- **failure navigation** — `AuthNService.js` `goToFailureUrl`: `gotoOnFail` query param (validated via
  `validateGoto`) and a 401 `detail.failureUrl` from AM (used verbatim — it is server-supplied, not user input).

## Locked decisions (planning, 2026-07)
- **Param recall = the `fullLoginURL` equivalent over `sessionStorage`.** `LoginPage` records the whitelisted
  entry params on load; the Failure/Expired views recall them so the return-to-login link carries them back.
- No transport-level 401 interceptor (the transport returns raw Responses; EUI has no data surface to intercept
  yet). Session-timeout detection is P1-5k's monitor, not an interceptor here.

## Current state (built in P1-5b…P1-5e — reuse, don't duplicate)
- `commons-ui-next/auth`: `startAuthentication`/`submitCallbacks` (**failure is a value**; only network errors throw),
  `CallbackForm`, `validateGoto`, guards/accessors. `AmCallback.type` is `string` + typed guards.
- `commons-ui-next/session`: `getToken`/`setToken`/`clearToken`, `logout(transport, token)`.
- eui `features/auth/`: `LoginPage.tsx`, `useLogin.ts` (`useAuthenticationFlow` — multi-stage loop, 408 restart,
  polling, redirect/return-leg resume; **`startAuth()` has no `.catch`** → a thrown start error currently hangs on
  the spinner), `ConfirmLogin.tsx`, `loginParams.ts` (`parseLoginParams`/`buildAuthQuery`). `App.tsx`:
  `/login`+`/confirmLogin` under `AppShell variant="auth"`; `/` under `AppShell` (app variant).
  `amTransport` in `src/config/transport.ts`.
- i18n already has the needed titles (nested): `templates.user.SessionExpiredTemplate.sessionExpired`,
  `templates.user.RestLogoutTemplate.loggedOut`, `authentication.unavailable`,
  `config.messages.CommonMessages.{loginTimeout,loggedOut,authenticationFailed}`. Only
  `common.user.returnToLoginPage` (the shared link text) is missing.
- Mock (`commons-ui-next/src/mock`): `sessions.ts` serves `POST …?_action=logout` → `LOGOUT_RESULT`, GET/`getSessionInfo`
  → `DEMO_SESSION` (valid `DEMO_TOKEN_ID`) or 401. `users.ts` serves `validateGoto`.

## Implementation steps (ordered, each independently testable)

1. **i18n** (`commons-ui-next/src/i18n/locales/en/translation.json`) — add `common.user.returnToLoginPage`
   (link text for the shared partial). All other keys already exist.
2. **Shared partial + param recovery** (eui `features/auth/`):
   - `ReturnToLogin.tsx` — centered `{title}` + return-to-login `Link`, mirroring `ReturnToLoginTemplate.html`.
   - `loginReturn.ts` — the `fullLoginURL` equivalent: `filterLoginParams` (whitelist
     `arg/authIndexType/authIndexValue/goto/gotoOnFail/ForceAuth/locale`) + `rememberLoginParams`/`recallLoginParams`
     over `sessionStorage`. `LoginPage` records on entry; failure/expired views recall for the return link.
3. **LoginFailure + engine start-error surface:** add `.catch` in `useLogin.startAuth` → new field `startFailed`
   (the thrown error, distinct from the `failure` *value*). `LoginPage`: `startFailed` → `navigate('/failedLogin')`.
   `LoginFailure.tsx`: `clearToken()` + `<ReturnToLogin title={t('authentication.unavailable')} />`. Route
   `/failedLogin` (auth shell).
4. **Failure navigation (`useLogin.ts`/`LoginPage.tsx`):** on a terminal `failure` step (the *value* failure path,
   not `startFailed`) — if the `gotoOnFail` query param is present → validate via `validateGoto` then navigate there;
   if the failure response body carries `detail.failureUrl` → hard `window.location.href` navigation (bypasses
   `validateGoto`, matching legacy `goToFailureUrl` — the URL comes from AM, not user input). Both params are already
   parsed by P1-5d/`loginParams.ts` but not yet acted on. Legacy ref: `AuthNService.js goToFailureUrl`.
5. **SessionExpired** (`SessionExpired.tsx`): `clearToken()` +
   `<ReturnToLogin title={t('templates.user.SessionExpiredTemplate.sessionExpired')} />` with recalled params.
   Route `/sessionExpired`.
6. **Logout** (`Logout.tsx`): on mount, if `getToken()` → best-effort `logout(amTransport, token)`; always
   `clearToken()`; then `<ReturnToLogin title={t('templates.user.RestLogoutTemplate.loggedOut')} />`. Route `/logout`.
7. **Tests:** LoginFailure (start error → failure view, token cleared); failure navigation (`gotoOnFail` present →
   navigates to the validated goto; `detail.failureUrl` in the failure body → hard-navigates via
   `window.location.href`); SessionExpired + Logout (title + return link; logout calls `_action=logout`, token
   cleared regardless).
8. **Docs:** update `reference/eui-foundation.md` (new `features/auth/*`, `useLogin` `startFailed`); `tasks.yml`
   P1-5f → done. Note the new routes (`/failedLogin`, `/sessionExpired`, `/logout`) for P1-10's hash-compat map.
   **Do not** flip `route-ownership.yml` — that is P1-5k's atomic gate flip.

## Files
- **New (eui `openam-ui-eui/src/features/auth/`):** `ReturnToLogin.tsx`, `loginReturn.ts`, `LoginFailure.tsx`,
  `SessionExpired.tsx`, `Logout.tsx` (+ tests).
- **Edit:** eui `features/auth/{useLogin.ts,LoginPage.tsx}`, eui `App.tsx` (add the three routes under the auth
  shell), `commons-ui-next/src/i18n/locales/en/translation.json`, `reference/eui-foundation.md`, `tasks.yml`.
- **Conventions:** CDDL header, TS strict, 2-space/single-quote, react-bootstrap 5, no Backbone/jQuery/RequireJS;
  no app-specific imports into `commons-ui-next` (ADR-0002); no hardcoded `/EUI`/`/XUI` (ADR-0004/0011). Use
  `scaffold-eui`.

## Out of scope
Remember-me (**P1-5j**). Session-timeout re-auth dialog + monitor + guard, and the parity-gate route-ownership flip
(**P1-5k**). ScriptTextOutput exec (P1-5g). Login-page self-service links
(`showForgotPassword`/`showForgotUserName`/`showSelfRegistration`) — documented exclusion (→ **P1-6**). Social login
buttons — documented exclusion (→ **P2-6**, needs serverinfo `socialImplementations` modeling).

## Verification
`npm run test:run` + `npm run lint` + typecheck for `openam-ui-eui` and `commons-ui-next`; `dev:mock` walk of
`/logout` → logged-out page (calls `_action=logout`), `/sessionExpired` + `/failedLogin` return links, and a
failed login that carries `gotoOnFail` navigating to the validated target. Route-ownership drift test unaffected
(this task leaves `route-ownership.yml` unchanged).
