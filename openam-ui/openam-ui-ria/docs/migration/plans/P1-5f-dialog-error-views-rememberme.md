# P1-5f — Login parity (GATE): session dialog + LoginFailure/SessionExpired/Logout views + remember-me

**Depends on:** P1-5b · **Parity gate** · Read [`README.md`](README.md) (shared research) first.

## Goal

The remaining ancillary login UI, the session-timeout re-auth modal, and remember-me. **When this lands, login
reaches parity** — flip `route-ownership.yml` login → `status: migrated` and keep the TS mirror
(`openam-ui-eui/src/config/routeOwnership.ts`) in sync.

## Legacy reference
- **session-timeout dialog** — `RESTLoginDialog.js` (46) + `AMConfig.js` 271–309 (`EVENT_SHOW_LOGIN_DIALOG`).
  Sets `Configuration.backgroundLogin = true`, `SessionToken.remove()` (clears stale token), re-renders
  `RESTLoginView` inside a non-closable `BootstrapDialog` (`common.form.sessionExpired` title). Role branch in
  `AMConfig`: `loggedUser.hasRole("ui-self-service-user")` → full `logout()` + route to SessionExpired; **else
  (admin/unknown) → modal re-auth**.
- **LoginFailureView** (41) — shown when `AuthNService.getRequirements()` itself rejects (server unreachable/bad
  params). `SessionToken.remove()` + `AuthenticationToken.remove()`; preserves the current fragment query string;
  renders `ReturnToLoginTemplate.html` with title `openam.authentication.unavailable`.
- **SessionExpiredView** (54) — post-logout. Recovers prior params from `Configuration.globalData.auth.fullLoginURL`
  via `getSuccessfulLoginUrlParams()` + `filterUrlParams()`; deletes `fullLoginURL` + `Configuration.gotoURL`; emits
  anonymous mode; renders `ReturnToLoginTemplate.html` (title `templates.user.SessionExpiredTemplate.sessionExpired`).
- **RESTLogoutView** (55) + `logout.jsm` — `POST /json/sessions?_action=logout[&tokenId=…]` (only if session valid),
  clears the session token regardless, then renders `ReturnToLoginTemplate.html` (title
  `templates.user.RestLogoutTemplate.loggedOut`).
- **remember-me** — `RESTLoginView.formSubmit` (221–228) + `prefillLoginData` (407–418) + `_RememberLogin.html`.
  Cookie **`login`**, 20-day expiry, stores the **first text input's** value; on return pre-fills that input, checks
  the box, focuses the password field. Checkbox gated to username/password stages (`showRememberLogin`).
- **ReturnToLoginTemplate.html** — shared centered `{{title}}` + one return-to-login link
  (`routeTo('login') + params`, text `common.user.returnToLoginPage`), used by ConfirmLogin/Failure/Expired/Logout.

## Locked decisions (planning, 2026-07)
- **Session-timeout trigger = `useSessionMonitor` hook** polling `isSessionValid`/`getTimeLeft`, run in the
  authenticated shell. On expiry: self-service role → navigate `/sessionExpired`; else (admin/unknown) → open modal.
  No transport-level 401 interceptor (the transport returns raw Responses; EUI has no data surface to intercept yet).
- **Remember-me storage = the legacy `login` cookie**, 20-day expiry — same name legacy XUI uses, so the remembered
  username carries across `/XUI` ↔ `/EUI` during coexistence.

## Current state (built in P1-5b…P1-5e — reuse, don't duplicate)
- `commons-ui-next/auth`: `startAuthentication`/`submitCallbacks` (**failure is a value**; only network errors throw),
  `CallbackForm` (`src/auth/CallbackForm.tsx`, generic renderer), `setCallbackValue`/`fillCallbacks`, `validateGoto`,
  guards/accessors (`isNameCallback`, `getPrompt`, …). `AmCallback.type` is `string` + typed guards.
- `commons-ui-next/session`: `getSessionInfo`/`isSessionValid`/`getTimeLeft`/`logout` (all `(transport, token)`),
  `getToken`/`setToken`/`clearToken`, `createSessionService`. `AmSessionInfo` = `{username, universalId, realm,
  properties, latestAccessTime, maxSessionExpirationTime, maxIdleExpirationTime}` — **no role field surfaced yet**.
- eui `features/auth/`: `LoginPage.tsx`, `useLogin.ts` (`useAuthenticationFlow` — multi-stage loop, 408 restart,
  polling; **`startAuth()` has no `.catch`** → a thrown start error currently hangs on the spinner), `ConfirmLogin.tsx`,
  `loginParams.ts` (`parseLoginParams`/`buildAuthQuery`/`extractIDTokens`). `App.tsx`: `/login`+`/confirmLogin` under
  `AppShell variant="auth"`; `/` (Home) under `AppShell` (app variant). `amTransport` in `src/config/transport.ts`.
- Mock (`commons-ui-next/src/mock`): `sessions.ts` serves `POST …?_action=logout` → `LOGOUT_RESULT`,
  `_action=getSessionInfo`/GET → `DEMO_SESSION` (valid `DEMO_TOKEN_ID`) or 401. i18n already has
  `templates.user.LoginTemplate.loginRemember`, `templates.user.SessionExpiredTemplate.sessionExpired`,
  `templates.user.RestLogoutTemplate.loggedOut`, `common.form.sessionExpired`,
  `config.messages.CommonMessages.{loginTimeout,loggedOut,authenticationFailed}`, `openam.authentication.unavailable`.
- Drift guard (`routeOwnership.test.ts`) checks **path/owner only, not status** — so the yaml status flip needs no TS
  change (login `owner` is already `eui`).

## Implementation steps (ordered, each independently testable)

1. **i18n** (`commons-ui-next/src/i18n/locales/en/translation.json`) — reuse existing keys above; add only
   `common.user.returnToLoginPage` if absent (link text for the shared partial).
2. **Shared partial + param recovery** (eui `features/auth/`):
   - `ReturnToLogin.tsx` — centered `{title}` + return-to-login `Link`, mirroring `ReturnToLoginTemplate.html`.
   - `loginReturn.ts` — the `fullLoginURL` equivalent: `filterLoginParams` (whitelist
     `arg/authIndexType/authIndexValue/goto/gotoOnFail/ForceAuth/locale`) + `rememberLoginParams`/`recallLoginParams`
     over `sessionStorage`. `LoginPage` records on entry; failure/expired/logout views recall for the return link.
3. **LoginFailure + engine start-error surface:** add `.catch` in `useLogin.startAuth` → new field `startFailed`
   (thrown error, distinct from the `failure` *value*). `LoginPage`: `startFailed` → `navigate('/failedLogin')`.
   `LoginFailure.tsx`: `clearToken()` + `<ReturnToLogin title={t('openam.authentication.unavailable')} />`. Route
   `/failedLogin` (auth shell).
4. **SessionExpired** (`SessionExpired.tsx`): `clearToken()` +
   `<ReturnToLogin title={t('templates.user.SessionExpiredTemplate.sessionExpired')} />` with recalled params. Route
   `/sessionExpired`.
5. **Logout** (`Logout.tsx`): on mount, if `getToken()` → best-effort `logout(amTransport, token)`; always
   `clearToken()`; then `<ReturnToLogin title={t('templates.user.RestLogoutTemplate.loggedOut')} />`. Route `/logout`.
6. **Remember-me:** `rememberMe.ts` (cookie `login`, 20-day: get/set/clear). `CallbackForm.tsx` gains optional
   `rememberMe?: { checked; onChange }` — renders the checkbox (`templates.user.LoginTemplate.loginRemember`) before
   the submit button **only when** the challenge has a `NameCallback` (pure props, no app import → ADR-0002 clean).
   `LoginPage`: seed the `NameCallback` value + default the box checked when a remembered login exists; on submit set
   or clear the cookie; autoFocus password when pre-filled.
7. **Session-timeout dialog + monitor** (eui `features/auth/`):
   - `useSessionMonitor.ts` — interval poll of `isSessionValid`/`getTimeLeft` against `getToken()`; fires `onExpiry`
     once; pauses when no token; clears its timer on unmount.
   - `SessionTimeoutDialog.tsx` — non-closable react-bootstrap `Modal` (`backdrop="static"`) reusing
     `useAuthenticationFlow` + `CallbackForm`; on success `setToken` + `onResume()` (close, **no navigation**). Title
     `common.form.sessionExpired`.
   - `SessionGuard.tsx` — runs the monitor for authenticated routes; on expiry: self-service → `/sessionExpired`, else
     modal. Role via `isSelfServiceUser(sessionInfo)` **defaulting false → modal** (legacy `else` fallback);
     documented limitation — real role wiring lands with the user/profile slice (P2-4). Mount inside the full-chrome
     `AppShell` group in `App.tsx`.
8. **Parity GATE flip:** `route-ownership.yml` login → `status: migrated`; `routeOwnership.ts` unchanged; confirm
   `routeOwnership.test.ts` passes.
9. **Tests:** LoginFailure (start error → failure view); SessionExpired + Logout (title + return link; logout calls
   `_action=logout`, token cleared); remember-me round-trip (submit checked → cookie; reload → pre-filled + checked);
   session-timeout (expiry → admin modal re-auth via `demo/changeit` restores token; self-service → `/sessionExpired`).
10. **Docs:** update `reference/eui-foundation.md` (new `features/auth/*`, `CallbackForm` `rememberMe` prop,
    `useLogin` `startFailed`); update `tasks.yml` (P1-5f → done, P1-5 → done (and `route-ownership.yml`
    login → `status: migrated`)); note new routes (`/failedLogin`, `/sessionExpired`, `/logout`) for
    P1-10's hash-compat map.

## Files
- **New (eui `openam-ui-eui/src/features/auth/`):** `ReturnToLogin.tsx`, `loginReturn.ts`, `LoginFailure.tsx`,
  `SessionExpired.tsx`, `Logout.tsx`, `rememberMe.ts`, `useSessionMonitor.ts`, `SessionTimeoutDialog.tsx`,
  `SessionGuard.tsx` (+ tests).
- **Edit:** eui `features/auth/{useLogin.ts,LoginPage.tsx}`, eui `App.tsx`, `commons-ui-next/src/auth/CallbackForm.tsx`,
  `commons-ui-next/src/i18n/locales/en/translation.json`, `docs/migration/route-ownership.yml`, docs in step 10.
- **Conventions:** CDDL header, TS strict, 2-space/single-quote, react-bootstrap 5, no Backbone/jQuery/RequireJS; no
  app-specific imports into `commons-ui-next` (ADR-0002); no hardcoded `/EUI`/`/XUI` (ADR-0004/0011). Use `scaffold-eui`.

## Out of scope
ScriptTextOutput exec (P1-5g). Redirect/polling (P1-5c), goto (P1-5d), existing-session/zero-page (P1-5e) land first.

## Verification
`npm run test:run` + `npm run lint` + typecheck for `openam-ui-eui` and `commons-ui-next`; **route-ownership drift test
still passes after the status flip**; `dev:mock` walk of remember-me pre-fill on reload, `/logout` → logged-out page,
`/sessionExpired` + `/failedLogin` return links, and a session-timeout modal re-auth (admin default) that restores the
session on `demo/changeit`.
