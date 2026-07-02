# P1-5f — Login parity (GATE): session dialog + LoginFailure/SessionExpired/logout views + remember-me

**Depends on:** P1-5b · **Parity gate** · Read [`README.md`](README.md) (shared research) first.

## Goal

The remaining ancillary login UI, the session-timeout re-auth modal, and remember-me. **When this lands, login
reaches parity** — flip `route-ownership.yml` login → `status: migrated` and keep the TS mirror
(`openam-ui-eui/src/config/routeOwnership.ts`) in sync.

## Legacy reference
- **session-timeout dialog** — `RESTLoginDialog.js` (46) + `AMConfig.js` 271–300 (`EVENT_SHOW_LOGIN_DIALOG`).
  Clears the stale token then re-renders the login form inside a modal. Role-based: admin → modal re-auth;
  self-service user → full logout to SessionExpired. Legacy swaps the view's target element into the dialog body.
- **LoginFailureView** (41) — shown when requirements fetch fails (server unreachable/bad params); clears tokens,
  preserves filtered fragment params, renders an "authentication unavailable" template.
- **SessionExpiredView** (54) — post-logout; recovers prior login params from `fullLoginURL`, clears goto, emits
  anonymous-mode, renders "session expired" with a back-to-login link (shared `ReturnToLoginTemplate.html`).
- **RESTLogoutView** (55) — logout flow.
- **remember-me** — `RESTLoginView.formSubmit` (221–228) + `prefillLoginData` (407–418) + `_RememberLogin.html`.
  20-day cookie storing the username; pre-fills + checks the box and focuses password on return.

## Approach (new stack)
- **Dialog:** reuse the P1-5b `CallbackForm` + loop hook inside a react-bootstrap `Modal`. Trigger from an
  app-level session-expiry signal (a small session-monitor built on `commons-ui-next/session` `getTimeLeft`/
  `isSessionValid`, or a 401 interceptor) rather than the legacy Backbone event. Role branch: admin → modal;
  self-service → route to SessionExpired.
- **Views:** `LoginFailure`, `SessionExpired`, `Logout` components + routes (eui), sharing a small
  "return to login" partial. Wire logout through `commons-ui-next/session` `logout()` + `clearToken()`.
- **remember-me:** a checkbox surfaced by `CallbackForm` for username/password stages (or in `LoginPage`);
  persist the username (cookie or `localStorage`) and pre-fill on load. Keep it a small isolated helper.

## Files (anticipated)
- `openam-ui-eui/src/features/auth/` — `SessionTimeoutDialog.tsx`, `LoginFailure.tsx`, `SessionExpired.tsx`,
  `Logout.tsx`, remember-me helper; `App.tsx` routes.
- `commons-ui-next/src/session/` — optional session-monitor helper; ensure `logout` is wired.
- i18n — reuse existing `templates.user.LoginTemplate.loginRemember`, `common.form.sessionExpired`, etc.
- **`docs/migration/route-ownership.yml`** — flip login → `status: migrated`; keep `routeOwnership.ts` in sync.
- Tests: dialog re-auth (admin) + logout-to-expired (self-service); failure/expired/logout views; remember-me round-trip.

## Out of scope
ScriptTextOutput exec (P1-5g). Redirect/polling (P1-5c), goto (P1-5d), existing-session/zero-page (P1-5e) land first.

## Verification
Vitest + typecheck + lint; **route-ownership drift test still passes after the status flip**; `dev:mock` walk of a
session-timeout modal, a forced logout → SessionExpired, and remember-me pre-fill on reload.
