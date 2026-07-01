# Legacy login feature map (XUI)

_Reference inventory of everything `RESTLoginView` and its neighbors do in the legacy `openam-ui-ria` app. Written while scoping P1-5; feeds **P1-5b** (the deferred parity slice — see `tasks.yml`). Paths are relative to `openam-ui-ria/`. Not a template to copy 1:1 into the new app — the new app models the same AM protocol with hooks/TanStack Query, not Backbone views/Handlebars templates._

## Core files

| File | LOC | Responsibility |
|---|---|---|
| `src/main/js/org/forgerock/openam/ui/user/login/RESTLoginView.js` | 550 | The login form Backbone view. Multi-stage render loop, per-callback-type Handlebars rendering, `goto`/fragment param handling, zero-page/auto-login, remember-me, existing-session handling. |
| `src/main/js/org/forgerock/openam/ui/user/login/RESTLoginDialog.js` | 46 | Session-timeout re-auth **modal**. Sets `Configuration.backgroundLogin = true`, removes the stale session cookie, re-renders `RESTLoginView` inside a `BootstrapDialog`. |
| `src/main/js/org/forgerock/openam/ui/user/login/RESTLoginHelper.js` | 173 | Orchestrates one login attempt: calls `AuthNService.getRequirements`/`submitRequirements`, resolves the logged-in user, sets the success URL (`goto` validation), exposes `filterUrlParams`. |
| `src/main/js/org/forgerock/openam/ui/user/services/AuthNService.js` | 275 | Lowest-level `/json/authenticate` client. `begin()`/`submitRequirements()`, the multi-stage `requirementList` state machine, timeout/retry (`408`) handling, `validateGotoUrl()` (`POST /json/users?_action=validateGoto`). |
| `src/main/js/org/forgerock/openam/ui/user/login/RESTConfirmLoginView.js` | 47 | `#confirmLogin/` route — shown when realm changed mid-session; logs out then bounces to login. |
| `src/main/js/org/forgerock/openam/ui/user/login/LoginFailureView.js` | 41 | `#failedLogin` route — shown when `AuthNService.getRequirements()` itself rejects (server unreachable etc). Clears session/auth tokens. |
| `src/main/js/org/forgerock/openam/ui/user/login/SessionExpiredView.js` | 54 | Post-logout "your session expired" view; preserves filtered login URL params for "log back in" link. |
| `src/main/js/org/forgerock/openam/ui/user/login/RESTLogoutView.js`, `logout.jsm` | — | Logout flow (not detailed here — out of scope for P1-5/P1-5b). |
| `src/main/js/org/forgerock/openam/ui/user/login/gotoUrl.jsm` | 40 | Thin accessor over `Configuration.globalData.auth.urlParams.goto` (`set`/`get`/`exists`/`toHref`). |
| `src/main/js/org/forgerock/openam/ui/user/login/tokens/SessionToken.jsm` | 132 | Session token (`tokenId`) holder — cookie-backed, with an `HTTP_ONLY_TOKEN` sentinel/in-memory fallback when the AM session cookie is `HttpOnly`. `isAuthenticated(response)` — the canonical "did this authenticate response succeed" check. |
| `src/main/js/org/forgerock/openam/ui/user/login/tokens/AuthenticationToken.jsm` | 47 | `authId` holder (separate cookie), used to resume an in-progress multi-stage auth (e.g. across a `RedirectCallback` round-trip). |

## The AM `/json/authenticate` protocol, as this app drives it

- `AuthNService.begin()` — POST empty body (`Accept-API-Version: protocol=1.0,resource=2.1`) to `/authenticate?realm=...&<fragment params>` → first challenge (`{authId, callbacks, stage, ...}`).
- `AuthNService.submitRequirements(requirements)` — POST the (filled-in) requirements object back to the same URL → next challenge, a success body (`tokenId`/`successUrl`/`realm`), or a 401 error body.
- State machine: `requirementList` (module-level array) tracks each stage seen so far; `getRequirements()` decides whether to resume an in-flight `authId` (`AuthenticationToken.get()`), replay the last-seen stage, or start fresh (`begin()`) — fresh-start triggers are realm change or authIndexType/Value change (`hasRealmChanged`/`hasAuthIndexChanged`).
- 401 handling: if the error body still has an `authId`, the chain can continue (`submitRequirements` recurses); otherwise the process resets and the error message is displayed.
- 408 (timeout) handling: retries `begin()` once; if still at stage 1, resubmits the original requirements against the fresh `authId`; otherwise restarts the process and shows a "timeout, restarting" message.
- `goToFailureUrl` — a 401 error body carrying `detail.failureUrl` triggers a hard `window.location.href` navigation (used by some auth trees on hard failure).
- `commons-ui-next/src/auth/authenticate.ts` (the new app's equivalent) intentionally does **not** implement the multi-stage `requirementList`/retry/timeout machinery — it exposes single-step `startAuthentication`/`submitCallbacks` and leaves state management (and any retry policy) to the caller. P1-5b decides whether/how much of this belongs in `useLogin`.

## Callback rendering (`Handlebars.registerHelper('callbackRender', ...)`  in `RESTLoginView.js`)

Dispatches by `callback.type` to a partial in `src/main/resources/partials/login/`:

| Callback type | Partial | Notes |
|---|---|---|
| `PasswordCallback` | `_Password.html` | |
| `TextInputCallback` | `_TextInput.html` | |
| `TextOutputCallback` | `_TextOutput.html` or `_ScriptTextOutput.html` | Branches on `messageType === "4"` (magic number from AM's `ScriptTextOutputCallback.java`) → renders raw `<script>` content instead of a message. |
| `ConfirmationCallback` | `_Confirmation.html` (once per option) | Renders one button per option; single-option sets get `btn-primary`, else the `defaultOption` index does. |
| `ChoiceCallback` | `_Choice.html` | Renders a `<select>`-style list; marks the callback's current `input.value` index active. |
| `HiddenValueCallback` | `_HiddenValue.html` | |
| `RedirectCallback` | `_Redirect.html` | Rendering is mostly moot — `renderForm` intercepts `RedirectCallback` **before** the template step (see below) and navigates away immediately. |
| `PollingWaitCallback` | `_PollingWait.html` | Same — `renderForm` also special-cases this one directly. |
| **`NameCallback` and anything else** | `_Default.html` | Falls through the `switch`'s `default:` case — a plain `<input type="text" name="callback_{{index}}">`. **`NameCallback` has no dedicated case**; it's handled generically. |

`_RememberLogin.html`, `_SelfService.html`, `_SocialAuthn.html` are separate partials rendered directly by `RESTLoginTemplate.html` (not through `callbackRender`), gated by `populateTemplate()`'s `showRememberLogin`/`showForgotten`/`showSocialLogin` flags — see below.

## `renderForm()` special-casing (outside the generic callback loop)

- **`RedirectCallback`** (SAML/OAuth/social-login hop): builds a `<form>` from the callback's `output` (`redirectUrl`, `redirectMethod`, `redirectData`) and either submits it (`POST`) or does `window.location.replace(redirectUrl)` (`GET`) — leaves the page entirely. If the callback also carries `trackingCookie: true` output, the current `authId` is stashed in `AuthenticationToken` so the flow can resume after the redirect returns.
- **`PollingWaitCallback`** (push/OTP-style async auth): reads a `waitTime` (ms) from `output`, then after that delay re-submits the login request with `suppressSpinner: true` if the stage is still polling. No user input.
- **Synthetic submit button**: if neither `ConfirmationCallback` nor `PollingWaitCallback` is present on the stage, `renderForm` **appends a synthetic `ConfirmationCallback`** (label = `common.user.login`) so every ordinary username/password-style stage gets a submit button, even though AM didn't send one.
- **Stage-specific templates**: tries `templates/openam/authn/${reqs.stage}.html` first (per-module-name override), falls back to the generic `templates/openam/RESTLoginTemplate.html` if that template doesn't exist. `reqs.stage` is the AM auth-module name (e.g. `DataStore1`).
- **`userNamePasswordStage`** flag — `true` when `reqs.stage` is one of `DataStore1`, `AD1`, `JDBC1`, `LDAP1`, `Membership1`, `RADIUS1`. Gates whether self-service links/remember-me/social-login render at all (see `populateTemplate` below) — a hardcoded module-name allowlist, not something the protocol communicates.

## `populateTemplate()` — chrome around the form

- `firstUserNamePassStage` — true only on stage 1 of a username/password stage; gates self-service link visibility so they don't show on later MFA stages.
- `showForgotPassword` / `showForgotUserName` / `showSelfRegistration` — driven by `Configuration.globalData.{forgotPassword,forgotUsername,selfRegistration}` server flags (P1-6 territory).
- `showRememberLogin` — shows the "remember my username" checkbox on username/password stages.
- `showSocialLogin` — first stage only, not already logged in, and `Configuration.globalData.socialImplementations` non-empty.
- **Session-timeout dialog**: if `Configuration.backgroundLogin` is set (by `RESTLoginDialog`), instead of rendering inline it opens a `BootstrapDialog` (class `login-dialog`, not closable) and retargets the view's render element (`self.element`) to the dialog body for the duration, restoring it in `onshown`. Triggered by `AMConfig.js`'s `EVENT_SHOW_LOGIN_DIALOG` handler (`src/main/js/config/process/AMConfig.js:271`) — used for logged-in admins whose session expired (self-service users are logged out and see `SessionExpiredView` instead).

## Zero-page / auto-login (`isZeroPageLoginAllowed` / `autoLogin`)

- Triggered when the URL carries `IDToken1`/`IDToken2`/... params and `Configuration.globalData.zeroPageLogin.enabled` is true.
- `isZeroPageLoginAllowed()` — if there's no `document.referrer`, allowed only if `zeroPageLogin.allowedWithoutReferer`; otherwise the referrer must be in `zeroPageLogin.refererWhitelist` (or the whitelist is empty).
- `autoLogin()` — maps each `IDTokenN` URL param to `callback_{N-1}` and fires the login request immediately, without ever rendering the form (unless it fails, in which case `autoLoginAttempts` prevents an infinite loop and the form renders normally on retry).

## Existing-session / realm-change handling

- `render()`: if simply asking AM for "requirements" already returns an authenticated response (`SessionToken.isAuthenticated`), the user already has a valid session — `handleExistingSession()` runs instead of rendering a form.
- `handleExistingSession()`: fetches the logged-in user; if the realm changed since the session was established (`isRealmChanged()`), redirects to `#confirmLogin/` (`RESTConfirmLoginView`) instead of completing login. Otherwise resolves the success URL and navigates (honoring `goto`/`Configuration.gotoURL`).
- `RESTConfirmLoginView` (`#confirmLogin/`): if realm actually changed, logs out (clearing the stale cross-realm session) then re-renders as "logged out of previous site, log in to new site"; otherwise just bounces to the default route.
- `arg=newsession` query param forces a logout before proceeding (clears an existing session deliberately).

## `goto` / fragment param handling

- `handleParams()` parses the composite (fragment + query) string, maps legacy shorthand params (`authlevel`/`module`/`service`/`user`/`resource`) to `authIndexType`/`authIndexValue` (unless `composite_advice` is already set), and special-cases `goto` values starting with `/SSORedirect` or `/SSOPOST` (context-prefixes them).
- `RESTLoginHelper.setSuccessURL(tokenId, successUrl)`: if a `goto` param is present, calls `AuthNService.validateGotoUrl(goto)` (`POST /json/users?_action=validateGoto`) — an **open-redirect guard**: AM decides whether the target is on an allowed list and returns the sanitized `successURL`. Only a validated URL is ever navigated to. If no `goto`, falls back to the AM-provided `successUrl` (unless it's the admin console path).
- `filterUrlParams(params)` — whitelists `arg`, `authIndexType`, `authIndexValue`, `goto`, `gotoOnFail`, `ForceAuth`, `locale` when replaying params (e.g. into the "unavailable"/"session expired" views' retry links).

## Remember-me

- `formSubmit()`: if a `loginRemember` checkbox is checked, sets a `login` cookie (20-day expiry) to the value of the **first** `input[type=text]` on the form (assumes username is always the first text field). `prefillLoginData()` reads that cookie back on next render and pre-fills + focuses the password field; otherwise it focuses the first fillable input.
- Rendered via the separate `_RememberLogin.html` partial, gated by `showRememberLogin`.

## Templates

- `templates/openam/RESTLoginTemplate.html` — the generic per-stage template (used when no stage-specific override exists).
- `templates/common/LoginBaseTemplate.html` — base/chrome template (commons dependency — not in this repo).
- `templates/openam/ReturnToLoginTemplate.html` — shared by `RESTConfirmLoginView`, `LoginFailureView`, `SessionExpiredView` ("logged out" / "unavailable" / "session expired" pages with a link back to login).
- `templates/openam/authn/${stage}.html` — optional per-auth-module-name override (looked up dynamically; doesn't exist for most stages, so the generic template is used almost always in practice).

## Routes (`src/main/js/config/routes/AMRoutesConfig.js`)

- `confirmLogin` → `RESTConfirmLoginView`, url `confirmLogin/`.
- `loginFailure` → `LoginFailureView`, url pattern `/failedLogin([^&]+)?(&.+)?/`.
- A `sessionExpired`-style route → `SessionExpiredView` (exact route entry not reproduced here; grep `AMRoutesConfig.js` if needed).
- The main `#login` route itself is **not** defined in this file — it comes from the external Commons UI dependency's `CommonRoutesConfig` (see the `// TODO: The first undefined argument is the deprecated realm...` comment in `RESTLoginView.render()`), which is out of this repo entirely. Route-compat mapping for `#login` (P1-10) targets that external route, not a route defined here.

## Session-timeout dialog wiring (`AMConfig.js`)

- `src/main/js/config/process/AMConfig.js` registers a handler on `Constants.EVENT_SHOW_LOGIN_DIALOG` (around line 271) that renders `RESTLoginDialog` only when there's an empty callback queue (avoids stacking dialogs). This is the event that distinguishes "session expired while browsing as a logged-in admin" (→ modal re-auth via `RESTLoginDialog`) from "session expired as an anonymous/self-service user" (→ full-page `SessionExpiredView`).

## Deferred to P1-5b (per the P1-5 plan)

Multi-stage loop + generic callback renderer (`ChoiceCallback`, `ConfirmationCallback`, `TextOutputCallback`/`ScriptTextOutputCallback`, `TextInputCallback`, `HiddenValueCallback`, default/`NameCallback`); `RedirectCallback` + `PollingWaitCallback` handling; the session-timeout **modal** (`RESTLoginDialog` + `EVENT_SHOW_LOGIN_DIALOG`); zero-page/auto-login; existing-session/realm-change (`handleExistingSession`/`confirmLogin`); `LoginFailureView`/`SessionExpiredView`/logout views; remember-me; `goto`/realm/fragment params + `validateGotoUrl` (may share work with P1-10's route-compat map). See `tasks.yml` P1-5b for the tracked entry.
