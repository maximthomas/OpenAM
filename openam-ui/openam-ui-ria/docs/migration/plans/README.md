# Login-parity plans (P1-5b–P1-5g)

Per-task implementation plans for the login-parity work, plus the shared research they all build on.
Read this file first, then the plan for the specific task you're picking up. Locked decisions live in
[`../context.md`](../context.md); the legacy feature map is [`../reference/legacy-login.md`](../reference/legacy-login.md);
the new-app API surface is [`../reference/eui-foundation.md`](../reference/eui-foundation.md).

| Task | Plan | Scope |
|------|------|-------|
| P1-5b | [P1-5b-callback-engine.md](P1-5b-callback-engine.md) | Multi-stage loop + generic callback renderer (engine) |
| P1-5c | [P1-5c-redirect-polling.md](P1-5c-redirect-polling.md) | RedirectCallback + PollingWaitCallback + 408 retry |
| P1-5d | [P1-5d-goto-validate.md](P1-5d-goto-validate.md) | goto/realm/fragment params + validateGoto |
| P1-5e | [P1-5e-existing-session-zeropage.md](P1-5e-existing-session-zeropage.md) | existing-session/realm-change + zero-page/auto-login |
| P1-5f | [P1-5f-error-logout-views.md](P1-5f-error-logout-views.md) | return-to-login views (LoginFailure/SessionExpired/Logout) + failure navigation |
| P1-5j | [P1-5j-remember-me.md](P1-5j-remember-me.md) | remember-me (persist username) |
| P1-5k | [P1-5k-session-timeout-dialog.md](P1-5k-session-timeout-dialog.md) | session-timeout re-auth dialog + monitor + guard (**parity gate**) |
| P1-5g | [P1-5g-scripttextoutput.md](P1-5g-scripttextoutput.md) | ScriptTextOutput execution (device-print/WebAuthn/reCAPTCHA) |

P1-5f was itself split 3-way (2026-07-03) into P1-5f / P1-5j / P1-5k — ~9 new files across three concerns
(return views, remember-me, and a new background session-monitor subsystem). The **parity gate** moved from
P1-5f to **P1-5k** (the last to land), with `depends_on` preconditions `[P1-5f, P1-5j, P1-5h, P1-5i]`.

## Other plans

| Plan | Scope |
|------|------|
| [review-remediation-2026-07.md](review-remediation-2026-07.md) | Staged fixes for doc↔doc/doc↔code drift found in the 2026-07-02 migration-docs review, plus new tasks P1-5h (serverinfo/referrer-whitelist) and P1-5i (redirect return-leg resume) |

## Why the split

`tasks.yml`'s original P1-5b bundled ~9 distinct legacy sub-features spanning ~1,200 LOC — a mini-phase, not
a task. It is carved so the parity-critical **engine** (P1-5b) ships first and everything else layers on it.
**The login route stays `status: in_progress` across the whole split; flip to `migrated` only when P1-5k
(the gate) lands.** Dependency shape: P1-5c/d/f/g and P1-5j all `depends_on: [P1-5b]`; P1-5e additionally
depends on P1-5d (it builds on P1-5d's param parsing — see P1-5e's own header); P1-5k (the gate)
`depends_on: [P1-5f, P1-5j, P1-5h, P1-5i]`.

## Shared research

### What P1-5 already delivered (build on this; don't duplicate)

- **`commons-ui-next/auth`** (`src/auth/`): `startAuthentication(transport)`, `submitCallbacks(transport, challenge)`,
  immutable `setCallbackValue`/`fillCallbacks`, guards `isAuthSuccess`/`isAuthFailure`. Result is a discriminated
  `AuthStep = requirements | success | failure` — **failure is a value, not a throw**. Types in `src/auth/types.ts`;
  `AmCallback.type` is **hardcoded** to `'NameCallback' | 'PasswordCallback'`. No loop, no other callback types.
- **`commons-ui-next/session`** (`src/session/`): in-memory token holder (`getToken`/`setToken`/`clearToken`),
  `getSessionInfo`/`isSessionValid`/`getTimeLeft`/`logout`, `createSessionService(transport)`.
- **`commons-ui-next/http` + `src/transport.ts`**: `createFetchTransport({ baseUrl })` → builds
  `${baseUrl}/json${resolvedRealm}${path}` with `credentials: 'include'`; `resolveRealmPath()`; `parseAmError`.
- **`commons-ui-next/shell`**: `AppShell({ variant: 'app' | 'auth', brand, ... })`. Login uses `variant="auth"`.
- **`commons-ui-next/i18n`**: `createI18nInstance()`; keys present include `common.user.{username,password,login,forgotPassword}`,
  `config.messages.CommonMessages.{authenticationFailed,unknown}`, and a `templates.user.LoginTemplate.*` set
  (remember-me/social/forgot — present but not wired).
- **eui** (`src/features/auth/`): `LoginPage.tsx` (static username/password form) + `useLogin.ts` (single
  `startAuthentication`→one `submitCallbacks`, matches by callback `type`). Route `/login` wired in `src/App.tsx`
  under `AppShell variant="auth"`. Tests: `LoginPage.test.tsx` (happy + failure), `commons-ui-next/src/auth/auth.test.ts`.
- **Mock** (`commons-ui-next/src/mock/`): `handlers/authenticate.ts` + `fixtures/authenticate.ts` — single-stage
  `demo/changeit` only (`AUTH_CHALLENGE`/`AUTH_SUCCESS`/`AUTH_ERROR`, plus `AUTH_ID`/`DEMO_TOKEN_ID`).
- **Routing**: HashRouter, no `basename` (ADR-0011). `routeOwnership.ts` mirrors `route-ownership.yml`; a Vitest
  drift test guards `owner`/`path` only (**not** `status`/`slice`), so status edits are free.

### Legacy sub-feature → files / LOC / AM endpoints (corroborated against source)

Legacy source under `openam-ui-ria/src/main/js/org/forgerock/openam/ui/user/login/` (+ `services/AuthNService.js`,
`RESTLoginHelper.js`); Handlebars partials under `src/main/resources/partials/login/`.

| Sub-feature | Legacy file(s) | ~LOC | AM endpoint(s) | Target task |
|---|---|---|---|---|
| Multi-stage loop + callback render (Choice/Confirmation/TextOutput+Script/TextInput/HiddenValue/Name/Default) | RESTLoginView.js (renderForm 311–406, callbackRender 451–538) + 7 partials + AuthNService.js | ~300 core | `POST /json/authenticate` | **P1-5b** |
| RedirectCallback (SAML/OAuth) | RESTLoginView.js 326–341 | ~15 | client form→external IdP | P1-5c |
| PollingWaitCallback (push) | RESTLoginView.js 342–352, `_PollingWait.html` | ~10 | re-`POST /json/authenticate` after waitTime | P1-5c |
| 408 timeout-retry | AuthNService.js | ~10 | `POST /json/authenticate` | P1-5c |
| goto/realm/fragment + validateGoto | RESTLoginView.handleParams 420–448, RESTLoginHelper.setSuccessURL 130–160 / filterUrlParams / gotoUrl.jsm, AuthNService.validateGotoUrl 263–273 | ~100 | `POST /json/users?_action=validateGoto` | P1-5d |
| existing-session / realm-change (confirmLogin) | RESTLoginView.handleExistingSession 142–175, RESTConfirmLoginView.js | ~80 | `POST /json/authenticate`, `POST /json/users?_action=idFromSession` | P1-5e |
| zero-page / auto-login | RESTLoginView.isZeroPageLoginAllowed 192–205 / autoLogin 177–190 | ~40 | `POST /json/authenticate` (pre-filled) | P1-5e |
| session-timeout re-auth dialog | RESTLoginDialog.js (46), AMConfig.js 271–300 | ~80 | `POST /json/authenticate` | P1-5f |
| LoginFailure / SessionExpired / logout views | LoginFailureView.js (41), SessionExpiredView.js (54), RESTLogoutView.js (55) | ~150 | `POST /json/users?_action=idFromSession`, logout | P1-5f |
| remember-me | RESTLoginView.formSubmit 221–228 / prefillLoginData 407–418, `_RememberLogin.html` | ~25 | none (cookie) | P1-5f |
| failure navigation (`gotoOnFail` param, 401 `detail.failureUrl`) | AuthNService.js `goToFailureUrl` | ~30 | `POST /json/users?_action=validateGoto` (reused) | P1-5f |
| ScriptTextOutput execution (msg type 4) | RESTLoginView.callbackRender (script branch) | small | none (raw JS exec) | P1-5g |

### Cross-cutting conventions for every sub-task
- New commons-ui-next / eui files: CDDL header (see any existing `.ts`), TS strict, 2-space indent, single
  quotes, react-bootstrap 5, no Backbone/jQuery/Redux/RequireJS. Use the `scaffold-eui` skill.
- **No app-specific imports into `commons-ui-next`** (ADR-0002 — it is extracted upstream in phase 5).
- Everything validated against the MSW mock (ADR-0010); grow `commons-ui-next/src/mock/*` per sub-task.
- Path-relocatable: no hardcoded `/EUI` or `/XUI` strings (ADR-0011 / ADR-0004).
