# EUI foundation — new-app API surface

_Reference inventory, not a decision doc — see [`../decisions/`](../decisions/) for the ADRs behind these choices. Update this file whenever a slice adds/changes a `commons-ui-next` export or app wiring pattern; last updated for P1-5i (RedirectCallback return-leg resume) — review-remediation-2026-07 Stage 5, 2026-07-03._

Read this when building a slice (see the `migrate-slice` skill) and you need to know what already exists in `commons-ui-next` / the `eui` app scaffold before writing new code.

## commons-ui-next modules

Workspace package `@openidentityplatform/commons-ui-next` (`openam-ui/commons-ui-next`). No app-specific imports allowed here (ADR-0002) — everything is generic enough to extract to the ForgeRock commons project later (Phase 5).

### `commons-ui-next/auth` — AM `/json/authenticate` callback flow
- `startAuthentication(transport: Transport, queryString?: string): Promise<AuthStep>` — step 1, empty POST → challenge. `queryString` (P1-5d) appends auth-selection params (e.g. `?authIndexType=module&authIndexValue=DataStore`).
- `resumeAuthentication(transport: Transport, authId: string, queryString?: string): Promise<AuthStep>` (P1-5i) — return-leg resume after a federated redirect: POSTs `{ authId }` instead of an empty `begin()`, mirroring `AuthNService.getRequirements`'s tracked-token branch.
- `submitCallbacks(transport: Transport, challenge: AmAuthChallenge): Promise<AuthStep>` — step 2+, POST the (filled) challenge back.
- `setCallbackValue(challenge, index, value)` — immutable update of one callback's first input.
- `fillCallbacks(challenge, values)` — fill all callbacks in order.
- `isAuthSuccess(step)` / `isAuthFailure(step)` — type-guards on `AuthStep`.
- `validateGoto(transport, goto): Promise<string | null>` (`validateGoto.ts`) — open-redirect guard; POSTs `/users?_action=validateGoto`, returns AM's sanitized `successURL` or `null` on rejection/error.
- Types (`types.ts`): `AmCallback` is now an **open type** — `{ type: string, output, input }` — plus `KnownCallbackType` (`'NameCallback' | 'PasswordCallback' | 'TextInputCallback' | 'HiddenValueCallback' | 'ChoiceCallback' | 'ConfirmationCallback' | 'TextOutputCallback' | 'RedirectCallback' | 'PollingWaitCallback'`) and the `KNOWN_CALLBACK_TYPES` array. Narrow with the type guards below rather than comparing `type` directly. `AmAuthChallenge` (`authId, template, stage, header, callbacks`), `AmAuthSuccess` (`tokenId, successUrl, realm`), `AmAuthError` (`code, reason, message`), `AuthStep` (discriminated union: `{kind:'requirements',challenge}` | `{kind:'success',success}` | `{kind:'failure',error}`).
- Failure is a **value** (`kind: 'failure'`), not a thrown exception. Only network/unexpected errors throw.
- `callbacks.ts` — pure accessors/guards over `AmCallback`: `getOutput(cb, name)`, `getPrompt(cb)`, `getChoices(cb)`, `getMessageType(cb)`, `getConfirmationOptions(cb)`, `getRedirectUrl(cb)`/`getRedirectMethod(cb)`/`getRedirectData(cb)`/`getTrackingCookie(cb)` (RedirectCallback), `getWaitTime(cb)`/`getPollingMessage(cb)` (PollingWaitCallback), plus one `isXCallback(cb): boolean` guard per `KnownCallbackType`.
- `trackingToken.ts` (P1-5i) — `getTrackingToken()`/`setTrackingToken(authId, options?)`/`clearTrackingToken(options?)`, a port of legacy `AuthenticationToken.jsm`'s `authId` cookie (name kept for XUI/EUI coexistence interop; path `/`; `options: { domains?, secure? }` writes one cookie per domain, host-only when omitted). `buildTrackingCookieStrings` is the pure builder underneath (unit-tested without a DOM — this package's Vitest environment is `node`).
- `CallbackForm({ challenge, onSubmit, submitting })` (`CallbackForm.tsx`) — generic renderer for an `AmAuthChallenge`: one control per callback (Name/Default/Password → text/password input, TextInput → textarea, HiddenValue → hidden input, Choice → `<Form.Select>`, Confirmation → one button per option that submits immediately), a synthetic submit button when no `ConfirmationCallback` is present, `TextOutputCallback` messageType 0/1/2 rendered as Bootstrap alerts (info/warning/danger) — **messageType 4 (ScriptTextOutput) is skipped (returns `null`), deferred to P1-5g**. A `PollingWaitCallback` present anywhere in the challenge switches the whole form to a spinner + optional message (auto-resubmit is driven by the caller, not this component).
- `createFetchTransport` / `Transport` are re-exported here too (see below).

### `commons-ui-next` (root) — `transport.ts`
- `type Transport = (path: string, init?: RequestInit) => Promise<Response>` — the seam shared by `auth` and `session`.
- `createFetchTransport(opts: { baseUrl: string }): Transport` — convenience wrapper defaulting `realm: '/'` (root realm), delegates to `createAmTransport`.

### `commons-ui-next/http` — realm path + AM transport
- `resolveRealmPath(realm: string | false, path: string): string` — realm→path-segment algorithm ported from legacy `fetchUrl.jsm` (`false` → no realm prefix; `"/"` → `/realms/root`; sub-realms prepend `/root` then every `/` becomes `/realms/`).
- `AmApiError` — `{ status, code, reason, message }`.
- `parseAmError(res: Response): Promise<AmApiError>`.
- `createAmTransport(opts: { baseUrl: string; realm?: string | false }): Transport` — builds `${baseUrl}/json${resolveRealmPath(realm, path)}`, always `credentials: 'include'` (cookie-based AM session). Returns the raw `Response`; callers own error handling.

### `commons-ui-next/serverinfo`
- `fetchServerInfo(transport: Transport): Promise<AmServerInfo>` (`serverinfo.ts`) — `GET /json/serverinfo/*` (the wildcard attribute returns the full object).
- Type `AmServerInfo` (`types.ts`) — `domains, protectedUserAttributes, cookieName, secureCookie, forgotPassword, selfRegistration, lang, successfulUserRegistrationDestination, socialImplementations, referralsEnabled, zeroPageLogin, realm, xuiUserSessionValidationEnabled`. `zeroPageLogin: AmZeroPageLogin` is `{ enabled, refererWhitelist, allowedWithoutReferer }`, matching the real AM `ServerInfo.java:87`/`ServerInfoResource.java:185` shape (fixed by **P1-5h**, replacing the mock's previously-invented flat `zeroPageLoginAllowed` boolean; the invented `FQDN`/`inplaceUpgrade` fields were dropped in the same pass — neither has a `ServerInfo.java` counterpart).
- `isZeroPageLoginAllowed(config: AmZeroPageLogin, referrer: string): boolean` (`zeroPageLogin.ts`) — pure port of legacy `RESTLoginView.isZeroPageLoginAllowed`: disabled → false; no referrer → `allowedWithoutReferer`; otherwise an empty/missing whitelist allows any referrer, else exact-string match. `LoginPage.tsx` gates its zero-page auto-submit on this, not the raw `enabled` flag.
- `./serverinfo` is a separate `commons-ui-next` package export entry (`import { fetchServerInfo, isZeroPageLoginAllowed, type AmServerInfo, type AmZeroPageLogin } from '@openidentityplatform/commons-ui-next/serverinfo'`). `mock/types.ts`'s `AmServerInfo`/`AmZeroPageLogin` re-export from here — one definition.

### `commons-ui-next/session`
- `getSessionInfo`, `isSessionValid`, `getTimeLeft`, `logout` (`sessions.ts`).
- `getToken`, `setToken`, `clearToken` (`token.ts`) — the client-side session-token holder.
- `createSessionService` / `SessionService` type (`service.ts`).
- Re-exports `createFetchTransport` / `Transport`.

### `commons-ui-next/i18n`
- `createI18nInstance()` — builds an isolated i18next instance (`initReactI18next`, `lng: 'en'`, resources from `./locales/en/translation.json`). Call once per app/test render, wrap in `<I18nextProvider i18n={...}>`.
- Re-exports `useTranslation`, `I18nextProvider` from `react-i18next`.
- Locale file: `commons-ui-next/src/i18n/locales/en/translation.json`. Existing keys relevant to login: `common.user.username`, `common.user.password`, `common.user.login`, `common.form.submit`, `config.messages.CommonMessages.authenticationFailed`, plus a larger `templates.user.LoginTemplate.*` set (remember-me, register, forgot password/username, social auth, polling) — present in the JSON but not all wired to a component yet (they map to legacy features deferred past the minimal login slice).

### `commons-ui-next/shell`
- `AppShell({ variant = 'app', brand, nav, end, footerVersion })` — layout route component (renders `<Outlet>` between `<Header>`/`<Footer>`). `variant="auth"` drops `nav`/`end` (mirrors legacy `LoginBaseTemplate`) — use for pre-auth routes like `/login`.
- `Header`, `Footer`, `Nav` — also individually exported; see `shell/AppShell.test.tsx` for direct usage/test patterns.

### `commons-ui-next/routing`
- `createCrossLinkResolver({ routes, mounts, currentOwner })` — builds a resolver from the route-ownership map; same-owner routes resolve in-app, other-owner routes resolve to a full-page URL under that owner's mount.
- `<CrossLinkProvider resolver={...}>`, `<CrossLink to="...">`, `useCrossLink()`.
- Types: `RouteOwnership` (`{ path, owner }`), `MountMap` (`{ eui, xui, ... }`), `CrossLinkConfig`, `CrossLinkResolution`, `CrossLinkResolver`.

### `commons-ui-next/mock` (ADR-0010)
- `handlers` — the full array of MSW request handlers (used by Vitest `setupServer`, the browser `setupWorker`, and the standalone Express mock server — one source of truth).
- Handler files: `mock/handlers/{authenticate,serverinfo,sessions}.ts`.
- `authenticate.ts` covers `POST */json/authenticate` and `POST */json/realms/root/authenticate`: empty body → `AUTH_CHALLENGE` (authId + `NameCallback` + `PasswordCallback`); submitted `demo`/`changeit` → `AUTH_SUCCESS`; anything else → `AUTH_ERROR` (HTTP 401). Fixtures/constants (`AUTH_CHALLENGE`, `AUTH_ERROR`, `AUTH_ID`, `AUTH_SUCCESS`, `DEMO_TOKEN_ID`, `SERVER_INFO`, `DEMO_SESSION`, `LOGOUT_RESULT`) are re-exported from `mock/index.ts` for use in tests.

## `eui` app wiring (`openam-ui/openam-ui-eui`)

### Bootstrap (`src/main.tsx`)
Provider stack, outside-in:
```
<I18nextProvider i18n={createI18nInstance()}>
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <HashRouter>
        <CrossLinkProvider resolver={crossLinkResolver}>
          <App />
        </CrossLinkProvider>
      </HashRouter>
    </QueryClientProvider>
  </StrictMode>
</I18nextProvider>
```
- `HashRouter` (react-router 7, ADR-0011): the mount path (`/EUI`, `/XUI`) lives in the real URL; react-router sees only the fragment (`/login`, `/dashboard`). No `basename` needed or used.
- Asset relocatability is independent: Vite `base: './'` + host-rewritten `<base href>` in `index.html` (ADR-0004). `src/config/runtime.ts` has been removed (it was only used to derive the router basename).
- `crossLinkResolver` is built from `mounts` + `routeOwnership` in `src/config/routeOwnership.ts`.
- Mock worker (`src/mocks/browser.ts`) is started conditionally via a dynamic import gated on `import.meta.env.VITE_MOCK`, so it's dead-code-eliminated from production builds. `onUnhandledRequest` only warns for un-mocked `/json/` calls (app static assets/HMR pass through silently).

### Route ownership (`src/config/routeOwnership.ts`)
- `mounts: MountMap` — `{ eui: '/EUI', xui: '/XUI' }`.
- `routeOwnership: RouteOwnership[]` — array of `{ path, owner }`. Flip an entry's `owner` to `'eui'` when a slice lands its route in this app.
- **Must stay in sync with** `docs/migration/route-ownership.yml` (the doc source of truth, which additionally carries `status`/`slice` fields). A Vitest drift-guard test (`src/config/routeOwnership.test.ts`) parses the yaml and asserts: `mounts` matches (excluding yaml's `final` key), every referenced `owner` has a mount, and the ordered `{path, owner}` pairs match. **It does NOT check `status`/`slice`** — those can be edited freely in the yaml without touching the TS file or breaking the test.

### Routes (`src/App.tsx`)
Plain react-router `<Routes>`/`<Route>` tree. `<AppShell>` is used as a layout route (wraps children, renders matched child via `<Outlet>`). Different route groups can mount under different `<AppShell variant=...>` instances (e.g. full-chrome `app` variant for the home/dashboard tree, minimal `auth` variant for pre-auth routes).

### Deps installed (`package.json`)
react 19.2, react-dom 19.2, react-router 7.15, react-bootstrap 2.10 (+ `bootstrap` 5.3 CSS), i18next 25 + react-i18next 15, `@tanstack/react-query` 5.101 (used by `useLogin`/`LoginPage` for the auth-flow mutation + serverinfo query), `@openidentityplatform/commons-ui-next` (workspace `*`). Dev: vite 8, vitest 4, @testing-library/{react,jest-dom,user-event}, msw 2.4, tsx, express (mock server), js-yaml, eslint 9 + typescript-eslint 8, typescript ~5.8.

### `features/auth` (login slice, `src/features/auth/`)
- `LoginPage.tsx` — the `/login` route. Drives `useAuthenticationFlow` (below), renders `CallbackForm` for `kind: 'requirements'` steps, intercepts `RedirectCallback` (builds+submits a hidden-field POST form or `location.replace` for GET), handles `success` (sets the token, resolves `goto` via `validateGoto` or navigates `/`), the existing-session branch (`isExistingSession`: same realm → treat as success, different realm → navigate to `/confirmLogin`), zero-page auto-login (pre-fills callbacks from `IDToken1..N` URL params and auto-submits when `isZeroPageLoginAllowed(serverInfo.zeroPageLogin, document.referrer)` — see the serverinfo note above), and the tracked-408 timeout branch (P1-5i, `isTimedOut`: shows `config.messages.CommonMessages.loginTimeout` and stops instead of restarting).
- `useLogin.ts` — exports `useAuthenticationFlow(queryString?)`: the multi-stage loop (`start → render → submit → repeat`), `isExistingSession` (true when the initial `/authenticate` returns success with zero submits), a `PollingWaitCallback` auto-resubmit schedule (`setTimeout` keyed off `getWaitTime`), 408 retry (auto-restarts unless a tracked `authId` cookie is set, in which case it exposes `isTimedOut: true` instead of retrying), and return-leg resume (P1-5i): on start, if `getTrackingToken()` finds a stored `authId` it calls `resumeAuthentication` instead of `startAuthentication` and clears the cookie once the response resolves to anything other than `kind: 'failure'`; when a `requirements` step carries a `RedirectCallback` with a tracking cookie, it calls `setTrackingToken(challenge.authId)` before `LoginPage` navigates away.
- `loginParams.ts` — `parseLoginParams(searchParams): LoginParams` (whitelist: `authIndexType, authIndexValue, goto, gotoOnFail, ForceAuth, locale, arg, realm`; maps legacy shorthand `authlevel/module/service/user/resource` → `authIndexType`/`authIndexValue`), `buildAuthQuery(params)` (auth-selection subset → `/authenticate` query string), `extractIDTokens(searchParams)` (ordered `IDToken1..N` values for zero-page).
- `ConfirmLogin.tsx` + `/confirmLogin` route — realm-change interstitial shown when an existing session's realm differs from the URL's `realm` param; reads `previousRealm` from its own query string, links back to `/login`.

### Test pattern (Vitest + Testing Library + MSW)
- `src/test/setup.ts` — registers `@testing-library/jest-dom/vitest` matchers, starts an MSW `setupServer(...handlers)` from `commons-ui-next/mock` for the whole run (`onUnhandledRequest: 'warn'`), calls Testing Library `cleanup()` + `server.resetHandlers()` in `afterEach` (Vitest is not configured with `globals: true`, so cleanup must be wired explicitly), `server.close()` in `afterAll`.
- Component tests wrap the tree in whichever providers the component needs: `I18nextProvider` (`createI18nInstance()`), `CrossLinkProvider` (`createCrossLinkResolver({...})`), `MemoryRouter` (+ `Routes`/`Route` when testing a layout route so `<Outlet>` resolves, or `initialEntries` to land on a specific path when rendering the full `<App />`). See `src/shell/AppShell.test.tsx` and `src/App.test.tsx` for the concrete patterns.
- MSW handler overrides per-test: `server.use(...)` before the render/action, relies on `resetHandlers()` in the shared `afterEach` to undo it.

## Not yet built (add when a slice needs it)
- Session-timeout re-auth dialog, `LoginFailure`/`SessionExpired`/`Logout` views, and remember-me — **P1-5f** (the login parity gate; login stays `route-ownership.yml` `status: in_progress` until this lands).
- `ScriptTextOutput` execution (`TextOutputCallback` messageType 4 — device-print/WebAuthn/reCAPTCHA hooks) — **P1-5g**, deferred as security-sensitive.
