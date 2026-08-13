# What the XUI reads from `serverinfo` at bootstrap

Source-read only — no container was started, no live AM was contacted. Everything below is from the
XUI and commons-UI sources, the recorded capture, `REQUESTS.md` and the spec files.

This is the input to **task 2.9**, which `server-lib/state.mjs:59-60` describes as the task that "has
to answer more than the capture holds: the site configuration and the feature flags that decide
which optional UI is presented".

## The two documents, and why "site configuration" is `serverinfo/*`

There is no endpoint called `site-configuration`. In AM's XUI the *site configuration* **is**
`GET /json/serverinfo/*`. The delegation runs:

```
commons  SiteConfigurator (remoteConfig: true, delegate: …/SiteConfigurationService)
   └─> AM  common/services/SiteConfigurationService.getConfiguration
          └─> AM  common/services/ServerService.getConfiguration
                 └─> GET /json/serverinfo/*   Accept-API-Version: protocol=1.0,resource=1.1
```

wired in `openam-ui-ria/src/main/js/config/AppConfiguration.js:38-45`.

A second, unrelated call — `ServerService.getVersion()` → `GET /json/serverinfo/version` at
`resource=1.0` — is **not** part of bootstrap; see "Not bootstrap" below.

Both are in the capture (`capture/README.md` resource table, rows 1 and 2):
`json/serverinfo/star/GET.resource=1.1.json`, `json/serverinfo/star/GET.resource=1.0.json`,
`json/serverinfo/version/GET.json`. The two `serverinfo/*` bodies are byte-identical; only the
recorded `request.acceptApiVersion` differs.

## Where the values are parked

`SiteConfigurator.processConfiguration` (commons, `SiteConfigurator.js:61-80`) does:

```js
_.extend(conf.globalData, config);          // every key, verbatim
conf.globalData.auth.cookieName     = config.cookieName;
conf.globalData.auth.cookieDomains  = config.domains;      // note the rename
conf.globalData.auth.cookieSameSite = config.cookieSameSite;
```

So **every** wire key lands on `Configuration.globalData.<sameName>` whether anything reads it or
not, and three of them get a second home under `globalData.auth`. Only the `auth.*` copies are read
for cookies — nothing reads `globalData.cookieName`. `realm` gets a third home in the redux store
via `ServerService.jsm:54` (`store.dispatch(serverAddRealm(response.realm))`).

The `roles` / `defaultNotificationType` / `notificationTypes` branches in `processConfiguration` are
dead for AM — AM's `serverinfo/*` returns none of them.

## Phase-0 scope used for the spec column

The openspec change is
`openspec-commons/openspec/changes/modernize-openam-ui-build/`. Its `tasks.md` splits phase 0 in
two: **0a**, the regression net (tasks 1.1-1.16, `tasks.md:3`), and **0b**, the local API server
(tasks 2.1-2.18, `tasks.md:25`). Task **2.9 — `serverinfo` and site configuration — is still open**,
and this document is its input; the requirement it implements is
`specs/ui-local-backend/spec.md:59-71` ("Server and site configuration discovery" / "Feature flags
govern optional UI").

**Phase 0 is therefore all 12 XUI spec files, 57 tests** (`xui/BASELINE.md:283-294`) — not just the
local-server subset. The distinction that still matters:

| | files | tests | relevance |
|---|---|---|---|
| all phase-0 specs (`@deployed-am`) | 12 | 57 | the regression net; these are the specs whose assertions the column below reflects |
| `@local-server` subset | 5 (`xui-cache-busting`, `xui-login`, `xui-profile`, `xui-realms`, `xui-services`) | 23 | what task 2.9's server actually has to satisfy |

So `xui-httponly.spec.mjs` and `xui-theming.spec.mjs` **are** phase-0 specs even though the local
server never runs them — and they are the two that read `serverinfo/*` hardest.

Column values below mean:

- **structural** — the bootstrap breaks mechanically without it, so every phase-0 spec fails
- **value** — a phase-0 spec asserts something that changes if the value changes
- **premise** — no assertion names it, but `BASELINE.md:73-75` or `NOTES-auth.md` pins it as the
  environment the baseline was recorded against, so changing it invalidates the comparison
- **presence** — must be served, but nothing in phase 0 observes the value

## The values

Capture values are from `capture/json/serverinfo/star/GET.resource=1.1.json`. `{{COOKIE_DOMAIN}}` is
a portability placeholder, not a recorded literal.

| wire name | parked name | what it gates | capture value | spec dependency |
|---|---|---|---|---|
| `realm` | `globalData.realm` + redux `store.getState().server.realm` | three things. (a) theme selection — `ThemeManager.js:166` → `findMatchingTheme:95-105`; (b) **the realm-change check on every route** — `isRealmChanged.jsm:22-27` compares `store.server.realm` (this field) against `store.session.realm`, and `SiteConfigurationService.js:55-61` sends the browser to `#confirmLogin/` on a mismatch; (c) the `#login<realm>` redirect after self-registration (`SelfRegistrationView.js:47,54`). **Also structural**: `ServerService.jsm:54` dispatches it *before* returning, and `store/reducers/server.jsm` does `action.realm.toLowerCase()` unguarded | `"/"` | **structural + value** — must be a string, and must match the authenticated session's realm or every route bounces to `#confirmLogin/`. `xui-theming.spec.mjs:41-43` names "the realm reaching ThemeManager at all" as what it guards; `:535` opens `?realm=…` and `:571-580` compares the whole stylesheet list per realm, so a response echoing `"/"` for a realm-scoped request resolves the default theme and turns that spec red |
| `cookieName` | `globalData.auth.cookieName` (+ `globalData.cookieName`, unread) | the name of every session-cookie read/write/delete: `SessionToken.jsm:44-46,111,121,130` | `"iPlanetDirectoryPro"` | **structural + value** — every phase-0 spec logs in through the browser, so a name the server does not also set/read means no session survives. `xui-httponly.spec.mjs:98,113-114` reads it and asserts a cookie of that name exists (it defaults to `iPlanetDirectoryPro` when absent, so absence is tolerated *only* if the cookie really is called that). `xui-profile.spec.mjs:247` hardcodes the same literal as a fixture request header |
| `cookieHttpOnly` | `globalData.cookieHttpOnly` (**not** under `auth`) | switches `SessionToken` between the readable-cookie path and the HttpOnly path: `isHttpOnly()` (`SessionToken.jsm:65-68`) changes `get`/`set`/`remove`, and `isAuthenticated()` (`:92-102`) changes whether a login with no `tokenId` counts as complete | `false` | **value — the strongest case in the suite.** `xui-httponly.spec.mjs:99` reads it, `:115` asserts the real cookie's `httpOnly` equals it, `:121` asserts `document.cookie` visibility is its inverse, and `:186` `test.skip(!httpOnly, …)`. `BASELINE.md:73-75` calls it the environment premise and `:344-349` records it as what makes **1 of the 57 tests skip** |
| `kbaEnabled` | `globalData.kbaEnabled` | registers the KBA tab on the user profile — `SiteConfigurationService.js:30-37` lazily `require`s `UserProfileKBATab` and calls `UserProfileView.registerTab`. String `=== "true"`. **Read off the raw response, before it is parked** | `"false"` | **value** — `xui-profile.spec.mjs:366-373` asserts the profile's tab list is *exactly* `[basicInfo, password]`, with the comment at `:368` naming "a KBA tab on an instance with kbaEnabled" as the failure it is guarding against. Serving `"true"` turns that spec red |
| `protectedUserAttributes` | `globalData.protectedUserAttributes` | which profile fields demand the current password before they can be changed — `UserModel.js:161`, `["password"].concat(...)` | `[]` | **value** — `xui-profile.spec.mjs:81-85` states it in prose ("this instance's serverinfo adds nothing, reporting `protectedUserAttributes: []`"). A value naming a details-form attribute — the spec edits `givenName` at `:139` — makes the save test hit a ConfirmPassword dialog and go red |
| `domains` | `globalData.auth.cookieDomains` (**renamed**) | the `domain=` attribute the XUI writes the session cookie for, and deletes it with — `SessionToken.jsm:48-50`, `AuthenticationToken.jsm:28-29`. `CookieHelper.setCookie:66-77` treats `[]` as "host-only cookie" and a non-empty array as one write per domain | `["{{COOKIE_DOMAIN}}"]` | **premise** — no spec asserts it, but `BASELINE.md:73-75` pins the recorded value and `NOTES-auth.md:268-274` is emphatic that a server on another origin must serve `[]`: served `["example.org"]` from localhost the XUI's own write is silently dropped, and logout's `deleteCookie` then fails to remove the host-only cookie the server set |
| `secureCookie` | `globalData.secureCookie` (**not** under `auth`) | `;secure` on the XUI's cookie write — `SessionToken.jsm:52-54`, `AuthenticationToken.jsm:32-33` | `false` | **premise** — `BASELINE.md:73-75`; `NOTES-auth.md:275-276` requires it stay `false` over plain HTTP or the XUI writes a `;secure` cookie the browser drops on an `http://` origin, breaking every login |
| `cookieSameSite` | `globalData.auth.cookieSameSite` | `;SameSite=` on the XUI's own cookie write — `SessionToken.jsm:56-58,111`. Not applied on delete (`CookieHelper.deleteCookie:100-104` drops it) | `"Lax"` | presence — a browser-acceptable value is required, nothing observes which. `server-lib/rest.mjs:449-451` copies `SameSite=Lax` deliberately so the server's `Set-Cookie` and the XUI's own write agree |
| `lang` | `globalData.lang` | `i18nManager.init({serverLang: …})` (commons `CommonConfig.js:46-50`) — the locale bundle loaded, and the `Accept-Language` header on every later REST call (`ServiceInvoker.js:167-168`). Overridden by an `i18next` cookie or a `locale` URL param | `"en-US"` | presence. No phase-0 spec references it, and the deployed tree ships only `locales/en`, so any other value falls back to `en` anyway |
| `forgotPassword` | `globalData.forgotPassword` | the "Forgot Password" link on the login form — `RESTLoginView.js:63`, rendered by `partials/login/_SelfService.html:8`. **String** compare `=== "true"` | `"false"` | presence — `xui-login.spec.mjs` asserts nothing about self-service links |
| `forgotUsername` | `globalData.forgotUsername` | the "Forgot Username" link — `RESTLoginView.js:64`, `_SelfService.html:4`. String `=== "true"` | `"false"` | presence |
| `selfRegistration` | `globalData.selfRegistration` | the "Register" link — `RESTLoginView.js:66-67`, `_SelfService.html:15`. String `=== "true"` | `"false"` | presence |
| `socialImplementations` | `globalData.socialImplementations` | the social-login button row on the first username/password stage — `RESTLoginView.js:71-72` (`!_.isEmpty(...)`), rendered by `partials/login/_SocialAuthn.html:6`, gated in `RESTLoginTemplate.html:25`, `authn/DataStore1.html:25`, `authn/WebAuthn{Authentication,Registration}2.html:30` | `[]` | presence |
| `successfulUserRegistrationDestination` | `globalData.successfulUserRegistrationDestination` | where self-registration lands: `"auto-login"` ⇒ set the token and resume the session; `"login"` ⇒ `#login<realm>`; anything else ⇒ stay in the process view — `SelfRegistrationView.js:46,53-58` | `"default"` | presence |
| `xuiUserSessionValidationEnabled` | `globalData.xuiUserSessionValidationEnabled` | starts the idle-session poller for non-admin users — `AMConfig.js:239-243` (`SessionValidator.start(token, MaxIdleTimeLeftStrategy)`). Truthy check, not a string compare. `SessionValidator.js:45-50` logs the user out and routes to `sessionExpired` if the strategy rejects; the strategy polls `_action=getSessionInfo` (`SessionService.jsm:52-57`) | `true` | presence, **with a backend obligation**. No spec asserts it, but it is `true` in the capture, so every end-user session in `xui-login` and `xui-profile` starts a poller. Serving `true` alongside expiry timestamps in the past, or a `getSessionInfo` that fails, logs the user out mid-test. `server-lib/auth.mjs:50-58,155-157` was built for exactly this polling |
| `zeroPageLogin.enabled` | `globalData.zeroPageLogin.enabled` | whether `?IDToken1=…` credentials in the URL auto-submit the login form — `RESTLoginView.js:196`, reached from `:266` | `false` | presence — the whole block is unreachable in phase 0. No spec ever puts `IDToken1` in a URL (a case-sensitive grep over `e2e/xui` and `e2e/common` finds none; the `#idToken1` hits are DOM selectors) |
| `zeroPageLogin.allowedWithoutReferer` | `globalData.zeroPageLogin.allowedWithoutReferer` | zero-page login when `document.referrer` is empty — `RESTLoginView.js:200-202` | `true` | presence — as above |
| `zeroPageLogin.refererWhitelist` | `globalData.zeroPageLogin.refererWhitelist` | the referrer allow-list for zero-page login; empty ⇒ any referrer — `RESTLoginView.js:194,204` | `[]` | presence — as above |
| `referralsEnabled` | `globalData.referralsEnabled` | **nothing.** Zero consumers in `openam-ui-ria/src` or in the expanded commons (`target/dependencies-expanded/forgerock-ui-user`); a repo-wide grep over `.js/.jsm/.jsx/.html` outside `node_modules` and `target` also returns nothing | `"false"` | presence only |

### The string/boolean split is a trap

`forgotPassword`, `forgotUsername`, `kbaEnabled`, `selfRegistration` and `referralsEnabled` are
**strings** on the wire (`"false"`), compared with `=== "true"`. `secureCookie`, `cookieHttpOnly`,
`xuiUserSessionValidationEnabled` and the three `zeroPageLogin` sub-flags are **JSON booleans**.
Only `cookieHttpOnly` is read tolerantly (`httpOnly === true || httpOnly === "true"`,
`SessionToken.jsm:67`).

Serving `false` where AM serves `"false"` silently pins a string-compared flag to permanently-off.
Since every one of them *is* off in the capture, that bug stays invisible until someone tries to
turn a flag on — which is exactly what a later spec for self-service or KBA would do.

### `_id` / `_rev`

`capture/README.md:99-100` records that `GET /json/serverinfo/*` returns `_id` and `_rev` **only**
when no `Accept-API-Version` is negotiated. The XUI always negotiates `resource=1.1`, so it never
sees them and never reads them. Neither recorded body contains them.

## Bootstrap order, and what must succeed before the first route renders

The runtime chain, from `main.js:187-204` through commons:

1. `EVENT_DEPENDENCIES_LOADED` → `Configuration.sendConfigurationChangeInfo()`
   (`ProcessConfiguration.js:35-37`)
2. per-module `EVENT_CONFIGURATION_CHANGED` → `ProcessConfiguration.updateConfigurationCallback`
   loads `AMConfig` + `CommonConfig`, registers every listener, then fires
   `EVENT_READ_CONFIGURATION_REQUEST` (`ProcessConfiguration.js:76`)
3. `SiteConfigurator` hears it, sees `remoteConfig: true`, and issues **`GET /json/serverinfo/*`**
   (`SiteConfigurator.js:31-58`)
4. either way — success *or* failure — it fires `EVENT_APP_INITIALIZED`
5. `CommonConfig.js:27-65` handles that: `i18nManager.init({serverLang: globalData.lang})`, then
   `SessionManager.getLoggedUser`, then `EVENT_AUTHENTICATION_DATA_CHANGED`, and only in its
   `.then` does `Router.init()` run — the first route

So **`serverinfo/*` is the first request the XUI makes, and it is the only one that gates step 4.**
Everything after it is chained off `EVENT_APP_INITIALIZED`.

`NOTES-auth.md:337-340` states the same order and adds which requests gate a *logged-in* first
route:

> **Order:** 1 strictly first (it is what supplies the cookie name). 2 and 3 are issued
> **concurrently**. 4 is chained off 3. Only 3 and 4 gate the UI: 3 supplies `username`, 4 supplies
> `roles`, and together they populate `Configuration.loggedUser`, without which
> `EVENT_HANDLE_DEFAULT_ROUTE` sends the user to `#login` regardless of the cookie.

Combining the two, the requests that must succeed before a **useful** first route renders are:

1. `GET /json/serverinfo/*` — must return, must carry `cookieName`, and must carry `realm` as a
   string
2. `POST /json/{realms/root/}users?_action=idFromSession` — 401 when anonymous is the *normal*
   path, not a failure (`REQUESTS.md` "Facts that bind the implementation" §1)
3. `POST /json/sessions?_action=getSessionInfo` — supplies `username`
4. `GET /json/realms/root/users/<id>` — supplies `roles`

3 and 4 populate `Configuration.loggedUser`; without it `EVENT_HANDLE_DEFAULT_ROUTE`
(`AMConfig.js:174-191`) routes to `#login` no matter what the cookie says.

**Also on the render path, on every view change:** `EVENT_CHANGE_VIEW` awaits
`SiteConfigurator.configurePage` (commons `CommonConfig.js:223`), which calls AM's
`SiteConfigurationService.checkForDifferences` → `SessionService.updateSessionInfo`. AM's
implementation resolves even when that call fails (`SiteConfigurationService.js:63-68`), so it
cannot stall rendering — but it is a per-route request, not a bootstrap one. It never re-runs
`processConfiguration`, because `checkForDifferences` resolves with `undefined` rather than a config.

### The capture's recorded order is not the runtime order

`capture/index.json` has `POST /json/users?_action=idFromSession` at `order: 1` and the two
`serverinfo/*` calls at `order: 2` and `3`. That is `capture.mjs` walking `REQUESTS.md`, not the
browser. Do not read it as the XUI's sequence.

## Cookie name — agreement with `NOTES-auth.md`

**They agree.** `NOTES-auth.md:216` states `**Name: iPlanetDirectoryPro.**` and `:218-226` gives the
same three-hop chain this document derives from source, under the heading "**Where the XUI learns
it — it is not hardcoded.**":

1. `ServerService.getConfiguration` → `GET /json/serverinfo/*` at `protocol=1.0,resource=1.1`
2. `SiteConfigurator.processConfiguration` → `conf.globalData.auth.cookieName = config.cookieName`
3. `SessionToken.jsm`'s private `cookieName()` reads `Configuration.globalData.auth.cookieName`

That matches `SiteConfigurator.js:77` and `SessionToken.jsm:44-46` exactly. The capture's
`cookieName` is `"iPlanetDirectoryPro"`, which `capture/README.md:242` deliberately leaves
un-normalised ("the cookie's name, which the XUI needs. No value."), and which
`server-lib/auth.mjs:258` already reads out of the capture rather than hardcoding.

**No disagreement on the cookie name, its source, or the three related attributes.**

`NOTES-auth.md:268-279` adds a deployment decision this document does not contradict but which
should be read alongside the `domains` row above: a local server on another origin must serve
`domains: []`, not the recorded domain, because `CookieHelper.setCookie` documents the empty array
as the way to write a host-only cookie, and `SessionToken.remove()` on logout would otherwise fail
to delete the cookie the server set.

## Read at bootstrap but **not** in the capture

- **Realm-scoped `serverinfo/*`.** `ServerService.getUrl` (`ServerService.jsm:31-38`) sends the
  request through `fetchUrl` with `realm` taken from the page's query string, so with `?realm=/x`
  the bootstrap call is `GET /json/realms/root/realms/x/serverinfo/*`, not the bare path.
  `REQUESTS.md:151-152` records both realm-scoped shapes in its **"Out of scope — 35 requests"**
  table, reached only by `xui-theming`. That spec *is* phase 0 but is `@deployed-am`-only, so the
  local server never has to answer it — which is why the capture omits it deliberately. It is still
  a genuine bootstrap read that the capture does not hold, and it is the one place where `realm`
  must come back realm-scoped rather than `"/"` (see the `realm` row).
- **Nothing else.** Every field the bootstrap path reads is present in `GET.resource=1.1.json`, and
  the capture holds no `serverinfo/*` field with no reader (except `referralsEnabled`, which has no
  reader anywhere).

`GET /json/serverinfo/version` is in the capture and is **not** a bootstrap read; see below.

## Not bootstrap, but adjacent

- **`/json/serverinfo/version`** (`version`, `revision`, `date`) is fetched by `Footer.render()` →
  `getVersion()` **only when `showVersion()` is true**, i.e. only for a user with `ui-realm-admin`
  (`common/components/Footer.js:23-33`, commons `Footer.js:29-56`). It renders the footer string
  `OpenAM <version> <build> <revision> (<date>)`. It is never reached before login.
  `capture/README.md:235-238` says these three are deliberately *not* normalised so task 2.15's
  drift job goes red on an image rebuild — nothing reads them for behaviour. Capture values:
  `version` `"16.2.0-SNAPSHOT"`, `revision` `"fc8e2e67c7"`, `date` `"2026-August-04 10:48"`.
  Note `xui-cache-busting.spec.mjs`'s "version" assertions are about the Maven-substituted
  `urlArgs: "v=${version}"` in `index.html` (`:20-23,99-100`), **not** this endpoint.
- **`OAuth2ConsentPageHelper`** (`user/oauth2/OAuth2ConsentPageHelper.js:31-44`) issues its **own**
  `GET /json/serverinfo/*` at `resource=1.1` and reads `cookieName` off the raw response, bypassing
  `globalData` entirely. That is the OAuth2 consent page's separate entry point, not the XUI
  bootstrap. `xui-authorize` exercises it but is `@deployed-am` only, so the local server never
  serves this call.

## What happens if a value is absent

### If the whole request fails

**The XUI boots anyway, without a session — no throw, no error screen.** Two variants, and which one
you get depends on the URL:

*Without a `?realm=` URL parameter* (the normal case):

- `ServiceInvoker.restCall` rejects its `$.Deferred()` with `(jqXHR, textStatus, errorThrown)`
  (`ServiceInvoker.js:85-87`, the `suppressEvents` branch — `SiteConfigurationService.js:45` passes
  `{ suppressEvents: true }`)
- `ServerService.getConfiguration`'s rejection handler (`ServerService.jsm:57-61`) calls
  `serverAddRealm(getRealmUrlParameter())`, which is `serverAddRealm(undefined)`, and the reducer's
  `action.realm.toLowerCase()` throws a `TypeError`
- jQuery 3.7.1's `.then` is Promises/A+, so the throw rejects the derived promise
- `SiteConfigurationService`'s `errorCallback` fires → `SiteConfigurator.js:49-52` →
  `processConfiguration({})` → `EVENT_APP_INITIALIZED`

*With a `?realm=…` URL parameter:* the dispatch succeeds and the handler reaches **`return reason;`**
— it does not rethrow. Returning from a rejection handler *fulfils* the derived promise, so
`SiteConfigurationService` takes its **success** branch with the `jqXHR` object standing in for
`serverInfo`, and `_.extend(conf.globalData, jqXHR)` splats the XHR's enumerable properties onto
`globalData`.

Either way `EVENT_APP_INITIALIZED` fires, `Router.init()` runs, and a route renders with
`auth.cookieName`, `auth.cookieDomains` and `auth.cookieSameSite` all `undefined`.
`SessionToken.get()` becomes `CookieHelper.getCookie(undefined)`, finds nothing, and the user lands
anonymous on `#login` — with a login form showing no self-service links and no social buttons,
because every gating value is `undefined`.

**A server that 500s on `serverinfo/*` therefore produces a plausible-looking login page, not a
visible failure.** That is the failure mode to design the fixture against.

### If individual keys are absent

| absent key | behaviour |
|---|---|
| `realm` | **throws, and takes the whole config with it.** `ServerService.jsm:54` dispatches *before* returning the response, and `store/reducers/server.jsm` does `action.realm.toLowerCase()` unguarded. The `TypeError` rejects the derived promise, so `SiteConfigurator` runs `processConfiguration({})` and **discards every other field, `cookieName` included.** This is the most destructive single omission in the document |
| `zeroPageLogin` | **throws.** `RESTLoginView.js:194` reads `.refererWhitelist` off it unguarded. Reached only from `:266`, which requires an `IDToken1` URL parameter, so it stays latent until then |
| `cookieName` | no throw. `CookieHelper.getCookie(undefined)` returns `undefined`; `setCookie` writes a cookie literally named `undefined`. Silent, total session loss. `server-lib/capture-store.mjs:180-186` already guards the capture side of this |
| `domains` | no throw. `CookieHelper.setCookie:67-69` wraps a non-array as `[domains]`, so `undefined` becomes `[undefined]`, and `domain ? ";domain=" + domain : ""` (`:49`) makes that a host-only cookie — accidentally equivalent to `[]` |
| `cookieSameSite` | no throw; the `;SameSite=` attribute is simply omitted (`CookieHelper.js:51`) |
| `secureCookie` | no throw; falsy ⇒ no `;secure`. Same as `false` |
| `cookieHttpOnly` | no throw; `undefined` fails both arms of `httpOnly === true \|\| httpOnly === "true"` ⇒ readable-cookie path. Same as `false` |
| `lang` | no throw. `i18nManager.init` gets `serverLang: undefined` and falls back to `Constants.DEFAULT_LANGUAGE` = `"en"` (commons `Constants.js:98`). `Accept-Language` is then omitted from later calls (`ServiceInvoker.js:167`) |
| `protectedUserAttributes` | no throw, but `["password"].concat(undefined)` yields `["password", undefined]` — a junk entry, not a crash |
| `forgotPassword`, `forgotUsername`, `selfRegistration`, `kbaEnabled` | no throw; `undefined === "true"` is false ⇒ feature off. Identical in effect to the capture's `"false"` |
| `socialImplementations` | no throw; `_.isEmpty(undefined)` is `true` ⇒ no social row. Identical to `[]` |
| `successfulUserRegistrationDestination` | no throw; read via `_.get`, so `undefined` falls to the "stay in the process view" branch |
| `xuiUserSessionValidationEnabled` | no throw; falsy ⇒ no idle-session poller |
| `referralsEnabled` | no effect — nothing reads it |

Summary: **`realm` and `zeroPageLogin` are the only keys whose absence throws.** `realm`'s throw is
catastrophic and unconditional; `zeroPageLogin`'s is latent. `cookieName` is the only key whose
absence is silently catastrophic. Everything else degrades to its off/default value.

## Unresolved

- What AM serves for `domains` when a deployment has no cookie domain configured is not determinable
  from these sources — the capture only shows a one-element array. Task 2.9 settled what the *local
  server* puts there, `[]`, on `NOTES-auth.md:268-274`'s argument; what AM itself would answer is
  still unknown, and a re-record against a differently-configured deployment is the only way to find
  out.
- Whether any consumer depends on `globalData` *not* carrying extra keys was not checked; `_.extend`
  means anything AM adds to `serverinfo/*` in a future version lands on `globalData` unfiltered.
- The `@local-server` verdicts above were **prospective when written** — derived from the XUI source
  and the recorded assertions rather than from an observed run, at a point where `serverinfo/*` still
  answered 501 and no browser had ever bootstrapped against the local server. Task 2.9 has since
  served the document and confirmed the self-service group of them in a browser: `selfRegistration`,
  `forgotPassword` and `forgotUsername` driven `"false"` → `"true"` → `"false"`, with
  `nav.remember-forgot` and `div.toggle-login-register` appearing and disappearing with them. The
  rest are still derived, not observed.
