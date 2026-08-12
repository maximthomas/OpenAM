# XUI authentication, session resolution and logout — the wire exchange

What a local stand-in has to implement to satisfy tasks 2.7 and 2.8, whose acceptance test is
[`../xui/xui-login.spec.mjs`](../xui/xui-login.spec.mjs).

Three flows: **authenticate** (a two-leg callback exchange), **resolve a session after a page
reload** (from the cookie alone), and **log out**. All of it is `POST`/`GET` JSON under
`/openam/json`; none of it is a redirect, a form post or a servlet.

## Sources, and which said what

Two, kept separate throughout. Where they are marked in the tables:

- **[src]** — the XUI's own source under
  `../../openam-ui/openam-ui-ria/src/main/js/org/forgerock/openam/ui/`. This is the authority on
  *what the client sends and why*, and on what it does with a response.
- **[live]** — probed against `http://openam.example.org:8080/openam` (OpenAM 16.2.0-SNAPSHOT) on
  2026-08-12: `node` for request-level detail, one throwaway `chromium` script from
  `@playwright/test` for the browser's request *order*. This is the authority on *what AM answers*.
- **[cap]** — [`capture/json/`](capture/json/), recorded by task 2.2. Corroborates [live] for every
  body below; the recorded files and the live probe agree field-for-field.

The XUI source files that own this behaviour: `common/services/fetchUrl.jsm`,
`user/services/AuthNService.js`, `user/services/SessionService.jsm`, `user/login/RESTLoginHelper.js`,
`user/login/logout.jsm`, `user/login/tokens/SessionToken.jsm`, plus commons'
`SiteConfigurator.js` and `CookieHelper.js`, and `config/process/AMConfig.js` for the routing
decisions.

## The path shape — why `/realms/root/…`

`fetchUrl.jsm` [src] is 40 lines of logic and explains every path in the tables. It rewrites a
resource path into a realm-scoped one:

| Input | Output |
|---|---|
| `fetchUrl("/authenticate")`, session realm `/` | `/realms/root/authenticate` |
| `fetchUrl("/authenticate")`, session realm `/myRealm` | `/realms/root/realms/myRealm/authenticate` |
| `fetchUrl("/authenticate", { realm: false })` | `/authenticate` |
| `fetchUrl("/authenticate", { realm: "myAlias" })` | `/realms/myAlias/authenticate` |

Every `/` in an absolute realm becomes `/realms/`, and the root realm is redesignated `/root`. The
result is appended after `…/json`.

**This is why the same endpoint appears at two path shapes in one run, and both must route.** The
realm defaults to `store.getState().session.realm`, which is *unset until a session exists*. So the
bootstrap's `idFromSession` — fired before login — goes to the bare `/json/users?…`, and the same
call after login goes to `/json/realms/root/users?…`. Both were observed in one page load [live].
`AuthNService` is the exception: it passes `store.getState().server.realm` explicitly, which
`ServerService.getConfiguration` populates from `serverinfo/*`, so authenticate is realm-scoped from
the first call.

---

## 1. Authentication — the full exchange in order

A cold page load at `/XUI/#login/` with no session. Order is as observed in the browser [live];
bodies are [live], identical to [cap].

| # | Method | Path | `Accept-API-Version` | Request body | Status | Response body | Owner [src] |
|---|---|---|---|---|---|---|---|
| 1 | `GET` | `/json/serverinfo/*` | `protocol=1.0,resource=1.1` | — | 200 | site config; see §3 | `ServerService.getConfiguration` |
| 2 | `POST` | `/json/users?_action=idFromSession` | `protocol=1.0,resource=2.0` | — | **401** | `{"code":401,"reason":"Unauthorized","message":"Access Denied"}` | `RESTLoginHelper.getLoggedUser` |
| 3 | `POST` | `/json/realms/root/authenticate` | `protocol=1.0,resource=2.1` | **empty string** | 200 | callbacks document, below | `AuthNService.begin` |
| 4 | `POST` | `/json/realms/root/authenticate` | `protocol=1.0,resource=2.1` | the callbacks document, `input[0].value` filled | 200 | `{"tokenId":…,"successUrl":"/openam/console","realm":"/"}` | `AuthNService.submitRequirements` |
| 5 | `POST` | `/json/realms/root/users?_action=idFromSession` | `protocol=1.0,resource=2.0` | — | 200 | `{"id":"demo","realm":"/","dn":…,"successURL":"/openam/console","fullLoginURL":"/openam/UI/Login?realm=%2F"}` | `RESTLoginHelper.getLoggedUser` |
| 6 | `POST` | `/json/sessions?_action=getSessionInfo&tokenId=<token>` | `protocol=1.0,resource=2.0` | `{}` | 200 | session info, below | `SessionService.updateSessionInfo` |
| 7 | `GET` | `/json/realms/root/users/demo` | `protocol=1.0,resource=2.0` | — | 200 | user profile, incl. `roles` | `UserModel.fetchById` |
| 8 | `POST` | `/json/sessions?_action=getSessionInfo&tokenId=<token>` | `protocol=1.0,resource=2.0` | `{}` | 200 | as #6 | `SiteConfigurationService.checkForDifferences`, and `SessionValidator` |

**Two round trips of authentication proper** (#3 begin, #4 submit). #5–#8 are what the UI does with
the resulting session; they are not part of the authentication protocol but the login does not
complete visibly without them (§8).

`#5` and `#6` are issued **concurrently**, not in sequence — `getLoggedUser` fires the
`idFromSession` call and does not wait for it (its `.then` only stashes `fullLoginURL`), then calls
`updateSessionInfo`. `#7` is chained off `#6`'s response (`UserModel.fetchById(data.username)`).

### #3 — the initial callbacks document

Request: `POST`, `Accept-API-Version: protocol=1.0,resource=2.1`, and `data: ""` [src,
`AuthNService.begin`] — an **empty string body**, not `{}` and not absent.

The browser also sends `X-NoSession: true`, `X-Username: anonymous`, `X-Password: anonymous` on
every authenticate call, including the one that carries real credentials and gets a token back.
**A server that honours those headers never logs anyone in.** The real principal is only ever in the
`NameCallback` input value. (REQUESTS.md Fact 3; re-confirmed here — the live probe omitted them
entirely and the exchange was identical.)

```json
{
  "authId": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.<payload>.<sig>",
  "template": "",
  "stage": "DataStore1",
  "header": "Sign in to OpenAM",
  "infoText": ["", ""],
  "callbacks": [
    { "type": "NameCallback",
      "output": [{ "name": "prompt", "value": "User Name:" }],
      "input":  [{ "name": "IDToken1", "value": "" }] },
    { "type": "PasswordCallback",
      "output": [{ "name": "prompt", "value": "Password:" }],
      "input":  [{ "name": "IDToken2", "value": "" }] }
  ]
}
```

`input[i].name` is what the rendered form's field id derives from — `IDToken1` / `IDToken2` are the
`#idToken1` / `#idToken2` the specs type into (`SEL` in `../common/xui-commons.mjs`). `stage`
(`DataStore1`) selects the login template. `template` and `infoText` are present and empty.

Response headers [live]:

```
Set-Cookie: AMAuthCookie=<in-flight auth id>;path=/;domain=example.org;SameSite=Lax
Set-Cookie: amlbcookie=01;path=/;domain=example.org;SameSite=Lax
```

**Neither cookie is needed for the exchange.** The submit was accepted with no cookies at all, and
also with an `AMAuthCookie` belonging to a *different* `begin` [live]. `authId` alone correlates the
two legs. A stand-in need not issue either cookie.

### #4 — what the XUI posts back

`AuthNService.submitRequirements` sends `JSON.stringify(requirements)` [src] — **the whole document
from #3, echoed verbatim**, with `RESTLoginHelper.login` having written the typed values into
`callbacks[i].input[0].value` [src]. `authId`, `stage`, `header`, `infoText`, `template` and every
`output` come back unchanged. The server should read the `input` values and `authId`, and ignore the
rest.

Success [live, cap]:

```
200
Set-Cookie: iPlanetDirectoryPro=<token>;path=/;domain=example.org;SameSite=Lax
Set-Cookie: amlbcookie=01;path=/;domain=example.org;SameSite=Lax
Set-Cookie: AMAuthCookie=LOGOUT; Expires=Thu, 01 Jan 1970 00:00:10 GMT; Domain=example.org; Path=/

{"tokenId":"AQIC5wM2LY4S…*","successUrl":"/openam/console","realm":"/"}
```

Exactly three fields. `realm` is `"/"` — the XUI dispatches it into the redux store as the session
realm (`addRealmToStore` [src]), which is what flips subsequent paths to `/realms/root/…`.
`successUrl` is consumed by `RESTLoginHelper.setSuccessURL`; **it does not decide where the user
lands** (§8). The completion is recognised by `SessionToken.isAuthenticated(response)` [src], which
in the non-HttpOnly case is simply "has a `tokenId`".

### #6 — session info

```json
{
  "username": "demo",
  "universalId": "id=demo,ou=user,dc=openam,dc=openidentityplatform,dc=org",
  "realm": "/",
  "sessionHandle": "shandle:AQIC5wM2LY4S…*",
  "latestAccessTime": "2026-08-12T16:56:22Z",
  "maxIdleExpirationTime": "2026-08-12T17:26:22Z",
  "maxSessionExpirationTime": "2026-08-12T18:56:21Z"
}
```

`username` is load-bearing twice: `isSessionValid` is `_.has(response, "username")` [src], and
`getLoggedUser` chains `UserModel.fetchById(data.username)` off it. `realm` and `sessionHandle` are
dispatched to the store. **The two expiration timestamps must be in the future and must keep
moving**: `SessionValidator` reschedules itself for `min(idle, max) − now` seconds, and *logs the
user out and routes to `#sessionExpired` if this call ever rejects* [src]. Idle +30 min, max +2 h
[live].

### #7 — the profile read that decides the landing route

`GET /json/realms/root/users/<username>` returns the profile. `roles` becomes
`loggedUser.uiroles` [src, `UserModel.js`], and `AMConfig.js`'s `EVENT_HANDLE_DEFAULT_ROUTE` reads
it: `ui-realm-admin` → `#realms`, otherwise → `#profile/details`.

| user | `roles` | lands on |
|---|---|---|
| `demo` | `["ui-self-service-user"]` [live] | `#profile/details` |
| `amadmin` | `["ui-global-admin","ui-realm-admin"]` [cap] | `#realms` |

Both users get the identical `successUrl` `/openam/console` from #4 [live], so **a stand-in that
gets `roles` wrong sends both users to the same place** and half of `xui-login.spec.mjs` fails.

---

## 2. `authId`

- **What it is** [live]: a compact `HS256` JWT. Header `{"typ":"JWT","alg":"HS256"}`; payload
  `{"otk":"<25-char nonce>","realm":"dc=openam,dc=openidentityplatform,dc=org","sessionId":"<AM session id>"}`.
  Note the realm is in **DN form** here, not the `/` form used everywhere else.
- **Opaque to the client, stateful to the server.** The XUI never parses, inspects or constructs it
  — it only echoes it back inside the requirements document, and (for `RedirectCallback` flows only)
  stores the raw string in an `authId` cookie via `AuthenticationToken.jsm` [src]. So from the
  client's side it is a pure opaque token.
- **The server must round-trip state through it, or key state off it.** AM does the former:
  `sessionId` in the payload is byte-identical to the `AMAuthCookie` value *and* to the `tokenId`
  the successful #4 eventually returns [live] — AM allocates the session at `begin` and the JWT
  carries its id. A stand-in may instead hold the in-flight state server-side in a map keyed by an
  opaque `authId`; nothing the XUI does can tell the difference. What it may **not** do is ignore
  it: with two concurrent logins in flight the `authId` is the only correlator (the cookies are not
  — see §1).
- **AM validates it.** Flipping one character of the signature, or re-encoding the payload and
  keeping the old signature, both give
  `400 {"code":400,"reason":"Bad Request","message":"AuthId JWT Signature not valid"}` [live].
- **It survives across requests, and it is single-use.** It survives the round trip by definition,
  and survives a full page navigation when parked in the `authId` cookie. But replaying a consumed
  one gives `408 {"code":408,"reason":"Request Time-out","message":"Session has timed out"}` [live]
  — matching `NOTES-volatility.md` §"Unsafe to issue twice". `AuthNService` has an explicit 408
  branch [src]: it restarts `begin()` and, if the failure was at stage 1, immediately re-submits the
  old requirements with the *new* `authId`. A stand-in that never expires an `authId` simply never
  exercises that branch, which is fine — nothing in `xui-login.spec.mjs` drives it.
- Two `begin` calls always give distinct `authId`s [live].

---

## 3. The session cookie

**Name: `iPlanetDirectoryPro`.** [live, cap]

**Where the XUI learns it — it is not hardcoded.** The chain is three hops [src]:

1. `ServerService.getConfiguration` → `GET /json/serverinfo/*`, `Accept-API-Version:
   protocol=1.0,resource=1.1`, which returns `cookieName` among other fields.
2. commons' `SiteConfigurator.processConfiguration` copies it onto global state:
   `conf.globalData.auth.cookieName = config.cookieName`, alongside
   `.cookieDomains = config.domains` and `.cookieSameSite = config.cookieSameSite`.
3. `SessionToken.jsm`'s private `cookieName()` reads `Configuration.globalData.auth.cookieName`, and
   every `get`/`set`/`remove` goes through it.

The whole `serverinfo/*` body [live, cap]:

```json
{ "domains": ["example.org"], "protectedUserAttributes": [], "cookieName": "iPlanetDirectoryPro",
  "secureCookie": false, "cookieHttpOnly": false, "cookieSameSite": "Lax",
  "forgotPassword": "false", "forgotUsername": "false", "kbaEnabled": "false",
  "selfRegistration": "false", "lang": "en-US",
  "successfulUserRegistrationDestination": "default", "socialImplementations": [],
  "referralsEnabled": "false",
  "zeroPageLogin": { "enabled": false, "refererWhitelist": [], "allowedWithoutReferer": true },
  "realm": "/", "xuiUserSessionValidationEnabled": true }
```

**When it is set.** On the successful submit (#4) only. `begin` (#3) sets `AMAuthCookie`, not the
session cookie. On #4 AM sets `iPlanetDirectoryPro` *and* expires `AMAuthCookie`. And because
`cookieHttpOnly` is `false`, **the XUI also writes the cookie itself** from JavaScript —
`SessionToken.set(requirements.tokenId)` in `AuthNService.handleRequirements` [src] — using
`CookieHelper.setCookie(cookieName, token, "", "/", cookieDomains(), secureCookie(), cookieSameSite())`.
So the server's `Set-Cookie` and the client's own write both have to be able to land.

**Every attribute AM sets** [live, raw `Set-Cookie`]:

| Attribute | Value | Notes |
|---|---|---|
| name=value | `iPlanetDirectoryPro=<token>` | |
| `path` | `/` | |
| `domain` | `example.org` | the deployment's cookie domain |
| `SameSite` | `Lax` | |
| *(no `HttpOnly`)* | — | because `cookieHttpOnly` is false in this deployment |
| *(no `Secure`)* | — | because `secureCookie` is false |
| *(no `Expires`/`Max-Age`)* | — | a browser-session cookie; Chromium reports `expires: -1` [live] |

Browser-side confirmation [live]: `{name: "iPlanetDirectoryPro", domain: ".example.org", path: "/",
httpOnly: false, secure: false, sameSite: "Lax", expires: -1}`, and `document.cookie` reads it back.

### What a local server on a different host must NOT copy

1. **`Domain=` on the `Set-Cookie` — drop the attribute entirely.** `example.org` belongs to the
   recording deployment. A `localhost`/`127.0.0.1` origin cannot set it, and the browser discards the
   whole cookie. Emit a host-only cookie: `iPlanetDirectoryPro=<token>; Path=/; SameSite=Lax`.
2. **`domains: ["example.org"]` in the `serverinfo/*` body — serve `[]`.** This is the subtler half
   and it is not cosmetic. `CookieHelper.setCookie` treats the array as the set of domains to write
   the cookie for, and **an empty array is its documented way to write a host-only cookie** ("Use
   empty array for creating host-only cookies" [src]). Served `["example.org"]` from localhost, the
   XUI's own write is silently dropped; worse, `SessionToken.remove()` on logout calls
   `CookieHelper.deleteCookie(name, "/", cookieDomains())`, which then fails to delete the host-only
   cookie the server actually set, and a dead cookie lingers in the browser.
3. **`Secure`** — must stay off over plain HTTP, and `secureCookie: false` must stay `false` in
   `serverinfo/*`, or the XUI writes a `;secure` cookie the browser drops on an `http://` origin.
4. **`HttpOnly`** — do not set it. `cookieHttpOnly: false` is what puts `SessionToken` on its
   readable-cookie path; flipping it turns on the HTTP-only code path, which is `@deployed-am`
   territory (§9).
5. **`amlbcookie=01`** — a load-balancer stickiness cookie naming *this container's* server id.
   Nothing in the XUI reads it. Do not emit it.
6. **`AMAuthCookie`** — not needed at all (§1); do not emit it, and in particular do not emit the
   `AMAuthCookie=LOGOUT; Domain=example.org` clear on success.

`SameSite=Lax` and `Path=/` are safe to copy.

---

## 4. A rejected credential

Request identical to #4, wrong `PasswordCallback` value.

```
401
Content-API-Version: resource=2.1
(no Set-Cookie at all)

{"code":401,"reason":"Unauthorized","message":"Authentication Failed"}
```

[live, cap]. `reason` is the HTTP reason phrase; `message` carries the AM-specific text. There is no
`authId` and no `detail` in the body.

**Note the two 401 bodies are different and both are needed**: `"Authentication Failed"` from a
rejected credential, `"Access Denied"` from an unauthenticated `idFromSession`/`getSessionInfo`.

**How the XUI surfaces it** [src, `AuthNService.submitRequirements`]: 401 falls into the
`errorsHandlers.unauthorized` branch. The body is parsed; because it has **no `authId`**, the XUI
calls `resetProcess()`, raises `Messages.addMessage({ message: errorBody.message, type:
Messages.TYPE_DANGER })` — a `.alert-danger` node in `#messages` — and rejects with a sentinel
reason that is deliberately *not* translated into a second message. `RESTLoginHelper.login`'s
failure handler then only calls `ViewManager.refresh()` when `failedStage > 1`, so a **first-stage
failure leaves the form exactly where it is** at `#login/`.

The message text shown to the user is therefore **AM's `message` field, rendered verbatim**. That
is why `xui-login.spec.mjs` deliberately asserts the *class* (`alert-danger`) and not the wording.

**The `authId`-in-a-401-body case exists and is different.** If a 401 body *does* carry an `authId`,
`AuthNService` re-submits it to advance to the next module in the chain [src]. Not reachable from a
single-module `DataStore1` chain, and not driven by `xui-login.spec.mjs`.

---

## 5. Session resolution after a page reload

The state being recovered: a genuine new page load, no in-memory JS state, only the cookie jar.
Observed with a fresh browser page in the same context [live]:

| # | Method | Path | `Accept-API-Version` | Must return |
|---|---|---|---|---|
| 1 | `GET` | `/json/serverinfo/*` | `protocol=1.0,resource=1.1` | 200 + `cookieName`, so the XUI can read the cookie at all |
| 2 | `POST` | `/json/users?_action=idFromSession` | `protocol=1.0,resource=2.0` | 200 `{id, realm, dn, successURL, fullLoginURL}` |
| 3 | `POST` | `/json/sessions?_action=getSessionInfo&tokenId=<cookie value>` | `protocol=1.0,resource=2.0` | 200 with `username` |
| 4 | `GET` | `/json/realms/root/users/<username>` | `protocol=1.0,resource=2.0` | 200 with `roles` |
| 5 | `POST` | `/json/sessions?_action=getSessionInfo&tokenId=…` (×N) | `protocol=1.0,resource=2.0` | 200; the `checkForDifferences` and `SessionValidator` repeats |

**Order:** 1 strictly first (it is what supplies the cookie name). 2 and 3 are issued
**concurrently**. 4 is chained off 3. Only 3 and 4 gate the UI: 3 supplies `username`, 4 supplies
`roles`, and together they populate `Configuration.loggedUser`, without which
`EVENT_HANDLE_DEFAULT_ROUTE` sends the user to `#login` regardless of the cookie.

**`tokenId` is present in the query string on reload**, because with `cookieHttpOnly: false` the XUI
reads the cookie back with JavaScript. **But the server must also resolve the session from the
cookie alone** — `getSessionInfo` with *no* `tokenId` parameter returns the same 200 body [live],
and `SessionService.jsm` omits the parameter whenever the token is not client-readable [src]. A
stand-in should resolve `tokenId` if given, else the cookie, else the `iPlanetDirectoryPro` request
header (which is how the Playwright `APIRequestContext` fixtures pass it — REQUESTS.md Fact 6, and
what `sessionInfo()` in `../common/xui-commons.mjs` relies on).

**A stale or unknown cookie** must produce 401 from *both* #2 and #3. Observed with a bogus cookie
value [live]: both 401, the XUI then falls through to `POST /json/realms/root/authenticate` and
renders the login form at `#login/`. Answering 200-with-empty or 500 to either breaks that path.

**Load at `#login/` while a session exists** is a different flow and is worth knowing about even
though `xui-login.spec.mjs` never reaches it (Playwright gives each test a fresh context — no
`storageState` in `playwright.config.mjs`). `handleFragmentParameters` [src] appends
`?sessionUpgradeSSOTokenId=<token>` to the `begin` call when a resolvable token exists; AM answers
that **200 with a `tokenId` immediately and no callbacks**, returning the *same* token, and the XUI
routes straight to `#profile/details` [live].

---

## 6. Logout

`logout.jsm` → `SessionService.logout` [src]. Two calls, in this order [live]:

| # | Method | Path | `Accept-API-Version` | Body | Response |
|---|---|---|---|---|---|
| 1 | `POST` | `/json/sessions?_action=getSessionInfo&tokenId=<token>` | `protocol=1.0,resource=2.0` | `{}` | 200 — `isSessionValid` guard; a rejection here skips the logout entirely |
| 2 | `POST` | `/json/sessions?_action=logout&tokenId=<token>` | `protocol=1.0,resource=2.0` | `{}` | 200 `{"result":"Successfully logged out"}` |

As with `getSessionInfo`, `tokenId` is omitted when the token is not client-readable, so the server
must accept the cookie-only form. **AM requires an authenticated request context**: `_action=logout`
with a correct `tokenId` in the query but *no* cookie gives 401 [live].

**AM sends no `Set-Cookie` on the logout response** [live] — the response has no cookie headers at
all. The browser cookie is cleared **client-side**, by `SessionToken.remove()` →
`CookieHelper.deleteCookie` [src]. A stand-in may additionally expire the cookie server-side; it
must not *rely* on that being what ends the session.

**What must stop resolving afterwards**, all 401 [live]:

- `POST /json/users?_action=idFromSession` (both path shapes) → 401 `"Access Denied"`
- `POST /json/sessions?_action=getSessionInfo` with that token, or with the cookie → 401
- `POST /json/sessions?_action=logout` replayed with the same token → 401

The token must be invalidated **server-side**. This is exactly what `xui-login.spec.mjs` asserts,
and it says so: *"The browser cookie is not the thing to check … What matters is that the server
stops resolving it."*

After logout the XUI settles on `#loggedOut/`, and a subsequent load of `#profile/details` issues a
fresh `POST /json/realms/root/authenticate` and lands on `#login/` [live].

---

## 7. State machine

Server-side, three states per browser and one per in-flight login.

```
                    ┌──────────────────────────────────────────────┐
                    │ ANONYMOUS                                    │
                    │  idFromSession    -> 401 "Access Denied"     │
                    │  getSessionInfo   -> 401 "Access Denied"     │
                    │  serverinfo/*     -> 200 (always, no session)│
                    └───────────────┬──────────────────────────────┘
                                    │ POST /realms/root/authenticate, body ""
                                    v
                    ┌──────────────────────────────────────────────┐
                    │ AUTH IN FLIGHT   (keyed by authId)           │
                    │  hold: realm, stage, which callbacks are due │
                    │  emit: {authId, callbacks[], stage, header,  │
                    │         template, infoText}                  │
                    └───────┬──────────────────────────┬───────────┘
       submit, bad creds    │                          │  submit, good creds
                            v                          v
    401 {code,reason:"Unauthorized",         200 {tokenId, successUrl, realm}
        message:"Authentication Failed"}     Set-Cookie: <cookieName>=<token>; Path=/; SameSite=Lax
    authId consumed; no session                        │
    XUI: alert-danger, stays at #login/                v
                                    ┌──────────────────────────────────────────────┐
                                    │ AUTHENTICATED  (keyed by token)              │
                                    │  hold: username, realm "/", sessionHandle,   │
                                    │        idle+max expiry (must stay in future) │
                                    │  idFromSession  -> 200 {id, realm, dn,       │
                                    │                    successURL, fullLoginURL} │
                                    │  getSessionInfo -> 200 {username, realm,     │
                                    │                    sessionHandle, 3×time}    │
                                    │  users/<name>   -> 200 {…, roles:[…]}        │
                                    └───────────────┬──────────────────────────────┘
                                                    │ POST /json/sessions?_action=logout
                                                    v
                                        200 {"result":"Successfully logged out"}
                                        token invalidated -> back to ANONYMOUS
```

Rules that fall out of it:

- **`authId` is single-use in AM** and its consumption is what makes a replay a 408. A stand-in may
  keep it reusable; nothing under test notices.
- **Resolution precedence** on every session-bearing call: `tokenId` query parameter → session
  cookie → `iPlanetDirectoryPro` request header. Any one alone must work.
- **Anonymous is not an error state.** `idFromSession` answering 401 is the bootstrap's normal path
  on every cold load (REQUESTS.md Fact 1).
- **The session realm drives the path shape**, so both `/json/users?…` and
  `/json/realms/root/users?…` are hit in a single login, and both must route to the same handler.

---

## 8. What `xui-login.spec.mjs` drives specifically

It is tagged `["@deployed-am", "@local-server"]`, so all four of its tests must pass against the
stand-in. Mapped to the sections above:

| Test | Exercises |
|---|---|
| *end user logs in and lands on their profile* | §1 all of #1–#7. Needs `roles: ["ui-self-service-user"]` on `demo` so `EVENT_HANDLE_DEFAULT_ROUTE` picks `#profile/details`; then `sessionInfo()` → `idFromSession` returning `id: "demo"` and `realm: "/"`. |
| *administrator logs in and lands on the realms console* | §1 with `amadmin`, and `roles` containing `ui-realm-admin` → `#realms`. Pulls in the realm/service reads of tasks 2.10–2.11 beyond this note's scope. |
| *invalid credentials are rejected without establishing a session* | §4 in full: the 401 body, the `alert-danger` in `#messages`, the URL staying at `#login/`, and `idFromSession` still 401 afterwards. |
| *logout ends the session and protected routes return to the login form* | §6 in full, then §5's stale-cookie path — `#profile/details` must bounce to `#login`. |

**Not driven by this spec, though reachable elsewhere:** the `sessionUpgradeSSOTokenId` begin (§5) —
each test gets a fresh context, so no test loads `#login/` holding a session; the 408 `authId`-replay
retry (§2); the `authId`-in-a-401-body chain advance (§4); multi-stage chains and non-`DataStore1`
modules (`xui-auth-chains`, `xui-auth-modules`, both `@deployed-am`).

Two things the spec relies on that are easy to miss:

- `sessionInfo()` in `../common/xui-commons.mjs` calls **`POST /json/users?_action=idFromSession`
  from an `APIRequestContext`**, which shares no cookie jar with the browser — it accepts 401 *or*
  403 as "no session" and treats anything else non-OK as a hard failure. So the stand-in must not
  answer a missing session with 500 or an empty 200.
- The spec asserts the `#profile/details` page renders a *"User profile"* heading and `#realms` a
  level-1 *"Realms"* heading — those need §1 #7 and the console's own reads, not just the session.

---

## 9. The boundary — server behaviour a stand-in must not reproduce

**The known case: `xui-httponly.spec.mjs`, `@deployed-am` only.** It asserts (a) the `HttpOnly`
attribute on the real browser cookie matching `serverinfo/*`'s `cookieHttpOnly`, (b) that in
HttpOnly mode a successful authenticate response *omits* `tokenId` from the body (governed by
`org.openidentityplatform.openam.httponly.allowTokenInBody`), and (c) AM's server-side
session-upgrade fallback — that with `sessionUpgradeSSOTokenId` absent, the REST authenticate flow
resolves the session to upgrade from the auto-sent HttpOnly cookie instead of orphaning it. Its own
header states the reason: a stand-in would have to reimplement the behaviour under test, so a green
run would prove only that both sides were written to agree (design.md D16).

**Others found, all of them AM-internal and none of them asserted by an `@local-server` spec:**

1. **`authId` as a signed HS256 JWT carrying `otk`/`realm`/`sessionId`.** AM round-trips its
   in-flight session id through the token and rejects a tampered one with
   `400 "AuthId JWT Signature not valid"` [live]. A stand-in should treat `authId` as an opaque
   handle into its own map. Reproducing AM's JWT — signature, `otk` nonce, DN-form realm — would be
   modelling AM's internals, and nothing observes it.
2. **`authId` single-use expiry and the 408 retry.** `408 "Session has timed out"` on replay, and
   `AuthNService`'s stage-1 auto-retry. Real AM behaviour, not driven by any `@local-server` spec.
3. **`AMAuthCookie` and the `AMAuthCookie=LOGOUT` clear.** An AM implementation detail for tracking
   an in-flight authentication; proven not to be part of the protocol (§1).
4. **`amlbcookie`.** Load-balancer stickiness carrying the container's server id. No XUI code reads
   it.
5. **The session-upgrade shortcut** (`?sessionUpgradeSSOTokenId=`, §5) — AM returns the existing
   token with no callbacks. This one is *reachable* from a `@local-server` spec in principle (any
   fresh load of `#login/` holding a session), just not from `xui-login.spec.mjs`. Worth a
   deliberate decision rather than an accident.
6. **Zero-page login** (`X-Username`/`X-Password`/`X-NoSession`, and the `zeroPageLogin` block in
   `serverinfo/*`), and the `X-OpenAM-Username`/`X-OpenAM-Password` one-call authenticate the
   capture tool and fixtures use (`NOTES-volatility.md` §Authentication). The browser sends the
   `X-*` anonymous headers on every authenticate call and AM ignores them; a stand-in must ignore
   them too, which means *not* implementing zero-page login.
7. **Account lockout.** Off in a default AM, which is the only reason
   `xui-login.spec.mjs`'s failed-login test can share an instance and a user with the tests around
   it (its own comment says so). A stand-in must not add lockout.
8. **`serverinfo/version` requiring a session** — 403 `"No session for request."` when anonymous
   [live]. Called by the Footer after login, not part of the auth exchange.

---

## Instance state

No configuration was changed, no realm created, no user modified. Every write-shaped call in this
survey was a read; `PUT /json/realms/root/users/demo` was never issued.

Sessions were created and all but two were invalidated. **Two live sessions were left behind** — one
`demo`, one `amadmin` — created by a probe that compared value identity without printing the tokens,
so they could not be logged out by handle afterwards. They expire on AM's own timers: 30-minute idle,
2-hour maximum, both observed on `getSessionInfo` [live]. Session enumeration was attempted as a
cleanup route and is **not available on this instance**: both
`GET /json/sessions?_queryFilter=true` and `?_queryId=all` answer `500` with an empty body as
`amadmin`.

## Not determined

- **Why `GET /json/sessions?_queryFilter=true` returns 500** on this instance. Only pursued as a
  cleanup route, abandoned rather than worked around.
- **Whether AM ever omits `successUrl` from a successful authenticate response.** Both `demo` and
  `amadmin` got `/openam/console` here; the `SessionToken.isAuthenticated` HttpOnly branch depends on
  `successUrl` being present, but that branch is `@deployed-am` territory anyway.
- **The exact number of `getSessionInfo` repeats after login.** Three owners fire it
  (`updateSessionInfo`, `checkForDifferences`, `SessionValidator`), the count varies with route
  changes and timing, and nothing asserts it. The stand-in only has to answer every one of them 200.
- **Multi-stage chain behaviour** — how `authId` advances across two modules, and the shape of a
  second-stage callbacks document. Out of this note's scope (`DataStore1` is one stage) and covered
  by the `@deployed-am` `xui-auth-chains` spec.
