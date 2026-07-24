# Phase 5a-2 — the 9 simple OAuth2/OIDC JSON endpoints → CHF: Detailed Implementation Plan

Execution plan for **step 5a-2** of [Phase 5](phase-5-oauth2.md) of the Restlet → CHF migration — the nine
remaining Group-A JSON endpoints, ported off Restlet onto CHF as **build-ahead handlers wired to no route**
(Restlet still serves `/oauth2` until the 5d-1 flip). Parent tracker: [plan.md](plan.md); umbrella substrate:
[phase-5-oauth2.md](phase-5-oauth2.md); the step this one builds on: [phase-5a-1.md](phase-5a-1.md) (the shared
`AbstractOAuth2HttpJsonEndpoint` base + `TokenEndpointHandler` reference); decisions: [decisions.md](decisions.md);
reusable CHF patterns: [chf-patterns.md](chf-patterns.md); test layers:
[../../test-infrastructure.md](../../test-infrastructure.md). Written 2026-07-24; branch
`features/restlet-migration`. All facts below verified against the tree on 2026-07-24 (three parallel
source-mapping passes over the nine Restlet resources + their services + the route wiring + the openam-http
annotation dispatcher).

## Context

5a-2 ports the **nine mechanical JSON endpoints** — everything in [Group A](phase-5-oauth2.md#group-a--json-endpoints-5a)
except `/access_token` (done in 5a-1). Each is the same [conversion-template](phase-5-oauth2.md#the-conversion-template)
shape: `extends ServerResource`, `@Inject` a transport-free service + `OAuth2RequestFactory` + the Restlet
`ExceptionHandler`, one verb method doing `requestFactory.create(getRequest())` → one service call returning a
`JsonValue` → wrap in a `Representation`, plus a uniform `doCatch(Throwable) → exceptionHandler.handle(...)`.
They become subclasses of the **`AbstractOAuth2HttpJsonEndpoint`** base that 5a-1 established
(`openam-oauth2/.../oauth2/http/AbstractOAuth2HttpJsonEndpoint.java:42`).

**The domain services are already transport-free and are NOT touched** — `TokenInfoService`,
`TokenIntrospectionService`, `UserInfoService`, `OpenIDConnectProviderConfiguration`,
`OpenIdConnectClientRegistrationService`, `TokenStore`/`ClientAuthenticator` (revoke), the id-token validators,
`tokenStore.createDeviceCode` (device/code). 5a-2 ports only the **transport shells**.

The nine, with their current route wiring (`OAuth2RouterProvider.java:106-146`) and the CHF handler each becomes:

| Route | Verb(s) | Restlet resource (`file:line`) | Transport-free service call (kept) | → CHF handler |
|---|---|---|---|---|
| `/tokeninfo` | GET | `ValidationServerResource` (`:72-98`) | `tokenInfoService.getTokenInfo(o2)` (`:78`) | `TokenInfoHandler` |
| `/introspect` | GET+POST | `TokenIntrospectionResource` (`:62-82`) | `tokenIntrospectionService.introspect(o2)` (`:69`) | `TokenIntrospectionHandler` |
| `/userinfo` | GET+POST | `UserInfo` (`:70-92`) | `userInfoService.getUserInfo(o2)` (`:77`) | `UserInfoHandler` |
| `/.well-known/openid-configuration` | GET | `OpenIDConnectConfiguration` (`:68-87`) | `providerConfiguration.getConfiguration(o2)` (`:72`) | `OpenIDConnectConfigurationHandler` |
| `/connect/jwk_uri` | GET | `OpenIDConnectJWKEndpoint` (`:67-86`) | `providerSettingsFactory.get(o2).getJWKSet()` (`:71-72`) | `JwkUriHandler` |
| `/connect/register` | GET+POST→201 | `ConnectClientRegistration` (`:84-134`) | `clientRegistrationService.createRegistration/getRegistration` (`:94,:118`) | `ConnectClientRegistrationHandler` |
| `/device/code` | POST | `DeviceCodeResource` (`:83-151`) | `tokenStore.createDeviceCode(...)` (`:106`) | `DeviceCodeHandler` |
| `/token/revoke` | POST | `TokenRevocationResource` (`:110-238`) | `clientAuthenticator.authenticate` + `tokenStore` cascade | `TokenRevocationHandler` |
| `/idtokeninfo` | POST | `IdTokenInfo` (`:114-234`) | `validateIdToken(o2)` + `clientRegistrationStore.get` | `IdTokenInfoHandler` |

Build-ahead: **nothing is routed.** The guard is the per-handler unit tests + the §E oracle recorded against
live Restlet ([R-5.9](phase-5-oauth2.md#risk-register-extends-planmds--phase-4s)); the handlers first appear in a
live CHF chain in `OAuth2RouterIT` at 5d-1. `mvn -o -pl openam-oauth2 install -DskipTests` at the end so 5b
compiles against any shared additions.

> **Convention.** New classes: `org.openidentityplatform.openam.oauth2.http`, CDDL header, `Copyright 2026 3A
> Systems LLC.`, **no `@since`** ([decisions.md](decisions.md)). Modified-in-place classes (the base) keep their
> header and gain a `Portions copyright 2026 3A Systems LLC.` line.

## Scope & sizing — split into 5a-2a + 5a-2b (confirmed 2026-07-24)

Nine handlers + one base correction is too much for one reviewable commit. Eight are near-mechanical; one
(`IdTokenInfoHandler`) rewrites the request's operative realm mid-flight and is the genuine risk. Split on the
same reviewability/risk-isolation principle the umbrella used for 5b/5d:

| Step | Scope | New/changed | Risk |
|---|---|---|---|
| **5a-2a** | **Base cache correction (D1)** + the 5 pure-template handlers: `TokenInfoHandler`, `TokenIntrospectionHandler`, `UserInfoHandler`, `OpenIDConnectConfigurationHandler`, `JwkUriHandler`. Establishes the per-endpoint cache hook + the `@Get @Post` dual-verb pattern (D2). | base edit + 5 handlers + 5 tests | **Low** |
| **5a-2b** | The 4 handlers with real decisions: `ConnectClientRegistrationHandler` (201 + deployment URL + Bearer, D5), `DeviceCodeHandler` (verification URL + params), `TokenRevocationHandler` (challenge + cascade + `CoreTokenException`, D4), `IdTokenInfoHandler` (realm rewrite + non-base errors + `String`→`Map`, D3). `IdTokenInfoHandler` is the gating item — ported **last** with a real-context test. | 4 handlers + 4 tests | **Med** (idtokeninfo) |

**Chosen: 2-way** (2026-07-24) — 5a-2a is trivially reviewable and de-risks the base change; 5a-2b groups the
four judgement calls with idtokeninfo isolated as the last, separately-tested item. (Alternatives weighed and
rejected: **one commit** — all 9 + base, ~18 files, larger review; **3-way** — idtokeninfo split into its own
5a-2c, an extra commit for marginal isolation over "port it last within 5a-2b".)

## Key research findings (drove this design)

### 1. ⚠ Cache-header provenance is per-endpoint — the shared base's unconditional `noCache` is wrong for 8 of 9

The base `onError` calls `noCache(response)` **unconditionally** (`AbstractOAuth2HttpJsonEndpoint.java:60`),
adding `Cache-Control: no-store` + `Pragma: no-cache` to every JSON error body. That is correct **only for
`/access_token`** (and `/authorize`, the browser base). **Verified against source:**

- The Restlet `OAuth2Filter` that stamps `no-store`+`Pragma` (`OAuth2Filter.java:76-77`) is extended by
  **exactly two** classes — `TokenEndpointFilter` (`/access_token`) and `AuthorizeEndpointFilter` (`/authorize`).
- All nine 5a-2 routes are wrapped by `auditWithOAuthFilter(...)` = **`OAuth2AccessAuditFilter` only**
  (`OAuth2AccessAuditFilter extends OAuth2AbstractAccessAuditFilter extends AbstractRestletAccessAuditFilter` —
  **not** `OAuth2Filter`), so the filter adds **no** cache headers.
- Of the nine resources, **only `ValidationServerResource` (`/tokeninfo`) sets cache headers itself** —
  `getResponse().getCacheDirectives().add(CacheDirective.noCache()/noStore())` (`:81-82`), i.e. one header
  `Cache-Control: no-cache, no-store` (**no `Pragma`**), on the **success path only** (set after the service
  returns; the `doCatch` error path adds nothing). The other eight set none, anywhere.

⇒ **Three distinct cache contracts:**

| Endpoint(s) | Restlet cache headers |
|---|---|
| `/access_token` (5a-1) | `Cache-Control: no-store` + `Pragma: no-cache` — success **and** error (from `OAuth2Filter`) |
| `/tokeninfo` | `Cache-Control: no-cache, no-store` (no `Pragma`) — **success only** (from the resource) |
| `/introspect`, `/userinfo`, `/connect/register`, `/connect/jwk_uri`, `/.well-known/…`, `/device/code`, `/token/revoke`, `/idtokeninfo` | **none, ever** |

As shipped, every 5a-2 handler's error body would gain `no-store`+`Pragma` Restlet never sent (the 8), and even
`/tokeninfo` would get the wrong shape. The 5d-1 byte-diff would flag all of it. **This also makes 5a-1's
round-1 finding-1 note ("correct for all 5a-2 endpoints — they inherit it from `OAuth2Filter`") factually
wrong** — corrected here and in the 5a-1 doc, chf-patterns §5, and the base javadoc (D1).

### 2. openam-http already supports `@Get @Post` on one method — the GET+POST "split" is a non-issue

`/introspect` and `/userinfo` are each **one** Restlet method serving both verbs (`@Post("form") @Get` /
`@Get @Post("form:json")`). CHF handles this natively: `Endpoints.from` calls `AnnotatedMethod.findMethod` **once
per verb** (`Endpoints.java:60-63`), and `findMethod` scans `getMethods()` for **that verb's** annotation
independently (`AnnotatedMethod.java:204-213`). A single method carrying **both** `@Get` and `@Post` is returned
by both scans → both verbs dispatch to it. So introspect/userinfo port as a **single dual-annotated method** —
near-verbatim of the Restlet shape, no delegation, no framework change. (Pin it with a test that dispatches both
GET and POST to the one method — cheap insurance that the dual-annotation resolves.) The ignored
`Representation body` parameter both resources carry (a Restlet entity-availability idiom) is **deleted** — the
CHF `Entity` is buffered ([chf-patterns §7](chf-patterns.md)).

### 3. `IdTokenInfo` rewrites the operative realm from the token body — the one complex port

`/idtokeninfo` derives its realm from the **id_token's `realm` claim**, not the URL/`RealmContext`, and injects
it back so three downstream collaborators (all reading the *plain* request) see it. Two mechanisms:

- **Inner `ValidateIdTokenRequest extends OAuth2Request`** (`IdTokenInfo.java:236-348`) — a delegating wrapper
  that overrides `getParameter` (`:251-256`) to return the token's realm for `OAuth2Constants.JWTTokenParams.REALM`
  (== `"realm"`), delegating everything else verbatim. Passed only to `clientRegistrationStore.get(clientId,
  wrapper)` (`:162`). **Port:** keep it as a plain `OAuth2Request` subclass; **delete its `getRequest()` override**
  (`:245-248`, Restlet-typed — nothing on the CHF path calls it; the base throws `UnsupportedOperationException`).
- **`setRealmOnRequest(o2, realm)`** (`:190-196`) writes the realm in four places → three CHF writes:
  - `request.setAttribute(OAuth2Constants.Custom.REALM, realm)` (collapses the two Restlet `getAttributes().put`
    at `:191-192`; `ChfOAuth2Request.getParameter` reads attributes first, overriding the seeded realm).
  - `request.setAttribute(OAuth2Constants.Custom.REALM_OBJECT, Realm.of(realm))` (`:193`) — **load-bearing:**
    `urisFactory.get(request)` (`:169`) reads `REALM_OBJECT` **directly with no fallback**
    ([chf-patterns §7](chf-patterns.md)); omit it and `.getTokenEndpoint()` NPEs.
  - `request.getHttpServletRequest().setAttribute(ISAuthConstants.REALM_PARAM, realm)` (replaces
    `ServletUtils.getRequest(...).setAttribute(...)` at `:194-195`).

The failure mode is silent (wrong-realm client lookup) or an NPE inside `urisFactory` — **neither caught by a
mocked `OAuth2Request` test** (a mock makes `setRealmOnRequest`/`getParameter` no-ops). Hence the real-context
test (D3).

### 4. `/token/revoke` — the challenge decoration is deleted, `CoreTokenException` is the one non-base error

`TokenRevocationResource` (241 L, package `org.forgerock.openam.oauth2.rest`) authenticates the client, verifies
token ownership, and cascade-deletes (single access token, or a refresh token + all its access tokens; per-token
`ServerException` in the loop is logged not rethrown, `:183-185`), returning empty `{}` at 200 (`:135`). Two
notes:

- It decorates `getResponse().setChallengeRequests(new ChallengeRequest("Basic", realm))` before rethrowing
  `InvalidClientAuthZHeaderException` (`:136-142`). **Port: just `throw e`** — `OAuth2Error.of` copies the
  challenge and the factory emits `WWW-Authenticate: Basic realm="…"` (the D14 path 5a-1 already proved). The
  `RestletConstants` scheme map dies with the resource.
- `CoreTokenException` (`:147-150`) is the **only** non-`OAuth2Exception` it catches, mapped to a bespoke 500. The
  base `@ExceptionHandler(OAuth2Exception)` will **not** catch it → framework CREST 500. It is effectively
  unreachable (`tokenStore.read` throws the OAuth2 `ServerException`/`NotFoundException` instead), but to keep the
  **status** at 500 the handler catches it and rethrows `new ServerException(...)` (D4). (The exact error string
  diverges; acceptable on an unreachable path.)

### 5. `/connect/register` — deployment-URL derivation + an unguarded-Bearer NPE that the neutral read fixes

- **Bearer token:** POST reads it null-guarded (`:88-89`), **GET reads it unguarded** (`:115`,
  `getChallengeResponse().getRawValue()`) — which **NPEs today** when no `Authorization` header is present.
  The neutral `o2.getAuthorizationBearerToken()` returns `null` gracefully in both cases → the null flows to the
  service's auth check → a proper 401 instead of a 500 NPE. This is a **deliberate, documented divergence** (like
  the GET→405 change at 5d-1); record it in 5d-1's smoke matrix. (Second subtlety: `getRawValue()` returns the
  raw credential for any scheme; `getAuthorizationBearerToken()` is `Bearer`-only — benign, registration expects
  Bearer.)
- **Deployment URL** (`:92-93`): `getHostRef() + "/" + getResourceRef().getSegments().get(0)` =
  `scheme://host[:port]/<first-segment>` (e.g. `https://host:port/openam`). CHF's `Request.getUri()` is not a safe
  source (may be context-relative under `HttpFrameworkServlet`), so reconstruct from
  `o2.getHttpServletRequest()`. **Choose raw reconstruction (byte-parity)** over
  `BaseURLProviderFactory.get(realm).getRootURL(servletRequest)` (the *configured* base URL, which can diverge
  under a forwarded-header/fixed-value provider config) — zero behaviour change is the migration default. A small
  private helper in the handler suffices; extract to a shared util only if 5b needs the same. **Note:**
  `/device/code` uses the *configured* `getRootURL` fallback deliberately (`DeviceCodeResource.java:135`) — keep
  each endpoint's existing derivation, do not unify.

### 6. `IdTokenInfo`'s success body is a JSON `String` → convert to `Map` (avoid the ISO-8859-1 trap)

`IdTokenInfo` returns `filterClaims(...).build()` (`:120`); `JwtClaimsSet.build()` returns a **JSON `String`**
(commons). `setEntity(String)` on a hand-built `Response` silently encodes **ISO-8859-1**
([chf-patterns §6](chf-patterns.md), risk #21) — and id_token claims can carry non-ASCII (`name`, `locale`). So
the handler must turn the claims into a `Map`/`JsonValue` before `setEntity` (e.g.
`JsonValueBuilder.toJsonValue(claims.build()).asMap()`), routing through `setJson` → `application/json;
charset=UTF-8`. This is the only endpoint whose Restlet body is a `String`; the other eight already build from a
`JsonValue.asMap()`.

## Design decisions

<a id="d1"></a>
### D1 — Correct the base: per-endpoint cache headers via an overridable error hook

The shipped base (`AbstractOAuth2HttpJsonEndpoint`) hard-codes `noCache` on the error path. Make no-cache
**opt-in** so each endpoint reproduces its real Restlet contract (finding 1). Surgical change:

```java
@ExceptionHandler
public Response onError(OAuth2Exception e, @Contextual Context ctx, @Contextual Request request) {
    OAuth2Request o2 = requestFactory.create(ctx, request);
    Response response = errorResponseFactory.toJsonResponse(
            OAuth2Error.of(e).withState(o2.<String>getParameter("state")));
    return withErrorHeaders(response);          // was: noCache(response)
}

/** Endpoint-specific error-response headers. Default: none — most OAuth2 JSON endpoints add no cache headers
 *  on their error path (only /access_token does, via the Restlet OAuth2Filter). */
protected Response withErrorHeaders(Response response) {
    return response;
}

protected static Response noCache(Response response) { /* unchanged: no-store + Pragma no-cache */ }
```

- **`TokenEndpointHandler` (5a-1)** overrides `withErrorHeaders` → `return noCache(response);` and keeps
  `noCache(response)` on its success path — preserving both its cache headers and its
  `errorResponseCarriesCacheHeaders` test unchanged.
- **`TokenInfoHandler`** sets `response.getHeaders().put("Cache-Control", "no-cache, no-store")` on its
  **success** response only (not via `noCache()` — the shape differs: no `Pragma`), and does **not** override
  `withErrorHeaders` (its error path carries nothing).
- **The other seven** override nothing and set nothing → no cache headers, matching Restlet.
- **Docs corrected:** base javadoc (`:63-66`), [chf-patterns §5](chf-patterns.md) ("No-cache belongs on every
  OAuth2 response…" bullet), and [phase-5a-1.md](phase-5a-1.md) round-1 finding-1 note — all currently overclaim
  the `OAuth2Filter` provenance.

This base edit is 5a-2a's **first** step (build-ahead, no route — safe to touch shipped 5a-1 code). Land it with
the `TokenEndpointHandler` override + a re-run of the 5a-1 suite green before the first new handler.

<a id="d2"></a>
### D2 — GET+POST endpoints: one method, both annotations

`TokenIntrospectionHandler`/`UserInfoHandler`: a single `@Get @Post public Response introspect(@Contextual
Context ctx, @Contextual Request req)` (finding 2). No shared-helper split, no `Representation` param. Pin with a
test that drives both a GET and a POST `Request` through `Endpoints.from(handler)` to the same method.
`ConnectClientRegistrationHandler` stays **two** methods (`@Get getClient` 200, `@Post createClient` 201) — they
are genuinely different calls, not one shared body.

<a id="d3"></a>
### D3 — `IdTokenInfoHandler`: port the realm rewrite faithfully, test with a real context

Reproduce finding 3 exactly: keep `ValidateIdTokenRequest` (drop its `getRequest()` override), the three
`setRealmOnRequest` writes, the `String`→`Map` conversion (finding 6), **and the two non-base error paths** —
`RealmLookupException` → `BadRequestException` (`:126-128`) and the `InvalidClientException` **message override**
(`:121-123`, throw a fresh `InvalidClientException("no registered client matches audience of id_token")`, not
`e.getMessage()`). Both must stay explicit catches (neither reaches the base mapper as-is). **Test with a real
`ChfOAuth2Request`** over a `RootContext → AttributesContext → RealmContext → UriRouterContext` chain
([chf-patterns §5](chf-patterns.md#5-chf-handler-test-scaffolding)), asserting the token-claim realm actually
reaches `providerSettingsFactory`/`urisFactory` and the servlet attribute — a mocked `OAuth2Request` hides the
exact regression this guards.

<a id="d4"></a>
### D4 — `TokenRevocationHandler`: throw the challenge, rethrow `CoreTokenException` as `ServerException`

Delete the `ChallengeRequest` decoration (`throw` the `InvalidClientAuthZHeaderException`; base emits the
header). Catch `CoreTokenException` → `throw new ServerException(...)` to keep the 500 status (finding 4). Port
the cascade-delete + client-ownership check verbatim (transport-free).

<a id="d5"></a>
### D5 — `ConnectClientRegistrationHandler`: neutral Bearer, raw deployment URL, handler-owned 201

`o2.getAuthorizationBearerToken()` for both verbs (GET no longer NPEs — documented divergence). Deployment URL
reconstructed raw from the servlet request (finding 5). POST returns `new Response(Status.valueOf(201))
.setEntity(registration.asMap())`; GET returns 200. `client_id` on GET via `o2.getParameter(CLIENT_ID)`.

<a id="d6"></a>
### D6 — The uniform mechanical port (all nine)

Drop `extends ServerResource`, `doCatch`, the per-verb `catch (OAuth2Exception)` re-wrap, and the
`ExceptionHandler`/`JacksonRepresentationFactory` deps. Extend `AbstractOAuth2HttpJsonEndpoint`; add
`@Contextual Context ctx, @Contextual Request request`; build `o2 = requestFactory.create(ctx, request)`
(the `(Context, Request)` overload); **`throw` the `OAuth2Exception`** to the base `onError`; success =
`new Response(Status.valueOf(200)).setEntity(jsonValue.asMap())` (`setJson` → `application/json; charset=UTF-8`;
**never `setEntity(String)`** — finding 6). Also drop `TokenIntrospectionResource`'s dead
`OAuth2ProviderSettingsFactory` field (`:41,:51`, stored-never-used).

## New / modified / tests

### New (openam-oauth2, `org.openidentityplatform.openam.oauth2.http`, new-class convention)

**5a-2a:** `TokenInfoHandler`, `TokenIntrospectionHandler`, `UserInfoHandler`,
`OpenIDConnectConfigurationHandler`, `JwkUriHandler`.
**5a-2b:** `ConnectClientRegistrationHandler`, `DeviceCodeHandler`, `TokenRevocationHandler`,
`IdTokenInfoHandler` (+ its `ValidateIdTokenRequest` inner class).

### Modified in place (no `Portions` line — both are our own 2026 classes)

- **`AbstractOAuth2HttpJsonEndpoint`** — the D1 error-hook (5a-2a).
- **`TokenEndpointHandler`** — override `withErrorHeaders` → `noCache` (D1, 5a-2a).

(Both carry `Copyright 2026 3A Systems LLC.` from 5a-1 — no ForgeRock header — so a `Portions` line does not apply.)

### Tests (openam-oauth2; TestNG + Mockito + AssertJ; scaffold per [chf-patterns §5](chf-patterns.md))

One focused test class per handler. Common asserts: success status + `body == service.asMap()` +
`Content-Type: application/json; charset=UTF-8`; a thrown `OAuth2Exception` → the JSON error body (base
`onError`); **cache headers exactly per finding 1** (tokeninfo: `no-cache, no-store` on success, none on error;
the other eight: none anywhere). Per-handler specials:

- **`TokenIntrospectionHandler`/`UserInfoHandler`** — dispatch **both** GET and POST through `Endpoints.from` to
  the single dual-annotated method (D2). Introspect: assert whether the client-auth path can throw
  `InvalidClientAuthZHeaderException` → a **new** `WWW-Authenticate` the Restlet resource never emitted (verify
  the exact `InvalidClient*` subtype; if so, record as a deliberate divergence). Userinfo: `InvalidTokenException`
  carries no challenge → no `WWW-Authenticate` (parity).
- **`ConnectClientRegistrationHandler`** — POST→201, GET→200; Bearer via `getAuthorizationBearerToken()`;
  deployment-URL helper (assert the reconstructed `scheme://host/<seg>`); GET with no `Authorization` → graceful
  (no NPE).
- **`TokenRevocationHandler`** — empty `{}` 200; `InvalidClientAuthZHeaderException` → 401 + `WWW-Authenticate:
  Basic realm="…"`; refresh-token cascade (mock `TokenStore.queryForToken` → deletes each); `CoreTokenException`
  → 500.
- **`IdTokenInfoHandler`** — the **real-context** test (D3): token-claim realm reaches the collaborators +
  `ISAuthConstants.REALM_PARAM` servlet attribute; `RealmLookupException` → 400 "Invalid realm"; unregistered
  audience → 400 "no registered client matches audience of id_token"; non-ASCII claim round-trips UTF-8 (guards
  finding 6).
- **`DeviceCodeHandler`** — success map keys (`device_code`/`user_code`/`expires_in`/`interval`/
  `verification_uri`); missing `client_id`/`scope`/`response_type` → 400 `bad_request` (byte-parity with the
  Restlet's literal `OAuth2RestletException(400, "bad_request", …)` — **not** `invalid_request`, corrected 5a-2b);
  verification-URL fallback via the servlet request.
- **`AbstractOAuth2HttpJsonEndpoint` (D1)** — a focused assertion that `withErrorHeaders` default adds nothing,
  and `TokenEndpointHandler`'s override still stamps `no-store`+`Pragma` on the error path (re-run the 5a-1 suite;
  `errorResponseCarriesCacheHeaders` must stay green).
- **Gate:** `grep -rn "org.restlet\|getCurrent()"` over the nine new files → 0.

## Integration testing

5a-2 ships **no route**, so — like 5a-1 — there is no composition IT yet; the handlers first run in a live CHF
chain in `OAuth2RouterIT` at **5d-1**. What 5a-2 owns and what it feeds forward:

- **Unit** (above) — per-handler dispatch, error mapping, cache headers, the dual-verb resolution, the
  revoke cascade, and `IdTokenInfoHandler`'s real-context realm test (the closest thing to an IT in 5a-2, because
  it exercises the `ChfOAuth2Request` attribute-precedence + `REALM_OBJECT` seeding that a mock would void).
- **§E cache-lock rows — RECORDED 2026-07-24** (task #11 done; `e2e/oauth2/oauth2-test.spec.mjs`, 13 rows green
  vs live `openidentityplatform/openam` Restlet). Finding 1 is now a **recorded oracle**, not a code-read. The
  three distinct contracts, captured verbatim (do not "tidy"):
  - `/access_token` — `Cache-Control: no-store` + `Pragma: no-cache`, on **success** (client_credentials 200) **and
    error** (GET 405). Both asserted.
  - `/tokeninfo` — success (200) carries `Cache-Control: no-cache, no-store` and **no `Pragma`** (matches
    `TokenInfoHandler`'s hardcoded string byte-for-byte); the 401 error path carries **none**.
  - `/introspect` (200) and `/userinfo` (400) — **no** `Cache-Control`/`Pragma`.
  - **New find:** `/tokeninfo` success `Content-Type` is `application/json` with **no charset** (Restlet), whereas
    CHF `setEntity(Map)` will emit `application/json; charset=UTF-8` → a deliberate 5d-1 byte-diff, asserted in the
    oracle so it is not lost when Restlet dies. Flag-not-fix at the flip.
- **Forward context for 5d-1's `OAuth2RouterIT`** (assert then, not now): `/tokeninfo` GET cache headers; the
  three-error-shapes coexistence; `/connect/register` GET with no auth → 401 not 500; `/idtokeninfo` realm
  resolution end-to-end; the dual-verb endpoints answering both GET and POST on one route.

## Verification criteria

Per sub-step (5a-2a, then 5a-2b):

1. `mvn -o -pl openam-oauth2 test` — new handler tests green; **existing suite unchanged** (5a-1 baseline **950**
   surefire — [phase-5a-1 as-built](phase-5a-1.md); the count only grows). The 5a-1 suite in particular must stay
   green through the D1 base edit.
2. `grep -rn "org.restlet\|getCurrent()"` over the new handler files → 0 (verification gate).
3. `mvn -o -pl openam-oauth2 install -DskipTests` — so 5b compiles against the corrected base.
4. Whole-reactor `mvn -o install -DskipTests` — **doclint is fatal** ([test-infrastructure.md](../../test-infrastructure.md));
   the new classes carry no route, so the WAR is unchanged in behaviour.
5. CI (`.github/workflows/build.yml`): JDK 11–26 × 3 OSes on the `features/**` push — free cross-version coverage
   of the entity/charset handling (load-bearing for `IdTokenInfoHandler`'s UTF-8 body).

Success = all nine handlers exist as build-ahead subclasses of the corrected base, each unit-proven for its
success/error/cache contract, zero Restlet imports, module + reactor build green, and the §E cache rows recorded
against live Restlet.

## Risks (extends [phase-5-oauth2.md](phase-5-oauth2.md)'s register)

- **R-5a2.1 — the base cache correction (finding 1/D1).** If the D1 hook is wrong, either `/access_token` loses
  its error-path cache headers (5a-1 regression) or the eight no-cache endpoints keep them (5d-1 diff). **Guard:**
  the 5a-1 suite stays green through D1; each new handler asserts its exact cache contract; the §E rows record the
  live truth.
- **R-5a2.2 — `IdTokenInfoHandler` realm rewrite (finding 3).** A wrong `setRealmOnRequest` write or a missed
  `REALM_OBJECT` seed silently resolves in the wrong realm or NPEs `urisFactory`. **Guard:** the real-context test
  (D3) — explicitly **not** a mocked `OAuth2Request`.
- **R-5a2.3 — dual-verb dispatch (finding 2/D2).** If `@Get @Post` on one method does not resolve as read, GET or
  POST 404/405s on `/introspect` or `/userinfo`. **Guard:** the both-verbs dispatch test; falls back to two
  delegating methods if the framework surprises us (it won't — verified against `AnnotatedMethod.findMethod`).
- **R-5a2.4 — new `WWW-Authenticate` on `/introspect`.** The base emits the challenge whenever the exception
  carries one; the introspect client-auth path may now surface `WWW-Authenticate` the resource never sent.
  **Guard:** assert the exact `InvalidClient*` subtype in the introspect test; if it challenges, log it as a
  deliberate 5d-1 divergence.
- **R-5a2.5 — `setEntity(String)` charset (finding 6).** `IdTokenInfoHandler` is the only endpoint whose Restlet
  body is a `String`; an ASCII fixture would miss an ISO-8859-1 regression. **Guard:** convert to `Map`/`JsonValue`
  before `setEntity`; assert a non-ASCII claim round-trips UTF-8.
- **R-5a2.6 — build-ahead, no live guard (risk #19).** Dormant until 5d-1. **Guard:** unit + §E rows + the 5d-1
  `OAuth2RouterIT`.

## CHF / framework friction (per the "fix what we own" invitation)

Three touch points were examined; only one needs a change, and it is in **our** migration base, not the framework:

- **The base cache design (D1)** — fixed in `AbstractOAuth2HttpJsonEndpoint` (ours). Not an openam-http change.
- **`@Get @Post` on one method** — **no change needed**; openam-http already dispatches per-verb independently
  (finding 2). A convenience multi-verb annotation was considered and **rejected** (the dual-annotation already
  works; a new annotation is scope for no gain — [chf-patterns §14](chf-patterns.md) smell test).
- **`setEntity(String)` ISO-8859-1 on a hand-built `Response`** (commons `Entity`, [chf-patterns §6](chf-patterns.md))
  — a known commons backlog item; 5a-2 routes around it by building `Map`/`JsonValue` bodies (finding 6). Not
  fixed here (contained, no release dependency), consistent with the phase's locked decision on
  `Form.fromRequestEntity`.

## Execution order

**5a-2a**
1. **D1 base edit** — `withErrorHeaders` hook + `TokenEndpointHandler` override → re-run 5a-1 suite green. Correct
   the three docs.
2. `OpenIDConnectConfigurationHandler` + `JwkUriHandler` (the two trivial GETs) → tests.
3. `TokenInfoHandler` (own success cache header) → test.
4. `TokenIntrospectionHandler` + `UserInfoHandler` (dual-verb, D2) → tests (both verbs dispatched).
5. `mvn -o -pl openam-oauth2 test` + gate + `install` → commit 5a-2a.

**5a-2b**
6. `ConnectClientRegistrationHandler` (D5) → test.
7. `DeviceCodeHandler` → test.
8. `TokenRevocationHandler` (D4) → test.
9. `IdTokenInfoHandler` (D3) — **last, with the real-context test**.
10. `mvn -o -pl openam-oauth2 test` + gate + `install` + whole-reactor `install -DskipTests` → commit 5a-2b.

**§E (any time in 5a–5c, before 5d-1):** add the cache-header rows to `e2e/oauth2/oauth2-test.spec.mjs` against
live Restlet (finding 1 oracle).

Then mark 5a-2 done in [plan.md](plan.md) and proceed to **5b-1**.

## As-built

### 5a-2a (landed 2026-07-24) — D1 base fix + 5 handlers

**Shipped:** `AbstractOAuth2HttpJsonEndpoint` D1 hook + `TokenEndpointHandler` override; handlers
`JwkUriHandler`, `OpenIDConnectConfigurationHandler`, `TokenInfoHandler`, `TokenIntrospectionHandler`,
`UserInfoHandler`; 5 focused test classes. **Suite: 950 → 963 surefire (+13), all green;** grep gate 0 restlet
refs; module `install` clean (javadoc jar built → doclint OK on the new classes).

**Verified findings (so they need not be re-read):**

- **D1 landed as designed.** `onError` → `withErrorHeaders(response)` (default: none); `TokenEndpointHandler`
  overrides → `noCache`. `TokenEndpointHandlerTest` (22) stayed green through the edit. `TokenInfoHandler` sets
  its own success-only `Cache-Control: no-cache, no-store` (no `Pragma`); the other four set nothing.
- **Introspect `WWW-Authenticate` divergence — CONFIRMED REAL and ACCEPTED (R-5a2.4).** The introspect service
  authenticates the client (`TokenIntrospectionService.introspect` → `clientAuthenticator.authenticate`, `:71`).
  The Restlet error path (`ExceptionHandler.handle(Throwable, Response)`, `ExceptionHandler.java:150-158`) sets
  status + JSON only — **never** a challenge. The CHF base emits `WWW-Authenticate: Basic realm="…"` for
  `InvalidClientAuthZHeaderException`. ⇒ **CHF introspect adds a header Restlet omitted** (spec-compliant, RFC 6749
  §5.2; consistent with the base's uniform challenge handling from 5a-1). **Decision: accept** (user-confirmed
  2026-07-24). **→ Record in the 5d-1 smoke matrix.**
- **`WWW-Authenticate` is emitted iff `error.getChallengeScheme() != null`** (`OAuth2ErrorResponseFactory.withChallenge`,
  `:326-330`). Only `InvalidClientAuthZHeaderException` carries a scheme; plain `InvalidClientException` (400) and
  `InvalidTokenException` (401, `invalid_token`) do **not** → userinfo stays parity (no challenge).
- **Dual-verb `@Get @Post` confirmed at RUNTIME** (not just by reading `AnnotatedMethod`): the introspect/userinfo
  tests dispatch both a GET and a POST through `Endpoints.from` to the single method and get 200. No framework
  change needed (finding 2).
- **Exception → wire codes (for later handlers' tests):** `ServerException` = **400** `server_error`
  (surprising — `super(400, …)`, not 500); `NotFoundException` = 404 `not_found`; `InvalidTokenException` = 401
  `invalid_token` (**no-arg constructor only**); `InvalidClientAuthZHeaderException` = 401 + Basic challenge; plain
  `InvalidClientException` = 400, no challenge.
- **Ignored `Representation body` param deleted** on introspect/userinfo (CHF entity is buffered).
  `TokenIntrospectionResource`'s dead `OAuth2ProviderSettingsFactory` field dropped (D6).
- **No `Portions` line** on `AbstractOAuth2HttpJsonEndpoint`/`TokenEndpointHandler` — both are our own 2026
  classes (the plan's "Modified in place (add Portions line)" note was corrected).

**Review watch-items (5a-2a review, 2026-07-24 — follow-ups, not code changes):**

- **5d-1 byte-diff — tokeninfo cache-header string. ORACLE CAPTURED 2026-07-24 (task #11 done).** Live Restlet
  renders `CacheDirective.noCache()+noStore()` (`ValidationServerResource:81-82`) as exactly
  `Cache-Control: no-cache, no-store` (one header, space after the comma, no `Pragma`) — **identical** to
  `TokenInfoHandler`'s hardcoded string, so no cache-header divergence is expected. Pinned in
  `e2e/oauth2/oauth2-test.spec.mjs`. **New sub-finding:** the tokeninfo success `Content-Type` is `application/json`
  with **no charset** on Restlet, but CHF `setEntity(Map)` emits `application/json; charset=UTF-8` → a deliberate
  Content-Type byte-diff to flag (not fix) at 5d-1; also asserted in the oracle.
- **POST content-type variance.** Restlet tagged introspect `@Post("form")` and userinfo `@Post("form:json")`
  (variant hints); the CHF handlers accept any POST and rely on `ChfOAuth2Request`/service-layer param extraction.
  Parity holds for form bodies (the real case); a JSON-body **userinfo** POST is an untested edge. Acceptable — noted
  so 5d-1 doesn't treat it as a surprise. Verb *sets* themselves match 1:1 (Get/Post ↔ Get/Post, verified in review).

**Committed 2026-07-24** (5a-2a landed as a single commit; 5a-2b to follow).

### 5a-2b (built 2026-07-24) — the 4 handlers with real decisions

**Shipped:** `ConnectClientRegistrationHandler` (D5), `DeviceCodeHandler`, `TokenRevocationHandler` (D4),
`IdTokenInfoHandler` (D3, + inner `ValidateIdTokenRequest`); 4 focused test classes (**16 new tests**, all green;
http-package suite 42 green incl. the `TokenEndpointHandler` D1 regression). Grep gate: 0 `org.restlet` / `getCurrent()`
imports in the new handlers (javadoc prose that *names* the dropped Restlet types is not a code ref).

**Verified findings & decisions (so they need not be re-read):**

- **D5 deployment URL — reused `OAuth2Utils.getDeploymentURL(servletRequest)`** instead of the plan's "small private
  helper". It already emits the exact `scheme://host:port/<first-URI-segment>` shape (raw reconstruction, **not** the
  configured `BaseURLProvider` root the plan warned against) and is `@Inject`-ed like `DeviceCodeResource`. Concern
  **C2 pinned**: the deployment root is the first URI segment (`openam`), not a contextPath.
- **D5 neutral Bearer** — `getAuthorizationBearerToken()` on both verbs; the Restlet GET-without-header **500 NPE
  becomes a graceful null → proper 401**. Documented 5d-1 divergence (record in the smoke matrix).
- **DeviceCode missing-param → `bad_request`, not `invalid_request`** (plan line 306 corrected). `BadRequestException(msg)`
  = `super(400, "bad_request", …)` reproduces the Restlet's literal. Dropped the provably-dead `if (scope == null)`
  line (the `isEmpty(scope)` guard already threw). Verification-URI fallback keeps the **configured** `getRootURL`
  (deliberately not unified with D5's raw reconstruction).
- **D4 revoke — `CoreTokenException` catch omitted (plan D4 corrected, user-approved).** `TokenStore.read(String)` throws
  only the OAuth2 `ServerException`/`NotFoundException`; nothing in the flow throws `CoreTokenException` — the Restlet
  catch was unreachable dead code (its `getToken` over-declared `throws CoreTokenException`). D4's stated goal (keep the
  path at 500 via `new ServerException`) was doubly wrong: **`ServerException` is 400**, and **no `OAuth2Exception` maps
  to 500** (the class is abstract). Recorded in [chf-patterns §15](chf-patterns.md#15-oauth2exception--http-status-quirks-phase-5a-2b).
  The challenge decoration is deleted — a bare `throw` lets the base emit `WWW-Authenticate` (D14 path).
- **D3 idtokeninfo — two plan corrections, wire output preserved byte-for-byte.** `new InvalidClientException(msg)` does
  **not compile** (ctor is `protected`); reproduced 400 + `invalid_client` + fixed message via
  `BadRequestException(e.getError(), "no registered client matches audience of id_token")`. The `RealmLookupException`
  path likewise → `BadRequestException("Invalid realm", …)`. Kept `ValidateIdTokenRequest` minus its Restlet-typed
  `getRequest()` override; three CHF realm writes (`REALM`, load-bearing `REALM_OBJECT`, servlet `REALM_PARAM`);
  `build()` String → `JsonValueBuilder.toJsonValue(...).asMap()` for UTF-8 (finding 6). Dropped the Restlet's dead
  `SigningManager` field (D6 precedent).
- **Concern C1 answered:** `JWTTokenParams.REALM` == `Custom.REALM` == `"realm"`, and `ChfOAuth2Request.getParameter`
  reads attributes first, so after `setRealmOnRequest` the wrapper's `getParameter("realm")` override is **redundant on
  the CHF path** (the attribute-seeding already returns the token realm). **Kept** for faithfulness — harmless.
- **D3 real-context test proves the regression the plan feared:** a real `ChfOAuth2Request` over
  `RootContext→AttributesContext→RealmContext→UriRouterContext` with a real HS256 id_token whose `realm` claim (`/beta`)
  differs from the URL realm (`/alpha`) asserts `/beta` reaches `providerSettingsFactory`, `urisFactory`, the servlet
  attribute, and the client-lookup wrapper — plus UTF-8 round-trip + `charset=UTF-8`. A mocked request would no-op
  `setRealmOnRequest` and hide it.

**Review dispositions (5a-2b code-review, 2026-07-24):** no new correctness bug; all divergences are accepted,
documented, or deferred to the 5d-1 live oracle.

- **F1/F2 — client/config-reachable `RuntimeException` → CHF CREST 500 (Restlet gave 400 `server_error`).**
  `DeviceCodeHandler` `Integer.valueOf(max_age)` (a malformed `max_age` client value) and `IdTokenInfoHandler`
  `JwsAlgorithm.valueOf(<configured alg>)` throw non-`OAuth2Exception` runtimes the base does not map. This is the
  **deliberately-accepted 5a-1 decision** (`decisions.md:48-49`, `phase-5a-1.md:282`): every unmapped `Throwable`
  diverges 400→500. Not re-litigated here. **→ record both reachable instances in the 5d-1 smoke matrix.**
- **F3 — `/connect/register` deployment URL adds `:443`/`:80` on default-port deployments.**
  `OAuth2Utils.getDeploymentURL` always appends `getServerPort()`; the Restlet `getHostRef()` reflects the `Host`
  header literally, so it omits the port when the client does. Matches on OpenAM's usual non-default/proxied ports.
  **Decision (user, 2026-07-24): keep `getDeploymentURL` (DRY/canonical) and treat as a 5d-1 byte-diff watch-item**
  (like the tokeninfo cache header) — the live oracle is the definitive check; fix then only if it actually diverges.
- **F4 — error body echoes `state` on `/connect/register` + `/idtokeninfo`.** Those Restlet resources passed
  `null`; the shared base `onError` echoes `state` uniformly (5a-1 design — not overridable per-handler). Only
  manifests if a client sends `state`, which is out-of-flow for these endpoints. Accepted; note for the 5d-1 matrix.
- **F5 — moot.** `OpenAMClientRegistrationStore.get` never calls `request.getRequest()`, so dropping the wrapper's
  `getRequest()` override is safe; the D3 test *does* exercise the wrapper's `getParameter` override (captured + asserted).
- **F6 (dropped unexpected-error logging) / F7 (test-scaffold duplication across the 9 http test classes)** —
  valid quality notes, **deferred** to a separate focused cleanup (F6 is base-level/cross-cutting; F7 also touches the
  committed 5a-2a tests).

**Not committed yet** (verification passed; commit pending user go-ahead).
