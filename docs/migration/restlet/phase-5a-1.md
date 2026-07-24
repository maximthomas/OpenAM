# Phase 5a-1 — OAuth2 `/access_token` → CHF: Detailed Implementation Plan

Detailed execution plan for **step 5a-1** of [Phase 5](phase-5-oauth2.md) of the Restlet → CHF migration —
the OAuth2 token endpoint (`/oauth2/access_token`). Parent tracker: [plan.md](plan.md); umbrella
substrate: [phase-5-oauth2.md](phase-5-oauth2.md); decisions: [decisions.md](decisions.md); reusable CHF
patterns: [chf-patterns.md](chf-patterns.md); the pattern this step copies: [phase-4-uma.md](phase-4-uma.md)
(the `@ExceptionHandler` base + error factory shape) and [phase-2-integration-tests.md](phase-2-integration-tests.md)
(layer-2 IT). Build-ahead infra it consumes: [phase-3a-oauth2request.md](phase-3a-oauth2request.md)
(`ChfOAuth2Request`), [phase-3b-collaborators.md](phase-3b-collaborators.md) (neutral bearer/basic readers),
[phase-3c-2-error-layer.md](phase-3c-2-error-layer.md) (`OAuth2Error`/`OAuth2ErrorResponseFactory`). Test
layers: [../../test-infrastructure.md](../../test-infrastructure.md). Written 2026-07-24; branch
`features/restlet-migration`. All facts below verified against the tree on 2026-07-24 (three source-mapping
passes over the Restlet token stack, the hook seam, and the build-ahead APIs).

## Context

Step 5a-1 ports the **`/access_token` token endpoint** — the one genuinely complex handler in sub-phase 5a —
off Restlet onto CHF, as a **build-ahead commit wired to no route** (Restlet still serves `/oauth2` until the
5d-1 flip). It is scheduled first in Phase 5 because it establishes two things every later 5a/5b step reuses:

1. **`AbstractOAuth2HttpJsonEndpoint`** — the shared JSON `@ExceptionHandler` base (finding #2 in the umbrella),
   extended by all nine 5a-2 handlers.
2. **The CHF hook seam** (`ChfTokenRequestHook`, D5-2) — and, gating its design, **the cookie spike** (the one
   unproven assumption in the whole phase).

The token endpoint collapses **six** Restlet classes — `TokenEndpointFilter`, `OAuth2Filter` (base),
`AccessTokenFlowFinder`, `OAuth2FlowFinder` (base), `TokenEndpointResource`, `RefreshTokenResource`, plus
`ErrorResource` — into **one** `TokenEndpointHandler`. The grant handlers themselves (`AccessTokenService` and
the `GrantTypeHandler`s it dispatches to) are already transport-free and are **not** touched.

**Today's route** (`OAuth2RouterProvider.java:102-105`):

```java
router.attach("/access_token", auditWithOAuthFilter(new TokenEndpointFilter(new AccessTokenFlowFinder(),
        jacksonRepresentationFactory),
        formAuditor(RESPONSE_TYPE, GRANT_TYPE, CLIENT_ID, USERNAME, SCOPE, REDIRECT_URI),
        jacksonAuditor(SCOPE, TOKEN_TYPE)));
```

The audit pair (`formAuditor(RESPONSE_TYPE, GRANT_TYPE, CLIENT_ID, USERNAME, SCOPE, REDIRECT_URI)` request /
`jacksonAuditor(SCOPE, TOKEN_TYPE)` response → CHF `formAuditor(...)` / `jsonAuditor(SCOPE, TOKEN_TYPE)`) is
**5d wiring**, recorded here as forward context; 5a-1 wires no audit filter. The CHF `Entity` is buffered
([chf-patterns §7](chf-patterns.md)), so when 5d wraps audit around this handler the request body stays
re-readable — no work needed in 5a-1.

## Scope & sizing

One commit. **3 new classes + 1 new hook interface, 2 modified in place, 1 new test class** (plus the spike),
all in **openam-oauth2**:

| Kind | Item |
|---|---|
| New | `org.openidentityplatform.openam.oauth2.http.AbstractOAuth2HttpJsonEndpoint` (the shared JSON base) |
| New | `org.openidentityplatform.openam.oauth2.http.TokenEndpointHandler` |
| New | `org.openidentityplatform.openam.oauth2.http.ChfTokenRequestHook` (interface; **signature gated on the spike**) |
| Modified in place | `LoginHintHook` (openam-oauth2, `org.forgerock.openidconnect.restlet`) — implement `ChfTokenRequestHook` too |
| Modified in place | `OAuth2GuiceModule` — add the `ChfTokenRequestHook` Multibinder |
| Test | `TokenEndpointHandlerTest` (+ base coverage) + the cookie-spike assertion |

Build-ahead: nothing is routed. The guard is the unit tests + the golden/§E oracle recorded against live
Restlet ([R-5.9](phase-5-oauth2.md#risk-register-extends-planmds--phase-4s)). openam-oauth2 is the only module
touched, so no cross-module `install` ordering applies within the step; `mvn -o -pl openam-oauth2 install
-DskipTests` at the end so **5a-2** compiles against the new base.

> **Convention.** New classes: `org.openidentityplatform.openam.oauth2.http`, CDDL header, `Copyright 2026
> 3A Systems LLC.`, **no `@since`** ([decisions.md](decisions.md) new-class rule). Modified-in-place classes
> keep their package + header and gain a `Portions copyright 2026 3A Systems LLC.` line.

## ⚠ First task — the cookie spike (finding #6)

Before writing the hook seam, settle the **one unproven assumption** the whole phase's hook design rests on:
that a cookie written on the **bridged servlet response** survives `HttpFrameworkServlet` writing back the CHF
`Response`.

**Why it is unproven.** `LoginHintHook` today writes the `oidcLoginHint` cookie exclusively through the
**Restlet** response — `response.getCookieSettings().add(new CookieSetting(...))`
(`LoginHintHook.java:47,88`, `org.restlet.data.CookieSetting`), never `HttpServletResponse`. On CHF there is no
Restlet response; the neutral escape hatch is `ChfOAuth2Request.getHttpServletResponse()`
(`ChfOAuth2Request.java:195-198`, reads `HttpServletResponse` off the `AttributesContext`). CSRF's analogous
servlet-response cookie write exists but has **only ever run build-ahead, never on a live CHF route**
(umbrella §5a-1), so nothing has proven that a cookie set on that servlet response is not clobbered when
`HttpFrameworkServlet` copies the CHF `Response` back onto the same servlet response.

**The spike.**

1. **Read `HttpFrameworkServlet`** (openam-http / commons http-servlet) and trace how it writes the CHF
   `Response` back onto the `HttpServletResponse` — specifically whether it `reset()`s the servlet response,
   whether it copies CHF `Response` headers additively, and whether the servlet response is already committed
   at write-back. This alone may answer it.
2. **Prove it over the wire.** On a throwaway `@Get` route (or the token handler itself), write a cookie via
   `oauth2Request.getHttpServletResponse().addCookie(new Cookie("spikeCookie","1"))` and, driving a real
   request **through the actual `HttpFrameworkServlet`** (Cargo boot smoke, or a servlet-level test that
   instantiates the servlet — *not* the in-process `OAuth2RouterIT`, which bypasses the servlet write-back),
   assert `Set-Cookie: spikeCookie=1` reaches the response.

**The decision it gates:**

- **If the cookie survives** → `ChfTokenRequestHook.afterTokenHandling(OAuth2Request)` stands as designed
  (D5-2, neutral-only signature). `LoginHintHook`'s CHF impl reads/writes the cookie via
  `getHttpServletRequest()` / `getHttpServletResponse()`.
- **If it does NOT survive** → the hook must set `Set-Cookie` on the CHF `Response` headers directly, so its
  signature widens to `afterTokenHandling(OAuth2Request, Response)` (CHF `org.forgerock.http.protocol.Response`).
  Cheaper to learn now than to discover it in 5b-1's `AuthorizeRequestHook`, which has the same dependency.

Record the spike outcome inline in this doc's As-built before writing `ChfTokenRequestHook`. The spike is a
throwaway — delete the probe route/cookie once the answer is recorded.

## Key research findings (drove this design)

### 1. ⚠ The `OAuth2Filter` "write error then CONTINUE" bug changes what `GET /access_token` returns today

`OAuth2Filter.beforeHandle` (`OAuth2Filter.java:58-80`) catches a method/content-type validation failure,
writes the error status + entity, then **falls through to `return super.beforeHandle(...)` → `Filter.CONTINUE`**
(`:79`) — so the request proceeds to the wrapped finder/resource anyway, and the resource's output **overwrites**
the error just written. Consequence, traced through the chain:

- `GET /access_token`: `TokenEndpointFilter.validateMethod` (`:53-59`) writes **405 `method_not_allowed`**, then
  CONTINUE → `AccessTokenFlowFinder` reads `grant_type` (empty on a bare GET) → `OAuth2FlowFinder.create`
  (`:77-80`) returns `ErrorResource(InvalidRequestException("Grant type is not set"))` → **400 `invalid_request`
  overwrites the 405.** So today's wire response to `GET /access_token` is very likely **400 invalid_request**,
  *not* 405. **Do not predict this — the §E lock must record it by observation** (below).
- The CHF handler is **`@Post`-only and returns on validation failure**, so `GET /access_token` yields a clean
  framework **405** ([finding 3](#3-405-for-get-is-free--content-type-still-needs-an-explicit-check)). That is a
  **deliberate behaviour change at the 5d-1 flip** — more correct than the buggy 400, and belonging in 5d-1's
  smoke matrix. The umbrella's "**5a's `TokenEndpointHandler` must return, not continue**"
  ([phase-3c-2 "Recorded for Phase 5a"](phase-3c-2-error-layer.md)) is exactly this: the handler must not
  reproduce the fall-through.

`OAuth2Filter` also adds **`Cache-Control: no-store` + `Pragma: no-cache` unconditionally on every response**
(`:76-77`, `CacheDirective.noStore()` + `HeaderConstants.HEADER_PRAGMA`/`CACHE_NO_CACHE`). The handler
reproduces these explicitly (D5-3 provenance: `/access_token`'s cache headers come from the *filter*, not the
resource — contrast `/tokeninfo` in 5a-2).

### 2. Two grant-dispatch tables run in series — the handler must reproduce the **finder's** gate

There are two independent `grant_type` maps, and the **first** one decides the error for an unknown grant:

- **`AccessTokenFlowFinder.getEndpointClasses()`** (`AccessTokenFlowFinder.java:37-47`) maps `grant_type` → a
  Restlet resource. Known set (constant → wire string, from `OAuth2Constants.TokenEndpoint`):

  | grant_type (wire) | → resource | → CHF service call |
  |---|---|---|
  | `authorization_code` | `TokenEndpointResource` | `accessTokenService.requestAccessToken` |
  | `client_credentials` | `TokenEndpointResource` | `requestAccessToken` |
  | `password` | `TokenEndpointResource` | `requestAccessToken` |
  | `urn:ietf:params:oauth:grant-type:device_code` | `TokenEndpointResource` | `requestAccessToken` |
  | `urn:ietf:params:oauth:grant-type:jwt-bearer` | `TokenEndpointResource` | `requestAccessToken` |
  | `urn:ietf:params:oauth:grant-type:saml2-bearer` | `TokenEndpointResource` | `requestAccessToken` |
  | `refresh_token` | `RefreshTokenResource` | `accessTokenService.refreshToken` |

- **`OAuth2FlowFinder.create`** (`OAuth2FlowFinder.java:72-95`) gates before dispatch: empty `grant_type` →
  `InvalidRequestException("Grant type is not set")` (`:79`); **not in the map** →
  `UnsupportedGrantTypeException("Grant type is not supported")` (`:86`).
- **`AccessTokenService.requestAccessToken`** (`AccessTokenService.java:107-118`) has a **second** map — keyed
  by `GrantTypeHandler` Guice bindings — and throws `InvalidGrantException("Unknown Grant Type, …")` (`:115`)
  for a grant with no handler.

⇒ Because the finder runs first, an unknown grant today exits **`unsupported_grant_type` (400)**, never
`invalid_grant`. **The handler must gate on the finder's known set** and route: `refresh_token` →
`refreshToken(o2)`, a known access grant → `requestAccessToken(o2)`, else `UnsupportedGrantTypeException`. If it
routed everything to `requestAccessToken` and let the service reject, an unknown grant would wrongly become
`invalid_grant`. (The two maps should list the same grants; if they ever diverge the finder's set wins, exactly
as today.)

### 3. 405 for GET is free; content-type still needs an explicit check

Per [chf-patterns §2](chf-patterns.md), a handler with only a `@Post` method (no `@Get`) returns a framework
**405** for GET/PUT/DELETE **without checking the verb** — and since Phase 4 the framework 405 body is
405-coded CREST. So the handler needs **no method check**; `TokenEndpointFilter.validateMethod` disappears. What
it still needs is **content-type validation**: `TokenEndpointFilter.validateContentType` (`:67-75`) allows a
null/empty entity, else requires the parsed media type to be `application/x-www-form-urlencoded`, else
`InvalidRequestException("Invalid Content Type")`. Reproduce it with the charset-safe parse
([chf-patterns §7](chf-patterns.md)): `ContentTypeHeader.valueOf(request).getType()` compared to
`application/x-www-form-urlencoded` — **never** `Form.fromRequestEntity`/`getForm()` (silently empty on a
`;charset=UTF-8` body). The handler reads `grant_type` and the rest via `oauth2Request.getParameter(...)`, which
`ChfOAuth2Request` already parses correctly across query + charset-suffixed form body — so the handler parses
no form itself.

### 4. `WWW-Authenticate` rides on `OAuth2Error`, never re-derived (D14)

Today `TokenEndpointResource` (`:102-108`) and `RefreshTokenResource` (`:90-96`) catch
`InvalidClientAuthZHeaderException` and decorate the Restlet response with a `ChallengeRequest` **before**
throwing, using the single-entry `RestletConstants.SUPPORTED_RESTLET_CHALLENGE_SCHEMES` map (`RestletConstants.java:32`,
Basic only — any other scheme NPEs). On CHF there is no response to decorate before throwing. Confirmed
end-to-end that the build-ahead layer already carries the challenge:

- `InvalidClientAuthZHeaderException` (401, `invalid_client`) carries `challengeScheme`/`challengeRealm`, set to
  `"Basic"` + normalised realm **only when the request already has an Authorization header**
  (`ClientAuthenticationFailureFactory.getException:54-58`).
- `OAuth2Error.of(OAuth2Exception)` copies the challenge off it (`OAuth2Error.java:187-191`).
- `OAuth2ErrorResponseFactory.toJsonResponse` → private `withChallenge` emits
  `WWW-Authenticate: <scheme> realm="<quoted realm>"` iff `getChallengeScheme() != null`
  (`OAuth2ErrorResponseFactory.java:326-332`).

⇒ The handler routes the exception through the shared `@ExceptionHandler` (below) and **must not touch
`WWW-Authenticate`**. `RestletConstants` + its scheme map die with the resources at 5d-2. Realm quoting is
RFC-7235 (`HeaderUtil.quote` + printable-ASCII strip) — a deliberate wire divergence for a realm containing
`"`/`\`/CTL only (D14).

### 5. The success body is `AccessToken.toMap()`, not `getTokenInfo()`

`TokenEndpointResource` returns `accessTokenService.requestAccessToken(request)` → `accessToken.toMap()`
(`:88,94`); `RefreshTokenResource` the same via `.refreshToken(request)` (`:85-86`). `AccessToken.toMap()`
(`StatefulAccessToken.java:434-442`) builds `{access_token, token_type, expires_in}` (keys resolved via the
`OAuth2CoreToken.properties` bundle; `expires_in` = seconds-remaining computed at serialization) **plus**
`extraData` (where `scope`, `refresh_token`, and provider extras ride in). It is **not** `getTokenInfo()` (that
is the tokeninfo/introspection shape — 5a-2). The handler builds `new Response(Status.valueOf(200))
.setEntity(accessToken.toMap())` — `setJson`/`setEntity(Map)` supplies `application/json; charset=UTF-8`
([chf-patterns §6](chf-patterns.md)); **never** `setEntity(String)`.

### 6. The hook seam is Restlet-typed and needs a parallel CHF interface (D5-2)

`TokenRequestHook.afterTokenHandling(OAuth2Request, org.restlet.Request, org.restlet.Response)`
(`TokenRequestHook.java`) is invoked once, after a successful token, in `TokenEndpointResource.token`
(`:90-92`), iterating a Guice-multibound `Set<TokenRequestHook>` (bound in `OAuth2GuiceModule.java:230-232`;
sole impl `LoginHintHook`). The CHF handler cannot call the Restlet-typed method, and re-signing the interface
in place would break the still-live Restlet caller (`TokenEndpointResource`) until 5d. So 5a-1 introduces a
**parallel** CHF interface (D5-2); `LoginHintHook` implements both; the Restlet interface + methods are deleted
at 5d-2. (`AuthorizeRequestHook`'s parallel CHF interface is 5b-1's job — same pattern.)

## Design decisions

<a id="d1"></a>
### D1 — `AbstractOAuth2HttpJsonEndpoint`: catch `OAuth2Exception`, field-inject the collaborators

Mirror [`AbstractUmaHttpEndpoint`](../../../openam-uma/src/main/java/org/openidentityplatform/openam/uma/AbstractUmaHttpEndpoint.java)
but for the OAuth2 JSON shape. Two differences from the UMA base: it catches **`OAuth2Exception`** (not
`Throwable`), because `OAuth2Error.of` requires an `OAuth2Exception`; and it **field-injects** its collaborators
(the UMA base needs none — `UmaErrorResponseFactory` is a static utility, whereas `OAuth2ErrorResponseFactory`
is `@Inject`-constructed with a renderer):

```java
public abstract class AbstractOAuth2HttpJsonEndpoint {
    @Inject protected OAuth2RequestFactory requestFactory;
    @Inject protected OAuth2ErrorResponseFactory errorResponseFactory;

    @ExceptionHandler
    public Response onError(OAuth2Exception e, @Contextual Context ctx, @Contextual Request request) {
        OAuth2Request o = requestFactory.create(ctx, request);
        return errorResponseFactory.toJsonResponse(OAuth2Error.of(e).withState(o.getParameter("state")));
    }
}
```

- `Endpoints.from(Class)` resolves the subclass through Guice (`InjectorHolder`), so `@Inject` on the **base
  fields** is populated by member injection when the handler is constructed — the same mechanism the XACML/UMA
  handlers rely on. (Verify during the build; if member injection on the base does not fire, fall back to a
  base constructor the subclass chains — but field injection is the expectation.)
- **Subclasses must not override `onError`** — Java drops the annotation on an override
  ([chf-patterns §2](chf-patterns.md)). `AnnotatedMethod.findExceptionHandlers` scans inherited public methods,
  so the base's handler is discovered on every subclass ([phase-4 finding 2](phase-4-uma.md)).
- Dispatch is on the thrown exception **directly** (F2 hands the real cause over, no Restlet wrapping —
  [phase-4 finding 2](phase-4-uma.md)); `.getCause()` unwrapping is **not** ported.

<a id="d2"></a>
### D2 — `IllegalArgumentException` → `InvalidRequestException`, converted in the handler

Both Restlet resources catch `IllegalArgumentException` → **400 `invalid_request`**
(`TokenEndpointResource.java:98-100`, `RefreshTokenResource.java:87-89`; the refresh path raises IAE from
`AccessTokenService.refreshToken`'s `Reject.ifTrue`, `AccessTokenService.java:141`). This is a **contractual
client error, not a bug** — it must stay 400, so it cannot be left to the framework's 500. Since the base
handles only `OAuth2Exception`, the handler **converts it at the call site**:

```java
try {
    accessToken = "refresh_token".equals(grantType) ? service.refreshToken(o2) : service.requestAccessToken(o2);
} catch (IllegalArgumentException e) {
    throw new InvalidRequestException(e.getMessage());   // → base @ExceptionHandler → 400 invalid_request
}
```

The JSON error shape carries only `error`/`error_description`/`state`, so the Restlet path's extra
`redirect_uri` threading on IAE is irrelevant here (no redirect on a JSON endpoint). Every other exception the
service throws is already an `OAuth2Exception` subclass and reaches the base directly. A genuinely unexpected
non-`OAuth2Exception` `Throwable` falls to the framework's CREST **500** — kept deliberately per
[decisions.md D3](decisions.md) ("keep CHF's 500 on the bug path"); the contractual 400s are all preserved
(`ServerException` — itself an `OAuth2Exception`, 400 `server_error` — reaches the base and stays 400).

<a id="d3"></a>
### D3 — `TokenEndpointHandler`: one `@Post`, explicit content-type + grant gate, return on failure

```java
public class TokenEndpointHandler extends AbstractOAuth2HttpJsonEndpoint {
    @Inject AccessTokenService accessTokenService;
    @Inject Set<ChfTokenRequestHook> hooks;

    @Post
    public Response token(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        OAuth2Request o2 = requestFactory.create(ctx, request);           // (Context, Request) overload — one cached instance
        validateContentType(request);                                     // finding 3; throw InvalidRequestException on miss
        String grantType = o2.getParameter("grant_type");
        AccessToken token = dispatch(grantType, o2);                      // finding 2 gate + D2 IAE conversion
        for (ChfTokenRequestHook hook : hooks) { hook.afterTokenHandling(o2); }   // finding 6 / spike outcome
        Response response = new Response(Status.valueOf(200)).setEntity(token.toMap());   // finding 5
        response.getHeaders().put("Cache-Control", "no-store");           // finding 1 (D5-3)
        response.getHeaders().put("Pragma", "no-cache");
        return response;
    }
}
```

- `create(ctx, request)` is the **`(Context, Request)` overload** so the (future 5d) audit/error filters and the
  handler share one cached `ChfOAuth2Request` (`OAuth2RequestFactory.java:90-100`; [phase-4 finding 4](phase-4-uma.md)).
- `dispatch`: empty `grantType` → `InvalidRequestException("Grant type is not set")`; `refresh_token` →
  `refreshToken`; a grant in the finder's known set → `requestAccessToken`; else
  `UnsupportedGrantTypeException("Grant type is not supported")` (finding 2), all under the D2 IAE catch.
- **Returns** on every path — no CONTINUE fall-through (finding 1). Throws the `OAuth2Exception` to the base
  `@ExceptionHandler`; never re-derives `WWW-Authenticate` (finding 4, D14).
- Cache headers set via `getHeaders().put` (not `setEntity`), so `setEntity(Map)` does not clobber them.

<a id="d4"></a>
### D4 — `ChfTokenRequestHook` + `LoginHintHook` dual-impl (signature per spike)

New interface (assuming the spike confirms servlet-response cookie survival — the neutral signature):

```java
package org.openidentityplatform.openam.oauth2.http;
public interface ChfTokenRequestHook {
    void afterTokenHandling(OAuth2Request o2request);
}
```

- `LoginHintHook` (`org.forgerock.openidconnect.restlet`, modified in place, add `Portions` line) implements
  **both** `TokenRequestHook` and `ChfTokenRequestHook`. The CHF `afterTokenHandling(OAuth2Request)` reproduces
  `removeCookie` (`LoginHintHook.java:83-90`) against the servlet request/response:
  read via `o2request.getHttpServletRequest().getCookies()`, delete by writing a max-age-0
  `jakarta.servlet.http.Cookie("oidcLoginHint","")` on `o2request.getHttpServletResponse()`. Cookie name
  `OAuth2Constants.Custom.LOGIN_HINT_COOKIE` (`= "oidcLoginHint"`), HttpOnly, path `/` — parity with the Restlet
  `CookieSetting`.
- `OAuth2GuiceModule.configure` gains a third Multibinder beside the two existing ones (`:226-232`):
  `Multibinder.newSetBinder(binder(), ChfTokenRequestHook.class).addBinding().to(LoginHintHook.class);`.
- If the spike says cookies do **not** survive, the interface method becomes
  `afterTokenHandling(OAuth2Request, org.forgerock.http.protocol.Response)` and `LoginHintHook` sets `Set-Cookie`
  on the CHF `Response` headers instead; `TokenEndpointHandler` passes its `Response` in. Record the chosen
  signature in As-built.

## New / modified / tests

### New (openam-oauth2, `org.openidentityplatform.openam.oauth2.http`, new-class convention)

1. **`AbstractOAuth2HttpJsonEndpoint`** — D1.
2. **`TokenEndpointHandler`** — D3.
3. **`ChfTokenRequestHook`** — D4 (signature per spike).

### Modified in place (keep package + header, add `Portions` line)

4. **`LoginHintHook`** (openam-oauth2) — implement `ChfTokenRequestHook` (D4). Keep the Restlet impls untouched
   (still called by `TokenEndpointResource`/`AuthorizeResource` until 5d).
5. **`OAuth2GuiceModule`** — add the `ChfTokenRequestHook` Multibinder (D4).

### Tests (openam-oauth2; TestNG + Mockito)

- **`TokenEndpointHandlerTest`** — construct a real `Request` + context chain
  ([chf-patterns §5](chf-patterns.md): `RootContext → AttributesContext → RealmContext`, `RealmTestHelper`),
  stub `AccessTokenService`, `OAuth2ErrorResponseFactory` (or use the real one with a stub renderer), and a spy
  `ChfTokenRequestHook`. Assert:
  - **success** → 200, body == `accessToken.toMap()`, `Content-Type: application/json; charset=UTF-8`,
    `Cache-Control: no-store`, `Pragma: no-cache`; the hook's `afterTokenHandling` called **once** after the
    service call.
  - **grant routing** — `refresh_token` → `refreshToken` (not `requestAccessToken`); `authorization_code` /
    `client_credentials` / `password` / the three `urn:…` grants → `requestAccessToken` (finding 2).
  - **empty `grant_type`** → 400 `invalid_request` ("Grant type is not set").
  - **unknown `grant_type`** → 400 `unsupported_grant_type` (**not** `invalid_grant` — finding 2, the
    load-bearing assertion of this test).
  - **content-type** — null/empty entity OK; `application/x-www-form-urlencoded` OK;
    `application/x-www-form-urlencoded;charset=UTF-8` **OK** (the §7 charset trap — a bare string-compare would
    reject it); `application/json` → 400 `invalid_request` ("Invalid Content Type").
  - **`InvalidClientAuthZHeaderException`** (stub the service to throw it with scheme `"Basic"` + a realm) → 401,
    body `{error:"invalid_client",…}`, header `WWW-Authenticate: Basic realm="<realm>"` (finding 4). And a
    plain `InvalidClientException` (no Authorization header) → 401, **no** `WWW-Authenticate`.
  - **`IllegalArgumentException`** from the service → 400 `invalid_request` (D2).
  - **`state`** echoed into every error body when present (D1 `.withState`).
- **Base coverage** — the `@ExceptionHandler` path is exercised transitively above; a focused
  `AbstractOAuth2HttpJsonEndpoint` assertion (a trivial subclass throwing a known `OAuth2Exception`) pins that
  `onError` maps status/error/state via `toJsonResponse`. Not a separate concern if `TokenEndpointHandlerTest`
  already covers all branches.
- **`LoginHintHook`** — a CHF-path test: `afterTokenHandling(o2request)` deletes the `oidcLoginHint` cookie via
  a mocked `HttpServletResponse` (assert a max-age-0 `Cookie`), reading from a mocked `HttpServletRequest`.
  Keep the existing Restlet-path test green (dual-impl, both live until 5d-2).
- **Cookie spike** — the throwaway over-the-wire assertion from the spike section; record its result, then
  delete the probe.
- **Gate:** `grep -rn "org.restlet\|getCurrent()"` over the three **new** files → 0. `LoginHintHook` is
  **excluded** from the gate — it legitimately keeps its Restlet imports (dual-impl) until 5d-2, exactly as the
  Restlet shims do ([decisions.md](decisions.md)).

## The §E e2e contract lock (tracked as step 5-E; record here, against live Restlet)

The **§E e2e contract lock** is its own tracked step **5-E** in [plan.md](plan.md) — a gate, not a build step:
it records the live-Restlet `/oauth2` contract, lands any time in 5a–5c, and **must precede 5d-1** because
Restlet stops serving `/oauth2` at the flip (risk #20). It is **scheduled right after 5a-1** because the
`/access_token` slice below empirically settles finding #1's `GET /access_token` question. So while 5-E is
recorded as a separate commit, its token-endpoint rows belong with this step. Extend
`e2e/oauth2/oauth2-test.spec.mjs`, **writing by observation against a live container built from this tree**, not
by prediction:

- JSON error shape on `/access_token` for a bad `grant_type` and a bad client secret;
  `WWW-Authenticate: Basic realm="…"` on the bad-secret 401.
- **`GET /access_token`** — record the *actual* status/body (finding 1: likely 400 `invalid_request` via the
  CONTINUE bug, **not** 405). This row is the oracle for the deliberate 405 change at 5d-1: capture what Restlet
  does now, and flag the post-flip 405 as an allowed divergence in 5d-1's smoke diff.

This capture is gated to 5a–5c (while Restlet still *serves* `/oauth2`); it cannot be written after 5d-1.

## Integration testing

5a-1 ships **no route**, so there is no composition IT yet — the token handler first appears in a live CHF chain
in `OAuth2RouterIT` at **5d-1** (umbrella §Integration testing). What 5a-1 owns:

- **Unit** (`TokenEndpointHandlerTest`, above) — the per-grant dispatch, both error tables, content-type,
  `WWW-Authenticate`, cache headers, hook invocation. This is R-5.6's primary guard.
- **The cookie spike** — the only over-the-wire test in 5a-1, because it is the only thing that *cannot* be
  proven in-process (it exercises the servlet write-back the in-process IT bypasses).
- **The §E lock rows** above — recorded, not yet re-run (the re-run is a 5d-1 gate).

Forward context for 5d-1's `OAuth2RouterIT` (assert then, not now): `GET /access_token` → 405 with the
verb-unchecked handler (finding 3); `WWW-Authenticate` on a bad client secret; `Cache-Control: no-store` on
success; one request through the (5d) audit wrap proving the buffered body re-reads (risk #1).

## Verification criteria

1. `mvn -o -pl openam-oauth2 test` — `TokenEndpointHandlerTest` + `LoginHintHook` CHF-path test green; existing
   suite unchanged (openam-oauth2 baseline **882** surefire + 6 failsafe — [phase-3c-2 as-built](phase-3c-2-error-layer.md#as-built);
   the count only grows).
2. `grep -rn "org.restlet\|getCurrent()"` over the 3 new files → 0 (`LoginHintHook` excluded — dual-impl).
3. `mvn -o -pl openam-oauth2 install -DskipTests` — so **5a-2** compiles against `AbstractOAuth2HttpJsonEndpoint`.
4. Whole-reactor `mvn -o install -DskipTests` — **doclint is fatal** ([test-infrastructure.md](../../test-infrastructure.md));
   the new Guice binding compiles/wires without breaking the WAR assembly (the handler is bound but routed
   nowhere — dormant).
5. CI (`.github/workflows/build.yml`): JDK 11–26 × 3 OSes on the `features/**` push — free cross-version
   coverage of the entity/charset handling.

## Risks (extends [phase-5-oauth2.md](phase-5-oauth2.md)'s register)

- **R-5a1.1 — the cookie spike is the gating unknown (R-5.8).** If the servlet-response cookie does not survive
  the CHF write-back and 5a-1 ships the neutral hook signature anyway, `login_hint` cookie behaviour silently
  vanishes at 5d-1 and stays invisible until an e2e `login_hint` round-trip. **Guard:** the spike runs
  **first** and its outcome picks the signature (D4); a `LoginHintHook` CHF-path unit test; the 5d-1 e2e
  `login_hint` round-trip.
- **R-5a1.2 — the two-map gate (R-5.6).** Routing all grants to `requestAccessToken` instead of reproducing the
  finder's known-set gate flips an unknown grant from `unsupported_grant_type` to `invalid_grant`. **Guard:**
  `TokenEndpointHandlerTest` asserts unknown → `unsupported_grant_type` explicitly (finding 2).
- **R-5a1.3 — the CONTINUE-bug behaviour change (finding 1).** `GET /access_token` changes from today's
  (buggy) 400 to a clean 405 at the flip. If the §E lock predicts 405 instead of recording the real 400, the
  5d-1 diff hides the change. **Guard:** record the row by observation now; list the 405 as an allowed
  divergence in 5d-1's smoke diff.
- **R-5a1.4 — base field injection.** If `Endpoints.from`'s Guice construction does not member-inject the
  abstract base's `@Inject` fields, `onError` NPEs on `errorResponseFactory`. **Guard:** the unit test
  constructs the handler through the injector (or a base-constructor fallback, D1); `mvn install` + the 5d-1
  `OAuth2RouterIT` exercise the real Guice path.
- **R-5a1.5 — build-ahead, no live guard (risk #19).** The handler is dormant until 5d-1. **Guard:** the unit
  tests + the §E lock recorded against live Restlet; the golden/error-parity tests (3c) already cover the
  render/error contract. Retired when 5d-1 wires the route and `OAuth2RouterIT` exercises it.
- **R-5a1.6 — `setEntity` charset trap (risk #21).** The token map is ASCII, so an ASCII fixture would not
  catch an ISO-8859-1 regression. **Guard:** build the body with `setEntity(Map)` (routes to `setJson`,
  UTF-8 for free — [chf-patterns §6](chf-patterns.md)); never `setEntity(String)`. Assert
  `Content-Type: application/json; charset=UTF-8`.

## Execution order

0. **The cookie spike** — read `HttpFrameworkServlet` + prove servlet-response cookie survival over the wire;
   record the outcome and the chosen `ChfTokenRequestHook` signature (D4) in As-built. Delete the probe.
1. **`AbstractOAuth2HttpJsonEndpoint`** (D1).
2. **`ChfTokenRequestHook`** (D4, signature per step 0) + **`LoginHintHook`** dual-impl + **`OAuth2GuiceModule`**
   Multibinder.
3. **`TokenEndpointHandler`** (D3) — content-type gate, two-map dispatch (finding 2), D2 IAE conversion, cache
   headers, hook loop.
4. **`TokenEndpointHandlerTest`** + `LoginHintHook` CHF-path test → `mvn -o -pl openam-oauth2 test`.
5. **§E lock** — extend `e2e/oauth2/oauth2-test.spec.mjs` with the `/access_token` rows against live Restlet
   (record `GET /access_token`'s real response, finding 1).
6. Gate (0 Restlet imports in new files) → `mvn -o -pl openam-oauth2 install -DskipTests` → whole-reactor
   `mvn -o install -DskipTests` → mark 5a-1 done in [plan.md](plan.md) and proceed to **5a-2**.
