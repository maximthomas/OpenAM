# Phase 3a — `OAuth2Request` abstraction + consumer re-plumb: Detailed Plan

Detailed execution plan for **sub-phase 3a** of the Restlet → CHF migration. Parent
tracker: [plan.md](plan.md) (Phase 3); research & sizing:
[phase-3-research.md](phase-3-research.md); reusable CHF patterns:
[chf-patterns.md](chf-patterns.md); inventory: [inventory.md](inventory.md).
Written 2026-07-09; branch `features/restlet-migration`.

## Context

Phase 3 makes the OAuth2 core transport-neutral so UMA (Phase 4) and OAuth2/OIDC (Phase 5)
can migrate incrementally. It is split into four shippable commits (3a–3d, see
[phase-3-research.md](phase-3-research.md) §4). **3a is the keystone**: it introduces the
transport-neutral `OAuth2Request` API that 3b–3d and Phases 4–5 all build on.

**No route flips.** After 3a, `/oauth2`+`/uma` still run on Restlet exactly as today; the
only observable change is internal — the shared OAuth2 collaborators stop grubbing the
Restlet `Request` and go through neutral accessors that *both* transports implement.
`ChfOAuth2Request` is built and unit-tested here but wired to no live route until Phase 4/5.

**Outcome:** `OAuth2Request` is abstract with two subclasses (`RestletOAuth2Request` =
today's behavior verbatim; `ChfOAuth2Request` = CHF `Context`+`Request`); the 13 shared
collaborators use neutral accessors; the whole existing Restlet test suite stays green;
`ChfOAuth2RequestTest` proves precedence/body/locale/endpoint-type parity ahead of any flip.

## Scope & sizing

Single shippable green commit. **2 new classes, ~16 modified, 0 deleted**, plus 1 new test
and touch-ups to `OAuth2RequestFactoryTest`. This is the largest 3-x commit and the highest
risk because it edits code the **live Restlet path** executes — the guardrail is that every
edit must keep the existing Restlet-path unit tests passing unchanged.

## Key design decisions

- **Abstract base holds only shared state; transport specifics are abstract.** The base
  keeps the token map, `sessionId`, `clientRegistration`, and their accessors (all
  transport-free today). Everything that reads the wire becomes abstract:
  `getParameter`, `getParameterCount`, `getParameterNames`, `getBody`, `getLocale`,
  `getEndpointType`, plus the new accessors below. `RealmOnlyOAuth2Request`
  (`OAuth2Request.forRealm`) already overrides these by throwing — it becomes a third,
  unchanged subclass.
- **`getRequest()` stays on the base as a deprecated default that throws**, overridden only
  by `RestletOAuth2Request`. Rationale: ~10 **Restlet-package** endpoint classes
  (`AuthorizeResource`, `UserInfo`, `ResourceSetRegistrationEndpoint`, …) still call
  `request.getRequest()` and are only deleted in Phase 5. Leaving a throwing default avoids
  ~10 pointless casts in code that is about to be removed; `ChfOAuth2Request` inherits the
  throwing default (it is never on a Restlet-only endpoint path). This one Restlet import on
  the base is transitional debt, deleted with `RestletOAuth2Request` in Phase 5d. **Only the
  13 *shared* collaborators (reached by both transports) are migrated off `getRequest()` in
  3a** — see the split rationale in [phase-3-research.md](phase-3-research.md) §2a.
- **Servlet request/response come from `AttributesContext`** on the CHF side (verified:
  `HttpFrameworkServlet` puts them under `HttpServletRequest.class.getName()` /
  `HttpServletResponse.class.getName()` — [phase-3-research.md](phase-3-research.md) §1). No
  new `SecurityContext`/thread-local plumbing on the CHF side.
- **Exact parameter precedence preserved** (Restlet order, reproduced by `ChfOAuth2Request`):
  (1) internal attribute map → (2) query (`Form.fromRequestQuery`) → (3) POST form body →
  (4) POST JSON body. `getParameterCount` counts **query-string duplicates only**
  (`DuplicateRequestParameterValidator` contract). Form/JSON parsed once from the buffered
  CHF entity and instance-cached (CHF buffers the entity, so no Restlet-style
  `setEntity(form.getWebRepresentation())` re-read hack is needed).
- **Per-request cache moves to `AttributesContext`** under the same `OAUTH2_REQ_ATTR` key.
  **Open item to settle in implementation:** the plan's note about *also* mirroring the
  cache to the servlet attribute "so mixed stacks agree" is likely unnecessary — web.xml
  maps each path to exactly one servlet, so no path is served by both transports at once
  (risk R-3.5). Default: **do not mirror**; keep the Restlet factory path caching on the
  servlet attribute as today and the CHF path caching on `AttributesContext`. Revisit only
  if an integration test shows a shared-path case.

## The neutral `OAuth2Request` API (post-3a)

| Member | Kept / New | Restlet impl | CHF impl |
|---|---|---|---|
| `getParameter(name)` | abstract | attr → query → form → json (verbatim) | same precedence over `Context`+`Request` |
| `getParameterCount(name)` | abstract | `resourceRef.getQueryAsForm().subList` | `Form.fromRequestQuery` duplicates |
| `getParameterNames()` | abstract | method/media-type branch (verbatim) | same over CHF entity |
| `getBody()` | abstract | `JacksonRepresentationFactory` | `request.getEntity().getJson()` (cached) |
| `getLocale()` | abstract | `ServletUtils.getRequest(req).getLocale()` | `Accept-Language` preferred locale |
| `getEndpointType()` | abstract | `REALM_URL` attr → path-after-realm | post-realm-routing remaining URI |
| **`getHttpServletRequest()`** | **new abstract** | `ServletUtils.getRequest(request)` | `AttributesContext` key |
| **`getHttpServletResponse()`** | **new abstract** | `ServletUtils.getResponse(Response.getCurrent())` | `AttributesContext` key |
| **`getBasicAuthCredentials()`** | **new abstract** | `ChallengeResponse` id/secret | `Authorization: Basic` parsed ISO-8859-1 |
| **`getAuthorizationBearerToken()`** | **new abstract** | `ChallengeResponse`/header | `Authorization: Bearer` parse |
| **`getAcceptedLanguages()`** | **new abstract** | servlet request locales | `Accept-Language` q-ordered list |
| **`getAttribute(name)` / `setAttribute(name,val)`** | **new abstract** | Restlet request attributes | CHF-side attribute map |
| **`getRequestUrl()`** | **new abstract** | `resourceRef.toString()` | reconstruct from CHF `Request.getUri()` |
| `getRequest()` | kept, **deprecated default throws** | returns Restlet `Request` | inherits throwing default |
| tokens / session / clientRegistration | kept concrete on base | shared | shared |

`getBasicAuthCredentials()` returns a small immutable holder
(`oauth2.core.BasicAuthHeader{ String clientId; char[] secret }`, new) or `null` —
**decoded ISO-8859-1** to match Restlet (risk #5). This replaces the `ChallengeResponse`
grubbing in `ClientCredentialsReader` (3b) and `ClientAuthenticator`.

## Work items

### New — openam-oauth2 (`org.forgerock.oauth2.core`)

1. **`RestletOAuth2Request`** — subclass carrying **today's `OAuth2Request` body verbatim**
   (the current `getParameter`/`getBody`/`getEndpointType`/`getLocale` impls move here
   unchanged; `getRequest()` returns the wrapped Restlet `Request`). New accessors implement
   over the Restlet request: `getHttpServletRequest` = `ServletUtils.getRequest(request)`,
   `getHttpServletResponse` = `ServletUtils.getResponse(Response.getCurrent())`,
   `getBasicAuthCredentials` from `ChallengeResponse`, `getAcceptedLanguages` from the
   servlet request, `getAttribute/setAttribute` over `request.getAttributes()`,
   `getRequestUrl` = `resourceRef.toString()`.
2. **`ChfOAuth2Request`** — wraps `org.forgerock.services.context.Context` +
   `org.forgerock.http.protocol.Request`. Attribute map seeded from
   `RealmContext.getRealm().asPath()` + accumulated
   `UriRouterContext.getUriTemplateVariables()` (covers `realm`, `rsid`), writable via
   `setAttribute`. Parameter precedence + `getBody` + `getParameterCount` +
   `getParameterNames` per the precedence rules above. `getEndpointType` from the
   post-realm-routing remaining URI → `EndpointType.get(path)`
   (`org.forgerock.openam.oauth2.OAuth2Constants.EndpointType`). Servlet req/resp from
   `AttributesContext`. `getLocale`/`getAcceptedLanguages` from `Accept-Language`.
3. **`BasicAuthHeader`** (small value type) — `clientId` + `char[] secret`; ISO-8859-1
   Base64 decode of `Authorization: Basic`.

### Modified — `OAuth2Request` → abstract

- Strip the concrete wire-reading body out to `RestletOAuth2Request`; leave the abstract
  declarations + shared token/session/clientRegistration state + `forRealm` +
  deprecated throwing `getRequest()` default. `RealmOnlyOAuth2Request` continues to extend
  it (add throwing overrides for the new abstract accessors, mirroring its existing ones).

### Modified — `OAuth2RequestFactory`

- Keep `create(Request)` (returns `RestletOAuth2Request`; **still used by ~13 Restlet-package
  callers** until Phase 5 — see [phase-3-research.md](phase-3-research.md) call-site list).
- Add `create(Context, Request)` (returns `ChfOAuth2Request`); cache under `OAUTH2_REQ_ATTR`
  on `AttributesContext`; pre-resolve client registration via the neutral `getParameter`
  (works for both transports). Factor `addClientRegistrationToOAuth2Request` to take the
  `OAuth2Request` (neutral) rather than `HttpServletRequest`.

### Modified — the 13 shared collaborators (off `getRequest()` → neutral accessors)

Each edit must leave the Restlet path behaving identically (RestletOAuth2Request implements
the neutral accessor with today's exact call).

| File | Replacement |
|---|---|
| `ResourceOwnerSessionValidator` | `getHttpServletRequest()` (SSO token, auth URL); `getRequestUrl()` for `gotoUrl` (was `resourceRef.toString()`); **`alterMaxAge` → `setAttribute(MAX_AGE, CONFIRMED_MAX_AGE)`** (attribute tier out-ranks query, same effect, no query mutation); **`setCurrentAcr` → `setAttribute(ACR, matchedAcr)`**; `removeLoginPrompt` retargeted at the servlet request |
| `ResourceOwnerAuthenticator` | `getHttpServletRequest()` + `getHttpServletResponse()` for `lc.login(req,resp)` (drop `Request/Response.getCurrent()`) |
| `ClientAuthenticator` | `getHttpServletRequest()`/`getHttpServletResponse()` (drop `Request/Response.getCurrent()`); `setAttribute(AM_CTX_ID, …)` |
| `CsrfProtection` | `getHttpServletRequest()` + `getHttpServletResponse()` |
| `TokenInfoService` | `setAttribute(OAuth2Constants.Custom.REALM, realm)` |
| `StatefulTokenStore` | `getHttpServletRequest()` (cookie/SSO); `getAttribute(ACR)` |
| `OpenAMScopeValidator` | `getHttpServletRequest()`; `getAttribute(...)` |
| `OAuth2UrisFactory` | `getHttpServletRequest()` for base URL |
| `ClientCredentialsReader` | (bulk in **3b**) but the `getRequest()`/`ChallengeResponse`/`getResourceRef().getLastSegment()` reads become `getBasicAuthCredentials()` + `getEndpointType()==TOKEN_ENDPOINT` |
| `IdTokenResponseTypeHandler` | neutral request access |
| `uma.UmaTokenIntrospectionHandler` | neutral request access |
| `uma.UmaUrisFactory` | `getHttpServletRequest()` for base URL |
| `uma.AuthorizationRequestEndpoint` | Restlet endpoint — but move its shared reads to neutral accessors so the factory swap is clean |

### The `Request.getCurrent()` thread-local leak (research §2c — must be resolved here)

`OAuthProblemException.OAuthError.SERVER_ERROR.handle(Request.getCurrent(), …)` in
`OpenAMClientRegistration` (5×), `openam.oauth2.Utils`, `openidconnect.OpenIdConnectToken`
has **no CHF equivalent** and returns null on the CHF path. **3a decision:** thread the
neutral `OAuth2Request` (or its `getHttpServletRequest()`) to these call sites and drop the
`Request.getCurrent()` argument, OR — where the exception is purely for message construction
and the Restlet request is only used for locale — pass `null`/the servlet request explicitly.
Enumerate the 7 call sites, convert them, and add a `grep` gate
(`grep -rn "getCurrent()" openam-oauth2/src/main | grep -v /restlet/` → 0). Restlet-package
callers of `getCurrent()` are untouched (deleted in Phase 5).

## Tests

- **`ChfOAuth2RequestTest`** (new) — the parity workhorse:
  - precedence matrix: attribute > query > form > json; attribute-tier wins over query
    (proves the `alterMaxAge`/`setCurrentAcr` rewrite).
  - body re-read stability: `getBody()` twice + `getParameter` from form + a simulated audit
    read all see the same body (CHF buffered entity).
  - `getParameterCount` = query duplicates only (duplicate `redirect_uri`).
  - `getParameterNames` per method/media-type (GET query, POST form, POST JSON).
  - `getLocale`/`getAcceptedLanguages` from `Accept-Language` (q-values, multi-range).
  - `getEndpointType` incl. realm-prefixed URIs (`/oauth2/realms/root/access_token` →
    `TOKEN_ENDPOINT`).
  - `getBasicAuthCredentials` ISO-8859-1 (high-bit char in secret); `getAuthorizationBearerToken`.
  - servlet req/resp read from `AttributesContext`.
  Scaffolding per [chf-patterns.md](chf-patterns.md) §5 (`RootContext → AttributesContext →
  RealmContext → UriRouterContext`, `RealmTestHelper`, real `new Request()`).
- **`OAuth2RequestFactoryTest`** — extend for `create(Context, Request)` (returns
  `ChfOAuth2Request`, caches on `AttributesContext`, resolves client registration); keep the
  existing `create(Request)` assertions green.
- **Existing Restlet-path tests stay green unchanged** — the acceptance gate for "behavior
  preserved" (`RestletOAuth2Request` is today's code verbatim; collaborators' neutral
  accessors resolve to the same Restlet calls). No test should need editing beyond
  compilation-driven type touch-ups.

## Verification

1. `mvn -pl openam-oauth2,openam-uma test` (no `-am`; heavy server modules stay out — see
   [feedback: no -am builds]).
2. `mvn install -DskipTests` (whole reactor; confirms no dangling refs / signature breaks).
3. `grep -rn "getCurrent()" openam-oauth2/src/main --include=*.java | grep -v /restlet/` → 0.
4. No route flip, so **no Cargo IT behavior change expected** — but run the OAuth2/UMA smoke
   matrix (client_credentials, authorization_code, refresh, userinfo, introspect,
   permission_request) to confirm the live Restlet path is byte-for-byte unchanged. Record
   pre/post curl for the token + authorize + introspect endpoints; they must match.
5. CI (`.github/workflows/build.yml`) — JDK 11–26 × 3 OSes on the `features/**` push.

## Parity checklist (subset of [plan.md](plan.md) risk register)

| Item | Guard |
|---|---|
| Parameter precedence exact (R-3.1, risk #10) | `ChfOAuth2RequestTest` matrix; `RestletOAuth2Request` verbatim |
| Body re-readability (R-3.2, risk #1) | re-read test; CHF buffered entity |
| `getCurrent()` thread-local leak (R-3.3) | 7 call sites converted + grep gate |
| Basic-auth ISO-8859-1 (risk #5) | `getBasicAuthCredentials` charset + high-bit test |
| Locale parity (risk #15) | `getLocale`/`getAcceptedLanguages` Accept-Language tests |
| Endpoint-type incl. realm-prefixed (risk #12) | `getEndpointType` tests |
| Cache location (R-3.5) | no servlet-attr mirroring unless IT shows a shared path |
| Live Restlet path unchanged | existing suite green + pre/post curl diff |

## Execution order

`OAuth2Request` → abstract + `RestletOAuth2Request` (verbatim move) → new accessors on base
(abstract) + `RealmOnlyOAuth2Request` overrides → `BasicAuthHeader` → `ChfOAuth2Request`
(+`ChfOAuth2RequestTest`) → `OAuth2RequestFactory.create(Context,Request)`
(+factory test) → migrate the 13 collaborators → convert the 7 `getCurrent()` sites →
`mvn -pl openam-oauth2,openam-uma test` → whole build → grep gates → smoke/curl diff →
mark 3a done in [plan.md](plan.md) and start [phase-3b] from
[phase-3-research.md](phase-3-research.md).
