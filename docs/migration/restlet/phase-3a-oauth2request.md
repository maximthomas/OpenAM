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

**Outcome:** `OAuth2Request` is abstract with two new transport subclasses
(`RestletOAuth2Request` = today's behavior verbatim; `ChfOAuth2Request` = CHF
`Context`+`Request`) alongside the two subclasses that already exist; the shared
collaborators use neutral accessors; the whole existing Restlet test suite stays green;
`ChfOAuth2RequestTest` proves precedence/body/locale/endpoint-type parity ahead of any flip.

## Scope & sizing

Single shippable green commit. **3 new classes** (`RestletOAuth2Request`,
`ChfOAuth2Request`, `BasicAuthHeader`), **~18 modified, 0 deleted**, plus 1 new test and
touch-ups to `OAuth2RequestFactoryTest`. This is the largest 3-x commit and the highest
risk because it edits code the **live Restlet path** executes — the guardrail is that every
edit must keep the existing Restlet-path unit tests passing unchanged.

## Key design decisions

- **Abstract base holds only shared state; transport specifics are abstract.** The base
  keeps the token map, `sessionId`, `clientRegistration`, and their accessors (all
  transport-free today). Everything that reads the wire becomes abstract:
  `getParameter`, `getParameterCount`, `getParameterNames`, `getBody`, `getLocale`,
  `getEndpointType`, plus the new accessors below.
- **There are four subclasses after 3a, not three.** Besides the two new transport
  subclasses:
  - `RealmOnlyOAuth2Request` (`OAuth2Request.forRealm`, nested in `OAuth2Request`) throws
    from most wire accessors — but it does **not** override `getEndpointType()` today, so
    promoting that to abstract is a compile break. It needs a throwing override for
    `getEndpointType()` plus every new accessor.
  - `IdTokenInfo.ValidateIdTokenRequest` (`openam-oauth2`,
    `org.forgerock.openidconnect.restlet`) is a **delegating wrapper** that extends
    `OAuth2Request` via `super(null, null)` and forwards `getRequest`/`getParameter`/
    `getParameterCount`/`getParameterNames`/`getBody`/`getLocale` to a delegate. It must
    **delegate** every new abstract accessor, *not* throw — `/oauth2/idtokeninfo` runs
    through it. It also needs a no-arg (or delegate-only) super constructor once the
    `(JacksonRepresentationFactory, Request)` constructor moves down to
    `RestletOAuth2Request`.
- **`RestletOAuth2Request` must be `public`.** `openam-uma` constructs it directly (see
  work items), so openam-uma keeps its Restlet compile dependency until Phase 4.
- **The `@Inject`/`@Assisted` annotations on today's `OAuth2Request` constructor are
  vestigial** — no `FactoryModuleBuilder` binding for it exists anywhere in the repo. Drop
  them rather than carrying an `@Inject` constructor onto an abstract class.
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
  CHF entity and instance-cached (CHF buffers the entity — `Entity` caches both its `json`
  and `string` fields — so no Restlet-style `setEntity(form.getWebRepresentation())` re-read
  hack is needed).
- **Two CHF form-parsing traps (verified against http-framework 3.1.1 bytecode):**
  1. **Do not use `Request.getForm()`.** It is `fromRequestQuery(this)` *then*
     `fromRequestEntity(this)` into one `Form` — it merges query and body and collapses
     precedence tiers 2 and 3.
  2. **Do not use `Form.fromRequestEntity(request)` as-is.** It guards on
     `ContentTypeHeader.getFirst(...).equalsIgnoreCase("application/x-www-form-urlencoded")`
     — an exact compare against the **whole header value**. A client sending
     `Content-Type: application/x-www-form-urlencoded;charset=UTF-8` (common in OAuth2
     client libraries) gets an **empty form, silently**. Restlet compares the *parsed*
     `MediaType` and ignores parameters, so it matches.

  Correct recipe for both the form and JSON tiers: parse the media type with
  `ContentTypeHeader.valueOf(request).getType()`, compare that against
  `application/x-www-form-urlencoded` / `application/json`, and only then call
  `new Form().fromFormString(entity.getString())` / `entity.getJson()`. `Entity` has no
  `getForm()` method.
- **The request URL is mutable state, not just a read accessor.**
  `ResourceOwnerSessionValidator.alterMaxAge` and `removeLoginPrompt` rewrite the *query
  string of the request URL*, and `authenticationRequired` then reads that mutated URL back
  as the `goto` parameter of the login redirect. Their whole purpose is to change what the
  **browser sends on the way back**. So the neutral API needs `setQueryParameter(name,
  value)` and `removeQueryParameterValue(name, value)` in addition to `getRequestUrl()`.
  Restlet implements them with today's `resourceRef.setQuery(...)` verbatim; CHF implements
  them over `Request.getUri()` (`MutableUri.setQuery`/`setRawQuery` both exist). See the
  regression note under the collaborator table.
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
| `getBody()` | abstract | `JacksonRepresentationFactory` | `entity.getJson()` (cached); empty `JsonValue` on `IOException`, matching Restlet |
| `getLocale()` | abstract | `ServletUtils.getRequest(req).getLocale()` | preferred `Accept-Language`, **falling back to `Locale.getDefault()` when the header is absent** (servlet-spec semantics — see risk #15 note) |
| `getEndpointType()` | abstract | `REALM_URL` attr → path-after-realm | realm-matched URI stripped from `Request.getUri()`, **leading slash preserved** |
| **`getHttpServletRequest()`** | **new abstract** | `ServletUtils.getRequest(request)` | `AttributesContext` key |
| **`getHttpServletResponse()`** | **new abstract** | `ServletUtils.getResponse(Response.getCurrent())` | `AttributesContext` key |
| **`getBasicAuthCredentials()`** | **new abstract** | `ChallengeResponse` id/secret | `Authorization: Basic` parsed ISO-8859-1 |
| **`getAuthorizationBearerToken()`** | **new abstract** | `ChallengeResponse`/header | `Authorization: Bearer` parse |
| **`getAcceptedLanguages()`** | **new abstract** | servlet request locales | `Accept-Language` q-ordered list |
| **`getAttribute(name)` / `setAttribute(name,val)`** | **new abstract** | Restlet **request** attributes (`request.getAttributes()`) | CHF-side attribute map |
| **`getRequestUrl()`** | **new abstract** | `resourceRef.toString()` | reconstruct from CHF `Request.getUri()` |
| **`setQueryParameter(name,val)`** | **new abstract** | `resourceRef.setQuery(...)` (verbatim `alterMaxAge` body) | `MutableUri.setQuery(...)` |
| **`removeQueryParameterValue(name,val)`** | **new abstract** | `resourceRef.setQuery(...)` (verbatim `removeLoginPrompt` body) | `MutableUri.setQuery(...)` |
| `getRequest()` | kept, **deprecated default throws** | returns Restlet `Request` | inherits throwing default |
| tokens / session / clientRegistration | kept concrete on base | shared | shared |

**`getAttribute`/`setAttribute` map to the Restlet request attribute map only.** They are
*not* a servlet-attribute accessor: `ClientAuthenticator` writes `NO_SESSION_REQUEST_ATTR`
on the **servlet** request (`ClientAuthenticator:155`) and `AM_CTX_ID` on the **Restlet**
request (`:183`). The first becomes `getHttpServletRequest().setAttribute(...)`; only the
second becomes `setAttribute(...)`. (Note: `AM_CTX_ID` has **no reader** anywhere in the
repo off request attributes — confirm before spending an accessor preserving it.)

**`getEndpointType()` on CHF — get this exactly right.** `EndpointType.get(path)`
(`openam-core`, `org.forgerock.openam.oauth2.OAuth2Constants`) matches paths **with a
leading slash** (`/access_token`, `/authorize`) and returns **`null`**, not an exception,
when nothing matches. Two traps: `UriRouterContext.getRemainingUri()` yields a path with
**no** leading slash, and by the time a handler constructs the `OAuth2Request` the innermost
`UriRouterContext` has already consumed the endpoint segment (remaining URI is empty). So
`ChfOAuth2Request` must derive the path by stripping the **realm router's** matched URI from
`Request.getUri()` — mirroring what the Restlet impl does with `REALM_URL` — and prepend the
slash. Get it wrong and `ClientCredentialsReader`'s `EndpointType == TOKEN_ENDPOINT` check
silently evaluates false, skipping the token-endpoint client-authentication rules.
`ChfOAuth2RequestTest` must assert non-null, not just equality.

`getBasicAuthCredentials()` returns a small immutable holder
(`oauth2.core.BasicAuthHeader{ String clientId; char[] secret }`, new) or `null` —
**decoded ISO-8859-1** to match Restlet (risk #5). This replaces the `ChallengeResponse`
grubbing in `ClientCredentialsReader` (3b) and `ClientAuthenticator`.

## Work items

### New — openam-oauth2 (`org.forgerock.oauth2.core`)

1. **`RestletOAuth2Request`** (must be `public`) — subclass carrying **today's `OAuth2Request`
   body verbatim** (the current `getParameter`/`getBody`/`getEndpointType`/`getLocale` impls
   move here unchanged, along with the `JacksonRepresentationFactory` field and the
   `(JacksonRepresentationFactory, Request)` constructor; `getRequest()` returns the wrapped
   Restlet `Request`). New accessors implement over the Restlet request:
   `getHttpServletRequest` = `ServletUtils.getRequest(request)`,
   `getHttpServletResponse` = `ServletUtils.getResponse(Response.getCurrent())`,
   `getBasicAuthCredentials` from `ChallengeResponse`, `getAcceptedLanguages` from the
   servlet request, `getAttribute/setAttribute` over `request.getAttributes()`,
   `getRequestUrl` = `resourceRef.toString()`, `setQueryParameter`/
   `removeQueryParameterValue` = today's `resourceRef.getQueryAsForm()` +
   `resourceRef.setQuery(...)` bodies lifted from `ResourceOwnerSessionValidator`.
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
  deprecated throwing `getRequest()` default. Drop the vestigial `@Inject`/`@Assisted`.
- `RealmOnlyOAuth2Request` continues to extend it: add throwing overrides for the new
  abstract accessors **and for `getEndpointType()`**, which it does not override today.

### Modified — the two existing out-of-factory constructors (compile breaks)

Making `OAuth2Request` abstract breaks **openam-uma**, which calls the constructor directly
outside `OAuth2RequestFactory`. Both become `new RestletOAuth2Request(...)`:

- `UmaUrisFactory:79` — `get(Request req)` overload.
- `UmaProviderSettingsFactory:75` — `get(Request req)` overload. **Absent from the
  collaborator table below**; it is reached from `UmaTokenIntrospectionHandler`,
  `PermissionRequestEndpoint`, `UmaWellKnownConfigurationEndpoint` and
  `AuthorizationRequestEndpoint`.

### Modified — `IdTokenInfo.ValidateIdTokenRequest` (compile break)

Delegating subclass in `org.forgerock.openidconnect.restlet`. Forward every new abstract
accessor to its `delegate` field. Do **not** give it throwing overrides — `/oauth2/idtokeninfo`
executes it.

### Modified — `OAuth2RequestFactory`

- Keep `create(Request)` (returns `RestletOAuth2Request`; **still used by the Restlet-package
  callers** until Phase 5 — see [phase-3-research.md](phase-3-research.md) call-site list).
  **Leave its client-registration resolution byte-for-byte as it is**: today it reads
  `httpRequest.getParameter(CLIENT_ID)` — *servlet* semantics, i.e. query + form body,
  container-parsed. Swapping it to the neutral `getParameter` would add an **attribute tier**
  and a **JSON-body tier**, so a JSON `POST` carrying `client_id` would newly pre-resolve a
  `ClientRegistration`. That is a live-Restlet-path behavior change inside a phase whose
  contract is "no observable change."
- Add `create(Context, Request)` (returns `ChfOAuth2Request`); cache under `OAUTH2_REQ_ATTR`
  on `AttributesContext`. Only **this** overload resolves the client registration via the
  neutral `getParameter`. Add a `addClientRegistrationToOAuth2Request(OAuth2Request)` overload
  rather than re-signing the existing `HttpServletRequest` one. Put the request into the
  cache **before** resolving the registration, so a re-entrant
  `ClientRegistrationStore` → `ProviderSettings` → `create(...)` path cannot loop.

### Modified — the shared collaborators (off `getRequest()` → neutral accessors)

Each edit must leave the Restlet path behaving identically (RestletOAuth2Request implements
the neutral accessor with today's exact call).

| File | Replacement |
|---|---|
| `ResourceOwnerSessionValidator` | `getHttpServletRequest()` (SSO token, auth URL); `getRequestUrl()` for `gotoUrl`; **`alterMaxAge` → `setQueryParameter(MAX_AGE, CONFIRMED_MAX_AGE)`**; **`removeLoginPrompt` → `removeQueryParameterValue(PROMPT, "login")`**; **`setCurrentAcr` → `setAttribute(ACR, matchedAcr)`** |
| `ResourceOwnerAuthenticator` | `getHttpServletRequest()` + `getHttpServletResponse()` for `lc.login(req,resp)` (drop `Request/Response.getCurrent()`) |
| `ClientAuthenticator` | `getHttpServletRequest()`/`getHttpServletResponse()` (drop `Request/Response.getCurrent()`); `NO_SESSION_REQUEST_ATTR` stays on the **servlet** request; `setAttribute(AM_CTX_ID, …)` on the neutral map |
| `CsrfProtection` | `getHttpServletRequest()` + `getHttpServletResponse()` |
| `TokenInfoService` | `setAttribute(OAuth2Constants.Custom.REALM, realm)` |
| `StatefulTokenStore` | `getHttpServletRequest()` (cookie/SSO); `getAttribute(ACR)` |
| `OpenAMScopeValidator` | `getHttpServletRequest()`; `getAttribute(...)` |
| `OAuth2UrisFactory` | `getHttpServletRequest()` for base URL |
| `ClientCredentialsReader` | (bulk in **3b**) but the `getRequest()`/`ChallengeResponse`/`getResourceRef().getLastSegment()` reads become `getBasicAuthCredentials()` + `getEndpointType()==TOKEN_ENDPOINT` |
| `IdTokenResponseTypeHandler` | neutral request access |
| `uma.UmaTokenIntrospectionHandler` | neutral request access |
| `uma.UmaUrisFactory` | `getHttpServletRequest()` for base URL |

**Not a collaborator:** `uma.AuthorizationRequestEndpoint:123`'s `this.getRequest()` is
Restlet `ServerResource.getRequest()`, not `OAuth2Request.getRequest()`. It needs no accessor
change in 3a; it is ported wholesale in Phase 4.

#### Why `alterMaxAge`/`removeLoginPrompt` must mutate the URL, not an attribute

Both methods rewrite the **query string of the request URL**
(`ResourceOwnerSessionValidator:263-276` and `:499-507`, each ending in
`resourceRef.setQuery(...)`). `authenticationRequired` then reads that mutated URL straight
back as the login redirect's `goto` parameter (`:359-361`). Their purpose is to change what
the **browser sends on the way back from authN** — `alterMaxAge`'s own comment says
"otherwise we'll loop forever and ever."

A request attribute lives in one JVM request and never reaches the browser. Rewriting
`alterMaxAge` as `setAttribute(MAX_AGE, …)` leaves the original `max_age` in the goto URL,
`isPastMaxAge` fires again on return, and `/authorize` ↔ login loops indefinitely — and it
regresses the **live Restlet path** in 3a, because `RestletOAuth2Request.setAttribute` writes
`request.getAttributes()`, not the resource ref. Likewise `removeLoginPrompt` cannot be
"retargeted at the servlet request": `HttpServletRequest`'s query string is immutable, and
the goto URL is built from the request URL, so `prompt=login` would survive and loop.

Hence the `setQueryParameter` / `removeQueryParameterValue` pair in the accessor table.
`ChfOAuth2RequestTest` must assert that both are visible through `getRequestUrl()`.

### The `Request.getCurrent()` thread-local leak (research §2c — must be resolved here)

There are **12** `getCurrent()` uses outside `openam-oauth2`'s restlet packages, in two groups:

- **7 error-construction sites**:
  `OAuthProblemException.OAuthError.SERVER_ERROR.handle(Request.getCurrent(), …)` in
  `OpenAMClientRegistration` (5×), `openam.oauth2.Utils` (1×),
  `openidconnect.OpenIdConnectToken` (1×).
- **5 auth-collaborator sites** already covered by the collaborator table above:
  `CsrfProtection:207`, `ResourceOwnerAuthenticator:105,107`, `ClientAuthenticator:154,157`.

All have **no CHF equivalent** and return null on the CHF path. **3a decision:** thread the
neutral `OAuth2Request` (or its `getHttpServletRequest()`) to these call sites and drop the
`Request.getCurrent()` argument, OR — where the exception is purely for message construction
and the Restlet request is only used for locale — pass `null`/the servlet request explicitly.
Restlet-package callers of `getCurrent()` are untouched (deleted in Phase 5).

The 7 error sites take the second route via the new `OAuthProblemException.handle(String)`
overload, which builds `new OAuthProblemException(this, null)`. Dropping the request drops the
`redirect_uri`/`state`/`scope` echo it would have populated — **verified unobservable**: the
sole reader of those fields, `OAuth2Utils.OAuthProblemExceptionRedirector#getRedirector`, has
**no callers** repo-wide (nor do `OAuthProblemException.pushException`/`popException`), and the
live error path — `ExceptionHandler` — rebuilds a fresh `OAuth2RestletException` from the status
code and never consults them. So a `SERVER_ERROR` raised after `redirect_uri` is known (e.g.
`OpenIdConnectToken` during implicit/hybrid id_token issuance) renders the same error page it
did before; no client error-redirect is lost because none was ever emitted from these fields.

**The grep gate must exclude `RestletOAuth2Request` itself.** Its
`getHttpServletResponse()` is defined as `ServletUtils.getResponse(Response.getCurrent())`
and it lives in `org.forgerock.oauth2.core`, not a `/restlet/` path, so the naive gate can
never reach 0. Use:

```
grep -rn "getCurrent()" openam-oauth2/src/main --include=*.java \
  | grep -v /restlet/ | grep -v RestletOAuth2Request.java   # → 0
```

(Alternative, if you prefer a clean gate: put `RestletOAuth2Request` in
`org.forgerock.oauth2.restlet` — but that package is deleted wholesale in Phase 5d, and the
class must be `public` for openam-uma, so the exclusion is the lower-friction option.)

## Tests

- **`ChfOAuth2RequestTest`** (new) — the parity workhorse:
  - precedence matrix: attribute > query > form > json; attribute-tier wins over query
    (proves the `setCurrentAcr` rewrite).
  - **`Content-Type` with parameters**: `application/x-www-form-urlencoded;charset=UTF-8` and
    `application/json;charset=UTF-8` must resolve form/JSON params — this is the regression
    `Form.fromRequestEntity` would introduce.
  - body re-read stability: `getBody()` twice + `getParameter` from form + a simulated audit
    read all see the same body (CHF buffered entity).
  - `getParameterCount` = query duplicates only (duplicate `redirect_uri`).
  - `getParameterNames` per method/media-type (GET query, POST form, POST JSON).
  - `getLocale`/`getAcceptedLanguages` from `Accept-Language` (q-values, multi-range), **plus
    the no-header case → `Locale.getDefault()`**.
  - `getEndpointType` incl. realm-prefixed URIs (`/oauth2/realms/root/access_token` →
    `TOKEN_ENDPOINT`); **assert non-null**, since `EndpointType.get` returns null on a miss.
  - **`setQueryParameter`/`removeQueryParameterValue` are observable through
    `getRequestUrl()`** — the `alterMaxAge`/`removeLoginPrompt` goto-URL contract.
  - `getBasicAuthCredentials` ISO-8859-1 (high-bit char in secret); `getAuthorizationBearerToken`.
  - servlet req/resp read from `AttributesContext`.
  Scaffolding per [chf-patterns.md](chf-patterns.md) §5 (`RootContext → AttributesContext →
  RealmContext → UriRouterContext`, `RealmTestHelper`, real `new Request()`).
- **`ResourceOwnerSessionValidatorTest`** — add (or assert existing) coverage that the login
  redirect's `goto` parameter carries the rewritten `max_age` and has `prompt=login` stripped.
  This is the regression guard for the highest-severity change in 3a; it must pass on the
  Restlet path before and after.
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
3. `grep -rn "getCurrent()" openam-oauth2/src/main --include=*.java | grep -v /restlet/ | grep -v RestletOAuth2Request.java` → 0.
4. No route flip, so **no Cargo IT behavior change expected** — but run the OAuth2/UMA smoke
   matrix (client_credentials, authorization_code, refresh, userinfo, introspect,
   permission_request) to confirm the live Restlet path is byte-for-byte unchanged. Record
   pre/post curl for the token + authorize + introspect endpoints; they must match.
   **Include a browser `max_age` re-auth and a `prompt=login` flow** — those are the two
   paths the query-mutation rewrite can silently turn into infinite redirect loops, and no
   unit test on `ChfOAuth2Request` covers them.
5. CI (`.github/workflows/build.yml`) — JDK 11–26 × 3 OSes on the `features/**` push.

## Parity checklist (subset of [plan.md](plan.md) risk register)

| Item | Guard |
|---|---|
| Parameter precedence exact (R-3.1, risk #10) | `ChfOAuth2RequestTest` matrix; `RestletOAuth2Request` verbatim |
| **`Content-Type` with charset parameter (R-3.6)** | parse via `ContentTypeHeader.valueOf`; never `Form.fromRequestEntity`/`Request.getForm()`; test both media types with `;charset=UTF-8` |
| **goto-URL query mutation (R-3.7)** | `setQueryParameter`/`removeQueryParameterValue`; `getRequestUrl()` assertions; browser `max_age` + `prompt=login` smoke |
| Body re-readability (R-3.2, risk #1) | re-read test; CHF buffered entity |
| `getCurrent()` thread-local leak (R-3.3) | 12 call sites converted + grep gate (excl. `RestletOAuth2Request`) |
| Basic-auth ISO-8859-1 (risk #5) | `getBasicAuthCredentials` charset + high-bit test |
| Locale parity (risk #15) | `getLocale`/`getAcceptedLanguages` Accept-Language tests **+ absent-header → `Locale.getDefault()`** |
| Endpoint-type incl. realm-prefixed (risk #12) | `getEndpointType` tests, leading slash, **assert non-null** |
| Cache location (R-3.5) | no servlet-attr mirroring unless IT shows a shared path |
| Factory client-registration resolution unchanged on Restlet | `create(Request)` keeps `httpRequest.getParameter`; only `create(Context,Request)` uses the neutral accessor |
| Live Restlet path unchanged | existing suite green + pre/post curl diff |

## Execution order

`OAuth2Request` → abstract + `RestletOAuth2Request` (verbatim move, `public`) → new accessors
on base (abstract) → **fix the two other subclasses**: `RealmOnlyOAuth2Request` throwing
overrides (incl. `getEndpointType`) + `IdTokenInfo.ValidateIdTokenRequest` delegating
overrides → **fix the two openam-uma constructor call sites** (`UmaUrisFactory:79`,
`UmaProviderSettingsFactory:75`) so the reactor compiles → `BasicAuthHeader` →
`ChfOAuth2Request` (+`ChfOAuth2RequestTest`) → `OAuth2RequestFactory.create(Context,Request)`
(+factory test) → migrate the shared collaborators (`ResourceOwnerSessionValidator`'s
query-mutation rewrite first — it is the riskiest) → convert the 12 `getCurrent()` sites →
`mvn -pl openam-oauth2,openam-uma test` → whole build → grep gates → smoke/curl diff incl.
`max_age` + `prompt=login` browser flows → mark 3a done in [plan.md](plan.md) and start
[phase-3b] from [phase-3-research.md](phase-3-research.md).

## As-built (3a delivered)

Delivered as planned, with four deviations from the plan above. Each is deliberate; 3b/4 should
pick them up from here rather than from the plan text.

1. **`getEndpointPath()` is the abstract member, not `getEndpointType()`.** `getEndpointType()`
   became a concrete `EndpointType.get(getEndpointPath())` on the base. This gave
   `OpenAMScopeValidator` a neutral replacement for its `getResourceRef().getLastSegment()
   .equals("userinfo")` check — `"/userinfo".equals(request.getEndpointPath())` — which
   `EndpointType` alone could not express (it has no `USERINFO` constant).

2. **`RestletOAuth2Request.getEndpointPath()` strips `/realms/{realm}` segments** (approved
   deviation from "no observable change"). The Restlet realm router leaves `realmUrl` pointing at
   the `/oauth2` base, so before this fix `getEndpointType()` returned `null` for every
   realm-prefixed URI (`/oauth2/realms/root/access_token`). Converting
   `ClientCredentialsReader` to `getEndpointType() == TOKEN_ENDPOINT` without the fix would have
   silently disabled `token_endpoint_auth_method` enforcement for OIDC clients on realm-prefixed
   token endpoints. **Consequence:** `AuthorizeRequestValidatorImpl:93` now also skips
   `redirect_uri` validation on `/oauth2/realms/{r}/device/user`, aligning it with the
   already-correct `/oauth2/device/user` behaviour. This is a **fix, not a regression**: before
   the strip, `getEndpointType()` was `null` there, so the validator ran
   `redirectUriValidator.validate(client, redirect_uri)` with the device flow's empty
   `redirect_uri` — which, per `RedirectUriValidator:48-53`, throws
   `InvalidRequestException("Missing parameter: redirect_uri")` for any device client not
   registered with exactly one redirect URI (the usual case). The realm-prefixed device
   verification path was therefore already broken; stripping repairs it. Pinned by
   `RestletOAuth2RequestTest.endpointPathIsResolvedForAMultiSegmentEndpoint`.

3. **`getAuthorizationBearerToken()` and `getAcceptedLanguages()` were not added.** Neither has a
   consumer outside the `/restlet/` packages in 3a (`RestletHeaderAccessTokenVerifier` is 3b;
   `ConsentRequiredResource` / `DeviceCodeVerificationResource` read languages off the Restlet
   `ServerResource`, not off `OAuth2Request`). Add them in 3b/4 when their consumers are ported.
   `ChfOAuth2Request.getLocale()` already parses `Accept-Language` q-values via
   `AcceptLanguageHeader.valueOf(Set)` — note that the `valueOf(String...)` overload does **not**
   parse q-values.

4. **The new transport accessors are throwing defaults on the base, not `abstract`** (only
   `getParameter`/`getParameterCount`/`getParameterNames`/`getBody`/`getLocale`/`getEndpointPath`
   are abstract). `RealmOnlyOAuth2Request` inherits the throwing defaults;
   `IdTokenInfo.ValidateIdTokenRequest` overrides all of them to delegate.

**`ChfOAuth2Request.getEndpointPath()` contract for 4/5:** it concatenates the matched URIs of
every `UriRouterContext` nested **inside the innermost `RealmContext`** and prepends `/`. This
holds because `RealmRoutingFactory.ChfRealmRouter` creates a `RealmContext` at each realm level
before routing onward, so the endpoint routers always sit below it. **Wire the CHF `/oauth2`
routes through `new RealmRoutingFactory().createRouter(next)`** — with only `HostnameFilter`'s
`RealmContext` in the chain the `/oauth2` prefix would leak into the endpoint path.

**Tests:** `ChfOAuth2RequestTest` (27), `RestletOAuth2RequestTest` (14, incl. the realm-prefix
regression), extended `OAuth2RequestFactoryTest` (`create(Context, Request)` + `AttributesContext`
caching). `ResourceOwnerSessionValidatorTest` was reworked off a mocked `OAuth2Request` onto a
spied real `RestletOAuth2Request`, so it now exercises the actual query-string rewrite behind
`prompt=login` removal and the `goto` URL. `ResourceOwnerSessionValidator.getHttpServletRequest`
kept its `@VisibleForTesting` seam, retyped to `OAuth2Request`.

**Still Restlet-bound by design after 3a:** `OAuth2RequestFactory.create(Request)` resolves the
client registration via `httpRequest.getParameter(CLIENT_ID)` (servlet semantics: query + form
only); only `create(Context, Request)` uses the neutral `getParameter`. `OAuth2Utils` takes a
Restlet `Request` directly and is 3b's problem. `RestletOAuth2Request.getHttpServletResponse()`
is the last `Response.getCurrent()` reader and dies with the Restlet transport.

**Verified:** `mvn -o -pl openam-oauth2,openam-uma test` is green (openam-oauth2 655, openam-uma
192; 0 failures/errors/skips) and both static grep gates pass.

**Not verified:** the OAuth2/UMA smoke matrix (`max_age` re-auth and `prompt=login` browser
flows) has not been run against a deployed server — it needs a running instance. `ChfOAuth2Request`
is wired to no live route, so its only coverage is `ChfOAuth2RequestTest`.

**Reusable findings hoisted to [chf-patterns.md](chf-patterns.md) §§7–11** (the cross-phase
reference every later handler consults): CHF request-side parameter/body parsing traps
(`getForm`/`fromRequestEntity`/charset, buffered `Entity`, query mutation), header/locale/basic-auth
parsing (Accept-Language q-values + `Locale.getDefault()` fallback, ISO-8859-1, servlet objects on
`AttributesContext`), endpoint-path derivation across the realm router (the
`new RealmRoutingFactory().createRouter(next)` wiring requirement for Phase 5), the
`Request.getCurrent()` grep gate, and the openam-uma local-`~/.m2` build ordering + spy-don't-mock
test rule. 3b/3c/4/5 should read those from chf-patterns, not re-derive them here.
