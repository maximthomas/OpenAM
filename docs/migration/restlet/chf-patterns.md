# CHF Target-Stack Patterns

Reusable patterns discovered/verified while implementing [Phase 2 — XACML](phase-2-xacml.md),
the first area moved off Restlet. Every later phase (3–8) reuses this shape. Parent tracker:
[plan.md](plan.md). Written 2026-07-08 on branch `features/restlet-migration`, verified against
`org.openidentityplatform.commons.http-framework:core:3.1.1`.

§§1–6 are the routing / response / test-scaffold side (Phase 2). **§§7–11 are the CHF
*request* side — parameter/body/header/locale/basic-auth parsing and endpoint-path
derivation — verified while delivering [Phase 3a](phase-3a-oauth2request.md)
(`ChfOAuth2Request`).** Phases 3b/3c/4/5 read requests through the `OAuth2Request` neutral
API, but any new CHF handler parsing a raw `org.forgerock.http.protocol.Request` hits the
same traps.

## 1. HttpRouteProvider SPI

- `org.forgerock.openam.http.HttpRouteProvider` (`openam-http/.../http/HttpRouteProvider.java`) —
  `Provider<Set<HttpRoute>>`. Register via
  `src/main/resources/META-INF/services/org.forgerock.openam.http.HttpRouteProvider` (one FQCN per
  line). `HttpRouterProvider` (openam-http) loads every registered provider via `ServiceLoader` and
  Guice `injectMembers` — so a provider class needs no `@Inject` constructor, only `@Inject`-annotated
  setter methods (mirrors `OAuth2RestHttpRouteProvider`, `STSPublishServiceHttpRouteProvider`,
  `XacmlHttpRouteProvider`).
- `HttpRoute.newHttpRoute(RoutingMode, String uriTemplate, Handler)` — the plain-`Handler` overload
  is enough when the provider builds the handler chain itself (as opposed to a Guice `Key`/`Class`/
  `Provider<Handler>` overload used when the handler is resolved lazily per-request).
- `routing-base=context_path` in `openam-server-only/.../WEB-INF/web.xml`'s `OpenAM` servlet means
  `STARTS_WITH` templates match the leading path segment directly (`"xacml"`, `"json"`, ...).

## 2. `Endpoints.from` — semantics that matter

`org.forgerock.openam.http.annotations.Endpoints.from(Class)` / `AnnotatedMethod`
(`openam-http/.../http/annotations/`) turn `@Get`/`@Post`/`@Put`/`@Delete` annotated methods into a
`Handler`. Two behaviors are **easy to miss and load-bearing**:

- **A thrown exception does NOT become a business error response.** `AnnotatedMethod.invoke` only
  catches `IllegalAccessException`/`InvocationTargetException` from the *reflective call itself*, and
  `Endpoints.from`'s wrapping `Handler.handle` catches `Throwable` generically → bare
  `500 Internal Server Error` with `new InternalServerErrorException(t).toJsonValue().getObject()`. A
  thrown `ResourceException`'s real status/reason is **lost**. **Handler methods must catch
  everything internally and return `Response` objects for every error path.**
- **The framework's own fallbacks already use CREST error-map JSON bodies**: unmapped HTTP method →
  `405` + `new NotSupportedException().toJsonValue().getObject()`; uncaught `Throwable` → `500` +
  `new InternalServerErrorException(t).toJsonValue().getObject()`. **Quirk found in Phase 2**: the
  embedded map's own `code` field is `NotSupportedException`'s fixed value (`501`), not the `405`
  actually set on the `Response` — the outer HTTP status and the JSON body's `code` field can
  legitimately disagree. This is shared framework code (`AnnotatedMethod`/`Endpoints`, used by every
  `Endpoints.from` consumer, e.g. `AuthenticationServiceV1`/`V2`), not something a later phase should
  patch per-endpoint; if it needs fixing, fix it once in `openam-http`.
- A single `Filter` that rewrites any `≥400` response whose entity is a CREST error map into another
  form (XML, in Phase 2's case) therefore covers **every** error path — business errors returned by
  the handler *and* the framework's own 405/500 fallbacks — for free. See
  `XacmlXmlErrorFilter` (`openam-entitlements/.../xacml/v3/rest/XacmlXmlErrorFilter.java`): read the
  cached object back with `response.getEntity().getJson()` (cheap — `Entity.setJson`/`setEntity`
  caches the original object, no re-parse) rather than re-deserializing.
- **Placement matters for "every" to hold**: wrap this filter around the *whole* route (outside the
  realm router — `Handlers.chainOf(root, xacmlXmlErrorFilter)`), **not** inside the per-realm inner
  chain. The legacy Restlet app rendered realm-routing failures (`RestletRealmRouter`) as XML via its
  `XMLRestStatusService`; a filter buried inside the inner chain misses realm-resolution errors
  (invalid realm / DNS alias), leaking the framework-default JSON error body instead.

## 3. Realm routing wiring (mirrors `/json`)

Model: `RestGuiceModule.getChfRootRouter()` (`openam-rest/.../rest/RestGuiceModule.java`). For a
**new top-level area** (not nested under `/json`'s existing root router), build the same shape
directly in the route provider (see `XacmlHttpRouteProvider`):

```java
Router root = new Router();
root.addRoute(requestUriMatcher(STARTS_WITH, RealmRoutingFactory.REALM_ROUTE),
        Handlers.chainOf(realmRoutingFactory.createRouter(root), realmRoutingFactory.createHostnameFilter()));
root.setDefaultRoute(Handlers.chainOf(innerChain, realmContextFilter));
```

- `RealmRoutingFactory.createRouter(Handler next)` (openam-rest) — recursive `realms/{realmId}`
  matching; `next` is typically the router itself (safe: `next` is only invoked lazily per-request,
  not at construction time, so `createRouter(root)` before `root` is fully built is fine).
- `RealmRoutingFactory.createHostnameFilter()` — DNS-alias realm resolution.
- `RealmContextFilter` (openam-rest, battle-tested on `/json`) — legacy path realm, realm alias,
  `?realm=` override; injected via plain constructor (`@Inject`), no explicit Guice binding needed.
- Both `RealmRoutingFactory` and `RealmContextFilter` are concrete classes with `@Inject` constructors
  — Guice JIT-binds them, no module wiring required.
- Realm is read downstream via `context.asContext(RealmContext.class).getRealm().asPath()`
  (`org.forgerock.openam.rest.RealmContext`).

## 4. `@Named` filters and `Handlers.chainOf` ordering

- `Handlers.chainOf(Handler handler, Filter... filters)` builds `filters[0] . (filters[1] . (... .
  handler))` — **the first filter argument is outermost and runs first**; `handler` (the first
  positional parameter) is the innermost target. Verified by reading
  `org.forgerock.http.handler.Handlers` source (`core-3.1.1-sources.jar`), not just inferring from
  call sites.
- `@Named("AuthenticationFilter")` and `@Named("ResourceApiVersionFilter")` (both bound in
  `RestGuiceModule`) are reusable CHF `Filter`s beyond `/json`. **`resourceApiVersionContextFilter`
  MUST run before any `requestResourceApiVersionMatcher`-based routing** (explicit javadoc
  constraint in `RouteMatchers`) — order relative to the authentication filter is not constrained the
  same way; `/json` happens to run auth outermost, Phase 2 runs the XML-error filter and version
  filter outermost with auth innermost (still legal, since version-filter-before-version-router is
  the only hard constraint).
- Version routing on a single resource: nest another `Router` matched by
  `RouteMatchers.requestResourceApiVersionMatcher(version(N))` inside a `Router` matched by
  `requestUriMatcher(EQUALS, "<resource>")` — same 2-level shape the old Restlet
  `ResourceApiVersionRestlet` used, and the same shape `CoreRestAuthenticationGuiceModule` uses for
  `/json/authenticate`.

## 5. CHF handler test scaffolding

- Build real context chains instead of mocking CHF types (they're concrete, cheap to construct):
  `new RealmContext(new RootContext(), realm)`. Only add `AttributesContext` to the chain if a test
  actually exercises code that reads it.
- **`Realm.root()`/`Realm.of(...)` require class-level static injection** — a plain unit test will
  NPE (`Realm.coreWrapper`/`Realm.realmLookup` are static and injected via Guice
  `requestStaticInjection`). Use `org.forgerock.openam.core.realms.RealmTestHelper`
  (`openam-core` test-jar — already a test dependency of most REST modules):
  `new RealmTestHelper()` → `setupRealmClass()` in `@BeforeMethod` → `tearDownRealmClass()` in
  `@AfterMethod` (throws if a previous test forgot to tear down — a class-level `static` guard). Use
  `realmTestHelper.mockRealm("sub1", "sub2")` for non-root realms (path segments, not a single
  slash-joined string); zero-arg `mockRealm()` returns `Realm.root()`.
- Construct real requests: `new Request().setMethod("POST").setUri("/xacml/policies?dryrun=true")`;
  `Form.fromRequestQuery(request)` reads the query string directly off the URI.
- To stub only the permission/authorization seam without mocking the whole CAF auth chain, subclass
  the handler and override the package-private `checkPermission(...)` entry point (same package,
  legal): see `XacmlServiceHandlerTest.TestXacmlServiceHandler`. Keep the innermost
  `checkPermission(DelegationPermission, SSOToken, String)` seam `@VisibleForTesting` and test it
  directly for the granted/denied audit-logging assertions.

## 6. Header/entity gotchas (CHF `Response`)

- `Response.setEntity(Object)` (`MessageImpl.setEntity0`) dispatches on runtime type:
  `byte[]` → `Entity.setBytes` (only touches `Content-Length`); anything else → `Entity.setJson`
  (**overwrites `Content-Type` to `application/json; charset=UTF-8`, unconditionally**). Set a custom
  `Content-Type` header *before* `setEntity(...)` only matters if the entity is `byte[]`/`String`/
  `BranchingInputStream` — for a POJO/Map entity, any manually-set `Content-Type` is clobbered by
  `setJson`. (Existing house style, e.g. `AuthenticationServiceV1.createResponse`, sets it anyway for
  documentation purposes even though it's redundant — harmless, matches convention.)
- `Entity.getJson()` returns the **cached original object** (no re-parse) if the entity was populated
  via `setJson`/`setEntity(Object)` — useful in filters/tests that need to inspect a body that was
  just set programmatically in the same process.

## 7. CHF request-side parameter & body parsing (`ChfOAuth2Request`, Phase 3a)

The read side of a migrated request — every handler in 3b/4/5 that pulls params/body off a raw
`org.forgerock.http.protocol.Request`. Verified against http-framework 3.1.1 bytecode and the
delivered `openam-oauth2/.../oauth2/core/ChfOAuth2Request.java`.

- **Parameter precedence to reproduce Restlet:** (1) per-request attribute map → (2) query string →
  (3) `POST` `application/x-www-form-urlencoded` body → (4) `POST` JSON body. Query wins over body.
  `getParameterCount(name)` counts **query-string duplicates only** (the
  `DuplicateRequestParameterValidator` contract) — build it from `new Form().fromRequestQuery(request)`,
  never from the body.
- **Never call `Request.getForm()`.** It is `fromRequestQuery(this)` *then* `fromRequestEntity(this)`
  merged into **one** `Form`, which collapses precedence tiers 2 and 3 (query and body become
  indistinguishable).
- **Never call `Form.fromRequestEntity(request)` as-is.** It guards on an **exact** compare of the
  *whole* `Content-Type` header against `application/x-www-form-urlencoded`, so a client sending
  `application/x-www-form-urlencoded;charset=UTF-8` (common in OAuth2 client libraries) gets an
  **empty form, silently**. Restlet compares the *parsed* `MediaType` and ignores parameters.
- **Correct content-type test:** `mediaType.equalsIgnoreCase(ContentTypeHeader.valueOf(request).getType())`.
  `ContentTypeHeader.valueOf(request).getType()` is the parsed media type with parameters stripped.
- **Read a form body** with `new Form().fromFormString(request.getEntity().getString())`. `Entity` has
  **no** `getForm()` method.
- **The CHF `Entity` is buffered.** `getString()` / `getJson()` do **not** consume the stream and both
  cache (an `Entity` caches its `json` and `string` fields), so the Restlet
  `request.setEntity(form.getWebRepresentation())` re-read hack is unnecessary — parse once and
  instance-cache the `Form` / `JsonValue`. (Contrast `RestletOAuth2Request`, which must re-`setEntity`
  after every `new Form(entity)`.) This is why the body stays re-readable by audit + auth + handler in
  one request (risk #1).
- **Mutating the query string:** `new Form().fromRequestQuery(request)` reads the query off the URI;
  edit the `List<String>` values in place; `form.toRequestQuery(request)` writes it back onto
  `Request.getUri()`. **Invalidate any cached query `Form` after a write** (the cache is derived from
  the URI). This is the `setQueryParameter` / `removeQueryParameterValue` pair that keeps
  `alterMaxAge` / `removeLoginPrompt` from looping the login redirect (risk #17) — see the
  [3a plan](phase-3a-oauth2request.md) "goto-URL" note.
- **`getBody()` on `IOException`** returns an **empty** `JsonValue` (`JsonValue.json(JsonValue.object())`),
  matching Restlet — never propagate the exception.

## 8. CHF request headers, locale, and basic auth (Phase 3a)

- **Locale:** `AcceptLanguageHeader.valueOf(Set<String>)` parses q-values and sorts by preference; the
  `valueOf(String...)` overload does **not** parse q-values. Wrap the single raw header value in a
  `LinkedHashSet` and read `.getLocales().getPreferredLocale()`. **When `Accept-Language` is absent,
  fall back to `Locale.getDefault()`** — that is exactly what `HttpServletRequest.getLocale()` returns,
  and downstream i18n relies on it (risk #15).
- **Basic auth is decoded ISO-8859-1, not UTF-8** (risk #5). The neutral holder is
  `oauth2.core.BasicAuthHeader { String clientId; char[] secret }`; `BasicAuthHeader.parse(header)`:
  `null` header → `null`; non-`Basic` scheme → `new BasicAuthHeader(null, null)`; `Basic` → Base64
  decode as ISO-8859-1, split on the **first** `:`. This replaces `ChallengeResponse` grubbing in
  `ClientCredentialsReader` / `ClientAuthenticator`.
  - **Restlet trap it preserves:** `Request.getChallengeResponse()` is **non-null for *every* scheme**
    (Bearer included), with a null identifier for non-Basic. OAuth2 client authentication uses the mere
    *presence* of credentials to detect "two authentication methods on one request", so a `null` return
    would change behavior. Both transports return a **non-null** `BasicAuthHeader` with `null` clientId
    for a non-Basic `Authorization` header, and `null` only when the header is entirely absent.
- **Servlet request/response on the CHF side** live on `AttributesContext` under the keys
  `HttpServletRequest.class.getName()` / `HttpServletResponse.class.getName()` (put there by
  `HttpFrameworkServlet`). No thread-local, no `SecurityContext` plumbing. Guard with
  `context.containsContext(AttributesContext.class)` first. `RestletOAuth2Request` gets the same objects
  via `ServletUtils.getRequest(request)` / `ServletUtils.getResponse(Response.getCurrent())`.

## 9. Endpoint-path derivation across the realm router (Phase 3a)

`EndpointType.get(path)` (`openam-core`, `org.forgerock.openam.oauth2.OAuth2Constants`) matches
**leading-slash** paths (`/access_token`, `/authorize`, `/device/user`) and returns **`null`** on a
miss — not an exception. Get the path wrong and `ClientCredentialsReader`'s
`getEndpointType() == TOKEN_ENDPOINT` check silently evaluates false, disabling token-endpoint
client-auth-method enforcement — so **assert non-null** in tests, not just equality.

The delivered abstraction makes `getEndpointPath()` the abstract member and derives
`getEndpointType()` as a concrete `EndpointType.get(getEndpointPath())` on the base — this also gives
`OpenAMScopeValidator` a neutral form of its old `getLastSegment().equals("userinfo")` check
(`"/userinfo".equals(request.getEndpointPath())`), which `EndpointType` has no constant for.

- **CHF** (`ChfOAuth2Request.getEndpointPath()`): concatenate the `getMatchedUri()` of every
  `UriRouterContext` nested **inside the innermost `RealmContext`** (outermost first, `/`-joined,
  leading slash prepended); return `null` when there is no `RealmContext`.
  `RealmRoutingFactory.ChfRealmRouter` creates a `RealmContext` at each realm level before routing
  onward, so the endpoint routers always sit below it. **Wire the CHF `/oauth2` routes through
  `new RealmRoutingFactory().createRouter(next)`** — with only `HostnameFilter`'s `RealmContext` in the
  chain, the `/oauth2` prefix leaks into the endpoint path. Two traps: `getRemainingUri()` has **no**
  leading slash, and by the time a handler builds the request the innermost router has already
  **consumed** the endpoint segment (remaining URI empty) — so use **matched** URIs, not remaining.
- **Restlet** (`RestletOAuth2Request.getEndpointPath()`): the realm router leaves the `REALM_URL`
  attribute pointing at the `/oauth2` base, so the path is `resourceRef` minus `realmUrl`, then
  **strip leading `/realms/{id}` segments in a loop** (they sit *below* the realm base). Without the
  strip, every realm-prefixed URI (`/oauth2/realms/root/access_token`) yields a `null` endpoint type.
  Accepted consequence of the strip: `AuthorizeRequestValidatorImpl` also skips `redirect_uri`
  validation on `/oauth2/realms/{r}/device/user`, aligning it with the already-correct
  `/oauth2/device/user`.

## 10. `Request.getCurrent()` / `Response.getCurrent()` — Restlet thread-locals (Phase 3a)

Restlet thread-locals with **no CHF equivalent** (they return `null` off the Restlet path). Every use
outside a `/restlet/` package must be eliminated before its area flips.

- **Grep gate** (must be 0), excluding the one legitimate reader —
  `RestletOAuth2Request.getHttpServletResponse()` uses `Response.getCurrent()` but lives in
  `org.forgerock.oauth2.core` (not a `/restlet/` path) and dies with the Restlet transport in Phase 5:
  ```
  grep -rn "getCurrent()" openam-oauth2/src/main --include=*.java \
    | grep -v /restlet/ | grep -v RestletOAuth2Request.java   # → 0
  ```
- **Error-construction sites** that only needed the request to build an `OAuthProblemException`
  message: use the behavior-neutral `OAuthProblemException.handle(String description)` overload (drops
  the request argument). Applied to `OpenAMClientRegistration` (5×), `openam.oauth2.Utils`,
  `openidconnect.OpenIdConnectToken`.
- **Auth-collaborator sites** (`CsrfProtection`, `ResourceOwnerAuthenticator`, `ClientAuthenticator`):
  thread the `OAuth2Request` in and read `getHttpServletRequest()` / `getHttpServletResponse()`.

## 11. Build & test notes for the OAuth2 request re-plumb (Phase 3a)

- **openam-uma resolves openam-oauth2 from the local `~/.m2` repo, not the reactor**, when built
  module-scoped. After changing an openam-oauth2 **public** API that openam-uma calls directly
  (`new RestletOAuth2Request(...)`, `getHttpServletRequest()`, …), run
  `mvn -o -pl openam-oauth2 install -DskipTests` **before** `mvn -o -pl openam-uma test`, or openam-uma
  fails to compile against the stale installed jar.
- **`RealmTestHelper` needs the openam-core test-jar** — added as a `test`-scoped `<type>test-jar</type>`
  dependency on `openam-core` in `openam-oauth2/pom.xml` (see §5 for the helper's lifecycle).
- **When the code under test mutates the request** (the query rewrite in `alterMaxAge` /
  `removeLoginPrompt`), **spy a real `RestletOAuth2Request` — do not mock `OAuth2Request`.** A mock
  makes `setQueryParameter` / `removeQueryParameterValue` no-ops, so the `goto`-URL regression those
  methods exist to prevent (risk #17) passes silently. `ResourceOwnerSessionValidatorTest` was reworked
  from a mocked request onto `spy(new RestletOAuth2Request(null, restletRequest))`, stubbing only the
  parameter lookups via `doReturn(...).when(spy).getParameter(...)`.
- **`ChfOAuth2RequestTest` scaffolding:** real `new Request()` + a context chain
  `RootContext → AttributesContext → RealmContext → UriRouterContext` (per §5); assert charset-bearing
  content types resolve, `getParameterCount` = query duplicates only, ISO-8859-1 basic auth,
  Accept-Language q-values **and** the absent-header `Locale.getDefault()` fallback, and endpoint type
  **non-null** on realm-prefixed URIs.

## 12. Verified library versions

`org.openidentityplatform.commons.http-framework:core:3.1.1`,
`org.openidentityplatform.commons:json-resource:3.1.1`,
`org.openidentityplatform.commons:util:3.1.1` (resolved via `mvn -o dependency:tree` against
`openam-http`; API signatures in this doc were confirmed against these jars' sources, not assumed
from call-site inference).
