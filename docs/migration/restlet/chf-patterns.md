# CHF Target-Stack Patterns

Reusable patterns discovered/verified while implementing [Phase 2 — XACML](phase-2-xacml.md),
the first area moved off Restlet. Every later phase (3–8) reuses this shape. Parent tracker:
[plan.md](plan.md). Written 2026-07-08 on branch `features/restlet-migration`, verified against
`org.openidentityplatform.commons.http-framework:core:3.1.1`.

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

## 7. Verified library versions

`org.openidentityplatform.commons.http-framework:core:3.1.1`,
`org.openidentityplatform.commons:json-resource:3.1.1`,
`org.openidentityplatform.commons:util:3.1.1` (resolved via `mvn -o dependency:tree` against
`openam-http`; API signatures in this doc were confirmed against these jars' sources, not assumed
from call-site inference).
