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
same traps. **§13 is the build-ahead testing pattern** (Phase 3c).

> **⚠ §2 and §6 were corrected on 2026-07-17 during Phase 3c planning.** Both were wrong in ways that
> matter to anyone writing a CHF `Filter` or setting a response entity — §2 about what an
> `Endpoints.from` handler's thrown exception actually produces (an **empty** 500, not a CREST error
> map) and how many 405 bodies exist (**two**); §6 about `setEntity`'s dispatch (**four** branches,
> and `String` silently encodes **ISO-8859-1**). Both corrections are bytecode/source-verified and
> carry inline notes. If you read this doc before that date, re-read those two sections.

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
`Handler`.

> **Corrected 2026-07-17 (Phase 3c).** The original text of the first two bullets was **wrong** about
> the 500 path and about the 405 body, and every later phase reads this section to build filters. The
> corrected facts are below, verified by reading `AnnotatedMethod.java` / `Endpoints.java`. See
> [phase-3c-2-error-layer.md](phase-3c-2-error-layer.md) finding 7.

- **A thrown exception does NOT become a business error response — it becomes an EMPTY 500.** A
  handler method that *throws* is caught by `AnnotatedMethod.invoke` (`:90-94`), which returns
  `new Response(Status.INTERNAL_SERVER_ERROR).setCause(new IllegalStateException("Exception from
  invocation should be handled by promise", e))` — **no `setEntity`**. So: 500, **empty body**, cause
  set. A thrown `ResourceException`'s real status/reason is **lost**.
  ⇒ **Handler methods must catch everything internally and return `Response` objects for every error
  path.** ⇒ **A filter that reads `response.getEntity().getJson()` sees an empty entity and gets an
  `IOException`** — so the usual `catch (IOException) → return response` lets a bare, bodiless 500
  through. Handle the empty-entity case explicitly (`getCause() != null` identifies it).
- **The CREST error-map path is narrower than it looks.** `Endpoints.java:73-76`'s
  `catch (Throwable t)` → `500` + `new InternalServerErrorException(t).toJsonValue().getObject()`
  fires **only** for throwables escaping `AnnotatedMethod.invoke` itself — i.e.
  `parameter.getContext(context)` (`:80-82`, *before* the try) or `responseAdapter.apply` (`:85`,
  inside the try but not among the two caught types). Not for a throwing handler method.
- **There are TWO framework 405 bodies, not one:**

  | Trigger | Status | Body `code` |
  |---|---|---|
  | Verb not in the `{GET,POST,PUT,DELETE}` map (HEAD/OPTIONS/PATCH) — `Endpoints.java:66-67` | 405 | **501** (`NotSupportedException`) |
  | Verb *is* mapped but no annotated method — `AnnotatedMethod.java:71-75` | 405 | **405** (`ResourceException.getException(405, …)`) |

  `findMethod` never returns `null` (`:120` returns a sentinel with `method == null`), so
  GET/POST/PUT/DELETE always take the second path. The Phase-2 "body says 501" quirk is real but
  applies **only** to the first row — the outer HTTP status and the JSON `code` legitimately disagree
  there. This is shared framework code (used by every `Endpoints.from` consumer, e.g.
  `AuthenticationServiceV1`/`V2`), not something a later phase should patch per-endpoint; if it needs
  fixing, fix it once in `openam-http`.
- **Annotated-method return types are constrained, and `String` is a trap.** Verified in
  `AnnotatedMethod.checkMethod:138-152`. Permitted: **`Response`** (`:141-147`), `String` / `Void` /
  `byte[]` / `JsonValue` (`ResponseCreator.forType:182-191`). A **`Promise`** return reaches
  `PromisedResponseCreator.apply:202` → `throw new UnsupportedOperationException("to be implemented")`
  — **unimplemented**, despite `checkMethod:139-140` appearing to support it. Any other type →
  `IllegalArgumentException("Unsupported response type: …")` (`:192`), thrown at **`Endpoints.from`
  construction time** (route-provider wiring), not per-request.
  A `String`-returning method goes to `ResponseCreator.apply:171` →
  `new Response(OK).setEntity(content)` → §6's **ISO-8859-1 path, with no `Content-Type`**.
  ⇒ **Return `Response`** from handler methods.
- **`@ExceptionHandler` (`openam-http/.../annotations/ExceptionHandler.java`) is dead code** — no
  `@Retention` (so it defaults to `CLASS` and is invisible to reflection), no `@Target`, **zero
  usages**, and neither `Endpoints` nor `AnnotatedMethod` ever looks for it. It cannot be used to turn
  exceptions into responses. A `Filter` is the only lever. Worth deleting in Phase 8's sweep.
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

> **Corrected 2026-07-17 (Phase 3c).** The original first bullet said `setEntity(Object)` sends
> "anything not `byte[]`" to `setJson`. **There are four branches, and the `String` branch silently
> encodes ISO-8859-1.** Verified at bytecode level against `core-3.1.1.jar`. See
> [phase-3c-1-renderer.md](phase-3c-1-renderer.md) finding 3.

- **`Response.setEntity(Object)` (`MessageImpl.setEntity0`) dispatches on runtime type — four
  branches:**

  | Runtime type | Routes to | Effect on `Content-Type` |
  |---|---|---|
  | `BranchingInputStream` | `Entity.setRawContentInputStream` | untouched |
  | `byte[]` | `Entity.setBytes` | untouched (only `Content-Length`) |
  | **`String`** | **`Entity.setString`** | **untouched — and see below** |
  | anything else (POJO/Map/…) | `Entity.setJson` | **overwritten to `application/json; charset=UTF-8`, unconditionally** |

- **⚠ `setEntity(String)` encodes ISO-8859-1 unless `Content-Type` already carries a charset.**
  `Entity.setString(v)` → `setBytes(v.getBytes(cs(null)))`, and `cs(null)` reads the message's current
  `Content-Type` charset, **falling back to `StandardCharsets.ISO_8859_1`** (RFC 2616). `setString`
  never sets `Content-Type` itself. So `response.setEntity(html)` on a fresh `Response` mangles every
  non-ASCII character in the body — and **ASCII-only test fixtures will not catch it**.
  **Mandated recipe for any text body** (order-independent, no reliance on `cs()`):
  ```java
  response.getHeaders().put(ContentTypeHeader.NAME, "text/html; charset=UTF-8");
  response.setEntity(html.getBytes(StandardCharsets.UTF_8));   // byte[] → setBytes, Content-Type untouched
  ```
  This also applies to `Endpoints.from` handler methods that **return `String`** — they go through
  `ResponseCreator.apply:171` → `new Response(OK).setEntity(content)` and hit the same path with no
  `Content-Type` at all. See §2: **return `Response`**.
  > **Being fixed in-tree (F4).** That second path is `openam-http`'s, not commons' — the module owns a
  > `@Produces` annotation it never reads. [openam-http-framework.md](openam-http-framework.md) F4 sets the
  > header and encodes to the declared charset, after which a `String` return is safe and "return `Response`"
  > is house style rather than a trap. The commons-side default (`Entity.setString` with no `Content-Type`)
  > is filed for an upstream fix; the recipe above is correct either way.
- For a POJO/Map entity, any manually-set `Content-Type` is clobbered by `setJson`. (Existing house
  style, e.g. `AuthenticationServiceV1.createResponse`, sets it anyway for documentation purposes even
  though it's redundant — harmless, matches convention.) This is why an OAuth2 JSON error body wants
  `setEntity(map)`: `setJson` supplies `application/json; charset=UTF-8` for free.
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

## 13. The 3-way golden oracle (Phase 3c) — how parity survives Restlet's deletion

Introduced by [phase-3c-1-renderer.md](phase-3c-1-renderer.md). Applies to any **build-ahead** class
(one wired to no route until a later phase), where the usual guardrail — "the existing Restlet suite
must stay green" — does not exist because the new code is not on any path yet.

**The problem.** Phases 3c/3d ship classes that encode a *contract* which only becomes observable at
the Phase-5d flip, potentially months later. Nothing tests them against reality. Worse, the only
oracle for "what does OpenAM actually do today" is the Restlet code itself — which Phase 5d/8
**deletes**. Write the parity test late and there is nothing left to compare against.

**The pattern.** While Restlet is still on the classpath, drive **both** implementations in one JVM
and assert against a committed golden file:

```
assertThat(restletOutput).isEqualTo(golden);   // proves the golden IS Restlet's real output
assertThat(chfOutput).isEqualTo(golden);       // proves the new code matches it
```

- **Today** it gives maximal confidence: the golden is *proven* to be the legacy behaviour, not
  someone's belief about it, and the new code is measured against it.
- **After 5d** delete the Restlet leg (one line). It degrades gracefully to `golden == CHF` — a
  durable regression guard that still encodes Restlet's truth after Restlet is gone.

**Driving legacy Restlet code in-process — use a `Component` context, never `new Context()`.** Any phase that
characterizes Restlet code from a unit test hits this (verified 2026-07-17 resolving 3c-1's §B):

```java
Component comp = new Component();                       // real client dispatcher, no CLAP client registered
Context ctx = comp.getContext().createChildContext();   // == RestEndpointServlet's shape
```

- **`new org.restlet.Context()` has a null `clientDispatcher`** (the field is returned unguarded, no lazy
  init). Anything dispatching through the context — `ContextTemplateLoader` (`clap:///`), RIAP, any client
  protocol — throws `NullPointerException: ... the return value of
  "org.restlet.Context.getClientDispatcher()" is null`.
- **An NPE skips the framework's graceful-degradation paths.** Restlet/FreeMarker turn "not found" into `null`
  via `catch (IOException)` (`MultiTemplateLoader` fall-through; `TemplateRepresentation.getTemplate`) — an NPE
  sails past both. Expect this shape wherever a legacy `null` is really an `IOException` catch.
- A `Component` context degrades exactly as production does: no connector for the scheme → dispatcher returns
  an error status → the caller's `null`/fallback path runs.

**Rules.**
- Generate goldens **only** while the Restlet leg lives (a `-Dgolden.regenerate=true` mode). A golden
  regenerated after 5d is unfalsifiable — it just records whatever the new code does. If one must
  change post-5d, re-derive it from git history and say so in the commit.
- **Drive the real legacy object, never a hand-rebuilt equivalent.** If the behaviour lives in a collaborator
  (3c-1: popup composition is in `OAuth2Representation`, not `TemplateFactory`), scaffold that object — passing
  `null` for collaborators it does not use on the path under test — instead of reproducing its logic in the
  test. A leg that reimplements the legacy asserts "my copy == my new code": the post-5d golden trap, arriving
  early.
- **Derive fixtures from the real producers, not from the API's apparent shape.** Both legs get the same
  fixture, so a *fictional* one still passes parity while silently voiding the golden's post-migration value.
  3c-1 found three keys whose natural-looking types are wrong — see
  [phase-3c-1 D12](phase-3c-1-renderer.md#d12--golden-data-models-are-derived-from-the-producers).
- **Pin the golden files' own I/O charset** (`UTF_8` on read *and* write). Pinning the renderer's encoding says
  nothing about how the test reads its fixtures; default-charset I/O reintroduces `file.encoding` dependence
  across the JDK 11–26 × 3-OS matrix (JEP 400 flipped the default at 18).
- **Hardening that is inert today needs a config assert, not a behavioural test.** 3c-1's `RETHROW_HANDLER` is
  observationally identical to FreeMarker's default under eager render-to-`String` (`DEBUG_HANDLER` prints
  *and rethrows*), so "does it throw?" passes with the line deleted. Assert the setting itself.
- **Do not edit the inputs the golden depends on** (for 3c-1: the 10 `.ftl` templates). Editing them
  destroys the golden's meaning as a legacy oracle — even to fix an obvious bug. File the bug; defer.
- Goldens are for **large structural output** (HTML). For 2–4-field maps and one-line URLs, inline
  asserts (`containsExactly(entry(...), …)`) are more precise, more readable and self-documenting —
  a file containing `{"error":"x"}` is pure ceremony. See
  [phase-3c-2-error-layer.md](phase-3c-2-error-layer.md) §B.

**Precedent.** This is the repo's first golden-file infrastructure — there are no `*.golden` files and
no `expected/` dirs. The nearest relative is
`openam-rest/src/test/java/org/forgerock/openam/rest/fluent/JsonUtils.java`'s
`assertJsonValue(JsonValue, resourcePath)` (compares `toString()` against a classpath resource;
duplicated in openam-audit-core). [plan.md](plan.md) risk #14 and Phase 5d both already call for
golden render tests — 3c is simply the last moment the oracle is alive to generate them truthfully.

**Why it earns its keep:** [phase-3b-collaborators.md](phase-3b-collaborators.md)'s as-built #2 —
characterization tests written *before* a strip **failed 3/4 against the unmodified code**, because
the author's belief about the legacy contract was wrong. Every parity claim in a migration plan is a
belief until executed. This is the instrument that converts beliefs into facts mechanically.

## 14. Framework defects: fix them, don't pattern around them (2026-07-21)

**Before designing a workaround for CHF or endpoint-framework behaviour, check which tier of the stack owns
it** — the full ownership map and decision procedure live in
[docs/framework-ownership.md](../../framework-ownership.md).

The short version, because it changes plans:

- **`openam-http` is in this repo.** `org.forgerock.openam.http.annotations` (`Endpoints`, `AnnotatedMethod`,
  `@ExceptionHandler`) is module `openam-http`, not a vendored dependency. **A `org.forgerock.*` package name
  is not evidence of foreign ownership** — most of this codebase carries ForgeRock package names and is
  maintained here.
- **Commons `http-framework` (`Entity`, `ContentTypeHeader`, `Status`) is ours but released**, and its version
  is not even pinned in this pom — it arrives through the imported `opendj-parent` BOM. When the fix is
  general, **fix commons, cut a release, and consume it** (a direct `dependencyManagement` entry here
  overrides the BOM without waiting on an OpenDJ release); work around only when the defect is specific to
  how we call the API.
- **Check the cheap tier first.** Of three defects the Restlet migration filed under commons, **two were
  tier 1 all along** — the `String`-return charset trap (this module never sets a `Content-Type`, and owns an
  unread `@Produces` annotation that says what it should be → F4) and `BaseURLProvider`'s CHF-unreachable
  overload (`openam-core`).
- Land tier-1 framework fixes as **their own commit with their own tests**, never inside a migration commit.

Phase 3c-2 initially designed around three `openam-http` defects — a filter rule synthesising a body the
framework should have written, a "handlers must catch everything" rule, and a value type justified by "a
thrown exception is swallowed into a bodiless 500". All three dissolved once the framework was fixed instead:
see [openam-http-framework.md](openam-http-framework.md). §2 above describes the framework **as fixed by
F1–F3**; the pre-fix behaviour is preserved in
[phase-3c-2-error-layer.md](phase-3c-2-error-layer.md#7--the-filter-cannot-catch--and-endpointsfroms-500-has-an-empty-body)
as the baseline the fix is measured against.

**Smell test.** You are working around something you own if the plan contains: a wrapper synthesising what the
framework should emit; a rule saying "every handler must remember to X"; a behaviour that survives only
because some call *accidentally* throws; a declared-but-unimplemented annotation or return type; or the
sentence *"if this needs fixing, it should be fixed once in \<module\>"*.
