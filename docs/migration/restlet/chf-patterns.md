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
same traps. **§13 is the build-ahead testing pattern** (Phase 3c); **§14 is the framework-ownership
rule** (fix defects in code we own); **§15 is the CHF access-audit base** (Phase 3d); **§17 is
`OAuth2Exception` → status** (5a-2b); **§18 is the servlet-built request URI** (5b-1).

> **⚠ §2 describes a framework that was fixed on 2026-07-22 — re-read it if you read this doc earlier.**
> `openam-http`'s annotation framework had four defects (empty-bodied 500s, a dead `@ExceptionHandler`, an
> unimplemented `Promise` return, ignored `@Produces`); all four are fixed in-tree, and §2 now describes the
> result. See [openam-http-framework.md](openam-http-framework.md#as-built). **§6 still stands as corrected on
> 2026-07-17**: `setEntity`'s dispatch has **four** branches and `setEntity(String)` on a `Response` you built
> yourself still silently encodes **ISO-8859-1** — F4 fixed the framework's `String`-return path, not commons'
> `Entity`. Both sections are source-verified and carry inline notes.

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

> **Rewritten 2026-07-22 (F1–F4).** This section previously described a framework in which a thrown
> exception vanished into an **empty** 500, `@ExceptionHandler` was dead, a `Promise` return detonated,
> and a `String` return was ISO-8859-1. All four are **fixed in-tree** — see
> [openam-http-framework.md](openam-http-framework.md) and its
> [As-built](openam-http-framework.md#as-built). The pre-fix behaviour is preserved as the baseline in
> [phase-3c-2-error-layer.md](phase-3c-2-error-layer.md#7--the-filter-cannot-catch--and-endpointsfroms-500-has-an-empty-body).
> An earlier correction (2026-07-17) fixed this section's account of the 405 bodies; a later fix (2026-07-23,
> Phase 4) made the two 405 paths emit one shape — see the 405 table below.

- **A thrown exception becomes a response — one shape, whatever failed.** `AnnotatedMethod.invoke`
  catches everything a handler method can throw and produces a CREST error:
  `500` + `new InternalServerErrorException(t).toJsonValue().getObject()`, i.e.
  `{code: 500, reason: "Internal Server Error", message: <the throwable's message>}` with
  `Content-Type: application/json; charset=UTF-8` (written for free by `setJson` — §6). `Response.getCause()`
  is still set for debugging; it is never serialised.
  ⇒ **Every failure response the framework itself generates now has a CREST body** — this 500 and both
  405s below. The empty-entity special case filters used to need for the 500 is gone. (A *handler* can
  still return a bodiless `≥400` of its own; that is its choice, not the framework's.)
  ⇒ **`message` carries the throwable's own message**, so a handler should not put anything in an
  exception message it would not send to a client. No stack trace ships (`includeCause` is false), and
  the message is HTML-escaped by `toJsonValue()`.
- **An endpoint can map its own exceptions — `@ExceptionHandler` is live** (see below). Failing that,
  the CREST 500 above is the answer. Handler methods may therefore `throw`; catching everything
  internally is house style for endpoints that want a *specific* status, not a framework requirement.
- **The framework's own failures are not offered to `@ExceptionHandler`.** Only what the annotated
  method itself threw (the `InvocationTargetException` path) reaches the endpoint's mapper; a failure of
  the framework's plumbing — an unresolvable `@Contextual` context, say — goes straight to the default
  500. Otherwise an endpoint mapping `IllegalArgumentException` could turn a wiring error into a 200 and
  mask it indefinitely.
- **Both framework 405 paths now emit a 405-coded body** (fixed 2026-07-23, Phase 4):

  | Trigger | Status | Body `code` |
  |---|---|---|
  | Verb not in the `{GET,POST,PUT,DELETE}` map (HEAD/OPTIONS/PATCH) — `Endpoints.java` `method == null` | 405 | **405** (`ResourceException.getException(405, "Method Not Allowed")`) |
  | Verb *is* mapped but no annotated method — `AnnotatedMethod.java:94-98` | 405 | **405** (`ResourceException.getException(405, …)`) |

  `findMethod` never returns `null` (`:201` returns a sentinel with `method == null`), so
  GET/POST/PUT/DELETE always take the second path. **History:** the first row used to emit a body whose
  `code` was **501** (`new NotSupportedException()`) against the 405 status — a self-contradiction that also
  diverged from Restlet. Phase 4 fixed `Endpoints.java` to use a 405-coded body there too, so the two paths
  now render one shape. `/oauth2` never depended on the fix (its `OAuth2ErrorFilter` keys off the wire
  status), but `/uma` carries no such filter and needed the raw framework body coherent. Pinned by
  `EndpointsTest.unmappedVerbGives405WithA405Body`.
- **Annotated-method return types are constrained, and each has one meaning.** Decided in
  `AnnotatedMethod.checkMethod` at **`Endpoints.from` construction time** (route-provider wiring), not
  per request — an unsupported type is `IllegalArgumentException("Unsupported response type: …")` while
  there is still someone to tell.

  | Return | Result |
  |---|---|
  | `Response` | sent as built — the method owns its status and headers |
  | `Promise<Response, NeverThrowsException>` | passed through; **exactly** those two type arguments, checked against the *generic* return type at wiring time |
  | `String` | `200` + `text/plain; charset=UTF-8`, or whatever `@Produces` declares |
  | `byte[]` | `200`, no `Content-Type` unless `@Produces` says one |
  | `JsonValue` | `200` + `application/json; charset=UTF-8` (`setJson` writes it) |
  | `Void` | `204`, empty and untyped |
  | `void` (primitive) | **rejected** at wiring time — `void` is not `Void` |

  **Returning `null`** gives `204` from a `String`, `byte[]` or `Promise` method, as `Void` always does.
  Two exceptions, both pre-existing and both pinned by tests rather than fixed: a `JsonValue` method
  returning null yields a **500** (the converter dereferences first), and a `Response` method returning
  null yields a **null `Response`** that fails downstream in CHF.

  **A `String` return is now safe**: F4 sets the `Content-Type` *before* the entity, so `Entity` encodes
  with the declared charset instead of §6's ISO-8859-1 fallback. Returning `Response` remains the house
  style when a method needs a specific status or extra headers — it is no longer a trap to do otherwise.
- **`@Produces("…")` declares the content type** for a `String`/`byte[]`/`JsonValue` return. It is
  **rejected at wiring time** where it cannot be honoured: on a method returning `Response` or `Promise`
  (which owns its own headers), on `Void` (no content to describe), when it contradicts a `JsonValue`'s
  `application/json`, when empty, and when the charset is unknown. A type with no charset gets
  `; charset=UTF-8` completed onto it for `String` returns — writing `@Produces("text/html")` must not
  quietly reinstate ISO-8859-1.
- **`@ExceptionHandler` turns an exception into a response** — the endpoint's own `doCatch`:

  ```java
  @ExceptionHandler
  public Response onOAuth2Error(OAuth2Exception e, @Contextual Request request) { … }
  ```

  Exactly one unannotated parameter assignable to `Throwable`; optional `@Contextual` `Context`/`Request`;
  the same return types as a verb method, `@Produces` included. Dispatch is **most-specific assignable**,
  so a handler for a supertype catches the subtype thrown. One method per exception type (duplicates are
  a wiring error); an unmatched throwable falls back to the CREST 500; and a mapper that itself throws
  logs both throwables and falls back rather than recursing. **Java does not inherit annotations onto an
  override** — a subclass that overrides an `@ExceptionHandler` method must re-annotate it.
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
- **Testing an `AbstractOAuth2HttpJsonEndpoint` subclass (Phase 5a) — don't spin up Guice.** `new TheHandler()`,
  then set the four `@Inject` fields by walking the class hierarchy with reflection (`getDeclaredField` on each
  superclass, since `requestFactory`/`errorResponseFactory` live on the base), then drive through
  `Endpoints.from(handler)` (the `Object` overload — it uses the instance as-is) so the base
  `@ExceptionHandler onError` actually runs and maps thrown `OAuth2Exception`s. Use the **real**
  `OAuth2ErrorResponseFactory(mock(FreemarkerTemplateRenderer.class), mock(BaseURLProviderFactory.class),
  mock(RealmNormaliser.class))` — its `toJsonResponse` needs no renderer — so the error body and
  `WWW-Authenticate` are the production shapes. Mint real `InvalidClient*Exception`s (their ctors are
  package-private) via a one-off test subclass of the abstract `ClientAuthenticationFailureFactory`
  (`hasAuthorizationHeader`→true/false, `getRealm`→…) and its `getException(o2, msg)` / `getException(msg)`.
  Mock `OAuth2Request` and stub `getParameter("grant_type")`/`"state"` — no servlet/realm context needed, a bare
  `new RootContext()` suffices. Read either body with `response.getEntity().getJson()` (§2). See
  `TokenEndpointHandlerTest`. Note `InvalidClientException(String)` is **400**; only
  `InvalidClientAuthZHeaderException` (auth-header path) is **401** (RFC 6749 §5.2).
- **Cache headers are per-endpoint — do NOT default them on the base (corrected 5a-2, 2026-07-24).** The Restlet
  `OAuth2Filter.beforeHandle` stamps `Cache-Control: no-store` + `Pragma: no-cache` on success *and* error, but
  it wraps **only** `/access_token` + `/authorize` (`TokenEndpointFilter`/`AuthorizeEndpointFilter` are its only
  subclasses). The other OAuth2 JSON endpoints get **none** from the filter — `/tokeninfo` sets its own
  `Cache-Control: no-cache, no-store` (**no `Pragma`**) on its **success** path only; the rest set nothing. So
  the base's `onError` calls an overridable `withErrorHeaders(Response)` that **defaults to no headers**;
  `TokenEndpointHandler` overrides it to `noCache` and also calls `noCache` on its success response. Each handler
  reproduces its own contract — `noCache` is opt-in, never a base default. Getting this wrong (an unconditional
  base `noCache`, as 5a-1 first had it) adds `no-store`/`Pragma` the other endpoints never sent, and the 5d-1
  byte-diff flags it.
- **Content-type validation: gate on body-emptiness, compare case-insensitively (5a review).** The Restlet
  `*EndpointFilter.validateContentType` only rejects a **non-empty** entity — an empty/absent body is never
  checked. Reproduce with an early `if (request.getEntity().isRawContentEmpty()) return;` (that call peeks via
  `push`/`read`/`pop`, so it does **not** consume the body). Then compare with `equalsIgnoreCase` — media types
  are case-insensitive (RFC 7231) and `ContentTypeHeader.getType()` preserves the header's case.

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
  > **No longer applies to `Endpoints.from` handler methods that return `String`** (fixed 2026-07-22, F4).
  > That path was `openam-http`'s, not commons': the module owned a `@Produces` annotation it never read.
  > `ResponseCreator` now puts the `Content-Type` on the response **before** the entity, so `cs(null)`
  > resolves the declared charset — default `text/plain; charset=UTF-8`. A `String` return is safe; see §2.
  > The recipe above remains mandatory for any `Response` you build yourself, because the commons-side
  > default (`Entity.setString` with no `Content-Type`) is unchanged and is filed for an upstream fix.
- For a POJO/Map entity, any manually-set `Content-Type` is clobbered by `setJson`. (Existing house
  style, e.g. `AuthenticationServiceV1.createResponse`, sets it anyway for documentation purposes even
  though it's redundant — harmless, matches convention.) This is why an OAuth2 JSON error body wants
  `setEntity(map)`: `setJson` supplies `application/json; charset=UTF-8` for free.
- `Entity.getJson()` returns the **cached original object** (no re-parse) if the entity was populated
  via `setJson`/`setEntity(Object)` — useful in filters/tests that need to inspect a body that was
  just set programmatically in the same process.

### ⚠ `Headers` re-parses known headers on the way **in** — the raw value is unrecoverable (Phase 5b-1a)

`Headers.put(String, Object)` / `add(String, Object)` look the name up in a static `FACTORIES` map and,
when one matches, **store the parsed `Header` object instead of the string you passed**
(`Headers.java:136-145`, `putUsingFactory`). `getFirst(name)` then re-renders that object. So for every
header commons has a factory for, the value you read is the factory's *canonical* rendering, not the
client's bytes — and `HttpFrameworkServlet.createRequest` populates the request through exactly this path
(`request.getHeaders().add(name, list(req.getHeaders(name)))`, `:309-312`), so it applies in production, not
just in tests. Only headers whose factory **throws** `MalformedHeaderException` fall back to a
`GenericHeader` and survive verbatim.

Measured for `Accept-Language` (`AcceptLanguageHeader` → `PreferredLocales`), 2026-07-26:

| Client sent | `getFirst("Accept-Language")` returns |
|---|---|
| `en-GB,en;q=0.8,fr;q=0.9` | `en-GB;q=1,fr;q=0.9,en;q=0.8` — **re-sorted by quality** |
| `de,fr` | `de;q=1,fr;q=0.9` — **q values invented by position** |
| `en-GB, fr ; q=0.5` | `en-GB;q=1,fr;q=0.9` — **the client's 0.5 is discarded** |
| `en;q=0` | `en;q=1` — a "not acceptable" tag **promoted to preferred** |
| `EN-gb` | `en-GB;q=1` — case normalised |
| `` (empty) | `*;q=1` via `add`, absent via `put` |
| `en;q=bogus` | `en;q=bogus` — parse failed ⇒ `GenericHeader` ⇒ raw survives |

⇒ **If you need a header exactly as the client sent it, read it from the servlet request**
(`OAuth2Request.getHttpServletRequest()`), which is also where Restlet's own adapter read it, and keep the CHF
header as a best-effort fallback for non-servlet transports. `ChfOAuth2Request.getAcceptedLanguages()` does
this; `RestletAcceptLanguageParityTest` is the proof. Nothing about this is specific to `Accept-Language` —
check `FACTORIES` before trusting any `getFirst`.

> **⚠ Use `getHeaders(name)` (plural), not `getHeader(name)`.** A client may split one logical header over
> several lines. Restlet's adapter folds them with `getRequestHeaders().getValues(name)`, which **joins with a
> comma**; `HttpServletRequest.getHeader` returns only the *first* line. Reproduce the fold:
> `String.join(",", Collections.list(servletRequest.getHeaders(name)))`. A parity test whose fixture is a
> single `String` cannot reach this case — drive it with a list of header lines.
>
> **Read the jar the reactor actually resolves.** OpenAM depends on
> `org.openidentityplatform.openam.jakarta:org.restlet`, a fork — **not** upstream `org.restlet.jee:2.4.4`.
> `mvn -o -pl <module> dependency:tree | grep restlet` before `javap`; the two differ where it matters.

## 7. CHF request-side parameter & body parsing (`ChfOAuth2Request`, Phase 3a)

The read side of a migrated request — every handler in 3b/4/5 that pulls params/body off a raw
`org.forgerock.http.protocol.Request`. Verified against http-framework 3.1.1 bytecode and the
delivered `openam-oauth2/.../oauth2/core/ChfOAuth2Request.java`.

- **Parameter precedence to reproduce Restlet:** (1) per-request attribute map → (2) query string →
  (3) `POST` `application/x-www-form-urlencoded` body → (4) `POST` JSON body. Query wins over body.
  `getParameterCount(name)` counts **query-string duplicates only** (the
  `DuplicateRequestParameterValidator` contract) — build it from `new Form().fromRequestQuery(request)`,
  never from the body.
- **The attribute map is seeded from `RealmContext`:** `ChfOAuth2Request.attributes()` puts `realm` (the
  realm *path string*) and `realmObject` (the `Realm` *object*, `RealmContext.getRealm(context)`) — so
  `getParameter(REALM)` / `getParameter(REALM_OBJECT)` resolve under CHF. Load-bearing: the
  `*UrisFactory.get(OAuth2Request)` overloads (`OAuth2UrisFactory.java:68`, `UmaUrisFactory.java:83`) read
  `REALM_OBJECT` **directly** with no token/`realm` fallback, so an unseeded `realmObject` NPEs them — a break
  that *compiles* and slips past mocked tests (see [phase-4-uma.md](phase-4-uma.md) finding 6; `realmObject`
  seeding was added in Phase 4a). The provider-settings factories are safe without it — they resolve through
  `OAuth2RealmResolver` (stashed-token realm, else seeded `realm`).
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
  - **A hand-built empty legacy representation is not a production empty body.** Verified building 3d-2's
    `RestletAuditParityTest`: a production empty body is a `Representation` reporting `isEmpty()==true`, on which
    `RestletBodyAuditor.jacksonAuditor` short-circuits to `{}`. A `new JacksonRepresentation<>(new
    StringRepresentation(""), Map.class)` does **not** report empty — it tries to parse `""` and throws. So the
    empty-body row cannot A/B the Jackson leg; assert the CHF auditor against the **org.json `jsonAuditor`** leg
    there (it guards `isEmpty()` on the representation) and document why. General lesson: an empty/edge fixture
    hand-wrapped for the legacy leg may not hit the same guard the real producer does — check the guard, not the
    constructor.
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
F1–F4** (landed 2026-07-22, 64 new tests in a package that had none); the pre-fix behaviour is
preserved in
[phase-3c-2-error-layer.md](phase-3c-2-error-layer.md#7--the-filter-cannot-catch--and-endpointsfroms-500-has-an-empty-body)
as the baseline the fix is measured against.

**Smell test.** You are working around something you own if the plan contains: a wrapper synthesising what the
framework should emit; a rule saying "every handler must remember to X"; a behaviour that survives only
because some call *accidentally* throws; a declared-but-unimplemented annotation or return type; or the
sentence *"if this needs fixing, it should be fixed once in \<module\>"*.

## 15. CHF access-audit base (`AbstractHttpAccessAuditFilter`) — shape & traps (Phase 3d)

The CHF access-audit base is `org.forgerock.openam.audit.AbstractHttpAccessAuditFilter` (openam-audit-core,
**in-tree**); its Restlet counterpart is `AbstractRestletAccessAuditFilter` (openam-rest). It emits two events
per request (`AM_ACCESS_ATTEMPT` before the handler in `filter()`, `AM_ACCESS_OUTCOME` in the `.then(...)`),
reading `userId`/`trackingIds` from `AuditRequestContext` and HTTP detail from
`AMAccessAuditEventBuilder.forRequest(request, context)`. Facts verified 2026-07-23 (full detail:
[phase-3d-audit.md](phase-3d-audit.md)):

- **It is a *stripped* port — two gaps vs the Restlet base.** (1) **No body detail**: it never calls
  `builder.requestDetail(...)` / `responseWithDetail(..., detail)` even though both exist on the builder.
  (2) Its **outcome hooks take only `Response`** (`getUserIdForAccessOutcome(Response)` etc.) — no request, no
  context — and the attempt hooks lack the context. Any subclass that needs the request in the outcome (OAuth2
  reads tokens off it) must widen the hooks. Do it **additively** — new `(Context, …)` overloads whose defaults
  delegate to the existing signatures — so the live `/json` subclasses (`AuthenticationAccessAuditFilter`,
  `DocsAccessAuditFilter`) and the base test stay untouched.
- **⚠ 3xx is audited as FAILED.** `filter()` branches on `Status.isSuccessful()`, which is **2xx only**
  (`Status.java` has `isRedirection()`/`isClientError()`/`isServerError()` and **no `isError()`**). The Restlet
  base branches on `isError()` (4xx/5xx), so it audits every 3xx as **success**. For any area that returns 3xx
  on success (OAuth2 `/authorize` = 302), reproduce Restlet: failure iff `isClientError() || isServerError()`.
- **⚠ `forRequest` leaks POST-body form fields into `http/request/queryParameters`.** It reads query params via
  `request.getForm()` (`AMAccessAuditEventBuilder:123`) = query **+** body merged (§7). The Restlet path
  (`forHttpServletRequest`) used the servlet query string only. Fix at source: `Form.fromRequestQuery(request)`.
- **Body auditors are per-route, not per-component.** `/json` binds one filter per `Component` via a
  `MapBinder` + `HttpAccessAuditFilterFactory`; OAuth2/UMA attach a fresh filter **per endpoint** with a
  different body-auditor pair. CHF audit filters for those areas are plain constructible classes, built in the
  route provider — do **not** route them through the component MapBinder.
- **Body auditing needs no buffering.** The CHF `Entity` is buffered (§7), so reading the body in the audit
  filter leaves it re-readable for the handler — no `BufferingRepresentation` equivalent needed (contrast the
  Restlet base's transient-entity wrap). Restlet's `jsonAuditor`+`jacksonAuditor` **collapse to one** on CHF
  (single `Entity.getJson()`).

**Confirmed building 3d-2** (`OAuth2HttpAccessAuditFilter`/`UMAHttpAccessAuditFilter`/`HttpBodyAuditor`, commit
`41170fb92a`; full record: [phase-3d-audit.md § As-built](phase-3d-audit.md#as-built)):

- **`OAuth2RequestFactory.create(context, request)` caches one `ChfOAuth2Request` on the `AttributesContext`.**
  So every per-request reader in a chain — the audit filter, `ClientAuthenticator`, any handler — that calls
  `create(context, request)` gets the **same instance and its attribute map**. This is what makes the audit
  filter's `AM_CTX_ID` request-attribute fallback (`oAuth2Request.getAttribute(AM_CTX_ID)`) able to read what
  `ClientAuthenticator` wrote, and it means a filter never pays to rebuild the request. Rely on it when wiring
  Phase 4/5 routes; do **not** thread a request object through manually.
- **Give any filter that resolves an SSO session a `protected SSOToken getSSOToken(OAuth2Request)` seam.**
  `SSOTokenManager.getInstance().createSSOToken(...)` is a static that cannot run in a unit/IT JVM; a `protected`
  override point lets tests supply (or null out) the session without the static. Its cost, inherited from the
  Restlet original, is that it is **not cached per request** — called in both `getUserId` and the tracking-id
  helper, i.e. up to **4× per audited request**. Faithful to Restlet; a caching pass is a CHF-cleanup item, not
  a migration change.
- **`OpenIdConnectToken` does not implement `IntrospectableToken`.** So the identity-derivation `instanceof`
  ladder (`IntrospectableToken` → `getResourceOwnerId()`, else `OpenIdConnectToken` → `get(sub)`) is
  order-safe — an OIDC token never matches the introspectable branch.
- **`HttpBodyAuditor` is a pure `Entity → JsonValue`** with one shared `select(fields, valueOf)` loop behind
  `jsonAuditor` (`map::get`) and `formAuditor` (`form::getFirst`) — the field-selection contract is defined once,
  mirroring the legacy `RestletBodyAuditor.extractValues`. `noBodyAuditor()` is literally `null` (a `—` in the
  finding-2 route matrix), so wiring can pass it directly.

## 16. The Restlet `StatusService` renders a CREST body for *bare* error statuses (Phase 4)

Verified 2026-07-23 building [Phase 4](phase-4-uma.md) (finding 1), by disassembling the in-repo Restlet
`org.restlet.engine.application.StatusFilter`. **Applies to every Restlet area whose app sets a
`StatusService` — `/oauth2` and `/uma` both do** — so Phase 5 needs it too.

- **Any error status with a null entity gets a body, whether or not the resource set one.** A Restlet
  `Filter` that rejects with `response.setStatus(new Status(4xx, throwable))` and returns `STOP` (e.g.
  `AccessTokenProtectionFilter`) never sets an entity. But the app's outer `StatusFilter.afterHandle` runs
  on the way out and, seeing `status.isError() && getEntity() == null`, fills it from
  `getStatusService().toRepresentation(status, …)`. So a "bare 401" is **not** empty on the wire.
- **The body is CREST `{code, reason, message}`, not the exception's own shape.** `RestStatusService`
  (base of `JSONRestStatusService`, openam-rest) does
  `ResourceException.getException(status.getCode(), throwable.getMessage()).toJsonValue()` when the
  throwable is **not** a CREST `ResourceException`. `OAuth2Exception`/`UmaException` are **not** CREST
  `ResourceException`s, so their `getError()` (`"invalid_token"`, …) is **discarded** — the client sees
  `{"code":401,"reason":"Unauthorized","message":"<getMessage()>"}` at `application/json`. Only the
  HTTP status code and the exception *message* survive.
- **This is the SAME shape `Endpoints.from` emits natively** for a framework 405/500 (§2 —
  `crestBody(ResourceException)`). So a CHF port that (a) lets the framework produce 405/500 and (b) has
  its filters build the CREST map via `ResourceException.getException(code, msg).toJsonValue().getObject()`
  reproduces the legacy `StatusService` output **without any error filter**. `setEntity(Map)` supplies
  `application/json; charset=UTF-8` (§6) — the lone, benign difference from Restlet's charset-less
  `application/json`.
- **The endpoint-exception path is different and must not be conflated.** When a resource's `doCatch`
  (Restlet) / `@ExceptionHandler` (CHF) sets its own entity, `StatusFilter` leaves it alone — that path
  keeps the endpoint's designed shape (UMA `{error, error_description, …}`; OAuth2's error map). ⇒ two
  shapes coexist on one area: **CREST for filter/framework errors, the endpoint's shape for endpoint
  errors.** Wiring a blanket rewriter like `OAuth2ErrorFilter` over an area that has CREST-shaped
  filter/framework errors (UMA) changes them; scope it to areas whose contract *is* the OAuth2 shape
  end-to-end. Check which of the two paths each error takes before choosing where the shape is produced.

## 17. `OAuth2Exception` → HTTP status quirks (Phase 5a-2b)

<a id="15-oauth2exception--http-status-quirks-phase-5a-2b"></a>
*(Numbered §15 when written; renumbered to §17 in 5b-1 planning — §15 was already the access-audit base. The
old anchor is kept above so existing links still resolve.)*


Facts pinned while porting `/token/revoke` — a CHF handler that `throw`s to the base
`@ExceptionHandler(OAuth2Exception)` gets the status from `e.getStatusCode()`, so these govern the wire:

- **`ServerException` is `400 server_error`, not 500** (`ServerException(String)` → `super(400, …)`).
  Surprising given the name.
- **`OAuth2Exception` is `abstract` and no subtype maps to 500** (`grep 'super(500' …/core/exceptions`
  → none). ⇒ **a handler cannot produce a 500 by throwing to the base mapper.** A genuine 500 only comes
  from the framework's own CREST fallback (an *unmatched*, non-`OAuth2Exception` throwable — §2).
- **Corollary for `/token/revoke` (corrects plan D4):** the Restlet's `catch (CoreTokenException) → 500`
  is unreachable dead code (`TokenStore.read(String)` throws only the OAuth2 `ServerException`/
  `NotFoundException`; nothing in the flow throws `CoreTokenException` — `getToken` merely over-declared it).
  The port omits the catch; there was no reachable 500 to preserve, and `new ServerException` would have
  yielded 400 anyway. Byte-parity holds because the branch never executed.

## 18. The CHF request URI under `HttpFrameworkServlet` is **absolute** (Phase 5b-1)

Verified in `commons/http-framework/servlet/.../HttpFrameworkServlet.java:293-320` while planning the
`/authorize` port; reusable by every later phase that needs a URL rather than a parameter.

- `createRequest` builds the CHF `Request` URI as
  `Uris.createNonStrict(req.getScheme(), null, req.getServerName(), req.getServerPort(), req.getRequestURI(),
  req.getQueryString(), null)` (`:300-306`). So:
  - `request.getUri().toString()` is the **absolute** request URL — scheme, host, port, **context path**, query.
    This is what `ChfOAuth2Request.getRequestUrl()` returns, which is what `ResourceOwnerSessionValidator`
    threads into the login redirect's `goto` (risk #17): absolute, as the Restlet `ResourceRef` was.
  - `request.getUri().getPath()` **includes the context path** (`/openam/oauth2/authorize`), matching Restlet's
    `getResourceRef().getPath()`. It is *not* route-relative, whatever `routing-base` says — `routing-base` only
    feeds `UriRouterContext.matchedUri`/`remainingUri` (`:337-343`, `ServletRoutingBase.CONTEXT_PATH` returns the
    context path minus its leading slash; `SERVLET_PATH` appends the servlet path).
  - The query is **re-encoded** by `createNonStrict` (CHF-81 tolerance of invalid query strings), where Restlet
    passed the raw string through. Equal for well-formed queries; note it before byte-diffing a URL built from it.
- ⇒ **Reconstruct a path+query value from the CHF `Request` URI, not from `getHttpServletRequest()`.** They agree
  on the bytes, but only the CHF URI carries `OAuth2Request.setQueryParameter`/`removeQueryParameterValue`
  mutations — `ChfOAuth2Request` writes those back through `Form.toRequestQuery(request)`
  (`ChfOAuth2Request.java:270-274`), exactly as the Restlet accessors mutate the resource reference. Sourcing
  from the servlet request silently reverts them.
- **Exception, already in force:** the *deployment root* (`scheme://host:port/<first-segment>`) is reconstructed
  from the servlet request via `OAuth2Utils.getDeploymentURL` ([phase-5a-2b as-built](phase-5a-2.md#as-built) D5),
  because that helper is the canonical shape and is what `/connect/register` and `/device/code` already use.

**Related gap (Phase 5b-1):** there was no neutral accessor for the *list* of `Accept-Language` tags —
`OAuth2Request.getLocale()` collapses the header to a single `Locale`. The consent page's `locale` key needs the
raw preference-ordered tags, so `getAcceptedLanguages()` is added in 5b-1a and A/B'd against Restlet's
`ClientInfo` parser ([phase-5b-1 D3](phase-5b-1.md#d3)) — **built 2026-07-26**; the parity table is the
authority on its behaviour, and it diverges from D3's predictions in four places
([phase-5b-1 as-built S4](phase-5b-1-asbuilt.md#as-built-s4)).

⇒ **When a neutral accessor needs a base default, use the value an absent header produces — not "empty".**
`getAcceptedLanguages()` defaults to `List.of("*")`, because its tags are *joined into a page* and an empty
list renders `locale: ""`, a value no live request produces (a client that sends no `Accept-Language` yields
`*`). "This transport cannot tell you" and "the client did not ask" both mean *no stated preference*, so they
should answer alike; consumers already handle the wildcard, and none handle `""`. The alternative — making the
accessor `abstract` so the compiler forces every transport to answer — is worse here: it obliges the Restlet
subclass and its decorators to implement a call that never happens, i.e. **new Restlet code written during the
phase whose purpose is deleting Restlet**. Applies to any further neutral accessor these phases add.

## 19. What the Restlet `OAuth2Filter` did around **every** OAuth2 resource (Phase 5b-1)

`org.forgerock.oauth2.restlet.OAuth2Filter.beforeHandle:58-79`, read while porting `/authorize`. Every ported
endpoint under `/oauth2` inherits these three behaviours from the filter that wrapped it, and a CHF handler has
to reproduce them itself — nothing wraps it any more.

1. **`validateMethod`, then `validateContentType` — on every method.** The content-type check is *not* gated on
   the verb, so a `GET` carrying a non-empty entity is refused exactly as a `POST` is. Reproduce it on **every**
   verb of the ported handler; the normal bodyless GET early-returns on `isRawContentEmpty()`, so it costs
   nothing. Checking only the body-bearing verb silently widens what the endpoint accepts.
   The two subclasses differ only in their verb list — `TokenEndpointFilter` (POST) and `AuthorizeEndpointFilter`
   (GET or POST) — and carry a **byte-identical** `validateContentType`, so the 5a-1 recipe ports verbatim
   ([§5](#5-chf-handler-test-scaffolding)).

   ⚠ **Two things about that check are not what a reader predicts, and both were ported wrong before an oracle
   caught them** (`RestletContentTypeParityTest`, which drives the real filters). The whole check is
   `!MediaType.APPLICATION_WWW_FORM.equals(entity.getMediaType())`, so *everything* turns on that one `equals`:
   - **A body with no `Content-Type` at all is a 400, not a pass.** `equals(null)` is false, the negation fires,
     Restlet threw. Reading a null type as "no opinion" is the natural mistake and it is worse than a wrong
     status: `ChfOAuth2Request.getParameter` reads a POST body only when the type *is* form, so on `/authorize`
     the consent form's `decision=allow` arrives as `null`, `consentGiven` becomes `false`, and the resource
     owner's approval is delivered to the service as a **refusal** — `access_denied` to the client, no error
     logged anywhere.
   - **The comparison is case-sensitive.** `MediaType.valueOf` preserves the spelling and `MediaType.equals`
     compares names, so Restlet 400'd an `APPLICATION/X-WWW-FORM-URLENCODED` that RFC 7231 §3.1.1.1 says is
     legal. The CHF ports compare case-insensitively — a deliberate widening, since it can only turn a Restlet
     400 into a success, never the reverse.

   A `;charset=UTF-8` parameter is *not* part of the comparison on either side: Restlet's `ContentType` splits
   the charset into the representation's character set before `equals` sees it, which `ContentTypeHeader.getType()`
   matches. The rule now lives once, in `OAuth2ContentTypes.isFormUrlEncoded`, because two independent ports of
   it drifted into the same defect.
2. **`Cache-Control: no-store` + `Pragma: no-cache`, unconditionally**, on success *and* error, after the
   validation. Only `/access_token` and `/authorize` were wrapped by an `OAuth2Filter` subclass, which is why
   `noCache` is opt-in per handler rather than a base default.
   ⚠ **No handler can close this one from the inside**, and that is the point: a response the *framework*
   produces — the 405 for an unannotated verb, the 404, the CREST 500 for an unmatched throwable — never reaches
   the handler or its `withErrorHeaders`, so per-method stamping cannot cover it. Restlet had no such hole
   because its filter *wrapped* the resource instead of being called by it. ⇒ **`OAuth2NoCacheFilter`** restores
   exactly that: a filter that stamps every response, composed on `/authorize` and `/access_token` **only** —
   applying it to the whole `/oauth2` application would be a widening, for the same reason `noCache` is opt-in.
   The handlers keep their own `noCache` calls; `Headers.put` makes the overlap idempotent, and it keeps them
   correct when driven directly, which is how the unit suites drive them.
3. **It returns `CONTINUE` even after writing an error** — the CONTINUE bug. The ported handler always
   **returns**; it must never reproduce the fall-through. Whether each filter error actually survived to the
   wire is an observation, not a derivation: capture it live before porting
   ([phase-3c-2](phase-3c-2-error-layer.md)).

**Adjacent fact, same phase:** `templates/page/error.ftl` interpolates only `error` and `error_description`.
The `state` the error producer has always put in its data model reaches **no template**, so the HTML error page
does not echo `state` — only the *redirect* branch does, where it rides in `asMap()` as a query parameter.


## 20. On the browser base, **build** your errors — never throw them (Phase 5b-1)

A handler under `AbstractOAuth2HttpJsonEndpoint` can throw any `OAuth2Exception` safely: that base has one
rendering, a JSON body at the exception's status. A handler under `AbstractOAuth2HttpBrowserEndpoint`
**cannot**, and the difference is a security boundary rather than a style choice.

`onError` redirects whenever `OAuth2Error.mayRedirect(e)` is true and the request carries a `redirect_uri`, and
`mayRedirect` keys on **exception type** against a fixed `NEVER_REDIRECT` list. So the two types a handler
reaches for when it detects a problem itself are both redirectable:

| Thrown | Reaches the browser base as | Restlet did |
|---|---|---|
| `InvalidRequestException` (bad content type, missing parameter) | **302** to the request's raw `redirect_uri` | 400 page — `OAuth2RestletException(status, error, msg, state)`, redirect null (`OAuth2Filter:66-70`) |
| `ServerException` (template fault, wrapped bug) | **302**, error description in the client's query string | 400 page — `ExceptionHandler.handle(Throwable, …):86-89`, redirect null |

In both cases the request failed **before the client was resolved**, so the `redirect_uri` has been validated by
nothing: the redirect is an open redirect, and it exfiltrates the error description with it.

⇒ **Rule.** An error a browser handler *detects itself* is built, not thrown:

```java
return withErrorHeaders(errorResponseFactory.toResponse(o2,
        OAuth2Error.of(400, "invalid_request", description).withState(o2.<String>getParameter(STATE))));
```

`OAuth2Error.of(int, String, String)` carries **no** redirect target, so `toResponse` takes the page branch by
construction — the property is structural, not a guard someone has to remember. Throwing stays correct for
errors the *core* raises, which is what the collapse in [phase-5b-1 D9](phase-5b-1.md#d9) is about; the
distinction is who detected the problem, not how severe it is.

**Test rule that follows:** every row asserting a self-built error must stub a `redirect_uri`. Without it the
response takes the page branch either way and the row passes whichever form the handler used — which is exactly
how both defects reached review in 5b-1.

## 21. Restlet's conditional-request machinery (Phase 5c)

Disassembled from the resolved fork (`org.openidentityplatform.openam.jakarta:org.restlet:16.2.0-SNAPSHOT`)
on 2026-07-29 while planning [Phase 5c](phase-5c.md) — the only endpoint in the migration that uses HTTP
conditional requests. Recorded here because the mechanism is invisible in the endpoint's own source and the
Restlet oracle dies at 5d-2.

- **`ServerResource` evaluates preconditions itself, before the annotated method runs.** The constructor sets
  `conditional = true`, `existing = true`, `negotiated = true`, `annotated = true`. `handle()` then does
  `if (isConditional()) doConditionalHandle()`, and `doConditionalHandle()` runs the precondition logic
  whenever `getConditions().hasSome()` — i.e. whenever `If-Match` or `If-None-Match` is on the request.
- **To get the current ETag it invokes the `@Get` method.** With `existing == true` the info branch calls
  `doGetInfo(Variant)` → `doHandle(MethodAnnotationInfo, Variant)`, which dispatches to the resource's own
  `@Get`. So a conditional `PUT`/`DELETE` performs the read as a side effect, and a failure *of the read*
  (e.g. `NotFoundException`) is what the client sees.
- **The two headers are compared by *different* rules.** `Conditions.getStatus(Method, RepresentationInfo)`
  compares `If-Match` with `Tag.equals(obj, /* checkWeakness */ false)` — names only, so `If-Match: "x"` and
  `If-Match: W/"x"` both match a tag named `x` — but compares `If-None-Match` with
  `checkWeakness = GET || HEAD`, so there **weakness matters**, on the only two verbs that ever consult it.
  ⚠ And the wildcard is a single positional test, `getMatch().get(0).equals(Tag.ALL)`: `*` counts only as the
  **first** parsed element and only in its **strong** form. Line-by-line in [§21b](#21b) — this bullet said
  "ignores weakness, `*` matches any existing entity" until 2026-07-29 and both halves were too broad.
  A mismatch yields **412** with **no entity**; `If-None-Match` matching yields **304**.
- ⇒ **A resource whose Java only asks `!getConditions().getMatch().isEmpty()` still has full `If-Match`
  enforcement** — the presence check is the endpoint's, the matching is the framework's. Porting only the
  visible half is a silent loss of lost-update protection. `Endpoints.from` has **no** conditional-request
  support (`Endpoints.java:60-63` dispatches on verb alone), so the CHF side must evaluate preconditions
  explicitly ([phase-5c D6](phase-5c.md#d6)).

Related: `Filter.handle` returns `CONTINUE`/`SKIP`/`STOP` as `0`/`1`/`2`. `STOP` skips **only that filter's
own** `afterHandle`; an enclosing filter's `doHandle` still returns `CONTINUE`, so **its** `afterHandle` runs
and sees the inner filter's bare status. That ordering is why `/oauth2/resource_set`'s 401 comes out
OAuth2-shaped while `/uma`'s comes out CREST-shaped ([phase-5c finding 1](phase-5c-research.md#1--the-resource_set-401-is-oauth2-shaped-not-crest--the-4a-filter-cannot-be-reused-unchanged)) —
a per-route fact that §16's general rule does not settle on its own.

**`openam-http` gaps this exposed** (both in the
[CHF cleanup backlog](decisions.md#chf-cleanup-backlog)): `@Consumes`, `@Payload` and `@PayloadTranslator` are
declared, documented and **read by no code**, so there is no media-type validation and no payload binding; and
there is no conditional-request/ETag support at all.

<a id="21a"></a>
### 21a. …and what it actually does on the wire (5-E4, measured 2026-07-29)

The disassembly above is right about the mechanism. Three things it does **not** tell you, all recorded
against a live container and all load-bearing for any reimplementation
([5-E4 as-built](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29)):

| Header | Wire behaviour |
|---|---|
| `If-Match: *`, the exact weak tag, or its strong form | match |
| `If-Match` as a **comma list** — any position, with or without a space after the comma | match; the list is parsed |
| `If-Match` that parses but does not match, on **`PUT`/`DELETE`** — including `""` | **412**. ⚠ The conditional layer leaves it **entity-less**; whatever body the client sees is the enclosing filter's — on `/oauth2/resource_set` that is `{"error":"precondition_failed"}` from `ResourceSetRegistrationExceptionFilter`, not from Restlet. ⚠ **Not so on `GET`** — see the `If-Match` row below, where the entity is already populated and the filter's 412 branch never fires |
| `If-Match` that does **not parse** — unquoted token, empty header, `!!!` | ⚠ **indistinguishable from an absent header.** The parser drops what it cannot read, `getConditions().getMatch()` comes back empty, and a resource whose Java asks *"is this conditional?"* concludes **no** |
| `If-None-Match: <current>` | **304**, **carrying the `ETag`**, with **no `Content-Type`** and **no `Content-Length`** — on `GET` and on `HEAD`. ⚠ Body emptiness is *not* part of this record: an HTTP client never surfaces a 304 entity, so it cannot be observed and no row asserts it |
| `If-None-Match: *` | **200.** RFC 7232 §3.2 asks for 304 when a representation exists; Restlet does not do it |
| `If-Match` on a **`GET`** | `*` → 200; a stale tag → **412 carrying the full representation and the `ETag`** |

⚠ **Four more 5-E4 rows (18–21), six behaviours, measured 2026-07-29 while planning the CHF handler.**
Everything above
is the *item* URL and the two verbs the plan expected to be conditional; none of that is where the mechanism
actually stops:

| Request | Wire behaviour |
|---|---|
| `If-None-Match` matching, on **`PUT`/`DELETE`** | **412** — never a 304, which only `GET`/`HEAD` can answer. A non-matching one falls through to whatever the verb does with a missing `If-Match` |
| a **winning `If-Match` plus a matching `If-None-Match`** | **412.** Both headers are evaluated, in that order; the first does not short-circuit the second |
| `If-Match` on a **`POST`** | evaluated like any other verb: `*` → the create proceeds, a stale tag → **412** |
| the same headers against a **tag-less representation** (here: the collection URL) | the answers invert. Stale `If-Match` → **412 carrying the whole body**; `If-None-Match: *` → **304**, where an item answers 200; `If-None-Match: <concrete>` → 200 |
| `If-None-Match: "<strong form of a weak tag>"` | **200 on a `GET`, 412 on a `PUT`** — the weakness flag is `GET‖HEAD`, so it genuinely varies by verb |
| `If-None-Match: W/*` | not the wildcard, exactly as `If-Match: W/*` is not |

⇒ **the precondition pass is one verb-independent gate**, and a reimplementation that attaches conditional
rules per verb gets six of these wrong. `HEAD` is `GET` here, so it needs no separate rule.

⚠ The unparseable row is the trap: a garbage `If-Match` takes the *no-header* path, not the *mismatch* path,
so an implementation that reports "present but unmatched" for garbage answers 412 where Restlet answers
whatever the endpoint does with a missing header.

<a id="21c"></a>
### 21c. ⚠ `Content-Type` on the wire is not the string CHF wrote (measured 2026-07-29)

Not conditional-request specific, but it is where it was found, and it makes two correct assertions look
contradictory. `Entity.setJson` writes the constant `"application/json; charset=UTF-8"` — **with a space**
(`Entity.java:71`). The container re-renders it: a live `/uma/permission_request` 401, served by CHF through
`ChfAccessTokenProtectionFilter` today, comes back as **`application/json;charset=UTF-8`** — *no* space.

⇒ a unit test asserting `"application/json; charset=UTF-8"` on a `Response` and an e2e asserting
`"application/json;charset=UTF-8"` on the wire are **both right**, and neither is evidence against the other.
Check which side of the servlet boundary an assertion sits on before "fixing" one to match the other.

⇒ the corollary that matters at 5d-1: writing a **bare** `application/json` after `setEntity` really does
reach the wire bare, so matching Restlet's no-charset form costs one line and no divergence row
([phase-5c S2](phase-5c-asbuilt.md#as-built-s2)).

<a id="21b"></a>
### 21b. The tag parser itself, line by line (disassembled 2026-07-29 while writing `HttpConditions`)

The table above is the *behaviour*; this is the code that produces it, so nobody has to open the jar again.
`TagReader.readValue` → `HeaderReader.readRawValue` → `Tag.parse`, then `HeaderReader.addValues` collects.
Two of these are not derivable from the measured rows:

- ⚠ **The splitter is not quote-aware.** `readRawValue` reads characters until a comma or EOF with **no**
  quote tracking, so a comma always ends an element — even inside `"…"`. `If-Match: "a,b"` splits into `"a`
  and `b"`, *neither* of which parses, so the whole header is dropped and reads as absent. ⇒ a tag whose name
  contains a comma can never be expressed and never matches. Commons' `HeaderUtil.split` **does** honour
  quotes, so reaching for it as the obvious reuse is a behaviour change, not a cleanup.
- ⚠ **`*` and `"*"` are the same tag.** `Tag.parse` checks the quoted form *first*, so `"*"` yields a tag
  **named** `*` — indistinguishable from the wildcard `*`, which yields the same. Restlet cannot tell them
  apart. ⚠ But do **not** conclude from this that a tag can be reduced to its name: `W/*` also parses, to a
  *weak* tag named `*`, and the wildcard test below rejects it. The parser conflates `*` and `"*"`; the
  comparator still needs the weak flag.
- Leading spaces are skipped and trailing linear whitespace stripped per element; an empty element yields
  `null`.
- `Tag.parse` strips a leading `W/`, then accepts `"…"` (name = the inner text, `W/` recorded as the weak
  flag) or `*`, and otherwise **logs a warning and returns `null`** — no exception, which is why garbage
  vanishes silently.
- `addValues` → `canAdd` drops `null`s **and duplicates**, and its loop catches only `IOException`. So one
  garbage member does not poison the rest of a list, and an all-garbage header leaves an empty list. The
  duplicate test is `Collection.contains`, i.e. the weakness-checked `Tag.equals(Object)`, so `"x"` and
  `W/"x"` both survive in one list.
- ⚠ **A lone `"` throws.** `startsWith("\"") && endsWith("\"")` is true for the single character `"`, so
  `Tag.parse` does `substring(1, 0)` → `StringIndexOutOfBoundsException`, which is **not** an `IOException`
  and so escapes `addValues`. Unmeasured; presumed to surface as a 500. `HttpConditions` deliberately drops it
  as invalid instead of reproducing the crash (decided 2026-07-29).

<a id="21b-comparator"></a>
#### …and the comparator, which is a *different* class (disassembled 2026-07-29, after the first cut of `HttpConditions` got it wrong)

The parser above says how a header becomes a `List<Tag>`. What that list *means* is `Conditions.getStatus`,
and reading only the parser is how S1 shipped two divergences that its 21 rows all passed. Three facts, none
of them derivable from `Tag.parse` and none covered by the measured table:

```java
// Conditions.getStatus(Method, boolean entityExists, Tag actualTag, Date modificationDate)
boolean all = getMatch().size() > 0 && getMatch().get(0).equals(Tag.ALL);   // 1-arg equals => weakness checked
if (entityExists) {
    if (!all && actualTag != null) {
        for (Tag t : getMatch())    matched = t.equals(actualTag, false);              // If-Match: names only
    } else  matched = all;
} else { failed = all; }
...
for (Tag t : getNoneMatch())        matched = t.equals(actualTag, GET.equals(m) || HEAD.equals(m));
```

- ⚠ **The wildcard is positional.** `all` is computed from `get(0)` alone, so `If-Match: "stale", *` is *not*
  a wildcard — the fallback loop then compares names, and no real tag is named `*`, so it **412**s. An
  implementation asking "does the list contain `*`" silently applies an update Restlet refuses.
- ⚠ **The wildcard is strong-only.** `Tag.ALL` is `Tag.parse("*")` (weak = false) and `Tag.equals(Object)` is
  `equals(o, /* checkWeakness */ true)`, so `If-Match: W/*` fails the test and then fails the name loop too.
- ⚠ **`If-None-Match` compares weakness; `If-Match` does not.** The second argument is
  `GET.equals(method) || HEAD.equals(method)`. `/oauth2/resource_set` answers a *weak* `ETag`, so on a `GET`
  `If-None-Match: "<name>"` (the strong form) gets **200 and the full body**, not a 304; only the verbatim
  `W/"<name>"` produces the 304 that [§21a](#21a)'s table records.
  ⚠ **This bullet claimed until 2026-07-29 that GET/HEAD are the only verbs reaching the `noneMatch` branch,
  so that the flag is "in practice always `true`". Both halves are wrong, and they were measured wrong**
  ([phase-5c row 18](phase-5c-asbuilt.md#as-built-5-e4-rows-18-21), row 21): `doConditionalHandle` guards **every**
  verb, so a `PUT`/`DELETE`/`POST` reaches the comparison too — with the flag `false`, i.e. **names only**. So
  the strong form of this endpoint's weak tag is a **200 on a `GET` and a 412 on a `PUT`**, and any
  reimplementation needs the flag as a *parameter*, not a constant.
- The `noneMatch` wildcard is `Tag.ALL.equals(getNoneMatch().get(0))` reached **only when `actualTag` is
  `null`** — which is the mechanism behind the measured "`If-None-Match: *` answers 200": with a real tag
  present, that branch is unreachable and `*` falls through to the name comparison.
- `If-Modified-Since` also participates, but only where `modificationDate != null`; this endpoint sets a tag
  and no modification date, so every date branch collapses to "not modified-since" and no 304 comes from it.

**`HEAD` and `PATCH` are dispatched through other methods' annotations.** `HEAD` is rewritten to `GET` before
the annotation lookup (§22 records the CHF side), and — measured, not disassembled — **`PATCH` reaches the
`@Put` method**: on `/oauth2/resource_set` a `PATCH` performs a full replace and answers 200. A verb Restlet
has no mapping for at all (`OPTIONS`, `PROPFIND`, `LOCK`, `COPY`) is the one that gets the framework 405, with
`Allow: POST, PUT, GET, DELETE`. `Endpoints.from` maps `{DELETE, GET, POST, PUT}` and nothing else, so both
`HEAD` and `PATCH` become 405s at a port.

## 22. CHF URI-template matching — trailing slashes, variables, and `HEAD` (Phase 5c review)

Read from commons `org.forgerock.http.routing.UriRouteMatcher`
(`../commons/commons/http-framework/core`) on 2026-07-29 while reviewing [Phase 5c](phase-5c.md). These decide
what a `newHttpRoute` / `addRoute` template can and cannot express, so check them **before** transcribing a
Restlet `router.attach` table.

- **A template's trailing slash is stripped; the request URI's is not.** `UriTemplateParser.createRegex`
  (`:194`) starts with `removeTrailingSlash(removeLeadingSlash(uriTemplate))`, so `EQUALS "foo/"` and
  `EQUALS "foo"` compile to the **same** regex. But `evaluate` (`:94-119`) matches
  `joinPath(getPathElements(uri))`, and `Paths.getPathElements` splits with `split(rawPath, -1)` — limit `-1`
  **keeps trailing empty elements** — so the URI `foo/` stays `"foo/"`. ⇒ **`EQUALS "foo/"` matches nothing,
  and no `EQUALS` template matches a request path ending in `/`.** A Restlet router that attached `/foo` and
  `/foo/` separately cannot be transcribed route-for-route.
- **A template variable compiles to `([^/]+)`** (`:212`) — it never matches an empty segment, so
  `EQUALS "foo/{id}"` does **not** cover `foo/`.
- **`EQUALS ""` compiles to `(\Q\E)` and matches an empty remaining URI.** Combined with a
  `STARTS_WITH "foo"` parent (regex `(\Qfoo\E)(/(.*))?`, remaining `""` for both `foo` and `foo/`), a nested
  router expresses the whole `foo` / `foo/` / `foo/{id}` family — the fix [phase-5c D9](phase-5c.md#d9) uses.
- **Nested `UriRouterContext`s compose.** `ChfOAuth2Request.attributes()` merges the template variables of
  every `UriRouterContext` in the chain, so a variable bound by a child router is still visible to
  `getParameter`/`getAttribute`.
- ⚠ **Restlet's `Router.attach` picks its matching mode *from the target*, not from the router's default —
  so "is this route exact?" is a per-row question when transcribing a `router.attach` table.** Disassembled
  from the fork 2026-07-30 and **corrected during 5d-1's review** (the first reading claimed the mode was
  always `EQUALS`, which cannot be true: `/oauth2/realms/root/.well-known/openid-configuration` is green in
  e2e today and an `EQUALS` `/realms/{realmId}` could never match it). What the bytecode actually says:
  - `Router()` sets `defaultMatchingMode = 2` (`Template.MODE_EQUALS`), and `Template.match` uses
    `Matcher.matches()` — a whole-string match — for that mode (`lookingAt()` is the `MODE_STARTS_WITH`
    branch);
  - but `attach(String, Restlet)` calls **`getMatchingMode(target)`**, which returns `1`
    (`MODE_STARTS_WITH`) when the target is a `Router` **or** a `Directory`, **recurses through
    `Filter.getNext()`** when the target is a `Filter`, and only otherwise falls back to the default.

  ⇒ read each attachment's target before concluding anything. In `OAuth2RouterProvider`:
  `/realms/{realmId}` targets a `RestletRealmRouter` ⇒ **STARTS_WITH**; every endpoint row targets
  `OAuth2AccessAuditFilter → (endpoint filter) → RestletUtils.wrap(...)`, which is a **`Finder`**, so the
  recursion bottoms out at a non-router ⇒ **EQUALS**. That is why `OAuth2RouterProvider:131-133` attaches
  `resource_set` three times and no other endpoint twice, and why a flat CHF `EQUALS` table is the right
  transcription for the other 14 — but the conclusion comes from the *targets*, not from the default mode.
- ⚠ **`HEAD` is not routed.** `Endpoints.from` builds its verb map from `{DELETE, GET, POST, PUT}`
  (`Endpoints.java:60-63`), so `HEAD` takes the unmapped-verb branch and answers **405** — while Restlet's
  `ServerResource.doHandle(Method, Form, Representation)` rewrites `HEAD` → `GET` before annotation lookup and
  answers **200 with no body**. This affects **every** endpoint this migration ports that has a `@Get`, not
  just the one that found it; the fix is two lines
  ([phase-5c C3](phase-5c.md#framework-items-openam-http-is-ours)) and the decision belongs to 5d-1.

## 23. Route-provider mechanics — when handlers are built, and what a no-match answers (Phase 5d-1)

Read from `openam-http` and commons `http-framework/core` on 2026-07-30 while planning
[Phase 5d-1](phase-5d-1.md). These are the facts a phase needs *before* it writes an `HttpRouteProvider`, and
none of them is visible from the provider's own source.

- ⚠ **`Endpoints.from(Class)` builds the endpoint instance when the route is built, not per request.**
  `Endpoints.java:97-109` resolves through `InjectorHolder.getInstance(key)` at `from(...)` time, and
  `HttpRouterProvider.get()` (`:46-56`) calls **every** registered `HttpRouteProvider` while assembling the
  **single** `Router` behind the one `OpenAM` `HttpFrameworkServlet`. ⇒ a Guice failure constructing *any*
  endpoint of *any* provider aborts the router that also serves `/json`, `/xui`'s REST calls, `/xacml`,
  `/uma` and `/rest-sts`. The observable failure is *"the admin console is down"*, not *"my endpoint 500s"*,
  and it happens as soon as the provider is on the classpath — a `META-INF/services` line is a production
  change even when the servlet mapping has not moved.
- **The lazy alternative is a trap.** `HttpRoute.newHttpRoute(mode, template, Provider<Handler>)` exists, but
  `HttpRoute.getHandler():213-216` calls `handler.get()` **inside `handle`** — i.e. per request. Using it to
  defer construction rebuilds the whole route subtree on every request. `GuiceHandler` (package-private,
  keyed on a bound `Handler`) is the framework's own lazy-once idiom; there is no lazy-once form for an
  annotated POJO.
- **A router with no matching route answers a *bodiless* 404.** Commons `Router.handle`
  (`routing/Router.java:96-104`) returns `newNotFound()` — status only, no entity. Any error filter that
  guards on `Content-Type` before parsing (as `OAuth2ErrorFilter` and `XacmlXmlErrorFilter` do) therefore
  passes it straight through. If an application's contract is "every error has a parseable body", the router
  needs a `setDefaultRoute(...)`; a filter cannot fill in what has no type.
- **`RealmContextFilter` never 404s an unknown path element.** `evaluate` (`:208-278`) greedily consumes
  leading elements that resolve as realms or realm aliases, and **breaks out of the loop** on the first that
  does not (`:239-248`, `catch (InternalServerErrorException ignored)`), leaving it in the remaining URI for
  the router. A `?realm=` override **replaces** the resolved realm rather than appending, and a bad realm —
  resolved or overridden — is a `BadRequestException` (**400**, `:255-257`/`:263-276`), never a 404. This is
  why the legacy `/<prefix>/<subrealm>/<endpoint>` style keeps working without any route entry, and why
  Restlet's *"No mapping organization found for organization identifier: …"* 404 has **no CHF counterpart**.
  `filter:85-93` is what turns those exceptions into responses: `BadRequestException` → **400**, every other
  `ResourceException` → **500**, both CREST-shaped.
- ⚠ **The realm pair validates the request's `Host`, and a Restlet application may not have.** Two separate
  checks, on two different branches, and neither runs on both:
  - non-`realms/` (the `RealmContextFilter` default route): `coreWrapper.isValidFQDN(host)` (`:229-231`) →
    **400** *"FQDN … is not valid."*. This is a literal membership test on the configured FQDN map
    (`FqdnValidator:99-101`, `fqdnMap.values().contains(host.toLowerCase())`) — being a realm alias is not
    enough;
  - `realms/{realmId}`: `HostnameFilter` (`RealmRoutingFactory:123-131`) resolves `Realm.of(host)` and
    answers **400** if it throws. No FQDN-map test. `RealmContextFilter` then short-circuits on the recursion
    (`:225-227`, a `RealmContext` is already present), so the FQDN check **never** runs on this branch.

  ⇒ moving a surface onto the CHF realm pair can start rejecting requests that a proxy or ingress used to
  deliver under an unrewritten `Host`. `/json` has always behaved this way, so it reads as normal until the
  first port of a surface that did not — and no e2e suite can see it, because the suite always uses the
  container's own hostname.
- **Realm-layer failures do not all share a status.** With the pair mounted, a routing failure can be a **404**
  (`ChfRealmRouter:146-154`, unknown `realms/{realmId}` — message `Realm "x" not found`), a **400**
  (bad `?realm=`, bad host, invalid FQDN), a **500** (an `IdRepo`/SSO failure inside the alias lookup) or a
  **bodiless 404** (no route matched). An error filter keyed on status must map all four deliberately.
- **`@Named("InvalidRealmNames")` is a realm-*creation* guard, not a router input.** It is read by
  `OrganizationConfigManager:522` and the `/json` route builders; `RealmContextFilter` does not consult it.
  Registering an endpoint segment stops an administrator creating a realm that would shadow the endpoint
  through the greedy consumption above. Register the **first** path segment (`connect`, not
  `connect/register`), or one realm name shadows several endpoints at once.
- **There are two 405 producers in `openam-http`, and only one of them knows the verb map.**
  `Endpoints.java:67-77` handles a verb that is not a map key (`PATCH`, `HEAD`, `OPTIONS`, …);
  `AnnotatedMethod.java:93-98` handles a verb that *is* mapped but whose endpoint declares no such method
  (the null-method sentinel). Both emit the same CREST body and — until [5d-1a's F5](phase-5d-1.md#d4) — neither emits `Allow`. Anything that has to be true of *every* 405
  belongs in `Endpoints.from`, which is the only place the supported-verb set exists.
- **`Endpoints` honours `X-HTTP-Method-Override` on a POST** (`getMethod:119-126`). Restlet's equivalent
  (`TunnelService`) is configured separately, so a port can silently gain or lose method tunnelling — worth a
  recorded row wherever the endpoint is security-relevant.
- **The global CHF chain adds filters no Restlet application had.** `OpenAMHttpApplication.start():68-80`
  wraps the router in a runtime-exception logger, `ApiDescriptorFilter` and `OpenApiRequestFilter` — the last
  two react to `?_api` / `?_crestapi`. Any path moved onto the `OpenAM` servlet inherits them.
- **Servlet mapping precedence still decides who serves what.** An exact `<url-pattern>` (e.g.
  `/oauth2/connect/checkSession`) out-ranks a path mapping (`/oauth2/*`) regardless of which servlet owns the
  prefix, so a JSP that shadows an endpoint today keeps shadowing it after a flip; an extension mapping
  (`*.jsp`) loses to a path mapping and does not.
