# Phase 3c-2 — Error layer (`OAuth2Error`, `RedirectUris`, `OAuth2ErrorResponseFactory`, `OAuth2ErrorFilter`)

Detailed execution plan for **sub-phase 3c-2** of the Restlet → CHF migration. Parent tracker:
[plan.md](plan.md) (Phase 3); research & sizing: [phase-3-research.md](phase-3-research.md); reusable CHF
patterns: [chf-patterns.md](chf-patterns.md); predecessors: [phase-3a-oauth2request.md](phase-3a-oauth2request.md),
[phase-3b-collaborators.md](phase-3b-collaborators.md), **[phase-3c-1-renderer.md](phase-3c-1-renderer.md)**;
test layers: [docs/test-infrastructure.md](../../test-infrastructure.md). Written 2026-07-17; branch
`features/restlet-migration`. All facts below were verified against the tree and jar bytecode on 2026-07-17.

## Context

**Depends on 3c-1** — the error factory's HTML branch renders `page/error.ftl` through
`FreemarkerTemplateRenderer`. Read [phase-3c-1-renderer.md](phase-3c-1-renderer.md)'s Context first; the
build-ahead framing (no live guard, build the oracle while Restlet can still be one) applies identically here.

**Outcome:** the CHF replacements for `ExceptionHandler` + `OAuth2RestletException`, plus a shared redirect
composer that Phase 5b's *success* path reuses, plus a filter that unifies the OAuth2 provider's error shape.
Wired to no route until Phase 5.

## Scope & sizing (decided)

**Four new classes + five test classes + one e2e spec.** ~450 LOC main, ~1000 LOC test.

- **Package `org.openidentityplatform.openam.oauth2.http`** per [decisions.md](decisions.md) — CDDL header,
  `Copyright 2026 3A Systems LLC.`, **no `@since`**.
- **No pom change** — http-framework `core` 3.1.1 is already a direct compile dep
  (`openam-oauth2/pom.xml:61-64`); `Promise`/`Promises`/`NeverThrowsException` and
  `org.forgerock.services.context.Context` arrive transitively from commons `util`. testng/mockito/assertj are
  already test-scoped.
- **Adds no Guice bindings** — both `@Singleton`s JIT-bind (concrete classes, `@Inject` ctors). 3b's
  binding-guard concern does not recur, and openam-oauth2 stays free of `commons.guice:test`.
- **Deletes nothing.** `ExceptionHandler`, `OAuth2RestletException`, `OAuth2Representation`,
  `JSONRestStatusService` and `OAuth2Filter` die in Phase 5.

## Key research findings (drove this plan)

### 1. `ExceptionHandler`'s decision core — the spec for `toResponse`

`ExceptionHandler.handle(OAuth2RestletException, Context, Request, Response)` (`:111-138`), three **ordered**
branches:

**(a) 307 → 301, `:113-117`**
```java
if (exception.getStatus().equals(Status.REDIRECTION_TEMPORARY)) {
    Redirector redirector = new Redirector(new Context(), exception.getRedirectUri(),
            Redirector.MODE_CLIENT_PERMANENT);
    redirector.handle(request, response); return;
}
```
- Restlet's `Status.equals` compares **code only** (bytecode-verified) ⇒ this is `code == 307`.
- `MODE_CLIENT_PERMANENT` (1) → `Response.redirectPermanent()` → **`REDIRECTION_PERMANENT` = 301**.
  **So a 307 exception emits 301 on the wire.** Sole producer: `ResourceOwnerAuthenticationRequired` (307,
  `redirection_temporary`) → the login-page redirect is emitted as a cacheable 301.
- `asMap()` is **not** applied — no error params, no `state`. The target is the raw redirect URI.

**(b) redirectUri present → 302, `:119-132`**
```java
response.setStatus(exception.getStatus());                              // :119 — DEAD on this branch
if (!isEmpty(exception.getRedirectUri())) {
    Reference ref = new Reference(exception.getRedirectUri());
    if (UrlLocation.FRAGMENT.equals(exception.getParameterLocation())) {
        ref.setFragment(representation.toForm(exception.asMap()).getQueryString());   // REPLACES the fragment
    } else {
        ref.addQueryParameters(representation.toForm(exception.asMap()));             // APPENDS to the query
    }
    new Redirector(context, ref.toString(), Redirector.MODE_CLIENT_FOUND).handle(request, response);
    return;
}
```
- `MODE_CLIENT_FOUND` (2) → `redirectFound` → **302**, **overwriting the status set at `:119`**. Do not
  reproduce the dead write.
- FRAGMENT **replaces** any existing fragment; QUERY **appends**, preserving existing query params.

**(c) fallback → HTML `page/error.ftl`, `:133-137`** — status from `:119`; data model = `asMap()` + `realm`
(from `requestFactory.create(request).getParameter("realm")`) + `baseUrl` (from
`baseURLProviderFactory.get(realm).getRootURL(ServletUtils.getRequest(request))`). Note `:137` calls the
package-private 4-arg overload with display hardcoded `"page"` — **preserve that** (there is no
`error.ftl` outside `page/`; see [3c-1 finding 8](phase-3c-1-renderer.md#8-template-inventory--data-model-keys-verified-by-interpolation-scan)).

**The JSON entry point is separate:** `handle(Throwable, Response)` (`:150-158`) — no redirect logic at all;
body = `asMap()` as JSON via `jacksonRepresentationFactory`. It `LOGGER.warn`s **every** error including 4xx,
with a stack trace — i.e. a client typo logs at WARN.

**Overload asymmetry to note:** `handle(Throwable, Context, Request, Response)` (`:82-93`) checks **only**
`throwable.getCause() instanceof OAuth2RestletException`; `toOAuth2RestletException` (`:160-176`) checks the
throwable **itself** first, then the cause, then `getCause() instanceof OAuth2Exception` (**dropping
`parameterLocation` and `redirectUri`**), else wraps in `ServerException`.

### 2. `OAuth2RestletException.asMap()` — the error-shape contract

`:163-176`:
```java
final Map<String, String> map = new HashMap<String, String>();
map.put("error", getError());
if (!isEmpty(getErrorDescription())) { map.put("error_description", getErrorDescription()); }
if (!isEmpty(getErrorUri()))         { map.put("error_uri", getErrorUri()); }
if (!isEmpty(getState()))            { map.put("state", getState()); }
```
- It is a **`HashMap`**, so serialized field order is hash order, **not** insertion order.
  [plan.md](plan.md)'s "Preserves `asMap()` field order" is a **false premise** — there is no *designed* order
  to preserve. Nuance: HashMap order is **deterministic for a fixed key set** (a pure function of
  `String.hashCode`), so today's output is *stable but arbitrary*, and a golden file would reproduce it.
- **`error_uri` is never populated in production** — `setErrorUri` has zero callers. Keep the shape; ship no
  populator.
- **Ctor trap:** the 4-arg `(int, String error, String description, String state)` (`:49-51`) has **`state`**
  as its last parameter and sets `redirectUri = null` — it is the *"do not redirect"* ctor. The 5-arg form is
  `(int, error, description, redirectUri, state)` (`:63-65`). This is the trap `OAuth2Error` kills.
- `getStatus()` (`:145`) → `new Status(statusCode)` — the Restlet `Status` to re-type to
  `org.forgerock.http.protocol.Status`.

### 3. ⚠ `ServerException` = **400**, not 500

`ServerException.java:39` → `super(400, "server_error", message)`; `ServerException(Throwable)` (`:47`) →
`this(cause.getMessage())`. So **every unmapped `Throwable` reaching `ExceptionHandler` exits as HTTP 400
`server_error`**. This is the single most surprising fact in the error layer.

### 4. ⚠ GET and POST have **different** no-redirect sets — and POST has an open redirect

"Do not auto-redirect on invalid redirect_uri" has **no flag, no predicate, no marker interface**. It is
implemented *purely* by which `OAuth2RestletException` constructor each catch block picks — and therefore by
**catch-clause ordering**.

`AuthorizeResource` GET (`:120-149`) catches: `IllegalArgumentException`(msg `.contains("client_id")`),
`ResourceOwnerAuthenticationRequired`, `ResourceOwnerConsentRequired`, `InvalidClientException`,
`RedirectUriMismatchException`, `DuplicateRequestParameterException`, **`OAuth2ProviderNotFoundException`**,
then generic `OAuth2Exception`.
POST (`:186-208`) catches: `ResourceOwnerAuthenticationRequired`, `InvalidClientException`,
`RedirectUriMismatchException`, `DuplicateRequestParameterException`, **`CsrfException`**, then generic
`OAuth2Exception`. **No `OAuth2ProviderNotFoundException` catch. No `IllegalArgumentException` catch.**

The generic branch passes the **unvalidated, client-supplied** `request.getParameter("redirect_uri")`:
```java
} catch (OAuth2Exception e) {
    throw new OAuth2RestletException(e.getStatusCode(), e.getError(), e.getMessage(),
            request.<String>getParameter("redirect_uri"), request.<String>getParameter("state"),
            e.getParameterLocation());
}
```

⇒ **`OAuth2ProviderNotFoundException` does not redirect on GET but does on POST.** That is not a designed
contract; it is two independently-maintained catch lists that drifted. And it is an **open redirect**: no
provider ⇒ `redirect_uri` was never validated. This is the concrete case that makes `isRedirectable` worth
having.

> **Correction to an earlier draft.** `RelativeRedirectUriException` and `InvalidRedirectUri` were believed to
> be a gap where they "fall to the generic branch and DO redirect". **They do not.**
> `RelativeRedirectUriException` is thrown only at `EndSession:149`, and `EndSession:117-119` uses the
> **JSON** overload; `InvalidRedirectUri` (`org.forgerock.openidconnect.exceptions`, *not*
> `oauth2.core.exceptions`) is thrown only at `OpenIdConnectClientRegistrationService:246`, and
> `ConnectClientRegistration:132-134` also uses the JSON overload. Neither is in `AuthorizationService.authorize`'s
> `throws` clause, so neither can reach `AuthorizeResource`'s catches. The real exposure is the set that *is*
> in that `throws` clause with no dedicated catch — `UnsupportedResponseTypeException`, `InvalidRequestException`,
> `AccessDeniedException`, `ServerException`, `LoginRequiredException`, `BadRequestException`,
> `InteractionRequiredException`, `ResourceOwnerConsentRequiredException`, `InvalidScopeException`, and
> **`NotFoundException`** (the sharpest).

### 5. The `OAuth2Exception` hierarchy — status + error name (Phase 5 reference)

`OAuth2Exception` (abstract, `org.forgerock.oauth2.core.exceptions`, `:26`) has `statusCode`, `error`,
`parameterLocation` (defaulting to `UrlLocation.QUERY`). **There is no `asMap()`, no `toJsonValue()`, no
`getDescription()`** — the description is only `getMessage()`, and serialization exists *only* on
`OAuth2RestletException`. The core hierarchy is presentation-free; **status is a hardcoded constructor literal
per subclass, with no mapping table.**

| Class | Status | `error` |
|---|---|---|
| `AccessDeniedException` | 400 | `access_denied` |
| `AuthorizationDeclinedException` | 403 | `authorization_declined` |
| `AuthorizationPendingException` | 400 | `authorization_pending` |
| `BadRequestException` | 400 | `bad_request` |
| `CsrfException` | 400 | `bad_request` — **description `null`** |
| `DuplicateRequestParameterException` | 400 | `invalid_request` |
| `ExpiredTokenException` | 401 | `expired_token` |
| `InsufficientScopeException` | 403 | `insufficient_scope` |
| `InteractionRequiredException` | 400 | `interaction_required` |
| `InvalidClientException` | 400 | `invalid_client` — **package-private ctors**; built via `ClientAuthenticationFailureFactory` |
| `InvalidClientAuthZHeaderException` | **401** | `invalid_client` — extends `InvalidClientException`; adds `getChallengeScheme()`/`getChallengeRealm()` |
| `InvalidCodeException` | 400 | `invalid_code` |
| `InvalidGrantException` | 400 | `invalid_grant` |
| `InvalidRequestException` | 400 | `invalid_request` |
| `InvalidScopeException` | 400 | `invalid_scope` |
| `InvalidTokenException` | 401 | `invalid_token` |
| `LoginRequiredException` | 400 | `login_required` |
| `NotFoundException` | 404 | `not_found` |
| `OAuth2ProviderNotFoundException` | 404 | `not_found` — extends `NotFoundException` |
| `RedirectUriMismatchException` | 400 | `redirect_uri_mismatch` |
| `RelativeRedirectUriException` | 400 | `relative_redirect_uri` |
| `ResourceOwnerAuthenticationRequired` | **307** | `redirection_temporary` — carries `URI redirectUri` |
| `ResourceOwnerConsentRequiredException` | 400 | `consent_required` |
| `ServerException` | **400** | `server_error` |
| `UnauthorizedClientException` | 400 | `unauthorized_client` |
| `UnsupportedGrantTypeException` | 400 | `unsupported_grant_type` |
| `UnsupportedResponseTypeException` | 400 | `unsupported_response_type` |
| `InvalidClientMetadata` (openidconnect) | 400 | `invalid_client_metadata` |
| `InvalidPostLogoutRedirectUri` (openidconnect) | 400 | `invalid_post_logout_redirect_uris` |
| `InvalidRedirectUri` (openidconnect) | 400 | `invalid_redirect_uri` |
| `UmaException` (openam-uma) | caller | caller — adds `JsonValue detail` |

**`ResourceOwnerConsentRequired` extends `Exception`, not `OAuth2Exception`** — it is a control-flow signal to
render `authorize.ftl`, never an error. **Do not sweep it into the error mapper.**

### 6. ⚠ Three incompatible error shapes on the same endpoints

| Shape | Producer | Body |
|---|---|---|
| OAuth2 (**handled**) | `ExceptionHandler` → `asMap()` | `{error, error_description?, error_uri?, state?}` — HashMap order |
| CREST (**uncaught**) | `JSONRestStatusService` (openam-rest), installed by `OAuth2ServiceEndpointApplication:36` and `UMAServiceEndpointApplication:36` | `{code, reason, message, detail?, cause?}` — **LinkedHashMap, order guaranteed**; `message` is **HTML-escaped** |
| UMA (flattened) | `UmaExceptionHandler` | `{error, error_description}` + `detail.asMap()` **flattened into the top level**, able to overwrite `error` |

(A fourth exists but is Phase 6's: `OAuth2StatusService` → `{error: reasonPhrase, error_description: description}`,
installed **only** by `WebFinger:60`.)

⇒ The `/oauth2` app emits **two incompatible shapes on the same endpoints** depending on whether the error was
caught. Unifying them is `OAuth2ErrorFilter`'s purpose ([D4](#d4--error-shape-unification-fix)).

### 7. ⚠ The filter cannot catch — and `Endpoints.from`'s 500 has an **empty body**

[chf-patterns.md](chf-patterns.md) §2 said an uncaught `Throwable` yields `500 + InternalServerErrorException`
map. **That is only true for exceptions thrown *outside* the reflective call.** A handler method that *throws*
takes `AnnotatedMethod.java:90-94`:

```java
} catch (InvocationTargetException e) {
    DEBUG.warning("Could not invoke method: ", e);
    return newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR)
            .setCause(new IllegalStateException("Exception from invocation should be handled by promise", e)));
}
```

**No `setEntity`.** So: 500, **empty body**, cause set. `Endpoints.java:73-76`'s `catch (Throwable)` → CREST
map fires only for throwables escaping `AnnotatedMethod.invoke` itself — `parameter.getContext(context)`
(`:80-82`, *before* the try) or `responseAdapter.apply` (`:85`, inside the try but not among the two caught
types).

Consequence: `Entity.getJson()` on an empty entity **throws IOException**, so `XacmlXmlErrorFilter`'s
`catch (IOException) → return response` means an empty-bodied 500 **passes through unrewritten**. A filter
modelled naively on Phase 2 leaks a bare, bodiless 500.

**Two framework 405 bodies, not one:**

| Trigger | Status | Body `code` |
|---|---|---|
| Verb not in the `{GET,POST,PUT,DELETE}` map (HEAD/OPTIONS/PATCH) — `Endpoints.java:66-67` | 405 | **501** (`NotSupportedException`) |
| Verb *is* mapped but no annotated method — `AnnotatedMethod.java:71-75` | 405 | **405** (`ResourceException.getException(405, …)`) |

`findMethod` never returns `null` (`:120` returns a sentinel with `method == null`), so GET/POST/PUT/DELETE
always take the second path. Both must be in the filter's test matrix.

**`@ExceptionHandler` (openam-http) is dead code** — no `@Retention` (defaults to `CLASS`, invisible to
reflection), no `@Target`, **zero usages** (grep-confirmed), and neither `Endpoints` nor `AnnotatedMethod`
ever looks for it. It cannot solve 3c-2's problem. The Filter is the only lever. Flag for deletion in Phase 8.

### 8. ⚠ `BaseURLProvider`'s CHF-looking overload is unreachable from a filter

`BaseURLProviderFactory.get(String realm)` → `BaseURLProvider`, which has **two** `getRootURL` overloads:
`getRootURL(HttpServletRequest)` and `getRootURL(HttpContext)`. The `HttpContext` is
**`org.forgerock.json.resource.http.HttpContext`** — a **CREST** context, not a CHF one. Its `(Context, Request)`
ctor is **package-private** and is constructed at exactly one site: CREST's `HttpAdapter.java:767`.
`Endpoints.from` is openam-http's own annotation handler and never goes through `HttpAdapter`, so an
`Endpoints.from` route has **no `HttpContext` at any depth** — `context.asContext(HttpContext.class)` would
throw.

⇒ Use `getRootURL(HttpServletRequest)` via `ChfOAuth2Request.getHttpServletRequest()` (which reads
`AttributesContext` under `HttpServletRequest.class.getName()`, put there by `HttpFrameworkServlet`).
**Guard for null** — Grizzly/unit contexts have none. Precedent for carrying both shapes side by side:
`OAuth2UrisFactory:79-102`.

### 9. ⚠ Restlet's `Redirector` runs the redirect URI through a `Template`

`getTargetRef` builds `new Template(targetTemplate)` and calls `Template.format(request, response)` on **both**
the relative and absolute branches. So `{...}` sequences in a redirect URI are variable-substituted today —
and the generic catch (finding 4) feeds it the **unvalidated** `redirect_uri`. **Reproducing this would be
reproducing a URI-injection vector.** Diverge ([D11](#d11--redirectors--substitution-diverge)).

### 10. CHF `Form` is `LinkedHashMap`-backed — canonical ordering is free

`Form extends MultiValueMap<String,String>`, and `Form()` calls `super(new LinkedHashMap<>())`;
`toQueryString()` iterates `keySet()` ⇒ **insertion order**. Encoding differs from Restlet, though: CHF's
`Uris.urlEncodeQueryParameterNameOrValue` is RFC 3986 (`SAFE_URL_QUERY_CHARS`), while Restlet uses
`Reference`/`Form` encoding. **This is [plan.md](plan.md) risk #3**, and it is exactly what
[`RestletErrorParityTest`](#b-restleterrorparitytest--the-oracle) exists to pin.

## Work items

### 1. `OAuth2Error` — the neutral carrier

Replaces `OAuth2RestletException`. **A value type, not a `Throwable`.** `OAuth2RestletException extends
Exception` only because Restlet's `doCatch` required *throwing*; CHF handlers must **return** `Response`
objects — a thrown exception is swallowed into a bodiless 500 (finding 7). Making it a value type also kills
the ctor trap (finding 2).

```java
public final class OAuth2Error {
    // fields: statusCode, error, description, redirectUri, state, errorUri, parameterLocation
    public static OAuth2Error of(OAuth2Exception e);          // status/error/description/parameterLocation from e
    public static OAuth2Error of(int statusCode, String error, String description);
    public OAuth2Error withState(String state);
    public OAuth2Error withErrorUri(String errorUri);
    public OAuth2Error redirectingTo(String redirectUri, UrlLocation location);  // explicit opt-in
    public boolean isRedirectable();                          // redirectUri != null && !isEmpty
    public Map<String, String> asMap();                       // LinkedHashMap, canonical order
    public static boolean isRedirectable(OAuth2Exception e);  // the policy table
    // getters: getStatusCode/getError/getDescription/getRedirectUri/getState/getErrorUri/getParameterLocation
}
```

- `asMap()` — **`LinkedHashMap`**, canonical order `error`, `error_description`, `error_uri`, `state`; the
  three optional keys emitted only when `!isEmpty` (the identical predicate to `OAuth2RestletException.asMap()`,
  via `org.forgerock.oauth2.core.Utils.isEmpty`). Keep `errorUri` in the shape but ship **no populator**
  (finding 2). See [D1](#d1--asmap-field-order-fix).
- **`static boolean isRedirectable(OAuth2Exception)`** — the [D6](#d6--isredirectable-unified-to-the-safe-union-fix)
  fix. Encode as **data** what is today emergent from catch ordering:

  ```java
  private static final Set<Class<? extends OAuth2Exception>> NEVER_REDIRECT = Set.of(
      RedirectUriMismatchException.class, InvalidClientException.class,
      OAuth2ProviderNotFoundException.class, DuplicateRequestParameterException.class,
      CsrfException.class);
  ```
  **Unified to the union of GET's and POST's sets** (the safe side of finding 4). Must match on
  **assignability**, not identity, so `InvalidClientAuthZHeaderException` (extends `InvalidClientException`)
  and `OAuth2ProviderNotFoundException` (extends `NotFoundException`) resolve correctly. Every one of the ~30
  subclasses in finding 5 gets an explicit verdict in `OAuth2ErrorTest`, so **adding a subclass without
  deciding is a test failure** (R-3c.6).

  The `IllegalArgumentException`-`.contains("client_id")` case is *not* an `OAuth2Exception`; it stays a 5b
  handler concern.

This collapses `AuthorizeResource`'s 7 catch blocks into one in 5b:
```java
catch (OAuth2Exception e) {
    OAuth2Error err = OAuth2Error.of(e).withState(request.getParameter("state"));
    if (OAuth2Error.isRedirectable(e) && redirectUri != null) {
        err = err.redirectingTo(redirectUri, e.getParameterLocation());
    }
    return errorResponseFactory.toResponse(request, err);
}
```
`redirectingTo` being an **explicit opt-in** is the point: redirecting becomes something you *do*, not
something that happens because you picked the wrong constructor.

### 2. `RedirectUris` — shared fragment-vs-query composition

Two near-identical copies exist today:
- `ExceptionHandler:122-131` (**error**): `Reference` → FRAGMENT ? `setFragment(form.getQueryString())` :
  `addQueryParameters(form)` → `Redirector(MODE_CLIENT_FOUND)`.
- `OAuth2Representation.toRepresentation:148-173` (**success**): `Reference` → `isFragment()` ?
  `setFragment(...)` : `addQueryParameter` loop → `Redirector(MODE_CLIENT_FOUND)`.

```java
public final class RedirectUris {
    public static String compose(String redirectUri, Map<String, String> params, UrlLocation location);
}
```

Semantics to preserve exactly: **FRAGMENT replaces** any existing fragment; **QUERY appends**, preserving
existing query params; ordering from the `LinkedHashMap` input (finding 10).

**Do not port the dead de-dup guard.** `OAuth2Representation.toForm(Map):209-218` skips
`if (!result.contains(p))` — unreachable for a `Map` input (no duplicate keys possible). Note it; drop it.

3c-2 consumes it for the error path; **Phase 5b consumes it for the success path**, which makes 5b's
`toRepresentation` port a one-liner. This is the single highest-leverage class in 3c for the phases downstream.

### 3. `OAuth2ErrorResponseFactory`

```java
@Singleton
public class OAuth2ErrorResponseFactory {
    @Inject public OAuth2ErrorResponseFactory(FreemarkerTemplateRenderer renderer,
                                              BaseURLProviderFactory baseURLProviderFactory);

    public Response toResponse(OAuth2Request request, OAuth2Error error);   // the 3-branch dispatcher (5b's entry point)
    public Response toJsonResponse(OAuth2Error error);                      // 5a's entry point
    public Response toLoginRedirectResponse(String loginUri);               // 301 — the finding-1 quirk
    public Response toRedirectResponse(OAuth2Error error);                  // 302, fragment vs query
    @VisibleForTesting Response toHtmlErrorResponse(OAuth2Error error, String realm, String baseUrl);
}
```

`toResponse` mirrors finding 1's three **ordered** branches exactly:
1. `error.getStatusCode() == 307` → `toLoginRedirectResponse(error.getRedirectUri())` → **301 + `Location`**,
   no error params, no state.
2. `error.isRedirectable()` → `toRedirectResponse` → **302** + `Location: RedirectUris.compose(...)`.
   Do not reproduce the dead `:119` status write.
3. else → `toHtmlErrorResponse` with status = `error.getStatusCode()`, rendering `templates/page/error.ftl`
   (display hardcoded `"page"`, per finding 1c).

- `realm` ← `request.getParameter("realm")`, **defaulting to `"/"`** ([D9](#d9--null-realm--fix)).
- `baseUrl` ← `baseURLProviderFactory.get(realm).getRootURL(request.getHttpServletRequest())` — the
  **`HttpServletRequest`** overload, never `HttpContext` (finding 8). **Guard `getHttpServletRequest() == null`.**
- JSON: `response.setEntity(error.asMap())` → `setJson` sets `application/json; charset=UTF-8` natively ⇒
  **`JacksonRepresentationFactory` dies here**.
- HTML: via `FreemarkerTemplateRenderer.toHtmlResponse` — the
  [3c-1 finding-3 recipe](phase-3c-1-renderer.md#3--content-type-texthtml-charsetutf-8-is-implicit-today--and-chfs-default-is-iso-8859-1)
  (header first, then `getBytes(UTF_8)`).
- `toHtmlErrorResponse(error, realm, baseUrl)` is pure and `@VisibleForTesting` so the render tests need no
  `BaseURLProviderFactory` mock (it needs a `ServletContext`, which is why every existing test mocks it).
- **No `LOGGER.warn` on every error.** `ExceptionHandler:151-153` warns with a stack trace for *every* error
  including 4xx. Log **5xx at `warn`, 4xx at `debug`**. Zero client-observable change, and it is the
  difference between a usable and an unusable OAuth2 provider log.

### 4. `OAuth2ErrorFilter`

`implements Filter`; `filter()` chains `.then(Function<Response,Response,NeverThrowsException>)` onto
`next.handle(...)`; early-returns on `< 400`; **never fails a request**. `XacmlXmlErrorFilter`
(openam-entitlements) is the model, and its 102-line test is the scaffold.

**It cannot catch** (finding 7) — it rewrites responses. Contract:

| Input (status ≥ 400) | Action | Rationale |
|---|---|---|
| `Content-Type` not JSON (incl. **HTML**) | **untouched** | 5b's `page/error.ftl` 400 must survive. Guard on Content-Type **before** parsing |
| JSON map containing key `error` | **untouched** | already OAuth2-shaped → idempotent |
| JSON map containing key `code` (CREST) | rewrite → `{error, error_description}` | the framework 405/500 fallbacks (finding 7) |
| entity empty **and** `getCause() != null` | synthesize `{error: "server_error", error_description: …}` | the finding-7 gap; `getCause() != null` targets it precisely without clobbering a deliberate empty-body 4xx |
| anything else | untouched | unknown shape |

**Discriminating CREST from OAuth2 (both are `Map`s):** a CREST map is `{code, reason, message, detail?, cause?}`
and never has `error`; an OAuth2 map is `{error, error_description?, error_uri?, state?}` and never has `code`.
Check **`error` first** (idempotency), then `code`.

**Improvement over the Phase-2 model — guard on `Content-Type` before parsing.** `XacmlXmlErrorFilter` relies
on `getJson()` throwing `IOException` on a non-JSON body to fall through. That works, but only *by accident*,
and for 3c-2 the accident is load-bearing: it is the only thing standing between the filter and a destroyed
consent-error page. Make it explicit and cheap (`ContentTypeHeader.valueOf(response).getType()`), and test the
HTML case directly (R-3c.5).

CREST → OAuth2 mapping: `500 → server_error`, `405 → invalid_request`, other 4xx → `invalid_request`;
`error_description` ← the map's `message`.

## Decisions

<a id="d1--asmap-field-order-fix"></a>
### D1 — `asMap()` field order: **fix** (canonical)

Restlet's order is deterministic-but-arbitrary (finding 2). RFC 6749 does not order error params and every
client parses by name. CHF's `Form` is `LinkedHashMap`-backed (finding 10), so `error, error_description,
error_uri, state` is free. **Correct [plan.md](plan.md)'s "Preserves `asMap()` field order"** — a false premise.

<a id="d2--serverexception--400-on-the-contract-path-reproduce"></a>
### D2 — `ServerException` = 400 on the contract path: **reproduce**

`ServerException.java:39` hardcodes 400 + `server_error`, so every *handled* internal error exits 400 today
(finding 3). **Key point: `ServerException` is shared by both transports** — changing it is a one-line edit
that affects Restlet and CHF identically, and is therefore **not a migration concern at all**. Do it
separately, with its own test and release note. Bundling a status change into a migration is how migrations
get blamed for regressions. (RFC 6749 §5.2's intent is that `server_error` *is* the 500 case, so the fix is
probably right — just not here.)

<a id="d3--uncaught-bug-path-400-vs-500-diverge--keep-500"></a>
### D3 — Uncaught-bug path 400 vs 500: **diverge → keep 500** (signed off 2026-07-17)

Restlet's `doCatch` wraps *any* `Throwable` into `ServerException` → **400**. CHF's framework gives **500**.
**Keep 500**, because: (a) this path is by definition a **bug** — an exception the handler failed to catch —
and has no legitimate client contract; (b) [chf-patterns.md](chf-patterns.md) §2 already mandates that
handlers catch everything, so it should be unreachable in correct Phase-5 code; (c) reproducing 400 would mean
a filter that *downgrades* a 500, permanently masking server bugs from monitoring.

The **contractual** 400 ([D2](#d2--serverexception--400-on-the-contract-path-reproduce)) is preserved exactly.
This is the one status divergence. **Do not assert it in the e2e lock.**

<a id="d4--error-shape-unification-fix"></a>
### D4 — Error-shape unification: **fix**

The `/oauth2` app emits two incompatible shapes (finding 6). `OAuth2ErrorFilter` collapses them to one.
Deliberate; it is the class's purpose. This is a **unification, not parity**.

<a id="d6--isredirectable-unified-to-the-safe-union-fix"></a>
### D6 — `isRedirectable` unified to the safe union: **fix** (signed off 2026-07-17)

Finding 4: the policy is emergent from catch ordering, and GET/POST disagree —
`OAuth2ProviderNotFoundException` does **not** redirect on GET but **does** on POST. That asymmetry is drift,
not design, and the POST side is an **open redirect** (no provider ⇒ `redirect_uri` was never validated).
Unify to the union; encode as data; enumerate every subclass in the test.

⚠ **It changes POST behaviour** at the 5d flip: `POST /oauth2/authorize` against a realm with no OAuth2
provider will render the error page instead of redirecting. **Do not assert the current behaviour in the e2e
lock.**

<a id="d9--null-realm--fix"></a>
### D9 — Null realm → `"/"`: **fix**

`page/error.ftl` dereferences `${realm?js_string}` and `${baseUrl?js_string}` inside `<#if error??>`, and
`${baseUrl?html}` **outside any guard**, with no `!` default. FreeMarker treats a Java `null` as *missing* ⇒
`InvalidReferenceException`. `ExceptionHandler:134` feeds `requestFactory.create(request).getParameter("realm")`,
which **can** be null. Combined with `DEBUG_HANDLER`
([3c-1 finding 4](phase-3c-1-renderer.md#4--new-configuration-pins-incompatibleimprovements--230-and-bumping-it-is-behaviour-changing)),
that renders a **FreeMarker stack trace into the browser** today. Defaulting to `"/"` (what
`Realm.root().asPath()` returns) turns it into a working error page. 3c-1's `RETHROW_HANDLER` closes the
disclosure; D9 closes the trigger.

<a id="d11--redirectors--substitution-diverge"></a>
### D11 — `Redirector`'s `{}` substitution: **diverge** (verbatim `Location`)

Finding 9. Reproducing it would reproduce a URI-injection vector on an unvalidated `redirect_uri`. Set
`Location` verbatim; document it in the parity test.

## Tests

### A. Unit tests per class — table stakes

- **`OAuth2ErrorTest`** — `asMap()` order and omission (`error_uri` never emitted; optional keys gated on
  `isEmpty`); **`isRedirectable` enumerating all ~30 subclasses** of finding 5 (R-3c.6), incl. the
  assignability cases `InvalidClientAuthZHeaderException` and `OAuth2ProviderNotFoundException`.
- **`RedirectUrisTest`** — fragment **replaces** / query **appends** / existing query preserved / special
  chars.
- **`OAuth2ErrorResponseFactoryTest`** — all four modes; exact **301** / **302** / 4xx; null realm → `"/"`
  ([D9](#d9--null-realm--fix)); **null `HttpServletRequest`** guarded.
- **`OAuth2ErrorFilterTest`** — **`XacmlXmlErrorFilterTest` verbatim as the scaffold**: TestNG + AssertJ, no
  Mockito, no Guice, no `@BeforeMethod`; `Handler next = (ctx, req) -> Promises.newResultPromise(canned);` +
  `filter.filter(context, request, next).getOrThrowUninterruptibly()`. Cover every row of the contract table,
  especially **HTML untouched** and **idempotent on an OAuth2-shaped body**.

### B. `RestletErrorParityTest` — the oracle

**Feasibility verified** (bytecode): Restlet's `Redirector` modes 1/2 are pure in-memory —
`MODE_CLIENT_PERMANENT` → `Response.redirectPermanent(ref)` → `setLocationRef` + `setStatus(301)`;
`MODE_CLIENT_FOUND` → `setLocationRef` + `setStatus(302)`; `handle()` returns straight after the switch
(`headersCleaning` applies only to server-side modes 3–7). **No connector, no `Component`, no server** —
`new Redirector(new Context(), uri, mode).handle(new Request(...), new Response(request))` works in a plain
unit test.

Scope it **tightly** — A/B only where a claim is a *belief*, not an observation:

| Case | Asserts |
|---|---|
| auth-required | Restlet `Redirector(MODE_CLIENT_PERMANENT).handle(...)` → **301** + `Location`; factory → same |
| fragment vs query | incl. a `redirect_uri` that **already has** a query and/or a fragment |
| **error-param encoding** (risk #3) | space, `+`, `&`, `=`, unicode in `state`/`error_description`. Restlet `Reference`/`Form` vs CHF `Uris.urlEncodeQueryParameterNameOrValue` **genuinely differ** — the row most likely to fail |
| `{}` in the redirect URI | documents the [D11](#d11--redirectors--substitution-diverge) divergence |

`ExceptionHandler` needs 4 mockable collaborators; `ServletUtils.getRequest(plainRequest)` returns **null**,
so stub `baseURLProviderFactory.get(realm).getRootURL(null)`.

**No goldens here — rejected.** The maps are 2–4 fields and the redirect URLs are one-line strings.
`assertThat(body).containsExactly(entry("error","invalid_request"), entry("error_description","…"))` is more
precise, more readable and self-documenting than a file containing `{"error":"x"}`. Pure ceremony. (Goldens
*are* used for HTML — see [3c-1 §C](phase-3c-1-renderer.md#c-golden-files--yes-for-html).)

**Honest limitation: this test dies in 5d/8.** It is a development-time instrument.

### C. `OAuth2ErrorRouteCompositionIT` — in-process composition (**second-highest value**)

`openam-oauth2/src/test/java/org/openidentityplatform/openam/oauth2/http/OAuth2ErrorRouteCompositionIT.java`.

**The decisive argument:** [chf-patterns.md](chf-patterns.md) §2's account of the 500 path turned out to be
**wrong** (finding 7). A unit test with a canned `Response` **cannot** catch that class of error — the canned
response *encodes the author's belief about the framework*. Only real composition proves it. ~80 lines, **no
Guice, no container, no server**:

```java
Handler h = Handlers.chainOf(Endpoints.from(new TestHandler()), new OAuth2ErrorFilter());
Response r = h.handle(new RootContext(), new Request().setMethod("GET").setUri("/")).getOrThrowUninterruptibly();
```

Covers, and nothing else does: the **two** distinct 405 bodies (finding 7), the **empty-body 500** on a thrown
exception, and that the filter **does not clobber an HTML 400**.

> **Name trap:** `*IT.java` ⇒ **failsafe only**. `mvn -pl openam-oauth2 test` (verification step 1) will
> **not** run it — the single most surprising fact in
> [test-infrastructure.md](../../test-infrastructure.md). Step 1b below adds `verify`. `IT` is nonetheless the
> right layer (it tests composition with framework code), and CI runs `verify` on all 9 legs.

### D. Golden files — **rejected for this sub-phase**

See §B. HTML goldens live in [3c-1](phase-3c-1-renderer.md#c-golden-files--yes-for-html).

### E. e2e error contract lock

**It buys nothing for 3c-2's classes. Zero.** They are unrouted; no e2e request can reach them. What it buys
is a **live-oracle executable specification of the target contract**, recorded while Restlet still serves
`/oauth2`, that 5d must satisfy. That is real — but it is *5d's* test, written early because **the oracle
expires**.

**Rule that makes it a lock rather than a snapshot: every assertion must correspond to a row in the
[parity checklist](#parity-checklist) marked "reproduce".** Assert nothing 3c flags for change — otherwise 5d
has to *edit* the lock, at which point it was never a lock (R-3c.8).

**Assert** (frozen rows only): JSON error shape on `/oauth2/access_token` (bad `grant_type`; bad client secret
→ incl. `WWW-Authenticate: Basic`); **301 + `Location`** on unauthenticated `/oauth2/authorize`; **302** +
query-vs-fragment error composition on a valid `redirect_uri`; the HTML error page's
`Content-Type: text/html;charset=UTF-8`.

**Do not assert:** the uncaught-500 status ([D3](#d3--uncaught-bug-path-400-vs-500-diverge--keep-500)); POST's
redirecting `OAuth2ProviderNotFoundException` ([D6](#d6--isredirectable-unified-to-the-safe-union-fix));
`checkSession?display=popup` ([3c-1 D5](phase-3c-1-renderer.md#d5--popup-hardcoding-authorizeftl-fix)).

**Mechanics:** extend `e2e/oauth2/oauth2-test.spec.mjs`. Fixtures already exist (`test_client_app`, public +
PKCE, `redirect_uri http://app.invalid/cb`, scope `profile`, `isConsentImplied: true`), and CI runs specs
**unqualified** in `build-docker` (`.github/workflows/build.yml:306-307`), so additions need no wiring.
`maxRedirects: 0` + `expect(response.status()).toBe(N)` per 3b's precedent. **If a second identity is ever
authenticated, use a disposable `apiRequest.newContext()`** — the cookie-outranks-header trap that failed the
whole xacml suite on its first CI run.

> **Write it by observation, not prediction.** Run it against the live server **first** and record what it
> actually returns. If a row surprises you, that is the finding — exactly as 3b's characterization tests failed
> 3/4 against unmodified code. A spec that passes against Restlet today is a **verified oracle**; one written
> after the flip merely restates the new behaviour.

### Considered and rejected

- **Cargo/Selenium IT (layer 3)** — drives only the installer UI; Linux-only; fresh Tomcat per test method.
  Duplicates §E at far higher cost. [test-infrastructure.md](../../test-infrastructure.md): "layer 3 is rarely
  the answer".
- **A Guice binding guard** (3b's `OAuth2GuiceModuleTest` pattern) — **not applicable**: 3c-2 adds **no**
  bindings (both singletons JIT-bind).
- **Unwrapping `response.getCause()`** in the filter to recover the thrown exception (finding 7) —
  **rejected**. Technically possible and tempting, but it builds on an implementation detail of shared
  framework code whose own message calls the situation a bug ("Exception from invocation should be handled by
  promise"). The contract is that handlers catch their own exceptions; the filter is a **net, not a
  mechanism**. If `Endpoints.from`'s swallowing needs fixing, [chf-patterns.md](chf-patterns.md) §2 is right
  that it should be fixed **once in openam-http**, not worked around per-area.

## Verification

1. `mvn -o -pl openam-oauth2 install -DskipTests` → `mvn -o -pl openam-oauth2,openam-uma test`.
   **Baseline (3b as-built): openam-oauth2 716, openam-uma 192**, 0 failures/errors/skips. 3c is additive ⇒
   openam-uma must stay **exactly 192**.
1b. **`mvn -o -pl openam-oauth2 verify`** — **the only step that runs `OAuth2ErrorRouteCompositionIT`.**
   Step 1 cannot see it (failsafe is bound unconditionally at the root pom, `:1843-1856`; `mvn test` skips
   `*IT.java`).
2. `mvn install -DskipTests` (whole reactor). **Doclint is fatal** (`-Xdoclint:all,-missing` +
   `failOnWarnings`, commit `3c45ff8d53`), and four new classes with javadoc is exactly where a dangling
   `{@link}` lands. Non-negotiable.
3. Grep gates:
   - `grep -rn "org.restlet" openam-oauth2/src/main/java/org/openidentityplatform/openam/oauth2/http/ --include=*.java` → **0**
     (the parity *test* legitimately imports Restlet).
   - `grep -rn "getCurrent()" openam-oauth2/src/main --include=*.java | grep -v /restlet/ | grep -v RestletOAuth2Request.java` → still **0**.
   - No doc still **specifies** the pre-lock package: `grep -rln "org.forgerock.oauth2.http" docs/` must
     list only this file and [phase-3c-1-renderer.md](phase-3c-1-renderer.md), which *quote* it to record
     the correction. `plan.md` and `phase-3-research.md` were corrected 2026-07-17 and must not reappear.
4. **No route flip ⇒ no behaviour change expected anywhere.** The e2e lock (§E) must pass **against the
   unmodified live Restlet server** — that is what makes it an oracle. Run `npx playwright test oauth2` against
   a local container built from this tree (3b as-built #5's recipe: build the war, CI `build-docker` IDP
   recipe, OpenDJ + OpenAM containers, configurator, demo user).
5. CI: `build-maven` 9 legs run `verify` ⇒ the IT runs on all 9; `build-docker` runs the e2e specs.

## Parity checklist

| Item | Verdict | Guard |
|---|---|---|
| Auth-required → **301** (not 307) | reproduce | `RestletErrorParityTest` A/B; e2e lock |
| Error + `redirect_uri` → **302**, fragment replaces / query appends | reproduce | `RedirectUrisTest`; parity test with pre-existing query+fragment; e2e |
| Error-param **encoding** (risk #3) | **verify, don't assume** | parity test: space/`+`/`&`/`=`/unicode in `state`+`error_description` |
| JSON `{error, error_description, state?}` + status | reproduce | `OAuth2ErrorResponseFactoryTest`; e2e |
| `asMap()` field **order** | **fix** ([D1](#d1--asmap-field-order-fix)) | `OAuth2ErrorTest` asserts LinkedHashMap order |
| `error_uri` never emitted | reproduce | shape retained, no populator; `OAuth2ErrorTest` |
| Dead `:119` status write on the 302 branch | drop | `OAuth2ErrorResponseFactoryTest` asserts 302 |
| Error page display hardcoded `"page"` | reproduce | factory renders `templates/page/error.ftl` |
| `ServerException` = 400 (handled) | reproduce ([D2](#d2--serverexception--400-on-the-contract-path-reproduce)) | `OAuth2ErrorTest`; e2e |
| Uncaught bug path status | **diverge → 500** ([D3](#d3--uncaught-bug-path-400-vs-500-diverge--keep-500)) | `OAuth2ErrorRouteCompositionIT`; **not** asserted in e2e |
| Two framework 405 bodies (405 vs 501 `code`) | reproduce | `OAuth2ErrorRouteCompositionIT` (finding 7) |
| Empty-body 500 → `server_error` JSON | **fix** | `OAuth2ErrorRouteCompositionIT` (finding 7) |
| Filter must **not** clobber HTML 400 | new guard | `OAuth2ErrorFilterTest` + IT; Content-Type guard before parse |
| Filter idempotent on OAuth2-shaped bodies | new guard | `OAuth2ErrorFilterTest` |
| Two error shapes on one app | **fix → unify** ([D4](#d4--error-shape-unification-fix)) | `OAuth2ErrorFilterTest` |
| No-redirect policy | **fix → explicit union** ([D6](#d6--isredirectable-unified-to-the-safe-union-fix)) | `OAuth2ErrorTest` enumerates **all ~30** subclasses |
| `Redirector` `{}` substitution | **diverge** ([D11](#d11--redirectors--substitution-diverge)) | parity test documents it |
| Null realm | **fix → `"/"`** ([D9](#d9--null-realm--fix)) | factory test |
| WARN on every 4xx | fix → 5xx warn / 4xx debug | not client-observable |

**Recorded for Phase 5a, not 3c:** `OAuth2Filter.beforeHandle:58-80` catches `OAuth2RestletException` /
`InvalidRequestException`, writes the error entity inline, then **falls through to
`return super.beforeHandle(...)` → CONTINUE** — the request proceeds to the wrapped resource anyway and its
output overwrites the error. 3c ships no equivalent; **5a's `TokenEndpointHandler` must return, not continue**.
It also adds `Cache-Control: no-store` + `Pragma: no-cache` (`:76-77`), which 5a must reproduce.

**Recorded for Phase 5b:** `ConsentRequiredResource.getDataModel:75-108` seeds its map from
`new HashMap<>(getRequest().getAttributes())` (`:79`) then `putAll(getQuery().getValuesMap())` (`:80`) —
`realm`/`redirect_uri`/`scope`/`state`/`nonce`/`acr`/`response_type`/`client_id`/`ui_locales` arrive
**implicitly** and are never `put` explicitly. A CHF port must **enumerate them** or every `<#if x??>` silently
goes false and the consent page renders with a broken `pageData`.

## Execution order

1. `OAuth2Error` + `OAuth2ErrorTest` (incl. the all-subclasses `isRedirectable` enumeration).
2. `RedirectUris` + `RedirectUrisTest`.
3. `RestletErrorParityTest` — **the Restlet leg first**, so the encoding row (risk #3) tells you the truth
   before the CHF side is written to a belief.
4. `OAuth2ErrorResponseFactory` + test → close the parity test's CHF leg.
5. `OAuth2ErrorFilter` + `OAuth2ErrorFilterTest` (`XacmlXmlErrorFilterTest` as the scaffold).
6. **`OAuth2ErrorRouteCompositionIT` — write it in the same step as the filter**, not after. It is the only
   gate on the framework-composition beliefs, and finding 7 proves those beliefs are wrong more often than not.
7. `mvn -o -pl openam-oauth2 install -DskipTests` → `test` → **`verify`** → whole-reactor build → grep gates.
8. e2e lock spec → run against a local container **built from unmodified `/oauth2`**.
9. Correct [chf-patterns.md](chf-patterns.md) **§2** (finding 7: empty-body 500 + `setCause`; two 405 bodies;
   `Promise` return unimplemented; `@ExceptionHandler` dead) — wrong today, and every later phase reads it.
   Update [plan.md](plan.md) (drop "Preserves `asMap()` field order"; risk rows) and
   [decisions.md](decisions.md) (D3, D6). Mark 3c done and record an **As-built** section here.

## Risks (extends [plan.md](plan.md)'s register; shares R-3c.1/.2/.3 with [3c-1](phase-3c-1-renderer.md#risks-extends-planmds-register))

| # | Risk | Detail | Mitigation |
|---|---|---|---|
| **R-3c.5** | **Filter destroys the HTML error page** | 5b returns a 400 with an HTML body; a Phase-2-shaped filter survives only by `getJson()` *accidentally* throwing | Explicit Content-Type guard **before** parsing; direct test + IT row |
| **R-3c.6** | **`isRedirectable` drift** | A new `OAuth2Exception` subclass silently defaults to redirectable | `OAuth2ErrorTest` enumerates all ~30 subclasses ⇒ adding one without a verdict fails the build |
| **R-3c.8** | **The e2e lock locks the wrong thing** | Asserting a quirk 3c/5b intends to fix means 5d must edit the lock — at which point it was never a lock | Rule: every e2e assertion maps to a "reproduce" row in the parity checklist. Write by observation, not prediction |
| **R-3c.9** | **`OAuth2Error` re-grows a `Throwable`** | 5b may be tempted to `throw` it to a filter, re-importing the swallowing problem (finding 7) | `final` value type, no `Throwable` in the hierarchy; javadoc states the return-don't-throw contract |
| **R-3c.11** | **D3/D6 land silently at the 5d flip** | Both are invisible until the route moves, months later | Recorded in [decisions.md](decisions.md); excluded from the e2e lock **by design**, and listed in 5d's smoke matrix |
