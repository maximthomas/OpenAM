# Phase 3c-2 — Error layer (`OAuth2Error`, `RedirectUris`, `OAuth2ErrorResponseFactory`, `OAuth2ErrorFilter`)

Detailed execution plan for **sub-phase 3c-2** of the Restlet → CHF migration. Parent tracker:
[plan.md](plan.md) (Phase 3); research & sizing: [phase-3-research.md](phase-3-research.md); reusable CHF
patterns: [chf-patterns.md](chf-patterns.md); predecessors: [phase-3a-oauth2request.md](phase-3a-oauth2request.md),
[phase-3b-collaborators.md](phase-3b-collaborators.md), **[phase-3c-1-renderer.md](phase-3c-1-renderer.md)**;
test layers: [docs/test-infrastructure.md](../../test-infrastructure.md). Written 2026-07-17; branch
`features/restlet-migration`. All facts below were verified against the tree and jar bytecode on 2026-07-17.

> ### ✅ Prerequisite **landed 2026-07-22** — [openam-http-framework.md](openam-http-framework.md#as-built)
>
> This plan originally designed **around** three defects in `openam-http`'s endpoint framework. That was the
> wrong call: **`openam-http` is in-tree and we maintain it** (`openam-http/src/main/java/org/forgerock/openam/http/annotations/`),
> so the defects got fixed — all four, with 64 new tests in a package that had none.
> **F1** gives a handler-thrown exception a CREST response body; **F2** makes the long-dead
> `@ExceptionHandler` annotation real; **F3** implements the `Promise` return type; **F4** honours `@Produces`
> and makes a `String` return safe to encode.
>
> What that changes here, in one line each: `OAuth2ErrorFilter` loses its synthesize rule (F1 guarantees a
> body); R-3c.9 and R-3c.14 are retired; and 5b's handlers may `throw` the existing `OAuth2Exception`s into an
> `@ExceptionHandler` method instead of returning `Response`s by hand. **`OAuth2Error` itself is unchanged** —
> it is what that method builds. See the effect table in
> [openam-http-framework.md](openam-http-framework.md#effect-on-phase-3c-2). Sections below are annotated
> **F1**/**F2**/**F3** where the prerequisite changed them.
>
> **One as-built caveat worth carrying into 3c-2's design:** the framework's *own* failures are **not** offered
> to `@ExceptionHandler` — only what the annotated method itself threw. An `@ExceptionHandler(OAuth2Exception)`
> on an OAuth2 handler will therefore never see a context-resolution or plumbing failure, and those still
> arrive as the CREST 500 the filter's rules 2–5 handle. That is deliberate; see the
> [As-built](openam-http-framework.md#as-built).

> **Reviewed 2026-07-21.** Findings 1–5, 7 and 10 re-verified line-for-line against the tree and jar bytecode;
> the 31-class hierarchy table (finding 5) was independently re-enumerated and is complete. Six corrections
> folded in, most-material first:
> 1. **⛔ The work-item-1 collapse snippet emitted a 301 to the *client's* `redirect_uri`** for
>    `ResourceOwnerAuthenticationRequired` — an open redirect at an unauthenticated entry point, and the loss
>    of the login redirect. Fixed by [D13](#d13--resourceownerauthenticationrequired-carries-its-own-redirect-uri-carve-out): the login URI is
>    carried by `OAuth2Error.of`, and RoAR joins the never-redirect set so the generic opt-in cannot overwrite it.
> 2. **⚠ The filter's rule order defeated its own headline fix.** `Entity.setJson` is what writes
>    `Content-Type: application/json; charset=UTF-8` (bytecode-verified), so the finding-7 empty-body 500 —
>    which never calls `setEntity` — has **no `Content-Type` at all** and was swallowed by the Content-Type
>    guard the plan placed first. The empty-entity rule now runs **before** the guard (work item 4).
> 3. **New [D14](#d14--www-authenticate-carried-on-oauth2error-and-tested-in-every-phase)** — `WWW-Authenticate` was frozen in the §E e2e lock with nothing in 3c-2's API able to
>    reproduce it. It is now carried on `OAuth2Error` and asserted at **every** layer: unit, IT, e2e (finding 12).
> 4. Finding 4 under-described `AuthorizeResource:120-126`: the `IllegalArgumentException` catch has **two**
>    branches, and the non-`client_id` one redirects with the unvalidated `redirect_uri`.
> 5. `isRedirectable` named two different questions (instance = state, static = policy) →
>    `hasRedirectUri()` / `mayRedirect(OAuth2Exception)`.
> 6. Verification's test baseline was stale (716 is 3b's; **3c-1 as-built is 743**).

## Context

**Depends on 3c-1** — the error factory's HTML branch renders `page/error.ftl` through
`FreemarkerTemplateRenderer`. Read [phase-3c-1-renderer.md](phase-3c-1-renderer.md)'s Context first; the
build-ahead framing (no live guard, build the oracle while Restlet can still be one) applies identically here.

**Outcome:** the CHF replacements for `ExceptionHandler` + `OAuth2RestletException`, plus a shared redirect
composer that Phase 5b's *success* path reuses, plus a filter that unifies the OAuth2 provider's error shape.
Wired to no route until Phase 5.

## Scope & sizing (decided)

**Four new classes + six test classes + one e2e spec.** ~450 LOC main, ~1000 LOC test. (Six: four unit suites,
`RestletErrorParityTest`, and `OAuth2ErrorRouteCompositionIT` — the first draft's "five" omitted the IT.)

**Where the filter mounts is Phase 5's wiring, but its blast radius is decided here.** `OAuth2ErrorFilter`
is scoped to the whole `/oauth2` application — the same surface `OAuth2ServiceEndpointApplication:36`
installs `JSONRestStatusService` across today (the `OAuth2Router`), which is what makes finding 6's "two
shapes on the same endpoints" true and [D4](#d4--error-shape-unification-fix)'s unification meaningful. It is **not** to be reused for the
`/json` CREST endpoints, where the CREST shape *is* the contract.

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
- ⚠ **The redirect URI on this branch comes from the *exception*, not the request.**
  `ResourceOwnerAuthenticationRequired:28,45` carries its own `URI redirectUri` — the **login page** — and
  `AuthorizeResource:127-129` / `:187-189` have a dedicated catch for exactly that reason:
  `new OAuth2RestletException(…, e.getRedirectUri().toString(), null)`. Any design that feeds this branch the
  request's `redirect_uri` 301s the user agent to a **client-supplied, unvalidated** URI instead of the login
  page. See [D13](#d13--resourceownerauthenticationrequired-carries-its-own-redirect-uri-carve-out).

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

`AuthorizeResource` GET (`:120-149`) catches: `IllegalArgumentException`,
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

⚠ **The `IllegalArgumentException` catch has *two* branches, and only one of them is the `client_id` case**
(`AuthorizeResource:120-126`, corrected 2026-07-21 — an earlier draft wrote the catch as if it were guarded by
`.contains("client_id")`):

```java
} catch (IllegalArgumentException e) {
    if (e.getMessage().contains("client_id")) {
        throw new OAuth2RestletException(400, "invalid_request", e.getMessage(),
                request.<String>getParameter("state"));                              // no redirect
    }
    throw new OAuth2RestletException(400, "invalid_request", e.getMessage(),
            request.<String>getParameter("redirect_uri"), request.<String>getParameter("state"));  // REDIRECTS
}
```

The `else` branch is a **second open redirect** of the same shape as the generic one below, and it is the path
`?display=bogus` actually takes today ([3c-1 D7](phase-3c-1-renderer.md#d7--unknown-display--illegalargumentexception-reproduce)'s raw IAE from
`Enum.valueOf`) — so `?display=bogus` is a **302 to an unvalidated URI**, not an error page. `IllegalArgumentException`
is not an `OAuth2Exception`, so `mayRedirect` cannot police it; **5b must port both branches deliberately** and
decide whether to keep the second. `TokenEndpointResource:98-100` carries the identical pattern on the token
endpoint. Recorded here so 5b does not change it by accident in either direction.

⇒ **`OAuth2ProviderNotFoundException` does not redirect on GET but does on POST.** That is not a designed
contract; it is two independently-maintained catch lists that drifted. And it is an **open redirect**: no
provider ⇒ `redirect_uri` was never validated. This is the concrete case that makes `mayRedirect` worth
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

> **Superseded — the framework was fixed on 2026-07-22 ([F1–F4](openam-http-framework.md#as-built)).**
> Everything below is a correct description of the framework *as this plan found it*, and it is why the
> prerequisite existed — the finding is preserved verbatim because the fix is measured against it. As
> shipped: a handler-thrown exception yields a **CREST 500 with a body** (F1), first offered to the
> endpoint's own `@ExceptionHandler` (F2). The two 405 bodies are **unchanged** and remain live for the
> filter and the IT. Read [chf-patterns.md](chf-patterns.md) §2 for the current behaviour; read this only
> for the before-picture.

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

The sibling `catch (IllegalAccessException)` (`:86-89`) produces the **same** shape — 500, empty body,
`setCause(IllegalStateException)` — so any rule keyed on "empty entity + cause" covers both.

Consequence: `Entity.getJson()` on an empty entity **throws IOException**, so `XacmlXmlErrorFilter`'s
`catch (IOException) → return response` means an empty-bodied 500 **passes through unrewritten**. A filter
modelled naively on Phase 2 leaks a bare, bodiless 500.

⚠ **And a filter that guards on `Content-Type` first leaks it too** (corrected 2026-07-21). `Entity.setJson`
is what writes the header — bytecode, first three instructions:

```
getHeaders(); ldc "Content-Type"; ldc "application/json; charset=UTF-8"; Headers.put
```

So the CREST 405/500 fallbacks *do* carry `application/json; charset=UTF-8` (they reach `setEntity(Map)` →
`setJson`), but the `AnnotatedMethod:90-94` response never calls `setEntity` at all and therefore has **no
`Content-Type` header whatsoever**. A Content-Type guard placed ahead of the empty-entity rule classifies it as
"not JSON → untouched" and the synthesize row never fires — silently deleting the one behaviour
[§C's IT](#c-oauth2errorroutecompositionit--in-process-composition-second-highest-value) exists to prove. **Order the rules: empty entity first, Content-Type guard second**
(work item 4). Use `response.getEntity().isDecodedContentEmpty()` — it exists on `Entity` in core 3.1.1 and does
not rely on `getJson()` throwing.

**Two framework 405 bodies, not one:**

| Trigger | Status | Body `code` |
|---|---|---|
| Verb not in the `{GET,POST,PUT,DELETE}` map (HEAD/OPTIONS/PATCH) — `Endpoints.java:66-67` | 405 | **501** (`NotSupportedException`) |
| Verb *is* mapped but no annotated method — `AnnotatedMethod.java:71-75` | 405 | **405** (`ResourceException.getException(405, …)`) |

`findMethod` never returns `null` (`:120` returns a sentinel with `method == null`), so GET/POST/PUT/DELETE
always take the second path. Both must be in the filter's test matrix.

**`@ExceptionHandler` (openam-http) is dead code** — no `@Retention` (defaults to `CLASS`, invisible to
reflection), no `@Target`, **zero usages** (grep-confirmed), and neither `Endpoints` nor `AnnotatedMethod`
ever looks for it. ~~It cannot solve 3c-2's problem. The Filter is the only lever. Flag for deletion in Phase 8.~~

> **Reversed 2026-07-21 — this is now [F2](openam-http-framework.md), and it *is* the lever.** The annotation
> is dead, but it is dead in **our own in-tree module**, and its javadoc already states exactly the contract
> 3c-2 and Phase 5 need: *"Mark a method that handles exceptions thrown by a service method and turns them
> into a response."* Deleting it in Phase 8 would have thrown away a working name for a feature the migration
> then hand-rolls per endpoint. The three-line fix is `@Retention(RUNTIME)` + `@Target(METHOD)` + discovery in
> `Endpoints.from`. **The Filter is no longer the only lever, and no longer the primary one.**

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

### 11. ⚠ `WWW-Authenticate` is emitted by the *resources*, not by `ExceptionHandler`

(Added 2026-07-21. The §E e2e lock froze this header as a "reproduce" row while nothing in 3c-2's API could
produce it — see [D14](#d14--www-authenticate-carried-on-oauth2error-and-tested-in-every-phase).)

`ExceptionHandler` never touches `WWW-Authenticate`. The challenge is set on the Restlet `Response`
**before the throw**, by each resource that authenticates a client — `TokenEndpointResource:101-108`,
`RefreshTokenResource:93`, `TokenRevocationResource:139`:

```java
} catch (InvalidClientAuthZHeaderException e) {
    getResponse().setChallengeRequests(singletonList(new ChallengeRequest(
            ChallengeScheme.valueOf(SUPPORTED_RESTLET_CHALLENGE_SCHEMES.get(e.getChallengeScheme())),
            e.getChallengeRealm())));
    throw new OAuth2RestletException(e.getStatusCode(), e.getError(), e.getMessage(), … state);
}
```

Values are fully determined: `ClientAuthenticationFailureFactory:56` builds
`new InvalidClientAuthZHeaderException(message, "Basic", getRealm(request))`, and
`RestletConstants:32-33` maps technical name `"Basic"` → `ChallengeScheme.HTTP_BASIC`. Restlet then serialises
`Basic realm="<realm>"`. **Confirm the exact spelling by observation in the e2e lock, not from this paragraph.**

⇒ There is exactly one `OAuth2Exception` subclass that implies a response header, it is a **401** (the only
one in finding 5's table), and the header is part of the RFC 6749 §5.2 contract for `invalid_client`. In CHF
there is no `getResponse()` to decorate before throwing — the factory builds the whole `Response`, so the
challenge must ride on `OAuth2Error`.

## Work items

### 1. `OAuth2Error` — the neutral carrier

Replaces `OAuth2RestletException`. **A value type, not a `Throwable`** — and it stays one, though the reason
has changed (**F2**, 2026-07-21).

*Original rationale, now obsolete:* "CHF handlers must **return** `Response` objects — a thrown exception is
swallowed into a bodiless 500 (finding 7)." With [F1+F2](openam-http-framework.md) a throw is no longer
swallowed, so this argument no longer holds.

*Current rationale:* the thing worth throwing is the **existing `OAuth2Exception` hierarchy**, which 5b's
handlers already have in hand and which an `@ExceptionHandler` method matches on directly. `OAuth2Error` is
what that method *builds* on the way to a `Response` — the carrier that holds `redirectUri`, `state`,
`parameterLocation` and the challenge, none of which the core exceptions carry. It was never the thing that
needed throwing. Keeping it a value type still kills the ctor trap (finding 2), and adding no second throwable
type means no second way to be wrong.

```java
public final class OAuth2Error {
    // fields: statusCode, error, description, redirectUri, state, errorUri, parameterLocation,
    //         challengeScheme, challengeRealm
    public static OAuth2Error of(OAuth2Exception e);          // status/error/description/parameterLocation from e,
                                                              // + the D13 and D14 carve-outs
    public static OAuth2Error of(int statusCode, String error, String description);
    public OAuth2Error withState(String state);
    public OAuth2Error withErrorUri(String errorUri);
    public OAuth2Error withChallenge(String scheme, String realm);               // D14 — WWW-Authenticate
    public OAuth2Error redirectingTo(String redirectUri, UrlLocation location);  // explicit opt-in
    public boolean hasRedirectUri();                          // state:  redirectUri != null && !isEmpty
    public static boolean mayRedirect(OAuth2Exception e);     // policy: the never-redirect table
    public Map<String, String> asMap();                       // LinkedHashMap, canonical order
    // getters: getStatusCode/getError/getDescription/getRedirectUri/getState/getErrorUri/
    //          getParameterLocation/getChallengeScheme/getChallengeRealm
}
```

> **Naming (2026-07-21).** An earlier draft called both the instance predicate and the static policy check
> `isRedirectable`. They answer different questions — *"does this error carry a redirect target?"* versus
> *"is redirecting permitted for this exception type?"* — and one name for both invites writing the state
> check where the policy check belongs, in the very class whose purpose is to make redirecting deliberate.
> `hasRedirectUri()` / `mayRedirect(…)`.

- `asMap()` — **`LinkedHashMap`**, canonical order `error`, `error_description`, `error_uri`, `state`; the
  three optional keys emitted only when `!isEmpty` (the identical predicate to `OAuth2RestletException.asMap()`,
  via `org.forgerock.oauth2.core.Utils.isEmpty`). Keep `errorUri` in the shape but ship **no populator**
  (finding 2). See [D1](#d1--asmap-field-order-fix).
- **`static boolean mayRedirect(OAuth2Exception)`** — the [D6](#d6--isredirectable-unified-to-the-safe-union-fix)
  fix. Encode as **data** what is today emergent from catch ordering:

  ```java
  private static final Set<Class<? extends OAuth2Exception>> NEVER_REDIRECT = Set.of(
      RedirectUriMismatchException.class, InvalidClientException.class,
      OAuth2ProviderNotFoundException.class, DuplicateRequestParameterException.class,
      CsrfException.class,
      ResourceOwnerAuthenticationRequired.class);        // D13 — carries its own login URI; never the client's
  ```
  **Unified to the union of GET's and POST's sets** (the safe side of finding 4). Must match on
  **assignability**, not identity, so `InvalidClientAuthZHeaderException` (extends `InvalidClientException`)
  and `OAuth2ProviderNotFoundException` (extends `NotFoundException`) resolve correctly. Every one of the 31
  subclasses in finding 5 gets an explicit verdict in `OAuth2ErrorTest`, so **adding a subclass without
  deciding is a test failure** (R-3c.6).

  The `IllegalArgumentException` cases are *not* `OAuth2Exception`s; **both branches** of
  `AuthorizeResource:120-126` (finding 4) stay a 5b handler concern.

- **Two carve-outs inside `of(OAuth2Exception)`** — both are cases where the exception carries information the
  request cannot supply, so a generic mapper that reads only `statusCode`/`error`/`getMessage()` loses it:

  ```java
  if (e instanceof ResourceOwnerAuthenticationRequired) {                                   // D13
      err = err.redirectingTo(((ResourceOwnerAuthenticationRequired) e).getRedirectUri().toString(),
                              UrlLocation.QUERY);       // the LOGIN page, per finding 1a
  } else if (e instanceof InvalidClientAuthZHeaderException) {                               // D14
      InvalidClientAuthZHeaderException a = (InvalidClientAuthZHeaderException) e;
      err = err.withChallenge(a.getChallengeScheme(), a.getChallengeRealm());               // finding 11
  }
  ```
  Both are **assignability** checks for the same reason as `NEVER_REDIRECT`.

This collapses `AuthorizeResource`'s 7 catch blocks into one in 5b — and with **F2** it leaves the handler
method entirely, becoming the endpoint's `@ExceptionHandler`:

```java
@ExceptionHandler
public Response onOAuth2Error(OAuth2Exception e, @Contextual Request request) {
    OAuth2Request oauth2Request = requestFactory.create(request);
    OAuth2Error err = OAuth2Error.of(e).withState(oauth2Request.getParameter("state"));
    String redirectUri = oauth2Request.getParameter("redirect_uri");
    if (OAuth2Error.mayRedirect(e) && redirectUri != null) {
        err = err.redirectingTo(redirectUri, e.getParameterLocation());
    }
    return errorResponseFactory.toResponse(oauth2Request, err);
}
```

The `@Contextual Request` parameter is what makes this work: the mapper reads `state` and `redirect_uri` from
the request itself, so the thrown `OAuth2Exception` does not have to carry them and the handler method does not
have to catch anything. Without **F2** the same body sits in a `catch` block inside each handler method — the
design still functions, it just gets copied per verb, which is precisely how GET and POST drifted apart in the
first place (finding 4).
`redirectingTo` being an **explicit opt-in** is the point: redirecting becomes something you *do*, not
something that happens because you picked the wrong constructor.

⚠ **Why the D13 carve-out is load-bearing and not tidiness.** Without it this snippet is *wrong in the
dangerous direction*: `ResourceOwnerAuthenticationRequired` is an `OAuth2Exception` (`:26`) with status **307**,
so `mayRedirect` returns true by default, `redirectingTo` overwrites the login URI with the request's
`redirect_uri`, and `toResponse` branch 1 then emits **301 → a client-supplied, unvalidated URI** — the login
redirect silently replaced by an open redirect at the one endpoint that is reachable **unauthenticated**. It is
the same defect class D6 exists to remove, reintroduced by the mechanism advertised as the fix. Belt and
braces: `of` supplies the right URI, and membership in `NEVER_REDIRECT` stops any caller overwriting it.

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
   no error params, no state. Per [D13](#d13--resourceownerauthenticationrequired-carries-its-own-redirect-uri-carve-out) that URI is the **login page**, placed there by
   `OAuth2Error.of` — never the request's `redirect_uri`.
2. `error.hasRedirectUri()` → `toRedirectResponse` → **302** + `Location: RedirectUris.compose(...)`.
   Do not reproduce the dead `:119` status write.
3. else → `toHtmlErrorResponse` with status = `error.getStatusCode()`, rendering `templates/page/error.ftl`
   (display hardcoded `"page"`, per finding 1c).

- `realm` ← `request.getParameter("realm")`, **defaulting to `"/"`** ([D9](#d9--null-realm--fix)).
- `baseUrl` ← `baseURLProviderFactory.get(realm).getRootURL(request.getHttpServletRequest())` — the
  **`HttpServletRequest`** overload, never `HttpContext` (finding 8). **Guard `getHttpServletRequest() == null`.**
- JSON: `response.setEntity(error.asMap())` → `setJson` sets `application/json; charset=UTF-8` natively ⇒
  **`JacksonRepresentationFactory` dies here**.
- **`WWW-Authenticate`** ([D14](#d14--www-authenticate-carried-on-oauth2error-and-tested-in-every-phase)): whenever `error.getChallengeScheme() != null`, every branch of
  `toResponse` **and** `toJsonResponse` emits
  `response.getHeaders().put("WWW-Authenticate", scheme + " realm=\"" + realm + "\"")`. Put it in one private
  helper applied at the end, not per branch — today's producers (finding 11) set the challenge on the response
  *before* choosing an error shape, so it is orthogonal to the 3-branch dispatch. In practice only the JSON
  401 path fires (`InvalidClientAuthZHeaderException` is the sole carrier), but a header that depends on which
  branch ran is exactly how it goes missing in 5a.
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
| `Content-Type` not JSON (incl. **HTML**, and **absent**) | **untouched** | 5b's `page/error.ftl` 400 must survive. Guard on Content-Type **before** parsing |
| JSON map containing key `error` | **untouched** | already OAuth2-shaped → idempotent |
| JSON map containing key `code` (CREST) | rewrite → `{error, error_description}` | the framework 405/501 fallbacks (finding 7) |
| anything else | untouched | unknown shape |

> **F1 deleted a rule.** An earlier draft carried a fourth rule — *"entity empty **and** `getCause() != null` →
> synthesize `{error: "server_error", …}`"* — and it had to run **first**, because the bodiless 500 from
> `AnnotatedMethod:90-94` has no `Content-Type` and the guard above would otherwise drop it. That ordering
> constraint was subtle, silent when violated, and unobservable to any canned-response unit test (R-3c.14).
> [F1](openam-http-framework.md) removes the response that made it necessary: a handler-thrown exception now
> arrives here as a well-formed CREST map and is handled by the `code` rule like every other framework error.
> **The rules are no longer order-sensitive** — no input matches two of them.
>
> `OAuth2ErrorRouteCompositionIT` keeps asserting that a throwing handler produces a rewritten OAuth2-shaped
> 500; it is now verifying the fixed framework rather than compensating for the broken one.

**Discriminating CREST from OAuth2 (both are `Map`s):** a CREST map is `{code, reason, message, detail?, cause?}`
and never has `error`; an OAuth2 map is `{error, error_description?, error_uri?, state?}` and never has `code`.
Check **`error` first** (idempotency), then `code`.

**Improvement over the Phase-2 model — guard on `Content-Type` before parsing.** `XacmlXmlErrorFilter` relies
on `getJson()` throwing `IOException` on a non-JSON body to fall through. That works, but only *by accident*,
and for 3c-2 the accident is load-bearing: it is the only thing standing between the filter and a destroyed
consent-error page. Make it explicit and cheap (`ContentTypeHeader.valueOf(response).getType()` — verified
present in http-framework core 3.1.1), and test the HTML case directly (R-3c.5). **`valueOf` on a message with
no `Content-Type` yields a null type** ⇒ untouched, which is now unambiguously right: after
[F1](openam-http-framework.md) no framework response reaches this filter without a `Content-Type`.

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

`ResourceOwnerAuthenticationRequired` joins `NEVER_REDIRECT` for a **different** reason — not "this error must
not reach the client's URI" but "this error already knows its own URI". See
[D13](#d13--resourceownerauthenticationrequired-carries-its-own-redirect-uri-carve-out); keep the two rationales distinct in the test's comments, because a later
reader pruning the set on RFC grounds would otherwise remove the security guard with it.

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

<a id="d13--resourceownerauthenticationrequired-carries-its-own-redirect-uri-carve-out"></a>
### D13 — `ResourceOwnerAuthenticationRequired` carries its own redirect URI: **carve-out** (decided 2026-07-21)

**Reproduce** the behaviour; the decision is *how*, and the null option was a security regression.

RoAR is the sole producer of the 307 branch (finding 1a) and the only `OAuth2Exception` whose redirect target
comes from the **exception** (`:28,45` — the login page) rather than from the request. Under D6's data-driven
policy it would default to redirectable, and 5b's one-line collapse would then overwrite the login URI with the
client's `redirect_uri`, emitting **301 → unvalidated client URI** on unauthenticated `GET /oauth2/authorize`.

Two mechanisms, deliberately redundant because the failure is silent and security-relevant:
1. `OAuth2Error.of` populates `redirectUri` from `e.getRedirectUri()` for RoAR — the carrier knows the truth.
2. RoAR is in `NEVER_REDIRECT`, so `mayRedirect` is false and no caller can overwrite it.

`OAuth2ErrorTest` asserts both, including the adversarial case: `of(roar).redirectingTo("https://evil/", QUERY)`
must still yield the login URI, and the resulting response must be a **301 to the login page**. This is the
one row of the e2e lock ([§E](#e-e2e-error-contract-lock)) that would have gone from pass to *silently
wrong-but-still-301* at the 5d flip.

<a id="d14--www-authenticate-carried-on-oauth2error-and-tested-in-every-phase"></a>
### D14 — `WWW-Authenticate` carried on `OAuth2Error`, and tested in every phase (decided 2026-07-21)

Finding 11: the header is set by the resources, not by `ExceptionHandler`, so nothing in 3c-2's original API
could emit it — while [§E](#e-e2e-error-contract-lock) already froze it as a "reproduce" row. Deferring it
wholly to 5a was the alternative and is rejected: in CHF the factory owns the entire `Response`, so 5a would
have to reach around the factory to add a header, which is precisely the shape that goes missing.

`OAuth2Error` gains `challengeScheme`/`challengeRealm`, `of` populates them from
`InvalidClientAuthZHeaderException`, and the factory emits the header on every branch.

**Tested at every layer, per phase:**

| Phase | Layer | Assertion |
|---|---|---|
| 3c-2 | `OAuth2ErrorTest` | `of(InvalidClientAuthZHeaderException)` carries scheme `Basic` + the realm; every other subclass carries neither |
| 3c-2 | `OAuth2ErrorResponseFactoryTest` | `toJsonResponse` on a challenge-bearing 401 emits `WWW-Authenticate: Basic realm="…"`; a non-challenge error emits **no** such header |
| 3c-2 | `RestletErrorParityTest` | A/B against Restlet's `ChallengeRequest` serialisation — this is the row that pins the exact spelling, and it is a *belief* until executed |
| 3c-2 | e2e lock (§E) | bad client secret on `/oauth2/access_token` → 401 + the header, recorded **against live Restlet** |
| 5a | `TokenEndpointHandler` tests | the ported handler passes the exception through `OAuth2Error.of` rather than re-deriving the header |
| 5d | smoke matrix | the header survives the route flip |

The parity row is the load-bearing one: `Basic realm="…"` is what Restlet is *expected* to emit, not what has
been observed. If the parity leg disagrees, **the parity leg is right**.

## Tests

### A. Unit tests per class — table stakes

- **`OAuth2ErrorTest`** — `asMap()` order and omission (`error_uri` never emitted; optional keys gated on
  `isEmpty`); **`mayRedirect` enumerating all 31 subclasses** of finding 5 (R-3c.6), incl. the
  assignability cases `InvalidClientAuthZHeaderException` and `OAuth2ProviderNotFoundException`; the two
  `of` carve-outs — RoAR keeps the **login** URI even against an adversarial `redirectingTo`
  ([D13](#d13--resourceownerauthenticationrequired-carries-its-own-redirect-uri-carve-out)), and the challenge fields ([D14](#d14--www-authenticate-carried-on-oauth2error-and-tested-in-every-phase)).
- **`RedirectUrisTest`** — fragment **replaces** / query **appends** / existing query preserved / special
  chars.
- **`OAuth2ErrorResponseFactoryTest`** — all four modes; exact **301** / **302** / 4xx; null realm → `"/"`
  ([D9](#d9--null-realm--fix)); **null `HttpServletRequest`** guarded; `WWW-Authenticate` emitted exactly when
  the error carries a challenge ([D14](#d14--www-authenticate-carried-on-oauth2error-and-tested-in-every-phase)); the 307 branch targets the login URI, not any
  `redirect_uri` on the error ([D13](#d13--resourceownerauthenticationrequired-carries-its-own-redirect-uri-carve-out)).
- **`OAuth2ErrorFilterTest`** — **`XacmlXmlErrorFilterTest` verbatim as the scaffold**: TestNG + AssertJ, no
  Mockito, no Guice, no `@BeforeMethod`; `Handler next = (ctx, req) -> Promises.newResultPromise(canned);` +
  `filter.filter(context, request, next).getOrThrowUninterruptibly()`. Cover every row of the contract table,
  especially **HTML untouched** and **idempotent on an OAuth2-shaped body**. A header-less 500 must be left
  **untouched** — post-[F1](openam-http-framework.md) the framework no longer emits one, and a filter that
  invents a body for a response it cannot classify is guessing.

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
| **`WWW-Authenticate` spelling** ([D14](#d14--www-authenticate-carried-on-oauth2error-and-tested-in-every-phase)) | Restlet `ChallengeRequest(HTTP_BASIC, realm)` serialised vs the factory's `Basic realm="…"`. Finding 11's expected value is a **belief**; this row is what makes it a fact. ⚠ `Response.setChallengeRequests` stores objects — the header only materialises in the **connector**, so a plain unit `Response` has no `WWW-Authenticate` to read. Serialise it in-process with `AuthenticatorUtils.formatRequest(ChallengeRequest, Response, Series<Header>)` (verified present, `org.restlet.engine.security`) |

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
→ incl. `WWW-Authenticate: Basic`, per [D14](#d14--www-authenticate-carried-on-oauth2error-and-tested-in-every-phase)); **301 + `Location`** on unauthenticated
`/oauth2/authorize` — assert the `Location` **is the login page**, not merely that a `Location` exists
([D13](#d13--resourceownerauthenticationrequired-carries-its-own-redirect-uri-carve-out): a bare "301 with some `Location`" would have passed while pointing at the client's URI);
**302** + query-vs-fragment error composition on a valid `redirect_uri`; the HTML error page's
`Content-Type: text/html;charset=UTF-8` (reach it with an unknown `client_id` → `InvalidClientException` →
no-redirect ctor → the error page; **not** via `?display=bogus`, which finding 4's second IAE branch turns
into a 302).

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
  **rejected, and the rejection aged well**. It builds on an implementation detail of shared framework code
  whose own message calls the situation a bug ("Exception from invocation should be handled by promise"). The
  closing argument was: *"if `Endpoints.from`'s swallowing needs fixing, it should be fixed **once in
  openam-http**, not worked around per-area."*
  **That is now [F1](openam-http-framework.md), decided 2026-07-21.** The right conclusion was already on the
  page; what was missing was noticing that "should be fixed once in openam-http" describes a module in this
  repository that we maintain, not an upstream we petition. The filter is a **net, not a mechanism** — it just
  now has less to net.

## Verification

0. **[F1–F3](openam-http-framework.md) are already merged and green** — including
   `mvn -o -pl openam-rest,openam-core-rest,openam-entitlements verify`. 3c-2 must not be the commit that
   discovers a framework regression.
1. `mvn -o -pl openam-oauth2 install -DskipTests` → `mvn -o -pl openam-oauth2,openam-uma test`.
   **Baseline (3c-1 as-built): openam-oauth2 743, openam-uma 192**, 0 failures/errors/skips. 3c-2 is additive ⇒
   openam-uma must stay **exactly 192**, and openam-oauth2 grows from **743** (not 716 — that is 3b's number,
   before 3c-1's +27; corrected 2026-07-21).
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
| No-redirect policy | **fix → explicit union** ([D6](#d6--isredirectable-unified-to-the-safe-union-fix)) | `OAuth2ErrorTest` enumerates **all 31** subclasses |
| 307 branch targets the **login** URI, never the request's `redirect_uri` | reproduce ([D13](#d13--resourceownerauthenticationrequired-carries-its-own-redirect-uri-carve-out)) | `OAuth2ErrorTest` (incl. adversarial `redirectingTo`); factory test; e2e asserts the `Location` **value** |
| `WWW-Authenticate: Basic realm="…"` on the 401 | reproduce ([D14](#d14--www-authenticate-carried-on-oauth2error-and-tested-in-every-phase)) | every layer — unit, factory, parity (spelling), e2e, 5a, 5d |
| Handler-thrown exception → CREST 500 → rewritten to OAuth2 shape | **fix**, via [F1](openam-http-framework.md) | `OAuth2ErrorRouteCompositionIT` |
| `IllegalArgumentException`'s two branches (`?display=bogus` → 302 to unvalidated URI) | **defer to 5b, recorded** | finding 4; not asserted in the e2e lock |
| `Redirector` `{}` substitution | **diverge** ([D11](#d11--redirectors--substitution-diverge)) | parity test documents it |
| Null realm | **fix → `"/"`** ([D9](#d9--null-realm--fix)) | factory test |
| WARN on every 4xx | fix → 5xx warn / 4xx debug | not client-observable |

**Recorded for Phase 5a, not 3c:** `OAuth2Filter.beforeHandle:58-80` catches `OAuth2RestletException` /
`InvalidRequestException`, writes the error entity inline, then **falls through to
`return super.beforeHandle(...)` → CONTINUE** — the request proceeds to the wrapped resource anyway and its
output overwrites the error. 3c ships no equivalent; **5a's `TokenEndpointHandler` must return, not continue**.
It also adds `Cache-Control: no-store` + `Pragma: no-cache` (`:76-77`), which 5a must reproduce.

**Also for 5a:** the three token-family resources decorate the response with a `ChallengeRequest` *before*
throwing (finding 11). The ported handlers must **not** re-derive that header — they route the exception
through `OAuth2Error.of`, which carries it ([D14](#d14--www-authenticate-carried-on-oauth2error-and-tested-in-every-phase)), and let the factory emit it. `RestletConstants` and
its `SUPPORTED_RESTLET_CHALLENGE_SCHEMES` map die with the resources in Phase 5a.

**Recorded for Phase 5b:** `ConsentRequiredResource.getDataModel:75-108` seeds its map from
`new HashMap<>(getRequest().getAttributes())` (`:79`) then `putAll(getQuery().getValuesMap())` (`:80`) —
`realm`/`redirect_uri`/`scope`/`state`/`nonce`/`acr`/`response_type`/`client_id`/`ui_locales` arrive
**implicitly** and are never `put` explicitly. A CHF port must **enumerate them** or every `<#if x??>` silently
goes false and the consent page renders with a broken `pageData`.

## Execution order

0. **[openam-http-framework.md](openam-http-framework.md) F1–F3 land first**, as their own commit with their
   own tests — a shared-framework change must not ride inside a migration commit ([D2](#d2--serverexception--400-on-the-contract-path-reproduce)'s argument,
   applied consistently). 3c-2 is written against the fixed framework.
1. `OAuth2Error` + `OAuth2ErrorTest` (incl. the all-31-subclasses `mayRedirect` enumeration and both
   [D13](#d13--resourceownerauthenticationrequired-carries-its-own-redirect-uri-carve-out)/[D14](#d14--www-authenticate-carried-on-oauth2error-and-tested-in-every-phase) carve-outs).
2. `RedirectUris` + `RedirectUrisTest`.
3. `RestletErrorParityTest` — **the Restlet leg first**, so the encoding row (risk #3) and the
   `WWW-Authenticate` spelling row ([D14](#d14--www-authenticate-carried-on-oauth2error-and-tested-in-every-phase)) tell you the truth before the CHF side is written to a
   belief.
4. `OAuth2ErrorResponseFactory` + test → close the parity test's CHF leg.
5. `OAuth2ErrorFilter` + `OAuth2ErrorFilterTest` (`XacmlXmlErrorFilterTest` as the scaffold) — four rules
   now, not five ([F1](openam-http-framework.md) deleted the synthesize rule).
6. **`OAuth2ErrorRouteCompositionIT` — write it in the same step as the filter**, not after. It is the only
   gate on the framework-composition beliefs, and finding 7 proves those beliefs are wrong more often than not.
7. `mvn -o -pl openam-oauth2 install -DskipTests` → `test` → **`verify`** → whole-reactor build → grep gates.
8. e2e lock spec → run against a local container **built from unmodified `/oauth2`**.
9. ~~Correct [chf-patterns.md](chf-patterns.md) **§2**~~ — **done 2026-07-22 by the F1–F4 docs commit**, which
   rewrote §2 to describe the *fixed* framework rather than correcting its account of the broken one. Nothing
   left here beyond re-reading §2 before writing the filter.
   Update [plan.md](plan.md) (drop "Preserves `asMap()` field order"; risk rows) and
   [decisions.md](decisions.md) (D3, D6, **D13, D14**). Mark 3c done and record an **As-built** section here.

## Risks (extends [plan.md](plan.md)'s register; shares R-3c.1/.2/.3 with [3c-1](phase-3c-1-renderer.md#risks-extends-planmds-register))

| # | Risk | Detail | Mitigation |
|---|---|---|---|
| **R-3c.5** | **Filter destroys the HTML error page** | 5b returns a 400 with an HTML body; a Phase-2-shaped filter survives only by `getJson()` *accidentally* throwing | Explicit Content-Type guard **before** parsing; direct test + IT row |
| **R-3c.6** | **`mayRedirect` drift** | A new `OAuth2Exception` subclass silently defaults to redirectable | `OAuth2ErrorTest` enumerates all 31 subclasses ⇒ adding one without a verdict fails the build |
| **R-3c.8** | **The e2e lock locks the wrong thing** | Asserting a quirk 3c/5b intends to fix means 5d must edit the lock — at which point it was never a lock | Rule: every e2e assertion maps to a "reproduce" row in the parity checklist. Write by observation, not prediction |
| ~~**R-3c.9**~~ | ~~**`OAuth2Error` re-grows a `Throwable`**~~ | **Retired 2026-07-21.** The risk was that 5b would throw `OAuth2Error` into a filter and hit the swallowing problem. [F1+F2](openam-http-framework.md) remove the swallowing, and the thing 5b throws is the **existing** `OAuth2Exception`, not `OAuth2Error` — which stays a `final` value type with no `Throwable` in its hierarchy | — |
| **R-3c.11** | **D3/D6 land silently at the 5d flip** | Both are invisible until the route moves, months later | Recorded in [decisions.md](decisions.md); excluded from the e2e lock **by design**, and listed in 5d's smoke matrix |
| **R-3c.13** | **The login redirect degrades into an open redirect** | RoAR is an `OAuth2Exception` with a 307 and its *own* URI. Any generic mapper that reads only status/error/message and takes the redirect target from the request 301s an **unauthenticated** user agent to a client-supplied URI — and the response still looks right (301 + a `Location`), so a shape-only test passes | [D13](#d13--resourceownerauthenticationrequired-carries-its-own-redirect-uri-carve-out)'s two redundant mechanisms; `OAuth2ErrorTest`'s adversarial `redirectingTo` case; the e2e lock asserts the `Location` **value**, not its presence |
| ~~**R-3c.14**~~ | ~~**The filter's rule order regresses silently**~~ | **Retired 2026-07-21** with the rule it guarded. [F1](openam-http-framework.md) means no input matches two rules, so the filter is no longer order-sensitive | — |
