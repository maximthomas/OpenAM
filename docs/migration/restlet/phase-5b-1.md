# Phase 5b-1 — OAuth2 `/authorize` → CHF: Detailed Implementation Plan

Execution plan for **step 5b-1** of [Phase 5](phase-5-oauth2.md) of the Restlet → CHF migration — the
`/oauth2/authorize` endpoint, the centrepiece of the whole migration (consent HTML, success redirect
composition, `form_post`, the 301→login redirect, and the catch-collapse). Parent tracker: [plan.md](plan.md);
umbrella substrate: [phase-5-oauth2.md](phase-5-oauth2.md); the steps this one builds on:
[phase-5a-1.md](phase-5a-1.md) (the `AbstractOAuth2HttpJsonEndpoint` base + hook-seam precedent + the cookie
spike) and [phase-5a-2.md](phase-5a-2.md) (the per-endpoint cache-header correction, D1); the build-ahead infra
it consumes: [phase-3c-1-renderer.md](phase-3c-1-renderer.md) (`FreemarkerTemplateRenderer` + the **goldens**),
[phase-3c-2-error-layer.md](phase-3c-2-error-layer.md) (`OAuth2Error`/`RedirectUris`/`OAuth2ErrorResponseFactory`);
decisions: [decisions.md](decisions.md); reusable CHF patterns: [chf-patterns.md](chf-patterns.md); test layers:
[../../test-infrastructure.md](../../test-infrastructure.md). Written 2026-07-25; branch
`features/restlet-migration`. All facts below verified against the tree on 2026-07-25.

> **Naming.** The request that produced this plan said "5b-b1"; the tracked step is **5b-1**
> ([plan.md](plan.md) phase table). This doc splits it into **5-E2** (a test-only live-oracle gate),
> **5b-1a** (the browser substrate) and **5b-1b** (`AuthorizeHandler` itself) — the same
> reviewability/risk-isolation split 5a-2 used for 5a-2a/5a-2b.

## Context

`/oauth2/authorize` is the largest single port in Phase 5: three Restlet classes (`AuthorizeResource` 218 L +
`ConsentRequiredResource` 172 L + `OAuth2Representation` 219 L ≈ 600 L) plus the `AuthorizeEndpointFilter`
method/content-type/cache wrapper. It carries everything the JSON endpoints did not:

- an **HTML consent page** with a 20-key data model and four display folders;
- a **success 302** whose parameters go in the fragment or the query depending on `AuthorizationToken.isFragment()`;
- **`response_mode=form_post`**, an auto-submitting HTML form instead of a redirect;
- a **301 to the login page** on an unauthenticated request (with the request URL as `goto`);
- **fourteen catch clauses across two verbs** (8 on GET, 6 on POST, 9 distinct types) **that have drifted
  apart** — the thing [D6](decisions.md) unifies.

Everything it renders and every error shape it produces already exists as build-ahead infrastructure
(`FreemarkerTemplateRenderer` + 11 goldens, `OAuth2Error`/`mayRedirect`, `RedirectUris`,
`OAuth2ErrorResponseFactory`). **5b-1 authors no new rendering, redirect-composition or error infrastructure** —
it ports the endpoint shell onto them, plus the two things the JSON steps did not need: a **browser**
`@ExceptionHandler` base and a **shared consent-page collaborator**.

Build-ahead: **nothing is routed.** The handler first runs in a live CHF chain in `OAuth2RouterIT` at 5d-1. The
guards are the per-handler unit tests, the existing golden oracle, a new composition IT, and — the reason 5-E2
comes first — the **live-Restlet `/authorize` contract lock**, which cannot be recorded after 5d-1
([R-5.1](phase-5-oauth2.md#risk-register-extends-planmds--phase-4s), [plan.md](plan.md) risk #20).

> **Convention.** New classes: `org.openidentityplatform.openam.oauth2.http`, CDDL header, `Copyright 2026 3A
> Systems LLC.`, **no `@since`** ([decisions.md](decisions.md)). Classes modified in place keep their header and
> gain a `Portions copyright 2026 3A Systems LLC.` line — except our own 2026 classes, which carry no
> `Portions` line ([phase-5a-2 as-built](phase-5a-2.md#as-built)).

## Scope & sizing — split three ways

One commit covering the oracle, two abstract bases, a hook seam, a new neutral accessor, a shared consent
renderer and the 600-line handler would be ~15 files with three unrelated risk profiles. Split:

| Step | Scope | New / changed | Risk |
|---|---|---|---|
| **5-E2** ✅ | **The `/authorize` live-Restlet contract lock** — a consent-capable e2e client ([finding 12](#12--the-e2e-environment-cannot-currently-reach-a-consent-page)) plus 9 authorize rows in `e2e/oauth2/oauth2-test.spec.mjs`, written **by observation**. Test-only, no main code. Extends step **5-E**, whose recorded rows so far cover only `/access_token` + cache headers ([finding 1](#1--the-e-lock-does-not-yet-cover-authorize--and-cannot-be-written-after-5d-1)) | e2e spec only (0 main) | **High** — unrecoverable after 5d-1 |
| **5b-1a** | **The browser substrate**: extract `AbstractOAuth2HttpEndpoint` (shared fields + `noCache`/`withErrorHeaders`), add `AbstractOAuth2HttpBrowserEndpoint` (the browser `@ExceptionHandler`), `ChfAuthorizeRequestHook` + `LoginHintHook` dual-impl + Guice Multibinder, and the neutral **`getAcceptedLanguages()`** accessor the consent model needs ([finding 5](#5--getacceptedlanguages-does-not-exist--the-consent-models-locale-key-has-no-neutral-source)) | 3 new + 3 modified + 3 tests + 1 IT | **Med** |
| **5b-1b** | **`AuthorizeHandler`** + the shared **`ConsentPageRenderer`** (data model + `authorize.ftl` render, reused by 5b-2's device flow — [finding 6](#6--consentrequiredresource-is-shared-with-the-device-flow--on-chf-it-must-become-a-collaborator-not-a-base)) | 2 new + 2 tests | **High** |

**Total new main classes: 5** (`AbstractOAuth2HttpEndpoint`, `AbstractOAuth2HttpBrowserEndpoint`,
`ChfAuthorizeRequestHook`, `ConsentPageRenderer`, `AuthorizeHandler`) + one new accessor on two classes.

Order: **5-E2 → 5b-1a → 5b-1b**. 5-E2 is deliberately first, not merely "before 5d-1": the handler's
method/content-type behaviour and its 405/400 wire bodies are **decided by** what the oracle records
([finding 2](#2--the-continue-bug-makes-authorizes-filter-validation-unpredictable--record-it-do-not-derive-it)),
and characterizing before porting is the lesson [3b as-built #2](phase-3b-collaborators.md) and
[3c-1 execution step 3](phase-3c-1-renderer.md) both recorded.

## Key research findings (drove this design)

<a id="1--the-e-lock-does-not-yet-cover-authorize--and-cannot-be-written-after-5d-1"></a>
### 1. ⚠ The §E lock does **not** yet cover `/authorize` — and cannot be written after 5d-1

[plan.md](plan.md)'s 5-E row reads "recorded (13 rows green vs live Restlet)", which is true of the
`/access_token` rows and the cache-header rows. Verified against the spec
(`e2e/oauth2/oauth2-test.spec.mjs`, 510 L): its `describe` blocks are `"OAuth Service test"`,
`"OAuth2 /access_token contract lock (5-E, live Restlet)"` (3 rows) and
`"OAuth2 cache-header contract lock (5-E, live Restlet)"` (4 rows). **There is no authorize row at all** — no
301→login `Location`, no 302 query-vs-fragment, no `text/html;charset=UTF-8` error page, no consent-page
capture, although the umbrella's §E list ([phase-5-oauth2.md](phase-5-oauth2.md) prerequisite gate) names all
four. Restlet stops serving `/oauth2` at 5d-1, so these rows have to be recorded now, and 5b-1 is the step
that needs them.

<a id="2--the-continue-bug-makes-authorizes-filter-validation-unpredictable--record-it-do-not-derive-it"></a>
### 2. ⚠ The CONTINUE bug makes `/authorize`'s filter validation unpredictable — record it, do not derive it

`AuthorizeEndpointFilter extends OAuth2Filter` (`AuthorizeEndpointFilter.java:33`) contributes three things:

- `validateMethod` (`:54-59`) — GET or POST, else **405 `method_not_allowed`** with the literal message
  `"Required Method: GET or POST found: <method>"`;
- `validateContentType` (`:68-74`) — a **non-empty** entity must be `application/x-www-form-urlencoded`, else
  `InvalidRequestException("Invalid Content Type")`;
- **`Cache-Control: no-store` + `Pragma: no-cache` on every response** (`OAuth2Filter.java:76-77`), success and
  error alike. `/authorize` is one of exactly **two** endpoints that get these from the filter
  ([phase-5a-2 finding 1](phase-5a-2.md)).

But `OAuth2Filter.beforeHandle` (`:59-79`) writes the error status + a **JSON** entity and then falls through
to `return super.beforeHandle(...)` → `Filter.CONTINUE`, so the wrapped resource runs anyway. Whether the
filter's error survives is **not derivable**: 5a-1 predicted that the resource would overwrite the 405 on
`GET /access_token`, and the live capture **overturned that** — the 405 stood on the wire
([phase-5a-1 as-built §5-E](phase-5a-1.md#step-5-e--access_token-contract-lock-observed-against-live-restlet-2026-07-24)).
⇒ `PUT /oauth2/authorize` and a JSON-bodied `POST /oauth2/authorize` must be **observed**, not predicted, and
the handler's validation design (D8) follows the observation.

<a id="3--the-two-catch-lists-and-what-collapsing-them-actually-changes"></a>
### 3. The two catch lists, and what collapsing them actually changes

`AuthorizeResource` GET (`:120-149`) and POST (`:187-206`) — verified clause by clause, with each exception's
**own** status/error checked so the collapse can be proven byte-safe:

| Exception | GET | POST | Own `status/error` | Collapsed base result |
|---|---|---|---|---|
| `IllegalArgumentException` | 400 `invalid_request`; **redirects** to the raw `redirect_uri` unless the message contains `client_id` | *(not caught)* → `doCatch` → 400 `server_error` **HTML error page** | n/a | **D7** — one non-redirecting 400 `invalid_request` |
| `ResourceOwnerAuthenticationRequired` | 307+login URI → **301** | same | 307 `redirection_temporary` | identical (`OAuth2Error.of` pins the login URI, [D13](decisions.md)) |
| `ResourceOwnerConsentRequired` | renders `authorize.ftl` | *(not thrown — the 3-arg `authorize` cannot raise it)* | *not an `OAuth2Exception`* | handled **in the handler**, not the base |
| `InvalidClientException` | no redirect | no redirect | 400/401 `invalid_client` | identical (`NEVER_REDIRECT`) |
| `RedirectUriMismatchException` | no redirect | no redirect | 400 `redirect_uri_mismatch` | identical (`NEVER_REDIRECT`) |
| `DuplicateRequestParameterException` | no redirect, literal `400 invalid_request` | same | **400 `invalid_request`** | identical — the literal matches the exception's own values |
| `CsrfException` | *(not caught — unreachable on GET)* | no redirect, literal `400 bad_request` | **400 `bad_request`** | identical — literal matches |
| `OAuth2ProviderNotFoundException` | no redirect | **redirects** (falls to the generic catch, **unvalidated** URI) | inherits `NotFoundException` | **no redirect** — the [D6](decisions.md) open-redirect fix |
| any other `OAuth2Exception` | redirects to the raw `redirect_uri`, `parameterLocation` honoured | same | own | identical |

⇒ **Exactly two behaviour changes** land from the collapse, both already decided:
`OAuth2ProviderNotFoundException` on POST stops redirecting ([D6](decisions.md), already in 5d-1's smoke
matrix), and the `IllegalArgumentException` handling unifies (**D7**, new here). Everything else is
byte-identical, because each literal `(status, error)` pair the Restlet catch passed equals the exception's own
pair.

<a id="4--the-consent-data-model-is-already-pinned-by-a-golden--reproduce-it-key-for-key"></a>
### 4. The consent data model is already pinned by a golden — reproduce it key for key

R-5.5 (a CHF port that does not enumerate the implicitly-seeded keys renders a consent page with every `<#if>`
false) is **already de-risked**: `RendererFixtures.authorize()`
(`openam-oauth2/src/test/java/.../http/RendererFixtures.java`) is the producer-derived model, and
`RestletRendererParityTest` asserts `Restlet == golden == CHF` over `page/`, `popup/`, `touch/`, `wap/` and the
composed popup. The model to reproduce, with its source line in `ConsentRequiredResource` and its **type** (the
types are the trap — see the `RendererFixtures` class javadoc):

| Key | Source | Type |
|---|---|---|
| `realm` | request attribute (`:79`) — on CHF, `ChfOAuth2Request` seeds it from `RealmContext` (`:324-329`) | `String` |
| `redirect_uri`, `scope`, `state`, `nonce`, `acr`, `response_type`, `client_id`, `ui_locales` | `getQuery().getValuesMap()` (`:80`) — **query string only**, not the POST body | `String` |
| `target` | `resRef.getPath()` + `"?" + query` when the query is non-blank (`:81-87`) | `String` |
| `display_name`, `display_description` | ESAPI-encoded client name/description (`:88-89`) | `String` |
| `display_scopes`, `display_claims` | `JsonValue.toString()` (`:143,:160`) — **JSON text, not collections** | `String` |
| `display_scope` | raw scope-description list (`:147`) — read only by `wap/authorize.ftl` | `List<String>` |
| `user_name` | raw, **not** ESAPI-encoded (`:91`) — the only key carrying non-ASCII to the bytes | `String` |
| `xui` | `xuiState.isXUIEnabled()` (`:92`) — produced, read by no template | `Boolean` |
| `user_code` | `getParameter(USER_CODE)` (`:93`) — the device flow | `String`/null |
| `baseUrl` | `baseURLProviderFactory.get(realm).getRootURL(servletRequest)` (`:94-95`) | `String` |
| `saveConsentEnabled` | `consentRequired.isSaveConsentEnabled()` (`:96`) — **a real `Boolean`** (`<#if saveConsentEnabled >`) | `Boolean` |
| `csrf` | `csrfProtection.createCsrfToken(request)` (`:100`) — already neutral | `String` |
| `locale` | accepted-language names joined with `" "` (`:101-105`) | `String` |

Two sources need translating, and only two:

- **`target`** — Restlet reads the resource reference. The CHF equivalent is the **CHF `Request`'s** URI, not
  the servlet request's: `request.getUri().getPath()` + `"?" + request.getUri().getQuery()`. It must be the CHF
  URI because `ChfOAuth2Request.setQueryParameter`/`removeQueryParameterValue` write back through
  `Form.toRequestQuery(request)` (`ChfOAuth2Request.java:270-274`), exactly as the Restlet accessors mutate the
  resource reference — so a servlet-request reconstruction would silently drop query mutations. *(On the
  consent path itself no mutation has occurred — `alterMaxAge`/`removeLoginPrompt` fire only on the
  `ResourceOwnerAuthenticationRequired` path, `ResourceOwnerSessionValidator.java:183,344` — but sourcing
  `target` from the same place Restlet did removes the question rather than relying on that staying true.)*
  `HttpFrameworkServlet.createRequest` builds the CHF URI as
  `Uris.createNonStrict(scheme, null, serverName, serverPort, req.getRequestURI(), req.getQueryString(), null)`
  (`HttpFrameworkServlet.java:300-306`), so `getPath()` **includes the context path** —
  `/openam/oauth2/authorize`, matching the golden fixture's `target` exactly.
- **`locale`** — see finding 5.

Everything else transfers verbatim through `o2.getParameter(...)`, `o2.getHttpServletRequest()` and the
already-neutral `CsrfProtection`.

<a id="5--getacceptedlanguages-does-not-exist--the-consent-models-locale-key-has-no-neutral-source"></a>
### 5. ⚠ `getAcceptedLanguages()` does **not** exist — the consent model's `locale` key has no neutral source

[plan.md](plan.md)'s 3a bullet and the umbrella's 5b-1 section both say the consent locales come from
`getAcceptedLanguages()`. **No such method exists** on `OAuth2Request` (verified: the class declares
`getLocale()` and 17 other accessors, none of them this), and the only two callers of the Restlet
`getClientInfo().getAcceptedLanguages()` are `ConsentRequiredResource:102` and
`DeviceCodeVerificationResource:230` — i.e. precisely 5b-1 and 5b-2. So the accessor is a **5b-1a deliverable**,
not a consumed one.

`getLocale()` is not a substitute: it returns a single `Locale` (`ChfOAuth2Request.java:143-158`), while the
model needs the **full preference-ordered list of raw tags** joined with `" "` — `"en-GB en fr"` — and the raw
tag matters because the value is interpolated into the consent page's JavaScript (`${locale?js_string}`) for
XUI to pick translations. Round-tripping through `java.util.Locale` would normalise case and lose a `*`.

⇒ **D3**: add `List<String> getAcceptedLanguages()` to `OAuth2Request` (concrete, default empty) and implement
it on `ChfOAuth2Request` by parsing the raw `Accept-Language` header, **A/B'd against Restlet's own parser**
while Restlet is still on the classpath — the `RestletErrorParityTest` pattern
([chf-patterns §13](chf-patterns.md#13-the-3-way-golden-oracle-phase-3c--how-parity-survives-restlets-deletion)).

<a id="6--consentrequiredresource-is-shared-with-the-device-flow--on-chf-it-must-become-a-collaborator-not-a-base"></a>
### 6. `ConsentRequiredResource` is shared with the device flow — on CHF it must become a collaborator

`DeviceCodeVerificationResource extends ConsentRequiredResource` (`:81`) and calls the **same**
`getDataModel(e, request)` + `authorize.ftl` render (`:197-198`) for the device flow's consent step. On Restlet
the sharing mechanism was inheritance; on CHF the superclass slot is taken by
`AbstractOAuth2HttpBrowserEndpoint` (which carries the `@ExceptionHandler` that must not be overridden), and
Java has single inheritance. ⇒ the consent page becomes an **injected collaborator**, `ConsentPageRenderer`,
built in 5b-1b and consumed unchanged by 5b-2 (**D5**).

One field of `ConsentRequiredResource` does **not** survive: `resourceOwnerSessionValidator` (`:55,:64`) is
assigned and never read — `CsrfProtection` holds its own. Drop it (the `TokenIntrospectionResource` dead-field
precedent, [phase-5a-2 D6](phase-5a-2.md#d6)).

<a id="7--the-success-path-collapses-onto-redirecturis--with-one-documented-edge"></a>
### 7. The success path collapses onto `RedirectUris` — with one documented edge

`OAuth2Representation.toRepresentation` (`:148-173`) does three things: build a `Form` from
`AuthorizationToken.getToken()`, place it in the **fragment** (`setFragment`, replaces) or the **query**
(`addQueryParameter`, appends) per `authorizationToken.isFragment()`, and then either render
`FormPostResponse.ftl` (when `response_mode == form_post`, `:189-191`) or run a
`Redirector(MODE_CLIENT_FOUND)` = **302**.

That is `RedirectUris.compose(redirectUri, token.getToken(), isFragment ? FRAGMENT : QUERY)` exactly —
fragment replaces, query appends, encoding parity already proven ([plan.md](plan.md) risk #3, closed). Two notes:

- **`RedirectUris`' documented empty-params divergence is unreachable here.** Its javadoc flags that an empty
  map leaves the target untouched (where Restlet's `setFragment("")` would clear an existing fragment) and asks
  Phase 5b to decide. `AuthorizationToken` comes from `tokenIssuer.issueTokens` and always carries at least the
  code or the access token, so the empty case cannot arise on the success path. **Decision: leave `RedirectUris`
  unchanged**; pin the reasoning with a test asserting a one-entry token map still composes.
- **[D11](decisions.md) applies to the success redirect too.** Restlet ran the composed target through the
  `Redirector`'s `Template`, deleting unbound `{...}` sequences; CHF sets `Location` verbatim. On the success
  path the target has been validated by `authorize()`, so a braced URI is not reachable through a registered
  client — but the divergence is the same one D11 already accepted.

<a id="8--the-hook-seam-authorize-needs-both-halves-and-cannot-un-write-a-servlet-cookie"></a>
### 8. The hook seam: `/authorize` needs **both** halves, and cannot un-write a servlet cookie

`AuthorizeRequestHook` (`org.forgerock.oauth2.restlet`) has two Restlet-typed methods, both invoked by
`AuthorizeResource` on both verbs: `beforeAuthorizeHandling` (`:102-104`, `:166-168`) before anything, and
`afterAuthorizeSuccess` (`:114-116`, `:181-183`) after the representation is built. Sole impl `LoginHintHook`,
which already implements the CHF `ChfTokenRequestHook` from 5a-1 — including a working servlet-response
cookie-delete (`LoginHintHook.java`, `afterTokenHandling(OAuth2Request)`). The 5a-1 **cookie spike proved
servlet-response cookies survive `HttpFrameworkServlet`'s write-back**
([phase-5a-1 as-built step 0](phase-5a-1.md#step-0--cookie-spike-cookie-survives--neutral-signature-aftertokenhandlingoauth2request-2026-07-24)),
so the neutral signature stands here too.

One asymmetry has no CHF equivalent: `afterAuthorizeSuccess` first **removes** the `Set-Cookie` that
`beforeAuthorizeHandling` just added to the Restlet response's `CookieSetting` series, then adds the max-age-0
delete. A `jakarta.servlet.http.HttpServletResponse` has no cookie-removal API. ⇒ **D6**: the CHF impl emits
both headers — the set from `before`, then the max-age-0 delete from `after`. The browser applies them in order
and the end state is identical (the cookie is gone); the wire carries one extra `Set-Cookie` on the
authorize-success response. A documented 5d-1 byte-diff, not a behaviour change.

<a id="9--display-and-the-two-illegalargumentexception-sources"></a>
### 9. `?display=` and the two `IllegalArgumentException` sources

`FreemarkerTemplateRenderer.renderForDisplay` throws `IllegalArgumentException` from `Enum.valueOf` for an
unknown display, deliberately preserved so 5b can map it ([3c-1 D7](phase-3c-1-renderer.md)). Today that IAE is
raised **inside** `AuthorizeResource`'s `catch (ResourceOwnerConsentRequired)` block (`:130-132`), and a sibling
`catch` does not protect a `catch` body — so it escapes to `doCatch` →
`ExceptionHandler.handle(Throwable, Context, Request, Response)` (`:74-92`), which wraps a non-`OAuth2RestletException`
cause in `new ServerException(throwable)` → **400 `server_error`, rendered as the HTML error page** (`:132-137`,
no redirect URI ⇒ the page branch). The *other* IAE source — `authorizationService.authorize(...)`, whose javadoc
declares `IllegalArgumentException If the request is missing any required parameters` — is caught on GET
(`:120-126`) and not on POST, giving the split in finding 3.

⇒ three inputs, three different current answers (`400 invalid_request` + open redirect / `400 invalid_request`
error page / `400 server_error` error page). **D7** unifies them.

<a id="10--the-consent-model-reads-the-query-only-and-its-build-order-is-load-bearing"></a>
### 10. ⚠ The consent model reads the **query only**, and its build order is load-bearing (review, 2026-07-25)

`getDataModel` builds the map in three ordered phases (`ConsentRequiredResource.java:79-107`), and each phase
boundary matters:

```java
Map<String, Object> data = new HashMap<>(getRequest().getAttributes());  // 1. attributes
data.putAll(getQuery().getValuesMap());                                  // 2. QUERY overlay — wins
… data.put("target", …); data.put("display_name", …); addDisplayScopesAndClaims(data); …  // 3. derived
```

Two consequences a `getParameter`-based port gets **backwards**:

- **`getQuery().getValuesMap()` is the query string only — never the POST body.** `ChfOAuth2Request.getParameter`
  falls through query → **form body** on a POST (`:98-104`). That is invisible on `/authorize` (its consent page
  is only reached on GET) but **not** on the device flow: `DeviceCodeVerificationResource` renders the same
  `authorize.ftl` with the same `getDataModel` from inside its **`@Post`** method (`:128`, `:197-198`), so a
  `getParameter`-based renderer would populate the consent model with form-body values Restlet never put there.
  Since `ConsentPageRenderer` is shared with 5b-2 (finding 6), it must read those keys through
  **`o2.getQueryParameter(name)`** (`ChfOAuth2Request:219-221`), which is query-only by construction.
- **Query overlays attributes** — `putAll` after the attribute seed. `getParameter` has the *opposite*
  precedence (attributes first, `:87-90`), so a request carrying `?realm=alpha` puts the raw query value in
  today's model where `getParameter` would return the router-resolved path. Narrow (non-canonical realm
  spellings) but real. **Locked 2026-07-25: reproduce the overlay.**
- **Phase 3 must come after phase 2.** `addDisplayScopesAndClaims` carries an explicit comment
  (`:144-146`) that `display_scope` is set **after** the raw query copy *so an attacker cannot supply
  `display_scope` themselves*. Building the derived keys first and overlaying the query afterwards would
  reintroduce that injection. The port keeps the three phases in order (D5).

<a id="11--the-three-level-base-hierarchy-is-safe--and-the-obvious-alternative-is-not"></a>
### 11. The three-level base hierarchy is safe — and the obvious alternative is fragile

Verified in `AnnotatedMethod.java`: `findExceptionHandlers` scans `requestHandler.getClass().getMethods()`
(`:233`), which **includes inherited public methods**, so an `@ExceptionHandler` declared on a middle-level base
is discovered on every leaf handler — D1's `AbstractOAuth2HttpEndpoint` → two sibling bases → handlers works
as designed. Guice member injection likewise walks the whole hierarchy, so the `@Inject` fields may live on the
grandparent.

The alternative — `AbstractOAuth2HttpBrowserEndpoint extends AbstractOAuth2HttpJsonEndpoint`, overriding
`onError` — *would* work, but only by accident: `getMethods()` returns the override and hides the base method,
so there is exactly one candidate and `:246`'s "More than one @ExceptionHandler for <type>" never fires. It
depends entirely on the override being **re-annotated** (Java drops annotations on an override), and if that is
ever forgotten the endpoint silently loses its mapper and every OAuth2 error becomes a framework CREST 500.
Modelling "browser endpoint IS-A JSON endpoint" to save one file is not worth standing on that.

**Test-scaffolding consequence:** [chf-patterns §5](chf-patterns.md#5-chf-handler-test-scaffolding)'s recipe
("set the `@Inject` fields by walking the class hierarchy with reflection") now spans **three** levels. The
walk must not stop at the first superclass.

<a id="12--the-e2e-environment-cannot-currently-reach-a-consent-page"></a>
### 12. ⚠ The e2e environment cannot currently reach a consent page (review, 2026-07-25)

`ensureOAuth2ServiceExists` creates the provider with `clientsCanSkipConsent: true`, and **both** e2e clients
(`test_client_app`, `test_client_confidential`) are created with `isConsentImplied: true`
(`e2e/oauth2/oauth2-test.spec.mjs`). `AuthorizationService:166-167` computes
`requireConsent = !clientsCanSkipConsent || !clientRegistration.isConsentImplied()` — false for both ⇒
**`ResourceOwnerConsentRequired` is never thrown in e2e today**, so rows 2 and 9 of the 5-E2 table are
unreachable as the fixtures stand.

⇒ 5-E2 adds a **third client**, `test_client_consent`, with `isConsentImplied: false` (which makes
`requireConsent` true regardless of the service flag, so it does not depend on the service already existing with
the right config) and `responseTypes: [code, token]`, so rows 5 and 6 — the query-vs-fragment error
composition — are reachable from the same fixture. Additive; no existing row changes behaviour. 5b-2's
device-flow consent reuses it.

## Design decisions

<a id="d1"></a>
### D1 — Extract `AbstractOAuth2HttpEndpoint`; the browser base is its sibling, not its subclass

`AbstractOAuth2HttpJsonEndpoint` already owns three things both bases need: the two `@Inject` fields
(`requestFactory`, `errorResponseFactory`), the overridable `withErrorHeaders` hook (5a-2 D1) and the
`noCache(Response)` helper whose exact header strings are a **wire contract**. Duplicating them into the browser
base invites drift on precisely the bytes the 5d-1 diff checks.

```
AbstractOAuth2HttpEndpoint            (fields + withErrorHeaders + noCache — no @ExceptionHandler)
├── AbstractOAuth2HttpJsonEndpoint    @ExceptionHandler → toJsonResponse           (5a, unchanged behaviour)
└── AbstractOAuth2HttpBrowserEndpoint @ExceptionHandler → redirect / error page    (5b-1a, new)
```

The two `@ExceptionHandler`s stay on the concrete bases — they are siblings, so there is no override and no
annotation loss ([chf-patterns §2](chf-patterns.md#2-endpointsfrom--semantics-that-matter)); the framework
discovers them on inherited public methods, so every subclass keeps its mapper. The edit to
`AbstractOAuth2HttpJsonEndpoint` is a pure move of three members to a new superclass, guarded by the existing
42-test `http` suite.

*Alternative rejected:* leave the JSON base untouched and copy the members. Eight duplicated lines, two of which
are literal header values that must never diverge — the cost of the extract is lower than the cost of the
drift.

<a id="d2"></a>
### D2 — `AbstractOAuth2HttpBrowserEndpoint`: mayRedirect ⇒ 302, else the page — and the location comes from the error

```java
public abstract class AbstractOAuth2HttpBrowserEndpoint extends AbstractOAuth2HttpEndpoint {

    @ExceptionHandler
    public Response onError(OAuth2Exception e, @Contextual Context ctx, @Contextual Request request) {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        OAuth2Error err = OAuth2Error.of(e).withState(o2.<String>getParameter("state"));
        String redirectUri = o2.getParameter(OAuth2Constants.Params.REDIRECT_URI);
        if (OAuth2Error.mayRedirect(e) && !isEmpty(redirectUri)) {
            err = err.redirectingTo(redirectUri, err.getParameterLocation());
        }
        return withErrorHeaders(errorResponseFactory.toResponse(o2, err));
    }
}
```

⚠ **Two corrections to the umbrella's pseudocode** ([phase-5-oauth2.md](phase-5-oauth2.md) "Two bases, not one"),
both verified against the shipped API:

1. `redirectingTo` takes **two** arguments — `redirectingTo(String, UrlLocation)` (`OAuth2Error.java:261`).
   There is no single-argument overload. The location must be `err.getParameterLocation()`, which
   `OAuth2Error.of` already populated from `exception.getParameterLocation()` — dropping it would send every
   implicit-flow error to the query string where Restlet used the fragment.
2. The umbrella's version calls `toResponse` on **two** separate branches; one call after an optional
   `redirectingTo` is the same thing with one exit. `toResponse` already dispatches on `hasRedirectUri()` +
   `isRedirectUriFromException()` (`OAuth2ErrorResponseFactory.java:94-110`), so the login-redirect 301, the
   error 302 and the HTML page all fall out of that single call — and [D13](decisions.md)'s pin means a
   `ResourceOwnerAuthenticationRequired` cannot be retargeted even if a future subclass gets the guard wrong.

`withErrorHeaders` defaults to no headers (5a-2 D1); `AuthorizeHandler` overrides it to `noCache` because
`/authorize` is one of the two endpoints the Restlet `OAuth2Filter` stamped (finding 2).

<a id="d3"></a>
### D3 — `getAcceptedLanguages()`: a new neutral accessor, A/B'd against Restlet's parser

Add to `OAuth2Request` (modified in place, `Portions` line):

```java
/** The Accept-Language tags in preference order, raw as the client sent them. Empty when absent. */
public List<String> getAcceptedLanguages() {
    return Collections.emptyList();
}
```

`ChfOAuth2Request` overrides it, parsing the raw header into `(token, q)` pairs and returning the tokens in
descending-q order, ties broken by header order. `RestletOAuth2Request` is **not** touched — nothing on the
Restlet path calls the neutral accessor (`ConsentRequiredResource` keeps its own loop until 5d-2), and the
oracle does not need it: the parity test drives Restlet's `ClientInfo.getAcceptedLanguages()` **directly**, the
way `RestletErrorParityTest` drives `ExceptionHandler` directly.

**The exact ordering/`*` semantics are settled by observation, not by reading Restlet's parser.** The parity
test A/Bs a table of headers — `"en"`, `"en-GB,en;q=0.8,fr;q=0.9"`, `"*"`, `"en;q=0"`, an empty header, an
absent header, a malformed one — and the implementation is written to match what Restlet actually produced.
Whatever cannot be matched is recorded as a divergence in this doc's As-built and in the 5d-1 smoke matrix
rather than papered over. `ChfOAuth2Request.getLocale()` is left alone: it has its own contract and its own
tests.

<a id="d4"></a>
### D4 — `ChfAuthorizeRequestHook` + `LoginHintHook` triple-impl

```java
package org.openidentityplatform.openam.oauth2.http;
public interface ChfAuthorizeRequestHook {
    void beforeAuthorizeHandling(OAuth2Request o2request);
    void afterAuthorizeSuccess(OAuth2Request o2request);
}
```

Neutral signature, per the 5a-1 cookie-spike outcome (finding 8). `LoginHintHook` implements
`AuthorizeRequestHook`, `TokenRequestHook`, `ChfTokenRequestHook` **and** `ChfAuthorizeRequestHook`; the two CHF
authorize methods read/write the `oidcLoginHint` cookie through `getHttpServletRequest()`/
`getHttpServletResponse()`, reusing the private `hasLoginHintCookie` helper the CHF token method already added.
`OAuth2GuiceModule` gains a fourth Multibinder beside the existing three. Both Restlet interfaces and their
`LoginHintHook` methods die at **5d-2**, not here — `AuthorizeResource` is still live.

<a id="d5"></a>
### D5 — `ConsentPageRenderer`: the shared consent collaborator (composition, not inheritance)

```java
@Singleton
public class ConsentPageRenderer {
    @Inject ConsentPageRenderer(FreemarkerTemplateRenderer renderer, XUIState xuiState,
            BaseURLProviderFactory baseURLProviderFactory, CsrfProtection csrfProtection) { … }

    /** The consent page at 200, rendered for the request's ?display=. */
    public Response render(ResourceOwnerConsentRequired consentRequired, OAuth2Request o2, Request request)
            throws IOException, TemplateException { … }

    @VisibleForTesting
    Map<String, Object> dataModel(ResourceOwnerConsentRequired consentRequired, OAuth2Request o2,
            Request request) { … }
}
```

Port `ConsentRequiredResource.getDataModel` + `addDisplayScopesAndClaims` **verbatim in behaviour**, key for key
per finding 4, including the ordering quirk `RendererFixtures.addDisplayScopesAndClaims` documents (the scope
object is added to the array *before* `values` is put on it). Two translations only: `target` from
`request.getUri()` (finding 4) and `locale` from `getAcceptedLanguages()` joined with `" "` via the existing
`OAuth2Utils.joinStatic` (D3). Drop the dead `resourceOwnerSessionValidator` (finding 6).

**Build it in the producer's three phases, in order** (finding 10 — this is the correction the review added,
and it is the difference between a faithful port and a subtly wrong one):

1. **Attributes.** `realm` from `o2.getAttribute(Custom.REALM)` (seeded from `RealmContext`), plus any URI
   template variables.
2. **Query overlay — query wins.** **Enumerate** the keys (R-5.5) — `realm`, `redirect_uri`, `scope`, `state`,
   `nonce`, `acr`, `response_type`, `client_id`, `ui_locales` — reading each through
   **`o2.getQueryParameter(name)`**, *not* `getParameter`. Query-only is the contract
   (`getQuery().getValuesMap()`), and it is load-bearing for 5b-2, whose device flow renders this same page
   from a **POST** where `getParameter` would leak form-body values into the model. **Omit** a key whose value
   is null, so the templates' `<#if x??>` guards behave as they do today — a Restlet `getValuesMap()` never
   contains an absent parameter.
3. **Derived keys, strictly last** — `target`, `display_name`/`display_description`, `display_scopes`/
   `display_claims`/`display_scope`, `user_name`, `xui`, `user_code`, `baseUrl`, `saveConsentEnabled`, `csrf`,
   `locale`. Phase 3 **must** follow phase 2: `ConsentRequiredResource:144-146` records that `display_scope` is
   written after the query copy specifically so a client cannot supply its own. Reversing the phases
   reintroduces that injection.

`dataModel` is `@VisibleForTesting` so the golden assert can drive it without a `Response`.

Exposing it as an injected collaborator rather than a base class is forced by finding 6, and is what lets 5b-2
reuse it with no further work.

<a id="d6"></a>
### D6 — the login-hint cookie is set **and** deleted on an authorize success (**locked 2026-07-25; premise corrected 2026-07-26**)

Finding 8. `LoginHintHook`'s CHF `afterAuthorizeSuccess` cannot retract the `Set-Cookie` its
`beforeAuthorizeHandling` wrote, so a successful authorize carrying a `login_hint` emits two `Set-Cookie`
headers for `oidcLoginHint` (set, then max-age-0). End state identical. Asserted in the `LoginHintHook` CHF
test; recorded for the 5d-1 byte-diff, and **captured live in 5-E2 row 9b**.

⚠ **The "where Restlet emitted one" half was wrong** — corrected by the 5-E2 capture
([as-built](#as-built-5-e2--recorded-2026-07-26)). Restlet's `afterAuthorizeSuccess` retracts the `CookieSetting`
and then calls `removeCookie`, which emits the delete **only if the request carried the cookie**
(`LoginHintHook.java:67-75`, `:116-123`). Observed:

| Case | Restlet emits | CHF must emit |
|---|---|---|
| consent page (no success) + `login_hint` | `oidcLoginHint=demo; Path=/; HttpOnly` | the same |
| success + `login_hint`, **no prior cookie** | **nothing** | set **+ delete** |
| success, prior cookie present | one `oidcLoginHint=; Expires=<past>` (no `Path`, no `HttpOnly`) | set + delete |

⇒ the CHF `afterAuthorizeSuccess` must emit the max-age-0 delete **unconditionally when its before-hook set the
cookie**, not behind the `hasLoginHintCookie(request)` guard the CHF `afterTokenHandling` uses. With that guard
the no-prior-cookie success would emit the set and no delete, leaving `oidcLoginHint` **set in the browser** —
an end-state divergence, not merely an extra header. Second, smaller diff: Restlet's delete carries neither
`Path` nor `HttpOnly` (so it cannot actually clear the `Path=/` cookie it set); the CHF delete sets both, per
the 5a-1 `afterTokenHandling` precedent. Both go in the 5d-1 smoke matrix.

*Alternative rejected (user-confirmed 2026-07-25):* buffering the cookie on a request attribute and flushing it
only on the non-success paths. That invents machinery to hide a difference the browser cannot observe.

<a id="d7"></a>
### D7 — `IllegalArgumentException` → one non-redirecting 400 `invalid_request` (**locked 2026-07-25**)

Findings 3 and 9 leave three current answers for an IAE. Unify to **400 `invalid_request`, rendered as the HTML
error page, never redirected**, on both verbs and from both sources. **User-confirmed 2026-07-25** over the two
strict-parity alternatives (keep GET's redirect, or keep both verbs' drift).

**Scope: one `try`/`catch` around the whole handler-method body**, not per call. It must cover
`authorizationService.authorize(...)`, `redirectUriResolver.resolve(...)`, `RedirectUris.compose(...)`, the
consent render (where `renderForDisplay`'s `?display=bogus` IAE arises — finding 9) and the form-post render.
That is *simpler* than Restlet's structure, where the display IAE escaped the `catch` it was raised inside, and
it is what makes the three inputs converge on one answer:

```java
} catch (IllegalArgumentException e) {
    // Not routed through the base: mayRedirect() is keyed on exception type, and this is the one
    // 400 whose *policy* is "never redirect" while its type (InvalidRequestException) is redirectable.
    return withErrorHeaders(errorResponseFactory.toResponse(o2,
            OAuth2Error.of(400, "invalid_request", e.getMessage())
                    .withState(o2.<String>getParameter("state"))));
}
```

Rationale, in [D6](decisions.md)'s own terms — the safe union of what GET and POST each refused: POST does not
redirect an IAE at all, so the union refuses it. That **closes a second open redirect**: GET today sends a
malformed-parameter error to a `redirect_uri` that, the request having failed validation, was never checked
against the client's registered set. The two error-code changes it carries (`server_error` → `invalid_request`
on the POST and `?display=bogus` paths) make the wire *more* truthful, and `invalid_request` is exactly what
[3c-1 D7](phase-3c-1-renderer.md) asked 5b to map the display IAE to.

⚠ **A deliberate behaviour change at 5d-1** — sibling of [D6](decisions.md), belongs in the same smoke-matrix
row. It is **not** in the §E lock (the lock records reproduction only).

<a id="d8"></a>
### D8 — method and content-type validation: recorded first, then reproduced

Gated on 5-E2 (finding 2). **Resolved 2026-07-26 by the recorded rows** — both filter errors survive the
CONTINUE fall-through, exactly as `GET /access_token` did in 5-E:

| Row | Observed on live Restlet | Consequence for `AuthorizeHandler` |
|---|---|---|
| 7 — `PUT /oauth2/authorize` | **405** `application/json` `{"error_description":"Required Method: GET or POST found: PUT","error":"method_not_allowed"}` + `no-store`/`no-cache` | **No verb check.** The `@Get`/`@Post`-only handler's framework 405 matches on status; the body code becomes `invalid_request` via `OAuth2ErrorFilter` — a 5d-1 body divergence, not a status one |
| 8 — `POST` with `Content-Type: application/json` | **400** `application/json` `{"error_description":"Invalid Content Type","error":"invalid_request"}` + `no-store`/`no-cache` | **Reproduce the content-type check** with the 5a-1 recipe (empty-body early-return, case-insensitive `FORM_URLENCODED` compare) and **return** — never fall through |

The decision tree that produced those answers, kept for the record:

- **Verb.** A handler with only `@Get` and `@Post` returns the framework **405** for PUT/DELETE with no verb
  check ([chf-patterns §2](chf-patterns.md#2-endpointsfrom--semantics-that-matter)), and the CREST 405 body is
  rewritten by `OAuth2ErrorFilter` to `invalid_request` at 5d-1 — the same `method_not_allowed` →
  `invalid_request` body-code divergence 5-E already locked for `GET /access_token`. **No verb check in the
  handler**, whatever the oracle says about the status.
- **Content type.** If the oracle shows the filter's 400 `invalid_request` **survives** on a JSON-bodied POST,
  reproduce it in the handler with the charset-safe, empty-body-tolerant recipe 5a-1 settled
  (`request.getEntity().isRawContentEmpty()` early-return, then
  `FORM_URLENCODED.equalsIgnoreCase(ContentTypeHeader.valueOf(request).getType())` —
  [chf-patterns §5](chf-patterns.md#5-chf-handler-test-scaffolding)). If it shows the request **proceeded**
  (the CONTINUE bug winning), the check is dead code on the wire: **do not port it**, and record the
  no-op removal here. Either way the handler **returns** — it never reproduces the fall-through
  ([phase-3c-2](phase-3c-2-error-layer.md) "Recorded for Phase 5a").
- **Cache headers.** Unconditional, both verbs, success *and* error: `noCache` on every returned `Response` and
  `withErrorHeaders` overridden to `noCache` (finding 2, D1).

<a id="d9"></a>
### D9 — `AuthorizeHandler`: two verbs, one success path, one consent path

```java
public class AuthorizeHandler extends AbstractOAuth2HttpBrowserEndpoint {

    @Get public Response authorize(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
    @Post public Response consent(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
}
```

Both verbs: build `o2 = requestFactory.create(ctx, request)` (the `(Context, Request)` overload, one cached
instance shared with the 5d filters), run `beforeAuthorizeHandling` on every `ChfAuthorizeRequestHook`, call
`authorizationService.authorize(o2)` (GET) or `authorize(o2, consentGiven, saveConsent)` (POST, with
`consentGiven = "allow".equalsIgnoreCase(decision)` and `saveConsent = "on".equalsIgnoreCase(save_consent)` —
verbatim from `AuthorizeResource:170-171`), then the shared success tail:

1. `redirectUri = redirectUriResolver.resolve(o2)`;
2. `response_mode == form_post` → render `templates/FormPostResponse.ftl` with
   `{redirectUri: <composed>, formValues: token.getToken()}` at **200**; else **302** with
   `Location = RedirectUris.compose(redirectUri, token.getToken(), token.isFragment() ? FRAGMENT : QUERY)`
   (finding 7). ⚠ The composed reference is what `FormPostResponse.ftl` receives as `redirectUri` too —
   `OAuth2Representation:164-165` composes **before** branching, so form_post posts to the URI *with* the
   parameters already on it. Reproduce that ordering, do not "clean it up";
3. run `afterAuthorizeSuccess` on every hook;
4. `noCache` and return.

The GET path additionally catches `ResourceOwnerConsentRequired` (a plain `Exception`, so it cannot reach the
base) → `noCache(consentPageRenderer.render(e, o2, request))`. The POST path does **not**: the 3-arg
`authorize` cannot raise it (finding 3). Both catch `IllegalArgumentException` per D7 and let every
`OAuth2Exception` reach the base. `IOException`/`TemplateException` from a render become
`new ServerException(e)` so the status stays a contractual 400 rather than the framework's 500
([D3](decisions.md) applies to *bug* paths only; a missing template is a deployment fault the error page can
still describe).

## New / modified / tests

### 5-E2 — test-only

- `e2e/oauth2/oauth2-test.spec.mjs` — `ensureConsentClientExists` (`test_client_consent`, finding 12) wired
  into the existing `beforeAll`, plus a new
  `describe("OAuth2 /authorize contract lock (5-E, live Restlet)")` carrying the 9 rows.

### 5b-1a — the browser substrate

**New** (`org.openidentityplatform.openam.oauth2.http`): `AbstractOAuth2HttpEndpoint` (D1),
`AbstractOAuth2HttpBrowserEndpoint` (D2), `ChfAuthorizeRequestHook` (D4).
**Modified in place**: `AbstractOAuth2HttpJsonEndpoint` (members move to the new parent — our own 2026 class, no
`Portions` line), `OAuth2Request` + `ChfOAuth2Request` (D3 accessor; `OAuth2Request` gains a `Portions` line),
`LoginHintHook` (D4), `OAuth2GuiceModule` (D4 Multibinder).

### 5b-1b — the handler

**New**: `ConsentPageRenderer` (D5), `AuthorizeHandler` (D8, D9).

### Tests (openam-oauth2; TestNG + Mockito + AssertJ; scaffold per [chf-patterns §5](chf-patterns.md#5-chf-handler-test-scaffolding))

**5b-1a**

- **`AbstractOAuth2HttpBrowserEndpointTest`** — a trivial subclass driven through `Endpoints.from(handler)`
  (the `Object` overload, so the base mapper really runs), asserting all three branches of one `onError`:
  - `ResourceOwnerAuthenticationRequired(loginUri)` → **301**, `Location` == the login URI **verbatim**, no
    error parameters, and — the adversarial row — unchanged even when `redirect_uri=https://evil/` is on the
    request ([D13](decisions.md));
  - a redirectable `OAuth2Exception` + `redirect_uri` → **302**, parameters in the **query**; the same with
    `UrlLocation.FRAGMENT` on the exception → parameters in the **fragment** (the D2 correction — a test that
    passes with a dropped location argument is not testing this);
  - each `NEVER_REDIRECT` type + `redirect_uri` → the **HTML error page**, `Content-Type: text/html; charset=UTF-8`;
  - `state` echoed in every non-login branch; `withErrorHeaders` default adds nothing, and an overriding
    subclass stamps `no-store`/`Pragma`.
- **`ChfOAuth2RequestTest`** (extended) — `getAcceptedLanguages()` over the D3 header table, plus absent header
  → empty list, and that `getLocale()` is unaffected.
- **`RestletAcceptLanguageParityTest`** — the A/B oracle (D3): the same header table through Restlet's
  `ClientInfo.getAcceptedLanguages()` and through `ChfOAuth2Request`, asserted equal. Legitimately imports
  Restlet (a parity test, exempt from the grep gate until 5d-2), and degrades to deletion at 5d-2.
- **`LoginHintHookTest`** (extended) — CHF `beforeAuthorizeHandling` writes the cookie only when `login_hint`
  differs from the existing cookie; `afterAuthorizeSuccess` writes the max-age-0 delete; both together emit two
  `Set-Cookie`s (D6). Existing Restlet-path tests stay green.

**5b-1b**

- **`ConsentPageRendererTest`** — the load-bearing one: `dataModel(...)` built from a real `ChfOAuth2Request`
  over a `RootContext → AttributesContext → RealmContext → UriRouterContext` chain and a real
  `ResourceOwnerConsentRequired`, asserted **key-for-key and type-for-type against `RendererFixtures.authorize()`**
  (finding 4) — that fixture is the producer-derived golden model, so this is the only assertion that can catch
  a silently-empty model (R-5.5). Plus: **a POST whose form body carries a different `scope`/`state` than the
  query — the query values must win and the body must not appear** (finding 10 / R-5b1.9, the assertion that
  protects 5b-2's device flow); `?realm=alpha` overrides the resolved realm attribute (the locked overlay);
  `display_scope` is written after the query copy; `target` includes the context path and the query
  (`/openam/oauth2/authorize?…`) and survives a `setQueryParameter` mutation; an absent optional parameter is
  **omitted**, not null-valued; `locale` is the space-joined tag list; the rendered page is 200 + `text/html; charset=UTF-8`; a **non-ASCII `user_name`**
  round-trips as UTF-8 bytes (risk #21 — the templates are ASCII, so only a non-ASCII *model* catches it);
  `?display=touch` resolves `templates/touch/authorize.ftl`, `?display=popup` composes the wrapper.
- **`AuthorizeHandlerTest`** — driven through `Endpoints.from(handler)`:
  - **success GET, `response_type=code`** → 302, `Location` == redirect_uri + **query** parameters, `no-store` +
    `Pragma`, `afterAuthorizeSuccess` called **once**, `beforeAuthorizeHandling` called once **before** the
    service;
  - **success, `isFragment()`** → parameters in the **fragment**, target's existing fragment replaced (R-5.4);
  - **`response_mode=form_post`** → 200 HTML, `redirectUri` in the model is the **composed** target (D9 step 2),
    `formValues` == the token map;
  - **POST** → `decision=allow`/`save_consent=on` mapping asserted on the 3-arg `authorize` call; `decision=deny`
    → the `AccessDeniedException` the service raises reaches the base and redirects;
  - **consent** → `ResourceOwnerConsentRequired` on GET renders the page at 200 (delegating to
    `ConsentPageRenderer`, verified by interaction), and is **not** reachable on POST;
  - **the collapse table (finding 3)** — one row per exception: `ResourceOwnerAuthenticationRequired` → 301
    login; `InvalidClientException`/`RedirectUriMismatchException`/`DuplicateRequestParameterException`/
    `CsrfException`/`OAuth2ProviderNotFoundException` → error page with the exception's own `(status, error)`;
    a generic `OAuth2Exception` + `redirect_uri` → 302. The `OAuth2ProviderNotFoundException`-on-POST row is
    labelled as the [D6](decisions.md) change;
  - **D7** — an IAE from the service (with and without `client_id` in the message) and an IAE from
    `renderForDisplay` (`?display=bogus`) all → 400 `invalid_request` error page, **no `Location` header**;
  - **cache headers on the error path** (`withErrorHeaders` override) and on every success path;
  - **`state`** echoed in every error body.
- **Gate:** `grep -rn "org.restlet\|getCurrent()"` over the 5 new main files → 0 (`LoginHintHook` and the parity
  test are exempt, as in 5a-1).

## Integration testing

5b-1 ships **no route**, so there is no `OAuth2HttpRouteProvider` to exercise — but unlike 5a there *is* a
worthwhile in-process composition test, because the browser base is the first thing in this migration whose
contract is a **3xx and an HTML body flowing through the framework and the error filter**. Three layers:

1. **Layer-2 — `AuthorizeRouteCompositionIT`** (new, openam-oauth2, modelled on the existing
   `OAuth2ErrorRouteCompositionIT`, which already proved `Endpoints.from` composition needs **no**
   `commons.guice:test` dependency — [finding #5](phase-5-oauth2.md#integration-testing)). Build
   `Handlers.chainOf(Endpoints.from(handler), new OAuth2ErrorFilter())` in process and dispatch real `Request`s,
   asserting what a unit test structurally cannot:
   - a **301** and a **302** produced by an `@ExceptionHandler` survive the framework **and** `OAuth2ErrorFilter`
     untouched (the filter keys on `≥400`, so a 3xx must pass through — pinned, not assumed);
   - the **HTML error page** is not rewritten into an OAuth2 JSON body by the filter (it guards on
     `Content-Type` before parsing — the one interaction that would silently destroy the page);
   - the consent page reaches the wire as **`text/html; charset=UTF-8`** with UTF-8 bytes;
   - a **PUT** to a `@Get`/`@Post`-only handler gives the framework 405, rewritten by the filter to
     `invalid_request` — pinning the D8 divergence *now*, in-process, so 5d-1's `OAuth2RouterIT` only has to
     confirm it.
   Runs on all 9 CI legs (failsafe on `verify`).
2. **Layer-4 e2e — 5-E2** (below). This is the step's *primary* guard, and the only one that can ever be
   recorded.
3. **Layer-3 Cargo boot** — not needed in 5b-1a/5b-1b (no route, no new Guice-bound route provider; the new
   Multibinder binding is exercised by the whole-reactor build). It returns as a 5d-1 gate.

### 5-E2 — the `/authorize` rows to record against live Restlet

Write **by observation**, against a live container built from this tree, before `AuthorizeHandler` exists. The
build-ahead changes do not touch the Restlet `/oauth2` path, so the capture is authoritative.

**Fixture first (finding 12):** add `ensureConsentClientExists` to the existing `beforeAll`, creating
`test_client_consent` — `isConsentImplied: false` (so `requireConsent` is true whatever the provider's
`clientsCanSkipConsent` says), `clientType: Public`, `responseTypes: [code, token]`, the same
`redirect_uri`/`scope` as the other fixtures. Without it, rows 2, 6 and 9 cannot be reached at all.

| # | Request | Client | Record |
|---|---|---|---|
| 1 | `GET /oauth2/authorize?client_id=…&response_type=code&redirect_uri=…&scope=…`, **no session** | either | status (expect 301), the **`Location` value** incl. the `goto` parameter's exact encoding, `Cache-Control`/`Pragma` |
| 2 | same, **authenticated**, consent not yet given | consent | status, `Content-Type`, that the body is the consent page, `Cache-Control`/`Pragma` |
| 3 | `GET /oauth2/authorize?client_id=<unknown>&…` | — | status, `Content-Type` (expect `text/html;charset=UTF-8`), the `error`/`error_description` visible in the page, absence of `Location` |
| 4 | `GET /oauth2/authorize?…&response_type=code` with a **registered but mismatched** `redirect_uri` | app | status + whether a `Location` is emitted at all (the no-auto-redirect policy) |
| 5 | an error reachable **after** validation with `response_type=code` (e.g. an unsupported `scope`) | app | 302 + error parameters in the **query** |
| 6 | the same with `response_type=token` | consent | 302 + error parameters in the **fragment** |
| 7 | `PUT /oauth2/authorize` | — | status + body (**finding 2** — do not predict; this is the 405-vs-overwrite question) |
| 8 | `POST /oauth2/authorize` with `Content-Type: application/json` | — | status + body (**finding 2** — decides [D8](#d8)) |
| 9 | consent `POST` with `decision=allow` + the page's `csrf` token | consent | 302, `Location`'s parameter placement, and the `Set-Cookie` headers (the [D6](#d6) baseline) |

> **As recorded (2026-07-26):** these 9 rows plus a **row 9b** that the observation forced — row 9's
> `Set-Cookie` capture had to split into three cookie states to expose the [D6](#d6) correction. Two
> environment facts constrain every row: the provider **enforces PKCE**, and on `/authorize` only the session
> **cookie** authenticates, not the `iPlanetDirectoryPro` header. See the
> [as-built](#as-built-5-e2--recorded-2026-07-26).

Rows 7 and 8 are the ones that *change the code being written*; rows 1–6 and 9 are the 5d-1 byte-diff baseline.
Row 9 has to scrape `csrf` (and `target`) out of row 2's rendered page — which is also a free check that the
consent page really carries them. Authenticate any second identity in a disposable `apiRequest.newContext()`
(the cookie-outranks-header trap, [../../test-infrastructure.md](../../test-infrastructure.md)).

## Verification criteria

**5-E2**

1. `npx playwright test e2e/oauth2` against a live container from this tree — the new rows green **and**
   the 7 existing 5-E rows still green.
2. Every row asserts a **recorded** value, not a predicted one; rows 7–8 are written after seeing the response.
3. The 3c oracles still green — `RestletRendererParityTest` + `RestletErrorParityTest` (`Restlet == golden ==
   CHF`), confirming the goldens are proven-legacy before any 5b main code lands.

**5b-1a**

4. `mvn -o -pl openam-oauth2 test` — new tests green; **existing suite unchanged and only larger** (5a-2b
   baseline **979** surefire: 963 after 5a-2a + 16 from 5a-2b — [phase-5a-2 as-built](phase-5a-2.md#as-built)).
   The **5a suite must stay green through the D1 extract** — `TokenEndpointHandlerTest` (22) and the 42-test
   `http` package suite are the guard that the moved members still behave.
5. `mvn -o -pl openam-oauth2 verify` — `AuthorizeRouteCompositionIT` green (`mvn test` skips `*IT`).
6. `grep -rn "org.restlet\|getCurrent()"` over the 3 new main files → 0.
7. `mvn -o -pl openam-oauth2 install -DskipTests` — so 5b-1b compiles against the new base.

**5b-1b**

8. `mvn -o -pl openam-oauth2 test` + `verify` — `ConsentPageRendererTest` and `AuthorizeHandlerTest` green;
   `RestletRendererParityTest` **still green** (the consent model is now produced by our code as well as the
   fixture — if they disagree, one of them is wrong).
9. `grep` gate over the 2 new files → 0.
10. Whole-reactor `mvn -o install -DskipTests` — **doclint is fatal**
    ([../../test-infrastructure.md](../../test-infrastructure.md)); the new Guice binding wires without breaking
    WAR assembly (handler bound, routed nowhere).
11. CI (`.github/workflows/build.yml`): JDK 11–26 × 3 OSes on the `features/**` push — free cross-version
    coverage of the UTF-8 HTML bytes and the `Accept-Language` parse.

**Success** = the `/authorize` live contract is recorded and re-runnable; both bases exist with the JSON base's
behaviour unchanged; `AuthorizeHandler` + `ConsentPageRenderer` reproduce the consent model key-for-key against
the golden fixture, compose success redirects per `isFragment()`, and collapse fourteen catch clauses into one
mapper with **exactly two** intended behaviour changes ([D6](decisions.md) and [D7](#d7)), each recorded for the
5d-1 smoke matrix.

## Risks (extends [phase-5-oauth2.md](phase-5-oauth2.md)'s register)

- **R-5b1.1 — the authorize oracle is never recorded (R-5.1).** If 5b-1 ships the handler without 5-E2, the
  301/302/consent contract has no live baseline and 5d-1's byte-diff has nothing to diff against; after 5d-1 it
  is unrecoverable. **Guard:** 5-E2 is a separate, *first* commit, and criterion 3 pins the 3c oracles at the
  same moment. ✅ **Retired 2026-07-26** — the rows are recorded ([as-built](#as-built-5-e2--recorded-2026-07-26)).
- **R-5b1.2 — the consent model renders empty (R-5.5).** Restlet seeded 9 OAuth2 parameters *implicitly* from
  the query map; an enumerating port that misses one turns a `<#if x??>` false and silently drops a field from
  the consent page. **Guard:** `ConsentPageRendererTest` asserts key-for-key against `RendererFixtures.authorize()`
  — the producer-derived model — rather than against a hand-written expectation.
- **R-5b1.3 — fragment-vs-query comes from the wrong source (R-5.4).** The success location is
  `AuthorizationToken.isFragment()`; the *error* location is the exception's `parameterLocation`. Crossing them
  breaks implicit/hybrid flows in a way no compiler catches. **Guard:** separate assertions for each, and the D2
  correction (the two-argument `redirectingTo`) has its own test.
- **R-5b1.4 — the D1 extract regresses 5a.** Moving `noCache`/`withErrorHeaders`/the injected fields to a new
  superclass could break member injection or the `@ExceptionHandler` discovery that `Endpoints.from` performs
  over inherited methods. **Guard:** the 5a-1/5a-2 suites are run unchanged as the first step of 5b-1a; the
  `http` package suite (42) must stay green before any new class is written.
- **R-5b1.5 — `Accept-Language` divergence (D3).** A different tag order or a dropped `*` changes the consent
  page's `locale`, and therefore which XUI translation the user sees — invisible in an English test.
  **Guard:** `RestletAcceptLanguageParityTest` A/Bs the real Restlet parser; anything unmatchable is recorded,
  not hidden.
- **R-5b1.6 — D7 is a behaviour change wearing a mechanical-port disguise.** Unifying the IAE handling closes an
  open redirect *and* changes two error codes. If it is not recorded it will look like a regression at 5d-1.
  **Guard:** [D7](#d7) is stated as a change, kept out of the §E lock, and added to 5d-1's smoke matrix beside
  [D6](decisions.md).
- **R-5b1.7 — build-ahead, no live guard (risk #19).** Dormant until 5d-1. **Guard:** unit + the composition IT
  + the golden oracle + the 5-E2 rows. Retired when `OAuth2RouterIT` wires the route.
- **R-5b1.9 — the consent model built with `getParameter` (finding 10).** It would pass every `/authorize` test
  — the page is only rendered on GET there — and then quietly corrupt 5b-2's device-flow consent page, which
  renders the same model from a **POST** whose form body `getParameter` reads and `getQuery().getValuesMap()`
  never did. It would also invert the `?realm=` precedence. **Guard:** `ConsentPageRendererTest` drives a
  **POST whose form body carries a different `scope`/`state` than the query** and asserts the query values win;
  the three build phases are asserted in order, including that `display_scope` is written last.
- **R-5b1.8 — `target` sourced from the servlet request.** It would look right in every test and silently drop
  query mutations, breaking the consent form's action URL on the `max_age`/`prompt=login` paths (risk #17).
  **Guard:** `target` is built from `request.getUri()` (finding 4), asserted with a mutated query in
  `ConsentPageRendererTest`.

## CHF / framework friction (per the "fix what we own" invitation)

Five touch points examined. **No `openam-http` change is needed** — which is itself the finding: F1–F4
([openam-http-framework.md](openam-http-framework.md)) already removed the sharp edges this step would
otherwise have hit. **One commons gap is real**, and is filed rather than fixed in-phase.

- **`@ExceptionHandler` returning a 3xx.** Works: the mapper's `Response` is passed through as built
  ([chf-patterns §2](chf-patterns.md#2-endpointsfrom--semantics-that-matter)); no framework status clamping
  exists. Pinned by the composition IT rather than assumed.
- **HTML bodies.** `FreemarkerTemplateRenderer.toHtmlResponse` sets `Content-Type` *before* the byte entity, so
  the ISO-8859-1 fallback (§6, risk #21) cannot bite. No change needed; F4 removed the `String`-return trap
  independently.
- **Sibling `@ExceptionHandler` bases (D1).** `AnnotatedMethod` discovers handlers on inherited public methods
  and dispatches most-specific-assignable; two sibling bases each declaring one is ordinary use, not a new
  requirement.
- **`Form.fromRequestEntity` charset trap** (commons backlog, [decisions.md](decisions.md#chf-cleanup-backlog)).
  `/authorize`'s POST body is read through `ChfOAuth2Request.getParameter`, which already parses the media type
  (`ChfOAuth2Request.java:300-302`) — the phase's locked route-around. Unchanged here; the commons fix stays on
  its own cadence.
- **⚠ NEW — `AcceptLanguageHeader` cannot return the raw language tags** (commons,
  `org.forgerock.http.header`). It exposes `getLocales(): PreferredLocales`, i.e. parsed `java.util.Locale`s,
  which is lossy for exactly this use: a `*` disappears, non-canonical case is normalised, and the q-ordering
  is re-derived rather than reported. The consent page interpolates the raw tags into JavaScript, so 5b-1a
  hand-parses the header in `ChfOAuth2Request.getAcceptedLanguages` instead (D3) and proves the result against
  Restlet's parser. **Proposed commons fix:** an accessor returning the raw tokens in preference order beside
  the existing `getLocales()` — purely additive. **Blast radius:** none (new method). **Status: filed to the
  [CHF cleanup backlog](decisions.md#chf-cleanup-backlog), deferred** — the hand-parse is ~15 lines, contained
  in one class we own, and adopting a new commons release inside a migration phase buys nothing here. Revisit
  when another consumer needs the same thing.

## Iterative execution steps

Nine steps, implemented one after another. Each leaves the tree green and is separately reviewable; the
**Done when** column is the gate for starting the next one. S1–S2 are test-only, S3–S6 land as commit **5b-1a**,
S7–S8 as commit **5b-1b**. Only S3 touches already-shipped code, and it touches no behaviour.

| # | Step | Deliverable | Done when |
|---|---|---|---|
| **S1** | ✅ **done** — **e2e consent fixture** (finding 12) | `ensureConsentClientExists` → `test_client_consent` (`isConsentImplied:false`, `responseTypes:[code,token]`), called from the existing `beforeAll` | the full `e2e/oauth2` spec is green with the new client created and no existing row's behaviour changed |
| **S2** | ✅ **done 2026-07-26** — **5-E2 — record the live `/authorize` contract** (gate) | 9 rows **+ row 9b** in `e2e/oauth2/oauth2-test.spec.mjs`, written **after** reading each real response ([as-built](#as-built-5-e2--recorded-2026-07-26)) | 23 green (10 new + the 13 existing); `RestletRendererParityTest` + `RestletErrorParityTest` green (27); **rows 7–8's answers written into [D8](#d8)** ⇒ S8 unblocked; [D6](#d6)'s premise corrected by row 9b |
| **S3** | ✅ **done** — **D1 — extract `AbstractOAuth2HttpEndpoint`** | the two `@Inject` fields, `withErrorHeaders` and `noCache` move to a new parent; `AbstractOAuth2HttpJsonEndpoint` keeps only its `@ExceptionHandler` | `mvn -o -pl openam-oauth2 test` — **979 surefire, byte-identical outcomes**; the 42-test `http` suite and `TokenEndpointHandlerTest` (22) green with **no test edited**. A pure refactor: if any assertion had to change, the extract is wrong |
| **S4** | ✅ **done** — **D3 — `getAcceptedLanguages()`** | the accessor on `OAuth2Request` (default empty) + the hand-parse on `ChfOAuth2Request`; `RestletAcceptLanguageParityTest` over the header table | the parity table is green **against Restlet's real parser** — and the implementation was adjusted to match what Restlet does, not the other way round. Anything unmatchable is written into As-built |
| **S5** | ✅ **done** — **D2 — `AbstractOAuth2HttpBrowserEndpoint`** | the browser `@ExceptionHandler` + `AbstractOAuth2HttpBrowserEndpointTest` driving a trivial subclass through `Endpoints.from` | all three branches asserted — 301 login (incl. the adversarial `redirect_uri=https://evil/` row), 302 **query and fragment** separately, error page per `NEVER_REDIRECT` type; `state` echo; `withErrorHeaders` default and override |
| **S6** | ✅ **done** — **D4 — the hook seam** | `ChfAuthorizeRequestHook`, `LoginHintHook` fourth impl, `OAuth2GuiceModule` Multibinder, `LoginHintHookTest` extension | CHF before/after cookie behaviour asserted incl. the [D6](#d6) double `Set-Cookie`; existing Restlet-path hook tests untouched and green |
| **S6a** | ✅ **done** — **`AuthorizeRouteCompositionIT`** | the layer-2 composition guard for S5 | `mvn -o -pl openam-oauth2 verify` green: 3xx passes through `OAuth2ErrorFilter` untouched, the HTML page is not rewritten, UTF-8 bytes reach the wire, PUT → framework 405 → `invalid_request`. **→ commit 5b-1a** (gate + `install`) |
| **S7** | ✅ **done 2026-07-26** — **D5 — `ConsentPageRenderer`** ([as-built](#as-built-s7)) | the shared consent collaborator, built in the producer's three phases (finding 10), + `ConsentPageRendererTest` | `dataModel(...)` matches `RendererFixtures.authorize()` **key-for-key and type-for-type**; `target` carries context path + query; absent parameters omitted; query-only reads proven with a POST carrying a conflicting form body; non-ASCII `user_name` round-trips UTF-8; `RestletRendererParityTest` still green |
| **S8** | ✅ **done 2026-07-26** — **D9/D7/D8 — `AuthorizeHandler`** ([as-built](#as-built-s8)) | the handler + `AuthorizeHandlerTest` | success 302 query **and** fragment, `form_post` (composed URI in the model), consent branch, the full collapse table one row per exception, [D7](#d7) IAE rows with **no `Location`**, cache headers on every path, hooks called once in order. **→ commit 5b-1b** (gate + `install` + whole-reactor `install -DskipTests`) |
| **S9** | **Close out** | As-built filled in (oracle rows, `Accept-Language` outcome, D8's resolution, any plan corrections); [plan.md](plan.md) 5-E2/5b-1 marked done | 5d-1's smoke matrix has [D6](decisions.md) + [D7](#d7) + the double `Set-Cookie` recorded as expected divergences. Proceed to **5b-2**, which consumes `AbstractOAuth2HttpBrowserEndpoint` and `ConsentPageRenderer` unchanged |

**Hard ordering constraints** (everything else is preference):

- **S2 before S8** — rows 7–8 decide whether `AuthorizeHandler` validates content type at all ([D8](#d8)).
  S2 also cannot be written after 5d-1 at all (R-5b1.1).
- **S1 before S2** — rows 2, 6 and 9 are unreachable without the consent client.
- **S3 before S5** — the browser base extends the extracted parent.
- **S4 before S7** — the consent model's `locale` key needs the accessor.
- **S5 before S6a and S8** — both consume the base.
- **S7 before S8** — the handler injects the renderer.

S3 and S4 are independent of each other and of S1–S2; if the live container is not available immediately,
start at S3 and fold S1–S2 in before S8.

## As-built

<a id="as-built-5-e2--recorded-2026-07-26"></a>
### 5-E2 — recorded 2026-07-26 (S1 + S2, test-only)

Captured against a live container built from this tree: `openam-e2e:5e2` (the repo `Dockerfile` with its
`COPY` lines enabled over `openam-server/target/OpenAM-16.2.0-SNAPSHOT.war`) + `openidentityplatform/opendj`
on the `test-openam` network, configured exactly as CI's `build-docker` leg configures the IDP. Restlet still
serves `/oauth2` (`Server: Restlet-Framework/2.4.4` on every row); the only main-source deltas between the WAR
and HEAD are unrouted CHF classes plus two additive edits (`LoginHintHook`'s CHF method, `OAuth2GuiceModule`'s
Multibinder), so the Restlet `/authorize` path is byte-identical to HEAD's.

**Deliverables** — `e2e/oauth2/oauth2-test.spec.mjs` only, no main code:

- `ensureConsentClientExists` → `test_client_consent` (`isConsentImplied:false`, `clientType:Public`,
  `responseTypes:[code, token]`, `grantTypes:[authorization_code, implicit]`, same `redirect_uri`/`scope`),
  wired into the existing `beforeAll`. Additive — no existing row changed behaviour.
- `describe("OAuth2 /authorize contract lock (5-E2, live Restlet)")`, **10 tests**: the 9 planned rows plus
  **row 9b** (see the D6 correction below). Suite: **23 green** (13 existing + 10 new), re-runnable.

**Two environment facts the rows had to be written around** (both discovered by observation, both worth
knowing before writing any further `/authorize` e2e):

1. **The provider enforces PKCE.** A `response_type=code` request without `code_challenge` fails validation
   with `400 invalid_request` "Missing parameter, 'code_challenge'" **before** the session, consent or scope
   logic runs — the first probe of rows 1/2/5 recorded that error instead of the intended one. Every row that
   must get past validation carries a real fixed S256 challenge.
2. **On `/authorize` the `iPlanetDirectoryPro` *header* does not authenticate — only the *cookie* does.** A
   header-only request gets the 301 to `/UI/Login`. This is the mirror image of
   [../../test-infrastructure.md](../../test-infrastructure.md)'s cookie gotcha (the existing "Should receive
   an auth code" test passes only because `getAuthToken` left a session cookie in the shared context, not
   because of the header it sets). Each row therefore runs in a disposable context whose jar is seeded
   explicitly — via `apiRequest.newContext({storageState:{cookies:[…]}})` — with exactly the identity, and the
   extra cookies, that row needs.

#### The recorded rows

| # | Request | Recorded |
|---|---|---|
| 1 | valid GET, no session | **301**; `Location` = `<base>/UI/Login?realm=%2F&goto=<the whole request URL, singly percent-encoded>` — `realm` first, `%2F` not `/`, and the already-encoded `redirect_uri` therefore appears double-encoded; `no-store`+`no-cache` |
| 2 | authenticated GET, consent client | **200** `text/html;charset=UTF-8` (**no space** after the `;`); `no-store`+`no-cache`; `Set-Cookie: oauth2_csrf=…;Path=/;HttpOnly;SameSite=Lax`; model on the wire: `csrf`, `clientId`/`displayName` = `test_client_consent`, `userName` = `Demo Demo`, `responseType`, `redirectUri`, `scope`, `state`, `isSaveConsentEnabled: true`, `displayScopes: [ { "name": "profile" … } ]`, `locale: "*"`, and **`formTarget` = `\/openam/oauth2/authorize?<full query>`** — context path included, confirming [finding 4](#4--the-consent-data-model-is-already-pinned-by-a-golden--reproduce-it-key-for-key) |
| 3 | unknown `client_id` | **400** `text/html;charset=UTF-8`, **no `Location`**; page carries `message: "invalid_client"` / `description: "Client authentication failed"` |
| 4 | registered client, unregistered `redirect_uri` | **400** `text/html;charset=UTF-8`, **no `Location`** (the no-auto-redirect policy holds); `redirect_uri_mismatch` / "The redirection URI provided does not match a pre-registered value." |
| 5 | unknown scope, `response_type=code` | **302** to `http://app.invalid/cb?…` — parameters in the **query**, no `#`; `error=invalid_scope`, `error_description=Unknown/invalid scope(s): [no_such_scope]`, `state` echoed |
| 6 | the same, `response_type=token` | **302** to `http://app.invalid/cb#…` — parameters in the **fragment**, query empty. R-5b1.3's oracle |
| 7 | `PUT` | **405** `application/json` `{"error_description":"Required Method: GET or POST found: PUT","error":"method_not_allowed"}` + `no-store`/`no-cache` |
| 8 | `POST` `Content-Type: application/json` | **400** `application/json` `{"error_description":"Invalid Content Type","error":"invalid_request"}` + `no-store`/`no-cache` |
| 9 | consent `POST` `decision=allow` + the page's `csrf` | **302**; parameters **appended to the query**: `code`, `scope`, `iss=<base>/oauth2`, `state`, `client_id`; `no-store`/`no-cache`; **no `Set-Cookie` at all** |
| 9b | the `oidcLoginHint` contract (3 cases) | see [D6](#d6) — consent page emits `oidcLoginHint=demo; Path=/; HttpOnly`; success with **no prior cookie** emits **nothing**; success with a prior cookie emits exactly one `oidcLoginHint=; Expires=<past>` carrying **neither `Path` nor `HttpOnly`** |

#### What the observation changed

1. **[D8](#d8) resolved — both filter errors survive the CONTINUE fall-through.** Rows 7 and 8 recorded a
   **405** and a **400** that stand on the wire, exactly as `GET /access_token` did in 5-E. ⇒ `AuthorizeHandler`
   gets **no verb check** (the framework 405 matches on status; the body code diverges to `invalid_request`,
   a 5d-1 body diff) and **must reproduce the content-type check** and return. This is the answer S8 was
   waiting on; 5b-1b is now unblocked on that axis.
2. **[D6](#d6)'s premise corrected.** Restlet does **not** emit a `Set-Cookie` on a first authorize success
   carrying `login_hint`; it emits one only when the *request* already carried the cookie. The CHF port's
   delete must therefore be unconditional-when-set rather than guarded on the incoming cookie, or the first
   authorize would leave the cookie set in the browser. Recorded as row 9b and folded into D6's table.
3. **Row 9b exists at all.** The plan folded the D6 baseline into row 9; the correction above needs three
   distinct cookie states, which do not fit one request. Row 9 keeps the redirect-composition contract, 9b owns
   the cookie contract.
4. **A free `Accept-Language` data point for [D3](#d3)**: with no `Accept-Language` on the request, Restlet's
   `ClientInfo.getAcceptedLanguages()` yields the single tag `*`, and the consent page renders `locale: "*"`.
   That is the "absent header" row of the S4 parity table, already answered — and note it is **not** the empty
   string, so a CHF `getAcceptedLanguages()` returning an empty list would render `locale: ""` and diverge.
   S4 must A/B this case explicitly.
5. **`formTarget` confirmed against the live wire**, not just against the fixture: `\/openam/oauth2/authorize?…`
   includes the context path and the full query, so [finding 4](#4--the-consent-data-model-is-already-pinned-by-a-golden--reproduce-it-key-for-key)'s
   `request.getUri().getPath()` translation is right and R-5b1.8's guard is aimed at the right value.

#### Verification

- `npx playwright test oauth2` — **23 passed**, twice in a row (creation path and already-exists path both
  exercised); no existing row edited.
- `mvn -o -pl openam-oauth2 test -Dtest=RestletRendererParityTest,RestletErrorParityTest` — **27 green**
  (criterion 3: the 3c goldens are proven-legacy before any 5b main code lands).

⇒ **S1 and S2 done; the [R-5b1.1](#risks-extends-phase-5-oauth2mds-register) unrecoverable-oracle risk is
retired.** Next: **S3** (the D1 extract).

### S3 — the D1 extract (2026-07-26)

`AbstractOAuth2HttpEndpoint` created with the two `@Inject` fields, `withErrorHeaders` and `noCache`;
`AbstractOAuth2HttpJsonEndpoint` reduced to its `@ExceptionHandler` and made to extend it. **Surefire baseline
is 983, not the 979 the plan predicted** — the 5-E2 commit added 4 Java regression tests alongside the e2e
rows. 983 before, 983 after, **no test file edited**, which is the gate: a pure refactor is one where no
assertion had to change. The existing handler tests' reflection scaffolding already walked the full hierarchy
(`for (Class<?> c = target.getClass(); c != null; c = c.getSuperclass())`), so [finding
11](#11--the-three-level-base-hierarchy-is-safe--and-the-obvious-alternative-is-not)'s three-level warning cost
nothing.

<a id="as-built-s4"></a>
### S4 — `getAcceptedLanguages()` (2026-07-26): D3's premise was wrong twice

The A/B oracle (`RestletAcceptLanguageParityTest`, 12 rows) overturned two things the plan asserted, and
both changed the code:

1. **⚠ CHF destroys the raw header before our code runs.** D3 says "implement it on `ChfOAuth2Request` by
   parsing the raw `Accept-Language` header" — but `Headers.put`/`add` re-parse any header with a registered
   factory and store the *parsed object*, so `getFirst("Accept-Language")` returns
   `AcceptLanguageHeader`'s canonical rendering: re-sorted by quality, `q` values synthesised by position, the
   client's own `q` discarded, case normalised. `HttpFrameworkServlet` populates the request through that same
   path, so this is production behaviour, not a test artefact. The full measurement is in
   [chf-patterns §6](chf-patterns.md#-headers-re-parses-known-headers-on-the-way-in--the-raw-value-is-unrecoverable-phase-5b-1a);
   it applies to **every** typed header, so it is filed there rather than here.
   ⇒ **the accessor reads `getHttpServletRequest().getHeader("Accept-Language")`** — the same bytes Restlet's
   own servlet adapter read — and falls back to the CHF header only when the chain carries no servlet request.
   *This is a correction to D3, not a divergence:* it is what makes byte parity achievable at all. The commons
   gap the plan filed is real but is now understood to be larger than "the accessor is lossy" — the raw value
   cannot be recovered from a CHF `Headers` at all.
2. **Restlet does not sort by `q`.** D3 predicted "the tokens in descending-q order, ties broken by header
   order". The oracle says plain **header order**: `en-GB,en;q=0.8,fr;q=0.9` → `["en-GB", "en", "fr"]`, and
   `en;foo=bar;q=0.3,de` → `["en", "de"]`. So the implementation parses no `q` at all — it splits on `,`,
   drops everything after the first `;`, trims, and skips empties. ~12 lines, and the sort/`quality()`
   machinery the first cut had was deleted.

Also recorded, each now a test row:

- **absent header → `["*"]`** (`PreferenceReader.addLanguages(null, …)` adds `Language.ALL`), confirming the
  5-E2 `locale: "*"` observation, while a **present-but-empty header → `[]`**. The two are different, and only
  the absent case gets the wildcard.
- **case is preserved verbatim** — `EN-gb` stays `EN-gb`.
- **one deliberate divergence:** Restlet **throws** `IllegalArgumentException("Invalid quality value detected")`
  on `en;q=bogus`, i.e. a 500 for a header the client controls. CHF ignores the parameter and returns `["en"]`.
  Not reproduced — the `q` only ever fed an ordering Restlet does not apply. Asserted as a divergence row in
  the parity test rather than hidden; belongs in 5d-1's smoke matrix.

`RestletOAuth2Request` untouched, per D3. Suite **1001** (983 + 12 parity + 6 `ChfOAuth2RequestTest` rows).

<a id="as-built-s5-s6-s6a"></a>
### S5, S6, S6a — the browser substrate (2026-07-26)

**S5 — `AbstractOAuth2HttpBrowserEndpoint`.** D2 as written, including both of its corrections to the
umbrella's pseudocode (two-argument `redirectingTo`, one `toResponse` exit). 8 lines of mapper, 13 test rows.
Two notes from writing the suite:

- The **adversarial row passes for two independent reasons**, which is the point:
  `ResourceOwnerAuthenticationRequired` is in `NEVER_REDIRECT` *and* its target is pinned by
  [D13](decisions.md), so `redirect_uri=https://evil.example/` cannot retarget the 301 even if a future
  subclass gets the guard wrong.
- One planned row was **wrong in the plan's own collapse table**: `OAuth2ProviderNotFoundException` renders
  **404 `not_found`**, inherited from `NotFoundException` — not `server_error`. The table in
  [finding 3](#3--the-two-catch-lists-and-what-collapsing-them-actually-changes) says only "inherits
  `NotFoundException`", so nothing there was contradicted, but 5b-1b's collapse-table rows should use
  `not_found`.
- An **empty** `redirect_uri` is treated as no target (it would otherwise produce a `Location`-less 302,
  the `Headers.put(name, null)`-removes-the-header trap `OAuth2ErrorResponseFactory` already documents).

**S6 — the hook seam.** `ChfAuthorizeRequestHook` + `LoginHintHook`'s fourth impl + the fourth Multibinder.
The [D6](#d6) correction is implemented **without per-request state**: `afterAuthorizeSuccess` recomputes the
before-hook's own condition (`setsCookie`, a function of the two values it reads) rather than remembering what
it did. One instance serves every request, so a field would be cross-request state — and note `LoginHintHook`
carries no `@Singleton` and none of its four `addBinding().to(...)` calls scopes it, so Guice actually builds a
**separate instance per Multibinder**; the stateless design is required either way, but not for the
"one shared singleton" reason first written here. The delete therefore
fires on `beforeWouldSet || requestCarriedCookie` — the union that makes all three of row 9b's cookie states
end with the cookie gone. Refactor taken while there: the private `hasLoginHintCookie` became
`loginHintCookieValue` (the before-hook needs the value, not just presence) and the delete-cookie construction
was pulled into one `removeCookie(OAuth2Request)`; `afterTokenHandling` keeps its incoming-cookie guard, which
is correct for the token path.

**S6a — `AuthorizeRouteCompositionIT`**, 6 rows, all four planned claims plus a POST row: 301 and 302 pass
`OAuth2ErrorFilter` untouched (it keys on `>= 400`), the HTML page is not rewritten into a JSON body, a
non-ASCII page reaches the wire as UTF-8 **bytes** (asserted on `getEntity().getBytes()`, since an ISO-8859-1
encode is invisible to `getString()`), and `PUT` on a `@Get`/`@Post`-only handler is the framework 405
rewritten to `invalid_request` — [D8](#d8)'s body divergence, now pinned in process.

**Verification.** `mvn -o -pl openam-oauth2 verify` — **1021 surefire + 14 failsafe**, green.
`javadoc -Ddoclint=all,-missing -DfailOnWarnings=true` clean over the new classes.
`grep -rn "org.restlet\|getCurrent()"` over the three new main files → 0 (`LoginHintHook` and
`RestletAcceptLanguageParityTest` are exempt, as in 5a-1). `install -DskipTests` done, so 5b-1b compiles
against the new base.

#### What the code review changed (2026-07-26)

Seven of thirteen findings were acted on; the rest are recorded below as rejected-with-reason.

1. **⚠ The oracle was reading the wrong jar, and the accessor dropped repeated header lines.** This reactor
   resolves `org.openidentityplatform.openam.jakarta:org.restlet`, **not** upstream `org.restlet.jee:2.4.4` —
   the parity *test* always ran against the right one (Maven resolved it), but the bytecode check behind
   [S4](#as-built-s4)'s claim did not. In the real jar, `HttpRequest.getClientInfo()` reads
   `getRequestHeaders().getValues(name)`, and **`Series.getValues` joins repeated header lines with a comma**.
   `HttpServletRequest.getHeader` returns only the first, so `Accept-Language: de` + `Accept-Language: fr` on
   two lines gave Restlet `[de, fr]` and CHF `[de]` — the consent page silently losing a language. Fixed:
   the accessor folds `getHeaders(name)` with `String.join(",", …)`. The data provider now feeds **lists of
   header lines** to both legs (a single-String provider cannot express the case at all), with three new rows;
   15 parity rows green.
2. **A vacuous test deleted.** `acceptedLanguagesDoNotAffectGetLocale` never put an `Accept-Language` on the
   CHF request — the only source `getLocale()` reads — so it passed for an unrelated reason and would have
   passed with the accessor deleted entirely. Rewritten to populate **both** sources with **different** values,
   so it fails if either accessor starts reading the other's.
3. **The delegating wrappers were silently holed.** `ValidateIdTokenRequest` (both the CHF and Restlet twins)
   forwards all 17 accessors; because the new method is *concrete*, the compiler did not force an 18th, so a
   wrapped request would answer `[]`. Forwarders added.
4. **Uniform mutability** — `Collections.unmodifiableList` on both branches, so the result's mutability no
   longer depends on whether the client sent a header.
5. **A narrowing in the refactor undone** — `hasLoginHintCookie` → `loginHintCookieValue` changed the token
   path's guard from cookie *presence* to *non-null value*. The accessor now normalises a null-valued cookie to
   `""`, so non-null still means "present".
6. **The [D6](#d6) recompute has a caller contract, now stated.** `afterAuthorizeSuccess` recomputing the
   before-hook's decision is only equal to what happened if the **same** `OAuth2Request` instance reaches both
   hooks and `login_hint` is unperturbed between them. [D9](#d9) already specifies one cached instance per
   request; `ChfAuthorizeRequestHook`'s javadoc now makes it a documented precondition rather than an
   assumption **S8 must honour**.
7. **⚠ [D8](#d8) is one row wider than written — the 405 also loses its cache headers.** The framework's 405 is
   not a thrown `OAuth2Exception`, so it never reaches `onError`, the only caller of `withErrorHeaders`; live
   Restlet stamped `no-store`/`no-cache` on that exact response (5-E2 row 7) because `OAuth2Filter` *wrapped*
   the resource rather than being invoked by it. The composition IT now asserts their **absence**, so 5d-1's
   smoke matrix inherits the row instead of discovering it. The same gap applies to any
   non-`OAuth2Exception` reaching the framework's 500.

**Rejected, with reason:** a null-guard on `getHttpServletResponse()` in the two new hooks (the shipped 5a-1
`afterTokenHandling` dereferences it the same way, and `HttpFrameworkServlet` always installs it — guarding
would hide a misconfiguration rather than fix one); overriding the accessor on `RestletOAuth2Request` so the
Restlet leg answers `["*"]` (D3 excludes it because nothing on that leg calls it — `ConsentRequiredResource`
keeps its own loop until 5d-2 — and `ConsentPageRenderer` is CHF-only); fixing `getLocale()` to read the
servlet header too (D3 explicitly leaves it alone: its own contract, its own tests, and it is out of 5b-1's
scope); a Guice test for the new Multibinder (build-ahead by design — S8 is its consumer, and the module has no
`OAuth2GuiceModuleTest` to extend); and extracting the duplicated test scaffolding (`inject` is duplicated
verbatim across ~10 existing handler suites — matching house style beats a local abstraction).

#### Second review round (2026-07-26)

Ten of fourteen acted on. Three found real defects in code the first round had already passed over:

1. **⚠ A client-triggerable 500 on `/authorize`** (user-confirmed fix). `beforeAuthorizeHandling` put the raw,
   client-supplied `login_hint` into a servlet `Cookie`. Tomcat's default `Rfc6265CookieProcessor` rejects any
   value outside RFC 6265's `cookie-octet` — space, `,`, `;`, `"`, `\`, non-ASCII — by throwing
   `IllegalArgumentException` **while generating the header**, outside any handler's reach, so
   `?login_hint=John%20Doe` would have reached the browser as a CREST 500. Restlet never hit this because it
   wrote the `Set-Cookie` itself, unvalidated, emitting a malformed header instead. **The cookie is now skipped
   when the value is not a valid `cookie-octet` string** — byte-identical for every value Restlet could legally
   send (usernames, email addresses), and no container-dependent failure for the rest. The check lives inside
   `setsCookie`, so the after-hook's "did the before-hook set it?" answer stays exact. 6 new rows. A 5d-1
   divergence row.
2. **⚠ A naive `split(",")` fabricated a language tag.** `Accept-Language: en;x="a,b",de` → Restlet
   `["en", "de"]`, ours `["en", "b\"", "de"]` — and per the accessor's own contract those tags are interpolated
   **raw into the consent page's JavaScript**, so a fabricated quote-bearing tag is what S7 would have emitted.
   Malformed input (the grammar allows only `q`), but Restlet's tokenising reader handles it and ours did not.
   Split is now quote-aware; the parity row is in the table, and it **failed before the fix** — the only kind of
   regression row worth having.
3. **The UTF-8 wire assertion was half vacuous.** `new String(wire, ISO_8859_1)` maps every byte into
   U+0000..U+00FF, so `doesNotContain(NON_ASCII)` can never fail whatever the encoding. Replaced with a byte
   subsequence search for the UTF-8 encoding, plus the absence of the `'?'` run an ISO-8859-1 encoder leaves.
   Risk #21 is only covered now.

Also: `getAcceptedLanguages()` is **memoised** like the class's four other derived values (the header cannot
change within a request, the consent path reads it per render, and `getHeaders()` returns a one-shot
`Enumeration` — which had armed a trap for the next test to call it twice); a `WWW-Authenticate` row added for
`InvalidClientAuthZHeaderException`, the only `NEVER_REDIRECT` type carrying a challenge and previously
unexercised through the browser mapper; `isEmpty` switched to `oauth2.core.Utils` to match `OAuth2Error`, whose
predicate it mirrors; `Params.STATE` instead of a bare literal; the hook's double reads of the cookie array and
the `login_hint` parameter collapsed to one each; and the browser base's javadoc now states that
`IllegalArgumentException` is **deliberately not mapped** and must be caught by each subclass per [D7](#d7) —
the thing S8 would otherwise ship as a CREST 500.

⚠ **A factual correction to the S6 note above:** `LoginHintHook` carries **no `@Singleton`** and none of its
four `addBinding().to(...)` calls scopes it, so Guice builds a separate instance per Multibinder — not the
"shared singleton" first written here. The stateless design is required either way (one instance serves every
request), but for the ordinary reason, not that one.

**Rejected, with reason:** overriding the accessor on `RestletOAuth2Request` (raised twice; D3 excludes it
because nothing on that leg calls it, and `ConsentPageRenderer` is CHF-only — the class dies at 5d-2, so the
override would be dead code); making `getLocale()` share the servlet source (D3 explicitly leaves it alone —
its own contract, its own tests, out of 5b-1's scope); forwarding the six *stateful* members on the
`ValidateIdTokenRequest` wrappers (pre-existing, unrelated to this change — flagged, not fixed); and dropping
the `!isEmpty(redirectUri)` guard and the `error.getParameterLocation()` argument as redundant ([D2](#d2)
specifies both, and the guard is what keeps a `Location`-less 302 unreachable regardless of downstream
contracts).

⇒ **5b-1a complete.** Next: **S7** (`ConsentPageRenderer`), which consumes `getAcceptedLanguages()` for the
model's `locale` key.

<a id="as-built-s7"></a>
### S7 — `ConsentPageRenderer` (2026-07-26): the port was uneventful, the fixture was not

[D5](#d5) as written — a `@Singleton` collaborator, not a base class, with the model built in the producer's
three phases in order. ~90 lines of main code, 16 test rows. The port itself raised nothing; **what it found in
the test fixture did**.

Producing the model from real code, and asserting it key-for-key against `RendererFixtures.authorize()`, exposed
**two defects in the fixture** — the artifact the goldens were rendered from, and the thing
[finding 4](#4--the-consent-data-model-is-already-pinned-by-a-golden--reproduce-it-key-for-key) called "already
de-risked":

1. **`display_scope` was missing entirely.** The key was added to the producer on **2026-07-20** by the
   **CVE-2026-62280** fix (reflected XSS on the WAP consent page) and the fixture, derived before that, never
   caught up. `wap/authorize.ftl` is its only reader, so the `wap` golden carried an **empty region** where
   production renders the scope list.
2. **Claim *values* were not ESAPI-encoded.** `ConsentRequiredResource:135-137` pushes claim descriptions
   **and values** through `encodeForHTML`, so production emits `demo&#x40;example.com`; the fixture hand-wrote
   the raw `@` — despite its own javadoc claiming the values "are produced by running the same `JsonValue` calls
   the producer runs".

⚠ **Both were invisible to `RestletRendererParityTest` by construction** — it feeds the *same* model to both
legs, so a fictional model still passes `Restlet == CHF`. That is the blind spot the fixture's class javadoc
warns about, and it is exactly why **R-5b1.2**'s guard is stated as
"key-for-key against the producer-derived model" rather than against a hand-written expectation. The guard
earned its place on its first run.

Fixed in `RendererFixtures`, and the **five** affected goldens regenerated through the sanctioned
`-Dgolden.regenerate=true` path. That is legitimate only because this is pre-5d: the regenerated files are
re-derived from the **live Restlet renderer**, and `Restlet == golden == CHF` re-verifies without the flag. The
diffs are minimal and exactly what the two fixes predict — two `<b>` lines in `wap/authorize.html`, and
`@` → `&#x40;` in the four `displayScopes` interpolations.

Three smaller notes from writing the class:

- **`acr` is a query key, not the request's `acr_values`.** The templates read `${acr}`, and the producer only
  ever had whatever the query literally carried; `OAuth2Constants.JWTTokenParams.ACR` is the constant, not
  `Params.ACR_VALUES`.
- **`target` has no `?` when the query is empty**, matching the producer's `StringUtils.isBlank` guard — and it
  follows a `setQueryParameter` mutation, which a servlet-request reconstruction would not (R-5b1.8, asserted).
- **`locale` is `"*"` when no `Accept-Language` was sent**, which is [S4](#as-built-s4)'s wire-parity answer
  arriving in the consent page. Worth knowing before reading a `locale : "*"` on a rendered page as a bug.

**Verification.** `mvn -o -pl openam-oauth2 verify` — **1052 surefire + 14 failsafe**, green, with
`RestletRendererParityTest` (11) still green against the regenerated goldens. Grep gate over the new main file
→ 0. Doclint clean.

<a id="as-built-s8"></a>
### S8 — `AuthorizeHandler` (2026-07-26): fourteen catch clauses, one mapper

[D9](#d9) as written, with [D7](#d7)'s catch and [D8](#d8)'s content-type check. ~120 lines of main code, 45 test
rows plus 3 new composition rows. Three implementation notes:

- **The `IllegalArgumentException` catch sits one level out**, in a two-method split (`authorize(ctx, request)`
  wrapping a private `authorize(o2, request)`) rather than beside the consent catch. That placement *is*
  [finding 9](#9--display-and-the-two-illegalargumentexception-sources)'s fix: `?display=bogus` raises its IAE
  from **inside** the consent branch, and a sibling `catch` does not protect a `catch` body — which is precisely
  how Restlet leaked it to `doCatch` as a `server_error`. A single flat `try` would have reproduced the bug.
- **One `Render` functional interface** wraps the two render call sites (consent page, form-post page) so the
  `IOException`/`TemplateException` → `ServerException` conversion is written once. A render fault stays a
  contractual **400** error page rather than the framework's 500: a missing template is a deployment fault, not
  one of the bug paths [D3](decisions.md) sends to the framework.
- **The form-post target is composed before the branch**, reproducing `OAuth2Representation:164-165` — so the
  form posts to a URI that *already* carries the parameters and repeats them as hidden inputs. Asserted rather
  than tidied.

**Two facts the test suite discovered, both of which corrected the plan rather than the code:**

1. **⚠ `CsrfException` cannot be raised on `GET` — structurally, not by convention.** Mockito refused to stub it
   on the 1-arg `authorize`, because it is absent from that method's `throws` clause (the CSRF check lives in
   the 3-arg overload). [Finding 3](#3--the-two-catch-lists-and-what-collapsing-them-actually-changes) says
   "*not caught — unreachable on GET*"; this makes it a compiler-enforced fact. The shared collapse table
   therefore **cannot** carry the row — it is a POST-only test.
2. **⚠ The HTML error page does not carry `state`.** `page/error.ftl` interpolates only `error` and
   `error_description`; the `state` the producer has always put in the model reaches **no template**
   (`RendererFixtures.error()`'s javadoc already recorded this for the model, but the plan's test bullet asked
   for "`state` echoed in every error body"). It is echoed on the **redirect** branch only, where it rides in
   `asMap()` as a query parameter. Legacy behaviour, reproduced; pinned by a dedicated row so that a future
   change which starts rendering it registers as the wire change it would be. `OAuth2Error.withState` is still
   set on the D7 path — Restlet passed `state` there too, and it is not dead: the error-page fallback branch
   emits `asMap()` as JSON.

**Collapse table, as asserted** (one row per Restlet catch clause, values read off `AuthorizeResource` and each
exception's own definition — run against **both** verbs unless noted):

| Exception | Status / error | Redirects? |
|---|---|---|
| `RedirectUriMismatchException` | 400 `redirect_uri_mismatch` | no |
| `DuplicateRequestParameterException` | 400 `invalid_request` | no |
| `OAuth2ProviderNotFoundException` | 404 `not_found` | no — **[D6](decisions.md) change on POST** |
| `CsrfException` *(POST only)* | 400 `bad_request` | no |
| `InvalidScopeException`, `AccessDeniedException` | own | **yes**, per the exception's `parameterLocation` |
| `ResourceOwnerAuthenticationRequired` | 301 login URI | pinned target; an attacker's `redirect_uri` cannot retarget it |
| `InvalidClientAuthZHeaderException` | 401 `invalid_client` + `WWW-Authenticate` | no |
| `IllegalArgumentException` ×3 sources | 400 `invalid_request` page | no — **[D7](#d7) change** |

**Composition IT extended** (14 → 17 failsafe) with three rows that drive the **real** handler rather than the
stand-in, for claims a fixture cannot make: that `/authorize` genuinely is a two-verb endpoint (so the
[D8](#d8) 405 divergence is about the real thing), and that a 400 HTML page and a 302 the handler **returns** —
rather than ones the framework builds from a thrown exception — survive `OAuth2ErrorFilter` untouched.
[D7](#d7)'s page is the only response on this endpoint that takes the returned-not-thrown path.

**No Guice module change.** `AuthorizeHandler` is concrete with field `@Inject`s, so Guice JIT-binds it; the
`Set<ChfAuthorizeRequestHook>` it needs comes from [S6](#as-built-s5-s6-s6a)'s Multibinder. It is bound and
routed nowhere until 5d-1, as planned.

**Verification.** `mvn -o -pl openam-oauth2 verify` — **1102 surefire + 17 failsafe**, green. Grep gate over the
two new main files → 0. Doclint clean.

⚠ **Whole-reactor `install -DskipTests` is green except for one pre-existing offline hole.** 139 modules
SUCCESS, **`OpenAM Server` (the WAR) included** — so criterion 10's real question, that the new wiring
assembles, is answered. The single FAILURE is `openam-doc-source`, which dies at its *first* goal in 0.058 s:
`doc-maven-plugin:3.1.2` needs `json-fluent:3.1.2`, and `~/.m2` holds only `3.1.1` plus snapshots, so `-o`
cannot resolve it. A docs module containing no Java, failing on a missing artifact; the 16 SKIPPED modules are
its downstream packaging. **Needs one online run to seed the artifact before the 5b-1b commit** if the gate is
to be reported as unconditionally green.

#### What the code review changed — S7/S8 (2026-07-26)

Five of thirteen findings were real; two of those were **open redirects this step introduced**, and the same
root cause produced both.

1. **⚠⚠ The content-type check redirected the error.** The natural port —
   `throw new InvalidRequestException("Invalid Content Type")` — reaches the new browser mapper, and
   `InvalidRequestException` is **not** in `NEVER_REDIRECT`, so a JSON-bodied request carrying
   `redirect_uri=https://evil/` got a **302 to that URI**. The request had failed before the client was ever
   resolved, so nothing had validated it. Restlet built this error with the 4-argument
   `OAuth2RestletException` (last parameter `state`, redirect left null) and always rendered the page
   (`OAuth2Filter:66-70`). **This is the exact trap [D7](#d7) exists to describe, walked into one method
   over.**
2. **⚠⚠ A template fault redirected too**, for the same reason: `ServerException` is redirectable, so a missing
   `authorize.ftl` sent `error=server_error&error_description=<template path>` to the client's callback instead
   of showing an operator the failure. Restlet's `ExceptionHandler.handle(Throwable, …):86-89` also used the
   null-redirect form.
   ⇒ **Both fixed by making every error this handler builds itself a *built* response, not a thrown one**, via
   one `errorPage(o2, error, description)` helper on `OAuth2Error.of(int, String, String)` — which has no
   redirect target by construction, so `toResponse` cannot take a redirect branch. The class javadoc now states
   the rule. Corollary taken while there: a failed form-post render no longer runs the after-hooks, since
   [D9](#d9) puts them after the representation is built and one that failed to build was not.
   **Root cause worth carrying forward:** on the *JSON* base (5a) throwing was always safe, because that base
   has no redirect branch. On the browser base it is not. Any 5b/5c handler that builds its own error must use
   the built form.
3. **⚠ `target` was percent-decoded.** `ConsentPageRenderer.target` read `MutableUri.getPath()/getQuery()` —
   the **decoded** accessors; `getRawPath()/getRawQuery()` are the raw ones — where Restlet's
   `Reference.getQuery()` returns the raw string (its decoding form is the `getQuery(boolean)` overload). So
   `redirect_uri=https%3A%2F%2Frp%2Fcb%3Fa%3D1%26b%3D2` became a form action whose `&` and `=` the consent
   POST re-parses as extra top-level parameters → `RedirectUriMismatchException` on post-back. **Settled
   against a recorded oracle, not by reading code:** 5-E2 row 9 asserts live Restlet's `target` equals the
   percent-encoded query and then posts back to it successfully. No existing row could see it — the key-for-key
   assertion deliberately skips `target`'s value, and all three dedicated `target` rows used a query that is
   byte-identical encoded and decoded. New row asserts the escapes survive.
4. **⚠ `display` was read query-only.** `OAuth2Representation:72` uses `getParameter`, and `display` was never
   one of the keys the `getQuery().getValuesMap()` copy supplied — so [R-5b1.9](#risks-extends-phase-5-oauth2mds-register)'s
   query-only rule does not reach it. Harmless on `/authorize` (GET), wrong for the POST reuse this class was
   built for: a device-flow consent form carrying `display=touch` in its body would have silently fallen back
   to `page/`. Now `getParameter`; new row drives it from a form body.
5. **⚠ The `Accept-Language` splitter still fabricated a tag, one escape level deeper.**
   `en;x="a\",b",de` → Restlet `[en, de]`, ours `[en, b",de]`: the quote-toggle ignored RFC 9110's `\"`
   escape and closed the string early. Same defect class as the previous round's finding. **Recorded the way
   that one was — a parity row added first, which failed against the real parser, then the fix.** 17 parity
   rows.

**Rejected, with reason:** that `onError` builds a second `OAuth2Request` and loses attributes (**false** —
`OAuth2RequestFactory.create(Context, Request)` caches on the `AttributesContext`, so the mapper gets the
handler's own instance; no re-parse, and the instance-identity contract holds); reverting the `login_hint`
cookie-octet skip in favour of percent-encoding (user-confirmed 2026-07-26 — and encoding would change the
value the auth chain reads, trading one regression for another); replacing the servlet-response cookie with a
retractable CHF `SetCookieHeader` to undo the [D6](#d6) double `Set-Cookie` (the buffering alternative was
user-rejected 2026-07-25, and 5a-1's cookie spike settled the servlet-response mechanism); and de-duplicating
`validateContentType` against `TokenEndpointHandler`'s copy onto the shared base (after fix 1 the two are no
longer the same method — this one must *return* a page, that one *throws* to a JSON base; only the predicate is
common, and hoisting it would touch shipped 5a code for two call sites).

#### Third review round — staged files (2026-07-26)

Nine findings; **seven held, one was wrong, one was weak**. Three acted on by decision. Verification after:
**1129 surefire + 18 failsafe**, doclint clean.

##### 1. ⚠ The content-type check accepted a body with no `Content-Type`, where Restlet 400'd it

The severest defect this phase has produced, and it was **in two endpoints**, one of them already committed.

Restlet's whole check is `!MediaType.APPLICATION_WWW_FORM.equals(entity.getMediaType())`. `equals(null)` is
false, so the negation fires and a header-less body is a 400. Both CHF ports read a null type as "no opinion"
and passed it through. On `/authorize` that is not a wrong status but a **wrong decision**:
`ChfOAuth2Request.getParameter:104-110` reads a POST body only when the type *is* form, so the consent form's
`decision=allow` arrives as `null`, `consentGiven` becomes `false`, and `authorizationService.authorize` is
told the resource owner **refused** — the client gets `access_denied` for an approval the user gave, and
nothing anywhere reports an error.

**Settled by an oracle rather than by argument**, per this phase's method. `RestletContentTypeParityTest`
drives *both real filters* and the CHF predicate over one table, and it disagreed with three of my predictions:

| row | Restlet | CHF (before) | outcome |
|---|---|---|---|
| no `Content-Type`, non-empty body | **reject** | accept | CHF fixed |
| `APPLICATION/X-WWW-FORM-URLENCODED` | **reject** | accept | recorded divergence, kept |
| empty body (both filters) | accept | accept | fixture bug, fixed |

The second row is a **new discovery**: `MediaType.equals` compares names case-sensitively, so Restlet 400'd a
header RFC 7231 §3.1.1.1 calls legal. Two places in the codebase asserted the opposite in prose — the
`TokenEndpointHandler` javadoc and `mixedCaseFormContentTypeIsAccepted`'s comment, both claiming "Restlet's
`MediaType.equals` accepted mixed case, so we must too". The *behaviour* stays (a widening can only turn a
Restlet 400 into a success, never the reverse); the false justification is gone, and the row is now labelled a
divergence. The third row was my fixture's fault — `new StringRepresentation("")` is not an
`EmptyRepresentation`, which is how `TokenEndpointFilter` tests emptiness, so the fixture now models what the
adapter yields.

⚠ **Honest limit of the oracle**: it drives the filters, not the servlet adapter that produced the entity in
production. That gap does not reach the row it was built for — the filter accepts *exactly one* media type, so
whatever an adapter defaults a header-less body to (null, `application/octet-stream`, `*/*`), the answer is a
400 unless it defaults to form-urlencoded itself, which no HTTP stack does.

⇒ The rule now lives once, in **`OAuth2ContentTypes.isFormUrlEncoded`**, because two independent ports of one
contract had drifted into the same defect and fixing either alone would have left the other wrong. The callers
still differ in what they do with the answer — the token endpoint throws, `/authorize` must *build* its refusal
([§20](chf-patterns.md#20-on-the-browser-base-build-your-errors--never-throw-them-phase-5b-1)) — which is why
it returns a boolean. One existing test, `noContentTypeIsAccepted`, **was the defect written down as an
assertion**; it is now `noContentTypeIsRejected`. The motivating case has its own row,
`aConsentPostWithNoContentTypeIsRejectedRatherThanReadAsARefusal`, whose decisive assertion is that the service
is never told anything about a decision it cannot have. Same fix let `/access_token` validate **before**
`requestFactory.create`, closing there the client-lookup-per-malformed-post cost that round 2 closed here.

##### 2. The framework 405's missing cache headers — closed, not just recorded

`OAuth2Filter:72-77` added `no-store`/`Pragma` after its try/catch, unconditionally, so they landed on
responses that never reached the resource. The CHF ports moved stamping into the handler methods, which covers
everything a handler *returns* and nothing the framework produces alone — the 405 for an unannotated verb, the
404, the CREST 500. No care inside a handler closes that, because the handler is not on the path.

⇒ **`OAuth2NoCacheFilter`**, which restores the wrapping Restlet had, composed on `/authorize` and
`/access_token` **only** — applying it application-wide would be a widening, for the same reason `noCache` is
opt-in per handler. The IT row that recorded the gap by asserting the two headers *absent* now asserts them
present, on the stand-in and on the real handler.

(The reviewer's claim that "nothing asserts the cache headers" was inaccurate — the IT row did, deliberately,
as a pinned divergence. What was true is that recording it was a choice, and it has now been reversed.)

##### 3. Two comments of mine that were wrong

- The `HeaderUtil.split` comment claimed `en;x="a,b",de` *and* the backslash case "both fabricated a tag". The
  deleted quote-toggle handled the first correctly; only `en;x="a\",b",de` broke it, and only that row is new.
- `AbstractOAuth2HttpBrowserEndpoint`'s "⚠ subclasses must not override" warning named only `onError`, leaving
  `onIllegalArgument` — added by the D7 move, and the easier of the two to want to override — unguarded against
  the identical annotation-loss trap.

##### Rejected, with the reason

- **"The CSRF token is minted before `?display=` is validated."** Real behaviour, *faithful* behaviour:
  `AuthorizeResource:131-132` passes `getDataModel(e, request)` as an **argument** to
  `representation.getRepresentation(...)`, and Java evaluates arguments first — so Restlet also minted the token
  before `OAuth2Representation:73-75` ran `Enum.valueOf`. Changing it is a deliberate product change needing its
  own decision, not a review fix.
- **"`onIllegalArgument` destroys the stack trace."** The mechanism is real (`OAuth2ErrorResponseFactory:378-386`
  logs at DEBUG with a null cause), but the framing — that the D7 move caused it — is not: the pre-move code
  built the same 400. Threading a cause needs a `withCause` on `OAuth2Error`, which has none. Left as a known
  gap rather than smuggled in under a review.
- **"A hook throwing discards an issued authorization."** Structurally true and worth knowing; deferred as its
  own decision, since the remedies (swallow, or map `RuntimeException` on the browser base) are both behaviour
  changes and Restlet's `doCatch` answer differs from either.
- **"Three spellings of no-store."** Accurate, mild; the proposed remedy touches the token endpoint too.

#### Second review round — S7/S8 (2026-07-26)

Five of fourteen acted on. One of them **corrected a divergence the first round had not looked for**:

1. **⚠ The content-type refusal rendered the HTML error page where live Restlet sent JSON — and paid a store
   lookup to do it.** 5-E2 **row 8** recorded `400 application/json`
   `{"error_description":"Invalid Content Type","error":"invalid_request"}`; the filter wrote a Jackson
   representation and never a page. Fixed to `errorResponseFactory.toJsonResponse(...)`, which matches the
   recorded bytes — and, because that entry point needs no `OAuth2Request` at all, the check now runs
   **before** `requestFactory.create`. That matters beyond tidiness: `create` performs an unconditional
   `ClientRegistrationStore.get(client_id, …)`, so the previous ordering let an unauthenticated flood of
   malformed posts cost one client-registration lookup each, where `OAuth2Filter.beforeHandle` rejected them
   without ever reaching the resource. Asserted with `verify(requestFactory, never()).create(...)`.
2. **⚠ The render-fault page discarded the cause.** `serverErrorPage` built
   `new ServerException(e)` only to read `getMessage()`, so `OAuth2Error` carried `cause == null` and the
   provider log recorded a broken template with no stack — naming neither the template nor the frame that read
   it. `ServerException(Throwable)` calls `initCause` *specifically* so that survives. Now
   `OAuth2Error.of(new ServerException(e))`: identical wire shape, cause threaded through, still
   non-redirecting because nothing calls `redirectingTo` on it.
3. **The hand-rolled `Accept-Language` splitter was already in the library.**
   `org.forgerock.http.header.HeaderUtil.split(value, ',')` is quoted-string aware **including** the RFC 2616
   §2.2 backslash escape, trims, and drops empties — exactly the 18-line loop plus its `isEmpty` filter, and
   already imported elsewhere in this migration. Replaced; ~30 lines of code and justifying javadoc deleted.
   **The 17 parity rows are what make this safe** — the swap is proven equivalent against the real Restlet
   parser rather than by reading both implementations.
4. **A skipped `login_hint` cookie is now logged** (`debug`, naming the rejected value *class*, never the value
   — it is a claimed identity). The skip was previously invisible to operators: the user saw a login form that
   was not pre-filled and the log said nothing.
5. **An overstated comment corrected.** `redirectingTo(uri, error.getParameterLocation())` was described as
   load-bearing against "dropping this argument"; there is no one-argument overload, so it is a no-op today.
   The comment now says what is true — the parameter is not optional, and both alternatives a future edit
   reaches for (`null`, or a hardcoded `QUERY`) default every implicit-flow error to the query string.

**⚠ A pre-existing product bug surfaced, deliberately not fixed here.**
`templates/touch/authorize.ftl:56` emits **`isplayName:`** where `page/` and `popup/` both emit
`displayName:`. `openam-ui-ria/.../user/AuthorizeTemplate.html:19` renders `{{{oauth2Data.displayName}}}` as the
consent page's `<h1>`, so **`?display=touch` shows a blank client name** and asks the user to authorize an
unnamed client. Untouched by this migration and older than it; the regenerated `golden/touch/authorize.html`
records it because a golden's job is to record what legacy emits. Fixing it changes the wire and belongs in its
own change, not inside a port whose contract is byte-parity — but it should not be lost, so it is written down
here.

**Rejected, with reason:** that `ConsentPageRenderer` should reuse `OAuth2ErrorResponseFactory`'s
`normalised()`/`baseUrlOf()` (the producer at `ConsentRequiredResource:94-95` passes the **raw**
`getParameter("realm")` to an unguarded `getRootURL` — the port is verbatim, and the provider-cache growth is
pre-existing legacy behaviour that the *error* path chose to fix as its own decision); null-guarding
`getHttpServletResponse()` in the hooks (raised and rejected in the first round for the same still-true reason
— the shipped 5a-1 `afterTokenHandling` dereferences it identically and `HttpFrameworkServlet` always installs
it); folding repeated header lines in the CHF-header **fallback** branch of `parseAcceptedLanguages` (that
branch reads the already-canonicalised CHF value and is documented as best-effort, not byte-parity — no
servlet deployment reaches it); the duplicated `ValidateIdTokenRequest` decorators and the duplicated test
scaffolding (both pre-existing, both rejected in round one, both unchanged in kind); and that no test drives a
real `ChfAuthorizeRequestHook` through a composed route (true, and it is exactly R-5b1.7 build-ahead risk — the
CHF cookie path has no live guard until 5d-1 wires the route, which is why 5-E2 recorded the Restlet baseline
rather than trying to assert the CHF one early).

**Three findings raised as design questions rather than acted on**, since each would change a locked decision:

- **[D7](#d7) could live on the base as a second `@ExceptionHandler`.** `AnnotatedMethod` indexes handlers by
  exception type and dispatches most-specific-first, so
  `@ExceptionHandler public Response onIllegalArgument(IllegalArgumentException e, …)` on
  `AbstractOAuth2HttpBrowserEndpoint` is legal — and, building `OAuth2Error.of(int, String, String)`, it has no
  redirect target by construction, satisfying "never redirect" without any `mayRedirect` rule. D7's stated
  reason ("its type is redirectable") is about `OAuth2Error.of(OAuth2Exception)`, which an IAE never reaches.
  That would delete both `try`/`catch` blocks from `AuthorizeHandler` and hand the policy to 5b-2 and every
  later browser endpoint for free, removing the footgun the base's own javadoc admits to ("a subclass that
  forgets leaks the framework's CREST 500 to a browser"). The wire behaviour is unchanged; only D7's
  *"Scope: one `try`/`catch` around the whole handler-method body"* implementation note would go.
  **✅ Done 2026-07-26 (user-approved).** `AbstractOAuth2HttpBrowserEndpoint.onIllegalArgument` now carries the
  policy; `AuthorizeHandler` lost both `try`/`catch` blocks, the private two-method split that existed only to
  place one of them, and its `errorPage` helper. **The whole suite passed unchanged** — every D7 row (three IAE
  sources, both verbs, cache headers, absent `Location`) still green with the catches deleted, which is the
  behaviour-preservation evidence. Coverage added where the policy now lives: 3 rows on
  `AbstractOAuth2HttpBrowserEndpointTest` (including that the two mappers coexist and dispatch on type) and a
  composition row proving the page still reaches the browser as markup through `OAuth2ErrorFilter`.
  Two framework facts verified before the move, both worth carrying: `AnnotatedMethod.invoke:99-107` routes an
  endpoint method's throw — checked or unchecked — to `handleException`, so a `RuntimeException` is fully
  mappable; and a failure of the framework's *own* plumbing takes the sibling `catch (Throwable)` branch
  instead, so a reflective `IllegalArgumentException` still becomes the framework's 500 rather than being
  disguised as a client error.

- **`QUERY_KEYS` enumerates nine names where Restlet bulk-copied the whole query map** *and* the whole
  attributes map. Shipping templates read only these nine, so nothing is broken today — but a deployment with
  a customised `authorize.ftl` reading, say, `${prompt}` loses the field silently, and the key-for-key fixture
  assertion proves the nine are *present*, never that nine is *enough*. A bulk copy is available
  (`new Form().fromQueryString(request.getUri().getRawQuery())`) and would be both simpler and strictly more
  faithful. [D5](#d5) and [finding 4](#4--the-consent-data-model-is-already-pinned-by-a-golden--reproduce-it-key-for-key)
  locked the enumeration on the premise that "CHF has no equivalent bulk copy", which is not quite true.

  **✅ Resolved 2026-07-26 (user-approved): keep the enumeration, add a drift guard.** First, the measurement
  that decides it — extracting every variable the four shipped `authorize.ftl` templates read and subtracting
  the keys phase 1/3 write and the `<#list … as r>` loop variable leaves exactly
  `acr client_id nonce realm redirect_uri response_type scope state ui_locales`: **the nine, precisely.** The
  enumeration is complete, so this was never a correctness gap; every extra key a bulk copy would carry is
  inert, because no template reads it and every name templates *do* read beyond the nine is written by phase 3,
  which runs last. That left only drift as an argument for the bulk copy — and a test kills drift more cheaply
  than a rewrite that would have obliged us to reproduce Restlet `Series.getValuesMap()`'s duplicate-name
  semantics exactly (the precise class of subtle mismatch this phase kept turning up) and would have let a
  client put arbitrary keys into the model, harmless only because phase 3 happens to overwrite collisions.

  `ConsentPageRendererTest.everyTemplateVariableIsSuppliedByTheModel` asserts the real invariant —
  **every variable a template reads is a key the renderer supplies** — iterating `DisplayType.values()` so a
  fifth display cannot be missed. Nothing is written down twice: the supplied set comes from a live
  `dataModel()` call, so phases 1 and 3 subtract themselves and only the query enumeration is stated, as a
  query string. That makes it strictly stronger than a `QUERY_KEYS` equality check — it catches a dropped
  phase-3 key too — and it needs no access to the private field. The extractor deliberately
  **over**-approximates on FreeMarker it does not model (`<#assign>`, an unknown operator): a false positive
  fails the build and someone looks; an under-approximation would let the drift through, which is the one
  outcome that must not happen. **Mutation-tested both ways**: adding `${prompt}` to `page/authorize.ftl`
  fails it naming file and variable, and deleting `NONCE` from `QUERY_KEYS` fails it too (alongside the
  fixture row — two independent guards). ⚠ Known limit, unchanged by this: it guards the **shipped** templates,
  so a deployment that customises `authorize.ftl` to read a tenth parameter still loses the field silently.
  That case is a bulk copy's only remaining advantage, and it is not one this repo's tests can ever see.
- **`OAuth2Request.getAcceptedLanguages()` defaults to an empty list** and `RestletOAuth2Request` does not
  override it, so a Restlet-backed request reaching a shared collaborator would get `locale=null` rather than
  the `"*"` [S4](#as-built-s4) established. Unreachable today ([D3](#d3) rejected the override twice, correctly:
  nothing on that leg calls it), but a default of `["*"]` would make the gap harmless if that ever changes.

  **✅ Resolved 2026-07-26 (user-approved): the base default is now `List.of("*")`.** One line, plus the
  javadoc that explains it and a pinning row. The reasoning: the tags exist to be *joined into a page*
  (`ConsentPageRenderer:157` → the `locale` key), and `joinStatic` of an empty list is `""` — a value no live
  request has ever produced, because a client that sends no `Accept-Language` yields `*`. So the honest
  default for "this transport cannot tell you" is the same answer as "the client did not ask": both mean *no
  stated preference*, and every consumer already handles the wildcard. The alternative considered and
  rejected was making the method **abstract** — compiler-enforced and exact, but it would have obliged
  `RestletOAuth2Request` and both `IdTokenInfo*` decorators to implement it, i.e. **new Restlet code written
  during the phase whose purpose is deleting Restlet**, to cover a call that never happens.

  ⚠ The precondition D3 relied on is unchanged and still correct: the Restlet resources
  (`ConsentRequiredResource:102`, `DeviceCodeVerificationResource:230`) read
  `getRequest().getClientInfo().getAcceptedLanguages()` **directly**, never through `OAuth2Request`, so
  overriding it on the Restlet leg would still be dead code. This change does not make the leg answer
  correctly — it makes it answer *harmlessly*. Pinned by
  `RestletOAuth2RequestTest.theInheritedAcceptedLanguagesAreTheWildcardNotAnEmptyList`, which asserts what the
  one non-overriding subclass inherits. Orphaned the `java.util.Collections` import in `OAuth2Request`, removed.
