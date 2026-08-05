# Phase 5b-1 — OAuth2 `/authorize` → CHF: key research findings

Background for [phase-5b-1.md](phase-5b-1.md) — the findings that drove its design. Read once; the spec is what you re-read while implementing.

---

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

