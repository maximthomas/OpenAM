# Phase 5b-2 — `/device/user`, `/connect/checkSession`, `/connect/endSession` → CHF: key research findings

Background for [phase-5b-2.md](phase-5b-2.md) — the findings that drove its design. Read once; the spec is what you re-read while implementing.

---

## Key research findings

<a id="1--only-one-of-the-three-is-a-browser-endpoint-the-doccatch-arity-decides"></a>
### 1. ⚠ Only **one** of the three is a browser endpoint — the `doCatch` arity decides

`ExceptionHandler` (`org.forgerock.oauth2.restlet`) has **two** entry points with completely different wire
shapes, and which one a resource's `doCatch` calls is the whole error contract:

| Entry point | Shape | Called by |
|---|---|---|
| `handle(Throwable, Context, Request, Response)` (`:81-92`) | 301 login redirect / 302 error redirect / **`page/error.ftl` HTML** | `AuthorizeResource`, **`DeviceCodeVerificationResource:299-301`** |
| `handle(Throwable, Response)` (`:146-153`) | **JSON** `jacksonRepresentationFactory.create(exception.asMap())` — `{error, error_description?, error_uri?, state?}` at the exception's status | **`EndSession:117-119`**, **`OpenIDConnectCheckSessionEndpoint` `doCatch`** |

⇒ base-class assignment (**D1**):

- `DeviceCodeVerificationHandler` → `AbstractOAuth2HttpBrowserEndpoint`;
- `EndSessionHandler`, `CheckSessionHandler` → **`AbstractOAuth2HttpJsonEndpoint`**.

Confirmed empirically for endSession by an already-green e2e row: `GET /oauth2/connect/endSession` with no
`id_token_hint` answers **400 `application/json` `{"error":"bad_request","error_description":"The endSession
endpoint requires an id_token_hint parameter"}`** (`e2e/oauth2/oidc-test.spec.mjs:213-221`). Putting either of
these two on the browser base would replace that JSON with an HTML page for every error — a total contract
break that no unit test written against the wrong base would notice.

<a id="2--consentpagerenderer-phase-1-is-realm-only-and-that-silently-breaks-the-device-consent-page"></a>
### 2. ⚠ `ConsentPageRenderer` phase 1 is realm-only — and that silently breaks the **device** consent page

5b-1 built `ConsentPageRenderer.dataModel` in the producer's three phases
([phase-5b-1 D5](phase-5b-1.md#d5)), but implemented phase 1 as *"copy `realm` from the attributes"*
(`ConsentPageRenderer.java:127-132`). That is correct **for `/authorize`**, whose Restlet attribute map holds
only the realm, the realm object and router internals — nothing else any template reads.

It is **not** correct for the device flow. `DeviceCodeVerificationResource.addRequestParamsFromDeviceCode`
(`:239-257`) writes **the whole device-code record into the request attributes** *before* the consent page is
built, and `ConsentRequiredResource.getDataModel:79` then bulk-copies those attributes into the model. The
device-flow consent POST carries **no query string**, so phase 2 overlays nothing. Every model key the consent
templates read therefore arrives from **phase 1** on that path.

Keys the device code seeds that `page/authorize.ftl` + `popup/authorize.ftl` read, and that today's
`ConsentPageRenderer` would **drop**:

| Model key | Source in `DeviceCode` | Effect if dropped |
|---|---|---|
| `client_id` | `clientID` → renamed to `client_id` (`:251-252`) | `<#if client_id??>` false → XUI cannot name the client |
| `scope` | `scope`, joined with `" "` (`:248`) | consent screen shows no scopes |
| `state`, `nonce`, `response_type`, `ui_locales` | verbatim | lost from `oauth2Data` |
| `realm` | verbatim — **overwrites** the router-resolved realm | `<#if realm??>` false → XUI loads with no realm |

(`redirect_uri` and `acr` are *not* affected: a `DeviceCode` stores neither. It stores `acr_values`, which no
template reads.)

⇒ **D2**: generalise phase 1 to read the *same enumerated key list* from the attributes before the query
overlay. This is a strict superset of today's behaviour for `/authorize` (whose attributes contain none of
those keys except `realm`, which is already copied), so it is behaviour-neutral for the committed handler and
correct for the new one. It is **not** optional and it is **not** a device-handler-local workaround: the
renderer is the shared collaborator, and this is the sharing it was built for.

<a id="3--the-device-code-attribute-seeding-contract"></a>
### 3. The device-code attribute-seeding contract, exactly

`addRequestParamsFromDeviceCode` (`:239-257`) iterates `deviceCode.getObject()` — the `JsonValue`'s backing map
— and for each entry:

- **every value except `scope`** is a single-element `List<String>` (all `DeviceCode` setters go through
  `setStringProperty`), and is unwrapped with `((List<String>) value).iterator().next()`;
- **`scope`** is a `List<String>` joined with `" "`;
- the key `OAuth2Constants.CoreTokenParams.CLIENT_ID` — literal **`"clientID"`** (`OAuth2Constants.java:224`) —
  is written under `OAuth2Constants.Params.CLIENT_ID`, literal **`"client_id"`** (`:121`). **Every other key
  goes in verbatim**, including `realm`, `state`, `nonce`, `response_type`, `acr_values`, `ui_locales`,
  `user_code`, `prompt`, `login_hint`, `max_age`, `claims`, `code_challenge`, `code_challenge_method`,
  `username`, `id`, `tokenName`, `auditTrackingId`, `expireTime`.

On CHF this is `o2.setAttribute(key, value)` — `OAuth2Request.setAttribute` exists (`:241`) and
`ChfOAuth2Request` implements it over the same lazily-seeded map `getParameter` reads first (`:309-315`,
`:379-399`). So seeding the attributes reproduces **both** effects Restlet got for free: the consent model sees
them (finding 2) *and* every subsequent `o2.getParameter(...)` in the same request resolves against the device
code rather than the wire — which is what makes `providerSettingsFactory.get(request)`,
`clientRegistrationStore.get(client_id, request)` and `authorizationService.authorize(request)` work at all on
this endpoint.

⚠ The realm write is load-bearing and slightly surprising: a device code created in `/alpha` and verified via
`/oauth2/device/user` (root-realm URL) resolves the client in `/alpha`. Reproduce it; do not "fix" it.

<a id="4--which-renders-are-display-scoped-and-which-are-not"></a>
### 4. Which renders are `?display=`-scoped, and which are not

Three different rendering paths in one endpoint, and they do not agree:

| Page | Restlet call | Path resolution |
|---|---|---|
| `CodeVerificationForm.ftl`, `CodeThanks.ftl` | `getTemplateFactory(ctx).getTemplateRepresentation("templates/CodeVerificationForm.ftl")` (`:223-224`) | **literal path, no display folder** |
| consent `authorize.ftl` | `representation.getRepresentation(ctx, request, "authorize.ftl", model)` (`:197-198`) | **display-scoped**, incl. the popup composition |
| `checkSession.ftl` | `representation.getRepresentation(ctx, request, "checkSession.ftl", model)` (`OpenIDConnectCheckSessionEndpoint`) | **display-scoped** |

⇒ on CHF: `renderer.render("templates/CodeVerificationForm.ftl", …)` for the two device pages (never
`renderForDisplay`), `consentPageRenderer.render(…)` for the consent page, and `renderForDisplay` for
check-session (D5).

Template inventory verified: `templates/{CodeThanks,CodeVerificationForm,FormPostResponse}.ftl`,
`templates/page/{authorize,checkSession,error}.ftl`, `templates/popup/{authorize,popup}.ftl`,
`templates/touch/authorize.ftl`, `templates/wap/authorize.ftl`. **`checkSession.ftl` exists only under
`page/`.**

Model contracts (unguarded `${…}` = the render throws if absent):

- `CodeVerificationForm.ftl` — **requires** `realm`, `baseUrl`; optional `locale`, `errorCode`.
- `CodeThanks.ftl` — **requires** `realm`, `baseUrl`; optional `locale`. (Note `realm : "${realm?js_string}/XUI"`
  — a pre-existing oddity in the template. Not ours to fix here.)
- `page/checkSession.ftl` — **requires** `baseUrl`, `client_uri`, `valid_session`, `cookie_name`.
  `valid_session` is put as a **`String`** (`Boolean.valueOf(...).toString()`) and the template emits it
  unquoted (`var validSession = ${valid_session?js_string};`), so the type must stay `String`.

<a id="5--checksession-is-shadowed-by-a-jsp-and-what-that-does-and-does-not-mean"></a>
### 5. `/connect/checkSession` is shadowed by a JSP — what that does and does not mean

`web.xml` maps `/oauth2/connect/checkSession` to the `OAuth2ConnectCheckSession` servlet
(`<jsp-file>/oauth2/checkSession.jsp</jsp-file>`) as an **exact** mapping, which out-ranks both `/oauth2/*`
mappings under the servlet spec. Consequences, all verified:

- the standard path is served by the JSP **today and after 5d-1** — moving `/oauth2/*` from `ForgeRockRest` to
  `OpenAM` does not change exact-mapping precedence, so **no web.xml edit is needed for check-session** and
  none should be made ([D5-5](phase-5-oauth2.md), locked);
- the Restlet endpoint is reachable only via a **realm-prefixed** URL — `/oauth2/realms/root/connect/checkSession`
  or the legacy `/oauth2/<subrealm>/connect/checkSession`. Mounting `CheckSessionHandler` on the ordinary
  endpoint router reproduces exactly that, because the realm router is attached under the same endpoint router
  and the container keeps the JSP on the bare path. **No special routing work at 5d-1** — mount it like any
  other route;
- the JSP and the FTL are **not** byte-identical: the JSP loads `../../js/sha256.js` (relative) and inlines
  ESAPI-JavaScript-encoded values; the FTL loads `${baseUrl}/js/sha256.js` (absolute) and uses `?js_string`.
  That difference is the discriminator 5-E3 should use to prove which one answered a given URL;
- **`X-Frame-Options` is correctly suppressed on both paths.** `SetHeadersFilter` matches its `excludes` with
  `getRequestURI().endsWith(s)` (`:81`) and the exclude is `/connect/checkSession`, so
  `/openam/oauth2/realms/root/connect/checkSession` is excluded too. The session-management iframe therefore
  works on the handler path. Worth knowing; no action.

Related, and worth recording because it looks like a migration bug and is not: `FQDNValidationFilter` is mapped
to the **exact** patterns `/oauth2/authorize` and `/oauth2/device/user` only (`web.xml:186-193`), so the
realm-prefixed variants of both have never had FQDN validation. Servlet filters are unaffected by the flip.

<a id="6--no-e-lock-covers-these-three--what-e2e-already-records-and-what-it-does-not"></a>
### 6. ⚠ No §E lock covers these three — what e2e already records, and what it does not

The §E/§E2 contract locks cover `/access_token`, the cache headers and `/authorize`. Nothing covers these
three. What **does** already exist is ordinary behaviour coverage, which is useful but is not a byte-level lock:

Already green (keep, and treat as recorded oracle rows):

| Row | Where | Records |
|---|---|---|
| checkSession serves the iframe | `oidc-test.spec.mjs:201-213` | 200 `text/html`, contains `addEventListener`/`receiveMessage`/`session_state` — but **does not distinguish JSP from FTL** |
| endSession without `id_token_hint` | `oidc-test.spec.mjs:214-222` | **400 JSON** `bad_request` + exact description |
| endSession with a valid hint, no `post_logout_redirect_uri` | `oidc-test.spec.mjs:223-247` | **204, zero-length body** |
| `/device/user` GET, no `user_code` | `oauth2-endpoints-test.spec.mjs:243-259` | 200 `text/html` (the form) |
| `/device/user` GET + code, unauthenticated | `:261-283` | **301** → `/UI/Login` with `goto` containing `/oauth2/device/user` |
| `/device/user` GET + code, authenticated, consent implied | `:285-308` | 200 `text/html` (the thanks page) |

Missing, and only recordable before 5d-1 (**5-E3**):

1. `/device/user` with an **unknown/expired `user_code`** → the form page with `errorCode` (status? headers?);
2. `/device/user` **POST** `decision=allow` against a consent-requiring client → thanks page; and `decision=deny`
   → the delete path;
3. `/device/user` POST with a **missing/wrong `csrf`** → `OAuth2RestletException(400,"bad_request")` via the
   4-arg `doCatch` ⇒ expected to be the **HTML error page**, not JSON. Confirm;
4. `/device/user` **consent page** render for a consent-requiring client (needs `test_client_consent`, which
   5-E2 already added — reuse it), capturing the `oauth2Data` keys that finding 2 says must survive;
5. **cache headers** on all three (expected: none — see [finding 8](#8--none-of-the-three-gets-cache-headers));
6. `/oauth2/realms/root/connect/checkSession` → 200, and **which** page (the `sha256.js` discriminator);
7. `/oauth2/realms/root/connect/checkSession?display=popup` and `?display=touch` → the status/body today
   (gates **D5**);
8. `/connect/endSession` with a valid `post_logout_redirect_uri` **+ `state`** → 302 and the exact `Location`,
   including one case where the redirect URI **already carries a query string** (gates **D8**);
9. `/connect/endSession` with a `post_logout_redirect_uri` **not** in the client's registered list → JSON
   `redirect_uri_mismatch`; and a **relative** one → JSON `relative_redirect_uri` (400,
   `RelativeRedirectUriException:30`);
10. `/connect/endSession` with a **malformed** `id_token_hint` → the unchecked-JWT path (gates **D7**);
11. `PUT` on each of the three (framework-405 divergence, as [D8](phase-5b-1.md#d8) recorded for `/authorize`).

<a id="7--the-device-verify-control-flow-branch-by-branch"></a>
### 7. The device `verify()` control flow, branch by branch

`DeviceCodeVerificationResource.verify` (`:128-209`), the single method both verbs share
(`userCodeForm()` at `:265-274` delegates to it whenever `user_code` is present, else renders the bare form):

```
readDeviceCode(user_code)  --InvalidGrantException--> FORM page, errorCode="not_found"      [200]
   |
   +-- deviceCode == null || isIssued() ----------->  FORM page, errorCode="not_found"      [200]
   |
addRequestParamsFromDeviceCode()   (finding 3)
   |
requireConsent = !clientsCanSkipConsent || !isConsentImplied
   |
   +-- requireConsent && decision non-empty:
   |      isCsrfAttack -> OAuth2RestletException(400,"bad_request",null,state)     [HTML error page]
   |      save_consent=="on" -> saveConsent(request)
   |      decision=="allow" -> validate() ; setResourceOwnerId ; setAuthorized ; updateDeviceCode
   |      else               -> deleteDeviceCode
   |
   +-- requireConsent && decision empty:
   |      authorizationService.authorize(request)   -> throws ResourceOwnerConsentRequired
   |                                                  -> CONSENT page (authorize.ftl)       [200]
   |
   +-- !requireConsent:
          validate() ; setResourceOwnerId ; setAuthorized ; updateDeviceCode
   |
THANKS page                                                                                 [200]
```

Catch list (`:186-206`), all of which the browser base now absorbs except the first and third:

| Caught | Restlet result | CHF |
|---|---|---|
| `IllegalArgumentException` | 400 `invalid_request`; **redirects** to the raw `redirect_uri` unless the message names `client_id` | base `onIllegalArgument` → one non-redirecting 400 page (**D7 of 5b-1**, already shipped) |
| `ResourceOwnerAuthenticationRequired` | 307 → `Redirector(MODE_CLIENT_PERMANENT)` = **301** to the login URI | identical via `OAuth2Error.of` + [D13](decisions.md) |
| `ResourceOwnerConsentRequired` | consent page | caught in the handler (not an `OAuth2Exception`) |
| `InvalidClientException`, `RedirectUriMismatchException` | no redirect, own status/error | identical (`NEVER_REDIRECT`) |
| any other `OAuth2Exception` | redirect to raw `redirect_uri`, `parameterLocation` honoured | identical |

⇒ the device flow inherits **exactly** the 5b-1 `IllegalArgumentException` unification (D7 there) with no new
decision required: its GET/POST-symmetric `catch` is the *same shape* `AuthorizeResource`'s GET had, and the
base already answers it the safe way. Record it as the same divergence row, not a new one.

Also: `tokenStore.updateDeviceCode`/`deleteDeviceCode` declare `InvalidGrantException`, which the method
**re-throws** (it is only caught around `readDeviceCode`). `InvalidGrantException` is an `OAuth2Exception`, so
on CHF it reaches the base mapper — matching Restlet, where it reached `doCatch`'s 4-arg handler as an
`OAuth2Exception` cause. No special handling.

<a id="8--none-of-the-three-gets-cache-headers"></a>
### 8. None of the three gets cache headers — and all three audit with no body detail

`OAuth2Filter` has exactly two subclasses, `AuthorizeEndpointFilter` and `TokenEndpointFilter`, and
`OAuth2RouterProvider` wraps only `/authorize` and `/access_token` in them. All three of this step's endpoints
are attached as bare `auditWithOAuthFilter(wrap(X.class))` (`OAuth2RouterProvider:122,123,141`) ⇒ **no
`Cache-Control`, no `Pragma`, on success or error**.

⇒ none of the three overrides `withErrorHeaders`, none calls `noCache`, and `OAuth2NoCacheFilter` stays scoped
to its two routes at 5d-1 exactly as its javadoc warns. 5-E3 row 5 pins this.

**Audit matrix for 5d-1** (recorded here so the flip does not have to re-derive it). That same bare
`auditWithOAuthFilter(restlet)` overload passes `noBodyAuditor()` for **both** request and response
(`OAuth2RouterProvider:150-153`), so all three routes wrap in
`OAuth2HttpAccessAuditFilter(publisher, factory, requestFactory, HttpBodyAuditor.noBodyAuditor(),
HttpBodyAuditor.noBodyAuditor())` — i.e. **no body detail in either direction**:

| Route | Request auditor | Response auditor |
|---|---|---|
| `device/user` | none | none |
| `connect/checkSession` | none | none |
| `connect/endSession` | none | none |

Convenient, and worth stating rather than assuming: `/device/user` is the one endpoint of the three that reads
a **form body**, so a non-`noBodyAuditor` here would have put the audit filter and the handler in contention
for the buffered entity (risk #1). Restlet already declined to audit it; reproduce that.

<a id="9--no-hooks-and-no-content-type-validation"></a>
### 9. No hooks, and no method/content-type validation

- **Hooks.** None of the three invokes `AuthorizeRequestHook` or `TokenRequestHook` — verified by reading all
  three classes. `ChfAuthorizeRequestHook` is **not** injected into any 5b-2 handler. (`LoginHintHook` therefore
  does not run on `/device/user`; that is today's behaviour.)
- **Validation.** With no `OAuth2Filter` wrapper there is no `validateMethod` and no `validateContentType` on
  any of the three. ⇒ **no `OAuth2ContentTypes.isFormUrlEncoded` guard** in these handlers (unlike
  `AuthorizeHandler`, which needs it — [5-E2 row 8](phase-5b-1.md#d8)). Adding one would be a narrowing that
  turns today's 200 into a 400.
- Unsupported verbs get Restlet's own 405 today and the framework's 405 (body rewritten by `OAuth2ErrorFilter`)
  after the flip — the same status-matches/body-differs divergence [D8](phase-5b-1.md#d8) recorded. 5-E3 row 11.

<a id="10--endsession-the-two-shapes-and-the-unchecked-jwt-path"></a>
### 10. `EndSession`: two shapes, and the unchecked-JWT path

`EndSession.endSession()` (`:87-109`):

1. `openIDConnectEndSession.endSession(request, idToken)` — throws `BadRequestException` (an `OAuth2Exception`)
   when `id_token_hint` is absent/empty; **`ServerException` is caught and swallowed with a `warn`** (`:98-100`)
   — "possibly already timed out". Reproduce the swallow.
2. If `post_logout_redirect_uri` is non-empty → `handleRedirect` → `validateRedirect` (`:138-154`):
   reconstruct the JWT, read **only** the `azp` claim, look the client up, require an **absolute** URI
   (`RelativeRedirectUriException`, 400 `relative_redirect_uri`) and require the URI to be in
   `client.getPostLogoutRedirectUris()` (`RedirectUriMismatchException`). Then
   `new Reference(redirectUri)`, append `state` as a **query** parameter when non-empty, and
   `Redirector(MODE_CLIENT_FOUND)` = **302**.
3. Otherwise return `null` → **204, empty body** (already recorded in e2e).

⚠ **`JwtReconstruction.reconstructJwt` is unchecked.** A malformed `id_token_hint` raises a `RuntimeException`
that escapes the `catch (OAuth2Exception)` and lands in `doCatch` → `toOAuth2RestletException`'s final `else` →
`new ServerException(throwable)` → **400 `server_error` JSON**. On CHF an unchecked throw from an endpoint
method reaches `AnnotatedMethod.handleException`, and the JSON base's `@ExceptionHandler` declares
`OAuth2Exception`, which does not match ⇒ the framework's **CREST 500**. The `id_token_hint` is
client-controlled, so this is **not** one of the bug paths [D3](decisions.md) sends to the framework; it needs
the narrow handler-level wrap of D7.

⚠ **The `azp` claim is trusted without verifying the id_token signature** (`:142-144`) — already on the
[parity-preserved security-debt list](phase-5-oauth2.md#parity-preserved-security-debts--reproduce-now-fix-later-finding-7).
Reproduce verbatim; do not fix inside this migration.

<a id="11--no-openam-http-change-is-required"></a>
### 11. No openam-http change is required — verified, not assumed

`AnnotatedMethod.mostSpecificExceptionHandler` walks the thrown exception's superclass chain and picks the
closest declared handler (`:185+`); `findExceptionHandlers` scans `getClass().getMethods()`, so inherited
handlers count (`:230-250`). Both bases' mappers therefore behave as 5b-1 designed them, and nothing this step
needs is missing from the framework — F1–F4 ([openam-http-framework.md](openam-http-framework.md)) already
closed the endpoint-framework gaps.

⚠ **This was very nearly the wrong conclusion.** The first draft of this plan used that superclass-chain fact
to justify a `@ExceptionHandler onRuntimeFailure(RuntimeException …)` on `AbstractOAuth2HttpJsonEndpoint`,
restoring Restlet's blanket 400 `server_error` for *any* unchecked throw. It would have worked mechanically —
and it directly contradicts locked **[D3](decisions.md)**, which decided that the uncaught-*bug* path keeps
CHF's 500 precisely so server bugs are not permanently masked from monitoring. The lesson is worth recording:
*"the framework lets me"* is not *"the migration decided to"*. See D7 for the narrow, D3-compatible answer.

The change this step *does* make is in **our own** OAuth2 code, not the framework: `OAuth2ErrorFilter.errorFor`
(D10). The standing framework/commons items are unchanged and untouched by 5b-2 — they live in
[decisions.md's CHF cleanup backlog](decisions.md#chf-cleanup-backlog).

<a id="12--csrfprotection-is-already-neutral"></a>
### 12. `CsrfProtection` is already neutral — and the device flow checks it inline

`CsrfProtection.isCsrfAttack(OAuth2Request)` and `createCsrfToken(OAuth2Request)` take the neutral request and
reach the servlet objects through `getHttpServletRequest()`/`getHttpServletResponse()` — nothing to port. Two
behaviours to preserve:

- the check runs **only when `decision` is non-empty** (`:157-162`), so the consent-page GET and the
  no-consent-required path never touch it;
- on `/authorize` the equivalent check lives inside `AuthorizationService`; here it is inline. Keep it inline —
  moving it would change which errors precede it.

<a id="13--checksessions-data-model-and-its-servlet-request-dependency"></a>
### 13. `CheckSession`'s data model and its servlet-request dependency

`OpenIDConnectCheckSessionEndpoint.getDataModel` builds:

| Key | Source | Type |
|---|---|---|
| *(bulk)* | `new HashMap<>(getRequest().getAttributes())` | — inert: no key any template reads |
| `cookie_name` | `checkSession.getCookieName()` | `String` |
| `client_uri` | `checkSession.getClientSessionURI(servletRequest)` | `String` |
| `valid_session` | `Boolean.valueOf(checkSession.getValidSession(servletRequest)).toString()` | **`String`** |
| `baseUrl` | `baseURLProviderFactory.get(realm).getRootURL(servletRequest)` | `String` |

`CheckSession` (`org.forgerock.openidconnect.CheckSession`) takes a raw `HttpServletRequest` — it reads the
`Referer` header to find an `id_token` and reads cookies. On CHF that is `o2.getHttpServletRequest()`. The class
itself is transport-neutral already (its no-arg constructor pulls its collaborators from `InjectorHolder`), so
**it is not ported** — only its Restlet wrapper is. Guice JIT-binds it.

`getClientSessionURI` can throw `UnauthorizedClientException`/`InvalidClientException`/`NotFoundException`, all
`OAuth2Exception`s ⇒ the JSON base maps them. It can also **NPE**: `:111-115` guards
`clientRegistration != null` for the validity check and then dereferences `clientRegistration` unconditionally,
so a JWT whose audience resolves to no client throws an NPE → today a 400 `server_error` JSON via `doCatch`,
after D7 the same. Pre-existing; reproduced by D7, not fixed here.

<a id="14--the-request-cache-is-load-bearing-here-and-nothing-tests-it"></a>
### 14. ⚠ The CHF request cache is load-bearing for the device flow — and **nothing tests it**

`OAuth2RequestFactory.create(Context, Request)` caches the `ChfOAuth2Request` on the `AttributesContext` under
`OAUTH2_REQ_ATTR`, so the handler and the base's `@ExceptionHandler` share **one instance** — and it publishes
into the cache *before* resolving the client registration, so re-entrancy is safe.

On `/authorize` that sharing is convenient. On `/device/user` it is **behaviour**: after
`addRequestParamsFromDeviceCode`, Restlet's catch clauses read `request.getParameter("state")` and get the
**device code's** state, not the wire's (the wire usually carries none — the user posted a form). If the CHF
mapper builds a fresh `OAuth2Request`, every device-flow error loses its `state`, and the attribute seeding of
D3 evaporates at exactly the moment it is needed.

⚠ **No existing test exercises this.** `AuthorizeHandlerTest` and `AuthorizeRouteCompositionIT` both **mock**
`OAuth2RequestFactory` and pass a bare `new RootContext()` — which is also why they work at all, since the real
`create` calls `context.asContext(AttributesContext.class)` and that **throws** when the context is absent. A
mocked factory hands the same stub to handler and mapper by construction, so a unit test is *structurally
incapable* of catching a broken cache. Only an IT with the **real** factory and an `AttributesContext` in the
chain can. That is a named row of `DeviceCodeRouteCompositionIT`, not an implied one.

---

