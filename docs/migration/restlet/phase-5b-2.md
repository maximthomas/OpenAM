# Phase 5b-2 — `/device/user`, `/connect/checkSession`, `/connect/endSession` → CHF: Detailed Plan

Execution plan for **step 5b-2** of [Phase 5](phase-5-oauth2.md) of the Restlet → CHF migration — the three
remaining browser-facing `/oauth2` endpoints. Parent tracker: [plan.md](plan.md); umbrella:
[phase-5-oauth2.md](phase-5-oauth2.md); the step this one builds on: [phase-5b-1.md](phase-5b-1.md) (the
`AbstractOAuth2HttpEndpoint`/`…Browser`/`…Json` hierarchy, `ConsentPageRenderer`, `OAuth2ContentTypes`,
`OAuth2NoCacheFilter`); build-ahead infra it consumes: [phase-3c-1-renderer.md](phase-3c-1-renderer.md),
[phase-3c-2-error-layer.md](phase-3c-2-error-layer.md); decisions: [decisions.md](decisions.md); reusable CHF
patterns: [chf-patterns.md](chf-patterns.md); test layers: [../../test-infrastructure.md](../../test-infrastructure.md).
Written 2026-07-28; branch `features/restlet-migration`. **All facts below were verified against the tree on
2026-07-28** — file and line references are to that state.

> **Naming.** [plan.md](plan.md)'s phase table calls this step **5b-2**. This doc splits it into **5-E3** (a
> test-only live-oracle gate), **5b-2a** (the two JSON-error endpoints) and **5b-2b** (the device flow) — the
> same reviewability/risk-isolation split 5a-2 and 5b-1 used.

## Context

The umbrella describes these three as "near-mechanical relative to `AuthorizeHandler`", and by volume they are:
`DeviceCodeVerificationResource` 302 L, `OpenIDConnectCheckSessionEndpoint` 119 L, `EndSession` 156 L against
`AuthorizeResource`'s ~600 L. But the umbrella's one-line framing —
*"Extend `AbstractOAuth2HttpBrowserEndpoint` (from 5b-1). All three are near-mechanical"* — **is wrong about
the most load-bearing thing in the step**: only **one** of the three is a browser endpoint. See
[finding 1](#1--only-one-of-the-three-is-a-browser-endpoint-the-doccatch-arity-decides).

Two further things make this step less mechanical than the sizing suggests:

- the device flow reaches the consent page through a **different data path** than `/authorize` does, and
  `ConsentPageRenderer` as shipped in 5b-1 **cannot serve it correctly** ([finding 2](#2--consentpagerenderer-phase-1-is-realm-only-and-that-silently-breaks-the-device-consent-page));
- there is **no §E contract lock** for any of the three, and three of this doc's decisions are gated on
  observations that can only be made while Restlet still serves `/oauth2`
  ([finding 6](#6--no-e-lock-covers-these-three--what-e2e-already-records-and-what-it-does-not)).

Build-ahead as usual: **nothing is routed** until 5d-1.

> **Convention.** New classes: `org.openidentityplatform.openam.oauth2.http` (OAuth2) /
> `org.openidentityplatform.openam.openidconnect.http` (OIDC), CDDL header, `Copyright 2026 3A Systems LLC.`,
> **no `@since`** ([decisions.md](decisions.md)). Classes modified in place keep their header and gain a
> `Portions copyright 2026 3A Systems LLC.` line — except our own 2026 classes, which carry no `Portions` line.

## Scope & sizing — split three ways

| Step | Scope | New / changed | Risk |
|---|---|---|---|
| **5-E3** | **The live-Restlet contract lock for all three endpoints.** ~14 rows added to the existing `e2e/oauth2/oidc-test.spec.mjs` (`OIDC session endpoints`) and `e2e/oauth2/oauth2-endpoints-test.spec.mjs` (`OAuth2 device flow`) describes, written **by observation**. Test-only, no main code. Gates D5, D7, D8 | e2e specs only (0 main) | **High** — unrecoverable after 5d-1 |
| **5b-2a** | **The two JSON-error endpoints**: `EndSessionHandler`, `CheckSessionHandler`. Both extend `AbstractOAuth2HttpJsonEndpoint` unchanged; each wraps its own client-reachable unchecked throw (D7). Carries the `OAuth2ErrorFilter` 405 one-liner (D10) | 2 new + 1 filter one-liner + 3 tests | **Med** |
| **5b-2b** | **The device flow**: `DeviceCodeVerificationHandler` + the `ConsentPageRenderer` phase-1 correction (D2) it forces | 1 new + 1 modified + 2 tests + 1 IT | **High** |

**Total new main classes: 3.** Plus one behavioural correction to a 5b-1 class (`ConsentPageRenderer`) and one
additive mapper on a 5a class (`AbstractOAuth2HttpJsonEndpoint`).

Order: **5-E3 → 5b-2a → 5b-2b**. 5-E3 first for the same reason 5-E2 was first in 5b-1: three of the decisions
below are *settled by* what it records, and the [CONTINUE-bug lesson](phase-5b-1.md#2--the-continue-bug-makes-authorizes-filter-validation-unpredictable--record-it-do-not-derive-it)
is that predicting this provider's error surface is unreliable. 5b-2a before 5b-2b because it is the smaller
and its `RuntimeException` mapper is a base-class edit the device handler also inherits.

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
[parity-preserved security-debt list](phase-5-oauth2.md#parity-preserved-security-debts--reproduce-now-fix-later).
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

## Design decisions

<a id="d1"></a>
### D1 — base class per endpoint, from the `doCatch` arity (finding 1)

```
AbstractOAuth2HttpEndpoint
├── AbstractOAuth2HttpJsonEndpoint    ← EndSessionHandler, CheckSessionHandler
└── AbstractOAuth2HttpBrowserEndpoint ← DeviceCodeVerificationHandler
```

Not negotiable and not a style choice: it is the difference between a JSON error body and an HTML page on every
error these endpoints produce. **The `@ExceptionHandler` methods on both bases must not be overridden**
(annotations are dropped on overrides — the trap both base javadocs already warn about).

<a id="d2"></a>
### D2 — `ConsentPageRenderer` phase 1 reads the same enumerated keys from the attributes

Change `dataModel`'s phase 1 from "copy `realm`" to "copy each of the enumerated keys that is present as an
attribute", keeping phase 2 (query overlay, `getQueryParameter` only) and phase 3 (derived, strictly last)
exactly as they are:

```java
// 1. Request attributes. On /authorize this is just the realm the RealmContext seeded; on the device
//    flow it is the whole device-code record, which is the ONLY source those keys have there.
for (String key : MODEL_KEYS) {                    // MODEL_KEYS == today's QUERY_KEYS
    Object value = o2.getAttribute(key);
    if (value != null) {
        data.put(key, value);
    }
}
// 2. Query overlay -- query wins.  (unchanged)
// 3. Derived keys, strictly last.  (unchanged)
```

Behaviour-neutral for `/authorize` (`ChfOAuth2Request.attributes()` seeds only `realm`, `realmObject` and URI
template variables — and `realmObject` is not in the list), and it is what makes the device consent page render
the same keys Restlet rendered. Guarded by a new `ConsentPageRendererTest` case that seeds device-code-shaped
attributes and asserts all seven keys survive.

*Alternative rejected:* have the device handler pre-copy attributes into the query. That mutates the request
URI (`setQueryParameter` writes through to it — `ChfOAuth2Request:324-334`), which would corrupt the consent
form's `target` and leak the device code's stored values into a page the user posts back.

<a id="d3"></a>
### D3 — seed the device code onto the `OAuth2Request` attributes, not into a local map

`o2.setAttribute(key, value)` per finding 3, including the `clientID` → `client_id` rename and the `scope`
join. Attributes are the first source `getParameter` consults, so this reproduces Restlet's effect on every
downstream collaborator in one place. Extracted as a package-private method so the test can assert the mapping
without a full flow.

<a id="d4"></a>
### D4 — the two device pages render by literal path; only the consent page is display-scoped

`renderer.render("templates/CodeVerificationForm.ftl", model)` / `"templates/CodeThanks.ftl"`, never
`renderForDisplay` (finding 4). Their model is exactly `{errorCode?, baseUrl, locale, realm}` with `errorCode`
**omitted** (not null-valued) when absent, so `<#if errorCode??>` behaves as it does today — Restlet put a null
into a `Map<String,String>`, which FreeMarker treats as missing; CHF should not put the key at all. `locale`
is `OAuth2Utils.joinStatic(o2.getAcceptedLanguages(), " ")` (the 5b-1a accessor); `baseUrl` is
`baseURLProviderFactory.get(o2.getParameter("realm")).getRootURL(o2.getHttpServletRequest())`.

<a id="d5"></a>
### D5 — `?display=` on check-session: keep display resolution, let a missing template be a 400 (**gated on 5-E3 row 7**)

`OpenIDConnectCheckSessionEndpoint` goes through the display-scoped renderer, so `CheckSessionHandler` uses
`renderForDisplay(display, "checkSession.ftl", model)`. Since `checkSession.ftl` exists only under `page/`:

| `?display=` | Restlet today | CHF after the 3c-1 D5 fix |
|---|---|---|
| absent / `page` | `page/checkSession.ftl` | identical |
| `popup` | renders the **hardcoded** `popup/authorize.ftl` with the check-session model — which reads `${display_name}`/`${display_scopes}` unguarded and therefore **throws**, surfacing as `ResourceException(400, "Server can not serve …")` → 400 JSON | `popup/checkSession.ftl` not found → `TemplateNotFoundException` (an `IOException`) |
| `touch` / `wap` | template missing → `TemplateFactory` returns null → `getRepresentation` throws `ResourceException(400, …)` → 400 JSON | `TemplateNotFoundException` |
| unknown | `Enum.valueOf` → `IllegalArgumentException` → 400 `server_error` JSON | `IllegalArgumentException` |

⇒ **Decision: one `try` around the render, mapping both `IOException` and `IllegalArgumentException` to
`ServerException` — 400 `server_error` JSON** (D7's second row). Every case above stays a 400 with a JSON body,
which is what live Restlet does for all of them; the only movement is in the `error_description` text.
**5-E3 row 7 must confirm the 400s before this lands**; if the oracle shows any of them succeeding, revisit (a
`page/` fallback is the alternative, and it would then be the parity-preserving choice).

This is the decision [3c-1's `renderForDisplay` javadoc](phase-3c-1-renderer.md) and
**[decisions.md D5](decisions.md)** both explicitly deferred to "Phase 5b's call". Update *both* to point here.

<a id="d6"></a>
### D6 — mount `CheckSessionHandler` on the ordinary route; the JSP keeps the bare path by itself

No web.xml change, no conditional routing, no special-casing (finding 5). `router.attach("connect/checkSession", …)`
in `OAuth2HttpRouteProvider` at 5d-1 is both correct and sufficient: the exact JSP mapping wins on
`/oauth2/connect/checkSession`, and the handler serves the realm-prefixed variants — which is precisely today's
split. **Do not delete the JSP or its mapping at 5d-2** ([R-5.7](phase-5-oauth2.md), locked).

<a id="d7"></a>
### D7 — wrap the **client-reachable** unchecked throws at their source; no base-class mapper (**revised at review; confirmed and extended by 5-E3, 2026-07-28**)

~~Three~~ **Four** unchecked throws in this step are reachable from client input, and each is wrapped where it
is raised so it leaves the handler as a checked `ServerException` — which the JSON base already maps to **400
`server_error`**, byte-identical to Restlet's `toOAuth2RestletException` fallback. All four are now pinned on
the live wire ([As-built](#as-built-5-e3--recorded-2026-07-28) rows 6d, 7 and 10):

| Where | Trigger | Wrap |
|---|---|---|
| `EndSessionHandler` | malformed `id_token_hint` → `JwtReconstruction.reconstructJwt` (finding 10) | `catch (RuntimeException e) { throw new ServerException(e); }` around the reconstruction |
| `CheckSessionHandler` | `?display=bogus` → `Enum.valueOf` `IllegalArgumentException` (D5) | around the `renderForDisplay` call, together with its `IOException` |
| `CheckSessionHandler` | id_token with **no `aud` claim** → NPE in `CheckSession.getClientSessionURI` (finding 13) | around the `getClientSessionURI`/`getValidSession` pair |
| `CheckSessionHandler` | **any** valid id_token when the client's `clientSessionURI` is **unset** → `NoSuchElementException` from `set.iterator().next()` in `OpenAMClientRegistration.getClientSessionURI:426-434` (**added by 5-E3**) | the same wrap as the row above — it is the same call |

⚠ The fourth row is the one to take seriously, because it is not an edge case: the admin API leaves
`com.forgerock.openam.oauth2provider.clientSessionURI` **empty on every client it creates**, and
`getClientSessionURI()` has no emptiness guard. So on a default-configured deployment, check-session **400s on
its own happy path** the moment an RP actually supplies an `id_token` — the endpoint's entire reason for
existing. 5-E3 only got a 200 out of row 6c after the fixture set the attribute explicitly. This does not
change the port (the same wrap covers it), but the separate null-guard ticket in checklist step 9 must cover
**the empty set as well as the null registration**, or it fixes the rarer half of the bug.

⚠ **Explicitly *not* a `@ExceptionHandler` on `AbstractOAuth2HttpJsonEndpoint`.** An earlier draft of this plan
proposed exactly that, and it contradicts locked **[D3](decisions.md)**: *"the uncaught-bug path keeps CHF's
500; Restlet's 400 is not reproduced […] reproducing 400 would mean a filter that downgrades a 500 —
permanently masking server bugs from monitoring."* A blanket mapper cannot tell a malformed JWT from a null
dereference in a collaborator, so it would restore parity on three paths by hiding every future one. Wrapping
at the source keeps the distinction the migration already decided to keep, and it touches **none** of the five
committed 5a handlers — so there is no base-class edit, no regression gate on their suites, and nothing new for
the 5d-1 diff notes.

The third row is a **pre-existing product bug**, not a migration artifact: `getClientSessionURI:111-115` guards
`clientRegistration != null` for the validity check and then dereferences it unconditionally, and
`getClientRegistration` returns null exactly when the JWT carries no audience. Reproduced here (400
`server_error`, as today); **fixing the guard is its own commit with its own test and release note** — the same
treatment `ServerException`'s hardcoded 400 got under [D2](decisions.md), and the same reason the
`touch/authorize.ftl` typo and the unverified `id_token_hint` signature are reproduced rather than corrected
inside a parity migration.

*Alternative rejected:* leave all three to the framework's 500. It converts three client-controlled inputs into
server errors, which is a monitoring regression in the opposite direction and a worse wire contract than the
one being replaced.

<a id="d10"></a>
### D10 — `OAuth2ErrorFilter` maps a rewritten **405** to `method_not_allowed` (**decided at review, 2026-07-28**)

```java
case 405:
    return "method_not_allowed";   // parity with AuthorizeEndpointFilter/TokenEndpointFilter
```

`errorFor` currently sends every rewritten 4xx except 401/403 to `invalid_request` through its `default` branch,
so at the flip a wrong verb answers `invalid_request` where live Restlet answered **`method_not_allowed`** —
recorded twice already, by [5-E](plan.md) for `GET /access_token` and [5-E2 row 7](phase-5b-1.md#d8) for
`PUT /authorize`.

> ⚠ **Cite the subclasses, not the base.** `OAuth2Filter.validateMethod` is **abstract** (`OAuth2Filter.java:88`)
> and emits nothing. The literal comes from `AuthorizeEndpointFilter.validateMethod:54` (`"Required Method: GET
> or POST found: "`) and `TokenEndpointFilter.validateMethod:54` (`"Required Method: POST found: "`) — the two
> concrete subclasses, and the reason the parity claim covers exactly two routes. An earlier draft of this
> decision and of the filter's own javadoc cited the abstract base, which sends a reader chasing the route-scope
> question to an empty declaration.

> **Corrected by 5-E3 row 11 (2026-07-28).** The original draft of this paragraph went on: *"5b-2 would have
> added three more endpoints to that list, which is what turned a tolerated one-off into a pattern worth
> closing."* **That is false.** None of this step's three endpoints emits `method_not_allowed` today — none is
> wrapped by `OAuth2Filter`, so a wrong verb gets the framework's **CREST** `{code, reason, message}` body
> (see the [As-built](#as-built-5-e3--recorded-2026-07-28)). D10 therefore rests on **two** endpoints,
> `/authorize` and `/access_token`, not five. It still stands — the caveat below anticipated exactly this
> outcome — but the "pattern" argument does not, and the decision should be read as the narrow parity fix it
> is.

One line, in **our own** code, no framework change. It **narrows but does not delete**
[expected divergence #3](plan.md#expected-divergences-at-the-flip): the `error` field — the one clients dispatch
on — becomes identical, while `error_description` still differs (the framework's `"Method Not Allowed"` against
Restlet's `"Required Method: GET or POST found: PUT"`). Update that row rather than removing it.

⚠ Two things to be honest about. `method_not_allowed` is **not** an RFC 6749 error code, and `errorFor`'s
javadoc argues for RFC-specific codes — but Restlet emitted the non-standard value, and this is a parity
migration, so the incumbent wins. And the mapping also applies to endpoints where a wrong verb produced a
**CREST** body under Restlet rather than an OAuth2 one (everything the `OAuth2Filter` did not wrap, including
all three of this step's); those diverge either way, and `method_not_allowed` is no further from a CREST 405
than `invalid_request` was. **5-E3 row 11 records what each of the three actually sends** — if any of them
turns out to emit `method_not_allowed` today, this decision gets *better*, not worse.

Lands in **5b-2a**, with a new `OAuth2ErrorFilterTest` case and a re-run of `AuthorizeRouteCompositionIT`
(whose D8 row asserts the current `invalid_request` body and must be updated in the same commit).

> **As-built 2026-07-28 — the blast radius is 4 test rows across 2 ITs, not 1.** Gate 6 predicted "exactly one
> intentional edit"; the real set is `AuthorizeRouteCompositionIT`'s two rows (the stand-in handler *and*
> `theRealHandlerAnswersPutWithTheFrameworks405`) plus `OAuth2ErrorRouteCompositionIT`'s
> `aMappedVerbWithNoAnnotatedMethod…` and `anUnmappedVerb…`, the latter pair proving one `case` covers **both**
> framework 405 paths — `AnnotatedMethod`'s own and `Endpoints`' fallback — because `errorFor` keys off the wire
> status, not the body's `code`. **The gate still passes on its substance**: every moved row is a 405 assertion,
> nothing at 400/401/403/404/500/503 moved. The plan simply recalled one of the two ITs.
>
> Also corrected: gate 6 and [R-5b2.9](#risk-register-extends-phase-5-oauth2mds) call `OAuth2ErrorFilter`
> "composed on already-committed routes" / "a live-bound path". It is **not bound to any route yet** —
> `new OAuth2ErrorFilter()` appears in three test files and nowhere else, and `openam-oauth2` has no
> `OAuth2HttpRouteProvider` (only the two `/frrest` providers). Build-ahead holds: D10 cannot reach a client
> until 5d-1 mounts the filter, which also means **no test here proves the value on a real wire** — only the
> 5d-1 e2e re-run will.

<a id="d8"></a>
### D8 — the endSession 302 composes through `RedirectUris` (**gated on 5-E3 row 8**)

```java
Map<String, String> params = isEmpty(state) ? Map.of() : Map.of("state", state);
return redirectTo(RedirectUris.compose(redirectUri, params, UrlLocation.QUERY));
```

`RedirectUris.compose(…, QUERY)` **appends**, which is what `Reference.addQueryParameter` did; the
percent-encoding parity between the two was proven and closed at 3c-2 ([plan.md](plan.md) risk #3). The
documented empty-params divergence — an empty map leaves the target untouched — is **the desired behaviour
here**, matching Restlet's `if (state != null && !state.isEmpty())` guard exactly.

The one thing observation must settle is whether `new Reference(uri).toString()` **normalises** a redirect URI
that already carries a query or a fragment, where `RedirectUris` emits it verbatim. 5-E3 row 8 registers a
`post_logout_redirect_uri` with an existing query string and records the exact `Location`. If they differ,
record it as an expected 5d-1 divergence rather than bending `RedirectUris`, whose contract is shared with
`/authorize`.

Status is **302** (`MODE_CLIENT_FOUND`); the no-redirect path returns **204 with no entity**, which on CHF is
`new Response(Status.NO_CONTENT)` — matching the already-recorded e2e row.

<a id="d9"></a>
### D9 — handler shapes

```java
// org.openidentityplatform.openam.oauth2.http
public class DeviceCodeVerificationHandler extends AbstractOAuth2HttpBrowserEndpoint {
    @Get  public Response userCodeForm(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
    @Post public Response verify(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
}

// org.openidentityplatform.openam.openidconnect.http
public class CheckSessionHandler extends AbstractOAuth2HttpJsonEndpoint {
    @Get  public Response checkSession(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
    @Post public Response checkSessionPost(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
}

public class EndSessionHandler extends AbstractOAuth2HttpJsonEndpoint {
    @Get  public Response endSession(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
}
```

`CheckSessionHandler` keeps **both** verbs (`OpenIDConnectCheckSessionEndpoint` has `@Get` and `@Post`, both
delegating to the same body). `EndSessionHandler` is GET-only, as today. `DeviceCodeVerificationHandler`'s two
verbs delegate to one private method, mirroring `userCodeForm()` → `verify(null)`; the GET renders the bare
form when `user_code` is absent.

---

## New / modified / tests

### 5-E3 — test-only

- `e2e/oauth2/oidc-test.spec.mjs` — extend `OIDC session endpoints` with the check-session and endSession rows
  (finding 6, items 6–11).
- `e2e/oauth2/oauth2-endpoints-test.spec.mjs` — extend `OAuth2 device flow` with the device rows (items 1–5),
  reusing `test_client_consent` from 5-E2 for the consent-requiring cases.
- Label every new row `(5-E3, live Restlet)` in its title so the 5d-1 re-run can select them.

### 5b-2a

**New:** `CheckSessionHandler`, `EndSessionHandler` (`org.openidentityplatform.openam.openidconnect.http`).
**Modified:** `OAuth2ErrorFilter` (D10, one `case` — our own 2026 class, no `Portions` line).
**Unmodified, deliberately:** `AbstractOAuth2HttpJsonEndpoint` — see D7.

### 5b-2b

**New:** `DeviceCodeVerificationHandler` (`org.openidentityplatform.openam.oauth2.http`).
**Modified:** `ConsentPageRenderer` (D2 — our own 2026 class, no `Portions` line);
`FreemarkerTemplateRenderer` javadoc (point the deferred `renderForDisplay` question at D5).

### Tests (openam-oauth2; TestNG + Mockito + AssertJ; scaffold per [chf-patterns §5](chf-patterns.md#5-chf-handler-test-scaffolding) — the reflection walk now spans **three** levels)

**5b-2a**

- **`OAuth2ErrorFilterTest`** (extended) — D10: a CREST-shaped **405** body is rewritten to
  `method_not_allowed`; 400/404 still give `invalid_request`; 401/403/503 unchanged. Plus the same round-trip
  through `AuthorizeRouteCompositionIT`'s existing D8 row, **updated in the same commit** — it currently asserts
  `invalid_request` for `PUT /authorize`.
- **`EndSessionHandlerTest`** — no `id_token_hint` → 400 `bad_request` JSON with the exact description;
  `ServerException` from `endSession` is **swallowed** and the flow continues; no `post_logout_redirect_uri`
  → **204, empty entity**; valid redirect + `state` → **302** with `state` in the **query**; valid redirect,
  no `state` → 302 with the URI untouched; relative URI → 400 `relative_redirect_uri`; unregistered URI →
  `redirect_uri_mismatch`; malformed `id_token_hint` → 400 `server_error` JSON (D7); **the `azp` claim selects
  the client and no signature is verified** (an explicit test naming the security debt, so deleting it is a
  deliberate act).
- **`CheckSessionHandlerTest`** — the four model keys with the right **types** (`valid_session` a `String`);
  GET and POST produce identical bytes; `text/html; charset=UTF-8`; a **non-ASCII** `client_uri` survives as
  UTF-8 (risk #21 — the templates are ASCII, so only the model can catch an ISO-8859-1 encode);
  `?display=touch` and `?display=bogus` → 400 JSON (D5); an `OAuth2Exception` from `getClientSessionURI` →
  JSON, not a page; **an id_token with no `aud` claim → 400 `server_error` JSON, not a 500** (D7 row 3 — the
  pre-existing NPE, pinned so the separate guard fix has a test to change deliberately).

**5b-2b**

- **`DeviceCodeVerificationHandlerTest`** — one case per branch of finding 7's flow diagram: unknown code →
  form + `errorCode=not_found` at 200; `isIssued()` → same; consent-implied → thanks page + `updateDeviceCode`
  with `authorized=true`; `decision=allow` → thanks page; `decision=deny` → `deleteDeviceCode` and **no**
  authorization; CSRF attack → 400 `bad_request` **HTML page**; no decision + consent required →
  `ResourceOwnerConsentRequired` → the consent page; `ResourceOwnerAuthenticationRequired` → **301** to the
  login URI verbatim; `save_consent=on` → `providerSettings.saveConsent` with the **validated** scope;
  GET without `user_code` → the bare form; GET **with** `user_code` → the same result as POST.
- **`DeviceCodeVerificationHandlerTest#seedsDeviceCodeAttributes`** — the D3 mapping: `clientID` → `client_id`,
  `scope` list joined with `" "`, every other key verbatim including `realm`, single-element lists unwrapped.
- **`ConsentPageRendererTest`** (extended) — the D2 case: attributes seeded device-code-style, **no query
  string**, and all seven keys (`realm`, `client_id`, `scope`, `state`, `nonce`, `response_type`, `ui_locales`)
  present in the model; plus the existing `/authorize` cases unchanged, proving neutrality.
- **`DeviceCodeRouteCompositionIT`** (new, failsafe) — modelled on `AuthorizeRouteCompositionIT`. Claims a unit
  test structurally cannot make: the **301** login redirect passes `OAuth2ErrorFilter` untouched; the consent
  **HTML** page is not rewritten into a JSON body; a non-ASCII consent model reaches the wire as UTF-8; `PUT`
  gives the framework 405 rewritten to `method_not_allowed` (D10); a **200 HTML** response from a `@Post`
  carrying a form body survives the audit-shaped buffered-body read.
  ⚠ **One row must use the *real* `OAuth2RequestFactory`** and a context chain containing `AttributesContext`
  (finding 14): seed device-code attributes in the handler, throw an `OAuth2Exception`, and assert the base
  mapper's error carries the **device code's** `state`. Every other test in this migration mocks the factory,
  which makes the cache untestable by construction — this is the only place the seeding design is checked at
  the seam where it can actually break.

**Golden coverage.** `RendererFixtures`/`RestletRendererParityTest` already pin `authorize.ftl` across all four
display folders. Add golden renders for `CodeVerificationForm.ftl`, `CodeThanks.ftl` and `page/checkSession.ftl`
— **while the Restlet leg is still on the classpath**, so they land as `Restlet == golden == CHF` three-way
assertions rather than unfalsifiable snapshots ([risk #20](plan.md), [chf-patterns §13](chf-patterns.md)).
These three templates have no golden today, which is exactly the build-ahead blind spot risk #19 describes.

---

## Verification criteria

**Per step (5b-2a, 5b-2b):**

1. `mvn -o -pl openam-oauth2 test` — new unit tests green; the existing suite unchanged and only larger. Baseline
   after 5b-1: **1132 surefire + 18 failsafe** ([plan.md](plan.md) 5b-1 row). State the new counts in the
   as-built.
2. `mvn -o -pl openam-oauth2 verify` — the composition ITs run (**`mvn test` skips `*IT`** —
   [test-infrastructure.md](../../test-infrastructure.md)).
3. `mvn -o -pl openam-oauth2 install -DskipTests` so the next step compiles.
4. **Grep gates** on the new files: `grep -rn "org.restlet\|getCurrent()" <new files>` → **0**. Parity *tests*
   may import Restlet until 5d-2.
5. Whole-reactor `mvn install -DskipTests` — **doclint is fatal**. (Never `-am` on `openam-server-only`/
   `openam-server`.)
6. **Blast-radius gate for D10.** `OAuth2ErrorFilter` is composed on already-committed routes, so after the
   one-line change the **whole** `http` suite plus `AuthorizeRouteCompositionIT` must be green, with exactly
   **one** intentional edit: that IT's D8 `PUT /authorize` row, from `invalid_request` to `method_not_allowed`.
   Any *other* test needing a change means the mapping moved further than intended.
   (There is no base-class gate: D7 was revised at review to touch no shared class — see D7.)

**5-E3 specifically:**

7. The new rows are **green against a live container built from this tree** *before* any of 5b-2's main code is
   written — that is the point of the gate. Record the captured bytes in this doc's As-built, not just the
   assertions.
8. Re-run + byte-diff after 5d-1. Only rows matching an [expected divergence](plan.md#expected-divergences-at-the-flip)
   may differ.

**Deferred to 5d-1** (this step wires no routes):

9. `OAuth2RouterIT` rows for the three paths, incl. `/oauth2/realms/root/connect/checkSession` reaching the
   handler while `/oauth2/connect/checkSession` reaches the JSP.
10. Cargo boot; whole `-am` build of the WAR modules; the e2e re-run.

---

## Integration testing

Layered per [test-infrastructure.md](../../test-infrastructure.md)'s cost model, and deliberately unbalanced
toward layers 2 and 4 because layer 1 cannot see composition and this is build-ahead code with no live guard
(risk #19).

1. **Layer 2 — `DeviceCodeRouteCompositionIT`** (new, in-process, failsafe). Composition is where this step's
   defects would hide: three response shapes (301, 200 HTML, 400 HTML) flowing through `OAuth2ErrorFilter`, and
   a POST whose form body is read by both the handler and — at 5d-1 — the audit filter. The rows are listed
   above. No new Maven dependency: model it on `AuthorizeRouteCompositionIT`, which composes
   `Endpoints.from` + the filter with plain `Handlers.chainOf` and no Guice.
   The two JSON handlers get their composition coverage from the existing `OAuth2ErrorRouteCompositionIT`
   pattern — add the D7 `RuntimeException` row there rather than authoring a third IT.
2. **Layer 4 — e2e**, in two passes. **5-E3 records** the live-Restlet contract (the gate above). After 5d-1 the
   *same* spec re-runs against CHF and must match byte-for-byte except for recorded divergences. Two cross-endpoint
   flows only become assertable at 5d-1 and belong in that step's matrix, not this one:
   - the **full device flow** end-to-end (`/device/code` → `/device/user` consent → `/access_token` poll with
     `grant_type=…device_code`), because `/device/code` is 5a-2 and `/device/user` is 5b-2 — neither is routed
     until the flip;
   - **check-session across the JSP/handler split**, asserting each URL is served by the expected page via the
     `sha256.js` discriminator (finding 5).
3. **Layer 3 — Cargo boot** at 5d-1 only: it proves the WAR starts with `OAuth2HttpRouteProvider` bound, which
   is the only automated check that a broken Guice binding for these handlers exists at all
   ([test-infrastructure.md](../../test-infrastructure.md) coverage gap). It asserts no OAuth2 behaviour.

**Do not** add a container IT for these endpoints. The device flow needs a real session, a real client and CTS;
that is what layer 4 already provides at a fraction of the cost.

---

## Risk register (extends [phase-5-oauth2.md](phase-5-oauth2.md)'s)

| # | Risk | Guard |
|---|---|---|
| **R-5b2.1** | **Wrong base class** — a JSON endpoint on the browser base turns every error into an HTML page (finding 1). Invisible to a unit test written against the wrong base, because it would simply assert the page | D1; `EndSessionHandlerTest`/`CheckSessionHandlerTest` assert `application/json` on **every** error row; 5-E3 rows pin the live shape first |
| **R-5b2.2** | **The device consent page silently loses its model** (finding 2). Every `<#if x??>` goes false and XUI renders a consent screen with no client, no scopes and no realm — a 200 that looks fine to a status assertion | D2 + the new `ConsentPageRendererTest` device case + 5-E3 row 4 capturing the live `oauth2Data` keys |
| **R-5b2.3** | **The request cache is invisible to unit tests** (finding 14). Every existing suite mocks `OAuth2RequestFactory`, so a device-flow error that silently loses the device code's `state` would pass all of them | The named real-factory row of `DeviceCodeRouteCompositionIT`; nothing else can see it |
| **R-5b2.9** | **D10 touches a committed filter on a live-bound path.** `OAuth2ErrorFilter` is already composed on the 5a/5b-1 routes, so a wrong `case` changes bodies beyond this step | `OAuth2ErrorFilterTest` covers 400/401/403/404/405/503; `AuthorizeRouteCompositionIT`'s D8 row is updated in the same commit and would fail if the mapping moved further than intended |
| **R-5b2.4** | **The oracle expires at 5d-1** (risk #20) for all three endpoints — nothing is recorded today beyond six smoke rows | 5-E3, and it lands **before** any 5b-2 main code |
| **R-5b2.5** | **`?display=` on check-session** — a plausible-looking `page/` fallback would be a *widening* of a live 400 into a 200 | D5 is explicitly gated on 5-E3 row 7; do not implement before it is recorded |
| **R-5b2.6** | **Device-code realm override** (finding 3): dropping the `realm` attribute write resolves the client in the URL's realm instead of the code's, breaking cross-realm device flows | `seedsDeviceCodeAttributes` asserts `realm` is written; 5-E3 could add a sub-realm row if the fixture allows |
| **R-5b2.7** | **`no-store` creep** — adding `OAuth2NoCacheFilter` or a `noCache` call to any of these three would emit headers Restlet never sent (finding 8) | 5-E3 row 5 records their absence; the 5d-1 byte-diff catches it |
| **R-5b2.8** | **Unverified `id_token_hint` signature** reproduced (finding 10). Correct for this migration, wrong forever | Named in `EndSessionHandlerTest`; already on the [security-debt list](phase-5-oauth2.md#parity-preserved-security-debts--reproduce-now-fix-later) |

---

## CHF / framework issues

**None forced by this step** — verified, not assumed (finding 11): `AnnotatedMethod` already resolves the
**most specific** `@ExceptionHandler` along the thrown type's superclass chain and already scans inherited
methods, which is exactly what D7 needs. The F1–F4 work ([openam-http-framework.md](openam-http-framework.md))
covers the rest.

Standing in-tree items, unchanged and unrelated to 5b-2 — listed so the next step does not rediscover them:

- **commons `Form.fromRequestEntity`** exact-matches the whole `Content-Type` header, so `;charset=UTF-8`
  silently yields an empty form (risk #18). Locked decision: route around in the handlers, land the commons fix
  independently. None of these three parses a form body, so 5b-2 is unaffected.
- **`AMAccessAuditEventBuilder.forRequest` port `-1`** (openam-audit-core). Surfaces at 5d-1's audit diff.

If wiring these three does surface a new `Endpoints.from`/`AnnotatedMethod` sharp edge, fix it **in openam-http
with its own tests, in its own commit** — never inside a 5x migration commit (the F1–F4 precedent).

---

## Execution checklist

**5-E3 — record first**

1. Build and boot a container from this tree (Restlet still serving `/oauth2`).
2. Add the ~14 rows of finding 6 to the two existing e2e specs, **written from observed output**, not from this
   doc's expectations.
3. Run `e2e/oauth2` green. Paste the captured statuses/headers/bodies into this doc's As-built.
4. Resolve **D5**, **D7** and **D8** against what was recorded; amend the decisions if the observations
   disagree, and say so explicitly rather than silently.

**5b-2a — the JSON pair**

5. **D10 first**, on its own: the `case 405` line, the `OAuth2ErrorFilterTest` cases, and the one-row update to
   `AuthorizeRouteCompositionIT`. Land it as a separable change so gate 6's blast radius is legible in the
   history; if the 5-E3 rows later argue against it, reverting is one line.
6. `EndSessionHandler` + test (incl. the D7 JWT wrap).
7. `CheckSessionHandler` + test (incl. both D7 wraps) + the `page/checkSession.ftl` golden (three-way, while
   Restlet is on the classpath).
8. Update the two deferred-question pointers to D5: `FreemarkerTemplateRenderer`'s `renderForDisplay` javadoc
   **and [decisions.md](decisions.md) D5**.
9. File the `CheckSession.getClientSessionURI` null-guard fix as a separate ticket (D7, row 3) so it is not lost
   when the Restlet oracle goes.
10. `test` → `verify` → grep gates → `install` → whole-reactor `install -DskipTests`.

**5b-2b — the device flow**

11. `ConsentPageRenderer` D2 correction + the extended `ConsentPageRendererTest` **first**, so the renderer is
    correct before anything depends on it.
12. `DeviceCodeVerificationHandler` + `DeviceCodeVerificationHandlerTest` (one case per branch of finding 7).
13. `CodeVerificationForm.ftl`/`CodeThanks.ftl` goldens (three-way).
14. `DeviceCodeRouteCompositionIT`, **including the real-factory row** (finding 14 / R-5b2.3).
15. `test` → `verify` → grep gates → `install` → whole-reactor `install -DskipTests`.
16. Write the As-built section; update [plan.md](plan.md)'s 5b-2 row and the
    [expected-divergences table](plan.md#expected-divergences-at-the-flip). Expected edits there: **narrow
    row 3** (D10 makes the `error` field match; only `error_description` still differs) and add any
    `RedirectUris`-vs-`Reference` normalisation difference D8 turns up.

**Not in this step:** route registration, `web.xml`, Guice unbinding of the Restlet resources, deletion of
`ConsentRequiredResource`/`OAuth2Representation`/`ExceptionHandler`. All of that is 5d-1/5d-2.

---

## Open questions for 5-E3 to close

1. **Row 7 (D5).** Do `?display=popup|touch|bogus` on `/oauth2/realms/root/connect/checkSession` really all
   answer 400 JSON today? The reasoning is solid but it is reasoning — and 5-E predicted `GET /access_token`
   wrong.
2. **Row 8 (D8).** Does `new Reference(uri).toString()` normalise a `post_logout_redirect_uri` that already
   carries a query or fragment, where `RedirectUris.compose` emits it verbatim?
3. **Row 10 (D7).** Is a malformed `id_token_hint` really 400 `server_error` JSON, or does
   `JwtReconstruction` fail in a way that produces something else?
4. **Row 3.** Is a device-flow CSRF failure really the **HTML** error page (the 4-arg `doCatch`), or does
   something upstream produce JSON?
5. **Row 1.** What status and headers accompany the `errorCode=not_found` form? A 200 is expected — an error
   code rendered inside a success page — but it is worth pinning, since it is the one place this provider
   reports a failure with a 200.
6. **Row 11 (D10).** What does a wrong verb produce on each of the three *today*? `OAuth2Filter` does not wrap
   them, so these are Restlet's own 405s rendered by `JSONRestStatusService` — a **CREST** body, not an OAuth2
   one. If any of them already answers `method_not_allowed`, D10 gets strictly better; if they answer something
   else entirely, record it and leave D10 justified by `/authorize` + `/access_token` alone.

---

<a id="as-built-5-e3--recorded-2026-07-28"></a>
## As-built — 5-E3, recorded 2026-07-28 (test-only)

Captured against a live container built from this tree: `openam-e2e:5e3` (the repo
`openam-distribution/openam-distribution-docker/Dockerfile` with its three `#COPY` lines uncommented, exactly
CI's `build-docker` sed) over `openam-server/target/OpenAM-16.2.0-SNAPSHOT.war`, plus
`openidentityplatform/opendj:latest` on the `test-openam` network, configured with CI's `conf.file`. Restlet
still serves `/oauth2`: every realm-prefixed row carries `Server: Restlet-Framework/2.4.4`, and `/oauth2/*` is
still mapped to `ForgeRockRest` in `web.xml` with no CHF `HttpRouteProvider` claiming those paths.

**Deliverables — e2e only, zero main-source lines:**

| File | Change |
|---|---|
| `e2e/common/oauth2-fixtures.mjs` | `POST_LOGOUT_REDIRECT_URI`, `POST_LOGOUT_REDIRECT_URI_WITH_QUERY`, `CLIENT_SESSION_URI`; `ensureOidcClient` additionally registers both post-logout URIs and a `clientSessionURI`; new `ensureDeviceConsentClient` and `deviceCodeForConsent` |
| `e2e/oauth2/oidc-test.spec.mjs` | new describe `OIDC session endpoints contract lock (5-E3, live Restlet)` — **9 rows** |
| `e2e/oauth2/oauth2-endpoints-test.spec.mjs` | new describe `OAuth2 device flow contract lock (5-E3, live Restlet)` — **5 rows** |

`npx playwright test oauth2` — **62 passed** (48 before), twice in a row. No existing row edited.

### The recorded rows

| # | Request | Recorded |
|---|---|---|
| 1 | `/device/user?user_code=<unknown>` | **200** `text/html;charset=UTF-8`, the code-entry form with `errorCode: "not_found"`. **Identical anonymously** — the code lookup fails before any session check, so an unknown code never reaches the 301-to-login a valid code triggers |
| 2 | `/device/user` POST `decision=allow` / `decision=deny` | **both 200**, both the **thanks** page (`done: true`). The branch only chooses update-vs-delete and then falls through to the same render; the difference is invisible on the wire |
| 3 | `/device/user` POST, `csrf` missing or wrong | **400** `text/html;charset=UTF-8`, `<title>OAuth2 Error Page</title>`, `message: "bad_request"`, **no `Location`** |
| 4 | `/device/user` consent page | **200**; model keys `clientId`, `scope` (`"openid profile"`), `state`, `nonce`, `responseType`, `locale`, `realm`, plus `userCode`/`userName`/`displayName`/`isSaveConsentEnabled`/`displayScopes`/`formTarget` |
| 5 | cache headers, all three endpoints, success **and** error | **none** — no `Cache-Control`, no `Pragma`, anywhere. [Finding 8](#8--none-of-the-three-gets-cache-headers) confirmed |
| 6 | `/oauth2/connect/checkSession` vs `/oauth2/realms/root/connect/checkSession` | bare path = **JSP** (`<script src="../../js/sha256.js">`, **no** `Server` header); realm-prefixed = **Restlet FTL** (absolute `<base>/js/sha256.js`, `Server: Restlet-Framework/2.4.4`). Both **200** `text/html;charset=UTF-8` |
| 6b | checkSession `GET` vs `POST` | byte-identical |
| 6c | checkSession with a valid `id_token` in the **`Referer`** query | **200**, page carries `var clientURI = "<clientSessionURI>";` |
| 6d | checkSession, `Referer` `id_token` with **no `aud`** / **unknown `aud`** / **malformed** | all **400** `application/json` `{"error":"server_error","error_description":"Internal Server Error (500) - …"}` |
| 7 | checkSession `?display=` | `page` → **200**; `popup`, `touch`, `wap` → **400** `server_error` `"Bad Request (400) - Server can not serve the content of authorization page"`; `bogus` → **400** `server_error` with the generic `"Internal Server Error (500) - …"` |
| 8 | endSession + registered `post_logout_redirect_uri` | no `state` → **302** to the URI **verbatim** (no trailing `?`); with `state` → `?state=st%20ate%2F1` (space `%20`, `/` `%2F`); URI that already has a query → existing query **preserved verbatim**, state **appended with `&`** |
| 9 | endSession, unregistered / relative `post_logout_redirect_uri` | **400 JSON** `redirect_uri_mismatch` / `relative_redirect_uri`, with the exact descriptions, no `Location` |
| 10 | endSession, malformed `id_token_hint` (and an unparseable redirect URI) | **400 JSON** `server_error`, generic description |
| 11 | `PUT` on all three | **405** `application/json`, **CREST** body `{"code":405,"reason":"Method Not Allowed","message":"The method specified in the request is not allowed for the resource identified by the request URI"}` — **no `error` field at all** |

### What the observation settled

1. **[D5](#d5) confirmed — and the reasoning that nearly overturned it was wrong.** While writing the probe I
   read `OAuth2Representation.getRepresentation` and concluded `?display=popup` would be a **200**, because
   popup is special-cased and `templates/popup/authorize.ftl` *does* exist. Live Restlet answers **400**. The
   mechanism is a third one neither the plan nor that reading had: the popup branch renders
   `popup/authorize.ftl` **against the check-session model**, which has no `display_name`, so FreeMarker throws
   `InvalidReferenceException`, `popup.getText()` fails, and the `IOException` becomes the *same*
   `ResourceException` a missing template produces. Three mechanisms — missing template (`touch`/`wap`), failed
   render (`popup`), `Enum.valueOf` (`bogus`) — two distinct bodies, one status. **D5 stands as written.**
2. **[D7](#d7) confirmed, and it needs a fourth wrap.** Rows 6d and 10 pin **400 `server_error`** on every
   client-reachable unchecked throw. But row 6c only passes because the fixture now sets `clientSessionURI`:
   `OpenAMClientRegistration.getClientSessionURI()` ends in `set.iterator().next()` with no emptiness guard
   (`:426-434`), and the admin API leaves that attribute **empty by default** — so for a default-configured
   client, a valid `id_token` in the `Referer` throws `NoSuchElementException` and check-session 400s on its
   own happy path. ⇒ **add a fourth row to D7's table**: `getClientSessionURI` must be wrapped too, and the
   separate null-guard ticket (checklist step 9) should cover the empty-set case, not just the NPE.
3. **[D8](#d8) resolved — and the open question answered "no normalisation".** `new Reference(uri)` does **not**
   rewrite a URI that already carries a query: `http://app.invalid/logout?ui=1` + `state=s2` comes out as
   `…?ui=1&state=s2`, existing pair untouched, `state` appended. With no `state` the URI is emitted byte-for-byte
   with no trailing `?`. The encoding is `%20` for space and `%2F` for `/` — **not** `+`. `RedirectUris.compose`
   has to match all three shapes; the space encoding is the one most likely to drift.
4. **[D10](#d10)'s justification narrowed — see the correction box in D10.** Row 11 shows all three endpoints
   emit a **CREST** 405 body, not `method_not_allowed`. D10 rests on `/authorize` + `/access_token` alone.
5. **Open question 4 answered.** A device CSRF failure really is the **HTML error page** (the 4-arg `doCatch`),
   confirming [D1](#d1)'s split: browser base for the device handler, JSON base for the other two.
6. **Open question 5 answered.** The `errorCode=not_found` form is a **200**, and — not anticipated — it is a
   200 **anonymously** as well.

### Three environment facts the rows had to be written around

Worth knowing before writing any further device-flow or check-session e2e; all three cost a probe cycle here.

1. **check-session takes its `id_token` from the `Referer` header's query string**, not from a request
   parameter (`CheckSession.getIDToken:191-218`). Without a `Referer` the model's `client_uri` is `""` and the
   endpoint's whole purpose is untested — which is exactly the state the pre-5-E3 smoke row was in.
2. **The consent-requiring device flow cannot use `response_type=device_code`.** `/device/code` stores the
   value **verbatim** and `/device/user` replays it through `authorizationService.authorize`, which validates
   against `providerSettings.getAllowedResponseTypes()` — and there is no `device_code` **response-type**
   handler (only `code`/`token`/`id_token`/`none`; `device_code` is a *grant* type). So the conventional call
   yields `unsupported_response_type`. Because this provider also pins `codeVerifierEnforced:true`, the working
   combination is `response_type=code` **plus** `code_challenge`/`code_challenge_method`, which `/device/code`
   accepts and stores (`DeviceCodeResource:119-120`). A consent-*implied* client sidesteps both, which is why
   the pre-existing device rows never hit this. Captured as `deviceCodeForConsent()`.
3. **`test_client_consent` cannot serve these rows** — it has no `device_code` grant and is a file-local const
   in `oauth2-test.spec.mjs`, not an export. The plan's "reuse it" instruction is superseded by
   `ensureDeviceConsentClient`.

### Two pre-existing quirks the CHF port must reproduce

- **`CodeThanks.ftl` renders `realm : "${realm?js_string}/XUI"`** — the realm arrives with `/XUI` appended
  (`realm : "\//XUI"` on the wire). Pinned by row 2 so the golden keeps it.
- **The JSP and the FTL check-session pages differ behaviourally, not just cosmetically.** The JSP emits
  `var validSession = "false"` — a **quoted string**, so `!validSession` is always false and `getBrowserState()`
  reads the cookie even for an invalid session. The FTL's `?js_string` escapes without adding quotes, so it
  emits a bare boolean literal and the guard works. The CHF handler inherits the **FTL**, i.e. the correct
  behaviour; the bare path keeps the JSP. Row 6 records both so the 5d-1 diff on the bare path is not misread
  as a regression.

⇒ **5-E3 done. [R-5b2.4](#risk-register-extends-phase-5-oauth2mds)'s unrecoverable-oracle risk is retired for
all three endpoints.** Next: **5b-2a**, starting with D10 on its own (checklist step 5).
