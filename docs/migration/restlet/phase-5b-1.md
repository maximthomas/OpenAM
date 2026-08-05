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
| **5-E2** ✅ | **The `/authorize` live-Restlet contract lock** — a consent-capable e2e client ([finding 12](phase-5b-1-research.md#12--the-e2e-environment-cannot-currently-reach-a-consent-page)) plus 9 authorize rows in `e2e/oauth2/oauth2-test.spec.mjs`, written **by observation**. Test-only, no main code. Extends step **5-E**, whose recorded rows so far cover only `/access_token` + cache headers ([finding 1](phase-5b-1-research.md#1--the-e-lock-does-not-yet-cover-authorize--and-cannot-be-written-after-5d-1)) | e2e spec only (0 main) | **High** — unrecoverable after 5d-1 |
| **5b-1a** | **The browser substrate**: extract `AbstractOAuth2HttpEndpoint` (shared fields + `noCache`/`withErrorHeaders`), add `AbstractOAuth2HttpBrowserEndpoint` (the browser `@ExceptionHandler`), `ChfAuthorizeRequestHook` + `LoginHintHook` dual-impl + Guice Multibinder, and the neutral **`getAcceptedLanguages()`** accessor the consent model needs ([finding 5](phase-5b-1-research.md#5--getacceptedlanguages-does-not-exist--the-consent-models-locale-key-has-no-neutral-source)) | 3 new + 3 modified + 3 tests + 1 IT | **Med** |
| **5b-1b** | **`AuthorizeHandler`** + the shared **`ConsentPageRenderer`** (data model + `authorize.ftl` render, reused by 5b-2's device flow — [finding 6](phase-5b-1-research.md#6--consentrequiredresource-is-shared-with-the-device-flow--on-chf-it-must-become-a-collaborator-not-a-base)) | 2 new + 2 tests | **High** |

**Total new main classes: 5** (`AbstractOAuth2HttpEndpoint`, `AbstractOAuth2HttpBrowserEndpoint`,
`ChfAuthorizeRequestHook`, `ConsentPageRenderer`, `AuthorizeHandler`) + one new accessor on two classes.

Order: **5-E2 → 5b-1a → 5b-1b**. 5-E2 is deliberately first, not merely "before 5d-1": the handler's
method/content-type behaviour and its 405/400 wire bodies are **decided by** what the oracle records
([finding 2](phase-5b-1-research.md#2--the-continue-bug-makes-authorizes-filter-validation-unpredictable--record-it-do-not-derive-it)),
and characterizing before porting is the lesson [3b as-built #2](phase-3b-collaborators.md) and
[3c-1 execution step 3](phase-3c-1-renderer.md) both recorded.

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
([as-built](phase-5b-1-asbuilt.md#as-built-5-e2--recorded-2026-07-26)). Restlet's `afterAuthorizeSuccess` retracts the `CookieSetting`
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
| 7 — `PUT /oauth2/authorize` | **405** `application/json` `{"error_description":"Required Method: GET or POST found: PUT","error":"method_not_allowed"}` + `no-store`/`no-cache` | **No verb check.** The `@Get`/`@Post`-only handler's framework 405 matches on status; the body code becomes `invalid_request` via `OAuth2ErrorFilter` — a 5d-1 body divergence, not a status one. ⚠ **Superseded 2026-07-28 by [D10](phase-5b-2.md#d10)**: the filter now emits `method_not_allowed`, so the `error` field matches too and only `error_description` diverges |
| 8 — `POST` with `Content-Type: application/json` | **400** `application/json` `{"error_description":"Invalid Content Type","error":"invalid_request"}` + `no-store`/`no-cache` | **Reproduce the content-type check** with the 5a-1 recipe (empty-body early-return, case-insensitive `FORM_URLENCODED` compare) and **return** — never fall through |

The decision tree that produced those answers, kept for the record:

- **Verb.** A handler with only `@Get` and `@Post` returns the framework **405** for PUT/DELETE with no verb
  check ([chf-patterns §2](chf-patterns.md#2-endpointsfrom--semantics-that-matter)), and the CREST 405 body is
  rewritten by `OAuth2ErrorFilter` to `invalid_request` at 5d-1 — the same `method_not_allowed` →
  `invalid_request` body-code divergence 5-E already locked for `GET /access_token`. **No verb check in the
  handler**, whatever the oracle says about the status.
  (⚠ The rewrite target changed to **`method_not_allowed`** on 2026-07-28 — [D10](phase-5b-2.md#d10). The "no
  verb check" conclusion is unaffected: it was never contingent on the body code.)
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

