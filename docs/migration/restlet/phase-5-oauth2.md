# Phase 5 — OAuth2/OIDC `/oauth2` → CHF: Research, Sizing & Sub-phase Plan

Umbrella plan for **Phase 5** of the Restlet → CHF migration — the largest area (`/oauth2`, all
OAuth2/OIDC protocol endpoints). Parent tracker: [plan.md](plan.md); inventory:
[inventory.md](inventory.md); decisions: [decisions.md](decisions.md); reusable CHF patterns:
[chf-patterns.md](chf-patterns.md); the pattern this phase copies wholesale:
[phase-4-uma.md](phase-4-uma.md) (atomic-flip mechanics, route provider, protection filter) +
[phase-2-integration-tests.md](phase-2-integration-tests.md) (layer-2 IT); the build-ahead infra it
**consumes**: [phase-3a-oauth2request.md](phase-3a-oauth2request.md) (`ChfOAuth2Request`),
[phase-3b-collaborators.md](phase-3b-collaborators.md) (neutral verifiers/reader),
[phase-3c-1-renderer.md](phase-3c-1-renderer.md) (`FreemarkerTemplateRenderer`),
[phase-3c-2-error-layer.md](phase-3c-2-error-layer.md) (`OAuth2Error`/`RedirectUris`/factory/filter),
[phase-3d-audit.md](phase-3d-audit.md) (CHF audit filters + `HttpBodyAuditor`); test layers:
[../../test-infrastructure.md](../../test-infrastructure.md). Written 2026-07-24; branch
`features/restlet-migration`. All facts below verified against the tree on 2026-07-24.

> **This doc is the shared substrate for sub-phases 5a–5d** (like [phase-3-research.md](phase-3-research.md)
> was for 3a–3d). It maps the whole `/oauth2` surface, confirms the consumed build-ahead inventory, sizes and
> splits the sub-phases, and records the cross-cutting decisions. Each sub-phase gets its own detailed
> execution doc (`phase-5a-*.md` … `phase-5d-*.md`) **when it is scheduled**, authored from this substrate —
> exactly the 3a–3d rhythm. The per-endpoint conversion tables here are detailed enough to start 5a
> immediately.

## Context

Phase 5 moves `/oauth2/*` — the entire OAuth2/OIDC protocol surface — off Restlet onto CHF. Everything hard
about the migration lives here: HTML consent pages, `redirect_uri` composition (fragment vs query), form-post,
301/302 semantics, `WWW-Authenticate`, grant-type dispatch, resource_set's trailing-slash routes, and the
richest audit matrix. XACML (Phase 2), the OAuth2 core re-plumb (Phase 3), and UMA (Phase 4) existed to make
this phase incremental rather than a big-bang rewrite.

**The whole of Phase 3c/3d/4a was build-ahead *for this phase*.** `ChfOAuth2Request`, the neutral verifiers,
`FreemarkerTemplateRenderer`, `OAuth2Error`/`RedirectUris`/`OAuth2ErrorResponseFactory`/`OAuth2ErrorFilter`,
`OAuth2HttpAccessAuditFilter`/`HttpBodyAuditor`, and `ChfAccessTokenProtectionFilter` all already exist, wired
to no route. Phase 5 is where they get wired and the flip happens. **This is the moment their contracts become
observable** ([plan.md](plan.md) risk #19) — so Phase 5's guard is not "keep the Restlet suite green" (the
Restlet suite is being *deleted*) but the golden oracle, composition ITs, and the e2e contract lock.

### Shape: build-ahead handler steps, then a two-commit flip

Unlike UMA (a single atomic flip — three JSON endpoints, no HTML), `/oauth2` is too large to flip in one
commit. It follows the 3c/5 model plan.md already set: **5a/5b/5c ship the CHF handlers as build-ahead
classes wired to no route** (Restlet still serves `/oauth2`), then **the flip is two commits**: **5d-1** wires
`OAuth2HttpRouteProvider`, moves one `<servlet-mapping>`, and re-signs the hooks — while **leaving the Restlet
stack in place, unrouted** (one-line revert) — and **5d-2** deletes the dormant Restlet stack once 5d-1 soaks
green (finding #3). Because 5a/5b/5c are additive, their boundaries are chosen for **reviewability, not
shippability** (every one is green-but-dormant until 5d-1).

## The consumed build-ahead inventory — confirmed present (2026-07-24)

Every class Phase 5 wires already exists with the API below (verified this session). **Phase 5 authors almost
no new response/error/audit/render infrastructure** — it ports endpoint *business shells* onto these.

| Class (pkg `org.openidentityplatform.openam.oauth2.*`) | Key API Phase 5 calls | Consumed by |
|---|---|---|
| `core.ChfOAuth2Request` | ctor `(Context, Request)`; seeds `realm` **and** `realmObject` (`:324-329`); `getBody():JsonValue`, `getParameter`, `getAuthorizationBearerToken`, `getBasicAuthCredentials`, `getHttpServletRequest/Response`, `setQueryParameter`/`removeQueryParameterValue`, `getEndpointPath` | all handlers |
| `oauth2.core.OAuth2RequestFactory` (still `org.forgerock.oauth2.core`) | `create(Context, Request)` — caches one `ChfOAuth2Request` on `AttributesContext` key `OAUTH2_REQ_ATTR` | all handlers + filters |
| `http.OAuth2Error` | `of(OAuth2Exception)`, `of(int,String,String)`, `mayRedirect(e)`, `withState`, `withChallenge`, `redirectingTo`, `asMap` | 5a/5b `@ExceptionHandler` |
| `http.OAuth2ErrorResponseFactory` (`@Inject` renderer + `BaseURLProviderFactory` + `RealmNormaliser`) | **public**: `toResponse(OAuth2Request, OAuth2Error)` (browser), `toJsonResponse(OAuth2Error)` (API). Redirect/HTML methods are package-private — **5a/5b go through these two** | 5a/5b `@ExceptionHandler` |
| `http.OAuth2ErrorFilter` (`implements org.forgerock.http.Filter`, no-arg) | rewrites `≥400` CREST `{code,…}` bodies → OAuth2 `{error,…}`; keyed on **wire status**; leaves HTML + already-`error` bodies alone | 5d route wrap |
| `http.RedirectUris` | `compose(redirectUri, Map, UrlLocation)` — fragment replaces / query appends | 5b success 302 |
| `http.FreemarkerTemplateRenderer` (`@Singleton`, no-arg) | `render(path, model)`, `renderForDisplay(display, name, model)`, static `toHtmlResponse(Status, html)` | 5b pages |
| `audit.OAuth2HttpAccessAuditFilter` | ctor `(AuditEventPublisher, AuditEventFactory, OAuth2RequestFactory, HttpBodyAuditor req, HttpBodyAuditor resp)` — `super(Component.OAUTH, …)` | 5d per-route audit wrap |
| `audit.HttpBodyAuditor` | static `jsonAuditor(fields…)`, `formAuditor(fields…)`, `noBodyAuditor()` (== `null`) | 5d audit matrix |
| `http.ChfAccessTokenProtectionFilter` (`implements Filter`) | ctor `(String requiredScope, TokenStore, OAuth2RequestFactory)`; **`null` scope** = validity-only (this is what resource_set needs) | 5c resource_set |

**Not yet built (Phase 5's actual new classes):** the ~14 endpoint *handlers*, the token-endpoint grant
dispatcher, a CHF `ResourceSetRegistrationExceptionFilter`, the CHF hook seam (below), and
`OAuth2HttpRouteProvider`.

## ⚠ Prerequisite gate — the e2e contract lock (§E) must be recorded **before** 5d-1

[phase-3c-2 §E](phase-3c-2-error-layer.md#e-e2e-error-contract-lock) is **deferred, not cancelled**
([its as-built](phase-3c-2-error-layer.md#as-built) "Still open"). It is a live-oracle executable spec of the
`/oauth2` error contract recorded **against the running Restlet server**. **Restlet stops serving `/oauth2`
at 5d-1** (the mapping moves), so the live capture must land **before 5d-1** — even though the Restlet
*classes* survive until 5d-2 ([plan.md](plan.md) risk #20). It must be written and green against unmodified
Restlet **before the 5d-1 flip**, then re-run after. Concretely, Phase 5 must, before 5d-1:

1. Extend `e2e/oauth2/oauth2-test.spec.mjs` with the §E rows (JSON error shape + `WWW-Authenticate: Basic` on
   `/access_token`; **301 to the login page** on unauthenticated `/authorize`, asserting the `Location`
   *value*; 302 query-vs-fragment error composition; `text/html;charset=UTF-8` on the error page reached via
   unknown `client_id`). **Write by observation, not prediction** — run it against a live container built from
   this tree first and record what it actually returns.
2. Also record the **golden HTML** state: the 3c-1 `RestletRendererParityTest` (`Restlet == golden == CHF`)
   and 3c-2 `RestletErrorParityTest` still live now; they call the Restlet classes directly, so they survive
   until **5d-2** (deletion), not the flip. Confirm they are green immediately before 5d-1 so the goldens are
   proven-legacy at deletion time.

This is the single hardest scheduling constraint in Phase 5: **the live-oracle capture is gated to happen while
Restlet still *serves* `/oauth2`**, i.e. any time in 5a–5c, but it *cannot* be written after 5d-1.

## Surface map — the `/oauth2` route table (15 endpoints, 3 groups)

From `OAuth2RouterProvider.get()` (`openam-oauth2/.../openam/oauth2/rest/OAuth2RouterProvider.java:94-149`).
**Count precisely for 5d wiring:** the provider issues **18 `router.attach()` calls** — 1 realm route + 17
endpoint attachments, where `/resource_set` is attached at **3 paths** (bare, trailing-slash, `{rsid}`) to one
shared restlet. So it is **15 logical endpoints** (10 Group A + 4 Group B + 1 Group C), not 16, and the CHF
provider must register the 3 resource_set routes separately (§5c). Every route is wrapped by
`OAuth2AccessAuditFilter` (→ becomes `OAuth2HttpAccessAuditFilter`). The realm router is
`new RestletRealmRouter()` + `/realms/{realmId}` recursion via `RealmRoutingFactory` — replaced by the same
`RealmRoutingFactory().createRouter(root)` shape [phase-4](phase-4-uma.md) uses.

> **Audit-matrix provenance (finding #4).** The per-route req/resp auditor pairs in the tables below are the
> **wire contract** and must be lifted **verbatim** from the current audit wiring, not re-derived. The routes in
> `OAuth2RouterProvider.get()` are plain `router.attach()` calls with **no** auditors declared inline; the
> field lists come from the current `OAuth2AccessAuditFilter`/`RestletBodyAuditor` construction (per
> [phase-3d-audit.md](phase-3d-audit.md)). When 5d authors the matrix, copy each field list from that source and
> cite the `file:line`, so a re-derivation error can't silently drop an audited field.

Split into the three sub-phase groups, with the **CHF handler** each Restlet resource becomes and the
**per-route body-auditor pair** (the 5d wiring matrix; `RestletBodyAuditor.jsonAuditor`+`jacksonAuditor` both
collapse to CHF `jsonAuditor`, `formAuditor`→`formAuditor`, `noBodyAuditor()`→`null`, per
[chf-patterns §15](chf-patterns.md)):

### Group A — JSON endpoints (5a)

| Route | Restlet resource (file) | Verb(s) | → CHF handler | req auditor | resp auditor |
|---|---|---|---|---|---|
| `/access_token` | `TokenEndpointFilter`→`AccessTokenFlowFinder`→`TokenEndpointResource`/`RefreshTokenResource`/`ErrorResource` | POST | `TokenEndpointHandler` (**5a-1**) | `formAuditor(RESPONSE_TYPE,GRANT_TYPE,CLIENT_ID,USERNAME,SCOPE,REDIRECT_URI)` | `jsonAuditor(SCOPE,TOKEN_TYPE)` |
| `/tokeninfo` | `ValidationServerResource` (99 L) | GET | `TokenInfoHandler` | `noBodyAuditor()` | `jsonAuditor(SCOPE,TOKEN_TYPE)` |
| `/introspect` | `TokenIntrospectionResource` (84 L) | GET+POST(form) | `TokenIntrospectionHandler` | `formAuditor(TOKEN_TYPE_HINT)` | `jsonAuditor(SCOPE,TOKEN_TYPE,CLIENT_ID,USERNAME,ACTIVE)` |
| `/token/revoke` | `TokenRevocationResource` (241 L) | POST | `TokenRevocationHandler` | `noBodyAuditor()` | `noBodyAuditor()` |
| `/userinfo` | `UserInfo` (93 L) | GET+POST(form:json) | `UserInfoHandler` | `noBodyAuditor()` | `noBodyAuditor()` |
| `/idtokeninfo` | `IdTokenInfo` (349 L, inner `ValidateIdTokenRequest`) | POST | `IdTokenInfoHandler` | `noBodyAuditor()` | `noBodyAuditor()` |
| `/connect/register` | `ConnectClientRegistration` (135 L) | GET+POST | `ConnectClientRegistrationHandler` | `jsonAuditor(CLIENT_NAME,APPLICATION_TYPE,REDIRECT_URIS)` | `jsonAuditor(CLIENT_ID,CLIENT_NAME,APPLICATION_TYPE,REDIRECT_URIS)` |
| `/.well-known/openid-configuration` | `OpenIDConnectConfiguration` (88 L) | GET | `OpenIDConnectConfigurationHandler` | `noBodyAuditor()` | `noBodyAuditor()` |
| `/connect/jwk_uri` | `OpenIDConnectJWKEndpoint` (87 L) | GET | `JwkUriHandler` | `noBodyAuditor()` | `noBodyAuditor()` |
| `/device/code` | `DeviceCodeResource` (152 L) | POST | `DeviceCodeHandler` | `formAuditor(RESPONSE_TYPE,GRANT_TYPE,CLIENT_ID,SCOPE)` | `noBodyAuditor()` |

### Group B — HTML/redirect flow (5b)

| Route | Restlet resource (file) | Verb(s) | → CHF handler | auditors |
|---|---|---|---|---|
| `/authorize` | `AuthorizeEndpointFilter`→`AuthorizeResource` (218 L) + `ConsentRequiredResource` (172 L) + `OAuth2Representation` (219 L) | GET+POST | `AuthorizeHandler` | `noBodyAuditor()`/`noBodyAuditor()` |
| `/device/user` | `DeviceCodeVerificationResource` (302 L) | GET+POST | `DeviceCodeVerificationHandler` | `noBodyAuditor()`/`noBodyAuditor()` |
| `/connect/checkSession` | `OpenIDConnectCheckSessionEndpoint` (129 L) — **but see the JSP gotcha below** | GET+POST | `CheckSessionHandler` | `noBodyAuditor()`/`noBodyAuditor()` |
| `/connect/endSession` | `EndSession` (156 L) | GET | `EndSessionHandler` | `noBodyAuditor()`/`noBodyAuditor()` |

### Group C — resource_set (5c)

| Route (3 attachments, one shared filter) | Restlet | Verbs | → CHF handler | auditors |
|---|---|---|---|---|
| `/resource_set`, `/resource_set/`, `/resource_set/{rsid}` | `ResourceSetRegistrationExceptionFilter`→`AccessTokenProtectionFilter(null)`→`ResourceSetRegistrationEndpoint` (367 L) | POST/GET/PUT/DELETE | `ResourceSetRegistrationHandler` + CHF exception filter | `jsonAuditor(NAME,SCOPES)` / `jsonAuditor("_id")` |

## Scope & sizing — the iterative step sequence

Phase 5 is **~7 shippable build commits plus a dedicated §E gate commit** (step **5-E** below — a test-only
recording of the live contract), implemented one after another. plan.md's 5a/5b/5c/5d is the skeleton, but
three of those four are too big or too coupled for one clean commit, so each is split on the **same
risk-isolation principle** (findings #1, #3): a commit should be reviewable on its own and revertible without
dragging unrelated work with it.

| Step | Sub-phase | Scope | New classes (approx) | Risk | Guard |
|---|---|---|---|---|---|
| **1** | **5a-1** | `/access_token` — the grant-type dispatcher (`TokenEndpointHandler`), replacing `TokenEndpointFilter`+`AccessTokenFlowFinder`+`OAuth2FlowFinder`+`TokenEndpointResource`+`RefreshTokenResource`+`ErrorResource`; `WWW-Authenticate`; `Cache-Control: no-store`+`Pragma`; CHF `TokenRequestHook` seam. **First task: the cookie spike** (finding #6). Establishes `AbstractOAuth2HttpJsonEndpoint` (finding #2). Detailed plan: [phase-5a-1.md](phase-5a-1.md) | base + 1 handler + 1 hook iface + hook re-impl | **High** | spike + unit + composition IT + e2e lock |
| **E** | **5-E (§E lock)** | e2e contract lock — record the live-Restlet `/oauth2` error/redirect contract into `e2e/oauth2/oauth2-test.spec.mjs` **by observation** (JSON error + `WWW-Authenticate: Basic` on `/access_token`, incl. the real `GET /access_token` body per finding #1; 301→login `Location`; 302 query-vs-fragment; `text/html;charset=UTF-8` error page) + confirm the 3c golden/parity tests green. A **gate**, not a build step: landable any time in 5a–5c, **recommended right after 5a-1**; **must precede 5d-1** | test-only (0) | **High** — unrecoverable after 5d-1 (risk #20) | the recorded spec, re-run + byte-diffed at 5d-1 |
| **2** | **5a-2** | The 9 remaining JSON endpoints — mechanical conversions off the shared template (`TokenInfoHandler`, `TokenIntrospectionHandler`, `TokenRevocationHandler`, `UserInfoHandler`, `IdTokenInfoHandler`, `ConnectClientRegistrationHandler`, `OpenIDConnectConfigurationHandler`, `JwkUriHandler`, `DeviceCodeHandler`) | 9 handlers | Med | unit per handler |
| **3** | **5b-1** | `AuthorizeHandler` **alone** — the centrepiece (~600L across `AuthorizeResource`+`ConsentRequiredResource`+`OAuth2Representation`): consent page + success 302 + the catch-collapse; port `ConsentRequiredResource.getDataModel`; CHF `AuthorizeRequestHook`; `RedirectUris` success path. Establishes `AbstractOAuth2HttpBrowserEndpoint` (finding #2) | base + 1 handler + 1 hook iface | **High** | unit + golden HTML + composition IT + e2e |
| **4** | **5b-2** | The 3 remaining browser endpoints — `DeviceCodeVerificationHandler`, `CheckSessionHandler` (realm-prefixed only — JSP kept, §5d), `EndSessionHandler` | 3 handlers | Med | unit + golden HTML |
| **5** | **5c** | resource_set — `ResourceSetRegistrationHandler` (POST/GET/PUT/DELETE, `rsid` from template attr) + CHF `ResourceSetRegistrationExceptionFilter`; guarded by `ChfAccessTokenProtectionFilter(null)` | 1 handler + 1 filter | Med | unit + composition IT |
| **6** | **5d-1** | **The flip, Restlet dormant** — `OAuth2HttpRouteProvider` wiring all 18 attachments + the audit matrix; append to `META-INF/services`; web.xml `/oauth2/*` → `OpenAM`; re-sign hooks. **Restlet classes left in place, unrouted.** Revertible by moving one `<servlet-mapping>` back | 1 provider | **High** | `OAuth2RouterIT` + Cargo boot + e2e re-run + smoke diff |
| **7** | **5d-2** | **The deletion** — after 5d-1 soaks green: delete the ~40-class Restlet OAuth2 stack + `ForgeRockRest` servlet; Guice unbinds; finalise hook re-sign (drop Restlet interfaces/methods) | ~40 deletions | Med | whole `-am` build + grep gates |

**Total new main classes: ~18** (14 handlers + 2 abstract bases + 2 hook interfaces) + `OAuth2HttpRouteProvider`
+ 1 CHF exception filter. Plus ~33 ported test files (inventory §11). This is the biggest phase; the split keeps
each commit reviewable and each risk isolated.

Step dependency order: **5a-1 → 5a-2 → 5b-1 → 5b-2 → 5c → 5d-1 → 5d-2** (5a/5b/5c independent after the two
shared bases + conversion template land in 5a-1/5b-1; 5d-1 depends on all handlers; 5d-2 depends only on 5d-1
soaking green). Each of 5a/5b/5c is build-ahead → `mvn install` its module so the next compiles, per the
[.m2 resolution rule](chf-patterns.md#11-build--test-notes-for-the-oauth2-request-re-plumb-phase-3a). The
**5-E gate** is out-of-band: it records live-Restlet behaviour, so it lands any time in 5a–5c (recommended
right after 5a-1) and constrains only 5d-1 — which must not flip until 5-E is recorded and green.

> **Why 5b splits (finding #1).** `AuthorizeHandler` ports three Restlet classes (~600L) and carries the
> hardest logic in the phase — the fragment/query redirect composition, the consent data-model, and the
> catch-collapse behaviour change. It is *larger and riskier than the token endpoint that already got its own
> commit*, so it gets one too. The other three browser endpoints are mechanical by comparison → 5b-2.
>
> **Why 5d splits (finding #3).** The original 5d did the atomic mapping-move **and** the ~40-class deletion in
> one commit. That commit is not cleanly revertible: if the flip regresses, backing it out also resurrects 40
> deleted files. Splitting gives 5d-1 a one-line revert (move the mapping back — the dormant Restlet stack still
> serves) and defers the irreversible deletion to 5d-2, once 5d-1 has proven itself green in CI + Cargo boot.

## The conversion template (applies to every 5a/5b/5c handler)

Every Restlet resource has the **same shape** (verified across all 14): `extends ServerResource`, `@Inject`
collaborators incl. `OAuth2RequestFactory` + `ExceptionHandler`, one `@Get`/`@Post` method calling
`requestFactory.create(getRequest())` then a service, and a uniform
`doCatch(Throwable) → exceptionHandler.handle(...)`. The mechanical port:

1. Drop `extends ServerResource`, `doCatch`, the `JacksonRepresentationFactory`/`ExceptionHandler` ctor deps.
2. `@Get`/`@Post public Response m(@Contextual Context ctx, @Contextual Request req)` — build
   `oauth2Request = requestFactory.create(ctx, req)` (**the `(Context, Request)` overload**, so filters +
   handler share one cached `ChfOAuth2Request` — [phase-4 finding 4](phase-4-uma.md)).
3. Read body via `oauth2Request.getBody()` (a `JsonValue`), params via `getParameter`, bearer via
   `getAuthorizationBearerToken()`, basic via `getBasicAuthCredentials()` — **never `ChallengeResponse`**.
4. Build the JSON body with `new Response(status).setEntity(map)` — `setJson` supplies
   `application/json; charset=UTF-8` for free ([chf-patterns §6](chf-patterns.md)). **Never `setEntity(String)`**
   (ISO-8859-1 trap).
5. **`throw` the existing `OAuth2Exception`** to a shared `@ExceptionHandler` (real since F2) instead of
   catching per-verb. The endpoint's error path is one method, not N catch blocks.
6. Extend **one of two** abstract bases, each carrying its own `@ExceptionHandler` — **subclasses must not
   override it** (Java drops the annotation on override, [chf-patterns §2](chf-patterns.md)).

**⚠ Two bases, not one (finding #2).** The original template proposed a single non-overridable base whose
`@ExceptionHandler` branched by comment between the JSON and browser responses — but a non-overridable method
*cannot* branch per subclass, and JSON vs browser is exactly a per-subclass difference (`toJsonResponse(err)`
vs `mayRedirect→redirectingTo else toResponse(o, err)`). So there are **two** bases (both mirror 4b's
`AbstractUmaHttpEndpoint`, both inject `OAuth2RequestFactory` + `OAuth2ErrorResponseFactory`):

- **`AbstractOAuth2HttpJsonEndpoint`** — established in **5a-1**, extended by every 5a handler:

  ```java
  @ExceptionHandler
  public Response onError(OAuth2Exception e, @Contextual Context ctx, @Contextual Request request) {
      OAuth2Request o = requestFactory.create(ctx, request);
      OAuth2Error err = OAuth2Error.of(e).withState(o.getParameter("state"));
      return errorResponseFactory.toJsonResponse(err);   // carries WWW-Authenticate when err has a challenge
  }
  ```

- **`AbstractOAuth2HttpBrowserEndpoint`** — established in **5b-1**, extended by every 5b handler:

  ```java
  @ExceptionHandler
  public Response onError(OAuth2Exception e, @Contextual Context ctx, @Contextual Request request) {
      OAuth2Request o = requestFactory.create(ctx, request);
      OAuth2Error err = OAuth2Error.of(e).withState(o.<String>getParameter("state"));
      String redirectUri = o.getParameter("redirect_uri");
      if (OAuth2Error.mayRedirect(e) && !isEmpty(redirectUri)) {
          err = err.redirectingTo(redirectUri, err.getParameterLocation());
      }
      return withErrorHeaders(errorResponseFactory.toResponse(o, err));
  }
  ```

  ⚠ **Corrected 2026-07-25 (5b-1 planning), against the shipped API.** The original sketch above had two
  defects: `redirectingTo` takes **two** arguments — `redirectingTo(String, UrlLocation)`
  (`OAuth2Error.java:261`), there is no one-argument overload, and dropping the location sends every
  implicit-flow error to the query where Restlet used the fragment; and the two `toResponse` branches are one
  call, because `toResponse` already dispatches on `hasRedirectUri()`/`isRedirectUriFromException()`
  (`OAuth2ErrorResponseFactory.java:94-110`). `withErrorHeaders` is the 5a-2 D1 hook — `/authorize` is one of
  the two endpoints the Restlet `OAuth2Filter` stamped with `no-store`/`Pragma`, so `AuthorizeHandler`
  overrides it. See [phase-5b-1 D2](phase-5b-1.md#d2).

(The two bodies share the first two lines but diverge on the response shape — which is precisely why they can't
be one non-overridable method. `resource_set` (5c) uses **neither** base — it has its own exception filter, D5-4.)

For **5a** the JSON base yields `toJsonResponse(err)`, which carries `WWW-Authenticate` when `err` has a challenge
(from `OAuth2Error.of(InvalidClientAuthZHeaderException)` — D14). ⇒ **5a handlers must NOT re-derive the
`WWW-Authenticate` header** the way `TokenEndpointResource:102-108` did; route the exception through
`OAuth2Error.of` and let the factory emit it. `RestletConstants.SUPPORTED_RESTLET_CHALLENGE_SCHEMES` dies with
the resources.

## Sub-phase 5a — JSON endpoints

### 5a-1 — the token endpoint (`/access_token`)

> **First task — the cookie spike (finding #6).** Before building the `TokenRequestHook` seam (D5-2), settle
> the one **unproven** assumption it rests on: that a cookie written on the **bridged servlet response**
> (`ChfOAuth2Request.getHttpServletResponse()`, confirmed at `:196`) actually survives `HttpFrameworkServlet`
> writing back the CHF `Response`. `LoginHintHook` writes the `oidcLoginHint` cookie, and CSRF's analogous
> servlet-response write has only ever run **build-ahead, never on a live CHF route** — so nothing has yet
> proven the seam. Spike it first: on a throwaway route (or the token handler itself), write a cookie via the
> bridged servlet response and assert with a real `Request` through the CHF servlet that `Set-Cookie` reaches
> the wire. If it survives, D5-2's neutral-signature hook stands as designed. If it does **not**, the hook must
> set the cookie on the CHF `Response` headers directly, and D5-2 changes here — cheaper to learn now than in
> 5b. This gates the hook-seam design for both 5a-1 and 5b-1.

The one genuinely complex 5a handler. Today: `TokenEndpointFilter` (method=POST + content-type gate) →
`AccessTokenFlowFinder.getEndpointClasses()` maps `grant_type` → a `ServerResource`
(`authorization_code`/`client_credentials`/`password`/`device_code`/`jwt-bearer`/`saml2-bearer` →
`TokenEndpointResource`; `refresh_token` → `RefreshTokenResource`); `OAuth2FlowFinder.create` renders
`ErrorResource` for missing/unknown grant. The grant handlers themselves (`AccessTokenService`,
`Saml2GrantTypeHandler`, …) are already transport-free.

`TokenEndpointHandler` (`@Post`) reproduces:
- **Method/content-type validation** — POST-only (else **405** `method_not_allowed`); entity empty or
  `application/x-www-form-urlencoded` (parsed media type — [chf-patterns §7](chf-patterns.md) charset trap;
  else `invalid_request`). Replaces `TokenEndpointFilter`. **Note (finding #8):** the 405 on `GET /access_token`
  is **free from CHF annotation dispatch** — a handler with only a `@Post` method and no `@Get` returns 405 for
  GET without the handler checking the verb. So this handler only needs to validate **content-type**, not the
  method; the 405 body still needs to be the OAuth2 `method_not_allowed` shape, which the framework
  405 → `OAuth2ErrorFilter` rewrite supplies (D5-1). Assert both (verb-not-checked, body-shaped) in
  `OAuth2RouterIT`.
- **`Cache-Control: no-store` + `Pragma: no-cache` on every response** — today added by `OAuth2Filter:76-77`,
  the base of `TokenEndpointFilter`. The handler sets them explicitly.
- **Grant dispatch** — read `grant_type`; empty → `InvalidRequestException("Grant type is not set")`; unknown
  → `UnsupportedGrantTypeException`; else `accessTokenService.requestAccessToken(request)` /
  `.refreshToken(request)`. Return the token map JSON.
- **`WWW-Authenticate`** — via `OAuth2Error.of` (above), never re-derived.
- **`TokenRequestHook`** — after success, run the hooks (see the hook decision below).

⚠ **Do NOT reproduce `OAuth2Filter.beforeHandle`'s "write an error entity then CONTINUE" bug** (`:58-80`
falls through to `super.beforeHandle` → CONTINUE even after writing an error, so the resource's output
overwrites it). The CHF handler **returns** on validation failure ([phase-3c-2](phase-3c-2-error-layer.md)
"Recorded for Phase 5a").

### 5a-2 — the 9 simple JSON endpoints

Each is a near-mechanical application of the conversion template. Per-endpoint notes (from the code map):

- **`TokenInfoHandler`** (`/tokeninfo`, `@Get`) — `tokenInfoService.getTokenInfo(req)`; sets
  `Cache-Control: no-cache, no-store` (the *resource itself* sets these — `ValidationServerResource:81-82`;
  note `/access_token`'s come from the filter instead). The plan.md worked-example template.
- **`TokenIntrospectionHandler`** (`/introspect`, `@Get`+`@Post`) — `tokenIntrospectionService.introspect(req)`.
- **`TokenRevocationHandler`** (`/token/revoke`, `@Post`) — the richest of the 9 (241 L): `ClientAuthenticator`
  auth, `TokenStore` cascade delete, empty-JSON 200; `InvalidClientAuthZHeaderException`→ challenge via
  `OAuth2Error.of`.
- **`UserInfoHandler`** (`/userinfo`, `@Get`+`@Post`) — `userInfoService.getUserInfo(req)`; bearer via the
  neutral verifier (Header+Form, 3b).
- **`IdTokenInfoHandler`** (`/idtokeninfo`, `@Post`) — carries the inner `ValidateIdTokenRequest` (an
  `OAuth2Request` delegating subclass that overrides `getParameter` to return the id_token's realm claim; 3a
  made its accessors delegate). `setRealmOnRequest` writes the realm onto the servlet request attribute — port
  via `oauth2Request.getHttpServletRequest().setAttribute(...)`.
- **`ConnectClientRegistrationHandler`** (`/connect/register`, `@Get`+`@Post`) — raw Bearer via
  `getAuthorizationBearerToken()` (replaces the `ChallengeResponse.getRawValue()` reads at `:88-89,115`);
  deployment URL from the request; POST → **201**.
- **`OpenIDConnectConfigurationHandler`** / **`JwkUriHandler`** — trivial GETs.
- **`DeviceCodeHandler`** (`/device/code`, `@Post`) — many params; uses `ServletUtils.getRequest` for the
  verification URL → `oauth2Request.getHttpServletRequest()`.

## Sub-phase 5b — HTML/redirect flow (split into 5b-1 + 5b-2)

The hard surface. The redirect-vs-error-page policy that Restlet spreads across catch-clause ordering in
`AuthorizeResource`/`ExceptionHandler` is **already encoded as data** in `OAuth2Error.mayRedirect` +
`redirectingTo` (3c-2, D6/D13), and the redirect composition in `RedirectUris` + the factory. 5b's job is to
port the endpoint shells onto them. **5b splits into two commits (finding #1):** `AuthorizeHandler` alone
(5b-1, ~600L, the riskiest handler in the phase) then the three mechanical browser endpoints (5b-2).

### 5b-1 — `AuthorizeHandler` (the centrepiece)

> **Detailed plan: [phase-5b-1.md](phase-5b-1.md)** (2026-07-25). It splits the step **three ways** — **5-E2**
> (the `/authorize` §E rows, test-only, *first*: two of them decide the handler's validation design), **5b-1a**
> (browser substrate), **5b-1b** (`AuthorizeHandler` + `ConsentPageRenderer`) — and supersedes the bullets below
> where they differ. Four corrections it makes to this section, all verified against the tree:
> **(a)** the §E lock has **no** `/authorize` row today, so the "recorded" state in [plan.md](plan.md) covers
> `/access_token` + cache headers only; **(b)** `getAcceptedLanguages()` **does not exist** on `OAuth2Request`
> — it is a 5b-1a deliverable, not consumed infrastructure; **(c)** `ConsentRequiredResource` is a **shared
> base with the device flow** (`DeviceCodeVerificationResource:81`), so on CHF the consent page must be an
> injected `ConsentPageRenderer`, not a base class — the base slot is taken by
> `AbstractOAuth2HttpBrowserEndpoint`; **(d)** the browser base pseudocode above is corrected (see the ⚠ note
> there).

Establishes `AbstractOAuth2HttpBrowserEndpoint` (the browser `@ExceptionHandler` base, finding #2) and the CHF
`AuthorizeRequestHook` seam (on the cookie-spike outcome from 5a-1).

- **`AuthorizeHandler`** (`@Get`+`@Post`) — the centrepiece:
  - **Success**: `authorizationService.authorize(request[, consentGiven, saveConsent])` → `AuthorizationToken`;
    `redirectUriResolver.resolve(request)`; compose the 302 via `RedirectUris.compose(...)` — **fragment vs
    query from `AuthorizationToken.isFragment()`** (`OAuth2Representation.toRepresentation:155`), or render
    `FormPostResponse.ftl` when `response_mode == form_post`.
  - **Consent**: on `ResourceOwnerConsentRequired` (which extends `Exception`, **not** `OAuth2Exception` — do
    not sweep it into the mapper) render `<display>/authorize.ftl` via `renderForDisplay`. **Port
    `ConsentRequiredResource.getDataModel` for real** — and it seeds the model from
    `new HashMap<>(getRequest().getAttributes())` + `getQuery().getValuesMap()`, so `realm`/`redirect_uri`/
    `scope`/`state`/`nonce`/`acr`/`response_type`/`client_id`/`ui_locales` arrive **implicitly**. A CHF port
    must **enumerate them** or every `<#if x??>` silently goes false
    ([phase-3c-2 "Recorded for Phase 5b"](phase-3c-2-error-layer.md)). ESAPI-encode `display_name`/
    `display_description`; the non-ASCII marker survives only in `user_name`
    ([3c-1 as-built #6](phase-3c-1-renderer.md#as-built)). CSRF token from `csrfProtection.createCsrfToken`
    (already neutral — reads `getHttpServletRequest/Response`).
  - **Errors**: the whole catch cascade collapses into **one** `@ExceptionHandler` using
    `mayRedirect(e) && redirect_uri != null → redirectingTo(...)`, else `toResponse` (error page). This
    **unifies GET's and POST's drifted catch lists to the safe union** (D6) and closes the POST open redirect —
    a deliberate behaviour change at the flip (decisions.md D6; 5d smoke matrix).
  - **`?display=bogus`** — `renderForDisplay` throws `IllegalArgumentException` (3c-1 D7). 5b must map IAE →
    `invalid_request`, and **decide** the two `IllegalArgumentException` branches of `AuthorizeResource:120-126`
    (one redirects to an unvalidated URI today — [phase-3c-2 finding 4](phase-3c-2-error-layer.md)).
### 5b-2 — the three remaining browser-facing endpoints

> **Detailed plan: [phase-5b-2.md](phase-5b-2.md)** (2026-07-28). It splits the step **three ways** — **5-E3**
> (the live-Restlet contract lock for all three, test-only, *first*: three decisions are gated on it), **5b-2a**
> (`EndSessionHandler` + `CheckSessionHandler`), **5b-2b** (`DeviceCodeVerificationHandler`) — and **supersedes
> the bullets below** where they differ. Two corrections it makes, both verified against the tree:
> **(a)** the line "Extend `AbstractOAuth2HttpBrowserEndpoint`. All three are near-mechanical" is **wrong about
> two of the three**. The `doCatch` arity is the error contract: `EndSession` and
> `OpenIDConnectCheckSessionEndpoint` call `ExceptionHandler.handle(Throwable, Response)`, which emits **JSON**,
> so they extend `AbstractOAuth2HttpJsonEndpoint`. Only `DeviceCodeVerificationResource` calls the 4-arg
> (page/redirect) variant. **(b)** the device flow does **not** simply "share the consent-page path" —
> `ConsentPageRenderer` as shipped in 5b-1 reads only `realm` from the request attributes, while the device flow
> seeds its *entire* consent model from attributes, so the shared collaborator needs a phase-1 correction (D2)
> before it can serve that caller at all.

- **`DeviceCodeVerificationHandler`** (`/device/user`, `@Get`+`@Post`) — `CodeVerificationForm.ftl`/
  `CodeThanks.ftl`; CSRF checked **inline** here (`csrfProtection.isCsrfAttack`), unlike `/authorize` where
  it is inside `AuthorizationService`. Shares the consent-page path with `AuthorizeHandler`. **Note:** the device
  flow is split across steps — `/device/code` is 5a-2, `/device/user` is 5b-2 — so an end-to-end device-flow
  e2e is only green **at 5d-1** when both are live on CHF. Unit-test each half in its own step; gate the
  cross-endpoint e2e on the flip.
- **`CheckSessionHandler`** (`/connect/checkSession`) — renders `checkSession.ftl`. **Decision (locked): keep
  the JSP; this handler serves realm-prefixed paths only.** The `checkSession.jsp` exact servlet-mapping already
  out-ranks `/oauth2/*` today, so the standard path is served by the JSP and the Restlet endpoint is shadowed
  (reachable only via `/oauth2/realms/root/connect/checkSession`). Mounting `CheckSessionHandler` for the
  realm-prefixed variants is zero-behaviour-change parity (D5-5; §5d web.xml keeps the JSP + mapping).
  `display=popup` now resolves `popup/checkSession.ftl` (nonexistent) after the 3c-1 D5 fix — 5b-2 decides error
  vs fall back to `page/` (decisions.md D5).
- **`EndSessionHandler`** (`/connect/endSession`, `@Get`) — `id_token_hint` → `azp` claim → validate
  `post_logout_redirect_uri` against the client's list → **302 with `state` always in query** (never fragment,
  `EndSession:127`). `ServerException` from session removal is swallowed with a warn today — reproduce. Note:
  the id_token signature is **not** verified today (only `azp` parsed) — reproduce, flag for a post-migration
  security item (do not fix inside a parity migration).

## Sub-phase 5c — resource_set

`ResourceSetRegistrationHandler` (POST/GET/PUT/DELETE) ports `ResourceSetRegistrationEndpoint` (367 L)
verbatim in business logic; `rsid` moves from the Restlet URI-template attribute
(`getRequestAttributes().get("rsid")`) to the seeded template variable on `ChfOAuth2Request` (merged from
`UriRouterContext`, [phase-3a](phase-3a-oauth2request.md)). Client id / resource owner from the stashed
`getToken(AccessToken.class)` — stashed by `ChfAccessTokenProtectionFilter(null scope)` (validity-only, exactly
resource_set's semantics: `OAuth2GuiceModule:401` builds `AccessTokenProtectionFilter(null, …)`).

The **`ResourceSetRegistrationExceptionFilter` has a resource-set-specific error shape** distinct from
`OAuth2ErrorFilter` (draft-hardjono-oauth-resource-reg §3): 405 → `{"error":"unsupported_method_type"}`, 412 →
`{"error":"precondition_failed"}`, `OAuth2Exception` → `{"error":…, "error_description":…}`, else 500
`server_error`. Port it as a CHF `Filter` (mirrors `XacmlXmlErrorFilter`'s afterHandle rewrite), scoped to the
resource_set routes only. ⇒ **resource_set does NOT get `OAuth2ErrorFilter`** — its exception filter is a
different contract, like UMA's CREST carve-out (D4).

**Trailing slash**: register all three CHF routes — `resource_set`, `resource_set/`, `resource_set/{rsid}` —
they are distinct attachments (risk #8).

## Sub-phase 5d — the flip, split into 5d-1 (flip) + 5d-2 (delete)

The flip is **two commits** (finding #3), because the original one-commit 5d bundled an *irreversible*
~40-class deletion with the mapping move — so a regression in the flip could only be backed out by resurrecting
40 files. Split:

- **5d-1 — flip, Restlet dormant.** Land `OAuth2HttpRouteProvider`, append to `META-INF/services`, **move** the
  `/oauth2/*` `<servlet-mapping>` from `ForgeRockRest` to `OpenAM`, finalise the hook re-sign so the CHF handlers
  own the live path. **Leave the entire Restlet OAuth2 stack in place, unrouted** (`ForgeRockRest` still
  declared, just no longer mapped to `/oauth2`). This commit is revertible by a **one-line** change — move the
  mapping back and the dormant Restlet stack serves again. Soak it green through `OAuth2RouterIT` + Cargo boot +
  the e2e re-run + smoke diff **before** proceeding.
- **5d-2 — delete.** Only after 5d-1 is proven: delete the ~40-class Restlet OAuth2 stack, remove the
  `ForgeRockRest` servlet + its mapping, drop the Restlet Guice bindings, and finalise the hook interfaces
  (delete the Restlet-typed interfaces + methods on `LoginHintHook`). Guarded by the whole `-am` build + grep
  gates — no behaviour change, pure removal.

The three subsections below are shared substrate; each notes whether it lands in **5d-1** or **5d-2**.

### `OAuth2HttpRouteProvider` (new, `org.forgerock.openam.oauth2.rest`) — **5d-1**

Mirror [`UmaHttpRouteProvider`](../../../openam-uma/src/main/java/org/openidentityplatform/openam/uma/UmaHttpRouteProvider.java)
(the confirmed template) but with the full 18-attachment table (15 endpoints; resource_set ×3) + the per-route
audit matrix above. Reuse its two helpers verbatim in shape:
- `protect(cls, scope)` = `chainOf(Endpoints.from(cls), new ChfAccessTokenProtectionFilter(scope, tokenStore, requestFactory))` — used **only** for resource_set (scope `null`), wrapped further by the CHF
  `ResourceSetRegistrationExceptionFilter`.
- `audited(handler, reqAuditor, respAuditor)` = `chainOf(handler, new OAuth2HttpAccessAuditFilter(publisher, factory, requestFactory, reqAuditor, respAuditor))` — audit outermost of each per-route chain.
- Realm-routing root identical to Xacml/Uma: `root.addRoute(STARTS_WITH, REALM_ROUTE, chainOf(createRouter(root), createHostnameFilter()))` + `root.setDefaultRoute(chainOf(endpointRouter, realmContextFilter))`.
- **Wrap the whole root in `OAuth2ErrorFilter`** — `newHttpRoute(STARTS_WITH, "oauth2", chainOf(root, oauth2ErrorFilter))` — so it catches framework 405/500 + realm-layer CREST errors and unifies them to OAuth2 shape (D4; unlike UMA which wanted CREST left alone). This is why XACML wrapped `chainOf(root, xacmlXmlErrorFilter)` and UMA wrapped nothing — `/oauth2`'s contract *is* the OAuth2 shape end-to-end.
- Register `authorize`, `access_token`, `resource_set`, … endpoint segments into `@Named("InvalidRealmNames")`
  (guards realm *creation*, as XACML did with `policies`).
- Append `org.forgerock.openam.oauth2.rest.OAuth2HttpRouteProvider` to the **existing**
  `openam-oauth2/.../META-INF/services/org.forgerock.openam.http.HttpRouteProvider` (already holds
  `OAuth2RestHttpRouteProvider` for `/frrest/oauth2`).

### web.xml (verified 2026-07-24)

- **5d-1:** Move `/oauth2/*` (`web.xml:1143-1146`) from `ForgeRockRest` → `OpenAM`, beside `/uma/*` and
  `/xacml/*` (`:1130-1137`). **Stop there in 5d-1** — leave the now-unmapped `ForgeRockRest` servlet **declared**
  so the flip is a one-line revert.
- **5d-2:** **delete the `ForgeRockRest` servlet + its only mapping entirely** — `/oauth2` was its last consumer
  (uma/xacml already moved in Phases 2/4). This is the last Restlet servlet on the request path.
- **Unchanged** (url-pattern-based, servlet-agnostic — they keep applying under `OpenAM`):
  `FQDNValidationFilter` on `/oauth2/device/user` + `/oauth2/authorize` (`:185-192`), `CORSFilter` on
  `/oauth2/*` (`:224-227`).
- **⚠ Two exact JSP mappings that out-rank `/oauth2/*`:**
  - `/oauth2/connect/checkSession` → `OAuth2ConnectCheckSession` (`checkSession.jsp`, `:1085-1088`). The JSP is
    a **self-contained** check-session iframe (uses `org.forgerock.openidconnect.CheckSession` directly). By
    servlet exact-mapping precedence it **already wins over `/oauth2/*` today**, so the Restlet
    `OpenIDConnectCheckSessionEndpoint` is effectively shadowed on the standard path (reachable only via
    realm-prefixed `/oauth2/realms/root/connect/checkSession`). **Decision (LOCKED): keep the JSP + its mapping**
    (parity — it is what serves today, and `CheckSessionHandler` covers only realm-prefixed variants) and mount
    `CheckSessionHandler` for the realm-prefixed path only. The JSP mapping is **not** touched in 5d-1 or 5d-2.
  - `/oauth2/registerClient.jsp` → `OAuth2RegisterClient` (`:1080-1083`) — a 308-line **UI form** for dynamic
    registration, unrelated to `/connect/register`. Leave it; it is not a Restlet endpoint.

### Deletions (the Restlet OAuth2 stack) — **5d-2**

`OAuth2RouterProvider`, `OAuth2Filter`+`TokenEndpointFilter`+`AuthorizeEndpointFilter`, `AccessTokenFlowFinder`+
`OAuth2FlowFinder`+`ErrorResource`, all `org.forgerock.oauth2.restlet.*` + `org.forgerock.openidconnect.restlet.*`
resources (**except** `WebFinger`/`OpenIDConnectDiscovery` → Phase 6), `OAuth2Representation`+`TemplateFactory`,
`ExceptionHandler`+`OAuth2RestletException`, `RestletConstants`, the Restlet `AccessTokenProtectionFilter`+
`ResourceSetRegistrationExceptionFilter`, `RestletOAuth2Request` + the `OAuth2RequestFactory.create(Request)`
Restlet overload, the Restlet OAuth2 audit filters, `RestEndpointServlet`+`RestletServiceServlet`+
`OAuth2ServiceEndpointApplication`. Guice: `OAuth2RestGuiceModule` drops `Router @Named("OAuth2Router")`
(`:44`); `OAuth2GuiceModule` drops the `@Named(RSR_ENDPOINT)` Restlet `@Provides` (`:394-403`) — re-typed to a
CHF `Handler` or removed since the route provider builds the chain directly.

⚠ **Correction to plan.md's 5d bullet:** it says "rebind the 3 `Restlet*AccessTokenVerifier`s". **Already
done** — `OAuth2GuiceModule:181-184` already binds the neutral `Header/FormBody/QueryParameter
AccessTokenVerifier` (3b), and no `Restlet*AccessTokenVerifier` class exists in the tree. Drop that item.

## Cross-cutting design decisions (new to Phase 5)

- **D5-1 — `/oauth2` framework/uncaught errors are CREST-shaped, and `OAuth2ErrorFilter` unifies them.**
  Verified: `OAuth2ServiceEndpointApplication:36` installs **`JSONRestStatusService`** (CREST
  `{code,reason,message}`), **not** `OAuth2StatusService`. So on CHF the framework 405/500 + realm-layer errors
  are CREST, and `OAuth2ErrorFilter` (keyed on wire status) rewrites them to OAuth2 `{error,…}`. `OAuth2StatusService`
  is **WebFinger-only** (`WebFinger:60`) → Phase 6. (An exploration pass mis-stated OAuth2StatusService as the
  `/oauth2` catch-all; the line-verified truth is JSONRestStatusService.)

- **D5-2 — the hooks need a CHF seam; add parallel CHF interfaces in 5a-1/5b-1, delete the Restlet ones at 5d-2.** `TokenRequestHook`
  and `AuthorizeRequestHook` today take Restlet `Request`/`Response`, and their sole impl `LoginHintHook`
  manipulates Restlet `CookieSetting`s. The CHF handlers (5a-1/5b-1) cannot call the Restlet-typed methods, and
  re-signing the interface in place would break the still-live Restlet callers. **Decision:** introduce CHF
  hook interfaces (e.g. `org.openidentityplatform.openam.oauth2.http.ChfTokenRequestHook` /
  `ChfAuthorizeRequestHook`) whose methods take just `OAuth2Request` — everything `LoginHintHook` needs
  (read `login_hint`, read/write the `oidcLoginHint` cookie) is reachable via `getHttpServletRequest/Response`
  on the neutral request. `LoginHintHook` implements **both** old and new (modified in place); the Multibinders
  gain a CHF binding; the CHF handlers inject the CHF set. At **5d-2**, delete the Restlet interfaces + the
  Restlet methods on `LoginHintHook`. (Alternative — plan.md's `(OAuth2Request, Context, Request, Response)`
  CHF-typed signature — also works but is wider than needed; the neutral-only signature is simpler and matches
  how CSRF already writes cookies through the servlet response.)

- **D5-3 — `Cache-Control`/`Pragma` provenance differs by endpoint.** `/access_token` gets `no-store`+`no-cache`
  from `OAuth2Filter` (the filter, `:76-77`); `/tokeninfo` sets `no-cache, no-store` from the *resource*
  (`ValidationServerResource:81-82`). The CHF handlers set these explicitly on the right endpoints — do not
  assume one blanket rule.

- **D5-4 — resource_set keeps its own error filter, not `OAuth2ErrorFilter`.** The resource-reg spec shape
  (405→`unsupported_method_type`, 412→`precondition_failed`) is not the OAuth2 shape. Scope the CHF
  `ResourceSetRegistrationExceptionFilter` to the three resource_set routes; the outer `OAuth2ErrorFilter`
  wrapping the whole `/oauth2` root would otherwise rewrite these — so the resource_set exception filter runs
  **inside** the endpoint chain and produces the final body before the outer filter sees a `≥400` with an
  `error` key (which the outer filter leaves alone — idempotent). Pin this interaction with an IT row.

- **D5-5 — the JSP check-session gotcha** (see 5d web.xml) — recorded so 5b does not assume its
  `CheckSessionHandler` owns the standard path.

- **Carried from 3c/decisions.md, landing silently at the 5d-1 flip** (all belong in 5d-1's smoke matrix, per
  [decisions.md](decisions.md) + plan.md risk #11/#22): **D3** uncaught bug path stays 500 (not Restlet's 400);
  **D5** popup stops ignoring `templateName` (checkSession?display=popup consequence); **D6** the no-redirect
  policy unifies to the safe union → `POST /authorize` with no provider renders the error page instead of
  redirecting; **D11** `Location` set verbatim (no Restlet `{}`-substitution); **D13** RoAR keeps the login
  URI; **D14** `WWW-Authenticate` realm is RFC-7235-quoted (a wire divergence only for a realm containing
  `"`/`\`/CTL).

## Framework / CHF issues we own and could fix in Phase 5

Per [decisions.md](decisions.md#chf-cleanup-backlog) + [framework-ownership.md](../../framework-ownership.md),
fix defects in code we own rather than pattern around them. Phase-5-relevant:

- **`Form.fromRequestEntity` charset trap** (commons, deferred backlog item). `/access_token` and
  `/introspect` read `application/x-www-form-urlencoded` bodies; OAuth2 client libraries routinely send
  `;charset=UTF-8`, which `getForm()` silently parses as empty. The handlers route around it (`ContentTypeHeader.valueOf(request).getType()` + `new Form().fromFormString(entity.getString())`,
  [chf-patterns §7](chf-patterns.md)) — **but Phase 5 is the first phase that reads a form *body* on a live
  route**, so this is the phase where fixing `Form.fromRequestEntity` at source (parse media type, ignore
  parameters) would finally pay for itself. **Decision (LOCKED):** route around in 5a-1/5a-2
  (`ContentTypeHeader.valueOf(request).getType()` + `new Form().fromFormString(...)`, contained, no
  release dependency) **and** file the commons `Form.fromRequestEntity` fix to land **independently** on its own
  release cadence — so the migration never blocks on a commons release, but the defect is still paid down.
- **`AMAccessAuditEventBuilder.forRequest` port `-1`** (in-tree, openam-audit-core; backlog). Surfaces on
  `/oauth2` audit `http/request/path` behind a TLS terminator. Fix in its own commit; record in 5d-1's audit
  smoke diff.
- **Any new `Endpoints.from`/`AnnotatedMethod` sharp edge** discovered while wiring 14 handlers — fix in-tree
  (openam-http) with its own tests, never inside a 5x migration commit (the F1–F4 precedent).

## Parity-preserved security debts — reproduce now, fix later (finding #7)

Two behaviours in the current `/oauth2` are arguably wrong but must be **reproduced faithfully** at the flip
(this is a parity migration; changing them silently would break the e2e byte-diff and hide a behaviour change
inside a mechanical port). Reproduce them, and record them here as an explicit post-migration security-debt
list so they are not forgotten once the Restlet oracle is deleted:

- **Unverified `id_token_hint` signature on `/connect/endSession`.** `EndSession.validateRedirect`
  (`EndSession.java:142-144`, CONFIRMED) reconstructs the JWT and reads **only** the `azp` claim to pick the
  client — it does **not** verify the id_token signature. A caller can forge an `id_token_hint` with an
  arbitrary `azp` to select a client whose `post_logout_redirect_uri` list it wants matched. 5b-2 reproduces
  this (swallow-and-warn on `ServerException` too). **Post-migration:** add signature verification.
- **301 (permanent) redirect to the login page on unauthenticated `/authorize`.** The redirect to the login
  page is a **301**, which is cacheable/permanent — a browser may cache it and skip re-hitting `/authorize`.
  A 302 would be more correct. The §E lock records the 301 as-is (observation, not prediction); 5b-1 reproduces
  it. **Post-migration:** consider 302.

Neither is fixed inside Phase 5. Both belong on the security backlog and should be linked from
[decisions.md](decisions.md) so they survive the oracle's deletion at 5d-2.

## Integration testing

The migration's highest-risk surface is **route composition** — realm routing, the protection filter, the
audit wrap, three error shapes (OAuth2 handled / CREST framework / resource-reg), the 302 fragment/query
composition — none of which a layer-1 unit test exercises. Three guards, layered by
[test-infrastructure.md](../../test-infrastructure.md)'s cost model:

1. **Layer-2 `OAuth2RouterIT`** (in-process, openam-oauth2). **Prefer adding no new test dependency (finding
   #5):** the 3c-2 IT `OAuth2ErrorRouteCompositionIT` already proved `openam-http`/`Endpoints.from` composition
   works **without** `commons.guice:test`, so model `OAuth2RouterIT` on it and build the router the same way
   first. **Only if** a route-provider IT genuinely needs the minimal Guice injector should the dep be added —
   and then it is **`org.openidentityplatform.commons.guice:test`** (the fork groupId; **not**
   `org.forgerock.commons.guice`), which `openam-oauth2/pom.xml` does not have today. Model:
   [`XacmlRouterIT`](phase-2-integration-tests.md)/[`UmaRouterIT`](phase-4-uma.md) — minimal
   injector, `setGuiceModuleLoader(→ empty)`, build the router from
   `InjectorHolder.getInstance(OAuth2HttpRouteProvider.class).get()`, dispatch real `Request`s. Assert, at
   minimum: token-endpoint 405 on GET; `WWW-Authenticate` on bad client secret; authorize 301→login (value);
   authorize 302 error fragment vs query; the **three error shapes coexisting** (OAuth2 handled, CREST
   framework via a wrong verb, resource-reg via 405 on resource_set); realm styles (`?realm=`,
   `/realms/root/`, legacy `/oauth2/sub/`); resource_set trailing-slash × 3; audit body-detail on
   `/access_token` (one request through audit+handler proves the buffered-body re-read, risk #1). This runs on
   all 9 CI legs (failsafe on `verify`).
2. **Layer-4 e2e** — extend `e2e/oauth2/oauth2-test.spec.mjs` (fixtures + CI wiring already exist). **This is
   also the §E contract-lock host** — write those rows against live Restlet *before* 5d (the gate above), then
   the same spec re-runs against the flipped CHF server after 5d and must match. Add the full smoke matrix:
   client_credentials / authorization_code / refresh / device flows, browser consent grant+deny, `form_post`,
   introspect/tokeninfo/revoke, dynamic registration, jwk_uri, checkSession, endSession redirect. Authenticate
   any second identity in a disposable `apiRequest.newContext()` (the cookie-outranks-header trap).
3. **Layer-3 Cargo boot** (`mvn -pl openam-server verify -P integration-test`) — proves the WAR starts with
   `OAuth2HttpRouteProvider` bound (a broken Guice binding fails startup; there is otherwise **no** test that
   catches a broken OAuth2 binding — test-infrastructure.md coverage gap). Asserts no OAuth2 behaviour.

The golden HTML oracle (3c-1) and error parity (3c-2) tests already exist and cover the render/error contract
build-ahead; they degrade to `golden == CHF` at 5d-2 (when the Restlet leg is deleted).

## Verification criteria

**Per build-ahead step (5a-1, 5a-2, 5b-1, 5b-2, 5c):**
1. `mvn -o -pl openam-oauth2 test` — new handler unit tests green; existing suite unchanged (the module count
   only grows; the current baseline is openam-oauth2 **882** surefire + 6 failsafe, openam-uma **194** — see
   [phase-3c-2 as-built](phase-3c-2-error-layer.md#as-built) + [phase-4](phase-4-uma.md)).
2. `mvn -o -pl openam-oauth2 verify` — the composition IT runs (**`mvn test` skips `*IT`** —
   [test-infrastructure.md](../../test-infrastructure.md)).
3. `mvn -o -pl openam-oauth2 install -DskipTests` so the next sub-phase compiles.
4. Grep gates: `grep -rn "org.restlet\|getCurrent()" <new handler files>` → 0 (parity *tests* may import
   Restlet legitimately until 5d-2).
5. Whole-reactor `mvn install -DskipTests` — **doclint is fatal** ([test-infrastructure.md](../../test-infrastructure.md)).

**5d-1 (the flip, Restlet dormant):**
6. `mvn -o -pl openam-oauth2 verify` — `OAuth2RouterIT` (all rows) green.
7. **Whole build with `-am`:** `mvn -o install -pl openam-oauth2,openam-oauth2-saml2,openam-uma,openam-rest -am -DskipTests` — confirms web.xml/WAR wiring with `/oauth2/*` now on `OpenAM` (`-am` avoids the stale-SNAPSHOT
   trap — memory `.m2 stale schema jar trap`).
8. Cargo boot (criterion 3 above).
9. **e2e re-run** — the §E lock + full smoke matrix, now against the flipped CHF server, byte-diffed against
   the pre-flip capture. The **only** rows allowed to differ are the D3/D5/D6/D11/D13/D14 changes above — every
   other row must match. Record the diff. **This is the soak gate: 5d-1 must be green here before 5d-2.**
10. CI: JDK 11–26 × 3 OSes on the `features/**` push — cross-version coverage of entity/charset handling free.

**5d-2 (the deletion, after 5d-1 soaks):**
11. **Whole build with `-am`** — now confirms `RestEndpointServlet`/`ForgeRockRest` deletion and **no dangling
    refs to the ~40 deleted classes**.
12. Grep gates (final): `grep -rn "org.restlet" openam-oauth2/src/main --include=*.java` → 0 except the
    Phase-6 WebFinger/OpenIDConnectDiscovery classes; `getCurrent()` gate → 0.
13. e2e re-run once more (now `golden == CHF` only) + CI green → mark Phase 5 `done`.

## Risk register (extends [plan.md](plan.md)'s + [phase-4](phase-4-uma.md)'s)

- **R-5.1 The oracle expires at the flip.** The §E e2e lock and the golden/parity tests are the only record of
  "what `/oauth2` does today". The **live** e2e oracle expires at **5d-1** (Restlet stops serving `/oauth2`);
  the golden/parity unit tests (direct class calls) survive until **5d-2**. If the live lock is not recorded
  *before 5d-1* it is unrecoverable. **Guard:** the prerequisite gate above; generate/confirm all oracles during
  5a–5c.
- **R-5.2 Three error shapes, one app.** OAuth2 (handled, via `@ExceptionHandler`), CREST (framework/realm, via
  `OAuth2ErrorFilter` rewrite), resource-reg (via the scoped exception filter). Wiring the wrong filter over
  the wrong route silently corrupts a shape. **Guard:** `OAuth2RouterIT` asserts all three in situ (D5-1/D5-4).
- **R-5.3 The catch-collapse changes behaviour (D6/D13).** Unifying GET/POST catch lists closes the POST open
  redirect and changes `POST /authorize` with no provider from a 302 to an error page. **Guard:** enumerated in
  `OAuth2ErrorTest` (3c-2, all 31 subclasses); 5d-1 smoke matrix; **not** asserted in the §E lock (it is a
  change, not a reproduce).
- **R-5.4 Success-redirect fragment/query.** From `AuthorizationToken.isFragment()`, not the exception's
  `parameterLocation`. Getting this from the wrong source breaks implicit/hybrid flows. **Guard:**
  `AuthorizeHandlerTest` asserts 302 `Location` composition per response_type; e2e authorization_code (query)
  + implicit (fragment).
- **R-5.5 Consent data-model implicit keys.** `getDataModel` seeds from request attributes + query map; a CHF
  port that does not **enumerate** them renders a broken consent page with every `<#if>` false. **Guard:**
  golden render (3c-1 derived the model from the real producer) + e2e browser consent.
- **R-5.6 The token-endpoint dispatcher.** Six Restlet classes collapse into one handler; a missed grant type
  or the reproduced `OAuth2Filter` continue-bug silently breaks a flow. **Guard:** `TokenEndpointHandlerTest`
  per grant_type + e2e client_credentials/authorization_code/refresh/device.
- **R-5.7 The JSP check-session shadow (D5-5).** Mounting `CheckSessionHandler` on `/oauth2/connect/checkSession`
  does nothing while the JSP exact-mapping wins; assuming it works masks a dead route. **Resolved (LOCKED):**
  keep the JSP, mount `CheckSessionHandler` for realm-prefixed paths only. **Guard:** e2e hits the actual served
  path (the JSP on the standard path, the handler on `/realms/root/...`).
- **R-5.8 Hook seam gap (D5-2).** If the CHF handlers skip the hook loop (or the re-sign breaks the Restlet
  callers before 5d-1), the `login_hint` cookie behaviour silently vanishes. **Also unproven until the 5a-1
  cookie spike:** whether a cookie written on the bridged servlet response survives the CHF servlet write-back
  (finding #6). **Guard:** the 5a-1 spike; unit test the CHF `LoginHintHook` path; e2e `login_hint` round-trip.
- **R-5.9 Build-ahead has no live guard** (risk #19). 5a/5b/5c handlers are dormant until 5d-1. **Guard:** golden
  oracle + composition IT + the §E lock — the same instruments 3c/4 relied on.
- **R-5.10 resource_set trailing slash** (risk #8) — three CHF routes, verified per-route in `OAuth2RouterIT`.

## Execution order — 7 build steps + the §E gate step (5-E)

**5-E (the §E gate).** Record the live-Restlet `/oauth2` error/redirect contract into
`e2e/oauth2/oauth2-test.spec.mjs` **by observation, not prediction** + confirm the 3c golden/parity tests green.
A distinct, tracked step — but a **gate**, not a sequential build step: landable any time in 5a–5c,
**recommended right after 5a-1** (its `/access_token` rows empirically settle finding #1's `GET /access_token`
question), and it **must land before 5d-1** — the live oracle dies when the mapping moves (risk #20). Re-run +
byte-diff the same spec after 5d-1; only the deliberate D3/D5/D6/D11/D13/D14 rows may differ.

The seven build steps, one after another:

1. **5a-1** — **the cookie spike first** (finding #6), then `TokenEndpointHandler` + `AbstractOAuth2HttpJsonEndpoint`
   base + CHF `TokenRequestHook` seam + `LoginHintHook` dual-impl → tests → `install`.
2. **5a-2** — the 9 simple JSON handlers off the conversion template → tests → `install`.
3. **5b-1** — `AuthorizeHandler` **alone** + `AbstractOAuth2HttpBrowserEndpoint` base (+ ported `getDataModel`,
   CHF `AuthorizeRequestHook`) → golden + unit tests → `install`.
4. **5b-2** — `DeviceCodeVerificationHandler`, `CheckSessionHandler` (realm-prefixed only), `EndSessionHandler`
   → golden + unit tests → `install`.
5. **5c** — `ResourceSetRegistrationHandler` + CHF `ResourceSetRegistrationExceptionFilter` → tests → `install`.
6. **5d-1 (flip, Restlet dormant)** — `OAuth2HttpRouteProvider` + services file + `OAuth2RouterIT`; web.xml
   `/oauth2/*` mapping move; hook re-sign finalise. **Restlet stack left in place.** → module `verify` → whole
   `-am` build → Cargo boot → **e2e re-run + smoke diff**. Soak green.
7. **5d-2 (delete)** — after 5d-1 soaks: delete the Restlet OAuth2 stack + `ForgeRockRest` servlet; Guice
   unbinds; drop the Restlet hook interfaces/methods → whole `-am` build → grep gates → mark Phase 5 `done` in
   [plan.md](plan.md).

## Corrections to plan.md (folded into plan.md's superseding banner 2026-07-24)

These were folded into [plan.md](plan.md)'s Phase 5 banner + phase-status table (the 7-step split) on 2026-07-24:

- The 3 `Restlet*AccessTokenVerifier` rebind is **already done** (3b) — dropped from the 5d bullet.
- `CheckSessionHandler` accounts for the **JSP exact-mapping** on `/oauth2/connect/checkSession` — decision
  locked: keep the JSP, mount the handler for realm-prefixed paths only (D5-5).
- The hook re-sign is a **coordination** problem (parallel CHF interfaces in 5a-1/5b-1, delete Restlet ones at
  5d-2), not a single in-place edit (D5-2).
- `/oauth2` framework errors are **CREST via JSONRestStatusService** (D5-1), which is what makes
  `OAuth2ErrorFilter` the right tool (plan.md's `OAuth2StatusService` mention is Phase 6's WebFinger case).
