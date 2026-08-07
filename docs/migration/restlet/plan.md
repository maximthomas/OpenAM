# Restlet → CHF Migration Plan

Executable phase plan for removing the Restlet framework from OpenAM. Research backing
this plan: [inventory.md](inventory.md); decision record: [decisions.md](decisions.md); CHF
target-stack patterns verified during Phase 2, reused by every later phase:
[chf-patterns.md](chf-patterns.md).
Written 2026-07-08; branch `features/restlet-migration`.

## Decisions (locked)

- **Target**: CHF Handlers (`org.forgerock.http`) via the existing `HttpRouteProvider`
  SPI and `Endpoints.from` annotated POJOs — the codebase's own declared direction.
  Rejected alternatives: JAX-RS/Jersey (duplicates realm/audit/version infra, second
  modern stack), plain servlets (boilerplate), Spring MVC (foreign stack).
- **Strategy**: incremental strangler — one endpoint area per phase, each phase a
  shippable green commit. Cutover lever: the `OpenAM` `HttpFrameworkServlet` uses
  `routing-base=context_path`, so each area moves by (a) adding an `HttpRouteProvider`
  for its leading path segment + `META-INF/services` registration, and (b) moving its
  `<servlet-mapping>` from `ForgeRockRest` to `OpenAM` in
  `openam-server-only/src/main/webapp/WEB-INF/web.xml`.
- **Scope**: full removal — server endpoints, outbound scripting client, vestigial
  imports, then deletion of `openam-restlet` and the vendored
  `transform-jakarta/restlet-parent-jakarta` fork.
- **Order**: XACML (smallest, proves the pattern) → core re-plumb → UMA → OAuth2/OIDC →
  WebFinger/stragglers → outbound client → deletion.

## Phase status

| Phase | Scope | Status |
|---|---|---|
| 1 | Migration docs (this folder) | done |
| 2 | XACML `/xacml` → CHF | done (integration tests pending — [phase-2-integration-tests.md](phase-2-integration-tests.md)) |
| 3a | `OAuth2Request` abstraction + consumer re-plumb | done ([phase-3a-oauth2request.md](phase-3a-oauth2request.md)) |
| 3b | Transport-neutral collaborators (verifiers, `ClientCredentialsReader`, `OAuth2Utils`) | done ([phase-3b-collaborators.md](phase-3b-collaborators.md)) |
| 3c-1 | FreeMarker template renderer (`org.openidentityplatform.openam.oauth2.http`) | done ([phase-3c-1-renderer.md](phase-3c-1-renderer.md)) |
| **F1–F4** | **`openam-http` framework fixes** — handler-thrown exceptions get a body (F1); `@ExceptionHandler` made real (F2); `Promise` return type implemented (F3); `@Produces` honoured (F4) | done 2026-07-22 ([as-built](openam-http-framework.md#as-built)) |
| 3c-2 | Error layer — `OAuth2Error`, `RedirectUris`, error factory + filter | done 2026-07-22 ([phase-3c-2-error-layer.md](phase-3c-2-error-layer.md)) |
| 3d | CHF audit filters + `HttpBodyAuditor` | done 2026-07-23, as the mandated two commits ([as-built](phase-3d-audit.md#as-built)) |
| 4 | UMA `/uma` → CHF — **4a** shared protection filter + **4b** endpoints/flip | done 2026-07-23 ([phase-4-uma.md](phase-4-uma.md)) |
| **5** | **OAuth2/OIDC `/oauth2` → CHF** — the largest area; umbrella research + route table: [phase-5-oauth2.md](phase-5-oauth2.md) | in progress — sub-steps below |
| 5a-1 | `/access_token` grant dispatcher (`TokenEndpointHandler`) + `AbstractOAuth2HttpJsonEndpoint` base | done ([phase-5a-1.md](phase-5a-1.md)) |
| 5-E | **e2e contract lock (§E)** — the live-Restlet `/oauth2` error/redirect contract, recorded while the oracle still exists | done 2026-07-24 — re-run + byte-diff due at **5d-1c** |
| 5a-2 | The 9 simple JSON endpoints off the shared conversion template (split 2-way) | done ([phase-5a-2.md](phase-5a-2.md)) |
| 5-E2 | **§E `/authorize` contract lock** — the half 5-E did not cover | done 2026-07-26, 10 rows ([as-built](phase-5b-1-asbuilt.md#as-built-5-e2--recorded-2026-07-26)) |
| 5b-1 | `AuthorizeHandler` + the `AbstractOAuth2HttpBrowserEndpoint` base | done 2026-07-26 ([spec](phase-5b-1.md) · [as-built](phase-5b-1-asbuilt.md)) |
| 5b-2 | `device/user`, `connect/checkSession`, `connect/endSession` (split 3-way; gate **5-E3**) | done 2026-07-28 ([spec](phase-5b-2.md) · [as-built](phase-5b-2-asbuilt.md)) |
| 5c | `/oauth2/resource_set` + the conditional-request helper (split; gate **5-E4**) | done 2026-07-30 ([spec](phase-5c.md) · [as-built](phase-5c-asbuilt.md)) |
| 5d-1 | **the flip** — `OAuth2HttpRouteProvider` (18 attachments + audit matrix) + `META-INF/services` + the web.xml mapping move; Restlet left dormant behind a one-line revert **done 2026-08-05** — **5-E5** ✅ 2026-08-04 · **5d-1a** ✅ · **5d-1b** ✅ · **5d-1c** ✅ the flip, e2e 131 passed / 1 skipped / 0 failed, divergence rows 14–30 recorded ([spec](phase-5d-1.md) · [as-built](phase-5d-1-asbuilt.md)). Criteria 12–16 all green **and recorded** — 16 on 2026-08-06: CI run `31031060622`, 9/9 legs + `build-docker`, on the SHA the branch still carries ([record](phase-5d-1-asbuilt.md#criterion-16--ci-nine-legs--recorded-2026-08-06)). **criterion 17, the soak** ✅ 2026-08-06 ([record](phase-5d-1-asbuilt.md#criterion-17--the-soak--recorded-2026-08-06)) — 3 fresh-env full-suite runs with **zero flake**, both tripwires clear, a 90,689-request load probe clean, and the three coverage gaps closed with 21 new rows. It **found one regression the byte-diff missed** — confidential-client and resource-owner authentication broken in non-root realms on every path spelling — root-caused, fixed, and guarded; details in the record. ⚠ The fix is **not yet in CI**: criterion 16 covers the flip commit, not it |
| 5d-2 | **the deletion** — the Restlet OAuth2 stack + `ForgeRockRest` + Guice unbinds + the core de-leak | **planned 2026-08-06, split four ways / five commits** ([spec](phase-5d-2.md) · [research](phase-5d-2-research.md)); **5d-2a reviewed 2026-08-06** and split again into **5d-2a-i** (build the CHF route dormant) + **5d-2a-ii** (flip `web.xml`, delete the Restlet classes), with four corrections recorded in [research §1 review](phase-5d-2-research.md#1-review): **5d-2a** WebFinger → CHF (pulled forward from phase 6 — it holds twelve classes hostage), **5d-2b** the openam-oauth2 stack, **5d-2c** the openam-rest layer, **5d-2d** the core de-leak + exit gates. The soak's fix **is** committed and pushed (`83f465452b` on `upstream`); its CI run `31105613611` is the gate on 5d-2b's first `git rm`. ⚠ Two of [§ Handed to 5d-2](phase-5d-1-asbuilt.md#handed-to-5d-2)'s five traps are **out of date** — see [research §5](phase-5d-2-research.md#5) and [§2](phase-5d-2-research.md#2) |
| 6 | ~~WebFinger~~ + stragglers | **WebFinger moved to [5d-2a](phase-5d-2.md#d1)** 2026-08-06 — it cannot be deferred, because `WebFinger` + `OpenIDConnectDiscovery` import twelve of the classes 5d-2 exists to delete ([research §1](phase-5d-2-research.md#1)). The stragglers (vestigial imports, `Saml2BearerServerResource`) also fold into 5d-2b/d, so **phase 6 is fully absorbed**. ⚠ Its finding stands as originally written: **every** request to `/.well-known/webfinger` 500s (`web.xml` mounts the application on **upstream** `org.restlet.ext.servlet.ServerServlet`, so OpenAM's `ServletUtils.getRequest(...)` returns `null` and `getRootURL(null)` NPEs). A 2026-08-06 review briefly narrowed this to the success path, holding the 400s/404 out as parity targets; **the [pre-flip capture](artefacts/well-known-probes-pre-flip.md) refuted that the same day** — the NPE precedes `discover(...)`, so those validation paths have never executed. [Rows 33–36](#expected-divergences-at-the-flip) carry the measured shapes |
| 7 | Outbound scripting HTTP client | pending |
| 8 | Delete openam-restlet + vendored fork + pom sweep | pending |

---

## Phase 2 — XACML `/xacml` → CHF

Detailed execution plan: [phase-2-xacml.md](phase-2-xacml.md). Integration-test plan:
[phase-2-integration-tests.md](phase-2-integration-tests.md) — the route wiring shipped with unit
coverage only; the Cargo IT that phase-2 named as its guard only drives the installer UI.

No `OAuth2Request` coupling; the existing CHF→Restlet bridge for CAF auth
(`RestEndpointServlet.RestletAuthnHttpApplication`) already proves the filter chain.

**New (openam-entitlements):**
- `org.forgerock.openam.xacml.v3.rest.XacmlServiceHandler` — `@Get` export / `@Post`
  import via `Endpoints.from`; business logic moved from `XacmlService`. Realm from
  `RealmContext` (replaces `RestletRealmRouter.getRealmFromRequest`); authenticated
  caller from `AttributesContext` key `org.forgerock.authentication.context` (no more
  servlet-attribute copying); query params (`filter` multi-valued, `dryrun`) from
  `Form.fromRequestQuery`; export response sets
  `Content-Type: application/xacml+xml; version=3.0` and
  `Content-Disposition: attachment; filename=<realm>-realm-policies.xml`.
- `org.forgerock.openam.xacml.v3.rest.XacmlXmlErrorFilter` — CHF `Filter` replacing
  `XMLRestStatusService`; renders ResourceException as XML via existing
  `XMLResourceExceptionHandler.asXMLDOM` (openam-rest).
- `org.forgerock.openam.entitlement.rest.XacmlHttpRouteProvider` +
  `src/main/resources/META-INF/services/org.forgerock.openam.http.HttpRouteProvider` —
  `newHttpRoute(STARTS_WITH, "xacml", ...)`; chain mirrors `/json`:
  `@Named("AuthenticationFilter")` → realm routing
  (`RealmRoutingFactory.createRouter`/`createHostnameFilter` + `RealmContextFilter`) →
  `requestResourceApiVersionMatcher(version(1))` on `policies` → error filter → handler.
  Register `"policies"` into `@Named("InvalidRealmNames")` as today.

**Modified:** web.xml (`/xacml/*` → `OpenAM`); `RestEndpointServlet` (drop xacml branch,
`RestletAuthnHttpApplication`, `RestletHandler`, `HttpServletWrapper`);
`EntitlementRestGuiceModule` (drop `XacmlRouter` binding).
**Deleted:** `XacmlService`, `XacmlRouterProvider`, `XACMLServiceEndpointApplication`,
`XMLRestStatusService`.
**Tests:** port `XacmlServiceTest` (permission checks at
`checkPermission(DelegationPermission, SSOToken, String)` granularity survive unchanged;
export/import tests use constructed CHF Request + context chain).
**Verify:** `mvn -pl openam-entitlements,openam-rest test`; Cargo IT; smoke:
`GET /openam/xacml/policies` (admin cookie → 200 XACML XML + Content-Disposition; no
cookie → CAF 401), `GET /openam/xacml/realms/root/policies`, POST import round-trip,
`?filter=` query.

## Phase 3 — `OAuth2Request` dual-transport re-plumb + shared infra (no route flips)

Makes the OAuth2 core transport-neutral while both transports coexist, so UMA/OAuth2
migrate incrementally afterwards. Reuse the CHF target-stack patterns (HttpRouteProvider SPI,
`Endpoints.from` semantics, realm routing, filter ordering, error-map rewriting, test scaffolding)
captured in [chf-patterns.md](chf-patterns.md) during Phase 2 — every phase below builds on it.

> **Sizing (2026-07-09): Phase 3 is ~3–4 PRs, not one — recommend splitting into
> sub-phases 3a–3d, each a shippable commit with its own detailed plan doc.** Coupling
> map, verified CHF facts (servlet req/resp on `AttributesContext`), the full accessor
> list, the `Request.getCurrent()` thread-local leak (missing from the bullets below), and
> the split rationale are in [phase-3-research.md](phase-3-research.md). Author the 3a–3d
> detailed plans from that research; the bullets below are the tracker-level outline.
> Detailed 3a plan: [phase-3a-oauth2request.md](phase-3a-oauth2request.md).

**3a. `OAuth2Request` (openam-oauth2, `org.forgerock.oauth2.core`)**
- Make abstract; transport-neutral API (`getParameter`, `getParameterNames`,
  `getParameterCount`, `getBody`, tokens, session, locale, client registration,
  `getEndpointType`) plus new accessors replacing direct `getRequest()` grubbing:
  `getHttpServletRequest()` (used by `ResourceOwnerSessionValidator`,
  `StatefulTokenStore` cookie extraction, `OpenAMClientRegistrationStore`, baseURL),
  `getBasicAuthCredentials()` + `getAuthorizationBearerToken()` (single Authorization
  header parse, replaces `ChallengeResponse`), `getAcceptedLanguages()`.
- `RestletOAuth2Request` — temporary subclass with the current implementation verbatim.
- `ChfOAuth2Request` — wraps `Context` + `org.forgerock.http.protocol.Request`.
  **Exact parameter precedence preserved**: (1) internal attribute map seeded from
  `RealmContext.getRealm().asPath()` + accumulated
  `UriRouterContext.getUriTemplateVariables()` (covers `realm`, `rsid`), writable by
  handlers; (2) query via `Form.fromRequestQuery`; (3) POST form body; (4) POST JSON
  body — form/JSON parsed once from the buffered entity and instance-cached (reproduces
  Restlet's entity-reset re-readability). `getParameterCount` = **query-string
  duplicates only** (`DuplicateRequestParameterValidator` contract). Locale from
  `Accept-Language` (matches `HttpServletRequest.getLocale()` semantics).
  `getEndpointType()` from the post-realm-routing remaining URI → `EndpointType.get`.
- `OAuth2RequestFactory`: add `create(Context, Request)`; per-request cache moves to
  `AttributesContext` under the same `OAUTH2_REQ_ATTR` key. (Settled in the 3a plan: **no**
  servlet-attribute mirroring — web.xml maps each path to exactly one servlet. And
  `create(Request)` keeps resolving the client registration via `httpRequest.getParameter`;
  only the CHF overload uses the neutral accessor.)

**3b. Transport-neutral collaborators (openam-oauth2).** Detailed execution plan:
[phase-3b-collaborators.md](phase-3b-collaborators.md).
- New `Header/FormBody/QueryParameter AccessTokenVerifier` (pure `OAuth2Request` API) in
  `org.forgerock.oauth2.core`; rebind in `OAuth2GuiceModule` (~180–183, ~314/319–335);
  delete the three `Restlet*AccessTokenVerifier`s. Needs three new neutral accessors —
  `getAuthorizationBearerToken()`, `getQueryParameter(name)`, `getFormParameter(name)` —
  because the header/form/query **token-location distinction is load-bearing** (userinfo =
  header+form, tokeninfo = header+query) and must not collapse to a merged `getParameter`.
- `ClientCredentialsReader`: **already migrated in the 3a commit** (`getBasicAuthCredentials()`
  + `getEndpointType() == TOKEN_ENDPOINT`) — 3b only back-fills its missing test coverage.
- `OAuth2Utils` (**`org.forgerock.openam.oauth2.OAuth2Utils`**, not `oauth2.core`): delete the
  Restlet half (`getRealm(Request)`, `getRealm(HttpServletRequest)`, `getLocale(Request)`,
  `getRequestParameter`/`getRequestParameters`/`getParameters`, `ParameterLocation`,
  `getRedirector`); keep string helpers, `getDeploymentURL(HttpServletRequest)`,
  `getConfirmationKey`.
- **Pulled forward** (both small, behaviour-neutral on the live path): (a)
  `OAuthProblemException` — strip its dead, always-`null` Restlet-request plumbing
  (`handle(Request*)`, the `Request` ctor branch, `pushException`/`popException`/`getErrorForm`/
  `getErrorMessage`) to unblock the full `OAuth2Utils` clear; keeps `extends ResourceException`
  + `Status` for Phase 5. (b) `OpenAMClientAuthenticationFailureFactory.hasAuthorizationHeader`
  → `getBasicAuthCredentials() != null`, so `ClientCredentialsReader`'s failure path is neutral
  end-to-end (de-risks the Phase 5 CHF token endpoint).

**3c. Response/HTML/exception layer (new package `org.openidentityplatform.openam.oauth2.http`)**

> **Split into two commits (2026-07-17).** Detailed plans:
> [phase-3c-1-renderer.md](phase-3c-1-renderer.md) → [phase-3c-2-error-layer.md](phase-3c-2-error-layer.md)
> (3c-2 depends on 3c-1: the error factory's HTML branch renders `page/error.ftl`). **5 new classes**,
> not 3. Both sub-phases are purely additive — wired to no route until Phase 5 — so they carry **no
> live guard**; the golden 3-way oracle ([chf-patterns.md](chf-patterns.md) §13) is the substitute.

- **3c-1 — `FreemarkerTemplateRenderer`** — direct FreeMarker 2.3.31 (already a *direct* dep of
  openam-oauth2; **no pom change**); `@Singleton` `Configuration` pinned to `VERSION_2_3_0` +
  `ClassTemplateLoader` **only** (the `clap:///` loader is dead at runtime), same
  `templates/{display}/{name}.ftl` resolution incl. popup composition (`authorize.ftl`
  embedded as `htmlCode` in `popup.ftl`) and `FormPostResponse.ftl`; renders to CHF
  `Response` with `Content-Type: text/html; charset=UTF-8` (implicit today via Restlet's
  `CharacterRepresentation` — **must be explicit**, and the body must be set as
  `getBytes(UTF_8)`, never `setEntity(String)`). The real port target is `TemplateFactory`,
  not `OAuth2Representation`.
- **3c-2 — `OAuth2Error`** (neutral carrier replacing `OAuth2RestletException`; a **value type, not a
  `Throwable`** — it is what an `@ExceptionHandler` method *builds*, while the thing handlers **throw** stays
  the existing `OAuth2Exception` hierarchy) + **`RedirectUris`** (shared fragment-vs-query
  composition, reused by Phase 5b's **success** path).
- **3c-2 — `OAuth2ErrorResponseFactory`** — replaces `ExceptionHandler`:
  (a) auth-required (307) → **301** `Location: <login url>`, no error params; (b) errors with
  `redirect_uri` → **302** with the error map in fragment (`UrlLocation.FRAGMENT`, **replaces**) or
  query (**appends**); (c) JSON `{error, error_description, state?}` with the exception's status; (d)
  rendered `page/error.ftl` for the authorize UI flow.
- **3c-2 — `OAuth2ErrorFilter`** — CHF `Filter` unifying the provider's **two** error shapes
  (OAuth2 `{error,…}` when handled; CREST `{code,…}` via `JSONRestStatusService` when not). It
  **cannot catch** — it rewrites responses, guarding on `Content-Type` before parsing so it cannot eat the
  HTML error page. *(Its fifth rule, synthesising a body for `Endpoints.from`'s empty 500, was deleted by
  [F1](openam-http-framework.md) — the framework now emits a body.)*

**3d. Audit** — detailed plan: [phase-3d-audit.md](phase-3d-audit.md).
- `OAuth2HttpAccessAuditFilter` / `UMAHttpAccessAuditFilter` (new pkg
  `org.openidentityplatform.openam.oauth2.audit`, openam-oauth2) — extend
  `AbstractHttpAccessAuditFilter` (openam-audit-core); port userId/trackingIds
  extraction from `OAuth2AbstractAccessAuditFilter` via 3a's neutral accessors; realm from
  `RealmContext`. **Constructed per-route with per-endpoint body auditors**, not as
  `Component`-MapBinder singletons (the auditor pair varies per endpoint — full matrix in the
  3d doc).
- `HttpBodyAuditor` — CHF replacement for `RestletBodyAuditor` over the buffered CHF `Entity`.
  `jsonAuditor` **collapses** Restlet's `jsonAuditor`+`jacksonAuditor` (one `Entity.getJson()`
  on CHF); `formAuditor` via `fromFormString` (not `fromRequestEntity` — charset trap);
  `noBodyAuditor` == null.
- **Two `openam-audit-core` fixes (we own it), each additive/behaviour-neutral for `/json`:**
  the CHF base carries **no** body detail and its outcome hooks lack the request/context —
  add context-bearing + detail hooks (delegating defaults, no existing subclass edited); and
  it audits **3xx as FAILED** (`isSuccessful()` = 2xx only) where Restlet audits 3xx as
  success — fix to `isClientError()||isServerError()` so OAuth2's 301/302 flows are not
  logged as failures at 5d. Separately, `AMAccessAuditEventBuilder.forRequest` leaks POST
  form fields into `queryParameters` (risk #13) — recommended fix in its own commit.

**Tests:** `ChfOAuth2RequestTest` (precedence matrix, body re-read stability,
per-method/media-type parameterNames, locale, endpoint type, ISO-8859-1 basic-auth
charset), `OAuth2ErrorResponseFactoryTest` (all modes, fragment vs query, exact
301/302/4xx), `FreemarkerTemplateRendererTest` (golden renders); port
`ClientCredentialsReaderTest`, `OAuth2RequestFactoryTest`. Existing Restlet-path tests
stay green.
**Verify:** `mvn -pl openam-oauth2 test`; `mvn install -DskipTests`.

## Phase 4 — UMA `/uma` → CHF

Detailed execution plan: [phase-4-uma.md](phase-4-uma.md). Atomic flip (like Phase 2 XACML — three
JSON endpoints, no HTML/redirect/3xx), split into **4a** (shared `ChfAccessTokenProtectionFilter`,
openam-oauth2, build-ahead, reused by Phase 5c) and **4b** (endpoints + flip, openam-uma). The
tracker-level outline below; the doc supersedes two of these bullets — see its "Deviation from plan.md".

- Re-base **in place** (names/packages kept, Restlet base → `Endpoints` annotations): `PermissionRequestEndpoint`
  (`@Post`, 201 + `{"ticket"}`), `AuthorizationRequestEndpoint` (`@Post`, 200 `{"rpt"}` / 403),
  `UmaWellKnownConfigurationEndpoint` (`@Get`, public).
- `UmaExceptionHandler` → a shared **`@ExceptionHandler`** (`UmaErrorResponseFactory` + `AbstractUmaHttpEndpoint`
  base), **not a filter** — a filter cannot recover the exception's status/error after the framework's CREST
  500 ([phase-4-uma.md](phase-4-uma.md) finding 2). Dispatch on the *actual* thrown exception, not `.getCause()`.
- New shared **`ChfAccessTokenProtectionFilter`** (openam-oauth2, 4a): Bearer via `getAuthorizationBearerToken()`
  → `tokenStore.readAccessToken` → scope check; on failure reproduce the Restlet **CREST** `{code,reason,message}`
  body (via the app `StatusFilter`/`JSONRestStatusService` today), **no** `WWW-Authenticate`, **no** OAuth2 `error`
  field ([phase-4-uma.md](phase-4-uma.md) findings 1, 3); stashes the `AccessToken` on the cached `OAuth2Request`.
- New `UmaHttpRouteProvider` + services file (openam-uma has none today); per-route chain (audit outermost,
  inside the realm router): `UMAHttpAccessAuditFilter(bodyAuditors)` → `ChfAccessTokenProtectionFilter(scope)` →
  `Endpoints.from(handler)`; realm routing as Phase 2 (the audit filter is the CHF `UMAHttpAccessAuditFilter`
  from 3d-2). **No `OAuth2ErrorFilter`** — UMA keeps CREST-shape
  framework/filter errors + UMA-shape endpoint errors ([phase-4-uma.md](phase-4-uma.md) D4).
- Modified: `UmaGuiceModule` (drop `UMARouter` + the two `Restlet @Named` endpoint providers), `UmaAuditLogger`
  (Restlet `Request` → `OAuth2Request`), web.xml (`/uma/*` → `OpenAM`), `RestEndpointServlet` (drop uma branch).
  Deleted: `UmaRouterProvider`, `UmaExceptionHandler`, `UMAServiceEndpointApplication`; Restlet `UMAAccessAuditFilter`
  deferred to Phase 8 (shares `OAuth2AbstractAccessAuditFilter`). Restlet `AccessTokenProtectionFilter` survives
  until Phase 5c (resource_set still uses it).
- Tests: port the endpoint + exception tests to constructed CHF requests/contexts; new `UmaRouterIT` (layer 2,
  in-process composition) pins both error shapes; e2e `/uma/.well-known` smoke now, full protected flow deferred
  to share Phase 5c resource_set fixtures.
- Verify: `mvn -o -pl openam-oauth2 test` + `install` (4a), then `mvn -o -pl openam-uma test`/`verify` + whole
  build `-am` (4b); Cargo boot; both-error-shape assertions in `UmaRouterIT` are the load-bearing guard.

## Phase 5 — OAuth2/OIDC `/oauth2` → CHF

> **Detailed umbrella plan (research + sizing + step sequence + verification + IT + risks):
> [phase-5-oauth2.md](phase-5-oauth2.md)** (2026-07-24, **reviewed + restructured into 7 iterative steps**; all
> factual/API/line claims verified against the tree). It supersedes the bullets below where they differ.
> Key deltas surfaced by the full code map: **(1)** the 3 `Restlet*AccessTokenVerifier` rebind is **already
> done** (3b) — no such class exists; **(2)** `/oauth2` framework/uncaught errors are **CREST via
> `JSONRestStatusService`** (not `OAuth2StatusService`, which is WebFinger-only → Phase 6) — that is what makes
> `OAuth2ErrorFilter` the right unifier; **(3)** the `TokenRequestHook`/`AuthorizeRequestHook` re-sign is a
> **coordination** problem (parallel CHF hook interfaces in 5a-1/5b-1, delete Restlet ones at **5d-2**), since
> the Restlet callers stay live until the flip; **(4)** `/oauth2/connect/checkSession` is served today by an
> **exact-mapped JSP** that out-ranks `/oauth2/*` — **decision locked: keep the JSP, mount `CheckSessionHandler`
> for realm-prefixed paths only**; **(5)** the phase is **7 steps** — 5a→**5a-1**(token)+**5a-2**(9 JSON),
> 5b→**5b-1**(`AuthorizeHandler` alone)+**5b-2**(3 browser endpoints), 5c, 5d→**5d-1**(flip, Restlet dormant,
> one-line revert)+**5d-2**(delete); two `@ExceptionHandler` bases (JSON + browser), not one; **(6)** the **§E
> e2e contract lock + golden/parity tests must be recorded against live Restlet before 5d-1** — the oracle
> expires at the flip (risk #20); **(7)** surface is **15 endpoints / 18 `router.attach()`** (resource_set ×3),
> not "16 routes". **Session decisions:** `Form.fromRequestEntity` charset trap → route around in handlers now,
> fix commons in parallel; two parity-preserved security debts deferred (unverified `id_token_hint` signature;
> 301→login redirect).

Sub-phases 5a–5c land as build-ahead commits while Restlet still serves `/oauth2`; the flip is **two commits** —
5d-1 moves the path prefix in web.xml (Restlet left dormant, one-line revert), 5d-2 deletes the dormant stack.

**5a. JSON endpoints** — handlers in `org.openidentityplatform.openam.oauth2.http` /
`org.openidentityplatform.openam.openidconnect.http`, each `Endpoints`-annotated, using
`OAuth2RequestFactory.create(context, request)` + `OAuth2ErrorFilter` + audit wrappers.
**Handler methods must return `Response`** and catch everything internally — a thrown exception
becomes an *empty* 500 ([chf-patterns.md](chf-patterns.md) §2), and a `String` return silently
encodes ISO-8859-1 (§6). `OAuth2Filter`'s "write an error entity then CONTINUE anyway" behaviour
(`:58-80`) must **not** be reproduced — return; do reproduce its
`Cache-Control: no-store` + `Pragma: no-cache`:
- `TokenEndpointHandler` (`/access_token`, POST-only): method/content-type validation
  (405 `method_not_allowed`; non-form → `invalid_request`), `grant_type` dispatch
  replacing `AccessTokenFlowFinder`/`OAuth2FlowFinder`/`TokenEndpointResource`/`ErrorResource`
  (grant handlers like `AccessTokenService`/`Saml2GrantTypeHandler` are already
  transport-free); `InvalidClientAuthZHeaderException` → 401 +
  `WWW-Authenticate: Basic realm="..."`. ⚠ The `TokenRequestHook` re-sign this listed was **already done**
  ([finding 1](phase-5d-1-research.md#1--the-hook-re-sign-is-already-done)) — the CHF halves exist alongside
  the Restlet ones, which 5d-2 deletes.
- Conversion template (worked example): `TokenInfoHandler` (`/tokeninfo`) — `@Get`
  method calls `tokenInfoService.getTokenInfo(req)` → 200 JSON +
  `Cache-Control: no-cache, no-store`; `OAuth2Exception` rethrown to the error filter.
- Also: `TokenIntrospectionHandler`, `TokenRevocationHandler`, `UserInfoHandler`
  (GET+POST, Bearer via verifier), `IdTokenInfoHandler`,
  `OpenIDConnectConfigurationHandler`, `JwkUriHandler`,
  `ConnectClientRegistrationHandler` (raw Bearer via `getAuthorizationBearerToken()`),
  `DeviceCodeHandler`.

**5b. HTML/redirect flow**
- `AuthorizeHandler` — port of `AuthorizeResource` + `AuthorizeEndpointFilter` +
  `ConsentRequiredResource`: consent page via `FreemarkerTemplateRenderer` (data model
  ported from `ConsentRequiredResource.getDataModel`: attributes+query merge, `target`,
  ESAPI encoding, CSRF via `CsrfProtection`, `baseUrl` via `BaseURLProviderFactory`,
  locales via `getAcceptedLanguages()`); success → 302 fragment/query per
  `AuthorizationToken.isFragment()`, or `FormPostResponse.ftl` for
  `response_mode=form_post`; all catches → `OAuth2ErrorResponseFactory` preserving
  state/redirect_uri/parameter-location. ⚠ The `AuthorizeRequestHook` re-sign this listed was **already done**
  ([finding 1](phase-5d-1-research.md#1--the-hook-re-sign-is-already-done)).
- `DeviceCodeVerificationHandler` (`/device/user` — CodeVerificationForm/CodeThanks
  ftl + CSRF), `CheckSessionHandler` (checkSession.ftl iframe), `EndSessionHandler`
  (id_token_hint validation + **302** post_logout_redirect_uri with `state`).

**5c. resource_set**
- `ResourceSetRegistrationHandler` (POST/GET/PUT/DELETE; `rsid` from seeded template
  attribute) + CHF port of `ResourceSetRegistrationExceptionFilter`; guard with
  `ChfAccessTokenProtectionFilter(null scope)`; `OAuth2GuiceModule`
  `@Named(RSR_ENDPOINT)` re-typed `Restlet` → `Handler`. Delete Restlet
  `AccessTokenProtectionFilter`.

**5d. Flip**
- `OAuth2HttpRouteProvider` (`org.forgerock.openam.oauth2.rest`) —
  `newHttpRoute(STARTS_WITH, "oauth2", ...)`; realm routing as before; endpoint router
  registers the full table from `OAuth2RouterProvider` incl. per-route body-auditor
  combos and **all three** resource_set routes (`resource_set`, `resource_set/`,
  `resource_set/{rsid}` — trailing-slash is a distinct CHF route). Append to the
  existing openam-oauth2 `META-INF/services` file.
- web.xml: `/oauth2/*` → `OpenAM`; **delete the `ForgeRockRest` servlet + all mappings**
  (last path). Delete `RestEndpointServlet`, `RestletServiceServlet`,
  `ServiceEndpointApplication` + OAuth2 subclass, `RestStatusService`/`JSONRestStatusService`,
  `org.forgerock.oauth2.restlet.*`, `org.forgerock.openidconnect.restlet.*` (except
  `WebFinger`/`OpenIDConnectDiscovery` → Phase 6), `OAuth2RouterProvider`,
  `RestletOAuth2Request` + the restlet factory overload, Restlet OAuth2 audit filters
  (WebFinger's audit need moves to Phase 6). `OAuth2RestGuiceModule`: drop
  `OAuth2Router`.
- Tests: port the ~33 openam-oauth2 tests per sub-phase (`AuthorizeResourceTest` →
  `AuthorizeHandlerTest` asserting 302 Location fragment/query composition + rendered
  consent HTML; `ResourceSetRegistrationEndpointTest` → CHF). Golden-parity tests for
  top error shapes against recorded Restlet responses.
- Verify: `mvn -pl openam-oauth2,openam-oauth2-saml2,openam-uma test`;
  `mvn install -DskipTests` + Cargo IT; smoke matrix: client_credentials /
  authorization_code / refresh / device flows, browser consent grant+deny, form_post,
  realm styles (`?realm=`, `/realms/root/`, legacy `/oauth2/subrealm/`),
  introspect/tokeninfo/revoke, dynamic client registration, jwk_uri, checkSession,
  endSession redirect.

### Expected divergences at the flip

The §E and §E2 e2e specs are re-run and byte-diffed after 5d-1, and the live-Restlet oracle **dies at the flip**
(risk #20) — so a difference found then can no longer be checked against the producer. Everything below was
decided deliberately, with the evidence recorded at the time. **A diff that matches one of these rows is
expected; a diff that does not is a regression.**

From **5b-1** (`/authorize`), all detailed in [phase-5b-1.md](phase-5b-1.md):

| # | What differs | Restlet | CHF | Why |
|---|---|---|---|---|
| 1 | `IllegalArgumentException` on `/authorize` — **and, from 5b-2b, on `/device/user`** | `/authorize`: GET **redirected** to the raw `redirect_uri` (unless the message mentioned `client_id`); POST gave a 400 `server_error` page. `/device/user`: the **same three answers** — `DeviceCodeVerificationResource:186-193` redirects to the raw `redirect_uri` unless the message names `client_id`, while an IAE from `?display=` is raised inside the sibling `catch (ResourceOwnerConsentRequired)` and so reaches `doCatch` as a 400 `server_error` page | one non-redirecting **400 `invalid_request` page**, both verbs, both endpoints | [D7](phase-5b-1.md#d7) — the safe union. Closes an open redirect: a request that failed parameter validation never had its `redirect_uri` checked against the client's registered set. ⚠ The generalisation is **structural**: D7 lives on `AbstractOAuth2HttpBrowserEndpoint`, so it applies to every browser endpoint this migration ports, not to `/authorize` alone. 5b-2's [finding 7](phase-5b-2-research.md#7-the-device-verify-control-flow-branch-by-branch) predicted this and asked for it here rather than as a new row. ⚠ **The Restlet column is corrected 2026-08-06 by the soak:** a GET carrying `?display=bogus` — an IAE whose message does **not** mention `client_id`, i.e. the case this row says was redirected — measured as the **400 `server_error` page**, not a redirect. The CHF column is exactly as stated; only the incumbent's behaviour was described too broadly |
| 2 | `oidcLoginHint` on a first authorize carrying `login_hint` | one `Set-Cookie` (the set), retracted in-process on success | **two** `Set-Cookie` headers — the set, then the expiry | [D6](phase-5b-1.md#d6) — a servlet response has no cookie-removal API. Both go on the wire, the browser applies them in order, and ends with no cookie. Guarding on the incoming cookie instead would leave it **set** after a first authorize (5-E2 row 9b) |
| 3 | Unsupported verb (`PUT`) body — **narrowed 2026-07-28** | 405 `method_not_allowed` + `"Required Method: GET or POST found: PUT"` | 405 `method_not_allowed` + `"Method Not Allowed"` | [D8](phase-5b-1.md#d8) — the framework's 405, body rewritten by `OAuth2ErrorFilter`. **Status and cache headers already matched** (`OAuth2NoCacheFilter` restored the `no-store`/`Pragma` per-method stamping could not reach); the 5b-2 review then added [D10](phase-5b-2.md#d10), so the `error` field matches too and **only `error_description` still differs**. Verify D10 has landed before diffing this row |
| 4 | `login_hint` that is not an RFC 6265 `cookie-octet` string | wrote the malformed header itself | **writes no cookie**, logs the skip at debug | Identical bytes for every value Restlet could legally send; avoids a container-dependent 500 (Tomcat's `Rfc6265CookieProcessor` throws while generating the header, outside any handler's reach) |
| 5 | `Accept-Language` with a malformed `q` (`en;q=bogus`) | **throws** — a 500 for a header the client controls | ignores the parameter, returns `["en"]` | The `q` only ever fed an ordering Restlet does not apply ([as-built S4](phase-5b-1-asbuilt.md#as-built-s4)) |
| 6 | `Content-Type: APPLICATION/X-WWW-FORM-URLENCODED` | **400** — `MediaType.equals` compares names case-sensitively | accepted | RFC 7231 §3.1.1.1 says it is legal. A widening: it can only turn a Restlet 400 into a success, never the reverse. Pinned by `RestletContentTypeParityTest` |
| 7 | A hook throwing **after** the authorization is issued | `doCatch` → HTML `server_error` page | framework CREST-JSON 500 | Recorded, not fixed — [why](phase-5b-1-asbuilt.md#div-hook-throw). If the soak produces a CREST-JSON body from `/authorize`, start there |

⚠ **Not a divergence, do not "fix" it during the flip:** `templates/touch/authorize.ftl:56` emits `isplayName`
where `page/` and `popup/` emit `displayName`, so `?display=touch` renders a blank client name in the consent
`<h1>`. A pre-existing product bug, reproduced verbatim because changing it changes the wire; it belongs in its
own change.

From **5a-2**: `/tokeninfo` sends `Content-Type: application/json` with **no charset** (cache-header oracle,
2026-07-24), and `connect/register` answers **405** to `DELETE registration_client_uri` — a dynamically
registered client cannot deregister itself. Both are reproduced deliberately; see the 5a-2 row above.

From **5b-2a** ([D10](phase-5b-2.md#d10)), and it applies to **every `/oauth2` route `OAuth2Filter` did not
wrap** — which is all of them except `/authorize` and `/access_token`:

| # | What differs | Restlet | CHF | Why |
|---|---|---|---|---|
| 8 | Unsupported-verb body on a **non-`OAuth2Filter`** route — `device/user`, `connect/checkSession`, `connect/endSession`, `connect/register`'s `DELETE`, `tokeninfo`, `introspect`, `userinfo`. ⚠ **`resource_set` was listed here and is not one of them** — corrected 2026-07-29 by [5-E4 row 11](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29), which measured its 405 as **`{"error":"unsupported_method_type"}`** with `Allow: POST, PUT, GET, DELETE`, emitted by `ResourceSetRegistrationExceptionFilter`'s own 405 branch before the CREST `StatusService` is reached. That is a **third** 405 shape under `/oauth2` and it needs its own divergence line, not this one | 405 **CREST** `{"code":405,"reason":"Method Not Allowed","message":"The method specified in the request is not allowed for the resource identified by the request URI"}` — **no `error` field at all** (pinned for the first three by [5-E3 row 11](phase-5b-2-asbuilt.md#as-built-5-e3--recorded-2026-07-28)) | 405 **OAuth2** `{"error":"method_not_allowed","error_description":"Method Not Allowed"}` | The **shape** change comes from mounting `OAuth2ErrorFilter` across the application at all — not from D10, which only chooses the value inside the new shape. Before D10 the same routes would have said `invalid_request`, equally non-CREST and equally undefined by RFC 6749 for a 405. `errorFor` has **no route scope** and deliberately so: a client parsing `/oauth2` errors gets one shape everywhere, which is the filter's whole purpose |

⚠ Row 8 is a **widening in shape, not a regression**. It is here because the table's rule is that an unmatched
diff must be treated as one — without this row, the 5d-1 operator diffing `PUT /oauth2/connect/endSession` would
correctly follow the rule and revert D10.

| # | What differs | Restlet | CHF | Why |
|---|---|---|---|---|
| 9 | A `/` inside a redirect **parameter value** — `state`, `error_description`. **Applies to `/authorize`'s error redirect as well**, not just endSession | `?state=a%2Fb` — `Reference` percent-encodes it | `?state=a/b` — `Form.toQueryString` leaves it bare | Found while porting endSession (5b-2a), confirmed against the **real Restlet** by `RestletErrorParityTest#aSlashInsideAValueIsEncodedByRestletAndNotByChf`. Both are legal and parse identically — RFC 3986 §3.4 puts `/` in the `query` production — so no client can observe it. Recorded rather than fixed, on [D8](phase-5b-2.md#d8)'s own instruction: `RedirectUris` is shared with `/authorize`, so bending the encoder would change bytes on a committed endpoint to buy nothing. ⚠ **`+`, space, `&`, `=` and non-ASCII all still match exactly** — only `/` differs, and only inside a value. ⚠ **Corrected 2026-08-06 by the soak:** `:` differs too — the `iss` of an `/authorize` success redirect is `http%3A%2F%2F…` on Restlet and bare `http://…` on CHF. Same encoder pair, same "no client can observe it" argument; the claim that `/` was the only character was simply narrower than the evidence |

⚠ Row 9 corrects a claim [D8](phase-5b-2.md#d8) made: *"the percent-encoding parity between the two was proven
and closed at 3c-2."* It was proven for the characters that test's fixture happened to contain (`a b&c=d+e`)
and no others. The parity harness was right; its input was incomplete.

| # | What differs | Restlet | CHF | Why |
|---|---|---|---|---|
| 10 | `state` in the **error body** of `connect/endSession` and `connect/checkSession` when the request carried one | **absent** — verified live 2026-07-28: `GET /oauth2/connect/endSession?state=abc123` answers exactly the body it answers without the parameter. Both Restlet resources build `new OAuth2RestletException(status, error, message, null)` (`EndSession:106`), and the 2-arg `ExceptionHandler.handle` fallback also passes `null`, so `asMap()` never carries it | `{"error":…,"error_description":…,"state":"abc123"}` | `AbstractOAuth2HttpJsonEndpoint.onError:53` does `OAuth2Error.of(e).withState(o2.getParameter("state"))` for **every** JSON endpoint. Not fixable per-endpoint: an override would drop the `@ExceptionHandler` annotation ([D1](phase-5b-2.md#d1)), and changing the shared base would move the five committed 5a handlers. **Additive** — a client reading `error`/`error_description` is unaffected, and `state` echo is what RFC 6749 §4.1.2.1 asks for anyway |

⚠ Row 10 is **not** specific to 5b-2a: the base has behaved this way since 5a-2, so it applies to every CHF
JSON endpoint. 5b-2a is merely the first step whose Restlet counterpart demonstrably passed `null`, which is
what made it observable. Worth a deliberate look at 5d-1 across all of them rather than only these two.

**Phase-5-wide, found reviewing 5c-2 (2026-07-30) and applying to every endpoint already ported:**

| # | What differs | Restlet | CHF | Why |
|---|---|---|---|---|
| 11 | ~~**Every `Content-Type` that carries a charset gains a space after the `;`**~~ — ⚠ **WITHDRAWN at 5d-1c: it never happened on the wire** | `text/html;charset=UTF-8`, `application/json;charset=UTF-8` — **no space**, measured and explicitly flagged at [5-E2 row 2](phase-5b-1.md) | **the same bytes, no space** — measured post-flip 2026-08-05 | **The row confused the in-memory view with the socket.** commons `ContentTypeHeader.getValues()` does build `sb.append("; charset=")`, so `getFirst("Content-Type")` in a unit test really does return the spaced form — but that renderer only runs when something *reads the header back as a `ContentTypeHeader`*. `setEntity(Map)` → `setJson` writes the literal constant `application/json;charset=UTF-8`, and that is what reaches the client. The post-flip capture contains **no spaced Content-Type at all**: every one of the 26 logged values across both stacks is `application/json`, `application/json;charset=UTF-8` or `text/html;charset=UTF-8` ([artefacts/e2e-transcript-post-flip.txt](artefacts/e2e-transcript-post-flip.txt)). The rows this predicted would go red — 5-E2 rows 2/3/4, the 5-E3 device-page rows, 5-E4 row 7 — are **all green**. ⚠ The same false claim was copied into three in-code comments and is corrected in the 5d-1c commit; the unit rows that pin the spaced form are pinning `getFirst`, and are correct about *it* |

From **5c-2** (`/oauth2/resource_set`), detailed in [phase-5c.md](phase-5c.md):

| # | What differs | Restlet | CHF | Why |
|---|---|---|---|---|
| 12 | An error status ≥ 400 reaching the resource_set error producer with **no throwable attached** | `ResourceSetRegistrationExceptionFilter.setExceptionResponse` **NPEs** — the client gets whatever the engine makes of a crash | a clean **500** `{"error":"server_error","error_description":"<message, or null>"}` | [D3](phase-5c.md#d3)'s third row. Deliberately **not** reproduced: the branch was reached with a null throwable and crashed, so "what it did" is not a contract — the port answers the shape the branch was *written* to answer. Recorded as [T7](#post-migration-tickets--raised-by-the-port-deliberately-not-fixed-in-it), which this closes. ⚠ Expect **no** byte-diff to show it: no 5-E4 row reaches the branch, which is why it is written down instead |
| 13 | **JSON key order in every 200/201 body** | `createJsonResponse` copies into a **`HashMap`**, so the wire order is hash order | insertion order — `LinkedHashMap` seeded from `asMap()`, then `_id`, then `user_access_policy_uri` | ⚠ **Derived from the two sources, not measured** — no 5-E4 row asserts key order, and none should: object member order is semantically meaningless in JSON (RFC 8259 §4) and no client may depend on it. Listed only so a *raw-byte* diff at the flip is not mistaken for a regression. Note the ETag is unaffected: it hashes `ResourceSetDescription`, never the response map |

⚠ **Two rows from 5c-2 itself, and only the first is behavioural.** Row 13 is byte-level formatting no
conformant client can observe as a behaviour change; it is here because the flip's check is a byte-diff and
this table is what tells a reader which diffs are expected. Row 11 above was found the same way and is the
larger one — it is Phase-5-wide and already in committed code ([review](phase-5c-asbuilt.md#s7-review-findings)).
Everywhere else it was tempted to improve things, the
port reproduces the incumbent instead: the lenient `org.json` parser ([T8](#post-migration-tickets--raised-by-the-port-deliberately-not-fixed-in-it)),
the `512`-derived 400 ([T5](#post-migration-tickets--raised-by-the-port-deliberately-not-fixed-in-it)), the
reason phrase in `error` ([T6](#post-migration-tickets--raised-by-the-port-deliberately-not-fixed-in-it)),
bare `application/json` on every other status, weak `W/"…"` ETag bytes, and the whole conditional-request
comparator including the rules that are RFC-wrong (`If-None-Match: *` → 200, positional strong-only wildcard).
Two of those comparator rules were *briefly* divergences introduced by 5c-1's own helper and were fixed to
match Restlet rather than recorded ([S1 review](phase-5c-asbuilt.md#-corrected-in-review-same-day--two-divergences-both-from-reading-the-parser-and-not-the-comparator)).
The two remaining resource_set differences — **`PATCH`** and the **vanishing `Allow` header** — are Phase-5-wide
verb-mapping questions owed at 5d-1, not 5c divergences; they get a row here only if 5d-1 decides to record
rather than fix them.

From **5d-1c** (the flip itself), detailed in [phase-5d-1.md](phase-5d-1.md) and measured in the
[as-built](phase-5d-1-asbuilt.md#as-built-5d-1c--recorded-2026-08-05):

⚠ **Every row below is MEASURED on both stacks** — Restlet from
[artefacts/e2e-transcript-pre-flip.txt](artefacts/e2e-transcript-pre-flip.txt) (image `openam-e2e:5d1b`,
2026-08-04/05), CHF from [artefacts/e2e-transcript-post-flip.txt](artefacts/e2e-transcript-post-flip.txt)
(image `openam-e2e:5d1c-v5`, 2026-08-05). Where a row is derived rather than observed it says so in its own
cell. The three **direction** words matter more than the bytes: *shape-only* means both stacks accept or both
reject and only the wire form moved; *narrowing* means CHF rejects what Restlet served; *widening* means CHF
serves what Restlet refused — and a widening is the only kind that can let a request through that used to be
stopped.

| # | What differs | Restlet | CHF | Why · direction |
|---|---|---|---|---|
| 14 | `PATCH /oauth2/resource_set/{rsid}` | routed to the `@Put` method: a working **full replace**, 200 + a new `ETag` ([5-E4 row 11](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29)) | **405** `{"error":"unsupported_method_type"}` + `Allow: DELETE, GET, POST, PUT`; the stored set is **unchanged** | [D4](phase-5d-1.md#d4) — aliasing `PATCH` to `PUT` in `Endpoints.from` would impose an RFC 5789-wrong full-replace `PATCH` on every CHF endpoint with a `@Put`. Scoped to `resource_set`: the only ported endpoint with one. **Narrowing** — the only row here where a *write* stops happening |
| 15 | Every unrouted `/oauth2` path, and `/oauth2/realms/<bogus>/…` | **two** shapes depending on segment count: `ROUTER_404` `{"code":404,"reason":"Not Found","message":"The server has not found anything matching the request URI"}` for one-element spellings, and `{"code":404,…,"message":"No mapping organization found for organization identifier: /connect"}` (etc.) for two-element ones, because Restlet's router ate the first element as a sub-realm. `/oauth2/realms/bogus/…`: `{"code":404,…,"message":"No mapping organization found for organization identifier: /bogus"}` — note the **leading slash**, where the `?realm=` spelling of the same failure (row 16) had none | **one** body everywhere — `{"error":"not_found","error_description":"Not Found"}` — and for `/realms/bogus/…` a different sentence, `{"error":"not_found","error_description":"Realm &quot;bogus&quot; not found"}`. ⚠ **Refined 2026-08-06 by the soak:** that is the **flat** spelling, which is all 5-E5 asked. The **nested** `/realms/root/realms/<bogus>/…` keeps the leading slash — `Realm &quot;/nosuchsub&quot; not found` — on CHF, where Restlet said `…identifier: /nosuchsub` on **both** spellings. Direction unchanged: both 404, shape-only | [D5](phase-5d-1.md#d5). **Status is preserved at 404; only the shape moves.** `RealmContextFilter` consumes a leading element only if it *resolves* as a realm and stops at the first that does not, so Restlet's per-segment messages have no counterpart. The `&quot;` is `ResourceException.toJsonValue` HTML-escaping — product-wide since 14.0, deliberately not un-escaped ([`OAuth2ErrorFilter.rewriteIfCrestError`](../../../openam-oauth2/src/main/java/org/openidentityplatform/openam/oauth2/http/OAuth2ErrorFilter.java)). **Shape-only** |
| 16 | `?realm=<bogus>` on any `/oauth2` path | **404**, `{"code":404,…,"message":"No mapping organization found for organization identifier: bogus"}` on a matched path; on an **unmatched** path the override was skipped entirely and the answer was `ROUTER_404` (`RestletRealmRouter:86` guarded on `next != delegateRoute`) | **400** `{"error":"invalid_request","error_description":"Invalid realm, bogus"}` — on matched and unmatched paths alike | `RealmContextFilter:253-256` runs **before** the router, so a bad override is now fatal everywhere rather than only where a route matched. Not worth "fixing" in a filter `/json` has depended on since 14.0. **Shape-only** by accept/reject, but the *scope of validation widened* — a client that branches on 404 sees a 400 |
| 17 | A request whose `Host` OpenAM does not know | **500** on all three URL styles: `{"code":500,"reason":"Internal Server Error","message":"No mapping organization found for organization identifier: not-a-real-host.invalid"}` | **400** on all three, from two different filters: default route `{"error":"invalid_request","error_description":"FQDN &quot;not-a-real-host.invalid&quot; is not valid."}`; `/realms/root/…` `{"error":"invalid_request","error_description":"Realm &quot;not-a-real-host.invalid&quot; not found"}` | `HostnameFilter` + `RealmContextFilter`. ⚠ [Finding 16](phase-5d-1-research.md#16--the-flip-adds-host-validation-to-oauth2-that-restlet-never-did) predicted `/oauth2/realms/root/…` still *worked* under an unknown Host; the pre-flip capture measured **500 for that style too**, which drops this from "can break a working deployment" to a status/shape change. **Shape-only** (both stacks reject) |
| 18 | `Content-Type` on JSON bodies rendered by CHF | `application/json` | `application/json;charset=UTF-8` — **no space** after the `;` | CHF's `setEntity(Map)` → `setJson` writes the charset; Restlet did not. Scope is narrower than it looks: `.well-known/openid-configuration` and `connect/jwk_uri` **already** sent the charset under Restlet, and `resource_set` still answers bare `application/json` on every status because four sites re-stamp it. ⚠ See the withdrawn **row 11** — the spaced form this was once predicted to take does not exist on the wire. **Shape-only** |
| 19 | The body of a 405/404 on any route Restlet's `OAuth2Filter` never wrapped — `connect/checkSession`, `connect/endSession`, `device/user`, `tokeninfo`, `connect/jwk_uri`, `resource_set/a/b` | CREST, with **no `error` field at all**: `{"code":405,"reason":"Method Not Allowed","message":"The method specified in the request is not allowed for the resource identified by the request URI"}` | `{"error":"method_not_allowed","error_description":"Method Not Allowed"}`; the 404 leg `{"error":"not_found","error_description":"Not Found"}`. `code`/`reason`/`message` are all gone | The shape change comes from mounting `OAuth2ErrorFilter` across the application at all — not from [D10](phase-5d-1.md#d10), which only chooses the *word* inside the new shape. One error vocabulary for the whole surface is the filter's purpose. ⚠ The Restlet `code`/`reason`/`message` **values** here were recorded in prose and logs; the pre-flip assertions pinned the status and the *absence* of `error`. **Shape-only** |
| 20 | The `error_description` of a 405 on `/access_token` and `/authorize` — the two endpoints Restlet's `OAuth2Filter` **did** wrap | names the verbs: `"Required Method: POST found: GET"`, `"Required Method: GET or POST found: PUT"`, … | the generic `"Method Not Allowed"` | `Endpoints.from`'s unmapped-verb fallback rejects before any handler runs and cannot name the verbs it wanted. `error` itself is unchanged (`method_not_allowed` on both stacks, [D10](phase-5d-1.md#d10)). ⚠ Post-flip the surface has **two** 405 bodies, not one: this and `resource_set`'s `{"error":"unsupported_method_type"}`. Restlet had three. **Shape-only** |
| 21 | An unmapped verb on `/tokeninfo` no longer runs the `@Get` first | Restlet resolved the representation before looking for a handler, so the GET's side effects reached the wire ahead of the 405: `PATCH` carried `Cache-Control: no-cache, no-store`, and an **unauthenticated** `PATCH` answered the GET's `401 invalid_token` | 405 with no cache directives; unauthenticated `PATCH` is **405**, never reaching the token check | The 405 is produced by the verb map before handler code runs. ⚠ PATCH-specific: `PUT /tokeninfo` carried no cache directives on **either** stack (measured), so only the verbs Restlet failed to resolve took the `@Get` path. **Narrowing** on the unauthenticated leg — the verb is rejected before authentication |
| 22 | `Content-Length` on a successful `HEAD` | **absent** | **present** — the GET's length, computed from the entity the container then strips (measured: `/tokeninfo` 213, `.well-known/openid-configuration` 1515, `connect/jwk_uri` 447, `resource_set` item 238) | ⚠ **INVERTED from the prediction.** [Finding 7](phase-5d-1-research.md#7--content-length-on-a-head-is-tomcats-decision) expected CHF to be the side that sent none. It is the container's decision, not the application's, and it changed with the stack. Asserted as *defined* rather than pinned: `/tokeninfo` carries `expires_in`, whose digit count shrinks as the token ages. **Shape-only** |
| 23 | An **erroring** `HEAD` | Restlet substituted an HTML status page: `text/html;charset=utf-8` (lowercase), with a `Content-Length` (721 on the `/tokeninfo` 401) | the JSON entity's own headers: `application/json;charset=UTF-8`, length 135 | Distinct from row 22 — here Restlet *did* send a length, but for a different document. The lowercase `utf-8` was Restlet's status-page renderer and is the only place it appeared; it is gone with the page. **Shape-only** |
| 24 | A `redirect_uri` **nested inside** `goto` (the login 301) or `formTarget` (the consent page) | the query verbatim as sent — doubly encoded on the wire: `redirect_uri%3Dhttp%253A%252F%252Fapp.invalid%252Fcb` | singly encoded: `redirect_uri%3Dhttp%3A%2F%2Fapp.invalid%2Fcb` | CHF rebuilds the request URI from the **decoded** form, so every value is re-encoded exactly once. ⚠ Functional consequence, not just bytes: the consent POST goes to the URL the *page* names, which is no longer byte-identical to the URL the GET was made with. **Shape-only** |
| 25 | `oidcLoginHint` on an `/authorize` **success** carrying a `login_hint` | with no prior cookie: **neither** header. With a prior cookie: **one** header, the delete — carrying neither `Path` nor `HttpOnly`, so it could not actually clear the `Path=/` cookie its own before-hook had set | **two** headers in both cases: `oidcLoginHint=demo; Path=/; HttpOnly` then `oidcLoginHint=; Expires=Thu, 01 Jan 1970 00:00:10 GMT; Path=/; HttpOnly` | The CHF port cannot retract a servlet cookie, so its `afterAuthorizeSuccess` emits the delete unconditionally when its before-hook set one. The **end state is the same** (no cookie left in the browser); the header count moved, and the delete going from unscoped to `Path=/; HttpOnly` is a *fix*. **Shape-only** |
| 26 | `?_api` on **any** `/oauth2` endpoint, authenticated or not | **200** with the endpoint's own answer — the parameter was ignored, byte-identical to the plain request | **501**, empty body, no `Content-Type` | commons `OpenApiRequestFilter` is mounted on the whole CHF application (`OpenAMHttpApplication:80`), shared with `/json` — whose descriptor **works** (a 5.8 MB Swagger). It answers 501 when the routed branch returns no descriptor, which the non-`Describable` `/oauth2` handlers do not. Scoping it off `/oauth2` would mean either moving `/json`'s bytes or stripping `_api` from a query `/authorize` echoes into `goto` (row 24) — recording it is the proportionate call. `?_crestapi` is unaffected. **Narrowing** — and it shadows token-bearing calls, not just discovery-shaped ones |
| 27 | `/oauth2/` — bare, trailing slash, nothing after | **404** `ROUTER_404`, like its three siblings `/oauth2`, `/oauth2/realms`, `/oauth2/realms/root` | **500**, empty body | commons `RouteMatchers.getRemainingRequestUri:164-170` sublists without a guard → `IllegalArgumentException: fromIndex(4) > toIndex(3)`. ⚠ **Not introduced by this flip and not fixable here**: `/json/` and `/uma/` have answered the same way for nine releases, and `RouteMatchers` is external commons. Pinned as measured so the byte-diff does not read it as new. **Shape-only** by accept/reject; the status class moved 4xx → 5xx |
| 28 | `Allow` on a 405 from `/access_token` and `/authorize` | **absent** — the RFC 7231 §6.5.5 gap [D4](phase-5d-1.md#d4) set out to close | `Allow: POST` and `Allow: GET, POST`, from `Endpoints.withAllow` (5d-1a), in the fixed order DELETE, GET, POST, PUT; HEAD excluded | ⚠ **Not "every 405"**: Restlet's framework-produced 405s already carried one — `PATCH /tokeninfo` measured `allow=GET` on both stacks, and `resource_set` measured the four-verb join pre-flip. Only these two endpoints gain it. **Shape-only** (a standards fix) |
| 29 | The `Server` response header | `Restlet-Framework/2.4.4` | **absent** — CHF stamps no banner | Recorded because the realm-prefixed `connect/checkSession` row used the banner as its stack discriminator; the assertion is kept as a tripwire, since a banner reappearing on either path would mean the servlet mapping regressed. **Shape-only** |
| 30 | Both of Restlet's method tunnels | `POST /oauth2/access_token?method=GET` → **405** `"Required Method: POST found: GET"`; `GET /oauth2/tokeninfo` + `X-HTTP-Method-Override: PUT` → **405** | `?method=GET` → **200, and it issues a real access token**; the override on a GET → **200**, the request runs as the GET it is | One root cause: Restlet's `TunnelService` (POST-only) has no CHF counterpart, and `Endpoints.getMethod` reads the header and nothing else, gated on `"POST".equals(method)`. ⚠ **WIDENING — the only one in this table.** CHF mints a token for a request Restlet refused. Both legs measured on both stacks; no plan row anticipated it, which is why it gets its own row and a release-note line |

#### Rows 31–34 — added by [phase 5d-2](phase-5d-2.md#divergence-rows-this-phase-adds-to-planmd)

⚠ **Different incumbent.** Restlet stopped serving `/oauth2` at 5d-1c, so for these three rows the
"before" column is the **post-flip CHF stack**, not Restlet. The table's rule is unchanged: a diff
matching a row is expected, a diff matching none is a regression.

| # | What differs | Before (post-flip CHF) | After (5d-2) | Why · direction |
|---|---|---|---|---|
| 31 | Errors raised as `OAuthProblemException` — token-store failures, client-registration attribute reads, id_token signing | framework CREST 500 `{code,reason,message}` | OAuth2 `{error,error_description}` carrying the exception's own status | [D5](phase-5d-2.md#d5) — the exception loses its Restlet supertype and gains an `@ExceptionHandler`. Same unifying argument as row 19. **Shape-only** (both stacks reject) |
| 32 | Password-grant internal failures (`ResourceOwnerAuthenticator:127,145,150`) | framework CREST 500 | OAuth2 `{"error":"server_error"}` | [D6](phase-5d-2.md#d6) — the raw Restlet `ResourceException` was an artefact of the transport, never a contract. **Shape-only** |
| 33 | `/.well-known/webfinger`, **every routed request** — the success JRD *and* the missing-`resource`, missing/wrong-`rel` and unknown-user paths | **500**, `{"error":"Internal Server Error"}`, 149 B, on all of them | 200 JRD naming the issuer; 400 `bad_request`; 404 `not_found` | [D1](phase-5d-2.md#d1)/[D2](phase-5d-2.md#d2) — a pre-existing defect fixed by construction; `e2e/oauth2/webfinger-test.spec.mjs` already asserts the target. **Widening**, and the phase's one intentional user-visible fix. ⚠ **Rewritten 2026-08-06** from the [capture](artefacts/well-known-probes-pre-flip.md): the draft scoped this to the success path and held the 400s/404 out as parity targets. They were never reachable — `getRootURL(null)` NPEs before `discover(...)` runs |
| 34 | `/.well-known` **no-match** — unrouted children (`/nonsense`, `/a/b/c`, `/webfinger/extra`), a realm-spelled path, context-root `/openid-configuration`, bare `/.well-known`(`/`) | **500** (149 B) for anything with a path element — Restlet's `attach("/webfinger",…)` matched far more than its literal path; **404 `OAuth2StatusService`** for the two bare spellings only | `OAuth2NotFoundHandler`: `{"error":"not_found","error_description":"Not Found"}` | [D1](phase-5d-2.md#d1) — the status service is one of the twelve classes 5d-2b deletes, so the shape cannot survive; `not_found` is what the rest of the migrated surface emits. **Narrowing + shape** |
| 35 | `/.well-known/webfinger?realm=<unresolvable>` | **404**, `{"error":"Not Found","error_description":"Realm \"/bogus\" not found"}` | 400, OAuth2-shaped | [D1](phase-5d-2.md#d1) — `RealmContextFilter` raises `BadRequestException`, never a 404 ([chf-patterns §23](chf-patterns.md#23-route-provider-mechanics--when-handlers-are-built-and-what-a-no-match-answers-phase-5d-1)). Buys one realm-error shape across the migrated surface. **Status + shape** |
| 36 | `POST /.well-known/webfinger` | **500** (149 B) — Restlet dispatched `POST` into the `@Get` resource | 405 + `Allow` | [D1](phase-5d-2.md#d1) — `Endpoints` refuses an unmapped method; RFC 7033 defines `GET` only. **Shape-only** (both stacks reject) |

### Post-migration tickets — raised by the port, deliberately not fixed in it

Bugs the migration **reproduces faithfully** because it is a parity migration, each with a live-Restlet
observation and a pinning test that must be changed deliberately when the fix lands. Not tracked in an issue
tracker on purpose: they have to survive the deletion of the Restlet oracle at 5d-2, and this document is what
outlives it.

| # | Ticket | Reproduced by | Details |
|---|---|---|---|
| T1 | **`CheckSession.getClientSessionURI` throws on its own happy path.** A default-configured client — the admin API leaves `clientSessionURI` **empty on every client it creates** — makes check-session **400** as soon as an RP supplies an `id_token`. ⚠ The fix must cover **both** the `NoSuchElementException` (empty set, the common case) and the `NullPointerException` (null registration, the rarer one); a guard for only the latter repairs the wrong half | `CheckSessionHandler` (5b-2a), as 400 `server_error` | [phase-5-oauth2.md](phase-5-oauth2.md#post-migration-ticket-filed-by-5b-2a-checklist-step-9--checksessiongetclientsessionuri-throws-on-its-own-happy-path) — both triggers tabled with the four tests that pin them (5-E3 rows 6d/6e + two `CheckSessionHandlerTest` rows) |
| T2 | **Unverified `id_token_hint` signature on `/connect/endSession`** — the client is chosen from the `azp` claim of a JWT nobody verifies | `EndSessionHandler` (5b-2a) | [security-debt list](phase-5-oauth2.md#parity-preserved-security-debts--reproduce-now-fix-later-finding-7); pinned by `EndSessionHandlerTest#theAzpClaimSelectsTheClientAndNoSignatureIsVerified` |
| T3 | **301 (permanent, cacheable) login redirect** on unauthenticated `/authorize`, where a 302 would be correct | `AuthorizeHandler` (5b-1) | [security-debt list](phase-5-oauth2.md#parity-preserved-security-debts--reproduce-now-fix-later-finding-7) |
| T4 | **`templates/touch/authorize.ftl:56` emits `isplayName`**, so `?display=touch` renders a blank client name in the consent `<h1>` | golden, verbatim | Noted under the divergence table above — **not** a divergence; do not "fix" it during the flip |
| T5 | **The missing-`If-Match` rejection is a 400 `server_error`**, not a 412/428, and it is built by throwing a status the code never uses (`512`) — semantically wrong on the wire and confusing in the source | `ResourceSetRegistrationHandler` (5c-2), per [D4](phase-5c.md#d4) | [phase-5c.md](phase-5c.md#post-migration-tickets); pinned by 5-E4 rows 4/6 and the unit rows for D4 |
| T6 | **The duplicate-name rejection puts a reason phrase in the `error` field** — `{"error":"Bad Request"}`, where every other error on this endpoint uses a snake_case code | `ResourceSetRegistrationHandler` (5c-2), per [D8](phase-5c.md#d8) | [phase-5c.md](phase-5c.md#post-migration-tickets) |
| T7 | **`ResourceSetRegistrationExceptionFilter.setExceptionResponse` NPEs on a throwable-less error status** — a latent 500 on the live Restlet endpoint | **closed** by [D3](phase-5c.md#d3); the class dies at 5d-2 | [phase-5c.md](phase-5c.md#post-migration-tickets) — recorded so the CHF replacement's differing behaviour reads as a fix, not drift |
| T8 | **`/oauth2/resource_set` parses request bodies with `org.json`, which is lenient** — it decides **five** wire outcomes, so swapping in Jackson is a behaviour change and not a cleanup. ⚠ Two unit rows and 5-E4 row 22 are the executable statement of what T8 changes: **edit them with the ticket, never relax them to make it pass** | `ResourceSetRegistrationHandler` (5c-2), deliberately | [phase-5c.md](phase-5c.md#t8) — full before/after table, incl. duplicate-key and key-order effects |

## Phase 6 — ~~WebFinger + stragglers~~ **absorbed into 5d-2** (2026-08-06)

Every bullet this phase carried now has an owner inside [phase 5d-2](phase-5d-2.md), because none of
them could wait: `WebFinger` and `OpenIDConnectDiscovery` import twelve of the classes 5d-2 deletes
([research §1](phase-5d-2-research.md#1)), so deferring them would leave all three Restlet packages
non-empty and the exit gate unreachable.

| Was | Now |
|---|---|
| `WebFingerHandler` + `WellKnownHttpRouteProvider`, web.xml `/.well-known/*` → `OpenAM` | **5d-2a-i** (the handler + provider) and **5d-2a-ii** (the mapping) ([D1](phase-5d-2.md#d1)). ⚠ `STARTS_WITH ".well-known"`, not the `EQUALS ".well-known/webfinger"` this bullet specified — the provider must own the segment the servlet mapping owns |
| Delete `WebFinger`, `OpenIDConnectDiscovery`, `GuicedRestlet`, `OAuth2StatusService`, the openam-oauth2 restlet audit classes | **5d-2a-ii** (the first two) and **5d-2b** (the rest) |
| Vestigial imports — `AuthenticationServiceV1`, `DefaultWsFedAuthenticator` | **5d-2d**. ⚠ A third was found that is **not** vestigial: `SmsRealmProvider:25` really uses `HeaderConstants.HEADER_IF_NONE_MATCH` and needs the literal inlined ([research §2](phase-5d-2-research.md#2)) |
| Dead `Saml2BearerServerResource` + `openam-oauth2-saml2` restlet deps | **5d-2b** |

Phase 7 is unaffected and remains the next phase after 5d-2.

## Phase 7 — Outbound scripting HTTP client

- Rewrite `RestletHttpClient` (openam-http-client) on **`java.net.http.HttpClient`**
  (Java 11 built-in, zero new WAR artifacts; `followRedirects(NEVER)` to match current
  behavior). Preserve the deprecated public surface:
  `getHttpClientResponse(uri, body, requestData, method)`,
  `HttpClientRequest/Response/Cookie` beans, header/cookie/query conventions.
- Type-rename updates: `JavaScriptHttpClient`, `GroovyHttpClient`,
  `ScriptingGuiceModule` (openam-scripting), `Scripted` (openam-auth-scripted),
  `ScriptCondition` (openam-entitlements). Remove restlet from
  `openam-http-client/pom.xml`; fix javadoc refs in the beans.
- Verify: `mvn -pl openam-http-client,openam-scripting,openam-authentication/openam-auth-scripted,openam-entitlements test`;
  scripted-auth smoke via integration test.

## Phase 8 — Final deletion

⚠ **Reduced 2026-08-06.** Steps 1 and 4 moved into [5d-2d](phase-5d-2.md#d7) — they are what makes
openam-rest and openam-uma Restlet-free, and leaving them here would keep four modules depending on
`openam-restlet` for nothing but two string constants. Struck below, kept so the move is traceable.
After 5d-2 and phase 7, this phase is a module delete plus a pom sweep and nothing else.

1. ~~Relocate `RestRealmValidator` openam-restlet → openam-rest
   (`org.forgerock.openam.rest.router`); update importers (`RealmContextFilter` et al.).~~ → **5d-2d**
2. Delete module `openam-restlet`; delete `transform-jakarta/restlet-parent-jakarta/`
   (+ module entry in `transform-jakarta/pom.xml`).
3. Root pom sweep: `restlet.version`, all
   `org.openidentityplatform.openam.jakarta:org.restlet*` + `org.restlet.jee:*`
   dependencyManagement entries, restlet `excludeArtifact` lines, talend repo,
   `<module>openam-restlet</module>`, openam-restlet dependencyManagement entry.
4. ~~openam-rest: delete `AbstractRestletAccessAuditFilter`, `RestletBodyAuditor`,
   Restlet branch + inner `RestletRealmRouter` of `RealmRoutingFactory`; drop restlet
   deps (and the "TODO until Restlet endpoints are moved to CHF" comment).~~ → **5d-2c/5d-2d**
   - ~~Repoint the `REALM_OBJECT` readers/writers off the deleted `RestletRealmRouter.REALM_OBJECT`
     onto the surviving `OAuth2Constants.Custom.REALM_OBJECT`.~~ → **[5d-2d D7](phase-5d-2.md#d7)**.
     ⚠ The site list here was incomplete and one entry is wrong: the readers are **six**, not four —
     `OAuth2UrisFactory:69`, `OAuth2RealmResolver:51`, `UmaUrisFactory:87`,
     `UmaProviderSettingsFactory:80`, `RealmRoutingFactory:21-22/248-263` and `UmaUrisFactoryTest`;
     `IdTokenInfo` is deleted by 5d-2b rather than repointed, and `REALM` is migrated alongside
     `REALM_OBJECT` ([research §5](phase-5d-2-research.md#5)).
5. Sweep remaining poms (openam-oauth2, openam-uma, openam-server-only war excludes).
6. Gates: `grep -rn "org.restlet" --include="*.java" .` → 0 outside docs;
   `grep -rn restlet --include=pom.xml .` → 0; `mvn clean install`;
   `mvn -pl openam-server verify -P integration-test`.

---

## Risk register (behavioral compatibility)

| # | Risk | Detail | Verification |
|---|---|---|---|
| 1 | Form-POST body re-reading | Restlet re-sets the entity after `new Form(entity)`; CHF handlers + audit + auth all read the body | `ChfOAuth2RequestTest` re-read tests; audit + `/access_token` in one integration request |
| 2 | Redirect codes & semantics | 301 auth-required, 302 error/success/endSession; fragment vs query per `UrlLocation`; no auto-redirect on invalid redirect_uri | Exact-status unit asserts; record current responses with curl before flip, diff after |
| 3 | ~~Error-param encoding~~ **closed 2026-07-22** | Restlet `Reference`/`Form` vs CHF `Form.toQueryString`. Feared to differ; **they do not** — both emit RFC 3986 percent-encoded UTF-8, space as `%20` (not `+`), `&`/`=`/`+` as `%26`/`%3D`/`%2B`. Observed, not argued | `RestletErrorParityTest` A/B's space, `+`, `&`, `=` and Cyrillic in `state` + `error_description`, in query and fragment |
| 4 | `WWW-Authenticate` on 401 | Basic challenge at token endpoint; Bearer challenge on protected endpoints | Header asserts in handler tests; pre/post curl diff |
| 5 | Basic-auth charset | Restlet decodes `Authorization: Basic` as ISO-8859-1, not UTF-8 | Explicit charset in `getBasicAuthCredentials()` + test with high-bit char in secret |
| 6 | Content types | Restlet conneg defaulted JSON (OAuth2/UMA), `application/xacml+xml; version=3.0`, HTML | Explicit `Content-Type` everywhere; asserts; curl `-H "Accept: */*"` diff |
| 7 | StatusService error bodies | `JSONRestStatusService`/`XMLRestStatusService` CREST-format bodies for uncaught errors | Error-filter tests against recorded bodies |
| 8 | Trailing-slash routes | `/resource_set`, `/resource_set/`, `/resource_set/{rsid}` are three attachments | Register all three CHF routes; integration hits each |
| 9 | Realm resolution parity | DNS alias, legacy path realm, `?realm=` override, `realms/{realmId}` recursion, 400-vs-404 on bad realm | `RealmContextFilter` battle-tested on `/json`; per-area integration cases for all styles. ✅ **The Restlet side is now recorded end to end** — [5-E5](phase-5d-1-asbuilt.md#the-recorded-rows) rows 1–4 and 14, which found that a flat `realms/<non-root>` resolves, that a bad `?realm=` is a 404 whose message is the cause's, and that an unknown `Host` 500s on **every** style. `OAuth2RouterIT`'s realm rows are what must reproduce them |
| 10 | `getParameterCount` | Counts query duplicates only (`DuplicateRequestParameterValidator`) | Keep query-only semantics; test duplicate `redirect_uri` |
| 11 | Case sensitivity | Both Restlet templates and CHF matchers are case-sensitive | Spot-check `/oauth2/Authorize` → 404 pre & post. ✅ **Pre-flip half done** — [5-E5 row 13](phase-5d-1-asbuilt.md#the-recorded-rows): `/oauth2/Tokeninfo`, `/oauth2/TOKENINFO`, `/oauth2/Connect/jwk_uri` and `/oauth2/connect/JWK_URI` are all 404. Re-run the same row after 5d-1c for the post half |
| 12 | Endpoint-type checks | `ClientCredentialsReader` keys auth-method rules off the `/access_token` path | `EndpointType` tests incl. realm-prefixed URIs |
| 13 | Audit event parity | Restlet `forHttpServletRequest` vs CHF `forRequest` builder paths; body detail per route. **Two concrete divergences found and fixed in 3d** ([phase-3d-audit.md](phase-3d-audit.md)): (a) the CHF base audited **3xx as FAILED** (`isSuccessful()`=2xx only) where Restlet audits it as success — broke every authorize-success 302 → **fixed** in the base ([D2](phase-3d-audit.md#d2--3xx-classified-as-success-fix-in-the-base)); (b) `forRequest` read query params from `getForm()`, leaking POST-body form fields (incl. `client_secret`) into `queryParameters` → **fixed** in `forRequest` ([D3](phase-3d-audit.md#d3--forrequest-query-param-leak-fix-separately)). Body-auditor parity **proven green** by the oracle against the real `RestletBodyAuditor`. One accepted, pre-existing residual: the FAILED-path `reason` string (`getReasonPhrase()` vs Restlet `getDescription()`) — record at 5d | `RestletAuditParityTest` (body auditors), `AbstractHttpAccessAuditFilterTest` (302→SUCCESSFUL), `OAuth2AuditRouteCompositionIT`; per-area recorded-JSON diff at 5d |
| 14 | HTML output | Same FreeMarker 2.3.31; only the loader changes | Golden-file render tests; browser smoke of consent + device pages |
| 15 | Locale selection | `HttpServletRequest.getLocale()` vs Accept-Language parse (q-values); servlet returns `Locale.getDefault()` when the header is absent | Multi-range header unit test + absent-header test |
| 16 | Scripting client behavior | Redirect-following / cookie defaults differ between Restlet client and java.net.http | `followRedirects(NEVER)`; script integration test |
| 17 | goto-URL query mutation | `alterMaxAge`/`removeLoginPrompt` rewrite the request URL's query; the result becomes the login redirect's `goto`. An attribute write cannot replace it — infinite re-auth loop | Neutral `setQueryParameter`/`removeQueryParameterValue`; `getRequestUrl()` asserts; browser smoke of `max_age` + `prompt=login` |
| 18 | `Content-Type` parameters | CHF `Form.fromRequestEntity` exact-matches the whole header; `;charset=UTF-8` silently yields an empty form. Restlet compares the parsed `MediaType` | Parse via `ContentTypeHeader.valueOf`; form/JSON tests with a charset parameter |
| 19 | **Build-ahead has no live guard** (3c/3d) | 3c/3d classes are wired to no route until Phase 4/5, so the "Restlet suite stays green" guardrail does not apply and a wrong contract is invisible until the flip. No existing test asserts rendered HTML, charset or popup composition | The **golden 3-way oracle** ([chf-patterns.md](chf-patterns.md) §13): `Restlet == golden == CHF` in one JVM while Restlet is still on the classpath; degrades to `golden == CHF` at 5d. **Audit slice retired 2026-07-23**: 3d-2's `RestletAuditParityTest` (A/B vs real `RestletBodyAuditor`) + `OAuth2AuditRouteCompositionIT` (real CHF chain) cover the audit build-ahead; the renderer (3c-1) portion stays open until 5d |
| 20 | **The oracle expires at 5d** | Phase 5d/8 deletes the Restlet code that is the only oracle for "what does OpenAM do today". A golden regenerated after that is unfalsifiable | Generate goldens **only** while the Restlet leg lives; never regenerate post-5d without re-deriving from git history. **`/oauth2` discharged**: §E (2026-07-24, `/access_token` + cache headers) and §5-E2 (2026-07-26, `/authorize`) are both recorded against live Restlet |
| 21 | **`setEntity(String)` → ISO-8859-1** | CHF falls back to ISO-8859-1 when `Content-Type` carries no charset ([chf-patterns.md](chf-patterns.md) §6). All 10 templates are ASCII, so **ASCII test fixtures will not catch it** | Header first, then `setEntity(html.getBytes(UTF_8))`; assert bytes with a **non-ASCII data-model value** |
| 22 | **Open redirect via catch-ordering drift** | The no-redirect policy is emergent from catch ordering; `AuthorizeResource` GET and POST disagree, and POST redirects `OAuth2ProviderNotFoundException` to an **unvalidated** `redirect_uri` | Explicit `OAuth2Error.mayRedirect` table unified to the safe union ([phase-3c-2](phase-3c-2-error-layer.md#d6--isredirectable-unified-to-the-safe-union-fix)); test enumerates all 31 subclasses, and `ResourceOwnerAuthenticationRequired` is carved out so the login redirect can never be retargeted ([D13](phase-3c-2-error-layer.md#d13--resourceownerauthenticationrequired-carries-its-own-redirect-uri-carve-out)) |

## Verification workflow (every phase)

1. Module-scoped: `mvn -pl <changed modules> test`
2. Whole build: `mvn install -DskipTests`
3. Integration (Linux; needs `127.0.0.1 openam.local` in `/etc/hosts`, as CI does):
   `mvn -pl openam-server verify -P integration-test`
4. After 5d and 8: manual smoke of the full OAuth2/OIDC/UMA/XACML matrix against a
   running WAR; record pre-flip curl responses so post-flip output can be diffed.

CI (`.github/workflows/build.yml`) builds every push to `features/**` on JDK 11–26 × 3
OSes, so each phase commit gets cross-version coverage automatically.
