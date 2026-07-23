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
| **F1–F4** | **openam-http framework fixes** — handler-thrown exceptions get a body (F1); `@ExceptionHandler` made real (F2); `Promise` returns implemented (F3); `@Produces` honoured so `String` returns stop being ISO-8859-1 (F4). **Prerequisite to 3c-2** | **done** 2026-07-22 — 64 new tests in a package that had **none** ([as-built](openam-http-framework.md#as-built)). Also unblocks **5b**: per-endpoint catch blocks collapse into one `@ExceptionHandler` per handler class |
| 3c-2 | Error layer — `OAuth2Error`, `RedirectUris`, error factory + filter | done 2026-07-22 — +123 unit tests and the module's first IT ([as-built](phase-3c-2-error-layer.md#as-built)). Three review passes also chained `ServerException`'s cause and stopped openam-http HTML-escaping CREST messages ([review outcomes](phase-3c-2-error-layer.md#review-outcomes)). e2e contract lock (§E) **deferred**, still to be recorded against live Restlet before 5d |
| 3d | CHF audit filters + `HttpBodyAuditor` | done 2026-07-23 — landed as the mandated **two commits**: **3d-1** (`666ea57318`) enhances the shared `AbstractHttpAccessAuditFilter` (openam-audit-core) with context/detail hooks, the **3xx→SUCCESSFUL** fix ([D2](phase-3d-audit.md#d2--3xx-classified-as-success-fix-in-the-base)) and `forRequest` query-only ([D3](phase-3d-audit.md#d3--forrequest-query-param-leak-fix-separately)) — a **live-path** change to `/json` audit, guarded by its tests; **3d-2** (`41170fb92a`) = 3 build-ahead OAuth2/UMA classes + the parity oracle in openam-oauth2 (**+29 unit, +2 IT**; 916 module green; import gate 0) ([as-built](phase-3d-audit.md#as-built)). A review pass folded in reuse/cleanup fixes (`select` helper, static logger). Live-route audit smoke (risk #13 pre/post-flip `queryParameters` diff) **deferred to 5d** |
| 4 | UMA `/uma` → CHF (atomic flip; sub-phases **4a** shared protection filter + **4b** endpoints/flip) | planned ([phase-4-uma.md](phase-4-uma.md)) |
| 5a–5d | OAuth2/OIDC `/oauth2` → CHF (flip in 5d) | pending |
| 6 | WebFinger `/.well-known` + stragglers | pending |
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

Sub-phases 5a–5c land as shippable commits while Restlet still serves `/oauth2`; 5d is
the atomic flip (a path prefix moves whole in web.xml).

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
  `WWW-Authenticate: Basic realm="..."`; re-sign `TokenRequestHook` to
  `(OAuth2Request, Context, Request, Response)` (update `LoginHintHook`).
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
  state/redirect_uri/parameter-location; re-sign `AuthorizeRequestHook`.
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

## Phase 6 — WebFinger + stragglers

- `WebFingerHandler` (port of `OpenIDConnectDiscovery`; GET, `resource`/`rel`, JRD JSON)
  + `WellKnownHttpRouteProvider` (`newHttpRoute(EQUALS, ".well-known/webfinger")`,
  chained with `RealmContextFilter` + audit). web.xml: replace the
  `org.restlet.ext.servlet.ServerServlet` WebFinger block with `/.well-known/*` on
  `OpenAM`.
- Delete `WebFinger`, `OpenIDConnectDiscovery`, `GuicedRestlet`, `OAuth2StatusService`,
  remaining restlet audit classes in openam-oauth2.
- Strip vestigial imports: `AuthenticationServiceV1` (openam-core-rest),
  `DefaultWsFedAuthenticator` (OpenFM).
- Delete dead `Saml2BearerServerResource` (+ test) and restlet deps in
  `openam-oauth2-saml2/pom.xml`.
- Verify: `mvn -pl openam-oauth2,openam-core-rest,openam-oauth2-saml2 test`; smoke
  `GET /openam/.well-known/webfinger?resource=...&rel=http://openid.net/specs/connect/1.0/issuer`.

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

1. Relocate `RestRealmValidator` openam-restlet → openam-rest
   (`org.forgerock.openam.rest.router`); update importers (`RealmContextFilter` et al.).
2. Delete module `openam-restlet`; delete `transform-jakarta/restlet-parent-jakarta/`
   (+ module entry in `transform-jakarta/pom.xml`).
3. Root pom sweep: `restlet.version`, all
   `org.openidentityplatform.openam.jakarta:org.restlet*` + `org.restlet.jee:*`
   dependencyManagement entries, restlet `excludeArtifact` lines, talend repo,
   `<module>openam-restlet</module>`, openam-restlet dependencyManagement entry.
4. openam-rest: delete `AbstractRestletAccessAuditFilter`, `RestletBodyAuditor`,
   Restlet branch + inner `RestletRealmRouter` of `RealmRoutingFactory`; drop restlet
   deps (and the "TODO until Restlet endpoints are moved to CHF" comment).
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
| 9 | Realm resolution parity | DNS alias, legacy path realm, `?realm=` override, `realms/{realmId}` recursion, 400-vs-404 on bad realm | `RealmContextFilter` battle-tested on `/json`; per-area integration cases for all styles |
| 10 | `getParameterCount` | Counts query duplicates only (`DuplicateRequestParameterValidator`) | Keep query-only semantics; test duplicate `redirect_uri` |
| 11 | Case sensitivity | Both Restlet templates and CHF matchers are case-sensitive | Spot-check `/oauth2/Authorize` → 404 pre & post |
| 12 | Endpoint-type checks | `ClientCredentialsReader` keys auth-method rules off the `/access_token` path | `EndpointType` tests incl. realm-prefixed URIs |
| 13 | Audit event parity | Restlet `forHttpServletRequest` vs CHF `forRequest` builder paths; body detail per route. **Two concrete divergences found and fixed in 3d** ([phase-3d-audit.md](phase-3d-audit.md)): (a) the CHF base audited **3xx as FAILED** (`isSuccessful()`=2xx only) where Restlet audits it as success — broke every authorize-success 302 → **fixed** in the base ([D2](phase-3d-audit.md#d2--3xx-classified-as-success-fix-in-the-base)); (b) `forRequest` read query params from `getForm()`, leaking POST-body form fields (incl. `client_secret`) into `queryParameters` → **fixed** in `forRequest` ([D3](phase-3d-audit.md#d3--forrequest-query-param-leak-fix-separately)). Body-auditor parity **proven green** by the oracle against the real `RestletBodyAuditor`. One accepted, pre-existing residual: the FAILED-path `reason` string (`getReasonPhrase()` vs Restlet `getDescription()`) — record at 5d | `RestletAuditParityTest` (body auditors), `AbstractHttpAccessAuditFilterTest` (302→SUCCESSFUL), `OAuth2AuditRouteCompositionIT`; per-area recorded-JSON diff at 5d |
| 14 | HTML output | Same FreeMarker 2.3.31; only the loader changes | Golden-file render tests; browser smoke of consent + device pages |
| 15 | Locale selection | `HttpServletRequest.getLocale()` vs Accept-Language parse (q-values); servlet returns `Locale.getDefault()` when the header is absent | Multi-range header unit test + absent-header test |
| 16 | Scripting client behavior | Redirect-following / cookie defaults differ between Restlet client and java.net.http | `followRedirects(NEVER)`; script integration test |
| 17 | goto-URL query mutation | `alterMaxAge`/`removeLoginPrompt` rewrite the request URL's query; the result becomes the login redirect's `goto`. An attribute write cannot replace it — infinite re-auth loop | Neutral `setQueryParameter`/`removeQueryParameterValue`; `getRequestUrl()` asserts; browser smoke of `max_age` + `prompt=login` |
| 18 | `Content-Type` parameters | CHF `Form.fromRequestEntity` exact-matches the whole header; `;charset=UTF-8` silently yields an empty form. Restlet compares the parsed `MediaType` | Parse via `ContentTypeHeader.valueOf`; form/JSON tests with a charset parameter |
| 19 | **Build-ahead has no live guard** (3c/3d) | 3c/3d classes are wired to no route until Phase 4/5, so the "Restlet suite stays green" guardrail does not apply and a wrong contract is invisible until the flip. No existing test asserts rendered HTML, charset or popup composition | The **golden 3-way oracle** ([chf-patterns.md](chf-patterns.md) §13): `Restlet == golden == CHF` in one JVM while Restlet is still on the classpath; degrades to `golden == CHF` at 5d. **Audit slice retired 2026-07-23**: 3d-2's `RestletAuditParityTest` (A/B vs real `RestletBodyAuditor`) + `OAuth2AuditRouteCompositionIT` (real CHF chain) cover the audit build-ahead; the renderer (3c-1) portion stays open until 5d |
| 20 | **The oracle expires at 5d** | Phase 5d/8 deletes the Restlet code that is the only oracle for "what does OpenAM do today". A golden regenerated after that is unfalsifiable | Generate goldens **only** while the Restlet leg lives; never regenerate post-5d without re-deriving from git history |
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
