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
| 4 | UMA `/uma` → CHF (atomic flip; sub-phases **4a** shared protection filter + **4b** endpoints/flip) | done 2026-07-23 (uncommitted; Cargo boot + `e2e/uma` smoke deferred) — `/uma/*` flipped to the `OpenAM` CHF servlet via new `UmaHttpRouteProvider`; three endpoints re-based in place, shared `@ExceptionHandler`/`UmaErrorResponseFactory`, `ChfAccessTokenProtectionFilter` (4a) wired; `UmaRouterProvider`/`UmaExceptionHandler`/`UMAServiceEndpointApplication` deleted. **194 unit + `UmaRouterIT` 11 IT** green, whole `-am` WAR assembles, import gate 0 ([as-built](phase-4-uma.md#as-built)). ⚠ **The deferred `e2e/uma` smoke landed 2026-07-26 and immediately found a live regression the flip had shipped**: `/uma/.well-known/uma-configuration` was a **500 for every request** (`UmaUrisFactory`/`OAuth2UrisFactory` asked for a CREST `HttpContext` that a plain CHF chain does not carry). Both `UmaRouterIT` case 6 and `UmaWellKnownConfigurationEndpointTest` **mock `UmaUrisFactory`**, so neither could see it. Fixed via the new shared `ChfContexts` helper + `UmaUrisFactoryTest` (module now **196**), and guarded end-to-end by `e2e/uma/uma-test.spec.mjs` (11 rows) |
| **5** | **OAuth2/OIDC `/oauth2` → CHF** — umbrella research + plan: [phase-5-oauth2.md](phase-5-oauth2.md). Largest area; **reviewed + restructured into 7 iterative steps** (all factual/API/line claims verified against the tree). Surface is **15 endpoints / 18 `router.attach()`** (resource_set ×3), not "16 routes". All of 3c/3d/4a was build-ahead *for this phase* (renderer, error layer, audit, protection filter — **all confirmed present**). **Gate: the §E e2e contract lock + golden/parity tests must be recorded against live Restlet before 5d-1** (the oracle is deleted at the flip) | **planned** 2026-07-24 |
| 5a-1 | `/access_token` grant dispatcher (`TokenEndpointHandler`) + `AbstractOAuth2HttpJsonEndpoint` base + `TokenRequestHook` seam. **Cookie spike first** (settle servlet-response cookie survival before the hook seam). Detailed plan: [phase-5a-1.md](phase-5a-1.md) | done (build-ahead; 945 tests green, WAR + doclint green) |
| 5-E | **e2e contract lock (§E)** — record the live-Restlet `/oauth2` error/redirect contract into `e2e/oauth2/oauth2-test.spec.mjs` **by observation** (JSON error + `WWW-Authenticate: Basic` on `/access_token`, incl. the real `GET /access_token` body per [phase-5a-1 finding 1](phase-5a-1.md); 301→login `Location`; 302 query-vs-fragment; `text/html;charset=UTF-8` error page) + confirm the 3c golden/parity tests green. A **gate, not a build step**: no new main classes, landable any time in 5a–5c, **recommended right after 5a-1**, and it **must land before 5d-1** — the live oracle dies at the flip (risk #20). Re-run + byte-diffed after 5d-1 | recorded (13 rows green vs live Restlet). **3 `/access_token` rows** (unknown grant→`unsupported_grant_type`, bad secret→401 `Basic realm="/"`, GET→405 `method_not_allowed`; finding 1's 400 prediction overturned) + **cache-header oracle 2026-07-24** (task #11): 3 contracts pinned verbatim — `/access_token` `no-store`+`Pragma:no-cache` (success+error), `/tokeninfo` `no-cache, no-store` no-Pragma (success only) + `Content-Type: application/json` **no-charset** (a new deliberate 5d-1 diff), `/introspect`+`/userinfo` none. Re-run + byte-diff still due at 5d-1. ✅ **The `/authorize` half is now recorded too** — see step **5-E2** below (2026-07-26, 10 further rows) |
| 5a-2 | The 9 simple JSON endpoints off the shared conversion template. **Split 2-way** — 5a-2a: base cache-header correction ([per-endpoint, not blanket](phase-5a-2.md)) + 5 pure-template handlers (tokeninfo, introspect, userinfo, openid-configuration, jwk_uri); 5a-2b: the 4 with real decisions (connect/register, device/code, token/revoke, idtokeninfo — the realm-rewrite case, ported last with a real-context test). Detailed plan: [phase-5a-2.md](phase-5a-2.md) | done (build-ahead) — **5a-2a** `3ab13256d3` (5 handlers + D1 per-endpoint cache fix; +13 surefire) + **5a-2b** `b2cc5c8c89` (4 handlers, D3/D4/D5 plan corrections, +16 tests, real-context realm-claim test). All 9 endpoints unit-green, `http` suite 42/42, `install`/doclint clean, import gate 0. Wired to **no route** until 5d-1. §E cache-header oracle rows **recorded 2026-07-24** (see 5-E row) ([as-built](phase-5a-2.md#as-built)). ⚠ Recorded 2026-07-26 in `e2e/oauth2/oauth2-endpoints-test.spec.mjs`: `connect/register` implements RFC 7591 create + RFC 7592 **read only** — `DELETE registration_client_uri` answers **405**, so a dynamically registered client cannot deregister itself. `ChfClientRegistrationHandler` must reproduce that; do not "fix" it as part of the port |
| 5-E2 | **§E authorize contract lock** — the `/authorize` half of the §E gate, which 5-E did **not** cover (its 7 recorded rows are `/access_token` + cache headers only). 9 rows against live Restlet: 301→login `Location`, consent page, `text/html` error page, 302 query-vs-fragment, `PUT`/JSON-`POST` (the CONTINUE-bug questions that *decide* 5b-1's validation design), consent-success `Set-Cookie`. Test-only; **must precede 5b-1b and 5d-1**. Detailed plan: [phase-5b-1.md](phase-5b-1.md) | **done 2026-07-26** — recorded against a live container from this tree: 9 rows **+ row 9b**, `e2e/oauth2` **23 green** (10 new + 13 existing), 3c parity oracles green (27). Two decisions landed: **[D8](phase-5b-1.md#d8) resolved** — `PUT`→405 `method_not_allowed` and JSON-`POST`→400 `Invalid Content Type` both **survive** the CONTINUE fall-through, so `AuthorizeHandler` gets **no verb check** but **must** reproduce the content-type check; **[D6](phase-5b-1.md#d6) premise corrected** — a Restlet authorize success emits **no** `oidcLoginHint` `Set-Cookie` unless the request already carried one, so the CHF delete must be unconditional-when-set or the cookie is left set in the browser. Also recorded: PKCE is enforced by the provider, and on `/authorize` only the session **cookie** authenticates (the header does not). ([as-built](phase-5b-1.md#as-built-5-e2--recorded-2026-07-26)) |
| 5b-1 | `AuthorizeHandler` **alone** (~600L) + `AbstractOAuth2HttpBrowserEndpoint` base (+ consent data model, catch-collapse, `AuthorizeRequestHook`). **Split 3-way** — **5-E2** (gate, above) → **5b-1a** browser substrate (`AbstractOAuth2HttpEndpoint` extract, browser `@ExceptionHandler` base, `ChfAuthorizeRequestHook`, the missing neutral `getAcceptedLanguages()`) → **5b-1b** `AuthorizeHandler` + shared `ConsentPageRenderer`. Detailed plan: [phase-5b-1.md](phase-5b-1.md) | **done 2026-07-26** — `77c37284cf` (S1–S9; 5-E2 gate, 5b-1a substrate and 5b-1b handler landed together). `AuthorizeHandler` + `ConsentPageRenderer` + `OAuth2ContentTypes` + `OAuth2NoCacheFilter`; **1132 surefire + 18 failsafe**, doclint clean, import gate 0. **Wired to no route until 5d-1.** Three review rounds; two defects were found by oracles rather than by reading, one of them wire-visible on a **committed** endpoint — a body with no `Content-Type` was accepted where Restlet 400'd it, which on `/authorize` turned a consent **"allow" into a silent `access_denied`** (`getParameter` reads a POST body only when the type is form). Seven expected divergences recorded for the flip: [see below](#expected-divergences-at-the-flip) ([as-built](phase-5b-1.md#as-built-s8)) |
| 5b-2 | device/user, checkSession (**realm-prefixed only — JSP kept**), endSession. **Split 3-way** — **5-E3** (gate: ~14 live-Restlet contract rows; none of the three is locked today) → **5b-2a** `EndSessionHandler` + `CheckSessionHandler` → **5b-2b** `DeviceCodeVerificationHandler`. Detailed plan: [phase-5b-2.md](phase-5b-2.md) | **5-E3 done** 2026-07-28 (test-only, 14 e2e rows, `npx playwright test oauth2` **62 passed**, was 48); **5b-2a done** 2026-07-28 — `f1ffda5d28` (D10 alone) + `67c71eb41e` (the handler pair, checklist steps 6–10): `EndSessionHandler` + `CheckSessionHandler` on `AbstractOAuth2HttpJsonEndpoint` unchanged, **1157 surefire + 18 failsafe** (was 1132 after 5b-1), e2e `oauth2` **63 passed**, grep gate 0, routed nowhere until 5d-1. Review found a wire-visible plan gap — [D7](phase-5b-2.md#d7)'s wrap list missed that `OpenIDConnectEndSession.endSession` reconstructs the id_token *itself*, so a malformed `id_token_hint` was a framework **500** against live Restlet's 400 `server_error`, and the first test for it was a **false green** off an unstubbed mock. Two divergences found and recorded rather than fixed ([rows 9 and 10](#expected-divergences-at-the-flip)), both applying beyond this step ([as-built](phase-5b-2.md#as-built-5b-2a--landed-2026-07-28)); **5b-2b done** 2026-07-28 — `021c345061`: `DeviceCodeVerificationHandler` on `AbstractOAuth2HttpBrowserEndpoint` + the [D2](phase-5b-2.md#d2) `ConsentPageRenderer` correction (phase 1 copies all nine `MODEL_KEYS` from the attributes, not `realm` alone — the device consent model has **no query to come from**), **1180 surefire + 25 failsafe**, grep gate 0, doclint clean, routed nowhere until 5d-1. The plan held: [D2](phase-5b-2.md#d2)/[D3](phase-5b-2.md#d3)/[D4](phase-5b-2.md#d4) went in as written and [finding 7](phase-5b-2.md#7-the-device-verify-control-flow-branch-by-branch) called both traps — the `InvalidGrantException` catch must stay scoped to `readDeviceCode` alone (`update`/`deleteDeviceCode` throw the same type), and the IAE divergence belongs in **row 1**, not a new row. ⚠ **The false green recurred**: three "unusable user code" rows were green off an unstubbed `user_code` (`anyString()` does not match `null`), so all three silently took the `deviceCode == null` branch and the `InvalidGrantException`/`isIssued` paths were never executed — the same shape as 5b-2a's unstubbed mock, again caught by *reviewing* the tests. `DeviceCodeRouteCompositionIT` drives the **real** `OAuth2RequestFactory` in every row (the checklist asked for one), which is the only way the request cache is testable at all ([finding 14 / R-5b2.3](phase-5b-2.md#14--the-request-cache-is-load-bearing-here-and-nothing-tests-it)); mutation-checked — removing the one seeding call turns 5 of its 7 rows red ([as-built](phase-5b-2.md#as-built-5b-2b--landed-2026-07-28)). Two corrections to the umbrella, both verified: **(1)** only **one** of the three is a browser endpoint — the `doCatch` arity is the error contract, and `EndSession`/`OpenIDConnectCheckSessionEndpoint` call the **2-arg** `ExceptionHandler.handle` (**JSON**), so they extend `AbstractOAuth2HttpJsonEndpoint`, not the browser base ([finding 1](phase-5b-2.md#1--only-one-of-the-three-is-a-browser-endpoint-the-doccatch-arity-decides)); **(2)** `ConsentPageRenderer`'s phase 1 (shipped in 5b-1) is **realm-only**, and the device flow seeds its whole consent model from request *attributes* — so as it stands the device consent page silently loses `client_id`/`scope`/`state`/`nonce`/`response_type`/`ui_locales`/`realm` ([finding 2](phase-5b-2.md#2--consentpagerenderer-phase-1-is-realm-only-and-that-silently-breaks-the-device-consent-page), fixed by D2). **Reviewed 2026-07-28**, which caught a defect in the plan's own first draft: a proposed `RuntimeException` mapper on the shared JSON base re-litigated locked **D3** (bug paths keep CHF's 500) — replaced by narrow, source-level `ServerException` wraps for the three *client-reachable* unchecked throws, touching no shared class ([D7](phase-5b-2.md#d7)). Review also added **[D10](phase-5b-2.md#d10)**: `OAuth2ErrorFilter.errorFor` gains `case 405 → method_not_allowed`, one line in our own code that **narrows expected-divergence #3** to `error_description` only for `/authorize` and `/access_token` (the two `OAuth2Filter`-wrapped routes). **No CHF/openam-http change is needed** — `AnnotatedMethod` already resolves the most-specific `@ExceptionHandler` on inherited methods. **[5-E3 as-built](phase-5b-2.md#as-built-5-e3--recorded-2026-07-28)** settled the three gated decisions: **D5** stands (every non-`page` `?display=` is a 400, by three different mechanisms); **D8** resolved — `Reference` does **no** normalisation, an existing query survives verbatim and `state` appends with `&`, encoded `%20`/`%2F`; **D7** confirmed **and extended to a fourth wrap** — `getClientSessionURI` throws `NoSuchElementException` whenever a client's `clientSessionURI` is unset, which is the admin API's default, so check-session 400s on its own happy path today. **D10's justification narrowed**: none of the three emits `method_not_allowed` (all three send a CREST 405 body), so D10 rests on `/authorize` + `/access_token` alone |
| 5c | resource_set — handler + CHF `ResourceSetRegistrationExceptionFilter`, guarded by `ChfAccessTokenProtectionFilter(null)` | pending |
| 5d-1 | **the flip, Restlet dormant** — `OAuth2HttpRouteProvider` (18 attachments + audit matrix) + services + web.xml mapping move + hook re-sign; **Restlet stack left in place** (one-line revert); soak green. ⚠ **Re-run the §E/§E2 e2e specs and byte-diff; the differences below are expected and must not be "fixed"** — see [expected divergences at the flip](#expected-divergences-at-the-flip) | pending |
| 5d-2 | **the deletion** — after 5d-1 soaks: delete the ~40-class Restlet OAuth2 stack + `ForgeRockRest` servlet + Guice unbinds + drop Restlet hook interfaces | pending |
| 6 | WebFinger `/.well-known` + stragglers | pending. ⚠ **`/.well-known/webfinger` is already broken today, before any migration work** — recorded 2026-07-26 in `e2e/oauth2/webfinger-test.spec.mjs`. `web.xml` mounts the WebFinger application on **upstream** `org.restlet.ext.servlet.ServerServlet`, while `OpenIDConnectDiscovery` reads the servlet request via OpenAM's own `ServletUtils.getRequest(...)`, which only recognises OpenAM's `ServletCall` — so it returns `null` and `getRootURL(null)` NPEs: **500 on every request**. The CHF port fixes this by construction; the spec's success case is `test.fail()`-marked and will go red (= remove the annotation) once it does |
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

### Expected divergences at the flip

The §E and §E2 e2e specs are re-run and byte-diffed after 5d-1, and the live-Restlet oracle **dies at the flip**
(risk #20) — so a difference found then can no longer be checked against the producer. Everything below was
decided deliberately, with the evidence recorded at the time. **A diff that matches one of these rows is
expected; a diff that does not is a regression.**

From **5b-1** (`/authorize`), all detailed in [phase-5b-1.md](phase-5b-1.md):

| # | What differs | Restlet | CHF | Why |
|---|---|---|---|---|
| 1 | `IllegalArgumentException` on `/authorize` — **and, from 5b-2b, on `/device/user`** | `/authorize`: GET **redirected** to the raw `redirect_uri` (unless the message mentioned `client_id`); POST gave a 400 `server_error` page. `/device/user`: the **same three answers** — `DeviceCodeVerificationResource:186-193` redirects to the raw `redirect_uri` unless the message names `client_id`, while an IAE from `?display=` is raised inside the sibling `catch (ResourceOwnerConsentRequired)` and so reaches `doCatch` as a 400 `server_error` page | one non-redirecting **400 `invalid_request` page**, both verbs, both endpoints | [D7](phase-5b-1.md#d7) — the safe union. Closes an open redirect: a request that failed parameter validation never had its `redirect_uri` checked against the client's registered set. ⚠ The generalisation is **structural**: D7 lives on `AbstractOAuth2HttpBrowserEndpoint`, so it applies to every browser endpoint this migration ports, not to `/authorize` alone. 5b-2's [finding 7](phase-5b-2.md#7-the-device-verify-control-flow-branch-by-branch) predicted this and asked for it here rather than as a new row |
| 2 | `oidcLoginHint` on a first authorize carrying `login_hint` | one `Set-Cookie` (the set), retracted in-process on success | **two** `Set-Cookie` headers — the set, then the expiry | [D6](phase-5b-1.md#d6) — a servlet response has no cookie-removal API. Both go on the wire, the browser applies them in order, and ends with no cookie. Guarding on the incoming cookie instead would leave it **set** after a first authorize (5-E2 row 9b) |
| 3 | Unsupported verb (`PUT`) body — **narrowed 2026-07-28** | 405 `method_not_allowed` + `"Required Method: GET or POST found: PUT"` | 405 `method_not_allowed` + `"Method Not Allowed"` | [D8](phase-5b-1.md#d8) — the framework's 405, body rewritten by `OAuth2ErrorFilter`. **Status and cache headers already matched** (`OAuth2NoCacheFilter` restored the `no-store`/`Pragma` per-method stamping could not reach); the 5b-2 review then added [D10](phase-5b-2.md#d10), so the `error` field matches too and **only `error_description` still differs**. Verify D10 has landed before diffing this row |
| 4 | `login_hint` that is not an RFC 6265 `cookie-octet` string | wrote the malformed header itself | **writes no cookie**, logs the skip at debug | Identical bytes for every value Restlet could legally send; avoids a container-dependent 500 (Tomcat's `Rfc6265CookieProcessor` throws while generating the header, outside any handler's reach) |
| 5 | `Accept-Language` with a malformed `q` (`en;q=bogus`) | **throws** — a 500 for a header the client controls | ignores the parameter, returns `["en"]` | The `q` only ever fed an ordering Restlet does not apply ([as-built S4](phase-5b-1.md#as-built-s4)) |
| 6 | `Content-Type: APPLICATION/X-WWW-FORM-URLENCODED` | **400** — `MediaType.equals` compares names case-sensitively | accepted | RFC 7231 §3.1.1.1 says it is legal. A widening: it can only turn a Restlet 400 into a success, never the reverse. Pinned by `RestletContentTypeParityTest` |
| 7 | A hook throwing **after** the authorization is issued | `doCatch` → HTML `server_error` page | framework CREST-JSON 500 | Recorded, not fixed — [why](phase-5b-1.md#div-hook-throw). If the soak produces a CREST-JSON body from `/authorize`, start there |

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
| 8 | Unsupported-verb body on a **non-`OAuth2Filter`** route — `device/user`, `connect/checkSession`, `connect/endSession`, `connect/register`'s `DELETE`, `resource_set`, `tokeninfo`, `introspect`, `userinfo` | 405 **CREST** `{"code":405,"reason":"Method Not Allowed","message":"The method specified in the request is not allowed for the resource identified by the request URI"}` — **no `error` field at all** (pinned for the first three by [5-E3 row 11](phase-5b-2.md#as-built-5-e3--recorded-2026-07-28)) | 405 **OAuth2** `{"error":"method_not_allowed","error_description":"Method Not Allowed"}` | The **shape** change comes from mounting `OAuth2ErrorFilter` across the application at all — not from D10, which only chooses the value inside the new shape. Before D10 the same routes would have said `invalid_request`, equally non-CREST and equally undefined by RFC 6749 for a 405. `errorFor` has **no route scope** and deliberately so: a client parsing `/oauth2` errors gets one shape everywhere, which is the filter's whole purpose |

⚠ Row 8 is a **widening in shape, not a regression**. It is here because the table's rule is that an unmatched
diff must be treated as one — without this row, the 5d-1 operator diffing `PUT /oauth2/connect/endSession` would
correctly follow the rule and revert D10.

| # | What differs | Restlet | CHF | Why |
|---|---|---|---|---|
| 9 | A `/` inside a redirect **parameter value** — `state`, `error_description`. **Applies to `/authorize`'s error redirect as well**, not just endSession | `?state=a%2Fb` — `Reference` percent-encodes it | `?state=a/b` — `Form.toQueryString` leaves it bare | Found while porting endSession (5b-2a), confirmed against the **real Restlet** by `RestletErrorParityTest#aSlashInsideAValueIsEncodedByRestletAndNotByChf`. Both are legal and parse identically — RFC 3986 §3.4 puts `/` in the `query` production — so no client can observe it. Recorded rather than fixed, on [D8](phase-5b-2.md#d8)'s own instruction: `RedirectUris` is shared with `/authorize`, so bending the encoder would change bytes on a committed endpoint to buy nothing. ⚠ **`+`, space, `&`, `=` and non-ASCII all still match exactly** — only `/` differs, and only inside a value |

⚠ Row 9 corrects a claim [D8](phase-5b-2.md#d8) made: *"the percent-encoding parity between the two was proven
and closed at 3c-2."* It was proven for the characters that test's fixture happened to contain (`a b&c=d+e`)
and no others. The parity harness was right; its input was incomplete.

| # | What differs | Restlet | CHF | Why |
|---|---|---|---|---|
| 10 | `state` in the **error body** of `connect/endSession` and `connect/checkSession` when the request carried one | **absent** — verified live 2026-07-28: `GET /oauth2/connect/endSession?state=abc123` answers exactly the body it answers without the parameter. Both Restlet resources build `new OAuth2RestletException(status, error, message, null)` (`EndSession:106`), and the 2-arg `ExceptionHandler.handle` fallback also passes `null`, so `asMap()` never carries it | `{"error":…,"error_description":…,"state":"abc123"}` | `AbstractOAuth2HttpJsonEndpoint.onError:53` does `OAuth2Error.of(e).withState(o2.getParameter("state"))` for **every** JSON endpoint. Not fixable per-endpoint: an override would drop the `@ExceptionHandler` annotation ([D1](phase-5b-2.md#d1)), and changing the shared base would move the five committed 5a handlers. **Additive** — a client reading `error`/`error_description` is unaffected, and `state` echo is what RFC 6749 §4.1.2.1 asks for anyway |

⚠ Row 10 is **not** specific to 5b-2a: the base has behaved this way since 5a-2, so it applies to every CHF
JSON endpoint. 5b-2a is merely the first step whose Restlet counterpart demonstrably passed `null`, which is
what made it observable. Worth a deliberate look at 5d-1 across all of them rather than only these two.

### Post-migration tickets — raised by the port, deliberately not fixed in it

Bugs the migration **reproduces faithfully** because it is a parity migration, each with a live-Restlet
observation and a pinning test that must be changed deliberately when the fix lands. Not tracked in an issue
tracker on purpose: they have to survive the deletion of the Restlet oracle at 5d-2, and this document is what
outlives it.

| # | Ticket | Reproduced by | Details |
|---|---|---|---|
| T1 | **`CheckSession.getClientSessionURI` throws on its own happy path.** A default-configured client — the admin API leaves `clientSessionURI` **empty on every client it creates** — makes check-session **400** as soon as an RP supplies an `id_token`. ⚠ The fix must cover **both** the `NoSuchElementException` (empty set, the common case) and the `NullPointerException` (null registration, the rarer one); a guard for only the latter repairs the wrong half | `CheckSessionHandler` (5b-2a), as 400 `server_error` | [phase-5-oauth2.md](phase-5-oauth2.md#post-migration-ticket-filed-by-5b-2a-checklist-step-9--checksessiongetclientsessionuri-throws-on-its-own-happy-path) — both triggers tabled with the four tests that pin them (5-E3 rows 6d/6e + two `CheckSessionHandlerTest` rows) |
| T2 | **Unverified `id_token_hint` signature on `/connect/endSession`** — the client is chosen from the `azp` claim of a JWT nobody verifies | `EndSessionHandler` (5b-2a) | [security-debt list](phase-5-oauth2.md#parity-preserved-security-debts--reproduce-now-fix-later); pinned by `EndSessionHandlerTest#theAzpClaimSelectsTheClientAndNoSignatureIsVerified` |
| T3 | **301 (permanent, cacheable) login redirect** on unauthenticated `/authorize`, where a 302 would be correct | `AuthorizeHandler` (5b-1) | [security-debt list](phase-5-oauth2.md#parity-preserved-security-debts--reproduce-now-fix-later) |
| T4 | **`templates/touch/authorize.ftl:56` emits `isplayName`**, so `?display=touch` renders a blank client name in the consent `<h1>` | golden, verbatim | Noted under the divergence table above — **not** a divergence; do not "fix" it during the flip |

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
   - Repoint the `REALM_OBJECT` readers/writers off the deleted `RestletRealmRouter.REALM_OBJECT`
     onto the surviving `OAuth2Constants.Custom.REALM_OBJECT` (seeded by `ChfOAuth2Request` since
     Phase 4a; the two constants share the literal `"realmObject"` and Phase 4a left a note on the
     survivor). Sites: `OAuth2UrisFactory:68`, `UmaUrisFactory:83`, `RealmRoutingFactory:22/248-263`,
     `IdTokenInfo:193`. After this, delete `RestletRealmRouter` with the module.
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
