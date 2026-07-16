# Phase 2 — XACML `/xacml` → CHF: Detailed Implementation Plan

Detailed execution plan for Phase 2 of the Restlet → CHF migration. Parent tracker:
[plan.md](plan.md); research: [inventory.md](inventory.md); decisions: [decisions.md](decisions.md).
Written 2026-07-08; branch `features/restlet-migration`.

## Context

Part of the Restlet → CHF strangler migration. Phase 1 (docs) is done. Phase 2 moves the
smallest URL area — `/xacml/*` (policy export/import) — off Restlet onto ForgeRock CHF.
XACML is the ideal first cut: it has **no `OAuth2Request` coupling**, it is the only Restlet
area already fronted by a CHF→Restlet CAF-auth bridge (so the auth chain is proven), and it
is a single POST/GET resource. Landing it proves the end-to-end CHF pattern
(HttpRouteProvider + `Endpoints.from` handler + realm routing + CAF auth + XML error rendering)
that phases 3–8 reuse. Version matching is deliberately **not** part of the pattern proven here —
see the API version item under Design, which records why `/xacml` must stay unversioned.

**Outcome:** `/xacml/*` served natively by the `OpenAM` `HttpFrameworkServlet` via a new
`HttpRouteProvider`; the Restlet XACML classes and the CHF→Restlet bridge for `/xacml`
deleted; behavior (status codes, headers, XML error bodies, delegation permission checks,
audit) preserved.

## Scope & sizing

Single shippable green commit. ~4 new files, ~3 modified, 5 deleted, 2 test files
reworked + 1 test deleted. This is a normal PR-sized unit — **no further splitting needed**.
`/oauth2` and `/uma` remain on Restlet (later phases); `RestEndpointServlet` stays but
loses its xacml branch.

## Key finding that shapes the design

`Endpoints.from` (`openam-http/.../http/annotations/Endpoints.java` + `AnnotatedMethod.java`)
**does not preserve a thrown business exception** — any exception escaping a handler method
becomes a bare `500` (status only) or a generic `InternalServerErrorException` JSON body;
the status/reason of a thrown `ResourceException` is lost. Therefore the migrated handler
**must return `Response` objects for error cases, never throw**.

Conveniently, the framework's own fallbacks already emit **CREST error-map JSON entities**:
`405` → `new NotSupportedException().toJsonValue().getObject()`, `500` →
`new InternalServerErrorException(t).toJsonValue().getObject()`. So if the handler also
returns its business errors as CREST error maps (`ResourceException.toJsonValue().getObject()`),
a **single filter** that rewrites any `≥400` response carrying a CREST error map into the
XML `<error>` form reproduces the old `XMLRestStatusService` for **every** error path
(business, 405, 500) — this is the clean realization of the planned `XacmlXmlErrorFilter`.

## Design decisions

- **Error rendering — full parity.** Handler returns CREST error maps for business errors;
  `XacmlXmlErrorFilter` converts every `≥400` CREST-error-map response to XML `<error>`
  via the framework-neutral `XMLResourceExceptionHandler.asXMLDOM(map)`
  (`openam-rest/.../forgerockrest/utils/XMLResourceExceptionHandler.java`), `Content-Type:
  application/xml` — matching today's `XMLRestStatusService` (`DomRepresentation(APPLICATION_XML, …)`),
  including the 405/500 fallbacks.
- **Auth caller — from `AttributesContext`, behind a filter that requires a token.** After the CAF
  authentication filter runs, the auth map is on `AttributesContext` under key
  `org.forgerock.authentication.context` (constant
  `AuthenticationFramework.ATTRIBUTE_AUTH_CONTEXT`). Handler reads `tokenId` from it and
  `SSOTokenManager.getInstance().createSSOToken(tokenId)` — identical to today, minus the
  servlet-attribute copy. No `SecurityContext`/`HttpContextFilter` introduced.

  **Corrected 2026-07-16.** This route uses `@Named("RequiredAuthenticationFilter")`, *not* the
  `@Named("AuthenticationFilter")` that `/json` uses. The latter is built on
  `OptionalSSOTokenSessionModule`, which admits a request carrying no token so that endpoints like
  `/json/authenticate` are reachable; the handler would then read a null `tokenId` and report the
  missing credential as a `500` from `createSSOToken(null)`. Restlet had the identical defect — this
  is not a migration regression — but it was fixed here rather than carried forward, so a missing or
  expired token is now a `401` from the framework. See
  [phase-2-integration-tests.md](phase-2-integration-tests.md#the-401-that-was-a-500). The `/json`,
  OAuth2 and STS routes still use the optional filter and are unchanged.
- **Realm — `RealmContext`, superset routing.** Handler reads
  `context.asContext(RealmContext.class).getRealm().asPath()` (replaces
  `RestletRealmRouter.getRealmFromRequest`). Route mirrors `RestGuiceModule.getChfRootRouter()`:
  recursive `realms/{realmId}` route (`RealmRoutingFactory.createRouter` + `createHostnameFilter`)
  **and** a default route with `RealmContextFilter` (legacy path realm `/xacml/sub/policies`,
  realm alias, `?realm=`, DNS alias). This is a **superset** of the old Restlet behavior
  (adds modern `/xacml/realms/{realmId}/policies`), consistent with `/json` and matching the
  plan's smoke matrix.
- **Permission parity.** `urlLastSegment` = last path segment of `request.getUri().getPath()`
  = `"policies"` (confirmed from `XacmlService.checkPermission` — it is the resource name, not
  a version). `DelegationPermissionFactory.newInstance(realm, "rest", "1.0", "policies",
  action, actions, emptyMap)` and `evaluator.isAllowed(...)` are ported **verbatim**. Audit
  component string preserved as `"org.forgerock.openam.xacml.v3.rest.XacmlService"` (constant,
  not `getClass().getName()`) so `RestLog` events don't drift.
- **API version — no gate (corrected 2026-07-16).** The endpoint router routes `policies` straight
  to `Endpoints.from(XacmlServiceHandler)` with **no** version matcher and **no**
  `@Named("ResourceApiVersionFilter")` in the chain. Any `Accept-API-Version` value is ignored, as
  under Restlet.

  This bullet originally specified `requestResourceApiVersionMatcher(version(1))` plus the shared
  version filter, and that is what shipped in `191b3ed346`. It was **wrong**, and
  `XacmlRouterIT` caught it. `/json` routes get a v1 gate by default
  (`Routers.ServiceRoute.toService()` → `forVersion(1)`), which makes them subject to the global
  *REST APIs → Default Version* setting (`RestApis.xml`, `openam-rest-apis-default-version`;
  Latest/Oldest/**None**, default Latest). Restlet's `/xacml` had no version gate and so was never
  subject to it. Under `None`, `ResourceApiVersionRouteMatcher.evaluate` returns no match for an
  unversioned request → **404 for every legacy XACML client** (ssoadm and the CLI-era exporters,
  none of which send the header). Fixed by removing the gate; see the comment in
  `XacmlHttpRouteProvider.get()` and the version cases in `XacmlRouterIT`.

  Note the gate is inert without the filter: absent an `ApiVersionRouterContext`, the matcher falls
  back to a hardcoded `LATEST`. Both must be present to reintroduce the bug, and both are guarded.
- **Locale.** Derive from `request.getHeaders().get(AcceptLanguageHeader.class)` →
  `getLocales().getPreferredLocale()`, default `Locale.getDefault()` (idiom from
  `AuthenticationServiceV1`). Used only for `EntitlementException.getLocalizedMessage(locale)`.
  Minor parity note vs `HttpServletRequest.getLocale()` — verify in smoke (low risk; English default).
- **Response bodies.** Export: write `PolicySet` via
  `XACMLPrivilegeUtils.writeXMLToStream(policySet, baos)` → `response.setEntity(bytes)`,
  `Content-Type: application/xacml+xml; version=3.0` (literal string constant; drop the
  Restlet `MediaType.register`), `Content-Disposition: attachment; filename=<name>` (same
  `getPolicyAttachmentFileName` logic). Import: `response.setEntity(List<Map<String,String>>)`
  (CHF serializes to JSON; drops `JacksonRepresentationFactory`), `Content-Type: application/json`,
  `200`; empty-doc → `400`.

## Work items

### New — openam-entitlements

1. **`org.forgerock.openam.xacml.v3.rest.XacmlServiceHandler`** — annotated POJO
   (replaces `XacmlService`). `@Inject` ctor keeps `XACMLExportImport`, `PrivilegedAction<SSOToken>`,
   `@Named("frRest") Debug`, `RestLog`, `DelegationEvaluator` (drop `JacksonRepresentationFactory`).
   - `@Get public Response exportXACML(@Contextual Context ctx, @Contextual Request req)`
   - `@Post public Response importXACML(@Contextual Context ctx, @Contextual Request req)`
     (read body via `req.getEntity().getRawContentInputStream()`/`newDecodedContentReader`;
     `dryrun`/`filter` via `new Form().fromRequestQuery(req)` — `.getFirst("dryrun")`,
     `.get("filter")`).
   - Port `checkPermission(...)` chain verbatim; realm from `RealmContext`, tokenId from
     `AttributesContext` auth map. Keep the `@VisibleForTesting boolean
     checkPermission(DelegationPermission, SSOToken, String)` seam for tests. Every error
     path returns `new Response(status).setEntity(<CREST error map>)` using CHF
     `ForbiddenException`/`BadRequestException`/`InternalServerErrorException`.
2. **`org.forgerock.openam.xacml.v3.rest.XacmlXmlErrorFilter`** — `org.forgerock.http.Filter`;
   after `next.handle(...)`, if `status.getCode() ≥ 400` and entity is a CREST error map,
   replace entity with serialized `XMLResourceExceptionHandler.asXMLDOM(map)` and set
   `Content-Type: application/xml`.
3. **`org.forgerock.openam.entitlement.rest.XacmlHttpRouteProvider`** — `implements
   HttpRouteProvider`; `@Inject` setter injection (mirror `OAuth2RestHttpRouteProvider`) for
   `@Named("AuthenticationFilter") Filter`, `@Named("ResourceApiVersionFilter") Filter`,
   `RealmRoutingFactory`, `RealmContextFilter`, `XacmlXmlErrorFilter`,
   `@Named("InvalidRealmNames") Set<String>`. `get()` builds: endpoint router
   (`requestUriMatcher(EQUALS,"policies")` → version router `version(1)` →
   `Endpoints.from(XacmlServiceHandler.class)`), inner chain
   `Handlers.chainOf(endpointRouter, resourceApiVersionFilter, authenticationFilter)`, realm wrapper
   mirroring `getChfRootRouter()`; `invalidRealmNames.add("policies")`; wraps the whole route in the
   XML error filter (`Handlers.chainOf(root, xacmlXmlErrorFilter)`) so realm-resolution errors are
   XML too; returns `singleton(newHttpRoute(STARTS_WITH, "xacml", chain))`.
4. **`openam-entitlements/src/main/resources/META-INF/services/org.forgerock.openam.http.HttpRouteProvider`**
   — one line: `org.forgerock.openam.entitlement.rest.XacmlHttpRouteProvider`.
5. **pom** — add explicit `openam-http` dependency to `openam-entitlements/pom.xml` if the
   CHF/openam-http types aren't resolvable directly (currently transitive via `openam-rest`;
   add for hygiene).

### Modified

- **`openam-server-only/src/main/webapp/WEB-INF/web.xml`** (~line 1129) — move `/xacml/*`
  from the `ForgeRockRest` servlet mapping to a new mapping under the `OpenAM`
  (`HttpFrameworkServlet`, `routing-base=context_path`) servlet.
- **`openam-rest/.../rest/RestEndpointServlet.java`** — drop the xacml branch in `service()`,
  the `restletXACMLServiceServlet`/`restletXACMLHttpServlet` fields, the `authenticationFilter`
  field, and the inner classes `RestletAuthnHttpApplication`, `RestletHandler`, `HttpServletWrapper`
  (all xacml-only). Servlet keeps serving `/oauth2` + `/uma`.
- **`openam-entitlements/.../entitlement/guice/EntitlementRestGuiceModule.java`** — remove the
  `Router @Named("XacmlRouter")` → `XacmlRouterProvider` binding (other entitlement bindings
  untouched).

### Deleted

- `openam-entitlements/.../xacml/v3/rest/XacmlService.java`
- `openam-entitlements/.../entitlement/rest/XacmlRouterProvider.java`
- `openam-rest/.../rest/service/XACMLServiceEndpointApplication.java`
- `openam-rest/.../rest/service/XMLRestStatusService.java`
- `openam-rest/.../rest/service/XMLRestStatusServiceTest.java` (dies with its SUT; port its
  XML-body assertions into `XacmlXmlErrorFilterTest`)

Reference check confirms no other production references to these classes. `RestStatusService`
(base) and `JSONRestStatusService` stay (still used by `/oauth2`/`/uma`).

### Tests (TestNG + Mockito; drop the JUnit4/PowerMock outlier)

- **`XacmlServiceHandlerTest`** (rewrite of `XacmlServiceTest` + `XacmlServiceTestWrapper`) —
  build `RootContext → AttributesContext` (seed auth-context map with `tokenId`) `→ RealmContext`
  (`new RealmContext(parent, realm)` via `RealmTestHelper.mockRealm(...)` / `Realm.root()`;
  `setupRealmClass`/`tearDownRealmClass` in `@BeforeMethod`/`@AfterMethod`), real
  `new Request().setMethod(...).setUri(...)`. Assert `Response.getStatus()`, headers
  (`Content-Type`, `Content-Disposition`), export XACML XML bytes, import JSON array, and the
  business-error CREST maps. Port the three permission tests against the surviving
  `checkPermission(DelegationPermission, SSOToken, String)` seam (`verify(restLog).auditAccessGranted/Denied`).
  Subclass the handler to stub token acquisition (as the old wrapper stubbed `checkPermission`).
  Models: `AuthenticationServiceV2Test`, `RealmContextFilterTest`, `PrivilegeAuthzModuleTest`.
- **`XacmlXmlErrorFilterTest`** (new) — a `403`/`400`/`405`/`500` CREST-error-map response →
  XML `<error>` with `code`/`reason`/`message` + `Content-Type: application/xml` (absorbs
  `XMLRestStatusServiceTest` assertions).
- **`XacmlRouterIT`** (new, layer 2) — dispatches through the real `XacmlHttpRouteProvider`
  composition: root/legacy-path/`realms/root` realm styles, the absence of version routing, the
  `405` → XML fallback, `404` for unknown endpoints, and the `InvalidRealmNames` registration.
  See [phase-2-integration-tests.md](phase-2-integration-tests.md).
- Route wiring is **not** exercised by the Cargo IT smoke, contrary to this plan's original claim:
  the only container ITs are `IT_Setup`/`IT_SetupWithOpenDJ`, which drive the installer UI through
  Selenium and never call `/xacml`. That run proves the WAR boots (a broken Guice binding would fail
  startup) and nothing more.

### Research artifact (reusable for later phases)

The CHF target-stack patterns discovered here (HttpRouteProvider SPI + ServiceLoader +
`injectMembers`; `Endpoints.from` method/return/exception semantics; realm routing;
`@Named` auth/version filters; error-map→body; CHF handler test scaffolding) are reused by
**every** later phase. As the first execution step, create
**`docs/migration/restlet/chf-patterns.md`** capturing these with file-path anchors, and add a
reference line to it from [plan.md](plan.md)'s Phase 3+ sections.

## Verification

1. `mvn -pl openam-entitlements,openam-rest test` (no `-am` — heavy server modules stay out).
2. `mvn install -DskipTests` (whole reactor; confirms web.xml/WAR + no dangling refs).
3. Cargo IT (Linux; needs `127.0.0.1 openam.local` in `/etc/hosts`):
   `mvn -pl openam-server verify -P integration-test`.
4. **Automated, replacing the manual curl matrix this step used to list** — see
   [phase-2-integration-tests.md](phase-2-integration-tests.md):
   - `mvn -pl openam-entitlements verify` → `XacmlRouterIT` (13 cases): route composition, realm
     styles, the unversioned contract, `405` → XML. Runs on all 9 CI legs. Note `mvn test` will
     **not** run it — failsafe is bound at the root pom.
   - `cd e2e && npx playwright test xacml` → `xacml-test.spec.mjs` (15 cases): the same surface over
     the wire plus real auth (`401`/`403`), real XML serialization, and the import round-trip.
     Needs a running WAR; CI's `build-docker` job runs it unqualified. **15/15 verified against a
     live server** (local Docker mirroring `build.yml`'s IDP), including the `401` this phase fixed.
5. CI (`.github/workflows/build.yml`) runs JDK 11–26 × 3 OSes on the `features/**` push.

## Phase-2 parity checklist (subset of [plan.md](plan.md) risk register)

| Item | Guard |
|---|---|
| XML error bodies (incl. 405/500) | `XacmlXmlErrorFilter` + `XacmlXmlErrorFilterTest` |
| `application/xacml+xml; version=3.0` + `Content-Disposition` | explicit headers + handler test asserts |
| Delegation permission identity (`realm`,`rest`,`1.0`,`policies`) | verbatim port; audit component string pinned |
| Auth caller (`tokenId` → SSOToken) from CAF context | read `AttributesContext` auth map; `RequiredAuthenticationFilter` makes no-token a real `401` (was `500` under Restlet *and* as first shipped) — `e2e/xacml` asserts it |
| Realm styles (root / `realms/{id}` / legacy path / alias / `?realm=`) | mirror `getChfRootRouter()`; per-style smoke |
| Version routing (`version(1)` on `policies`) | `requestResourceApiVersionMatcher` |
| Locale for localized messages | `AcceptLanguageHeader`; smoke-verify vs `getLocale()` |

## Execution order

pom/dep → `XacmlXmlErrorFilter` (+test) → `XacmlServiceHandler` (+test) →
`XacmlHttpRouteProvider` + services file → `EntitlementRestGuiceModule` edit → web.xml flip →
strip `RestEndpointServlet` xacml branch → delete 5 classes → `mvn -pl ... test` → whole
build → Cargo IT → smoke → create `docs/migration/restlet/chf-patterns.md` + mark Phase 2
`done` in [plan.md](plan.md).
