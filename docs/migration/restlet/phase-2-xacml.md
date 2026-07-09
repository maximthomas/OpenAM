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
(HttpRouteProvider + `Endpoints.from` handler + realm routing + version matching + CAF auth +
XML error rendering) that phases 3–8 reuse.

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
- **Auth caller — faithful, from `AttributesContext`.** After the CAF
  `@Named("AuthenticationFilter")` runs, the auth map is on `AttributesContext` under key
  `org.forgerock.authentication.context` (constant
  `AuthenticationFramework.ATTRIBUTE_AUTH_CONTEXT`). Handler reads `tokenId` from it and
  `SSOTokenManager.getInstance().createSSOToken(tokenId)` — identical to today, minus the
  servlet-attribute copy. No `SecurityContext`/`HttpContextFilter` introduced.
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
- **API version.** `@Named("ResourceApiVersionFilter")` (`resourceApiVersionContextFilter`)
  in the chain; endpoint router matches `policies` with
  `RouteMatchers.requestResourceApiVersionMatcher(version(1))` → `Endpoints.from(XacmlServiceHandler)`.
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
- Route wiring is exercised by the Cargo IT smoke (below), matching how existing providers
  are covered (`RestRouterIT`-style).

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
4. Manual smoke against a running WAR (record pre-change curl, diff after):
   - `GET /openam/xacml/policies` — admin cookie → `200` XACML XML + `Content-Type:
     application/xacml+xml; version=3.0` + `Content-Disposition: attachment; filename=realm-policies.xml`;
     no cookie → CAF `401`.
   - `GET /openam/xacml/realms/root/policies` and legacy `/openam/xacml/<subrealm>/policies`
     and `?realm=` override — realm parity.
   - `POST /openam/xacml/policies` import round-trip (+ `?dryrun=true`), empty doc → `400` XML.
   - `?filter=` (multi-valued) export.
   - Error → XML `<error>` body (e.g. non-admin READ → `403`; `PUT` → `405` XML).
5. CI (`.github/workflows/build.yml`) runs JDK 11–26 × 3 OSes on the `features/**` push.

## Phase-2 parity checklist (subset of [plan.md](plan.md) risk register)

| Item | Guard |
|---|---|
| XML error bodies (incl. 405/500) | `XacmlXmlErrorFilter` + `XacmlXmlErrorFilterTest` |
| `application/xacml+xml; version=3.0` + `Content-Disposition` | explicit headers + handler test asserts |
| Delegation permission identity (`realm`,`rest`,`1.0`,`policies`) | verbatim port; audit component string pinned |
| Auth caller (`tokenId` → SSOToken) from CAF context | read `AttributesContext` auth map; no-cookie → 401 smoke |
| Realm styles (root / `realms/{id}` / legacy path / alias / `?realm=`) | mirror `getChfRootRouter()`; per-style smoke |
| Version routing (`version(1)` on `policies`) | `requestResourceApiVersionMatcher` |
| Locale for localized messages | `AcceptLanguageHeader`; smoke-verify vs `getLocale()` |

## Execution order

pom/dep → `XacmlXmlErrorFilter` (+test) → `XacmlServiceHandler` (+test) →
`XacmlHttpRouteProvider` + services file → `EntitlementRestGuiceModule` edit → web.xml flip →
strip `RestEndpointServlet` xacml branch → delete 5 classes → `mvn -pl ... test` → whole
build → Cargo IT → smoke → create `docs/migration/restlet/chf-patterns.md` + mark Phase 2
`done` in [plan.md](plan.md).
