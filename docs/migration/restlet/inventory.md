# Restlet Usage Inventory

Research findings for the Restlet → CHF migration. Captured 2026-07-08 on branch
`features/restlet-migration` (== `master`, commit `74b471b428`). Companion document:
[plan.md](plan.md).

## 1. Summary

OpenAM serves four URL areas on Restlet 2.4.4: `/oauth2/*` (all OAuth2/OIDC protocol
endpoints), `/uma/*`, `/xacml/*`, and `/.well-known/*` (WebFinger). ~105 production Java
files import `org.restlet`. Restlet is abandoned upstream (no jakarta release), so the
repo maintains a **vendored jakarta-transformed fork** plus a hand-ported servlet bridge
module (`openam-restlet`). The rest of the REST surface (`/json`, `/frrest`, REST STS)
already runs on ForgeRock **CHF** (`org.forgerock.http`) + **CREST**
(`org.forgerock.json.resource`); `RestletRealmRouter` is `@Deprecated` in favor of CHF's
`RealmRoutingFactory`, and `openam-rest/pom.xml` carries the comment *"TODO required
until Restlet endpoints are moved to CHF"* — CHF is the codebase's own declared target.

Baseline: Java 11 (`maven.compiler.source/target`), fully `jakarta.servlet` (0 files on
`javax.servlet`), Guice DI (`InjectorHolder`), TestNG + Mockito tests.

## 2. Dependency topology

- Root `pom.xml`: `<restlet.version>2.4.4</restlet.version>` (~line 87);
  `dependencyManagement` pins all Restlet artifacts (~lines 1390–1465); restlet
  `excludeArtifact` entries around lines 238–242; upstream artifacts pulled from
  `https://maven.restlet.talend.com`.
- **Two flavors in use:**
  - `org.openidentityplatform.openam.jakarta` : `org.restlet`, `.ext.jackson`,
    `.ext.json`, `.ext.xml`, `.ext.servlet` — version `${project.version}`, i.e. **built
    in-tree** by `transform-jakarta/restlet-parent-jakarta/` (5 submodules; Eclipse
    Transformer rewrites upstream `org.restlet.jee:*:2.4.4` javax bytecode to jakarta).
  - `org.restlet.jee` 2.4.4 upstream (javax): `.ext.freemarker`, `.ext.ssl`,
    `.ext.simple`, `.ext.crypto`, `.ext.httpclient`, `.ext.net`, `.ext.slf4j`.
- Modules declaring Restlet deps: `openam-restlet`, `openam-oauth2`,
  `openam-oauth2-saml2`, `openam-rest`, `openam-uma`, `openam-http-client`,
  `openam-sts/openam-soap-sts(-server)` (transitive/runtime only — **no Java imports**).

## 3. Restlet imports by module (main sources)

| Module | Files | Packages |
|---|---|---|
| openam-oauth2 | ~65 | `org.forgerock.oauth2.restlet` (28), `org.forgerock.openidconnect.restlet` (10), **`org.forgerock.oauth2.core` (7 — the leak)**, `org.forgerock.openam.oauth2*` (15), `org.forgerock.openam.rest.audit` (3) |
| openam-restlet | ~13 | `org.forgerock.openam.rest.jakarta.servlet(.internal)` (jakarta ServerServlet port), `org.forgerock.openam.rest.service`, `.representations`, `.router` |
| openam-rest | ~10 | `org.forgerock.openam.rest.service` (ServiceEndpointApplication hierarchy, RestletServiceServlet, StatusServices), `.rest.audit`, `RestEndpointServlet`, `RealmRoutingFactory` (Restlet branch) |
| openam-uma | ~10 | `org.forgerock.openam.uma`, `.uma.rest`, `.uma.audit` |
| openam-entitlements | 3–5 | `org.forgerock.openam.xacml.v3.rest` (XacmlService), `.entitlement.rest` (XacmlRouterProvider), `.entitlement.guice` |
| openam-oauth2-saml2 | 1 | `Saml2BearerServerResource` — **dead code** (nothing routes it; SAML2 bearer grant flows via `Saml2GrantTypeHandler` in the token endpoint's grant map) |
| openam-http-client | 1 | `org.forgerock.http.client.RestletHttpClient` — **outbound** client for scripted auth modules |
| openam-core-rest | 1 | `AuthenticationServiceV1` — vestigial import only (unused `org.restlet.resource.ResourceException` + javadoc ref) |
| openam-federation/OpenFM | 1 | `DefaultWsFedAuthenticator` — vestigial unused imports only |

Test sources: ~17 files import `org.restlet` (openam-oauth2, openam-uma, openam-rest,
openam-entitlements, openam-restlet).

Most-used Restlet types: `Request` (86), `Response` (42), `Representation` (42),
`data.Status` (26), `ServerResource` (25), `JacksonRepresentation` (18),
`routing.Router` (17), `JsonRepresentation` (16), `data.Form` (10), `routing.Filter` (7),
`ChallengeScheme`/`ChallengeResponse` (7 each). (Note: `ChallengeResponse` hits in
`openam-schema/openam-liberty-schema` are SAML JAXB — false positives.)

## 4. Entry points and request flow

All in `openam-server-only/src/main/webapp/WEB-INF/web.xml` (the `openam-server` WAR
overlays it):

```
/oauth2/*  ─┐
/uma/*     ─┼→ servlet ForgeRockRest = o.f.openam.rest.RestEndpointServlet (plain HttpServlet)
/xacml/*   ─┘     ├ /oauth2 → RestletServiceServlet(OAuth2ServiceEndpointApplication)
                  ├ /uma    → RestletServiceServlet(UMAServiceEndpointApplication)
                  └ /xacml  → HttpFrameworkServlet(RestletAuthnHttpApplication)
                              = CHF chain: @Named("AuthenticationFilter") (CAF)
                                → RestletHandler → RestletServiceServlet(XACMLServiceEndpointApplication)
                              (an existing CHF→Restlet bridge, proves the CHF filter chain works here)

/.well-known/* → servlet WebFinger = org.restlet.ext.servlet.ServerServlet
                  (org.restlet.application = o.f.openidconnect.restlet.WebFinger; RIAP/CLAP clients)

/json/*, /frrest/oauth2/*, /rest-sts/*, /sts-publish/*, /sts-tokengen/*
               → servlet OpenAM = org.forgerock.http.servlet.HttpFrameworkServlet
                  application-loader=guice, **routing-base=context_path** (web.xml ~line 1097)
                  → Guice HttpApplication = OpenAMHttpApplication (openam-http)
                  → HttpRouterProvider: ServiceLoader over o.f.openam.http.HttpRouteProvider SPI

/ws/*, /federationws/* → Jersey (JAX-RS, com.sun.identity.rest.*) — unrelated legacy stack
```

`RestletServiceServlet extends ServerServlet` — the **custom jakarta port** in
`openam-restlet` (`org.forgerock.openam.rest.jakarta.servlet.ServerServlet` +
`ServletCall`, `ServletWarClient(Helper)`, `ServletWarEntity`, `ServletUtils`).
`ServletUtils.getRequest(restletRequest)` is the Restlet⇄HttpServletRequest bridge used
throughout.

**`routing-base=context_path` is the strangler lever**: `HttpRouteProvider`s route on the
leading path segment (e.g. `RestHttpRouteProvider` → `newHttpRoute(STARTS_WITH, "json")`),
so an area migrates by adding a provider for its segment and moving its
`<servlet-mapping>` from `ForgeRockRest` to `OpenAM`. Multiple mappings on one servlet
are already used (5 today).

## 5. Route tables

### /oauth2 — `OAuth2RouterProvider` (openam-oauth2, Guice `Router @Named("OAuth2Router")`)

Root router = `new RestletRealmRouter()` + recursive `realms/{realmId}` route via
`RealmRoutingFactory().createRouter(router)`. Every route wrapped in
`OAuth2AccessAuditFilter` with per-route `RestletBodyAuditor`s:

| Route | Target (all Restlet ServerResources unless noted) |
|---|---|
| `/authorize` | `AuthorizeEndpointFilter` → `AuthorizeResource` |
| `/access_token` | `TokenEndpointFilter` → `AccessTokenFlowFinder` (`OAuth2FlowFinder` picks handler by `grant_type`; errors → `ErrorResource`) |
| `/tokeninfo` | `ValidationServerResource` |
| `/introspect` | `TokenIntrospectionResource` |
| `/connect/register` | `ConnectClientRegistration` |
| `/userinfo` | `UserInfo` |
| `/idtokeninfo` | `IdTokenInfo` |
| `/connect/checkSession` | `OpenIDConnectCheckSessionEndpoint` |
| `/connect/endSession` | `EndSession` |
| `/connect/jwk_uri` | `OpenIDConnectJWKEndpoint` |
| `/resource_set`, `/resource_set/`, `/resource_set/{rsid}` | Guice `Restlet @Named(RSR_ENDPOINT)` = `ResourceSetRegistrationEndpoint` wrapped in `AccessTokenProtectionFilter` (**three distinct attachments incl. trailing slash**) |
| `/.well-known/openid-configuration` | `OpenIDConnectConfiguration` |
| `/device/user` | `DeviceCodeVerificationResource` |
| `/device/code` | `DeviceCodeResource` |
| `/token/revoke` | `TokenRevocationResource` |

### /uma — `UmaRouterProvider` (openam-uma, `Router @Named("UMARouter")`)

`RestletRealmRouter` + realm recursion; routes wrapped in `UMAAccessAuditFilter` +
`AccessTokenProtectionFilter` (scope-checked):
`/permission_request` → `PermissionRequestEndpoint`, `/authz_request` →
`AuthorizationRequestEndpoint`, `/.well-known/uma-configuration` →
`UmaWellKnownConfigurationEndpoint`. Errors via `UmaExceptionHandler`.
(UMA *policy management* is already CREST under `/json` — 21 files — only the protocol
endpoints are Restlet.)

### /xacml — `XacmlRouterProvider` (openam-entitlements, `Router @Named("XacmlRouter")`)

Routes `/policies` through `ResourceApiVersionRestlet` (version 1 — the **only** use of
API versioning on the Restlet side) to `XacmlService` (export `@Get` / import `@Post`;
`Content-Type: application/xacml+xml; version=3.0`; `Content-Disposition: attachment`;
reads authenticated caller from HttpServletRequest attribute
`org.forgerock.authentication.context` copied there by `RestEndpointServlet.RestletHandler`).
Errors via `XMLRestStatusService`.

### /.well-known — `WebFinger` Application (openam-oauth2)

Routes `/webfinger` → `OpenIDConnectDiscovery` (GET; `resource`/`rel` params; JRD JSON).

## 6. Restlet extension points in use

- **Applications**: `ServiceEndpointApplication` (abstract, openam-rest) →
  `OAuth2-`/`UMA-`/`XACMLServiceEndpointApplication`; `WebFinger`.
- **ServerResources (24)**: listed in route tables above, plus `RouterContextResource`
  (openam-restlet), `Saml2BearerServerResource` (dead).
- **Filters (6)**: `OAuth2Filter`, `AuthorizeEndpointFilter`, `TokenEndpointFilter`,
  `ResourceSetRegistrationExceptionFilter`, `AccessTokenProtectionFilter`,
  `AbstractRestletAccessAuditFilter` (base of `OAuth2AccessAuditFilter`,
  `UMAAccessAuditFilter`).
- **Custom Restlets**: `RestletRealmRouter` (@Deprecated), `ResourceApiVersionRestlet`,
  `RealmRoutingFactory`'s inner Restlet router, `GuicedRestlet` +
  `RestletUtils.wrap(...)` (per-request `ServerResource` construction via
  `InjectorHolder`).
- **StatusServices** (exception→HTTP mapping): `OAuth2StatusService`,
  `RestStatusService`/`JSONRestStatusService`/`XMLRestStatusService`.
- **Representations**: `JacksonRepresentation` via `JacksonRepresentationFactory`
  (openam-restlet) for JSON; `org.restlet.ext.freemarker.TemplateRepresentation` +
  `TemplateFactory`/`ContextTemplateLoader` for HTML.
- **Engine internals referenced** (hotspots): `engine.adapter.HttpRequest`/`ServerCall`,
  `engine.header.*`, `engine.local.*`, `engine.io.Unclosable*Stream`, `engine.Engine`.

## 7. Coupling analysis — where Restlet leaks past the adapter layer

- **`org.forgerock.oauth2.core.OAuth2Request`** wraps `org.restlet.Request` directly
  (despite javadoc claiming transport-agnosticism). Parameter precedence: **request
  attributes → query params (`resourceRef.getQueryAsForm`) → POST form body
  (`new Form(entity)` then re-`setEntity` to keep the body readable) → POST JSON body**.
  `getParameterCount` counts *query-string* duplicates only (relied on by
  `DuplicateRequestParameterValidator`). `getLocale()` via
  `ServletUtils.getRequest(request).getLocale()`. `getEndpointType()` computes the
  path-after-realm using the `RestletRealmRouter.REALM_URL` request attribute. The
  "attributes" tier serves Restlet URI template variables + realm (`realm`, `rsid`,
  `realmId`) and handler-written values.
- `OAuth2RequestFactory` creates/caches it per request (servlet request attribute
  `OAUTH2_REQ_ATTR`), pre-resolves the client registration.
- ~7 `oauth2.core` classes import `org.restlet` directly: `OAuth2Request`,
  `OAuth2RequestFactory`, `ResourceOwnerAuthenticator`, `TokenInfoService`,
  `CsrfProtection`, `ResourceOwnerSessionValidator`, `ClientAuthenticator`.
- `AccessTokenVerifier` bindings are Restlet-specific: `RestletHeaderAccessTokenVerifier`,
  `RestletFormBodyAccessTokenVerifier`, `RestletQueryParameterAccessTokenVerifier`
  (bound in `OAuth2GuiceModule` ~lines 180–183 and realm-agnostic `@Provides` ~312–334).
- Client authentication parses Restlet `ChallengeScheme`/`ChallengeResponse`:
  `ClientCredentialsReader` (also keys token-endpoint rules off
  `req.getResourceRef().getLastSegment().equals(ACCESS_TOKEN)`), `OAuth2Utils`,
  `OpenAMClientAuthenticationFailureFactory`, `ConnectClientRegistration` (raw Bearer).
- **Error/HTML layer**: `OAuth2RestletException` (status + error + redirectUri + state,
  `asMap()` = JSON body); `ExceptionHandler` → `Redirector.MODE_CLIENT_PERMANENT`
  (**301**) for auth-required redirects, `MODE_CLIENT_FOUND` (**302**) for error
  redirects to `redirect_uri` (fragment vs query per `UrlLocation`), JSON otherwise, or
  rendered `page/error.ftl`; `OAuth2Representation` → **302** success redirects and
  FreeMarker consent pages (`templates/{page|popup|touch|wap}/authorize.ftl`,
  `error.ftl`, `popup.ftl`, `checkSession.ftl`, `FormPostResponse.ftl`,
  `CodeVerificationForm.ftl`, `CodeThanks.ftl`); `EndSession` → **302**.

## 8. The replacement stack already in-repo (reuse targets)

- **CHF servlet + SPI**: `HttpFrameworkServlet` (`OpenAM` servlet) →
  `OpenAMHttpApplication`/`HttpGuiceModule`/`HttpRouterProvider` (openam-http) →
  `org.forgerock.openam.http.HttpRouteProvider` implementations registered via
  `META-INF/services/org.forgerock.openam.http.HttpRouteProvider`. Existing examples:
  `RestHttpRouteProvider` (/json, openam-rest), `OAuth2RestHttpRouteProvider`
  (/frrest/oauth2, openam-oauth2 — a services file already exists in this module),
  three STS providers.
- **Annotated-POJO handler shape**: `org.forgerock.openam.http.annotations.Endpoints.from(Class)`
  with `@Get/@Post/@Put/@Delete` (+ `Contextual`, `Consumes`/`Produces`,
  `PayloadTranslator`) — proven by `AuthenticationServiceV1/V2`
  (`CoreRestAuthenticationGuiceModule` lines 76–77).
- **Realm routing**: `RealmRoutingFactory.createRouter(Handler)` (recursive
  `realms/{realmId}`, builds `RealmContext`), `createHostnameFilter()` (DNS alias), and
  `RealmContextFilter` (openam-rest — legacy path realms `/oauth2/subrealm/...`, realm
  aliases, `?realm=` override; battle-tested on `/json`). Wiring pattern to copy:
  `RestGuiceModule.getChfRootRouter()` (~lines 170–195).
- **CAF authentication**: CHF `Filter @Named("AuthenticationFilter")`
  (`RestGuiceModule` ~131–142) — needed by `/xacml`; `/oauth2` + `/uma` do their own
  OAuth2 auth.
- **API version routing**: `resourceApiVersionContextFilter` +
  `RouteMatchers.requestResourceApiVersionMatcher` (used for `/json`,
  `RestGuiceModule` ~124–129).
- **Audit**: `AbstractHttpAccessAuditFilter` + `HttpAccessAuditFilterFactory`
  (openam-audit-core, CHF-native). Missing vs Restlet filters: OAuth2/UMA
  userId/trackingIds extraction and per-route request/response **body** detail
  (`RestletBodyAuditor`) — must be ported.
- **FreeMarker 2.3.31** is a direct dependency of openam-oauth2
  (`org.freemarker:freemarker`, independent of `org.restlet.jee:org.restlet.ext.freemarker`).
- **XML error rendering**: `XMLResourceExceptionHandler.asXMLDOM` (openam-rest,
  restlet-free) for the XACML error filter.

## 9. Guice bindings that change/die

| Binding | Module | Fate |
|---|---|---|
| `Router @Named("OAuth2Router")` → `OAuth2RouterProvider` | OAuth2RestGuiceModule | delete (replaced by `OAuth2HttpRouteProvider`) |
| `Router @Named("UMARouter")` → `UmaRouterProvider` | UmaGuiceModule | delete |
| `Router @Named("XacmlRouter")` → `XacmlRouterProvider` | EntitlementRestGuiceModule | delete |
| `Restlet @Named(RSR_ENDPOINT)` (~line 395) | OAuth2GuiceModule | re-type to CHF `Handler` |
| `Restlet @Named(PERMISSION_REQUEST_ENDPOINT / AUTHORIZATION_REQUEST_ENDPOINT)` | UmaGuiceModule | re-type to CHF `Handler` |
| 3 × `Restlet*AccessTokenVerifier` bindings | OAuth2GuiceModule | rebind to transport-neutral impls |

## 10. Outbound Restlet clients

- `org.forgerock.http.client.RestletHttpClient` (openam-http-client): base of the
  scripted-auth HTTP client. Subclasses `JavaScriptHttpClient`/`GroovyHttpClient`
  (openam-scripting, bound in `ScriptingGuiceModule`); consumers `Scripted`
  (openam-auth-scripted) and `ScriptCondition` (openam-entitlements). Public surface to
  preserve: `getHttpClientResponse(uri, body, requestData, method)` +
  `HttpClientRequest/Response/Cookie` beans.
- `DefaultWsFedAuthenticator` (OpenFM): restlet imports are **unused** — cleanup only.

## 11. Tests & CI

- Unit tests: TestNG + Mockito; Restlet `Request`/`Response` are **mocked** (no embedded
  Restlet server anywhere). Representative: `AuthorizeResourceTest`,
  `OAuth2RequestFactoryTest`, `ClientCredentialsReaderTest`,
  `ResourceSetRegistrationEndpointTest` (openam-oauth2, 33 test files);
  `PermissionRequestEndpointTest`, `AuthorizationRequestEndpointTest`,
  `UmaWellKnownConfigurationEndpointTest` (openam-uma, 21); `RestletRealmRouterTest`,
  `JacksonRepresentationFactoryTest` (openam-restlet); `RestRouterIT` (openam-rest).
  CHF protocol objects are concrete classes — ported tests construct
  `new Request().setMethod(...).setUri(...)` and context chains
  (`RootContext → AttributesContext → RealmContext → UriRouterContext`) instead of mocking.
- Integration: Cargo-based Tomcat tests in openam-server
  (`CargoBaseTest`, `IT_Setup`, `IT_SetupWithOpenDJ`), enabled by profile
  `-P integration-test` (defined in `openam-server/pom.xml`); CI runs it on
  ubuntu only and adds `127.0.0.1 openam.local` to `/etc/hosts`.
- CI: `.github/workflows/build.yml` — JDK 11/17/21/25/26 × 3 OSes,
  `mvn verify`; builds pushes to `features/**` (this branch included).

## 12. Deletion checklist (final state)

- Module `openam-restlet` (relocate `RestRealmValidator` → openam-rest first; it is used
  by CHF `RealmContextFilter`).
- `transform-jakarta/restlet-parent-jakarta/` (5 submodules) + its `<module>` entry.
- Root pom: `restlet.version` property, all
  `org.openidentityplatform.openam.jakarta:org.restlet*` and `org.restlet.jee:*`
  dependencyManagement entries, restlet `excludeArtifact` lines, talend repo (if restlet-only),
  `<module>openam-restlet</module>` (~line 283), openam-restlet dependencyManagement
  entry (~line 665).
- web.xml: `ForgeRockRest` servlet + mappings, `WebFinger` ServerServlet block.
- Classes: `RestEndpointServlet`, `RestletServiceServlet`, `ServiceEndpointApplication`
  hierarchy, StatusServices, `AbstractRestletAccessAuditFilter`, `RestletBodyAuditor`,
  Restlet branch of `RealmRoutingFactory`, all `*.restlet.*` packages, dead
  `Saml2BearerServerResource`.
- Gates: `grep -rn "org.restlet" --include="*.java" .` → 0 outside docs;
  `grep -rn restlet --include=pom.xml .` → 0.
