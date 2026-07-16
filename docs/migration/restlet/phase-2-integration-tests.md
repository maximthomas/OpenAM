# Phase 2 — XACML `/xacml` → CHF: Integration Test Development Plan

Integration-test plan for the shipped Phase 2 migration. Implementation plan:
[phase-2-xacml.md](phase-2-xacml.md); parent tracker: [plan.md](plan.md); test-layer reference:
[../../test-infrastructure.md](../../test-infrastructure.md); CHF patterns: [chf-patterns.md](chf-patterns.md).
Written 2026-07-16; branch `features/restlet-migration`; Phase 2 landed as `191b3ed346`.

## Context

Phase 2 moved `/xacml/*` off Restlet onto CHF and is marked **done** in [plan.md](plan.md). It shipped
with two layer-1 unit tests:

- `XacmlServiceHandlerTest` — 12 tests, calls `handler.exportXACML(ctx, req)` / `importXACML(ctx, req)`
  **directly** with a hand-built `RealmContext`.
- `XacmlXmlErrorFilterTest` — 6 tests, calls `filter.filter(ctx, req, next)` **directly** with a stub next-handler.

Both are good, and neither dispatches a request. **Nothing exercises `XacmlHttpRouteProvider`** — the class
that composes CAF auth + realm routing + version matching + the XML error filter, and the one piece Phase 2
actually invented. This plan closes that gap.

### The guard that phase-2 claimed does not exist

[phase-2-xacml.md](phase-2-xacml.md) rests route-wiring coverage on two claims, both of which are false in
the tree as it stands:

1. *"Route wiring is exercised by the Cargo IT smoke (below), matching how existing providers are covered
   (`RestRouterIT`-style)"* — and Verification step 3, `mvn -pl openam-server verify -P integration-test`.
   Per [test-infrastructure.md](../../test-infrastructure.md), the only container ITs are `IT_Setup` and
   `IT_SetupWithOpenDJ`, which drive the **web installer UI through Selenium** and assert the console renders.
   They never touch `/xacml`. The Cargo run proves the WAR boots — nothing more. (It is not worthless: a
   `CreationException` from a broken Guice binding would fail startup. But it asserts no XACML behaviour.)
2. Verification step 4 — the realm/auth/error/`filter` matrix — is **manual curl**. The parity checklist rows
   "Realm styles … per-style smoke", "Auth caller … no-cookie → 401 smoke", and "Locale … smoke-verify" are
   guarded by a human, once, on one machine.

So the migration's highest-risk surface (routing, realm resolution, auth wiring, version matching) has no
automated guard at all, and the risk register's items 6, 7 and 9 are unenforced for `/xacml`.

**Outcome of this plan:** the Phase-2 parity checklist becomes executable in CI, and the resulting
Playwright spec becomes the regression net that Phases 4–5 inherit for their own flips.

## A parity risk that no existing test can see — CONFIRMED AS A BUG, FIXED

**Status: found by `XacmlRouterIT`, fixed 2026-07-16.** This section's hypothesis was right, and the
mechanism turned out to be slightly different from what is described below. Kept for the record.

Phase 2 put `requestResourceApiVersionMatcher(version(1))` in front of `policies`, plus the shared
`@Named("ResourceApiVersionFilter")` in the chain. **Restlet had no version gate at all.** So an
unversioned request — which is every existing XACML client, including the `ssoadm`/CLI-era consumers —
became subject to the deployment-wide *REST APIs → Default Version* setting.

What the investigation established:

1. **The gate is the house default, not an XACML invention.** `Routers.ServiceRoute.toService()`
   (`Routers.java:109-112`) routes every unversioned `/json` service through `forVersion(1)` — the same
   matcher. So this was Phase 2 following house style.
2. **`None` is one click away.** `openam-rest-apis-default-version` (`RestApis.xml:35-50`) is a global
   single-choice admin setting: Latest / Oldest / **None**, default Latest. Under `None`,
   `ResourceApiVersionRouteMatcher.evaluate` returns no match for an unversioned request → 404.
3. **So the regression is narrow but real:** `/xacml` lost its Restlet exemption from that setting. Its
   clients cannot be changed to send the header, so under `None` they would 404 with no recourse.
   Stock installs (Latest) were unaffected, which is why nothing else caught it.
4. **The gate was inert without the filter.** Absent an `ApiVersionRouterContext`, the matcher falls back
   to a hardcoded `LATEST` — CHF even carries a `//TODO should this blow up if ApiVersionRouterContext
   not present` at that spot. Deleting the filter alone changed no observable behaviour, which is how the
   first version of `XacmlRouterIT` passed while blind to it. Fixed by asserting `Content-API-Version`.

**Fix:** the version gate and the version filter are removed from `XacmlHttpRouteProvider`; `/xacml`
ignores `Accept-API-Version` entirely, as under Restlet. Consequences accepted deliberately:
`resource=2.0` now returns `200` (served v1, Restlet behaviour) rather than `404`, and no
`Content-API-Version` response header is sent. `/xacml` cannot be versioned later without a breaking
change — acceptable for a legacy endpoint being kept alive rather than evolved.

## The 401 that was a 500

**Status: found while writing deliverable 1, fixed 2026-07-16.** The case table below used to expect
`401` for an unauthenticated export. It does not, and did not, return `401`. Tracing it before writing
the assertion:

1. `/xacml` used `@Named("AuthenticationFilter")` (`RestGuiceModule:139`), which is built on
   `@Named("OptionalSsoTokenSession")` → `OptionalSSOTokenSessionModule`. That module exists to let
   `/json/authenticate` be reached without a token: it overrides `getInvalidSSOTokenAuthStatus()` to
   return `SUCCESS` where the base `LocalSSOTokenSessionModule` returns `SEND_FAILURE`.
2. So CAF admits the request and seeds `AttributesContext` with an **empty** auth map
   (`AuthenticationFramework:191-196`) — the module only fills it on the valid-token path.
3. `XacmlServiceHandler.checkPermission` reads `authContext.get("tokenId")` → `null` (no NPE), and
   `createSSOToken(null)` throws `SSOException` → `EntitlementException(INTERNAL_ERROR)` → **`500`**.
4. **Restlet did exactly the same.** `git show 191b3ed346^:.../XacmlService.java` reads the same
   `FORGEROCK_AUTH_CONTEXT` map, the same `tokenId`, the same `createSSOToken`, and maps
   `EntitlementException` to `INTERNAL_ERROR`. This was a pre-existing defect, **not** a migration
   regression, so the parity-only framing would have preserved it.

**Fix:** a new `@Named("RequiredAuthenticationFilter")` (`RestGuiceModule`), identical to the
existing one but built on a new `@Named("RequiredSsoTokenSession")` → `LocalSSOTokenSessionModule`,
which rejects a request with no usable token. `XacmlHttpRouteProvider` injects it. A missing or
expired token is now a framework `401`, rendered as XML by `XacmlXmlErrorFilter` (CAF's
`JsonResponseWriter` writes a `Map` entity, which is exactly what the filter rewrites).

Deliberately **not** applied to `/json`, OAuth2 or the two STS route providers, which still use the
optional filter: `/json` genuinely needs anonymous access, and the others are out of Phase 2's scope.
They are likely to have the same wart — worth a look, but not here.

Consequences: an unauthenticated (or expired-token) caller now gets `401` where it got `500`, and
`/xacml/<anything>` is `401` rather than `404` for such a caller, which also stops endpoint probing.

**Also settled:** the "`iPlanetDirectoryPro` header not accepted" risk below is a non-risk.
`LocalSSOTokenSessionModule:207-210` reads the cookie and **falls back to the header of the same
name**, so header auth works and no cookie fallback is needed.

## Layer decision

Per [test-infrastructure.md § Choosing a layer](../../test-infrastructure.md#choosing-a-layer):

| Layer | Verdict | Why |
|---|---|---|
| **4 — Playwright** (`e2e/`) | **Primary** | Only layer with a real server: real CAF auth, real `SSOToken`, real `DelegationEvaluator`, real XML serialization, real `Content-Type`/`Content-Disposition` over the wire. CI runs specs **unqualified**, so a new spec needs zero wiring. |
| **2 — in-process CHF IT** (`openam-entitlements`) | **Secondary** | Deterministic route-composition assertions (version matching, 405, `InvalidRealmNames`) with no container. Runs on **all 9 CI legs** via `verify`, so it carries the cross-JDK/cross-OS signal that layer 4 (Linux-only, one JDK) cannot. |
| **3 — Cargo container IT** | **Not used** | Fresh Tomcat per test method, Linux-only in CI, and layer 4 covers the same protocol surface far more cheaply. Keep the existing run as a boot check only. |

The two deliverables split cleanly on **auth**: layer 4 owns real authentication (401/403 paths); layer 2
stubs the auth filter and owns everything downstream of it. Neither duplicates the other.

---

## Deliverable 1 (primary) — `e2e/xacml/xacml-test.spec.mjs`

Model: `e2e/oauth2/oauth2-test.spec.mjs` (idempotent `ensure*` fixtures in `beforeAll`, `request` fixture,
no browser). Reuse `OPENAM_BASE`, `getAdminToken`, `getAuthToken`, `USERNAME`/`PASSWORD` from
`e2e/common/openam-commons.mjs` — no new helpers needed.

### Hard constraint: fixtures must live under `e2e/`

The `build-docker` CI job checks out with **`sparse-checkout: e2e`** (`.github/workflows/build.yml`, the
`actions/checkout@v6` step before the Playwright run). Anything outside `e2e/` — notably
`openam-entitlements/src/test/resources/test_data/xacml3_policy_import.xml` — **is not on disk** in that job.
Do not reference it.

Preferred: **avoid a fixture file entirely** by making the import test a round-trip of what export just
produced (below). It is both fixture-free and a stronger parity assertion. Only add
`e2e/xacml/fixtures/*.xml` if a malformed-input case needs a doc that export cannot generate.

### Setup (`beforeAll`, idempotent)

1. `getAdminToken(request)`; skip the suite if absent (same guard as the oauth2 spec).
2. `ensureSubRealmExists("xacmltest")` — `POST /json/realms?_action=create`, `Accept-API-Version:
   resource=1.0`, body `{ name, parentPath: "/", active: true }`; tolerate an existing realm (409/400).
   Needed for the realm-style cases and for a non-root `Content-Disposition` filename.
3. `ensurePolicyExists()` — `PUT /json/realms/root/policies/<name>`. A fresh install's root realm has no
   privileges, so **export would otherwise return an empty `PolicySet`** and the round-trip and `filter`
   cases would prove nothing. This fixture is what makes them deterministic.

   **Use `Accept-API-Version: resource=1.0`, not `2.1`.** v2+ requires `resourceTypeUuid` — a per-realm
   generated id the spec would have to query for. `PolicyV1Filter.retrieveResourceType`
   (`PolicyV1Filter.java:186-206`) derives it from `applicationName` instead, and the default
   `iPlanetAMWebAgentService` application has exactly one resource type (`entitlement.xml:552-556`),
   which is the single-resource-type precondition that filter enforces. The v1 body is flat
   (`name`, `active`, `applicationName`, `actionValues`, `resources`, `subject`) because `JsonPolicy`
   marks the entitlement `@JsonUnwrapped`. Create with `If-None-Match: *`; a bare `PUT` is a CREST
   update and 404s on a missing policy.

Auth is passed as the `iPlanetDirectoryPro` **header**, as the oauth2 spec does against `/oauth2/authorize`.
`/xacml` sits behind the same CAF `@Named("AuthenticationFilter")` as `/json`, so the header should be
accepted — **confirm on the first run**; fall back to a cookie if not.

### Cases

Each row maps to a Phase-2 parity-checklist row or a risk-register item.

| # | Request | Expect | Guards |
|---|---|---|---|
| 1 | `GET /xacml/policies` + admin | `200`; `Content-Type: application/xacml+xml; version=3.0`; `Content-Disposition: attachment; filename=realm-policies.xml`; body parses as XML, root `PolicySet` | Content types (risk 6); export headers |
| 2 | `GET /xacml/policies`, **no token** | `401` + XML `<error>` **only after the fix above** — was `500` | Auth caller; CAF wiring |
| 3 | `GET /xacml/policies` + **demo** token | `403`; `Content-Type: application/xml`; body `<error>` with `code` `403` | Delegation identity; XML errors (risk 7) |
| 4 | `PUT /xacml/policies` + admin | `405`; XML `<error>` whose embedded `<code>` is **`501`**, not `405` | `Endpoints.from` 405 fallback → XML, end-to-end |
| 5 | `GET /xacml/policies` **no `Accept-API-Version`** | `200` | **The version-gate regression above**, over the wire |
| 6 | `GET /xacml/policies` + `Accept-API-Version: resource=1.0` | `200`; **no** `Content-API-Version` response header | Header is ignored, not routed on |
| 7 | `GET /xacml/policies` + `Accept-API-Version: resource=2.0` | `200` — **not** a non-2xx | The route is unversioned; a 404 here means the gate is back |
| 8 | `GET /xacml/realms/root/policies` + admin | `200`, filename `realm-policies.xml` | Modern realm style (new in Phase 2) |
| 9 | `GET /xacml/xacmltest/policies` + admin | `200`, filename `xacmltest-realm-policies.xml` | **Legacy** path realm — the Restlet-compat style |
| 10 | `GET /xacml/policies?realm=/xacmltest` + admin | `200`, filename `xacmltest-realm-policies.xml` | `?realm=` override (risk 9) |
| 11 | `GET /xacml/policies?filter=name=<policy>` + admin | `200`; exported `PolicySet` contains only that policy | `filter` param |
| 12 | `GET /xacml/policies?filter=name=<policy>&filter=name=<none>` | `200`; **empty** `PolicySet` | `Form.fromRequestQuery` list semantics — filters are ANDed (`PrivilegeManager.search` passes `boolAnd=true`), so an unsatisfiable second filter must empty the result; if only the first were read the policy would still be exported |
| 13 | `POST /xacml/policies` + admin, body = **case-1 export**, `?dryrun=true` | `200`; JSON array of `{status,name,type}`; **and** a follow-up export is unchanged | Import + dryrun non-persistence |
| 14 | `POST /xacml/policies?realm=/xacmltest` + admin, body = case-1 export | `200`; JSON array; follow-up export of `xacmltest` contains the policy | **Round-trip** — the real proof |
| 15 | `POST /xacml/policies` + admin, empty body | `400`; XML `<error>` | Empty-doc path |

Case 14 is the load-bearing one: it exports from root and imports into a sub-realm, so it exercises export
serialization, import parsing, both realm resolutions, and both permission checks in one flow.

Cases 3 and 15 are where the `XacmlXmlErrorFilter` is proven **in situ** — unit tests confirm the rewrite,
but only these confirm it is actually *mounted* on the route.

### Assertion helper

Two local helpers in the spec (not in `openam-commons.mjs` — both are XACML-specific):

- `expectXmlError(response, embeddedCode)` — asserts `Content-Type: application/xml` and the
  `<error>/<code>` text. Used by cases 2, 3, 4 and 15 (case 7 no longer errors — the route is
  unversioned). The parameter is the **embedded** code, which is not always the HTTP status: case 4 is
  `405` with `<code>501</code>`.
- `policyIds(xml)` — every `PolicyId="…"`, which `XACMLPrivilegeUtils.privilegeNameToPolicyId` returns
  as the privilege name verbatim. Anchor the match (`\bPolicyId=`) so `PolicySetId` does not match.

Parse with a regex; do **not** add an XML-library dependency to `e2e/package.json` for these. Node has
no global `DOMParser`, so a "tiny DOM parse" is not actually available without one.

---

## Deliverable 2 (secondary) — `openam-entitlements/.../rest/XacmlRouterIT.java`

In-process dispatch through the **real** `XacmlHttpRouteProvider`, modelled on
`openam-rest/src/test/java/org/forgerock/openam/rest/RestRouterIT.java` — the repo's only real-injector test
and the designated template.

**No pom change needed.** `org.openidentityplatform.commons.guice:test` (which provides `GuiceTestCase`,
`@GuiceModules`, `InjectorConfiguration`) is already a test-scope dep of `openam-entitlements`
(`pom.xml:122-126`). Note this contradicts the module table in
[test-infrastructure.md § Guice testing](../../test-infrastructure.md#guice-testing), which lists only
`openam-rest`/`openam-uma`/`openam-oauth2` — **update that table** when this lands.

### Correction: the `configureOverrideBindings` design below does not work

**The shape sketched in this section was not buildable, and the shipped test does not use it.** It called
for overriding `Iterable<HttpRouteProvider>` in `configureOverrideBindings` with
`@GuiceModules({HttpGuiceModule.class, RestGuiceModule.class})` installed, citing
`HttpRouterProviderTest.java:84` as the proven seam. That test has **no `@GuiceModules`** and never
installs `HttpGuiceModule`. `HttpGuiceModule` is a `PrivateModule`, and `Modules.override` only descends
into private bindings when the base is a single `PrivateElements` element — so the override never binds.

The shipped `XacmlRouterIT` instead builds a **minimal injector**: no `HttpGuiceModule`, no
`RestGuiceModule`, `InjectorConfiguration.setGuiceModuleLoader(→ empty set)` to kill classpath scanning,
and `configure()` binds only what `XacmlHttpRouteProvider` actually needs. It then builds the router from
`InjectorHolder.getInstance(XacmlHttpRouteProvider.class).get()` directly rather than via
`HttpApplication.start()`. This also sidesteps the `ServiceLoader` problem in fact 1 below — no
`ServiceLoader` runs at all.

Tradeoff accepted: the test covers neither the `META-INF/services` registration nor the real module
graph's bindings. Both surface at server startup and in the e2e spec.

Two further test-only notes:

- `HttpRoute`'s `getMode()`/`getUriTemplate()`/`getHandler()` are package-private, so the test needs the
  `org.forgerock.openam.http.HttpRouteAccessor` shim (test tree, no production change).
- The test lives in `org.forgerock.openam.xacml.v3.rest`, not next to `XacmlHttpRouteProvider`, so it can
  override the package-private `XacmlServiceHandler.checkPermission` (whose real implementation reaches
  for the `SSOTokenManager` singleton).

### Two wiring facts that dictate the design

1. **`ServiceLoader` is classpath-wide.** `HttpGuiceModule.getHttpRouteProviders()`
   (`openam-http/.../HttpGuiceModule.java:53-54`) is `ServiceLoader.load(HttpRouteProvider.class)`. On
   `openam-entitlements`'s test classpath that finds `RestHttpRouteProvider` (from the `openam-rest` jar)
   **as well as** `XacmlHttpRouteProvider`, dragging in a binding graph this test has no reason to satisfy.
   `HttpRouterProvider` takes `Iterable<HttpRouteProvider>` as an **injected** constructor param
   (`HttpRouterProvider.java:37-46`), so **override that binding** to a singleton set containing only the
   XACML provider — exactly the seam `HttpRouterProviderTest.java:84` already uses. Because it is a
   `@Provides` method in `HttpGuiceModule`, the override must go in `configureOverrideBindings`, not
   `configure` (a `configure` binding would collide).
2. **`Endpoints.from(Class)` resolves eagerly through `InjectorHolder`.**
   `Endpoints.from(cls)` → `from(Key.get(cls))` → `from(InjectorHolder.getInstance(key))`
   (`Endpoints.java:89-101`) — evaluated when `XacmlHttpRouteProvider.get()` **builds the route**, not per
   request. So `XacmlServiceHandler` must be bound before the router is built. Bind an instance constructed
   with mocked `XACMLExportImport` / `DelegationEvaluator` / `RestLog` / `Debug` / `PrivilegedAction<SSOToken>`.
   This also rules out any "just call `new XacmlHttpRouteProvider()` and set the fields" shortcut: the public
   `@Inject` setters are settable, but `get()` still needs a primed `InjectorHolder`.

### Shape

```java
@GuiceModules({HttpGuiceModule.class, RestGuiceModule.class})
public class XacmlRouterIT extends GuiceTestCase {
    // setupMocks(): lift RestRouterIT's scaffold verbatim — CoreWrapper (isValidFQDN -> true,
    //   getAdminToken), RestRealmValidator, SSOTokenManager, AuthUtilsWrapper, AuditEventPublisher,
    //   AuditServiceProvider, SessionCache, @Named(SESSION_DEBUG) Debug, PrivilegedAction<SSOToken>,
    //   RealmTestHelper.setupRealmClass().
    // setupGuiceModules(): InjectorConfiguration.setGuiceModuleLoader(-> empty set) to kill scanning.
    // configure(): bind the mocks above + the XacmlServiceHandler instance.
    // configureOverrideBindings(): bind Iterable<HttpRouteProvider> -> singleton(xacmlProvider),
    //   ResourceApiVersionBehaviourManager -> mock,
    //   @Named("AuthenticationFilter") Filter -> pass-through that seeds AttributesContext
    //     ["org.forgerock.authentication.context"] = {"tokenId": "TOKEN"}.
    // setup(): handler = InjectorHolder.getInstance(HttpApplication.class).start();
}
```

The stubbed auth filter is deliberate and is *also* an assertion: it reproduces the exact
`AttributesContext` contract the handler reads (`XacmlServiceHandler.java:255-259`), so if that key or shape
drifts, this test breaks. Real CAF auth stays with layer 4.

`RealmTestHelper` is already in use in `XacmlServiceHandlerTest` — same import, no new dependency.

### Cases

| # | Request | Assert |
|---|---|---|
| 1 | `GET /xacml/policies` | reaches the handler; `RealmContext` realm is root |
| 2 | `GET /xacml/subrealm/policies` | legacy path realm resolves (mock the realm via `RealmTestHelper` + `CoreWrapper`, per `RestRouterIT.mockRealm`) |
| 3 | `GET /xacml/realms/root/policies` | modern realm route resolves |
| 4 | `GET /xacml/policies` with `Accept-API-Version` absent / `1.0` / `2.0` / unparseable | `200` for all four — the route is unversioned; pinned cross-JDK |
| 5 | `GET /xacml/policies`, behaviour manager = `NONE` | `200` — the regression guard; fails if the gate **and** filter return |
| 5b | `GET /xacml/policies` | no `Content-API-Version` response header — fails if the filter returns |
| 6 | `PUT /xacml/policies` | `405` **and** `Content-Type: application/xml` — proves the error filter is mounted |
| 7 | `GET /xacml/nonsense` | `404` |
| 8 | provider `get()` | `"policies"` was added to the injected `InvalidRealmNames` set (`XacmlHttpRouteProvider.java:92`) |

Case 8's original rationale ("without it, `/xacml/policies` could be parsed as realm `policies`") is
**wrong**. The set is write-only at the routing layer: providers register their own first path segment,
exactly as `Routers.ServiceRouterImpl.route` does. Its sole reader is
`OrganizationConfigManager.validateOrgName` (`OrganizationConfigManager.java:522`), reached from
`createSubOrganization`, which rejects creating a realm whose name clashes with an endpoint. So the case
guards **realm creation**, not request routing. The assertion is still worth keeping; the reason was not.

---

## Explicitly out of scope

- **Locale parity** (`AcceptLanguageHeader` vs `HttpServletRequest.getLocale()`). It affects only
  `EntitlementException.getLocalizedMessage(locale)` on error paths, the English default makes it near-
  unobservable, and asserting it needs a localized `EntitlementException`. [phase-2-xacml.md](phase-2-xacml.md)
  already rates it low risk. Revisit in Phase 3c, where `getAcceptedLanguages()` becomes load-bearing for the
  consent UI.
- **Audit-event parity** (`RestLog` component string). Needs an audit-log reader; belongs with Phase 3d, which
  builds the CHF audit filters.
- **DNS-alias realm style.** Requires per-test container DNS; the other four realm styles cover the
  `RealmContextFilter` paths that Phase 2 actually rewired.
- **Restlet-vs-CHF golden diffing.** Restlet no longer serves `/xacml` on this branch, so there is nothing
  to diff against without checking out `master` and running two servers. The table above pins the intended
  values directly instead.

## Execution order

**Amended:** steps 1–3 were swapped. There is no local OpenAM server (nothing listening, no containers),
so the layer-4 spec cannot be run locally at all — only CI can exercise it. The layer-2 IT went first
because it is the part that can actually be verified on this machine, and it is what found the version-gate
bug.

1. ~~Write the layer-4 spec~~ → **Write the layer-2 IT (deliverable 2).** ✅ Done: 13 cases, green.
   Found and fixed the version-gate bug above.
2. ✅ **Done: layer-4 spec written** (deliverable 1), 15 cases. As predicted, case 2 was the surprise,
   though not in the way expected: the header works fine, and the `401` was a `500`. That mismatch was
   neither "a Phase-2 bug" nor "a test to bend" — it was a **pre-existing** defect the migration
   faithfully carried over (see [above](#the-401-that-was-a-500)), fixed rather than pinned.

   The spec is **unverified**: there is no local OpenAM server, so only CI has ever run it. The
   assertions are derived from source, not from observed responses; treat the first CI run as the real
   verification. `npx playwright test xacml --list` (15 tests) and node-level checks of the two regex
   helpers are all that could be confirmed locally.
3. Note cases 5–7 in the deliverable-1 table now assert the **unversioned** contract: `200` for a missing
   header, `200` for `resource=1.0`, and `200` (not a non-2xx) for `resource=2.0`.
4. Update [test-infrastructure.md](../../test-infrastructure.md): the Guice-test module table
   (openam-entitlements has `commons.guice:test`), and the "container ITs cover only the installer" gap now
   that layer 4 covers `/xacml`.
5. Correct [phase-2-xacml.md](phase-2-xacml.md)'s "Route wiring is exercised by the Cargo IT smoke" claim and
   point its Verification section at these two suites.

## Verification

```bash
# Deliverable 2 — note: `mvn test` will NOT run *IT.java (failsafe is bound at the root pom).
mvn -o -pl openam-entitlements verify

# Deliverable 1 — against a running WAR
cd e2e && npx playwright test xacml --reporter=list
# defaults to http://openam.example.org:8080/openam; override with OPENAM_BASE_URL

# Whole-reactor safety, per test-infrastructure.md's -pl gotcha
mvn install -DskipTests
```

CI needs **no changes**: `verify` on all 9 legs picks up `XacmlRouterIT`, and the `build-docker` job's
unqualified `npx playwright test` picks up `xacml-test.spec.mjs`.

## Risks in this work

| Risk | Mitigation |
|---|---|
| Layer-2 IT drags in `RestGuiceModule`'s full graph and won't construct | Copy `RestRouterIT`'s mock scaffold **verbatim** — it is a proven-resolvable set. If it still fails, the override of `Iterable<HttpRouteProvider>` is the first thing to check. |
| ~~`iPlanetDirectoryPro` header not accepted on `/xacml`~~ | **Resolved, not a risk.** `LocalSSOTokenSessionModule:207-210` reads the cookie then falls back to the same-named header. |
| Export returns an empty `PolicySet` on a fresh install | The `ensurePolicyExists` fixture exists precisely for this; if the round-trip is empty, the fixture failed silently — case 1 asserts the fixture policy is in the export. |
| ~~Sub-realm creation API version differs from `resource=1.0`~~ | **Confirmed** `resource=1.0`: `SmsRestRouteProvider:68` registers `realms` via `toCollection`, which defaults to v1; `active` is a boolean (`SmsRealmProvider:208`). |
| **Sub-realm import (case 14) may fail on resource types, not on Phase 2** | The imported privilege must resolve a resource type in `xacmltest`. If case 14 alone fails on the first CI run, suspect the fixture/realm setup before suspecting the migration. |
| **Layer-2 IT cannot see the auth fix** | `XacmlRouterIT` stubs the auth filter, so the `401` has no cross-JDK guard — only `e2e` covers it. The IT does bind the stub under `RequiredAuthenticationFilter` **only**, so reverting the provider to the optional filter fails every case with a missing-binding error. |
| Doclint is fatal on JDK 11/26 | No `{@link}` to anything not imported in the new IT. |
