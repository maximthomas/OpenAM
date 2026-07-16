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

## A parity risk that no existing test can see

Phase 2 put `requestResourceApiVersionMatcher(version(1))` in front of `policies`
(`XacmlHttpRouteProvider.java:94-98`). **Restlet had no version gate at all.** So the behaviour of a request
carrying no `Accept-API-Version` header — which is every existing XACML client, including the
`ssoadm`/CLI-era consumers — now depends on `ResourceApiVersionBehaviourManager`'s default rather than on
nothing. A wrong default turns every legacy XACML client into a 404 or 406.

This is invisible to both unit tests (they bypass the router entirely) and to the Cargo IT (it never calls
`/xacml`). It is the single strongest argument for the work below, and it gets a dedicated case in **both**
deliverables.

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
3. `ensurePolicyExists()` — `PUT /json/realms/root/policies/<name>` with `Accept-API-Version:
   resource=2.1` (route registered at `EntitlementsRestRouteProvider.java:38-47`; v2.1 is
   `PolicyResourceWithCopyMoveSupport`). A fresh install's root realm has no privileges, so **export would
   otherwise return an empty `PolicySet`** and the round-trip and `filter` cases would prove nothing. This
   fixture is what makes them deterministic.

Auth is passed as the `iPlanetDirectoryPro` **header**, as the oauth2 spec does against `/oauth2/authorize`.
`/xacml` sits behind the same CAF `@Named("AuthenticationFilter")` as `/json`, so the header should be
accepted — **confirm on the first run**; fall back to a cookie if not.

### Cases

Each row maps to a Phase-2 parity-checklist row or a risk-register item.

| # | Request | Expect | Guards |
|---|---|---|---|
| 1 | `GET /xacml/policies` + admin | `200`; `Content-Type: application/xacml+xml; version=3.0`; `Content-Disposition: attachment; filename=realm-policies.xml`; body parses as XML, root `PolicySet` | Content types (risk 6); export headers |
| 2 | `GET /xacml/policies`, **no token** | `401` | Auth caller; CAF wiring |
| 3 | `GET /xacml/policies` + **demo** token | `403`; `Content-Type: application/xml`; body `<error>` with `code` `403` | Delegation identity; XML errors (risk 7) |
| 4 | `PUT /xacml/policies` + admin | `405`; XML `<error>` body | `Endpoints.from` 405 fallback → XML, end-to-end |
| 5 | `GET /xacml/policies` **no `Accept-API-Version`** | `200` | **The version-gate regression above** |
| 6 | `GET /xacml/policies` + `Accept-API-Version: resource=1.0` | `200` | Version routing |
| 7 | `GET /xacml/policies` + `Accept-API-Version: resource=2.0` | non-2xx, XML error | Version routing is real, not inert |
| 8 | `GET /xacml/realms/root/policies` + admin | `200`, filename `realm-policies.xml` | Modern realm style (new in Phase 2) |
| 9 | `GET /xacml/xacmltest/policies` + admin | `200`, filename `xacmltest-realm-policies.xml` | **Legacy** path realm — the Restlet-compat style |
| 10 | `GET /xacml/policies?realm=/xacmltest` + admin | `200`, filename `xacmltest-realm-policies.xml` | `?realm=` override (risk 9) |
| 11 | `GET /xacml/policies?filter=name=<policy>` + admin | `200`; exported `PolicySet` contains only that policy | `filter` param |
| 12 | `GET /xacml/policies?filter=…&filter=…` | `200`; multi-valued filter honoured | `Form.fromRequestQuery` list semantics |
| 13 | `POST /xacml/policies` + admin, body = **case-1 export**, `?dryrun=true` | `200`; JSON array of `{status,name,type}`; **and** a follow-up export is unchanged | Import + dryrun non-persistence |
| 14 | `POST /xacml/policies?realm=/xacmltest` + admin, body = case-1 export | `200`; JSON array; follow-up export of `xacmltest` contains the policy | **Round-trip** — the real proof |
| 15 | `POST /xacml/policies` + admin, empty body | `400`; XML `<error>` | Empty-doc path |

Case 14 is the load-bearing one: it exports from root and imports into a sub-realm, so it exercises export
serialization, import parsing, both realm resolutions, and both permission checks in one flow.

Cases 3 and 15 are where the `XacmlXmlErrorFilter` is proven **in situ** — unit tests confirm the rewrite,
but only these confirm it is actually *mounted* on the route.

### Assertion helper

Add one local helper to the spec (not to `openam-commons.mjs` — it is XACML-specific):
`expectXmlError(response, code)` — asserts `Content-Type: application/xml`, parses the body, and checks the
`<error>/<code>` text. Cases 3, 4, 7 and 15 all use it. Parse with a regex or a tiny DOM parse; do **not**
add an XML-library dependency to `e2e/package.json` for four assertions.

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
| 4 | `GET /xacml/policies` **no `Accept-API-Version`** | `200` — the version-gate regression, pinned cross-JDK |
| 5 | `GET /xacml/policies` + `resource=2.0` | non-2xx |
| 6 | `PUT /xacml/policies` | `405` **and** `Content-Type: application/xml` — proves the error filter is mounted |
| 7 | `GET /xacml/nonsense` | `404` |
| 8 | provider `get()` | `"policies"` was added to the injected `InvalidRealmNames` set (`XacmlHttpRouteProvider.java:92`) |

Case 8 is cheap and guards a subtle one: without it, `/xacml/policies` could be parsed as realm `policies`.

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

1. Write the layer-4 spec (deliverable 1) — highest value, no Java, no pom, no CI wiring.
2. Run it against a local WAR; **record any case where the shipped behaviour differs from the table** — cases
   5 and 7 (version gate) and 2 (header vs cookie auth) are the ones most likely to surprise. A mismatch
   here is a Phase-2 bug found, not a test to bend: fix the code or amend
   [phase-2-xacml.md](phase-2-xacml.md)'s parity claim, and say which.
3. Write the layer-2 IT (deliverable 2).
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
| `iPlanetDirectoryPro` header not accepted on `/xacml` | Confirm on first run; fall back to a cookie. Either way case 2 (`401`) still holds. |
| Export returns an empty `PolicySet` on a fresh install | The `ensurePolicyExists` fixture exists precisely for this; if the round-trip is empty, the fixture failed silently — assert it is non-empty in case 1. |
| Sub-realm creation API version differs from `resource=1.0` | Confirm against `/json/realms` on first run; the realm cases (9, 10, 14) depend on it. |
| Doclint is fatal on JDK 11/26 | No `{@link}` to anything not imported in the new IT. |
