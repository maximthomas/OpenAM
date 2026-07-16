# Test infrastructure — what exists, where, and what it can catch

Repo-wide reference for OpenAM's test layers. Written 2026-07-16 while planning the Restlet→CHF
[phase 3b](migration/restlet/phase-3b-collaborators.md); every claim below was verified against the tree on
`features/restlet-migration` (HEAD `0b389aed4e`) rather than inferred, but **file/line references drift** —
re-grep before relying on an exact line.

Read this before adding a test, so you put it in the layer that will actually run it and actually catch the
thing you care about.

## The four layers at a glance

| Layer | Where | Runner | Runs on | Naming |
|---|---|---|---|---|
| 1. Unit | every module's `src/test/java` | surefire | `mvn test` (and `verify`) | `*Test.java`, `Test*.java`, `*TestCase.java` |
| 2. In-process IT | `openam-rest` (one test) | failsafe | `mvn verify` — **any module, no profile** | `IT*.java`, `*IT.java`, `*ITCase.java` |
| 3. Container IT | `openam-server` | failsafe + Cargo + Selenium | `mvn verify -P integration-test` | `IT_*.java` |
| 4. End-to-end | `e2e/` | Playwright (Node) | `npx playwright test` — **not in the Maven reactor** | `*.spec.mjs` |

No pom overrides surefire/failsafe `<includes>` anywhere, so the stock naming defaults above are the real
contract. **Layer 1 vs 2 is decided purely by the class name.**

## Layer 1 — unit tests (surefire)

Stack is **TestNG + Mockito + AssertJ**. There is **no JUnit** in the reactor, and no rest-assured, no
wiremock, no Restlet test jar anywhere. Versions come from the root pom's `<dependencyManagement>`; child
poms declare artifacts without versions.

Root pom pins surefire at `pom.xml:1830-1842` with `<argLine>${java.surefire.options}</argLine>` and no
`<includes>`.

## Layer 2 — in-process ITs (failsafe)

**The root pom binds `maven-failsafe-plugin` unconditionally** in `<build><plugins>` (`pom.xml:1843-1856`;
goals `integration-test` + `verify`; version pinned `3.5.3` at `:2098-2102`). Not in `pluginManagement`, no
profile, no skip — so **every module** will run `*IT.java` on `mvn verify`, and **`mvn test` silently skips
it**. This is the single most surprising fact in this document: name a class `…IT` and your inner-loop
`mvn test` will never run it.

`openam-server` is the only module that opts out, overriding failsafe with `<skip>true</skip>`
(`openam-server/pom.xml:45-51`) and re-enabling it inside the `integration-test` profile (layer 3).

### The only in-process HTTP test in the repo

`openam-rest/src/test/java/org/forgerock/openam/rest/RestRouterIT.java` — dispatches a real
`org.forgerock.http.protocol.Request` through a real CHF `Handler`:

```java
@GuiceModules({HttpGuiceModule.class, RestGuiceModule.class})
public class RestRouterIT extends GuiceTestCase {
    // configure(Binder) / configureOverrideBindings(Binder) bind mocks
    // InjectorConfiguration.setGuiceModuleLoader(...) -> empty set, to kill classpath scanning
    handler = InjectorHolder.getInstance(HttpApplication.class).start();
    handler.handle(context, request);
}
```

Contexts are built from `RootContext` / `AttributesContext` / `SessionContext` / `HttpContext` /
`SecurityContext` / `RequestAuditContext`; routing is asserted by verifying the mock resource
(`verify(usersResource).readInstance(...)`) and inspecting `RealmContext`. **This is the template** for any
future in-process CHF test.

Everything else that touches `org.restlet.Request` or CHF types is unit-level — it calls a method directly
rather than dispatching. Notably there is **no** Restlet in-process dispatch anywhere: no `new Component(...)`,
no `restlet.Client`, no `RestletTestUtils`, no MockHttpServletRequest harness.

## Layer 3 — container ITs (`openam-server`, profile-gated)

`openam-server/src/test/java/org/openidentityplatform/openam/test/integration/`:

- **`CargoBaseTest.java`** — starts a **fresh Tomcat + OpenAM WAR per test method** (`@BeforeMethod` /
  `@AfterMethod`, so instances run sequentially, not in parallel). Downloads/caches the Tomcat zip via
  Cargo's `ZipURLInstaller`, deploys at context `test-am` on port **8207**, polls the context root with a
  180s deadline, exposes `OPENAM_URL = http://openam.local:8207/test-am`.
  **Requires `openam.local` in `/etc/hosts`** — CI adds `127.0.0.1 openam.local`.
- **`BaseTest.java`** — Selenium `ChromeDriver` harness, screenshot-on-failure, `cleanConfig()`.
- **`IT_Setup.java`, `IT_SetupWithOpenDJ.java`** — the only container ITs. They drive the **web installer UI**
  through Selenium and assert the console renders (`By.className("Tab1Div")`). **No OAuth2/OIDC/UMA/SAML
  coverage.**

Run: `mvn verify -P integration-test` (profile at `openam-server/pom.xml:135-182`; sets failsafe
`<skip>false</skip>`, passes `openam.war` / `cargo.containerId` / `cargo.tomcat.zip.url` / `cargo.install.dir` /
`cargo.config.dir` / `cargo.logback.config` / `test.config.path`, and re-binds compiler `compile`+`testCompile`
to `pre-integration-test`).

Container defaults to `tomcat10x` (`:29`); the auto-activating `jdk17.options` profile (`:219-227`) switches
to `tomcat11x` / Tomcat 11.0.2 on JDK ≥ 17.

Two traps here:
- The `cargo-maven3-plugin` declaration at `openam-server/pom.xml:54-74` (`<extensions>true</extensions>`) is
  for the **`uberwar` packaging** (`src/assemble/merge.xml`), **not** for starting a container. The container
  lifecycle is driven from Java (`CargoBaseTest`) via Cargo's API, not the plugin.
- `org.testcontainers:testcontainers` is declared as a test dep (`:102-103`) but **nothing imports it**.

## Layer 4 — end-to-end (Playwright, outside Maven)

`e2e/` is a Node project, **not a Maven module**. Config `e2e/playwright.config.mjs`:
`testMatch: "**/*.spec.mjs"`, `timeout: 180000`, `retries: 0`, headless, screenshot + trace on failure.

| Spec | Covers |
|---|---|
| `e2e/oauth2/oauth2-test.spec.mjs` | authorize (code + PKCE S256) → `POST /oauth2/access_token` → `GET /oauth2/userinfo` with a **Bearer header**. Creates the OAuth2 service + a public client `test_client_app` (scope `profile`) via `/json/realms/root/realm-config/…` if absent. |
| `e2e/saml/saml-test.spec.mjs` | SAML IdP↔SP flow |
| `e2e/xui/xui-httponly.spec.mjs` | XUI cookie flags |
| `e2e/common/openam-commons.mjs` | shared helpers: `OPENAM_BASE`, `ADMIN_USER`/`ADMIN_PASS`, `USERNAME`/`PASSWORD`, `getAdminToken(request)`, `getAuthToken(request, user, pass)` — all env-overridable |

**This is the only layer that exercises a real HTTP request through a real server**, and therefore the only
one where Restlet's server adapter is in play (see [Gotchas](#gotchas-that-have-actually-bitten)).

## CI (`.github/workflows/build.yml`)

Two jobs. There is **no separate IT job** — ITs are folded into the build via `verify` + the profile.

**`build-maven`** — 9 matrix legs, `fail-fast: false`:

| OS | JDKs |
|---|---|
| `ubuntu-latest` | 11, 17, 21, 25, 26 |
| `macos-latest` | 11, 26 |
| `windows-latest` | 11, 26 |

- `:52-57` — **on `ubuntu-latest` only**: sets `MAVEN_PROFILE_FLAG=-P integration-test` and adds
  `127.0.0.1 openam.local` to `/etc/hosts`. So layer 3 runs on **5 of 9 legs**; macOS/Windows never run it.
- `:61` — `mvn --batch-mode --errors --update-snapshots verify --file pom.xml ${MAVEN_PROFILE_FLAG}`.
  **`verify`, not `test`** ⇒ layer-2 ITs run on **all 9 legs**.

**`build-docker`** (`needs: build-maven`) — builds the image, runs `openam-idp` + `openam-sp` + OpenDJ
containers, then `:306-307` `npx playwright install chromium --with-deps` and **`npx playwright test
--reporter=list`** — *unqualified, so every spec runs, including `oauth2/`*. Later `:330` re-runs only
`npx playwright test xui` with `EXPECT_COOKIE_HTTPONLY=true`, then a 3-node multi-server test
(`test-openam1/2/3`).

Other workflows run **no** tests: `deploy.yml` uses `package`/`deploy`, `release.yml` uses
`release:prepare`/`release:perform`, and `codeql.yml`'s `mvn` line is commented out (`:115`).

## Guice testing

`GuiceTestCase`, `@GuiceModules`, `InjectorConfiguration` and `GuiceModuleLoader` come from
`org.openidentityplatform.commons.guice:test`.

| Module | Has `commons.guice:test`? | Uses it? |
|---|---|---|
| `openam-rest` | yes (`pom.xml:145-149` — the declaration to copy) | yes — `RestRouterIT`, `NotificationsWebSocketFilterTest`, `JSONRestStatusServiceTest` |
| `openam-uma` | yes (`pom.xml:79-83`) | **no** — declared but unused |
| `openam-oauth2` | **no** | n/a |

**`RestRouterIT` is the only test in the repo that wires a real Guice injector.** Consequence:
`OAuth2GuiceModule`, `OAuth2RestGuiceModule` and `LabelsGuiceModule` have **zero** test coverage, so **no
test can currently catch a broken OAuth2/UMA Guice binding** — it surfaces as a `CreationException` when a
server starts.

Cheaper alternative when you only need to assert *binding targets*, without paying for an injector: Guice's
`Elements.getElements(new SomeModule())` records the binding graph with **no** dependency resolution, no eager
singletons, and no SMS. `.to()` binds show up as `LinkedKeyBinding` (assert `getLinkedKey()`); `@Provides`
methods do not expose their target, but they are often package-private and callable directly from a test in
the same package. Guice is on the compile classpath via `org.openidentityplatform.commons.guice:core`, so this
needs no new dependency. See
[phase-3b § Integration tests](migration/restlet/phase-3b-collaborators.md#integration-tests) for a worked
example.

Beware: creating a real injector over one module usually **fails** — Guice validates the whole binding graph
at `createInjector`, so a module whose bindings reach into sibling modules needs those modules (or broad mock
scaffolding) just to construct. That is why `RestRouterIT` loads `HttpGuiceModule` **and** `RestGuiceModule`
and stubs out the module loader.

## Known coverage gaps

Recorded so they're not rediscovered:

- **OAuth2/OIDC endpoints have no endpoint-level tests.** `UserInfoService` and `TokenInfoService` have **no
  test at all**; nor do `TokenEndpointResource`, `TokenEndpointFilter`, `TokenIntrospectionResource`,
  `GuicedRestlet`.
- The closest thing is an anti-pattern: **mock the `ServerResource`'s own accessors and call the annotated
  method directly** — e.g. `given(endpoint.getRequest()).willReturn(request); endpoint.createResourceSet(entity)`
  in `ResourceSetRegistrationEndpointTest`, `AuthorizationRequestEndpointTest`,
  `UmaWellKnownConfigurationEndpointTest`, `PermissionRequestEndpointTest`, `AuthorizeResourceTest`. Restlet
  routing, `Finder`, and Guice are all bypassed. Copy `RestRouterIT` instead if you need real dispatch.
- **Container ITs cover only the installer** (layer 3) — every protocol-level assertion lives in layer 4.
- `openam-oauth2/src/test/.../OpenAMClientRegistrationJwksUriIntegrationTest.java` is named "Integration" but
  ends in `Test`, so it is a **surefire unit test**. Naming here is not a reliable signal of layer.

## Gotchas that have actually bitten

- **`mvn test` skips `*IT.java`.** Failsafe is bound at the root, so `verify` is the only goal that runs
  layer 2. Inner-loop `mvn test` gives false confidence.
- **`mvn -pl <module>` cannot see cross-module callers.** Sibling modules resolve each other from `~/.m2`, so
  a single-module build happily compiles against a stale installed jar. `mvn -o -pl openam-oauth2 install
  -DskipTests` before `mvn -o -pl openam-oauth2,openam-uma test`, and run a whole-reactor build before
  claiming a signature change is safe. (This is exactly how a missed `openam-uma` caller nearly shipped in
  phase 3b — see [D1](migration/restlet/phase-3b-collaborators.md#d1--handlerequest-string-has-three-callers-not-two-compile-break).)
- **Doclint is fatal.** Commit `3c45ff8d53` enabled `-Xdoclint:all,-missing` with `failOnWarnings` on JDK 11
  and JDK 26. A dangling `{@link}` to a member you deleted is a **build error**, not a warning.
- **Restlet's Bearer/header parsing is unreachable from a plainly-constructed `Request`.**
  `RestletHeaderAccessTokenVerifier:73` gates its raw-header read on
  `request instanceof org.restlet.engine.adapter.HttpRequest` — a server-adapter internal that only exists
  under real HTTP dispatch. A unit test over `new Request(Method.GET, uri)` silently takes the fallback path
  and can pass while proving nothing. Reaching the real branch needs `mock(HttpRequest.class)` with a stubbed
  `getHttpCall().getRequestHeaders()`, or layer 4. See
  [D6](migration/restlet/phase-3b-collaborators.md#d6--the-bearer-parse-is-unreachable-from-a-plainly-constructed-restlet-request).
- **Guice binding errors are invisible to every build.** Nothing fails until a server starts. If you rebind,
  bring your own guard.

## Choosing a layer

- Pure logic, mocked collaborators → **layer 1**.
- Real CHF routing/filters/contexts in-process → **layer 2**, `RestRouterIT` as the template. Remember the
  `…IT` name means `mvn verify`.
- Real HTTP, real server adapter, real protocol behaviour → **layer 4**. It is cheaper than it looks: the
  fixtures and helpers already exist, and CI runs the specs unqualified, so a new `.spec.mjs` (or a new case
  in an existing `describe`) needs no wiring at all.
- **Layer 3 is rarely the answer** — it is heavyweight (fresh Tomcat per method), Linux-only in CI, and
  layer 4 covers the same protocol surface far more cheaply.
