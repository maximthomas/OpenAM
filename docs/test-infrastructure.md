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
| `e2e/oauth2/oauth2-test.spec.mjs` | authorize (code + PKCE S256) → `POST /oauth2/access_token` → `GET /oauth2/userinfo` with a **Bearer header**. Creates the OAuth2 service + a public client `test_client_app` (scope `profile`) via `/json/realms/root/realm-config/…` if absent. Also carries the Restlet-migration **contract locks** §5-E (`/access_token` + cache headers) and §5-E2 (`/authorize`), recorded against live Restlet — see `docs/migration/restlet/`. |
| `e2e/oauth2/oidc-test.spec.mjs` | OIDC surface: `.well-known/openid-configuration` (root + realm-prefixed), `connect/jwk_uri`, `connect/checkSession`, `connect/endSession`, `idtokeninfo`, and id_token issuance/claims. |
| `e2e/oauth2/oauth2-endpoints-test.spec.mjs` | `connect/register` (RFC 7591/7592), the device flow (`device/code`, `device/user`), `token/revoke` (incl. that the token really stops validating), and the `resource_set` lifecycle with `If-Match`. Also carries two Restlet-migration **contract locks**: §5-E3 (`/oauth2/device/user`) and §5-E4 (`/oauth2/resource_set`, 20 rows). ⚠ **The 5-E4 describe is a byte oracle, not a shape guard** — including its `Content-Type` and `ETag` rows — and it cannot be re-recorded once 5d-1 flips `/oauth2` to CHF. Editing a string in it destroys the oracle; a red row after the flip is a divergence to record in `docs/migration/restlet/plan.md`, not a test to relax. |
| `e2e/oauth2/webfinger-test.spec.mjs` | `/.well-known/webfinger`. **Known broken** (pre-existing, not a migration regression): the success case is `test.fail()`-marked with the root cause — remove that annotation when phase 6 fixes it. |
| `e2e/uma/uma-test.spec.mjs` | `/uma` protocol endpoints: `uma-configuration` (the regression guard — phase 4 shipped it as a 500), `permission_request`, `authz_request`. Asserts **both** error shapes on purpose: CREST `{code,reason,message}` from the protection filter, UMA `{error,error_description}` from the endpoints. |
| `e2e/saml/saml-test.spec.mjs` | SAML IdP↔SP flow |
| `e2e/xacml/xacml-test.spec.mjs` | `/xacml` export/import: headers, realm styles, `?filter=`, import round-trip into a sub realm, and the auth paths (`401`/`403`) that no other layer covers. Creates realm `xacmltest` (via `/json/global-config/realms` — **not** the deprecated `/json/realms/root/realms`) and policy `xacml-e2e-policy` (via `/json` v1) if absent. Authenticates in disposable request contexts; see the cookie gotcha below. Paired with `openam-entitlements`' `XacmlRouterIT`, which covers route composition below the auth filter. |
| `e2e/xui/xui-httponly.spec.mjs` | XUI cookie flags |
| `e2e/common/openam-commons.mjs` | shared helpers: `OPENAM_BASE`, `ADMIN_USER`/`ADMIN_PASS`, `USERNAME`/`PASSWORD`, `getAdminToken(request)`, `getAuthToken(request, user, pass)` — all env-overridable |
| `e2e/common/oauth2-fixtures.mjs` | shared OAuth2/OIDC/UMA fixtures: OAuth2 + UMA provider creation, scope widening, per-spec clients, PKCE, session contexts, PAT/AAT, resource-set helpers. **Clients are per spec file** — Playwright runs spec files in parallel and rewriting a client invalidates its issued tokens. **Shared config is created here, never in one spec's `beforeAll`** — with files running in parallel, any spec that is not the creator races it on a cold container, so every "ensure" is create-if-absent and tolerates a concurrent creator. |

**This is the only layer that exercises a real HTTP request through a real server**, and therefore the only
one where Restlet's server adapter is in play (see [Gotchas](#gotchas-that-have-actually-bitten)).

## Running layer 4 locally against a WAR built from your tree

The recipe the §E contract-lock steps use (5-E2, 5-E3). Reproduces CI's `build-docker` leg closely enough that
the recorded bytes are the ones CI would see. Budget ~40 min cold, almost all of it Maven.

```bash
# 1. the artifacts (the Dockerfile COPYs all three)
mvn install -DskipTests -Dmaven.javadoc.skip=true -Dmaven.source.skip=true

# 2. a MINIMAL docker context -- never build with the repo root as context, it tars ~10G of target/
mkdir -p ctx/openam-server/target ctx/openam-distribution/openam-distribution-{ssoadmintools,ssoconfiguratortools}/target
ln <war> <ssoadmintools zip> <ssoconfiguratortools zip> into the matching ctx/ paths   # hard links, not copies
sed -E '/^#COPY openam-(server|distribution)\//s/^#//' \
    openam-distribution/openam-distribution-docker/Dockerfile > ctx/Dockerfile   # the same sed CI applies
docker build --build-arg VERSION=<project version> -t openam-e2e:<tag> ctx/

# 3. boot + configure exactly as build.yml does (opendj-idp + openam-idp on the test-openam network,
#    the ssoconfiguratortools conf.file, then create the demo user over REST)
# 4. npx playwright test oauth2
```

`/etc/hosts` must map `openam.example.org` to `127.0.0.1` — `OPENAM_BASE` defaults to
`http://openam.example.org:8080/openam` and the `COOKIE_DOMAIN=example.org` session cookie will not attach to
`localhost`.

**Copy the artifacts into a clean context dir rather than pointing the Dockerfile at `target/`.** Both `COPY`
lines are globs (`OpenAM-*.war`, `*.zip`), so a `target/` still holding a previous version's artifacts silently
copies **both** and the image gets whichever the glob expands to first.

**Rebuild the two distribution zips, not only the WAR.** `SSOAdminTools.zip` bundles the product jars, so a
module change reaches the image by two paths and a stale zip puts mixed provenance behind the gate. One
invocation covers all three:
`mvn -o install -DskipTests -Dmaven.javadoc.skip=true -Dmaven.source.skip=true -am -pl openam-server,openam-distribution/openam-distribution-ssoadmintools,openam-distribution/openam-distribution-ssoconfiguratortools`.

**To prove what the *running* container actually deployed, checksum the jar — do not read the banner.** The
build-number plugin stamps the branch's **merge base**, so the login banner says nothing about which classes
are in `WEB-INF/lib`. And the image ships **neither `jar` nor `unzip`**, so listing the archive in place fails.
What works:

```bash
docker cp openam-idp:/usr/local/tomcat/webapps/openam/WEB-INF/lib/<module>-<version>.jar /tmp/deployed.jar
md5sum /tmp/deployed.jar <module>/target/<module>-<version>.jar        # must match
```

### Two build hazards that cost a cycle each (2026-07-28)

- **Never `-T1C` this reactor.** `transform-jakarta/jato-shaded` consumes the root `jato-shaded` artifact
  through `maven-dependency-plugin` configuration rather than a declared `<dependency>`, so the reactor DAG has
  no edge between them and the parallel builder can start the consumer first. It then fails resolving
  `…:jato-shaded:jar:<version>` from the *remote* repo — and Maven **caches that miss**, so the obvious
  `-rf` retry fails again with "resolution is not reattempted". Recovery: delete
  `~/.m2/repository/org/openidentityplatform/external/com/iplanet/jato/jato-shaded/<version>/` and resume
  serially from `-rf org.openidentityplatform.external.com.iplanet.jato:jato-shaded`.
- **A half-installed `node_modules` fails the frontend module, not the network.** `openam-ui-js-sdk` died with
  `ERR_MODULE_NOT_FOUND` for a file *inside* an installed package. `rm -rf` that module's `node_modules` and
  resume. Note this rewrites `package-lock.json` — revert it, it is not part of your change.

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
| `openam-entitlements` | yes (`pom.xml:122-126`) | yes — `XacmlRouterIT` |
| `openam-uma` | yes (`pom.xml:79-83`) | **no** — declared but unused |
| `openam-oauth2` | **no** | n/a |

**`RestRouterIT` is the only test that wires the real module graph** (`@GuiceModules({HttpGuiceModule,
RestGuiceModule})`). Consequence: `OAuth2GuiceModule`, `OAuth2RestGuiceModule` and `LabelsGuiceModule` have
**zero** test coverage, so **no test can currently catch a broken OAuth2/UMA Guice binding** — it surfaces
as a `CreationException` when a server starts.

`XacmlRouterIT` is the second real-injector test but takes the opposite approach: a **minimal injector**
that binds only what the class under test needs, with `InjectorConfiguration.setGuiceModuleLoader(→ empty
set)` to kill classpath scanning. Prefer this when you want to assert one provider's route composition —
it is far easier to construct, and it does not drag in every `HttpRouteProvider` on the test classpath via
`ServiceLoader`. The trade-off is that it proves nothing about the real bindings or the `META-INF/services`
registration. Note that `Modules.override` **cannot** be used to patch `HttpGuiceModule`: it is a
`PrivateModule`, and the override only descends into private bindings when the base is a single
`PrivateElements`.

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
  Layer 4 is Linux-only and runs on one JDK, so anything it alone covers (for `/xacml`: the `401`/`403`
  auth paths) has **no cross-JDK/cross-OS guard**. Pair a layer-4 spec with a layer-2 IT where the
  behaviour can be asserted without a container; `e2e/xacml` + `XacmlRouterIT` split on exactly that line.
- `openam-oauth2/src/test/.../OpenAMClientRegistrationJwksUriIntegrationTest.java` is named "Integration" but
  ends in `Test`, so it is a **surefire unit test**. Naming here is not a reliable signal of layer.

<a id="unused-imports-are-not-caught-by-any-gate"></a>
### Unused imports are not caught by any gate

`javac` does not warn on them, the build has no checkstyle/PMD step, and `javadoc:javadoc` ignores them — so an
unused import survives a full green `verify` **and** the doclint gate indefinitely. Reviewing for them by eye is
unreliable (it produced a confidently wrong "none here" during the 5c-2 review). Decide it with a script:

```bash
find <module>/src -path '*org/openidentityplatform/*' -name '*.java' | sort | while read -r f; do
  body=$(grep -v '^import ' "$f")
  out=$(grep '^import ' "$f" | sed 's/^import static //; s/^import //; s/;$//' | while read -r imp; do
    sym=${imp##*.}; [ "$sym" = "*" ] && continue
    grep -qw "$sym" <<<"$body" || echo "   UNUSED: $imp"
  done)
  [ -n "$out" ] && { echo "== $f"; echo "$out"; }
done
```

`grep -w` on the simple name is what makes it usable: it will not match `JsonValue` inside `JsonValueBuilder`,
so there are no false "used" verdicts from prefix collisions. Two caveats — it skips `import x.*` (no simple
name to test), and a name that appears **only inside a comment or a javadoc `{@link}`** counts as used, which
is the conservative direction. As of 2026-07-30 the `openam-oauth2` migration tree has three real hits, all
pre-existing: `TokenRevocationHandler` (`ClientRegistration`), `TokenRevocationHandlerTest` (`JsonValue`).

The same shape catches the other silent class of defect — **relative doc links from Java sources**. From
`src/{main,test}/java/org/openidentityplatform/openam/<area>/<pkg>/` the repo root is **nine** `..`, not eight;
miscount it and nothing fails. Resolve them instead of counting:

```bash
grep -rnoE '(\.\./)+docs/[^"< )]*' --include=*.java <module>/src | while IFS=: read -r f l link; do
  echo "$f:$l -> $(cd "$(dirname "$f")" && readlink -m "$link")"
done      # then eyeball for any path that is not under the repo root
```

And the same for **markdown-to-markdown links**, which additionally have anchors to get wrong:

```bash
for d in docs/migration/restlet/*.md; do
  grep -oE '\]\([^)#][^)]*\.md(#[^)]*)?\)' "$d" | sed 's/^](//; s/)$//' | sort -u | while read -r link; do
    file=${link%%#*}; anchor=${link#*#}
    target=$(cd "$(dirname "$d")" && readlink -m "$file")
    if [ ! -f "$target" ]; then echo "MISSING FILE  $d -> $link"
    elif [ "$anchor" != "$link" ]; then
      slugs=$( { grep -oP '<a id="\K[^"]+' "$target"
                 grep -oP '^#{1,6} \K.*' "$target" | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9 -]//g; s/ /-/g'; } )
      grep -qxF -- "$anchor" <<<"$slugs" || echo "MISSING ANCHOR $d -> $link"
    fi
  done
done
```

⚠ That loop only sees **cross-file** links. Same-file `](#anchor)` links need their own pass over the same slug
set — a real blind spot, since most anchors in these documents are same-file:

```bash
slugs=$( { grep -oP '<a id="\K[^"]+' "$d"
           grep -oP '^#{1,6} \K.*' "$d" | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9 -]//g; s/ /-/g'; } )
grep -oE '\]\(#[^)]+\)' "$d" | sed 's/^](#//; s/)$//' | sort -u | while read -r a; do
  grep -qxF -- "$a" <<<"$slugs" || echo "MISSING $a"
done
```

⚠ **The `--` in that `grep -qxF --` is load-bearing, and leaving it out makes the script lie rather than fail.**
GitHub slugs a heading that starts with an emoji to a **leading hyphen** (`##### ⚠ Corrected in review…` →
`#-corrected-in-review…`), and this tree uses that form. Without `--`, `grep` parses such an anchor as a bundle
of short options and the test misreports — the first run of this sweep produced one false "MISSING ANCHOR"
against a link that was perfectly correct, which cost a round of chasing a non-bug. Two rules follow: pass `--`
before any variable that can start with `-`, and when a sweep reports a failure, **reproduce it by hand once**
before editing anything.

As of 2026-07-30 the real hits are four citations of one stale anchor: the
`Parity-preserved security debts` heading in `phase-5-oauth2.md` gained a trailing `(finding #7)`, so its slug
now ends `-finding-7`, while `plan.md` (×2) and `phase-5b-2.md` (×2) still link to the older form.

## Gotchas that have actually bitten

- ⚠ **Playwright does not send a string `data` verbatim when the request carries a JSON `Content-Type`**
  (measured 2026-07-29). The same single-quoted body — valid to a lenient parser, invalid to a strict one —
  answers **201** sent as `text/plain` and **400** sent as `application/json`, against one unchanged server.
  The client evidently passes through what is already valid JSON and re-encodes what is not, so the server
  never sees the bytes the test spelled out. ⇒ **any row that asserts how the server treats a deliberately
  malformed or non-standard body must use a raw client** (`node:http`, as
  `oauth2-endpoints-test.spec.mjs`'s `postWithoutContentType` and 5-E4 row 22 do). Written the natural way,
  such a row asserts Playwright's behaviour while looking exactly like a server assertion: three rows read as
  a clean `400 bad_request` for requests the server actually answers **201** to, and that reading nearly
  became a decision to reimplement the endpoint's parser.
- ⚠ **Which surefire report is the fresh one depends on how you invoked the run.** A full `mvn test` rewrites
  `target/surefire-reports/TEST-TestSuite.xml` (TestNG's whole-suite report). A `mvn test -Dtest=SomeClass`
  run does **not** — it leaves that file untouched at its previous contents and writes only
  `target/surefire-reports/junitreports/TEST-<fqcn>.xml`. Read the wrong one after a focused run and you get
  the previous full run's counts, which look plausible and are stale by hours; this is the same trap as
  leftover reports from another branch, one directory up. ⇒ **check the mtime**, and for mutation checking —
  where the whole point is to see the count go from green to red — read the per-class file under
  `junitreports/`. Also note the attribute order in those files: `<testcase classname="…" name="…">`, so a
  regex anchored on `<testcase name=` matches nothing and silently reports zero failures.
- **`mvn test` skips `*IT.java`.** Failsafe is bound at the root, so `verify` is the only goal that runs
  layer 2. Inner-loop `mvn test` gives false confidence.
- ⚠ **`-DskipTests=true` on a `verify` run skips failsafe too**, and the build still reports `BUILD SUCCESS`
  having run **no** IT. Combined with the report-freshness trap above this reads as a clean green: the
  `failsafe-reports` left in `target/` are from whenever an IT last actually ran, possibly another branch and
  possibly with failures. To run one IT and no unit tests:
  `mvn -o -pl <module> verify -Dtest=NoSuchUnitTest -Dit.test=<TheIT> -Dsurefire.failIfNoSpecifiedTests=false
  -Dfailsafe.failIfNoSpecifiedTests=false`.
- **In process, `Entity.getJson()` returns the object the producer set** — there is no serialization round
  trip inside a CHF chain. A handler that does `setEntity(someSet)` gives the test back that `HashSet`, not the
  `List` the wire would show, so assert membership (`containsExactly`) rather than equality against a literal.
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
- **In `e2e`, a session cookie silently outranks the `iPlanetDirectoryPro` header.**
  `POST /json/authenticate` sets an `iPlanetDirectoryPro` **cookie**, and Playwright's `request` fixture keeps
  a cookie jar for the whole spec file. `LocalSSOTokenSessionModule.validate:207-210` reads the cookie
  *first* and only then falls back to the same-named header. So a second `getAuthToken(request, …)` for a
  weaker user replaces the jar's session and downgrades every later "admin" call — the header is still sent,
  and still ignored. This failed the whole `xacml` suite on its first CI run with a `403` that looks exactly
  like a delegation problem. It also quietly breaks negative cases: with a cookie present, a "no token"
  request is not unauthenticated. `e2e/oauth2` survives only because it never authenticates a second
  identity. **Authenticate in a disposable `apiRequest.newContext()` and dispose it**, as `e2e/xacml` does,
  so the shared fixture's jar stays empty and each request carries the identity in its header. See
  [the write-up](migration/restlet/phase-2-integration-tests.md#the-cookie-that-outranks-the-header).
- ⚠ **An `e2e` container is good for ONE pass of `oauth2`/`uma`.** The shared fixtures rewrite the OAuth2
  client unconditionally on every run, which mints a new UMA resource-type id and orphans the policies of
  every resource set created before it. A second pass therefore dies in `warmUpResourceSetStore` with
  `resource-set store never became ready: 400 server_error`, over
  `EntitlementException: Resource Type <id> does not exist in realm /` (logged in **`debug/Entitlement`** and
  `debug/UmaProvider`), and each further pass degrades. Run `npx playwright test oauth2 uma` — or CI's
  unqualified `npx playwright test` — **once**, against a freshly built container, and rebuild before
  believing any red that follows an earlier run. Corollary: the per-suite counts are not separable after the
  fact, so capture the one pass's full output rather than `tail`-ing it and re-measuring. Full analysis, incl.
  the underlying product defect, in
  [phase-5c.md](migration/restlet/phase-5c.md#run-this-gate-against-a-fresh-container).

## Choosing a layer

- Pure logic, mocked collaborators → **layer 1**.
- Real CHF routing/filters/contexts in-process → **layer 2**, `RestRouterIT` as the template. Remember the
  `…IT` name means `mvn verify`.
- Real HTTP, real server adapter, real protocol behaviour → **layer 4**. It is cheaper than it looks: the
  fixtures and helpers already exist, and CI runs the specs unqualified, so a new `.spec.mjs` (or a new case
  in an existing `describe`) needs no wiring at all.
- **Layer 3 is rarely the answer** — it is heavyweight (fresh Tomcat per method), Linux-only in CI, and
  layer 4 covers the same protocol surface far more cheaply.
