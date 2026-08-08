# Phase 5d-2 — the deletion: as-built

What actually landed, sub-phase by sub-phase, and every value measured against a live container. Spec:
[phase-5d-2.md](phase-5d-2.md). Criterion numbers cite
[its verification criteria](phase-5d-2.md#verification-criteria).

---

<a id="as-built-5d-2a-i--recorded-2026-08-08"></a>
## As-built — 5d-2a-i, the dormant WebFinger route, recorded 2026-08-08

`/.well-known/webfinger` ported to CHF and **left unreachable**: the route is registered in the router, but
`web.xml` still maps `/.well-known/*` to the Restlet `WebFinger` servlet. Nothing changes on the wire. The
flip is 5d-2a-ii.

### Deliverables — five files

| File | Change |
|---|---|
| `openam-oauth2/.../openam/oauth2/http/WebFingerHandler.java` | new, 71 lines. One `@Get discover(...)`, per [D1](phase-5d-2.md#d1). `HEAD` needs no method (`Endpoints` maps it onto the `GET`); `BadRequestException`/`NotFoundException` need no handler (`@ExceptionHandler` dispatch is polymorphic). The only line that is not a transcription of the Restlet incumbent is the **null-servlet-request guard** — the incumbent NPE'd there on every request |
| `openam-oauth2/.../openam/oauth2/http/WellKnownHttpRouteProvider.java` | new, 157 lines. The chain of [D1](phase-5d-2.md#d1): `OAuth2ErrorFilter` outermost, realm layer, audit filter *inside* it, `OAuth2NotFoundHandler` as the endpoint router's default, `.well-known` + `webfinger` registered as `InvalidRealmNames`. Realm layer, `endpoint(...)` and `auditFilter(...)` are **byte-faithful copies** of `OAuth2HttpRouteProvider:210-266`, differing only in the route prefix |
| `openam-oauth2/.../META-INF/services/org.forgerock.openam.http.HttpRouteProvider` | +1 line. **The only production behaviour change in this commit** |
| `openam-oauth2/src/test/.../WebFingerHandlerTest.java` | new, 172 lines, 4 rows |
| `openam-oauth2/src/test/.../WellKnownRouterIT.java` | new, 353 lines, 7 rows |

Setter injection throughout the provider, no `@Inject` constructor: `HttpRouterProvider` loads providers through
`ServiceLoader` — which needs a public no-arg constructor — and only then calls `injectMembers`.

### The gate

| # | Criterion | Measured |
|---|---|---|
| 1 | `mvn -q -am -pl openam-oauth2 verify` | **surefire 1309 / failsafe 70**, 0 failures, 0 errors, 0 skipped. Against 5d-1b's carried baseline (1305 / 63) that is **+4** (`WebFingerHandlerTest`) and **+7** (`WellKnownRouterIT`). Nothing fell |
| 2 | `mvn install -DskipTests` + Cargo boot | BUILD SUCCESS, 156 modules, 40:03. Cargo: `OpenAM instance started, context=/test-am` ×3, `Tests run: 3, Failures: 0, Errors: 0`. **No** `CreationException`/`ConfigurationException`/`ProvisionException` anywhere, and no mention of the new classes in any error context |
| 3 | full `npx playwright test` | **153 declared, 152 passed, 1 skipped, 0 failed** (1.7 m, exit 0) — the soak baseline exactly, no movement in the declared count |
| 4 | `git diff --stat` vs the doc's file list | the five files above + this as-built and two docs. Nothing unlisted |
| 5 | D2 pre-port capture exists before this commit | [`artefacts/well-known-probes-pre-flip.md`](artefacts/well-known-probes-pre-flip.md), committed 2026-08-06 in `9ce100f9d2` |
| 6 | `WellKnownRouterIT` mutation-checked | see below |
| 7 | **dormancy** | see below |

### Criterion 6 — the IT, and what breaking it costs

Mutating the URI template (`"webfinger"` → `"webfingerX"`, `WellKnownHttpRouteProvider:116`) reddens **4 of 7
rows**, all with `expected: 200 but was: 404`. The three that stay green never reach the endpoint, which is
correct. Restored and re-run green; verified by `grep` rather than `git diff`, because the provider is still an
untracked file at that point.

Two rows exist for reasons a status assertion would not capture:

- **`theAuditEventCarriesTheResolvedRealm`** asserts the realm by **exact value**, because
  `AuditEventFactory.accessEvent` **omits the `realm` key entirely** when the realm is blank
  (`AuditEventFactory.java:43-49`). Hoisting the audit filter out of the realm layer — the obvious tidy-up,
  one wrap instead of one per endpoint — therefore produces an event with *no* realm key, which an
  `isNotNull()` would have caught only by accident.
- **`anUnresolvableRealmComesBackInTheOAuth2ErrorShape`** — `?realm=bogus` → **400 `invalid_request`
  `"Invalid realm, bogus"`**, asserted together with `doesNotContainKeys("code","reason","message")`. This is
  the repo's first test of the CREST→OAuth2 error conversion. It fails if `OAuth2ErrorFilter` is mounted
  *inside* `root` rather than outside it, which is the mistake the chain shape exists to prevent.

Row 3 asserts `verify(baseUrlProviderFactory, times(2)).get("/subrealm")` across the legacy path style and
`?realm=`. The realm picks the `BaseURLProvider` and hence the issuer in the JRD, so a status-only assertion
would pass with the realm silently root — precisely the WebFinger bug that matters, a sub-realm's clients told
the wrong issuer.

### Criterion 7 — dormancy, byte for byte

Image `openam-e2e:5d2ai` (`sha256:840538af…`), built from the working tree's WAR (293,170,782 B, mtime
2026-08-08 07:04). `openam-idp` + `openam-sp` + two OpenDJ, `build.yml`'s `conf.file` verbatim, probes against
`http://openam.example.org:8080/openam` — **the same base URL as the pre-flip capture**, which is required:
the issuer strings in the control document are absolute.

Provenance by **md5 of the deployed jar, not the banner**: `8a58f87a2459127a481a1041022e48df`, identical in the
running container, the exploded WAR, the WAR archive and the module build. The deployed jar's SPI file carries
`WellKnownHttpRouteProvider` as its third line.

The servlet mapping was asserted **structurally**, not by eye: parsing `web.xml` from
`openam-server-only/src/main/webapp/` (105 mappings) and from the built WAR (121) gives **source-only = ∅** —
every source mapping survives verbatim, the 16 extra being JAXRPC servlets the assembly appends.
`/.well-known/*` → `WebFinger` and `/oauth2/*` → `OpenAM` in both.

**Result: the 19-probe script-generated region is byte-identical to the pre-flip capture — status lines,
headers, body byte counts and md5s — with only `Date:` differing.**

| Answer | Probes | md5 |
|---|---|---|
| 500 JSON, 149 B | **14** | `dd82fa5d59a42118454371b094ddfa6a` |
| 404 JSON, 102 B | 2 | `1b2c72cf6c481841700579cec2730fd2` |
| 404 JSON, 70 B | 1 | `2c54883f2d648b11fa2c17d7ad640f48` |
| 200 JSON, 1515 B — **the control** (`/oauth2/.well-known/openid-configuration`) | 1 | `74c2c745fbbdc2c4bdd52cbe748d83ed` |
| 0 B (probe 13, `HEAD`) | 1 | `d41d8cd98f00b204e9800998ecf8427e` |

`Server: Restlet-Framework/2.4.4` on every `/.well-known` row, and the **only** 200 in the whole capture is
probe 16, the control. No probe returned a JRD. For this sub-phase a working endpoint would have been a
**failure**, not a success.

<a id="the-oracle-needs-a-post-suite-container"></a>
### ⚠ The oracle is only comparable on a post-suite container

The first probe run raised a false alarm on the **control** row: on a freshly configured container
`/oauth2/.well-known/openid-configuration` answers **404, 82 B**
`{"error":"not_found","error_description":"No OpenID Connect provider for realm /"}`, not the 1515-B document.

The cause is fixture state, not code: the `oauth-oidc` service does not exist until `ensureOAuth2Provider`
(`e2e/common/oauth2-fixtures.mjs:92`) creates it, and nothing deletes it afterwards — so the pre-flip capture
was taken on a container the e2e suite had already run against. Re-running the probes after the Playwright
suite reproduced the 1515-B control exactly.

**Run the suite before capturing, or the control row reads as a regression.** This applies to criterion 8's
post-flip capture too.

<a id="the-control-row-is-a-free-non-vacuity-check"></a>
### The control row is a free non-vacuity check

The control returning its document proves the CHF router **built with `WellKnownHttpRouteProvider` in its SPI
list**. `HttpRouterProvider.get()` (`HttpRouterProvider.java:46-52`) builds **one** `Router`, loops every SPI
provider, and is bound at `HttpGuiceModule.java:45` as a `Singleton` `@Named("HttpHandler") Handler` — the root
handler for the whole CHF servlet. A failure inside our `get()` aborts that loop and **no** route is added, so
`/oauth2` would have died with it. That is a stronger in-container signal than the Cargo boot, and it costs
nothing. The Cargo boot's 13 × HTTP 200 on `/test-am/json/...` is the same argument on the other transport.

<a id="the-war-build-banner-lies"></a>
### ⚠ The WAR's build banner lies about provenance

`WEB-INF/classes/serverdefaults.properties` in this WAR reads
`com.iplanet.am.version=OpenAM 16.2.0-SNAPSHOT Build bccbc9c4d9 (2026-August-06 14:19)` while `HEAD` is
`9ce100f9d2`. `ssoadm` echoes it, so **`The version of your server instance is: … Build bccbc9c4d9` is not
evidence of what is deployed.**

Cause: `openam-server-only/target/OpenAM-ServerOnly-*/` was not cleaned, and `openam-server-prepare-war.xml`'s
ant `<copy>` filter is timestamp-based, so it declined to rewrite the `@REVISION@`/`@DATESTAMP@` tokens.
Harmless here — every WAR entry is dated 2026-08-08, and `bccbc9c4d9..HEAD` touches only `openam-oauth2` code
(md5-verified fresh), docs and `e2e/`. But **use jar md5s, not the banner**, and add a `clean` on
`openam-server-only` to the image recipe. This is the second time provenance-by-banner has misled in this
phase family; 5-E4 recorded the first.

### Handed to 5d-2a-ii

1. The pre-flip oracle is captured and cannot be re-derived — 5d-2a-ii destroys the endpoint it measures.
   Criterion 8 is the **inverse** test: every one of the 19 probes must land on a divergence row 33–36 with a
   written reason, and the control's md5 must be unchanged.
2. Capture the post-flip probes on a **post-suite** container, per the note above.
3. `WellKnownRouterIT` and `WebFingerHandlerTest` already pin the CHF answers the flip makes reachable —
   200 JRD, 400 `bad_request`, 404 `not_found`, and the 400 `server_error` guard. `webfinger-test.spec.mjs`'s
   new rows should assert the same values, and its header comment's "broken today" claim must be **kept**.

---

<a id="as-built-5d-2a-ii--recorded-2026-08-08"></a>
## As-built — 5d-2a-ii, the flip, recorded 2026-08-08

`/.well-known/*` moved off the Restlet `WebFinger` servlet onto the CHF router, and both Restlet classes
deleted. The route 5d-2a-i built dormant is now the one that answers, and **the WAR carries no `org.restlet`
reference at all**. One `<servlet-mapping>` hunk reverts it.

### Deliverables — four files, plus the other half of the oracle

| File | Change |
|---|---|
| `openam-server-only/src/main/webapp/WEB-INF/web.xml` | the `WebFinger` `<servlet>` block deleted (`:1046-1068` — **the WAR's last four `org.restlet` references**), and the `/.well-known/*` `<servlet-mapping>` repointed to `<servlet-name>OpenAM</servlet-name>`, placed contiguously after the `/oauth2/*` mapping. **This is the whole behaviour change of the commit, and the one-hunk revert** |
| `openam-oauth2/.../org/forgerock/openidconnect/restlet/WebFinger.java` | deleted, 85 lines |
| `openam-oauth2/.../org/forgerock/openidconnect/restlet/OpenIDConnectDiscovery.java` | deleted, 101 lines |
| `e2e/oauth2/webfinger-test.spec.mjs` | rewritten, **2 rows → 8** — criterion 9 below |
| [`artefacts/well-known-probes-post-flip.md`](artefacts/well-known-probes-post-flip.md) | new, 443 lines. The 19 probes re-run — the other half of the [pre-flip oracle](artefacts/well-known-probes-pre-flip.md) |

The [spec's 2026-08-06 finding](phase-5d-2.md#new--modified--deleted) — that nothing outside `web.xml` and the
two classes' own mutual reference names either of them — held. The reactor compiles, and the Cargo boot raises
no Guice error (criterion 2), which is where a missed `META-INF/services` entry or string binding would have
surfaced.

### The gate

| # | Criterion | Measured |
|---|---|---|
| 1 | `mvn -am -pl openam-oauth2 verify` | BUILD SUCCESS, 46 modules, 8:41 min. **surefire 1309 / failsafe 70**, 0 failures, 0 errors, 0 skipped — **identical to 5d-2a-i's** 1309/70. This commit deletes two production classes and **zero** tests, so an unchanged count is the point of the row, not a coincidence. Reactor-wide 10018 surefire / 156 failsafe, all green. ⚠ Scope: `openam-server-only` is **not** in `-pl` because it has no `src/test` at all; it is built for real in criterion 2 and again in the image |
| 2 | `mvn install -DskipTests` + Cargo boot | Cargo: BUILD SUCCESS 8:27 min, `OpenAM instance started, context=/test-am` ×3, `Tests run: 3, Failures: 0, Errors: 0, Skipped: 0`, and **zero** `CreationException` / `ConfigurationException` / `ProvisionException`. The install itself was interrupted and resumed — [recorded below](#criterion-2--the-install-was-interrupted) |
| 3 | full `npx playwright test` | `--reporter=list`, byte-identical to `build.yml:307`, no env overrides: **159 declared, 158 passed, 1 skipped, 0 failed**, 1.4 m. Against the 153/152/1/0 baseline that is **+6** — exactly the movement criterion 3 sanctions for this sub-phase: **−1** for the deleted 500-pinning row, **+7** new rows. **No other row moved** |
| 4 | `git diff --stat` vs the spec's file list | the four files above, this as-built, and the docs it cites. The only other paths in the working tree are the two `openam-ui/*/package-lock.json` files Maven rewrites on every build — npm churn, to be reverted before the commit and no part of this change |
| 8 | the 19 probes vs the pre-flip capture | 18 of 19 land on a divergence row; the control is unchanged; probe 10 lands on **[new row 37](#row-37)**. [Classification below](#criterion-8--where-the-nineteen-probes-landed) |
| 9 | `webfinger-test.spec.mjs` | `test.fail()` removed and the row **genuinely passes** (Playwright did not report "expected to fail but passed"); the 500-pinning row deleted; the header comment's "broken today" claim **kept**, reframed as the historical record of what the port fixed and citing the byte evidence (14 of 19 probes, one 149-byte body, md5 `dd82fa5d…`). 7 new rows cover divergence rows 33–36. **All 8 pass** |
| 10 | `grep -c "org.restlet" web.xml` | **0** — the WAR's last Restlet reference is gone. ⚠ The criterion's closing clause needed a correction; see [correction 3](#four-corrections) |

### Provenance — by jar md5, not the banner

Image `openam-e2e:5d2aii`
(`sha256:1ad54f240f0e817be55eb1757ae65381ee003a010e924138656a19e1b2f7893f`), fresh `openam-idp` +
`openam-sp` + two OpenDJ, `build.yml`'s `conf.file` verbatim. Per [the 5d-2a-i trap](#the-war-build-banner-lies)
provenance is taken from the deployed jar, not the WAR banner: `openam-oauth2-16.2.0-SNAPSHOT.jar` md5
**`de027e091684f2f80ea842a57f5b9201`**, identical in the running container and the module build, and the
deployed jar's SPI file carries `org.openidentityplatform.openam.oauth2.http.WellKnownHttpRouteProvider` as
its third line.

The container's `WEB-INF/web.xml` has **0** `org.restlet` and **0** `WebFinger`, and `/.well-known/*` maps to
`OpenAM` — the flip is in the artefact under test, not only in the source tree.

<a id="criterion-2--the-install-was-interrupted"></a>
### ⚠ Criterion 2 — the install was interrupted, and why the WARs are still this commit's

Recorded honestly rather than re-run: `mvn -pl openam-server-only,openam-server clean` (BUILD SUCCESS,
10.6 s), then `mvn install -DskipTests` was **stopped externally at module 143/156** after ~42 min. That is an
external stop, **not a build failure** — no module reported an error. It was resumed with
`mvn install -DskipTests -rf :openam-distribution-ssoadmintools` → BUILD SUCCESS, 2:19 min.

Modules **128** (`openam-server-only`) and **129** (`openam-server`) had both completed in the *first* run,
and their WARs are timestamped **09:56** and **09:58** — after the **09:33** clean. Both are therefore built
from this commit, which is the only thing criterion 2 needs from the install leg.

The explicit `clean` was deliberate, not hygiene: [5d-2a-i recorded](#the-war-build-banner-lies) that a
surviving `openam-server-only/target/` is exactly what made the WAR banner lie, and **this commit's entire
payload is a `web.xml` edit inside that module**. A stale staging directory would have shipped the old
mapping while every other signal read green.

<a id="criterion-8--where-the-nineteen-probes-landed"></a>
### Criterion 8 — where the nineteen probes landed

Re-run on the **post-suite** container (Playwright first, then the probes), per
[the 5d-2a-i warning](#the-oracle-needs-a-post-suite-container). **The control, probe 16, is unchanged:
1515 bytes, md5 `74c2c745fbbdc2c4bdd52cbe748d83ed`** — the one value the pre-flip capture still arbitrates,
and the [free non-vacuity check](#the-control-row-is-a-free-non-vacuity-check) that the router built at all.

Eighteen of nineteen land on a divergence row. One does not, and gets [row 37](#row-37).

| Probes | Pre-flip → post-flip | Row |
|---|---|---|
| 01, 02, 11 | 500 (149 B) → **200 JRD**, 152 B, md5 `2df598686034f3c5ecae01102e6a3c39` | 33 |
| 03, 07 | 500 → 400 `bad_request` "No resource provided in discovery.", 80 B, md5 `16b0e18092c50b4ad565a76350346372` | 33 |
| 04, 05 | 500 → 400 `bad_request` "No or invalid rel provided in discovery.", 86 B, md5 `08e8fec4a79efd233fe1fefd26dc38d1` | 33 |
| 06 | 500 → 404 `not_found` "Invalid parameters.", 63 B, md5 `e9e7a36eb75f9e8899a980e8085697a5` | 33 |
| 13 (`HEAD`) | 500 → 200, 0 B (no body, correct for `HEAD`) | 33 |
| 09, 12, 15, 17, 18, 19 | 500 (404, 102 B for 17) → 404 `{"error":"not_found","error_description":"Not Found"}`, 53 B, md5 `6995583eaf3206e9093f2f4dfc469b72` | 34 |
| 08 | 404 (70 B) → 400 `invalid_request` "Invalid realm, /bogus", 71 B, md5 `68c64a4ffebaee87bf293484fbcdcf06` | 35 |
| 14 (`POST`) | 500 → 405 + `Allow: GET`, 71 B, md5 `3ffb126e2da396a161e9cbb88c3a3487` | 36 |
| 16 — the control | 1515 B, md5 `74c2c745…` | **unchanged** |
| **10** | 404 (102 B) → **500, `Content-Length: 0`, no `Content-Type`** | **new [row 37](#row-37)** |

Row 33 is the phase's one intentional user-visible fix, and it is now measured on the wire rather than
predicted: the endpoint serves a JRD, and its three validation answers — which
[had never once executed in this deployment](artefacts/well-known-probes-pre-flip.md) — execute.

<a id="four-corrections"></a>
### Four corrections — measurements replacing predictions

1. **Probe 11 was predicted wrong, and the prediction has been corrected in the artefact.**
   [`artefacts/well-known-probes-pre-flip.md`](artefacts/well-known-probes-pre-flip.md) grouped
   `/.well-known/realms/root/webfinger` with the row-34 no-match probes. Measured: **200 JRD, row 33** — the
   `/realms/{realm}` spelling resolves, exactly as `WellKnownRouterIT.theRealmsPathStyleReachesTheEndpoint`
   and [research §10](phase-5d-2-research.md#10) already said. Per
   [the oracle rule](INDEX.md#the-oracle-record) the measurement replaces the prediction, so the artefact's
   *expectation* row was edited on 2026-08-08 with a pointer here. ⚠ **No measured value in that artefact was
   touched** — statuses, headers, byte counts and md5s are the Restlet oracle and are not re-derivable.
2. **`Invalid realm, /bogus` keeps the leading slash.** It survives into `RealmContextFilter`'s message;
   `WellKnownRouterIT` had only pinned the bare `bogus` form, so the exact wire string was unpinned until now.
   The e2e row asserts it verbatim.
3. **`ForgeRockRest` already had zero `<servlet-mapping>` blocks before this commit** — criterion 10's
   closing clause ("after it, `ForgeRockRest` is a declaration with no mappings") reads as though this commit
   emptied it. It did not: the `/.well-known/*` mapping pointed at **`WebFinger`**, not `ForgeRockRest`. A
   structural parse of `web.xml`, `HEAD` vs working tree, gives exactly:
   - mappings only-in-original `[('WebFinger','/.well-known/*')]`, only-in-new `[('OpenAM','/.well-known/*')]`,
     **total unchanged at 105**;
   - servlet declarations **91 → 90**, the single removal being
     `('WebFinger','org.restlet.ext.servlet.ServerServlet')`.

   Nothing else in `web.xml` moved. `ForgeRockRest`'s own declaration is 5d-2b's to delete.
4. **TestNG reports one `TestSuite`, so a per-class grep of the build log proves nothing.** `openam-oauth2`
   emits no per-class `Tests run:` lines — grepping for `WellKnownRouterIT` returns nothing **even when it
   ran**. Only the aggregate is observable, which is why criterion 1 cites counts and not class names. Noted
   in [test-infrastructure.md](../../test-infrastructure.md#layer-1--unit-tests-surefire).

<a id="row-37"></a>
### New divergence row 37 — bare `/.well-known/` answers a bodyless 500

The one probe that matched no existing row. `GET /.well-known/` — bare, **with the trailing slash**:

| | |
|---|---|
| Before (Restlet) | **404**, 102 B, `{"error":"Not Found","error_description":"The server has not found anything matching the request URI"}` — `OAuth2StatusService` |
| After (CHF) | **500**, `Content-Length: 0`, **no body, no `Content-Type`** |

**This is pre-existing CHF servlet/router behaviour, not something 5d-2a-ii introduced**, and that is the
part worth recording. Measured on the same container, in the same session:

| Path | Answer |
|---|---|
| `/oauth2/` | 500, len=0 |
| `/uma/` | 500, len=0 |
| `/json/` | 500, len=0 |
| `/oauth2` | 404, 53 B |
| `/json` | 404, 75 B |
| `/.well-known` | 404, 53 B |

Every trailing-slash spelling answers the bodyless 500; every no-trailing-slash spelling answers a proper
404. **`/json` is the oldest CHF surface in the product and predates this migration entirely** — so the
defect is the framework's, and `/.well-known/` has merely joined the set. The identical measurement on
`/oauth2/` is already [divergence row 27](plan.md#expected-divergences-at-the-flip), pinned at 5d-1c for the
same reason.

The root cause is the one **row 27 already measured**, and it is not the `UriRouteMatcher` trailing-slash
limitation that first looks like the culprit: commons `RouteMatchers.getRemainingRequestUri:164-170` sublists
without a guard, throwing `IllegalArgumentException: fromIndex(4) > toIndex(3)`. Row 37 therefore records no
new defect — it exists only because criterion 8 requires every probe to land on a row and row 27 is scoped to
`/oauth2/`. Tracked in [decisions.md](decisions.md#chf-cleanup-backlog). No stack trace reaches
`catalina.out`; the exception is swallowed, which is why the diagnosis had to come from the sibling paths.

**Direction: narrowing** — a pre-existing framework defect newly exposed on one more path, the flip trading
Restlet's 404 for the CHF stack's uniform bodyless 500.

**Open follow-up, explicitly out of scope here.** A bodyless 500 on a public endpoint deserves its own phase,
and per [the repo's own stance](chf-patterns.md#14-framework-defects-fix-them-dont-pattern-around-them-2026-07-21)
the fix belongs in the CHF layer, not in a per-route workaround. But a CHF-layer fix moves `/json/`,
`/oauth2/` and `/uma/` too, and all three have their own byte oracles — so it is not 5d-2a-ii's to make.

### Handed to 5d-2b

1. **`GuicedRestlet` and `OAuth2StatusService` are now self-referencing orphans.** With `WebFinger` and
   `OpenIDConnectDiscovery` gone, nothing outside the Restlet packages reaches either. They are left in place
   deliberately — 5d-2b deletes those packages wholesale, and pulling two classes forward would split a
   revertible commit for no gain.
2. **`WellKnownHttpRouteProvider.java:48` points at a file that no longer exists.** Its class javadoc names
   the incumbent it replaced — `openam-oauth2/.../restlet/WebFinger.java` — as deliberate provenance. It is
   `{@code}`, not `{@link}`, so [doclint](../../test-infrastructure.md#gotchas-that-have-actually-bitten)
   does not fail on it; keep or reword it as a decision, not by accident.
3. **The `/.well-known` oracle is now two files.** Pre-flip is Restlet and unrepeatable; post-flip is the CHF
   contract and *is* repeatable via `e2e/tools/well-known-probes.sh`. A later phase that changes the OAuth2
   error layer should diff against the post-flip capture.
4. [Row 37](#row-37)'s bodyless 500 is an open follow-up, not a 5d-2b deletion target.
