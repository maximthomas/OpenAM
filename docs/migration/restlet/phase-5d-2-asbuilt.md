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
