# Backend parity — deployed AM vs the local API server

Parity check of the **`@local-server` lane** across the two backends that lane is meant to be
portable between: the deployed AM container (`local/openam-up.sh`) and the local API server
(`local/server.mjs`). Both served the **same built XUI**, byte for byte, so any divergence is a
backend difference and not a build difference.

**Result: the two backends agree on 23 of 23 tests — but only in the run that was clean on both.**
One test, `xui-login.spec.mjs:123`, failed on the local server in run 1 and passed on the same
server in run 2 with nothing changed between them. **The two local runs therefore disagree with
each other, so the lane is not stable on the local server**, and the one test that differs from the
deployed side is the same test [`xui/BASELINE.md`](../xui/BASELINE.md) records as flaky and
**never root-caused**.

| Run | Backend | Passed | Failed | Skipped | Playwright | Measured wall-clock | Exit |
|---|---|---:|---:|---:|---|---|---|
| Deployed | AM container | **23** | 0 | 0 | 54.3s | **56s** | 0 |
| Local 1 | `server.mjs` | 22 | **1** | 0 | 1.3m | **80s** | 1 |
| Local 2 | `server.mjs` | **23** | 0 | 0 | 43.3s | **45s** | 0 |

The divergence is **one test, and it is not deterministic**. Deployed vs local run 2 is a clean
23/23 match. Deployed vs local run 1 differs by exactly `xui-login.spec.mjs:123`. Because local run
2 passed the test local run 1 failed, this is **flakiness on the local server, not a demonstrated
behavioural difference between the backends** — no test failed on both local runs, and no test
failed on the deployed side at all.

Recorded: 2026-08-14. Repo commit `35c2e3970c3576262626b14db62997d669a2d8ca`
(`features/openam-ui-migration`). Working tree clean before and after — no spec, tag, config or
product file was modified, and nothing was fixed in response to the failure.

---

## Gate verdict — task 2.17

**Task 2.17's criterion is "the backends agree", and on that criterion the gate is met.** The two
backends agree on **23 of 23** tests in every clean pairing. The single non-agreement,
`xui-login.spec.mjs:123`, is non-deterministic and reproduces on **both** backends — it is
classified below as neither a local-server bug nor a spec belonging on the deployed instance, so it
is not a disagreement *between* the backends. No spec was retagged.

**What this verdict does not assert.** It is deliberately narrower than a clean bill of health, and
the difference is the reason the criterion had to be chosen rather than assumed:

- **Not that the lane is stable.** It is not. The two local runs disagree, and the same test is
  recorded failing 3 of 6 gated runs against the deployed AM in [`xui/BASELINE.md`](../xui/BASELINE.md).
  Instability is a property of the shared suite, on both backends, and predates this group — see
  [Classification](#classification). It is **open, not closed by this gate.**
- **Not that the local backend is a faithful stand-in for AM.** Three runs, one lane, one build. The
  baseline needed 14 runs across 4 batches to characterise this suite.
- **Not that the acceptance gate has moved.** Per D13 and the `ui-local-backend` requirement *"The
  local backend is not the acceptance oracle"*, sign-off for a UI build change still requires the
  suite green against a deployed AM. This document changes nothing about that.

Passing 2.17 closes group 2. Per the Migration Plan's sequencing constraints it unblocks nothing —
phases 1 and 2 do not wait for phase 0b.

---

## The timing correlation carries over

`xui/BASELINE.md` records that on the deployed side, under the original protocol, every gated run
at or below 241s passed and every run at or above 252s failed — the failure tracked run duration,
and always at `xui-login.spec.mjs:123`. **The same relationship appears here on the other backend:**

| Local run | Measured wall-clock | `xui-login.spec.mjs:123` |
|---|---|---|
| 1 | 80s | **failed** |
| 2 | 45s | passed |

Run 1's 80s includes the failing test's own 30s timeout, so the honest comparison is 50s of test
work versus 45s — the slower run is the one that failed, consistent with the baseline's finding.
Two runs is not enough to call that a correlation; it is recorded because it matches a pattern
already documented on the deployed backend, and because it suggests the latent defect is in the
**XUI or the spec** rather than in either backend — it now reproduces on both.

---

## Environment

### Backend A — deployed AM

| | |
|---|---|
| AM version | `16.2.0-SNAPSHOT`, revision `8628aba262`, built 2026-August-08 09:56 (`/json/serverinfo/version`) |
| Container image | `openam-e2e:local`, `sha256:1ad54f240f0e…` (also tagged `openam-e2e:5d2aii`), built 2026-08-08T11:05:52+03:00 |
| Base image | `tomcat:11-jre25` |
| Servlet container | Apache Tomcat 11.0.24 |
| JVM | OpenJDK 25.0.3 LTS, Temurin-25.0.3+9 |
| AM container | `openam-idp`, started 2026-08-14T19:15:01Z, healthy |
| Identity store | `opendj-idp`, `openidentityplatform/opendj:latest`, `sha256:dfeba0268d08…`, healthy |
| Base URL | `http://openam.example.org:8080/openam` (`OPENAM_BASE_URL` unset — the default in `common/openam-commons.mjs`) |
| Container user | `uid=1001(openam) gid=0(root)` |

**Identical image digest to `xui/BASELINE.md`** (`sha256:1ad54f240f0e…`) — the AM side is the same
image the baseline was recorded against. The container itself is new: it was destroyed and rebuilt
by `openam-reset.sh` immediately before these runs, so its configuration is the post-configuration
baseline and not residue from earlier tasks.

### Backend B — the local API server

| | |
|---|---|
| Process | `local/server.mjs --port 8090`, Node v22.22.2, Node standard library only |
| Base URL | `http://localhost:8090/openam` (passed as `OPENAM_BASE_URL`) |
| State | in-memory, built at startup from `local/capture/` (1 realm) |
| AM surface | reads, authentication, sessions, bootstrap configuration, realm and service admin, user profile; a labelled 501 outside that |
| Startup | serving ~2s after launch |

### Configuration differences between the two backends

Recorded because they are real and were not corrected — neither produced a test divergence:

| `/json/serverinfo/*` | Deployed | Local |
|---|---|---|
| `cookieHttpOnly` | `false` | `false` |
| `secureCookie` | `false` | `false` |
| `cookieName` | `iPlanetDirectoryPro` | `iPlanetDirectoryPro` |
| `domains` | `["example.org"]` | `[]` |

`/json/serverinfo/version` also differs: the deployed instance returns a real `revision`
(`8628aba262`) and `date`, and **requires a session** (403 `No session for request.` without one);
the local server answers unauthenticated with the placeholders `<REVISION>` and `<BUILD-DATE>`.
No test in this lane asserts on either, so neither shows up in the results.

### The XUI build both backends served

| | |
|---|---|
| Artifact | `openam-ui/openam-ui-ria/target/openam-ui-ria-16.2.0-SNAPSHOT-www.zip` |
| Size | 2,450,123 bytes |
| SHA-1 | `51335a54d29c1b52d42549a3c53ebb10d2f9e605` |
| Contents | 854 zip entries, **652 regular files** |
| Built | 2026-08-14 21:02 (entry timestamps) |
| Deployed file count in container | 652 — matches the archive |

**How identical bytes were ensured.** Not by assuming the two loaders agree — by comparing the two
served trees directly:

1. **Same source artifact by construction.** Both were invoked with no argument, and both resolve
   the same default: `xui-deploy.sh` builds the path from `am_version()`, and `server.mjs` resolves
   the same `-www.zip`. The server's startup banner names the file it unpacked, and it is the same
   path `xui-deploy.sh` logged.
2. **Same bytes by verification.** A per-file `md5sum` manifest was taken of the container's
   deployed `/usr/local/tomcat/webapps/openam/XUI` (via `docker exec`) and of the local server's
   unpacked tree (`/tmp/xui-www-QKQ6KL`), each sorted by path:

   ```
   deployed  652 files
   local     652 files
   diff      no differences — every path present on both sides with the same md5
   md5 of the deployed manifest  9467256ccf39e84e798593400ef67f48
   md5 of the local manifest     9467256ccf39e84e798593400ef67f48
   ```

   Equal file counts, equal paths, equal per-file digests, and an equal digest over the whole
   manifest. **Both backends served identical bytes**, so a divergence in the results cannot be a
   build difference.

**One caveat against `xui/BASELINE.md`.** The baseline records this artifact at SHA-1
`143932f4268514b924eb920fe88929298fa2ec65`, built 2026-08-08 09:52. The zip present now has the
**same size (2,450,123) and the same 652 files** but a **different SHA-1**
(`51335a54d29c1b52d42549a3c53ebb10d2f9e605`) and entry timestamps of 2026-08-14 21:02 — it is a
**rebuild** of the same source, not the byte-identical archive the baseline measured. An identical
size and file count is consistent with only embedded build timestamps differing, but the original
artifact is gone, so **this could not be proven** — see [Not determined](#not-determined). It does
not affect the parity finding, which only requires the two backends to serve the same bytes as each
other, and they did.

### Test runner

| | |
|---|---|
| Playwright | 1.60.0 |
| Node | v22.22.2 |
| Config | `e2e/playwright.config.mjs` — `retries: 0`, `workers: 1`, `timeout: 180000`, `expect.timeout: 15000` |
| Browser | Chromium, headless |
| Tracing | `--trace=off` on all three runs |
| Filter | `--grep @local-server` |

`retries: 0` is what makes the run-1 failure visible rather than retried away.

---

## How this was produced

1. **Four-point precondition gate**, re-run from scratch: the local server started and served
   (`/openam/XUI/index.html` 200, `/openam/json/serverinfo/*` 200); the deployed instance answered
   (`/openam` 302, `/openam/XUI/` 200, `/openam/json/serverinfo/*` 200, `amadmin` authenticate
   returned a `tokenId`); Docker reached both containers (`openam-idp` and `opendj-idp` up and
   healthy, `docker exec` returning `uid=1001(openam)`); and `xui/BASELINE.md` was present.

2. **Reset to the post-configuration baseline** — both containers destroyed and rebuilt, so the
   deployed side is `BASELINE.md`'s configuration and not what the last few tasks left behind:

   ```
   ./local/openam-reset.sh > /tmp/2.17-reset.txt 2>&1     # exit 0, 98s
   ==> ready
   ```

   The image layer was cached, so the configurator re-ran but the image did not rebuild —
   the digest is unchanged from the baseline's.

3. **Clean Grunt-built `/XUI` redeployed** over the reset container:

   ```
   ./local/xui-deploy.sh > /tmp/2.17-deploy.txt 2>&1      # exit 0, ~1s
   ==> deployed. http://openam.example.org:8080/openam/XUI/ now serves 652 files
   ```

4. **Local server started on the same artifact**, and the two trees compared by md5 manifest as
   above before any test ran.

5. **The lane run three times, to three separate files** — once deployed, twice local. Separate
   process invocations rather than `--repeat-each`, because the risk being probed is state one run
   leaves behind for the next:

   ```
   npx playwright test xui/ --grep @local-server --reporter=line --trace=off > /tmp/2.17-deployed.txt 2>&1
   OPENAM_BASE_URL=http://localhost:8090/openam npx playwright test … > /tmp/2.17-local-1.txt 2>&1
   OPENAM_BASE_URL=http://localhost:8090/openam npx playwright test … > /tmp/2.17-local-2.txt 2>&1
   ```

   No `-x`, so every run reports its whole divergence picture rather than stopping at the first
   failure. Results were read from these four text files only; `playwright-report/` and
   `test-results/` were not opened.

---

## Lane size

**5 spec files, 23 tests** — Playwright's own count from `--list --grep @local-server`, unchanged
from `xui/BASELINE.md`.

| Spec | Tests |
|---|---:|
| `xui/xui-cache-busting.spec.mjs` | 2 |
| `xui/xui-login.spec.mjs` | 4 |
| `xui/xui-profile.spec.mjs` | 3 |
| `xui/xui-realms.spec.mjs` | 7 |
| `xui/xui-services.spec.mjs` | 7 |
| **Total** | **23** |

**That both sides ran the whole lane is evidenced by the `list` reporter's own enumeration**, not by
the coverage footer. Each of the three runs numbered its tests `[1/23]` through `[23/23]`, with
identical titles in identical order on both backends, and Playwright reported 0 skipped in all
three. Equal counts of equal tests is what this gate needs: neither side quietly ran fewer.

**Correction — the backend-coverage footer did not run, on any of the three runs.**
`playwright.config.mjs` lists `./common/backend-tag-reporter.mjs` last, but all three commands
passed `--reporter=line`, and a CLI `--reporter` *replaces* the config's reporter list rather than
appending to it. That is the exact trap task 2.16's note records having hit while building the PR
job, and these runs walked into it. So the footer's `undeclared none` was **never asserted here**,
and the 9 excluded spec files were not independently confirmed to be excluded *by the tag filter*
rather than by some other cause. `xui-auth-modules.spec.mjs` and `xui-auth-chains.spec.mjs` are
`@deployed-am` only by design and are correctly absent, but that is read from their tags, not from a
footer this run produced. Anyone re-running this comparison should append the reporter
(`--reporter=line,./common/backend-tag-reporter.mjs`) so the D16 coverage block is actually emitted.

---

## Per-test results

`P` = passed, `F` = failed. No test was skipped in any run.

| # | Spec | Test | Deployed | Local 1 | Local 2 |
|---:|---|---|:--:|:--:|:--:|
| 1 | `xui-cache-busting.spec.mjs:106` | a template fetched at runtime carries the build version | P | P | P |
| 2 | `xui-cache-busting.spec.mjs:144` | `require.toUrl()` applies the configured urlArgs | P | P | P |
| 3 | `xui-login.spec.mjs:63` | end user logs in and lands on their profile | P | P | P |
| 4 | `xui-login.spec.mjs:77` | administrator logs in and lands on the realms console | P | P | P |
| 5 | `xui-login.spec.mjs:97` | invalid credentials are rejected without establishing a session | P | P | P |
| 6 | **`xui-login.spec.mjs:123`** | **logout ends the session and protected routes return to the login form** | **P** | **F** | **P** |
| 7 | `xui-profile.spec.mjs:356` | the profile renders for an end user, populated from their record | P | P | P |
| 8 | `xui-profile.spec.mjs:409` | an edit to the first name is saved, confirmed, and survives a reload | P | P | P |
| 9 | `xui-profile.spec.mjs:451` | Reset discards a pending edit and never reaches the server | P | P | P |
| 10 | `xui-realms.spec.mjs:239` | a realm created through the console appears in the realm list | P | P | P |
| 11 | `xui-realms.spec.mjs:277` | an illegal realm name is refused before anything is submitted | P | P | P |
| 12 | `xui-realms.spec.mjs:311` | an existing realm's identity is fixed once it has one | P | P | P |
| 13 | `xui-realms.spec.mjs:336` | an edit made in the console persists | P | P | P |
| 14 | `xui-realms.spec.mjs:373` | a realm deleted from the edit form disappears from the console | P | P | P |
| 15 | `xui-realms.spec.mjs:399` | a realm deleted from the realm list disappears from the console | P | P | P |
| 16 | `xui-realms.spec.mjs:426` | the top level realm cannot be deleted or deactivated | P | P | P |
| 17 | `xui-services.spec.mjs:334` | a service created through the console appears in the service list | P | P | P |
| 18 | `xui-services.spec.mjs:402` | changing the chosen type rebuilds the create form | P | P | P |
| 19 | `xui-services.spec.mjs:448` | the create form stops offering a type the realm already has | P | P | P |
| 20 | `xui-services.spec.mjs:474` | an edit made in the console persists | P | P | P |
| 21 | `xui-services.spec.mjs:527` | a service deleted from the edit form disappears from the console | P | P | P |
| 22 | `xui-services.spec.mjs:562` | a service deleted from the service list disappears from the console | P | P | P |
| 23 | `xui-services.spec.mjs:599` | a service selected in the list can be deleted with the toolbar | P | P | P |

**22 of 23 tests produced the same result on every run on both backends.** Row 6 is the only
divergence, and it diverges *within* the local server as well as against the deployed one.

---

## The divergence

### `xui-login.spec.mjs:123` — local run 1

Failed on the local API server; passed on the deployed AM and on the second local run.

```
1) xui/xui-login.spec.mjs:123:5 › XUI login and logout (default realm) ›
   logout ends the session and protected routes return to the login form @deployed-am @local-server

  TimeoutError: page.waitForURL: Timeout 30000ms exceeded.
  =========================== logs ===========================
  waiting for navigation until "load"
  ============================================================

    139 |         // than rendering with stale in-memory state.
    140 |         await page.goto(xuiUrl("#profile/details"));
  > 141 |         await page.waitForURL((url) => url.hash.startsWith("#login"), { timeout: 30_000 });
        |                    ^
    142 |         await expect(page.locator(SEL.usernameInput)).toBeVisible();
    143 | });
    144 | });
      at /home/maxim/Documents/_projects/forgerock/OpenAM/e2e/xui/xui-login.spec.mjs:141:20
```

The test logs out, then navigates to a protected route and expects the XUI to bounce it to
`#login`. The redirect did not happen within 30s. The assertion that never ran is the one on the
next line — the username input — so the failure is the routing step, not the form.

**This is the same test, at the same line, with the same shape of failure, that
`xui/BASELINE.md` records failing 3 of 6 gated runs on the deployed backend** and describes as
*"never root-caused… made to stop reproducing by resetting between runs… latent, not resolved."*
This run is the first record of it reproducing against the local API server.

That it now fails on both backends is the useful part: a defect that reproduces on an in-memory
Node server with no AM, no OpenDJ, no Tomcat and no session store is **unlikely to live in AM**.
The two backends share exactly one thing — the XUI bytes proven identical above — and the spec.

**Nothing was fixed, and no attempt was made to fix it.** It is recorded here as a finding.

### What this does not mean

- **It is not evidence that the backends behave differently.** The same backend produced both
  results 45 seconds apart. A difference that does not reproduce on a second run of the same
  backend cannot be attributed to the backend.
- **It is not evidence the local server is a faithful stand-in for AM.** 23/23 agreement in the
  clean pair is one lane, in one pairing of runs, against one build. The baseline needed 14 runs
  across 4 batches to characterise this suite; 3 runs characterise much less.
- **It does not clear the local server of the failure either.** One local run failed. Whether the
  local server makes the latent defect *more* likely to reproduce is not determinable from two
  runs, and is not claimed here.

### Classification

Task 2.17 asks that a test which does not agree across the backends be treated as one of two
things: **a server bug to fix in this group**, or **a spec asserting server behaviour, which belongs
on the deployed instance**. This divergence is **neither**, and the reasoning matters more than the
label, because each of the two offered outcomes is refuted by specific evidence rather than merely
judged a poor fit.

**Not a server bug.** A server bug in the local API server is a defect the local server has and the
deployed AM does not. This defect is present on both. [`xui/BASELINE.md`](../xui/BASELINE.md)
records this same test, at this same line, with this same failure shape, **failing 3 of 6 gated runs
against the deployed AM**, and describes it as never root-caused. It failed 1 of 2 runs against the
local server here. A defect that predates the local server's existence, and reproduces against a
real AM with a real session store, is not something the local server introduced and not something
fixing the local server would remove. Task 2.16's note reached the same reading from the other side
— "measured 5 runs in 10 against the local server, and `xui/BASELINE.md` already records 1 in 3
against the deployed instance, so it is not backend-specific."

**Not a spec that belongs on the deployed instance.** The retag argument requires the spec to assert
*server* behaviour. This one asserts that after logout the XUI **routes** a request for a protected
route back to `#login` — client-side routing, in the browser, which D16 places explicitly on the
run-against-both side: "UI behaviour — routing, view rendering, form generation — runs against
both." Nothing in the failing assertion touches a cookie attribute, a token semantic, or an
authentication flow. The spec is correctly tagged, and **it was not retagged.** D16's stated purpose
is to prevent a suite that quietly shrinks; retagging a UI-routing spec because it is flaky would be
exactly that failure, and "this test is unreliable" is not the argument that justifies a retag.

**What it is.** A pre-existing, backend-independent defect in either the XUI's post-logout routing
or in how the spec waits for it. The two backends share exactly two things — the XUI bytes proven
identical above, and the spec — and the defect tracks neither backend. That it reproduces against an
in-memory Node server with no AM, no OpenDJ, no Tomcat and no session store is positive evidence for
the XUI-or-spec reading and against any backend reading.

Task 2.16 left a concrete lead that is not pursued here: replacing the spec's `page.waitForURL` with
a poll of the *settled* URL makes it fail 4 of 4, reporting `#profile/details` where `#login` is
expected — so the two waits disagree, and either the redirect never happens and the passing runs
were catching a transient, or it happens and is immediately reverted. Distinguishing those two needs
the trace that `--trace=off` suppressed on all three runs here.

**Consequences of this classification.** No spec was retagged, no tag was changed, no server code
was touched, and nothing was fixed — this document records a finding. The defect does not belong to
group 2 and is not resolved by it; it remains open against the XUI or the spec, where
`xui/BASELINE.md` first recorded it. Because it is a defect in the shared suite rather than in
either backend, it will also be visible to task 1.16's re-record of `BASELINE.md`.

---

## Stability

**The two local runs do not agree.** They differ on `xui-login.spec.mjs:123` — run 1 failed it,
run 2 passed it, with the server process unchanged and un-restarted between them.

The runs were deliberately two separate process invocations to two separate files, so that state
left behind by run 1 would be visible to run 2. The local server holds its state in memory and was
**not** reset between the two runs (`POST /local-api-server/reset` was not called), so run 2 ran
against whatever run 1 left in it — including the realms and services the realm and service specs
create and delete. Run 2 nonetheless passed 23/23, so no accumulated state broke it; if anything
the ordering is the reverse of what state contamination would predict, since the failure was in the
*first* run against a freshly built state.

**Speed.** A clean local run is 45s against the deployed side's 56s — about 20% faster per run, but
that understates it. The deployed lane also needs its instance: `openam-reset.sh` cost **98s** here
with the image layer cached, and `openam-up.sh` from a cold image costs minutes. The local server
was serving **~2s** after launch. Per iteration that is roughly 45s versus 154s including the reset
the baseline's amended protocol requires before every run.

---

## Not determined

- **Whether the deployed `/XUI` is byte-identical to the one `xui/BASELINE.md` measured.** The zip
  present now has the same size and the same 652 files but a different SHA-1 and later entry
  timestamps; it is a rebuild. The artifact the baseline hashed no longer exists on disk, so the
  two could not be compared. Both backends served the same bytes *as each other*, which is what
  this parity check requires, but "the deployed side reproduces BASELINE.md's build exactly" was
  **not** verified and is not claimed.
- **The root cause of `xui-login.spec.mjs:123`.** Unchanged from the baseline: not investigated
  here, and deliberately not investigated — this task was a comparison, not a debugging session.
  Diagnosing it would need the trace that `--trace=off` suppressed.
- **Whether the failure rate differs between the backends.** Two local runs and one deployed run
  cannot separate a backend effect from the run-to-run variance the baseline already documented on
  the deployed side. Establishing that needs many more runs on both.
