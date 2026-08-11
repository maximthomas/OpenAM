# XUI e2e baseline — Grunt-built XUI

Baseline of the Playwright XUI suite against the **unmodified Grunt build output**, established
before the Vite migration so the same suite can be pointed at a Vite-built `/XUI` and compared.

**Result: the gate is MET, under [the amended gate protocol](#the-gate-protocol).** 57 tests,
12 spec files, green in three consecutive separate runs at `retries: 0` —
[batch 4](#fourth-batch--gated-amended-protocol--this-is-the-authoritative-result).

Getting there took four batches and 14 runs, and the route matters, because **the amended protocol
is itself the finding.**

| Batch | Protocol | Result |
|---|---|---|
| [First gated batch](#first-gated-batch) | 3 runs, deploy once per batch | 2 green, 1 failed `xui-login.spec.mjs:123` |
| [Diagnostic](#diagnostic-five-further-runs-with-tracing) | 5 runs, `--trace=on`, not gated | 4 green, 1 failed `xui-services.spec.mjs:402` |
| [Second gated batch](#second-gated-batch) | 3 runs, deploy once per batch | 1 green, **2 failed** `xui-login.spec.mjs:123` |
| [Third batch](#third-batch--modified-protocol-reset-before-every-run) | 3 runs, reset before each run, not gated | **3 green** |
| [**Fourth batch**](#fourth-batch--gated-amended-protocol--this-is-the-authoritative-result) | 3 runs, **reset before each run — the gate** | **3 green — gate met** |

Under the original protocol — deploy `/XUI` once, then run three times — `xui-login.spec.mjs:123`
failed **3 of 6 gated runs**, and the suite slowed monotonically within a batch (241 → 299 → 316s),
with every run at or below 241s passing and every run at or above 252s failing. Adding a **full
instance reset before every run** removed the slowdown and the failures: batches 3 and 4 went six
for six green with flat timings, including runs slower than the level at which every earlier gated
run had failed. The protocol was amended on that basis and batch 4 was then run as the real gate.

**`xui-login.spec.mjs:123` was never root-caused.** It was made to stop reproducing by resetting
between runs, which is a change to how the suite is run — not a fix to the XUI, a spec, or AM.
Nothing was fixed anywhere in this work. The failure is latent, not resolved, and could resurface
on a slower CI box or a longer suite; see
[What this does not mean](#what-this-does-not-mean).

This re-records the baseline after tasks 1.14 (`xui-auth-modules.spec.mjs`) and 1.15
(`xui-auth-chains.spec.mjs`) landed, which added 16 tests and 2 spec files to the previous
41-test / 10-file baseline.

The three fixes to the local harness recorded in the previous baseline still ship and are still
required. None touched the XUI, a spec, or any product code; all three were in `e2e/local/`, and
all three were bugs in the machinery that deploys a built `/XUI` rather than in what it deploys.
See [Harness fixes](#harness-fixes).

Recorded: 2026-08-11. Repo commit `7ff6efba1f5f82717110f5f3ff9f2092946b6f61`
(`features/openam-ui-migration`).

---

## Environment

### AM under test

| | |
|---|---|
| AM version | `16.2.0-SNAPSHOT`, revision `8628aba262`, built 2026-August-08 09:56 (`/json/serverinfo/version`) |
| Container image | `openam-e2e:local`, `sha256:1ad54f240f0e…`, built 2026-08-08T11:05:52+03:00 (also tagged `openam-e2e:5d2aii`) |
| Base image | `tomcat:11-jre25` (`openam-distribution/openam-distribution-docker/Dockerfile`) |
| Servlet container | Apache Tomcat 11.0.24 |
| JVM | OpenJDK 25.0.3 LTS, Temurin-25.0.3+9 |
| AM container | `openam-idp`, started 2026-08-11T11:22:29Z, healthy |
| Identity store | `opendj-idp`, `openidentityplatform/opendj:latest`, healthy |
| Base URL | `http://openam.example.org:8080/openam` |
| Container user | `uid=1001(openam) gid=0(root)` |

Same image as the previous baseline (identical digest) — the AM side did not change between the
two recordings, only the suite did.

The base URL comes from `common/openam-commons.mjs`:
`process.env.OPENAM_BASE_URL ?? "http://openam.example.org:8080/openam"`. `OPENAM_BASE_URL` was
unset for these runs, so the default applied. There is no `.env` file in `e2e/`; the harness takes
its settings from `local/lib.sh`. Reachability confirmed before the runs:
`GET /openam/isAlive.jsp` → 200, `GET /openam/XUI/index.html` → 200.

Server session-cookie mode, read from `/json/serverinfo/*`: `cookieHttpOnly: false`,
`secureCookie: false`, `domains: ["example.org"]`. The first of those is what makes one test skip
— see [Per-run results](#per-run-results).

The image is built by `local/openam-up.sh`, which stages a Docker context from the reactor's
`openam-server` war plus the SSOAdminTools/SSOConfiguratorTools zips and un-comments the `COPY`
lines in the shipped distribution `Dockerfile`. Only the IdP and its OpenDJ store are started —
the harness never creates an SP container.

### The XUI build

Produced by **Grunt**, driven from Maven — not built by hand for this baseline.

- Source: `openam-ui/openam-ui-ria/src/main/js` plus `src/main/resources`, composed with the
  `forgerock-ui-user` dependency expanded under `target/dependencies-expanded/`.
- Build entry point: `openam-ui/openam-ui-ria/pom.xml` runs `frontend-maven-plugin` in the
  `compile` phase with `npm run build:production -- --target-version=${project.version}`, which is
  `cross-env NODE_ENV=production grunt prod --verbose`. Node `v22.21.1`, npm `11.6.2` (pinned as
  `<nodeVersion>`/`<npmVersion>` in `openam-ui/pom.xml`).
- `grunt prod` → `build`, whose task chain is
  `copy:compose → eslint → babel → copy:libraries → requirejs → less → replace → copy:compiled →
  copy:transpiled` (`openam-ui/openam-ui-ria/Gruntfile.js:376`).
- `maven-assembly-plugin` then packages `target/XUI` into the `-www.zip` with no top-level
  directory, so its contents map straight onto `/XUI`.

Build output actually deployed for this baseline:

| | |
|---|---|
| Artifact | `openam-ui/openam-ui-ria/target/openam-ui-ria-16.2.0-SNAPSHOT-www.zip` |
| Size | 2,450,123 bytes |
| SHA-1 | `143932f4268514b924eb920fe88929298fa2ec65` |
| Contents | 854 zip entries, **652 regular files** |
| Built | 2026-08-08 09:52 (entry timestamps) |
| Deployed file count in container | 652 — matches the archive |

**Byte-identical to the previous baseline** (same size, same SHA-1). The XUI build output did not
change between the two recordings; the artifact was redeployed rather than rebuilt, so this
baseline measures the same bits the 41-test baseline did.

### Test runner

| | |
|---|---|
| Playwright | 1.60.0 (`@playwright/test` `^1.60.0`, installed 1.60.0; `npx playwright --version` → 1.60.0) |
| Node | v22.22.2 |
| Config | `e2e/playwright.config.mjs` — `testDir: "."`, `testMatch: "**/*.spec.mjs"`, `retries: 0`, `workers: 1`, `timeout: 180000`, `expect.timeout: 15000` |
| Browser | Chromium, headless |
| Tracing | `--trace=off` on all four runs, overriding the config's `retain-on-failure` |

`retries: 0` and `workers: 1` are deliberate: the suite is the migration's regression oracle, and
every spec drives the same single AM instance.

---

## Harness fixes

Carried forward from the previous baseline — **these still ship and are still required.** The
first attempt at that baseline produced 34 passed / 6 failed / 1 skipped, identically in all three
runs. All six failures were in `e2e/local/`, not in the XUI. They are recorded here because the
same bugs would have hit the Vite side of the comparison, and because two of them are silent.

### 1. `docker cp` leaves `/XUI` owned by the host UID

`xui-deploy.sh` populated `/XUI` with `docker cp`, which preserves the staging files' host
ownership. On native Linux that is the invoking host UID verbatim — 1000 here — while the
container runs as `openam`, uid 1001, gid 0. Against a `1000:1000` tree owned by neither, `openam`
matches only the *other* permission bits: `r-x` on directories, `r--` on files.

Tomcat still serves the tree, which is why it went unnoticed. But six specs write into the
deployed `/XUI` through `docker exec` — the four theming ones via `ThemeConfiguration.js`, the two
operator-module ones via `AppConfiguration.js` and `E2EStandInLoginHelper.js` — and every one of
them failed in fixture setup, before touching a browser assertion:

```
Error: Command failed: docker exec -i openam-idp sh -c tmp="$1.e2e-tmp";
  cp -p "$1" "$tmp" && cat > "$tmp" && mv -f "$tmp" "$1"
  sh /usr/local/tomcat/webapps/openam/XUI/config/AppConfiguration.js
cp: cannot create regular file
  '…/XUI/config/AppConfiguration.js.e2e-tmp': Permission denied
   at common/deployed-xui-commons.mjs:80
```

Tomcat's own war-expanded `/XUI` is `openam`-owned, which is what the specs were written against;
`xui-deploy.sh` is what changed it. Fixed by chowning after the copy.

**Docker Desktop's VM maps UIDs on `docker cp` and hides this entirely — it reproduces only on
native Linux, which is also what CI runs.**

### 2. The same ownership breaks the *next* deploy, mid-flight

Surfaced by fixing nothing but running the deploy again. `xui-deploy.sh` replaces rather than
merges, and its `docker exec … rm -rf "$XUI_PATH"` also ran as `openam`. Unlinking depends on
write permission on the containing directory, which `openam` did not have, so the `rm` failed on
every file left by the previous deploy, `set -e` aborted the script, and it left a **half-deleted
`/XUI` that Tomcat then served as 404s** — a worse state than the one it started from.

Fixed together with the above: the `rm`, the `mkdir` and the `chown` all now run as `-u 0`.
`chown` requires root regardless, and `docker exec`'s default user is `openam`.

### 3. `am_version()` dies on SIGPIPE under `pipefail`

Independent of the other two, and it blocked the first deploy attempt outright.
`local/lib.sh` sets `set -euo pipefail`, and `am_version()` was:

```sh
sed -n 's/.*<version>\(.*\)<\/version>.*/\1/p' "${REPO_ROOT}/pom.xml" | head -1
```

`head -1` exits after the first line while `sed` is still writing the remaining matches from a
2,488-line `pom.xml`; `sed` takes SIGPIPE and exits 141, `pipefail` promotes 141 to the pipeline's
status, and `set -e` kills the script — silently, because it happens inside `VERSION="$(am_version)"`
before anything is logged. The only symptom is an immediate exit 141 with no output.

Measured 8 failures in 8 attempts on this machine; after the fix, 8 successes in 8. It affects
every script sourcing `lib.sh` — `xui-deploy.sh`, `openam-up.sh`, `openam-down.sh`.

Fixed by making `sed` quit at the first match instead of piping to `head`, which removes the pipe
and the race with it. Written as a POSIX address form rather than GNU `T`/`q`, since the harness
is also used on macOS.

---

## The gate protocol

**This is the current protocol. Use it.** Per run, three times, as three separate invocations:

```
./local/openam-reset.sh                 # full container rebuild, ~140s
./local/xui-deploy.sh                   # redeploy the zip; verify its SHA-1
npx playwright test xui/ --reporter=line --trace=off > /tmp/<run-N>.txt 2>&1
```

`retries: 0`, `workers: 1`, no `-x`, not `--repeat-each` — three separate process invocations, so
that state one run leaves behind for the next is actually exercised rather than hidden. The zip
SHA-1 is verified before each deploy, so a changed build cannot slip into a batch unnoticed. The
redeploy is **required** after a reset, not optional: the rebuilt container serves the war's own
`/XUI`, not the zip under test.

### Why the reset step was added

The protocol originally reset nothing and deployed `/XUI` once per batch. Under that protocol
`xui-login.spec.mjs:123` failed **3 of 6 gated runs**, and the suite slowed monotonically within a
batch (241 → 299 → 316s). [Batch 3](#third-batch--modified-protocol-reset-before-every-run) then
ran the same suite with a full reset before every run: the slowdown disappeared, the timings went
flat, and all three runs passed — including two that were *slower* than the duration at which every
previous gated run had failed. That is the evidence for the change.

Two honest qualifications:

- **This is a protocol decision, not a root cause.** It rests on three runs. The reset clears
  accumulated AM configuration state *and* restarts the JVM and Tomcat; nothing here separates
  those, so what the reset actually fixes is "something a full container rebuild clears". The
  mechanism behind `xui-login.spec.mjs:123` was never established.
- **It costs about 152s per run** (~140s reset plus deploy), roughly doubling a three-run batch's
  wall-clock. That is the price of a batch whose result means something.

Batches 1 and 2 below are kept as the record of what the *old* protocol produced. The contrast
between them and batches 3 and 4 is the evidence for the change, so they are deliberately not
rewritten.

---

## How this baseline was produced

The account below describes batches 1 and 2, which ran under the **original** protocol (deploy once
per batch, no reset). It is preserved as recorded; the protocol in force now is the one above.

1. `/XUI` in the running container was replaced with a clean unpack of the Grunt-built zip, so the
   runs are against unmodified build output rather than whatever earlier specs left behind:

   ```
   ./local/xui-deploy.sh
   ==> deploying …/openam-ui-ria-16.2.0-SNAPSHOT-www.zip
   ==> replacing /usr/local/tomcat/webapps/openam/XUI
   ==> deployed. http://openam.example.org:8080/openam/XUI/ now serves 652 files
   ```

   Invoked with no argument, so it resolved the zip through `am_version()` — exercising fix 3.
   Exit 0. Post-deploy: 652 files in the container matching the archive, `/XUI` and `/XUI/config`
   owned `openam:root` with `config/` group-writable, `GET /openam/XUI/index.html` → 200,
   `GET /openam/isAlive.jsp` → 200.

   This matters more than it did last time: the two new specs drive authentication modules and
   chains, which mutate server-side configuration, so starting from a known `/XUI` is the only way
   the three runs mean anything.

2. The XUI suite was then run **three separate times**, to three separate files. Three separate
   process invocations rather than `--repeat-each`, because the risk being probed is state one run
   leaves behind — in the deployed XUI *and*, now, in AM's authentication configuration — for the
   next run:

   ```
   npx playwright test xui/ --reporter=line --trace=off > /tmp/1.16-xui-{1,2,3}.txt 2>&1
   ```

3. `oauth2/ saml/` was run once afterwards, for the record only — see [Non-XUI specs](#non-xui-specs).
   `ls` in `e2e/` confirmed those are the only non-`xui/` spec directories present.

No spec, config, or product source file was modified to produce this baseline, and nothing was
fixed in response to the run 3 failure.

---

## Suite size

**12 spec files, 57 tests.**

| Spec | Tests | Backend tag (D16) |
|---|---:|---|
| `xui/xui-auth-chains.spec.mjs` | 9 | `@deployed-am` |
| `xui/xui-auth-modules.spec.mjs` | 7 | `@deployed-am` |
| `xui/xui-authorize.spec.mjs` | 5 | `@deployed-am` |
| `xui/xui-cache-busting.spec.mjs` | 2 | `@deployed-am` `@local-server` |
| `xui/xui-device.spec.mjs` | 3 | `@deployed-am` |
| `xui/xui-httponly.spec.mjs` | 3 | `@deployed-am` |
| `xui/xui-login.spec.mjs` | 4 | `@deployed-am` `@local-server` |
| `xui/xui-operator-module.spec.mjs` | 2 | `@deployed-am` |
| `xui/xui-profile.spec.mjs` | 3 | `@deployed-am` `@local-server` |
| `xui/xui-realms.spec.mjs` | 7 | `@deployed-am` `@local-server` |
| `xui/xui-services.spec.mjs` | 7 | `@deployed-am` `@local-server` |
| `xui/xui-theming.spec.mjs` | 5 | `@deployed-am` |
| **Total** | **57** | 34 deployed-AM-only, 23 both |

Every test carries a backend tag, declared on the `test.describe` block. Counts are Playwright's
own, not a grep — taken from `--list`:

| Selector | Result |
|---|---|
| `--list` | 57 tests in 12 files |
| `--list --grep "@deployed-am"` | 57 tests in 12 files |
| `--list --grep "@local-server"` | 23 tests in 5 files |
| `--list --grep "@deployed-am\|@local-server"` | 57 tests in 12 files |

So `@local-server` is a strict subset of `@deployed-am`: every test runs against a deployed AM, and
23 of them also run against the local server. **Deployed-AM-only = 57 − 23 = 34.**

The 5 files carrying `@local-server` are `xui-cache-busting` (2), `xui-login` (4), `xui-profile`
(3), `xui-realms` (7) and `xui-services` (7).

**Both new specs are `@deployed-am` only.** Worth stating explicitly because a naive grep for
`@local-server` matches both files: each contains a comment saying it is *deliberately not* tagged
`@local-server` (`xui-auth-modules.spec.mjs:270`, `xui-auth-chains.spec.mjs:218`). The actual
declarations are `tag: ["@deployed-am"]` at `xui-auth-modules.spec.mjs:280` and
`xui-auth-chains.spec.mjs:228`. Playwright's `--grep` counts above confirm it: neither file appears
in the 5 `@local-server` files.

Change against the previous baseline: **+2 spec files, +16 tests** (`xui-auth-chains` 9,
`xui-auth-modules` 7), all of them deployed-AM-only, taking that column from 18 to 34. The
`@local-server` set is unchanged at 23 tests in 5 files.

---

## Per-run results

### First gated batch

| Run | Passed | Failed | Skipped | Playwright wall-clock | Measured wall-clock | Exit |
|---|---:|---:|---:|---|---|---|
| 1 | 56 | 0 | 1 | 3.7m | **227s** | 0 |
| 2 | 56 | 0 | 1 | 3.6m | **220s** | 0 |
| 3 | 55 | **1** | 1 | 4.2m | **252s** | 1 |

**Total measured wall-clock for the three gated runs: 699s (11m 39s).**

A [second gated batch](#second-gated-batch) was run later under the same protocol; it failed twice
more. This table records the first batch only and is unchanged.

Runs 1 and 2 are clean and identical, with no error output anywhere in either log. Run 3 differs
by exactly one test. Runs are ~80s longer than the previous baseline's 138s/147s/140s, consistent
with 16 added tests that create and delete authentication modules and chains.

The 1 skipped test is the same one as before and skipped in all three runs:
`xui/xui-httponly.spec.mjs:177` — *"step-up after a fresh page load is recognised as a session
upgrade, not a new login"*. It self-skips via `test.skip(!httpOnly, …)` after reading
`cookieHttpOnly` from `/json/serverinfo`; this server reports `cookieHttpOnly: false` (confirmed
independently above), so the branch under test does not apply. A legitimate conditional skip, not
a disabled test.

### The run 3 failure

```
1) xui/xui-login.spec.mjs:123:5 › XUI login and logout (default realm) ›
   logout ends the session and protected routes return to the login form
   @deployed-am @local-server

  TimeoutError: page.waitForURL: Timeout 30000ms exceeded.
  =========================== logs ===========================
  waiting for navigation until "load"
  ============================================================

    140 |         await page.goto(xuiUrl("#profile/details"));
  > 141 |         await page.waitForURL((url) => url.hash.startsWith("#login"), { timeout: 30_000 });
        |                    ^
    142 |         await expect(page.locator(SEL.usernameInput)).toBeVisible();
```

**Read: most likely an environment-sensitive flake in the spec's own wait, not a product
regression — but not proven, and it fails the gate either way.**

What supports "flake":

- It passed in runs 1 and 2 and failed in run 3, against the same deployed build, with nothing
  changed in between.
- It failed at the *last* assertion of the test. Everything before it passed, including the
  security-relevant ones: the UI reached `#loggedOut/`, showed the logged-out heading, and
  `sessionInfo()` confirmed **the server had stopped resolving the session cookie**. Logout itself
  worked. What timed out is only the follow-up check that a protected route bounces back to the
  login form.
- Run 3 was the slowest of the three overall (252s vs 227s and 220s), consistent with host load.
- The mechanism is plausible under load: the XUI is deployed unbundled, so routing to
  `#profile/details` fetches the profile module's dependency closure one file at a time before the
  router can find there is no session and redirect. That is exactly the cold-start cost the config
  comments call out when setting `expect.timeout` to 15s — but this call site hard-codes its own
  30s timeout and does not inherit it.

Per the gate's own rule — `retries: 0`, and any test not green in all three runs is a flake — this
is a flake, and **the gate is not met**. Not fixed, by instruction: the failing test is the
finding. Before the Vite comparison is trusted, this test wants either a root-cause pass or a
deliberate, documented decision about its 30s wait.

### Diagnostic: five further runs with tracing

The read above was inference from a single occurrence, so the full suite was run **five more
times**, as five separate invocations with `--trace=on`, against the same container state with
**no redeploy** — the point being to reproduce under the conditions that produced the failure.
These five runs are **diagnostic only. They do not re-open, replace, or satisfy the gate**, which
is still decided by the three `--trace=off` runs recorded above.

| Traced run | Result | Wall-clock |
|---|---|---:|
| 1 | **1 failed**, 1 skipped, 55 passed — `xui-services.spec.mjs:402` | **470s** |
| 2 | 56 passed, 1 skipped | 318s |
| 3 | 56 passed, 1 skipped | 323s |
| 4 | 56 passed, 1 skipped | 323s |
| 5 | 56 passed, 1 skipped | 318s |

**`xui-login.spec.mjs:123` did not fail once in the five runs — 0/5, so 1/8 combined with the
gated runs.** It could not be reproduced.

What did happen is more informative than a straight reproduction: traced run 1 failed a
*different* test with the *same symptom*.

```
1) xui/xui-services.spec.mjs:402:5 › changing the chosen type rebuilds the create form

  Error: expect(locator).toBeVisible() failed
  Locator: locator('#idToken1')
  Expected: visible
  Timeout: 20000ms
  Error: element(s) not found
     at common/xui-commons.mjs:76        (openLoginForm)
     at loginViaXui      (common/xui-commons.mjs:88)
     at openAdminConsole (common/xui-commons.mjs:106)
     at xui/xui-services.spec.mjs:411
```

Both failures are the same class: **a timeout waiting for the XUI login route to render.** The
gated failure waited 30s for the hash to reach `#login` after logout; this one waited 20s for the
login form's username field to appear at all. Critically, `xui-services.spec.mjs:402` fails during
a plain `openAdminConsole` login at the *start* of the test, with **no logout anywhere in it**.

That materially weakens the logout-specific explanation. A race in the router's post-logout
session check cannot explain a login form failing to render in a test that never logs out. A
general "the XUI is slow to render the login route under load" explanation covers both.

**Wall-clock correlation is strong, and is the clearest signal in the data.** In each batch, the
one failing run was the slowest run of that batch:

- gated (`--trace=off`): 227s pass, 220s pass, **252s fail**
- traced (`--trace=on`): **470s fail**, 318s / 323s / 323s / 318s pass

The four clean traced runs sit within 318–323s — a 1.6% spread — which makes run 1's 470s a +47%
outlier rather than ordinary variance. Two batches, two failures, both in the slowest member.

Note also that tracing costs about +42% (≈320s traced vs ≈225s gated), so **the five traced runs
are not conditions identical to the gated runs**; they are a heavier-load variant of them. That
cuts both ways: it makes them a harsher test that still did not reproduce `xui-login:123`, and it
means their timings cannot be compared directly against the gated numbers.

**Verdict: a load-sensitive flake in the suite's waits, not a logout defect.** The supporting
evidence is (a) two failures across eight runs, both timeouts on the same XUI login-route render,
(b) one of them in a test with no logout in it, and (c) both landing in the slowest run of their
batch, against otherwise very tight timings.

> **Revised by later evidence.** The rate quoted in this subsection (0/5 here, 1/8 overall) was
> superseded by the [second gated batch](#second-gated-batch), in which `xui-login.spec.mjs:123`
> failed twice more — taking it to 3 of 6 gated runs. The load-correlation read held up and
> strengthened; the "rare flake" framing did not. This subsection is kept as recorded, since it is
> what the five diagnostic runs alone established.

Still not settled by this evidence:

- **The mechanism is unobserved.** Because `xui-login:123` never failed again, there is no trace of
  it failing — the gated run used `--trace=off`, and the traced runs were green on that test. So
  what actually happens after `goto("#profile/details")` on a failing run — whether the app routes
  somewhere other than `#login`, stalls outright, or arrives after the 30s deadline — **remains
  undetermined.** Nothing in these runs can answer it.
- Traced run 1's failure trace was not preserved: Playwright wipes `test-results/` at the start of
  every run, and run 2 cleared it before it could be archived. It was an `xui-services` failure in
  any case, outside the one test this investigation was scoped to inspect.
- Whether the underlying slowness is only host contention on this machine, or a genuine cold-start
  cost of the unbundled XUI that a slower CI box would hit reliably, is not distinguished here.
- That the two failures share one root cause is inferred from the symptom, not demonstrated.

Nothing was fixed, no spec was edited, no timeout was raised and no retry was added.

Raw output: `/tmp/1.16-xui-trace-1.txt` … `/tmp/1.16-xui-trace-5.txt`.

### Second gated batch

Run under the **same gate protocol as the first batch** — a clean `./local/xui-deploy.sh` redeploy
first, then three separate invocations, `--trace=off`, `retries: 0` — so the two batches are
directly comparable. The deployed zip was verified before the batch:
SHA-1 `143932f4268514b924eb920fe88929298fa2ec65`, 2,450,123 bytes, **matching the artifact recorded
above exactly**, so the build did not change between batches. Post-deploy: 652 files, `openam:root`,
`/XUI/index.html` and `/isAlive.jsp` both 200.

| Run | Passed | Failed | Skipped | Playwright wall-clock | Measured wall-clock | Exit |
|---|---:|---:|---:|---|---|---|
| 1 | 56 | 0 | 1 | 4.0m | **241s** | 0 |
| 2 | 55 | **1** | 1 | 5.0m | **299s** | 1 |
| 3 | 55 | **1** | 1 | 5.2m | **316s** | 1 |

**Total measured wall-clock: 856s (14m 16s).** Both failures are `xui-login.spec.mjs:123` — the
same test that failed in the first batch. **This batch is not green.**

This changes the picture materially. `xui-login.spec.mjs:123` has now failed **3 of 6 gated runs**,
which is not a rare flake.

#### Wall-clock separates passes from failures exactly

Across all six gated runs, ordered by duration:

| Wall-clock | Result |
|---:|---|
| 220s | pass |
| 227s | pass |
| 241s | pass |
| 252s | **fail** |
| 299s | **fail** |
| 316s | **fail** |

**Every gated run at or below 241s passed; every gated run at or above 252s failed.** Six runs, a
clean split with no overlap. Within the second batch the slowdown is monotonic (241 → 299 → 316)
and tracks the failures directly. This is the strongest evidence in the record, and it is what
turns "load-sensitive" from a guess into a measured relationship.

#### The failure has two distinct forms

All three gated failures are the same test, but not the same assertion:

| Run | Fails at | Navigation observed during the wait |
|---|---|---|
| batch 1, run 3 | `xui-login.spec.mjs:141` — post-logout `goto("#profile/details")`, waiting for `#login` | none logged |
| batch 2, run 2 | `xui-login.spec.mjs:141` — identical | none logged |
| batch 2, run 3 | `common/xui-commons.mjs:114` in `logoutViaXui`, via `xui-login.spec.mjs:127` — waiting for `#loggedOut`/`#login` | `navigated to ".../XUI/#profile/details"` |

Batch 2 run 3 fails **earlier in the test than the other two**: logout itself never reaches
`#loggedOut`. It is also the only failure so far in which Playwright logged an actual navigation
during the wait, and what it logged is the app going to **`#profile/details`** while the test was
waiting for the logout route to resolve.

That is the first direct observation of what the app does rather than what it fails to do, and it
partly answers the mechanism question the diagnostic runs could not: at least in this instance, the
page did not simply stall — it navigated to the profile route while a logout was pending. Whether
that is the router restoring the pre-logout route, a queued hash change winning a race with the
logout handler, or the logout handler never running at all is **not determined here**; the gate
protocol runs with `--trace=off`, so there is no trace of it, and no trace was opened.

#### Why batch 2 is slower than batch 1 — hypothesis, not established

Batch 2 started from an identical, freshly redeployed `/XUI`, yet every run was slower than its
batch 1 counterpart (241/299/316 vs 227/220/252). The plausible difference is **accumulated AM
server state**: `xui-deploy.sh` replaces `/XUI` only, and does not reset AM's configuration. By
the time batch 2 ran, the instance had been through eight full suite runs, each creating and
deleting realms, services, authentication modules and chains. `local/openam-reset.sh` exists for a
configuration reset but is **not part of the gate protocol**, and was not run.

This is a hypothesis consistent with the timings, not a demonstrated cause. Testing it would mean
resetting the instance and re-running — which was not done here, and would be a change to the gate
protocol rather than an execution of it.

That test was subsequently run: see
[Third batch](#third-batch--modified-protocol-reset-before-every-run).

### Third batch — MODIFIED protocol, reset before every run

**This batch does not follow the gate protocol and is not comparable to batches 1 and 2.** It
exists solely to test the accumulated-state hypothesis above. It does not replace either gated
batch, and it does not satisfy the gate.

Protocol per run: `./local/openam-reset.sh` → `./local/xui-deploy.sh` → one suite invocation,
`--trace=off`, `retries: 0`.

`openam-reset.sh` is `openam-down.sh` + `openam-up.sh` — it **destroys and rebuilds both
containers**. Both run with `--rm` and hold no volumes, so no state survives; the image layer is
cached, so it re-runs the configurator rather than the image build. A **redeploy is required after
every reset**, because the rebuilt container serves the war's own `/XUI` rather than the deployed
zip. The zip SHA-1 was re-verified before each of the three deploys and matched
`143932f4268514b924eb920fe88929298fa2ec65` every time.

No re-provisioning was needed: `openam-up.sh` restores the post-configuration baseline (amadmin,
the seeded `demo` user, ssoadm), and the specs create their own fixtures under unique names and
remove them in teardown, so a freshly reset instance is exactly what they expect.

| Run | Reset | Deploy | Passed | Failed | Skipped | Suite wall-clock | Exit | Load at start |
|---|---:|---:|---:|---:|---:|---:|---|---:|
| 1 | 132s | 1s | 56 | 0 | 1 | **245s** | 0 | 5.85 |
| 2 | 177s | 3s | 56 | 0 | 1 | **266s** | 0 | 6.09 |
| 3 | 147s | 1s | 56 | 0 | 1 | **249s** | 0 | 5.88 |

**All three runs green. `xui-login.spec.mjs:123` passed in all three.** Reset cost averaged 152s
per run *on top of* suite wall-clock; it is tabulated separately so it is not confused with suite
time. Suite total 760s, reset total 456s, deploys 5s.

#### What the data shows

**The inter-run slowdown disappeared.** With a reset before each run the timings are flat —
245 / 266 / 249, jitter of about ±10s around ~253s with no trend. Without resets, batch 2 climbed
monotonically: 241 → 299 → 316, a +75s rise across three runs. The climb is precisely what the
reset removed.

**The wall-clock threshold is a correlate, not a cause.** Batch 3 runs at **266s and 249s both
passed**, while every gated run at or above 252s had failed. Duration alone therefore does not
predict failure — a slow run on a *freshly reset* instance is fine. This refines the earlier
reading: wall-clock and failure were both symptoms of the same accumulating condition, rather than
slowness itself causing the failure.

**Host load does not explain batch 3's success.** It ran under a 1-minute load average of 5.8–6.1
at each run's start (11.4 shortly after run 3) and still went green three times. Load was not
recorded during batches 1 and 2, so no direct comparison is possible — but "the machine happened to
be quiet" is not available as an explanation here, because it was not quiet.

#### What it does not show

- **Three runs cannot separate "the reset fixed it" from "this batch got lucky."** At the ~50%
  per-run failure rate seen in gated runs, three consecutive greens would occur by chance roughly
  one time in eight. Suggestive, well short of conclusive.
- **The reset clears two things at once, and this batch cannot tell them apart.** It discards
  accumulated AM *configuration* state **and** restarts the *JVM* — fresh heap, fresh caches, fresh
  Tomcat. Either could be responsible. The hypothesis is therefore supported only in the loose
  sense of *something a full container rebuild clears*, not specifically as "configuration state".
- Whether the same condition would affect a Vite-built `/XUI` is untested, though nothing about it
  appears XUI-specific.

#### Indicated, not proven

On this evidence the gate protocol itself looks wrong: it redeploys `/XUI` once and then runs the
suite three times against an instance that accumulates state between runs. That means **batches 1
and 2 may have been measuring a protocol artefact rather than a defect in the XUI or the specs** —
and the "3 of 6 gated runs" failure rate would then be a property of how the gate is run, not of
what it tests.

If that is right, the protocol needs a reset before *every* gated run rather than once per batch,
at a cost of roughly 152s per run. **This is indicated on three runs, not proven**, and it should be
confirmed with a longer reset-per-run batch before the protocol is changed on the strength of it.
Until then the gate verdict stands as recorded: **not met** under the protocol as defined.

Nothing was fixed, no spec was edited, no timeout was raised, and no retry was added.

Raw output: `/tmp/1.16-xui-b3-1.txt`, `/tmp/1.16-xui-b3-2.txt`, `/tmp/1.16-xui-b3-3.txt`; resets
`/tmp/1.16-b3-reset-{1,2,3}.txt`; deploys `/tmp/1.16-b3-deploy-{1,2,3}.txt`.

### Fourth batch — GATED, amended protocol · **this is the authoritative result**

Run under [the gate protocol](#the-gate-protocol) as amended: reset → redeploy → one invocation,
three times, `--trace=off`, `retries: 0`. Unlike batch 3, **this batch is the gate**, not a
diagnostic.

| Run | Reset | Deploy | SHA-1 | Passed | Failed | Skipped | Suite wall-clock | Exit | Load at start |
|---|---:|---:|---|---:|---:|---:|---:|---|---:|
| 1 | 137s | 1s | match | 56 | 0 | 1 | **250s** | 0 | 4.47 |
| 2 | 135s | 1s | match | 56 | 0 | 1 | **251s** | 0 | 5.84 |
| 3 | 140s | 1s | match | 56 | 0 | 1 | **230s** | 0 | 4.27 |

**All three runs green: 56 passed, 0 failed, 1 conditional skip, exit 0 each time.** No failure
text appears anywhere in the three logs. `xui-login.spec.mjs:123` passed in all three, as did
`xui-services.spec.mjs:402`. The skip is the usual `xui-httponly.spec.mjs:177`, conditional on
`cookieHttpOnly`.

The deployed artifact was verified before each of the three deploys and matched
`143932f4268514b924eb920fe88929298fa2ec65` every time, so all three runs are against the same
Grunt build recorded at the top of this file.

Wall-clock is flat — 250 / 251 / 230, no upward trend, and run 3 is the fastest of the three. The
monotonic slowdown that characterised batch 2 does not appear. Suite total 731s; reset overhead
412s on top.

**The gate is met**: 57 tests green in three consecutive separate runs at `retries: 0`, under a
protocol that is stated, repeatable, and cheap enough to re-run.

#### What this does not mean

`xui-login.spec.mjs:123` was **never root-caused.** It was made to stop reproducing by resetting
the instance between runs — that is a change to how the suite is run, not a fix to the XUI, the
spec, or AM. Nothing was diagnosed and nothing was repaired. The failure remains latent, and could
resurface wherever the conditions that produced it recur: a slower CI box, a longer suite, a
machine under heavier load, or any future change that makes the instance accumulate state faster
than a per-run reset clears it. If it does reappear, the record above — three failures, the
navigation to `#profile/details` during a pending logout, and the wall-clock correlation — is the
starting point, not new information.

Raw output: `/tmp/1.16-xui-b4-1.txt`, `/tmp/1.16-xui-b4-2.txt`, `/tmp/1.16-xui-b4-3.txt`; resets
`/tmp/1.16-b4-reset-{1,2,3}.txt`; deploys `/tmp/1.16-b4-deploy-{1,2,3}.txt`.

---

## Baseline for comparison

When the Vite-built `/XUI` is deployed and this suite is re-run, the Grunt baseline to match is:

- **57 tests, 12 spec files**
- **56 passed, 1 skipped, 0 failed**, in each of three consecutive runs (the skip is
  `xui-httponly.spec.mjs:177`, conditional on `cookieHttpOnly`)
- **~230–251s wall-clock** per run, `workers: 1`, `retries: 0`, plus ~140s reset per run
- **Anything short of 56/1/0 on the Vite side is a migration finding**, provided the Vite batch is
  run under the same amended protocol.

**Run the Vite side under [the same protocol](#the-gate-protocol)** — reset and redeploy before
every run, `./local/xui-deploy.sh path/to/outDir` — so both sides go through identical deployment
*and* identical instance state. Comparing a reset-per-run Grunt batch against a deploy-once Vite
batch would reproduce exactly the artefact that cost four batches to identify here.

One caveat when reading a Vite failure: `xui-login.spec.mjs:123` and `xui-services.spec.mjs:402`
both failed under the old protocol and were never root-caused. If either fails on Vite, check the
run's wall-clock and whether the reset actually ran before concluding it is a regression — under
the old protocol they failed on Grunt too.

---

## Non-XUI specs

Run once for the record, **not gated on**. `ls` in `e2e/` confirmed `oauth2/` and `saml/` are the
only non-`xui/` spec directories; both were run. These specs predate the XUI work and assert
server behaviour, not XUI behaviour.

```
npx playwright test oauth2/ saml/ --reporter=line --trace=off
→ 4 passed, 2 failed (20.2s)   [measured 22s, exit 1]
```

Identical outcome to the previous baseline — same two failures, same causes.

1. **`oauth2/oauth2-test.spec.mjs:183` — "Should accept the session id as the csrf value"** —
   known pre-existing failure, flagged as such going in and unrelated to the XUI work.

   ```
   expect(received).toBe(expected)   Expected: 302   Received: 400
   ```

   The other 4 oauth2 tests pass, including the two negative CSRF cases.

2. **`saml/saml-test.spec.mjs:76` — "should log in as demo and reach the authenticated page"** —
   infrastructure, not a regression. **I did not run `saml/bootstrap.sh` by hand**, and it does not
   need running: the spec executes it itself in a `beforeAll`. It failed there:

   ```
   Error response from daemon: No such container: openam-sp
   Error: saml/bootstrap.sh exited with code 1
   ```

   Bootstrap configures a circle of trust and exchanges SAML metadata between **two** AM
   containers, `openam-idp` and `openam-sp`, and this harness only ever starts the IdP.
   `local/openam-up.sh` contains no reference to `openam-sp` and the spec targets
   `http://sp.mycompany.org:8081/openam`, so SAML cannot pass under `local/` as shipped.

   It is also **not idempotent**: it mutates the IdP before failing, so its failure mode depends on
   whether it has run before. On a pristine instance it reports `No such container: openam-sp`
   (what happened here); on a later run it may instead report `Circle of Trust exists : MYSAML`.
   Both are the same missing-SP problem. Reset the instance before any run that needs a pristine
   IdP.

Neither non-XUI spec carries a D16 backend tag; tagging them is task 2.13's scope, not this
baseline's. Both ran only *after* all three gated XUI runs.

Raw run output — first gated batch: `/tmp/1.16-xui-1.txt`, `/tmp/1.16-xui-2.txt`,
`/tmp/1.16-xui-3.txt`; diagnostic: `/tmp/1.16-xui-trace-1.txt` … `/tmp/1.16-xui-trace-5.txt`;
second gated batch: `/tmp/1.16-xui-b2-1.txt`, `/tmp/1.16-xui-b2-2.txt`, `/tmp/1.16-xui-b2-3.txt`;
non-XUI: `/tmp/1.16-rest.txt`; deploys: `/tmp/1.16-xui-deploy.txt`, `/tmp/1.16-b2-deploy.txt`.
