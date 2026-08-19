# XUI e2e phase 1 record — Grunt build consuming the commons AMD build from npm

Result of running the Playwright XUI suite against a **deployed** AM serving the phase 1 XUI: still
built by Grunt, but composing the commons sources from the `@openidentityplatform/ui-commons` and
`@openidentityplatform/ui-user` npm packages instead of the `commons.ui:user:zip:www` expansion.

**Result: the gate is MET.** 57 tests, 12 spec files, **56 passed / 1 skipped / 0 failed, exit 0,
in three consecutive separate runs** at `retries: 0`, under the amended protocol (reset before every
run). **No delta against [`BASELINE.md`](BASELINE.md): same 12 spec files, same 57 tests, same
per-spec counts, same backend-tag split, same single conditional skip.**

`xui-login.spec.mjs:123` — the known, never-root-caused flake — **passed in all three gated runs.**
It did fail once in the optional local-server lane below, which is context only and not the gate;
that is consistent with the existing record of it as backend-independent, not with a phase 1
regression.

Recorded: 2026-08-19. Repo commit `11fc4657cfc6d25ff3ff06f34872408b38d16e92`
(`features/openam-ui-migration`).

This file is **new**. It does not replace `BASELINE.md`, which remains the Grunt/Maven-zip oracle
this run is compared against and which was **not modified**.

---

## What was under test

### The two npm packages

| | |
|---|---|
| Packages | `@openidentityplatform/ui-commons`, `@openidentityplatform/ui-user` |
| Version | **`3.2.0-SNAPSHOT`** (both), read from each installed `node_modules/@openidentityplatform/<pkg>/package.json` |
| Origin | Maven artifacts `org.openidentityplatform.commons.ui:{commons,user}:tgz:npm` |
| Resolved from | `~/.m2` only — published to no registry (publishing is task 3.11, behind this gate) |

### How they are pinned

**Not through `openam-ui-ria/package.json`.** That file names neither package, and by design: they
are installed *out of band*, so npm records nothing. The pin lives in Maven:

- `openam-ui-ria/pom.xml` declares `<commons.ui.version>3.2.0-SNAPSHOT</commons.ui.version>`,
  pinned explicitly rather than inherited, because the version managed through the imported BOM
  chain resolves inside that BOM and carries no `tgz:npm`.
- `maven-dependency-plugin` execution `copy-commons-npm-tarballs` copies both artifacts into
  `target/npm/` as `ui-commons.tgz` / `ui-user.tgz` at `initialize`.
- `frontend-maven-plugin` execution `npm-install-commons` then runs
  `install target/npm/ui-commons.tgz target/npm/ui-user.tgz --no-save --legacy-peer-deps`.
  `--no-save` is what keeps them out of `package.json` and `package-lock.json`;
  `--legacy-peer-deps` stops npm auto-installing ~50 unpinned peer libraries from the public
  registry.

So the pinned coordinate is the Maven version property, and the lockfile is deliberately silent.
**Anyone auditing this by grepping `package.json` will find nothing and should not conclude the
switch did not happen.**

### How the zip was confirmed to be a phase 1 build

Five independent checks, all agreeing:

1. **Grunt composes from the packages.** `Gruntfile.js:46-58` defines `commonsPackageSource(pkg)`
   returning `node_modules/@openidentityplatform/<pkg>/{amd,www}`, and `buildCompositionDirs`
   includes both packages via `npmPackageDirs`. The pre-3.7 line
   `"target/dependencies-expanded/forgerock-ui-user"` as the *commons expansion* is gone.
2. **The Maven unpack that fed it is gone.** The `unpack-forgerock-ui-user` execution that wrote
   the commons `zip:www` into `target/dependencies-expanded/forgerock-ui-user` no longer exists in
   `pom.xml` (removed in `9598061ddd`).
3. **The tarballs and the installed packages are present on disk.** `target/npm/` holds both
   `.tgz` files (10:01); `node_modules/@openidentityplatform/{ui-commons,ui-user}` are installed at
   `3.2.0-SNAPSHOT` (10:41:22).
4. **The zip matches task 3.7's own acceptance numbers exactly** — 854 zip entries, **652**
   non-directory files (`unzip -l`). The deploy script independently reported 652 files served.
5. **`target/dependencies-expanded/forgerock-ui-user` holds exactly one file**,
   `libs/form2js-2.0-769718a.js`. That directory is not a pre-3.7 leftover: a leftover would carry
   the entire commons expansion (hundreds of files). One file is the precise signature of the
   *narrow* `unpack-forgerock-ui-user-form2js` execution introduced by HEAD (`11fc4657cf`), which
   pins the bytes of the one library the two composition sources were found to disagree on.

**Note on the stated precondition.** The brief asked to confirm "the build no longer composes from
`target/dependencies-expanded/forgerock-ui-user`". Literally, it still does — but only for that one
pinned `form2js` file, deliberately and documented in both `pom.xml` and `Gruntfile.js`. The bulk
commons composition has moved to the npm packages, which is the substance of the check.

Timing corroborates that the zip was built from the HEAD tree: `dependencies-expanded` 10:40:33,
`target/XUI` 10:40:40, `target/npm` 10:41:09, `node_modules/@openidentityplatform` 10:41:22, zip
10:41:24 — one build run — and HEAD was committed at 10:45:21, i.e. built, verified, then committed.
Only HEAD's narrow unpack can produce that one-file directory.

### The artifact

| | |
|---|---|
| Artifact | `openam-ui/openam-ui-ria/target/openam-ui-ria-16.2.0-SNAPSHOT-www.zip` |
| Size | 2,450,584 bytes |
| SHA-1 | `ec95d8c5cff2051a4b26af32adfbe88153f080f3` |
| Contents | 854 zip entries, **652 regular files** |
| Built | 2026-08-19 10:41 (entry timestamps) |
| Deployed file count in container | 652 — matches the archive, all three deploys |
| Deployed `main.js` SHA-1 | `7871b0564cfac744e4cba7dd1882a241a8187e4c` — equals the zip's own `main.js` |

Against `BASELINE.md`'s artifact (`143932f426…`, 2,450,123 bytes): different bytes, **identical
shape** — 854 entries / 652 files either way. `BASELINE.md` records that 638 of the 652 files are
byte-identical and 14 differ, the 14 being the r.js bundle plus commons `3.1.2 → 3.2.0-SNAPSHOT`
source changes.

The XUI deployed in the container **before** these runs had 652 files but `main.js` SHA-1
`e783c9ec…` — a *different* build. The protocol's mandatory redeploy is what made the runs measure
the intended artifact; this is a live example of why that step is not optional.

### Build toolchain (unchanged from `BASELINE.md`)

Grunt, driven from Maven: `frontend-maven-plugin` runs
`npm run build:production -- --target-version=${project.version}` →
`cross-env NODE_ENV=production grunt prod`. Node `v22.21.1`, npm `11.6.2`, pinned as
`<nodeVersion>`/`<npmVersion>` in `openam-ui/pom.xml`. **Phase 1 is not a bundler change** — Grunt
and r.js still produce the output; only where the commons sources come from changed.

---

## Environment

### AM under test

| | | vs `BASELINE.md` |
|---|---|---|
| AM version | `16.2.0-SNAPSHOT` | same |
| Revision / build date | `fc8e2e67c7`, 2026-August-04 10:48 | differs (`8628aba262`, 2026-August-08) |
| Container image | `openam-e2e:local`, `sha256:0dbcf692083c…`, built 2026-08-19T08:28:35Z | differs (`sha256:1ad54f240f0e…`) |
| Servlet container | Apache Tomcat 11.0.25 | 11.0.24 |
| JVM | OpenJDK 25.0.3 LTS, Temurin-25.0.3+9 | same |
| Identity store | `opendj-idp`, `openidentityplatform/opendj:latest`, healthy | same |
| Base URL | `http://openam.example.org:8080/openam` | same |
| Container user | `uid=1001(openam) gid=0(root)` | same |

The image was rebuilt for this work, so the revision and build-date stamps moved. That is expected
and documented: commit `e61f249f70` records that `revision` is buildnumber-maven-plugin's
`git.short.sha1` and `date` an Ant `<tstamp>`, both of which move between image builds, which is
why the drift job normalises them. `version` is pinned and unchanged. **No XUI-relevant AM
behaviour differs**; the suite's assertions are behavioural.

Reachability confirmed before the batch: `GET /openam/isAlive.jsp` → 200,
`GET /openam/XUI/index.html` → 200, `docker ps` listing `openam-idp` and `opendj-idp` healthy.
`/json/serverinfo/version` returns 403 without a session on this instance, so the version above was
read with an `amadmin` token.

### Test runner (identical to `BASELINE.md` except Node)

| | |
|---|---|
| Playwright | **1.60.0** (`@playwright/test` `^1.60.0`, installed 1.60.0; `npx playwright --version` → 1.60.0) |
| Node | v22.20.0 (`BASELINE.md`: v22.22.2) |
| Config | `e2e/playwright.config.mjs` — `retries: 0`, `workers: 1`, `timeout: 180000`, `expect.timeout: 15000` |
| Browser | Chromium, headless |
| Tracing | `--trace=off` on every run |
| Reporter | `line` + `./common/backend-tag-reporter.mjs`, appended explicitly on the CLI |

The backend-tag reporter is named on the command line because a CLI `--reporter` **replaces** the
config's reporter list rather than adding to it; omitting it silently drops the D16 coverage
footer.

---

## Suite size — identical to `BASELINE.md`

**12 spec files, 57 tests.** Counts are Playwright's own, from `--list`, not a grep.

| Spec | Tests (phase 1) | Tests (`BASELINE.md`) | Δ |
|---|---:|---:|---:|
| `xui/xui-auth-chains.spec.mjs` | 9 | 9 | 0 |
| `xui/xui-auth-modules.spec.mjs` | 7 | 7 | 0 |
| `xui/xui-authorize.spec.mjs` | 5 | 5 | 0 |
| `xui/xui-cache-busting.spec.mjs` | 2 | 2 | 0 |
| `xui/xui-device.spec.mjs` | 3 | 3 | 0 |
| `xui/xui-httponly.spec.mjs` | 3 | 3 | 0 |
| `xui/xui-login.spec.mjs` | 4 | 4 | 0 |
| `xui/xui-operator-module.spec.mjs` | 2 | 2 | 0 |
| `xui/xui-profile.spec.mjs` | 3 | 3 | 0 |
| `xui/xui-realms.spec.mjs` | 7 | 7 | 0 |
| `xui/xui-services.spec.mjs` | 7 | 7 | 0 |
| `xui/xui-theming.spec.mjs` | 5 | 5 | 0 |
| **Total** | **57** | **57** | **0** |

**No spec file was lost and no test was lost.** A green run that dropped files or tests would not
be a green run, and this table is the check for that.

### Backend-tag breakdown — identical to `BASELINE.md`

| Selector | Phase 1 | `BASELINE.md` | Δ |
|---|---|---|---|
| `--list` | 57 tests in 12 files | 57 in 12 | 0 |
| `--list --grep "@deployed-am"` | 57 tests in 12 files | 57 in 12 | 0 |
| `--list --grep "@local-server"` | 23 tests in 5 files | 23 in 5 | 0 |
| `--list --grep "@deployed-am\|@local-server"` | 57 tests in 12 files | 57 in 12 | 0 |

`@local-server` remains a strict subset of `@deployed-am`; **deployed-AM-only = 57 − 23 = 34.**
The 5 `@local-server` files are `xui-cache-busting` (2), `xui-login` (4), `xui-profile` (3),
`xui-realms` (7), `xui-services` (7) — unchanged.

D16 coverage footer, identical in all three gated runs:

```
   filter     none — no tag filter, so every declared backend is in scope
   ran        12 of 14 spec files, 57 tests
   NOT RUN    2 spec files — not run, not passed:
              oauth2/oauth2-test.spec.mjs  @deployed-am   not selected by this run's paths
              saml/saml-test.spec.mjs      @deployed-am   not selected by this run's paths
   undeclared none — every spec file declares a backend
```

---

## The protocol used

The amended protocol from `BASELINE.md`, followed exactly — **reset before every run**, three
separate process invocations, no `--repeat-each`, no `-x`, `retries: 0`:

```
./local/openam-reset.sh
./local/xui-deploy.sh ../openam-ui/openam-ui-ria/target/openam-ui-ria-16.2.0-SNAPSHOT-www.zip
npx playwright test xui/ --reporter=line,./common/backend-tag-reporter.mjs --trace=off \
    > /tmp/3.8-xui-N.txt 2>&1
```

Three separate output files, because `>` truncates. `openam-reset.sh` destroys and rebuilds both
containers, so the redeploy after it is required: the rebuilt container serves the war's own
`/XUI`, not the zip under test.

**Path note.** `openam-ui` is a directory *inside* the OpenAM checkout
(`OpenAM/openam-ui/openam-ui-ria/`), not a sibling of it. From the working directory `OpenAM/e2e`
the relative path `../openam-ui/...` resolves correctly regardless, which is what
`xui-deploy.sh` itself assumes (`${REPO_ROOT}/openam-ui/openam-ui-ria/target/...`).

---

## Per-run results — GATED

| Run | Reset | Deploy | Deployed files | Tests | Passed | Failed | Skipped | Suite wall-clock | Measured | Exit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | 171s | 3s | 652 | 57 | **56** | **0** | 1 | **282s** (4.7m) | 292s | 0 |
| 2 | 170s | 4s | 652 | 57 | **56** | **0** | 1 | **252s** (4.2m) | 254s | 0 |
| 3 | 188s | 4s | 652 | 57 | **56** | **0** | 1 | **270s** (4.5m) | 271s | 0 |

**All three runs green: 56 passed, 0 failed, 1 conditional skip, exit 0 each time.** Grepping all
three logs for failure markers (`✘`, `✗`, `failed`, `error:`, `timeout exceeded`) returns **zero
matches** in every file.

The skip is the usual `xui-httponly.spec.mjs:177` — *"step-up after a fresh page load is recognised
as a session upgrade, not a new login"* — conditional on the server's `cookieHttpOnly`, identical to
`BASELINE.md`.

`xui-login.spec.mjs:123` **passed in all three runs**, as did `xui-services.spec.mjs:402`.

Suite total 817s measured; reset overhead 529s and deploys 11s on top.

Raw output: `/tmp/3.8-xui-1.txt`, `/tmp/3.8-xui-2.txt`, `/tmp/3.8-xui-3.txt`; resets
`/tmp/3.8-reset-{1,2,3}.txt`; deploys `/tmp/3.8-deploy-{1,2,3}.txt`.

### Wall-clock against `BASELINE.md`

| | Run 1 | Run 2 | Run 3 | Mean |
|---|---:|---:|---:|---:|
| `BASELINE.md` batch 4 suite | 250s | 251s | 230s | 244s |
| Phase 1 suite (measured) | 292s | 254s | 271s | 272s |
| `BASELINE.md` batch 4 reset | 137s | 135s | 140s | 137s |
| Phase 1 reset | 171s | 170s | 188s | 176s |

The phase 1 suite is ~11% slower than the batch 4 baseline. **This is not attributed to phase 1**,
because the reset step — which rebuilds containers and touches no XUI code whatsoever — is ~28%
slower over the same three runs. A machine-independent step slowing by more than the suite is the
signature of a slower or more loaded host, not of the artifact under test. Timings are also flat
within the batch (no monotonic upward trend), which is the property `BASELINE.md` identified as
distinguishing healthy batches from the failing ones.

Recorded as an observation, not a finding. Nothing here isolates host load from build cost, and
no measurement was taken that would.

---

## Unstable tests

**None in the gated batch.** Every one of the 57 tests was green in all three runs (56 executed +
1 conditional skip, consistently the same skip).

The only XUI failure seen anywhere in this work was in the **non-gated local-server lane** below.

---

## Optional: local-server lane — CONTEXT ONLY, NOT THE GATE

Run once for context and clearly not part of the acceptance decision. `design.md` D13 puts the
acceptance gate on the **deployed instance and nowhere else**; a green or red local-server run
neither meets nor fails this gate.

```
npm run local-server -- ../openam-ui/.../openam-ui-ria-16.2.0-SNAPSHOT-www.zip --port 8090
OPENAM_BASE_URL=http://127.0.0.1:8090/openam \
  npx playwright test xui/ --grep @local-server \
      --reporter=line,./common/backend-tag-reporter.mjs --trace=off
→ 22 passed, 1 failed (58.8s)   [measured 61s, exit 1]
```

23 tests in 5 files, as expected. The one failure:

**`xui-login.spec.mjs:123` — "logout ends the session and protected routes return to the login
form"**

```
Error: expect(locator).toBeVisible() failed
Locator: getByRole('heading', { name: 'You have been logged out.' })
Expected: visible   Timeout: 15000ms   Error: element(s) not found
  at xui-login.spec.mjs:130
```

**Read: the known, never-root-caused, backend-independent flake.** Not a phase 1 regression, and
not retagged, not fixed, not re-run for a better number. The evidence:

- `BASELINE.md` records this exact test failing **3 of 6 gated runs** under the older protocol,
  against the *Grunt/Maven-zip* XUI — i.e. it failed before phase 1 existed.
- Task 2.16 measured it failing **5 in 10** against the local server specifically.
- It **passed 3 of 3** here against the deployed AM under the amended protocol.

A test that fails against the local API server — which has no AM backend at all — while passing
consistently against the real one is behaving exactly as the existing record describes. The
mechanism was never established and is not established here either; this run adds one more
occurrence to that record and nothing more.

---

## Non-XUI specs — run once for the record, NOT gated on

`ls` in `e2e/` was run first rather than trusting a remembered list. Directories present:
`common/`, `fixtures/`, `local/`, `node_modules/`, `oauth2/`, `playwright-report/`, `policy/`,
`saml/`, `test-results/`, `xui/`.

**`policy/` exists but is empty** — it contains no files at all, so there is nothing to run in it.
`find` for `*.spec.mjs` outside `xui/` returns exactly two files, confirming `oauth2/` and `saml/`
are the only non-XUI spec directories, and both were run. This also matches the reporter's
"14 spec files" total (12 XUI + 2).

```
npx playwright test oauth2/ saml/ --reporter=line --trace=off
→ 4 passed, 2 failed (25.4s)   [measured 28s, exit 1]
```

**Identical outcome to `BASELINE.md` — same two failures, same causes.** Both predate this change
and assert server behaviour, not XUI behaviour. Recorded, not fixed.

1. **`oauth2/oauth2-test.spec.mjs:197` — "Should accept the session id as the csrf value"** —
   known pre-existing failure, flagged as such going in, unrelated to the XUI work. The other 4
   oauth2 tests pass. (`BASELINE.md` cites this at `:183`; the line moved, the test name and cause
   are the same.)

2. **`saml/saml-test.spec.mjs:87` — "should log in as demo and reach the authenticated page"** —
   infrastructure, not a regression. Its `beforeAll` runs `saml/bootstrap.sh`, which failed with:

   ```
   Error response from daemon: No such container: openam-sp
   Error: saml/bootstrap.sh exited with code 1
   ```

   Bootstrap needs **two** AM containers and this harness only ever starts the IdP, so SAML cannot
   pass under `local/` as shipped. (`BASELINE.md` cites this at `:76`.)

   Note this spec **mutates the IdP** before failing and is not idempotent. It was run *after* the
   three gated runs, so it cannot have contaminated them; anything run against this instance now
   should reset first.

Raw output: `/tmp/3.8-rest.txt`.

---

## Comparison against `BASELINE.md` — summary

| | `BASELINE.md` (Grunt + Maven zip) | Phase 1 (Grunt + commons npm) | Verdict |
|---|---|---|---|
| Spec files | 12 | **12** | **no delta** |
| Tests | 57 | **57** | **no delta** |
| Per-spec test counts | see table | **identical, all 12 rows** | **no delta** |
| `@deployed-am` | 57 in 12 files | **57 in 12** | **no delta** |
| `@local-server` | 23 in 5 files | **23 in 5** | **no delta** |
| Deployed-AM-only | 34 | **34** | **no delta** |
| Passed / failed / skipped | 56 / 0 / 1 ×3 | **56 / 0 / 1 ×3** | **no delta** |
| The skip | `xui-httponly.spec.mjs:177` | **same** | **no delta** |
| Exit status | 0 ×3 | **0 ×3** | **no delta** |
| Zip entries / files | 854 / 652 | **854 / 652** | **no delta** |
| Suite wall-clock | 250 / 251 / 230s | 292 / 254 / 271s | slower; reset slower by more — host, not build |
| Non-XUI | 4 passed, 2 failed | **4 passed, 2 failed** | **no delta** |

**`BASELINE.md` was not modified by this work.** It records the Grunt-built, Maven-zip-consuming
XUI and remains the oracle. This file sits beside it.

---

## What this does not mean

- **`xui-login.spec.mjs:123` is still not root-caused.** It passed 3 of 3 here against the deployed
  AM and failed once against the local server. Nothing in this work diagnosed or repaired it. It
  remains latent and could resurface on a slower box or a longer suite.
- **Three green runs are three green runs.** The gate is stated, repeatable and was met, but it
  rests on three samples on one host. `BASELINE.md` needed four batches and 14 runs to establish
  that the *protocol* was the variable; this record inherits that protocol rather than re-deriving
  it.
- **Nothing was fixed anywhere in this work.** No spec, no XUI source, no harness file was edited
  to produce this result.
- **The suite is behavioural, not byte-level.** It establishes that the phase 1 XUI *behaves* like
  the baseline across 57 assertions. It does not establish that the 14 differing files are
  otherwise equivalent; that is task 3.4's job.
- **The commons packages resolve from `~/.m2` only.** Nothing is published to any registry, so this
  result is not reproducible on a machine without those artifacts installed. Publishing is task
  3.11, behind this gate.

## Not determined

- **Why the suite ran ~11% slower than batch 4.** The reset step slowing by ~28% points at host
  load, and that is the reading recorded above, but no measurement was taken that isolates host
  load from any cost introduced by the npm composition. Left open rather than guessed at.
