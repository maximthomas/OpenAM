# XUI e2e baseline — Grunt-built XUI

Baseline of the Playwright XUI suite against the **unmodified Grunt build output**, established
before the Vite migration so the same suite can be pointed at a Vite-built `/XUI` and compared.

**Result: the gate is met.** All 41 tests are green across three consecutive runs — 40 passed,
1 conditional skip, 0 failed, 0 flakes.

Getting there required three fixes to the local harness. None touched the XUI, a spec, or any
product code; all three were in `e2e/local/`, and all three were bugs in the machinery that
deploys a built `/XUI` rather than in what it deploys. See [Harness fixes](#harness-fixes).

Recorded: 2026-08-11. Repo commit `aa69325110dfd28eb3bcc6b18315e453e87c868e`
(`features/openam-ui-migration`), plus the two `e2e/local/` fixes below, which ship with this
baseline.

---

## Environment

### AM under test

| | |
|---|---|
| AM version | `16.2.0-SNAPSHOT` (from reactor root `pom.xml`) |
| Container image | `openam-e2e:local`, `sha256:1ad54f240f0e…`, built 2026-08-08T11:05:52+03:00 |
| Base image | `tomcat:11-jre25` (`openam-distribution/openam-distribution-docker/Dockerfile`) |
| Servlet container | Apache Tomcat 11.0.24 |
| JVM | OpenJDK 25.0.3 LTS, Temurin-25.0.3+9 |
| AM container | `openam-idp`, started 2026-08-11T04:53:34Z, healthy |
| Identity store | `opendj-idp`, `openidentityplatform/opendj:latest`, healthy |
| Base URL | `http://openam.example.org:8080/openam` |
| Container user | `uid=1001(openam) gid=0(root)` |

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
  `cross-env NODE_ENV=production grunt prod --verbose`. Node `v22.21.1`, npm `11.6.2` (pinned in
  `openam-ui/pom.xml`).
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
| Built | 2026-08-08 09:52 (entry timestamps; `target/compiled` matches) |
| Deployed file count in container | 652 — matches the archive |

### Test runner

| | |
|---|---|
| Playwright | 1.60.0 (`@playwright/test` `^1.60.0`, installed 1.60.0) |
| Node | v22.22.2 |
| Config | `e2e/playwright.config.mjs` — `retries: 0`, `workers: 1`, `timeout: 180000`, `expect.timeout: 15000` |
| Browser | Chromium, headless |

`retries: 0` and `workers: 1` are deliberate: the suite is the migration's regression oracle, and
every spec drives the same single AM instance.

---

## Harness fixes

The first attempt at this baseline produced 34 passed / 6 failed / 1 skipped, identically in all
three runs. All six failures were in `e2e/local/`, not in the XUI. They are recorded here because
the same bugs would have hit the Vite side of the comparison, and because two of them are silent.

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

## How this baseline was produced

1. `/XUI` in the running container was replaced with a clean unpack of the Grunt-built zip, so the
   runs are against unmodified build output rather than whatever earlier specs left behind:

   ```
   ./local/xui-deploy.sh
   ==> deploying …/openam-ui-ria-16.2.0-SNAPSHOT-www.zip
   ==> replacing /usr/local/tomcat/webapps/openam/XUI
   ==> deployed. http://openam.example.org:8080/openam/XUI/ now serves 652 files
   ```

   Invoked with no argument, so it resolved the zip through `am_version()` — exercising fix 3.
   Post-deploy verification: 652 files in the container matching the archive, `/XUI` and
   `/XUI/config` owned `openam:root`, `config/` writable by the container user,
   `GET /openam/XUI/index.html` → 200, `GET /openam/isAlive.jsp` → 200.

2. The XUI suite was then run **three separate times**, to three separate files. Three separate
   process invocations rather than `--repeat-each`, because the risk being probed is state one run
   leaves behind in the deployed XUI for the next run:

   ```
   npx playwright test xui/ --reporter=line > /tmp/suite-xui-fixed-{1,2,3}.txt 2>&1
   ```

3. `oauth2/ saml/` was run once afterwards, for the record only — see [Non-XUI specs](#non-xui-specs).

No spec, config, or product source file was modified to produce this baseline. The only changes
are the three `e2e/local/` harness fixes above.

---

## Suite size

**10 spec files, 41 tests.**

| Spec | Tests | Backend tag (D16) |
|---|---:|---|
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
| **Total** | **41** | 18 deployed-AM-only, 23 both |

Every test carries a backend tag, declared on the `test.describe` block. Verified by comparing
`--list` against `--list --grep "@deployed-am|@local-server"`: both report 41 tests in 10 files.

---

## Per-run results

| Run | Passed | Failed | Skipped | Playwright wall-clock | Measured wall-clock |
|---|---:|---:|---:|---|---|
| 1 | 40 | 0 | 1 | 2.3m | **138s** |
| 2 | 40 | 0 | 1 | 2.4m | **147s** |
| 3 | 40 | 0 | 1 | 2.3m | **140s** |

Identical in all three runs, exit code 0 each time, no error output anywhere in the three logs.
No test changed state between runs in either direction. **There are no flakes in this suite.**

Runs are ~35s slower than the pre-fix attempt (114s / 102s / 99s) for the expected reason: the six
theming and operator-module tests now execute their fixtures and drive a browser, where before
they aborted in setup within milliseconds.

The 1 skipped test is `xui/xui-httponly.spec.mjs:177` — *"step-up after a fresh page load is
recognised as a session upgrade, not a new login"*. It self-skips via `test.skip(!httpOnly, …)` at
line 186 after reading `cookieHttpOnly` from `/json/serverinfo`; this server runs in
token-readable mode, so the branch under test does not apply. This is a legitimate conditional
skip, not a disabled test, and it skipped in all three runs.

---

## Baseline for comparison

When the Vite-built `/XUI` is deployed and this suite is re-run, the Grunt baseline to match is:

- **41 tests, 10 spec files**
- **40 passed, 1 skipped, 0 failed** (the skip is `xui-httponly.spec.mjs:177`, conditional on
  `cookieHttpOnly`)
- **~135–150s wall-clock**, `workers: 1`, `retries: 0`
- **Zero flakes** across three consecutive runs

Deploy the Vite build the same way — `./local/xui-deploy.sh path/to/outDir` — so both sides go
through identical deployment. Anything short of 40/1/0 on the Vite side is a migration finding.

---

## Non-XUI specs

Run once for the record, **not gated on**. These specs predate the XUI work and assert server
behaviour, not XUI behaviour; the migration cannot affect either of them.

```
npx playwright test oauth2/ saml/ --reporter=line
→ 4 passed, 2 failed (6.1s)
```

1. **`oauth2/oauth2-test.spec.mjs:183` — "Should accept the session id as the csrf value"** —
   known pre-existing failure, flagged as such going in.

   ```
   expect(received).toBe(expected)   Expected: 302   Received: 400
   ```

   The other 4 oauth2 tests pass, including the two negative CSRF cases.

2. **`saml/saml-test.spec.mjs:76` — "should log in as demo and reach the authenticated page"** —
   infrastructure, not a regression. The spec runs `saml/bootstrap.sh` itself in a `beforeAll`
   (`execScript`, line 60); it does not need running by hand. Bootstrap configures a circle of
   trust and exchanges SAML metadata between **two** AM containers, `openam-idp` and `openam-sp`,
   and this harness only ever starts the IdP. `local/openam-up.sh` contains no reference to
   `openam-sp` and the spec targets `http://sp.mycompany.org:8081/openam`, so SAML cannot pass
   under `local/` as shipped.

   It is also **not idempotent**: it mutates the IdP before failing, so its failure mode depends
   on whether it has run before. On a pristine instance it reports `No such container: openam-sp`;
   on a second run it reports `Circle of Trust exists : MYSAML` and then exits 127. Both are the
   same missing-SP problem. Reset the instance before any run that needs a pristine IdP.

   `bootstrap.sh` does not source `local/lib.sh`, so fix 3 above neither caused nor cures this.

Neither non-XUI spec carries a D16 backend tag; tagging them is task 2.13's scope, not this
baseline's. Both ran only *after* all three gated XUI runs.

Raw run output: `/tmp/suite-xui-fixed-1.txt`, `/tmp/suite-xui-fixed-2.txt`,
`/tmp/suite-xui-fixed-3.txt`, `/tmp/suite-rest-fixed.txt`, `/tmp/xui-deploy-fixed.txt`.
