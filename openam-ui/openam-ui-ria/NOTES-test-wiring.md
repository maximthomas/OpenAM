# NOTES-test-wiring.md — how the unit suite and the end-to-end suite should be wired

Reconnaissance for task **9.3** of `modernize-openam-ui-build` ("Wire `npm test` and the
end-to-end command into the Maven build and CI"). Measured 2026-09-06 on
`features/openam-ui-migration` at `66edb9d`/`bd36540958` (OpenAM HEAD `bd36540958`), tasks 9.1
and 9.2 landed. **No tracked file was changed by this pass.** Every number below was measured on
this machine unless it says otherwise; where a figure is quoted from another note or from a task
record, it says so.

The headline is short, and it is not the one the task title implies:

> **The Maven half of 9.3 is already done, and was done upstream in August 2025.** The
> `npm-test` execution is not new and is not this change's; it is on `master`. What 9.1 changed
> is what `npm test` *means*. The work left in 9.3 is therefore not a pom edit — it is deciding
> what to do about a suite that is **deliberately red**, and that red suite is currently
> breaking `build.yml` on all nine matrix cells.

---

## 0. The single most important finding: `mvn verify` is red today, on every cell

`npm run test` is `npm run test:unit` is `vitest run`. Measured, three consecutive runs:

```
Test Files  2 failed | 16 passed (18)
     Tests  10 failed | 153 passed (163)
```

Those ten are **deliberate**. Commit `ade9c24878` ("XUI: replace Squire mocking with vi.mock")
says so in its own message:

> Ten cases land red and are deliberately left red, documented in the two file headers:
>   - RealmHelper (6): commons URIUtils.js calls `_.object` while binding lodash 4. Pre-existing
>     defect from the lodash/underscore split; `npm run verify:lib-split` already reports it as an
>     error and exits 1. This is the first suite that executes it rather than mocking it.
>   - resolveAssetUrl (4): the `require.toUrl` branch is unreachable from a Vitest module scope,
>     because vite-node mints a per-module CJS require that shadows the global. The branch is still
>     live in production on the openam-oauth2 `.ftl` entry points; only the e2e specs now cover it.

Reproduced exactly, both failure modes:

* `TypeError: default.object is not a function` at
  `node_modules/@openidentityplatform/ui-commons/esm/org/forgerock/commons/ui/common/util/URIUtils.js:57`
  ← `RealmHelper.js:117` (6 cases)
* `TypeError: Cannot stub non-existent own property toUrl` at
  `resolveAssetUrl.test.mjs:114`, plus three assertion failures downstream of the same cause (4 cases)

**Consequence nobody has written down yet.** `build.yml` runs

```
mvn --batch-mode --errors --update-snapshots verify --file pom.xml [-P integration-test]
```

with **no `-DskipTests`**, over the whole reactor, on nine matrix cells. `openam-ui` is module
~29 of 40+ in the root `pom.xml` (line 299), well ahead of `openam-server` (302) and
`openam-distribution` (310). So on this branch:

1. every one of the nine cells fails at `openam-ui-ria`'s `test` phase;
2. the `Upload artifacts` step never runs, so no war and no distribution kit is produced;
3. `build-docker` is `needs: build-maven`, so it never starts — and with it the two
   **`UI Smoke Tests (Playwright)`** steps that are build.yml's own deployed-AM e2e coverage
   (the HttpOnly matrix) never run either.

The red unit suite is therefore not a cosmetic annoyance. It is currently suppressing all of
build.yml's end-to-end coverage. **9.3 cannot be closed without deciding what happens to those
ten cases**, and that decision is upstream of every wiring question below.

`build.yml` triggers on `push` to `features/**`, so this is live on this branch now, not
hypothetical.

---

## A. Does `-DskipTests` skip the `npm-test` execution? — **YES**

Proven twice, statically and empirically.

### A.1 Empirical — the line that settles it

```
$ mvn -o -pl openam-ui/openam-ui-ria -DskipTests test        # exit 0, 59 s wall
...
[INFO] --- frontend:1.15.4:npm (npm-test) @ openam-ui-ria ---
[INFO] Skipping execution.
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
```

**`[INFO] --- frontend:1.15.4:npm (npm-test) @ openam-ui-ria ---` immediately followed by
`[INFO] Skipping execution.` is the answer.** The execution is entered and declines to run.

The control, same command without the flag:

```
$ mvn -o -pl openam-ui/openam-ui-ria test                    # exit 1, 65 s wall
[INFO] --- frontend:1.15.4:npm (npm-test) @ openam-ui-ria ---
...
[INFO]  Test Files  2 failed | 16 passed (18)
[INFO]       Tests  10 failed | 153 passed (163)
[INFO] BUILD FAILURE
[ERROR] Failed to execute goal com.github.eirslett:frontend-maven-plugin:1.15.4:npm (npm-test)
        on project openam-ui-ria: Failed to run task: 'npm run test' failed.
        org.apache.commons.exec.ExecuteException: Process exited with an error: 1 (Exit value: 1)
```

Note that `npm-build` (bound to `compile`) ran in **both** invocations — `-DskipTests` skips the
test-phase execution only, and the Vite build still happens. That is exactly what
`xui-e2e.yml`, `xui-local-server.yml` and `e2e/local/README.md` depend on.

### A.2 Static — why, so it cannot be mistaken for luck

From `~/.m2/repository/com/github/eirslett/frontend-maven-plugin/1.15.4/frontend-maven-plugin-1.15.4.jar`.

`META-INF/maven/plugin.xml`, the **`npm` mojo** (checked on that mojo specifically, not on a
sibling):

```xml
<skip        implementation="boolean"           default-value="${skip.npm}">${skip.npm}</skip>
<skipTests   implementation="java.lang.Boolean" default-value="false">${skipTests}</skipTests>
<testFailureIgnore implementation="boolean"     default-value="false">${maven.test.failure.ignore}</testFailureIgnore>
```

`AbstractFrontendMojo` bytecode:

```
private boolean isTestingPhase();
    execution.getLifecyclePhase()  ->  "test".equals(p) || "integration-test".equals(p)

private boolean skipTestPhase();
    skipTests.booleanValue() && isTestingPhase()

public void execute();
    26: invokespecial skipTestPhase()   ifne -> 157   // "Skipping execution."
    33: invokevirtual skipExecution()   ifne -> 157
```

So: `skipTests` is bound to the `${skipTests}` user property; `isTestingPhase()` keys off the
**declared `<phase>` of the execution**, not off the goal; `npm-test` declares
`<phase>test</phase>`; therefore `-DskipTests` skips it and would equally skip any execution
bound to `integration-test`.

**Two corollaries worth having in hand.**

* `-Dmaven.test.skip=true` is **not** a synonym here. Only `${skipTests}` is bound. A build using
  `maven.test.skip` would still run the Vitest suite.
* `-Dmaven.test.failure.ignore=true` **is** honoured, and only in the test/integration-test
  phases: the mojo catches `TaskRunnerException`, logs `There are test failures.\nFailed to run
  task:` and continues. That is the one-flag lever for the red suite, and it is a lever
  `build.yml` does not currently pull.

### A.3 What this means for the three consumers named in the task

All three build the XUI with `-DskipTests` and all three are therefore **unaffected** by the red
suite — they were correct before this pass and stay correct:

| Consumer | Command |
|---|---|
| `e2e/local/README.md:78, :160, :176` | `mvn -DskipTests install` / `mvn -o -DskipTests package` / `mvn -pl … -am -DskipTests package` |
| `.github/workflows/xui-e2e.yml:…` | `mvn --batch-mode --errors -DskipTests install --file pom.xml` |
| `.github/workflows/xui-local-server.yml:…` | `mvn --batch-mode --errors -pl openam-ui/openam-ui-ria -am -DskipTests package --file pom.xml` |

`build.yml` is the **only** lane that does not pass the flag, which is why it is the only one that
is red.

---

## B. What `mvn -o -pl openam-ui/openam-ui-ria test` does, end to end

| Phase | Execution | What happens |
|---|---|---|
| `initialize` | `install-node-and-npm` (inherited from `openam-ui/pom.xml`) | node **v22.21.1** / npm **11.6.2** into `openam-ui/openam-ui-ria/node` (gitignored) |
| `initialize` | `npm-install` (inherited) | bare `npm install` — **rewrites `package-lock.json`** |
| `initialize` | `copy-commons-npm-tarballs` (dependency-plugin) | `ui-commons.tgz`, `ui-user.tgz` into `target/npm/` |
| `initialize` | `npm-install-commons` | re-installs the two tarballs `--no-save --legacy-peer-deps`, undoing the prune the bare `npm install` just did |
| `compile` | `npm-build` | `npm run build:production` → `vite build`, **22.42 s**, 263 static files + 37 runtime libraries + 3 stylesheets into `target/compiled` |
| `test` | **`npm-test`** | `npm run test` → `vitest run` |

**Yes, it reaches `npm-test`. Yes, the suite runs — a real one, 18 files / 163 tests. No, it does
not pass.** Vitest's own duration inside Maven was **9.57 s**; the whole invocation was **65 s**
wall against a warm `~/.m2` and a warm `target/`, versus **59 s** for the identical run with
`-DskipTests`.

Confirms the fail-fast precondition: not a stub. `master`'s `"test"` script was
`grunt karma:build`; this branch's is `npm run test:unit` → `vitest run`.

**One side effect that matters and is already documented in the workflow.**
`xui-local-server.yml` says it plainly:

> Note that this step rewrites `openam-ui-ria/package-lock.json`: the pom's `npm-install`
> execution runs `npm install`, not `npm ci`. Harmless on a runner that is thrown away; do not add
> a clean-tree assertion after it without fixing that first.

Reproduced: both Maven runs above left `package-lock.json` dirty (+15 lines, all `"peer": true`
markers). It was restored with `git checkout --`. **Anyone running Maven in this module locally
must expect to restore that file**, and 9.3 should not add a clean-tree assertion anywhere
downstream of a Maven invocation without first switching `npm-install` to `npm ci`.

---

## C. Timing, and where the unit suite belongs in CI

### C.1 Measured

`npm run test:unit` alone, three runs on this machine (warm `node_modules`, warm page cache):

| Run | Wall (`/usr/bin/time`) | Vitest self-reported duration |
|---:|---:|---|
| 1 | 11.51 s | 10.54 s (transform 3.56, setup 1.55, collect 6.90, tests 9.71) |
| 2 | 11.12 s | 10.20 s |
| 3 | 12.46 s | 11.57 s |
| *inside Maven* | (65 s − 59 s ≈ 6 s of a noisy delta) | **9.57 s** |

**Call it ~10–12 s wall per invocation on Linux.** The slowest single file is
`ThemeManager.test.mjs` at 3.4 s; `RESTLoginHelper` 2.4 s and `SessionValidator` 1.0 s follow.
Nothing else is above 0.5 s.

The marginal cost of `npm-test` really is only the Vitest run: `install-node-and-npm` and
`npm-install` are bound to `initialize` and are paid on every cell regardless of `-DskipTests`.

### C.2 Across build.yml's nine cells

The nine are `ubuntu × {11,17,21,25,26}` plus `macos × {11,26}` plus `windows × {11,26}`.

* On GitHub's ubuntu runners, expect **~12–20 s** per cell (their I/O is slower than this
  machine's).
* macOS and Windows runners are typically **1.5–2.5×** slower for Node/jsdom work — call it
  **20–35 s**.
* Aggregate runner time added: **roughly 2.5–4 minutes** across the nine.
* **Wall-clock added to the matrix: none worth counting.** The cells run concurrently, so the
  matrix gets ~20–35 s longer, against cells that already take tens of minutes for a full
  `mvn verify` of the OpenAM reactor. **Well under 1 %.**

**The cost of running the unit suite on all nine cells is negligible. The cost of it being red
is total.** Do not let the timing analysis obscure which of those two numbers is the decision.

### C.3 Is it actually a feasibility question on Windows? — **No. Checked, not assumed.**

I checked rather than reasoning from "jsdom is cross-platform":

* **`npm-build` already runs on `windows-latest` and `macos-latest` today**, in these same cells,
  through this same plugin. `vite build` loads `vite.config.js` (276 kB) there and succeeds. The
  only *new* code path `npm-test` adds is Vitest + jsdom on top of a config file the platform
  already parses.
* `vitest.config.mjs` re-exports `viteConfig.resolve.alias` and `viteConfig.define` and adds
  nothing platform-specific. Its one path-shaped construct is already separator-agnostic:
  `server.deps.inline: [/@openidentityplatform[\\/]/]` — the `[\\/]` is deliberate.
* `include: ["src/test/vitest/**/*.test.mjs"]` is a Vitest glob, normalised internally.
* **No test file touches the filesystem.** `grep -rnE "process\.platform|/tmp/|C:\\\\|path\.(join|resolve)|readFileSync|__dirname" src/test/vitest/` returns nothing.
* `jsdom` is a declared devDependency at `26.1.0`. (`vitest.config.mjs` carries a warning that on
  some working copies it resolves from the parent `node_modules` "an accident of an untracked
  tree"; on a fresh clone the declared dependency is what answers.)

So it is a **cost** question, as the task states. The one genuine Windows unknown is Vitest's own
worker-pool behaviour on that runner, which nothing here can measure — but it is a
"might be slower / might need `pool: 'forks'`" risk, not a feasibility wall.

### C.4 Recommendation — **ubuntu only**, and the tradeoffs for all three

**Recommendation: run the unit suite on the ubuntu cells only, inside the existing `build.yml`
matrix, gated by an `if:` on `matrix.os` — and keep it in `build.yml` rather than giving it a job
of its own.** Concretely, that means leaving `npm-test` bound where it is and adding `-DskipTests`
on the non-ubuntu cells, or (cleaner, and it reads better) leaving `mvn verify` alone on ubuntu
and adding `-DskipTests` to the macOS/Windows cells.

The honest tradeoffs, all three:

**All nine cells** — *what you get*: a genuine cross-platform signal. The suite exercises the
alias table, `define` substitution and 163 assertions against 18 modules; if a path or a
line-ending assumption ever creeps in, this is what catches it. *What it costs*: ~2.5–4 min of
aggregate runner time (trivial) and **nine copies of every failure**. That last one is the real
cost and it is not about money: a single red case turns a nine-cell matrix into nine red
X's, three of them on platforms where nobody will read the log, and the reader has to work out
that it is one defect rather than a platform-specific one. It also makes the *unit* suite able to
block artifact upload and `build-docker` — which is precisely the failure mode described in §0.

**Ubuntu only** — *what you get*: the same 163 assertions, once per Java version (still five
times — redundant, but that redundancy is free and already how the matrix works), on the platform
where `xui-e2e.yml`, `xui-local-server.yml` and every contributor actually run. Failures are
legible. *What it costs*: no Windows/macOS signal for the UI unit tests. Given that (a) the
suite touches no filesystem, (b) `vite build` — the genuinely path-sensitive step — still runs on
all nine, and (c) the deployed-AM oracle is ubuntu-only anyway, **that is a signal with almost
nothing to say.** Precedent already in the file: `build.yml` gates its `Set Integration Test
Environment` step on `if: matrix.os == 'ubuntu-latest'`.

**A job of its own** — *what you get*: the best failure legibility of the three (one red job with
one name), the fastest feedback (~2 min end to end: checkout, node, `npm ci`, `vitest run` — no
Maven reactor at all), and it can be a required check independent of the heavy matrix. It could
skip Maven entirely and run `npm ci && npm run test:unit`. *What it costs*: **a second answer to
"is the UI tested"**, and a `npm-test` execution in `pom.xml` that either duplicates the job or
has to be neutered. If the pom binding stays live, `mvn verify` still runs the suite on nine
cells and the separate job adds nothing but a tenth. If the pom binding is disabled to avoid
that, then `mvn verify` no longer tests the UI and the module's own build stops being
self-verifying — which is the property `npm-test` was added upstream to provide (#902). It also
needs its own node/`npm ci` setup, and `npm ci` in this module is exactly the thing the pom
avoids: the two commons tarballs are installed out of band precisely because a `3.2.0-SNAPSHOT`
tarball breaks lockfile integrity. A standalone job would have to reproduce that dance or resolve
commons from the registry (i.e. wait for 10.2/10.3).

**Why ubuntu-only wins on balance:** it keeps one answer to "is the UI tested", it costs one
`if:` line, it needs no new job and no second commons-installation story, and it removes the
three least-legible copies of any failure. The separate job becomes the right answer *after*
10.3, when commons comes from the registry and `npm ci` works standalone — at which point the
speed argument (2 min vs the full reactor) becomes real. It is not the right answer today.

**And none of this is worth doing until the ten red cases are resolved.** See §G.

---

## D. The end-to-end half

### D.1 What the requirement actually asks for

`openspec/changes/modernize-openam-ui-build/specs/ui-build-and-packaging/spec.md:119` —
**Requirement: Verification commands**:

> The UI module SHALL expose **commands** to run its unit tests and its end-to-end tests. The
> end-to-end suite SHALL run against a deployed instance through the browser, so that it verifies
> behaviour independently of which build pipeline produced the instance.
>
> - Scenario: Unit tests run from the module — WHEN the unit test command is run in the UI module
>   THEN the unit suite executes and reports pass or failure
> - Scenario: End-to-end suite runs against a deployed instance — WHEN the end-to-end command is
>   run against a deployed instance THEN the suite drives the deployed UI through a browser and
>   reports pass or failure

**It says "expose commands". It does not say "bind into the Maven lifecycle".** That distinction
is the whole of D.

### D.2 Is `test:e2e` wired? — yes, and it was verified rather than read

`package.json:19`: `"test:e2e": "npm --prefix ../../e2e run test:xui --"`, and
`e2e/package.json`: `"test:xui": "playwright test xui"`.

Verified live, without a container, using `--list` (which resolves the config and enumerates
specs but starts no browser and makes no request):

```
$ npm --prefix openam-ui/openam-ui-ria run test:e2e -- --list     # exit 0
   filter     none — no tag filter, so every declared backend is in scope
   ran        14 of 16 spec files, 66 tests
   NOT RUN    2 spec files — not run, not passed:
              oauth2/oauth2-test.spec.mjs  @deployed-am   not selected by this run's paths
              saml/saml-test.spec.mjs      @deployed-am   not selected by this run's paths
   undeclared none — every spec file declares a backend
```

The delegation works, the `--` passthrough works, and the argument reaches Playwright. **66
tests** — the same 66 as task 8.3's bracket (`8 failed, 1 skipped, 57 passed`), which is a useful
independent check that the suite has not changed size.

Base URL: `e2e/common/openam-commons.mjs:29` —
`process.env.OPENAM_BASE_URL ?? "http://openam.example.org:8080/openam"`.

### D.3 Can the e2e suite be bound into the Maven lifecycle at all?

**It could be. It should not be. Say so plainly.**

It is *technically* possible — `frontend-maven-plugin` would happily run
`npm run test:e2e` from an execution bound to `integration-test`, and (per §A) `-DskipTests`
would skip that too, since `isTestingPhase()` matches `integration-test` as well as `test`.

But every one of its three preconditions is outside Maven's reach and outside the module's:

1. **A running AM container.** `e2e/local/openam-up.sh` needs a Docker daemon, and the war,
   `SSOAdminTools` and `SSOConfiguratorTools` **already built** — it hard-`die`s otherwise,
   telling you to run `mvn -DskipTests install`. Those artifacts come from `openam-server` and
   `openam-distribution`, which are reactor modules **downstream** of `openam-ui` (302 and 310 vs
   299). Binding the e2e suite into `openam-ui-ria`'s lifecycle would make module 299 depend on
   the output of modules 302 and 310. That is a reactor cycle, not an inconvenience.
2. **A Playwright browser download.** `npm run setup` → `playwright install chromium`, hundreds
   of MB into `~/.cache/ms-playwright`, from the network, outside `~/.m2` and outside `target/`.
   Maven has no story for that cache and CI handles it with `actions/cache`.
3. **An `/etc/hosts` entry.** `openam.example.org → 127.0.0.1`, which requires root. `openam-up.sh`
   calls `require_hosts_entry` and refuses without it. A build that needs `sudo` is not a build.

Add the runtime: **4.3 minutes** for the suite (task 8.3's record: "Running 66 tests using 1
worker → 8 failed, 1 skipped, 57 passed (4.3m)"), on top of **3–8 minutes cold / ~2 minutes warm**
to stand the instance up (`e2e/local/README.md:38, :90`). Bound into the lifecycle, every
`mvn verify` of the OpenAM reactor — all nine cells — would try to do that.

**Verdict: it cannot and should not be bound into the Maven lifecycle. "No pom change" is the
finding.** The documented command plus the CI job is the correct shape, and it is the shape the
repository already has.

### D.4 Is the requirement already met by `xui-e2e.yml`? — **yes**

Evidence, step by step from the workflow:

| Spec clause | Where it is satisfied |
|---|---|
| "expose commands" | `package.json:19` `test:e2e` → `e2e` `test:xui`; verified by `--list` above |
| "run against a **deployed** instance" | `Start the OpenAM instance` → `working-directory: e2e/local`, `run: ./openam-up.sh` — a real war in a real container |
| "**through the browser**" | `Install the suite` → `npm run setup -- --with-deps` (Playwright chromium); `XUI end-to-end suite` → `npm run test:xui` |
| "independently of which build pipeline produced the instance" | `Build the artifacts the instance is assembled from` → `mvn -DskipTests install`, then `openam-up.sh` assembles from those artifacts; the suite only ever talks HTTP to `http://openam.example.org:8080/openam` |
| "reports pass or failure" | the step's exit status; plus `Collect instance diagnostics` and `Upload failure artifacts` on `failure()`, and `Tear the instance down` on `always()` |

The workflow header states the intent in its own words:

> Runs the XUI end-to-end suite against the instance `e2e/local/openam-up.sh` stands up — the same
> script a contributor runs, so the documented setup is exercised on every run rather than only
> when someone happens to try it.

That last clause is the strongest evidence: the CI job and the documented contributor command are
**the same code path**, so the "command" the spec asks for and the CI lane cannot drift apart.

**One gap, and it is a trigger gap rather than a wiring gap.** `xui-e2e.yml` fires on
`workflow_dispatch` and `pull_request` (paths `openam-ui/**`, `e2e/**`,
`openam-distribution/openam-distribution-docker/Dockerfile`, its own file) — **not on `push` to
`features/**`**. `xui-local-server.yml` fires on both push and pull_request. So on a feature
branch with no open PR, the non-gate lane runs on every push and the acceptance gate runs on
none. Worth recording; it is a deliberate cost choice (the deployed lane has
`timeout-minutes: 120`) and not obviously wrong, but it means "green on this branch" today means
"green on the local-server lane".

### D.5 What is left to wire for the end-to-end half

**Nothing structural.** Specifically:

* **`pom.xml`: no change.** See D.3.
* **`package.json`: no change.** `test:e2e` exists and works.
* **CI: no new job.** `xui-e2e.yml` is the gate; `build.yml`'s `build-docker` job additionally
  runs `npx playwright test xui --reporter=list` twice against its own containers, covering the
  HttpOnly matrix that `xui-e2e.yml` does not.
* The only thing worth *considering* is adding `push: branches: ['features/**']` to
  `xui-e2e.yml`, and that is a cost decision (a 120-minute-budget job on every push), not a
  requirement gap.

### D.6 Oracle separation — **the current workflows respect it. Yes.**

`design.md` D13:

> **D13 — A local API server for the inner loop; the deployed AM stays the oracle** … It does
> **not** move the acceptance gate — tasks 1.13 and 10.1 still require the suite green against the
> deployed instance from task 1.1.

`specs/ui-local-backend/spec.md:141`:

> Every end-to-end spec SHALL declare which backends it is valid against. … **Acceptance of a UI
> build change SHALL require the suite to be green against a deployed AM; a green run against the
> local backend alone SHALL NOT satisfy it.**

The workflows enforce this at four separate points, which is more than lip service:

1. **The job name is the disclaimer.** `xui-local-server.yml`'s job is literally named
   `'Not the acceptance gate -- @local-server specs only; the @deployed-am specs do not run here'`.
   It appears on every check-run list and in every PR status.
2. **The lane is tag-filtered.** `--grep @local-server`, and it overrides
   `OPENAM_BASE_URL=http://localhost:8090/openam`. The `@deployed-am` specs cannot run there even
   by accident.
3. **A step exists purely to say what was missed.** `What this run did not cover`
   (`if: always()`) writes to `$GITHUB_STEP_SUMMARY`:
   > The `@local-server` specs only. This is **not** the acceptance gate — that stays on the
   > deployed AM (`xui-e2e.yml`, tasks 1.13 and 10.1).
4. **Backend declarations are enforced, not conventional.** `./common/backend-tag-reporter.mjs`
   runs in both `playwright.config.mjs`'s default reporter list and the lane's explicit list, and
   its output includes `undeclared none — every spec file declares a backend`.

**No change proposed here, and the `@local-server` lane is explicitly NOT proposed as the
end-to-end job.** The separation is in better shape than most of the rest of the wiring.

---

## E. Workflow drift visible from here

### E.1 The `hashFiles`/`Gruntfile.js` trap — **still live, and now closer to springing**

`NOTES-vite-build.md:826` flagged it:

> `.github/workflows/xui-local-server.yml` | 130 | cache key
> `hashFiles(…, 'openam-ui/openam-ui-ria/Gruntfile.js', …)` — **stale the moment `Gruntfile.js`
> is deleted**; `hashFiles` on a missing path contributes nothing rather than failing, so the cache
> key silently weakens. Must gain `vite.config.js`.

Status today, checked path by path:

* `Gruntfile.js` **still exists** — so the key is **not yet weakened**. The trap has not sprung.
* `vite.config.js` **has been added** to the key (`xui-local-server.yml:151`). That half of the
  note is **resolved**; the note is stale in saying it "must gain" it.
* Every one of the eight hashed paths resolves: `src/**`, `package.json`, `package-lock.json`,
  `Gruntfile.js`, `vite.config.js`, `.eslintrc.js`, `openam-ui-ria/pom.xml`, `openam-ui/pom.xml`.
* **The prose above the key is stale.** `xui-local-server.yml:140`: *"Gruntfile.js stays in the key
  until 4.8 retires it."* 4.8 did not retire it; 7.1 explicitly decided against deleting it
  ("Grunt and Karma retire together or not at all"); 9.1 did not either. Three tasks have now
  passed the buck, and the comment still names 4.8.
* **The trap is closer than it was.** Everything `Gruntfile.js` still serves is now dead or
  nearly so (see E.3), so it is a plausible deletion in any future tidy-up — and the day it goes,
  the key silently loses an input rather than failing loudly. Whoever deletes it must edit
  `xui-local-server.yml:151` in the same commit. **Not fixed here.**

*(Not a defect, but worth knowing: `src/**` now includes `src/test/vitest/**`, so editing a unit
test invalidates the built-XUI zip cache even though unit tests cannot affect the zip. It costs a
~38 s rebuild. Pre-existing — `src/test/js/**` was in the same glob.)*

### E.2 Workflow references to `karma.conf.js` or `test:karma` — **none in any executable line**

`grep -rn "karma" .github/workflows/` returns exactly one hit, and it is a **comment**:

* `xui-local-server.yml:208` —
  > `-DskipTests` is honoured by frontend-maven-plugin -- it skips the **karma** execution, which
  > would otherwise want a browser. The lane below is what tests this UI.

  **The mechanical claim is still true** (§A proves `-DskipTests` skips `npm-test`), but both
  nouns are now wrong: the execution runs **Vitest**, not Karma, and it **does not want a
  browser** — it runs under jsdom. The stated *reason* for the flag has evaporated; the real
  reason to keep it there today is that the suite is red and that lane is not the place to find
  out. That matters because a reader who checks the comment against reality will conclude the flag
  is unnecessary and may remove it.

No workflow invokes `npm run test:karma`, references `karma.conf.js`, or references
`src/test/js/**`. `codeql.yml:89` excludes `**/src/test/**`, which still matches the new
`src/test/vitest/**` — correct by accident, but correct.

### E.3 Stale in configuration (not workflows), all made stale by 9.1

| Where | What | Why it is stale |
|---|---|---|
| `package.json:18` | `"test:karma": "grunt karma:build"` | `karma.conf.js` was deleted by 9.1; `grunt-karma` is gone from `devDependencies` and absent from `node_modules`. The script is dead. |
| `Gruntfile.js:224-226` | `karma: { build: { configFile: "karma.conf.js" } }` | points at a deleted file |
| `Gruntfile.js:384` | `grunt.loadNpmTasks("grunt-karma")` | the package is not installed; Grunt warns and the `karma` task never registers, so `npm run test:karma` cannot work |
| `package.json:88` | `"mocha": "7.2.0"` | orphaned by 9.1 — `karma-mocha` is gone and Vitest brings its own runner. Nothing references it but a comment in `vitest.config.mjs:92`. |
| `package.json` (`chai` 3.5.0) | | orphaned by 9.2 — `grep -rn 'from "chai"' src/` is empty; `setup.mjs` uses `import { chai } from "vitest"` (chai 5) and only `sinon-chai` comes from the package tree |
| `e2e/local/NOTES-xui-build.md:146, :151` | "`test` (karma)"; "karma suite runs and needs a browser" | describes the lifecycle as it was before 9.1 |
| `NOTES-libs-retire.md:186`, `NOTES-vite-build.md:814-820`, `NOTES-lodash-4.md:1277` | various | describe `npm test` as a stub echo and `test:karma` as "the documented path" — both untrue since 9.1 |

*(`requirejs` 2.3.7 is still a devDependency, and the shipped `libs/requirejs-2.3.7-min.js` is a
**vendored** file under `src/main/js/libs/` with no `NPM_LIBRARY_FILES` row — so the
devDependency looks orphaned too. That predates 9.1 (4.7/5.5) and is noted only for completeness.)*

**Listed, not fixed**, per the task.

---

## F. What a live end-to-end verification would cost

### F.1 Is the AM container up, and what is in its `/XUI`? — **there is no container at all**

```
$ docker ps        -> (empty)
$ docker ps -a     -> (empty)
$ curl --max-time 5 http://openam.example.org:8080/openam/XUI/index.html   -> 000
```

The Docker daemon is alive (server 29.4.2) and the images are still cached
(`openidentityplatform/openam:latest`, `openidentityplatform/opendj:latest`, `openam-e2e:local`
1.3 GB, `openam-e2e:phase3b`, `openam-local:test`). **But no `openam-idp` container exists,
stopped or running.**

So the question "is a Grunt tree or a Vite tree deployed" has no answer: **nothing is deployed.**
Task 8.3's record — *"Container restored to the shipped Grunt build and verified by full-tree
SHA-256"* — was true when written and has since been superseded by a full teardown
(`openam-down.sh` destroys the container; per `README.md:125` the containers hold no volumes, so
there is no residue). Checked rather than assumed, as instructed, and the answer is "neither".

Two consequences:

* The cost below is a **cold** cost, not a redeploy cost. There is no instance to mutate and
  restore — there is one to create and then destroy.
* That is *cheaper to reason about*, because "restore afterwards" collapses to
  `./openam-down.sh`, which returns the machine to exactly today's state. No SHA-256 tree
  comparison is needed, unlike 8.3.

Prerequisites already satisfied on this machine:

* `/etc/hosts` already carries `127.0.0.1 openam.example.org` — **no `sudo` needed**.
* Playwright browsers already cached: `chromium-1217/1223/1234` + headless shells + `ffmpeg-1011`
  in `~/.cache/ms-playwright`. `npm run setup` is a no-op.
* `e2e/node_modules` present.
* The three artifacts `openam-up.sh` requires all exist, at `16.2.0-SNAPSHOT`, from **17 Aug**:
  `openam-server/target/OpenAM-16.2.0-SNAPSHOT.war` (293 MB),
  `SSOAdminTools-16.2.0-SNAPSHOT.zip` (163 MB), `SSOConfiguratorTools-16.2.0-SNAPSHOT.zip` (4.3 MB).
  **So the full `mvn -DskipTests install` is not needed** — and the war's baked-in `/XUI` is the
  17 Aug Grunt-era build, which is conveniently the "shipped Grunt" baseline.

### F.2 What would have to change to run the XUI lane against a Vite build, and what restored

| # | Step | Cost | Mutates |
|---|---|---|---|
| 1 | `./e2e/local/openam-up.sh` | **3–8 min cold**, ~2 min if the image layer is reused (`README.md:38, :90`) | creates the `openam-idp` + `opendj-idp` containers and a build context under `e2e/local/` |
| 2 | `mvn -o -DskipTests package` in `openam-ui-ria` | **~35–41 s** warm `~/.m2` (`NOTES-xui-build.md:157-163`; ~22 s of that is `vite build`, measured today) | rebuilds `target/compiled` and writes `target/openam-ui-ria-16.2.0-SNAPSHOT-www.zip`; **rewrites `package-lock.json`** (§B) |
| 3 | `./e2e/local/xui-deploy.sh` | seconds | `rm -rf` + `docker cp` over `/usr/local/tomcat/webapps/openam/XUI` **inside the container only** |
| 4 | `npm --prefix openam-ui/openam-ui-ria run test:e2e` | **4.3 min** for 66 tests, 1 worker (8.3's record) | writes `e2e/playwright-report/`, `e2e/test-results/` — both gitignored |
| 5 | Restore: `./e2e/local/openam-down.sh` | ~seconds | destroys both containers; no volumes, so no residue |
| 6 | Restore: `git checkout -- openam-ui/openam-ui-ria/package-lock.json` | instant | back to `HEAD` |

**Total: ~9–14 minutes wall**, dominated by the container bring-up and the 4.3-minute suite.

**What it would leave mutated after step 5–6:** `openam-ui/openam-ui-ria/target/` rebuilt
(gitignored), `e2e/playwright-report/` and `e2e/test-results/` written (both gitignored per
`e2e/.gitignore:21-22`), one extra Docker image layer, and nothing tracked. `~/.m2` untouched if
`-o` and `package` (not `install`) are used. **Because there is no container to restore to, the
"restore the shipped Grunt build" step 8.3 had to do does not exist** — `openam-down.sh` is the
whole of it.

**Not run. Not deployed. Costed only, as instructed.**

### F.3 Is 8.3's known-red set still the right comparison point? — **yes, and this is checkable**

The claim: 8 failed / 1 skipped / 57 passed against a deployed Vite tree, ids
`xui-cache-busting:106,144`, `xui-operator-module:461,491`, `xui-theming:662,688,820,838`.

The check that makes it trustworthy — **nothing that could move those ids has changed since 8.3**:

```
$ git diff --name-only 415f52527e..HEAD -- openam-ui/openam-ui-ria/src/main \
                                           openam-ui/openam-ui-ria/vite.config.js \
                                           e2e/
(no output)
```

`415f52527e` is 8.3's last commit (`XUI: add verify:lib-split to guard the lodash/underscore
split`). Since then the only changes are `karma.conf.js` (deleted), `src/test/**`,
`vitest.config.mjs`, `package.json`, `package-lock.json` and `NOTES-vitest.md` — i.e. **9.1 and
9.2 touched no runtime source, no build config and no spec file.**

Since the ids are `file:line` and the spec files are byte-identical, the line numbers still point
at the same tests. And the arithmetic checks out independently: `8 + 1 + 57 = 66`, and today's
`test:e2e -- --list` reports **66 tests across 14 of 16 spec files**.

**So yes — 8.3's set is still the correct comparison point, and it is the *only* one available**,
since 9.1 and 9.2 ran no e2e lane (correctly: neither changed anything the browser can see).

Two caveats to carry into any live run:

* The eight are described in 8.3 as "the known unowned set", owned by **10.1/10.4**, not by 9.3.
  A run that reproduces exactly those eight is a **pass** for 9.3's purposes.
* Task 5.5 recorded a *separate*, narrower theming observation (a 13-test filtered run where
  `xui-theming`'s fixture dies in setup because D6 bundles config and `target/compiled/config/`
  does not exist). That is the mechanism behind the four `xui-theming` ids, not a second
  comparison point. Do not mix the two records.

---

## G. Summary — what 9.3 should actually do

1. **`pom.xml`: no change.** The `npm-test` execution came from upstream `9a9a1ac44b`
   ("Run frontend Karma tests during the Maven test phase (#902)", 2025-08-07) and is present on
   `master` verbatim. 9.1 repointed what it runs. Nothing to add, and nothing should be added for
   the e2e half (D.3).
2. **`package.json`: no change.** `test:unit` and `test:e2e` both exist and both work.
3. **The end-to-end half is already satisfied** by `xui-e2e.yml` plus `build.yml`'s
   `build-docker` smoke steps, and the deployed instance is correctly and visibly the acceptance
   oracle (D.6).
4. **The blocking issue is the ten red unit cases**, which today break `mvn verify` on all nine
   `build.yml` cells and, through `needs: build-maven`, suppress build.yml's own deployed-AM
   Playwright coverage (§0). Three options, in preference order:
   * **fix the six `RealmHelper` cases** — they execute a *real, already-known* defect that
     `npm run verify:lib-split` reports as an error and exits 1 on. This suite is the first thing
     to actually run it rather than mock it. Fixing the defect is the honest answer; it is
     arguably 8.3's leftover rather than 9.3's, and it belongs to whoever owns the commons
     `URIUtils.js` `_.object` call.
   * **`it.skip` the four `resolveAssetUrl` cases with the commit message's reasoning in the
     header** — the branch is genuinely unreachable from a Vitest module scope (vite-node's
     per-module CJS `require` shadows the global) and is genuinely still live in production on the
     `openam-oauth2` `.ftl` entry points, where only the e2e specs reach it. A skip with that
     explanation is accurate; a red test asserting an unreachable branch is not.
   * **`-Dmaven.test.failure.ignore=true`** — supported by the mojo (§A.2) but it makes the suite
     advisory everywhere, which is worse than not running it, because it looks like coverage.
5. **Then, and only then, pick the CI placement.** Recommendation: **ubuntu cells only**, via an
   `if: matrix.os == 'ubuntu-latest'` on the flag, following the precedent already in `build.yml`
   for the integration-test environment step (C.4).
6. **Do not fix the stale references in this task** (E.2, E.3). They are listed so the tidy-up
   commit that deletes `Gruntfile.js` knows it must edit `xui-local-server.yml:151` in the same
   breath.

---

## H. State left by this reconnaissance

* `git status --porcelain` in `OpenAM/`: this file plus the five pre-existing untracked paths
  (`e2e/xui/NOTES-config-warning.md`, `e2e/zz-d6-scratch/`, `openam-ui-ria/NOTES-amd-to-esm.md`,
  `NOTES-d6-upgrade.md`, `NOTES-entry-templates.md`). **No tracked file modified.**
  `package-lock.json` was dirtied by the two Maven runs and restored with `git checkout --`.
* `openam-ui/openam-ui-ria/target/`: `compiled/`, `css-composed/`, `npm/`, `npm-libs/`, `classes/`
  refreshed by the two `vite build`s. `openam-ui-ria-16.2.0-SNAPSHOT-www.zip` **untouched** (28 Aug)
  — neither run reached `package`. All of `target/` is gitignored.
* `~/.m2`: **untouched.** `find ~/.m2/repository -newermt "2026-09-06 06:50" -type f | wc -l` → `0`.
  Both runs used `-o` and stopped at `test`.
* Docker: unchanged — no container was created, started or stopped.
* Throwaway logs were written under the session scratchpad only and deleted; no scripts were
  created in the repository.

---

# PART II — what task 9.3 actually did

Written 2026-09-06, after the reconnaissance above and after the change owner answered four
questions. Everything in Part I stands as measured; this part records the decisions taken, the
three files changed, and the evidence re-measured *after* those changes.

## I.1 The four decisions, as given

| # | Question | Answer |
|---|---|---|
| 1 | Where the unit suite runs in CI | **All nine `build.yml` matrix cells** |
| 2 | What to do about the ten red cases | **Leave all ten red; record it** |
| 3 | The end-to-end half | **Confirm and document only; change nothing** |
| 4 | How to verify | **Static check only** — no container, no deploy |

A fifth question was raised before any edit and is worth keeping, because Part I's §C.4 glossed
it: **"ubuntu cells only" could not have been implemented without a pom change.** `npm-test` has
no `<configuration>` lever of its own, and `-DskipTests` on `build.yml`'s single `mvn verify`
applies to the whole reactor — it would have disabled every Java surefire test on the four
macOS/Windows cells as well, not just the XUI suite. Ubuntu-only would have needed a dedicated
skip property added to the execution (`<skip>${xui.skipUnitTests}</skip>` or equivalent), and so
would a job of its own. **"All nine cells" is the only one of the three placements that needs no
pom change at all**, because it is what the existing binding already does. That is a point in its
favour that Part I did not credit it with.

## I.2 What changed — three files, all of them comments

**No functional change was made anywhere.** No `<phase>`, `<goal>`, `<arguments>` or `run:` line
was touched; no script, no dependency, no test file, no cache key.

1. **`openam-ui/openam-ui-ria/pom.xml`** — +46 lines, 0 deletions, a comment block above the
   `npm-test` execution. It records what the execution runs now, that `-DskipTests` skips it and
   *why* (the `${skipTests}` binding plus `isTestingPhase()`), that `-Dmaven.test.skip` is **not**
   a synonym, that `npm-build` is bound to `compile` so the zip is unaffected by the flag, which
   lane does run the suite, and that ten cases are red on purpose. This is the deliverable of the
   task's item 2: the next person can now answer "does `-DskipTests` skip the suite" from the file
   rather than from the plugin's bytecode.
2. **`.github/workflows/xui-local-server.yml`** — two stale comments corrected (§I.4).
3. **`.github/workflows/build.yml`** — a comment above `Build with Maven` making the all-nine-cells
   placement a recorded decision rather than an accident of the default binding, with the timings,
   the alternatives rejected, and the consequence while the suite is red.

**`pom.xml` needed no structural edit and got none.** The `npm-test` execution is not this
change's work: `git show master:openam-ui/openam-ui-ria/pom.xml` returns it byte for byte as it
stands here. Verified, not assumed — `9a9a1ac44b` is real ("Run frontend Karma tests during the
Maven test phase (#902)", 2025-08-07), and `master`'s `package.json` still reads
`"test": "grunt karma:build"` where this branch reads `"test": "npm run test:unit"`. 9.1 repointed
the meaning of `npm test`; the binding was already there.

## I.3 Evidence re-measured after the pom edit

`pom.xml` parses (`xml.dom.minidom`), both workflows parse (`yaml.safe_load`), and `build.yml`'s
`mvn` line is unchanged.

From `OpenAM/`, both runs redirected to a file and grepped:

```
$ mvn -o -pl openam-ui/openam-ui-ria -DskipTests test      exit 0, 62.02 s wall (Maven 59.486 s)
  1040  [INFO] --- frontend:1.15.4:npm (npm-test) @ openam-ui-ria ---
  1041  [INFO] Skipping execution.
  1043  [INFO] BUILD SUCCESS

$ mvn -o -pl openam-ui/openam-ui-ria test                  exit 1, 53.07 s wall (Maven 50.712 s)
  1040  [INFO] --- frontend:1.15.4:npm (npm-test) @ openam-ui-ria ---
  1242  [INFO]  Test Files  2 failed | 16 passed (18)
  1243  [INFO]       Tests  10 failed | 153 passed (163)
  1245  [INFO]    Duration  10.46s
  1248  [INFO] BUILD FAILURE
  1253  [ERROR] Failed to execute goal ... :npm (npm-test) on project openam-ui-ria:
                Failed to run task: 'npm run test' failed. ... Exit value: 1
```

Both runs reach the **same execution at the same log line, 1040**, and diverge only in what it
does there. That is the whole of question A, and it now holds with the documenting comment in
place.

Unit suite wall-clock: **10.46 s** self-reported inside Maven, **10.85 s** standalone
(`npm run test` from the precondition check) — consistent with Part I §C.1's 10-12 s.

**Static verification of the end-to-end half** (decision 4), from `OpenAM/`:

```
$ npm --prefix openam-ui/openam-ui-ria run test:e2e -- --list      exit 0
  Total: 66 tests in 14 files
  filter     none - no tag filter, so every declared backend is in scope
  ran        14 of 16 spec files, 66 tests
  NOT RUN    2 spec files - not run, not passed
  undeclared none - every spec file declares a backend
```

The delegation chain resolves, the `--` passthrough reaches Playwright, and the count still
brackets task 8.3's `8 + 1 + 57 = 66`. No browser was started and no request was made. **The lane
was not run and nothing was deployed.**

## I.4 Stale references — fixed, and left

**Fixed (both in `.github/workflows/xui-local-server.yml`, both comments):**

* **`:208`** said `-DskipTests` "skips the karma execution, which would otherwise want a browser.
  The lane below is what tests this UI." The mechanical claim survives but both nouns were made
  wrong by 9.1: the execution runs **Vitest under jsdom** and wants no browser. The replacement
  names `npm-test`, says the original reason has expired while the flag is still correct (this
  step exists to *produce* the zip), points at the pom comment, and — deliberately — reaffirms
  that **nothing in this lane is the acceptance gate**. The old sentence "the lane below is what
  tests this UI" read as if it were, which is exactly the D13 confusion this task was warned
  against; it is gone.
* **`:140`** said "Gruntfile.js stays in the key until 4.8 retires it." 4.8 did not retire it, 7.1
  explicitly decided Grunt and Karma retire together or not at all, and 9.1 retired Karma alone —
  three tasks have now passed the buck while the comment still named the first. The replacement
  states the position as it actually is and puts the obligation where it belongs: whoever deletes
  `Gruntfile.js` must remove it from the key in the same commit, because `hashFiles` on a missing
  path contributes nothing rather than failing.

**The cache key itself was NOT changed.** `Gruntfile.js` still exists, so the key is intact and
nothing is silently weakened today; removing the path would be a live change to cache behaviour,
which is not this task's to make. The trap is documented in place instead.

**Found and left (none of them in a workflow; all made stale by 9.1/9.2, all listed in Part I
§E.3):** `package.json:18` `"test:karma": "grunt karma:build"` pointing at a deleted
`karma.conf.js` with `grunt-karma` uninstalled; `Gruntfile.js:224-226` and `:384` likewise;
orphaned devDependencies `mocha` 7.2.0 and `chai` 3.5.0; and the prose in
`e2e/local/NOTES-xui-build.md:146,151` plus three `NOTES-*.md` files still describing `npm test`
as a stub and `test:karma` as the documented path. These are 9.1's and 9.2's leftovers rather than
9.3's, and none of them is a CI input — no workflow invokes `test:karma`, references
`karma.conf.js`, or references `src/test/js/**`. `codeql.yml:89` excludes `**/src/test/**`, which
still matches `src/test/vitest/**`: correct by accident, but correct.

## I.5 Oracle separation

Unchanged and still respected, at the four points Part I §D.6 lists. This task **did not** wire the
`@local-server` lane as the end-to-end job and proposed no such thing; the one edit made inside
that workflow strengthens the separation rather than weakening it, by deleting the sentence that
implied the local lane was what tests the UI. The acceptance gate stays `xui-e2e.yml` against the
deployed instance, per D13 and `ui-local-backend`'s *The local backend is not the acceptance
oracle*.

The one open item is unchanged and remains a **trigger** gap rather than a wiring gap:
`xui-e2e.yml` fires on `workflow_dispatch` and `pull_request` but not on `push` to `features/**`,
so on a branch with no open PR only the non-gate lane runs. Recorded, deliberately not changed —
decision 3 was "confirm and document only", and adding a push trigger to a job with
`timeout-minutes: 120` is a cost decision for the change owner, not a requirement gap.

## I.6 The requirement, clause by clause

`ui-build-and-packaging` — **Verification commands**: *"The UI module SHALL expose commands to run
its unit tests and its end-to-end tests. The end-to-end suite SHALL run against a deployed instance
through the browser..."*

| Clause | Satisfied by | Status |
|---|---|---|
| expose a unit test command | `package.json` `test` / `test:unit` → `vitest run`; also bound at `test` phase by `npm-test` | met; measured, 18 files / 163 tests |
| unit suite "executes and reports pass or failure" | exit 1 with `10 failed / 153 passed` | met — reporting failure *is* the scenario |
| expose an end-to-end command | `package.json:19` `test:e2e` → `e2e` `test:xui` | met; verified by `--list` |
| runs against a **deployed** instance, **through the browser** | `xui-e2e.yml`: `openam-up.sh`, Playwright chromium, `npm run test:xui` | met |
| independent of which pipeline produced the instance | the suite only ever speaks HTTP to the deployed URL | met |

`ui-build-and-packaging` — **Distributable artifact contract**: untouched. The only pom edit is a
comment; `zip.xml`, `build-final-zip` and the `package` phase are byte-identical, and `npm-build`
stays bound to `compile` so `-DskipTests` still cannot affect what the zip contains. D8 holds.

## I.7 What 9.3 does NOT close

The ten red cases, by decision 2. `mvn verify` therefore still fails in this module on all nine
`build.yml` cells, `Upload artifacts` still does not run, and `build-docker` — and with it
build.yml's own deployed-AM Playwright HttpOnly coverage — still does not start. That is now
written down in three places (the pom comment, the build.yml comment, and here) instead of nowhere,
which was the point of recording rather than hiding it. The six `RealmHelper` cases are a real
lodash-4 defect in commons `URIUtils.js` that `npm run verify:lib-split` already reports as an
error; fixing them belongs to whoever owns that call. The four `resolveAssetUrl` cases assert a
branch unreachable from a Vitest module scope and are arguably 9.2's to skip or 10.1's to cover.

## I.8 State left by this pass

* `git status --porcelain` in `OpenAM/`: `.github/workflows/build.yml`,
  `.github/workflows/xui-local-server.yml` and `openam-ui/openam-ui-ria/pom.xml` modified; this
  file plus the five pre-existing untracked paths untracked. **Nothing committed, and 9.3 is not
  marked `[x]`.**
* `package-lock.json`: dirtied by the two Maven runs (the pom's `npm-install` is `npm install`,
  not `npm ci`) — exactly the 15 `"peer": true` insertions `xui-local-server.yml` warns about, and
  restored with `git checkout --`. Clean at handoff.
* `node_modules`: `@openidentityplatform/ui-commons` and `@openidentityplatform/ui-user` both
  present at `3.2.0-SNAPSHOT`. The pom's `npm-install-commons` re-installed them after the bare
  `npm install`, as designed; no manual repair was needed.
* `target/`: `compiled/`, `css-composed/`, `npm/`, `npm-libs/`, `classes/` refreshed by the two
  `vite build`s (26.67 s and 26.9 s). `openam-ui-ria-16.2.0-SNAPSHOT-www.zip` untouched — neither
  run reached `package`. All gitignored.
* `~/.m2`: untouched. Both runs used `-o` and stopped at `test`.
* Docker: untouched. No container was created, started or stopped; there is still none.
* Scratchpad logs only; no throwaway script was left anywhere in the repository.

---

## PART III — code review of the 9.3 comments, and what it changed

A reviewer was dispatched over the uncommitted diff (base `bd36540958`). Because the diff is
entirely comment text, the review surface was not "does it build" but "is every assertion true".
Five claims did not survive; all five are now corrected in place.

1. **`pom.xml` "and only it" was false, and this is the one that mattered.** The comment named
   `build.yml` as the sole lane running the unit suite. Three other Maven invocations reach the
   `test` phase with no `-DskipTests`: `deploy.yml:53` (`package`), `deploy.yml:60` (`deploy`) and
   `release.yml:57` (`release:prepare clean release:perform`). The impact is asymmetric and that
   asymmetry is now written down. `deploy.yml`'s `deploy-maven` job is conditional on
   `workflow_run.conclusion == 'success'` for the Build/Release workflows, so while the ten cases
   stay red it never starts — shielded. `release.yml` is `workflow_dispatch` with no such gate, and
   `maven-release-plugin` 3.0.0-M7 (root `pom.xml:1813`) has its `<goals>` element commented out at
   `:1817`, so `preparationGoals` sits at the default `clean verify`. **A release cut while this
   suite is red fails inside `release:prepare`.** A maintainer reading "and only it" would have
   concluded the opposite from the most authoritative comment in the module.
2. **The build-path enumeration was not exhaustive.** `xui-capture-drift.yml:143` is a fourth
   `-DskipTests` path. It passes the flag like the other three, so the substance held; the list is
   now complete and every entry carries its line number.
3. **"reactor module 29 of 40+" was wrong in both halves and mis-framed.** It was an index into the
   root pom's `<modules>` list, which Maven explicitly does not use for ordering; `openam-ui` is
   entry 25 of 55 there (24 of 54 in the default profile — `openam-mcp-server` at `:257` is behind
   `jdk17.options`), and the real recursive reactor is ~156 modules. The causal claim never needed
   the number, so it is gone: "builds well ahead of `openam-server` and `openam-distribution`"
   carries the argument and cannot rot.
4. **`build.yml`'s timing sentence read as an arithmetic error.** 9 x 11 s is ~1.7 min, not 2.5-4.
   The reconciling fact was in these notes (§C, macOS/Windows at 1.5-2.5x for Node/jsdom work) but
   not in the comment. It is now in the comment, which also makes the ~20-35 s wall-clock figure
   follow rather than look arbitrary.
5. **`xui-local-server.yml`'s "still exists" invited a misreading.** True of `hashFiles` inputs,
   but 9.1 removed `grunt-karma` from `package.json` without touching `Gruntfile.js:384`'s
   `grunt.loadNpmTasks("grunt-karma")`, so Grunt now fails at load time and `npm start` and
   `build:grunt` are broken alongside `test:karma`. The comment now says so and scopes its own claim
   to the cache key. Repairing Grunt remains out of 9.3's scope.

**One reviewer finding was rejected.** It flagged "ten of 163 cases" as an overcount, reporting 160
`it(`/`test(` call sites. That count anchored on line-start and missed three: the suite has 161
`it(` plus 2 `test(` = 163, no `.each` expansion anywhere, matching the `Tests 10 failed | 153
passed (163)` line from the real Maven run. The figure stands unchanged.

The reviewer confirmed the load-bearing half against the plugin itself rather than the docs: the
`npm` mojo's `<skipTests>${skipTests}</skipTests>` binding, the *absence* of any
`${maven.test.skip}` binding in `plugin.xml`, `AbstractFrontendMojo.isTestingPhase()` comparing
`MojoExecution.getLifecyclePhase()` against `test`/`integration-test`, and
`<testFailureIgnore>${maven.test.failure.ignore}</testFailureIgnore>`. It also confirmed the
oracle separation held: nothing in the `xui-local-server.yml` edit lets the local lane read as the
acceptance gate, and its closing sentence re-asserts the deployed AM in `xui-e2e.yml`.

All corrections are comment text. `pom.xml` parses, both workflows parse, no XML comment body
contains `--`, and no `<phase>`, `<goal>`, `<arguments>` or `run:` line was touched.
