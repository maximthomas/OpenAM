# NOTES: cheapest way to get a servable, built XUI

Question: in a clean checkout, what is the cheapest way to obtain a servable `/XUI` —
without building or deploying the server application — for (a) a CI job and (b) a
contributor's first run.

Everything below was measured on this machine, not inferred from the poms.
Measured 2026-08-14. Maven 3.9.15 / Java 11.0.32 / node v22.22.2 / npm 10.9.7.
Repo `OpenAM` @ `a6b486e7e2`, branch `features/openam-ui-migration`.

---

## TL;DR

| Path | Cost | Works on clean CI? |
| --- | --- | --- |
| Download the **published** `-www.zip` | **2.78 s** | yes |
| `mvn -o -DskipTests package` in `openam-ui/openam-ui-ria` (warm `~/.m2`) | **~35–40 s** | only if `~/.m2` already warm |
| `mvn -pl openam-ui/openam-ui-ria -am -DskipTests package` (empty `~/.m2`) | **355.81 s** | yes |
| `mvn -pl openam-ui/openam-ui-ria -DskipTests package` (empty `~/.m2`) | fails at 110.49 s | **no** |
| `npm ci && npm run build:production` alone | fails at 11.62 s | **no** |

- **CI job**: download the published zip (2.8 s). If CI must build from source, it
  **must** use `-am` — see §3.
- **Contributor's first run**: also the published zip, unless they have changed XUI
  sources; then `cd openam-ui/openam-ui-ria && mvn -o -DskipTests package` (~35–40 s).

---

## 1. Does `npm ci && npm run build:production` alone work? — **No.**

Tested against a pristine tree with no `target/` and no `node_modules`, produced with
`git archive` so Maven had provably never run:

```bash
git archive HEAD openam-ui | tar -x -C "$SCRATCH/clean"
cd "$SCRATCH/clean/openam-ui/openam-ui-ria"
npm ci                      # 12.59 s, exit 0
npm run build:production    # 11.62 s, exit 1   <-- FAILS
```

It fails in `requirejs:compile`:

```
Error: ENOENT: no such file or directory, open
  '.../openam-ui-ria/target/transpiled/org/forgerock/commons/ui/common/util/Constants.js'
```

### Why

`Gruntfile.js` composes `target/XUI` from several sources:

```js
buildCompositionDirs = [
    "target/dependencies",                           // maven-assembly-plugin (dir.xml)
    "node_modules/@openidentityplatform/ui-commons/amd",  // npm, installed by Maven (task 3.7)
    "node_modules/@openidentityplatform/ui-commons/www",
    "node_modules/@openidentityplatform/ui-user/amd",
    "node_modules/@openidentityplatform/ui-user/www",
    "target/dependencies-expanded/forgerock-ui-user", // dependency-plugin:unpack, form2js ONLY
    "./src/main/js", "./src/main/resources"           // in the repo
]
```

> **Updated by task 3.7.** Before it, the commons sources arrived as one directory,
> `target/dependencies-expanded/forgerock-ui-user`, unpacked from `commons.ui:user:zip:www`
> by an execution named `unpack-forgerock-ui-user`. That execution is gone. The AMD and
> static sources now arrive as two npm packages installed from Maven-hosted `tgz:npm`
> artifacts; the unpack survives only to supply one file — see *form2js* below.

Everything but the repo's own two is produced by Maven — `target/dependencies` and the
`dependencies-expanded` unpack at `process-resources`, the npm packages at `initialize`.
With no Maven run they do not exist, and `grunt-contrib-copy` **silently ignores a missing
`cwd`** — no warning, no failure. The log shows `copy:compose` copying `Created 174
directories, copied 485 files`, all of them from the repo's own `src/`. A correct build has
**854** files.

Since task 3.7 the `build` task runs `check-composition-sources` first, which fails loudly
naming any missing directory. That guard is why this failure mode should not recur. It does
not cover the `dev`/watch path, which composes a different list.

The npm-installed sources are the fragile ones now: they are installed with the `no-save`
flag and are absent from `package.json`, so **any bare `npm install` in this module prunes
them** ("removed 50 packages"). Re-run the Maven build to restore them.

What is missing from `target/XUI` when the composition sources are absent:

- the entire **`org/forgerock/commons/**`** tree — before 3.7 from `commons.ui:user:zip:www`,
  now from the `ui-commons` and `ui-user` npm packages. `target/XUI/org/forgerock/`
  contains only `openam/`. This is what kills the build — `main.js` requires
  `org/forgerock/commons/ui/common/util/Constants`.
- **all 50 vendor libraries** (`commons.ui.libs`): jquery, backbone, react, react-dom,
  requirejs, lodash, handlebars, moment, i18next, backgrid, selectize, codemirror, …
  `target/XUI/libs/` held only the 4 JS shims that live in the repo.

  *(An earlier revision of this file said 47. The built tree has held 50 since before task
  3.7 — 46 from `target/dependencies` plus 4 shims that live in the repo
  (`backgrid-paginator-0.3.5-custom.min.js`, `jquery.autosize.input.min.js`,
  `jsoneditor-0.7.23-custom.js`, `popover-clickaway.js`) — so the 47 that tasks.md quotes was
  already stale when it was written.)*
- **all vendor CSS**: bootstrap, backgrid, selectize, font-awesome, titatoggle,
  react-select, bootstrap-dialog, … `target/XUI/css/` held only the `.less` sources.

The build died before `less`, `replace`, `copy:compiled` and `copy:transpiled`, so
`target/compiled/` was never created.

### form2js, and CDN artifact drift

The npm packages ship no `libs/` at all, so every shipped library now arrives through
`dir.xml`'s `commons.ui.libs:*:js` dependencySet into `target/dependencies`. All 25 files the
www zip used to supply are covered there — verified, `comm -23` returns empty — so dropping
the zip's unpack loses no *file*. It nearly changed one file's *content*.

`libs/form2js-2.0-769718a.js` is supplied by both sources, and on the build of 2026-08-04 they
disagreed: `3095c47f` from `target/dependencies` against `897ec696` from the zip, the former
carrying seven extra lines that rewrite bracketed form field names (`foo[bar]` → `foo.bar`)
during serialisation. `form2js` backs `RESTLoginView` and five commons self-service views. The
zip's copy composed last and is what AM ships, so removing the unpack would have swapped it —
and **file counts are identical either way**, so nothing in the acceptance check could see it.

The cause is not specific to form2js. The ~58 `commons.ui.libs` artifacts are published to no
repository; `maven-external-dependency-plugin` fetches them from a dozen CDNs by version
string, and **the same coordinate can yield different bytes on a re-fetch**. A later
`install-external` run pulled form2js `2.0-769718a` again and got `897ec696`, matching the zip,
so the two agree today and the pin is currently inert. Task 3.7 kept it
(`unpack-forgerock-ui-user-form2js`) because it makes that one file drift-proof; **the general
risk is unresolved** and applies to all 46 files arriving this way. Only a per-file digest
comparison sees it — counts cannot.

### Second, independent reason npm alone can never be enough

Grunt's `prod` task only ever produces the **directory** `target/compiled`. The
`-www.zip` is built by `maven-assembly-plugin` at the **`package`** phase from
`src/main/assembly/zip.xml`. So even a hypothetically complete Grunt run would not
produce the zip that `xui-deploy.sh` defaults to. (`xui-deploy.sh` does accept a
directory argument, so `target/compiled` could be deployed directly — but only after
Maven has populated `target/` anyway.)

---

## 2. Cheapest Maven invocation — measured

`openam-ui-ria` is `packaging=pom`; the phases that matter are `initialize`
(`install-node-and-npm`, `npm install`), `process-resources` (resources, 2×
`dependency:unpack`, `dependency:copy-dependencies`, `assembly:single` → `dir.xml`),
`compile` (`npm run build:production`), `test` (karma), `package` (`assembly:single` →
`zip.xml`).

All runs used `-DskipTests`, which **is** honoured by frontend-maven-plugin — the log
shows `--- frontend:1.15.4:npm (npm-test) --- / Skipping execution.` Without it the
karma suite runs and needs a browser.

"cold target" = `rm -rf target` first (the CI / first-run condition).

| # | Command (cwd) | `~/.m2` | target | Wall |
| --- | --- | --- | --- | --- |
| 2 | `mvn -o -DskipTests package` (`openam-ui/openam-ui-ria`) | warm | cold | **35.16 s** |
| 8 | `mvn -o -DskipTests -Dmaven.javadoc.skip=true -Dsource.skip=true package` (module) | warm | cold | 37.18 s |
| 3 | `mvn -o -pl openam-ui/openam-ui-ria -DskipTests package` (repo root) | warm | cold | 38.09 s |
| 7 | `mvn -DskipTests package` (module, online) | warm | cold | 38.58 s |
| 4 | `mvn -o -pl openam-ui/openam-ui-ria -am -DskipTests package` (root) | warm | cold | 39.36 s |
| 9 | `mvn -o -DskipTests package` (module) — repeat of #2 | warm | cold | 39.81 s |
| 1 | `mvn -o -DskipTests package` (module) | warm | **warm** | 41.46 s |
| 5 | `mvn -Dmaven.repo.local=EMPTY -pl openam-ui/openam-ui-ria -DskipTests package` | **empty** | cold | **FAIL** @ 110.49 s |
| 6 | `mvn -Dmaven.repo.local=EMPTY -pl openam-ui/openam-ui-ria -am -DskipTests package` | **empty** | cold | **355.81 s** ok |

### Reading the numbers honestly

Repeats of the *same* command (#2 = 35.16 s, #9 = 39.81 s) spread by ~4.6 s. Every
warm-`~/.m2` variant lands in 35–40 s, i.e. **inside the noise of each other**.

Conclusions that survive the noise:

- **Scoping buys nothing.** `-pl`, `-pl … -am`, and running from the module directory
  are all the same cost. There is no reactor to avoid: `openam-ui-ria` has zero
  reactor dependencies, so `-am` only adds two `pom`-packaging modules (~1 s).
- **`-o` buys ~3 s** (#2 vs #7). Only usable with an already-warm repo.
- **A warm `target/` is not faster** (#1, 41.46 s) — Grunt re-does `copy:compose`
  and `requirejs` regardless, and stale-file comparison costs more than it saves.
  There is no reason to preserve `target/` between runs.
- **`-Dmaven.javadoc.skip` / `-Dsource.skip` buy nothing** (#8). Note that
  `maven-source-plugin` forks `generate-sources`, which makes `install-node-and-npm`
  and **`npm install` run a second time** (~5 s); these flags do not suppress the fork.

**Cheapest command:**

```bash
cd /home/maxim/Documents/_projects/forgerock/OpenAM/openam-ui/openam-ui-ria
mvn -o -DskipTests package
# -> target/openam-ui-ria-16.2.0-SNAPSHOT-www.zip   (35–40 s, warm ~/.m2)
```

This is exactly what `xui-deploy.sh` already suggests in its error message, minus `-o`.

Output verified: 854 files, 7 216 015 bytes uncompressed, file list **identical** to
the pre-existing zip. (Byte-level differences are zip entry timestamps only.)

---

## 3. Does it need artifacts that exist only because someone ran `mvn install` here? — **Yes, and this is the important finding.**

`openam-ui-ria` resolves **60** `commons.ui*` artifacts. They fall into two groups with
completely different availability:

### (a) `org.openidentityplatform.commons.ui` — on Maven Central, fine

`user:zip:www:3.1.2` and its transitive `commons:zip:www:3.1.2`.

```
200  https://repo1.maven.org/maven2/org/openidentityplatform/commons/ui/user/3.1.2/user-3.1.2-www.zip
200  https://repo1.maven.org/maven2/org/openidentityplatform/commons/ui/commons/3.1.2/commons-3.1.2-www.zip
```

`~/.m2/.../user/3.1.2/_remote.repositories` says `user-3.1.2-www.zip>central=` — genuinely
downloaded from Central.

### (b) `org.openidentityplatform.commons.ui.libs` — **not published anywhere**

All 58 of them (47 distinct artifactIds) **404 on Maven Central**:

```
404  https://repo1.maven.org/maven2/org/openidentityplatform/commons/ui/libs/
404  .../commons/ui/libs/CodeMirror/4.10/CodeMirror-4.10.zip
404  .../commons/ui/libs/text/2.0.15/text-2.0.15.js
```

In `~/.m2` every one of them carries the locally-installed marker — `_remote.repositories`
with an **empty** repository id:

```
selectize-non-standalone-0.12.1-min.js>=
selectize-non-standalone-0.12.1.pom>=
```

(contrast `>central=` above), plus `maven-metadata-local.xml`, plus `.lastUpdated` files
recording the *failed* Central lookups:

```
https\://repo.maven.apache.org/maven2/.lastUpdated=1778072146080
https\://repo.maven.apache.org/maven2/.error=
```

There is no `~/.m2/settings.xml`; the only repositories in play are Central and the
`central-portal-snapshots` repo declared in the root pom. Neither serves these.

### Where they actually come from

`openam-ui/pom.xml` declares `maven-external-dependency-plugin` with
**`<inherited>false</inherited>`**, bound to `process-resources`
(`resolve-external`, `install-external`). It downloads all 60 artifactItems from CDNs
(`cdnjs.cloudflare.com`, `raw.githubusercontent.com`, `www.eyecon.ro`) and
`install`s them into the local repository. The root `openam` pom does the same for
`extlib/` jars (jato, cc, jdmkrt, jdmktk).

I verified coverage is exact: **47 required artifactIds, 47 covered, 0 missing.**

Because it is `inherited=false`, **it does not run when you build `openam-ui-ria` alone.**
That is the whole story:

- `-pl openam-ui/openam-ui-ria` (no `-am`) on a clean runner → **BUILD FAILURE**:
  ```
  Could not resolve dependencies for project openam-ui-ria:pom:16.2.0-SNAPSHOT
  dependency: org.openidentityplatform.commons.ui.libs:jquery.ba-dotimeout:js:min:1.0 (compile)
      Could not find artifact ... in central (https://repo.maven.apache.org/maven2)
  [+ ~57 more]
  ```
- `-pl openam-ui/openam-ui-ria -am` on a clean runner → **BUILD SUCCESS in 355.81 s**,
  local repo grows to 105 MB.

**So: a clean CI runner can do it, but only with `-am`.** The `-am` is not an
optimisation knob here; it is load-bearing.

### Caveat: the CDN path is not reproducible

The clean-repo build produced a zip differing from this machine's in exactly one file:

```
libs/bootstrap-tabdrop-1.0.js   5105 bytes (this machine)  vs  3283 bytes (fresh CDN fetch)
```

Both are real JavaScript, but different versions. `bootstrap-tabdrop`'s `downloadUrl` is
the **unversioned** `https://www.eyecon.ro/bootstrap-tabdrop/js/bootstrap-tabdrop.js`;
upstream now serves the original 2012 file, while `~/.m2` holds a later fork (extra
"Copyright 2013 Jenna Schabdach / Copyright 2014 Jose Ant. Aranda" lines). Because the
plugin runs with `<force>false</force>`, a warm machine never re-downloads and never
notices the drift.

Other non-reproducible `downloadUrl`s in `openam-ui/pom.xml`:
- `jquery-sortable` → `raw.githubusercontent.com/johnny/jquery-sortable/**master**/…`
- `handlebars` is declared version `4.7.7` but its `downloadUrl` points at **4.7.6**

For a migration comparison that must be byte-stable, pin the built zip (§4), don't
re-resolve from CDNs.

---

## 4. Cheaper paths

### (a) Download the published artifact — cheapest by two orders of magnitude

The `-www.zip` **is published**. Snapshots go to the `central-portal-snapshots` repo
already declared in the root pom:

```bash
curl -sSL -o xui.zip \
  https://central.sonatype.com/repository/maven-snapshots/org/openidentityplatform/openam/openam-ui-ria/16.2.0-SNAPSHOT/openam-ui-ria-16.2.0-20260812.095407-12-www.zip
# 2.78 s, 2 449 622 bytes
```

Resolve the current timestamped name from
`.../openam-ui-ria/16.2.0-SNAPSHOT/maven-metadata.xml` (it lists `classifier=www,
extension=zip`; latest at time of writing `16.2.0-20260812.095407-12`, buildNumber 12).

Verified: 854 files, **identical file list** to a local build, `index.html` at the root
(which is what `xui-deploy.sh` checks), `main.js` 543 470 bytes, all three compiled
stylesheets, 47 libs. Content matches a local build in every file except the
`bootstrap-tabdrop` noted above. It is directly deployable:

```bash
./xui-deploy.sh /path/to/xui.zip
```

Releases are on Maven Central too, with `.sha1`/`.sha256`/`.sha512`/`.asc`:
`https://repo1.maven.org/maven2/org/openidentityplatform/openam/openam-ui-ria/16.1.2/openam-ui-ria-16.1.2-www.zip`
(released 15.1.4 … 16.1.2).

**Limitation, and it matters for the migration work:** the published snapshot is built
from upstream `master`, not from the working tree. It is the right answer for "I just
need a servable XUI to run the suite against"; it is the wrong answer the moment you
have local XUI changes, and it cannot be used for the Grunt-vs-Vite comparison, which
needs a locally-built Grunt artifact.

### (b) Cache in CI

Ordered by payoff:

1. **Cache the built zip.** Skips everything. Key on the inputs that actually change it:
   ```
   xui-www-${{ hashFiles(
       'openam-ui/openam-ui-ria/src/**',
       'openam-ui/openam-ui-ria/package.json',
       'openam-ui/openam-ui-ria/package-lock.json',
       'openam-ui/openam-ui-ria/Gruntfile.js',
       'openam-ui/openam-ui-ria/.eslintrc.js',
       'openam-ui/openam-ui-ria/pom.xml',
       'openam-ui/pom.xml') }}
   ```
   `openam-ui/pom.xml` must be in the key — it pins every vendor lib version.
   `openam-ui-ria/package.json` must be in it too, and the lock file is not a
   substitute: npm lock files do not record `scripts`, and `build:production` —
   the command that produces this zip — lives there. Without it, a change to the
   build script itself leaves every other hashed input identical, hits the cache,
   and the run is served the *previous* build. (Added after review of the task
   2.16 job; the list above originally omitted it.)
   Cache path: `openam-ui/openam-ui-ria/target/openam-ui-ria-*-www.zip`.
   Hit → 0 s; miss → §2.

2. **Cache `~/.m2/repository`.** Turns the clean-runner build from **355.81 s → ~38 s**,
   the single biggest lever if you must build. 105 MB for this module scope.
   Key on `hashFiles('**/pom.xml')`, restore-key `m2-`. This also caches the
   CDN-provisioned `commons.ui.libs` — which, given §3's drift caveat, is a *feature*:
   it freezes the vendor libs.

3. **Cache `openam-ui/openam-ui-ria/node_modules`**, key on
   `hashFiles('openam-ui/openam-ui-ria/package-lock.json')`. Worth ~13 s (`npm ci`
   measured at 12.59 s; the plugin's `npm install` on a warm tree costs ~5 s, and runs
   **twice** because `maven-source-plugin` forks `generate-sources`).

4. **Cache the node distribution** — `frontend-maven-plugin` installs node v22.21.1 /
   npm 11.6.2 into `openam-ui/openam-ui-ria/node/`. Small, and already covered if you
   cache `~/.m2` (the archive lives under `~/.m2/repository/com/github/eirslett`).

---

## Gotchas found along the way

- **`mvn package` dirties the working tree.** The `npm-install` execution runs
  `npm install` (not `npm ci`), and npm 11.6.2 rewrote `package-lock.json`, adding 11
  `"peer": true` lines. A CI job that checks for a clean tree will fail on this. I
  reverted it with `git checkout -- openam-ui/openam-ui-ria/package-lock.json`.
- **Never run `clean` on `openam-ui` or with `-am`.** `maven-external-dependency-plugin`
  binds `clean-external` to the `clean` phase on that module, which removes the
  CDN-provisioned artifacts **from `~/.m2`** — it will cold-bust a warm local repo.
  `mvn clean` scoped to `openam-ui-ria` only is safe (that module doesn't inherit the
  plugin); `rm -rf openam-ui/openam-ui-ria/target` is safer still.
- **`target/…-www.zip.sha`** is produced by `checksum-maven-plugin` at the **`verify`**
  phase, so a `package` build does not create it. The one present before this
  investigation was a leftover from an earlier `mvn install`. Nothing consumes it —
  `xui-deploy.sh` does not.

---

## What this investigation changed on disk

- `openam-ui/openam-ui-ria/target/` was deleted and rebuilt several times. Final state
  is a normal `mvn -o -DskipTests package` result; the zip's file list is identical to
  the one that was there at the start. The stale `…-www.zip.sha` is not restored (see
  above).
- `package-lock.json` was modified by the build and **reverted**. `git status` is clean.
- All experiments on a "Maven has never run" tree used a throwaway `git archive` copy in
  the scratchpad; the real tree was never used for that.
- Empty-local-repository runs used `-Dmaven.repo.local=<scratchpad>`; `~/.m2` was never
  emptied. `~/.m2` did gain the extlib/external artifacts that run #4 re-installed
  (idempotent — they were already present).
- The container was not started and the Playwright suite was not run.
