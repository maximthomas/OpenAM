# NOTES-zip-contract.md — task 4.6: does the zip contract survive the Vite migration?

Task 4.6 (`tasks.md:72`): *Preserve `src/main/assembly/zip.xml` producing `openam-ui-ria-www.zip`
from the new output directory; confirm the server build consumes it with no change.*

**This was a run, not an implementation.** No `pom.xml`, no assembly descriptor, no
`vite.config.js`, no `package.json` and no source file was modified. Nothing was deployed to the
container. The one tracked file that changed is an incidental npm side effect in a different
module — §8.

Companion records this builds on and does not repeat:
[`PHASE1-TREE.md`](PHASE1-TREE.md) (the 652-file Grunt oracle),
[`NOTES-vite-build.md`](NOTES-vite-build.md), [`NOTES-vite-entrypoints.md`](NOTES-vite-entrypoints.md),
[`NOTES-vite-aliases.md`](NOTES-vite-aliases.md), [`NOTES-static-assets.md`](NOTES-static-assets.md),
[`NOTES-npm-commons.md`](NOTES-npm-commons.md), [`NOTES-commons-version-pin.md`](NOTES-commons-version-pin.md).

---

## 0. Headline

**The zip contract survived unchanged. `zip.xml` needed no edit, and the server build needed no
change of any kind.** D8 holds.

**Task 10.4 does NOT yet hold, and neither does scenario 1 of the spec requirement this task
serves.** That distinction is the most important thing in this document. See §0.1.

| question | answer |
|---|---|
| `zip.xml` changed? | **No.** Last touched in 2015 (`5003b40088`); `git diff ca2bfde45d^..HEAD` on it is empty |
| Server-side change needed? | **No.** `openam-server-only` built green against the new zip with zero edits |
| Coordinates changed? | **No.** `org.openidentityplatform.openam:openam-ui-ria:16.2.0-SNAPSHOT:www:zip`, unchanged on both sides |
| Static-directory manifest delta | **none** — `css/`, `images/`, `locales/`, `partials/`, `templates/`, `themes/` are **267/267 md5-identical** |
| Overall manifest delta | 652 → **273** files: 381 absent, 4 differing, 2 extra — all already owned by 4.2, 4.5 and 4.7 |
| Deployable contains a *working* UI? | **No.** `libs/` is absent, the loader 404s, `main.js` requires 303 ids not in the tree — §7 |

### 0.1 What is confirmed, and what is not

The requirement this task serves is **"Distributable artifact contract"**
(`openspec/changes/modernize-openam-ui-build/specs/ui-build-and-packaging/spec.md:7-19`). It has two
scenarios, and this run satisfies exactly one of them:

| | status |
|---|---|
| *Scenario: Artifact produced by the outer build* — produced by the standard Maven build, without the contributor invoking the frontend toolchain directly | **SATISFIED.** `mvn -DskipTests package` on `openam-ui` produces the zip; `frontend-maven-plugin` execution `npm-build` (`pom.xml:503-509`) runs `npm run build:production`. No hand-run Vite. |
| *Scenario: Server build consumes the artifact unchanged* — "**THEN** it produces a deployable containing a **working UI**" | **NOT SATISFIED.** The server build consumes it with zero edits — that half is confirmed. The deployable it produces does **not** contain a working UI (§7). |

Task 4.6's own text (`tasks.md:72`) asks only to *"confirm the server build consumes it with no
change"*, and that **is** confirmed. The *working UI* half belongs to **task 10.4**
(`tasks.md:122`), which reads *"Confirm the server build produces a **working deployable** with no
server-side change."* **No group-4 task owns it**, and it cannot be confirmed until 4.7 ships
`libs/` and group 5 converts the source off AMD.

Do not cite this document as evidence that 10.4 holds. It is evidence that the *packaging* contract
holds.

The single load-bearing reason `zip.xml` needed no edit: it packs `<directory>target/compiled</directory>`,
and task 4.1 pointed Vite's `outDir` at that same directory (`vite.config.js:1144`). The descriptor
never had to learn the new build; the new build was aimed at the old descriptor's directory.

---

## 1. Preconditions

| check | result |
|---|---|
| `src/main/assembly/zip.xml` exists | yes, 1,533 bytes |
| `PHASE1-TREE.md` exists | yes, 75,551 bytes, 652 manifest lines |
| `node_modules/@openidentityplatform/ui-commons` | present, `3.2.0-SNAPSHOT`, 200 files |
| `node_modules/@openidentityplatform/ui-user` | present, `3.2.0-SNAPSHOT`, 65 files |

Re-verified after every build — see §9. No `mvn clean` was run on `openam-ui`, and no `-am` build
was run from the repo root; the ~58 `org.openidentityplatform.commons.ui.libs` artifacts in `~/.m2`
are intact.

---

## 2. The UI build

```
cd openam-ui && mvn -DskipTests package      # log: /tmp/4.6-ui-build.txt
```

**BUILD SUCCESS**, 01:47 min. All four reactor modules green:

```
OpenAM UI Parent ................................... SUCCESS [  9.924 s]
OpenAM RIA Web UI .................................. SUCCESS [ 52.937 s]
OpenAM API UI ...................................... SUCCESS [  8.182 s]
OpenAM API and UI JS SDK ........................... SUCCESS [ 35.577 s]
```

What Vite emitted (`/tmp/4.6-ui-build.txt:412-421`):

```
✓ 3 modules transformed.
target/compiled/main-device.js     1.37 kB │ gzip: 0.64 kB │ map:  4.65 kB
target/compiled/main-authorize.js  2.04 kB │ gzip: 0.95 kB │ map:  8.30 kB
target/compiled/main.js            4.11 kB │ gzip: 1.35 kB │ map: 10.36 kB
[plugin xui-static-assets] copied 263 static files verbatim, compiled 3 stylesheets
  and stamped index.html with version 16.2.0-SNAPSHOT, into target/compiled
✓ built in 2.77s
```

### `✓ 3 modules transformed` is the whole story of the absences

Three modules, not 3 + 331. **Rollup never walked the application graph, because the source is
still AMD.** The emitted `main.js` is the AMD entry minified and passed through essentially
verbatim — it still opens with `require.config({map:{...},paths:{...},shim:{...}})` and still ends
with a top-level `require([...303 module ids...], ...)`. Vite treated the `define`/`require` calls
as opaque runtime calls, resolved nothing behind them, exited 0.

### Which vite actually ran — closing an open question 4.3 escalated

`tasks.md:69` records 4.3 leaving this unresolved: *"no vite is installed in
`openam-ui-ria/node_modules`, so resolution walks up to 8.1.0 … Which vite actually runs is still
unresolved and now matters."* **This run resolves it, and falsifies the premise.**

```
/tmp/4.6-ui-build.txt:410   vite v5.4.21 building for production...
```

`openam-ui-ria/node_modules/vite` is now present at **5.4.21** — the declared `^5.4.21`
(`package.json:61`) resolves, runs, and builds green. The npm install that 4.3 predicted would leave
it absent installed it. **4.3's predicted `"default" is not exported` failure does not reproduce**,
because the vendored UMD lodash is handled by `build.commonjsOptions.include`, not by rolldown's
native CJS interop.

Three vite majors are live in one reactor, which is worth knowing before anyone debugs a build
difference between modules:

| module | vite |
|---|---|
| `openam-ui-ria` | **5.4.21** (declared `^5.4.21`) |
| `openam-ui` | 8.1.0 |
| `openam-ui-js-sdk` | 8.0.16 |

**This is the expected phase-2 midpoint outcome, and it is not a failure of this task.** The build
completes; the artifact packs; the server consumes it. What the artifact cannot yet do is *run* —
see §7. Converting the source is group 5's (`5.1` onward). No AMD shim was added to force a
fuller bundle.

---

## 3. The artifact

| | |
|---|---|
| Path | `openam-ui/openam-ui-ria/target/openam-ui-ria-16.2.0-SNAPSHOT-www.zip` |
| Size | 788,513 bytes (was 2,450,123 for the Grunt-built copy in `~/.m2`) |
| Files | **273** (phase 1: 652) |
| Uncompressed | 1,713,428 bytes (phase 1: 7,217,101) |
| Coordinates | `org.openidentityplatform.openam:openam-ui-ria:16.2.0-SNAPSHOT:www:zip` |
| Built by | `assembly:3.8.0:single (build-final-zip)`, `src/main/assembly/zip.xml` |
| Installed to | `~/.m2/repository/org/openidentityplatform/openam/openam-ui-ria/16.2.0-SNAPSHOT/openam-ui-ria-16.2.0-SNAPSHOT-www.zip` |

Archive root is still the tree root — `<baseDirectory>/</baseDirectory>`, `target/compiled` →
`<outputDirectory>/</outputDirectory>` — so every path in the manifest below is also its path
inside the zip and its path under `/openam/XUI/` on a deployed instance. Unchanged from phase 1.

---

## 4. Manifest diff against `PHASE1-TREE.md`

Method: unzip the artifact, `md5sum` + `stat -c%s` every file, sort by path, join against
`PHASE1-TREE.md` §7 on path. **Per-file digests, not counts** — task 3.7 found `form2js` differing
between two sources with the counts identical either way, so a count comparison proves nothing.

| directory | phase 1 | zip | md5-identical | differing | absent | extra | verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| `(root)` | 8 | 10 | 4 | 4 | 0 | 2 | see below |
| `components/` | 5 | 0 | 0 | 0 | 5 | 0 | absent — bundled/deferred |
| `config/` | 17 | 0 | 0 | 0 | 17 | 0 | absent — bundled/deferred |
| `css/` | 10 | 10 | 10 | 0 | 0 | 0 | **none** |
| `images/` | 19 | 19 | 19 | 0 | 0 | 0 | **none** |
| `libs/` | 50 | 0 | 0 | 0 | 50 | 0 | absent — bundled/deferred |
| `locales/` | 3 | 3 | 3 | 0 | 0 | 0 | **none** |
| `org/` | 303 | 0 | 0 | 0 | 303 | 0 | absent — bundled/deferred |
| `partials/` | 29 | 29 | 29 | 0 | 0 | 0 | **none** |
| `store/` | 6 | 0 | 0 | 0 | 6 | 0 | absent — bundled/deferred |
| `templates/` | 198 | 198 | 198 | 0 | 0 | 0 | **none** |
| `themes/` | 4 | 4 | 4 | 0 | 0 | 0 | **none** |
| **total** | **652** | **273** | **267** | **4** | **381** | **2** | |

Bytes: phase 1 7,217,101, zip 1,713,428.

### The 4 differing files (present in both, md5 mismatch)

| path | phase 1 md5 / size | zip md5 / size |
|---|---|---|
| `main-authorize.js` | `2d68e9cc4918e7c2625461ae1849921e` / 5,044 | `0c1a8bf52430f310a35ef82d8a9066a9` / 2,038 |
| `main-device.js` | `8b90ee3a59609959db6110b8241be6cc` / 2,907 | `8cbc0363875cf4f20f634a075a89cc0b` / 1,371 |
| `main.js` | `2d6b6ce6644ba9ef4b2dbbaef37de2ae` / 543,480 | `aaf811b06c1dd4708d9e29294d48fc23` / 4,111 |
| `main.js.map` | `36d56746c0a7ba001ce8890fb1711e7f` / 1,590,337 | `c52fdc6932d15d0a34b165f331adc3ba` / 10,362 |

### The 2 extra files (in zip, not in phase 1)

- `main-authorize.js.map` — 8,298 bytes
- `main-device.js.map` — 4,651 bytes

### The 381 absent files, by subtree

| subtree | absent | bytes |
|---|---:|---:|
| `components/` | 5 | 10,224 |
| `config/` | 17 | 92,219 |
| `libs/` | 50 | 1,970,218 |
| `org/forgerock/commons/` | 72 | 309,531 |
| `org/forgerock/openam/` | 231 | 1,001,683 |
| `store/` | 6 | 8,861 |
| **total** | **381** | **3,392,736** |

### Reading of the delta

**The six static directories are the answer to the question this task was asked, and the answer is
`none`.** `css/` 10/10, `images/` 19/19, `locales/` 3/3, `partials/` 29/29, `templates/` 198/198,
`themes/` 4/4 — **263 files, every one md5-identical to the Grunt build**, plus 4 of the 8 root
files (`favicon.ico`, `index.html`, `oauthReturn.html`, `timezones.json`). 267 byte-identical
files, zero drift, zero reordering, zero re-encoding. Nothing in the operator-facing surface moved.

Two results inside that deserve to be named, because both could have silently degraded:

- **All three LESS outputs reproduce byte-for-byte.** `css/structure.css` (89,221),
  `css/theme.css` (10,690) and `css/styles-admin.css` (158,377) match phase 1's md5 exactly. Task
  4.4 compiled them outside the Vite graph with the same `less` + `less-plugin-clean-css` and
  Grunt's exact options rather than letting `build.cssMinify` near them; this run confirms that
  decision produces identical bytes through the zip, not just in `target/compiled`.
- **`index.html` is md5 `e3444d65a0de8574ec3f356481f16e09`, 988 bytes — identical to the Grunt
  file**, verified here through the zip a second time, independently of task 4.5's own check. The
  `${version}` stamp landed as `v=16.2.0-SNAPSHOT`.

The 4 differing + 2 extra are **4.2's known and recorded deltas**: three bundler entry outputs plus
their sourcemaps. `sourcemap: true` over the two new entries emits `main-authorize.js.map` and
`main-device.js.map`, which the Grunt tree never had. `main.js` shrinking 543,480 → 4,111 and
`main.js.map` 1,590,337 → 10,362 is the same fact as `✓ 3 modules transformed`: Grunt's RequireJS
optimiser inlined a partial bundle into `main.js`, Vite inlined nothing.

The 381 absences split two ways, and the split matters:

- **331 are intended** — `org/` (303), `config/` (17), `store/` (6), `components/` (5). These are
  the JS module tree, which D6 already commits to changing. Task 4.5 recorded the change owner's
  reading of "identical layout" as the addressable operator-facing surface, not the module tree.
  *Caveat this run adds:* they are absent because Rollup could not see them (§2), not because they
  were deliberately bundled into `main.js` — the intent and the mechanism agree on the manifest but
  not on the reason. They become genuinely bundled in group 5.
- **50 are a known deficit handed to 4.7** — all of `libs/`, 1,970,218 bytes. Grunt never shipped
  `libs/` through `copy:compiled`; it arrived via `copy:libraries` from the Maven unpack into
  `target/dependencies`. Task 4.7 owns moving that to npm. Until it lands, the tree is not
  loadable — §7.

**Nothing in the delta is unexplained, and nothing in it is caused by `zip.xml`.**

---

## 5. `src/main/assembly/zip.xml` — did it need to change?

**No. It was not edited, and it did not need to be.** Verbatim, the only functional part:

```xml
<id>www</id>
<baseDirectory>/</baseDirectory>
<formats><format>zip</format></formats>
<fileSets>
    <fileSet>
        <directory>target/compiled</directory>
        <outputDirectory>/</outputDirectory>
    </fileSet>
</fileSets>
```

Evidence it is untouched:

- `git log -- src/main/assembly/zip.xml` → newest commit is `5003b40088` *AME-8327 Move the
  majority of build tasks from Maven to Grunt*. Nothing since.
- `git diff ca2bfde45d^..HEAD -- src/main/assembly/zip.xml` — spanning the entire Vite migration
  from *XUI: add Vite and the npm scripts behind it* to `HEAD` — is **empty**.
- `git status` on the file is clean.

Why no change was needed: the descriptor names a *directory*, not files, patterns, or entry names.
Task 4.1 set `outDir: "target/compiled"` (`vite.config.js:1144`) — the same directory Grunt wrote
and the same directory `zip.xml` has always packed. Task 4.4's `xuiStaticAssets` plugin writes into
that directory too, in `writeBundle`. So the descriptor is indifferent to which tool filled the
directory. It would only need to change if the output directory moved, if a top-level folder were
introduced inside the archive, or if part of the tree had to be excluded — none of which happened.

**One property worth stating explicitly because a later task could break it silently:** the fileSet
has no `<includes>`/`<excludes>`. It packs whatever is in `target/compiled`. That is why the 3 new
`.map` files needed no descriptor edit — and equally why anything a future task drops in that
directory ships without review. It also inherits `useDefaultExcludes=true`, so a dotfile or an
editor-backup pattern emitted at the tree root would be dropped silently; nothing is affected today.

**Production sourcemaps — decided here as "not 4.6's", and handed to group 5.** Three `.map` files
now ship into the 288 MB production war where Grunt shipped one. `zip.xml` was deliberately **not**
given an `<excludes>**/*.map</excludes>`, for three reasons:

1. **Exposure went *down*, not up.** Grunt's `main.js.map` shipped into the same war carrying 85
   sources and ~874 KB of embedded `sourcesContent`. The three Vite maps total 23,311 bytes.
2. OpenAM is CDDL open source — the embedded sources are already public.
3. **`zip.xml` is the wrong control point.** Excluding there exceeds 4.6's scope and would create a
   −1 manifest delta against `PHASE1-TREE.md` with no owning task, corrupting the oracle 4.7 and 4.8
   depend on. The right lever is `build.sourcemap`.

**The forward risk is real and currently unowned.** `vite.config.js:1146` is a bare
`sourcemap: true` with no comment and no task reference — conspicuous in a file where `outDir` two
lines above carries an 11-line rationale. Once group 5 makes the source ESM and Rollup walks the
full graph, that flag emits maps embedding `sourcesContent` for the entire application, and this
fileSet ships them into the war *by construction*. **Group 5 must decide `build.sourcemap: false`
or `"hidden"` for production.** Do not solve it in `zip.xml`.

---

## 6. The server build

```
cd openam-ui && mvn -DskipTests install                # log: /tmp/4.6-ui-install.txt   BUILD SUCCESS
cd openam-server-only && mvn -DskipTests install       # log: /tmp/4.6-server-build.txt BUILD SUCCESS
```

**`openam-server-only` is the consumer**, found by grepping the poms rather than guessing: only
four poms mention `openam-ui-ria`, and `openam-server-only/pom.xml` is the only one that *consumes*
the `:www:zip` (the root pom only manages its version; `openam-ui/pom.xml` and the module's own pom
produce it). `openam-server` is the uberwar that overlays `openam-server-only`; it was deliberately
not built, so that `openam-server/target/OpenAM-16.2.0-SNAPSHOT/XUI` survives as the last on-disk
phase-1 oracle (§10).

**SERVER-SIDE CHANGE NEEDED: no. Zero edits of any kind.** Not to a pom, not to `web.xml`, not to
the war-packaging configuration. D8's *"lets the migration land without a coordinated server-side
change"* holds.

**This does NOT uphold task 10.4.** 10.4 requires a *working deployable*; this run produced a
deployable whose UI cannot load (§7). What is upheld is the narrower claim D8 actually makes: the
migration lands without a coordinated server-side change. See §0.1.

The two places the server touches the artifact both worked untouched:

| `openam-server-only/pom.xml` | what it does | outcome |
|---|---|---|
| `:95-103` `dependency:unpack` `artifactItem` | unpacks `:www:zip` with `<includes>**/*</includes>` into `target/XUI` | unpacked all 273 files |
| `:264-272` `war` `webResource` | copies `target/XUI/` → war `XUI/` with `<filtering>true</filtering>` | copied all 273 files |

Both are path-agnostic — `**/*` and `**/**` — so neither enumerates a file that moved. That is the
structural reason no server-side change was needed: the server never knew what was in the zip.

**Verified end to end, not inferred.** The exploded war's XUI tree was digested and compared to the
zip: **273 files, 273/273 md5-identical, 0 differing, 0 missing, 0 extra.** The war's
`<filtering>true</filtering>` pass altered nothing — worth confirming rather than assuming, because
that pass expands `${...}` in any file whose extension is not in `nonFilteredFileExtensions`, and
`.js`/`.map`/`.html`/`.json`/`.css` are all filtered — none of them appears in
`nonFilteredFileExtensions` (`openam-server-only/pom.xml:230-263`). The extension *set* in the zip
is unchanged from phase 1 (`.js .map .html .json .css .png .ico .woff .woff2 .otf .eot .svg`, `.map`
going 1 → 3 and `.js` 384 → 3).

**The extension argument is not the load-bearing one, and on its own it would be wrong.** Maven's
war filtering triggers on *tokens*, not on extensions: it expands `${...}` in the *content* of any
file whose extension is filtered. So what matters is which `${...}` tokens the shipped tree
contains, and **the Vite tree contains tokens the Grunt tree did not**:

| tree | files containing `${` | tokens |
|---|---|---|
| phase 1 (Grunt) | 1 — `libs/codemirror/mode/javascript/javascript.js` | (in `libs/`, which the Vite tree does not yet ship) |
| this build (Vite) | 2 — `main-authorize.js`, `main-authorize.js.map` | `${themePath}`, `${templatePath}`, `${x}`, `${m}` |

These are ES template literals that survived minification, not Maven properties. **They pass today
only because none of those four names resolves to a Maven property** — which the 273/273 md5
equality between zip and war proves empirically, and which is the real evidence in this section.

**Handed forward to 4.7, 4.8 and group 5 as a live hazard.** The exposure grows with the bundle: at
303+ modules with `sourcemap: true` embedding `sourcesContent` for the whole application, any
literal shaped like `${project.…}`, `${basedir}` or any other real property becomes a **silent**
substitution inside the deployed war — no warning, no build failure. The check is
`grep -rl '\${' ` over the shipped tree against the resolved property set, and it belongs in every
later war-contents verification. The eventual fix is adding `js` and `map` to
`nonFilteredFileExtensions` — which would be the first genuine server-side change this migration
needs, so it is worth knowing early that D8's "no server-side change" has a shelf life.

War produced: `openam-server-only/target/OpenAM-ServerOnly-16.2.0-SNAPSHOT.war`, 288,923,519 bytes.

---

## 7. What this run does NOT establish

The build is green and the contract is intact. **The shipped tree is not loadable**, and no build
step says so:

- `index.html` ships `<script src="libs/base64-1.0.0-min.js">` and
  `<script src="libs/requirejs-2.3.7-min.js">`. `libs/` is empty in the zip. **Both 404.**
- The six `.ftl` pages in `openam-oauth2` do the same against
  `${baseUrl}/XUI/libs/requirejs-2.3.7-min.js` (`page/authorize.ftl:65`, `popup/authorize.ftl:64`,
  `touch/authorize.ftl:64`, `page/error.ftl:56`, `CodeVerificationForm.ftl:37`, `CodeThanks.ftl:37`).
- Even with the loader present, `main.js` would `require([...])` 303 module ids that are not in the
  tree.

None of that is a zip-contract or server-configuration problem, and none of it is fixable here:
`libs/` is task 4.7's, the AMD source is group 5's. It is recorded so that 4.7 and 4.8 do not
inherit a green build as evidence of a working one.

---

## 8. Incidental side effect

`git status` after the runs shows exactly one modified tracked file:

```
 M openam-ui/openam-ui-js-sdk/package-lock.json
```

A **different module** (`OpenAM API and UI JS SDK`), touched by its own `npm install` during the
`openam-ui` aggregator build: 26 insertions, 39 deletions, all `"peer": true` annotations npm 11
re-derives. Unrelated to the zip contract.

**CORRECTION — this section described a state that no longer exists.** It originally said the file
was *"left as-is"*. It was subsequently **restored to HEAD** (mtime 18:26, eight minutes after this
document was first written and eleven after the last build). Verified at review time:

```
$ git status --porcelain          # OpenAM
?? openam-ui/openam-ui-ria/NOTES-zip-contract.md
$ git diff --stat -- openam-ui/openam-ui-js-sdk/package-lock.json
(empty)
```

**The OpenAM working tree is clean apart from this untracked notes file.** No build side effect
survives. `openam-ui/openam-ui-ria/package-lock.json` was never modified.

---

## 9. Commons packages — re-verified after every build

| package | state |
|---|---|
| `node_modules/@openidentityplatform/ui-commons` | **present**, `3.2.0-SNAPSHOT`, 200 files |
| `node_modules/@openidentityplatform/ui-user` | **present**, `3.2.0-SNAPSHOT`, 65 files |

No manual restore was needed. The module's own pom does it: `dependency:copy`
(`copy-commons-npm-tarballs`, `initialize`) stages both tarballs into `target/npm/`, then
`frontend:npm` (`npm-install-commons`) runs
`install target/npm/ui-commons.tgz target/npm/ui-user.tgz --no-save --legacy-peer-deps` — after
the bare `npm install` that would otherwise prune them.

---

## 10. Container, and what was deleted

**Container: not touched.** Nothing was deployed. `docker ps -a` is empty — there is no OpenAM
container on this host at all, running or stopped. `e2e/local/openam-reset.sh` was therefore not
run and was not needed.

**Deleted: `openam-server-only/target`, deliberately, before the server build.** The *removal* was
required for an honest result: `dependency:unpack` does not prune, so unpacking the 273-file zip
over the existing 652-file Grunt tree would have left a merged tree and a false pass on the war
contents. The brief's sanctioned `rm -rf <module>/target` was used; **no `mvn clean` was run
anywhere.** The result is verifiably clean — `target/XUI` is exactly 273 files, no merge residue.

**But the *loss* was avoidable, and this document originally called it unavoidable.** A
`cp -a` of the two trees to `/tmp` beforehand would have cost seconds and ~15 MB and preserved both
oracles `NOTES-static-assets.md:28-29` named. Recorded so the next task does the copy first.

**Precondition for 4.7 and 4.8, which each plan another war-contents digest:** the unpack is
`<overWrite>false</overWrite>` (`openam-server-only/pom.xml:100`) and gated by
`target/dependency-maven-plugin-markers`. On a warm `target` the XUI tree is not merely un-pruned —
it **may not be re-unpacked at all**, leaving it entirely stale. *Every* verification of war
contents must start from a removed `target/XUI`.

`NOTES-static-assets.md` §0 named three surviving Grunt trees as a second oracle. Two were in
`openam-server-only/target` and are now gone. **The third was preserved on purpose:**

```
openam-server/target/OpenAM-16.2.0-SNAPSHOT/XUI    652 files    (STALE BY 13 FILES - see below)
```

`openam-server` was not built, specifically so this tree survives for tasks 4.7 and 4.8. It dies on
the next build or clean of `openam-server` — after that, `PHASE1-TREE.md` is the only oracle left.

**It is NOT a byte oracle for anything commons-derived, and this document originally called it
"intact".** It has the right 652 paths, but **13 of them disagree with `PHASE1-TREE.md`**. The tree
was built авг 17, before group 3's commons `3.2.0-SNAPSHOT` rebuild, so all 13 trace to commons:

```
main.js                                                        templates/common/LoginTemplate.html
main.js.map                                                    oauthReturn.html
org/forgerock/commons/ui/common/components/Messages.js
org/forgerock/commons/ui/common/main/AbstractDelegate.js
org/forgerock/commons/ui/common/main/ViewManager.js
org/forgerock/commons/ui/common/util/CustomPolyfill.js
org/forgerock/commons/ui/common/util/ObjectUtil.js
org/forgerock/commons/ui/common/util/UIUtils.js
org/forgerock/commons/ui/common/util/ValidatorsUtils.js
org/forgerock/commons/ui/user/anonymousProcess/AnonymousProcessView.js
org/forgerock/commons/ui/user/profile/UserProfileKBATab.js
```

**For the scope that actually needs it, it is clean: `libs/` is 50/50 md5-identical to
`PHASE1-TREE.md`.** So 4.7 (all 50 `libs/` files) and 4.8 (CodeMirror, under `libs/`) may use it
safely. Anyone diffing `org/`, `templates/` or `oauthReturn.html` against it in group 5 gets 13
false positives. **`PHASE1-TREE.md` is the authority; this tree is a convenience for `libs/` only.**

Also overwritten: `~/.m2/.../openam-ui-ria-16.2.0-SNAPSHOT-www.zip` now holds the 273-file Vite
artifact (788,513 bytes) in place of the 652-file Grunt one (2,450,123 bytes). Unavoidable — step 4
required installing it — and expected. The stale `16.0.7-SNAPSHOT` and `16.1.2-SNAPSHOT` zips (652
files each) are untouched.

**The consequence, stated so nobody hits it by accident: anyone who builds `openam-server` on this
machine now gets a war with a non-loadable XUI *and* would have destroyed the last surviving Grunt
tree in the same command.**

**That second half is now mitigated.** The tree was copied out on the change owner's decision:

```
OpenAM/.phase1-oracle/XUI      652 files, 9.3 MB, verified 652/652 md5-identical to the source
OpenAM/.phase1-oracle/README.md   states the 13-file staleness and what it is safe for
```

Git-ignored via a `.gitignore` entry (the one tracked file this task modified, and the only one).
It survives any Maven build or clean. `README.md` there repeats the `libs/`-only caveat so the
warning travels with the tree rather than living only in this file. Delete it once 4.7 and 4.8 are
done.

---

## 11. Coordinates

**Unchanged on both sides.**

| | produced | requested by `openam-server-only` |
|---|---|---|
| groupId | `org.openidentityplatform.openam` (inherited from parent `openam-ui`, `pom.xml:20-24`) | `org.openidentityplatform.openam` (`:96`, `:583`) |
| artifactId | `openam-ui-ria` (`pom.xml:26`) | `openam-ui-ria` (`:97`, `:584`) |
| version | `16.2.0-SNAPSHOT` | `${project.version}` → `16.2.0-SNAPSHOT`, via root `pom.xml:894-900` `dependencyManagement` |
| classifier | `www` (`zip.xml` `<id>www</id>`) | `www` (`:98`, `:586`) |
| type / packaging | `zip` (`zip.xml` `<format>zip</format>`); module is `<packaging>pom</packaging>` with the zip as an attached artifact | `zip` (`:99`, `:585`) |

Direct evidence from the install log, both sides of the same path:

```
Installing .../target/openam-ui-ria-16.2.0-SNAPSHOT-www.zip to
  ~/.m2/repository/org/openidentityplatform/openam/openam-ui-ria/16.2.0-SNAPSHOT/openam-ui-ria-16.2.0-SNAPSHOT-www.zip
```
```
Unpacking ~/.m2/repository/org/openidentityplatform/openam/openam-ui-ria/16.2.0-SNAPSHOT/openam-ui-ria-16.2.0-SNAPSHOT-www.zip
  to .../openam-server-only/target/XUI with includes "**/*"
```

The producer writes the path the consumer reads. No coordinate changed, and none of `zip.xml`'s
`<id>`, the module's `<artifactId>`/`<packaging>`, or the parent's `<groupId>`/`<version>` was
edited during the migration.

---

## 12. Verdict on task 4.6

Both halves of the task are satisfied by the current tree, with no work required:

- *Preserve `zip.xml` producing `openam-ui-ria-www.zip` from the new output directory* — **already
  true.** The descriptor is untouched since 2015 and packs `target/compiled`, which is where Vite
  writes. §5.
- *Confirm the server build consumes it with no change* — **confirmed by a real build.**
  `openam-server-only` is green, the war's XUI tree is byte-identical to the zip, zero server-side
  edits. §6.

The contract that survived is narrower than "the tree is unchanged", and the distinction should be
carried forward: **the packaging contract is intact and the operator-facing static surface is
byte-identical; the JS module tree is not, and `libs/` is missing.** The first two are what D8
promised. The third is 4.7's, and §7 is the note that it is not yet paid.

**What this document does NOT confirm** (see §0.1): task 10.4, and scenario 1 of the
*Distributable artifact contract* requirement, which both require a **working** deployable. Neither
is confirmable until 4.7 ships `libs/` and group 5 converts the source off AMD.

---

## 13. Review record

This document was independently reviewed after the run. Every load-bearing claim was re-derived
from disk — the zip re-unpacked, the md5 manifest rebuilt from scratch, diffed against
`PHASE1-TREE.md` §7 and against the exploded war, and all sampled `file:line` citations checked.

**Reproduced exactly:** the §4 manifest table (267 identical / 4 differing / 381 absent / 2 extra,
and the absent-by-subtree split to the byte), the 273/273 zip-vs-war equality, the coordinate
citations, the six `.ftl` loader citations, `vite.config.js:1144`, and the `zip.xml` git history.
The no-change decision on `zip.xml` was confirmed correct.

**Three statements did not survive review and are corrected above:**

| § | was | now |
|---|---|---|
| §0, §6 | "task 10.4's claim is upheld" | 10.4 is **not** upheld — it needs a working deployable, §7 shows there is none |
| §8 | lock file "left as-is", tree dirty | lock file was restored; tree is clean |
| §10 | oracle tree "(intact)" | 652 paths but **13 files stale**; valid for `libs/` only |

**Four additions came out of review:** the vite-version finding closing 4.3's open question (§2),
the production-sourcemap hand-forward to group 5 (§5), the `${...}` war-filtering hazard (§6), and
the `<overWrite>false</overWrite>` precondition for 4.7/4.8's war digests (§10).

**One protective action was taken on the change owner's decision** (§10): the last Grunt tree was
copied to `OpenAM/.phase1-oracle/` before a future `openam-server` build destroys it. This added a
`.gitignore` entry — **the only tracked file this task modified.** `zip.xml` remains untouched.

One review finding is **deliberately not actioned**: tracking this file, annotating `tasks.md:72`
and committing. The change owner scoped this run to *"do not commit, and do not mark 4.6 [x]"*,
pending approval.
