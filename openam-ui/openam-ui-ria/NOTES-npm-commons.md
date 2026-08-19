# Task 3.7 — consuming the commons AMD build from the Maven npm tarballs

Measurement record for the change that moved `openam-ui-ria` off `commons.ui:user:zip:www`
expansion and onto the `tgz:npm` artifacts attached in task 3.6, while the build stays on Grunt.

Acceptance for this task is a **file-count comparison against the pre-change build**, not the
absence of an error: `grunt-contrib-copy` ignores a missing source directory silently, so a
composition that dropped an entire tree looks exactly like one that worked until
`requirejs:compile` fails for an unrelated-looking reason. Counts are recorded below, and so is
a per-file digest comparison — because counts turned out to be blind to a real content change.

---

## 1. Counts, before and after

Baseline is the pre-change build; "after" is a from-scratch build
(`rm -rf target node_modules`, then `mvn -DskipTests package` from `openam-ui`).

| Measure | Baseline | After | |
|---|---|---|---|
| `target/XUI` files | 719 | 719 | equal |
| `target/XUI/libs` files | 50 | 50 | equal |
| `…-www.zip` entries | 854 | 854 | equal |
| `…-www.zip` non-directory files | 652 | 652 | equal |

**The task text's "47 files in the built tree" is stale.** The tree held 50 before this change
and 50 after: 46 from `target/dependencies` plus 4 shims that live in the repo
(`backgrid-paginator-0.3.5-custom.min.js`, `jquery.autosize.input.min.js`,
`jsoneditor-0.7.23-custom.js`, `popover-clickaway.js`). The 47 traces to an earlier revision of
`e2e/local/NOTES-xui-build.md` and was already wrong when `tasks.md` quoted it. Nothing regressed;
the number in the plan was never right.

## 2. Where each of the 25 libs still comes from

Task 3.7 asks to "name where each still comes from". The answer is uniform, and it is not what
the task text assumes:

**All 25 files in the www zip's `libs/` were already present in `target/dependencies/libs`**,
placed there by `dir.xml`'s `commons.ui.libs:*:js` dependencySet. Verified with `comm -23` over
the two sorted path lists — the result is empty. The zip was overwriting files the first
composition directory already held.

So removing the zip's unpack loses **no file**. The libs continue to arrive exactly as before,
through `dir.xml`, and the npm packages contribute nothing to `libs/` — they ship no `libs/`
directory at all.

That makes `dir.xml`'s dependencySet the **sole** route for the shipped `/libs`, which it was not
before. It is fed transitively: `commons.ui:user:zip:www` → `commons.ui:commons:zip:www` → 33
`commons.ui.libs` dependencies (25 `js`, 6 `css`, 1 `less`, 1 `zip`). This is why the `zip:www`
dependency is **retained** even though its unpack execution is gone, and why removing it as the
task text literally instructs would empty `/libs`.

### The plan's premise here is wrong

`tasks.md` 3.7 says, in bold, "**`dir.xml` is not part of this** — its `dependencySet` blocks
reference `commons.ui.libs:*`, a different groupId, and retire in 4.7." That reasons from groupId
alone. Those artifacts reach the build *transitively through* `commons.ui`, so the two are not
independent. Two consequences:

- `dir.xml` had to change in this task anyway (font-awesome, and the `:less` include).
- `dir.xml` is not packaging-only. It is also the descriptor for the `prepare-working-dir`
  execution that **produces `target/dependencies`**, the first entry in `buildCompositionDirs`.
  Retiring its dependencySet blocks therefore removes a Grunt composition source. That is a much
  larger change than 4.7's scope suggests, and `commons.ui:user:zip:www` must retire with it.

## 3. Content: what counts cannot see

652 shipped files compared by md5 against the baseline zip. **638 identical, 14 different.**

| Differing file | Why |
|---|---|
| `main.js`, `main.js.map` | the r.js bundle; changes whenever any bundled module does |
| `oauthReturn.html`, `templates/common/LoginTemplate.html` | commons-supplied |
| 10 modules under `org/forgerock/commons/` | commons-supplied |

All 14 are commons-supplied and attributable to the version change: the packages are commons
**3.2.0-SNAPSHOT** where the old `zip:www` was **3.1.2**. Spot-checked, the differences are Babel
output formatting (compact vs expanded helpers) plus real source changes — e.g.
`ValidatorsUtils.js` gains a copyright line and a `namePattern` regex fix, `\xF0-s]` →
`\xF0\s-]`. Task 3.4 (`commons/ui/AMD-PARITY.md`) is what establishes the two builds are
behaviourally interchangeable.

### form2js — a content swap the counts hid

One file was *not* a version difference and would have changed silently.

`libs/form2js-2.0-769718a.js` is supplied by both composition sources. On the pre-change build:

```
target/dependencies/libs/form2js-2.0-769718a.js                 3095c47f  12656 bytes  LF
target/dependencies-expanded/forgerock-ui-user/libs/…           897ec696  10160 bytes  CRLF
shipped in …-www.zip                                            897ec696
```

The Maven-artifact copy carries seven lines the zip's copy does not:

```js
function replacer(match, p1, p2, p3, p4, offset, string) {
    return "." + p2;
}
var name = name.replace(/(\[)([a-z][a-z0-9_]+)(\])/i, replacer);
```

That rewrites bracketed form field names (`foo[bar]` → `foo.bar`) during serialisation. `form2js`
is bound at `main.js:56` and used by `RESTLoginView` plus five commons self-service views. The
zip's copy composed later and won; dropping the unpack would have shipped the other one — with
**identical** file counts, zip counts and libs counts. No count-based check could detect it.

**Root cause is broader.** The ~58 `commons.ui.libs` artifacts are published to no repository.
`maven-external-dependency-plugin` fetches them from a dozen CDNs by version string, and the same
coordinate can yield different bytes on a re-fetch. A later `install-external` run pulled form2js
`2.0-769718a` again and got `897ec696` — matching the zip — so today the two sources **agree** and
the pin below is inert.

**Resolution.** `unpack-forgerock-ui-user-form2js` unpacks only `libs/form2js-*.js` from the
retained `zip:www` into `target/dependencies-expanded/forgerock-ui-user`, which composes after
`target/dependencies`. The shipped file stays `897ec696`, drift-proof. Chosen over adopting the
Maven copy so that task 3.8's gate is not run against a library swap folded into a build-plumbing
change; whether AM should move is task 4.7's, where this dependency retires anyway.

**The general drift risk is unresolved** and applies to all 46 files arriving through
`target/dependencies`. Only a per-file digest comparison sees it.

## 4. The five AM-over-commons overrides

Verified by content out of the shipped zip, not by an argument about ordering. All five are
identical to the baseline and to AM's own source, so AM still wins:

| File | md5 |
|---|---|
| `locales/en/translation.json` | `e85549b5…` |
| `templates/user/UserProfileTemplate.html` | `2366b007…` |
| `templates/user/process/registration/userDetails-initial.html` | `fcb95166…` |
| `templates/user/process/reset/resetStage-initial.html` | `5b825ad8…` |
| `templates/user/process/reset/userQuery-initial.html` | `cc5d656c…` |

`mavenProjectSource(".")` remains last in `buildCompositionDirs`, which is what guarantees this.

## 5. Composition

```js
buildCompositionDirs = [
    "target/dependencies",                                // maven-assembly-plugin (dir.xml)
    "node_modules/@openidentityplatform/ui-commons/amd",  // npm, installed by Maven
    "node_modules/@openidentityplatform/ui-commons/www",
    "node_modules/@openidentityplatform/ui-user/amd",
    "node_modules/@openidentityplatform/ui-user/www",
    "target/dependencies-expanded/forgerock-ui-user",     // form2js ONLY
    "./src/main/js", "./src/main/resources"               // last: AM overrides win
]
```

Module ids come out unchanged as `org/forgerock/commons/…` with no path rewrite, because `cwd` is
each package's `amd/` directory. `ui-commons` and `ui-user` have **zero** overlapping paths, so
their relative order cannot matter.

`!package.json` is scoped to the npm directories only — it drops the CommonJS marker at the root
of each package's `amd/`, and applying it to every source would be a latent trap for any future
composition source that legitimately ships one.

### The guard

`grunt build` now runs `check-composition-sources` first, failing with the missing directories
named. This is the defence against the silent-drop class the plan flags in five separate
callouts, and it is needed more than before: the npm sources are installed with the `no-save`
flag and are absent from `package.json`, so **any bare `npm install` prunes them**
("removed 50 packages"). Verified by removing `node_modules/@openidentityplatform` and running
the task — it fails and names all four directories. Not registered for `dev`/watch, which
composes a different list.

## 6. Build wiring

Effective execution order at `initialize` — `dependency:copy` → `install-node-and-npm` →
`npm install` → `npm install <tgz> <tgz>`. The out-of-band install is declared *first* in this
pom but runs *last*, because Maven's pluginManagement merge injects executions inherited from
`openam-ui/pom.xml` ahead of module-declared ones. **That ordering is load-bearing and invisible
in this file**; a comment on the execution records it.

`--legacy-peer-deps` is required. Both packages declare their runtime libraries as
`peerDependencies` and npm 7+ auto-installs those: without the flag the build resolves **50**
unpinned packages (react, backbone, handlebars, jquery, …) from the public registry on every run,
recorded in neither `package.json` nor `package-lock.json` because `--no-save` suppresses exactly
that record. With it, npm adds 2 and stays offline — verified: none of react, react-dom, backbone,
handlebars, i18next, dragula, backgrid, xdate is present in `node_modules` after a build, and both
packages have their `amd/` and `www/` directories. Do **not** substitute `--omit=peer`: `ui-user`
declares `ui-commons` itself as an optional peer, so omitting peers drops `ui-commons`.

`overWriteReleases`/`overWriteSnapshots` are set true on the copy because `destFileName` strips
the version, making the destination stable across versions; with `dependency:copy`'s defaults a
re-pinned `commons.ui.version` whose artifact has an older mtime would silently leave the previous
tarball in place.

## 7. Version state

Two commons versions are in play and nothing checks they agree:

- **AMD/www sources**: `3.2.0-SNAPSHOT`, via `<commons.ui.version>` on the `artifactItem`s.
- **The 33 transitive `commons.ui.libs` pins**: `3.1.2`, via the retained `zip:www`, whose version
  the BOM chain manages. The BOM is `scope=import`, so its properties interpolate inside the BOM
  and `commons.ui.version` cannot reach it.

A vendor-library bump in commons 3.2 will not reach AM, and nothing says why. Task 3.10 should
record this as a version **split**, not a single pin; 3.12 removes it.

## 8. Prerequisites — the build does not stand alone

1. **The tarballs exist only in `~/.m2`.** No released commons carries `tgz:npm`. Build them first
   from the sibling commons checkout on `features/ui-migration`: `mvn install -f ui/pom.xml`.
   Without it this module fails at `initialize` with *Could not find artifact
   org.openidentityplatform.commons.ui:commons:tgz:npm:3.2.0-SNAPSHOT*.
2. **Build from `openam-ui`, not from `openam-ui-ria`.** The ~58 `commons.ui.libs` artifacts are
   fetched by `maven-external-dependency-plugin`, which is `inherited=false` on the `openam-ui`
   aggregator with `install-external` bound to `process-resources`. A standalone build here never
   runs it and dies resolving `selectize-non-standalone`, `text`, `sifter`, … from Central.
   Encountered during this task on a partially-populated `~/.m2` (52 real artifacts, 87
   `.lastUpdated` markers).
3. **Never `mvn clean` on `openam-ui`, never `mvn … -am` from the OpenAM root.** `clean-external`
   deletes those artifacts from `~/.m2` and nothing restores them but a CDN round trip — which,
   per §3, may not return the same bytes. Use `rm -rf target`.

Both prerequisites are now recorded as comments in `pom.xml` and in the `check-composition-sources`
failure message, not only here.

## 9. `package-lock.json`

Task 3.7 names a dirty `git status` after a clean build as the failure signal. It fired, and the
cause pre-dates this change: a plain `npm install` on npm 11.6.2 adds **11 `"peer": true` lines**
to the committed lock — metadata annotations, no `version` or `integrity` changes — from the
*inherited* `npm-install`, so no flag on the new execution could remove it. `--no-save` contributes
none of it.

That normalization is committed separately, so the "dirty lockfile = something happened" signal is
usable again for task 3.8 and CI. Confirmed idempotent afterwards.

Note: building from the `openam-ui` aggregator also rewrites
`openam-ui-js-sdk/package-lock.json` (entry removals, not just annotations). That module is
untouched by this task and the change was reverted; it is a pre-existing behaviour worth a
separate look.

## 10. Smoke check

Green: **23 passed** in 2.2m against the local API server, serving this phase-1 zip.

```
OPENAM_BASE_URL=http://127.0.0.1:8090/openam \
  npx playwright test xui/ --grep @local-server \
    --reporter=line,./common/backend-tag-reporter.mjs
```

The coverage footer reports `ran 5 of 14 spec files, 23 tests`, with the other 9 named and
`excluded by the tag filter` — full expected coverage for this lane, not a shortfall. The
`--reporter` must append `backend-tag-reporter.mjs`: a CLI `--reporter` *replaces* the config's
list, and without it nothing reports what did not run.

`OPENAM_BASE_URL` is required and defaults to the deployed instance
(`common/openam-commons.mjs`). Omitting it runs the lane against `openam.example.org:8080` and
every test fails with `ERR_CONNECTION_REFUSED` — which is what happened on the first attempt here.

Worth recording: `xui/xui-login.spec.mjs:123` passed. Tasks 2.16 and 2.17 measured it failing
roughly 1 run in 2 against this backend and 3 of 6 against the deployed instance, never
root-caused, so one green run is not evidence it is fixed.

**This is not the gate.** Task 3.8 is, it runs against the deployed instance, and design.md D13
says in as many words that the local backend never becomes the acceptance oracle.
