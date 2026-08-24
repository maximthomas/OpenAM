# NOTES-vite-build.md — what a Vite build of the XUI has to produce

Survey and spike for task 4.0. **Nothing was implemented.** No `pom.xml`, `package.json`,
`Gruntfile.js` or source file was modified; `git status` on this module shows only the two
artifacts this task produces, `PHASE1-TREE.md` and this file. The question of *when* the build
flips is not settled here — that is task 4.1's.

Companion artifact: [`PHASE1-TREE.md`](PHASE1-TREE.md) — the 652-file digest manifest of
`target/compiled`, captured while the Grunt pipeline is still live. It is the acceptance oracle
for tasks 4.4–4.8 and cannot be regenerated after 4.1.

Prior records this builds on and does not repeat:
[`NOTES-npm-commons.md`](NOTES-npm-commons.md) (how the commons packages arrive),
[`NOTES-commons-version-pin.md`](NOTES-commons-version-pin.md) (the version split).

---

## 0. Preconditions, as observed

| Check | Result |
|---|---|
| `target/compiled` exists and is populated | **652 files**, 203 directories, 7,217,101 bytes — matches the expected ~652 |
| `node_modules/@openidentityplatform/ui-commons` | present |
| `node_modules/@openidentityplatform/ui-user` | present |
| `NOTES-npm-commons.md` | present (14,483 bytes) |
| `NOTES-commons-version-pin.md` | present (13,463 bytes) |

All three preconditions pass. Both commons packages were re-verified present after the spike
(§9) — the spike never ran npm in this module.

---

## 1. The pipeline, stage by stage

`grunt prod` → `build`, registered in `Gruntfile.js:430-441` as:

```js
grunt.registerTask("build", [
    "check-composition-sources",
    "copy:compose",
    "eslint",
    "babel",
    "copy:libraries",
    "requirejs",
    "less",
    "replace",
    "copy:compiled",
    "copy:transpiled"
]);
```

Three directories carry the work: `target/XUI` (composition), `target/transpiled` (Babel output),
`target/compiled` (the shipped tree).

### 1.1 `check-composition-sources` — guard, no output

Consumes: the `buildCompositionDirs` list. Emits: nothing, or a fatal error naming the missing
directories. Added in task 3.7 because `grunt-contrib-copy` **ignores a missing `cwd` silently**.

**Vite equivalent: none, and it is still needed.** Vite has no composition step at all (§1.2), so
whatever replaces `copy:compose` needs the same guard. Vite's own failure mode here is *worse*
than Grunt's, not better — see §3.

### 1.2 `copy:compose` — the four composition source roots

Consumes six directories in this exact order, emits `target/XUI` (719 files):

```js
buildCompositionDirs = [
    "target/dependencies",                                // 1. maven-assembly-plugin, dir.xml
    "node_modules/@openidentityplatform/ui-commons/amd",  // 2. npm, installed by Maven
    "node_modules/@openidentityplatform/ui-commons/www",  //    "
    "node_modules/@openidentityplatform/ui-user/amd",     //    "
    "node_modules/@openidentityplatform/ui-user/www",     //    "
    "target/dependencies-expanded/forgerock-ui-user",     // 3. form2js ONLY
    "./src/main/js", "./src/main/resources"               // 4. LAST: AM overrides win
]
```

**Order is load-bearing and is the whole mechanism.** `grunt-contrib-copy` overwrites, so a later
source wins. Specifically:

- **`mavenProjectSource(".")` must be last.** Five files are AM overrides of commons-supplied
  files and only ship as AM's because of this — `locales/en/translation.json`,
  `templates/user/UserProfileTemplate.html`, and three self-service templates
  (`NOTES-npm-commons.md` §4 has the digests).
- **`target/dependencies-expanded/forgerock-ui-user` must compose after `target/dependencies`.**
  It holds exactly one file, `libs/form2js-2.0-769718a.js`, and `target/dependencies` supplies a
  *different build of the same library*. `NOTES-npm-commons.md` §3 records that the two differ by
  seven lines that rewrite bracketed form field names, and that **no count-based check can see the
  swap** — file counts, zip counts and libs counts are all identical either way.
- `ui-commons` and `ui-user` have **zero** overlapping paths, so their order relative to each
  other cannot matter (`NOTES-npm-commons.md` §5).
- `!package.json` is applied **only** to the four npm directories, dropping the CommonJS marker at
  each package's `amd/` root. Applying it globally would be a latent trap for a future source that
  legitimately ships one.

**Vite equivalent: NONE.** This is the largest gap in the whole migration. Vite has `publicDir`,
which is *one* directory copied verbatim to the output root — it is not a layered composition with
last-wins overwrite, and it does not participate in the module graph. Reproducing this needs
either a copy plugin (`vite-plugin-static-copy`) configured with the same six roots in the same
order, or a build-time script that composes into a staging directory before Vite runs. Either way
**the ordering and the override semantics have to be reproduced explicitly**, and the form2js case
above is the proof that getting it wrong is silent.

### 1.3 `eslint` — lint, no output

Consumes `src/main/js/**/*.{js,jsm,jsx}` (excluding `libs/`) and `src/test/js/**/*.js`. Emits
nothing but a report, via `eslint-formatter-warning-summary`. Config: `.eslintrc.js`, extending
`eslint-config-forgerock` (a `file:` tarball from `../node_packages`).

Note it lints **`src/main/js` directly, not the composition directory** — so it lints AM's own
source only, never the composed commons tree.

**Vite equivalent: none, and none is needed.** Vite does not lint. This becomes either a separate
`npm run lint` script or `vite-plugin-eslint`. It is not on the build's critical path — nothing
downstream consumes its output — so it can move independently of everything else here.

### 1.4 `babel` — two targets

- **`babel:transpileJS`**: consumes `target/XUI/**/*.js` except `libs/**`, emits
  `target/transpiled` (same paths). Presets `@babel/preset-env` (targets
  `> 0.2%, not dead, last 2 versions`) and `@babel/preset-react`, plus
  `@babel/plugin-transform-classes` in loose mode. **AMD `define()` calls pass through
  untouched** — no module transform is applied to `.js`.
- **`babel:transpileJSM`**: consumes `target/XUI/**/*.{jsm,jsx}`, emits `target/transpiled` with
  the extension rewritten to `.js`, and adds **`@babel/plugin-transform-modules-amd`**. This is
  the step that converts the 46 ESM source files into AMD so RequireJS can load them.

That second target is the important one: **the repo already contains 46 ES-module files**
(`.jsm`/`.jsx`), all using `import`/`export`, and the build converts them *to* AMD. The migration
runs this conversion in the opposite direction for the other 207.

**Vite equivalent: partial.** Vite/esbuild handles the ES2015+ and JSX transforms natively via
`esbuild` and `@vitejs/plugin-react`, and `build.target` replaces the browserslist query. But the
`transform-modules-amd` step has no equivalent and must simply **disappear** — Vite consumes ESM
and emits ESM; converting to AMD would defeat the exercise. The `.jsm` extension is not one Vite
recognises by default and would need `resolve.extensions` or a rename.

### 1.5 `copy:libraries`

Consumes `target/XUI/libs/**/*.js`, emits `target/transpiled/libs`. Its only job is to put the
untranspiled vendor libraries where `requirejs:compile` can resolve them, since Babel skipped
them. 50 files.

**Vite equivalent: none as such.** These are the `require.config.paths` targets — vendor libraries
in AMD/UMD/global form. Under Vite they either become real npm dependencies resolved through the
module graph, or stay as copied static files reached by `resolve.alias`. That decision is
task 4.6's, not this one's, but note `libs/` is 50 files / 1.97 MB and is currently **never
processed by any tool** — it is copied twice and left alone.

### 1.6 `requirejs:compile` — the r.js bundle, and it includes only `"main"`

```js
options: {
    baseUrl: transpiledDirectory,
    mainConfigFile: transpiledDirectory + "/main.js",
    out: compiledDirectory + "/main.js",
    include: ["main"],
    preserveLicenseComments: false,
    generateSourceMaps: true,
    optimize: "uglify2",
    excludeShallow: ["config/AppConfiguration", "config/ThemeConfiguration"]
}
```

Consumes `target/transpiled`, emits **two files only**: `target/compiled/main.js` (543,480 bytes)
and `target/compiled/main.js.map` (1,590,337 bytes).

**`include: ["main"]` is the single most consequential line in the build.** It follows only the
static dependency graph reachable from `main.js`, which reaches **90 named module ids**. Measured:

| | Count |
|---|---:|
| Named `define("id",…)` inside `main.js` | 90 |
| …also shipped as a standalone `.js` file (**double-shipped**) | 76 |
| …present only inside the bundle (vendor `paths` aliases) | 14 |
| Shipped standalone `.js` **not** in the bundle | 308 |
| Total `.js` shipped | 384 |

So the shipped tree is **not "a bundle plus assets"**. It is a partial bundle of the eager startup
path, sitting on top of a *complete unbundled AMD module tree* — 308 modules that RequireJS fetches
by path at runtime, on demand. 76 modules ship **twice**, once inside `main.js` and once as a
standalone file.

`excludeShallow` keeps `config/AppConfiguration` and `config/ThemeConfiguration` out of the bundle
deliberately, "so that the UI can be customized without having to repackage it". Verified: both
are absent from `main.js` and present as standalone files.

**Vite equivalent: `build.rollupOptions`, but the shapes do not match.** Rollup bundles the whole
reachable graph and code-splits into *hashed* chunks. It has no notion of "bundle this entry but
also emit every module as an individually addressable file at a stable path". Reproducing the
current shape would need either `preserveModules: true` (which emits the tree but changes the
bundle) or a second build pass. And per design.md D1/D5, `AppConfiguration.js` **names modules by
string** and operators may add their own modules to a deployed tree
(`e2e/xui/xui-operator-module.spec.mjs`), so **the set of reachable module ids is not closed at
build time** — which is precisely what a bundler assumes.

### 1.7 `less` — the three LESS files

Consumes three files from `target/XUI/css/`, emits three into `target/compiled/css/`:

| Source | Output | Size |
|---|---|---:|
| `structure.less` | `structure.css` | 89,221 |
| `theme.less` | `theme.css` | 10,690 |
| `styles-admin.less` | `styles-admin.css` | 158,377 |

Options: `compress: true`, `less-plugin-clean-css`, **`relativeUrls: true`**.

Two things matter. First, there is a **fourth** `.less` file in the composition
(`css/backgrid.min-0.3.5.less`) that is *not* an entry — it is `@import`ed. Second, the LESS runs
against the **composition** directory, so `@import`s resolve across all six composition sources —
a theme's LESS can import a commons variable file. `relativeUrls: true` is what keeps `url()`
references correct after that rewriting.

**Vite equivalent: native.** Vite compiles LESS out of the box given the `less` package, via
`css.preprocessorOptions.less`. Minification is `build.cssMinify`. The catch is that Vite compiles
CSS **as part of the module graph** — a stylesheet normally gets pulled in by an `import` from JS
and emitted as a hashed asset. Here the three CSS files are referenced **by path** from templates
and from `ThemeConfiguration`, not imported. They need stable names and must be emitted whether or
not anything imports them, which means treating them as additional Rollup inputs plus
`assetFileNames` pinning, or compiling them outside the Vite graph.

### 1.8 `replace:buildNumber` — the `${version}` text replace

Consumes `target/XUI/index.html`, emits `target/compiled/index.html`. Replaces the literal string
`${version}` with `grunt.option("target-version") || "dev"`. The pom passes
`--target-version=${project.version}`, so a Maven build stamps `16.2.0-SNAPSHOT` and a bare
`npm run build:production` stamps `dev`.

The target is RequireJS's cache-busting query parameter:

```html
var require = {
    urlArgs : "v=16.2.0-SNAPSHOT",
    deps : ['main']
};
```

`urlArgs` appends `?v=…` to **every** module RequireJS fetches. That is the entire cache-busting
mechanism for all 308 unbundled modules and every runtime-fetched template — one string, applied
by the loader.

**Vite equivalent: none that is equivalent.** Vite's cache-busting is content hashing in
filenames, which applies only to files in the module graph. The 308 unbundled modules, the 229
templates and the locale JSON are not in the graph and get no hash. design.md D3/D4 already record
that static assets need the build version appended as a query parameter via a `resolveAssetUrl`
helper — this is the requirement that creates. `define()` of the version is
`import.meta.env`/`define:` in Vite config, but **the helper that consumes it does not exist yet**.
`e2e/xui/NOTES-urlargs.md` and `e2e/xui/xui-cache-busting.spec.mjs` are the existing record and
test of this behaviour.

### 1.9 The two copy steps into `target/compiled`

Both run **last**, after r.js, and both are ordinary copies.

- **`copy:compiled`** — consumes `target/XUI`, emits the static assets, selected by
  `nonCompiledFiles`, explicitly excluding `!main.js` (r.js writes it) and `!index.html`
  (grunt-text-replace writes it):

  ```js
  nonCompiledFiles = [
      "**/*.html", "**/*.ico", "**/*.json", "**/*.png", "**/*.eot",
      "**/*.svg", "**/*.woff", "**/*.woff2", "**/*.otf",
      "css/bootstrap-3.3.5-custom.css",
      "themes/**/*.*"
  ]
  ```

  **268 files**: 229 `.html`, 20 `.png`, 6 `.json`, fonts, the favicon, one vendor CSS, the theme
  tree. Note `themes/**/*.*` is a wholesale copy — themes are not filtered by extension.

- **`copy:transpiled`** — consumes `target/transpiled/**/*.js` except `main.js`, emits into
  `target/compiled`. **This is the step that ships the 384 − 1 = 383 individual JS files**,
  including the 308 not in the bundle, the 76 double-shipped ones, `main-authorize.js`,
  `main-device.js` and all 50 of `libs/`.

**Vite equivalent: `publicDir`, partially.** `publicDir` copies one directory verbatim to the
output root without processing — right semantics, wrong cardinality (one source, not six layered
ones). And `copy:transpiled` has no equivalent at all, because emitting every module as a
standalone addressable file is not a thing Rollup does alongside bundling.

### 1.10 Summary table

| Grunt task | Consumes | Emits | Vite equivalent |
|---|---|---|---|
| `check-composition-sources` | the dir list | fatal or nothing | **none** — still needed, more so |
| `copy:compose` | 6 roots, ordered | `target/XUI` (719) | **NONE** — the biggest gap |
| `eslint` | `src/main/js`, `src/test/js` | report | none needed; separate script or plugin |
| `babel:transpileJS` | `XUI/**/*.js` − libs | `transpiled` | esbuild / `build.target` (AMD passes through today) |
| `babel:transpileJSM` | `XUI/**/*.{jsm,jsx}` | `transpiled/*.js` (AMD) | must **disappear**; JSX via plugin-react |
| `copy:libraries` | `XUI/libs/**/*.js` | `transpiled/libs` | none — 4.6's question |
| `requirejs:compile` | `transpiled` | `compiled/main.js` + `.map` | `rollupOptions`, **shape does not match** |
| `less` | 3 `.less` | 3 `.css` | native, but needs stable names |
| `replace:buildNumber` | `XUI/index.html` | `compiled/index.html` | **none** — needs D3's `resolveAssetUrl` |
| `copy:compiled` | `XUI` static | 268 files | `publicDir`, partially |
| `copy:transpiled` | `transpiled/**/*.js` | 383 files | **none** |

---

## 2. What `target/compiled` actually contains

Full per-file manifest with md5 and size: **[`PHASE1-TREE.md`](PHASE1-TREE.md)**. Summary:

- **652 files**, 7,217,101 bytes, 11 top-level directories plus 8 root files.
- **384 JavaScript** files — but see §1.6: only 90 module ids are in the bundle, 308 `.js` files
  are unbundled and addressed by path at runtime, 76 ship twice.
- **268 static assets** that must be copied verbatim — 229 `.html` templates and partials fetched
  at runtime by path, 20 `.png`, 6 `.json`, 6 `.css`, 4 font files, 1 `.ico`, 1 `.svg`.

| Path | Files | `.js` | Bytes |
|---|---:|---:|---:|
| `(root)` | 8 | 3 | 2,174,459 |
| `components/` | 5 | 5 | 10,224 |
| `config/` | 17 | 17 | 92,219 |
| `css/` | 10 | 0 | 1,121,945 |
| `images/` | 19 | 0 | 99,234 |
| `libs/` | 50 | 50 | 1,970,218 |
| `locales/` | 3 | 0 | 68,657 |
| `org/` | 303 | 303 | 1,311,214 |
| `partials/` | 29 | 0 | 14,488 |
| `store/` | 6 | 6 | 8,861 |
| `templates/` | 198 | 0 | 202,513 |
| `themes/` | 4 | 0 | 143,069 |

`zip.xml` maps `target/compiled` to the archive root with `<baseDirectory>/</baseDirectory>`, so
every path in the manifest is also its path inside `-www.zip` **and** under `/openam/XUI/` on a
deployed instance. That is why the manifest is a usable oracle at all.

**Three entry points at the root with stable, unhashed names**: `main.js`, `main-authorize.js`,
`main-device.js`. The latter two are loaded by path from AM's own OAuth2 consent and device-flow
pages — they are not reachable from `main.js` and r.js never sees them; they arrive through
`copy:transpiled`. A Vite default of `assets/main-authorize-<hash>.js` breaks that contract.

---

## 3. Can Vite build this source today? **No.**

### The counts, verified

| Measure | Count |
|---|---:|
| `.js` files under `src/main/js` | **213** |
| …opening with `define(` at column 0 | **203** |
| …matching `^\s*define\(` (indented included) | **207** |
| …using ESM `import`/`export` | **0** |
| `.jsm` + `.jsx` files | **46** |
| …of those using ESM `import`/`export` | **46** |

Confirmed exactly as stated in the task. The 6 `.js` files that are neither: `main-authorize.js`,
`main-device.js`, and four vendor shims under `libs/`.

Worth noting the corollary — **the 46 `.jsm`/`.jsx` files are already ESM**, and the build
currently converts them *down* to AMD (§1.4).

### The spike, and what actually happened

Vite is **not** installed in this module, and installing it here was not an option: a bare
`npm install` prunes the two commons packages, which are installed `--no-save`. So the spike ran
in an **isolated scratchpad npm project** — `vite@5.4.21`, node `v22.20.0` — with source files
copied in. Nothing was installed into, or written to, `openam-ui-ria`. The spike directory has
been deleted.

Five cases, real output:

**Case 1 — `define({...})` object form** (`SingleRouteRouter.js`):

```
✓ 1 modules transformed.
dist-1/assets/case1-define-object-CoegtdIo.js  0.03 kB
✓ built in 87ms
```

Exit 0. Output, in full:

```js
define({
  currentRoute: null
});
```

**Case 2 — `define([deps], factory)` form** (`deprecatedWarning.js`): exit 0, output is the input
reformatted, `define` still there.

**Case 3 — the real `main.js`** — 51 module paths, 38 `paths` aliases, 29 `shim` entries, and a
`require([...])` of 12 startup modules:

```
✓ 1 modules transformed.
dist-3/assets/case3-main-Sw9n2xGZ.js  5.63 kB
✓ built in 83ms
```

Exit 0. The output is the **entire input, verbatim**, reformatted. Zero of the 12 entry
dependencies were followed. `require.config({...})` is emitted as a plain function call.

**Case 4 — a `.jsm` ESM file with bare RequireJS-style ids** (`showConfirmationBeforeAction.jsm`):

```
✓ 1 modules transformed.
x Build failed in 101ms
error during build:
[vite]: Rollup failed to resolve import "i18next" from ".../case4-esm-bareid.js".
This is most likely unintended because it can break your application at runtime.
If you do want to externalize this module explicitly add it to
`build.rollupOptions.external`
```

Non-zero exit. **This is the correct behaviour** and is what `resolve.alias` (design.md D2) exists
to fix.

**Case 5 — the real `index.html` as a Vite HTML entry**:

```
<script src="libs/base64-1.0.0-min.js"> in "/index.html" can't be bundled without type="module" attribute
<script src="libs/requirejs-2.3.7-min.js"> in "/index.html" can't be bundled without type="module" attribute
✓ 1 modules transformed.
dist-5/index.html  0.98 kB
✓ built in 80ms
```

Exit 0. **One file emitted**: `index.html`, copied verbatim, with `${version}` **unreplaced**. Zero
JavaScript. The entire application is invisible to Vite, because `index.html` has no
`<script type="module">` — it bootstraps RequireJS with a plain `<script src>`.

### The finding

**A working bundle is not reachable before the AMD → ESM conversion in group 5 lands.** That was
the expected answer. But the *manner* of the failure is the part that changes how task 4.1 should
be done, and it is the opposite of what "Vite consumes ES modules" suggests:

> **Vite does not reject AMD. It accepts it, exits 0, and produces a bundle that does nothing.**

`define` and `require` are, to Vite, undeclared free globals. It parses the file as an ES module,
finds no `import` statements, concludes the module graph has exactly one node, reports
"✓ 1 modules transformed", and emits the input. There is no warning about `define`. The build is
green.

Consequences that task 4.1 has to plan around:

- **Exit status is not a signal during the transition.** A partially converted tree will build
  green while silently shipping unbundled, non-functioning AMD. This is the same failure class as
  `grunt-contrib-copy`'s silent missing `cwd` (§1.1) — and this build has already been bitten by
  that once.
- **The acceptance check must be the output tree, not the exit code.** Which is exactly what
  `PHASE1-TREE.md` is for.
- **ESM failures are loud, AMD failures are silent.** Case 4 versus cases 1–3, 5. So converted
  files fail usefully and unconverted ones do not — meaning progress through group 5 cannot be
  measured by "does the build pass".
- A useful cheap guard for 4.1: fail the build if any emitted chunk still contains a top-level
  `define(` or `require.config(`.

---

## 4. The script surface

### The governing requirement

`openspec/changes/modernize-openam-ui-build/specs/ui-build-and-packaging/spec.md:117-129`:

> ### Requirement: Verification commands
>
> The UI module SHALL expose commands to run its unit tests and its end-to-end tests. The
> end-to-end suite SHALL run against a deployed instance through the browser, so that it verifies
> behaviour independently of which build pipeline produced the instance.
>
> #### Scenario: Unit tests run from the module
>
> - **WHEN** the unit test command is run in the UI module
> - **THEN** the unit suite executes and reports pass or failure
>
> #### Scenario: End-to-end suite runs against a deployed instance
>
> - **WHEN** the end-to-end command is run against a deployed instance
> - **THEN** the suite drives the deployed UI through a browser and reports pass or failure

The requirement is **tool-agnostic**. It names no script names, no `test:unit`, and not Vite. It
constrains only that *a* unit-test command and *an* e2e command exist. `test:unit` appears nowhere
in the openspec store; the name is unconstrained.

The adjacent requirement at lines 103–115, *Development server with live reload*, additionally
requires the dev server to serve against a running AM, apply source changes without
package-and-deploy, and **still serve templates by path including theme overrides**.

### Current scripts

```json
"start":            "grunt",
"build:production": "cross-env NODE_ENV=production grunt prod --verbose",
"test":             "grunt karma:build",
"test:e2e":         "npm --prefix ../../e2e run test:xui --"
```

### Proposed

| Script | Command | Notes |
|---|---|---|
| `build:production` | `vite build` | **Keep the name.** The pom calls it, and so does `.github/workflows/xui-local-server.yml`'s cache key rationale. Renaming it means editing the pom for no benefit. The `-- --target-version=X` argument has no Vite equivalent and must become an env var or a `--mode`/`define` — see the caveat below. |
| `dev` | `vite` | New. Task 4.10 builds the backend half. `start` currently means `grunt` (= watch+deploy); repointing `start` at `vite` is reasonable but `dev` is the conventional name and avoids overloading a name whose meaning changes. |
| `test:unit` | `vitest run` | New, per design.md D12 (Karma/RequireJS/Squire → Vitest). Satisfies "a command for unit tests". |
| `test` | `npm run test:unit` | **Keep `test` as the pom's entry point.** The pom's `npm-test` execution calls `run test`; leaving `test` as the alias means that execution needs no edit. |
| `test:e2e` | `npm --prefix ../../e2e run test:xui --` | **Already exists, unchanged.** Delegates to `e2e/`. Satisfies the second scenario: `test:xui` targets the deployed instance by default (`OPENAM_BASE_URL` defaults to `http://openam.example.org:8080/openam`). |
| `lint` | `eslint src/main/js src/test/js` | New. `eslint` is currently a Grunt task with no npm entry point; deleting `Gruntfile.js` removes the only way to run it. |

Only two Maven executions call npm scripts, and **with these names neither changes**: `npm-build`
runs `run build:production`, `npm-test` runs `run test`. That is deliberate — it confines the pom
edit to what actually has to change (§5).

**Caveat on `--target-version`.** The pom passes
`run build:production -- --target-version=${project.version}`. Grunt reads it via
`grunt.option("target-version")`. Vite has no equivalent CLI option parsing, so this must become
either an environment variable read in `vite.config.js` (`process.env.TARGET_VERSION`) or a
`--mode`. If it becomes an env var, **the pom's `<arguments>` for `npm-build` does change** — it
would lose the `-- --target-version=…` suffix and gain an `<environmentVariables>` block. That is
the one place my "no pom edit" claim above has a genuine dependency on an unmade decision. Flagged
rather than decided.

---

## 5. The pom edit, written out

### 5.1 The ordering constraint — verbatim

`pom.xml:443-470`, the comment above `npm-install-commons`. Quoted in full because the second
paragraph is the constraint:

> Installs the two commons packages out of band. They are deliberately NOT
> in package.json: npm pins file: tarballs by content hash, and a
> 3.2.0-SNAPSHOT tarball is one version string over changing bytes, so the
> integrity would go stale on every commons rebuild - `npm ci` hard-fails
> and `npm install` rewrites the lockfile.
>
> ORDER IS LOAD-BEARING AND IS NOT WHAT THIS FILE SHOWS. This execution is
> declared first but must RUN LAST, after install-node-and-npm and
> npm-install. It does, because Maven's pluginManagement merge injects the
> executions inherited from openam-ui/pom.xml ahead of module-declared
> ones. Move npm-install into this pom, or reorder it, and the order flips:
> a plain `npm install` reconciles node_modules against package.json and
> prunes both packages ("removed 50 packages"). Grunt's copy:compose then
> drops the missing source directories SILENTLY and the build fails much
> later in requirejs:compile for an unrelated-looking reason. The guard in
> Gruntfile.js turns that into a named failure; do not rely on it instead
> of preserving the order.
>
> The legacy-peer-deps flag is required, not cosmetic. Both packages declare
> their runtime libraries as peerDependencies, and npm 7+ auto-installs
> those: without the flag the build resolves 50 unpinned packages (react,
> backbone, handlebars, jquery, ...) from the public registry on every run,
> recorded in neither package.json nor package-lock.json because the
> no-save flag suppresses exactly that record. AM already ships these
> libraries from the Maven commons.ui.libs artifacts, so they would be a
> duplicate, unaudited and network-dependent supply chain. With the flag,
> npm adds 2 packages and stays offline. Do NOT substitute the omit=peer
> flag: ui-user declares ui-commons itself as an optional peer, so omitting
> peers silently drops ui-commons.

The effective order at `initialize` is:

```
dependency:copy  →  install-node-and-npm  →  npm-install  →  npm-install-commons
                    └── inherited from openam-ui/pom.xml ──┘   └─ declared here ─┘
```

### 5.2 `openam-ui/pom.xml` — **NO CHANGE**

The `pluginManagement` block (lines 585–619) declares `install-node-and-npm` (node `v22.21.1`, npm
`11.6.2`) and `npm-install` (`install`). Neither is Grunt-specific: they install a toolchain and
run `npm install`. **Both are needed identically by a Vite build.**

There is no Grunt reference anywhere in `openam-ui/pom.xml` — verified by grep. The task brief
anticipates "two poms"; on the evidence, **the parent pom needs no edit at all**, and editing it
is the specific action the comment above warns against.

### 5.3 `openam-ui-ria/pom.xml` — the minimal edit

With the script names in §4, **`npm-install-commons` and `npm-test` are unchanged**, and only
`npm-build` changes, and only if `--target-version` becomes an env var.

Current (`pom.xml:485-494`):

```xml
<execution>
    <id>npm-build</id>
    <goals>
        <goal>npm</goal>
    </goals>
    <phase>compile</phase>
    <configuration>
        <arguments>run build:production -- --target-version=${project.version}</arguments>
    </configuration>
</execution>
```

Proposed:

```xml
<execution>
    <id>npm-build</id>
    <goals>
        <goal>npm</goal>
    </goals>
    <phase>compile</phase>
    <configuration>
        <arguments>run build:production</arguments>
        <environmentVariables>
            <TARGET_VERSION>${project.version}</TARGET_VERSION>
        </environmentVariables>
    </configuration>
</execution>
```

`vite.config.js` then reads `process.env.TARGET_VERSION`, defaulting to `"dev"` to preserve the
current `grunt.option("target-version") || "dev"` behaviour.

`npm-install-commons` (`pom.xml:474-483`) and `npm-test` (`pom.xml:495-504`) are **quoted here
unchanged** to be explicit that the proposal does not touch them:

```xml
<execution>
    <id>npm-install-commons</id>
    <goals>
        <goal>npm</goal>
    </goals>
    <phase>initialize</phase>
    <configuration>
        <arguments>install ${project.build.directory}/npm/ui-commons.tgz ${project.build.directory}/npm/ui-user.tgz --no-save --legacy-peer-deps</arguments>
    </configuration>
</execution>
```

```xml
<execution>
    <id>npm-test</id>
    <goals>
        <goal>npm</goal>
    </goals>
    <phase>test</phase>
    <configuration>
        <arguments>run test</arguments>
    </configuration>
</execution>
```

### 5.4 Does this preserve the order? **Yes.**

How I checked, not how I reasoned:

1. The constraint is that `npm-install-commons` runs **after** the inherited `install-node-and-npm`
   and `npm-install`. That ordering is produced by Maven's pluginManagement merge injecting
   inherited executions ahead of module-declared ones.
2. The proposed edit **does not add, remove, move or reorder any execution**. It changes the
   `<configuration>` body of one execution — `npm-build` — and nothing else.
3. `npm-build` is bound to `compile`; `npm-install-commons`, `install-node-and-npm` and
   `npm-install` are all bound to `initialize`. `compile` runs after `initialize` in the Maven
   lifecycle, so `npm-build` is not part of the ordered set at all.
4. **No execution is moved into `openam-ui-ria/pom.xml` from the parent** — which is the exact
   action the comment names as flipping the order ("Move npm-install into this pom, or reorder it,
   and the order flips").
5. `openam-ui/pom.xml` is not edited, so the inherited set is byte-identical.

**The order is preserved.** No LOUD warning is required for this proposal.

**The failure mode to watch for in 4.1**, stated loudly because it is the one this build has
already hit: *if* task 4.1 decides to add a Vite-specific npm execution at `initialize`, or to move
`npm-install` down into this pom to add a flag, **the order flips and both commons packages are
pruned**. With Grunt, `check-composition-sources` catches that with a named failure. **With Vite
there is no such guard**, and per §3 the build would go green while emitting nothing. Any new
`initialize`-phase npm execution must be declared so that it still runs after
`npm-install-commons`, and 4.1 should port `check-composition-sources` into the Vite config before
removing `Gruntfile.js`.

---

## 6. The output directory — options and consequences, not a decision

Two consumers bind to `target/compiled` today:

- `src/main/assembly/zip.xml:36` — `<directory>target/compiled</directory>`, mapped to the archive
  root with `<baseDirectory>/</baseDirectory>`, producing `openam-ui-ria-<version>-www.zip`.
- `karma.conf.js:13` — `{ pattern: "target/compiled/**/*.js", included: false }`, alongside
  `target/test-classes` at lines 11, 12, 20, 21.

And two more, found by grep and easy to miss:

- `e2e/local/server-lib/options.mjs:78-79` and `xui-source.mjs:34` — the local API server accepts
  `target/compiled` as a directory input, and explicitly documents that `target/XUI` does **not**
  work ("it is the pre-filter tree").
- `e2e/local/xui-deploy.sh` — accepts a directory, and its usage text already names "a Vite
  `outDir`".

### Option A — `outDir: "target/compiled"`

- `zip.xml` needs **no edit**; packaging keeps working unchanged.
- `xui-deploy.sh` and `npm run local-server` keep working with no argument, since both default to
  the `-www.zip`.
- `PHASE1-TREE.md` compares in place: build with Grunt, snapshot, build with Vite, diff the same
  path.
- **But**: Vite's `emptyOutDir` would delete a directory Maven's lifecycle also writes into, and
  during any transition period the two builds overwrite each other with no way to hold both for
  comparison. It also puts a build output where a reader reasonably expects Grunt's.
- **And**: `karma.conf.js` keeps resolving — which is a *hazard*, not a benefit. The Karma files
  globs would silently match a Vite tree of a different shape and the suite would pass or fail for
  reasons unrelated to the code. Task 9.1 deletes `karma.conf.js`; until then this coupling is
  live.

### Option B — a new directory, e.g. `outDir: "target/vite"` or `target/dist`

- Both builds can produce output **simultaneously**, which is what makes the `PHASE1-TREE.md`
  comparison a diff rather than a sequence of snapshots. For a migration whose acceptance test is
  "same tree, different pipeline", this is a real advantage.
- `karma.conf.js` keeps pointing at the Grunt tree, so the existing suite stays meaningful for
  exactly as long as the Grunt build still runs, and stops resolving cleanly the moment it does not
  — a loud failure rather than a quiet one.
- **But**: `zip.xml:36` must change (one `<directory>` element), and the change is a one-way flip —
  after it, the zip contains the Vite output and the Grunt output is no longer packaged.
- Task 4.7's prompt already anticipates exactly this: "If 4.1 chose `target/compiled` as Vite's
  `outDir`, this descriptor needs no edit and the whole task is the confirmation. If 4.1 chose a
  different `outDir`, one `<directory>` element changes."

### Option C — `outDir` configurable, defaulting to `target/compiled`

- Env var or mode selects the directory; CI and the comparison tasks override it.
- Gets A's zero-edit packaging and B's side-by-side comparison.
- **But**: adds a build input that can differ between a developer's machine and CI, which is the
  class of thing that makes "it works locally" reports unfalsifiable. It also means `zip.xml` packs
  a path that is only correct for the default.

### The trade-off, stated plainly

**A minimises edits; B maximises comparability.** They trade against each other on exactly the axis
this migration is graded on: A makes the switch cheap but makes the Grunt-vs-Vite diff a
before/after sequence that cannot be re-run once the pipeline flips, while B costs one `zip.xml`
element and keeps both trees on disk at once, which is what `PHASE1-TREE.md` was captured to
support. C is a compromise that adds a configuration surface.

**Not decided here.** This is task 4.1's call, and the prompt for 4.7 is written to accept either.

---

## 7. What the dev server needs

The constraint is design.md D14, at
`openspec/changes/modernize-openam-ui-build/design.md:208-214`:

> ### D14 — One origin, one path prefix: the server serves the XUI too
>
> The local server serves the XUI tree at `/{context}/XUI/` and the REST API at `/{context}/json/`
> on a single origin, defaulting to the `openam` context the container instance uses.
>
> *Why:* forced by the Context finding above. `Constants.host` is `""` and `Constants.context`
> comes from `location.pathname`, so the XUI has no configurable backend URL — it asks whatever
> origin served it, under the path it was served from. A backend on a second port would need a UI
> change to reach, which would break the "one build, either backend" property that makes the
> comparison worth anything. Same-origin also gets session-cookie behaviour right for free.
>
> It serves the XUI two ways: a built tree (a `www` zip or a Vite `outDir`, the same inputs
> `xui-deploy.sh` takes), or a proxy to the Vite dev server for HMR once phase 2 lands. Both
> preserve the path prefix.

`e2e/local/README.md` states the same constraint from the runtime side: "Both surfaces sit under
one context because the XUI has no configurable backend URL: `Constants.host` is `""` and the
context is derived from `location.pathname`, so it asks whatever origin served it, under the path
it was served from. That is what lets one build run against either backend unmodified."

### What has to be recorded

```js
// vite.config.js — the constraint, not a proposed implementation
export default defineConfig({
    base: "/openam/XUI/",          // must match the deployed path prefix exactly
    server: {
        proxy: {
            "/openam/json":       { target: "http://127.0.0.1:8090", changeOrigin: false },
            "/openam/oauth2":     { target: "http://127.0.0.1:8090", changeOrigin: false },
            "/openam/XUI/config": { target: "http://127.0.0.1:8090", changeOrigin: false }
        }
    }
});
```

- **`base` must be `/openam/XUI/`** and must end in a slash. It is not cosmetic: it is what every
  generated asset URL is prefixed with, and `Constants.context` is derived from
  `location.pathname`, so a different prefix changes which REST paths the UI computes. Note the
  context is configurable on the local server (`--context`, `OPENAM_LOCAL_CONTEXT`), so `base`
  should be derived from the same value rather than hard-coded, or the two can disagree.
- **`changeOrigin` must be false** — the session cookie is host-only (`e2e/local/NOTES-auth.md`),
  and rewriting the Host header breaks it.
- **The REST prefixes must not be swallowed by `base`.** `/openam/json/` sits *beside*
  `/openam/XUI/`, both under `/openam/`, so the proxy table has to be precise enough not to
  intercept XUI asset requests, and Vite's dev server has to not treat `/openam/json/…` as a
  missing static file.
- **Task 4.10 builds the other half** — the D14 note says the local server proxies
  `/{context}/XUI/` *to* the Vite dev server. So the direction may be the reverse of the sketch
  above: one server in front, Vite behind. That is 4.10's decision; recorded here, not made.
- **HMR is a WebSocket**, and `e2e/local/server.mjs` is a `node:http` server that does not proxy
  one by default. Task 4.10's prompt already names this.
- **The dev server must still serve the 229 templates and the locale JSON by path**, per the
  *Development server with live reload* requirement — they are not in the module graph, so Vite
  will not serve them unless they are in `publicDir` or a plugin serves them.

---

## 8. What else depends on Grunt

Grepped the whole OpenAM checkout (excluding `node_modules` and `target`) for `grunt`,
`target/XUI`, `target/transpiled`, `target/compiled` and `target/test-classes`.

### Blocking — must change when the pipeline flips

| File | Line | Reference |
|---|---:|---|
| `openam-ui/openam-ui-ria/package.json` | 11 | `"build:production": "cross-env NODE_ENV=production grunt prod --verbose"` |
| `openam-ui/openam-ui-ria/package.json` | 12 | `"test": "grunt karma:build"` |
| `openam-ui/openam-ui-ria/package.json` | 10 | `"start": "grunt"` |
| `openam-ui/openam-ui-ria/package.json` | 27–38 | 12 `grunt*` devDependencies: `grunt`, `grunt-babel`, `grunt-cli`, `grunt-contrib-copy`, `grunt-contrib-less`, `grunt-contrib-requirejs`, `grunt-contrib-watch`, `grunt-eslint`, `grunt-karma`, `grunt-newer`, `grunt-sync`, `grunt-text-replace` |
| `openam-ui/openam-ui-ria/package.json` | 41–45, 50 | `karma`, `karma-babel-preprocessor`, `karma-chrome-launcher`, `karma-mocha`, `karma-requirejs`, `requirejs` — retire with `karma.conf.js` in task 9.1 |
| `openam-ui/openam-ui-ria/package.json` | 66 | the `grunt` block inside `overrides` (pins `js-yaml`) |
| `openam-ui/openam-ui-ria/src/main/assembly/zip.xml` | 36 | `<directory>target/compiled</directory>` — **only if `outDir` changes** (§6) |
| `openam-ui/openam-ui-ria/karma.conf.js` | 11, 12, 13, 20, 21 | binds to `target/test-classes/**` and `target/compiled/**/*.js`; also `frameworks: ["mocha", "requirejs"]` at line 9. Task 9.1 deletes this file. |

### CI

| File | Line | Reference |
|---|---:|---|
| `.github/workflows/xui-local-server.yml` | 130 | cache key `hashFiles(…, 'openam-ui/openam-ui-ria/Gruntfile.js', …)` — **stale the moment `Gruntfile.js` is deleted**; `hashFiles` on a missing path contributes nothing rather than failing, so the cache key silently weakens. Must gain `vite.config.js`. |
| `.github/workflows/xui-local-server.yml` | 129 | artifact path `openam-ui/openam-ui-ria/target/openam-ui-ria-*-www.zip` — survives if `zip.xml` keeps producing the same name |
| `.github/workflows/xui-local-server.yml` | 117 | comment: "`openam-ui-ria/package.json` is in it because npm lock files do not record `scripts`" |
| `.github/workflows/xui-local-server.yml` | 171, 185 | "No `clean`, and not by accident"; `mvn … -pl openam-ui/openam-ui-ria -am -DskipTests package` |
| `.github/workflows/xui-e2e.yml` | 28 | path filter `openam-ui/**` — unaffected |
| `.github/workflows/codeql.yml` | 95 | excludes `openam-ui/openam-ui-ria/src/main/js/libs/**` — unaffected |
| `.github/workflows/deploy.yml` | 65 | excludes the UI modules from deploy — unaffected |

### e2e harness

| File | Line | Reference |
|---|---:|---|
| `e2e/local/server-lib/options.mjs` | 78–79 | accepts `target/compiled` as a directory input; documents that `target/XUI` does **not** work |
| `e2e/local/server-lib/xui-source.mjs` | 34 | `zip.xml` maps `target/compiled` to `/`, "so its entries map straight" |
| `e2e/local/server-lib/static-tree.mjs` | 189 | "`target/compiled` contains no links today" |
| `e2e/local/README.md` | 157 | "`npm run build:production` alone cannot produce it. Grunt composes `target/XUI` out of two directories Maven writes at `process-resources`" |
| `e2e/local/NOTES-xui-build.md` | 51, 86, 89, 94, 102, 105, 132, 136 | the whole composition and `target/compiled` description |
| `e2e/xui/BASELINE.md` | 91, 106, 108, 111 | records the Grunt task chain and the 719/50 file shape |
| `e2e/xui/PHASE1-BASELINE.md` | 84, 113 | `cross-env NODE_ENV=production grunt prod` |
| `e2e/xui/NOTES-urlargs.md` | 235, 248 | `Gruntfile.js:224-238` `replace:buildNumber`, `${version}` → `v=16.2.0-SNAPSHOT` |

Docs, not code — but `NOTES-urlargs.md:235` cites `Gruntfile.js` line numbers, and
`e2e/local/README.md:157` states a fact ("`npm run build:production` alone cannot produce it") that
a Vite build may make false.

### A separate module that also uses Grunt — do not touch

| File | Line | Reference |
|---|---:|---|
| `openam-ui/openam-ui-api/Gruntfile.js` | 17, 20, 54, 55, 57 | its own Grunt build (`copy:swagger`, `copy:resources`) |
| `openam-ui/openam-ui-api/package.json` | 6 | `"build:production": "grunt build:prod"` |

**`openam-ui-api` is a different module with an independent Grunt build.** It is out of scope for
this migration, and a repo-wide "remove Grunt" sweep would break it. Noted because a grep for
`grunt` hits it and the change's scope does not say so anywhere.

### Not found

- **No reference to `target/transpiled` outside `Gruntfile.js`.** It is purely internal.
- **No Grunt reference in `openam-ui/pom.xml` or `openam-ui/openam-ui-ria/pom.xml`** — the poms
  call npm scripts by name and never name Grunt. The two hits in `openam-ui-ria/pom.xml` (lines
  456, 459) are inside the ordering comment quoted in §5.1 and are prose.

---

## 9. Post-conditions

| Check | Result |
|---|---|
| `node_modules/@openidentityplatform/ui-commons` | **still present** |
| `node_modules/@openidentityplatform/ui-user` | **still present** |
| Restore command needed? | **No.** The spike ran in an isolated scratchpad npm project; no npm command was run in this module. |
| `NOTES-npm-commons.md` | present, unmodified |
| `NOTES-commons-version-pin.md` | present, unmodified |
| `PHASE1-TREE.md` | present, 652 entries |
| Throwaway spike config/scripts | deleted (scratchpad `vite-spike/`, including its `vite.config.js`) |
| `git status` on this module | only `PHASE1-TREE.md` and `NOTES-vite-build.md`, both new. Nothing modified. |
| `mvn clean` run anywhere | **no** |
| bare `npm install` run in this module | **no** |

---

## 10. Open questions this survey could not settle

1. **Whether the Maven build flips to Vite in 4.1 or at the end of phase 2.** Explicitly out of
   scope here, and the openspec prompt for group 4 names it as "the one thing to settle before 4.1
   runs".
2. **`outDir`.** Presented as a trade-off in §6, deliberately not decided.
3. **Whether `--target-version` becomes an env var or a mode** (§4). It decides whether the pom's
   `npm-build` execution changes at all.
4. **How the 308 unbundled modules are emitted.** `preserveModules`, a second build pass, or a
   change to the runtime contract. This is the substance of tasks 4.4–4.8 and cannot be answered
   before the AMD → ESM conversion is scoped.
5. **How `libs/` (50 files, 1.97 MB) is handled** — real npm dependencies versus copied static
   files reached by alias. Task 4.6.
6. **Whether the dev server sits in front of Vite or behind it** (§7). Task 4.10.
