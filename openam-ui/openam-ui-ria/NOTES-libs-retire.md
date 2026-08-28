# Task 4.7 — retiring the `commons.ui.libs` Maven channel from the OpenAM XUI build

Analysis record. **Nothing was modified to produce this file** — no pom, no assembly descriptor,
no source, no `package.json`. No Maven goal was run at all (see §11). This file says what has to
change, what the shipped tree must still contain afterwards, and what is still open.

Reads: `commons/ui/LIBS-INVENTORY.md` (task 3.1), `NOTES-npm-commons.md` (3.7),
`NOTES-static-assets.md` (4.4), `PHASE1-TREE.md` (4.0/4.1), `vite.config.js`, `Gruntfile.js`,
`karma.conf.js`, the three poms and `src/main/assembly/dir.xml`.

> **Path note.** The task brief's paths (`commons/ui/…`, `OpenAM/openam-ui/…`) are relative to
> `/home/maxim/Documents/_projects/forgerock/`, not to the `openspec-commons` checkout, which
> holds only `openspec/`. All five preflight items pass at that root. Absolute paths are used
> below.

---

## 0. Preflight

| Check | Result |
|---|---|
| `commons/ui/LIBS-INVENTORY.md` | present, 64,706 B, 591 lines |
| `openam-ui-ria/NOTES-npm-commons.md` | present, 14,483 B, tracked |
| `openam-ui-ria/PHASE1-TREE.md` | present, 75,551 B, 835 lines; manifest = lines 183–834 (652 entries) |
| `openam-ui-ria/target/XUI/libs` | present, **50 files** |
| `node_modules/@openidentityplatform/ui-commons` | present |
| `node_modules/@openidentityplatform/ui-user` | present |

`target/compiled` deliberately **not** preflighted: since 4.1 it is Vite's output and has no
`libs/` at all. Confirmed — `ls target/compiled/libs` → *No such file or directory*.

### State of the build as 4.7 starts

This matters more than it sounds. `target/compiled` today holds **273 files**; `PHASE1-TREE.md`
records **652**. Against the manifest the current Vite tree is:

| | Count | What |
|---|---:|---|
| missing | **381** | `org/` 303, **`libs/` 50**, `config/` 17, `store/` 6, `components/` 5 |
| extra | 2 | `main-authorize.js.map`, `main-device.js.map` |
| common paths | 271 | of which **267 byte-identical**, 4 differ |
| differing | 4 | `main.js`, `main.js.map`, `main-authorize.js`, `main-device.js` — the entry bundles |

The 331 missing AMD modules (`org/`, `config/`, `store/`, `components/`) are **group 5's**
AMD→ESM conversion, not 4.7's. The **50 missing `libs/` files are 4.7's** (minus `libs/codemirror/`,
which is 4.8's). Every shipped `css/` file already matches the manifest byte-for-byte.

**Consequence for 4.7's design, and it is the central one:** the module system has not been
converted yet, so route (a) — "an npm dependency resolved by the bundler" — is **not available to
this task for any runtime library**. `main.js` is still AMD, the 14 vendor aliases are still
`require.config.paths` entries, and `index.html`, six `.ftl` templates and `EditScriptView.js`
address `libs/<file>.js` **by literal path**. 4.7 must therefore keep every `libs/` path exactly
where it is and change only *who supplies the bytes*: Maven artifact → npm package file, copied
into the output. Route (a) becomes available in group 5, not here.

---

## 1. THE FULL SCOPE, ENUMERATED

Only **three** poms in the whole OpenAM tree mention `commons.ui.libs`
(`grep -rln commons.ui.libs OpenAM --include=pom.xml`): `OpenAM/pom.xml`,
`OpenAM/openam-ui/pom.xml`, `OpenAM/openam-ui/openam-ui-ria/pom.xml`. `openam-ui-api` and
`openam-ui-js-sdk` reference it zero times. **`openam-ui-ria` is the sole consumer module**, so
retiring it there retires the channel from OpenAM entirely.

### 1.1 `openam-ui-ria/src/main/assembly/dir.xml`

| Block | Lines | Produces today | Consumed by |
|---|---|---|---|
| `dependencySet` — `include org.openidentityplatform.commons.ui.libs:*:js`, `exclude …:CodeMirror`, `outputDirectory /libs` | 119–127 | **42 files** in `target/dependencies/libs/` | Grunt `copy:compose` / Vite `COMPOSITION_SOURCES[0]`; `karma.conf.js:14` |
| `dependencySet` — `include …:*:css` **and** `include …:*:less`, `outputDirectory /css` | 128–134 | **12 files** in `target/dependencies/css/` (11 `.css` + `backgrid.min-0.3.5.less`) | the LESS compile; `css/bootstrap-3.3.5-custom.css` also ships verbatim |
| `fileSet` ×6 — `codemirror5-${v}.0`, `CodeMirror-${v}.0`, `codemirror-${v}` × (`/libs/codemirror`, `/css/codemirror`) | 27–80 | **4 JS** + **2 CSS** under `libs/codemirror/`, `css/codemirror/` | `EditScriptView.js` (literal AMD paths); `styles-admin.less:31–32` |
| `fileSet` — `Font-Awesome-${font-awesome.version}` → `/css/fontawesome` | 95–103 | **8 files** | `structure.less:23–24`, `styles-admin.less:25–26`; 5 fonts ship verbatim |

The `:less` include is the one 3.7 added, for `backgrid.min-0.3.5.less`. Three classifiers, two
blocks. Six of the seven `fileSet`s are the same CodeMirror content under three candidate root
names (the zip's root has varied); only `codemirror5-4.10.0` exists in `target/` today.

### 1.2 `openam-ui-ria/pom.xml`

| Element | Lines | Produces today | Consumed by |
|---|---|---|---|
| `<dependency>` `commons.ui:user:zip:www` | 75–80 | nothing directly — it is the **sole transitive carrier** of the 33 `commons.ui.libs` pins (25 `js`, 6 `css`, 1 `less`, 1 `zip`) that the `dependencySet`s resolve | the two `dependencySet`s above; `unpack-forgerock-ui-user-form2js` |
| **21 runtime `commons.ui.libs` `<dependency>` entries** | 81–215, 245–251 | the other 18 `libs/` files + 4 `css/` files + the CodeMirror zip | as above |
| **4 test `commons.ui.libs` `<dependency>` entries** (`sinon`, `qunit:js`, `qunit:css`, `squire`) | 217–244 | `target/test-classes/libs/` via `copy-dependencies-test` | `karma.conf.js` |
| execution `unpack-forgerock-ui-user-form2js` | 361–379 | `target/dependencies-expanded/forgerock-ui-user/libs/form2js-2.0-769718a.js` — **one file** | composition source #6; pins the shipped form2js bytes (§7) |
| execution `unpack-font-awesome` | 380–404 | `target/Font-Awesome-4.5.0/` (filtered to css + fonts + `less/variables.less`) | `dir.xml`'s font-awesome `fileSet` |
| execution `unpack-codemirror` | 405–421 | `target/codemirror5-4.10.0/` | `dir.xml`'s six CodeMirror `fileSet`s |
| execution `copy-dependencies-test` | 423–436 | `target/test-classes/libs/` (`sinon,qunit,squire`) | `karma.conf.js` — dormant, `npm test` is a stub |
| execution `prepare-working-dir` (`maven-assembly-plugin`, descriptor `dir.xml`) | 530–543 | **`target/dependencies/` — 66 files** | §2 |

The 21 runtime artifactIds: `selectize-non-standalone`, `text`, `sifter`, `microplugin`,
`qrcode`, `jquery-sortable`, `jsoneditor`, `bootstrap-tabdrop`, `CodeMirror` (zip),
`bootstrap-clockpicker` (js + css), `bootstrap-datetimepicker` (js + css), `handlebars` (min js),
`redux`, `react-bootstrap`, `classnames`, `react-input-autosize`, `react-select` (js + css),
`base64`.

### 1.3 `OpenAM/openam-ui/pom.xml` — the plugin that is the whole hazard

| Element | Lines | Notes |
|---|---|---|
| `maven-external-dependency-plugin`, `<inherited>false</inherited>`, **60 `<artifactItem>`s** | 43–583 | fetches the artifacts from a dozen CDNs into `~/.m2`; they are published to **no** repository |
| execution `clean-external-dependencies` → goal `clean-external`, phase `clean` | 561–566 | **DELETES them from `~/.m2`.** This is the execution the whole task is warned about |
| execution `resolve-install-external-dependencies` → goals `resolve-external`, `install-external`, phase `process-resources` | 568–574 | the only reason a build here resolves at all |

Retiring the channel is what finally lets this plugin be deleted, and deleting it is what removes
the `clean-external` landmine from the OpenAM build permanently. It cannot go until the **4 test
artifacts** move too (`sinon`, `qunit` js+css, `squire` → `sinon`/`qunitjs@1.15.0`/`squirejs@0.2.0`
in `devDependencies`). `sinon` is already a devDependency, at **1.17.6**, not 1.15.4.

The sibling `commons/ui` checkout has its own copy of this plugin; removing OpenAM's does not
affect it.

### 1.4 `OpenAM/pom.xml`

Exactly **one** `commons.ui.libs` entry: the dead `jquery.qrcode:0.11.0:min:js`
`dependencyManagement` block at **lines 914–920**. Nothing references it and it is absent from
`~/.m2` (`ls ~/.m2/…/commons/ui/libs | grep -i qrcode` → `qrcode` only, which is #52
`qrcode-generator`). This is open decision **§12.5**, and it is 4.7's — see §9.

---

## 2. WHAT `target/dependencies` IS FOR

`dir.xml` is **not** packaging-only. The same descriptor is bound twice, and the second binding is
the load-bearing one.

`openam-ui-ria/pom.xml:530–543`:

```xml
<execution>
    <id>prepare-working-dir</id>
    <phase>process-resources</phase>
    <goals><goal>single</goal></goals>
    <configuration>
        <finalName>dependencies</finalName>
        <appendAssemblyId>false</appendAssemblyId>
        <descriptors>
            <descriptor>src/main/assembly/dir.xml</descriptor>
        </descriptors>
    </configuration>
</execution>
```

`finalName=dependencies` + `appendAssemblyId=false` + `<format>dir</format>` ⇒ the descriptor's
output **is** `target/dependencies`. Measured today: **66 files** — 46 under `libs/` (42 flat + 4
`codemirror/`) and 20 under `css/`.

`Gruntfile.js:58–69`:

```js
buildCompositionDirs = _.flatten([
    "target/dependencies",                                // maven-assembly-plugin (dir.xml)
    npmPackageDirs,
    "target/dependencies-expanded/forgerock-ui-user",
    // This must come last so that it overwrites any conflicting files!
    mavenProjectSource(".")
]),
```

`vite.config.js:152–161` carries the same list, post-4.1:

```js
const COMPOSITION_SOURCES = [
    "target/dependencies",
    "node_modules/@openidentityplatform/ui-commons/amd",
    …
];
```

`karma.conf.js:14` is the third consumer:

```js
{ pattern: "target/dependencies/libs/**/*.js", included: false },
```

**Four consumers, not one.** `dir.xml` is the descriptor for the packaging step *and* the producer
of composition source #1 *and* the vendor-lib root for the Karma harness.

### What removing the `dependencySet` blocks does

| Build | Effect |
|---|---|
| **Grunt** (`npm run build:grunt`, still wired, `Gruntfile.js` intact) | `copy:compose` loses 54 of the 66 files in source #1. `grunt-contrib-copy` **ignores a missing/empty source directory silently** — the 3.7 record opens on exactly this. `requirejs:compile` then fails later for an unrelated-looking reason, or worse, succeeds against a partial tree. `check-composition-sources` guards only the four npm directories, **not** `target/dependencies`. |
| **Vite** (`npm run build:production`, live) | `composeStaticAssets` loses `css/bootstrap-3.3.5-custom.css` and the 5 shipped Font Awesome fonts. `renderStylesheets` **fails hard**: `structure.less` and `styles-admin.less` `@import` eight vendor files out of the staged `css/` tree (§5), and LESS errors on a missing import. `libs/` is already absent from Vite's output, so *that* half is a no-op today. **Vite has no `check-composition-sources` equivalent.** |
| **Karma** | `target/dependencies/libs/**/*.js` resolves to nothing; the 17 specs lose every vendor lib. Dormant — `npm test` is a stub echo since 4.1 — but `npm run test:karma` is the documented path. |

If the CodeMirror and Font Awesome `fileSet`s go as well, `target/dependencies` becomes empty and
`prepare-working-dir`, the `dir.xml` descriptor, and `COMPOSITION_SOURCES[0]` /
`buildCompositionDirs[0]` should all be deleted rather than left producing an empty directory —
an empty composition source is precisely the silent-drop shape the plan flags five times.

---

## 3. THE PER-FILE DESTINATION TABLE

Routes: **(a)** npm dependency resolved by the bundler · **(b)** npm package file copied into the
output at the same path · **(c)** vendored in `src/main/js/libs` · **(d)** still a Maven artifact ·
**(e)** dropped.

npm names/versions are **taken from `LIBS-INVENTORY.md` §2** and not re-derived. `evidence`
carries the inventory's own verdict: **MD5** = artifact is byte-identical to a named file in the
npm tarball (so route (b) reproduces `PHASE1-TREE.md` exactly); **VER** = version matches but npm
ships no byte-equivalent build (route (b) **changes the digest**); **bump** = that version was
never published.

### 3.1 `libs/` — all 50 files in `target/XUI/libs`

| # | File | md5 (shipped) | From today | npm coordinate | ev. | After | Route |
|---:|---|---|---|---|---|---|---|
| 1 | `backbone-1.1.2-min.js` | `9c3e3189` | `dependencySet` :js | `backbone@1.1.2` → `backbone-min.js` | MD5 | npm file copied to `libs/` | **b** |
| 2 | `backbone.paginator.min-2.0.2-min.js` | `7ef9bd3e` | :js | `backbone.paginator@2.0.2` → `lib/backbone.paginator.min.js` | MD5 | copied | **b** |
| 3 | `backbone-relational-0.9.0-min.js` | `2282dafb` | :js | `backbone-relational@0.9.0` | VER | copied — **npm has unminified only; digest changes** | **b** |
| 4 | `backgrid-filter.min-0.3.7-min.js` | `af6fb96a` | :js | `backgrid-filter@0.3.7` | MD5 | copied | **b** |
| 5 | `backgrid.min-0.3.5-min.js` | `248635b0` | :js | `backgrid@0.3.5` → `lib/backgrid.min.js` | VER | copied — **cdnjs re-min; digest changes** | **b** |
| 6 | `backgrid-paginator-0.3.5-custom.min.js` | `ebd4b6db` | `src/main/js/libs` | patched — inventory §12.3 open | — | unchanged | **c** |
| 7 | `backgrid-paginator.min-0.3.5-min.js` | `c08f46d1` | :js | `backgrid-paginator@0.3.5` (Cloudflare fork) | VER | **dead** (§9) — decision §12.6 | **b or e** |
| 8 | `backgrid-select-all-0.3.5-min.js` | `9cefb2cc` | :js | `backgrid-select-all@0.3.5` | VER | copied — digest changes | **b** |
| 9 | `base64-1.0.0-min.js` | `152e3662` | :js | `Base64@1.0.0` | VER | **see §4.2 — must survive** | **b or c** |
| 10 | `bootstrap-3.3.5-custom.js` | `8015042d` | :js | `bootstrap@3.3.5` → `dist/js/bootstrap.js` | MD5 | copied | **b** |
| 11 | `bootstrap-clockpicker-0.0.7-min.js` | `28af1dfd` | :js | `clockpicker@0.0.7` | VER | copied — digest changes | **b** |
| 12 | `bootstrap-datetimepicker-4.14.30-min.js` | `7b418408` | :js | `eonasdan-bootstrap-datetimepicker@4.14.30` | VER | **npm ships `src/js` only — a build step is required** | **b + build** |
| 13 | `bootstrap-dialog-1.34.4-min.js` | `5ce8851d` | :js | `bootstrap3-dialog@1.35.1` | bump | copied — **1.34.4 never published** | **b + bump** |
| 14 | `bootstrap-tabdrop-1.0.js` | `7c4081d5` | :js | **none** (§6.1) | NONE | options only | **V/R/M** |
| 15 | `classnames-2.2.5.js` | `757d3f1f` | :js | `classnames@2.2.5` → `index.js` | MD5 | copied | **b** |
| 16 | `codemirror/addon/display/fullscreen.js` | `fb86184c` | `fileSet` (zip) | `codemirror@4.10.0` | MD5 | **4.8's decision — FLAGGED, not decided** | **4.8** |
| 17 | `codemirror/lib/codemirror.js` | `1c570cd1` | `fileSet` | `codemirror@4.10.0` | MD5 | **4.8** | **4.8** |
| 18 | `codemirror/mode/groovy/groovy.js` | `4f97d9e7` | `fileSet` | `codemirror@4.10.0` | MD5 | **4.8** | **4.8** |
| 19 | `codemirror/mode/javascript/javascript.js` | `921ad047` | `fileSet` | `codemirror@4.10.0` | MD5 | **4.8** | **4.8** |
| 20 | `dragula-3.6.7-min.js` | `8ef652fe` | :js | `dragula@3.6.7` | MD5 | **dead in AM** (§9) — decision §12.6 | **b or e** |
| 21 | `form2js-2.0-769718a.js` | `897ec696` | **`dependencies-expanded`** | **none** (§6.1) | NONE | **§7 — the hazard** | **V/R/M** |
| 22 | `handlebars-4.7.7.js` | `c4d39d28` | :js | `handlebars@4.7.7` → `dist/handlebars.js` | MD5 | copied — **this is the one `main.js` binds** | **b** |
| 23 | `handlebars-4.7.7-min.js` | `5a252786` | pom :js | **`handlebars@4.7.6`** (label is wrong, §7 inv.) | MD5 | **dead** (§9) — decision §12.6 | **b or e** |
| 24 | `i18next-1.7.3-min.js` | `35578b3a` | :js | `i18next@1.7.3` → `lib/dep/i18next.min.js` | MD5 | copied | **b** |
| 25 | `jquery-3.7.1-min.js` | `2c872dbe` | :js | `jquery@3.7.1` → `dist/jquery.min.js` | MD5 | copied | **b** |
| 26 | `jquery.autosize.input.min.js` | `fa516338` | `src/main/js/libs` | **none** (inv. §8) | NONE | unchanged | **c** |
| 27 | `jquery.ba-dotimeout-1.0-min.js` | `f10a418e` | :js | **none** (§6.1) | NONE | options only | **V/R/M** |
| 28 | `jquery.placeholder-2.0.8.js` | `d7098f9b` | :js | `jquery-placeholder@2.1.1` | bump | **dead in AM** (§9) — decision §12.6 | **b or e** |
| 29 | `jquery-sortable-0.9.13.js` | `8efebfc0` | pom :js | `jquery-sortable@0.9.13` | VER | copied — **artifact was fetched from unpinned `master`**; digest changes | **b** |
| 30 | `js2form-2.0-769718a.js` | `fc83dc6a` | :js | **none** (§6.1) | NONE | options only | **V/R/M** |
| 31 | `jsoneditor-0.7.23-custom.js` | `6c39c8be` | `src/main/js/libs` | patched — inventory §12.4 open | — | unchanged | **c** |
| 32 | `jsoneditor-0.7.9-min.js` | `ce6de91c` | pom :js | `json-editor@0.7.9` | MD5 | **dead** (§9) — decision §12.6 | **b or e** |
| 33 | `lodash-3.10.1-min.js` | `7629cac4` | **`src/main/js/libs`** (4.3) | `lodash@3.10.1` | VER | **already vendored** — beats the Maven copy | **c** |
| 34 | `microplugin-0.0.3.js` | `8c6cdcd5` | pom :js | `microplugin@0.0.3` → `src/microplugin.js` | MD5 | copied | **b** |
| 35 | `moment-2.28.0-min.js` | `bb51b2cd` | :js | `moment@2.28.0` → `min/moment.min.js` | MD5 | copied | **b** |
| 36 | `popover-clickaway.js` | `e92d40fd` | `src/main/js/libs` | **not a dependency** — AM's own code | — | unchanged | **c** |
| 37 | `qrcode-1.4.4-min.js` | `e259e455` | pom :js | `qrcode-generator@1.4.4` (rename) | VER | copied — digest changes | **b** |
| 38 | `react-15.2.1-min.js` | `a4137323` | :js | `react@15.2.1` → `dist/react.min.js` | MD5 | copied | **b** |
| 39 | `react-bootstrap-0.30.1-min.js` | `bf1e00b8` | pom :js | `react-bootstrap@0.30.1` | MD5 | copied | **b** |
| 40 | `react-dom-15.2.1-min.js` | `981fd81a` | :js | `react-dom@15.2.1` → `dist/react-dom.min.js` | MD5 | copied — **709 B shim, see §10** | **b** |
| 41 | `react-input-autosize-1.1.0-min.js` | `c60e2a13` | pom :js | `react-input-autosize@1.1.0` | MD5 | copied | **b** |
| 42 | `react-select-1.0.0-rc.2-min.js` | `bd4ca8e8` | pom :js | `react-select@1.0.0-rc.2` | MD5 | copied | **b** |
| 43 | `redux-3.5.2-min.js` | `c5ee165e` | pom :js | `redux@3.5.2` → `dist/redux.min.js` | MD5 | copied | **b** |
| 44 | `requirejs-2.3.7-min.js` | `01252f25` | :js | `requirejs@2.3.7` (**already a devDependency**) | VER | **see §4.1 — must survive** | **b or c** |
| 45 | `selectize-0.12.1-min.js` | `7a8aec7b` | :js | `selectize@0.12.1` → `dist/js/selectize.min.js` | MD5 | **dead** (§9), same bytes as #46 | **b or e** |
| 46 | `selectize-non-standalone-0.12.1-min.js` | `7a8aec7b` | pom :js | `selectize@0.12.1` — **identical bytes to #45** | MD5 | copied — **this is the one `main.js` binds** | **b** |
| 47 | `sifter-0.4.1-min.js` | `3e0fa985` | pom :js | `sifter@0.4.1` | MD5 | copied | **b** |
| 48 | `spin-2.0.1-min.js` | `104d92ce` | :js | `spin.js@2.0.1` (rename) | VER | copied — digest changes | **b** |
| 49 | `text-2.0.15.js` | `2a17da82` | pom :js | `requirejs-text@2.0.15` (rename) | MD5 | copied | **b** |
| 50 | `xdate-0.8-min.js` | `68f8cdca` | :js | `xdate@0.8.0` → `src/xdate.js` | MD5 | copied — **artifact is unminified despite `-min`** | **b** |

**Unrouted: none.** All 50 trace to a source and a destination.

Totals — MD5-exact **28**, VER **12**, bump **2**, no-npm **4**, vendored-only **4**
(28+12+2+4 = 46 from `target/dependencies` + 4 `src/main/js/libs` files not otherwise counted
= 50; `lodash` is counted once, under VER, but its live route is (c)).

### 3.2 `css/` — the 20 files `dir.xml` supplies

`target/XUI/css` holds 78 files: **20** from `dir.xml` (below), **37** from
`ui-commons/www/css` (`css/common/**`), **21** from `src/main/resources/css` (`css/am-*`,
`structure.less`, `theme.less`, `styles-admin.less`). Only the 20 are 4.7's.

Of the 20, only **6 reach the shipped tree** — 1 verbatim (`bootstrap-3.3.5-custom.css`, listed in
`NON_COMPILED_PATHS`) and 5 as Font Awesome fonts. The rest are LESS *inputs*, compiled into
`structure.css` / `styles-admin.css`, or dead.

| File | md5 | npm coordinate | ev. | Consumed by | After | Route |
|---|---|---|---|---|---|---|
| `bootstrap-3.3.5-custom.css` | `957474c3` | `bootstrap@3.3.5` → `dist/css/bootstrap.css` | MD5 | **shipped verbatim** | copied | **b** |
| `fontawesome/css/font-awesome.min.css` | `4fbd15cb` | `font-awesome@4.5.0` | MD5 | `structure.less:23`, `styles-admin.less:25` | §5 | **b** |
| `fontawesome/less/variables.less` | `49b82ead` | `font-awesome@4.5.0` | — | `structure.less:24`, `styles-admin.less:26` | §5 | **b** |
| `fontawesome/fonts/FontAwesome.otf` | `87d8ca3d` | `font-awesome@4.5.0` | — | shipped verbatim | §5 | **b** |
| `fontawesome/fonts/fontawesome-webfont.eot` | `32400f4e` | `font-awesome@4.5.0` | — | shipped verbatim | §5 | **b** |
| `fontawesome/fonts/fontawesome-webfont.svg` | `f775f9cc` | `font-awesome@4.5.0` | — | shipped verbatim | §5 | **b** |
| `fontawesome/fonts/fontawesome-webfont.woff` | `a35720c2` | `font-awesome@4.5.0` | — | shipped verbatim | §5 | **b** |
| `fontawesome/fonts/fontawesome-webfont.woff2` | `db812d8a` | `font-awesome@4.5.0` | — | shipped verbatim | §5 | **b** |
| `fontawesome/fonts/fontawesome-webfont.ttf` | `a3de2170` | `font-awesome@4.5.0` | — | **composed but NOT shipped** — no `**/*.ttf` in `nonCompiledFiles` | §5 | **b** |
| `bootstrap-dialog-1.34.4-min.css` | `e8d761e4` | `bootstrap3-dialog@1.35.1` | bump | `structure.less:21`, `styles-admin.less:21` | copied to LESS stage | **b + bump** |
| `selectize-0.12.1-bootstrap3.css` | `d75b17eb` | `selectize@0.12.1` → `dist/css/selectize.bootstrap3.css` | MD5 | `structure.less:26`, `styles-admin.less:28` | copied | **b** |
| `titatoggle-1.2.6-min.css` | `cc982336` | `titatoggle@1.2.14` | bump | `structure.less:27`, `styles-admin.less:29` | copied | **b + bump** |
| `bootstrap-clockpicker-0.0.7-min.css` | `3d3a40f0` | `clockpicker@0.0.7` | VER | `styles-admin.less:22` | copied | **b** |
| `bootstrap-datetimepicker-4.14.30-min.css` | `48063c9a` | `eonasdan-bootstrap-datetimepicker@4.14.30` | **no CSS in the tarball at all** | `styles-admin.less:23` | **must be built from LESS or vendored** | **b + build / c** |
| `react-select-1.0.0-rc.2-min.css` | `7b4c89c5` | `react-select@1.0.0-rc.2` → `dist/react-select.min.css` | MD5 | `styles-admin.less:34` | copied | **b** |
| `codemirror/lib/codemirror.css` | `1c26f7d1` | `codemirror@4.10.0` | MD5 | `styles-admin.less:31` | **4.8** | **4.8** |
| `codemirror/addon/display/fullscreen.css` | `1a278e72` | `codemirror@4.10.0` | MD5 | `styles-admin.less:32` | **4.8** | **4.8** |
| `backgrid-filter.min-0.3.7.css` | `67cbc211` | `backgrid-filter@0.3.7` | MD5 | **nothing** | drop | **e** |
| `backgrid-paginator.min-0.3.5.css` | `fded3185` | `backgrid-paginator@0.3.5` | VER | **nothing** | drop | **e** |
| `backgrid.min-0.3.5.less` | `8eb051ca` | **none** (§6.1) | NONE | **nothing** | drop | **e** |

**The three backgrid vendor stylesheets are imported by nothing.** Verified by grepping every
`@import` in the composed `css/` tree: the only backgrid styling is
`css/common/structure/backgrid.less`, which is hand-written commons LESS with **no `@import` lines
at all**, and `am-user/{structure,theme}/uma.less`, which style `.backgrid` selectors directly.
None of the three is in the shipped zip. Route **(e)** is safe for all three and costs nothing —
including `backgrid.min-0.3.5.less`, the `:less` include 3.7 added, which was added to preserve
composition parity when the zip unpack was removed, not because anything consumes it. **Dropping
it also disposes of one of the eight no-npm rows (§6) at zero risk** — see §6.

---

## 4. THE FILES THAT MUST SURVIVE REGARDLESS OF BUNDLING

All three claims **confirmed against the tree**.

### 4.1 `libs/requirejs-2.3.7-min.js` — the trap 4.2 found

Confirmed. Six server-side FreeMarker templates in `openam-oauth2` load it by absolute deployed
path:

```
openam-oauth2/src/main/resources/templates/CodeThanks.ftl:37
openam-oauth2/src/main/resources/templates/CodeVerificationForm.ftl:37
openam-oauth2/src/main/resources/templates/page/error.ftl:56
openam-oauth2/src/main/resources/templates/page/authorize.ftl:65
openam-oauth2/src/main/resources/templates/touch/authorize.ftl:64
openam-oauth2/src/main/resources/templates/popup/authorize.ftl:64
```

each `<script data-main="${baseUrl?html}/XUI/main-{device,authorize}"
src="${baseUrl?html}/XUI/libs/requirejs-2.3.7-min.js">`, plus
`src/main/resources/index.html:28` `<script src="libs/requirejs-2.3.7-min.js">`.

Confirmed it has **no `src/` copy**: the only non-`target/` hits for `requirejs-2.3.7` in the whole
OpenAM tree are those six `.ftl`s, `index.html`, and two comments in `vite.config.js`. It reaches
the tree solely through the `dependencySet` this task retires.

`node_modules/requirejs` is present and is version **2.3.7** — but it ships **only the unminified
`require.js`, 86,578 B, md5 `1bb804a8f1532f366359435fab1232c4`**. The shipped artifact is the
17,420 B cdnjs minification, md5 `01252f25e96768861bd3effa7bf8889e`. **Same release, different
bytes — 5× the size.**

**Where it comes from after this task.** Two routes, and the choice is a real one:

- **(b)** copy `node_modules/requirejs/require.js` → `libs/requirejs-2.3.7-min.js`. Managed,
  auditable, satisfies the requirement. Costs a **+69,158 B digest change on the loader itself**,
  under a filename that says `-min`. Re-minifying to chase the cdnjs bytes will not reproduce them
  (different tool, different flags) and adds a build step for one file.
- **(c)** vendor the exact 17,420 B file into `src/main/js/libs/`, as 4.3 already did for lodash.
  Byte-identical to `PHASE1-TREE.md`, zero risk, and the loader is the one file where a surprise
  is unrecoverable — if it fails, nothing else in the UI loads and the six OAuth2 pages break too.
  Leaves one file outside `npm audit`'s view.

Route **(d)** is not tenable: keeping one Maven artifact keeps the entire
`maven-external-dependency-plugin` and its `clean-external` goal.

**Whichever is chosen, the path `libs/requirejs-2.3.7-min.js` cannot change** without editing six
`.ftl` files in a different Maven module — which is outside this module's blast radius and would
need its own change.

### 4.2 `libs/base64-1.0.0-min.js`

Confirmed — `src/main/resources/index.html:21`, `<script src="libs/base64-1.0.0-min.js">`, a
literal non-AMD `<script>` before RequireJS loads. Present in the stamped `target/compiled/index.html`
too, so the reference ships today even though the file does not.

npm `Base64@1.0.0` exists but ships `base64.js` **unminified, 2,219 B**; the artifact is the 835 B
cdnjs min (VER). Same two routes as requirejs, same trade: (b) is a digest change, (c) is
byte-exact. Lower stakes than the loader — it is a small polyfill, not the module system.

### 4.3 `libs/codemirror/*` — 4.8's, FLAGGED not decided

Confirmed. `EditScriptView.js` names four literal AMD paths in its `define` array:

```
src/main/js/org/forgerock/openam/ui/admin/views/realms/scripts/EditScriptView.js:21  "libs/codemirror/lib/codemirror"
                                                                               :35  "libs/codemirror/mode/groovy/groovy"
                                                                               :36  "libs/codemirror/mode/javascript/javascript"
                                                                               :37  "libs/codemirror/addon/display/fullscreen"
```

used at `:401` as `CodeMirror.fromTextArea(...)`. Two more files, `css/codemirror/lib/codemirror.css`
and `css/codemirror/addon/display/fullscreen.css`, are `@import (less)`-ed by `styles-admin.less:31–32`.

CodeMirror does not follow the other libraries' route — it arrives as a **zip**, is unpacked by
`unpack-codemirror`, and is placed by six `fileSet`s rather than a `dependencySet`. Inventory §11
names it the reassessment case. `codemirror@4.10.0` on npm is an exact MD5 match for
`lib/codemirror.js`.

**This is task 4.8's decision and is not made here.** What 4.7 must record is the coupling: if 4.7
deletes `unpack-codemirror` and the six `fileSet`s while 4.8 has not landed, six files disappear
from the tree and the admin script editor breaks. **Either 4.7 leaves the CodeMirror `fileSet`s,
`unpack-codemirror` and the `CodeMirror:zip` dependency in place for 4.8, or the two land
together.** Leaving them in place means `target/dependencies` — and therefore `prepare-working-dir`
and composition source #1 — must survive 4.7 as well, holding 6 files instead of 66.

---

## 5. FONT AWESOME

`dir.xml:95–103` supplies **8 files** under `css/fontawesome/` that **neither npm package ships** —
confirmed: `find node_modules/@openidentityplatform -type d -name libs` is empty, and
`ui-commons/www/css` holds only `css/common/**` (37 LESS files + `config.json`). No `fontawesome/`,
no vendor CSS of any kind.

The 8: `css/font-awesome.min.css`, `less/variables.less`, and 6 fonts (`FontAwesome.otf`,
`fontawesome-webfont.{eot,svg,ttf,woff,woff2}`).

**Build-blocking, not decorative** — confirmed against the LESS sources:

```
css/structure.less:23     @import (less) "fontawesome/css/font-awesome.min.css";
css/structure.less:24     @import        "fontawesome/less/variables.less";
css/styles-admin.less:25  @import (less) "fontawesome/css/font-awesome.min.css";
css/styles-admin.less:26  @import        "fontawesome/less/variables.less";
```

LESS errors on a missing `@import`, so losing either file fails `renderStylesheets` outright —
`structure.css` and `styles-admin.css` are two of the ten files in the shipped `css/` tree.

**After this task:** `font-awesome@4.5.0` — inventory #28, an **exact MD5 match** for
`css/font-awesome.min.css` between the GitHub zip and the npm tarball. All 8 files exist in that
package under the same relative paths (`css/`, `fonts/`, `less/`). Route **(b)**: an npm dependency
whose 8 files are copied into the LESS staging tree and, for the 5 shipped fonts, into the output.
`unpack-font-awesome` and the `fileSet` both retire.

Two things to carry over:

- **The case-sensitivity trap**, recorded in the `dir.xml` comment. The `fileSet` directory is
  `Font-Awesome-${font-awesome.version}` with a **capital F and A** because the artifact is the
  GitHub source archive (`github.com/FortAwesome/Font-Awesome/archive/v4.5.0.zip`), which roots at
  `Font-Awesome-4.5.0/`. On a case-sensitive filesystem a lowercase spelling silently matches
  nothing; **on macOS it resolves anyway, so the error is invisible locally**. Moving to npm makes
  the trap go away — the tarball roots at `package/` — but the same class of bug transfers to
  whatever path the copy step hardcodes, and `node_modules/font-awesome/...` is all lowercase.
- **`fontawesome-webfont.ttf` is composed but not shipped** — there is no `**/*.ttf` in
  `nonCompiledFiles`. `vite.config.js:185–191` reproduces this deliberately. Do **not** fix it in
  4.7: it would put a permanent +1 delta against `PHASE1-TREE.md` that 4.8 then has to re-explain.

---

## 6. THE NO-NPM-EQUIVALENT ROWS

`LIBS-INVENTORY.md` §6 lists **8**, of which 5 reach the built OpenAM XUI. Two more from inventory
§8 are in the same position and reach OpenAM as vendored source. **No disposition is chosen here.**

Route **(M) — keep the Maven artifact — contradicts the `ui-build-and-packaging` requirement
*Runtime libraries are managed package dependencies*** ("runtime libraries SHALL NOT be distributed
as hand-published binary artifacts of this project") **directly**, for every runtime row. Taking it
needs the requirement amended or an explicit exception recorded. It also has a compounding cost
specific to 4.7: **route (M) for even one artifact keeps `maven-external-dependency-plugin`, its 60
`artifactItem`s and its `clean-external` goal alive**, which is most of what this task exists to
remove.

### 6.1 Reaching OpenAM — 5 from §6

| # | Artifact | Shipped as | RequireJS id | Options |
|---:|---|---|---|---|
| 20 | `bootstrap-tabdrop:1.0:js` | `libs/bootstrap-tabdrop-1.0.js` | `bootstrap-tabdrop` | **(V)** vendor the 5,105 B file to `src/main/js/libs` — byte-exact, joins the 5 already there. **(R)** npm `bootstrap-tabdrop` is `ispot-tv`'s fork, no 1.0, different lineage — real behaviour risk. **(M)** as above. *Extra pressure: AM's `downloadUrl` points at `www.eyecon.ro`, a dead vanity domain, and commons' points at an unpinned `master` — this artifact is already unreproducible.* |
| 31 | `form2js:2.0-769718a:js` | `libs/form2js-2.0-769718a.js` | `form2js` | see **§7** — the highest-stakes row |
| 32 | `js2form:2.0-769718a:js` | `libs/js2form-2.0-769718a.js` | `js2form` | **(V)** vendor the 9,118 B file. **(R)** not a package on npm under any name. **(M)** as above. *Sibling file of #31, same repo and commit — decide the two together.* |
| 41 | `jquery.ba-dotimeout:1.0:min:js` | `libs/jquery.ba-dotimeout-1.0-min.js` | `doTimeout` | **(V)** vendor the 1,065 B file. **(R)** `jquery-dotimeout`, `jquery.ba-dotimeout`, `jquery-ba-dotimeout`, `dotimeout` all 404 — no target to replace with. **(M)** as above. |
| 5 | `backgrid.min:0.3.5:less` | `css/backgrid.min-0.3.5.less` | — | **A fourth route the others lack, and §3.2 makes it free: nothing imports this file.** Verified — no `@import` of it anywhere in the composed `css/` tree, and it is absent from the shipped zip. **(e) drop** disposes of the row at zero risk. (V)/(R)/(M) all remain available but buy nothing. |

### 6.2 Also reaching OpenAM — 2 from inventory §8

| File | Shipped as | Options |
|---|---|---|
| `jquery.autosize.input.min.js` (1,503 B) | `libs/…` | Same three routes; **(V) is the status quo** — already in `src/main/js/libs`. Inventory §12.2. `jquery-autosize-input` / `jquery.autosize.input` 404; npm `autosize-input` is a different library. |
| `popover-clickaway.js` (3,668 B) | `libs/…` | **Not a dependency at all** — this project's own XUI-only Bootstrap-popover helper. It is source that belongs in `src/main/js`, where it already is. No decision needed. |

### 6.3 Not reaching OpenAM — 3

`contentflow:1.0.2` (openidm-enduser), `jquery-cron:f831f2` (openidm-admin),
`ldapjs-filter:2253` (openidm-admin). Out of scope for 4.7; they matter to the OpenIDM path only.
Recorded so the count reconciles: 5 + 3 = 8.

---

## 7. THE FORM2JS HAZARD

### Which bytes ship today

```
897ec696be559d5bb804b0803616efc5      10160  libs/form2js-2.0-769718a.js
```

Computed from the built tree and cross-checked three ways:

| Source | md5 | Bytes |
|---|---|---|
| `target/dependencies-expanded/forgerock-ui-user/libs/form2js-2.0-769718a.js` (the `zip:www` copy) | `897ec696…` | 10,160 |
| `target/dependencies/libs/form2js-2.0-769718a.js` (the `commons.ui.libs` artifact) | `897ec696…` | 10,160 |
| `target/XUI/libs/form2js-2.0-769718a.js` (composed) | `897ec696…` | 10,160 |
| `PHASE1-TREE.md:256` (the manifest) | `897ec696…` | 10,160 |

**The two sources agree today**, so `unpack-forgerock-ui-user-form2js` is currently inert — exactly
as `NOTES-npm-commons.md` §3 says. They did **not** agree on 2026-08-04: `target/dependencies` held
`3095c47f…` at 12,656 B (LF) against the zip's `897ec696…` at 10,160 B (CRLF), the Maven copy
carrying seven extra lines that rewrite bracketed field names (`foo[bar]` → `foo.bar`) during
serialisation. A later `install-external` re-fetch pulled `897ec696…` and the disagreement closed.
The pin exists because it can reopen: these artifacts are fetched from CDNs by version string and
**the same coordinate can yield different bytes on a re-fetch**.

### Where it comes from after this task

**There is no npm package.** Inventory #31: npm `form2js@1.0.0` is `kirill-zhirnov`'s fork;
`maxatwork/form2js` — the lineage this file is from, pinned at commit `769718a1…` — was never
published. So:

> **The npm package does NOT match these bytes. There is no npm package to match them.**
> Route (a) and route (b) do not exist for this file.

The available routes are (V) vendor / (R) replace / (M) keep the Maven artifact, exactly as §6 —
**and this is not a behaviour change if route (V) is taken.** Vendoring the 10,160 B `897ec696…`
file into `src/main/js/libs/` (where 5 files already live, including `lodash-3.10.1-min.js` since
4.3) reproduces `PHASE1-TREE.md` byte-for-byte and additionally makes the pin unnecessary — the
CDN drift channel is closed for this file permanently, which is strictly better than today.

Route (R) — adopting `form2js@1.0.0` — **would** be a behaviour change, and must be reported as
one if taken: `form2js` is bound at `main.js:56` and backs `RESTLoginView` plus five commons
self-service views, so a different fork's serialisation semantics land on the login path. **No
count-based check can detect it** — file counts, zip counts and libs counts are identical either
way. That is precisely the failure 3.7 caught, and the reason acceptance here is a per-file digest.

`js2form-2.0-769718a.js` (`fc83dc6a…`, 9,118 B) is the sibling file from the same repo and commit
and has the same standing. **Decide the two together.**

### What retires with it

Once form2js is vendored (or otherwise sourced outside Maven), `unpack-forgerock-ui-user-form2js`
retires, and with it the last consumer of `commons.ui:user:zip:www` — the dependency 3.7 retained
for exactly this reason. `target/dependencies-expanded/` disappears and
`COMPOSITION_SOURCES[6]` / `buildCompositionDirs[5]` must be removed from `vite.config.js` and
`Gruntfile.js` rather than left pointing at a missing directory.

---

## 8. THE ACCEPTANCE PROCEDURE

### 8.1 Produce the manifest and diff it

`PHASE1-TREE.md`'s manifest is **lines 183–834**, 652 entries, format `md5  size  path`, sorted by
path, paths relative to `target/compiled`.

```bash
cd /home/maxim/Documents/_projects/forgerock/OpenAM/openam-ui/openam-ui-ria
WORK=$(mktemp -d)

# 1. Extract the phase-1 oracle.
sed -n '183,834p' PHASE1-TREE.md > "$WORK/phase1.txt"

# 2. Manifest the post-change tree, same format.
( cd target/compiled && find . -type f | sed 's|^\./||' | sort \
    | while read -r f; do
          printf '%s %10s  %s\n' "$(md5sum "$f" | cut -d' ' -f1)" "$(stat -c%s "$f")" "$f"
      done ) > "$WORK/now.txt"

# 3. Path-level diff.
awk '{print $3}' "$WORK/phase1.txt" | sort > "$WORK/p1.paths"
awk '{print $3}' "$WORK/now.txt"    | sort > "$WORK/now.paths"
echo "--- MISSING (in phase1, not in the new tree) ---"; comm -23 "$WORK/p1.paths" "$WORK/now.paths"
echo "--- EXTRA   (in the new tree, not in phase1)  ---"; comm -13 "$WORK/p1.paths" "$WORK/now.paths"

# 4. Content diff on the paths both trees have.
join -j 3 -o 0,1.1,2.1,1.2,2.2 \
     <(sort -k3,3 "$WORK/phase1.txt") <(sort -k3,3 "$WORK/now.txt") > "$WORK/joined.txt"
echo "--- DIFFERING md5 ---"
awk '$2!=$3 {printf "  %-60s phase1=%s (%s B)  now=%s (%s B)\n",$1,$2,$4,$3,$5}' "$WORK/joined.txt"

# 5. The 4.7-specific slice.
echo "libs/ present: $(grep -c '  libs/' "$WORK/now.txt") / 50"
awk '$2!=$3 && $1 ~ /^libs\//' "$WORK/joined.txt"
```

**Build with `mvn -DskipTests package` from `openam-ui`, never from `openam-ui-ria`, and use
`rm -rf <module>/target` — never `mvn clean`.** See §11.

### 8.2 What a CORRECT diff looks like

Not zero. The baseline 4.7 inherits already differs; the question is only whether 4.7 moved the
right lines.

**MISSING — expected to fall from 381 to 331 (or 335).**

| Group | Count | Expected after 4.7 |
|---|---:|---|
| `org/` | 303 | **still missing** — group 5, AMD→ESM |
| `config/` | 17 | **still missing** — group 5 |
| `store/` | 6 | **still missing** — group 5 |
| `components/` | 5 | **still missing** — group 5 |
| `libs/` (non-codemirror) | 46 | **must become 0** — this is 4.7's deliverable |
| `libs/codemirror/` | 4 | **0 if 4.8 landed with it; still 4 if 4.8 is deferred** (§4.3) |

Minus whatever §12.6 decides to drop (§9): dropping the dead six leaves them permanently missing,
i.e. MISSING = 331 + 6 = 337, and that is a **deliberate** delta that must be stated in the notes,
not a regression.

**EXTRA — expected to stay at exactly 2**: `main-authorize.js.map`, `main-device.js.map`. Vite
emits sourcemaps for all three entries; Grunt emitted one. Anything else appearing here is a bug.

**DIFFERING — expected to be the 4 entry bundles, plus a bounded, enumerated set of `libs/` rows.**

- `main.js`, `main.js.map`, `main-authorize.js`, `main-device.js` — differ today and will keep
  differing until group 5. Not 4.7's.
- `libs/` rows: **28 of the 50 can be byte-identical** (the MD5-exact rows in §3.1) and **should
  be** — any difference there is a real defect, a wrong file picked out of the tarball.
- **12 rows will differ legitimately** (the VER rows: `backbone-relational`, `backgrid.min`,
  `backgrid-paginator.min`, `backgrid-select-all`, `base64`, `bootstrap-clockpicker`,
  `bootstrap-datetimepicker`, `jquery-sortable`, `lodash`, `qrcode`, `requirejs`, `spin`) because
  npm publishes no byte-equivalent build. **Each must be listed with its before/after digest and
  size and a one-line reason**; an unexplained entry in this set is a defect.
- **2 rows differ by version bump** (`bootstrap-dialog` 1.34.4→1.35.1, `jquery.placeholder`
  2.0.8→2.1.1).
- **4 no-npm rows and 5 vendored rows must be byte-identical** if route (V) is taken — they are
  copied bytes, and a difference there means the wrong file was vendored.
- **`css/` must be byte-identical across the board.** All 10 shipped `css/` files match today; the
  LESS pipeline is deterministic and its vendor inputs are MD5-exact on npm except
  `bootstrap-clockpicker` (VER) and `bootstrap-datetimepicker` (no CSS on npm at all). **If
  `structure.css` or `styles-admin.css` changes digest, the cause is one of those two inputs** —
  identify which before accepting it.

### 8.3 A second oracle exists, and it is nearly gone

`NOTES-static-assets.md` §0 names three Grunt-built 652-file trees outside this module. **Two have
already been overwritten by a post-Vite build** — `openam-server-only/target/XUI` and
`openam-server-only/target/OpenAM-ServerOnly-16.2.0-SNAPSHOT/XUI` now hold 273 files with **no
`libs/`**. One survives:

```
OpenAM/openam-server/target/OpenAM-16.2.0-SNAPSHOT/XUI
```

Verified against `PHASE1-TREE.md`: **652 files, 0 missing, 0 extra, 639/652 md5-identical**, and
**all 50 `libs/` files byte-identical**. The 13 that differ are the known stale-commons set
(`main.js` + `.map`, `oauthReturn.html`, 10 `org/forgerock/commons/**`,
`templates/common/LoginTemplate.html`).

This confirms `PHASE1-TREE.md`'s `libs/` digests independently and gives 4.7 a live tree to diff a
candidate `libs/` against file by file:

```bash
diff <(cd OpenAM/openam-server/target/OpenAM-16.2.0-SNAPSHOT/XUI && find libs -type f | sort | xargs md5sum) \
     <(cd OpenAM/openam-ui/openam-ui-ria/target/compiled && find libs -type f | sort | xargs md5sum)
```

**It dies on the next `mvn clean` of `openam-server`.** Copy it somewhere safe before doing
anything that could rebuild that module.

---

## 9. THE TWO OPEN DECISIONS `LIBS-INVENTORY.md` §12 ASSIGNS TO THIS TASK

Presented with the evidence needed to settle them. Both are cheap; neither is decided here.

### §12.5 — the dead `jquery.qrcode` `dependencyManagement` entry

`OpenAM/pom.xml:914–920`, `commons.ui.libs:jquery.qrcode:0.11.0:min:js`. Confirmed: zero
`<dependency>` references it anywhere in the tree, and it is **absent from `~/.m2`** (the `qrcode`
directory there is #52 `qrcode-generator`, a different artifact). Neither choice affects a build.

- **Delete** — 7 lines, and it makes `OpenAM/pom.xml` free of `commons.ui.libs` entirely, which is
  this task's stated goal. **Recommended**, on the grounds that leaving a dangling coordinate to a
  groupId the change is retiring is the kind of residue the next reader has to re-investigate.
- **Leave** — zero risk, zero benefit.

### §12.6 — the six dead shipped-but-unbound files

From inventory §9; all six confirmed present in `target/XUI/libs` and in `PHASE1-TREE.md`.

| File | Bytes | Why it is dead |
|---|---:|---|
| `backgrid-paginator.min-0.3.5-min.js` | 3,815 | superseded by the `-custom` file; `main.js` binds `backgrid.paginator` to the custom one |
| `jsoneditor-0.7.9-min.js` | 125,002 | superseded by `jsoneditor-0.7.23-custom.js`; `main.js` binds `jsonEditor` to the custom one |
| `selectize-0.12.1-min.js` | 37,122 | superseded by `selectize-non-standalone-0.12.1-min.js` — **byte-identical**, `7a8aec7b…` both |
| `handlebars-4.7.7-min.js` | 80,257 | declared only "to fix the processing dependencies in the release build"; all three main files bind the non-min `handlebars-4.7.7.js`. Also mislabelled — it is really 4.7.6 |
| `dragula-3.6.7-min.js` | 11,368 | arrives via commons; `grep -ri dragula src/main/js` → zero references |
| `jquery.placeholder-2.0.8.js` | 5,297 | arrives via commons; in no `paths` block |

Total **262,861 B**, 13.3% of the 1,970,218 B `libs/` tree.

- **Drop all six** — the tree shrinks by 6 files, `PHASE1-TREE.md` gains a permanent −6 MISSING
  delta that every later task must carry and re-explain, and two npm dependencies
  (`jquery-placeholder`, one of the two `backgrid-paginator` routes) never need adding. Cheapest
  supply chain. *Caveat: "unbound in `main.js`" is not the same as "unreachable" —
  `AppConfiguration.js` names modules by string and `PHASE1-TREE.md` §4 records that the reachable
  set is not closed at build time, and operators may drop their own module into a deployed `/XUI`.
  A `grep` over `src/main/js`, `themes/` and the `e2e/` specs for each of the six should be run
  before dropping, and it has not been run here.*
- **Port all six** — parity with `PHASE1-TREE.md` at zero delta, which keeps the acceptance diff
  clean for 4.8 and group 5. Costs 6 npm dependencies carried purely for dead weight, one of them
  (`bootstrap3-dialog`/`jquery-placeholder`) a forced version bump.
- **Split** — drop the four that are provably superseded by another file *in the same tree*
  (`backgrid-paginator.min`, `jsoneditor-0.7.9`, `selectize-0.12.1`, `handlebars-4.7.7-min`), port
  the two that are merely unreferenced (`dragula`, `jquery.placeholder`). Defensible, but produces
  a −4 delta that still has to be explained, for less benefit than dropping all six.

**Whichever is chosen, state it in the change's notes as a deliberate delta**, or 4.8's acceptance
diff will read as a regression.

---

## 10. SURPRISES WORTH CARRYING FORWARD

- **`libs/react-dom-15.2.1-min.js` is 709 bytes and contains no ReactDOM.** It is a UMD shim whose
  entire body is `function(e){return e.__SECRET_DOM_DO_NOT_USE_OR_YOU_WILL_BE_FIRED}` over
  `require("react")` / `define(["react"], …)` / `window.React`. The implementation lives inside
  `react-15.2.1-min.js` (147,398 B). The inventory's MD5-exact verdict against
  `react-dom@15.2.1`'s `dist/react-dom.min.js` is correct — that is genuinely what React 15
  published. **Consequence:** `react` and `react-dom` must be moved as a pair, at the same version,
  and any attempt to take `react-dom` from a newer major while leaving `react` at 15 yields a
  `ReactDOM` that is `undefined` at runtime with no build error. `react-dom` is also injected as
  `window.ReactDOM` by the synthetic `reactSelectDep` module.
- **`selectize-0.12.1-min.js` and `selectize-non-standalone-0.12.1-min.js` are the same 37,122
  bytes** (`7a8aec7b…`) under two artifactIds, and npm's *actual* standalone build
  (`dist/js/standalone/selectize.min.js`) is neither. `main.js` binds `selectize` to the
  `-non-standalone` file. One npm dependency, one file, one alias — do not port both.
- **`target/XUI` is itself an acceptance oracle and the standard safety advice destroys it.**
  `vite.config.js:259–261` and `NOTES-static-assets.md` §0 both treat it as the second oracle for
  4.4–4.8. Nothing writes it any more — Vite stages LESS in `target/css-composed` specifically to
  avoid it, and `grunt copy:compose` is the only producer. It is frozen at the last Grunt build
  (2026-08-18). **`rm -rf target`, the sanctioned alternative to `mvn clean`, deletes it**, and it
  cannot be regenerated without reverting to Grunt. Copy it out before any `rm -rf target`.

---

## 11. WHAT WAS NOT RUN, AND WHY

- **No `mvn` command of any kind was executed** — not `clean`, not `package`, not `-am`, not
  `clean-external`. This was an analysis task and the built trees from 2026-08-18 and 2026-08-27
  answered every question.
- `~/.m2/repository/org/openidentityplatform/commons/ui/libs` holds **57 artifactId directories**,
  unchanged. They are published to no repository; `clean-external` deletes them and only a CDN
  round trip restores them — which, per §7, may not return the same bytes.
- Both `node_modules/@openidentityplatform/ui-commons` and `…/ui-user` are present.
- The registry was **not** queried. Every npm name, version and evidence class in §3 is quoted from
  `LIBS-INVENTORY.md` §2 rather than re-derived, as instructed.

## 12. COULD NOT DETERMINE

- **Whether the 6 Font Awesome font files in `font-awesome@4.5.0`'s npm tarball are byte-identical
  to the GitHub-zip copies.** Inventory #28 establishes the MD5 match for
  `css/font-awesome.min.css` only. The fonts and `less/variables.less` are asserted to be the same
  release but were not byte-compared, and doing so needs a registry fetch, which this task did not
  make. **Five of those fonts ship verbatim, so a mismatch is a visible digest delta** — compare
  them before accepting §8.2's "css/ must be byte-identical".
- **Whether any of the six §12.6 "dead" files is reachable by string from `AppConfiguration.js`, a
  theme, or an `e2e/` spec.** Not grepped here; §9 says what to run.
- **What a fresh fetch of the four unpinned-`master` artifacts reaching OpenAM would produce**
  (`bootstrap-tabdrop`, `jquery-sortable`, `backgrid.min:less`, and historically `form2js`). The
  URLs are branch refs; the bytes in `~/.m2` are whatever a past build happened to download.
  Inventory §13 records this as a reproducibility hole independent of the npm migration. It is
  also the strongest single argument for finishing this task.

---
---

# PART 2 — WHAT TASK 4.7 ACTUALLY DID

Everything above is the analysis record, written before any file was modified. This part records
the implementation: the decisions taken, what was changed, and the acceptance diff. Where the two
disagree, this part is what happened.

## 13. THE SIX DECISIONS, AS TAKEN

All were put to the change owner rather than assumed. Five were the ones §6, §7, §4.1/§4.2 and
§9 flagged; the sixth surfaced during implementation.

| # | Decision | Taken |
|---|---|---|
| 1 | The no-npm libraries reaching OpenAM (§6.1) — `bootstrap-tabdrop`, `js2form`, `jquery.ba-dotimeout` | **(V) vendor all three** into `src/main/js/libs`, byte-exact |
| 2 | `form2js` (§7) | **(V) vendor the pinned `897ec696…` bytes.** NOT the npm fork — see below |
| 3 | `requirejs` + `base64` (§4.1, §4.2) | **(V) vendor both, byte-exact** |
| 4 | The six dead shipped-but-unbound files (§9 / inventory §12.6) | **Drop all six** |
| 5 | The dead `jquery.qrcode` `dependencyManagement` entry (§9 / inventory §12.5) | **Delete** |
| 6 | `bootstrap-datetimepicker` — npm ships **no** built JS and **no** CSS at all, only `src/` | **Vendor both built files, KEEP the npm dependency declared** so the package still appears in the lockfile and in `npm audit` |

**§12.6 REQUIRES THIS TO BE STATED, SO IT IS STATED HERE: dropping the six dead files is a
DELIBERATE −6 delta against `PHASE1-TREE.md`.** Task 4.8 and group 5 will see six `libs/` paths
permanently MISSING. That is this task's decision, not a regression:

```
libs/backgrid-paginator.min-0.3.5-min.js      3,815 B   superseded by the -custom file
libs/jsoneditor-0.7.9-min.js                125,002 B   superseded by jsoneditor-0.7.23-custom.js
libs/selectize-0.12.1-min.js                 37,122 B   byte-identical duplicate of -non-standalone
libs/handlebars-4.7.7-min.js                 80,257 B   all three entries bind the non-min file
libs/dragula-3.6.7-min.js                    11,368 B   zero references anywhere
libs/jquery.placeholder-2.0.8.js              5,297 B   zero references anywhere
                                            ---------
                                            262,861 B   13.3% of the libs/ tree
```

**The reachability grep §12 recorded as never run WAS run before dropping them**, over
`src/main/js`, `src/main/resources`, `themes/` and `e2e/`, for each of the six: zero hits. The
`main.js` `paths` block (lines 38-79) binds the `-custom` / `-non-standalone` / non-min sibling in
every superseded case.

**CORRECTION, from code review — that grep was incomplete, and two of the six DO have hits.** It
covered the AM tree but not the two `@openidentityplatform` packages, which are composition
sources and ship into the built tree. Both of these exist:

```
ui-commons/amd/org/forgerock/commons/ui/common/util/BackgridUtils.js:17   define([..., "dragula", ...])
                                                                    :46   dragDropInstance = dragula(data.containers, {...})
ui-commons/amd/org/forgerock/commons/ui/common/LoginView.js:17            define(["underscore", "placeholder", ...])
```

**The drop still stands, but the evidence is different from what the paragraph above claims, and
4.8 and group 5 must not inherit the wrong reason.** What actually makes it safe, verified rather
than assumed:

1. **Neither id was ever bound.** `dragula` and `placeholder` appear in no `require.config.paths`
   block anywhere — not in `main.js`, `main-authorize.js` or `main-device.js`, and not in either
   commons package. So both ids resolved to a 404 *before* this change; the two files shipped
   into `libs/` but no loader could reach them under those names. 4.7 removes bytes that were
   already unreachable, and changes nothing about the resolution.
2. **Both holder modules are themselves unreachable in AM.** `BackgridUtils` is superseded by
   AM's own `org/forgerock/openam/ui/common/util/BackgridUtils.js`, which has no `dragula`
   dependency. Commons' `LoginView` is superseded by `main.js:23`, `"LoginView" :
   "org/forgerock/openam/ui/user/login/RESTLoginView"`. Nothing in AM or in either commons
   package requires either commons module by its full path — the only textual hits are the
   modules' own `@exports` docblocks.

So the correct statement is: **two of the six are referenced by a composition source, both
references were already dead, and neither module is reachable in AM.** The other four have no
hits anywhere, including in the commons packages. **This closes could-not-determine #2** — on that
basis, not on "zero hits".

*Method note for whoever repeats this:* a reachability grep in this module must cover
`node_modules/@openidentityplatform/*/amd` and `/www`. They are composition sources. Grepping only
`src/` understates the reference set, which is how this got recorded wrong the first time.

## 14. FILES CHANGED

| File | Change |
|---|---|
| `openam-ui-ria/src/main/assembly/dir.xml` | both `dependencySet` blocks removed (`:js`, and `:css` + `:less`); Font Awesome `fileSet` removed. **The six CodeMirror `fileSet`s kept** |
| `openam-ui-ria/pom.xml` | **24** `commons.ui.libs` `<dependency>` entries removed (20 runtime, 4 test), `CodeMirror:zip` kept; `commons.ui:user:zip:www` removed; executions `unpack-forgerock-ui-user-form2js`, `unpack-font-awesome`, `copy-dependencies-test` removed; `font-awesome.version` property removed; three stale comment blocks corrected |
| `openam-ui/pom.xml` | `maven-external-dependency-plugin` cut from **60 `artifactItem`s to 1** (CodeMirror) |
| `OpenAM/pom.xml` | dead `jquery.qrcode` `dependencyManagement` entry removed — **`OpenAM/pom.xml` now contains zero `commons.ui.libs` references** |
| `openam-ui-ria/package.json` | **31 runtime `dependencies` added**; `squirejs` devDependency added; `microtime` override added |
| `openam-ui-ria/package-lock.json` | all 31 pinned with integrity hashes |
| `openam-ui-ria/vite.config.js` | `NPM_LIBRARY_FILES` map (42 entries), `stageNpmLibraries`, `copyLibraries`; `COMPOSITION_SOURCES` gains `target/npm-libs`, loses `target/dependencies-expanded/forgerock-ui-user` |
| `openam-ui-ria/Gruntfile.js` | `buildCompositionDirs` updated to match; guard message updated |
| `openam-ui-ria/karma.conf.js`, `src/test/js/test-main.js` | repointed off `target/dependencies/libs` and `target/test-classes/libs` |
| `src/main/js/libs/` (**+7 files**) | `requirejs-2.3.7-min.js`, `base64-1.0.0-min.js`, `form2js-2.0-769718a.js`, `js2form-2.0-769718a.js`, `bootstrap-tabdrop-1.0.js`, `jquery.ba-dotimeout-1.0-min.js`, `bootstrap-datetimepicker-4.14.30-min.js` |
| `src/main/resources/css/` (**+1 file**) | `bootstrap-datetimepicker-4.14.30-min.css` |

### What was NOT changed, and why

**CodeMirror is untouched — it is task 4.8's decision.** The `CodeMirror:zip` dependency, the
`unpack-codemirror` execution, the six `fileSet`s in `dir.xml` and the one surviving
`artifactItem` in `openam-ui/pom.xml` are all exactly as 4.7 found them. §4.3 named the coupling
and it was honoured: had they gone before 4.8 landed, six files would have vanished and the admin
script editor would have broken.

**Consequences 4.8 inherits, all of them intended:** `target/dependencies` still exists but holds
**6 files instead of 66**; `prepare-working-dir` and composition source #1 still exist to produce
it; and `maven-external-dependency-plugin` — with its `clean-external` goal, the hazard this whole
task is warned about — is **still alive for one artifact**. Deleting it is 4.8's to finish.

## 15. ACCEPTANCE — THE PER-FILE DIGEST DIFF

Procedure exactly as §8.1. Build: `mvn -DskipTests package` from `openam-ui`. **No `mvn clean`
was run, and no `mvn ... -am` from the OpenAM root.** Stale outputs were cleared with
`rm -rf target/{dependencies,dependencies-expanded,npm-libs,compiled,css-composed,transpiled,Font-Awesome-4.5.0}`,
preserving `target/XUI` (the second oracle, §8.3) and `target/npm`.

```
                        before 4.7      after 4.7      expected
target/compiled              273            317         --
  of which libs/               0             44         28 npm + 12 vendored + 4 codemirror
target/dependencies           66              6         codemirror only
MISSING vs PHASE1-TREE       381            337         331 group-5 + 6 deliberate drops  OK
EXTRA                          2              2         the two .map files                OK
DIFFERING                      4             14         4 entry bundles + 8 libs + 2 css  OK
```

**MISSING = 337 is the predicted number exactly.** The 331 that remain are `org/` 303, `config/`
17, `store/` 6, `components/` 5 — group 5's AMD→ESM conversion, untouched by 4.7. The 6 `libs/`
entries are precisely the six dropped in §13, verified by name. **All 46 `libs/` files 4.7 owned
are restored: the `libs/` MISSING count went 50 → 6.**

### The 14 differing files, every one classified

**4 entry bundles — NOT 4.7's, pre-existing, unchanged by this task:** `main.js`, `main.js.map`,
`main-authorize.js`, `main-device.js`. They differed before 4.7 and keep differing until group 5.

**8 `libs/` rows — every one an expected VER or bump, and the set is exactly the one §8.2
predicted** once the vendored and dropped rows are removed from its list of 12:

| file | phase1 | now | Δ bytes | why |
|---|---|---|---:|---|
| `backbone-relational-0.9.0-min.js` | `2282dafb` | `77943a34` | +47,098 | VER — npm publishes no minified build |
| `backgrid.min-0.3.5-min.js` | `248635b0` | `e15b47b4` | +91 | VER — the artifact was a cdnjs re-minification |
| `backgrid-select-all-0.3.5-min.js` | `9cefb2cc` | `16386084` | +7 | VER |
| `bootstrap-clockpicker-0.0.7-min.js` | `28af1dfd` | `d25d9e41` | +369 | VER |
| `bootstrap-dialog-1.34.4-min.js` | `5ce8851d` | `2f87d7b9` | +617 | **bump** — 1.34.4 was never published; `bootstrap3-dialog@1.35.1` |
| `jquery-sortable-0.9.13.js` | `8efebfc0` | `bcab39a5` | +692 | VER — the artifact was fetched from an unpinned `master` ref |
| `qrcode-1.4.4-min.js` | `e259e455` | `6e6189e2` | +36,307 | VER — `qrcode-generator@1.4.4` ships unminified |
| `spin-2.0.1-min.js` | `104d92ce` | `ac2f1a06` | +5,905 | VER — `spin.js@2.0.1` ships unminified |

§8.2 required 28 MD5-exact rows to be byte-identical and they are. **36 of the 44 shipped `libs/`
files are byte-identical to `PHASE1-TREE.md`**, including all four no-npm vendored rows, all
seven other vendored rows, and all four CodeMirror files.

**2 `css/` rows, and §8.2's prediction of the cause was WRONG in an instructive way.** It named
`bootstrap-clockpicker` and `bootstrap-datetimepicker` as the only two possible causes. The actual
causes are the two **version bumps**, and they were measured, not guessed:

```
css/structure.css      89,221 -> 87,570 B   (-1,651)
css/styles-admin.css  158,377 -> 156,728 B  (-1,649)

bootstrap-dialog-1.34.4-min.css   1,956 -> 1,837 B   (-119)     1.34.4 -> 1.35.1
titatoggle-1.2.6-min.css         20,327 -> 18,808 B  (-1,519)   1.2.6  -> 1.2.14
bootstrap-clockpicker-0.0.7-min.css 3,135 -> 3,137 B (+2)       VER
bootstrap-datetimepicker / selectize / react-select / font-awesome:  byte-identical
```

Both bumped stylesheets are `@import`ed by **both** entries — `structure.less:21,27` and
`styles-admin.less:21,29` — which is why both outputs moved by nearly the same amount.
`bootstrap-datetimepicker` is not a cause because decision 6 vendored it byte-exact; the
`clockpicker` +2 B reaches `styles-admin.css` only. **The other 8 shipped `css/` files, including
all five Font Awesome fonts and `bootstrap-3.3.5-custom.css`, are byte-identical.**

### Distributable contract

`openam-ui-ria-16.2.0-SNAPSHOT-www.zip` was rebuilt and its contents are **exactly**
`target/compiled` — 317 files, 44 under `libs/`, no path renamed, no hashed filename. D8 and the
"Distributable artifact contract" requirement hold unchanged.

## 16. FORM2JS — WHAT SHIPS, AND WHY IT IS NOT A BEHAVIOUR CHANGE

`libs/form2js-2.0-769718a.js` ships as **`897ec696be559d5bb804b0803616efc5`, 10,160 B** — verified
byte-identical to `PHASE1-TREE.md:256` in the post-change tree. Its sibling
`libs/js2form-2.0-769718a.js` ships as **`fc83dc6af4259d45638391faa8fc9b29`, 9,118 B**, also
identical.

**The npm package does not match, because there is no npm package to match.**
`maxatwork/form2js` @ `769718a` was never published; npm `form2js@1.0.0` is `kirill-zhirnov`'s
unrelated fork. Route (a) and route (b) do not exist for this file. It is vendored.

**There is therefore NO behaviour change behind `RESTLoginView` or the five self-service views.**
The exact bytes that shipped before ship now. This is strictly better than the state 4.7 inherited:
the source is no longer a CDN fetch whose bytes can change under a fixed version string, so the
drift channel 3.7 caught — `3095c47f…`/12,656 B against `897ec696…`/10,160 B, seven lines that
rewrite `foo[bar]` to `foo.bar` during serialisation — is closed permanently for this file.
`unpack-forgerock-ui-user-form2js` retired with it, and with that the last consumer of
`commons.ui:user:zip:www`.

## 17. WHAT THE npm CHANNEL MADE VISIBLE

`npm audit --omit=dev` now reports **18 advisories** against the runtime libraries AM ships,
including `handlebars` and `backgrid` at critical. **4.7 introduced none of them.** They are the
same library versions AM shipped before; they were simply unauditable while they were
hand-published Maven binaries, which is the failure the
*Runtime libraries are managed package dependencies* requirement exists to prevent. Fixing them
means version bumps, which are behaviour changes and belong to their own change — inventory §10
already scopes the four largest.

All 31 runtime dependencies carry an exact resolved version and an integrity hash in
`package-lock.json`, satisfying the requirement's *Reproducible dependency resolution* scenario.

**Task 4.8 adds a 19th advisory and a 32nd dependency, on the same terms.** `codemirror@4.10.0`
carries `GHSA-4gw3-8f77-f72c` (moderate, ReDoS, affects `<5.58.2`). It is the nineteenth instance
of exactly the pattern above: the same bytes AM already shipped, previously unauditable because
they arrived as `commons.ui.libs:CodeMirror:zip:4.10`. **It is deferred, not overlooked** — 4.10.0
to 5.58.2 is a major-version jump behind a script editor that **no e2e spec covers**, so the
upgrade is a behaviour change with no regression net and belongs with the other eighteen in their
own change. No CI workflow gates on `npm audit`, so nothing breaks in the meantime. This paragraph
is the durable record of that deferral; §10 of the inventory scopes the bumps.

## 18. THINGS THE NEXT TASK SHOULD KNOW

- **`sifter@0.4.1` has TWO packaging bugs, and both are overridden.** It arrives whether or not it
  is declared directly, because `selectize@0.12.1` depends on `sifter@^0.4.0`, so neither is
  avoidable by dropping a direct dependency. `package.json` carries
  `"overrides": { "sifter": { "microtime": "3.1.1", "node-csv": "0.1.2" } }`:
  - **`microtime`** — a native module declared as a *runtime* dependency. It fails to compile on
    Node 22. 3.1.1 resolves through `node-gyp-build` and installs a prebuilt binary.
    **Without the override a plain `npm install` fails outright.** Do not "fix" it with
    `--ignore-scripts`, which would break `esbuild`'s postinstall on a clean machine. *Caveat for
    CI:* the prebuilds cover glibc linux-x64/arm/arm64, darwin-x64/arm64 and win32. A **musl**
    runner (Alpine) has no prebuild and falls back to `node-gyp`, so it needs a compiler.
  - **`node-csv`** — declared as `https://github.com/voodootikigod/node-csv/tarball/master`, an
    **unpinned VCS ref in the production tree**. Found in code review. This is precisely the
    hazard 4.7 exists to remove — a coordinate whose bytes change under a fixed reference — and it
    is also a hard install-time dependency on a third-party VCS host: when `master` moves the
    recorded integrity stops matching, and when the repo goes away the install fails permanently.
    Overridden to the registry release `0.1.2`. **Nothing ships from it**: `node-csv` is required
    only by `node_modules/sifter/bin/sifter.js:25`, the CLI binary. `sifter`'s `main` is
    `./sifter.js` and what the build stages is `sifter/sifter.min.js`, so it is unreachable from
    browser bytes either way.

  Both are scoped under `sifter` rather than global, so they cannot silently retarget an unrelated
  future dependency of the same name. **After the override the lockfile has exactly one
  non-registry coordinate left, and it is dev-only** — `eslint-config-forgerock`, a local `file:`
  tarball that predates this change. Zero production entries lack an integrity hash.
- **`.gitattributes` had to be amended, or vendoring would have silently failed at `git add`.**
  Caught at commit time, not by any build. This module's `.gitattributes` carries `* text=auto`
  and `*.js text`, and the repo runs `core.autocrlf=input` — so git normalises line endings into
  the stored blob. **`form2js` and `js2form` are CRLF upstream** (349 and 330 lines), so the blobs
  git was about to store were `8c993db9…` and `929bbcaa…` rather than the pinned `897ec696…` and
  `fc83dc6a…`. The working tree would have kept building correctly; **a fresh clone would not**,
  and its acceptance manifest would have shown two `libs/` rows DIFFERING for no reason anyone
  could trace back to a code change. That undoes decision 2 — byte-parity is the entire reason
  those two are vendored rather than taken from npm. Fixed with `src/main/js/libs/** -text` plus
  the one stylesheet, `-text` rather than `binary` so they stay diffable, with `README.md` and
  `popover-clickaway.js` put back under normal rules because they are ours. Verified by checking
  the index out to a scratch tree: both files come back byte-identical to `PHASE1-TREE.md`.
  **Anything vendored here in future needs the same treatment**, and the check is
  `git cat-file -p :<path> | md5sum` against the worktree — not `git status`, which says nothing.
- **`copyLibraries` THROWS on a duplicate `libs/` path; it does not resolve one.** Added in code
  review. The three suppliers are disjoint — 28 npm-staged + 12 vendored + 4 CodeMirror = 44
  distinct — so the strictness is free today. It exists because after 4.7 the `dir.xml` descriptor
  emits a strict *subset* of what it used to, so a stale `target/dependencies` from a pre-4.7
  build still holds the 60 retired files, they sort *after* `target/npm-libs`, and under the old
  last-wins rule they would silently win: retired Maven bytes shipped, the six dropped files
  resurrected, exit 0. **A file count cannot see this** — the count goes *up*, to the pre-4.7
  number. If 4.8 or 8.3 needs a real override in `libs/`, make it explicit in `copyLibraries`
  rather than implicit in the order of `COMPOSITION_SOURCES`.
- **`assertVendoredVersions` guards the one drift channel vendoring leaves open.** Added in code
  review. `eonasdan-bootstrap-datetimepicker` is a declared dependency contributing zero bytes
  (npm ships `src/` only), so a version bump would move the pin and leave the vendored built files
  behind with no build signal. The check compares the declared version against the upstream
  `version :` header in each vendored file. It covers only that library, because it is the only
  vendored file with an npm dependency behind it to compare against.
- **OPEN, and worth one CI run before this range is considered settled:** the pom's `npm-install`
  execution runs a plain `npm install`, with no `--legacy-peer-deps`, before `npm-install-commons`
  adds the flag. Every one of the 31 new packages' declared peers admits `react@15.2.1`
  (`react-bootstrap` `>=0.14.0`, `react-select` and `react-input-autosize` `^0.14 || ^15`), so
  strict peer resolution should succeed — but that has only been observed against a warm
  `node_modules`, never from empty on a clean machine.
- **`npm install` still prunes the two `@openidentityplatform` packages** — `--no-save`, per
  `pom.xml`. This was hit during implementation. Restore with
  `npm install target/npm/ui-commons.tgz target/npm/ui-user.tgz --no-save --legacy-peer-deps`.
- **`target/dependencies` is not cleaned by the assembly plugin.** The first build after this
  change composed **50** `libs/` files instead of 44, because 60 stale files from the previous
  build were still sitting there and `copyLibraries` walks that directory. `rm -rf` the stale
  output directories before trusting a manifest diff — and **do not `rm -rf target` wholesale**,
  because that destroys `target/XUI`, the §8.3 oracle, which nothing regenerates any more.
- **`vite.config.js` DOES have a `check-composition-sources` equivalent** — `assertSourcesPresent`,
  added by 4.4, covering every entry in `COMPOSITION_SOURCES`. §2 of this file says it does not;
  §2 is wrong on that point. It means a missing `target/npm-libs` or `target/dependencies` fails
  loudly rather than silently, and `stageNpmLibraries` adds a second, more specific guard that
  names the individual library file that could not be found.
- **QUnit was dead too.** The `qunit:js` and `qunit:css` test artifacts had zero references
  anywhere in the module — the Karma frameworks are `mocha` and `requirejs`. They were dropped
  rather than replaced; only `squirejs` (used by 10 specs) and `sinon` (already a devDependency,
  at 1.17.6 rather than the artifact's 1.15.4) were rewired.
- **The Karma harness is dormant and could not be executed** — `npm test` has been a stub since
  4.1 and the migration to Vitest is group 9 (D12). `karma.conf.js` and `test-main.js` were
  repointed off the two Maven-fed directories so they stay coherent, and every path they now name
  was verified to exist, but no Karma run confirms it.
- **`npm run build:grunt` now needs a Vite build to have run first.** `target/npm-libs` is staged
  by `vite.config.js`, and Grunt has no step that creates it. Grunt stopped being the production
  pipeline in 4.1 and is deleted in group 5, so this was not worth a second copy of the file map.
  `Gruntfile.js`'s guard message says so explicitly.

## 19. COULD NOT DETERMINE — UPDATED

- ~~Whether the Font Awesome npm tarball matches the GitHub zip~~ — **CLOSED.** All 8 files
  compared: `css/font-awesome.min.css`, `less/variables.less` and all 6 fonts are **byte-identical**.
  Font Awesome moved to npm at zero digest delta, and the five shipped fonts prove it in the
  acceptance diff.
- ~~Whether any of the six dead files is reachable by string~~ — **CLOSED, but not by "zero
  hits".** The first grep missed the two commons packages, and `dragula` and `placeholder` both
  have hits there. Both references were already dead — neither id is bound in any
  `require.config.paths` block, and both holder modules are superseded in AM. See §13 for the
  corrected evidence and the method note.
- **Still open: what a fresh fetch of the unpinned-`master` artifacts would produce.** Now moot
  for every artifact except CodeMirror, which is the only one left. `jquery-sortable`'s +692 B
  difference is the visible trace of exactly this problem: the Maven artifact was fetched from a
  branch ref, so nobody can say which upstream commit the bytes AM shipped came from. The npm
  package is pinned by version and integrity hash and cannot drift.
