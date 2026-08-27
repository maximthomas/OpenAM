# NOTES-static-assets.md — task 4.4 discovery

What the XUI build must copy verbatim, where each file comes from, and what the Vite
equivalent of Grunt's composition step is.

Produced by task 4.4 discovery. **No source file, pom, `package.json`, `Gruntfile.js` or
`vite.config.js` was modified to produce it.**

## 0. Preflight

| Check | Result |
|---|---|
| `target/XUI` exists, holds the Grunt composition tree | **719 files** — intact |
| `PHASE1-TREE.md` exists | yes, 75,551 bytes |
| `PHASE1-TREE.md` committed | yes — `ca2bfde45d` *XUI: add Vite and the npm scripts behind it* |
| `node_modules/@openidentityplatform/ui-commons` | present, `3.2.0-SNAPSHOT` |
| `node_modules/@openidentityplatform/ui-user` | present, `3.2.0-SNAPSHOT` |
| `NOTES-vite-build.md` exists | yes, 46,358 bytes |

`target/compiled` was **not** preflighted. It holds Vite's 6 files since 4.1
(`main.js`, `main-authorize.js`, `main-device.js` + 3 `.map`), not Grunt's 652.

### A second, better oracle exists — and it validates the manifest

`target/compiled` is gone, but **three Grunt-built copies of the shipped tree survive**
outside this module and were never touched by 4.1:

- `OpenAM/openam-server-only/target/XUI`
- `OpenAM/openam-server-only/target/OpenAM-ServerOnly-16.2.0-SNAPSHOT/XUI`
- `OpenAM/openam-server/target/OpenAM-16.2.0-SNAPSHOT/XUI`

Each holds **exactly 652 files**. Against `PHASE1-TREE.md`: **0 missing, 0 extra, 639/652
md5-identical**. The 13 that differ are a stale-commons artefact, not manifest error — all 13 are
commons-sourced (`main.js` + `.map`, `oauthReturn.html`, 10 `org/forgerock/commons/**`,
`templates/common/LoginTemplate.html`), i.e. a tree built before the commons version pin
(`NOTES-commons-version-pin.md`). **Every one of the three LESS outputs matches the manifest
byte-for-byte in these trees.** PHASE1-TREE.md is trustworthy; treat these trees as a
second oracle for 4.4–4.8 while they survive (they die on the next `mvn clean` of those modules).

---

## 1. THE PROVENANCE TABLE

`compositionDirectory = "target/XUI"` (`Gruntfile.js:39`). `buildCompositionDirs`
(`Gruntfile.js:57-68`), in order — **last entry wins**:

```
1  target/dependencies                                  (dir.xml assembly)
2  node_modules/@openidentityplatform/ui-commons/amd    (npm, minus root package.json)
3  node_modules/@openidentityplatform/ui-commons/www
4  node_modules/@openidentityplatform/ui-user/amd       (npm, minus root package.json)
5  node_modules/@openidentityplatform/ui-user/www
6  target/dependencies-expanded/forgerock-ui-user       (form2js only — 1 file)
7  src/main/js               \ mavenProjectSource(".") — "must come last so that it
8  src/main/resources        /  overwrites any conflicting files!"
```

### Full composition tree — all 719 files, by output directory and winning source

| output dir | deps | cmn/amd | cmn/www | usr/amd | usr/www | deps-exp | src/main/js | src/main/resources | total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `(root)` | – | – | 2 | – | – | – | 3 | 2 | 7 |
| `components/` | – | – | – | – | – | – | 5 | – | 5 |
| `config/` | – | 5 | – | 2 | – | – | 10 | – | 17 |
| `css/` | 20 | – | 37 | – | – | – | – | 21 | 78 |
| `images/` | – | – | 9 | – | – | – | – | 10 | 19 |
| `libs/` | 44 | – | – | – | – | 1 | 5 | – | 50 |
| `locales/` | – | – | – | – | – | – | – | 3 | 3 |
| `org/` | – | 60 | – | 12 | – | – | 231 | – | 303 |
| `partials/` | – | – | 1 | – | 4 | – | – | 24 | 29 |
| `store/` | – | – | – | – | – | – | 6 | – | 6 |
| `templates/` | – | – | 14 | – | 22 | – | – | 162 | 198 |
| `themes/` | – | – | – | – | – | – | – | 4 | 4 |
| **TOTAL** | **64** | **65** | **63** | **14** | **26** | **1** | **260** | **226** | **719** |

### Non-JavaScript only — 335 files

| output dir | deps | cmn/www | usr/www | src/main/resources | total |
|---|---:|---:|---:|---:|---:|
| `(root)` | – | 2 | – | 2 | 4 |
| `css/` | 20 | 37 | – | 21 | 78 |
| `images/` | – | 9 | – | 10 | 19 |
| `locales/` | – | – | – | 3 | 3 |
| `partials/` | – | 1 | 4 | 24 | 29 |
| `templates/` | – | 14 | 22 | 162 | 198 |
| `themes/` | – | – | – | 4 | 4 |
| **TOTAL** | **20** | **63** | **26** | **226** | **335** |

**The two `amd/` directories contribute zero non-JS files** — they are 79 `.js` files and nothing
else. Every non-JS byte from npm comes from the two `www/` directories.

**Verification: 0 orphans and 0 content mismatches.** Every one of the 335 non-JS files in
`target/XUI` resolves to a named source, and every one is md5-identical to the winning source's
copy. The composition is fully explained.

### Where two sources supply the same path — all 7 collisions in the tree

Resolved by `buildCompositionDirs` order; the later entry overwrites.

| path | supplied by | winner | why |
|---|---|---|---|
| `libs/form2js-2.0-769718a.js` | `target/dependencies`, `deps-expanded` | **deps-expanded** | deliberate — `Gruntfile.js:60-63` says the `commons.ui.libs` Maven artifact is a *different build* of the same library and the zip's copy is the one AM ships. This is task 3.7's finding: **identical counts, different bytes.** |
| `libs/lodash-3.10.1-min.js` | `target/dependencies`, `src/main/js` | **src/main/js** | vendored into source by 4.3 |
| `locales/en/translation.json` | `user/www` (12,415 B) | **src/main/resources** (67,685 B) | AM's is 5.5× larger — a superset |
| `templates/user/UserProfileTemplate.html` | `user/www` | **src/main/resources** | AM override |
| `templates/user/process/registration/userDetails-initial.html` | `user/www` | **src/main/resources** | AM override |
| `templates/user/process/reset/resetStage-initial.html` | `user/www` | **src/main/resources** | AM override |
| `templates/user/process/reset/userQuery-initial.html` | `user/www` | **src/main/resources** | AM override |

The last five are exactly the "five AM-over-commons overrides" of `NOTES-npm-commons.md` §4 —
**independently rederived here from the composition tree and in agreement.**
`ui-commons` and `ui-user` have zero overlapping paths, so their relative order cannot matter.

---

## 2. THE COMMONS ASSETS

### Composed vs shipped — the two numbers differ and it matters

| package dir | supplied | wins composition | **ships** | dropped |
|---|---:|---:|---:|---:|
| `ui-commons/amd` | 65 | 65 | 65 (all `.js`) | 0 |
| `ui-commons/www` | 63 | 63 | **27** | 36 |
| `ui-user/amd` | 14 | 14 | 14 (all `.js`) | 0 |
| `ui-user/www` | 31 | 26 | **26** | 0 |

**89 non-JS files arrive from the two npm packages; 53 of them ship.** The 36 that do not are
`ui-commons/www/css/**/*.less` — LESS partials `@import`ed into the three entry stylesheets and
never emitted individually (§3).

### The 53 that ship, at their output paths

| output path | from | count |
|---|---|---:|
| `templates/**` | `ui-commons/www` 14 + `ui-user/www` 22 | **36** |
| `partials/**` | `ui-commons/www` 1 + `ui-user/www` 4 | **5** |
| `locales/**` | — | **0** |
| `images/**` | `ui-commons/www` | 9 |
| `css/common/structure/config.json` | `ui-commons/www` | 1 |
| `favicon.ico`, `oauthReturn.html` (root) | `ui-commons/www` | 2 |

**Locales: zero.** `ui-user/www` supplies exactly one — `locales/en/translation.json` — and AM's
own copy overwrites it. All 3 shipped locale files are `src/main/resources`. Do not build a
Vite copy rule that assumes commons contributes locales; it contributes none, and a rule that
copies commons' locales *after* AM's would silently regress translation coverage by 55 kB.

### Options for reproducing this under Vite — NOT DECIDED

The hard constraint is `ui-customization` spec.md:109-127, *Override of templates and partials by
a theme*: a theme MAY declare an asset path, and the UI looks for **each** template and **each**
partial under that path first, falling back silently to the unprefixed path. That requires these
to remain **individually addressable files at stable paths**. Anything that concatenates,
inlines, hashes or bundles them breaks the override mechanism, and it breaks it *silently* —
the fallback path is taken and the page still renders.

| # | Option | Cost |
|---|---|---|
| **A** | `vite-plugin-static-copy` | New devDependency (not installed). Declarative `targets` with globs and `rename`. Handles multi-source fan-in naturally. Runs in `writeBundle`, so it survives `emptyOutDir`. Cost: one more dep on a build that 3.x spent effort pruning, and the plugin's own glob semantics become part of the contract. |
| **B** | Build-time Node script, `prebuild`/`postbuild` npm script | No new dep. Total control; can reproduce `buildCompositionDirs` order exactly, including the 7 collisions, using the same last-wins rule. Cost: it is a second build system living beside Vite — `vite build` alone stops being sufficient, `vite dev` does not run it, and 4.10's dev-server task inherits that hole. |
| **C** | Import them into the module graph (`import.meta.glob`) | **Actively breaks the contract.** Turns runtime-fetched paths into build-time module ids, subjects them to `assetFileNames` hashing, and removes the theme-override fallback entirely — the UI would resolve a template at build time, so a theme's override at `themes/acme/templates/...` could never be found. Also changes 229 HTML fetches into bundled strings. **Do not.** |
| **D** | `publicDir` | Verbatim, unhashed, correct semantics — exactly the shape wanted. But `publicDir` is **a single directory**, and these assets fan in from **four** places (2 npm packages + `src/main/resources` + `target/dependencies`) with a defined override order. Requires a pre-staging step that composes them first — i.e. option B wearing a different hat, and then `publicDir` points at the staged tree. Also: `vite.config.js:466` sets `publicDir: false` deliberately, with a note that turning it on by accident silently changes the shipped layout. |
| **E** | Inline Rollup plugin in `vite.config.js` (`writeBundle` + `fs.cp`) | No new dep, no second entry point, runs inside `vite build`. ~30 lines. Cost: hand-rolled; needs its own ordering logic for the 7 collisions; `configureServer` middleware needed separately for dev. |
| **F** | Keep the copy in Maven (`maven-resources-plugin`) after `npm-build` | Zero JS-side change; Maven already knows all four source locations. Cost: **the output is no longer reproducible from `npm run build:production`**, which is what 4.1's whole pipeline flip was for; and D14/4.10's dev server would have no equivalent. |

**Note on availability.** The two packages are installed by `pom.xml:481`
(`npm install target/npm/ui-commons.tgz target/npm/ui-user.tgz --no-save --legacy-peer-deps`)
with **`--no-save`**, so they are absent from `package.json` and **any bare `npm install` prunes
them** (`NOTES-npm-commons.md` §5, "The guard"). Whichever option is chosen, referencing
`node_modules/@openidentityplatform/*/www` from `vite.config.js` inherits that fragility.
Grunt defends with a `check-composition-sources` task that fails and names the missing
directories; **Vite has no equivalent, and 4.4 should add one** — otherwise a pruned
`node_modules` yields a green `vite build` that has silently dropped 53 files.

---

## 3. THE LESS QUESTION

### The three files, their outputs, and who names them

`Gruntfile.js:222-244`, `less:compile`:

| LESS source (in `target/XUI/css/`) | output (in shipped tree) | bytes | named by |
|---|---|---:|---|
| `css/structure.less` | `css/structure.css` | 89,221 | `ThemeConfiguration.js:23` (**default**) **and** `:67` (`fr-dark-theme`) |
| `css/theme.less` | `css/theme.css` | 10,690 | `ThemeConfiguration.js:23` (**default**) |
| `css/styles-admin.less` | `css/styles-admin.css` | 158,377 | **`Constants.js:60`** `DEFAULT_STYLESHEETS`, *not* ThemeConfiguration |

- **default theme** — `stylesheets: ["css/bootstrap-3.3.5-custom.css", "css/structure.css", "css/theme.css"]`. Two of the three LESS outputs, plus a verbatim-copied vendor CSS.
- **`fr-dark-theme`** (the shipped `dark` theme) — `["themes/dark/css/bootstrap.min.css", "css/structure.css", "themes/dark/css/theme-dark.css"]`. It names two of its own files **but still shares `css/structure.css`**. The prompt's framing ("the shipped `dark` theme names its own") is *half* right: it replaces bootstrap and theme, and *reuses* structure. Dropping `css/structure.css` breaks the dark theme too, not just the default.
- **`css/styles-admin.css` is referenced by neither theme.** It is `Constants.DEFAULT_STYLESHEETS` — the admin console's stylesheet set. It is the largest of the three and it is invisible to anyone grepping `ThemeConfiguration.js`.

### Can Vite emit them at the same paths, same names, no hash, no inlining, no renaming?

**Paths and names: yes, but not by default and not for free.**

- `build.rollupOptions.output.assetFileNames` is currently `"assets/[name]-[hash].[ext]"` (set by 4.2). Any CSS entering the graph lands at `assets/structure-<hash>.css`. The fix is the **function form**, returning `"css/[name].[ext]"` for these three (a flat `"[name].[ext]"` would drop the `css/` prefix and break all three references).
- `build.cssCodeSplit` defaults `true`; setting it `false` merges all CSS into one `style.css` — **actively wrong here**, because the three are *alternative* stylesheet sets (login vs admin vs dark), not additive. Merging would apply admin console styling to login pages.
- Declaring the three `.less` files as `rollupOptions.input` entries makes Vite 5 emit `<name>.css` — but it also emits a **stray empty `.js` chunk per CSS entry**, which would be 3 files the manifest does not have.

**Bytes: no. Not reproducible, and I verified this rather than asserting it.**

I recompiled all three from `target/XUI` with `less` 4.4.1 using Grunt's exact options
(`compress: true`, `plugins: [new (require("less-plugin-clean-css"))({})]`, `relativeUrls: true`):

| output | md5 (recompiled) | md5 (PHASE1-TREE.md) | |
|---|---|---|---|
| `css/structure.css` | `7859690d4d01a822395378b8b43fe8b6` | `7859690d4d01a822395378b8b43fe8b6` | **exact** |
| `css/theme.css` | `30c3779152a174b221cd8bcf3e873853` | `30c3779152a174b221cd8bcf3e873853` | **exact** |
| `css/styles-admin.css` | `6ebeb312190424bb6f540a9cc2b39ab5` | `6ebeb312190424bb6f540a9cc2b39ab5` | **exact** |

Byte-exact, three ways: manifest digest, on-disk deployed tree, and this recompilation. So the
Grunt LESS step is fully reproducible **with those two options**. Without them it is not:

| variant | `structure.css` bytes | `url()` emitted |
|---|---:|---|
| Grunt-equivalent (clean-css + `relativeUrls`) | 89,221 | `url(./fontawesome/fonts/fontawesome-webfont.eot?v=4.5.0)` |
| `compress` only (no clean-css, no `relativeUrls`) | 89,475 | `url('../fonts/fontawesome-webfont.eot?v=4.5.0')` |
| naive (no options at all) | 130,169 | `url('../fonts/fontawesome-webfont.eot?v=4.5.0')` |

**`relativeUrls: true` is load-bearing, not cosmetic.** Without it, `url()` stays relative to the
*imported* file (`css/fontawesome/css/font-awesome.min.css` → `../fonts/...`). Served from
`css/structure.css`, `../fonts/...` resolves to `/openam/XUI/fonts/fontawesome-webfont.eot` —
which does not exist. **Every Font Awesome icon in the console 404s.** With `relativeUrls`, the
url is rebased to the *entry* file's directory and resolves correctly.

**Good news: Vite already does this rebasing, by a different mechanism.** Vite 5 installs its own
`ViteLessManager` less `FileManager` (`vite/dist/node/chunks/dep-BK3b2jBa.js:37646-37700`) whose
`loadFile` runs `rebaseUrls(resolved, rootFile, …)` — rewriting `url()` in each imported file
relative to the **root** file's directory before Less ever sees it. That is functionally what
`relativeUrls: true` does. So a naive Vite setup does **not** hit the 404. But it then goes
further than Grunt: it resolves those rebased urls into **asset references**, emits the fonts
through `assetFileNames`, and rewrites the `url()` to the hashed output path. Grunt leaves them
as plain relative urls into a verbatim-copied `css/fontawesome/fonts/` tree.

**clean-css is not reproducible.** `less-plugin-clean-css` 1.5.1 wraps clean-css **3.4.28**;
Vite's `build.cssMinify` is `esbuild` (or `lightningcss`). Neither produces clean-css 3.x bytes.
The ~254-byte delta on `structure.css` is structural optimisation clean-css does and `compress`
does not. **Consequence for the 4.4–4.8 acceptance oracle: the three CSS files can be matched
functionally but their md5s cannot be matched, unless the LESS is compiled outside Vite by the
`less` + `less-plugin-clean-css` devDependencies that are still installed.** That is a real,
costed reason to consider keeping LESS out of the Vite graph — record it as a deliberate choice
either way, because otherwise 4.8's diff will show three "unexplained" mismatches.

### Scope: is this 4.4's, or unowned?

**De jure: unowned.** Task 4.4's text is *"Copy `themes/`, `templates/`, `partials/` and
`locales/` into the build output verbatim, unbundled and unhashed (D3)"*. LESS, CSS and `css/`
appear in **no group-4 task text at all** — I checked 4.1 through 4.10.

**De facto: 4.4's, by 4.2's handoff.** `vite.config.js:709-716` states it explicitly:
*"The asset kind it DOES govern is `css/` … the setting below would both relocate them to
`assets/` and hash them the moment 4.4 pulls LESS into the graph. That is the collision 4.4 has
to resolve."* `vite.config.js:468-482` also parks `css.preprocessorOptions.less` with a note
that reaching the LESS files *"is 4.4's problem"*.

**My read: it is 4.4's and 4.4's task text should be amended to say so.** Two reasons. First,
nobody else can take it — 4.5 is index.html, 4.6 is the zip, 4.7 is the Maven unpacks, 4.8 is
CodeMirror; none touches CSS. Second, the failure mode is severe and silent at build time: if
4.4 ships only the four named directories, `css/structure.css`, `css/theme.css` and
`css/styles-admin.css` are simply absent, `vite build` exits 0, and **every page in the UI loads
unstyled** — the default theme, the dark theme and the admin console all at once, because all
three `stylesheets`/`DEFAULT_STYLESHEETS` lists 404. Leaving this between tasks is how it gets
missed.

---

## 4. THE FILES NOBODY LISTS

`PHASE1-TREE.md:53` records 8 root files, and it is the only surviving record of them in this
module. Of the 652 shipped files, **33 are neither JavaScript nor inside
`themes/`/`templates/`/`partials/`/`locales/`** — 32 once `index.html` (4.5's) is set aside.

### The 8 root files

| file | source | what happens if dropped |
|---|---|---|
| `index.html` | `src/main/resources` | the UI does not load at all. **4.5 owns this**; `${version}` → Maven version via `replace:buildNumber`. |
| `main.js` | r.js bundle | 4.2 |
| `main.js.map` | r.js | 4.2 |
| `main-authorize.js` | `src/main/js` | 4.2 |
| `main-device.js` | `src/main/js` | 4.2 |
| **`favicon.ico`** | **`ui-commons/www`** | `ThemeConfiguration.js:28` `icon: "favicon.ico"`; ThemeManager writes it into `<link rel="icon">`. Dropping it → 404 on every page load and a default browser icon. Cosmetic, but it is in the theme contract, so an operator overriding `icon` on a custom theme is relying on the mechanism working. |
| **`oauthReturn.html`** | **`ui-commons/www`** | the OAuth/OIDC popup return page, referenced by commons `org/forgerock/commons/ui/common/util/OAuth.js`. Dropping it **breaks social-login / OAuth redirect completion** — the popup lands on a 404 and never posts back to the opener. Functional, not cosmetic, and not covered by any e2e spec I found. |
| **`timezones.json`** | **`src/main/resources`** | fetched by `$.ajax({url: "timezones.json"})` at `ConditionAttrArrayView.js:90` — the authorization-policy time-condition editor. Dropping it → that editor renders with an empty timezone dropdown. Note the **relative** url: it resolves against the XUI base, so the path is part of the contract. |

### The other 25 nobody names

| group | count | source | if dropped |
|---|---:|---|---|
| `css/structure.css`, `css/theme.css`, `css/styles-admin.css` | 3 | LESS (§3) | **entire UI unstyled** — default theme, dark theme and admin console |
| `css/bootstrap-3.3.5-custom.css` | 1 | `target/dependencies` | default theme's first stylesheet — unstyled UI. Copied verbatim (it is the one `.css` explicitly named in `nonCompiledFiles`) |
| `css/fontawesome/fonts/*` (`.otf`, `.eot`, `.svg`, `.woff`, `.woff2`) | 5 | `target/dependencies` | every icon in the console becomes a tofu box; targets of the `url()` in `structure.css`/`styles-admin.css` |
| `css/common/structure/config.json` | 1 | `ui-commons/www` | a LESS **variable dictionary** (`@gray-base`, `@brand-primary`, …) mirroring `common/forgerock-variables.less`. No runtime consumer — it is tooling/documentation input for operators authoring a custom theme (`themes/dark/config.json` is its sibling and *is* inside `themes/`, so 4.4 already covers that one). Dropping it breaks the documented theme-authoring workflow, not the running UI. |
| `images/**` `.png` | 19 | `ui-commons/www` 9 + `src/main/resources` 10 | see below |

### The images are a trap for any graph-driven approach

**No image is referenced from the compiled CSS.** I checked all three outputs: `url()` count is
6, 0 and 6, and **every one is a Font Awesome font** — zero `.png`, `.jpg`, `.gif` or
`images/` urls in any of them. And in the whole 719-file composition tree, **18 of the 19 images
have no static reference of any kind**; only `images/login-logo.png` is named, twice, in
`ThemeConfiguration.js:33,44`.

They ship because `nonCompiledFiles` contains a blanket `**/*.png`. Consequence: **an approach
that emits only graph-reachable assets drops 18 of 19 images and nothing fails at build time,
and probably nothing fails in e2e either.** They are reached — when they are reached — through
theme config and operator-supplied templates, which are exactly the string-keyed, not-closed-at-
build-time surface `PHASE1-TREE.md` §4 warns about. Copy `images/` wholesale; do not try to
prove which ones are live.

---

## 5. HASHING AND BUNDLING

### Confirmed from PHASE1-TREE.md: no asset carries a content hash today

I scanned all 652 manifest paths. **Not one** matches a hash-suffix pattern
(`-[0-9a-f]{8,}`). The only hex-looking tokens in the whole tree are
`libs/form2js-2.0-769718a.js` and `libs/js2form-2.0-769718a.js` — the same upstream **git sha
baked into a vendored filename**, constant across builds, not a content hash. Version-bearing filenames like
`libs/requirejs-2.3.7-min.js` and `css/bootstrap-3.3.5-custom.css` are likewise upstream version
strings, stable across rebuilds.

Cache-busting is done **globally, not per file**: `index.html:24` carries
`urlArgs: "v=16.2.0-SNAPSHOT"`, which RequireJS appends as a query string to every module it
fetches. That is why every path can be stable — and it is what D4/task 4.9's `resolveAssetUrl`
replaces. **A content hash in a filename is not just unnecessary here, it is incompatible with
the theme-override contract**: an operator dropping `themes/acme/templates/common/FooterTemplate.html`
onto a deployed instance has no way to know a hash.

### The Vite defaults that violate it

| # | Default | What it breaks | Turn it off with |
|---|---|---|---|
| 1 | `build.rollupOptions.output.assetFileNames` — currently **`"assets/[name]-[hash].[ext]"`** (set by 4.2) | Any asset that enters the module graph is **relocated to `assets/` and hashed**. Today the only such assets would be the three LESS outputs and the 5 Font Awesome fonts they `url()`. `css/structure.css` → `assets/structure-a1b2c3d4.css`; the `stylesheets` lists 404. | Function form: `assetFileNames: (info) => …` returning `"css/[name].[ext]"` for the three stylesheets and `"css/fontawesome/fonts/[name].[ext]"` for the fonts. A flat `"[name].[ext]"` is **not** sufficient — it loses the `css/` prefix. |
| 2 | `build.assetsInlineLimit` — **4096** | Assets under 4 kB reached from CSS/JS become **`data:` URIs** and vanish as files. **No active victim today** — the 5 fonts are 66–365 kB, and no image is reached from CSS — but it is a silent default: the first small `url()` anyone adds disappears from the output. | `build.assetsInlineLimit: 0` |
| 3 | `build.cssCodeSplit` — **true** | Emits one hashed CSS file per JS chunk, named after the chunk, not after the LESS entry. Does not produce three fixed names at `css/`. **Setting it `false` is worse**, not better: it merges all CSS into a single `style.css`, and the three stylesheets are *alternative* sets (login / admin / dark), so merging applies admin styling to login pages. | Neither value is right. Either keep LESS out of the graph and compile it separately, or declare three CSS entries and fix the names via (1) — accepting the stray empty `.js` chunk per CSS entry that Vite 5 emits. |
| 4 | `build.cssMinify` — **`esbuild`** | Cannot reproduce clean-css 3.4.28 bytes (§3). Functional parity only. | `build.cssMinify: false` gets closer to nothing; exact parity needs the LESS compiled outside Vite with the existing `less-plugin-clean-css`. |
| 5 | `publicDir` — **`false`** (`vite.config.js:466`) | Nothing outside the module graph is emitted at all — all 234 files in the four named directories, plus `images/`, plus the root statics. | Enable it against a staged tree, or replace with §2 option A/B/E. |
| 6 | `build.emptyOutDir` — **true** | `outDir` is wiped at build start. A copy step that writes in `buildStart` is erased. | Copy in `writeBundle`/`closeBundle`, or `postbuild`. Not a config change — an ordering constraint. |

### The 4.2 note, and where the collision actually is

`vite.config.js:709-716` (read in full). **The task text's implication is wrong and the note is
right.** `assetFileNames` governs *emitted assets*, i.e. things Rollup discovered in the module
graph. `themes/`, `templates/`, `partials/` and `locales/` are fetched by path at runtime, never
imported, never enter the graph — **`assetFileNames` cannot see them and cannot break them.**
They need `publicDir` or a copy plugin, and no `output.*` option is relevant to them.

The asset kind `assetFileNames` **does** govern is **`css/`**. `PHASE1-TREE.md:212-214` ships
`css/structure.css`, `css/styles-admin.css` and `css/theme.css` unhashed under `css/`, and the
current setting would both relocate them to `assets/` and hash them the moment LESS enters the
graph. **I am treating that as this task's, and saying so** — consistent with §3's scope finding.

---

## 6. THE MANIFEST — VERIFIED, NOT REGENERATED

`PHASE1-TREE.md` exists (75,551 B), is **tracked and committed** at `ca2bfde45d`, and is clean in
`git status`. **Nothing was regenerated.** 652 digest lines parsed.

### Ten-entry spot-check against `target/XUI`

`target/XUI` is the **composition** tree, not the shipped one, so derived files are expected to
differ. I sampled 12 to cover both classes; the 10 verbatim-copied assets are the meaningful test.

| # | entry | class | result |
|---|---|---|---|
| 1 | `templates/common/DefaultBaseTemplate.html` | template, `ui-commons/www` | **MATCH** |
| 2 | `partials/form/_JSONSchemaFooter.html` | partial | **MATCH** |
| 3 | `locales/en/translation.json` | locale (AM override wins) | **MATCH** |
| 4 | `themes/dark/css/theme-dark.css` | theme asset | **MATCH** |
| 5 | `themes/dark/images/login-logo-white.png` | theme image | **MATCH** |
| 6 | `images/login-logo.png` | image | **MATCH** |
| 7 | `favicon.ico` | root static, `ui-commons/www` | **MATCH** |
| 8 | `timezones.json` | root static | **MATCH** |
| 9 | `css/bootstrap-3.3.5-custom.css` | vendor CSS, verbatim | **MATCH** |
| 10 | `libs/requirejs-2.3.7-min.js` | vendor JS, verbatim | **MATCH** |
| 11 | `css/structure.css` | LESS **output** | absent — *expected* |
| 12 | `index.html` | version-stamped | differs — *expected* |

**10/10 on verbatim-copied assets.** Both non-matches are derived files with a fully accounted
delta:

- `css/structure.css` is absent from `target/XUI` **by design** — the composition tree holds
  `css/structure.less`; the `.css` is produced by `less:compile` straight into `target/compiled`.
  Reproduced byte-exact in §3.
- `index.html` differs by **exactly 5 bytes** (988 vs 983). `diff` shows a single line:
  `urlArgs : "v=${version}"` → `urlArgs : "v=16.2.0-SNAPSHOT"`. `len("16.2.0-SNAPSHOT") -
  len("${version}") = 15 - 10 = 5`. `replace:buildNumber`, exactly as documented.

### Whole-manifest comparison, for scale

Against `target/XUI`: **313/652 md5-identical**, 289 differ, 50 absent. Every bucket is explained:

| class | match | differ | absent | why |
|---|---:|---:|---:|---|
| static (copy verbatim) | **263** | 1 | 0 | the 1 is `index.html` |
| `libs/**` JS (verbatim) | **50** | 0 | 0 | `babel.options.ignore: ["libs/"]` |
| other JS | 0 | 288 | 46 | Babel-transpiled; the 46 absent are `.jsm`/`.jsx` renamed to `.js` by `transpileJSM` |
| LESS output | 0 | 0 | 3 | §3 |
| sourcemap | 0 | 0 | 1 | `main.js.map`, r.js output |

**Every file the manifest says must be copied verbatim is byte-identical in `target/XUI`, except
the one that is version-stamped.** That is the result 4.4 needs.

Counts alone would not have shown this — task 3.7's lesson (`form2js` differing between two
sources with counts identical either way) is why everything above is md5-based, and it paid off:
the `form2js`/`lodash` collisions in §1 are invisible to a count.

---

## 7. Things that surprised me

1. **`css/fontawesome/fonts/fontawesome-webfont.ttf` is referenced but never shipped.** The
   compiled CSS contains `url(./fontawesome/fonts/fontawesome-webfont.ttf?v=4.5.0)`, the file is
   present in `target/XUI/css/fontawesome/fonts/`, and it is **absent from all 652 manifest
   entries** — because `nonCompiledFiles` lists `.eot .svg .woff .woff2 .otf` and **has no
   `**/*.ttf`**. A pre-existing, harmless-in-practice bug (woff2/woff cover every current
   browser; `.ttf` is the old-Android fallback). It matters to 4.4 for one reason: **a copy rule
   written as a glob over the font directory will ship the `.ttf` and produce a +1 file delta
   against the oracle.** Decide deliberately whether to reproduce the bug or fix it; do not let
   4.8 discover it as an unexplained diff.
2. **`images/navi-next.png` is referenced by code and does not exist anywhere.**
   `org/forgerock/commons/ui/common/components/Breadcrumbs.js:80` emits
   `<img src="images/navi-next.png" …>`. The file is in neither the composition tree nor either
   npm package. A live 404 in the shipped product today, pre-existing and not 4.4's to fix — but
   worth knowing before someone treats a missing-image report as a migration regression.
3. **Three Grunt-built copies of the shipped tree survived 4.1** in `openam-server-only/target/`
   and `openam-server/target/` (§0), each with exactly 652 files and 639/652 matching the
   manifest. `PHASE1-TREE.md` said it "cannot be regenerated once task 4.1 flips the build" —
   true for this module, but these trees are a genuine second oracle for 4.4–4.8, and they are
   the only place the *actual bytes* of `css/structure.css` still exist on disk. They will be
   destroyed by the next `mvn clean` of those modules. Consider copying the 10 `css/` files
   somewhere durable before that happens.
4. Also worth flagging: **36 of the 63 files from `ui-commons/www` never ship** (all `.less`),
   and **`ui-user/www` contributes zero locales** despite shipping one. Both are easy to get
   wrong from a directory listing.

## 8. Confirmations

- Both `@openidentityplatform` packages still installed after this work:
  `node_modules/@openidentityplatform/ui-commons` (`3.2.0-SNAPSHOT`, 200 files, of which
  65 `amd/` + 63 `www/` feed composition) and `node_modules/@openidentityplatform/ui-user`
  (`3.2.0-SNAPSHOT`, 65 files, of which 14 `amd/` + 31 `www/` feed composition). Re-verified at
  the end of the task.
- No `mvn` command was run. No `mvn clean`, no `-am`. Nothing was deleted from `~/.m2`.
- No source file, pom or config was edited. `git status` clean except this new file.
- All scratch scripts (`/tmp/prov*.py`, `/tmp/spot.py`, `/tmp/cross.py`, `/tmp/lesscmp.js`,
  `/tmp/unlisted.py`, `/tmp/provwork/`) were written under `/tmp` and removed. No `NOTES-*.md`
  and no `PHASE1-TREE.md` was deleted or modified.

---

## 9. What task 4.4 actually landed

One file changed: `vite.config.js`. No pom, no `package.json`, no new dependency, no source file.

### The three decisions, taken by the change owner rather than derived

| | Decision | Where the options were costed |
|---|---|---|
| Copy mechanism | **Inline Rollup plugin in `vite.config.js`** (§2 option E) | §2 — A, B, D, F all rejected on cost, C on correctness |
| The three LESS files | **In 4.4's scope, compiled OUTSIDE the Vite graph** with the installed `less` + `less-plugin-clean-css` and Grunt's exact options | §3 — the byte-parity argument |
| `fontawesome-webfont.ttf` | **Reproduce Grunt exactly — do not ship it** | §7.1 — fix it as its own change, against a clean diff |

### The plugin — `xuiStaticAssets`, `apply: "build"`

- `buildStart` → `assertSourcesPresent`. The `check-composition-sources` equivalent §2 said Vite
  lacked. Fails and names the missing directory rather than shipping 53 files short.
- `writeBundle` → the copy and the LESS compile. **`writeBundle`, not `buildStart`**, because
  `emptyOutDir: true` wipes `outDir` when the bundle starts (§5 #6).
- The copy fuses Grunt's two passes: walk `COMPOSITION_SOURCES` in Gruntfile order, keep only what
  the ported `nonCompiledFiles` selects, write straight to `outDir`. Last-wins falls out of
  `copyFileSync` overwriting at the same path, so all 7 collisions in §1 resolve the way Grunt
  resolves them. The 384 JavaScript files are not staged — the bundler owns those.
- The LESS step stages `css/**` from all eight sources into `target/css-composed/css/` first.
  **That staging is not optional**: the entries `@import` as if the composed tree existed, and
  Less's `paths` option is not a substitute because `relativeUrls` rebases each `url()` from the
  imported file's real directory. Resolving an import out of `target/dependencies` that way emits
  `url(../../../target/dependencies/css/fontawesome/fonts/…)`. `target/css-composed` is a new
  build-time directory, deliberately **not** `target/XUI` — that tree is §0's second oracle.

### Config changes beside the plugin

- `publicDir` stays `false`, now with the second reason recorded (§2 option D).
- `build.assetsInlineLimit: 0`. No victim today; set because the requirement is a property of the
  output, not of today's file sizes (§5 #2).
- `build.rollupOptions.output.assetFileNames` → function form, `.css` to `css/[name].[ext]` and
  everything else to the hashed default. The `css/` collision 4.2 flagged is resolved *primarily*
  by keeping LESS out of the graph, which makes the string form harmless in fact; the function
  form is a guard, because "harmless today" is what cost this task a re-derivation.
- `build.cssCodeSplit` left at its default and untouched — inert while no CSS is in the graph, and
  §3 records that neither value is right if any ever is.

### Acceptance — `PHASE1-TREE.md`, per-file md5, after `mvn -DskipTests package` (BUILD SUCCESS)

652 manifest entries against 272 emitted files:

| directory | match | differ | absent | extra |
|---|---:|---:|---:|---:|
| `(root)` | 3 | 4 | 1 | 2 |
| `components/` | 0 | 0 | 5 | 0 |
| `config/` | 0 | 0 | 17 | 0 |
| `css/` | **10** | 0 | 0 | 0 |
| `images/` | **19** | 0 | 0 | 0 |
| `libs/` | 0 | 0 | 50 | 0 |
| `locales/` | **3** | 0 | 0 | 0 |
| `org/` | 0 | 0 | 303 | 0 |
| `partials/` | **29** | 0 | 0 | 0 |
| `store/` | 0 | 0 | 6 | 0 |
| `templates/` | **198** | 0 | 0 | 0 |
| `themes/` | **4** | 0 | 0 | 0 |
| **TOTAL** | **266** | 4 | 382 | 2 |

**Every one of the 382 absences is a `.js` file except `index.html`.** Every difference is
accounted for:

- **382 absent** — 381 `.js` (`org/` 303, `libs/` 50, `config/` 17, `store/` 6, `components/` 5)
  are the unbundled AMD module tree; the source is still AMD and groups 5–7 own it. `index.html`
  is **4.5's**, and is excluded by name in the plugin: it matches `**/*.html`, so without the
  exclusion the unfiltered `src/main/resources` copy would overwrite the stamped file with a
  literal `${version}`.
- **4 differ** — `main.js`, `main-authorize.js`, `main-device.js` and `main.js.map`: Vite output
  where the manifest holds r.js output. 4.2's.
- **2 extra** — `main-authorize.js.map`, `main-device.js.map`. Recorded in tasks.md as 4.2's
  expected delta: `sourcemap: true` over two entries the Grunt tree never had.

**The static set is 266/266 byte-identical, zero unexplained.** That includes all three LESS
outputs at their manifest md5s — `structure.css` `7859690d…`, `styles-admin.css` `6ebeb312…`,
`theme.css` `30c37791…` — which is §3's byte-parity claim confirmed through the real build rather
than a recompilation. And it includes the 5 Font Awesome fonts, with no `.ttf`: **the delta from
§7.1 is 0, as intended.**

`src/main/assembly/zip.xml` needed no edit — `openam-ui-ria-16.2.0-SNAPSHOT-www.zip` packs the
same 272 files plus 80 directory entries. That is 4.6's to confirm properly.

### Still true after this task

Both `@openidentityplatform` packages present and unchanged (`ui-commons` 3.2.0-SNAPSHOT, 200
files; `ui-user` 3.2.0-SNAPSHOT, 65 files). `target/XUI` still 719 files. No `mvn clean`, no
`-am`, nothing removed from `~/.m2`.

### Code review, and what changed after it

A reviewer re-derived the acceptance independently — the 263-path selection against Grunt's own
`glob` 7.1.7 with the eleven `nonCompiledFiles` patterns, the winning source for each of the 263,
the full 652-entry manifest diff, and a second build byte-identical to the first. No Critical
issues. Verdict *ready with fixes*; the fixes were documentation with teeth plus one real
divergence. Applied, and the manifest diff is unchanged at **266 / 4 / 382 / 2** after them:

- **Dotfiles.** `shipsVerbatim` now drops any file whose basename starts with `.`. minimatch and
  `glob` exclude dotfiles from a wildcard unless `dot: true`; `path.extname()` plus a directory
  walk do not, so Grunt drops `themes/.DS_Store` and `.eslintrc.json` where the port shipped them.
  **This was the only measured divergence** across 26 edge cases — case sensitivity, `**/*.ext` at
  the tree root, `themes/**/*.*` with zero intermediate segments, multi-dot basenames,
  extensionless files and the `css/bootstrap-3.3.5-custom.css` scoping are all exact. No such file
  exists in any source today, but `themes/` is the tree operators edit in place.
- **The collision comment was wrong.** It said "the other five are AM overriding a commons
  template". Four are; the fifth is `libs/lodash-3.10.1-min.js`, vendored by 4.3. The file it
  dropped is the one **4.7** removes a supplier of and **8.3** replaces. Corrected, with a warning
  that `NOTES-npm-commons.md` §4's "five" is a *different* set — it counts `translation.json`
  where this one counts lodash.
- **The `assetFileNames` comment overstated the guard.** `[name]` is the *chunk* name, so
  `import "css/structure.less"` from `main.js` emits `css/main.css`, not `css/structure.css`. The
  guard buys the directory and the absence of a hash, not the three required names. Said so.
- Smaller: `assertSourcesPresent` uses `isDirectory` rather than `existsSync`, matching
  `grunt.file.isDir` (`Gruntfile.js:410`) — a source path existing as a *file* previously threw a
  bare `ENOTDIR` from inside `walk` and lost the actionable message; `outDir` falls back to
  `config.build.outDir` captured in `configResolved` instead of a repeated string literal; the
  recursive `rmSync` of the staging directory asserts it resolves under `root`; and `walk`'s
  symlink behaviour (`lstat`-based, so symlinks are skipped where `glob` would follow) is now
  stated rather than incidental.
- `apply: "build"` carries a forward note: under `npm run dev` none of this runs and every theme,
  template, partial, locale and stylesheet 404s. Expected, and **4.10's**.

### Two findings left open, deliberately

1. **This file is untracked.** `vite.config.js:97` opens with *"READ NOTES-static-assets.md BEFORE
   CHANGING ANYTHING BELOW"* and cites it nine times. It is not gitignored — it just has to be
   `git add`ed with the change, or every one of those pointers dangles on a fresh clone.
2. **The oracle is still not mechanized, and has no owner.** `PHASE1-TREE.md` is in the repo and
   the comparison is ~30 lines of Node, but nothing runs it; this task's acceptance was a manual
   diff, and 4.6 and 4.7 each plan another one by hand. Task 3.7 established that a file count is
   structurally blind to the failure it found. A `npm run verify:tree` — diff `target/compiled`
   against §7 with a known-delta allowlist (the three JS entries, `main.js.map`, the two extra
   `.map`s, `index.html`, the 381 `.js`) — would make 4.5–4.8 mechanical and catch a silent drop
   at the moment it happens. Out of 4.4's scope, and named here so it is a decision rather than an
   omission.
