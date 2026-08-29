# Task 5.2 discovery — the per-library table for the AMD→ESM conversion

What every runtime library the XUI binds through RequireJS today costs to import as an ES module.
Read with `NOTES-libs-retire.md` (§3 per-file destinations, §4 must-survive, §6 no-npm rows, §13
the six decisions, §18 what the next task should know), `src/main/js/libs/README.md` (the D20
register) and `vite.config.js:226-393` (`NPM_LIBRARY_FILES`) — none of which is re-derived here.

**Nothing was changed.** No edit to `vite.config.js`, `main.js`, `package.json` or anything under
`src/`. Every claim below is measured from the installed bytes, not from the shim's `exports` field.

---

## 0. PRECONDITION DEVIATIONS — read first

Three of the four stated preconditions did not hold as written. All three are benign and the
substance of each holds, but they are recorded rather than smoothed over.

1. **The OpenAM checkout is NOT at `<workspace root>/OpenAM`.** `openspec-commons` contains only
   `.claude/`, `.git/` and `openspec/`. The checkout is its **sibling**:
   `/home/maxim/Documents/_projects/forgerock/OpenAM`. Every path in this file is absolute for
   that reason. The working directory named by the task —
   `.../OpenAM/openam-ui/openam-ui-ria` — exists and holds every file the task named.
2. **`git status --short` in `OpenAM` is NOT empty.** One untracked file:
   `openam-ui/openam-ui-ria/NOTES-entry-templates.md` (47,250 B, mtime Aug 28 16:47). The task
   states "no untracked notes file from a sibling task exists yet — anything untracked you find,
   you created." That is stale: **this is not mine and I did not touch it.** No *tracked* file is
   modified. `NOTES-shims.md` is the only file this run created.
3. **`npm ls --depth=0` exits 1** (`ELSPROBLEMS`), for three reasons, two expected and one not:
   - `extraneous: @openidentityplatform/ui-commons@3.2.0-SNAPSHOT` and `…/ui-user@3.2.0-SNAPSHOT`
     — expected; they are installed `--no-save` per `pom.xml` (§18).
   - **`missing: codemirror@4.10.0, required by openam-ui-ria@14.0.0`** — NOT expected.
     `package.json:35` declares it and `node_modules/codemirror` does not exist. Task 4.8 moved
     the four `libs/codemirror/*` files onto that dependency (`vite.config.js:341-384`), so a
     build from this tree would fail `stageNpmLibraries` on all four. Recorded, not fixed.

`node_modules/@openidentityplatform/ui-commons` and `…/ui-user` both exist. `main.js` has the
`paths` block at 36-79 and the `shim` block at 80-172, as stated. **I did not run `npm install`,
so nothing needed restoring.**

---

## 1. SCOPE — the three blocks, reconciled

| Block | `paths` | `shim` | Notes |
|---|---:|---:|---|
| `main.js:36-79` / `:80-172` | 38 | 26 | superset; every shim id is also a paths id |
| `main-authorize.js:36-43` / `:44-55` | 6 | 3 | `handlebars`, `i18next`, `jquery`, `lodash`, `redux`, `text` |
| `main-device.js:27-34` / `:35-46` | 6 | 3 | identical six, identical three |

**Union = 38 ids.** `main-authorize.js` and `main-device.js` introduce no id `main.js` does not
already bind, and bind none of the six to a different file. Plus:

- `underscore` — a `map: {"*": …}` entry in all three, pointing at `lodash`.
- `reactAutosizeInputDep`, `reactSelectDep` — synthetic `define()`s at `main.js:175` and `:180`.
- four literal `libs/codemirror/**` AMD paths, bound **outside** `require.config` by
  `EditScriptView.js:21,35,36,37` — surveyed as an appendix because they are runtime library
  bindings with a deployed-path contract.

**45 rows surveyed.**

### 1.1 Names bound differently across the three blocks — the findings

- **`handlebars` has a `shim` in `main-authorize.js:45-47` and `main-device.js:36-38`
  (`exports: "handlebars"`) and NO shim in `main.js`.** The divergence is harmless because the
  shim is dead either way: `handlebars/dist/handlebars.js` is a webpack UMD that calls
  `define([], t)`, and RequireJS ignores a shim's `exports` for a file that calls `define`. It is
  also *misnamed* — the global handlebars sets is `Handlebars`, not `handlebars` — so if it ever
  became live it would resolve to `undefined`.
- **`redux` is bound in all three `paths` blocks and is dead in two of them.** Its only real
  importers are `src/main/js/store/index.jsm` and `src/main/js/store/reducers/index.jsm`, reached
  from `main.js`'s `require([… "store/index"])` at `:198`. Neither `main-authorize.js` nor
  `main-device.js` loads `store/index`, and neither names `redux` in its `require` array. The
  entry is inert in both.
- **`text` is bound in all three and its real use is the `text!` prefix** — see §4.
- `Router` is the one id the three entries map to *different modules*; that was 4.3's and is
  already settled in `vite.config.js:1484` (the ui-commons Router wins, globally).
- `main-authorize.js:70-71` does `window.$ = $; window._ = _;` in its entry callback.
  `main-device.js` does neither, and `main.js` does neither. Under AMD nobody had to, because
  jQuery assigns its own globals on the browser branch — see §5.1, which is exactly what stops
  being true under ESM.

---

## 2. THE PER-LIBRARY TABLE

Columns: **id** · **entries** (M = `main.js`, A = `main-authorize.js`, D = `main-device.js`) ·
**bytes today** (N = an `NPM_LIBRARY_FILES` row staged into `libs/`, V = vendored under
`src/main/js/libs/`) · **installed package @ version** · **formats it ships** ·
**ESM specifier** · **disposition** · **importers** (files declaring it: AM `src/main/js` +
the two commons `amd/` trees) · **still ship the `libs/` file?**

Disposition key — (1) nothing needed · (2) a `build.commonjsOptions.include` entry ·
(3) a side-effect import with an order constraint · (4) a global assigned before it loads.
The existing `include` regex `/src[\\/]main[\\/]js[\\/]libs[\\/]/` (`vite.config.js:1834`) already
covers every (2) row; none is new work, but the rows are marked so that deleting the regex is
visibly load-bearing for five ids and not just for lodash.

| id | entries | bytes today | package @ version | formats | ESM specifier | disp. | imp. | ship? |
|---|---|---|---|---|---|---|---:|---|
| `autosizeInput` | M | V `jquery.autosize.input.min.js` | — (no npm publication) | plain script; TS-namespace IIFE, ends `}(jQuery)})(Plugins||(Plugins={}))` | **alias** → `src/main/js/libs/jquery.autosize.input.min.js` | **4** +3 | 1 | no |
| `backbone` | M | N `backbone/backbone-min.js` | `backbone@1.1.2` | UMD (AMD + CJS + global) | `backbone` | **4** * | 51 | no |
| `backbone.paginator` | M | N `…/lib/backbone.paginator.min.js` | `backbone.paginator@2.0.2` | UMD | `backbone.paginator` | **1** | 8 | no |
| `backbone-relational` | M | N `backbone-relational.js` | `backbone-relational@0.9.0` | UMD | `backbone-relational` | **1** | 4 | no |
| `backgrid` | M | N `backgrid/lib/backgrid.min.js` | `backgrid@0.3.5` | UMD | `backgrid` | **1** | 1 | no |
| `backgrid-filter` | M | N `backgrid-filter.min.js` | `backgrid-filter@0.3.7` | UMD | `backgrid-filter` | **1** ‡ | 8 | no |
| `backgrid.paginator` | M | V `backgrid-paginator-0.3.5-custom.min.js` | local patched fork | UMD, **non-exclusive branches** | **alias** → vendored file | **4** +2 | 1 | no |
| `backgrid-selectall` | M | N `backgrid-select-all.min.js` | `backgrid-select-all@0.3.5` | CJS + global; **no AMD branch** | `backgrid-select-all` | **3** | 1 | no |
| `bootstrap` | M | N `bootstrap/dist/js/bootstrap.js` | `bootstrap@3.3.5` | plain script ×12, free global `jQuery` | `bootstrap/dist/js/bootstrap.js` (bare `bootstrap` → `dist/js/npm`, different file, same global read) | **4** +3 | 1 + 2 dyn | no |
| `bootstrap-datetimepicker` | M | V `bootstrap-datetimepicker-4.14.30-min.js` | `eonasdan-bootstrap-datetimepicker@4.14.30` (declared, ships `src/` only) | UMD; CJS branch `a(require("jquery"),require("moment"))` | **alias** → vendored file | **2** | 1 | no |
| `bootstrap-dialog` | M | N `bootstrap3-dialog/dist/js/bootstrap-dialog.min.js` | `bootstrap3-dialog@1.35.1` | UMD, **named** `define("bootstrap-dialog",…)` | **subpath** `bootstrap3-dialog/dist/js/bootstrap-dialog.min.js` — package has **no `main` and no `index.js`**, bare name does not resolve | **4** | 1 + 1 dyn | no |
| `bootstrap-tabdrop` | M | V `bootstrap-tabdrop-1.0.js` | — (npm name is a different lineage) | plain script, ends `}(window.jQuery)` | **alias** → vendored file | **4** +3 | 9 | no |
| `classnames` | M | N `classnames/index.js` | `classnames@2.2.5` | CJS + named AMD + global | `classnames` | **1** | 1 | no |
| `clockPicker` | M | N `clockpicker/dist/bootstrap-clockpicker.min.js` | `clockpicker@0.0.7` | plain script, captures global jQuery | **subpath** `clockpicker/dist/bootstrap-clockpicker.min.js` — **no `main`**, bare name does not resolve | **4** +3 | 1 | no |
| `doTimeout` | M | V `jquery.ba-dotimeout-1.0-min.js` | — (all four npm names 404) | plain script, ends `})(jQuery)` | **alias** → vendored file | **4** +3 | 2 | no |
| `form2js` | M | V `form2js-2.0-769718a.js` | — (npm fork differs, §7/§16) | UMD, **CJS branch first** | **alias** → vendored file | **2** | 6 | no |
| `handlebars` | M A D | N `handlebars/dist/handlebars.js` | `handlebars@4.7.7` | UMD (webpack) | `handlebars` — `browser` map sends `.` → `dist/cjs/handlebars.js` | **1** | 18 | no |
| `i18next` | M A D | N `i18next/lib/dep/i18next.min.js` | `i18next@1.7.3` | CJS + global; **no AMD branch** | **subpath** `i18next/lib/dep/i18next.min.js` — bare name → `index.js` → `lib/i18next.js`, which `require('fs')` and `require('cookies')`: a **Node-only build** | **4** | 15 | no |
| `jquery` | M A D | N `jquery/dist/jquery.min.js` | `jquery@3.7.1` | UMD; CJS branch sets **no globals** | `jquery` | **4** † | 170 | no |
| `js2form` | M | V `js2form-2.0-769718a.js` | — (not on npm) | UMD, CJS branch first | **alias** → vendored file | **2** | 3 | no |
| `jsonEditor` | M | V `jsoneditor-0.7.23-custom.js` | local patched fork of `jsoneditor@0.7.23` | **plain IIFE**, ends `window.JSONEditor=g` — no CJS, no AMD | **alias** → vendored file | **3** | 3 | no |
| `lodash` | M A D | V `lodash-3.10.1-min.js` | vendored 3.10.1; `node_modules/lodash` is a **devDependency at 4.18.1** | UMD | `lodash` — **keep the existing alias** (`vite.config.js:1574`) | **2** | 170 | no |
| `microplugin` | M | N `microplugin/src/microplugin.js` | `microplugin@0.0.3` | UMD | `microplugin` | **1** | 0 | no |
| `moment` | M | N `moment/min/moment.min.js` | `moment@2.28.0` | UMD | `moment` | **1** | 5 | no |
| `popoverclickaway` | M | V `popover-clickaway.js` | **this project's own source** | plain script, ends `}(window.jQuery)` | relative import of the source file | **4** +3 | 3 | no |
| `qrcode` | M | N `qrcode-generator/qrcode.js` | `qrcode-generator@1.4.4` | UMD | `qrcode-generator` (**renamed**) | **1** | 1 | no |
| `react-bootstrap` | M | N `react-bootstrap/dist/react-bootstrap.min.js` | `react-bootstrap@0.30.1` | UMD `define(["react","react-dom"])`; `main` = `lib/index.js` CJS | `react-bootstrap` | **1** | 8 | no |
| `react-dom` | M | N `react-dom/dist/react-dom.min.js` (709 B shim) | `react-dom@15.2.1` | UMD `define(["react"])`; `main` = `index.js` → `lib/ReactDOM` | `react-dom` | **1** | 4 | no |
| `react` | M | N `react/dist/react.min.js` | `react@15.2.1` | UMD `define([])`; `main` = `react.js` → `lib/React` | `react` | **1** | 21 | no |
| `react-input-autosize` | M | N `…/dist/react-input-autosize.min.js` | `react-input-autosize@1.1.0` | dist = browserify UMD reading `window.React`; **`main` = `lib/AutosizeInput.js`, plain CJS, `require('react')`** | `react-input-autosize` | **1** via `lib/` — **4** if the `dist/` file is kept | 1 | no |
| `react-select` | M | N `react-select/dist/react-select.min.js` | `react-select@1.0.0-rc.2` | dist = browserify UMD reading four globals; **`main` = `lib/Select.js`, plain CJS** | `react-select` | **1** via `lib/` — **4** if the `dist/` file is kept | 1 | no |
| `redux` | M A D | N `redux/dist/redux.min.js` | `redux@3.5.2` | UMD `define([])`; `main` = `lib/index.js` | `redux` | **1** | 2 | no |
| `selectize` | M | N `selectize/dist/js/selectize.min.js` | `selectize@0.12.1` | UMD; CJS branch requires jquery+sifter+microplugin | `selectize` | **1** | 15 | no |
| `sifter` | M | N `sifter/sifter.min.js` | `sifter@0.4.1` | UMD | `sifter` | **1** | 0 | no |
| `sortable` | M | N `jquery-sortable/source/js/jquery-sortable.js` | `jquery-sortable@0.9.13` | plain script, ends `}(jQuery, window, 'sortable')` | `jquery-sortable` (**renamed**) | **4** +3 | 2 | no |
| `spin` | M | N `spin.js/spin.js` | `spin.js@2.0.1` | UMD | `spin.js` (**renamed**) | **1** | 2 | no |
| `text` | M A D | N `requirejs-text/text.js` | `requirejs-text@2.0.15` | **AMD loader plugin only** — `define(['module'], …)`, no CJS, no ESM | **none — the id and the package leave the tree** (§4) | — | 0 bare | **no** |
| `xdate` | M | N `xdate/src/xdate.js` | `xdate@0.8.0` | CJS + AMD | `xdate` | **1** | 1 | no |
| `underscore` (map) | M A D | V `lodash-3.10.1-min.js` | — | UMD | `underscore` — **keep the existing alias** (`vite.config.js:1557`) | **2** | 28 (all commons) | no |
| `reactAutosizeInputDep` | M | synthetic `define` at `main.js:175` | — | — | **deleted** — see §3 | — | 0 | — |
| `reactSelectDep` | M | synthetic `define` at `main.js:180` | — | — | **deleted** — see §3 | — | 0 | — |

Appendix rows — bound by literal AMD path, never through `require.config.paths`:

| id (literal path) | bytes today | package | ESM specifier | disp. | imp. | ship? |
|---|---|---|---|---|---:|---|
| `libs/codemirror/lib/codemirror` | N `codemirror/lib/codemirror.js` | `codemirror@4.10.0` **declared, NOT INSTALLED** | `codemirror/lib/codemirror.js` | **1** | 1 | **conditional** — §6 |
| `libs/codemirror/mode/groovy/groovy` | N | ″ | `codemirror/mode/groovy/groovy.js` | **3** | 1 | conditional |
| `libs/codemirror/mode/javascript/javascript` | N | ″ | `codemirror/mode/javascript/javascript.js` | **3** | 1 | conditional |
| `libs/codemirror/addon/display/fullscreen` | N | ″ | `codemirror/addon/display/fullscreen.js` | **3** | 1 | conditional |

**Tally — 45 rows: (1) 20 · (2) 5 · (3) 5 · (4) 12 · removed 3.**
**Specifiers — 24 resolve by bare npm name · 3 need an explicit npm subpath (`bootstrap-dialog`,
`clockPicker`, `i18next`) plus the 4 codemirror subpaths · 11 need an alias to a vendored file ·
3 disappear.** (`bootstrap` resolves bare but to a *different file* than the one that ships; the
subpath is recommended for behaviour parity, not because bare fails.)

\* `backbone` is a **variant of (4)**: the global must be assigned *after* the import, not before.
See §5.2 — the four-way taxonomy does not have a clean box for it, and that is itself the finding.

† `jquery` needs nothing for its own import. It is filed under (4) because it is the **subject** of
the assignment nine other rows depend on, and no other row can own that. See §5.1.

‡ `backgrid-filter`'s CJS branch contains `try{c=require("lunr")}catch(d){}`. Rollup resolves
`require` statically, so **`lunr` enters the bundle** — it is installed
(`node_modules/lunr` exists, transitively). Today it never loads, because the AMD branch declares
only `["underscore","backbone","backgrid"]`. Not a build failure; a silent size and
code-path delta. Stub it or mark it external if that matters.

### 2.1 Shim `exports` fields that are already dead today

Measured from the bytes, not from the config. RequireJS ignores a shim's `exports` when the file
calls `define()`. These eleven `exports` declarations therefore have no effect **right now**, and
deleting them is a no-op rather than a change:

`backbone` (AMD branch present), `backgrid`, `form2js`, `js2form`, `lodash`, `moment`, `qrcode`,
`spin`, `xdate`, and `handlebars` in A and D.

Three more are **live but resolve to `undefined`**, because the named global is never set:
`clockPicker` (the file sets `$.fn.clockpicker`, never `window.clockPicker`), `doTimeout` (sets
`$.doTimeout`), `autosizeInput` (sets `Plugins.AutosizeInput` and `$.fn.autosizeInput`). Harmless
— every consumer reaches them through `$`, not through the returned value.

Only **two** `exports` fields are load-bearing today: `i18next` → `i18n` and `jsonEditor` →
`JSONEditor`. Both files genuinely have no `define()` and genuinely set a `window` property.

Two shim **`deps`** are redundant against the libraries' own dependency declarations:
`selectize`'s `["jquery","sifter","microplugin"]` (its own UMD declares exactly those three), and
the `handlebars` half of `i18next`'s `["jquery","handlebars"]` — **`i18next.min.js` contains zero
occurrences of `Handlebars` or `handlebars`**, in all three entry points.

---

## 3. A. THE `text` ROW · B. THE TWO REACT ROWS

### 3.1 A — `text` / `requirejs-text`

`text` → `libs/text-2.0.15.js`, staged from `requirejs-text/text.js`
(`vite.config.js:329`, MD5-exact). The file is `define(['module'], function(module){ … return
text; })` — an **AMD loader plugin**, with `load`, `write`, `writeFile` and `finishLoad`. It is
neither CommonJS nor ESM: `@rollup/plugin-commonjs` will not transform it (no `module.exports`,
no `exports.x`), so Rollup treats it as an ES module, and the top-level `define(…)` call becomes
a `ReferenceError: define is not defined` at evaluation. **There is no way to import it.**

**Zero modules import the bare id** — it appears only as a `paths` entry in `main.js:77`,
`main-authorize.js:42`, `main-device.js:33`. Its entire use is the `text!` prefix, and there are
exactly **8 call sites in 3 files, all in `src/main/js`, none in either commons package**:

| # | file:line | form |
|---:|---|---|
| 1-5 | `src/main/js/main-device.js:54,55,56,57,58` | five **static** ids in the entry `require([…])` array: `text!templates/user/DeviceTemplate.html`, `…/DeviceDoneTemplate.html`, `text!templates/common/LoginBaseTemplate.html`, `…/FooterTemplate.html`, `…/LoginHeaderTemplate.html` |
| 6 | `src/main/js/main-authorize.js:135` | `` `text!${themePath}${templatePath}` `` — a template literal built inside `_.map` at runtime over the four paths declared at `:78-81`, fed to a **dynamic** `require(templatePaths, cb)` at `:138`. Not statically resolvable |
| 7-8 | `src/main/js/org/forgerock/openam/ui/admin/views/realms/authentication/chains/EditLinkView.js:25,26` | two **static** ids in a `define([…])` array: `text!templates/admin/views/realms/authentication/SelectModuleItem.html`, `…/SelectModuleOption.html` |

**All eight are task 5.5's**, per `tasks.md:85` ("5.5 owns the `text!` template contract for all
three files that use it, including `EditLinkView.js`"). Reported, not solved.

**What happens to the package.** Once the three `paths` entries go, nothing references
`libs/text-2.0.15.js` — no `<script src>`, no literal AMD path, no `text!` id. So:
`requirejs-text` leaves `package.json:49` `dependencies`, the row leaves
`NPM_LIBRARY_FILES` (`vite.config.js:329`), and `libs/text-2.0.15.js` (16,259 B) leaves the
shipped tree as a deliberate −1 against `PHASE1-TREE.md`. That deletion is **gated on 5.5**, not on
5.2: the package cannot go until all eight sites have a replacement.

One evaluation-order consequence 5.5 will meet: today the five ids at `main-device.js:54-58` are
resolved *before* the entry factory runs, so `DeviceTemplate` and friends are **strings** by the
time the body executes (`:65`, `:83-86`). Any replacement that fetches at runtime makes them
promises and the whole body has to move inside a `.then`. `design.md:54` and D3 also forbid the
obvious shortcut — bundling a template with `?raw` removes it from the theme-overridable set and
breaks `ui-customization`'s *Override of templates and partials by a theme*.

### 3.2 B — `react-select` and `react-input-autosize`

**The installed bytes.** `node_modules/react-select/dist/react-select.min.js`, 45,790 B, a
browserify standalone bundle. Its UMD header declares **no AMD dependencies at all** —
`define([],e)` — and the four externals were replaced at build time by `browserify-shim`
global reads. Quoted verbatim from the file (`<g>` is the module factory's injected `global`
parameter, bound at the bundle tail by
`}).call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{})`):

```
"undefined"!=typeof window?window.React:"undefined"!=typeof <g>?<g>.React:null
"undefined"!=typeof window?window.ReactDOM:"undefined"!=typeof <g>?<g>.ReactDOM:null
"undefined"!=typeof window?window.classNames:"undefined"!=typeof <g>?<g>.classNames:null
"undefined"!=typeof window?window.AutosizeInput:"undefined"!=typeof <g>?<g>.AutosizeInput:null
```

The `Select` module's own line, unedited, showing all four together in one initialiser list:

```
l="undefined"!=typeof window?window.React:"undefined"!=typeof n?n.React:null,p=s(l),
d="undefined"!=typeof window?window.ReactDOM:"undefined"!=typeof n?n.ReactDOM:null,c=s(d),
f="undefined"!=typeof window?window.AutosizeInput:"undefined"!=typeof n?n.AutosizeInput:null,h=s(f),
E="undefined"!=typeof window?window.classNames:"undefined"!=typeof n?n.classNames:null,y=s(E),
```

**When.** These are `var` initialisers at the top of each browserify module factory, and the
bundle's prelude executes the entry module eagerly — the file ends `},{},[5])(5)});`, i.e. it
runs module 5 immediately when the UMD factory is called. So all four are read **synchronously at
the moment the file is evaluated**, not lazily at first render. There is no `e("react")` fallback
anywhere in the file: `grep -oE 'e\("(react|react-dom|classnames|react-input-autosize)"\)'`
returns nothing. Counts across the bundle: `window.React` ×8, `window.classNames` ×4,
`window.ReactDOM` ×1, `window.AutosizeInput` ×1.

`node_modules/react-input-autosize/dist/react-input-autosize.min.js` (3,708 B) is the same shape
and reads **exactly one** global, at evaluation:
`n="undefined"!=typeof window?window.React:"undefined"!=typeof e?e.React:null`.

**So `main.js`'s comments are right about the fact and understate the timing** — the reads happen
at file evaluation, which is why the shim `deps` (not the `exports`) are what make it work:
RequireJS loads a shim's `deps` before it even inserts the module's `<script>`, so
`reactSelectDep` has assigned all four globals before `react-select.min.js` is fetched.

**The mechanisms that would satisfy it under ESM, and what each costs.**

| mechanism | cost |
|---|---|
| **(i) Use the bare package names.** `react-select`'s `main` is `lib/Select.js`, which is plain CJS: `require('react')`, `require('react-dom')`, `require('react-input-autosize')`, `require('classnames')` — all four **by name, no globals**. `react-input-autosize`'s `main` is `lib/AutosizeInput.js`, `require('react')`. Both are declared in `react-select`'s `dependencies` (`classnames ^2.2.4`, `react-input-autosize ^1.1.0`) and its `peerDependencies` admit `react ^15.0` | The four globals, both synthetic modules and both shim entries **all disappear**, and the ordering becomes an import edge. The shipped bytes change: `lib/` is unminified ES5 CJS rather than the 45,790 B browserify bundle, and it is bundled anyway. Same package, same version — the Non-Goals pin is untouched. **Lowest cost by a wide margin, and it is disposition (1).** |
| **(ii) Keep `dist/`, establish the globals in a side-effect module** imported before it (`window.React = React; window.ReactDOM = ReactDOM; window.classNames = cx; window.AutosizeInput = AutosizeInput;`) | Reproduces `reactSelectDep` in ESM. The coupling stays invisible to any reader of the consuming file, and correctness depends on module evaluation order, which nothing in the source states. Four globals leak permanently. |
| **(iii) Keep `dist/`, wrapper module aliased in front of the id** — the wrapper sets the globals then re-exports | Same globals, but the coupling is at least in one named file the alias points at. Costs one alias entry and one file. |
| **(iv) Keep `dist/`, a build-time `banner`/`define`** | Cheapest to write, worst to read: the requirement disappears from source entirely and only exists in `vite.config.js`. |

Mechanism (i) is the only one that removes the constraint rather than relocating it, and it needs
no version change. **That decision is 5.3's, not mine, and the playbook reserves it to the change
owner.**

**The tension, stated and not resolved.** `tasks.md:84` offers 5.3 two routes — "establish those
before it loads **or find a supported alternative**". `design.md:89` (Non-Goals) closes the second:
"React 15.2.1, `react-bootstrap` 0.30.1 and `react-select` 1.0.0-rc.2 move to npm at their current
versions", and `design.md:386` adds "treat any React port as out of scope for this change". There
is no supported alternative to `react-select` 1.0.0-rc.2 *at* 1.0.0-rc.2 — every candidate is a
different package or a later major, which is precisely what the Non-Goal forbids. So the two
documents disagree about whether 5.3 may substitute, and only the change owner can settle it.
Worth putting on the table when they do: **mechanism (i) satisfies the "establish the globals"
branch by making the globals unnecessary, without touching a version**, so the conflict may not
need to be settled at all — but that is an argument for the owner, not a decision here.

---

## 4. C. THE D20 ROWS

### 4.1 New vendoring proposed: **none**

Every row that needs bytes from outside npm already has them. `D20`'s bar
(`design.md:318-333`) is not reached by any *new* row, because the three shapes that looked like
candidates are all solved by a specifier rather than by a file:

- `bootstrap3-dialog` and `clockpicker` have **no `main` and no `index.js`**, so the bare name
  does not resolve. That is a subpath problem, not a supply problem — the package publishes the
  exact bytes AM ships. Neither limb of the bar is cleared, and vendoring either would be wrong.
- `i18next`'s bare name resolves to a Node-only build. Same: the browser build is *in* the
  tarball, at `lib/dep/i18next.min.js`, which is what `NPM_LIBRARY_FILES` already names.
- `react-select`/`react-input-autosize` `dist` vs `lib` is a build-selection question inside one
  published package.

The eleven existing vendored rows keep their justification unchanged; the ESM conversion adds no
argument for or against any of them, except the two D20 names itself (§4.2) and one removal
candidate: **`popover-clickaway.js` is not third-party at all** — `src/main/js/libs/README.md`
already records it as "this project's own source, not a dependency". Converting it to ESM is the
natural moment to move it into `src/main/js` proper and drop its register row. That is a
housekeeping observation, not a task.

**If a future row does need vendoring**, `NOTES-libs-retire.md` §18's rule applies without
exception: `src/main/js/libs/README.md` is the register (origin URL, version, md5, licence,
`Since`), and `.gitattributes` already carries `src/main/js/libs/** -text`. A **CRLF-upstream**
file added without that would be normalised into the blob by `* text=auto` / `*.js text` under
`core.autocrlf=input`, the working tree would keep building, and a **fresh clone would silently
stop matching the pinned md5**. The check is
`git cat-file -p :src/main/js/libs/<file> | md5sum` against the worktree — `git status` says
nothing about it.

### 4.2 D20's removal trigger applied to `requirejs` and `base64`

`design.md:362-364`: *"a row leaves the register when a real npm publication of the same lineage
appears, or when the module that binds it goes. Group 5 should expect to revisit `requirejs` and
`base64` specifically — their whole justification is the AMD loader, which group 5 removes."*

**`requirejs-2.3.7-min.js` — the trigger is armed but does not fire in group 5.** Its
justification is not "AM binds the id" (nothing binds it; it is in no `paths` block) but "eight
HTML/FTL pages name the file in a `src` attribute". Verified, all eight, by grep over the whole
OpenAM tree:

```
openam-ui/openam-ui-ria/src/main/resources/index.html:28              <script src="libs/requirejs-2.3.7-min.js">
openam-oauth2/src/main/resources/templates/CodeThanks.ftl:37          data-main=".../XUI/main-device"     src=".../XUI/libs/requirejs-2.3.7-min.js"
openam-oauth2/src/main/resources/templates/CodeVerificationForm.ftl:37 data-main=".../XUI/main-device"     src=".../XUI/libs/requirejs-2.3.7-min.js"
openam-oauth2/src/main/resources/templates/page/authorize.ftl:65      data-main=".../XUI/main-authorize"  src=".../XUI/libs/requirejs-2.3.7-min.js"
openam-oauth2/src/main/resources/templates/popup/authorize.ftl:64     data-main=".../XUI/main-authorize"  src=".../XUI/libs/requirejs-2.3.7-min.js"
openam-oauth2/src/main/resources/templates/touch/authorize.ftl:64     data-main=".../XUI/main-authorize"  src=".../XUI/libs/requirejs-2.3.7-min.js"
openam-oauth2/src/main/resources/templates/page/error.ftl:56          data-main=".../XUI/main-authorize"  src=".../XUI/libs/requirejs-2.3.7-min.js"
```

Six of the seven `.ftl`s live in the **`openam-oauth2` Maven module**, which `design.md`'s D8 says
this migration does not touch. So the row leaves the register only once (a) 5.4 settles how the
three entry points are loaded — `NOTES-vite-entrypoints.md` §3/§7.1, still open — **and** (b)
somebody edits six files in another module. Until both, `libs/requirejs-2.3.7-min.js` must exist
at exactly that path. The trigger's condition ("the module that binds it goes") is met by the
*intent* of group 5 and not by its *scope*.

**`base64-1.0.0-min.js` — the trigger does NOT fire, and D20's stated expectation is wrong about
this row.** Its justification was never the AMD loader. Reading the 835 bytes settles it: the file
is a **`btoa`/`atob` polyfill**, not a Base64 library —

```
!function(){function t(t){this.message=t}var r="undefined"!=typeof exports?exports:self, … 
r.btoa||(r.btoa=function(r){…}), r.atob||(r.atob=function(r){…})}();
```

— it installs `self.btoa` / `self.atob` **only if absent**, has no RequireJS id, and is loaded by
`index.html:21` before the config object and before RequireJS. Its consumers are the bare global
calls that no bundler rewrites:
`node_modules/@openidentityplatform/ui-commons/amd/org/forgerock/commons/ui/common/util/Base64.js:54`
(`return btoa(utf);`) and `:93` (`utf = atob(encoded);`), and
`src/main/js/org/forgerock/openam/ui/admin/services/global/RealmsService.js:46` (`return btoa(path)`).
The AM module named `Base64` is a *commons AMD module* (`define([], function () {…})`), unrelated
to this file. Removing the AMD loader changes nothing about any of that.

Its real removal trigger is different and belongs to nobody in group 5: `btoa`/`atob` have been
native since IE10, so on every browser AM supports the polyfill is a no-op and the row could leave
on that evidence alone. That is a separate, checkable decision — recorded here so the next reader
does not go looking for the AMD binding D20 implies exists.

---

## 5. D. THE ORDER CONSTRAINTS

AMD's shim `deps` encoded load order in config. Under ESM, evaluation order comes from the import
graph. Most of the shim's ordering is **recovered for free**, because the libraries' own CJS
branches `require()` the same things the shim declared — `backbone.paginator`,
`backbone-relational`, `backgrid`, `backgrid-filter`, `backgrid-selectall`, `selectize`,
`bootstrap-datetimepicker` all fall in this class, and `selectize`'s shim deps are redundant with
its own `require("sifter")` / `require("microplugin")`.

Six constraints do **not** survive a naive per-module import, in descending order of blast radius.

### 5.1 `window.jQuery` and `window.$` are never assigned — 9 rows depend on it

jQuery 3.7.1's UMD, quoted:

```
"object"==typeof module&&"object"==typeof module.exports ? module.exports = e.document ? t(e,!0) : … : t(e)
…
ne.amd&&define("jquery",[],function(){return ce}); … "undefined"==typeof e&&(ie.jQuery=ie.$=ce), ce
```

`e` is the factory's second parameter, `noGlobal`. The browser/AMD path calls `t(e)` with one
argument, so `typeof e === "undefined"` and **the globals ARE set** — which is why nothing in AM
ever had to set them. The CommonJS path calls `t(e, !0)`, so `typeof e === "boolean"` and **the
globals are NOT set**. `@rollup/plugin-commonjs` supplies `module`/`exports`, so an ESM build takes
the CommonJS path.

Nine bound ids read the global at **evaluation** time and would get `undefined`:

| id | the bytes |
|---|---|
| `bootstrap` | `if (typeof jQuery === 'undefined') { throw new Error("Bootstrap's JavaScript requires jQuery") }` then `+function ($) {…}(jQuery)` ×12 — **throws loudly** |
| `bootstrap-tabdrop` | `}(window.jQuery);` |
| `popoverclickaway` | `}(window.jQuery);` |
| `sortable` | `}(jQuery, window, 'sortable');` |
| `doTimeout` | `})(jQuery);` |
| `autosizeInput` | `}(jQuery)})(Plugins||(Plugins={}))`, plus a `$(function(){…})` ready hook |
| `clockPicker` | captures jQuery into the IIFE, registers `$.fn.clockpicker` |
| `bootstrap-dialog` | indirectly — see §5.4 |
| `i18next` | `A=this, B=A.jQuery||A.Zepto` at eval, then `extend:B?B.extend:a, each:B?B.each:b, ajax:B?B.ajax:…` — **silently falls back** to internal implementations and never registers `$.t` / `$.fn.i18n`. The only row in this group that fails without an error |

**What enforces it instead:** one side-effect module — `import $ from "jquery"; window.jQuery =
window.$ = $;` — imported by each of the nine (or aliased in front of them). An import edge, not a
config entry. Note that `main-authorize.js:70-71` already does exactly this for `$` and `_`,
described in its own comment as "helpers for the code that hasn't been properly migrated"; under
ESM that line stops being a helper and becomes load-bearing, and `main.js` and `main-device.js`
do not have it.

### 5.2 `Backbone.$` is left undefined — 51 importers

Backbone 1.1.2's UMD, quoted in full:

```
(function(t,e){
  if(typeof define==="function"&&define.amd){
    define(["underscore","jquery","exports"],function(i,r,s){t.Backbone=e(t,s,i,r)})
  } else if(typeof exports!=="undefined"){
    var i=require("underscore"); e(t,exports,i)
  } else {
    t.Backbone=e(t,{},t._,t.jQuery||t.Zepto||t.ender||t.$)
  }
})(this,function(t,e,i,r){ … e.$=r; … })
```

The AMD branch passes **four** arguments and `jquery` is the fourth. The CommonJS branch passes
**three** — `r` is `undefined`, so `Backbone.$ = undefined`. Setting `window.jQuery` does not
help: the CommonJS branch never reads a global. Every Backbone `View` in AM and commons depends on
`Backbone.$` for `this.$el`.

**What enforces it instead:** nothing in the graph can. It needs an explicit assignment *after*
the import — a wrapper module (`import Backbone from "backbone"; import $ from "jquery";
Backbone.$ = $; export default Backbone;`) aliased in front of the `backbone` id. **This is the
one row where the ESM shape is strictly worse than the AMD one**, and it is the row with the
second-highest importer count (43 in `src/main/js` + 8 in commons). `backgrid`,
`backgrid-filter`, `backgrid-selectall`, `backgrid.paginator`, `backbone.paginator` and
`backbone-relational` all inherit it transitively.

### 5.3 The vendored `backgrid.paginator` calls its factory twice under CommonJS

The vendored fork's prologue, quoted — note the **comma**, not an `else if`:

```
!function(a,b){
  "object"==typeof exports&&(module.exports=b(require("underscore"),require("backbone"),require("backgrid"),require("backbone.paginator"))),
  "function"==typeof define&&define.amd ? define(["underscore","backbone","backgrid","backbone.paginator"],b)
                                        : b(a._,a.Backbone,a.Backgrid)
}(this,function(a,b,c){"use strict";var d=c.Extension.PageHandle=b.View.extend({…
```

Under CommonJS both statements run: `module.exports = …` succeeds, then `define` is undefined so
the **else** branch calls the factory a second time with `a._`, `a.Backbone`, `a.Backgrid`. `a` is
top-level `this`, which `@rollup/plugin-commonjs` rewrites to `commonjsGlobal`. If `window._`,
`window.Backbone` and `window.Backgrid` are not set, `c.Extension` throws
`TypeError: Cannot read properties of undefined` **at import time**.

Today the AMD branch is taken and the else never runs, so this is latent. It is a property of the
**local fork** — a stock UMD would use `else if`.

**What enforces it instead:** three globals set before it, or a patch to the vendored file (which
breaks byte-parity and invalidates the `ebd4b6db` md5 in the register), or an alias to npm's
`backgrid-paginator@0.3.5` — the Cloudflare fork, a different lineage, a behaviour decision.
`NOTES-libs-retire.md` §3.1 row 6 records the fork's patch as inventory §12.3 **still open**, so
none of the three can be chosen without reopening that. *This is inferred from the bytes; I did
not run a build to observe the throw.*

### 5.4 `bootstrap-dialog` needs `$.fn.modal` on the same jQuery object it imports

Its CommonJS branch is `module.exports=e(require("jquery"),require("bootstrap"))`, but the factory
signature is `function(t)` — one parameter — and its first statement is
`var e=t.fn.modal.Constructor`. So `require("bootstrap")` is there purely for its side effect. But
`require("bootstrap")` resolves to `bootstrap/dist/js/npm.js`, which requires twelve files each
shaped `+function ($) {…}(jQuery)` — reading the **free global**, not the required instance. So
`$.fn.modal` lands on `window.jQuery` while `t` is the module-graph jQuery. If those are not the
same object, `t.fn.modal` is `undefined` and it throws at evaluation.

**What enforces it instead:** the same §5.1 side-effect module, which makes `window.jQuery` *be*
the module-graph instance. The two constraints have one fix.

### 5.5 `popoverclickaway` must evaluate after `bootstrap`, and no shim says so

Its last statement reads `$.fn.popover.defaults` at evaluation:

```
$.fn.popoverclickaway.defaults = $.extend({}, $.fn.popover.defaults, { trigger: "manual" });
…
}(window.jQuery);
```

`$.fn.popover` is registered by Bootstrap. **`popoverclickaway` has no `shim` entry at all** — it
is a bare `paths` row at `main.js:65` — so this ordering exists in the bytes and nowhere in the
config. It works today only because its three consumers reach it after `AbstractView` has already
pulled Bootstrap in.

**What enforces it instead:** an explicit `import "bootstrap"` (or the §5.1 module) inside
`popover-clickaway.js`. That file is AM's own source, so it can simply be edited — the cheapest
fix in this section.

### 5.6 CodeMirror's three mode/addon files must follow the core

`mode/groovy`, `mode/javascript` and `addon/display/fullscreen` are side-effect registrations
against the core. Their own UMD wrappers `require("../../lib/codemirror")`, so the import graph
enforces it — but only once the four literal AMD paths in `EditScriptView.js` become imports.
Unverified against the bytes: **`codemirror@4.10.0` is declared and not installed** (§0.3).

### 5.7 What the shim encoded that is now free

`backbone` after `lodash`; `backbone.paginator`/`backbone-relational` after `backbone`;
`backgrid` after jquery+lodash+backbone; `backgrid-filter`/`backgrid-selectall` after `backgrid`;
`backgrid.paginator` after `backgrid` + `backbone.paginator`; `selectize` after `sifter` +
`microplugin`; `bootstrap-datetimepicker` after `jquery` + `moment`. Every one of these is
declared by the library's own CommonJS `require()` calls, so the import graph reproduces it with
no configuration. The `underscore`→`lodash` half is already handled by the alias at
`vite.config.js:1557` — and note that **`underscore` has 28 declarers, all of them in the two
commons packages and none in AM**, so that alias exists entirely for the composition sources.

---

## 6. WHICH `libs/` FILES MUST STILL EXIST IN THE DEPLOYED TREE

Checked individually rather than assumed.

| file | must ship? | why |
|---|---|---|
| `libs/requirejs-2.3.7-min.js` | **YES** | `index.html:28` plus **six** `.ftl` pages in `openam-oauth2` name it as the `src` attribute (all seven listed in §4.2). The path is a cross-module contract; renaming it needs edits in a Maven module D8 excludes. Survives until 5.4's entry-point decision *and* an `openam-oauth2` change |
| `libs/base64-1.0.0-min.js` | **YES** | `index.html:21`, a literal `<script src>` before the RequireJS config object. It is a `btoa`/`atob` polyfill with no module id; its consumers are bare `btoa(…)`/`atob(…)` calls in commons `Base64.js:54,93` and `RealmsService.js:46`. Independent of the loader entirely |
| `libs/codemirror/lib/codemirror.js`, `mode/groovy/groovy.js`, `mode/javascript/javascript.js`, `addon/display/fullscreen.js` | **CONDITIONAL** | Required only while `EditScriptView.js:21,35,36,37` names them by literal AMD path. They never pass through `require.config.paths`, so no alias can redirect them (`vite.config.js:363`). Once 5.4 converts that file — it is in the `admin/views` batch — nothing loads them by path and the four can stop shipping. **Do not delete them before that file is converted**: nothing else in the build and no e2e spec covers the admin script editor (`vite.config.js:376-380`) |
| every other `libs/*.js` — all 28 remaining | **NO** | Each is reached only through a `require.config.paths` id, which disappears with the loader. But see the caveat below |

**Caveat that outranks the table.** While `main`, `main-authorize` and `main-device` are still
loaded *by RequireJS* — which is 5.4's open question — the `libs/` tree cannot be dismantled at
all, because the loader still resolves every `paths` id against it. The "NO" column describes the
state *after* the entry-point loader changes, not a licence to delete anything now.

One more: `css/react-select-1.0.0-rc.2-min.css`, `css/selectize-0.12.1-bootstrap3.css`,
`css/bootstrap-dialog-1.34.4-min.css`, `css/bootstrap-clockpicker-0.0.7-min.css` and the two
`css/codemirror/*.css` are LESS **inputs** (`structure.less`, `styles-admin.less`), not module
imports. Nothing in this task's scope touches them and LESS errors on a missing `@import`, so they
are unaffected by anything the ESM conversion does to the JS ids.

---

## 7. COULD NOT DETERMINE

- **Whether the §5.3 `backgrid.paginator` double-invocation actually throws.** Inferred from the
  bytes and from `@rollup/plugin-commonjs`'s top-level-`this` rewrite; no build was run. Two
  attempts, both static. It is cheap to settle with an isolated probe of the kind 4.3 used for
  lodash (`vite.config.js:1795-1806`), and that is worth doing before 5.2 acts on it.
- **CodeMirror's four files could not be inspected** — `codemirror@4.10.0` is declared in
  `package.json:35` and absent from `node_modules` (§0.3). Formats and the mode/addon dependency
  edges in §5.6 are stated from the package's published shape, not from installed bytes.
- **Which Vite actually runs.** `vite.config.js:1808-1816` records it as still unresolved:
  `package.json` declares `^5.4.21`, no vite is installed in this module, and resolution walks up
  to `OpenAM/openam-ui/node_modules/vite` at **8.1.0**. Vite 5 bundles with Rollup and needs
  `commonjsOptions`; Vite 8 bundles with rolldown and ignores it. Every (2) row and every CJS-branch
  claim in §5 is engine-dependent in the same way lodash was, and the answer is still not recorded.
- **Whether `i18next`'s jQuery fallback path is functionally equivalent.** Confirmed that it falls
  back rather than throwing (`extend:B?B.extend:a, each:B?B.each:b, ajax:B?B.ajax:…`); not
  confirmed that AM's `i18nManager` survives losing `$.t` / `$.fn.i18n`.
- **`lodash@4.18.1` in `devDependencies`.** Reported as installed; not checked against the
  registry. It matters only as the thing the `lodash` alias must keep the runtime *away* from —
  lodash 4 dropped `_.contains`, `_.pluck` and `_.any`, which AM uses.
