<!--
  The contents of this file are subject to the terms of the Common Development and
  Distribution License (the License). You may not use this file except in compliance with the
  License.

  You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
  specific language governing permission and limitations under the License.

  When distributing Covered Software, include this CDDL Header Notice in each file and include
  the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
  Header, with the fields enclosed by brackets [] replaced by your own identifying
  information: "Portions copyright [year] [name of copyright owner]".

  Copyright 2026 3A Systems, LLC.
-->

# Where `resolveAssetUrl(url)` has to live — task 4.9 groundwork

**This file records; it does not decide.** Every option below is costed, none is chosen. The
question of *what* `resolveAssetUrl` must do is already answered and is not reopened here:
`e2e/xui/NOTES-urlargs.md` (task 1.12) and design.md D4 establish that `require.toUrl()` applies
`urlArgs`, that templates reach it through the single entry point `UIUtils.fetchTemplate`, and that
the target behaviour is *every runtime-fetched asset url ends in `?v=<build version>`*.

The open question this file serves is the *placement* one: `resolveAssetUrl` has to be reachable
from AM under a Vite build **and** from the same commons source running inside OpenIDM and OpenIG
under RequireJS, without forcing either of those products to move (D5) and without the AMD and ESM
commons builds diverging (D19).

**The single largest finding, up front: most of this already exists.** Tasks 3.2/3.3 landed
`org/forgerock/commons/ui/common/util/esm/LoaderRuntime` in the commons ESM build, with a `toUrl`
that takes `baseUrl`, `urlArgs` *and* a full `resolveUrl` override — and `build/npm-package.js`
already rewrites both commons `require.toUrl(` call sites to `loaderRuntime.toUrl(` when it emits
the ESM tree. `NPM-PACKAGE.md:456` names D4's `resolveAssetUrl` explicitly as the thing that
"plugs into" that seam "rather than routing around" it. So option (b) below is not a proposal — it
is a mechanism that is built, tested and shipped. What is *not* decided is whether AM uses it, and
what happens to AM's own six call sites.

---

## 1. The complete call-site list

Swept `OpenAM/openam-ui` (all modules, not just `openam-ui-ria`), `commons/ui` (all modules, not
just `commons` and `user`), `OpenIG/openig-ui` and `OpenIDM/openidm-ui`, excluding `node_modules/`,
`target/` and the vendored `libs/requirejs-2.3.7-min.js` (which contains `toUrl` as its own
implementation, not as a call).

| # | repo | file:line | resolves | notes |
|---|---|---|---|---|
| 1 | OpenAM | `openam-ui-ria/src/main/js/org/forgerock/openam/ui/common/util/ThemeManager.js:40` | `path + icon` — favicon | `rel="icon"` |
| 2 | OpenAM | `.../ThemeManager.js:46` | `path + icon` — favicon | `rel="shortcut icon"`, same value as #1 |
| 3 | OpenAM | `.../ThemeManager.js:53` | one entry of `stylesheets` | inside `_.each` over the list |
| 4 | OpenAM | `.../ThemeManager.js:111` | `theme.settings.logo.src` | in `makeUrlsRelativeToEntryPoint` |
| 5 | OpenAM | `.../ThemeManager.js:114` | `theme.settings.loginLogo.src` | same function |
| 6 | OpenAM | `openam-ui-ria/src/main/js/org/forgerock/openam/ui/user/oauth2/TokensView.js:116` | `` `locales/${i18nManager.language}/translation.json` `` | DataTables `oLanguage.sUrl` |
| 7 | commons | `commons/src/main/js/org/forgerock/commons/ui/common/util/UIUtils.js:38` | the `url` argument of `fetchTemplate` | the single template/partial entry point |
| 8 | commons | `commons/src/main/js/org/forgerock/commons/ui/common/main/i18nManager.js:83` | `"locales/__lng__/__ns__.json"` | i18next `resGetPath` |
| 9 | OpenIDM | `openidm-ui/openidm-ui-common/src/main/js/org/forgerock/openidm/ui/common/util/ThemeManager.js:34` | `theme.path + theme.icon` | `rel="icon"` |
| 10 | OpenIDM | `.../openidm/ui/common/util/ThemeManager.js:40` | `theme.path + theme.icon` | `rel="shortcut icon"` |
| 11 | OpenIDM | `.../openidm/ui/common/util/ThemeManager.js:47` | one entry of `theme.stylesheets` | inside `_.forEach` |

**Counts: OpenAM `openam-ui-ria` 6 · commons `ui/commons` 2 · commons `ui/user` 0 ·
`OpenIG/openig-ui` 0 · `OpenIDM/openidm-ui` 3. Total 11 production call sites.**

The five given as "verified" in the brief are all confirmed at those exact lines. Beyond them the
sweep found **one more production site** — `OpenIDM ThemeManager.js:47`, the stylesheet loop, which
makes IDM's ThemeManager three sites rather than two — and no others anywhere.

### Non-production occurrences, recorded so a later grep does not re-find them as news

- `openam-ui-ria/src/test/js/.../ThemeManagerTest.js:65` — `sandbox.stub(require, "toUrl", …)`.
  A Karma/Squire unit test that stubs the **global** `require.toUrl` to prefix `"toUrl:"`. Any
  option that stops AM's ThemeManager calling `require.toUrl` breaks this stub, and it is a
  RequireJS/Squire test that D12 migrates to Vitest in group 9 anyway. Not a blocker, but it is a
  file task 4.9 has to touch and it is not in anyone's call-site list.
- `commons/ui/commons/build/npm-package.js:76-90` — the two ESM patch rules that rewrite sites 7
  and 8. Not calls; the machinery that replaces them.
- `commons/ui/build/npm-package-lib.js:247` — `assertNoLoaderApiSurvives`, the net that fails the
  commons build if `require.toUrl(` survives anywhere in the emitted ESM tree.
- `commons/ui/commons/build/verify-esm.mjs:238-269` — five checks over `LoaderRuntime.toUrl`,
  including `urlArgs` with `?` and with `&`, and the `resolveUrl` override.
- `openam-ui-ria/vite.config.js:930` — prose in the `stampIndexHtml` comment.
- Various `NOTES-*.md`, `NPM-PACKAGE.md`, design.md, tasks.md, `xui-cache-busting.spec.mjs` prose.
- `gotoUrl` / `validateGotoUrl` / `photoUrl` — unrelated identifiers that match a naive `toUrl`
  grep. Ignore them.

### Two facts about the call sites that change the shape of the problem

**(a) Only some sites get a *contextual* `require`.** RequireJS gives a module a local
`require` only if the module declares `"require"` in its dependency array; otherwise the call binds
to the global.

| call site | how `require` is bound |
|---|---|
| commons `UIUtils.js` (7) | **declared dep** — `define([… "require" …], function ($, _, require, …)` |
| commons `i18nManager.js` (8) | **declared dep** — same shape |
| AM `TokensView.js` (6) | **declared dep** — `"require"` is the last entry of the define array |
| AM `ThemeManager.js` (1-5) | **global** — no `"require"` in the define array |
| IDM `ThemeManager.js` (9-11) | **global** — no `"require"` in the define array |

This matters for option (a) below: a shim that only installs a global `require` covers AM's
ThemeManager but **not** commons' two sites or `TokensView`, because those three receive `require`
as an injected AMD dependency, not off `window`.

**(b) OpenIG never cache-busts, and never called `toUrl` in the first place.**
`OpenIG/openig-ui/src/main/resources/index.html` boots RequireJS with a bare
`<script data-main="main" src="libs/requirejs-2.3.7-min.js">` and **no `urlArgs` config at all** —
there is no pre-existing `require` global. `OpenIG/openig-ui/.../common/util/ThemeManager.js` sets
`href: theme.path + theme.icon` and `href: stylesheet` **raw**, with no resolution call. So under
OpenIG, commons sites 7 and 8 resolve through `toUrl` with `baseUrl` only and produce **no `?v=`**.
OpenIDM does configure it: `openidm-ui/openidm-ui-common/src/main/resources/index.html:27` carries
`urlArgs : "v=${version}"`, the same line AM has.

Consequence: "preserve today's behaviour" is **not one behaviour**. It is `?v=<version>` under AM
and IDM, and bare paths under IG. Any commons-side helper that unconditionally appends a version
would be a behaviour *change* for OpenIG, which D5 says must not be forced to move.

---

## 2. What each call site needs

| # | input | already theme-prefixed? | output consumed as |
|---|---|---|---|
| 1, 2 | `path + icon`, e.g. `themes/dark/` + `favicon.ico` | **yes, at the call site** — `applyThemeToPage(theme.path, theme.icon, …)` concatenates before calling | `<link rel="icon">` **href** |
| 3 | one `stylesheets` entry, app-root-relative | **no** — the list is already absolute-ish in config (`css/structure.css`, `themes/dark/css/theme-dark.css`); `theme.path` is *not* prepended | `<link rel="stylesheet">` **href** |
| 4, 5 | `settings.logo.src` / `settings.loginLogo.src`, app-root-relative (`images/login-logo.png`, `themes/dark/images/login-logo-white.png`) | **no** — `makeUrlsRelativeToEntryPoint` prefixes nothing, it only resolves | written back onto the theme object; ends up as an `<img>` **src** in a Handlebars template |
| 6 | `` locales/<lang>/translation.json `` — app-root-relative, language interpolated at call time | n/a | DataTables `oLanguage.sUrl` — a **library config value**, which DataTables fetches with its own XHR |
| 7 | `fetchTemplate`'s `url` argument | **sometimes** — see below | `$.ajax({url, dataType:"html"})` |
| 8 | the literal `"locales/__lng__/__ns__.json"`, with i18next's own `__lng__`/`__ns__` placeholders **unexpanded** | n/a | i18next `resGetPath` — a **library config value**; i18next substitutes the placeholders and fetches |
| 9, 10 | `theme.path + theme.icon` | **yes, at the call site** | `<link>` **href** |
| 11 | one `theme.stylesheets` entry | **no** | `<link rel="stylesheet">` **href** |

### Correction to the brief's premise on site 7

The brief states "ThemeManager prefixes theme.path before calling; UIUtils does not." That is right
about the *immediate* call site and wrong about the code path. `UIUtils.compileTemplate:105-125`
computes `templateUrlWithPath = theme.path + templateUrl` and hands **that** to
`fetchAndCompileTemplate` → `fetchTemplate` → `require.toUrl`, with a 404 fallback that retries the
unprefixed url. `UIUtils.preloadTemplates` and `registerPartial`/`preloadPartial` do the same. So
`toUrl` at site 7 receives an app-root-relative url that **may already carry a theme prefix** — the
prefixing happens one frame up rather than at the call. Anything that reasons about site 7's input
as "never theme-prefixed" will be wrong for every themed realm, and the theme-path/404-fallback
logic is exactly what D3 says is kept as-is.

### Two library-config sites are structurally different from the rest

Sites 6 and 8 do not produce a url that the caller then fetches. They produce a **template string
handed to a third-party library**, which interpolates and fetches it itself:

- site 8's string still contains `__lng__` and `__ns__` when `toUrl` sees it. A resolver that
  URL-encodes, normalises, or validates its input would corrupt it. RequireJS's `toUrl` happens to
  be tolerant here only because it does string surgery on the last `.` and a `paths` prefix match.
- site 6's `sUrl` is consumed by DataTables 1.x, whose fetch this build does not control.

For both, the `?v=` must be appended to a string that is *not yet a valid url*, and it lands before
the library's own query handling. This is fine today because `toUrl` appends blindly. It constrains
any replacement that wants to be url-aware.

---

## 3. Where the build version comes from at runtime

Today: `src/main/resources/index.html` declares `var require = { urlArgs: "v=${version}", deps:
["main"] }` before `require.js` loads, and RequireJS normalises the string to a function at
`configure` time. `${version}` is substituted by `stampIndexHtml` in `vite.config.js` (formerly
Grunt's `replace:buildNumber`), driven by `process.env.TARGET_VERSION`, defaulting to `"dev"`.
There is no RequireJS under Vite, so `urlArgs` has no reader.

Four routes to get the version to a helper. **Not decided here.**

### (i) A Vite `define` — already wired

`vite.config.js:1587-1593` **already declares** `define: { __TARGET_VERSION__:
JSON.stringify(targetVersion) }`, with the comment "4.5 owns the index.html half; this exposes the
same value to source." So AM source can read `__TARGET_VERSION__` today with no new plumbing.

- *Cost inside AM:* zero. It is there.
- *Consequence for the two commons call sites:* **fatal if commons reads it directly.** `define` is
  a compile-time textual substitution performed by the consuming bundler. A commons module
  containing `__TARGET_VERSION__` is a free identifier that is a `ReferenceError` under OpenIDM's
  and OpenIG's `r.js`/RequireJS builds, which do no such substitution. It also violates the spirit
  of "commons contains no reference to a product's build machinery". Usable only if commons never
  names it and AM passes the value **in**.

### (ii) An `import.meta` value

`import.meta.env.VITE_*`, or a custom `import.meta` field.

- *Cost inside AM:* small; needs the value exposed as a `VITE_`-prefixed env var or an
  `import.meta.define`.
- *Consequence for the two commons call sites:* **fatal, and worse than (i)** — `import.meta` is a
  syntax error in a script/AMD context, not merely undefined. A commons module carrying it cannot
  even be *parsed* by the AMD build, so `amd/` and `esm/` would have to differ at that line, which
  is precisely what D19 forbids. Note the existing `LoaderRuntime` doc comment already rules
  `import.meta.url` out on a *different* ground: these paths resolve against the application root,
  not the importing module's location.

### (iii) A global set by `index.html`

e.g. `<script>window.__XUI_VERSION__ = "${version}";</script>`, stamped by the same
`stampIndexHtml` pass that already runs.

- *Cost inside AM:* one line in `src/main/resources/index.html` plus a second substitution site.
  `readIndexHtmlSource` currently **throws** if `${version}` is missing, and `stampIndexHtml` does a
  global `split/join`, so a second token is substituted for free. But it changes the shipped
  `index.html` bytes, and 4.5's acceptance criterion was **byte equality** with the Grunt oracle
  (md5 `e3444d65a0de8574ec3f356481f16e09`, 988 bytes). That md5 stops being the oracle.
- *Consequence for the two commons call sites:* **works everywhere, at the price of a global.**
  IG and IDM would simply not set it, and commons would fall back. It is the one option in this
  list that requires no injection and no per-product wiring — and the one that puts a product-shaped
  global into commons, which the substitution requirement in `ui-module-loading` is written against.
- *Interaction with the pinning spec:* the spec reads the version out of `index.html` by matching
  `/urlArgs\s*:\s*"v=([^"]+)"/`. If the RequireJS bootstrap is ever removed, that regex finds
  nothing and `deployedVersion()` fails at its `expect(match, …).toBeTruthy()`. A global would need
  the spec's reader updated in the same commit.

### (iv) Reading it from a served document

Fetch `index.html` (or a small `version.json`) at boot and parse the version out.

- *Cost inside AM:* an extra network round-trip on the critical path, before the first template can
  be fetched — and `UIUtils.fetchTemplate` is on the login render path. Also an ordering hazard: the
  helper becomes async, but every one of the 11 call sites uses it **synchronously**, four of them
  assigning straight into a `$("<link/>", {href: …})` literal.
- *Consequence for the two commons call sites:* would make commons fetch a product artifact by
  path, which is a product reference in commons.

### (v) Injection — the version never reaches the helper, the product configures it

The shape the existing `LoaderRuntime.configure({ baseUrl, urlArgs })` already implements. The
product reads the version by whichever of (i)-(iv) suits *it*, and calls `configure` once at boot.
Commons names no version source at all.

- *Consequence for the two commons call sites:* they read `settings.urlArgs`, which is `null` until
  someone sets it. **OpenIG's current no-cache-buster behaviour is the default**, which is exactly
  right for IG (see §1(b)). AM sets `urlArgs: __TARGET_VERSION__` from (i); IDM would set it from
  its own `index.html` if and when it moves.

---

## 4. The commons options, with costs

Shared constraints, restated so each option is judged against the same bar:

- **D5:** OpenIDM (245 AMD modules) and OpenIG (48) must keep consuming the AMD output unchanged.
  Neither is forced to move.
- **D19:** `amd/` and `esm/` must be **provably the same modules under the same ids**. Any option
  that adds a module to one tree and not the other, or that makes a module's *id set* differ, is a
  D19 problem. Note the bar D19 actually sets is same-modules-same-ids, not same-bytes — AMD-PARITY
  already records that all 79 module files differ byte-wise because the package Babel-transpiles
  what the zip ships verbatim, and that was accepted.
- **Rebuild/re-attach:** any change under `commons/ui/*/src/main/js` means `npm run build:npm`,
  a new `tgz:npm` artifact, `mvn install` in `commons/ui`, and AM re-running task 3.7's out-of-band
  install. D18 records that AM currently pins commons **3.1.2 from Central**, which carries no
  `tgz:npm` and never will, so phase 1 already needs a `commons.ui.version` override — the
  re-attach cost is one already being paid, not a new one.

---

### (a) Leave commons on `require.toUrl`; AM's Vite build shims `require`

Commons source is untouched. AM provides something named `require` with a `toUrl` method.

**What the shim would have to do, precisely:**

1. Expose an object with a `toUrl(moduleNamePlusExt) → string` that reproduces `nameToUrl`'s
   contract: strip a trailing `.ext` off the id (the `toUrl` half), resolve against a base, and
   append `urlArgs` with `?` or `&` chosen by whether the url already has a query — the separator
   logic at `require.js:1291-1296`. Not just "append `?v=`": site 8's `resGetPath` and any
   already-queried url need the `&` branch, which `verify-esm.mjs:251` already tests for.
2. **Reach two different binding routes.** A `window.require` covers AM ThemeManager (1-5) and
   IDM's (9-11). It does **not** cover commons `UIUtils`/`i18nManager` (7, 8) or AM `TokensView`
   (6), which take `require` as an AMD dependency — under Vite those become an *import of a module
   named `"require"`*, so the shim needs a `resolve.alias` entry for the bare id `"require"`
   pointing at a module whose default export is the shim object. Two mechanisms, one shim, and the
   AMD-dependency route is the one easy to miss because it looks identical in the source.
3. Survive `@buxlabs/amd-to-es6`. The commons ESM emit converts `define([… "require" …])` into an
   `import` — and `assertNoLoaderApiSurvives` (`npm-package-lib.js:247`) **fails the commons build
   outright** on any surviving `require.toUrl(` in the ESM tree. So this option requires either
   deleting that guard or exempting those two files from it.

- **commons changes:** none to source. But the ESM emit's existing patch rules (`npm-package.js:76`,
  `:87`) and the residual guard would have to be **removed**, because they are what currently
  guarantees `require.toUrl` does *not* survive into ESM. That is a real change to commons' build.
- **IDM / IG:** nothing. Best-in-class on D5.
- **Rebuild/re-attach:** yes, if the emit rules change; the emitted ESM bytes change.
- **D19:** **yes, a risk.** The ESM tree would then contain `require.toUrl(` — a call to an
  identifier that has no ESM meaning — resolvable only by a consumer-supplied alias for the bare id
  `"require"`. `amd/` and `esm/` stay the same ids and the same 65 modules, so the letter of D19
  holds, but `build/verify-esm.mjs` (which imports the tree through the documented alias and has no
  `require`) would fail, and the "provably the same" claim now rests on a consumer alias that only
  AM has. It also directly contradicts `NPM-PACKAGE.md`'s published contract table.
- **Also:** it keeps a RequireJS-shaped API alive as the seam for the whole migration, which is what
  D1/D6 are trying to retire.

---

### (b) Commons calls an injected `resolveAssetUrl`, each product binds its own

**Check requested by the brief: does an existing binding mechanism already cover this?
Yes — two of them, and the second is built and shipped.**

*Mechanism 1, the spec requirement.* `specs/ui-module-loading/spec.md:64`, *Substitution of commons
modules by the product*: "The shared commons UI SHALL refer to substitutable collaborators by
**logical name** … and SHALL contain no reference to a product's module paths. Each product SHALL
declare which of its own modules implements each logical name." Its third scenario — "A logical name
left unbound … the failure is reported against the logical name rather than surfacing as an
unrelated runtime error" — is exactly the diagnostic contract a url resolver needs. Under AMD this
is the `require.config.map` / bare-id mechanism (`"ThemeManager"`, `"Router"`); under Vite it is
`resolve.alias` (D2, task 4.3). **But note:** that requirement is about substituting *modules*, and
a url resolver is a *function value*, not a view. Binding it as a module id is possible (a
`"resolveAssetUrl"` bare id each product aliases) but is a slightly different use of the seam than
the requirement's own examples — router, login view, theme manager, user profile view.

*Mechanism 2, the one that actually exists.*
`commons/ui/commons/src/main/esm/org/forgerock/commons/ui/common/util/esm/LoaderRuntime.js` —
ESM-build-only, hand-written, with `configure({ baseUrl, urlArgs, resolveUrl, moduleConfig,
resolveModule })` and a `toUrl(resourcePath)` that:

- returns `settings.resolveUrl(resourcePath)` outright if the consumer supplied one — the
  **full-override** seam;
- otherwise joins `baseUrl` (normalising the trailing/leading slash) and appends `urlArgs`, which
  may be a literal string **or** `(resourcePath, url) => String`, with the `?`/`&` separator chosen
  the way RequireJS chooses it.

`NPM-PACKAGE.md:451-457` states the intent in as many words: *"A consumer whose asset URLs come from
a bundler manifest instead can replace the resolution outright with `resolveUrl: (path) => String`,
which is the seam design decision D4's `resolveAssetUrl` plugs into rather than routing around."*
`verify-esm.mjs:241-269` already tests `baseUrl` join, no-double-slash, `urlArgs` with `?`, `urlArgs`
with `&`, a function-form `urlArgs`, and `resolveUrl` winning over both.

- **commons changes:** **none, if AM uses `LoaderRuntime`.** Sites 7 and 8 keep `require.toUrl` in
  `src/main/js`; the emit rewrites them for ESM only, as it does today. If instead a *new* injected
  `resolveAssetUrl` module were introduced, commons source changes at both sites and a new module id
  appears — see D19 below.
- **IDM / IG:** **nothing**, and this is the option's strongest property. They consume `amd/`, whose
  sites 7 and 8 still say `require.toUrl`, still read `urlArgs` from their own `index.html`
  bootstrap (IDM: `v=${version}`; IG: absent). Their behaviour is bit-for-bit what it is today.
- **Rebuild/re-attach:** **not required** if AM uses `LoaderRuntime` as shipped. AM calls
  `configure(…)` in its own bootstrap. That is the only option here with a zero-commons-diff form.
- **D19:** **no risk in the as-shipped form.** `LoaderRuntime` is already ESM-only and already
  accounted for — the emit counts it as a `hand` payload entry distinct from the 65 shared modules,
  and `NPM-PACKAGE.md` documents it as "This module exists **only in the ESM build**". D19's
  same-65-modules-same-ids property is about the shared tree and is untouched.
  **Risk appears only if a new `resolveAssetUrl` module is added to `src/main/js`**, in which case it
  must appear in *both* trees under the same id, and every consumer must be able to bind it.
- **Open cost, and it is the real one:** AM's six call sites (1-6) are **not** commons and are not
  covered by `LoaderRuntime` at all. AM still needs its own `resolveAssetUrl` for ThemeManager and
  TokensView, and would then have two resolvers to keep in agreement — AM's own, and the one it
  injects into commons. Whether those are the same function object is a decision 4.9 has to take.
- **Second open cost:** timing. `configure` must run before the first `fetchTemplate`, which is on
  the login render path. Nothing today enforces that ordering, and an unconfigured `LoaderRuntime`
  fails *silently* for `toUrl` (empty `baseUrl`, no `urlArgs` → a bare relative path that still
  200s) rather than loudly the way `loadModule` does. That is a missing-cache-buster shipped green.

---

### (c) `resolveAssetUrl` in commons with a RequireJS-detecting fallback

A single commons module, present in both trees, that does
`typeof require !== "undefined" && require.toUrl ? require.toUrl(u) : <configured resolution>`.

- **commons changes:** a new module in `src/main/js` (so it flows to both `amd/` and `esm/`), plus
  edits at sites 7 and 8 to call it. The emit's two patch rules for `require.toUrl(` would be
  deleted or repointed.
- **IDM / IG:** nothing to do — the detection finds RequireJS and delegates, so behaviour is
  preserved including IG's no-`urlArgs` case. **But** they now carry a module whose ESM branch is
  dead code, and `assertNoLoaderApiSurvives` **fails the build** on the `require.toUrl(` the ESM
  copy of that module would contain. So either the guard is weakened for this file, or the module is
  the one thing that is genuinely different between the two trees.
- **Rebuild/re-attach:** yes — new module, new payload counts, both packages re-emitted and
  re-attached, AM re-installs.
- **D19:** **yes, a risk, and the most direct one of the four.** The module has to be the same id in
  both trees; the only way to keep `require.toUrl` out of the ESM tree is to emit a *different body*
  for it in `esm/` than in `amd/`. That is a module that is not provably the same, at the same id —
  which is what D19 is written to prevent, and what makes a reviewer diffing the two trees stop
  being able to compare like with like.
- **Also:** `typeof require !== "undefined"` is unreliable under a bundler. Vite/Rollup can leave a
  CJS-interop `require` in scope, and any AM shim from option (a) would make the detection
  false-positive. Detection is the mechanism that fails quietly when it fails.

---

### (d) Others found

**(d1) Do nothing in commons; the *consumer* resolves the base.** `LoaderRuntime.toUrl`'s
`baseUrl`+`urlArgs` path is already a complete `resolveAssetUrl` for sites 7 and 8. AM sets
`urlArgs: "v=" + __TARGET_VERSION__` at boot and writes its own tiny helper for its six sites.
Nothing new is injected, nothing new is a logical name. This is (b) with `resolveUrl` left unused —
called out separately because it is materially cheaper: the `resolveUrl` override exists for
consumers whose urls come from a *bundler manifest*, and D3 explicitly keeps these assets out of the
manifest, so AM may not need the override at all.
*Costs:* same as (b); D19 risk **no**; IDM/IG do **nothing**; commons rebuild **not required**.

**(d2) Push the cache-buster out of JS entirely — a server-side or path-based version segment.**
e.g. serve the tree under `/XUI/<version>/`. Removes the helper question. Rejected on sight by D3
and contract 3: an operator drops `themes/myTheme/templates/common/FooterTemplate.html` into the
deployed tree at a *fixed* path, and a versioned path segment breaks that. Recorded so it is not
re-proposed.

**(d3) AM's six sites and commons' two need not use the same mechanism.** Nothing forces one
answer. AM's ThemeManager and TokensView are AM source under AM's bundler and could use
`__TARGET_VERSION__` directly, while commons' two go through `LoaderRuntime.configure`. The cost is
two spellings of one decision — which `LoaderRuntime`'s own `unwrapModule` comment records as
having already gone wrong once in this codebase.

### Summary table

| option | commons source diff | commons rebuild + re-attach | IDM does | IG does | D19 divergence |
|---|---|---|---|---|---|
| (a) shim `require` in AM | none, but the ESM patch rules and residual guard must go | yes (emit changes) | nothing | nothing | **yes** — ESM tree keeps a call with no ESM meaning; `verify-esm.mjs` breaks |
| (b) injected, via existing `LoaderRuntime` | **none** | **no** | nothing | nothing | **no** |
| (b′) injected, via a *new* `resolveAssetUrl` module | both sites + new module | yes | nothing | nothing | **no**, if the module is in both trees at one id |
| (c) commons module with RequireJS detection | both sites + new module | yes | nothing | nothing | **yes** — the module's body must differ between trees |
| (d1) consumer configures `baseUrl`/`urlArgs` only | **none** | **no** | nothing | nothing | **no** |
| (d2) versioned path segment | none | no | n/a | n/a | n/a — but breaks D3/contract 3 |

---

## 5. What the pinning spec asserts

`OpenAM/e2e/xui/xui-cache-busting.spec.mjs`. **Tag: `["@deployed-am", "@local-server"]` — both,
not one.** The file's own comment gives the reason: this is the XUI serving its own static tree and
resolving urls in the browser, and D14 has the local server serve the XUI from the same origin and
path prefix, so it serves this `index.html` and this template too. Nothing in it is AM-side
behaviour.

**Shared helper `deployedVersion(page)`** — used by both tests:
1. `GET ${XUI_BASE}/index.html`, asserts `response.ok()`.
2. Matches `/urlArgs\s*:\s*"v=([^"]+)"/` against the body and asserts the match exists.
3. Asserts the captured value does **not** contain `"${"` — i.e. the token was substituted. This is
   the guard against deploying `openam-ui-ria/target/XUI` instead of the `-www.zip`.
4. Returns the captured version.

**Test 1 — "a template fetched at runtime carries the build version".** Arms a `page.on("request")`
listener **before** navigating (load-bearing: the template is fetched during the initial load),
collects every request url containing `/XUI/templates/common/LoginBaseTemplate.html`, runs
`openLoginForm(page)`, waits for `SEL.usernameInput`, then asserts the capture list is non-empty and
that **every** captured url equals exactly
`` `${XUI_BASE}/templates/common/LoginBaseTemplate.html?v=${version}` ``.
Whole-string equality on the request url — not `toContain`, not a response status.

**Test 2 — "require.toUrl() applies the configured urlArgs".** `page.evaluate(() =>
require.toUrl("templates/common/LoginBaseTemplate.html"))` and asserts it equals
`` `./templates/common/LoginBaseTemplate.html?v=${version}` `` — with the leading `./` from the
deployed `baseUrl`. The file's own header says this one **is mechanism and is expected to be
replaced at task 4.9** along with the call it pins, because there is no `require` global once D1's
loader lands. Test 1 is "the contract, and survives the migration verbatim".

### Would each option keep it green?

Assume in every row that AM's Vite tree is what is deployed and that the RequireJS bootstrap in
`index.html` is still present (it is — 4.5 ships all three `<script>` tags byte-identical).

| option | test 1 (the contract) | test 2 (the mechanism) | notes |
|---|---|---|---|
| (a) shim `require` | **green**, if the shim reproduces base + `?v=` exactly, including the `./` question | **green** — this is the *only* option that keeps test 2 alive as written, since a `require.toUrl` global still exists | its main selling point, and also why it is misleading: test 2 passing no longer means RequireJS |
| (b) / (b′) injected | **green**, if `configure` runs before the first `fetchTemplate` and sets `urlArgs` to the deployed version | **fails as written**; expected — the header says so | test 2 must be rewritten in the same commit, or it is a red suite, not a caught regression |
| (c) detecting fallback | **green** under AMD; **green** under Vite if the configured branch is reached | **fails as written** under Vite; **green** while RequireJS is still loading the tree | the detection makes which branch ran invisible to the spec, which is the failure mode this suite exists to catch |
| (d1) `baseUrl`/`urlArgs` only | same as (b) | same as (b) | |
| all | `deployedVersion` still needs `urlArgs : "v=…"` in `index.html`. Any option that also **removes** the RequireJS bootstrap makes the helper fail and takes **both** tests down at step 2 | | that is a group-5 concern, not 4.9's, but it is the spec's single point of failure |

### The gap this spec does not cover, and it is large

The spec pins **exactly one url**: `templates/common/LoginBaseTemplate.html`, i.e. call site 7 and
only site 7. It pins **none** of the other ten. In particular:

- Sites 1-5 (AM ThemeManager: favicon, stylesheets, both logos) are **unpinned**.
  `xui-theming.spec.mjs` *does* assert on those hrefs — but its `normalizeHref` helper at line 185
  is `String(href).replace(/^\.\//, "").replace(/\?.*$/, "")`, which **strips the query string
  before comparing**. It therefore passes whether or not the theme assets carry `?v=`.
- Site 6 (`TokensView` DataTables `sUrl`) is unpinned; it is behind the OAuth2 tokens view.
- Site 8 (i18next `resGetPath`) is unpinned. The locale fetch is on every page load, so a regression
  there is a live cache bug that nothing catches.

So "the only mechanical check that this task did not change behaviour" covers **1 of 11 call
sites**, and the one it covers is the one call site that is already handled by a shipped,
independently tested mechanism. That asymmetry should be flagged before 4.9 is scoped.

---

## 6. Whether this can land before the Vite flip

**Yes, the staging is available.** Flagged, not decided.

**Why it is available.** The phase-0a suite runs against a deployed AM (`@deployed-am`) and against
the local server (`@local-server`), and neither cares which build produced the tree — the Grunt
build (`npm run build:grunt`) is still present in `package.json` and still produces a deployable
`-www.zip`. `xui-deploy.sh` deploys either. The Grunt tree is therefore a live oracle while the Vite
tree is still being assembled, which is precisely the arrangement task 3.8 and D11 set up.

**What the staging would look like.** Introduce `resolveAssetUrl` as a thin function that, under
AMD, is `require.toUrl` — same argument, same return, no version logic of its own — and repoint the
six AM call sites at it. Build with Grunt, deploy, run the suite.

**What that would prove.**

- That the **call-site refactor** is behaviour-preserving: the six AM sites (and, if commons is
  touched, sites 7-8) still produce identical urls. Behaviour-preserving *by construction*, since
  the body is a delegation, so the suite is confirming the plumbing rather than discovering it.
- That every call site was found and repointed — a green `xui-theming.spec.mjs` plus a green
  `xui-cache-busting.spec.mjs` plus a manual check of the tokens view would catch a missed site,
  because a *missing* url is a broken page rather than a missing query parameter.
- That the AMD-dependency vs global `require` split (§1(a)) was handled: `TokensView` and commons
  take `require` as a dep, AM/IDM ThemeManager take it off the global. A delegation that got that
  wrong throws at module init under Grunt, immediately.
- That the seam has a name and a single place to change, so the Vite flip is a one-line
  reimplementation rather than eleven edits under time pressure.

**What it would not prove — and this is most of what matters.**

- **Nothing about the version source.** Under Grunt the version still comes from RequireJS
  `urlArgs`, read out of `index.html`. Every option in §3 is untested by this staging. The one thing
  the Vite flip actually has to get right is the one thing a delegating helper cannot exercise.
- **Nothing about `LoaderRuntime.configure` timing** — the silent-failure mode identified in §4(b),
  where an unconfigured resolver returns a bare path that still 200s and ships a
  cache-buster-less page green.
- **Nothing about the ESM tree.** Under Grunt, commons is consumed as AMD. `verify-esm.mjs`,
  `assertNoLoaderApiSurvives` and the D19 parity property are all unexercised by a Grunt run.
- **Nothing about the ten unpinned call sites** beyond "the page still renders", per §5.
- It would **not** let test 2 of the pinning spec be rewritten, because under AMD `require.toUrl`
  still exists and still passes — so the rewrite lands unverified at the flip, when the suite is
  simultaneously red for other reasons.

**The staging's own cost, recorded:** it is two landings of the same task, and the second one is
where all the residual risk lives. If the first landing is taken as evidence that 4.9 is done, the
version-source decision (§3) and the configure-ordering hazard (§4(b)) both cross the Vite flip
unexamined.

---

## Blocked / could not determine

- **Whether `openidm-ui` and `openig-ui` will ever consume the npm packages.** D5's removal trigger
  ("the AMD output is deleted once `openidm-ui` and `openig-ui` are both on ESM") implies they
  eventually will, but neither repo has an npm-package consumption path today; both take
  `commons.ui:user:zip:www`. The costs above assume they stay on the zip for the duration, which is
  what D18's *"nothing consuming it moves until it chooses to"* says. Not verified against either
  product's own plan — no OpenSpec change exists for either repo in this store.
- **Whether OpenIG's missing `urlArgs` is deliberate or a latent defect.** IG ships templates and
  locales through the same commons `UIUtils` path AM and IDM do, with no cache-buster on any of
  them. Whether "preserve" for IG means "keep no `?v=`" or "IG has a bug nobody has filed" is a
  product decision, not something determinable from the source. It changes which options are
  behaviour-preserving for IG.
- **Whether AM's own six sites and commons' two should share one resolver instance.** §4(d3) sets
  out the choice; nothing in design.md or the specs settles it.

## 7. Decisions taken (2026-08-28)

Answered by the user after this investigation. These close §3, §4, the OpenIG item in "Blocked",
and §6. The third blocked item stays open.

- **§4 — commons approach: (b), the existing `LoaderRuntime`.** AM binds its `resolveAssetUrl` via
  `LoaderRuntime.configure({ resolveUrl })`. No commons source diff, no package rebuild or
  re-attach, OpenIDM and OpenIG do nothing, and the amd/ and esm/ trees stay identical under D19.
  Two residual costs carried into implementation: AM's own six call sites are *not* covered by
  `LoaderRuntime` and need their own binding, and `configure` ordering fails silently if it runs
  after the first `toUrl` — that needs a guard or an ordering assertion.
- **§3 — version source: the Vite `define`.** `__TARGET_VERSION__` (vite.config.js:1592) is read by
  AM at startup and passed into `configure`; commons never names the identifier, so nothing breaks
  under r.js. Rejected: `import.meta` (parse error in AMD → D19 divergence), an index.html global
  (changes index.html bytes, breaking task 4.5's md5 oracle), and fetching a served document
  (async, while all 11 call sites are synchronous).
- **OpenIG: stays on bare paths.** "Preserve today's behaviour" for IG means *no* `?v=`. The
  resolver appends a version only where the product configured one, so IG is genuinely unchanged.
  Whether IG's missing `urlArgs` is a defect is deliberately left unfixed here — it would be a
  behaviour change for IG and needs its own change proposal under D5.
- **§6 — staging: land under Grunt first.** The delegating `resolveAssetUrl` lands while Grunt
  still builds, with the phase-0a suite as a live oracle. Scope of that proof is unchanged from §6:
  it establishes the refactor is behaviour-preserving, that all 11 sites were found, and that the
  AMD-dep-vs-global `require` split was handled. It establishes nothing about the version source,
  `configure` ordering, ESM parity, or the test-2 rewrite.

Still open: whether AM's six sites and commons' two share one resolver instance (§4(d3)); whether
`openidm-ui`/`openig-ui` ever consume the npm packages.

Not covered by any decision above, and worth its own task: the pinning coverage gap in §5 — only
1 of 11 call sites is pinned, because `xui-theming.spec.mjs:185` strips the query string in
`normalizeHref` before comparing.

## 8. What landed (task 4.9)

Implementation record. §7 holds the decisions; this is what was built against them and what was
actually verified.

### Files changed — OpenAM only

- **new** `src/main/js/org/forgerock/openam/ui/common/util/resolveAssetUrl.js`
- **modified** `src/main/js/org/forgerock/openam/ui/common/util/ThemeManager.js` — call sites 1-5,
  plus the new module added to the `define` array
- **modified** `src/main/js/org/forgerock/openam/ui/user/oauth2/TokensView.js` — call site 6; the
  `"require"` AMD dependency is **removed**, since `require` was used at `:116` and nowhere else

`commons/`, `OpenIDM/` and `OpenIG/` have **zero diff**. No Maven was run in any repository. The
commons version in `~/.m2` is **3.2.0-SNAPSHOT**, unchanged, and `node_modules/@openidentityplatform`
still holds `ui-commons` and `ui-user`, both 3.2.0-SNAPSHOT.

### The constraint that changed the shape of the task

§4(b) assumed AM could bind `LoaderRuntime.configure({ resolveUrl })`. It cannot, yet, and the
reason was not visible from the commons side:

- The **D19 prefix alias** mapping `org/forgerock/commons/...` to the package's `esm/` tree **is not
  in `vite.config.js`**, and is owned by no landed task. Its own comment at `vite.config.js:1341`
  states this: *"which needs D19's prefix alias — NOT in this file, and not owned by any task that
  has landed."*
- Vite composes commons from `node_modules/@openidentityplatform/ui-commons/amd`
  (`vite.config.js:184-187`, `:403-406`). That copy's `UIUtils.js:28` still says `require.toUrl`.
  The `esm/` copy — the one whose `UIUtils.js:32` says `loaderRuntime.toUrl` — is reached today only
  by the two package-specifier aliases for `Router` and `UserProfileView`.
- So `LoaderRuntime` is **not in AM's module graph**, and `configure` has nothing to configure.
- Separately, `main.js` is still AMD (group 5 owns the conversion), so an ESM `import` of
  `LoaderRuntime` would break `build:grunt` — the only build that currently produces a runnable
  tree, and therefore the oracle this task is verified against.

**Deferred with a named owner:** whoever lands the D19 prefix alias must also call
`LoaderRuntime.configure({ resolveUrl: resolveAssetUrl })` in AM's bootstrap. Until then commons
resolves exactly as it does today, through the `amd/` copy, under RequireJS `urlArgs`.

### Shape of the helper

Exports the function with `.configure` attached, so the six call sites read `resolveAssetUrl(url)`
and the ESM conversion in group 5 becomes `export default` plus a named `configure` with no
call-site churn.

- **Unconfigured** → delegates to `require.toUrl`. Under RequireJS that is not an approximation of
  today's behaviour, it *is* it (D4, task 1.12), which is what makes the replacement
  behaviour-preserving by construction rather than by measurement.
- **Unconfigured and no `require.toUrl`** → **throws**. But see §9: that condition is narrower
  than it reads, and the guard is not yet the forgot-to-`configure` alarm this line first claimed.
- **Configured** → appends `settings.urlArgs`, choosing `?` or `&` the way RequireJS chooses it. An
  empty `urlArgs` resolves without a cache-buster, which is the shape OpenIG's bootstrap has today.

The helper **never names `__TARGET_VERSION__`**, though `vite.config.js:1592` already defines it.
`define` is a compile-time substitution performed by the consuming bundler, so naming it is a
`ReferenceError` under Grunt/r.js — and would be one under OpenIDM and OpenIG if this shape ever
moved into commons. §3(i)'s "usable only if commons never names it and AM passes the value in" turns
out to bind AM's own modules too, for as long as two builds have to work.

**Two divergences from `require.toUrl` in the configured path**, documented in the module header
rather than papered over: no `baseUrl` (returns `templates/...`, not `./templates/...` — the same
request url in a browser, a different returned string, which is exactly what
`xui-cache-busting.spec.mjs` test 2 compares), and no `blob:` exclusion.

### What was verified, and what was not

Verified:

- `npm run build:grunt` — **exit 0**, 384 files into `target/compiled`; `index.html` carries
  `urlArgs : "v=dev"`, substituted, so `deployedVersion()`'s `${` guard is satisfied.
- `xui-cache-busting.spec.mjs` against the local API server serving that tree — **2 passed**.
  See §9 for what that does and does not evidence; the first version of this line got it wrong.
- `npm run test:karma` — **163 of 163 SUCCESS**, including `ThemeManagerTest`. Its
  `sandbox.stub(require, "toUrl", …)` still intercepts *through* the delegation, so its assertions
  on `${baseUrl}icon.png`, `${baseUrl}a.css` and the two logo `src` values pin sites 1-5 unchanged.
  No test file needed editing — §1's warning that the stub would break did not materialise, because
  the helper delegates to the same global the stub replaces.

Not verified, and not claimed:

- **`xui-theming.spec.mjs` could not be run.** Both of its describe blocks are tagged
  `@deployed-am` only — a `--grep @local-server` run reports "No tests found". It needs a deployed
  AM in a container, and the Docker daemon is not running here, so `readDeployedFile` fails. It is
  the only browser-level check on sites 1-5.
- **Site 6, `TokensView`, has no test of any kind** — no unit test exists for it
  (`src/test/js/.../user/oauth2/` does not exist) and no e2e spec covers the tokens view.
- Everything §6 lists: the version source, `configure` ordering, the ESM tree, D19 parity.

So the coverage asymmetry §5 flagged is now concrete: the one spec that pins a cache-buster pins
**call site 7, which this task did not change**, and none of the six it did.

## 9. Peer review, and three corrections it forced

A code review of §8's implementation confirmed the parts that matter — it independently swept the
call sites, re-implemented RequireJS 2.3.7's `toUrl`/`nameToUrl` from the deployed minified source
and ran every real call-site input through both paths, and checked the built `target/compiled/
main.js` to confirm commons' `UIUtils` still resolves through its own injected `require`. Three
things it found were right and are fixed here; one more is recorded as a plan-level gap.

### C1 — the "fail loudly" guarantee was overclaimed

§8 and the module header both stated that an unconfigured helper **throws**, presenting that as
§4(b)'s silent-failure mode closed. It is not closed yet. The guard is
`typeof require === "undefined" || !require.toUrl`, and **task 4.5 deliberately ships `index.html`
byte-identical, RequireJS bootstrap included** (md5 `e3444d65…`). So under the Vite tree
`window.require.toUrl` still exists, and an unconfigured helper **delegates to RequireJS silently**
rather than throwing.

Not user-visible — RequireJS applies its own `urlArgs`, so the resolved url is correct. But a
group-5 implementer relying on "it will throw if I forget to configure" would be misled, and the
symmetry is worth stating: **forgetting `LoaderRuntime.configure({ resolveUrl })` on the commons
side fails silently too** (commons drops back to bare paths). Neither seam alarms until group 5
removes the bootstrap. The module header now carries that precondition instead of the guarantee.

### C2 — §7's ordering hazard was only half-guarded

§7 recorded that "`configure` ordering fails silently if it runs after the first `toUrl`". The
throw covered *never configured*; nothing covered *configured too late* — urls already handed to a
`<link href>` or DataTables' `sUrl` without a cache-buster, then `configure` lands and every
subsequent url carries one, with nothing reporting the split. A `resolved` flag now makes a late
`configure` throw. `resolveAssetUrl.reset()` is exported alongside it for D12's Vitest migration,
where module scope is shared across a file unless `vi.resetModules()` runs.

### C3 — what the pinning spec evidences was stated wrongly

§8 said test 2 "still passes because the delegation keeps a real `require.toUrl` in play". That is
wrong. Test 2 is `page.evaluate((t) => require.toUrl(t), TEMPLATE)` at
`xui-cache-busting.spec.mjs:148` — it calls RequireJS **in the page** and never reaches the helper.
It passes because the bootstrap is present, and would pass identically had the helper not delegated
at all. And test 1's `TEMPLATE` is `templates/common/LoginBaseTemplate.html` — **call site 7, in
commons, which this task did not change**.

The accurate statement: **`xui-cache-busting.spec.mjs` 2/2 is a no-regression signal for the tree,
not evidence about this change.** §5 already said the spec covers 1 of 11 sites and that the one it
covers is handled by a shipped mechanism; §8's sentence contradicted that and is now corrected in
both places.

### What the new unit test closes

`src/test/js/org/forgerock/openam/ui/common/util/resolveAssetUrlTest.js` — 12 cases. Before it,
the configured branch, the `?`/`&` separator, the empty-`urlArgs` passthrough, the throw and
`configure`'s validation had **never executed anywhere**; the module's whole reason for existing
was scheduled to run for the first time at the Vite flip, when §6 notes the suite is red for other
reasons. It needs no Docker, no deployed AM and no Vite.

Two harness facts worth knowing before re-running it, both of which cost a confusing red run here:
`target/test-classes` is populated by `grunt sync:test`, which is in the `dev`/`deploy` task list
and **not** in `prod`, so `npm run test:karma` after editing a spec runs the stale copy; and the
module under test is loaded from `target/compiled`, so editing `src/main/js` needs a rebuild before
Karma sees it.

### Still open — a plan-level gap, not an implementation one

The review re-derived §5's coverage hole independently and sharpened it:
`e2e/xui/xui-theming.spec.mjs:185`'s `normalizeHref` does `.replace(/\?.*$/, "")`, stripping the
query before comparing, so the only browser-level check on sites 1-5 passes **whether or not the
theme assets carry `?v=`**. One assertion there that the query survives on a single href would turn
"the page renders" into "the page cache-busts" for exactly the five sites this task changed. That
spec is `@deployed-am` in both describe blocks, so it needs the container this run did not have.
**Worth its own task; 4.9 does not close it.**

Also promoted from open to settled by the implementation: §4(d3) asked whether AM's six sites and
commons' two share one resolver. They do not. There are **two resolvers with two independent
states and two `configure` calls** — AM's `resolveAssetUrl` and commons' `LoaderRuntime` — bound
together at the flip by passing the first as the second's `resolveUrl`.
