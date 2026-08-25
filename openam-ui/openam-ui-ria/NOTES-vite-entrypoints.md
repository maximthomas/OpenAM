# NOTES-vite-entrypoints.md — what a multi-entry Vite build must emit for all three XUI entry points

Discovery for task 4.2 (`tasks.md:68`, *Configure the three entry points — `main.js`,
`main-authorize.js`, `main-device.js` — as a multi-entry build*). **Nothing was implemented and
nothing was decided.** No `.ftl`, no `pom.xml`, no `package.json`, no `vite.config.js`, no
`Gruntfile.js` and no source file was modified. This file is the only artifact.

Companion records this builds on and does not repeat:
[`NOTES-vite-build.md`](NOTES-vite-build.md) (task 4.1's survey of the whole pipeline),
[`PHASE1-TREE.md`](PHASE1-TREE.md) (the 652-file per-file digest manifest of the shipped tree),
`../../e2e/xui/NOTES-urlargs.md` (task 1.12 on `toUrl`/`urlArgs`).

## Provenance of the evidence, and one caveat about `target/compiled`

`target/compiled` **no longer holds the Grunt tree**. Task 4.1 landed `vite.config.js` with
`outDir: "target/compiled"` and `emptyOutDir: true` (`vite.config.js:150-151`), and the first
`vite build` emptied it; it now contains exactly two files, `assets/main-CfrLTCo_.js` and its map,
and `target/openam-ui-ria-16.2.0-SNAPSHOT-www.zip` was re-packed from that. `vite.config.js:130-133`
records this as a known and accepted cost. **Nothing here tried to restore it** — that is a
plan-level decision taken elsewhere.

Every observation below therefore comes from one of:

| Source | What it is | Why it is authoritative here |
|---|---|---|
| `src/main/js/main*.js` | the three entry sources | unaffected by 4.1 |
| `target/XUI/` | Grunt's composition tree, 719 files, all three entries + `libs/` at its root | pre-`requirejs`/`less`/`replace`, but byte-identical for the files quoted |
| `target/XUI/libs/requirejs-2.3.7-min.js` | the loader, md5 `01252f25e96768861bd3effa7bf8889e` | **identical bytes** to `target/dependencies/libs/`, to `openam-server/target/OpenAM-16.2.0-SNAPSHOT/XUI/libs/` and to the served copy recorded in `e2e/xui/NOTES-urlargs.md:44`. There is no `src/main/js/libs/requirejs-2.3.7-min.js` — the file arrives through the Maven unpack into `target/dependencies` (see §3, note on task 4.7) |
| `PHASE1-TREE.md` | per-file md5 + size of the 652 shipped files | the record of what the built tree contained |
| `node_modules/vite` 5.4.21, `node_modules/rollup` 4.62.5 | the installed bundler | §4 is grounded in these exact versions, not in docs |

---

## 1. THE COMPLETE LIST of pages that load an XUI entry point

Seven pages, in two Maven modules. **Six of the seven are `.ftl` templates in `openam-oauth2`, a
different module from `openam-ui-ria`.**

| # | File | Line | Entry | Mechanism |
|---|---|---:|---|---|
| 1 | `openam-ui/openam-ui-ria/src/main/resources/index.html` | 23-26, 28 | **`main`** | global `require` object, `deps: ['main']`, then `<script src="libs/requirejs-2.3.7-min.js">` |
| 2 | `openam-oauth2/src/main/resources/templates/page/authorize.ftl` | 65 | **`main-authorize`** | `data-main` |
| 3 | `openam-oauth2/src/main/resources/templates/popup/authorize.ftl` | 64 | **`main-authorize`** | `data-main` |
| 4 | `openam-oauth2/src/main/resources/templates/touch/authorize.ftl` | 64 | **`main-authorize`** | `data-main` |
| 5 | `openam-oauth2/src/main/resources/templates/page/error.ftl` | 56 | **`main-authorize`** | `data-main` |
| 6 | `openam-oauth2/src/main/resources/templates/CodeVerificationForm.ftl` | 37 | **`main-device`** | `data-main` |
| 7 | `openam-oauth2/src/main/resources/templates/CodeThanks.ftl` | 37 | **`main-device`** | `data-main` |

All six `.ftl` lines are byte-identical in shape:

```html
<script data-main="${baseUrl?html}/XUI/main-authorize" src="${baseUrl?html}/XUI/libs/requirejs-2.3.7-min.js"></script>
```

(`main-device` in the two device templates.) `index.html` is different — no `data-main`:

```html
<script src="libs/base64-1.0.0-min.js"></script>
<script type="text/javascript">
    var require = {
        urlArgs : "v=${version}",
        deps : ['main']
    };
</script>
<script src="libs/requirejs-2.3.7-min.js"></script>
```

### Completeness: confirmed by two independent sweeps

The claimed list of six is **complete and correct**. Sweeps run over the whole OpenAM checkout,
all file types, no extension filter:

```
grep -rn "data-main" .                                   # 15 hits total
rg -n -g '!target' -g '!node_modules' 'XUI/main' .
rg -n -g '!target' -g '!node_modules' 'main-authorize|main-device' .
rg -n -g '!target' -g '!node_modules' 'requirejs-2.3.7' .
```

**One `data-main` exists beyond the six, and it is unrelated to the XUI:**

- `openam-server-only/src/main/webapp/config/auth/default/devicePrintLogin.jsp:73`
  ```html
  <script language="JavaScript" data-main="<%= ServiceURI %>/js/openam-authnmodule-adaptive-deviceprint-scripts-min.js" src="<%= ServiceURI %>/js/require-jquery.js"></script>
  ```
  A different loader (`require-jquery.js`), a different tree (`/js/`, not `/XUI/`), a different
  target. **It does not load an XUI entry point and is out of scope for 4.2.** Worth recording only
  so a future `data-main` grep does not re-raise it as a finding. Note its `data-main` *does* carry
  a `.js` suffix, which takes the other branch described in §2 — irrelevant here but a useful
  contrast.

**Two near-misses checked and excluded:**

- `XUI/oauthReturn.html` (root of the shipped tree, `PHASE1-TREE.md:151`, 1,554 bytes). It is a
  self-contained classic-script IIFE that rewrites `window.location.href` to move OAuth query
  params into the hash fragment. It loads **no** script of any kind. It has no source under
  `openam-ui-ria/src` — it arrives from the commons `zip:www` unpack.
- `e2e/xui/xui-operator-module.spec.mjs:137` and `e2e/xui/NOTES-operator-module.md:201` describe a
  page loading `requirejs-2.3.7-min.js` with **no** `data-main` and no `baseUrl`. That is
  `index.html` itself (row 1), described from the test's point of view — not an eighth loader.

The remaining `XUI/main.js` hits are all in `e2e/local/server-lib/router.test.mjs` (lines 152, 187,
192, 199, 238, 660, 669), where the path is a **fixture string** for the local server's routing
tests, not a page that loads the entry.

---

## 2. WHAT `data-main` ACTUALLY DOES to a non-AMD file

Determined **from the deployed bytes only** — `target/XUI/libs/requirejs-2.3.7-min.js`, md5
`01252f25e96768861bd3effa7bf8889e`, 17,420 bytes, minified to a single line. Every quote below is
copied verbatim out of that file. Offsets are byte offsets into it.

### 2.1 The `data-main` handler — verbatim, at offset 4130

```js
isBrowser&&!cfg.skipDataMain&&eachReverse(scripts(),function(e){if(head=head||e.parentNode,dataMain=e.getAttribute("data-main"))return mainScript=dataMain,cfg.baseUrl||-1!==mainScript.indexOf("!")||(mainScript=(src=mainScript.split("/")).pop(),subPath=src.length?src.join("/")+"/":"./",cfg.baseUrl=subPath),mainScript=mainScript.replace(jsSuffixRegExp,""),req.jsExtRegExp.test(mainScript)&&(mainScript=dataMain),cfg.deps=cfg.deps?cfg.deps.concat(mainScript):[mainScript],!0}),
```

and, 500 bytes later in the same expression, the call that consumes it:

```js
define.amd={jQuery:!0},req.exec=function(text){return eval(text)},req(cfg)
```

De-minified:

```js
if (isBrowser && !cfg.skipDataMain) {
    eachReverse(scripts(), function (script) {
        head = head || script.parentNode;
        dataMain = script.getAttribute("data-main");
        if (dataMain) {
            mainScript = dataMain;
            if (!cfg.baseUrl && mainScript.indexOf("!") === -1) {
                src        = mainScript.split("/");
                mainScript = src.pop();
                subPath    = src.length ? src.join("/") + "/" : "./";
                cfg.baseUrl = subPath;
            }
            mainScript = mainScript.replace(jsSuffixRegExp, "");        // jsSuffixRegExp = /\.js$/
            if (req.jsExtRegExp.test(mainScript)) { mainScript = dataMain; }
            cfg.deps = cfg.deps ? cfg.deps.concat(mainScript) : [mainScript];
            return true;
        }
    });
}
...
req(cfg);
```

Two supporting literals, both verbatim:

```js
jsSuffixRegExp=/\.js$/                       // offset ~330, in the top-level var list
req.jsExtRegExp=/^\/|:|\?|\.js$/             // offset 2566
```

### 2.2 The trace for `data-main=".../XUI/main-authorize"`

The six `.ftl` pages set **only** a `pageData` global before the loader — verified by reading all
six: each has exactly one prior `<script type="text/javascript">` block, containing `pageData = {…}`
and nothing else. There is **no `var require = {…}`**, so `cfg` is `{}` and `cfg.baseUrl` is
undefined when the handler runs.

With `${baseUrl}` rendering to, e.g., `http://openam.example.org:8080/openam`:

1. `dataMain = "http://openam.example.org:8080/openam/XUI/main-authorize"`, `mainScript = dataMain`.
2. `!cfg.baseUrl` is true and there is no `"!"`, so the split branch runs:
   `mainScript = "main-authorize"`, `subPath = "http://openam.example.org:8080/openam/XUI/"`,
   **`cfg.baseUrl = "http://openam.example.org:8080/openam/XUI/"`**.
3. `.replace(/\.js$/, "")` — no change, there was no extension.
4. `req.jsExtRegExp.test("main-authorize")` → `/^\/|:|\?|\.js$/` against a bare basename → **false**
   (no leading `/`, no `:`, no `?`, no `.js`). So `mainScript` stays the **bare id**; the
   `mainScript = dataMain` revert does **not** fire.
5. `cfg.deps = ["main-authorize"]`.
6. `req(cfg)` → `require({ baseUrl: ".../XUI/", deps: ["main-authorize"] })`.

**Answer to the key sub-question: `data-main` is NOT used as a literal path here. It is reduced to a
module id (`"main-authorize"`) plus an inferred `baseUrl`, and then loaded through the ordinary
`require([...])` machinery — which means it goes through `nameToUrl`.**

The revert branch at step 4 is worth knowing about: it fires only when the value still looks like a
URL *after* the basename split, i.e. when `cfg.baseUrl` was already configured (skipping step 2) or
the value contains a loader-plugin `!`. **If any of those six pages ever gained a global
`require = { baseUrl: … }`, `data-main` would become a literal URL and the analysis below would not
apply.** Today none of them has one.

### 2.3 `nameToUrl` — `.js` is appended, and `urlArgs` is applied

Verbatim, offset 16127:

```js
nameToUrl:function(e,t,i){var r,n,o,a,s,u=getOwn(b.pkgs,e);if(u=getOwn(m,e=u?u:e))return f.nameToUrl(u,t,i);if(req.jsExtRegExp.test(e))a=e+(t||"");else{for(r=b.paths,o=(n=e.split("/")).length;0<o;--o)if(s=getOwn(r,n.slice(0,o).join("/"))){isArray(s)&&(s=s[0]),n.splice(0,o,s);break}a=n.join("/"),a=("/"===(a+=t||(/^data\:|^blob\:|\?/.test(a)||i?"":".js")).charAt(0)||a.match(/^[\w\+\.\-]+:/)?"":b.baseUrl)+a}return b.urlArgs&&!/^blob\:/.test(a)?a+b.urlArgs(e,a):a},load:function(e,t){req.load(f,e,t)},
```

Three things this settles, for the id `"main-authorize"` (`b` is the context config):

- **`.js` IS appended.** `a += t || (/^data\:|^blob\:|\?/.test(a) || i ? "" : ".js")` — `t` (ext) is
  undefined and `i` (skipExt) is false for a normal `require([…])` load, so `".js"` is concatenated.
  The requested URL is `<baseUrl>main-authorize.js`.
- **`paths` mapping WOULD apply.** The `for` loop walks `b.paths` longest-prefix-first. No `paths`
  entry named `main-authorize` exists in any of the three entries (§5), so today it is a no-op — but
  it is on the path, which is why `data-main` is a module id and not an opaque URL.
- **`urlArgs` IS applied**, on the single return: `return b.urlArgs && !/^blob\:/.test(a) ? a + b.urlArgs(e,a) : a`.
  There is no `data-main`-specific or `skipExt`-specific bypass. This is the same return path
  `e2e/xui/NOTES-urlargs.md` established for `toUrl` in task 1.12 — `toUrl` (offset ~15500,
  `f.nameToUrl(v(e,o&&o.id,!0),t,!0)`) is just another caller of it.

  **But `urlArgs` is not configured on the six `.ftl` pages** (§2.2 — they set only `pageData`), so
  in practice those two entries are requested **without** a cache-buster: `…/XUI/main-authorize.js`,
  plain. `urlArgs` is set only in `index.html:24` (`"v=${version}"`), which is why the `main` entry
  and everything it pulls *is* requested as `…?v=<version>`.

  The asymmetry is a live consequence for the migration: **the two secondary entries have no
  cache-busting mechanism at all today**, so whatever replaces them must be either unhashed and
  short-cache-lived, or hashed behind a stable-named indirection. `urlArgs` normalisation is task
  4.9's (`resolveAssetUrl`), but 4.9 covers `require.toUrl` call sites, not this.

### 2.4 The script node is a CLASSIC script — so an IIFE runs, and ESM does not

Verbatim, offset ~3021:

```js
req.createNode=function(e,t,i){var r=e.xhtml?document.createElementNS("http://www.w3.org/1999/xhtml","html:script"):document.createElement("script");return r.type=e.scriptType||"text/javascript",r.charset="utf-8",r.async=!0,r},req.load=function(t,i,r){var e,n=t&&t.config||{};if(isBrowser)return(e=req.createNode(n,i,r)).setAttribute("data-requirecontext",t.contextName),e.setAttribute("data-requiremodule",i),
```

and the tail of `req.load`, offset ~4130:

```js
e.src=r,n.onNodeCreated&&n.onNodeCreated(e,n,i,r),currentlyAddingScript=e,baseElement?head.insertBefore(e,baseElement):head.appendChild(e),currentlyAddingScript=null,e;
```

and the `Module` method that supplies the url, offset 10003:

```js
load:function(){var e=this.map.url;n[e]||(n[e]=!0,f.load(this.map.id,e))}
```

So: `script.type = config.scriptType || "text/javascript"`, `script.async = true`,
`script.src = <the nameToUrl url>`, appended to `head`. **`type="text/javascript"` — a classic
script.** The browser parses and executes it on arrival, unconditionally, before RequireJS looks at
it at all.

Consequences:

- **A plain IIFE at that URL runs normally.** Nothing about `data-main` gates execution on the file
  being AMD.
- **An ES module at that URL does NOT work.** A top-level `import`/`export` in a classic script is a
  `SyntaxError` at parse time. `scriptType` can be configured (`config.scriptType`), but only from a
  global `require` object on the page — which the six `.ftl` pages do not have, and adding one is a
  server-side change.

### 2.5 What happens after it runs if it never calls `define()` — nothing bad

`completeLoad`, verbatim, offset ~16000:

```js
completeLoad:function(e){var t,i,r,n=getOwn(b.shim,e)||{},o=n.exports;for(O();l.length;){if(null===(i=l.shift())[0]){if(i[0]=e,t)break;t=!0}else i[0]===e&&(t=!0);a(i)}if(f.defQueueMap={},r=getOwn(d,e),!t&&!hasProp(h,e)&&r&&!r.inited){if(!(!b.enforceDefine||o&&getGlobal(o)))return E(e)?void 0:M(makeError("nodefine","No define call for "+e,null,[e]));a([e,n.deps||[],n.exportsFn])}P()}
```

De-minified (`t`=found, `d`=registry, `h`=defined, `l`=defQueue, `a`=callGetModule,
`E`=hasPathFallback, `M`=onError, `P`=checkLoaded):

```js
completeLoad: function (moduleName) {
    var found, args, mod, shim = getOwn(config.shim, moduleName) || {}, exports = shim.exports;
    takeGlobalQueue();
    while (defQueue.length) { /* … match anonymous/named defines to moduleName … */ }
    context.defQueueMap = {};
    mod = getOwn(registry, moduleName);
    if (!found && !hasProp(defined, moduleName) && mod && !mod.inited) {
        if (!(!config.enforceDefine || (exports && getGlobal(exports)))) {
            return hasPathFallback(moduleName) ? undefined
                 : onError(makeError("nodefine", "No define call for " + moduleName, null, [moduleName]));
        }
        callGetModule([moduleName, shim.deps || [], shim.exportsFn]);   // synthesise a definition
    }
    checkLoaded();
}
```

`enforceDefine` is **not set anywhere** in this codebase — `rg 'enforceDefine'` over
`openam-ui-ria/src`, `Gruntfile.js`, `vite.config.js` and `openam-oauth2/src` returns nothing, and
none of the six `.ftl` pages nor `index.html` defines a global `require` carrying it. So
`!config.enforceDefine` is **true**, the guard's condition is false, the `"No define call"` error is
**not** reached, and control falls through to `callGetModule([name, [], undefined])`, which registers
the module with an `undefined` export and lets `checkLoaded()` complete the graph.

**This is not theoretical — it is what happens today.** The current `src/main/js/main-authorize.js`
is itself a non-AMD classic script: it calls `require.config({…})` and `require([…], fn)` against the
global `require` that the already-loaded `requirejs-2.3.7-min.js` installed, and it never calls
`define()`. Same for `main-device.js`. The shipped `main-authorize.js` is 5,044 bytes
(`PHASE1-TREE.md:148`) and `main-device.js` 2,907 (`:149`) — essentially the Babel-transpiled
sources, unbundled. The live pages therefore already prove the whole path.

### 2.6 Summary of §2

| Question | Answer, from the 2.3.7 bytes |
|---|---|
| Does `data-main` go through `nameToUrl`? | **Yes** (when it has no `!` and no `.js` suffix, as here). It becomes `cfg.deps = ["main-authorize"]` plus an inferred `baseUrl`, then an ordinary `require([…])`. |
| Does it therefore pick up `urlArgs`? | **Yes, structurally** — `nameToUrl`'s single return applies it. **But `urlArgs` is not configured on those six pages**, so no cache-buster is appended in practice. Only `index.html` sets one. |
| Is `.js` appended? | **Yes**, by `nameToUrl`. The request is `<baseUrl>main-authorize.js`. |
| What is `baseUrl` inferred as? | The **directory portion of the `data-main` value** — `cfg.baseUrl = subPath` where `subPath` is everything before the last `/`, with a trailing slash. Here: `<AM baseUrl>/XUI/`. |
| Must the file call `define()`? | **No.** The browser executes it as a classic script regardless, and `completeLoad` synthesises a definition because `enforceDefine` is unset. A bare IIFE just runs. |
| Can the file be an ES module? | **No.** `req.createNode` sets `type="text/javascript"`. A classic script cannot contain top-level `import`/`export`. |
| Does `libs/requirejs-2.3.7-min.js` still need to exist? | **Yes, unconditionally**, for as long as the `.ftl` files are unchanged — it is the `src` attribute. If it 404s, `data-main` is never read and nothing loads at all. |

---

## 3. THE OPTION SET, and what each costs

### The constraint that frames all of them: D8 and task 10.4

`design.md:164-170`, **D8 — Maven stays the outer build; the zip contract is unchanged**:

> `frontend-maven-plugin` continues to drive the frontend build; only the npm script behind it
> changes. `src/main/assembly/zip.xml` keeps producing `openam-ui-ria-www.zip` from the build output
> directory.
>
> *Why:* `openam-server` consumes that artifact. Preserving it keeps the blast radius inside
> `openam-ui`, **and lets the migration land without a coordinated server-side change.**

`tasks.md:122`, task **10.4**:

> - [ ] 10.4 **Confirm the server build produces a working deployable with no server-side change**

Both are unambiguous, and both are about *this*: the two secondary entries are loaded from a module
`openam-ui-ria` does not own.

### (a) Emit `main-authorize` / `main-device` as unhashed IIFE entry chunks at those exact paths

Keep `libs/requirejs-2.3.7-min.js` in the tree purely so the `.ftl` `src` resolves and `data-main`
still runs.

- **Change outside `openam-ui-ria`? NO.**
- **Blocked as a single build.** IIFE cannot be produced for three entries in one Rollup output —
  see §4.2, verified against the installed rollup 4.62.5 and vite 5.4.21. It requires **two extra
  single-entry Vite builds** (one per secondary entry) alongside the main build, each with
  `format: "iife"` and `inlineDynamicImports` (which Vite sets automatically for `iife`).
- **Cost — size.** Those two entries are 5,044 and 2,907 bytes today because they are *unbundled*:
  they `require([...])` jQuery, lodash, Handlebars, i18next, `Configuration`, `Constants`,
  `i18nManager`, `ThemeManager`, `SingleRouteRouter` and (for `main-device`) four `text!` templates
  **by path at runtime**, sharing the 308 unbundled `.js` files and 50 `libs/` files with `main`
  (`NOTES-vite-build.md:276-277`). An IIFE bundle inlines all of that into each file — jQuery,
  lodash, Handlebars and i18next alone are several hundred KB, duplicated into **both** secondary
  bundles **and** again into `main`. Three near-complete copies of the vendor set in one tree.
- **Cost — no code-splitting for those two entries.** Acceptable in isolation (neither uses a dynamic
  import today), but it means the `ui-module-loading` requirement is satisfied only by `main`.
- **Cost — a shared-chunk story that cannot exist.** Separate builds cannot share a chunk with
  `main` by construction. §5 argues this is a *feature*, not only a cost.
- **Cost — three build invocations** to wire into one npm script and one `frontend-maven-plugin`
  execution, and three `outDir`s to merge without one emptying another
  (`emptyOutDir` — see the caveat at the top of this file).
- **Interaction with task 4.7 that is easy to miss.** "Keep `libs/requirejs-2.3.7-min.js` in the
  tree" is not free: **there is no `src/main/js/libs/requirejs-2.3.7-min.js`.** The file arrives via
  `target/dependencies` from the Maven unpack that task 4.7 retires. Whichever option is chosen, if
  RequireJS must survive, its *source* has to move — `node_modules/requirejs/require.js` is the same
  2.3.7 release (`version = '2.3.7'`, line 14) and is already a devDependency
  (`requirejs: 2.3.7`), so a `publicDir`/copy step from `node_modules` is available. **Record this
  as a dependency 4.2 hands to 4.7.**

### (b) Change the six `.ftl` files to `<script type="module" src=".../XUI/main-authorize.js">`

Drop RequireJS from those pages entirely.

- **Change outside `openam-ui-ria`? YES** — six files in `openam-oauth2/src/main/resources/templates/`,
  a different Maven module, packaged into a different artifact.
- **This contradicts D8 and task 10.4 as they are written.** D8's stated *why* is that preserving the
  zip contract "lets the migration land **without a coordinated server-side change**"; 10.4 is the
  gate that confirms exactly that. Option (b) is a coordinated server-side change by definition.
  **Not decided here** — the tradeoff is recorded, not resolved.
- **The tradeoff, stated fairly.** It is by far the *cleanest* end state: native ESM, no loader
  shim, no `libs/requirejs-2.3.7-min.js` to keep alive, no format contortion, and hashing becomes
  possible for those two entries too (the `.ftl` would have to name the hashed file, or read a
  manifest — which is itself another coupling). Against that: it re-scopes the change from
  "inside `openam-ui`" to "`openam-ui` + `openam-oauth2`", makes the XUI build and the AM server
  build lock-step for one release, and forfeits D8's rollback story — reverting the UI build no
  longer restores a working consent screen unless the `.ftl` revert ships with it.
- **A partial variant exists**: change only the `src` (point it at an ESM entry) and *keep* the
  `data-main` attribute, so an old server template still works against a new tree. This does not
  reduce the blast radius — it is still six `.ftl` edits in `openam-oauth2`.

### (c) Other options found

#### (c1) A generated unhashed classic-script **stub** at each of the two paths, dynamically importing the real hashed ESM chunk

`/XUI/main-authorize.js` becomes a few bytes of classic script:

```js
/* generated */ import("./assets/main-authorize-<hash>.js");
```

- **Change outside `openam-ui-ria`? NO.**
- **Why it works, from §2:** the `.ftl` `src` still finds RequireJS; `data-main` still resolves to
  the id `main-authorize`; `nameToUrl` still requests `/XUI/main-authorize.js`; the browser executes
  it as a **classic** script (§2.4) — and `import()` *is* legal in a classic script, unlike a static
  `import`. The stub calls no `define()`, so `completeLoad` synthesises an empty module and does not
  error (§2.5).
- **Keeps code-splitting and hashing** for the real chunks, and lets all three entries **share**
  chunks — subject entirely to §5's `map` problem, which is what actually decides whether sharing is
  safe.
- **Cost:** a small Vite plugin to emit the stubs, reading the hashed names out of the bundle in
  `generateBundle`/`writeBundle`. It is real code to own and test.
- **Cost:** an extra round-trip on those two pages (stub, then chunk) with no HTTP preload hint,
  since the `.ftl` `<head>` cannot be touched.
- **Cost:** RequireJS is still loaded and parsed on those pages (17 KB) purely to be ignored — and
  it still has to be kept in the tree (see the 4.7 note in (a)).
- **Cost / unresolved:** dynamic `import()` from a classic script is modern-browser-only. `index.html`
  still carries IE9 conditional comments (`index.html:9-14`); ESM at all ends IE support regardless,
  so this is arguably already conceded by the change as a whole — but it is not conceded *anywhere
  in writing* that I found. **Recorded as an open point for 4.2/4.5.**

#### (c2) Emit those entries in **AMD** format so RequireJS loads them as intended

- **Change outside `openam-ui-ria`? NO.**
- **Rollup permits AMD with code-splitting**, unlike IIFE/UMD: `validateOptionsForMultiChunkOutput`
  (rollup 4.62.5, `dist/shared/rollup.js:22453-22455`) rejects **only** `umd` and `iife`. Vite's
  automatic `inlineDynamicImports` is likewise set only for `umd`/`iife`
  (`vite/dist/node/chunks/dep-BK3b2jBa.js:65646`). So `format: "amd"` is *not* blocked by either
  guard.
- **Attractive on paper**: the file calls anonymous `define([...], fn)`, `completeLoad` names it,
  and shared chunks become AMD modules RequireJS resolves itself — cache-busting via `urlArgs` would
  even work again.
- **UNVERIFIED, and I could not settle it without running a build** (which this task does not do).
  Open questions: whether Rollup's AMD relative chunk ids (`"./chunk-<hash>.js"`) resolve correctly
  under RequireJS's `nameToUrl` given `req.jsExtRegExp` matches a `.js`-suffixed id and takes the
  literal-URL branch; whether Vite's ESM-assuming runtime helpers (`__vitePreload`, `import.meta.url`
  rewriting, the modulepreload plugin) survive an AMD output in a **non-lib** app build; and whether
  a mixed tree (ESM `main` + AMD secondaries) can share chunks at all — almost certainly not, since
  a chunk has one format. **Needs a spike before it can be costed.**

#### (c3) Leave the two secondary entries out of the Vite build entirely — copy them verbatim

Treat `main-authorize.js` and `main-device.js` the way `templates/` and `locales/` are treated in
task 4.4: static, unbundled, copied to the tree root, still AMD/classic, still resolved at runtime by
the RequireJS that stays on those pages.

- **Change outside `openam-ui-ria`? NO.** This is the *only* option that changes nothing at all about
  what those pages fetch — the bytes at `/XUI/main-authorize.js` stay what they are today.
- **Cost:** RequireJS, the `paths`/`shim`/`map` config and the entire unbundled AMD module tree they
  reach (`ThemeManager`, `Configuration`, `Constants`, `i18nManager`, `SingleRouteRouter`,
  `store/index`, the `text!` plugin, and every `libs/` vendor file they name) must **all keep
  existing in AMD form** in the shipped tree. That directly collides with group 5 (task 5.1, the
  AMD→ESM conversion of 203 modules) — the moment those modules become ESM, these two entries stop
  resolving.
- So this is explicitly a **deferral**, not a solution: it keeps phase 2 green and moves the whole
  problem to phase 5, where the same option set reappears with fewer choices (the AMD tree is gone).
  Worth recording precisely because it is the cheapest thing to do in 4.2 and the most expensive
  thing to discover in 5.1.

### Option summary

| Option | Change outside `openam-ui-ria`? | Code-splitting for the 2 secondaries? | Hashing for them? | RequireJS still shipped? | Main risk |
|---|---|---|---|---|---|
| (a) unhashed IIFE entries | **No** | No | No | Yes (`src` only) | 3 builds; vendor code triplicated; no chunk sharing |
| (b) `type="module"` in the `.ftl` | **Yes — 6 files in `openam-oauth2`** | Yes | Yes | No | contradicts D8 and 10.4 |
| (c1) unhashed classic stub → dynamic `import()` | **No** | Yes | Yes (behind the stub) | Yes (unused) | custom plugin; extra round-trip; §5 must be solved |
| (c2) AMD format output | **No** | Rollup allows it | via `urlArgs` | Yes (used) | **unverified**; Vite helpers assume ESM |
| (c3) copy verbatim, don't build them | **No** | n/a | No | Yes (used) | defers the whole problem into task 5.1 |

**Not decided here.** (a), (c1), (c2) and (c3) all satisfy "no change outside `openam-ui-ria`";
they differ in what they cost and where they push the cost.

---

## 4. THE NAMING CONFIGURATION

Grounded in the versions actually installed in this module: **vite 5.4.21, rollup 4.62.5**
(`node_modules/{vite,rollup}/package.json`).

### 4.1 What Vite does by default, and why the current output looks the way it does

`vite/dist/node/chunks/dep-BK3b2jBa.js:65635-65646`:

```js
entryFileNames: ssr ? `[name].${jsExt}`
              : libOptions ? ({ name }) => resolveLibFilename(libOptions, format, name, root, jsExt, packageCache)
              : path.posix.join(options.assetsDir, `[name]-[hash].${jsExt}`),
chunkFileNames: libOptions ? `[name]-[hash].${jsExt}` : path.posix.join(options.assetsDir, `[name]-[hash].${jsExt}`),
assetFileNames: libOptions ? `[name].[ext]`          : path.posix.join(options.assetsDir, `[name]-[hash].[ext]`),
inlineDynamicImports: output.format === "umd" || output.format === "iife" || ssrWorkerBuild && (typeof input === "string" || Object.keys(input).length === 1),
...output
```

`assetsDir` defaults to `"assets"`, which is exactly why the current skeleton emitted
`assets/main-CfrLTCo_.js`. `PHASE1-TREE.md:155-156` states the requirement it violates:

> Three entry points — `main.js`, `main-authorize.js`, `main-device.js` — all at the tree root with
> **stable, unhashed names**. Vite's default `assets/<name>-<hash>.js` breaks this.

### 4.2 IIFE and code-splitting — verified, not recalled

**Two independent guards, both in the installed bytes:**

1. `rollup/dist/shared/rollup.js:22453-22455`, reached from `:22309` (`if (chunks.length > 1)`):

   ```js
   function validateOptionsForMultiChunkOutput(outputOptions, log) {
       if (outputOptions.format === 'umd' || outputOptions.format === 'iife')
           return error(logInvalidOption('output.format', URL_OUTPUT_FORMAT,
               'UMD and IIFE output formats are not supported for code-splitting builds', outputOptions.format));
   ```

   Note the trigger is **`chunks.length > 1`**, not "has a dynamic import". Three entry points
   produce three chunks, so this fires even with zero dynamic imports. **AMD, ES, CJS and SystemJS
   are *not* rejected** — only UMD and IIFE.

2. `rollup/dist/shared/rollup.js:23831-23832`:

   ```js
   if (inlineDynamicImports && (Array.isArray(input) ? input : Object.keys(input)).length > 1)
       return error(logInvalidOption('output.inlineDynamicImports', URL_OUTPUT_INLINEDYNAMICIMPORTS,
           'multiple inputs are not supported when "output.inlineDynamicImports" is true'));
   ```

**The consequence, precisely:** setting `format: "iife"` on a three-entry Vite build fails at
*option validation*, before chunking, because Vite auto-sets `inlineDynamicImports: true` for `iife`
(`:65646`) and rollup then rejects it for having 3 inputs. Overriding
`output.inlineDynamicImports: false` (legal — the `...output` spread at `:65647` puts user options
last) does not rescue it: the build then reaches `:22309` with 3 chunks and dies on
*"UMD and IIFE output formats are not supported for code-splitting builds"*.

**`build.lib` does not help either.** `vite/…:65794-65803`:

```js
const libHasMultipleEntries = typeof libOptions.entry !== "string" && Object.values(libOptions.entry).length > 1;
const libFormats = libOptions.formats || (libHasMultipleEntries ? ["es", "cjs"] : ["es", "umd"]);
if (!Array.isArray(outputs)) {
    if (libFormats.includes("umd") || libFormats.includes("iife")) {
        if (libHasMultipleEntries) {
            throw new Error('Multiple entry points are not supported when output formats include "umd" or "iife".');
```

Lib mode also swaps `entryFileNames` for `resolveLibFilename` and `assetFileNames` for
`[name].[ext]` (`:65635-65644`), i.e. it takes away the very control this task needs. **A normal
multi-entry app build is the right shape; lib mode is not.**

**Therefore: IIFE for three entries in one build is impossible. The only route to IIFE is one
single-entry build per entry** — which is option (a), and which forfeits code-splitting for those
entries.

### 4.3 The config that gives unhashed entries at the tree root **and** keeps code-splitting

Copy-pasteable, for `vite.config.js`'s existing `build` block:

```js
import { resolve } from "node:path";

// …
build: {
    outDir: "target/compiled",
    emptyOutDir: true,
    sourcemap: true,

    rollupOptions: {
        input: {
            "main":           resolve(__dirname, "src/main/js/main.js"),
            "main-authorize": resolve(__dirname, "src/main/js/main-authorize.js"),
            "main-device":    resolve(__dirname, "src/main/js/main-device.js")
        },
        output: {
            // ES is the only format that supports code-splitting AND is what a
            // <script type="module"> / dynamic import() can execute. See §4.2.
            format: "es",

            // The three entry points keep stable, unhashed names at the tree ROOT,
            // because AM's FreeMarker templates hardcode two of these paths.
            entryFileNames: "[name].js",

            // Everything Rollup splits out stays hashed, under assets/.
            chunkFileNames: "assets/[name]-[hash].js",
            assetFileNames: "assets/[name]-[hash].[ext]"
        }
    }
}
```

The `[name]` for an entry chunk is the **key** of the `input` object, so the three keys above are
what produce `main.js`, `main-authorize.js`, `main-device.js` at the root. `entryFileNames` applies
**only** to entry chunks; `chunkFileNames` to every code-split chunk — so hashing is preserved
exactly where the `ui-module-loading` requirement needs it and dropped exactly where the `.ftl`
files need it. **Turning hashing off entirely is not required and is not proposed here.**

A stricter variant, if any *other* entry chunk should stay hashed (e.g. an HTML entry added by
task 4.5), since `entryFileNames` accepts a function:

```js
const UNHASHED_ENTRIES = new Set(["main", "main-authorize", "main-device"]);

entryFileNames: (chunkInfo) =>
    UNHASHED_ENTRIES.has(chunkInfo.name) ? "[name].js" : "assets/[name]-[hash].js",
```

Notes on the individual options, as asked:

- **`output.format`** — must be `"es"` for a code-splitting multi-entry build. `"iife"`/`"umd"` are
  rejected (§4.2). `"amd"` and `"system"` are *not* rejected by either guard, which is what makes
  option (c2) worth a spike.
- **`output.inlineDynamicImports`** — **cannot be used here.** Rollup rejects it outright with more
  than one input (`:23831`). It is also the mechanism Vite silently enables for `iife`, which is the
  proximate reason `format: "iife"` fails.
- **`output.entryFileNames` / `chunkFileNames` / `assetFileNames`** — as above. Note
  `assetFileNames` governs CSS and copied assets and is where task 4.4's "unbundled and unhashed"
  requirement for `themes/`, `templates/`, `partials/`, `locales/` will collide; those are better
  handled by `publicDir`/a copy plugin than by `assetFileNames`, since they must not be hashed
  **or** renamed. Not settled here — 4.4's.
- **Interaction with `index.html` (task 4.5)** — if `index.html` is added as an HTML input, Vite
  derives an entry chunk from it and `entryFileNames` applies to that too. Declaring `main` as an
  explicit JS input *and* `index.html` as an HTML input that references it risks emitting the entry
  twice under two names. **Flagged for 4.5; not resolved here.**
- **`build.manifest`** — not required by any option above, but option (c1)'s stub generator would
  read the bundle in `generateBundle` rather than the manifest file, since the stub must be emitted
  in the same build.

---

## 5. WHAT THE THREE ENTRIES SHARE — and the shared-chunk hazard

Task 4.3 owns translating `require.config.map` into `resolve.alias`. What follows records **which
entry declares what**, and one specific way a shared chunk breaks.

### 5.1 Per entry, verbatim from source

#### `src/main/js/main.js` (204 lines)

- **`map["*"]` — 12 bindings** (`main.js:19-34`, the range task 4.3 names):

  | logical name | bound to |
  |---|---|
  | `Footer` | `org/forgerock/openam/ui/common/components/Footer` |
  | `ThemeManager` | `org/forgerock/openam/ui/common/util/ThemeManager` |
  | `LoginView` | `org/forgerock/openam/ui/user/login/RESTLoginView` |
  | `UserProfileView` | `org/forgerock/commons/ui/user/profile/UserProfileView` |
  | `ForgotUsernameView` | `org/forgerock/openam/ui/user/anonymousProcess/ForgotUsernameView` |
  | `PasswordResetView` | `org/forgerock/openam/ui/user/anonymousProcess/PasswordResetView` |
  | `LoginDialog` | `org/forgerock/openam/ui/user/login/RESTLoginDialog` |
  | `NavigationFilter` | `org/forgerock/openam/ui/common/components/navigation/filters/RouteNavGroupFilter` |
  | **`Router`** | **`org/forgerock/commons/ui/common/main/Router`** |
  | `RegisterView` | `org/forgerock/openam/ui/user/anonymousProcess/SelfRegistrationView` |
  | `KBADelegate` | `org/forgerock/openam/ui/user/services/KBADelegate` |
  | `underscore` | `lodash` |

- **`paths` — 41 entries** (`main.js:37-77`): the full vendor set — `autosizeInput`, `backbone`,
  `backbone.paginator`, `backbone-relational`, `backgrid`, `backgrid-filter`, `backgrid.paginator`,
  `backgrid-selectall`, `bootstrap`, `bootstrap-datetimepicker`, `bootstrap-dialog`,
  `bootstrap-tabdrop`, `classnames`, `clockPicker`, `doTimeout`, `form2js`, `handlebars`, `i18next`,
  `jquery`, `js2form`, `jsonEditor`, `lodash`, `microplugin`, `moment`, `popoverclickaway`, `qrcode`,
  `react-bootstrap`, `react-dom`, `react`, `react-input-autosize`, `react-select`, `redux`,
  `selectize`, `sifter`, `sortable`, `spin`, `text`, `xdate`.
- **`shim` — 25 entries** (`main.js:78-171`), including the `react-input-autosize` →
  `reactAutosizeInputDep` and `react-select` → `reactSelectDep` indirections.
- **Two named `define()` calls of its own** (`main.js:173-183`): `"reactAutosizeInputDep"` and
  `"reactSelectDep"`, whose whole purpose is assigning `window.React`, `window.ReactDOM`,
  `window.classNames`, `window.AutosizeInput`. **These are globals-by-side-effect and will not
  survive a naive ESM translation** — recorded here because it is an entry-local fact, though it is
   5.1's to fix.
- **`deps` / callback** (`main.js:185-204`): requires `Constants`, `EventManager`, `jquery`,
  `lodash`, `backbone`, `handlebars`, `i18next`, `spin`,
  `org/forgerock/commons/ui/common/main`, `org/forgerock/openam/ui/main`, `config/main`,
  `store/index`; the callback fires a single `EventManager.sendEvent(Constants.EVENT_DEPENDENCIES_LOADED)`.

#### `src/main/js/main-authorize.js` (160 lines)

- **`map["*"]` — 3 bindings** (`main-authorize.js:28-35`):

  | logical name | bound to |
  |---|---|
  | `ThemeManager` | `org/forgerock/openam/ui/common/util/ThemeManager` — **same as `main`** |
  | **`Router`** | **`org/forgerock/openam/ui/common/SingleRouteRouter`** — **DIFFERENT from `main`** |
  | `underscore` | `lodash` — same as `main` |

- **`paths` — 6 entries** (`:36-43`): `handlebars`, `i18next`, `jquery`, `lodash`, `redux`, `text`.
  All six are declared identically in `main.js`. `redux` is present only because `ThemeManager`
  requires `store/index`, which requires it.
- **`shim` — 3 entries** (`:44-55`): `handlebars` (`exports: "handlebars"`), `i18next`
  (`deps: ["jquery","handlebars"], exports: "i18n"`), `lodash` (`exports: "_"`). All three identical
  to `main`'s.
- **`deps` / callback** (`:58-159`): `jquery`, `lodash`, `handlebars`, `Configuration`, `Constants`,
  `i18nManager`, `ThemeManager`, `Router`. The callback sets `window.$` and `window._`, inits i18n
  with `nameSpace: "authorize"`, normalises `pageData.oauth2Data`, sets
  `Configuration.globalData = { realm }` and `Router.currentRoute = { navGroup: "user" }`, then
  inside `ThemeManager.getTheme().always()` re-requires its four templates **theme-prefixed**
  (`:134-136`, `text!${themePath}${templatePath}`), compiles them and binds a
  `"click keyup"` panel toggle (`:149-156`).

#### `src/main/js/main-device.js` (88 lines)

- **`map["*"]`, `paths`, `shim`: byte-identical to `main-authorize.js`.** Verified:
  `diff <(sed -n '18,47p' main-device.js) <(sed -n '27,56p' main-authorize.js)` → no output. Same
  3 map bindings including **`Router` → `SingleRouteRouter`**, same 6 paths, same 3 shims.
- **`deps` / callback** (`:49-88`): `jquery`, `handlebars`, `Configuration`, `Constants`, then
  **four `text!` templates listed statically** (`text!templates/user/DeviceTemplate.html`,
  `DeviceDoneTemplate.html`, `templates/common/LoginBaseTemplate.html`, `FooterTemplate.html`,
  `LoginHeaderTemplate.html`), then `i18nManager`, `ThemeManager`, `Router`. Inits i18n with
  `nameSpace: "device"`, sets `Configuration.globalData` and `Router.currentRoute = {navGroup:"user"}`,
  and renders `data.done ? DeviceDoneTemplate : DeviceTemplate`. **No logic of its own** beyond that
  ternary.

### 5.2 The shared-chunk hazard is REAL, and it is `Router`

`Router` is bound to **two different modules** depending on the entry:

| Entry | `Router` resolves to | What that is |
|---|---|---|
| `main` | `org/forgerock/commons/ui/common/main/Router` | the full commons Backbone router |
| `main-authorize`, `main-device` | `org/forgerock/openam/ui/common/SingleRouteRouter` | `define({ currentRoute: null })` — a 2-line stub, the entire file |

That would be harmless if only the entry files consumed the name. **They do not.** A sweep for the
bare id across `src/main/js` and both commons npm packages returns exactly four consumers — the
three entries, and:

- **`src/main/js/org/forgerock/openam/ui/common/util/ThemeManager.js:25`** — `"Router"` is the
  eighth dependency in its `define([...])` array, and at **`ThemeManager.js:168`**:

  ```js
  isAdminTheme = Router.currentRoute.navGroup === "admin",
  ```

**`ThemeManager` is required by all three entries.** So the same module must see two different
`Router` implementations depending on which entry pulled it in. In RequireJS that works, because
`map` is per-context and resolution is per-referrer. **In a Vite/Rollup build it does not**, because
`resolve.alias` (task 4.3's mechanism) is **global to the build** — one build cannot give `Router`
two meanings.

Concretely, if `ThemeManager` lands in a chunk shared between `main` and the two secondary entries:

- **alias `Router` → commons `Router`:** on the consent and device pages nothing ever sets
  `currentRoute` on *that* object — the entries set it on `SingleRouteRouter`
  (`main-authorize.js:126-128`, `main-device.js:76-78`). `Router.currentRoute` is `null`, so
  `ThemeManager.js:168` throws `TypeError: Cannot read properties of null (reading 'navGroup')`, the
  theme never resolves, `structure.css` is never appended, and — because both `.ftl` families ship
  `<body style="display:none">` and nothing else removes it — **the page stays blank**. It also drags
  the whole commons router and its route table onto two pages that have no routes.
- **alias `Router` → `SingleRouteRouter`:** the console can never report `navGroup === "admin"`, so
  the **admin theme silently stops being applied** in the console — a quiet behaviour change, not a
  crash, and the worse of the two failures to debug.

**Conclusion for §5: the three entries can share chunks safely for everything *except* the modules
whose behaviour depends on a per-entry `map` binding.** Today that set is `{ ThemeManager }`, via
`Router`. `ThemeManager` and `underscore → lodash` are bound identically everywhere and are safe.
The nine `main`-only bindings (`Footer`, `LoginView`, `UserProfileView`, `ForgotUsernameView`,
`PasswordResetView`, `LoginDialog`, `NavigationFilter`, `RegisterView`, `KBADelegate`) are safe
because the secondary entries never reach them.

Ways out — **not decided here**, and 4.3 owns the choice:

1. Do not share: separate builds per entry (option (a)), which makes the collision structurally
   impossible at the cost of duplicating everything.
2. Remove the collision at the source: have `ThemeManager` take the router as a parameter, or
   import `SingleRouteRouter` explicitly, or give the two names distinct ids. This is a **source
   change inside `openam-ui-ria`** and therefore permitted under D8 — but it changes behaviour the
   e2e specs pin, and `e2e/xui/xui-device.spec.mjs:37-38` explicitly calls this binding out as
   something to guard.
3. Per-entry alias via three Vite configs / three `build` invocations sharing a cache — same as (1)
   in practice.

`e2e/xui/xui-device.spec.mjs:37-38` already names it as the thing to protect:

> `require.config.map` rebinding, declared a third time in main-device.js (D2), and note that its
> Router binding is SingleRouteRouter rather than the console's Router;

---

## 6. HOW EACH ENTRY IS COVERED TODAY

Both specs live in the OpenAM checkout at `/Users/maximthomas/Documents/_projects/forgerock/OpenAM/e2e/xui/`.
Both are tagged `@deployed-am` — they **cannot** run against the local API server, because AM itself
serves these pages (`design.md`'s D16 case; see task 2.13).

### `e2e/xui/xui-authorize.spec.mjs` — the `main-authorize` entry (5 tests)

From its header (`:17-51`), what it is guarding:

- *"a second entry point exists at all and is reachable at the URL AM hardcodes into its own HTML
  (design.md D7, task 4.2 — **a multi-entry build that emitted one bundle would fail here alone**)"*;
- *"`require.config.map` rebinding, declared separately in main-authorize.js from main.js (D2)"*;
- templates and locales fetched by path at runtime and compiled in the browser, *"through the `text!`
  plugin rather than UIUtils, and prefixed with the theme path (D3, and main-authorize.js:133 …)"*.
  Its strings are asserted against the **deployed `locales/en/authorize.json`**, *"so this fails if
  the bundle stops being copied verbatim or the entry point stops selecting the `authorize`
  namespace"*;
- the theme actually being applied: *"`authorize.ftl` ships `<body style="display:none">` and nothing
  in the page removes it, so the page becomes visible only once ThemeManager has appended
  structure.css, whose `body { display: block !important }` overrides it. **Every `toBeVisible()`
  below therefore also asserts the theme was applied.**"*

Tests: `the consent screen renders the authorization request` (:155), `a scope panel expands to show
the values it covers` (:203), `allowing the request returns an authorization code to the client`
(:221), `denying the request returns access_denied to the client` (:232), `a rejected authorization
request renders the error panel` (:243 — this is the `page/error.ftl` loader, row 5 of §1).

### `e2e/xui/xui-device.spec.mjs` — the `main-device` entry (3 tests)

From its header (`:17-61`):

- *"a third entry point exists and is reachable at the URL AM hardcodes into its own HTML
  (design.md D7, task 4.2 — three entry points, not two)"*;
- the `Router` → `SingleRouteRouter` binding, quoted in §5.2;
- templates and locales by path, strings asserted against the deployed `locales/en/device.json`,
  *"so this fails if the bundle stops being copied verbatim, or if the entry point stops selecting
  the `device` namespace and falls back to the console's"*;
- theme resolution via the same `display:none` mechanism, plus logo and footer assertions that
  *"check the resolved theme reached the templates that render from it"*;
- an asymmetry the header flags as easy to "fix" during migration and thereby change behaviour:
  *"main-authorize.js re-requires its templates with `text!${themePath}` after the theme resolves,
  so a theme can override them. main-device.js lists its four templates statically in the top-level
  require array, before the theme is known, so a theme template override does NOT apply to these
  pages today."*

Tests: `the verification form renders for a user who is not logged in` (:143), `an unknown code
renders the error branch of the same template` (:166), `a submitted user code authorizes the device
and renders the done page` (:183) — covering `CodeVerificationForm.ftl` and `CodeThanks.ftl`.

### What these two specs WOULD catch

- **A single-bundle build.** Either entry missing, or emitted at a hashed/`assets/`-prefixed path,
  fails immediately — the page 404s its `data-main` target and renders nothing. This is the direct
  regression test for the §4 naming configuration.
- **`libs/requirejs-2.3.7-min.js` disappearing from the tree** (the §3 4.7 interaction). The `src`
  attribute 404s, no loader, blank page, all 8 tests fail.
- **ESM emitted at those paths** (§2.4). The classic script throws a `SyntaxError`, nothing runs,
  blank page.
- **The §5.2 `Router` shared-chunk collision, in one direction only.** Aliasing `Router` to the
  commons router breaks `ThemeManager.js:168` on both page families → no `structure.css` → `body`
  stays `display:none` → every `toBeVisible()` fails. **These specs catch that.**
- **The wrong i18n namespace, or `locales/` not copied verbatim** — every string is asserted against
  the deployed bundle rather than a literal.
- **The theme not resolving or not reaching the templates** — logo and footer assertions in the
  device spec.

### What these two specs would NOT catch

- **The other direction of the `Router` collision.** Aliasing `Router` to `SingleRouteRouter`
  globally leaves the consent and device pages perfectly green and silently disables the **admin
  theme in the console**. Nothing in these two specs looks at the console; whether
  `xui-theming.spec.mjs` covers `navGroup === "admin"` was **not checked here** — flagged.
- **Payload size and chunk duplication.** Option (a)'s triplication of jQuery/lodash/Handlebars/
  i18next is invisible to both specs; they assert rendering, not bytes. The `PHASE1-TREE.md` digest
  manifest is the instrument for that, not these specs.
- **Whether code-splitting still happens.** The `ui-module-loading` requirement's two scenarios
  ("Initial payload excludes unvisited views", "Navigation fetches the view") are about the console
  and are not exercised by either spec.
- **Cache-busting.** Neither spec asserts anything about `?v=` on these pages — consistent with
  §2.3's finding that these pages have no `urlArgs` at all. `xui-cache-busting.spec.mjs` covers the
  `index.html`/`main` side.
- **The four `.ftl` variants that are not `page/`.** `popup/authorize.ftl` (:64) and
  `touch/authorize.ftl` (:64) load the same entry as `page/authorize.ftl` but are **not driven by
  any test** — the spec reaches the consent screen through the standard `/oauth2/…/authorize`
  endpoint only. Their markup differs (different `#wrapper`/`#content` scaffolding), so a change
  that works in `page/` is not proven for `popup/` or `touch/`. **This is a real coverage gap for
  option (b), which would have to edit all six.**
- **Theme template overrides on the device pages** — the header explicitly records that they do not
  apply today (task 1.10 covers overrides); so a migration that *starts* honouring them there would
  be an undetected behaviour change in the permissive direction.

---

## 7. What this task could NOT determine

1. **Option (c2), AMD-format output, is unverified.** Rollup 4.62.5 and Vite 5.4.21 both permit
   `format: "amd"` with code-splitting (§4.2) — that much is read from the installed bytes. Whether
   Rollup's relative AMD chunk ids resolve under RequireJS 2.3.7's `nameToUrl`, and whether Vite's
   ESM-assuming runtime helpers survive an AMD app build, needs a build to answer. No build was run.
2. **Whether dynamic `import()` from a classic script (option (c1)) is acceptable** given
   `index.html:9-14` still carries IE9 conditional comments. ESM ends IE support regardless, but I
   found no written record of that being conceded.
3. **Whether `xui-theming.spec.mjs` asserts `navGroup === "admin"`**, which is what would close the
   §6 coverage gap on the second direction of the `Router` collision. Not read.
4. **Whether `${baseUrl}` in the six `.ftl` files is ever a *relative* value.** The §2.2 trace holds
   for both absolute and root-relative forms (the basename split runs either way), but a value with
   a `!` in it would take the literal-URL branch. Not exhaustively checked against AM's
   `baseUrl` computation, which lives in `openam-oauth2` Java.
