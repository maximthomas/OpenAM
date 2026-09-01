# Task 7.5 spike — porting the theming specs to a Vite-built, D6-configured XUI

Measured 2026-09-01 against the running `openam-idp` container (`OpenAM-16.2.0-SNAPSHOT`) at
`http://openam.example.org:8080/openam/XUI`. Everything below was run, not reasoned from the
sources; where something was not measured it says so.

**Nothing here has been applied to `xui/xui-theming.spec.mjs`, to `vite.config.js` or to
`src/main/js/config/ThemeConfiguration.js`.** All three are untouched at exit and were verified
byte-for-byte back to their starting sha256s. `xui/NOTES-theming.md` — 1.9/1.10's tracked record of
the AMD/Grunt baseline — and `xui/NOTES-operator-module-d6.md` are untouched too.

**Container state on entry and on exit: the SAME Vite-built `/XUI`, verified byte for byte across
all 900 files.** See §7 — and read §0 first, because the state on entry was not what the brief
expected.

> **Second pass.** An earlier pass of this task left a version of this file on disk. Every
> load-bearing claim in it has been **independently re-measured here** and is confirmed, with three
> corrections noted inline (§2.3 byte delta, §2.4 scope, §8 item 3). This file supersedes it.

---

## 0. THE BRIEF'S PREMISE WAS ALREADY FALSE, AND THAT IS THE FIRST THING TO KNOW

The brief said the deployed `/XUI` "is still the pre-migration GRUNT tree from the war" and is
"irreplaceable if you destroy it". It is neither, and it was not before this task touched anything.
Checked before any mutation:

| checked before any mutation | value |
|---|---|
| top-level entries under `/XUI` | **15** — `assets/`, `css/`, `favicon.ico`, `images/`, `index.html`, `libs/`, `locales/`, `main-authorize.js`, `main-device.js`, `main.js`, `oauthReturn.html`, `partials/`, `templates/`, `themes/`, `timezones.json` |
| `XUI/config/` | **absent** |
| `XUI/assets/` | **present** |
| `XUI/index.html` sha256 | `88ecf91a82eb0f7fe1e74766435c89c87179147bef5d7683aedba799aa394726` — the Vite `index.html`, **not** the `961345a9…` Grunt one that `NOTES-operator-module-d6.md` §9.2 recorded |
| files / tar entries | 900 / 983 |

The tree on arrival was a Vite build one build older than `target/compiled`: `index.html`,
`main-authorize.js` and `main-device.js` matched the local build exactly, `main.js` did not
(`b76d41fd…` deployed vs `ae92b7c2…` local). §2.4 explains why that is expected and not evidence of
a config drift.

**Consequences.**

- **No Grunt tree was destroyed by this task and none was available to destroy.** An earlier
  session's `xui-deploy.sh` had already replaced it.
- **The snapshot-before-deploy discipline was followed regardless** — `docker exec … tar czf -`,
  3.5 MB, 983 entries, sha256 `0084da4074acb33da05c0b5696d23605050bb51165e3931c83b6a2917669ba8f`.
  §7 records the restore against it, verified file-by-file rather than by spot check.
- **`openam.war` (294 MB) is still in the container**, so `unzip -o openam.war 'XUI/*'` recovers the
  Grunt tree if a phase-1 comparison run is ever wanted. 6.6 §9.1's "tar the live tree out first" is
  still the right habit, but it is no longer the only line of defence.

---

## 1. PART A — INTERCEPTION IS DEAD. A REQUEST STILL EXISTS, AND THAT IS WORSE.

### 1.1 The measurement the brief asked for first

One anonymous `XUI/?realm=/#login/` load against the deployed Vite tree, every request recorded
(52 requests total):

```
THEMECFG_REQUESTS_COUNT = 1
THEMECFG_REQUESTS  = [{"method":"HEAD","url":".../XUI/config/ThemeConfiguration.js?v=16.2.0-SNAPSHOT"}]
THEMECFG_RESPONSES = [{"status":404, "url":".../XUI/config/ThemeConfiguration.js?v=16.2.0-SNAPSHOT"}]
THEMECFG_REQUESTFAILED = [{"err":"net::ERR_ABORTED"}]
```

**So the naive answer is "yes, one request still exists" — and it is a trap.** The request:

- is a **`HEAD`**, not a `GET`;
- returns **404** (Chromium additionally reports `net::ERR_ABORTED`);
- is issued by **`src/main/js/warnRetiredConfig.js`** (task 7.4), whose whole job is to detect a
  *stale* `config/ThemeConfiguration.js` left in a tree upgraded in place and `console.warn` about
  it. `warnRetiredConfig.js:64` is
  `const RETIRED = ["config/AppConfiguration.js", "config/ThemeConfiguration.js"]`, and it never
  reads a response body — `fetch(toUrl(name), { method: "HEAD", cache: "no-store" })`;
- has **nothing to do with theme resolution**. `ThemeManager.js:19` is
  `import ThemeConfiguration from "config/ThemeConfiguration"` — a static ESM import, bundled at
  build time. `fr-dark-theme` occurs in **exactly one** of the 296 emitted chunks,
  `assets/warnRetiredConfig-BkM1oWMH.js` (337 kB; the chunk is merely *named* for another module in
  it).

On a clean tree the file 404s, so `warnRetiredConfig` stays silent — measured, zero retired-config
console messages.

### 1.2 Proved by fulfilling it, not by reading the source

`context.route("**/config/ThemeConfiguration.js*", route => route.fulfill({ status: 200, body }))`
where `body` maps the **root** realm to `fr-dark-theme` — if anything consumed it the root login
page would go dark:

| | measured |
|---|---|
| route hits | **1**, method **`HEAD`** |
| stylesheets | `css/bootstrap-3.3.5-custom.css`, `css/structure.css`, `css/theme.css` — **the default theme** |
| `img.main-logo` | `images/login-logo.png`, alt `OpenAM` — **the default theme** |
| theme changed | **false** |
| side effect | a `console.warn`: *"[XUI] config/ThemeConfiguration.js is still present in the deployed /XUI tree, but it is no longer read…"* |
| `pageerror` | 0 |

**Interception is dead, and it is now actively harmful.** The only thing `route.fulfill` achieves is
to convince `warnRetiredConfig` that the operator has a stale config file — because the fulfilled
`HEAD` answers 200 where the real tree answers 404. `xui/xui-retired-config.spec.mjs:253` is a
tracked test named *"a clean tree produces no warning at all"*; any theming fixture that keeps the
interception route is a cross-spec hazard the moment the two share a context.

`NOTES-theming.md`'s *"Preferred alternative: don't edit the deployed file at all"* and `tasks.md`
10.1's citation of it (`NOTES-theming.md:37 already names the fix`) are both **superseded**. Delete
the recommendation rather than weaken it.

### 1.3 There is no replacement URL to intercept

There is no chunk carrying only the theme configuration.
`assets/warnRetiredConfig-BkM1oWMH.js` is 337 702 bytes and holds jQuery, i18next, `URIUtils`, the
theme config and more. Intercepting it means serving a hand-written 337 kB bundle chunk whose name
is a content hash that moves between builds (§2.4). Not a mechanism.

---

## 2. PART A — HOW A MAPPING GETS INJECTED. RECOMMENDATION: (b), WITH A JSON-STRING DEFINE FLAG.

### 2.1 The three options, re-costed for theming

| | cost here | verdict |
|---|---|---|
| **(a) spec drives a source edit and a build** | 6.6's objection is unchanged and *stronger*: `src/main/js/config/ThemeConfiguration.js` is tracked product source, a killed worker leaves it dirty, and `OpenAM/e2e` would gain an `npm` toolchain dependency it does not otherwise have. Measured build 12.0–14.2 s wall, redeploy ~1 s. | **rejected** |
| **(b) build is an asserted PRECONDITION, a `define` flag is the mechanism** | one env var; nothing tracked is mutated per run; teardown shrinks to "delete the realms". Precondition is cheap and exact — §2.5. | **RECOMMENDED** |
| **(c) spec deploys a pre-built fixture tree** | 900 files / ~10 MB, goes stale, and now *also* swaps the whole `/XUI` out from under `xui-retired-config.spec.mjs` and every other spec sharing the instance. | fallback only |

### 2.2 What the flag substitutes — and why it is ONE flag, not two

The spec needs **two different things** from the built configuration, and a single JSON blob is the
only shape that supplies both:

1. a **mapping** realm → theme, for the two selection tests. `fr-dark-theme` is already registered,
   so a mapping alone suffices there;
2. a **theme declaring a non-empty `path`**, for the two override tests. No shipped theme has one
   (§4.1), so this half has to *register* a theme, which a mappings-only flag cannot do.

Measured working end to end (§3, §4.1):

```js
// vite.config.js, beside targetVersion / loginHelperClass
const themeConfigOverride = process.env.THEME_CONFIG_OVERRIDE || "";

// vite.config.js, in define, beside __LOGIN_HELPER_CLASS__
__THEME_CONFIG_OVERRIDE__: JSON.stringify(themeConfigOverride)
```

```js
// src/main/js/config/ThemeConfiguration.js
/* global __THEME_CONFIG_OVERRIDE__ */

function applyOverride (base, override) {
    return {
        themes: Object.assign({}, base.themes, override.themes),
        mappings: (override.mappings || []).concat(base.mappings)
    };
}

const configuration = { /* ...the shipped object, verbatim and untouched... */ };

export default __THEME_CONFIG_OVERRIDE__
    ? applyOverride(configuration, JSON.parse(__THEME_CONFIG_OVERRIDE__))
    : configuration;
```

**The `define` value must be a primitive STRING. That is load-bearing** — see §2.3. The fallback to
`""` lives in `vite.config.js`, not in the substituted expression, exactly as `LOGIN_HELPER_CLASS`
does, so what lands in the chunk is always a quoted literal and never the token `undefined`.

`npx eslint src/main/js/config/ThemeConfiguration.js` is clean on the patched file. (`npx eslint
vite.config.js` reports `Parsing error: Unexpected token import` — **pre-existing**, reproduced on
the untouched backup at the same construct.)

Set by whoever builds the tree, e.g.:

```
THEME_CONFIG_OVERRIDE='{"themes":{"e2e-theme-path":{"path":"themes/dark/"}},
  "mappings":[{"theme":"fr-dark-theme","realms":["/e2e-d6-dark"]},
              {"theme":"e2e-theme-path","realms":["/e2e-d6-path"]},
              {"theme":"default","realms":["/e2e-d6-default"]}]}'
```

`.concat(base.mappings)` puts the override's entries **first**, which is what first-match-wins
requires and what `withMappings` in the current spec already does.

### 2.3 The chunk-hash proof, run as the brief asked — and it does NOT come out clean

| build | theme chunk | size |
|---|---|---|
| control, no flag in the source at all (two independent clean builds) | `warnRetiredConfig-BkM1oWMH.js` | 337 702 B |
| flag present, `THEME_CONFIG_OVERRIDE` **unset** | `warnRetiredConfig-DslHoCQ8.js` | 337 708 B (**+6**) |
| flag present, set to the JSON above | `warnRetiredConfig-DAVCqLqh.js` | — |

**The unset build is NOT hash-identical.** But the difference is one alias binding and nothing else.
Extracting the theme-configuration region from both chunks and comparing them character for
character (region length 856 in both):

```
control :  const Fn=oi(Uc),hn={themes:{…},mappings:[]},Uh=Object.freeze(…)
flagged :  const Fn=oi(Uc),Fc={themes:{…},mappings:[]},hn=Fc,Fh=Object.freeze(…)
                            ^^                         ^^^^^
```

- the emitted **configuration object is byte-identical**, key for key, string for string;
- `applyOverride` is **absent** from the whole chunk — `grep applyOverride` → no match;
- `JSON.parse` of the override is **absent** — esbuild constant-folds the ternary on the `""`
  literal and tree-shakes both;
- the entire residue is that the source now has two bindings (`configuration` and the default
  export) where it had one. **+6 bytes.**

**Why an object-valued `define` can never pass this test.** esbuild only inlines *primitive* define
values; an object or array value is hoisted into a shared `var` so every reference gets one
identity, which changes the emitted chunk even when the flag is unset. That is precisely why
`__LOGIN_HELPER_CLASS__` (a string) passed 6.6's identical-hash test and why a
`__THEME_MAPPINGS__: JSON.stringify([])` shape cannot.

**Recommendation: accept the hash change and state the proof differently.** The honest claim the
implementing task should make is *"with the flag unset the emitted configuration object is byte
identical to the pre-flag build, `applyOverride` and `JSON.parse` are tree-shaken out entirely, and
the chunk grows by 6 bytes of aliasing"* — not 6.6's "identical hash". Do not contort the source to
recover the last 6 bytes; §2.4 makes exact hash equality an unattainable target anyway.

*(Correction to the first pass of this file, which recorded 12 bytes. Re-measured: 6.)*

### 2.4 CHUNK HASHES ARE NOT REPRODUCIBLE ON THIS TREE — 6.6's proof method no longer holds

Two builds from **byte-identical source**, same command
(`TARGET_VERSION=16.2.0-SNAPSHOT npx vite build`), same machine, `git status` clean over
`openam-ui/openam-ui-ria/` in between, `build.emptyOutDir` true so nothing is stale:

| | |
|---|---|
| chunk **names** under `assets/` that changed | **197 of 296** |
| emitted `.js` files whose **content sha256** appears in both builds | **139 of 337** — so **198 differ in bytes, not merely in name** |
| `main.js` (unhashed entry) sha256 | `ae92b7c2…` → `3364dd2a…` |
| the theme-config chunk | `warnRetiredConfig-BkM1oWMH.js` in **both** — one of the stable ones, which is what makes §2.3 meaningful |

*(Correction to the first pass, which measured chunk-name churn only. The churn is real content
churn: minified identifier assignment shifts between runs, so the comparison must be done on the
extracted configuration region, as §2.3 does, and not on chunk sizes or hashes.)*

**Any future task that tries to prove something "by chunk hash, not by grep" must first establish
that its chunk is one of the stable ones.** This also disposes of an open question the first pass
left: the deployed `main.js` differing from `target/compiled`'s (§0) needs no "different
`vite.config.js` revision" explanation — two clean builds of the *same* source differ in `main.js`.

Root cause not determined; two attempts, then stopped per the brief. This bears on **design.md D23 /
the open question on build reproducibility** and is bigger than this task.

### 2.5 How the precondition is asserted, and how the realm half composes

**This is the difference from 6.6 the brief asked about: a mapping needs a realm to exist, and a
build flag cannot create one.** The two halves compose cleanly, in this order and no other:

1. **Build half — static, and a precondition.** The flag names realms by **fixed, lowercase
   literal**. It is baked at build time and the spec never changes it.
2. **Realm half — dynamic, and the spec's own fixture.** The spec creates exactly those realms with
   `createRealm` and deletes them with `removeRealm`, as it does today.

**Fixed realm names, not `uniqueRealmName()`, and that is a deliberate loss.** Uniqueness existed to
stop a stale mapping in an *editable deployed file* matching a later run's realm. Under D6 the
mapping lives in the bundle, the spec never writes it, and there is nothing to go stale — so the
guard protects against nothing while costing the ability to name the realm at build time. Residual
risk: two concurrent runs against one instance colliding on a realm name, which is already true of
the suite generally.

**The precondition probe, and its ordering trap.** Create the realms **first**, then open
`XUI/?realm=/<dark-realm>#login/` in a fresh context and read the stylesheet list. If the tree was
not built with the flag, every realm resolves to `default` and the list is the default three. Fail
loudly with a remediation naming the flag and the redeploy — never `test.skip()`; 6.6 §10 item 1's
decision applies unchanged and for the same reason. **The realms must exist before the probe can
tell "not built with the flag" from "realm does not exist"**, because an unknown realm also renders
the default theme. That ordering is the mirror image of 6.6 §3's, where the module had to be *absent*
first.

Remediation, two steps:

```
1. cd openam-ui/openam-ui-ria && THEME_CONFIG_OVERRIDE='…' npm run build:production
2. e2e/local/xui-deploy.sh openam-ui/openam-ui-ria/target/compiled
```

**A rule inherited from 6.6 §3.3 that bites harder here.** `xui-deploy.sh` `rm -rf`s `$XUI_PATH`
before copying. Measured in passing during this spike: a file placed at
`themes/dark/templates/common/FooterTemplate.html` before a redeploy was **gone afterwards**. So the
override tests must place their theme assets on **every** run and never assume a previous run left
them.

---

## 3. PART A — THE END-TO-END PROOF

Built with the flag set to §2.2's value, deployed with `xui-deploy.sh`, three realms created over
REST, each opened in its own fresh `browser.newContext()`. **Nothing was intercepted**; the deployed
configuration is the one the build emitted.

| realm | stylesheets (normalised) | favicon | `img.main-logo` | alt | requests under `/XUI/themes/` |
|---|---|---|---|---|---|
| `/e2e-d6-default` | `css/bootstrap-3.3.5-custom.css`, `css/structure.css`, `css/theme.css` | `favicon.ico` | `images/login-logo.png` | OpenAM | **0** |
| `/e2e-d6-dark` | `themes/dark/css/bootstrap.min.css`, `css/structure.css`, `themes/dark/css/theme-dark.css` | `favicon.ico` (inherited) | `themes/dark/images/login-logo-white.png` | **ForgeRock** | **3, all 200** |
| `/e2e-d6-path` | the default three (inherited) | **`themes/dark/favicon.ico`** | `images/login-logo.png` | OpenAM | **27 — 25 × 404 + 2 × 200** |

`pageerror` was **0** on every one; `#idToken1` visible on every one; `#footer`'s mailto anchor
present on every one that had no override. Three things this settles:

- **Per-realm theme selection survives D6 intact**, driven entirely from the built configuration.
  Every assertion the two selection tests make today is reproduced here, including the
  favicon-inheritance discriminator at `xui-theming.spec.mjs:618` (`fr-dark-theme` declares no
  `icon`, so `extendTheme` gives it the default's).
- **`themes/` survives as unbundled static assets that a config URL still points at** (D3) — the
  three `themes/dark/…` fetches on the dark realm are real 200s off disk.
- **The theme-path 404 fallback is unchanged from the Grunt baseline.** `NOTES-theming.md` measured
  27 misses (19 partials + 8 templates); this measured 27 requests under `themes/` with two of them
  satisfied by the placed overrides. Still swallowed, still zero `pageerror`. **Record it as a cost,
  never assert it** — that guidance is unchanged.

---

## 4. PART B — THE FOUR ASSET KINDS. ALL FOUR EDITABLE IN PLACE, NO REBUILD.

`themes/`, `templates/`, `partials/`, `css/` and `images/` all ship as **individually addressable
static files** in the Vite tree. `target/compiled` has no `config/`, but it has all five, and every
one is fetched at runtime with a plain `?v=16.2.0-SNAPSHOT` — **none is content-hashed**.

Each was edited **alone** in the deployed `/XUI` via `docker exec`, proved in a fresh browser
context, and restored with a sha256 check before the next was touched. A control run on the
untouched tree came first.

| kind | file edited | edit | assertion that showed it took effect | restored |
|---|---|---|---|---|
| **stylesheet** | `css/theme.css` | appended `#footer{background-color:rgb(1,2,3) !important}` | `getComputedStyle(#footer).backgroundColor` went `rgba(0, 0, 0, 0.04)` → **`rgb(1, 2, 3)`** | sha `1334138791ab…` ✓ |
| **image** | `images/login-logo.png` | replaced with a 1×1 PNG | `img.main-logo` `naturalWidth`×`naturalHeight` went `225×57` → **`1×1`**, same URL | sha `675034b008cf…` ✓ |
| **template** | `templates/common/FooterTemplate.html` | replaced with a marker div | `#e2e-tpl-marker` = **`E2E-TEMPLATE-EDIT-OK`** *and* the shipped `#footer a[href^="mailto:"]` count **0** — replaced, not merged | sha `76f394770a38…` ✓ |
| **partial** | `partials/login/_Default.html` | prepended a marker span, form markup left intact | `#e2e-partial-marker` = **`E2E-PARTIAL-EDIT-OK`** *and* `#idToken1` still visible | sha `69bbd10c7535…` ✓ |

`pageerror` 0 throughout. All four are `-rw-r--r-- openam root` in the deployed tree and
`docker exec -i … 'cat > <path>'` truncates in place, so owner and mode survive the edit.

**The empty theme path does make it simpler than expected — but only for these four.** With
`default.path === ""` the theme-prefixed URL *is* the unprefixed URL, so none of the four needed a
theme, a realm, a mapping or a build: they are ordinary static files and the proof is an ordinary
file edit against the root realm. That is the whole of `ui-customization`'s *"Stylesheet edited in a
deployed instance"* scenario, and by extension the plain reading of *"Theme assets remain editable
in a deployed instance"*.

**It does NOT cover the theme-path scenario, and those are two different requirements.** §4.1.

### 4.1 THEME PATH REGISTERED AT BUILD TIME: **YES, REQUIRED**

With the **shipped** configuration deployed (no flag), a file was placed at
`themes/dark/templates/common/FooterTemplate.html` and confirmed served — `curl` 200, 541 ms after
the write. Then a fresh context loaded `XUI/?realm=/#login/`:

```
TPL_MARKER = null
FOOTER_MAILTO_COUNT = 1          (the shipped template rendered)
THEME_REQ_COUNT = 0              (requests under /XUI/themes/)
```

**Zero requests.** `default` sets `path: ""` and `fr-dark-theme` declares no `path`, so `extendTheme`
gives it `""` too; `UIUtils.compileTemplate` / `preloadPartial` take the `else` branch and never
construct a themed URL at all. The file is on disk, served, and unreachable.

With a theme carrying `path: "themes/dark/"` **registered in the built configuration** (§3), the same
placements worked immediately and with **no rebuild** — both files were written into the already
deployed tree after the deploy:

| placed in the deployed tree | observed on `/e2e-d6-path` | control on `/e2e-d6-dark` (path `""`) |
|---|---|---|
| `themes/dark/templates/common/FooterTemplate.html` | `#e2e-tpl-marker` = **`THEMED-TEMPLATE-OK`**, shipped mailto anchor count **0** | marker `null`, mailto count 1 |
| `themes/dark/partials/login/_Default.html` | `#e2e-partial-marker` = **`THEMED-PARTIAL-OK`**, `#idToken1` still visible | marker `null` |

`pageerror` 0 in both. Neither directory (`themes/dark/templates/`, `themes/dark/partials/`) exists
out of the box; both were created by the probe and both were removed.

So `ui-customization`'s *"Template override added to a deployed instance"* — *"under the asset path
of a theme already registered in the built configuration"* — **needs the build flag of §2.2**. It is
the one scenario in that requirement a plain file edit cannot reach, and it is why the flag must
carry a `themes` half and not only `mappings`.

**The theme-path convention itself was NOT changed.** design.md's Open Questions defers it and D3
preserves current behaviour verbatim. It did get in the way once, and this is the record the brief
asked for: because no shipped theme declares a non-empty `path`, "an operator adds an asset to an
already-registered theme" is not testable at all without *first* registering a theme — which under
D6 means a build. A convention where the shipped dark theme declared `path: "themes/dark/"` would
have made §4.1 an ordinary file edit like the other four. Worked around with the flag; not
re-litigated.

### 4.2 The three defeaters — CONFIRMED, all unchanged against a Vite tree

Not assumed. Each re-measured on the deployed Vite tree.

| defeater | `NOTES-theming.md` (Grunt) | measured here (Vite) |
|---|---|---|
| **Tomcat `WebResourceRoot` staleness** | ~5 s (stale at 4.4 s, fresh at 5.4 s) | **unchanged.** With the old bytes primed into the cache by a `GET` immediately before the write: `css/theme.css` fresh at **4 894 ms**, `templates/common/FooterTemplate.html` at **4 925 ms**. Where the path was *not* primed the new bytes appeared in **541–706 ms** — a file at a URL nobody has asked for resolves at once, which is why the current spec's "poll for absent first" step then costs a full TTL. **Poll for the served bytes; never sleep.** |
| **browser cache** (`Cache-Control: public, max-age=2592000`) | a fresh `newContext()` is required; `page.reload()` is not | **confirmed, both halves, and the header is on everything.** Verified present on `templates/`, `css/`, `images/`, `partials/` **and** `themes/`. After restoring the template on disk and polling until the server served the restored bytes, `page.reload()` in the same context **still rendered the stale marker**; a fresh `browser.newContext()` saw the restored footer. |
| **fixed `?v=` within a build** | RequireJS `urlArgs`, one value per build | **confirmed.** Across 33 runtime fetches of `templates/`, `partials/`, `css/`, `images/`, `themes/` and `locales/` on one login load, the set of distinct query strings is exactly `["?v=16.2.0-SNAPSHOT"]`. The source moved — it is now `main.js`'s `LoaderRuntime` `urlArgs` fed by `__TARGET_VERSION__` rather than RequireJS — but the consequence is identical: **there is no URL cache-bust available to a spec.** |

---

## 5. PART C — THE FIVE TESTS IN `xui-theming.spec.mjs`

**0 survive unchanged, 4 need rewriting, 1 must be DELETED.**

Measured, whole file, against the deployed Vite tree:

```
$ npx playwright test xui/xui-theming.spec.mjs
  4 failed
  1 passed (13.3s)                                                              exit 1
```

All four failures are the same fixture error, before any test body runs:

```
Error: Command failed: docker exec openam-idp cat /usr/local/tomcat/webapps/openam/XUI/config/ThemeConfiguration.js
cat: …/XUI/config/ThemeConfiguration.js: No such file or directory
```

Both fixtures are dead in exactly the way 6.6 §7.3 recorded. `readDeployedConfig()` reads
`${XUI_ROOT}/config/ThemeConfiguration.js`, which does not exist, so `parseThemeConfig`,
`withMappings`, `withThemes`, `waitForServedConfig`, `deployedConfigSha256`,
`writeDeployedConfig` and the pristine-sha teardown all go with it. What survives from the fixture
machinery is what survived in 6.6: `placeDeployedFile`, `removeDeployedFile` with its
`OVERRIDE_DIRS`, `deployedPathExists`, `waitForServed` — used now against the *theme-path* override
files, unchanged. (Note `readDeployedConfig` throws before `createRealm`, so the failed run leaks no
realms; verified, realm list was `["/"]` afterwards.)

| # | line | test | verdict |
|---|---|---|---|
| 1 | 558 | each realm gets the stylesheets of the theme it is mapped to | **rewrite** — fixture only. Every assertion reproduced verbatim in §3, including the whole-list comparison. |
| 2 | 584 | each realm gets the login logo of the theme it is mapped to | **rewrite** — fixture only. Reproduced in §3, including the favicon-inheritance discriminator. |
| 3 | 626 | **the theme configuration is fetched as its own module, at a stable URL** | **DELETE** — §5.1. |
| 4 | 736 | a template the theme supplies replaces the default one | **rewrite** — fixture needs §2.2's flag to register a non-empty `path`; the file placement and both assertions survive (§4.1). |
| 5 | 754 | a template the theme does not supply still renders from the default path | **rewrite** — same. All five assertions survive: `expectThemePathApplied` (favicon `themes/dark/favicon.ico`), the mailto text, `#e2e-template-override` absent, `#idToken1` visible, `pageerror` empty. |

### 5.1 Why test 3 must be deleted, and why it is worse than 6.6's case

The spec header says this test *"is the one that is **supposed** to fail"* when config becomes
bundled, so the intended break "has a name of its own", and that every other test then "fails merely
as a consequence".

**It does not fail. It passes, and the other four fail on their own.** Run in isolation against the
deployed Vite tree, unmodified:

```
$ npx playwright test xui/xui-theming.spec.mjs -g "fetched as its own module"
  ✓  xui/xui-theming.spec.mjs:626:5 › … at a stable URL (2.6s)
  1 passed                                                                      exit 0
```

Because `warnRetiredConfig` issues exactly one request for that pathname (§1.1), `fetched` has
length 1 and `new URL(fetched[0]).pathname` matches `THEME_CONFIG_URL`'s. Both assertions are
satisfied — **by a 404 deprecation `HEAD` probe, on a tree where the capability the test names has
been deleted.** The test checks neither method nor status, and could not usefully be made to: a
`GET`-and-200 form would fail, but it would be asserting the *absence* of a deprecation probe, which
is `xui-retired-config.spec.mjs`'s job and not this file's.

6.6 §7.2's precedent (delete `delegatesTo`, do not adapt it) applies, and applies **harder**. There
the assertion failed honestly because the property was gone. Here the assertion goes green while
asserting the opposite of the truth — the worst possible state for a migration guard: it reports the
D6 break as a clean pass, and 1.9's baseline looks preserved when it has been removed. Weakening is
not available either; there is no weaker form of "fetched as its own module" that a bundled
configuration satisfies.

**Delete the test, and delete `THEME_CONFIG_PATH`, `THEME_CONFIG_URL`, `readDeployedConfig`,
`writeDeployedConfig`, `deployedConfigSha256`, `parseThemeConfig`, `withMappings`, `withThemes` and
`waitForServedConfig` with it.** What replaces it is already tracked and already passing:
`xui/xui-retired-config.spec.mjs` asserts the *inverse* contract — that a
`config/ThemeConfiguration.js` present in a deployed tree produces a warning and is not read, and
that a clean tree produces no warning at all (`:253`). That is the D6-side statement of the same
fact, owned by task 7.4. Nothing is lost by deletion.

### 5.2 Three rewrites the header itself needs

- The *"This spec asserts post-deploy config editing, which D6 removes"* block predicts that test 3
  fails and the other four "fail merely as a consequence". **Exactly inverted** — rewrite it.
- The *"Deployed AM only, and why the file really goes on disk"* block, and the
  *"Fixtures the spec needs"* reasoning above it, both recommend
  `context.route("**/config/ThemeConfiguration.js*", …fulfill…)` as the fallback for the day the
  migration stops serving templates over the network. The migration did **not** stop serving
  templates over the network (§4), and the config interception the block leans on is dead and now
  noisy (§1.2). Both mentions should go.
- The `TEMPLATE_THEME` / `TEMPLATE_THEME_PATH` comment ("A theme with a non-empty `path` has to be
  authored, and one key is all it takes") is still correct, but "authored" now means "registered at
  build time through the flag", not "inserted into the deployed file". Say so, and cross-reference
  the precondition.

---

## 6. D22 / TASK 5.5's ORPHANED GAP — FLAGGED, NOT DECIDED

5.5 handed over: the theme-path 404 fallback is unverified for all eleven former `text!` templates,
and no spec covers the four authorize or five device templates under a theme at all, because
`xui-authorize.spec.mjs` uses a fixed `AUTHORIZE_URL` and neither secondary spec parameterises the
realm.

**Two facts found here that change the shape of that gap, in opposite directions.** Both read out of
the current source, not inferred:

1. **`NOTES-theming.md`'s "Trap: `main-authorize.js` uses `theme.path` with **no** fallback" is
   obsolete — the migration fixed it.** `src/main/js/main-authorize.js:43-49` records that the
   hand-rolled `text!${themePath}${templatePath}` prefixing was replaced by
   `UIUtils.compileTemplate(templatePath, null)` (`:160`), which does theme-path-first **with** the
   404 fallback the hand-rolled version never had. A themed-`path` fixture no longer breaks the
   consent page. That trap paragraph in `NOTES-theming.md` should be marked superseded by whoever
   next edits that file.
2. **`main-device.js` gained a theme path it never had.** `src/main/js/main-device.js:34-42`: the
   five templates at `:111-115` were static `text!` ids with **no** theme prefixing at the base SHA;
   `compileTemplate` now prefixes `theme.path` for all five, so they become theme-overridable for
   the first time. Recorded there as an accepted D22 behaviour change.

**My read: it does not belong in this task, and it belongs to whoever owns D22, soon.** One clause —
7.5 is scoped to the theming spec's own five tests and the four asset kinds, and closing this would
mean parameterising two other spec files by realm; but item 2 is a *widening* of the D3 surface that
no spec covers, already shipped, and cheap to test now and expensive to discover later. Note the
§2.2 flag makes the fixture available for free: any realm can be mapped to a `path`-bearing theme at
build time, and `main-authorize` / `main-device` read the same resolved theme. Flagged, not decided.

---

## 7. RESTORE — WHAT THE CONTAINER AND THE WORKSPACE ARE NOW

### 7.1 `/XUI`

Snapshot taken **before any mutation**: `docker exec … tar czf -`, 3.5 MB, 983 entries, sha256
`0084da4074acb33da05c0b5696d23605050bb51165e3931c83b6a2917669ba8f`. Restored with `rm -rf` +
`tar xzf -` as `-u 0`. `local/openam-reset.sh` was not needed and was not run.

- **All 900 files byte-identical to the snapshot** — `sha256sum` over the whole tree on both sides,
  sorted and `diff`ed: **FULL TREE IDENTICAL**. Not a spot check.
- 15 top-level entries, 983 total entries; `/XUI` is `drwxr-x--- openam root`, `index.html` is
  `-rw-r----- openam root`.
- `themes/dark/` back to `config.json`, `css`, `images`. No `templates/` or `partials/` under it.
- `find /XUI \( -name '*e2e*' -o -name '*E2E*' \)` → **0**.
- **Probe realms deleted**: `/json/global-config/realms?_queryFilter=true` returns exactly `["/"]`.
  All three of `/e2e-d6-default`, `/e2e-d6-dark`, `/e2e-d6-path` are gone.
- **The instance works**: `npx playwright test xui/xui-login.spec.mjs` → **4 passed (11.7 s)**,
  exit 0.
- `openam-idp` and `opendj-idp` both Up and healthy; no container was rebuilt, restarted or reset.

The tree that is there is the **Vite tree that was there on arrival** (§0), not a Grunt tree. If a
Grunt baseline is ever wanted, take it out of `/usr/local/tomcat/webapps/openam.war`, still in the
container.

### 7.2 Workspace

- `vite.config.js` and `src/main/js/config/ThemeConfiguration.js` **restored byte-for-byte** from
  copies taken before the first edit — sha256 `1756bf5242ed7ad3…` and `5964787cc4e8e134…`, both
  re-verified. The flag of §2.2 is **recommended, not applied**.
- `target/compiled` holds a clean default build (900 files, theme chunk
  `warnRetiredConfig-BkM1oWMH.js`, **0** files mentioning `THEME_CONFIG_OVERRIDE`, `applyOverride`
  or any `e2e-d6-` realm). It cannot be restored byte-for-byte — §2.4 — and is a build artefact, so
  it was rebuilt clean instead.
- `git status` in `OpenAM/` is back to exactly the two modified tracked files it started with —
  `openam-server-only/src/main/webapp/WEB-INF/web.xml` and
  `openam-ui/openam-ui-js-sdk/package-lock.json`, **neither of them this task's** — plus this
  untracked file.
- All throwaway scripts deleted.
- `xui/xui-theming.spec.mjs`, `xui/NOTES-theming.md`, `xui/NOTES-operator-module-d6.md`,
  `xui/BASELINE.md`, `xui/PHASE1-BASELINE.md` and `openam-ui-ria/PHASE1-TREE.md` were **not** edited.

---

## 8. NOT DETERMINED

1. **Why 197 of 296 chunk names and 198 of 337 emitted `.js` files change between builds from
   identical source** (§2.4). Two builds measured here, matching an earlier four-build sample; root
   cause not found, two attempts then stopped. It invalidates "prove it by chunk hash" as a general
   method on this tree and is D23's problem, not 7.5's.
2. **Whether the 6-byte alias residue in §2.3 can be eliminated.** Not pursued past the DCE variant,
   because §2.4 makes exact hash equality unattainable anyway.
3. **Nothing was measured about post-login theming under D6** — the profile page and the admin
   console. The current spec is pre-login only and deliberately so; that reasoning is unaffected by
   anything here, but it was not re-checked either.
4. **The `authenticationChains` half of a mapping** was not exercised under D6. `NOTES-theming.md`
   measured its traps against the Grunt tree and the current spec deliberately omits it; nothing
   here changes that, and nothing here confirms it.
