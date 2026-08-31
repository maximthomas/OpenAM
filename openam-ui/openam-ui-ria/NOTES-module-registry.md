# NOTES-module-registry.md — the runtime module registry for the Vite build (task 6.1 / D1)

Survey run 2026-08-30 against the tree as it stands after task 5.4. Everything below the word
MEASURED was produced by a throwaway spike through the real `vite.config.js` and then deleted.
Nothing in `src/main/js` and nothing in `vite.config.js` was modified by this survey.

---

## 0. INDEX

| § | subject | read this if you want |
|---|---|---|
| 1 | Fail-fast checks and the "before" numbers | the baseline the apply run is measured against |
| 2 | How Vite 5.4.21 actually resolves `import.meta.glob` | why node_modules is *not* always ignored |
| 3 | MEASURED: which pattern forms enumerate which tree | **the runnable patterns, with counts** |
| 4 | MEASURED: key shape and the key -> id normalisation | the exact string surgery |
| 5 | Where the glob file has to live | the answer is "anywhere, if you use §3's patterns" |
| 6 | Lazy vs `{ eager: true }` | it changes payload, not resolution |
| 7 | The identifier corpus (122 ids, full table) | **what the registry must answer for** |
| 8 | The 9 ids no glob produces | the explicit map entries |
| 9 | The seven logical names: drift, instance identity, unbound-name reporting | the two questions asked |
| 10 | Shape constraints (lazy, thunk-vs-static, the two secondary entries) | the decisions the apply run cannot derive |
| 11 | What the registry itself costs | entry-chunk bytes, measured three ways |
| 12 | Hand-offs and traps for the apply run | **read this before writing the registry** |
| 13 | Not determined | open items |
| 14 | **fallback** — resolving an identifier the build never saw (task 6.3) | **the derived url, the module format, and what a miss does** |

---

## 1. FAIL-FAST CHECKS AND THE "BEFORE" NUMBERS

All four passed before anything was touched.

| check | result |
|---|---|
| `require.resolve("vite")` | `/…/openam-ui-ria/node_modules/vite/index.cjs` — inside this project, not one directory up |
| vite version | **5.4.21** — the 5.4.x the build declares, so `import.meta.glob` behaves as §2 describes |
| `node_modules/@openidentityplatform/ui-commons/esm` | exists (66 `.js`/`.jsx`) |
| `node_modules/@openidentityplatform/ui-user/esm` | exists (14 `.js`/`.jsx`) |
| `npm run build:production` | **exit 0**, `✓ 563 modules transformed`, `✓ built in 8.35s` |

**BEFORE (pre-registry baseline):**

- `target/compiled/main.js` = **183842 bytes** (183.84 kB; gzip 56.27 kB)
- `target/compiled/assets/` = **10 files** (5 chunks + 5 `.map`): `main.js` is at the tree root, plus
  `Promise`, `main-device`, `main-authorize`, `ReactAdapterView`, `i18nManager`.

Two pre-existing deferral notices fire in that build and are relevant to 6.1 — see §12.1.

---

## 2. HOW VITE 5.4.21 ACTUALLY RESOLVES `import.meta.glob`

Read out of the installed engine, `node_modules/vite/dist/node/chunks/dep-BK3b2jBa.js`, then
confirmed by measurement in §3. Three functions decide everything.

**2.1 `toAbsoluteGlob` (`:39038`)** — how a pattern becomes an absolute glob:

```js
if (glob[0] === "/")          return pre + posix.join(root, glob.slice(1));   // root-absolute
if (glob.startsWith("./"))    return pre + posix.join(dir, glob.slice(2));    // importer-relative
if (glob.startsWith("../"))   return pre + posix.join(dir, glob);             // importer-relative
if (glob.startsWith("**"))    return pre + glob;
const resolved = normalizePath(await resolveId(glob, importer, …) || glob);   // <-- ALIAS PATH
if (isAbsolute(resolved))     return pre + globSafeResolvedPath(resolved, glob);
throw new Error(`Invalid glob: "${glob}" (resolved: "${resolved}"). It must start with '/' or './'`);
```

`root` is the Vite root (here: `openam-ui-ria`, since `vite.config.js` sets no `root`). `dir` is the
directory of the file the glob is written in. **A bare pattern goes through the full Vite resolver,
so `resolve.alias` applies** — that is what makes an alias-prefixed pattern work at all, and the
`throw` on the last line is what makes an un-aliasable one a hard build failure rather than an
empty object.

**2.2 `getCommonBase` (`:39063`)** — the longest common directory ancestor of the resolved
patterns, with `!`-negated patterns excluded from the calculation.

**2.3 The ignore, `transformGlobImport` (`:38944-38951`)** — the thing the task warned about:

```js
const cwd = getCommonBase(globsResolved) ?? root;
const files = (await glob(globsResolved, {
    cwd,
    absolute: true,
    dot: !!options.exhaustive,
    ignore: options.exhaustive ? [] : [join(cwd, "**/node_modules/**")]
})).filter((file) => file !== id).sort();
```

**The consequence, which is the single most important fact in this file:** the `node_modules` ignore
is joined to the **common base of the resolved globs**, not to the project root. So

- a glob whose common base is **at or above the project root** excludes every `node_modules` path;
- a glob whose common base is **already inside `node_modules`** produces the ignore pattern
  `<base>/**/node_modules/**`, which matches only *nested* `node_modules` and therefore blocks
  nothing in the two commons packages.

That is why §3's package patterns work without `exhaustive`, and why §3.4's mixed array silently
loses two whole trees.

Also note `.filter((file) => file !== id)`: **a glob never matches the file it is written in.**

**2.4 `resolvePaths` (`:38957-38973`)** — the key shape; see §4.

---

## 3. MEASURED: WHICH PATTERN FORMS ENUMERATE WHICH TREE

Method: 40 throwaway one-line modules, each containing exactly one `import.meta.glob`, transformed
through the **real `vite.config.js`** (`createServer({ configFile: vite.config.js })` +
`server.transformRequest`), with the generated object's keys counted out of the transform output.
Cross-checked against `find`: `find src/main/js -name '*.js' -o -name '*.jsx'` = 250, `+ .jsm` = 281;
commons = 66; user = 14. Every count below matches the filesystem exactly.

### 3.1 THE THREE PATTERNS THAT WORK — use these

```js
// AM's own sources                        281 matches
const am = import.meta.glob("/src/main/js/**/*.{js,jsx,jsm}");

// ui-commons                               66 matches
const cm = import.meta.glob("/node_modules/@openidentityplatform/ui-commons/esm/**/*.{js,jsx}");

// ui-user                                  14 matches
const us = import.meta.glob("/node_modules/@openidentityplatform/ui-user/esm/**/*.{js,jsx}");
```

**They must be three separate `import.meta.glob` calls, merged in JS.** Not one call with an array.
See §3.4.

361 distinct ids total, with **zero** id colliding between trees and **zero** extension collision
within a tree (verified: 281 + 66 + 14 = 361 distinct normalised ids).

### 3.2 Full measurement table

| # | pattern (as written) | matches | verdict |
|---|---|---|---|
| 1 | `"/src/main/js/**/*.{js,jsx}"` | **250** | works, but **misses all 31 `.jsm` files** |
| 2 | `"/src/main/js/**/*.{js,jsx,jsm}"` | **281** | **works — the AM pattern** |
| 3 | `"/node_modules/@openidentityplatform/ui-commons/esm/**/*.{js,jsx}"` | **66** | **works — the commons pattern** (node_modules ignore does *not* fire) |
| 4 | `"/node_modules/@openidentityplatform/ui-user/esm/**/*.{js,jsx}"` | **14** | **works — the user pattern** |
| 5 | `"org/forgerock/openam/**/*.{js,jsx}"` (alias-prefixed) | **207** | works, but covers only `org/` — misses `config/`, `store/`, `components/`, `shims/`, `libs/` and every `.jsm` |
| 6 | `"org/forgerock/commons/ui/common/**/*.{js,jsx}"` (alias-prefixed) | **61** | works, but **misses commons' 5 `config/**` modules** |
| 7 | `"org/forgerock/commons/ui/user/**/*.{js,jsx}"` (alias-prefixed) | **12** | works, but **misses user's 2 `config/**` modules** |
| 8 | `"org/forgerock/openam/ui/**/*.{js,jsx,jsm}"` | 231 | works, narrower still |
| 9 | `"@openidentityplatform/ui-commons/esm/**/*.{js,jsx}"` (bare package specifier) | — | **THROWS** `Invalid glob: … It must start with '/' or './'`. Kills the build at transform time. |
| 10 | `"org/forgerock/commons/**/*.{js,jsx}"` | — | **THROWS**, same error — no alias matches `org/forgerock/commons` (only `…/ui/common` and `…/ui/user` are aliased) |
| 11 | `"config/process/CommonConfig/**/*.{js,jsx}"` | — | **THROWS** `ENOTDIR` — the seven `config/**` aliases point at *files*, so no glob can be built on them |
| 12 | `"/node_modules/**/*.{js,jsx}"` | **14364** | "works" and is a disaster — the ignore only blocks *nested* node_modules |
| 13 | `"/node_modules/@openidentityplatform/**/*.{js,jsx}"` | **159** | trap: picks up the packages' **`amd/` builds** as well as `esm/` |
| 14 | `"/**/*.{js,jsx}"` | **1169** | common base = root, so node_modules *is* excluded — but it sweeps in `target/XUI`, `target/classes`, `src/test/js`, `Gruntfile.js`, `vite.config.js` |
| 15 | `"./**/*.{js,jsx}"` from `<root>/spike-tmp/p2` | 13 (of 14 files) | importer-relative; **excludes the globbing file itself** |
| 16 | `"../../src/main/js/**/*.{js,jsx,jsm}"` | **281** | works; importer-relative keys (§4) |
| 17 | `"../../node_modules/@openidentityplatform/ui-commons/esm/**/*.{js,jsx}"` | **66** | works — a relative path *into* node_modules is fine, because the common base is still inside it |

### 3.3 `{ exhaustive: true }`

| pattern | default | `exhaustive: true` |
|---|---|---|
| commons `esm/**` | 66 | **66** — no change |
| user `esm/**` | 14 | 14 — no change |
| `/node_modules/**` | 14364 | 15319 (adds nested node_modules and dotfiles) |
| `/**` | 1169 | 17644 |
| the mixed 3-pattern array (§3.4) | **281** | **361** |

**`exhaustive` is not needed by §3.1's patterns** and should not be used: it also turns on `dot: true`,
which starts matching dotfiles (measured: `/**` exhaustive returns `.eslintrc.js`). Its only effect
that matters here is rescuing the broken array form, and the array form should not be used anyway.

### 3.4 THE TRAP: one glob call with an array of patterns SILENTLY LOSES TWO TREES

```js
// MEASURED: 281 matches, NOT 361. The two node_modules trees contribute NOTHING.
import.meta.glob([
    "/src/main/js/**/*.{js,jsx,jsm}",
    "/node_modules/@openidentityplatform/ui-commons/esm/**/*.{js,jsx}",
    "/node_modules/@openidentityplatform/ui-user/esm/**/*.{js,jsx}"
]);
```

The common base of those three globs is the **project root**, so the ignore becomes
`<root>/**/node_modules/**` and both packages are filtered out. There is **no error and no warning** —
the object is simply 281 keys instead of 361, and the missing 80 ids fail one at a time at runtime,
months later, on routes nobody clicked during testing.

Confirmed three ways:

- the mixed array of three root-absolute patterns → **281** (adding `{ exhaustive: true }` → 361);
- the mixed array of three **alias-prefixed** patterns
  `["org/forgerock/openam/**", "org/forgerock/commons/ui/common/**", "org/forgerock/commons/ui/user/**"]`
  → **207** — same failure, both package trees gone;
- an array that mixes `/src/main/js/**` with just the commons pattern → **270** (= 281 AM minus the
  11 excluded `libs/`, commons' 66 absent).

Arrays are only safe when **every** pattern shares a base inside `node_modules`:
`["…/ui-commons/esm/**", "…/ui-user/esm/**"]` → **80** ✓, and
`["org/forgerock/commons/ui/common/**", "org/forgerock/commons/ui/user/**"]` → **73** ✓.

Three separate calls each get their own common base, so **three calls is the only shape that is
correct for a reason rather than by accident.**

---

## 4. MEASURED: KEY SHAPE AND THE KEY -> ID NORMALISATION

From `resolvePaths` (`dep-BK3b2jBa.js:38957`), and confirmed by measurement:

- **relative pattern** (`./…`, `../…`): key = the path from the *importing file's directory* to the
  match, `./`-prefixed if it does not already start with `.`;
- **root-absolute pattern** (`/…`) and **alias-prefixed pattern** (bare, resolved by `resolve.alias`):
  key = the path from the **Vite root**, `/`-prefixed — *unless* it starts with `.`, in which case it
  is left bare (measured: `/**` exhaustive yields the key `.eslintrc.js`, no leading slash).

### 4.1 Real keys and their real ids

| pattern | a real key | the id the application passes |
|---|---|---|
| `"/src/main/js/**/*.{js,jsx,jsm}"` | `/src/main/js/org/forgerock/openam/ui/common/components/TreeNavigation.js` | `org/forgerock/openam/ui/common/components/TreeNavigation` |
| `"/src/main/js/**/*.{js,jsx,jsm}"` | `/src/main/js/store/index.jsm` | `store/index` |
| `"/src/main/js/**/*.{js,jsx,jsm}"` | `/src/main/js/config/routes/AMRoutesConfig.js` | `config/routes/AMRoutesConfig` |
| `"/node_modules/@openidentityplatform/ui-commons/esm/**/*.{js,jsx}"` | `/node_modules/@openidentityplatform/ui-commons/esm/org/forgerock/commons/ui/common/util/UIUtils.js` | `org/forgerock/commons/ui/common/util/UIUtils` |
| `"/node_modules/@openidentityplatform/ui-commons/esm/**/*.{js,jsx}"` | `/node_modules/@openidentityplatform/ui-commons/esm/config/process/CommonConfig.js` | `config/process/CommonConfig` |
| `"/node_modules/@openidentityplatform/ui-user/esm/**/*.{js,jsx}"` | `/node_modules/@openidentityplatform/ui-user/esm/org/forgerock/commons/ui/user/profile/UserProfileView.js` | `org/forgerock/commons/ui/user/profile/UserProfileView` |
| `"org/forgerock/commons/ui/common/**/*.{js,jsx}"` (alias form) | `/node_modules/@openidentityplatform/ui-commons/esm/org/forgerock/commons/ui/common/EnableCookiesView.js` | `org/forgerock/commons/ui/common/EnableCookiesView` |

Note the last row: **the alias-prefixed form produces exactly the same key shape as the
root-absolute form.** The alias affects *what is found*, never *how it is named*.

### 4.2 The normalisation, as runnable code

```js
const AM_PREFIX = "/src/main/js/";
const CM_PREFIX = "/node_modules/@openidentityplatform/ui-commons/esm/";
const US_PREFIX = "/node_modules/@openidentityplatform/ui-user/esm/";

const strip = (key, prefix) => key.slice(prefix.length).replace(/\.(jsx?|jsm)$/, "");
```

Two properties of this that were verified rather than assumed:

- **the extension strip is unambiguous.** Within each tree, no two files share a normalised id:
  AM 281 files → 281 distinct ids, CM 66 → 66, US 14 → 14. There is no `Foo.js` beside a `Foo.jsm`.
- **the three trees do not collide.** 281 + 66 + 14 = 361 distinct ids across the merged map, so
  merge order is irrelevant for correctness. (It still matters for §12.4.)

---

## 5. WHERE THE GLOB FILE HAS TO LIVE

MEASURED by writing the *same* patterns into two files at different depths
(`<root>/spike-tmp/p/x.js` and `<root>/spike-tmp/p/deep/x.js`) and diffing the keys:

| pattern form | keys from depth 1 | keys from depth 2 | importer-sensitive? |
|---|---|---|---|
| `"/src/main/js/**/*.{js,jsx}"` | `/src/main/js/components/Block.jsx` | `/src/main/js/components/Block.jsx` | **no** |
| `"/node_modules/@…/ui-commons/esm/**/*.{js,jsx}"` | `/node_modules/@…/esm/config/errorhandlers/CommonErrorHandlers.js` | identical | **no** |
| `"org/forgerock/commons/ui/common/**/*.{js,jsx}"` | `/node_modules/@…/esm/org/…/EnableCookiesView.js` | identical | **no** |
| `"../src/main/js/**"` vs `"../../../src/main/js/**"` | `../src/main/js/…` | `../../../src/main/js/…` | **yes** — pattern *and* key both change |

**Answer: with §3.1's root-absolute patterns the file's location does not affect the keys at all, so
the registry can live anywhere inside the Vite root.** That is the main reason to prefer them over
the `./**` form the task text proposes: `./**` would pin the registry to `src/main/js/` forever, and
moving it one directory would silently change all 281 keys and therefore all 281 ids.

Two caveats that do bind the location:

1. The patterns are relative to the **Vite root**, which is `openam-ui-ria` (no `root:` key in
   `vite.config.js`). If a later task sets `root`, all three prefixes in §4.2 must change.
2. `.filter((file) => file !== id)` — a glob never matches its own file. If the registry lives at
   `src/main/js/<something>.js`, its own id is absent from the map. Harmless for a registry;
   fatal if anyone ever tries to make a module load itself by id.

---

## 6. LAZY vs `{ eager: true }`

MEASURED, same pattern both ways:

| | lazy (default) | `{ eager: true }` |
|---|---|---|
| commons pattern match count | 66 | **66** |
| commons alias-form match count | 61 | **61** |
| keys | `/node_modules/@…/esm/config/errorhandlers/CommonErrorHandlers.js` | **identical** |

**`eager` changes nothing about resolution, enumeration, ignore behaviour or key shape.** It changes
only the generated code — `() => import(x)` becomes a hoisted `import * as __vite_glob_0_0 from x`.
So it is purely a payload decision, and §10.1 is why the answer is "stay lazy".

---

## 7. THE IDENTIFIER CORPUS

Derived, not recalled. Extracted mechanically from source by a script that read:

- `src/main/js/config/AppConfiguration.js` — 10 `moduleClass`, 1 `loginHelperClass`, the
  `SiteConfigurator` delegate, 6 Router `loader` routes, 2 `processConfigurationFiles`,
  1 `defaultHandlers`, 3 `messages`, 2 `validators`;
- every `view:` / `dialog:` / `page:` string in all six route configs — AM
  `config/routes/{AMRoutesConfig, admin/GlobalRoutes, admin/RealmsRoutes, user/UMARoutes}.js`,
  commons `config/routes/CommonRoutesConfig.js`, user `config/routes/UserRoutesConfig.js`;
- every element of every `dependencies:` array in `config/process/AMConfig.js` and commons
  `config/process/CommonConfig.js` (multi-line arrays included);
- every string-literal argument to `ModuleLoader.load(...)`, `require([...])` and `callService(...)`
  across all three trees;
- the synthesised `UnauthorizedView` fallback route in `CommonConfig.js`.

**Result: 122 distinct string identifiers. 113 of them a glob produces; 9 it does not.**

Distribution: **AM 82, commons 27, user 4, unglobbable 9.**

Two things worth stating because they were checked rather than assumed:

- **`ValidatorsManager` contributes nothing.** `ValidatorsManager.js:88` does
  `_.map(validatorConfig.dependencies, ModuleLoader.load)`, but **every** `dependencies` array in
  both validator configs is empty: commons `config/validators/CommonValidators.js` (5 validators,
  all `[]`) and AM `config/validators/AMValidators.js` (4 validators, all `[]`). There is no
  ui-user validators config. Zero ids from this source.
- **Every route `view:`/`dialog:`/`page:` value in all six route configs is still a string
  literal.** None has been replaced by an imported binding during the AMD→ESM conversion, so the
  registry — not `resolve.alias` — is what has to answer for all of them.

### 7.1 Ids that need an extension other than `.js`

This is why §3.1's AM pattern is `{js,jsx,jsm}` and not the `{js,jsx}` in the task text.
**10 of the 122 ids resolve to a `.jsm` file and would be unresolvable at runtime under `{js,jsx}`:**

```
org/forgerock/openam/ui/admin/views/realms/applications/agents/NewAgentView       .jsm
org/forgerock/openam/ui/admin/views/realms/authentication/modules/EditModuleView  .jsm
org/forgerock/openam/ui/admin/views/realms/ListRealmsView                         .jsm
org/forgerock/openam/ui/admin/views/realms/services/NewServiceView                .jsm
org/forgerock/openam/ui/common/util/NavigationHelper                              .jsm
org/forgerock/openam/ui/user/dashboard/views/DashboardView                        .jsm
org/forgerock/openam/ui/user/login/logout                                         .jsm
org/forgerock/openam/ui/user/login/tokens/SessionToken                            .jsm
store/actions/creators                                                            .jsm
store/index                                                                       .jsm
```

A further 5 resolve to `.jsx` (`ListApiView`, `ListAuthenticationView`, `ListGlobalServicesView`,
`SelectAgentView`, `SessionsView`), which the task text's pattern does cover.

### 7.2 The full table

| # | identifier | tree | file ext | glob produces it? | first use site |
|---|---|---|---|---|---|
| 1 | `bootstrap` | **none** | -- | **NO** | CM org/forgerock/commons/ui/common/components/Navigation.js:54 (ModuleLoader.load literal) (+1 more) |
| 2 | `bootstrap-dialog` | **none** | -- | **NO** | CM org/forgerock/commons/ui/common/util/UIUtils.js:345 (ModuleLoader.load literal) |
| 3 | `config/AppMessages` | AM | .js | yes | AM config/AppConfiguration.js:105 (loader messages) |
| 4 | `config/errorhandlers/CommonErrorHandlers` | CM | .js | yes | AM config/AppConfiguration.js:64 (loader defaultHandlers) |
| 5 | `config/messages/CommonMessages` | CM | .js | yes | AM config/AppConfiguration.js:103 (loader messages) |
| 6 | `config/messages/UserMessages` | US | .js | yes | AM config/AppConfiguration.js:104 (loader messages) |
| 7 | `config/process/AMConfig` | AM | .js | yes | AM config/AppConfiguration.js:48 (processConfigurationFiles) |
| 8 | `config/process/CommonConfig` | CM | .js | yes | AM config/AppConfiguration.js:49 (processConfigurationFiles) |
| 9 | `config/routes/admin/GlobalRoutes` | AM | .js | yes | AM config/AppConfiguration.js:32 (loader routes) |
| 10 | `config/routes/admin/RealmsRoutes` | AM | .js | yes | AM config/AppConfiguration.js:31 (loader routes) |
| 11 | `config/routes/AMRoutesConfig` | AM | .js | yes | AM config/AppConfiguration.js:28 (loader routes) |
| 12 | `config/routes/CommonRoutesConfig` | CM | .js | yes | AM config/AppConfiguration.js:29 (loader routes) |
| 13 | `config/routes/user/UMARoutes` | AM | .js | yes | AM config/AppConfiguration.js:33 (loader routes) |
| 14 | `config/routes/UserRoutesConfig` | US | .js | yes | AM config/AppConfiguration.js:30 (loader routes) |
| 15 | `config/validators/AMValidators` | AM | .js | yes | AM config/AppConfiguration.js:114 (loader validators) |
| 16 | `config/validators/CommonValidators` | CM | .js | yes | AM config/AppConfiguration.js:113 (loader validators) |
| 17 | `Footer` | **none** | -- | **NO** | AM config/process/AMConfig.js:194 (dependencies) (+1 more) |
| 18 | `ForgotUsernameView` | **none** | -- | **NO** | US config/routes/UserRoutesConfig.js:27 (route view:) |
| 19 | `LoginDialog` | **none** | -- | **NO** | CM config/routes/CommonRoutesConfig.js:45 (route dialog:) (+2 more) |
| 20 | `LoginView` | **none** | -- | **NO** | CM config/routes/CommonRoutesConfig.js:34 (route view:) |
| 21 | `org/forgerock/commons/ui/common/components/BootstrapDialog` | CM | .js | yes | CM org/forgerock/commons/ui/common/components/BootstrapDialogView.js:37 (ModuleLoader.load literal) |
| 22 | `org/forgerock/commons/ui/common/components/LoginHeader` | CM | .js | yes | AM config/process/AMConfig.js:194 (dependencies) (+1 more) |
| 23 | `org/forgerock/commons/ui/common/components/Messages` | CM | .js | yes | CM config/process/CommonConfig.js:245 (dependencies) (+1 more) |
| 24 | `org/forgerock/commons/ui/common/components/Navigation` | CM | .js | yes | CM config/process/CommonConfig.js:57 (dependencies) (+6 more) |
| 25 | `org/forgerock/commons/ui/common/EnableCookiesView` | CM | .js | yes | CM config/routes/CommonRoutesConfig.js:30 (route view:) (+1 more) |
| 26 | `org/forgerock/commons/ui/common/main/Configuration` | CM | .js | yes | AM config/process/AMConfig.js:28 (dependencies) (+16 more) |
| 27 | `org/forgerock/commons/ui/common/main/ErrorsHandler` | CM | .js | yes | AM config/AppConfiguration.js:59 (moduleClass) |
| 28 | `org/forgerock/commons/ui/common/main/i18nManager` | CM | .js | yes | CM config/process/CommonConfig.js:27 (dependencies) |
| 29 | `org/forgerock/commons/ui/common/main/ProcessConfiguration` | CM | .js | yes | AM config/AppConfiguration.js:45 (moduleClass) |
| 30 | `org/forgerock/commons/ui/common/main/Router` | CM | .js | yes | AM config/process/AMConfig.js:28 (dependencies) (+12 more) |
| 31 | `org/forgerock/commons/ui/common/main/ServiceInvoker` | CM | .js | yes | AM config/AppConfiguration.js:53 (moduleClass) |
| 32 | `org/forgerock/commons/ui/common/main/SessionManager` | CM | .js | yes | AM config/process/AMConfig.js:28 (dependencies) (+4 more) |
| 33 | `org/forgerock/commons/ui/common/main/SpinnerManager` | CM | .js | yes | CM config/process/CommonConfig.js:147 (dependencies) |
| 34 | `org/forgerock/commons/ui/common/main/ValidatorsManager` | CM | .js | yes | AM config/AppConfiguration.js:109 (moduleClass) |
| 35 | `org/forgerock/commons/ui/common/main/ViewManager` | CM | .js | yes | CM config/process/CommonConfig.js:112 (dependencies) (+4 more) |
| 36 | `org/forgerock/commons/ui/common/NotFoundView` | CM | .js | yes | CM config/routes/CommonRoutesConfig.js:20 (route view:) (+1 more) |
| 37 | `org/forgerock/commons/ui/common/SiteConfigurator` | CM | .js | yes | CM config/process/CommonConfig.js:147 (dependencies) (+1 more) |
| 38 | `org/forgerock/commons/ui/common/UnauthorizedView` | CM | .js | yes | CM config/process/CommonConfig.js:152 (synthesised route view) (+1 more) |
| 39 | `org/forgerock/commons/ui/common/util/CookieHelper` | CM | .js | yes | CM config/process/CommonConfig.js:27 (dependencies) |
| 40 | `org/forgerock/commons/ui/common/util/ModuleLoader` | CM | .js | yes | CM config/process/CommonConfig.js:112 (dependencies) (+2 more) |
| 41 | `org/forgerock/commons/ui/common/util/Queue` | CM | .js | yes | AM config/process/AMConfig.js:273 (dependencies) (+1 more) |
| 42 | `org/forgerock/commons/ui/common/util/UIUtils` | CM | .js | yes | CM config/process/CommonConfig.js:27 (dependencies) (+1 more) |
| 43 | `org/forgerock/commons/ui/user/anonymousProcess/KBAView` | US | .js | yes | CM config/process/CommonConfig.js:344 (dependencies) (+1 more) |
| 44 | `org/forgerock/commons/ui/user/profile/UserProfileKBATab` | US | .js | yes | AM org/forgerock/openam/ui/common/services/SiteConfigurationService.js:38 (require([...]) literal) |
| 45 | `org/forgerock/openam/ui/admin/services/global/RealmsService` | AM | .js | yes | AM config/process/AMConfig.js:205 (dependencies) |
| 46 | `org/forgerock/openam/ui/admin/services/global/ServicesService` | AM | .js | yes | AM config/process/AMConfig.js:205 (dependencies) |
| 47 | `org/forgerock/openam/ui/admin/utils/RedirectToLegacyConsole` | AM | .js | yes | AM config/process/AMConfig.js:103 (dependencies) (+7 more) |
| 48 | `org/forgerock/openam/ui/admin/views/api/ApiDocView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:298 (route view:) (+1 more) |
| 49 | `org/forgerock/openam/ui/admin/views/api/ListApiView` | AM | .jsx | yes | AM config/routes/admin/RealmsRoutes.js:291 (route view:) (+1 more) |
| 50 | `org/forgerock/openam/ui/admin/views/common/server/EditServerView` | AM | .js | yes | AM config/routes/admin/GlobalRoutes.js:120 (route page:) (+1 more) |
| 51 | `org/forgerock/openam/ui/admin/views/configuration/authentication/EditGlobalAuthenticationView` | AM | .js | yes | AM config/routes/admin/GlobalRoutes.js:28 (route view:) (+1 more) |
| 52 | `org/forgerock/openam/ui/admin/views/configuration/authentication/ListAuthenticationView` | AM | .jsx | yes | AM config/routes/admin/GlobalRoutes.js:21 (route view:) (+1 more) |
| 53 | `org/forgerock/openam/ui/admin/views/configuration/global/EditGlobalServiceSubSchemaView` | AM | .js | yes | AM config/routes/admin/GlobalRoutes.js:57 (route view:) (+1 more) |
| 54 | `org/forgerock/openam/ui/admin/views/configuration/global/EditGlobalServiceSubSubSchemaView` | AM | .js | yes | AM config/routes/admin/GlobalRoutes.js:65 (route view:) (+1 more) |
| 55 | `org/forgerock/openam/ui/admin/views/configuration/global/EditGlobalServiceView` | AM | .js | yes | AM config/routes/admin/GlobalRoutes.js:42 (route view:) (+1 more) |
| 56 | `org/forgerock/openam/ui/admin/views/configuration/global/ListGlobalServicesView` | AM | .jsx | yes | AM config/routes/admin/GlobalRoutes.js:35 (route view:) (+1 more) |
| 57 | `org/forgerock/openam/ui/admin/views/configuration/global/NewGlobalServiceSubSchemaView` | AM | .js | yes | AM config/routes/admin/GlobalRoutes.js:49 (route view:) (+1 more) |
| 58 | `org/forgerock/openam/ui/admin/views/configuration/server/EditServerDefaultsTreeNavigationView` | AM | .js | yes | AM config/routes/admin/GlobalRoutes.js:132 (route view:) (+1 more) |
| 59 | `org/forgerock/openam/ui/admin/views/deployment/servers/EditServerTreeNavigationView` | AM | .js | yes | AM config/routes/admin/GlobalRoutes.js:119 (route view:) (+1 more) |
| 60 | `org/forgerock/openam/ui/admin/views/deployment/servers/ListServersView` | AM | .js | yes | AM config/routes/admin/GlobalRoutes.js:94 (route view:) (+1 more) |
| 61 | `org/forgerock/openam/ui/admin/views/deployment/servers/NewServerView` | AM | .js | yes | AM config/routes/admin/GlobalRoutes.js:101 (route view:) (+3 more) |
| 62 | `org/forgerock/openam/ui/admin/views/deployment/sites/EditSiteView` | AM | .js | yes | AM config/routes/admin/GlobalRoutes.js:80 (route view:) (+1 more) |
| 63 | `org/forgerock/openam/ui/admin/views/deployment/sites/ListSitesView` | AM | .js | yes | AM config/routes/admin/GlobalRoutes.js:73 (route view:) (+1 more) |
| 64 | `org/forgerock/openam/ui/admin/views/deployment/sites/NewSiteView` | AM | .js | yes | AM config/routes/admin/GlobalRoutes.js:87 (route view:) (+1 more) |
| 65 | `org/forgerock/openam/ui/admin/views/realms/applications/agents/NewAgentView` | AM | .jsm | yes | AM config/routes/admin/RealmsRoutes.js:283 (route page:) |
| 66 | `org/forgerock/openam/ui/admin/views/realms/applications/agents/SelectAgentView` | AM | .jsx | yes | AM config/routes/admin/RealmsRoutes.js:274 (route page:) |
| 67 | `org/forgerock/openam/ui/admin/views/realms/authentication/chains/AddChainView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:84 (route page:) |
| 68 | `org/forgerock/openam/ui/admin/views/realms/authentication/chains/EditChainView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:76 (route page:) |
| 69 | `org/forgerock/openam/ui/admin/views/realms/authentication/ChainsView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:67 (route page:) |
| 70 | `org/forgerock/openam/ui/admin/views/realms/authentication/modules/AddModuleView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:103 (route page:) |
| 71 | `org/forgerock/openam/ui/admin/views/realms/authentication/modules/EditModuleView` | AM | .jsm | yes | AM config/routes/admin/RealmsRoutes.js:112 (route page:) |
| 72 | `org/forgerock/openam/ui/admin/views/realms/authentication/ModulesView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:94 (route page:) |
| 73 | `org/forgerock/openam/ui/admin/views/realms/authentication/SettingsView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:58 (route page:) |
| 74 | `org/forgerock/openam/ui/admin/views/realms/authorization/policies/EditPolicyView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:202 (route page:) (+1 more) |
| 75 | `org/forgerock/openam/ui/admin/views/realms/authorization/policySets/EditPolicySetView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:184 (route page:) (+1 more) |
| 76 | `org/forgerock/openam/ui/admin/views/realms/authorization/policySets/PolicySetsView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:175 (route page:) |
| 77 | `org/forgerock/openam/ui/admin/views/realms/authorization/resourceTypes/EditResourceTypeView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:229 (route page:) (+1 more) |
| 78 | `org/forgerock/openam/ui/admin/views/realms/authorization/resourceTypes/ResourceTypesView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:220 (route page:) |
| 79 | `org/forgerock/openam/ui/admin/views/realms/dashboard/DashboardView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:49 (route page:) |
| 80 | `org/forgerock/openam/ui/admin/views/realms/EditRealmView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:32 (route view:) (+3 more) |
| 81 | `org/forgerock/openam/ui/admin/views/realms/ListRealmsView` | AM | .jsm | yes | AM config/routes/admin/RealmsRoutes.js:25 (route view:) (+1 more) |
| 82 | `org/forgerock/openam/ui/admin/views/realms/RealmTreeNavigationView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:48 (route view:) (+53 more) |
| 83 | `org/forgerock/openam/ui/admin/views/realms/scripts/EditScriptView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:256 (route page:) (+1 more) |
| 84 | `org/forgerock/openam/ui/admin/views/realms/scripts/ScriptsView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:247 (route page:) |
| 85 | `org/forgerock/openam/ui/admin/views/realms/services/EditServiceSubSchemaView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:157 (route page:) |
| 86 | `org/forgerock/openam/ui/admin/views/realms/services/EditServiceView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:130 (route page:) |
| 87 | `org/forgerock/openam/ui/admin/views/realms/services/NewServiceSubSchemaView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:148 (route page:) |
| 88 | `org/forgerock/openam/ui/admin/views/realms/services/NewServiceView` | AM | .jsm | yes | AM config/routes/admin/RealmsRoutes.js:139 (route page:) |
| 89 | `org/forgerock/openam/ui/admin/views/realms/services/ServicesView` | AM | .js | yes | AM config/routes/admin/RealmsRoutes.js:121 (route page:) |
| 90 | `org/forgerock/openam/ui/admin/views/realms/sessions/SessionsView` | AM | .jsx | yes | AM config/routes/admin/RealmsRoutes.js:166 (route page:) |
| 91 | `org/forgerock/openam/ui/common/RouteTo` | AM | .js | yes | AM config/process/AMConfig.js:253 (dependencies) |
| 92 | `org/forgerock/openam/ui/common/services/SiteConfigurationService` | AM | .js | yes | AM config/AppConfiguration.js:42 (SiteConfigurator delegate) |
| 93 | `org/forgerock/openam/ui/common/sessions/SessionValidator` | AM | .js | yes | AM config/process/AMConfig.js:28 (dependencies) (+1 more) |
| 94 | `org/forgerock/openam/ui/common/sessions/strategies/MaxIdleTimeLeftStrategy` | AM | .js | yes | AM config/process/AMConfig.js:205 (dependencies) |
| 95 | `org/forgerock/openam/ui/common/util/NavigationHelper` | AM | .jsm | yes | AM config/process/AMConfig.js:205 (dependencies) |
| 96 | `org/forgerock/openam/ui/common/views/error/ForbiddenView` | AM | .js | yes | AM org/forgerock/openam/ui/common/RouteTo.js:39 (synthesised route view) |
| 97 | `org/forgerock/openam/ui/user/anonymousProcess/PasswordResetView` | AM | .js | yes | AM config/routes/AMRoutesConfig.js:19 (route view:) (+1 more) |
| 98 | `org/forgerock/openam/ui/user/anonymousProcess/SelfRegistrationView` | AM | .js | yes | AM config/routes/AMRoutesConfig.js:27 (route view:) (+1 more) |
| 99 | `org/forgerock/openam/ui/user/dashboard/views/DashboardView` | AM | .jsm | yes | AM config/routes/AMRoutesConfig.js:41 (route view:) (+1 more) |
| 100 | `org/forgerock/openam/ui/user/login/LoginFailureView` | AM | .js | yes | AM config/routes/AMRoutesConfig.js:61 (route view:) (+1 more) |
| 101 | `org/forgerock/openam/ui/user/login/logout` | AM | .jsm | yes | AM config/process/AMConfig.js:273 (dependencies) |
| 102 | `org/forgerock/openam/ui/user/login/RESTConfirmLoginView` | AM | .js | yes | AM config/routes/AMRoutesConfig.js:35 (route view:) (+1 more) |
| 103 | `org/forgerock/openam/ui/user/login/RESTLoginHelper` | AM | .js | yes | AM config/AppConfiguration.js:21 (loginHelperClass) |
| 104 | `org/forgerock/openam/ui/user/login/RESTLogoutView` | AM | .js | yes | AM config/routes/AMRoutesConfig.js:54 (route view:) (+1 more) |
| 105 | `org/forgerock/openam/ui/user/login/SessionExpiredView` | AM | .js | yes | AM config/routes/AMRoutesConfig.js:68 (route view:) (+1 more) |
| 106 | `org/forgerock/openam/ui/user/login/tokens/SessionToken` | AM | .jsm | yes | AM config/process/AMConfig.js:205 (dependencies) |
| 107 | `org/forgerock/openam/ui/user/oauth2/TokensView` | AM | .js | yes | AM config/routes/AMRoutesConfig.js:48 (route view:) (+1 more) |
| 108 | `org/forgerock/openam/ui/user/uma/views/history/ListHistory` | AM | .js | yes | AM config/routes/user/UMARoutes.js:106 (route view:) (+1 more) |
| 109 | `org/forgerock/openam/ui/user/uma/views/request/EditRequest` | AM | .js | yes | AM config/routes/user/UMARoutes.js:114 (route view:) (+1 more) |
| 110 | `org/forgerock/openam/ui/user/uma/views/request/ListRequest` | AM | .js | yes | AM config/routes/user/UMARoutes.js:121 (route view:) (+1 more) |
| 111 | `org/forgerock/openam/ui/user/uma/views/resource/LabelTreeNavigationView` | AM | .js | yes | AM config/routes/user/UMARoutes.js:20 (route view:) (+15 more) |
| 112 | `org/forgerock/openam/ui/user/uma/views/resource/MyLabelsPage` | AM | .js | yes | AM config/routes/user/UMARoutes.js:85 (route page:) |
| 113 | `org/forgerock/openam/ui/user/uma/views/resource/MyResourcesPage` | AM | .js | yes | AM config/routes/user/UMARoutes.js:21 (route page:) |
| 114 | `org/forgerock/openam/ui/user/uma/views/resource/ResourcePage` | AM | .js | yes | AM config/routes/user/UMARoutes.js:31 (route page:) (+3 more) |
| 115 | `org/forgerock/openam/ui/user/uma/views/resource/SharedWithMePage` | AM | .js | yes | AM config/routes/user/UMARoutes.js:43 (route page:) |
| 116 | `org/forgerock/openam/ui/user/uma/views/resource/StarredPage` | AM | .js | yes | AM config/routes/user/UMARoutes.js:64 (route page:) |
| 117 | `org/forgerock/openam/ui/user/uma/views/share/BaseShare` | AM | .js | yes | AM config/routes/user/UMARoutes.js:130 (route view:) (+1 more) |
| 118 | `PasswordResetView` | **none** | -- | **NO** | US config/routes/UserRoutesConfig.js:34 (route view:) |
| 119 | `RegisterView` | **none** | -- | **NO** | US config/routes/UserRoutesConfig.js:41 (route view:) |
| 120 | `store/actions/creators` | AM | .jsm | yes | AM config/process/AMConfig.js:28 (dependencies) |
| 121 | `store/index` | AM | .jsm | yes | AM config/process/AMConfig.js:28 (dependencies) |
| 122 | `UserProfileView` | **none** | -- | **NO** | US config/routes/UserRoutesConfig.js:19 (route view:) |

---

## 8. THE 9 IDS NO GLOB PRODUCES

These are the registry's explicit map entries. Nothing else in the 122 needs one.

| identifier | kind | asked for at | must resolve to |
|---|---|---|---|
| `bootstrap` | library name | commons `main/AbstractView.js:32`, `components/Navigation.js:54` (both `ModuleLoader.load("bootstrap")`) | the `bootstrap` package (already `resolve.alias` #29 → `src/main/js/shims/bootstrap.js`) |
| `bootstrap-dialog` | library name | commons `util/UIUtils.js:345` | `bootstrap3-dialog/dist/js/bootstrap-dialog.min.js` (already `resolve.alias` #45) |
| `Footer` | logical name | AM `config/process/AMConfig.js:195`, commons `config/process/CommonConfig.js:57` (both `dependencies`) | `org/forgerock/openam/ui/common/components/Footer` |
| `LoginView` | logical name | commons `config/routes/CommonRoutesConfig.js:34` (route `view:`) | `org/forgerock/openam/ui/user/login/RESTLoginView` |
| `LoginDialog` | logical name | commons `config/routes/CommonRoutesConfig.js:45` (route `dialog:`), commons `config/process/CommonConfig.js:305`, AM `config/process/AMConfig.js:274` | `org/forgerock/openam/ui/user/login/RESTLoginDialog` |
| `ForgotUsernameView` | logical name | user `config/routes/UserRoutesConfig.js:27` (route `view:`) | `org/forgerock/openam/ui/user/anonymousProcess/ForgotUsernameView` |
| `PasswordResetView` | logical name | user `config/routes/UserRoutesConfig.js:34` (route `view:`) | `org/forgerock/openam/ui/user/anonymousProcess/PasswordResetView` |
| `RegisterView` | logical name | user `config/routes/UserRoutesConfig.js:41` (route `view:`) | `org/forgerock/openam/ui/user/anonymousProcess/SelfRegistrationView` |
| `UserProfileView` | logical name | user `config/routes/UserRoutesConfig.js:19` (route `view:`) — **and** AM `SiteConfigurationService.js:25` as a static import | `@openidentityplatform/ui-user/esm/org/forgerock/commons/ui/user/profile/UserProfileView.js` |

The two library names are exactly the case commons documents rather than a discovery:
`LoaderRuntime.js`'s header and `ui-commons/NPM-PACKAGE.md` § *"The three loader APIs with no ES
module equivalent"* both say so in the same words — *"Three of the ids commons passes are library
names rather than module paths … which the glob above matches neither of"* — and both warn that
`bootstrap-dialog` is one of the ids the product **rebinds**, since the npm package is
`bootstrap3-dialog`. The corpus measurement agrees with the documentation on all three call sites.

### 8.1 One more id that is not a `ModuleLoader.load` case but needs the registry anyway

`org/forgerock/commons/ui/user/profile/UserProfileKBATab` — AM
`org/forgerock/openam/ui/common/services/SiteConfigurationService.js:38`, inside
`if (serverInfo.kbaEnabled === "true")`. It is a **bare `require([...])`**, not `ModuleLoader.load`,
and today it is dead: `index.html` no longer loads RequireJS, so the guard
`if (typeof require === "function")` is false and the `else` branch logs

> `KBA tab not loaded: needs the 6.1 import.meta.glob module registry (D1).`

The glob **does** produce this id (user tree, `.js`), so the registry covers it the moment the
`require([...])` is replaced by a registry lookup. That replacement is 6.1's, and the comment in the
source says so. It must stay **conditional** — hoisting it to a static import turns a KBA-only fetch
into an unconditional one.

---

## 9. THE SEVEN LOGICAL NAMES

### 9.1 Drift check against the tables

The table beside `resolve.alias` in `vite.config.js` (search `RUNTIME STRING IDENTIFIERS`, ~line
3065) and the per-name tables in `NOTES-vite-aliases.md` §2 were re-checked against the source.

**The names, the targets and the classification are all still correct. Every `file:line` has
drifted**, because those tables were written against the AMD-era files and the ESM conversion
shortened them.

| name | table says | actually |
|---|---|---|
| `Footer` | AM `AMConfig.js:196` | **`:195`** |
| `Footer` | commons `CommonConfig.js:73` | **`:57`** |
| `LoginView` | commons `CommonRoutesConfig.js:40` | **`:34`** |
| `LoginDialog` | commons `CommonRoutesConfig.js:51` | **`:45`** |
| `LoginDialog` | commons `CommonConfig.js:420` | **`:305`** |
| `LoginDialog` | AM `AMConfig.js:275` | **`:274`** |
| `ForgotUsernameView` | user `UserRoutesConfig.js:32` | **`:27`** |
| `PasswordResetView` | user `UserRoutesConfig.js:39` | **`:34`** |
| `RegisterView` | user `UserRoutesConfig.js:46` | **`:41`** |
| `UserProfileView` | user `UserRoutesConfig.js:24` | **`:19`** |
| `UserProfileView` | AM `SiteConfigurationService.js:25` | `:25` — line unchanged, but it is now `import UserProfileView from "UserProfileView";`, an ESM import, not a `define([...])` dep |
| `RESTLoginHelper` string-equality case (c) | AM `RESTLoginHelper.js:61` | **`:61` — unchanged** |

Two further drifts in `NOTES-vite-aliases.md` §2's header: its sweep basis says *"all 259 AM files …
all 65 COMMONS files, all 14 USER files"*. Today: **281** AM (`.js`/`.jsx`/`.jsm`), **66** commons
(`LoaderRuntime.js` was added), 14 user.

The case (c) warning still stands verbatim and still has no owner: `RESTLoginHelper.js:61` compares
`ViewManager.currentView === "LoginView"` against the **raw, unresolved** route identifier. If the
registry (or anyone) rewrites the route configs to name real module paths, that comparison becomes
permanently false and the re-render branch dies silently. **The registry must resolve the logical
name without rewriting the route config that produces it.**

### 9.2 `UserProfileView` — one instance or two?

**One instance. The KBA tab trap does not fire.**

The question matters because `SiteConfigurationService.js:39` calls `UserProfileView.registerTab(tab)`
on the module it got through the **alias** (a static import), while the route `view: "UserProfileView"`
would get its module through the **registry** (a dynamic import). Two instances would mean the tab
is registered on an object the route never renders.

**How it was determined** — not by reasoning about resolvers, but by building it. A throwaway entry
reached the same module both ways at once:

```js
import UPV from "UserProfileView";                                   // the alias, statically
const us = import.meta.glob("/node_modules/@openidentityplatform/ui-user/esm/**/*.{js,jsx}");
globalThis.__CHECK__ = () => us["/node_modules/@openidentityplatform/ui-user/esm/org/forgerock/commons/ui/user/profile/UserProfileView.js"]()
    .then((m) => (m.default || m) === UPV);
```

built through the real `vite.config.js` with `write: false`, then the resulting Rollup bundle was
asked how many module records it holds whose id ends in `UserProfileView.js`:

```
UserProfileView.js module records: 1
   both.js  <-  /…/node_modules/@openidentityplatform/ui-user/esm/org/forgerock/commons/ui/user/profile/UserProfileView.js
```

**One record.** `resolve.alias` replaces `"UserProfileView"` with an absolute filesystem path
(`fromPkgPath(...)`), and the glob's generated `import()` is an importer-relative path to the same
file; both are normalised to the same absolute id before Rollup keys the module graph, so Rollup
deduplicates them into a single module. One module means one evaluation and one set of module-level
bindings — the same object, so `registerTab` lands on the instance the route renders.

Repeated with the seven names bound as **thunks** instead: still `1`. **The identity holds in both
shapes**, so §10.2's thunk recommendation does not put it at risk.

One consequence worth knowing: because the static alias import wins, `UserProfileView` is pulled
into the **initial** chunk today regardless of what the registry does. That is a property of the
existing alias, not of the registry.

### 9.3 "A logical name left unbound" — what the registry has to do

The scenario (`openspec/changes/modernize-openam-ui-build/specs/ui-module-loading/spec.md:78-81`):

> **WHEN** a product does not declare an implementation for a logical name that commons resolves
> **THEN** the failure is reported against the logical name rather than surfacing as an unrelated
> runtime error

`resolve.alias` cannot satisfy this: an unbound alias is a build-time *unresolved-import warning* and
a runtime `undefined`, and neither mentions the logical name at the point of failure.

**The registry already gets most of the way for free, and there is exactly one way to lose it.**
`LoaderRuntime.loadModule` (commons
`org/forgerock/commons/ui/common/util/esm/LoaderRuntime.js:201-236`) throws, naming the id, when the
resolver yields nothing:

```js
if (module === null || module === undefined) {
    throw new Error(
        "[LoaderRuntime] The configured resolveModule returned nothing for \"" + id +
        "\". The consuming application's module registry does not cover this id. …"
    );
}
```

Because the id commons passes **is** the logical name — `"LoginView"`, not a path — that message
already names it. So the registry's obligations are:

1. **`resolveModule` must RETURN `undefined` for an unknown id, never throw.** The natural spelling
   `return (names[id] || modules[id] || libraries[id])()` throws a `TypeError: … is not a function`.
   `LoaderRuntime` catches it (it calls the resolver inside `Promise.resolve().then(...)` precisely
   because *"a missing entry in an `import.meta.glob` map is a TypeError, not a rejection"*), but the
   rejection then carries *"x is not a function"* and **the logical name is gone**. Write it as
   `NPM-PACKAGE.md` does, with the explicit no-op fallback:

   ```js
   resolveModule: (id) => (logicalNames[id] || modules[id] || libraries[id] || (() => undefined))()
   ```

2. **Look the raw id up as given.** Do not normalise, path-ify or pre-resolve a logical name before
   the lookup — the moment the registry maps `"LoginView"` to a path *and then* fails on the path,
   the error names the path and the scenario is not met.

3. **What the registry can do that the alias cannot, and should:** hold the seven logical names in
   an explicit, separate table (not merged into the glob map) and validate it at `configure()` time
   against the set commons requires, so an unbound name fails **at startup, naming the name**,
   instead of at first navigation to that route. That converts the scenario from "reported when hit"
   to "reported before it can be hit", and it is the concrete thing a registry buys over an alias.
   This is a recommendation, not something the current `LoaderRuntime` enforces.

One residual gap, recorded not solved: the sibling scenario at spec.md:59-62 wants the error to name
*"the identifier **and the location that was tried**"*. `LoaderRuntime`'s message names the id only.
The registry knows the three prefixes it globbed and could append them; nothing currently does.

---

## 10. SHAPE CONSTRAINTS THE REGISTRY MUST SATISFY

### 10.1 The glob must stay LAZY

`src/main/js/org/forgerock/openam/ui/admin/main.js` — **CONFIRMED**:

- **43 static `import` statements**, of which **28** are under `views/`;
- **imported by nothing.** Grepped all three trees for the id and for the path: zero references
  outside the file itself.

`{ eager: true }` would hoist all 43 into whatever chunk holds the registry — i.e. the initial
payload — and would do it with a green build and no warning, breaking
`ui-module-loading`'s *"Initial payload excludes unvisited views"* silently.

**It is not the only orphan.** Every `main.js` aggregator in AM except two is unreferenced:

| aggregator | static imports | imported by |
|---|---|---|
| `org/forgerock/openam/ui/admin/main.js` | 43 (28 views) | **nothing** |
| `org/forgerock/openam/ui/user/uma/main.js` | 19 | **nothing** |
| `org/forgerock/openam/ui/user/main.js` | 9 | **nothing** |
| `org/forgerock/openam/ui/user/dashboard/main.js` | 8 | **nothing** |
| `org/forgerock/openam/ui/common/main.js` | 4 | **nothing** |
| `org/forgerock/openam/ui/main.js` | 6 | `src/main/js/main.js:67` |
| `config/main.js` | 15 | `src/main/js/main.js:77` |
| commons `org/forgerock/commons/ui/common/main.js` | 12 | `src/main/js/main.js:66` |

So five orphan aggregators, together carrying ~83 static imports, are all in the glob's reach. Under
`eager` every one of them is dragged in. Under lazy they are inert unless something asks for their
id — and nothing in the 122-id corpus does.

### 10.2 Thunk or static import for the seven logical names? — **THUNK**

This is the one shape decision the apply run cannot derive, so it was measured. Two throwaway entries,
identical except for how the seven names are bound, both built through the real `vite.config.js`:

| | entry chunk | modules in entry | chunks | total bytes across all chunks |
|---|---|---|---|---|
| **static** — `import LoginView from "…/RESTLoginView"` ×7 | **1 015 415 B** | **191** | 2 | 1 366 936 |
| **thunk** — `() => import("…/RESTLoginView")` ×7 | **4 083 B** | **2** | 15 | 1 371 389 |

**Binding the seven names statically puts 1.01 MB — the login view, the login dialog, the profile
view, forgot-username, password-reset, self-registration and everything they reach — into the initial
chunk.** The thunk form puts 4 KB there and defers the rest into 13 named async chunks
(`RESTLoginView` 197 KB, `AbstractView` 697 KB shared, `UserProfileView` 20 KB, `Footer` 1.8 KB,
`RESTLoginDialog` 619 B, …). Total shipped bytes are the same to within 0.3% — the entire difference
is *when* they are shipped.

So: **yes, resolving a logical name through a static import has exactly the same payload consequence
as `eager: true` does for the glob**, and for the same reason. `resolve.alias` is not a way to bind
these names cheaply. Bind all seven as thunks in the registry.

(This is also why `UserProfileView` is a special case worth noting rather than copying: its alias is
a *live static import* from `SiteConfigurationService`, so it is eagerly in the payload today no
matter what the registry does. The other six have no static consumer and must not acquire one.)

### 10.3 `main-authorize.js` and `main-device.js` configure no loader — **CONFIRMED, and must stay that way**

Both entries import `configure` from `LoaderRuntime` and call it with **only** the two seams they
need:

```js
// src/main/js/main-authorize.js:99   and   src/main/js/main-device.js:69
configureLoader({ baseUrl: data.baseUrl, urlArgs: `v=${__TARGET_VERSION__}` });
```

No `resolveModule`. **Neither entry reaches `ModuleLoader.load`.** Confirmed two ways:

- from the source: neither file mentions `ModuleLoader`, and neither contains a dynamic `import(`;
- from `NOTES-entry-templates.md` §6.1, which traced both entries' full static graphs and states
  it plainly — *"**No `ModuleLoader`. No dynamic import.** No network call except the assets the
  `<link>` tags fetch"* — and §6.2, which classifies `resolveModule` as *"needed only by `loadModule`,
  i.e. only by `ModuleLoader`. **Not reached.** Group 6's job, and not on these pages' path."*

`baseUrl` on those two, by contrast, is **required** and fails silently without it
(`NOTES-entry-templates.md` §6.2: i18next's `resGetPath` goes document-relative, 404s, and the pages
render with untranslated keys). That is already done. **Adding `resolveModule` to these two entries
would pull the whole 361-module registry into two pages that need none of it.** Do not.

---

## 11. WHAT THE REGISTRY ITSELF COSTS

Measured by building the complete registry shape (three lazy globs + the 7 logical-name thunks +
the 2 library thunks + `LoaderRuntime.configure`) as a standalone entry through the real config:

| build | entry chunk | chunks emitted | total across all chunks |
|---|---|---|---|
| unminified | 129 008 B | 381 | 4 190 248 B |
| **minified (as the real build)** | **112 917 B** | **381** | 2 256 612 B |
| minified, `modulePreload: false` | 62 697 B | 381 | 2 205 494 B |

Two things to take from this:

- **the registry makes the whole application code-split: 381 chunks.** The baseline build emits 5.
  That is the point of D1 — everything is reachable and nothing is eager — but it is a large change
  in the shape of `target/compiled/assets/`, and any assertion elsewhere that counts files there
  will move.
- **~50 KB of the registry's 113 KB entry cost is Vite's `modulePreload` dependency manifests**, not
  the glob map itself. `modulePreload: false` halves it at the cost of a request waterfall on first
  navigation. Recorded as a lever, **not** a recommendation — it is a latency/bytes trade the apply
  run should make deliberately if the entry size matters.

---

## 12. HAND-OFFS AND TRAPS FOR THE APPLY RUN

### 12.1 The registry trips two deferrals that are already armed in `vite.config.js`

Both appear in today's baseline build as "did not fire, as declared" notices naming task 6.1. When
the registry lands they **fire**, and one of them **fails the build**. Both are expected; neither is
a bug in the registry.

1. **`xui-sloppy-mode-libraries` — hard failure.** Measured: building the registry entry aborts with

   > `[xui-sloppy-mode-libraries] these patches carry a 'requiredFrom' deferral and yet DID fire:`
   > `/libs[\\/]jsoneditor-0\.7\.23-custom\.js$/  (requiredFrom: 6.1)` ×2
   > *"The library is in the static module graph now, so the deferral is spent. Delete the
   > `requiredFrom` field from each entry above."*

   The AM glob reaches `src/main/js/libs/jsoneditor-0.7.23-custom.js`, so **the apply run must delete
   the two `requiredFrom: 6.1` fields** in that plugin's table — which is exactly what the message
   instructs, and which puts those patches back under the hard check.

2. **`xui-assert-aliased-libraries`** — today it reports `libs/codemirror → node_modules/codemirror`
   is in no chunk *"as declared … 6.1 (D1 runtime module registry — what makes EditScriptView
   statically reachable) closes this."* With the registry, `EditScriptView` becomes reachable
   (measured: a 339 KB `EditScriptView` chunk appears) and the deferral is spent. That plugin has a
   second branch for exactly this case; check which message it emits.

### 12.2 Should the AM glob exclude `libs/` and `shims/`?

It can — measured: `["/src/main/js/**/*.{js,jsx,jsm}", "!/src/main/js/libs/**", "!/src/main/js/shims/**"]`
returns **256** instead of 281, and negation does not disturb the common base (negated patterns are
excluded from `getCommonBase`). **No id in the 122-id corpus lives under `libs/` or `shims/`**, and
`vite.config.js`'s own `LITERAL_PATH_LIBRARY_CONSUMERS` is empty with the build reporting
*"0 of them named by literal AMD path"*, so excluding them loses nothing the application asks for.

Doing so would also sidestep §12.1's jsoneditor failure — **but by accident, not by design.**
`jsoneditor` genuinely is needed by `EditScriptView`, which reaches it through the module graph
rather than through the registry. Excluding `libs/` from the glob does not stop that; it only stops
the registry being the thing that first pulls it in. Prefer deleting the spent `requiredFrom` fields
as the plugin instructs, and treat the exclusion as a separate, optional tidy.

### 12.3 Do not use the array form. Do not use `exhaustive`. Do not use the alias form.

Restating §3.4 and §3.2 because each of the three fails *quietly*:

- the **array** form loses both node_modules trees (281 instead of 361) with no error;
- the **alias-prefixed** form loses the seven `config/**` package modules — including
  `config/routes/CommonRoutesConfig`, `config/routes/UserRoutesConfig` and `config/process/CommonConfig`,
  which are the very files that name the seven logical names — with no error;
- **`exhaustive: true`** would paper over the first while turning on dotfile matching.

### 12.4 Merge order and collisions

Verified: no id appears in more than one tree, and no `.js`/`.jsx`/`.jsm` pair normalises to the same
id within a tree. So the three maps can be merged in any order. **The logical-name table must be
consulted before the glob map anyway** (§9.3), and none of the seven names collides with a glob id —
but note the glob does produce the bare ids `main`, `main-authorize`, `main-device` and
`config/main`, so a future logical name must not be called any of those.

### 12.5 A second resolution mechanism still exists

`SiteConfigurationService.js:38`'s bare `require([...])` (§8.1) is the only remaining
resolve-by-string path that does not go through `ModuleLoader` / `LoaderRuntime`. It is currently
dead behind a `typeof require === "function"` guard. 6.1 owns replacing it. Everything else that
looked like a second mechanism is a literal-string dynamic import a bundler traces on its own —
commons `main/ViewManager.js:60`'s `import("…/ReactAdapterView")`, which goes through
`LoaderRuntime.unwrapModule` but needs no resolver.

### 12.6 `unwrapModule` is already correct for `import.meta.glob`

`LoaderRuntime.isNamespace` tests **both** `__esModule` and `Symbol.toStringTag === "Module"`, and
its comment records why: *"a **native** ES module namespace, which is what `import()` and
`import.meta.glob` hand back, does not carry `__esModule`"*. The registry needs to do nothing here —
it must return the module record (or the thunk's promise of one) and let `loadModule` unwrap it.
Returning `m.default` from the registry itself would double-unwrap.

---

## 13. NOT DETERMINED

1. **Whether the registry's own `import.meta.glob` in `src/main/js` produces `./`-prefixed keys.**
   Not measured, because this survey was forbidden from writing into `src/main/js`. The key *rule*
   was measured from two other directories (§5) and read out of the engine source (§2.4), and it is
   unambiguous — but §3.1 recommends the root-absolute form precisely so that this never has to be
   relied on: those keys are importer-independent and were measured directly.
2. **Whether 381 output chunks breaks anything downstream** — the zip contract, the `.ftl` pages, or
   `PHASE1-TREE.md`'s per-file oracle. Out of scope here; `NOTES-zip-contract.md` and
   `NOTES-vite-entrypoints.md` are the places to check before the apply run commits to it.
3. **Whether the `?v=<version>` cache-busting applies to registry-loaded chunks.** `LoaderRuntime.toUrl`
   handles `urlArgs` for templates and locales, but Vite's own chunk URLs are content-hashed and do
   not pass through it. Probably fine (hash *is* the cache key), not verified.

---

## 14. FALLBACK — RESOLVING AN IDENTIFIER THE BUILD NEVER SAW (TASK 6.3 SPIKE)

Spike run 2026-08-31 against the tree as it stands after 6.1/6.1a and 6.2. Everything below was
measured; nothing was reasoned from the docs. The scratch entry (`src/main/js/spike63.js`) and the
files dropped into `target/compiled/` were deleted afterwards — `git status` is back to the two
untracked `NOTES-*.md` it started with, and `npm run build:production` exits 0 at **1523 modules
transformed** with `target/compiled/main.js` = 982 B (the 6.1a stub).

**Harness.** `node local/server.mjs ../openam-ui/openam-ui-ria/target/compiled` from `OpenAM/e2e`,
answering on `http://localhost:8090/openam/XUI/`; Playwright 1.60.0 (`@playwright/test`, already an
e2e devDependency), headless chromium. The probe module was loaded into the live page as
`<script type="module">` importing the spike's own emitted chunk, so **every dynamic import below
runs from inside a bundled chunk under `assets/`, which is where a real fallback would run** — not
from `page.evaluate`'s document context, which resolves against a different base and would have
given the wrong answer to §14.2.

### 14.1 A RUNTIME-COMPUTED `import()` SURVIVES THE BUILD UNTOUCHED, AND `@vite-ignore` DOES NOT

The smallest module, dropped at `src/main/js/spike63.js` — it needs no entry-point wiring, because
6.1's AM glob `/src/main/js/**/*.{js,jsx,jsm}` reaches it and rollup gives it its own chunk:

```js
export const withIgnore    = (url) => import(/* @vite-ignore */ url);
export const withoutIgnore = (url) => import(url);
export const moduleUrl     = import.meta.url;
```

**The emitted chunk, `target/compiled/assets/spike63-D_G3gzjw.js` (0.51 kB), verbatim:**

```js
const o=e=>import(e),r=e=>import(e),n=import.meta.url,…export{n as moduleUrl,…,o as withIgnore,r as withoutIgnore};
```

Read the first fourteen characters twice. `o` (with the comment) and `r` (without it) are **byte-for-byte
the same function**. The `/* @vite-ignore */` comment **does not survive** — esbuild's minify pass
strips it — and its absence changes nothing, because nothing in the *build* pipeline was ever going
to act on `import(e)` where `e` is a plain identifier.

- **No warning, either form.** The build log's warning set is *byte-identical* to the pre-spike
  baseline: **55 `(!)` lines in both**, same subjects (all of them 6.1's pre-existing
  "dynamically imported by moduleRegistry.js but also statically imported by …" notices). Zero
  occurrences of `not be analyzed`, `string literal`, `@vite-ignore` or `spike63` anywhere in the
  log except the one size-report line. Exit 0.
- **Rollup bundles nothing for it.** The chunk's only static imports are the ones the spike itself
  wrote; the dynamic specifier contributes no module to the graph and no chunk to the output.
- **A function call as the specifier is equally untouched.** The larger spike compiled
  `import(/* @vite-ignore */ derive(id))` to `import(r(t))`.
- **`import.meta.url` survives as `import.meta.url`** in the ES-format chunk, so it evaluates to the
  chunk's own URL at runtime. §14.2 uses that.

**Position for 6.3: keep the `/* @vite-ignore */` comment anyway.** It costs nothing, it states the
intent at the one line where a reader will ask, and *this spike did not measure the dev server*
(`vite serve`), where `vite:import-analysis` does warn on an unanalysable dynamic import. What is
established is only that the **production build** neither warns nor rewrites with or without it.

### 14.2 WHAT THE URL RESOLVES AGAINST — MEASURED, NOT ASSUMED

Served page: `http://localhost:8090/openam/XUI/`, which the app immediately turns into
`…/XUI/#login/`. The probe chunk reported its own location as

```
http://localhost:8090/openam/XUI/assets/spike63-D_G3gzjw.js
```

Seven candidate forms for the identifier `config/E2EStandInLoginHelper`, all imported **from that
chunk**:

| form | what the browser did |
|---|---|
| `config/E2EStandInLoginHelper.js` (bare) | ✗ `TypeError: Failed to resolve module specifier 'config/E2EStandInLoginHelper.js'` |
| `config/E2EStandInLoginHelper.js?v=dev` (what `LoaderRuntime.toUrl` returns today) | ✗ same `TypeError` |
| `./config/E2EStandInLoginHelper.js` | ✗ `TypeError: Failed to fetch dynamically imported module: http://localhost:8090/openam/XUI/`**`assets/`**`config/E2EStandInLoginHelper.js` |
| `../config/E2EStandInLoginHelper.js` | ✓ fetched from the tree root |
| `new URL(id + ".js", document.baseURI).href` | ✓ fetched from the tree root |
| `new URL(id + ".js?v=dev", document.baseURI).href` | ✓ fetched from the tree root |
| `new URL("../" + id + ".js", import.meta.url).href` | ✓ fetched from the tree root |

Three facts follow, and the first two are the ones that would have been got wrong by reasoning:

1. **A bare specifier is not a URL and never resolves.** `import()` applies module-specifier rules,
   not URL rules: anything not starting with `/`, `./` or `../` (or a scheme) needs an import map,
   and **the served page has none** (measured: `document.querySelector('script[type="importmap"]')`
   is null; the only `<script src>` on the page is `main.js?v=dev`). So the naive
   `import(LoaderRuntime.toUrl(id + ".js"))` — the one-liner that looks obviously right, since
   `toUrl` is exactly the `require.toUrl` this build replaced — **fails on every id**, including
   ones whose file is present.
2. **A `./`-relative specifier resolves against the importing CHUNK, i.e. `/XUI/assets/`,** not
   against the deployed tree root. That is the whole difference the task warns about, and it is why
   the correct answer cannot be a relative string.
3. **`document.baseURI` is the deployed tree root, context path included, and is fragment-proof.**
   Measured at three different document URLs:

   | document URL | `document.baseURI` | derived |
   |---|---|---|
   | `…/openam/XUI/` | `…/openam/XUI/#login/` | `http://localhost:8090/openam/XUI/config/E2EStandInLoginHelper.js` |
   | `…/openam/XUI/index.html#login/` | `…/openam/XUI/index.html#login/` | *same* |
   | `…/openam/XUI/#realms/%2F/dashboard` | `…/openam/XUI/#login/` | *same* |

   No `<base>` tag is emitted, so `baseURI` is the document URL; `new URL()` discards the base's
   fragment and the `index.html` filename alike. This is the same origin RequireJS used — its
   `baseUrl` was inferred from the document — which is why §"THE PATH CONVENTION TASK 6.3 NEEDS
   SURVIVES THIS" in `vite.config.js` is confirmed rather than merely preserved.

**`import.meta.url` + `"../"` also works today and is the worse anchor.** It is correct only while
every chunk sits exactly one directory below the tree root; it is a property of
`chunkFileNames`/`assetFileNames`, not of the deployment, and it would break silently the day a
chunk is emitted at a different depth. `document.baseURI` is a property of the deployment.

### 14.3 THE EXACT DERIVED URL

**Recommended derivation, measured working in the live page:**

```js
import { toUrl } from "org/forgerock/commons/ui/common/util/esm/LoaderRuntime";

const fallbackUrl = (id) => new URL(toUrl(`${id}.js`), document.baseURI).href;
```

Measured outputs on the served build (`__TARGET_VERSION__` unset, so the version stamp is `dev`):

| id | derived url |
|---|---|
| `config/E2EStandInLoginHelper` | `http://localhost:8090/openam/XUI/config/E2EStandInLoginHelper.js?v=dev` |
| `org/forgerock/commons/ui/common/main/Configuration` | `http://localhost:8090/openam/XUI/org/forgerock/commons/ui/common/main/Configuration.js?v=dev` |

So: **prefix** = the directory `index.html` is served from, context path and all, taken from
`document.baseURI`; **extension** = `.js`, always and unconditionally (no `.jsm`/`.jsx` probing — an
operator drops a browser-loadable file, and the convention `org/forgerock/…/Foo` → `Foo.js` is what
1.11 and RequireJS's `nameToUrl` both used); **query** = `?v=<version>`, see §14.4.

**Why compose `toUrl` rather than hand-rolling the string.** `toUrl` already owns the two things that
vary — `baseUrl` and `urlArgs` — and `new URL(…, document.baseURI)` only supplies the origin that
`import()` needs and `toUrl` deliberately does not. That makes one derivation correct on all three
entry points: `main.js` leaves `baseUrl` at `""` (measured: the derived url is document-relative and
right), while `main-authorize.js:99` and `main-device.js:69` inject
`configureLoader({ baseUrl: data.baseUrl })` where `data.baseUrl` is already `"<serverBase>/XUI"` —
and those two pages are served from `/oauth2/…`, where `document.baseURI` is **not** the XUI root.
Measured with `baseUrl` flipped to `"http://localhost:8090/openam/XUI"`: the derived url is
unchanged and correct. (Neither secondary configures `resolveModule` today, so the fallback is not
reachable there — but writing the derivation this way means it is not *wrong* there either, which a
bare `document.baseURI` version would have been.)

### 14.4 SHOULD THE FALLBACK URL CARRY THE VERSION? — POSITION: YES

**Recommendation: yes, `?v=${__TARGET_VERSION__}`, i.e. exactly what `toUrl` already appends. This
is the change owner's call; here is both sides and the measurement that settles the tie.**

The requirement reads two ways because the operator's module has two properties at once, and
`ui-build-and-packaging`'s *Cache invalidation for runtime-fetched assets* only names the first:
*"Assets fetched by path at runtime SHALL carry the build version in the URL used to fetch them."*

- **For.** It *is* fetched by path at runtime, which is the requirement's literal subject. It sits
  under `/XUI/*`, which `openam-server-only/src/main/webapp/WEB-INF/web.xml:226-228` maps to
  `CacheForAMonth` → `public, max-age=2592000`, with excludes for only `/XUI/`, `/XUI/index.html`
  and the two RequireJS stubs (`:97`). An operator's module therefore gets a **30-day browser cache
  at a URL that never changes**. The failure this prevents is concrete: an AM upgrade replaces the
  webapp, the operator re-drops their updated module at the same path, and a returning browser
  serves the month-old copy. With the version on the url, the upgrade changes the key and the
  refetch happens.
- **Against.** The version is the *product's*, and the operator's module is not a build artifact —
  editing it within one deployed version does not change the url, so the query buys no invalidation
  for the change most likely to happen. That is true, and it is an argument that the version is
  *insufficient*, not that it is *wrong*: without it the same edit is equally uncached, and the
  upgrade case above additionally breaks. The version strictly dominates.
- **The one real cost, measured.** A file imported at two different urls is **two module records and
  two evaluations** — the 6.1a hazard, reproduced here directly: a module that increments a counter
  at top level was imported as `…/config/SpikeCount.js` and then as `…/config/SpikeCount.js?v=dev`,
  and `window.__spikeEvalCount` came back **2**. Its own `import.meta.url` carried the query. So the
  rule is *consistency*, not *absence*: the fallback must use one derivation for every id, and an
  operator who ships two files must be told that a sibling `import("./Other.js")` from inside their
  own module resolves **without** the query (measured: `import.meta.url` is
  `…/config/SpikeCount.js?v=dev`, so a sibling relative import inherits the directory but not the
  query) and would therefore double-evaluate a module the fallback also loads. That belongs in 6.6's
  operator documentation.

### 14.5 FORMAT: ESM. AMD IS FETCHED, PARSED, AND THEN THROWS

Both forms were dropped into the served tree at the path their identifier implies
(`target/compiled/config/E2EStandInLoginHelper.js`, id `config/E2EStandInLoginHelper` — the same id
task 1.11's fixture declares for itself) and imported through the derived url.

| dropped file | result |
|---|---|
| `fixtures/E2EStandInLoginHelper.js` **verbatim (AMD)** | ✗ `ReferenceError: define is not defined` |
| an ESM module whose first line is `import … from "org/forgerock/openam/ui/user/login/RESTLoginHelper"` | ✗ `TypeError: Failed to resolve module specifier "org/forgerock/openam/ui/user/login/RESTLoginHelper". Relative references must start with either "/", "./", or "../".` |
| a self-contained ESM module | ✓ namespace with `Symbol.toStringTag === "Module"` and a `default`; `LoaderRuntime.unwrapModule` returns the default; the module's `window` marker was written |

Three things worth keeping from that:

- **`ReferenceError`, not `SyntaxError`.** `define([…], function (…) {…})` is valid ES-module syntax,
  so the AMD fixture is fetched and *parsed* successfully and dies at evaluation on the missing
  global. The failure is therefore indistinguishable, from the outside, from any other bug in the
  operator's module — it does not say "this file is AMD", and it names neither the url nor the id.
- **An operator's ESM module cannot reach a shipped module by its AMD id.** Bare specifiers need an
  import map and the page has none. Measured what the page *does* expose: comparing
  `Object.getOwnPropertyNames(window)` against a pristine same-origin iframe, the XUI's own additions
  are exactly **`$`, `jQuery`** and jQuery's internal expando — **no module-resolution global at
  all**. So 1.11's "delegate to the shipped `RESTLoginHelper`" design has *no channel* under D1 as it
  stands. See §14.8; this is 6.6's to settle, not 6.3's to invent.
- The ESM module's own `import.meta.url` is its served url, so **relative imports between two
  operator-supplied files work** (`./Other.js` resolves inside `/XUI/config/`).

**The working ESM stand-in, verbatim — 6.6 starts from this.** It is deliberately *not* a port of
1.11's fixture: the delegation half is the part that has no channel, so what is proved working here
is the format, the marker and the three-formal-parameter arity constraint that `_.curry` imposes
(`SessionManager` takes the arity from `fn.length`; rest args make it 0 and login hangs silently —
1.11's note applies unchanged).

```js
const marker = window.__spikeEsmPlain = {
    loaded: true,
    moduleId: "config/SpikeEsmPlain",
    calls: []
};

export default {
    login (params, successCallback, errorCallback) { marker.calls.push("login"); },
    logout (successCallback, errorCallback) { marker.calls.push("logout"); },
    getLoggedUser (successCallback, errorCallback) { marker.calls.push("getLoggedUser"); }
};
```

A second file at `org/forgerock/openam/ui/spike/DeepEsm.js`, identifier
`org/forgerock/openam/ui/spike/DeepEsm`, resolved identically — **the path convention holds at full
depth**, not only for the shallow `config/` case.

### 14.6 WHAT A MISS LOOKS LIKE

Importing the derived url of a file that is not there, with the local server answering
`404 Not Found` / `Content-Type: text/plain` / `Cache-Control: no-store`:

```
TypeError: Failed to fetch dynamically imported module: http://localhost:8090/openam/XUI/config/ThisFileIsNotThere.js
```

- **Type:** `TypeError` (`error instanceof Error` true, `error.constructor.name === "TypeError"`).
- **Catchable:** yes, as an ordinary promise rejection — `await` inside `try/catch` caught it every
  time, and it is a rejection rather than a synchronous throw, so it composes with
  `LoaderRuntime.loadModule`'s existing promise chain with no special handling.
- **Names the url:** yes, in full and absolute. It does **not** name the identifier as such — though
  by construction the identifier is a substring of the url (`…/no/such/Module.js?v=dev` for the id
  `no/such/Module`). It carries no HTTP status, no `cause`, and nothing that distinguishes 404 from
  a network failure or a CORS refusal.
- **Stable on repeat:** a second import of the same missing url produced the identical `TypeError`;
  the browser does not degrade or cache a miss into a different error.
- A **500 or a 200 serving HTML** would be different shapes (a non-JS content type yields the same
  `Failed to fetch…` form; a JS-typed body that does not parse yields a `SyntaxError` naming a line).
  Not measured — the local server only ever answered 404 or 200.

### 14.7 WHERE THE FALLBACK SITS, AND WHETHER THE TWO MISSES CAN BE TOLD APART

`moduleRegistry.js` ends in

```js
export const resolveModule = (id) =>
    (logicalNames[id] || modules[id] || libraries[id] || (() => undefined))();
```

**The fallback replaces the trailing `(() => undefined)` and nothing else.** That placement is what
makes both halves of the requirement hold, and both halves were measured on the live page by
installing a 6.3-shaped resolver through `LoaderRuntime.configure` and re-running `loadModule`:

```js
configure({ resolveModule: (id) => {
    const hit = resolveModule(id);
    return hit === undefined ? import(/* @vite-ignore */ fallbackUrl(id)) : hit;
} });
```

| id | table | with the fallback installed |
|---|---|---|
| `org/forgerock/commons/ui/common/main/Configuration` | glob | ✓ resolved from the registry — **not** from `…/XUI/org/…/Configuration.js`, which does not exist in the deployed tree, so a fallback that had fired would have 404'd |
| `LoginView` | logical name | ✓ resolved from the registry (same argument: `…/XUI/LoginView.js` does not exist) |
| `bootstrap` | library | ✓ (`resolveModule` returns non-undefined before the fallback) |
| `constructor` | none — the tables are null-prototype | falls through to the fallback, as it must |
| `config/SpikeEsmPlain` | none | ✓ loaded from `/XUI/config/SpikeEsmPlain.js?v=dev` |
| `no/such/Module` | none | ✗ `TypeError: Failed to fetch dynamically imported module: …/no/such/Module.js?v=dev` |

A registered id therefore **never** reaches the fallback (the three tables are consulted first, in
order, and §12.4 already establishes there are no collisions), and an unregistered id **always**
does. The null-prototype tables are load-bearing here for a second reason beyond 6.1's: with plain
`{}`, `constructor` / `toString` / `valueOf` would resolve to an inherited member and never reach the
fallback either.

**Can the two be told apart from outside? Partly — and the part that is lost matters to 6.4.**

- **What is lost, and it is the important one.** With the fallback installed, `resolveModule` can no
  longer return nullish for *any* id, so **`LoaderRuntime.loadModule`'s named error becomes
  unreachable**. Measured, before installing the fallback:
  `Error: [LoaderRuntime] The configured resolveModule returned nothing for "config/SpikeEsmPlain". …`
  — an `Error` that names the identifier, which is what `ui-module-loading`'s *Unresolvable
  identifier fails observably* ("fails with an error naming the unresolved identifier") is currently
  satisfied by. After installing it, the same id fails as an anonymous `TypeError` about a url.
  **6.4 must re-supply the identifier**: catch the rejection inside the fallback and rethrow naming
  both the id and the derived url. Do not rely on the id being a substring of the url.
- **What can still be told apart, by url shape.** A registry hit whose chunk fails to load also
  rejects with `Failed to fetch dynamically imported module:` — but at
  `…/XUI/assets/<Name>-<8-char-hash>.js`, whereas a fallback miss is always at the identifier's own
  path below the tree root with no hash. So the discriminator is the **url**, not the error type;
  both are `TypeError` with the same message prefix. An operator module that loads and then throws
  (the AMD case, §14.5) is a third shape again — whatever error the module itself threw, with no url
  and no id anywhere.

### 14.8 NOT DETERMINED

1. **How an operator's ESM module reaches a shipped module.** Measured that it cannot today: no
   import map, no module-resolution global (only `$`/`jQuery`), and no stable ESM export surface in
   the emitted tree — `main.js` is the 982 B stub and exports nothing, and every real chunk name
   carries a content hash. Task 1.11's fixture is built entirely on delegating to
   `RESTLoginHelper`, so **6.6 cannot be a straight AMD→ESM transcription of it**. The candidate
   channels (a documented global exposing `ModuleLoader.load`; an import map stamped into
   `index.html`; a self-contained fixture that drops the delegation) each change something outside
   6.3's scope and none was chosen here.
2. **Dev-server behaviour (`vite serve`).** Not measured. `@vite-ignore` may well matter there even
   though it provably does not in the production build; §14.1's finding is scoped to `vite build`.
3. **Non-404 miss shapes** (500, or a 200 with a non-JS body) — §14.6.
4. **Whether the fallback should probe `.jsm`/`.jsx`.** Not measured and, in this spike's view, not
   wanted: `.js` unconditionally is what the deployed layout's convention says. Flagged only because
   6.1 found ten *registry* ids that carry `.jsm`, and someone may reasonably ask.
