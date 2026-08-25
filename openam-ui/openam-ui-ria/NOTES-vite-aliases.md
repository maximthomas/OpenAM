# NOTES-vite-aliases.md — the `require.config.map` bindings, their consumers, and what `resolve.alias` can and cannot carry

Source survey for task **4.3** ("Translate the 12 `require.config.map` bindings in `main.js:19-34`
into `resolve.alias` entries, including `underscore` → `lodash` (D2)").

Read-only. No build was run, no source file was edited, no Maven goal was invoked.

**Paths in this file.** The three source trees named by the survey brief are, on disk:

| short name used below | absolute path |
|---|---|
| **AM** | `/home/maxim/Documents/_projects/forgerock/OpenAM/openam-ui/openam-ui-ria/src/main/js` |
| **COMMONS** | `/home/maxim/Documents/_projects/forgerock/commons/ui/commons/src/main/js` |
| **USER** | `/home/maxim/Documents/_projects/forgerock/commons/ui/user/src/main/js` |

The OpenSpec workspace (`openspec-commons/`) and the two product checkouts (`OpenAM/`, `commons/`)
are **siblings** under `/home/maxim/Documents/_projects/forgerock/`, not nested. The brief's paths
are relative to that shared parent, not to the OpenSpec repo root.

---

## 0. The starting hypothesis, checked

| claim | verdict | evidence |
|---|---|---|
| `main.js` declares 12 `map` entries | **TRUE** | `main.js:21-33`, 12 keys under a single `"*"` scope opened at `main.js:20` |
| `main-authorize.js` and `main-device.js` each declare 3 | **TRUE** | `main-authorize.js:30-33`, `main-device.js:21-24` |
| In both secondaries, `Router` → `org/forgerock/openam/ui/common/SingleRouteRouter` | **TRUE** | `main-authorize.js:31`, `main-device.js:22` |
| In `main.js`, `Router` → `org/forgerock/commons/ui/common/main/Router` | **TRUE** | `main.js:29` |
| `ThemeManager.js` declares `Router` as an AMD dependency and is loaded by all three entries | **TRUE**, with one nuance | `ThemeManager.js:25` declares it; `:168` reads `Router.currentRoute.navGroup`. The two secondaries load `ThemeManager` **directly** (`main-authorize.js:65`, `main-device.js:60`); `main.js` reaches it **transitively** — `main.js:198` requires `org/forgerock/commons/ui/common/main`, whose `define` array (COMMONS `org/forgerock/commons/ui/common/main.js:22`) pulls `./main/AbstractView`, and `AbstractView.js:26` declares `"ThemeManager"`. `UIUtils.js:24` is a second route to the same place. |

Nothing in the hypothesis is wrong. Two things it does not say, both load-bearing:

- The `map` block in all three entries is scoped `"*"` only. There are **no per-module `map`
  entries** anywhere, so nothing depends on RequireJS's per-referrer resolution *within* one entry.
  The only per-referrer behaviour that matters is *between* entries — section 3.
- `main.js` also declares **38** `paths` entries (`main.js:37-78`), not ~35, and **26** `shim`
  entries (`main.js:80-172`). See section 6.

---

## 1. THE FULL TABLE — every `map` entry in each entry point

`map."*"` in all three. `file:line` is the line of the binding itself.

| # | mapped name | `main.js` | `main-authorize.js` | `main-device.js` | agree? |
|---|---|---|---|---|---|
| 1 | `Footer` | `org/forgerock/openam/ui/common/components/Footer`<br>`main.js:21` | — | — | **main only** |
| 2 | `ThemeManager` | `org/forgerock/openam/ui/common/util/ThemeManager`<br>`main.js:22` | `org/forgerock/openam/ui/common/util/ThemeManager`<br>`main-authorize.js:30` | `org/forgerock/openam/ui/common/util/ThemeManager`<br>`main-device.js:21` | all three, identical |
| 3 | `LoginView` | `org/forgerock/openam/ui/user/login/RESTLoginView`<br>`main.js:23` | — | — | **main only** |
| 4 | `UserProfileView` | `org/forgerock/commons/ui/user/profile/UserProfileView`<br>`main.js:24` | — | — | **main only** |
| 5 | `ForgotUsernameView` | `org/forgerock/openam/ui/user/anonymousProcess/ForgotUsernameView`<br>`main.js:25` | — | — | **main only** |
| 6 | `PasswordResetView` | `org/forgerock/openam/ui/user/anonymousProcess/PasswordResetView`<br>`main.js:26` | — | — | **main only** |
| 7 | `LoginDialog` | `org/forgerock/openam/ui/user/login/RESTLoginDialog`<br>`main.js:27` | — | — | **main only** |
| 8 | `NavigationFilter` | `org/forgerock/openam/ui/common/components/navigation/filters/RouteNavGroupFilter`<br>`main.js:28` | — | — | **main only** |
| 9 | **`Router`** | `org/forgerock/commons/ui/common/main/Router`<br>`main.js:29` | **`org/forgerock/openam/ui/common/SingleRouteRouter`**<br>`main-authorize.js:31` | **`org/forgerock/openam/ui/common/SingleRouteRouter`**<br>`main-device.js:22` | ⚠️ **DISAGREE — the only one** |
| 10 | `RegisterView` | `org/forgerock/openam/ui/user/anonymousProcess/SelfRegistrationView`<br>`main.js:30` | — | — | **main only** |
| 11 | `KBADelegate` | `org/forgerock/openam/ui/user/services/KBADelegate`<br>`main.js:31` | — | — | **main only** |
| 12 | `underscore` | `lodash`<br>`main.js:33` | `lodash`<br>`main-authorize.js:33` | `lodash`<br>`main-device.js:24` | all three, identical |

**Counts: 12 / 3 / 3.** Union of distinct names = 12. Declared by all three = 2 (`ThemeManager`,
`underscore`). Declared by `main.js` only = 9. Declared by all three but **disagreeing** = 1
(`Router`).

### Every target resolves to a real file

Checked file-by-file against AM, COMMONS, USER and the two installed npm packages
(`openam-ui-ria/node_modules/@openidentityplatform/ui-{commons,user}`). No dangling target.

| target | owning tree |
|---|---|
| `org/forgerock/openam/ui/common/components/Footer` | AM |
| `org/forgerock/openam/ui/common/util/ThemeManager` | AM |
| `org/forgerock/openam/ui/user/login/RESTLoginView` | AM |
| `org/forgerock/commons/ui/user/profile/UserProfileView` | **USER** (also `ui-user/amd/` + `ui-user/esm/`) |
| `org/forgerock/openam/ui/user/anonymousProcess/ForgotUsernameView` | AM |
| `org/forgerock/openam/ui/user/anonymousProcess/PasswordResetView` | AM |
| `org/forgerock/openam/ui/user/login/RESTLoginDialog` | AM |
| `org/forgerock/openam/ui/common/components/navigation/filters/RouteNavGroupFilter` | AM |
| `org/forgerock/commons/ui/common/main/Router` | **COMMONS** (also `ui-commons/amd/` + `ui-commons/esm/`) |
| `org/forgerock/openam/ui/user/anonymousProcess/SelfRegistrationView` | AM |
| `org/forgerock/openam/ui/user/services/KBADelegate` | AM |
| `org/forgerock/openam/ui/common/SingleRouteRouter` | AM (`SingleRouteRouter.js`, 22 lines, body is `define({ currentRoute: null })`) |
| `lodash` | **nowhere in source** — a `paths` entry, `main.js:62` → `libs/lodash-3.10.1-min`, and that file exists only under `target/` (section 5) |

Ten of the twelve targets are AM's own modules. Two point into the commons packages
(`UserProfileView`, `Router`) — those two are the ones D19's prefix alias also has to reach
(section 4).

---

## 2. THE CONSUMERS, PER NAME — with `file:line` for every use

Classification, per the brief:

- **(a) AMD dependency** — a bare name inside `define([...])` or `require([...])`. **This is what
  becomes a `resolve.alias` entry.**
- **(b) string identifier in configuration** — a route's `view:`/`dialog:`, or a member of a
  ProcessConfiguration `dependencies` array. Resolved at RUNTIME through `ModuleLoader.load` →
  `require([libPath])` (COMMONS `org/forgerock/commons/ui/common/util/ModuleLoader.js:22-26`, reached
  from `ProcessConfiguration.js:44-45`). **`resolve.alias` never sees these.** They belong to
  task 6.1's registry.
- **(c)** one case is neither: a string *equality comparison* against a logical name. Called out
  because it survives neither mechanism.

Sweep basis: all 259 AM files (`.js`/`.jsm`/`.jsx`, including the 4 vendored files under
`src/main/js/libs/`), all 65 COMMONS files, all 14 USER files.

### `Footer` — (b) only

| use | class | file:line |
|---|---|---|
| declaration | — | AM `main.js:21` |
| `dependencies` array, `EVENT_THEME_CHANGED` handler | **(b)** | AM `config/process/AMConfig.js:196` |
| `dependencies` array, `EVENT_CHANGE_BASE_VIEW` handler | **(b)** | COMMONS `config/process/CommonConfig.js:73` |

No `define([...])`/`require([...])` reference anywhere. An alias for `Footer` is a **no-op** for
the bundler.

### `ThemeManager` — (a) only

| use | class | file:line |
|---|---|---|
| declarations | — | AM `main.js:22`, `main-authorize.js:30`, `main-device.js:21` |
| entry `require([...])` array | **(a)** | AM `main-authorize.js:65` |
| entry `require([...])` array | **(a)** | AM `main-device.js:60` |
| `define([...])` dep #9 | **(a)** | COMMONS `org/forgerock/commons/ui/common/main/AbstractView.js:26` |
| `define([...])` dep #6 | **(a)** | COMMONS `org/forgerock/commons/ui/common/util/UIUtils.js:24` |

Call sites of the resolved module (not alias sites, listed for section 3): COMMONS
`AbstractView.js:104`, `UIUtils.js:107`, `UIUtils.js:137`, `UIUtils.js:179`, AM
`main-authorize.js:130`, `main-device.js:80` — all `ThemeManager.getTheme()`.

### `LoginView` — (b) and (c), never (a)

| use | class | file:line |
|---|---|---|
| declaration | — | AM `main.js:23` |
| route `view:` | **(b)** | COMMONS `config/routes/CommonRoutesConfig.js:40` |
| `ViewManager.currentView === "LoginView"` | **(c)** | AM `org/forgerock/openam/ui/user/login/RESTLoginHelper.js:61` |

The (c) case is a trap and is recorded here because nothing else will see it.
`ViewManager.currentView` holds the **unresolved** route identifier — it is assigned the raw
`viewPath` at COMMONS `ViewManager.js:95` and the raw `route.view` at COMMONS
`config/process/CommonConfig.js:327`. So `RESTLoginHelper.js:61` compares against the literal
string `"LoginView"` that `CommonRoutesConfig.js:40` put there. If task 6.1 (or anyone) rewrites
route configs to name real module paths, this comparison becomes permanently false and the
re-render branch is dead — silently. No alias and no registry entry protects it.

### `UserProfileView` — **(a) and (b)**

| use | class | file:line |
|---|---|---|
| declaration | — | AM `main.js:24` |
| `define([...])` dep #7 | **(a)** | AM `org/forgerock/openam/ui/common/services/SiteConfigurationService.js:25` |
| route `view:` | **(b)** | USER `config/routes/UserRoutesConfig.js:24` |

The only name in the twelve that is reached both ways. `SiteConfigurationService.js:33` calls
`UserProfileView.registerTab(tab)` on the resolved module, so the (a) route is live, not vestigial.

### `ForgotUsernameView` — (b) only

| use | class | file:line |
|---|---|---|
| declaration | — | AM `main.js:25` |
| route `view:` | **(b)** | USER `config/routes/UserRoutesConfig.js:32` |

### `PasswordResetView` — (b) only

| use | class | file:line |
|---|---|---|
| declaration | — | AM `main.js:26` |
| route `view:` | **(b)** | USER `config/routes/UserRoutesConfig.js:39` |

### `LoginDialog` — (b) only

| use | class | file:line |
|---|---|---|
| declaration | — | AM `main.js:27` |
| route `dialog:` | **(b)** | COMMONS `config/routes/CommonRoutesConfig.js:51` |
| `dependencies` array, `EVENT_SHOW_LOGIN_DIALOG` handler | **(b)** | COMMONS `config/process/CommonConfig.js:420` |
| `dependencies` array, `EVENT_SHOW_LOGIN_DIALOG` **override** handler | **(b)** | AM `config/process/AMConfig.js:275` |

### `NavigationFilter` — (a) only

| use | class | file:line |
|---|---|---|
| declaration | — | AM `main.js:28` |
| `define([...])` dep #10 | **(a)** | COMMONS `org/forgerock/commons/ui/common/components/Navigation.js:27` |

### `Router` — (a) only, and it is the conflict

| use | class | file:line |
|---|---|---|
| declarations | — | AM `main.js:29`, `main-authorize.js:31`, `main-device.js:22` |
| entry `require([...])` array | **(a)** | AM `main-authorize.js:66` |
| entry `require([...])` array | **(a)** | AM `main-device.js:61` |
| `define([...])` dep #8 | **(a)** | AM `org/forgerock/openam/ui/common/util/ThemeManager.js:25` |

**Exactly one non-entry consumer: `ThemeManager.js:25`.** Everything else in all three trees
imports the commons router by its **full path**, `"org/forgerock/commons/ui/common/main/Router"` —
49 such imports in AM alone, plus COMMONS `components/Navigation.js`, `components/hoc/withRouter.js`,
`util/UIUtils.js`, `main/AbstractView.js`, and USER `anonymousProcess/AnonymousProcessView.js`.
Those are untouched by any `Router` alias and must stay that way.

Reads and writes of `currentRoute` on the resolved module, which is what the conflict turns on:

| site | operation | file:line |
|---|---|---|
| assign `{navGroup:"user"}` on the **aliased** `Router` | write | AM `main-authorize.js:126` |
| assign `{navGroup:"user"}` on the **aliased** `Router` | write | AM `main-device.js:76` |
| `Router.currentRoute.navGroup === "admin"` on the **aliased** `Router` | read | AM `org/forgerock/openam/ui/common/util/ThemeManager.js:168` |
| `obj.currentRoute = {}` at module scope | init | COMMONS `org/forgerock/commons/ui/common/main/Router.js:32` |
| `obj.currentRoute = route` | write | COMMONS `Router.js:213`, `Router.js:243` |
| `currentRoute: null` — the whole module body | init | AM `org/forgerock/openam/ui/common/SingleRouteRouter.js:21` |

Reads via the **full path** (unaffected by the alias, listed so they are not mistaken for
consumers): AM `RouteNavGroupFilter.js:27,28`, AM `PoliciesView.js:135`, AM
`user/anonymousProcess/AnonymousProcessView.js:56,80`, AM `LabelTreeNavigationView.js:29`,
COMMONS `components/Navigation.js:194`, COMMONS `components/hoc/withRouter.js:47`, USER
`anonymousProcess/AnonymousProcessView.js:151,191`.

### `RegisterView` — (b) only

| use | class | file:line |
|---|---|---|
| declaration | — | AM `main.js:30` |
| route `view:` | **(b)** | USER `config/routes/UserRoutesConfig.js:46` |

### `KBADelegate` — (a) only

| use | class | file:line |
|---|---|---|
| declaration | — | AM `main.js:31` |
| `define([...])` dep #8 | **(a)** | USER `org/forgerock/commons/ui/user/profile/UserProfileKBATab.js:26` |

Note that `UserProfileKBATab` itself is reached only by a runtime `require([...])` at AM
`SiteConfigurationService.js:32`, gated on `serverInfo.kbaEnabled === "true"`. So the `KBADelegate`
alias is only exercised down a conditional dynamic-import path.

### `underscore` — (a) only, 29 files

Declarations: AM `main.js:33`, `main-authorize.js:33`, `main-device.js:24`.

**COMMONS — 25 files, all `define([...])` deps, all (a):**

```
org/forgerock/commons/ui/common/LoginDialog.js:19
org/forgerock/commons/ui/common/LoginView.js:18
org/forgerock/commons/ui/common/SiteConfigurator.js:20
org/forgerock/commons/ui/common/backgrid/extension/ThemeableServerSideFilter.js:32
org/forgerock/commons/ui/common/components/BootstrapDialog.js:18
org/forgerock/commons/ui/common/components/BootstrapDialogView.js:19
org/forgerock/commons/ui/common/components/Breadcrumbs.js:19
org/forgerock/commons/ui/common/components/ChangesPending.js:19
org/forgerock/commons/ui/common/components/Dialog.js:19
org/forgerock/commons/ui/common/components/Messages.js:20
org/forgerock/commons/ui/common/components/Navigation.js:19
org/forgerock/commons/ui/common/main/AbstractCollection.js:19
org/forgerock/commons/ui/common/main/AbstractDelegate.js:18
org/forgerock/commons/ui/common/main/AbstractModel.js:19
org/forgerock/commons/ui/common/main/AbstractView.js:19
org/forgerock/commons/ui/common/main/ErrorsHandler.js:18
org/forgerock/commons/ui/common/main/EventManager.js:19
org/forgerock/commons/ui/common/main/ProcessConfiguration.js:20
org/forgerock/commons/ui/common/main/Router.js:18
org/forgerock/commons/ui/common/main/ServiceInvoker.js:19
org/forgerock/commons/ui/common/main/SessionManager.js:19
org/forgerock/commons/ui/common/main/ViewManager.js:20
org/forgerock/commons/ui/common/util/DateUtil.js:18
org/forgerock/commons/ui/common/util/UIUtils.js:20
org/forgerock/commons/ui/common/util/ValidatorsUtils.js:20
```

**USER — 3 files, all (a):**

```
org/forgerock/commons/ui/user/anonymousProcess/AnonymousProcessView.js:20
org/forgerock/commons/ui/user/delegates/AnonymousProcessDelegate.js:19
org/forgerock/commons/ui/user/profile/UserProfileView.js:19
```

**AM — 1 file, and it is a vendored library, not application code:**

```
src/main/js/libs/backgrid-paginator-0.3.5-custom.min.js:8   define(["underscore","backbone","backgrid","backbone.paginator"], …)
```

That file is the target of the `paths` entry `"backgrid.paginator"` (`main.js:45`) and is section
6 / task 4.7's problem, but it **does** consume the `underscore` binding and would break if the
alias were dropped. `libs/jsoneditor-0.7.23-custom.js` mentions the word in prose only, not as a
dependency.

**No AM application module imports `"underscore"`.** AM's own code imports `lodash` directly —
16 ESM `import _ from "lodash";` statements across `.jsm`/`.jsx`:

```
store/reducers/session.jsm:22
org/forgerock/openam/ui/admin/services/global/ApiService.jsm:21
org/forgerock/openam/ui/admin/views/api/ListApiView.jsx:20
org/forgerock/openam/ui/admin/views/api/SideNavGroupItem.jsx:18
org/forgerock/openam/ui/admin/views/realms/ListRealmsView.jsm:17
org/forgerock/openam/ui/admin/views/realms/services/NewServiceView.jsm:17
org/forgerock/openam/ui/admin/views/realms/sessions/SessionsTable.jsx:17
org/forgerock/openam/ui/admin/views/realms/sessions/SessionsTableRow.jsx:17
org/forgerock/openam/ui/admin/views/realms/sessions/SessionsView.jsx:17
org/forgerock/openam/ui/common/components/SelectComponent.jsm:21
org/forgerock/openam/ui/common/services/ServerService.jsm:21
org/forgerock/openam/ui/common/util/NavigationHelper.jsm:20
org/forgerock/openam/ui/common/util/uri/query.jsm:20
org/forgerock/openam/ui/user/dashboard/views/AuthenticationDevicesView.jsm:18
org/forgerock/openam/ui/user/login/gotoUrl.jsm:21
org/forgerock/openam/ui/user/services/SessionService.jsm:18
```

plus many `define([… "lodash" …])` AMD declarations. Those import `lodash` **directly**, not
through the alias, and they are the reason section 5's chaining question matters.

### Summary: what `resolve.alias` actually carries

| | names | which |
|---|---|---|
| reached as an **AMD dependency** — `resolve.alias` handles them | **6** | `ThemeManager`, `NavigationFilter`, `Router`, `KBADelegate`, `underscore`, `UserProfileView` |
| reached **only** as a runtime string identifier — `resolve.alias` never sees them | **6** | `Footer`, `LoginView`, `ForgotUsernameView`, `PasswordResetView`, `LoginDialog`, `RegisterView` |

`UserProfileView` is in both categories (one `define` dep, one route `view:`). Writing all twelve
aliases is still correct — D2 says translate all twelve, and a no-op alias costs nothing and
documents the binding — but **six of them will not be exercised by the bundler at all**, and if
task 6.1's registry does not honour the same twelve names, the login page, the login dialog, the
profile page, forgot-username, password-reset and self-registration all resolve to nothing. That
is the single most important hand-off in this file.

**AM's `config/AppConfiguration.js` names no mapped name.** All 15 of its `moduleClass` /
`delegate` / `loader` identifiers are full module paths. The (b) surface for these twelve names is
entirely in the two route configs and the two process configs listed above.

---

## 3. THE CONFLICT — `Router`, and what it would take to honour all three entries

One name, one non-entry consumer (`ThemeManager.js:25`), two incompatible targets.

Under RequireJS this works because `map` is per-context and resolution is per-referrer: each page
loads its own `require.config`, so `ThemeManager` sees whatever that page bound. Under Vite,
`resolve.alias` is **global to the build** — one build cannot give one id two meanings.

### What each single-binding outcome actually does (corrected)

`NOTES-vite-entrypoints.md` §5.2 costs both directions and **gets both backwards**. The correction
matters, because it flips which direction is the safe one. The mechanism it misses is that
`main-authorize.js:66` and `main-device.js:61` request the *aliased* name `"Router"` themselves —
so under a global alias the entries and `ThemeManager` always agree with each other; they cannot
diverge.

- **`Router` → commons `Router` (main.js's binding wins).** All three entries and `ThemeManager`
  get the same object. `main-authorize.js:126` / `main-device.js:76` write
  `currentRoute = {navGroup:"user"}` **onto that object**, and `ThemeManager.js:168` then reads
  `{navGroup:"user"}.navGroup === "admin"` → `false` → the non-admin theme, which is correct for
  the consent and device pages. **Behaviourally correct on all three entries.** §5.2's claim that
  `currentRoute` would be `null` and the page would stay blank does not hold: the entries no longer
  touch `SingleRouteRouter` at all, and commons `Router.js:32` initialises `currentRoute` to `{}`,
  never `null`.
  *Costs, and they are real.* It drags COMMONS `main/Router.js` and its whole dependency closure —
  `backbone`, `underscore`→lodash, `EventManager`, `Configuration`, `AbstractConfigurationAware`,
  `URIUtils` — onto two pages that today load a 22-line stub with zero dependencies. **`backbone`
  is not in either secondary entry's `paths` block** (`main-authorize.js:37-42`, `main-device.js:28-33`
  list only handlebars, i18next, jquery, lodash, redux, text), so this adds a dependency those two
  bundles have never had. Import-time side effects were checked and are **nil**: `Backbone.history.start()`
  and `new Backbone.Router(...)` are both inside `obj.init` (COMMONS `Router.js:188,227,228`), which
  only `AppConfiguration`'s `moduleDefinition` invokes, and the secondary entries never load it.
- **`Router` → `SingleRouteRouter` (the secondaries' binding wins).** `main.js`'s console gets the
  22-line stub in `ThemeManager`. Nothing in the `main.js` flow ever assigns
  `SingleRouteRouter.currentRoute`, so it stays `null` and `ThemeManager.js:168` evaluates
  `null.navGroup` → **`TypeError: Cannot read properties of null (reading 'navGroup')`**, thrown
  synchronously inside `getTheme()`. `getTheme()` is called from COMMONS `AbstractView.js:104` and
  `UIUtils.js:107,137,179` — i.e. on **every** view render, not just admin ones. §5.2 describes
  this as "the admin theme silently stops being applied"; on a static reading it is a hard throw on
  first render of any console page. Routing itself keeps working, because the 49 AM modules and the
  commons modules that need the real router import it by full path.
  **This direction is worse than §5.2 says, and §6 of that file records that the e2e suite cannot
  see it** — `xui-authorize.spec.mjs` and `xui-device.spec.mjs` exercise only the two secondary
  entries, which stay green. A green suite is not evidence.

*This correction is a static reading of the source. It has not been executed — this task runs no
build. It should be confirmed the first time 4.3 can actually run the tree.*

### The options, costed — NOT DECIDED HERE

| # | option | what it costs | what it breaks / risks |
|---|---|---|---|
| 1 | **One Vite config per entry point (three builds)** | Three configs, three `vite build` invocations, three sets of `outDir` bookkeeping into one tree. No shared chunk between entries, so anything common to `main` and the secondaries is emitted three times. `build.emptyOutDir` must be off for runs 2 and 3 or each wipes the last. | Structurally makes the collision impossible, and it is the only option that reproduces today's semantics exactly. But it forfeits cross-entry code-splitting, and 4.2 chose a **multi-entry** `rollupOptions.input` on purpose — undoing that reopens 4.2's `entryFileNames` reasoning. It also multiplies the `.map` output and the build time by three. |
| 2 | **A plugin resolving `Router` per importing chunk** | A custom `resolveId` that inspects `importer` and returns a different module for `ThemeManager` depending on which entry pulled it. | **Does not work as stated, and this should be checked before anyone tries it.** `resolveId`'s `importer` is the *importing module*, always `ThemeManager.js` here — not the entry that reached it. Rollup has no per-entry module identity at resolve time; a module is resolved once for the whole graph. Making it work needs two *distinct module instances* of `ThemeManager` (e.g. a `\0`-prefixed virtual duplicate per entry), which duplicates `ThemeManager` and everything downstream of it and is option 3 wearing a plugin costume. |
| 3 | **Rewrite the source so the name is not shared** | Small and local: `ThemeManager` takes the router as a parameter, or reads `navGroup` from something both pages set, or the two bindings get distinct ids (`Router` / `SingleRouteRouter`) with `ThemeManager` importing the concrete one. Touches AM files only — `ThemeManager.js`, `main-authorize.js`, `main-device.js`. | **Permitted under D8** (AM-internal, no server-side change). But it changes behaviour that e2e pins, and `e2e/xui/xui-device.spec.mjs:37-38` explicitly names this binding as the thing to guard. It also removes an override seam commons' substitution model is built on — a product's theme manager no longer discovers its router by logical name. Whoever takes it must say what happens to the seam. |
| 4 | **Accept one binding; change the entry that loses** | Zero build machinery. Given the correction above, the direction that survives is **commons `Router` wins**: the two secondaries keep working, `SingleRouteRouter.js` becomes dead (its only two references are `main-authorize.js:31` and `main-device.js:22`) and can be deleted. | Adds `backbone` + the commons router closure to the consent, device and OAuth2 error pages — pages whose whole point is being small and dependency-free, and which are served by FreeMarker templates in **openam-oauth2**, a different Maven module this build does not test. Payload growth on the OAuth2 consent screen is a user-visible cost. The reverse direction (SingleRouteRouter wins) is not viable: it throws on every console view render. |

Whatever is chosen, the acceptance evidence must exercise **`main`**, not just the two secondary
specs — `NOTES-vite-entrypoints.md` §6 shows the existing e2e coverage is blind in exactly the
direction that fails.

---

## 4. THE COMMONS SIDE

### Does "commons contains no reference to a product's module paths" hold today? **YES.**

`ui-module-loading`'s *Substitution of commons modules by the product* requirement, scenario
*Commons carries no product references*.

Evidence, over the full `src/main` of both commons modules (82 `.js`, 46 `.html`, 36 `.less`,
9 `.png`, 2 `.xml`, 2 `.json`, 1 `.ico` — not only the JavaScript):

```
grep -rn -E 'org/forgerock/(openam|openidm|openig)' commons/ui/commons/src/main commons/ui/user/src/main
  → 0 matches
```

Case-insensitively, the product names appear **four times, all in prose comments**, never as a
module path:

```
commons/ui/commons/src/main/js/org/forgerock/commons/ui/common/main/AbstractView.js:131
    * This is due to OpenAM's requirement for two views rendering being rendered at the same time
commons/ui/commons/src/main/js/org/forgerock/commons/ui/common/main/ErrorsHandler.js:51
    // OpenAM authentication no longer produce 403 status
commons/ui/commons/src/main/js/org/forgerock/commons/ui/common/main/ErrorsHandler.js:126
    //TODO add support for openidm errors
commons/ui/commons/src/main/js/org/forgerock/commons/ui/common/main/i18nManager.js:102
    // TODO: OPENAM-9618 The safeString check must remain until we use
```

These are behaviour notes and a JIRA reference. They do not name a module path and nothing resolves
through them. `commons/ui/commons/NPM-PACKAGE.md` asserts the same ("Commons references no product
module path anywhere — that was checked across all of `src/main`, not just the JavaScript") and the
assertion holds on re-check.

The substitution mechanism is visible from both sides in the source, exactly as the requirement
describes:

- commons **names** collaborators it does not own: `ThemeManager` (`AbstractView.js:26`,
  `UIUtils.js:24`), `NavigationFilter` (`Navigation.js:27`), `KBADelegate`
  (USER `UserProfileKBATab.js:26`), `underscore`, `config/AppConfiguration`
  (COMMONS `main/Configuration.js:20`).
- commons **resolves** logical names the product binds: `LoginView`, `LoginDialog`
  (`CommonRoutesConfig.js:40,51`), `UserProfileView`, `ForgotUsernameView`, `PasswordResetView`,
  `RegisterView` (`UserRoutesConfig.js:24,32,39,46`), `Footer` (`CommonConfig.js:73`).
- the product **declares** all of them, in one place: `main.js:21-33`.

The two `NPM-PACKAGE.md` files already publish this contract as a table
("Identifiers the consumer must supply") and `npm run verify:esm` fails if a fifth appears — so
this is checked, not merely asserted.

### Does `resolve.alias` preserve the property? **YES, and it preserves it in the same shape.**

The alias is declared in `openam-ui-ria/vite.config.js` — the product's file. Commons keeps
importing the bare logical name and stays ignorant of what it resolves to. The direction of
knowledge is unchanged from `require.config.map`: product knows commons, commons does not know
product. Both `NPM-PACKAGE.md` files say so directly ("Under AMD they come from
`require.config.map`; under ES modules they are build-time aliases").

Two qualifications:

1. **Only for the 6 names that are AMD dependencies.** The other 6 are runtime strings; the alias
   preserves nothing for them because it never sees them. For those, the property is preserved by
   whatever task 6.1 builds — and the requirement's third scenario (*A logical name left unbound* →
   "the failure is reported against the logical name") is a **registry** obligation, not an alias
   one. `resolve.alias` fails an unbound name in the opposite way; see the next paragraph.
2. **An unbound name does not fail loudly.** Verified in the installed alias plugin: on no match it
   returns `null` and the id falls through to normal resolution (bare `LoginView` → not found in
   `node_modules` → Rollup's "unresolved dependency" warning, treated as external by default). And
   when an alias *does* match but its replacement resolves to nothing, the plugin warns
   (`rewrote X to Y but was not an absolute path…`) and returns `{ id: updatedId }` — **a warning,
   not an error**. A typo'd alias target therefore produces a silently external import, not a build
   failure. Whoever lands 4.3 should decide whether to make that fatal.

### D19 — does it interact with these map aliases? **YES, in three concrete ways.**

D19 (`design.md:286-300`): the ES build keeps the AMD id space, and *"An ESM consumer resolves them
with one bundler alias from that prefix (plus `config/`, see below) to the package's `esm/`
directory."*

**(i) Aliases do not chain — verified, and it changes what 4.3 may write.**

Vite implements `resolve.alias` with the bundled `@rollup/plugin-alias`. Verbatim from
`OpenAM/openam-ui/node_modules/vite/dist/node/chunks/node.js:4757-4766` (vite 8.1.0; identical
construct at `openam-react-example/node_modules/vite/dist/node/chunks/dep-Glf1enhJ.js:220`,
vite 5.1.2 — the same 5.x line the lockfile pins at 5.4.21):

```js
resolveId(importee, importer, resolveOptions) {
    const matchedEntry = entries.find((entry) => matches$1(entry.find, importee));
    if (!matchedEntry) return null;
    const updatedId = importee.replace(matchedEntry.find, matchedEntry.replacement);
    if (matchedEntry.resolverFunction) return matchedEntry.resolverFunction.call(this, updatedId, importer, resolveOptions);
    return this.resolve(updatedId, importer, Object.assign({ skipSelf: true }, resolveOptions)).then((resolved) => {
        if (resolved) return resolved;
        if (!path.isAbsolute(updatedId)) this.warn(`rewrote ${importee} to ${updatedId} but was not an absolute path and was not handled by other plugins. …`);
        return { id: updatedId };
    });
}
```

Two properties follow, and both bite here:

- `entries.find(...)` — **first match wins, order matters, exactly one alias applies per import.**
- `skipSelf: true` — the alias plugin does **not** run on its own replacement. **Aliases do not
  chain.**

So `"UserProfileView"` → `"org/forgerock/commons/ui/user/profile/UserProfileView"` will **not**
then be re-run through D19's `org/forgerock/commons/…` → `<pkg>/esm/` prefix alias. Same for
`"Router"` → `"org/forgerock/commons/ui/common/main/Router"`. The two map bindings that point into
the commons packages must therefore resolve **in one hop** — i.e. their replacement has to be the
already-resolved path (an absolute path or a package specifier), not another aliasable id. The ten
that point at AM's own modules are unaffected only if AM's own `org/forgerock/openam/…` ids are
themselves resolvable in one hop, which is a `resolve.alias`/`resolve.roots` question 4.3 also owns.
`underscore` → `lodash` is the same shape and is section 5.

**(ii) D19's "never alias `config/` wholesale" leaves 7 ids stranded, and 6 of the 12 map names
depend on them.**

D19 and both `NPM-PACKAGE.md` files are emphatic: alias the five commons `config/**` ids
**individually**, because `config/AppConfiguration` and `config/ThemeConfiguration` are the
product's own files and a prefix alias would point them at the package, inverting the
customization route.

Those individually-aliased files are precisely where the (b) identifiers live:

| commons/user `config/**` module | which mapped names it carries |
|---|---|
| `config/routes/CommonRoutesConfig` | `LoginView` (`:40`), `LoginDialog` (`:51`) |
| `config/routes/UserRoutesConfig` | `UserProfileView` (`:24`), `ForgotUsernameView` (`:32`), `PasswordResetView` (`:39`), `RegisterView` (`:46`) |
| `config/process/CommonConfig` | `Footer` (`:73`), `LoginDialog` (`:420`) |

**If those three ids are not individually aliased into the packages, six of the twelve map names
have no consumer at all** — the route tables and the process config simply never load, and the
absence looks like "the alias was unnecessary" rather than like a failure.

**(iii) AM's `config/main.js` reaches 7 of them by *relative* id, and relative ids cannot be
aliased.**

`AM config/main.js:26-44` declares its 15 dependencies with `./` specifiers. Routing each to its
owning tree:

| specifier in `config/main.js` | owning tree |
|---|---|
| `./errorhandlers/CommonErrorHandlers` | **COMMONS** |
| `./validators/CommonValidators` | **COMMONS** |
| `./validators/AMValidators` | AM |
| `./routes/CommonRoutesConfig` | **COMMONS** |
| `./routes/AMRoutesConfig` | AM |
| `./routes/UserRoutesConfig` | **USER** |
| `./routes/admin/RealmsRoutes` | AM |
| `./routes/admin/GlobalRoutes` | AM |
| `./routes/user/UMARoutes` | AM |
| `./messages/CommonMessages` | **COMMONS** |
| `./messages/UserMessages` | **USER** |
| `./AppMessages` | AM |
| `./AppConfiguration` | AM |
| `./process/CommonConfig` | **COMMONS** |
| `./process/AMConfig` | AM |

Seven of fifteen live in the packages. Today Grunt's `copy:compose` flattens all four source roots
into one directory, so `./routes/CommonRoutesConfig` resolves inside the composed tree. Under Vite
resolving against `node_modules`, `./routes/CommonRoutesConfig` resolves relative to
`src/main/js/config/`, **where that file does not exist**. The alias plugin cannot help: it matches
on the importee string, so the only way to catch `./routes/CommonRoutesConfig` is a literal entry
for that exact relative string — which is fragile and would still not distinguish it from AM's own
`./routes/AMRoutesConfig`. The two routes out are the ones `NPM-PACKAGE.md` already names: keep a
composition **copy** step (its route 2), or rewrite `config/main.js` to absolute ids so the D19
individual aliases can catch them.

**None of (i)–(iii) is task 4.3's to decide** — 4.3 owns twelve aliases. But all three land on
4.3's file, and (ii) plus (iii) are the difference between "six aliases were unnecessary" and "six
route/config bindings silently stopped existing".

---

## 5. `underscore` → `lodash`

### The chain today

`main.js:33` maps `"underscore"` → `"lodash"`; `main.js:62` sets `paths["lodash"]` →
`"libs/lodash-3.10.1-min"`; `main.js:157-159` shims it to export `_`. The two secondaries repeat
the same pair (`main-authorize.js:33` + `:40`, `main-device.js:24` + `:31`). So today `underscore`
resolves, in two hops, to **lodash 3.10.1**.

`libs/lodash-3.10.1-min.js` **is not in `src/`.** `src/main/js/libs/` holds only four files
(`backgrid-paginator-0.3.5-custom.min.js`, `jquery.autosize.input.min.js`,
`jsoneditor-0.7.23-custom.js`, `popover-clickaway.js`). The lodash file arrives through the Maven
unpack into `target/dependencies/libs/` and from there into `target/transpiled`, `target/XUI` and
`target/compiled` — i.e. it is **task 4.7's** artifact, not 4.3's.

Meanwhile `openam-ui-ria/package.json` declares `"lodash": "4.18.1"` in **`devDependencies`**, and
`package-lock.json:6974-6979` marks it `"dev": true`. There is **no runtime lodash npm dependency**.
This is the split task 8.3 exists to close.

### Which alias target is correct at the moment 4.3 lands

**Whatever `lodash` itself resolves to at that moment must be lodash 3.10.1, and the naive alias
does not achieve that.** Because aliases do not chain (section 4(i), verified), writing

```js
resolve: { alias: { "underscore": "lodash" } }
```

does **not** re-enter the alias table on `"lodash"`. `"lodash"` is then a bare specifier resolved by
normal Node resolution → `node_modules/lodash` → **4.18.1** — the dev dependency. That silently
performs group 8's lodash 3 → 4 upgrade, at task 4.3, for all 28 commons/user modules that import
`"underscore"`, with no commit that says so.

It is not a benign upgrade. Call sites in the `underscore`-bound trees that lodash 4 removed or
renamed:

| API | commons/user sites |
|---|---|
| `_.contains` (→ `_.includes`) | `util/UIUtils.js:611`, `util/UIUtils.js:631`, `components/Navigation.js:180`, `components/navigation/filters/RoleFilter.js:37` |
| `_.findWhere` (removed) | USER `anonymousProcess/KBAView.js:108`, `:130` |
| `_.object` (→ `_.zipObject`/`_.fromPairs`) | `util/URIUtils.js:120` |

and in AM's own lodash-bound modules a further 25 call sites: `_.contains` ×15, `_.pluck` ×4
(removed, → `_.map`), `_.where` ×3 (removed, → `_.filter`), `_.findWhere` ×2, `_.any` ×1
(→ `_.some`). Those AM sites import `lodash` **directly** and so already resolve to whatever
`lodash` resolves to — meaning the same hazard reaches them whether or not `underscore` is aliased.

**So the correct target at 4.3 is the lodash 3.10.1 file itself, in one hop** — an absolute path to
the built `libs/lodash-3.10.1-min.js`, or an alias for `"lodash"` pointing there with `"underscore"`
pointing at the same resolved target (not at the string `"lodash"`). What is *not* correct at 4.3 is
a bare `"lodash"` replacement, because that quietly resolves to 4.18.1.

**Recorded as unresolved:** the built `libs/lodash-3.10.1-min.js` exists only under `target/`, which
is 4.7's territory and which 4.1 has already repointed (`target/compiled` is now Vite's `outDir`).
Where a *source* lodash 3.10.1 comes from between 4.3 and 4.7 is **not something this survey can
determine** and 4.3 must settle it with 4.7 rather than assume the file is there. Options visible
from here: vendor it into `src/main/js/libs/` (the four files already there are precedent), add
`lodash@3.10.1` as a real runtime dependency under a distinct alias, or sequence 4.3 after 4.7.

### Does the alias have to change again in group 8? **YES if 4.3 pins 3.10.1; NO if 4.3 leaves it bare — but "no" is the wrong kind of no.**

Task 8.3: *"Drop the split between lodash 3.10.1 at runtime and lodash 4.18.1 as a build
dependency; land as its own commit with the phase-0a suite green either side."* If 4.3 pins the
alias to 3.10.1, group 8 repoints it (or deletes it, once `underscore` has no consumers left — the
`// TODO: Remove this when there are no longer any references to the "underscore" dependency`
comment at `main.js:32`, `main-authorize.js:32`, `main-device.js:23` is that intent). If 4.3 leaves
it bare, group 8 has nothing to change *because the upgrade already happened at 4.3* — untested, in
the wrong commit, and without 8.3's "phase-0a suite green either side" gate.

### Count of modules depending on `"underscore"` today

| tree | files declaring `"underscore"` as a dependency |
|---|---|
| COMMONS | **25** |
| USER | **3** |
| AM — application code | **0** |
| AM — vendored library (`src/main/js/libs/backgrid-paginator-0.3.5-custom.min.js:8`) | **1** |
| **total** | **29** (28 application modules + 1 vendored library) |

Cross-checked against the installed packages: 28 files under
`node_modules/@openidentityplatform/ui-{commons,user}/amd/` carry the id, matching 25 + 3. Both
`NPM-PACKAGE.md` files quote the same numbers ("25 modules", "3 modules"). The three entry-point
declarations are excluded from the count.

---

## 6. THE PATHS BLOCK — **4.7's, not 4.3's**

`main.js:37-78` declares **38** `paths` entries (the brief says ~35; the actual count is 38), all
pointing at `libs/*`. `main-authorize.js:37-42` and `main-device.js:28-33` declare 6 each
(`handlebars`, `i18next`, `jquery`, `lodash`, `redux`, `text`), a subset of main's.

**They are 4.7's**, and the change's own artifacts say so in three independent places:

1. **tasks.md:69 — 4.3's scope is explicit and closed:** *"Translate the **12 `require.config.map`
   bindings** in `main.js:19-34` into `resolve.alias` entries."* `paths` is not mentioned.
2. **tasks.md:73 — 4.7 owns where every `libs/` file comes from:** *"Retire the
   `maven-dependency-plugin` unpack steps and the `commons.ui.libs` `dependencySet` blocks in
   `dir.xml` **as their contents move to npm**."*
3. **`prompts/group-4-phase-2.md:1555-1559` — 4.7's own deliverable is the routing decision, per
   file:** *"THE PER-FILE DESTINATION TABLE. For every file currently in the built `libs/` and
   `css/` trees: where it comes from now, and where it comes from after this task. Route each to
   exactly one of: an npm dependency resolved by the bundler; an npm package file copied into the
   output; a vendored file in `src/main/js/libs`; still a Maven artifact (and why); or dropped."*

And `vite.config.js:85-91`, written by 4.1 to assign ownership, gives 4.3 only *"the 12
require.config.map bindings from main.js:19-34"* plus *"`resolve.extensions` and the `.jsm`
extension"*.

**Answer, so neither task double-claims nor double-skips:** the 38 `libs/*` `paths` entries become
**ordinary npm imports under 4.7**, resolved by the bundler from `node_modules`, for every library
that has an npm equivalent — that is what "as their contents move to npm" means and what the
per-file destination table decides. A minority will not: `NPM-PACKAGE.md` already records five ids
that differ from their package name and would need an alias (`spin`→`spin.js`,
`placeholder`→`jquery-placeholder`, `bootstrap-dialog`→`bootstrap3-dialog`,
`backgrid-selectall`→`backgrid-select-all`, `backgrid.paginator`→`backgrid-paginator`), and
`LIBS-INVENTORY.md` §6 records eight artifacts with **no** npm equivalent at all. Those residual
aliases are still **4.7's**, decided by 4.7's table — 4.3 must not pre-empt them.

**Two seams where the two tasks touch, and 4.3 must not resolve either silently:**

- **`lodash`.** It is simultaneously a `paths` entry (4.7's) and the target of a `map` binding
  (4.3's). Section 5. 4.3 needs a resolution for `lodash` to exist before `underscore` can point at
  it, and it must be 3.10.1 until 8.3 says otherwise.
- **`text`.** `main.js:77` maps `text` → `libs/text-2.0.15`, the RequireJS text plugin, used as a
  loader prefix — `main-authorize.js:135` builds `` `text!${themePath}${templatePath}` `` and
  `main-device.js:54-58` has five literal `text!templates/...` dependencies. That is a **loader
  plugin syntax**, not a module id, and no `resolve.alias` entry resolves an `id!path` specifier.
  It is out of scope for both 4.3 and 4.7 as written and belongs with the AMD→ESM conversion
  (group 5) or D3's static-asset handling (4.4). **Flagged, not resolved.**

The 26 `shim` entries (`main.js:80-172`) are also not `resolve.alias` material — they are AMD
export/dependency metadata for non-AMD libraries, and their fate follows whatever 4.7 decides for
each library's npm equivalent.

---

## 7. Could not determine

1. **Where lodash 3.10.1 comes from as a *source* between 4.3 and 4.7.** The only copies on disk
   are under `target/`. Section 5.
2. **Whether the corrected `Router` failure modes hold at runtime.** Section 3's correction to
   `NOTES-vite-entrypoints.md` §5.2 is a static reading; no build was run, and none could be under
   this task's constraints. It should be confirmed the first time the tree executes.
3. **Which vite the build actually uses.** `package.json` declares `"vite": "^5.4.21"` and
   `package-lock.json:9759-9762` pins 5.4.21, but **no `vite` is installed in
   `openam-ui-ria/node_modules`** (547 packages, no `vite`, no `.bin/vite`). Node resolution walks
   up to `OpenAM/openam-ui/node_modules/vite`, which is **8.1.0** — a gitignored directory with no
   `package.json` beside it. `vite.config.js`'s comments cite line offsets in vite 5.4.21 internals
   that will not match. The alias semantics in section 4(i) were therefore verified against 8.1.0
   **and** independently against a 5.1.2 install elsewhere on this machine; they are identical. But
   which vite `npm run build:production` runs today is not something this survey can settle, and
   4.3 should check before trusting any version-specific reasoning.
4. **Whether an unresolved alias should be fatal.** Section 4 shows the plugin warns rather than
   errors. Whether 4.3 adds a guard is a decision, not a finding.
