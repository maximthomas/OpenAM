# XUI per-realm theming — what a Playwright spec can rely on

Findings verified empirically against `openam-idp` (OpenAM 16.2.0-SNAPSHOT) on 2026-08-07, using two
throwaway realms `/e2e-theme-a` and `/e2e-theme-b`. The instance was returned to its pristine state
afterwards. Source of truth for the behaviour:
`openam-ui/openam-ui-ria/src/main/js/org/forgerock/openam/ui/common/util/ThemeManager.js`.

## The mechanism in one paragraph

`config/ThemeConfiguration.js` is a plain RequireJS AMD module fetched over the network as
`XUI/config/ThemeConfiguration.js?v=16.2.0-SNAPSHOT`, separately from `main.js`. `ThemeManager.getTheme()`
walks `mappings` in order, takes the first entry whose `realms` (and, if present, `authenticationChains`)
match, and applies `themes[<that theme>]`. Everything is client-side; there is no server-side theme state.

## Correction to the starting assumptions

| Assumed | Actual |
| --- | --- |
| second theme is keyed `dark` | it is keyed **`fr-dark-theme`** (the *directory* is `themes/dark/`) |
| every mapping ships commented out | true — confirmed, out of the box every realm gets `default` |
| `xui-deploy.sh` is the reset | true but far heavier than needed — see Restore |

## Editing the deployed config

| Question | Answer |
| --- | --- |
| container | `openam-idp` |
| path | `/usr/local/tomcat/webapps/openam/XUI/config/ThemeConfiguration.js` |
| owner/perms | `640 openam:root`; `docker exec` runs as `uid=1001(openam) gid=0(root)` |
| how to write | `docker exec -i openam-idp sh -c 'cat > <path>' < newfile` — truncates in place, so owner and mode are preserved. `docker cp` also works but writes a root-owned file. |
| does Tomcat need a restart | **no** — static resource, picked up live |
| **staleness** | **Tomcat's `WebResourceRoot` cache serves the OLD bytes for ~5 s after the write** (measured: stale at t+4.4 s, fresh at t+5.4 s — the default `cacheTtl=5000`). A page loaded inside that window silently gets the previous config. This is server-side, not the browser: a brand-new Chromium process still saw the stale copy. |
| how to beat it | poll `GET /XUI/config/ThemeConfiguration.js` until the body contains a marker from the new content, *then* open the page. Do not use a fixed sleep. |
| browser cache | the file is served `Cache-Control: public, max-age=2592000`, so a context that has already loaded the page will not refetch. A fresh `browser.newContext()` (i.e. Playwright's default per-test context) is enough; `page.reload()` in the same context is **not**. |
| cache-bust via URL | not available — RequireJS `urlArgs` is the fixed build version `?v=16.2.0-SNAPSHOT`, identical before and after the edit. |

### Preferred alternative: don't edit the deployed file at all

`context.route("**/config/ThemeConfiguration.js*", route => route.fulfill({ body }))` was verified to
drive theme selection with the deployed file left **pristine**. It has no Tomcat-cache window, no restore
step, no cross-test leakage, and no shared-instance risk. Every result in the tables below was produced
this way. Recommend the spec use interception and treat file editing as a fallback only.

## Restore

| | |
| --- | --- |
| mechanism | keep the pristine bytes (`docker cp openam-idp:<path> orig.js` before any change) and write them back with the same `docker exec -i … 'cat > …'`. Verify with `sha256sum` on both sides. |
| is `xui-deploy.sh` the right reset | no. It `rm -rf`s and re-copies the whole `/XUI` from a Maven build artifact that must exist locally; it is the wrong granularity and fails outright if `openam-ui-ria/target/*-www.zip` was never built. Use it only if `/XUI` is damaged beyond the one file. |
| current state | restored, `sha256 f34dcefd0196b0db4314c009e3d5ee078146a3d4f98734f8b42cd98dc044cbca`, `640 openam:root`, `mappings` all commented out; probe realms deleted; realm list back to `[/]` only. |

## How the realm reaches the theme

`ServerService.getConfiguration()` fetches `/json/serverinfo/*` with the realm taken from
`URIUtils.getCurrentQueryString()` (the **outer** query string only) and dispatches `serverAddRealm`.
`store/reducers/server.jsm` **lowercases** it.

| URL form | realm seen by ThemeManager |
| --- | --- |
| `XUI/?realm=/e2e-theme-b#login/` | `/e2e-theme-b` ✔ **use this** |
| `XUI/#login/e2e-theme-b` | `/` ✘ the hash route form does not set it |
| `XUI/?realm=/E2E-Theme-B#login/` | `/e2e-theme-b` (lowercased) |
| `XUI/#login/` | `/` |

## Mapping syntax — measured

Each row is one `mappings` array; results are `realm-a` / `realm-b`.

| mapping | a | b | |
| --- | --- | --- | --- |
| `{ theme: "fr-dark-theme", realms: ["/e2e-theme-b"] }` | default | fr-dark-theme | ✔ |
| `{ …, realms: ["e2e-theme-b"] }` (no leading slash) | default | default | ✘ |
| `{ …, realms: ["/E2E-Theme-B"] }` (mixed case) | default | default | ✘ **mapping must be lowercase** |
| `{ …, realms: [/^\/e2e-theme-b$/] }` | default | fr-dark-theme | ✔ regex works |
| `{ …, realms: [/^\/e2e-theme-/] }` | fr-dark-theme | fr-dark-theme | ✔ prefix regex matches both |
| `[{default, /^\/e2e-theme-/}, {fr-dark-theme, "/e2e-theme-b"}]` | default | default | ✘ **first match wins** |
| `[{fr-dark-theme, "/e2e-theme-b"}, {default, "/e2e-theme-a"}]` | default | fr-dark-theme | ✔ **the two-realm form to use** |
| `{ …, realms: ["/e2e-theme-b"], authenticationChains: ["ldapService"] }` | default | default | ✘ see below |
| `{ …, realms: ["/e2e-theme-b"], authenticationChains: [""] }` | default | fr-dark-theme | ✔ |
| `{ theme: "no-such-theme", realms: ["/e2e-theme-b"] }` | default | **themeName `no-such-theme` but default stylesheets** | ⚠ silent |

Two traps in that table:

- `authenticationChains` is matched against `getAuthenticationChainName()`, which reads `service` /
  `authIndexType=service` from the URL and returns `""` otherwise. A plain `#login/` therefore only ever
  matches `[""]`. Leave `authenticationChains` out of the spec's mapping entirely.
- A typo'd theme name does **not** throw. `extendTheme(undefined, defaultTheme)` yields the default theme
  while `globalData.themeName` still reads back the bogus name. **Never assert on `themeName` alone** —
  assert on the stylesheet hrefs and logo `src`, which are the observable the migration must preserve.

## Stylesheets — what to assert

`applyThemeToPage` does `$("link").remove()` first, so the theme **replaces** the whole `<link>` list; it
never appends to it. Assert the full `document.head` list in document order, and note the first two are
always the favicon pair.

| index | selector | default theme | `fr-dark-theme` |
| --- | --- | --- | --- |
| 0 | `head link[rel="icon"]` | `./favicon.ico?v=…` | same (inherited) |
| 1 | `head link[rel="shortcut icon"]` | `./favicon.ico?v=…` | same (inherited) |
| 2 | `head link[rel="stylesheet"]` | `./css/bootstrap-3.3.5-custom.css?v=…` | `./themes/dark/css/bootstrap.min.css?v=…` |
| 3 | `head link[rel="stylesheet"]` | `./css/structure.css?v=…` | `./css/structure.css?v=…` (identical — do not assert on this one alone) |
| 4 | `head link[rel="stylesheet"]` | `./css/theme.css?v=…` | `./themes/dark/css/theme-dark.css?v=…` |

Hrefs are produced by `require.toUrl()`, so every one carries a `./` prefix and a `?v=<build version>`
suffix. Normalise with `href.replace(/^\.\//, "").replace(/\?.*$/, "")` rather than matching literally —
the `?v=` value is the Maven version and will change.

Exactly 3 stylesheets in both cases; a count assertion is a cheap guard that the theme replaced rather
than merged.

## Logos — what to assert

`ThemeConfiguration` defines two, and they render in **different, mutually exclusive** places.

| surface | selector | attribute | source key | default | `fr-dark-theme` |
| --- | --- | --- | --- | --- | --- |
| login page | `img.main-logo` | `src`, `alt`, `width`, `height` | `settings.loginLogo` | `./images/login-logo.png`, alt `OpenAM`, 225px×57px | `./themes/dark/images/login-logo-white.png`, alt `ForgeRock`, 220px×228px |
| post-login | `#navbarBrand img` | `src`, `alt`; title on the parent `#navbarBrand a` | `settings.logo` | `./images/login-logo.png`, alt `OpenAM` | **`./images/login-logo.png`, alt `OpenAM` — identical** |

`img.main-logo` is absent post-login; `#navbarBrand img` is absent pre-login. Do not write one assertion
that covers both.

**The post-login logo does not distinguish the themes as shipped.** `fr-dark-theme` declares only
`loginLogo`; `extendTheme` merges it over `default`, so it inherits the default `settings.logo`. Verified:
after login to realm b on `fr-dark-theme`, `#navbarBrand img` is still `images/login-logo.png alt="OpenAM"`.
If the spec wants a post-login logo difference it must add a `settings.logo` block to the injected theme —
verified working, `#navbarBrand img` then reads `themes/dark/images/login-logo-white.png`.

### Render race

`img.main-logo` is **not** present when `#idToken1` first becomes visible — measured absent on one of four
login loads at that moment, present after waiting. Always
`await expect(page.locator("img.main-logo")).toBeVisible()` before reading its `src`; never gate on the
username field.

## When theme selection is observable

| point | observable | notes |
| --- | --- | --- |
| **before login**, on `#login/` | **yes** — full stylesheets + `loginLogo` | realm comes from `?realm=` on the initial page load, so it is known before any credential is entered. This is where the spec should do its main work. |
| at login submit | n/a | no re-theme; the realm has not changed |
| after login, user page (`#profile/details`) | yes — stylesheets **and** `#navbarBrand img` | requires a non-admin user *in that realm* |
| after login, admin console (`#realms`) | **stylesheets: no** | `isAdminTheme = Router.currentRoute.navGroup === "admin"` forces `Constants.DEFAULT_STYLESHEETS` = `css/bootstrap-3.3.5-custom.css`, `css/styles-admin.css`, even though `themeName` is still `fr-dark-theme`. The navbar logo *is* still theme-driven. |

Because the pre-login page already carries the whole difference, the two-realm assertion needs no login at
all. That is the simplest spec and the one to write first.

## Fixtures the spec needs

- Realms: reuse `createRealm` / `removeRealm` / `uniqueRealmName` from `../common/realms-commons.mjs`
  (task 1.6). Do not add a second helper.
- **Realm names must be lowercase** so they survive the store's `toLowerCase()` and still match the mapping
  literal. `uniqueRealmName()` already produces lowercase (`base36` timestamp).
- A post-login test additionally needs a user *in* the sub-realm — `amadmin` cannot authenticate into one
  (login hangs on `#login`). Create with:
  `POST /json/realms/root/realms/<realm>/users?_action=create`, `Accept-API-Version: protocol=2.0,resource=3.0`,
  body `{ username, userPassword, sn, cn }`. Note `resource=4.0` 404s. Deleting the realm removes its users.

## Phase-2 (D6) dependency

D6 removes the ability to edit config inside the deployed `/XUI`. This spec's relationship to that:

- The spec does **not** need to write into the deployed `/XUI` — `context.route(...).fulfill(...)` was
  verified to work with the deployed file untouched. On that axis it is D6-safe.
- It **does** depend on `config/ThemeConfiguration.js` remaining a **separately fetched module at a stable
  URL**. Confirmed today: exactly one request, `config/ThemeConfiguration.js?v=16.2.0-SNAPSHOT`, distinct
  from `main.js`. If the Vite build inlines the config into the bundle, *both* the interception approach and
  the file-edit approach stop working, and this spec has to be rewritten around whatever replaces the file.
- Recording that request URL is therefore the load-bearing baseline. A phase-2 regression shows up as the
  interception route never firing, so the spec should fail loudly if the route handler was not invoked
  rather than silently asserting the default theme.

## Follow-ups

Raised by the code review of `xui-theming.spec.mjs` (2026-08-10), deliberately left undone because they
fall outside task 1.9. Neither blocks the spec.

| | |
| --- | --- |
| **Extract the deployed-`/XUI` helpers at task 1.10** | `xui-theming.spec.mjs` keeps `readDeployedConfig` / `writeDeployedConfig` / `deployedSha256` / `waitForServedConfig` local, which is right for one caller. Task 1.10 (theme template override) and task 1.11 (`AppConfiguration.loginHelperClass` pointing at a module added to the deployed tree) both need the identical write-into-container → wait-out-the-Tomcat-cache → restore machinery. Move them to `common/deployed-xui-commons.mjs` when 1.10 lands, so it is a planned extraction rather than a third copy. |
| **No escape hatch for a hard-killed run** | The spec restores the config in fixture teardown, which covers assertion failure, timeout and `SIGINT`. It cannot cover `SIGKILL` on the worker or the docker daemon dying mid-run — those leave the mutated config deployed, and then every later spec gets the wrong theme. `xui-deploy.sh` is the wrong granularity for putting one file back (see Restore above) and fails outright without a Maven `-www.zip`. Consider a one-file reset in `local/`. Mitigated but not solved today: the leaked mapping names realms that no longer exist, so other specs still fall through to `default`. |
