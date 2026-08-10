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
| **Extract the deployed-`/XUI` helpers — deferred from 1.10 to 1.11** | Originally raised as "do this when 1.10 lands". 1.10 landed *inside* `xui-theming.spec.mjs` rather than as a second spec file, so there is still exactly one copy and extracting would have been churn against a single caller. The helper set has grown to seven — `readDeployedConfig`, `writeDeployedConfig`, `deployedSha256`, `placeDeployedFile`, `removeDeployedOverride`, `deployedPathExists`, `waitForServed` — and task 1.11 (`AppConfiguration.loginHelperClass` pointing at a module added to the deployed tree) needs `placeDeployedFile` + `waitForServed` + the remove-and-verify pattern essentially unchanged, in a different file. **1.11 is the forcing function**: extract to `common/deployed-xui-commons.mjs` there, before writing a second copy. |
| **No escape hatch for a hard-killed run** | The spec restores the config in fixture teardown, which covers assertion failure, timeout and `SIGINT`. It cannot cover `SIGKILL` on the worker or the docker daemon dying mid-run — those leave the mutated config deployed, and then every later spec gets the wrong theme. `xui-deploy.sh` is the wrong granularity for putting one file back (see Restore above) and fails outright without a Maven `-www.zip`. Consider a one-file reset in `local/`. Mitigated but not solved today: the leaked mapping names realms that no longer exist, so other specs still fall through to `default`. |

## Theme template override — what a spec can rely on

Verified empirically against `openam-idp` (OpenAM 16.2.0-SNAPSHOT) on 2026-08-10, five throwaway Chromium
runs against `XUI/#login/` in the root realm. Instance returned to pristine afterwards (see Restore of the
override, below).

### Correction: `ThemeManager.js` does *not* resolve templates

`ThemeManager.js` only ever passes `theme.path` to the favicon:

```js
applyThemeToPage(theme.path, theme.icon, stylesheets);   // line 190
```
```js
applyThemeToPage = function (path, icon, stylesheets) {  // line 33
    $("link").remove();
    $("<link/>", { rel: "icon", type: "image/x-icon", href: require.toUrl(path + icon) }).appendTo("head");
```

Template resolution lives in **`org/forgerock/commons/ui/common/util/UIUtils.js`**, which consumes the theme
object that `ThemeManager.getTheme()` resolves. That file is **not in the OpenAM source tree** — it is
unpacked at build time from the Maven artifact `org.openidentityplatform.commons.ui:user:zip:www`
(`openam-ui/openam-ui-ria/pom.xml`, execution `unpack-forgerock-ui-user`). Read it at
`openam-ui/openam-ui-ria/target/XUI/org/forgerock/commons/ui/common/util/UIUtils.js`, or in the container at
`/usr/local/tomcat/webapps/openam/XUI/org/forgerock/commons/ui/common/util/UIUtils.js` — the deployed copy is
byte-equivalent in behaviour (same `was not found. Trying` strings at lines 102 / 128 / 165).

### The mechanism, quoted

Three call sites, one shape: try `theme.path + url`, and on **any** failure retry the bare `url`.

`compileTemplate` (single template, the one the login page hits most):

```js
obj.compileTemplate = function (templateUrl, data) {
    if (templateUrl) {
        return ThemeManager.getTheme().then(function (theme) {
            var templateUrlWithPath = theme.path + templateUrl,
                templateSavedPath = theme.path ? templateUrlWithPath : templateUrl;

            if (obj.templates[templateSavedPath]) {
                return Handlebars.compile(obj.templates[templateSavedPath])(data);
            } else if (theme.path) {
                return fetchAndCompileTemplate(templateUrlWithPath, templateUrlWithPath, data)
                    .then(null, function fallBackToDefaultPath() {
                        console.log(templateUrlWithPath + " was not found. Trying " + templateUrl);
                        return fetchAndCompileTemplate(templateUrl, templateUrlWithPath, data);
                    });
            } else {
                return fetchAndCompileTemplate(templateUrl, templateUrl, data);
            }
        });
    }
```

`preloadTemplates` and `preloadPartial` repeat it verbatim for bulk templates and Handlebars partials:

```js
        promises.push(
            fetchAndSaveTemplate(urlWithPath, urlWithPath).then(null, function fallBackToDefaultPath() {
                console.log(urlWithPath + " was not found. Trying " + templateUrl);
                promises.push(fetchAndSaveTemplate(templateUrl, urlWithPath));
            }));
```
```js
            } else if (theme.path) {
                return registerPartial(name, theme.path + url)
                    .then(null, function fallBackToDefaultPath() {
                        console.log(theme.path + url + " was not found. Trying " + url);
                        return registerPartial(name, url);
                    });
```

Two consequences that matter for the spec:

- The **memo key is always the themed path** (`urlToSave = templateUrlWithPath` on *both* branches). So the
  miss is paid once per template per page load, not once per render.
- The fetch is `$.ajax({ type: "GET", url: require.toUrl(url), dataType: "html" })`, so every template URL
  carries the same `?v=<build version>` suffix as the stylesheets.

### `path` is only ever set by the theme author

`default` ships `path: ""`; **`fr-dark-theme` does not declare `path` at all**, and `extendTheme` merges it
over `default`, so it inherits `""`. Selecting `fr-dark-theme` therefore changes stylesheets and the login
logo but **does not redirect a single template**. A spec that wants to exercise template resolution must
inject a theme that declares a non-empty `path` — reuse the `context.route(...)` config interception from the
sections above and add `path: "themes/dark/"`. Measured: `themes/dark/` on disk contains only `css/`,
`images/` and `config.json` — **no templates** — which makes it a free, realistic fallback fixture.

### The subject template: `templates/common/FooterTemplate.html`

| criterion | why it qualifies |
| --- | --- |
| small | 16 lines, no partials, no sub-includes |
| visibly distinct | renders into `#footer`, plain visible text, no CSS needed to see it |
| no setup | present on `XUI/#login/` in the root realm — no realm, no user, no authentication |
| unambiguous | the theme inherits `settings.footer` from `default`, so **no** theme setting can change the footer text. Literal text appearing there can only have come from an overridden template. |

Rejected alternatives: `templates/common/LoginHeaderTemplate.html` renders `img.main-logo` but its content is
driven by `settings.loginLogo`, so an assertion there cannot distinguish "template was overridden" from
"setting was applied" — exactly the confusion this test exists to avoid. `templates/common/LoginBaseTemplate.html`
is structural (`#content` lives inside it); overriding it breaks the rest of the page.

### Placing and removing the override

Absolute path in the deployed tree:

```
/usr/local/tomcat/webapps/openam/XUI/themes/dark/templates/common/FooterTemplate.html
```

`themes/dark/templates/` and `themes/dark/templates/common/` do **not** exist out of the box — both are
created by the test and both must be removed.

```sh
X=/usr/local/tomcat/webapps/openam/XUI
# place
docker exec openam-idp sh -c "mkdir -p $X/themes/dark/templates/common && \
  printf '%s\n' '<div class=\"container\"><p id=\"e2e-tpl-marker\">E2E-TEMPLATE-OVERRIDE-OK</p></div>' \
  > $X/themes/dark/templates/common/FooterTemplate.html"
# wait out the Tomcat WebResourceRoot cache — poll, never sleep (see Editing the deployed config)
curl -sS -o /dev/null -w '%{http_code}' \
  http://openam.example.org:8080/openam/XUI/themes/dark/templates/common/FooterTemplate.html   # until 200
# remove
docker exec openam-idp sh -c "rm -f $X/themes/dark/templates/common/FooterTemplate.html && \
  rmdir $X/themes/dark/templates/common $X/themes/dark/templates"
```

`docker exec` runs as `openam:root`, so the created file is `644 openam:root` (the surrounding tree is `640`
/ `750`); it is world-readable for the few seconds it exists, which Tomcat does not care about. Because the
file is *new*, there is nothing to back up — restore is `rm` + `rmdir`, not a byte restore.

**Preferred alternative, same as for the config:** `context.route("**/themes/dark/templates/common/FooterTemplate.html*",
route => route.fulfill({ body }))` was verified to produce an identical result with the deployed `/XUI` left
completely untouched. Use interception; keep the disk recipe as a fallback for the case where the migration
stops serving templates over the network.

### The assertion that proves the override rendered

DOM, not network:

```js
await expect(page.locator("#footer #e2e-tpl-marker")).toHaveText("E2E-TEMPLATE-OVERRIDE-OK");
```

Measured: `#e2e-tpl-marker` count 1, visible `true`, `#footer` innerText exactly `E2E-TEMPLATE-OVERRIDE-OK`
(the default footer text `open-identity-platform-openam@googlegroups.com … Join OpenAM Community` is gone).
Identical result via disk override and via `route.fulfill`. Survives `page.reload()`.

### The fallback path — measured network sequence

Themed (`path: "themes/dark/"`), **no** override anywhere, one `#login/` page load:

| | |
| --- | --- |
| requests for `*.html` | **54** — 27 × `404 themes/dark/<url>` immediately followed by 27 × `200 <url>` |
| default theme, same page | 27 × `200 <url>`, zero 404s |
| with the one override in place | 26 × 404 + 26 × 200, plus `200 themes/dark/templates/common/FooterTemplate.html` and **no** request for `templates/common/FooterTemplate.html` |
| is a 404 really issued | **yes** — real HTTP 404 from Tomcat, one per template, in strict try-then-retry order (e.g. `404 themes/dark/templates/common/FooterTemplate.html` → `200 templates/common/FooterTemplate.html`) |
| once or every render | **once per template per page load.** In-page navigation `#login/ → #profile/details → #login/` issued **0** further `.html` requests and **0** further fallback logs — `UIUtils.templates` is memoised under the *themed* key. |
| across a full reload | **repeats in full** — `page.reload()` re-issued all 26 404s and 26 fallback logs. The memo is a JS object, not an HTTP cache, and Tomcat sends no cache headers on the 404. |
| swallowed or surfaced | **swallowed.** `.then(null, fallBackToDefaultPath)` catches the jQuery ajax rejection. `pageerror` count is **0** in every themed run. Nothing reaches the user. |

### How to assert the fallback without asserting on the 404

**Behavioural requirement (assert this):** with a theme whose `path` supplies no override for a template, the
page still renders that template's content from the default location. Concretely, for a theme with
`path: "themes/dark/"` and no `themes/dark/templates/common/FooterTemplate.html`:

```js
await expect(page.locator("#footer")).toContainText("Join OpenAM Community");
await expect(page.locator("#e2e-tpl-marker")).toHaveCount(0);
```

plus the guard the theming spec already uses — fail loudly if the `ThemeConfiguration.js` route handler was
never invoked, otherwise the test silently degrades into "the default theme renders", which proves nothing.
Optionally pin that the theme really was applied by checking a stylesheet href, so a broken injection cannot
pass this test.

**Mechanism (do NOT assert this):** the `404 themes/dark/…` → `200 …` pair, the request count 54, the ordering,
and the `console.log("… was not found. Trying …")` line. Every one of those is an artefact of RequireJS +
jQuery ajax + a runtime probe. A Vite build knows the theme's file list at build time and can legitimately
resolve the override statically, emit zero 404s, and still satisfy the requirement. A spec that counts 404s
fails the migration for being *better*. Assert the rendered text; let the transport change.

The one mechanism fact worth recording as a **baseline note rather than an assertion**: the fallback costs one
404 per template per page load (27 on the login page). If a spec ever wants to guard the *cost*, phrase it as
an upper bound that a zero-404 implementation also passes, e.g. `expect(count404).toBeLessThanOrEqual(27)` —
never an equality.

### Correction: the footer assertions above are not sufficient — partials are the larger half

Raised by the code review of the 1.10 spec (2026-08-10) and verified with two interception-only probes
(deployed tree untouched, theme injected via `context.route`, root realm).

The "27 × 404" above is **19 partials + 8 templates**, and the two come from *different* `UIUtils` call
sites. The footer and the login logo are both `compileTemplate` output; nothing about them exercises
`preloadPartial`, which is where the 19 are and where the login form comes from. `#idToken1` is
rendered by `partials/login/_Default.html`, one of the 19 `partialUrls` in `AppConfiguration.js:74`.

Measured, themed path in both cases, one login page load each:

| probe | `#idToken1` | submit | `img.main-logo` | `#footer` mailto | `pageerror` |
| --- | --- | --- | --- | --- | --- |
| A — nothing blocked | 1 | 1 | 1 | 1 | 0 |
| B — only `partials/login/_Default.html` made to fail on the **default** path | **0** | **0** | 1 | 1 | 0 |

Probe B is what a loader that kept `compileTemplate`'s fallback and lost `preloadPartial`'s looks
like. Every assertion the section above recommends passes against it, on a login page with no form on
it. So the fallback assertion set must include one observable from a partial:

```js
await expect(page.locator("#idToken1")).toBeVisible();
```

Still behaviour, not mechanism — it names a rendered element, not a request. `xui-login.spec.mjs` does
not close this gap: it runs under the default theme, where `theme.path` is `""` and `preloadPartial`
takes the `else` branch that never falls back.

### Console noise — a strict test cannot pass, theme or no theme

| run | `console` errors | `pageerror` |
| --- | --- | --- |
| default theme | 2 | 0 |
| themed, no override | 29 (2 baseline + 27 template 404s) | 0 |

The themed run adds one browser-generated `[error] Failed to load resource: … 404` per missed template, plus
one explicit `[log] themes/dark/<url> was not found. Trying <url>` per template — **57 console messages** on a
single login page load. There is no way to suppress either from the page.

Critically, the **default** login page already emits two console errors with no theming involved at all:

```
404 /openam/XUI/locales/en-US/translation.json?v=16.2.0-SNAPSHOT
401 /openam/json/users?_action=idFromSession
```

So a "fail on any console error" harness is already unusable on `XUI/#login/` and this spec does not make it
newly unusable. `pageerror` is clean (0) in **every** run, themed or not — if a strict guard is wanted, guard
`pageerror`, never `console`.

### Restore of the override

| | |
| --- | --- |
| what was mutated | one new file `themes/dark/templates/common/FooterTemplate.html` plus its two new parent dirs. `config/ThemeConfiguration.js` was **never written** — all theme selection went through `context.route`. |
| current state | file and both dirs removed; `themes/dark/` back to `config.json`, `css/`, `images/`. `GET …/themes/dark/templates/common/FooterTemplate.html` → **404**; `GET …/templates/common/FooterTemplate.html` → **200**; `GET /openam/XUI/` → **200**. `ThemeConfiguration.js` sha256 `f34dcefd0196b0db4314c009e3d5ee078146a3d4f98734f8b42cd98dc044cbca`, `640 openam:root` — matches the pristine value recorded above. Browser re-check: `themeName` `default`, logo `./images/login-logo.png`, footer back to the community text, `#e2e-tpl-marker` count 0, zero `.html` 404s. |

### Phase-2 (D6) dependency, for this spec specifically

- The DOM assertions are transport-agnostic and D6-safe.
- The **fixture** depends on `config/ThemeConfiguration.js` staying a separately fetched module (already
  recorded above) *and* on templates being separately fetched `.html` files at `<theme.path><url>`. Vite will
  almost certainly inline templates into the bundle; when it does, the override fixture must move from
  "serve a file at a URL" to whatever the new build's theme-asset mechanism is. Write the spec so that the
  fixture is one helper and the assertions do not know how the override got there.
- The template fallback lives in a **third-party artifact** (`org.openidentityplatform.commons.ui:user`), not
  in OpenAM. Any migration that keeps `UIUtils.js` keeps this behaviour for free; any migration that replaces
  it must reimplement the try-themed-then-default rule deliberately. Flag it in the phase-2 plan.

### Trap: `main-authorize.js` uses `theme.path` with **no** fallback

`openam-ui/openam-ui-ria/src/main/js/main-authorize.js` (the OAuth2 consent page, deployed as
`XUI/main-authorize.js`) prefixes its templates with the theme path too, but through the RequireJS `text!`
plugin and with no error branch:

```js
var themePath = Configuration.globalData.theme.path;
templatePaths = _.map(templatePaths, function (templatePath) {
    return `text!${themePath}${templatePath}`;
});
```

A theme that sets `path` but ships no `templates/common/LoginBaseTemplate.html`,
`templates/common/FooterTemplate.html`, `templates/common/LoginHeaderTemplate.html` or the authorize template
will therefore **break the consent page**, not fall back. Do not reuse a themed-`path` fixture in
`xui-authorize.spec.mjs` without also placing those four templates.
