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

# `require.toUrl()` and `urlArgs` — the target behaviour for the XUI build migration

**The question:** does `require.toUrl()` apply the configured `urlArgs` cache-busting parameter?

**The answer: YES.** In the RequireJS 2.3.7 the XUI actually deploys, `toUrl()` delegates to
`nameToUrl()`, and `nameToUrl()` applies `urlArgs` on its single return path. There is no
`toUrl`-specific bypass.

Established twice, independently, on 2026-08-11 against OpenAM 16.2.0-SNAPSHOT:

1. from the deployed `requirejs-2.3.7-min.js` (read before the experiment was run), and
2. empirically in a browser against the running `openam-idp` instance.

**The two agree.** No discrepancy to report.

---

## 1. From the source

### The file that is actually deployed

| | |
|---|---|
| loaded by | `XUI/index.html`, line 28: `<script src="libs/requirejs-2.3.7-min.js"></script>` |
| deployed path | `openam-server/target/OpenAM-16.2.0-SNAPSHOT/XUI/libs/requirejs-2.3.7-min.js` |
| served at | `http://openam.example.org:8080/openam/XUI/libs/requirejs-2.3.7-min.js` |
| md5 | `01252f25e96768861bd3effa7bf8889e` — **the served bytes and the on-disk war bytes are identical**, verified by `md5sum` on both |
| size | 17 420 bytes, minified, single line |
| version, from the file itself | `version="2.3.7"` (a literal in the file's own variable list, not a filename claim) |

The filename says 2.3.7 *and* the file's internal `version` literal says `2.3.7` *and* the runtime
`requirejs.version` read in the browser says `2.3.7`. All three agree.

A readable copy of the same release sits at
`openam-ui/openam-ui-ria/node_modules/requirejs/require.js` (`version = '2.3.7'`); line numbers
below refer to it purely for legibility. **The deployed minified file is the authority** and every
quote below is copied verbatim out of it.

### `toUrl` — it just forwards to `nameToUrl`

Verbatim from the deployed file:

```js
toUrl:function(e){var t,i=e.lastIndexOf("."),r=e.split("/")[0];return-1!==i&&(!("."===r||".."===r)||1<i)&&(t=e.substring(i,e.length),e=e.substring(0,i)),f.nameToUrl(v(e,o&&o.id,!0),t,!0)}
```

Unminified equivalent (`require.js:1479-1493`):

```js
toUrl: function (moduleNamePlusExt) {
    var ext,
        index = moduleNamePlusExt.lastIndexOf('.'),
        segment = moduleNamePlusExt.split('/')[0],
        isRelative = segment === '.' || segment === '..';

    //Have a file extension alias, and it is not the
    //dots from a relative path.
    if (index !== -1 && (!isRelative || index > 1)) {
        ext = moduleNamePlusExt.substring(index, moduleNamePlusExt.length);
        moduleNamePlusExt = moduleNamePlusExt.substring(0, index);
    }

    return context.nameToUrl(normalize(moduleNamePlusExt, ...), ext, true);
}
```

All `toUrl` does is split a trailing `.ext` off the id and hand the pieces to `nameToUrl` with
`skipExt = true`. It does nothing with `urlArgs` itself, and — the point — it does nothing to
*suppress* it either.

### `nameToUrl` — the single `urlArgs` application site

Verbatim from the deployed file:

```js
nameToUrl:function(e,t,i){var r,n,o,a,s,u=getOwn(b.pkgs,e);if(u=getOwn(m,e=u?u:e))return f.nameToUrl(u,t,i);if(req.jsExtRegExp.test(e))a=e+(t||"");else{for(r=b.paths,o=(n=e.split("/")).length;0<o;--o)if(s=getOwn(r,n.slice(0,o).join("/"))){isArray(s)&&(s=s[0]),n.splice(0,o,s);break}a=n.join("/"),a=("/"===(a+=t||(/^data\:|^blob\:|\?/.test(a)||i?"":".js")).charAt(0)||a.match(/^[\w\+\.\-]+:/)?"":b.baseUrl)+a}return b.urlArgs&&!/^blob\:/.test(a)?a+b.urlArgs(e,a):a}
```

The load-bearing clause is the **return statement**, which is the only exit from the function:

```js
return b.urlArgs&&!/^blob\:/.test(a)?a+b.urlArgs(e,a):a
```

Unminified (`require.js:1679-1680`):

```js
return config.urlArgs && !/^blob\:/.test(url) ?
       url + config.urlArgs(moduleName, url) : url;
```

`b` is the context `config`. So: **if `urlArgs` is configured, every url `nameToUrl` returns gets
it appended, unless the url is a `blob:` url.** There is no `skipExt`/`toUrl` branch guarding it.
`toUrl` goes through this return like every other caller, so `toUrl` gets `urlArgs`.

`grep -c` on the deployed file: `urlArgs` appears **5** times and `nameToUrl` **5** times. There is
exactly one place that appends `urlArgs` to a url — the return above.

### How the configured string becomes that function

`urlArgs` is documented as a string but is normalised to a function at `configure` time. Verbatim
from the deployed file:

```js
"string"==typeof e.urlArgs&&(i=e.urlArgs,e.urlArgs=function(e,t){return(-1===t.indexOf("?")?"?":"&")+i});
```

Unminified (`require.js:1291-1296`):

```js
// Convert old style urlArgs string to a function.
if (typeof cfg.urlArgs === 'string') {
    var urlArgs = cfg.urlArgs;
    cfg.urlArgs = function(id, url) {
        return (url.indexOf('?') === -1 ? '?' : '&') + urlArgs;
    };
}
```

So the separator is chosen per-url: `?` normally, `&` if the url already carries a query string.

### Source verdict

`require.toUrl("templates/common/LoginBaseTemplate.html")` must return
`<baseUrl>templates/common/LoginBaseTemplate.html?v=<configured value>`.

---

## 2. Empirically

Run **after** the source reading was written down, so the experiment could not colour it.
Instance: `openam-idp`, OpenAM 16.2.0-SNAPSHOT, Playwright 1.60.0 / Chromium, headless, fresh
`browser.newContext()` (cold HTTP cache), page `XUI/#login/`.

### `require.toUrl()` in the live app

| evaluated in the page | returned |
|---|---|
| `requirejs.version` | `2.3.7` |
| `requirejs.s.contexts._.config.baseUrl` | `./` |
| `typeof …config.urlArgs` | `function` (i.e. the string was normalised, as the source says) |
| `…config.urlArgs("someId","some/url.html")` | `?v=16.2.0-SNAPSHOT` |

`require.toUrl(...)` on ids the app really uses:

```
templates/common/LoginBaseTemplate.html     -> ./templates/common/LoginBaseTemplate.html?v=16.2.0-SNAPSHOT
templates/openam/RESTLoginTemplate.html     -> ./templates/openam/RESTLoginTemplate.html?v=16.2.0-SNAPSHOT
templates/openam/authn/DataStore1.html      -> ./templates/openam/authn/DataStore1.html?v=16.2.0-SNAPSHOT
partials/login/_Default.html                -> ./partials/login/_Default.html?v=16.2.0-SNAPSHOT
config/AppConfiguration                     -> ./config/AppConfiguration?v=16.2.0-SNAPSHOT
org/…/common/util/UIUtils                   -> ./org/…/common/util/UIUtils?v=16.2.0-SNAPSHOT
locales/en/translation.json                 -> ./locales/en/translation.json?v=16.2.0-SNAPSHOT
```

**`toUrl` applies `urlArgs`.** Same answer as the source.

### The network log

Every template and partial fetched during a cold load of `XUI/#login/` carried the parameter —
27 of them, all `200`, e.g.:

```
GET /openam/XUI/templates/common/LoginBaseTemplate.html?v=16.2.0-SNAPSHOT
GET /openam/XUI/templates/common/LoginHeaderTemplate.html?v=16.2.0-SNAPSHOT
GET /openam/XUI/templates/common/FooterTemplate.html?v=16.2.0-SNAPSHOT
GET /openam/XUI/templates/common/NavigationTemplate.html?v=16.2.0-SNAPSHOT
GET /openam/XUI/templates/openam/authn/DataStore1.html?v=16.2.0-SNAPSHOT
GET /openam/XUI/partials/login/_Default.html?v=16.2.0-SNAPSHOT
… (19 more partials/ and templates/)
```

Across the whole page load: **41 requests under `/XUI/`, 38 of them carrying
`?v=16.2.0-SNAPSHOT`.** The only three without it are the ones RequireJS never sees:

```
/openam/XUI/                              (the document itself)
/openam/XUI/libs/base64-1.0.0-min.js      (static <script src> in index.html)
/openam/XUI/libs/requirejs-2.3.7-min.js   (static <script src> in index.html)
```

That is the expected shape: anything RequireJS resolves gets the parameter, the two hard-coded
`<script src>` tags in `index.html` and the document do not.

### Agreement

**Source and experiment agree: `toUrl()` applies `urlArgs`.** Nothing to reconcile.

---

## Where `urlArgs` is configured

**It is configured — in `index.html`, not in any JS module.** A grep of
`openam-ui-ria/src/main/js` finds nothing because the config is set as the RequireJS *bootstrap
global*, before `require.js` is even loaded.

`openam-ui/openam-ui-ria/src/main/resources/index.html`, lines 22-27:

```html
<script type="text/javascript">
    var require = {
        urlArgs : "v=${version}",
        deps : ['main']
    };
</script>
<script src="libs/requirejs-2.3.7-min.js"></script>
```

RequireJS picks up a pre-existing global `require` object as its config, so this is a plain
`urlArgs` config — the same thing `require.config({urlArgs: …})` would do.

### How `${version}` is substituted

Two independent mechanisms both target the same token:

| mechanism | where | result |
|---|---|---|
| **Maven resource filtering** — `openam-ui-ria/pom.xml` declares `src/main/resources` with `<filtering>true</filtering>` | produces `target/classes/index.html` | `v=16.2.0-SNAPSHOT` |
| **Grunt `replace:buildNumber`** — `Gruntfile.js:224-238`, `from: "${version}"`, `to: targetVersion`, where `targetVersion = grunt.option("target-version") \|\| "dev"`; the pom passes `run build:production -- --target-version=${project.version}` (`pom.xml:325`) | produces `target/compiled/index.html` and the `-www.zip` | `v=16.2.0-SNAPSHOT` |

The Gruntfile states the intent outright:

> Include the version of AM in the index file.
> This is needed to force the browser to refetch JavaScript files when a new version of AM is deployed.

Observed values, so a migration can check its own output against them:

| artifact | `urlArgs` value |
|---|---|
| `src/main/resources/index.html` (source) | `v=${version}` (raw token) |
| `target/classes/index.html` | `v=16.2.0-SNAPSHOT` |
| `target/compiled/index.html` | `v=16.2.0-SNAPSHOT` |
| `target/openam-ui-ria-16.2.0-SNAPSHOT-www.zip` → `index.html` | `v=16.2.0-SNAPSHOT` |
| the war: `openam-server/target/OpenAM-16.2.0-SNAPSHOT/XUI/index.html` | `v=16.2.0-SNAPSHOT` |
| **served by the running instance** | `v=16.2.0-SNAPSHOT` |
| ⚠ `openam-ui-ria/target/XUI/index.html` | **`v=${version}` — token NOT substituted** |

That last row is a trap for anyone using `xui-deploy.sh`. The default (`./xui-deploy.sh` with no
argument) deploys the **`-www.zip`**, which is correctly substituted. But
`./xui-deploy.sh path/to/outDir` pointed at `openam-ui-ria/target/XUI` would deploy an
`index.html` whose `urlArgs` is the literal string `v=${version}` — every asset url would then
end in `?v=$%7Bversion%7D`. A migration must keep the substitution, and any spec pinning this
behaviour should read the expected value out of the deployed `index.html` rather than hard-code
it (see the assertion below), so this failure mode shows up as a wrong-value mismatch rather than
being silently accepted.

---

## Which code path actually fetches templates — and yes, it goes through `toUrl`

**Everything funnels through one function**, `fetchTemplate` in
`org/forgerock/commons/ui/common/util/UIUtils.js` (deployed copy, lines 26-32):

```js
function fetchTemplate(url) {
  return $.ajax({
    type: "GET",
    url: require.toUrl(url),
    dataType: "html"
  });
}
```

Callers, all in the same file:

| function | used by |
|---|---|
| `fetchAndSaveTemplate` | `preloadTemplates` / `preloadInitialTemplates` — the `templateUrls` in `config/AppConfiguration.js` |
| `fetchAndCompileTemplate` | `compileTemplate` → `renderTemplate` / `fillTemplateWithData` — every `AbstractView` render |
| `registerPartial` | `preloadPartial` / `preloadInitialPartials` — the `partialUrls` in `config/AppConfiguration.js` |

So there is exactly one network entry point for templates and partials, and its url is
`require.toUrl(url)`. **The cache-buster on a template fetch comes from RequireJS `urlArgs`, via
`toUrl`, and from nowhere else.**

Two things it is *not*:

- **Not the RequireJS `text!` plugin.** The XUI does not load templates as AMD modules; it fetches
  them with jQuery and only borrows RequireJS's url resolution.
- **Not jQuery.** `$.ajax` adds its own `_=<timestamp>` only when `cache === false`, and jQuery
  defaults `cache` to `false` only for `script`/`jsonp` dataTypes. Here `dataType: "html"` and no
  `cache` option, so jQuery adds nothing. Confirmed in the deployed `libs/jquery-3.7.1-min.js`,
  whose only `_=` site is guarded by `!1===v.cache`. Confirmed empirically too: no observed
  template url carried a `_=` parameter.

Note also `obj.templates[...]` — an in-memory map that memoises each template after its first
fetch. **A template is fetched at most once per page instance**; navigating away and back inside
the SPA does not refetch it. This matters for the spec (see below).

---

## The assertion to pin today's behaviour

### Which template

**`templates/common/LoginBaseTemplate.html`.**

- It is fetched on the plain `XUI/#login/` load, which every other spec in this suite already
  drives, so it needs no fixture, no realm and no auth-chain setup.
- It is a real view template rendered through `AbstractView` → `compileTemplate` →
  `fetchTemplate`, i.e. the genuine runtime path, not a preload.
- It is route-driven, not config-driven, so it does not depend on `AppConfiguration`'s
  `templateUrls`/`partialUrls` lists staying as they are.

Deliberately *not* chosen: `templates/openam/authn/DataStore1.html` — the filename is the auth
*stage* name, so it changes if the realm's auth chain changes. And not
`templates/openam/RESTLoginTemplate.html` — despite being `RESTLoginView`'s declared `template`,
**it is never fetched** on a default login; the stage template is used instead. (Observed: it is
absent from the network log.)

### The assertion

```js
test("runtime template fetches carry the RequireJS urlArgs cache-buster", async ({ page }) => {
    // Arm the listener BEFORE navigating — the template is fetched during the initial load.
    const templateRequests = [];
    page.on("request", (request) => {
        if (request.url().includes("/XUI/templates/common/LoginBaseTemplate.html")) {
            templateRequests.push(request.url());
        }
    });

    await page.goto(`${XUI_BASE}/#login/`);
    await expect(page.locator(SEL.usernameInput)).toBeVisible();

    // The cache-buster is the build version. Read it from the deployed index.html rather than
    // hard-coding it, so a version bump does not break the spec — but a *missing* or
    // unsubstituted value still fails.
    const indexHtml = await (await page.request.get(`${XUI_BASE}/index.html`)).text();
    const version = indexHtml.match(/urlArgs\s*:\s*"v=([^"]+)"/)[1];

    expect(templateRequests.length).toBeGreaterThan(0);
    for (const url of templateRequests) {
        expect(url).toBe(
            `${XUI_BASE}/templates/common/LoginBaseTemplate.html?v=${version}`);
    }
});
```

Worth pairing with the direct `toUrl` contract, which is what the migration actually has to
preserve and is a one-liner:

```js
const resolved = await page.evaluate(() =>
    require.toUrl("templates/common/LoginBaseTemplate.html"));
expect(resolved).toBe(`./templates/common/LoginBaseTemplate.html?v=${version}`);
```

(`./` is the leading `baseUrl`, which is `./` in the deployed config.)

**Verified.** The block above was executed verbatim against the running instance three times on
fresh contexts: `PASS, PASS, PASS`, `version=16.2.0-SNAPSHOT`, one matching request each run.

### Is it stable, or does it flake on a cold cache?

**Stable.** Measured, all against `templates/common/LoginBaseTemplate.html`:

| scenario | requests Playwright reported |
|---|---|
| cold `browser.newContext()` (Playwright's default per test) | **1** ✔ |
| a second, separate cold context | **1** ✔ |
| warm HTTP cache — new page in a context that already loaded the XUI | **1** ✔ |
| warm + `page.reload()` — two full loads in one context | **2** (one per load, both matching) |
| in-SPA hash navigation away and back, same page instance | **1** — *not refetched* |

The reason cold vs. warm does not matter: the server sends
`cache-control: public, max-age=2592000` with an `ETag`, so a warm context may well serve the
template from cache — but **Chromium still reports the request to Playwright**, so the `request`
event fires either way. The assertion is on the request url, not on a `200` from the origin, so
cache state is irrelevant. Asserting on a *response* status would be the flaky formulation; do
not do that.

The two ways to actually break it, both avoidable and both in the snippet above:

1. **Arming the listener after `page.goto`.** The template is fetched during the initial load; a
   listener attached afterwards sees nothing. Attach first.
2. **Asserting after an in-SPA navigation.** `UIUtils.obj.templates` memoises the template, so
   navigating away and back produces no second fetch. Assert on the initial load.

Using `expect(...).toBeGreaterThan(0)` plus a loop over every captured url, rather than
`toHaveLength(1)`, keeps the spec honest if a future build legitimately renders the base template
twice — it still fails if any fetch is missing the parameter.

---

## Summary for the migration

| | |
|---|---|
| does `toUrl()` apply `urlArgs`? | **yes** — `nameToUrl`'s only return applies it; `toUrl` routes through it |
| where is `urlArgs` set? | `openam-ui-ria/src/main/resources/index.html` as `urlArgs : "v=${version}"`, substituted to the AM version by Maven resource filtering and by Grunt `replace:buildNumber` (`--target-version`) |
| what fetches templates? | `UIUtils.fetchTemplate` → `$.ajax({url: require.toUrl(url)})` — the single entry point |
| what must the new build preserve? | every RequireJS-resolved url, templates included, ends in `?v=<AM version>`; the two `<script src>` tags in `index.html` and the document do not |
| observed today | 38 of 41 `/XUI/` requests carry `?v=16.2.0-SNAPSHOT` |

---

## Incidental finding: `e2e/local/lib.sh` fails in a non-interactive shell

Not part of this question, but it blocked the experiment and will block CI or anyone scripting the
harness.

`am_version()` in `e2e/local/lib.sh`:

```bash
am_version() {
    sed -n 's/.*<version>\(.*\)<\/version>.*/\1/p' "${REPO_ROOT}/pom.xml" | head -1
}
```

`lib.sh` sets `set -euo pipefail`. `head -1` exits after the first of the 281 lines `sed` emits
from the 2 488-line root pom, `sed` takes `SIGPIPE`, and `pipefail` propagates **141**, which
`set -e` turns into a silent abort of `openam-up.sh` at `VERSION="$(am_version)"` — no output at
all, exit 141. Reproduced every time when run non-interactively (backgrounded / output
redirected); it happens not to trigger in an interactive terminal, which is presumably why it has
survived.

Worked around here without touching the repo, by putting a draining `head` shim ahead on `PATH`.
A real fix would be to drop the pipe, e.g.
`sed -n '…{p;q}' "${REPO_ROOT}/pom.xml"`, which quits `sed` itself after the first match.
