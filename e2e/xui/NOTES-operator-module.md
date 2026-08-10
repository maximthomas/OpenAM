# Operator-supplied XUI module — what a Playwright spec can rely on

Findings verified empirically against `openam-idp` (OpenAM 16.2.0-SNAPSHOT) on 2026-08-10, with six
throwaway Chromium runs against `XUI/#login/` in the root realm, as `demo` and as `amadmin`. The
instance was returned to its pristine state afterwards and a plain login re-confirmed — see Restore.

Companion to `NOTES-theming.md`, which documents the deployed-config edit/restore mechanism this note
reuses. Read that one first for the Tomcat cache and the `docker exec` write recipe.

## The question

`config/AppConfiguration.js:23` names a module by ID:

```js
moduleClass: "org/forgerock/commons/ui/common/main/SessionManager",
configuration: {
    loginHelperClass: "org/forgerock/openam/ui/user/login/RESTLoginHelper"
}
```

A spec has to prove that a module an operator adds to the deployed `/XUI` and names there is *actually
used* — not merely that the app still works.

## 1. The contract — measured, and narrower than the name suggests

**`loginHelperClass` is consumed by exactly one module**: `org/forgerock/commons/ui/common/main/SessionManager`
(commons, shipped inside the `main.js` bundle and also present unbundled at
`org/forgerock/commons/ui/common/main/SessionManager.js`). It resolves the ID through
`ModuleLoader.load` on **every** call and uses **three** members:

| member | signature | called from | when |
| --- | --- | --- | --- |
| `login` | `(params, successCallback, errorCallback)` | `config/process/CommonConfig.js` → `EVENT_LOGIN_REQUEST` | login form submit |
| `logout` | `(successCallback, errorCallback)` | `config/process/AMConfig.js` → `EVENT_LOGOUT` (override), `RouteTo.js` | `#logout/` |
| `getLoggedUser` | `(successCallback, errorCallback)` | `config/process/CommonConfig.js` → `EVENT_APP_INITIALIZED`, `RESTLoginView.js:144` | **every page load, before the login form renders** |

That last row is the most useful fact in this note: the configured module is loaded and called on a
plain, anonymous `#login/` page load. **A spec does not have to log in to prove the module was
resolved** — though it does have to log in to prove `login` went through it.

### The other RESTLoginHelper members are NOT part of this contract

`setSuccessURL`, `filterUrlParams` and `getSuccessfulLoginUrlParams` are real members of
`RESTLoginHelper.js`, but every caller requires the module **directly by path**, never through
`loginHelperClass`:

| member | callers (all direct `define([... "org/forgerock/openam/ui/user/login/RESTLoginHelper"])`) |
| --- | --- |
| `setSuccessURL` | `RESTLoginView.js:149` (and `RESTLoginHelper.login` internally, via `this`) |
| `filterUrlParams` | `RESTLoginView.js:307`, `RESTLogoutView.js:43`, `SessionExpiredView.js:42` |
| `getSuccessfulLoginUrlParams` | `RESTLogoutView.js:43`, `SessionExpiredView.js:42` |

Direct requirers of `RESTLoginHelper` are `main.js`, `RESTLoginView.js`, `RESTLogoutView.js`,
`RESTConfirmLoginView.js`, `SessionExpiredView.js`. **Pointing `loginHelperClass` elsewhere does not
redirect any of them** — they keep getting the shipped `RESTLoginHelper`. Do not let the spec (or its
name) claim it swaps "the login helper" wholesale; it swaps SessionManager's three entry points.

### `AbstractConfigurationAware` is not required of the module

`RESTLoginHelper` is `new AbstractConfigurationAware()`, but nothing pushes configuration into it:
`ProcessConfiguration` only calls `updateConfigurationCallback` on `moduleClass` entries, and the
helper is named in a *configuration value*, not as a `moduleClass`. A plain object satisfies the
contract. (The stand-in below inherits from the real helper anyway, so the point is moot for it.)

### Trap: `login` must declare exactly three formal parameters

`SessionManager.login` does:

```js
return ModuleLoader.load(obj.configuration.loginHelperClass).then(function (helper) {
    return ModuleLoader.promiseWrapper(_.bind(_.curry(helper.login)(params), helper), { ... });
});
```

`underscore` is mapped to `lodash` (`libs/lodash-3.10.1-min`) in the RequireJS config, and lodash's
`_.curry(fn)` takes its arity from `fn.length`. A `login` written as `function () { … arguments … }`
has `length` 0, so `_.curry(login)(params)` **invokes immediately with only `params`** and the
callbacks are never passed.

**Measured**: with an arity-0 `login`, the module still loads and `getLoggedUser` still fires, but the
form submit goes nowhere — the router never leaves `#login`, and `pageerror` count is **0**. It fails
*silently*. Any stand-in must spell out `(params, successCallback, errorCallback)`.

## 2. The stand-in module — the source that was verified working

Deployed to `<XUI>/config/E2EStandInLoginHelper.js`. It delegates everything to the shipped
`RESTLoginHelper` and records that it was loaded and called, so it can prove itself without changing
any observable login behaviour. This is the exact text that ran.

```js
/**
 * E2E stand-in login helper.
 *
 * An operator-supplied AMD module, added to the deployed /XUI and named by
 * AppConfiguration's `loginHelperClass`. It delegates every member of the login
 * helper contract to the shipped RESTLoginHelper and records that it was loaded
 * and called, so a test can prove the configured module is the one the app used.
 */
define([
    "org/forgerock/openam/ui/user/login/RESTLoginHelper"
], function (RESTLoginHelper) {
    var marker = window.__e2eLoginHelper = {
        loaded: true,
        moduleId: "config/E2EStandInLoginHelper",
        delegatesTo: "org/forgerock/openam/ui/user/login/RESTLoginHelper",
        calls: []
    };

    // Inherit every other member (setSuccessURL, filterUrlParams,
    // getSuccessfulLoginUrlParams, the AbstractConfigurationAware bits) unchanged.
    var standIn = Object.create(RESTLoginHelper);

    // SessionManager does `_.curry(helper.login)(params)`, and lodash's curry reads
    // `fn.length`. These three must declare exactly the arity the real members declare.
    standIn.login = function (params, successCallback, errorCallback) {
        marker.calls.push("login");
        return RESTLoginHelper.login(params, successCallback, errorCallback);
    };

    standIn.logout = function (successCallback, errorCallback) {
        marker.calls.push("logout");
        return RESTLoginHelper.logout(successCallback, errorCallback);
    };

    standIn.getLoggedUser = function (successCallback, errorCallback) {
        marker.calls.push("getLoggedUser");
        return RESTLoginHelper.getLoggedUser(successCallback, errorCallback);
    };

    return standIn;
});
```

Three deliberate choices:

- **AMD, not ESM.** The deployed tree is loaded by RequireJS 2.3.7. An `export` would be a syntax
  error inside the `define` shim and the module would never register.
- **Delegate with `RESTLoginHelper.login(...)`, not `.call(this, ...)`.** The real `login` does
  `var self = this; … self.setSuccessURL(...)`, and SessionManager binds the helper as `this`. Calling
  through the real object keeps `this` pointing at the real helper, so `setSuccessURL` resolves even
  though the stand-in never declares it. (`Object.create` would also make it resolve, but relying on
  the prototype chain for the *product's* internal `this` is a sharper edge than it needs to be.)
- **`Object.create(RESTLoginHelper)`** so any member this note has not enumerated is inherited rather
  than lost, which is what makes this the *cheapest honest* stand-in rather than a mock.

## 3. Observing the marker — use the window property, and assert the call, not the load

| option | verdict |
| --- | --- |
| **`window.__e2eLoginHelper.calls` contains `"login"`** | ✔ **use this** |
| `window.__e2eLoginHelper.loaded === true` | weaker — proves the module was *loaded*, not that the app *used* it. A loader that resolved the module and then ignored it passes. Keep it as a secondary assertion, not the primary one. |
| console message | ✘ brittle. Needs the listener attached before `goto`; messages are lost across a document navigation; `console` on `XUI/#login/` already carries two unrelated errors (see NOTES-theming), so the channel is noisy; and the assertion becomes string-matching on formatting. |
| the network request for the module URL | ✘ **never assert this.** It is pure mechanism, and it is precisely what D1 removes — see §8. Record it as a baseline note only. |
| an observable behaviour difference (stand-in rejects/rewrites the login) | ✘ for this spec. It is the strongest possible proof of use, but it makes a bug in the stand-in indistinguishable from a bug in the app, and it is the one variant that can lock the console out. Not worth it when a marker is available. |

Why the window property is least brittle: it is written by the operator module's own code, so nothing
but that module executing can satisfy it; it is readable at any point on the same document with no
listener that must be installed beforehand; and it says nothing about *how* the module was resolved,
so a build-time registry that resolves the same module ID satisfies it unchanged.

Measured values, for reference:

| moment | `window.__e2eLoginHelper` |
| --- | --- |
| pristine config, any moment | `null` (the property is never created) |
| stand-in, on `#login/` before any credential | `{loaded:true, moduleId:"config/E2EStandInLoginHelper", calls:["getLoggedUser"]}` |
| stand-in, after a successful login | `calls:["getLoggedUser","login"]` |
| stand-in, after `#logout/` | `calls:["getLoggedUser","login","logout"]` |

Spec-authoring notes:

- **Assert `calls` *contains* `"login"`; never assert the array equals a literal.** `getLoggedUser`
  fires at `EVENT_APP_INITIALIZED` and again from `RESTLoginView`, and its count is not contractual.
- The marker is per-document: a full `page.reload()` re-runs the module and resets `calls` to `[]`.
  Read it on the document you exercised.
- Prefer `expect.poll` on the marker over a fixed wait. `calls.push("login")` happens when
  SessionManager invokes the member, which is before the login outcome is known, so it is available
  early — but polling avoids coupling to that ordering.
- **Guard against silent degradation.** If `window.__e2eLoginHelper` is `null`, fail loudly with a
  message naming the fixture. Otherwise a spec whose fixture silently failed to apply degrades into
  "login still works", which proves nothing — the same trap NOTES-theming records for the
  `ThemeConfiguration` route handler.
- Post-login routing on this instance lands on `/openam/XUI/` with an **empty** hash for both `demo`
  and `amadmin` (identical with and without the stand-in). `waitForURL(u => !u.hash.startsWith("#login"))`
  is satisfied by that empty hash, so do not additionally assume a `#profile/...` or `#realms` hash
  without waiting for it separately.

## 4. Where the file goes, and the module ID

| | |
| --- | --- |
| container | `openam-idp` |
| deployed root | `/usr/local/tomcat/webapps/openam/XUI` |
| file | `<root>/config/E2EStandInLoginHelper.js` |
| **module ID** | **`config/E2EStandInLoginHelper`** — the path under the webapp root, minus `.js` |
| resolved URL | `/openam/XUI/config/E2EStandInLoginHelper.js?v=16.2.0-SNAPSHOT` (measured, HTTP 200) |
| owner/mode as created | `644 openam:root` (the file is new; `docker exec` runs as `uid=1001(openam) gid=0(root)`). The surrounding `config/` files are `640` — the difference is cosmetic and Tomcat does not care. |

`baseUrl` is the directory of `index.html`, i.e. `/openam/XUI/`. `index.html` sets only
`var require = { urlArgs: "v=16.2.0-SNAPSHOT", deps: ["main"] }` and loads
`libs/requirejs-2.3.7-min.js` with no `data-main` and no `baseUrl`, so RequireJS defaults to the page's
directory. `urlArgs` appends the fixed build version to every module URL.

Any path under the webapp works; `config/` was chosen because that is where the other operator-editable
modules (`AppConfiguration.js`, `ThemeConfiguration.js`) already live.

### Trap: a bundled module ID cannot be overridden by dropping a file at its path

`main.js` (543 KB) is an r.js bundle that contains `define("org/forgerock/openam/ui/user/login/RESTLoginHelper", …)`
and `define("org/forgerock/commons/ui/common/main/SessionManager", …)` among many others. RequireJS
never fetches a module that is already defined.

**Measured**: across every run, the standalone file
`XUI/org/forgerock/openam/ui/user/login/RESTLoginHelper.js` — which exists on disk — was **never
requested**. The only module fetched over the wire in the stand-in runs was the stand-in itself.

So an operator module must use a **new** ID. Overwriting the deployed `RESTLoginHelper.js` in place
would have no effect whatsoever, and a spec that tried that would pass for the wrong reason.

## 5. Editing `AppConfiguration.js`, and what reload is needed

`AppConfiguration.js` is fetched separately over the network — measured, exactly one request per page
load: `/XUI/config/AppConfiguration.js?v=16.2.0-SNAPSHOT`. It is not inlined into `main.js`.

The edit is one string:

```diff
-        loginHelperClass: "org/forgerock/openam/ui/user/login/RESTLoginHelper"
+        loginHelperClass: "config/E2EStandInLoginHelper"
```

| question | answer |
| --- | --- |
| how to write | `docker exec -i openam-idp sh -c 'cat > "$1"' sh <path> < newfile` — truncates in place, preserving `640 openam:root`. `docker cp` writes a root-owned file the Tomcat process cannot read. |
| Tomcat restart | **no** |
| container restart | **no** |
| redeploy / `xui-deploy.sh` | **no** — wrong granularity, and it needs a Maven `-www.zip` that may not exist |
| server-side staleness | see below — poll, never sleep |
| browser cache | `Cache-Control: public, max-age=2592000`. A **fresh `browser.newContext()`** is required; `page.reload()` in a context that already loaded the page is **not** enough. |
| URL cache-bust | not available — `urlArgs` is the fixed build version, identical before and after |

### Refinement to NOTES-theming's 5 s cache window

NOTES-theming records "Tomcat serves the OLD bytes for ~5 s after a write". Measured more precisely
here with a throwaway file: **the 5 s TTL runs from the last GET that loaded the cache entry, not from
the write.**

```
write VERSION_ONE; GET -> VERSION_ONE      (cache entry loaded here)
write VERSION_TWO
t+0s..t+4s -> VERSION_ONE                  (stale)
t+5s..     -> VERSION_TWO                  (fresh)
```

Consequently, in all six write→poll cycles in this session the fresh bytes were served on the **first**
poll (<50 ms), because each write happened well over 5 s after anything had read that file. The
staleness only bites when a page load precedes the write closely — which is exactly the
setup-after-a-previous-test case. **Keep polling**: it is cheap, it is correct in both cases, and the
timing is not something a spec should depend on.

### Ordering rule — this one is load-bearing

**Place the module and confirm it is served *before* flipping `AppConfiguration.js`. On teardown,
restore `AppConfiguration.js` *before* removing the module.**

Measured consequence of getting it wrong — `loginHelperClass` naming an ID that does not resolve:

| | |
| --- | --- |
| module URL | HTTP 404 |
| `pageerror` | `Error: Script error for "config/E2ENoSuchModule"` (requirejs.org/docs/errors.html#scripterror) |
| login form | **never renders** — `#idToken1` not visible after 30 s |
| marker | n/a, nothing loaded |

This is not a degraded login, it is a dead application: `EVENT_APP_INITIALIZED` calls
`SessionManager.getLoggedUser` before `Router.init()`, so a failed `ModuleLoader.load` stops the app
booting at all. That window is the lockout risk in this whole exercise, and the ordering rule closes
it. It is also why the teardown must not be "remove everything in parallel".

## 6. Does login still complete with the stand-in? — yes

Full end-to-end, verified for both users, with the stand-in named in `AppConfiguration.js`:

| run | login form | left `#login` | `idFromSession` | `#logout/` | after logout | `pageerror` |
| --- | --- | --- | --- | --- | --- | --- |
| `demo` / `changeit` | visible | yes | `200 {id:"demo", realm:"/"}` | `#loggedOut/` | `401` | 0 |
| `amadmin` / `ampassword` | visible | yes | `200 {id:"amadmin", realm:"/"}` | `#loggedOut/` | `401` | 0 |

`idFromSession` is asserted from inside the page's own cookie jar, so it is server-side proof of a real
session rather than a claim about the DOM. The navbar rendered (`#navbarBrand` count 1) in every run.
No stand-in iteration was needed beyond getting the arity right; the arity-0 variant in §1 was written
deliberately as a negative control, not as a failed attempt.

## 7. Restore — procedure and confirmation

Backup taken with `docker cp` **before the first edit**:

```sh
docker cp openam-idp:/usr/local/tomcat/webapps/openam/XUI/config/AppConfiguration.js ./AppConfiguration.js.orig
```

Pristine: sha256 `343bee5cb9798b336b9ddf598352b9222d2ead43b63139c14d66bd6040b8cc87`, 9328 bytes,
`640 openam:root`.

Restore, in this order:

```sh
X=/usr/local/tomcat/webapps/openam/XUI
# 1. byte-restore the config FIRST (see the ordering rule in §5)
docker exec -i openam-idp sh -c 'cat > "$1"' sh $X/config/AppConfiguration.js < AppConfiguration.js.orig
# 2. then remove the added module — it is a new file, so this is a removal, not a byte restore
docker exec openam-idp rm -f $X/config/E2EStandInLoginHelper.js
# 3. poll until the pristine config is served and the module 404s (Tomcat caches the hit as readily as the miss)
```

**Current state — confirmed:**

| check | result |
| --- | --- |
| `AppConfiguration.js` sha256, container | `343bee5c…cc87` — **identical to the host backup** |
| mode / owner | `-rw-r----- openam root`, 9328 bytes |
| `loginHelperClass` as served over HTTP | `"org/forgerock/openam/ui/user/login/RESTLoginHelper"` |
| `config/` directory listing | back to the 9 shipped entries; no `E2E*` |
| `find $X -name 'E2E*' -o -name '*StandIn*'` | empty |
| `GET config/E2EStandInLoginHelper.js` | **404** |
| `GET /openam/XUI/` | **200** |
| plain login, `demo` | form visible → left `#login` → `idFromSession 200 demo` → `#logout/` → `401`, marker `null`, `pageerror` 0 |
| plain login, `amadmin` | form visible → left `#login` → `idFromSession 200 amadmin` → `#logout/` → `401`, marker `null`, `pageerror` 0 |

`local/openam-reset.sh` was **not** needed and was not run. The three temporary files
(`config/E2EStandInLoginHelper.js`, `config/E2EArity.js`, `config/E2ECacheProbe.js`) were all removed.

## 8. Phase-2 (D1) dependency — what would break

D1 replaces RequireJS path resolution with a build-time registry. This spec is the baseline for the
fallback path that has to keep working, so the dependencies must be stated exactly.

**Depends on today's mechanism (would break under a naive D1):**

1. **A module ID resolving to a file under the deployed webapp.** `config/E2EStandInLoginHelper` works
   today *only* because RequireJS turns the ID into `GET /openam/XUI/config/E2EStandInLoginHelper.js`
   at runtime. A build-time registry knows only the modules present at build time. An operator file
   dropped into the deployed tree afterwards is not in the registry, so the ID does not resolve — and
   §5 measured what an unresolvable `loginHelperClass` does: **the application does not boot at all**,
   no login form, one `pageerror`. That is the regression to guard against, and it is severe.
2. **`config/AppConfiguration.js` staying a separately fetched module at a stable URL.** Measured: one
   request per page load, distinct from `main.js`. If Vite inlines it into the bundle, editing the
   deployed file stops having any effect and the fixture must move to whatever replaces it. (Same
   dependency NOTES-theming records for `ThemeConfiguration.js`.)
3. **The stand-in being able to `define([...])` a dependency on a bundled module ID.**
   `Object.create(RESTLoginHelper)` requires `org/forgerock/openam/ui/user/login/RESTLoginHelper` to be
   requirable *by ID* from a module that was not part of the build. Under a bundler the shipped
   helper may not have a stable external name at all. If it does not, the delegating stand-in is
   impossible and the fixture has to fall back to a free-standing implementation of the three members
   — which is a materially worse test, because it stops proving the real flow still works.
4. **`_.curry` reading `fn.length`.** Any build step that transpiles the *operator's* module through
   Babel to ES5 rest-args, or wraps it, changes `login.length` and silently breaks login (§1). This is
   invisible in source review.

**Does NOT depend on the mechanism (D1-safe as written):**

- The `window.__e2eLoginHelper` assertion. It names an observable the operator module itself creates
  and says nothing about resolution, so a registry that resolves the same ID satisfies it unchanged.
- The end-to-end login/logout assertions and `idFromSession`.
- The contract itself — three members, and the arity of `login` — which lives in commons
  `SessionManager`, not in the loader.

**Explicitly not to be asserted**, because a better implementation would legitimately fail it: the
`GET .../config/E2EStandInLoginHelper.js?v=…` request, its `200`, its count, and the fact that
`RESTLoginHelper.js` is *not* fetched. Record these as baseline notes (done, §4) and let the transport
change. If D1 keeps an operator-extension path at all, the spec should assert that a module named in
`loginHelperClass` is loaded and called — not that it arrived over HTTP from a path.

**The question D1 has to answer**, which this note cannot: *how does an operator add a module to a
deployed instance once resolution is build-time?* Today the answer is "drop a `.js` file in and name
it". If D1 has no replacement, the capability is removed, not migrated — and this spec is the thing
that will say so out loud.

## Fixtures the spec needs

`NOTES-theming.md` flags task 1.11 as the forcing function for extracting the deployed-`/XUI` helpers
out of `xui-theming.spec.mjs` into `common/deployed-xui-commons.mjs`. This work confirms it. The
helpers needed here, essentially unchanged: `placeDeployedFile`, `waitForServed`, `readDeployedConfig`,
`writeDeployedConfig`, `deployedSha256`, `deployedPathExists`, plus `AM_CONTAINER` / `XUI_ROOT`.

Two things this spec needs that the theming spec did not:

- **The ordering rule of §5** — module in and served before the config flip; config restored before the
  module removal. Encode it in the fixture, not in a comment, because the failure mode is a dead app.
- **A byte-restore *and* a removal in the same teardown**, nested so that a failure in either still runs
  the other. Restore the config first.

Unlike theming, `context.route(...).fulfill(...)` is **not** an option here: the point of the exercise
is that the module is resolvable *from the deployed webapp*. Intercepting the module response would
prove RequireJS can be fed bytes, which is not the requirement, and would prove nothing about the
operator-extension path D1 threatens. This spec must write to the deployed tree.
