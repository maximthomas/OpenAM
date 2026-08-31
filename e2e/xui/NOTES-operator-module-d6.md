# Task 6.6 spike — porting 1.11's operator-supplied-module spec to a Vite-built, D6-configured XUI

Measured 2026-08-31 against the running `openam-idp` container (`OpenAM-16.2.0-SNAPSHOT`, build
ceda844487) at `http://openam.example.org:8080/openam/XUI`. Everything below was run, not reasoned
from the sources; where something was not measured it says so.

**Nothing in this file has been applied to `xui/xui-operator-module.spec.mjs` or to
`fixtures/E2EStandInLoginHelper.js`.** Both are untouched. `xui/NOTES-operator-module.md` — 1.11's
tracked record of the AMD/Grunt baseline — is untouched too.

**Container state on entry and on exit: the Grunt/RequireJS `/XUI` baked into the war.** See §9.

---

## 0. WHAT WAS PROVED, IN ONE TABLE

The capability 1.11 exists to defend — *an operator writes a module, drops it into the deployed
webapp, names it in configuration, and the XUI loads and uses it* — **survives D1+D6 intact**, and
was demonstrated by hand end to end before any spec was edited.

| step | result |
|---|---|
| Vite tree built from a source `AppConfiguration` naming `config/E2EStandInLoginHelper` | ✓ exit 0, 13.1 s |
| that tree deployed to the container, ESM stand-in dropped at `/XUI/config/E2EStandInLoginHelper.js` | ✓ 0.87 s |
| the loader fetched it, at the url §14.3 of `NOTES-module-registry.md` predicted | ✓ `200 http://openam.example.org:8080/openam/XUI/config/E2EStandInLoginHelper.js?v=dev` |
| `window.__e2eLoginHelper` observable on an anonymous page load, with `getLoggedUser` recorded | ✓ |
| login through the real form completed: left `#login`, landed `#profile/details` | ✓ `login` recorded |
| AM issued a real session for the right user | ✓ `idFromSession` → `demo` |
| logout completed: reached `#loggedOut/`, session gone | ✓ `logout` recorded, `idFromSession` → null |
| console errors identical to the shipped-helper control run | ✓ (one 404, one 401 — both present in the control) |

---

## 1. HOW THE D6 CONFIGURATION EDIT IS ACTUALLY MADE — AND WHAT IT COSTS

### 1.1 The old in-place edit has nothing left to act on. Confirmed from the built tree.

The spec's fixture reads and rewrites `${XUI_ROOT}/config/AppConfiguration.js` in the container.
Under a Vite build that file is not deployed at all:

```
$ ls -d openam-ui/openam-ui-ria/target/compiled/config
ls: cannot access '.../target/compiled/config': No such file or directory

$ curl -o /dev/null -w '%{http_code}' .../XUI/config/AppConfiguration.js     # Vite tree deployed
404
```

`target/compiled/` has 15 top-level entries and `config/` is not one of them — no `config/`, no
`org/`, no `components/`, no `store/`. `src/main/js/config/AppConfiguration.js` is reached by 6.1's
AM glob (`/src/main/js/**/*.{js,jsx,jsm}`) like any other source module, so it is bundled. In the
control build it landed in `assets/i18nManager-Co6QgOIE.js`.

So `readDeployedFile(APP_CONFIG_PATH)` throws before the fixture can do anything. This is precisely
task 6.6's "the fixture has nothing left to edit", and it is **not** a D1 regression.

### 1.2 The operator's edit is now: edit source, rebuild, redeploy.

```
$ vi openam-ui/openam-ui-ria/src/main/js/config/AppConfiguration.js   # loginHelperClass: "config/E2EStandInLoginHelper"
$ npm run build:production
$ OpenAM/e2e/local/xui-deploy.sh openam-ui/openam-ui-ria/target/compiled
```

### 1.3 Measured wall-clock of the rebuild-and-redeploy cycle

| step | wall clock | notes |
|---|---|---|
| `npm run build:production` (warm `node_modules`, no clean) | **13.1 s** (`✓ built in 12.35s`) | exit 0, 1523 modules, no new warnings |
| `local/xui-deploy.sh <dir>` into the running container | **0.87 s** | 901 files; `rm -rf` + `docker cp` + `chown`, no Tomcat restart |
| **total per config change** | **≈ 14 s** | |

Two things a spec has to live with beyond the 14 seconds:

- **The build is not idempotent in its output names.** Changing that one string changed the emitted
  entry chunk from `assets/main-DN_XC4oM.js` to `assets/main-r9j2ic-0.js` and the config chunk from
  `i18nManager-Co6QgOIE.js` to `i18nManager-CoRSbdGm.js`, and `main.js` (the stub `index.html`
  loads) is rewritten to name the new chunk. **A config edit is a whole-tree redeploy**, not a
  one-file swap.
- **The whole tree is replaced, not merged** (`xui-deploy.sh` `rm -rf`s `$XUI_PATH` first, and that
  is deliberate). So a redeploy also *deletes* anything the operator had dropped into the deployed
  tree — including the stand-in. Ordering below in §3 depends on this.

### 1.4 One datum for anyone tempted to patch the bundle instead

The literal `"org/forgerock/openam/ui/user/login/RESTLoginHelper"` occurs **exactly once** as a
quoted string across all 592 emitted asset chunks, in the chunk AppConfiguration was bundled into.
So a post-build `sed` on the deployed bundle is mechanically possible and would leave the
content-hashed filename lying about its content. Measured, not recommended; see §2 option (d).

---

## 2. CAN THE SPEC MAKE THAT EDIT? — THE JUDGMENT CALL

All three options are viable and were costed against what was actually measured. My recommendation
is **(b)**, with **(c)** as the fallback if (b)'s precondition proves too irritating in CI.

> **DECIDED (change owner, 2026-08-31): the precondition FAILS LOUDLY. It does not skip.**
> A run against a tree that was not built for the fixture is a red `npm run test:xui`, with a
> remediation message naming the build flag — never a green run with a skipped test. This resolves
> the only open question (b) had; see the *Against* bullet below and §10 item 1.

### (a) The spec drives the source edit and the build

The Playwright fixture would `writeFileSync` into
`openam-ui/openam-ui-ria/src/main/js/config/AppConfiguration.js`, shell out to
`npm run build:production`, then call `xui-deploy.sh`.

- **For.** It is the only option that is honest about what a D6 operator does end to end, and it
  keeps the whole thing in one file with one teardown.
- **Against, and this is the decisive one.** It changes what the spec *is*. Today's spec mutates a
  **deployed artefact** — recoverable in seconds, and its blast radius is one container. (a) mutates
  **tracked product source** and then overwrites `target/`. A run killed between the write and the
  restore leaves a dirty working tree that the developer will find by `git status`, or worse commit;
  and it destroys whatever `target/compiled` held, which is not the spec's to destroy. It also makes
  the e2e suite depend on a working `npm` toolchain in the UI module, which `OpenAM/e2e` does not
  otherwise need — the suite currently talks only to a deployed instance over HTTP and `docker exec`.
- **Cost.** +14 s per test *file*, or +28 s if the two tests do not share a worker fixture. Tolerable.
- The 14 s is not the objection. The objection is that a test that edits source and runs a build is a
  build-system test wearing a browser test's clothes.

### (b) The build is a precondition the spec asserts; a human or CI performs it — **RECOMMENDED**

The spec asserts, and fails fast with a remediation message, that the deployed instance is already
serving a tree whose configuration names the fixture's module id. It then does only what it always
did on top: place the module, run the browser assertions, remove the module.

- **How the assertion is actually made.** The deployed `AppConfiguration.js` is gone, so the check
  cannot read it. Two probes are available and both were measured working:
  1. **the negative one, cheap and exact** — with the module absent the application does not boot at
     all (§4). So `GET <XUI>/config/<id>.js` returning 404 while the tree is configured for it is a
     *guaranteed* dead console, which is why the check must come before anything is placed.
  2. **the positive one** — after placing the module, poll for `window.__e2eLoginHelper`. If the
     deployed tree was *not* built with the fixture's id, the marker never appears and
     `expectModuleRan` already fails by name with a message that says so. That is 1.11's existing
     `expectModuleRan`, unchanged, doing exactly the job it was written for.
  So (b) needs no new mechanism — it needs a hard-failing guard and a good message. Per the
  decision above the guard is an assertion, not a `test.skip()`: probe 1 fails the run outright when
  the tree is not configured for the fixture, and its message must name the build flag and the
  redeploy command so the reader can fix it in one step.
- **For.** The spec stays a browser test. It never touches source, never runs a build, never writes
  outside the container. Teardown returns to one artefact (§7). The 14 s moves to the place that was
  going to pay it anyway — whoever built the tree under test.
- **Against.** It is no longer self-contained: `npm run test:xui` against an arbitrary deployed
  instance goes **red**, and someone has to remember the build flag. That is the accepted cost of the
  decision above. The alternative — skipping — was rejected precisely because a skip nobody reads is
  how a capability quietly stops being tested; a red run is noisy on ordinary instances but it can
  only ever be fixed by building the tree the spec needs, which is the behaviour we want. Whoever
  wires this must make sure the failure message carries the remediation, or the noise becomes a
  puzzle instead of an instruction.
- **Why it still wins.** The thing 6.6 has to defend is the *loader's fallback*, not Vite's ability
  to bundle a config file. The fallback is exercised identically however the tree got built. (a)
  buys one extra link in the chain — "the operator's edit reaches the bundle" — at the price of
  turning an e2e spec into a build driver, and that link is better covered by a unit assertion on
  the emitted chunk than by a 14-second browser test.

### (c) The spec deploys a pre-built tree fixture

A tree built once with the fixture's id, committed or produced by a setup script, deployed by the
spec via `xui-deploy.sh`, and the pristine tree redeployed on teardown.

- **For.** Self-contained again, and no build at test time. **This is the shape the demonstration in
  §5 actually used** (a staged copy of `target/compiled` with `config/E2EStandInLoginHelper.js`
  added), and it worked first time; it also closes the dangerous window in §3 for free, because the
  module ships *inside* the tree being deployed and is therefore never absent while named.
- **Against.** A committed built tree is ~900 files and ~10 MB of hashed chunks that go stale the
  moment the product changes, and a stale fixture tree tests last month's XUI while claiming to test
  this one. Producing it at setup time instead is option (a) with extra steps. And it swaps the
  deployed tree out from under any other spec sharing the instance — the mutation window is now the
  whole `/XUI`, not one file.
- **When it wins over (b).** If CI is going to build the tree anyway, (c) with a *generated* (not
  committed) fixture tree is (b) with the precondition automated, and is a fine landing place.

### (d) Not recommended, recorded because someone will ask

`sed` the one occurrence of the helper id in the deployed content-hashed chunk (§1.4). It would
work — nothing verifies chunk integrity — and it is exactly the kind of thing that makes a migration
comparison lie. The chunk filename would no longer describe its content, and the edit is invisible
to `git`, to the build, and to the next deploy.

---

## 3. HOW THE MODULE STAYS ABSENT AT BUILD TIME

### 3.1 The guarantee, concretely

The registry is built by three `import.meta.glob` calls in `src/main/js/moduleRegistry.js:122-129`:

```js
const amTree      = import.meta.glob(["/src/main/js/**/*.{js,jsx,jsm}", "!…/main.js", "!…/main-authorize.js", "!…/main-device.js"]);
const commonsTree = import.meta.glob("/node_modules/@openidentityplatform/ui-commons/esm/**/*.{js,jsx}");
const userTree    = import.meta.glob("/node_modules/@openidentityplatform/ui-user/esm/**/*.{js,jsx}");
```

Every one of them is rooted at a directory that is **product source**. The absence guarantee is
therefore a single, checkable statement:

> **The operator's module lives in `OpenAM/e2e/fixtures/`, and is copied only into the deployed
> `/XUI` in the container. It is never written into `openam-ui/openam-ui-ria/src/main/js/` or into
> either npm package.**

That is the same place 1.11 already keeps it, so nothing has to move. Verified for this run:

```
$ ls openam-ui/openam-ui-ria/src/main/js/config/E2EStandInLoginHelper.js
ls: cannot access ...: No such file or directory
$ grep -rn "E2EStandIn" openam-ui/openam-ui-ria/src/main/js vite.config.js
(no output)
```

and, positively, the loader is observed taking the fallback: the *only* request for the id was
`200 …/XUI/config/E2EStandInLoginHelper.js?v=dev` — the identifier's own path below the deployed
tree root, with no content hash, which §14.7 of `NOTES-module-registry.md` establishes is the
distinguishing url shape of a fallback rather than a registry hit.

### 3.2 What would silently break it

Each of these leaves a **green** test that is no longer testing the fallback:

1. **Someone copies the fixture into `src/main/js/config/` to "keep it with the config it names."**
   The glob picks it up, `modules["config/E2EStandInLoginHelper"]` exists, `resolveModule` returns
   at the second table and never reaches `loadFromDeployedInstance`. The module still runs, the
   marker still appears, every assertion still passes.
2. **Someone gives the fixture a `.jsm` or `.jsx` extension while moving it.** Same outcome — the AM
   pattern deliberately includes all three.
3. **A build step, a test-setup script, or a `vite.config.js` plugin copies `e2e/fixtures/` into the
   source root or into `target/compiled/` at build time.** Case 3 is the nastiest: the module would
   be in the *deployed* tree without anyone having deployed it, so even the "did we place it?" check
   passes.
4. **The id stops being unregistered because the product grows a real module at that path.**
   Unlikely for this name; it is why the name is `E2E…`.

The cheap guard against all four, and it belongs in the spec rather than in a comment: assert that
the fetch for the module's url actually happened and returned 200. 1.11's header explicitly declines
to assert that ("it does *not* assert that the module arrived over HTTP from a path under the
webapp, that its request returned 200") on the grounds that it is pure mechanism — and it was right
for the AMD baseline, where RequireJS resolved everything by url so the assertion was vacuous. Under
D1 it stops being vacuous: it is the **only** externally visible difference between the fallback and
the registry. **Recommendation: add it, as one `page.on("response")` check, and say in the comment
that it is there to keep the test on the branch it names.**

### 3.3 The deployed tree is not a hiding place either

`xui-deploy.sh` `rm -rf`s `$XUI_PATH` before copying. So a module left in the deployed `/XUI` does
not survive the next deploy — which is good for cleanliness and bad for option (b), because it means
"the tree was built for this" and "the module is present" can go out of sync in one direction only:
a redeploy silently removes the module while leaving the configuration naming it. That is the dead
console of §4. **Under (b) the spec must therefore re-place the module on every run and never assume
a previous run left it there.** 1.11's fixture already does exactly this, and its
`deployedPathExists(MODULE_PATH) === false` precondition already fails loudly if it did not.

---

## 4. WHAT A MISS DOES — MEASURED, AND IT IS THE WHOLE REASON THE ORDERING IS LOAD-BEARING

With the deployed tree configured for `config/E2EStandInLoginHelper` and the module removed from
`/XUI/config/` (and put straight back):

```
PROBE2 LOGIN_FORM=ABSENT
PROBE2 MARKER= null
PROBE2 HITS= ["404 http://openam.example.org:8080/openam/XUI/config/E2EStandInLoginHelper.js?v=dev"]
```

The login form never renders. `SessionManager.getLoggedUser` is called at `EVENT_APP_INITIALIZED`
before `Router.init()`, so a `loginHelperClass` that does not resolve stops the application booting
— **identical to the AMD/Grunt behaviour 1.11's header describes**, and the reason its fixture
orders setup and teardown the way it does. D1 changed the error's *shape* (a `TypeError` about a
url, wrapped by 6.4 to re-name the identifier) but not its *consequence*.

**Under D6 this gets worse, and it is the single most important operational finding here.** In the
Grunt world the dead console was fixed by editing one deployed text file — seconds, `docker exec`,
no toolchain. Under D6 the bad `loginHelperClass` is **inside a content-hashed bundle chunk**. There
is no deployed file to put back. Recovering means rebuilding and redeploying (≈14 s *if* a working
UI toolchain and the right source state are to hand) or redeploying a known-good tree. A spec that
can leave the instance in that state must be able to get it out again without a build; see §7.

---

## 5. THE ESM STAND-IN

### 5.1 Why it is not a transcription of the AMD fixture

`NOTES-module-registry.md` §14.5/§14.8 measured that an operator's ESM module has **no channel** to
a shipped module, and this run re-confirmed every leg of that:

- no import map on the page, so `import RESTLoginHelper from "org/forgerock/…/RESTLoginHelper"`
  fails with `TypeError: Failed to resolve module specifier`;
- the only globals the XUI adds are `$` / `jQuery`;
- and — new here — **`RESTLoginHelper` has no chunk of its own in the emitted tree at all**
  (`ls target/compiled/assets | grep RESTLoginHelper` → nothing; its code is inlined into
  `assets/main-*.js` and two view chunks). So even the ugly escape hatch of importing a hashed
  chunk by relative url is unavailable *for this module specifically*.

1.11's fixture is built entirely on `Object.create(RESTLoginHelper)` and delegating. **That design
cannot be ported.** The stand-in below is the "self-contained fixture that drops the delegation"
candidate from §14.8, taken all the way: it re-implements the three members of the contract against
AM's REST API. It is a bigger fixture than 1.11's and that is a genuine cost — a bug in it is now
harder to tell from a bug in the product, which is the exact trade 1.11's header warned about. The
control run in §6.2 is what buys that back.

### 5.2 The `_.curry` arity trap — CONFIRMED STILL LIVE, AND STILL AVOIDED

The trap is unchanged by the migration. `SessionManager` is now the bundled ESM copy at
`node_modules/@openidentityplatform/ui-commons/esm/org/forgerock/commons/ui/common/main/SessionManager.js`,
and it still reads:

```js
obj.login = function (params, successCallback, errorCallback) {
  cookieHelper.deleteCookie("session-jwt", "/", "");
  return ModuleLoader.load(obj.configuration.loginHelperClass).then(function (helper) {
    return ModuleLoader.promiseWrapper(_.bind(_.curry(helper.login)(params), helper), {
      success: successCallback,
      error: errorCallback
    });
  });
};
```

`_.curry` reads the arity off `fn.length`. **The stand-in below declares `login (params,
successCallback, errorCallback)` — three formal parameters, spelled out, no rest args, no defaults**
(a default parameter would also truncate `fn.length`). `logout` and `getLoggedUser` declare their
two. This was not merely written that way, it was exercised: `login` was recorded in `marker.calls`
*and* its `successCallback` ran, which is only reachable if `_.curry` handed the callbacks through.

A second, related constraint was found and is recorded in the source: `ModuleLoader.promiseWrapper`
does `$.when(functionToCall(success, error))` and treats **any non-`undefined` return as the
outcome**, so the three members must return `undefined` — an `async` member would return a promise
and change the semantics. `RESTLoginHelper.login` returns `undefined` for the same reason.

### 5.3 The ported source, verbatim and runnable

This is byte-for-byte what was served from `/XUI/config/E2EStandInLoginHelper.js` for the green run
in §6.

```js
/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 3A Systems, LLC.
 */

/**
 * A stand-in login helper for a Vite-built XUI, standing for whatever an operator would supply.
 *
 * ESM, not AMD: under D1 the module is reached by a native dynamic import of
 * `<XUI root>/config/E2EStandInLoginHelper.js?v=<version>` (moduleRegistry's
 * `loadFromDeployedInstance`), so `define` is not defined and an AMD body dies at evaluation with a
 * bare `ReferenceError`. The default export is what `LoaderRuntime.unwrapModule` hands to
 * `SessionManager`.
 *
 * SELF-CONTAINED, AND THAT IS NOT A SIMPLIFICATION. The AMD fixture did `Object.create(
 * RESTLoginHelper)` and delegated. That has no channel here: the deployed page has no import map,
 * so a bare specifier such as "org/forgerock/openam/ui/user/login/RESTLoginHelper" throws
 * `TypeError: Failed to resolve module specifier`; the only globals the XUI adds are `$`/`jQuery`;
 * and RESTLoginHelper has no chunk of its own in the emitted tree to reach by relative URL. So this
 * module re-implements the three members of the contract against AM's REST API instead, deriving
 * the AM base from `document.baseURI` exactly as the loader derives the fallback URL.
 *
 * Three things here are load-bearing:
 *
 *   - **`login` declares exactly three formal parameters.** `SessionManager.login` calls
 *     `_.curry(helper.login)(params)` and lodash reads the arity off `fn.length`. Written
 *     `login (...args)`, `length` is 0, `_.curry` invokes immediately with only `params`, the
 *     callbacks are never passed, and the form submit goes nowhere with no error anywhere. The same
 *     applies to `logout` and `getLoggedUser`, which take two. Never use rest args here, and never
 *     let a build step transpile this file into them.
 *   - **The three members return `undefined`, not a promise.** `ModuleLoader.promiseWrapper` does
 *     `$.when(functionToCall(success, error))` and treats any non-undefined return as the outcome;
 *     RESTLoginHelper.login returns undefined for the same reason.
 *   - **The user object must answer `uiroles` and `hasRole`.** `Router.checkRole` reads
 *     `loggedUser.uiroles`, AMConfig's EVENT_HANDLE_DEFAULT_ROUTE reads it again to choose the
 *     landing route, and EVENT_AUTHENTICATED calls `loggedUser.hasRole(...)`. A plain
 *     `{ id, username }` gets as far as leaving `#login` and then throws.
 */

/** The observable. Written by this module and by nothing else. */
const marker = window.__e2eLoginHelper = {
    loaded: true,
    moduleId: "config/E2EStandInLoginHelper",
    delegatesTo: null,
    calls: []
};

/**
 * The AM context root, derived from the deployed tree's own location.
 *
 * `document.baseURI` is `<serverBase>/<context>/XUI/#<route>` — the same anchor the loader's
 * fallback URL is derived from — so `..` is the context root whatever the context path is called
 * and whatever route the page is on. `new URL` discards the fragment.
 */
const AM_ROOT = new URL("..", document.baseURI).href;

const CREST_V2 = { "Accept-API-Version": "protocol=1.0,resource=2.0" };
const CREST_V3 = { "Accept-API-Version": "protocol=1.0,resource=3.0" };

function rest (path, options) {
    const opts = options || {};
    return fetch(`${AM_ROOT}json${path}`, {
        credentials: "same-origin",
        method: opts.method || "GET",
        headers: Object.assign({ "Content-Type": "application/json" }, opts.headers || {}),
        body: opts.body
    });
}

/** `?realm=…` when the login form is scoped to a sub-realm, and nothing otherwise. */
function realmQuery (params) {
    const realm = params && (params.realm || params.subRealm);
    return realm && realm !== "/" ? `?realm=${encodeURIComponent(realm)}` : "";
}

/**
 * The two-step `/json/authenticate` exchange, filling the callbacks the login form collected.
 *
 * This is RESTLoginHelper's flow — `getRequirements` then `submitRequirements` — reduced to the
 * single-stage username/password case, and it reads `callback_<n>` out of `params` by the same
 * convention `RESTLoginView` writes them by. AM sets the session cookie itself on the response, so
 * nothing here has to write one.
 */
async function authenticate (params) {
    const query = realmQuery(params);
    const first = await rest(`/authenticate${query}`, { method: "POST", headers: CREST_V2 });
    if (!first.ok) { throw new Error(`authenticate (requirements) answered ${first.status}`); }

    const requirements = await first.json();
    (requirements.callbacks || []).forEach((callback, index) => {
        const supplied = params[`callback_${index}`];
        if (supplied !== undefined && callback.input && callback.input.length) {
            callback.input[0].value = supplied;
        }
    });

    const second = await rest(`/authenticate${query}`, {
        method: "POST",
        headers: CREST_V2,
        body: JSON.stringify(requirements)
    });
    const result = second.ok ? await second.json() : null;
    if (!result || !(result.tokenId || (result.successUrl && !result.authId))) {
        throw new Error(`authentication did not complete (${second.status})`);
    }
    return result;
}

/**
 * A user good enough for everything the console asks of `Configuration.loggedUser`.
 *
 * `uiroles` is derived the way `UserModel.parse` derives it, `ui-user` included, because the router
 * and AMConfig both branch on it.
 */
function toUser (identity, attributes) {
    const raw = attributes.roles;
    const uiroles = Array.isArray(raw) ? raw.slice() : (typeof raw === "string" ? raw.split(",") : []);
    if (uiroles.indexOf("ui-user") === -1) { uiroles.push("ui-user"); }

    const values = Object.assign({}, attributes, {
        id: identity.id,
        realm: identity.realm,
        uid: attributes.uid || [identity.id]
    });

    return {
        id: identity.id,
        uiroles,
        attributes: values,
        get (name) { return values[name]; },
        has (name) { return values[name] !== undefined; },
        toJSON () { return Object.assign({}, values); },
        hasRole (roles) {
            const wanted = Array.isArray(roles) ? roles : [roles];
            return wanted.some((role) => uiroles.indexOf(role) !== -1);
        }
    };
}

/**
 * The session cookie the XUI reads back through `SessionToken.get`.
 *
 * Removing it is part of the contract, not tidying: `SiteConfigurationService.checkForDifferences`
 * — which `EVENT_CHANGE_VIEW` awaits before it will route anywhere — branches on
 * `SessionToken.get()`, and the shipped helper's `logout` reaches
 * `removeSessionToken()` for exactly this reason. AM does not clear the cookie on the logout
 * response, so a stand-in that only ends the session server-side leaves the XUI stuck on
 * `#logout/`.
 */
const SESSION_COOKIE = "iPlanetDirectoryPro";

function forgetSessionCookie () {
    const labels = window.location.hostname.split(".");
    const domains = [""];
    for (let i = 0; i + 1 < labels.length; i++) { domains.push(labels.slice(i).join(".")); }
    domains.forEach((domain) => {
        document.cookie = `${SESSION_COOKIE}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/${
            domain ? `;domain=${domain}` : ""}`;
    });
}

/** The user the session cookie identifies, or null when there is no session. */
async function currentUser () {
    const session = await rest("/users?_action=idFromSession", { method: "POST", headers: CREST_V2 });
    if (!session.ok) { return null; }

    const identity = await session.json();
    const profile = await rest(`/users/${encodeURIComponent(identity.id)}`, { headers: CREST_V3 });
    return toUser(identity, profile.ok ? await profile.json() : {});
}

export default {
    login (params, successCallback, errorCallback) {
        marker.calls.push("login");
        authenticate(params || {})
            .then(currentUser)
            .then((user) => {
                if (!user) { throw new Error("authenticated, but no session could be read back"); }
                successCallback(user);
            })
            .catch((error) => { errorCallback(String(error && error.message ? error.message : error)); });
    },

    logout (successCallback, errorCallback) {
        marker.calls.push("logout");
        rest("/sessions?_action=logout", { method: "POST", headers: CREST_V2 })
            .then((response) => (response.ok ? response.json() : {}), () => ({}))
            .then((response) => {
                forgetSessionCookie();
                successCallback(response);
            }, errorCallback);
    },

    getLoggedUser (successCallback, errorCallback) {
        marker.calls.push("getLoggedUser");
        currentUser()
            .then((user) => { if (user) { successCallback(user); } else { errorCallback(); } })
            .catch(() => { errorCallback(); });
    },

    /* Members SessionManager never calls but a login helper is still expected to answer. */
    getSuccessfulLoginUrlParams () { return {}; },
    setSuccessURL (tokenId, successUrl) { return Promise.resolve(successUrl); },
    filterUrlParams () { return ""; }
};
```

---

## 6. THE END-TO-END PROOF

### 6.1 What was run

Throwaway node scripts driving headless chromium from `@playwright/test` 1.60.0, run from
`OpenAM/e2e` with stdout to a file. No `test-results/`, no DOM dumps. All scripts have been deleted.

Setup: source `AppConfiguration.js` edited to `loginHelperClass: "config/E2EStandInLoginHelper"`,
`npm run build:production`, `target/compiled` copied to a staging directory, the stand-in added at
`config/E2EStandInLoginHelper.js` inside it, `local/xui-deploy.sh <staging dir>`.

### 6.2 Result — and the control that makes it mean something

```
                                        stand-in run              control run (shipped helper,
                                                                  same Vite tree, rebuilt)
LOGIN_FORM_VISIBLE                      yes                       yes
MARKER_ON_ANON_LOAD                     {…,"calls":["getLoggedUser"]}   null
LEFT_LOGIN_HASH                         (left #login)             (left #login)
MARKER_AFTER_LOGIN                      calls: getLoggedUser,login      null
SESSION_AFTER_LOGIN                     demo                      demo
HASH_SETTLED                            #profile/details          #profile/details
LOGOUT_HASH                             #loggedOut/               #loggedOut/
MARKER_AFTER_LOGOUT                     calls: …,login,logout     null
SESSION_AFTER_LOGOUT                    null                      null
ERRORS                                  [404, 401]                [404, 401]
```

**Marker observable: yes. Login completes end to end: yes.** The landing route, the session AM
issued, the logout route and the console-error set are all identical to the control, so the operator
module is on the path rather than beside it, and it changed nothing about how login behaves.

### 6.3 The one failure along the way was the stand-in's, and the control is what proved it

The first stand-in got through login perfectly and then **hung at `#logout/`** — `logout` was
recorded on the marker, the REST logout returned `{"result":"Successfully logged out"}`, and the
router never moved. The temptation is to relax the assertion. Instead the shipped helper was built
and deployed onto the same Vite tree and run through the same script: it reached `#loggedOut/`.
**So the app was fine and the stand-in was wrong**, exactly as this task predicted.

The bug, and it is worth recording because any future ESM port will hit it: the shipped
`logout.jsm` calls `removeSessionToken()`, and `SiteConfigurationService.checkForDifferences` — which
`EVENT_CHANGE_VIEW` `await`s before it will route anywhere — branches on `SessionToken.get()`, i.e.
on the `iPlanetDirectoryPro` cookie. **AM does not clear that cookie on the logout response**
(measured: the logout response carries no `Set-Cookie`). A stand-in that ends the session only
server-side leaves a stale cookie, `checkForDifferences` takes the authenticated branch against a
dead session, and the deferred that gates `Router.routeTo` never resolves. Deleting the cookie
client-side is part of the login-helper contract, not tidying. `forgetSessionCookie()` in §5.3 is
that fix.

### 6.4 Mechanism, recorded rather than asserted

- fallback url actually fetched: `200 …/XUI/config/E2EStandInLoginHelper.js?v=dev` — the identifier's
  own path below the deployed tree root, `.js` unconditional, version query present, no content
  hash. Matches `NOTES-module-registry.md` §14.3 exactly, on a real AM context path.
- no request was made for any `RESTLoginHelper` url, which is trivially true here because it has no
  chunk of its own.
- with the module absent the url returns 404 and the app does not boot (§4).

---

## 7. WHICH ASSERTIONS SURVIVE — AND WHERE THE HEADER'S "TRANSPORT-BLIND" CLAIM IS WRONG

The header claims the assertions are deliberately transport-blind. **Checked against what was
actually observed: the claim holds for every *behavioural* assertion and fails for exactly one, plus
the whole of the fixture's setup/teardown machinery, which the claim never covered.**

### 7.1 Survive unchanged — all four behavioural assertions

| assertion | evidence |
|---|---|
| `expectCalled(page, "getLoggedUser")` on a plain anonymous load, before any credential | marker `calls: ["getLoggedUser"]` at the login form |
| `expect(marker.moduleId).toBe(standInHelper.moduleId)` | `"config/E2EStandInLoginHelper"` |
| `expectCalled(page, "login")` after `loginViaXui`, plus `sessionInfo()` → `demo` | both, identically to the control |
| `expectCalled(page, "logout")` after `logoutViaXui`, plus `sessionInfo()` → null | both, identically to the control |

`expectModuleRan` / `readMarker` / the `expect.poll` shapes all survive verbatim, and
`readModuleId(source)` still works because the ESM fixture keeps `moduleId: "<id>"` as a literal.
The marker-per-document reasoning survives too: `#login → #profile/details → #logout/ → #loggedOut/`
are all hash changes on one document, so `calls` accumulates exactly as the comment describes.

### 7.2 Cannot survive — one assertion

```js
expect(marker.delegatesTo).toBe(SHIPPED_HELPER);
```

**Gone, and it cannot be rewritten — the property it asserts no longer exists.** There is no channel
from an operator's ESM module to a shipped module (§5.1), so the ported fixture does not delegate and
`delegatesTo` is `null`. The comment above the assertion explains it as a guard against `SHIPPED_HELPER`
and the fixture's own literal drifting apart; under D6 `SHIPPED_HELPER` has no second reader either,
because the spec no longer restores a config file that names it. **Both the assertion and the
`SHIPPED_HELPER` constant should be deleted rather than adapted**, and the drift they guarded is
replaced by the §3.2 recommendation (assert the module was fetched over HTTP).

### 7.3 Cannot survive — the fixture, entirely

Not assertions, but they are what makes the assertions run, and every one of them is dead:

| what it does | why it is dead |
|---|---|
| `readDeployedFile(APP_CONFIG_PATH)` | `/XUI/config/AppConfiguration.js` does not exist (§1.1) |
| `withStandInHelper()` and its "names it exactly once" count | there is no deployed file to count in |
| `writeDeployedFile(APP_CONFIG_PATH, mutated)` + `deployedSha256` check | ditto |
| `waitForServed(APP_CONFIG_URL, …)` (both directions) | `APP_CONFIG_URL` is a permanent 404 |
| the teardown's config restore and its pristine-sha assertion | ditto |

What survives from the fixture: the `deployedPathExists(MODULE_PATH) === false` precondition,
`placeDeployedFile` + `waitForServed(MODULE_URL, 200)`, `removeDeployedFile` +
`waitForServed(MODULE_URL, 404)`. Those four are unchanged and still correct.

### 7.4 Where the header's own reasoning is now wrong

The header says the spec does not assert "that the module arrived over HTTP from a path under the
webapp, that its request returned 200 … all true today, all pure mechanism, and a registry that
resolved the same ID better would fail every one of them." Under D1 that reasoning inverts: **the
registry resolving the same id is precisely the failure mode** (§3.2), and the HTTP fetch is the only
thing that distinguishes it. The paragraph should be rewritten, not merely kept.

The two-traps section survives intact and both traps were re-confirmed live: the `_.curry` arity trap
(§5.2) and the "a `loginHelperClass` that does not resolve stops the application booting" trap (§4).

---

## 8. WHAT TEARDOWN HAS TO UNDO NOW

Today's teardown restores **one deployed file** and removes **one deployed file**, in that order,
each confirmed on the wire. What it has to undo depends entirely on which option from §2 is chosen —
and this is the strongest practical argument for (b).

### 8.1 Per artefact: what a failed / killed run leaves behind

| artefact | mutated by | what a failed run leaves | how bad | how it is recovered |
|---|---|---|---|---|
| **the deployed module** `/XUI/config/<id>.js` | (a) (b) (c) | a stray file nothing names *if* the config is pristine | inert — 1.11's own reasoning, still true | `docker exec rm`; the next `xui-deploy.sh` also removes it (§3.3) |
| **the deployed tree** `/XUI` | (c) only | a tree built for the fixture, i.e. one whose config names a module that may no longer be there | **dead console** — no login form, nobody can reach the admin UI (§4) | redeploy a known-good tree; there is *no* single-file fix any more |
| **product source** `src/main/js/config/AppConfiguration.js` | (a) only | a dirty tracked file naming a test fixture | not an outage, but it can be committed, and it makes every later build wrong | `git checkout` — but only if the developer notices |
| **the build output** `target/compiled/` | (a) only | a tree built from the mutated source, silently wrong for every later `xui-deploy.sh` | delayed and confusing: the *next* deploy takes the console down, long after the test that caused it | rebuild (13 s) — again, only if noticed |
| **the deployed AppConfiguration** | nobody, any more | — | — | the artefact 1.11's teardown existed to protect no longer exists |

### 8.2 The consequences for how teardown must be written

- **The asymmetry 1.11 encodes is still right, and its two halves now have different weights.** "Put
  the configuration back first, confirm it on the wire, only then remove the module" was written
  because a config naming an absent module is an outage while a stray module is inert. Under D6 the
  first half has no cheap form: putting the configuration back means putting a *tree* back.
- **So under (b) the ordering problem largely dissolves**, and that is (b)'s biggest practical win.
  The spec never changes the configuration, so it can never leave one naming an absent module. Its
  teardown shrinks back to one step — remove the module — and the worst a killed run leaves is a
  stray inert file that the existing `deployedPathExists` precondition already catches by name on
  the next run.
- **Under (a) and (c) the teardown must be able to restore a whole tree without running a build**,
  because the state it is recovering from is one where nobody can log in and 14 seconds of toolchain
  may not be available. Concretely: snapshot the deployed `/XUI` (a `docker exec … tar czf -` of the
  live tree is 2.0 MB and takes under a second — measured, §9) *before* deploying anything, and
  restore from that tarball in teardown. Do not rely on rebuilding.
- **Under (a) the teardown additionally owns a tracked source file**, and a `finally` block is not a
  strong enough guarantee for that: the spec's own comment notes that a hung `docker exec` gets the
  worker killed outright with no teardown at all. A source-file mutation that survives that is a
  worse outcome than any of the deployed-artefact ones.

---

## 9. RESTORE — WHAT THE CONTAINER IS NOW

### 9.1 The baseline was Grunt, and it was recoverable after all

The `/XUI` baked into `OpenAM-16.2.0-SNAPSHOT.war` and expanded by Tomcat is a **Grunt/RequireJS
tree**, determined before anything was touched: 19 top-level entries including `config/`, `org/`,
`components/`, `store/`, `main.js` + `main.js.map`; **no `assets/`**; and an `index.html` that ends

```html
<script src="libs/base64-1.0.0-min.js"></script>
<script type="text/javascript">
    var require = { urlArgs : "v=16.2.0-SNAPSHOT", deps : ['main'] };
</script>
<script src="libs/requirejs-2.3.7-min.js"></script>
```

The task brief notes that no Grunt-built `www` zip survives on disk, so "put the Grunt XUI back" is
unavailable. **That turned out to be recoverable from the container itself**, and it is worth
recording as a general technique: before touching anything,

```
docker exec openam-idp sh -c 'cd /usr/local/tomcat/webapps/openam && tar czf - XUI' > XUI-baseline.tgz
```

produced a 2.0 MB / 855-file archive in well under a second, and

```
docker exec -u 0 openam-idp rm -rf /usr/local/tomcat/webapps/openam/XUI
docker exec -i -u 0 openam-idp tar xzf - -C /usr/local/tomcat/webapps/openam < XUI-baseline.tgz
```

put it back with ownership and modes intact (`drwxr-x--- openam root`, files dated Aug 17 —
Tomcat's own war expansion). **`local/openam-reset.sh` was not needed and was not run.**

### 9.2 State at exit — verified, not assumed

- **The container's `/XUI` is the Grunt/RequireJS tree that ships inside
  `OpenAM-16.2.0-SNAPSHOT.war` (build ceda844487), byte-identical to how this task found it.**
  Three SHA-256s taken before any mutation and again after the restore:

  | file | sha256 (before == after) |
  |---|---|
  | `XUI/index.html` | `961345a9af3f523af921b73f8f5501d1fa212b0a9ed378c79127961b97bee4d7` |
  | `XUI/config/AppConfiguration.js` | `343bee5cb9798b336b9ddf598352b9222d2ead43b63139c14d66bd6040b8cc87` |
  | `XUI/main.js` | `cd9c73e50a8ba026bd68daeb1c20f155ccfd8e6587d72e6e64a3286a32d5d9ae` |

- 19 top-level entries; `XUI/assets/` does not exist; owner `openam:root`.
- **No stand-in is left**: `GET /XUI/config/E2EStandInLoginHelper.js` → **404**.
- **The deployed configuration is the shipped one**: `/XUI/config/AppConfiguration.js` serves 200 and
  names `org/forgerock/openam/ui/user/login/RESTLoginHelper` exactly once.
- **The instance works**: browser run against the restored tree — login form renders, `demo`/`changeit`
  logs in, `idFromSession` → `demo`, lands on `#profile/details`, `#logout/` reaches `#loggedOut/`,
  session gone. `window.__e2eLoginHelper` is `null` throughout.
- `openam-idp` and `opendj-idp` both Up and healthy; no container was rebuilt, restarted or reset.

### 9.3 Workspace state at exit

- `src/main/js/config/AppConfiguration.js` restored to `loginHelperClass:
  "org/forgerock/openam/ui/user/login/RESTLoginHelper"`.
- `target/compiled/` holds a **clean, unmutated** production build (the control build); no chunk
  mentions `config/E2EStandInLoginHelper`.
- `git status` is back to the three untracked files it started with (`e2e/xui/NOTES-operator-module-d6.md`
  — this file — plus `openam-ui-ria/NOTES-amd-to-esm.md` and `NOTES-entry-templates.md`). No tracked
  file was modified.
- All throwaway scripts deleted.
- `xui/xui-operator-module.spec.mjs`, `fixtures/E2EStandInLoginHelper.js` and
  `xui/NOTES-operator-module.md` were **not** edited.

---

## 10. NOT DETERMINED

1. ~~**Whether option (b)'s precondition should skip or fail**~~ — **RESOLVED (change owner,
   2026-08-31): fail loudly, do not skip.** `npm run test:xui` against a tree that was not built for
   the fixture is red, with a remediation message naming the build flag; the capability going
   quietly untested was judged the worse failure. Recorded here because the reasoning is now in §2
   option (b) rather than open.
2. **Whether an operator should be given a real channel to shipped modules** (a documented global over
   `ModuleLoader.load`, or an import map stamped into `index.html`). Still open, still §14.8's item 1,
   and it is a product-documentation question rather than a spec question. Note that the fixture no
   longer *needs* it — but a real operator writing a login helper almost certainly does, and shipping
   D1 without it narrows the capability even though it does not remove it.
3. **The secondary entry points** (`main-authorize.js`, `main-device.js`) were not exercised. They do
   not configure `resolveModule`, so the fallback is unreachable there; unchanged from §14.3.
4. **Sub-realm login** was not exercised. The stand-in's `realmQuery` handles `params.realm` but only
   the root realm was measured.
5. **A second operator file** (`import "./Other.js"` from inside the stand-in) was not re-measured
   here; §14.4's double-evaluation hazard around the `?v=` query is taken from that spike unchanged.

---

## APPENDIX — the rewrite, applied and proved (2026-08-31)

Everything above is the spike. This appendix records the rewrite that was made *from* it and the two
runs that prove it, against the same container. Only `xui/xui-operator-module.spec.mjs`,
`fixtures/E2EStandInLoginHelper.js` and this appendix were edited; `xui/NOTES-operator-module.md` and
every other tracked notes file are still untouched.

### A.1 What the rewrite did

| # | change | from |
|---|---|---|
| 1 | **Option (b), with the precondition failing loudly.** `expectTreeBuiltForModule(browser)` asserts, before anything is placed, that the deployed tree was already built naming the fixture's id. No `test.skip()` anywhere in the file. The spec still never edits product source and never invokes a build. | §2 decision, §10 item 1 |
| 2 | **The fixture is the ESM stand-in of §5.3, byte-for-byte.** `login (params, successCallback, errorCallback)` — three formal parameters spelled out, no rest args, no defaults; `logout` and `getLoggedUser` declare their two; no member is `async` and all three return `undefined`; `logout` calls `forgetSessionCookie()` before its success callback. | §5.2, §5.3, §6.3 |
| 3 | **Deleted, not adapted**: `expect(marker.delegatesTo).toBe(SHIPPED_HELPER)` and the `SHIPPED_HELPER` constant; `readDeployedFile`/`withStandInHelper` and its exactly-once count; `writeDeployedFile`; `deployedSha256`/`sha256`; `APP_CONFIG_PATH`/`APP_CONFIG_URL` and both `waitForServed(APP_CONFIG_URL)` calls; the teardown's config restore and its pristine-sha assertion. | §7.2, §7.3 |
| 4 | **Kept**: all four behavioural assertions, `expectModuleRan`, `readMarker`, the `expect.poll` shapes, `readModuleId(source)`, and the `deployedPathExists(MODULE_PATH) === false` precondition — every one of them by *body*, not by text. **Three messages changed, not one** (corrected 2026-08-31 by the fix pass in appendix B; the original wording of this row claimed only the first): (i) the `deployedPathExists` precondition's, because the old one instructed the reader to restore a deployed config file that no longer exists — under (b) the remediation is to delete the stray file; (ii) `expectModuleRan`'s, which said "check … that the deployed AppConfiguration names `<id>`" and so named `/XUI/config/AppConfiguration.js`, a permanent 404 under D6 — it now says the deployed *tree* was built naming it; (iii) `readModuleId`'s, which listed "the deployed path, the configured `loginHelperClass` and the marker assertion" as what it derives, and the spec no longer writes any `loginHelperClass` — it now says the fallback URL. All three changes were correct; the audit trail should have said there were three. | §7.1, §3.3, §1.1 |
| 5 | **New: the module arrived over HTTP.** `recordModuleFetches(page)` records every response whose path is *exactly* `/openam/XUI/config/E2EStandInLoginHelper.js`, and the first test asserts a `200` among them. The exact-path match is the assertion: a registry hit is served from `assets/<name>-<contenthash>.js` and can never produce that path. The header was rewritten around this — the old "transport-blind" paragraph is replaced by the D1 inversion, plus the absence guarantee and its four silent breakers. | §3.1, §3.2, §7.4, §14.7 of NOTES-module-registry.md |
| 6 | **Teardown is one artefact**: remove the deployed module, confirm the 404, confirm it is gone. It is the first statement in the `finally`, so it runs on the failure path and when setup itself failed. | §8.2 |

### A.2 GREEN — the rewritten spec against a tree built for the fixture

Setup, exactly the §1.2 cycle: source `AppConfiguration.js` set to `loginHelperClass:
"config/E2EStandInLoginHelper"`, `npm run build:production` (**exit 0, `✓ built in 13.07s`**, chunks
`main-r9j2ic-0.js` / `i18nManager-CoRSbdGm.js` — the same pair §1.3 measured), the tree staged and
deployed with `local/xui-deploy.sh` (**0.92 s, 900 files**), source restored immediately afterwards.
The staged tree names the id in exactly one chunk and **does not contain the fixture**, so the
absence guarantee of §3.1 held for this run by construction.

```
$ npx playwright test xui/xui-operator-module.spec.mjs
  ✓  1 … a module added to the deployed /XUI and named in the built configuration is loaded and used (12.2s)
  ✓  2 … login and logout still complete end to end through the operator's module (10.3s)
  2 passed (23.9s)                                                              exit 0
```

Asserted, and all of it green: `getLoggedUser` recorded on a plain anonymous load; `marker.moduleId`
is `config/E2EStandInLoginHelper`; **a 200 for `/openam/XUI/config/E2EStandInLoginHelper.js`** —
the fallback shape, no content hash; `login` recorded and `idFromSession` → `demo`; `logout` recorded
and the session gone. Teardown removed the module and the 404 was confirmed on the wire.

### A.3 RED — the same spec against a tree that was *not* built for the fixture

The control tree (identical build, shipped `RESTLoginHelper`) redeployed; nothing else changed.

```
$ npx playwright test xui/xui-operator-module.spec.mjs
  ✘  1 … (20.1s)
  ✘  2 … (20.1s)
  2 failed                                                                      exit 1
```

**Two failures, no skips, exit 1** — which is the decision in §2 doing what it was chosen to do. The
poll reports *which* of the two states it saw rather than merely timing out:

```
Expected: "asked-for-the-module"
Received: "booted-without-the-module"
```

and the message it fails with is the remediation, verbatim from the run:

```
the deployed /XUI was not built naming "config/E2EStandInLoginHelper" as its loginHelperClass, so
this spec cannot exercise the operator-module fallback and must not pretend to. D6 compiles
AppConfiguration into a content-hashed bundle chunk, so there is no deployed
config/AppConfiguration.js for this spec to edit — the tree has to be built that way. To fix, from
the repository root:
    1. set  loginHelperClass: "config/E2EStandInLoginHelper"  in openam-ui/openam-ui-ria/src/main/js/config/AppConfiguration.js
    2. cd openam-ui/openam-ui-ria && npm run build:production
    3. e2e/local/xui-deploy.sh openam-ui/openam-ui-ria/target/compiled
and restore that one line afterwards — it is tracked product source. The redeploy in step 3 replaces
the whole tree, so it also removes /usr/local/tomcat/webapps/openam/XUI/config/E2EStandInLoginHelper.js;
this spec places it again on every run and never assumes a previous run left it there.
```

Note what the failure did *not* leave behind: the precondition throws before anything is placed, so
`GET /XUI/config/E2EStandInLoginHelper.js` was **404** immediately after the red run, with no
teardown having had to run.

### A.4 Restore, re-verified

The `docker exec … tar czf -` technique of §9.1 was used again, taken **before any mutation**: 2.0 MB,
855 files, 0.4 s. `local/openam-reset.sh` was not needed and was not run.

- The container's `/XUI` is the Grunt/RequireJS tree baked into the war again. The three SHA-256s of
  §9.2 were re-taken after the restore and **all three match**: `index.html` `961345a9…e4d7`,
  `config/AppConfiguration.js` `343bee5c…cc87`, `main.js` `cd9c73e5…d9ae`.
- 19 top-level entries, 855 files, `XUI/assets/` does not exist, owner `openam:root`.
- **No stand-in is left**: `GET /XUI/config/E2EStandInLoginHelper.js` → **404**; a `find` for
  `*E2E*`/`*StandIn*` across the deployed tree is empty.
- **The deployed configuration is the shipped one**: `/XUI/config/AppConfiguration.js` serves 200 and
  names `org/forgerock/openam/ui/user/login/RESTLoginHelper` exactly once.
- **The instance works**: `npx playwright test xui/xui-login.spec.mjs` → **4 passed (11.5s)**, exit 0.
- `src/main/js/config/AppConfiguration.js` restored (sha `3653e5d0…0351`); `target/compiled` restored
  to the clean control build (900 files, no chunk naming the fixture). Every staged tree, tarball and
  log was deleted. `git status` is back to the three untracked files it started with, plus the two
  intended edits to the spec and the fixture.

---

## APPENDIX B — the review fix pass, and the build flag (2026-08-31)

Appendix A recorded the rewrite. This appendix records the fix pass applied to it after review
("ready to merge with fixes", no Critical), the `LOGIN_HELPER_CLASS` build flag that closes §2(b)'s
one loose end, and the two runs that re-prove both. Same container, same
`OpenAM-16.2.0-SNAPSHOT`. Nothing above this line was rewritten; the one correction made to it is
appendix A.1 item 4, which had understated which messages changed.

### B.1 What the fix pass changed, and why

| # | change | why |
|---|---|---|
| 1 | **Teardown now takes the directory back too.** `MODULE_DIRS` is derived from the module ID (`config/E2EStandInLoginHelper` → `<XUI>/config`, deepest first) and handed to `removeDeployedFile(MODULE_PATH, MODULE_DIRS)`. | `config/` is **not** in the built tree — §1.1 measured 15 top-level entries and no `config/` — so `placeDeployedFile`'s `mkdir -p` creates it and the old teardown left it behind, empty. That contradicted the fixture's own "exactly one artefact" claim and §8.2. `rmdir` refuses a populated directory, which is what keeps this correct against a Grunt tree, where `config/` is the product's. Same mechanics as `xui-theming.spec.mjs`'s `OVERRIDE_DIRS`. **This is the one fix that could only be proved at run time; see B.4.** |
| 2 | **The fixture now says where it must live.** A paragraph at the top of `fixtures/E2EStandInLoginHelper.js`: it stays in `e2e/fixtures/`; `moduleRegistry.js` globs `/src/main/js/**` and the two `@openidentityplatform` ESM trees over `.js`/`.jsm`/`.jsx`; a copy under any of them makes `resolveModule` answer from the table and the fallback is never reached; cross-referenced to the spec header's absence guarantee. | §3.2 breaker 1, verbatim: the person who breaks the guarantee is the one who opens the *fixture* and thinks it belongs next to the config it names. The AMD version it replaced at least said "It is a fixture, not product code"; the rewrite had dropped that line. |
| 3 | **The precondition probe keeps `ignoreHTTPSErrors`, and no longer leaks its context.** `browser.newContext({ ignoreHTTPSErrors: true })`, with `newPage()` and `recordModuleFetches` moved inside the `try`. | A context created off `browser` does not inherit the config's `use` block, and `playwright.config.mjs:39` sets that option deliberately for self-signed https instances (`OPENAM_BASE_URL`). Without it `probe.goto` rejects on a raw TLS error and the fixture dies *before* the poll — so `preconditionMessage()` is never printed, which is the one thing the fail-loudly decision of §2 depends on. The `newPage()` move fixes a leak on the same path. |
| 4 | **The remediation names the `still-booting` state.** A sentence saying that if `Received` is `still-booting` neither state was observed — no login form *and* no request for the module URL — so the instance may be down, slow or broken for an unrelated reason, and that should be checked before following the steps. | The poll has three outcomes and only two of them are statements about how the tree was built. The old message gave build-and-redeploy advice for all three. |
| 5 | **`delegatesTo: null` carries a comment saying why.** Nothing reads it — its assertion was correctly deleted (A.1 item 3) — and the comment records that an operator ESM module has no channel to a shipped one, cross-referencing the spec header. | §5.1/§7.2. Kept rather than deleted because it is the honest answer to the question the AMD marker answered with a module ID. |
| 6 | **The stray-file precondition names the build hazard.** Its message now offers two explanations — a previous run that did not clean up, **or** a build/deploy step copying `e2e/fixtures/` into the tree — and says to establish which before deleting. | §3.2 breaker 3 is the nastiest of the four precisely because the module is in the deployed tree without anyone having deployed it. The old message papered over it by telling the reader to delete the file. |
| 8 | **The fixture header states its cookie assumption.** One paragraph: a JS-readable session cookie named `iPlanetDirectoryPro`. | `SESSION_COOKIE` is hardcoded while the product reads the name from `Configuration.globalData.auth.cookieName` (`SessionToken.jsm`), and the suite has `xui/xui-httponly.spec.mjs` for instances where that cookie is HttpOnly and undeletable from `document.cookie` — never exercised here. Deliberately **not** made dynamic; that is a separate change. |
| 9 | **The comment on the three extra members corrected.** It said they are members "a login helper is still expected to answer". Measured otherwise: `NOTES-operator-module.md` §1, re-confirmed by grep here — `setSuccessURL`, `filterUrlParams` and `getSuccessfulLoginUrlParams` are reached by a **direct import** of the shipped `RESTLoginHelper` in every caller (`RESTLoginView`, `RESTLogoutView`, `SessionExpiredView`), and under D6 nothing reaches this object except through `loginHelperClass`, which only `SessionManager` resolves. They are there for shape; replacing the login helper does not replace them. | §1 of NOTES-operator-module.md |

Fix 7 is not in the list because the review had no item 7.

### B.2 The build flag — `LOGIN_HELPER_CLASS`

§2(b) assumed a build flag existed for satisfying the precondition. **It did not.** The remediation
therefore told a human to edit tracked product source, build, deploy, and remember to put the line
back — which is the exact hazard §2 used to reject option (a) (§8.1 row 3: "a dirty tracked file
naming a test fixture … it can be committed"), moved onto human memory with no teardown at all.
The change owner closed it with a flag rather than a wrapper script.

**How it is wired.** Following the existing `process.env.TARGET_VERSION` → `define` precedent
(`vite.config.js:105`, consumed as a bare `__TARGET_VERSION__` in `main.js` under a
`/* global */` comment), and not a second style:

```js
// vite.config.js, beside targetVersion
const loginHelperClass = process.env.LOGIN_HELPER_CLASS
    || "org/forgerock/openam/ui/user/login/RESTLoginHelper";

// vite.config.js, in define
__LOGIN_HELPER_CLASS__: JSON.stringify(loginHelperClass)
```

```js
// src/main/js/config/AppConfiguration.js
/* global __LOGIN_HELPER_CLASS__ */
    loginHelperClass: __LOGIN_HELPER_CLASS__
```

The fallback is applied in `vite.config.js`, **not** in the substituted expression, which is what
handles the undefined case properly: `define` is a textual substitution, so what lands in the chunk
is always a quoted string literal. A `define` of bare `process.env.LOGIN_HELPER_CLASS` would have
put a `process` lookup — or the token `undefined` — into a browser bundle.

**Proof the default is unchanged.** A plain `npm run build:production` (exit 0, `✓ built in 12.24s`):

```
$ grep -o 'loginHelperClass:"[^"]*"' $(find target/compiled -name '*.js' ! -name '*.map') | sort | uniq -c
   1 target/compiled/assets/i18nManager-Co6QgOIE.js:loginHelperClass:"org/forgerock/openam/ui/user/login/RESTLoginHelper"
```

One chunk, one occurrence, nothing else named — and the chunk is **`i18nManager-Co6QgOIE.js`, the
same content hash §1.1 and §1.3 recorded for the pre-flag control build.** The emitted configuration
chunk is byte-identical to what the tree emitted before the flag existed, which is a stronger
statement than "the string is still right".

With the flag set, the same build emits `i18nManager-CoRSbdGm.js` — again the exact hash §1.3
measured for the *source-edited* build. So the flag reproduces the source edit byte for byte, and
§1.3's "a config edit is a whole-tree redeploy" is unchanged by it.

**The remediation message now reads (verbatim from the red run in B.5):**

```
the deployed /XUI was not built naming "config/E2EStandInLoginHelper" as its loginHelperClass, so
this spec cannot exercise the operator-module fallback and must not pretend to. D6 compiles
AppConfiguration into a content-hashed bundle chunk, so there is no deployed
config/AppConfiguration.js for this spec to edit — the tree has to be built that way.
If Received above is "still-booting", neither state was observed — the login form never rendered and
the module URL was never requested — so this is not yet a statement about how the tree was built:
the instance may be down, slow, or broken for an unrelated reason. Check it is up and serving /XUI/
before following the steps.
To fix, from the repository root:
    1. cd openam-ui/openam-ui-ria && LOGIN_HELPER_CLASS="config/E2EStandInLoginHelper" npm run build:production
    2. e2e/local/xui-deploy.sh openam-ui/openam-ui-ria/target/compiled
LOGIN_HELPER_CLASS is a build-time override read by vite.config.js; unset, the build emits the
shipped org/forgerock/openam/ui/user/login/RESTLoginHelper unchanged. So nothing tracked is edited
here and there is nothing to restore afterwards. The redeploy in step 2 replaces the whole tree, so
it also removes /usr/local/tomcat/webapps/openam/XUI/config/E2EStandInLoginHelper.js; this spec
places it again on every run and never assumes a previous run left it there.
```

This supersedes the message quoted in A.3. Three steps became two, the "and restore that one line
afterwards — it is tracked product source" clause is **gone** because there is no longer a tracked
file to restore, and the accurate warning about the redeploy removing the placed module is kept
unchanged.

### B.3 GREEN — the fixed spec against a flag-built tree

```
$ LOGIN_HELPER_CLASS=config/E2EStandInLoginHelper npm run build:production     # exit 0, ✓ built in 12.45s
$ e2e/local/xui-deploy.sh openam-ui/openam-ui-ria/target/compiled              # 0.90 s, 900 files
$ npx playwright test xui/xui-operator-module.spec.mjs
  ✓  1 … a module added to the deployed /XUI and named in the built configuration is loaded and used (11.2s)
  ✓  2 … login and logout still complete end to end through the operator's module (11.2s)
  2 passed (23.9s)                                                              exit 0
```

No source file was edited to get there — the whole of §1.2's "edit source, rebuild, redeploy" cycle
is now "rebuild with a variable set, redeploy". The deployed tree named the id in exactly one chunk
and did **not** contain the fixture, so §3.1's absence guarantee held for this run by construction.

### B.4 DIRCHECK — what fix 1 actually buys, measured after teardown

The deployed tree has 15 top-level entries and no `config/`. Immediately after the green run's
teardown, with no other action in between:

```
$ docker exec openam-idp sh -c 'ls -1 …/XUI | wc -l'                       15
$ docker exec openam-idp sh -c '[ -d …/XUI/config ] && echo PRESENT || echo GONE'
GONE
$ docker exec openam-idp find …/XUI -name '*E2E*' -o -name '*StandIn*'     (empty)
$ curl -o /dev/null -w '%{http_code}' …/XUI/config/E2EStandInLoginHelper.js
404
```

15 before the run and 15 after. Before this fix it would have been 16, with an empty `config/`
left in a tree that ships none — a difference no static reading of the spec surfaces, and the
reason this check was run rather than reasoned about.

### B.5 RED — the same spec against a tree built without the flag

The control tree (plain `npm run build:production`, shipped `RESTLoginHelper`, deployed config chunk
verified in the container to name it exactly once) redeployed; nothing else changed.

```
$ npx playwright test xui/xui-operator-module.spec.mjs
  ✘  1 … (20.0s)
  ✘  2 … (20.0s)
  2 failed                                                                      exit 1
```

**2 failed, 0 skipped, exit 1** — the summary line is exactly `2 failed`, with no skip count, which
is §2's decision still doing what it was chosen to do. The poll still reports which of the two
states it saw:

```
Expected: "asked-for-the-module"
Received: "booted-without-the-module"
```

and it fails with the message in B.2. As in A.3, the precondition throws before anything is placed,
so `GET /XUI/config/E2EStandInLoginHelper.js` was 404 immediately afterwards and `config/` was never
created — no teardown had to run.

### B.6 Restore, re-verified

`docker exec … tar czf -` taken **before any mutation**: 2.0 MB, 855 entries, 0.38 s.
`local/openam-reset.sh` was not needed and was not run.

- The container's `/XUI` is the Grunt/RequireJS tree baked into the war. All three SHA-256s of §9.2
  re-taken after the restore and **all three match**: `index.html` `961345a9…e4d7`,
  `config/AppConfiguration.js` `343bee5c…cc87`, `main.js` `cd9c73e5…d9ae`.
- 19 top-level entries, 855 entries in total, `XUI/assets/` does not exist, owner `openam:root`.
- **No stand-in is left**: `GET /XUI/config/E2EStandInLoginHelper.js` → **404**; a `find` for
  `*E2E*`/`*StandIn*` across the deployed tree is empty.
- **The deployed configuration is the shipped one**: `/XUI/config/AppConfiguration.js` serves 200 and
  names `org/forgerock/openam/ui/user/login/RESTLoginHelper` exactly once.
- **The instance works**: `npx playwright test xui/xui-login.spec.mjs` → **4 passed (10.9s)**, exit 0.
- `target/compiled` rebuilt to the clean default (900 files, `i18nManager-Co6QgOIE.js`, no chunk
  naming the fixture). Every staged tree, tarball and log deleted.
- `git status` shows the three untracked notes files it started with, plus four modified tracked
  files: `e2e/xui/xui-operator-module.spec.mjs`, `e2e/fixtures/E2EStandInLoginHelper.js`,
  `openam-ui/openam-ui-ria/vite.config.js` and
  `openam-ui/openam-ui-ria/src/main/js/config/AppConfiguration.js`. The last two are the flag.
  `src/main/js/config/AppConfiguration.js` is modified **once and permanently** — it now names
  `__LOGIN_HELPER_CLASS__` instead of a literal — which is precisely what removes the per-run
  source mutation the old remediation asked for.
