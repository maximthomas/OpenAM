# NOTES-vitest.md — reconnaissance for group 9 (D12): the 18 Karma specs under Vitest

Recon only. **No production test file was written and no tracked file was changed.** Everything
below was measured on `features/openam-ui-migration` at the state recorded by the last commit
(`65b928b`), in `openam-ui/openam-ui-ria`, with throwaway configs and test files that have since
been deleted. Where a claim is measured it says so; where it is a guess it says that too.

Preconditions checked before anything else, all four green:

| # | check | result |
|---|-------|--------|
| 1 | branch | `features/openam-ui-migration` |
| 2 | `src/test/js` | 18 `*Test.js` + `test-main.js` |
| 3 | runner | `node_modules/vitest` 2.1.9 (pin `^2.1.9`), `node_modules/vite` **5.4.21** |
| 4 | configs | `vite.config.js` (275 894 bytes) and `karma.conf.js` both present |

---

## A. The runner and its configuration

### A1. What `npm run test:unit` does today

It **exits 1 having selected nothing**. It does not error on the config; it errors on the empty
selection. Verbatim, the last four lines:

```
 RUN  v2.1.9 /home/maxim/Documents/_projects/forgerock/OpenAM/openam-ui/openam-ui-ria

include: **/*.{test,spec}.?(c|m)[jt]s?(x)
exclude:  **/node_modules/**, **/dist/**, **/cypress/**, **/.{idea,git,cache,output,temp}/**, **/{karma,rollup,webpack,vite,vitest,jest,ava,babel,nyc,cypress,tsup,build,eslint,prettier}.config.*

No test files found, exiting with code 1
```

One line above that: `The CJS build of Vite's Node API is deprecated.` — emitted because there is no
`"type": "module"` in `package.json`, so Vitest loads Vite's CJS entry. A `.mjs` Vitest config makes
the warning go away (measured: it is absent from every run made through `--config *.mjs`).

Note the default `include` glob: `**/*.{test,spec}.?(c|m)[jt]s?(x)`. **None of the 18 files can ever
be selected by it** — they are `*Test.js`. So the switch-on moment is not "write a config", it is
"write the first `*.test.mjs`", and until then this script is green-by-vacuum-minus-one.

### A2. Does Vitest load `vite.config.js`? Yes. Do its build hooks fire? No. Does it write to `target/`? No.

**Loaded — measured.** With *no* Vitest config at all, a throwaway
`src/test/recon-throwaway/probe.test.mjs` containing
`import arrayify from "org/forgerock/openam/ui/common/util/array/arrayify"` **resolved and passed**.
There is no `node_modules/org`; the only thing that can resolve that specifier is
`vite.config.js`'s `resolve.alias`. So Vitest picks `vite.config.js` up as its Vite config when no
`vitest.config.*` exists, evaluates the whole file including the `EXPECTED_VITE_MAJOR` guard, and
applies `resolve`.

The guard does not trip: `require.resolve("vite")` from this directory is the local 5.4.21, exactly
as the comment at `vite.config.js:245` predicted for this consumer. If it ever did trip it would
throw during config load and `vitest run` would die before collection.

**Build hooks do not fire, and nothing is written to `target/`.** Measured directly: a
`find target -type f -printf '%p %s %T@\n' | sort` snapshot taken before and after `npm run
test:unit`, and again after a real (passing) test run, **diffed to zero lines both times** — 2664
files, no additions, no size changes, no mtime changes.

Mechanically why, per plugin in the `plugins:` array (`vite.config.js:2664`):

| plugin | hooks | fires under `vitest run`? |
|---|---|---|
| `react({jsxRuntime:"classic"})` | transform | yes, if a `.jsx` is reached |
| `xui-sloppy-mode-libraries` (`enforce:"pre"`) | `buildStart`, `transform`, `buildEnd` | serve-mode only; see the caveat below |
| `xui-assert-alias-ordering` | `configResolved` | **yes** — assertion only, no writes |
| `xui-assert-aliased-libraries` | `buildEnd` | see caveat |
| `xui-assert-side-effects` | `configResolved` | **yes** — assertion only |
| `xui-assert-react-select-globals` | `configResolved` | **yes** — assertion only |
| `xui-assert-configured-modules` | `configResolved`, `generateBundle` | `generateBundle` never runs in serve |
| `xui-requirejs-entry-stubs` | `configResolved`, `generateBundle` | `generateBundle` never runs in serve |
| **`xui-static-assets`** | `configResolved`, `buildStart`, `writeBundle` | **`apply: "build"` (`vite.config.js:2569`) — the whole plugin is skipped** |

`xui-static-assets` is the only plugin that writes anything (`stageNpmLibraries`,
`composeStaticAssets`, `copyLibraries`, `renderStylesheets`, `stampIndexHtml`), and its
`apply: "build"` is what keeps a test run out of `target/`. **That single line is load-bearing for
the whole Vitest story.** If someone ever deletes it to make `npm run dev` serve assets, every
`vitest run` starts staging npm libraries into `target/npm-libs` and composing `target/compiled` as
a side effect of running a unit test. Worth a note wherever 4.10 lands.

**One caveat that did not bite but could.** `xui-sloppy-mode-libraries.buildEnd` *throws* if the
i18next patch never fired (`vite.config.js:2228`), and Vite's dev-server plugin container does call
`buildEnd` on close. It did not fire in any run made here — the plugin's `transform` never saw
i18next (a node_modules dependency goes through esbuild pre-bundling, which does not run Vite
transform hooks; the plugin's own header says so), and no run failed at teardown. Recorded as
"observed not to happen", not as "cannot happen": if a future Vitest/Vite pairing starts closing the
container the way `vite build` does, this is the plugin that turns a green suite red at the very
end with a message about a library patch. **If that ever happens, do not delete the patch entry.**

### A3. Config shape — recommendation

**Recommended: a separate `vitest.config.mjs` that imports `vite.config.js` and re-exports its
`resolve.alias`, `resolve.extensions` and `define`.** This is what was used for every measurement
below and it is the only one of the three that was made to work end to end.

```js
import { defineConfig } from "vitest/config";
import viteConfig from "./vite.config.js";

export default defineConfig({
    resolve: {
        alias: viteConfig.resolve.alias,
        extensions: viteConfig.resolve.extensions
    },
    define: viteConfig.define,
    test: {
        environment: "jsdom",
        include: ["src/test/vitest/**/*.test.mjs"],
        setupFiles: ["src/test/vitest/setup.mjs"],
        server: { deps: { inline: [/@openidentityplatform[\\/]/] } }
    }
});
```

Three things about that block are not obvious and were each learned by a failing run — see B.

**The three options, and what each costs when `vite.config.js` changes:**

| option | cost of a later `vite.config.js` change | other cost |
|---|---|---|
| **import the alias array (recommended)** | none — alias edits, new shims, new vendored libs all arrive for free. The one way it breaks is a *rename* of `resolve.alias` / `define`, which fails loudly at config load | parses 276 kB of config on every run. **Measured: ~120 ms** (2.06 s vs 1.94 s wall for an identical single-file jsdom run, n=3 each, stable to 10 ms). Negligible |
| redeclare only the aliases the tests need | **the expensive one.** The tests reach 3 of the shims, both commons packages, `store/`, `config/ThemeConfiguration`, the bare `Router` id, `jquery`, `lodash` and `i18next`. A silent divergence between the two tables is exactly the "two Routers" failure the alias-3 comment at `vite.config.js:3207` warns about, arriving through the test harness instead of the build | fastest to load; needs its own copy of `define`, which is where `__THEME_CONFIG_OVERRIDE__` was first found missing |
| a `test:` block inside `vite.config.js` | zero drift by construction | **rejected.** It puts test-only config (`environment`, `setupFiles`, `server.deps.inline`) into the file the *production build* reads, and it forgoes a `.mjs` config, so the CJS-deprecation warning stays. It also makes `vitest.config.mjs`'s absence a thing a reader has to notice |

The parse cost is the only real argument against the recommendation and it is 120 ms. Import it.

### A4. Environment: **jsdom**. 9 of the 18 subject modules cannot be imported without a DOM.

Measured, not assumed. A throwaway probe `await import(...)`-ed each of the 18 subject modules
(plus `jquery`, `lodash`, `Constants`) **unmocked**, once under `environment: "node"` and once under
`environment: "jsdom"`, with `server.deps.inline` and `define` already in place so the only variable
was the DOM:

| subject | node | why |
|---|---|---|
| `.../navigation/createBreadcrumbs` | **FAIL** | `window is not defined` |
| `.../common/models/JSONSchema` | **FAIL** | `window is not defined` |
| `.../common/models/JSONValues` | ok | |
| `.../common/RouteTo` | **FAIL** | `location is not defined` (through `Constants`) |
| `.../common/sessions/SessionValidator` | **FAIL** | `window is not defined` |
| `.../sessions/strategies/MaxIdleTimeLeftStrategy` | **FAIL** | `location is not defined` (through `Constants`) |
| `.../util/array/arrayify` | ok | |
| `.../util/object/flattenValues` | ok | |
| `.../common/util/Promise` | **FAIL** | `window is not defined` (through `jquery`) |
| `.../common/util/RealmHelper` | **FAIL** | `window is not defined` |
| `.../common/util/resolveAssetUrl` | ok | |
| `.../common/util/ThemeManager` | **FAIL** | `window is not defined` |
| `.../common/util/uri/query` | ok | |
| `.../user/login/RESTLoginHelper` | **FAIL** | `window is not defined` |
| `store/actions/creators` | ok | |
| `store/actions/types` | ok | |
| `store/reducers/server` | ok | |
| `store/reducers/session` | ok | |
| *(`jquery`)* | **FAIL** | `window is not defined` |
| *(`lodash`)* | ok | |
| *(`Constants`)* | **FAIL** | `location is not defined` |

**9 need a DOM, 9 do not.** All 21 imported clean under jsdom. Note the failures are at *module
evaluation* time in transitive `jquery`/commons code, not in an assertion — so they are not
negotiable by rewriting a test. Four of the 18 test files also `import "jquery"` themselves, and all
four are already in the DOM-needing nine.

Splitting the run by environment (per-file `// @vitest-environment node` on the nine cheap ones)
would save roughly 0.7 s of environment setup per worker and buy a second thing to keep in step.
**Recommend one `environment: "jsdom"` for all 18**, matching
`commons/ui/commons/vitest.config.mjs`, whose own comment gives the same reasoning.

**happy-dom** was not benchmarked. It is not installed anywhere in this tree, and the modules that
need a DOM need `window.location`, jQuery's full bootstrap and `$("<link/>").appendTo("head")` —
which is exactly the surface where happy-dom and jsdom diverge. Not worth the risk for 0.7 s.

> **jsdom is not a devDependency of this module and is not in `package-lock.json`.**
> Every jsdom run above worked only because `require.resolve("jsdom")` walks up and lands on
> `OpenAM/openam-ui/node_modules/jsdom` (27.4.0) — the untracked phantom tree that
> `vite.config.js:225-234` explicitly warns against building against (`git ls-files
> openam-ui/package.json` returns nothing). A fresh clone plus `npm install` inside `openam-ui-ria`
> gets **no jsdom**, and `environment: "jsdom"` then fails at startup. See "New dependencies".

---

## B. Resolution — proved by running

**A test file can `import` a module by its AMD id.** Cheapest real module,
`org/forgerock/openam/ui/common/util/array/arrayify` (a 3-line `[].concat(value)` with no imports):

```js
import { describe, it, expect } from "vitest";
import arrayify from "org/forgerock/openam/ui/common/util/array/arrayify";
```

passed with **no Vitest config at all** (vite.config.js picked up automatically) and again under the
recommended `vitest.config.mjs`. The whole probe of 21 ids in A4 resolved under jsdom.

### The one class of ids that does NOT resolve out of the box

**Bare AMD ids imported from *inside* `node_modules/@openidentityplatform/ui-commons` and
`…/ui-user`.** Not the ids AM's own sources use — those go through `resolve.alias` and work. The
ones the *commons package's own modules* use to reach each other and to reach AM.

The failure, measured, under jsdom with a config that carried the full alias array:

```
PROBE FAIL  org/forgerock/openam/ui/common/RouteTo ::
  Cannot find package 'org' imported from
  /home/…/openam-ui-ria/node_modules/@openidentityplatform/ui-commons/esm/…
```

Cause: Vitest **externalizes `node_modules` by default** and hands those files to Node's own ESM
loader, which has never heard of `resolve.alias`. So `import … from "org/forgerock/…"` inside a
commons file is read as a bare *package* specifier named `org`.

Affected in the probe: `RouteTo`, `SessionValidator`, `MaxIdleTimeLeftStrategy`, `RealmHelper`,
`RESTLoginHelper` — i.e. every subject with an unmocked transitive commons import. **Fix, measured
to work:**

```js
test: { server: { deps: { inline: [/@openidentityplatform[\\/]/] } } }
```

`commons/ui/commons/vitest.config.mjs` needs the same knob for the same reason (there, against
`target/npm/esm/`), which is a decent sign it is the intended shape rather than a workaround.

**This is masked by mocking, which is why it is worth writing down.** The D port of `RouteToTest`
passes *without* `deps.inline`, because all four commons ids are `vi.mock`ed and the real files are
never loaded. The gap surfaces only on the tests that let a real commons module through —
`RealmHelperTest` most of all. Put `deps.inline` in from the start; do not wait for it to show up
as a mystery in 9.2.

### A second, quieter one: `define`

`ThemeManager` failed under jsdom with `__THEME_CONFIG_OVERRIDE__ is not defined` until
`define: viteConfig.define` was copied across. `vite.config.js:3813` declares three of these —
`__TARGET_VERSION__`, `__LOGIN_HELPER_CLASS__`, `__THEME_CONFIG_OVERRIDE__` — and they are
compile-time substitutions, so a Vitest config that omits `define` produces a `ReferenceError` at
module evaluation, not a resolution error. Another reason to import `vite.config.js` rather than
retype a subset of it.

---

## C. The 18 files

`cases` = count of `it(`. Total **160**. "Fresh module needed" = the subject holds mutable state at
module scope, so ESM's one-instance-per-process caching changes behaviour that Squire's
per-injector RequireJS context used to isolate.

| # | path (under `src/test/js/`) | squire | sinon | cases | imports (beyond squire/sinon) | will not survive a mechanical port |
|---|---|---|---|---|---|---|
| 1 | `org/…/admin/views/common/navigation/createBreadcrumbsTest.js` | **yes** | yes (24) | 20 | mocks `commons/util/URIUtils`, `jquery` | 20 × `sinon.test(() => …)` — **arrow, no `this`**, so the wrapper is pure ceremony and drops. Otherwise mechanical |
| 2 | `org/…/common/models/JSONSchemaTest.js` | **yes** | yes (3) | 14 | imports `JSONValues`; mocks `i18next` | 1 sinon-chai `calledWith`. Mock must be `{ default: {t} }` — `i18next` resolves to `shims/i18next.js` |
| 3 | `org/…/common/models/JSONValuesTest.js` | no | no | 19 | `JSONValues` | nothing. **Cheapest port in the set** |
| 4 | `org/…/common/RouteToTest.js` | **yes** | yes (8) | 9 | `jquery`, `Constants`; mocks 4 commons ids | ported and run — see D. `context` alias; sinon-chai; fresh module per case |
| 5 | `org/…/common/sessions/SessionValidatorTest.js` | **yes** | yes (6) | 5 | `jquery`; mocks `openam/…/login/logout` | **fresh module per case is mandatory** (module-scope `delay`). `sinon.useFakeTimers`, `sinon.spy(window,"clearTimeout")` — both verified to work. See G |
| 6 | `org/…/common/sessions/strategies/MaxIdleTimeLeftStrategyTest.js` | **yes** | yes (3) | 2 | `jquery`; mocks `SessionService` | nothing beyond the standard rewrite. **Smallest Squire file — the natural first port** |
| 7 | `org/…/common/util/array/arrayifyTest.js` | no | no | 3 | `arrayify` | 5 × `context` → alias. Assertions (`.instanceOf`, `.empty`, `.members`, `.eql`) verified to pass unchanged |
| 8 | `org/…/common/util/object/flattenValuesTest.js` | no | no | 1 | `flattenValues` | nothing |
| 9 | `org/…/common/util/PromiseTest.js` | no | **yes (6)** | 16 | `jquery`, `lodash`, `Promise` | **24 sinon-chai assertions** — the densest in the set. 8 × `context` |
| 10 | `org/…/common/util/RealmHelperTest.js` | **yes (`.store()`)** | yes (14) | 12 | `.store()`s `commons/main/Configuration` + `commons/util/URIUtils` | **NOT mechanical.** Squire `.store()` has no `vi.mock` equivalent, and 11 × `this.stub(…)` inside `sinon.test(function(){})` — **`this` is `undefined` under Vitest** (measured). See D and G |
| 11 | `org/…/common/util/resolveAssetUrlTest.js` | **yes** | yes (3) | 12 | none | **NOT mechanical.** 5 cases stub `require.toUrl`; `typeof globalThis.require === "undefined"` under Vitest (measured). Fresh module per case (or the module's own `reset()`) |
| 12 | `org/…/common/util/ThemeManagerTest.js` | **yes** | yes (10) | 24 | `jquery`, `lodash`, `Constants`; mocks `jquery`, `config/ThemeConfiguration`, 2 commons ids, bare `Router` | **hardest of the ten.** Mocks `jquery` *and* needs the real `$.Deferred` (`mock$.Deferred = _.bind($.Deferred,$)`) → `vi.importActual("jquery")`, verified available. Also stubs `require.toUrl`. 12 sinon-chai assertions. Needs `define` |
| 13 | `org/…/common/util/uri/queryTest.js` | **yes** | yes (3) | 7 | mocks `commons/util/URIUtils` | nothing beyond the standard rewrite. Subject is a `.jsm` — see the specifier warning in D |
| 14 | `org/…/user/login/RESTLoginHelperTest.js` | **yes** | no | 5 | mocks 3 ids **with `{}`** (cycle-breaking only, nothing asserted on them) | `before` (once) not `beforeEach`. Mocking with `{}` gives a namespace with no `default`; the importers must tolerate `undefined` — **verify, do not assume** |
| 15 | `store/actions/creatorsTest.js` | no | no | 3 | `store/actions/creators`, `…/types` | nothing |
| 16 | `store/actions/typesTest.js` | no | no | 3 | `store/actions/types` | nothing |
| 17 | `store/reducers/serverTest.js` | no | no | 2 | `store/actions/types`, `store/reducers/server` | nothing |
| 18 | `store/reducers/sessionTest.js` | no | no | 3 | `store/actions/types`, `store/reducers/session` | nothing |

**The Squire ten** are 1, 2, 4, 5, 6, 10, 11, 12, 13, 14. **The Squire-free eight** are 3, 7, 8, 9,
15, 16, 17, 18.

### C1. Assertion style — the chai half works unchanged

`test-main.js` did `chai.use(sinonChai); window.expect = chai.expect`. Vitest's `expect` **is** chai
(5.x) with jest matchers bolted on, and the plain-chai assertions in these files pass against it
**unchanged** — verified by running `expect(x).to.be.an.instanceOf(Array).and.be.empty`,
`.and.have.members([…])` and `.to.be.eql([…])` (three of `arrayifyTest`'s four assertion shapes) as
a real Vitest test. `.to.throw(/…/)`, `.to.eq`, `.to.equal`, `.to.not.have.ownProperty` are all
chai core and are used throughout; no rewrite needed.

The only *mandatory* per-file edits for the eight Squire-free files are therefore:
`import { describe, it, expect } from "vitest"` (house style: explicit, not `globals: true`), a
`const context = describe;` where `context` is used — **Vitest does not export `context`**, measured
`typeof vitestExports.context === "undefined"` — and the `define([…], (…) => {…})` wrapper becoming
`import` statements.

### C2. sinon-chai is **NOT** droppable — correction to the brief

The premise is half right and the wrong half matters.

**Confirmed: no file uses a `.to.have.been.*` matcher.** `grep -rn "to\.have\.been" src/test/js`
returns nothing.

**But sinon-chai is used, 46 times, in its short form** — `.to.be.called`, `.to.be.calledOnce`,
`.to.be.calledWith(…)`, `.to.not.be.called`, and the chained `.to.be.calledOnce.calledWith(…)`.
Those properties/methods are registered by **sinon-chai**, not by chai:

| file | sinon-chai assertions |
|---|---|
| `PromiseTest.js` | 24 |
| `ThemeManagerTest.js` | 12 |
| `RouteToTest.js` | 7 |
| `SessionValidatorTest.js` | 3 |
| `JSONSchemaTest.js` | 1 |

**Measured: `chai.use(sinonChai)` works under Vitest 2.1.9.** A throwaway setup file —

```js
import { chai } from "vitest";
import sinonChai from "sinon-chai";
chai.use(sinonChai);
```

— made `expect(spy).to.be.calledOnce`, `.to.be.calledOnce.calledWith("a", 1)` and
`expect(other).to.not.be.called` all pass, *and* made an uncalled spy fail
`expect(spy).to.be.calledOnce` (checked explicitly, so it is a live assertion and not a no-op).
This is the same `setupFiles` slot the commons suite uses for `consumer-bindings.mjs`.

Two things to know about that:

1. **sinon-chai 2.8.0 declares `peerDependencies: { chai: ">=1.9.2 <4", sinon: ">=1.4.0 <2" }`.**
   Vitest 2.1.9 bundles chai **5**. So it is being used two majors outside its declared range. It
   works — the plugin API did not change — but this is unenforced and should be written into
   whatever config file registers it. Upgrading to sinon-chai 4.x is *not* a free fix: it needs
   sinon ≥ 9, and these tests use sinon 1.x APIs (`sinon.sandbox.create()`, three-argument
   `sandbox.stub(obj, "m", fn)`, `sinon.test`) that sinon 2+ removed. **Keep sinon 1.17.6 and
   sinon-chai 2.8.0 together.**
2. **If sinon-chai is dropped without rewriting the 46 assertions, chai 5 fails loudly, not
   silently.** Measured: without `chai.use(sinonChai)`, `expect(uncalledSpy).to.be.calledOnce`
   *throws* (chai 4+ proxies `Assertion` and rejects unknown properties), and `.calledWith(…)`
   throws as "not a function". So there is no silent-green hazard here. That is a relief, not a
   licence — the 46 assertions still have no jest-matcher equivalent, because Vitest's
   `toHaveBeenCalled*` family looks for a `.mock` property that sinon spies do not have.

**Recommendation: keep sinon and sinon-chai, register sinon-chai in `setupFiles`, change none of
the 46 assertions.** That is also what makes the ports transcriptions rather than rewrites, which is
the house rule the commons suite's header states.

### C3. Module-scope state that must be fresh per case

Squire gave each `new Squire()` its own RequireJS context, so every `beforeEach` got a genuinely new
module. ESM caches one instance per process. Modules in the 18's blast radius that hold mutable
module-scope state:

| module | state | consequence |
|---|---|---|
| `…/util/resolveAssetUrl.js` | `settings = { urlArgs, resolved }` | **known**, and the module already ships `resolveAssetUrl.reset()` with a comment naming D12 and `vi.resetModules()` by name. Its test's `beforeEach` builds a new injector *specifically* for this |
| `…/sessions/SessionValidator.js` | `let delay` (line 23) | **found here, not previously flagged.** `start()` throws `"Validator has already been started"` when `delay` is truthy; the test's `#start > when invoked for the 2nd time > beforeEach` starts the validator and nothing stops it. Without a fresh module per case, the *next* test's first `start()` throws. There is no `reset()` export — the only levers are `Validator.stop()` in an `afterEach` or `vi.resetModules()` |
| `…/util/ThemeManager.js` | `var defaultThemeName = "default", …` | the chain is one `var` of function expressions plus a constant; **no module-scope reassignment found** (`grep -nE "^\s{0,4}[a-zA-Z_]+ = "` returns only the function definitions). Its test's per-test injector is about the *mocks*, not about module state |
| `…/util/RealmHelper.js`, `…/user/login/RESTLoginHelper.js` | `var obj = {}` / `new AbstractConfigurationAware()` | the exported object itself. Stubs planted on it must be restored, which both tests already do |

**So: two, and the second one is new.** `resolveAssetUrl` and `SessionValidator`. Use
`vi.resetModules()` + dynamic `import()` in `beforeEach` for both; it is proved to work in D.

---

## D. The Squire ten — one worked port

### Why `RouteToTest.js`

Chosen as the most representative because it is the only one that exercises all four of the things
the other nine will each need some subset of:

* **four bare aliased AMD ids mocked at once** (`commons/main/{Configuration,EventManager,Router,SessionManager}`) — the dominant shape; 7 of the 10 do exactly this;
* **mock objects built in the test body** (`beforeEach`), which is the `vi.mock` hoisting problem in its natural habitat;
* **a per-case fresh module** (`new Squire()` in `beforeEach`);
* **sinon-chai** (7 assertions) *and* plain chai (`to.not.have.ownProperty`) side by side;
* plus `context`, an unmocked real import (`Constants`), a `$.Deferred` promise, and
  `sinon.spy(RouteTo, "setGoToUrlProperty")` — spying on a method of the subject's own default
  export, which only works because `RouteTo.logout()` calls `obj.setGoToUrlProperty()` and not a
  bare local (checked in the source; **if it had called the local binding, the spy would have been
  silently ineffective** — worth checking per subject).

`ThemeManagerTest` is harder and `RealmHelperTest` is stranger, but neither is *typical*. Both are
called out separately below.

### The port, in full — **run, 9/9 passing, first attempt**

Run under the A3 config with `environment: "jsdom"` and the sinon-chai `setupFiles`:
`✓ RouteTo.test.mjs (9 tests) 66ms — Tests 9 passed (9)`.

```js
/*
 * ES module port of src/test/js/org/forgerock/openam/ui/common/RouteToTest.js — same tests,
 * same names, same order.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import $ from "jquery";
import sinon from "sinon";
import Constants from "org/forgerock/openam/ui/common/util/Constants";

const context = describe;

// Stable identities across vi.resetModules(); repopulated per case in beforeEach.
const mocks = vi.hoisted(() => ({
    Configuration: {},
    EventManager: {},
    Router: {},
    SessionManager: {}
}));

vi.mock("org/forgerock/commons/ui/common/main/Configuration", () => ({ default: mocks.Configuration }));
vi.mock("org/forgerock/commons/ui/common/main/EventManager", () => ({ default: mocks.EventManager }));
vi.mock("org/forgerock/commons/ui/common/main/Router", () => ({ default: mocks.Router }));
vi.mock("org/forgerock/commons/ui/common/main/SessionManager", () => ({ default: mocks.SessionManager }));

describe("org/forgerock/openam/ui/common/RouteTo", () => {
    let Configuration;
    let EventManager;
    let Router;
    let RouteTo;
    let SessionManager;

    beforeEach(async () => {
        Configuration = mocks.Configuration;
        EventManager = mocks.EventManager;
        Router = mocks.Router;
        SessionManager = mocks.SessionManager;

        // Squire built these fresh per case; here the identity is stable and the CONTENT is reset.
        Object.keys(Configuration).forEach((k) => delete Configuration[k]);
        Object.keys(EventManager).forEach((k) => delete EventManager[k]);
        Object.keys(Router).forEach((k) => delete Router[k]);
        Object.keys(SessionManager).forEach((k) => delete SessionManager[k]);

        Configuration.globalData = { authorizationFailurePending: true };
        Configuration.setProperty = sinon.stub();
        EventManager.sendEvent = sinon.stub();
        Router.configuration = { routes: { login: { url: "loginUrl" } } };
        Router.getCurrentHash = sinon.stub().returns("page");
        SessionManager.logout = sinon.stub();

        vi.resetModules();
        RouteTo = (await import("org/forgerock/openam/ui/common/RouteTo")).default;
    });

    describe("#setGoToUrlProperty", () => {
        context("when a gotoURL is not set and the current hash does not match the login route's URL", () => {
            it("sets the gotoURL to be the current hash", () => {
                RouteTo.setGoToUrlProperty();
                expect(Configuration.setProperty).to.be.calledOnce.calledWith("gotoURL", "#page");
            });
        });
    });

    describe("#forbiddenPage", () => {
        it("deletes \"authorizationFailurePending\" attribute Configuration.globalData", () => {
            RouteTo.forbiddenPage();
            expect(Configuration.globalData).to.not.have.ownProperty("authorizationFailurePending");
        });
        it("sends EVENT_CHANGE_VIEW event", () => {
            RouteTo.forbiddenPage();
            expect(EventManager.sendEvent).to.be.calledOnce.calledWith(Constants.EVENT_CHANGE_VIEW, {
                route: {
                    view: "org/forgerock/openam/ui/common/views/error/ForbiddenView",
                    url: /.*/
                },
                fromRouter: true
            });
        });
    });

    describe("#forbiddenError", () => {
        it("sends EVENT_DISPLAY_MESSAGE_REQUEST event", () => {
            RouteTo.forbiddenError();
            expect(EventManager.sendEvent).to.be.calledOnce.calledWith(Constants.EVENT_DISPLAY_MESSAGE_REQUEST,
                "unauthorized");
        });
    });

    describe("#logout", () => {
        let promise;

        beforeEach(() => {
            promise = $.Deferred();
            SessionManager.logout = sinon.stub().returns(promise);
            sinon.spy(RouteTo, "setGoToUrlProperty");
        });

        afterEach(() => {
            RouteTo.setGoToUrlProperty.restore();
        });

        it("invokes #setGoToUrlProperty", () => {
            RouteTo.logout();
            expect(RouteTo.setGoToUrlProperty).to.be.calledOnce;
        });

        context("when logout is successful", () => {
            it("sends EVENT_AUTHENTICATION_DATA_CHANGED event", () => {
                const p = promise.resolve();
                return p.then(() => {
                    RouteTo.logout().then(() => {
                        expect(EventManager.sendEvent).to.be
                            .calledWith(Constants.EVENT_AUTHENTICATION_DATA_CHANGED, { anonymousMode: true });
                    });
                });
            });

            it("sends EVENT_CHANGE_VIEW event", () => {
                const p = promise.resolve();
                return p.then(() => {
                    return RouteTo.logout().then(() => {
                        expect(EventManager.sendEvent).to.be.calledWith(Constants.EVENT_CHANGE_VIEW, {
                            route: Router.configuration.routes.login
                        });
                    });
                });
            });
        });

        context("when logout is unsuccessful", () => {
            it("sends no events", () => {
                promise.fail();
                RouteTo.logout();
                expect(EventManager.sendEvent).to.not.be.called;
            });
        });
    });

    describe("#loginDialog", () => {
        it("sends EVENT_SHOW_LOGIN_DIALOG event", () => {
            RouteTo.loginDialog();
            expect(EventManager.sendEvent).to.be.calledOnce.calledWith(Constants.EVENT_SHOW_LOGIN_DIALOG);
        });
    });
});
```

Every assertion is byte-identical to the original. What changed is the wrapper, the mock mechanism,
`const context = describe`, and the mock-object lifecycle.

### D1. Can `vi.mock` intercept a bare aliased AMD-id specifier? **Yes.**

`vi.mock("org/forgerock/commons/ui/common/main/Configuration", …)` intercepted the *source module's*
`import Configuration from "org/forgerock/commons/ui/common/main/Configuration"` cleanly. Vitest
resolves the `vi.mock` specifier through the same Vite resolver (aliases included) that resolves the
import, and matches on the resolved path.

### D2. Must the specifier string match the import exactly? **No — but a non-resolving string is a silent no-op, and that is the trap.**

Measured, three ways, against `org/forgerock/openam/ui/common/util/uri/query`:

* `vi.mock("org/forgerock/openam/ui/common/util/uri/query", …)` — applied. (the exact id)
* `vi.mock("../../main/js/org/forgerock/openam/ui/common/util/uri/query.jsm", …)` — **applied.** A
  relative path from the test file to the same file works; only the resolved path has to match.
* `vi.mock("…/uri/query.js", …)` (wrong extension — the real file is `query.jsm`) — **not applied,
  no error, no warning.** Same for a made-up id. The test simply runs against the real module.

**That is the single most dangerous thing found in this recon.** Ten files are about to be rewritten
into `vi.mock` calls; a fat-fingered id or a wrong extension produces a test that runs the *real*
module and, for the ones whose mocks are only breaking a cycle (`RESTLoginHelperTest`) or supplying
an empty stub, may still go green. Mitigation: after porting each file, assert something about the
mock (all ten already do, except `RESTLoginHelperTest`, which mocks with `{}` and asserts nothing on
them — that one needs a deliberate check that the mock is live). Also worth remembering that `.jsm`
is the real extension for a good number of these modules, so *prefer the bare AMD id* — it goes
through `resolve.extensions` and cannot get the extension wrong.

### D3. What `vi.mock` hoisting costs when the mock needs a value from the test body

`vi.mock` calls are hoisted above every `import` and every top-level statement. Measured failure,
from a first attempt that computed a path into a `const` and named it in the factory:

```
ReferenceError: Cannot access 'ABS' before initialization
```

— thrown at *file load*, killing the whole file, not one test.

The cost is therefore: **every value a `vi.mock` factory closes over must come from `vi.hoisted()`**,
which is an extra indirection and, more importantly, an extra *lifetime*. `vi.hoisted` runs once per
file, while the Squire `beforeEach` ran once per case. That is the real structural difference between
the two harnesses and it is what the `Object.keys(…).forEach(delete)` block in the port above is
paying for: the mock **objects** must have file lifetime (so the factory can name them and so
`vi.resetModules()` does not swap them out from under the test's local handles) while the mock
**contents** must have case lifetime. Keeping identity stable and resetting contents is the shape
that works; rebuilding the objects in `beforeEach` and expecting the factory to see the new ones does
not, because the factory closed over the old reference.

Two cheaper variants exist and are worth knowing: `vi.mock(id)` with no factory plus
`vi.mocked(await import(id))` in the body avoids hoisting entirely for auto-mockable modules; and
for a subject with exactly one mocked dependency, `vi.doMock` (not hoisted) inside `beforeEach`
followed by a dynamic import is simpler than the above. `queryTest`, `MaxIdleTimeLeftStrategyTest`
and `JSONSchemaTest` each mock exactly one id and are candidates for the `vi.doMock` shape.

### D4. Per-case fresh module instance — **achievable, `vi.resetModules()` + dynamic `import()`**

Measured both directions against `resolveAssetUrl`, the module that documents this problem:

* two `await import(…)` of the same id in one test → **same instance** (`a === b`, and the second
  handle saw the first's `configure({urlArgs:"v=1"})`);
* `vi.resetModules()` then `await import(…)` → **fresh instance**, which threw
  `resolveAssetUrl("x") called before configure() and with no require.toUrl available` — i.e.
  `settings.urlArgs` was back to `null`. Freshness proved by the module's own guard.

Static `import` at the top of the file is **not** an option for a subject that needs freshness — it
binds once. The subject must be pulled in with `await import()` inside `beforeEach`, exactly as the
port above does. `resolveAssetUrl.reset()` is the alternative for that one module and is cheaper,
but `vi.resetModules()` is the general answer and is what `SessionValidator` (no `reset()` export)
will need.

### D5. Are the other nine mechanical? **Seven yes, two no.**

**Mechanical (7)** — `queryTest`, `MaxIdleTimeLeftStrategyTest`, `createBreadcrumbsTest`,
`JSONSchemaTest`, `SessionValidatorTest`, `RESTLoginHelperTest`, and `RouteToTest` itself. They are
all "`beforeEach` → new Squire → `.mock(id, stubObject)` × N → `.require([subject])`", which is
exactly the shape ported above. `createBreadcrumbsTest`'s 20 `sinon.test(() => …)` wrappers are
arrow functions that never touch `this`, so they simply drop. `SessionValidatorTest` needs the
`vi.resetModules()` half (C3) and nothing else structural. `RESTLoginHelperTest` needs one
deliberate check that its three `{}` mocks are actually live (D2).

**Not mechanical (2), and both for reasons that are about the harness rather than the assertions:**

1. **`RealmHelperTest.js`** — two separate problems.
   * It uses Squire's **`.store()`**, not `.mock()`: it asks for the *real* commons modules and
     receives them through a `"mocks"` pseudo-module so it can stub methods on them. `vi.mock` has
     no equivalent. The ESM replacement is different in kind: `import URIUtils from
     "org/forgerock/commons/ui/common/util/URIUtils"` and stub methods on it directly. That works
     **because both commons modules end `export default obj` where `obj` is a plain mutable object**
     (checked in `node_modules/@openidentityplatform/ui-commons/esm/…`), so the stub is visible to
     `RealmHelper`, which imports the same instance. It is not a frozen namespace object and
     `vi.spyOn` is not needed. But it is a rewrite of the setup, not a transcription of it.
   * **11 × `this.stub(…)` inside `it(name, sinon.test(function () { … }))`.** Measured: **`this`
     is `undefined` under Vitest**, so this throws `Cannot read properties of undefined (reading
     'stub')`. Mocha called the test function with its own `Context` as `this`; Vitest passes a
     `TestContext` as the first *argument* and leaves `this` unbound. All 11 must become an explicit
     `sinon.sandbox.create()` in `beforeEach` with `sandbox.restore()` in `afterEach` — which is
     verified to work (`sinon.sandbox.create()` and the three-argument `sandbox.stub(o,"m",fn)` both
     tested).
   * It also uses `before` (once for the file), not `beforeEach`, while mutating
     `Configuration.globalData.auth.subRealm` per case. That is order-dependent today and stays
     order-dependent after the port; it is not made worse, but it is not made better either.

2. **`resolveAssetUrlTest.js`** — 5 of its 12 cases do `sandbox.stub(require, "toUrl", …)` or
   `require.toUrl = undefined`. Measured: **`typeof globalThis.require === "undefined"`** under
   Vitest (both `node` and `jsdom`), so those five throw `ReferenceError` before they assert
   anything. This is not a defect in the module — the module's own header says the delegating branch
   exists for the three `.ftl` entry points that still load RequireJS — but the test can no longer
   get at it by accident. The port has to install a fake: `globalThis.require = { toUrl: … }` in
   `beforeEach`, `delete globalThis.require` in `afterEach`. That is a decision about what the test
   *means*, not a mechanical rewrite, and it should be made deliberately and commented.

**`ThemeManagerTest.js` is mechanical but expensive** and deserves its own note: it is the largest
(24 cases, 12 sinon-chai assertions), it mocks six ids including `jquery` and the bare `Router`, it
needs `vi.importActual("jquery")` for the real `$.Deferred` while `jquery` is mocked (verified
available), it stubs `require.toUrl` (same problem as above), and it is the only file that depends
on `define` being carried across. Budget it as two files' worth of work.

---

### D6. Mocha's `done` callback does NOT work under Vitest, and it fails SILENTLY

> **Added during task 9.1, not during this recon.** The recon never probed the `done` callback,
> and section C's per-file table does not mention it. It is the one thing 9.1 found that would
> have gone unnoticed until a test lied about passing.

**Measured, three ways, under Vitest 2.1.9:**

| probe | expected under Mocha | actual under Vitest |
|---|---|---|
| `it("x", (done) => setTimeout(done, 10))` | passes after 10 ms | **passes immediately** |
| `it("x", (done) => setTimeout(() => done(new Error("M")), 10))` | **fails** with `M` | **PASSES** |
| `it("x", (done) => { /* never calls done */ })` | **times out** | **passes instantly** (3.07 s whole run) |

The first argument *is* a function (`typeof arg === "function"`, `ISFN=true`), which is exactly
why this is dangerous — the callback looks supported. It is not awaited, and calling it with an
Error does nothing. The test body returns `undefined` synchronously, Vitest marks the case passed,
and whatever the callback was going to assert runs after the case is over, or never.

**So a faithfully-transcribed `done` test is worse than a deleted one: it passes unconditionally
while looking like coverage.** Vitest 3 removes the callback outright, which would at least fail
loudly; 2.1.9 does not.

### Which files this touches

`grep -rn "(done)" src/test/js` — **10 of the 18**:

| file | occurrences | where | risk |
|---|---|---|---|
| `PromiseTest.js` | 1 (× 4 cases) | inside `it`, via the `whenPassed` helper | **HIGH — handled in 9.1** |
| `ThemeManagerTest.js` | **2** | check each one | **HIGH — the one to read first in 9.2** |
| `createBreadcrumbsTest.js` | 1 | Squire `beforeEach` | low |
| `JSONSchemaTest.js` | 1 | Squire `beforeEach` | low |
| `queryTest.js` | 1 | Squire `beforeEach` | low |
| `RouteToTest.js` | 1 | Squire `beforeEach` | low |
| `SessionValidatorTest.js` | 1 | Squire `beforeEach` | low |
| `RealmHelperTest.js` | 1 | Squire `before` | low |
| `RESTLoginHelperTest.js` | 1 | Squire `before` | low |
| `resolveAssetUrlTest.js` | 1 | Squire `beforeEach` | low |

The eight "low" rows are `done` in a **Squire `beforeEach`/`before`**, which `vi.mock` deletes
anyway — the callback goes when the injector goes, so the port cannot accidentally keep it. The
two that matter are the ones where `done` is inside an `it`, because those survive a mechanical
transcription and go green while asserting nothing. **`ThemeManagerTest.js` is the open one: it
has two occurrences and 24 cases, and nobody has looked at whether either is inside an `it`.**

### What 9.1 did about it, as the pattern for 9.2

`PromiseTest`'s four `whenPassed` cases became promise-returning. `done(new Error(...))` becomes a
`throw` from the fulfilment handler — jQuery 3's promises are Promises/A+ compliant, so the throw
rejects the returned promise and Vitest fails the case with that message:

```js
// was: it("rejects the promise", (done) => {
//          Promise.all(value).then(() => { done(new Error("Excepted ...")); },
//                                  (value) => { expect(value)...; done(); }); });
it("rejects the promise", () => Promise.all(value).then(() => {
    throw new Error("Excepted the promise to be rejected");
}, (value) => {
    expect(value).to.be.an.instanceOf(TypeError);
}));
```

The assertion, its message and the test name are unchanged. Proof the four are live rather than
vacuous: the file settles in 188 ms, where an unsettled returned promise would hit the 5 s
timeout, and a resolution instead of a rejection would hit the `throw`.

**Rule for 9.2: a ported case must never take a parameter.** If the original's `it` took `done`,
return the promise instead. `grep -n "it(.*(done)" ` on each file before porting it.

---

## E. The split — **preference: A**

> **A** — 9.1 stands up the harness, ports the 8 Squire-free files and deletes `karma.conf.js`;
> 9.2 ports the 10 Squire files as it converts them.
> **B** — 9.1 ports all 18 with a stand-in for Squire; 9.2 replaces the stand-in with `vi.mock`.

**A, and not by a small margin.** Stated as a preference only; the decision is the user's.

The case for A:

* **9.1 gets a real green run out of genuinely cheap material.** The eight Squire-free files are
  71 of the 160 cases, and five of them (`JSONValuesTest`, `flattenValuesTest`, and the three `store`
  files) are pure-function tests needing nothing but an `import` and a `context` alias. That is
  enough signal to prove the harness — alias resolution, `deps.inline`, `define`, jsdom, sinon-chai,
  the `context` alias — without any of it being entangled with mocking decisions.
* **The harness questions and the mocking questions fail differently and should fail separately.**
  Everything in section B (the `Cannot find package 'org'` class, the missing `define`) is a
  *config* fault that shows up as an import error. Everything in D is a *mock* fault that shows up
  as a wrong value. Landing them in one task means the first red of 9.1 could be either.
* **B's stand-in is work that is thrown away by design, and it is not small.** A Squire shim would
  have to reproduce `.mock()`, `.store()`, `.require()` and the `"mocks"` pseudo-module over ESM —
  i.e. re-implement a RequireJS context feature (`.store()`) that has no ESM analogue at all. It
  would be the hardest code in the group, written to be deleted, and it would carry its own bugs
  into every one of the ten ports, so a red in 9.2 would have three possible causes instead of two.
* **A lets `RealmHelperTest` and `resolveAssetUrlTest` be *decisions* rather than surprises.** Both
  need a judgement call (D5). Under A they land in 9.2 with the harness already trusted. Under B
  they land in 9.1 wearing a stand-in that is itself unproven.
* **The one thing A gives up is the "all 18 green at once" moment**, and with it the guarantee that
  no assertion is silently lost between the two tasks. That is real, and the mitigation is cheap:
  keep the 18 originals on disk through 9.1 and delete them only as each port lands in 9.2, so the
  originals are the checklist. (`karma.conf.js` going in 9.1 is fine — the harness is dormant and
  cannot be revived; see below. The 18 `*Test.js` files are not `karma.conf.js`.)

One amendment to A worth considering: **port `MaxIdleTimeLeftStrategyTest` in 9.1 as well.** It is
the smallest Squire file — 2 cases, one mocked id, no sinon-chai property assertions, no module
state — and having exactly one `vi.mock` file in 9.1 turns "does mocking work here at all" from a
9.2 risk into a 9.1 fact, for perhaps twenty minutes.

---

## F. The retirement radius

**Nothing in this section has been deleted.** This is the list, with what still references each
item. Checked against `package.json`, `Gruntfile.js`, `vite.config.js`, `pom.xml`, `tools/`,
`config/` and `.github/workflows/`.

### F1. Files (5)

| file | still referenced by | note |
|---|---|---|
| `karma.conf.js` | `Gruntfile.js:224-226` (`karma.build.configFile`) only | goes with Grunt or before it |
| `src/test/js/test-main.js` | `karma.conf.js` `files[0]` (as `target/test-classes/test-main.js`) only | the `chai`/`sinon-chai`/`window.expect` bootstrap the Vitest `setupFiles` replaces |
| `Gruntfile.js` | `package.json` scripts `start`, `build:grunt`, `test:karma`; **`.github/workflows/xui-local-server.yml:151`** `hashFiles(… 'openam-ui/openam-ui-ria/Gruntfile.js' …)`; the comment at `:140` says "Gruntfile.js stays in the key until 4.8 retires it" — 4.8 did not, so it is still there | the workflow line must be edited in the same change |
| `src/test/.eslintrc.json` | eslint via `npm run lint` (which lints `src/test/js`) | **not dead — wrong.** `{"env":{"mocha":true},"globals":{"expect":true}}` describes the Karma world. A Vitest suite needs no `expect` global and `env.mocha` does not supply `describe`/`it` from `vitest`. Rewrite, do not delete |
| the 18 `src/test/js/**/*Test.js` | nothing but Karma | replaced file-by-file; keep as the checklist until each port lands |

### F2. `package.json` scripts (4)

| script | current value | still referenced by |
|---|---|---|
| `start` | `grunt` | nothing outside a developer's muscle memory. **Dead** |
| `build:grunt` | `cross-env NODE_ENV=production grunt prod --verbose` | nothing — `pom.xml:247` runs `run build:production` (Vite). **Dead** |
| `test:karma` | `grunt karma:build` | nothing. **Dead** |
| `test` | the `echo "unit tests: … migrate to Vitest in group 9 (D12) …" && exit 0` stub | **`pom.xml:254-260`, the `npm-test` execution, `<phase>test</phase>`, `<arguments>run test</arguments>`.** **NOT dead — this is the wire.** Group 9 should repoint `test` at `vitest run` (or at `test:unit`), and that is what makes the suite part of `mvn package` |

### F3. devDependencies

**Dead with Karma (10):**
`karma` 6.4.3, `karma-babel-preprocessor` 8.0.2, `karma-chrome-launcher` ^3.2.0, `karma-mocha`
2.0.1, `karma-requirejs` 1.1.0, `mocha` 7.2.0, `chai` 3.5.0, `squirejs` 0.2.0, `requirejs` 2.3.7,
`cross-env` 3.1.3.

* `requirejs` is referenced only as `karma-requirejs`'s peer (`peerDependencies: {karma, requirejs}`).
  **But `src/main/js/libs/requirejs-2.3.7-min.js` is a vendored, tracked source file and MUST STAY** —
  `index.html:28` plus six `.ftl` pages in `openam-oauth2` load it by literal path, and
  `xui-requirejs-entry-stubs` emits stubs for them. Two different things with the same name. **This
  is the riskiest entry on the list**: deleting the wrong one is a green build that 404s the OAuth2
  consent, device and error pages, in a Maven module D8 excludes from this work.
* `chai` 3.5.0 is dead as a *package* — Vitest bundles its own chai 5 — but `expect`'s chai-ness is
  what the ported assertions rely on, so do not read "chai is dead" as "the chai assertions go".
* `cross-env` is used by exactly one script (`build:grunt`).

**Dead with Grunt (12):**
`grunt` 1.6.2, `grunt-cli` 1.4.3, `grunt-babel` 8.0.0, `grunt-contrib-copy` 1.0.0,
`grunt-contrib-less` 3.0.0, `grunt-contrib-requirejs` 1.0.0, `grunt-contrib-watch` 1.1.0,
`grunt-eslint` 19.0.0, `grunt-karma` 4.0.2, `grunt-newer` 1.3.0, `grunt-sync` 0.8.2,
`grunt-text-replace` 0.4.0.

**Dead once both go (3), each with a caveat:**

| package | verdict | why |
|---|---|---|
| `@babel/preset-env` ^7.28.3 | dead | used at `Gruntfile.js:121` and by `karma.conf.js`'s `babelPreprocessor`. `vite.config.js` mentions it only in a comment (`:3622`) |
| `@babel/preset-react` 7.27.1 | dead | `Gruntfile.js:122` only |
| `@babel/core` ^7.29.6 | dead **as a top-level declaration** | but it stays installed: `@vitejs/plugin-react` declares `"@babel/core": "^7.28.0"` as its own dependency. Removing the devDep does not remove the package |

**NOT dead — keep (5):** `sinon` 1.17.6 and `sinon-chai` 2.8.0 (C2); `less` and
`less-plugin-clean-css` (`vite.config.js:1333` `renderStylesheets` requires them at build time);
`rimraf`, `jsdoc`, `js-yaml`, `ajv`, `minimatch`, `eslint-config-forgerock`,
`eslint-formatter-warning-summary`, `@vitejs/plugin-react`, `vite`, `vitest`.

### F4. `package.json` `overrides` blocks (2)

`overrides.mocha` (`{flat: "5.0.2", js-yaml: "$js-yaml"}`) and `overrides.grunt`
(`{js-yaml: "$js-yaml"}`) become dead the moment their target packages go. `overrides.eslint`,
`overrides.minimatch` and `overrides.sifter` stay.

### F5. CI (1)

`.github/workflows/xui-local-server.yml:151` — `Gruntfile.js` is in the `hashFiles(…)` cache key for
the `-www.zip` cache. Removing the file changes the key (one cold cache, then normal). No workflow
step *runs* Karma or Grunt: `:208` merely notes that `-DskipTests` "skips the karma execution", and
there is no karma execution in `pom.xml` any more — the only `frontend-maven-plugin` executions are
`npm-install-commons`, `npm-build` and `npm-test`. No workflow greps for `test:karma`, `test:unit`
or `vitest`.

**Count: 5 file entries + 4 scripts (3 dead, 1 to rewire) + 25 devDependencies (22 dead outright,
3 dead with a caveat) + 2 `overrides` blocks + 1 CI line = 37 entries.**

Riskiest single entry: **`requirejs`** — because the npm devDependency is dead and the vendored
`src/main/js/libs/requirejs-2.3.7-min.js` it shares a name with is a cross-module contract that
`openam-oauth2` depends on by literal path.

---

## G. Tests that look likely to fail against the *current module*, not against the port

There is no green baseline — the Karma harness has been dormant since 4.1 and cannot be revived
(Grunt reads AMD sources; 5.4 converted all of them). So these are guesses, written down now so they
can be checked off later. Ordered by confidence.

1. **`resolveAssetUrlTest.js` — 5 of 12 cases. High confidence, measured cause.**
   `globalThis.require` is `undefined` under Vitest (measured). The cases
   *"delegates to require.toUrl…"*, *"throws when there is no require.toUrl…"*, *"does not consult
   require.toUrl once configured"*, *"throws when it lands after a url has already been resolved"*
   and *"restores the unconfigured state…"* all touch `require`. They fail as `ReferenceError`, not
   as an assertion. **This is the harness, not the module** — but the port cannot be faithful
   without a decision about what to substitute.

2. **`RealmHelperTest.js` — 11 of 12 cases. High confidence, measured cause.**
   `this` is `undefined` inside `sinon.test(function () { … })` under Vitest (measured:
   `TypeError: Cannot read properties of undefined (reading 'stub')`). Every case that calls
   `this.stub(URIUtils, …)` dies before asserting.

3. **`SessionValidatorTest.js` — cross-case leakage. Medium-high.**
   Module-scope `let delay` (C3). `#start > when invoked for the 2nd time > beforeEach` starts the
   validator and nothing stops it, so a shared module instance makes the *next* `start()` throw
   `"Validator has already been started"` in a test that expects it not to. Fixed by
   `vi.resetModules()`; will bite immediately if that is left out.

4. **`SessionValidatorTest.js` — `expect(logout.default).to.be.calledOnce`. Medium.**
   `SessionValidator.js:47` calls `logout()`, a plain call on the default import. The test mocks
   with `{"default": sinon.stub()…}` and asserts on `logout.default` — a shape inherited from
   Babel's AMD output. Under real ESM the mock factory must return `{ default: stub }` and the
   assertion must land on *that same stub object*. It does if the test keeps its handle
   (`const logoutMock = { default: sinon.stub() }` … `expect(logoutMock.default)`), so this is
   probably fine — but it is the kind of thing that goes green while testing nothing if the handle
   and the factory drift apart. Check it explicitly.

5. **`ThemeManagerTest.js` — the `require.toUrl` cases. Medium.** Same cause as (1);
   `sandbox.stub(require, "toUrl", …)` in the top-level `beforeEach`, so it takes **all 24 cases**
   with it unless a fake `globalThis.require` is installed.

6. **`ThemeManagerTest.js` — the `jquery` mock. Medium.** `mock$.Deferred = _.bind($.Deferred, $)`
   needs the real jQuery in a file where `jquery` is mocked for everyone. `vi.importActual("jquery")`
   is verified to work but is `async`, so the `beforeEach` has to become `async` — a shape change
   that has to be got right or `mock$.Deferred` is `undefined` and every promise-returning case
   fails obscurely.

7. **`RESTLoginHelperTest.js` — the three `{}` mocks. Medium-low.**
   `.mock(id, {})` under Squire gave a module whose value was `{}`. `vi.mock(id, () => ({}))` gives a
   namespace with **no `default`**, so an importer doing `import X from id` gets `undefined` rather
   than `{}`. If `RESTLoginHelper` (or anything on its import chain) touches a property of one of
   them at module scope, this is a `TypeError` at import. Use `() => ({ default: {} })` unless
   there is a reason not to.

8. **`createBreadcrumbsTest.js` — 20 cases sharing one `$.t` stub. Low.**
   The `beforeEach` builds `$ = { t: sinon.stub() }` fresh per case under Squire. Under `vi.hoisted`
   + stable identity (D3) the stub must be explicitly reset per case or `.returns(…)` calls
   accumulate. Not a module bug; a port bug that will look like one.

9. **`JSONSchemaTest.js` — `sinon.stub().withArgs(…).returns(…)`. Low.**
   The mock is `{ t: sinon.stub().withArgs("console.common.global").returns("Global Attributes") }`,
   which returns the *`withArgs` filter*, not the stub — a long-standing wart in the original that
   the port will faithfully carry across. Worth reading twice when this one goes red.

10. **Everything asserting on `Constants.*`. Low, but systemic.**
    `Constants` needs `location` at module scope and is imported unmocked by `RouteToTest` and
    `ThemeManagerTest`. Under jsdom `location` is `http://localhost:3000/` (or whatever
    `test.environmentOptions.url` says), not an OpenAM context path. Nothing in the 18 was observed
    to depend on the value — the D port passed — but if a `Constants` key is ever derived from the
    path, a jsdom URL is what it will be derived from.

**Not expected to fail:** all eight Squire-free files bar `PromiseTest` (which is only exposed
through the volume of its sinon-chai assertions, all of which are the forms verified in C2), and the
four `store` files.

---

## Things this recon could not determine

* **Whether `xui-sloppy-mode-libraries.buildEnd` can ever fire under `vitest run`.** It did not in
  any run made here and no run failed at teardown, but the plugin declares no `apply` and Vite's
  plugin container does call `buildEnd` on close. Recorded as observed-absent, not proved-impossible.
* **Whether the nine DOM-free subjects stay DOM-free once their *mocks* are applied.** The A4 probe
  imported them unmocked, which is an upper bound on what they need, not the condition the tests run
  under. It does not change the recommendation (one jsdom environment) but it means the "9 of 18"
  figure is about module imports, not about the tests.
* **`happy-dom`.** Not installed anywhere in the tree, not benchmarked.
* **Whether any of the 18 currently pass.** There is no baseline and there cannot be one. Section G
  is a written guess, which is its whole purpose.

## New dependencies required

**One, and it is not optional: `jsdom`.** It is absent from `package.json` and from
`package-lock.json`; every jsdom run in this recon resolved it from the untracked
`OpenAM/openam-ui/node_modules` tree that `vite.config.js:225` warns against. Add a `jsdom` entry to `devDependencies`; vitest 2.1.9 declares it as an optional peer with the
range `"*"`, so the pin is a choice — the copy that was actually exercised in this recon (via the
parent tree) was **27.4.0**, so pin that unless something objects.

**It was NOT installed by this recon.** `pom.xml:213-219` installs
`@openidentityplatform/ui-commons` and `@openidentityplatform/ui-user` from
`target/npm/*.tgz` with `--no-save --legacy-peer-deps`, and a plain `npm install` prunes both
("removed 50 packages", per the comment at `pom.xml:192`). Whoever adds jsdom must reinstall both
tarballs from `target/npm` afterwards, or run the add inside a Maven cycle that does it for them.

Everything else needed is already present: `vitest` 2.1.9, `vite` 5.4.21, `sinon` 1.17.6,
`sinon-chai` 2.8.0. Nothing new is needed for mocking — `vi.mock` replaces `squirejs`, and
`squirejs` is on the retirement list rather than the shopping list.
