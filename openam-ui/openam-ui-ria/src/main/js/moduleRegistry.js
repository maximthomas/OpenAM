/**
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
 * Portions copyright 2026 3A Systems, LLC.
 */

/**
 * D1'S RUNTIME MODULE REGISTRY -- the `resolveModule` seam LoaderRuntime asks the consuming
 * application to supply, so that `ModuleLoader.load(id)` can resolve an id that is only a string
 * at run time. Task 6.1.
 *
 * Until this exists the console does not boot at all: with no `resolveModule` configured
 * `LoaderRuntime.loadModule` rejects on the very first runtime id
 * (`org/forgerock/commons/ui/common/main/Configuration`), `ProcessConfiguration` swallows it into
 * a `console.warn`, and the login page stops after three requests showing "Loading...".
 *
 * ==== WHY THREE SEPARATE GLOBS AND NOT ONE ====
 *
 * D19 keeps the AMD id space across the ES module build, so the ids the application passes resolve
 * into THREE trees, not one: AM's own source, and the two commons packages installed under
 * node_modules. A registry built only over `./**` -- which is what D1's sketch shows -- covers
 * AM alone, and the first id asked for is a commons one.
 *
 * These must be three separate `import.meta.glob` calls. Passing the three patterns as an ARRAY to
 * a single call is measured to return 281 keys instead of 361, SILENTLY: Vite 5.4 joins its
 * `**\/node_modules/**` ignore to the common base of the resolved patterns, and the common base of
 * a mixed array is the project root, so both package trees are filtered out with no error and no
 * warning. Three calls each get their own common base -- inside node_modules for two of them --
 * so the ignore never matches. `{ exhaustive: true }` would also paper over it, but it turns on
 * dotfile matching as well; three calls is the shape that is correct for a reason.
 *
 * The patterns are ROOT-ABSOLUTE (leading `/`, resolved against the Vite root, which is
 * `openam-ui-ria`) rather than importer-relative (`./**`). Root-absolute keys do not depend on
 * where this file sits, so moving it cannot silently renumber every id. `./**` would pin this
 * file to `src/main/js/` forever.
 *
 * Do NOT add `{ eager: true }`. It changes nothing about resolution, enumeration or key shape --
 * only about payload -- and five orphan `main.js` aggregators carrying ~83 static imports between
 * them are inside the glob's reach, `org/forgerock/openam/ui/admin/main.js` alone holding 43 (28
 * of them administrative views) while being imported by nothing. Eager would hoist all of it into
 * the initial chunk, with a green build and no warning, breaking ui-module-loading's "Initial
 * payload excludes unvisited views".
 *
 * Counts at the time of writing: AM 281 (282 files less this one -- a glob never matches the file
 * it is written in), ui-commons 66, ui-user 14, so 361 ids in the merged map. A registry that
 * resolves nothing is the failure mode to watch for, and it looks like a near-empty map rather
 * than an error.
 *
 * ==== WHY THE THREE ENTRY POINTS ARE EXCLUDED ====
 *
 * Hygiene, not a fix -- and the distinction is worth keeping straight, because the exclusion was
 * added while chasing a bug it turned out not to cause. Without the negations the AM pattern
 * matches `main.js`, `main-authorize.js` and `main-device.js`, so `resolveModule("main")` would
 * re-execute an entry body that calls `configureLoader(...)`, `resolveAssetUrl.configure(...)` and
 * `EventManager.sendEvent(...)` at top level -- reconfiguring the console's loader mid-flight.
 * NOTES-module-registry.md section 12.4 records the name-collision half; this is the sharper half.
 *
 * SINCE 6.3 THE EXCLUSION NO LONGER CLOSES THAT TRAP. It keeps the entry bodies out of the glob
 * map, but an excluded id now reaches the dynamic-import fallback instead, and all three files
 * exist at the deployed tree root. `main` is saved only by URL IDENTITY: the fallback derives
 * `main.js?v=<version>` and `index.html` is stamped with the same `main.js?v=${version}`, so it
 * resolves to the SAME module record and the body does not re-run -- which is precisely the
 * coincidence 6.1a exists to stop depending on. `main-authorize` and `main-device` are the two
 * classic-IIFE RequireJS stubs, and nothing stops those being fetched and evaluated as ES modules,
 * body and side effects included. Nothing asks for any of the three ids today, so this stays
 * latent -- but read the exclusion as payload and name-collision hygiene now, not as a guarantee.
 *
 * `config/main` stays in: an orphan aggregator with no top-level side effects.
 *
 * The negation form is safe here where an array is otherwise a trap (see above): all four patterns
 * share the `/src/main/js` base, so the common base does not widen to the project root and both
 * node_modules trees are unaffected. Measured after the change: AM 278.
 *
 * ==== WHAT ACTUALLY BREAKS THE ADMIN CONSOLE -- NOT FIXED HERE, NOT THIS FILE'S BUG ====
 *
 * Recorded here because this registry is what makes it reachable, and the next person to read this
 * file is the one who will hit it.
 *
 * `index.html` loads the console as `<script type="module" src="main.js?v=${version}">` (5.4's
 * entry format c1), but Rollup's own chunk imports name the entry as a bare `../main.js`. With the
 * registry in place almost every emitted view chunk imports it -- the entry chunk holds the shared
 * modules. Two URLs for one file are TWO module records, so the entry body runs TWICE.
 *
 * The second run reaches `resolveAssetUrl.configure(...)` (main.js:105) after the first run has
 * already resolved an asset URL (`images/login-logo.png`, via ThemeManager.getTheme() ->
 * preloadInitialTemplates), and that guard throws by design. Both copies share ONE `resolveAssetUrl`
 * instance, because it lives in a shared hashed chunk with a single URL.
 *
 * The throw lands inside a dynamic import, so `ModuleLoader.load` REJECTS -- and its callers are
 * `$.when(...).then(onFulfilled)` with no rejection handler (commons ProcessConfiguration.js:38).
 * An unhandled jQuery Deferred rejection is SILENT: no `unhandledrejection` event, nothing printed.
 * Hence the symptom -- chunks fetch correctly over the wire, the console log is clean, and the
 * admin console never paints. main.js:99-104's "nothing resolves an asset URL before this
 * statement" was true when written and is false once the app actually renders.
 *
 * If a view loads but does not render, instrument `ModuleLoader.load`'s reject path FIRST. An
 * empty console proves nothing here.
 *
 * This file is excluded from `npm run lint` (see the `--ignore-pattern` in package.json). ESLint
 * here is 3.8.1, whose espree cannot parse `import.meta` or dynamic `import()` at ANY
 * `ecmaVersion` -- setting 2020 does not help, it makes every one of the 290 linted files fail
 * with "Invalid ecmaVersion". Task 5.8 hit the same 3.8.1 wall over `globals` severities and
 * solved it per-file too. Revisit when ESLint is upgraded; nothing else here needs the exclusion.
 */

import { toUrl } from "org/forgerock/commons/ui/common/util/esm/LoaderRuntime";

const AM_PREFIX = "/src/main/js/";
const COMMONS_PREFIX = "/node_modules/@openidentityplatform/ui-commons/esm/";
const USER_PREFIX = "/node_modules/@openidentityplatform/ui-user/esm/";

const amTree = import.meta.glob([
    "/src/main/js/**/*.{js,jsx,jsm}",
    "!/src/main/js/main.js",
    "!/src/main/js/main-authorize.js",
    "!/src/main/js/main-device.js"
]);
const commonsTree = import.meta.glob("/node_modules/@openidentityplatform/ui-commons/esm/**/*.{js,jsx}");
const userTree = import.meta.glob("/node_modules/@openidentityplatform/ui-user/esm/**/*.{js,jsx}");

/*
 * `.jsm` is in the AM pattern deliberately: 31 of AM's source files carry that extension and ten
 * of them are ids the application asks for (`store/index` among them). The `{js,jsx}` pattern D1
 * sketches returns 250 instead of 281 and loses them.
 *
 * The key a root-absolute glob produces is the path from the Vite root, `/`-prefixed:
 *   `/src/main/js/store/index.jsm`                        -> `store/index`
 *   `/node_modules/@.../ui-commons/esm/config/process/CommonConfig.js`
 *                                                         -> `config/process/CommonConfig`
 * Verified when this was built: no two files in a tree normalise to the same id, and no id occurs
 * in more than one tree, so merge order does not affect correctness.
 */
/*
 * NULL-PROTOTYPE, all three tables. A plain `{}` inherits from `Object.prototype`, so the ids
 * `constructor`, `toString`, `valueOf`, `hasOwnProperty` and `__proto__` would find an inherited
 * member and never reach the LAST BRANCH of `resolveModule` at all -- `constructor` would resolve
 * to a non-nullish placeholder and `__proto__` would throw with the id lost. Since 6.3 that last
 * branch is the dynamic-import fallback, so this is what keeps the open-set guarantee true for
 * every possible string rather than for the ids we happen to have today; the reasoning lives with
 * the resolver. No id in the current corpus is affected. It also stops `addTree` writing through
 * `__proto__` if a file were ever so named.
 */
const modules = Object.create(null);

const addTree = (tree, prefix) => {
    Object.keys(tree).forEach((key) => {
        modules[key.slice(prefix.length).replace(/\.(jsx?|jsm)$/, "")] = tree[key];
    });
};

addTree(amTree, AM_PREFIX);
addTree(commonsTree, COMMONS_PREFIX);
addTree(userTree, USER_PREFIX);

/**
 * The two ids that are LIBRARY NAMES rather than module paths, which no glob over any of the three
 * trees can match. `LoaderRuntime`'s own header and ui-commons' NPM-PACKAGE.md
 * ("The three loader APIs with no ES module equivalent") both record this case: commons'
 * `main/AbstractView` and `components/Navigation` load `"bootstrap"`, and `util/UIUtils` loads
 * `"bootstrap-dialog"`.
 *
 * They cannot be collapsed into a bare `import(id)` fall-through: a dynamic import of a run-time
 * string is untraceable by every bundler, so nothing would be included in the build, and a bare
 * specifier needs an import map to resolve in the browser at all. The two entries below are static
 * strings, so Rollup traces them normally. Both specifiers go through `resolve.alias`, which is
 * where AM's rebinding of them lives -- `bootstrap` to AM's own concatenated shim, and
 * `bootstrap-dialog` to the npm package's real name, `bootstrap3-dialog`.
 */
const libraries = Object.assign(Object.create(null), {
    "bootstrap": () => import("bootstrap"),
    "bootstrap-dialog": () => import("bootstrap-dialog")
});

/**
 * THE SEVEN LOGICAL NAMES -- ui-module-loading's "Substitution of commons modules by the product".
 *
 * Commons names its substitutable collaborators by logical name and carries no product paths.
 * These names appear only as string identifiers inside ui-commons' and ui-user's route and process
 * configs, resolved at run time through `ModuleLoader.load`, so `resolve.alias` never sees six of
 * them. Without this table the login page, the login dialog, the profile page, forgot-username,
 * password-reset and self-registration each resolve to nothing.
 *
 * Kept as a SEPARATE table consulted BEFORE the glob map, and looked up under the RAW id as
 * commons passes it. That is what keeps the requirement's third scenario REACHABLE -- a logical
 * name left unbound must be reported AGAINST THE LOGICAL NAME -- because the id commons passes is
 * `"LoginView"`, not a path. Mapping a name to a path first and then failing on the path would
 * report the path and lose the scenario outright.
 *
 * SINCE 6.3 THE RAW ID IS NECESSARY BUT NO LONGER SUFFICIENT. Until then an unbound name fell
 * through to `undefined` and `LoaderRuntime` threw `returned nothing for "LoginView"`, which named
 * it, and that error was the whole of what satisfied the scenario. It is now UNREACHABLE: an
 * unbound name reaches the fallback, which derives `<tree root>/LoginView.js?v=<version>` -- a path
 * that is meaningless for a logical name by construction -- and fails with `TypeError: Failed to
 * fetch dynamically imported module: ...`, which reads as "a file is missing" rather than "a
 * binding is missing". 6.4 is what restores a legible failure, and because the fallback is entered
 * with the RAW id the error it rethrows can still name `"LoginView"` -- which is the reason this
 * table must go on looking up the raw id and must not be folded into the glob map.
 *
 * THUNKS, NOT STATIC IMPORTS. Measured: binding these seven with static `import` puts 1 015 415
 * bytes in the entry chunk against 4 083 for thunks -- the login view, login dialog, profile view
 * and the three anonymous-process views plus everything they reach. Total shipped bytes are the
 * same to within 0.3%; the whole difference is when. A static binding here has exactly the payload
 * consequence `{ eager: true }` has on the glob, and is ruled out by the same requirement.
 *
 * `UserProfileView` is the seventh name and the only one in both categories: it has a real static
 * consumer (`SiteConfigurationService`, through `resolve.alias`) AND a route `view:`. Aliasing it
 * does not cover the route use, which is why it is here. It is bound through the same alias
 * specifier the static consumer uses, so both paths normalise to one absolute id and Rollup keeps
 * ONE module record -- verified by building it both ways at once and counting records. That
 * matters because `SiteConfigurationService` calls `registerTab` on its instance; two instances
 * would mean the KBA tab registered on an object no route renders, with no error anywhere.
 *
 * NOT PROTECTED BY THIS TABLE, and nothing else protects it either: AM's
 * `org/forgerock/openam/ui/user/login/RESTLoginHelper.js:61` compares
 * `ViewManager.currentView === "LoginView"` against the RAW, UNRESOLVED route identifier. The
 * registry resolves the logical name without rewriting the route config that produces it, which is
 * what keeps that comparison working; rewriting the route configs to name real module paths would
 * make it permanently false and kill the re-render branch silently.
 */
const logicalNames = Object.assign(Object.create(null), {
    "Footer": () => import("org/forgerock/openam/ui/common/components/Footer"),
    "LoginView": () => import("org/forgerock/openam/ui/user/login/RESTLoginView"),
    "LoginDialog": () => import("org/forgerock/openam/ui/user/login/RESTLoginDialog"),
    "ForgotUsernameView": () =>
        import("org/forgerock/openam/ui/user/anonymousProcess/ForgotUsernameView"),
    "PasswordResetView": () =>
        import("org/forgerock/openam/ui/user/anonymousProcess/PasswordResetView"),
    "RegisterView": () =>
        import("org/forgerock/openam/ui/user/anonymousProcess/SelfRegistrationView"),
    "UserProfileView": () => import("UserProfileView")
});

/**
 * THE OPEN-SET HALF OF D1 -- task 6.3. Derives the url of a module the build never saw from its
 * identifier, using the deployed layout's own convention: `org/forgerock/.../Foo` -> `Foo.js` at
 * that same path below the deployed tree root, which is what RequireJS's `nameToUrl` did and what
 * the PATH CONVENTION block in vite.config.js preserves.
 *
 * `new URL(..., document.baseURI)` is not decoration, and the three obvious spellings are all
 * wrong -- measured in a served build under the `/openam/XUI/` context path
 * (NOTES-module-registry.md section 14.2):
 *
 *   `import("config/Foo.js")`     -> TypeError: Failed to resolve module specifier. `import()`
 *                                    applies MODULE SPECIFIER rules, not url rules; a bare
 *                                    specifier needs an import map and the deployed page has none.
 *                                    So the one-liner that looks obviously right --
 *                                    `import(toUrl(id + ".js"))`, since `toUrl` is the
 *                                    `require.toUrl` this build replaced -- fails on EVERY id,
 *                                    including ids whose file is present.
 *   `import("./config/Foo.js")`   -> fetches `/XUI/assets/config/Foo.js`. A relative specifier
 *                                    resolves against the importing CHUNK, and this file is
 *                                    bundled into a chunk under `assets/`. 404.
 *   `import(new URL("../" + ..., import.meta.url))` -> works today and is the worse anchor: it is
 *                                    correct only while every chunk sits exactly one directory
 *                                    below the tree root, which is a property of `chunkFileNames`,
 *                                    not of the deployment.
 *
 * `document.baseURI` is the directory `index.html` is served from, context path included, and is
 * fragment-proof -- measured identical at `/XUI/`, `/XUI/index.html#login/` and
 * `/XUI/#realms/%2F/dashboard`, because `new URL()` discards the base's fragment and filename and
 * no `<base>` tag is emitted. That is the same origin RequireJS inferred from the document.
 *
 * COMPOSE `toUrl` RATHER THAN HAND-ROLLING THE STRING. `toUrl` owns the two things that vary here
 * -- `baseUrl` and `urlArgs` -- and `new URL(..., document.baseURI)` supplies only the origin that
 * `import()` needs and `toUrl` deliberately does not. That makes ONE derivation correct on all
 * three entry points: `main.js` leaves `baseUrl` at `""` (the derived url is document-relative and
 * right), while `main-authorize.js` and `main-device.js` configure `baseUrl` to
 * `"<serverBase>/XUI"` and are served from `/oauth2/...`, where `document.baseURI` is NOT the XUI
 * root. Neither secondary entry configures a `resolveModule`, so the fallback is unreachable there
 * today -- but written this way it is not wrong there either.
 *
 * `toUrl` has a THIRD branch this deliberately inherits: a configured `resolveUrl` short-circuits
 * both `baseUrl` and `urlArgs`. Nothing in AM configures one (LoaderRuntime documents it for a
 * consumer whose asset urls come from a bundler manifest, which is the wrong answer for a module
 * id, since the point of this path is ids the bundler never saw). If a consumer ever sets it, this
 * derivation changes meaning silently -- that is the price of composing rather than hand-rolling,
 * and it is the right side of the trade while `resolveUrl` stays unused.
 *
 * THE VERSION QUERY IS DELIBERATE. `toUrl` appends `urlArgs`, which `main.js` sets to
 * `v=${__TARGET_VERSION__}`, so the derived url ends `?v=<build version>`. D4 and
 * ui-build-and-packaging's "Cache invalidation for runtime-fetched assets" cover assets fetched by
 * path at runtime, which this is: `/XUI/*` is mapped to `CacheForAMonth` (`public, max-age=2592000`)
 * in `openam-server-only/.../web.xml`, with excludes for only `/XUI/`, `/XUI/index.html` and the two
 * RequireJS stubs, so without the query an AM upgrade plus a re-dropped operator module serves a
 * month-old cached copy at an unchanged url. The version does not invalidate an operator's edit
 * WITHIN one deployed version -- but neither does its absence, so it strictly dominates.
 *
 * The one real cost is measured and is a consistency rule, not an argument against: a file imported
 * at two different urls is TWO module records and TWO evaluations (the 6.1a hazard, reproduced
 * directly -- `?v=` and no `?v=` gave an evaluation count of 2). So every id goes through THIS
 * derivation and no other, and an operator shipping two files must be told that a sibling
 * `import("./Other.js")` from inside their own module inherits the directory but NOT the query.
 * That belongs in 6.6's operator documentation.
 *
 * `.js`, ALWAYS AND UNCONDITIONALLY -- no `.jsm`/`.jsx` probing. Ten registry ids carry `.jsm`, but
 * those are build-time source files reached by glob; the deployed layout's convention for a file an
 * operator drops in is `Foo.js`, which is what 1.11 and RequireJS both used.
 *
 * THE OPERATOR'S MODULE MUST BE AN ES MODULE. Measured: task 1.11's AMD fixture dropped at the path
 * its identifier implies is fetched and PARSED successfully -- `define([...], function () {})` is
 * valid ES-module syntax -- and dies at evaluation with `ReferenceError: define is not defined`,
 * naming neither the file nor the format. A self-contained ES module resolves cleanly and
 * `LoaderRuntime.unwrapModule` returns its default export. Section 14.5 carries a working stand-in.
 *
 * NO IDENTIFIER VALIDATION, AND THAT IS A CHOICE RATHER THAN AN OVERSIGHT -- recorded because this
 * is the one place in the application where a string becomes a url that then gets EXECUTED. With
 * `baseUrl` at `""`, a protocol-relative id `//host/x` derives `http://host/x.js` (cross-origin
 * script execution), a leading slash escapes the context path, `..` segments are normalised away
 * by `new URL`, an id containing `?` makes `toUrl` append `&v=` instead of `?v=`, and everything
 * after a `#` becomes a fragment. There is no live injection path today: every id that reaches
 * here is developer-controlled -- `config/AppConfiguration.js` holds `loginHelperClass` and
 * `delegate` as literals, the route and process view ids are bundled, and D6 makes configuration
 * compile-time. A guard rejecting `^[a-z]+:`, `^//`, `^/` and ids containing `?` or `#` belongs
 * with 6.4, which is already writing the error path this would reject into; adding it here would
 * mean inventing a failure shape 6.4 then has to replace.
 * @returns {String} The absolute url to import it from.
 */
const fallbackUrl = (id) => new URL(toUrl(`${id}.js`), document.baseURI).href;

/**
 * Resolves a runtime module identifier to the module, or to a promise of it.
 *
 * FOUR BRANCHES IN ONE `||` CHAIN, AND THE ORDER IS THE CONTRACT. The three tables are consulted
 * first, in order, and the dynamic-import fallback is the last alternative -- so a REGISTERED id can
 * never reach the fallback and an UNREGISTERED id always does, structurally rather than by luck.
 * `||` short-circuits, so `fallbackUrl` is not even evaluated for an id a table covers. There are no
 * cross-table collisions (section 12.4) and every table value is a function, hence truthy, so no
 * registered id can fall through by being falsy.
 *
 * The null-prototype tables are load-bearing for this as well as for 6.1's reason: with a plain
 * `{}`, the ids `constructor`, `toString`, `valueOf` and `__proto__` would find an INHERITED member
 * and never reach the fallback at all. Measured with the fallback installed: `constructor` and
 * `no/such/Module` fall through, while `org/forgerock/commons/ui/common/main/Configuration`,
 * `LoginView` and `bootstrap` still resolve from their tables -- none of which has a file at the
 * url its identifier implies, so a fallback that had fired would have 404'd.
 *
 * A TRAILING THUNK IS STILL LOAD-BEARING, and that is why the fallback is written as one rather
 * than bolted on outside. Written the natural way -- `(logicalNames[id] || modules[id] ||
 * libraries[id])()` -- an unknown id throws `TypeError: ... is not a function` and THE IDENTIFIER
 * IS GONE. `LoaderRuntime` calls this resolver inside a promise chain precisely because a missing
 * entry in an `import.meta.glob` map is a TypeError rather than a rejection, so it would catch it
 * and reject carrying "x is not a function".
 *
 * DO NOT CATCH THE FALLBACK'S REJECTION HERE. Task 6.4 turns a miss into a legible rejection and
 * needs the raw failure intact. Its raw shape, measured: `TypeError: Failed to fetch dynamically
 * imported module: http://<host>/openam/XUI/config/ThisFileIsNotThere.js` -- an ordinary catchable
 * promise rejection, naming the url in full, carrying no HTTP status and no `cause`, and not naming
 * the identifier as such.
 *
 * WHAT 6.3 COSTS, RECORDED HERE BECAUSE 6.4 IS WHERE IT IS PAID. This function can no longer return
 * nullish for any id, so `LoaderRuntime.loadModule`'s named
 * `"The configured resolveModule returned nothing for <id>"` error -- what ui-module-loading's
 * "Unresolvable identifier fails observably" was satisfied by until now -- becomes UNREACHABLE, and
 * an unresolvable id fails instead as an anonymous `TypeError` about a url. 6.4 must re-supply the
 * identifier by catching inside the fallback and rethrowing with both the id and the derived url;
 * it must not rely on the id being a substring of the url, and it should reuse `fallbackUrl` rather
 * than re-derive the string, so that the url it names and the url it fetched cannot drift apart. Until then the two miss shapes are
 * distinguishable only by url: a registry hit whose CHUNK fails to load rejects with the same
 * message prefix but at `assets/<Name>-<hash>.js`, while a fallback miss is always at the
 * identifier's own path below the tree root with no hash.
 *
 * The `/* @vite-ignore *\/` comment does not survive the production build -- esbuild's minify pass
 * strips it, and `import(/* @vite-ignore *\/ url)` and `import(url)` emit byte-identically, with no
 * warning either way and nothing added to the module graph. It is kept because it states the intent
 * at the one line where a reader will ask, and because `vite serve` was not measured, where
 * `vite:import-analysis` does warn on an unanalysable dynamic import.
 *
 * @param {string} id Module id, e.g. `"org/forgerock/commons/ui/common/main/Router"`, or a logical
 *                    name such as `"LoginView"`, or a library name such as `"bootstrap"`.
 * @returns {Promise|Object} The module namespace or a promise of it. For an id no table covers, a
 *                           promise of the module fetched from the deployed instance, which rejects
 *                           when nothing is there.
 *
 * Before 6.3 this never threw at all. It still never REJECTS-BY-THROWING in practice, but the
 * claim is now approximate rather than exact: `fallbackUrl` can throw synchronously if `document`
 * is absent (a unit-test context -- `npm run test:unit`) or if `new URL` refuses a pathological id.
 * `LoaderRuntime.loadModule` calls the resolver inside `Promise.resolve().then(...)`, precisely
 * because a missing `import.meta.glob` entry is a synchronous TypeError, so the OBSERVABLE
 * contract -- always a promise, never a throw at the call site -- is unchanged.
 */
export const resolveModule = (id) =>
    (logicalNames[id] || modules[id] || libraries[id] ||
        (() => import(/* @vite-ignore */ fallbackUrl(id))))();

export default resolveModule;
