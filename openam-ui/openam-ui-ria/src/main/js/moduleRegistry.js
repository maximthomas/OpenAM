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
 * Nothing asks for those ids today, so this closes a trap rather than repairing damage.
 * NOTES-module-registry.md section 12.4 records the name-collision half; this is the sharper half.
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
 * member and never reach the `(() => undefined)` fallback below -- `constructor` would resolve to
 * a non-nullish placeholder, which is the one thing the resolver's contract forbids, and
 * `__proto__` would throw with the id lost. No id in the current corpus is affected; this keeps
 * the fallback's guarantee true for every possible string rather than for the ids we happen to
 * have today. It also stops `addTree` writing through `__proto__` if a file were ever so named.
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
 * commons passes it. That is what satisfies the requirement's third scenario -- a logical name
 * left unbound must be reported AGAINST THE LOGICAL NAME. The id commons passes is `"LoginView"`,
 * not a path, so `LoaderRuntime`'s "returned nothing for ..." error names it. Mapping a name to a
 * path first and then failing on the path would report the path and lose the scenario.
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
 * Resolves a runtime module identifier to the module (or a promise of it), or to `undefined` when
 * nothing covers it.
 *
 * THE TRAILING `(() => undefined)` IS LOAD-BEARING and must not be tidied away. Written the
 * natural way -- `(logicalNames[id] || modules[id] || libraries[id])()` -- an unknown id throws
 * `TypeError: ... is not a function`. `LoaderRuntime` catches that (it calls the resolver inside a
 * promise chain precisely because a missing entry in an `import.meta.glob` map is a TypeError, not
 * a rejection), but the rejection then carries "x is not a function" and THE IDENTIFIER IS GONE.
 * Returning `undefined` instead lets `loadModule` reject with a message naming the id, which is
 * what ui-module-loading's "Unresolvable identifier fails observably" asks for.
 *
 * Equally, this must not resolve with a placeholder for an unknown id. `LoaderRuntime` turns a
 * nullish result into a named error; anything non-nullish defeats that and the failure resurfaces
 * later as a property access on the wrong object.
 *
 * There is deliberately NO dynamic-import fallback here for ids absent from the registry. That is
 * task 6.3's, and adding it now would hide which branch a resolution took.
 *
 * @param {string} id Module id, e.g. `"org/forgerock/commons/ui/common/main/Router"`, or a logical
 *                    name such as `"LoginView"`, or a library name such as `"bootstrap"`.
 * @returns {Promise|Object|undefined} The module namespace or a promise of it; `undefined` when no
 *                                     table covers `id`. Never throws.
 */
export const resolveModule = (id) =>
    (logicalNames[id] || modules[id] || libraries[id] || (() => undefined))();

export default resolveModule;
