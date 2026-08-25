/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2026 3A Systems LLC.
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 */

/*
 * Vite build for the XUI. Task 4.1 lands this skeleton; the sections below name the task that
 * owns each one, so later tasks extend rather than rewrite.
 *
 *   4.2  build.rollupOptions        the three entry points and their emitted file names
 *   4.3  resolve.alias              the require.config.map bindings from main.js:19-34. LANDED:
 *                                  6 of the 12 as aliases -- the six ever reached as an AMD
 *                                  dependency -- and the other 6 recorded beside them as
 *                                  runtime string identifiers for task 6.1, because
 *                                  resolve.alias cannot see those. resolve.extensions and
 *                                  .jsm were NOT done here; see the note after the alias
 *                                  block. Router's per-entry collision is resolved there too.
 *   4.4  static assets              themes/ templates/ partials/ locales/ copied verbatim
 *   4.5  index.html + ${version}    the filtered index.html, the deployed /XUI layout, and
 *                                  index.html as a build input. The entryFileNames half is
 *                                  SETTLED IN 4.2: the three JS entries are emitted unhashed at
 *                                  the tree root, which is how all three are loaded today
 *                                  (PHASE1-TREE.md:150) and what the urlArgs scheme assumes.
 *                                  What is left for 4.5 is the index.html interaction -- if
 *                                  index.html is added as an HTML input, Vite derives an entry
 *                                  chunk from it and entryFileNames applies to that too, so
 *                                  declaring main as an explicit JS input AND index.html as an
 *                                  HTML input that references it risks emitting the entry twice
 *                                  under two names. NOTES-vite-entrypoints.md 4.3 gives the
 *                                  function form of entryFileNames that fixes it if so.
 *   4.9  resolveAssetUrl            cache-busting for runtime-fetched assets (D4)
 *   4.10 server.*                   the dev server, paired with e2e/local (D14)
 *
 * READ BEFORE EDITING: NOTES-vite-build.md in this directory. In particular section 3 — Vite does
 * not reject AMD, it accepts it, exits 0 and emits a bundle that does nothing. Until the AMD to
 * ESM conversion in group 5 lands, a green `vite build` here is NOT evidence that the output
 * works. The acceptance oracle for that is PHASE1-TREE.md, the per-file digest of the Grunt tree,
 * not the exit code.
 */

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

/*
 * Maven passes the project version through this variable. The pom's npm-build execution sets it;
 * see openam-ui-ria/pom.xml. "dev" mirrors Gruntfile.js:45, `grunt.option("target-version") || "dev"`.
 */
const targetVersion = process.env.TARGET_VERSION || "dev";

/*
 * Absolute paths for resolve.alias replacements (task 4.3). Every replacement in the alias table
 * below has to resolve in ONE HOP -- see the alias block for why -- and a bare AMD id such as
 * org/forgerock/openam/ui/common/util/ThemeManager resolves against nothing under Vite: there is
 * no equivalent of RequireJS's baseUrl. fileURLToPath(new URL(...)) is Vite's own documented
 * idiom and works whether the config is loaded as ESM or bundled to CJS (package.json declares no
 * "type", so it is bundled).
 */
const fromSrc = (id) => fileURLToPath(new URL(`./src/main/js/${id}`, import.meta.url));

export default defineConfig({
    /*
     * Relative, deliberately. The XUI has no configurable backend URL: Constants.host is "" and
     * Constants.context is derived from location.pathname, so the deployed tree must work under
     * whatever context path serves it (D14). An absolute base would bake one context into the
     * build and break the "one build, either backend" property the e2e comparison depends on.
     *
     * 4.10 owns the dev-server half, where base DOES have to be the served prefix
     * (e.g. "/openam/XUI/", trailing slash required) and must be derived from the same context
     * value e2e/local uses (--context / OPENAM_LOCAL_CONTEXT) rather than hard-coded.
     */
    base: "./",

    plugins: [
        /*
         * 15 .jsx files under src/main/js. Note for 4.3: this plugin's default include is
         * /\.[tj]sx?$/, which does NOT match .jsm — widening it is part of the .jsm work below.
         */
        react()
    ],

    /*
     * ==== 4.3 -- THE require.config.map BINDINGS ====
     *
     * main.js:19-34 declares 12 bindings under a single "*" scope; main-authorize.js:28-34 and
     * main-device.js:19-25 declare 3 each. Counted against the source rather than recalled:
     * 12 / 3 / 3, union of 12 distinct names, 2 declared by all three (ThemeManager, underscore),
     * 9 by main.js alone, and exactly ONE name where the three DISAGREE -- Router, entry 3 below.
     * There are no per-module map scopes anywhere, so nothing depends on RequireJS per-referrer
     * resolution within an entry; the only per-referrer behaviour that matters is between entries.
     *
     * The full binding table, every consumer with file:line, and the costing behind each decision
     * taken here: NOTES-vite-aliases.md in this directory. Read it before changing anything below.
     *
     * ONLY SIX OF THE TWELVE ARE HERE, AND THAT IS DELIBERATE. Six of the twelve names are ever
     * reached as an AMD dependency -- a bare name inside define([...]) or require([...]) -- and
     * those six are the only ones resolve.alias can act on. They are the six below. The other six
     * are RUNTIME STRING IDENTIFIERS, listed in full in the block immediately after this one.
     * resolve.alias never sees them; an alias for any of them would be a no-op for the bundler and
     * would read as coverage that does not exist. 6 + 6 = 12, none dropped, none in both.
     *
     * ---- ALIASES DO NOT CHAIN, AND THAT CONSTRAINS EVERY REPLACEMENT BELOW ----
     * Vite implements resolve.alias with the bundled @rollup/plugin-alias, and constructs it as
     *
     *     alias({ entries: config.resolve.alias, customResolver: viteAliasCustomResolver })
     *
     * (node_modules/vite/dist/node/chunks/node.js:29257-29261). That detail is load-bearing and
     * easy to get wrong: getEntries (:4717-4733) copies the top-level customResolver onto EVERY
     * entry as resolverFunction, so the plugin's own
     * `this.resolve(updatedId, importer, { skipSelf: true, ... })` branch (:4761) is NEVER
     * REACHED -- resolveId returns through `if (matchedEntry.resolverFunction) return
     * matchedEntry.resolverFunction.call(...)` one line earlier. Do not cite :4761 as the reason
     * for anything; it is dead code under Vite.
     *
     * The behaviour that matters survives anyway, by a different route. viteAliasCustomResolver
     * (:29407) is just `this.resolve(id, importer, options)`, and skipSelf defaults to true in
     * both resolvers -- Rollup's PluginContext.resolve for the build, and Vite's own plugin
     * container for dev (:29825, `if (options?.skipSelf === false) ...`). So the alias plugin
     * still does not re-enter itself and ALIASES DO NOT CHAIN. In a bundled build Vite swaps in a
     * different plugin entirely (applyToEnvironment, :29263), with the same property.
     *
     * Two further properties of the matcher, both of which bite here. matches (:4711-4716) is
     *
     *     importee === pattern || importee.startsWith(pattern + "/")
     *
     * so entries.find() means FIRST MATCH WINS and exactly one entry applies per import; and a
     * bare-word key is a PREFIX CAPTURE, not an exact match. "lodash" below therefore also
     * captures "lodash/fp", "lodash/merge" and every other subpath, rewriting them to
     * <abs>/libs/lodash-3.10.1-min.js/fp -- which resolves to nothing. Checked: there are ZERO
     * lodash/ or underscore/ subpath imports in AM source today, so it is currently harmless. It
     * will not stay harmless once 4.7 and 8.3 add npm libraries; revisit it there.
     *
     * Therefore every replacement below must resolve in ONE HOP: an absolute filesystem path, or
     * a package specifier that normal node resolution can finish on its own. A replacement that is
     * itself another aliasable id is silently NOT re-aliased -- which is exactly the trap that
     * `"underscore": "lodash"`, the naive transcription of main.js:33, falls into. See entry 6.
     *
     * A further consequence worth knowing before editing: an unmatched name falls through to
     * normal resolution and ends as a Rollup "unresolved dependency" WARNING treated as external,
     * and a matched name whose replacement resolves to nothing also only warns ("rewrote X to Y
     * but was not an absolute path...") and returns { id: updatedId }. Neither fails the build. A
     * typo here produces a silently external import, not an error.
     */
    resolve: {
        alias: {
            /*
             * 1. ThemeManager -- AM's own module. Bound identically by all three entries
             * (main.js:22, main-authorize.js:30, main-device.js:21). Consumers: ui-commons
             * main/AbstractView.js:26 and util/UIUtils.js:24 as define deps, plus
             * main-authorize.js:65 and main-device.js:60 in the entry require arrays. One of the
             * four identifiers ui-commons/NPM-PACKAGE.md lists under "Identifiers the consumer
             * must supply".
             */
            "ThemeManager": fromSrc("org/forgerock/openam/ui/common/util/ThemeManager.js"),

            /*
             * 2. NavigationFilter -- AM's own module. main.js:28, main only. Exactly one consumer:
             * ui-commons components/Navigation.js:27. Also on NPM-PACKAGE.md's must-supply list.
             */
            "NavigationFilter": fromSrc(
                "org/forgerock/openam/ui/common/components/navigation/filters/RouteNavGroupFilter.js"),

            /*
             * 3. Router -- THE ONE NAME THE THREE ENTRIES BIND DIFFERENTLY, and the only real
             * decision in this task. main.js:29 binds it to the ui-commons Router;
             * main-authorize.js:31 and main-device.js:22 bind it to AM's SingleRouteRouter.
             * resolve.alias is global to the build and cannot give one id two meanings. There is
             * exactly ONE non-entry consumer of the aliased name: ThemeManager.js:25, used at
             * ThemeManager.js:168. Everything else in all three trees -- 49 sites in AM alone --
             * imports the commons router by its full path and is untouched by this entry.
             *
             * DECIDED: the ui-commons Router wins, one global alias, no source rewrite and no
             * per-entry build. Chosen by the change owner from the four costed options in
             * NOTES-vite-aliases.md section 3. It was NOT taken as the obvious choice.
             *
             * WHY THIS DIRECTION SURVIVES -- and this CORRECTS NOTES-vite-entrypoints.md section
             * 5.2, which has both failure modes backwards. The mechanism 5.2 misses is that the
             * two secondary entries request the ALIASED name themselves (main-authorize.js:66,
             * main-device.js:61), so under a global alias the entries and ThemeManager always
             * receive the same object and cannot diverge:
             *
             *   main-authorize.js:126 / main-device.js:76   Router.currentRoute = {navGroup:"user"}
             *   ui-commons Router.js:32                     obj.currentRoute = {}     <- never null
             *   ThemeManager.js:168                         Router.currentRoute.navGroup === "admin"
             *                                                 -> "user" === "admin" -> false
             *                                                 -> non-admin theme, which is correct
             *                                                    for the consent and device pages
             *
             * THE DIRECTION THIS CHOICE FAILS IN, stated because no test will tell you: the cost
             * of this option is PAYLOAD, not behaviour. It drags ui-commons main/Router.js and its
             * whole closure -- backbone, lodash, EventManager, Configuration,
             * AbstractConfigurationAware, URIUtils -- onto the OAuth2 consent, OAuth2 error and
             * device-flow pages, which today load a 22-line zero-dependency stub. backbone is in
             * NEITHER secondary entry's paths block (main-authorize.js:37-42 and
             * main-device.js:28-33 list only handlebars, i18next, jquery, lodash, redux, text), so
             * this is a dependency those two bundles have never carried. Import-time side effects
             * were checked and are nil: Backbone.history.start() and new Backbone.Router(...) are
             * both inside obj.init (ui-commons Router.js:188,227,228), which only
             * AppConfiguration's moduleDefinition invokes, and the secondaries never load it. The
             * pages that pay this cost are served by FreeMarker templates in the openam-oauth2
             * Maven module, which this build does not test.
             *
             * THE OTHER DIRECTION, and why a green e2e run is not evidence: aliasing to
             * SingleRouteRouter instead THROWS. Its entire body is define({currentRoute: null})
             * (SingleRouteRouter.js:20-22) and nothing in the main.js console flow ever assigns
             * it, so ThemeManager.js:168 evaluates null.navGroup -> TypeError, synchronously
             * inside getTheme(), which ui-commons AbstractView.js:104 and UIUtils.js:107,137,179
             * call on EVERY view render, not only admin ones. The e2e suite exercises only the two
             * secondary entries, so it stays GREEN while the admin console throws --
             * NOTES-vite-entrypoints.md section 6 records exactly this blindness.
             *
             * UNVERIFIED AT RUNTIME, deliberately: the above is a static reading of the source. No
             * build can execute here -- the tree is still AMD until group 5, and a green
             * `vite build` proves nothing (see READ BEFORE EDITING at the top of this file).
             * Confirm the first time the tree actually runs, and confirm it against main.js, not
             * only the two secondary specs.
             *
             * CONSEQUENCE: SingleRouteRouter.js is now dead code. Its only two references were
             * main-authorize.js:31 and main-device.js:22, both superseded by this entry. It is NOT
             * deleted here -- deleting it is a source change 4.3 was not asked to make, and group
             * 5 will be in these files anyway. Note the consequence for 6.1: because the file
             * stays, D1's import.meta.glob registry will still register it, so it remains
             * reachable by a configured identifier even though no alias points at it.
             *
             * THE TARGET IS DERIVED, NOT CHOSEN. It is the package's esm/ tree with an explicit
             * .js because ui-commons/package.json exposes "./esm/*" and deliberately does NOT
             * expose "./amd/*", so an amd/ subpath is blocked by the exports map; and
             * NPM-PACKAGE.md records that exports subpath patterns do literal substitution and
             * never append an extension, so the .js is required. This is the route D19 prescribes
             * and the one build/verify-esm.mjs tests. It resolves in one hop: the alias plugin does
             * not re-enter itself, so normal node resolution still finishes the package subpath.
             *
             * MODULE IDENTITY IS LOAD-BEARING HERE, and it is not visible from this line.
             * ThemeManager reaches the router through the PACKAGE SPECIFIER below. The 49 AM sites
             * and every commons module reach the same module through the bare id
             * org/forgerock/commons/ui/common/main/Router, which needs D19's prefix alias -- NOT
             * in this file, and not owned by any task that has landed. If those two routes ever
             * resolve to two physical copies, ThemeManager reads a SECOND Router whose
             * currentRoute is never written: {}.navGroup -> undefined !== "admin" -> the admin
             * theme silently stops being applied. That is the exact failure §5.2 mis-attributed to
             * this direction, arriving by a different road. It should be fine -- Rollup dedupes on
             * realpath and preserveSymlinks defaults false -- but "should be fine" is why this note
             * exists. Whoever lands D19's prefix alias must point it at the SAME esm/ tree.
             *
             * BOTH PACKAGE-SPECIFIER ALIASES DEPEND ON AN OUT-OF-BAND INSTALL. @openidentityplatform/
             * ui-commons and ui-user are in node_modules but are declared in NEITHER dependency
             * block of package.json -- task 3.7 installs them from the Maven tarballs. A standalone
             * `npm ci && npm run build:production` therefore leaves this alias and UserProfileView's
             * unresolvable, and per the note above that is a WARNING, not an error. These are the
             * first two entries in this config to depend on that arrangement.
             */
            "Router": "@openidentityplatform/ui-commons/esm/org/forgerock/commons/ui/common/main/Router.js",

            /*
             * 4. KBADelegate -- AM's own module. main.js:31, main only. Exactly one consumer:
             * ui-user profile/UserProfileKBATab.js:26. Note that UserProfileKBATab is itself
             * reached only by a runtime require([...]) at AM SiteConfigurationService.js:32, gated
             * on serverInfo.kbaEnabled === "true", so this alias is exercised only down a
             * conditional dynamic-import path and will not show up in a default build graph.
             */
            "KBADelegate": fromSrc("org/forgerock/openam/ui/user/services/KBADelegate.js"),

            /*
             * 5. UserProfileView -- THE ONLY NAME OF THE TWELVE REACHED BOTH WAYS. It is here
             * because it has a real AMD consumer: AM SiteConfigurationService.js:25 declares it as
             * a define dep and calls UserProfileView.registerTab(tab) at :33, so this alias is
             * live, not vestigial. But it is ALSO a route view: at ui-user
             * config/routes/UserRoutesConfig.js:24, and THIS ALIAS DOES NOT COVER THAT USE. Task
             * 6.1's registry must bind it too; the block below repeats the warning where 6.1 will
             * be reading. Target derived the same way as entry 3.
             *
             * TWO THINGS 6.1 CANNOT INFER FROM THE TABLE BELOW, both specific to this name.
             * (1) Its target is a ui-user PACKAGE module, not an AM source file, so
             * import.meta.glob("./**\/*.{js,jsx}") over AM's source root will never contain it.
             * 6.1 cannot fix this by adding a key -- it needs an explicit import of the package
             * module. That is a different and harder change than the other six.
             * (2) Module identity is load-bearing, as for Router above, and here the failure is
             * concrete rather than theoretical: SiteConfigurationService.js:33 calls
             * UserProfileView.registerTab(tab) on the ALIASED module, while UserRoutesConfig.js:24
             * renders it through the registry. registerTab pushes onto per-instance state, so if
             * the two routes resolve to two instances the KBA tab is registered on an object
             * nobody renders and simply never appears -- with no error anywhere.
             */
            "UserProfileView": "@openidentityplatform/ui-user/esm/org/forgerock/commons/ui/user/profile/UserProfileView.js",

            /*
             * 6. underscore -> lodash 3.10.1, VENDORED BY THIS TASK. Bound identically by all
             * three entries (main.js:33, main-authorize.js:33, main-device.js:24). 29 consumers
             * today: 25 modules in ui-commons, 3 in ui-user, 0 in AM application code, and 1 in
             * AM's own vendored libs/backgrid-paginator-0.3.5-custom.min.js:8 -- which does consume
             * the binding and would break if it were dropped.
             *
             * WHAT THIS ENTRY IS NOT: `"underscore": "lodash"`. That is the literal transcription
             * of main.js:33 and it is WRONG here, because aliases do not chain (see the block
             * above). "lodash" would not be re-entered into this table; it would be handed to
             * normal node resolution, land on node_modules/lodash, and that is 4.18.1 and a
             * devDependency -- package.json:54, and package.json has NO `dependencies` key at all, so
             * there is no runtime lodash dependency of any kind. Writing it that way would silently perform
             * group 8's lodash 3 -> 4 upgrade inside task 4.3, untested, in a commit that does not
             * say so, and without task 8.3's "phase-0a suite green either side" gate. It is not a
             * benign upgrade: it breaks _.contains x4 (ui-commons util/UIUtils.js:611,631,
             * components/Navigation.js:180, navigation/filters/RoleFilter.js:37), _.findWhere x2
             * (ui-user anonymousProcess/KBAView.js:108,130) and _.object x1
             * (ui-commons util/URIUtils.js:120) in the underscore-bound trees, plus 25 further
             * call sites in AM's directly-lodash-importing modules.
             *
             * So 4.3 stays behaviour-neutral and both ids point at the real lodash 3.10.1 file in
             * one hop. src/main/js/libs/lodash-3.10.1-min.js is NEW: it was vendored by this task,
             * byte-identical (md5 7629cac4f079926ef505e2271bb5135f) to
             * target/dependencies/libs/lodash-3.10.1-min.js, the Maven unpack that supplies it
             * today. It had no source copy at all before -- every copy on disk was under target/,
             * which 4.1 has already repointed to Vite's outDir. The four files already in
             * src/main/js/libs are the precedent for vendoring it there.
             *
             * GROUP 8 CHANGES THIS, and that is the point of pinning it. Task 8.3 drops the
             * 3.10.1-at-runtime / 4.18.1-as-a-build-dependency split as its own reviewable commit;
             * at that point both this entry and the one below repoint to the npm lodash 4, and
             * "underscore" disappears altogether once its consumers are gone -- which is what the
             * TODO at main.js:32, main-authorize.js:32 and main-device.js:23 asks for. Task 4.7
             * owns where the vendored file finally lives, through its per-file destination table.
             */
            "underscore": fromSrc("libs/lodash-3.10.1-min.js"),

            /*
             * NOT ONE OF THE TWELVE, AND DELIBERATELY WRITTEN ANYWAY. "lodash" is a main.js PATHS
             * entry (main.js:62 -> libs/lodash-3.10.1-min, repeated at main-authorize.js:40 and
             * main-device.js:31), and the paths block belongs to task 4.7, not to 4.3. This single
             * entry is the seam where the two tasks touch. It is written rather than left silent
             * because omitting it is NOT neutral: without it, ui-commons and ui-user modules would
             * get lodash 3 through "underscore" while AM's own 16 direct `import _ from "lodash"`
             * statements and its many define([... "lodash" ...]) declarations resolved to 4.18.1
             * from node_modules -- TWO major versions of lodash in one bundle, split down the
             * middle of the dependency graph, which is worse than either version uniformly. One
             * version, and it is the one that ships today.
             *
             * 4.7 still owns the paths block and where this file comes from; 8.3 still owns the
             * version. This entry is a pin, not a decision about either.
             */
            "lodash": fromSrc("libs/lodash-3.10.1-min.js")
        }
    },

    /*
     * ==== THE OTHER SIX BINDINGS: RUNTIME STRING IDENTIFIERS -- TASK 6.1 OWNS THESE ====
     *
     * These six of main.js's twelve map bindings are NEVER reached as an AMD dependency. They
     * appear only as string identifiers inside ui-commons' and ui-user's route and process
     * configs, and are resolved at RUNTIME through ModuleLoader.load -> require([libPath])
     * (ui-commons org/forgerock/commons/ui/common/util/ModuleLoader.js:22-26, reached from
     * main/ProcessConfiguration.js:44-45). resolve.alias NEVER SEES THEM, which is why they are
     * absent from the table above rather than written there as no-ops.
     *
     * THIS LIST IS THE HAND-OFF TO TASK 6.1, AND IT IS THE REASON IT IS WRITTEN HERE RATHER THAN
     * ONLY IN A NOTES FILE. D1's registry is keyed by source-root-relative path without extension
     * (task 6.1). If it is built ONLY that way, every one of these six fails to resolve at runtime
     * with nothing to say why -- the login page, the login dialog, the profile page,
     * forgot-username, password-reset and self-registration each resolve to nothing. The registry
     * must ALSO honour these six logical names, bound to the targets below. This is what
     * ui-module-loading's "Substitution of commons modules by the product" requires and what its
     * third scenario -- a logical name left unbound must fail AGAINST THE LOGICAL NAME -- makes a
     * registry obligation rather than an alias one. resolve.alias cannot satisfy that scenario:
     * an unbound name there degrades to an unresolved-import warning, not a named failure.
     *
     *   logical name        must resolve to                                                    used at (file:line)
     *   ------------------  -------------------------------------------------------------      -------------------------------------------------
     *   Footer              org/forgerock/openam/ui/common/components/Footer                    AM config/process/AMConfig.js:196 and
     *                                                                                          ui-commons config/process/CommonConfig.js:73
     *                                                                                          (both dependencies arrays)
     *   LoginView           org/forgerock/openam/ui/user/login/RESTLoginView                    ui-commons config/routes/CommonRoutesConfig.js:40
     *                                                                                          (route view:)
     *   ForgotUsernameView  org/forgerock/openam/ui/user/anonymousProcess/ForgotUsernameView    ui-user config/routes/UserRoutesConfig.js:32
     *                                                                                          (route view:)
     *   PasswordResetView   org/forgerock/openam/ui/user/anonymousProcess/PasswordResetView     ui-user config/routes/UserRoutesConfig.js:39
     *                                                                                          (route view:)
     *   LoginDialog         org/forgerock/openam/ui/user/login/RESTLoginDialog                  ui-commons config/routes/CommonRoutesConfig.js:51
     *                                                                                          (route dialog:), ui-commons
     *                                                                                          config/process/CommonConfig.js:420, and AM
     *                                                                                          config/process/AMConfig.js:275 (override handler)
     *   RegisterView        org/forgerock/openam/ui/user/anonymousProcess/SelfRegistrationView  ui-user config/routes/UserRoutesConfig.js:46
     *                                                                                          (route view:)
     *
     * A SEVENTH NAME FOR 6.1, which is in the alias table above rather than in this list because
     * it has a real AMD consumer: UserProfileView is reached BOTH ways -- a define dep at AM
     * SiteConfigurationService.js:25 (aliased above, live) AND a route view: at ui-user
     * config/routes/UserRoutesConfig.js:24 (runtime, needs the registry). It is the only name of
     * the twelve in both categories. ALIASING IT DOES NOT COVER ITS ROUTE USE.
     *
     * AND ONE CASE NEITHER MECHANISM SAVES: AM
     * org/forgerock/openam/ui/user/login/RESTLoginHelper.js:61 tests
     * ViewManager.currentView === "LoginView" -- a string EQUALITY comparison against the raw,
     * UNRESOLVED route identifier, which is assigned the bare viewPath at ui-commons
     * main/ViewManager.js:95 and the bare route.view at config/process/CommonConfig.js:327. It is
     * not an import and not a registry lookup. If anyone rewrites the route configs to name real
     * module paths, that comparison becomes permanently false and the re-render branch dies
     * silently. No alias and no registry entry protects it. Recorded here because nothing else
     * will see it.
     *
     * WHERE THE (b) IDENTIFIERS PHYSICALLY LIVE, which is D19's problem and lands on this file:
     * all six are inside three ui-commons/ui-user config/** modules -- config/routes/
     * CommonRoutesConfig, config/routes/UserRoutesConfig and config/process/CommonConfig -- and
     * D19 requires the config/ prefix be aliased ID BY ID, never wholesale, because
     * config/AppConfiguration and config/ThemeConfiguration are the product's own files and a
     * prefix alias would invert the customization route. If those ids are never individually
     * aliased, these six bindings have no consumer at all and the absence looks like "the alias
     * was unnecessary" rather than like a failure. Compounding it, AM config/main.js:26-44 reaches
     * 7 of its 15 dependencies by RELATIVE id (./routes/CommonRoutesConfig and friends), and
     * relative specifiers cannot be aliased at all -- Grunt's copy:compose flattening is the only
     * reason they resolve today. Neither is 4.3's to settle; both are recorded so they are not
     * rediscovered.
     *
     * THREE MORE PRODUCT-SUPPLIED IDENTIFIERS THAT ARE NOT map BINDINGS AND HAVE NO OWNER.
     * They are the same mechanism as the six above -- commons names a collaborator, the product
     * decides what it is -- but they are not in main.js's map block, so 4.3 correctly does not
     * bind them, and nothing else currently does either.
     *
     *   config/AppConfiguration  ui-commons main/Configuration.js:20 declares it. It is the fourth
     *                            entry in ui-commons/NPM-PACKAGE.md's "Identifiers the consumer
     *                            must supply" table; the other three (underscore, ThemeManager,
     *                            NavigationFilter) are all aliased above. This one resolves by
     *                            baseUrl today. It is also exactly the id D19 says must never be
     *                            caught by a wholesale config/ prefix alias, since it is the
     *                            product's own file -- see the paragraph above.
     *   form2js / js2form        ui-user NPM-PACKAGE.md:245-246 -- 5 and 3 modules respectively.
     *                            NO npm package exists for either: they are maxatwork/form2js at
     *                            pinned commit 769718a, and the registry's form2js is a different
     *                            fork. They are ALSO the same failure mode this task just fixed
     *                            for lodash -- neither file calls define(), both are plain scripts
     *                            assigning a global, so a paths entry or a bare alias is not
     *                            sufficient on its own. Whoever owns them will need the
     *                            commonjsOptions treatment in build below, or a shim.
     *
     * NOT DONE BY 4.3, AND IT STILL NEEDS AN OWNER: resolve.extensions and the .jsm extension,
     * which this file's own 4.1 header assigns to 4.3. tasks.md:69 scopes 4.3 to the 12 map
     * bindings and names nothing else, so it was left out here deliberately rather than done
     * silently. Nothing fails loudly for it: Vite's default resolve.extensions has no .jsm and
     * esbuild has no loader for it, and the react plugin's default include does not match .jsm
     * either, so the .jsm files get neither resolution nor a JSX transform. The closest fitting
     * owner is task 5.2, "stop transpiling the .jsm/.jsx files to AMD".
     */

    /*
     * 4.4 owns static assets. themes/, templates/, partials/ and locales/ ship unbundled and
     * unhashed (D3) and are fetched by path at runtime, so they are not in the module graph and
     * Vite will not emit them without being told to. publicDir is off because this module has no
     * public/ directory; turning it on by accident would silently change the shipped layout.
     */
    publicDir: false,

    css: {
        /*
         * Grunt compiled three LESS files (Gruntfile.js:222-244): css/structure.less,
         * css/theme.less and css/styles-admin.less, with clean-css minification. Reaching them
         * through the module graph is 4.4's problem; the sources live under the composed tree,
         * not under src/main/js.
         */
        preprocessorOptions: {
            /*
             * javascriptEnabled is deliberately NOT set. Less 4 defaults it off as code-execution
             * hardening, and no .less file needs it: checked src/main/resources (21 files), the
             * commons packages (36) and target/dependencies (2) — not one contains a backtick.
             * If 4.4 finds one that does, turn it on here and name the file.
             */
            less: {}
        }
    },

    define: {
        /*
         * Grunt's replace:buildNumber substituted ${version} into index.html (Gruntfile.js:246-258).
         * 4.5 owns the index.html half; this exposes the same value to source.
         */
        __TARGET_VERSION__: JSON.stringify(targetVersion)
    },

    build: {
        /*
         * ==== 4.3 -- MAKING THE VENDORED lodash USABLE, NOT MERELY RESOLVABLE ====
         *
         * The two lodash aliases above point at src/main/js/libs/lodash-3.10.1-min.js, and that
         * file is UMD: its export mechanism is the tail
         *
         *     typeof define == "function" && typeof define.amd == "object" && define.amd
         *       ? (Zn._ = Yn, define(...)) : Mn && qn ? ... : Zn._ = Yn;
         *
         * It has no ES exports at all. @rollup/plugin-commonjs is what converts such a file, and
         * Vite's DEFAULT build.commonjsOptions.include is [/node_modules/] (node.js:32352) -- which
         * excludes everything under src/. Resolving in one hop is therefore NOT sufficient: the id
         * resolves and the module is still unusable. That distinction is why this block exists.
         *
         * MEASURED, NOT ASSUMED, AND THE RESULT DEPENDS ON WHICH VITE RUNS. An isolated probe
         * built `import _ from "lodash"` against this exact file through this exact alias:
         *
         *   vite 5.1.2 (Rollup), default commonjsOptions -> BUILD FAILS:
         *       "default" is not exported by src/main/js/libs/lodash-3.10.1-min.js
         *   vite 5.1.2 (Rollup), with the include below -> builds; at runtime
         *       _ is a function, _.contains is a function, _.VERSION === "3.10.1"
         *   vite 8.1.0 (rolldown), either way -> builds and works
         *
         * The split is the engine: vite 5 bundles with Rollup and needs the commonjs plugin, vite
         * 8 bundles with rolldown, which has native CJS/UMD interop and ignores commonjsOptions.
         * package.json declares "vite": "^5.4.21" and the lockfile pins 5.4.21, but NO vite is
         * installed in this module's node_modules -- resolution walks up to
         * OpenAM/openam-ui/node_modules/vite, which is 8.1.0. So without the setting below, this
         * task's own alias target breaks under the version the project DECLARES while working
         * under the version that currently RESOLVES. That is the worst shape a defect can have,
         * and it is why the setting is written rather than left to be discovered.
         *
         * NOTES-vite-aliases.md section 7.3 records "which vite the build actually uses" as
         * unresolved. It is still unresolved; this setting is correct under both engines (vite 8
         * ignores it) so it does not depend on the answer, but the underlying question needs one.
         *
         * SCOPE: no task owns build.commonjsOptions. 4.3 sets it because 4.3 created the file that
         * needs it. Task 4.7 owns where libs/ files finally live and MUST update this regex when
         * it moves them -- the coupling is deliberate and is called out here so it is not silently
         * broken. Task 8.3 deletes both the file and this entry when lodash 4 lands.
         *
         * The regex is scoped to src/main/js/libs/ rather than to the one file on purpose: the
         * other four vendored files there are AMD/UMD in exactly the same way, and 4.7 will be
         * reasoning about them as a group.
         */
        commonjsOptions: {
            include: [/node_modules/, /src[\\/]main[\\/]js[\\/]libs[\\/]/],
            extensions: [".js", ".cjs"]
        },

        /*
         * Decided in 4.1: target/compiled, the directory Grunt wrote and the one
         * src/main/assembly/zip.xml:36 packs. Keeping it means the zip contract needs no edit
         * (D8) and xui-deploy.sh / e2e local-server keep working with no argument.
         *
         * The cost, recorded so it is not rediscovered: emptyOutDir wipes the Grunt tree on the
         * first run. Gruntfile.js is retained through 4.8 for exactly that reason. Regenerate with
         *
         *     npm run build:grunt -- --target-version=16.2.0-SNAPSHOT
         *
         * and pass the version EVERY time. It is not optional and it is not cosmetic: until 4.1 the
         * only caller of the Grunt build was this pom, which always supplied it, so the script
         * itself never needed a default. replace:buildNumber (Gruntfile.js:246-259) is the sole
         * thing that stamps it, because mavenProjectSource (Gruntfile.js:24-28) composes from the
         * UNFILTERED src/main/resources rather than Maven's filtered target/classes. Omit it and
         * Grunt writes v=dev, index.html comes out 976 bytes against PHASE1-TREE.md's 988, and the
         * oracle mismatches on its single most important file. Verified: with the option, all 652
         * files are byte-identical to the manifest; without it, exactly that one differs.
         *
         * Nothing in the Maven lifecycle writes to target/compiled — openam-ui-ria/pom.xml has zero
         * references to it — so the Grunt tree is the only thing emptyOutDir can destroy.
         *
         * karma.conf.js:13 still globs target/compiled/**\/*.js and will now match a Vite tree of
         * a different shape. That coupling is live until 9.1 deletes karma.conf.js.
         */
        outDir: "target/compiled",
        emptyOutDir: true,
        sourcemap: true,

        rollupOptions: {
            /*
             * ==== 4.2 — THE THREE ENTRY POINTS, AND WHY TWO OF THEIR NAMES ARE FIXED ====
             *
             * Three entry points ship today. r.js compiled `include: ["main"]` alone
             * (Gruntfile.js:270), which is why 308 of the shipped .js files are unbundled and
             * reached by path; see NOTES-vite-build.md §1.6.
             *
             * main-authorize.js and main-device.js MUST be emitted at exactly those two names, at
             * the root of the tree, unhashed. That constraint does not live in this module and
             * nothing here would otherwise reveal it: six FreeMarker templates in the
             * **openam-oauth2** Maven module fetch them through RequireJS `data-main`, which
             * resolves the bare id against baseUrl and appends ".js" —
             *
             *   openam-oauth2/src/main/resources/templates/page/authorize.ftl:65      main-authorize
             *   openam-oauth2/src/main/resources/templates/popup/authorize.ftl:64     main-authorize
             *   openam-oauth2/src/main/resources/templates/touch/authorize.ftl:64     main-authorize
             *   openam-oauth2/src/main/resources/templates/page/error.ftl:56          main-authorize
             *   openam-oauth2/src/main/resources/templates/CodeVerificationForm.ftl:37   main-device
             *   openam-oauth2/src/main/resources/templates/CodeThanks.ftl:37             main-device
             *
             * Rename or hash either one and the OAuth2 consent screen, the OAuth2 error page and
             * the device-flow pages break — in a different Maven module, which this build does not
             * test. Editing those templates is a server-side change, which D8 ("lets the migration
             * land without a coordinated server-side change") and task 10.4 both say this migration
             * does not require. src/main/resources/index.html:21-27 pins the third name, but by a
             * DIFFERENT attribute: a global `require` object carrying `deps: ['main']`, not
             * data-main. Same nameToUrl resolution and same classic-script injection (§2.6, where
             * data-main is shown to be implemented AS cfg.deps plus an inferred baseUrl) — the
             * mechanisms converge, the ownership does not, and that is the asymmetry that matters
             * here: index.html lives in THIS module and 4.5 may rewrite it; the six .ftl live in
             * openam-oauth2 and D8 says this migration does not touch them.
             *
             * Full evidence, including the deminified RequireJS 2.3.7 trace showing data-main goes
             * through nameToUrl rather than being used as a literal path:
             * NOTES-vite-entrypoints.md §1 (the complete loader list) and §2 (what data-main does).
             *
             * ---- DEFERRED HERE, AND IT MUST NOT BE REDISCOVERED IN GROUP 5 ----
             * The names below are right; the FORMAT is not yet. RequireJS injects a CLASSIC script
             * (§2.4: req.createNode sets type="text/javascript") for BOTH loader forms, so an ES
             * module breaks ALL THREE entries, not just the two secondaries — index.html's
             * `deps: ['main']` route is the same code path (§2.6). Do not read this section as
             * "main.js is safe". This task does not introduce the problem — the source is still
             * AMD, so nothing this build emits executes yet (see READ BEFORE EDITING above) — but
             * it becomes real the moment group 5 converts the tree to ESM. The difference between
             * main and the other two is not mechanism, it is editability: 4.5 can rewrite
             * index.html in this module, so main has an escape the secondaries do not.
             * NOTES-vite-entrypoints.md §3 costs the four options that need no server-side change:
             * (a) three single-entry IIFE builds, (c1) an unhashed classic stub that
             * dynamic-imports the hashed chunk, (c2) AMD output, (c3) copy the two entries
             * verbatim. 4.2 deliberately chose none of them: configure the naming now, decide the
             * loader story when the source can actually execute. Nothing below forecloses any.
             */
            input: {
                /*
                 * Relative to the project root, not resolve(__dirname, ...) as
                 * NOTES-vite-entrypoints.md 4.3 writes it. frontend-maven-plugin runs npm with
                 * workingDirectory defaulting to ${basedir}, so the two are equivalent here, and a
                 * wrong cwd would fail loudly at resolve time rather than silently mis-emit.
                 *
                 * Note for 4.4-4.8, whose oracle is PHASE1-TREE.md's per-file digest: 4.1's
                 * sourcemap:true plus these two extra entries emits main-authorize.js.map and
                 * main-device.js.map, which the Grunt tree never had (PHASE1-TREE.md:53 lists 8
                 * root files with exactly one .map). Those two are an EXPECTED delta, not drift.
                 */
                "main":           "src/main/js/main.js",
                "main-authorize": "src/main/js/main-authorize.js",
                "main-device":    "src/main/js/main-device.js"
            },

            output: {
                /*
                 * "es" is the only format that supports code-splitting in a multi-entry build.
                 * Verified against the installed rollup 4.62.5, not recalled from docs:
                 * validateOptionsForMultiChunkOutput (rollup/dist/shared/rollup.js:22453-22455)
                 * rejects "umd" and "iife" for code-splitting builds, and its trigger at :22309 is
                 * `chunks.length > 1` — three entries fire it with zero dynamic imports. Vite also
                 * auto-sets inlineDynamicImports for iife/umd, in buildOutputOptions
                 * (vite/dist/node/chunks/dep-BK3b2jBa.js:65645 in vite 5.4.21 — the chunk filename
                 * carries a content hash and the offset moves on every bump, so search the symbol,
                 * not the line), which rollup then rejects outright for multiple inputs (:23831).
                 * "amd" and "system" are rejected by neither guard, which is what keeps option (c2)
                 * open — though §7.1 records (c2) as UNVERIFIED: whether rollup's relative AMD
                 * chunk ids resolve under RequireJS 2.3.7's nameToUrl needs a spike, not an
                 * assumption. Treat it as open, not as a known-good escape hatch.
                 *
                 * "es" is also Vite's own default (:65618). Stated explicitly because the guards
                 * above make it load-bearing, not because it changes behaviour.
                 */
                format: "es",

                /*
                 * [name] for an entry chunk is the KEY of the input object above, so those three
                 * keys are what put main.js, main-authorize.js and main-device.js at the tree root
                 * with stable, unhashed names. PHASE1-TREE.md:155-156 records that as the
                 * requirement Vite's default assets/[name]-[hash].js violates.
                 */
                entryFileNames: "[name].js",

                /*
                 * entryFileNames applies ONLY to entry chunks, so hashing stays on for everything
                 * rollup splits out. That is deliberate and load-bearing: ui-module-loading's
                 * "On-demand loading of resolvable modules" requires a route's view to be fetched
                 * when the route is first visited rather than shipped in the initial payload, so
                 * this build must keep code-splitting. Disabling hashing wholesale would satisfy
                 * the two .ftl paths and forfeit that requirement's cache story; it is not needed
                 * and is not done. D1's import.meta.glob registry (tasks 6.1-6.3) is what will
                 * populate these chunks — nothing here presumes its shape.
                 *
                 * Note for 4.3, which owns the resolve.alias bindings: a multi-entry build lets
                 * rollup hoist shared code into a common chunk, and that is safe for everything
                 * EXCEPT a module whose behaviour depends on a per-entry require.config.map
                 * binding. Today that set is {ThemeManager}, via Router — main.js:29 binds Router
                 * to the commons Router while main-authorize.js:31 and main-device.js:22 bind it
                 * to SingleRouteRouter, and ThemeManager.js:25,168 reads Router.currentRoute.
                 * resolve.alias is global to the build and cannot give one id two meanings.
                 * NOTES-vite-entrypoints.md §5 has both failure modes — and §6 records that e2e
                 * catches only ONE direction: aliasing globally to SingleRouteRouter leaves the
                 * consent and device specs green while silently killing the admin theme. A green
                 * suite is not evidence 4.3 got this right.
                 *
                 * ---- SUPERSEDED BY 4.3. READ THIS BEFORE ACTING ON THE PARAGRAPH ABOVE. ----
                 * 4.3 landed the binding (commons Router wins) and, in doing so, found that
                 * NOTES-vite-entrypoints.md §5.2 has BOTH failure modes backwards. The sentence
                 * above -- "silently killing the admin theme" -- is the superseded reading.
                 * Corrected: the two secondary entries request the ALIASED name themselves
                 * (main-authorize.js:66, main-device.js:61), so entries and ThemeManager cannot
                 * diverge. Aliasing to SingleRouteRouter does not silently degrade -- it throws a
                 * TypeError on every console view render. The evidence and the trace are in the
                 * resolve.alias block above, entry 3, and in NOTES-vite-aliases.md §3. §6's point
                 * stands and is why this matters: the e2e suite is blind in that direction.
                 *
                 * chunkFileNames and assetFileNames are both Vite's defaults, restated so they are
                 * explicit; neither changes behaviour against vite 5.4.21.
                 *
                 * 4.4 collides with assetFileNames, but NOT over themes/, templates/, partials/ or
                 * locales/ — those are fetched at runtime, never enter the module graph, and this
                 * option cannot see them (they need publicDir or a copy plugin). The asset kind it
                 * DOES govern is css/: PHASE1-TREE.md:212-214 ships css/structure.css,
                 * css/styles-admin.css and css/theme.css unhashed under css/, and the setting below
                 * would both relocate them to assets/ and hash them the moment 4.4 pulls LESS into
                 * the graph. That is the collision 4.4 has to resolve.
                 */
                chunkFileNames: "assets/[name]-[hash].js",
                assetFileNames: "assets/[name]-[hash].[ext]"
            }
        }
    }
});
