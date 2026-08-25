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
 *   4.3  resolve.alias              the 12 require.config.map bindings from main.js:19-34
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

/*
 * Maven passes the project version through this variable. The pom's npm-build execution sets it;
 * see openam-ui-ria/pom.xml. "dev" mirrors Gruntfile.js:45, `grunt.option("target-version") || "dev"`.
 */
const targetVersion = process.env.TARGET_VERSION || "dev";

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
     * 4.3 owns this. main.js:19-34 carries 12 require.config.map bindings, including
     * underscore -> lodash (D2). Empty until then so the omission is visible rather than implied.
     *
     * 4.3 also owns resolve.extensions and the .jsm extension, which is easy to miss because
     * nothing here fails loudly for it. babel:transpileJSM (Gruntfile.js:120-133) consumed
     * **\/*.{jsm,jsx} and renamed both to .js. Vite's default resolve.extensions has no .jsm and
     * esbuild has no loader for it, so those files get neither resolution nor a JSX transform.
     */
    resolve: {
        alias: {}
    },

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
