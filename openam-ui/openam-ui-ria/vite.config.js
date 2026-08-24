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
 *   4.2  build.rollupOptions.input   the three entry points
 *   4.3  resolve.alias              the 12 require.config.map bindings from main.js:19-34
 *   4.4  static assets              themes/ templates/ partials/ locales/ copied verbatim
 *   4.5  index.html + ${version}    the filtered index.html and the deployed /XUI layout
 *   4.5  output.entryFileNames     Grunt emitted an unhashed target/compiled/main.js at the tree
 *                                  root (PHASE1-TREE.md:53), which index.html's RequireJS
 *                                  data-main and the urlArgs scheme both depend on. Vite currently
 *                                  emits assets/main-<hash>.js. Reconciling that is 4.5's.
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
             * 4.2 owns this. Three entry points ship today — main.js, main-authorize.js and
             * main-device.js — and only main.js is wired up here so the skeleton resolves.
             * r.js compiled `include: ["main"]` alone (Gruntfile.js:270), which is why 308 of the
             * shipped .js files are unbundled and reached by path; see NOTES-vite-build.md §1.6.
             */
            input: {
                main: "src/main/js/main.js"
            }
        }
    }
});
