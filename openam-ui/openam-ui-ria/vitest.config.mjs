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

/*
 * ============================================================================================
 * The unit suite.  Run:  npm run test:unit   (and `npm test`, which pom.xml calls)
 * ============================================================================================
 *
 * Task 9.1 (D12). This replaces karma.conf.js, which bound the suite to Grunt's target/compiled
 * and target/test-classes layout and has been unrunnable since task 5.4 converted the sources
 * from AMD to ES modules.
 *
 * WHY THIS FILE IMPORTS vite.config.js RATHER THAN DECLARING ITS OWN ALIASES
 *
 * The sources keep the AMD id space (D19): they import each other as bare, extensionless,
 * absolute ids -- "org/forgerock/openam/ui/common/util/Constants", not a relative path and not a
 * package specifier. Nothing on disk is called that. The ONLY thing that turns those ids into
 * files is vite.config.js's resolve.alias array, and it is not a small table: a prefix entry for
 * org/forgerock/openam, explicit entries for every commons id, the shims, and the vendored
 * libraries of D20.
 *
 * So a second, hand-written copy of that table here would be a second answer to "what does this
 * id mean". The alias-ordering comment in vite.config.js warns about exactly one failure this
 * produces -- two different modules answering to `Router` -- and a divergence introduced through
 * the test harness is the worst version of it, because the suite would then be green about a
 * module graph the build never produces. Importing the array means an alias added to the build
 * is an alias the tests get, with no second edit and no way to forget.
 *
 * The cost is real and was measured: vite.config.js is ~276 kB and parsing it adds about 120 ms
 * to a run (2.06 s vs 1.94 s wall, n=3). That is the whole price. Pay it.
 *
 * `define` is carried across for the same reason and is not optional: __TARGET_VERSION__,
 * __LOGIN_HELPER_CLASS__ and __THEME_CONFIG_OVERRIDE__ are compile-time substitutions, so a
 * config that omits them does not fail to resolve -- it throws ReferenceError partway through
 * evaluating a module, which reads like a source bug and is not one.
 *
 * NO PLUGIN FROM vite.config.js RUNS HERE, which is worth stating because the import above
 * invites the opposite assumption. Vitest picks its config by first match over
 * CONFIG_NAMES = ["vitest.config", "vite.config"] (vitest/dist/chunks/constants.*.js), so the
 * mere existence of this file means vite.config.js is never loaded AS the Vite config; and the
 * object below re-exports `resolve` and `define` only, never `plugins`. vite.config.js is
 * evaluated as an ordinary module -- its top-level EXPECTED_VITE_MAJOR guard still runs, and
 * still throws on a non-5.x vite -- and nothing else about it applies.
 *
 * The consequence that matters now: `vitest run` writes nothing to target/ (measured: 2664 files
 * byte-identical before and after). NOT because xui-static-assets declares `apply: "build"`, but
 * because no plugin is registered at all.
 *
 * The consequence to watch in 9.2: this module graph inherits the build's alias table and NONE
 * of its transforms -- not xui-sloppy-mode-libraries, not the xui-assert-* guards, not
 * xui-requirejs-entry-stubs. Harmless for the nine subjects ported here; ThemeManagerTest and
 * RouteToTest are the likeliest to notice the difference.
 */

import { defineConfig } from "vitest/config";
import viteConfig from "./vite.config.js";

export default defineConfig({
    resolve: {
        alias: viteConfig.resolve.alias,
        extensions: viteConfig.resolve.extensions
    },
    define: viteConfig.define,
    test: {
        /*
         * jsdom, one environment for the whole suite. Measured: 9 of the 18 subjects cannot be
         * imported at all under `node` -- they fail while evaluating transitive jquery/commons
         * code with `window is not defined` or `location is not defined`, before any assertion
         * runs. Splitting the run by environment would save roughly 0.7 s and add a second thing
         * to keep in step; commons/ui/commons/vitest.config.mjs reaches the same conclusion.
         *
         * NOTE: jsdom is a devDependency of this module. It resolves from the parent directory's
         * node_modules on some working copies, which is an accident of an untracked tree and not
         * something a fresh clone gets.
         */
        environment: "jsdom",
        /*
         * Continuity with the harness this replaces: karma.conf.js set
         * `client.mocha.timeout: 6000`, and Vitest's default is 5000. Nothing here is remotely
         * close (slowest file 258 ms), but 9.2's Squire files are the heavier ones and a budget
         * that silently shrank during the migration is not a thing to discover later.
         */
        testTimeout: 6000,
        include: ["src/test/vitest/**/*.test.mjs"],
        /*
         * What test-main.js did for Karma, minus the globals. See the file for why sinon-chai
         * survives the migration and chai the package does not.
         */
        setupFiles: ["src/test/vitest/setup.mjs"],
        /*
         * The commons packages are ES modules that import AM's and their own ids in the same
         * bare AMD form (D19). Vitest externalises node_modules by default and hands those files
         * to Node's own loader, which has never heard of resolve.alias and reads
         * `import ... from "org/forgerock/..."` as a package named `org`:
         *
         *     Cannot find package 'org' imported from
         *       node_modules/@openidentityplatform/ui-commons/esm/...
         *
         * Inlining puts them on the same module graph as the tests, so the alias array applies
         * to them too. commons/ui/commons/vitest.config.mjs needs the same knob for the same
         * reason. This is invisible to any test that mocks every commons id it touches, so it
         * goes in from the start rather than waiting to surface as a mystery in 9.2.
         */
        server: {
            deps: {
                inline: [/@openidentityplatform[\\/]/]
            }
        }
    }
});
