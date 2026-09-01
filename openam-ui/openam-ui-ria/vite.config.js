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
 *   4.4  static assets              themes/ templates/ partials/ locales/ copied verbatim.
 *                                  LANDED as the xuiStaticAssets plugin defined below this
 *                                  header block, replaying Grunt's copy:compose (8 sources,
 *                                  last wins) and copy:compiled (the nonCompiledFiles
 *                                  filter) in writeBundle. It ships 263 files, not the four
 *                                  directories the task text names: also images/, the five
 *                                  Font Awesome fonts, favicon.ico, oauthReturn.html and
 *                                  timezones.json, none of which any task lists. It ALSO
 *                                  compiles the three LESS files, which no group-4 task
 *                                  owns -- decided in, not assumed by, this task; see the
 *                                  LESS_ENTRIES comment. publicDir stays false and the
 *                                  assetFileNames collision 4.2 flagged is resolved below.
 *   4.5  index.html + ${version}    LANDED as stampIndexHtml below, called from the same
 *                                  writeBundle as 4.4: read src/main/resources/index.html,
 *                                  substitute ${version}, write it to the tree root. index.html
 *                                  is deliberately NOT a Vite HTML input -- the reasons, and the
 *                                  two ${version} mechanisms of which only one is live, are in
 *                                  the block above stampIndexHtml. The entryFileNames half was
 *                                  SETTLED IN 4.2 and stays the plain "[name].js": the three JS
 *                                  entries emit unhashed at the tree root, which is how all
 *                                  three are loaded today (PHASE1-TREE.md:150) and what the
 *                                  urlArgs scheme assumes. Because no HTML input is declared,
 *                                  Vite derives no fourth entry chunk, so the double-emit
 *                                  hazard NOTES-vite-entrypoints.md 4.3 flagged cannot arise
 *                                  and its function form of entryFileNames is not needed.
 *   4.9  resolveAssetUrl            cache-busting for runtime-fetched assets (D4)
 *   4.10 server.*                   the dev server, paired with e2e/local (D14)
 *
 *   5.1  resolve.extensions         the .jsm extension, inherited from the scope 4.3 declined.
 *                                  LANDED as exactly ONE knob -- resolve.extensions, spelled
 *                                  out in full because it REPLACES rather than extends Vite's
 *                                  default. The React plugin's include was measured and
 *                                  deliberately NOT widened (no .jsm contains JSX), and no
 *                                  esbuild loader mapping was added (vite:esbuild never sees a
 *                                  .jsm). 5.1 also PINS the engine: the guard below the imports
 *                                  fails the build if a vite other than the declared 5.x
 *                                  resolves. Nothing in 5.1 converts a module; it is resolution
 *                                  mechanics only.
 *
 *   5.2  resolve.alias (again)     the 26 require.config.shim entries in main.js:80-172 and the
 *                                  paths ids they name. LANDED as 24 further alias entries, 13
 *                                  shim modules under src/main/js/shims/, requireReturnsDefault
 *                                  on build.commonjsOptions, and the sloppyModeLibraries plugin.
 *                                  It is the RESOLUTION half only -- no AMD module is converted
 *                                  here, that is 5.4 -- so NOTHING 5.2 landed is exercised yet and
 *                                  a green build says nothing about it, per the note just below.
 *                                  The alias block carries the reasoning; the ordering invariant
 *                                  it depends on is enforced by assertAliasOrdering rather than
 *                                  left to a comment. The two react rows are 5.3's and untouched.
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
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

/*
 * Maven passes the project version through this variable. The pom's npm-build execution sets it;
 * see openam-ui-ria/pom.xml. "dev" mirrors Gruntfile.js:45, `grunt.option("target-version") || "dev"`.
 */
const targetVersion = process.env.TARGET_VERSION || "dev";

/*
 * The login helper config/AppConfiguration names, overridable at build time, defaulting to the one
 * the product ships. Deliberately the same shape as TARGET_VERSION above -- an environment variable
 * read here once and handed to source through `define` below -- so that no module under src/ ever
 * names `process.env`, which does not exist in a browser bundle.
 *
 * WHY IT EXISTS. OpenAM/e2e/xui/xui-operator-module.spec.mjs defends the capability that an operator
 * can drop a module into the deployed /XUI, name it in configuration, and have the XUI load it. It
 * therefore needs a deployed tree whose configuration names that module. Under this build the
 * string is compiled into a content-hashed chunk, so there is no deployed config/AppConfiguration.js
 * left to edit and the only remaining instruction would have been "edit tracked product source,
 * build, deploy, and remember to put the line back" -- a source mutation with no teardown, resting
 * on human memory. This flag removes the mutation: nothing tracked changes, so nothing has to be
 * restored.
 *
 * UNSET IS THE SHIPPED BEHAVIOUR, AND THAT IS THE POINT. The fallback below is character for
 * character the string config/AppConfiguration.js carried before this flag existed, so a plain
 * `npm run build:production` emits exactly what it always emitted.
 */
const loginHelperClass = process.env.LOGIN_HELPER_CLASS
    || "org/forgerock/openam/ui/user/login/RESTLoginHelper";

/*
 * Extra themes and theme mappings to merge into config/ThemeConfiguration.js at build time, as a
 * JSON string. Empty -- the shipped configuration, untouched -- unless the environment sets it.
 *
 * WHY IT EXISTS, and it is the same argument as `loginHelperClass` above with one addition.
 * OpenAM/e2e/xui/xui-theming.spec.mjs defends per-realm theme selection and the theme-path template
 * override. Both need a *configuration* the shipped one does not contain: a mapping from a test's
 * realm to a theme, and -- for the override half -- a theme declaring a non-empty `path`, which no
 * shipped theme does (`default` sets `path: ""` and `fr-dark-theme` declares none, so `extendTheme`
 * gives it `""` too). Before D6 the spec wrote both into the deployed config/ThemeConfiguration.js
 * and restored it afterwards. That file no longer exists in a built tree, so without this flag the
 * only remaining instruction would be "edit tracked product source, build, deploy, and remember to
 * put it back" -- a source mutation with no teardown, resting on human memory.
 *
 * THE ADDITION, and it is the difference from __LOGIN_HELPER_CLASS__: a mapping needs a REALM TO
 * EXIST, and a build flag cannot create one. So this flag is only half the fixture. It names realms
 * as fixed literals at build time; the spec creates exactly those realms over REST before it
 * probes, and deletes them in teardown. The spec asserts the build half as a PRECONDITION and never
 * performs it -- see the header of xui-theming.spec.mjs.
 *
 * UNSET IS THE SHIPPED BEHAVIOUR. With this empty, esbuild constant-folds the ternary in
 * ThemeConfiguration.js on the `""` literal and tree-shakes `applyOverride` and the `JSON.parse`
 * out of the bundle entirely -- verified by extracting the emitted configuration object from the
 * chunk and comparing it character for character against a build made before this flag existed.
 * It is NOT hash-identical the way __LOGIN_HELPER_CLASS__ was: the source now has two bindings
 * where it had one, which costs a few bytes of aliasing. That is the whole difference, and exact
 * hash equality is unattainable on this tree anyway -- two builds from byte-identical source move
 * most chunk hashes (design.md D23's open question on build reproducibility).
 *
 * THE VALUE MUST STAY A PRIMITIVE STRING. esbuild only inlines primitive `define` values; an object
 * or an array is hoisted into a shared `var` so that every reference gets one identity, which
 * changes the emitted chunk even when the flag is unset. A `__THEME_MAPPINGS__: JSON.stringify([])`
 * shape would therefore never tree-shake away. The JSON is parsed in source, not here.
 */
const themeConfigOverride = process.env.THEME_CONFIG_OVERRIDE || "";

/*
 * VALIDATED HERE, AT BUILD TIME, BECAUSE THE PARSE HAPPENS IN THE BROWSER.
 *
 * config/ThemeConfiguration.js calls JSON.parse on the substituted literal at module evaluation.
 * A malformed value therefore costs nothing during the build and throws a SyntaxError inside the
 * theme chunk at runtime: a build that succeeded, deployed clean, and serves a blank page with
 * nothing useful logged. That is worth guarding because the value is a ~200-character JSON string
 * that xui-theming.spec.mjs's BUILD_REMEDIATION asks an operator to paste into a shell, so a
 * quoting slip is the expected failure rather than an exotic one -- and the symptom it produces,
 * the theming spec failing its precondition, points at the wrong remediation ("rebuild") when the
 * rebuild is what introduced it.
 *
 * The same argument the xui-assert-configured-modules plugin below makes about LOGIN_HELPER_CLASS,
 * whose substituted value it validates for the same reason. Shape and not only syntax: the two keys
 * ThemeConfiguration.js reads are the two checked here, because an override that parses cleanly but
 * carries `mapping` for `mappings` is silently ignored rather than rejected, and silence is the one
 * outcome this flag cannot afford -- the spec that depends on it would report a missing mapping as
 * a build that was never made.
 *
 * Unset skips all of it, so a plain `npm run build:production` never enters this block.
 */
if (themeConfigOverride) {
    const fail = (why) => new Error(
        `[vite.config.js] THEME_CONFIG_OVERRIDE ${why}.\n\n` +
        "It is merged into config/ThemeConfiguration.js at build time and must be a JSON object " +
        "with an optional `themes` object and an optional `mappings` array. See the " +
        "BUILD_REMEDIATION message in OpenAM/e2e/xui/xui-theming.spec.mjs for the exact shape " +
        `the theming spec expects.\n\nGot: ${themeConfigOverride}`);

    const isPlainObject = (value) =>
        value !== null && typeof value === "object" && !Array.isArray(value);

    let parsed;

    try {
        parsed = JSON.parse(themeConfigOverride);
    } catch (e) {
        throw fail(`is not valid JSON (${e.message})`);
    }

    if (!isPlainObject(parsed)) {
        throw fail("is not a JSON object");
    }

    if ("themes" in parsed && !isPlainObject(parsed.themes)) {
        throw fail("has a `themes` key that is not an object");
    }

    if ("mappings" in parsed && !Array.isArray(parsed.mappings)) {
        throw fail("has a `mappings` key that is not an array");
    }
}

/*
 * ==== 5.1 -- WHICH VITE RUNS. PINNED, AND MADE TO FAIL LOUDLY WHEN IT IS NOT ====
 *
 * SETTLED IN 5.1 because it is the first task in group 5 and so the first one to build anything.
 * This module builds against ITS OWN vite: the copy package.json declares ("vite": "^5.4.21")
 * and the tracked package-lock.json pins. Measured at the time of the decision, not recalled:
 *
 *   require.resolve("vite")                 openam-ui-ria/node_modules/vite/index.cjs
 *   require("vite/package.json").version    5.4.21  (rollup 4.62.5)
 *   OpenAM/openam-ui/node_modules/vite      8.1.0   (rolldown ~1.1.2)  <-- ONE DIRECTORY UP
 *
 * The parent copy is not a second opinion, it is an accident. OpenAM/openam-ui/package.json does
 * not exist and has never been tracked -- `git ls-files openam-ui/package.json` returns nothing,
 * only its .gitignore is tracked -- yet that tree's node_modules/.package-lock.json names a
 * phantom "openam-ui-workspace". Nothing in the repository regenerates it, so a fresh clone plus
 * `npm install` in this module yields 5.4.21 and nothing else. Building against 8.1.0 would mean
 * building against a tree neither CI nor a new checkout has.
 *
 * WHY THIS IS WORTH AN ASSERTION RATHER THAN A COMMENT. The two engines are not interchangeable
 * for this file. vite 5 bundles with Rollup and needs @rollup/plugin-commonjs to make the
 * vendored UMD lodash usable; vite 8 bundles with rolldown, which has native CJS/UMD interop and
 * IGNORES commonjsOptions entirely -- measured in the build.commonjsOptions comment below, where
 * one and the same alias fails under one engine and works under the other. Group 6 is built on
 * import.meta.glob, which is the next place the two will diverge. An engine that can change
 * underfoot without saying so is the worst shape this defect can have, so the check below turns
 * it into a startup failure instead.
 *
 * THE OTHER CONSUMER OF THIS CONFIG WAS CHECKED, so the guard does not ambush it: vitest 2.1.9
 * (`npm run test:unit`) resolves the same openam-ui-ria/node_modules/vite 5.4.21, and so passes
 * the check rather than tripping over it. The throw is deliberately hard rather than a warning
 * -- this module is built by frontend-maven-plugin, where a warning in the log is invisible, and
 * the failure it guards against is a build that goes GREEN while emitting something subtly
 * different, which is the exact shape NOTES-vite-build.md section 3 exists to warn about.
 *
 * To move the pin deliberately, change package.json and EXPECTED_VITE_MAJOR together. Do not
 * delete the check.
 */
const EXPECTED_VITE_MAJOR = 5;
const resolvedViteVersion = createRequire(import.meta.url)("vite/package.json").version;
if (parseInt(resolvedViteVersion, 10) !== EXPECTED_VITE_MAJOR) {
    throw new Error(
        `vite ${resolvedViteVersion} resolved, but this config is pinned to vite ` +
        `${EXPECTED_VITE_MAJOR}.x (Rollup). Vite 8 bundles with rolldown, which ignores the ` +
        `commonjsOptions this file depends on. Run npm install inside openam-ui-ria rather than ` +
        `building against OpenAM/openam-ui/node_modules/vite, or move the pin deliberately by ` +
        `changing package.json and EXPECTED_VITE_MAJOR together.`);
}

/*
 * Absolute paths for resolve.alias replacements (task 4.3). Every replacement in the alias table
 * below has to resolve in ONE HOP -- see the alias block for why -- and a bare AMD id such as
 * org/forgerock/openam/ui/common/util/ThemeManager resolves against nothing under Vite: there is
 * no equivalent of RequireJS's baseUrl. fileURLToPath(new URL(...)) is Vite's own documented
 * idiom and works whether the config is loaded as ESM or bundled to CJS (package.json declares no
 * "type", so it is bundled).
 */
const fromSrc = (id) => fileURLToPath(new URL(`./src/main/js/${id}`, import.meta.url));

/*
 * TASK 5.2. The same thing for a file inside an npm package. Used only where a shim in
 * src/main/js/shims/ has to reach the REAL library whose AMD id is aliased to that shim -- see
 * the PREFIX CAPTURE paragraph in the 5.2 alias block for why those four cannot simply be
 * written as bare subpath strings inside the shim.
 *
 * It resolves eagerly, at config load, so a package that is declared but not installed fails
 * with a clear MODULE_NOT_FOUND naming the specifier, rather than as a Rollup "unresolved
 * import" warning that only becomes a 404 at runtime.
 */
const requireFromConfig = createRequire(import.meta.url);
const fromPkg = (specifier) => requireFromConfig.resolve(specifier);

/*
 * TASK 5.4 (batch B0). A PATH inside an installed package -- a directory OR a file -- as an
 * absolute path, for D19's two package prefix aliases and the seven commons config/** leaves.
 *
 * The DIRECTORY case cannot go through fromPkg. require.resolve() honours the package's "exports"
 * map, and both commons packages expose only "./esm/*", "./www/*" and "./package.json": no subpath
 * pattern there resolves to a directory, and require.resolve() of one fails MODULE_NOT_FOUND.
 *
 * The FILE case could go through fromPkg -- "./esm/*" does cover esm/config/**.js, and fromPkg
 * would additionally survive a hoisted install, which this helper cannot. It deliberately does
 * not, so that all nine entries fail the same way, naming the reinstall below. Under a hoist the
 * two directory entries throw regardless, so routing seven of the nine around this helper would
 * buy no real resilience and would cost a second spelling for B2-B11 to choose between.
 * NOTES-amd-to-esm.md 3c
 * built both replacement forms -- package specifier and absolute filesystem path -- and got the
 * identical 560-module graph from each, then preferred this one, because the package-specifier
 * form only works by way of Vite retrying the failed lookup with resolve.extensions to supply the
 * ".js" that an exports subpath pattern never appends. That retry is not part of the exports
 * contract; this form does not need it.
 *
 * It asserts rather than returning a bad path, because the failure it prevents is unreadable: a
 * hoisted or absent install leaves the prefix pointing at a directory that is not there, and every
 * bare id underneath it goes unresolved at once. @vitejs/plugin-react rethrows UNRESOLVED_IMPORT
 * (NOTES-amd-to-esm.md 3c), so that arrives as a build failure rather than a warning -- but as
 * dozens of them, naming modules rather than naming this line.
 */
const fromPkgPath = (id) => {
    const resolved = fileURLToPath(new URL(`./node_modules/${id}`, import.meta.url));
    if (!fs.existsSync(resolved)) {
        throw new Error(
            `[vite.config] resolve.alias needs the path ${resolved}, which does not exist.\n` +
            "@openidentityplatform/ui-commons and ui-user are installed OUT OF BAND from the Maven " +
            "tarballs (task 3.7) and appear in NEITHER dependency block of package.json, so a plain " +
            "`npm ci` does not create them, and neither does `npm install`. Restore them with:\n" +
            "  npm install target/npm/ui-commons.tgz target/npm/ui-user.tgz --no-save --legacy-peer-deps"
        );
    }
    return resolved;
};

/*
 * ==== 4.4 -- STATIC ASSETS: THE COMPOSITION STEP GRUNT USED TO DO ====
 *
 * READ NOTES-static-assets.md IN THIS DIRECTORY BEFORE CHANGING ANYTHING BELOW. It has the
 * per-source provenance of all 719 composed files, the 7 path collisions and their winners, and
 * the costing behind every option not taken here.
 *
 * The shipped tree is NOT produced by one directory being copied. Grunt built it in two passes:
 *
 *   1. copy:compose   -- eight source directories copied over each other into target/XUI,
 *                        IN ORDER, last one wins (Gruntfile.js:57-68, 135-156).
 *   2. copy:compiled  -- the subset of that tree matching `nonCompiledFiles` copied on into
 *                        target/compiled (Gruntfile.js:83-95, 160-170).
 *
 * Vite reproduces neither on its own. themes/, templates/, partials/ and locales/ are fetched by
 * path at runtime -- ui-customization's "Override of templates and partials by a theme" is what
 * requires that -- so they never enter the module graph, and no rollup output option can see
 * them. This plugin replays both passes in writeBundle.
 *
 * WHY A PLUGIN AND NOT publicDir. publicDir is exactly the right SEMANTICS -- verbatim,
 * unhashed, no graph -- but it is ONE directory, and these assets fan in from four places with a
 * defined override order (see the collisions table below). Using it would need a pre-staging step
 * that composes them first, i.e. this code, plus a second entry point that `vite build` alone
 * does not run. The other options and their costs are in NOTES-static-assets.md section 2.
 *
 * WHY writeBundle AND NOT buildStart. build.emptyOutDir is true; it wipes outDir when the bundle
 * starts. Anything written in buildStart is erased. This is an ordering constraint, not a config
 * choice.
 */

/*
 * Gruntfile.js:57-68, in order. THE ORDER IS THE CONTRACT for everything except libs/: the last
 * source to supply a path wins. TASK 4.7 CHANGED THIS COUNT. Before it, seven paths were supplied
 * twice; two of those seven were libs/ collisions against the commons.ui.libs copies in
 * target/dependencies, and retiring that channel removed both --
 *
 *   libs/form2js-2.0-769718a.js   GONE. Used to be target/dependencies losing to
 *                                 dependencies-expanded: same library, DIFFERENT BUILD, identical
 *                                 file counts either way. Task 3.7 found it, and it is why
 *                                 acceptance is per-file md5 against PHASE1-TREE.md and not a
 *                                 file count. 4.7 vendored the pinned build to
 *                                 src/main/js/libs/ and deleted both suppliers, so the file now
 *                                 has exactly one source and the CDN drift channel behind it is
 *                                 closed. See NOTES-libs-retire.md section 13, decision 2.
 *   libs/lodash-3.10.1-min.js     GONE. 4.3 vendored lodash into src/main/js/libs/, where it beat
 *                                 the commons.ui.libs copy in target/dependencies; 4.7 retired
 *                                 that supplier, so the vendored file now stands alone. 8.3 still
 *                                 replaces it.
 *
 * FIVE remain, and libs/ is no longer among them -- copyLibraries now THROWS on a duplicate
 * rather than resolving one, because after 4.7 a second supplier means a stale target/ far more
 * often than it means a deliberate override. Of the five, four are AM overriding a commons
 * template. The fifth is the one non-obvious survivor:
 *
 *   locales/en/translation.json   ui-user/www (12,415 B) loses to src/main/resources (67,685 B).
 *                                 Reverse this order and translation coverage silently drops by
 *                                 55 kB with no build error.
 *
 * NOTES-static-assets.md section 1 lists the original seven. Cross-reference with care:
 * NOTES-npm-commons.md section 4 also says "five AM-over-commons overrides", but its five are the
 * four templates plus locales/en/translation.json, which is accounted for separately above. The
 * two fives are different sets, and neither is the five that survives 4.7.
 *
 * The two amd/ directories contribute ZERO non-JavaScript files -- they are 79 .js and nothing
 * else -- so they never win anything below. They are listed anyway because they are composition
 * sources, and because the presence check in buildStart has to cover them: a bare `npm install`
 * prunes both packages (pom.xml:219 installs them with --no-save), and a pruned node_modules
 * otherwise yields an exit-0 build that has silently dropped 53 files.
 */
const COMPOSITION_SOURCES = [
    /*
     * TASK 4.7. Staged from node_modules by stageNpmLibraries below, NOT unpacked by Maven. This
     * replaces the bulk of what target/dependencies used to carry: the commons.ui.libs
     * dependencySet blocks in dir.xml are gone, so the 42 libs/ and 12 css/ files they placed now
     * arrive from declared npm dependencies instead. It is FIRST where target/dependencies used
     * to be, so the non-libs/ composition order is unchanged. For libs/ specifically, "first" no
     * longer means "overridable": copyLibraries throws on a duplicate rather than letting a later
     * source win, so nothing after this may quietly replace an npm-staged library.
     */
    "target/npm-libs",
    /*
     * TASK 4.8 REMOVED target/dependencies FROM THIS LIST. It was composition source #1 through
     * the whole Grunt era and held 66 files; 4.7 cut it to 6 and 4.8 took the last of them --
     * CodeMirror -- to npm, so the maven-dependency-plugin unpack, the dir.xml descriptor and the
     * prepare-working-dir execution that produced the directory are all gone from pom.xml. There
     * is no Maven-unpacked composition source left. Do not re-add the entry to "be safe": an
     * empty or absent composition source is the silent-drop shape this build is built to refuse,
     * and assertSourcesPresent would now fail the build on a directory nothing creates.
     */
    "node_modules/@openidentityplatform/ui-commons/amd",
    "node_modules/@openidentityplatform/ui-commons/www",
    "node_modules/@openidentityplatform/ui-user/amd",
    "node_modules/@openidentityplatform/ui-user/www",
    "src/main/js",
    "src/main/resources"
];

/*
 * ==== 4.7 -- THE RUNTIME LIBRARIES, FROM npm INSTEAD OF commons.ui.libs ====
 *
 * READ NOTES-libs-retire.md IN THIS DIRECTORY BEFORE CHANGING ANYTHING BELOW. It carries the
 * per-file destination table, the provenance of every digest named here, and the acceptance
 * procedure.
 *
 * WHAT THIS REPLACES. Until 4.7 every file in the shipped libs/ tree arrived as a hand-published
 * Maven artifact under org.openidentityplatform.commons.ui.libs -- ~58 of them, fetched from a
 * dozen CDNs by maven-external-dependency-plugin, published to no repository, and reachable only
 * because a past build had already downloaded them into ~/.m2. ui-build-and-packaging's "Runtime
 * libraries are managed package dependencies" requires the opposite: declared dependencies, from
 * the public registry, pinned in a committed lockfile and visible to `npm audit`. The map below
 * is that channel.
 *
 * WHY A COPY AND NOT AN import. Route (a) -- letting the bundler resolve these -- is NOT
 * available yet and will not be until group 5. main.js is still AMD, its 40 vendor bindings are
 * require.config.paths entries naming libs/<file> by literal path, and index.html plus six
 * FreeMarker templates in openam-oauth2 load two of these files with a literal <script src>.
 * So 4.7 changes only WHO SUPPLIES THE BYTES, never where they land. Every path below is exactly
 * the path that shipped before.
 *
 * THE FILENAMES ARE NOT COSMETIC. The keys are the deployed names, version suffix and all, and
 * they must not be "tidied": main.js:38-79 binds them, and three of them lie -- xdate-0.8-min.js
 * is not minified, bootstrap-datetimepicker-4.14.30-min.js is vendored rather than npm-built, and
 * handlebars-4.7.7-min.js was really 4.7.6 (it is one of the six 4.7 drops; see the notes).
 *
 * evidence: MD5 = the npm file is byte-identical to the retired Maven artifact, so this row
 * reproduces PHASE1-TREE.md exactly. VER = same version, but npm publishes no byte-equivalent
 * build, so the digest changes and the change is expected. bump = that version was never
 * published to npm at all and the nearest published one is used.
 */
const NPM_LIBRARY_STAGE = "target/npm-libs";

const NPM_LIBRARY_FILES = {
    // ---- libs/ : 28 files, all bound by main.js:38-79 -------------------------------------
    // (the four libs/codemirror files below are a separate case -- see the block above them)
    "libs/backbone-1.1.2-min.js": "backbone/backbone-min.js",                              // MD5
    "libs/backbone.paginator.min-2.0.2-min.js":
        "backbone.paginator/lib/backbone.paginator.min.js",                                // MD5
    "libs/backbone-relational-0.9.0-min.js": "backbone-relational/backbone-relational.js", // VER
    "libs/backgrid-filter.min-0.3.7-min.js": "backgrid-filter/backgrid-filter.min.js",     // MD5
    "libs/backgrid.min-0.3.5-min.js": "backgrid/lib/backgrid.min.js",                      // VER
    "libs/backgrid-select-all-0.3.5-min.js":
        "backgrid-select-all/backgrid-select-all.min.js",                                  // VER
    "libs/bootstrap-3.3.5-custom.js": "bootstrap/dist/js/bootstrap.js",                    // MD5
    "libs/bootstrap-clockpicker-0.0.7-min.js":
        "clockpicker/dist/bootstrap-clockpicker.min.js",                                   // VER
    "libs/bootstrap-dialog-1.34.4-min.js":
        "bootstrap3-dialog/dist/js/bootstrap-dialog.min.js",                               // bump
    "libs/classnames-2.2.5.js": "classnames/index.js",                                     // MD5
    "libs/handlebars-4.7.7.js": "handlebars/dist/handlebars.js",                           // MD5
    "libs/i18next-1.7.3-min.js": "i18next/lib/dep/i18next.min.js",                         // MD5
    "libs/jquery-3.7.1-min.js": "jquery/dist/jquery.min.js",                               // MD5
    "libs/jquery-sortable-0.9.13.js": "jquery-sortable/source/js/jquery-sortable.js",      // VER
    "libs/microplugin-0.0.3.js": "microplugin/src/microplugin.js",                         // MD5
    "libs/moment-2.28.0-min.js": "moment/min/moment.min.js",                               // MD5
    "libs/qrcode-1.4.4-min.js": "qrcode-generator/qrcode.js",                              // VER
    "libs/react-15.2.1-min.js": "react/dist/react.min.js",                                 // MD5
    "libs/react-bootstrap-0.30.1-min.js":
        "react-bootstrap/dist/react-bootstrap.min.js",                                     // MD5
    /*
     * 709 bytes, and it contains no ReactDOM: it is a UMD shim returning
     * React.__SECRET_DOM_DO_NOT_USE_OR_YOU_WILL_BE_FIRED, and the implementation lives inside
     * react-15.2.1-min.js. That is genuinely what React 15 published. react and react-dom
     * therefore move as a VERSION-LOCKED PAIR: take react-dom from a newer major while react
     * stays at 15 and ReactDOM is undefined at runtime, with no build error.
     */
    "libs/react-dom-15.2.1-min.js": "react-dom/dist/react-dom.min.js",                     // MD5
    "libs/react-input-autosize-1.1.0-min.js":
        "react-input-autosize/dist/react-input-autosize.min.js",                           // MD5
    "libs/react-select-1.0.0-rc.2-min.js": "react-select/dist/react-select.min.js",        // MD5
    "libs/redux-3.5.2-min.js": "redux/dist/redux.min.js",                                  // MD5
    /*
     * selectize.min.js is the NON-standalone build and is what main.js:75 binds. The retired
     * artifact set carried it twice, as selectize-0.12.1-min.js and
     * selectize-non-standalone-0.12.1-min.js, byte-identical under two artifactIds; only this one
     * was ever bound and the duplicate is one of the six 4.7 drops. npm's actual standalone build
     * (dist/js/standalone/selectize.min.js) is a third, different file -- do not reach for it.
     */
    "libs/selectize-non-standalone-0.12.1-min.js": "selectize/dist/js/selectize.min.js",   // MD5
    "libs/sifter-0.4.1-min.js": "sifter/sifter.min.js",                                    // MD5
    "libs/spin-2.0.1-min.js": "spin.js/spin.js",                                           // VER
    "libs/xdate-0.8-min.js": "xdate/src/xdate.js",                                         // MD5

    /*
     * ---- libs/codemirror/ : 4 files, and they are NOT bound by main.js ----
     *
     * TASK 4.8 DECIDED THIS, and it is the entry that finally empties target/dependencies. Until
     * 4.8 these four arrived as org.openidentityplatform.commons.ui.libs:CodeMirror:zip:4.10 --
     * the last hand-published Maven artifact in the build, fetched from a GitHub archive URL by
     * maven-external-dependency-plugin, published to no repository, and invisible to `npm audit`.
     * That is precisely what ui-build-and-packaging's "Runtime libraries are managed package
     * dependencies" forbids, and with it went the CodeMirror dependency, the unpack-codemirror
     * execution, dir.xml's six fileSets, the prepare-working-dir execution that produced
     * target/dependencies, and the whole maven-external-dependency-plugin -- including
     * clean-external, the goal that made `mvn clean` here unrecoverable.
     *
     * ZERO DIGEST DELTA, measured rather than assumed. All four are md5-identical between npm
     * codemirror@4.10.0 and PHASE1-TREE.md:251-254, so the shipped bytes do not move:
     *   lib/codemirror.js               1c570cd14e3ec3db7726f86bfbabf2d3
     *   mode/groovy/groovy.js           4f97d9e79258b2a380fcda2daf85afd6
     *   mode/javascript/javascript.js   921ad047a5a73a57f2ccf5d526faf01c
     *   addon/display/fullscreen.js     fb86184c4fb36398188f2199fd28f167
     * Maven `4.10` and npm `4.10.0` are the same release. LIBS-INVENTORY.md row 22 had already
     * recorded the first of the four; 4.8 measured the other three.
     *
     * THE DESTINATION PATHS ARE THE CONTRACT, not a convention. EditScriptView.js:21,35,36,37 --
     * the only consumer in the tree -- names all four by LITERAL AMD path
     * (`libs/codemirror/lib/codemirror`, `mode/groovy/groovy`, `mode/javascript/javascript`,
     * `addon/display/fullscreen`), so they never pass through main.js's require.config.paths and
     * no alias or registry entry can redirect them. The keys below reproduce those paths exactly;
     * that is why the source file needed no edit. A rename here is a 404 in the admin script
     * editor and nothing else in the build will say so.
     *
     * AND NOTHING IN THE E2E SUITE WOULD CATCH IT. No spec under OpenAM/e2e touches the script
     * editor -- the regression net covers login, authorize, device, realms, services, profile,
     * theming, cache-busting, httponly, operator-module, auth-chains, auth-modules, oauth2 and
     * saml, and none of them loads CodeMirror. The digests above are the whole verification.
     *
     * codemirror@4.10.0 carries a known moderate advisory, GHSA-4gw3-8f77-f72c (ReDoS, affects
     * <5.58.2). The same bytes shipped before this task; what changed is that `npm audit` can now
     * see them, which is the point of the requirement. Upgrading past it is a behaviour change to
     * the script editor with no spec behind it, so it is not 4.8's -- it belongs with the other
     * advisories NOTES-libs-retire.md leaves open.
     */
    /*
     * THE FOUR ROWS THAT WERE HERE ARE GONE -- 5.4/B7, under D23. EditScriptView.js is ESM now and
     * imports all four through the `libs/codemirror` prefix alias, so they are bundled rather than
     * staged and shipping them too would be duplicate bytes. That is the -4 delta against
     * PHASE1-TREE.md:251-254, taken deliberately.
     *
     * Everything 4.8 established above still holds and is why this was safe: same package, same
     * release (Maven 4.10 == npm 4.10.0), and all four md5-identical to the shipped bytes. What
     * changed is only how they reach the browser.
     */

    // ---- css/ : 8 stylesheets -----------------------------------------------------------------
    // The only one that ships verbatim; the rest are LESS inputs compiled into structure.css
    // and styles-admin.css. NON_COMPILED_PATHS above names this one file.
    "css/bootstrap-3.3.5-custom.css": "bootstrap/dist/css/bootstrap.css",                  // MD5
    "css/bootstrap-clockpicker-0.0.7-min.css":
        "clockpicker/dist/bootstrap-clockpicker.min.css",                                  // VER
    "css/bootstrap-dialog-1.34.4-min.css":
        "bootstrap3-dialog/dist/css/bootstrap-dialog.min.css",                             // bump
    /*
     * TASK 4.8, the other half of the CodeMirror move, and these two are NOT dead weight even
     * though no `css/codemirror/` directory has ever appeared in the shipped tree
     * (PHASE1-TREE.md:205-214 lists the whole of css/ and it is not there). They are LESS INPUTS:
     * css/styles-admin.less:31-32 `@import (less)` both of them, which is why styles-admin.css
     * carries CodeMirror's entire layout rule set -- .CodeMirror-scroll, -gutters, -cursors,
     * -fullscreen and the rest. The commons `structure/codemirror.less` route
     * (ui-commons css/common/structure.less:107) is a different and much smaller thing: it
     * supplies only the .CodeMirror border, the linenumber colour and the .cm-s-forgerock token
     * palette, into structure.css. Drop these two and LESS errors on a missing @import, so the
     * build fails outright rather than shipping an unstyled editor -- but the reason to keep them
     * is that the admin console needs the rules, not that the failure is loud.
     * Both byte-identical to the retired Maven artifact:
     *   lib/codemirror.css              1c26f7d1f30cbcc58982178f588906d5
     *   addon/display/fullscreen.css    1a278e72b51528270f8ce9ec991929a1
     */
    "css/codemirror/lib/codemirror.css": "codemirror/lib/codemirror.css",                  // MD5
    "css/codemirror/addon/display/fullscreen.css":
        "codemirror/addon/display/fullscreen.css",                                         // MD5
    "css/react-select-1.0.0-rc.2-min.css": "react-select/dist/react-select.min.css",       // MD5
    "css/selectize-0.12.1-bootstrap3.css": "selectize/dist/css/selectize.bootstrap3.css",  // MD5
    "css/titatoggle-1.2.6-min.css": "titatoggle/dist/titatoggle-dist-min.css",             // bump

    /*
     * ---- css/fontawesome/ : 8 files, and they are BUILD-BLOCKING, not decorative ----
     *
     * css/structure.less:23-24 and css/styles-admin.less:25-26 both @import font-awesome.min.css
     * AND less/variables.less. LESS errors on a missing @import, so losing either file fails
     * renderStylesheets outright and two of the ten shipped css/ files never get written.
     *
     * All 8 verified byte-identical between the npm tarball and the GitHub source archive
     * dir.xml used to unpack, so this move costs zero digest delta. That closes the one thing
     * NOTES-libs-retire.md section 12 could not determine.
     *
     * THE CASE TRAP THAT DIES HERE. dir.xml's fileSet read `Font-Awesome-${font-awesome.version}`
     * with a capital F and A, because the artifact was github.com/FortAwesome/Font-Awesome's
     * archive and it roots at Font-Awesome-4.5.0/. On a case-sensitive filesystem a lowercase
     * spelling silently matched nothing; on macOS it resolved anyway, so the error was invisible
     * locally. The npm tarball roots at package/ and installs to an all-lowercase
     * node_modules/font-awesome, so the trap is gone -- but the class of bug transfers to the
     * literal paths below, which is why they are written out rather than globbed.
     *
     * fontawesome-webfont.ttf is staged but NOT shipped: there is no `**\/*.ttf` in
     * NON_COMPILED_EXTENSIONS. That is a pre-existing Grunt omission reproduced deliberately --
     * see the note on that constant. The compiled CSS still references it. Do not "fix" it here.
     */
    "css/fontawesome/css/font-awesome.min.css": "font-awesome/css/font-awesome.min.css",   // MD5
    "css/fontawesome/less/variables.less": "font-awesome/less/variables.less",             // MD5
    "css/fontawesome/fonts/FontAwesome.otf": "font-awesome/fonts/FontAwesome.otf",         // MD5
    "css/fontawesome/fonts/fontawesome-webfont.eot":
        "font-awesome/fonts/fontawesome-webfont.eot",                                      // MD5
    "css/fontawesome/fonts/fontawesome-webfont.svg":
        "font-awesome/fonts/fontawesome-webfont.svg",                                      // MD5
    "css/fontawesome/fonts/fontawesome-webfont.ttf":
        "font-awesome/fonts/fontawesome-webfont.ttf",                                      // MD5
    "css/fontawesome/fonts/fontawesome-webfont.woff":
        "font-awesome/fonts/fontawesome-webfont.woff",                                     // MD5
    "css/fontawesome/fonts/fontawesome-webfont.woff2":
        "font-awesome/fonts/fontawesome-webfont.woff2"                                     // MD5
};

/*
 * The npm-installed sources are the only ones carrying a root package.json, the CommonJS marker,
 * which is not part of the UI and which `**\/*.json` below would otherwise ship to the tree root.
 * Grunt drops it at copy:compose and scopes the exclusion to these directories deliberately, so
 * that a future source legitimately shipping a root package.json does not lose it silently.
 * Only the two amd/ directories have one today; all four are listed to match Gruntfile.js:148-153.
 */
const NPM_PACKAGE_SOURCES = new Set([
    "node_modules/@openidentityplatform/ui-commons/amd",
    "node_modules/@openidentityplatform/ui-commons/www",
    "node_modules/@openidentityplatform/ui-user/amd",
    "node_modules/@openidentityplatform/ui-user/www"
]);

/*
 * Gruntfile.js:83-95, `nonCompiledFiles`, ported verbatim. This list -- not a directory list --
 * is what decides the shipped static set, and it does not decompose into "the four directories
 * task 4.4 names": it also ships favicon.ico, oauthReturn.html, timezones.json, images/, five
 * Font Awesome fonts, css/bootstrap-3.3.5-custom.css and css/common/structure/config.json.
 * PHASE1-TREE.md:53 is the only surviving record of the eight root files; NOTES-static-assets.md
 * section 4 says what each is for and what breaks without it.
 *
 * DELIBERATELY REPRODUCED, NOT FIXED: there is no `**\/*.ttf` here, so
 * css/fontawesome/fonts/fontawesome-webfont.ttf is NOT shipped even though the compiled CSS
 * references it and the file is staged into target/npm-libs. That is a pre-existing Grunt
 * omission (harmless in practice -- woff2/woff cover every current browser). Adding it here would
 * be a real fix, but it would also put a permanent +1 delta against PHASE1-TREE.md that tasks
 * 4.6, 4.7 and 4.8 each have to carry forward and re-explain. Fix it as its own change, against a
 * clean diff.
 */
const NON_COMPILED_EXTENSIONS = new Set([
    ".html", ".ico", ".json", ".png", ".eot", ".svg", ".woff", ".woff2", ".otf"
]);
const NON_COMPILED_PATHS = new Set(["css/bootstrap-3.3.5-custom.css"]);
const NON_COMPILED_PREFIX = "themes/";

/*
 * Gruntfile.js:164-167. main.js is emitted by the bundler, index.html by the version-stamping
 * step -- and index.html DOES match `**\/*.html`, so without this exclusion the unfiltered
 * src/main/resources copy would overwrite the stamped one with a literal `${version}`.
 *
 * Task 4.5 has landed and index.html is no longer an absence: stampIndexHtml below emits it.
 * This exclusion is what keeps the two from fighting, and the ORDER in writeBundle is the other
 * half -- composeStaticAssets runs first, stampIndexHtml second. Drop `index.html` from this set
 * and the verbatim copy still loses the race, but only by accident of ordering; keep both.
 */
const NOT_COPIED = new Set(["main.js", "index.html"]);

/*
 * Reproduces the eleven `nonCompiledFiles` globs. Written out rather than taken through minimatch
 * so the interpretation of each pattern is visible and reviewable: `**\/*.<ext>` is any file with
 * that extension at any depth INCLUDING the root, and `themes/**\/*.*` is any file below themes/
 * whose basename carries a dot. Case-sensitive, as minimatch is by default.
 *
 * The dotfile rule below is the one place a naive port diverges, and it was measured rather than
 * assumed: minimatch and glob exclude dotfiles from a wildcard unless `dot: true`, so Grunt drops
 * .eslintrc.json and themes/.DS_Store while path.extname() and a plain directory walk would ship
 * both. No such file exists in any of the seven sources today, but themes/ is the tree operators
 * edit in place and this module's own root already carries a .DS_Store, so the divergence is one
 * stray file away from putting an unexplained "extra" in front of task 4.8's manifest diff.
 *
 * The set this produces is checked against PHASE1-TREE.md, which is the actual acceptance test.
 */
const shipsVerbatim = (relPath) => {
    if (NOT_COPIED.has(relPath)) { return false; }
    if (path.basename(relPath).startsWith(".")) { return false; }
    if (NON_COMPILED_PATHS.has(relPath)) { return true; }
    if (relPath.startsWith(NON_COMPILED_PREFIX) && path.basename(relPath).includes(".")) { return true; }
    return NON_COMPILED_EXTENSIONS.has(path.extname(relPath));
};

/*
 * Gruntfile.js:222-244, `less:compile`.
 *
 * NO GROUP-4 TASK NAMES THESE THREE FILES. They are here by decision of the change owner, taken
 * on the finding in NOTES-static-assets.md section 3: nobody else in the group can take them
 * (4.5 is index.html, 4.6 the zip, 4.7 the Maven unpacks, 4.8 CodeMirror), and the failure is
 * silent -- omit them and `vite build` exits 0 while every page in the UI loads unstyled, because
 * all three stylesheet lists 404 at once. ui-build-and-packaging's "Deployed directory layout"
 * names stylesheets alongside templates and partials in the same sentence, so the stable-path
 * requirement covers them whether or not a task text does.
 *
 * Who names each output -- one of the three is invisible from the theme config:
 *   css/structure.css      ThemeConfiguration.js:23 (default) AND :67 (fr-dark-theme). The dark
 *                          theme replaces bootstrap and theme but SHARES structure.
 *   css/theme.css          ThemeConfiguration.js:23 (default only)
 *   css/styles-admin.css   Constants.js:60 DEFAULT_STYLESHEETS -- the admin console. Referenced
 *                          by NEITHER theme, and the largest of the three.
 */
const LESS_ENTRIES = [
    { src: "css/structure.less", dest: "css/structure.css" },
    { src: "css/theme.less", dest: "css/theme.css" },
    { src: "css/styles-admin.less", dest: "css/styles-admin.css" }
];

/*
 * Staging directory for the LESS compile. NOT target/XUI: that is the Grunt composition tree and
 * the second acceptance oracle for tasks 4.4-4.8 (NOTES-static-assets.md section 0), so nothing
 * here may write into it.
 */
const LESS_STAGE = "target/css-composed";

/*
 * Recursive file list, POSIX-separated and relative to `base`. Dirent.isFile()/isDirectory() are
 * lstat-based, so a symlink is neither and is skipped, where glob would have followed it. None
 * exists in any composition source today; noted because it is a silent difference, and because it
 * is also why this cannot loop.
 */
const walk = (dir, base = dir) => {
    const found = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            found.push(...walk(full, base));
        } else if (entry.isFile()) {
            found.push(path.relative(base, full).split(path.sep).join("/"));
        }
    }
    return found;
};

const copyFile = (from, to) => {
    fs.mkdirSync(path.dirname(to), { recursive: true });
    fs.copyFileSync(from, to);
};

/*
 * Pass 1 and 2 fused: walk the sources in order and copy only what `nonCompiledFiles` selects,
 * straight into outDir. Composing the whole 719-file tree first and filtering afterwards would
 * be a closer transcription of Grunt, but 384 of those files are JavaScript the bundler owns,
 * and staging them would put a second, stale copy of the module tree on disk next to Vite's.
 * The last-wins property is preserved exactly, because a later source's copyFileSync overwrites
 * an earlier one at the same path.
 */
/*
 * TASK 4.7. Stage the mapped node_modules files into target/npm-libs, which COMPOSITION_SOURCES
 * lists first. Runs in buildStart, BEFORE assertSourcesPresent, so that a pruned node_modules
 * fails on the named file below rather than on a missing composition directory two frames later.
 *
 * WHY A STAGING DIRECTORY AND NOT A DIRECT COPY INTO outDir. Ten of these files are not shipped
 * at all -- seven LESS/CSS inputs that stageLessSources has to see under a composed css/ tree
 * before renderStylesheets can resolve `@import "fontawesome/less/variables.less"` relative to
 * the entry, plus fontawesome/less/variables.less itself, the deliberately-omitted .ttf, and the
 * two CodeMirror stylesheets task 4.8 added. Copying them straight to outDir would ship ten files
 * that never shipped and still leave the LESS compile with nothing to import. Staging puts them
 * where both passes already look, and costs one directory.
 *
 * EVERY MISSING FILE IS FATAL, and that is the point. The failure this guards against is the one
 * the plan flags repeatedly: a source that quietly contributes nothing, an exit-0 build, and a
 * 404 in production. A package that changes its internal layout between versions -- which is
 * exactly what happened to bootstrap-dialog and titatoggle, both of which had to move version --
 * silently drops a runtime library otherwise.
 */
const stageNpmLibraries = (root) => {
    const stage = path.resolve(root, NPM_LIBRARY_STAGE);
    /*
     * Same guard as stageLessSources, for the same reason: NPM_LIBRARY_STAGE is a constant but
     * `root` is config.root, and this delete is recursive.
     */
    if (!stage.startsWith(root + path.sep)) {
        throw new Error(`Refusing to clear a library staging directory outside the project root: ${stage}`);
    }
    fs.rmSync(stage, { recursive: true, force: true });

    const missing = [];
    for (const [dest, source] of Object.entries(NPM_LIBRARY_FILES)) {
        const from = path.resolve(root, "node_modules", source);
        if (!fs.existsSync(from)) {
            missing.push(`  ${dest}  <-  node_modules/${source}`);
            continue;
        }
        copyFile(from, path.join(stage, dest));
    }
    if (missing.length > 0) {
        throw new Error(
            "Runtime libraries are missing from node_modules, so the build would ship an " +
            "incomplete libs/ tree:\n" + missing.join("\n") +
            "\n\nThese are declared dependencies in package.json (task 4.7 moved them off the " +
            "org.openidentityplatform.commons.ui.libs Maven artifacts). Run `npm install`. If a " +
            "path above is wrong rather than absent, the package changed its internal layout " +
            "between versions -- fix the map in NPM_LIBRARY_FILES, and see NOTES-libs-retire.md."
        );
    }
    return Object.keys(NPM_LIBRARY_FILES).length;
};

/*
 * TASK 4.7. THE ONE DRIFT CHANNEL VENDORING LEAVES OPEN.
 *
 * eonasdan-bootstrap-datetimepicker is a declared dependency that contributes ZERO bytes: the
 * package publishes only src/, no built js and no built css, so both shipped files are vendored
 * into source instead (NOTES-libs-retire.md section 13, decision 6). The dependency is kept
 * anyway so the library stays in the lockfile with a resolved version and an integrity hash, and
 * so `npm audit` can see it -- vendored bytes are invisible to both.
 *
 * That leaves the declared version and the vendored bytes free to drift apart with no build
 * signal: `ncu -u`, or anything else that bumps package.json, moves one and not the other, and
 * nothing downstream notices. Both vendored files carry an upstream `version : x.y.z` header, so
 * the check is a string compare, and it is worth the twelve lines because the failure it catches
 * is silent and the evidence is already in the files.
 *
 * This is deliberately NOT a general mechanism. It covers the one case where a vendored file has
 * a declared npm dependency behind it; the other ten vendored files have no npm publication at
 * all under any name, so there is nothing to compare them against. See src/main/js/libs/README.md
 * for the provenance of all twelve.
 */
const VENDORED_VERSION_CHECKS = [
    { file: "src/main/js/libs/bootstrap-datetimepicker-4.14.30-min.js", dependency: "eonasdan-bootstrap-datetimepicker" },
    { file: "src/main/resources/css/bootstrap-datetimepicker-4.14.30-min.css", dependency: "eonasdan-bootstrap-datetimepicker" }
];

const assertVendoredVersions = (root) => {
    const manifest = JSON.parse(fs.readFileSync(path.resolve(root, "package.json"), "utf8"));
    for (const { file, dependency } of VENDORED_VERSION_CHECKS) {
        const declared = (manifest.dependencies || {})[dependency];
        if (declared === undefined) {
            throw new Error(
                `${file} is vendored against the npm dependency ${dependency}, which package.json ` +
                "no longer declares. Either restore the dependency or drop this entry from " +
                "VENDORED_VERSION_CHECKS -- and record the provenance in " +
                "src/main/js/libs/README.md if the file is now standing alone."
            );
        }
        const header = fs.readFileSync(path.resolve(root, file), "utf8").slice(0, 512);
        const found = /version\s*:\s*([0-9][0-9A-Za-z.\-]*)/.exec(header);
        if (found === null) {
            throw new Error(`${file} no longer carries an upstream \`version :\` header, so it cannot be checked against ${dependency}.`);
        }
        if (found[1] !== declared) {
            throw new Error(
                `${file} carries upstream version ${found[1]}, but package.json pins ` +
                `${dependency} at ${declared}.\n\n` +
                "This package ships no built files, so the bytes AM serves are the vendored ones " +
                "and the dependency exists only to keep the library visible to the lockfile and " +
                "to `npm audit`. The two have drifted: re-vendor the built files from the pinned " +
                "version, or move the pin back. See NOTES-libs-retire.md section 13, decision 6."
            );
        }
    }
    return VENDORED_VERSION_CHECKS.length;
};

const composeStaticAssets = (root, outDir) => {
    const shipped = new Set();
    for (const source of COMPOSITION_SOURCES) {
        const from = path.resolve(root, source);
        for (const rel of walk(from)) {
            if (NPM_PACKAGE_SOURCES.has(source) && rel === "package.json") { continue; }
            if (!shipsVerbatim(rel)) { continue; }
            copyFile(path.join(from, rel), path.resolve(outDir, rel));
            shipped.add(rel);
        }
    }
    return shipped;
};

/*
 * TASK 4.7. Grunt shipped libs/ in two hops that had nothing to do with nonCompiledFiles:
 * copy:libraries took libs/**\/*.js out of the composition tree into target/transpiled
 * (Gruntfile.js:185-192, bypassing babel), then copy:transpiled carried target/transpiled on into
 * target/compiled (:172-183). shipsVerbatim above does NOT select .js, so without this step the
 * Vite tree has no libs/ at all -- which is exactly the state 4.7 inherited: target/compiled held
 * 273 files against PHASE1-TREE.md's 652, and all 50 libs/ files were among the missing.
 *
 * Same source order as composeStaticAssets, but NOT the same last-wins rule -- this walk refuses
 * a collision instead of resolving one. The two suppliers are disjoint, 32 + 12 = 44 distinct
 * paths and no overlap:
 *   target/npm-libs   32 files, from the npm dependencies mapped above -- 28 bound by main.js
 *                     plus the four libs/codemirror files TASK 4.8 moved off the Maven zip
 *   src/main/js       12 files, the vendored set (see NOTES-libs-retire.md section 3)
 * target/dependencies was the third supplier until 4.8 and is gone with the unpack that made it.
 * The two commons packages carry no libs/ at all and contribute nothing here; they are walked
 * anyway rather than special-cased, so that a future commons release shipping one is not
 * silently ignored.
 *
 * WHY THROW RATHER THAN LAST-WINS. maven-assembly-plugin did not clean its own output, and 4.7
 * made the dir.xml descriptor emit a strict SUBSET of what it used to: target/dependencies went
 * from 66 files to 6. So a target/ left over from a pre-4.7 build still holds the 60 retired
 * commons.ui.libs files, they sort after target/npm-libs in this list, and under last-wins they
 * would silently beat the npm channel -- shipping the retired Maven bytes, resurrecting the six
 * deliberately dropped files, exit 0, no warning. That is the plan's silent-drop hazard inverted
 * into a silent STALE-SHIP, and a file count does not see it: the count goes UP, to the number
 * the pre-4.7 tree had. It is not hypothetical; it is what the first 4.7 build did, 50 libs/
 * files instead of 44.
 *
 * 4.8 RETIRED THAT FAILURE MODE ENTIRELY, and the guard changes meaning rather than going away.
 * target/dependencies is no longer in COMPOSITION_SOURCES, so a stale one is not walked and
 * cannot collide; and stageNpmLibraries rmSyncs target/npm-libs at the top of every build, so a
 * stale one of those cannot exist either. A collision can therefore no longer be a leftover
 * directory, which is what the message below used to say it almost always was. The two ways it
 * can still fire are both real overlaps:
 *   - a new NPM_LIBRARY_FILES key colliding with a file vendored under src/main/js/libs
 *     (src/main/js/libs/README.md is the register of the twelve, and D20 the standing exception)
 *   - a future commons release starting to ship a libs/ tree of its own
 * Neither is fixed by deleting anything, which is why the message names the causes instead.
 *
 * The reason `mvn clean` used to be forbidden here died with the same task: clean-external went
 * when maven-external-dependency-plugin did, so there is no longer a goal in this build that
 * deletes an unpublished artifact from ~/.m2.
 *
 * The cost of this strictness is zero today because the suppliers are disjoint. If 8.3 ever needs
 * one source to override another in libs/, the override has to become explicit here rather than
 * implicit in the order of COMPOSITION_SOURCES.
 */
const copyLibraries = (root, outDir) => {
    const shipped = new Set();
    const suppliers = new Map();
    for (const source of COMPOSITION_SOURCES) {
        const from = path.resolve(root, source, "libs");
        if (!isDirectory(from)) { continue; }
        for (const rel of walk(from)) {
            if (path.extname(rel) !== ".js") { continue; }
            const shippedPath = path.posix.join("libs", rel);
            if (suppliers.has(shippedPath)) {
                throw new Error(
                    `Two composition sources supply ${shippedPath}:\n` +
                    `  ${suppliers.get(shippedPath)}\n  ${source}\n\n` +
                    "The libs/ suppliers are meant to be disjoint. Since task 4.8 this cannot be " +
                    "a stale directory -- target/dependencies is no longer a composition source " +
                    "and stageNpmLibraries clears target/npm-libs on every build -- so deleting " +
                    "something will not fix it. It is a real overlap, and there are two:\n" +
                    "  - a new NPM_LIBRARY_FILES key that collides with a file vendored under " +
                    "src/main/js/libs (see src/main/js/libs/README.md)\n" +
                    "  - a commons release that has started shipping a libs/ tree of its own\n\n" +
                    "Decide which supplier owns the path. If the collision is deliberate, make " +
                    "the override explicit in copyLibraries rather than relying on the order of " +
                    "COMPOSITION_SOURCES."
                );
            }
            suppliers.set(shippedPath, source);
            copyFile(path.join(from, rel), path.resolve(outDir, "libs", rel));
            shipped.add(shippedPath);
        }
    }
    return shipped;
};

/*
 * TASK 4.8. THE ONE LIBRARY CONTRACT NOTHING ELSE CHECKS.
 *
 * Almost every runtime library is reached through a require.config.paths entry in main.js, so a
 * broken supplier shows up as an unresolved AMD id with a name in it. CodeMirror is not: its four
 * files are named by LITERAL AMD PATH in one view, and the shipped path IS the identifier. Rename
 * an NPM_LIBRARY_FILES key -- or take a future codemirror version that moves mode/ or addon/ --
 * and the build still exits 0, ships 44 libraries, matches every count, and 404s the moment an
 * administrator opens a script. 4.8 moved that contract out of dir.xml's <outputDirectory>, where
 * Maven at least failed on a missing fileSet directory, into a JS object literal where nothing
 * did. This is what replaces it.
 *
 * NO TEST WOULD CATCH IT. There is no spec under OpenAM/e2e for the script editor -- the suite
 * covers login, authorize, device, realms, services, profile, theming, cache-busting, httponly,
 * operator-module, auth-chains, auth-modules, oauth2 and saml, and none of them loads CodeMirror.
 * The digest evidence in NPM_LIBRARY_FILES is a point-in-time measurement; this is the standing
 * check, and it is the only one.
 *
 * IT READS THE CONSUMER, IT DOES NOT RESTATE IT. The ids come out of the source file at build
 * time, so the check is bidirectional: renaming a map key fails, and so does renaming the id in
 * the view without the map following. A hardcoded copy of the four paths here would be a third
 * place to keep in step and would agree with itself while both other places drifted.
 *
 * THE CONSUMER LIST IS ONE FILE BECAUSE THE TREE HAS ONE. `grep -rn "libs/" --include=*.js
 * src/main/js` finds literal library ids in EditScriptView.js and nowhere else. If a second view
 * ever takes one, add it here; the guard is per-file so the failure names which one.
 *
 * IT THROWS WHEN IT FINDS NOTHING, and that is deliberate rather than defensive. The only way a
 * listed consumer stops naming these is task 5.1 converting it to ESM, at which point literal AMD
 * paths stop being how it loads them at all -- and that conversion has to decide what replaces
 * this, not discover later that the guard quietly stopped guarding.
 */
/*
 * EMPTIED BY 5.4/B7 UNDER D23, and this is the disposal route the guard's own third error message
 * prescribes: "this consumer should be removed from LITERAL_PATH_LIBRARY_CONSUMERS as part of
 * deciding that, not before." The decision is D23's `libs/codemirror` prefix alias, so the four ids
 * are now bundled imports and the four NPM_LIBRARY_FILES rows that fed them are gone with them.
 *
 * THE GUARD IS KEPT, NOT DELETED. It is generic -- any future view that names a runtime library by
 * literal shipped path belongs in this list, and the mechanism is the only thing in the build that
 * would catch such a path moving. With the list empty it checks nothing and reports 0, which is
 * honest; a deleted guard would have to be rediscovered.
 *
 * WHAT REPLACED IT AS A CHECK. The old failure mode was silent: a shipped path and a source string
 * that disagreed 404'd at runtime with the build still green, and no e2e spec loads CodeMirror. As
 * bundled imports they cannot fail that way -- an unresolved "libs/codemirror/..." specifier is a
 * hard Rollup error, because build.commonjsOptions.include matches neither src/main/js/config/ nor
 * src/main/js/org/, so nothing rescues it quietly.
 */
const LITERAL_PATH_LIBRARY_CONSUMERS = [];

const assertLiteralPathLibraries = (root, shippedLibraries) => {
    let checked = 0;
    for (const consumer of LITERAL_PATH_LIBRARY_CONSUMERS) {
        const file = path.resolve(root, consumer);
        if (!fs.existsSync(file)) {
            throw new Error(
                `${consumer} is listed in LITERAL_PATH_LIBRARY_CONSUMERS but does not exist.\n\n` +
                "It is the reason four libs/codemirror entries are in NPM_LIBRARY_FILES. If the " +
                "view moved, repoint this list; if it is gone, those entries are dead weight and " +
                "should go with it."
            );
        }
        const ids = [...fs.readFileSync(file, "utf8").matchAll(/"(libs\/[^"]+?)(?:\.js)?"/g)]
            .map((match) => match[1]);
        if (ids.length === 0) {
            throw new Error(
                `${consumer} no longer names any libs/ path literally.\n\n` +
                "This guard exists because the shipped path IS the identifier for those files, " +
                "so nothing else in the build would notice them moving. If task 5.1 has " +
                "converted this view to ESM, the four libs/codemirror entries in " +
                "NPM_LIBRARY_FILES need a new contract -- an alias, a registry entry, or a " +
                "bundled import -- and this consumer should be removed from " +
                "LITERAL_PATH_LIBRARY_CONSUMERS as part of deciding that, not before."
            );
        }
        const missing = ids.filter((id) => !shippedLibraries.has(`${id}.js`));
        if (missing.length > 0) {
            throw new Error(
                `${consumer} loads runtime libraries by literal AMD path, and the build did not ` +
                "ship them:\n" + missing.map((id) => `  ${id}.js`).join("\n") + "\n\n" +
                "The path in the source and the destination key in NPM_LIBRARY_FILES are the " +
                "same contract and have to match exactly. This is almost always a renamed map " +
                "key, or a package version that moved its internal layout -- codemirror's " +
                "mode/ and addon/ trees in particular. Nothing else in the build or the e2e " +
                "suite checks this: without it the admin script editor 404s at runtime and the " +
                "build still exits 0."
            );
        }
        checked += ids.length;
    }
    return checked;
};

/*
 * ==== 4.5 -- index.html: THE VERSION STAMP, AND THE LOADER THAT IS NOT REWRITTEN ====
 *
 * Grunt emitted index.html from grunt-text-replace, not from copy:compiled -- which is why
 * `index.html` sits in NOT_COPIED above and why 4.4 recorded it as an expected absence. This is
 * that step: read the source, substitute ${version}, write it to the tree root.
 *
 * THERE ARE TWO ${version} MECHANISMS IN THIS MODULE AND ONLY THIS ONE IS LIVE.
 * pom.xml:82-85 declares src/main/resources as a FILTERED resource root, so
 * maven-resources-plugin substitutes ${version} into target/classes/index.html at
 * process-resources. Nothing ever ships that copy: zip.xml packs `target/compiled`, not
 * target/classes, and this module is <packaging>pom</packaging> (pom.xml:28), so no jar is built
 * from target/classes either. The UI build does not read it -- Gruntfile.js:24-29
 * (`mavenProjectSource`) composes from ./src/main/resources DIRECTLY, the unfiltered source, and
 * COMPOSITION_SOURCES above does the same. So the Maven-filtered file is a dead end that happens
 * to contain the right bytes. The live mechanism was grunt-text-replace (Gruntfile.js:246-259)
 * driven by grunt.option("target-version"); this reproduces it, now driven by
 * process.env.TARGET_VERSION (see `targetVersion` at the top of this file, and the npm-build
 * execution in pom.xml which sets it from ${project.version}).
 *
 * The dead Maven filtering is LEFT IN PLACE, deliberately -- but NOT because D9 requires it, and
 * the difference matters for whoever reads D9 next. D9 decides the SOURCE LAYOUT
 * (src/main/js, src/main/resources) and cites "maven-resources-plugin still filters
 * src/main/resources for ${version}" as supporting evidence for keeping it. That sentence is
 * still literally true -- the filtering is bound at pom.xml:98-117 and does run -- but this task
 * establishes it is NON-PROBATIVE: the filtered output reaches nothing that ships. D9's
 * conclusion survives on its other leg (a rename buys nothing user-visible and would bury the
 * real diff); its ${version} leg does not. Recorded here, and in 4.5's completion note, the way
 * 4.2/4.3/4.4 each recorded a disproved premise.
 *
 * The actual reasons to leave it: removing it changes target/classes for no shipped effect, it is
 * outside this task's scope, and src/main/resources still feeds target/classes for anything else
 * that may want it. Preserving a mechanism nothing reads would not be preservation, which is why
 * this comment says it is dead rather than treating it as the live one.
 *
 * WHY NOT A VITE HTML INPUT. Adding index.html to rollupOptions.input makes Vite parse it and
 * pull its <script src> tags into the module graph. (As of 5.4/B12 it has ONE tag and it names
 * main.js, which IS an input already -- so the double-emit half of this now matters more than the
 * unresolvable half. Both are still reasons.) At 4.5 both tags would have failed to resolve:
 * src/main/resources has NO libs/ directory at all -- libs/base64-1.0.0-min.js and
 * libs/requirejs-2.3.7-min.js were vendored under src/main/js/libs (4.7; neither had an npm
 * publication that could supply them, and both had to exist as files before any module system
 * runs) and reach the tree through copyLibraries, not through this html
 * -- so the build throws at resolve time. If it somehow did resolve, Vite would bundle and hash
 * both, moving two files PHASE1-TREE.md:244 and :279 record at fixed paths. It would also derive a
 * fourth entry chunk from the html while `main` is already an explicit JS input, which is the
 * double-emit hazard NOTES-vite-entrypoints.md 4.3 flagged for this task. Stamping sidesteps all
 * three, and is why entryFileNames stays the plain "[name].js" rather than 4.3's function form.
 *
 * WHAT HAPPENS TO THE THREE SCRIPT TAGS: nothing. All three ship byte-identical.
 * The RequireJS bootstrap is NOT rewritten to <script type="module">, and that is a decision
 * rather than an omission -- the source is still AMD (NOTES-vite-build.md section 3: Vite accepts
 * AMD, exits 0, and emits a bundle that does nothing), so an ESM loader here would faithfully
 * load something that cannot execute. 4.2 deferred the loader story for exactly this reason and
 * costed five options in NOTES-vite-entrypoints.md section 3 -- four of which need no
 * server-side change, (b) being the one that does; group 5 is what makes any of them
 * choosable. Until then the global `var require = {urlArgs, deps:["main"]}` stays, and it is
 * load-bearing twice: it is what loads `main` at all, and its urlArgs is the ONLY cache-buster on
 * every runtime-fetched template, partial, locale and theme asset (D4) until 4.9's
 * resolveAssetUrl takes that over. The two literal <script src> tags stay the only urls on a
 * login page with no cache-buster -- the pre-existing gap task 1.12 measured (38 of 41 urls carry
 * ?v=), unchanged by this task rather than introduced by it.
 *
 * ---- SUPERSEDED BY 5.4/B12. THE PARAGRAPH ABOVE IS THE 4.5 STATE, KEPT FOR ITS REASONING. ----
 * The tree is ESM now, so the condition that paragraph waited on is met and all three tags are
 * gone. index.html carries ONE tag:
 *
 *     <script type="module" src="main.js?v=${version}"></script>
 *
 * - The `var require = {urlArgs, deps:["main"]}` object and the requirejs <script src> went with
 *   it. `libs/requirejs-2.3.7-min.js` still SHIPS -- six .ftl pages in openam-oauth2 load it by
 *   literal <script src> and D8/task 10.4 forbid editing them -- but nothing in THIS module loads
 *   it any more. Under option (c1) its remaining job on those six pages is to fetch the classic
 *   stub xui-requirejs-entry-stubs emits; see that plugin's header.
 * - `libs/base64-1.0.0-min.js` is GONE from the tree, not merely unreferenced. index.html:21 was
 *   its only loader in the whole repository -- zero of the six .ftl pages mention it -- it is a
 *   btoa/atob polyfill that installs itself only when those globals are absent, no AM module reads
 *   a `base64` global, and commons util/Base64 has a complete pure-JS fallback behind a `typeof`
 *   test. Any browser that runs type="module" has both natively. D20's register row went with the
 *   file; see src/main/js/libs/README.md.
 * - `urlArgs` is replaced in two places, not one. For the runtime-fetched templates, partials,
 *   locales and theme assets it is main.js's `resolveAssetUrl.configure({ urlArgs })` call, fed by
 *   the `__TARGET_VERSION__` define below. For main.js ITSELF -- the one JS file this build emits
 *   unhashed, and so the only one a browser could serve stale across a redeploy -- it is the
 *   `?v=${version}` on the tag above. That is why the VERSION_TOKEN guard in readIndexHtmlSource
 *   is untouched by B12: it still guards a live mechanism rather than a decorative token.
 *
 * THE PATH CONVENTION TASK 6.3 NEEDS SURVIVES THIS. 6.3 derives a url from a module identifier
 * "using the deployed layout's own convention": identifier `org/forgerock/.../Foo` -> `Foo.js` at
 * that same path below the tree root, which is what RequireJS's baseUrl-relative nameToUrl does
 * today. Two things preserve it here, and neither is the unbundled module tree. First, this file
 * is emitted AT the tree root, unhashed, so the resolution origin stays addressable -- and TODAY
 * that origin is RequireJS's baseUrl, inferred from the <script src="libs/requirejs-2.3.7-min.js">
 * tag below, not from anything Vite emits. Second, PROSPECTIVELY: `base: "./"` in the build config
 * keeps every url Vite emits relative to the directory index.html is served from, so the tree root
 * survives as the origin under any context path once 4.9 and groups 5-6 start emitting urls at
 * all. Note the tense -- index.html is a static stamp and never passes through Vite, so `base`
 * does not touch the three script tags below; do not go looking for an effect that is not wired
 * yet. 6.3's fallback is for
 * identifiers ABSENT from the registry -- an operator's own module dropped into a deployed /XUI
 * (e2e/xui/xui-operator-module.spec.mjs) -- so what it needs is the convention and a stable root,
 * not the 331 bundled modules that no longer ship standalone.
 */
const INDEX_HTML = "index.html";
const INDEX_HTML_SOURCE = "src/main/resources/index.html";
const VERSION_TOKEN = "${version}";

/*
 * split/join, and it matches Grunt on OCCURRENCE COUNT -- do not read this as a first-vs-global
 * divergence, because it is not one. grunt-text-replace does not do a raw-string replace: it
 * passes `from` through convertPatternToRegex first (lib/grunt-text-replace.js:67, and :130-140),
 * which escapes the pattern and returns `new RegExp(pattern, "g")`. For "${version}" that is
 * /\$\{version\}/g -- GLOBAL. So Grunt substituted every occurrence and so does this.
 *
 * The ONE real divergence is `$` handling in the REPLACEMENT. Grunt reaches
 * text.replace(regex, string) with a plain string (:68 expandStringReplacement), so JS expands
 * $&, $1 and $` inside it: with a version of "1.0-$&", Grunt emits "1.0-${version}" while
 * split/join emits the literal "1.0-$&". split/join is the correct side of that -- a version
 * string is data, not a replacement pattern -- and it is also why this is not simply
 * String.replaceAll, which has the identical $-expansion behaviour.
 *
 * Either way the shipped bytes match: index.html carries exactly one ${version} and no version
 * string in play contains a $. Verified against the oracle -- md5 e3444d65a0de8574ec3f356481f16e09,
 * 988 bytes at 16.2.0-SNAPSHOT, PHASE1-TREE.md:147 and :235.
 *
 * The token check is a real addition, not a port. Grunt's "No replacements were found" warning
 * (lib/grunt-text-replace.js:87,107) fires when the `replacements` CONFIG is undefined, never
 * when the token is missing from the file -- so if someone edited the token out of index.html,
 * Grunt would copy it through silently and every runtime-fetched asset would lose its
 * cache-buster with no build-time signal at all. That failure is invisible until a redeploy
 * serves stale templates from a browser cache, so it fails the build here instead.
 */
/*
 * Read from src/main/resources DIRECTLY, where Grunt read the COMPOSED tree
 * (Gruntfile.js:253, `compositionDirectory + "/index.html"`). Equivalent today and checked, not
 * assumed: none of the other seven composition sources carries a root index.html, so the composed
 * copy was always this file. The new failure mode is also the better one -- a missing source
 * throws ENOENT naming the path, where Grunt would silently have stamped whichever source won.
 */
/*
 * ==== 5.4/B12 -- WHAT THIS GUARD NOW CHECKS, AND WHY IT MOVED ====
 *
 * At 4.5 the token was read by RequireJS as `urlArgs` and applied to EVERY runtime-fetched asset,
 * so `source.includes("${version}")` was a faithful test of the whole mechanism. B12 removed the
 * RequireJS bootstrap: the runtime-asset half of D4 is now main.js's
 * `resolveAssetUrl.configure({ urlArgs })`, fed by the `__TARGET_VERSION__` define, and the token
 * that is LEFT in index.html covers exactly one thing -- the cache-buster on main.js itself, the
 * single unhashed JS file this build emits.
 *
 * A plain `includes` would therefore have become a decorative check, and measurably so: it is
 * satisfied by the word appearing anywhere, a comment included, while the src attribute quietly
 * lost its query string. (That is not hypothetical -- the first draft of B12's index.html
 * comment mentioned the token, and the negative test passed a build with the cache-buster
 * deleted.) So the check is against the module script tag itself. It hard-codes nothing about the
 * entry NAME, only that the module script's src carries the token.
 *
 * Note this file is not a Vite HTML input (see the block above), so nothing else in the build
 * parses index.html and nothing else would notice.
 */
const MODULE_SCRIPT_WITH_VERSION =
    /<script\b(?=[^>]*\btype\s*=\s*["']module["'])(?=[^>]*\bsrc\s*=\s*["'][^"']*\$\{version\})[^>]*>/;

/*
 * REVIEW FIX. The guard is tested against the file with HTML COMMENTS REMOVED. Probing it showed
 * the same false green the tightening was meant to close, one level down: a commented-out correct
 * tag plus a live tag with no token passed. Stripping comments first is the only form of this
 * check that cannot be satisfied by text the browser never executes.
 */
const stripHtmlComments = (source) => source.replace(/<!--[\s\S]*?-->/g, "");

/*
 * REVIEW FIX. Returns the module script's src with any query stripped -- i.e. the file name
 * index.html actually asks the browser for. xui-assert-index-entry checks the bundle contains it.
 */
const indexHtmlModuleEntry = (source) => {
    const tag = MODULE_SCRIPT_WITH_VERSION.exec(stripHtmlComments(source));
    const src = tag && /\bsrc\s*=\s*["']([^"']+)["']/.exec(tag[0]);
    return src ? src[1].split("?")[0] : null;
};

const readIndexHtmlSource = (root) => {
    const source = fs.readFileSync(path.resolve(root, INDEX_HTML_SOURCE), "utf8");
    if (!MODULE_SCRIPT_WITH_VERSION.test(stripHtmlComments(source))) {
        throw new Error(
            `${INDEX_HTML_SOURCE} has no <script type="module"> whose src carries the ` +
            `${VERSION_TOKEN} token. main.js is the one JS file this build emits UNHASHED, so ` +
            "that query string is the only thing stopping a browser serving a stale copy of the " +
            "whole application after a redeploy. Write it as:\n\n" +
            `    <script type="module" src="main.js?v=${VERSION_TOKEN}"></script>\n\n` +
            "Putting the token anywhere else in the file -- a comment (HTML comments are stripped " +
            "before this test), an attribute on something that is not the module script -- does " +
            "NOT satisfy this, deliberately. See design.md " +
            "D4, and note that the runtime-asset half of D4 is main.js's resolveAssetUrl." +
            "configure({ urlArgs }) call, not this token."
        );
    }
    return source;
};

const stampIndexHtml = (root, outDir) => {
    const dest = path.resolve(outDir, INDEX_HTML);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, readIndexHtmlSource(root).split(VERSION_TOKEN).join(targetVersion));
    return INDEX_HTML;
};

/*
 * The LESS entries live in src/main/resources/css, but their @imports do not: `common/*.less`
 * comes from ui-commons/www/css and `fontawesome/`, `bootstrap-dialog`, `selectize`, `titatoggle`,
 * `codemirror` and `react-select` come from target/npm-libs/css (4.7 for all but `codemirror`,
 * which 4.8 moved off the Maven zip). They are written as if the composed tree existed, so it has
 * to exist. Less's `paths` option would resolve them but is NOT a substitute: `relativeUrls`
 * rebases each url() from the imported file's real directory to the entry's, so resolving an
 * import out of the staging directory would emit
 * `url(../../../target/npm-libs/css/fontawesome/fonts/...)`. Only a composed tree gives the
 * `url(./fontawesome/fonts/...)` the shipped CSS actually has.
 */
const stageLessSources = (root) => {
    const stage = path.resolve(root, LESS_STAGE);
    /*
     * LESS_STAGE is a constant, but `root` is config.root and the delete is recursive, so the
     * resolved path is checked before anything is removed. Cheap, and it means a mistyped
     * LESS_STAGE fails loudly instead of deleting somewhere it should not.
     */
    if (!stage.startsWith(root + path.sep)) {
        throw new Error(`Refusing to clear a LESS staging directory outside the project root: ${stage}`);
    }
    fs.rmSync(stage, { recursive: true, force: true });
    for (const source of COMPOSITION_SOURCES) {
        const from = path.resolve(root, source, "css");
        if (!fs.existsSync(from)) { continue; }
        for (const rel of walk(from)) {
            copyFile(path.join(from, rel), path.join(stage, "css", rel));
        }
    }
    return stage;
};

/*
 * Compiled OUTSIDE the module graph, with the `less` and `less-plugin-clean-css` devDependencies
 * that are already installed, and with Grunt's exact three options. That is a deliberate choice
 * over Vite's built-in LESS handling, and the reason is byte parity:
 *
 *   compress + clean-css + relativeUrls   ->  89,221 B  url(./fontawesome/fonts/...eot?v=4.5.0)
 *   compress alone                        ->  89,475 B  url('../fonts/...eot?v=4.5.0')  <- 404s
 *   no options                            -> 130,169 B  url('../fonts/...eot?v=4.5.0')  <- 404s
 *
 * All three outputs reproduce PHASE1-TREE.md's md5 exactly under the first row, verified three
 * ways in NOTES-static-assets.md section 3. Vite's css pipeline cannot match it: build.cssMinify
 * is esbuild or lightningcss and neither emits clean-css 3.4.28 bytes, so routing LESS through
 * the graph would put three permanently unexplainable mismatches in front of task 4.8. It would
 * also turn the five Font Awesome fonts into hashed graph assets, where Grunt leaves them as
 * plain relative urls into a verbatim-copied css/fontawesome/fonts/ tree.
 *
 * relativeUrls is load-bearing, not cosmetic -- without it every Font Awesome icon in the console
 * 404s. Vite would have got that part right on its own, by a different mechanism (its
 * ViteLessManager runs rebaseUrls against the root file); that is worth knowing before anyone
 * reads its absence from a naive config as the bug it is not.
 *
 * The option shapes match grunt-contrib-less 3.0.0 (tasks/less.js:119-121, 192): `filename` is
 * the source path and `paths` defaults to its directory, then options go straight to
 * less.render.
 */
const renderStylesheets = async (root, outDir) => {
    const require_ = createRequire(import.meta.url);
    const less = require_("less");
    const CleanCSSPlugin = require_("less-plugin-clean-css");
    const stage = stageLessSources(root);

    for (const entry of LESS_ENTRIES) {
        const filename = path.resolve(stage, entry.src);
        const output = await less.render(fs.readFileSync(filename, "utf8"), {
            filename,
            paths: [path.dirname(filename)],
            compress: true,
            relativeUrls: true,
            plugins: [new CleanCSSPlugin({})]
        });
        const dest = path.resolve(outDir, entry.dest);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, output.css);
    }
    return LESS_ENTRIES.map((entry) => entry.dest);
};

/*
 * Grunt has a check-composition-sources task that fails and names the missing directory. Vite has
 * no equivalent and 4.4 adds one, because the failure it guards against is silent: pom.xml:219
 * installs both @openidentityplatform packages with --no-save, so they are absent from
 * package.json and ANY bare `npm install` prunes them. Without this check that produces a green
 * build missing 53 files -- 36 templates, 5 partials, 9 images, favicon.ico, oauthReturn.html and
 * css/common/structure/config.json -- and the first symptom is a 404 at runtime.
 *
 * buildStart, not writeBundle: fail before the bundle is built, not after.
 */
const isDirectory = (target) => {
    try {
        return fs.statSync(target).isDirectory();
    } catch {
        return false;
    }
};

/*
 * Grunt used grunt.file.isDir (Gruntfile.js:410), not an existence check, and the distinction is
 * worth keeping: a source path that exists as a FILE would pass fs.existsSync and then throw a
 * bare ENOTDIR from inside walk(), losing the message below. Note what this still does NOT catch,
 * because Grunt does not catch it either: a source directory that exists but is EMPTY silently
 * contributes nothing.
 */
const assertSourcesPresent = (root) => {
    const missing = COMPOSITION_SOURCES.filter((source) => !isDirectory(path.resolve(root, source)));
    if (missing.length > 0) {
        throw new Error(
            "Composition sources are missing, so the build would silently ship an incomplete tree:\n" +
            missing.map((source) => `  - ${source}`).join("\n") +
            "\n\nThe two node_modules/@openidentityplatform packages are installed by Maven with " +
            "--no-save (pom.xml:219) and are pruned by a bare `npm install`. Re-run the Maven " +
            "build, or reinstall them from target/npm/*.tgz.\n\n" +
            "target/npm-libs is the only target/ source left -- task 4.8 retired " +
            "target/dependencies with the last maven-dependency-plugin unpack -- and it is staged " +
            "by this config, stageNpmLibraries in buildStart, from declared npm dependencies. So " +
            "it is missing here only if that call was removed or reordered after this check."
        );
    }
};

/*
 * ==== 5.2 -- TWO LIBRARIES THAT ONLY RUN IN SLOPPY MODE ====================================
 *
 * These two work today for one reason: RequireJS injects them as classic <script> elements, and
 * a classic script is SLOPPY MODE. Everything inside an ES module is strict, and strictness is
 * lexical, so once either file is bundled it is strict no matter what wraps it -- there is no
 * Rollup or Vite option that re-sloppies a module. `moduleContext` does not help either: both
 * constructs sit inside a nested IIFE, not at a module's top level.
 *
 * MEASURED, by building each id and evaluating the bundle under jsdom:
 *   i18next     -> TypeError: Cannot read properties of undefined (reading 'jQuery')
 *   jsonEditor  -> TypeError: 'caller', 'callee', and 'arguments' properties may not be
 *                  accessed on strict mode functions
 *
 * The change owner chose a build-time rewrite over patching the bytes on disk. That keeps
 * src/main/js/libs/jsoneditor-0.7.23-custom.js byte-exact against the md5 pinned in
 * src/main/js/libs/README.md, and keeps i18next an ordinary npm dependency rather than making it
 * a NEW vendored file under D20 -- which would have been the first addition to that register
 * since 4.7, and a new hole in `npm audit`, to fix two tokens.
 *
 * EVERY REPLACEMENT ASSERTS ITS MATCH COUNT. Each token below occurs exactly once in its file
 * today (verified). A version bump that moves or reformats one FAILS THE BUILD here, naming the
 * file and the token, instead of silently shipping a library that throws on first use. That is
 * the whole reason this is a plugin with assertions rather than two `.replace()` calls.
 */
const SLOPPY_MODE_PATCHES = [
    {
        /*
         * i18next 1.7.3's browser build opens with `var z,A=this,B=A.jQuery||A.Zepto` inside
         * `!function(){...}()`. Called with no receiver, `this` is the global object in sloppy
         * mode and `undefined` in strict. The unminified sibling (lib/dep/i18next.js, `var root =
         * this`) has the identical problem, so switching builds is not an escape.
         *
         * globalThis is exactly what `this` evaluated to in the browser here, so the rewrite is
         * behaviour-preserving rather than merely throw-suppressing: shims/i18next.js has already
         * set window.jQuery by the time this runs, so B binds to jQuery and $.t / $.fn.i18n are
         * registered -- which is the SILENT failure this library has when jQuery is missing.
         */
        match: /i18next[\\/]lib[\\/]dep[\\/]i18next\.min\.js$/,
        from: "A=this,B=A.jQuery",
        to: "A=globalThis,B=A.jQuery",
        /*
         * 5.4/B12: REQUIRED, i.e. a build in which this patch does not fire FAILS. Measured, not
         * assumed: i18next is a static import of shims/i18next.js, which every one of the three
         * entry points reaches (main.js imports it directly; both secondaries reach it through
         * commons main/i18nManager), so it is in the graph on every build from B12 onwards.
         */
        requiredFrom: null
    },
    {
        /*
         * The vendored JSON Editor fork carries John Resig's "simple JavaScript inheritance", in
         * which the extend function reassigns itself onto each subclass:
         *
         *     a.extend=function(a){ ... return d.prototype=f, d.prototype.constructor=d,
         *                                  d.extend=arguments.callee, d }
         *
         * `arguments.callee` is a hard SyntaxError-class access in strict mode. It cannot be
         * replaced with `a.extend`, because the function's own parameter is also named `a` and
         * shadows the outer binding -- naming the function expression is the only local fix.
         *
         * TWO tokens, both asserted: the name has to be introduced before it can be referenced.
         */
        match: /libs[\\/]jsoneditor-0\.7\.23-custom\.js$/,
        from: "a.extend=function(a){",
        to: "a.extend=function __jsonEditorExtend(a){"
        /*
         * ==== TASK 6.1 CLOSED THIS DEFERRAL. The history below is kept because it is the
         * measurement that dated it. ====
         *
         * This entry carried `requiredFrom: "6.1"` until 6.1 landed D1's runtime module registry.
         * It fires now -- `src/main/js/moduleRegistry.js`'s glob over `/src/main/js/**` puts
         * `libs/jsoneditor-0.7.23-custom.js` in the graph -- so buildEnd failed and told whoever
         * landed 6.1 to delete the field, exactly as the last paragraph below said it would. Done;
         * both entries are back under the hard check.
         *
         * ---- the original note, unchanged ----
         *
         * ==== NOT YET REQUIRED, AND 5.2's STATED PREMISE FOR THE PROMOTION WAS WRONG ====
         *
         * 5.2 wrote that once 5.4 converted the tree "both files ARE reachable". B12 converted the
         * tree and MEASURED otherwise: `vite build` walks 563 modules and jsoneditor is in none of
         * them. Converting a module to ESM does not make it statically reachable; only an import
         * edge does, and jsoneditor has no static edge from any entry.
         *
         * The three importers of the `jsonEditor` id are admin/models/Form.js,
         * admin/utils/JSONEditorTheme.js and common/views/jsonSchema/editors/JSONEditorView.js.
         * Every path into all three runs through a view id that exists only as a STRING -- a
         * `moduleClass` in config/AppConfiguration.js, or a view name in config/routes/admin/*.js --
         * resolved at run time by ModuleLoader. Under AMD that was `require([id])`; under ESM it is
         * LoaderRuntime.loadModule, which rejects until a consumer supplies `resolveModule`. So the
         * task that puts this file in the graph is 6.1's `import.meta.glob` registry (D1), NOT 5.4.
         * `org/forgerock/openam/ui/admin/main.js`, the aggregator that side-effect-imports Form and
         * JSONEditorTheme, has zero references of any kind in the tree -- string or import.
         *
         * So this entry warns instead of failing, and the exception is dated and self-closing: the
         * buildEnd check FAILS if a `requiredFrom` patch starts firing, so whoever lands 6.1 is told
         * to delete these two fields rather than left to remember.
         */
    },
    {
        match: /libs[\\/]jsoneditor-0\.7\.23-custom\.js$/,
        from: "d.extend=arguments.callee",
        to: "d.extend=__jsonEditorExtend"
        // Same file, same reachability story as the entry above -- and the same closure: 6.1's
        // registry put the file in the graph, so this deferral is spent too and the field is gone.
    }
];

/*
 * ---- TASK 5.2: enforce the alias ordering invariant instead of asking for it ------------------
 *
 * @rollup/plugin-alias takes the FIRST entry whose pattern matches -- `importee === pattern ||
 * importee.startsWith(pattern + "/")` -- so a bare key listed BEFORE a longer key beginning with
 * it makes the longer key unreachable. "jquery" above "jquery/dist/jquery.js" sends that import to
 * shims/jquery.js/dist/jquery.js and fails with ENOTDIR, which is how it was found.
 *
 * The alias block explains the rule and asks the next editor to check new entries by hand. That is
 * the one kind of check this file otherwise always turns into a throw -- the vite pin,
 * assertSourcesPresent, the patch-count assertion in xui-sloppy-mode-libraries -- and a comment
 * cannot protect against an entry added by 5.3, 6.1 or 8.3 by someone who never read it.
 *
 * configResolved runs after Vite has normalised the alias into an ordered array and after every
 * other plugin has contributed to it, so this checks the list that actually runs rather than the
 * literal written below.
 *
 * TASK 5.4 (batch B0), AND THE REASON resolve.alias IS WRITTEN AS AN ARRAY RATHER THAN AN OBJECT:
 * this guard cannot see a DUPLICATE key in an object literal, because JavaScript collapses one at
 * parse time -- last wins, silently, before Vite or this plugin ever runs. The table crossed 45
 * entries in B0 and batches B2-B11 add roughly thirty more to the same literal, so a re-added
 * "store" or a second "org/forgerock/openam" was exactly the kind of thing that would land
 * unnoticed and resolve to the wrong file with a green build. In array form the duplicate survives
 * normalisation and the check below throws on it. DO NOT "tidy" this back into an object literal.
 *
 * A regex `find` is still unchecked: it is filtered out because neither startsWith nor equality is
 * meaningful on one. There are none today; a batch that adds one gets no protection here.
 */
const assertAliasOrdering = () => ({
    name: "xui-assert-alias-ordering",

    configResolved(config) {
        const patterns = (config.resolve?.alias ?? [])
            .map((entry) => entry.find)
            .filter((find) => typeof find === "string");

        const duplicated = [...new Set(patterns.filter((find, index) => patterns.indexOf(find) !== index))];

        if (duplicated.length > 0) {
            throw new Error(
                "[xui-assert-alias-ordering] resolve.alias lists the same pattern more than once:\n" +
                `${duplicated.map((find) => `    "${find}"`).join("\n")}\n` +
                "@rollup/plugin-alias takes the first match, so the later entry is dead. Remove it, " +
                "or merge the two into the single entry that was meant."
            );
        }

        const shadowed = patterns.flatMap((later, index) => {
            const captor = patterns
                .slice(0, index)
                .find((earlier) => later.startsWith(`${earlier}/`));
            return captor
                ? [`    "${later}" can never match: "${captor}" is listed before it`]
                : [];
        });

        if (shadowed.length > 0) {
            throw new Error(
                "[xui-assert-alias-ordering] resolve.alias contains entries that can never " +
                "match, because @rollup/plugin-alias takes the first matching pattern:\n" +
                `${shadowed.join("\n")}\n` +
                "Move each specific key ABOVE the shorter key that captures it."
            );
        }
    }
});

/*
 * ==== 5.3 -- react-select AND react-input-autosize NEED NO GLOBALS ==========================
 *
 * WHAT main.js DOES TODAY. Its require.config binds both ids to the browserify `dist/` bundles
 * (main.js:91-92) and hangs a synthetic AMD module off each shim (shim entries at main.js:223-228,
 * the two `define()`s at :253-263). Those modules exist for exactly one reason: the installed
 * react-select 1.0.0-rc.2 dist bundle reads window.React, window.ReactDOM, window.classNames and
 * window.AutosizeInput SYNCHRONOUSLY at file evaluation. browserify-shim replaced the four externals with global reads when the bundle was
 * published, and the prelude runs the entry module eagerly -- the file ends `},{},[5])(5)});`.
 * NOTES-shims.md section 3.2 B quotes all four initialisers from the installed bytes and counts
 * them: window.React x8, window.classNames x4, window.ReactDOM x1, window.AutosizeInput x1.
 * RequireJS satisfied that ordering because a shim's `deps` are loaded before the shimmed file's
 * <script> is even inserted -- not because anything in the source says so.
 *
 * WHAT 5.3 DECIDED, AND WHY THERE IS NO SHIM MODULE FOR EITHER ID. Both packages' own `main` is
 * plain CommonJS that requires everything BY NAME: react-select's lib/Select.js takes react,
 * react-dom, react-input-autosize and classnames; react-input-autosize's lib/AutosizeInput.js
 * takes react. classnames and react-input-autosize are react-select's own declared dependencies,
 * and its peerDependencies admit react ^15.0 -- which is the version this module pins. So the
 * bare specifier already resolves to code that needs no globals at all, and the ordering that
 * RequireJS's `deps` used to enforce becomes an ordinary import edge that Rollup orders for us.
 *
 * That is why NEITHER ID APPEARS IN resolve.alias BELOW, and why src/main/js/shims/ has no file
 * for either: here the fix is the ABSENCE of a redirect, not a redirect to something better. The
 * four globals are not relocated into an ESM shim, they stop existing. The version is untouched
 * -- same package, same 1.0.0-rc.2 that design.md's Non-Goals pin -- so this is not a library
 * substitution, which those Non-Goals also forbid.
 *
 * WHY THIS IS A BUILD-TIME CHECK AND NOT A COMMENT. An absence cannot be read. Nothing in
 * SessionsView.jsx -- the single consumer in the tree, at :21 -- says that adding one innocuous
 * alias entry would swap a by-name import graph for four undeclared globals, and the failure
 * would be silent in the worst way: the build stays green, react-select still resolves, the
 * globals are simply never assigned, and the Select renders against a null React at runtime.
 * This throws at config time instead. It is the same reasoning as assertVendoredVersions above --
 * pin the thing the decision actually rests on, not the comment describing it.
 */
const GLOBAL_FREE_REACT_PACKAGES = {
    "react-select": "lib/Select.js",
    "react-input-autosize": "lib/AutosizeInput.js"
};

/*
 * D23 FOLLOW-UP, ADDED BY THE 5.4 REVIEW. D23 deleted the four `libs/codemirror` NPM_LIBRARY_FILES
 * rows on the premise that EditScriptView.js now imports them through the prefix alias, so they are
 * bundled rather than staged. That premise is CORRECT but NOT YET IN EFFECT, and the difference
 * matters: `find target/compiled -iname '*codemirror*'` returns nothing today, because
 * EditScriptView is reachable only through a runtime view-id string -- the identical situation this
 * config already diagnosed for jsoneditor at the SLOPPY_MODE_PATCHES `requiredFrom` note.
 *
 * So the -4 delta is contingent on 6.1, not on B7, and until 6.1 lands the safety claim on
 * LITERAL_PATH_LIBRARY_CONSUMERS ("an unresolved libs/codemirror/... specifier is a hard Rollup
 * error") is vacuous -- nothing resolves those ids at all, so a broken alias would fail silently.
 *
 * RESTORING THE FOUR ROWS WOULD BE THE WRONG FIX. Nothing fetches the staged copies: EditScriptView
 * loads CodeMirror by ESM import, not by literal path, so shipping them again would ship four files
 * with no reader. What was missing is the CHECK, not the files. This is that check, in the same
 * bidirectional shape as the sloppy-mode deferral: it cannot become a permanent exemption.
 */
/*
 * TASK 6.1 SPENT THE ONLY ENTRY THIS LIST HELD. D1's registry made EditScriptView statically
 * reachable, `node_modules/codemirror` is bundled through the D23 prefix alias exactly as
 * predicted, and buildEnd's spent-deferral branch fired and said to delete the entry. Deleted.
 *
 * The list is kept, empty, because both of its branches are still live for the next deferral: it
 * is the shape a "this alias is not yet exercised" exemption has to take here, and the check is
 * what stops one outliving its reason. The note above records why restoring the four staged
 * `libs/codemirror` rows would be the wrong fix if this ever looks broken again.
 */
const DEFERRED_ALIASED_LIBRARIES = [];

const assertAliasedLibrariesBundled = () => ({
    name: "xui-assert-aliased-libraries",
    buildEnd (error) {
        if (error) {
            return;
        }
        const ids = Array.from(this.getModuleIds()).map((id) => id.replace(/\\/g, "/"));

        for (const lib of DEFERRED_ALIASED_LIBRARIES) {
            const consumerInGraph = ids.some((id) => id.endsWith(lib.consumer));
            const libraryInGraph = ids.some((id) => lib.inGraph(id));

            if (consumerInGraph && !libraryInGraph) {
                throw new Error(
                    `[xui-assert-aliased-libraries] ${lib.label}\n\n` +
                    "Its consumer IS in the module graph now, but the library is NOT. The alias no " +
                    "longer resolves, so the four staged files D23 removed have no replacement and " +
                    "the script editor ships without CodeMirror. Fix the alias -- do not re-add the " +
                    "NPM_LIBRARY_FILES rows, which would ship files nothing fetches."
                );
            }

            if (consumerInGraph && libraryInGraph) {
                throw new Error(
                    `[xui-assert-aliased-libraries] ${lib.label}\n\n` +
                    "The deferral is SPENT: the library is bundled through the alias, exactly as " +
                    `D23 predicted, now that ${lib.requiredFrom} has landed. Delete this entry from ` +
                    "DEFERRED_ALIASED_LIBRARIES. Leaving it would let the deferral outlive its " +
                    "reason, which is the failure mode this check exists to prevent."
                );
            }

            this.warn(
                `[xui-assert-aliased-libraries] ${lib.label} is in NO chunk, as declared.\n` +
                `Its consumer has no static import edge from any entry point yet; ${lib.requiredFrom} ` +
                "closes this. Until then the -4 delta against PHASE1-TREE.md ships nothing in its place."
            );
        }
    }
});

/*
 * ADDED BY THE 5.4 REVIEW. 269 bare `import "id";` side-effect imports survived the AMD->ESM
 * conversion, and 28 of them ARE the D21 fix -- the graft that guarantees AM's Constants keys are
 * installed before a module-top-level reader runs. Nothing in this build pins the setting that
 * keeps them: Rollup's default `moduleSideEffects: true`. Adding `"sideEffects": false` to
 * package.json, or a treeshake preset that disables it, would delete all 269 edges silently, and
 * D21 would fail as `.../undefined/json` request paths at runtime with the build still green.
 *
 * This is the same unenforced-invariant shape D21 records for "nothing enforces file 29", and it
 * is cheaper to check: it is two fields.
 */
const assertSideEffectsPinned = () => ({
    name: "xui-assert-side-effects",
    configResolved (config) {
        const treeshake = config.build && config.build.rollupOptions && config.build.rollupOptions.treeshake;
        const disabled = treeshake === false ||
            (treeshake && treeshake.moduleSideEffects === false) ||
            (treeshake && treeshake.preset === "smallest");
        if (disabled) {
            throw new Error(
                "[xui-assert-side-effects] build.rollupOptions.treeshake disables moduleSideEffects.\n\n" +
                "269 bare side-effect imports depend on it, 28 of them the D21 Constants graft. " +
                "Dropping those edges makes D21 fail at runtime, not at build time."
            );
        }

        const pkg = JSON.parse(fs.readFileSync(path.resolve(config.root, "package.json"), "utf8"));
        if (pkg.sideEffects === false || (Array.isArray(pkg.sideEffects) && pkg.sideEffects.length === 0)) {
            throw new Error(
                '[xui-assert-side-effects] package.json declares "sideEffects": false.\n\n' +
                "That tells Rollup every module in this package is side-effect free, which would " +
                "delete all 269 bare `import \"id\";` edges -- including the 28 that implement D21. " +
                "The failure would surface as undefined Constants values at runtime, behind a " +
                "green build. Remove the field, or list the D21 files explicitly."
            );
        }
    }
});

const assertReactSelectNeedsNoGlobals = () => ({
    name: "xui-assert-react-select-globals",

    configResolved(config) {
        const aliasPatterns = (config.resolve?.alias ?? []).map((entry) => entry.find);

        const failures = Object.entries(GLOBAL_FREE_REACT_PACKAGES).flatMap(([id, expectedMain]) => {
            const problems = [];

            /*
             * 1. Nothing may redirect the id. A string `find` matches exactly or as a path
             * prefix, so both shapes are checked -- a `find` of "react" does NOT capture
             * "react-select", only "react" and "react/...", which is why the prefix test appends
             * the separator rather than using a bare startsWith.
             *
             * RegExp finds are checked too, and are not a hypothetical shape: resolve.alias
             * accepts them, and a guard whose entire job is to prove that NO redirect exists
             * would be worthless if the one alias form it cannot see were the form someone
             * reached for. The regex is rebuilt without /g because `test` on a global regex is
             * stateful through lastIndex and would report differently on a second call.
             */
            const redirect = aliasPatterns.find((find) => (
                find instanceof RegExp
                    ? new RegExp(find.source, find.flags.replace("g", "")).test(id)
                    : typeof find === "string" && (find === id || id.startsWith(`${find}/`))
            ));
            if (redirect !== undefined) {
                problems.push(
                    `    resolve.alias "${redirect}" redirects "${id}" away from its package main`
                );
            }

            /*
             * 2. The package main must still be the by-name CommonJS entry. A version bump that
             * moved `main` onto a dist bundle would reintroduce all four globals without touching
             * one line of this config, and no alias check would see it.
             */
            const manifest = path.resolve(config.root, "node_modules", id, "package.json");
            if (!fs.existsSync(manifest)) {
                problems.push(`    ${id} is not installed under ${config.root}/node_modules`);
                return problems;
            }
            const declaredMain = JSON.parse(fs.readFileSync(manifest, "utf8")).main;
            if (declaredMain !== expectedMain) {
                problems.push(
                    `    ${id} package main is "${declaredMain}", expected "${expectedMain}" ` +
                    "-- a dist/ main reads window.React and three more globals at evaluation"
                );
            }

            return problems;
        });

        if (failures.length > 0) {
            throw new Error(
                "[xui-assert-react-select-globals] react-select and react-input-autosize must " +
                "reach this build through their own package main, which requires react, " +
                "react-dom, react-input-autosize and classnames BY NAME:\n" +
                `${failures.join("\n")}\n\n` +
                "Task 5.3 removed the window.React / window.ReactDOM / window.classNames / " +
                "window.AutosizeInput globals by relying on exactly that. Restoring a dist/ " +
                "binding brings all four back, and neither this build nor the e2e suite would " +
                "report it -- see NOTES-shims.md section 3.2 B for the measured reads."
            );
        }
    }
});

/*
 * ==== 7.2 -- EVERY MODULE config/AppConfiguration.js NAMES BY STRING SURVIVES THE BUILD =====
 *
 * WHAT IS UNENFORCED WITHOUT THIS. AppConfiguration.js names 26 modules by string identifier and
 * imports none of them. Nothing else in the source references most of them either -- that is the
 * whole point of the file, and it is what "Modules named by application configuration" requires:
 * "resolvable without the module being referenced anywhere else in the source". The consequence is
 * that renaming or moving one of those 26 files is INVISIBLE to the build. Rollup has no edge to
 * break; `import.meta.glob` in moduleRegistry.js simply enumerates one file fewer and the id is
 * quietly absent from the registry. The build stays green, the zip ships, and the failure surfaces
 * in a browser as a route that never renders or a login that stops at "Loading...".
 *
 * WHY generateBundle AND NOT A RUNTIME OR TEST CHECK. "Present in the built application" is a
 * property of the emitted chunk set, which is exactly what generateBundle is handed. Confirming it
 * at runtime would mean RESOLVING each id, and resolving is fetching -- 26 modules pulled into the
 * initial payload to prove a build-time fact, which is precisely what the requirement
 * "On-demand loading of resolvable modules" forbids. THIS PLUGIN ADDS NO STATIC IMPORT AND SETS NO
 * `eager` FLAG, and neither may any future edit of it: `{ eager: true }` on moduleRegistry.js's
 * globs would make every id trivially "present" and would drag org/forgerock/openam/ui/admin/main.js
 * -- 43 static imports, 28 of them admin views, nothing importing it -- into the entry chunk, with
 * a green build and a working console hiding the regression. Task 6.5 measured that tree; do not
 * flatten it to satisfy this check.
 *
 * WHERE THE ID LIST COMES FROM: AppConfiguration.js ITSELF, not a copy of it. A checked-in list
 * would need a drift check to stay honest, and the drift check would have to read the file anyway
 * -- so reading the file is the whole job. Five rules cover the eight shapes the file uses today
 * (10 moduleClass, 1 loginHelperClass, 1 SiteConfigurator delegate, 6 Router loader routes,
 * 2 processConfigurationFiles, 1 defaultHandlers, 3 messages, 2 validators = 26), and a seventh
 * route or a fourth message config is covered the moment it is added, with no edit here. The
 * `loader` rule is deliberately generic over the entry's KEY, which is what makes routes /
 * defaultHandlers / messages / validators one rule rather than four.
 *
 * THE FILE IS EVALUATED, NOT PATTERN-MATCHED. `templateUrls`, `partialUrls`, the Navigation `links`
 * tree and `helpLinks` are also arrays of strings in this file and are NOT module ids; a text scan
 * for quoted strings would report all of them. Walking the evaluated object reaches only the five
 * positions that are ids.
 *
 * THE LOGIN HELPER IS THE ONE ID THAT IS NOT IN THE SOURCE TEXT. 6.6 replaced the literal with
 * `__LOGIN_HELPER_CLASS__`, a build-time define. The substitution below uses the SAME
 * `loginHelperClass` const the `define` block feeds to Vite, so this check reads the value the
 * build actually emits -- including an operator's LOGIN_HELPER_CLASS override, which is the case
 * that most needs checking and the one a source-text scan cannot see at all.
 *
 * NOT COVERED HERE, DELIBERATELY: the nine ids of NOTES-module-registry.md section 8 that no glob
 * produces. None of AppConfiguration.js's 26 is among them -- checked, not assumed -- so every id
 * this plugin enforces resolves through the glob, and the normalisation below is the same one
 * moduleRegistry.js's `addTree` applies. If a future edit does put a logical name or a library name
 * in this file, the failure message says so rather than leaving the contributor to guess.
 */
const APP_CONFIGURATION = "src/main/js/config/AppConfiguration.js";

/*
 * The three trees moduleRegistry.js globs, the prefix each strips to make an id, and -- for AM --
 * the three ids its glob explicitly excludes.
 *
 * MATCHED WITH lastIndexOf RATHER THAN A ROOT-RELATIVE SLICE so a symlinked node_modules, whose
 * module ids arrive as realpaths outside the Vite root, still normalises. That is the whole of
 * the justification: a HOISTED node_modules would not work either way, because
 * moduleRegistry.js's globs are root-absolute and would enumerate nothing in that layout, so the
 * build would already be dead long before reaching here.
 *
 * THE EXCLUSIONS MATTER because without them this check is a SUPERSET of the registry. Measured
 * on a real build: 362 normalisable ids emitted against 359 registry keys, and the three extra
 * are exactly the entries the AM glob drops with its "!" patterns. An id that is one of those
 * three would be present in the build and still unanswerable by the registry -- precisely the
 * false negative this plugin exists to prevent. Keep this list in step with moduleRegistry.js's
 * amTree patterns.
 */
const REGISTRY_TREES = [
    { prefix: "/src/main/js/", excluded: ["main", "main-authorize", "main-device"] },
    { prefix: "/node_modules/@openidentityplatform/ui-commons/esm/", excluded: [] },
    { prefix: "/node_modules/@openidentityplatform/ui-user/esm/", excluded: [] }
];

const registryIdFor = (moduleId) => {
    if (moduleId.startsWith("\0")) {
        return null;
    }
    const posix = moduleId.replace(/\\/g, "/").split("?")[0];
    for (const tree of REGISTRY_TREES) {
        const at = posix.lastIndexOf(tree.prefix);
        if (at !== -1) {
            const match = /^(.*)\.(jsx?|jsm)$/.exec(posix.slice(at + tree.prefix.length));
            if (match) {
                return tree.excluded.includes(match[1]) ? null : match[1];
            }
        }
    }
    return null;
};

const configuredModuleIds = (root, resolvedLoginHelperClass) => {
    const file = path.resolve(root, APP_CONFIGURATION);
    const source = fs.readFileSync(file, "utf8");
    const lines = source.split("\n");

    /*
     * TAGGED, because the transform below is deliberately narrow and four realistic future edits
     * of AppConfiguration.js break it: an object-literal `export default { ... }`, a second
     * `export`, any `import`, or a comment containing the phrase "export default obj". All four
     * fail LOUDLY rather than silently -- the right side of the safety line -- but untagged they
     * surface as a bare `SyntaxError: Unexpected token 'export'` pointing into vite.config.js,
     * which tells an operator nothing. Every other assertion in this file explains itself when it
     * fires; so does this one.
     */
    let evaluated;
    try {
        evaluated = vm.runInNewContext(
            source
                .replace(/__LOGIN_HELPER_CLASS__/g, JSON.stringify(resolvedLoginHelperClass))
                .replace(/\bexport\s+default\s+(\w+)\s*;?/, "$1;"),
            Object.create(null),
            { filename: file, timeout: 5000 }
        );
    } catch (cause) {
        throw new Error(
            "[xui-assert-configured-modules] could not evaluate " + APP_CONFIGURATION + " to " +
            "read the module ids it names.\n\n" +
            "This check strips a single `export default <identifier>;` and evaluates the rest in " +
            "node:vm. It cannot handle an object-literal default export, a second `export`, or " +
            "an `import` -- if the file has grown one of those, widen the transform here.\n\n" +
            "Original failure: " + cause.message
        );
    }

    const lineOf = (needle) => {
        const index = lines.findIndex((line) => line.includes(needle));
        return index === -1 ? "" : `:${index + 1}`;
    };

    const found = [];
    const record = (id, where, needle) => {
        if (typeof id === "string" && id.length > 0) {
            found.push({ id, where: `config/AppConfiguration.js${lineOf(needle ?? `"${id}"`)} ${where}` });
        }
    };

    ((evaluated && evaluated.moduleDefinition) || []).forEach((entry, index) => {
        const base = `moduleDefinition[${index}]`;
        const configuration = (entry && entry.configuration) || {};

        record(entry && entry.moduleClass, `${base}.moduleClass`);

        /*
         * KEY PRESENCE, NOT VALUE TYPE. The requirement behind this check names loginHelperClass
         * as the one id that must not be silently skipped, and a `typeof === "string"` test does
         * exactly that when the value is anything else. There is a concrete path to it:
         * `JSON.stringify(undefined)` returns the JS value `undefined`, so a `define` that lost
         * its fallback would substitute the TEXT `undefined`, evaluate to `loginHelperClass:
         * undefined`, and drop the id with a green build. Unreachable today -- the
         * `loginHelperClass` const above has a `||` fallback -- but that guard lives a long way
         * from here, and this is the id least able to afford a silent skip.
         */
        if ("loginHelperClass" in configuration) {
            const where = `config/AppConfiguration.js${lineOf("loginHelperClass:")} ` +
                `${base}.configuration.loginHelperClass -- a build-time define, not a source ` +
                "literal: vite.config.js sets __LOGIN_HELPER_CLASS__ from the " +
                "LOGIN_HELPER_CLASS environment variable";

            if (typeof configuration.loginHelperClass !== "string" ||
                    configuration.loginHelperClass.length === 0) {
                throw new Error(
                    "[xui-assert-configured-modules] " + where + " is not a non-empty string " +
                    `(got ${JSON.stringify(configuration.loginHelperClass)}).\n\n` +
                    "It names the login helper module and must be an identifier. Check that " +
                    "vite.config.js still defines __LOGIN_HELPER_CLASS__, and that a " +
                    "LOGIN_HELPER_CLASS override, if set, is not empty."
                );
            }

            found.push({ id: configuration.loginHelperClass, where });
        }

        record(configuration.delegate, `${base}.configuration.delegate`);

        (configuration.processConfigurationFiles || []).forEach((id, slot) => {
            record(id, `${base}.configuration.processConfigurationFiles[${slot}]`);
        });

        /*
         * GENERIC OVER THE ENTRY KEY, which is what makes routes / defaultHandlers / messages /
         * validators one rule instead of four, and what makes a fourth message config covered
         * with no edit here. The cost of that genericity: a loader entry that ever gains a
         * non-id string field -- `{ "routes": "...", "when": "admin" }` -- would make "admin" a
         * required module id and fail the build. Narrow this to a key allow-list if that day
         * comes; until then the open form is the one that keeps the check self-maintaining.
         */
        (configuration.loader || []).forEach((entryForSlot, slot) => {
            Object.keys(entryForSlot || {}).forEach((key) => {
                record(entryForSlot[key], `${base}.configuration.loader[${slot}].${key}`);
            });
        });
    });

    /*
     * ==== THE SHAPE CROSS-CHECK -- what stops a PARTIAL restructure passing green ====
     *
     * The walk above knows five positions. A "found nothing at all" floor (in the plugin below)
     * catches only the total failure; the likelier one is PARTIAL. Rename `loader` to `loaders`,
     * or move `processConfigurationFiles` under a new key, and the ten moduleClass ids still
     * come back -- the count stays plausible, no floor fires, and SIXTEEN OF THE TWENTY-SIX
     * silently stop being enforced behind a green build. That is the same vacuous pass the floor
     * exists to prevent, wearing a disguise.
     *
     * So: deep-walk every string in the evaluated object, keep the ones SHAPED like module ids,
     * and require that set to be a subset of what the structured walk found. This asserts a
     * SHAPE INVARIANT, not a count -- adding or removing a configured module stays a one-file
     * change with no edit here, which is the property this check was chosen for.
     *
     * THE PREDICATE, AND WHY EACH CLAUSE IS THERE. Measured against the current file: 109
     * distinct strings, of which exactly 26 survive, and they are exactly the 26 the structured
     * walk returns. A slash is required (excludes the i18n keys, "fa fa-cloud hidden-md", the
     * role names and loggerLevel); "#" excludes the Navigation hrefs (#realms, #profile/details);
     * ".." excludes ../task/Home; the extension test excludes the 3 templateUrls and 19
     * partialUrls, which are the only other slash-bearing strings in the file; "://" excludes a
     * documentation URL, should one ever be added.
     *
     * A FALSE POSITIVE HERE IS THE POINT, not a flaw. If a future edit adds an id-shaped string
     * somewhere the walk does not look, this fails and says so -- which is the loud failure the
     * derive-from-the-file approach otherwise trades away for being self-maintaining.
     */
    const foundIds = new Set(found.map((entry) => entry.id));
    const idShaped = (value) => typeof value === "string" &&
        value.includes("/") &&
        !value.startsWith("#") &&
        !value.startsWith("..") &&
        !value.includes("://") &&
        !/\.(html|css)$/.test(value);

    const everyString = [];
    const collect = (node) => {
        if (typeof node === "string") {
            everyString.push(node);
        } else if (node && typeof node === "object") {
            Object.keys(node).forEach((key) => collect(node[key]));
        }
    };
    collect(evaluated);

    const uncovered = [...new Set(everyString.filter(idShaped))].filter((id) => !foundIds.has(id));

    if (uncovered.length > 0) {
        throw new Error(
            "[xui-assert-configured-modules] " + APP_CONFIGURATION + " contains strings shaped " +
            "like module identifiers that this check does not know how to collect:\n\n" +
            uncovered.map((id) => `    "${id}"${lineOf(`"${id}"`)}`).join("\n") + "\n\n" +
            "The walk understands five positions: moduleClass, loginHelperClass, the " +
            "SiteConfigurator delegate, processConfigurationFiles, and the values of loader " +
            "entries. A string that looks like an id but sits somewhere else means either the " +
            "file grew a new kind of configuration -- teach the walk that position, or those " +
            "modules go unenforced -- or the string is not a module id at all, in which case " +
            "widen the idShaped predicate above and say why."
        );
    }

    return found;
};

const assertConfiguredModulesBundled = () => {
    let root = null;

    return {
        name: "xui-assert-configured-modules",

        configResolved(config) {
            root = config.root;
        },

        generateBundle(_options, bundle) {
            const configured = configuredModuleIds(root, loginHelperClass);

            /*
             * THE TOTAL case of a vacuous pass: the file no longer parses into anything the walk
             * recognises, so it finds nothing and enforces nothing behind a green build. The
             * PARTIAL case -- a restructure that moves some ids out of the walk's reach while
             * others still come back -- is caught upstream by the shape cross-check in
             * configuredModuleIds, which is the more likely of the two and the one a bare floor
             * cannot see. Both are floors on SHAPE, not on count: adding or removing a configured
             * module stays a one-file change.
             */
            if (configured.length === 0) {
                throw new Error(
                    "[xui-assert-configured-modules] found no module identifiers in " +
                    `${APP_CONFIGURATION}.\n\n` +
                    "The file has always named at least one. Either it no longer exports a " +
                    "`moduleDefinition` array, or it now names modules in a shape this check does " +
                    "not walk (moduleClass, loginHelperClass, delegate, processConfigurationFiles " +
                    "and loader entries). Teach the walk the new shape -- passing green while " +
                    "covering nothing is the one outcome this check must not have."
                );
            }

            const emitted = new Set();
            Object.keys(bundle).forEach((fileName) => {
                Object.keys(bundle[fileName].modules || {}).forEach((moduleId) => {
                    const id = registryIdFor(moduleId);
                    if (id !== null) {
                        emitted.add(id);
                    }
                });
            });

            const missing = configured.filter((entry) => !emitted.has(entry.id));

            if (missing.length > 0) {
                throw new Error(
                    "[xui-assert-configured-modules] config/AppConfiguration.js names modules by " +
                    "string identifier that no chunk in this build carries:\n\n" +
                    missing
                        .map((entry) => `    "${entry.id}"\n        named at ${entry.where}`)
                        .join("\n\n") +
                    "\n\n" +
                    "Nothing imports these statically. The application reaches them only through " +
                    "moduleRegistry.js's import.meta.glob, so a renamed, moved or deleted file " +
                    "breaks no build edge -- it just stops being enumerated, and the failure " +
                    "surfaces in a browser as a route that never renders or a login that stops at " +
                    '"Loading...". Restore the file under its old path, or update the ' +
                    "configuration entry named above to the new one.\n\n" +
                    "IF AN ID ABOVE IS A LOGICAL NAME OR A LIBRARY NAME rather than a module " +
                    "path, no glob produces it and this check cannot see it: it compares against " +
                    "the glob-derived ids only, not against moduleRegistry.js's explicit " +
                    "`logicalNames` and `libraries` tables. NOTES-module-registry.md section 8 " +
                    "lists the nine such ids. None of AppConfiguration.js's ids was one when " +
                    "this check was written, which is why covering those tables was left " +
                    "unbuilt. If that has changed, the id may well ALREADY resolve correctly at " +
                    "runtime -- confirm it against those two tables, and teach this check to " +
                    "treat a table entry as satisfying rather than deleting the check."
                );
            }
        }
    };
};

const sloppyModeLibraries = () => {
    /*
     * Indices of SLOPPY_MODE_PATCHES that actually fired. Checked in buildEnd, because the
     * failure mode this plugin exists to prevent is silent: if a patch never runs -- the file
     * stopped being reachable, an id shape changed, the regex stopped matching -- the build
     * still succeeds and the library still throws on first use in a browser. A patch that
     * matches nothing is as much a defect as one that matches twice.
     *
     * DEV SERVER -- task 4.10's to fix, recorded here because this is where it will bite. In
     * practice these patches apply to `vite build` only. The plugin declares no `apply`, so it is
     * nominally active in serve as well, but i18next is a node_modules dependency and goes through
     * esbuild dependency pre-bundling, which does not run Vite transform hooks: the
     * A=this -> A=globalThis rewrite never happens there, and esbuild's own CommonJS wrapper
     * leaves `this` undefined exactly as Rollup would. jsoneditor lives under src/ and WOULD be
     * patched. So under the dev server the two libraries diverge and i18next silently loses $.t,
     * which is the precise failure this plugin exists to prevent. Whoever lands 4.10 must either
     * set apply: "build" and accept that the dev server cannot run i18next, or add the matching
     * rewrite as an optimizeDeps.esbuildOptions.plugins entry.
     */
    const applied = new Set();

    return {
        name: "xui-sloppy-mode-libraries",
        enforce: "pre",
        buildStart() {
            applied.clear();
        },
        transform(code, id) {
            /*
             * @rollup/plugin-commonjs synthesises proxy modules for every CommonJS file it
             * converts -- "<path>?commonjs-module", "?commonjs-proxy", "?commonjs-es-import".
             * They carry the ORIGINAL PATH but a few lines of generated wrapper code, so a
             * path-only match sees them and the token assertion below fails against a file that
             * was never the real one. i18next hits this and jsoneditor does not, purely because
             * the latter has no module.exports and is left alone by that plugin.
             */
            if (id.includes("?commonjs")) {
                return null;
            }
            const cleanId = id.split("?")[0];
            let out = code;
            let touched = false;
            for (const [index, patch] of SLOPPY_MODE_PATCHES.entries()) {
                if (!patch.match.test(cleanId)) {
                    continue;
                }
                const seen = out.split(patch.from).length - 1;
                if (seen !== 1) {
                throw new Error(
                        `[xui-sloppy-mode-libraries] expected exactly one occurrence of\n` +
                        `    ${patch.from}\n` +
                        `in ${cleanId}, found ${seen}. The library changed under this patch. Re-read ` +
                        `the file, confirm whether it still needs a sloppy-mode fix at all, and ` +
                        `update SLOPPY_MODE_PATCHES in vite.config.js -- do NOT delete the entry to ` +
                        `make the build pass, because the failure it prevents is a runtime ` +
                        `TypeError on first use.`
                    );
                }
                out = out.replace(patch.from, patch.to);
                applied.add(index);
                touched = true;
            }
            return touched ? { code: out, map: null } : null;
        },
        buildEnd(error) {
            if (error) {
                return;
            }
            const entries = SLOPPY_MODE_PATCHES.map((patch, index) => ({ patch, index }));
            const missed = entries.filter(({ index }) => !applied.has(index));

            /*
             * A `requiredFrom` entry declares "this library is not in the static graph yet, and
             * here is the task that puts it there". The declaration is only allowed to be a
             * DEFERRAL, never a permanent exemption, so it is checked in both directions: a
             * deferred patch that has started firing fails the build asking for the field to go.
             * Without this half, the exemption would outlive its reason and silently become the
             * warning-that-never-fires this whole plugin exists to avoid.
             */
            const stale = entries.filter(({ patch, index }) => patch.requiredFrom && applied.has(index));
            if (stale.length > 0) {
                throw new Error(
                    "[xui-sloppy-mode-libraries] these patches carry a `requiredFrom` deferral and " +
                    "yet DID fire:\n" +
                    stale.map(({ patch }) => `    ${patch.match}  (requiredFrom: ${patch.requiredFrom})`)
                        .join("\n") +
                    "\n\nThe library is in the static module graph now, so the deferral is spent. " +
                    "Delete the `requiredFrom` field from each entry above -- that puts the patch " +
                    "back under the hard check, which is where it belongs. Do not widen the " +
                    "deferral instead."
                );
            }

            const deferred = missed.filter(({ patch }) => patch.requiredFrom);
            if (deferred.length > 0) {
                this.warn(
                    "[xui-sloppy-mode-libraries] these patches did not fire, as declared:\n" +
                    deferred.map(({ patch }) =>
                        `    ${patch.match}  ${patch.from}   (reachable from task ${patch.requiredFrom})`)
                        .join("\n") +
                    "\n\nThe library has no static import edge from any entry point yet. See the " +
                    "`requiredFrom` comment on the first of these entries for the measurement and " +
                    "for which task closes it."
                );
            }

            const missing = missed.filter(({ patch }) => !patch.requiredFrom);
            if (missing.length > 0) {
                /*
                 * A THROW SINCE 5.4/B12, AND IT WAS A WARNING BEFORE IT. 5.2 added this check as a
                 * `this.warn` for one reason: while the tree was still AMD the three entry points
                 * imported nothing -- `vite build` reported "3 modules transformed" -- so neither
                 * library was in the graph and neither patch COULD fire. Throwing then would have
                 * failed every build for a condition that was correct.
                 *
                 * B12 converted the three entries, so a real module graph exists and any patch
                 * whose library sits in it must match on every build. A patch that does not fire
                 * now means one of two things and both are defects: the library moved under the
                 * patch (the regex stopped matching a real file), or it stopped being reachable at
                 * all. The first ships an UNPATCHED library that throws at evaluation in the
                 * browser -- i18next silently loses $.t, jsoneditor throws a TypeError on first use
                 * -- behind a green build, which is the exact failure this plugin exists to
                 * prevent. The second is worth failing on too: it means a runtime library left the
                 * tree without anyone deciding that, and the patch entry is then dead weight to
                 * delete deliberately rather than leave sitting there matching nothing.
                 *
                 * WHAT B12 DID *NOT* GET TO PROMOTE, AND WHY. 5.2's premise for the promotion was
                 * "once 5.4 lands, both files ARE reachable". Half of that is false and B12
                 * measured it: converting a module to ESM does not create an import edge to it. The
                 * jsoneditor entries' only importers hang off view ids that exist as STRINGS in
                 * config/AppConfiguration.js and config/routes/admin/*.js and are resolved at run
                 * time, so nothing static reaches them until 6.1's import.meta.glob registry (D1).
                 * Those two entries therefore carry `requiredFrom: "6.1"` and warn instead, and the
                 * `stale` check above fails the build the moment they start firing so the deferral
                 * cannot outlive its reason. The i18next entry is under the hard check today.
                 *
                 * Do NOT demote this back to a warning to get a build through, and do NOT reach for
                 * `requiredFrom` for anything but a measured, dated absence from the graph. Either
                 * fix the pattern against the current bytes or delete the SLOPPY_MODE_PATCHES entry
                 * with a note saying why the library no longer needs it.
                 */
                throw new Error(
                    "[xui-sloppy-mode-libraries] these patches never fired:\n" +
                    missing.map(({ patch }) => `    ${patch.match}  ${patch.from}`).join("\n") +
                    "\n\nSince 5.4/B12 the whole module tree is reachable from the three entry " +
                    "points, so every patch here must match on every build. A patch that fires " +
                    "zero times means the library is being bundled UNPATCHED and will throw at " +
                    "evaluation in a browser, or that it has silently left the graph. Re-read the " +
                    "file, fix the pattern, or delete the entry deliberately -- do not turn this " +
                    "back into a warning."
                );
            }
        }
    };
};

/*
 * ==== 5.4/B12 -- OPTION (c1): AN UNHASHED CLASSIC-SCRIPT STUB PER REQUIREJS-LOADED ENTRY ====
 *
 * THE PROBLEM 4.2 DEFERRED AND B12 HAD TO SETTLE. RequireJS injects a CLASSIC script --
 * req.createNode sets type="text/javascript" (NOTES-vite-entrypoints.md 2.4) -- for both of its
 * loader forms. Six .ftl pages in the **openam-oauth2** Maven module load main-authorize and
 * main-device that way, through `data-main`:
 *
 *   openam-oauth2/src/main/resources/templates/page/authorize.ftl:65        main-authorize
 *   openam-oauth2/src/main/resources/templates/popup/authorize.ftl:64       main-authorize
 *   openam-oauth2/src/main/resources/templates/touch/authorize.ftl:64       main-authorize
 *   openam-oauth2/src/main/resources/templates/page/error.ftl:56            main-authorize
 *   openam-oauth2/src/main/resources/templates/CodeVerificationForm.ftl:37  main-device
 *   openam-oauth2/src/main/resources/templates/CodeThanks.ftl:37            main-device
 *
 * D8 and task 10.4 both say this migration lands without a coordinated server-side change, so those
 * six lines are fixed. Once the tree is ESM, an `import`/`export` in the file they name is a
 * SyntaxError at parse. index.html is in THIS module and B12 rewrote it to
 * `<script type="module" src="main.js?v=${version}">`, so `main` has an escape the other two do not
 * -- the difference is editability, not mechanism.
 *
 * ONE ROLLUP OUTPUT HAS ONE FORMAT. `output.format` is a single value for the whole build, so an
 * ESM `main` and two AMD secondaries cannot share a bundle, and they must share one: they share
 * jquery, lodash, handlebars, i18next, Configuration, Constants, i18nManager, ThemeManager and
 * Router.
 *
 * WHAT (c1) DOES. The two RequireJS-loaded entries are emitted as ordinary hashed ES chunks under
 * assets/, and this plugin writes an unhashed CLASSIC script at each one's fixed root name whose
 * only job is `import()` of that chunk. RequireJS is loaded, parsed, and then does exactly one
 * thing per page: fetch a ~1 kB stub. It is off the critical path and the whole tree stays ESM.
 *
 * WHY NOT (c2) -- EMIT EVERYTHING AS AMD. Measured to work, and rejected on three counts: it keeps
 * RequireJS on two pages' critical path, it keeps a second module format alive through phase 3, and
 * it SILENTLY disables modulepreload, because vite:build-import-analysis' generateBundle returns
 * early for any format that is not "es". Rejected (a) -- three separate single-entry builds --
 * because it triplicates the vendor set across the three outputs.
 *
 * WHY document.currentScript AND NOT A RELATIVE URL. The .ftl pages are served from /oauth2/...,
 * not from the XUI tree root, so resolving the chunk against the DOCUMENT would look for it under
 * the OAuth2 path. The script element's own src is the only thing on the page that knows where the
 * XUI tree is -- it is `${baseUrl}/XUI/main-authorize.js`, RequireJS's nameToUrl of `data-main`.
 * `document.currentScript` is set during the synchronous execution of a classic script, including
 * one inserted by appendChild with async=true, which is exactly how RequireJS injects it. The
 * getElementsByTagName sweep is the fallback for the case where it is not, and the document base is
 * the last resort rather than the first.
 *
 * WHY NO CACHE-BUSTER ON THE STUB'S OWN URL. There never was one: `data-main` goes through
 * nameToUrl with no `urlArgs` configured (the config object that used to carry one lived in
 * index.html, which these pages do not load), so `${baseUrl}/XUI/main-authorize.js` is fetched bare
 * today too. The chunk the stub imports IS content-hashed, so the payload behind it cannot go
 * stale; only the one-line stub can, and it changes only when the hash does.
 */
const REQUIREJS_LOADED_ENTRIES = new Set(["main-authorize", "main-device"]);

/*
 * ==== 6.1: THE CONSOLE ENTRY IS STUBBED TOO, FOR A DIFFERENT REASON ====
 *
 * The two entries above are stubbed because RequireJS injects a CLASSIC script and the real entry
 * is an ES module. `main` is stubbed to stop the entry being EVALUATED TWICE.
 *
 * index.html loads the console as `<script type="module" src="main.js?v=${version}">` (5.4's
 * option c1). Rollup's own chunk imports name the entry as a bare `../main.js`. Before 6.1 that
 * was harmless -- almost nothing was code-split, so nothing imported the entry chunk. The registry
 * changed that: the entry chunk holds the modules the lazily-loaded views share, so nearly every
 * emitted view chunk now imports it. `main.js?v=dev` and `main.js` are two URLs, and two URLs are
 * TWO MODULE RECORDS, so the entry body runs twice.
 *
 * The second run reaches `resolveAssetUrl.configure(...)` (main.js:105) after the first run has
 * already resolved an asset URL -- `images/login-logo.png`, via ThemeManager.getTheme() from
 * preloadInitialTemplates -- and that guard throws by design. Both copies share ONE resolveAssetUrl
 * instance, because it lives in a shared hashed chunk with a single URL. The throw lands inside a
 * dynamic import, so ModuleLoader.load REJECTS, and its callers are `$.when(...).then(onFulfilled)`
 * with no rejection handler (commons ProcessConfiguration.js:38). An unhandled jQuery Deferred
 * rejection is SILENT -- no `unhandledrejection` event, nothing printed. Symptom: chunks fetch
 * correctly, the console log is clean, and the admin console never paints.
 *
 * The fix is the one already proven for the other two: the root name becomes a stub, and the real
 * entry moves to a hashed chunk under assets/. The stub imports it by the SAME relative specifier
 * the view chunks use, so there is exactly one URL and one module record.
 *
 * Its stub must be a MODULE, not the classic IIFE above: index.html loads it with type="module",
 * where `document.currentScript` is null. A relative dynamic import needs no base -- it resolves
 * against the importing module's own URL, query string and all.
 */
const MODULE_LOADED_ENTRIES = new Set(["main"]);

/** Every entry whose fixed root name is owned by a stub, so its real chunk must be hashed. */
const STUBBED_ENTRIES = new Set([...REQUIREJS_LOADED_ENTRIES, ...MODULE_LOADED_ENTRIES]);

const renderEntryStub = (entryName, chunkFileName) => `/*
 * Generated by vite.config.js (xui-requirejs-entry-stubs). DO NOT EDIT -- it is rewritten on every
 * build and its content is derived from the hashed chunk name below.
 *
 * ${entryName} is an ES module, and the six openam-oauth2 FreeMarker pages load it through
 * RequireJS \`data-main\`, which injects a classic <script type="text/javascript">. This file is
 * what that <script> gets: a classic script that dynamic-imports the real module. See the
 * "OPTION (c1)" block in vite.config.js.
 */
(function () {
    "use strict";
    var chunk = ${JSON.stringify(chunkFileName)};
    var self = ${JSON.stringify(`${entryName}.js`)};
    var base = document.currentScript && document.currentScript.src;

    if (!base) {
        // Only reachable if something other than a <script src> evaluated this file.
        var scripts = document.getElementsByTagName("script");
        for (var i = scripts.length - 1; i >= 0 && !base; i--) {
            if (scripts[i].src && scripts[i].src.indexOf(self) !== -1) { base = scripts[i].src; }
        }
    }

    var url = new URL(chunk, base || document.baseURI || window.location.href).href;

    import(url)["catch"](function (error) {
        // Without this the failure is an unhandled rejection and the page just stays blank.
        console.error("[XUI] " + self + " could not load " + url, error);
    });
}());
`;

const renderModuleEntryStub = (entryName, chunkFileName) => `/*
 * Generated by vite.config.js (xui-requirejs-entry-stubs). DO NOT EDIT -- it is rewritten on every
 * build and its content is derived from the hashed chunk name below.
 *
 * index.html loads this as <script type="module" src="${entryName}.js?v=\${version}">. Its only job
 * is to import the real entry chunk by the SAME specifier the emitted view chunks use, so that the
 * cache-buster on this file's URL cannot fork the entry into two module records. See the
 * "THE CONSOLE ENTRY IS STUBBED TOO" block in vite.config.js for what that fork breaks.
 *
 * A relative specifier resolves against this module's own URL, so no document.currentScript and no
 * new URL(...) dance is needed -- and unlike the classic stubs, neither is available here.
 */
import(${JSON.stringify(`./${chunkFileName}`)}).catch(function (error) {
    // Without this the failure is an unhandled rejection and the page just stays blank.
    console.error("[XUI] ${entryName}.js could not load ${chunkFileName}", error);
});
`;

/*
 * Emitted in generateBundle rather than writeBundle because the chunk file names -- hashes included
 * -- are final there, and emitFile puts the stub through rollup's own output pipeline so it lands in
 * outDir with everything else and shows up in the build's file list.
 *
 * IT THROWS WHEN AN EXPECTED ENTRY IS ABSENT. The failure this guards against is silent in exactly
 * the way the .ftl pages cannot report: rename an input key, or drop an entry, and the six pages
 * 404 on main-authorize.js / main-device.js while this build still exits 0 -- in a different Maven
 * module, which this build does not test and which no e2e spec in this repo would reach.
 */
const requirejsEntryStubs = () => {
    let root = process.cwd();
    return {
    name: "xui-requirejs-entry-stubs",
    configResolved (config) {
        root = config.root;
    },
    generateBundle (options, bundle) {
        const stubbed = new Map();

        for (const chunk of Object.values(bundle)) {
            if (chunk.type !== "chunk" || !chunk.isEntry || !STUBBED_ENTRIES.has(chunk.name)) {
                continue;
            }
            const fileName = `${chunk.name}.js`;
            if (bundle[fileName]) {
                throw new Error(
                    `[xui-requirejs-entry-stubs] cannot emit the stub ${fileName}: the ` +
                    "bundle already contains a file at that path. build.rollupOptions.output." +
                    "entryFileNames must send every name in STUBBED_ENTRIES to a HASHED " +
                    "path under assets/, leaving the root name free for the stub."
                );
            }
            const render = MODULE_LOADED_ENTRIES.has(chunk.name)
                ? renderModuleEntryStub
                : renderEntryStub;
            this.emitFile({
                type: "asset",
                fileName,
                source: render(chunk.name, chunk.fileName)
            });
            stubbed.set(chunk.name, chunk.fileName);
        }

        /*
         * REVIEW FIX. web.xml serves /XUI/* with `Cache-Control: public, max-age=2592000`. These
         * two stubs sit at fixed URLs and embed the hashed name of the chunk they import, so
         * their content moves on nearly every build while their URL does not -- cached for a
         * month, a returning browser imports a chunk that no longer exists and the OAuth2 consent
         * page goes blank. The fix is one `excludes` entry each; this asserts it is still there,
         * because nothing else connects the two files and the failure is invisible for 30 days.
         */
        const webXml = path.resolve(root, "../../openam-server-only/src/main/webapp/WEB-INF/web.xml");
        if (fs.existsSync(webXml)) {
            const excluded = fs.readFileSync(webXml, "utf8");
            /*
             * REQUIREJS_LOADED_ENTRIES only, not every stub. `main.js` is exempt BY CONSTRUCTION,
             * not by oversight: index.html loads it as `main.js?v=${version}`, so its URL already
             * moves on every release, and web.xml excludes /XUI/ and /XUI/index.html from the same
             * filter -- so the browser always re-reads index.html and always sees the current
             * query. The two stubs below have no such query (`data-main` never carried one), which
             * is exactly why they need the exclusion and main does not.
             */
            const unexcluded = [...stubbed.keys()].filter((name) =>
                REQUIREJS_LOADED_ENTRIES.has(name) && !excluded.includes(`/XUI/${name}.js`));
            if (unexcluded.length > 0) {
                throw new Error(
                    "[xui-requirejs-entry-stubs] web.xml does not exclude these entry stubs from " +
                    `CacheForAMonth: ${unexcluded.map((n) => `/XUI/${n}.js`).join(", ")}.\n\n` +
                    "Add them to the `excludes` param of the CacheForAMonth filter. Without it a " +
                    "returning browser holds a month-old stub pointing at a chunk hash that no " +
                    "longer exists, and the OAuth2 consent and device-flow pages render blank " +
                    "after every upgrade -- with this build still green."
                );
            }
        } else {
            this.warn(
                "[xui-requirejs-entry-stubs] openam-server-only/.../web.xml not found, so the " +
                "CacheForAMonth exclusion for the entry stubs could not be verified."
            );
        }

        const missing = [...REQUIREJS_LOADED_ENTRIES].filter((name) => !stubbed.has(name));
        if (missing.length > 0) {
            throw new Error(
                "[xui-requirejs-entry-stubs] no entry chunk was emitted for: " +
                `${missing.join(", ")}.\n\n` +
                "Six FreeMarker pages in the openam-oauth2 Maven module fetch these by fixed name " +
                "through RequireJS data-main, and neither this build nor any e2e spec here loads " +
                "them -- so a missing stub is a 404 on the OAuth2 consent, OAuth2 error and " +
                "device-flow pages behind a green build. Either restore the entry in " +
                "build.rollupOptions.input under this exact key, or -- if the entry is genuinely " +
                "gone -- remove it from REQUIREJS_LOADED_ENTRIES and from those six templates in " +
                "the same change (D8 and task 10.4 say this migration does not touch them)."
            );
        }

        const missingModule = [...MODULE_LOADED_ENTRIES].filter((name) => !stubbed.has(name));
        if (missingModule.length > 0) {
            throw new Error(
                "[xui-requirejs-entry-stubs] no entry chunk was emitted for: " +
                `${missingModule.join(", ")}.\n\n` +
                "Without the stub the console entry keeps its unhashed root name, index.html and " +
                "rollup's own chunk imports name it by two different URLs, and the entry is " +
                "EVALUATED TWICE -- which fails silently through an unhandled jQuery Deferred " +
                "rejection and leaves the admin console blank. See the block above " +
                "MODULE_LOADED_ENTRIES."
            );
        }

        /*
         * REVIEW FIX. The two names above cannot be seen by this build, so they get the checks
         * higher up. main.js CAN be seen and had none: MODULE_SCRIPT_WITH_VERSION only asserted
         * that SOME module script carried the token, so renaming the `main` input key would 404
         * the whole console behind a green build -- exactly what this plugin refuses to allow for
         * main-authorize and main-device. Symmetry restored.
         */
        const indexEntry = indexHtmlModuleEntry(fs.readFileSync(
            path.resolve(root, INDEX_HTML_SOURCE), "utf8"));
        const emittedStub = (name) => stubbed.has(name.replace(/\.js$/, ""));
        if (indexEntry && !indexEntry.startsWith("http") &&
                !bundle[indexEntry] && !emittedStub(indexEntry)) {
            throw new Error(
                `[xui-requirejs-entry-stubs] ${INDEX_HTML_SOURCE} loads "${indexEntry}", but the ` +
                "bundle emits no file at that path.\n\nindex.html names the console entry as a " +
                "literal string, so a renamed build.rollupOptions.input key -- or an " +
                "entryFileNames that hashes it -- 404s the entire admin console with the build " +
                "still green. Keep the two in step, or update index.html in the same change."
            );
        }

        this.info(
            `emitted ${stubbed.size} entry stubs: ` +
            [...stubbed].map(([name, target]) => `${name}.js -> ${target}`).join(", ") +
            `; index.html entry "${indexEntry}" present in bundle`
        );
    }
    };
};

const xuiStaticAssets = () => {
    let root = process.cwd();
    let configuredOutDir = "";
    return {
        name: "xui-static-assets",
        /*
         * Build only. Under `npm run dev` none of this runs, so every theme, template, partial,
         * locale and stylesheet 404s -- and so does index.html, which since 4.5 is emitted by
         * stampIndexHtml rather than existing at the project root where Vite's dev server looks
         * for it. That is expected, not a bug: serving them in dev needs configureServer
         * middleware over the same composed sources, and it belongs with TASK 4.10, which owns
         * the dev server. Nothing here presumes its shape.
         */
        apply: "build",
        configResolved (config) {
            root = config.root;
            configuredOutDir = path.resolve(config.root, config.build.outDir);
        },
        buildStart () {
            /*
             * BEFORE assertSourcesPresent, not after: target/npm-libs is a composition source and
             * this is what creates it, so asserting first would fail on a directory this call is
             * about to write. Staging first also means a pruned node_modules is reported as the
             * named library file that is missing, which is the actionable message.
             */
            const staged = stageNpmLibraries(root);
            this.info(`staged ${staged} runtime library files from node_modules into ${NPM_LIBRARY_STAGE}`);
            assertVendoredVersions(root);
            assertSourcesPresent(root);
            /*
             * Read-and-check here, stamp in writeBundle. Both hooks read the file (983 bytes,
             * twice, once per build) and that is the point: the token check is worthless in
             * writeBundle, which runs AFTER rollup has emitted the bundle, after 263 files have
             * been copied and after 3 stylesheets have been compiled. Failing in buildStart costs
             * ~30s less and leaves no half-written tree in outDir.
             */
            readIndexHtmlSource(root);
            /*
             * The token guard above protects the case where ${version} vanishes from the SOURCE.
             * This is the other half of the same failure and, on the evidence, the likelier one:
             * `targetVersion` falls back to "dev" when TARGET_VERSION is unset, so if the
             * <TARGET_VERSION>${project.version}</TARGET_VERSION> wiring in the pom's npm-build
             * execution is ever dropped or renamed, this build keeps exiting 0 and stamps
             * `v=dev` into a production tree. Every release then shares one cache key and the
             * first symptom is a client serving a stale template after an upgrade -- exactly what
             * D4 exists to prevent, arrived at from the opposite direction.
             *
             * A warning and not a throw, deliberately. The "dev" default is a faithful port of
             * Gruntfile.js:45 and has to survive: 4.10's dev server needs a version when Maven is
             * not driving the build, and a standalone `npx vite build` is a legitimate thing to
             * run. This costs nothing when the pom is wired -- and note `apply: "build"` above,
             * so `npm run dev` never reaches this hook and gets no spurious warning either.
             */
            if (!process.env.TARGET_VERSION) {
                this.warn(
                    `TARGET_VERSION is unset, so ${INDEX_HTML} will be stamped "v=${targetVersion}". ` +
                    "In a released build every deploy would then share one cache key and clients " +
                    "would serve stale templates after an upgrade (design.md D4). Maven sets this " +
                    "from ${project.version} in the npm-build execution; see pom.xml."
                );
            }
        },
        async writeBundle (options) {
            /*
             * options.dir is what rollup is actually writing to. configuredOutDir is the same
             * value via build.outDir and is the fallback rather than a repeated "target/compiled"
             * literal, so this cannot drift out of step with the build config.
             */
            const outDir = options.dir || configuredOutDir;
            const shipped = composeStaticAssets(root, outDir);
            /*
             * TASK 4.7. Independent of composeStaticAssets: that pass ships what nonCompiledFiles
             * selects, and .js is deliberately not in that set. See copyLibraries.
             */
            const libraries = copyLibraries(root, outDir);
            const literalPaths = assertLiteralPathLibraries(root, libraries);
            const stylesheets = await renderStylesheets(root, outDir);
            /*
             * After composeStaticAssets, not before. index.html is excluded from the verbatim
             * copy by NOT_COPIED, so the two cannot collide today -- but the source tree that
             * copy walks is the same one this reads, and an ordering where the unfiltered copy
             * could land last would ship a literal ${version}. Keeping the stamp last means the
             * exclusion and the ordering both have to fail before that can happen.
             */
            const indexHtml = stampIndexHtml(root, outDir);
            this.info(
                `copied ${shipped.size} static files verbatim and ${libraries.size} runtime ` +
                `libraries (${literalPaths} of them named by literal AMD path), compiled ` +
                `${stylesheets.length} stylesheets and stamped ${indexHtml} with version ` +
                `${targetVersion}, into ${path.relative(root, outDir)}`
            );
        }
    };
};

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
         * 15 .jsx files under src/main/js. The note 4.3 left here read: this plugin's default
         * include is /\.[tj]sx?$/, which does NOT match .jsm, and widening it is part of the
         * .jsm work below.
         *
         * 5.1 DELIBERATELY DID NOT WIDEN IT, and that is a measurement rather than an omission.
         * All 31 .jsm files were handed to esbuild with loader: "js". Every one of them parsed.
         * A .jsx file put through the identical probe was rejected -- "The JSX syntax extension
         * is not currently enabled" -- so the probe does detect JSX; it simply is not there.
         * NO .jsm FILE CONTAINS JSX. Widening `include` would add a permanent knob that
         * transforms nothing, and an unnecessary knob is a puzzle for whoever reads this next.
         * If a .jsm ever gains JSX, this is the line that has to change -- rerun that probe
         * before believing it already does.
         *
         * The same measurement is why no esbuild loader mapping was added for .jsm either --
         * BUT READ THE NEXT PARAGRAPH BEFORE REUSING THAT SENTENCE. Vite 5's vite:esbuild
         * TRANSFORM has default include /\.(m?ts|[jt]sx)$/ (node_modules/vite/dist/node/chunks/
         * dep-BK3b2jBa.js:19267), so a .jsm is never routed to THAT PLUGIN, and Rollup parses
         * plain ESM whatever the extension. For `vite build` that is the whole story and no
         * loader mapping is needed.
         *
         * IT DOES NOT GENERALISE TO THE DEV SERVER, AND 4.10 IS WHO THAT COSTS. vite:esbuild is
         * not Vite's only esbuild pass. The dependency scanner is a second one, and it excludes
         * .jsm independently and for a different reason: isScannable (dep-BK3b2jBa.js:49918)
         * tests JS_TYPES_RE, which is /\.(?:j|t)sx?$|\.mjs$/ (constants.js:41) -- .mjs yes,
         * .jsm no. A module that is not scannable comes back as externalUnlessEntry, so
         * pre-bundling STOPS CRAWLING at every .jsm boundary and never sees the imports beyond
         * it. Vite ships a purpose-built knob for exactly this and nothing here sets it:
         * optimizeDeps.extensions: [".jsm"]. This config declares no optimizeDeps at all.
         *
         * Why 5.1 leaves it alone rather than setting it blind: initDepsOptimizer is reached
         * from createServer (dep-BK3b2jBa.js:63401) and from nowhere in the build path, so this
         * is dev-server-only, and 4.10 owns server.*. SERVING a .jsm already works, which is
         * worth recording because it is not obvious and the trace is a nuisance to rediscover:
         * .jsm fails knownJsSrcRE (:16837), so isExplicitImportRequired returns true (:64157),
         * so import analysis appends ?import (:64333), and the transform middleware then picks
         * it up via isImportRequest (:62092). So the dev-server exposure is degraded
         * pre-bundling, not a failure to serve.
         *
         * resolve.extensions below is the only RESOLUTION knob 5.1 sets, and the 5.1 spike is
         * what says so. jsxRuntime, immediately below, is the one TRANSFORM knob it sets, and
         * the same spike is what forced it.
         *
         * ==== 5.1 -- jsxRuntime: "classic". FORCED, NOT CHOSEN ====
         *
         * The spike surfaced this the moment .jsm resolution started working and it could reach
         * a .jsx at all:
         *
         *   [vite]: Rollup failed to resolve import "react/jsx-runtime" from
         *   .../admin/views/realms/sessions/SessionsTable.jsx
         *
         * @vitejs/plugin-react 4.7.0 defaults to jsxRuntime: "automatic", which rewrites JSX to
         * an import of react/jsx-runtime. This module's react is 15.2.1, which predates that
         * entry point entirely -- its package directory is react.js, lib/ and dist/, with no
         * jsx-runtime -- so "automatic" cannot work here at all. "classic" emits
         * React.createElement instead, and all 15 .jsx files already `import React` at the top
         * (checked, all 15), so nothing else has to change. There is no judgement in this
         * setting: with react 15 it is the only value that transforms.
         *
         * AND IT IS LOAD-BEARING IN A SECOND, LESS OBVIOUS WAY. Node disagrees with Vite about
         * this specifier. `require.resolve("react/jsx-runtime")` from this directory SUCCEEDS --
         * it walks up and lands on OpenAM/openam-ui/node_modules/react, which is 19.2.7. Vite's
         * resolver stops at the first react package it finds and fails instead. Vite is right:
         * had it walked up, the build would have gone green while linking React 19's jsx-runtime
         * against React 15's react, which is a runtime break that no build step would have
         * reported. Same shadowing hazard as the engine pin at the top of this file, same
         * parent node_modules, and a second reason not to trust that tree.
         *
         * Whoever moves this module off react 15 should revisit this line and not merely inherit
         * it. That is NOT 5.3: 5.3 kept react-select at 1.0.0-rc.2 per design.md's Non-Goals and
         * removed the window globals by resolving it to its by-name package main, which changes
         * no version. The nearest owner is whoever takes the React upgrade itself.
         */
        react({ jsxRuntime: "classic" }),

        /*
         * 5.2. Must run BEFORE @rollup/plugin-commonjs converts these two files, hence
         * enforce: "pre" on the plugin itself. See SLOPPY_MODE_PATCHES above for what it rewrites
         * and why patching at build time was chosen over patching the bytes on disk.
         */
        sloppyModeLibraries(),
        assertAliasOrdering(),
        assertAliasedLibrariesBundled(),
        assertSideEffectsPinned(),

        /*
         * 5.3. Config-time only. Guards the ABSENCE of a react-select / react-input-autosize
         * alias, which is what lets both resolve to a by-name package main and makes the four
         * window globals unnecessary. Defined above; the measurement is NOTES-shims.md 3.2 B.
         */
        assertReactSelectNeedsNoGlobals(),

        /*
         * 7.2. Bundle-time only. Reads config/AppConfiguration.js, walks the 26 module ids it
         * names by string, and fails the build naming any one no emitted chunk carries.
         * Nothing imports those modules statically, so without this a rename is a green build
         * and a broken route. Defined above, with why it is not a runtime or eager check.
         */
        assertConfiguredModulesBundled(),

        /*
         * 5.4/B12. Option (c1). Emits the two unhashed classic-script stubs the six openam-oauth2
         * .ftl pages fetch through RequireJS data-main, each dynamic-importing the hashed ES chunk
         * that entryFileNames below sends under assets/. Defined above, with the costing of the
         * options that were not taken.
         */
        requirejsEntryStubs(),

        /*
         * 4.4. Replays Grunt's copy:compose + copy:compiled passes in writeBundle. Defined above
         * this config object; the reasoning, the source order and the LESS decision are all in
         * the comments there and in NOTES-static-assets.md.
         */
        xuiStaticAssets()
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
        alias: [
            /*
             * 1. ThemeManager -- AM's own module. Bound identically by all three entries
             * (main.js:22, main-authorize.js:30, main-device.js:21). Consumers: ui-commons
             * main/AbstractView.js:26 and util/UIUtils.js:24 as define deps, plus
             * main-authorize.js:65 and main-device.js:60 in the entry require arrays. One of the
             * four identifiers ui-commons/NPM-PACKAGE.md lists under "Identifiers the consumer
             * must supply".
             */
            {
                find: "ThemeManager",
                replacement: fromSrc("org/forgerock/openam/ui/common/util/ThemeManager.js")
            },

            /*
             * 2. NavigationFilter -- AM's own module. main.js:28, main only. Exactly one consumer:
             * ui-commons components/Navigation.js:27. Also on NPM-PACKAGE.md's must-supply list.
             */
            {
                find: "NavigationFilter",
                replacement: fromSrc(
                    "org/forgerock/openam/ui/common/components/navigation/filters/RouteNavGroupFilter.js")
            },

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
             * two secondary entries request the ALIASED name themselves (as of 5.4/B12,
             * `import Router from "Router"` at main-authorize.js:62 and main-device.js:50 -- the
             * conversion deliberately kept the aliased id rather than reaching past it to
             * SingleRouteRouter, so this property survives the ESM rewrite), so under a global
             * alias the entries and ThemeManager always receive the same object and cannot
             * diverge:
             *
             *   main-authorize.js / main-device.js   Router.currentRoute = {navGroup:"user"}
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
             * NEITHER secondary entry's paths block (before 5.4/B12 deleted them, they listed
             * only handlebars, i18next, jquery, lodash, redux, text), so this is a dependency those
             * two bundles have never carried. B12 measured the cost: the two secondary chunks are
             * 1.42 kB and 0.93 kB, and the shared chunk they and main.js all pull is 332 kB. Import-time side effects
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
             * only the two secondary specs. STILL UNVERIFIED after 5.4/B12: the build now walks 563
             * real modules and exits 0, which is a resolution proof, not an execution proof.
             *
             * CONSEQUENCE: SingleRouteRouter.js is now dead code. Its only two references were the
             * `map` blocks of main-authorize.js and main-device.js, both superseded by this entry
             * and both deleted outright by 5.4/B12. It is NOT deleted here -- deleting it is a source change 4.3 was not asked to make, and group
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
            {
                find: "Router",
                replacement: "@openidentityplatform/ui-commons/esm/org/forgerock/commons/ui/common/main/Router.js"
            },

            /*
             * 4. KBADelegate -- AM's own module. main.js:31, main only. Exactly one consumer:
             * ui-user profile/UserProfileKBATab.js:26. Note that UserProfileKBATab is itself
             * reached only by a runtime require([...]) at AM SiteConfigurationService.js:32, gated
             * on serverInfo.kbaEnabled === "true", so this alias is exercised only down a
             * conditional dynamic-import path and will not show up in a default build graph.
             */
            {
                find: "KBADelegate",
                replacement: fromSrc("org/forgerock/openam/ui/user/services/KBADelegate.js")
            },

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
            {
                find: "UserProfileView",
                replacement: "@openidentityplatform/ui-user/esm/org/forgerock/commons/ui/user/profile/UserProfileView.js"
            },

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
             * devDependency. (When 4.3 wrote this, package.json had NO `dependencies` key at all;
             * TASK 4.7 ADDED ONE, 31 runtime libraries. Re-checked there: lodash is still absent
             * from it, no dependency of it pulls a lodash in, and no AM source imports a `lodash/`
             * subpath -- so the prefix-capture alias below is still harmless and this reasoning
             * still holds. 8.3 is where it stops holding.) Writing it that way would silently perform
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
            { find: "underscore", replacement: fromSrc("libs/lodash-3.10.1-min.js") },

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
            { find: "lodash", replacement: fromSrc("libs/lodash-3.10.1-min.js") },

            /*
             * 5.4/B7 -- D23. CodeMirror by LITERAL libs/ path.
             *
             * admin/views/realms/scripts/EditScriptView.js is the only consumer in the tree and it
             * names all four files by literal AMD path (`libs/codemirror/lib/codemirror`,
             * `mode/groovy/groovy`, `mode/javascript/javascript`, `addon/display/fullscreen`).
             * Those ids never pass through main.js's require.config.paths, so nothing else could
             * redirect them -- which is why the source file needs no edit and the ids stay spelled
             * exactly as they are.
             *
             * ONE PREFIX COVERS ALL FOUR. The sub-paths under libs/codemirror/ are byte-for-byte
             * the sub-paths under the npm package, which is what makes a prefix legal here rather
             * than four separate entries. codemirror@4.10.0 is installed and is the same source
             * NPM_LIBRARY_FILES already stages -- 4.8 measured all four md5-identical between the
             * npm package and PHASE1-TREE.md:251-254, so no bytes move.
             *
             * WHY NOT fromPkg. require.resolve() honours "exports", and this must resolve a
             * DIRECTORY so the four sub-paths continue past it; the same reason the D19 prefixes
             * below use fromPkgPath.
             *
             * THE -4 DELTA IS TAKEN, and it was taken only after a build proved the replacement.
             * B7's verification build has CodeMirror in the graph as four real modules, with the
             * three mode/ and addon/ UMD factories provably attaching to ONE core instance
             * (`(function(X){X(Gi())})(...)`, Gi being the memoised factory for lib/codemirror.js,
             * which appears exactly once). 154.8 kB min / 52.5 kB gzip as its own chunk.
             *
             * So the four libs/codemirror rows are gone from NPM_LIBRARY_FILES and
             * LITERAL_PATH_LIBRARY_CONSUMERS is empty -- see the note on that constant for why the
             * three edits are one edit. PHASE1-TREE.md is -4 against this build by design.
             */
            { find: "libs/codemirror", replacement: fromPkgPath("codemirror") },

            /*
             * ================================================================================
             * ==== 5.4/B0 -- D19's ID SPACE: THE FIVE PREFIXES AND THE SEVEN config/** IDS ====
             * ================================================================================
             *
             * READ NOTES-amd-to-esm.md SECTION 3 IN THIS DIRECTORY BEFORE CHANGING ANYTHING BELOW.
             * Every entry here is measured there, end to end: a scratch entry importing one id
             * from each family was built through a copy of this config with the table in place,
             * with a resolveId catcher logging any bare id nothing resolved. Exit 0, 560 modules,
             * one deliberate miss (`dataTable`, a pre-existing break -- see section 2c, decided in
             * batch B9).
             *
             * WHAT THIS IS FOR. D19 keeps the ES tree speaking the AMD id space: a converted module
             * imports "org/forgerock/commons/ui/common/main/Router", not a package specifier, so
             * that amd/ and esm/ remain provably the same modules under the same names and a
             * product can still redirect ONE commons module by moving ONE alias entry. The cost
             * D19 accepts is precisely this table -- the ES tree does not resolve without it.
             *
             * IT IS NOT ONLY 5.4's DEBT. The 46 .jsm/.jsx files task 5.1 wired up import by bare
             * id too ("org/forgerock/openam/...", "components/Card", "store/index"), and nothing
             * has resolved them until now; 5.1 was green because rollupOptions.input names only the
             * three still-AMD entries, so Rollup never walked into them (NOTES-amd-to-esm.md 5a).
             *
             * ONE HOP. @rollup/plugin-alias does not re-enter itself, so a replacement gets exactly
             * one chance. Each of these lands on an absolute filesystem path and normal resolution
             * finishes the job -- resolve.extensions (below, with .jsm and .jsx from 5.1) supplies
             * the extension the extensionless AMD id omits.
             *
             * ORDERING. A string `find` matches the id exactly or as a path prefix, and the first
             * match wins, so the seven commons config/** ids MUST stay above anything that could
             * capture them. xui-assert-alias-ordering enforces that mechanically at config time.
             */

            /*
             * B0.1 -- AM's own tree. 131 distinct ids, and it also covers server/util/QRCodeReader
             * because that id sits under org/forgerock/openam too.
             *
             * IDENTITY WITH ENTRIES 1 AND 2 ABOVE. ThemeManager and NavigationFilter are aliased
             * by bare name for commons to reach, AND are reachable through this prefix by their
             * full ids from AM's own 49 sites. Both routes land on the same absolute path under
             * src/main/js, so they are one module. If they ever diverge, ThemeManager reads a
             * second copy of itself -- the same class of silent failure the Router note below
             * describes, arriving from AM's side.
             */
            { find: "org/forgerock/openam", replacement: fromSrc("org/forgerock/openam") },

            /*
             * B0.2 and B0.3 -- the two commons packages. 28 ids and 8 ids respectively.
             *
             * THIS IS THE POINTER THE Router NOTE ABOVE WARNS ABOUT, and the hazard is real:
             * entry 3 reaches Router through the package specifier
             * "@openidentityplatform/ui-commons/esm/.../Router.js" while all 49 AM sites and every
             * commons module reach it through the bare id, i.e. through this prefix. Point this at
             * anything but the SAME PHYSICAL esm/ tree -- the package's amd/ build, a vendored
             * copy -- and there are two Routers: ThemeManager.js:168 then reads one whose
             * currentRoute is never written, {}.navGroup !== "admin", and the admin theme silently
             * stops being applied with a green build and no warning.
             *
             * MEASURED, NOT ASSUMED (NOTES-amd-to-esm.md 3b). A probe importing the same module
             * both ways was built: the emitted bundle contains one copy of the Router source and
             * one binding on both sides. node_modules/@openidentityplatform/ui-commons is a real
             * directory here and not a symlink, so realpath dedup is not what is doing the work --
             * the two resolved paths are simply the same string.
             *
             * Note that the exports map would have blocked an amd/ mistake for the package-
             * specifier form of entry 3. It does NOT block it for a filesystem path like this one.
             * The safety here is this comment and section 3b, not the package manifest.
             */
            {
                find: "org/forgerock/commons/ui/common",
                replacement: fromPkgPath("@openidentityplatform/ui-commons/esm/org/forgerock/commons/ui/common")
            },
            {
                find: "org/forgerock/commons/ui/user",
                replacement: fromPkgPath("@openidentityplatform/ui-user/esm/org/forgerock/commons/ui/user")
            },

            /*
             * B0.4 and B0.5 -- AM's Redux store and its React component directory. Reached only
             * from the 46 .jsm/.jsx files (store/index, store/actions/creators, and five
             * components/ ids), which is why neither has been needed before 5.1 landed.
             *
             * These two are the only entries in this block whose blast radius reaches OUTSIDE AM's
             * source tree. Every other id here is namespaced (org/forgerock/**, config/**); "store"
             * and "components" are unqualified, and resolve.alias applies to every importer, node_
             * modules included. "store" is also a real, widely depended-on npm package name, so a
             * future transitive dependency that imports it would be redirected into AM's Redux
             * store -- silently, with a green build and a wrong module at runtime.
             *
             * MEASURED, NOT ASSUMED, and worth re-measuring whenever a dependency is added:
             * neither node_modules/store nor node_modules/components exists, and grepping both
             * @openidentityplatform packages for a bare "store/" or "components/" specifier
             * returns zero. Safe today because nothing else claims the names.
             */
            { find: "store", replacement: fromSrc("store") },
            { find: "components", replacement: fromSrc("components") },

            /*
             * B0.6 -- THE SEVEN COMMONS config/** IDS, INDIVIDUALLY. D19 forbids the wholesale
             * "config/" prefix that would be one line instead of eight: the five shipped ui-commons
             * config modules are leaves the PRODUCT composes, and a prefix alias would also capture
             * AM's own config/AppConfiguration and config/ThemeConfiguration and point them into
             * the package -- inverting the customization route D6 replaces, so that editing AM's
             * AppConfiguration would stop having any effect.
             *
             * THE LIST IS CONFIRMED FROM THE INSTALLED PACKAGES, not from prose:
             * `find node_modules/@openidentityplatform/ui-commons/esm/config -type f` returns
             * exactly these five, ui-user/esm/config exactly these two, and ui-commons'
             * NPM-PACKAGE.md:192-205 ("The alias does not reach config/") lists the same five.
             * Seven -- which is also the number of commons dependencies in AM's own config/main.js
             * (section 3d, rewritten to these bare ids in batch B11).
             */
            {
                find: "config/errorhandlers/CommonErrorHandlers",
                replacement: fromPkgPath("@openidentityplatform/ui-commons/esm/config/errorhandlers/CommonErrorHandlers.js")
            },
            {
                find: "config/validators/CommonValidators",
                replacement: fromPkgPath("@openidentityplatform/ui-commons/esm/config/validators/CommonValidators.js")
            },
            {
                find: "config/routes/CommonRoutesConfig",
                replacement: fromPkgPath("@openidentityplatform/ui-commons/esm/config/routes/CommonRoutesConfig.js")
            },
            {
                find: "config/messages/CommonMessages",
                replacement: fromPkgPath("@openidentityplatform/ui-commons/esm/config/messages/CommonMessages.js")
            },
            {
                find: "config/process/CommonConfig",
                replacement: fromPkgPath("@openidentityplatform/ui-commons/esm/config/process/CommonConfig.js")
            },
            {
                find: "config/routes/UserRoutesConfig",
                replacement: fromPkgPath("@openidentityplatform/ui-user/esm/config/routes/UserRoutesConfig.js")
            },
            {
                find: "config/messages/UserMessages",
                replacement: fromPkgPath("@openidentityplatform/ui-user/esm/config/messages/UserMessages.js")
            },

            /*
             * B0.7 -- AM's own config/AppConfiguration, which MUST be an alias and cannot be left
             * to a relative specifier: ui-commons/esm/.../main/Configuration.js:19 imports it by
             * this bare id, and AM cannot edit a file inside the package. This is one of the four
             * AM -> commons -> AM edges section 2f describes; they are edges, not cycles (the graph
             * has zero), and they are why config/AppConfiguration.js, ThemeManager.js and
             * RouteNavGroupFilter.js are converted first, in batch B1.
             *
             * B0.8 -- config/ThemeConfiguration. NOTES-amd-to-esm.md 3a says this one needs no
             * alias, because its only importer is AM's own common/util/ThemeManager.js:20 and a
             * relative specifier would resolve natively. It is here anyway, and deliberately: D19
             * keeps the ES tree speaking the AMD id space, and task 5.4's conversion rule is that
             * an import keeps the id the define dep array used. The relative form that would save
             * this entry is `../../../../../../../config/ThemeConfiguration.js` -- seven levels of
             * ../ that say nothing about what is being imported, and the one spelling in the tree
             * that a later move of either file breaks silently. So the table is FOURTEEN entries,
             * not the thirteen section 3a counts; that is the only place this batch departs from
             * the survey, and it departs by adding, not by removing.
             *
             * config/main still needs no alias -- its only importer is main.js:278, which batch
             * B12 converts, and section 3d gives that file its own treatment.
             *
             * B12 CONFIRMED THAT AND CHOSE THE RELATIVE FORM: `import "./config/main.js"`. main.js
             * sits at the module-tree root, so the relative specifier is one level and reads
             * plainly -- the opposite of the seven-../ chain that put config/ThemeConfiguration in
             * the table above. Nothing else in the tree imports config/main, so no second spelling
             * of it exists to disagree with this one.
             */
            { find: "config/AppConfiguration", replacement: fromSrc("config/AppConfiguration.js") },
            { find: "config/ThemeConfiguration", replacement: fromSrc("config/ThemeConfiguration.js") },

            /*
             * ================================================================================
             * ==== 5.2 -- THE RUNTIME LIBRARY BINDINGS: main.js's paths AND shim BLOCKS    ====
             * ================================================================================
             *
             * READ NOTES-shims.md IN THIS DIRECTORY BEFORE CHANGING ANYTHING BELOW. It has the
             * 45-row per-library table (id, where its bytes come from today, installed version,
             * module formats, specifier, disposition, importer count), the six ordering
             * constraints, and the evidence for each. Everything here is measured from the
             * installed bytes; nothing is taken from the shim's `exports` field, which is dead
             * or wrong for 14 of the 26 entries.
             *
             * WHAT THIS BLOCK REPLACES. RequireJS's `require.config` in main.js:36-172 (and the
             * smaller copies in main-authorize.js and main-device.js) did two jobs: `paths`
             * mapped an id to a file, and `shim` declared load order and a global to pick up.
             * `paths` becomes the alias entries below. `shim` mostly evaporates -- the libraries'
             * own CommonJS `require()` calls re-declare it, so the import graph reproduces it for
             * free -- except for six constraints that a global carried and no import edge does.
             * Those live in src/main/js/shims/, one small file per id, aliased in front of it.
             * See that directory's README.md.
             *
             * THE main.js BLOCKS ARE DELIBERATELY LEFT IN PLACE. The tree is still AMD until 5.4
             * converts it, and deleting the loader config now would break it for no gain. Each
             * block carries a comment naming the entries here that will take over.
             *
             * THE TWO REACT ROWS ARE STILL NOT HERE, AND 5.3 SETTLED THAT THEY NEVER WILL BE.
             * 5.2 left `react-input-autosize` and `react-select` to TASK 5.3, with the
             * measurement in NOTES-shims.md section 3.2 B: the installed react-select 1.0.0-rc.2
             * dist reads window.React, window.ReactDOM, window.classNames and window.AutosizeInput
             * SYNCHRONOUSLY at file evaluation, while the package's own `main` (lib/Select.js)
             * requires all four BY NAME and needs no globals at all. 5.3 took the second: both
             * ids resolve as bare npm specifiers to their package main, so an ALIAS HERE WOULD BE
             * THE BUG rather than the fix. assertReactSelectNeedsNoGlobals, registered in
             * `plugins` above, fails the build if one is ever added. The synthetic
             * `reactAutosizeInputDep` / `reactSelectDep` modules in main.js stay until 5.4 deletes
             * require.config with the rest -- the tree is still AMD, so they are still load-bearing
             * there; the comment above them records that.
             *
             * ---- WHY THE AMD ID SPACE IS KEPT, AND WHY IT IS NOT A STYLE CHOICE --------------
             *
             * Nine of these ids are not npm package names. It would be possible to let 5.4 rewrite
             * each call site to the npm name and skip the alias -- but only for AM's own source.
             * THE COMMONS PACKAGES DECIDE THIS, NOT AM. Their published esm/ trees import
             * third-party libraries by the SAME AMD ids (measured across both packages: jquery 45,
             * underscore 28, lodash 20, backbone 8, handlebars 5, form2js 5, react 4, js2form 3,
             * moment 2, i18next 2, react-dom 2, and one each of xdate, spin, dragula, placeholder,
             * bootstrap, bootstrap-dialog, backgrid, backgrid-filter, backgrid-selectall,
             * backgrid.paginator, backbone.paginator). AM cannot edit those files, so `spin`,
             * `backgrid-selectall`, `bootstrap-dialog`, `i18next` and `bootstrap` MUST resolve as
             * written no matter what AM's own source does. Given that, the change owner chose to
             * alias the whole id space rather than leave a split one where `spin` is aliased and
             * `qrcode` is not: it makes 5.4 a mechanical define()->import rewrite with no
             * specifier renaming, and it keeps one answer to "what does this name mean".
             *
             * ---- ONE "NOTHING NEEDED" ID IS NOT QUITE NOTHING: backgrid-filter -------------
             *
             * backgrid-filter needs no alias and no shim, but it does not resolve to what the AMD
             * build loaded. Its CommonJS branch (node_modules/backgrid-filter/backgrid-filter.js
             * :15-19) wraps require("lunr") in a try/catch; @rollup/plugin-commonjs hoists that
             * into a static import, and lunr IS installed as backgrid-filter's own dependency.
             * Under RequireJS the AMD branch at :12 passes three arguments, so lunr is undefined
             * today and Backgrid.Extension.LunrFilter is inert. After 5.4 it resolves and ~56 KB
             * of lunr joins the bundle. Nothing in AM or in either commons package references
             * LunrFilter, so this is dead payload rather than a behaviour change -- but it is
             * payload the Grunt tree never carried, so group 8 should not be surprised by it.
             *
             * ---- PREFIX CAPTURE: WHY FOUR IDS APPEAR TWICE ----------------------------------
             *
             * Vite hands this object to @rollup/plugin-alias, whose matcher is
             *
             *     if (importee === pattern) return true;
             *     return importee.startsWith(pattern + "/");
             *
             * so the key "jquery" also captures "jquery/dist/jquery.js". That matters because the
             * shims have to import the real library, and the obvious spelling is exactly that
             * subpath. Measured: with only the bare key present, the build fails with
             *
             *     Could not load .../src/main/js/shims/jquery.js/dist/jquery.js
             *     (imported by src/main/js/shims/jquery.js): ENOTDIR
             *
             * @rollup/plugin-alias takes the FIRST matching entry (`entries.find(...)`) and
             * JavaScript objects preserve insertion order, so the fix is to list the specific
             * file key BEFORE the bare id. That is why jquery, backbone, bootstrap and i18next
             * each have two entries, specific first, and why they are resolved through fromPkg
             * rather than written as strings -- an absolute path cannot be prefix-captured by
             * anything, so the pair cannot be silently reordered by a later edit.
             *
             * IF YOU ADD AN ENTRY HERE, check it against every existing key for that startsWith
             * relationship. The ones that look dangerous and are NOT: "spin" does not capture
             * "spin.js", "qrcode" does not capture "qrcode-generator", "bootstrap" does not
             * capture "bootstrap-dialog"/"bootstrap-tabdrop"/"bootstrap-datetimepicker", and
             * "backbone" does not capture "backbone.paginator" -- all of them because the
             * matcher requires a "/" after the pattern, and none of these has one.
             */

            // -- the four specific-file keys, which MUST precede their bare ids (see above) ----
            { find: "jquery/dist/jquery.js", replacement: fromPkg("jquery/dist/jquery.js") },
            { find: "backbone/backbone.js", replacement: fromPkg("backbone/backbone.js") },
            { find: "bootstrap/dist/js/bootstrap.js", replacement: fromPkg("bootstrap/dist/js/bootstrap.js") },
            { find: "i18next/lib/dep/i18next.min.js", replacement: fromPkg("i18next/lib/dep/i18next.min.js") },

            /*
             * ---- (4) A GLOBAL MUST BE ASSIGNED BEFORE THE LIBRARY EVALUATES -----------------
             *
             * jQuery's CommonJS branch is `module.exports = e.document ? t(e,!0) : ...` -- it
             * passes noGlobal = true, so `ie.jQuery = ie.$ = ce` never runs and window.jQuery is
             * undefined. An ES module build always takes that branch. Nine ids read the global at
             * EVALUATION time; `bootstrap` throws loudly and `i18next` fails silently, which is
             * the worse of the two. shims/jquery.js restores the assignment, and every id below
             * that needs it imports that shim rather than trusting some earlier module to have
             * done it. 170 declarers.
             */
            { find: "jquery", replacement: fromSrc("shims/jquery.js") },

            /*
             * Backbone's CommonJS branch passes THREE arguments where the AMD branch passes four,
             * and the fourth is jquery -- so `Backbone.$` is undefined and every View loses
             * `this.$el`. Setting window.jQuery does not help; that branch never reads a global.
             * It needs an assignment after the import, which is the one thing an import graph
             * cannot express. 51 declarers, and the whole backgrid/backbone family inherits it.
             */
            { find: "backbone", replacement: fromSrc("shims/backbone.js") },

            /*
             * Bootstrap: 12 plugin IIFEs reading the free `jQuery` global, behind an explicit
             * `throw new Error("Bootstrap's JavaScript requires jQuery")`. The shim also pins the
             * concatenated dist/js/bootstrap.js that AM ships -- bare "bootstrap" resolves to
             * dist/js/npm.js, a different file that requires the 12 plugins separately.
             */
            { find: "bootstrap", replacement: fromSrc("shims/bootstrap.js") },

            /*
             * i18next has BOTH problems. Bare "i18next" resolves to the NODE build
             * (lib/i18next.js, which requires fs/cookies) -- measured, that builds successfully
             * and produces a 636 kB bundle pulling in express, keygrip, router and serve-static,
             * exit code 0, useless in a browser. The browser build is lib/dep/i18next.min.js,
             * 32 kB, which is what NPM_LIBRARY_FILES already stages. And it reads
             * `A.jQuery||A.Zepto` at evaluation, falling back silently to its own extend/each/ajax
             * and never registering $.t or $.fn.i18n. 15 declarers.
             */
            { find: "i18next", replacement: fromSrc("shims/i18next.js") },

            /*
             * The remaining jQuery-plugin rows. Each ends by reading the free global at
             * evaluation -- `}(jQuery)`, `}(window.jQuery)` -- and registers itself onto `$.fn`.
             * Their shims import shims/jquery.js first and hand back `$`, which is how every
             * consumer actually reaches them; the `exports` fields the AMD shim declared for
             * autosizeInput, clockPicker and doTimeout all resolved to undefined already, because
             * the files set $.fn.* and never a window property.
             *
             * bootstrap-tabdrop and popoverclickaway go through shims/bootstrap.js instead,
             * because they need $.fn.popover / the Bootstrap tab plugin, not just jQuery.
             * popoverclickaway is the one ordering constraint NO SHIM EVER ENCODED -- it is a bare
             * `paths` row at main.js:65 that reads `$.fn.popover.defaults` at evaluation and
             * worked only because its three consumers happened to load after AbstractView.
             */
            { find: "autosizeInput", replacement: fromSrc("shims/autosize-input.js") },
            { find: "doTimeout", replacement: fromSrc("shims/do-timeout.js") },
            { find: "bootstrap-tabdrop", replacement: fromSrc("shims/bootstrap-tabdrop.js") },
            { find: "popoverclickaway", replacement: fromSrc("shims/popover-clickaway.js") },
            { find: "sortable", replacement: fromSrc("shims/sortable.js") },
            { find: "clockPicker", replacement: fromSrc("shims/clockpicker.js") },

            /*
             * jsonEditor is a plain IIFE ending `window.JSONEditor = g`: no CommonJS branch, no
             * AMD branch, no ES export of any kind. `exports: "JSONEditor"` was one of only TWO
             * genuinely load-bearing exports fields in the entire shim block (the other is
             * i18next -> i18n); the shim re-exports the global so consumers get a value.
             */
            { find: "jsonEditor", replacement: fromSrc("shims/json-editor.js") },

            /*
             * The vendored backgrid.paginator fork's UMD prologue uses a COMMA where a stock UMD
             * uses `else if`, so under CommonJS it runs module.exports AND THEN calls the factory
             * a second time with `a._, a.Backbone, a.Backgrid`. Measured, by building it through
             * this config and evaluating the bundle: without those globals it throws
             * "TypeError: Cannot read properties of undefined (reading 'Extension')" at import.
             * Latent today because the AMD branch is taken. The shim sets the three globals in a
             * separate module, because import declarations are hoisted and only a module boundary
             * orders them.
             */
            { find: "backgrid.paginator", replacement: fromSrc("shims/backgrid-paginator.js") },

            /*
             * ---- (2) VENDORED FILES THAT NEED NO ORDERING, ONLY A PATH ----------------------
             *
             * All three are UMD with the CommonJS branch first, so @rollup/plugin-commonjs
             * converts them and nothing has to be assigned beforehand. They are covered by the
             * build.commonjsOptions.include regex below, which is why that regex is load-bearing
             * for five ids and not just for lodash. D20 records why each is vendored rather than
             * installed: form2js and js2form have no usable npm publication, and
             * eonasdan-bootstrap-datetimepicker publishes src/ only and ships no built file.
             */
            { find: "form2js", replacement: fromSrc("libs/form2js-2.0-769718a.js") },
            { find: "js2form", replacement: fromSrc("libs/js2form-2.0-769718a.js") },
            {
                find: "bootstrap-datetimepicker",
                replacement: fromSrc("libs/bootstrap-datetimepicker-4.14.30-min.js")
            },

            /*
             * ---- (1) NOTHING NEEDED BUT THE NAME --------------------------------------------
             *
             * The npm package name differs from the AMD id, or the package publishes no entry
             * point so the bare name does not resolve at all. Verified individually rather than
             * assumed: bootstrap3-dialog and clockpicker BOTH have an empty package.json main /
             * module / exports, so `require.resolve` on the bare name is MODULE_NOT_FOUND.
             *
             * bootstrap-dialog needs no shim even though its factory reads `t.fn.modal.Constructor`
             * at evaluation: its own CommonJS branch is
             * `module.exports = e(require("jquery"), require("bootstrap"))`, and both of those
             * resolve through the entries above, so the ordering arrives through its own imports.
             */
            { find: "backgrid-selectall", replacement: "backgrid-select-all" },
            { find: "qrcode", replacement: "qrcode-generator" },
            { find: "spin", replacement: "spin.js" },
            { find: "bootstrap-dialog", replacement: "bootstrap3-dialog/dist/js/bootstrap-dialog.min.js" },

            /*
             * ---- dragula AND placeholder: NOT IN ANY paths BLOCK, AND STILL REQUIRED ---------
             *
             * Neither is bound by main.js, so neither appears in NOTES-shims.md's table -- but
             * both commons packages import them by these ids from esm/ modules that AM reaches:
             * BackgridUtils.js:24 imports dragula and CALLS it at :28, and 14 AM modules import
             * BackgridUtils. placeholder has exactly ONE importer: ui-commons'
             * common/LoginView.js:18. (ui-user's AbstractUserProfileTab.js:67 and
             * UserProfileKBATab.js:89 only call .attr("placeholder", ...) on a DOM node; they do
             * not import the polyfill. An earlier draft of this comment counted them as importers
             * -- the decision below rests on the one real importer, which is enough on its own.)
             *
             * Task 4.7 dropped both files from the shipped tree as part of its deliberate -6
             * manifest delta, reasoning that "both holder modules are superseded in AM". That is
             * not true of BackgridUtils. Under AMD the ids simply 404 at runtime; under ESM they
             * are unresolved imports, so this is where it has to be settled.
             *
             * Restored as managed dependencies rather than as vendored files or as the Maven
             * artifacts 4.7 removed. dragula@3.6.7's dist/dragula.min.js is md5-identical
             * (8ef652fe9e78af44f287ac3c92d4a07f) to the file AM shipped, PHASE1-TREE.md:255 --
             * zero digest delta, so this is the right release and the bare name needs no alias.
             * NOTE what that check does and does not cover: the bundler never loads that dist
             * file. Bare `dragula` resolves to dragula/dragula.js, the CommonJS source that
             * requires contra and crossvent. Same release, so the digest is sound evidence about
             * the VERSION -- it is not evidence about the bytes Rollup will actually see.
             *
             * placeholder is the one row where npm cannot supply the exact bytes: AM ships 2.0.8
             * (PHASE1-TREE.md:264) and npm has 2.0.7, 2.1.0, 2.1.1 and 2.3.1. Diffed in full, the
             * 2.0.7 -> 2.0.8 delta is an Opera Mini detection branch plus one catch-variable
             * rename; isOperaMini is false on every browser AM supports, so isInputSupported
             * computes identically. The change owner chose 2.0.7 from npm over vendoring 2.0.8,
             * because D20's bar asks whether npm can deliver an equivalent and here it can --
             * keeping it in the lockfile and visible to `npm audit` is worth more than byte
             * parity with a polyfill.
             *
             * Rollup will warn THIS_IS_UNDEFINED on this file, and the warning is noise:
             * jquery.placeholder.js:183 ends `}(this, document, jQuery));` and the file carries no
             * CommonJS markers at all, so plugin-commonjs leaves it alone and Rollup rewrites the
             * top-level `this` to undefined. Checked the body -- the matching `window` parameter
             * is never referenced -- so nothing reads the value that goes undefined.
             *
             * A KNOWN AND ACCEPTED CONSEQUENCE, so that nobody "fixes" it without the context:
             * ui-commons declares `jquery-placeholder: "^2.1.1"` in its peerDependencies, which
             * 2.0.7 does not satisfy, so `npm ls` reports
             *
             *     jquery-placeholder@2.0.7 invalid: "^2.1.1" from .../ui-commons
             *
             * from now on, AND EXITS NON-ZERO with ELSPROBLEMS. That exit code is not new here
             * -- the two extraneous @openidentityplatform packages installed with --no-save
             * already cause it -- but if that arrangement is ever tidied up, `npm ls` will still
             * fail, for this reason. A clean `npm ls` is not a goal for this module.
             * The alternative was 2.1.1, and that is not a patch: 381 changed lines,
             * the file restructured into a UMD with an AMD branch and a new customClass option,
             * on the polyfill behind the login form, with no e2e spec covering it. The change
             * owner chose the closer bytes over the cleaner `npm ls`. Bumping to 2.1.1 later is a
             * real decision with a real behaviour delta, not a lockfile tidy-up.
             *
             * NEITHER FILE IS ADDED TO NPM_LIBRARY_FILES: they are bundled dependencies now, not
             * shipped libs/ files, so the deployed tree is unchanged at 317 files and 4.7's
             * deliberate -6 manifest delta still stands as recorded.
             */
            { find: "placeholder", replacement: fromSrc("shims/placeholder.js") }
        ],

        /*
         * ==== 5.1 -- resolve.extensions AND THE .jsm EXTENSION ====
         *
         * TAKEN BY 5.1, from the paragraph below the alias table that said this had no owner.
         *
         * 31 .jsm and 15 .jsx files live under src/main/js -- 46, not the 44 tasks.md:82 states;
         * counted, not recalled. Every one of the 46 is already ESM (import/export) and NOT ONE
         * calls define(), so the split is perfectly clean along the extension and this task is
         * resolution mechanics only. Nothing in 5.1 converts a module. 5.4 still owns the 203
         * that do call define().
         *
         * DECIDED, NOT ASSUMED: the extension stays and the config adapts, rather than the 31
         * .jsm files being renamed to .js. The rename looks free -- no import specifier anywhere
         * in src/main/js or src/test/js names an extension, so it needs zero import edits, and
         * Grunt already renames these files to .js on the way into the shipped tree -- but it is
         * not. Grunt is still live and task 7.1, not this one, owns Gruntfile.js. A renamed file
         * falls out of babel:transpileJSM (Gruntfile.js:137, the .jsm/.jsx glob) and into
         * babel:transpileJS (Gruntfile.js:129, the plain-.js glob). Both inherit the shared
         * babel options block at Gruntfile.js:113-124, whose @babel/preset-env sets no `modules`
         * option and therefore defaults to "auto"; what separates the two targets is only that
         * transpileJSM adds @babel/plugin-transform-modules-amd on top. Probed with the
         * Gruntfile's exact options against
         * `import x from "./y"; export default x;`:
         *
         *   transpileJSM (today)           define(["exports", "./y"], function (_exports, _y) {
         *   transpileJS  (after a rename)  "use strict"; exports.default = void 0;
         *
         * CommonJS, not AMD, for all 31 modules, out of a build that still exits 0. Renaming is
         * the right end state and should follow 7.1; doing it here would break the Grunt tree
         * silently in the interval.
         *
         * WHY THE LIST IS SPELLED OUT IN FULL. resolve.extensions REPLACES Vite's default, it
         * does not extend it. Vite 5's default is
         * [".mjs", ".js", ".mts", ".ts", ".jsx", ".tsx", ".json"], and dropping any member here
         * -- .json above all -- would break imports that have nothing to do with this task. So
         * the default is reproduced verbatim and ".jsm" inserted beside ".jsx", its sibling.
         *
         * ORDER IS NOT LOAD-BEARING TODAY, checked rather than assumed -- but check it the way
         * it is meant, because the loose reading gives the opposite answer. What matters is the
         * PATH STEM, directory plus name: across src/main/js and src/test/js no <dir>/<name>
         * exists under two of .js/.jsm/.jsx, so no lookup this list drives is ambiguous. BARE
         * BASENAMES do collide -- index, main, DashboardView, AuthenticationService,
         * ScriptsService, ServicesService, URLHelper -- so a `-printf '%f'` version of this
         * check returns seven hits and looks like a contradiction. It is not; they are in
         * different directories.
         *
         * WHICH WAY THE ORDER CUTS, AND 5.4 IS WHO IT COSTS. ".js" precedes ".jsm" in this
         * list. If 5.4 ever lands a converted foo.js beside a still-present foo.jsm, the .js
         * silently wins -- and mid-conversion the .js is the AMD file, so the build would
         * quietly prefer exactly the module the conversion was replacing. Delete the .jsm in
         * the same commit that creates the .js, or reverse these two entries.
         *
         * WHAT IT FIXES, MEASURED. Without it the 5.1 spike died at
         *   [vite:load-fallback] Could not load .../src/main/js/store/index
         * which corrects the claim in the paragraph below the alias table that nothing fails
         * loudly. It is only half right, and the wrong half is worth knowing: an id that reaches
         * a .jsm THROUGH AN ALIAS fails loudly, because alias resolution hands Rollup a concrete
         * path and load-fallback then cannot open it. It is the UNALIASED bare id that degrades
         * to the silent "unresolved dependency, treated as external" warning. Both cases need
         * this list; only one of them would ever have told you so.
         */
        extensions: [".mjs", ".js", ".mts", ".ts", ".jsx", ".jsm", ".tsx", ".json"]
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
     * was unnecessary" rather than like a failure. Compounding it, ALL FIFTEEN of AM
     * config/main.js:26-44's dependencies are RELATIVE ids, and relative specifiers cannot be
     * aliased at all -- Grunt's copy:compose flattening is the only reason they resolve today.
     * SEVEN of the fifteen resolve into the commons config/** tree -- CommonErrorHandlers,
     * CommonValidators, CommonRoutesConfig, UserRoutesConfig, CommonMessages, UserMessages and
     * CommonConfig -- and the other eight are AM's own files. Task 5.4 owns that resolution.
     * Neither is 4.3's to settle; both are recorded so they are not rediscovered.
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
     *                            fork. CORRECTION, 5.4/B11: the claim that stood
     *                            here -- that they are "the same failure mode as lodash", that
     *                            "neither file calls define()", and that a bare alias is therefore
     *                            insufficient -- is WRONG on its premise. Both are UMD:
     *                            form2js-2.0-769718a.js:34-37 is `else if (typeof define ===
     *                            "function" && define.amd) define(factory);`, and js2form matches.
     *                            That changes the mechanism, not just a detail -- as UMD they are
     *                            what @rollup/plugin-commonjs handles, and commonjsOptions.include
     *                            below already matches /src[\/]main[\/]js[\/]libs[\/]/, so the
     *                            bare aliases above are sufficient and no shim is pending.
     *                            Re-measure before inheriting either version of this paragraph.
     *
     * NOT DONE BY 4.3, AND NOW OWNED: resolve.extensions and the .jsm extension, which this
     * file's own 4.1 header assigned to 4.3. tasks.md:69 scopes 4.3 to the 12 map bindings and
     * names nothing else, so it was left out there deliberately rather than done silently.
     * TASK 5.1 TOOK IT -- not 5.2, which is what this paragraph used to guess -- and it is
     * settled in the resolve.extensions block inside resolve above. Of the three failures
     * predicted here, only one needed fixing and the framing of a second was wrong: no .jsm
     * contains JSX so the react plugin's include was left alone, vite:esbuild never sees a .jsm
     * so no loader was needed, and the "nothing fails loudly" claim holds only for UNALIASED
     * ids. The measurements behind each are in that block and in the react() comment above.
     */

    /*
     * STILL false after 4.4, and now for a second reason. The first stands: this module has no
     * public/ directory, and turning it on by accident would silently change the shipped layout.
     * The second is that publicDir cannot do 4.4's job -- it is ONE directory and the static
     * assets fan in from four, with an override order that decides which copy of
     * locales/en/translation.json ships. The xuiStaticAssets plugin above does it instead.
     * See NOTES-static-assets.md section 2, option D, for the full costing.
     */
    publicDir: false,

    css: {
        /*
         * DECIDED BY 4.4: the three LESS files are NOT reached through the module graph, so
         * nothing below is exercised today and it is left empty on purpose rather than deleted.
         * css/structure.less, css/theme.less and css/styles-admin.less are compiled by the
         * xuiStaticAssets plugin with the installed `less` + `less-plugin-clean-css` and Grunt's
         * exact options, which is the only way to reproduce PHASE1-TREE.md's bytes -- Vite's
         * cssMinify is esbuild or lightningcss and neither emits clean-css 3.4.28 output. The
         * full comparison is in the plugin comment and in NOTES-static-assets.md section 3.
         *
         * If a later task DOES import a stylesheet from a module, this is where its options go,
         * and build.rollupOptions.output.assetFileNames below already routes the result to a
         * stable unhashed path under css/.
         */
        preprocessorOptions: {
            /*
             * javascriptEnabled is deliberately NOT set. Less 4 defaults it off as code-execution
             * hardening, and no .less file needs it: checked src/main/resources (21 files) and the
             * commons packages (36) — not one contains a backtick. The two counted here as
             * target/dependencies were `.css` inputs, not `.less`, and 4.8 moved them to
             * target/npm-libs with the rest of CodeMirror.
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
        __TARGET_VERSION__: JSON.stringify(targetVersion),

        /*
         * The login helper id, from the environment variable above. `define` is a textual
         * substitution, so what reaches the chunk is a quoted string literal -- never a
         * `process.env` lookup, which would be a ReferenceError in the browser. `loginHelperClass`
         * has already fallen back to the shipped id, so the unset case substitutes that id and
         * never the token `undefined`.
         */
        __LOGIN_HELPER_CLASS__: JSON.stringify(loginHelperClass),

        /*
         * The theme configuration override, from the environment variable above. A quoted string
         * literal reaches the chunk, never a `process.env` lookup; `themeConfigOverride` has
         * already fallen back to "", so the unset case substitutes an empty string literal and
         * never the token `undefined`.
         */
        __THEME_CONFIG_OVERRIDE__: JSON.stringify(themeConfigOverride)
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
         * unresolved. SETTLED, and this paragraph is kept because 5.2's own comments cite it:
         * vite 5.4.21 IS installed in this module's node_modules and is what resolves, 5.1 added
         * the EXPECTED_VITE_MAJOR guard below the imports that fails the build if that changes,
         * and 5.2 re-confirmed it. So Rollup and @rollup/plugin-commonjs are what actually run,
         * and this setting is load-bearing rather than a hedge against an unknown engine.
         *
         * SCOPE: no task owns build.commonjsOptions. 4.3 sets it because 4.3 created the file that
         * needs it. Task 4.7 owns where libs/ files finally live and MUST update this regex when
         * it moves them -- the coupling is deliberate and is called out here so it is not silently
         * broken. Task 8.3 deletes both the file and this entry when lodash 4 lands.
         *
         * The regex is scoped to src/main/js/libs/ rather than to the one file on purpose: the
         * other four vendored files there are AMD/UMD in exactly the same way, and 4.7 will be
         * reasoning about them as a group.
        *
         * TASK 5.2 DEPENDS ON THIS REGEX AND ADDED NOTHING TO IT, which is worth stating so that
         * "no diff here" is not read as "no stake here". Five aliased ids now resolve to files
         * under src/main/js/libs/ that are UMD or CommonJS and would have no ES exports without
         * this include: form2js, js2form, bootstrap-datetimepicker, backgrid.paginator (through
         * shims/backgrid-paginator.js) and jsonEditor (through shims/json-editor.js), on top of
         * lodash and underscore. Narrowing this regex to the one lodash file, or deleting it when
         * task 8.3 removes lodash, breaks all five silently -- the ids still RESOLVE, and the
         * imported value is simply undefined. Everything else 5.2 binds lives under node_modules
         * and is covered by the first pattern.
         *
         * The shims themselves are ordinary ES modules and need no transform.
         */
        commonjsOptions: {
            include: [/node_modules/, /src[\\/]main[\\/]js[\\/]libs[\\/]/],
            extensions: [".js", ".cjs"],

            /*
             * ==== 5.2 -- WHAT `require("jquery")` RETURNS INSIDE A CommonJS LIBRARY ==========
             *
             * The alias table points `jquery`, `backbone`, `bootstrap` and `i18next` at ES module
             * shims. That is fine for ES importers, and it silently breaks every CommonJS library
             * that require()s the same ids -- which is most of them, because their UMD CommonJS
             * branches are exactly where those requires live:
             *
             *     backgrid:                 factory(require("underscore"), require("backbone"))
             *     bootstrap3-dialog:        e(require("jquery"), require("bootstrap"))
             *     selectize:                factory(require("jquery"), require("sifter"), ...)
             *     eonasdan-...-datetimepicker: a(require("jquery"), require("moment"))
             *
             * By default @rollup/plugin-commonjs gives such a require() the ES MODULE NAMESPACE
             * OBJECT, so the library receives { default: jQuery } where it expects jQuery, and
             * dies on the first property access. MEASURED, by building each id and evaluating the
             * bundle under jsdom -- nine ids built cleanly and threw at evaluation:
             *
             *     backgrid, backgrid-filter, backgrid-selectall, backgrid.paginator,
             *     backbone.paginator, backbone-relational  ->  reading 'extend'/'prototype' of undefined
             *     bootstrap-datetimepicker                 ->  setting 'datetimepicker' of undefined
             *     bootstrap-dialog                         ->  reading 'modal' of undefined
             *     selectize                                ->  $2.extend is not a function
             *
             * `requireReturnsDefault: "auto"` makes require() hand back the default export when
             * the module has one, which is what every one of those libraries expects and what
             * RequireJS gave them. All nine then build AND evaluate; verified again under
             * "preferred", which also works, so "auto" is chosen as the narrower of the two.
             *
             * THIS SETTING IS LOAD-BEARING FOR THE ALIAS TABLE, not a general preference. If the
             * four shim aliases above are ever removed, this can go with them; while they exist,
             * removing it turns nine libraries into runtime TypeErrors that no build step reports.
             */
            requireReturnsDefault: "auto"
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

        /*
         * 4.4. Vite's default is 4096: any graph asset under 4 kB becomes a `data:` URI and stops
         * existing as a file. NO ASSET IS AFFECTED TODAY -- the five Font Awesome fonts are
         * 66-365 kB and are copied verbatim rather than imported, and NOTES-static-assets.md
         * section 4 records that no image is reached from the compiled CSS at all. It is turned
         * off anyway because the requirement is a property of the output, not of today's file
         * sizes: ui-build-and-packaging's "Deployed directory layout" says these files are
         * individually addressable at stable paths, and an operator cannot override an asset that
         * has been inlined into a stylesheet. Left at the default, the first small url() anyone
         * adds disappears from the tree silently.
         */
        assetsInlineLimit: 0,

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
             *
             * ---- SETTLED BY 5.4/B12: OPTION (c1). ----
             * The change owner took (c1). `main` uses the escape this block describes -- index.html
             * is now a single `<script type="module" src="main.js?v=${version}">` -- and the two
             * secondaries get an unhashed CLASSIC stub at the fixed name the six .ftl pages fetch,
             * which dynamic-imports the hashed ES chunk. The stub is emitted by
             * xui-requirejs-entry-stubs (defined above this config object, with the costing of
             * (a) and (c2) that went with the decision), and it is the reason entryFileNames below
             * is a function rather than the plain "[name].js" 4.5 left here. The names in this
             * block are unchanged and still load-bearing: the STUB now carries them.
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
                 * [name] for an entry chunk is the KEY of the input object above, so `main` is what
                 * puts main.js at the tree root with a stable, unhashed name. PHASE1-TREE.md:155-156
                 * records that as the requirement Vite's default assets/[name]-[hash].js violates.
                 *
                 * ---- CHANGED BY 5.4/B12, AND THE STRING FORM WOULD NOW BE WRONG. ----
                 * 4.5 recorded that "entryFileNames stays the plain [name].js rather than 4.3's
                 * function form". That held only while all three entries were classic AMD scripts
                 * emitted at their own fixed names. Under option (c1) the two RequireJS-loaded
                 * entries do NOT own their fixed names any more -- the classic stub emitted by
                 * xui-requirejs-entry-stubs does, and the real ES chunk has to move out of its way.
                 * So those two are hashed under assets/ like any other chunk, and the stub is what
                 * the six .ftl pages fetch at main-authorize.js / main-device.js. Keeping the string
                 * form here does not fail loudly: rollup would refuse the duplicate file name from
                 * emitFile, which is why that plugin's guard names THIS option.
                 *
                 * ---- CHANGED AGAIN BY 6.1. ----
                 * B12 left `main` unhashed at the root, reasoning that index.html is in this Maven
                 * module and names it directly, so it "needs no stub and no hash". That held only
                 * while the build barely code-split. Once D1's registry lands, the view chunks
                 * import the entry chunk, and index.html's `?v=${version}` makes that the SAME FILE
                 * AT TWO URLS -- two module records, entry body evaluated twice, admin console
                 * blank with a clean console log. So `main` is now hashed under assets/ like the
                 * other two, and a module stub owns the root name. Full reasoning at
                 * MODULE_LOADED_ENTRIES above; index.html is unchanged and still names main.js.
                 */
                entryFileNames: (chunkInfo) => (
                    STUBBED_ENTRIES.has(chunkInfo.name) ? "assets/[name]-[hash].js" : "[name].js"
                ),

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
                 *
                 * ---- RESOLVED BY 4.4. ----
                 * Primarily by keeping LESS out of the graph entirely: the three stylesheets are
                 * compiled by the xuiStaticAssets plugin straight to css/*.css, so no CSS reaches
                 * this option today and the string form would in fact have been harmless.
                 *
                 * The function form is here anyway, and the reason is that "harmless today" was
                 * exactly the state 4.2 left behind and it cost this task a decision to re-derive.
                 * ui-build-and-packaging's "Deployed directory layout" names STYLESHEETS in the
                 * same sentence as templates and partials — individually addressable, stable
                 * paths, no build-generated content hash — so a stylesheet that does enter the
                 * graph later must not land at assets/<name>-<hash>.css. It gets css/[name].[ext]
                 * instead. A flat "[name].[ext]" is NOT sufficient: it loses the css/ prefix, and
                 * all three references (ThemeConfiguration.js:23,67 and Constants.js:60) are
                 * path-qualified.
                 *
                 * WHAT THIS DOES AND DOES NOT BUY, because the difference matters to whoever
                 * changes it next. It guarantees the DIRECTORY and the absence of a hash. It does
                 * NOT reproduce the three required file names: [name] here is the CHUNK name, so
                 * `import "css/structure.less"` from main.js emits css/main.css, not
                 * css/structure.css, and the theme stylesheet lists would still 404. Anyone moving
                 * LESS into the graph needs a per-file branch here as well -- and NOTES-static-
                 * assets.md section 3 has the other two reasons not to (byte parity, and
                 * cssCodeSplit being wrong at both values).
                 *
                 * Everything else keeps the hashed default. That is deliberate and narrow: the
                 * requirement is about the files operators address by path, not about every byte
                 * rollup emits, and nothing else in the tree is addressed that way.
                 */
                chunkFileNames: "assets/[name]-[hash].js",
                assetFileNames: (assetInfo) => {
                    const name = assetInfo.names?.[0] || assetInfo.name || "";
                    return name.endsWith(".css") ? "css/[name].[ext]" : "assets/[name]-[hash].[ext]";
                }
            }
        }
    }
});
