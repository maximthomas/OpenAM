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

/*
 * Maven passes the project version through this variable. The pom's npm-build execution sets it;
 * see openam-ui-ria/pom.xml. "dev" mirrors Gruntfile.js:45, `grunt.option("target-version") || "dev"`.
 */
const targetVersion = process.env.TARGET_VERSION || "dev";

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
    "libs/text-2.0.15.js": "requirejs-text/text.js",                                       // MD5
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
    "libs/codemirror/lib/codemirror.js": "codemirror/lib/codemirror.js",                   // MD5
    "libs/codemirror/mode/groovy/groovy.js": "codemirror/mode/groovy/groovy.js",           // MD5
    "libs/codemirror/mode/javascript/javascript.js":
        "codemirror/mode/javascript/javascript.js",                                        // MD5
    "libs/codemirror/addon/display/fullscreen.js":
        "codemirror/addon/display/fullscreen.js",                                          // MD5

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
const LITERAL_PATH_LIBRARY_CONSUMERS = [
    "src/main/js/org/forgerock/openam/ui/admin/views/realms/scripts/EditScriptView.js"
];

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
 * pull its <script src> tags into the module graph. Both would fail to resolve: src/main/resources
 * has NO libs/ directory at all -- libs/base64-1.0.0-min.js and libs/requirejs-2.3.7-min.js are
 * vendored under src/main/js/libs (4.7; neither has an npm publication that could supply them,
 * and both must exist as files before any module system runs) and reach the tree through
 * copyLibraries, not through this html
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
const readIndexHtmlSource = (root) => {
    const source = fs.readFileSync(path.resolve(root, INDEX_HTML_SOURCE), "utf8");
    if (!source.includes(VERSION_TOKEN)) {
        throw new Error(
            `${INDEX_HTML_SOURCE} no longer contains the ${VERSION_TOKEN} token. The deployed ` +
            "index.html would ship without a cache-buster, and every template, partial, locale " +
            "and theme asset fetched at runtime through require.toUrl's urlArgs would be served " +
            "from a stale browser cache after a redeploy. See design.md D4."
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
         * Whoever moves this module off react 15 -- 5.3 is the nearest task, it owns react-select
         * and the window globals it needs -- should revisit this line and not merely inherit it.
         */
        react({ jsxRuntime: "classic" }),

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
        },

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
