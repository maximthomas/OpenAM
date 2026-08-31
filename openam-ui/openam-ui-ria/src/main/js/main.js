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
 * Portions copyright 2011-2016 ForgeRock AS.
 * Portions copyright 2025-2026 3A Systems LLC.
 */

/*
 * TASK 5.4 (batch B12) -- THE CONSOLE ENTRY POINT, NOW AN ES MODULE.
 *
 * WHAT WENT, AND WHERE ITS REPLACEMENT LIVES. Three things were deleted here and none of them
 * needed a successor written in this file:
 *
 *   - `require.config({ map })`     -> vite.config.js `resolve.alias`. Every short id it bound
 *                                     (Footer, ThemeManager, LoginView, UserProfileView,
 *                                     ForgotUsernameView, PasswordResetView, LoginDialog,
 *                                     NavigationFilter, Router, RegisterView, KBADelegate,
 *                                     underscore) has an alias entry, so the ids keep working
 *                                     unchanged at the ~50 call sites that use them.
 *   - `require.config({ paths })`   -> the same alias block, plus package resolution by name.
 *                                     TASK 5.2 landed it and left this block byte-identical
 *                                     beside it precisely so this deletion would be a deletion.
 *   - `require.config({ shim })`    -> src/main/js/shims/*.js for the twelve ids that passed a
 *                                     dependency through a GLOBAL; the rest of the block was
 *                                     already dead (TASK 5.2 measured nine of fourteen `exports`
 *                                     fields as having no effect under RequireJS).
 *   - `define("reactAutosizeInputDep")` / `define("reactSelectDep")`
 *                                  -> NOTHING, by TASK 5.3's decision. Both ids are real npm
 *                                     package names now, resolved by name, and their own package
 *                                     `main` requires react, react-dom, react-input-autosize and
 *                                     classnames BY NAME rather than reading window globals.
 *                                     assertReactSelectNeedsNoGlobals in vite.config.js fails the
 *                                     build if a dist/ binding ever puts the globals back.
 *
 * The runtime `require([...], callback)` below became static imports. Load order is now the
 * import graph's, which is the same depth-first order RequireJS produced for this list.
 *
 * HOW THIS FILE IS LOADED. src/main/resources/index.html now carries a single
 * `<script type="module" src="main.js?v=${version}">`; the RequireJS bootstrap and the base64
 * polyfill are gone from it. This entry is therefore NOT loaded by RequireJS and needs no
 * classic-script stub -- unlike main-authorize.js and main-device.js, which six .ftl pages in the
 * openam-oauth2 module still fetch through RequireJS `data-main` (D8, task 10.4).
 */

import Constants from "org/forgerock/commons/ui/common/util/Constants";
import EventManager from "org/forgerock/commons/ui/common/main/EventManager";
import resolveAssetUrl from "org/forgerock/openam/ui/common/util/resolveAssetUrl";

// other modules that are necessary to include to startup the app
import "jquery";
import "lodash";
import "backbone";
import "handlebars";
import "i18next";
import "spin";
import "org/forgerock/commons/ui/common/main";
import "org/forgerock/openam/ui/main";
/*
 * The one specifier in this file that is NOT an AMD id, and vite.config.js's B0.8 note predicted
 * it: `config/main` is AM's own file and has no alias, because main.js was always its only
 * importer. Section 3d left the choice to this batch. A relative specifier is taken rather than a
 * fifteenth alias entry because this file sits AT the module-tree root, so the relative form is
 * `./config/main.js` -- no ../ chain, nothing a reader has to count. That is the exact argument
 * B0.8 used the other way round for config/ThemeConfiguration, whose relative form was seven
 * levels of ../.
 */
import "./config/main.js";
/* global __TARGET_VERSION__ */
import "store/index";
import { configure as configureLoader } from "org/forgerock/commons/ui/common/util/esm/LoaderRuntime";
import { resolveModule } from "./moduleRegistry.js";
import warnRetiredConfig from "./warnRetiredConfig.js";

/*
 * D4 -- THE CACHE-BUSTER, AND WHY IT IS ONLY CONFIGURED IN *THIS* ENTRY.
 *
 * RequireJS applied `urlArgs: "v=${version}"` from index.html to every runtime-fetched template,
 * partial, locale and theme asset. index.html no longer loads RequireJS, so `require.toUrl` does
 * not exist on the console page and resolveAssetUrl's unconfigured branch would throw. This call
 * is what replaces it, and `__TARGET_VERSION__` is vite.config.js's `define` of the same
 * ${project.version} Maven passes to the Grunt build (see resolveAssetUrl's header for why the
 * helper itself does not name that identifier).
 *
 * main-authorize.js and main-device.js deliberately do NOT make this call. RequireJS is still
 * loaded on their six .ftl pages -- it is what fetches their classic-script stubs -- so
 * `require.toUrl` is present there AND carries the baseUrl those pages need, which resolveAssetUrl
 * configured cannot supply (its own header, difference 1). Configuring them would trade a
 * cache-buster they never had for asset URLs resolved against /oauth2/... instead of /XUI/.
 *
 * ORDERING. Imports are evaluated before this statement, so this would throw if anything in the
 * graph above resolved an asset URL at module top level. Nothing does: resolveAssetUrl has exactly
 * two importers -- ThemeManager (5 call sites, all inside applyThemeToPage/makeUrlsRelativeTo-
 * EntryPoint) and TokensView (1, inside reloadData) -- and all six are function bodies reached
 * only from render paths that this file's sendEvent below is what starts.
 */
resolveAssetUrl.configure({ urlArgs: `v=${__TARGET_VERSION__}` });

/*
 * REVIEW FIX (D4). resolveAssetUrl covers only ThemeManager's 5 sites and TokensView's 1.
 * EVERYTHING commons fetches at runtime -- ~187 templates and partials, plus every locale's
 * translation.json -- goes through LoaderRuntime.toUrl instead, and shipped with no
 * cache-buster at all. Against web.xml's `max-age=2592000` on /XUI/* that means month-stale
 * templates after an upgrade, which is precisely what D4 exists to prevent. baseUrl is left at its "" default deliberately: the
 * console IS served from /XUI/, so document-relative resolution is already correct here.
 */
/*
 * D1 -- resolveModule is the registry (task 6.1). `./moduleRegistry.js` holds the three
 * import.meta.glob calls, the seven logical names and the two library names, and its header is
 * where the reasons live. It is a separate module rather than inline here for two reasons: the
 * root-absolute glob patterns make its keys independent of where it sits, so nothing about the ids
 * is tied to this file; and tasks 6.2-6.4 evolve resolution without touching the entry point.
 *
 * main-authorize.js and main-device.js deliberately do NOT pass resolveModule -- see
 * NOTES-entry-templates.md section 6.1, which traces both graphs. Neither entry EXECUTES a
 * ModuleLoader.load path. Be precise about that: ModuleLoader is in both static graphs, via
 * UIUtils (commons UIUtils.js:25 imports it and calls load("bootstrap-dialog") at :345) and via
 * Router -> AbstractConfigurationAware:25 -- it is reached but never called on those two pages.
 * So configuring resolveModule there would pull the whole 361-module registry into two pages that
 * ask nothing of it. They configure only baseUrl, which they DO need.
 */
configureLoader({ resolveModule, urlArgs: `v=${__TARGET_VERSION__}` });

/*
 * D6 (task 7.4). Two HEAD requests, deferred to idle, warning if this deployed tree still carries
 * `config/AppConfiguration.js` or `config/ThemeConfiguration.js` -- retired files that an in-place
 * upgrade leaves behind and that nothing reads any more.
 *
 * Placed after configureLoader by convention, NOT because the ordering is load-bearing: the probe
 * runs in a deferred callback, which cannot fire before this module body has finished, and it
 * resolves its url at that point rather than at module evaluation. So do not read this placement
 * as the thing keeping it correct -- the lazy resolution in warnRetiredConfig.js is. That file
 * carries the rest, including why `?v=` is not what defeats the cached 404 and `no-store` is.
 *
 * This entry leaves baseUrl at "" (the console IS served from /XUI/), so the probe's url happens to
 * match a document-relative one here. On the other two entries it does not, which is why the probe
 * goes through `toUrl` rather than the document.
 */
warnRetiredConfig();

EventManager.sendEvent(Constants.EVENT_DEPENDENCIES_LOADED);
