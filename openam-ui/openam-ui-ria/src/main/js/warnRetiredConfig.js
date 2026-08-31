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
 * Copyright 2026 3A Systems, LLC.
 */

/*
 * TASK 7.4 -- WARN WHEN A DEPLOYED /XUI STILL CARRIES THE RETIRED CONFIG FILES.
 *
 * D6 made `config/AppConfiguration.js` and `config/ThemeConfiguration.js` ordinary bundled source.
 * A deployed tree upgraded in place -- unpacked over an existing exploded webapp rather than
 * replaced -- keeps its old `config/` directory, and every edit an operator made in it silently
 * stops applying. Nothing errors. The UI runs on the configuration built into the bundle and looks
 * entirely healthy. design.md's Open Questions resolved that on 2026-08-04: build the warning
 * rather than wait for evidence, because the break is least visible in exactly the case it happens.
 *
 * Everything asserted below was measured against the running container, not reasoned from the
 * sources; e2e/xui/NOTES-config-warning.md holds the measurements and the response sizes.
 *
 * NO DEV-SERVER GUARD, AND THAT IS A DECISION RATHER THAN AN OVERSIGHT. The concern is real --
 * `config/AppConfiguration.js` does exist in source -- but the probe was measured returning 404
 * under both `npm run dev` and the documented `--base` form: Vite's dev root is the package
 * directory, the sources sit under `src/main/js/`, `vite.config.js` sets `publicDir: false`, and
 * nothing maps a URL path `config/...` onto the source tree. The spike recommended wrapping the
 * call in `import.meta.env.PROD` as insurance anyway, and that is NOT done here for a concrete
 * reason: `.eslintrc.js` pins `ecmaVersion: 6`, where `import.meta` is a parse error, so the guard
 * cannot be written without changing the lint configuration for the whole module. The cost of
 * going without is two 404s per dev page load. If `root` or `publicDir` ever change, this is the
 * comment that says where to look.
 *
 * WHY TWO NAMES AND NOT THE DIRECTORY. Widening to "is there a `config/` directory" would have
 * caught all seventeen retired files for one request, and it is not implementable: Tomcat answers
 * `/XUI/config/` with 404 whether the directory holds seventeen files, one file, or none --
 * directory listing is off, so there is nothing to probe. It would also have collided with
 * e2e/xui/xui-operator-module.spec.mjs, which places an operator's own module at
 * `config/E2EStandInLoginHelper.js` and thereby creates a `config/` directory that is entirely
 * legitimate. That is D1's fallback doing its job -- an identifier resolved out of the deployed
 * instance -- and it lives in the same URL space as the retired files. Watching two exact names
 * keeps the two apart; watching the directory cannot.
 */

/* global fetch, requestIdleCallback */

import { toUrl } from "org/forgerock/commons/ui/common/util/esm/LoaderRuntime";

/**
 * The files D6 retired, relative to the XUI root.
 *
 * Deliberately these two and no more. The other fifteen files that sat in `config/` are retired
 * too, and UPGRADE-XUI-BUILD.md describes all seventeen -- but each extra name costs its own
 * request on every page load of every instance forever, including the correctly-upgraded ones, and
 * these two are the pair the change is named for.
 */
const RETIRED = ["config/AppConfiguration.js", "config/ThemeConfiguration.js"];

/**
 * Where to send the operator, verbatim.
 *
 * This is the `citation:` field from the front matter of
 * openam-ui/openam-ui-ria/UPGRADE-XUI-BUILD.md, character for character. That file carries a
 * comment saying that renaming it means changing this string with it; the two are a pair, and the
 * point of pinning it there is that a note whose console message points somewhere else is worse
 * than no message. Path before URL so the useful half survives console truncation, no trailing
 * punctuation and no fragment so it survives being read off a screen and typed by hand.
 */
const NOTE = "XUI upgrade note: openam-ui/openam-ui-ria/UPGRADE-XUI-BUILD.md in the OpenAM source" +
    " tree, or https://github.com/OpenIdentityPlatform/OpenAM/blob/master/openam-ui/openam-ui-ria" +
    "/UPGRADE-XUI-BUILD.md";

function message (name) {
    return `[XUI] ${name} is still present in the deployed /XUI tree, but it is no longer read. ` +
        "Under the current build it is compiled into the application bundle, so the deployed copy " +
        "has no effect and any local edits to it are silently ignored. Remove it, and make the " +
        `change in the source and rebuild instead. ${NOTE}`;
}

function probe (name) {
    /*
     * toUrl IS CALLED HERE, NOT AT MODULE SCOPE. It reads the settings `configure()` installed, so
     * capturing a url when this module is evaluated captures the defaults instead. That is not a
     * theoretical ordering worry: a first integration attempt did exactly that, and the two
     * secondary entries went silent while the console printed correctly -- design.md D22's
     * regression in miniature, and it fails without a symptom.
     *
     * Resolving through toUrl rather than against the document is the whole reason this works on
     * all three entry points. main.js is served from /XUI/ and leaves baseUrl at "", so
     * document-relative resolution happens to be right there; main-authorize.js and main-device.js
     * are loaded by .ftl pages under /oauth2/, where the same document-relative url resolves to
     * `/oauth2/realms/root/config/AppConfiguration.js` and returns 404 with the file plainly
     * present on the server. Measured, both of them.
     *
     * THE CACHE, AND DO NOT SIMPLIFY THIS. web.xml maps `CacheForAMonth` to /XUI/*, and the filter
     * runs before the servlet, so `public, max-age=2592000` lands on the 404 as well as on the 200.
     * A plain GET therefore caches the miss for thirty days, and the operator this check exists for
     * -- the one who adds the file after first load -- never sees a warning, not on that page and
     * not after a reload.
     *
     * `?v=<build version>` does NOT fix that, so do not reach for it: the version is unchanged
     * between those two loads, so the cache key is identical and the stale 404 is served again.
     * D4's buster exists to force a refetch after a redeploy, and the failure being detected here
     * is a file appearing WITHOUT one. The url will still end in `?v=` because all three entries
     * configure `urlArgs` and toUrl honours it -- that is harmless, and it is not what makes this
     * work. `cache: "no-store"` is what makes it work, and HEAD keeps the response body at zero
     * bytes. Both were measured sufficient alone; both are kept because a stored GET entry can
     * otherwise answer a later HEAD.
     */
    return fetch(toUrl(name), { method: "HEAD", cache: "no-store" }).then((response) => {
        if (!response.ok) { return; }
        /*
         * console.warn, not console.error. The app works -- a stale config file is inert, not a
         * boot failure, and console.error is what the entry points already use when the
         * application genuinely could not start. A normal login page also emits a dozen console
         * errors of its own, so an error here would be indistinguishable from the noise; a warning
         * is not, and it matches what the rest of the app uses for "this runs, but you are wrong".
         */
        console.warn(message(name));
    }, () => {
        /*
         * A failed probe is not evidence of anything. The network is down, or the request was
         * blocked -- neither says the file is there, and neither is an application failure. Say
         * nothing and let the app carry on. This handler is why the check cannot throw.
         */
    });
}

/**
 * Look for the retired config files in the deployed tree and warn about any that are still there.
 *
 * Call after `configure()` has been given this page's `baseUrl` and `urlArgs`, and nothing needs to
 * await the result. Two HEAD requests per document, no response bodies, measured at ~4ms for the
 * pair; they cannot be folded into one, because there is no single url that answers for both names.
 *
 * Deferred so it can never delay first paint, with a bounded idle callback rather than a bare one:
 * an unbounded `requestIdleCallback` was measured at 4.5s on the console page and, once, never
 * fired at all. The timeout puts a ceiling on that, and the `setTimeout` branch covers browsers
 * that do not implement it.
 */
export default function warnRetiredConfig () {
    /*
     * The try/catch is what makes "this cannot throw" true rather than nearly true. `probe`'s
     * rejection handler is total over the fetch *promise*, but `toUrl(name)` and the `fetch`
     * reference itself are evaluated synchronously before any promise exists. Nothing can throw
     * there today -- `toUrl` is string manipulation unless a `resolveUrl` is configured, and none of
     * the three entries configures one -- but if anything ever did, it would escape the idle
     * callback as an uncaught error AND abort the loop so the second file was never probed. An
     * uncaught error is also not free: xui-theming.spec.mjs guards `pageerror`, so a detection
     * failure would surface as an unrelated red spec.
     */
    const run = () => {
        try {
            RETIRED.forEach(probe);
        } catch (error) {
            // Detection failing is not the application failing. Say nothing and carry on.
        }
    };

    if (typeof requestIdleCallback === "function") {
        requestIdleCallback(run, { timeout: 2000 });
    } else {
        setTimeout(run, 0);
    }
}
