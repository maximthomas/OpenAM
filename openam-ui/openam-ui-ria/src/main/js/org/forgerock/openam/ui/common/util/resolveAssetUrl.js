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
 * Copyright 2026 3A Systems, LLC.
 */

define([], function () {
    /**
     * Resolves the URL of an asset fetched by path at runtime, appending the build version so a
     * redeploy invalidates the client's cache (D3, D4).
     *
     * The assets in question are the ones D3 keeps unbundled and unhashed - templates, partials,
     * locales and theme assets. Vite content-hashes the JS it bundles; it does not touch these,
     * so they need a cache-buster of their own.
     *
     * TWO MODES, AND WHICH ONE IS LIVE DEPENDS ON THE BUILD.
     *
     * Unconfigured, this delegates to `require.toUrl`. Under RequireJS that is not an
     * approximation of today's behaviour, it *is* today's behaviour: task 1.12 verified that
     * `toUrl` forwards to `nameToUrl`, whose single return applies `config.urlArgs`, and
     * `index.html` sets `urlArgs: "v=${version}"`. So while the Grunt build is what produces the
     * deployable tree, this module changes nothing - which is what makes replacing the six call
     * sites behaviour-preserving by construction rather than by measurement.
     *
     * Configured, it appends `urlArgs` itself. That is the path the Vite build takes, where there
     * is no RequireJS and therefore no reader for the `urlArgs` in `index.html`.
     *
     * WHY THE VERSION IS INJECTED RATHER THAN READ.
     *
     * `vite.config.js` declares `define: { __TARGET_VERSION__: ... }`, and this module could name
     * that identifier directly. It deliberately does not. `define` is a compile-time textual
     * substitution performed by the consuming bundler, so a module naming `__TARGET_VERSION__` is
     * a `ReferenceError` under any build that does not perform it - which includes the Grunt/r.js
     * build this file still has to work under, and would include OpenIDM and OpenIG were this
     * shape ever moved into commons. The product passes the value in; the helper names no build
     * machinery. This is the same injection shape `LoaderRuntime.configure` uses in the commons
     * ESM build (see NOTES-resolve-asset-url.md section 4b).
     *
     * THREE KNOWN DIFFERENCES BETWEEN THE MODES, recorded rather than papered over. The first two
     * are inert for every input the six call sites pass; the third is inert only by accident.
     *
     * 1. No `baseUrl`. `require.toUrl` resolves against the configured base and so returns
     *    `./templates/...`; the configured path returns `templates/...` unchanged. Every input
     *    here is app-root-relative and `index.html` is served from the tree root with no `<base>`
     *    tag and hash-based routing, so the two resolve to the same request URL in the browser.
     *    The difference is visible only to a caller comparing the returned string.
     * 2. No `blob:` exclusion. RequireJS skips `urlArgs` for `blob:` URLs. Nothing here ever
     *    resolves one, so the branch is not reproduced.
     * 3. No `config.paths` or `config.map` substitution. `require.toUrl("text/foo.css")` returns
     *    `./libs/text-2.0.15/foo.css` because `text` is a `paths` key in `main.js`; this returns
     *    `text/foo.css`. No call site passes a path whose first segment collides with a `paths` or
     *    `map` key - they are all `themes/`, `css/`, `images/`, `locales/` or a template path - so
     *    this never fires. It is a difference rather than a bug: an operator asset path being
     *    rewritten into a library directory is a RequireJS wart, not behaviour worth preserving.
     *
     * @exports org/forgerock/openam/ui/common/util/resolveAssetUrl
     */

    var settings = {
        /*
         * `null` means "no product has configured this", which is distinct from the empty string,
         * meaning "configured to resolve without a cache-buster". `resolved` exists so a
         * configure() that lands after the first URL has already gone out is reported rather than
         * silently applying to later URLs only.
         */
        urlArgs: null,
        resolved: false
    };

    /**
     * Resolves an asset path to the URL it should be fetched from.
     *
     * @param {string} url Asset path, relative to the application root. May already carry a theme
     *   prefix - `UIUtils.compileTemplate` prepends `theme.path` before the fetch and falls back
     *   to the unprefixed path on a 404 (D3), and that resolution happens above this function.
     *   May also contain a library's own unexpanded placeholders, as i18next's `resGetPath` does;
     *   the input is appended to, never parsed or re-encoded.
     * @returns {string} The URL to fetch.
     */
    function resolveAssetUrl (url) {
        settings.resolved = true;

        if (settings.urlArgs === null) {
            /*
             * Not configured. Under AMD this is correct and complete - RequireJS applies the
             * urlArgs from index.html itself.
             *
             * THE THROW BELOW IS NARROWER THAN IT LOOKS, and a group-5 implementer should not
             * rely on it as a forgot-to-configure alarm. Task 4.5 ships index.html byte-identical,
             * RequireJS bootstrap included, so under the Vite tree `window.require.toUrl` still
             * exists and an unconfigured helper delegates to it silently rather than throwing.
             * That is not user-visible - RequireJS still applies its own urlArgs, so the URL is
             * right - but it means the guard only becomes an alarm once group 5 removes the
             * bootstrap from index.html. Until then, "did configure() run?" is not a question this
             * module can answer for you.
             */
            if (typeof require !== "undefined" && require.toUrl) {
                return require.toUrl(url);
            }
            throw new Error(
                `resolveAssetUrl("${url}") called before configure() and with no require.toUrl ` +
                "available. The application bootstrap must call configure({ urlArgs }) before the " +
                "first asset is fetched.");
        }

        if (!settings.urlArgs) {
            /*
             * Configured to resolve without a cache-buster - return the path rather than emit a
             * bare "?". Unreachable as AM deploys today, since `__TARGET_VERSION__` falls back to
             * "dev" and is never empty. Kept because it is the behaviour OpenIG's bootstrap has
             * (no urlArgs at all), and this shape is the candidate for moving into commons.
             */
            return url;
        }

        return url + (url.indexOf("?") === -1 ? "?" : "&") + settings.urlArgs;
    }

    /**
     * Supplies the query string appended to every resolved asset URL.
     *
     * Must be called before the first asset is fetched. `UIUtils.fetchTemplate` is on the login
     * render path, so "before the first template" means during bootstrap, not lazily. Calling it
     * after the first URL has been resolved throws, because the URLs already handed to a `<link
     * href>` or to DataTables' `sUrl` cannot be recalled and would be missing the cache-buster
     * that every later URL carries.
     *
     * Note this contract is deliberately narrower than the commons `LoaderRuntime.configure` this
     * helper is destined to be bound into: that one also accepts `urlArgs` as a function, which is
     * RequireJS's own normalised form. A string is all any AM call site needs, and rejecting the
     * rest keeps the two seams from quietly disagreeing about what a function-valued `urlArgs`
     * receives.
     *
     * @param {Object} options Configuration.
     * @param {string} options.urlArgs Query string to append, without a leading `?` or `&` - for
     *   example `"v=14.8.4"`. Pass an empty string to resolve without a cache-buster.
     */
    resolveAssetUrl.configure = function (options) {
        if (!options || typeof options.urlArgs !== "string") {
            throw new Error("resolveAssetUrl.configure requires { urlArgs: <string> }.");
        }
        if (settings.resolved) {
            throw new Error(
                "resolveAssetUrl.configure called after the first URL was already resolved. " +
                "Those URLs carry no cache-buster and cannot be recalled; configure during " +
                "bootstrap, before the first asset is fetched.");
        }
        settings.urlArgs = options.urlArgs;
    };

    /**
     * Restores the unconfigured state.
     *
     * For tests only. The module holds its settings at module scope, which under Karma/Squire is
     * per-injector and so isolated per spec - but under D12's Vitest migration one module instance
     * is shared across a file unless `vi.resetModules()` runs between tests. This gives that
     * migration a supported way to reset rather than reaching into module internals.
     */
    resolveAssetUrl.reset = function () {
        settings.urlArgs = null;
        settings.resolved = false;
    };

    return resolveAssetUrl;
});
