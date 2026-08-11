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

/**
 * OpenAM XUI — the cache-buster on a template fetched at runtime.
 *
 * `index.html` boots RequireJS with a pre-existing `require` global carrying `urlArgs : "v=${version}"`,
 * where `${version}` is substituted to the AM version by Maven resource filtering and by Grunt's
 * `replace:buildNumber`. The Gruntfile states the intent outright: force the browser to refetch after a
 * new version of AM is deployed. Every url RequireJS resolves therefore ends in `?v=<AM version>`.
 *
 * Templates are not AMD modules here — the XUI fetches them with jQuery, through the single entry point
 * `UIUtils.fetchTemplate`, and only borrows RequireJS's url resolution:
 *
 *     $.ajax({ type: "GET", url: require.toUrl(url), dataType: "html" })
 *
 * So the cache-buster on a template fetch comes from `urlArgs` via `toUrl`, and from nowhere else.
 * `$.ajax` contributes nothing: it appends its own `_=<timestamp>` only when `cache === false`, which
 * jQuery defaults to only for the `script`/`jsonp` dataTypes, and this is `html`.
 *
 * That `toUrl()` applies `urlArgs` at all was the open question in design.md D4, and it is settled:
 * in the deployed requirejs-2.3.7-min.js, `toUrl` only splits a trailing extension off the id and
 * forwards to `nameToUrl`, whose single return is
 *
 *     return config.urlArgs && !/^blob\:/.test(url) ? url + config.urlArgs(moduleName, url) : url;
 *
 * There is no `toUrl`-specific bypass. Confirmed independently in the browser. NOTES-urlargs.md records
 * both readings, the substitution mechanisms, and the measurements behind the notes on flakiness below.
 *
 * What this is guarding: D4 replaces `require.toUrl(url)` with a `resolveAssetUrl(url)` helper that
 * appends the build version, because D3 keeps `templates/`, `partials/`, `themes/` and `locales/`
 * unbundled and unhashed — a Vite content hash never reaches them, so the query parameter is the only
 * thing that gets a redeployed template past a browser cache. Task 4.9 is where the substitution
 * happens; this spec is the baseline it has to match.
 *
 * The two tests are not equally durable, deliberately:
 *
 *   - the network assertion is the contract, and survives the migration verbatim. It says nothing about
 *     *how* the url was resolved, only that a template fetched at runtime carried the deployed version.
 *   - the `require.toUrl()` assertion is mechanism, and is expected to be replaced at task 4.9 along
 *     with the call it pins — there is no `require` global once D1's loader lands. It is here because
 *     it is the one-liner form of the thing D4 has to preserve, and because a failure in it localises a
 *     failure in the other.
 */

import { test, expect } from "@playwright/test";
import { SEL, XUI_BASE, openLoginForm } from "../common/xui-commons.mjs";

/**
 * The template to pin, relative to the XUI base — and the module id `UIUtils` passes to `toUrl`.
 *
 * Chosen because the plain `#login/` load fetches it, so this needs no realm, no auth chain and no
 * fixture, and because it is a real view template rendered through `AbstractView` -> `compileTemplate`
 * -> `fetchTemplate`, i.e. the genuine runtime path rather than one of `AppConfiguration`'s preloads.
 *
 * Not `templates/openam/authn/DataStore1.html`, whose name is the auth *stage* and so changes with the
 * realm's chain, and not `templates/openam/RESTLoginTemplate.html`, which despite being `RESTLoginView`'s
 * declared template is never actually fetched on a default login — the stage template is used instead.
 */
const TEMPLATE = "templates/common/LoginBaseTemplate.html";

/**
 * Both backends. This is the XUI serving its own static tree and resolving urls in the browser, which is
 * the UI-behaviour side of D16's split; D14 has the local server serve the XUI from the same origin and
 * path prefix, so it serves this `index.html` and this template too. Nothing here is AM-side behaviour.
 */
test.describe("XUI cache-busting for runtime-fetched assets", {
    tag: ["@deployed-am", "@local-server"],
}, () => {
    /**
     * The cache-buster's expected value, read from the deployed `index.html` rather than hard-coded, so
     * that a version bump does not turn this spec red — while a missing or unsubstituted one still does.
     *
     * The unsubstituted case is real: `openam-ui-ria/target/XUI/index.html` still holds the raw
     * `v=${version}` token, and deploying *that* directory rather than the `-www.zip` would send every
     * asset url out ending in `?v=$%7Bversion%7D`. Asserting the token is gone is what makes that show up
     * here as a legible failure rather than as a matched pair of wrong values.
     */
    async function deployedVersion (page) {
        const url = `${XUI_BASE}/index.html`;
        const response = await page.request.get(url);
        expect(response.ok(), `the XUI index must be served at ${url}: HTTP ${response.status()}`)
            .toBeTruthy();

        const match = (await response.text()).match(/urlArgs\s*:\s*"v=([^"]+)"/);
        expect(match, `${url} must configure RequireJS urlArgs as v=<version>`).toBeTruthy();
        expect(match[1], "the ${version} token must have been substituted by the build")
            .not.toContain("${");

        return match[1];
    }

    test("a template fetched at runtime carries the build version", async ({ page }) => {
        // Armed before navigating, and this is load-bearing rather than tidy: the login route fetches
        // this template during the initial load, so a listener attached after page.goto sees nothing and
        // the test would fail on an empty array with no hint as to why.
        const templateRequests = [];
        page.on("request", (request) => {
            if (request.url().includes(`/XUI/${TEMPLATE}`)) {
                templateRequests.push(request.url());
            }
        });

        await openLoginForm(page);
        await expect(page.locator(SEL.usernameInput)).toBeVisible();

        const version = await deployedVersion(page);

        // Cold cache is not a hazard here, and this is measured rather than assumed. The server sends
        // `cache-control: public, max-age=2592000` with an ETag, so a warm context may well serve this
        // template out of the browser cache — but Chromium still reports the request to Playwright, so
        // the event fires either way, and the assertion is on the request url rather than on a 200 from
        // the origin. (Asserting on a response status is the formulation that would flake; do not.)
        // Observed: 1 request on a cold context, 1 on a second cold context, 1 on a warm-cache context,
        // 2 across a page.reload(), every one of them carrying the parameter.
        //
        // The one measured way to see zero is to assert after an in-SPA hash navigation: UIUtils memoises
        // each compiled template in `obj.templates`, so navigating away and back does not refetch. Assert
        // on the initial load, as above.
        expect(templateRequests.length, `${TEMPLATE} must be fetched on the login route`)
            .toBeGreaterThan(0);

        // A loop over every capture rather than toHaveLength(1): if a later build legitimately renders
        // the base template twice, that is not this spec's business — but a fetch that lost the
        // parameter still is.
        for (const url of templateRequests) {
            expect(url).toBe(`${XUI_BASE}/${TEMPLATE}?v=${version}`);
        }
    });

    test("require.toUrl() applies the configured urlArgs", async ({ page }) => {
        await openLoginForm(page);

        const version = await deployedVersion(page);
        const resolved = await page.evaluate((template) => require.toUrl(template), TEMPLATE);

        // The leading `./` is the deployed baseUrl, recorded here as part of today's whole-string
        // behaviour. D4's resolveAssetUrl resolves against a configured base instead, so this line is
        // expected to be rewritten at task 4.9 — what has to survive the rewrite is the `?v=` suffix.
        expect(resolved).toBe(`./${TEMPLATE}?v=${version}`);
    });
});
