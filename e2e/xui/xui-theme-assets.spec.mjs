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
 * OpenAM XUI — theme assets stay editable in a deployed instance.
 *
 * One requirement, four tests: `ui-customization` / *Theme assets remain editable in a deployed
 * instance* says theme stylesheets, images, templates and partials "SHALL remain individually
 * addressable files in a deployed instance, so an operator can add or replace an asset of an
 * already-registered theme without rebuilding the product". This file edits one of each, alone, in
 * the running container's `/XUI`, and asserts the running page changed. Nothing is rebuilt.
 *
 * === Why four tests and not one representative case ===
 *
 * The four kinds fail independently and for different reasons, so a single case would leave three
 * untested. A stylesheet is `<link>`ed by `applyThemeToPage` out of the theme's own `stylesheets`
 * array; an image is an `<img src>` resolved from `theme.settings`; a template is fetched and
 * Handlebars-compiled by `UIUtils.compileTemplate`; a partial goes through `preloadPartial`, a
 * different call site with a different cache. A build change can bundle, hash or inline any one of
 * them without touching the others — that is exactly what `?raw` imports would have done to
 * templates (design.md D22), and what content hashing would do to images. Each test therefore
 * names its own file and its own observable.
 *
 * === What this is guarding, and how it differs from xui-theming.spec.mjs ===
 *
 * That file asserts *which* theme a realm resolves to, and what a theme with a non-empty `path` can
 * override. This one asserts the flatter fact underneath both: that these files are still files.
 * `ui-build-and-packaging` / *Deployed directory layout* requires them deployed "as individually
 * addressable files at paths stable across builds", not bundled and not content-hashed, and
 * design.md D3 keeps `themes/`, `templates/`, `partials/` and `locales/` copied verbatim into the
 * build output for exactly this reason. If a later build change bundles any of them, the file on
 * disk stops being the file the page reads and every test here fails.
 *
 * === The empty theme path makes these four simpler than they look, and that is worth stating ===
 *
 * The shipped `default` theme sets `path: ""` (`config/ThemeConfiguration.js`) and `fr-dark-theme`
 * declares no `path` at all, so `extendTheme` gives it `""` too. With an empty path the
 * theme-prefixed URL *is* the unprefixed URL: `UIUtils.compileTemplate` and `preloadPartial` take
 * their `else` branch and never construct a themed URL. So all four edits below are ordinary static
 * files under the default theme, needing no theme, no realm, no mapping and no build — which is the
 * plain reading of the requirement, and the whole of its *Stylesheet edited in a deployed instance*
 * scenario.
 *
 * **It is NOT the whole of the requirement.** The other scenario, *Template override added to a
 * deployed instance*, says "under the asset path of a theme already registered in the built
 * configuration" — and since no shipped theme declares a non-empty `path`, that scenario cannot be
 * reached by a file edit alone. A theme with a path has to be REGISTERED AT BUILD TIME, which under
 * D6 means a rebuild, because the theme configuration is bundled source. Measured: with the shipped
 * configuration a file placed at `themes/dark/templates/common/FooterTemplate.html` is served 200 by
 * the container and the page issues *zero* requests under `/XUI/themes/` — the file is on disk,
 * served, and unreachable. That half lives in `xui-theming.spec.mjs`, whose fixtures assert a build
 * carrying `THEME_CONFIG_OVERRIDE` as a precondition. This is D6 working as designed and not a bug:
 * registration is configuration, and configuration needs a rebuild; the assets under a registered
 * path do not.
 *
 * === Three things defeat these tests if you get them wrong ===
 *
 * All three are recorded in NOTES-theming.md against the Grunt tree and were re-measured against
 * the Vite tree, where all three behave identically:
 *
 *   - **Tomcat's `WebResourceRoot` cache** serves the previous bytes for ~5s after a write
 *     (`cacheTtl` defaults to 5000). Measured here at 4.9s for a path already primed by an earlier
 *     request, and 0.5–0.7s for one nothing has asked for yet. Every edit below therefore polls the
 *     *served* bytes and never sleeps — see `waitForServedContent`;
 *   - **the browser cache.** Everything under `/XUI/*` is served `Cache-Control: public,
 *     max-age=2592000` — verified present on `templates/`, `css/`, `images/`, `partials/` and
 *     `themes/` alike. A `page.reload()` in a context that already loaded the page still renders
 *     the stale asset; a fresh `browser.newContext()` does not. Playwright gives each test its own
 *     context, which is what makes these tests safe, and it is why no test here navigates twice;
 *   - **the `?v=` cache-buster is fixed within a build.** Across 33 runtime fetches on one login
 *     load the set of distinct query strings is exactly `["?v=<build version>"]`. The source moved
 *     in the migration — it is `main.js`'s `LoaderRuntime` `urlArgs` fed by `__TARGET_VERSION__`
 *     now, not RequireJS's — but the consequence is unchanged: there is no URL-level cache-bust
 *     available to a spec. The `?probe=` parameter below is not one either; Tomcat keys its
 *     resource cache on the path, so it only stops a *client* cache answering the poll.
 *
 * === Deployed AM only ===
 *
 * D16: this establishes its premise by editing a file inside a named Docker container, so it cannot
 * run against the local API server of D13, which has no container to exec into. The behaviour it
 * asserts is ordinary UI behaviour and would be valid on both backends; it is the placement seam
 * that is not portable. Interception is not an option here even in principle — the capability under
 * test is precisely that a file placed in the deployed tree is picked up, so serving the bytes from
 * `context.route(...).fulfill(...)` would answer the question by assuming it.
 */

import { test as base, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { XUI_BASE } from "../common/xui-commons.mjs";
import {
    AM_CONTAINER,
    XUI_ROOT,
    deployedSha256,
    sha256,
    writeDeployedFile,
} from "../common/deployed-xui-commons.mjs";

/**
 * The four files, one per asset kind, each chosen because the login page reads it and because its
 * effect is visible without a session.
 *
 * `css/theme.css` is the third and last entry in the default theme's `stylesheets`, so a rule added
 * to it wins the cascade against the other two without needing `!important` for ordering reasons —
 * it carries one anyway, because `#footer`'s shipped background comes from `structure.css` with
 * equal specificity.
 *
 * `images/login-logo.png` is what the default theme's `settings.loginLogo.src` names, and the only
 * image on the login page that comes from theme configuration rather than from CSS.
 *
 * `templates/common/FooterTemplate.html` is 16 lines, includes no partials, and renders plain
 * visible text into `#footer`. It is also the one template on this page whose rendered text no
 * theme *setting* can change, so text appearing there can only have come from the template file.
 *
 * `partials/login/_Default.html` is one of the 19 `partialUrls` in `AppConfiguration`, and it
 * renders the username field. It is reachable only through `preloadPartial` — a different call site
 * from the template above, with its own theme-path-then-fallback logic and its own cache.
 */
const ASSETS = {
    stylesheet: "css/theme.css",
    image: "images/login-logo.png",
    template: "templates/common/FooterTemplate.html",
    partial: "partials/login/_Default.html",
};

const SEL = {
    // Rendered by FooterTemplate, and the element css/theme.css is made to restyle.
    footer: "#footer",
    footerMailto: "#footer a[href^=\"mailto:\"]",
    templateMarker: "#footer #e2e-template-marker",
    // Rendered by LoginHeaderTemplate from the resolved theme's settings.loginLogo.
    loginLogo: "img.main-logo",
    // Rendered by partials/login/_Default.html, along with the marker the partial test prepends.
    usernameInput: "#idToken1",
    partialMarker: "#e2e-partial-marker",
};

/**
 * A 1x1 transparent PNG.
 *
 * The image assertion is on `naturalWidth`/`naturalHeight`, which is a property of the *decoded
 * bytes* and of nothing else — not of the URL, not of an attribute, not of CSS. The shipped logo is
 * 225x57, so a page reporting 1x1 at the same `src` can only have decoded the file this test wrote.
 * That is what makes it a proof for the binary case specifically: a text marker would prove the
 * bytes were served, this proves they were *used*.
 */
const ONE_BY_ONE_PNG = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
    "base64");

/**
 * Unique per run, so that no assertion below can be satisfied by a stale copy — of a file left by a
 * killed run, or of a response held in a cache this spec does not control.
 */
const RUN_ID = `${Date.now().toString(36)}`;

/**
 * The string every text edit below carries, and the one thing `editDeployedAsset` looks for to tell
 * a file the product ships from one an earlier run left behind.
 *
 * It exists because the fixture takes whatever is on disk as the pristine bytes, and has no other
 * way to know better. A run killed between the write and its teardown — Ctrl-C, a worker crash, a
 * SIGKILL — leaves its edit in place; the next run would otherwise adopt that as pristine and
 * *restore to it*, making the damage permanent, and its teardown assertion would compare the file
 * against the leftover's own hash and pass. For `templates/common/FooterTemplate.html`, which is
 * replaced wholesale, that means the deployed footer stays a marker stub for good, and the
 * assertion written to catch exactly this would certify it instead.
 *
 * The binary asset carries no text and so cannot carry this; the fixture checks it against
 * `ONE_BY_ONE_PNG` directly, which is exact for the same reason the image assertion is.
 */
const EDIT_SENTINEL = "e2e-theme-assets-edit";

/**
 * The background colour the stylesheet test asserts, drawn fresh for each run.
 *
 * A fixed colour would be satisfied by a rule a killed run left in the file, whether or not this
 * run's own edit ever reached the page — the leftover guard above makes that state fail loudly
 * rather than pass quietly, and this makes the assertion itself unique so the two are independent.
 * 1..251 per channel keeps every value clear of 0 and 255, the two a shipped rule is most likely to
 * use. `getComputedStyle` normalises to `rgb(r, g, b)` with spaces; the CSS is written without them,
 * so the two forms are built separately rather than one being massaged into the other.
 */
const RUN_RGB = Array.from(randomBytes(3), (byte) => 1 + (byte % 251));
const RUN_COLOUR = `rgb(${RUN_RGB.join(", ")})`;
const RUN_COLOUR_CSS = `rgb(${RUN_RGB.join(",")})`;

/**
 * Read a deployed file as raw bytes.
 *
 * `readDeployedFile` in common/ decodes as UTF-8, which is right for the three text assets and
 * silently corrupts the PNG — a round trip through a JS string replaces every byte that is not
 * valid UTF-8 with U+FFFD, so the "restored" image would be a different file that still looked
 * plausible. `execFileSync` with no `encoding` returns a Buffer, and `writeDeployedFile` passes its
 * argument straight to stdin, so bytes survive both directions.
 */
function readDeployedBytes (path) {
    return execFileSync("docker", ["exec", AM_CONTAINER, "cat", path]);
}

let probeCounter = 0;

/**
 * Wait until the bytes the container serves at a URL satisfy a predicate.
 *
 * The byte-level twin of `waitForServed` in common/, which decodes to text and so cannot be used
 * for the image. `response.body()` is a Buffer either way, and Playwright has already undone any
 * `Content-Encoding`, so an exact `equals` against what was written is a sound comparison for all
 * four kinds.
 *
 * Not replaceable by a sleep, and the reason is in this file's header: Tomcat's resource cache
 * makes the file on disk and the file on the wire disagree for several seconds after a write, and a
 * page opened inside that window silently renders the previous asset. The `?probe=` parameter does
 * not dodge that cache — Tomcat keys it on the path — it is there so no client-side cache answers
 * this poll instead of the server.
 */
async function waitForServedContent (request, url, predicate, what) {
    await expect.poll(async () => {
        probeCounter += 1;
        const response = await request.get(`${url}?probe=${RUN_ID}-${probeCounter}`);
        return response.ok() ? predicate(await response.body()) : false;
    }, {
        message: `${url} must be served ${what}`,
        timeout: 30_000,
        intervals: [250, 500, 1000],
    }).toBe(true);
}

const test = base.extend({
    /**
     * Edit files the product ships, and put every one of them back.
     *
     * Handed to the test as a function rather than as a fixed set of edits, because each test edits
     * exactly one asset: the requirement is that each kind works on its own, and a fixture that
     * edited all four at once would let one kind's success mask another's failure. The bookkeeping
     * is here rather than in the test bodies so that the restore runs on a failing test, on a
     * timed-out test and on a test that never reached its assertions.
     *
     * The restore is a byte restore and not a removal: unlike the override files in
     * xui-theming.spec.mjs, all four of these exist in the shipped tree. `writeDeployedFile` goes
     * through a `cp -p` sibling and an atomic `mv`, so the file is only ever the old bytes or the
     * new ones and its `openam:root` ownership survives the replacement — a "restore" that left the
     * product's files owned by someone else, or `644` where the product ships `640`, would not be
     * one.
     *
     * Every write is issued before the first `await` in the teardown, so a worker killed between
     * two of them cannot leave one asset edited and another not.
     */
    editDeployedAsset: async ({ request }, use) => {
        const edited = [];
        try {
            await use(async (relativePath, makeContents) => {
                const path = `${XUI_ROOT}/${relativePath}`;
                const url = `${XUI_BASE}/${relativePath}`;
                const pristine = readDeployedBytes(path);
                const pristineSha = deployedSha256(path);

                expect(pristineSha, `${relativePath} must be readable in the deployed /XUI`)
                    .toBe(sha256(pristine));

                // The round trip above proves the read is faithful, not that these are the bytes
                // the product ships. See EDIT_SENTINEL: without the next two checks a run killed
                // mid-test corrupts the deployed tree permanently, and silently.
                const redeploy = "the deployed /XUI is not what the product ships. Redeploy it " +
                    "(e2e/local/xui-deploy.sh) before running this spec again";

                expect(pristine.includes(EDIT_SENTINEL),
                    `${relativePath} still carries a text edit from an earlier run of this spec: ` +
                    redeploy).toBe(false);

                expect(pristine.equals(ONE_BY_ONE_PNG),
                    `${relativePath} is still the placeholder image an earlier run of this spec ` +
                    `wrote: ${redeploy}`).toBe(false);

                const contents = makeContents(pristine);
                expect(contents.equals(pristine),
                    `the ${relativePath} edit must actually change the file`).toBe(false);

                // Recorded before the write, not after, so that a failure inside `writeDeployedFile`
                // still leaves the teardown able to put the file back.
                edited.push({ relativePath, path, url, pristine, pristineSha });

                writeDeployedFile(path, contents);
                expect(deployedSha256(path), `the ${relativePath} edit must have reached the container`)
                    .toBe(sha256(contents));
                await waitForServedContent(request, url, (body) => body.equals(contents),
                    "with this test's edit");

                return { path, url, pristine };
            });
        } finally {
            for (const asset of edited) {
                writeDeployedFile(asset.path, asset.pristine);
            }
            for (const asset of edited) {
                expect(deployedSha256(asset.path),
                    `${asset.relativePath} must be back to the bytes the product ships`)
                    .toBe(asset.pristineSha);
                // Polled as well as checked on disk: the next test opens its page immediately, and
                // Tomcat would serve it this test's edit for the rest of the cache TTL otherwise.
                await waitForServedContent(request, asset.url,
                    (body) => body.equals(asset.pristine), "unmodified again");
            }
        }
    },
});

/**
 * Open the default realm's login page.
 *
 * The wait is on the logo rather than on the username field because the two do not arrive together
 * — `img.main-logo` is measurably absent on some loads at the moment `#idToken1` becomes visible —
 * and three of the four tests read something the logo's arrival implies has rendered.
 *
 * Called exactly once per test. A second navigation in the same context would be answered from the
 * browser cache under `max-age=2592000` and could render either version of the asset.
 */
async function openLoginPage (page) {
    await page.goto(`${XUI_BASE}/#login/`);
    await expect(page.locator(SEL.loginLogo)).toBeVisible();
}

test.describe("XUI theme assets are editable in a deployed instance", { tag: ["@deployed-am"] }, () => {
    test("a stylesheet edited in the deployed tree restyles the page", async ({ page, editDeployedAsset }) => {
        // A colour no shipped stylesheet uses and no other run of this spec has used, so the
        // computed value cannot come from anywhere else -- see RUN_RGB. rgb() rather than a
        // keyword: getComputedStyle normalises to rgb()/rgba() regardless, and comparing against
        // the same form the browser reports keeps the assertion literal.
        const rule = `#footer{background-color:${RUN_COLOUR_CSS} !important;` +
            `/* ${EDIT_SENTINEL} ${RUN_ID} */}`;

        await editDeployedAsset(ASSETS.stylesheet,
            (pristine) => Buffer.concat([pristine, Buffer.from(`\n${rule}\n`, "utf8")]));

        await openLoginPage(page);

        // Appended, not replaced, so the rest of the theme still has to apply — a build that stopped
        // serving this file at all would fail here rather than rendering an unstyled page that
        // happened to satisfy a narrower assertion.
        await expect.poll(async () => page.locator(SEL.footer)
            .evaluate((el) => getComputedStyle(el).backgroundColor),
        { message: "the appended rule must reach the rendered page" }).toBe(RUN_COLOUR);
    });

    test("an image replaced in the deployed tree is the one the page decodes", async ({ page, editDeployedAsset }) => {
        await editDeployedAsset(ASSETS.image, () => ONE_BY_ONE_PNG);

        await openLoginPage(page);

        const logo = page.locator(SEL.loginLogo);

        // The src is unchanged — this is the same path the theme has always named, which is what
        // makes it a proof about the file rather than about configuration. Asserted first, so that
        // a failure below cannot be read as "the theme started pointing somewhere else".
        //
        // Compared after stripping the `./` prefix and the `?v=` the asset resolver adds, neither of
        // which the theme configuration controls — the same normalisation xui-theming.spec.mjs
        // applies for the same reason.
        expect(String(await logo.getAttribute("src")).replace(/^\.\//, "").replace(/\?.*$/, ""),
            "the theme must still name the same image path").toBe(ASSETS.image);

        // naturalWidth/naturalHeight come from the decoded bytes, so this cannot pass unless the
        // browser decoded the file this test wrote. `complete` guards the case where the assertion
        // runs before the decode finishes, where both dimensions read 0 and would fail confusingly.
        await expect.poll(async () => logo.evaluate((img) => (img.complete
            ? `${img.naturalWidth}x${img.naturalHeight}`
            : "decoding")), { message: "the replacement image must be the one decoded" })
            .toBe("1x1");
    });

    test("a template replaced in the deployed tree renders in place of the shipped one", async ({ page, editDeployedAsset }) => {
        const marker = `${EDIT_SENTINEL}-template-${RUN_ID}`;

        await editDeployedAsset(ASSETS.template, () => Buffer.from(
            `<div class="container"><p id="e2e-template-marker">${marker}</p></div>`, "utf8"));

        await openLoginPage(page);

        // The marker exists nowhere but the file this test wrote, and no theme setting feeds this
        // template, so text here can only mean the replacement was fetched, compiled and rendered.
        await expect(page.locator(SEL.templateMarker)).toHaveText(marker);

        // And the shipped template did not also render. Without this the test would pass for an
        // implementation that inlined the shipped template into the bundle and appended the
        // deployed one — which is precisely the D3 regression this file exists to catch.
        await expect(page.locator(SEL.footerMailto)).toHaveCount(0);
    });

    test("a partial edited in the deployed tree renders in every template that includes it", async ({ page, editDeployedAsset }) => {
        const marker = `${EDIT_SENTINEL}-partial-${RUN_ID}`;

        // Prepended, with the shipped markup left intact below it. Replacing the file wholesale
        // would prove the same thing about the fetch but would take the login form with it, and the
        // form is what shows the partial is still being *included* rather than merely served.
        await editDeployedAsset(ASSETS.partial, (pristine) => Buffer.concat([
            Buffer.from(`<span id="e2e-partial-marker">${marker}</span>\n`, "utf8"),
            pristine,
        ]));

        await openLoginPage(page);

        // preloadPartial is a different call site from compileTemplate above, with its own cache, so
        // this is not a second measurement of the template test.
        await expect(page.locator(SEL.partialMarker)).toHaveText(marker);

        // The form still renders. A partial that failed to load leaves the page looking almost
        // right — the logo, the footer and the theme all survive it — and only the username field
        // and the submit button go missing, so this is the assertion that tells "the edited partial
        // rendered" from "the partial broke and something else rendered".
        await expect(page.locator(SEL.usernameInput)).toBeVisible();
    });
});
