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
 * OpenAM XUI — theme selection by realm.
 *
 * An operator gives a realm its own look by adding an entry to `mappings` in
 * `config/ThemeConfiguration.js` inside the deployed `/XUI`. `ThemeManager.getTheme()` walks that
 * array in order, takes the first entry whose `realms` match the realm the page was opened for, and
 * applies `themes[<that theme>]`: `applyThemeToPage` removes every `<link>` in the document and
 * writes the theme's own list back, and the resolved theme object is what the login templates read
 * their logo out of. All of it is client-side; the server holds no theme state.
 *
 * What this is guarding:
 *
 *   - `themes/` surviving as unbundled static assets that a stylesheet URL in config can still point
 *     at (design.md D3). `fr-dark-theme` names `themes/dark/css/theme-dark.css` and
 *     `themes/dark/images/login-logo-white.png` by path, and neither is reachable from any module —
 *     only the config names them, so a build that tree-shakes or hashes them breaks here;
 *   - the theme *replacing* the stylesheet list rather than merging into it. The assertions compare
 *     the whole `<link rel=stylesheet>` list, in document order, against the list the config
 *     declares, so an appended default sheet fails as loudly as a missing themed one;
 *   - the realm reaching ThemeManager at all. That is a chain — `ServerService.getConfiguration()`
 *     reading `?realm=` off the outer query string, `serverAddRealm`, the store — and the migration
 *     touches every link in it.
 *
 * Three traps, each of which produces a green-looking wrong answer, and each of which is why an
 * assertion below is shaped the way it is:
 *
 *   - the store lowercases the realm before ThemeManager compares it, so a mapping literal that is
 *     not already lowercase never matches. The realm names here come from `uniqueRealmName()`, and
 *     the fixture asserts they are lowercase rather than trusting that they will stay so;
 *   - `?realm=/name` is the only form that sets it. `#login/name` leaves the realm at "/" and every
 *     realm then gets the default theme — a spec written against the hash form passes for the wrong
 *     reason on the default-theme half and fails on the other;
 *   - a theme name that matches nothing does not throw. `extendTheme(undefined, defaultTheme)`
 *     yields the default theme while `globalData.themeName` still reads back the name that was
 *     asked for. `themeName` is therefore not an oracle for anything, and nothing here reads it —
 *     the stylesheet hrefs and the logo `src` are the observables the migration has to preserve.
 *
 * Pre-login only, deliberately. The realm is known from the initial page load, so the whole
 * difference between the two realms is already on the login page and this needs no session. The two
 * post-login surfaces cannot add to it as shipped: `fr-dark-theme` declares only `loginLogo`, so
 * `extendTheme` gives it the default `settings.logo` and `#navbarBrand img` is
 * `images/login-logo.png` on both realms; and the admin console keeps the default stylesheets
 * whichever theme resolved, because `isAdminTheme = Router.currentRoute.navGroup === "admin"` makes
 * ThemeManager substitute `Constants.DEFAULT_STYLESHEETS` for the theme's own list — the rest of the
 * resolved theme still reaches the page there, including that identical navbar logo. Showing a
 * post-login difference would mean authoring a theme rather than using the one that ships.
 *
 * === This spec asserts post-deploy config editing, which D6 removes ===
 *
 * The premise here is that an operator can edit `config/ThemeConfiguration.js` inside the deployed
 * `/XUI` and have the running UI pick it up — that is what the fixture does, and it is exactly the
 * capability D6 drops when config becomes ordinary bundled source. So a failure in this file after
 * phase 2 begins is likely the intended break rather than a regression: check whether
 * `config/ThemeConfiguration.js` is still fetched as its own module before treating it as one. The
 * last test pins that request specifically, so the intended break has a name of its own — if config
 * has been bundled, it fails first and says so, and the two theming tests fail merely as
 * consequences. What has to keep working past D6 is theme *selection by realm*; how the operator
 * expresses the mapping is what changes, and this file will need rewriting around whatever replaces
 * the file, not deleting.
 */

import { test as base, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { getAdminToken } from "../common/openam-commons.mjs";
import { createRealm, removeRealm, uniqueRealmName } from "../common/realms-commons.mjs";
import { DEFAULT_REALM, XUI_BASE } from "../common/xui-commons.mjs";

/** The container the deployed `/XUI` lives in — `AM_CONTAINER` in local/lib.sh. */
const AM_CONTAINER = process.env.OPENAM_CONTAINER ?? "openam-idp";

/** The deployed config, at the path local/xui-deploy.sh writes the tree to. */
const THEME_CONFIG_PATH = process.env.OPENAM_THEME_CONFIG
    ?? "/usr/local/tomcat/webapps/openam/XUI/config/ThemeConfiguration.js";

const THEME_CONFIG_URL = `${XUI_BASE}/config/ThemeConfiguration.js`;

/** The two themes the product ships. Note the key is not the directory name, which is `dark`. */
const DEFAULT_THEME = "default";
const THEMED = "fr-dark-theme";

const SEL = {
    // LoginHeaderTemplate renders this from the resolved theme's `settings.loginLogo`. It is absent
    // post-login, where the navbar's own logo comes from `settings.logo` instead.
    loginLogo: "img.main-logo",
    // Everything applyThemeToPage wrote back as the theme's stylesheet list. The favicon pair is
    // themeable too — applyThemeToPage builds it from `theme.path + theme.icon` — but neither
    // shipped theme sets those, so it is out of this selector and asserted separately below.
    stylesheets: "head link[rel=\"stylesheet\"]",
    favicon: "head link[rel=\"icon\"]",
};

/**
 * Hrefs come out of `require.toUrl()`, so each carries a `./` prefix and a `?v=<maven version>`
 * suffix that neither the config nor the migration controls. Compare the part that is the contract.
 */
function normalizeHref (href) {
    return String(href).replace(/^\.\//, "").replace(/\?.*$/, "");
}

function sha256 (text) {
    return createHash("sha256").update(text).digest("hex");
}

function readDeployedConfig () {
    return execFileSync("docker", ["exec", AM_CONTAINER, "cat", THEME_CONFIG_PATH], {
        encoding: "utf8",
    });
}

/**
 * Overwrite the deployed config in place.
 *
 * `docker exec … 'cat > path'` rather than `docker cp`: the deployed file is 640 openam:root and
 * `docker cp` would replace it with one owned by root, which the Tomcat process — running as
 * openam — then cannot read. Truncating in place keeps the owner and the mode.
 */
function writeDeployedConfig (contents) {
    execFileSync("docker", ["exec", "-i", AM_CONTAINER, "sh", "-c", `cat > "${THEME_CONFIG_PATH}"`], {
        input: contents,
    });
}

function deployedSha256 () {
    const output = execFileSync("docker", ["exec", AM_CONTAINER, "sha256sum", THEME_CONFIG_PATH], {
        encoding: "utf8",
    });
    return output.trim().split(/\s+/)[0];
}

/**
 * The deployed config as an object, evaluated the way RequireJS evaluates it.
 *
 * The expectations below are read out of this rather than written as literals, so what they assert
 * is "the page shows what the operator configured" rather than "the page shows what this file
 * remembers the product shipping in 2026". It also means the spec fails, rather than silently
 * asserting nothing, if `fr-dark-theme` stops shipping.
 *
 * `new Function` will draw a security-review eye, so: the only thing ever passed here is bytes read
 * straight back out of the container this same process writes to, and nothing test-controlled or
 * network-sourced is interpolated into the body. There is no safe-parser alternative — the file is
 * JavaScript, not JSON, and it is evaluated for its side effect of calling `define`.
 */
function parseThemeConfig (source) {
    let captured;
    new Function("define", source)((value) => {
        captured = value;
    });
    expect(captured, "the deployed ThemeConfiguration must be an AMD module calling define()")
        .toBeTruthy();
    return captured;
}

/**
 * The same file with `mappings` entries inserted at the head of the array.
 *
 * Inserted rather than substituted: everything else in the file, including the ~660 bytes of
 * commented-out example mappings the product ships as operator documentation, is carried over byte
 * for byte. The teardown restores the whole file anyway, but a run killed outright leaves whatever
 * was last written, and that should be a file with one extra mapping in it rather than one with the
 * examples stripped out. It also means this makes no assumption about `mappings` being the last key
 * in the module — everything after the insertion point is untouched.
 *
 * The entries go first because matching is first-match-wins; a trailing comma before the shipped
 * comments and the closing bracket is legal and leaves no array hole.
 */
function withMappings (source, mappings) {
    const opening = "mappings: [";
    const start = source.indexOf(opening);
    expect(start, "the deployed ThemeConfiguration must declare a mappings array")
        .toBeGreaterThan(-1);

    const rendered = mappings.map((mapping) => `    ${JSON.stringify(mapping)},`).join("\n");
    const at = start + opening.length;
    return `${source.slice(0, at)}\n${rendered}\n${source.slice(at)}`;
}

let probe = 0;

/**
 * Wait until the *served* config satisfies a predicate.
 *
 * Not decoration, and not replaceable by a sleep. Tomcat's WebResourceRoot caches static resources
 * for `cacheTtl` — 5s by default — so for several seconds after the write the file on disk and the
 * file on the wire disagree, and a page opened in that window silently gets the previous config.
 * There is no way round it from the client: RequireJS's `urlArgs` is the fixed build version, the
 * same string before and after the edit, so the request URL cannot be varied to miss the cache.
 *
 * The probe parameter is not an attempt to dodge that cache — Tomcat keys it on the path, so it
 * cannot be dodged. It is there so that no client-side cache answers this poll instead of Tomcat.
 */
async function waitForServedConfig (request, predicate, what) {
    await expect.poll(async () => {
        probe += 1;
        const response = await request.get(`${THEME_CONFIG_URL}?probe=${probe}`);
        return response.ok() ? predicate(await response.text()) : false;
    }, {
        message: `the deployed ThemeConfiguration must be served ${what}`,
        timeout: 30_000,
        intervals: [250, 500, 1000],
    }).toBe(true);
}

const test = base.extend({
    /**
     * Two realms mapped to two themes in the deployed config, and a teardown that puts the
     * deployed config back.
     *
     * The restore is here, in fixture teardown, and not at the end of a test body: a test that
     * fails half way through leaves the mapping in place otherwise, and a leftover mapping does not
     * fail this spec — it changes the theme under every spec that runs after it, which surfaces
     * somewhere else entirely. The `finally` covers the case the fixture itself throws between the
     * write and `use()`.
     *
     * Test-scoped rather than worker-scoped for the same reason. Worker fixtures are torn down when
     * the worker exits, not when this file finishes, so a worker-scoped version of this would hold
     * the mutation across every later file in the run.
     */
    themedRealms: async ({ request }, use) => {
        const adminToken = await getAdminToken(request);
        expect(adminToken, "the fixture needs an admin session").toBeTruthy();

        const pristine = readDeployedConfig();
        const pristineSha = sha256(pristine);
        const { themes } = parseThemeConfig(pristine);
        expect(Object.keys(themes), `the deployed config must still ship the "${THEMED}" theme`)
            .toContain(THEMED);

        let defaultRealm;
        let themedRealm;
        try {
            defaultRealm = await createRealm(adminToken, request,
                { name: uniqueRealmName("e2e-theme-default") });
            themedRealm = await createRealm(adminToken, request,
                { name: uniqueRealmName("e2e-theme-dark") });

            // The realm has been through the store's toLowerCase() by the time ThemeManager
            // compares it, so a mapping literal that is not lowercase matches nothing and both
            // realms quietly get the default theme. Asserted rather than assumed: it is a property
            // of the prefix passed to uniqueRealmName, which is this file's to get wrong.
            for (const realm of [defaultRealm, themedRealm]) {
                expect(realm, "a mapping only matches a lowercase realm").toBe(realm.toLowerCase());
            }

            // Order is load-bearing: mappings are first-match-wins, so a broader entry placed first
            // swallows the one after it. The default realm is mapped explicitly rather than left to
            // fall through — that does not change what it renders, since the fallback theme is
            // `default` too, but it means a matcher broken in the over-matching direction fails the
            // default half of each assertion instead of going unnoticed.
            const mappings = [
                { theme: THEMED, realms: [themedRealm] },
                { theme: DEFAULT_THEME, realms: [defaultRealm] },
            ];
            const mutated = withMappings(pristine, mappings);

            // Parse the rewritten module back before it goes anywhere near the container. Without
            // this, a shape change in the deployed file that broke the rewrite would still satisfy
            // waitForServedConfig — the body does contain the realm name — and surface 15s later as
            // "img.main-logo never became visible", which names the wrong cause entirely.
            const rewritten = parseThemeConfig(mutated);
            expect(rewritten.themes, "rewriting mappings must leave the themes untouched")
                .toEqual(themes);
            expect(rewritten.mappings, "the rewritten module must declare exactly these mappings")
                .toEqual(mappings);

            writeDeployedConfig(mutated);
            expect(deployedSha256(), "the mapping must have reached the container")
                .toBe(sha256(mutated));
            // The realm names are unique per run, so finding one in the served body cannot be
            // satisfied by a cached copy of anything earlier.
            await waitForServedConfig(request, (body) => body.includes(themedRealm),
                "with this test's realm mapping");

            await use({ defaultRealm, themedRealm, themes });
        } finally {
            // Nested, so that a docker hiccup on the write or a timeout on the poll cannot skip the
            // realm cleanup and leave two realms in a long-lived instance. The config restore goes
            // first because it is the one step whose absence is felt by another spec rather than by
            // this one; it is also synchronous, so it completes even when the test timed out and
            // the surrounding await would have been cut short.
            try {
                writeDeployedConfig(pristine);
                await waitForServedConfig(request, (body) => body === pristine, "unmodified again");
            } finally {
                for (const realm of [themedRealm, defaultRealm].filter(Boolean)) {
                    await removeRealm(adminToken, request, realm);
                }
            }
            expect(deployedSha256(), "the deployed config must be back to its original bytes")
                .toBe(pristineSha);
        }
    },
});

/**
 * Open a realm's login page.
 *
 * `?realm=` on the outer query string and not `#login/<realm>`: `ServerService.getConfiguration()`
 * takes the realm from `URIUtils.getCurrentQueryString()`, which does not see the hash, so the
 * route form leaves ThemeManager resolving a theme for "/".
 *
 * The wait is on the logo rather than on the username field. The two do not arrive together —
 * `img.main-logo` is measurably absent on some loads at the moment `#idToken1` becomes visible — and
 * gating on the form would read the logo's attributes off an element that is not there yet.
 */
async function openLoginPageForRealm (page, realm) {
    await page.goto(`${XUI_BASE}/?realm=${realm}#login/`);
    await expect(page.locator(SEL.loginLogo)).toBeVisible();
}

/**
 * Deployed AM only. Not because of anything it asserts — theme application is UI behaviour, which
 * D16 puts on both backends — but because of how it establishes its premise: it edits a file inside
 * a Docker container by name. The local API server serves the XUI tree from disk (task 2.5) and has
 * no container to exec into, so this fixture cannot run against it as written.
 *
 * That was a choice, not a necessity, and the alternative was tried: NOTES-theming.md records
 * `context.route("**\/config/ThemeConfiguration.js*", …fulfill…)` driving theme selection with the
 * deployed file left pristine — no container, no Tomcat cache window, no restore step, and a spec
 * valid on both backends. It is rejected here because editing the deployed file is what an operator
 * actually does, which makes it the stronger oracle for the capability D6 removes, and because it
 * additionally proves the deployed tree is served live from disk — something interception, which
 * never reaches the server, cannot show. Interception remains the right fallback if this fixture
 * ever becomes the reason the suite cannot run somewhere.
 *
 * The last test in here mutates nothing and would be valid against either backend; it carries the
 * describe's tag rather than one of its own, so it is under-declared rather than mis-declared.
 */
test.describe("XUI theme selection by realm", { tag: ["@deployed-am"] }, () => {
    test("each realm gets the stylesheets of the theme it is mapped to", async ({ page, themedRealms }) => {
        const { defaultRealm, themedRealm, themes } = themedRealms;

        /**
         * Every stylesheet the page ended up with, in document order, against the list the theme
         * declares.
         *
         * Comparing the whole list is what asserts that applyThemeToPage replaced it rather than
         * appending to it: an extra sheet from the default theme fails this as surely as a missing
         * themed one. The two lists share css/structure.css, so an assertion narrowed to a single
         * href could pass against the wrong theme.
         */
        async function expectStylesheets (realm, declared) {
            await openLoginPageForRealm(page, realm);
            await expect.poll(async () => {
                const hrefs = await page.locator(SEL.stylesheets)
                    .evaluateAll((links) => links.map((link) => link.getAttribute("href")));
                return hrefs.map(normalizeHref);
            }, { message: `the stylesheets applied for ${realm}` })
                .toEqual(declared.map(normalizeHref));
        }

        await expectStylesheets(defaultRealm, themes[DEFAULT_THEME].stylesheets);
        await expectStylesheets(themedRealm, themes[THEMED].stylesheets);
    });

    test("each realm gets the login logo of the theme it is mapped to", async ({ page, themedRealms }) => {
        const { defaultRealm, themedRealm, themes } = themedRealms;

        /** The logo the theme declares is the logo the login page renders, attribute for attribute. */
        async function expectLoginLogo (realm, loginLogo) {
            await openLoginPageForRealm(page, realm);
            const logo = page.locator(SEL.loginLogo);

            // toHaveAttribute degrades to a presence-only check when the expected value is
            // undefined, and these come from the theme's own config — so a theme that stopped
            // declaring one of them would quietly weaken the assertion rather than fail it.
            for (const key of ["src", "alt", "width", "height"]) {
                expect(loginLogo[key], `the theme must declare loginLogo.${key}`).toBeTruthy();
            }

            // The src is the one value that tells the two themes apart, so it retries like the
            // assertions under it rather than being read once.
            await expect.poll(async () => normalizeHref(await logo.getAttribute("src")),
                { message: `the login logo for ${realm}` }).toBe(normalizeHref(loginLogo.src));
            await expect(logo).toHaveAttribute("alt", loginLogo.alt);
            // Both themes also declare loginLogo.title, and LoginHeaderTemplate does not render it
            // — the login logo carries src, alt, width and height and nothing else. Recorded rather
            // than asserted: it is a template that ignores a config key, not a theming failure.
            await expect(logo).toHaveAttribute("width", loginLogo.width);
            await expect(logo).toHaveAttribute("height", loginLogo.height);
        }

        await expectLoginLogo(defaultRealm, themes[DEFAULT_THEME].settings.loginLogo);
        await expectLoginLogo(themedRealm, themes[THEMED].settings.loginLogo);

        // Still on the themed realm. fr-dark-theme declares neither `path` nor `icon`, so a favicon
        // built out of the default theme's is what shows that extendTheme merged the two rather
        // than replacing one wholesale. The logo assertions above cannot show it: fr-dark-theme
        // declares a complete loginLogo, so that renders identically either way. Under a wholesale
        // replace this href becomes require.toUrl(undefined + undefined).
        const { path, icon } = themes[DEFAULT_THEME];
        await expect(page.locator(SEL.favicon)).toHaveCount(1);
        expect(normalizeHref(await page.locator(SEL.favicon).getAttribute("href")),
            "the themed realm must inherit the default theme's favicon")
            .toBe(normalizeHref(`${path}${icon}`));
    });

    test("the theme configuration is fetched as its own module, at a stable URL", async ({ page }) => {
        // No mapping and no realm: this asserts the mechanism the other two tests stand on, so it
        // must not depend on them having been set up.
        const fetched = [];
        page.on("request", (request) => {
            if (new URL(request.url()).pathname.endsWith("/config/ThemeConfiguration.js")) {
                fetched.push(request.url());
            }
        });

        await openLoginPageForRealm(page, DEFAULT_REALM);

        // One request, separate from main.js, at a path an operator can write to. This is the
        // baseline for D6 — see the note at the top of this file. When config becomes bundled
        // source, this is the test that is *supposed* to fail, and it failing alongside the other
        // two is how that break is told apart from a theming regression.
        expect(fetched, `${THEME_CONFIG_URL} must be fetched exactly once, as its own module`)
            .toHaveLength(1);
        expect(new URL(fetched[0]).pathname).toBe(new URL(THEME_CONFIG_URL).pathname);
    });
});
