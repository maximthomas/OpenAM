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
 * OpenAM XUI — theming.
 *
 * Two describes, two halves of the same operator-facing contract: which theme a realm resolves to,
 * and what a theme is then able to replace. The second has its own header, above it.
 *
 * === Theme selection by realm ===
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
 * `config/ThemeConfiguration.js` is still fetched as its own module before treating it as one.
 * "the theme configuration is fetched as its own module, at a stable URL" pins that request
 * specifically, so the intended break has a name of its own — if config has been bundled, it fails
 * and says so, and every other test in this file fails merely as a consequence, including both
 * override tests. What has to keep working past D6 is theme *selection by realm*; how the operator
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

/** The deployed `/XUI`, at the path local/xui-deploy.sh writes the tree to. */
const XUI_ROOT = process.env.OPENAM_XUI_ROOT ?? "/usr/local/tomcat/webapps/openam/XUI";

const THEME_CONFIG_PATH = process.env.OPENAM_THEME_CONFIG
    ?? `${XUI_ROOT}/config/ThemeConfiguration.js`;

const THEME_CONFIG_URL = `${XUI_BASE}/config/ThemeConfiguration.js`;

/** The two themes the product ships. Note the key is not the directory name, which is `dark`. */
const DEFAULT_THEME = "default";
const THEMED = "fr-dark-theme";

/**
 * The theme the override tests inject, and the only key it declares.
 *
 * Neither shipped theme can drive template resolution: `default` sets `path: ""` and
 * `fr-dark-theme` does not declare `path` at all, so `extendTheme` gives it the default's empty
 * one. A theme with a non-empty `path` has to be authored, and one key is all it takes —
 * everything else merges down from `default`.
 *
 * `themes/dark/` is the path because it already exists in the deployed tree and holds only
 * `config.json`, `css/` and `images/`. That absence of templates is the fixture for the fallback
 * test: every template the page asks for misses there and has to come from the default location.
 */
const TEMPLATE_THEME = "e2e-template-path";
const TEMPLATE_THEME_PATH = "themes/dark/";

/**
 * The template the override tests replace, and where a theme's copy of it goes.
 *
 * FooterTemplate because it is 16 lines with no partials, renders plain visible text into
 * `#footer`, and is on the login page — no realm content, no user, no session. It is also the one
 * template on that page whose rendered text no *theme setting* can change: the injected theme
 * declares only `path`, so `settings.footer` merges down from `default` unaltered. Text that
 * appears there instead can therefore only have come from a different template file, which is
 * exactly the thing under test. LoginHeaderTemplate would have failed that: its content comes from
 * `settings.loginLogo`, so an assertion on it cannot tell "the template was overridden" from "a
 * setting was applied".
 */
const FOOTER_TEMPLATE = "templates/common/FooterTemplate.html";
const OVERRIDE_PATH = `${XUI_ROOT}/${TEMPLATE_THEME_PATH}${FOOTER_TEMPLATE}`;
const OVERRIDE_URL = `${XUI_BASE}/${TEMPLATE_THEME_PATH}${FOOTER_TEMPLATE}`;

/**
 * Deepest first — `rmdir` only removes an empty directory, and these two are created by the
 * fixture. Neither exists out of the box, so both are the fixture's to take away again.
 */
const OVERRIDE_DIRS = [
    `${XUI_ROOT}/${TEMPLATE_THEME_PATH}templates/common`,
    `${XUI_ROOT}/${TEMPLATE_THEME_PATH}templates`,
];

const SEL = {
    // LoginHeaderTemplate renders this from the resolved theme's `settings.loginLogo`. It is absent
    // post-login, where the navbar's own logo comes from `settings.logo` instead.
    loginLogo: "img.main-logo",
    // Everything applyThemeToPage wrote back as the theme's stylesheet list. The favicon pair is
    // themeable too — applyThemeToPage builds it from `theme.path + theme.icon` — but neither
    // shipped theme sets those, so it is out of this selector and asserted separately below.
    stylesheets: "head link[rel=\"stylesheet\"]",
    favicon: "head link[rel=\"icon\"]",
    // What FooterTemplate renders. The mailto anchor is the shipped template's own structure
    // carrying the theme's configured address; the marker only exists in the override below.
    footerMailto: "#footer a[href^=\"mailto:\"]",
    overrideMarker: "#footer #e2e-template-override",
    // Rendered by partials/login/_Default.html, so it is the one observable on this page that
    // comes from preloadPartial rather than from compileTemplate. Kept here rather than imported
    // from xui-commons, whose own SEL this one shadows, so that all four selectors this file
    // reasons about are declared together — the value is the same `#idToken1`.
    usernameInput: "#idToken1",
};

/**
 * A theme's replacement for FooterTemplate.
 *
 * The marker text is the realm name, which is unique per run: a stale copy of this file left by an
 * earlier run — or served out of a cache — cannot satisfy the assertion. It deliberately contains
 * no mailto anchor, so the override test can also assert the shipped template's content is *gone*
 * rather than that both rendered.
 */
function overrideFooter (marker) {
    return `<div class="container"><p id="e2e-template-override">${marker}</p></div>`;
}

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
 * Add a file to the deployed tree, creating the directories above it.
 *
 * The path goes to `sh` as a positional argument rather than being interpolated into the script:
 * every value here is this file's own constant today, and passing it as `$1` keeps that from
 * mattering the day one of them comes from a realm name or an environment variable.
 *
 * No backup is taken because nothing is being replaced — this file does not exist in the shipped
 * tree, so the restore is a removal (below), not a byte restore.
 */
function placeDeployedFile (path, contents) {
    execFileSync("docker", ["exec", "-i", AM_CONTAINER, "sh", "-c",
        "mkdir -p \"$(dirname \"$1\")\" && cat > \"$1\"", "sh", path], { input: contents });
}

/**
 * Take the override and the two directories it needed back out of the deployed tree.
 *
 * `rmdir` rather than `rm -r`: it removes an empty directory and refuses a populated one, so this
 * can only ever take away the two directories the fixture itself created. A directory that has
 * something else in it survives, and both callers then fail on it — the setup because a theme with
 * its own templates invalidates the fallback test, the teardown because the tree no longer matches
 * what the product ships.
 *
 * The script's exit status is always 0, so a failing `rm` is swallowed as silently as a failing
 * `rmdir`. That is not relied on: nothing here reports success, and every caller establishes the
 * outcome afterwards with `waitForOverrideAbsent` or `deployedPathExists`.
 *
 * Callable when nothing was placed, which is what lets the teardown run unconditionally.
 */
function removeDeployedOverride () {
    execFileSync("docker", ["exec", AM_CONTAINER, "sh", "-c",
        "rm -f \"$1\"; rmdir \"$2\" \"$3\" 2>/dev/null || true",
        "sh", OVERRIDE_PATH, ...OVERRIDE_DIRS]);
}

function deployedPathExists (path) {
    const output = execFileSync("docker", ["exec", AM_CONTAINER, "sh", "-c",
        "if [ -e \"$1\" ]; then echo yes; else echo no; fi", "sh", path], { encoding: "utf8" });
    return output.trim() === "yes";
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

/**
 * The same file with extra entries inserted at the head of the `themes` object.
 *
 * Inserted, for the reasons `withMappings` is: everything the product ships — including the
 * commented-out key-by-key documentation of what a theme may declare — is carried over byte for
 * byte, so a run killed between the write and the restore leaves a file with one theme too many
 * rather than one with the shipped themes rewritten. The head of the object is a safe insertion
 * point because a later key would win over an earlier one of the same name, and these names do not
 * collide with the shipped ones; the fixture asserts both of those by parsing the result back.
 */
function withThemes (source, themes) {
    const opening = "themes: {";
    const start = source.indexOf(opening);
    expect(start, "the deployed ThemeConfiguration must declare a themes object")
        .toBeGreaterThan(-1);

    const rendered = Object.entries(themes)
        .map(([name, theme]) => `    ${JSON.stringify(name)}: ${JSON.stringify(theme)},`)
        .join("\n");
    const at = start + opening.length;
    return `${source.slice(0, at)}\n${rendered}\n${source.slice(at)}`;
}

let probe = 0;

/**
 * Wait until the bytes served at a URL satisfy a predicate.
 *
 * Not decoration, and not replaceable by a sleep. Tomcat's WebResourceRoot caches static resources
 * for `cacheTtl` — 5s by default — so for several seconds after the write the file on disk and the
 * file on the wire disagree, and a page opened in that window silently gets the previous bytes.
 * There is no way round it from the client: RequireJS's `urlArgs` is the fixed build version, the
 * same string before and after the edit, so the request URL cannot be varied to miss the cache.
 *
 * The probe parameter is not an attempt to dodge that cache — Tomcat keys it on the path, so it
 * cannot be dodged. It is there so that no client-side cache answers this poll instead of Tomcat.
 */
async function waitForServed (request, url, predicate, what) {
    await expect.poll(async () => {
        probe += 1;
        const response = await request.get(`${url}?probe=${probe}`);
        return predicate(response.status(), response.ok() ? await response.text() : "");
    }, {
        message: `${url} must be served ${what}`,
        timeout: 30_000,
        intervals: [250, 500, 1000],
    }).toBe(true);
}

function waitForServedConfig (request, predicate, what) {
    return waitForServed(request, THEME_CONFIG_URL,
        (status, body) => status === 200 && predicate(body), what);
}

/**
 * Wait until the deployed tree does not serve the override.
 *
 * The same cache that makes a written file take seconds to appear makes a removed one take seconds
 * to disappear: Tomcat's WebResourceRoot caches the miss as readily as the hit. Without this, the
 * fallback test can run against a 200 for a file that is no longer on disk — and then it fails,
 * loudly and for a reason that has nothing to do with the fallback, while the tree is in fact
 * correct. It cannot pass wrongly: a stale override serves the previous test's marker, which is
 * exactly what the fallback test asserts is absent.
 */
function waitForOverrideAbsent (request, what) {
    return waitForServed(request, OVERRIDE_URL, (status) => status === 404, what);
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

    /**
     * A realm on a theme whose `path` is a directory that ships no templates, and the means to put
     * one template there.
     *
     * The two things it hands over are deliberately split. Every test that uses this fixture gets
     * the theme and the guarantee that the override is *absent*; only the test that wants the
     * override calls `placeFooterOverride`. That is what lets the same fixture set up both halves
     * of the behaviour — a theme that supplies the template and a theme that does not — without
     * either test being able to leave the file behind for the other: the removal in teardown runs
     * whether or not it was ever placed.
     *
     * Teardown, not test body: a test that fails part way through would otherwise leave the
     * mutated config deployed. Later specs in the same run survive that — the leftover mapping
     * names a realm the teardown has deleted, so they fall through to `default` — but the next
     * *run* does not, because the mutated file is what its `pristine` is read from. The injection
     * would then be restored rather than removed, and would stay in the deployed tree
     * indefinitely. That is what the `finally` is protecting against, and it is why the
     * post-conditions below are asserted rather than assumed.
     */
    templateTheme: async ({ request }, use) => {
        const adminToken = await getAdminToken(request);
        expect(adminToken, "the fixture needs an admin session").toBeTruthy();

        const pristine = readDeployedConfig();
        const pristineSha = sha256(pristine);
        const { themes } = parseThemeConfig(pristine);

        let realm;
        try {
            realm = await createRealm(adminToken, request,
                { name: uniqueRealmName("e2e-theme-template") });
            expect(realm, "a mapping only matches a lowercase realm").toBe(realm.toLowerCase());

            const injected = { [TEMPLATE_THEME]: { path: TEMPLATE_THEME_PATH } };
            const mappings = [{ theme: TEMPLATE_THEME, realms: [realm] }];
            const mutated = withMappings(withThemes(pristine, injected), mappings);

            // Same reason as above: parse the rewritten module before it reaches the container, so
            // a shape change in the deployed file surfaces here rather than as a render timeout.
            // The default theme is compared whole because the injected theme inherits from it —
            // if the insertion had disturbed it, every assertion downstream would be measuring the
            // wrong baseline.
            const rewritten = parseThemeConfig(mutated);
            expect(rewritten.themes[TEMPLATE_THEME], "the injected theme must declare only a path")
                .toEqual({ path: TEMPLATE_THEME_PATH });
            expect(rewritten.themes[DEFAULT_THEME], "inserting a theme must leave `default` intact")
                .toEqual(themes[DEFAULT_THEME]);
            expect(rewritten.mappings, "the rewritten module must declare exactly these mappings")
                .toEqual(mappings);

            writeDeployedConfig(mutated);
            expect(deployedSha256(), "the mapping must have reached the container")
                .toBe(sha256(mutated));
            await waitForServedConfig(request, (body) => body.includes(realm),
                "with this test's themed-path mapping");

            // Start from a known-absent override rather than assuming it. A previous run killed
            // outright leaves the file, and a fallback test that ran against it would fail while
            // pointing at the wrong thing entirely.
            //
            // The poll is also what puts the *miss* into Tomcat's resource cache, which is why
            // `placeFooterOverride` then has a TTL to wait out — a file written at a path nobody
            // has asked for yet resolves on the first request. Removing this poll would make the
            // override test faster and stop it detecting a leftover; the trade is deliberate.
            removeDeployedOverride();
            await waitForOverrideAbsent(request, "absent before the test places anything");

            // No theme may ship templates of its own under this path, or the fallback test is not
            // testing a fallback: it would be asserting that a template rendered from the themed
            // location while believing it came from the default one, and would stay green through
            // a migration that dropped the fallback entirely.
            //
            // Checked after the removal above rather than before it, so a leftover from a killed
            // run self-repairs instead of failing the next run. `rmdir` only removes an empty
            // directory, so anything the product shipped alongside the override survives it and is
            // caught here. Nothing in any current build output puts templates under `themes/`, so
            // what this guards is a future one starting to.
            expect(deployedPathExists(OVERRIDE_DIRS[1]),
                `${OVERRIDE_DIRS[1]} must not exist — a theme that ships its own templates makes `
                + "the fallback test assert the opposite of what it claims").toBe(false);

            const marker = `template-override-${realm}`;
            await use({
                realm,
                themes,
                marker,
                placeFooterOverride: async () => {
                    placeDeployedFile(OVERRIDE_PATH, overrideFooter(marker));
                    // Wait for the *served* bytes, not the write: Tomcat answers from its resource
                    // cache for ~5s afterwards, and a page opened inside that window gets the 404
                    // and the default template, which reads as the override having failed.
                    await waitForServed(request, OVERRIDE_URL,
                        (status, body) => status === 200 && body.includes(marker),
                        "with this test's override");
                },
            });
        } finally {
            // Both mutations go back synchronously and before any await, so that a test killed by
            // its timeout cannot be cut short between them. The config first: a leftover override
            // under a themed path no other spec selects is inert, whereas a leftover mapping is
            // felt by whatever runs next.
            try {
                writeDeployedConfig(pristine);
                removeDeployedOverride();
                await waitForServedConfig(request, (body) => body === pristine, "unmodified again");
                await waitForOverrideAbsent(request, "gone from the deployed tree again");
            } finally {
                if (realm) {
                    await removeRealm(adminToken, request, realm);
                }
            }
            expect(deployedSha256(), "the deployed config must be back to its original bytes")
                .toBe(pristineSha);
            // The directories are checked as well as the file. They did not exist before this
            // fixture ran, and an empty `themes/dark/templates/` left behind is a deployed tree
            // that no longer matches what the product ships.
            for (const path of [OVERRIDE_PATH, ...OVERRIDE_DIRS]) {
                expect(deployedPathExists(path), `${path} must not be left in the deployed /XUI`)
                    .toBe(false);
            }
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

/**
 * `theme.path` applied, and the favicon is where it shows.
 *
 * The fallback test asserts that the page renders the shipped footer — which is also what a page
 * with no theme at all renders, so on its own that assertion passes just as well when the theme
 * was never applied, and proves nothing. This is the discriminator: `applyThemeToPage` builds the
 * favicon href as `require.toUrl(theme.path + theme.icon)`, so a non-empty `path` is visible in the
 * DOM whether or not any template resolved. The injected theme declares no `icon`, so extendTheme
 * gives it the default's — the expected href is the injected path against the default's icon.
 *
 * `themes/dark/favicon.ico` does not exist and the browser's request for it 404s. That is the
 * fallback under test showing up somewhere it has no fallback: `applyThemeToPage` writes the href
 * unconditionally, with none of `compileTemplate`'s retry. Harmless — a missing favicon is a
 * missing favicon — and it makes the point that the try-then-default rule is a property of
 * template resolution specifically, not of theming generally.
 */
async function expectThemePathApplied (page, themes) {
    // Both sides of the comparison below are built from this, so if it ever went missing the
    // expectation would degrade to `themes/dark/undefined` and match — weaker, but silently.
    expect(themes[DEFAULT_THEME].icon, "the default theme must declare an icon").toBeTruthy();

    await expect(page.locator(SEL.favicon)).toHaveCount(1);
    await expect.poll(async () => normalizeHref(await page.locator(SEL.favicon).getAttribute("href")),
        { message: "the injected theme's path must have reached applyThemeToPage" })
        .toBe(normalizeHref(`${TEMPLATE_THEME_PATH}${themes[DEFAULT_THEME].icon}`));
}

/**
 * XUI theme template override — an operator's own copy of a template winning, and the default one
 * still rendering for every template the operator did not copy.
 *
 * A theme may set `path`, and `UIUtils` prefixes it onto every template URL: it asks for
 * `<theme.path><template>` first and falls back to the bare `<template>` if that request fails.
 * That is the whole customization contract behind design.md D3 — an operator drops
 * `themes/myTheme/templates/common/FooterTemplate.html` into the deployed tree and it wins, without
 * copying the other ~180 templates they did not want to change. The two tests here are the two
 * halves of it, and neither is meaningful without the other: the first alone would pass for a build
 * that resolves *only* themed templates and 404s the rest of the page, and the second alone would
 * pass for a build that ignores `path` entirely.
 *
 * === Behaviour, not mechanism: why nothing here counts a 404 ===
 *
 * The fallback is implemented today as a real HTTP 404 against the themed path followed by a retry
 * against the default one, once per template per page load — 27 of each on this login page, all
 * swallowed by `.then(null, fallBackToDefaultPath)`. It would be easy, and wrong, to assert that
 * pair.
 *
 * The requirement is that the template *renders*. The 404-then-retry is one way to satisfy it, and
 * it is the way a runtime AMD loader with no knowledge of what is on disk has to satisfy it. A Vite
 * build knows the theme's file list at build time and can resolve the override statically, emitting
 * no 404 at all — that is a strictly better implementation of the same contract, and a spec that
 * counted 404s would fail the migration for it. These tests therefore assert only rendered DOM:
 * the override's text is present when the theme supplies the file, and the shipped template's text
 * is present when it does not. How the loader got there is left free to change.
 *
 * The one mechanism fact worth keeping is a cost, not a contract, and it is recorded in
 * NOTES-theming.md rather than asserted: the fallback costs one 404 per template per page load, so
 * a themed path is ~27 extra requests on the login page. If that ever needs guarding it has to be
 * phrased as an upper bound a zero-404 implementation also passes, never as an equality.
 *
 * === Console errors are not an oracle here, and never were ===
 *
 * A themed page emits ~57 console messages on one login load — a browser-generated "failed to load
 * resource" per missed template plus UIUtils' own "... was not found. Trying ..." log. None of it
 * reaches the user and none of it is assertable. It also cannot be told apart from the noise that
 * is already there: the *default* login page emits two console errors of its own, for
 * `locales/en-US/translation.json` and an unauthenticated `idFromSession`. `pageerror` is the guard
 * that means something — nothing in this flow throws — and the fallback test uses it.
 *
 * === Deployed AM only, and why the file really goes on disk ===
 *
 * Same reason as the describe above: this execs into a container by name. The fixture could have
 * served the override from `context.route(...).fulfill(...)` instead — verified to work, and it
 * would run against the local API server too — but the capability under test is precisely that a
 * file placed in the deployed tree is picked up, so faking the response would assert the fallback
 * logic while assuming away the thing D3 promises. Interception stays the fallback for the day the
 * migration stops serving templates over the network at all, at which point the fixture changes and
 * these assertions do not.
 *
 * The cost of that choice, which D16 requires be said out loud rather than discovered: once the
 * local API server of D13 exists, these two tests are absent from every run against it. Neither the
 * theme-path template contract nor the partial fallback is covered there, and both are instances of
 * "a broken runtime template fetch" — one of the three failure modes D11 names as the reason this
 * suite exists. If that gap needs closing before sign-off, the cheap half is to inject the theme by
 * intercepting `config/ThemeConfiguration.js` and keep only the override file on disk; the describe
 * above already establishes the deployed-config-editing capability, so nothing would be lost.
 */
test.describe("XUI theme template override", { tag: ["@deployed-am"] }, () => {
    test("a template the theme supplies replaces the default one", async ({ page, templateTheme }) => {
        const { realm, marker, placeFooterOverride } = templateTheme;

        await placeFooterOverride();
        await openLoginPageForRealm(page, realm);

        // The marker text exists nowhere but the file the fixture wrote, and no theme *setting*
        // feeds this template — the injected theme declares only `path`, so `settings.footer`
        // comes down from `default` untouched. Text here can only mean the themed file was
        // fetched, compiled and rendered.
        await expect(page.locator(SEL.overrideMarker)).toHaveText(marker);

        // And the shipped template did not also render. Without this the test would pass for an
        // implementation that appended the override to the default instead of replacing it —
        // "wins" is the contract, not "is present".
        await expect(page.locator(SEL.footerMailto)).toHaveCount(0);
    });

    test("a template the theme does not supply still renders from the default path",
        async ({ page, templateTheme }) => {
            const { realm, themes } = templateTheme;

            // Nothing throws on the way. The misses are all rejected jQuery promises caught by the
            // fallback handler; if one ever escapes, this is where it surfaces. This is installed
            // before the navigation because it does not survive one.
            const pageErrors = [];
            page.on("pageerror", (error) => pageErrors.push(error.message));

            await openLoginPageForRealm(page, realm);

            // The theme really did apply. The footer assertion below is identical to what an
            // unthemed page renders, so without this the test would pass just as well if the
            // mapping had silently matched nothing — which is the failure mode most likely to
            // arise, since it is what every realm-matching mistake in this file produces.
            await expectThemePathApplied(page, themes);

            // `themes/dark/` holds nothing fetchable at all, so this template is one of 27 misses
            // that had to come from the default location. Read out of the deployed config rather
            // than written as a literal, so it asserts "the page shows what the operator
            // configured" — the address is a theme setting, and the anchor around it is the
            // shipped template's own structure, which is the part that had to be fetched.
            await expect(page.locator(SEL.footerMailto))
                .toHaveText(themes[DEFAULT_THEME].settings.footer.mailto);
            await expect(page.locator(SEL.overrideMarker)).toHaveCount(0);

            // The login form, which is the other fallback path and the larger one.
            //
            // UIUtils has three try-themed-then-default call sites, not one: `compileTemplate`,
            // `preloadTemplates` and `preloadPartial`. Under this theme they account for 8 template
            // misses and 19 partial misses, so the assertions above — all of which read output of
            // the template path — leave the majority of the surface untested. `#idToken1` is
            // rendered by `partials/login/_Default.html`, one of the 19 `partialUrls` in
            // AppConfiguration, and so is reachable only through `preloadPartial`.
            //
            // Measured, with the theme applied and only `partials/login/_Default.html` made to fail
            // on the default path — a loader whose partial fallback is gone: `img.main-logo` still
            // renders, `#footer` still carries the mailto anchor, `pageerror` is still empty, and
            // the username field and submit button are both absent. Every other assertion in this
            // test passes against a login page with no form on it. This is the one that does not.
            await expect(page.locator(SEL.usernameInput)).toBeVisible();

            expect(pageErrors, "a template missing under the theme path must not surface an error")
                .toEqual([]);
        });
});
