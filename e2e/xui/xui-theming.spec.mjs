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
 * `config/ThemeConfiguration.js` and rebuilding -- under D6 that file is bundled source, not a
 * deployed one, and the D6 section below is the whole of what that changes for this spec.
 * `ThemeManager.getTheme()` walks that
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
 *     not already lowercase never matches. The realm names here are fixed literals shared with the
 *     build flag below, and the fixture asserts they are lowercase rather than trusting that
 *     whoever next edits them will keep them so;
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
 * === The theme configuration is bundled source, so this spec asserts the build (D6) ===
 *
 * This file used to write its mappings into `config/ThemeConfiguration.js` inside the deployed
 * `/XUI` and restore the file afterwards. That file does not exist in a built tree any more: the
 * theme configuration is an ordinary bundled module, reached by a static ESM import at
 * `ThemeManager.js:19` and emitted inside a content-hashed chunk together with ~30 other modules.
 * Two consequences shape every fixture below.
 *
 *   - **There is nothing left to intercept, and intercepting is now actively harmful.** One request
 *     for `config/ThemeConfiguration.js` is still issued on every page load, which makes the naive
 *     answer look like "yes" — but it is a `HEAD`, it 404s, and it is issued by
 *     `warnRetiredConfig.js` (task 7.4), whose entire job is to tell an operator that a file left
 *     behind in a tree upgraded in place is no longer read. Measured: fulfilling that route with a
 *     body mapping the root realm to `fr-dark-theme` leaves the applied theme completely unchanged,
 *     and does convince `warnRetiredConfig` that the tree is stale — which is the opposite of what
 *     `xui-retired-config.spec.mjs`'s "a clean tree produces no warning at all" asserts. So the
 *     "preferred alternative" NOTES-theming.md recommends, and the fallback the two describes below
 *     used to offer, are both superseded. Do not restore them.
 *   - **The mapping is a build input, so this spec asserts the build and never performs it.**
 *     `vite.config.js` reads `THEME_CONFIG_OVERRIDE` from the environment and substitutes it as the
 *     `__THEME_CONFIG_OVERRIDE__` define; `config/ThemeConfiguration.js` merges it over the shipped
 *     object. The alternative — having the spec edit tracked product source and run a build — was
 *     rejected for the reason task 6.6 rejected it for `AppConfiguration`: a killed worker leaves
 *     the source tree dirty with no teardown able to reach it. The fixtures probe for the flag and
 *     fail with the exact build command when it is absent, and deliberately never `test.skip()`: a
 *     skipped test reads as a passing one in everything that consumes the result, and the whole
 *     point of the probe is that a missing precondition must be loud.
 *
 * === A mapping needs a realm, and a build flag cannot create one ===
 *
 * That is the difference from 6.6, and it is why the fixture is in two halves that compose in one
 * order and no other. The flag names realms as **fixed lowercase literals** at build time; the
 * fixture creates exactly those realms over REST *before* it probes, and deletes them in teardown.
 * The ordering is load-bearing: an unknown realm renders the default theme just as a tree built
 * without the flag does, so a probe run before the realms exist cannot tell the two apart.
 *
 * Fixed names, where every other realm in this suite comes from `uniqueRealmName()`, and that is a
 * deliberate loss. Uniqueness existed to stop a stale mapping in an editable *deployed file*
 * matching a later run's realm. The mapping now lives in the bundle, this spec never writes it, and
 * there is nothing left to go stale — so the guard protects against nothing while costing the
 * ability to name the realm at build time at all. What it does cost is that two concurrent runs
 * against one instance would collide on a realm name; that is already true of the suite generally,
 * and `playwright.config.mjs` runs one worker. The fixtures delete before they create, so a run
 * killed outright self-repairs on the next one rather than failing it.
 *
 * === Where the expected values come from ===
 *
 * The stylesheet lists, logos and favicon asserted below are read out of the product's own
 * `config/ThemeConfiguration.js`. They used to be read out of the deployed copy of that file, and
 * the reason is unchanged: what is asserted should be "the page shows what the product configures"
 * and not "the page shows what this file remembers the product shipping in 2026", and the spec
 * should fail rather than silently assert nothing if `fr-dark-theme` stops shipping. Only the
 * source moved — from the container to the source tree — because D6 is precisely the decision that
 * those are now the same thing.
 */

import { test as base, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { getAdminToken } from "../common/openam-commons.mjs";
import { createRealm, removeRealm } from "../common/realms-commons.mjs";
import { XUI_BASE } from "../common/xui-commons.mjs";
import {
    XUI_ROOT,
    deployedPathExists,
    placeDeployedFile,
    removeDeployedFile,
    waitForServed,
} from "../common/deployed-xui-commons.mjs";

/** The product's own theme configuration — see "Where the expected values come from" above. */
const THEME_CONFIG_SOURCE = path.resolve(path.dirname(fileURLToPath(import.meta.url)),
    "../../openam-ui/openam-ui-ria/src/main/js/config/ThemeConfiguration.js");

/**
 * The configuration the product ships, read out of its source rather than out of deployed bytes.
 *
 * Evaluated rather than `import`ed, and that is forced rather than chosen: the file is `.js` under a
 * package.json with no `"type": "module"`, so Playwright's loader treats it as CommonJS and dies on
 * `export default`. Making the import work would mean flipping the whole module to `"type":
 * "module"`, which breaks the three CommonJS files at its root (`.eslintrc.js`, `Gruntfile.js`,
 * `karma.conf.js`). The same technique reads `config/AppConfiguration.js` inside
 * `vite.config.js`'s xui-assert-configured-modules plugin, so it is the established way to read a
 * config module from outside the build.
 *
 * `__THEME_CONFIG_OVERRIDE__` is supplied as `""`, which is the *unset* build. So `shippedThemes`
 * is always the baseline the flag adds to and never the flagged result — which is what a themed
 * page has to be compared against.
 *
 * `new Function` is avoided in favour of `vm.runInNewContext` so that the evaluated source cannot
 * see this file's scope. Nothing test-controlled or network-sourced is interpolated into it either
 * way: the only input is a tracked file in this repository, read from disk.
 */
const shippedThemes = (() => {
    const source = fs.readFileSync(THEME_CONFIG_SOURCE, "utf8");
    const context = { __THEME_CONFIG_OVERRIDE__: "", exported: undefined };

    // One anchored replacement, not a parse: `export default` is the module's last statement and
    // the only ESM syntax in the file. If that ever stops being true this throws below rather than
    // silently yielding an empty object, because `exported` stays undefined.
    vm.runInNewContext(source.replace(/^export default /m, "exported = "), context,
        { filename: THEME_CONFIG_SOURCE });

    expect(context.exported && context.exported.themes,
        `${THEME_CONFIG_SOURCE} must export a configuration declaring themes`).toBeTruthy();
    return context.exported.themes;
})();

/** The two themes the product ships. Note the key is not the directory name, which is `dark`. */
const DEFAULT_THEME = "default";
const THEMED = "fr-dark-theme";

/**
 * The theme the override tests inject, and the only key it declares.
 *
 * Neither shipped theme can drive template resolution: `default` sets `path: ""` and
 * `fr-dark-theme` does not declare `path` at all, so `extendTheme` gives it the default's empty
 * one. A theme with a non-empty `path` has to be REGISTERED AT BUILD TIME — under D6 the theme
 * configuration is bundled source, so there is no deployed file to insert one into — and one key is
 * all it takes, everything else merging down from `default`. That registration is what
 * `THEME_CONFIG_OVERRIDE` below carries, and it is why the flag needs a `themes` half and not only
 * a `mappings` one. Measured, so that the next reader does not file it as a bug: with the shipped
 * configuration a file placed at `themes/dark/templates/common/FooterTemplate.html` is served 200
 * by the container and the page issues *zero* requests under `/XUI/themes/` — on disk, served, and
 * unreachable, because with an empty path `UIUtils` never constructs a themed URL at all.
 *
 * `themes/dark/` is the path because it already exists in the deployed tree and holds only
 * `config.json`, `css/` and `images/`. That absence of templates is the fixture for the fallback
 * test: every template the page asks for misses there and has to come from the default location.
 */
const TEMPLATE_THEME = "e2e-template-path";
const TEMPLATE_THEME_PATH = "themes/dark/";

/**
 * The realms this spec drives, as fixed lowercase literals — see "A mapping needs a realm" above.
 *
 * Lowercase because the store lowercases the realm before ThemeManager compares it against the
 * mapping, so an uppercase literal here would match nothing and every realm would quietly render
 * the default theme. The fixtures assert it rather than trusting this comment.
 */
const THEME_REALMS = {
    default: "e2e-theme-default",
    themed: "e2e-theme-dark",
    templated: "e2e-theme-template",
};

/**
 * The theme configuration the deployed tree must have been built with.
 *
 * This is the whole of what the flag carries, and it is deliberately one object rather than two
 * flags: the selection tests need a `mappings` entry, the override tests additionally need a theme
 * that declares a non-empty `path` to exist at all, and a mappings-only flag could not register
 * one. `vite.config.js` passes it through as a JSON *string* — esbuild only inlines primitive
 * `define` values, so an object-valued define would be hoisted into a shared binding and would
 * never tree-shake away when the flag is unset.
 *
 * The mapping order matters and is asserted by the tests rather than by this comment: matching is
 * first-match-wins, and `applyOverride` concatenates these ahead of the shipped `mappings`, which
 * are entirely commented-out examples.
 *
 * The default realm is mapped explicitly rather than left to fall through. That does not change
 * what it renders — the fallback theme is `default` too — but it means a matcher broken in the
 * over-matching direction fails the default half of each assertion instead of going unnoticed.
 */
const THEME_CONFIG_OVERRIDE = {
    themes: { [TEMPLATE_THEME]: { path: TEMPLATE_THEME_PATH } },
    mappings: [
        { theme: THEMED, realms: [`/${THEME_REALMS.themed}`] },
        { theme: DEFAULT_THEME, realms: [`/${THEME_REALMS.default}`] },
        { theme: TEMPLATE_THEME, realms: [`/${THEME_REALMS.templated}`] },
    ],
};

/**
 * What to tell whoever hit the precondition failure.
 *
 * The JSON is stringified from the constant above rather than written out again, so the command
 * printed here cannot drift from what the fixtures assert. It is left as a placeholder rather
 * than derived, because `e2e/local/lib.sh` is a sourced library and not a command. `TARGET_VERSION`
 * is named at all because
 * `npm run build:production` leaves it unset, `vite.config.js` then falls back to "dev", and every
 * runtime-fetched asset gets `?v=dev` — which `xui-cache-busting.spec.mjs` asserts against the
 * deployed AM version, so an otherwise correct rebuild would turn this failure into that one.
 */
const BUILD_REMEDIATION = `

The deployed /XUI was not built with THEME_CONFIG_OVERRIDE. Under design.md D6 the theme
configuration is bundled source, so this spec asserts the build as a precondition and never
performs it. Rebuild and redeploy:

    cd openam-ui/openam-ui-ria
    TARGET_VERSION=<the deployed AM version> \\
        THEME_CONFIG_OVERRIDE='${JSON.stringify(THEME_CONFIG_OVERRIDE)}' \\
        npm run build:production
    ../../e2e/local/xui-deploy.sh target/compiled

Note that xui-deploy.sh replaces the whole tree, so any theme asset placed in the deployed /XUI by
hand is removed by the redeploy. The fixtures here place theirs on every run for that reason.
`;

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
 * The marker text carries `RUN_ID`, so a stale copy of this file left by a killed run — or served
 * out of a cache — cannot satisfy the assertion. It used to carry the realm name, which was unique
 * per run until the build flag forced the realms to be fixed literals; the uniqueness had to move
 * somewhere, and this is the only place it was doing any work. It deliberately contains no mailto
 * anchor, so the override test can also assert the shipped template's content is *gone* rather than
 * that both rendered.
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

/*
 * The deployed-tree primitives themselves live in common/deployed-xui-commons.mjs, shared with
 * xui-operator-module.spec.mjs (task 1.11), which needs the same write-in-place-and-poll mechanics
 * for a file of its own. What stays here is only this spec's binding of them to its own paths.
 */

/**
 * Take the override and the two directories it needed back out of the deployed tree.
 *
 * Both callers rely on `removeDeployedFile` refusing to remove a populated directory — the setup
 * because a theme with its own templates invalidates the fallback test, the teardown because the
 * tree would no longer match what the product ships.
 *
 * Callable when nothing was placed, which is what lets the teardown run unconditionally.
 */
function removeDeployedOverride () {
    removeDeployedFile(OVERRIDE_PATH, OVERRIDE_DIRS);
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

/**
 * Unique per run. See `overrideFooter` — the realms cannot carry this any more.
 */
const RUN_ID = Date.now().toString(36);

/**
 * Load a realm's login page in a throwaway context and read one thing off it.
 *
 * Its own context, and deliberately not the test's `page`: these probes run before `use()`, and
 * everything under `/XUI/*` is served `Cache-Control: public, max-age=2592000`. A probe that shared
 * the test's context would leave the page it loaded in that cache, and the test's own navigation —
 * which for three of the four tests is the thing being measured — would then be answered from the
 * cache rather than from the container.
 */
async function probeThemeFor (browser, realm, read) {
    // `ignoreHTTPSErrors` is restated and is not decoration: a context created straight off
    // `browser` does not inherit the config's `use` block, where playwright.config.mjs sets it, and
    // OPENAM_BASE_URL may be a self-signed https instance. Without it `page.goto` rejects on the TLS
    // error and BUILD_REMEDIATION -- the entire payoff of failing loudly here -- is never printed.
    // xui-operator-module.spec.mjs restates it in its own probe for the same reason.
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    try {
        const page = await context.newPage();
        await page.goto(`${XUI_BASE}/?realm=${realm}#login/`);
        await expect(page.locator(SEL.loginLogo)).toBeVisible();
        return await read(page);
    } finally {
        await context.close();
    }
}

/*
 * Both preconditions are memoised across the file. The build under test cannot change while a run
 * is in flight, so checking once per worker is sound, and the probe costs a page load that would
 * otherwise be paid by all four tests instead of by the first two.
 *
 * They are separate booleans, not one, because they establish different halves of the flag: the
 * `mappings` half selects a shipped theme by realm, the `themes` half registers a theme that does
 * not otherwise exist. A tree built with a hand-edited flag carrying only mappings would pass the
 * first and fail the second, and the failure should name which half is missing.
 */
let mappingPreconditionChecked = false;
let themePreconditionChecked = false;

/** The built configuration maps this realm to the shipped dark theme. */
async function assertMappingWasBuilt (browser, realm) {
    if (mappingPreconditionChecked) {
        return;
    }
    const hrefs = await probeThemeFor(browser, realm, (page) => page.locator(SEL.stylesheets)
        .evaluateAll((links) => links.map((link) => link.getAttribute("href"))));

    expect(hrefs.map(normalizeHref),
        `${realm} must resolve to the "${THEMED}" theme, and resolves to the default one.`
        + BUILD_REMEDIATION)
        .toEqual(shippedThemes[THEMED].stylesheets.map(normalizeHref));

    mappingPreconditionChecked = true;
}

/**
 * The built configuration registers a theme with a non-empty `path` and maps this realm to it.
 *
 * The favicon is the observable, for the same reason `expectThemePathApplied` uses it below:
 * `applyThemeToPage` builds its href as `theme.path + theme.icon` unconditionally, so a non-empty
 * path is visible in the DOM whether or not any template resolved. A stylesheet comparison could
 * not tell this theme from `default`, because it inherits the default's stylesheet list.
 */
async function assertThemeWasBuilt (browser, realm) {
    if (themePreconditionChecked) {
        return;
    }
    const href = await probeThemeFor(browser, realm,
        (page) => page.locator(SEL.favicon).getAttribute("href"));

    expect(normalizeHref(href),
        `${realm} must resolve to a theme declaring path "${TEMPLATE_THEME_PATH}".`
        + BUILD_REMEDIATION)
        .toBe(normalizeHref(`${TEMPLATE_THEME_PATH}${shippedThemes[DEFAULT_THEME].icon}`));

    themePreconditionChecked = true;
}

/**
 * Create one of the realms the build flag names.
 *
 * Deletes first, which `removeRealm` tolerates doing to a realm that is not there. The names are
 * fixed literals now, so a run killed between `createRealm` and its teardown would otherwise fail
 * every subsequent run with "already exists" — a self-inflicted red that says nothing about the
 * product. Deleting first makes that state self-repairing.
 *
 * The lowercase assertion is here rather than in each fixture because it is a property of the
 * literals in `THEME_REALMS`, and those are what a future edit would get wrong.
 */
async function ensureRealm (adminToken, request, name) {
    await removeRealm(adminToken, request, `/${name}`);
    const realm = await createRealm(adminToken, request, { name });
    expect(realm, "a mapping only matches a lowercase realm").toBe(realm.toLowerCase());
    return realm;
}

const test = base.extend({
    /**
     * Two realms that the built configuration maps to two themes, and a teardown that deletes them.
     *
     * Much smaller than it was, and D6 is the reason: the deployed configuration is not written any
     * more, so there is no file to restore, no Tomcat cache window to wait out on the way in or the
     * way out, and no mutation that could outlive this file and change the theme under a later
     * spec. What is left is the half a build flag cannot do — creating the realms the flag names.
     *
     * Still test-scoped rather than worker-scoped, and still for the original reason: worker
     * fixtures are torn down when the worker exits, not when this file finishes, so a worker-scoped
     * version would hold two realms in existence across every later file in the run.
     */
    themedRealms: async ({ browser, request }, use) => {
        const adminToken = await getAdminToken(request);
        expect(adminToken, "the fixture needs an admin session").toBeTruthy();

        // Read out of the product source, so this fails loudly if the theme stops shipping rather
        // than leaving the assertions below comparing undefined against undefined.
        expect(Object.keys(shippedThemes), `the product must still ship the "${THEMED}" theme`)
            .toContain(THEMED);

        let defaultRealm;
        let themedRealm;
        try {
            defaultRealm = await ensureRealm(adminToken, request, THEME_REALMS.default);
            themedRealm = await ensureRealm(adminToken, request, THEME_REALMS.themed);

            // After the realms exist and never before. An unknown realm renders the default theme
            // exactly as a tree built without the flag does, so a probe run first cannot tell those
            // two apart — it would report a missing build for what is really a missing realm, and
            // send the reader off to rebuild something that is already correct.
            await assertMappingWasBuilt(browser, themedRealm);

            await use({ defaultRealm, themedRealm, themes: shippedThemes });
        } finally {
            for (const realm of [themedRealm, defaultRealm].filter(Boolean)) {
                await removeRealm(adminToken, request, realm);
            }
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
     * The theme itself is registered by the build flag, not by this fixture, and that is the one
     * thing here D6 took away. What remains on disk is the override file, which is the subject of
     * the test rather than a means of configuring one.
     */
    templateTheme: async ({ browser, request }, use) => {
        const adminToken = await getAdminToken(request);
        expect(adminToken, "the fixture needs an admin session").toBeTruthy();

        // The override tests exist to show that a theme registered ONLY at build time takes effect.
        // A product that started shipping this key would make them prove nothing at all, while
        // still passing.
        expect(shippedThemes[TEMPLATE_THEME],
            `"${TEMPLATE_THEME}" must not be a theme the product ships — the override tests exist `
            + "to show a theme registered only through THEME_CONFIG_OVERRIDE takes effect")
            .toBeUndefined();

        let realm;
        try {
            realm = await ensureRealm(adminToken, request, THEME_REALMS.templated);

            // Start from a known-absent override rather than assuming it. A previous run killed
            // outright leaves the file, and a fallback test that ran against it would fail while
            // pointing at the wrong thing entirely. `xui-deploy.sh` `rm -rf`s the tree before it
            // copies, so a redeploy also takes the file away — which is why nothing here may assume
            // a previous run left anything behind, in either direction.
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

            // Last, so that it runs against the same absent-override tree the tests do, and after
            // the realm exists for the reason given in `themedRealms`.
            await assertThemeWasBuilt(browser, realm);

            const marker = `template-override-${RUN_ID}`;
            await use({
                realm,
                themes: shippedThemes,
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
            // The removal is synchronous and comes before any await, so a test killed by its
            // timeout cannot be cut short before it.
            removeDeployedOverride();
            try {
                try {
                    await waitForOverrideAbsent(request, "gone from the deployed tree again");
                } finally {
                    if (realm) {
                        await removeRealm(adminToken, request, realm);
                    }
                }
            } finally {
                // The directories are checked as well as the file. They did not exist before this
                // fixture ran, and an empty `themes/dark/templates/` left behind is a deployed tree
                // that no longer matches what the product ships.
                //
                // In its own `finally` so that a timeout in waitForOverrideAbsent, or a realm that
                // would not delete, cannot skip it. Those are the runs most likely to have left
                // something behind, so they are the ones the check exists for -- and skipping it
                // there was the whole of the bug. A failure here does mask one raised above it,
                // which is the right way round: a deployed tree that no longer matches the product
                // breaks every later run, and a realm that outlived its fixture breaks only this
                // one, which `ensureRealm` already repairs on the next.
                for (const path of [OVERRIDE_PATH, ...OVERRIDE_DIRS]) {
                    expect(deployedPathExists(path), `${path} must not be left in the deployed /XUI`)
                        .toBe(false);
                }
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
 * D16 puts on both backends — but because of how it establishes its premise: it needs a tree built
 * with a specific `THEME_CONFIG_OVERRIDE` and deployed by `local/xui-deploy.sh`. The local API
 * server of D13 serves whatever tree it is pointed at and knows nothing of a build flag, so the
 * precondition these fixtures assert has no meaning there.
 *
 * Note what that reason is NOT. These two tests no longer touch the container at all — under D6
 * there is no deployed configuration file to edit, so all they do is create realms over REST and
 * read a page. The tag is about the deployment, not about a `docker exec`, and it is deliberately
 * left as `@deployed-am` alone rather than widened: task 7.4 established that `@local-server` must
 * not be declared until CI can actually run it, and `.github/workflows/xui-local-server.yml:261`
 * starts `node local/server.mjs` with no tree of its own and no container behind it.
 *
 * The interception fallback this block used to offer is gone; the file header says why. There is no
 * `config/ThemeConfiguration.js` request left whose fulfilment would change a theme, and fulfilling
 * the one that does remain breaks `xui-retired-config.spec.mjs`.
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
 * The describe above needs a specific build; this one needs that AND execs into a container by
 * name, because the override file genuinely goes on disk. The fixture could have served it from
 * `context.route(...).fulfill(...)` instead — verified to work — but the capability under test is
 * precisely that a file placed in the deployed tree is picked up, so faking the response would
 * assert the fallback logic while assuming away the thing D3 promises. D6 does not change that
 * trade. What D6 changes is the other half: the *theme* can no longer be injected at all, and is a
 * build precondition instead.
 *
 * The cost of that choice, which D16 requires be said out loud rather than discovered: once the
 * local API server of D13 exists, these two tests are absent from every run against it. Neither the
 * theme-path template contract nor the partial fallback is covered there, and both are instances of
 * "a broken runtime template fetch" — one of the three failure modes D11 names as the reason this
 * suite exists. The cheap half used to be to intercept `config/ThemeConfiguration.js` and keep only
 * the override file on disk. D6 removes that option, so closing the gap now means teaching the
 * local server about a built tree, which is more than this file can decide. It is not closed here.
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
