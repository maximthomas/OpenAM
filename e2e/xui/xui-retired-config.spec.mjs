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
 * D6's startup warning: a deployed `/XUI` that still carries the retired config files says so.
 *
 * WHAT IS UNDER TEST. `src/main/js/warnRetiredConfig.js`, called from all three entry points. It
 * HEADs `config/AppConfiguration.js` and `config/ThemeConfiguration.js` through
 * `LoaderRuntime.toUrl` and `console.warn`s about any that answer 200. An in-place upgrade leaves
 * that directory behind, every edit in it silently stops applying, and nothing else in the product
 * reports it.
 *
 * BOTH DIRECTIONS ARE TESTED, AND THE SECOND IS THE LOAD-BEARING ONE. A check only ever seen firing
 * has never been tested for false positives, and a false positive here trains operators to ignore
 * the one message that tells them their customization is dead. So: it fires with a stale file
 * present, and it is *silent* on a clean tree.
 *
 * ALL THREE ENTRY POINTS, because only one of them can be got wrong. `main.js` leaves `baseUrl` at
 * `""` -- the console is served from `/XUI/` -- so on that page resolving through `toUrl` and
 * resolving against the document give the same url, and a broken implementation still passes. The
 * two OAuth2 entries are loaded by `.ftl` pages under `/oauth2/`, where a document-relative url
 * lands on `/oauth2/realms/root/config/AppConfiguration.js` and 404s with the file plainly present.
 * That is design.md D22's regression, it fails silently, and it is why those two tests assert on the
 * probe's URL and not only on the warning.
 *
 * THE CACHING TEST IS NOT DECORATION. `web.xml` maps `CacheForAMonth` to `/XUI/*` and the filter
 * runs before the servlet, so `public, max-age=2592000` lands on the 404 as well as on the 200. A
 * probe written as a plain GET caches the miss for thirty days, and the operator this check exists
 * for -- the one who adds the file after first load -- never sees a warning at all. That is the
 * single most breakable property of the implementation and the one a later "simplification" would
 * take out, so it gets its own test. `?v=<build version>` does not fix it and is not what is being
 * asserted: the version is identical across the two loads, so the cache key is too.
 *
 * BACKENDS (D16): `@deployed-am` only, and the reason is the fixture rather than the behaviour.
 * The *behaviour* was measured valid against both backends -- the local server serves the same
 * static tree from the same origin and path prefix (D14), and a stale file placed in a served
 * directory produces the identical 404 -> 200 transition. What is not portable is the *placement*.
 * Writing into the served tree here means `docker exec` (`common/deployed-xui-commons.mjs`, whose
 * header states that specs using it are `@deployed-am` by construction), and the `@local-server`
 * lane deliberately runs no container: `.github/workflows/xui-local-server.yml` starts
 * `node local/server.mjs` with no argument, so the tree it serves is a `www` zip unpacked into an
 * `mkdtemp` staging directory that no caller can address. Tagging this `@local-server` would not
 * have widened coverage, it would have failed the lane on every pull request. Per D16 that belongs
 * written down rather than left to a quietly red run. `xui-operator-module.spec.mjs`, the only other
 * tree-mutating spec, is `@deployed-am` for the same reason.
 *
 * The cached-404 test would be `@deployed-am` even if placement were portable: the local server
 * sends `no-store` on both the 200 and the 404, so it cannot reproduce the failure that test exists
 * to detect, and would pass there without exercising the property at all.
 */

import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PASSWORD, USERNAME, getAdminToken } from "../common/openam-commons.mjs";
import {
    AUTHORIZE_URL,
    CONSENT_CLIENT_ID,
    DEVICE_USER_URL,
    REDIRECT_URI,
    SCOPE,
    ensureOAuth2ClientExists,
    ensureOAuth2ServiceExists,
    generateChallenge,
    generateVerifier,
} from "../common/oauth2-commons.mjs";
import { SEL, XUI_BASE, loginViaXui, openLoginForm } from "../common/xui-commons.mjs";
import {
    XUI_ROOT,
    deployedPathExists,
    placeDeployedFile,
    removeDeployedFile,
    waitForServed,
} from "../common/deployed-xui-commons.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

/** The path component of the deployed tree root — what a correctly resolved probe must sit under. */
const XUI_PATH = new URL(XUI_BASE).pathname;

const WATCHED = ["config/AppConfiguration.js", "config/ThemeConfiguration.js"];

/**
 * The bytes to plant. A retired `AppConfiguration.js` as the Grunt tree actually shipped it — an
 * AMD `define`, which under the current build is not merely ignored but unloadable.
 *
 * The content is never asserted on and does not need to be the real 9KB file: what is under test is
 * that the *presence* of the path is noticed. It is recognisable on sight in case a run dies
 * between placing and removing.
 */
const STALE_SOURCE = "/* e2e fixture: a retired D6 config file, placed by xui-retired-config.spec.mjs */\n"
    + "define([], function () { return { moduleDefinition: [], loggerLevel: \"debug\" }; });\n";

/**
 * The citation the warning must print, read out of the upgrade note's own front matter rather than
 * copied into this file.
 *
 * This is the pin that keeps 7.3 and 7.4 from drifting. The note carries a comment saying that
 * renaming it means changing the console message with it; reading the string from there means a
 * rename that forgets the message turns this spec red instead of shipping a warning that points at
 * a file nobody can find.
 */
function citation () {
    const note = join(HERE, "..", "..", "openam-ui", "openam-ui-ria", "UPGRADE-XUI-BUILD.md");
    const match = readFileSync(note, "utf8").match(/^citation:\s*'(.+)'\s*$/m);
    expect(match, `${note} must carry a citation: field in its front matter`).toBeTruthy();
    return match[1];
}

/**
 * Collect the product's own warnings and the probe requests that produced them.
 *
 * Warnings are matched on the `[XUI] config/` prefix rather than on `type() === "warning"` alone: a
 * page load emits warnings that have nothing to do with this, and a test that counted all of them
 * would go red for unrelated reasons. Requests are collected by filename rather than by path, so
 * that a probe sent to the WRONG path is still captured and can be asserted against — filtering on
 * the correct path would make the D22 regression look like an absence of probes instead of a
 * misdirected one.
 *
 * Armed before any navigation: a listener attached after `goto` resolves has already missed the
 * load it was meant to watch.
 */
function recordProbes (page) {
    const warnings = [];
    const requests = [];
    page.on("console", (msg) => {
        if (msg.type() === "warning" && msg.text().startsWith("[XUI] config/")) {
            warnings.push(msg.text());
        }
    });
    page.on("request", (request) => {
        if (WATCHED.some((name) => request.url().includes(name))) {
            requests.push(request.url());
        }
    });
    return { warnings, requests };
}

/**
 * Every probe must have gone to the deployed tree, wherever the document itself came from.
 *
 * This is the assertion that fails if the implementation stops resolving through `toUrl`. On the
 * console it is trivially true; on the two OAuth2 pages it is the whole point, and asserting the
 * warning alone would not catch the regression — a document-relative probe 404s, so the page simply
 * stays quiet and every other assertion about "no warning" would still pass.
 */
function expectProbesResolvedAgainstTheTree (requests) {
    const seen = [...new Set(requests.map((url) => new URL(url).pathname))].sort();
    const expected = WATCHED.map((name) => `${XUI_PATH}/${name}`).sort();

    expect(seen,
        `every probe must resolve against the deployed tree at ${XUI_PATH}, not against the `
        + "document. A document-relative url lands on /oauth2/realms/root/config/... and 404s with "
        + "the file plainly present — design.md D22's regression, which produces no warning and no "
        + "other symptom, so this is the only assertion that catches it.")
        .toEqual(expected);
}

/**
 * Place one retired file for the duration of a test, and prove it gone afterwards.
 *
 * The removal is the first statement in the `finally`, so it happens whether or not the
 * confirmations after it do, and whether or not the test body threw.
 *
 * `removeDeployedFile` is handed the `config/` directory as well as the file. That matters as much
 * as the file: a built tree has no `config/` among its 15 top-level entries, so placing anything
 * under it creates a directory that is the fixture's alone, and task 6.6's review caught exactly
 * that leak. It removes the directory with `rmdir`, which takes an empty one and refuses a populated
 * one — so a run against a tree where `config/` is *not* the fixture's takes nothing away.
 */
async function withStaleFile (relative, request, body) {
    const path = `${XUI_ROOT}/${relative}`;
    const url = `${XUI_BASE}/${relative}`;

    expect(deployedPathExists(path),
        `${path} is already in the deployed tree. Either a previous run did not clean up, or this `
        + "is not a Vite build — a Grunt-era tree ships config/ full of the product's own files, and "
        + "this spec is not valid against one. Establish which before deleting anything; a stale "
        + "file left here makes the does-not-fire test meaningless rather than red.").toBe(false);

    try {
        placeDeployedFile(path, STALE_SOURCE);
        // Tomcat caches a negative lookup for cacheTtl (5s default), so the file is on disk before
        // it is on the wire. Poll for the wire, or the browser races the server's own cache.
        await waitForServed(request, url, (status) => status === 200,
            "before the browser is pointed at a tree containing it");
        await body(url);
    } finally {
        removeDeployedFile(path, [`${XUI_ROOT}/config`]);
        await waitForServed(request, url, (status) => status === 404,
            "no longer, once the fixture has removed it");
        expect(deployedPathExists(path), `${path} must not be left in the deployed tree`).toBe(false);
        expect(deployedPathExists(`${XUI_ROOT}/config`),
            "the config/ directory the fixture created must not be left behind — a Vite tree has no "
            + "config/ among its top-level entries").toBe(false);
    }
}

/** The three things the message owes an operator: which file, that it is dead, and where to read. */
function expectWellFormedWarning (warnings, relative) {
    const warning = warnings.find((text) => text.includes(relative));
    expect(warning, `a warning must name ${relative}; got ${JSON.stringify(warnings)}`).toBeTruthy();
    expect(warning).toContain("is no longer read");
    expect(warning.endsWith(citation()),
        `the warning must end with the upgrade note's own citation string.\n got: ${warning}`)
        .toBe(true);
    return warning;
}

test.describe("XUI warns about retired config files in a deployed tree", {
    tag: ["@deployed-am"],
}, () => {
    for (const relative of WATCHED) {
        test(`the warning names ${relative} when it is present in the deployed tree`,
            async ({ page, request }) => {
                const { warnings } = recordProbes(page);

                await withStaleFile(relative, request, async () => {
                    await openLoginForm(page);
                    await expect.poll(() => warnings.length, {
                        message: `${relative} is served by the deployed tree, so the startup check `
                            + "must warn about it",
                        timeout: 15_000,
                    }).toBeGreaterThan(0);
                });

                // At least one, never an exact count: the check runs once per document, so a flow
                // that loads a second page legitimately prints it again.
                expectWellFormedWarning(warnings, relative);

                // The other watched file was NOT planted, so nothing may claim it was found. This is
                // what catches a check that warns about the whole list once any one of them hits.
                const other = WATCHED.find((name) => name !== relative);
                expect(warnings.some((text) => text.includes(other)),
                    `nothing may warn about ${other}: it is not in the tree`).toBe(false);
            });
    }

    test("a clean tree produces no warning at all", async ({ page }) => {
        const { warnings, requests } = recordProbes(page);

        expect(deployedPathExists(`${XUI_ROOT}/config`),
            "this test is meaningless unless the deployed tree really has no config/ directory")
            .toBe(false);

        await openLoginForm(page);
        await expect(page.locator(SEL.usernameInput)).toBeVisible();

        // Give the deferred check the same room it gets in the firing tests before concluding it
        // stayed quiet — asserting an empty array the instant the form renders would pass even if
        // the check were about to warn.
        await page.waitForTimeout(3000);

        expect(warnings, "a correctly upgraded tree must be silent").toEqual([]);

        // Silence is only evidence of a working check if the check actually ran. Without this, an
        // implementation that had been deleted outright would pass this test.
        expect(requests.length, "both files must still have been probed on a clean tree").toBe(2);
    });
});

test.describe("XUI warns about retired config files on the OAuth2 entry points", {
    tag: ["@deployed-am"],
}, () => {
    /*
     * These two pages are the reason the implementation resolves through `toUrl`, and neither is
     * reachable from the console's own routes: they are rendered by `.ftl` templates in
     * openam-oauth2 and served from `/oauth2/...`. The setup is borrowed wholesale from
     * xui-authorize.spec.mjs and xui-device.spec.mjs — the same OAuth2 service and clients — because
     * what is under test here is the entry point booting at all, not the OAuth2 flow.
     */
    test.beforeAll(async ({ request }) => {
        const adminToken = await getAdminToken(request);
        expect(adminToken, "the fixtures need an admin session").toBeTruthy();

        await ensureOAuth2ServiceExists(adminToken, request);
        // Only the consent client. The device test opens the verification form and never submits a
        // code, so it needs no client of its own -- and ensuring the default one would assert an
        // isConsentImplied this instance does not necessarily have, failing this describe for a
        // reason that has nothing to do with the warning.
        await ensureOAuth2ClientExists(adminToken, request, CONSENT_CLIENT_ID, false);
    });

    const RELATIVE = "config/AppConfiguration.js";

    test("main-authorize warns, and probes the deployed tree rather than the /oauth2/ path",
        async ({ page, request }) => {
            const { warnings, requests } = recordProbes(page);

            await withStaleFile(RELATIVE, request, async () => {
                await loginViaXui(page, USERNAME, PASSWORD);

                const params = new URLSearchParams({
                    response_type: "code",
                    client_id: CONSENT_CLIENT_ID,
                    redirect_uri: REDIRECT_URI,
                    scope: SCOPE,
                    state: "retired-config",
                    code_challenge: await generateChallenge(generateVerifier()),
                    code_challenge_method: "S256",
                });
                await page.goto(`${AUTHORIZE_URL}?${params}`);
                await page.waitForFunction(
                    () => document.querySelector("#content")?.children.length > 0);

                await expect.poll(() => warnings.length, {
                    message: "the consent page boots main-authorize, which must run the check",
                    timeout: 15_000,
                }).toBeGreaterThan(0);
            });

            expectWellFormedWarning(warnings, RELATIVE);
            expectProbesResolvedAgainstTheTree(requests);
        });

    test("main-device warns, and probes the deployed tree rather than the /oauth2/ path",
        async ({ page, request }) => {
            const { warnings, requests } = recordProbes(page);

            await withStaleFile(RELATIVE, request, async () => {
                // No session deliberately: the verification page is the one XUI page that renders
                // for a browser that has never logged in, and the check must run there too.
                await page.goto(DEVICE_USER_URL);
                await page.waitForFunction(
                    () => document.querySelector("#content")?.children.length > 0);

                await expect.poll(() => warnings.length, {
                    message: "the device verification page boots main-device, which must run the check",
                    timeout: 15_000,
                }).toBeGreaterThan(0);
            });

            expectWellFormedWarning(warnings, RELATIVE);
            expectProbesResolvedAgainstTheTree(requests);
        });
});

test.describe("XUI warns about a retired config file added after the page was first loaded", {
    tag: ["@deployed-am"],
}, () => {
    /**
     * The regression this pins: a probe that lets the browser cache its own 404.
     *
     * The operator sequence is the realistic one — open the console, notice the customization is
     * gone, copy the old `config/` back in, reload. With a plain GET the reload is answered from the
     * browser cache with the 30-day-old 404 and stays silent. With `cache: "no-store"` it warns.
     *
     * One page, one context, deliberately: a fresh context would have an empty cache and the test
     * would pass against the very implementation it exists to reject.
     */
    test("the warning appears on a reload of the same page, not from a cached 404",
        async ({ page, request }) => {
            const { warnings } = recordProbes(page);
            const relative = "config/AppConfiguration.js";

            // First load against a clean tree. This is what poisons the cache: the probe 404s and
            // web.xml has already stamped `max-age=2592000` on that 404.
            await openLoginForm(page);
            await page.waitForTimeout(3000);
            expect(warnings, "the tree is clean on the first load, so nothing may warn yet")
                .toEqual([]);

            await withStaleFile(relative, request, async () => {
                await page.reload();
                await expect.poll(() => warnings.length, {
                    message: "the file was added after the first load, and an ordinary reload must "
                        + "still find it — if this is empty the probe is being answered from the "
                        + "browser's cached 404 and the warning is useless to the operator it is "
                        + "for. cache: \"no-store\" on the HEAD is what makes it work; ?v= does not, "
                        + "because the build version is identical across these two loads.",
                    timeout: 15_000,
                }).toBeGreaterThan(0);
            });

            expectWellFormedWarning(warnings, relative);
        });
});
