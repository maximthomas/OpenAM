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
 * OpenAM XUI — a module an operator added to the deployed `/XUI`, named by `AppConfiguration`.
 *
 * `config/AppConfiguration.js` names modules by string ID. One of them is the login helper:
 *
 *     moduleClass: "org/forgerock/commons/ui/common/main/SessionManager",
 *     configuration: { loginHelperClass: "org/forgerock/openam/ui/user/login/RESTLoginHelper" }
 *
 * Both files are operator-editable in a deployed instance, so the set of module IDs the loader has
 * to be able to reach is open: an operator can write a module, drop it into the deployed webapp and
 * name it there, and the XUI will load it. This spec exercises exactly that, with the stand-in in
 * `fixtures/E2EStandInLoginHelper.js`.
 *
 * === This is D1's fallback-path baseline ===
 *
 * D1 replaces RequireJS's runtime path resolution with a registry built by `import.meta.glob` at
 * build time, plus a native dynamic import for IDs the build did not know about:
 *
 *     ModuleLoader.load(id) -> registry[id]?.() ?? import(urlFor(id))
 *                              ^ known modules     ^ operator-added modules — this spec's path
 *
 * A build-time registry knows only what existed at build time, so an operator's file is by
 * definition on the second branch, and this spec is what will say whether that branch works. Task
 * 6.6 runs it against the new loader for precisely that reason. It is a baseline, not a
 * compatibility promise: the module's *format* is expected to change (AMD here, ESM under a native
 * dynamic import), and D6 separately removes in-place editing of `AppConfiguration.js`. What has to
 * survive is the capability — a module an operator supplies, named in configuration, gets loaded and
 * used. If D1 lands with no answer for how the operator gets their module to a deployed instance,
 * then the capability was removed rather than migrated, and this spec is the thing that says so.
 *
 * What this spec asserts is therefore deliberately transport-blind: it reads a marker the operator's
 * own module writes. It does *not* assert that the module arrived over HTTP from a path under the
 * webapp, that its request returned 200, or that the shipped RESTLoginHelper.js was not fetched —
 * all true today, all pure mechanism, and a registry that resolved the same ID better would fail
 * every one of them. NOTES-operator-module.md records them as measurements instead.
 *
 * === Two traps, both of which fail silently ===
 *
 *   - `SessionManager.login` calls `_.curry(helper.login)(params)`, and lodash reads the arity off
 *     `fn.length`. A stand-in whose `login` takes rest args has `length` 0, so `_.curry` invokes it
 *     immediately with only `params`, the callbacks are never passed, and the login form submit goes
 *     nowhere — no error, no page error, just a router that never leaves `#login`. Any build step
 *     that transpiles an operator's module to rest args breaks login invisibly. The fixture spells
 *     the three parameters out; the test that logs in end to end is what would catch it.
 *   - a `loginHelperClass` that does not resolve does not degrade login, it stops the application
 *     booting: `EVENT_APP_INITIALIZED` calls `SessionManager.getLoggedUser` before `Router.init()`,
 *     so a failed load means no login form at all. That is why the fixture's ordering below is
 *     load-bearing rather than tidy, and it is the shape the D1 regression would take.
 *
 * Deployed AM only. The whole premise is a file in a real deployed webapp, so there is nothing here
 * the local API server of D13-D16 could serve — it is the deployed-AM-only case of D16 by
 * construction, not by omission.
 */

import { test as base, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { PASSWORD, USERNAME } from "../common/openam-commons.mjs";
import {
    XUI_BASE,
    loginViaXui,
    logoutViaXui,
    openLoginForm,
    sessionInfo,
} from "../common/xui-commons.mjs";
import {
    XUI_ROOT,
    deployedPathExists,
    deployedSha256,
    placeDeployedFile,
    readDeployedFile,
    removeDeployedFile,
    sha256,
    waitForServed,
    writeDeployedFile,
} from "../common/deployed-xui-commons.mjs";

const APP_CONFIG_PATH = process.env.OPENAM_APP_CONFIG ?? `${XUI_ROOT}/config/AppConfiguration.js`;
const APP_CONFIG_URL = `${XUI_BASE}/config/AppConfiguration.js`;

/** The ID `AppConfiguration` ships with, and the one member of it this spec redirects. */
const SHIPPED_HELPER = "org/forgerock/openam/ui/user/login/RESTLoginHelper";

/**
 * The module source, read from the fixture file rather than built from a string here.
 *
 * Phase 2 has to point the same module at a Vite-built XUI (task 6.6), and a file can be redeployed
 * into a different tree; a heredoc in a spec cannot. It also means the thing under review is the
 * thing that runs.
 */
const MODULE_FILE = fileURLToPath(new URL("../fixtures/E2EStandInLoginHelper.js", import.meta.url));
const MODULE_SOURCE = readFileSync(MODULE_FILE, "utf8");

/**
 * The module ID the fixture declares for itself, taken out of its source.
 *
 * Parsed rather than restated as a constant here, because three things are built from it — the path
 * the file is deployed to, the string written into the deployed config, and the value the marker
 * assertion expects — while the fixture has to state it once more, inside the marker it writes. Two
 * literals that must agree and live in different files drift silently: renaming one of them leaves
 * a spec that still deploys the module, still configures it and still runs it, and then fails on an
 * ID comparison whose message names neither file.
 *
 * Not read from the loader — RequireJS's `define(["module"], …)` would give the module its own ID —
 * because the fixture is a real file precisely so phase 2 can redeploy it against a Vite-built
 * tree, and a loader-specific dependency inside it would take that away.
 */
function readModuleId (source) {
    const declared = /\bmoduleId:\s*"([^"]+)"/.exec(source);
    expect(declared,
        `${MODULE_FILE} must declare its own ID as \`moduleId: "<id>"\` — this spec derives the `
        + "deployed path, the configured loginHelperClass and the marker assertion from it")
        .not.toBeNull();
    return declared[1];
}

/**
 * Where the operator's module goes, and the ID that resolves to it.
 *
 * The ID is the path under the webapp root minus `.js`, because `index.html` boots RequireJS with
 * no `baseUrl` and no `data-main`, so the base is the directory `index.html` is in. Any path under
 * the webapp would work; `config/` is where the other operator-editable files already live.
 *
 * It has to be a *new* ID. `main.js` is an r.js bundle that already contains
 * `define("org/forgerock/openam/ui/user/login/RESTLoginHelper", …)`, and RequireJS never fetches a
 * module that is already defined — the standalone `RESTLoginHelper.js` in the deployed tree is
 * never requested at all. Overwriting a shipped module's file in place would therefore do nothing,
 * and a spec written that way would pass without testing anything.
 */
const MODULE_ID = readModuleId(MODULE_SOURCE);
const MODULE_PATH = `${XUI_ROOT}/${MODULE_ID}.js`;
const MODULE_URL = `${XUI_BASE}/${MODULE_ID}.js`;

/** The property the fixture module writes on the page it is loaded into. */
const MARKER = "__e2eLoginHelper";

/**
 * Point `loginHelperClass` at the operator's module, leaving the rest of the file byte for byte.
 *
 * A replacement rather than an insertion, since there is one string to change, and the count is
 * asserted: the deployed config names the shipped helper exactly once today, and a spec that
 * silently replaced two occurrences — or none — would be configuring something other than what it
 * claims. If the product ever names the helper twice, this fails and says so rather than guessing.
 */
function withStandInHelper (source) {
    const occurrences = source.split(`"${SHIPPED_HELPER}"`).length - 1;
    expect(occurrences,
        `the deployed AppConfiguration must name ${SHIPPED_HELPER} exactly once, and names it `
        + `${occurrences} times. A count of 0 is far more likely to be this spec's own mutation `
        + `left behind by a run that died before its teardown than a change in what the product `
        + `ships: check whether ${APP_CONFIG_PATH} already names ${MODULE_ID}, and if it does, `
        + `restore it to name ${SHIPPED_HELPER} — before removing ${MODULE_PATH}, never after.`)
        .toBe(1);
    return source.replace(`"${SHIPPED_HELPER}"`, `"${MODULE_ID}"`);
}

/** The marker the operator's module wrote on this page, or null if it never ran. */
function readMarker (page) {
    return page.evaluate((name) => window[name] ?? null, MARKER);
}

/**
 * Fail, loudly and by name, if the operator's module never ran on this page.
 *
 * Checked separately from the call assertions because of how it would otherwise fail. A fixture that
 * silently failed to apply leaves a perfectly working login page, and every behavioural assertion in
 * this file still passes against the shipped helper — the spec would quietly degrade into "login
 * works", which proves nothing about operator modules at all. The same trap NOTES-theming.md records
 * for a route handler that was never invoked.
 */
async function expectModuleRan (page) {
    await expect.poll(() => readMarker(page), {
        message: `window.${MARKER} is absent — the module named by loginHelperClass never ran, so `
            + `this spec would be asserting nothing. Check that the fixture placed ${MODULE_PATH} `
            + `and that the deployed AppConfiguration names ${MODULE_ID}.`,
        timeout: 30_000,
    }).not.toBeNull();
}

/**
 * The operator's module recorded a call to one of the three members of the contract.
 *
 * Polled rather than read once: `calls.push` happens when SessionManager invokes the member, which
 * for `login` is before the outcome is known and for `logout` is during a route change, so a bare
 * read would couple the assertion to an ordering that is not contractual.
 *
 * `toContain` and never an equality against the whole array: `getLoggedUser` fires at
 * EVENT_APP_INITIALIZED and again from RESTLoginView, and how many times is not part of any
 * contract.
 *
 * The marker is per-document, so `calls` accumulating across a login and the logout after it is a
 * property of *this flow*, not of the contract: the post-login landing and `#logout/` are both hash
 * changes on the document the form was submitted on. Should routing ever perform a real navigation
 * between them, the module re-runs with an empty `calls` and this reports the member as never
 * called — which reads as the operator-module capability having regressed when the cause is a
 * routing change. Recorded rather than asserted: pinning it would assert the router's mechanics.
 *
 * The generator tolerates a missing marker instead of reading `.calls` straight off it, because
 * `expect.poll` evaluates it *outside* the try/catch that decides whether to keep polling
 * (playwright/lib/matchers/expect.js) — a throw there propagates immediately and the message above
 * is never printed. A navigation landing between `expectModuleRan` and this poll is enough to reach
 * a document the module has not written to yet.
 */
async function expectCalled (page, member) {
    await expectModuleRan(page);
    await expect.poll(async () => (await readMarker(page))?.calls ?? [], {
        message: `the operator module must be the one ${member}() was called on`,
        timeout: 30_000,
    }).toContain(member);
}

const test = base.extend({
    /**
     * The operator's module in the deployed `/XUI`, named by the deployed `AppConfiguration`, and a
     * teardown that takes both back out.
     *
     * The order is the load-bearing part, in both directions, and it is encoded here rather than
     * left to a comment because the failure mode is not a failed test but an instance whose console
     * nobody can log in to:
     *
     *   setup     module in, and *confirmed served*, before the config names it
     *   teardown  config restored, and *confirmed served*, before the module is removed
     *
     * Either window in the wrong order leaves `loginHelperClass` naming an ID that does not resolve,
     * and `ModuleLoader.load` failing there stops the app booting — no login form, for as long as
     * the window lasts. Tomcat's static-resource cache is what makes those windows seconds wide
     * rather than instantaneous, so each step polls the *served* bytes rather than trusting the
     * write; see waitForServed.
     *
     * The teardown is asymmetric on purpose. The config restore runs unconditionally, but the module
     * is removed only once the pristine config is confirmed on the wire, because those two failures
     * are not equally bad: a leaked module file that nothing names is inert, while a config naming a
     * module that is no longer there is the dead-application state above. If the restore cannot be
     * confirmed, this leaves both halves in place — an instance that still logs in — and fails.
     *
     * Test-scoped, not worker-scoped: a worker fixture is torn down when the worker exits rather
     * than when this file finishes, which would hold the mutation across every later spec in the run.
     */
    standInHelper: async ({ request }, use) => {
        // First, before the config is even read. A run can die with no teardown at all — the docker
        // calls here are synchronous, so a hung `docker exec` blocks the worker's event loop, the
        // timer-based test timeout never fires and the parent kills the worker outright — and the
        // likelier moment for that is *after* the config flip, since that is where the whole test
        // body runs. That leaves the module present and the config already mutated, and
        // `withStandInHelper` then throws on a count of 0 before this ever runs. This message has
        // to be the one a human reaches, because the obvious remediation for a stray fixture file
        // is the one that takes the console down rather than bringing it back.
        expect(deployedPathExists(MODULE_PATH),
            `${MODULE_PATH} is already in the deployed /XUI — a previous run did not clean up. `
            + `Undo it in this order: first put "${SHIPPED_HELPER}" back as the loginHelperClass in `
            + `${APP_CONFIG_PATH} and confirm ${APP_CONFIG_URL} serves it, and only then delete the `
            + "module. The other way round leaves loginHelperClass naming an ID that no longer "
            + "resolves, and SessionManager is asked for it before the router starts — so the XUI "
            + "does not boot at all, no login form renders, and nobody can reach the console.")
            .toBe(false);

        const pristine = readDeployedFile(APP_CONFIG_PATH);
        const pristineSha = sha256(pristine);
        const mutated = withStandInHelper(pristine);

        try {
            // 1. The module first, and served, before anything names it.
            placeDeployedFile(MODULE_PATH, MODULE_SOURCE);
            await waitForServed(request, MODULE_URL,
                (status, body) => status === 200 && body.includes(MARKER),
                "before AppConfiguration may name it");

            // 2. Only now point the configuration at it.
            writeDeployedFile(APP_CONFIG_PATH, mutated);
            expect(deployedSha256(APP_CONFIG_PATH), "the edit must have reached the container")
                .toBe(sha256(mutated));
            await waitForServed(request, APP_CONFIG_URL,
                (status, body) => status === 200 && body.includes(`"${MODULE_ID}"`),
                `naming ${MODULE_ID} as the login helper`);

            await use({ moduleId: MODULE_ID });
        } finally {
            // 3. The configuration back first, so nothing names the module by the time it goes.
            writeDeployedFile(APP_CONFIG_PATH, pristine);
            expect(deployedSha256(APP_CONFIG_PATH),
                "the deployed AppConfiguration must be back to its original bytes")
                .toBe(pristineSha);
            await waitForServed(request, APP_CONFIG_URL,
                (status, body) => status === 200 && body.includes(`"${SHIPPED_HELPER}"`),
                "naming the shipped login helper again");

            // 4. And only then the module, now that the restore is confirmed on the wire.
            removeDeployedFile(MODULE_PATH);
            await waitForServed(request, MODULE_URL, (status) => status === 404,
                "no longer, once the fixture has removed it");
            expect(deployedPathExists(MODULE_PATH),
                `${MODULE_PATH} must not be left in the deployed /XUI`).toBe(false);
        }
    },
});

test.describe("XUI operator-supplied module (AppConfiguration.loginHelperClass)",
    { tag: ["@deployed-am"] }, () => {
        test("a module added to the deployed /XUI and named in AppConfiguration is loaded and used",
            async ({ page, standInHelper }) => {
                await openLoginForm(page);

                // Before any credential is entered. SessionManager resolves loginHelperClass at
                // EVENT_APP_INITIALIZED to ask whether there is already a session, so the operator's
                // module is loaded and called on a plain anonymous page load — which is what makes
                // this assertion about module *loading* rather than about authentication.
                await expectCalled(page, "getLoggedUser");

                const marker = await readMarker(page);
                expect(marker.moduleId, "the module that ran must be the one the config named")
                    .toBe(standInHelper.moduleId);
                // Not proof that the shipped helper resolved — `delegatesTo` is an unconditional
                // literal in the marker object, and the module having run at all is what shows the
                // resolution, since it is a `define` dependency. What this catches is this file's
                // SHIPPED_HELPER and the fixture's own literal drifting apart, which would leave
                // the stand-in delegating to one module while the config is restored to name
                // another — and the delegation is what keeps login working.
                expect(marker.delegatesTo,
                    "the fixture must delegate to the same helper the deployed config is restored "
                    + "to name")
                    .toBe(SHIPPED_HELPER);
            });

        test("login and logout still complete end to end through the operator's module",
            async ({ page, standInHelper }) => {
                // `standInHelper` is taken for its side effects on the deployed tree, not its
                // value: naming it in the signature is what places the module and points the
                // deployed AppConfiguration at it for the length of this test.
                await loginViaXui(page, USERNAME, PASSWORD);

                // The module is on the path a real login takes, not merely loaded beside it.
                await expectCalled(page, "login");

                // And the login it forwarded produced a real session. Asserted from the server
                // rather than from the DOM: the page having left #login says the router moved, while
                // this says AM issued a session for the right user — the thing an operator supplying
                // a login helper would actually be breaking if the delegation were wrong. Through
                // page.request, so it carries the browser's cookies rather than a fresh jar.
                const session = await sessionInfo(page.request);
                expect(session,
                    "the login forwarded through the operator's module must produce a session")
                    .not.toBeNull();
                expect(String(session.id).toLowerCase()).toBe(USERNAME.toLowerCase());

                // Logout is the third member of the contract, and the only one this spec can reach
                // that SessionManager calls on a route change rather than on a form submit.
                await logoutViaXui(page);
                await expectCalled(page, "logout");
                expect(await sessionInfo(page.request), "logout must end the session").toBeNull();
            });
    });
