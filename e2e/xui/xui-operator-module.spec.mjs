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
 * `AppConfiguration` names modules by string ID. One of them is the login helper:
 *
 *     moduleClass: "org/forgerock/commons/ui/common/main/SessionManager",
 *     configuration: { loginHelperClass: "org/forgerock/openam/ui/user/login/RESTLoginHelper" }
 *
 * The capability this spec defends is that the set of IDs the loader can reach is *open*: an
 * operator writes a module, drops it into the deployed webapp, names it in configuration, and the
 * XUI loads it and uses it. `fixtures/E2EStandInLoginHelper.js` is that module.
 *
 * === What D1 and D6 changed, and what this spec is now ===
 *
 * D1 replaced RequireJS's runtime path resolution with a registry built by `import.meta.glob` at
 * build time, plus a native dynamic import for IDs the build did not know about:
 *
 *     ModuleLoader.load(id) -> registry[id]?.() ?? import(fallbackUrl(id))
 *                              ^ known modules     ^ operator-added modules — this spec's path
 *
 * A build-time registry knows only what existed at build time, so an operator's file is by
 * definition on the second branch. That branch — `moduleRegistry.loadFromDeployedInstance`, fetching
 * `<XUI root>/<id>.js?v=<version>` — is the whole subject of this spec.
 *
 * D6 made the configuration compile-time. `/XUI/config/AppConfiguration.js` is not deployed at all
 * under a Vite build: it is a source module bundled into a content-hashed chunk, and the deployed
 * URL is a permanent 404. So the half of this spec that used to read, rewrite and restore that
 * deployed file has nothing left to act on and is gone, along with every assertion built on it. What
 * is left is the half that was always the point: place the operator's module, prove the application
 * loaded it over HTTP from the path its ID implies, and prove it used it.
 *
 * The module's *format* changed with the transport — the fixture is ESM under a native dynamic
 * import where it was AMD under RequireJS — and it no longer delegates to the shipped
 * `RESTLoginHelper`, because under D1 an operator's module has no channel to a shipped one: there is
 * no import map on the page, the only globals the XUI adds are `$`/`jQuery`, and `RESTLoginHelper`
 * has no chunk of its own in the emitted tree. The fixture re-implements the three members of the
 * contract against AM's REST API instead. That is a real cost — a bug in the fixture is now harder
 * to tell from a bug in the product — and it is why the end-to-end login and logout assertions below
 * matter more than they did, not less.
 *
 * === The precondition: the deployed tree must already have been built naming this module ===
 *
 * Under D6 nothing this spec can do at run time will make the deployed configuration name the
 * fixture; that string is compiled in. So the spec asserts the state it needs rather than creating
 * it, and **it fails loudly when the assertion does not hold — it never skips**. A skip nobody reads
 * is how a capability quietly stops being tested, and this spec exists precisely to say out loud
 * whether the capability survived. The cost is accepted and is stated here so it is not a surprise:
 * `npm run test:xui` against an arbitrary deployed instance goes red on this file, and the only
 * thing that turns it green is building the tree the spec needs. `preconditionMessage` below carries
 * that instruction, and it has to, or the noise is a puzzle instead of a step to take.
 *
 * The probe is the negative one, and it is exact: with the module *absent* from the deployed tree, a
 * tree that was built naming it will still ask for it — one request for the fallback URL, answered
 * 404 — and then fail to boot at all (see the second trap below). A tree built naming anything else
 * never asks for that URL and renders its login form as usual. So the two states are told apart by a
 * single observation, and it has to be made before the module is placed, which is why it lives in
 * the fixture ahead of everything else.
 *
 * === What this spec asserts, and the one mechanism assertion it makes on purpose ===
 *
 * Four behavioural assertions, each reading a marker the operator's own module writes: the module
 * ran on a plain anonymous page load, the module that ran is the one the configuration named, `login`
 * went through it and produced a real AM session, and `logout` went through it and ended that
 * session.
 *
 * On top of those it asserts one piece of mechanism: that the module arrived over HTTP, 200, at the
 * identifier's own path below the deployed tree root — `<XUI>/config/E2EStandInLoginHelper.js`, with
 * no content hash in it. The AMD-era version of this header declined to assert exactly that, on the
 * grounds that it was pure mechanism and "a registry that resolved the same ID better would fail
 * every one of them". Under D1 that reasoning inverts: **a registry resolving the same ID is the
 * failure mode**, not a better implementation of the same thing, and the HTTP fetch at the
 * unhashed path is the only externally visible difference between the fallback branch and a registry
 * hit. Without this assertion every other assertion in the file still passes on a build that
 * swallowed the fixture, and the spec silently stops testing the branch it is named after.
 *
 * === The absence guarantee, and what would silently break it ===
 *
 * The registry is built by three `import.meta.glob` calls rooted at product source:
 * `/src/main/js/**` and the `esm/**` trees of the `ui-commons` and `ui-user` packages. So the
 * guarantee that the fixture is *not* in the registry is one checkable statement:
 *
 *     the operator's module lives in `OpenAM/e2e/fixtures/`, and is copied only into the deployed
 *     `/XUI` in the container. It is never written into `openam-ui/openam-ui-ria/src/main/js/` or
 *     into either npm package.
 *
 * Each of the following leaves a green run that is no longer testing the fallback, and the HTTP
 * assertion above is the guard against all of them:
 *
 *   1. the fixture is copied into `src/main/js/config/` "to keep it with the config it names" — the
 *      glob picks it up and `resolveModule` returns from the table before it ever reaches the
 *      fallback;
 *   2. the same, with a `.jsm` or `.jsx` extension — the AM pattern deliberately includes all three;
 *   3. a build step, a setup script or a `vite.config.js` plugin copies `e2e/fixtures/` into the
 *      source root or into `target/compiled/` — the nastiest, because the module is then in the
 *      *deployed* tree without anyone having deployed it, so even "did we place it?" passes;
 *   4. the product grows a real module at `config/E2EStandInLoginHelper` — which is what the `E2E`
 *      prefix is for.
 *
 * === Two traps, both of which fail silently ===
 *
 *   - `SessionManager.login` calls `_.curry(helper.login)(params)`, and lodash reads the arity off
 *     `fn.length`. A stand-in whose `login` takes rest args — or a default value — has a shorter
 *     `length`, so `_.curry` invokes it immediately with only `params`, the callbacks are never
 *     passed, and the login form submit goes nowhere: no error, no page error, just a router that
 *     never leaves `#login`. Any build step that transpiles an operator's module to rest args breaks
 *     login invisibly. The fixture spells the three parameters out; the test that logs in end to end
 *     is what would catch it.
 *   - a `loginHelperClass` that does not resolve does not degrade login, it stops the application
 *     booting: `EVENT_APP_INITIALIZED` calls `SessionManager.getLoggedUser` before `Router.init()`,
 *     so a failed load means no login form at all. That is what the precondition probe above
 *     observes on purpose, and under D6 it is also the state a redeploy leaves behind — `xui-deploy.sh`
 *     replaces the tree rather than merging into it, so it removes the module while leaving the
 *     compiled configuration naming it. Hence the rule this fixture encodes: **re-place the module
 *     on every run, and never assume a previous run left it there.** Recovering from the dead state
 *     is no longer a one-file edit, because the configuration naming it is inside a hashed chunk.
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
    SEL,
    XUI_BASE,
    loginViaXui,
    logoutViaXui,
    openLoginForm,
    sessionInfo,
    xuiUrl,
} from "../common/xui-commons.mjs";
import {
    XUI_ROOT,
    deployedPathExists,
    placeDeployedFile,
    removeDeployedFile,
    waitForServed,
} from "../common/deployed-xui-commons.mjs";

/**
 * The module source, read from the fixture file rather than built from a string here.
 *
 * A file can be redeployed into a different tree; a heredoc in a spec cannot — which is what let the
 * same fixture follow the XUI from a Grunt/RequireJS tree to a Vite one. It also means the thing
 * under review is the thing that runs.
 */
const MODULE_FILE = fileURLToPath(new URL("../fixtures/E2EStandInLoginHelper.js", import.meta.url));
const MODULE_SOURCE = readFileSync(MODULE_FILE, "utf8");

/**
 * The module ID the fixture declares for itself, taken out of its source.
 *
 * Parsed rather than restated as a constant here, because three things are built from it — the path
 * the file is deployed to, the URL the loader is expected to fetch it from, and the value the marker
 * assertion expects — while the fixture has to state it once more, inside the marker it writes. Two
 * literals that must agree and live in different files drift silently: renaming one of them leaves a
 * spec that still deploys the module and still runs it, and then fails on an ID comparison whose
 * message names neither file.
 *
 * Under D6 the ID is load-bearing in a fourth place this spec cannot reach — the `loginHelperClass`
 * string compiled into the deployed bundle. That one is checked, not written, by the precondition.
 */
function readModuleId (source) {
    const declared = /\bmoduleId:\s*"([^"]+)"/.exec(source);
    expect(declared,
        `${MODULE_FILE} must declare its own ID as \`moduleId: "<id>"\` — this spec derives the `
        + "deployed path, the fallback URL and the marker assertion from it")
        .not.toBeNull();
    return declared[1];
}

/**
 * Where the operator's module goes, and the URL the ID resolves to.
 *
 * `moduleRegistry.fallbackUrl` is `new URL(toUrl(id + ".js"), document.baseURI)`, and `document.baseURI`
 * is the deployed tree root, so the ID is the path under `/XUI` minus `.js` — the same relationship
 * RequireJS's `baseUrl` gave it before D1. Any path under the webapp would work; `config/` is where
 * the operator-editable files historically lived.
 *
 * It has to be an ID the build did not know about, or `resolveModule` answers from the registry and
 * never reaches the fallback. See the absence guarantee in the header.
 */
const MODULE_ID = readModuleId(MODULE_SOURCE);
const MODULE_PATH = `${XUI_ROOT}/${MODULE_ID}.js`;
const MODULE_URL = `${XUI_BASE}/${MODULE_ID}.js`;

/**
 * Every directory the ID implies below the deployed tree root, deepest first.
 *
 * `placeDeployedFile` creates the directories above the file with `mkdir -p`, and under D6 the
 * built tree has no `config/` at all — it is not one of the 15 top-level entries Vite emits — so
 * the fixture creates that directory and it is the fixture's to take away again. Without these the
 * teardown would leave an empty `config/` behind and the "one artefact" claim below would be false.
 *
 * Deepest first because `removeDeployedFile` hands them straight to `rmdir`, which removes an empty
 * directory and refuses a populated one. That refusal is what makes this safe against a tree where
 * `config/` is *not* the fixture's — a Grunt/RequireJS tree ships it full of product files, and
 * there this list takes nothing away. Same mechanics, and the same reasoning, as
 * xui-theming.spec.mjs's `OVERRIDE_DIRS`.
 */
const MODULE_DIRS = MODULE_ID.split("/").slice(0, -1)
    .map((_, index, segments) =>
        `${XUI_ROOT}/${segments.slice(0, segments.length - index).join("/")}`);

/** The path component of the fallback URL — see recordModuleFetches for why this is the assertion. */
const MODULE_URL_PATH = new URL(MODULE_URL).pathname;

/** The property the fixture module writes on the page it is loaded into. */
const MARKER = "__e2eLoginHelper";

/**
 * What to tell whoever ran this against a tree that was not built for the fixture.
 *
 * This is the whole cost of the decision recorded in the header — the precondition fails rather than
 * skipping — so it has to be an instruction, not a diagnosis. Under D6 there is no deployed
 * `AppConfiguration.js` to edit: the string is compiled into a content-hashed chunk, so the only way
 * to satisfy this is to build a tree that names the fixture and deploy it. Paths are relative to the
 * repository root.
 *
 * The instruction is a build-time override — `LOGIN_HELPER_CLASS`, read by
 * `openam-ui/openam-ui-ria/vite.config.js` and substituted into `AppConfiguration`'s
 * `loginHelperClass` — rather than an edit to tracked product source. That matters for what the
 * message does *not* have to say: there is no "and put that line back afterwards" step, so a reader
 * who follows this and is then interrupted cannot leave a dirty working tree behind, and cannot
 * commit a product file naming a test fixture. Unset, the variable changes nothing: the build emits
 * the shipped `org/forgerock/openam/ui/user/login/RESTLoginHelper` exactly as it ships.
 *
 * It also names the one state the steps do *not* fix. The poll can end on `still-booting`, which
 * says neither of the two states was observed rather than saying which one was.
 */
function preconditionMessage () {
    return `the deployed /XUI was not built naming "${MODULE_ID}" as its loginHelperClass, so this `
        + "spec cannot exercise the operator-module fallback and must not pretend to. D6 compiles "
        + "AppConfiguration into a content-hashed bundle chunk, so there is no deployed "
        + "config/AppConfiguration.js for this spec to edit — the tree has to be built that way.\n"
        + "If Received above is \"still-booting\", neither state was observed — the login form never "
        + "rendered and the module URL was never requested — so this is not yet a statement about "
        + "how the tree was built: the instance may be down, slow, or broken for an unrelated "
        + "reason. Check it is up and serving /XUI/ before following the steps.\n"
        + "To fix, from the repository root:\n"
        + `    1. cd openam-ui/openam-ui-ria && LOGIN_HELPER_CLASS="${MODULE_ID}" `
        + "npm run build:production\n"
        + "    2. e2e/local/xui-deploy.sh openam-ui/openam-ui-ria/target/compiled\n"
        + "LOGIN_HELPER_CLASS is a build-time override read by vite.config.js; unset, the build "
        + "emits the shipped org/forgerock/openam/ui/user/login/RESTLoginHelper unchanged. So "
        + "nothing tracked is edited here and there is nothing to restore afterwards. The redeploy "
        + `in step 2 replaces the whole tree, so it also removes ${MODULE_PATH}; this spec places it `
        + "again on every run and never assumes a previous run left it there.";
}

/**
 * Record every response served at the fallback URL's own path, for the life of a page.
 *
 * Filtered on the *path* rather than the full URL because the loader appends `?v=<version>`, and
 * matched exactly rather than by substring because the exact match is the assertion: a registry hit
 * is served from `assets/<name>-<contenthash>.js` and can never produce this path, while the
 * fallback branch can produce nothing else. That is the whole of the distinguishing shape, so this
 * predicate is doing the work the header claims for it and must not be loosened to a `startsWith`
 * over the tree root.
 *
 * Installed on a page before it navigates; `response` fires on headers, so anything the module could
 * have executed from has already been recorded by the time the marker is observable.
 */
function recordModuleFetches (page) {
    const fetches = [];
    page.on("response", (response) => {
        if (new URL(response.url()).pathname === MODULE_URL_PATH) {
            fetches.push({ url: response.url(), status: response.status() });
        }
    });
    return () => fetches.slice();
}

/**
 * Fail unless the deployed tree's compiled configuration names the fixture's module ID.
 *
 * Run with the module absent, and that is not incidental: absence is what makes the observation
 * unambiguous. A tree built for the fixture asks for the fallback URL and is answered 404, and then
 * does not boot; a tree built for anything else never asks and renders its login form. The poll
 * therefore reports which of the two it saw rather than just timing out, so the failure says whether
 * the application booted without the module or never got far enough to ask for it.
 *
 * On its own browser context, never the test's `page`: this load is expected to 404 on the module,
 * and the deployed tree serves `Cache-Control: public, max-age=2592000`, so keeping the miss out of
 * the context the test then uses costs one context and removes a whole class of question.
 *
 * `ignoreHTTPSErrors` is restated here and is not decoration. A context created straight off the
 * `browser` does not inherit the config's `use` block, and playwright.config.mjs sets that option
 * deliberately for self-signed https instances (`OPENAM_BASE_URL`). Without it `probe.goto` rejects
 * on a raw TLS error, this function dies before the poll is ever reached, and `preconditionMessage`
 * — the one thing the fail-loudly decision in the header depends on — is never printed.
 *
 * Everything after the context exists is inside the `try`, so a throw from `newPage()` closes the
 * context rather than leaking it until the browser does.
 */
async function expectTreeBuiltForModule (browser) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });

    try {
        const probe = await context.newPage();
        const fetches = recordModuleFetches(probe);

        await probe.goto(xuiUrl("#login/"));
        await expect.poll(async () => {
            if (fetches().length > 0) {
                return "asked-for-the-module";
            }
            return await probe.locator(SEL.usernameInput).isVisible()
                ? "booted-without-the-module"
                : "still-booting";
        }, { message: preconditionMessage(), timeout: 20_000 })
            .toBe("asked-for-the-module");
    } finally {
        await context.close();
    }
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
            + `and that the deployed tree was built naming ${MODULE_ID}.`,
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
     * The operator's module in the deployed `/XUI`, on a tree that was already built to name it, and
     * a teardown that takes the module back out again.
     *
     * Under D6 this fixture owns exactly one artefact: the deployed module file, together with the
     * directory its ID implies, which the built tree does not contain and `placeDeployedFile`
     * therefore creates (`MODULE_DIRS`). The configuration
     * half of it is gone — there is no deployed `AppConfiguration.js` to rewrite and restore — and
     * with it the ordering rule that used to be the load-bearing part of this fixture in both
     * directions. That is the practical win of asserting the build rather than performing it: this
     * spec can no longer leave an instance whose configuration names a module that is not there,
     * which under D6 is an unbootable console with no single-file fix.
     *
     * What is left is checked in order anyway, and the order still matters for one reason: the
     * precondition probe reads the deployed tree's behaviour *with the module absent*, so it has to
     * run before anything is placed.
     *
     *   1. the module is not already there — a previous run cleaned up
     *   2. the deployed tree was built naming it — fails loudly, never skips
     *   3. place the module, and confirm it on the wire before the browser is pointed at it
     *   teardown: remove it and the directory it needed, and confirm the 404
     *
     * Teardown runs on the failure path too, and the removal is the first thing in the `finally` so
     * it happens whether or not the confirmations after it do. `removeDeployedFile` is callable when
     * nothing was placed, so a failure inside setup is covered by the same block.
     *
     * Test-scoped, not worker-scoped: a worker fixture is torn down when the worker exits rather
     * than when this file finishes, which would hold the mutation across every later spec in the run.
     */
    standInHelper: async ({ browser, page, request }, use) => {
        // First, and before the precondition probe, because the probe's whole meaning depends on the
        // module being absent. A stray file here is inert — nothing in a pristine deployed tree names
        // it — so unlike the AMD-era version of this spec the remediation is simply to delete it.
        expect(deployedPathExists(MODULE_PATH),
            `${MODULE_PATH} is already in the deployed /XUI — a previous run did not clean up, or a `
            + "build/deploy step is copying e2e/fixtures/ into the tree, which would defeat the "
            + "absence guarantee in the header (breaker 3) by putting the module in the deployed "
            + "tree without anyone having deployed it. Establish which before deleting it: if no "
            + "previous run can account for it, the build is the thing to fix, not this file. "
            + "Otherwise delete it (`docker exec openam-idp rm -f <path>`) and run again. A stray "
            + "copy is inert where it is: nothing names it unless the deployed tree was built to, "
            + "and this spec places its own copy on every run rather than trusting one it finds.")
            .toBe(false);

        await expectTreeBuiltForModule(browser);

        // Watch the test's own page for the fallback fetch, before anything navigates it.
        const moduleFetches = recordModuleFetches(page);

        try {
            placeDeployedFile(MODULE_PATH, MODULE_SOURCE);
            await waitForServed(request, MODULE_URL,
                (status, body) => status === 200 && body.includes(MARKER),
                "before the browser is pointed at a tree that names it");

            await use({ moduleId: MODULE_ID, moduleFetches });
        } finally {
            removeDeployedFile(MODULE_PATH, MODULE_DIRS);
            await waitForServed(request, MODULE_URL, (status) => status === 404,
                "no longer, once the fixture has removed it");
            expect(deployedPathExists(MODULE_PATH),
                `${MODULE_PATH} must not be left in the deployed /XUI`).toBe(false);
        }
    },
});

test.describe("XUI operator-supplied module (AppConfiguration.loginHelperClass)",
    { tag: ["@deployed-am"] }, () => {
        test("a module added to the deployed /XUI and named in the built configuration is loaded and used",
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

                // And it arrived over HTTP, on the fallback branch rather than out of the registry.
                // The recorder matches the identifier's own path exactly, so a 200 here cannot have
                // come from a hashed asset chunk — see the header. Without this the whole file still
                // passes on a build that swallowed the fixture into its module registry, which is the
                // one way this spec can go green while testing nothing it claims to.
                await expect.poll(() => standInHelper.moduleFetches().map((fetched) => fetched.status), {
                    message: `${MODULE_URL_PATH} must have been fetched, and answered 200: that URL — `
                        + "the identifier's own path below the deployed tree root, with no content "
                        + "hash — is the only externally visible difference between the deployed-"
                        + "instance fallback this spec exists to defend and the build-time registry "
                        + `resolving ${MODULE_ID} itself. No fetch at all means the module was in the `
                        + "registry, so it was in the build, so it is not an operator-supplied module.",
                    timeout: 10_000,
                }).toContain(200);
            });

        test("login and logout still complete end to end through the operator's module",
            async ({ page, standInHelper }) => {
                // `standInHelper` is taken for its side effects on the deployed tree, not its
                // value: naming it in the signature is what asserts the tree was built for the
                // module and places it for the length of this test.
                await loginViaXui(page, USERNAME, PASSWORD);

                // The module is on the path a real login takes, not merely loaded beside it.
                await expectCalled(page, "login");

                // And the login it performed produced a real session. Asserted from the server
                // rather than from the DOM: the page having left #login says the router moved, while
                // this says AM issued a session for the right user — the thing an operator supplying
                // a login helper would actually be breaking. Through page.request, so it carries the
                // browser's cookies rather than a fresh jar.
                const session = await sessionInfo(page.request);
                expect(session,
                    "the login performed through the operator's module must produce a session")
                    .not.toBeNull();
                expect(String(session.id).toLowerCase()).toBe(USERNAME.toLowerCase());

                // Logout is the third member of the contract, and the only one this spec can reach
                // that SessionManager calls on a route change rather than on a form submit.
                await logoutViaXui(page);
                await expectCalled(page, "logout");
                expect(await sessionInfo(page.request), "logout must end the session").toBeNull();
            });
    });
