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
 * OpenAM XUI — authentication chain administration: creating a chain, assembling it out of module
 * links, reordering those links by dragging them, setting a link's criteria, and the three separate
 * routes to deleting a chain.
 *
 * The fourth admin spec, and the only one in the suite that drives a drag.
 *
 * What this is guarding, beyond "chain CRUD works":
 *
 *   - `sortable`. This is the reason task 1.15 exists and the reason the reorder test below is not
 *     optional. `libs/jquery-sortable-0.9.13` is mapped at main.js:75 and shimmed at main.js:163
 *     (`deps: ["jquery"]`), and it has exactly two reachable consumers in the whole tree:
 *     admin/views/realms/authentication/chains/EditChainView.js, which this spec drives, and
 *     admin/views/realms/authorization/policies/conditions/ManageRulesView.js, which no spec covers
 *     and none is planned to. So when task 3.1 maps that library to an npm package and task 5.3
 *     decides whether it still needs a shim at all, this file is the only thing in the suite that
 *     will say whether it survived. A chain spec that created, edited and deleted chains but did not
 *     drag anything would leave the shim exactly as unobserved as it is today — it would be a spec
 *     for something else, and the library would be migrated blind;
 *   - a widget driven by raw mouse events rather than by the DOM. Everything else in this suite acts
 *     through click(), fill() and selectOption(); the reorder is the one place where the app's
 *     behaviour depends on the *timing* of the events it receives, which is exactly the kind of thing
 *     a build migration can break without breaking a single request. See dragLink below;
 *   - two selectize controls in one dialog that must be addressed differently (task 5.3 again —
 *     selectize is a shimmed non-AMD library). EditLinkView builds both selects with SelectComponent,
 *     but gives the module one a custom optionComponent whose renderer replaces selectize's own option
 *     element wholesale, so `.option` and `.item` are never applied to it while the criteria select
 *     keeps them. Both are exercised here;
 *   - view modules resolved by string identifier and loaded on demand (D1). ChainsView, AddChainView,
 *     EditChainView, EditLinkView and LinkView are loaded by no other spec.
 *
 * The whole spec is inert. Every chain and every module instance it creates lives in a scratch
 * sub-realm that is deleted in teardown, and nothing here reads, writes or repoints any realm's
 * `core.orgConfig` or `core.adminAuthModule` — the two settings that name the chains AM actually
 * authenticates a realm's users and administrators against. The console's admin session authenticates
 * against the root realm (idFromSession answers "/" for amadmin), so a sub-realm's authentication
 * configuration cannot lock the console out; that is what makes a scratch sub-realm a safe place to
 * assemble chains. The one test that looks at those settings only reads them — see the guard test.
 *
 * Two things about this console that a reader will otherwise assume wrongly, both load-bearing:
 *
 *   - **a chain edited in the console is entirely in-memory until [data-save-chain]**. Adding a link,
 *     dragging one, changing a link's criteria and removing a link all mutate
 *     `data.form.chainData.authChainConfiguration` and nothing else; saving PUTs that one array. So
 *     every assertion about persistence here has three parts — the DOM changed, AM had *not* changed
 *     before the save, and AM matches afterwards — and the middle one is what distinguishes a widget
 *     that moved something from a widget that also wrote it;
 *   - **the console's guard on a realm's default chains never fires on this build**, so nothing here
 *     may rely on it. AuthenticationService.chains.all flags a chain whose `_id` matches the realm's
 *     `adminAuthModule` or `orgConfig`, and ChainsTemplate uses that flag to add `default-config-row`
 *     and disable the row's checkbox and delete button — but AM returns those two keys nested under
 *     `core`, and the service reads them at the top level, so the comparison is against undefined and
 *     no chain is ever flagged. The consequence that matters: `[data-select-all]` skips only
 *     `:disabled` checkboxes, none are disabled, and so it selects the realm's default authentication
 *     chain along with everything else. **This spec never clicks it**, and the last test pins the
 *     defect so that fixing it is visible here rather than silent.
 *
 * The chain's three links are two `securid` instances either side of one `httpbasic` — 1.14's two
 * inert types, so the link's type line differs down the chain and a drag can be seen to carry a link's
 * type with it as well as its name. Three links and not two: with two, "moved to the end" and "swapped
 * with its neighbour" are the same observation, and a widget that could only ever swap adjacent items
 * would pass. Each link is seeded with a different criteria for the same reason — criteria are stored
 * per link rather than per position, and a reorder that carried the names but left the criteria behind
 * would otherwise look correct.
 *
 * Idempotency is structural, as in the sibling specs: every test gets its own realm, created over REST
 * and registered for teardown before it exists, and a realm deletes cleanly with chains and modules
 * still configured in it. That is what makes the fixed chain and module names below safe. It matters
 * slightly more here than for modules — a leftover chain collides on its name, which the console
 * reports by disabling the create button rather than by failing anything, so a name collision would
 * surface as an unexplained actionability timeout in the create test.
 */

import { test, expect } from "@playwright/test";
import { getAdminToken } from "../common/openam-commons.mjs";
import { captureMessages, localeBundle, openAdminConsole, xuiUrl } from "../common/xui-commons.mjs";
import {
    TOP_LEVEL_REALM,
    createRealm,
    realmHash,
    realmPathOf,
    removeRealm,
    uniqueRealmName,
} from "../common/realms-commons.mjs";
import {
    createChain,
    createModule,
    listModules,
    readChain,
    realmAuthenticationConfig,
    updateChain,
} from "../common/auth-commons.mjs";

/** The chain under test. Fixed, and safe because every test has a realm of its own. */
const CHAIN = "e2eChain";

/**
 * A chain every realm is seeded with, used as the "the list rendered" anchor and as the duplicate name
 * the create test is refused.
 *
 * The same reasoning as DataStore in the module spec: ChainsView renders its container before filling
 * it from a separate template fetch, so "the row I am looking for is absent" is equally true of a list
 * that never rendered. `ldapService` is also the chain a new realm names as both its `orgConfig` and
 * its `adminAuthModule`, which is what gives the guard test something to be about. It is never
 * deleted, edited or selected here.
 */
const STOCK_CHAIN = "ldapService";

/**
 * The chain's links, in the order they are seeded, with a distinct criteria each.
 *
 * The module types are 1.14's two inert types. Nothing outside the scratch realm references these
 * instances and the realm is deleted afterwards, so no chain that authenticates anything is affected.
 */
const LINKS = [
    { module: "e2eChainModA", type: "securid", criteria: "REQUIRED" },
    { module: "e2eChainModB", type: "httpbasic", criteria: "OPTIONAL" },
    { module: "e2eChainModC", type: "securid", criteria: "REQUISITE" },
];

/** What AM stores for a link: the console sends `options` too, and always has. */
function seedLinks () {
    return LINKS.map(({ module, criteria }) => ({ module, criteria, options: {} }));
}

const SEL = {
    // The chain list. Rows carry no data attribute of their own — unlike the module and service lists
    // — so a row is addressed through the checkbox inside it, which does.
    row: (name) => `tr.sorted-chains:has(input[data-chain-name="${name}"])`,
    rows: "tr.sorted-chains",
    rowCheckbox: (name) => `input[type="checkbox"][data-chain-name="${name}"]`,
    rowDelete: (name) => `button[data-delete-chain][data-chain-name="${name}"]`,
    // Never clicked. Present here so the guard test can name what it is pinning.
    selectAll: "[data-select-all]",
    bulkDelete: "[data-delete-chains]",
    addChain: "[data-add-chain]",
    // The class ChainsTemplate puts on a row for a chain the realm names as a default. See the guard
    // test: on this build it is never applied.
    defaultConfigRow: "tr.sorted-chains.default-config-row",

    // The create form. Scoped to the footer as the sibling specs scope theirs; the name input also
    // carries [data-chain-name], which is why every list selector above says `tr`.
    newChainName: "#name",
    create: "#content .panel-footer [data-save]",

    // The chain editor.
    title: "#content h1",
    subtitle: "#content h4.page-type",
    // Both [data-add-new-module] buttons live inside #chains and only ever one is visible: the
    // call-to-action's while the chain is empty, the toolbar's once it is not.
    addLinkCallToAction: "#chains .call-to-action-block [data-add-new-module]",
    addLinkToolbar: "#chains .btn-toolbar [data-add-new-module]",
    callToAction: "#chains .call-to-action-block",
    toolbar: "#chains .btn-toolbar",
    linkList: "#sortableAuthChain",
    links: "#sortableAuthChain li.chain-link",
    saveChain: "[data-save-chain]",
    // Must be scoped: every link carries a [data-delete] of its own, so a bare selector is a
    // strict-mode violation as soon as the chain has one link in it.
    deleteChain: "#content .page-header [data-delete]",
    // Must be scoped too, and for a stranger reason: #alertContainer is a duplicated id. The chain
    // validation one is here, and PostProcessView renders a <td id="alertContainer"> on the Settings
    // tab.
    alert: "#chains #alertContainer .alert",

    // Within a link.
    linkName: "h3.media-heading",
    linkType: ".status",
    linkCriteria: "[data-select-criteria]",
    linkEdit: "[data-edit]",
    linkDelete: "[data-delete]",
    // The pass arrow in the link's footer, which _CriteriaFooter re-renders on every criteria change.
    // Its class is the oracle rather than its text: the footer reads "CONTINUE"/"PASS" for OPTIONAL
    // and SUFFICIENT alike, and only the direction distinguishes them.
    linkPassArrow: ".panel-footer.criteria-view .panel-arrow-success",
    // The drag grab point. Decorative as a control — the whole <li> is a handle — but it is a safe
    // place to press: groupDefaults.onMousedown refuses to start a drag on an input, select or
    // textarea, so grabbing a link by its centre would land on [data-select-criteria] and do nothing.
    dragHandle: ".panel-menu .btn-group button",

    // The add/edit link dialog. Both selects are SelectComponents, and the two are NOT addressed the
    // same way: the module select is given a custom optionComponent, and SelectComponent.getRenderer
    // returns the component's inner HTML, which replaces selectize's own option element — so
    // `.option` and `.item` are never applied to it. The criteria select has no custom renderer and
    // keeps them.
    dialog: ".bootstrap-dialog",
    dialogTitle: ".bootstrap-dialog .bootstrap-dialog-title",
    dialogBody: ".bootstrap-dialog .bootstrap-dialog-message",
    // The only button on this dialog with a stable id; Cancel's is a fresh uuid per dialog.
    dialogOk: ".bootstrap-dialog #saveBtn",
    moduleControl: ".bootstrap-dialog [data-module-select] .selectize-input",
    moduleOptions: ".bootstrap-dialog [data-module-select] .selectize-dropdown-content > div",
    criteriaControl: ".bootstrap-dialog [data-criteria-select] .selectize-input",
    criteriaOptions: ".bootstrap-dialog [data-criteria-select] .selectize-dropdown-content .option",

    // The confirmation dialog, which is a different BootstrapDialog with the standard footer.
    dialogConfirm: ".bootstrap-dialog .modal-footer button.btn-danger",
    dialogCancel: ".bootstrap-dialog .modal-footer button.btn-default",
};

/**
 * Deployed AM only, and deliberately not tagged @local-server.
 *
 * The /realm-config/authentication/* endpoints are outside the local API server's scope: design.md's
 * open question on how far its coverage should reach names them as deferred, and task 2.1 scopes the
 * server to the requests the phase-0 specs cause — which puts anything reached only by a @deployed-am
 * spec out of scope by construction. Under D16 that has to be declared rather than left to a skip, so
 * this spec says so here. If it later passes against the local server, that is a decision to retag it,
 * not a reason.
 */
test.describe("XUI authentication chain administration (create, add links, reorder, criteria, delete)", {
    tag: ["@deployed-am"],
}, () => {
    /** The oracle for every string the console renders below. */
    let bundle;
    let adminToken;
    /** AM's display name for each link's module type, which is what a rendered link shows. */
    const typeDescriptions = new Map();

    /**
     * Realm paths this test caused to exist. Registered before the realm is created, so a test that
     * fails halfway still cleans up after itself — which here also takes every chain and module in it.
     */
    let scratchRealms;

    test.beforeAll(async ({ request }) => {
        adminToken = await getAdminToken(request);
        expect(adminToken, "the fixtures need an admin session").toBeTruthy();

        bundle = await localeBundle(request, "translation");
    });

    test.beforeEach(() => {
        scratchRealms = [];
    });

    test.afterEach(async ({ request }) => {
        // Deepest path first, and every removal attempted even if an earlier one fails: the
        // alternative is that one failure leaks every realm behind it — and every chain and module in
        // them — into the next run. No per-chain cleanup: a realm deletes cleanly with chains still
        // configured in it, which is verified by this teardown never failing.
        const ordered = [...scratchRealms].sort((a, b) => b.split("/").length - a.split("/").length);
        const failures = [];

        for (const path of ordered) {
            try {
                await removeRealm(adminToken, request, path);
            } catch (error) {
                failures.push(error.message);
            }
        }
        expect(failures.join("\n"), "teardown must leave the instance as it found it").toBe("");
    });

    /** A realm of this test's own, with nothing configured in it beyond what a new realm gets. */
    async function givenRealm (request) {
        const name = uniqueRealmName("e2e-chain");
        const path = realmPathOf(name, TOP_LEVEL_REALM);

        scratchRealms.push(path);
        await createRealm(adminToken, request, { name });
        return { name, path };
    }

    /**
     * A realm holding the three module instances a chain is assembled from.
     *
     * The type descriptions are resolved from the realm's own module list rather than named here: a
     * rendered link shows the module's `typeDescription` as AM reports it, and the add-link dialog's
     * options are labelled with it too, so asserting against a literal would pin this spec's idea of
     * the name instead of the instance's.
     */
    async function givenRealmWithModules (request) {
        const realm = await givenRealm(request);

        for (const { module, type } of LINKS) {
            await createModule(adminToken, request, realm.path, type, module);
        }

        if (!typeDescriptions.size) {
            const modules = await listModules(adminToken, request, realm.path);
            const resolved = new Map();

            for (const { module } of LINKS) {
                const instance = modules.find((candidate) => candidate._id === module);

                expect(instance, `the module "${module}" must have been created`).toBeTruthy();
                expect(instance.typeDescription,
                    `AM must report a type description for "${module}"`).toBeTruthy();
                resolved.set(module, instance.typeDescription);
            }
            // Published only once every lookup has succeeded, so a half-filled map cannot make every
            // later test resolve a type description of `undefined`.
            for (const [module, description] of resolved) {
                typeDescriptions.set(module, description);
            }
        }
        return realm;
    }

    /** A realm holding the modules and a chain already assembled out of them, in LINKS order. */
    async function givenRealmWithChain (request) {
        const realm = await givenRealmWithModules(request);

        await createChain(adminToken, request, realm.path, CHAIN);
        await updateChain(adminToken, request, realm.path, CHAIN, seedLinks());
        return realm;
    }

    function chainRoute (realmPath, fragment = "") {
        return `${realmHash(realmPath, "authentication-chains")}${fragment}`;
    }

    /** The chain's links as AM has them: the ordered array a save writes and a reorder rearranges. */
    async function persistedLinks (request, realmPath) {
        const chain = await readChain(adminToken, request, realmPath, CHAIN);

        expect(chain, `the chain "${CHAIN}" must exist in "${realmPath}"`).not.toBeNull();
        return chain.authChainConfiguration.map(({ module, criteria }) => ({ module, criteria }));
    }

    async function openChainList (page, realmPath) {
        await page.goto(xuiUrl(chainRoute(realmPath)));
        await expect(page.locator(SEL.row(STOCK_CHAIN)),
            "the chain list must have rendered").toHaveCount(1);
    }

    /**
     * Open a chain's editor, forcing a real render.
     *
     * The bounce off the list route is the single most important line in this file after dragLink, and
     * it is not defensive tidying. Backbone does not re-fire a route for the hash it is already on, so
     * a goto straight back to an editor this page has already visited renders nothing at all — and
     * because the previous view's `li.chain-link` elements are still in the DOM, every wait and every
     * order assertion that follows passes instantly against the *unsaved* state left behind by the
     * last action. Reproduced during discovery, where it faked a flaky drag convincingly enough to be
     * recorded as one: see NOTES-auth-chains.md §7. Going via the list guarantees a route change in
     * both directions, so what is asserted afterwards is what the server served.
     */
    async function openChainEditor (page, realmPath, name = CHAIN) {
        await openChainList(page, realmPath);
        await page.goto(xuiUrl(chainRoute(realmPath, `/edit/${encodeURIComponent(name)}`)));
        await expect(page.locator(SEL.title), "the editor must be this chain's").toHaveText(name);
    }

    /** The module names down the chain, in DOM order — the ordering oracle. */
    function linkNames (page) {
        return page.locator(SEL.links).locator(SEL.linkName);
    }

    /**
     * Add a link through the dialog.
     *
     * Which of the two [data-add-new-module] buttons to press is decided by the chain being empty,
     * because validateChain hides one and shows the other — the call-to-action block is the only way
     * in until the chain has a link, and the toolbar is the only way in afterwards.
     */
    async function addLink (page, { module, criteria }, { first = false } = {}) {
        await page.locator(first ? SEL.addLinkCallToAction : SEL.addLinkToolbar).click();
        await expect(page.locator(SEL.dialogTitle))
            .toHaveText(bundle.console.authentication.editChains.newModule);

        // Selected by the label the operator reads, never by data-value: SelectComponent stamps that
        // with the option's index in the array rather than with the module's name.
        await page.locator(SEL.moduleControl).click();
        await page.locator(SEL.moduleOptions, { hasText: module }).first().click();

        await page.locator(SEL.criteriaControl).click();
        await page.locator(SEL.criteriaOptions, { hasText: criteriaLabel(criteria) }).first().click();

        // validateDialog releases OK only once both selects have answered.
        await expect(page.locator(SEL.dialogOk)).toBeEnabled();
        await page.locator(SEL.dialogOk).click();
        await expect(page.locator(SEL.dialog)).toHaveCount(0);
    }

    /** The label the console renders for a criteria value, from the bundle rather than from a literal. */
    function criteriaLabel (criteria) {
        const index = ["REQUIRED", "OPTIONAL", "REQUISITE", "SUFFICIENT"].indexOf(criteria);

        expect(index, `"${criteria}" must be one of the four criteria`).toBeGreaterThan(-1);
        return bundle.console.authentication.editChains.criteria[index].title;
    }

    /**
     * Drag the chain link at index `from` onto the slot at index `to`.
     *
     * This is the sequence task 1.15 exists to establish, so it is written out rather than delegated,
     * and every line of it is load-bearing.
     *
     * `locator.dragTo()` does not work here and cannot be made to. EditChainView.initSortable
     * configures jquery-sortable with `delay: 100`, so the drag does not arm until 100ms after
     * mousedown and every mousemove before that is discarded; dragTo is one atomic call with no pause
     * between its mousedown and its moves, so `delayMet` is still false when the library's drag handler
     * runs and it returns early. Measured: dragTo completes in ~111ms without throwing, leaves no
     * `.dragged` element and no `li.placeholder` behind, and moves nothing — a hand-rolled sequence
     * taking 58ms fails identically, while the same sequence with a 150ms pause after mousedown
     * succeeds. So the pause below is not a settle or a flake guard; it is the mechanism.
     *
     * The rest:
     *   - the opening move is how the press is aimed. mouse.down fires wherever the cursor already is,
     *     so there is no separate hover() and no initial nudge — `distance` is 0, and the first move
     *     after the delay is what starts the drag;
     *   - the grab point is the link's handle button. Not its centre: groupDefaults.onMousedown
     *     refuses to begin a drag on an input, select or textarea, and the middle of a link is its
     *     criteria <select>;
     *   - the destination is four pixels inside the target's far edge rather than at its centre, so
     *     the pointer clears the target's midpoint and the placeholder is pushed all the way through
     *     the item being displaced instead of settling beside it. Inside the edge, not past it;
     *   - 12 intermediate moves. One is enough — 1, 2, 3 and 12 were all measured to land the link
     *     correctly — and 12 is margin on a loaded machine, at about 700ms per drag against 310ms.
     *     With retries at 0 that is a trade this suite should keep making.
     *
     * The target is measured before the press, and deliberately so. Arming the drag does change the
     * geometry — the dragged <li> leaves the flow and li.placeholder takes its slot — but the two are
     * the same size to within a rounding error: the placeholder's min-height is 171px (chains.less) and
     * a rendered link measures 173px, so nothing below it moves by more than about two pixels.
     * Re-measuring after the press was tried and reverted: it buys those two pixels and costs a second
     * round trip in the middle of a timing-sensitive sequence.
     *
     * Measured 30/30 across four scenarios during discovery (down, up, adjacent swap, and both
     * viewports), and the apparent flakiness of an earlier pass was the harness re-dragging its own
     * previous result rather than the drag — which is what openChainEditor's bounce prevents. What this
     * helper is actually exercised on here is one downward drag; see the reorder test for why, and for
     * what is known about the upward case.
     *
     * The step values are fixed rather than parameterised because nothing overrides them and the
     * numbers are the record of what was measured.
     */
    async function dragLink (page, from, to) {
        const DRAG_ARM = 150;
        const DRAG_STEPS = 12;
        const DRAG_SETTLE = 25;
        const items = page.locator(SEL.links);
        const start = await items.nth(from).locator(SEL.dragHandle).first().boundingBox();
        const target = await items.nth(to).boundingBox();

        expect(start, `link ${from} must be on the page to be dragged`).toBeTruthy();
        expect(target, `link ${to} must be on the page to be dragged onto`).toBeTruthy();

        const x = start.x + start.width / 2;
        const y0 = start.y + start.height / 2;
        const y1 = to > from ? target.y + target.height - 4 : target.y + 4;

        await page.mouse.move(x, y0);
        await page.mouse.down();
        await page.waitForTimeout(DRAG_ARM);
        for (let step = 1; step <= DRAG_STEPS; step += 1) {
            await page.mouse.move(x, y0 + ((y1 - y0) * step) / DRAG_STEPS);
            await page.waitForTimeout(DRAG_SETTLE);
        }
        await page.mouse.up();
    }

    /** Save the chain's links and wait for the console's own confirmation. */
    async function saveChain (page, messages) {
        await expect(page.locator(SEL.saveChain)).toBeEnabled();
        await page.locator(SEL.saveChain).click();

        // AM answers the PUT with the chain and no message, so this string is the console's own.
        // Recorded rather than polled for, because the alert removes itself after a few seconds.
        await expect.poll(
            async () => (await messages())
                .filter((message) => message.className.includes("alert-info"))
                .map((message) => message.text),
            { message: "a saved chain must be confirmed to the user", timeout: 30_000 }
        ).toContain(bundle.config.messages.AppMessages.changesSaved);
    }

    test("a chain created through the console starts empty", async ({ page, request }) => {
        const { path } = await givenRealm(request);

        await openAdminConsole(page);
        await openChainList(page, path);
        await expect(page.locator(SEL.row(CHAIN)),
            "precondition: the realm does not have this chain yet").toHaveCount(0);

        const messages = await captureMessages(page);

        await page.locator(SEL.addChain).click();
        await expect(page).toHaveURL(xuiUrl(chainRoute(path, "/new")));
        await expect(page.locator(SEL.title))
            .toHaveText(bundle.console.authentication.chains.newChain);
        // A chain has only a name — there is no type to choose, which is the whole of why this form is
        // hand-written and generates nothing.
        await expect(page.locator(SEL.create)).toBeDisabled();

        // The name is refused client-side against the chain list the form fetched when it rendered,
        // before anything is sent. Asserted here rather than in a test of its own because it is this
        // spec's idempotency premise: a chain left behind by a failed run does not fail the create, it
        // disables the button, which would otherwise surface as an unexplained actionability timeout.
        await page.fill(SEL.newChainName, STOCK_CHAIN);
        await page.locator(SEL.newChainName).press("End");
        await expect(page.locator(SEL.create),
            "a name the realm already uses must be refused").toBeDisabled();
        await expect.poll(
            async () => (await messages())
                .filter((message) => message.className.includes("alert-danger"))
                .map((message) => message.text),
            { message: "a duplicate name must be reported to the user", timeout: 30_000 }
        ).toContain(bundle.console.authentication.chains.duplicateChain);

        // press("End") and not fill() alone. Measured: with fill() alone the button stayed disabled
        // with a valid name in the box. Why was not isolated — validateChainProps is bound to keyup
        // and change, and fill() does dispatch input and change, so the keyup is the likely gap, but
        // that was not proven and NOTES-auth-chains.md §3 records it as undetermined. The keypress
        // sidesteps it either way; do not read this as a statement about what fill() dispatches.
        await page.fill(SEL.newChainName, CHAIN);
        await page.locator(SEL.newChainName).press("End");
        await expect(page.locator(SEL.create)).toBeEnabled();
        await page.locator(SEL.create).click();

        // A created chain is confirmed by the console routing to its editor — nothing is added to
        // #messages on this path.
        await expect(page).toHaveURL(xuiUrl(chainRoute(path, `/edit/${CHAIN}`)));
        await expect(page.locator(SEL.title)).toHaveText(CHAIN);
        await expect(page.locator(SEL.subtitle))
            .toHaveText(bundle.console.authentication.editChains.chains);

        // What an empty chain looks like, which is one state rather than four independent ones:
        // validateChain flips all of these together on the first link and back on the last.
        await expect(page.locator(SEL.callToAction)).toBeVisible();
        await expect(page.locator(SEL.callToAction))
            .toContainText(bundle.console.authentication.editChains.callToAction);
        await expect(page.locator(SEL.linkList)).toHaveClass(/hidden/);
        await expect(page.locator(SEL.toolbar)).toHaveClass(/hidden/);
        await expect(page.locator(SEL.links)).toHaveCount(0);
        await expect(page.locator(SEL.saveChain),
            "an empty chain must not be saveable").toBeDisabled();

        const chain = await readChain(adminToken, request, path, CHAIN);

        expect(chain, "the console must have created the chain").not.toBeNull();
        expect(chain.authChainConfiguration, "a created chain has no links").toEqual([]);
    });

    test("module links added through the console are saved in the order they were added", async ({ page, request }) => {
        const { path } = await givenRealmWithModules(request);

        await createChain(adminToken, request, path, CHAIN);

        await openAdminConsole(page);
        await openChainEditor(page, path);
        await expect(page.locator(SEL.links),
            "precondition: the chain starts empty").toHaveCount(0);

        const messages = await captureMessages(page);

        for (const [index, link] of LINKS.entries()) {
            await addLink(page, link, { first: index === 0 });
            await expect(page.locator(SEL.links)).toHaveCount(index + 1);
        }

        // The links are on screen, in order, each showing the module it was built from and the type
        // description AM reports for it.
        await expect(linkNames(page)).toHaveText(LINKS.map((link) => link.module));
        await expect(page.locator(SEL.links).locator(SEL.linkType))
            .toHaveText(LINKS.map((link) => typeDescriptions.get(link.module)));

        // ... and adding one flipped the editor out of its empty state.
        await expect(page.locator(SEL.callToAction)).toBeHidden();
        await expect(page.locator(SEL.linkList)).not.toHaveClass(/hidden/);

        // Nothing has been sent yet. Adding a link mutates the in-memory chain and posts nothing, so
        // this is what distinguishes the dialog having built a link from the dialog having saved one.
        expect(await persistedLinks(request, path),
            "adding a link must not reach AM before the chain is saved").toEqual([]);

        await saveChain(page, messages);

        expect(await persistedLinks(request, path), "the saved chain must be the chain on screen")
            .toEqual(LINKS.map(({ module, criteria }) => ({ module, criteria })));
    });

    test("a link dragged to a new position is reordered in the chain", async ({ page, request }) => {
        // The reason this spec exists. See dragLink for why the sequence is what it is, and the file
        // header for why `sortable` is worth a test of its own.
        const { path } = await givenRealmWithChain(request);
        const seeded = LINKS.map(({ module, criteria }) => ({ module, criteria }));
        // The first link moved to the end. The other two shift up, which is what makes this a move
        // rather than a swap — a widget that could only exchange neighbours would fail here.
        //
        // One drag, downwards, and that is a deliberate ceiling rather than the obvious first case.
        // A second leg dragging the link back up onto a slot in the middle was written, measured and
        // removed: it lands 4 times in 5 from a fresh render, and one probe of five reps missed every
        // time, against 5/5 and 30/30 for this downward drag under the same harness. The upward branch
        // of dragLink is therefore unexercised, and known to be unreliable rather than untested — see
        // NOTES-auth-chains.md and dragLink. Do not add an upward leg back without measuring it: an
        // intermittent assertion in a suite configured with retries at 0 is worse than a missing one,
        // and this test is the one place in the suite where a spurious red would be read as the
        // `sortable` migration having broken something.
        const reordered = [seeded[1], seeded[2], seeded[0]];

        await openAdminConsole(page);
        await openChainEditor(page, path);

        // Asserted before anything is measured, and this is not scenery: a drag is judged by the
        // difference it makes, so an editor showing a stale order would let a drag that did nothing
        // look like a drag that worked. See openChainEditor.
        await expect(linkNames(page), "precondition: the chain is in its seeded order")
            .toHaveText(seeded.map((link) => link.module));
        expect(await persistedLinks(request, path),
            "precondition: AM has the seeded order too").toEqual(seeded);

        const messages = await captureMessages(page);

        await dragLink(page, 0, 2);

        // The DOM moves immediately — jquery-sortable's onDrop reorders the list and EditChainView
        // splices the in-memory array to match, with no request involved.
        await expect(linkNames(page), "the dragged link must have moved in the DOM")
            .toHaveText(reordered.map((link) => link.module));
        // The type line moved with the name rather than staying with the position. Cheap here because
        // the middle link is the other module type, and it is the difference between the list having
        // been reordered and the list having been relabelled.
        await expect(page.locator(SEL.links).locator(SEL.linkType))
            .toHaveText(reordered.map((link) => typeDescriptions.get(link.module)));
        // ... and so did each link's criteria. Checked against the DOM here as well as against AM
        // after the save, so that a widget that moved the wrong thing is told apart from a save that
        // wrote the wrong thing rather than the two failing as one.
        for (const [index, link] of reordered.entries()) {
            await expect(page.locator(SEL.links).nth(index).locator(SEL.linkCriteria),
                `link ${index} must carry its own criteria after the drag`).toHaveValue(link.criteria);
        }

        // ... and AM has not heard about it. The drag is in-memory until the save, so a console that
        // reordered the DOM and silently persisted nothing would pass every assertion above.
        expect(await persistedLinks(request, path),
            "the drag alone must not reach AM").toEqual(seeded);

        await saveChain(page, messages);

        // The assertion this test is for: the reorder is what AM now has, and each link's criteria
        // travelled with it rather than staying at its index.
        expect(await persistedLinks(request, path),
            "the saved chain must be in the dragged order, criteria and all").toEqual(reordered);

        // ... and it survives the view being rebuilt from what AM served, which is the difference
        // between the array having been written and the chain having been reordered.
        await openChainEditor(page, path);
        await expect(linkNames(page), "the reorder must survive a re-render")
            .toHaveText(reordered.map((link) => link.module));
    });

    test("a link's criteria changed in the console is saved with the chain", async ({ page, request }) => {
        const { path } = await givenRealmWithChain(request);
        const seeded = LINKS.map(({ module, criteria }) => ({ module, criteria }));
        const changed = seeded.map((link, index) =>
            (index === 1 ? { ...link, criteria: "SUFFICIENT" } : link));

        await openAdminConsole(page);
        await openChainEditor(page, path);
        await expect(linkNames(page), "precondition: the chain is in its seeded order")
            .toHaveText(seeded.map((link) => link.module));

        const middle = page.locator(SEL.links).nth(1);

        // A plain <select>, and the one control in this editor that is not decorated by anything —
        // there is no selectize on a rendered link at all, which is why selectOption works here and
        // could not be used in the dialog.
        await expect(middle.locator(SEL.linkCriteria)).toHaveValue(seeded[1].criteria);
        // The pass arrow points down while passing this link continues down the chain.
        await expect(middle.locator(SEL.linkPassArrow)).toHaveClass(/panel-arrow-down/);

        const messages = await captureMessages(page);

        await middle.locator(SEL.linkCriteria).selectOption("SUFFICIENT");

        // LinkView.renderArrows rebuilds the footer from the new criteria. Asserted on the class and
        // not the text: the footer reads the same for OPTIONAL and SUFFICIENT, and only the arrow's
        // direction says that passing this link now leaves the chain.
        await expect(middle.locator(SEL.linkPassArrow),
            "a SUFFICIENT link must exit the chain on a pass").toHaveClass(/panel-arrow-right/);

        // validateChain re-runs on every criteria change, and this particular chain now trips its one
        // warning: a REQUIRED link precedes a SUFFICIENT one with something after it. It is advice
        // rather than a refusal, and pinning both halves is the point — a migration that turned this
        // into a blocking validation would stop operators saving a legal chain.
        await expect(page.locator(SEL.alert))
            .toHaveText(bundle.console.authentication.editChains.alerts.reqdFailSuffPass);
        await expect(page.locator(SEL.alert)).toHaveClass(/alert-warning/);
        await expect(page.locator(SEL.saveChain),
            "the warning must not prevent the chain being saved").toBeEnabled();

        expect(await persistedLinks(request, path),
            "a criteria change must not reach AM before the chain is saved").toEqual(seeded);

        await saveChain(page, messages);

        expect(await persistedLinks(request, path),
            "the saved chain must carry the new criteria").toEqual(changed);

        await openChainEditor(page, path);
        await expect(page.locator(SEL.links).nth(1).locator(SEL.linkCriteria),
            "the criteria change must survive a re-render").toHaveValue("SUFFICIENT");
    });

    test("a link can be edited and removed through the chain editor", async ({ page, request }) => {
        const { path } = await givenRealmWithChain(request);
        const seeded = LINKS.map(({ module, criteria }) => ({ module, criteria }));
        // The first link edited to SUFFICIENT through the dialog, and the second removed.
        const edited = [{ ...seeded[0], criteria: "SUFFICIENT" }, seeded[2]];

        await openAdminConsole(page);
        await openChainEditor(page, path);
        await expect(linkNames(page), "precondition: the chain is in its seeded order")
            .toHaveText(seeded.map((link) => link.module));

        const messages = await captureMessages(page);

        await page.locator(SEL.links).first().locator(SEL.linkEdit).click();
        await expect(page.locator(SEL.dialogTitle))
            .toHaveText(bundle.console.authentication.editChains.editModule);

        // The dialog opens with OK refused even though both selects are already populated, and that is
        // not a rendering delay to be waited out: validateDialog is only ever called from a select's
        // onChange handler, so a dialog opened to read a link and closed with OK cannot be closed with
        // OK at all. Pinned because it is the trap a spec written from the create dialog would fall
        // into, and because a migration that made OK enabled on open would be a behaviour change
        // nothing else here would notice.
        await expect(page.locator(SEL.dialogOk),
            "the edit dialog opens with OK refused until something changes").toBeDisabled();

        await page.locator(SEL.criteriaControl).click();
        await page.locator(SEL.criteriaOptions, { hasText: criteriaLabel("SUFFICIENT") }).first().click();
        await expect(page.locator(SEL.dialogOk)).toBeEnabled();
        await page.locator(SEL.dialogOk).click();
        await expect(page.locator(SEL.dialog)).toHaveCount(0);

        // The link was re-rendered in place rather than appended: same count, same order, new criteria.
        await expect(page.locator(SEL.links)).toHaveCount(seeded.length);
        await expect(page.locator(SEL.links).first().locator(SEL.linkCriteria))
            .toHaveValue("SUFFICIENT");

        // Removing a link has no confirmation at all — unlike deleting a chain, by any of its three
        // routes. The <li> goes immediately, and asserting that no dialog appeared is the only way to
        // say so. Order matters: toHaveCount(0) is satisfied by its first poll, so asked straight after
        // the click it would answer before a confirmation had had time to render and could not fail.
        // Waiting for the removal first is what gives it something to be true *after*.
        await page.locator(SEL.links).nth(1).locator(SEL.linkDelete).click();
        await expect(linkNames(page)).toHaveText(edited.map((link) => link.module));
        await expect(page.locator(SEL.dialog),
            "removing a link is not confirmed").toHaveCount(0);

        expect(await persistedLinks(request, path),
            "neither the edit nor the removal may reach AM before the chain is saved").toEqual(seeded);

        await saveChain(page, messages);

        expect(await persistedLinks(request, path),
            "the saved chain must carry both the edit and the removal").toEqual(edited);
    });

    test("a chain deleted from its editor disappears from the console", async ({ page, request }) => {
        const { path } = await givenRealmWithChain(request);

        await openAdminConsole(page);
        await openChainEditor(page, path);

        const messages = await captureMessages(page);

        // The confirmation is a gate rather than a formality, so this declines once before it agrees.
        // A dialog that deleted on cancel would pass every other assertion here.
        await page.locator(SEL.deleteChain).click();
        await expect(page.locator(SEL.dialogTitle))
            .toHaveText(`${bundle.common.form.confirm} ${bundle.common.form.delete}`);
        // This route resolves __type__ from console.authentication.modules.chain — a different key
        // from the list's, and the reason the three delete tests assert three different strings.
        await expect(page.locator(SEL.dialogBody)).toHaveText(
            bundle.console.common.confirmDeleteText
                .replace("__type__", bundle.console.authentication.modules.chain));
        await page.locator(SEL.dialogCancel).click();
        await expect(page.locator(SEL.dialog)).toHaveCount(0);

        await expect(page).toHaveURL(xuiUrl(chainRoute(path, `/edit/${CHAIN}`)));
        expect(await readChain(adminToken, request, path, CHAIN),
            "cancelling must not have deleted anything").not.toBeNull();

        await page.locator(SEL.deleteChain).click();
        await page.locator(SEL.dialogConfirm).click();

        // The only one of the three delete routes that says anything, and the only one that routes:
        // the operator is returned to the list, which no longer has the chain in it.
        await expect(page).toHaveURL(xuiUrl(chainRoute(path)));
        await expect(page.locator(SEL.row(STOCK_CHAIN)),
            "the chain list must have rendered").toHaveCount(1);
        await expect(page.locator(SEL.row(CHAIN))).toHaveCount(0);

        await expect.poll(
            async () => (await messages())
                .filter((message) => message.className.includes("alert-info"))
                .map((message) => message.text),
            { message: "a deleted chain must be confirmed to the user", timeout: 30_000 }
        ).toContain(bundle.console.authentication.editChains.deletedChain);

        expect(await readChain(adminToken, request, path, CHAIN),
            "the chain must be gone from AM").toBeNull();
    });

    test("a chain deleted from the chain list disappears from the console", async ({ page, request }) => {
        const { path } = await givenRealmWithChain(request);

        await openAdminConsole(page);
        await openChainList(page, path);
        await expect(page.locator(SEL.row(CHAIN)),
            "precondition: the realm has the chain").toHaveCount(1);

        const messages = await captureMessages(page);

        await page.locator(SEL.rowDelete(CHAIN)).click();
        await expect(page.locator(SEL.dialogTitle))
            .toHaveText(`${bundle.common.form.confirm} ${bundle.common.form.delete}`);
        // console.authentication.common.chain here, where the editor used
        // console.authentication.modules.chain: the same sentence, differing only in whether "chain"
        // is capitalised. Asserted from the bundle so the difference is pinned rather than papered
        // over by a case-insensitive match.
        await expect(page.locator(SEL.dialogBody)).toHaveText(
            bundle.console.common.confirmDeleteText
                .replace("__type__", bundle.console.authentication.common.chain));
        await page.locator(SEL.dialogCancel).click();
        await expect(page.locator(SEL.dialog)).toHaveCount(0);

        await expect(page.locator(SEL.row(CHAIN)),
            "cancelling must leave the chain alone").toHaveCount(1);
        expect(await readChain(adminToken, request, path, CHAIN),
            "cancelling must not have deleted anything").not.toBeNull();

        await page.locator(SEL.rowDelete(CHAIN)).click();
        await page.locator(SEL.dialogConfirm).click();

        // No routing on this route, and no message: the list re-renders in place and the row going
        // away is the whole of the feedback the operator gets. The silence is asserted rather than
        // assumed, because it is the difference from the editor's route.
        await expect(page.locator(SEL.row(CHAIN))).toHaveCount(0);
        await expect(page.locator(SEL.row(STOCK_CHAIN)),
            "the list must have re-rendered rather than emptied").toHaveCount(1);
        await expect(page).toHaveURL(xuiUrl(chainRoute(path)));

        expect((await messages()).map((message) => message.text),
            "deleting from the list must be silent")
            .not.toContain(bundle.console.authentication.editChains.deletedChain);

        expect(await readChain(adminToken, request, path, CHAIN),
            "the chain must be gone from AM").toBeNull();
    });

    test("a chain selected in the list can be deleted with the toolbar", async ({ page, request }) => {
        const { path } = await givenRealmWithChain(request);

        await openAdminConsole(page);
        await openChainList(page, path);

        // The third delete route, and the only one that is not a single click: the toolbar acts on
        // whatever is checked, so it is refused until something is.
        await expect(page.locator(SEL.bulkDelete)).toBeDisabled();
        // This chain's own checkbox, by name. NOT [data-select-all], which on this build would also
        // check the realm's default authentication chain — see the guard test and the file header.
        await page.locator(SEL.rowCheckbox(CHAIN)).check();
        await expect(page.locator(SEL.bulkDelete)).toBeEnabled();
        // ChainsView marks the row as well as enabling the button, so the operator can see what the
        // toolbar would act on.
        await expect(page.locator(SEL.row(CHAIN))).toHaveClass(/selected/);

        await page.locator(SEL.bulkDelete).click();

        // The third of the three delete strings, and the only one that mentions a selection. One chain
        // is checked, so i18next resolves the singular.
        await expect(page.locator(SEL.dialogTitle))
            .toHaveText(`${bundle.common.form.confirm} ${bundle.common.form.delete}`);
        await expect(page.locator(SEL.dialogBody))
            .toHaveText(bundle.console.authentication.chains.confirmDeleteSelected);
        await page.locator(SEL.dialogConfirm).click();

        await expect(page.locator(SEL.row(CHAIN))).toHaveCount(0);
        await expect(page.locator(SEL.row(STOCK_CHAIN)),
            "the list must have re-rendered rather than emptied").toHaveCount(1);
        // And the toolbar has forgotten the selection along with the row it belonged to.
        await expect(page.locator(SEL.bulkDelete)).toBeDisabled();

        expect(await readChain(adminToken, request, path, CHAIN),
            "the chain must be gone from AM").toBeNull();
    });

    test("the console does not flag the chains a realm authenticates against", async ({ page, request }) => {
        // A defect, pinned deliberately, and the assertions below are written so that fixing it turns
        // this test red with an explanation rather than leaving it quietly passing on new behaviour.
        //
        // ChainsView is meant to protect a realm's default chains: AuthenticationService.chains.all
        // marks a chain whose _id matches the realm's adminAuthModule or orgConfig, ChainsTemplate
        // gives that row `default-config-row` and disables its checkbox and its delete button, and
        // EditChainView.render disables the editor's delete button with an explanatory popover. None
        // of it ever fires, because AM nests those two keys under `core` and the service reads them at
        // the top level, so every comparison is against undefined.
        //
        // Why this belongs in a spec rather than only in NOTES-auth-chains.md: the consequence is that
        // [data-select-all] selects the realm's default authentication chain along with everything
        // else — it skips only :disabled checkboxes and none are disabled — so anything that clicks it
        // and then the bulk delete removes the chain the realm authenticates its users against. That
        // is the hazard this spec navigates around by checking boxes by name, and a reader who does
        // not know the guard is dead would reasonably assume it was covering them.
        const { path } = await givenRealm(request);

        const authentication = await realmAuthenticationConfig(adminToken, request, path);

        // The premise: this realm does name a chain as both of its defaults, so there is something for
        // the guard to fire on. If a future AM stopped seeding these, the pin below would be trivially
        // true and this is the line that would say so.
        expect(authentication.core?.orgConfig,
            "a new realm must name a default organization authentication chain").toBe(STOCK_CHAIN);
        expect(authentication.core?.adminAuthModule,
            "a new realm must name a default administrator authentication chain").toBe(STOCK_CHAIN);

        // The cause, asserted directly so that the day AM moves these keys — or the service learns to
        // read them where they are — this fails first and names the fix.
        expect(authentication.adminAuthModule,
            "AM nests these under `core`; the console reads them at the top level, which is the defect")
            .toBeUndefined();
        expect(authentication.orgConfig,
            "AM nests these under `core`; the console reads them at the top level, which is the defect")
            .toBeUndefined();

        await openAdminConsole(page);
        await openChainList(page, path);

        // The effect. Not "the default chain is protected" — that is what this console is trying to
        // do and does not manage.
        await expect(page.locator(SEL.defaultConfigRow),
            "no chain is flagged as a realm default, though one should be").toHaveCount(0);
        // ... including the row for the chain the realm actually authenticates against — and asserted
        // through the mechanism rather than the class, because the class is only the visible half.
        // ChainsView.selectAll ticks every input[data-chain-name] that is not :disabled, so an enabled
        // checkbox on this row is the whole of why select-all-then-delete reaches the realm's default
        // chain. Positive matchers on both: a negated one on a row that had stopped rendering would
        // pass for the wrong reason, and these cannot.
        await expect(page.locator(SEL.rowCheckbox(STOCK_CHAIN)),
            "the default chain's checkbox is left enabled, so select-all takes it").toBeEnabled();
        await expect(page.locator(SEL.selectAll),
            "select-all is offered, and on this build it would select that chain too").toBeVisible();
    });
});
