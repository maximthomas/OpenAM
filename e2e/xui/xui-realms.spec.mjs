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
 * OpenAM XUI — realm administration: creating, editing and deleting a realm through the console.
 *
 * The first spec in this suite that drives the admin console rather than an end-user page, and the
 * first that changes server state through the UI. xui-login.spec.mjs proves an administrator can
 * reach the realm list; this proves the list is an application.
 *
 * What this is guarding, beyond "realm CRUD works":
 *
 *   - a form generated at runtime from an SMS schema. The realm form is not written in a template:
 *     EditRealmView asks RealmsService for a schema — ?_action=schema alone when editing, and
 *     ?_action=schema plus ?_action=template when creating, since a new realm's defaults come from
 *     the template — and hands it to json-editor, which builds the inputs. Every `root[...]` selector
 *     below is a name json-editor derived from that payload, so a break in either fetch or in
 *     json-editor surfaces here as a missing field rather than as a failed request. This is also the
 *     machinery design.md D15 says the local API server's capture exists to reproduce, and 2.11 is
 *     scoped to serve. The realm *list* is not schema-generated — it is Handlebars over
 *     ?_queryFilter=true;
 *   - the aliases editor, which is selectize — one of the 20+ non-AMD libraries `main.js` shims
 *     (design.md task 5.3). It is exercised on create, where a value has to survive the round trip
 *     through the shimmed library into the request body;
 *   - Handlebars partials fetched by path and compiled in the browser (D3): the realm-name warning is
 *     partials/alerts/_Alert.html compiled at runtime, and the table rows are RealmsTableTemplate.html
 *     over util/_Status.html;
 *   - view modules resolved by string identifier and loaded on demand (D1). Reaching the edit form
 *     means the router resolved "…/admin/views/realms/EditRealmView" and ModuleLoader fetched it.
 *     xui-login.spec.mjs already loads ListRealmsView by proving an administrator lands on it;
 *     EditRealmView is loaded by no other spec in the suite.
 *
 * The rules asserted here are the console's, not AM's. AM enforces the same 17-character blacklist on
 * a realm name that EditRealmView.checkPattern does (SmsRealmProvider.BLACKLIST_CHARACTERS), so what
 * is console-only is not *that* an illegal name is refused but that it is refused client-side, with
 * nothing sent — along with which fields stop being editable once a realm exists, and which realm may
 * not be deleted or deactivated even though AM would allow both over REST. Those are what a migration
 * can break silently, so those are what is pinned.
 *
 * Two behaviours are recorded rather than asserted, because phase 0a records today's behaviour and
 * pinning a defect would make a later fix look like a regression:
 *
 *   - the edit view's delete confirmation reads "Are you sure that you want to delete this
 *     console.realms.edit.realm?" — EditRealmView passes $.t("console.realms.edit.realm") as the
 *     object type and the console's bundle defines no such key, so the raw key is rendered. What is
 *     asserted is the dialog's title and the part of the body that precedes the substitution, which
 *     is fixed by console.common.confirmDeleteText and survives the eventual fix;
 *   - the realm-name input carries pattern="^[^ @#$%&+?:;,/=\<>"]+$", which is not a valid regular
 *     expression under either Unicode mode: `\<` is an invalid escape under `u`, and the unescaped `/`
 *     inside the character class is invalid under `v`. HTML compiles pattern in Unicode mode, so this
 *     has never applied in any browser that implements the attribute as specified — it is not a recent
 *     Chromium change. The validation that does the work is EditRealmView's own, which is what the
 *     illegal-name test below drives.
 *
 * If the create test fails with the browser still on #realms/new, look at the network log before the
 * UI: creating a realm is two writes, and the second (PUT …/realm-config/authentication) is the one
 * that 500s on an instance whose SMS schema cache has expired. That is the instance, not a
 * regression — see "Reset between runs" in e2e/local/README.md.
 */

import { test, expect } from "@playwright/test";
import { getAdminToken } from "../common/openam-commons.mjs";
import { captureMessages, localeBundle, openAdminConsole, xuiUrl } from "../common/xui-commons.mjs";
import {
    TOP_LEVEL_REALM,
    createRealm,
    readRealm,
    realmHash,
    realmPathOf,
    removeRealm,
    uniqueRealmName,
} from "../common/realms-commons.mjs";

const SEL = {
    // The realm list renders both of its views at once and lets a tab decide which is shown, so every
    // assertion on it is scoped to one container. The table is the one that renders a realm's path,
    // status and aliases as text.
    table: "#viewBContainer",
    tableToggle: "#toggleCardList a[href=\"#toggleBView\"]",
    newRealm: "#toggleCardList a[href=\"#realms/new\"]",

    // The realm form. json-editor names its inputs after the schema properties, and renders a
    // readonly property as a disabled control.
    name: "input[name=\"root[name]\"]",
    active: "input[name=\"root[active]\"]",
    // Edit form only. On the new-realm form parentPath is an enum, which json-editor renders as a
    // <select> that selectize then decorates with an <input> of its own — so a selector matching both
    // would be ambiguous there. Nothing below needs it on that form.
    readOnlyParentPath: "[data-schemapath=\"root.parentPath\"] input",
    aliasInput: "[data-schemapath=\"root.aliases\"] .selectize-input input",
    aliasItems: "[data-schemapath=\"root.aliases\"] .selectize-input .item",
    nameAlert: "[data-realm-alert] .alert",
    save: "[data-save]",
    delete: "[data-delete]",

    dialogTitle: ".bootstrap-dialog .bootstrap-dialog-title",
    dialogBody: ".bootstrap-dialog .bootstrap-dialog-message",
    dialogButtons: ".bootstrap-dialog .modal-footer button",
    dialogConfirm: ".bootstrap-dialog .modal-footer button.btn-danger",
};

/**
 * Valid against both backends. Realm read and CRUD is what design.md task 2.10 commits the local API
 * server to, in the words of this spec — "a realm created through the console appears in the next
 * listing and a deleted one disappears" — and the SMS schema and template payloads the form is
 * generated from are task 2.11's. Nothing here asserts AM-specific server behaviour — contrast
 * xui-httponly.spec.mjs.
 *
 * Two dependencies are worth naming for 2.1's request enumeration, because neither is obviously realm
 * administration:
 *
 *   - creating a realm through this form also PUTs the new realm's realm-config authentication
 *     service, and the console treats a failure there as a failed create;
 *   - the fixtures below authenticate with getAdminToken, which is zero-page login — username and
 *     password as X-OpenAM-Username / X-OpenAM-Password headers on /json/authenticate. That is a
 *     different code path from the callback exchange task 2.7 describes, and this is the first
 *     local-server-valid spec that needs it.
 */
test.describe("XUI realm administration (create, edit, delete)", {
    tag: ["@deployed-am", "@local-server"],
}, () => {
    /** The oracle for every string the console renders below. */
    let bundle;
    let adminToken;

    /**
     * Realm paths this test caused to exist. Registered before the realm is created, so a test that
     * fails halfway still cleans up after itself — the instance is long-lived and shared, and a
     * leftover realm is visible to every later assertion on the realm list.
     */
    let scratchRealms;

    test.beforeAll(async ({ request }) => {
        adminToken = await getAdminToken(request);
        expect(adminToken, "the fixtures need an admin session").toBeTruthy();

        // The console's own namespace, fetched from the instance: asserting against it rather than
        // against literals also asserts locales/en/translation.json was packaged and served.
        bundle = await localeBundle(request, "translation");
    });

    test.beforeEach(() => {
        scratchRealms = [];
    });

    test.afterEach(async ({ request }) => {
        // Deepest path first, so a child is removed before its parent, and one at a time so that
        // ordering means something. Every removal is attempted even if an earlier one fails, because
        // the alternative is that one failure leaks every realm behind it into the next run's realm
        // list; the failures are reported together once the sweep is done.
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

    /** Name a realm this test is about to bring into existence, and return its path. */
    function scratchRealm (name) {
        const path = realmPathOf(name, TOP_LEVEL_REALM);
        scratchRealms.push(path);
        return path;
    }

    /** A realm that already exists, for the tests whose subject is editing or deleting one. */
    async function givenRealm (request, { active = true } = {}) {
        const name = uniqueRealmName();
        const path = scratchRealm(name);

        await createRealm(adminToken, request, { name, active });
        return { name, path };
    }

    /** Show the realm list in its table view, which is the view that renders a realm as text. */
    async function openRealmList (page) {
        await page.goto(xuiUrl("#realms"));
        await page.locator(SEL.tableToggle).click();
        await expect(page.locator(SEL.table)).toBeVisible();
    }

    /** The realm list's row for a realm, identified the way the template identifies it. */
    function realmRow (page, path) {
        return page.locator(`${SEL.table} tr`)
            .filter({ has: page.locator(`[data-realm-path="${path}"]`) });
    }

    /**
     * Assert the realm list has rendered and does not contain a realm.
     *
     * The absence needs an anchor. ToggleCardListView puts the toolbar and both empty containers into
     * the DOM first and fills each from its own template fetch afterwards, so "no row for this realm"
     * is equally true of a table that never rendered at all — including the failure this suite most
     * wants to catch, a template that stopped being served (D3). Asserting the top level realm's row
     * in the same breath makes the absence a statement about a list rather than about an empty div.
     */
    async function expectRealmAbsent (page, path) {
        await expect(page.locator(SEL.table)).toBeVisible();
        await expect(realmRow(page, TOP_LEVEL_REALM), "the list must have rendered").toHaveCount(1);
        await expect(realmRow(page, path)).toHaveCount(0);
    }

    /** Open a realm's edit form and wait until it has been generated. */
    async function openRealmEditForm (page, path) {
        await page.goto(xuiUrl(realmHash(path, "edit")));
        await expect(page.locator(SEL.name)).toBeVisible();
    }

    /**
     * Type into a field rather than filling it.
     *
     * EditRealmView enables its submit button from a keyup handler on the name input, and selectize
     * commits an entry on a keypress. A value assigned without key events leaves both unaware that
     * anything was entered, which reads as a disabled button and an empty field.
     */
    async function typeInto (locator, text) {
        await locator.click();
        await locator.pressSequentially(text);
    }

    test("a realm created through the console appears in the realm list", async ({ page, request }) => {
        const name = uniqueRealmName();
        const path = scratchRealm(name);
        // RFC 6761 reserves .invalid, so this alias can never resolve to anything.
        const alias = `${name}.alias.invalid`;

        await openAdminConsole(page);
        await page.locator(SEL.newRealm).click();
        await expect(page.locator(SEL.name)).toBeVisible();

        await typeInto(page.locator(SEL.name), name);
        await typeInto(page.locator(SEL.aliasInput), alias);
        await page.locator(SEL.aliasInput).press("Enter");
        // The alias is only entered once selectize has turned it into an item; before that it is
        // uncommitted text that the form would submit without.
        await expect(page.locator(SEL.aliasItems)).toHaveText([alias]);

        await page.locator(SEL.save).click();

        // The console sends a created realm to its own dashboard. Landing there is what says the
        // create resolved, rather than merely having been posted.
        await expect(page).toHaveURL(xuiUrl(realmHash(path, "dashboard")));

        // It reached the server, with what the form was given ...
        const created = await readRealm(adminToken, request, path);
        expect(created, "the console must have created the realm").not.toBeNull();
        expect(created.parentPath).toBe(TOP_LEVEL_REALM);
        expect(created.active).toBe(true);
        expect(created.aliases, "the alias must survive the selectize editor").toEqual([alias]);

        // ... and the list the console renders next is built from a fresh read, so it is there too.
        await openRealmList(page);
        const row = realmRow(page, path);
        await expect(row).toContainText(name);
        await expect(row).toContainText(path);
        await expect(row).toContainText(alias);
    });

    test("an illegal realm name is refused before anything is submitted", async ({ page }) => {
        await openAdminConsole(page);
        await page.locator(SEL.newRealm).click();
        await expect(page.locator(SEL.name)).toBeVisible();

        // AM refuses a space in a realm name too, so the assertion that carries this test is not that
        // the name is rejected but that it is rejected here: EditRealmView.checkPattern decides it and
        // nothing is sent. Recorded from the moment the illegal name is typed, so a console that
        // asked the server would be caught doing it.
        const creates = [];
        page.on("request", (req) => {
            if (req.method() === "POST" && req.url().includes("/global-config/realms")) {
                creates.push(req.url());
            }
        });

        await typeInto(page.locator(SEL.name), "illegal name");

        await expect(page.locator(SEL.save)).toBeDisabled();
        expect(creates, "the console must decide this without asking AM").toEqual([]);
        // The explanation is a Handlebars partial compiled and injected at runtime, so this asserts
        // partials/alerts/_Alert.html was fetched by path and compiled as well as what it says (D3).
        await expect(page.locator(SEL.nameAlert)).toHaveClass(/alert-warning/);
        await expect(page.locator(SEL.nameAlert))
            .toContainText(bundle.console.realms.realmNameValidationError);

        // And it is a live judgement on what is in the field rather than a latch: a legal name clears
        // the warning and releases the button.
        await page.locator(SEL.name).fill("");
        await typeInto(page.locator(SEL.name), uniqueRealmName());
        await expect(page.locator(SEL.nameAlert)).toHaveCount(0);
        await expect(page.locator(SEL.save)).toBeEnabled();
    });

    test("an existing realm's identity is fixed once it has one", async ({ page, request }) => {
        const { name, path } = await givenRealm(request);

        await openAdminConsole(page);
        await openRealmEditForm(page, path);

        // Level-scoped and exact, as xui-login.spec.mjs does: an unqualified h1 lookup would become a
        // strict-mode failure rather than a clear assertion the day the layout grows a second one.
        await expect(page.getByRole("heading", { level: 1, name, exact: true })).toBeVisible();

        // The console's rule, not AM's: a realm's name and parent are chosen at creation and never
        // edited afterwards. EditRealmView marks both readonly once the entity is not new, and
        // json-editor renders readonly as a disabled control — so this is what "cannot be changed"
        // looks like in the DOM, and both the values and their disabled state are the assertion.
        await expect(page.locator(SEL.name)).toHaveValue(name);
        await expect(page.locator(SEL.name)).toBeDisabled();
        await expect(page.locator(SEL.readOnlyParentPath)).toHaveValue(TOP_LEVEL_REALM);
        await expect(page.locator(SEL.readOnlyParentPath)).toBeDisabled();

        // What this realm may still do, so that the top level realm's restrictions below are read as
        // a difference rather than as how every realm renders.
        await expect(page.locator(SEL.active)).toBeEnabled();
        await expect(page.locator(SEL.delete)).toBeEnabled();
    });

    test("an edit made in the console persists", async ({ page, request }) => {
        const { path } = await givenRealm(request, { active: true });

        await openAdminConsole(page);
        await openRealmEditForm(page, path);
        await expect(page.locator(SEL.active), "precondition: the realm starts active").toBeChecked();

        const messages = await captureMessages(page);
        // Forced: json-editor renders the checkbox itself at 1px and puts the click surface on the
        // slider label drawn over it.
        await page.locator(SEL.active).click({ force: true });
        await expect(page.locator(SEL.active)).not.toBeChecked();
        await page.locator(SEL.save).click();

        // The console reports the save itself — AM answers a realm PUT with the realm and no message,
        // so this string is the UI's own. Recorded rather than polled for, because the alert removes
        // itself after a few seconds.
        await expect.poll(
            async () => (await messages())
                .filter((message) => message.className.includes("alert-info"))
                .map((message) => message.text),
            { message: "a saved realm must be confirmed to the user", timeout: 30_000 }
        ).toContain(bundle.config.messages.AppMessages.changesSaved);

        // It reached the server ...
        expect((await readRealm(adminToken, request, path)).active,
            "the edit must have been written, not just reported").toBe(false);

        // ... and the console reads it back that way in both of the places it shows realm status: the
        // list, and the form on a fresh render of the route.
        await openRealmList(page);
        await expect(realmRow(page, path)).toContainText(bundle.common.form.inactive);

        await openRealmEditForm(page, path);
        await expect(page.locator(SEL.active)).not.toBeChecked();
    });

    test("a realm deleted from the edit form disappears from the console", async ({ page, request }) => {
        const { path } = await givenRealm(request);

        await openAdminConsole(page);
        await openRealmEditForm(page, path);

        await page.locator(SEL.delete).click();

        // Deletion is confirmed before it happens. The body is asserted only as far as the
        // substitution, because what follows it is the untranslated key described in the file header
        // — but asserting this much still says the dialog was given a message, which an empty one
        // would not.
        await expect(page.locator(SEL.dialogTitle))
            .toHaveText(`${bundle.common.form.confirm} ${bundle.common.form.delete}`);
        await expect(page.locator(SEL.dialogBody))
            .toContainText(bundle.console.common.confirmDeleteText.split("__type__")[0].trim());
        await page.locator(SEL.dialogConfirm).click();

        // The console returns the operator to the list, which no longer has the realm in it.
        await expect(page).toHaveURL(xuiUrl("#realms"));
        await page.locator(SEL.tableToggle).click();
        await expectRealmAbsent(page, path);

        expect(await readRealm(adminToken, request, path), "the realm must be gone from AM").toBeNull();
    });

    test("a realm deleted from the realm list disappears from the console", async ({ page, request }) => {
        const { name, path } = await givenRealm(request);

        await openAdminConsole(page);
        await openRealmList(page);
        await expect(realmRow(page, path), "precondition: the realm is listed").toHaveCount(1);

        await realmRow(page, path).locator("[data-delete-realm]").click();

        // The second place the console deletes a realm from, and a different one: ListRealmsView
        // builds its own dialog, names the realm in the title, and offers deactivation as a third way
        // out that the edit form's confirmation does not.
        await expect(page.locator(SEL.dialogTitle))
            .toHaveText(bundle.console.realms.warningDialog.title.replace("__realmName__", name));
        await expect(page.locator(SEL.dialogButtons)).toHaveText([
            bundle.common.form.cancel,
            bundle.common.form.deactivate,
            bundle.common.form.delete,
        ]);
        await page.locator(SEL.dialogConfirm).click();

        // No routing this time: the list re-renders in place.
        await expectRealmAbsent(page, path);

        expect(await readRealm(adminToken, request, path), "the realm must be gone from AM").toBeNull();
    });

    test("the top level realm cannot be deleted or deactivated", async ({ page }) => {
        await openAdminConsole(page);
        await openRealmList(page);

        // The table view only. The card view guards the same two actions by a weaker mechanism — the
        // <li> is given a "disabled" class while the anchor stays clickable, and ListRealmsView's
        // handler is what actually refuses — so a migration could break that path without failing
        // here. Covering it would mean asserting on a non-disabled control, which is worth doing
        // deliberately rather than folding into this test.
        const topLevel = realmRow(page, TOP_LEVEL_REALM);
        // The console labels it rather than naming it: ListRealmsView substitutes its own title for
        // the "/" that AM returns.
        await expect(topLevel).toContainText(bundle.console.common.topLevelRealm);
        await expect(topLevel.locator("[data-delete-realm]")).toBeDisabled();
        await expect(topLevel.locator("[data-toggle-realm]")).toBeDisabled();

        await openRealmEditForm(page, TOP_LEVEL_REALM);

        // Neither of the two routes to deleting a realm offers it here, and neither does the one that
        // would achieve the same thing slowly: an inactive top level realm locks out every
        // administrator, so the console fixes `active` as well.
        await expect(page.locator(SEL.delete)).toBeDisabled();
        await expect(page.locator(SEL.active)).toBeDisabled();
        await expect(page.locator(SEL.active)).toBeChecked();
    });
});
