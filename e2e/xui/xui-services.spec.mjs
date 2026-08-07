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
 * OpenAM XUI — service administration: adding, editing and removing a realm's services through the
 * console.
 *
 * The second admin spec, and the one that drives the console's most heavily generated screens.
 * xui-realms.spec.mjs already proves a schema-generated form works; the realm form is generated from
 * one fixed schema, whereas this one is generated from whichever of 19 schemas the operator picks,
 * on a form that has to be torn down and rebuilt when they change their mind.
 *
 * What this is guarding, beyond "service CRUD works":
 *
 *   - a form whose *shape* is chosen at runtime. NewServiceView fetches ?_action=schema and
 *     ?_action=template for the selected type and hands them to json-editor, which builds the
 *     inputs; the type selector itself is filled from ?_action=getCreatableTypes. So a break
 *     anywhere in that chain surfaces here as a form with no fields rather than as a failed request.
 *     This is the machinery design.md D15 says the local API server's capture exists to reproduce,
 *     and task 2.11 is scoped to serve — "serve the SMS schema and template responses the console
 *     generates its forms from" is this screen;
 *   - selectize decorating a <select> (task 5.3, one of the 20+ shimmed non-AMD libraries), on the
 *     control that decides what the rest of the form is. The realm form exercises selectize as a
 *     tag editor; here it is a single-select whose change event drives a re-render;
 *   - view modules resolved by string identifier and loaded on demand (D1). ServicesView,
 *     NewServiceView and EditServiceView are loaded by no other spec, and EditServiceView reaches
 *     the shared EditSchemaComponent that every other per-service admin screen is built from;
 *   - the three separate routes to deleting a service, which do not share an implementation — see
 *     below.
 *
 * The service type under test is `baseurl` (Base URL Source), chosen because it is inert. Its
 * `source` property decides where AM derives a base URL from and defaults to REQUEST_VALUES, which
 * is what a realm with no such service does anyway; the `fixedValue` these tests write is only
 * consulted when `source` is FIXED_VALUE, which the create form never sets. So every test here
 * writes a service that changes nothing about how the instance behaves, in a scratch realm that is
 * deleted afterwards. It is also the type with the smallest form — two visible inputs — and, as it
 * happens, the flat-form case (see the sub-schema note below).
 *
 * Three things behave differently here from the realm console, and each is a place a migration
 * could quietly change behaviour:
 *
 *   - `showOnlyRequiredAndEmpty`. NewServiceView passes it, so json-editor builds every property but
 *     shows only those that are required *and* empty in the template, and JSONEditorView.getData()
 *     sends only those. `root[contextPath]` and `root[source]` are therefore in the create form's
 *     DOM, invisible, and absent from the request — a spec that tried to fill either would fail the
 *     actionability check rather than the assertion. The edit form is built without the flag and
 *     shows all four. The create test asserts the request body's keys for exactly this reason;
 *   - three delete routes, two dialog texts. The list's per-row button and its checkbox-plus-bulk
 *     button both re-render the list in place and post no message; the edit form's button routes
 *     back to the list and posts "Changes saved". The two list routes use
 *     console.services.list.confirmDeleteSelected and the edit form uses
 *     console.common.confirmDeleteSelected — different keys, and only one of them mentions services;
 *   - success is silent on three of the five write paths. Only save and delete-from-the-edit-form
 *     say anything. A created service is confirmed by the console routing to its edit form, and a
 *     deleted one by its row leaving the list — which is why those are asserted as the outcome
 *     rather than as scenery.
 *
 * Sub-schemas (secondary configurations) are deliberately NOT covered, here or anywhere else in
 * phase 0a — there is no later task holding them, so this is a scope decision rather than a
 * deferral, and the reasoning belongs here where the next reader will look for it. A service type
 * with sub-schema types grows two further routes served by two further view modules,
 * NewServiceSubSchemaView and EditServiceSubSchemaView. None of that is reachable from `baseurl`,
 * which has none: of the 19 types a realm can be given, `audit` is the only one with any, so
 * covering sub-schemas means introducing a second service type purely as a vehicle — and `audit`'s
 * sub-schemas are log handlers that start writing files or opening connections when created, which
 * is a different risk profile from anything here. If the migration is to be tested against them,
 * that wants its own task and its own instance to break.
 *
 * The edit test below asserts the tab bar is absent, so the boundary is pinned rather than merely
 * assumed. Note that the tab bar is not a sub-schema tell on its own: EditSchemaComponent.createTabs
 * builds tabs either from a non-empty getSubSchemaTypes() or from schema.isCollection(), and only
 * the flat case renders the .panel-footer that SEL.save lives in. So `baseurl` staying flat is
 * doubly pinned, and the day it stops being either flat or sub-schema-free, both fail and say so.
 *
 * Idempotency, which matters more here than in the realm spec: getCreatableTypes only offers types
 * the realm does not already have, so a service left behind by a failed run does not just pollute a
 * listing — it removes the option the create test clicks, and makes that test fail on its second
 * run having passed on its first. The fix is structural rather than a cleanup step: every test gets
 * its own realm, created over REST and registered for teardown before it exists, and a realm can be
 * deleted with services still configured in it. No test shares a realm with another or with a
 * previous run, so none can be affected by one.
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
import { creatableServiceTypes, createService, readService } from "../common/services-commons.mjs";

/** The type under test. See the file header for why this one. */
const SERVICE_TYPE = "baseurl";

/** RFC 6761 reserves .invalid, so nothing written below can resolve to anything. */
const CREATED_VALUE = "https://created.example.invalid";
const EDITED_VALUE = "https://edited.example.invalid";

const SEL = {
    // The list.
    row: (type) => `tr[data-service-id="${type}"]`,
    // A row links to the edit form twice — from the service's name, and from an Edit action drawn
    // as a button beside the delete one. The name is the one that carries the text.
    rowLink: "td a:not(.btn-link)",
    rowDelete: "[data-delete-service]",
    rowSelect: "[data-select-service]",
    addService: "button[data-add-service]",
    bulkDelete: "button[data-delete-services]",

    // The create form's type selector. The native <select> is hidden and selectize's control stands
    // in for it, so the click target and the value live on different elements — the assertions read
    // the select, because that is what NewServiceView's change handler reads.
    //
    // All four are scoped to the selector's own form group, because the schema's `source` property
    // is a second selectize on this page once a type has been chosen. Unscoped they are unambiguous
    // only before that, which was true while nothing re-opened the selector after choosing — the
    // rebuild test below does exactly that.
    typeSelect: "select[data-service-selection]",
    typeControl: ".form-group:has(select[data-service-selection]) .selectize-input",
    typeOption: (type) =>
        `.form-group:has(select[data-service-selection]) .selectize-dropdown-content .option[data-value="${type}"]`,
    typeOptions: ".form-group:has(select[data-service-selection]) .selectize-dropdown-content .option",
    typeItem: ".form-group:has(select[data-service-selection]) .selectize-input .item",
    typeLabel: "label[for=\"serviceSelection\"]",
    create: "[data-create]",
    // Where NewServiceView appends the generated form, and so the only part of the create screen
    // that changes when the chosen type does.
    jsonForm: "[data-json-form]",

    // The generated fields, by the names json-editor derives from the schema. Not by
    // [data-schemapath]: the edit form's payload carries _id and _type, so [data-schemapath="root._id"]
    // matches three elements there and the family of selectors is not strict-mode safe.
    fixedValue: "input[name=\"root[fixedValue]\"]",
    extensionClassName: "input[name=\"root[extensionClassName]\"]",
    contextPath: "input[name=\"root[contextPath]\"]",

    // The edit form. Both actions are unique on the page, but they are qualified by where they are
    // rendered, which is the thing that distinguishes this layout from the create form's.
    title: "#content h1",
    pageType: "#content h4.page-type",
    save: "#content .panel-footer [data-save]",
    delete: "#content header [data-delete]",
    tabs: "#content .nav-tabs",

    dialogTitle: ".bootstrap-dialog .bootstrap-dialog-title",
    dialogBody: ".bootstrap-dialog .bootstrap-dialog-message",
    dialogConfirm: ".bootstrap-dialog .modal-footer button.btn-danger",
    dialogCancel: ".bootstrap-dialog .modal-footer button.btn-default",
    dialog: ".bootstrap-dialog",
};

/**
 * Valid against both backends. Service read and CRUD, and the SMS schema and template payloads the
 * forms are generated from, are what design.md tasks 2.11 commits the local API server to. Nothing
 * here asserts AM-specific server behaviour — contrast xui-httponly.spec.mjs, which is
 * deployed-AM-only under D16 because reproducing what it asserts would mean reimplementing it.
 *
 * One dependency worth naming for task 2.1's request enumeration, because it is not obviously part
 * of service administration: the create form's type selector is filled by
 * POST /json/realm-config/services?_action=getCreatableTypes&forUI=true, whose answer depends on
 * what the realm already contains. A local server that returned a fixed list would pass the create
 * test and fail the one below it.
 */
test.describe("XUI service administration (create, edit, delete)", {
    tag: ["@deployed-am", "@local-server"],
}, () => {
    /** The oracle for every string the console renders below. */
    let bundle;
    let adminToken;
    /** The display name AM gives SERVICE_TYPE, which is what the console renders for it. */
    let serviceTypeName;

    /**
     * Realm paths this test caused to exist. Registered before the realm is created, so a test that
     * fails halfway still cleans up after itself — and here that is what keeps the next run
     * identical to this one, since a leftover service changes what the create form offers.
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
        // ordering means something. Every removal is attempted even if an earlier one fails, since
        // the alternative is that one failure leaks every realm behind it — and with it every
        // service in them — into the next run.
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

    /**
     * A realm of this test's own, with nothing configured in it beyond what a new realm gets.
     *
     * Every test calls this rather than sharing one: see the idempotency note in the file header.
     * The realm is registered for teardown before it is created, not after.
     */
    async function givenRealm (request) {
        const name = uniqueRealmName("e2e-svc");
        const path = realmPathOf(name, TOP_LEVEL_REALM);

        scratchRealms.push(path);
        await createRealm(adminToken, request, { name });

        // Resolved once, and from a realm that cannot already have the type. The console renders
        // AM's display name for a service type rather than its id, so asserting against a literal
        // would pin this spec's idea of the name instead of the instance's — and doing it here also
        // makes "a fresh realm may be given this service" a checked premise rather than an
        // assumption the create test would fail on obscurely.
        if (!serviceTypeName) {
            const offered = await creatableServiceTypes(adminToken, request, path);
            const type = offered.find((candidate) => candidate._id === SERVICE_TYPE);

            expect(type, `a fresh realm must be able to be given the "${SERVICE_TYPE}" service`)
                .toBeTruthy();
            serviceTypeName = type.name;
        }
        return { name, path };
    }

    /** A realm that already has the service under test, for the tests about editing or deleting one. */
    async function givenRealmWithService (request) {
        const realm = await givenRealm(request);

        await createService(adminToken, request, realm.path, SERVICE_TYPE, {
            fixedValue: CREATED_VALUE,
            extensionClassName: "",
        });
        return realm;
    }

    /**
     * Show a realm's service list.
     *
     * The wait is on the row a new realm always has rather than on the table: ServicesView renders
     * its container first and fills it from a separate template fetch, so "the row I am looking for
     * is absent" is equally true of a list that never rendered — including the failure this suite
     * most wants to catch, a template that stopped being served (D3). policyconfiguration is the
     * anchor because a realm is created with it and the console offers no way to remove it; if a
     * future AM stops seeding it, this is the line that says so rather than a confusing absence
     * failure elsewhere.
     */
    async function openServiceList (page, realmPath) {
        await page.goto(xuiUrl(realmHash(realmPath, "services")));
        await expect(page.locator(SEL.row("policyconfiguration")),
            "the service list must have rendered").toHaveCount(1);
    }

    /**
     * Open the create form and wait until its type selector is ready.
     *
     * Reached through the list's own button rather than by URL, because that button is the only
     * thing that proves the list links to the form.
     */
    async function openCreateForm (page, realmPath) {
        await page.locator(SEL.addService).click();
        await expect(page).toHaveURL(xuiUrl(`${realmHash(realmPath, "services")}/new`));
        await expect(page.locator(SEL.typeControl)).toBeVisible();
    }

    /**
     * Choose a type on the create form and wait for the fields it implies.
     *
     * selectize hides the <select> and answers clicks on a <div> of its own, so selectOption() has
     * nothing to act on here; clicking the option is what makes selectize write the value back onto
     * the native select and fire the change event NewServiceView listens for.
     */
    async function chooseServiceType (page, type) {
        await page.locator(SEL.typeControl).click();
        await page.locator(SEL.typeOption(type)).click();

        await expect(page.locator(SEL.typeSelect)).toHaveValue(type);
        await expect(page.locator(SEL.fixedValue)).toBeVisible();
    }

    /**
     * Open a service's edit form and wait until it has been generated.
     *
     * The wait is on the delete action rather than on a field, and that is not incidental: the
     * generated inputs have the same names on both forms, so waiting for one of those after leaving
     * the create form is satisfied by the create form still on screen, and the assertions that
     * follow run against the wrong view. [data-delete] exists only here.
     *
     * `timeout` is for the callers that wait through a cold start rather than a route change; left
     * undefined it takes the config's default, which is what an in-console navigation needs.
     */
    async function awaitEditForm (page, timeout) {
        await expect(page.locator(SEL.delete)).toBeVisible({ timeout });
        await expect(page.locator(SEL.fixedValue)).toBeVisible({ timeout });
    }

    async function openServiceEditForm (page, realmPath, type) {
        await page.goto(xuiUrl(`${realmHash(realmPath, "services")}/edit/${type}`));
        await awaitEditForm(page);
    }

    test("a service created through the console appears in the service list", async ({ page, request }) => {
        const { path } = await givenRealm(request);

        // What the console sent, recorded from before the form is opened. The create form shows two
        // of this schema's four properties and must send exactly those two — the other two are in
        // the DOM but hidden, and JSONEditorView.getData() filters them out. That filtering is the
        // behaviour being pinned; a migration that lost it would send a contextPath the operator
        // never saw and could not have chosen.
        const createBodies = [];
        page.on("request", (req) => {
            if (req.method() === "POST" && req.url().includes("_action=create")
                && req.url().includes(`/realm-config/services/${SERVICE_TYPE}`)) {
                createBodies.push(req.postDataJSON());
            }
        });

        await openAdminConsole(page);
        await openServiceList(page, path);
        await expect(page.locator(SEL.row(SERVICE_TYPE)),
            "precondition: the realm does not have this service yet").toHaveCount(0);

        await openCreateForm(page, path);
        await expect(page.locator(SEL.title)).toHaveText(bundle.console.services.edit.titleNew);
        await expect(page.locator(SEL.typeLabel)).toHaveText(bundle.console.services.edit.chooseServiceType);
        // Nothing can be created until a type is chosen, so the form opens with the action refused.
        await expect(page.locator(SEL.create)).toBeDisabled();

        await chooseServiceType(page, SERVICE_TYPE);
        await expect(page.locator(SEL.typeItem)).toHaveText(serviceTypeName);
        // Released only once json-editor has finished building the form it will read.
        await expect(page.locator(SEL.create)).toBeEnabled();

        // The other half of showOnlyRequiredAndEmpty, and the half the request body cannot show:
        // the withheld properties are *built and hidden*, not skipped. A migration in which
        // json-editor stopped building the non-default editors at all would send the same two keys
        // and leave every other assertion in this file green.
        await expect(page.locator(SEL.contextPath),
            "the withheld properties must be built, not skipped").toHaveCount(1);
        await expect(page.locator(SEL.contextPath)).toBeHidden();

        await page.fill(SEL.fixedValue, CREATED_VALUE);
        await page.locator(SEL.create).click();

        // The console sends a created service to its own edit form. Landing there is what says the
        // create resolved, rather than merely having been posted — nothing is added to #messages.
        await expect(page).toHaveURL(xuiUrl(`${realmHash(path, "services")}/edit/${SERVICE_TYPE}`));
        await awaitEditForm(page);

        expect(createBodies, "the console must have created the service once").toHaveLength(1);
        expect(Object.keys(createBodies[0]).sort(),
            "only the properties the form showed may be sent").toEqual(["extensionClassName", "fixedValue"]);

        // It reached the server, with what the form was given ...
        const created = await readService(adminToken, request, path, SERVICE_TYPE);
        expect(created, "the console must have created the service").not.toBeNull();
        expect(created.fixedValue).toBe(CREATED_VALUE);
        // ... and AM supplied the two the form withheld, which is what makes this service inert:
        // REQUEST_VALUES is how a realm with no baseurl service behaves.
        expect(created.source, "the created service must not change how AM derives a base URL")
            .toBe("REQUEST_VALUES");

        // ... and the list the console renders next is built from a fresh read, so it is there too.
        await openServiceList(page, path);
        await expect(page.locator(SEL.row(SERVICE_TYPE))).toContainText(serviceTypeName);
        await expect(page.locator(`${SEL.row(SERVICE_TYPE)} ${SEL.rowLink}`))
            .toHaveAttribute("href", `${realmHash(path, "services")}/edit/${SERVICE_TYPE}`);
    });

    test("changing the chosen type rebuilds the create form", async ({ page, request }) => {
        const { path } = await givenRealm(request);

        // Any second type will do — what is under test is the swap, not the schema — so it comes
        // from AM's own answer rather than being named here, and nothing below mentions its fields.
        const offered = await creatableServiceTypes(adminToken, request, path);
        const otherType = offered.find((candidate) => candidate._id !== SERVICE_TYPE);
        expect(otherType, "changing our mind needs a second type on offer").toBeTruthy();

        await openAdminConsole(page);
        await openServiceList(page, path);
        await openCreateForm(page, path);
        await chooseServiceType(page, SERVICE_TYPE);

        // NewServiceView.selectService disables create, tears the old form down, and builds the new
        // one in its place. Only the end state is asserted: the disabled moment lasts exactly as
        // long as the schema and template requests, so whether it can be observed at all depends on
        // how warm AM's caches are — it is real behaviour, but it is not a fact a test can hold.
        await page.locator(SEL.typeControl).click();
        await page.locator(SEL.typeOption(otherType._id)).click();
        await expect(page.locator(SEL.typeSelect)).toHaveValue(otherType._id);

        // The old schema's inputs are gone rather than covered up. This is the jsonSchemaView.remove()
        // that a migration touching view teardown would break, and the shape of that break is two
        // forms stacked on one page — which would leave every other test in this file green, since
        // they only ever assert about the form they asked for.
        await expect(page.locator(SEL.fixedValue),
            "the abandoned type's form must have been torn down").toHaveCount(0);

        // ... and something was built in its place. Attached rather than visible, and that is not a
        // weakened assertion but the same showOnlyRequiredAndEmpty rule seen from the other side: a
        // type with no required-and-empty properties renders a form that is entirely hidden. Which
        // is why what follows is asserted generically — the point is that the swap happened, not
        // what the second schema contains.
        await expect(page.locator(SEL.jsonForm).locator(".form-group").first(),
            "the newly chosen type must have produced a form").toBeAttached();
        // Create being enabled is the app's own account of the rebuild having finished:
        // selectService re-enables only from the new form's onRendered callback, and leaves it
        // disabled if fetching the schema failed.
        await expect(page.locator(SEL.create)).toBeEnabled();

        // And changing our mind back rebuilds the original — once, not beside what it replaced.
        await chooseServiceType(page, SERVICE_TYPE);
        await expect(page.locator(SEL.fixedValue)).toHaveCount(1);
    });

    test("the create form stops offering a type the realm already has", async ({ page, request }) => {
        // The console's rule, and the one this spec's own structure depends on: a realm may have at
        // most one service of a type, and the create form is built from what the realm does not yet
        // have. Asserted against AM's own answer as well as the rendered options, so a console that
        // stopped filtering and a server that stopped filtering are distinguishable.
        const { path } = await givenRealmWithService(request);

        const offered = await creatableServiceTypes(adminToken, request, path);
        expect(offered.map((type) => type._id),
            "AM must not offer a type the realm already has").not.toContain(SERVICE_TYPE);
        expect(offered.length, "the other types must still be on offer").toBeGreaterThan(0);

        await openAdminConsole(page);
        await openServiceList(page, path);
        await openCreateForm(page, path);

        await page.locator(SEL.typeControl).click();
        // The dropdown is populated, and this type is the one thing missing from it. The count is
        // AM's list exactly: the template also renders a disabled empty-value placeholder option,
        // which selectize drops rather than offering.
        await expect(page.locator(SEL.typeOptions),
            "the dropdown must offer every type AM still allows, and no others")
            .toHaveCount(offered.length);
        await expect(page.locator(SEL.typeOption(SERVICE_TYPE))).toHaveCount(0);
    });

    test("an edit made in the console persists", async ({ page, request }) => {
        const { path } = await givenRealmWithService(request);

        await openAdminConsole(page);
        await openServiceEditForm(page, path, SERVICE_TYPE);

        // The edit form is the same component with the opposite setting: no showOnlyRequiredAndEmpty,
        // so the two properties the create form withheld are editable here. Asserted because it is
        // the difference between the two screens, and a migration that lost the flag would make the
        // create form look like this one.
        await expect(page.locator(SEL.title)).toHaveText(serviceTypeName);
        await expect(page.locator(SEL.pageType)).toHaveText(bundle.console.services.edit.title);
        await expect(page.locator(SEL.fixedValue)).toHaveValue(CREATED_VALUE);
        await expect(page.locator(SEL.contextPath)).toBeVisible();
        await expect(page.locator(SEL.extensionClassName)).toBeVisible();
        // The scope boundary described in the file header, pinned: no sub-schema types means no tab
        // bar, and this whole spec is written for the flat form.
        await expect(page.locator(SEL.tabs),
            "baseurl is flat and sub-schema-free, so the edit form must be a single panel")
            .toHaveCount(0);

        const messages = await captureMessages(page);
        await page.fill(SEL.fixedValue, EDITED_VALUE);
        await page.locator(SEL.save).click();

        // The console reports the save itself — AM answers a service PUT with the service and no
        // message, so this string is the UI's own. Recorded rather than polled for, because the
        // alert removes itself after a few seconds.
        await expect.poll(
            async () => (await messages())
                .filter((message) => message.className.includes("alert-info"))
                .map((message) => message.text),
            { message: "a saved service must be confirmed to the user", timeout: 30_000 }
        ).toContain(bundle.config.messages.AppMessages.changesSaved);

        // Saving does not route anywhere; the operator is left on the form they saved.
        await expect(page).toHaveURL(xuiUrl(`${realmHash(path, "services")}/edit/${SERVICE_TYPE}`));

        // It reached the server ...
        expect((await readService(adminToken, request, path, SERVICE_TYPE)).fixedValue,
            "the edit must have been written, not just reported").toBe(EDITED_VALUE);

        // ... and it survives the console being rebuilt around it. A reload rather than a second
        // goto: Backbone does not re-fire a route for the hash it is already on, so navigating to
        // this one would be a no-op and would assert against the form still on screen.
        // A cold start, not a route change: this re-fetches the whole unbundled dependency closure,
        // so it gets the budget xui-commons gives its own boot waits rather than the assertion
        // default. With retries at 0 this is the difference between a slow run and a red one.
        await page.reload();
        await awaitEditForm(page, 30_000);
        await expect(page.locator(SEL.fixedValue)).toHaveValue(EDITED_VALUE);
    });

    test("a service deleted from the edit form disappears from the console", async ({ page, request }) => {
        const { path } = await givenRealmWithService(request);

        await openAdminConsole(page);
        await openServiceEditForm(page, path, SERVICE_TYPE);

        const messages = await captureMessages(page);
        await page.locator(SEL.delete).click();

        // Deletion is confirmed before it happens. This route uses the generic key rather than the
        // list's service-specific one, which is why the two delete tests assert different strings.
        await expect(page.locator(SEL.dialogTitle))
            .toHaveText(`${bundle.common.form.confirm} ${bundle.common.form.delete}`);
        await expect(page.locator(SEL.dialogBody))
            .toHaveText(bundle.console.common.confirmDeleteSelected);
        await page.locator(SEL.dialogConfirm).click();

        // The only delete route that says anything, and the only one that routes: the operator is
        // returned to the list, which no longer has the service in it.
        await expect(page).toHaveURL(xuiUrl(realmHash(path, "services")));
        await expect(page.locator(SEL.row("policyconfiguration")),
            "the service list must have rendered").toHaveCount(1);
        await expect(page.locator(SEL.row(SERVICE_TYPE))).toHaveCount(0);

        await expect.poll(
            async () => (await messages())
                .filter((message) => message.className.includes("alert-info"))
                .map((message) => message.text),
            { message: "a deleted service must be confirmed to the user", timeout: 30_000 }
        ).toContain(bundle.config.messages.AppMessages.changesSaved);

        expect(await readService(adminToken, request, path, SERVICE_TYPE),
            "the service must be gone from AM").toBeNull();
    });

    test("a service deleted from the service list disappears from the console", async ({ page, request }) => {
        const { path } = await givenRealmWithService(request);

        await openAdminConsole(page);
        await openServiceList(page, path);
        await expect(page.locator(SEL.row(SERVICE_TYPE)),
            "precondition: the realm has the service").toHaveCount(1);

        // The confirmation is a gate rather than a formality, so this test declines once before it
        // agrees. A dialog that deleted on cancel would otherwise pass every other assertion here.
        await page.locator(`${SEL.row(SERVICE_TYPE)} ${SEL.rowDelete}`).click();
        await expect(page.locator(SEL.dialogTitle))
            .toHaveText(`${bundle.common.form.confirm} ${bundle.common.form.delete}`);
        await expect(page.locator(SEL.dialogBody))
            .toHaveText(bundle.console.services.list.confirmDeleteSelected);
        await page.locator(SEL.dialogCancel).click();
        await expect(page.locator(SEL.dialog)).toHaveCount(0);

        await expect(page.locator(SEL.row(SERVICE_TYPE)),
            "cancelling must leave the service alone").toHaveCount(1);
        expect(await readService(adminToken, request, path, SERVICE_TYPE),
            "cancelling must not have deleted anything").not.toBeNull();

        await page.locator(`${SEL.row(SERVICE_TYPE)} ${SEL.rowDelete}`).click();
        await page.locator(SEL.dialogConfirm).click();

        // No routing and no message on this route: the list re-renders in place, and the row going
        // away is the whole of the feedback the operator gets.
        await expect(page.locator(SEL.row(SERVICE_TYPE))).toHaveCount(0);
        await expect(page.locator(SEL.row("policyconfiguration")),
            "the list must have re-rendered rather than emptied").toHaveCount(1);
        await expect(page).toHaveURL(xuiUrl(realmHash(path, "services")));

        expect(await readService(adminToken, request, path, SERVICE_TYPE),
            "the service must be gone from AM").toBeNull();
    });

    test("a service selected in the list can be deleted with the toolbar", async ({ page, request }) => {
        const { path } = await givenRealmWithService(request);

        await openAdminConsole(page);
        await openServiceList(page, path);

        // The third delete route, and the only one that is not a single click: the toolbar acts on
        // whatever is checked, so it is refused until something is.
        await expect(page.locator(SEL.bulkDelete)).toBeDisabled();
        await page.locator(`${SEL.row(SERVICE_TYPE)} ${SEL.rowSelect}`).check();
        await expect(page.locator(SEL.bulkDelete)).toBeEnabled();
        // ServicesView marks the row as well as enabling the button, so the operator can see what
        // the toolbar would act on.
        await expect(page.locator(SEL.row(SERVICE_TYPE))).toHaveClass(/selected/);

        await page.locator(SEL.bulkDelete).click();

        // One service selected, so i18next resolves the singular of the same key the per-row button
        // uses. The plural form exists and is not asserted here: a realm can only ever hold one
        // service of a type, so reaching it means selecting two different types, which is a case
        // about the toolbar rather than about service CRUD.
        await expect(page.locator(SEL.dialogTitle))
            .toHaveText(`${bundle.common.form.confirm} ${bundle.common.form.delete}`);
        await expect(page.locator(SEL.dialogBody))
            .toHaveText(bundle.console.services.list.confirmDeleteSelected);
        await page.locator(SEL.dialogConfirm).click();

        await expect(page.locator(SEL.row(SERVICE_TYPE))).toHaveCount(0);
        await expect(page.locator(SEL.row("policyconfiguration")),
            "the list must have re-rendered rather than emptied").toHaveCount(1);
        // And the toolbar has forgotten the selection along with the row it belonged to.
        await expect(page.locator(SEL.bulkDelete)).toBeDisabled();

        expect(await readService(adminToken, request, path, SERVICE_TYPE),
            "the service must be gone from AM").toBeNull();
    });
});
