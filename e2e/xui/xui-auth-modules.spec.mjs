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
 * OpenAM XUI — authentication module administration: creating, editing and removing a realm's
 * authentication module instances through the console.
 *
 * The third admin spec, and the one that pins a form generated per *type* rather than per screen.
 * xui-services.spec.mjs already drives a schema-generated form, so what is new here is not that a
 * schema becomes inputs — it is that the same view produces visibly different forms for different
 * types, and that the two types below were chosen so that difference is observable rather than
 * asserted on faith.
 *
 * Where the generated form actually is, which is not where task 1.14's wording suggests:
 *
 *   the create form is hand-written. AddModuleView renders a name field and a type selector from
 *   AddModuleTemplate.html, fetches no schema, and posts `{_id}` and nothing else. The per-type form
 *   generated from ?_action=schema is the *edit* form — the console creates an instance from the
 *   type's template and then hands the operator the generated form to configure it. That is the
 *   opposite of NewServiceView, which generates the create form and needs no second step, and it is
 *   why the create tests below assert the request body's keys: a migration in which the create form
 *   started sending configuration would change what a created module is, silently.
 *
 * What this is guarding, beyond "module CRUD works":
 *
 *   - a form whose shape is chosen by the instance's type. EditModuleView.jsm fetches ?_action=schema
 *     for the type in the route and hands the result to models/Form.js, which builds a raw
 *     json-editor from it. Form has no equivalent of the create form's showOnlyRequiredAndEmpty — it
 *     is not an option Form takes — so every property is rendered and visible. The edit tests assert
 *     the rendered field names against the schema AM served rather than against a list copied into
 *     this file, so a form that was generated and a form that merely looks like one are
 *     distinguishable;
 *   - selectize on a generated enum. `httpbasic` is here for this: its backendModuleName renders as a
 *     hidden native <select> decorated by selectize through JSONEditor.plugins.selectize
 *     (models/Form.js:39), which is a shimmed non-AMD library and so task 5.3's problem. `securid` is
 *     the control — same size of schema, two plain text inputs, no third-party widget at all. Running
 *     the same tests over both is what makes "the form is generated per type" a checked claim;
 *   - view modules resolved by string identifier and loaded on demand (D1). ModulesView,
 *     AddModuleView and EditModuleView are loaded by no other spec;
 *   - the two delete routes, which do not share an implementation and are both silent. The edit form
 *     has no delete action at all — unlike the service console, deleting is list-only.
 *
 * The types under test are `securid` and `httpbasic`, both chosen because they are inert. Neither is
 * referenced by a chain when created, and a module instance no chain references does not participate
 * in authentication: verified by snapshotting the root and scratch realms' modules, chains and
 * realm-config/authentication, and the callbacks POST /json/authenticate offers for both realms,
 * before and after creating instances of both types — every one identical. An unreferenced instance
 * is reachable as an explicit `&module=<name>` index, which a caller must ask for by name; it alters
 * no default, no chain and no existing flow, and the realm holding it is deleted afterwards. The
 * candidates rejected on this ground are recorded in NOTES-auth-modules.md — `anonymous` has the
 * widest spread of widgets of any small type and would have been the better second choice on every
 * criterion except that an Anonymous module is the one candidate where an accidental chain reference
 * means credential-free login.
 *
 * Nothing here touches the root realm's authentication configuration, and nothing touches any realm's
 * adminAuthModule or orgConfig: the console's admin session authenticates against the root realm —
 * idFromSession answers "/" for amadmin — so a sub-realm's authentication configuration cannot lock
 * the console out, and that is what makes a scratch sub-realm a safe place to do this.
 *
 * Idempotency, which inverts the service spec's rule rather than repeating it: getAllTypes is
 * unfiltered, so unlike getCreatableTypes it keeps offering a type however many instances of it a
 * realm already has. A module left behind by a failed run therefore does not change what the create
 * form offers — modules are named instances, and it collides on the *name*. The last test asserts
 * exactly that, including that the console refuses the name across all types while AM itself would
 * allow the same name under a different type. The structural fix is the same as the service spec's
 * and is what makes fixed instance names safe here: every test gets its own realm, created over REST
 * and registered for teardown before it exists, and a realm deletes cleanly with modules still
 * configured in it.
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
    createModule,
    moduleExists,
    moduleSchema,
    moduleTypes,
    readModule,
} from "../common/auth-commons.mjs";

/**
 * A module every realm is seeded with, used as the "the list rendered" anchor.
 *
 * The same reasoning as policyconfiguration in the service spec: ModulesView renders its container
 * before filling it from a separate template fetch, so "the row I am looking for is absent" is
 * equally true of a list that never rendered — including the failure this suite most wants to catch,
 * a template that stopped being served (D3). DataStore is an instance of the `datastore` type that a
 * new realm is created with; if a future AM stops seeding it, this is the line that says so.
 */
const STOCK_MODULE = "DataStore";

/**
 * What the securid edit test writes to serverConfigPath.
 *
 * Nothing reads it: serverConfigPath is consulted when the module authenticates, and no chain
 * references the instance this is written to — which is the same reason the whole spec is inert. The
 * realm is deleted afterwards either way.
 */
const EDITED_CONFIG_PATH = "/tmp/e2e-securid-config";

const SEL = {
    // The list. Rows are scoped with tr because the create form's name input also carries
    // [data-module-name], and the two screens are reachable one click apart.
    row: (name) => `tr[data-module-name="${name}"]`,
    rowDelete: "[data-delete-module]",
    rowSelect: "[data-select-module]",
    // An <a> with no data attribute, unlike the service list's button[data-add-service].
    addModule: ".page-toolbar a.btn-primary",
    bulkDelete: "[data-delete-modules]",

    // The create form. Both fields are hand-written — there is no json-editor on this screen, and so
    // nothing here is named root[...].
    newModuleName: "#newModuleName",
    typeControl: "[data-module-type] .selectize-input",
    typeDropdown: "[data-module-type] .selectize-dropdown-content",
    typeOptions: "[data-module-type] .selectize-dropdown-content .option",
    typeItem: "[data-module-type] .selectize-input .item",
    // "Create", but stamped [data-save] — not [data-create] as on the service create form. Scoped to
    // the footer it is rendered in, as the service spec scopes its own: a bare page-wide attribute
    // selector becomes a strict-mode violation the day any dialog or shared header carries a save
    // button, and it would surface as a flake in whichever test ran first rather than as a selector
    // problem. Both screens render exactly one, in a .panel-footer.
    create: "#content .panel-footer [data-save]",
    // Nothing on the create screen is json-editor-generated. Asserted, not just asserted about in
    // the header — see the create test.
    generatedInputsAnywhere: "#content [name^=\"root[\"]",

    // The edit form. Where models/Form.js builds the generated form, and the two actions beside it.
    title: "#content h1",
    subtitle: "#content h4.page-type",
    form: "#tabpanel",
    // Every generated input, by the names json-editor derives from the schema. Field *order* is not
    // stable across loads — the schema's properties come from an unordered JSON object, and securid
    // has been observed rendering in both orders — so nothing here may address a field by index.
    field: (property) => `input[name="root[${property}]"]`,
    select: (property) => `select[name="root[${property}]"]`,
    generatedInputs: "#tabpanel [name^=\"root[\"]",
    formSelectize: "#tabpanel .selectize-control",
    formSelectizeInput: "#tabpanel .selectize-input",
    formSelectizeDropdown: "#tabpanel .selectize-dropdown-content",
    // The same footer selector as the create form's button, for the same reason. It carries a second
    // benefit here: EditModuleViewTemplate renders the panel-footer only inside {{#if values}}, so
    // waiting on this distinguishes a generated form from the notFound error branch, which renders
    // an <h3> call-to-action and no footer at all.
    save: "#content .panel-footer [data-save]",
    // Deleting is list-only. There is no delete action on this form, unlike the service console's.
    delete: "#content [data-delete]",
    tabs: "#content .nav-tabs",

    dialog: ".bootstrap-dialog",
    dialogTitle: ".bootstrap-dialog .bootstrap-dialog-title",
    dialogBody: ".bootstrap-dialog .bootstrap-dialog-message",
    dialogConfirm: ".bootstrap-dialog .modal-footer button.btn-danger",
    dialogCancel: ".bootstrap-dialog .modal-footer button.btn-default",
};

/**
 * The members of a schema property's enum, with the premise the tests rely on checked.
 *
 * Used rather than naming the values, because the one enum under test is not a fixed list: see
 * httpbasic below.
 */
function enumOf (schema, property) {
    const values = schema.properties[property]?.enum;

    expect(values, `the ${property} schema must offer an enum`).toBeTruthy();
    expect(values.length,
        `${property} must offer at least two members for an edit to be able to change it`)
        .toBeGreaterThan(1);
    return values;
}

/**
 * The two types under test, and everything that differs between them.
 *
 * `created` is what AM stores for an instance created with nothing but a name, which is what the
 * console's create form posts — so it is also the assertion that the type's template was applied.
 *
 * `rendered` and `edited` are functions of the served schema rather than literals, which matters for
 * exactly one property. httpbasic's backendModuleName is a single_choice whose ChoiceValuesClassName
 * is ConfiguredModuleInstances (amAuthHTTPBasic.xml), so its enum is built from the realm's *own*
 * module instances when the schema is requested — a fresh realm happens to answer ["LDAP","DataStore"],
 * but that is seeding, not a contract. Naming those values here would pin the realm's seed order and
 * would state the wrong rule: what the rendered case is really asserting is that json-editor selects
 * an enum's *first* option when the stored value is null, so the form shows a value that was never
 * stored. Deriving both from the schema says that, and keeps a reseeded AM from reddening a correct
 * console.
 */
const MODULE_TYPES = [
    {
        id: "securid",
        instance: "e2eSecurid",
        selectizeControls: 0,
        // Fixed defaults from the type's own schema, not derived from anything in the realm.
        created: {
            serverConfigPath: "/usr/openam/config/openam/auth/ace/data",
            authenticationLevel: 0,
        },
        // A new instance renders exactly what was stored for it.
        rendered: (created) => created,
        edited: () => ({ serverConfigPath: EDITED_CONFIG_PATH, authenticationLevel: 7 }),
        async expectRendered (page, values) {
            await expect(page.locator(SEL.field("serverConfigPath")))
                .toHaveValue(values.serverConfigPath);
            await expect(page.locator(SEL.field("authenticationLevel")))
                .toHaveValue(String(values.authenticationLevel));
        },
        async edit (page, values) {
            await page.fill(SEL.field("serverConfigPath"), values.serverConfigPath);
            await page.fill(SEL.field("authenticationLevel"), String(values.authenticationLevel));
        },
    },
    {
        id: "httpbasic",
        instance: "e2eHttpBasic",
        selectizeControls: 1,
        created: { backendModuleName: null, authenticationLevel: 0 },
        // The form shows the enum's first member for a stored null — a value that was never stored.
        rendered: (created, schema) => ({
            ...created,
            backendModuleName: enumOf(schema, "backendModuleName")[0],
        }),
        // Any member that is not the one already displayed, so the save has something to change.
        edited: (schema) => ({
            backendModuleName: enumOf(schema, "backendModuleName")[1],
            authenticationLevel: 5,
        }),
        async expectRendered (page, values) {
            // Read the hidden native <select> rather than selectize's stand-in: the visible input
            // selectize builds has no name and no value, and the <select> is what Form.js reads.
            await expect(page.locator(SEL.select("backendModuleName")))
                .toHaveValue(values.backendModuleName);
            await expect(page.locator(SEL.field("authenticationLevel")))
                .toHaveValue(String(values.authenticationLevel));
        },
        async edit (page, values) {
            await page.locator(SEL.formSelectizeInput).click();
            await page.locator(SEL.formSelectizeDropdown)
                .getByText(values.backendModuleName, { exact: true }).click();
            await expect(page.locator(SEL.select("backendModuleName")))
                .toHaveValue(values.backendModuleName);
            await page.fill(SEL.field("authenticationLevel"), String(values.authenticationLevel));
        },
    },
];

/**
 * Deployed AM only, and deliberately not tagged @local-server.
 *
 * The /realm-config/authentication/* endpoints are outside the local API server's scope: design.md's
 * open question on how far its coverage should reach names them as deferred, and task 2.1 scopes the
 * server to the requests the phase-0 specs cause — which puts anything reached only by a
 * @deployed-am spec out of scope by construction. Under D16 that has to be declared rather than left
 * to a skip, so this spec says so here. If it later passes against the local server, that is a
 * decision to retag it, not a reason.
 */
test.describe("XUI authentication module administration (create, edit, delete)", {
    tag: ["@deployed-am"],
}, () => {
    /** The oracle for every string the console renders below. */
    let bundle;
    let adminToken;
    /** AM's display name for each type under test, which is what the console renders and offers. */
    const typeNames = new Map();

    /**
     * Realm paths this test caused to exist. Registered before the realm is created, so a test that
     * fails halfway still cleans up after itself.
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
        // alternative is that one failure leaks every realm behind it — and every module in them —
        // into the next run.
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
     * Every test calls this rather than sharing one, which is what makes the fixed instance names
     * above safe — see the idempotency note in the file header. The realm is registered for teardown
     * before it is created, not after.
     */
    async function givenRealm (request) {
        const name = uniqueRealmName("e2e-auth");
        const path = realmPathOf(name, TOP_LEVEL_REALM);

        scratchRealms.push(path);
        await createRealm(adminToken, request, { name });

        // Resolved once, from a fresh realm. The console offers AM's display name for a type rather
        // than its id — and the create form's options carry an array index in data-value rather than
        // the id, so the display name is the only thing a test can select by. Doing it here also
        // makes "a fresh realm may be given these types" a checked premise rather than an assumption
        // the create tests would fail on obscurely.
        if (!typeNames.size) {
            const offered = await moduleTypes(adminToken, request, path);
            const resolved = new Map();

            for (const { id } of MODULE_TYPES) {
                const type = offered.find((candidate) => candidate._id === id);

                expect(type, `a fresh realm must offer the "${id}" module type`).toBeTruthy();
                resolved.set(id, type.name);
            }

            // Published only once every lookup has succeeded. Assigning as we go would leave a
            // half-filled map behind when the second type is the missing one — and since the guard
            // above is on the map being empty, every later test would skip resolution and select a
            // type by `undefined`. That turns one clear failure into one clear failure and six
            // obscure ones, which is the opposite of why this resolution is here.
            for (const [id, displayName] of resolved) {
                typeNames.set(id, displayName);
            }
        }
        return { name, path };
    }

    /** A realm that already has an instance of `type`, for the tests about editing or deleting one. */
    async function givenRealmWithModule (request, type) {
        const realm = await givenRealm(request);

        // Created with a name and nothing else, exactly as the console's create form does, so the
        // edit and delete tests operate on the same thing a create would have left behind.
        await createModule(adminToken, request, realm.path, type.id, type.instance);
        return realm;
    }

    function moduleRoute (realmPath, fragment = "") {
        return `${realmHash(realmPath, "authentication-modules")}${fragment}`;
    }

    async function openModuleList (page, realmPath) {
        await page.goto(xuiUrl(moduleRoute(realmPath)));
        await expect(page.locator(SEL.row(STOCK_MODULE)),
            "the module list must have rendered").toHaveCount(1);
    }

    /**
     * Open the create form and wait until both of its controls are ready.
     *
     * Reached through the list's own control rather than by URL, because that link is the only thing
     * that proves the list leads to the form.
     */
    async function openCreateForm (page, realmPath) {
        await page.locator(SEL.addModule).click();
        await expect(page).toHaveURL(xuiUrl(moduleRoute(realmPath, "/new")));
        await expect(page.locator(SEL.newModuleName)).toBeVisible();
        await expect(page.locator(SEL.typeControl)).toBeVisible();
    }

    /**
     * Choose a type on the create form, by the name the operator sees.
     *
     * Not by value: SelectComponent stamps each option's data-value with selectize's internal key,
     * which is the option's index in the array rather than the type id — so a spec that selected by
     * value would be pinning an ordinal that changes whenever AM gains a module type.
     *
     * Called last, after the name is filled: validateModuleProps re-reads the name from the DOM on
     * the type's change event, so filling the name needs no synthetic event of its own.
     */
    async function chooseModuleType (page, displayName) {
        await page.locator(SEL.typeControl).click();
        await page.locator(SEL.typeDropdown).getByText(displayName, { exact: true }).click();
        await expect(page.locator(SEL.typeItem)).toHaveText(displayName);
    }

    /**
     * Wait until the edit form for a named module has rendered.
     *
     * The wait is on the title carrying *this module's* name, and that is the single most important
     * line in this file. A hash change does not reload the document and the previous view's DOM
     * survives until the new one replaces it, so waiting on a generated field is satisfied by the
     * form that is already on screen — which for two module types with an authenticationLevel each
     * means the assertions that follow run happily against the wrong module. Reproduced: navigating
     * from the securid form to the httpbasic one and waiting only on a field read securid's fields
     * back, with the title still showing securid's name.
     *
     * `timeout` is for the callers waiting through a cold start rather than a route change.
     */
    async function awaitEditForm (page, name, timeout) {
        await expect(page.locator(SEL.title), "the edit form must be this module's").toHaveText(name, { timeout });
        await expect(page.locator(SEL.save)).toBeVisible({ timeout });
        await expect(page.locator(`${SEL.form} .form-group`).first()).toBeAttached({ timeout });
    }

    async function openModuleEditForm (page, realmPath, type) {
        await page.goto(xuiUrl(moduleRoute(realmPath, `/${type.id}/edit/${type.instance}`)));
        await awaitEditForm(page, type.instance);
    }

    /**
     * The schema property each generated input stands for, sorted — order on the page is not stable.
     *
     * Flat scalar schemas only, which both types under test are. json-editor names an array or
     * nested-object property's inputs root[x][0], and the greedy capture below would report that as
     * the property `x][0`. If a later spec covers a type with a non-scalar property — task 1.15's
     * chain types are the likely first — this needs to strip trailing index groups before it can be
     * reused, rather than silently producing an unreadable failure message.
     */
    async function renderedFieldNames (page) {
        const names = await page.locator(SEL.generatedInputs)
            .evaluateAll((nodes) => nodes.map((node) => node.getAttribute("name")));

        return names.map((name) => name.replace(/^root\[(.*)\]$/, "$1")).sort();
    }

    /** Record every module create the console posts, so a test can assert it posted once, or not at all. */
    function recordCreateRequests (page) {
        const bodies = [];

        page.on("request", (req) => {
            if (req.method() === "POST" && req.url().includes("_action=create")
                && req.url().includes("/realm-config/authentication/modules/")) {
                bodies.push(req.postDataJSON());
            }
        });
        return bodies;
    }

    for (const type of MODULE_TYPES) {
        test(`a ${type.id} module created through the console appears in the module list`, async ({ page, request }) => {
            const { path } = await givenRealm(request);
            const createBodies = recordCreateRequests(page);

            await openAdminConsole(page);
            await openModuleList(page, path);
            await expect(page.locator(SEL.row(type.instance)),
                "precondition: the realm does not have this module yet").toHaveCount(0);

            await openCreateForm(page, path);
            await expect(page.locator(SEL.title))
                .toHaveText(bundle.console.authentication.modules.addModuleTitle);

            // Both answers are needed, and the form opens with the action refused until they are
            // given. Asserted in two steps because a name alone passing would mean a module created
            // with whichever type happened to be first.
            await expect(page.locator(SEL.create)).toBeDisabled();
            await page.fill(SEL.newModuleName, type.instance);
            await expect(page.locator(SEL.create), "a name without a type is not enough").toBeDisabled();

            await chooseModuleType(page, typeNames.get(type.id));

            // The other half of "the create form is hand-written", and the half the request body
            // cannot show: choosing a type builds no form. NewServiceView would have fetched this
            // type's schema and generated inputs by now; AddModuleView fetches nothing, so there is
            // nothing named root[...] on the page. Asserted after the type is chosen, because before
            // it there would be nothing to find either way.
            await expect(page.locator(SEL.generatedInputsAnywhere),
                "choosing a type must not generate a form on the create screen").toHaveCount(0);

            await expect(page.locator(SEL.create)).toBeEnabled();
            await page.locator(SEL.create).click();

            // A created module is confirmed by the console routing to its edit form — nothing is
            // added to #messages on this path.
            await expect(page).toHaveURL(
                xuiUrl(moduleRoute(path, `/${type.id}/edit/${type.instance}`)));
            await awaitEditForm(page, type.instance);

            // The create form is hand-written and carries no configuration, so this is the whole of
            // what it may send. A migration in which it started sending schema values would create a
            // different module than the operator asked for, and every other assertion here would
            // stay green.
            expect(createBodies, "the console must have created the module once").toHaveLength(1);
            expect(Object.keys(createBodies[0]),
                "the create form may send the name and nothing else").toEqual(["_id"]);
            expect(createBodies[0]._id).toBe(type.instance);

            // It reached the server, and AM filled it in from the type's template.
            const created = await readModule(adminToken, request, path, type.id, type.instance);
            expect(created, "the console must have created the module").not.toBeNull();
            expect(created).toMatchObject(type.created);

            // ... and the list the console renders next is built from a fresh read, so it is there
            // too, under the type it was created as.
            await openModuleList(page, path);
            await expect(page.locator(SEL.row(type.instance))).toContainText(typeNames.get(type.id));
        });

        test(`an edit to a ${type.id} module made in the console persists`, async ({ page, request }) => {
            const { path } = await givenRealmWithModule(request, type);
            const schema = await moduleSchema(adminToken, request, path, type.id);
            // Both derived from the schema the console will be generated from, not from literals —
            // see the note on MODULE_TYPES for the one property where that is load-bearing.
            const rendered = type.rendered(type.created, schema);
            const edited = type.edited(schema);

            await openAdminConsole(page);
            await openModuleEditForm(page, path, type);

            // The dynamic title is the instance's name and the subtitle is its type's display name,
            // which is the pair that says the route resolved to the right instance of the right type.
            await expect(page.locator(SEL.subtitle)).toHaveText(typeNames.get(type.id));

            // The form is generated from the schema AM served for this type, asserted against that
            // schema rather than against a list of fields copied into this file. Every property, and
            // no others: Form is built without showOnlyRequiredAndEmpty, so unlike the service create
            // form nothing here is withheld.
            expect(await renderedFieldNames(page),
                "the edit form's fields must be the type's schema properties")
                .toEqual(Object.keys(schema.properties).sort());

            // And the per-type difference that makes running this twice worth anything: the same view
            // builds a plain text input for one type and a selectize-decorated <select> for the other.
            await expect(page.locator(SEL.formSelectize),
                `the ${type.id} form must render ${type.selectizeControls} selectize control(s)`)
                .toHaveCount(type.selectizeControls);

            // No module type on this instance is grouped — grouped is every property being an object
            // — so the tab bar EditModuleView imports bootstrap-tabdrop for is never rendered and the
            // whole form is built into #tabpanel. Asserted rather than assumed: with a grouped type,
            // renderTab empties #tabpanel and rebuilds it for one group, and save posts only that
            // group's data. The day a type under test becomes grouped, this says so.
            await expect(page.locator(SEL.tabs),
                "neither type is grouped, so the edit form must be a single panel").toHaveCount(0);

            // Deleting is list-only here, which is the other structural difference from the service
            // console — EditServiceView carries a delete action in its header and this view carries
            // none. Pinned because the file header claims it, and because the two delete tests below
            // would still pass if a third route quietly appeared.
            await expect(page.locator(SEL.delete),
                "the edit form must offer no delete action").toHaveCount(0);

            await type.expectRendered(page, rendered);

            const messages = await captureMessages(page);
            await type.edit(page, edited);
            await page.locator(SEL.save).click();

            // The console reports the save itself — AM answers the PUT with the instance and no
            // message. Recorded rather than polled for, because the alert removes itself after a few
            // seconds.
            await expect.poll(
                async () => (await messages())
                    .filter((message) => message.className.includes("alert-info"))
                    .map((message) => message.text),
                { message: "a saved module must be confirmed to the user", timeout: 30_000 }
            ).toContain(bundle.config.messages.AppMessages.changesSaved);

            // Saving does not route anywhere; the operator is left on the form they saved.
            await expect(page).toHaveURL(
                xuiUrl(moduleRoute(path, `/${type.id}/edit/${type.instance}`)));

            // It reached the server ...
            expect(await readModule(adminToken, request, path, type.id, type.instance),
                "the edit must have been written, not just reported").toMatchObject(edited);

            // ... and it survives the console being rebuilt around it. A reload rather than a second
            // goto: Backbone does not re-fire a route for the hash it is already on. A cold start
            // refetches the whole unbundled dependency closure, so it gets the budget the other specs
            // give their boot waits rather than the assertion default.
            await page.reload();
            await awaitEditForm(page, type.instance, 30_000);
            await type.expectRendered(page, edited);
        });
    }

    test("a module deleted from the module list disappears from the console", async ({ page, request }) => {
        // The per-row route, driven with securid. The two delete routes do not share an
        // implementation, and neither is per-type, so they are split across the two types rather than
        // run twice each.
        const type = MODULE_TYPES[0];
        const { path } = await givenRealmWithModule(request, type);

        await openAdminConsole(page);
        await openModuleList(page, path);
        await expect(page.locator(SEL.row(type.instance)),
            "precondition: the realm has the module").toHaveCount(1);
        // Both controls are disabled for a module a chain references. Nothing here creates a chain,
        // so this also pins that a freshly created instance is unreferenced — which is what makes it
        // inert.
        await expect(page.locator(`${SEL.row(type.instance)} ${SEL.rowDelete}`)).toBeEnabled();

        // The confirmation is a gate rather than a formality, so this declines once before agreeing.
        // A dialog that deleted on cancel would pass every other assertion here.
        await page.locator(`${SEL.row(type.instance)} ${SEL.rowDelete}`).click();
        await expect(page.locator(SEL.dialogTitle))
            .toHaveText(`${bundle.common.form.confirm} ${bundle.common.form.delete}`);
        await expect(page.locator(SEL.dialogBody)).toHaveText(
            bundle.console.common.confirmDeleteText
                .replace("__type__", bundle.console.authentication.common.module));
        await page.locator(SEL.dialogCancel).click();
        await expect(page.locator(SEL.dialog)).toHaveCount(0);

        await expect(page.locator(SEL.row(type.instance)),
            "cancelling must leave the module alone").toHaveCount(1);
        expect(await moduleExists(adminToken, request, path, type.instance),
            "cancelling must not have deleted anything").toBe(true);

        await page.locator(`${SEL.row(type.instance)} ${SEL.rowDelete}`).click();
        await page.locator(SEL.dialogConfirm).click();

        // No routing and no message on either delete route: the list re-renders in place, and the row
        // going away is the whole of the feedback the operator gets.
        await expect(page.locator(SEL.row(type.instance))).toHaveCount(0);
        await expect(page.locator(SEL.row(STOCK_MODULE)),
            "the list must have re-rendered rather than emptied").toHaveCount(1);
        await expect(page).toHaveURL(xuiUrl(moduleRoute(path)));

        // Asked with the console's own existence query rather than by reading the instance: AM
        // answers a GET for a deleted name with the type's defaults under an empty _id, so a read is
        // the one check that cannot tell a deleted module from a present one. See readModule.
        expect(await moduleExists(adminToken, request, path, type.instance),
            "the module must be gone from AM").toBe(false);
    });

    test("a module selected in the list can be deleted with the toolbar", async ({ page, request }) => {
        // The bulk route, driven with httpbasic.
        const type = MODULE_TYPES[1];
        const { path } = await givenRealmWithModule(request, type);

        await openAdminConsole(page);
        await openModuleList(page, path);

        // The toolbar acts on whatever is checked, so it is refused until something is.
        await expect(page.locator(SEL.bulkDelete)).toBeDisabled();
        await page.locator(`${SEL.row(type.instance)} ${SEL.rowSelect}`).check();
        await expect(page.locator(SEL.bulkDelete)).toBeEnabled();
        // ModulesView marks the row as well as enabling the button, so the operator can see what the
        // toolbar would act on.
        await expect(page.locator(SEL.row(type.instance))).toHaveClass(/selected/);

        await page.locator(SEL.bulkDelete).click();

        // A different key from the per-row dialog, and the only one of the two that mentions a
        // selection. One module is checked, so i18next resolves the singular.
        await expect(page.locator(SEL.dialogTitle))
            .toHaveText(`${bundle.common.form.confirm} ${bundle.common.form.delete}`);
        await expect(page.locator(SEL.dialogBody))
            .toHaveText(bundle.console.authentication.modules.confirmDeleteSelected);
        await page.locator(SEL.dialogConfirm).click();

        await expect(page.locator(SEL.row(type.instance))).toHaveCount(0);
        await expect(page.locator(SEL.row(STOCK_MODULE)),
            "the list must have re-rendered rather than emptied").toHaveCount(1);
        // And the toolbar has forgotten the selection along with the row it belonged to.
        await expect(page.locator(SEL.bulkDelete)).toBeDisabled();

        expect(await moduleExists(adminToken, request, path, type.instance),
            "the module must be gone from AM").toBe(false);
    });

    test("a name the realm already uses is refused whatever type is chosen", async ({ page, request }) => {
        // This spec's idempotency premise, asserted rather than trusted: a leftover module collides
        // on its name, and does not change what the create form offers. Both halves matter — the
        // second is what distinguishes this from the service console, where a leftover removes the
        // option the create test clicks.
        const existing = MODULE_TYPES[0];
        const other = MODULE_TYPES[1];
        const { path } = await givenRealmWithModule(request, existing);

        // AM keeps offering a type the realm already has an instance of. getAllTypes is unfiltered,
        // which is the opposite of getCreatableTypes for services.
        const offered = await moduleTypes(adminToken, request, path);
        expect(offered.map((type) => type._id),
            "a type must stay on offer however many instances of it exist").toContain(existing.id);

        const createBodies = recordCreateRequests(page);

        await openAdminConsole(page);
        await openModuleList(page, path);
        await openCreateForm(page, path);

        const messages = await captureMessages(page);
        await page.fill(SEL.newModuleName, existing.instance);

        // The dropdown offers AM's list exactly, including the type the realm already has.
        await page.locator(SEL.typeControl).click();
        await expect(page.locator(SEL.typeOptions),
            "the create form must offer every type AM does").toHaveCount(offered.length);
        await expect(page.locator(SEL.typeDropdown)
            .getByText(typeNames.get(existing.id), { exact: true }),
        "the type of the existing module must still be offered").toHaveCount(1);

        // A *different* type, so what is refused below is the name alone.
        await page.locator(SEL.typeDropdown)
            .getByText(typeNames.get(other.id), { exact: true }).click();
        await expect(page.locator(SEL.typeItem)).toHaveText(typeNames.get(other.id));
        await expect(page.locator(SEL.create),
            "the form has no reason to refuse until it asks the server").toBeEnabled();

        await page.locator(SEL.create).click();

        await expect.poll(
            async () => (await messages())
                .filter((message) => message.className.includes("alert-danger"))
                .map((message) => message.text),
            { message: "a duplicate name must be refused to the user", timeout: 30_000 }
        ).toContain(bundle.console.authentication.modules.addModuleError);

        // Refused before anything was sent: AddModuleView queries the name across all types first and
        // stops. The operator is left on the form, and nothing was posted.
        await expect(page).toHaveURL(xuiUrl(moduleRoute(path, "/new")));
        expect(createBodies, "a refused create must not reach the server").toHaveLength(0);

        // The console is stricter than AM here, which is worth pinning because it is the reason the
        // check is worth having: the server would have allowed this name under a different type, and
        // the list would then have shown two rows with one name.
        expect(await readModule(adminToken, request, path, other.id, existing.instance),
            "nothing may have been created under the other type").toBeNull();
        expect(await readModule(adminToken, request, path, existing.id, existing.instance),
            "and the module that was already there must be untouched").not.toBeNull();
    });
});
