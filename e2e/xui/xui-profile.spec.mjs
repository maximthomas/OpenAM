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
 * OpenAM XUI — the end user's own profile, and an edit to it that survives a reload.
 *
 * The only route in this suite that an ordinary user reaches. Everything else under #realms is the
 * administrator's console; this is what a person with no admin role sees when they log in, and it is
 * where they land automatically — AMConfig's EVENT_HANDLE_DEFAULT_ROUTE routes anyone without
 * `ui-realm-admin` to `profile` rather than to `realms`.
 *
 * What makes it worth its own spec is where the code lives. The view is not openam-ui-ria's:
 * UserProfileView and AbstractUserProfileTab come from the commons UI library
 * (org/forgerock/commons/ui/user/profile/), the route is declared in commons' UserRoutesConfig as
 * `profile/?`, and the form is assembled from commons' partials/form/_basicInput.html and
 * _basicSaveReset.html. openam-ui-ria contributes exactly one *template* —
 * templates/user/UserProfileTemplate.html, which overrides the commons template of the same name —
 * plus the two modules that decide where an end user lands (config/process/AMConfig.js) and how the
 * save is serialised (org/forgerock/openam/ui/user/UserModel.js). So this route crosses the
 * boundary the migration is about to move: phase 1 turns those commons artifacts from Maven
 * `zip:www` dependencies into npm packages (design.md D5, tasks 3.2–3.3), and phase 2 changes how a
 * consumer resolves and bundles them. A profile page that renders is the cheapest end-to-end
 * evidence that a commons view, a commons partial and an openam-ui-ria template override still find
 * each other afterwards.
 *
 * What this is guarding:
 *
 *   - the commons user route resolving and its view rendering into an openam-ui-ria template
 *     override — and specifically that the override is the one that won, which is asserted on the
 *     field list rather than assumed. The two templates render different forms: commons wraps every
 *     field in a `{{#property}}` block, so a field the user has no value for does not appear at all,
 *     while the override renders all five unconditionally. `demo` has no telephoneNumber, so an
 *     empty phone input existing is the fingerprint that separates them (D3, D5);
 *   - the form being generated from a Handlebars partial and then populated from the logged-in
 *     user model by js2form, which is the only place in the suite that pairing is exercised;
 *   - a write that reaches the server and comes back: the point of task 1.8 is the "and an edit
 *     that persists" half, so the value is checked after a full reload and again over REST, which
 *     does not go through the XUI at all;
 *   - the notification the UI raises on save, asserted against the deployed locale bundle rather
 *     than a literal, so it also fails if locales/ stops being packaged verbatim.
 *
 * Three things about this page are load-bearing for anyone changing this spec:
 *
 *   1. Update is gated on validation, not on dirtiness. AbstractView.validationCompleted sets
 *      `submit.disabled = !formValidated(form)` on any validation event, while only Reset and the
 *      pending-changes banner track actual changes ("change :input" → checkChanges). Since
 *      UserProfileView.render() focuses the first editable input on arrival, merely clicking away
 *      from it enables Update with nothing edited. "Update is disabled until the form is dirty" is
 *      therefore false here, and is not asserted below.
 *   2. page.fill() alone can never save. It dispatches a DOM `input` event and nothing else, so
 *      neither the `change` handler nor the blur-driven validators run, and clicking Update clicks
 *      a disabled button. editGivenName() below adds the blur that supplies both.
 *   3. The save is a fixed-attribute PUT, and neither the form nor Backbone decides which
 *      attributes. openam-ui-ria's UserModel overrides `sync` and treats "update" and "patch"
 *      identically, ignoring the {patch: true} AbstractUserProfileTab.submit passes and ignoring
 *      `options.attrs` that Backbone would otherwise have sent; it PUTs
 *      `_.pick(this.toJSON(), ["givenName", "sn", "mail", "postalAddress", "telephoneNumber"])`
 *      with `val || []` applied. The pick is over what the *model* holds, and lodash 3's `_.pick`
 *      omits a key the object does not have, so an attribute the record lacks is never sent. Two
 *      consequences: `username` is never sent even though it is on the form and in getFormContent();
 *      and `telephoneNumber` — which this user does not have, but which the template renders as an
 *      empty input that form2js round-trips back into the model — is written as `[]` on every save,
 *      which is how AM is asked to remove it. Teardown therefore owns the whole set of five that a
 *      save *can* touch, not the subset any one save happens to send — see FORM_ATTRIBUTES.
 *
 * Not covered here, deliberately: the Password tab and the KBA tab. The password form is a sibling
 * tab in the same template rather than a dialog, and staying on the details form never touches it.
 * ConfirmPasswordDialog is rendered only for a changed *protected* attribute, and it never fires
 * here for two reasons rather than one: UserModel.getProtectedAttributes() always includes
 * `password`, but formSubmit only considers attributes `_.has(formData, attr)` and the details form
 * has no password field; and this instance's serverinfo adds nothing, reporting
 * `protectedUserAttributes: []`. There is no KBA tab at all —
 * SiteConfigurationService registers UserProfileKBATab only when serverinfo reports
 * `kbaEnabled: "true"`, and this instance reports false. Password change and KBA are their own
 * flows; neither sits in the path of a field edit, and the tab assertion in the first test is what
 * would notice if one arrived.
 */

import { test, expect } from "@playwright/test";
import { OPENAM_BASE, PASSWORD, USERNAME, getAdminToken } from "../common/openam-commons.mjs";
import { captureMessages, localeBundle, loginViaXui, xuiUrl } from "../common/xui-commons.mjs";

/** The end user's own record. The API version is the one the XUI itself sends on this endpoint. */
const USER_URL = `${OPENAM_BASE}/json/realms/root/users/${USERNAME}`;
const API_VERSION = "protocol=1.0,resource=2.0";

/**
 * The route, as the router leaves it in the address bar. Commons' UserRoutesConfig declares the
 * pattern `profile/?` with `defaults: ["details"]`, and the default argument is written into the
 * URL rather than merely assumed, so an end user's landing URL names the tab.
 */
const PROFILE_HASH = "#profile/details";

/**
 * Every attribute a profile save *can* write, in the order UserModel.sync picks them — which is
 * neither the template's order nor the set of fields on the form. `username` is on the form and is
 * never written; `postalAddress` has no field in this template and is written for any user who
 * already has one. Read as one set and written back as one set, so teardown owns everything a save
 * could have disturbed rather than what one particular save sent.
 */
const FORM_ATTRIBUTES = ["givenName", "sn", "mail", "postalAddress", "telephoneNumber"];

/**
 * The fields openam-ui-ria's template override renders, in its order — the fingerprint that says
 * the override rather than the commons template is what rendered. See the header, and the
 * precondition beforeAll pins for it.
 */
const RENDERED_FIELDS = ["username", "givenName", "sn", "mail", "telephoneNumber"];

/**
 * Attributes this spec reads off the form and compares against the record. A record missing one
 * would make that comparison "" against "" — true, and meaningless — so beforeAll pins them.
 */
const POPULATED_FIELDS = ["givenName", "sn", "mail"];

/**
 * The attribute this spec edits.
 *
 * It is the only one on the form that is writable, carries no validator, and has no role in
 * authentication. The others were considered and rejected: `username` is readonly and is the login
 * identifier; `sn` is `required`, so editing it drags a validation dependency into a test that is
 * not about validation; `mail` feeds the forgot-password and forgot-username flows and may be a
 * login alias for the data store; `telephoneNumber` is absent on this user, so editing it would be
 * a create rather than an edit, and it carries a `validPhoneFormat` validator. `givenName` also
 * leaves `cn` alone — AM does not recompute it — so a changed first name is invisible to
 * everything except this form.
 */
const FIELD = "givenName";

const SEL = {
    heading: ".page-header h1",
    tabLinks: ".tab-menu ul.nav-tabs a[role=\"tab\"]",
    detailsPane: "#userDetailsTab",
    form: "form#details",
    // partials/form/_basicInput.html renders id="input-{{property}}" for each field, and is the only
    // thing that puts an input inside a .form-group here — so this matches the rendered fields and
    // nothing else. The Update and Reset controls sit in the panel footer, outside any form-group.
    fields: "form#details .form-group input",
    username: "form#details #input-username",
    givenName: "form#details #input-givenName",
    telephoneNumber: "form#details #input-telephoneNumber",
    givenNameLabel: "form#details label[for=\"input-givenName\"]",
    // partials/form/_basicSaveReset.html gives neither control an id; the pair is identified by type.
    update: "form#details input[type=\"submit\"]",
    reset: "form#details input[type=\"reset\"]",
    changesPending: "form#details .changes-pending",
};

/**
 * Valid against both backends. What is *asserted* here is UI behaviour — a route resolving, a view
 * rendering, a form generated from a partial and populated from a model — over a plain read and
 * write of one record, which is the side of D16's split that runs against both; contrast
 * xui-httponly.spec.mjs, whose subject is AM's own cookie and session behaviour.
 *
 * It does, though, lean on three things a local server has to get right, and they are easy to miss
 * when reading the phase 0b task list — recorded here for task 2.1's request enumeration:
 *
 *   - it reads and writes /json/realms/root/users/{user}, an endpoint no other spec drives, and it
 *     needs the end user `demo` in the baseline state (D15) rather than only the administrator;
 *   - `roles` on that read is virtual and depends on who is asking. Read with the administrator's
 *     token, `demo` comes back with no `roles` key at all; read with `demo`'s own session it comes
 *     back `["ui-self-service-user"]`. UserModel.parse turns that into `uiroles`, AMConfig branches
 *     on `ui-realm-admin` to choose the landing route, and commons' Router gates this route on
 *     `ui-self-service-user` (UserRoutesConfig declares `role` on it). A server that answers the
 *     same read identically regardless of caller sends this spec to the console and fails it at
 *     openProfile;
 *   - the teardown PUT below sends five attributes and expects a merge: `cn`, `uid`, `objectClass`
 *     and the password all survive it, and `demo` still authenticates afterwards. A server that
 *     implements PUT as a replace destroys the baseline user on the first teardown.
 */
test.describe("XUI end-user profile (view and an edit that persists)", {
    tag: ["@deployed-am", "@local-server"],
}, () => {
    /** The oracle for every string this page renders. */
    let bundle;
    let adminToken;

    /**
     * The user's form attributes as this spec found them, restored after every test.
     *
     * Read from the instance rather than hardcoded, so the spec restores what was actually there
     * and does not quietly assert a particular instance's idea of who `demo` is.
     */
    let originalAttributes;

    test.beforeAll(async ({ request }) => {
        adminToken = await getAdminToken(request);
        expect(adminToken, "the fixtures need an admin session").toBeTruthy();

        // The console's own namespace, fetched from the instance: asserting against it rather than
        // against literals also asserts locales/en/translation.json was packaged and served.
        bundle = await localeBundle(request, "translation");

        originalAttributes = await readFormAttributes(request);

        // What the assertions below need to be true of this user, pinned here rather than assumed,
        // because both failure modes are silent: an assertion that compares the form against an
        // attribute the record does not have compares "" with "" and passes on an empty form, and
        // the template fingerprint in the first test stops discriminating entirely if this user
        // gains a phone number. Neither shows up as a failure — they show up as a test that has
        // quietly stopped testing, which is the way a regression net rots (D11).
        for (const property of POPULATED_FIELDS) {
            expect(
                singleValue(originalAttributes, property),
                `this spec reads ${property} off the form, so ${USERNAME} must have one`
            ).not.toBe("");
        }
        expect(
            singleValue(originalAttributes, "telephoneNumber"),
            `the template fingerprint needs ${USERNAME} to have no phone number: it is the only `
                + "field the commons template and openam-ui-ria's override disagree about for this "
                + "user, so with one set the two render the same list"
        ).toBe("");
    });

    test.afterEach(async ({ request }) => {
        // The edit is server-side and outlives the browser, so leaving it in place would make this
        // spec's result depend on the order it ran in — and, since the instance is long-lived,
        // on which run left what behind. The whole set is restored rather than the edited field,
        // because a test that failed between the fill and the click may have rewritten any of them.
        const current = await readFormAttributes(request);

        if (JSON.stringify(current) !== JSON.stringify(originalAttributes)) {
            await writeFormAttributes(request, originalAttributes);
        }
        expect(
            await readFormAttributes(request),
            "teardown must leave the user as it found it"
        ).toEqual(originalAttributes);
    });

    function restHeaders (extra = {}) {
        return {
            "iPlanetDirectoryPro": adminToken,
            "Accept-API-Version": API_VERSION,
            "Content-Type": "application/json",
            ...extra,
        };
    }

    /**
     * The user's record, reduced to the attributes the form owns.
     *
     * A missing attribute reads as the empty array AM would answer with once it is removed, so a
     * record read before an edit and one read after the edit was undone compare equal.
     */
    async function readFormAttributes (request) {
        const response = await request.get(USER_URL, { headers: restHeaders() });

        expect(
            response.ok(),
            `this spec drives the profile of the end user "${USERNAME}", which the instance is `
                + `expected to ship and which nothing here creates — reading it answered `
                + `HTTP ${response.status()}: ${await response.text()}`
        ).toBeTruthy();

        const user = await response.json();
        return Object.fromEntries(FORM_ATTRIBUTES.map((attr) => [attr, user[attr] ?? []]));
    }

    /** Write those attributes back, as the form's own save does. */
    async function writeFormAttributes (request, attributes) {
        const response = await request.put(USER_URL, {
            headers: restHeaders({ "If-Match": "*" }),
            data: attributes,
        });
        expect(
            response.ok(),
            `restoring ${USERNAME} answered HTTP ${response.status()}: ${await response.text()}`
        ).toBeTruthy();
    }

    /**
     * The one value the form holds for an attribute, or "" when the record has none.
     *
     * AM answers the attributes this spec reads as single-element arrays — though not every
     * attribute on the record is one: `username` comes back as a plain string — so this normalises
     * rather than assuming either shape.
     */
    function singleValue (attributes, property) {
        return [].concat(attributes[property] ?? [])[0] ?? "";
    }

    /**
     * Wait until the details form holds the user's data.
     *
     * form#details is in the DOM as soon as the template is compiled, but UserProfileView fills it
     * afterwards: render() resolves its tab promises, then calls reloadFormData on each tab, whose
     * last act is initializeChangesPending() — which renders ChangesPendingTemplate into
     * .changes-pending. That element having children is therefore the signal that the form has
     * been populated. Waiting on form#details alone reads it back empty.
     */
    async function waitForFormData (page) {
        await page.waitForFunction(
            () => document.querySelector("form#details .changes-pending")?.children.length > 0,
            null,
            { timeout: 30_000 }
        );
    }

    /**
     * Log in as the end user and wait until the profile has arrived.
     *
     * No explicit navigation, deliberately. The profile *is* the end user's default route, and
     * loginViaXui returns as soon as the router leaves #login — while that landing navigation is
     * still in flight. A goto() issued on top of it races it, the same way openAdminConsole
     * documents for the console; and once it has landed, a goto() to the URL the browser is
     * already on is a no-op that leaves the previous render in place. Letting the landing route
     * arrive avoids both, and is also how a real end user gets here.
     */
    async function openProfile (page) {
        await loginViaXui(page, USERNAME, PASSWORD);
        await page.waitForURL((url) => url.hash.startsWith("#profile"), { timeout: 30_000 });
        await waitForFormData(page);
    }

    /**
     * Throw the whole application away and let it come back.
     *
     * reload() rather than a re-navigation: the router does not re-render for a goto() to the
     * current hash, so the form would keep the value the browser already had — which is exactly
     * the thing the assertion after it is trying to rule out.
     */
    async function reloadProfile (page) {
        await page.reload();
        await waitForFormData(page);
    }

    /**
     * Type a value into the first-name field the way the view expects it.
     *
     * The blur is not decoration: fill() dispatches a DOM `input` event only, and the view listens
     * for `change` (dirtiness) while the validators that enable Update run on blur. Without it,
     * clicking Update clicks a disabled button and the test times out looking like a UI failure.
     */
    async function editGivenName (page, value) {
        const input = page.locator(SEL.givenName);

        await input.fill(value);
        await input.blur();
    }

    test("the profile renders for an end user, populated from their record", async ({ page }) => {
        await openProfile(page);

        // Where an end user lands: not the console. The route is commons' `profile/?`, which the
        // default route handler picks for anyone without the ui-realm-admin role, and the URL comes
        // back with the tab argument filled in from UserRoutesConfig's `defaults: ["details"]` —
        // so the details form showing below is the route's own default, not a click.
        await expect(page, "an end user's default route is their own profile")
            .toHaveURL(xuiUrl(PROFILE_HASH));
        await expect(page.locator(SEL.heading)).toHaveText(bundle.common.user.userProfile);

        // Two tabs, in this order, and no third. Asserted as the complete list rather than as
        // "contains", so a tab arriving — a KBA tab on an instance with kbaEnabled, say — is a
        // failure here rather than a surprise in a test that assumes the details form is showing.
        await expect(page.locator(SEL.tabLinks)).toHaveText([
            bundle.common.user.basicInfo,
            bundle.common.user.password,
        ]);
        await expect(page.locator(SEL.detailsPane)).toBeVisible();

        // Which template rendered, and not merely that one did. The commons template of the same
        // name wraps each field in a `{{#property}}` block, so it renders only the fields this user
        // has a value for — username, givenName, sn and mail, four — where openam-ui-ria's override
        // renders five unconditionally. The margin is exactly one field, which is why beforeAll
        // pins the absent phone number. Asserting the exact list rather than a count also catches a
        // field arriving or disappearing.
        expect(
            await page.locator(SEL.fields).evaluateAll((inputs) => inputs.map((input) => input.id)),
            "openam-ui-ria's template override must be the one that rendered"
        ).toEqual(RENDERED_FIELDS.map((property) => `input-${property}`));
        // The fingerprint itself: an input for an attribute the user does not have.
        await expect(page.locator(SEL.telephoneNumber)).toHaveValue("");

        // The form was generated from _basicInput.html and then filled from the logged-in user
        // model — so this is both "the partial rendered" and "it rendered this user".
        await expect(page.locator(SEL.givenNameLabel)).toHaveText(bundle.common.user.givenName);
        await expect(page.locator(SEL.username)).toHaveValue(USERNAME);
        for (const property of POPULATED_FIELDS) {
            await expect(page.locator(`form#details #input-${property}`))
                .toHaveValue(singleValue(originalAttributes, property));
        }

        // The login identifier is shown but not editable: the template passes readonly=true, and
        // that is also what makes givenName the field UserProfileView.render() focuses on arrival.
        await expect(page.locator(SEL.username)).toHaveJSProperty("readOnly", true);

        // Nothing has been edited, so the dirty signals are silent. Update is deliberately not
        // asserted: it tracks validation rather than dirtiness, and the auto-focused field means
        // one click elsewhere enables it with no edit at all. See the file header.
        await expect(page.locator(SEL.changesPending)).toBeHidden();
        await expect(page.locator(SEL.reset)).toBeDisabled();
    });

    test("an edit to the first name is saved, confirmed, and survives a reload",
        async ({ page, request }) => {
            // Unique per run: the instance is long-lived, so a fixed value could pass against a
            // record a previous run failed to restore.
            const edited = `${singleValue(originalAttributes, FIELD)}-${Date.now().toString(36)}`;

            await openProfile(page);
            const messages = await captureMessages(page);

            await editGivenName(page, edited);

            // The two controls answer to different things, and this is the spec's record of which:
            // the banner and Reset track dirtiness, Update tracks validation.
            await expect(page.locator(SEL.changesPending)).toBeVisible();
            await expect(page.locator(SEL.reset)).toBeEnabled();
            await expect(page.locator(SEL.update)).toBeEnabled();

            await page.locator(SEL.update).click();

            // The UI's own string: AM answers the PUT with the record and no message, so this is
            // profileUpdateSuccessful out of the console's bundle. Recorded rather than polled for,
            // because commons' Messages removes the alert after a few seconds.
            await expect.poll(
                async () => (await messages())
                    .filter((message) => message.className.includes("alert-info"))
                    .map((message) => message.text),
                { message: "a saved profile must be confirmed to the user", timeout: 30_000 }
            ).toContain(bundle.config.messages.UserMessages.profileUpdateSuccessful);

            // The half of task 1.8 that matters: the value is on the server, not in the form. A
            // reload discards the router, the views and the user model, so the field can only come
            // back filled if the server answered with it.
            await reloadProfile(page);
            await expect(page.locator(SEL.givenName)).toHaveValue(edited);

            // And again without the XUI in the path at all. If the page were echoing state it had
            // kept for itself, this is the check that would notice.
            const stored = await readFormAttributes(request);
            expect(singleValue(stored, FIELD), "the edit must have reached the user's record")
                .toBe(edited);
        });

    test("Reset discards a pending edit and never reaches the server", async ({ page, request }) => {
        const original = singleValue(originalAttributes, FIELD);

        await openProfile(page);

        // Recorded from before the first keystroke, because comparing the record afterwards is the
        // weaker claim: a form that wrote on every change and whose Reset wrote the original back
        // would end in the right state having made two round trips. This is what makes the test's
        // name literally true.
        const writes = [];
        page.on("request", (req) => {
            if (req.method() !== "GET" && req.url().includes(`/users/${USERNAME}`)) {
                writes.push(`${req.method()} ${req.url()}`);
            }
        });

        await editGivenName(page, `${original}-discarded`);
        await expect(page.locator(SEL.changesPending)).toBeVisible();

        await page.locator(SEL.reset).click();

        // resetForm calls reloadFormData, which re-fills the form from the model the view already
        // holds — the same path render() takes on arrival — and clears the dirty signals.
        await expect(page.locator(SEL.givenName)).toHaveValue(original);
        await expect(page.locator(SEL.changesPending)).toBeHidden();
        await expect(page.locator(SEL.reset)).toBeDisabled();

        // Update is *not* asserted here, and the asymmetry is deliberate rather than an oversight:
        // it stays enabled after a reset, where it was disabled on arrival. reloadFormData disables
        // both controls from bindValidators' synchronous callback, but it first calls
        // clearValidators, which triggers `validationReset` on every field the edit had marked —
        // and AbstractView's handler for that goes through ModuleLoader.load("bootstrap"), so it
        // lands a microtask later and re-runs validationCompleted, which re-enables submit on a
        // form with no errors. On first render no field carries a status yet, nothing is triggered,
        // and the button stays disabled. Same cause as the header's first note: Update reports
        // validity, not pending changes.

        // Reset is a client-side undo: nothing was sent, and the record is untouched. This is also
        // what gives the previous test's assertions their meaning — a form that wrote as you typed
        // would pass those and fail these.
        expect(writes, "editing and resetting must not write to the user's record").toEqual([]);
        expect(
            await readFormAttributes(request),
            "a discarded edit must never have reached the server"
        ).toEqual(originalAttributes);
    });
});
