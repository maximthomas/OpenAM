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
 * OpenAM XUI — the device code verification pages, which are the `main-device` entry point.
 *
 * The third and last of the XUI's entry points. A device with no browser — a TV, a CLI — asks AM's
 * /oauth2/device/code endpoint for a user code and shows it to its owner, who types it into
 * /oauth2/device/user on a device that does have one. AM serves that page itself from the
 * openam-oauth2 FreeMarker templates (CodeVerificationForm.ftl, and CodeThanks.ftl once the code is
 * accepted), puts its state into a `window.pageData` global and boots RequireJS with
 * `data-main=…/XUI/main-device`.
 *
 * main-device.js is the smallest of the three: no router, no session bootstrap, no service layer, and
 * — unlike main-authorize — no logic of its own beyond `data.done ? DeviceDoneTemplate : DeviceTemplate`.
 * It initialises i18n against its own bundle, resolves the theme, compiles four templates and writes
 * them into the DOM. This spec drives all three states that produces: the form, the "code not found"
 * branch of DeviceTemplate, and DeviceDoneTemplate.
 *
 * What this is guarding:
 *
 *   - a third entry point exists and is reachable at the URL AM hardcodes into its own HTML
 *     (design.md D7, task 4.2 — three entry points, not two);
 *   - `require.config.map` rebinding, declared a third time in main-device.js (D2), and note that its
 *     Router binding is SingleRouteRouter rather than the console's Router;
 *   - templates and locales fetched by path at runtime and compiled in the browser (D3). Every string
 *     below is asserted against the deployed locales/en/device.json rather than a literal, so this
 *     fails if the bundle stops being copied verbatim, or if the entry point stops selecting the
 *     "device" namespace and falls back to the console's;
 *   - the theme being resolved and applied. Both FTL pages ship `<body style="display:none">` and
 *     nothing in the page removes it, so the page becomes visible only once ThemeManager has appended
 *     structure.css, whose `body { display: block !important }` overrides it — every toBeVisible()
 *     below therefore also asserts the theme was applied. The logo and footer assertions go further
 *     and check the resolved theme reached the templates that render from it.
 *
 * One asymmetry worth recording, because it is easy to "fix" during the migration and change
 * behaviour: main-authorize.js re-requires its templates with `text!${themePath}` after the theme
 * resolves, so a theme can override them. main-device.js lists its four templates statically in the
 * top-level require array, before the theme is known, so a theme template override does NOT apply to
 * these pages today. Task 1.10 covers overrides; this is the entry point where they do not reach.
 *
 * Not covered here, deliberately: the path where the client requires consent. AM answers a user code
 * for such a client by calling authorizationService.authorize() with the stored response_type
 * (device_code), for which this build registers no handler, so it renders the main-authorize error
 * page with unsupported_response_type — the device flow never reaches the consent screen. Whichever
 * way that is resolved server-side, the page it lands on is main-authorize's, covered by
 * xui-authorize.spec.mjs.
 */

import { test, expect } from "@playwright/test";
import { PASSWORD, USERNAME, getAdminToken } from "../common/openam-commons.mjs";
import {
    CLIENT_ID,
    DEVICE_CODE_URL,
    DEVICE_USER_URL,
    SCOPE,
    ensureOAuth2ClientExists,
    ensureOAuth2ServiceExists,
} from "../common/oauth2-commons.mjs";
import { loginViaXui, localeBundle } from "../common/xui-commons.mjs";

const SEL = {
    content: "#content",
    form: "#content form",
    formInfo: "#content #deviceFormInfo",
    codeInput: "#content input#deviceUserCode",
    codeLabel: "#content label[for=\"deviceUserCode\"]",
    submit: "#content button[type=\"submit\"]",
    errorPanel: "#content div.alert.alert-warning",
    done: "#content .jumbotron h1",
    // Rendered by LoginHeaderTemplate and FooterTemplate, the two templates shared with the other
    // entry points. They live outside #content, which LoginBaseTemplate renders.
    logo: "#loginBaseLogo img.main-logo",
    footer: "#footer",
};

/**
 * Deployed AM only, for the same reason as xui-authorize.spec.mjs: these pages are served by AM's
 * /oauth2/device/user endpoint, not from the XUI tree, and reaching them means AM issuing a user
 * code, storing it, resolving the resource owner's session and authorizing the device. design.md
 * scopes the local API server to authentication and session, serverinfo, site configuration and
 * realm and service administration — the device flow is outside it, which is the case D16 names as
 * deployed-AM-only. See task 2.13.
 */
test.describe("XUI device code verification (main-device entry point)", { tag: ["@deployed-am"] }, () => {
    /** The oracle for every string these pages render. */
    let bundle;

    test.beforeAll(async ({ request }) => {
        const adminToken = await getAdminToken(request);
        expect(adminToken, "the fixtures need an admin session").toBeTruthy();

        await ensureOAuth2ServiceExists(adminToken, request);
        // The default client implies consent, which is what lets a submitted code go straight to the
        // done page — see the note in the file header about the other path.
        await ensureOAuth2ClientExists(adminToken, request);

        bundle = await localeBundle(request, "device");
    });

    /** Ask AM for a user code, as the browserless device would. */
    async function requestUserCode (request) {
        const response = await request.post(DEVICE_CODE_URL, {
            form: { client_id: CLIENT_ID, scope: SCOPE, response_type: "device_code" },
        });
        expect(response.ok(), `device code request: HTTP ${response.status()} — ${await response.text()}`)
            .toBeTruthy();

        const { user_code: userCode } = await response.json();
        expect(userCode, "AM must issue a user code for the owner to type in").toBeTruthy();
        return userCode;
    }

    /** Open the verification page and wait until the entry point has rendered into it. */
    async function openVerificationForm (page) {
        await page.goto(DEVICE_USER_URL);
        await page.waitForFunction(() => document.querySelector("#content")?.children.length > 0);
    }

    /**
     * Type a code and submit. The form carries no action, so it posts to the page's own URL and AM
     * answers with a fresh document that boots this entry point again — which is why callers assert
     * on an element unique to the new page before reading pageData, rather than the other way round.
     */
    async function submitUserCode (page, userCode) {
        await page.fill(SEL.codeInput, userCode);
        await page.locator(SEL.submit).click();
    }

    test("the verification form renders for a user who is not logged in", async ({ page }) => {
        await openVerificationForm(page);

        // The premise of the whole flow: the owner arrives from a device that cannot show them a login
        // page, so this page must render for a browser with no session. AM answers a request that
        // needs one with a redirect to /UI/Login — it does exactly that for a user code submitted
        // anonymously — so still being on the verification URL is what proves this one did not.
        expect(page.url(), "the verification form must render without a session").toBe(DEVICE_USER_URL);

        await expect(page.locator(SEL.form)).toBeVisible();
        await expect(page.locator(SEL.formInfo)).toHaveText(bundle.form.description);
        await expect(page.locator(SEL.codeLabel)).toHaveText(bundle.form.code);
        await expect(page.locator(SEL.codeInput)).toHaveAttribute("placeholder", bundle.form.code);
        await expect(page.locator(SEL.codeInput)).toHaveAttribute("name", "user_code");
        await expect(page.locator(SEL.submit)).toHaveText(bundle.form.submit);

        // The resolved theme reached the two templates that render from it. The other two states share
        // these, so they are asserted once, here.
        const theme = await page.evaluate(() => window.pageData.theme);
        await expect(page.locator(SEL.logo)).toHaveAttribute("src", theme.settings.loginLogo.src);
        await expect(page.locator(SEL.footer)).toContainText(theme.settings.footer.mailto);
    });

    test("an unknown code renders the error branch of the same template", async ({ page }) => {
        await openVerificationForm(page);
        await submitUserCode(page, "NOSUCHCODE");

        // AM looks the code up before it validates any session, so this stays an anonymous request.
        await expect(page.locator(SEL.errorPanel)).toBeVisible();

        const errorCode = await page.evaluate(() => window.pageData.errorCode);
        expect(errorCode, "AM must have rejected the code").toBe("not_found");
        // DeviceTemplate translates whatever key AM put in pageData, so the message is the XUI's, and
        // the bundle is what says which one.
        await expect(page.locator(SEL.errorPanel)).toHaveText(bundle[errorCode]);

        // And it really is the template's other branch: nothing left to submit.
        await expect(page.locator(SEL.form)).toHaveCount(0);
    });

    test("a submitted user code authorizes the device and renders the done page", async ({ page, request }) => {
        const userCode = await requestUserCode(request);

        // The one state that needs a session: AM resolves the resource owner before it marks the
        // device code authorized, and redirects to the login page if it cannot.
        await loginViaXui(page, USERNAME, PASSWORD);
        await openVerificationForm(page);
        await submitUserCode(page, userCode);

        await expect(page.locator(SEL.done)).toBeVisible();
        await expect(page.locator(SEL.done)).toHaveText(bundle.common.form.thankYou);

        // Reaching this page is itself the assertion that the form posted a usable user_code: AM
        // returns CodeThanks.ftl only after it has authorized the device code, and answers anything
        // else with the form again. So `done` selecting the other template is the last thing to check.
        const pageData = await page.evaluate(() => window.pageData);
        expect(pageData.done, "the done page is what selects DeviceDoneTemplate").toBe(true);
        await expect(page.locator(SEL.form)).toHaveCount(0);

        // Recorded, not asserted: CodeThanks.ftl renders `realm : "${realm?js_string}/XUI"`, so this
        // page's pageData.realm is "//XUI" rather than "/". main-device.js feeds it to
        // Configuration.globalData.realm, which is what ThemeManager maps a realm to a theme by, so a
        // realm with its own theme gets the default theme on this page alone. That is an AM-side
        // defect in the template, not the XUI's, and phase 0a records today's behaviour rather than
        // changing it — pinning the wrong value here would make a later fix look like a regression.
    });
});
