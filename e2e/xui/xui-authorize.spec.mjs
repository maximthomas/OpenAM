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
 * OpenAM XUI — the OAuth2 consent screen, which is the `main-authorize` entry point.
 *
 * The second of the XUI's three entry points, and the first one covered here that is not `main.js`.
 * It is a different application from the console: AM's authorize endpoint serves its own HTML
 * (openam-oauth2 templates/page/authorize.ftl and templates/page/error.ftl), puts the whole
 * authorization request into a `window.pageData` global, and boots RequireJS with
 * `data-main=…/XUI/main-authorize`. There is no router, no session bootstrap and no service layer —
 * `main-authorize.js` reads pageData, resolves the theme, fetches four templates by path, compiles
 * them and writes the result into the DOM.
 *
 * What this is guarding. That short list is nearly all of what the Vite/ESM migration re-implements,
 * on a page that shares no code path with the console:
 *
 *   - a second entry point exists at all and is reachable at the URL AM hardcodes into its own HTML
 *     (design.md D7, task 4.2 — a multi-entry build that emitted one bundle would fail here alone);
 *   - `require.config.map` rebinding, declared separately in main-authorize.js from main.js (D2);
 *   - templates and locales fetched by path at runtime and compiled in the browser, here through the
 *     `text!` plugin rather than UIUtils, and prefixed with the theme path (D3, and main-authorize.js:133
 *     is the second consumer of the theme-path contract named by task 5.5). The strings this page owns
 *     are asserted against the deployed locales/en/authorize.json, so this fails if the bundle stops
 *     being copied verbatim or the entry point stops selecting the "authorize" namespace;
 *   - the theme stylesheets being applied — `authorize.ftl` ships `<body style="display:none">` and
 *     nothing in the page removes it, so the page becomes visible only once ThemeManager has
 *     appended structure.css, whose `body { display: block !important }` overrides it. Every
 *     toBeVisible() below therefore also asserts the theme was applied.
 *
 * Deliberately not asserted: AM's own strings — the error wording, the scope names, the client's
 * display name. Each test reads `window.pageData` and asserts the DOM renders *that*, so an AM
 * message change stays an AM message change; what the XUI decides is how pageData becomes a page.
 * The same rule xui-login.spec.mjs applies to the failure notification. The XUI's own strings are a
 * different matter and are asserted, against the bundle they come from.
 */

import { test, expect } from "@playwright/test";
import { PASSWORD, USERNAME, getAdminToken } from "../common/openam-commons.mjs";
import {
    AUTHORIZE_URL,
    CONSENT_CLIENT_ID,
    REDIRECT_URI,
    SCOPE,
    ensureOAuth2ClientExists,
    ensureOAuth2ServiceExists,
    generateChallenge,
    generateVerifier,
} from "../common/oauth2-commons.mjs";
import { loginViaXui, localeBundle } from "../common/xui-commons.mjs";

const STATE = "xui-consent-state";

// Everything main-authorize renders lands in #content, which is itself rendered by LoginBaseTemplate
// into the #wrapper that authorize.ftl ships. Scoping to it keeps these off the page's own markup.
const SEL = {
    content: "#content",
    title: "#content .page-header h1.text-center",
    form: "#content form",
    errorPanel: "#content div.alert.alert-warning",
    signedInAs: "#content span.text-primary",
    scopePanel: "#content .panel",
    allow: "#content button[name=\"decision\"][value=\"allow\"]",
    deny: "#content button[name=\"decision\"][value=\"deny\"]",
    hidden: (name) => `#content input[type="hidden"][name="${name}"]`,
};

/**
 * Deployed AM only. The consent screen is delivered by AM's /oauth2/…/authorize endpoint, not from
 * the XUI tree, and rendering it means running AM's own OAuth2 request validation, consent decision
 * and token issuance. design.md scopes the local API server to authentication and session,
 * serverinfo, site configuration, and realm and service administration; serving this page would mean
 * reimplementing the thing under test, which is the case D16 names as deployed-AM-only. Revisit only
 * if phase 0b's coverage question is answered the other way — see task 2.13.
 */
test.describe("XUI OAuth2 consent screen (main-authorize entry point)", { tag: ["@deployed-am"] }, () => {
    /** The oracle for the strings this page owns, as opposed to the ones AM supplies. */
    let bundle;

    test.beforeAll(async ({ request }) => {
        const adminToken = await getAdminToken(request);
        expect(adminToken, "the fixtures need an admin session").toBeTruthy();

        await ensureOAuth2ServiceExists(adminToken, request);
        await ensureOAuth2ClientExists(adminToken, request, CONSENT_CLIENT_ID, false);

        bundle = await localeBundle(request, "authorize");
    });

    /**
     * The authorization request. PKCE is mandatory — the client is public and authenticates with
     * "none" — and a fresh challenge per call keeps the tests independent of one another.
     */
    async function authorizeRequest (overrides) {
        return {
            response_type: "code",
            client_id: CONSENT_CLIENT_ID,
            redirect_uri: REDIRECT_URI,
            scope: SCOPE,
            state: STATE,
            code_challenge: await generateChallenge(generateVerifier()),
            code_challenge_method: "S256",
            ...overrides,
        };
    }

    /**
     * Log in, issue an authorization request, and wait until the entry point has rendered something.
     *
     * The wait is on #content having children rather than on a particular element, because which
     * element appears is what the tests below disagree about: the consent form, or the error panel.
     */
    async function openAuthorizeRequest (page, overrides) {
        await loginViaXui(page, USERNAME, PASSWORD);

        const params = new URLSearchParams(await authorizeRequest(overrides));
        await page.goto(`${AUTHORIZE_URL}?${params}`);
        await page.waitForFunction(() => document.querySelector("#content")?.children.length > 0);
    }

    /**
     * Post the resource owner's decision, and return where AM then sent the browser.
     *
     * The client application does not exist — RFC 6761 reserves .invalid precisely so that it cannot
     * resolve — so the browser never completes the navigation AM redirects it to. It does issue the
     * request, and the request URL is what carries AM's answer, so waiting on the request rather than
     * on the navigation is what makes a fictional client sufficient. Stubbing the callback instead
     * does not work: page.route() is not consulted for the redirect target of a request that was not
     * itself intercepted, and AM's redirect is exactly that.
     *
     * The wait is armed before the click and settled together with it, so a click that throws cannot
     * leave a 30-second wait pending to reject afterwards, unhandled, on top of another test.
     */
    async function postDecision (page, decision) {
        const [request] = await Promise.all([
            page.waitForRequest((req) => req.url().startsWith(REDIRECT_URI), { timeout: 30_000 }),
            page.locator(SEL[decision]).click(),
        ]);
        return new URL(request.url());
    }

    test("the consent screen renders the authorization request", async ({ page }) => {
        await openAuthorizeRequest(page);

        // The oracle for this test is the page's own pageData, not a literal: the XUI's job here is to
        // render what AM put on the page.
        const oauth2Data = await page.evaluate(() => window.pageData.oauth2Data);

        await expect(page.locator(SEL.form)).toBeVisible();
        await expect(page.locator(SEL.form)).toHaveAttribute("action", oauth2Data.formTarget);
        // displayName arrives HTML-encoded — ConsentRequiredResource runs it through ESAPI — and the
        // template emits it triple-stashed, so the browser decodes it back. The two sides agree here
        // only because the fixture client's name has no character outside ESAPI's immune set; a
        // display name with an apostrophe or an ampersand would need this to decode first.
        await expect(page.locator(SEL.title)).toHaveText(oauth2Data.displayName);
        await expect(page.locator(SEL.signedInAs)).toHaveText(oauth2Data.userName);

        // The prompt and the two button labels are the XUI's own strings, from its own namespace —
        // AM supplies none of them. Rendering the raw keys is what a lost locales/ copy step or a
        // dropped namespace looks like, and it is otherwise invisible to a spec that reads pageData.
        await expect(page.locator(SEL.form)).toContainText(bundle.form.description);
        await expect(page.locator(SEL.form)).toContainText(bundle.form.signedInAs);
        await expect(page.locator(SEL.allow)).toHaveText(bundle.form.allow);
        await expect(page.locator(SEL.deny)).toHaveText(bundle.form.deny);

        // One panel per scope and per claim, each headed by the name AM supplied. A migration that
        // broke template compilation renders the page with no panels rather than failing outright.
        const panelNames = [...oauth2Data.displayScopes, ...oauth2Data.displayClaims].map((s) => s.name);
        expect(panelNames.length, "the request must ask for something to consent to").toBeGreaterThan(0);
        await expect(page.locator(`${SEL.scopePanel} .panel-heading`)).toHaveText(panelNames);

        // The decision cannot be posted without these, and they are the part of the form a rendering
        // regression breaks silently — the page still looks right.
        await expect(page.locator(SEL.hidden("client_id"))).toHaveValue(CONSENT_CLIENT_ID);
        await expect(page.locator(SEL.hidden("response_type"))).toHaveValue("code");
        await expect(page.locator(SEL.hidden("redirect_uri"))).toHaveValue(REDIRECT_URI);
        await expect(page.locator(SEL.hidden("scope"))).toHaveValue(SCOPE);
        await expect(page.locator(SEL.hidden("state"))).toHaveValue(STATE);
        // A server-rendered random value, not the session cookie — which is what lets the cookie be
        // HttpOnly (main-authorize.js:115-117). Its correctness is proved by the allow test below.
        // Guarded before it is used as an expectation: toHaveValue(undefined) would spend the whole
        // expect timeout and then report a value mismatch instead of "AM sent no csrf token".
        expect(oauth2Data.csrf, "AM must supply a csrf token to post the decision with").toBeTruthy();
        await expect(page.locator(SEL.hidden("csrf"))).toHaveValue(oauth2Data.csrf);

        await expect(page.locator(SEL.allow)).toBeVisible();
        await expect(page.locator(SEL.deny)).toBeVisible();
    });

    test("a scope panel expands to show the values it covers", async ({ page }) => {
        await openAuthorizeRequest(page);

        // The one behaviour main-authorize.js implements itself rather than delegating to a view: it
        // binds "click keyup" on .panel-heading and toggles the panel below (main-authorize.js:149-156).
        // Scopes that carry values get a collapsible panel; a scope with none is a plain heading.
        const collapsible = page.locator(`${SEL.scopePanel}.panel-info`).first();
        await expect(collapsible, "the profile scope carries the values it would disclose").toBeVisible();

        const body = collapsible.locator(".panel-collapse");
        await expect(body).toBeHidden();

        await collapsible.locator(".panel-heading").click();

        await expect(body).toBeVisible();
        await expect(body).not.toBeEmpty();
    });

    test("allowing the request returns an authorization code to the client", async ({ page }) => {
        await openAuthorizeRequest(page);

        // The point of the test: the form the XUI rendered carries everything AM needs, including a
        // csrf value AM accepts. Anything missing or mangled comes back as an error, not a code.
        const callback = await postDecision(page, "allow");
        expect(callback.searchParams.get("error"), "allow must not return an error").toBeNull();
        expect(callback.searchParams.get("code"), "allow must return an authorization code").toBeTruthy();
        expect(callback.searchParams.get("state")).toBe(STATE);
    });

    test("denying the request returns access_denied to the client", async ({ page }) => {
        await openAuthorizeRequest(page);

        // Deny is the same form posting the same fields with a different button value, so it is the
        // assertion that the two buttons are actually distinguishable to the server.
        const callback = await postDecision(page, "deny");
        expect(callback.searchParams.get("code"), "deny must not return a code").toBeNull();
        expect(callback.searchParams.get("error")).toBe("access_denied");
        expect(callback.searchParams.get("state")).toBe(STATE);
    });

    test("a rejected authorization request renders the error panel", async ({ page }) => {
        // A redirect URI the client has not registered. AM has nowhere safe to send the error, so it
        // renders its error page — which boots this same entry point with an `error` in pageData and no
        // oauth2Data, and AuthorizeTemplate takes its other branch. Chosen over an unknown client_id
        // because here the client is real and the request otherwise complete, so the branch under test
        // is reached deliberately rather than by an unprovisioned instance.
        await openAuthorizeRequest(page, { redirect_uri: "http://not-registered.invalid/cb" });

        const error = await page.evaluate(() => window.pageData.error);
        expect(error, "AM must have rejected the request").toBeTruthy();
        // error.ftl emits the description only under <#if error_description??>, so a rejection raised
        // without one would otherwise reach toContainText(undefined) and fail on a timeout rather than
        // on the fact that AM said nothing.
        expect(error.description, "AM must describe why it rejected the request").toBeTruthy();

        await expect(page.locator(SEL.errorPanel)).toBeVisible();
        await expect(page.locator(`${SEL.errorPanel} strong`)).toHaveText(error.message);
        await expect(page.locator(SEL.errorPanel)).toContainText(error.description);

        // And the other branch really is the other branch: no form to post a decision from.
        await expect(page.locator(SEL.form)).toHaveCount(0);
    });
});
