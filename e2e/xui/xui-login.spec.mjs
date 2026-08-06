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
 * OpenAM XUI - login and logout in the default realm.
 *
 * The baseline case of the migration's regression net: a user reaches the login form, submits
 * credentials, and the XUI decides where they land and what it does when they leave.
 *
 * What this is actually guarding. Landing is not a redirect the server issues -- it is a decision
 * the XUI makes in the browser, in the EVENT_HANDLE_DEFAULT_ROUTE handler (config/process/
 * AMConfig.js): no session goes to #login, a session holding the ui-realm-admin role goes to the
 * realms console, anything else goes to the user's profile. Reaching either destination therefore
 * requires the whole chain to be intact -- the router resolving a route to a view module by string
 * identifier, ModuleLoader fetching it, and the view's template being fetched by path and compiled
 * at runtime. Those are exactly the three mechanisms the Vite/ESM migration re-implements
 * (design.md D1, D2, D3), so a break in any of them surfaces here as the wrong landing route or an
 * empty page rather than as a failed request.
 *
 * The two roles are covered separately because they exercise different halves of the application:
 * the end-user views, and the admin console. A migration that broke only one of the two would
 * otherwise pass.
 *
 * Deliberately not asserted: the wording of the failure notification. AM supplies that text in the
 * authentication response, so pinning it would make an AM message change look like a UI
 * regression. What the XUI decides -- that the failure is shown as a danger alert, that the form
 * stays put, and that no session is established -- is what this asserts.
 */

import { test, expect } from "@playwright/test";
import { ADMIN_USER, ADMIN_PASS, USERNAME, PASSWORD } from "../common/openam-commons.mjs";
import {
    DEFAULT_REALM,
    SEL,
    captureMessages,
    loginViaXui,
    logoutViaXui,
    openLoginForm,
    sessionInfo,
    submitCredentials,
    xuiUrl,
} from "../common/xui-commons.mjs";

// Valid against both backends: every assertion here is either UI routing or a REST call the local
// API server is committed to implementing -- authentication, cookie-only session resolution and
// logout (tasks 2.7-2.8), plus, for the admin case, the realm and service reads the console's
// landing view issues (tasks 2.10-2.11). Nothing here asserts AM-specific server behaviour --
// contrast xui-httponly.spec.mjs, which does and is therefore deployed-AM-only.
test.describe("XUI login and logout (default realm)", { tag: ["@deployed-am", "@local-server"] }, () => {
    test("end user logs in and lands on their profile", async ({ page }) => {
        await loginViaXui(page, USERNAME, PASSWORD);

        // The end-user branch of the default-route decision.
        await expect(page).toHaveURL(xuiUrl("#profile/details"));
        await expect(page.getByRole("heading", { name: "User profile" })).toBeVisible();

        // The session is real, and it is in the default realm.
        const session = await sessionInfo(page.request);
        expect(session, "a session must exist after logging in").not.toBeNull();
        expect(String(session.id).toLowerCase()).toBe(USERNAME.toLowerCase());
        expect(session.realm, "login must land in the default realm").toBe(DEFAULT_REALM);
    });

    test("administrator logs in and lands on the realms console", async ({ page }) => {
        await loginViaXui(page, ADMIN_USER, ADMIN_PASS);

        // The ui-realm-admin branch of the same decision. Reaching it means the admin view module
        // resolved and rendered, which the end-user case above does not prove.
        await expect(page).toHaveURL(xuiUrl("#realms"));
        // Exact and level-scoped: the realm cards below the title are headings too, and task 1.6
        // will start creating realms with arbitrary names in this same instance.
        await expect(page.getByRole("heading", { level: 1, name: "Realms", exact: true }))
            .toBeVisible();

        const session = await sessionInfo(page.request);
        expect(session, "a session must exist after logging in").not.toBeNull();
        expect(String(session.id).toLowerCase()).toBe(ADMIN_USER.toLowerCase());
        expect(session.realm, "login must land in the default realm").toBe(DEFAULT_REALM);
    });

    // Fails a login as the same user the other tests log in as. Safe because account lockout is
    // off in a default AM, but the coupling is real: enabling it would make this test poison the
    // ones after it, since the whole file runs against one instance in one worker.
    test("invalid credentials are rejected without establishing a session", async ({ page }) => {
        await openLoginForm(page);
        const messages = await captureMessages(page);

        await submitCredentials(page, USERNAME, "not-the-password");

        // The failure has to be visible to the user, and shown as a failure. Recorded rather than
        // polled for, because the alert removes itself after a few seconds. Polling for the danger
        // alert specifically rather than for any message: an unrelated notification arriving first
        // would otherwise satisfy the wait before the one under test had been raised.
        await expect.poll(
            async () => (await messages()).filter((m) => m.className.includes("alert-danger")),
            { message: "a failed login must be shown as a danger alert", timeout: 30_000 }
        ).not.toHaveLength(0);

        // A first-stage failure leaves the form in place rather than routing away from it, so the
        // user can try again: RESTLoginHelper only calls ViewManager.refresh() past the first
        // stage, and RESTLoginView only routes to loginUnavailable past it.
        await expect(page).toHaveURL(xuiUrl("#login/"));
        await expect(page.locator(SEL.usernameInput)).toBeVisible();

        // The point of the test: nothing was authenticated.
        expect(await sessionInfo(page.request), "a rejected login must not establish a session")
            .toBeNull();
    });

    test("logout ends the session and protected routes return to the login form", async ({ page }) => {
        await loginViaXui(page, USERNAME, PASSWORD);
        expect(await sessionInfo(page.request), "precondition: logged in").not.toBeNull();

        await logoutViaXui(page);

        await expect(page).toHaveURL(xuiUrl("#loggedOut/"));
        await expect(page.getByRole("heading", { name: "You have been logged out." })).toBeVisible();
        await expect(page.locator("a[data-return-to-login-page]")).toBeVisible();

        // The browser cookie is not the thing to check -- in HttpOnly mode JavaScript cannot clear
        // it and a dead cookie can linger. What matters is that the server stops resolving it.
        expect(await sessionInfo(page.request), "the session must be invalid after logout")
            .toBeNull();

        // And the UI agrees: a route that needs a session sends the user back to the form rather
        // than rendering with stale in-memory state.
        await page.goto(xuiUrl("#profile/details"));
        await page.waitForURL((url) => url.hash.startsWith("#login"), { timeout: 30_000 });
        await expect(page.locator(SEL.usernameInput)).toBeVisible();
    });
});
