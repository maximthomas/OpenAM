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
 * Shared primitives for the XUI specs: how you reach a route, how you log in and out through the
 * form, how you ask the server whether a session exists, and how you observe the UI's own
 * notifications.
 *
 * These belong in one place because the XUI migration is what this suite exists to guard. Every
 * spec that drives the login form is asserting something else — theming, module loading, admin
 * CRUD — and none of them should carry their own idea of what the login form looks like.
 */

import { expect } from "@playwright/test";
import { OPENAM_BASE } from "./openam-commons.mjs";

export const XUI_BASE = `${OPENAM_BASE}/XUI`;

/** The default realm, as the REST API names it. */
export const DEFAULT_REALM = "/";

export const SEL = {
    usernameInput: "#idToken1",
    passwordInput: "#idToken2",
    // The submit button id varies between XUI builds (loginButton / loginButton_0 / none),
    // so match by submit type as the working SAML spec does.
    loginButton: "#loginButton, input[type=\"submit\"], button[type=\"submit\"]",
    // Where commons' Messages component renders notifications.
    messages: "#messages",
};

/**
 * The deployed locale bundle for an entry point's i18n namespace.
 *
 * Fetched from the instance rather than read from the source tree, so a spec that asserts its strings
 * against it also asserts the bundle was packaged and served — which is what makes it a guard on the
 * migration copying `locales/` verbatim, and on the entry point still selecting its own namespace
 * rather than falling back to the console's.
 *
 * `en` and not the browser's own locale: pageData.locale carries the Accept-Language Chromium sends
 * (en-us), the tree ships only locales/en, and i18next falls back to it. That fallback is itself part
 * of today's behaviour.
 */
export async function localeBundle (request, nameSpace) {
    const url = `${XUI_BASE}/locales/en/${nameSpace}.json`;
    const response = await request.get(url);

    expect(response.ok(), `the ${nameSpace} locale bundle must be served at ${url}`).toBeTruthy();
    return response.json();
}

/** Absolute URL for a XUI route, e.g. xuiUrl("#login/"). */
export function xuiUrl (hash = "") {
    return `${XUI_BASE}/${hash}`;
}

/** Open a XUI route and wait for the login form to be rendered on it. */
export async function openLoginForm (page, hash = "#login/") {
    await page.goto(xuiUrl(hash));
    await expect(page.locator(SEL.usernameInput)).toBeVisible({ timeout: 20_000 });
}

/** Fill and submit the login form. Does not wait for the outcome — see loginViaXui. */
export async function submitCredentials (page, user, pass) {
    await page.fill(SEL.usernameInput, user);
    await page.fill(SEL.passwordInput, pass);
    await page.locator(SEL.loginButton).first().click();
}

/** Log in through the XUI login form and wait until the user leaves the #login route. */
export async function loginViaXui (page, user, pass) {
    await openLoginForm(page);
    await submitCredentials(page, user, pass);
    await page.waitForURL((url) => !url.hash.startsWith("#login"), { timeout: 30_000 });
}

/** Log out through the XUI and wait until it settles on the logged-out or login route. */
export async function logoutViaXui (page) {
    await page.goto(xuiUrl("#logout/"));
    await page.waitForURL((url) => /^#(loggedOut|login)/.test(url.hash), { timeout: 30_000 });
}

/**
 * Resolve the active session from the (auto-sent) session cookie, or null when there is none.
 * Returns the whole response so callers can assert on the realm as well as the user.
 *
 * Only an explicit "not authenticated" answer counts as "no session". Treating every failed
 * response that way would make a 500 or a 503 indistinguishable from a logged-out user, and the
 * assertions that matter most here are the negative ones — a rejected login and a completed
 * logout both prove themselves by this returning null. The suite runs with no retries precisely
 * so intermittents surface, so it must not swallow them.
 */
export async function sessionInfo (request) {
    const resp = await request.post(`${OPENAM_BASE}/json/users?_action=idFromSession`, {
        headers: { "Accept-API-Version": "protocol=1.0,resource=2.0" },
    });
    // AM answers 401 with no session; IdentityResourceV2 raises ForbiddenException (403) on some
    // paths and RESTLoginHelper registers handlers for both, so accept either.
    if (resp.status() === 401 || resp.status() === 403) {
        return null;
    }
    expect(
        resp.ok(),
        `idFromSession answered ${resp.status()}: ${await resp.text()}`
    ).toBeTruthy();
    return resp.json();
}

/** The username of the active session, or null when there is none. */
export async function idFromSession (request) {
    const info = await sessionInfo(request);
    return info === null ? null : info.id;
}

/**
 * Start recording the notifications the UI raises, and return a reader for them.
 *
 * Polling for the alert itself would be a race: commons' Messages component removes a message
 * after roughly 2.5-3.5 seconds (`delay` plus 20ms per character, Messages.js), so on a loaded
 * machine an assertion can arrive after the alert has already faded. Recording every message as
 * it is added makes the assertion independent of when it runs.
 *
 * Install this before the action that triggers the message; it does not survive a page load.
 */
export async function captureMessages (page) {
    await page.waitForSelector(SEL.messages, { state: "attached" });
    await page.evaluate((sel) => {
        window.__xuiMessages = [];
        // Installing twice on one page would otherwise leave two observers feeding one array.
        window.__xuiMessageObserver?.disconnect();
        window.__xuiMessageObserver = new MutationObserver((records) => {
            for (const record of records) {
                for (const node of record.addedNodes) {
                    if (node.nodeType !== Node.ELEMENT_NODE) {
                        continue;
                    }
                    window.__xuiMessages.push({
                        text: (node.textContent ?? "").trim(),
                        className: node.className ?? "",
                    });
                }
            }
        });
        window.__xuiMessageObserver.observe(document.querySelector(sel), {
            childList: true,
            subtree: true,
        });
    }, SEL.messages);

    return () => page.evaluate(() => window.__xuiMessages ?? []);
}
