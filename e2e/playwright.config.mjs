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

import { defineConfig } from "@playwright/test";

export default defineConfig({
    testDir: ".",
    testMatch: "**/*.spec.mjs",
    timeout: 180000,
    // No retries: this suite is the migration's regression oracle, and a retry turns a real
    // intermittent regression into a green run.
    retries: 0,
    // One worker. Every spec drives the same single AM instance, and the admin specs to come
    // (tasks 1.6 and 1.7) will create and delete realms and services in it, so parallel files
    // would interfere through server state rather than through anything in the tests.
    workers: 1,
    // A stray test.only would shrink the suite without the run saying so.
    forbidOnly: !!process.env.CI,
    use: {
        headless: true,
        ignoreHTTPSErrors: true,
        screenshot: "only-on-failure",
        trace: "retain-on-failure",
    },
    reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
});