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

/*
 * Cover for /.well-known/webfinger (OIDC issuer discovery, RFC 7033), the last Restlet area and the subject
 * of phase 6 of the migration (docs/migration/restlet/plan.md).
 *
 * ⚠ THIS ENDPOINT IS BROKEN TODAY, and was already broken before the migration started -- this is a
 * pre-existing defect, not a regression. Root cause: web.xml mounts the WebFinger application on UPSTREAM
 * `org.restlet.ext.servlet.ServerServlet`, while `OpenIDConnectDiscovery` reads the servlet request through
 * OpenAM's own `org.forgerock.openam.rest.jakarta.servlet.ServletUtils.getRequest(...)`. That helper only
 * recognises OpenAM's own `ServletCall`, so under the upstream servlet it returns null and
 * `baseUrlProviderFactory.get(realm).getRootURL(null)` throws -- every request becomes a 500.
 *
 * ⚠ WHOEVER LANDS PHASE 6 WILL SEE BOTH TESTS IN THIS FILE GO RED, AND THAT IS THE SUCCESS SIGNAL.
 *   - "returns a JRD ..." is marked `test.fail()` -- it asserts what the endpoint OUGHT to return, so
 *     Playwright reports "expected to fail but passed". Delete the `test.fail()` line; do not weaken the
 *     assertion.
 *   - "records the current live response" pins the 500 so phase 6 can tell "still broken the same way" from
 *     "broken a new way". Once the port lands, delete that test outright -- the JRD test replaces it.
 */

import { test, expect } from "@playwright/test";
import { OPENAM_BASE } from "../common/openam-commons.mjs";

const ISSUER_REL = "http://openid.net/specs/connect/1.0/issuer";
const RESOURCE = "acct:demo@example.com";

test.describe("/.well-known/webfinger", () => {

  test("records the current live response for an issuer lookup", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/.well-known/webfinger`, {
      params: { resource: RESOURCE, rel: ISSUER_REL, realm: "/" },
    });
    const body = await response.text();
    console.log(`[webfinger] issuer lookup -> ${response.status()} ct=${response.headers()["content-type"]} ${body.slice(0, 200)}`);

    // Recorded, not endorsed: the endpoint NPEs internally (see the file header) and Restlet renders its
    // generic 500. Pinned so phase 6 can tell "still broken the same way" from "broken a new way", and so
    // this suite reports the truth rather than skipping the endpoint. Asserted on the raw text rather than
    // via JSON.parse so that an HTML error page produces a readable diff instead of a SyntaxError.
    expect(response.status()).toBe(500);
    expect(body).toContain('"error":"Internal Server Error"');
  });

  test("returns a JRD naming the issuer for a known account", async ({ request }) => {
    test.fail(true, "Pre-existing defect: ServletUtils.getRequest returns null under the upstream " +
      "ServerServlet, so getRootURL(null) throws. Expected to be fixed by the phase-6 CHF port -- when " +
      "this starts passing, remove this test.fail().");

    const response = await request.get(`${OPENAM_BASE}/.well-known/webfinger`, {
      params: { resource: RESOURCE, rel: ISSUER_REL, realm: "/" },
    });

    expect(response.status()).toBe(200);
    const jrd = await response.json();
    expect(jrd.subject).toBe(RESOURCE);
    expect(Array.isArray(jrd.links)).toBe(true);
    const issuer = jrd.links.find((link) => link.rel === ISSUER_REL);
    expect(issuer).toBeTruthy();
    expect(issuer.href).toBe(`${OPENAM_BASE}/oauth2`);
  });
});
