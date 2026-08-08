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
 * Cover for /.well-known/webfinger (OIDC issuer discovery, RFC 7033), the last Restlet area and the subject of
 * phase 5d-2a (docs/migration/restlet/plan.md) -- phase 6, which used to own it, was absorbed into 5d-2 on
 * 2026-08-06 because WebFinger held twelve of the classes 5d-2 exists to delete.
 *
 * ⚠ THIS ENDPOINT WAS BROKEN, and had been since long before the migration started -- a pre-existing defect,
 * not a regression, and the one user-visible thing the port FIXED. Root cause: web.xml mounted the WebFinger
 * application on UPSTREAM `org.restlet.ext.servlet.ServerServlet`, while `OpenIDConnectDiscovery` read the
 * servlet request through OpenAM's own `org.forgerock.openam.rest.jakarta.servlet.ServletUtils.getRequest(...)`.
 * That helper only recognises OpenAM's own `ServletCall`, so under the upstream servlet it returned null and
 * `baseUrlProviderFactory.get(realm).getRootURL(null)` threw -- every request became a 500. Measured byte for
 * byte before the flip (artefacts/well-known-probes-pre-flip.md): fourteen of nineteen probes, one identical
 * 149-byte `{"error":"Internal Server Error",...}`, md5 dd82fa5d.
 *
 * The CHF port landed in phase 5d-2a-ii (docs/migration/restlet/phase-5d-2.md). The NPE preceded
 * `discover(...)`, so this endpoint's VALIDATION PATHS -- the 400s and the 404 -- never executed at all and
 * have NO PARITY BASELINE: nothing below is a recording of Restlet. Every value is the target contract, taken
 * from `WellKnownRouterIT` and `WebFingerHandlerTest` in openam-oauth2, and these rows are the e2e witness for
 * divergence rows 33-36 of docs/migration/restlet/plan.md.
 */

import { test, expect } from "@playwright/test";
import { OPENAM_BASE, getAdminToken } from "../common/openam-commons.mjs";
import { ensureProviderConfig } from "../common/oauth2-fixtures.mjs";

const ISSUER_REL = "http://openid.net/specs/connect/1.0/issuer";
const RESOURCE = "acct:demo@example.com";

// Parse via text, not response.json(): a stray HTML error page should fail as a readable diff naming the
// status and content-type, not as a bare SyntaxError. The incumbent rendered its 500 as text/html on HEAD.
async function readJson(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`expected JSON, got ${response.status()} `
      + `${response.headers()["content-type"]}: ${text.slice(0, 200)}`);
  }
}

test.beforeAll(async ({ request }) => {
  // The JRD rows need an OIDC provider in the root realm. Spec files run in any order, so create it here
  // rather than inheriting it from whichever suite happened to run first.
  const adminToken = await getAdminToken(request);
  if (!adminToken) {
    test.skip(true, "ADMIN_TOKEN not set");
  }
  await ensureProviderConfig(adminToken, request);
});

test.describe("/.well-known/webfinger", () => {

  test("returns a JRD naming the issuer for a known account", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/.well-known/webfinger`, {
      params: { resource: RESOURCE, rel: ISSUER_REL, realm: "/" },
    });
    const jrd = await readJson(response);
    console.log(`[webfinger] issuer lookup -> ${response.status()} ${JSON.stringify(jrd)}`);

    expect(response.status()).toBe(200);
    // toContain, not toBe: the unit tests pin `application/json; charset=UTF-8` at the handler, but how the
    // container renders that header end to end has not been measured, and the media type is the contract.
    expect(response.headers()["content-type"]).toContain("application/json");
    expect(jrd.subject).toBe(RESOURCE);
    expect(Array.isArray(jrd.links)).toBe(true);
    const issuer = jrd.links.find((link) => link.rel === ISSUER_REL);
    expect(issuer).toBeTruthy();
    // The href is realm-derived: it is the BaseURLProvider of the resolved realm, not a constant, which is why
    // every realm-spelling row below re-asserts it rather than settling for the status.
    expect(issuer.href).toBe(`${OPENAM_BASE}/oauth2`);
  });

  test("a missing resource is a 400 bad_request", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/.well-known/webfinger`, {
      params: { rel: ISSUER_REL },
    });
    const body = await readJson(response);
    console.log(`[webfinger] no resource -> ${response.status()} ${JSON.stringify(body)}`);

    expect(response.status()).toBe(400);
    expect(body.error).toBe("bad_request");
    expect(body.error_description).toBe("No resource provided in discovery.");
  });

  test("a missing or wrong rel is a 400 bad_request", async ({ request }) => {
    // Two inputs, one message: `discover` treats absent and non-issuer rel identically, and the wrong-rel leg
    // is the one that proves the value is compared rather than merely required.
    const cases = {
      "no rel": { resource: RESOURCE },
      "wrong rel": { resource: RESOURCE, rel: "http://example.com/not-the-issuer-rel" },
    };
    for (const [name, params] of Object.entries(cases)) {
      const response = await request.get(`${OPENAM_BASE}/.well-known/webfinger`, { params });
      const body = await readJson(response);
      console.log(`[webfinger] ${name} -> ${response.status()} ${JSON.stringify(body)}`);

      expect(response.status(), name).toBe(400);
      expect(body.error, name).toBe("bad_request");
      expect(body.error_description, name).toBe("No or invalid rel provided in discovery.");
    }
  });

  test("an unknown user is a 404 not_found", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/.well-known/webfinger`, {
      params: { resource: "acct:nobody@example.com", rel: ISSUER_REL },
    });
    const body = await readJson(response);
    console.log(`[webfinger] unknown user -> ${response.status()} ${JSON.stringify(body)}`);

    // 404, not 400: the account parses fine, it just does not exist -- `isUserValid` is the only check that
    // raises NotFoundException, so a 400 here would mean the resource never reached the identity lookup.
    expect(response.status()).toBe(404);
    expect(body.error).toBe("not_found");
    expect(body.error_description).toBe("Invalid parameters.");
  });

  test("the /realms/{realm} path spelling resolves to the same provider", async ({ request }) => {
    // This spelling resolves to realm `/`, and it is the row that settles a disagreement: the pre-flip
    // artefact predicted a 404 for it (well-known-probes-pre-flip.md probe 11, grouped with the no-match
    // rows), while `WellKnownRouterIT.theRealmsPathStyleReachesTheEndpoint` asserts 200. Only the container
    // can say which is true of the shipped chain.
    const response = await request.get(`${OPENAM_BASE}/.well-known/realms/root/webfinger`, {
      params: { resource: RESOURCE, rel: ISSUER_REL },
    });
    const jrd = await readJson(response);
    console.log(`[webfinger] realms/root -> ${response.status()} ${JSON.stringify(jrd)}`);

    expect(response.status()).toBe(200);
    expect(jrd.subject).toBe(RESOURCE);
    const issuer = jrd.links.find((link) => link.rel === ISSUER_REL);
    expect(issuer).toBeTruthy();
    // Same href as the bare path: same realm, therefore same BaseURLProvider, therefore same issuer.
    expect(issuer.href).toBe(`${OPENAM_BASE}/oauth2`);
  });

  test("an unrouted child under /.well-known is a 404 not_found", async ({ request }) => {
    // Restlet's single `attach("/webfinger", ...)` matched far more than its literal path, so this used to
    // reach the discovery resource and 500. The CHF route is EQUALS "webfinger" under STARTS_WITH
    // ".well-known", so the segment is owned and unmatched children fall to OAuth2NotFoundHandler.
    const response = await request.get(`${OPENAM_BASE}/.well-known/nonsense`);
    const body = await readJson(response);
    console.log(`[webfinger] unrouted child -> ${response.status()} ${JSON.stringify(body)}`);

    expect(response.status()).toBe(404);
    expect(body.error).toBe("not_found");
    expect(body.error_description).toBe("Not Found");
  });

  test("an unresolvable realm is a 400 invalid_request in the OAuth2 shape", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/.well-known/webfinger`, {
      params: { resource: RESOURCE, rel: ISSUER_REL, realm: "/bogus" },
    });
    const body = await readJson(response);
    console.log(`[webfinger] bad realm -> ${response.status()} ${JSON.stringify(body)}`);

    expect(response.status()).toBe(400);
    expect(body.error).toBe("invalid_request");
    // The leading slash survives into the message: measured on the container at the 5d-2a-ii flip
    // (artefacts/well-known-probes-post-flip.md probe 08), where WellKnownRouterIT only pins the bare
    // "Invalid realm, bogus" form.
    expect(body.error_description).toBe("Invalid realm, /bogus");
    // The proof that OAuth2ErrorFilter sits OUTSIDE the realm layer. RealmContextFilter raises a CREST
    // BadRequestException, which renders as {code, reason, message}; if any of those three survived, the
    // filter would be mounted inside `root` and this surface would speak two error vocabularies.
    expect(body.code).toBeUndefined();
    expect(body.reason).toBeUndefined();
    expect(body.message).toBeUndefined();
  });

  test("POST is a 405 and advertises the allowed methods", async ({ request }) => {
    // RFC 7033 defines GET only, and the handler carries no @Post, so `Endpoints` refuses the method rather
    // than dispatching it into the @Get the way Restlet did (which is how POST also produced the NPE 500).
    const response = await request.post(`${OPENAM_BASE}/.well-known/webfinger`, {
      params: { resource: RESOURCE, rel: ISSUER_REL, realm: "/" },
    });
    const allow = response.headers()["allow"];
    console.log(`[webfinger] POST -> ${response.status()} allow=${allow}`);

    expect(response.status()).toBe(405);
    // A 405 without Allow is a protocol violation, and Allow is what tells a client the endpoint is read-only.
    expect(allow).toBeTruthy();
    expect(allow).toContain("GET");
  });
});
