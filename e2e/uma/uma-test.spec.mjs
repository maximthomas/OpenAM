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
 * Protocol cover for the three /uma endpoints. Unlike the /oauth2 specs beside it, /uma has ALREADY moved
 * to CHF -- phase 4 flipped it (docs/migration/restlet/phase-4-uma.md) and deferred this smoke suite. That
 * deferral had a price: the flip shipped /uma/.well-known/uma-configuration returning
 * `500 No context of type org.forgerock.json.resource.http.HttpContext found` for every request, because
 * UmaUrisFactory asked for a CREST HttpContext that a plain CHF chain does not carry. Neither
 * UmaRouterIT nor UmaWellKnownConfigurationEndpointTest saw it -- both mock UmaUrisFactory. Only a real
 * request could, which is exactly what this file is for.
 *
 * Two error shapes live here on purpose (phase-4 finding 1 / D5), and the tests assert both:
 *   - the ACCESS TOKEN PROTECTION FILTER answers CREST-shaped: {code, reason, message}
 *   - the ENDPOINTS answer UMA-shaped:                          {error, error_description}
 * Crossing them is the regression this suite is meant to catch.
 */

import { test, expect } from "@playwright/test";
import { OPENAM_BASE, getAdminToken, PASSWORD, USERNAME } from "../common/openam-commons.mjs";
import {
  REALM, authorizationApiToken, deleteResourceSet, ensureProviderConfig, ensureResourceServerClient,
  ensureUmaProvider, protectionApiToken, registerResourceSet as postResourceSet, uniqueName,
  warmUpResourceSetStore,
} from "../common/oauth2-fixtures.mjs";

/** This spec's own client -- see the note in oauth2-fixtures.mjs about per-file ownership. */
const RS_CLIENT_ID = "test_client_rs_uma";

/** Protection API token: the resource server's bearer. */
let pat;
/** Authorization API token: the requesting party's bearer. */
let aat;

/** Resource sets registered by this run, torn down in afterAll. */
const registered = [];

/** Registers a resource set under a name no earlier run can have taken, and returns its id. */
async function registerResourceSet(request, label) {
  const { response } = await postResourceSet(request, pat, uniqueName(label));
  expect(response.status(), `resource_set registration failed: ${await response.text()}`).toBe(201);
  const id = (await response.json())._id;
  registered.push(id);
  return id;
}

test.beforeAll(async ({ request }) => {
  const adminToken = await getAdminToken(request);
  if (!adminToken) {
    test.skip(true, "ADMIN_TOKEN not set");
  }
  await ensureProviderConfig(adminToken, request);
  await ensureUmaProvider(adminToken, request);
  await ensureResourceServerClient(adminToken, request, RS_CLIENT_ID);
  pat = await protectionApiToken(request, RS_CLIENT_ID, USERNAME, PASSWORD);
  aat = await authorizationApiToken(request, RS_CLIENT_ID, USERNAME, PASSWORD);
  await warmUpResourceSetStore(request, pat);
});

test.afterAll(async ({ request }) => {
  for (const id of registered) {
    await deleteResourceSet(request, pat, id);
  }
});

test.describe("/uma/.well-known/uma-configuration", () => {

  test("is public and advertises the UMA endpoints", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/uma/.well-known/uma-configuration`);
    const config = await response.json();
    console.log(`[uma] uma-configuration -> ${response.status()} keys=${Object.keys(config).length}`);

    // REGRESSION GUARD: this returned 500 between the phase-4 flip and the UmaUrisFactory fix.
    expect(response.status()).toBe(200);
    expect(response.headers()["content-type"]).toContain("application/json");
    expect(config.version).toBeTruthy();
    expect(config.issuer).toBe(`${OPENAM_BASE}/oauth2`);
    expect(config.token_endpoint).toBe(`${OPENAM_BASE}/oauth2/access_token`);
    expect(config.authorization_endpoint).toBe(`${OPENAM_BASE}/oauth2/authorize`);
    expect(config.introspection_endpoint).toBe(`${OPENAM_BASE}/oauth2/introspect`);
    expect(config.resource_set_registration_endpoint).toBe(`${OPENAM_BASE}/oauth2/resource_set`);
    expect(config.permission_registration_endpoint).toBe(`${OPENAM_BASE}/uma/permission_request`);
    expect(config.rpt_endpoint).toBe(`${OPENAM_BASE}/uma/authz_request`);
    expect(config.pat_profiles_supported).toEqual(expect.arrayContaining(["bearer"]));
    expect(config.aat_profiles_supported).toEqual(expect.arrayContaining(["bearer"]));
    expect(config.rpt_profiles_supported).toEqual(expect.arrayContaining(["bearer"]));
  });

  test("resolves through the realm-prefixed path too", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/uma/realms/${REALM}/.well-known/uma-configuration`);
    expect(response.status()).toBe(200);
    expect((await response.json()).issuer).toBe(`${OPENAM_BASE}/oauth2`);
  });
});

test.describe("/uma/permission_request", () => {

  test("issues a permission ticket for a registered resource set", async ({ request }) => {
    const resourceSetId = await registerResourceSet(request, "uma e2e album");

    const response = await request.post(`${OPENAM_BASE}/uma/permission_request`, {
      headers: { Authorization: `Bearer ${pat}`, "Content-Type": "application/json" },
      data: { resource_set_id: resourceSetId, scopes: ["read"] },
    });
    const body = await response.json();
    console.log(`[uma] permission_request -> ${response.status()} ${JSON.stringify(body)}`);

    expect(response.status()).toBe(201);
    expect(body.ticket).toBeTruthy();
  });

  test("rejects an unknown resource set id in the UMA error shape", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/uma/permission_request`, {
      headers: { Authorization: `Bearer ${pat}`, "Content-Type": "application/json" },
      data: { resource_set_id: "no-such-resource-set", scopes: ["read"] },
    });
    const body = await response.json();
    console.log(`[uma] permission_request unknown rsid -> ${response.status()} ${JSON.stringify(body)}`);

    expect(response.status()).toBe(400);
    // Endpoint error => UMA shape. If this ever turns into {code, reason, message} the CREST error filter
    // has swallowed the endpoint's own error (phase-4 R-4.1).
    expect(body.error).toBe("invalid_resource_set_id");
    expect(body.error_description).toContain("Could not find Resource Set");
    expect(body.code).toBeUndefined();
  });

  test("rejects a request with no resource_set_id", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/uma/permission_request`, {
      headers: { Authorization: `Bearer ${pat}`, "Content-Type": "application/json" },
      data: {},
    });
    const body = await response.json();
    expect(response.status()).toBe(400);
    expect(body.error).toBe("invalid_resource_set_id");
    expect(body.error_description).toContain("Missing required attribute, 'resource_set_id'");
  });

  test("rejects an unauthenticated request in the CREST shape (phase-4 D5)", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/uma/permission_request`, {
      headers: { "Content-Type": "application/json" },
      data: { resource_set_id: "irrelevant", scopes: ["read"] },
    });
    const body = await response.json();
    console.log(`[uma] permission_request no token -> ${response.status()} ${JSON.stringify(body)}`);

    // Protection-filter error => CREST shape, deliberately NOT {error: "invalid_token"}. Reproducing the
    // Restlet behaviour here was an explicit phase-4 decision, so a switch to the OAuth2 shape is a
    // regression even though it would look more "correct".
    expect(response.status()).toBe(401);
    expect(body.code).toBe(401);
    expect(body.reason).toBe("Unauthorized");
    expect(body.message).toContain("access token provided is expired, revoked, malformed, or invalid");
    expect(body.error).toBeUndefined();
    // The Restlet filter set no challenge header and neither may the CHF one.
    expect(response.headers()["www-authenticate"]).toBeUndefined();
  });

  test("answers 405 for a verb the endpoint does not map", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/uma/permission_request`, {
      headers: { Authorization: `Bearer ${pat}` },
    });
    const body = await response.json();
    console.log(`[uma] permission_request GET -> ${response.status()} ${JSON.stringify(body)}`);
    // Route reached, verb unmapped: the framework's own 405, in the CREST shape.
    expect(response.status()).toBe(405);
    expect(body.code).toBe(405);
  });
});

test.describe("/uma/authz_request", () => {

  test("a valid ticket enters claim gathering", async ({ request }) => {
    const resourceSetId = await registerResourceSet(request, "uma e2e rpt album");
    const ticket = (await (await request.post(`${OPENAM_BASE}/uma/permission_request`, {
      headers: { Authorization: `Bearer ${pat}`, "Content-Type": "application/json" },
      data: { resource_set_id: resourceSetId, scopes: ["read"] },
    })).json()).ticket;

    const response = await request.post(`${OPENAM_BASE}/uma/authz_request`, {
      headers: { Authorization: `Bearer ${aat}`, "Content-Type": "application/json" },
      data: { ticket },
    });
    const body = await response.json();
    console.log(`[uma] authz_request -> ${response.status()} error=${body.error}`);

    // No policy grants the requesting party anything yet, so UMA asks for claims rather than issuing an RPT.
    // What matters for the migration is that the endpoint reaches its own logic and answers UMA-shaped.
    expect(response.status()).toBe(403);
    expect(body.error).toBe("need_info");
    expect(body.requesting_party_claims).toBeTruthy();
    expect(body.code).toBeUndefined();
  });

  test("rejects an unknown ticket in the UMA error shape", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/uma/authz_request`, {
      headers: { Authorization: `Bearer ${aat}`, "Content-Type": "application/json" },
      data: { ticket: "no-such-ticket" },
    });
    const body = await response.json();
    console.log(`[uma] authz_request bad ticket -> ${response.status()} ${JSON.stringify(body)}`);

    expect(response.status()).toBe(400);
    expect(body.error).toBe("invalid_ticket");
    expect(body.error_description).toContain("Unable to retrieve Permission Ticket");
    expect(body.code).toBeUndefined();
  });

  test("rejects a token without the uma_authorization scope", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/uma/authz_request`, {
      headers: { Authorization: `Bearer ${pat}`, "Content-Type": "application/json" },
      data: { ticket: "irrelevant" },
    });
    const body = await response.json();
    console.log(`[uma] authz_request wrong scope -> ${response.status()} ${JSON.stringify(body)}`);

    // Scope enforcement lives in the protection filter, so this is CREST-shaped like the 401 above.
    expect(response.status()).toBe(403);
    expect(body.code).toBe(403);
    expect(body.message).toContain("uma_authorization");
    expect(body.error).toBeUndefined();
  });

  test("rejects an unauthenticated request", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/uma/authz_request`, {
      headers: { "Content-Type": "application/json" },
      data: { ticket: "irrelevant" },
    });
    const body = await response.json();
    expect(response.status()).toBe(401);
    expect(body.code).toBe(401);
    expect(body.error).toBeUndefined();
  });
});
