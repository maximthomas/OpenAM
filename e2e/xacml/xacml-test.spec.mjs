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
 * Protocol-level cover for the /xacml endpoints, which moved from Restlet to CHF in phase 2 of the
 * Restlet migration (docs/migration/restlet/phase-2-xacml.md). This is the only layer that exercises
 * the real authentication filter, the real delegation check and the real XML serialization, so it
 * owns the 401/403 paths; the in-process XacmlRouterIT owns route composition below the auth filter.
 */

import { test, expect } from "@playwright/test";
import { OPENAM_BASE, getAdminToken, getAuthToken, PASSWORD, USERNAME } from "../common/openam-commons.mjs";

const SUB_REALM = "xacmltest";
const POLICY_NAME = "xacml-e2e-policy";
const POLICY_DESCRIPTION = "Fixture policy owned by the XACML e2e spec";
const APPLICATION_NAME = "iPlanetAMWebAgentService";

let adminToken;
let demoToken;

/**
 * Every PolicyId in an exported PolicySet. XACMLPrivilegeUtils.privilegeNameToPolicyId returns the
 * privilege name unchanged, so these are the policy names. Anchored so PolicySetId does not match.
 */
function policyIds(xml) {
  return [...xml.matchAll(/\bPolicyId="([^"]+)"/g)].map((match) => match[1]);
}

/**
 * Asserts the XacmlXmlErrorFilter rendered a CREST error as XML. The embedded code is not always the
 * HTTP status: Endpoints.from's 405 fallback embeds a bare NotSupportedException (501), a split that
 * XacmlXmlErrorFilterTest pins at the unit level too.
 */
async function expectXmlError(response, expectedEmbeddedCode) {
  expect(response.headers()["content-type"]).toContain("application/xml");
  const body = await response.text();
  expect(body).toContain("<error>");
  const code = body.match(/<code>(\d+)<\/code>/);
  expect(code, `expected an <error><code> element, got: ${body}`).not.toBeNull();
  expect(Number(code[1])).toBe(expectedEmbeddedCode);
}

function exportPolicies(request, { path = "/xacml/policies", token = adminToken, headers = {}, params } = {}) {
  const options = { headers: { ...headers } };
  if (token) {
    options.headers["iPlanetDirectoryPro"] = token;
  }
  if (params) {
    options.params = params;
  }
  return request.get(`${OPENAM_BASE}${path}`, options);
}

function importPolicies(request, body, params) {
  const options = {
    headers: { "iPlanetDirectoryPro": adminToken, "Content-Type": "application/xml" },
    data: body,
  };
  if (params) {
    options.params = params;
  }
  return request.post(`${OPENAM_BASE}/xacml/policies`, options);
}

/**
 * Needed by the realm-style cases, and gives the non-root Content-Disposition filename something to
 * be derived from. Tolerates an existing realm so the suite can be re-run against a live server.
 */
async function ensureSubRealmExists(request) {
  const response = await request.post(`${OPENAM_BASE}/json/realms/root/realms?_action=create`, {
    headers: {
      "iPlanetDirectoryPro": adminToken,
      "Content-Type": "application/json",
      "Accept-API-Version": "resource=1.0",
    },
    data: { name: SUB_REALM, parentPath: "/", active: true },
  });

  if (response.ok()) {
    console.log(`Realm "${SUB_REALM}" created`);
    return;
  }
  if (response.status() === 409 || response.status() === 400) {
    console.log(`Realm "${SUB_REALM}" already exists (${response.status()})`);
    return;
  }
  throw new Error(`Failed to create realm "${SUB_REALM}": ${response.status()} ${await response.text()}`);
}

/**
 * A fresh install's root realm holds no policies, so without this every export would return an empty
 * PolicySet and the filter and round-trip cases would pass while proving nothing.
 *
 * Uses resource=1.0 deliberately: PolicyV1Filter derives resourceTypeUuid from applicationName, so
 * the body does not have to name the realm's generated resource type. Later versions require it.
 */
async function ensurePolicyExists(request) {
  const url = `${OPENAM_BASE}/json/realms/root/policies/${POLICY_NAME}`;
  const headers = {
    "iPlanetDirectoryPro": adminToken,
    "Content-Type": "application/json",
    "Accept-API-Version": "resource=1.0",
  };

  const existing = await request.get(url, { headers });
  if (existing.ok()) {
    console.log(`Policy "${POLICY_NAME}" already exists`);
    return;
  }
  if (existing.status() !== 404) {
    throw new Error(`Failed to check policy "${POLICY_NAME}": ${existing.status()} ${await existing.text()}`);
  }

  const created = await request.put(url, {
    headers: { ...headers, "If-None-Match": "*" },
    data: {
      name: POLICY_NAME,
      active: true,
      description: POLICY_DESCRIPTION,
      applicationName: APPLICATION_NAME,
      actionValues: { GET: true },
      resources: ["http://xacml-e2e.example.com:8080/*"],
      subject: { type: "AuthenticatedUsers" },
    },
  });

  if (!created.ok()) {
    throw new Error(`Failed to create policy "${POLICY_NAME}": ${created.status()} ${await created.text()}`);
  }
  console.log(`Policy "${POLICY_NAME}" created`);
}

test.beforeAll(async ({ request }) => {
  adminToken = await getAdminToken(request);
  test.skip(!adminToken, "admin token not available");

  demoToken = await getAuthToken(request, USERNAME, PASSWORD);

  await ensureSubRealmExists(request);
  await ensurePolicyExists(request);
});

test.describe("XACML policy export", () => {
  test("exports the root realm as an XACML 3.0 attachment", async ({ request }) => {
    const response = await exportPolicies(request);

    expect(response.status()).toBe(200);
    expect(response.headers()["content-type"]).toContain("application/xacml+xml");
    expect(response.headers()["content-type"]).toContain("version=3.0");
    expect(response.headers()["content-disposition"]).toBe("attachment; filename=realm-policies.xml");

    const body = await response.text();
    expect(body).toMatch(/<(\w+:)?PolicySet[\s>]/);
    // If the fixture is missing here, the filter and round-trip cases below are vacuous.
    expect(policyIds(body)).toContain(POLICY_NAME);
  });

  test("rejects an unauthenticated export with 401", async ({ request }) => {
    const response = await exportPolicies(request, { token: null });

    // Before the RequiredAuthenticationFilter fix this was a 500: the shared AuthenticationFilter
    // admits requests with no token, and the handler then failed building an SSOToken from a null id.
    expect(response.status()).toBe(401);
    await expectXmlError(response, 401);
  });

  test("rejects an export by a user without delegation permission with 403", async ({ request }) => {
    const response = await exportPolicies(request, { token: demoToken });

    expect(response.status()).toBe(403);
    await expectXmlError(response, 403);
  });

  test("renders the method-not-allowed fallback as XML", async ({ request }) => {
    const response = await request.put(`${OPENAM_BASE}/xacml/policies`, {
      headers: { "iPlanetDirectoryPro": adminToken },
      data: "",
    });

    expect(response.status()).toBe(405);
    await expectXmlError(response, 501);
  });
});

/*
 * The /xacml route is deliberately unversioned, unlike every /json route, which
 * Routers.ServiceRoute.toService() gates at version 1 by default. Phase 2 originally copied that
 * default, which made pre-existing XACML clients (ssoadm and the CLI-era exporters, none of which
 * send Accept-API-Version) subject to the global "REST APIs > Default Version" setting: an
 * administrator selecting None would have turned all of them into 404s. These cases pin the absence
 * of the gate over the wire; XacmlRouterIT pins it in-process on every CI leg.
 */
test.describe("XACML export is unversioned", () => {
  test("exports when no Accept-API-Version header is sent", async ({ request }) => {
    const response = await exportPolicies(request);

    expect(response.status()).toBe(200);
  });

  test("ignores a known Accept-API-Version and answers without Content-API-Version", async ({ request }) => {
    const response = await exportPolicies(request, { headers: { "Accept-API-Version": "resource=1.0" } });

    expect(response.status()).toBe(200);
    // Present only if a version filter is back in the chain.
    expect(response.headers()["content-api-version"]).toBeUndefined();
  });

  test("serves a version that does not exist rather than 404ing", async ({ request }) => {
    const response = await exportPolicies(request, { headers: { "Accept-API-Version": "resource=2.0" } });

    // There is no version 2 of /xacml. Under a version gate this would be a 404; unversioned, the
    // header is ignored and the request is served, which is what Restlet did.
    expect(response.status()).toBe(200);
  });
});

test.describe("XACML export realm styles", () => {
  test("resolves the modern realms/root path", async ({ request }) => {
    const response = await exportPolicies(request, { path: "/xacml/realms/root/policies" });

    expect(response.status()).toBe(200);
    expect(response.headers()["content-disposition"]).toBe("attachment; filename=realm-policies.xml");
  });

  test("resolves a legacy path realm", async ({ request }) => {
    const response = await exportPolicies(request, { path: `/xacml/${SUB_REALM}/policies` });

    expect(response.status()).toBe(200);
    expect(response.headers()["content-disposition"])
      .toBe(`attachment; filename=${SUB_REALM}-realm-policies.xml`);
  });

  test("honours the realm query parameter", async ({ request }) => {
    const response = await exportPolicies(request, { params: { realm: `/${SUB_REALM}` } });

    expect(response.status()).toBe(200);
    expect(response.headers()["content-disposition"])
      .toBe(`attachment; filename=${SUB_REALM}-realm-policies.xml`);
  });
});

test.describe("XACML export filters", () => {
  test("restricts the export to a matching filter", async ({ request }) => {
    const query = new URLSearchParams();
    query.append("filter", `name=${POLICY_NAME}`);

    const response = await request.get(`${OPENAM_BASE}/xacml/policies?${query}`, {
      headers: { "iPlanetDirectoryPro": adminToken },
    });

    expect(response.status()).toBe(200);
    expect(policyIds(await response.text())).toEqual([POLICY_NAME]);
  });

  test("applies every value of a repeated filter parameter", async ({ request }) => {
    const query = new URLSearchParams();
    query.append("filter", `name=${POLICY_NAME}`);
    query.append("filter", "name=no-such-policy");

    const response = await request.get(`${OPENAM_BASE}/xacml/policies?${query}`, {
      headers: { "iPlanetDirectoryPro": adminToken },
    });

    expect(response.status()).toBe(200);
    // Filters are ANDed (PrivilegeManager.search passes boolAnd=true), so a second, unsatisfiable
    // filter must empty the result. If only the first were read, the policy would still be here.
    expect(policyIds(await response.text())).toEqual([]);
  });
});

test.describe("XACML policy import", () => {
  test("reports the steps of a dryrun without persisting them", async ({ request }) => {
    const before = await (await exportPolicies(request)).text();

    const response = await importPolicies(request, before, { dryrun: "true" });

    expect(response.status()).toBe(200);
    expect(response.headers()["content-type"]).toContain("application/json");

    const steps = await response.json();
    expect(Array.isArray(steps)).toBe(true);
    expect(steps.length).toBeGreaterThan(0);
    expect(steps[0]).toHaveProperty("status");
    expect(steps[0]).toHaveProperty("name");
    expect(steps[0]).toHaveProperty("type");

    const after = await (await exportPolicies(request)).text();
    expect(policyIds(after).sort()).toEqual(policyIds(before).sort());
  });

  test("round-trips an export from the root realm into a sub realm", async ({ request }) => {
    const exported = await (await exportPolicies(request)).text();

    const response = await importPolicies(request, exported, { realm: `/${SUB_REALM}` });

    expect(response.status()).toBe(200);
    const steps = await response.json();
    expect(steps.length).toBeGreaterThan(0);

    // The load-bearing assertion of the suite: export serialization, import parsing, both realm
    // resolutions and both permission checks all have to be right for the policy to land here.
    const subRealm = await exportPolicies(request, { path: `/xacml/${SUB_REALM}/policies` });
    expect(subRealm.status()).toBe(200);
    expect(policyIds(await subRealm.text())).toContain(POLICY_NAME);
  });

  test("rejects an empty document with 400", async ({ request }) => {
    const response = await importPolicies(request, "");

    expect(response.status()).toBe(400);
    await expectXmlError(response, 400);
  });
});
