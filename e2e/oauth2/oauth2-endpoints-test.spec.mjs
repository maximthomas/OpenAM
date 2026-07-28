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
 * Protocol cover for the /oauth2 routes that are neither the token endpoint nor the OIDC surface:
 * dynamic client registration, the device flow, token revocation and resource-set registration. All four
 * are still served by Restlet and move to CHF in phase 5 (5a-2b for register/device-code/revoke,
 * 5b-2 for device/user, 5c for resource_set -- docs/migration/restlet/plan.md); none of them had any
 * end-to-end cover before this spec.
 *
 * Like oidc-test.spec.mjs this is a MIGRATION GUARD rather than a byte oracle: statuses, body fields and
 * lifecycle behaviour, not exact Content-Type bytes (CHF adds `; charset=UTF-8`, a known divergence locked
 * by the 5-E rows in oauth2-test.spec.mjs). Re-run unchanged after the 5d-1 flip.
 */

import { test, expect, request as apiRequest } from "@playwright/test";
import { OPENAM_BASE, getAdminToken, getAuthToken, PASSWORD, USERNAME } from "../common/openam-commons.mjs";
import {
  RS_CLIENT_SECRET,
  deleteClient, deviceCodeForConsent, ensureDeviceConsentClient, ensureOidcClient, ensureProviderConfig,
  ensureResourceServerClient, ensureUmaProvider, protectionApiToken, registerResourceSet, sessionContext,
  uniqueName, warmUpResourceSetStore,
} from "../common/oauth2-fixtures.mjs";

/** This spec's own clients -- see the note in oauth2-fixtures.mjs about per-file ownership. */
const OIDC_CLIENT_ID = "test_client_oidc_dev";
const RS_CLIENT_ID = "test_client_rs_reg";
/** Consent-requiring, device-capable: the 5-E3 rows that must reach the device consent page. */
const DEVICE_CONSENT_CLIENT_ID = "test_client_device_consent";

/** Protection API token: the bearer that guards /oauth2/resource_set and authorises dynamic registration. */
let pat;

test.beforeAll(async ({ request }) => {
  const adminToken = await getAdminToken(request);
  if (!adminToken) {
    test.skip(true, "ADMIN_TOKEN not set");
  }
  await ensureProviderConfig(adminToken, request);
  await ensureUmaProvider(adminToken, request);
  await ensureOidcClient(adminToken, request, OIDC_CLIENT_ID);
  await ensureDeviceConsentClient(adminToken, request, DEVICE_CONSENT_CLIENT_ID);
  await ensureResourceServerClient(adminToken, request, RS_CLIENT_ID);
  pat = await protectionApiToken(request, RS_CLIENT_ID, USERNAME, PASSWORD);
  await warmUpResourceSetStore(request, pat);
});

test.describe("/oauth2/resource_set registration", () => {

  const bearer = () => ({ Authorization: `Bearer ${pat}`, "Content-Type": "application/json" });

  test("full lifecycle: register, read, list, update, delete", async ({ request }) => {
    // --- register. Resource-set names are unique per owner, so a fixed name would work exactly once
    // against a given container and 400 on every later run.
    const { response: created, name } = await registerResourceSet(
      request, pat, uniqueName("e2e album"), { type: "http://example.invalid/album" });
    const registration = await created.json();
    const etag = created.headers()["etag"];
    console.log(`[oauth2] resource_set POST -> ${created.status()} id=${registration._id} etag=${etag}`);

    expect(created.status(), `resource_set registration failed: ${JSON.stringify(registration)}`).toBe(201);
    expect(registration._id).toBeTruthy();
    // The RS is told where the resource owner can manage sharing; a port that drops this breaks the UMA UI.
    expect(registration.user_access_policy_uri).toContain(`#uma/share/${registration._id}`);
    expect(etag).toBeTruthy();
    const id = registration._id;

    // --- read
    const read = await request.get(`${OPENAM_BASE}/oauth2/resource_set/${id}`, { headers: bearer() });
    const resourceSet = await read.json();
    expect(read.status()).toBe(200);
    expect(resourceSet.name).toBe(name);
    expect(resourceSet.scopes).toEqual(["read", "write"]);
    expect(resourceSet.type).toBe("http://example.invalid/album");
    expect(read.headers()["etag"]).toBeTruthy();

    // --- list: the trailing-slash attachment is a separate route in the Restlet router (3 attachments for
    // this one endpoint), so it has to keep working on its own.
    const list = await request.get(`${OPENAM_BASE}/oauth2/resource_set/?_queryId=*`, { headers: bearer() });
    expect(list.status()).toBe(200);
    expect(await list.json()).toContain(id);

    // --- update: concurrency control is part of the contract, not an implementation detail
    const noIfMatch = await request.put(`${OPENAM_BASE}/oauth2/resource_set/${id}`, {
      headers: bearer(),
      data: { name: `${name} renamed`, scopes: ["read"] },
    });
    const noIfMatchBody = await noIfMatch.json();
    console.log(`[oauth2] resource_set PUT without If-Match -> ${noIfMatch.status()} ${JSON.stringify(noIfMatchBody)}`);
    expect(noIfMatch.status()).toBe(400);
    expect(noIfMatchBody.error_description).toContain("Require If-Match header to update Resource Set");

    const updated = await request.put(`${OPENAM_BASE}/oauth2/resource_set/${id}`, {
      headers: { ...bearer(), "If-Match": "*" },
      data: { name: `${name} renamed`, scopes: ["read"] },
    });
    expect(updated.status()).toBe(200);
    const afterUpdate = await (await request.get(`${OPENAM_BASE}/oauth2/resource_set/${id}`,
      { headers: bearer() })).json();
    expect(afterUpdate.name).toBe(`${name} renamed`);
    expect(afterUpdate.scopes).toEqual(["read"]);

    // --- delete
    const deleted = await request.delete(`${OPENAM_BASE}/oauth2/resource_set/${id}`, {
      headers: { ...bearer(), "If-Match": "*" },
    });
    console.log(`[oauth2] resource_set DELETE -> ${deleted.status()}`);
    expect(deleted.status()).toBe(204);

    const gone = await request.get(`${OPENAM_BASE}/oauth2/resource_set/${id}`, { headers: bearer() });
    const goneBody = await gone.json();
    expect(gone.status()).toBe(404);
    expect(goneBody.error).toBe("not_found");
    expect(goneBody.error_description).toContain(id);
  });

  test("rejects a request with no bearer token", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/resource_set`, {
      headers: { "Content-Type": "application/json" },
      data: { name: "unauthorised", scopes: ["read"] },
    });
    const body = await response.json();
    console.log(`[oauth2] resource_set no token -> ${response.status()} ${JSON.stringify(body)}`);
    // The protection filter answers in the OAuth2 error shape here (unlike /uma, which is CREST-shaped).
    expect(response.status()).toBe(401);
    expect(body.error).toBe("invalid_token");
  });

  test("rejects a request with an unknown bearer token", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/resource_set`, {
      headers: { Authorization: "Bearer not-a-real-token", "Content-Type": "application/json" },
      data: { name: "unauthorised", scopes: ["read"] },
    });
    expect(response.status()).toBe(401);
    expect((await response.json()).error).toBe("invalid_token");
  });
});

test.describe("/oauth2/connect/register dynamic client registration", () => {

  /**
   * Whatever this run registered. Every run mints a brand-new client, so without this a long-lived container
   * accumulates orphan agents until listing them slows the other fixtures down.
   *
   * Cleanup goes through the ADMIN api, not RFC 7592: OpenAM's connect/register implements the create and the
   * read but not the delete -- see the 405 asserted below.
   */
  let registeredClientId;

  test.afterAll(async ({ request }) => {
    if (registeredClientId) {
      await deleteClient(await getAdminToken(request), request, registeredClientId);
    }
  });

  test("registers a client and reads it back with the registration access token", async ({ request }) => {
    const created = await request.post(`${OPENAM_BASE}/oauth2/connect/register`, {
      headers: { Authorization: `Bearer ${pat}`, "Content-Type": "application/json" },
      data: { redirect_uris: ["http://dynamic.invalid/cb"], client_name: "e2e dynamic client" },
    });
    const client = await created.json();
    console.log(`[oauth2] connect/register -> ${created.status()} client_id=${client.client_id}`);
    registeredClientId = client.client_id;

    expect(created.status(), `dynamic registration failed: ${JSON.stringify(client)}`).toBe(201);
    expect(client.client_id).toBeTruthy();
    expect(client.client_secret).toBeTruthy();
    expect(client.redirect_uris).toEqual(["http://dynamic.invalid/cb"]);
    // The RFC 7592 handles: without these the client can never manage its own registration.
    expect(client.registration_access_token).toBeTruthy();
    expect(client.registration_client_uri)
      .toBe(`${OPENAM_BASE}/oauth2/connect/register?client_id=${client.client_id}`);

    const readBack = await request.get(client.registration_client_uri, {
      headers: { Authorization: `Bearer ${client.registration_access_token}` },
    });
    const stored = await readBack.json();
    console.log(`[oauth2] connect/register read-back -> ${readBack.status()}`);
    expect(readBack.status()).toBe(200);
    expect(stored.client_id).toBe(client.client_id);
    expect(stored.redirect_uris).toEqual(["http://dynamic.invalid/cb"]);

    // RFC 7592 deregistration is NOT implemented -- the Restlet resource maps GET and nothing else, so the
    // verb falls through to the framework's 405. Recorded rather than treated as a bug: the CHF port has to
    // reproduce it, and a port that silently starts accepting DELETE is a behaviour change either way.
    const deregistered = await request.delete(client.registration_client_uri, {
      headers: { Authorization: `Bearer ${client.registration_access_token}` },
    });
    console.log(`[oauth2] connect/register DELETE -> ${deregistered.status()}`);
    expect(deregistered.status()).toBe(405);
  });

  test("rejects registration without an access token", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/connect/register`, {
      headers: { "Content-Type": "application/json" },
      data: { redirect_uris: ["http://dynamic.invalid/cb"] },
    });
    const body = await response.json();
    console.log(`[oauth2] connect/register no token -> ${response.status()} ${JSON.stringify(body)}`);
    // Note the shape: a 400 access_denied, NOT a 401 -- registration validates the token itself rather than
    // sitting behind the protection filter.
    expect(response.status()).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.error_description).toBe("Access Token not valid");
  });
});

test.describe("OAuth2 device flow", () => {

  test("/oauth2/device/code issues a user code and a verification URI", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/device/code`, {
      form: { client_id: OIDC_CLIENT_ID, scope: "openid profile", response_type: "device_code" },
    });
    const body = await response.json();
    console.log(`[oauth2] device/code -> ${response.status()} user_code=${body.user_code}`);

    expect(response.status()).toBe(200);
    expect(body.device_code).toBeTruthy();
    expect(body.user_code).toBeTruthy();
    expect(body.verification_uri).toBe(`${OPENAM_BASE}/oauth2/device/user`);
    expect(body.interval).toBeGreaterThan(0);
    expect(body.expires_in).toBeGreaterThan(0);
  });

  test("/oauth2/device/code rejects a request missing required parameters", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/device/code`, {
      form: { client_id: OIDC_CLIENT_ID },
    });
    const body = await response.json();
    console.log(`[oauth2] device/code missing params -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(400);
    expect(body.error).toBe("bad_request");
    expect(body.error_description).toBe("client_id, scope and response_type are required parameters");
  });

  test("/oauth2/device/user serves the code-entry page with no user_code", async () => {
    // Anonymous, no user_code: the bare code-entry form is public. This is a FreeMarker render, so the port
    // has to keep the renderer wired (phase 5b-2).
    const anonCtx = await apiRequest.newContext();
    try {
      const response = await anonCtx.get(`${OPENAM_BASE}/oauth2/device/user`, { maxRedirects: 0 });
      const html = await response.text();
      console.log(`[oauth2] device/user no code -> ${response.status()} ct=${response.headers()["content-type"]} bytes=${html.length}`);
      expect(response.status()).toBe(200);
      expect(response.headers()["content-type"]).toContain("text/html");
      expect(html.length).toBeGreaterThan(0);
    } finally {
      await anonCtx.dispose();
    }
  });

  test("/oauth2/device/user sends an unauthenticated user_code submission to login", async ({ request }) => {
    const code = await (await request.post(`${OPENAM_BASE}/oauth2/device/code`, {
      form: { client_id: OIDC_CLIENT_ID, scope: "openid profile", response_type: "device_code" },
    })).json();

    const anonCtx = await apiRequest.newContext();
    try {
      const response = await anonCtx.get(
        `${OPENAM_BASE}/oauth2/device/user?${new URLSearchParams({ user_code: code.user_code })}`,
        { maxRedirects: 0 });
      const location = response.headers()["location"];
      console.log(`[oauth2] device/user unauthenticated -> ${response.status()} location=${location}`);
      // Verifying a code needs a resource owner, so this is the same 301->login contract /authorize has.
      expect(response.status()).toBe(301);
      expect(location.startsWith(`${OPENAM_BASE}/UI/Login`)).toBe(true);
      expect(new URL(location).searchParams.get("goto")).toContain("/oauth2/device/user");
    } finally {
      await anonCtx.dispose();
    }
  });

  test("/oauth2/device/user renders the verification page for an authenticated user", async ({ request }) => {
    const code = await (await request.post(`${OPENAM_BASE}/oauth2/device/code`, {
      form: { client_id: OIDC_CLIENT_ID, scope: "openid profile", response_type: "device_code" },
    })).json();

    const loginCtx = await apiRequest.newContext();
    let ssoToken;
    try {
      ssoToken = await getAuthToken(loginCtx, USERNAME, PASSWORD);
    } finally {
      await loginCtx.dispose();
    }
    const userCtx = await sessionContext(apiRequest, ssoToken);
    try {
      const response = await userCtx.get(
        `${OPENAM_BASE}/oauth2/device/user?${new URLSearchParams({ user_code: code.user_code })}`,
        { maxRedirects: 0 });
      const html = await response.text();
      console.log(`[oauth2] device/user authenticated -> ${response.status()} ct=${response.headers()["content-type"]} bytes=${html.length}`);
      expect(response.status()).toBe(200);
      expect(response.headers()["content-type"]).toContain("text/html");
      expect(html.length).toBeGreaterThan(0);
    } finally {
      await userCtx.dispose();
    }
  });
});

/**
 * Step 5-E3: the contract lock for /oauth2/device/user, recorded against LIVE RESTLET. Restlet stops serving
 * /oauth2 at the 5d-1 flip, so none of this is recordable afterwards
 * (docs/migration/restlet/phase-5b-2.md).
 *
 * Every value here was OBSERVED FIRST and only then asserted (2026-07-28, openam-e2e:5e3 built from this
 * tree). Do not "tidy" a string: the exact bytes ARE the oracle for the 5d-1 byte diff.
 *
 * Unlike the two OIDC session endpoints, this one is a BROWSER endpoint -- its doCatch calls the 4-arg
 * ExceptionHandler, so its errors are HTML pages. Row 3 is the proof, and it is why the CHF port extends the
 * browser base while the other two extend the JSON one.
 */
test.describe("OAuth2 device flow contract lock (5-E3, live Restlet)", () => {

  let demoCtx;

  /** The device pages carry their model in a `pageData`/`oauth2Data` literal, exactly like /authorize. */
  const pageValue = (html, key) =>
    (new RegExp(`(?:^|[{,\\s])${key}:\\s*"([^"]*)"`).exec(html) ?? [])[1];

  /** Drives a consent-requiring code to the consent page and returns the page plus its scraped csrf. */
  async function consentPage(request, extra = {}) {
    const code = await deviceCodeForConsent(request, DEVICE_CONSENT_CLIENT_ID, extra);
    const page = await demoCtx.get(
      `${OPENAM_BASE}/oauth2/device/user?${new URLSearchParams({ user_code: code.user_code })}`,
      { maxRedirects: 0 });
    const html = await page.text();
    return { code, page, html, csrf: pageValue(html, "csrf") };
  }

  test.beforeAll(async () => {
    const loginCtx = await apiRequest.newContext();
    let ssoToken;
    try {
      ssoToken = await getAuthToken(loginCtx, USERNAME, PASSWORD);
    } finally {
      await loginCtx.dispose();
    }
    demoCtx = await sessionContext(apiRequest, ssoToken);
  });

  test.afterAll(async () => {
    await demoCtx?.dispose();
  });

  test("row 1: an unknown user_code is a 200 form page carrying errorCode", async () => {
    // The one place this provider reports a failure with a 200: readDeviceCode's InvalidGrantException is
    // swallowed and re-rendered as the code-entry form with an error marker.
    const anonCtx = await apiRequest.newContext();
    try {
      for (const [who, ctx] of [["authenticated", demoCtx], ["anonymous", anonCtx]]) {
        const response = await ctx.get(`${OPENAM_BASE}/oauth2/device/user?user_code=ZZZZZZZZ`,
          { maxRedirects: 0 });
        const html = await response.text();
        console.log(`[5-E3] row1 unknown code (${who}) -> ${response.status()}`);
        expect(response.status(), who).toBe(200);
        expect(response.headers()["content-type"], who).toBe("text/html;charset=UTF-8");
        expect(html, who).toContain('errorCode: "not_found"');
        // NOTE: the anonymous case is a 200 too -- the code lookup fails BEFORE any session check, so an
        // unknown code never reaches the 301-to-login that a valid code triggers.
        expect(response.headers()["location"], who).toBeUndefined();
        // finding 8: no cache headers on this endpoint, ever.
        expect(response.headers()["cache-control"], who).toBeUndefined();
        expect(response.headers()["pragma"], who).toBeUndefined();
      }
    } finally {
      await anonCtx.dispose();
    }
  });

  test("row 4: the device consent page carries a model built ENTIRELY from request attributes", async ({ request }) => {
    // ⚠ This is the 5b-2 finding-2 / D2 oracle, and the reason ConsentPageRenderer's phase 1 cannot stay
    // realm-only. The device-flow GET carries ONLY user_code in the query, so every key below reached the
    // page through phase 1 -- the request ATTRIBUTES that addRequestParamsFromDeviceCode seeded from the
    // stored device code. A CHF renderer that copies only `realm` in phase 1 renders this page with every
    // <#if x??> false: a 200 that looks fine to a status assertion and is useless to a user.
    const { code, page, html, csrf } = await consentPage(request, {
      state: "devstate", nonce: "devnonce", ui_locales: "fr-CA",
    });
    console.log(`[5-E3] row4 consent page -> ${page.status()} bytes=${html.length}`);

    expect(page.status()).toBe(200);
    expect(page.headers()["content-type"]).toBe("text/html;charset=UTF-8");

    expect(csrf).toBeTruthy();
    // Seeded from the device code, NOT from the query -- the query has only user_code.
    expect(pageValue(html, "clientId")).toBe(DEVICE_CONSENT_CLIENT_ID);
    expect(pageValue(html, "scope")).toBe("openid profile");
    expect(pageValue(html, "state")).toBe("devstate");
    expect(pageValue(html, "nonce")).toBe("devnonce");
    expect(pageValue(html, "responseType")).toBe("code");
    // `ui_locales` OVERRIDES the Accept-Language-derived locale (page/authorize.ftl:43 prefers it), so a
    // renderer that drops the key silently changes the page's language rather than merely losing a field.
    expect(pageValue(html, "locale")).toBe("fr-CA");
    // realm rides along on the same attribute map, at the TOP level of pageData rather than inside oauth2Data.
    expect(html).toContain('realm: "\\/"');

    // Device-specific model keys /authorize never sets.
    expect(pageValue(html, "userCode")).toBe(code.user_code);
    expect(pageValue(html, "userName")).toBe("Demo Demo");
    expect(pageValue(html, "displayName")).toBe(DEVICE_CONSENT_CLIENT_ID);
    expect(html).toContain("isSaveConsentEnabled: true");
    expect(html).toContain('displayScopes: [ { "name": "openid" }');
    // The form posts back to the device endpoint carrying the user_code, with the context path included.
    expect(pageValue(html, "formTarget"))
      .toBe(`\\/openam/oauth2/device/user?user_code=${code.user_code}`);
  });

  test("row 2: decision=allow and decision=deny both render the thanks page", async ({ request }) => {
    for (const decision of ["allow", "deny"]) {
      const { code, csrf } = await consentPage(request);
      const response = await demoCtx.post(`${OPENAM_BASE}/oauth2/device/user`, {
        form: { decision, save_consent: "off", csrf, user_code: code.user_code },
        maxRedirects: 0,
      });
      const html = await response.text();
      console.log(`[5-E3] row2 decision=${decision} -> ${response.status()}`);
      expect(response.status(), decision).toBe(200);
      expect(response.headers()["content-type"], decision).toBe("text/html;charset=UTF-8");
      // BOTH decisions land on the thanks page: the allow/deny branch only chooses between updating and
      // deleting the device code, and the method then falls through to the same render. `deny` is NOT an
      // error page and NOT a redirect -- the difference is invisible on the wire and only observable by
      // polling /access_token afterwards.
      expect(html, decision).toContain("done: true");
      // Pre-existing quirk, reproduced deliberately: CodeThanks.ftl renders `realm : "${realm?js_string}/XUI"`,
      // so the realm arrives with /XUI appended. The CHF golden must keep this.
      expect(html, decision).toContain('realm : "\\//XUI"');
    }
  });

  test("row 3: a CSRF failure is an HTML error PAGE, not JSON (the 4-arg doCatch)", async ({ request }) => {
    // Closes 5b-2 open question 4. DeviceCodeVerificationResource.doCatch calls the 4-arg
    // ExceptionHandler.handle, which renders page/error.ftl -- so unlike endSession/checkSession, this
    // endpoint's errors are pages. That is what pins DeviceCodeVerificationHandler to the BROWSER base.
    for (const [name, csrf] of [["missing", undefined], ["wrong", "not-the-token"]]) {
      const { code } = await consentPage(request);
      const form = { decision: "allow", save_consent: "off", user_code: code.user_code };
      if (csrf) form.csrf = csrf;
      const response = await demoCtx.post(`${OPENAM_BASE}/oauth2/device/user`, { form, maxRedirects: 0 });
      const html = await response.text();
      console.log(`[5-E3] row3 csrf ${name} -> ${response.status()} ct=${response.headers()["content-type"]}`);

      expect(response.status(), name).toBe(400);
      expect(response.headers()["content-type"], name).toBe("text/html;charset=UTF-8");
      expect(html, name).toContain("<title>OAuth2 Error Page</title>");
      expect(html, name).toContain('message: "bad_request"');
      // No redirect: the error is rendered, never sent anywhere.
      expect(response.headers()["location"], name).toBeUndefined();
    }
  });

  test("row 11: PUT on /device/user is Restlet's own 405 with a CREST body", async ({ request }) => {
    // Same shape as the two OIDC session endpoints (see the 5-E3 block in oidc-test.spec.mjs): no
    // OAuth2Filter wrapper, so no OAuth2-shaped 405. This body is CREST, not `method_not_allowed`.
    const response = await request.fetch(`${OPENAM_BASE}/oauth2/device/user`,
      { method: "PUT", maxRedirects: 0 });
    const body = await response.json();
    console.log(`[5-E3] row11 PUT /device/user -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(405);
    expect(response.headers()["content-type"]).toBe("application/json");
    expect(body.code).toBe(405);
    expect(body.reason).toBe("Method Not Allowed");
    expect(body.error).toBeUndefined();
    expect(response.headers()["cache-control"]).toBeUndefined();
  });
});

test.describe("/oauth2/token/revoke", () => {

  test("revokes an access token so it stops validating", async ({ request }) => {
    const token = await protectionApiToken(request, RS_CLIENT_ID, USERNAME, PASSWORD);

    const before = await request.get(`${OPENAM_BASE}/oauth2/tokeninfo`, {
      params: { access_token: token }, headers: { Accept: "application/json" },
    });
    expect(before.status()).toBe(200);

    const revoked = await request.post(`${OPENAM_BASE}/oauth2/token/revoke`, {
      form: { token, client_id: RS_CLIENT_ID, client_secret: RS_CLIENT_SECRET },
    });
    console.log(`[oauth2] token/revoke -> ${revoked.status()} ${await revoked.text()}`);
    expect(revoked.status()).toBe(200);

    const after = await request.get(`${OPENAM_BASE}/oauth2/tokeninfo`, {
      params: { access_token: token }, headers: { Accept: "application/json" },
    });
    const afterBody = await after.json();
    console.log(`[oauth2] tokeninfo after revoke -> ${after.status()} ${JSON.stringify(afterBody)}`);
    // The revocation must actually take effect, not just answer 200.
    expect(after.status()).toBe(401);
    expect(afterBody.error).toBe("invalid_token");
  });

  test("rejects a revocation with no token parameter", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/token/revoke`, {
      form: { client_id: RS_CLIENT_ID, client_secret: RS_CLIENT_SECRET },
    });
    const body = await response.json();
    console.log(`[oauth2] token/revoke no token -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toBe("Missing parameter: token");
  });

  test("rejects a revocation with a bad client secret", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/token/revoke`, {
      form: { token: "irrelevant", client_id: OIDC_CLIENT_ID, client_secret: "wrong-secret" },
    });
    const body = await response.json();
    console.log(`[oauth2] token/revoke bad secret -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(400);
    expect(body.error).toBe("invalid_client");
    expect(body.error_description).toBe("Client authentication failed");
  });
});
