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
 * Protocol cover for the OIDC half of /oauth2 -- discovery, the JWKS, the session endpoints and
 * idtokeninfo. These five routes are still served by Restlet and move to CHF in phase 5
 * (docs/migration/restlet/phase-5-oauth2.md, phase-5a-2.md, phase-5b-2.md); until this spec existed NONE of
 * them had any end-to-end cover at all, so a port could have broken them silently.
 *
 * This is a MIGRATION GUARD, not a byte oracle. It asserts statuses, body fields and the redirect/HTML
 * contract -- the things the port must preserve -- and deliberately does NOT pin exact Content-Type bytes,
 * because CHF emits `application/json; charset=UTF-8` where Restlet emits bare `application/json`; that
 * known, deliberate divergence is locked separately by the 5-E rows in oauth2-test.spec.mjs.
 *
 * Re-run this suite unchanged after the 5d-1 flip: anything that goes red is a regression.
 */

import { test, expect, request as apiRequest } from "@playwright/test";
import { OPENAM_BASE, getAdminToken, getAuthToken, PASSWORD, USERNAME } from "../common/openam-commons.mjs";
import {
  OIDC_CLIENT_SECRET, REALM,
  authorizationCodeTokens, basicAuth, ensureOidcClient, ensureProviderConfig, sessionContext,
} from "../common/oauth2-fixtures.mjs";

/** This spec's own client -- spec files run in parallel and rewriting a shared client kills its tokens. */
const OIDC_CLIENT_ID = "test_client_oidc";

const NONCE = "n-0S6_WzA2Mj";

let demoToken;
/** Cookie jar holding the demo session -- /oauth2/authorize authenticates by cookie, not by header. */
let demoCtx;
let tokens;

test.beforeAll(async ({ request }) => {
  const adminToken = await getAdminToken(request);
  if (!adminToken) {
    test.skip(true, "ADMIN_TOKEN not set");
  }
  await ensureProviderConfig(adminToken, request);
  await ensureOidcClient(adminToken, request, OIDC_CLIENT_ID);

  const loginCtx = await apiRequest.newContext();
  try {
    demoToken = await getAuthToken(loginCtx, USERNAME, PASSWORD);
  } finally {
    await loginCtx.dispose();
  }
  demoCtx = await sessionContext(apiRequest, demoToken);

  // One id_token for the whole suite: the session endpoints and idtokeninfo all need a real one.
  tokens = await authorizationCodeTokens(demoCtx, {
    clientId: OIDC_CLIENT_ID, clientSecret: OIDC_CLIENT_SECRET, scope: "openid profile", nonce: NONCE,
  });
});

test.afterAll(async () => {
  await demoCtx?.dispose();
});

test.describe("OIDC discovery", () => {

  test("/oauth2/.well-known/openid-configuration advertises this deployment's endpoints", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/oauth2/.well-known/openid-configuration`);
    expect(response.status()).toBe(200);
    expect(response.headers()["content-type"]).toContain("application/json");

    const config = await response.json();
    console.log(`[oidc] discovery issuer=${config.issuer} keys=${Object.keys(config).length}`);
    // Public discovery: no session, no client, no token.
    expect(config.issuer).toBe(`${OPENAM_BASE}/oauth2`);
    expect(config.authorization_endpoint).toBe(`${OPENAM_BASE}/oauth2/authorize`);
    expect(config.token_endpoint).toBe(`${OPENAM_BASE}/oauth2/access_token`);
    expect(config.userinfo_endpoint).toBe(`${OPENAM_BASE}/oauth2/userinfo`);
    expect(config.jwks_uri).toBe(`${OPENAM_BASE}/oauth2/connect/jwk_uri`);
    expect(config.end_session_endpoint).toBe(`${OPENAM_BASE}/oauth2/connect/endSession`);
    expect(config.check_session_iframe).toBe(`${OPENAM_BASE}/oauth2/connect/checkSession`);
    expect(config.response_types_supported).toEqual(expect.arrayContaining(["code", "token"]));
    expect(config.subject_types_supported).toEqual(expect.arrayContaining(["public"]));
    expect(config.scopes_supported).toEqual(expect.arrayContaining(["openid", "profile"]));
    expect(config.id_token_signing_alg_values_supported).toEqual(expect.arrayContaining(["HS256", "RS256"]));
  });

  test("the realm-prefixed discovery path resolves to the same provider", async ({ request }) => {
    // Realm routing is re-implemented at the flip (RestletRealmRouter -> RealmRoutingFactory), so both
    // spellings have to keep working.
    const modern = await request.get(`${OPENAM_BASE}/oauth2/realms/${REALM}/.well-known/openid-configuration`);
    expect(modern.status()).toBe(200);
    const config = await modern.json();
    expect(config.issuer).toBe(`${OPENAM_BASE}/oauth2`);
    expect(config.authorization_endpoint).toBe(`${OPENAM_BASE}/oauth2/authorize`);
  });

  test("/oauth2/connect/jwk_uri publishes a usable JWK set", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/oauth2/connect/jwk_uri`);
    expect(response.status()).toBe(200);
    expect(response.headers()["content-type"]).toContain("application/json");

    const jwks = await response.json();
    console.log(`[oidc] jwk_uri keys=${jwks.keys?.length}`);
    expect(Array.isArray(jwks.keys)).toBe(true);
    expect(jwks.keys.length).toBeGreaterThan(0);
    for (const key of jwks.keys) {
      // Enough for a relying party to select and build a key: an omission here breaks every RP.
      expect(key.kty).toBeTruthy();
      expect(key.kid).toBeTruthy();
      expect(key.use).toBeTruthy();
    }
    const rsa = jwks.keys.find((key) => key.kty === "RSA");
    expect(rsa, "the JWK set must publish the RSA signing key").toBeTruthy();
    expect(rsa.n).toBeTruthy();
    expect(rsa.e).toBeTruthy();
    // A JWK set must never carry private material.
    expect(rsa.d).toBeUndefined();
  });
});

test.describe("OIDC id_token issuance and idtokeninfo", () => {

  test("the authorization_code flow issues an id_token bound to the request", async () => {
    console.log(`[oidc] token keys=${Object.keys(tokens).join(",")}`);
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.scope).toContain("openid");
    expect(tokens.id_token).toBeTruthy();

    const [header, payload] = tokens.id_token.split(".");
    expect(tokens.id_token.split(".")).toHaveLength(3);
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    expect(JSON.parse(Buffer.from(header, "base64url").toString("utf8")).alg).toBe("HS256");
    expect(claims.iss).toBe(`${OPENAM_BASE}/oauth2`);
    expect(claims.aud).toBe(OIDC_CLIENT_ID);
    expect(claims.sub).toBe(USERNAME);
    expect(claims.nonce).toBe(NONCE);
    expect(claims.realm).toBe("/");
    // at_hash/c_hash bind the id_token to the access token and the code it came from.
    expect(claims.at_hash).toBeTruthy();
    expect(claims.c_hash).toBeTruthy();
    expect(claims.exp).toBeGreaterThan(claims.iat);
  });

  test("/oauth2/idtokeninfo returns the claim set for a valid id_token", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/idtokeninfo`, {
      headers: { Authorization: basicAuth(OIDC_CLIENT_ID, OIDC_CLIENT_SECRET) },
      form: { id_token: tokens.id_token },
    });
    const claims = await response.json();
    console.log(`[oidc] idtokeninfo -> ${response.status()} sub=${claims.sub}`);

    expect(response.status()).toBe(200);
    expect(response.headers()["content-type"]).toContain("application/json");
    expect(claims.sub).toBe(USERNAME);
    expect(claims.aud).toBe(OIDC_CLIENT_ID);
    expect(claims.iss).toBe(`${OPENAM_BASE}/oauth2`);
    expect(claims.nonce).toBe(NONCE);
    expect(claims.tokenName).toBe("id_token");
  });

  test("/oauth2/idtokeninfo rejects a missing id_token", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/idtokeninfo`, {
      headers: { Authorization: basicAuth(OIDC_CLIENT_ID, OIDC_CLIENT_SECRET) },
      form: {},
    });
    const body = await response.json();
    console.log(`[oidc] idtokeninfo no token -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(400);
    expect(body.error).toBe("bad_request");
    expect(body.error_description).toBe("no id_token in request");
  });

  test("/oauth2/idtokeninfo rejects a malformed id_token", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/idtokeninfo`, {
      headers: { Authorization: basicAuth(OIDC_CLIENT_ID, OIDC_CLIENT_SECRET) },
      form: { id_token: "not.a-jwt" },
    });
    const body = await response.json();
    console.log(`[oidc] idtokeninfo malformed -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(400);
    expect(body.error).toBe("bad_request");
    // The parse failure must surface as a 400, never as a 500.
    expect(body.error_description).toContain("invalid id_token");
  });
});

test.describe("OIDC session endpoints", () => {

  test("/oauth2/connect/checkSession serves the session-management iframe", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/oauth2/connect/checkSession`);
    const html = await response.text();
    console.log(`[oidc] checkSession -> ${response.status()} ct=${response.headers()["content-type"]} bytes=${html.length}`);

    expect(response.status()).toBe(200);
    expect(response.headers()["content-type"]).toContain("text/html");
    // The RP-facing contract of the iframe: it listens for postMessage and answers with a session state.
    expect(html).toContain("addEventListener");
    expect(html).toContain("receiveMessage");
    expect(html).toContain("session_state");
  });

  test("/oauth2/connect/endSession requires an id_token_hint", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/oauth2/connect/endSession`, { maxRedirects: 0 });
    const body = await response.json();
    console.log(`[oidc] endSession no hint -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(400);
    expect(body.error).toBe("bad_request");
    expect(body.error_description).toBe("The endSession endpoint requires an id_token_hint parameter");
  });

  test("/oauth2/connect/endSession accepts a valid id_token_hint", async () => {
    // A fresh session + id_token: this test ends the session, so it must not use the suite-wide one.
    const loginCtx = await apiRequest.newContext();
    let ssoToken;
    try {
      ssoToken = await getAuthToken(loginCtx, USERNAME, PASSWORD);
    } finally {
      await loginCtx.dispose();
    }
    const ctx = await sessionContext(apiRequest, ssoToken);
    try {
      const own = await authorizationCodeTokens(ctx, {
        clientId: OIDC_CLIENT_ID, clientSecret: OIDC_CLIENT_SECRET, scope: "openid", nonce: "end-session",
      });
      const response = await ctx.get(
        `${OPENAM_BASE}/oauth2/connect/endSession?${new URLSearchParams({ id_token_hint: own.id_token })}`,
        { maxRedirects: 0 });
      console.log(`[oidc] endSession -> ${response.status()} location=${response.headers()["location"]}`);
      // No post_logout_redirect_uri was supplied, so there is nothing to redirect to: 204, no body.
      expect(response.status()).toBe(204);
      expect((await response.body()).length).toBe(0);
    } finally {
      await ctx.dispose();
    }
  });
});
