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

import { expect, test } from "@playwright/test";
import { isDeepStrictEqual } from "node:util";
import { OPENAM_BASE } from "../common/openam-commons.mjs";
import {
  REDIRECT_URI, SCOPE, isInactiveIntrospection, pkce, unreportedRequest,
  withIntrospectionClient, withRealmProvider,
} from "../common/oauth2-fixtures.mjs";

test.use({ trace: "off", screenshot: "off" });

test("creates a realm provider without clients, resource owners or owner sessions", async ({ ignoreHTTPSErrors }) => {
  await withRealmProvider({ ignoreHTTPSErrors }, async (realm) => {
    const prefixes = {
      nested: OPENAM_BASE + "/oauth2/realms/root/realms/" + realm.name,
      legacy: OPENAM_BASE + "/oauth2/" + realm.name,
      flat: OPENAM_BASE + "/oauth2/realms/" + realm.name,
      query: OPENAM_BASE + "/oauth2",
    };
    expect(realm.oauthUrl === prefixes.nested, "Canonical realm URL is independently derived").toBe(true);
    for (const spelling of Object.keys(prefixes)) {
      for (const path of ["/authorize", "/access_token", "/introspect", "/userinfo", "/token/revoke"]) {
        const params = new URLSearchParams([["tag", "first"], ["tag", "second"]]);
        const expected = new URL(prefixes[spelling] + path + "?existing=value");
        for (const [key, value] of params) expected.searchParams.append(key, value);
        if (spelling === "query") expected.searchParams.append("realm", realm.name);
        const actual = realm.endpoint(spelling, path + "?existing=value", params);
        expect(actual === expected.href, "Spelling preserves its own path and repeated query values").toBe(true);
      }
    }
    const request = unreportedRequest.newContext({
      ignoreHTTPSErrors, maxRedirects: 0,
    });
    try {
      const response = await request.get(realm.endpoint("nested", "/.well-known/openid-configuration"));
      expect(response.status(), "Realm-only discovery returns the direct response").toBe(200);
      const body = await response.json().catch(() => undefined);
      expect(body?.issuer === prefixes.nested, "Discovery uses the canonical realm issuer").toBe(true);
    } finally {
      await request.dispose();
    }
  });
});

for (const spelling of ["nested", "legacy", "flat", "query"]) {
  test("completes an OAuth2 lifecycle in a non-root realm via " + spelling, async ({ ignoreHTTPSErrors }) => {
    await withRealmProvider({ ignoreHTTPSErrors }, async (realm) => {
      await realm.bootstrapAgentService();
      const owner = await realm.createUser();
      const session = await realm.createSession(owner);
      await withIntrospectionClient({
        ignoreHTTPSErrors, realm, resourceOwner: owner, prefix: "s7j1",
        additionalGrantTypes: ["authorization_code", "refresh_token", "password"],
        allowInactiveBeforeCleanup: true,
        clientData: {
          "com.forgerock.openam.oauth2provider.redirectionURIs": ["[0]=" + REDIRECT_URI],
          "com.forgerock.openam.oauth2provider.responseTypes": ["[0]=code"],
          isConsentImplied: true,
        },
      }, async (client) => {
        const { verifier, challenge } = await pkce();
        const state = realm.name + "-" + spelling;
        const params = new URLSearchParams({
          response_type: "code", client_id: client.id, redirect_uri: REDIRECT_URI,
          scope: SCOPE, state, code_challenge: challenge, code_challenge_method: "S256",
        });
        const authorize = await session.get(realm.endpoint(spelling, "/authorize", params));
        expect(authorize.status(), "Authorization returns a direct code redirect").toBe(302);
        let location;
        try { location = new URL(authorize.headers().location); }
        catch { throw new Error("Authorization returned a missing or malformed redirect"); }
        expect(location.origin + location.pathname === REDIRECT_URI, "Authorization redirect target matches").toBe(true);
        expect(location.hash === "", "Code redirect has no fragment").toBe(true);
        expect(isDeepStrictEqual([...location.searchParams.keys()].sort(), ["client_id", "code", "iss", "scope", "state"]),
          "Authorization redirect has the characterized parameters").toBe(true);
        expect(location.searchParams.get("state") === state, "Authorization preserves state").toBe(true);
        expect(location.searchParams.get("iss") === realm.oauthUrl, "Authorization uses the realm issuer").toBe(true);
        expect(location.searchParams.get("client_id") === client.id, "Authorization preserves client ID").toBe(true);
        expect(location.searchParams.get("scope") === SCOPE, "Authorization preserves scope").toBe(true);
        const code = location.searchParams.get("code");
        expect(typeof code === "string" && code.trim().length > 0, "Authorization issues a nonempty code").toBe(true);

        const response = await client.request.post(realm.endpoint(spelling, "/access_token"), {
          headers: client.credentials,
          form: { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: verifier },
        });
        const body = await response.json().catch(() => undefined);
        const { accessToken, refreshToken } = client.adoptTokens(body);
        expect(response.status(), "Code exchange returns the direct response").toBe(200);
        expect(response.headers()["content-type"] === "application/json", "Token media type matches").toBe(true);
        expect(response.headers()["cache-control"] === "no-store", "Token cache policy matches").toBe(true);
        expect(response.headers().pragma === "no-cache", "Token pragma matches").toBe(true);
        expect(typeof accessToken === "string" && accessToken.trim().length > 0, "Code exchange issues an access token").toBe(true);
        expect(typeof refreshToken === "string" && refreshToken.trim().length > 0, "Code exchange issues a refresh token").toBe(true);
        expect(accessToken === refreshToken, "Access and refresh tokens differ").toBe(false);
        expect(body.token_type === "Bearer", "Token type is Bearer").toBe(true);
        expect(body.scope === SCOPE, "Token scope matches").toBe(true);
        expect(Number.isInteger(body.expires_in) && body.expires_in > 0).toBe(true);

        const control = await client.issueTokens("password");
        expect(new Set([accessToken, refreshToken, control.accessToken, control.refreshToken]).size,
          "Code and password grants have distinct token identifiers").toBe(4);

        const endpoint = realm.endpoint(spelling, "/introspect");
        for (const [token, type] of [[accessToken, "access_token"], [refreshToken, "refresh_token"]]) {
          for (const method of ["GET", "POST"]) {
            const active = await client.introspect(token, type, method, "Realm " + method + " introspection", endpoint);
            expect(active.active === true, "Introspection token is active").toBe(true);
            expect(active.client_id === client.id, "Introspection client matches").toBe(true);
            expect(active.token_type === type, "Introspection token type matches").toBe(true);
            expect(active.sub === owner.username, "Introspection owner matches").toBe(true);
            expect(active.iss === realm.oauthUrl, "Introspection issuer matches").toBe(true);
          }
        }
        const headers = { Authorization: "Bearer " + accessToken };
        const reference = await client.request.get(realm.endpoint("nested", "/userinfo"), { headers });
        expect(reference.status(), "Canonical UserInfo returns the direct response").toBe(200);
        const claims = await reference.json().catch(() => undefined);
        expect(claims?.sub === owner.username, "UserInfo owner matches").toBe(true);
        const userInfo = await client.request.get(realm.endpoint(spelling, "/userinfo"), { headers });
        expect(userInfo.status(), "Selected UserInfo returns the direct response").toBe(200);
        expect(userInfo.headers()["content-type"] === "application/json;charset=UTF-8", "UserInfo media type matches").toBe(true);
        const selected = await userInfo.json().catch(() => undefined);
        expect(isDeepStrictEqual(selected, claims), "Same-token UserInfo claims match").toBe(true);

        const revoked = await client.postRevocation(refreshToken, realm.endpoint(spelling, "/token/revoke"));
        expect(revoked.status(), "Realm revocation returns the direct response").toBe(200);
        expect(revoked.headers()["content-type"]?.split(";")[0] === "application/json", "Revocation media type matches").toBe(true);
        const revocationBody = await revoked.json().catch(() => undefined);
        expect(isDeepStrictEqual(revocationBody, {}), "Revocation body is the characterized empty object").toBe(true);
        expect(revoked.headers()["cache-control"] === undefined, "Revocation omits Cache-Control").toBe(true);
        expect(revoked.headers().pragma === undefined, "Revocation omits Pragma").toBe(true);
        for (const [token, type] of [[accessToken, "access_token"], [refreshToken, "refresh_token"]]) {
          const inactive = await client.introspect(token, type, "POST", "Realm token after revocation");
          expect(isInactiveIntrospection(inactive), "Revoked " + type + " is inactive through the canonical realm").toBe(true);
        }
        for (const [token, type] of [[control.accessToken, "access_token"], [control.refreshToken, "refresh_token"]]) {
          const active = await client.introspect(token, type, "POST", "Independent realm grant after revocation");
          expect(active.active === true, "Revocation preserves the independent grant").toBe(true);
          expect(active.client_id === client.id, "Introspection client matches").toBe(true);
          expect(active.sub === owner.username, "Introspection owner matches").toBe(true);
          expect(active.iss === realm.oauthUrl, "Introspection issuer matches").toBe(true);
          expect(active.token_type === type, "Introspection token type matches").toBe(true);
        }
      });
    });
  });
}
