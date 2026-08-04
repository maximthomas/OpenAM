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

import { request as httpRequest } from "node:http";
import { test, expect, request as apiRequest } from "@playwright/test";
import { OPENAM_BASE, getAdminToken, getAuthToken, PASSWORD, USERNAME } from "../common/openam-commons.mjs";
import {
  REALM, REDIRECT_URI, SCOPE, ensureProviderConfig, pkce, sessionContext,
} from "../common/oauth2-fixtures.mjs";

const CLIENT_ID = "test_client_app";
// Confidential client for the 5-E bad-secret row: the public client cannot use client_credentials, so it
// never reaches client authentication (the WWW-Authenticate challenge path).
const CONFIDENTIAL_CLIENT_ID = "test_client_confidential"
const CONFIDENTIAL_SECRET = "confidential-secret"
// Consent-capable client for the 5-E2 /authorize rows. The provider is created with
// clientsCanSkipConsent:true and the other two clients with isConsentImplied:true, so
// AuthorizationService's requireConsent = !clientsCanSkipConsent || !isConsentImplied() is false for
// both of them and ResourceOwnerConsentRequired is never thrown. isConsentImplied:false makes
// requireConsent true whatever the service flag says. responseTypes [code, token] additionally makes
// the query-vs-fragment error rows reachable from the same fixture.
const CONSENT_CLIENT_ID = "test_client_consent"
/**
 * Ensures an OAuth2 client application exists in the OpenAM instance.
 * Creates it with default configuration if it doesn't exist.
 */

async function ensureOAuth2ClientExists(adminToken, request) {
  const response = await request.get(
    `${OPENAM_BASE}/json/realms/${REALM}/realm-config/agents/OAuth2Client/${CLIENT_ID}`,
    {
      method: "GET",
      headers: {
        "iPlanetDirectoryPro": adminToken,
        "Accept-API-Version": "protocol=2.0,resource=1.0",
      },
    }
  );

  if (response.status() === 404) {
    // Client doesn't exist, create it
    const createResponse = await request.put(
      `${OPENAM_BASE}/json/realms/${REALM}/realm-config/agents/OAuth2Client/${CLIENT_ID}`,
      {
        headers: {
          "iPlanetDirectoryPro": adminToken,
          "Content-Type": "application/json",
          "Accept-API-Version": "protocol=2.0,resource=1.0",
        },
        data: {
          "com.forgerock.openam.oauth2provider.clientType": "Public",
          "com.forgerock.openam.oauth2provider.redirectionURIs": [`[0]=${REDIRECT_URI}`],
          "com.forgerock.openam.oauth2provider.scopes": [`[0]=${SCOPE}`],
          "com.forgerock.openam.oauth2provider.defaultScopes": [`[0]=${SCOPE}`],
          "com.forgerock.openam.oauth2provider.grantTypes": ["[0]=authorization_code"],
          "com.forgerock.openam.oauth2provider.responseTypes": ["[0]=code"],
          "com.forgerock.openam.oauth2provider.tokenEndPointAuthMethod": "none",
          "isConsentImplied": true,
          "sunIdentityServerDeviceStatus": "Active"
        },
      }
    );

    if (!createResponse.ok()) {
      throw new Error(
        `Failed to create OAuth2 client: ${createResponse.statusText()}`
      );
    }
    console.log(`OAuth2 client "${CLIENT_ID}" created successfully`);
  } else if (!response.ok()) {
    throw new Error(
      `Failed to check OAuth2 client: ${response.statusText()}`
    );
  } else {
    console.log(`OAuth2 client "${CLIENT_ID}" already exists`);
  }
}

/**
 * Ensures a Confidential OAuth2 client (client_secret_basic) exists, for the 5-E bad-secret row.
 */
async function ensureConfidentialClientExists(adminToken, request) {
  const response = await request.get(
    `${OPENAM_BASE}/json/realms/${REALM}/realm-config/agents/OAuth2Client/${CONFIDENTIAL_CLIENT_ID}`,
    {
      headers: {
        "iPlanetDirectoryPro": adminToken,
        "Accept-API-Version": "protocol=2.0,resource=1.0",
      },
    }
  );

  if (response.status() === 404) {
    const createResponse = await request.put(
      `${OPENAM_BASE}/json/realms/${REALM}/realm-config/agents/OAuth2Client/${CONFIDENTIAL_CLIENT_ID}`,
      {
        headers: {
          "iPlanetDirectoryPro": adminToken,
          "Content-Type": "application/json",
          "Accept-API-Version": "protocol=2.0,resource=1.0",
        },
        data: {
          "userpassword": CONFIDENTIAL_SECRET,
          "com.forgerock.openam.oauth2provider.clientType": "Confidential",
          "com.forgerock.openam.oauth2provider.scopes": [`[0]=${SCOPE}`],
          "com.forgerock.openam.oauth2provider.defaultScopes": [`[0]=${SCOPE}`],
          "com.forgerock.openam.oauth2provider.grantTypes": ["[0]=client_credentials"],
          "com.forgerock.openam.oauth2provider.tokenEndPointAuthMethod": "client_secret_basic",
          "isConsentImplied": true,
          "sunIdentityServerDeviceStatus": "Active"
        },
      }
    );
    if (!createResponse.ok()) {
      throw new Error(`Failed to create confidential client: ${createResponse.statusText()}`);
    }
    console.log(`Confidential client "${CONFIDENTIAL_CLIENT_ID}" created successfully`);
  } else if (!response.ok()) {
    throw new Error(
      `Failed to check confidential client: ${response.statusText()}`
    );
  } else {
    console.log(`Confidential client "${CONFIDENTIAL_CLIENT_ID}" already exists`);
  }
}

/**
 * Ensures a consent-requiring OAuth2 client exists, for the 5-E2 /authorize consent rows.
 */
async function ensureConsentClientExists(adminToken, request) {
  const response = await request.get(
    `${OPENAM_BASE}/json/realms/${REALM}/realm-config/agents/OAuth2Client/${CONSENT_CLIENT_ID}`,
    {
      headers: {
        "iPlanetDirectoryPro": adminToken,
        "Accept-API-Version": "protocol=2.0,resource=1.0",
      },
    }
  );

  if (response.status() === 404) {
    const createResponse = await request.put(
      `${OPENAM_BASE}/json/realms/${REALM}/realm-config/agents/OAuth2Client/${CONSENT_CLIENT_ID}`,
      {
        headers: {
          "iPlanetDirectoryPro": adminToken,
          "Content-Type": "application/json",
          "Accept-API-Version": "protocol=2.0,resource=1.0",
        },
        data: {
          "com.forgerock.openam.oauth2provider.clientType": "Public",
          "com.forgerock.openam.oauth2provider.redirectionURIs": [`[0]=${REDIRECT_URI}`],
          "com.forgerock.openam.oauth2provider.scopes": [`[0]=${SCOPE}`],
          "com.forgerock.openam.oauth2provider.defaultScopes": [`[0]=${SCOPE}`],
          "com.forgerock.openam.oauth2provider.grantTypes": ["[0]=authorization_code", "[1]=implicit"],
          "com.forgerock.openam.oauth2provider.responseTypes": ["[0]=code", "[1]=token"],
          "com.forgerock.openam.oauth2provider.tokenEndPointAuthMethod": "none",
          // The point of this fixture: consent is NOT implied, so ResourceOwnerConsentRequired is thrown.
          "isConsentImplied": false,
          "sunIdentityServerDeviceStatus": "Active"
        },
      }
    );
    if (!createResponse.ok()) {
      throw new Error(`Failed to create consent client: ${createResponse.statusText()}`);
    }
    console.log(`Consent client "${CONSENT_CLIENT_ID}" created successfully`);
  } else if (!response.ok()) {
    throw new Error(
      `Failed to check consent client: ${response.statusText()}`
    );
  } else {
    console.log(`Consent client "${CONSENT_CLIENT_ID}" already exists`);
  }
}

test.beforeAll(async ({ request }) => {
  const adminToken = await getAdminToken(request)

  if (!adminToken) {
    test.skip(true, "ADMIN_TOKEN not set");

  }
  await ensureProviderConfig(adminToken, request);
  await ensureOAuth2ClientExists(adminToken, request);
  await ensureConfidentialClientExists(adminToken, request);
  await ensureConsentClientExists(adminToken, request);
});

let accessToken;

test.describe("OAuth Service test", () => {
  test("Should receive an auth code and exchange it to access token", async ({ request }) => {

      function generateVerifier(length = 64) {
          const array = new Uint32Array(length);
          crypto.getRandomValues(array);
          const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
          return Array.from(array, x => chars[x % chars.length]).join('');
      }

      async function generateChallenge(verifier) {
          const encoder = new TextEncoder();
          const data = encoder.encode(verifier);
          const hash = await crypto.subtle.digest('SHA-256', data);
          
          return btoa(String.fromCharCode(...new Uint8Array(hash)))
              .replace(/\+/g, '-')
              .replace(/\//g, '_')
              .replace(/=+$/, '');
      }

      const demoToken = await getAuthToken(request, USERNAME, PASSWORD);

      const state = "random-state";

      const verifier = generateVerifier();

      const challenge = await generateChallenge(verifier);

      const codeResponse = await request.get(
        `${OPENAM_BASE}/oauth2/authorize`, {
          headers: {
            "iPlanetDirectoryPro": demoToken,
          },
          params: {
            response_type: "code",
            client_id: CLIENT_ID,
            redirect_uri: REDIRECT_URI,
            scope: SCOPE,
            state: state,
            code_challenge: challenge,
            code_challenge_method: "S256"
          },
          maxRedirects: 0
        }
      )

      expect(codeResponse.status()).toBe(302);
      
      const headers = codeResponse.headers();

      const location = headers['location'];

      const locationURL = new URL(location);

      const code = locationURL.searchParams.get("code");

      expect(code).toBeTruthy()
    

      const response = await request.post(`${OPENAM_BASE}/oauth2/access_token`, {
        form: {
          grant_type: 'authorization_code',
          client_id: CLIENT_ID,
          code: code,
          redirect_uri: REDIRECT_URI,
          code_verifier: verifier,
          state: state
        },
        headers: {
          'Accept': 'application/json'
        }
      });

      expect(response.ok()).toBeTruthy();

      const tokens = await response.json();

      expect(tokens).toHaveProperty('access_token');

      accessToken = tokens.access_token

      console.log(`Got access token: ${accessToken}`);
  });

  test("Get user info with access token", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/oauth2/userinfo`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json'
        }
      });

      expect(response.ok()).toBeTruthy();
      expect(response.status()).toBe(200);

      // 4. Получение и вывод тела ответа
      const userInfo = await response.json();
      expect(userInfo.sub).toBe('demo');
      console.log('User Info Claims:', userInfo);

  });

  test("Get user info with access token in POST form body", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/userinfo`, {
        form: {
          access_token: accessToken
        },
        headers: {
          'Accept': 'application/json'
        }
      });

      expect(response.status()).toBe(200);

      const userInfo = await response.json();
      expect(userInfo.sub).toBe('demo');
  });

  test("Reject user info request with token in both header and form body", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/userinfo`, {
        form: {
          access_token: accessToken
        },
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json'
        }
      });

      // UserInfoService rejects a token supplied in both locations with server_error
      expect(response.status()).toBe(400);

      const error = await response.json();
      expect(error.error).toBe('server_error');
  });

  test("Get token info with access token in query parameter", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/oauth2/tokeninfo`, {
        params: {
          access_token: accessToken
        },
        headers: {
          'Accept': 'application/json'
        }
      });

      expect(response.status()).toBe(200);

      const tokenInfo = await response.json();
      expect(tokenInfo.grant_type).toBe('authorization_code');
      expect(tokenInfo.scope).toContain(SCOPE);
  });

  test("Get token info with access token in header", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/oauth2/tokeninfo`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json'
        }
      });

      expect(response.status()).toBe(200);

      const tokenInfo = await response.json();
      expect(tokenInfo.grant_type).toBe('authorization_code');
      expect(tokenInfo.scope).toContain(SCOPE);
  });

  test("Reject token info request with token in both header and query parameter", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/oauth2/tokeninfo`, {
        params: {
          access_token: accessToken
        },
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json'
        }
      });

      // TokenInfoService rejects a token supplied in both locations with invalid_request
      expect(response.status()).toBe(400);

      const error = await response.json();
      expect(error.error).toBe('invalid_request');
  });

});

/**
 * Step 5-E: the /access_token contract lock, recorded against LIVE RESTLET (must land before 5d-1, since
 * Restlet stops serving /oauth2 at the flip). The two contract-certain rows assert the shape; the
 * GET /access_token row is RECORDED BY OBSERVATION (finding 1) and is the oracle for the deliberate 405
 * change at 5d-1 -- do not predict its exact status here, pin it from the logged capture.
 */
test.describe("OAuth2 /access_token contract lock (5-E, live Restlet)", () => {

  test("unknown grant_type -> 400 unsupported_grant_type", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/access_token`, {
      form: { grant_type: "no_such_grant", client_id: CLIENT_ID },
      headers: { Accept: "application/json" },
    });
    const body = await response.json();
    console.log(`[5-E] unknown grant_type -> ${response.status()} ${JSON.stringify(body)}`);
    // The finder gates on its known set before dispatch, so an unknown grant is unsupported_grant_type,
    // never invalid_grant (which the second, service-level map would give).
    expect(response.status()).toBe(400);
    expect(body.error).toBe("unsupported_grant_type");
  });

  test("bad client secret -> 401 with WWW-Authenticate", async ({ request }) => {
    // A CONFIDENTIAL client: the public client hits unauthorized_client (400) before client auth runs.
    const badBasic = Buffer.from(`${CONFIDENTIAL_CLIENT_ID}:wrong-secret`).toString("base64");
    const response = await request.post(`${OPENAM_BASE}/oauth2/access_token`, {
      form: { grant_type: "client_credentials", scope: SCOPE },
      headers: { Accept: "application/json", Authorization: `Basic ${badBasic}` },
    });
    const body = await response.json();
    const wwwAuth = response.headers()["www-authenticate"];
    console.log(`[5-E] bad secret -> ${response.status()} WWW-Authenticate=${wwwAuth} ${JSON.stringify(body)}`);
    // An Authorization header that fails client auth carries the RFC 6749 5.2 challenge.
    expect(response.status()).toBe(401);
    expect(body.error).toBe("invalid_client");
    expect(wwwAuth).toMatch(/^Basic realm=/);
  });

  test("GET /access_token records the live-Restlet response (finding 1 oracle)", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/oauth2/access_token`, {
      headers: { Accept: "application/json" },
      maxRedirects: 0,
    });
    const body = await response.json();
    console.log(`[5-E] GET /access_token -> status=${response.status()} body=${JSON.stringify(body)}`);
    // OBSERVED against live Restlet (2026-07-24): TokenEndpointFilter.validateMethod's 405 STANDS -- the
    // OAuth2Filter "write error then CONTINUE" path does NOT overwrite it with the finder's 400, so finding 1's
    // 400-invalid_request prediction was wrong. At 5d-1 the @Post-only CHF handler also yields 405, but its
    // body error code is framework-derived (invalid_request via OAuth2ErrorFilter), not method_not_allowed:
    // flag THAT body divergence in the 5d-1 smoke diff, NOT a status change.
    expect(response.status()).toBe(405);
    expect(body.error).toBe("method_not_allowed");
    expect(body.error_description).toBe("Required Method: POST found: GET");
    // OBSERVED: /access_token stamps the OAuth2Filter cache headers on the ERROR path too (finding 1).
    expect(response.headers()["cache-control"]).toBe("no-store");
    expect(response.headers()["pragma"]).toBe("no-cache");
  });

});

/**
 * Step 5-E cache-header contract lock (finding 1 oracle), recorded against LIVE RESTLET and thus a GATE that
 * must land before 5d-1 (Restlet stops serving /oauth2 at the flip). Three distinct cache contracts, captured
 * VERBATIM while Restlet still serves them -- the CHF handlers must byte-match at the 5d-1 diff:
 *   - /access_token : "Cache-Control: no-store" + "Pragma: no-cache"   (success AND error; from OAuth2Filter)
 *   - /tokeninfo    : "Cache-Control: no-cache, no-store", NO Pragma    (success only; from the resource)
 *   - everything else (userinfo, introspect, ...) : no cache headers, ever
 * Do not "tidy" these strings -- the exact bytes ARE the oracle. Observed 2026-07-24 against openidentityplatform/openam.
 */
test.describe("OAuth2 cache-header contract lock (5-E, live Restlet)", () => {

  const CC_BASIC = Buffer.from(`${CONFIDENTIAL_CLIENT_ID}:${CONFIDENTIAL_SECRET}`).toString("base64");
  let ccToken;

  test.beforeAll(async ({ request }) => {
    // client_credentials is a single self-contained grant (no PKCE dance); the 200 token response is itself
    // the /access_token SUCCESS-path cache-header oracle.
    const resp = await request.post(`${OPENAM_BASE}/oauth2/access_token`, {
      form: { grant_type: "client_credentials", scope: SCOPE },
      headers: { Accept: "application/json", Authorization: `Basic ${CC_BASIC}` },
    });
    expect(resp.status()).toBe(200);
    console.log(`[5-E] /access_token success -> Cache-Control=${resp.headers()["cache-control"]} Pragma=${resp.headers()["pragma"]}`);
    expect(resp.headers()["cache-control"]).toBe("no-store");
    expect(resp.headers()["pragma"]).toBe("no-cache");
    ccToken = (await resp.json()).access_token;
  });

  test("/tokeninfo success carries 'no-cache, no-store' and NO Pragma", async ({ request }) => {
    const response = await request.get(`${OPENAM_BASE}/oauth2/tokeninfo`, {
      params: { access_token: ccToken },
      headers: { Accept: "application/json" },
    });
    const cc = response.headers()["cache-control"];
    const pragma = response.headers()["pragma"];
    const ct = response.headers()["content-type"];
    console.log(`[5-E] /tokeninfo success -> ${response.status()} Cache-Control=${cc} Pragma=${pragma} Content-Type=${ct}`);
    expect(response.status()).toBe(200);
    // Verbatim oracle: one header, a space after the comma, no Pragma -- exactly TokenInfoHandler's hardcoded string.
    expect(cc).toBe("no-cache, no-store");
    expect(pragma).toBeUndefined();
    // Restlet renders JSON as "application/json" with NO charset; the CHF setEntity(Map) emits
    // "application/json; charset=UTF-8" -> a KNOWN, deliberate Content-Type byte-diff to FLAG (not fix) at 5d-1.
    expect(ct).toBe("application/json");
  });

  test("/introspect success carries no cache headers", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/introspect`, {
      form: { token: ccToken },
      headers: { Accept: "application/json", Authorization: `Basic ${CC_BASIC}` },
    });
    console.log(`[5-E] /introspect success -> ${response.status()} Cache-Control=${response.headers()["cache-control"]} Pragma=${response.headers()["pragma"]}`);
    expect(response.status()).toBe(200);
    expect(response.headers()["cache-control"]).toBeUndefined();
    expect(response.headers()["pragma"]).toBeUndefined();
  });

  test("/userinfo carries no cache headers", async ({ request }) => {
    // A client_credentials token has no resource owner, so userinfo returns 400 here -- but the cache-header
    // contract is outcome-independent: neither the 200 (see the functional test above) nor this 400 adds headers.
    const response = await request.get(`${OPENAM_BASE}/oauth2/userinfo`, {
      headers: { Accept: "application/json", Authorization: `Bearer ${ccToken}` },
    });
    console.log(`[5-E] /userinfo -> ${response.status()} Cache-Control=${response.headers()["cache-control"]} Pragma=${response.headers()["pragma"]}`);
    expect(response.headers()["cache-control"]).toBeUndefined();
    expect(response.headers()["pragma"]).toBeUndefined();
  });

});

/**
 * Step 5-E2: the /oauth2/authorize contract lock, recorded against LIVE RESTLET. This is a GATE for phase
 * 5b-1 (docs/migration/restlet/phase-5b-1.md): Restlet stops serving /oauth2 at the 5d-1 flip, so these rows
 * cannot be recorded afterwards, and rows 7-8 are what DECIDE whether the CHF AuthorizeHandler validates the
 * method and the content type at all (D8) -- the OAuth2Filter "write the error then return CONTINUE" path
 * makes that unpredictable, exactly as it was for GET /access_token in 5-E.
 *
 * Every value below was OBSERVED first and only then asserted (2026-07-26, openam-e2e image built from this
 * tree). Do not "tidy" a string here: the exact bytes ARE the oracle for the 5d-1 byte diff.
 *
 * Environment note: this OAuth2 provider enforces PKCE, so a `code` request without code_challenge fails
 * validation with invalid_request long before it reaches the session/consent logic. Every row that needs to
 * get PAST validation therefore carries a real S256 challenge.
 *
 * Session note: on /authorize the `iPlanetDirectoryPro` HEADER does not authenticate -- only the COOKIE does
 * (observed: header-only requests get the 301 to /UI/Login). That is the mirror image of the cookie gotcha in
 * docs/test-infrastructure.md, so each row runs in a disposable context whose cookie jar is seeded
 * explicitly with exactly the identity that row needs.
 */
test.describe("OAuth2 /authorize contract lock (5-E2, live Restlet)", () => {

  // The deployment's context path, which several rows assert is part of the form target. Derived rather
  // than hardcoded so the oracle still runs against a deployment mounted somewhere other than /openam.
  const CONTEXT_PATH = new URL(OPENAM_BASE).pathname.replace(/\/$/, "");

  let CHALLENGE;
  let demoToken;
  /** No cookies at all -- the genuinely unauthenticated case. */
  let anonCtx;
  /** Cookie jar holding the demo session, and nothing else. */
  let demoCtx;

  /** A context whose jar carries the demo session plus any extra cookies this row needs. */
  async function seededContext(extraCookies = []) {
    return sessionContext(apiRequest, demoToken, extraCookies);
  }

  /** The authorize query string, built by hand so parameter ORDER is pinned (row 1 asserts it inside goto). */
  function authorizeQuery({ clientId = CLIENT_ID, responseType = "code", scope = SCOPE,
                            redirectUri = REDIRECT_URI, state, withPkce = true, loginHint } = {}) {
    const parts = [
      `response_type=${encodeURIComponent(responseType)}`,
      `client_id=${encodeURIComponent(clientId)}`,
      `redirect_uri=${encodeURIComponent(redirectUri)}`,
      `scope=${encodeURIComponent(scope)}`,
    ];
    if (state) parts.push(`state=${encodeURIComponent(state)}`);
    if (loginHint) parts.push(`login_hint=${encodeURIComponent(loginHint)}`);
    if (withPkce) parts.push(`code_challenge=${encodeURIComponent(CHALLENGE)}`, "code_challenge_method=S256");
    return parts.join("&");
  }

  /**
   * The oauth2Data values the consent page interpolates, scraped out of the rendered page.
   *
   * The key is anchored on a preceding delimiter: unanchored, a longer key that merely ENDS in the one
   * asked for (`sessionState` for `state`, `xsrf` for `csrf`) would match first and the row would then be
   * asserting the recorded bytes against the wrong field.
   */
  function consentPageValue(html, key) {
    const match = new RegExp(`(?:^|[{,\\s])${key}:\\s*"([^"]*)"`).exec(html);
    return match && match[1];
  }

  test.beforeAll(async () => {
    // The shared fixed verifier/challenge pair, so the recorded goto/formTarget values are reproducible.
    CHALLENGE = (await pkce()).challenge;

    const loginCtx = await apiRequest.newContext();
    try {
      demoToken = await getAuthToken(loginCtx, USERNAME, PASSWORD);
    } finally {
      await loginCtx.dispose();
    }
    anonCtx = await apiRequest.newContext();
    demoCtx = await seededContext();
  });

  test.afterAll(async () => {
    await anonCtx?.dispose();
    await demoCtx?.dispose();
  });

  test("row 1: unauthenticated GET -> 301 to /UI/Login carrying the request as goto", async () => {
    const query = authorizeQuery({ state: "row1state" });
    const authorizeUrl = `${OPENAM_BASE}/oauth2/authorize?${query}`;
    const response = await anonCtx.get(authorizeUrl, { maxRedirects: 0 });
    const location = response.headers()["location"];
    console.log(`[5-E2] row1 unauthenticated GET -> ${response.status()} Location=${location}`);

    // OBSERVED: 301 (not 302) -- ResourceOwnerAuthenticationRequired carries 307 redirection_temporary as its
    // own status, but AuthorizeResource turns it into a Restlet permanent redirect. D13 pins this login URI.
    expect(response.status()).toBe(301);
    // Verbatim prefix: the realm comes FIRST and is percent-encoded ("%2F", not "/").
    expect(location.startsWith(`${OPENAM_BASE}/UI/Login?realm=%2F&goto=`)).toBe(true);
    const loginUrl = new URL(location);
    expect(loginUrl.searchParams.get("realm")).toBe("/");
    // goto is the WHOLE original request URL, absolute, with its query intact and singly percent-encoded
    // (so the already-encoded redirect_uri shows up double-encoded on the wire).
    expect(loginUrl.searchParams.get("goto")).toBe(authorizeUrl);
    expect(location).toContain("redirect_uri%3Dhttp%253A%252F%252Fapp.invalid%252Fcb");
    // /authorize is one of the two endpoints the Restlet OAuth2Filter stamps -- on EVERY response.
    expect(response.headers()["cache-control"]).toBe("no-store");
    expect(response.headers()["pragma"]).toBe("no-cache");
  });

  test("row 2: authenticated GET on a consent-requiring client -> the 200 consent page", async () => {
    const query = authorizeQuery({ clientId: CONSENT_CLIENT_ID, state: "row2state" });
    const response = await demoCtx.get(`${OPENAM_BASE}/oauth2/authorize?${query}`, { maxRedirects: 0 });
    const html = await response.text();
    console.log(`[5-E2] row2 consent page -> ${response.status()} Content-Type=${response.headers()["content-type"]} bytes=${html.length}`);

    expect(response.status()).toBe(200);
    // Verbatim: NO space after the semicolon. The CHF FreemarkerTemplateRenderer must match these bytes.
    expect(response.headers()["content-type"]).toBe("text/html;charset=UTF-8");
    expect(response.headers()["cache-control"]).toBe("no-store");
    expect(response.headers()["pragma"]).toBe("no-cache");
    // CsrfProtection.createCsrfToken also writes the token to a cookie; the page carries the same value.
    expect(response.headers()["set-cookie"]).toContain("oauth2_csrf=");
    expect(response.headers()["set-cookie"]).toContain("Path=/;HttpOnly;SameSite=Lax");

    // The consent data model as it reaches the wire (R-5.5: an enumerating CHF port that drops a key renders
    // this page with the corresponding <#if> false, and nothing else would notice).
    expect(consentPageValue(html, "csrf")).toBeTruthy();
    expect(consentPageValue(html, "clientId")).toBe(CONSENT_CLIENT_ID);
    expect(consentPageValue(html, "displayName")).toBe(CONSENT_CLIENT_ID);
    expect(consentPageValue(html, "userName")).toBe("Demo Demo");
    expect(consentPageValue(html, "responseType")).toBe("code");
    expect(consentPageValue(html, "redirectUri")).toBe(REDIRECT_URI);
    expect(consentPageValue(html, "scope")).toBe(SCOPE);
    expect(consentPageValue(html, "state")).toBe("row2state");
    expect(html).toContain("isSaveConsentEnabled: true");
    expect(html).toContain('displayScopes: [ { "name": "profile"');
    // `target` carries the CONTEXT PATH and the full query -- the CHF port builds it from the CHF Request URI
    // (phase-5b-1 finding 4), and "/openam/..." is what proves the context path is included.
    expect(consentPageValue(html, "formTarget")).toBe(`\\${CONTEXT_PATH}/oauth2/authorize?${query}`);
    // No Accept-Language on the request -> Restlet's ClientInfo yields the wildcard tag (the D3 oracle's
    // absent-header row).
    expect(consentPageValue(html, "locale")).toBe("*");
  });

  test("row 3: unknown client_id -> 400 HTML error page, no Location", async () => {
    const query = authorizeQuery({ clientId: "no_such_client", state: "row3state" });
    const response = await demoCtx.get(`${OPENAM_BASE}/oauth2/authorize?${query}`, { maxRedirects: 0 });
    const html = await response.text();
    console.log(`[5-E2] row3 unknown client -> ${response.status()} Content-Type=${response.headers()["content-type"]}`);

    // InvalidClientException is NEVER_REDIRECT: the error is rendered, never sent to the redirect_uri.
    expect(response.status()).toBe(400);
    expect(response.headers()["content-type"]).toBe("text/html;charset=UTF-8");
    expect(response.headers()["location"]).toBeUndefined();
    expect(html).toContain('message: "invalid_client"');
    expect(html).toContain('description: "Client authentication failed"');
    expect(response.headers()["cache-control"]).toBe("no-store");
    expect(response.headers()["pragma"]).toBe("no-cache");
  });

  test("row 4: registered client, unregistered redirect_uri -> 400 HTML error page, no Location", async () => {
    const query = authorizeQuery({ redirectUri: "http://evil.invalid/cb", state: "row4state" });
    const response = await demoCtx.get(`${OPENAM_BASE}/oauth2/authorize?${query}`, { maxRedirects: 0 });
    const html = await response.text();
    console.log(`[5-E2] row4 redirect_uri mismatch -> ${response.status()} Location=${response.headers()["location"]}`);

    // The no-auto-redirect policy: an unvalidated redirect_uri never receives the error.
    expect(response.status()).toBe(400);
    expect(response.headers()["content-type"]).toBe("text/html;charset=UTF-8");
    expect(response.headers()["location"]).toBeUndefined();
    expect(html).toContain('message: "redirect_uri_mismatch"');
    expect(html).toContain('description: "The redirection URI provided does not match a pre-registered value."');
  });

  test("row 5: post-validation error with response_type=code -> 302, parameters in the QUERY", async () => {
    const query = authorizeQuery({ scope: "no_such_scope", state: "row5state" });
    const response = await demoCtx.get(`${OPENAM_BASE}/oauth2/authorize?${query}`, { maxRedirects: 0 });
    const location = response.headers()["location"];
    console.log(`[5-E2] row5 invalid_scope code -> ${response.status()} Location=${location}`);

    expect(response.status()).toBe(302);
    expect(location.startsWith(`${REDIRECT_URI}?`)).toBe(true);
    expect(location).not.toContain("#");
    const target = new URL(location);
    expect(target.searchParams.get("error")).toBe("invalid_scope");
    expect(target.searchParams.get("error_description")).toBe("Unknown/invalid scope(s): [no_such_scope]");
    expect(target.searchParams.get("state")).toBe("row5state");
    expect(response.headers()["cache-control"]).toBe("no-store");
    expect(response.headers()["pragma"]).toBe("no-cache");
  });

  test("row 6: the same error with response_type=token -> 302, parameters in the FRAGMENT", async () => {
    const query = authorizeQuery({
      clientId: CONSENT_CLIENT_ID, responseType: "token", scope: "no_such_scope", state: "row6state", withPkce: false,
    });
    const response = await demoCtx.get(`${OPENAM_BASE}/oauth2/authorize?${query}`, { maxRedirects: 0 });
    const location = response.headers()["location"];
    console.log(`[5-E2] row6 invalid_scope token -> ${response.status()} Location=${location}`);

    // R-5b1.3: the ERROR location comes from the exception's parameterLocation, not from the token's
    // isFragment(). An implicit-flow error goes to the fragment; the query stays empty.
    expect(response.status()).toBe(302);
    const [base, fragment] = location.split("#");
    expect(base).toBe(REDIRECT_URI);
    expect(fragment).toBeTruthy();
    const params = new URLSearchParams(fragment);
    expect(params.get("error")).toBe("invalid_scope");
    expect(params.get("error_description")).toBe("Unknown/invalid scope(s): [no_such_scope]");
    expect(params.get("state")).toBe("row6state");
  });

  test("row 7: PUT /oauth2/authorize records the live-Restlet response (D8 input)", async () => {
    const response = await anonCtx.fetch(`${OPENAM_BASE}/oauth2/authorize?${authorizeQuery()}`, {
      method: "PUT", maxRedirects: 0,
    });
    const body = await response.json();
    console.log(`[5-E2] row7 PUT -> ${response.status()} ${JSON.stringify(body)}`);

    // OBSERVED 2026-07-26: AuthorizeEndpointFilter.validateMethod's 405 STANDS on the wire -- the OAuth2Filter
    // CONTINUE fall-through does NOT let AuthorizeResource overwrite it. Same outcome as GET /access_token in
    // 5-E, so the CONTINUE bug is consistently invisible on the wire.
    // At 5d-1 the @Get/@Post-only CHF handler also yields 405, but the BODY code becomes framework-derived
    // (invalid_request via OAuth2ErrorFilter) instead of method_not_allowed, and the body becomes JSON with a
    // charset: flag THAT as a 5d-1 body divergence, not a status change. D8: no verb check in the handler.
    expect(response.status()).toBe(405);
    expect(response.headers()["content-type"]).toBe("application/json");
    expect(body.error).toBe("method_not_allowed");
    expect(body.error_description).toBe("Required Method: GET or POST found: PUT");
    expect(response.headers()["cache-control"]).toBe("no-store");
    expect(response.headers()["pragma"]).toBe("no-cache");
  });

  test("row 8: POST with a JSON body records the live-Restlet response (D8 input)", async () => {
    const response = await anonCtx.post(`${OPENAM_BASE}/oauth2/authorize`, {
      headers: { "Content-Type": "application/json" },
      data: { response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: SCOPE },
      maxRedirects: 0,
    });
    const body = await response.json();
    console.log(`[5-E2] row8 POST application/json -> ${response.status()} ${JSON.stringify(body)}`);

    // OBSERVED 2026-07-26: AuthorizeEndpointFilter.validateContentType's 400 SURVIVES too -- the resource never
    // gets to overwrite it. D8 is therefore RESOLVED IN THE AFFIRMATIVE: AuthorizeHandler must reproduce the
    // content-type check (empty-body-tolerant, charset-safe, case-insensitive) and RETURN, not fall through.
    expect(response.status()).toBe(400);
    expect(response.headers()["content-type"]).toBe("application/json");
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toBe("Invalid Content Type");
    expect(response.headers()["cache-control"]).toBe("no-store");
    expect(response.headers()["pragma"]).toBe("no-cache");
  });

  test("row 9: consent POST decision=allow -> 302 with the code in the QUERY", async () => {
    const query = authorizeQuery({ clientId: CONSENT_CLIENT_ID, state: "row9state" });
    const consentCtx = await seededContext();
    try {
      const page = await consentCtx.get(`${OPENAM_BASE}/oauth2/authorize?${query}`, { maxRedirects: 0 });
      const html = await page.text();
      expect(page.status()).toBe(200);
      const csrf = consentPageValue(html, "csrf");
      // The page's own target is where the browser posts back -- unescape the FreeMarker ?js_string slash.
      const target = consentPageValue(html, "formTarget").replace(/\\\//g, "/");
      expect(csrf).toBeTruthy();
      expect(target).toBe(`${CONTEXT_PATH}/oauth2/authorize?${query}`);

      const response = await consentCtx.post(`${new URL(OPENAM_BASE).origin}${target}`, {
        form: { decision: "allow", save_consent: "off", csrf },
        maxRedirects: 0,
      });
      const location = response.headers()["location"];
      console.log(`[5-E2] row9 consent POST -> ${response.status()} Location=${location} Set-Cookie=${JSON.stringify(response.headersArray().filter((h) => h.name.toLowerCase() === "set-cookie").map((h) => h.value))}`);

      expect(response.status()).toBe(302);
      // AuthorizationToken.isFragment() is false for the code flow -> the parameters are APPENDED to the query.
      expect(location.startsWith(`${REDIRECT_URI}?`)).toBe(true);
      expect(location).not.toContain("#");
      const redirect = new URL(location);
      expect(redirect.searchParams.get("code")).toBeTruthy();
      expect(redirect.searchParams.get("state")).toBe("row9state");
      expect(redirect.searchParams.get("scope")).toBe(SCOPE);
      expect(redirect.searchParams.get("client_id")).toBe(CONSENT_CLIENT_ID);
      expect(redirect.searchParams.get("iss")).toBe(`${OPENAM_BASE}/oauth2`);
      expect(response.headers()["cache-control"]).toBe("no-store");
      expect(response.headers()["pragma"]).toBe("no-cache");
      // No login_hint on this request, so no oidcLoginHint cookie traffic at all (row 9b owns that contract).
      expect(response.headers()["set-cookie"] ?? "").not.toContain("oidcLoginHint");
    } finally {
      await consentCtx.dispose();
    }
  });

  /*
   * Row 9b -- the oidcLoginHint Set-Cookie contract (the D6 baseline row 9 was meant to carry). Split out
   * because the observation CORRECTED the plan: phase-5b-1 D6 assumed a Restlet authorize success emits the
   * `set` and then the max-age-0 delete. It does not. AuthorizeRequestHook.afterAuthorizeSuccess RETRACTS the
   * CookieSetting that beforeAuthorizeHandling added, and only then calls removeCookie, which emits the delete
   * ONLY IF THE REQUEST CARRIED THE COOKIE (LoginHintHook.java:67-75, :116-123). So a success with no prior
   * cookie emits NOTHING. The CHF port cannot retract a servlet cookie, so its afterAuthorizeSuccess must emit
   * the max-age-0 delete UNCONDITIONALLY when its before-hook set one -- otherwise the first authorize would
   * leave oidcLoginHint set in the browser, which is an END-STATE divergence, not just an extra header.
   */
  test("row 9b: the oidcLoginHint cookie contract on the live wire (D6 baseline)", async () => {
    const setCookies = (response) =>
      response.headersArray().filter((h) => h.name.toLowerCase() === "set-cookie").map((h) => h.value);

    // (a) consent page: the request does NOT succeed, so the before-hook's `set` reaches the wire.
    const pageCtx = await seededContext();
    let consentSetCookies;
    try {
      const page = await pageCtx.get(
        `${OPENAM_BASE}/oauth2/authorize?${authorizeQuery({ clientId: CONSENT_CLIENT_ID, state: "row9b-a", loginHint: "demo" })}`,
        { maxRedirects: 0 });
      expect(page.status()).toBe(200);
      consentSetCookies = setCookies(page);
    } finally {
      await pageCtx.dispose();
    }
    console.log(`[5-E2] row9b consent page Set-Cookie=${JSON.stringify(consentSetCookies)}`);
    // Verbatim: SPACES after the semicolons here, unlike the oauth2_csrf cookie above.
    expect(consentSetCookies).toContain("oidcLoginHint=demo; Path=/; HttpOnly");

    // (b) success, NO prior cookie: zero oidcLoginHint headers -- the set is retracted and no delete is added.
    const freshCtx = await seededContext();
    let freshSetCookies;
    try {
      const ok = await freshCtx.get(
        `${OPENAM_BASE}/oauth2/authorize?${authorizeQuery({ state: "row9b-b", loginHint: "demo" })}`,
        { maxRedirects: 0 });
      expect(ok.status()).toBe(302);
      freshSetCookies = setCookies(ok);
    } finally {
      await freshCtx.dispose();
    }
    console.log(`[5-E2] row9b success, no prior cookie Set-Cookie=${JSON.stringify(freshSetCookies)}`);
    expect(freshSetCookies.filter((c) => c.includes("oidcLoginHint"))).toEqual([]);

    // (c) success WITH a prior cookie: exactly one header, the delete -- and it carries neither Path nor
    // HttpOnly, unlike the `set` in (a). Recorded as-is; the CHF delete sets Path=/ and HttpOnly, so this is a
    // known 5d-1 byte diff (and arguably a fix -- a pathless delete does not clear a Path=/ cookie).
    const primedCtx = await seededContext([{ name: "oidcLoginHint", value: "someoneelse" }]);
    let primedSetCookies;
    try {
      const ok = await primedCtx.get(
        `${OPENAM_BASE}/oauth2/authorize?${authorizeQuery({ state: "row9b-c", loginHint: "demo" })}`,
        { maxRedirects: 0 });
      expect(ok.status()).toBe(302);
      primedSetCookies = setCookies(ok);
    } finally {
      await primedCtx.dispose();
    }
    console.log(`[5-E2] row9b success, prior cookie Set-Cookie=${JSON.stringify(primedSetCookies)}`);
    const hintCookies = primedSetCookies.filter((c) => c.includes("oidcLoginHint"));
    expect(hintCookies).toHaveLength(1);
    expect(hintCookies[0].startsWith("oidcLoginHint=; Expires=")).toBe(true);
    expect(hintCookies[0]).not.toContain("Path=");
    expect(hintCookies[0]).not.toContain("HttpOnly");
  });

});

/**
 * Step 5-E5: the /oauth2 ROUTING contract lock -- realm styles, path forms, unmapped verbs, the method
 * tunnel and the request `Host` -- recorded against LIVE RESTLET. The LAST live-Restlet gate
 * (docs/migration/restlet/phase-5d-1.md): every row here describes the ROUTER, and the router is exactly what
 * the 5d-1c flip replaces, so not one of these answers can be re-recorded afterwards.
 *
 * Every value was OBSERVED first and only then asserted (2026-08-04, image `openam-e2e:5e5` built from this
 * tree, provenance checked by md5 of the deployed `openam-oauth2` jar rather than the banner). FIVE rows
 * overturned what the plan had predicted from the source -- rows 4, 5, 7, 10 and 14, each saying so in its own
 * comment. That is the whole reason this gate is written by observation.
 *
 * ⚠ Two different 404 bodies recur below, and telling them apart IS the measurement:
 *   - the ROUTER 404 -- "The server has not found anything matching the request URI" -- Restlet's own, when
 *     no route matched and the realm layer never ran;
 *   - the REALM 404 -- "No mapping organization found for organization identifier: X" -- when the unmatched
 *     element was consumed as a sub-realm by `RestletRealmRouter`'s `/{subrealm}` default route and the realm
 *     lookup then failed.
 * Which one a URL gets depends on how many path elements sit below `/oauth2` (rows 11-13), because the
 * router's attributes are populated by the route TEMPLATE, i.e. only after `doHandle` has already run: the
 * first pass always resolves the realm from the host, and only the recursive second pass sees a `subrealm`.
 *
 * ⚠ The realm message is the CAUSE's, not the router's. `RestletRealmRouter:102-104` throws
 * `ResourceException(CLIENT_ERROR_NOT_FOUND, "Realm \"" + x + "\" not found", e)`, but
 * `RestStatusService.toRepresentation:42-52` renders `status.getThrowable().getMessage()` whenever there is a
 * throwable -- so the RealmLookupException's own wording wins and the router's description never reaches the
 * wire. phase-5d-1 finding 15 predicted `Realm "bogus" not found` for these rows, and D5 built a
 * near-byte-parity argument for divergence row 15 on that prediction; both are corrected by rows 2 and 4.
 */
test.describe("/oauth2 routing contract lock (5-E5, live Restlet)", () => {

  const BASE = new URL(OPENAM_BASE);
  const OAUTH2 = `${OPENAM_BASE}/oauth2`;
  /** Realms are created through global-config (the deprecated RealmResource rejects this body). */
  const SUB_REALM = "e2e5e5realm";
  /** SmsRealmProvider's resource id is base64url of the realm PATH -- "/e2e5e5realm", not the name. */
  const SUB_REALM_ID = Buffer.from(`/${SUB_REALM}`).toString("base64url");
  const REALMS_URL = `${OPENAM_BASE}/json/global-config/realms`;

  const ROUTER_404 = {
    code: 404, reason: "Not Found",
    message: "The server has not found anything matching the request URI",
  };
  const realm404 = (identifier) => ({
    code: 404, reason: "Not Found",
    message: `No mapping organization found for organization identifier: ${identifier}`,
  });
  /** The 405 Restlet's ServerResource raises for a verb its annotations do not cover. */
  const CREST_405 = {
    code: 405, reason: "Method Not Allowed",
    message: "The method specified in the request is not allowed for the resource identified by the request URI",
  };

  let adminToken;
  /** A client_credentials token, so the /tokeninfo rows have something real to look up. */
  let ccToken;
  let demoToken;

  /**
   * A raw node:http request. Needed for three things Playwright cannot express: a `Host` header that does not
   * match the connection (row 14), path bytes a normalising client could rewrite (`//tokeninfo`, a trailing
   * slash -- row 13), and a request with no `Content-Type` at all.
   */
  function raw(path, { method = "GET", headers = {}, hostHeader, body } = {}) {
    return new Promise((resolve, reject) => {
      const req = httpRequest({
        hostname: BASE.hostname, port: BASE.port || 80, path, method,
        headers: { ...(hostHeader ? { Host: hostHeader } : {}), ...headers },
        // setHost:false only when we supply our own, or node appends a second Host header.
        setHost: hostHeader === undefined,
      }, (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (c) => { text += c; });
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, text }));
      });
      req.on("error", reject);
      req.end(body);
    });
  }

  /** `/oauth2…` as a raw path, context path included. */
  const path = (suffix) => `${BASE.pathname.replace(/\/$/, "")}/oauth2${suffix}`;
  const bodyOf = (response) => JSON.parse(response.text);

  test.beforeAll(async ({ request }) => {
    adminToken = await getAdminToken(request);

    const created = await request.post(`${REALMS_URL}?_action=create`, {
      headers: {
        iPlanetDirectoryPro: adminToken,
        "Content-Type": "application/json",
        "Accept-API-Version": "protocol=1.0,resource=1.0",
      },
      // aliases is not optional: SmsRealmProvider.validateRealmAliases rejects a body without it.
      data: { name: SUB_REALM, parentPath: "/", active: true, aliases: [] },
    });
    // 409 means a previous run left it behind, which is as good as creating it.
    if (!created.ok() && created.status() !== 409) {
      throw new Error(`Failed to create realm ${SUB_REALM}: ${created.status()} ${await created.text()}`);
    }
    console.log(`[5-E5] realm ${SUB_REALM} ready (${created.status()})`);

    const basic = Buffer.from(`${CONFIDENTIAL_CLIENT_ID}:${CONFIDENTIAL_SECRET}`).toString("base64");
    const token = await request.post(`${OAUTH2}/access_token`, {
      form: { grant_type: "client_credentials", scope: SCOPE },
      headers: { Accept: "application/json", Authorization: `Basic ${basic}` },
    });
    expect(token.status()).toBe(200);
    ccToken = (await token.json()).access_token;

    const loginCtx = await apiRequest.newContext();
    try {
      demoToken = await getAuthToken(loginCtx, USERNAME, PASSWORD);
    } finally {
      await loginCtx.dispose();
    }
  });

  test.afterAll(async ({ request }) => {
    // Best effort: a leaked empty realm would make the next run's create a 409, which is tolerated above,
    // but leaving one behind on a long-lived container is still untidy.
    const deleted = await request.delete(`${REALMS_URL}/${SUB_REALM_ID}`, {
      headers: { iPlanetDirectoryPro: adminToken, "Accept-API-Version": "protocol=1.0,resource=1.0" },
    });
    console.log(`[5-E5] realm ${SUB_REALM} teardown -> ${deleted.status()}`);
  });

  test("row 13: path forms -- a trailing slash, a case change and an empty segment are all 404", async () => {
    // ⚠ WRITTEN AND RUN FIRST, because it is the one row whose answer could redesign the CHF route table:
    // a trailing-slash 200 would mean all 15 endpoints need D2's nested-router shape, not just resource_set
    // (phase-5d-1 R-5d1.8). It does not -- every form below is a 404, so D1's flat EQUALS table stands.
    const slash = await raw(`${path("/tokeninfo")}/?access_token=${ccToken}`);
    console.log(`[5-E5] row13 /tokeninfo/ -> ${slash.status} ${slash.text}`);
    expect(slash.status).toBe(404);
    // ⚠ And it is the ROUTER 404, not the realm 404 finding 8 predicted ("falls to /{subrealm} and 404s on
    // Realm.of(root,'tokeninfo')"). One unmatched element leaves the recursive pass with an EMPTY remaining
    // URI, which matches no route at all -- so `doHandle` never runs and no realm is ever looked up.
    expect(bodyOf(slash)).toEqual(ROUTER_404);

    // Two segments below /oauth2 is the other case: the FIRST element is consumed as a sub-realm, and it is
    // the realm lookup that fails. Same status, different body, different producer.
    const twoSegment = await raw(`${path("/connect/jwk_uri")}/`);
    console.log(`[5-E5] row13 /connect/jwk_uri/ -> ${twoSegment.status} ${twoSegment.text}`);
    expect(twoSegment.status).toBe(404);
    expect(bodyOf(twoSegment)).toEqual(realm404("/connect"));

    const wellKnown = await raw(`${path("/.well-known/openid-configuration")}/`);
    console.log(`[5-E5] row13 /.well-known/openid-configuration/ -> ${wellKnown.status} ${wellKnown.text}`);
    expect(bodyOf(wellKnown)).toEqual(realm404("/.well-known"));

    // Routing is CASE-SENSITIVE -- risk #11 asks for exactly this spot-check, and CHF's EQUALS matcher is
    // case-sensitive too, so this is parity rather than a divergence.
    for (const [label, url, expected] of [
      ["/Tokeninfo", path("/Tokeninfo"), ROUTER_404],
      ["/TOKENINFO", path("/TOKENINFO"), ROUTER_404],
      ["/Connect/jwk_uri", path("/Connect/jwk_uri"), realm404("/Connect")],
      ["/connect/JWK_URI", path("/connect/JWK_URI"), realm404("/connect")],
      // An empty path segment does not collapse: `//tokeninfo` matches nothing.
      ["//tokeninfo", path("//tokeninfo"), ROUTER_404],
    ]) {
      const response = await raw(url);
      console.log(`[5-E5] row13 ${label} -> ${response.status} ${response.text}`);
      expect(response.status, label).toBe(404);
      expect(bodyOf(response), label).toEqual(expected);
    }

    // The counter-example that explains why resource_set needed three attachments: it is the ONLY endpoint
    // Restlet attaches with an explicit trailing-slash route, and it is the only one that answers here.
    const resourceSet = await raw(`${path("/resource_set")}/`);
    console.log(`[5-E5] row13 /resource_set/ -> ${resourceSet.status} ${resourceSet.text}`);
    expect(resourceSet.status).toBe(401);
    expect(bodyOf(resourceSet).error).toBe("invalid_token");
  });

  test("row 1: the ?realm= override is honoured -- and skipped entirely when no route matched", async ({ request }) => {
    for (const value of ["/", "%2F"]) {
      const response = await request.get(`${OAUTH2}/tokeninfo?realm=${value}&access_token=${ccToken}`);
      const body = await response.json();
      console.log(`[5-E5] row1 ?realm=${value} -> ${response.status()} realm=${body.realm}`);
      expect(response.status(), value).toBe(200);
      expect(body.realm, value).toBe("/");
    }

    // The override really SWITCHES realm rather than merely being tolerated: the discovery document is the
    // one endpoint whose answer names the realm it resolved to, and the sub-realm has no OIDC provider.
    const switched = await request.get(
      `${OAUTH2}/.well-known/openid-configuration?realm=${SUB_REALM}`, { maxRedirects: 0 });
    const switchedBody = await switched.json();
    console.log(`[5-E5] row1 ?realm=${SUB_REALM} -> ${switched.status()} ${JSON.stringify(switchedBody)}`);
    expect(switched.status()).toBe(404);
    expect(switchedBody).toEqual({
      error: "not_found", error_description: `No OpenID Connect provider for realm /${SUB_REALM}`,
    });
    // The leading slash is optional in the override value.
    const withSlash = await request.get(`${OAUTH2}/.well-known/openid-configuration?realm=/${SUB_REALM}`);
    expect((await withSlash.json()).error_description).toBe(`No OpenID Connect provider for realm /${SUB_REALM}`);

    // ⚠ The half no CHF row can reproduce: `RestletRealmRouter:86` guards the override on
    // `next != delegateRoute`, so on a path that matched NO endpoint the override is never applied. A BAD
    // override proves it -- if it were applied, this would be the realm 404 of row 2 instead of the router's.
    const unmatched = await raw(`${path("/nosuchendpoint")}?realm=bogus`);
    console.log(`[5-E5] row1 unmatched path + ?realm=bogus -> ${unmatched.status} ${unmatched.text}`);
    expect(unmatched.status).toBe(404);
    expect(bodyOf(unmatched)).toEqual(ROUTER_404);
    // CHF applies `?realm=` in RealmContextFilter, BEFORE the router runs, so after the flip the same request
    // is a 400 `invalid_request` about the realm. Recorded here so that difference reads as expected.
  });

  test("row 2: a bad ?realm= override is a 404 -- and CHF will answer 400", async ({ request }) => {
    // Confirms provisional divergence row 16's STATUS (404 here, 400 after the flip via
    // RealmContextFilter:255-257) and corrects its BODY: the message is the RealmLookupException's, not the
    // `Realm "bogus" not found` the plan quoted from RestletRealmRouter:103.
    const onGet = await request.get(`${OAUTH2}/tokeninfo?realm=bogus&access_token=${ccToken}`);
    const getBody = await onGet.json();
    console.log(`[5-E5] row2 GET /tokeninfo?realm=bogus -> ${onGet.status()} ${JSON.stringify(getBody)}`);
    expect(onGet.status()).toBe(404);
    expect(getBody).toEqual(realm404("bogus"));

    // The same on the busiest endpoint in the product, and by the same producer: the realm layer answers
    // before /access_token's own filter ever sees the request, so the body is CREST, not OAuth2.
    const onPost = await request.post(`${OAUTH2}/access_token?realm=bogus`, {
      form: { grant_type: "client_credentials", scope: SCOPE },
      headers: { Authorization: `Basic ${Buffer.from(`${CONFIDENTIAL_CLIENT_ID}:${CONFIDENTIAL_SECRET}`).toString("base64")}` },
    });
    const postBody = await onPost.json();
    console.log(`[5-E5] row2 POST /access_token?realm=bogus -> ${onPost.status()} ${JSON.stringify(postBody)}`);
    expect(onPost.status()).toBe(404);
    expect(postBody).toEqual(realm404("bogus"));
    // ⚠ No `Cache-Control: no-store` here: the OAuth2Filter that stamps /access_token sits INSIDE the realm
    // router, so a realm failure never reaches it. After the flip the OAuth2NoCacheFilter is inside the realm
    // filter too (D1), so this stays absent -- assert it, or a "tidy" hoist to the root would go unnoticed.
    expect(onPost.headers()["cache-control"]).toBeUndefined();
    expect(onPost.headers()["pragma"]).toBeUndefined();
  });

  test("row 3: the legacy /oauth2/<subrealm>/... style resolves to that sub-realm", async ({ request }) => {
    // The style RestletRealmRouter's `/{subrealm}` default route exists for. It is NOT dead: it resolves, and
    // it resolves to the sub-realm rather than quietly falling back to root -- which is what the discovery
    // document proves, since only the realm's own provider can answer it.
    const discovery = await request.get(`${OAUTH2}/${SUB_REALM}/.well-known/openid-configuration`);
    const body = await discovery.json();
    console.log(`[5-E5] row3 /oauth2/${SUB_REALM}/.well-known/... -> ${discovery.status()} ${JSON.stringify(body)}`);
    expect(discovery.status()).toBe(404);
    expect(body).toEqual({
      error: "not_found", error_description: `No OpenID Connect provider for realm /${SUB_REALM}`,
    });

    // An endpoint that does not need the realm's own provider answers normally under the legacy prefix.
    const tokeninfo = await request.get(`${OAUTH2}/${SUB_REALM}/tokeninfo?access_token=${ccToken}`);
    console.log(`[5-E5] row3 /oauth2/${SUB_REALM}/tokeninfo -> ${tokeninfo.status()}`);
    expect(tokeninfo.status()).toBe(200);

    // And the query override REPLACES the path realm rather than appending to it (RestletRealmRouter:86-90
    // overwrites `realm`), which is the same rule RealmContextFilter follows after the flip.
    const overridden = await request.get(`${OAUTH2}/${SUB_REALM}/.well-known/openid-configuration?realm=/`);
    console.log(`[5-E5] row3 legacy + ?realm=/ -> ${overridden.status()}`);
    expect(overridden.status()).toBe(200);
    expect((await overridden.json()).issuer).toBe(`${OPENAM_BASE}/oauth2`);
  });

  test("row 4: the modern /oauth2/realms/... style, including the FLAT non-root spelling", async ({ request }) => {
    const root = await request.get(`${OAUTH2}/realms/root/tokeninfo?access_token=${ccToken}`);
    console.log(`[5-E5] row4 /realms/root/tokeninfo -> ${root.status()}`);
    expect(root.status()).toBe(200);

    const bogus = await request.get(`${OAUTH2}/realms/bogus/tokeninfo?access_token=${ccToken}`);
    const bogusBody = await bogus.json();
    console.log(`[5-E5] row4 /realms/bogus/tokeninfo -> ${bogus.status()} ${JSON.stringify(bogusBody)}`);
    expect(bogus.status()).toBe(404);
    // ⚠ Note the LEADING SLASH: the inner router hands `Realm.of` a path, so the identifier is "/bogus" here
    // and a bare "bogus" in row 2. Same failure, two spellings.
    expect(bogusBody).toEqual(realm404("/bogus"));

    // ⚠ OVERTURNS THE PLAN. phase-5d-1 row 4 predicted Restlet would 404 a FLAT `realms/<non-root>` (the
    // inner RestletRealmRouter throws unless the element is `root` or a REALM_OBJECT is already set) and that
    // CHF serving it would be a capability GAIN to record. Restlet serves it too: the OUTER router's
    // `doHandle` runs before the `/realms/{realmId}` template is parsed, so REALM_OBJECT is always already
    // set to the host's realm by the time the inner router looks. No divergence, nothing to record -- but it
    // would have read as a regression in reverse at the byte diff.
    for (const [label, url] of [
      [`flat /realms/${SUB_REALM}`, `${OAUTH2}/realms/${SUB_REALM}/.well-known/openid-configuration`],
      [`nested /realms/root/realms/${SUB_REALM}`,
        `${OAUTH2}/realms/root/realms/${SUB_REALM}/.well-known/openid-configuration`],
    ]) {
      const response = await request.get(url);
      const body = await response.json();
      console.log(`[5-E5] row4 ${label} -> ${response.status()} ${JSON.stringify(body)}`);
      expect(response.status(), label).toBe(404);
      // The endpoint answered, in the sub-realm: routing worked and the realm resolved to /e2e5e5realm.
      expect(body, label).toEqual({
        error: "not_found", error_description: `No OpenID Connect provider for realm /${SUB_REALM}`,
      });
    }
  });

  test("row 5: HEAD is served as GET -- except on the two endpoints with a method filter", async () => {
    // D4's incumbent beyond resource_set. The 5d-1a fix maps HEAD to the @Get entry in `Endpoints.from`;
    // these are the answers it has to reproduce.
    for (const [label, url, contentType] of [
      ["/tokeninfo", `${path("/tokeninfo")}?access_token=${ccToken}`, "application/json"],
      ["/.well-known/openid-configuration", path("/.well-known/openid-configuration"), "application/json;charset=UTF-8"],
      ["/connect/jwk_uri", path("/connect/jwk_uri"), "application/json;charset=UTF-8"],
    ]) {
      const head = await raw(url, { method: "HEAD" });
      const get = await raw(url);
      console.log(`[5-E5] row5 HEAD ${label} -> ${head.status} ct=${head.headers["content-type"]}`
        + ` len=${head.headers["content-length"]} (GET ${get.status})`);
      expect(head.status, label).toBe(200);
      expect(get.status, label).toBe(200);
      expect(head.headers["content-type"], label).toBe(contentType);
      // No Content-Length on a HEAD, exactly as 5-E4 row 15 recorded for resource_set. finding 7 asks for
      // this measurement because it is the container's decision, not the application's.
      expect(head.headers["content-length"], label).toBeUndefined();
      // An HTTP client discards a HEAD entity whatever the server sent, so body emptiness is NOT asserted.
    }
    // /tokeninfo's own cache contract survives the verb change.
    const cached = await raw(`${path("/tokeninfo")}?access_token=${ccToken}`, { method: "HEAD" });
    expect(cached.headers["cache-control"]).toBe("no-cache, no-store");

    // ⚠ OVERTURNS THE PLAN, and this is the sharpest finding of the gate. phase-5d-1 finding 6 states that
    // `HEAD /oauth2/authorize` "runs the real authorization flow ... Restlet did precisely the same". It does
    // not: AuthorizeEndpointFilter.validateMethod accepts GET and POST only, and Restlet rewrites HEAD to GET
    // at ANNOTATION LOOKUP -- inside the resource, below the filter -- so the filter sees a HEAD and 405s.
    // After 5d-1a maps HEAD to @Get in `Endpoints.from`, the same request would run the flow and ISSUE A
    // CODE. That is a wire change on the authorize endpoint, and it has to be decided in D4, not discovered.
    const authorizeQuery = [
      "response_type=code", `client_id=${CLIENT_ID}`, `redirect_uri=${encodeURIComponent(REDIRECT_URI)}`,
      `scope=${SCOPE}`, "state=row5", `code_challenge=${encodeURIComponent((await pkce()).challenge)}`,
      "code_challenge_method=S256",
    ].join("&");
    const authCtx = await sessionContext(apiRequest, demoToken);
    try {
      const head = await authCtx.fetch(`${OAUTH2}/authorize?${authorizeQuery}`, { method: "HEAD", maxRedirects: 0 });
      const get = await authCtx.get(`${OAUTH2}/authorize?${authorizeQuery}`, { maxRedirects: 0 });
      console.log(`[5-E5] row5 HEAD /authorize -> ${head.status()} (the same GET -> ${get.status()}`
        + ` Location=${get.headers()["location"]})`);
      expect(head.status()).toBe(405);
      // The control that makes the 405 meaningful: the identical GET succeeds and issues a code.
      expect(get.status()).toBe(302);
      expect(new URL(get.headers()["location"]).searchParams.get("code")).toBeTruthy();
      // The 405 carries /authorize's cache headers -- so it is the OAuth2Filter-wrapped path, not a container
      // error -- and an HTML body, not the JSON a GET-shaped error would produce (see below).
      expect(head.headers()["cache-control"]).toBe("no-store");
      expect(head.headers()["pragma"]).toBe("no-cache");
    } finally {
      await authCtx.dispose();
    }

    // /access_token has the same filter and answers the same way to HEAD as to GET.
    const tokenHead = await raw(path("/access_token"), { method: "HEAD" });
    console.log(`[5-E5] row5 HEAD /access_token -> ${tokenHead.status} ct=${tokenHead.headers["content-type"]}`);
    expect(tokenHead.status).toBe(405);

    // ⚠ A HEAD that ends in an ERROR status does not send the JSON body's headers at all: the Restlet stack
    // substitutes an HTML status page, with a Content-Length. Compare the same request as a GET, which is
    // `application/json` with no length. CHF keeps the JSON content type on a HEAD (verified against
    // /openam/json), so this is a header divergence to expect at the flip, on every erroring HEAD.
    const errorHead = await raw(path("/tokeninfo"), { method: "HEAD" });
    const errorGet = await raw(path("/tokeninfo"));
    console.log(`[5-E5] row5 HEAD /tokeninfo (no token) -> ${errorHead.status} ct=${errorHead.headers["content-type"]}`
      + ` len=${errorHead.headers["content-length"]} (GET ct=${errorGet.headers["content-type"]})`);
    expect(errorHead.status).toBe(401);
    expect(errorGet.status).toBe(401);
    expect(errorHead.headers["content-type"]).toBe("text/html;charset=utf-8");
    expect(errorHead.headers["content-length"]).toBeTruthy();
    expect(errorGet.headers["content-type"]).toBe("application/json");
  });

  test("row 6: an unmapped verb is 405 -- with Allow from the resource, without from the filter", async () => {
    // The `Allow` header D4 restores in `Endpoints.from`. ⚠ Its VALUE is per endpoint and is not the
    // resource_set list: these two endpoints declare a single @Get, so Restlet advertises exactly "GET".
    for (const endpoint of ["/tokeninfo", "/connect/jwk_uri"]) {
      for (const method of ["PROPFIND", "PUT"]) {
        const response = await raw(path(endpoint), { method, headers: { "Content-Length": 0 } });
        const label = `${method} ${endpoint}`;
        console.log(`[5-E5] row6 ${label} -> ${response.status} allow=${response.headers["allow"]} ${response.text}`);
        expect(response.status, label).toBe(405);
        expect(response.headers["allow"], label).toBe("GET");
        // The CREST 405 body -- a THIRD shape alongside /access_token's `method_not_allowed` and
        // resource_set's `unsupported_method_type` (5-E4 row 11).
        expect(bodyOf(response), label).toEqual(CREST_405);
        // No cache headers on these: only /authorize and /access_token are OAuth2Filter-wrapped.
        expect(response.headers["cache-control"], label).toBeUndefined();
      }
    }

    // The other 405 producer: an endpoint whose own filter checks the verb. It sends the OAuth2 body, the
    // cache headers -- and NO Allow at all, which is the RFC 7231 §6.5.5 gap that survives the flip on this
    // path unless the CHF handler stamps it (D4 stamps it in Endpoints.from, i.e. on the framework's 405).
    for (const [endpoint, expected] of [
      ["/access_token", "Required Method: POST found: PROPFIND"],
      ["/authorize", "Required Method: GET or POST found: PROPFIND"],
    ]) {
      const response = await raw(path(endpoint), { method: "PROPFIND" });
      console.log(`[5-E5] row6 PROPFIND ${endpoint} -> ${response.status} allow=${response.headers["allow"]}`
        + ` ${response.text}`);
      expect(response.status, endpoint).toBe(405);
      expect(bodyOf(response), endpoint).toEqual({ error: "method_not_allowed", error_description: expected });
      expect(response.headers["allow"], endpoint).toBeUndefined();
      expect(response.headers["cache-control"], endpoint).toBe("no-store");
    }
  });

  test("row 7: PATCH runs the @Get method and THEN 405s -- so it is wider than resource_set", async () => {
    // ⚠ OVERTURNS THE PLAN's scoping. 5-E4 row 11 found PATCH on resource_set routed to the @Put method, and
    // D4 scoped divergence row 14 to that endpoint on the grounds that it is the only ported endpoint with a
    // @Put. What Restlet actually does with a PATCH is run the resource's @Get FIRST (to obtain the current
    // representation) and only then look for a handler -- so on a @Get-only endpoint the GET's side effects
    // and the GET's ERRORS are on the wire, and only afterwards does the 405 appear.
    //
    // Proof, three requests: with a valid token the 405 carries /tokeninfo's OWN cache directives, which only
    // `ValidationServerResource.validate()` sets; without a token the request never reaches the 405 at all
    // and answers the GET's 401; and a PUT -- which does not run the @Get -- carries neither.
    const patched = await raw(`${path("/tokeninfo")}?access_token=${ccToken}`,
      { method: "PATCH", headers: { "Content-Length": 0 } });
    console.log(`[5-E5] row7 PATCH /tokeninfo (valid token) -> ${patched.status}`
      + ` cache=${patched.headers["cache-control"]} allow=${patched.headers["allow"]}`);
    expect(patched.status).toBe(405);
    expect(bodyOf(patched)).toEqual(CREST_405);
    expect(patched.headers["allow"]).toBe("GET");
    expect(patched.headers["cache-control"]).toBe("no-cache, no-store");

    const unauthenticated = await raw(path("/tokeninfo"), { method: "PATCH", headers: { "Content-Length": 0 } });
    console.log(`[5-E5] row7 PATCH /tokeninfo (no token) -> ${unauthenticated.status} ${unauthenticated.text}`);
    expect(unauthenticated.status).toBe(401);
    expect(bodyOf(unauthenticated).error).toBe("invalid_token");

    const put = await raw(`${path("/tokeninfo")}?access_token=${ccToken}`,
      { method: "PUT", headers: { "Content-Length": 0 } });
    console.log(`[5-E5] row7 PUT /tokeninfo (valid token) -> ${put.status} cache=${put.headers["cache-control"]}`);
    expect(put.status).toBe(405);
    expect(put.headers["cache-control"]).toBeUndefined();

    // On the two method-filtered endpoints the filter refuses PATCH before any of that.
    const onToken = await raw(path("/access_token"), { method: "PATCH", headers: { "Content-Length": 0 } });
    console.log(`[5-E5] row7 PATCH /access_token -> ${onToken.status} ${onToken.text}`);
    expect(onToken.status).toBe(405);
    expect(bodyOf(onToken)).toEqual({
      error: "method_not_allowed", error_description: "Required Method: POST found: PATCH",
    });
  });

  test("row 8: ?_api and ?_crestapi are ignored", async ({ request }) => {
    // The baseline for phase-5d-1 finding 10: after the flip the global CHF chain's ApiDescriptorFilter and
    // OpenApiRequestFilter see these parameters on /oauth2 for the first time. Today they are simply query
    // parameters nobody reads, and the endpoint answers exactly as it would without them.
    const plain = await request.get(`${OAUTH2}/connect/jwk_uri`);
    const plainBody = await plain.text();
    for (const parameter of ["_api", "_crestapi"]) {
      const response = await request.get(`${OAUTH2}/connect/jwk_uri?${parameter}`);
      console.log(`[5-E5] row8 /connect/jwk_uri?${parameter} -> ${response.status()}`
        + ` ct=${response.headers()["content-type"]}`);
      expect(response.status(), parameter).toBe(200);
      expect(response.headers()["content-type"], parameter).toBe("application/json;charset=UTF-8");
      expect(await response.text(), parameter).toBe(plainBody);
    }
    const withToken = await request.get(`${OAUTH2}/tokeninfo?_api&access_token=${ccToken}`);
    console.log(`[5-E5] row8 /tokeninfo?_api -> ${withToken.status()}`);
    expect(withToken.status()).toBe(200);
  });

  test("row 9: OPTIONS is a 405, and no CORS headers are produced at all", async ({ request }) => {
    // The CORSFilter is mapped to /oauth2/* in web.xml (`:224-227`) and survives the flip untouched, being
    // url-pattern based. On this deployment it is unconfigured, so it adds nothing -- recorded so that a
    // post-flip run showing Access-Control-* headers would be a change in the FILTER's configuration and not
    // something the migration did.
    for (const origin of [undefined, "http://app.invalid"]) {
      const response = await request.fetch(`${OAUTH2}/authorize`, {
        method: "OPTIONS", maxRedirects: 0,
        headers: origin ? { Origin: origin, "Access-Control-Request-Method": "GET" } : {},
      });
      const body = await response.json();
      const label = origin ? "with Origin" : "no Origin";
      console.log(`[5-E5] row9 OPTIONS /authorize ${label} -> ${response.status()} ${JSON.stringify(body)}`);
      expect(response.status(), label).toBe(405);
      expect(body, label).toEqual({
        error: "method_not_allowed", error_description: "Required Method: GET or POST found: OPTIONS",
      });
      for (const header of Object.keys(response.headers())) {
        expect(header.startsWith("access-control-"), `${label}: ${header}`).toBe(false);
      }
    }

    // On an endpoint with no method filter, OPTIONS lands on the same CREST 405 as any other unmapped verb --
    // Restlet does NOT implement the automatic OPTIONS response its ServerResource could.
    const onGetOnly = await raw(path("/tokeninfo"), { method: "OPTIONS" });
    console.log(`[5-E5] row9 OPTIONS /tokeninfo -> ${onGetOnly.status} allow=${onGetOnly.headers["allow"]}`);
    expect(onGetOnly.status).toBe(405);
    expect(onGetOnly.headers["allow"]).toBe("GET");
    expect(bodyOf(onGetOnly)).toEqual(CREST_405);
  });

  test("row 10: the method tunnel -- the header is honoured on ANY verb, the query only on POST", async ({ request }) => {
    // ⚠ THIS ROW SETTLES D11, and it settles it in three parts rather than the two the decision anticipated.
    //
    // (a) `X-HTTP-Method-Override` on a POST: HONOURED, exactly as `Endpoints.getMethod:119-126` will do
    //     after the flip. No divergence -- D11's first branch.
    const overridden = await request.post(`${OAUTH2}/access_token`, {
      form: { grant_type: "client_credentials", scope: SCOPE },
      headers: {
        Authorization: `Basic ${Buffer.from(`${CONFIDENTIAL_CLIENT_ID}:${CONFIDENTIAL_SECRET}`).toString("base64")}`,
        "X-HTTP-Method-Override": "GET",
      },
    });
    const overriddenBody = await overridden.json();
    console.log(`[5-E5] row10 POST /access_token + override GET -> ${overridden.status()}`
      + ` ${JSON.stringify(overriddenBody)}`);
    expect(overridden.status()).toBe(405);
    // The verb was rewritten BEFORE TokenEndpointFilter.validateMethod ran -- the message says so.
    expect(overriddenBody).toEqual({
      error: "method_not_allowed", error_description: "Required Method: POST found: GET",
    });
    // The control: the identical request without the header issues a token.
    const control = await request.post(`${OAUTH2}/access_token`, {
      form: { grant_type: "client_credentials", scope: SCOPE },
      headers: {
        Authorization: `Basic ${Buffer.from(`${CONFIDENTIAL_CLIENT_ID}:${CONFIDENTIAL_SECRET}`).toString("base64")}`,
      },
    });
    console.log(`[5-E5] row10 the same POST without the header -> ${control.status()}`);
    expect(control.status()).toBe(200);
    // And the rewrite is real in the other direction too: a POST becomes a working GET on a @Get endpoint.
    const posted = await raw(`${path("/tokeninfo")}?access_token=${ccToken}`, {
      method: "POST", headers: { "X-HTTP-Method-Override": "GET", "Content-Length": 0 },
    });
    console.log(`[5-E5] row10 POST /tokeninfo + override GET -> ${posted.status}`);
    expect(posted.status).toBe(200);

    // (b) the same header on a NON-POST: Restlet honours it, CHF will not (`Endpoints.getMethod` gates on
    //     POST). So this GET, a 405 today, becomes a 200 after the flip -- a divergence in the safe
    //     direction, but a divergence.
    const onGet = await raw(`${path("/tokeninfo")}?access_token=${ccToken}`,
      { headers: { "X-HTTP-Method-Override": "PUT" } });
    console.log(`[5-E5] row10 GET /tokeninfo + override PUT -> ${onGet.status} allow=${onGet.headers["allow"]}`);
    expect(onGet.status).toBe(405);
    expect(bodyOf(onGet)).toEqual(CREST_405);

    // (c) Restlet's OWN tunnel, the `method` QUERY parameter (TunnelService, POST-only), which CHF has no
    //     equivalent for at all. `POST /access_token?method=GET` is a 405 today and will ISSUE A TOKEN after
    //     the flip. Nobody had measured this; it is a divergence row of its own.
    const queryTunnel = await request.post(`${OAUTH2}/access_token?method=GET`, {
      form: { grant_type: "client_credentials", scope: SCOPE },
      headers: {
        Authorization: `Basic ${Buffer.from(`${CONFIDENTIAL_CLIENT_ID}:${CONFIDENTIAL_SECRET}`).toString("base64")}`,
      },
    });
    const queryBody = await queryTunnel.json();
    console.log(`[5-E5] row10 POST /access_token?method=GET -> ${queryTunnel.status()} ${JSON.stringify(queryBody)}`);
    expect(queryTunnel.status()).toBe(405);
    expect(queryBody.error_description).toBe("Required Method: POST found: GET");
    // ...and it really is POST-only: the same parameter on a GET changes nothing.
    const queryOnGet = await request.get(`${OAUTH2}/tokeninfo?method=PUT&access_token=${ccToken}`);
    console.log(`[5-E5] row10 GET /tokeninfo?method=PUT -> ${queryOnGet.status()}`);
    expect(queryOnGet.status()).toBe(200);
  });

  test("row 11: an unrouted path is a 404 -- from one of two different producers", async () => {
    // What D5's OAuth2NotFoundHandler is measured against. The producer depends on the SEGMENT COUNT, which
    // is the finding phase-5d-1's finding 8 half-predicted: it expected every unmatched path to be a realm
    // 404, and one-segment paths are not.
    for (const [label, url, expected] of [
      ["/nosuchendpoint (one segment -> router)", path("/nosuchendpoint"), ROUTER_404],
      ["/authorize/extra (two -> realm)", path("/authorize/extra"), realm404("/authorize")],
      ["/connect/nosuch (two -> realm)", path("/connect/nosuch"), realm404("/connect")],
      ["/realms/root/nosuch (consumed by the realm route -> router)", path("/realms/root/nosuch"), ROUTER_404],
    ]) {
      const response = await raw(url);
      console.log(`[5-E5] row11 ${label} -> ${response.status} ${response.text}`);
      expect(response.status, label).toBe(404);
      expect(bodyOf(response), label).toEqual(expected);
      // No OAuth2-shaped body anywhere here: /oauth2's routing failures speak CREST today. After the flip
      // they all become {"error":"not_found",...} (D5) -- a shape change on every one of these URLs.
      expect(response.headers["content-type"], label).toBe("application/json");
    }
  });

  test("row 12: the bare prefix, and the realm prefix with no endpoint, are router 404s", async () => {
    // Never recorded by any row before this one. The bare prefix is the one place `/{subrealm}` has nothing
    // to bind, so Restlet's own router 404 surfaces -- and `/realms` and `/realms/root` behave the same way.
    for (const [label, url] of [
      ["/oauth2/", `${path("")}/`],
      ["/oauth2", path("")],
      ["/oauth2/realms", path("/realms")],
      ["/oauth2/realms/root", path("/realms/root")],
    ]) {
      const response = await raw(url);
      console.log(`[5-E5] row12 ${label} -> ${response.status} ${response.text}`);
      expect(response.status, label).toBe(404);
      expect(bodyOf(response), label).toEqual(ROUTER_404);
    }
  });

  test("row 14: an unknown Host is a 500 today -- on BOTH URL styles", async () => {
    // ⚠ OVERTURNS THE PLAN, and it is the row that matters most to a live deployment. phase-5d-1 finding 16
    // predicted that `/oauth2/realms/root/...` WORKS today under an unrecognised Host (the outer router
    // short-circuits when `realmId` is set) and would 400 after the flip -- "the only row here that can break
    // a deployment that works today". It does not work today: `realmId` is set by the route TEMPLATE, which
    // is parsed after `doHandle` has already called `getRealmFromServerName`, so the host is resolved on
    // every request and both styles answer 500.
    //
    // ⇒ provisional divergence row 17 becomes "500 -> 400 on both styles", i.e. a better answer to a request
    //   that is already failing, not a working integration breaking. R-5d1.9's severity drops accordingly.
    for (const [label, url] of [
      ["/oauth2/tokeninfo", `${path("/tokeninfo")}?access_token=${ccToken}`],
      ["/oauth2/realms/root/tokeninfo", `${path("/realms/root/tokeninfo")}?access_token=${ccToken}`],
      ["/oauth2/.well-known/openid-configuration", path("/.well-known/openid-configuration")],
    ]) {
      const response = await raw(url, { hostHeader: "not-a-real-host.invalid" });
      console.log(`[5-E5] row14 ${label} under an unknown Host -> ${response.status} ${response.text}`);
      expect(response.status, label).toBe(500);
      expect(bodyOf(response), label).toEqual({
        code: 500, reason: "Internal Server Error",
        message: "No mapping organization found for organization identifier: not-a-real-host.invalid",
      });
    }

    // ⚠ The positive control that makes the three rows above mean anything: the SAME raw client, the same
    // URL, with the deployment's own hostname, answers 200. Without it a client that silently dropped the
    // Host header would leave every assertion above passing for the wrong reason.
    const known = await raw(path("/connect/jwk_uri"), { hostHeader: BASE.hostname });
    console.log(`[5-E5] row14 the same request with Host: ${BASE.hostname} -> ${known.status}`);
    expect(known.status).toBe(200);
  });

});
