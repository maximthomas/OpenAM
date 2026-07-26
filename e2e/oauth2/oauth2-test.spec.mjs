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
