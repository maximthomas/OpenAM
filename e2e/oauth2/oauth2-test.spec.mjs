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
// A client that does not imply consent, so the resource owner's decision must be posted explicitly. This is
// the situation issue #1080 reports: a non-browser client cannot obtain a token to post with the decision.
const CONSENT_CLIENT_ID = "test_consent_app";
const CONSENT_STATE = "consent-state";
const SCOPE="profile"
const REDIRECT_URI="http://app.invalid/cb"
/**
 * Ensures the OAuth2 service exists in the OpenAM instance.
 * Creates it with default configuration if it doesn't exist.
 */
async function ensureOAuth2ServiceExists(adminToken, request) {
  const response = await request.get(`${OPENAM_BASE}/json/realms/${REALM}/realm-config/services/oauth-oidc`,
    {
      headers: {
        "iPlanetDirectoryPro": adminToken,
        "Accept-API-Version": "protocol=1.0,resource=1.0",
      },
    }
  );

  if (response.status() === 404) {
    // OAuth2 service doesn't exist, create it
    const createResponse = await request.post(`${OPENAM_BASE}/json/realms/${REALM}/realm-config/services/oauth-oidc?_action=create`,
      {
        headers: {
          "iPlanetDirectoryPro": adminToken,
          "Content-Type": "application/json",
          "Accept-API-Version": "protocol=1.0,resource=1.0",
        },
        data: {
          advancedOAuth2Config: {
            clientsCanSkipConsent: true,
            supportedScopes: [SCOPE],
            defaultScopes: [SCOPE],
          },
        },
      }
    );

    if (!createResponse.ok()) {
      throw new Error(
        `Failed to create OAuth2 service: ${createResponse.statusText()}`
      );
    }
    console.log("OAuth2 service created successfully");
  } else if (!response.ok()) {
    throw new Error(
      `Failed to check OAuth2 service: ${createResponse.statusText()}`
    );
  } else {
    console.log("OAuth2 service already exists");
  }
}

/**
 * Ensures an OAuth2 client application exists in the OpenAM instance.
 * Creates it with default configuration if it doesn't exist.
 */

async function ensureOAuth2ClientExists(adminToken, request, clientId = CLIENT_ID, isConsentImplied = true) {
  const response = await request.get(
    `${OPENAM_BASE}/json/realms/${REALM}/realm-config/agents/OAuth2Client/${clientId}`,
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
      `${OPENAM_BASE}/json/realms/${REALM}/realm-config/agents/OAuth2Client/${clientId}`,
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
          "isConsentImplied": isConsentImplied,
          "sunIdentityServerDeviceStatus": "Active"
        },
      }
    );

    if (!createResponse.ok()) {
      throw new Error(
        `Failed to create OAuth2 client: ${createResponse.statusText()}`
      );
    }
    console.log(`OAuth2 client "${clientId}" created successfully`);
  } else if (!response.ok()) {
    throw new Error(
      `Failed to check OAuth2 client: ${response.statusText()}`
    );
  } else {
    console.log(`OAuth2 client "${clientId}" already exists`);
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
  await ensureOAuth2ClientExists(adminToken, request, CONSENT_CLIENT_ID, false);
});

let accessToken;

// PKCE is mandatory for these clients: they are public and authenticate with "none", so OpenAM rejects an
// authorization request without code_challenge before it reaches consent handling.
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

test.describe("OAuth Service test", () => {
  test("Should receive an auth code and exchange it to access token", async ({ request }) => {

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
    // 400-invalid_request prediction was wrong. CONFIRMED at the 5d-1c flip: the @Post-only CHF handler yields
    // the same 405, so the status is unchanged. The prediction that its `error` would turn framework-derived
    // (invalid_request) was ALSO wrong -- OAuth2ErrorFilter.errorFor maps a 405 to `method_not_allowed` (D10),
    // deliberately keeping the incumbent word. Only the DESCRIPTION moved, and it is the one thing to flag.
    expect(response.status()).toBe(405);
    expect(body.error).toBe("method_not_allowed");
    // ⚠ 5d-1c divergence: the 405 description is now the framework's generic reason phrase, because the check
    // is no longer a verb-aware filter but `Endpoints.from`'s unmapped-verb fallback, which cannot name the
    // verbs it wanted. Restlet: "Required Method: POST found: GET".
    expect(body.error_description).toBe("Method Not Allowed");
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
    // Restlet rendered JSON as "application/json" with NO charset; the CHF setEntity(Map) appends one. The
    // divergence was predicted and is now CONFIRMED on the wire -- with one correction: CHF writes NO SPACE
    // after the semicolon, so the bytes are "application/json;charset=UTF-8", not the "; charset=UTF-8" the
    // prediction spelled. Recorded exactly as measured, because the exact bytes ARE the oracle.
    // ⚠ 5d-1c divergence: JSON responses gained a charset parameter. Restlet: "application/json".
    expect(ct).toBe("application/json;charset=UTF-8");
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
   * ⚠ 5d-1c divergence, shared by rows 1, 2 and 9: the query as CHF ECHOES it back, which is not the query
   * that was sent. Restlet handed back the raw query string it received, so an already-percent-encoded
   * parameter value survived byte-for-byte. CHF rebuilds the request URI from the DECODED form, so every
   * value is re-encoded exactly once and a value that arrived encoded comes back in its plain spelling.
   * `redirect_uri` is the only parameter here whose value contains anything to encode, so it is the only one
   * that moves -- and it moves the same way wherever the request URI is re-rendered: inside `goto` (row 1)
   * and inside the consent page's `formTarget` (rows 2 and 9). Restlet: the query verbatim as sent.
   */
  const chfEchoedQuery = (query) => query.replace(encodeURIComponent(REDIRECT_URI), REDIRECT_URI);

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
    // goto is the WHOLE original request URL, absolute, with its query intact and singly percent-encoded for
    // its trip inside the goto parameter.
    // ⚠ 5d-1c divergence: the redirect_uri NESTED in goto is now singly encoded, because CHF rebuilds the
    // request URI from the decoded query (see chfEchoedQuery). Restlet: the sent query verbatim, i.e.
    // `redirect_uri=http%3A%2F%2Fapp.invalid%2Fcb` inside goto, hence double-encoded on the wire.
    expect(loginUrl.searchParams.get("goto")).toBe(`${OPENAM_BASE}/oauth2/authorize?${chfEchoedQuery(query)}`);
    // The same fact one encoding layer out: goto is percent-encoded once for the Location header, so the
    // singly-encoded nested value shows as `%3D` + `http%3A%2F%2F...` where Restlet showed `%253A%252F%252F`.
    // ⚠ 5d-1c divergence: one fewer encoding layer on the nested redirect_uri. Restlet:
    // "redirect_uri%3Dhttp%253A%252F%252Fapp.invalid%252Fcb".
    expect(location).toContain("redirect_uri%3Dhttp%3A%2F%2Fapp.invalid%2Fcb");
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
    // ⚠ 5d-1c divergence: the nested redirect_uri in formTarget is now singly encoded, since that "built from
    // the CHF Request URI" is built from the DECODED query (see chfEchoedQuery). Restlet:
    // `redirect_uri=http%3A%2F%2Fapp.invalid%2Fcb`.
    expect(consentPageValue(html, "formTarget")).toBe(`\\${CONTEXT_PATH}/oauth2/authorize?${chfEchoedQuery(query)}`);
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
    // CONFIRMED at the 5d-1c flip: the @Get/@Post-only CHF handler yields the same 405 with no verb check of
    // its own (D8 stands), and the body gained the charset as predicted. The other half of the prediction was
    // wrong: the body code did NOT turn framework-derived -- OAuth2ErrorFilter.errorFor maps 405 to
    // `method_not_allowed` on purpose (D10). What moved is the DESCRIPTION, which is now generic.
    expect(response.status()).toBe(405);
    // ⚠ 5d-1c divergence: JSON responses gained a charset parameter. Restlet: "application/json".
    expect(response.headers()["content-type"]).toBe("application/json;charset=UTF-8");
    expect(body.error).toBe("method_not_allowed");
    // ⚠ 5d-1c divergence: `Endpoints.from`'s unmapped-verb fallback cannot name the verbs it wanted, so every
    // 405 on the surface now carries the reason phrase. Restlet: "Required Method: GET or POST found: PUT".
    expect(body.error_description).toBe("Method Not Allowed");
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
    // CONFIRMED at the 5d-1c flip: AuthorizeHandler.authorize does reproduce it, and the BODY is byte-identical
    // -- this row's only movement is the Content-Type charset every JSON response on the surface gained.
    expect(response.status()).toBe(400);
    // ⚠ 5d-1c divergence: JSON responses gained a charset parameter. Restlet: "application/json".
    expect(response.headers()["content-type"]).toBe("application/json;charset=UTF-8");
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
      // ⚠ 5d-1c divergence: the nested redirect_uri is singly encoded in formTarget (see chfEchoedQuery), so
      // the POST below goes to the URL the PAGE names, which is no longer the URL the GET was made with.
      // Restlet: `redirect_uri=http%3A%2F%2Fapp.invalid%2Fcb`.
      expect(target).toBe(`${CONTEXT_PATH}/oauth2/authorize?${chfEchoedQuery(query)}`);

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
   * cookie emitted NOTHING. The CHF port cannot retract a servlet cookie, so its afterAuthorizeSuccess must emit
   * the max-age-0 delete UNCONDITIONALLY when its before-hook set one -- otherwise the first authorize would
   * leave oidcLoginHint set in the browser, which is an END-STATE divergence, not just an extra header.
   *
   * ⚠ 5d-1c: that is exactly what landed, and part (b) below measures it. Every authorize SUCCESS carrying a
   * login_hint now emits TWO headers, the set and the delete, whatever the request's own cookie jar held --
   * plan.md divergence row 2's two-header pattern. The END STATE is the same as Restlet's (no cookie left in
   * the browser); it is the header count on the wire that moved, and it moved on both (b) and (c).
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

    // (b) success, NO prior cookie: the set AND the delete, in that order. The CHF hook cannot retract the
    // header its before-hook already wrote, so it deletes unconditionally -- two headers where Restlet sent
    // none. The Expires value is a FIXED epoch string, not a per-run timestamp, so it pins exactly.
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
    // ⚠ 5d-1c divergence: an authorize success with a login_hint and NO prior cookie now emits both the set and
    // the max-age-0 delete (plan.md divergence row 2). Restlet: [] -- neither header.
    expect(freshSetCookies.filter((c) => c.includes("oidcLoginHint"))).toEqual([
      "oidcLoginHint=demo; Path=/; HttpOnly",
      "oidcLoginHint=; Expires=Thu, 01 Jan 1970 00:00:10 GMT; Path=/; HttpOnly",
    ]);

    // (c) success WITH a prior cookie. Restlet emitted exactly one header here, the delete, carrying neither
    // Path nor HttpOnly -- so it could not actually clear the Path=/ cookie its own before-hook had set.
    // ⚠ 5d-1c: the request's cookie jar no longer changes the answer at all. The CHF hook pair emits the same
    // two headers as (b), and the delete now carries Path=/ and HttpOnly, so it does clear what (a) set.
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
    // ⚠ 5d-1c divergence: two headers, the set then the delete, exactly as in (b). Restlet: one header.
    expect(hintCookies).toHaveLength(2);
    expect(hintCookies[0]).toBe("oidcLoginHint=demo; Path=/; HttpOnly");
    expect(hintCookies[1].startsWith("oidcLoginHint=; Expires=")).toBe(true);
    // ⚠ 5d-1c divergence: the delete is scoped, so it clears the cookie the set created. Restlet's delete
    // carried neither attribute and therefore could not clear a Path=/ cookie at all.
    expect(hintCookies[1]).toContain("Path=/");
    expect(hintCookies[1]).toContain("HttpOnly");
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
 * ⚠ Two different 404 bodies USED to recur below, and telling them apart WAS the measurement:
 *   - the ROUTER 404 -- "The server has not found anything matching the request URI" -- Restlet's own, when
 *     no route matched and the realm layer never ran;
 *   - the REALM 404 -- "No mapping organization found for organization identifier: X" -- when the unmatched
 *     element was consumed as a sub-realm by `RestletRealmRouter`'s `/{subrealm}` default route and the realm
 *     lookup then failed.
 * Which one a URL got depended on how many path elements sat below `/oauth2` (rows 11-13), because the
 * router's attributes are populated by the route TEMPLATE, i.e. only after `doHandle` has already run: the
 * first pass always resolved the realm from the host, and only the recursive second pass saw a `subrealm`.
 *
 * ⚠ 5d-1c COLLAPSED that distinction, and it is the largest single change in this describe. CHF's
 * `RealmContextFilter` consumes a leading element only if it RESOLVES as a realm and simply stops at the first
 * that does not (`RealmContextFilter:236-248`), so an unmatched path element is never mistaken for a failed
 * sub-realm: every unrouted `/oauth2` path now reaches `OAuth2NotFoundHandler` and answers ONE body,
 * {"error":"not_found","error_description":"Not Found"} (D5). A realm lookup can still fail -- but only where
 * a realm was actually named, i.e. `?realm=` (row 2, a 400) and `/realms/{id}` (row 4, a 404 whose message is
 * the CHF realm router's own). Rows 11-13 no longer measure "which producer"; they measure that there is one.
 *
 * ⚠ The Restlet realm message was the CAUSE's, not the router's. `RestletRealmRouter:102-104` threw
 * `ResourceException(CLIENT_ERROR_NOT_FOUND, "Realm \"" + x + "\" not found", e)`, but
 * `RestStatusService.toRepresentation:42-52` rendered `status.getThrowable().getMessage()` whenever there was a
 * throwable -- so the RealmLookupException's own wording won and the router's description never reached the
 * wire. phase-5d-1 finding 15 predicted `Realm "bogus" not found` for these rows, and D5 built a
 * near-byte-parity argument for divergence row 15 on that prediction; both were corrected by rows 2 and 4
 * against Restlet. ⚠ 5d-1c: CHF's `/realms/{id}` failure DOES say `Realm "bogus" not found` (row 4), so
 * finding 15's wording turns out to describe the successor rather than the incumbent.
 */
test.describe("/oauth2 routing contract lock (5-E5, live Restlet)", () => {

  const BASE = new URL(OPENAM_BASE);
  const OAUTH2 = `${OPENAM_BASE}/oauth2`;
  /** Realms are created through global-config (the deprecated RealmResource rejects this body). */
  const SUB_REALM = "e2e5e5realm";
  /** SmsRealmProvider's resource id is base64url of the realm PATH -- "/e2e5e5realm", not the name. */
  const SUB_REALM_ID = Buffer.from(`/${SUB_REALM}`).toString("base64url");
  const REALMS_URL = `${OPENAM_BASE}/json/global-config/realms`;

  /**
   * ⚠ 5d-1c divergence: the one body every unrouted `/oauth2` path now answers, from
   * `OAuth2NotFoundHandler` (D5). It replaces BOTH of Restlet's routing 404s at once --
   * ROUTER_404 = {code:404, reason:"Not Found", message:"The server has not found anything matching the
   * request URI"} and realm404(x) = {code:404, reason:"Not Found", message:"No mapping organization found for
   * organization identifier: x"} -- so the rows below that used to distinguish them no longer can.
   */
  const OAUTH2_404 = { error: "not_found", error_description: "Not Found" };
  /**
   * ⚠ 5d-1c divergence: the CHF realm router's own 404, for the ONLY path form that still names a realm and
   * fails to find it -- `/oauth2/realms/{id}` (row 4). Restlet: realm404("/" + id), i.e. the CREST shape with
   * "No mapping organization found for organization identifier: /bogus".
   * ⚠ The `&quot;` is MEASURED, not a typo: `ResourceException.toJsonValue` HTML-escapes the message and
   * `/json` has emitted the identical bytes for this failure since 14.0. Pre-existing, product-wide, and
   * deliberately not unescaped by `OAuth2ErrorFilter` (see its rewriteIfCrestError comment).
   */
  const oauth2Realm404 = (identifier) => ({
    error: "not_found", error_description: `Realm &quot;${identifier}&quot; not found`,
  });
  /**
   * ⚠ 5d-1c divergence: a bad `?realm=` is a 400 from `RealmContextFilter:253-256`, which runs BEFORE the
   * router. Restlet answered realm404("bogus") -- a 404 raised inside the router, and only on a path that had
   * matched a route.
   */
  const invalidRealm400 = (value) => ({ error: "invalid_request", error_description: `Invalid realm, ${value}` });
  /**
   * ⚠ 5d-1c divergence: the 405 body of every `/oauth2` route except `resource_set`. `Endpoints.from`'s unmapped-verb fallback
   * produces a CREST 405 whose message is the reason phrase, and `OAuth2ErrorFilter.errorFor` maps the status
   * to `method_not_allowed` (D10) -- so the endpoints with a verb-checking filter and the endpoints without
   * one now answer identically. Restlet had THREE shapes here: CREST_405 = {code:405, reason:"Method Not
   * Allowed", message:"The method specified in the request is not allowed for the resource identified by the
   * request URI"} from a plain resource, {error:"method_not_allowed", error_description:"Required Method: X
   * found: Y"} from the two OAuth2Filter endpoints, and resource_set's {error:"unsupported_method_type"}
   * (5-E4 row 11) -- and only the last of the three survives the flip.
   */
  const OAUTH2_405 = { error: "method_not_allowed", error_description: "Method Not Allowed" };

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
    // ⚠ Under Restlet it was the ROUTER 404, not the realm 404 finding 8 predicted ("falls to /{subrealm} and
    // 404s on Realm.of(root,'tokeninfo')"). One unmatched element left the recursive pass with an EMPTY
    // remaining URI, which matched no route at all -- so `doHandle` never ran and no realm was looked up.
    // ⚠ 5d-1c divergence: the OAuth2-shaped routing 404 (D5). CHF reaches the same conclusion by a shorter
    // route -- `tokeninfo` does not resolve as a realm, so RealmContextFilter consumes nothing and the
    // endpoint router sees ["tokeninfo",""], which its EQUALS matcher rejects. Restlet: ROUTER_404.
    expect(bodyOf(slash)).toEqual(OAUTH2_404);

    // Two segments below /oauth2 WAS the other case: Restlet consumed the FIRST element as a sub-realm and the
    // realm lookup failed -- same status, different body, different producer.
    const twoSegment = await raw(`${path("/connect/jwk_uri")}/`);
    console.log(`[5-E5] row13 /connect/jwk_uri/ -> ${twoSegment.status} ${twoSegment.text}`);
    expect(twoSegment.status).toBe(404);
    // ⚠ 5d-1c divergence: no second producer left. `connect` does not resolve as a realm, so nothing consumes
    // it and the router 404s on the whole two-element path. Restlet: realm404("/connect").
    expect(bodyOf(twoSegment)).toEqual(OAUTH2_404);

    const wellKnown = await raw(`${path("/.well-known/openid-configuration")}/`);
    console.log(`[5-E5] row13 /.well-known/openid-configuration/ -> ${wellKnown.status} ${wellKnown.text}`);
    // ⚠ 5d-1c divergence: same collapse. Restlet: realm404("/.well-known").
    expect(bodyOf(wellKnown)).toEqual(OAUTH2_404);

    // Routing is CASE-SENSITIVE -- risk #11 asks for exactly this spot-check, and CHF's EQUALS matcher is
    // case-sensitive too, so the STATUS here is parity. Only the body moved.
    // ⚠ 5d-1c divergence: one body for all five forms, where Restlet answered ROUTER_404 for the one-element
    // spellings and realm404("/Connect") / realm404("/connect") for the two-element ones.
    for (const [label, url, expected] of [
      ["/Tokeninfo", path("/Tokeninfo"), OAUTH2_404],
      ["/TOKENINFO", path("/TOKENINFO"), OAUTH2_404],
      ["/Connect/jwk_uri", path("/Connect/jwk_uri"), OAUTH2_404],
      ["/connect/JWK_URI", path("/connect/JWK_URI"), OAUTH2_404],
      // An empty path segment did not collapse under Restlet: `//tokeninfo` matched nothing. It was the one
      // form here whose post-flip STATUS was in doubt -- `RealmContextFilter` cleans "" to "/", which resolves
      // as the root realm, so the empty element could have been CONSUMED and `tokeninfo` reached (a 401
      // invalid_token, no token being supplied). ⚠ MEASURED 2026-08-05: it stays a 404. The filter's cleanup
      // does not make the empty element routable, so this form collapses with the other four.
      ["//tokeninfo", path("//tokeninfo"), OAUTH2_404],
    ]) {
      const response = await raw(url);
      console.log(`[5-E5] row13 ${label} -> ${response.status} ${response.text}`);
      expect(response.status, label).toBe(404);
      expect(bodyOf(response), label).toEqual(expected);
    }

    // The counter-example that explains why resource_set needed three attachments: it was the ONLY endpoint
    // Restlet attached with an explicit trailing-slash route, and it is still the only one that answers here --
    // now because D2 gives it a STARTS_WITH parent whose child sees an empty remaining URI for both collection
    // spellings (OAuth2HttpRouteProvider.resourceSetRouter). Same answer, different mechanism.
    const resourceSet = await raw(`${path("/resource_set")}/`);
    console.log(`[5-E5] row13 /resource_set/ -> ${resourceSet.status} ${resourceSet.text}`);
    expect(resourceSet.status).toBe(401);
    expect(bodyOf(resourceSet).error).toBe("invalid_token");
  });

  test("row 1: the ?realm= override is honoured -- and after the flip it applies even with no route matched", async ({ request }) => {
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

    // ⚠ The half no CHF row can reproduce: `RestletRealmRouter:86` guarded the override on
    // `next != delegateRoute`, so on a path that matched NO endpoint the override was never applied. A BAD
    // override proved it -- had it been applied, this would have been the realm 404 of row 2 rather than the
    // router's. CONFIRMED CORRECT AND NOW GONE: the prediction recorded below measured out exactly.
    const unmatched = await raw(`${path("/nosuchendpoint")}?realm=bogus`);
    console.log(`[5-E5] row1 unmatched path + ?realm=bogus -> ${unmatched.status} ${unmatched.text}`);
    // ⚠ 5d-1c divergence: CHF applies `?realm=` in RealmContextFilter, BEFORE the router runs, so the override
    // is validated whether or not anything would have matched -- and a bad one loses the race with the routing
    // 404. Restlet: 404 with ROUTER_404, the override skipped entirely.
    expect(unmatched.status).toBe(400);
    expect(bodyOf(unmatched)).toEqual(invalidRealm400("bogus"));
  });

  test("row 2: a bad ?realm= override is a 400 -- CHF answers before the endpoint is reached", async ({ request }) => {
    // Provisional divergence row 16 predicted the STATUS change (404 under Restlet, 400 after the flip via
    // RealmContextFilter:253-256) and it is now CONFIRMED on the wire. Its BODY was corrected twice: against
    // Restlet the message was the RealmLookupException's own, not the `Realm "bogus" not found` the plan quoted
    // from RestletRealmRouter:103; and CHF says neither, it says what the filter's BadRequestException says.
    const onGet = await request.get(`${OAUTH2}/tokeninfo?realm=bogus&access_token=${ccToken}`);
    const getBody = await onGet.json();
    console.log(`[5-E5] row2 GET /tokeninfo?realm=bogus -> ${onGet.status()} ${JSON.stringify(getBody)}`);
    // ⚠ 5d-1c divergence: the realm override is resolved in a filter that answers 400 on failure, not in the
    // router. Restlet: 404 with realm404("bogus").
    expect(onGet.status()).toBe(400);
    expect(getBody).toEqual(invalidRealm400("bogus"));

    // The same on the busiest endpoint in the product, and by the same producer: the realm layer answers
    // before /access_token's own handler ever sees the request. Under Restlet that made the body CREST rather
    // than OAuth2; after the flip OAuth2ErrorFilter wraps the realm layer too, so it is OAuth2-shaped -- but
    // still the realm layer's answer, which is what this row is here to prove.
    const onPost = await request.post(`${OAUTH2}/access_token?realm=bogus`, {
      form: { grant_type: "client_credentials", scope: SCOPE },
      headers: { Authorization: `Basic ${Buffer.from(`${CONFIDENTIAL_CLIENT_ID}:${CONFIDENTIAL_SECRET}`).toString("base64")}` },
    });
    const postBody = await onPost.json();
    console.log(`[5-E5] row2 POST /access_token?realm=bogus -> ${onPost.status()} ${JSON.stringify(postBody)}`);
    // ⚠ 5d-1c divergence: as on the GET above. Restlet: 404 with realm404("bogus").
    expect(onPost.status()).toBe(400);
    expect(postBody).toEqual(invalidRealm400("bogus"));
    // ⚠ No `Cache-Control: no-store` here: the OAuth2Filter that stamped /access_token sat INSIDE the realm
    // router, so a realm failure never reached it. CONFIRMED unchanged after the flip -- OAuth2HttpRouteProvider
    // puts OAuth2NoCacheFilter on the two endpoint ROUTES (D1), i.e. inside the realm filter -- so this stays
    // absent; assert it, or a "tidy" hoist to the root would go unnoticed.
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
    // ⚠ Under Restlet the LEADING SLASH mattered: the inner router handed `Realm.of` a path, so the identifier
    // was "/bogus" here and a bare "bogus" in row 2 -- same failure, two spellings.
    // ⚠ 5d-1c divergence: CHF's realm router raises its OWN message and nothing rewrites it, so the identifier
    // is the bare name and the wording is `Realm "bogus" not found` -- which is what phase-5d-1 finding 15
    // predicted for Restlet and got wrong. Restlet: realm404("/bogus").
    expect(bogusBody).toEqual(oauth2Realm404("bogus"));

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
    // these are the answers it had to reproduce, and it does -- every one of these is still a 200.
    for (const [label, url, contentType] of [
      // ⚠ 5d-1c divergence: JSON responses gained a charset parameter. Restlet: "application/json" here (the
      // other two endpoints already sent the charset under Restlet, so only this row moves).
      ["/tokeninfo", `${path("/tokeninfo")}?access_token=${ccToken}`, "application/json;charset=UTF-8"],
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
      // ⚠ 5d-1c divergence: CHF DOES send Content-Length on a HEAD (measured 213 on /tokeninfo here, and 238
      // on the resource_set item in 5-E4 row 15) -- it is the GET's length, computed from the entity the
      // container then strips. finding 7 asked for this measurement because it is the container's decision,
      // not the application's, and the decision changed with the stack. Restlet: no Content-Length at all.
      // ⚠ Asserted as DEFINED rather than pinned to 213: /tokeninfo's body carries `expires_in`, whose digit
      // count shrinks as the token ages, so the exact number is not a stable oracle. The follow-up run this
      // asked for measured the other two on 2026-08-05 -- .well-known/openid-configuration 1515,
      // connect/jwk_uri 447 -- and they are still left DEFINED here: both track provider config and signing
      // keys, so a container with a different key set moves them without anything regressing.
      expect(head.headers["content-length"], label).toBeDefined();
      // An HTTP client discards a HEAD entity whatever the server sent, so body emptiness is NOT asserted.
    }
    // /tokeninfo's own cache contract survives the verb change.
    const cached = await raw(`${path("/tokeninfo")}?access_token=${ccToken}`, { method: "HEAD" });
    expect(cached.headers["cache-control"]).toBe("no-cache, no-store");

    // ⚠ OVERTURNED THE PLAN, and this was the sharpest finding of the gate. phase-5d-1 finding 6 stated that
    // `HEAD /oauth2/authorize` "runs the real authorization flow ... Restlet did precisely the same". It did
    // not: AuthorizeEndpointFilter.validateMethod accepted GET and POST only, and Restlet rewrote HEAD to GET
    // at ANNOTATION LOOKUP -- inside the resource, below the filter -- so the filter saw a HEAD and 405d.
    // Once 5d-1a mapped HEAD to @Get in `Endpoints.from`, the same request WOULD have run the flow and issued
    // a code. ⚠ It does not, and that is this row's doing: the finding was decided rather than discovered, and
    // `AuthorizeHandler.authorize` now refuses a HEAD explicitly before anything else (5-E5 correction 2). So
    // the 405 below is parity, deliberately preserved -- not an accident of the framework.
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
      // The 405 carries /authorize's cache headers -- under Restlet because it was the OAuth2Filter-wrapped
      // path rather than a container error, and after the flip because OAuth2NoCacheFilter is chained onto the
      // authorize ROUTE, so it stamps the handler's own methodNotAllowed() response too.
      expect(head.headers()["cache-control"]).toBe("no-store");
      expect(head.headers()["pragma"]).toBe("no-cache");
    } finally {
      await authCtx.dispose();
    }

    // /access_token answers the same way to HEAD as to GET -- under Restlet because of its method filter,
    // after the flip because HEAD maps to the @Get entry and TokenEndpointHandler declares only @Post, so the
    // framework's unmapped-verb fallback answers. Same status, different reason.
    const tokenHead = await raw(path("/access_token"), { method: "HEAD" });
    console.log(`[5-E5] row5 HEAD /access_token -> ${tokenHead.status} ct=${tokenHead.headers["content-type"]}`);
    expect(tokenHead.status).toBe(405);

    // ⚠ A HEAD that ended in an ERROR status did not send the JSON body's headers at all under Restlet: the
    // stack substituted an HTML status page, with a Content-Length, where the same request as a GET was
    // `application/json` with no length. CHF keeps the JSON content type on a HEAD (verified against
    // /openam/json), which was recorded as a divergence to EXPECT at the flip -- and it landed.
    const errorHead = await raw(path("/tokeninfo"), { method: "HEAD" });
    const errorGet = await raw(path("/tokeninfo"));
    console.log(`[5-E5] row5 HEAD /tokeninfo (no token) -> ${errorHead.status} ct=${errorHead.headers["content-type"]}`
      + ` len=${errorHead.headers["content-length"]} (GET ct=${errorGet.headers["content-type"]})`);
    expect(errorHead.status).toBe(401);
    expect(errorGet.status).toBe(401);
    // ⚠ 5d-1c divergence: an erroring HEAD keeps the JSON entity's headers instead of an HTML status page.
    // Restlet: "text/html;charset=utf-8".
    expect(errorHead.headers["content-type"]).toBe("application/json;charset=UTF-8");
    expect(errorHead.headers["content-length"]).toBeTruthy();
    // ⚠ 5d-1c divergence: JSON responses gained a charset parameter. Restlet: "application/json".
    expect(errorGet.headers["content-type"]).toBe("application/json;charset=UTF-8");
  });

  test("row 6: an unmapped verb is 405 -- and after the flip every producer says the same thing", async () => {
    // The `Allow` header D4 restores in `Endpoints.from`. ⚠ Its VALUE is per endpoint and is not the
    // resource_set list: these two endpoints declare a single @Get, so both stacks advertise exactly "GET".
    for (const endpoint of ["/tokeninfo", "/connect/jwk_uri"]) {
      for (const method of ["PROPFIND", "PUT"]) {
        const response = await raw(path(endpoint), { method, headers: { "Content-Length": 0 } });
        const label = `${method} ${endpoint}`;
        console.log(`[5-E5] row6 ${label} -> ${response.status} allow=${response.headers["allow"]} ${response.text}`);
        expect(response.status, label).toBe(405);
        expect(response.headers["allow"], label).toBe("GET");
        // ⚠ 5d-1c divergence: the OAuth2 405 body, from `Endpoints.from`'s fallback via OAuth2ErrorFilter.
        // Restlet answered CREST_405 here -- a THIRD shape alongside /access_token's `method_not_allowed` and
        // resource_set's `unsupported_method_type` (5-E4 row 11) -- and that third shape is now gone.
        expect(bodyOf(response), label).toEqual(OAUTH2_405);
        // No cache headers on these: only /authorize and /access_token carry OAuth2NoCacheFilter.
        expect(response.headers["cache-control"], label).toBeUndefined();
      }
    }

    // What used to be the OTHER 405 producer: an endpoint whose own filter checked the verb. It sent the
    // OAuth2 body, the cache headers -- and NO Allow at all, the RFC 7231 §6.5.5 gap D4 set out to close.
    // ⚠ 5d-1c: there is no second producer any more. These two endpoints have no verb filter; their 405 comes
    // from the same `Endpoints.from` fallback as the loop above, so the body is identical and the Allow gap is
    // closed. Only the cache headers still tell the two groups apart.
    for (const [endpoint, allow] of [
      ["/access_token", "POST"],
      ["/authorize", "GET, POST"],
    ]) {
      const response = await raw(path(endpoint), { method: "PROPFIND" });
      console.log(`[5-E5] row6 PROPFIND ${endpoint} -> ${response.status} allow=${response.headers["allow"]}`
        + ` ${response.text}`);
      expect(response.status, endpoint).toBe(405);
      // ⚠ 5d-1c divergence: the generic 405 body. Restlet: {error:"method_not_allowed", error_description:
      // "Required Method: POST found: PROPFIND"} and "... GET or POST found: PROPFIND" respectively.
      expect(bodyOf(response), endpoint).toEqual(OAUTH2_405);
      // ⚠ 5d-1c divergence: Allow is now stamped on the 405s that lacked it -- the two OAuth2Filter endpoints,
      // `/access_token` and `/authorize` (Endpoints.withAllow), listing the endpoint's mapped verbs in the
      // fixed order DELETE, GET, POST, PUT. HEAD is deliberately excluded. Restlet: no Allow on THESE two,
      // the RFC 7231 §6.5.5 gap D4 closed. ⚠ Not "every 405": Restlet's framework-produced 405s already
      // carried one -- row 7 measured `allow=GET` on its PATCH /tokeninfo, and 5-E4 row 11 measured the same
      // "DELETE, GET, POST, PUT" join on resource_set -- so those two are unchanged, not new.
      expect(response.headers["allow"], endpoint).toBe(allow);
      expect(response.headers["cache-control"], endpoint).toBe("no-store");
    }
  });

  test("row 7: PATCH is refused before the @Get runs -- narrower than under Restlet, and than resource_set", async () => {
    // ⚠ OVERTURNED THE PLAN's scoping. 5-E4 row 11 found PATCH on resource_set routed to the @Put method, and
    // D4 scoped divergence row 14 to that endpoint on the grounds that it is the only ported endpoint with a
    // @Put. What Restlet actually did with a PATCH was run the resource's @Get FIRST (to obtain the current
    // representation) and only then look for a handler -- so on a @Get-only endpoint the GET's side effects
    // and the GET's ERRORS were on the wire, and only afterwards did the 405 appear.
    //
    // ⚠ 5d-1c REMOVES that behaviour entirely, and this row now measures its absence. PATCH is not one of the
    // four verbs `Endpoints.from` maps, so it never resolves to a method and the 405 is produced before any
    // handler code runs. The three requests below were the proof that the @Get ran; they are now the proof
    // that it does not: the 405 carries none of /tokeninfo's own cache directives (only
    // `ValidationServerResource.validate()` set those, and it no longer executes), and the unauthenticated
    // PATCH -- which used to answer the GET's 401 -- never reaches the token check at all.
    const patched = await raw(`${path("/tokeninfo")}?access_token=${ccToken}`,
      { method: "PATCH", headers: { "Content-Length": 0 } });
    console.log(`[5-E5] row7 PATCH /tokeninfo (valid token) -> ${patched.status}`
      + ` cache=${patched.headers["cache-control"]} allow=${patched.headers["allow"]}`);
    expect(patched.status).toBe(405);
    // ⚠ 5d-1c divergence: the framework 405 body. Restlet: CREST_405.
    expect(bodyOf(patched)).toEqual(OAUTH2_405);
    expect(patched.headers["allow"]).toBe("GET");
    // ⚠ 5d-1c divergence: no cache directives, because the @Get that set them never runs. Restlet:
    // "no-cache, no-store" -- which was the whole evidence that PATCH executed the GET first.
    expect(patched.headers["cache-control"]).toBeUndefined();

    const unauthenticated = await raw(path("/tokeninfo"), { method: "PATCH", headers: { "Content-Length": 0 } });
    console.log(`[5-E5] row7 PATCH /tokeninfo (no token) -> ${unauthenticated.status} ${unauthenticated.text}`);
    // ⚠ 5d-1c divergence: the verb is rejected before authentication, so a PATCH with no token is a 405 and not
    // the GET's 401. Restlet: 401 with error "invalid_token".
    expect(unauthenticated.status).toBe(405);
    expect(bodyOf(unauthenticated)).toEqual(OAUTH2_405);

    const put = await raw(`${path("/tokeninfo")}?access_token=${ccToken}`,
      { method: "PUT", headers: { "Content-Length": 0 } });
    console.log(`[5-E5] row7 PUT /tokeninfo (valid token) -> ${put.status} cache=${put.headers["cache-control"]}`);
    expect(put.status).toBe(405);
    expect(put.headers["cache-control"]).toBeUndefined();

    // On /access_token the answer is the same as ever -- Restlet's filter refused PATCH before any of that,
    // and the framework now refuses it for the same reason it refuses every unmapped verb.
    const onToken = await raw(path("/access_token"), { method: "PATCH", headers: { "Content-Length": 0 } });
    console.log(`[5-E5] row7 PATCH /access_token -> ${onToken.status} ${onToken.text}`);
    expect(onToken.status).toBe(405);
    // ⚠ 5d-1c divergence: the generic 405 body. Restlet: {error:"method_not_allowed", error_description:
    // "Required Method: POST found: PATCH"}.
    expect(bodyOf(onToken)).toEqual(OAUTH2_405);
  });

  test("row 8: ?_api now answers 501; only ?_crestapi is still ignored", async ({ request }) => {
    // The baseline for phase-5d-1 finding 10: after the flip the global CHF chain's ApiDescriptorFilter and
    // OpenApiRequestFilter see these parameters on /oauth2 for the first time. Under Restlet they were simply
    // query parameters nobody read, and the endpoint answered exactly as it would without them.
    // ⚠ 5d-1c: finding 10 landed, and it landed on ONE of the two. `OpenApiRequestFilter:68-75` intercepts
    // `_api` and, the /oauth2 handlers being non-Describable, answers 501 with no entity at all. `_crestapi`
    // belongs to `ApiRouteMatcher` on the CREST side and still passes through untouched. So the two parameters
    // no longer behave alike and the row can no longer assert them together.
    const plain = await request.get(`${OAUTH2}/connect/jwk_uri`);
    const plainBody = await plain.text();
    for (const [parameter, status] of [["_api", 501], ["_crestapi", 200]]) {
      const response = await request.get(`${OAUTH2}/connect/jwk_uri?${parameter}`);
      console.log(`[5-E5] row8 /connect/jwk_uri?${parameter} -> ${response.status()}`
        + ` ct=${response.headers()["content-type"]}`);
      // ⚠ 5d-1c divergence: `?_api` is intercepted before the endpoint and answered 501 with an EMPTY body and
      // no Content-Type. Restlet: 200 with the endpoint's own answer, byte-identical to the plain request.
      expect(response.status(), parameter).toBe(status);
      if (status === 501) {
        expect(response.headers()["content-type"], parameter).toBeUndefined();
        expect(await response.text(), parameter).toBe("");
      } else {
        expect(response.headers()["content-type"], parameter).toBe("application/json;charset=UTF-8");
        expect(await response.text(), parameter).toBe(plainBody);
      }
    }
    const withToken = await request.get(`${OAUTH2}/tokeninfo?_api&access_token=${ccToken}`);
    console.log(`[5-E5] row8 /tokeninfo?_api -> ${withToken.status()}`);
    // ⚠ 5d-1c divergence: the filter is in the shared chain, so `?_api` shadows EVERY /oauth2 endpoint, not
    // just the discovery-shaped ones -- an authenticated /tokeninfo call included. Restlet: 200.
    expect(withToken.status()).toBe(501);
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
      // ⚠ 5d-1c divergence: the generic 405 body -- the check is now the framework's unmapped-verb fallback,
      // which cannot name the verbs it wanted. Restlet: {error:"method_not_allowed", error_description:
      // "Required Method: GET or POST found: OPTIONS"}.
      expect(body, label).toEqual(OAUTH2_405);
      for (const header of Object.keys(response.headers())) {
        expect(header.startsWith("access-control-"), `${label}: ${header}`).toBe(false);
      }
    }

    // On an endpoint with no method filter, OPTIONS lands on the same 405 as any other unmapped verb --
    // neither stack implements the automatic OPTIONS response it could (Restlet's ServerResource then,
    // `Endpoints.from`'s four-verb map now).
    const onGetOnly = await raw(path("/tokeninfo"), { method: "OPTIONS" });
    console.log(`[5-E5] row9 OPTIONS /tokeninfo -> ${onGetOnly.status} allow=${onGetOnly.headers["allow"]}`);
    expect(onGetOnly.status).toBe(405);
    expect(onGetOnly.headers["allow"]).toBe("GET");
    // ⚠ 5d-1c divergence: the framework 405 body. Restlet: CREST_405.
    expect(bodyOf(onGetOnly)).toEqual(OAUTH2_405);
  });

  test("row 10: the method tunnel -- the header is honoured on POST only, and the query tunnel is gone", async ({ request }) => {
    // ⚠ THIS ROW SETTLED D11, and it settled it in three parts rather than the two the decision anticipated.
    //
    // (a) `X-HTTP-Method-Override` on a POST: HONOURED, exactly as `Endpoints.getMethod:169-176` does after
    //     the flip. No divergence in BEHAVIOUR -- D11's first branch -- only in the message it produces.
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
    // The verb is still rewritten before the endpoint's verb dispatch -- the 405 on a POST that would
    // otherwise have issued a token (see the control below) is what proves it.
    // ⚠ 5d-1c divergence: the MESSAGE no longer evidences the rewrite. Under Restlet it named the observed
    // verb, so "found: GET" on a POST request WAS the proof; `Endpoints.from`'s fallback emits the generic
    // reason phrase, so the proof is now the control pair, not the body. Restlet:
    // {error:"method_not_allowed", error_description:"Required Method: POST found: GET"}.
    expect(overriddenBody).toEqual(OAUTH2_405);
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

    // (b) the same header on a NON-POST: Restlet honoured it, CHF does not -- `Endpoints.getMethod:171` gates
    //     the rewrite on `"POST".equals(method)`. So this GET, a 405 under Restlet, is now the plain GET's
    //     200: a divergence in the safe direction, but a divergence.
    // ⚠ 5d-1c divergence: the override header is ignored on a GET, so the request runs as the GET it is.
    // Restlet: 405 with CREST_405.
    const onGet = await raw(`${path("/tokeninfo")}?access_token=${ccToken}`,
      { headers: { "X-HTTP-Method-Override": "PUT" } });
    console.log(`[5-E5] row10 GET /tokeninfo + override PUT -> ${onGet.status} allow=${onGet.headers["allow"]}`);
    expect(onGet.status).toBe(200);
    expect(bodyOf(onGet).realm).toBe("/");

    // (c) Restlet's OWN tunnel, the `method` QUERY parameter (TunnelService, POST-only), which CHF has no
    //     equivalent for at all -- `Endpoints.getMethod` reads the header and nothing else. `POST
    //     /access_token?method=GET` was a 405 and now ISSUES A TOKEN. Both legs are measured (Restlet
    //     2026-08-04, CHF 2026-08-05); what nobody had anticipated is the WIDENING, which no plan row
    //     predicted and which is why this gets a divergence row of its own.
    // ⚠ 5d-1c divergence: the query tunnel is gone, so the parameter is an unread query parameter and the POST
    // runs as posted. Restlet: 405 with error_description "Required Method: POST found: GET".
    const queryTunnel = await request.post(`${OAUTH2}/access_token?method=GET`, {
      form: { grant_type: "client_credentials", scope: SCOPE },
      headers: {
        Authorization: `Basic ${Buffer.from(`${CONFIDENTIAL_CLIENT_ID}:${CONFIDENTIAL_SECRET}`).toString("base64")}`,
      },
    });
    const queryBody = await queryTunnel.json();
    console.log(`[5-E5] row10 POST /access_token?method=GET -> ${queryTunnel.status()} ${JSON.stringify(queryBody)}`);
    expect(queryTunnel.status()).toBe(200);
    expect(queryBody.access_token).toBeTruthy();
    // ...and it really is POST-only: the same parameter on a GET changes nothing.
    const queryOnGet = await request.get(`${OAUTH2}/tokeninfo?method=PUT&access_token=${ccToken}`);
    console.log(`[5-E5] row10 GET /tokeninfo?method=PUT -> ${queryOnGet.status()}`);
    expect(queryOnGet.status()).toBe(200);
  });

  test("row 11: an unrouted path is a 404 -- and after the flip from a single producer", async () => {
    // What D5's OAuth2NotFoundHandler is measured against. Under Restlet the producer depended on the SEGMENT
    // COUNT, which is the finding phase-5d-1's finding 8 half-predicted: it expected every unmatched path to be
    // a realm 404, and one-segment paths were not.
    // ⚠ 5d-1c: the segment count no longer decides anything. `authorize`, `connect` and `nosuchendpoint` alike
    // fail to resolve as realms, so RealmContextFilter consumes none of them and every URL below lands on the
    // endpoint router's default route. The labels keep their Restlet-era annotations because that difference
    // in ROUTE is still real; it is only the ANSWER that has stopped depending on it.
    for (const [label, url, expected] of [
      ["/nosuchendpoint (one segment -> router)", path("/nosuchendpoint"), OAUTH2_404],
      ["/authorize/extra (two -> realm)", path("/authorize/extra"), OAUTH2_404],
      ["/connect/nosuch (two -> realm)", path("/connect/nosuch"), OAUTH2_404],
      ["/realms/root/nosuch (consumed by the realm route -> router)", path("/realms/root/nosuch"), OAUTH2_404],
    ]) {
      const response = await raw(url);
      console.log(`[5-E5] row11 ${label} -> ${response.status} ${response.text}`);
      expect(response.status, label).toBe(404);
      // ⚠ 5d-1c divergence: one OAuth2-shaped 404 everywhere -- the shape change D5 predicted for every one of
      // these URLs, CONFIRMED. Restlet: ROUTER_404 for rows 1 and 4, realm404("/authorize") and
      // realm404("/connect") for rows 2 and 3.
      expect(bodyOf(response), label).toEqual(expected);
      // ⚠ 5d-1c divergence: JSON responses gained a charset parameter. Restlet: "application/json".
      expect(response.headers["content-type"], label).toBe("application/json;charset=UTF-8");
    }
  });

  test("row 12: the prefix with no endpoint is a 404 -- except the bare `/oauth2/`, which is a 500", async () => {
    // Never recorded by any row before this one. The bare prefix was the one place `/{subrealm}` had nothing
    // to bind, so Restlet's own router 404 surfaced -- and `/realms` and `/realms/root` behaved the same way.
    //
    // ⚠ NOT A CLEAN DIVERGENCE, and the only entry in this file that is not. `/oauth2/` -- the prefix with a
    // TRAILING SLASH and nothing after it -- is a 500 with an EMPTY body, from
    // `RouteMatchers.getRemainingRequestUri:164-170`: it computes the unmatched tail as
    // `path.subList(matchedUri.size(), path.size())` with no guard, and on this one shape the matched base is
    // longer than the path, so the sublist throws `IllegalArgumentException: fromIndex(4) > toIndex(3)`.
    //   - It is NOT introduced by this flip. `/json/` and `/uma/` have answered the same way for years, and
    //     `/json` has been CHF-served since OpenAM 14.0 -- so the defect predates the migration by nine
    //     releases and merely became visible on `/oauth2` when `/oauth2` joined the same router.
    //   - It is NOT fixable here. `RouteMatchers` is external commons, not in this repository.
    // Pinned as measured so that a future commons upgrade turning it back into a 404 registers as a CHANGE
    // rather than passing silently.
    for (const [label, url, status] of [
      ["/oauth2/", `${path("")}/`, 500],
      ["/oauth2", path(""), 404],
      ["/oauth2/realms", path("/realms"), 404],
      ["/oauth2/realms/root", path("/realms/root"), 404],
    ]) {
      const response = await raw(url);
      console.log(`[5-E5] row12 ${label} -> ${response.status} ${response.text}`);
      // ⚠ 5d-1c divergence: `/oauth2/` alone is a 500 with no body at all, from the pre-existing commons
      // sublist defect described above. Restlet: 404 with ROUTER_404, like its three siblings.
      expect(response.status, label).toBe(status);
      if (status === 500) {
        expect(response.text, label).toBe("");
      } else {
        // ⚠ 5d-1c divergence: the OAuth2-shaped routing 404 (D5). Restlet: ROUTER_404.
        expect(bodyOf(response), label).toEqual(OAUTH2_404);
      }
    }
  });

  test("row 14: an unknown Host is a 400 after the flip -- on BOTH URL styles, from two different filters", async () => {
    // ⚠ OVERTURNED THE PLAN, and it is the row that mattered most to a live deployment. phase-5d-1 finding 16
    // predicted that `/oauth2/realms/root/...` WORKED under an unrecognised Host (the outer router
    // short-circuiting when `realmId` is set) and would 400 after the flip -- "the only row here that can break
    // a deployment that works today". It did not work: `realmId` was set by the route TEMPLATE, which is parsed
    // after `doHandle` has already called `getRealmFromServerName`, so the host was resolved on every request
    // and both styles answered 500.
    //
    // ⇒ provisional divergence row 17 was rewritten to "500 -> 400 on both styles", i.e. a better answer to a
    //   request that is already failing rather than a working integration breaking, and R-5d1.9's severity
    //   dropped accordingly. ⚠ 5d-1c CONFIRMS the 400 -- with a refinement the plan did not have: the two URL
    //   styles fail in DIFFERENT filters and therefore say different things. The default route runs
    //   `RealmContextFilter`, which rejects the hostname outright (`isValidFQDN`); `/realms/{id}` runs
    //   `RealmRoutingFactory.HostnameFilter` first, which gets as far as `Realm.of(host)` and reports a realm
    //   lookup failure. Same status, same 400, two messages.
    const fqdn400 = {
      error: "invalid_request", error_description: `FQDN &quot;not-a-real-host.invalid&quot; is not valid.`,
    };
    for (const [label, url, expected] of [
      ["/oauth2/tokeninfo", `${path("/tokeninfo")}?access_token=${ccToken}`, fqdn400],
      ["/oauth2/realms/root/tokeninfo", `${path("/realms/root/tokeninfo")}?access_token=${ccToken}`,
        { error: "invalid_request", error_description: `Realm &quot;not-a-real-host.invalid&quot; not found` }],
      ["/oauth2/.well-known/openid-configuration", path("/.well-known/openid-configuration"), fqdn400],
    ]) {
      const response = await raw(url, { hostHeader: "not-a-real-host.invalid" });
      console.log(`[5-E5] row14 ${label} under an unknown Host -> ${response.status} ${response.text}`);
      // ⚠ 5d-1c divergence: an unrecognised Host is a 400 about the request, not a 500 about the server.
      // Restlet: 500 with {code:500, reason:"Internal Server Error", message:"No mapping organization found
      // for organization identifier: not-a-real-host.invalid"} on all three.
      expect(response.status, label).toBe(400);
      // ⚠ The `&quot;` is MEASURED (see oauth2Realm404): ResourceException.toJsonValue HTML-escapes, exactly as
      // /json has since 14.0. Pinned verbatim -- unescaping it here would hide a product-wide behaviour.
      expect(bodyOf(response), label).toEqual(expected);
    }

    // ⚠ The positive control that makes the three rows above mean anything: the SAME raw client, the same
    // URL, with the deployment's own hostname, answers 200. Without it a client that silently dropped the
    // Host header would leave every assertion above passing for the wrong reason.
    const known = await raw(path("/connect/jwk_uri"), { hostHeader: BASE.hostname });
    console.log(`[5-E5] row14 the same request with Host: ${BASE.hostname} -> ${known.status}`);
    expect(known.status).toBe(200);
  });
});

/**
 * A non-browser client posts its consent decision directly, without ever rendering the consent page, and
 * submits its own session id as the csrf value. This is the flow documented for headless clients.
 */
test.describe("OAuth2 consent posted directly by a non-browser client", () => {

  /**
   * The authorization request parameters, shared by the GET that renders the consent page and the POST that
   * carries the decision. Both must describe the same request, including the PKCE challenge: the request
   * validators run before the csrf check, so an incomplete POST fails with a redirect long before the csrf
   * value is looked at.
   */
  function authorizeRequest(challenge, extra) {
    return {
      response_type: "code",
      client_id: CONSENT_CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPE,
      state: CONSENT_STATE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      ...extra,
    };
  }

  /**
   * Authenticates and confirms consent really is required for this client: the GET returns the consent page
   * instead of redirecting with a code. That precondition also proves the client's redirect URI, scope,
   * response type and PKCE requirements are satisfied, so the rejection tests below cannot go green on a 400
   * that has nothing to do with the csrf value.
   */
  async function startConsentFlow(request) {
    const demoToken = await getAuthToken(request, USERNAME, PASSWORD);
    const challenge = await generateChallenge(generateVerifier());

    const consentPage = await request.get(`${OPENAM_BASE}/oauth2/realms/${REALM}/authorize`, {
      headers: {
        "iPlanetDirectoryPro": demoToken,
      },
      params: authorizeRequest(challenge),
      maxRedirects: 0,
    });

    expect(consentPage.status()).toBe(200);
    return { demoToken, challenge };
  }

  test("Should accept the session id as the csrf value", async ({ request }) => {
    const { demoToken, challenge } = await startConsentFlow(request);

    const response = await request.post(`${OPENAM_BASE}/oauth2/realms/${REALM}/authorize`, {
      headers: {
        "iPlanetDirectoryPro": demoToken,
      },
      form: authorizeRequest(challenge, { decision: "allow", csrf: demoToken }),
      maxRedirects: 0,
    });

    expect(response.status()).toBe(302);

    const location = new URL(response.headers()['location']);
    expect(location.searchParams.get("code")).toBeTruthy();
    expect(location.searchParams.get("state")).toBe(CONSENT_STATE);
  });

  test("Should reject the consent decision when csrf is missing", async ({ request }) => {
    const { demoToken, challenge } = await startConsentFlow(request);

    const response = await request.post(`${OPENAM_BASE}/oauth2/realms/${REALM}/authorize`, {
      headers: {
        "iPlanetDirectoryPro": demoToken,
      },
      form: authorizeRequest(challenge, { decision: "allow" }),
      maxRedirects: 0,
    });

    expect(response.status()).toBe(400);
  });

  test("Should reject a csrf value that is not the caller's session", async ({ request }) => {
    const { demoToken, challenge } = await startConsentFlow(request);

    const response = await request.post(`${OPENAM_BASE}/oauth2/realms/${REALM}/authorize`, {
      headers: {
        "iPlanetDirectoryPro": demoToken,
      },
      form: authorizeRequest(challenge, { decision: "allow", csrf: "not-the-session-id" }),
      maxRedirects: 0,
    });

    expect(response.status()).toBe(400);
  });

});
