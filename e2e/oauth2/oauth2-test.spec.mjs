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

import { test, expect } from "@playwright/test";
import { OPENAM_BASE, getAdminToken, getAuthToken, PASSWORD, USERNAME } from "../common/openam-commons.mjs";
import {
  CLIENT_ID,
  // A client that does not imply consent, so the resource owner's decision must be posted explicitly. This
  // is the situation issue #1080 reports: a non-browser client cannot obtain a token to post the decision.
  CONSENT_CLIENT_ID,
  OAUTH2_REALM as REALM,
  REDIRECT_URI,
  SCOPE,
  ensureOAuth2ClientExists,
  ensureOAuth2ServiceExists,
  generateChallenge,
  generateVerifier,
} from "../common/oauth2-commons.mjs";

const CONSENT_STATE = "consent-state";

test.beforeAll(async ({ request }) => {
  const adminToken = await getAdminToken(request)

  if (!adminToken) {
    test.skip("Skipping: ADMIN_TOKEN not set");

  }
  await ensureOAuth2ServiceExists(adminToken, request);
  await ensureOAuth2ClientExists(adminToken, request);
  await ensureOAuth2ClientExists(adminToken, request, CONSENT_CLIENT_ID, false);
});

let accessToken;

/**
 * Deployed AM only, and deliberately not tagged @local-server.
 *
 * Everything asserted below is AM's OAuth2 server behaviour — authorization-code issuance, PKCE
 * verification, token exchange — reached through `/oauth2/*` rather than through the XUI. No UI
 * build change can affect it, so it sits on the deployed-AM side of D16's split. The local API
 * server's scope is the requests the phase-0 specs cause the XUI to issue (task 2.1), which puts
 * these endpoints out of scope by construction; serving them there would mean reimplementing the
 * behaviour under test (design.md D16).
 */
test.describe("OAuth Service test", { tag: ["@deployed-am"] }, () => {
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

});

/**
 * A non-browser client posts its consent decision directly, without ever rendering the consent page, and
 * submits its own session id as the csrf value. This is the flow documented for headless clients.
 *
 * Deployed AM only, for the reason given on the describe above: this asserts how AM's consent
 * endpoint treats a decision posted without a browser session — server behaviour the migration
 * cannot affect (design.md D16).
 */
test.describe("OAuth2 consent posted directly by a non-browser client", { tag: ["@deployed-am"] }, () => {

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
