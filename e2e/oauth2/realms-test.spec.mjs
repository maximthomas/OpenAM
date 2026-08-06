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
 * `/oauth2` in a NON-ROOT realm, through all three realm spellings.
 *
 * WHY THIS FILE EXISTS. Every other e2e row runs against default config in the ROOT realm. The one existing
 * exception -- 5-E5 rows 3 and 4 in `oauth2-test.spec.mjs` -- creates an EMPTY sub-realm and only ever asks
 * routing questions of it: the realm has no OAuth2 provider, no client and no user, so the deepest answer it
 * can produce is "no OIDC provider for realm /x". Nothing anywhere exercised a real OAuth2 deployment in a
 * sub-realm, which is the shape most production installs actually run, and which
 * [risk #9](../../docs/migration/restlet/plan.md#risk-register-behavioral-compatibility) -- realm resolution
 * parity -- is about. `phase-5d-1.md:468-470` names it the first of the three gaps a green suite does not
 * close.
 *
 * The three spellings, all of which resolve to the same realm and all of which are exercised below:
 *   1. `/oauth2/realms/root/realms/<sub>/…`  -- the modern, nested form the realm's own discovery document
 *                                               advertises;
 *   2. `/oauth2/<sub>/…`                     -- the legacy form `RestletRealmRouter`'s `/{subrealm}` route
 *                                               existed for, still served by `RealmContextFilter`;
 *   3. `/oauth2/…?realm=<sub>`               -- the query override.
 * A fourth, FLAT `/oauth2/realms/<sub>/…`, is covered too: 5-E5 row 4 measured it live on Restlet and found
 * it works, overturning what the plan predicted, so it is a spelling in production use.
 *
 * ⚠ ROWS 3 AND 10 ARE THE GUARD FOR A REGRESSION THIS FILE FOUND AND THE SAME PASS FIXED. Confidential-client
 * authentication at `/oauth2/access_token` in a non-root realm worked on the `?realm=` spelling and was BROKEN
 * on all three path spellings. Measured A/B on 2026-08-06 with one identical fixture and identical requests:
 *   - pre-flip Restlet (`openam-e2e:5d1b`)  -- all four spellings issue a token, 200;
 *   - post-flip CHF    (`openam-e2e:soak`)  -- the three path spellings answer 401 `invalid_client`,
 *                                              `WWW-Authenticate: Basic realm="/<sub>"`; only `?realm=` works.
 * It matched no row in [expected divergences](../../docs/migration/restlet/plan.md#expected-divergences-at-the-flip),
 * and by that table's own rule an unmatched difference is a regression. Cause and fix are in row 3's comment;
 * row 10 covers the resource-owner half of the same fault, which no measurement caught because the password
 * grant is the only flow that reaches `ResourceOwnerAuthenticator`. Both rows assert the CORRECT (Restlet)
 * answer, so they can never be "fixed" by quietly rewriting the expectation.
 *
 * Everything else here was OBSERVED on CHF first and only then asserted, and every row that could be compared
 * was also run against the pre-flip Restlet image, so the comments say which stack a value comes from.
 */

import { request as httpRequest } from "node:http";
import { test, expect, request as apiRequest } from "@playwright/test";
import { OPENAM_BASE, getAdminToken } from "../common/openam-commons.mjs";
import { REDIRECT_URI, basicAuth, sessionContext } from "../common/oauth2-fixtures.mjs";

const BASE = new URL(OPENAM_BASE);
const OAUTH2 = `${OPENAM_BASE}/oauth2`;

/** This spec's own realm. Distinct from 5-E5's `e2e5e5realm`, which is a different fixture with no provider. */
const SUB_REALM = "e2erealmsoak";
/** SmsRealmProvider's resource id is base64url of the realm PATH, not the name (5-E5 established this). */
const SUB_REALM_ID = Buffer.from(`/${SUB_REALM}`).toString("base64url");
const REALMS_URL = `${OPENAM_BASE}/json/global-config/realms`;
const REALM_CONFIG = `${OPENAM_BASE}/json/realms/root/realms/${SUB_REALM}`;

const CLIENT_ID = "soak_realm_client";
/** >=256 bits: OpenAM signs id_tokens HS256 with the client secret and a short one fails opaquely. */
const CLIENT_SECRET = "soak-realm-secret-0123456789-0123456789-0123456789";
const SCOPE = "profile";

/** The realm needs its OWN resource owner: a root-realm session does not authorize here (row 7). */
const SUB_USER = "soakrealmuser";
const SUB_PASS = "S0akRealmPassw0rd!";

let adminToken;
let subUserToken;
let rootUserToken;
/** A client_credentials token minted through the one spelling that works, so the /tokeninfo rows have a
 *  real sub-realm token to look up whatever row 3 is doing. */
let subRealmToken;

const adminHeaders = (version) => ({
  iPlanetDirectoryPro: adminToken, "Content-Type": "application/json", "Accept-API-Version": version,
});

/** The four spellings, as URL builders. `?realm=` needs the separator chosen by whether a query is present. */
const SPELLINGS = [
  ["nested", (path, query = "") => `${OAUTH2}/realms/root/realms/${SUB_REALM}${path}${query}`],
  ["legacy", (path, query = "") => `${OAUTH2}/${SUB_REALM}${path}${query}`],
  ["flat", (path, query = "") => `${OAUTH2}/realms/${SUB_REALM}${path}${query}`],
  ["query", (path, query = "") => `${OAUTH2}${path}${query ? `${query}&` : "?"}realm=${SUB_REALM}`],
];
/** The three PATH spellings -- i.e. every spelling that does NOT name the realm in the query. */
const PATH_SPELLINGS = SPELLINGS.filter(([label]) => label !== "query");

/** `/oauth2…` as raw path bytes, context path included -- for the rows Playwright's client would normalise. */
const rawPath = (suffix) => `${BASE.pathname.replace(/\/$/, "")}/oauth2${suffix}`;

/** A raw node:http request, for the `Host` row: a Host that does not match the connection cannot be sent
 *  through Playwright. Same helper shape as 5-E5's, deliberately. */
function raw(path, { method = "GET", headers = {}, hostHeader } = {}) {
  return new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: BASE.hostname, port: BASE.port || 80, path, method,
      headers: { ...(hostHeader ? { Host: hostHeader } : {}), ...headers },
      setHost: hostHeader === undefined,
    }, (response) => {
      let text = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { text += chunk; });
      response.on("end", () => resolve({ status: response.statusCode, headers: response.headers, text }));
    });
    request.on("error", reject);
    request.end();
  });
}

async function authenticate(request, realmPath, username, password) {
  const response = await request.post(`${OPENAM_BASE}/json${realmPath}/authenticate`, {
    headers: {
      "Content-Type": "application/json", "X-OpenAM-Username": username,
      "X-OpenAM-Password": password, "Accept-API-Version": "resource=2.0, protocol=1.0",
    },
  });
  return (await response.json()).tokenId;
}

/**
 * Builds a REAL OAuth2 deployment inside a fresh sub-realm. Four steps, and the third is the non-obvious one.
 *
 * ⚠ A realm created over REST has NO `AgentService` organization config, so every write to
 * `realm-config/agents/OAuth2Client/<id>` in it answers `404 Parent service does not exist.`
 * (`SmsResourceProvider:200-202`), and `agents` is not in the realm's `getCreatableTypes` list either -- so
 * there is no admin-API call that creates it. What DOES create it is the product's own client-registration
 * path: `connect/register` goes through `AgentConfiguration.createAgent`, which creates the org config when
 * it is missing. Hence step 3: turn on dynamic registration, register one throwaway client to bootstrap the
 * container, and only then write the real client through the admin API. Discovered by measurement
 * (2026-08-06); it is the reason no earlier spec has ever put a client in a sub-realm.
 */
async function buildSubRealm(request) {
  const created = await request.post(`${REALMS_URL}?_action=create`, {
    headers: adminHeaders("protocol=1.0,resource=1.0"),
    // `aliases` is not optional: SmsRealmProvider.validateRealmAliases rejects a body without it.
    data: { name: SUB_REALM, parentPath: "/", active: true, aliases: [] },
  });
  // 409 means a previous run left it behind, which is as good as creating it.
  if (!created.ok() && created.status() !== 409) {
    throw new Error(`realm create failed: ${created.status()} ${await created.text()}`);
  }
  console.log(`[realms] realm ${SUB_REALM} ready (${created.status()})`);

  const providerUrl = `${REALM_CONFIG}/realm-config/services/oauth-oidc`;
  const provider = await request.post(`${providerUrl}?_action=create`, {
    headers: adminHeaders("protocol=1.0,resource=1.0"),
    data: {
      coreOAuth2Config: { savedConsentAttribute: "description" },
      advancedOAuth2Config: {
        // ⚠ FALSE here, where the ROOT provider pins it true. This realm's rows are about the realm, not
        // about PKCE, and enforcing it would make every authorize row carry a challenge for no added cover.
        clientsCanSkipConsent: true, codeVerifierEnforced: false,
        supportedScopes: [SCOPE, "openid"], defaultScopes: [SCOPE],
      },
    },
  });
  if (!provider.ok() && provider.status() !== 409) {
    throw new Error(`provider create failed: ${provider.status()} ${await provider.text()}`);
  }

  // Step 3 -- the AgentService bootstrap. See this function's javadoc for why it cannot be done any other way.
  const current = await request.get(providerUrl, { headers: adminHeaders("protocol=1.0,resource=1.0") });
  const config = await current.json();
  if (!config.advancedOIDCConfig?.allowDynamicRegistration) {
    config.advancedOIDCConfig.allowDynamicRegistration = true;
    const enabled = await request.put(providerUrl, {
      headers: adminHeaders("protocol=1.0,resource=1.0"), data: config,
    });
    if (!enabled.ok()) {
      throw new Error(`could not enable dynamic registration: ${enabled.status()} ${await enabled.text()}`);
    }
  }
  const bootstrap = await request.post(`${OAUTH2}/realms/root/realms/${SUB_REALM}/connect/register`, {
    headers: { "Content-Type": "application/json" },
    data: { redirect_uris: [REDIRECT_URI], client_name: "agent service bootstrap" },
  });
  if (bootstrap.status() !== 201) {
    throw new Error(`AgentService bootstrap failed: ${bootstrap.status()} ${await bootstrap.text()}`);
  }
  console.log(`[realms] AgentService bootstrapped in /${SUB_REALM} via connect/register`);

  const client = await request.put(
    `${REALM_CONFIG}/realm-config/agents/OAuth2Client/${CLIENT_ID}`, {
      headers: adminHeaders("protocol=2.0,resource=1.0"),
      data: {
        userpassword: CLIENT_SECRET,
        "com.forgerock.openam.oauth2provider.clientType": "Confidential",
        "com.forgerock.openam.oauth2provider.redirectionURIs": [`[0]=${REDIRECT_URI}`],
        "com.forgerock.openam.oauth2provider.scopes": [`[0]=${SCOPE}`, "[1]=openid"],
        "com.forgerock.openam.oauth2provider.defaultScopes": [`[0]=${SCOPE}`],
        "com.forgerock.openam.oauth2provider.grantTypes": [
          // `password` is here for row 10: ResourceOwnerAuthenticator authenticates the RESOURCE OWNER
          // through the same AuthContext cross-check row 3 covers for the CLIENT, so the two rows together
          // pin both AuthContext call sites under /oauth2.
          "[0]=authorization_code", "[1]=client_credentials", "[2]=refresh_token", "[3]=password",
        ],
        "com.forgerock.openam.oauth2provider.responseTypes": ["[0]=code", "[1]=token"],
        "com.forgerock.openam.oauth2provider.tokenEndPointAuthMethod": "client_secret_basic",
        isConsentImplied: true,
        sunIdentityServerDeviceStatus: "Active",
      },
    });
  if (!client.ok()) {
    throw new Error(`client write failed: ${client.status()} ${await client.text()}`);
  }

  const user = await request.post(`${REALM_CONFIG}/users?_action=create`, {
    headers: adminHeaders("resource=3.0, protocol=2.1"),
    data: {
      username: SUB_USER, userpassword: SUB_PASS, mail: "soak@example.com",
      sn: "Soak", givenName: "Soak", cn: "Soak Realm User",
    },
  });
  if (!user.ok() && user.status() !== 409) {
    throw new Error(`sub-realm user create failed: ${user.status()} ${await user.text()}`);
  }
}

test.beforeAll(async ({ request }) => {
  adminToken = await getAdminToken(request);
  await buildSubRealm(request);

  subUserToken = await authenticate(request, `/realms/root/realms/${SUB_REALM}`, SUB_USER, SUB_PASS);
  expect(subUserToken, "the sub-realm user must authenticate IN the sub-realm").toBeTruthy();
  rootUserToken = await authenticate(request, "/realms/root", "demo", "changeit");

  // Minted through `?realm=`, the one spelling row 3 shows still works. Deliberately NOT through a path
  // spelling: every later row would then fail in setup rather than in its own assertion.
  const token = await request.post(`${OAUTH2}/access_token?realm=${SUB_REALM}`, {
    headers: { Authorization: basicAuth(CLIENT_ID, CLIENT_SECRET) },
    form: { grant_type: "client_credentials", scope: SCOPE },
  });
  expect(token.status(), `sub-realm client_credentials: ${await token.text()}`).toBe(200);
  subRealmToken = (await token.json()).access_token;
});

test.afterAll(async ({ request }) => {
  // Best effort. A leaked realm makes the next run's create a 409, which is tolerated above, but a
  // long-lived container should not accumulate them.
  const deleted = await request.delete(`${REALMS_URL}/${SUB_REALM_ID}`, {
    headers: { iPlanetDirectoryPro: adminToken, "Accept-API-Version": "protocol=1.0,resource=1.0" },
  });
  console.log(`[realms] realm ${SUB_REALM} teardown -> ${deleted.status()}`);
});

test.describe("/oauth2 in a non-root realm", () => {

  test("row 1: discovery answers on all four spellings and advertises the NESTED form", async ({ request }) => {
    for (const [label, url] of SPELLINGS) {
      const response = await request.get(url("/.well-known/openid-configuration"));
      const config = await response.json();
      console.log(`[realms] row1 discovery ${label} -> ${response.status()} issuer=${config.issuer}`);
      expect(response.status(), label).toBe(200);

      // The realm's own provider answered -- the root one would name the root issuer. This is what proves
      // the realm reached the ENDPOINT and not merely the router.
      const canonical = `${OAUTH2}/realms/root/realms/${SUB_REALM}`;
      expect(config.issuer, label).toBe(canonical);
      // ⚠ Every advertised endpoint is the NESTED spelling, whichever spelling was used to ask -- so a
      // conformant OIDC client that discovers this realm will use path spelling 1 for everything, including
      // `token_endpoint`. That is precisely the spelling row 3 shows is broken, which is what turns row 3
      // from a curiosity into a deployment-breaking regression.
      expect(config.authorization_endpoint, label).toBe(`${canonical}/authorize`);
      expect(config.token_endpoint, label).toBe(`${canonical}/access_token`);
      expect(config.userinfo_endpoint, label).toBe(`${canonical}/userinfo`);
      expect(config.jwks_uri, label).toBe(`${canonical}/connect/jwk_uri`);
      // The realm's own supported scopes, not root's -- root's provider carries uma_* as well.
      expect(config.scopes_supported, label).toEqual(expect.arrayContaining(["openid", SCOPE]));
    }
  });

  test("row 2: /access_token client_credentials works through ?realm=", async ({ request }) => {
    const response = await request.post(`${OAUTH2}/access_token?realm=${SUB_REALM}`, {
      headers: { Authorization: basicAuth(CLIENT_ID, CLIENT_SECRET) },
      form: { grant_type: "client_credentials", scope: SCOPE },
    });
    const body = await response.json();
    console.log(`[realms] row2 ?realm= client_credentials -> ${response.status()}`);

    expect(response.status()).toBe(200);
    expect(body.access_token).toBeTruthy();
    expect(body.scope).toBe(SCOPE);
    // The token endpoint's cache contract holds in a sub-realm too.
    expect(response.headers()["cache-control"]).toBe("no-store");
    // A leading slash in the override value is optional -- the same rule 5-E5 row 1 recorded for root.
    const withSlash = await request.post(`${OAUTH2}/access_token?realm=/${SUB_REALM}`, {
      headers: { Authorization: basicAuth(CLIENT_ID, CLIENT_SECRET) },
      form: { grant_type: "client_credentials", scope: SCOPE },
    });
    expect(withSlash.status()).toBe(200);
  });

  test("row 3: /access_token authenticates a confidential client on the PATH spellings", async ({ request }) => {
    // ⚠ This row was RED at the 5d-1c flip and is the regression guard for the fix. Measured A/B: Restlet
    // issued a token on all three path spellings, CHF answered 401 invalid_client on all three, while
    // `?realm=` (row 2) kept working. That asymmetry was the whole diagnosis -- the realm reached the CLIENT
    // LOOKUP (the client is found, and `WWW-Authenticate` even names `Basic realm="/<sub>"`) but not the
    // client AUTHENTICATION.
    //
    // Cause: `AMLoginContext.processIndexType` cross-checks the AuthContext realm against
    // `AuthClientUtils.getDomainNameByRequest`, which reads the realm off the SERVLET request attribute
    // first, then the query string, and only then falls back to the host name. Restlet's realm router wrote
    // that attribute for every request it routed (`RestletRealmRouter:97`); CHF's realm layer publishes the
    // realm on `RealmContext` instead, so a path-spelled realm fell through to the host's realm -- root --
    // and the mismatch threw AUTH_ERROR. Fixed by `ClientAuthenticator.authenticate` setting
    // `ISAuthConstants.REALM_PARAM` to the realm it built the AuthContext with, which is the same value the
    // Restlet router used to write. Row 10 pins the resource-owner half of the same fault.

    for (const [label, url] of PATH_SPELLINGS) {
      const response = await request.post(url("/access_token"), {
        headers: { Authorization: basicAuth(CLIENT_ID, CLIENT_SECRET) },
        form: { grant_type: "client_credentials", scope: SCOPE },
      });
      const text = await response.text();
      console.log(`[realms] row3 ${label} client_credentials -> ${response.status()} ${text}`
        + ` www-authenticate=${response.headers()["www-authenticate"]}`);
      expect(response.status(), `${label}: ${text}`).toBe(200);
      expect(JSON.parse(text).access_token, label).toBeTruthy();
    }
  });

  test("row 4: /tokeninfo resolves a sub-realm token on every spelling, and at root too", async ({ request }) => {
    for (const [label, url] of SPELLINGS) {
      const response = await request.get(url("/tokeninfo", `?access_token=${subRealmToken}`));
      const body = await response.json();
      console.log(`[realms] row4 tokeninfo ${label} -> ${response.status()} realm=${body.realm}`);
      expect(response.status(), label).toBe(200);
      // The answer names the realm the TOKEN belongs to.
      expect(body.realm, label).toBe(`/${SUB_REALM}`);
      expect(body.client_id, label).toBe(CLIENT_ID);
      expect(body.scope, label).toEqual([SCOPE]);
      expect(response.headers()["cache-control"], label).toBe("no-cache, no-store");
    }

    // ⚠ /tokeninfo is NOT realm-scoped: the ROOT endpoint resolves a token issued in the sub-realm and
    // reports its realm rather than refusing it. Measured on BOTH stacks (2026-08-06) -- Restlet does exactly
    // the same -- so this is parity, not a flip regression, and it is asserted here so a future change that
    // adds realm scoping is a deliberate one. It also explains 5-E5 row 3, where a ROOT-realm token resolved
    // under a sub-realm prefix.
    const atRoot = await request.get(`${OAUTH2}/tokeninfo?access_token=${subRealmToken}`);
    const rootBody = await atRoot.json();
    console.log(`[realms] row4 tokeninfo at ROOT for a sub-realm token -> ${atRoot.status()} realm=${rootBody.realm}`);
    expect(atRoot.status()).toBe(200);
    expect(rootBody.realm).toBe(`/${SUB_REALM}`);
  });

  test("row 5: an unauthenticated /authorize redirects to the SUB-REALM login", async ({ request }) => {
    const anonCtx = await apiRequest.newContext();
    try {
      for (const [label, url] of SPELLINGS) {
        const target = url("/authorize", `?${authorizeQuery()}`);
        const response = await anonCtx.get(target, { maxRedirects: 0 });
        const location = response.headers()["location"];
        console.log(`[realms] row5 authorize anon ${label} -> ${response.status()} ${location}`);

        // 301, not 302 -- the same answer 5-E2 row 1 pinned for root.
        expect(response.status(), label).toBe(301);
        const loginUrl = new URL(location);
        // The realm reached the LOGIN redirect, which is what a sub-realm deployment depends on: land the
        // user on the right realm's login page or the whole flow authenticates the wrong directory.
        expect(loginUrl.searchParams.get("realm"), label).toBe(`/${SUB_REALM}`);
        // goto is the request URL in the SPELLING it was made with -- CHF does not canonicalise it, so a
        // legacy-prefix deployment keeps working across the login bounce.
        // ⚠ 5d-1c divergence row 24: the redirect_uri NESTED inside goto is now SINGLY encoded, because CHF
        // rebuilds the request URI from the decoded query. Restlet handed back the raw query it received, so
        // the same value was doubly encoded on the wire. Measured on both stacks with this very fixture.
        expect(loginUrl.searchParams.get("goto"), label)
          .toBe(target.replace(encodeURIComponent(REDIRECT_URI), REDIRECT_URI));
        expect(response.headers()["cache-control"], label).toBe("no-store");
      }
    } finally {
      await anonCtx.dispose();
    }
  });

  test("row 6: /authorize issues a code on every spelling for a SUB-REALM session", async () => {
    // /oauth2/authorize authenticates by COOKIE, never by header. The jar carries the sub-realm session only.
    const subCtx = await sessionContext(apiRequest, subUserToken);
    try {
      const codes = new Set();
      for (const [label, url] of SPELLINGS) {
        const response = await subCtx.get(url("/authorize", `?${authorizeQuery()}`), { maxRedirects: 0 });
        const location = new URL(response.headers()["location"]);
        console.log(`[realms] row6 authorize ${label} -> ${response.status()} ${location}`);

        expect(response.status(), label).toBe(302);
        expect(location.origin + location.pathname, label).toBe(REDIRECT_URI);
        const code = location.searchParams.get("code");
        expect(code, label).toBeTruthy();
        codes.add(code);
        expect(location.searchParams.get("state"), label).toBe("realmrow");
        expect(location.searchParams.get("client_id"), label).toBe(CLIENT_ID);
        // `iss` is the realm's canonical NESTED issuer whichever spelling was used -- the same value row 1's
        // discovery document advertises, which is what an RP validates it against.
        expect(location.searchParams.get("iss"), label)
          .toBe(`${OAUTH2}/realms/root/realms/${SUB_REALM}`);
      }
      // Four distinct codes: no cross-request reuse of an authorization code.
      expect(codes.size).toBe(SPELLINGS.length);
    } finally {
      await subCtx.dispose();
    }
  });

  test("row 7: a ROOT session does NOT authorize into the sub-realm", async () => {
    // Realm isolation, the security half of risk #9. The demo user exists in root and not here, so the
    // sub-realm authorize must send the browser to log in rather than mint a code for a foreign identity.
    const rootCtx = await sessionContext(apiRequest, rootUserToken);
    try {
      for (const [label, url] of SPELLINGS) {
        const response = await rootCtx.get(url("/authorize", `?${authorizeQuery()}`), { maxRedirects: 0 });
        console.log(`[realms] row7 root session on ${label} -> ${response.status()}`);
        expect(response.status(), label).toBe(301);
        expect(new URL(response.headers()["location"]).searchParams.get("realm"), label)
          .toBe(`/${SUB_REALM}`);
      }
    } finally {
      await rootCtx.dispose();
    }
  });

  test("row 8: the realm failures of divergence rows 15-17, in a sub-realm context", async () => {
    // ⚠ Row 15 extension, MEASURED: a nested unknown realm names the identifier WITH a leading slash, where
    // the flat spelling names it bare. plan.md row 15 records only the bare form (`Realm "bogus" not found`),
    // because 5-E5 only ever asked the flat question. Restlet answered
    // `No mapping organization found for organization identifier: /nosuchsub` for BOTH -- so the leading
    // slash is not new, only the sentence around it is. Shape-only, both stacks 404.
    const nested = await raw(rawPath(`/realms/root/realms/nosuchsub/tokeninfo?access_token=x`));
    console.log(`[realms] row8 nested unknown realm -> ${nested.status} ${nested.text}`);
    expect(nested.status).toBe(404);
    expect(JSON.parse(nested.text))
      .toEqual({ error: "not_found", error_description: "Realm &quot;/nosuchsub&quot; not found" });

    const flat = await raw(rawPath(`/realms/nosuchsub/tokeninfo?access_token=x`));
    console.log(`[realms] row8 flat unknown realm -> ${flat.status} ${flat.text}`);
    expect(flat.status).toBe(404);
    expect(JSON.parse(flat.text))
      .toEqual({ error: "not_found", error_description: "Realm &quot;nosuchsub&quot; not found" });

    // Row 15's other half: an unrouted path BELOW a realm that does resolve. One body, from
    // OAuth2NotFoundHandler, whichever spelling named the realm. Restlet: ROUTER_404 on both.
    for (const suffix of [`/${SUB_REALM}/nosuchendpoint`, `/realms/root/realms/${SUB_REALM}/nosuchendpoint`]) {
      const unrouted = await raw(rawPath(suffix));
      console.log(`[realms] row8 unrouted ${suffix} -> ${unrouted.status} ${unrouted.text}`);
      expect(unrouted.status, suffix).toBe(404);
      expect(JSON.parse(unrouted.text), suffix)
        .toEqual({ error: "not_found", error_description: "Not Found" });
    }

    // Row 16 in a sub-realm: a bad `?realm=` is fatal wherever it appears, and it BEATS the path spelling --
    // the override replaces the path realm rather than being additive (the rule 5-E5 row 3 recorded).
    const badOverride = await raw(rawPath(`/${SUB_REALM}/tokeninfo?realm=bogus&access_token=x`));
    console.log(`[realms] row8 legacy path + bad ?realm= -> ${badOverride.status} ${badOverride.text}`);
    expect(badOverride.status).toBe(400);
    expect(JSON.parse(badOverride.text))
      .toEqual({ error: "invalid_request", error_description: "Invalid realm, bogus" });

    // A `?realm=` naming a real realm plus a non-existent CHILD -- the value is reported verbatim, slash
    // included, so the message is the caller's own string and not a re-derived one.
    const deepOverride = await raw(rawPath(`/tokeninfo?realm=${SUB_REALM}%2Fnosuch&access_token=x`));
    console.log(`[realms] row8 deep bad ?realm= -> ${deepOverride.status} ${deepOverride.text}`);
    expect(deepOverride.status).toBe(400);
    expect(JSON.parse(deepOverride.text))
      .toEqual({ error: "invalid_request", error_description: `Invalid realm, ${SUB_REALM}/nosuch` });

    // Row 17 in a sub-realm: an unknown Host is a 400 from two DIFFERENT filters, and which one answers
    // depends on the spelling -- HostnameFilter for the default route and the query override, and
    // RealmContextFilter for the /realms/... prefix, which never reaches the hostname check.
    for (const [label, path, description] of [
      ["legacy", rawPath(`/${SUB_REALM}/tokeninfo`),
        "FQDN &quot;not-a-real-host.invalid&quot; is not valid."],
      ["nested", rawPath(`/realms/root/realms/${SUB_REALM}/tokeninfo`),
        "Realm &quot;not-a-real-host.invalid&quot; not found"],
      ["query", rawPath(`/tokeninfo?realm=${SUB_REALM}`),
        "FQDN &quot;not-a-real-host.invalid&quot; is not valid."],
    ]) {
      const response = await raw(path, { hostHeader: "not-a-real-host.invalid" });
      console.log(`[realms] row8 unknown Host ${label} -> ${response.status} ${response.text}`);
      expect(response.status, label).toBe(400);
      expect(JSON.parse(response.text), label)
        .toEqual({ error: "invalid_request", error_description: description });
    }
  });

  test("row 9: a realm name in the path is matched case-INSENSITIVELY", async () => {
    // ⚠ Two different rules on one URL. The ENDPOINT segment is matched case-SENSITIVELY -- `/oauth2/Tokeninfo`
    // is a 404 (5-E5 row 13) -- but the REALM segment is not: `/oauth2/E2ERealmSoak/tokeninfo` resolves the
    // realm and reaches the endpoint, which then rejects the bogus token. Measured on BOTH stacks: Restlet
    // answers the identical `invalid_token`, so this is parity and the row exists to keep it that way.
    const response = await raw(rawPath(`/${SUB_REALM.toUpperCase()}/tokeninfo?access_token=not-a-token`));
    console.log(`[realms] row9 upper-cased realm -> ${response.status} ${response.text}`);
    expect(response.status).toBe(401);
    expect(JSON.parse(response.text).error).toBe("invalid_token");
  });

  test("row 10: the password grant authenticates a RESOURCE OWNER on every spelling", async ({ request }) => {
    // The second half of row 3's fault, and the one no measurement caught: `ResourceOwnerAuthenticator`
    // authenticates the resource owner through the same `new AuthContext(realm)` + `lc.login(..., servlet
    // request, ...)` shape as `ClientAuthenticator`, so it failed the identical realm cross-check on a
    // path-spelled realm. It is exercised only by the password grant, which no other row uses -- which is
    // why row 3 could be red while the whole rest of the suite was green.
    //
    // Both principals here live in the SUB-REALM: the client (row 3's) and the user. A pass therefore means
    // the realm survived to both AuthContext logins, not just one.
    for (const [label, url] of SPELLINGS) {
      const response = await request.post(url("/access_token"), {
        headers: { Authorization: basicAuth(CLIENT_ID, CLIENT_SECRET) },
        form: {
          grant_type: "password", username: SUB_USER, password: SUB_PASS, scope: SCOPE,
        },
      });
      const text = await response.text();
      console.log(`[realms] row10 ${label} password grant -> ${response.status()} ${text}`);
      expect(response.status(), `${label}: ${text}`).toBe(200);
      const body = JSON.parse(text);
      expect(body.access_token, label).toBeTruthy();
      expect(body.scope, label).toBe(SCOPE);
    }

    // The negative control: a WRONG password must still fail, so the row cannot pass by the cross-check
    // having been disabled rather than fixed. Measured 400 `invalid_grant`, not 401 -- a bad resource-owner
    // credential is a bad GRANT (RFC 6749 §5.2), while 401 is what a bad CLIENT credential gets (row 3).
    const wrong = await request.post(`${OAUTH2}/realms/root/realms/${SUB_REALM}/access_token`, {
      headers: { Authorization: basicAuth(CLIENT_ID, CLIENT_SECRET) },
      form: { grant_type: "password", username: SUB_USER, password: "not-the-password", scope: SCOPE },
    });
    const wrongText = await wrong.text();
    console.log(`[realms] row10 wrong password -> ${wrong.status()} ${wrongText}`);
    expect(wrong.status(), wrongText).toBe(400);
    expect(JSON.parse(wrongText).error).toBe("invalid_grant");

    // ⚠ A ROOT-realm user DOES get a token from the sub-realm's token endpoint, and that is PARITY, not a
    // hole this migration opened: measured 200 on the pre-flip Restlet image (`openam-e2e:5d1b`) and 200 on
    // CHF, same fixture, same request. The cause is the fixture, not the code -- a realm created over REST
    // has no identity store of its own, so its authentication chain reaches the same directory root uses,
    // and `demo` is a valid account there. Asserted rather than left out so that a future change to realm
    // scoping has to come here and say so deliberately.
    //
    // It is NOT the row-7 property. Row 7 is about an SSO SESSION minted in root not being honoured in the
    // sub-realm, which holds. This is a CREDENTIAL that the sub-realm's own chain accepts.
    const rootUser = await request.post(`${OAUTH2}/realms/root/realms/${SUB_REALM}/access_token`, {
      headers: { Authorization: basicAuth(CLIENT_ID, CLIENT_SECRET) },
      form: { grant_type: "password", username: "demo", password: "changeit", scope: SCOPE },
    });
    const rootText = await rootUser.text();
    console.log(`[realms] row10 root user into sub-realm -> ${rootUser.status()} ${rootText}`);
    expect(rootUser.status(), rootText).toBe(200);
    expect(JSON.parse(rootText).access_token).toBeTruthy();
  });

});

/** The authorize query, built by hand so parameter order is stable across the rows that assert `goto`. */
function authorizeQuery() {
  return [
    "response_type=code", `client_id=${CLIENT_ID}`,
    `redirect_uri=${encodeURIComponent(REDIRECT_URI)}`, `scope=${SCOPE}`, "state=realmrow",
  ].join("&");
}
