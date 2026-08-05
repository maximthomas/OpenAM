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
 * idtokeninfo. These five routes were served by Restlet when this spec was written and have been served by
 * CHF since the 5d-1c flip (docs/migration/restlet/phase-5-oauth2.md, phase-5a-2.md, phase-5b-2.md); until
 * this spec existed NONE of them had any end-to-end cover at all, so the port could have broken them silently.
 *
 * This is a MIGRATION GUARD, not a byte oracle. It asserts statuses, body fields and the redirect/HTML
 * contract -- the things the port had to preserve -- and deliberately does NOT pin exact Content-Type bytes,
 * because CHF emits `application/json;charset=UTF-8` (measured post-flip: NO space after the semicolon)
 * where Restlet emitted bare `application/json`; that known, deliberate divergence is locked separately by
 * the 5-E rows in oauth2-test.spec.mjs.
 *
 * The 5d-1c flip has happened. Everything here is now asserted against the CHF contract, and the handful of
 * rows whose value legitimately moved carry a `⚠ 5d-1c divergence:` comment naming the old Restlet value.
 * Re-run this suite unchanged from here on: anything that goes red is a regression.
 */

import { createHmac } from "node:crypto";
import { test, expect, request as apiRequest } from "@playwright/test";
import { OPENAM_BASE, getAdminToken, getAuthToken, PASSWORD, USERNAME } from "../common/openam-commons.mjs";
import {
  CLIENT_SESSION_URI, OIDC_CLIENT_SECRET, POST_LOGOUT_REDIRECT_URI, POST_LOGOUT_REDIRECT_URI_WITH_QUERY, REALM,
  REDIRECT_URI, authorizationCodeTokens, basicAuth, ensureNoSessionUriOidcClient, ensureOidcClient,
  ensureProviderConfig, sessionContext,
} from "../common/oauth2-fixtures.mjs";

/** This spec's own client -- spec files run in parallel and rewriting a shared client kills its tokens. */
const OIDC_CLIENT_ID = "test_client_oidc";
/** Same realm, no clientSessionURI: the default-configured client of 5-E3 row 6e. */
const NO_SESSION_URI_CLIENT_ID = "test_client_oidc_nosessionuri";

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
  await ensureNoSessionUriOidcClient(adminToken, request, NO_SESSION_URI_CLIENT_ID);

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

/**
 * Step 5-E3: the contract lock for /oauth2/connect/checkSession and /oauth2/connect/endSession, recorded
 * against LIVE RESTLET. Restlet stops serving /oauth2 at the 5d-1 flip, so none of this is recordable
 * afterwards -- and phase 5b-2's D5, D7 and D8 are DECIDED by what is below
 * (docs/migration/restlet/phase-5b-2.md).
 *
 * Every value here was OBSERVED FIRST and only then asserted (2026-07-28, openam-e2e:5e3 built from this
 * tree; `Server: Restlet-Framework/2.4.4` on every realm-prefixed row -- gone everywhere under /oauth2 since
 * the flip, because nothing CHF serves stamps that banner). Do not "tidy" a string: the exact bytes ARE the
 * oracle for the 5d-1 byte diff. Where an observation contradicted the plan, the comment says so rather than
 * quietly matching the code.
 *
 * POST-FLIP (5d-1c): the values below are now the CHF contract. Rows re-pinned at the flip carry a
 * `⚠ 5d-1c divergence:` comment naming what moved and what Restlet answered. Row 8's state-encoding leg moved
 * too but was pre-absorbed by an either/or written for that purpose (plan.md expected-divergences row 9, see
 * the comment there). Everything else held byte for byte, which is the whole point of having recorded it.
 *
 * Both endpoints answer errors as JSON, which is the single most load-bearing fact in 5b-2: their doCatch
 * called the 2-arg ExceptionHandler.handle. A CHF port that put them on the browser base would answer every
 * row below with an HTML page instead -- CONFIRMED post-flip: rows 6d, 7, 9 and 10 all still answer JSON, so
 * AbstractOAuth2HttpJsonEndpoint is the base that was actually wired.
 */
test.describe("OIDC session endpoints contract lock (5-E3, live Restlet)", () => {

  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");

  /** A crafted JWT. Nothing verifies the signature before the claims are read, so "sig" is enough. */
  const jwt = (claims) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}.c2ln`;

  /**
   * A crafted JWT that actually verifies. `CheckSession.isJwtValid` HMACs the id_token against the client
   * secret and a false there returns "" early (a 200), so row 6e cannot use `jwt()` -- it has to get past
   * the signature check to reach the throw. Signing it here rather than running a token flow keeps the row
   * to one request.
   */
  const signedJwt = (claims, secret) => {
    const signingInput = `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}`;
    const sig = createHmac("sha256", secret).update(signingInput).digest("base64url");
    return `${signingInput}.${sig}`;
  };

  /** A fresh session + its own id_token: every endSession row ends the session it uses. */
  async function ownSession(nonce) {
    const loginCtx = await apiRequest.newContext();
    let ssoToken;
    try {
      ssoToken = await getAuthToken(loginCtx, USERNAME, PASSWORD);
    } finally {
      await loginCtx.dispose();
    }
    const ctx = await sessionContext(apiRequest, ssoToken);
    const tokens = await authorizationCodeTokens(ctx, {
      clientId: OIDC_CLIENT_ID, clientSecret: OIDC_CLIENT_SECRET, scope: "openid", nonce,
    });
    return { ctx, tokens };
  }

  const endSession = (ctx, params) =>
    ctx.get(`${OPENAM_BASE}/oauth2/connect/endSession?${new URLSearchParams(params)}`, { maxRedirects: 0 });

  // ---------------------------------------------------------------- checkSession

  test("row 6: the bare path is the JSP and the realm-prefixed path is the CHF-rendered FTL", async ({ request }) => {
    // 5b-2 D6 keeps the JSP on the bare path and mounts CheckSessionHandler on the realm-prefixed one, so
    // proving WHICH page answers WHICH url is the whole point of this row. CONFIRMED post-flip: the exact
    // web.xml mapping of /oauth2/connect/checkSession still out-ranks /oauth2/*, so the container keeps
    // serving the JSP on the bare path while CHF renders checkSession.ftl on the realm-prefixed one --
    // exactly as D6 predicted, with no web.xml edit and no conditional routing.
    const jsp = await request.get(`${OPENAM_BASE}/oauth2/connect/checkSession`);
    const ftl = await request.get(`${OPENAM_BASE}/oauth2/realms/${REALM}/connect/checkSession`);
    const jspHtml = await jsp.text();
    const ftlHtml = await ftl.text();
    console.log(`[5-E3] row6 jsp server=${jsp.headers()["server"]} ftl server=${ftl.headers()["server"]}`);

    expect(jsp.status()).toBe(200);
    expect(ftl.status()).toBe(200);
    expect(jsp.headers()["content-type"]).toBe("text/html;charset=UTF-8");
    expect(ftl.headers()["content-type"]).toBe("text/html;charset=UTF-8");

    // Discriminator 1 -- the script src. The JSP is container-served and uses a RELATIVE path; the FTL
    // interpolates the absolute baseUrl. This one survives the flip, so it is the durable oracle --
    // CONFIRMED: post-flip the realm-prefixed body still carries the absolute baseUrl form, which only
    // checkSession.ftl produces and which the JSP cannot produce at all.
    expect(jspHtml).toContain('<script src="../../js/sha256.js">');
    expect(ftlHtml).toContain(`<script src="${OPENAM_BASE}/js/sha256.js">`);

    // The Server banner is DEAD as a discriminator. It told the two apart only while Restlet answered the
    // realm-prefixed path; CHF stamps no banner, so the header is now absent on BOTH and separates nothing.
    // Kept -- not deleted -- because "no Restlet banner anywhere under /oauth2" is the flip's single most
    // visible wire fact, and a banner reappearing on either path would mean the servlet mapping regressed.
    // The discrimination this pair used to carry is done entirely by discriminators 1 and 2, both of which
    // are BODY facts and so cannot be faked by one server answering both urls.
    expect(jsp.headers()["server"]).toBeUndefined();
    // ⚠ 5d-1c divergence: the realm-prefixed checkSession is served by CHF, which stamps no Server header at all. Restlet: "Restlet-Framework/2.4.4".
    expect(ftl.headers()["server"]).toBeUndefined();

    // Discriminator 2, and ⚠ NOT cosmetic. The JSP emits a quoted STRING, so `!validSession` is false even
    // when the session is invalid and getBrowserState() reads the cookie regardless; the FTL's `?js_string`
    // escapes without adding quotes, so it emits a bare boolean literal and the guard actually works. The
    // CHF port inherits the FTL, i.e. the CORRECT behaviour -- CONFIRMED post-flip: CheckSessionHandler
    // seeds valid_session with Boolean.toString(...) and page/checkSession.ftl still interpolates it
    // unquoted, so the realm-prefixed page keeps the bare literal while the bare path keeps the JSP's quoted
    // one. Two pages, two different renderers, one url apart -- record the difference so the 5d-1 diff on the
    // bare path (which keeps the JSP) is not mistaken for a regression.
    expect(jspHtml).toContain('var validSession = "false";');
    expect(ftlHtml).toContain("var validSession = false;");

    // finding 8: no cache headers on either page, ever. Holds under CHF too -- OAuth2HttpRouteProvider wraps
    // noCache() around /authorize and /access_token only (the two routes the Restlet OAuth2Filter covered),
    // and connect/checkSession is not one of them.
    for (const response of [jsp, ftl]) {
      expect(response.headers()["cache-control"]).toBeUndefined();
      expect(response.headers()["pragma"]).toBeUndefined();
    }
  });

  test("row 6b: checkSession answers GET and POST identically", async ({ request }) => {
    const get = await request.get(`${OPENAM_BASE}/oauth2/realms/${REALM}/connect/checkSession`);
    const post = await request.post(`${OPENAM_BASE}/oauth2/realms/${REALM}/connect/checkSession`, { form: {} });
    console.log(`[5-E3] row6b GET=${get.status()} POST=${post.status()}`);
    expect(post.status()).toBe(200);
    expect(await post.text()).toBe(await get.text());
  });

  test("row 6c: an id_token in the REFERER supplies client_uri", async ({ request }) => {
    // CheckSession.getIDToken reads id_token from the Referer query string (CheckSession.java:191-218), NOT
    // from a request parameter -- that is how the RP iframe passes it, and it is the only way to reach the
    // model's client_uri at all.
    const response = await request.get(`${OPENAM_BASE}/oauth2/realms/${REALM}/connect/checkSession`, {
      headers: { Referer: `http://rp.invalid/page?id_token=${tokens.id_token}` },
    });
    const html = await response.text();
    console.log(`[5-E3] row6c valid id_token -> ${response.status()}`);
    expect(response.status()).toBe(200);
    // The registered clientSessionURI reaches the page as the postMessage origin check.
    expect(html).toContain(`var clientURI = "${CLIENT_SESSION_URI}";`);
  });

  test("row 6d: every unusable id_token in the Referer is a 400 server_error JSON", async ({ request }) => {
    // The three unchecked throws behind CheckSession, all client-reachable, all landing on the same wire
    // shape via the 2-arg ExceptionHandler -> ServerException (400 "server_error"). 5b-2 D7 wraps these at
    // source so the CHF port reproduces the 400 rather than letting CHF answer 500. CONFIRMED post-flip, but
    // only after a fix: the first post-flip run answered `unknown aud` with a 500, because that leg raises an
    // UnsupportedOperationException (the store's InvalidClientException asks the realm-only
    // OAuth2Request.forRealm for its Authorization header) and CheckSessionHandler's typed catch listed only
    // NullPointerException and NoSuchElementException. That was a genuine port DEFECT, not a licensed
    // divergence, and it was fixed in the handler rather than by relaxing anything here -- so all three cases
    // below still answer the recorded Restlet 400. Do not weaken these: a 500 on any of them is a regression.
    const cases = {
      // getClientRegistration returns null when there is no `aud`, and getClientSessionURI then dereferences
      // it unguarded (CheckSession.java:111-115) -- a genuine NPE, pinned here so the separate null-guard
      // fix has a test to change deliberately.
      "no aud claim (the CheckSession NPE)": jwt({ iss: "x", sub: "demo" }),
      "unknown aud": jwt({ aud: "no_such_client", realm: "/" }),
      "malformed jwt": "not.a-jwt",
    };
    for (const [name, idToken] of Object.entries(cases)) {
      const response = await request.get(`${OPENAM_BASE}/oauth2/realms/${REALM}/connect/checkSession`, {
        headers: { Referer: `http://rp.invalid/page?id_token=${idToken}` },
      });
      const body = await response.json();
      console.log(`[5-E3] row6d ${name} -> ${response.status()} ${JSON.stringify(body)}`);
      expect(response.status(), name).toBe(400);
      expect(response.headers()["content-type"], name).toContain("application/json");
      expect(body.error, name).toBe("server_error");
      expect(body.error_description, name)
        .toBe("Internal Server Error (500) - The server encountered an unexpected condition"
          + " which prevented it from fulfilling the request");
    }
  });

  test("row 6e: a DEFAULT-configured client 400s on checkSession's own happy path", async ({ request }) => {
    // The other way into CheckSession.java:115's single throwing exit, and the one that is not an edge case:
    // the admin API leaves clientSessionURI EMPTY on every client it creates, and
    // OpenAMClientRegistration.getClientSessionURI:426-434 ends in set.iterator().next() with no emptiness
    // guard. So a valid id_token from an ordinary client -- exactly what an RP iframe sends, and the
    // endpoint's entire reason for existing -- is a NoSuchElementException today. Row 6c only gets a 200
    // because ensureOidcClient sets the attribute explicitly.
    //
    // 5b-2 D7's wrap already covers this (same call as row 6d), so this row does NOT guard the port -- and it
    // came through the flip green, unchanged. It guards the SEPARATE null-guard fix, which could repair the
    // null-registration half and leave this one. If that fix lands, this row must be changed deliberately --
    // it is not a passive snapshot.
    const idToken = signedJwt({ aud: NO_SESSION_URI_CLIENT_ID, realm: "/", sub: "demo" }, OIDC_CLIENT_SECRET);
    const response = await request.get(`${OPENAM_BASE}/oauth2/realms/${REALM}/connect/checkSession`, {
      headers: { Referer: `http://rp.invalid/page?id_token=${idToken}` },
    });
    const body = await response.json();
    console.log(`[5-E3] row6e default client -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(400);
    // toContain, not toBe: CHF emits `application/json;charset=UTF-8` (measured post-flip -- no space after
    // the semicolon) where Restlet emitted it bare, and this file's header says it deliberately does not pin
    // those bytes.
    expect(response.headers()["content-type"]).toContain("application/json");
    expect(body.error).toBe("server_error");
  });

  test("row 7: every non-page ?display= on checkSession is a 400 (5b-2 D5)", async ({ request }) => {
    // OBSERVED, and it CORRECTED the reading that produced it: `popup` was expected to render, because
    // OAuth2Representation special-cases popup and templates/popup/authorize.ftl DOES exist. It renders that
    // template against the CHECK-SESSION model, which has no display_name, so FreeMarker throws, getText()
    // fails and the IOException becomes the same ResourceException as a missing template. touch/wap have no
    // checkSession.ftl at all. Same status, same body, three different mechanisms.
    //
    // Post-flip the three mechanisms have collapsed into one, with no change on the wire: CHF's
    // FreemarkerTemplateRenderer.renderForDisplay resolves <display>/checkSession.ftl FIRST even for popup
    // (only popup/authorize.ftl and popup/popup.ftl exist), so all three now fail identically on a missing
    // template and CheckSessionHandler answers the authored RESTLET_TEMPLATE_ERROR. Do not read the paragraph
    // above as a description of the code that serves this today -- it is the recorded Restlet mechanism, kept
    // because it is what the observation corrected.
    for (const display of ["popup", "touch", "wap"]) {
      const response = await request.get(
        `${OPENAM_BASE}/oauth2/realms/${REALM}/connect/checkSession?display=${display}`);
      const body = await response.json();
      console.log(`[5-E3] row7 display=${display} -> ${response.status()} ${JSON.stringify(body)}`);
      expect(response.status(), display).toBe(400);
      expect(response.headers()["content-type"], display).toContain("application/json");
      expect(body.error, display).toBe("server_error");
      expect(body.error_description, display)
        .toBe("Bad Request (400) - Server can not serve the content of authorization page");
    }

    // `page` is the only value that renders -- and it is also the no-display default.
    const page = await request.get(
      `${OPENAM_BASE}/oauth2/realms/${REALM}/connect/checkSession?display=page`);
    expect(page.status()).toBe(200);
    expect(page.headers()["content-type"]).toBe("text/html;charset=UTF-8");

    // An unknown value dies EARLIER, in Enum.valueOf, so it carries the generic message rather than the
    // "can not serve the content" one. D5 keeps display resolution and lets both stay 400s.
    const bogus = await request.get(
      `${OPENAM_BASE}/oauth2/realms/${REALM}/connect/checkSession?display=bogus`);
    const bogusBody = await bogus.json();
    console.log(`[5-E3] row7 display=bogus -> ${bogus.status()} ${JSON.stringify(bogusBody)}`);
    expect(bogus.status()).toBe(400);
    expect(bogusBody.error).toBe("server_error");
    expect(bogusBody.error_description)
      .toBe("Internal Server Error (500) - The server encountered an unexpected condition"
        + " which prevented it from fulfilling the request");
  });

  // ---------------------------------------------------------------- endSession

  test("row 8: a registered post_logout_redirect_uri redirects, and state goes in the QUERY", async () => {
    // Gates D8. Restlet composes with `new Reference(uri).addQueryParameter("state", v)`; the CHF port uses
    // RedirectUris.compose, so these three shapes are exactly what it has to reproduce.
    const noState = await ownSession("5e3-8a");
    try {
      const response = await endSession(noState.ctx, {
        id_token_hint: noState.tokens.id_token, post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
      });
      console.log(`[5-E3] row8 no state -> ${response.status()} ${response.headers()["location"]}`);
      expect(response.status()).toBe(302);
      // No state => the URI is emitted VERBATIM. Not even a trailing "?".
      expect(response.headers()["location"]).toBe(POST_LOGOUT_REDIRECT_URI);
    } finally {
      await noState.ctx.dispose();
    }

    const withState = await ownSession("5e3-8b");
    try {
      const response = await endSession(withState.ctx, {
        id_token_hint: withState.tokens.id_token, post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
        state: "st ate/1",
      });
      console.log(`[5-E3] row8 with state -> ${response.status()} ${response.headers()["location"]}`);
      expect(response.status()).toBe(302);
      // Space -> %20, never "+". That half IS parity and must not drift.
      expect(response.headers()["location"]).toContain("state=st%20ate");
      // ⚠ The slash is a RECORDED DIVERGENCE (plan.md expected-divergences row 9), not parity: Restlet's
      // Reference emits %2F, CHF's Form.toQueryString leaves "/" bare. Both are legal and parse identically
      // (RFC 3986 §3.4 puts "/" in the query production), and RedirectUris is shared with /authorize, so the
      // encoder is not being bent to match. Asserted as an either/or so this row stays GREEN across the flip
      // -- the file's contract is "re-run unchanged; anything red is a regression", and a row that is
      // guaranteed to go red for a known-and-accepted reason destroys that signal.
      expect([`${POST_LOGOUT_REDIRECT_URI}?state=st%20ate%2F1`,   // Restlet, recorded 2026-07-28
        `${POST_LOGOUT_REDIRECT_URI}?state=st%20ate/1`])          // CHF, after 5d-1
        .toContain(response.headers()["location"]);
    } finally {
      await withState.ctx.dispose();
    }

    const withQuery = await ownSession("5e3-8c");
    try {
      const response = await endSession(withQuery.ctx, {
        id_token_hint: withQuery.tokens.id_token,
        post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI_WITH_QUERY, state: "s2",
      });
      console.log(`[5-E3] row8 existing query -> ${response.status()} ${response.headers()["location"]}`);
      expect(response.status()).toBe(302);
      // The open question D8 asked: an existing query is preserved VERBATIM and state is APPENDED with "&".
      // No normalisation, no reordering, no re-encoding of the existing pair.
      expect(response.headers()["location"]).toBe(`${POST_LOGOUT_REDIRECT_URI_WITH_QUERY}&state=s2`);
    } finally {
      await withQuery.ctx.dispose();
    }
  });

  test("row 9: an unregistered or relative post_logout_redirect_uri is a 400 JSON", async () => {
    const mismatch = "The redirection URI provided does not match a pre-registered value.";
    const cases = [
      ["http://evil.invalid/x", "redirect_uri_mismatch", mismatch],
      // ⚠ The load-bearing case. REDIRECT_URI is registered on this client as an ordinary redirectionURI but
      // NOT as a post-logout one, so it is the single input that tells the two sets apart. validateRedirect
      // reads getPostLogoutRedirectUris() (EndSession.java:151); a CHF EndSessionHandler wired to
      // getRedirectUris() instead still rejects evil.invalid and passes every other row in this file, while
      // silently permitting logout redirects to every registered callback.
      [REDIRECT_URI, "redirect_uri_mismatch", mismatch],
      ["/relative/cb", "relative_redirect_uri", "The redirection URI provided is not absolute."],
    ];
    for (const [uri, error, description] of cases) {
      const { ctx, tokens: own } = await ownSession(`5e3-9-${error}`);
      try {
        const response = await endSession(ctx, {
          id_token_hint: own.id_token, post_logout_redirect_uri: uri,
        });
        const body = await response.json();
        console.log(`[5-E3] row9 ${uri} -> ${response.status()} ${JSON.stringify(body)}`);
        expect(response.status(), uri).toBe(400);
        expect(response.headers()["content-type"], uri).toContain("application/json");
        // JSON, not a page: proof that EndSession's doCatch is the 2-arg overload (5b-2 D1).
        expect(body.error, uri).toBe(error);
        expect(body.error_description, uri).toBe(description);
        expect(response.headers()["location"], uri).toBeUndefined();
      } finally {
        await ctx.dispose();
      }
    }
  });

  test("row 10: a malformed id_token_hint is a 400 server_error (5b-2 D7)", async ({ request }) => {
    // JwtReconstruction throws UNCHECKED, so this never reached the OAuth2Exception catch -- it landed in
    // Restlet's doCatch, which wrapped it as ServerException: status 400, error "server_error". D7 reproduces
    // the 400 at source rather than letting CHF's default 500 stand, and this row is why that is parity and
    // not a re-litigation of decisions.md D3: the path is reachable by any client, so it is contract, not a
    // bug. CONFIRMED post-flip: both cases below came through the flip green and unchanged, so
    // EndSessionHandler's typed wrap covers the same two throws Restlet's doCatch swallowed.
    // Reached only when a post_logout_redirect_uri is present -- without one the endpoint returns before
    // validateRedirect ever reconstructs the JWT, which is the second case below.
    const response = await request.get(`${OPENAM_BASE}/oauth2/connect/endSession?${new URLSearchParams({
      id_token_hint: "not.a-jwt", post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
    })}`, { maxRedirects: 0 });
    const body = await response.json();
    console.log(`[5-E3] row10 malformed hint -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(400);
    expect(response.headers()["content-type"]).toContain("application/json");
    expect(body.error).toBe("server_error");
    expect(body.error_description)
      .toBe("Internal Server Error (500) - The server encountered an unexpected condition"
        + " which prevented it from fulfilling the request");

    // A URI that URI.create cannot parse dies the same way -- an unchecked IllegalArgumentException.
    const garbage = await request.get(`${OPENAM_BASE}/oauth2/connect/endSession?${new URLSearchParams({
      id_token_hint: "not.a-jwt", post_logout_redirect_uri: "ht tp://%%%",
    })}`, { maxRedirects: 0 });
    console.log(`[5-E3] row10 garbage uri -> ${garbage.status()} ${JSON.stringify(await garbage.json())}`);
    expect(garbage.status()).toBe(400);
    expect((await garbage.json()).error).toBe("server_error");
  });

  test("row 11: PUT on either endpoint is a 405 carrying the OAuth2 method_not_allowed body", async ({ request }) => {
    // Closed 5b-2 open question 6, and the answer LIMITED D10 rather than supporting it. Neither endpoint was
    // wrapped by OAuth2Filter, so there was no validateMethod and no OAuth2-shaped 405 here: Restlet's
    // framework answered with a CREST {code, reason, message} body carrying no `error` field at all. That
    // divergence was PREDICTED to happen at the flip whatever OAuth2ErrorFilter mapped 405 to -- and it did:
    // plan.md expected-divergences row 8 names `device/user`, `connect/checkSession` and `connect/endSession`
    // explicitly and calls the exact post-flip body asserted below.
    //
    // ⚠ The shape change comes from mounting OAuth2ErrorFilter across the whole application at all
    // (phase-5-oauth2.md D5-1, the root filter in OAuth2HttpRouteProvider.get), NOT from D10 -- so it lands on
    // these two even though OAuth2Filter never wrapped them, which is exactly what row 11 predicted it would
    // do. D10 only chooses the word inside the new shape; before it the same routes would have said
    // `invalid_request` -- equally non-CREST, equally undefined by RFC 6749 for a 405. OAuth2ErrorFilter's
    // errorFor() has no route scope, deliberately, so /oauth2 speaks one error shape end to end. D10 itself
    // is still justified by /authorize and /access_token (which emitted method_not_allowed before the flip
    // too), not by these two.
    //
    // The STATUS is unchanged at 405, and neither endpoint has gained or lost a verb: what moved is the body.
    for (const path of [`/oauth2/realms/${REALM}/connect/checkSession`, "/oauth2/connect/endSession"]) {
      const response = await request.fetch(`${OPENAM_BASE}${path}`, { method: "PUT", maxRedirects: 0 });
      const body = await response.json();
      console.log(`[5-E3] row11 PUT ${path} -> ${response.status()} ${JSON.stringify(body)}`);
      expect(response.status(), path).toBe(405);
      expect(response.headers()["content-type"], path).toContain("application/json");
      // ⚠ 5d-1c divergence: the root OAuth2ErrorFilter rewrites the CREST body into the OAuth2 shape, so `error` now exists (plan.md expected-divergences row 8). Restlet: no `error` field at all, body.error was undefined.
      expect(body.error, path).toBe("method_not_allowed");
      // ⚠ 5d-1c divergence: the description is the framework's generic reason phrase, from Status.METHOD_NOT_ALLOWED.getReasonPhrase() carried over as the CREST `message` (plan.md expected-divergences row 8). Restlet: no `error_description` field at all, body.error_description was undefined.
      expect(body.error_description, path).toBe("Method Not Allowed");
      // No CREST error shape left at all -- all three of its fields are gone, which is the other half of
      // plan.md row 8 and the thing a client that parsed `code` would notice.
      // ⚠ 5d-1c divergence: `code` is consumed by the rewrite and not re-emitted. Restlet: 405.
      expect(body.code, path).toBeUndefined();
      // ⚠ 5d-1c divergence: `reason` is dropped by the rewrite. Restlet: "Method Not Allowed".
      expect(body.reason, path).toBeUndefined();
      // ⚠ 5d-1c divergence: `message` is carried over into error_description, not kept under its own key. Restlet: "The method specified in the request is not allowed for the resource identified by the request URI".
      expect(body.message, path).toBeUndefined();
      // finding 8 again, on the error path this time. Still holds: neither route is wrapped by noCache(), and
      // the 405 is produced by Endpoints/AnnotatedMethod, which set Allow and nothing else.
      expect(response.headers()["cache-control"], path).toBeUndefined();
      expect(response.headers()["pragma"], path).toBeUndefined();
    }
  });
});
