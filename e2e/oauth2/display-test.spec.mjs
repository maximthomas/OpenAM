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
 * The `?display=` surface of the two browser endpoints -- `/oauth2/authorize` and `/oauth2/device/user`.
 *
 * WHY THIS FILE EXISTS. Phase 3c-1 ported the FreeMarker renderer (`FreemarkerTemplateRenderer`,
 * `ConsentPageRenderer`) ahead of any route that used it, so
 * [risk #19](../../docs/migration/restlet/plan.md#risk-register-behavioral-compatibility) -- "build-ahead has
 * no live guard" -- records the renderer half as **open until the 5d-1 flip**, which is now. Before this file
 * the 131 e2e rows exercised exactly one display: the default. Four template folders ship
 * (`page/`, `popup/`, `touch/`, `wap/`) and three of them had no end-to-end cover at all, so a port that
 * resolved the wrong folder, lost a model key, or stopped composing the popup wrapper was invisible.
 *
 * Every value below was OBSERVED against CHF first (2026-08-06, image `openam-e2e:soak` built from this tree,
 * provenance by md5 of the deployed `openam-oauth2` jar) and only then asserted. This is a REGRESSION NET, not
 * a byte oracle: the live-Restlet producer for `/oauth2` is gone, so nothing here can be re-recorded, and a
 * row that goes red is a behaviour change to explain rather than a string to update.
 *
 * ⚠ ROW 4 ASSERTS A BUG ON PURPOSE. `templates/touch/authorize.ftl:56` emits `isplayName` where `page/` and
 * `popup/` emit `displayName`, so `?display=touch` hands the XUI a consent page with NO client name. That is a
 * PRE-EXISTING product defect reproduced verbatim by the port -- ticket T4, and
 * [plan.md](../../docs/migration/restlet/plan.md#expected-divergences-at-the-flip) says in as many words
 * "not a divergence, do not fix it during the flip", because changing it changes the wire. Row 4 pins the
 * typo so that fixing it is a deliberate act with a red test attached, not a silent one.
 */

import { test, expect, request as apiRequest } from "@playwright/test";
import { OPENAM_BASE, getAdminToken, getAuthToken, PASSWORD, USERNAME } from "../common/openam-commons.mjs";
import { REALM, REDIRECT_URI, SCOPE, ensureProviderConfig, pkce, sessionContext } from "../common/oauth2-fixtures.mjs";

/** This spec's own clients -- Playwright runs spec FILES in parallel and a shared client rewritten mid-run
 *  invalidates the other file's tokens (see the note in common/oauth2-fixtures.mjs). */
const CONSENT_CLIENT_ID = "test_client_display";
const DEVICE_CLIENT_ID = "test_client_display_device";

const OAUTH2 = `${OPENAM_BASE}/oauth2`;
/** The deployment's context path, so the form-target rows survive a deployment mounted elsewhere. */
const CONTEXT_PATH = new URL(OPENAM_BASE).pathname.replace(/\/$/, "");

let adminToken;
let demoToken;
let demoCtx;
let challenge;

const agentHeaders = () => ({
  iPlanetDirectoryPro: adminToken, "Content-Type": "application/json",
  "Accept-API-Version": "protocol=2.0,resource=1.0",
});

/**
 * Writes a consent-REQUIRING client. `isConsentImplied:false` is the whole point: the shared provider is
 * created with `clientsCanSkipConsent:true`, and `requireConsent = !clientsCanSkipConsent ||
 * !isConsentImplied()`, so this flag alone decides whether the request reaches the consent page -- which is
 * the only page `?display=` selects a template for.
 */
async function writeClient(request, clientId, extra) {
  const written = await request.put(
    `${OPENAM_BASE}/json/realms/${REALM}/realm-config/agents/OAuth2Client/${clientId}`, {
      headers: agentHeaders(),
      data: {
        "com.forgerock.openam.oauth2provider.clientType": "Public",
        "com.forgerock.openam.oauth2provider.redirectionURIs": [`[0]=${REDIRECT_URI}`],
        "com.forgerock.openam.oauth2provider.scopes": [`[0]=${SCOPE}`, "[1]=openid"],
        "com.forgerock.openam.oauth2provider.defaultScopes": [`[0]=${SCOPE}`],
        "com.forgerock.openam.oauth2provider.responseTypes": ["[0]=code", "[1]=token"],
        "com.forgerock.openam.oauth2provider.tokenEndPointAuthMethod": "none",
        isConsentImplied: false,
        sunIdentityServerDeviceStatus: "Active",
        ...extra,
      },
    });
  if (!written.ok()) {
    throw new Error(`Failed to write ${clientId}: ${written.status()} ${await written.text()}`);
  }
}

test.beforeAll(async ({ request }) => {
  adminToken = await getAdminToken(request);
  await ensureProviderConfig(adminToken, request);
  await writeClient(request, CONSENT_CLIENT_ID, {
    "com.forgerock.openam.oauth2provider.grantTypes": ["[0]=authorization_code"],
  });
  await writeClient(request, DEVICE_CLIENT_ID, {
    "com.forgerock.openam.oauth2provider.grantTypes": [
      "[0]=authorization_code", "[1]=urn:ietf:params:oauth:grant-type:device_code",
    ],
  });

  // The shared provider pins codeVerifierEnforced:true, so every response_type=code request below needs a
  // real S256 challenge or it 400s on validation long before a template is chosen.
  challenge = (await pkce()).challenge;

  const loginCtx = await apiRequest.newContext();
  try {
    demoToken = await getAuthToken(loginCtx, USERNAME, PASSWORD);
  } finally {
    await loginCtx.dispose();
  }
  // /oauth2/authorize authenticates by COOKIE, never by the iPlanetDirectoryPro header.
  demoCtx = await sessionContext(apiRequest, demoToken);
});

test.afterAll(async () => {
  await demoCtx?.dispose();
});

/** The authorize query, built by hand so the `display` value is the only thing that moves between rows. */
function authorizeQuery(display) {
  const parts = [
    "response_type=code", `client_id=${CONSENT_CLIENT_ID}`,
    `redirect_uri=${encodeURIComponent(REDIRECT_URI)}`, `scope=${SCOPE}`, "state=display",
    `code_challenge=${encodeURIComponent(challenge)}`, "code_challenge_method=S256",
  ];
  if (display !== undefined) parts.push(`display=${display}`);
  return parts.join("&");
}

/**
 * A value the templates interpolate into the `pageData` object literal, scraped out of the rendered page.
 *
 * Anchored on a preceding delimiter for the same reason `oauth2-test.spec.mjs` anchors its copy: unanchored,
 * `displayName` would also match the `isplayName` row 4 exists to tell apart, and the two rows would stop
 * distinguishing anything.
 */
function pageDataValue(html, key) {
  const match = new RegExp(`(?:^|[{,\\s])${key}:\\s*"([^"]*)"`).exec(html);
  return match && match[1];
}

/** Mints a device code that can actually reach the consent page. */
async function deviceCode(request) {
  const response = await request.post(`${OAUTH2}/device/code`, {
    form: {
      client_id: DEVICE_CLIENT_ID, scope: SCOPE, response_type: "code",
      code_challenge: challenge, code_challenge_method: "S256",
    },
  });
  if (!response.ok()) {
    throw new Error(`device/code failed: ${response.status()} ${await response.text()}`);
  }
  return (await response.json()).user_code;
}

test.describe("?display= on /oauth2/authorize", () => {

  test("row 1: display=page renders the page/ consent template", async () => {
    const response = await demoCtx.get(`${OAUTH2}/authorize?${authorizeQuery("page")}`, { maxRedirects: 0 });
    const html = await response.text();
    console.log(`[display] row1 page -> ${response.status()} ct=${response.headers()["content-type"]} bytes=${html.length}`);

    expect(response.status()).toBe(200);
    // Every display is served as text/html, WML included (row 5) -- the media type was fixed at the
    // representation and never varied by folder. FreemarkerTemplateRenderer.toHtmlResponse reproduces that.
    expect(response.headers()["content-type"]).toBe("text/html;charset=UTF-8");
    // /authorize is one of the two endpoints stamped on EVERY response, consent page included.
    expect(response.headers()["cache-control"]).toBe("no-store");
    expect(response.headers()["pragma"]).toBe("no-cache");

    expect(html.startsWith("<!DOCTYPE html>")).toBe(true);
    // The model keys the port had to carry across by ENUMERATION -- CHF has no equivalent of Restlet's two
    // bulk copies, so a name missing from ConsentPageRenderer.MODEL_KEYS makes the field silently vanish
    // (R-5b1.2). These are the ones this template reads.
    expect(pageDataValue(html, "displayName")).toBe(CONSENT_CLIENT_ID);
    expect(pageDataValue(html, "clientId")).toBe(CONSENT_CLIENT_ID);
    expect(pageDataValue(html, "userName")).toBe("Demo Demo");
    expect(pageDataValue(html, "responseType")).toBe("code");
    expect(pageDataValue(html, "redirectUri")).toBe(REDIRECT_URI);
    expect(pageDataValue(html, "scope")).toBe(SCOPE);
    expect(pageDataValue(html, "state")).toBe("display");
    expect(pageDataValue(html, "csrf")).toBeTruthy();
    // `page/authorize.ftl:59` is the ONLY template with the `<#if saveConsentEnabled>` guard, which is why
    // rows 3 and 4 assert its ABSENCE: it is the cheapest proof that a different file was rendered.
    expect(html).toContain("isSaveConsentEnabled: true");
    // The post-back target carries the display through, so a consent POST stays on the same template.
    expect(pageDataValue(html, "formTarget"))
      .toBe(`\\${CONTEXT_PATH}/oauth2/authorize?${authorizeQuery("page").replace(encodeURIComponent(REDIRECT_URI), REDIRECT_URI)}`);
  });

  test("row 2: an EMPTY display= is the page/ template, not a 400", async () => {
    // Not hypothetical: `?display=` is a reachable URL and reads back as "". The legacy path builder did
    // `display != null ? display : "page"`, so mirroring only that and then calling Enum.valueOf("") would
    // turn a rendered page into a 400. FreemarkerTemplateRenderer.renderForDisplay:211-218 treats null and ""
    // alike, and this row is what holds it there.
    const response = await demoCtx.get(`${OAUTH2}/authorize?${authorizeQuery("")}`, { maxRedirects: 0 });
    const html = await response.text();
    console.log(`[display] row2 display= (empty) -> ${response.status()} bytes=${html.length}`);

    expect(response.status()).toBe(200);
    expect(html.startsWith("<!DOCTYPE html>")).toBe(true);
    expect(pageDataValue(html, "displayName")).toBe(CONSENT_CLIENT_ID);
    expect(html).toContain("isSaveConsentEnabled: true");
  });

  test("row 3: display=popup composes the wrapper AROUND the consent page", async () => {
    const response = await demoCtx.get(`${OAUTH2}/authorize?${authorizeQuery("popup")}`, { maxRedirects: 0 });
    const html = await response.text();
    console.log(`[display] row3 popup -> ${response.status()} bytes=${html.length}`);

    expect(response.status()).toBe(200);
    expect(response.headers()["content-type"]).toBe("text/html;charset=UTF-8");
    // popup.ftl's own doctype is LOWERCASE where every other template's is uppercase -- the cheapest possible
    // discriminator for "the wrapper was rendered, not the bare page".
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).toContain("<title>Authorize popup</title>");
    expect(html).toContain("function poponload()");
    // The composition itself: popup.ftl interpolates the already-rendered consent page into htmlCode, and
    // does it UNESCAPED, so the inner page's own pageData is readable here. If the wrapper were rendered
    // without its embedded page -- the failure mode when the two-step render in renderForDisplay:220-229
    // breaks -- this div would be empty and the two assertions below are what would catch it.
    expect(html).toContain('<div id="print" style="visibility: hidden">');
    expect(pageDataValue(html, "displayName")).toBe(CONSENT_CLIENT_ID);
    expect(pageDataValue(html, "clientId")).toBe(CONSENT_CLIENT_ID);
    // popup/authorize.ftl has no `saveConsentEnabled` guard, so the embedded page is popup/'s and not page/'s.
    expect(html).not.toContain("isSaveConsentEnabled");
  });

  test("row 4: display=touch renders a BLANK client name -- the isplayName typo, T4", async () => {
    const response = await demoCtx.get(`${OAUTH2}/authorize?${authorizeQuery("touch")}`, { maxRedirects: 0 });
    const html = await response.text();
    console.log(`[display] row4 touch -> ${response.status()} bytes=${html.length}`
      + ` isplayName=${JSON.stringify(pageDataValue(html, "isplayName"))}`
      + ` displayName=${JSON.stringify(pageDataValue(html, "displayName"))}`);

    expect(response.status()).toBe(200);
    expect(response.headers()["content-type"]).toBe("text/html;charset=UTF-8");

    // ⚠ THE BUG, ASSERTED. templates/touch/authorize.ftl:56 writes the value into `isplayName`, so the key
    // the XUI reads -- `displayName` -- is simply not on the page and the consent <h1> renders empty. The
    // model itself is fine: the value IS there, under the wrong key, which is what these two lines separate.
    // Fixing the template is a deliberate change that must also change this row; it is NOT part of the
    // migration (plan.md, "Not a divergence, do not fix it during the flip").
    expect(pageDataValue(html, "isplayName")).toBe(CONSENT_CLIENT_ID);
    expect(pageDataValue(html, "displayName")).toBeNull();

    // Everything else on the touch page is intact, which is what makes the missing name a template typo
    // rather than a broken data model.
    expect(pageDataValue(html, "clientId")).toBe(CONSENT_CLIENT_ID);
    expect(pageDataValue(html, "userName")).toBe("Demo Demo");
    expect(pageDataValue(html, "csrf")).toBeTruthy();
    expect(html).not.toContain("isSaveConsentEnabled");
  });

  test("row 5: display=wap is WML served as text/html, and DOES render the client name", async () => {
    const response = await demoCtx.get(`${OAUTH2}/authorize?${authorizeQuery("wap")}`, { maxRedirects: 0 });
    const html = await response.text();
    console.log(`[display] row5 wap -> ${response.status()} ct=${response.headers()["content-type"]} bytes=${html.length}`);

    expect(response.status()).toBe(200);
    // ⚠ Measured, and deliberately NOT corrected by the port: a WML document goes out as text/html. The
    // legacy representation fixed the media type once and never varied it by display
    // (FreemarkerTemplateRenderer.toHtmlResponse's javadoc says so and cites this template).
    expect(response.headers()["content-type"]).toBe("text/html;charset=UTF-8");
    expect(html.startsWith('<?xml version="1.0"?>')).toBe(true);
    expect(html).toContain('<!DOCTYPE wml PUBLIC "-//WAPFORUM//DTD WML 1.2//EN"');
    expect(html).toContain("<wml>");
    // No pageData at all -- wap/ is the one template that renders server-side instead of handing a model to
    // the XUI, so it is also the one that proves the model reaches the TEMPLATE and not just the browser.
    expect(html).not.toContain("pageData");
    expect(html).toContain(`<p>${CONSENT_CLIENT_ID}:</p>`);
    // `display_scope` -- the RAW, unencoded scope-description list this template alone reads. It is written
    // AFTER the query overlay in ConsentPageRenderer.addDisplayScopesAndClaims specifically so a client
    // cannot supply its own (CVE-2026-62280); if that ordering were ever reversed, this is the page it would
    // show up on.
    expect(html).toContain(`<b>${SCOPE}</b>`);
    // A real HTML form with the CSRF token and the two decision buttons, posted back to the same URL.
    expect(html).toContain(`<form action="${CONTEXT_PATH}/oauth2/authorize?`);
    expect(html).toMatch(/<input type="hidden" name="csrf" value="[^"]+"\/>/);
    expect(html).toContain('<input type="submit" name="decision" class="button gray" value="Allow"/>');
  });

  test("row 6: an UNKNOWN display is a non-redirecting 400 invalid_request page (D7)", async () => {
    const response = await demoCtx.get(`${OAUTH2}/authorize?${authorizeQuery("bogus")}`, { maxRedirects: 0 });
    const html = await response.text();
    console.log(`[display] row6 bogus -> ${response.status()} bytes=${html.length} location=${response.headers()["location"]}`);

    // D7's unified answer. The direction that matters is that it does NOT redirect: this request failed
    // parameter validation, so its redirect_uri was never checked against the client's registered set, and
    // bouncing to it would be an open redirect. Restlet's GET DID redirect to the raw redirect_uri here
    // (divergence row 1) -- closing that is the whole point of D7.
    expect(response.status()).toBe(400);
    expect(response.headers()["location"]).toBeUndefined();
    expect(response.headers()["content-type"]).toBe("text/html;charset=UTF-8");
    expect(html).toContain("<title>OAuth2 Error Page</title>");
    expect(html).toContain('message: "invalid_request"');
    // The description is the IllegalArgumentException's own -- Enum.valueOf's message, class name included.
    // ⚠ Asserted rather than masked ON PURPOSE: the 5d-1c parity fix that masks unauthored `server_error`
    // descriptions deliberately leaves D7's `invalid_request` untouched (phase-5d-1-asbuilt.md, fix 1), so a
    // future widening of that mask to every error would show up here rather than silently.
    expect(html).toContain("No enum constant org.forgerock.openam.oauth2.OAuth2Constants.DisplayType.BOGUS");
  });

  test("row 7: the display name is case-INSENSITIVE, unlike route matching", async () => {
    // renderForDisplay:217 upper-cases before Enum.valueOf, so PAGE/page and TOUCH/touch are the same folder.
    // Worth a row because /oauth2 ROUTE matching is case-SENSITIVE (5-E5 row 13) -- two different rules on
    // one URL, and only one of them is the router's.
    const upperPage = await demoCtx.get(`${OAUTH2}/authorize?${authorizeQuery("PAGE")}`, { maxRedirects: 0 });
    const upperPageHtml = await upperPage.text();
    const upperTouch = await demoCtx.get(`${OAUTH2}/authorize?${authorizeQuery("TOUCH")}`, { maxRedirects: 0 });
    const upperTouchHtml = await upperTouch.text();
    console.log(`[display] row7 PAGE -> ${upperPage.status()} TOUCH -> ${upperTouch.status()}`);

    expect(upperPage.status()).toBe(200);
    expect(upperPageHtml).toContain("isSaveConsentEnabled: true");
    expect(pageDataValue(upperPageHtml, "displayName")).toBe(CONSENT_CLIENT_ID);

    expect(upperTouch.status()).toBe(200);
    expect(pageDataValue(upperTouchHtml, "isplayName")).toBe(CONSENT_CLIENT_ID);
    expect(pageDataValue(upperTouchHtml, "displayName")).toBeNull();
  });

  test("row 8: display is validated AFTER authentication, not before", async () => {
    // An unauthenticated request with an unknown display gets the login 301, not row 6's 400 -- the session
    // check runs first and short-circuits. Recorded because it fixes the ORDER of two independent guards:
    // were the display parsed first, an anonymous caller could probe DisplayType by status code, and the
    // 400's body names an internal enum (row 6).
    const anonCtx = await apiRequest.newContext();
    try {
      const response = await anonCtx.get(`${OAUTH2}/authorize?${authorizeQuery("bogus")}`, { maxRedirects: 0 });
      console.log(`[display] row8 anon+bogus -> ${response.status()} location=${response.headers()["location"]}`);
      expect(response.status()).toBe(301);
      expect(response.headers()["location"]).toContain(`${OPENAM_BASE}/UI/Login?realm=%2F&goto=`);
      // The unknown display survives into goto, so the 400 happens after the user comes back.
      expect(response.headers()["location"]).toContain("display%3Dbogus");
    } finally {
      await anonCtx.dispose();
    }
  });

});

test.describe("?display= on /oauth2/device/user", () => {

  test("row 9: the device CONSENT page honours every display, exactly as /authorize does", async ({ request }) => {
    // The device flow reaches the same ConsentPageRenderer -- by COMPOSITION on CHF, where Restlet shared it
    // by inheritance (DeviceCodeVerificationResource extends ConsentRequiredResource). That re-plumbing is
    // what this row guards: a device consent page rendered from the wrong folder, or with the model the
    // /authorize path builds instead of the device one, would show up here and nowhere else.
    //
    // The post-back target is asserted per template rather than once: it reaches the page through
    // `pageData.formTarget` on the three XUI templates and through the WML `<form action=…>` on wap, which is
    // the same value by two routes. It matters on the device flow more than on /authorize -- D2: the device
    // consent POST carries NO query at all, so every model key here comes from the request ATTRIBUTES the
    // handler seeds from the device-code record, and the target is what carries user_code back.
    for (const [display, assertions] of [
      ["page", (html, target) => {
        expect(html.startsWith("<!DOCTYPE html>")).toBe(true);
        expect(pageDataValue(html, "displayName")).toBe(DEVICE_CLIENT_ID);
        expect(html).toContain("isSaveConsentEnabled: true");
        expect(pageDataValue(html, "formTarget")).toBe(`\\${target}`);
      }],
      ["popup", (html, target) => {
        expect(html.startsWith("<!doctype html>")).toBe(true);
        expect(html).toContain("<title>Authorize popup</title>");
        expect(pageDataValue(html, "displayName")).toBe(DEVICE_CLIENT_ID);
        expect(pageDataValue(html, "formTarget")).toBe(`\\${target}`);
      }],
      // The same T4 typo, on the second endpoint that renders the touch template.
      ["touch", (html, target) => {
        expect(pageDataValue(html, "isplayName")).toBe(DEVICE_CLIENT_ID);
        expect(pageDataValue(html, "displayName")).toBeNull();
        expect(pageDataValue(html, "formTarget")).toBe(`\\${target}`);
      }],
      // wap renders server-side and so has no pageData at all -- the target is the form's own action, and
      // the `&` is HTML-escaped because this template escapes at the template layer.
      ["wap", (html, target) => {
        expect(html.startsWith('<?xml version="1.0"?>')).toBe(true);
        expect(html).toContain(`<p>${DEVICE_CLIENT_ID}:</p>`);
        expect(pageDataValue(html, "formTarget")).toBeNull();
        expect(html).toContain(`<form action="${target.replace(/&/g, "&amp;")}" method="post">`);
      }],
    ]) {
      const userCode = await deviceCode(request);
      const response = await demoCtx.get(`${OAUTH2}/device/user?user_code=${userCode}&display=${display}`,
        { maxRedirects: 0 });
      const html = await response.text();
      console.log(`[display] row9 device/user display=${display} -> ${response.status()}`
        + ` ct=${response.headers()["content-type"]} bytes=${html.length}`);
      expect(response.status(), display).toBe(200);
      expect(response.headers()["content-type"], display).toBe("text/html;charset=UTF-8");
      assertions(html, `${CONTEXT_PATH}/oauth2/device/user?user_code=${userCode}&display=${display}`);
    }
  });

  test("row 10: an unknown display on the device CONSENT page is a 400, as on /authorize", async ({ request }) => {
    const userCode = await deviceCode(request);
    const response = await demoCtx.get(`${OAUTH2}/device/user?user_code=${userCode}&display=bogus`,
      { maxRedirects: 0 });
    const html = await response.text();
    console.log(`[display] row10 device/user bogus -> ${response.status()} location=${response.headers()["location"]}`);

    // D7 lives on AbstractOAuth2HttpBrowserEndpoint, so it applies to every browser endpoint the migration
    // ports and not to /authorize alone (divergence row 1's "the generalisation is structural"). This row is
    // that claim, measured on the second endpoint.
    expect(response.status()).toBe(400);
    expect(response.headers()["location"]).toBeUndefined();
    expect(html).toContain('message: "invalid_request"');
    expect(html).toContain("No enum constant org.forgerock.openam.oauth2.OAuth2Constants.DisplayType.BOGUS");
  });

  test("row 11: the device CODE-ENTRY page ignores display entirely -- including a bogus one (D4)", async () => {
    // The counter-example that makes rows 9 and 10 mean something. `DeviceCodeVerificationHandler` resolves
    // `templates/CodeVerificationForm.ftl` LITERALLY, with no display folder, because :223-224 asked the
    // legacy template factory for that path verbatim and `templates/popup/CodeVerificationForm.ftl` does not
    // exist to be found. So on this page `?display=` is never parsed -- and an unknown one is therefore a
    // 200, where the consent page one URL later is a 400.
    const rendered = [];
    for (const display of ["page", "popup", "touch", "wap", "bogus"]) {
      const response = await demoCtx.get(`${OAUTH2}/device/user?display=${display}`, { maxRedirects: 0 });
      const html = await response.text();
      console.log(`[display] row11 device form display=${display} -> ${response.status()} bytes=${html.length}`);
      expect(response.status(), display).toBe(200);
      // CodeVerificationForm.ftl is an XUI shell: it carries no form of its own, only the model the
      // `main-device` bundle renders the code box from. Asserting that bundle name is what distinguishes
      // this page from the consent page and from the thanks page, which load different ones.
      expect(html, display).toContain("XUI/main-device");
      expect(html, display).toContain("<title>OAuth2 Authorization Server</title>");
      rendered.push(html);
    }
    // Byte-identical across all five, which is the strongest available statement of "the folder was not
    // consulted". A future change that routes this page through the display scheme reddens exactly here.
    for (const html of rendered) {
      expect(html).toBe(rendered[0]);
    }
  });

});
