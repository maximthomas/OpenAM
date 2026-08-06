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
 * Criterion 17's load / concurrency probe: minutes of concurrent `/oauth2/access_token` and
 * `/oauth2/authorize` against one container.
 *
 *   node e2e/tools/oauth2-load.mjs --seconds 180 --concurrency 12
 *
 * WHY A TOOL AND NOT A SPEC. Two reasons, both structural:
 *   - `playwright.config.mjs` sets `timeout: 180000` per test, and the point of this probe is to run
 *     LONGER than that. Splitting it into sub-timeout rows would defeat it: what this is looking for
 *     accumulates.
 *   - a pass/fail that depends on how much CPU the host had is a flaky row, and the suite has enough
 *     history with that already (commit 2f16a47c0d). So the exit code here keys on CORRECTNESS ONLY --
 *     a wrong answer, a leaked value, a 5xx -- never on a latency number. The latencies are reported
 *     because they are useful to a human, and asserted by nothing.
 *
 * WHAT IT IS ACTUALLY PROBING. Not throughput. Three specific things the flip could have broken and a
 * sequential suite cannot see (docs/migration/restlet/plan.md risk #1):
 *
 *   1. THE BUFFERED-ENTITY RE-READ. On `/oauth2/access_token` the form body is read three times over --
 *      by the audit filter, by client authentication, and by the handler. Restlet re-set the entity after
 *      `new Form(entity)`; CHF relies on the entity being re-readable. A body consumed by the first reader
 *      shows up as `invalid_client` or a missing `grant_type` -- and only reliably under concurrency, when
 *      buffers are contended. Half the token load therefore uses `client_secret_post`, which puts the
 *      credentials IN the body so all three readers need it, and half uses `client_secret_basic` as the
 *      control: if only the POST half breaks, the body is the cause.
 *
 *   2. PER-REQUEST STATE SHARED BETWEEN REQUESTS. Every request carries a value unique to itself -- a
 *      `state` on `/authorize`, a distinct scope-free marker on the token calls -- and the answer must
 *      carry that same value back. A response echoing ANOTHER request's value is the signature of a
 *      collaborator that CHF holds per-application where Restlet held it per-request. This is the check
 *      that would catch it; a "no 5xx" run would not.
 *
 *   3. TOKEN UNIQUENESS. Two concurrent grants that mint the same access token would be catastrophic and
 *      silent. Every issued token is kept and the set size is compared to the issue count.
 *
 * TRIPWIRE. A CREST-shaped body -- `{"code":…,"reason":…,"message":…}` -- from `/authorize` is
 * [divergence row 7](../../docs/migration/restlet/plan.md): a hook throwing AFTER the authorization was
 * issued. No e2e row exercises it, which is exactly why the soak watches for it. Seeing one is reported in
 * full and fails the run.
 *
 * Fixtures come from `../common/oauth2-fixtures.mjs` unchanged, so this probe cannot drift from what the
 * specs exercise. It creates two clients of its own (`load_probe_*`) so it never disturbs a spec's state.
 */

import { OPENAM_BASE, USERNAME, PASSWORD, getAdminToken, getAuthToken } from "../common/openam-commons.mjs";
import { REALM, REDIRECT_URI, SCOPE, basicAuth, ensureProviderConfig, pkce } from "../common/oauth2-fixtures.mjs";

const OAUTH2 = `${OPENAM_BASE}/oauth2`;

/* Distinct from every spec's client id: a spec rewriting a client invalidates tokens issued against it,
 * and this probe is designed to be runnable while nothing else is. */
/* TWO token clients, differing ONLY in tokenEndPointAuthMethod. OpenAM enforces the configured method --
 * a client_secret_basic client answers `Invalid authentication method for accessing this endpoint.` to body
 * credentials -- so the body-reading half of probe 1 needs a client that actually accepts them. */
const TOKEN_CLIENT_POST = "load_probe_token_post";
const TOKEN_CLIENT_BASIC = "load_probe_token_basic";
const AUTHZ_CLIENT = "load_probe_authz";
/* >=256 bits: OpenAM signs id_tokens HS256 with the client secret and a short one fails opaquely. */
const SECRET = "load-probe-secret-0123456789-0123456789-0123456789";

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 && process.argv[i + 1] !== undefined ? Number(process.argv[i + 1]) : fallback;
}
const SECONDS = arg("seconds", 180);
const CONCURRENCY = arg("concurrency", 12);

const adminHeaders = (token, version) => ({
  iPlanetDirectoryPro: token, "Content-Type": "application/json", "Accept-API-Version": version,
});

async function ensureClient(adminToken, clientId, extra) {
  const response = await fetch(
    `${OPENAM_BASE}/json/realms/${REALM}/realm-config/agents/OAuth2Client/${clientId}`, {
      method: "PUT",
      headers: adminHeaders(adminToken, "protocol=2.0,resource=1.0"),
      body: JSON.stringify({
        userpassword: SECRET,
        "com.forgerock.openam.oauth2provider.clientType": "Confidential",
        "com.forgerock.openam.oauth2provider.redirectionURIs": [`[0]=${REDIRECT_URI}`],
        "com.forgerock.openam.oauth2provider.scopes": [`[0]=${SCOPE}`, "[1]=openid"],
        "com.forgerock.openam.oauth2provider.defaultScopes": [`[0]=${SCOPE}`],
        "com.forgerock.openam.oauth2provider.responseTypes": ["[0]=code", "[1]=token"],
        isConsentImplied: true,
        sunIdentityServerDeviceStatus: "Active",
        ...extra,
      }),
    });
  if (!response.ok) {
    throw new Error(`client ${clientId} write failed: ${response.status} ${await response.text()}`);
  }
}

/*
 * The shared fixtures speak Playwright's `APIRequestContext`, not `fetch`. Rather than restate them here --
 * which is the one thing that would let this probe drift from what the specs exercise -- this adapts `fetch`
 * to the four methods they call. `data` is serialised as JSON because every fixture call that carries one
 * also sets `Content-Type: application/json`, exactly as `APIRequestContext` does.
 */
function playwrightLikeContext() {
  const call = async (method, url, { headers, data } = {}) => {
    const response = await fetch(url, {
      method, headers, body: data === undefined ? undefined : JSON.stringify(data),
    });
    const text = await response.text();
    return {
      ok: () => response.ok,
      status: () => response.status,
      text: async () => text,
      json: async () => JSON.parse(text),
      headers: () => Object.fromEntries(response.headers),
    };
  };
  return {
    get: (url, options) => call("GET", url, options),
    post: (url, options) => call("POST", url, options),
    put: (url, options) => call("PUT", url, options),
    delete: (url, options) => call("DELETE", url, options),
  };
}

/** Everything a worker needs, computed once. */
async function setUp() {
  const shim = playwrightLikeContext();

  const adminToken = await getAdminToken(shim);
  if (!adminToken) throw new Error("no admin token -- is the container up?");
  await ensureProviderConfig(adminToken, shim);

  await ensureClient(adminToken, TOKEN_CLIENT_POST, {
    "com.forgerock.openam.oauth2provider.grantTypes": ["[0]=client_credentials"],
    "com.forgerock.openam.oauth2provider.tokenEndPointAuthMethod": "client_secret_post",
  });
  await ensureClient(adminToken, TOKEN_CLIENT_BASIC, {
    "com.forgerock.openam.oauth2provider.grantTypes": ["[0]=client_credentials"],
    "com.forgerock.openam.oauth2provider.tokenEndPointAuthMethod": "client_secret_basic",
  });
  await ensureClient(adminToken, AUTHZ_CLIENT, {
    "com.forgerock.openam.oauth2provider.grantTypes": ["[0]=authorization_code"],
    "com.forgerock.openam.oauth2provider.tokenEndPointAuthMethod": "client_secret_basic",
  });

  const sessionToken = await getAuthToken(shim, USERNAME, PASSWORD);
  if (!sessionToken) throw new Error("no demo session -- is the demo user created?");
  return { adminToken, sessionToken };
}

/* ------------------------------------------------------------------ the run */

const stats = new Map();
const latencies = new Map();
const issuedTokens = new Set();
let issuedCount = 0;
const anomalies = [];

function record(key, status, ms) {
  const id = `${key} ${status}`;
  stats.set(id, (stats.get(id) ?? 0) + 1);
  if (!latencies.has(key)) latencies.set(key, []);
  latencies.get(key).push(ms);
}

function anomaly(what, detail) {
  anomalies.push({ what, detail });
  console.log(`\n!! ANOMALY ${what}\n   ${detail}\n`);
}

/** A CREST body from /authorize is divergence row 7 -- report it whole, it is the thing the soak watches for. */
function checkCrest(where, status, body) {
  if (/"code"\s*:\s*\d+/.test(body) && /"reason"\s*:/.test(body) && /"message"\s*:/.test(body)) {
    anomaly(`CREST-JSON body from ${where}`, `status=${status} body=${body}`);
  }
}

async function timed(key, run) {
  const started = Date.now();
  try {
    const { status, body } = await run();
    record(key, status, Date.now() - started);
    return { status, body };
  } catch (transportFailure) {
    record(key, "EXC", Date.now() - started);
    anomaly(`transport failure on ${key}`, String(transportFailure));
    return { status: 0, body: "" };
  }
}

/** client_secret_post: credentials in the BODY, so audit, client auth and the handler all re-read it. */
async function tokenViaPost(marker) {
  return timed("access_token(post)", async () => {
    const response = await fetch(`${OAUTH2}/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials", scope: SCOPE,
        client_id: TOKEN_CLIENT_POST, client_secret: SECRET,
      }).toString(),
    });
    const body = await response.text();
    if (response.status === 200) {
      let parsed;
      try { parsed = JSON.parse(body); } catch { anomaly("token body not JSON", body); return { status: response.status, body }; }
      issuedCount += 1;
      if (issuedTokens.has(parsed.access_token)) {
        anomaly("DUPLICATE access_token issued", `${parsed.access_token} (marker ${marker})`);
      }
      issuedTokens.add(parsed.access_token);
      // The scope must be the one THIS request asked for. A different one means the answer was built
      // from another request's parameters.
      if (parsed.scope !== SCOPE) anomaly("scope echo mismatch on token(post)", `got ${JSON.stringify(parsed.scope)} want ${SCOPE}`);
    } else {
      anomaly(`access_token(post) -> ${response.status}`, body);
    }
    return { status: response.status, body };
  });
}

/** The control: identical grant, credentials in the Authorization header, body untouched by auth. */
async function tokenViaBasic() {
  return timed("access_token(basic)", async () => {
    const response = await fetch(`${OAUTH2}/access_token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: basicAuth(TOKEN_CLIENT_BASIC, SECRET),
      },
      body: new URLSearchParams({ grant_type: "client_credentials", scope: SCOPE }).toString(),
    });
    const body = await response.text();
    if (response.status === 200) {
      const parsed = JSON.parse(body);
      issuedCount += 1;
      if (issuedTokens.has(parsed.access_token)) anomaly("DUPLICATE access_token issued", parsed.access_token);
      issuedTokens.add(parsed.access_token);
    } else {
      anomaly(`access_token(basic) -> ${response.status}`, body);
    }
    return { status: response.status, body };
  });
}

/** A per-request `state` that must come back on the redirect, and a code that must be unique. */
async function authorize(sessionToken, marker, challenge) {
  return timed("authorize", async () => {
    const query = new URLSearchParams({
      response_type: "code", client_id: AUTHZ_CLIENT, redirect_uri: REDIRECT_URI,
      scope: SCOPE, state: marker,
      // ensureProviderConfig pins codeVerifierEnforced:true, so every response_type=code request needs a
      // real S256 challenge or it 400s on validation and this probe measures the validator, not the flow.
      code_challenge: challenge, code_challenge_method: "S256",
    });
    const response = await fetch(`${OAUTH2}/authorize?${query}`, {
      redirect: "manual",
      headers: { Cookie: `iPlanetDirectoryPro=${sessionToken}` },
    });
    const body = await response.text();
    checkCrest("/authorize", response.status, body);
    if (response.status === 302) {
      const location = new URL(response.headers.get("location"));
      const echoed = location.searchParams.get("state");
      if (echoed !== marker) {
        anomaly("STATE CROSS-TALK on /authorize", `sent ${marker}, got back ${echoed} (Location ${location})`);
      }
      const code = location.searchParams.get("code");
      if (!code) anomaly("authorize 302 with no code", String(location));
    } else {
      anomaly(`authorize -> ${response.status}`, body.slice(0, 600));
    }
    return { status: response.status, body };
  });
}

/** An erroring token request in the same mix: the error path re-reads the body too. */
async function badGrant(marker) {
  return timed("access_token(bad)", async () => {
    const response = await fetch(`${OAUTH2}/access_token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: basicAuth(TOKEN_CLIENT_BASIC, SECRET),
      },
      body: new URLSearchParams({ grant_type: `no_such_grant_${marker}`, scope: SCOPE }).toString(),
    });
    const body = await response.text();
    // Pinned: the shape must stay OAuth2's under load, not become the framework's CREST 500.
    if (response.status !== 400) anomaly(`bad grant -> ${response.status}`, body);
    else if (!/"error"\s*:\s*"unsupported_grant_type"/.test(body)) {
      anomaly("bad grant wrong error", body);
    }
    return { status: response.status, body };
  });
}

async function tokeninfo(token) {
  return timed("tokeninfo", async () => {
    const response = await fetch(`${OAUTH2}/tokeninfo?access_token=${token}`);
    const body = await response.text();
    if (response.status !== 200) anomaly(`tokeninfo -> ${response.status}`, body);
    return { status: response.status, body };
  });
}

function percentile(sorted, p) {
  if (sorted.length === 0) return 0;
  return sorted[Math.min(sorted.length - 1, Math.floor((sorted.length * p) / 100))];
}

async function main() {
  console.log(`[load] target ${OAUTH2}  seconds=${SECONDS}  concurrency=${CONCURRENCY}`);
  const { sessionToken } = await setUp();
  const { challenge } = await pkce();
  console.log("[load] fixtures ready");

  const deadline = Date.now() + SECONDS * 1000;
  let sequence = 0;
  const started = Date.now();

  async function worker(id) {
    while (Date.now() < deadline) {
      const marker = `w${id}-${sequence++}-${Math.random().toString(36).slice(2, 8)}`;
      // The mix. One authorize per two token calls, plus an error and a lookup, so the error path and
      // the token store are contended at the same time as the two hot endpoints.
      const post = await tokenViaPost(marker);
      await authorize(sessionToken, marker, challenge);
      await tokenViaBasic();
      if (sequence % 5 === 0) await badGrant(marker);
      if (post.status === 200 && sequence % 3 === 0) {
        try { await tokeninfo(JSON.parse(post.body).access_token); } catch { /* covered above */ }
      }
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, (_, i) => worker(i)));
  const elapsed = (Date.now() - started) / 1000;

  console.log(`\n[load] done in ${elapsed.toFixed(1)}s`);
  console.log("\n--- status counts ---");
  for (const [key, count] of [...stats.entries()].sort()) console.log(`  ${key.padEnd(28)} ${count}`);

  console.log("\n--- latency ms (p50 / p95 / max) ---");
  let total = 0;
  for (const [key, values] of [...latencies.entries()].sort()) {
    const sorted = [...values].sort((a, b) => a - b);
    total += values.length;
    console.log(`  ${key.padEnd(22)} n=${String(values.length).padEnd(6)}`
      + ` ${percentile(sorted, 50)} / ${percentile(sorted, 95)} / ${sorted[sorted.length - 1]}`);
  }
  console.log(`\n  total requests ${total}  (${(total / elapsed).toFixed(1)}/s)`);
  console.log(`  access tokens issued ${issuedCount}, distinct ${issuedTokens.size}`
    + `${issuedCount === issuedTokens.size ? " -- OK" : " -- ⚠ COLLISION"}`);

  if (anomalies.length > 0) {
    console.log(`\n[load] ${anomalies.length} ANOMALIES:`);
    for (const { what, detail } of anomalies) console.log(`  - ${what}: ${detail}`);
    process.exit(1);
  }
  console.log("\n[load] no correctness anomalies");
}

main().catch((failure) => { console.error(failure); process.exit(1); });
