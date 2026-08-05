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
 * D8's audit smoke: drives a fixed 8-request /oauth2 sequence against a running container and extracts
 * exactly the audit rows those 8 requests produced. Run once before the 5d-1c flip and once after; the two
 * artefacts are diffed field by field (docs/migration/restlet/phase-5d-1.md, D8).
 *
 *   node e2e/tools/d8-audit-capture.mjs pre-flip
 *
 * Why a tool and not a spec: the post-flip capture happens on a REBUILT container, so the only thing that
 * makes the two artefacts comparable is that the same code created the same fixtures and sent the same
 * bytes. That is also why every fixture here is imported from common/oauth2-fixtures.mjs rather than
 * restated -- and why the artefact header records this file's and the fixtures' checksums, so a diff taken
 * across an edit to either is detectable rather than silently wrong.
 *
 * Three things the plan assumed that are NOT true, established 2026-08-05 against openam-e2e:5d1b:
 *   - D8 step 1 ("enable the file-based access-audit handler") is a no-op: a `Global CSV Handler` ships
 *     enabled, with the `access` topic on, writing $OPENAM_DATA_DIR/$OPENAM_PATH/log/access.csv.
 *   - What DOES need changing is `csvBuffering.bufferingEnabled`, which ships `true` with autoFlush `false`.
 *     The buffer is FIFO with no bounded latency: a capture's rows sit behind whatever backlog the container
 *     already had, so a flush after the 8 requests emits the OLDEST pending records, not ours, and
 *     line-offset extraction silently yields someone else's traffic. Disabling it makes writes synchronous
 *     (and flushes the backlog as a side effect). 5d-1c must do the same before the post-flip capture.
 *   - The auditor detail is at `request.detail` / `response.detail`, NOT `http.request.detail`
 *     (AMAccessAuditEventBuilder:145 -> addDetail(detail, REQUEST), AccessAuditEventBuilder:84 REQUEST="request").
 *
 * Expect 8 rows, not 16: `AM-ACCESS-ATTEMPT` is blacklisted unless the JVM property
 * `org.forgerock.openam.audit.access.attempt.enabled` is set (AuditServiceConfigurationProviderImpl:221), so a
 * default container logs only `AM-ACCESS-OUTCOME`. Decided 2026-08-05 to leave it off: enabling it needs a
 * restart on BOTH sides of the flip, and the only field it would add -- `request.detail`, the request-side
 * auditor field lists -- is already pinned in-process by
 * OAuth2RouterIT.theAccessTokenAuditDetailIsExactlyTheConfiguredFieldList. Everything risk #13's residual
 * actually rides on (the FAILED-path `reason`, `queryParameters`, the `:-1` port) is on the outcome event.
 */

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { OPENAM_BASE, USERNAME, PASSWORD, getAdminToken, getAuthToken } from "../common/openam-commons.mjs";
import {
  REDIRECT_URI, RS_CLIENT_SECRET, basicAuth, ensureProviderConfig, ensureResourceServerClient,
  ensureUmaProvider, protectionApiToken, warmUpResourceSetStore,
} from "../common/oauth2-fixtures.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const LABEL = process.argv[2];
const CONTAINER = process.env.OPENAM_CONTAINER ?? "openam-idp";
const ACCESS_LOG = process.env.OPENAM_ACCESS_LOG ?? "/usr/openam/config/openam/log/access.csv";
const OUT_DIR = process.env.D8_OUT_DIR ?? resolve(HERE, "../../docs/migration/restlet/artefacts");

/* The client. Deliberately a distinct id from every e2e client so a capture never depends on -- or
 * disturbs -- fixture state another suite owns. ensureResourceServerClient's payload already grants
 * password + authorization_code + client_credentials and the uma_protection scope, which is exactly the
 * set these 8 requests need, so no new client shape is introduced here. */
const CLIENT_ID = "d8_probe";
/* Fixed, not unique(): pre and post run against DIFFERENT containers, so a constant name keeps the
 * `request.detail` of request 7 byte-identical across the two artefacts. Re-running a capture against an
 * already-captured container will 400 on the duplicate name -- that is the intended loud failure. */
const RESOURCE_SET_NAME = "d8-probe-resource";
/* Fixed state/nonce for the same reason: they land in http.request.queryParameters. */
const AUTHORIZE_PARAMS = {
  response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
  scope: "openid", state: "d8-state", nonce: "d8-nonce",
};

if (!LABEL) {
  console.error("usage: node e2e/tools/d8-audit-capture.mjs <label>   (e.g. pre-flip)");
  process.exit(2);
}

/*
 * Minimal adapter presenting Playwright's APIRequestContext surface over fetch, so the fixtures import
 * unchanged. The fixtures only ever call status()/text()/ok()/json(), and call several of them on one
 * response -- hence the buffered body.
 */
const request = {
  get: (url, opts) => send("GET", url, opts),
  put: (url, opts) => send("PUT", url, opts),
  post: (url, opts) => send("POST", url, opts),
  delete: (url, opts) => send("DELETE", url, opts),
};

async function send(method, url, { headers = {}, data, form, maxRedirects } = {}) {
  const init = { method, headers: { ...headers }, redirect: maxRedirects === 0 ? "manual" : "follow" };
  if (form !== undefined) {
    init.body = new URLSearchParams(form).toString();
    init.headers["Content-Type"] = "application/x-www-form-urlencoded";
  } else if (data !== undefined) {
    init.body = JSON.stringify(data);
    init.headers["Content-Type"] ??= "application/json";
  }
  const res = await fetch(url, init);
  const body = await res.text();
  return {
    status: () => res.status,
    ok: () => res.status >= 200 && res.status < 300,
    text: async () => body,
    json: async () => JSON.parse(body),
    headers: () => Object.fromEntries(res.headers),
  };
}

const md5 = (path) => createHash("md5").update(readFileSync(path)).digest("hex");
const inContainer = (cmd) =>
  execFileSync("docker", ["exec", CONTAINER, "bash", "-c", cmd], { encoding: "utf8" });
const logLineCount = () => Number(inContainer(`wc -l < ${ACCESS_LOG}`).trim());
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/*
 * The CSV handler ships with bufferingEnabled=true / autoFlush=false, so rows land after the request
 * returns. Poll until the file stops growing rather than guessing an interval.
 */
async function settled(from) {
  let last = -1;
  let quiet = 0;
  for (let attempt = 0; attempt < 60 && quiet < 3; attempt++) {
    await sleep(1000);
    const now = logLineCount();
    quiet = now === last ? quiet + 1 : 0;
    last = now;
  }
  return last - from;
}

const AUDIT_HANDLER =
  `${OPENAM_BASE}/json/global-config/services/audit/CSV/${encodeURIComponent("Global CSV Handler")}`;
const CONFIG_HEADERS = (adminToken) => ({
  iPlanetDirectoryPro: adminToken, "Accept-API-Version": "protocol=2.0,resource=1.0",
});

/** Makes the CSV writes synchronous. Returns the prior setting so the artefact can record it. */
async function disableCsvBuffering(adminToken) {
  const list = await request.get(`${OPENAM_BASE}/json/global-config/services/audit/CSV?_queryFilter=true`,
    { headers: CONFIG_HEADERS(adminToken) });
  if (!list.ok()) {
    throw new Error(`audit CSV handler not readable: ${list.status()} ${await list.text()}`);
  }
  const handler = (await list.json()).result?.[0];
  if (!handler) {
    throw new Error("no CSV audit handler configured");
  }
  const was = handler.csvBuffering?.bufferingEnabled;
  if (was === false) {
    console.log("CSV audit buffering already disabled");
    return was;
  }
  // Read-modify-write the whole representation: this is a full replace, so anything dropped here is lost.
  delete handler._rev;
  delete handler._type;
  handler.csvBuffering = { ...handler.csvBuffering, bufferingEnabled: false };
  const written = await request.put(AUDIT_HANDLER,
    { headers: CONFIG_HEADERS(adminToken), data: handler });
  if (!written.ok()) {
    throw new Error(`could not disable CSV buffering: ${written.status()} ${await written.text()}`);
  }
  console.log(`CSV audit buffering disabled (was ${was})`);
  return was;
}

/**
 * Removes a previous capture's resource set. The name is fixed on purpose (see RESOURCE_SET_NAME), and
 * names are unique per resource owner, so without this a second capture against one container 400s.
 * Matches by name rather than clearing the collection -- `demo` also owns the e2e suite's resource sets.
 */
async function dropProbeResourceSet(pat) {
  const bearer = { Authorization: `Bearer ${pat}` };
  const listed = await request.get(`${OPENAM_BASE}/oauth2/resource_set?_queryFilter=true`, { headers: bearer });
  if (!listed.ok()) {
    throw new Error(`resource_set query failed: ${listed.status()} ${await listed.text()}`);
  }
  for (const id of await listed.json()) {
    const read = await request.get(`${OPENAM_BASE}/oauth2/resource_set/${id}`, { headers: bearer });
    if (read.ok() && (await read.json()).name === RESOURCE_SET_NAME) {
      // DELETE requires an If-Match (ResourceSetRegistrationHandler:276); without one it is a 400, not a 428.
      const gone = await request.delete(`${OPENAM_BASE}/oauth2/resource_set/${id}`,
        { headers: { ...bearer, "If-Match": read.headers().etag } });
      if (gone.status() !== 204) {
        throw new Error(`could not remove previous "${RESOURCE_SET_NAME}" (${id}): `
          + `${gone.status()} ${await gone.text()}`);
      }
      console.log(`removed previous "${RESOURCE_SET_NAME}" (${id})`);
    }
  }
}

async function main() {
  console.log(`### D8 audit capture "${LABEL}" -- container ${CONTAINER}, base ${OPENAM_BASE}`);

  // --- setup: every prerequisite request happens BEFORE the marker, so the captured window holds
  // --- exactly the 8 D8 requests and nothing else.
  const adminToken = await getAdminToken(request);
  if (!adminToken) {
    throw new Error("admin authentication failed");
  }
  const bufferingWas = await disableCsvBuffering(adminToken);
  await ensureProviderConfig(adminToken, request);
  await ensureUmaProvider(adminToken, request);
  await ensureResourceServerClient(adminToken, request, CLIENT_ID);
  const session = await getAuthToken(request, USERNAME, PASSWORD);
  const pat = await protectionApiToken(request, CLIENT_ID, USERNAME, PASSWORD);
  await warmUpResourceSetStore(request, pat);
  await dropProbeResourceSet(pat);

  // Disabling buffering flushes whatever backlog was pending, so wait for the file to stop moving before
  // marking -- otherwise the window opens over someone else's rows.
  await settled(0);
  const before = logLineCount();
  console.log(`### marker: access.csv at ${before} lines`);

  // --- the 8 requests, in D8's order.
  const auth = { Authorization: basicAuth(CLIENT_ID, RS_CLIENT_SECRET) };
  const query = new URLSearchParams(AUTHORIZE_PARAMS).toString();
  const observed = [];
  const step = async (n, what, expected, run) => {
    const res = await run();
    observed.push({ n, what, expected, actual: res.status() });
    console.log(`  ${n}. ${what.padEnd(28)} expected ${expected}  actual ${res.status()}`
      + `${res.status() === expected ? "" : "   <-- DIFFERS"}`);
    return res;
  };

  const cc = await step(1, "client_credentials token", 200, () =>
    request.post(`${OPENAM_BASE}/oauth2/access_token`, {
      headers: auth, form: { grant_type: "client_credentials", scope: "uma_protection" },
    }));
  const accessToken = cc.ok() ? (await cc.json()).access_token : null;

  await step(2, "bad-secret token", 401, () =>
    request.post(`${OPENAM_BASE}/oauth2/access_token`, {
      headers: { Authorization: basicAuth(CLIENT_ID, "wrong-secret") },
      form: { grant_type: "client_credentials", scope: "uma_protection" },
    }));

  // D8 predicts 301 here; the artefact records whatever it actually is, on both sides of the flip.
  await step(3, "authorize, no session", 302, () =>
    request.get(`${OPENAM_BASE}/oauth2/authorize?${query}`, { maxRedirects: 0 }));

  await step(4, "authorize, with session", 302, () =>
    request.get(`${OPENAM_BASE}/oauth2/authorize?${query}`, {
      headers: { Cookie: `iPlanetDirectoryPro=${session}` }, maxRedirects: 0,
    }));

  await step(5, "tokeninfo", 200, () =>
    request.get(`${OPENAM_BASE}/oauth2/tokeninfo?access_token=${encodeURIComponent(accessToken ?? "")}`));

  await step(6, "introspect", 200, () =>
    request.post(`${OPENAM_BASE}/oauth2/introspect`, {
      headers: auth, form: { token: accessToken ?? "", token_type_hint: "access_token" },
    }));

  await step(7, "resource_set create", 201, () =>
    request.post(`${OPENAM_BASE}/oauth2/resource_set`, {
      headers: { Authorization: `Bearer ${pat}` },
      data: { name: RESOURCE_SET_NAME, scopes: ["read", "write"] },
    }));

  await step(8, "405 (PROPFIND tokeninfo)", 405, () =>
    send("PROPFIND", `${OPENAM_BASE}/oauth2/tokeninfo`));

  // --- extract.
  const rows = await settled(before);
  console.log(`### ${rows} audit rows written`);
  const csv = inContainer(`tail -n +${before + 1} ${ACCESS_LOG}`);
  const header = inContainer(`head -1 ${ACCESS_LOG}`);

  const provenance = [
    `# D8 audit capture: ${LABEL}`,
    `# container=${CONTAINER} image=${dockerImage()} base=${OPENAM_BASE}`,
    // The two md5s are what actually make the pre/post pair comparable: they pin the code that created the
    // fixtures and sent the bytes. The commit is context, not the guarantee.
    `# git=${git("rev-parse HEAD")}`,
    `# tool.md5=${md5(fileURLToPath(import.meta.url))}`,
    `# fixtures.md5=${md5(resolve(HERE, "../common/oauth2-fixtures.mjs"))}`,
    `# statuses=${observed.map((o) => `${o.n}:${o.actual}`).join(" ")}`,
    `# csvBuffering.bufferingEnabled: was ${bufferingWas} -> false for this capture`,
    `# rows=${rows}`,
    "",
  ].join("\n");

  mkdirSync(OUT_DIR, { recursive: true });
  const out = resolve(OUT_DIR, `d8-audit-${LABEL}.csv`);
  writeFileSync(out, provenance + header + csv);
  console.log(`### wrote ${out}`);

  const differs = observed.filter((o) => o.actual !== o.expected);
  if (differs.length) {
    console.log(`### NOTE: ${differs.length} status(es) differ from D8's prediction -- recorded, not fatal`);
  }
}

function git(args) {
  try {
    return execFileSync("git", args.split(" "), { cwd: HERE, encoding: "utf8" }).trim();
  } catch (unavailable) {
    return "";
  }
}

function dockerImage() {
  try {
    return execFileSync("docker", ["inspect", "--format={{.Config.Image}}", CONTAINER],
      { encoding: "utf8" }).trim();
  } catch (unavailable) {
    return "?";
  }
}

await main();
