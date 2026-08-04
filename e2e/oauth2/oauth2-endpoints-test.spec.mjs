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
 * Protocol cover for the /oauth2 routes that are neither the token endpoint nor the OIDC surface:
 * dynamic client registration, the device flow, token revocation and resource-set registration. All four
 * are still served by Restlet and move to CHF in phase 5 (5a-2b for register/device-code/revoke,
 * 5b-2 for device/user, 5c for resource_set -- docs/migration/restlet/plan.md); none of them had any
 * end-to-end cover before this spec.
 *
 * Like oidc-test.spec.mjs the ORIGINAL describes here are MIGRATION GUARDS rather than byte oracles:
 * statuses, body fields and lifecycle behaviour, not exact Content-Type bytes (CHF adds `; charset=UTF-8`, a
 * known divergence locked by the 5-E rows in oauth2-test.spec.mjs). Re-run unchanged after the 5d-1 flip.
 *
 * ⚠ The `(5-E4, live Restlet)` describe below is the EXCEPTION: it is a byte oracle, deliberately, including
 * its Content-Type rows. Do not relax one of its assertions on the strength of the paragraph above -- if a
 * 5-E4 row goes red at the flip, that is a divergence to record, not a test to loosen.
 */

import { request as httpRequest } from "node:http";
import { test, expect, request as apiRequest } from "@playwright/test";
import {
  ADMIN_PASS, ADMIN_USER, OPENAM_BASE, getAdminToken, getAuthToken, PASSWORD, USERNAME,
} from "../common/openam-commons.mjs";
import {
  RS_CLIENT_SECRET,
  deleteClient, deviceCodeForConsent, ensureDeviceConsentClient, ensureOidcClient, ensureProviderConfig,
  ensureResourceServerClient, ensureUmaProvider, protectionApiToken, registerResourceSet, sessionContext,
  uniqueName, warmUpResourceSetStore,
} from "../common/oauth2-fixtures.mjs";

/** This spec's own clients -- see the note in oauth2-fixtures.mjs about per-file ownership. */
const OIDC_CLIENT_ID = "test_client_oidc_dev";
const RS_CLIENT_ID = "test_client_rs_reg";
/** Consent-requiring, device-capable: the 5-E3 rows that must reach the device consent page. */
const DEVICE_CONSENT_CLIENT_ID = "test_client_device_consent";

/** Protection API token: the bearer that guards /oauth2/resource_set and authorises dynamic registration. */
let pat;

const RS = `${OPENAM_BASE}/oauth2/resource_set`;
/** Defaults to this spec's PAT; row 10 passes a second resource owner's token. */
const bearer = (token) => ({ Authorization: `Bearer ${token ?? pat}`, "Content-Type": "application/json" });

test.beforeAll(async ({ request }) => {
  const adminToken = await getAdminToken(request);
  if (!adminToken) {
    test.skip(true, "ADMIN_TOKEN not set");
  }
  await ensureProviderConfig(adminToken, request);
  await ensureUmaProvider(adminToken, request);
  await ensureOidcClient(adminToken, request, OIDC_CLIENT_ID);
  await ensureDeviceConsentClient(adminToken, request, DEVICE_CONSENT_CLIENT_ID);
  await ensureResourceServerClient(adminToken, request, RS_CLIENT_ID);
  pat = await protectionApiToken(request, RS_CLIENT_ID, USERNAME, PASSWORD);
  await warmUpResourceSetStore(request, pat);
});

test.describe("/oauth2/resource_set registration", () => {

  test("full lifecycle: register, read, list, update, delete", async ({ request }) => {
    // --- register. Resource-set names are unique per owner, so a fixed name would work exactly once
    // against a given container and 400 on every later run.
    const { response: created, name } = await registerResourceSet(
      request, pat, uniqueName("e2e album"), { type: "http://example.invalid/album" });
    const registration = await created.json();
    const etag = created.headers()["etag"];
    console.log(`[oauth2] resource_set POST -> ${created.status()} id=${registration._id} etag=${etag}`);

    expect(created.status(), `resource_set registration failed: ${JSON.stringify(registration)}`).toBe(201);
    expect(registration._id).toBeTruthy();
    // The RS is told where the resource owner can manage sharing; a port that drops this breaks the UMA UI.
    expect(registration.user_access_policy_uri).toContain(`#uma/share/${registration._id}`);
    expect(etag).toBeTruthy();
    const id = registration._id;

    // --- read
    const read = await request.get(`${OPENAM_BASE}/oauth2/resource_set/${id}`, { headers: bearer() });
    const resourceSet = await read.json();
    expect(read.status()).toBe(200);
    expect(resourceSet.name).toBe(name);
    expect(resourceSet.scopes).toEqual(["read", "write"]);
    expect(resourceSet.type).toBe("http://example.invalid/album");
    expect(read.headers()["etag"]).toBeTruthy();

    // --- list: the trailing-slash attachment is a separate route in the Restlet router (3 attachments for
    // this one endpoint), so it has to keep working on its own.
    const list = await request.get(`${OPENAM_BASE}/oauth2/resource_set/?_queryId=*`, { headers: bearer() });
    expect(list.status()).toBe(200);
    expect(await list.json()).toContain(id);

    // --- update: concurrency control is part of the contract, not an implementation detail
    const noIfMatch = await request.put(`${OPENAM_BASE}/oauth2/resource_set/${id}`, {
      headers: bearer(),
      data: { name: `${name} renamed`, scopes: ["read"] },
    });
    const noIfMatchBody = await noIfMatch.json();
    console.log(`[oauth2] resource_set PUT without If-Match -> ${noIfMatch.status()} ${JSON.stringify(noIfMatchBody)}`);
    expect(noIfMatch.status()).toBe(400);
    expect(noIfMatchBody.error_description).toContain("Require If-Match header to update Resource Set");

    const updated = await request.put(`${OPENAM_BASE}/oauth2/resource_set/${id}`, {
      headers: { ...bearer(), "If-Match": "*" },
      data: { name: `${name} renamed`, scopes: ["read"] },
    });
    expect(updated.status()).toBe(200);
    const afterUpdate = await (await request.get(`${OPENAM_BASE}/oauth2/resource_set/${id}`,
      { headers: bearer() })).json();
    expect(afterUpdate.name).toBe(`${name} renamed`);
    expect(afterUpdate.scopes).toEqual(["read"]);

    // --- delete
    const deleted = await request.delete(`${OPENAM_BASE}/oauth2/resource_set/${id}`, {
      headers: { ...bearer(), "If-Match": "*" },
    });
    console.log(`[oauth2] resource_set DELETE -> ${deleted.status()}`);
    expect(deleted.status()).toBe(204);

    const gone = await request.get(`${OPENAM_BASE}/oauth2/resource_set/${id}`, { headers: bearer() });
    const goneBody = await gone.json();
    expect(gone.status()).toBe(404);
    expect(goneBody.error).toBe("not_found");
    expect(goneBody.error_description).toContain(id);
  });

  test("rejects a request with no bearer token", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/resource_set`, {
      headers: { "Content-Type": "application/json" },
      data: { name: "unauthorised", scopes: ["read"] },
    });
    const body = await response.json();
    console.log(`[oauth2] resource_set no token -> ${response.status()} ${JSON.stringify(body)}`);
    // The protection filter answers in the OAuth2 error shape here (unlike /uma, which is CREST-shaped).
    expect(response.status()).toBe(401);
    expect(body.error).toBe("invalid_token");
  });

  test("rejects a request with an unknown bearer token", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/resource_set`, {
      headers: { Authorization: "Bearer not-a-real-token", "Content-Type": "application/json" },
      data: { name: "unauthorised", scopes: ["read"] },
    });
    expect(response.status()).toBe(401);
    expect((await response.json()).error).toBe("invalid_token");
  });
});

/**
 * Step 5-E4: the contract lock for /oauth2/resource_set, recorded against LIVE RESTLET. Restlet stops
 * serving /oauth2 at the 5d-1 flip, so none of this is recordable afterwards
 * (docs/migration/restlet/phase-5c.md).
 *
 * Every value here was OBSERVED FIRST and only then asserted (2026-07-29, openam-e2e:5e4 built from this
 * tree). Do not "tidy" a string: the exact bytes ARE the oracle for the 5d-1 byte diff.
 *
 * This is the migration's ONLY conditional-request endpoint. Restlet's ServerResource does the If-Match
 * MATCHING for it -- the endpoint's own `isConditionalRequest()` only asks whether the header is present --
 * and CHF has no equivalent, so rows 1, 1b, 2a, 2b, 3 and 3b are the specification for the helper that
 * replaces it. Six of these rows contradicted what the plan predicted; see the 5-E4 as-built.
 */
test.describe("/oauth2/resource_set contract lock (5-E4, live Restlet)", () => {

  /**
   * Everything this describe registers -- via `newResourceSet` OR through the raw client -- so the container
   * does not accumulate resource sets run after run. The CI image is long-lived and `warmUpResourceSetStore`
   * already sets the precedent of cleaning up after itself (oauth2-fixtures.mjs).
   *
   * ⚠ Every row that creates successfully must land an id here. Tracking only `newResourceSet` leaked five
   * per run (measured: the owner's list grew by exactly 5 across a full suite run).
   */
  const created = [];

  test.afterAll(async ({ request }) => {
    // ⚠ Deliberately NOT `deleteResourceSet`, which swallows every error: a teardown that silently fails is
    // worse than none, because it makes the suite look tidy while the container fills up. This one reports.
    //
    // Expect failures. `UmaResourceSetRegistrationHook.resourceSetDeleted` resolves the client's UMA resource
    // TYPE, and the shared fixtures rewrite the OAuth2 client on every run (`ensureResourceServerClient` is
    // an unconditional full PUT), which mints a new resource-type id and orphans the policies of every
    // resource set created before it. `resourceSetDeleted` then throws an OAuth2 `ServerException`, which
    // this endpoint reports as **400** (not 500 -- see row 4 for why every non-OAuth2Exception lands on 400),
    // and the resource set cannot be removed through the API at all. So this teardown mitigates
    // accumulation, it does not guarantee it. See the 5-E4 as-built.
    // ⚠ Sequential, deliberately -- NOT `Promise.all`. Issuing these concurrently corrupts the realm's
    // entitlement model and takes the container down for the rest of the run (run 30900393465: 45 deletes
    // in one Promise.all, realm poisoned at 11:56:52.352, every later /json policy and UMA call 500s).
    // `resourceSetDeleted` is a read-modify-write -- getApplication / removeResourceTypeUuid /
    // saveApplication -- and only THEN deletes the ResourceType. Run in parallel, one thread re-persists an
    // application snapshot still listing an id another thread has removed, and that thread then deletes the
    // id's ResourceType; the application is left referencing a type that is gone. From there
    // OpenSSOApplicationPrivilegeManager.getAllBaseResource throws NO_SUCH_RESOURCE_TYPE on the first id it
    // cannot resolve, which is realm-wide and permanent because every entitlement call goes through
    // ApplicationPrivilegeManager.getInstance. The uma and xacml specs both died on it.
    const results = [];
    for (const id of created) {
      const response = await request.delete(`${RS}/${id}`, {
        headers: { Authorization: `Bearer ${pat}`, "If-Match": "*" },
      });
      results.push(response.status());
    }
    const failed = results.filter((status) => status !== 204);
    console.log(`[5-E4] teardown: ${results.length - failed.length}/${results.length} deleted`
      + (failed.length ? `; ${failed.length} could not be removed (statuses ${[...new Set(failed)].join(", ")})` : ""));
  });

  /**
   * A POST carrying NO `Content-Type` header at all. Playwright always supplies one -- for a string body,
   * a Buffer, anything -- so row 12's absent-Content-Type case has to drop to Node's raw client, which sends
   * exactly the headers it is given. `sentContentType` reports what actually went out, so the row can prove
   * it tested absence rather than assuming it.
   */
  function postWithoutContentType(url, body) {
    return new Promise((resolve, reject) => {
      const target = new URL(url);
      const req = httpRequest({
        hostname: target.hostname, port: target.port, path: `${target.pathname}${target.search}`,
        method: "POST",
        headers: { Authorization: `Bearer ${pat}`, "Content-Length": Buffer.byteLength(body) },
      }, (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => { text += chunk; });
        res.on("end", () => resolve({
          status: res.statusCode, headers: res.headers, text,
          // ⚠ Read back from the ClientRequest, NOT from the literal above. The literal provably has no
          // Content-Type -- asserting on it would be `expect(undefined).toBeUndefined()` and would keep
          // passing if Node, an agent or a later edit started adding one. `getHeaders()` reflects what the
          // request actually carries, implicit headers included.
          sentContentType: req.getHeaders()["content-type"],
        }));
      });
      req.on("error", reject);
      req.end(body);
    });
  }

  /** Records a create that went through the raw client rather than `newResourceSet`. Returns it unchanged. */
  async function track(response) {
    if (response.status() === 201) {
      created.push((await response.json())._id);
    }
    return response;
  }

  /** Registers a resource set and hands back its id, name and the RAW ETag bytes the POST answered with. */
  async function newResourceSet(request, prefix, extra = {}) {
    const { response, name } = await registerResourceSet(request, pat, uniqueName(prefix), extra);
    // Read the body only when it is needed: the message argument is evaluated eagerly, and this helper runs
    // ~30 times per run.
    if (response.status() !== 201) {
      expect(response.status(), `fixture "${prefix}" failed: ${await response.text()}`).toBe(201);
    }
    const id = (await response.json())._id;
    created.push(id);
    return { id, name, postEtag: response.headers()["etag"] };
  }

  /**
   * The order the LABEL STORE hands a resource set's labels back in -- which is NOT sorted and NOT the order
   * the client sent. `UmaLabelsStore.query` returns a `HashSet<ResourceSetLabel>` and
   * `ResourceSetLabel.hashCode()` mixes in `LabelType.hashCode()`, which for an enum is the identity hash and
   * therefore differs per JVM run. So the order is stable within a container and can flip when it restarts.
   *
   * Row 2b must therefore DISCOVER this order rather than assume one, or it asserts a coin flip. Row 5 sits
   * the problem out instead, by using an unlabelled resource set.
   */
  async function storeLabelOrder(request, labels) {
    const { id } = await newResourceSet(request, "5e4 label order probe", { labels });
    const read = await (await request.get(`${RS}/${id}`, { headers: bearer() })).json();
    expect(read.labels.slice().sort()).toEqual(labels.slice().sort());
    return read.labels;
  }

  /**
   * The tag a GET currently answers with. Rows 2a/2b exist because this is NOT always the tag the POST
   * returned -- see row 2b.
   */
  async function currentEtag(request, id) {
    const response = await request.get(`${RS}/${id}`, { headers: bearer() });
    expect(response.status()).toBe(200);
    return response.headers()["etag"];
  }

  test("row 1: a stale If-Match is a 412 precondition_failed, weak form and strong form alike", async ({ request }) => {
    // Proves Restlet really is doing the MATCHING. The endpoint only checks presence, so a literal CHF port
    // that keeps `isConditionalRequest()` and nothing else would answer 200 here and silently drop
    // lost-update protection -- an unobservable regression that no status assertion elsewhere would catch.
    const { id, name } = await newResourceSet(request, "5e4 stale");
    for (const [form, ifMatch] of [["weak", 'W/"12345"'], ["strong", '"12345"']]) {
      const response = await request.put(`${RS}/${id}`, {
        headers: { ...bearer(), "If-Match": ifMatch }, data: { name: `${name} x`, scopes: ["read"] },
      });
      const body = await response.json();
      console.log(`[5-E4] row1 stale If-Match (${form}) -> ${response.status()} ${JSON.stringify(body)}`);
      expect(response.status(), form).toBe(412);
      // The filter's own 412 branch: an `error` and NOTHING else -- no error_description.
      expect(body, form).toEqual({ error: "precondition_failed" });
      expect(response.headers()["content-type"], form).toBe("application/json");
      expect(response.headers()["etag"], form).toBeUndefined();
    }

    // ⚠ And the same on DELETE, at the ITEM url. Every other mismatch case in this describe goes through
    // PUT, and row 9's DELETE-with-a-tag is the COLLECTION -- where rsid is null and the list representation
    // carries no Tag, so it 412s by a different mechanism and says nothing about item-level comparison.
    // Without this, a port that ports `isConditionalRequest()` literally for deleteResourceSet (400 when
    // absent, delete unconditionally when present) answers 204 here, drops lost-update protection on the
    // destructive verb, and passes the entire gate.
    const doomed = await newResourceSet(request, "5e4 stale delete");
    const deleted = await request.delete(`${RS}/${doomed.id}`, {
      headers: { ...bearer(), "If-Match": 'W/"12345"' },
    });
    const deletedBody = await deleted.json();
    console.log(`[5-E4] row1 stale If-Match on DELETE -> ${deleted.status()} ${JSON.stringify(deletedBody)}`);
    expect(deleted.status()).toBe(412);
    expect(deletedBody).toEqual({ error: "precondition_failed" });
    // And it really did not delete.
    expect((await request.get(`${RS}/${doomed.id}`, { headers: bearer() })).status()).toBe(200);
  });

  test("row 1b: how Restlet PARSES If-Match -- the specification the CHF helper must satisfy", async ({ request }) => {
    // ⚠ This row exists because the prose table in phase-5c.md is not an oracle. Restlet's tag parser dies at
    // the 5d-1 flip; without executable rows, a helper that 412s on garbage instead of 400ing, or that fails
    // to parse a comma list and 412s a well-behaved client, goes green with nothing left to check it against.
    //
    // Three outcomes are possible and all three occur:
    //   200 -- parsed, and something matched
    //   412 -- parsed, nothing matched
    //   400 -- ⚠ did NOT parse. The unparseable header is dropped, the match list comes out EMPTY, and
    //          `isConditionalRequest()` then reports "no If-Match at all", so the request takes the
    //          missing-header path of row 4. A garbage If-Match and an absent one are indistinguishable.
    const forms = [
      ["the exact weak tag", (tag) => tag, 200],
      ["the strong form of the same tag", (tag) => tag.replace(/^W\//, ""), 200],
      ["a comma list, current tag second", (tag) => `W/"nope", ${tag}`, 200],
      ["a comma list, current tag first", (tag) => `${tag}, W/"nope"`, 200],
      ["a comma list with no space after the comma", (tag) => `W/"nope",${tag}`, 200],
      ["*", () => "*", 200],
      ["a comma list containing neither", () => 'W/"nope", W/"nope2"', 412],
      ["a quoted empty string", () => '""', 412],
      ["the tag unquoted", (tag) => tag.replace(/^W\//, "").replace(/"/g, ""), 400],
      ["an empty header", () => "", 400],
      ["garbage", () => "!!!", 400],
    ];

    // A fresh resource set only where one is needed. A 200 moves the tag, so those forms cannot share; a 412
    // or a 400 provably leaves the resource set untouched, so the five non-mutating forms reuse one fixture.
    // (The tag is re-read per form regardless, so sharing cannot mask a stale-tag mistake.)
    const shared = await newResourceSet(request, "5e4 ifmatch form shared");

    for (const [label, make, expected] of forms) {
      const { id } = expected === 200 ? await newResourceSet(request, "5e4 ifmatch form") : shared;
      const tag = await currentEtag(request, id);
      const value = make(tag);
      const response = await request.put(`${RS}/${id}`, {
        headers: { ...bearer(), "If-Match": value }, data: { name: uniqueName("5e4 form"), scopes: ["read"] },
      });
      const body = await response.json();
      console.log(`[5-E4] row1b ${label} (${JSON.stringify(value)}) -> ${response.status()}`);
      expect(response.status(), label).toBe(expected);
      if (expected === 412) {
        expect(body, label).toEqual({ error: "precondition_failed" });
      } else if (expected === 400) {
        // Byte-identical to row 4's missing-header answer -- that identity IS the finding.
        expect(body.error, label).toBe("server_error");
        expect(body.error_description, label)
          .toBe("precondition_failed (512) - Require If-Match header to update Resource Set");
      }
    }
  });

  test("row 2a: If-Match echoing the GET's ETag verbatim succeeds, W/ prefix and all", async ({ request }) => {
    // The tag is weak (`W/"..."`), and a weak tag may not be used for If-Match under RFC 7232 sec 3.1. Restlet
    // compares with checkWeakness=false, so the weakness is ignored and the round trip works. The CHF port has
    // to ignore it too, or every well-behaved client that echoes what it was given starts 412ing.
    const { id, name } = await newResourceSet(request, "5e4 match get", { labels: ["alpha", "beta"] });
    const etag = await currentEtag(request, id);
    expect(etag).toMatch(/^W\/"-?\d+"$/);

    const updated = await request.put(`${RS}/${id}`, {
      headers: { ...bearer(), "If-Match": etag }, data: { name: `${name} v2`, scopes: ["read"] },
    });
    console.log(`[5-E4] row2a PUT If-Match ${etag} -> ${updated.status()} newEtag=${updated.headers()["etag"]}`);
    expect(updated.status()).toBe(200);
    // The update moved the tag, and the new one comes back on the same response.
    expect(updated.headers()["etag"]).toMatch(/^W\/"-?\d+"$/);
    expect(updated.headers()["etag"]).not.toBe(etag);

    // ⚠ And the update WIPED the labels. `updateLabelsForExistingResourceSet` is driven from the request
    // body, so a PUT that does not resend `labels` deletes them -- a wire-visible change to the GET body and,
    // because labels are in the hash, to the ETag. The fixture above was created with two; the PUT sent none.
    // Asserted rather than trusted to "the business logic is ported verbatim": that assumption is exactly
    // what this gate exists to distrust, and after 5d-1 it cannot be re-measured.
    const afterUpdate = await (await request.get(`${RS}/${id}`, { headers: bearer() })).json();
    console.log(`[5-E4] row2a labels after a labels-less PUT -> ${JSON.stringify(afterUpdate.labels)}`);
    expect(afterUpdate.labels).toEqual([]);

    // The DELETE twin, on its own resource set so the PUT above cannot have moved the tag underneath it.
    const doomed = await newResourceSet(request, "5e4 del exact", { labels: ["alpha", "beta"] });
    const doomedEtag = await currentEtag(request, doomed.id);
    const deleted = await request.delete(`${RS}/${doomed.id}`, {
      headers: { ...bearer(), "If-Match": doomedEtag },
    });
    console.log(`[5-E4] row2a DELETE If-Match ${doomedEtag} -> ${deleted.status()}`);
    expect(deleted.status()).toBe(204);
  });

  test("row 2b: the POST's ETag is already stale unless the client's label order matches the store's", async ({ request }) => {
    // ⚠ The row this gate exists for. The tag hashes the resource set INCLUDING its `labels`, but the two
    // responses take `labels` from different places: the POST echoes back what the CLIENT sent, while a GET
    // reads them out of umaLabelsStore. `List.hashCode` is order-sensitive, so whenever those two orders
    // differ the tag the POST handed the client never matched anything and its very next conditional update
    // 412s -- while the byte-identical request in the other order succeeds.
    //
    // ⚠ The store's order is NEITHER sorted NOR the client's: it is `HashSet<ResourceSetLabel>` iteration
    // order, and `ResourceSetLabel.hashCode()` mixes in an enum's identity hash, so it can differ from one
    // container start to the next. Hence `storeLabelOrder` -- this row DISCOVERS the order and then drives
    // both directions off it. Hard-coding either order makes this row a coin flip per restart.
    //
    // Two labels are the minimum that can expose it: one label, or none, cannot be out of order.
    const storeOrder = await storeLabelOrder(request, ["alpha", "beta"]);
    const reversed = storeOrder.slice().reverse();
    console.log(`[5-E4] row2b the label store's order is ${JSON.stringify(storeOrder)}`);

    for (const [how, labels, agrees] of [
      ["matching the store", storeOrder, true], ["opposite to the store", reversed, false],
    ]) {
      const { id, postEtag } = await newResourceSet(request, "5e4 order", { labels });
      const read = await request.get(`${RS}/${id}`, { headers: bearer() });
      const readBody = await read.json();
      const getEtag = read.headers()["etag"];
      console.log(`[5-E4] row2b ${how}: sent=${JSON.stringify(labels)} read=${JSON.stringify(readBody.labels)}`
        + ` POST=${postEtag} GET=${getEtag}`);

      // Same labels, same order, every time -- whatever that order happens to be on this container.
      expect(readBody.labels, how).toEqual(storeOrder);
      // ⚠ Compare the VALUES, and only after pinning that both exist. `getEtag === postEtag` would be
      // `undefined === undefined` -- true -- against a port that stopped emitting ETags altogether, and the
      // matching half of this row would certify nothing.
      expect(postEtag, `${how}: the POST carries a tag`).toMatch(/^W\/"-?\d+"$/);
      expect(getEtag, `${how}: the GET carries a tag`).toMatch(/^W\/"-?\d+"$/);
      if (agrees) {
        expect(getEtag, how).toBe(postEtag);
      } else {
        expect(getEtag, how).not.toBe(postEtag);
      }

      const conditional = await request.put(`${RS}/${id}`, {
        headers: { ...bearer(), "If-Match": postEtag }, data: { name: uniqueName("5e4 renamed"), scopes: ["read"] },
      });
      console.log(`[5-E4] row2b ${how}: PUT with the POST tag -> ${conditional.status()}`);
      if (agrees) {
        expect(conditional.status(), how).toBe(200);
      } else {
        expect(conditional.status(), how).toBe(412);
        expect(await conditional.json(), how).toEqual({ error: "precondition_failed" });
      }
    }
  });

  test("row 3: If-None-Match with the current tag is a 304 that still carries the ETag", async ({ request }) => {
    const { id } = await newResourceSet(request, "5e4 inm", { labels: ["alpha", "beta"] });
    const etag = await currentEtag(request, id);

    const notModified = await request.get(`${RS}/${id}`, { headers: { ...bearer(), "If-None-Match": etag } });
    const body = await notModified.text();
    console.log(`[5-E4] row3 304 -> ${notModified.status()} etag=${notModified.headers()["etag"]}`
      + ` ct=${notModified.headers()["content-type"]} bytes=${body.length}`);
    expect(notModified.status()).toBe(304);
    // Restlet DOES send the validator back on the 304 (RFC 7232 sec 4.1 asks for it) but sends no
    // Content-Type at all. Both halves are recorded: CHF would have to be told to do either.
    expect(notModified.headers()["etag"]).toBe(etag);
    expect(notModified.headers()["content-type"]).toBeUndefined();
    // ⚠ No `expect(body).toBe("")` here. RFC 7230 forbids a body on a 304 and the client never surfaces one,
    // so that assertion is true by construction -- the same trap row 15 refuses for HEAD. `Content-Length` is
    // what is actually observable, and Restlet sends none.
    expect(notModified.headers()["content-length"]).toBeUndefined();

    const stale = await request.get(`${RS}/${id}`, { headers: { ...bearer(), "If-None-Match": 'W/"12345"' } });
    expect(stale.status()).toBe(200);
    expect(stale.headers()["etag"]).toBe(etag);

    // ⚠ `*` means "if any representation exists" and RFC 7232 sec 3.2 makes that a 304 here. Restlet answers
    // 200. Recorded, not fixed.
    const star = await request.get(`${RS}/${id}`, { headers: { ...bearer(), "If-None-Match": "*" } });
    console.log(`[5-E4] row3 If-None-Match: * -> ${star.status()}`);
    expect(star.status()).toBe(200);

    // HEAD gets the same conditional treatment as GET -- see row 15 for why HEAD works at all.
    const head = await request.head(`${RS}/${id}`, { headers: { ...bearer(), "If-None-Match": etag } });
    expect(head.status()).toBe(304);
    expect(head.headers()["etag"]).toBe(etag);
    // The docs record "no Content-Type on the 304, on GET and on HEAD"; assert the HEAD half too, or the
    // second clause is prose. A port whose 304 runs through the shared JSON writer stamps
    // `;charset=UTF-8` here -- exactly the divergence row 14 exists to watch for.
    expect(head.headers()["content-type"]).toBeUndefined();
    // …and the Content-Length half of the same recorded fact, for the same reason.
    expect(head.headers()["content-length"]).toBeUndefined();
  });

  test("row 3b: a GET honours If-Match too -- and a stale one 412s WITH the representation", async ({ request }) => {
    // ⚠ The conditional layer runs on GET as well, which nothing in the endpoint's own source suggests: it
    // invokes the @Get to obtain the tag, then fails the precondition with the representation already in
    // hand. So the 412 carries a 200-shaped body AND the ETag -- a shape no error path on this endpoint
    // produces anywhere else.
    //
    // A CHF handler that consults If-Match only on PUT/DELETE answers 200 here. That is a silent 412 -> 200
    // change on a live endpoint, and Restlet stops serving /oauth2 at 5d-1, so this is the last chance to
    // record it.
    const { id, name } = await newResourceSet(request, "5e4 ifmatch on get", { labels: ["alpha"] });
    const etag = await currentEtag(request, id);

    const wildcard = await request.get(`${RS}/${id}`, { headers: { ...bearer(), "If-Match": "*" } });
    console.log(`[5-E4] row3b GET If-Match:* -> ${wildcard.status()}`);
    expect(wildcard.status()).toBe(200);
    expect((await wildcard.json()).name).toBe(name);

    const stale = await request.get(`${RS}/${id}`, { headers: { ...bearer(), "If-Match": '"12345"' } });
    const body = await stale.json();
    console.log(`[5-E4] row3b GET stale If-Match -> ${stale.status()} etag=${stale.headers()["etag"]}`
      + ` name=${body.name}`);
    expect(stale.status()).toBe(412);
    // Not `{"error":"precondition_failed"}` -- the entity is already populated, so the exception filter's
    // 412 branch (which only fires on an empty entity) never runs. This is the resource set itself.
    expect(body.name).toBe(name);
    expect(body.labels).toEqual(["alpha"]);
    expect(body.error).toBeUndefined();
    expect(stale.headers()["etag"]).toBe(etag);
    expect(stale.headers()["content-type"]).toBe("application/json");
  });

  test("row 4: PUT without If-Match is a 400 server_error, never a 412 and never a 512", async ({ request }) => {
    // The endpoint throws `new ResourceException(512, "precondition_failed", ...)`, and 512 is not a status
    // any client sees. `doCatch` hands the throwable to the endpoint's own ExceptionHandler, whose
    // `toOAuth2RestletException` finds neither an OAuth2RestletException nor an OAuth2Exception cause -- the
    // overload used here is `ResourceException(int, String, String, String)`, whose 4th parameter is the URI,
    // so it CANNOT carry a cause -- and falls to `new ServerException(throwable)`, which is 400
    // `server_error` with the message passed through. That fills the response entity, so
    // ResourceSetRegistrationExceptionFilter is skipped entirely on this path; it is not the producer here.
    //
    // ⚠ The message is Restlet's FORMATTED one -- `"<reason> (<code>) - <description>"` -- not the sentence
    // the endpoint wrote. A port that throws the bare sentence changes these bytes.
    const { id, name } = await newResourceSet(request, "5e4 no ifmatch");
    const response = await request.put(`${RS}/${id}`, {
      headers: bearer(), data: { name: `${name} v2`, scopes: ["read"] },
    });
    const body = await response.json();
    console.log(`[5-E4] row4 PUT no If-Match -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(400);
    expect(body.error).toBe("server_error");
    expect(body.error_description)
      .toBe("precondition_failed (512) - Require If-Match header to update Resource Set");
  });

  test("row 5: the ETag is a weak tag around a signed decimal, on POST, PUT and GET alike", async ({ request }) => {
    // `new Tag(Integer.toString(hashCode), true)` -- so `W/"<int>"`, negatives included. A port that emits a
    // strong tag, or a hex/quoted-differently one, changes bytes on the wire for every response here.
    // ⚠ UNLABELLED on purpose. Both responses then see `labels: []` and the two tags are comparable on any
    // container; with labels the comparison depends on the store's iteration order, which is row 2b's subject
    // and would make this row's last assertion a coin flip.
    const { id, postEtag } = await newResourceSet(request, "5e4 etag bytes");
    const read = await request.get(`${RS}/${id}`, { headers: bearer() });
    const updated = await request.put(`${RS}/${id}`, {
      headers: { ...bearer(), "If-Match": "*" }, data: { name: uniqueName("5e4 etag v2"), scopes: ["read"] },
    });
    console.log(`[5-E4] row5 etags post=${postEtag} get=${read.headers()["etag"]} put=${updated.headers()["etag"]}`);
    for (const [where, value] of [["POST", postEtag], ["GET", read.headers()["etag"]],
                                  ["PUT", updated.headers()["etag"]]]) {
      expect(value, where).toMatch(/^W\/"-?\d+"$/);
    }
    // Same state, same tag -- on an unlabelled resource set, unconditionally (row 2b is where they part).
    expect(read.headers()["etag"]).toBe(postEtag);
    // The list has NO validator at all. ⚠ Assert the status too: without it this passes on a 401/404/400,
    // and finding 12 predicts precisely a 404 on this URL from the obvious CHF transcription -- under which
    // the row would go green while proving nothing about ETag emission.
    const list = await request.get(`${RS}/?_queryId=*`, { headers: bearer() });
    expect(list.status()).toBe(200);
    expect(list.headers()["etag"]).toBeUndefined();
  });

  test("row 6: DELETE without If-Match is the same 400 server_error, with the delete wording", async ({ request }) => {
    const { id } = await newResourceSet(request, "5e4 del no ifmatch");
    const response = await request.delete(`${RS}/${id}`, { headers: bearer() });
    const body = await response.json();
    console.log(`[5-E4] row6 DELETE no If-Match -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(400);
    expect(body.error).toBe("server_error");
    expect(body.error_description)
      .toBe("precondition_failed (512) - Require If-Match header to delete Resource Set");
  });

  test("row 7: a duplicate name answers a reason PHRASE in the error field, with a charset", async ({ request }) => {
    // Two deliberate ugly facts, both reproduced rather than tidied:
    //   - `error` is `Status.CLIENT_ERROR_BAD_REQUEST.getReasonPhrase()`, so the literal string "Bad Request"
    //     where every other error on this endpoint uses a snake_case code;
    //   - this is the one response the endpoint builds as a JsonRepresentation ITSELF rather than through the
    //     exception filter, and it is consequently the ONLY one carrying `;charset=UTF-8` (see row 14).
    const name = uniqueName("5e4 duplicate");
    const first = await track(await request.post(RS, { headers: bearer(), data: { name, scopes: ["read"] } }));
    expect(first.status(), `first create failed: ${await first.text()}`).toBe(201);

    const second = await request.post(RS, { headers: bearer(), data: { name, scopes: ["read"] } });
    const body = await second.json();
    console.log(`[5-E4] row7 duplicate name -> ${second.status()} ct=${second.headers()["content-type"]}`
      + ` ${JSON.stringify(body)}`);
    expect(second.status()).toBe(400);
    expect(body.error).toBe("Bad Request");
    expect(body.error_description).toBe(`A shared item with the name '${name}' already exists`);
    expect(second.headers()["content-type"]).toBe("application/json;charset=UTF-8");
  });

  test("row 8: the validator's rejections, verbatim", async ({ request }) => {
    const cases = [
      ["missing name", { scopes: ["read"] },
        "Invalid Resource Set Description. Missing required attribute, 'name'."],
      ["missing scopes", { name: uniqueName("5e4 noscopes") },
        "Invalid Resource Set Description. Missing required attribute, 'scopes'."],
      ["non-array scopes", { name: uniqueName("5e4 badscopes"), scopes: "read" },
        "Invalid Resource Set Description. Required attribute, 'scopes', must be an array of Strings."],
      ["empty object", {},
        "Invalid Resource Set Description. Missing required attribute, 'name'."],
    ];
    for (const [label, data, description] of cases) {
      const response = await request.post(RS, { headers: bearer(), data });
      const body = await response.json();
      console.log(`[5-E4] row8 ${label} -> ${response.status()} ${JSON.stringify(body)}`);
      expect(response.status(), label).toBe(400);
      expect(body.error, label).toBe("bad_request");
      expect(body.error_description, label).toBe(description);
    }
  });

  test("row 9: PUT and DELETE on the COLLECTION give three different answers by If-Match form", async ({ request }) => {
    // `rsid` is null on the two collection attachments, and which failure you get depends entirely on how far
    // the conditional layer lets the request travel:
    //   *          -> the conditional check passes, the method runs, store.read(null) blows up
    //   a real tag -> the list representation carries no Tag, so nothing can match and it 412s first
    //   absent     -> the endpoint's own presence check fires before any of it
    // Both collection URLs behave identically, trailing slash or not.
    for (const [urlLabel, url] of [["/resource_set", RS], ["/resource_set/", `${RS}/`]]) {
      for (const verb of ["put", "delete"]) {
        const body = { name: uniqueName("5e4 collection"), scopes: ["read"] };

        const star = await request[verb](url, { headers: { ...bearer(), "If-Match": "*" }, data: body });
        const starBody = await star.json();
        console.log(`[5-E4] row9 ${verb.toUpperCase()} ${urlLabel} If-Match:* -> ${star.status()}`
          + ` ${JSON.stringify(starBody)}`);
        expect(star.status(), `${verb} ${urlLabel} *`).toBe(400);
        expect(starBody.error, `${verb} ${urlLabel} *`).toBe("server_error");
        expect(starBody.error_description, `${verb} ${urlLabel} *`)
          .toBe("Internal Server Error (500) - The server encountered an unexpected condition which prevented"
            + " it from fulfilling the request");

        const tagged = await request[verb](url, { headers: { ...bearer(), "If-Match": '"12345"' }, data: body });
        expect(tagged.status(), `${verb} ${urlLabel} tagged`).toBe(412);
        expect(await tagged.json(), `${verb} ${urlLabel} tagged`).toEqual({ error: "precondition_failed" });

        const bare = await request[verb](url, { headers: bearer(), data: body });
        const bareBody = await bare.json();
        expect(bare.status(), `${verb} ${urlLabel} bare`).toBe(400);
        expect(bareBody.error_description, `${verb} ${urlLabel} bare`).toBe(
          `precondition_failed (512) - Require If-Match header to ${verb === "put" ? "update" : "delete"}`
          + " Resource Set");
      }
    }
  });

  test("row 10: another resource owner's token gets 404, not 403", async ({ request }) => {
    // `store.read(id, ownerId)` is scoped by owner, so a resource set belonging to someone else is
    // indistinguishable from one that does not exist -- which is the right answer, and the port must not
    // "improve" it into a 403 that would confirm the id exists.
    const otherPat = await protectionApiToken(request, RS_CLIENT_ID, ADMIN_USER, ADMIN_PASS);
    // ⚠ `bearer()` falls back to this spec's own PAT when handed a nullish token, so an unexpected token
    // response would quietly turn this cross-owner row into a same-owner one -- and the failure would read
    // as "the endpoint's owner scoping is broken" rather than "the fixture is".
    expect(otherPat, `no PAT for ${ADMIN_USER}`).toBeTruthy();
    expect(otherPat).not.toBe(pat);
    const { id } = await newResourceSet(request, "5e4 owned by demo");

    for (const [verb, options] of [
      ["get", { headers: bearer(otherPat) }],
      ["put", { headers: { ...bearer(otherPat), "If-Match": "*" }, data: { name: uniqueName("x"), scopes: ["read"] } }],
      ["delete", { headers: { ...bearer(otherPat), "If-Match": "*" } }],
    ]) {
      const response = await request[verb](`${RS}/${id}`, options);
      const body = await response.json();
      console.log(`[5-E4] row10 ${verb.toUpperCase()} as ${ADMIN_USER} -> ${response.status()} ${JSON.stringify(body)}`);
      expect(response.status(), verb).toBe(404);
      expect(body.error, verb).toBe("not_found");
      expect(body.error_description, verb).toBe(`Resource set does not exist with id ${id}`);
    }
  });

  test("row 11: an unmapped verb is 405 unsupported_method_type -- but PATCH is NOT unmapped", async ({ request }) => {
    // ⚠ Two facts, and the second one was a surprise.
    //
    // The 405 body comes from the exception filter's own 405 branch, so it is `unsupported_method_type` --
    // NOT the `method_not_allowed` that 5b-2's D10 gave the OAuth2Filter-wrapped routes, and not the CREST
    // body the unwrapped ones send. Three different 405 shapes now live under /oauth2.
    //
    // And Restlet routes PATCH to the @Put method: a PATCH is a full REPLACE here today, not an error. CHF
    // maps only {DELETE, GET, POST, PUT}, so the port turns a working (if surprising) update into a 405.
    const { id } = await newResourceSet(request, "5e4 verbs");

    for (const method of ["OPTIONS", "PROPFIND"]) {
      const response = await request.fetch(`${RS}/${id}`, { method, headers: bearer() });
      const body = await response.json();
      console.log(`[5-E4] row11 ${method} -> ${response.status()} allow=${response.headers()["allow"]}`
        + ` ${JSON.stringify(body)}`);
      expect(response.status(), method).toBe(405);
      expect(body, method).toEqual({ error: "unsupported_method_type" });
      // ⚠ Assert PRESENCE before shape. `Endpoints.from`'s unmapped-verb branch builds its 405 as
      // `new Response(Status.METHOD_NOT_ALLOWED)` with a CREST entity and NO `Allow` header, so at the flip
      // this header disappears -- and `.split(", ")` on undefined would throw a TypeError that reads as a
      // broken test rather than as the divergence it is.
      const allow = response.headers()["allow"];
      expect(allow, `${method}: no Allow header at all`).toBeTruthy();
      // ⚠ The SET, not the string. Restlet builds `Allow` by walking `Class.getDeclaredMethods()`, whose
      // order the JDK leaves unspecified, so `"POST, PUT, GET, DELETE"` merely reflects today's declaration
      // order in ResourceSetRegistrationEndpoint.java. Reordering those four methods would turn an exact
      // string assertion red for no behaviour change. The observed order is in the log line above.
      expect(allow.split(", ").sort(), method).toEqual(["DELETE", "GET", "POST", "PUT"]);
    }

    // Anchor the pre-state instead of trusting `registerResourceSet`'s default body, which lives in another
    // file and could be narrowed without this row noticing.
    const before = await (await request.get(`${RS}/${id}`, { headers: bearer() })).json();
    expect(before.scopes).toEqual(["read", "write"]);
    const patchedName = uniqueName("5e4 patched");
    const patched = await request.fetch(`${RS}/${id}`, {
      method: "PATCH", headers: { ...bearer(), "If-Match": "*" },
      data: { name: patchedName, scopes: ["read"] },
    });
    console.log(`[5-E4] row11 PATCH -> ${patched.status()}`);
    expect(patched.status()).toBe(200);
    const after = await (await request.get(`${RS}/${id}`, { headers: bearer() })).json();
    // A full REPLACE, not a merge: both fields took the PATCH body's values.
    expect(after.name).toBe(patchedName);
    expect(after.name).not.toBe(before.name);
    expect(after.scopes).toEqual(["read"]);
  });

  test("row 12: the request's media type is ignored entirely; only the BODY can fail", async ({ request }) => {
    // Settles the media-type question. The endpoint declares `@Post createResourceSet(JsonRepresentation)`
    // and Restlet converts whatever arrives, so text/plain, application/xml and a missing Content-Type all
    // create a resource set. Only unparseable JSON fails, and it fails with the JSON library's own words.
    for (const contentType of ["text/plain", "application/xml"]) {
      const response = await track(await request.post(RS, {
        headers: { Authorization: `Bearer ${pat}`, "Content-Type": contentType },
        data: JSON.stringify({ name: uniqueName(`5e4 ct ${contentType}`), scopes: ["read"] }),
      }));
      console.log(`[5-E4] row12 Content-Type ${contentType} -> ${response.status()}`);
      expect(response.status(), contentType).toBe(201);
      expect(response.headers()["content-type"], contentType).toBe("application/json");
    }

    // ⚠ And with NO Content-Type at all -- through Node's raw client, because Playwright always supplies one
    // and a row that asserted absence through it would be asserting `application/json` and passing for the
    // wrong reason. This case is the evidence C1 (delete the dead `@Consumes`/`@Payload` annotations) rests
    // on, so it needs an oracle that outlives the flip rather than a one-off measurement in a doc.
    const absent = await postWithoutContentType(RS,
      JSON.stringify({ name: uniqueName("5e4 ct absent"), scopes: ["read"] }));
    console.log(`[5-E4] row12 no Content-Type -> ${absent.status} sentCt=${absent.sentContentType} ${absent.text}`);
    expect(absent.sentContentType, "the raw client must send no Content-Type").toBeUndefined();
    expect(absent.status).toBe(201);
    created.push(JSON.parse(absent.text)._id);

    const notJson = await request.post(RS, {
      headers: { Authorization: `Bearer ${pat}`, "Content-Type": "application/json" }, data: "hello",
    });
    const body = await notJson.json();
    console.log(`[5-E4] row12 non-JSON body -> ${notJson.status()} ${JSON.stringify(body)}`);
    expect(notJson.status()).toBe(400);
    expect(body.error).toBe("bad_request");
    expect(body.error_description).toBe("A JSONObject text must begin with '{' at 1 [character 2 line 1]");
  });

  /**
   * One response per status this endpoint can produce, shared by rows 13 and 14 -- they sweep the same
   * surface and differ only in which header they judge. Declaring it twice had already let the two lists
   * drift apart, and each row then paid its own round trips.
   *
   * `expectedContentType` is row 14's column; row 13 ignores it. The duplicate-name 400 is deliberately
   * absent: it is the charset exception, asserted in row 7 where it is produced.
   *
   * ⚠ The status in each label is asserted, not decorative. Nearly every failure on this endpoint is
   * `400 application/json`, which is also what most of these entries expect for a SUCCESS -- so without a
   * status assertion a container whose resource-set store has degraded (see the as-built) answers 400 to the
   * `POST 201` and `DELETE 204` entries and both rows still pass, certifying Content-Type and cache-header
   * claims for statuses the run never actually produced.
   */
  function statusSweep(request, id, name, etag) {
    return [
      ["POST 201", "application/json",
        () => request.post(RS, { headers: bearer(), data: { name: uniqueName("5e4 sweep"), scopes: ["read"] } }).then(track)],
      ["GET 200", "application/json", () => request.get(`${RS}/${id}`, { headers: bearer() })],
      ["GET 304", undefined, () => request.get(`${RS}/${id}`, { headers: { ...bearer(), "If-None-Match": etag } })],
      ["GET list 200", "application/json", () => request.get(`${RS}/?_queryId=*`, { headers: bearer() })],
      ["PUT 400", "application/json",
        () => request.put(`${RS}/${id}`, { headers: bearer(), data: { name, scopes: ["read"] } })],
      ["PUT 412", "application/json",
        () => request.put(`${RS}/${id}`, { headers: { ...bearer(), "If-Match": '"12345"' }, data: { name, scopes: ["read"] } })],
      ["GET 404", "application/json", () => request.get(`${RS}/nope-5e4`, { headers: bearer() })],
      ["OPTIONS 405", "application/json", () => request.fetch(`${RS}/${id}`, { method: "OPTIONS", headers: bearer() })],
      ["POST 401", "application/json",
        () => request.post(RS, { headers: { "Content-Type": "application/json" }, data: { name: "x", scopes: ["read"] } })],
      ["DELETE 204", "application/json", () => request.delete(`${RS}/${id}`, { headers: { ...bearer(), "If-Match": "*" } })],
    ];
  }

  test("row 13: no cache headers on any verb or any status", async ({ request }) => {
    // resource_set is not OAuth2Filter-wrapped, so nothing stamps no-store/Pragma on it -- the same finding
    // 5b-2 recorded for the three browser endpoints. A CHF port that mounts a blanket cache filter would add
    // headers this endpoint has never sent.
    const { id, name } = await newResourceSet(request, "5e4 cache");
    const etag = await currentEtag(request, id);
    for (const [label, , send] of statusSweep(request, id, name, etag)) {
      const response = await send();
      const headers = response.headers();
      console.log(`[5-E4] row13 ${label} -> ${response.status()} cc=${headers["cache-control"]} pragma=${headers["pragma"]}`);
      expect(response.status(), label).toBe(Number(label.match(/\d{3}$/)[0]));
      expect(headers["cache-control"], label).toBeUndefined();
      expect(headers["pragma"], label).toBeUndefined();
      expect(headers["expires"], label).toBeUndefined();
    }
  });

  test("row 14: Content-Type is a bare application/json everywhere but two places", async ({ request }) => {
    // CHF's `setEntity(Map)` stamps `; charset=UTF-8`, so every row here is a candidate divergence at the
    // flip -- exactly as /tokeninfo was in 5a-2. Note the 204 carries a Content-Type despite having no body.
    const { id, name } = await newResourceSet(request, "5e4 ct");
    const etag = await currentEtag(request, id);
    for (const [label, expected, send] of statusSweep(request, id, name, etag)) {
      const response = await send();
      console.log(`[5-E4] row14 ${label} -> ${response.status()} ct=${response.headers()["content-type"]}`);
      expect(response.status(), label).toBe(Number(label.match(/\d{3}$/)[0]));
      expect(response.headers()["content-type"], label).toBe(expected);
    }
    // `expected` is undefined for the 304, which is the assertion: it sends no Content-Type at all. The
    // duplicate-name 400 is the one response WITH a charset and is asserted in row 7, where it is produced.
  });

  test("row 15: HEAD is served as a GET with the body stripped -- 200, not 405", async ({ request }) => {
    // ⚠ A Phase-5-WIDE divergence, recorded here because this is the cheapest place to record it. Restlet
    // rewrites HEAD to GET before it looks up the annotation, so EVERY Restlet resource with a @Get answers
    // HEAD today. `Endpoints.from` builds its map from {DELETE, GET, POST, PUT} only, so every endpoint this
    // migration has ported already 405s HEAD. The decision -- map HEAD to GET in Endpoints, or accept the
    // regression -- is owed at 5d-1 for all 15 endpoints at once, not here.
    // ⚠ No assertion here claims the body is empty. An HTTP client discards a HEAD entity whatever the
    // server sent, so `(await response.text()).length === 0` is true by construction and would stay green
    // even against a server that streamed the whole document. What IS observable is that HEAD's headers
    // match the GET's -- which is the real claim, "HEAD is served as a GET".
    const { id } = await newResourceSet(request, "5e4 head");
    for (const [label, url] of [["item", `${RS}/${id}`], ["collection", RS], ["collection/", `${RS}/`]]) {
      const head = await request.head(url, { headers: bearer() });
      const get = await request.get(url, { headers: bearer() });
      console.log(`[5-E4] row15 HEAD ${label} -> ${head.status()} ct=${head.headers()["content-type"]}`
        + ` etag=${head.headers()["etag"]} len=${head.headers()["content-length"]}`);
      expect(head.status(), label).toBe(200);
      expect(head.status(), label).toBe(get.status());
      expect(head.headers()["content-type"], label).toBe("application/json");
      // Only the item form carries a validator. The equality lives inside that branch because for the two
      // collection forms both sides are `undefined`, and `undefined === undefined` certifies nothing about
      // "HEAD carries the same validator its GET does".
      if (label === "item") {
        expect(head.headers()["etag"], label).toMatch(/^W\/"-?\d+"$/);
        expect(head.headers()["etag"], label).toBe(get.headers()["etag"]);
      } else {
        expect(head.headers()["etag"], label).toBeUndefined();
      }
      // Restlet sends no Content-Length on HEAD at all -- recorded, since a port that starts sending one
      // (or sends the GET's) is a wire change even though no body is involved.
      expect(head.headers()["content-length"], label).toBeUndefined();
    }
  });

  test("row 16: POST to the item URL creates a resource set and ignores the rsid", async ({ request }) => {
    // All three attachments point at the same resource, and @Post does not look at rsid -- so a create
    // against an item URL is accepted and mints a NEW id. The CHF port keeps that by routing the same handler
    // at both the collection and the item template.
    const { id } = await newResourceSet(request, "5e4 item post");
    const response = await track(await request.post(`${RS}/${id}`, {
      headers: bearer(), data: { name: uniqueName("5e4 posted at item"), scopes: ["read"] },
    }));
    const body = await response.json();
    console.log(`[5-E4] row16 POST /resource_set/{id} -> ${response.status()} _id=${body._id}`);
    expect(response.status()).toBe(201);
    expect(body._id).toBeTruthy();
    expect(body._id).not.toBe(id);
  });

  test("row 17: two segments below the endpoint is a CREST 404 raised before authentication", async ({ request }) => {
    // Nothing the 5c port owns produces this: the extra segment is read as a REALM by the layer above the
    // OAuth2 router, which fails to resolve it and answers in the CREST shape -- no `error` field anywhere.
    // That is what pins the error filter to the HANDLER rather than around the router: wrapping the router
    // would turn this 404 into a 500 from a filter that assumes an exception is present.
    //
    // It also runs BEFORE the protection filter -- a bogus bearer changes nothing -- so the CHF chain must
    // not be able to answer 401 here either.
    for (const [label, headers] of [
      ["with a valid bearer", { Authorization: `Bearer ${pat}` }],
      ["with a bogus bearer", { Authorization: "Bearer not-a-real-token" }],
      ["with no bearer at all", {}],
    ]) {
      const response = await request.get(`${RS}/a/b`, { headers });
      const body = await response.json();
      console.log(`[5-E4] row17 GET /resource_set/a/b ${label} -> ${response.status()} ${JSON.stringify(body)}`);
      expect(response.status(), label).toBe(404);
      expect(body.code, label).toBe(404);
      expect(body.reason, label).toBe("Not Found");
      expect(body.message, label)
        .toBe("No mapping organization found for organization identifier: /resource_set");
      expect(body.error, label).toBeUndefined();
    }
    // For contrast: one segment down IS the endpoint, and there the protection filter answers.
    const guarded = await request.get(`${RS}/`, { headers: { Authorization: "Bearer not-a-real-token" } });
    expect(guarded.status()).toBe(401);
    expect((await guarded.json()).error).toBe("invalid_token");
  });

  test("row 22: the body parser is org.json, and org.json is LENIENT", async () => {
    // ⚠ Added 2026-07-29 while porting the handler, to settle whether the CHF side may simply use Jackson.
    // It may not: `@Post createResourceSet(JsonRepresentation)` reaches `new JSONObject(<raw body>)`
    // (JsonConverter wraps the representation; JsonRepresentation.getJsonText returns its raw text), and
    // org.json accepts three things Jackson rejects while rejecting one thing Jackson accepts. So the choice
    // of parser is a wire contract, not an implementation detail -- and none of it is recordable after 5d-1.
    //
    // ⚠ THIS ROW MUST USE A RAW CLIENT. Playwright does not send a string `data` verbatim when the request
    // carries a json Content-Type: measured, the very same single-quoted body answers 201 sent as
    // `text/plain` and 400 sent as `application/json`, because the client re-encodes what is not already
    // valid JSON. Written with `request.post` this row asserts Playwright's behaviour, not OpenAM's --
    // it read as a clean 400 for three rows that are really 201s.
    function rawPost(body) {
      return new Promise((resolve, reject) => {
        const target = new URL(RS);
        const req = httpRequest({
          hostname: target.hostname, port: target.port, path: target.pathname, method: "POST",
          headers: {
            Authorization: `Bearer ${pat}`, "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(body),
          },
        }, (res) => {
          let text = "";
          res.setEncoding("utf8");
          res.on("data", (c) => { text += c; });
          res.on("end", () => resolve({ status: res.statusCode, text }));
        });
        req.on("error", reject);
        req.end(body);
      });
    }
    // Three forms org.json ACCEPTS and every strict parser rejects. A CHF port built on Jackson answers 400
    // to all three, turning working resource servers off on upgrade -- silently, since the status a client
    // sees is a plausible 400 either way.
    for (const [label, body] of [
      ["strict (control)", `{"name":"${uniqueName("5e4 strict")}","scopes":["read"]}`],
      ["single-quoted strings", `{'name':'${uniqueName("5e4 sq")}','scopes':['read']}`],
      ["unquoted keys", `{name:"${uniqueName("5e4 uk")}",scopes:["read"]}`],
      ["a trailing comma", `{"name":"${uniqueName("5e4 tc")}","scopes":["read"],}`],
    ]) {
      const r = await rawPost(body);
      console.log(`[5-E4] row22 ${label} -> ${r.status} ${r.text}`);
      expect(r.status, label).toBe(201);
      created.push(JSON.parse(r.text)._id);
    }

    // ...and one org.json REJECTS and Jackson accepts, last-one-wins. A Jackson port creates here.
    const duplicate = await rawPost(`{"name":"${uniqueName("5e4 dk")}","name":"other","scopes":["read"]}`);
    console.log(`[5-E4] row22 duplicate keys -> ${duplicate.status} ${duplicate.text}`);
    expect(duplicate.status).toBe(400);
    expect(JSON.parse(duplicate.text).error).toBe("bad_request");
    expect(JSON.parse(duplicate.text).error_description)
        .toBe('Duplicate key "name" at 33 [character 34 line 1]');

    // The two both reject, with the message row 12 already locks -- note it is the SAME message whatever the
    // text is, because it only reports that the first character was not `{`.
    for (const [label, body] of [["a top-level array", "[1,2]"], ["not json at all", "hello"]]) {
      const r = await rawPost(body);
      console.log(`[5-E4] row22 ${label} -> ${r.status} ${r.text}`);
      expect(r.status, label).toBe(400);
      expect(JSON.parse(r.text).error_description, label)
          .toBe("A JSONObject text must begin with '{' at 1 [character 2 line 1]");
    }
  });

  test("row 18: If-None-Match is evaluated on PUT and DELETE too, and a match there is a 412", async ({ request }) => {
    // ⚠ Added 2026-07-29, while planning the handler: D6 gave If-None-Match to the GET path alone, on the
    // reasonable-looking grounds that only GET/HEAD can answer 304. Restlet evaluates it on EVERY verb --
    // `doConditionalHandle` runs before the annotated method whenever either header is present -- and on a
    // non-GET a match is a 412, not a 304. A handler that consults If-None-Match only on GET performs the
    // update instead. Not covered by any row 1-17.
    const matching = await newResourceSet(request, "5e4 inm put");
    const matchingTag = await currentEtag(request, matching.id);
    const refused = await request.put(`${RS}/${matching.id}`, {
      headers: { ...bearer(), "If-None-Match": matchingTag },
      data: { name: `${matching.name} x`, scopes: ["read"] },
    });
    const refusedBody = await refused.json();
    console.log(`[5-E4] row18 PUT If-None-Match:<current> -> ${refused.status()} ${JSON.stringify(refusedBody)}`);
    expect(refused.status()).toBe(412);
    expect(refusedBody).toEqual({ error: "precondition_failed" });
    // And it really did not update: the tag still matches what it was.
    expect(await currentEtag(request, matching.id)).toBe(matchingTag);

    // A NON-matching If-None-Match lets the precondition pass -- and then the endpoint's own
    // `isConditionalRequest()` finds no If-Match and takes row 4's path. So the two headers do not substitute
    // for one another: If-None-Match can only ever refuse a write here, never authorise one.
    const stale = await newResourceSet(request, "5e4 inm put stale");
    const rejected = await request.put(`${RS}/${stale.id}`, {
      headers: { ...bearer(), "If-None-Match": 'W/"12345"' },
      data: { name: `${stale.name} x`, scopes: ["read"] },
    });
    const rejectedBody = await rejected.json();
    console.log(`[5-E4] row18 PUT If-None-Match:<stale> -> ${rejected.status()} ${JSON.stringify(rejectedBody)}`);
    expect(rejected.status()).toBe(400);
    expect(rejectedBody).toEqual({
      error: "server_error",
      error_description: "precondition_failed (512) - Require If-Match header to update Resource Set",
    });

    const doomed = await newResourceSet(request, "5e4 inm delete");
    const doomedTag = await currentEtag(request, doomed.id);
    const undeleted = await request.delete(`${RS}/${doomed.id}`, {
      headers: { ...bearer(), "If-None-Match": doomedTag },
    });
    console.log(`[5-E4] row18 DELETE If-None-Match:<current> -> ${undeleted.status()}`);
    expect(undeleted.status()).toBe(412);
    expect(await undeleted.json()).toEqual({ error: "precondition_failed" });
    expect((await request.get(`${RS}/${doomed.id}`, { headers: bearer() })).status()).toBe(200);

    // ⚠ And a WINNING If-Match does not stop If-None-Match being consulted -- both are evaluated, in that
    // order, and either can fail the request. A client that round-trips the tag into both headers (harmless
    // under RFC 7232, where If-None-Match on a write means "only if absent") is refused.
    const both = await newResourceSet(request, "5e4 inm both");
    const bothTag = await currentEtag(request, both.id);
    const conflicted = await request.put(`${RS}/${both.id}`, {
      headers: { ...bearer(), "If-Match": bothTag, "If-None-Match": bothTag },
      data: { name: `${both.name} x`, scopes: ["read"] },
    });
    console.log(`[5-E4] row18 PUT If-Match + If-None-Match, both <current> -> ${conflicted.status()}`);
    expect(conflicted.status()).toBe(412);
    expect(await conflicted.json()).toEqual({ error: "precondition_failed" });
  });

  test("row 19: POST is conditional as well -- If-Match is evaluated before a create", async ({ request }) => {
    // ⚠ Added 2026-07-29 with row 18, and for the same reason: `doConditionalHandle` does not care which verb
    // it is guarding. D6 assigned conditional evaluation to GET/PUT/DELETE, so a port would create here where
    // Restlet answers 412.
    const star = await track(await request.post(RS, {
      headers: { ...bearer(), "If-Match": "*" }, data: { name: uniqueName("5e4 post star"), scopes: ["read"] },
    }));
    console.log(`[5-E4] row19 POST collection If-Match:* -> ${star.status()}`);
    expect(star.status()).toBe(201);

    // The collection representation carries NO tag (row 5), so `*` is the only If-Match that can ever pass
    // here: the wildcard is the one comparison that does not need a current tag. See row 20.
    const stale = await request.post(RS, {
      headers: { ...bearer(), "If-Match": 'W/"12345"' },
      data: { name: uniqueName("5e4 post stale"), scopes: ["read"] },
    });
    console.log(`[5-E4] row19 POST collection If-Match:<stale> -> ${stale.status()}`);
    expect(stale.status()).toBe(412);
    expect(await stale.json()).toEqual({ error: "precondition_failed" });

    // At the ITEM url the tag exists, so a matching If-Match passes and the create goes through -- with a new
    // id, exactly as row 16's unconditional POST does.
    const host = await newResourceSet(request, "5e4 post host");
    const hostTag = await currentEtag(request, host.id);
    const created201 = await track(await request.post(`${RS}/${host.id}`, {
      headers: { ...bearer(), "If-Match": hostTag },
      data: { name: uniqueName("5e4 post at item"), scopes: ["read"] },
    }));
    console.log(`[5-E4] row19 POST item If-Match:<its own tag> -> ${created201.status()}`);
    expect(created201.status()).toBe(201);
    expect((await created201.json())._id).not.toBe(host.id);

    const staleAtItem = await request.post(`${RS}/${host.id}`, {
      headers: { ...bearer(), "If-Match": 'W/"12345"' },
      data: { name: uniqueName("5e4 post at item stale"), scopes: ["read"] },
    });
    console.log(`[5-E4] row19 POST item If-Match:<stale> -> ${staleAtItem.status()}`);
    expect(staleAtItem.status()).toBe(412);
  });

  test("row 20: the collection representation carries no tag, which flips three conditional answers", async ({ request }) => {
    // ⚠ Added 2026-07-29. Rows 1-3b all measure the ITEM url. The collection's representation has no Tag at
    // all (row 5), and Restlet's comparator branches on exactly that: with no current tag the If-Match
    // fallback loop is skipped and the answer is the wildcard flag alone, while the If-None-Match wildcard --
    // dead on an item, which is why row 3 records `*` -> 200 -- becomes the only live branch. So the same
    // header gets OPPOSITE answers at the two urls, and a port with one code path for both cannot have both.

    // 412 carrying the full list. The exception filter only fills an EMPTY entity, and the conditional layer
    // ran the @Get to obtain the tag, so the array is already in hand -- the same shape as row 3b's item 412.
    const stale = await request.get(RS, { headers: { ...bearer(), "If-Match": 'W/"12345"' } });
    const staleBody = await stale.json();
    console.log(`[5-E4] row20 GET collection If-Match:<stale> -> ${stale.status()} ${staleBody.length} ids`);
    expect(stale.status()).toBe(412);
    expect(Array.isArray(staleBody)).toBe(true);        // NOT {"error":"precondition_failed"}
    expect(stale.headers()["content-type"]).toBe("application/json");
    expect(stale.headers()["etag"]).toBeUndefined();

    // ⚠ 304 where the item url answers 200 (row 3). This is the ONE place Restlet's noneMatch wildcard is
    // reachable, and it is reachable on the wire.
    const star = await request.get(RS, { headers: { ...bearer(), "If-None-Match": "*" } });
    console.log(`[5-E4] row20 GET collection If-None-Match:* -> ${star.status()}`
      + ` ct=${star.headers()["content-type"]}`);
    expect(star.status()).toBe(304);
    expect(star.headers()["content-type"]).toBeUndefined();
    expect(star.headers()["etag"]).toBeUndefined();     // no tag to echo, unlike row 3's item 304

    // ...and a concrete tag cannot match a representation that has none, so this is a plain 200.
    const concrete = await request.get(RS, { headers: { ...bearer(), "If-None-Match": 'W/"12345"' } });
    console.log(`[5-E4] row20 GET collection If-None-Match:<concrete> -> ${concrete.status()}`);
    expect(concrete.status()).toBe(200);

    // ⚠ And the RFC 7232 "create only if it does not exist" idiom is REFUSED by this endpoint: on a POST the
    // wildcard matches the tag-less collection, and a noneMatch match on a non-GET is a 412.
    const createIfAbsent = await request.post(RS, {
      headers: { ...bearer(), "If-None-Match": "*" },
      data: { name: uniqueName("5e4 create if absent"), scopes: ["read"] },
    });
    console.log(`[5-E4] row20 POST collection If-None-Match:* -> ${createIfAbsent.status()}`);
    expect(createIfAbsent.status()).toBe(412);
    expect(await createIfAbsent.json()).toEqual({ error: "precondition_failed" });
  });

  test("row 21: whether If-None-Match compares weakness depends on the VERB", async ({ request }) => {
    // ⚠ Added 2026-07-29 with rows 18-20. Restlet compares If-None-Match with
    // `checkWeakness = GET.equals(method) || HEAD.equals(method)`. Until row 18 that second argument looked
    // like a constant `true` -- the S1 review read it off the bytecode and concluded GET/HEAD were the only
    // verbs that could reach the comparison at all. They are not, so the flag really does vary, and the SAME
    // header gets opposite answers on a GET and on a PUT. This endpoint's tag is weak, which is what makes
    // the difference observable at all.
    const item = await newResourceSet(request, "5e4 inm weakness");
    const weak = await currentEtag(request, item.id);
    expect(weak).toMatch(/^W\/"-?\d+"$/);
    const strong = weak.replace(/^W\//, "");

    // GET: weakness IS compared, so the strong form does not match and the client gets the full body.
    // (This also converts the S1 review's bytecode-only claim into a measured row.)
    const read = await request.get(`${RS}/${item.id}`, { headers: { ...bearer(), "If-None-Match": strong } });
    console.log(`[5-E4] row21 GET If-None-Match:${strong} (strong form of ${weak}) -> ${read.status()}`);
    expect(read.status()).toBe(200);
    expect((await read.json())._id).toBe(item.id);

    // PUT: weakness is NOT compared, so the very same header matches -- and a noneMatch match on a non-GET
    // is row 18's 412. A helper with one weakness rule for both verbs cannot produce both of these.
    const write = await request.put(`${RS}/${item.id}`, {
      headers: { ...bearer(), "If-None-Match": strong }, data: { name: `${item.name} x`, scopes: ["read"] },
    });
    console.log(`[5-E4] row21 PUT If-None-Match:${strong} -> ${write.status()}`);
    expect(write.status()).toBe(412);
    expect(await write.json()).toEqual({ error: "precondition_failed" });

    // And the wildcard is strong-only on the noneMatch side too, exactly as it is for If-Match: `W/*` is a
    // weak tag named `*`, not Tag.ALL, so it fails the wildcard test and row 20's 412 does not happen.
    const weakStar = await track(await request.post(RS, {
      headers: { ...bearer(), "If-None-Match": "W/*" },
      data: { name: uniqueName("5e4 weak star"), scopes: ["read"] },
    }));
    console.log(`[5-E4] row21 POST collection If-None-Match:W/* -> ${weakStar.status()}`);
    expect(weakStar.status()).toBe(201);
  });
});

test.describe("/oauth2/connect/register dynamic client registration", () => {

  /**
   * Whatever this run registered. Every run mints a brand-new client, so without this a long-lived container
   * accumulates orphan agents until listing them slows the other fixtures down.
   *
   * Cleanup goes through the ADMIN api, not RFC 7592: OpenAM's connect/register implements the create and the
   * read but not the delete -- see the 405 asserted below.
   */
  let registeredClientId;

  test.afterAll(async ({ request }) => {
    if (registeredClientId) {
      await deleteClient(await getAdminToken(request), request, registeredClientId);
    }
  });

  test("registers a client and reads it back with the registration access token", async ({ request }) => {
    const created = await request.post(`${OPENAM_BASE}/oauth2/connect/register`, {
      headers: { Authorization: `Bearer ${pat}`, "Content-Type": "application/json" },
      data: { redirect_uris: ["http://dynamic.invalid/cb"], client_name: "e2e dynamic client" },
    });
    const client = await created.json();
    console.log(`[oauth2] connect/register -> ${created.status()} client_id=${client.client_id}`);
    registeredClientId = client.client_id;

    expect(created.status(), `dynamic registration failed: ${JSON.stringify(client)}`).toBe(201);
    expect(client.client_id).toBeTruthy();
    expect(client.client_secret).toBeTruthy();
    expect(client.redirect_uris).toEqual(["http://dynamic.invalid/cb"]);
    // The RFC 7592 handles: without these the client can never manage its own registration.
    expect(client.registration_access_token).toBeTruthy();
    expect(client.registration_client_uri)
      .toBe(`${OPENAM_BASE}/oauth2/connect/register?client_id=${client.client_id}`);

    const readBack = await request.get(client.registration_client_uri, {
      headers: { Authorization: `Bearer ${client.registration_access_token}` },
    });
    const stored = await readBack.json();
    console.log(`[oauth2] connect/register read-back -> ${readBack.status()}`);
    expect(readBack.status()).toBe(200);
    expect(stored.client_id).toBe(client.client_id);
    expect(stored.redirect_uris).toEqual(["http://dynamic.invalid/cb"]);

    // RFC 7592 deregistration is NOT implemented -- the Restlet resource maps GET and nothing else, so the
    // verb falls through to the framework's 405. Recorded rather than treated as a bug: the CHF port has to
    // reproduce it, and a port that silently starts accepting DELETE is a behaviour change either way.
    const deregistered = await request.delete(client.registration_client_uri, {
      headers: { Authorization: `Bearer ${client.registration_access_token}` },
    });
    console.log(`[oauth2] connect/register DELETE -> ${deregistered.status()}`);
    expect(deregistered.status()).toBe(405);
  });

  test("rejects registration without an access token", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/connect/register`, {
      headers: { "Content-Type": "application/json" },
      data: { redirect_uris: ["http://dynamic.invalid/cb"] },
    });
    const body = await response.json();
    console.log(`[oauth2] connect/register no token -> ${response.status()} ${JSON.stringify(body)}`);
    // Note the shape: a 400 access_denied, NOT a 401 -- registration validates the token itself rather than
    // sitting behind the protection filter.
    expect(response.status()).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.error_description).toBe("Access Token not valid");
  });
});

test.describe("OAuth2 device flow", () => {

  test("/oauth2/device/code issues a user code and a verification URI", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/device/code`, {
      form: { client_id: OIDC_CLIENT_ID, scope: "openid profile", response_type: "device_code" },
    });
    const body = await response.json();
    console.log(`[oauth2] device/code -> ${response.status()} user_code=${body.user_code}`);

    expect(response.status()).toBe(200);
    expect(body.device_code).toBeTruthy();
    expect(body.user_code).toBeTruthy();
    expect(body.verification_uri).toBe(`${OPENAM_BASE}/oauth2/device/user`);
    expect(body.interval).toBeGreaterThan(0);
    expect(body.expires_in).toBeGreaterThan(0);
  });

  test("/oauth2/device/code rejects a request missing required parameters", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/device/code`, {
      form: { client_id: OIDC_CLIENT_ID },
    });
    const body = await response.json();
    console.log(`[oauth2] device/code missing params -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(400);
    expect(body.error).toBe("bad_request");
    expect(body.error_description).toBe("client_id, scope and response_type are required parameters");
  });

  test("/oauth2/device/user serves the code-entry page with no user_code", async () => {
    // Anonymous, no user_code: the bare code-entry form is public. This is a FreeMarker render, so the port
    // has to keep the renderer wired (phase 5b-2).
    const anonCtx = await apiRequest.newContext();
    try {
      const response = await anonCtx.get(`${OPENAM_BASE}/oauth2/device/user`, { maxRedirects: 0 });
      const html = await response.text();
      console.log(`[oauth2] device/user no code -> ${response.status()} ct=${response.headers()["content-type"]} bytes=${html.length}`);
      expect(response.status()).toBe(200);
      expect(response.headers()["content-type"]).toContain("text/html");
      expect(html.length).toBeGreaterThan(0);
    } finally {
      await anonCtx.dispose();
    }
  });

  test("/oauth2/device/user sends an unauthenticated user_code submission to login", async ({ request }) => {
    const code = await (await request.post(`${OPENAM_BASE}/oauth2/device/code`, {
      form: { client_id: OIDC_CLIENT_ID, scope: "openid profile", response_type: "device_code" },
    })).json();

    const anonCtx = await apiRequest.newContext();
    try {
      const response = await anonCtx.get(
        `${OPENAM_BASE}/oauth2/device/user?${new URLSearchParams({ user_code: code.user_code })}`,
        { maxRedirects: 0 });
      const location = response.headers()["location"];
      console.log(`[oauth2] device/user unauthenticated -> ${response.status()} location=${location}`);
      // Verifying a code needs a resource owner, so this is the same 301->login contract /authorize has.
      expect(response.status()).toBe(301);
      expect(location.startsWith(`${OPENAM_BASE}/UI/Login`)).toBe(true);
      expect(new URL(location).searchParams.get("goto")).toContain("/oauth2/device/user");
    } finally {
      await anonCtx.dispose();
    }
  });

  test("/oauth2/device/user renders the verification page for an authenticated user", async ({ request }) => {
    const code = await (await request.post(`${OPENAM_BASE}/oauth2/device/code`, {
      form: { client_id: OIDC_CLIENT_ID, scope: "openid profile", response_type: "device_code" },
    })).json();

    const loginCtx = await apiRequest.newContext();
    let ssoToken;
    try {
      ssoToken = await getAuthToken(loginCtx, USERNAME, PASSWORD);
    } finally {
      await loginCtx.dispose();
    }
    const userCtx = await sessionContext(apiRequest, ssoToken);
    try {
      const response = await userCtx.get(
        `${OPENAM_BASE}/oauth2/device/user?${new URLSearchParams({ user_code: code.user_code })}`,
        { maxRedirects: 0 });
      const html = await response.text();
      console.log(`[oauth2] device/user authenticated -> ${response.status()} ct=${response.headers()["content-type"]} bytes=${html.length}`);
      expect(response.status()).toBe(200);
      expect(response.headers()["content-type"]).toContain("text/html");
      expect(html.length).toBeGreaterThan(0);
    } finally {
      await userCtx.dispose();
    }
  });
});

/**
 * Step 5-E3: the contract lock for /oauth2/device/user, recorded against LIVE RESTLET. Restlet stops serving
 * /oauth2 at the 5d-1 flip, so none of this is recordable afterwards
 * (docs/migration/restlet/phase-5b-2.md).
 *
 * Every value here was OBSERVED FIRST and only then asserted (2026-07-28, openam-e2e:5e3 built from this
 * tree). Do not "tidy" a string: the exact bytes ARE the oracle for the 5d-1 byte diff.
 *
 * Unlike the two OIDC session endpoints, this one is a BROWSER endpoint -- its doCatch calls the 4-arg
 * ExceptionHandler, so its errors are HTML pages. Row 3 is the proof, and it is why the CHF port extends the
 * browser base while the other two extend the JSON one.
 */
test.describe("OAuth2 device flow contract lock (5-E3, live Restlet)", () => {

  let demoCtx;

  /** The device pages carry their model in a `pageData`/`oauth2Data` literal, exactly like /authorize. */
  const pageValue = (html, key) =>
    (new RegExp(`(?:^|[{,\\s])${key}:\\s*"([^"]*)"`).exec(html) ?? [])[1];

  /** Drives a consent-requiring code to the consent page and returns the page plus its scraped csrf. */
  async function consentPage(request, extra = {}) {
    const code = await deviceCodeForConsent(request, DEVICE_CONSENT_CLIENT_ID, extra);
    const page = await demoCtx.get(
      `${OPENAM_BASE}/oauth2/device/user?${new URLSearchParams({ user_code: code.user_code })}`,
      { maxRedirects: 0 });
    const html = await page.text();
    return { code, page, html, csrf: pageValue(html, "csrf") };
  }

  test.beforeAll(async () => {
    const loginCtx = await apiRequest.newContext();
    let ssoToken;
    try {
      ssoToken = await getAuthToken(loginCtx, USERNAME, PASSWORD);
    } finally {
      await loginCtx.dispose();
    }
    demoCtx = await sessionContext(apiRequest, ssoToken);
  });

  test.afterAll(async () => {
    await demoCtx?.dispose();
  });

  test("row 1: an unknown user_code is a 200 form page carrying errorCode", async () => {
    // The one place this provider reports a failure with a 200: readDeviceCode's InvalidGrantException is
    // swallowed and re-rendered as the code-entry form with an error marker.
    const anonCtx = await apiRequest.newContext();
    try {
      for (const [who, ctx] of [["authenticated", demoCtx], ["anonymous", anonCtx]]) {
        const response = await ctx.get(`${OPENAM_BASE}/oauth2/device/user?user_code=ZZZZZZZZ`,
          { maxRedirects: 0 });
        const html = await response.text();
        console.log(`[5-E3] row1 unknown code (${who}) -> ${response.status()}`);
        expect(response.status(), who).toBe(200);
        expect(response.headers()["content-type"], who).toBe("text/html;charset=UTF-8");
        expect(html, who).toContain('errorCode: "not_found"');
        // NOTE: the anonymous case is a 200 too -- the code lookup fails BEFORE any session check, so an
        // unknown code never reaches the 301-to-login that a valid code triggers.
        expect(response.headers()["location"], who).toBeUndefined();
        // finding 8: no cache headers on this endpoint, ever.
        expect(response.headers()["cache-control"], who).toBeUndefined();
        expect(response.headers()["pragma"], who).toBeUndefined();
      }
    } finally {
      await anonCtx.dispose();
    }
  });

  test("row 4: the device consent page carries a model built ENTIRELY from request attributes", async ({ request }) => {
    // ⚠ This is the 5b-2 finding-2 / D2 oracle, and the reason ConsentPageRenderer's phase 1 cannot stay
    // realm-only. The device-flow GET carries ONLY user_code in the query, so every key below reached the
    // page through phase 1 -- the request ATTRIBUTES that addRequestParamsFromDeviceCode seeded from the
    // stored device code. A CHF renderer that copies only `realm` in phase 1 renders this page with every
    // <#if x??> false: a 200 that looks fine to a status assertion and is useless to a user.
    const { code, page, html, csrf } = await consentPage(request, {
      state: "devstate", nonce: "devnonce", ui_locales: "fr-CA",
    });
    console.log(`[5-E3] row4 consent page -> ${page.status()} bytes=${html.length}`);

    expect(page.status()).toBe(200);
    expect(page.headers()["content-type"]).toBe("text/html;charset=UTF-8");

    expect(csrf).toBeTruthy();
    // Seeded from the device code, NOT from the query -- the query has only user_code.
    expect(pageValue(html, "clientId")).toBe(DEVICE_CONSENT_CLIENT_ID);
    expect(pageValue(html, "scope")).toBe("openid profile");
    expect(pageValue(html, "state")).toBe("devstate");
    expect(pageValue(html, "nonce")).toBe("devnonce");
    expect(pageValue(html, "responseType")).toBe("code");
    // `ui_locales` OVERRIDES the Accept-Language-derived locale (page/authorize.ftl:43 prefers it), so a
    // renderer that drops the key silently changes the page's language rather than merely losing a field.
    expect(pageValue(html, "locale")).toBe("fr-CA");
    // realm rides along on the same attribute map, at the TOP level of pageData rather than inside oauth2Data.
    expect(html).toContain('realm: "\\/"');

    // Device-specific model keys /authorize never sets.
    expect(pageValue(html, "userCode")).toBe(code.user_code);
    expect(pageValue(html, "userName")).toBe("Demo Demo");
    expect(pageValue(html, "displayName")).toBe(DEVICE_CONSENT_CLIENT_ID);
    expect(html).toContain("isSaveConsentEnabled: true");
    expect(html).toContain('displayScopes: [ { "name": "openid" }');
    // The form posts back to the device endpoint carrying the user_code, with the context path included.
    expect(pageValue(html, "formTarget"))
      .toBe(`\\/openam/oauth2/device/user?user_code=${code.user_code}`);
  });

  test("row 2: decision=allow and decision=deny both render the thanks page", async ({ request }) => {
    for (const decision of ["allow", "deny"]) {
      const { code, csrf } = await consentPage(request);
      const response = await demoCtx.post(`${OPENAM_BASE}/oauth2/device/user`, {
        form: { decision, save_consent: "off", csrf, user_code: code.user_code },
        maxRedirects: 0,
      });
      const html = await response.text();
      console.log(`[5-E3] row2 decision=${decision} -> ${response.status()}`);
      expect(response.status(), decision).toBe(200);
      expect(response.headers()["content-type"], decision).toBe("text/html;charset=UTF-8");
      // BOTH decisions land on the thanks page: the allow/deny branch only chooses between updating and
      // deleting the device code, and the method then falls through to the same render. `deny` is NOT an
      // error page and NOT a redirect -- the difference is invisible on the wire and only observable by
      // polling /access_token afterwards.
      expect(html, decision).toContain("done: true");
      // Pre-existing quirk, reproduced deliberately: CodeThanks.ftl renders `realm : "${realm?js_string}/XUI"`,
      // so the realm arrives with /XUI appended. The CHF golden must keep this.
      expect(html, decision).toContain('realm : "\\//XUI"');
    }
  });

  test("row 3: a CSRF failure is an HTML error PAGE, not JSON (the 4-arg doCatch)", async ({ request }) => {
    // Closes 5b-2 open question 4. DeviceCodeVerificationResource.doCatch calls the 4-arg
    // ExceptionHandler.handle, which renders page/error.ftl -- so unlike endSession/checkSession, this
    // endpoint's errors are pages. That is what pins DeviceCodeVerificationHandler to the BROWSER base.
    for (const [name, csrf] of [["missing", undefined], ["wrong", "not-the-token"]]) {
      const { code } = await consentPage(request);
      const form = { decision: "allow", save_consent: "off", user_code: code.user_code };
      if (csrf) form.csrf = csrf;
      const response = await demoCtx.post(`${OPENAM_BASE}/oauth2/device/user`, { form, maxRedirects: 0 });
      const html = await response.text();
      console.log(`[5-E3] row3 csrf ${name} -> ${response.status()} ct=${response.headers()["content-type"]}`);

      expect(response.status(), name).toBe(400);
      expect(response.headers()["content-type"], name).toBe("text/html;charset=UTF-8");
      expect(html, name).toContain("<title>OAuth2 Error Page</title>");
      expect(html, name).toContain('message: "bad_request"');
      // No redirect: the error is rendered, never sent anywhere.
      expect(response.headers()["location"], name).toBeUndefined();
    }
  });

  test("row 11: PUT on /device/user is Restlet's own 405 with a CREST body", async ({ request }) => {
    // Same shape as the two OIDC session endpoints (see the 5-E3 block in oidc-test.spec.mjs): no
    // OAuth2Filter wrapper, so no OAuth2-shaped 405. This body is CREST, not `method_not_allowed`.
    const response = await request.fetch(`${OPENAM_BASE}/oauth2/device/user`,
      { method: "PUT", maxRedirects: 0 });
    const body = await response.json();
    console.log(`[5-E3] row11 PUT /device/user -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(405);
    expect(response.headers()["content-type"]).toContain("application/json");
    expect(body.code).toBe(405);
    expect(body.reason).toBe("Method Not Allowed");
    expect(body.error).toBeUndefined();
    expect(response.headers()["cache-control"]).toBeUndefined();
  });
});

test.describe("/oauth2/token/revoke", () => {

  test("revokes an access token so it stops validating", async ({ request }) => {
    const token = await protectionApiToken(request, RS_CLIENT_ID, USERNAME, PASSWORD);

    const before = await request.get(`${OPENAM_BASE}/oauth2/tokeninfo`, {
      params: { access_token: token }, headers: { Accept: "application/json" },
    });
    expect(before.status()).toBe(200);

    const revoked = await request.post(`${OPENAM_BASE}/oauth2/token/revoke`, {
      form: { token, client_id: RS_CLIENT_ID, client_secret: RS_CLIENT_SECRET },
    });
    console.log(`[oauth2] token/revoke -> ${revoked.status()} ${await revoked.text()}`);
    expect(revoked.status()).toBe(200);

    const after = await request.get(`${OPENAM_BASE}/oauth2/tokeninfo`, {
      params: { access_token: token }, headers: { Accept: "application/json" },
    });
    const afterBody = await after.json();
    console.log(`[oauth2] tokeninfo after revoke -> ${after.status()} ${JSON.stringify(afterBody)}`);
    // The revocation must actually take effect, not just answer 200.
    expect(after.status()).toBe(401);
    expect(afterBody.error).toBe("invalid_token");
  });

  test("rejects a revocation with no token parameter", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/token/revoke`, {
      form: { client_id: RS_CLIENT_ID, client_secret: RS_CLIENT_SECRET },
    });
    const body = await response.json();
    console.log(`[oauth2] token/revoke no token -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toBe("Missing parameter: token");
  });

  test("rejects a revocation with a bad client secret", async ({ request }) => {
    const response = await request.post(`${OPENAM_BASE}/oauth2/token/revoke`, {
      form: { token: "irrelevant", client_id: OIDC_CLIENT_ID, client_secret: "wrong-secret" },
    });
    const body = await response.json();
    console.log(`[oauth2] token/revoke bad secret -> ${response.status()} ${JSON.stringify(body)}`);
    expect(response.status()).toBe(400);
    expect(body.error).toBe("invalid_client");
    expect(body.error_description).toBe("Client authentication failed");
  });
});
