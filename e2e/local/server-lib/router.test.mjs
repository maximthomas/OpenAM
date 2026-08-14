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

/**
 * What the two surfaces answer, over a real socket and a real directory.
 *
 *     node --test local/server-lib/
 *
 * A real server on an ephemeral port and a real tree in a temporary directory, because the things
 * worth checking here are the ones a mocked `res` would agree with and a browser would not: that a
 * symlink out of the tree is refused (which needs a filesystem), that an unreadable file fails
 * *before* the 200 headers rather than after (which needs a real response), that a directory
 * without its trailing slash redirects, and that `?v=…` is not part of a file name.
 *
 * Every case here is a request the XUI makes or an attack on the one that serves it. None of them
 * need the AM: the administrative reads come out of the committed capture, authentication out of
 * task 2.7 (auth.test.mjs), and what is left is 501. The "what is not served" block says so.
 *
 * The last block is the control surface — reset, task 2.13 — which is the one thing here that is
 * not an AM request at all.
 */

import assert from "node:assert/strict";
import { createServer } from "node:http";
import { chmod, mkdtemp, mkdir, realpath, symlink, writeFile } from "node:fs/promises";
import { after, before, describe, it } from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

import { ADMIN_PASS, ADMIN_USER, PASSWORD, USERNAME } from "../../common/openam-commons.mjs";
import { createRequestHandler } from "./router.mjs";
import { buildBaselineState } from "./state.mjs";

const CAPTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "capture");

const MAIN_JS = "define([], function () { return {}; });\n";
const INDEX_HTML = "<!DOCTYPE html><title>XUI</title>\n";

/** Root can read a file whose mode is 000, so the unreadable case has nothing to prove there. */
const asRoot = process.getuid?.() === 0;

let server;
let origin;
let outside;

/**
 * A tree with the shapes that matter: a nested directory, a link inside the tree, a link out of
 * it, and a file the process may not read.
 */
async function buildTree () {
    const base = await realpath(await mkdtemp(join(tmpdir(), "xui-tree-")));
    const root = join(base, "compiled");
    outside = join(base, "OUTSIDE.txt");

    await mkdir(join(root, "config"), { recursive: true });
    await writeFile(join(root, "index.html"), INDEX_HTML);
    await writeFile(join(root, "main.js"), MAIN_JS);
    await writeFile(join(root, "config", "Constants.js"), MAIN_JS);
    await writeFile(join(root, "config", "index.html"), INDEX_HTML);
    await writeFile(outside, "secret\n");

    await symlink(outside, join(root, "linked-out.txt"));
    await symlink(join(base), join(root, "linked-dir"));
    await symlink(join(root, "main.js"), join(root, "linked-in.js"));

    await writeFile(join(root, "unreadable.js"), MAIN_JS);
    await chmod(join(root, "unreadable.js"), 0o000);

    return root;
}

/** The response, with its body, from a request to the running server. */
async function get (path, init = {}) {
    const response = await fetch(`${origin}${path}`, { redirect: "manual", ...init });
    return {
        status: response.status,
        type: response.headers.get("content-type"),
        length: response.headers.get("content-length"),
        cache: response.headers.get("cache-control"),
        location: response.headers.get("location"),
        allow: response.headers.get("allow"),
        body: await response.text(),
    };
}

/**
 * A live session token, taken through the door the fixtures use.
 *
 * The one-call header authentication `common/openam-commons.mjs` performs, rather than a reach into
 * the store: a test that needs a session should get one the way something under test gets one, so
 * that "this route requires a session" and "this is what a session looks like" cannot drift apart.
 */
async function sessionToken (username, password) {
    const response = await get("/openam/json/authenticate", {
        method: "POST",
        headers: { "X-OpenAM-Username": username, "X-OpenAM-Password": password },
    });
    assert.equal(response.status, 200);
    return JSON.parse(response.body).tokenId;
}

before(async () => {
    const root = await buildTree();
    // The same call twice, as server.mjs makes it: the state to start from, and how the reset
    // endpoint gets another. See the control-surface block at the end of this file.
    const buildState = () =>
        buildBaselineState(CAPTURE_DIR, { context: "openam", hostname: "localhost" });
    const handle = createRequestHandler({
        root,
        context: "openam",
        state: buildState(),
        rebuildState: buildState,
    });
    server = createServer((req, res) => {
        handle(req, res).catch((error) => {
            res.writeHead(500);
            res.end(error.message);
        });
    });
    await new Promise((ready) => server.listen(0, "127.0.0.1", ready));
    origin = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
    server.closeAllConnections();
    server.close();
});

describe("the XUI surface", () => {
    it("serves the tree's index at the mount", async () => {
        const response = await get("/openam/XUI/");
        assert.equal(response.status, 200);
        assert.equal(response.type, "text/html;charset=UTF-8");
        assert.equal(response.body, INDEX_HTML);
    });

    it("serves a module with its type and length", async () => {
        const response = await get("/openam/XUI/main.js");
        assert.equal(response.status, 200);
        assert.equal(response.type, "text/javascript;charset=UTF-8");
        assert.equal(response.length, String(Buffer.byteLength(MAIN_JS)));
        assert.equal(response.body, MAIN_JS);
    });

    it("ignores the cache-busting query RequireJS appends to every module", async () => {
        // index.html sets urlArgs, so nothing arrives without one of these.
        const response = await get("/openam/XUI/config/Constants.js?v=16.2.0-SNAPSHOT");
        assert.equal(response.status, 200);
        assert.equal(response.body, MAIN_JS);
    });

    it("redirects the bare mount so relative script sources resolve", async () => {
        // At /openam/XUI the browser resolves index.html's relative <script src="libs/…"> against
        // /openam/, and RequireJS is never loaded.
        const response = await get("/openam/XUI");
        assert.equal(response.status, 302);
        assert.equal(response.location, "/openam/XUI/");
    });

    it("redirects a directory to its trailing slash, keeping the query", async () => {
        const response = await get("/openam/XUI/config?v=1");
        assert.equal(response.status, 302);
        assert.equal(response.location, "/openam/XUI/config/?v=1");
    });

    it("serves a directory's index rather than listing it", async () => {
        const response = await get("/openam/XUI/config/");
        assert.equal(response.status, 200);
        assert.equal(response.body, INDEX_HTML);
    });

    it("tells the browser to keep nothing, because the tree changes underneath it", async () => {
        assert.equal((await get("/openam/XUI/main.js")).cache, "no-store");
        assert.equal((await get("/openam/XUI/nope.js")).cache, "no-store");
    });

    it("answers HEAD with the headers and no body", async () => {
        const response = await get("/openam/XUI/main.js", { method: "HEAD" });
        assert.equal(response.status, 200);
        assert.equal(response.length, String(Buffer.byteLength(MAIN_JS)));
        assert.equal(response.body, "");
    });

    it("refuses a method the tree has no meaning for", async () => {
        const response = await get("/openam/XUI/main.js", { method: "POST" });
        assert.equal(response.status, 405);
        assert.equal(response.allow, "GET, HEAD");
    });

    it("404s a file that is not there", async () => {
        const response = await get("/openam/XUI/missing.js");
        assert.equal(response.status, 404);
        assert.match(response.body, /not in the served XUI tree/);
    });
});

describe("what the XUI surface refuses to read", () => {
    it("follows a link that stays inside the tree", async () => {
        const response = await get("/openam/XUI/linked-in.js");
        assert.equal(response.status, 200);
        assert.equal(response.body, MAIN_JS);
    });

    it("refuses a link out of the tree", async () => {
        // resolve() is string arithmetic and cannot see this; only the real path can.
        const response = await get("/openam/XUI/linked-out.txt");
        assert.equal(response.status, 403);
        assert.doesNotMatch(response.body, /secret/);
    });

    it("refuses a path through a linked directory", async () => {
        const response = await get("/openam/XUI/linked-dir/OUTSIDE.txt");
        assert.equal(response.status, 403);
        assert.doesNotMatch(response.body, /secret/);
    });

    it("refuses an encoded traversal", async () => {
        const response = await get("/openam/XUI/..%2f..%2f..%2fetc/passwd");
        assert.equal(response.status, 400);
        assert.match(response.body, /escapes the served tree/);
    });

    it("refuses a NUL byte", async () => {
        const response = await get("/openam/XUI/main.js%00.txt");
        assert.equal(response.status, 400);
        assert.match(response.body, /NUL byte/);
    });

    it("fails an unreadable file before the headers, not after", { skip: asRoot }, async () => {
        // The regression: stat, writeHead(200, {Content-Length}), then open. The client got a 200
        // with a declared length and an empty body, which surfaces as ERR_EMPTY_RESPONSE and a
        // RequireJS script error with no cause anywhere.
        const response = await get("/openam/XUI/unreadable.js");
        assert.equal(response.status, 403);
        assert.equal(response.type, "text/plain;charset=UTF-8");
        assert.match(response.body, /cannot be read/);
    });
});

describe("the REST surface", () => {
    it("answers an administrative read from the baseline state", async () => {
        // Only that the mount reaches the state at all -- that what comes back agrees with the
        // capture is state.test.mjs's business, where it can be asserted against the recording.
        const response = await get("/openam/json/global-config/realms?_queryFilter=true");
        assert.equal(response.status, 200);
        assert.equal(response.type, "application/json;charset=UTF-8");
        assert.deepEqual(JSON.parse(response.body).result.map((realm) => realm.name), ["/"]);
    });

    it("answers the bootstrap's own two documents", async () => {
        // The first request the XUI makes, and the one every later one is chained off. Only that
        // the mount reaches it; what is *in* the document is state.test.mjs's, against the
        // recording.
        const configuration = await get("/openam/json/serverinfo/*");
        assert.equal(configuration.status, 200);
        assert.equal(configuration.type, "application/json;charset=UTF-8");
        assert.equal(JSON.parse(configuration.body).cookieName, "iPlanetDirectoryPro");

        const version = await get("/openam/json/serverinfo/version");
        assert.equal(version.status, 200);
        assert.equal(JSON.parse(version.body).version, "16.2.0-SNAPSHOT");
    });

    it("carries a realm write from the wire into the state and back out of a read", async () => {
        // Task 2.10 over HTTP. What the store does with a realm is state.test.mjs's; this is that
        // a `_action=create` body arrives parsed, and that the realm it made is in the listing the
        // next request gets -- the whole of D15's "not a replayer" as a client can observe it.
        const created = await get("/openam/json/global-config/realms?_action=create", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: "wire", parentPath: "/", active: true, aliases: [] }),
        });
        assert.equal(created.status, 201);
        const realmId = JSON.parse(created.body)._id;

        const listed = await get("/openam/json/global-config/realms?_queryFilter=true");
        assert.deepEqual(JSON.parse(listed.body).result.map((realm) => realm.name),
            ["/", "wire"]);

        const removed = await get(`/openam/json/global-config/realms/${realmId}`,
            { method: "DELETE" });
        assert.equal(removed.status, 200);
        const after = await get("/openam/json/global-config/realms?_queryFilter=true");
        assert.deepEqual(JSON.parse(after.body).result.map((realm) => realm.name), ["/"]);
    });

    it("addresses a realm it created itself by the name in the URL", async () => {
        // The property the console's create depends on and that no unit test can reach: the segment
        // `parseRoute` pulls out of the URL has to be the same string `createRealm` filed the realm
        // under. EditRealmView's save is two writes, and it reports a failure of this second one as
        // a failed create -- so if the URL segment and the store key ever stopped agreeing, the
        // console would say the realm was not created while the listing showed it was.
        const created = await get("/openam/json/global-config/realms?_action=create", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: "paired", parentPath: "/", active: true, aliases: [] }),
        });
        assert.equal(created.status, 201);

        const saved = await get(
            "/openam/json/realms/root/realms/paired/realm-config/authentication",
            {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ statelessSessionsEnabled: true }),
            },
        );
        assert.equal(saved.status, 200);
        // Not merely "not a 404": the realm the write landed on is the one that was created, and
        // the recorded sections a later render reads from are still there.
        assert.ok(JSON.parse(saved.body).general);

        await get(`/openam/json/global-config/realms/${JSON.parse(created.body)._id}`,
            { method: "DELETE" });
    });

    it("carries a service write from the wire, and recomputes what is creatable after it", async () => {
        // Task 2.11 over HTTP, and the half no unit test reaches: that `rest.mjs`'s four new cases
        // dispatch, and that the verbatim documents are offered before them -- a `schema` that fell
        // through to the write switch would 501, and a `getCreatableTypes` served from `statics`
        // would answer the recording forever. Both are one string away in the same switch.
        const created = await get("/openam/json/global-config/realms?_action=create", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: "wired", parentPath: "/", active: true, aliases: [] }),
        });
        assert.equal(created.status, 201);
        const realm = "/openam/json/realms/root/realms/wired/realm-config/services";
        const creatable = async () => JSON.parse((await get(`${realm}?_action=getCreatableTypes`,
            { method: "POST" })).body).result.map((type) => type._id);

        const before = await creatable();
        assert.ok(before.includes("baseurl"));
        // Served from the recording, not from the switch below it.
        assert.equal((await get(`${realm}/baseurl?_action=schema`, { method: "POST" })).status, 200);

        const service = await get(`${realm}/baseurl?_action=create`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ extensionClassName: "", fixedValue: "https://wire.invalid" }),
        });
        assert.equal(service.status, 201);
        assert.equal(JSON.parse(service.body).fixedValue, "https://wire.invalid");

        // The state-dependent half, over the wire and after a write the same process made.
        assert.deepEqual(await creatable(), before.filter((type) => type !== "baseurl"));

        const saved = await get(`${realm}/baseurl`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ...JSON.parse(service.body), fixedValue: "https://edited.invalid" }),
        });
        assert.equal(saved.status, 200);
        assert.equal(JSON.parse((await get(`${realm}/baseurl`)).body).fixedValue,
            "https://edited.invalid");

        const removed = await get(`${realm}/baseurl`, { method: "DELETE" });
        assert.equal(removed.status, 200);
        assert.deepEqual(JSON.parse(removed.body), { success: true });
        // Offered again, which is what makes two runs of xui-services.spec.mjs against one process
        // ask for the same thing twice.
        assert.deepEqual(await creatable(), before);

        await get(`/openam/json/global-config/realms/${JSON.parse(created.body)._id}`,
            { method: "DELETE" });
    });

    it("reaches the same service through the legacy realm-as-query path", async () => {
        // The console uses the realm-scoped path and the fixtures use this one, so both families
        // have to land on one resource. state.test.mjs pins that `parseRoute` reads them the same;
        // this is that the write routes really are reachable through the second.
        const created = await get("/openam/json/global-config/realms?_action=create", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: "legacy", parentPath: "/", active: true, aliases: [] }),
        });
        assert.equal(created.status, 201);

        const service = await get(
            "/openam/json/realm-config/services/baseurl?_action=create&realm=%2Flegacy",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ fixedValue: "https://legacy.invalid" }),
            },
        );
        assert.equal(service.status, 201);
        // Written through one path, read back through the other.
        const read = await get(
            "/openam/json/realms/root/realms/legacy/realm-config/services/baseurl");
        assert.equal(read.status, 200);
        assert.equal(JSON.parse(read.body).fixedValue, "https://legacy.invalid");

        await get(`/openam/json/global-config/realms/${JSON.parse(created.body)._id}`,
            { method: "DELETE" });
    });

    it("keeps an action the request list does not record off the service routes", async () => {
        // The service analogue of the realms case below. `create` and `getCreatableTypes` are the
        // only two actions REQUESTS.md records here; anything else is out of scope by construction,
        // and 501 rather than a create is what says the switch discriminates on the action at all.
        // The realm deliberately does not exist: the action gate is before any state lookup, so a
        // 404 here would mean the action had been accepted and only the realm had saved us.
        const collection = await get(
            "/openam/json/realms/root/realms/alpha/realm-config/services?_action=somethingElse",
            { method: "POST", body: "{}" },
        );
        assert.equal(collection.status, 501);

        const member = await get(
            "/openam/json/realms/root/realms/alpha/realm-config/services/baseurl?_action=update",
            { method: "POST", body: "{}" },
        );
        assert.equal(member.status, 501);
    });

    it("answers a body that is not JSON with 400 rather than acting on nothing", async () => {
        const response = await get("/openam/json/global-config/realms?_action=create", {
            method: "POST",
            body: "{not json",
        });

        assert.equal(response.status, 400);
        assert.equal(JSON.parse(response.body).reason, "Bad Request");
    });

    it("keeps an action the request list does not record out of the write path", async () => {
        // `create` is the only action REQUESTS.md records against this collection. Any other is
        // out of scope by construction, and out of scope reads as 501 here as it does everywhere.
        const response = await get("/openam/json/global-config/realms?_action=somethingElse", {
            method: "POST",
            body: JSON.stringify({ name: "never" }),
        });

        assert.equal(response.status, 501);
        const listed = await get("/openam/json/global-config/realms?_queryFilter=true");
        assert.deepEqual(JSON.parse(listed.body).result.map((realm) => realm.name), ["/"]);
    });

    it("answers the profile read that ends a login, because roles are what leave #login", async () => {
        // Asserted here rather than left to the browser specs because nothing else in
        // `npm run test:server` covers the route: break the keying or the route shape and every
        // unit test stays green while every console spec fails in `waitForURL`, which is a long way
        // from the cause. `RESTLoginHelper.getLoggedUser` fetches this last, and RealmsRoutes gates
        // every admin route on the roles it carries -- which the administrator gets here because
        // this is a read of their own record. See `profileFor`.
        const response = await get("/openam/json/realms/root/users/amadmin", {
            headers: { iPlanetDirectoryPro: await sessionToken(ADMIN_USER, ADMIN_PASS) },
        });
        assert.equal(response.status, 200);
        assert.equal(response.type, "application/json;charset=UTF-8");
        assert.ok(JSON.parse(response.body).roles.includes("ui-realm-admin"));
    });

    it("does not answer a profile to a request carrying no session", async () => {
        // Task 2.12's tightening of the read 2.10 borrowed, which answered whoever asked because
        // every caller it had was logged in already. `Access Denied` rather than a 404 or an empty
        // document: it is the one answer this server gives an anonymous caller on every
        // session-bearing route, and the specs prove a logout by asking one of them.
        const read = await get(`/openam/json/realms/root/users/${USERNAME}`);
        assert.equal(read.status, 401);
        assert.equal(JSON.parse(read.body).message, "Access Denied");

        const written = await get(`/openam/json/realms/root/users/${USERNAME}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ givenName: ["Nobody"] }),
        });
        assert.equal(written.status, 401);
    });

    it("carries a profile save from the wire into the state and back out of a read", async () => {
        // Task 2.12 over HTTP, and the realm write's analogue: what the store does with a profile
        // is state.test.mjs's, and this is that the PUT body arrives parsed and that the read after
        // it answers with what was saved. Restored at the end, because every test in this file
        // shares one state.
        const token = await sessionToken(USERNAME, PASSWORD);
        const headers = { "Content-Type": "application/json", iPlanetDirectoryPro: token };

        const saved = await get(`/openam/json/realms/root/users/${USERNAME}`, {
            method: "PUT", headers, body: JSON.stringify({ givenName: "Edited" }),
        });
        assert.equal(saved.status, 200);
        // A user saving their own profile gets their own roles back, which is what Backbone feeds
        // through `UserModel.parse` to rebuild `uiroles` from.
        assert.deepEqual(JSON.parse(saved.body).roles, ["ui-self-service-user"]);

        const read = await get(`/openam/json/realms/root/users/${USERNAME}`,
            { headers: { iPlanetDirectoryPro: token } });
        assert.equal(read.status, 200);
        // A scalar, because a value is stored as it arrives and the console sends scalars. AM would
        // answer `["Edited"]`; see `updateUser` for why that divergence is left standing.
        assert.equal(JSON.parse(read.body).givenName, "Edited");

        const restored = await get(`/openam/json/realms/root/users/${USERNAME}`, {
            method: "PUT", headers, body: JSON.stringify({ givenName: ["Demo"] }),
        });
        assert.equal(restored.status, 200);
        assert.deepEqual(JSON.parse(restored.body).givenName, ["Demo"]);
    });

    it("answers a profile HEAD as the read, with the body elided", async () => {
        // The route takes GET, HEAD and PUT together, so a HEAD that fell through to the fallback
        // would answer the labelled 501 -- "this resource is not implemented" about one that is.
        // `sendJson` drops the body itself; this is that HEAD reaches the same handler.
        const headers = { iPlanetDirectoryPro: await sessionToken(ADMIN_USER, ADMIN_PASS) };
        const read = await get(`/openam/json/realms/root/users/${USERNAME}`, { headers });
        const head = await get(`/openam/json/realms/root/users/${USERNAME}`,
            { method: "HEAD", headers });

        assert.equal(head.status, 200);
        assert.equal(head.body, "");
        assert.equal(head.length, read.length);
    });

    it("refuses a profile save whose body is not a JSON object of attributes", async () => {
        const headers = { "Content-Type": "application/json",
            iPlanetDirectoryPro: await sessionToken(USERNAME, PASSWORD) };

        const array = await get(`/openam/json/realms/root/users/${USERNAME}`,
            { method: "PUT", headers, body: JSON.stringify(["givenName"]) });
        assert.equal(array.status, 400);

        // A bodyless PUT is the same answer by the same rule: `readDocument` reports no body as
        // `undefined`, which has no attributes to merge either. `updateRealm` answers that one
        // 200-unchanged; the divergence is noted in `updateUser` rather than papered over here.
        const empty = await get(`/openam/json/realms/root/users/${USERNAME}`,
            { method: "PUT", headers });
        assert.equal(empty.status, 400);
    });

    it("holds the profile routes to the shapes the request list records", async () => {
        const token = await sessionToken(ADMIN_USER, ADMIN_PASS);

        // Neither a realm-scoped profile nor an account outside this server's two-entry directory
        // is in REQUESTS.md, and both stay the labelled 501 rather than becoming a 404 this server
        // invented -- `RESTLoginHelper` reads a 404 here as "the session names a user who does not
        // exist" and clears the session cookie for it. See `state.user`.
        const scoped = await get("/openam/json/realms/root/realms/alpha/users/amadmin",
            { headers: { iPlanetDirectoryPro: token } });
        assert.equal(scoped.status, 501);

        const stranger = await get("/openam/json/realms/root/users/nobody",
            { headers: { iPlanetDirectoryPro: token } });
        assert.equal(stranger.status, 501);

        // Password change is the console's own action on this member, and is out of scope by the
        // rule everything else here follows: REQUESTS.md does not record it. D13's Non-Goal.
        const password = await get(
            `/openam/json/realms/root/users/${USERNAME}?_action=changePassword`, {
                method: "POST",
                headers: { "Content-Type": "application/json", iPlanetDirectoryPro: token },
                body: JSON.stringify({
                    username: USERNAME, currentpassword: "a", userpassword: "b",
                }),
            });
        assert.equal(password.status, 501);
    });

    it("answers a path it does not implement with 501, in AM's error envelope", async () => {
        // The realm-scoped site configuration, which task 2.9 deliberately did not answer: it is
        // not in the capture (REQUESTS.md:151-152, reached only by the @deployed-am theming spec),
        // and the alternative to this 501 is a `realm` this server invented -- which ThemeManager
        // would resolve a theme from, and which the re-record-and-diff job cannot catch because
        // there is nothing recorded to diff it against.
        const response = await get("/openam/json/realms/root/realms/alpha/serverinfo/*");
        assert.equal(response.status, 501);
        assert.equal(response.type, "application/json;charset=UTF-8");
        assert.deepEqual(Object.keys(JSON.parse(response.body)).sort(),
            ["code", "message", "reason"]);
        assert.equal(JSON.parse(response.body).code, 501);
    });

    it("names the request that got it, because that is the first thing asked", async () => {
        // A sub-schema instance. Out of scope by decision rather than by deferral -- no type this
        // server serves has sub-schema types, xui-services.spec.mjs pins that by asserting the tab
        // bar which would lead to one is absent, and there is no later task holding them -- which is
        // what makes it a stable subject, in the sense the test below argues for. This was
        // `PUT …/services/baseurl` until task 2.11 turned that into a real route, at which point it
        // stopped asserting anything about the 501 and started asserting a 404.
        const response = await get(
            "/openam/json/realms/root/realm-config/services/audit/handler", { method: "PUT" },
        );
        assert.equal(response.status, 501);
        assert.match(JSON.parse(response.body).message, /PUT \/openam\/json\/realms\/root/);
    });

    it("does not let a caller past a route it does not implement", async () => {
        // A login into a named chain or module. Every spec that drives one is @deployed-am and this
        // server holds only the recorded DataStore1 chain, so the route is deliberately not
        // implemented and is not scheduled to be -- which is what makes it a stable guard, unlike a
        // not-yet route that will quietly turn into a 200 two tasks from now and stop asserting
        // anything. Answering it with the default chain's callbacks would let a caller log in
        // through a chain that was never asked for. 501 rather than 404 because the resource is not
        // missing: this server does not serve it.
        const response = await fetch(
            `${origin}/openam/json/realms/root/authenticate?authIndexType=service`
            + "&authIndexValue=ldapService",
            { method: "POST" },
        );

        assert.equal(response.status, 501);
        assert.equal(response.headers.get("set-cookie"), null);
    });

    it("answers the session routes without establishing or ending anything by itself", async () => {
        // Reached with no session, they are 401 rather than 501 (task 2.8). No Set-Cookie on
        // either: the only response in this server that establishes a session is a successful
        // authenticate, and the only one that ends a session ends it server-side -- both
        // auth.test.mjs's, where the sessions to resolve exist.
        for (const path of ["/openam/json/sessions?_action=getSessionInfo",
            "/openam/json/sessions?_action=logout"]) {
            const response = await fetch(`${origin}${path}`, { method: "POST" });

            assert.equal(response.status, 401, path);
            assert.equal(response.headers.get("set-cookie"), null, path);
        }
    });
});

describe("everything else", () => {
    it("sends someone who opened the port to the UI", async () => {
        for (const path of ["/", "/openam", "/openam/"]) {
            const response = await get(path);
            assert.equal(response.status, 302, path);
            assert.equal(response.location, "/openam/XUI/", path);
        }
    });

    it("404s an unknown path, naming the two surfaces it does serve", async () => {
        const response = await get("/openam/oauth2/authorize");
        assert.equal(response.status, 404);
        assert.match(response.body, /\/openam\/XUI\//);
        assert.match(response.body, /\/openam\/json\//);
    });

    it("does not treat a path that merely starts like a mount as one", async () => {
        // "/openam/XUIx" is not under "/openam/XUI", and "/openam/jsonx" is not the REST surface.
        assert.equal((await get("/openam/XUIx/main.js")).status, 404);
        assert.equal((await get("/openam/jsonx/serverinfo")).status, 404);
    });

    it("gives every response a length, so nothing is chunked into a guess", async () => {
        // One of each branch that writes a response: redirect, static hit, JSON, 501, static miss
        // and 404. The 501 has to be a path that stays one -- `serverinfo/*` itself is a 200 now.
        for (const path of ["/", "/openam/XUI/main.js", "/openam/json/serverinfo/*",
            "/openam/json/realms/root/realms/alpha/serverinfo/*",
            "/openam/XUI/missing.js", "/openam/nowhere"]) {
            assert.notEqual((await get(path)).length, null, path);
        }
    });

    it("survives a malformed Host header, which the HTTP parser lets through", async () => {
        // Parsing the target against the Host header made this a 400 that blamed the URL.
        const response = await get("/openam/XUI/main.js", { headers: { Host: "a b" } });
        assert.equal(response.status, 200);
    });
});

/**
 * Task 2.13. Deliberately the last block in the file, because these are the only tests here that
 * leave the shared server in a different state than they found it — and the only ones that do not
 * clean up after themselves, which is the point: every write above is followed by its own DELETE
 * because until now that was the only way back, and these prove it is no longer.
 */
describe("the control surface", () => {
    /** The realm names the store answers with, which is the cheapest observation of "baseline". */
    async function realmNames () {
        const listed = await get("/openam/json/global-config/realms?_queryFilter=true");
        assert.equal(listed.status, 200);
        return JSON.parse(listed.body).result.map((realm) => realm.name);
    }

    async function reset () {
        const response = await get("/local-api-server/reset", { method: "POST" });
        assert.equal(response.status, 200, response.body);
        return JSON.parse(response.body);
    }

    it("discards a write that a test left behind, and says what it went back to", async () => {
        const created = await get("/openam/json/global-config/realms?_action=create", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: "residue", parentPath: "/", active: true, aliases: [] }),
        });
        assert.equal(created.status, 201);
        const realmId = JSON.parse(created.body)._id;
        assert.deepEqual(await realmNames(), ["/", "residue"]);

        const report = await reset();

        assert.equal(report.reset, true);
        // The count is the one the startup banner prints, so a caller can see the baseline it got
        // without a second request -- and it is asserted against the listing, so the two cannot
        // disagree about what "back to baseline" meant.
        assert.equal(report.realms, 1);
        assert.equal(typeof report.milliseconds, "number");
        assert.deepEqual(await realmNames(), ["/"]);
        // Not merely absent from the listing: the realm's own id no longer addresses anything, which
        // is the difference between a listing rebuilt and a store emptied.
        assert.equal((await get(`/openam/json/global-config/realms/${realmId}`)).status, 404);
    });

    it("takes back a half-finished write, including one made to a baseline document", async () => {
        // The failure the requirement names. The console's create is two writes -- POST the realm,
        // then PUT its `realm-config/authentication` -- so a test that dies between them leaves a
        // realm no teardown knows about. The second write here is the harder half: it lands on
        // *root*, a realm that came out of the capture rather than out of a create, so nothing can
        // put it right by being deleted. Only rebuilding the baseline does.
        const created = await get("/openam/json/global-config/realms?_action=create", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: "halfway", parentPath: "/", active: true, aliases: [] }),
        });
        assert.equal(created.status, 201);
        // ...and the authentication PUT that would have followed never happens.

        const authentication = "/openam/json/realms/root/realm-config/authentication";
        const recorded = JSON.parse((await get(authentication)).body).core.adminAuthModule;
        const edited = await get(authentication, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ adminAuthModule: "[dirty]" }),
        });
        assert.equal(edited.status, 200);
        assert.equal(JSON.parse(edited.body).core.adminAuthModule, "[dirty]");

        await reset();

        assert.deepEqual(await realmNames(), ["/"]);
        assert.equal(JSON.parse((await get(authentication)).body).core.adminAuthModule, recorded);
    });

    it("ends the sessions the run opened", async () => {
        // Sessions are in the state like everything else, so the swap takes them with it -- which is
        // what a reset has to mean for a suite whose next test logs in again. A browser holding the
        // old cookie is in the position it would be in after any other reset of the backend: the
        // session it names is gone, and `RESTLoginHelper` sends it to the login page.
        const token = await sessionToken(ADMIN_USER, ADMIN_PASS);
        const headers = { iPlanetDirectoryPro: token };
        assert.equal((await get("/openam/json/sessions?_action=getSessionInfo",
            { method: "POST", headers })).status, 200);

        await reset();

        assert.equal((await get("/openam/json/sessions?_action=getSessionInfo",
            { method: "POST", headers })).status, 401);
    });

    it("discards a profile edit, and a login that had begun but not finished", async () => {
        // The two stores the swap takes that a realm listing cannot see. The profile is the one
        // worth its own test: `profileFor` clones on read *because* of this reset, so that a save
        // cannot write through to the document the capture loader cached -- and that clone is only
        // sufficient because the rebuild reads the capture again rather than reusing a handle.
        // `inFlight` is the other half of `auth`, and auth.mjs accepts that it only ever shrinks on
        // a *completed* login: an abandoned one is left there until a reset takes it.
        const token = await sessionToken(USERNAME, PASSWORD);
        const profile = `/openam/json/realms/root/users/${USERNAME}`;
        const recorded = JSON.parse((await get(profile,
            { headers: { iPlanetDirectoryPro: token } })).body).givenName;

        const saved = await get(profile, {
            method: "PUT",
            headers: { "Content-Type": "application/json", iPlanetDirectoryPro: token },
            body: JSON.stringify({ givenName: "[dirty]" }),
        });
        assert.equal(saved.status, 200);

        // A login taken through its first leg and abandoned there, as a killed test leaves one.
        const begun = await get("/openam/json/authenticate", { method: "POST" });
        assert.equal(begun.status, 200);
        const requirements = JSON.parse(begun.body);

        await reset();

        // Read through a new login, because the old token went with the sessions -- which is what
        // the next test in a suite does anyway.
        const read = await get(profile,
            { headers: { iPlanetDirectoryPro: await sessionToken(USERNAME, PASSWORD) } });
        assert.equal(read.status, 200);
        assert.deepEqual(JSON.parse(read.body).givenName, recorded);

        // And the abandoned handle no longer names anything, so finishing that login now fails the
        // way an unknown authId does rather than completing against a state that is gone.
        requirements.callbacks[0].input[0].value = USERNAME;
        requirements.callbacks[1].input[0].value = PASSWORD;
        const finished = await get("/openam/json/authenticate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(requirements),
        });
        assert.equal(finished.status, 401);
    });

    it("is not on the AM surface, and is not something a stray GET can trigger", async () => {
        // The naming rule, asserted rather than left to the comment: nothing under the AM namespace
        // resets anything, so a request log can be read without wondering.
        assert.equal((await get("/openam/json/reset", { method: "POST" })).status, 501);

        const got = await get("/local-api-server/reset");
        assert.equal(got.status, 405);
        assert.equal(got.allow, "POST");
        assert.match(got.body, /POST/);

        // A neighbour on the control prefix is a 404 that says what the prefix is for, not a
        // fallthrough to the 404 that lists the AM surfaces.
        const neighbour = await get("/local-api-server/restart", { method: "POST" });
        assert.equal(neighbour.status, 404);
        assert.match(neighbour.body, /\/local-api-server\/reset/);
    });

    it("says the reset did not happen, and keeps serving, when the baseline will not build",
        async () => {
            // Task 2.15 re-records the capture, and a re-record underneath a running server is the
            // realistic way a rebuild comes to throw. Assignment only on success is a one-line
            // property that a refactor could lose silently, so it is asserted rather than argued:
            // the state the server had is still the state it serves, and the 500 says so, because
            // "did that reset half-apply?" is not a question a stack trace answers.
            //
            // On its own server: the shared one must not be left holding a handler that cannot
            // reset, since every test above it depends on one that can.
            let broken = false;
            const build = () => {
                if (broken) {
                    throw new Error("capture/ is being re-recorded");
                }
                return buildBaselineState(CAPTURE_DIR, {
                    context: "openam", hostname: "localhost",
                });
            };
            const handle = createRequestHandler({
                root: CAPTURE_DIR, context: "openam", state: build(), rebuildState: build,
            });
            const own = createServer((req, res) => {
                handle(req, res).catch((error) => {
                    res.writeHead(500);
                    res.end(error.message);
                });
            });
            await new Promise((ready) => own.listen(0, "127.0.0.1", ready));
            const at = `http://127.0.0.1:${own.address().port}`;

            try {
                const created = await fetch(`${at}/openam/json/global-config/realms?_action=create`,
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            name: "kept", parentPath: "/", active: true, aliases: [],
                        }),
                    });
                assert.equal(created.status, 201);

                broken = true;
                const refused = await fetch(`${at}/local-api-server/reset`, { method: "POST" });
                assert.equal(refused.status, 500);
                const report = await refused.json();
                assert.equal(report.reset, false);
                assert.match(report.message, /being re-recorded/);

                // Still serving, and serving what it had rather than something half-built.
                const listed = await fetch(
                    `${at}/openam/json/global-config/realms?_queryFilter=true`);
                assert.equal(listed.status, 200);
                assert.deepEqual((await listed.json()).result.map((realm) => realm.name),
                    ["/", "kept"]);
            } finally {
                own.closeAllConnections();
                own.close();
            }
        });

    it("refuses at construction the two ways a handler could turn out unable to reset", () => {
        const state = buildBaselineState(CAPTURE_DIR, { context: "openam", hostname: "localhost" });

        // The context that collides with the control prefix. The check that keeps the reset path
        // off the AM surface would swallow both of that context's mounts, so it is refused where
        // server.mjs still has somewhere to put the message -- before the port.
        assert.throws(() => createRequestHandler({
            root: CAPTURE_DIR, context: "local-api-server", state, rebuildState: () => state,
        }), /control prefix/);

        // And the handler with no way to build a baseline, which would otherwise take the port and
        // fail on the first reset a suite asked for.
        assert.throws(() => createRequestHandler({ root: CAPTURE_DIR, context: "openam", state }),
            /rebuildState/);
    });
});
