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
 * task 2.7 (auth.test.mjs), and everything else is 501 until tasks 2.8-2.13. The last block below
 * is what says so.
 */

import assert from "node:assert/strict";
import { createServer } from "node:http";
import { chmod, mkdtemp, mkdir, realpath, symlink, writeFile } from "node:fs/promises";
import { after, before, describe, it } from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

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

before(async () => {
    const root = await buildTree();
    const handle = createRequestHandler({
        root,
        context: "openam",
        state: buildBaselineState(CAPTURE_DIR, { context: "openam", hostname: "localhost" }),
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
        // Task 2.12's resource, borrowed by 2.10 (state.user). It is asserted here rather than left
        // to the browser specs because nothing else in `npm run test:server` covers it: break the
        // keying or the route shape and every unit test stays green while every console spec fails
        // in `waitForURL`, which is a long way from the cause. `RESTLoginHelper.getLoggedUser`
        // fetches this last, and RealmsRoutes gates every admin route on the roles it carries.
        const response = await get("/openam/json/realms/root/users/amadmin");
        assert.equal(response.status, 200);
        assert.equal(response.type, "application/json;charset=UTF-8");
        assert.ok(JSON.parse(response.body).roles.includes("ui-realm-admin"));
    });

    it("holds the borrowed profile read to the one document and realm it was borrowed for", async () => {
        // Both halves are 2.10 scope discipline rather than AM's behaviour, and both are 2.12's to
        // widen: `demo` is a profile this server has not implemented, not one a directory is
        // missing, and 404 is the answer `RESTLoginHelper` clears the session cookie for.
        const other = await get("/openam/json/realms/root/users/demo");
        assert.equal(other.status, 501);

        const scoped = await get("/openam/json/realms/root/realms/alpha/users/amadmin");
        assert.equal(scoped.status, 501);
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
