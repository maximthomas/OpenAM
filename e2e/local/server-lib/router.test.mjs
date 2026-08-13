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
        const response = await get("/openam/json/realms/root/realm-config/services/baseurl", {
            method: "PUT",
        });
        assert.equal(response.status, 501);
        assert.match(JSON.parse(response.body).message, /PUT \/openam\/json\/realms\/root/);
    });

    it("does not let a caller past a route it does not implement", async () => {
        // Header authentication, which `getAuthToken` in common/openam-commons.mjs uses: the
        // credentials go up as headers and `tokenId` comes straight back. It is deliberately not
        // implemented and is not scheduled to be (NOTES-auth.md §9.6), which is what makes it a
        // stable guard -- unlike a not-yet route, it will not quietly turn into a 200 two tasks
        // from now and stop asserting anything. Answering it with a callbacks document would hand
        // the caller an `undefined` token that surfaces as an unexplained 401 several calls later.
        // 501 rather than 404 because the resource is not missing: this server does not serve it.
        const response = await fetch(`${origin}/openam/json/realms/root/authenticate`, {
            method: "POST",
            headers: { "X-OpenAM-Username": "demo", "X-OpenAM-Password": "changeit" },
        });

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
