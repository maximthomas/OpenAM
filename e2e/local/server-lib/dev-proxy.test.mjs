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
 * What crosses the boundary when `/{context}/XUI/` is proxied to a dev server.
 *
 *     node --test local/server-lib/
 *
 * **There is no Vite here, and that is the point.** The application source is still AMD until
 * groups 5 and 6, so a Vite dev server cannot serve a running XUI yet and "HMR reloads a module" is
 * not a thing this task can demonstrate. The proxy, however, does not care what is behind it: it
 * cares about the path, the query, `Host`, the upgrade, and the two buffered head buffers. So the
 * upstream below is a stand-in — fifteen lines of `node:http` plus a `sha1` — and every assertion
 * is about what arrived, not about what it means.
 *
 * The router is the real one. `createRequestHandler` is imported unchanged and given a `devServer`,
 * so what is under test is the branch *in its real dispatch order*: the REST surface, the control
 * mount and the 404 are asserted here precisely because a proxy that captured any of them would
 * still pass every test written only about the XUI mount.
 *
 * **Two of these cases exist because of a bug that hides.** `head` and `upHead` are the bytes each
 * HTTP parser read past the end of its header block and buffered; they are empty most of the time,
 * so a proxy that drops them works in casual testing and loses the first WebSocket frame whenever a
 * peer put that frame in the same TCP segment as the handshake. Both peers here therefore write
 * their handshake and a marker in a *single* `socket.write`, and the marker is sent at no other
 * time — so if the buffered head is dropped, the marker is lost for good rather than arriving late.
 *
 * **Two behaviours here are defence in depth and no single mutation isolates them.** The symmetric
 * `close` handlers overlap with the pipe's own end-on-end and with the error handlers, and
 * `agent: false` has no observable this side of a pool that never fills. They are asserted at the
 * level of the outcome, or not at all, and this note is here so that a later reader does not take a
 * green run as proof that removing them is safe. Everything else in this file has been checked by
 * deleting the line it covers and watching exactly one case go red.
 *
 * No `ws` package, no `http-proxy`. See the note in server.mjs for why that is load-bearing.
 */

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { connect } from "node:net";
import { after, before, describe, it } from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { closeProxyConnections, LOOP_GUARD, proxyUpgrade } from "./dev-proxy.mjs";
import { createRequestHandler, isUnderMount, requestPath, xuiMountFor } from "./router.mjs";
import { buildBaselineState } from "./state.mjs";

const CAPTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "capture");

/** RFC 6455's magic string. The whole of a WebSocket handshake that a server has to compute. */
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/** Written past the end of a header block, in the same write, and at no other time. */
const UPSTREAM_HEAD = "UPSTREAM-HEAD-MARKER";
const CLIENT_HEAD = "CLIENT-HEAD-MARKER";

const CONTEXT = "openam";
const XUI_MOUNT = xuiMountFor(CONTEXT);

let upstream;              // the stand-in dev server
let upstreamPort;
/** Switched per case: how the stand-in should misbehave. See startUpstream. */
let upstreamMode = "normal";
let seen;                  // what the stand-in last received
let upstreamData;          // everything the stand-in's upgraded socket received
let upstreamSocket;        // the stand-in's end of the upgraded connection

let proxy;                 // the local API server, in dev-server mode
let proxyPort;
let upgrades;
let inflight;

let deadProxy;             // the same, pointed at a port with nothing on it
let deadProxyPort;

const accept = (key) => createHash("sha1").update(key + GUID).digest("base64");

const wait = (ms) => new Promise((done) => { setTimeout(done, ms); });

/**
 * Wait for a condition rather than for a duration.
 *
 * Every wait here is for bytes that have already been written on loopback, so the honest bound is
 * "when they arrive", not a number. A fixed settle passes alone and fails in a full suite run on a
 * loaded machine, which is the least useful kind of test there is.
 */
async function until (predicate, what, timeout = 5000) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
        if (predicate()) {
            return;
        }
        await wait(5);
    }
    assert.fail(`timed out waiting for ${what}`);
}

/**
 * A dev server, for the purposes of a proxy: something that answers, and something that upgrades.
 *
 * It reports the path and the `Host` it was given rather than serving anything, because "what did
 * the upstream actually receive" is the entire question this file asks.
 */
function startUpstream () {
    const server = createServer((req, res) => {
        seen = {
            url: req.url,
            host: req.headers.host,
            guard: req.headers[LOOP_GUARD],
            connection: req.headers.connection,
        };
        if (upstreamMode === "dies-mid-body") {
            // Headers and part of a body, then the socket goes -- what restarting Vite while a
            // page is loading looks like from here. The death is deferred a tick so the headers
            // have certainly reached the proxy: this case is about a response that is already in
            // flight, which is the one the request-side `out.on("error")` cannot catch.
            res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": 1000 });
            res.write("twelve bytes");
            setTimeout(() => res.socket?.destroy(), 50);
            return undefined;
        }
        const body = JSON.stringify({ upstream: true, path: req.url, host: req.headers.host });
        res.writeHead(200, {
            "Content-Type": "application/json;charset=UTF-8",
            "Content-Length": Buffer.byteLength(body),
            // Hop-by-hop, and the browser must not be told to act on this hop's decision.
            Connection: "close",
            // Distinctive, because node:http writes a `Keep-Alive` of its own for the client hop
            // and the question is only whether *this* one survived the crossing.
            "Keep-Alive": "timeout=99",
        });
        res.end(body);
    });

    server.on("upgrade", (req, socket, head) => {
        if (upstreamMode === "refuses-upgrade") {
            // A dev server whose `base` does not match this server's mount answers the HMR path
            // with an ordinary 404 rather than upgrading.
            seen = { url: req.url };
            socket.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"
                + "no HMR here\n");
            return socket.end();
        }
        seen = {
            url: req.url,
            host: req.headers.host,
            protocol: req.headers["sec-websocket-protocol"],
            origin: req.headers.origin,
            head: head.toString(),
        };
        upstreamData = "";
        upstreamSocket = socket;
        socket.on("data", (chunk) => { upstreamData += chunk.toString(); });

        // One write: the 101 and the marker together, so the proxy's client parser has to surface
        // the marker as `upHead` rather than as a later 'data' event.
        socket.write("HTTP/1.1 101 Switching Protocols\r\n"
            + "Upgrade: websocket\r\n"
            + "Connection: Upgrade\r\n"
            + `Sec-WebSocket-Accept: ${accept(req.headers["sec-websocket-key"])}\r\n`
            + `Sec-WebSocket-Protocol: ${req.headers["sec-websocket-protocol"] ?? ""}\r\n`
            + "\r\n"
            + UPSTREAM_HEAD);
    });

    return server;
}

/**
 * The local API server as server.mjs assembles it in dev-server mode.
 *
 * The same two wirings, and it has to be both: the request branch inside the router, and the
 * `'upgrade'` registration outside it. `node:http` does not route an upgrade through the request
 * handler — it emits this event and destroys the socket if nothing listens — so a version of this
 * harness with only the first wiring would pass every request case here and no upgrade case, which
 * is exactly the shape of the omission this file exists to catch.
 */
function startProxy (devServer) {
    const state = buildBaselineState(CAPTURE_DIR, { context: CONTEXT, hostname: "localhost" });
    const live = new Set();
    const out = new Set();

    const handle = createRequestHandler({
        root: null,
        devServer,
        inflight: out,
        context: CONTEXT,
        state,
        rebuildState: () => buildBaselineState(CAPTURE_DIR, {
            context: CONTEXT, hostname: "localhost",
        }),
    });

    const server = createServer((req, res) => {
        handle(req, res).catch(() => res.destroy());
    });
    server.on("upgrade", (req, socket, head) => {
        if (!isUnderMount(requestPath(req.url) ?? "", XUI_MOUNT)) {
            socket.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
            return socket.destroy();
        }
        proxyUpgrade(req, socket, head, {
            devServer, mount: XUI_MOUNT, upgrades: live, inflight: out,
        });
    });

    return { server, live, out };
}

const listen = (server) => new Promise((done) => {
    server.listen(0, "127.0.0.1", () => done(server.address().port));
});

const close = (server) => new Promise((done) => {
    server.closeAllConnections();
    server.close(done);
});

/** A port nothing is on: take one, then give it back. */
async function freePort () {
    const idle = createServer();
    const port = await listen(idle);
    await close(idle);
    return port;
}

/** The response, with its body, from the proxying server. */
async function get (port, path, init = {}) {
    const response = await fetch(`http://127.0.0.1:${port}${path}`, {
        redirect: "manual", ...init,
    });
    return { status: response.status, body: await response.text() };
}

/**
 * A WebSocket handshake over a raw socket, with a marker in the same write.
 *
 * Raw rather than a client library, for the reason the whole file is raw: the bytes are the
 * subject. Resolves with everything the client read, once the peer has gone quiet.
 */
function upgradeRequest (port, path, { protocol = "vite-hmr", origin = true } = {}) {
    return new Promise((done, fail) => {
        const key = randomBytes(16).toString("base64");
        const socket = connect(port, "127.0.0.1", () => {
            socket.write(`GET ${path} HTTP/1.1\r\n`
                + `Host: 127.0.0.1:${port}\r\n`
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + `Sec-WebSocket-Key: ${key}\r\n`
                + "Sec-WebSocket-Version: 13\r\n"
                + (protocol ? `Sec-WebSocket-Protocol: ${protocol}\r\n` : "")
                + (origin ? `Origin: http://127.0.0.1:${port}\r\n` : "")
                + "\r\n"
                // Past the end of the header block, in the same write, and nowhere else.
                + CLIENT_HEAD);
        });

        let received = "";
        socket.on("data", (chunk) => { received += chunk.toString(); });
        socket.on("error", fail);
        socket.on("close", () => { settle(); });

        // Resolve on the end of the response's header block, not on a stopwatch -- then one short
        // grace for the bytes written past it, which are the subject of two of the cases below and
        // arrive in the same segment or not at all.
        const settle = async () => {
            await until(() => received.includes("\r\n\r\n") || socket.destroyed,
                `a response header block from ${path}`);
            await wait(30);
            done({ socket, key, received });
        };
        settle().catch(fail);
    });
}

before(async () => {
    upstream = startUpstream();
    upstreamPort = await listen(upstream);

    const devServer = {
        origin: `http://127.0.0.1:${upstreamPort}`, hostname: "127.0.0.1", port: upstreamPort,
    };
    const started = startProxy(devServer);
    proxy = started.server;
    upgrades = started.live;
    inflight = started.out;
    proxyPort = await listen(proxy);

    const dead = await freePort();
    const deadStarted = startProxy({
        origin: `http://127.0.0.1:${dead}`, hostname: "127.0.0.1", port: dead,
    });
    deadProxy = deadStarted.server;
    deadProxyPort = await listen(deadProxy);
});

after(async () => {
    closeProxyConnections({ upgrades, inflight });
    await close(proxy);
    await close(deadProxy);
    await close(upstream);
});

describe("the XUI mount, proxied", () => {
    it("forwards the path and the query byte for byte", async () => {
        // `?v=…` is on nearly every module URL a page fetches, because index.html configures
        // RequireJS with urlArgs. static-tree.mjs resolves off the pathname and ignores the query;
        // this must do the opposite and preserve it.
        const path = `${XUI_MOUNT}/deep/module/Foo.js?v=16.2.0-SNAPSHOT&x=1`;
        const { status, body } = await get(proxyPort, path);

        assert.equal(status, 200);
        assert.equal(JSON.parse(body).path, path);
        assert.equal(seen.url, path);
    });

    it("forwards the client's Host rather than the target's", async () => {
        // Vite's HMR client builds the socket URL it connects back to out of the host it was
        // served under. Rewritten to the target, the browser would open its HMR socket straight at
        // Vite and around this server -- a second origin, which is what D14 exists to prevent.
        await get(proxyPort, `${XUI_MOUNT}/index.html`);
        assert.equal(seen.host, `127.0.0.1:${proxyPort}`);
        assert.notEqual(seen.host, `127.0.0.1:${upstreamPort}`);
    });

    it("does not proxy a path that merely starts with the mount", async () => {
        // isUnderMount matches the mount exactly or followed by a slash, so this is under neither
        // mount and belongs to the 404 that names all three surfaces.
        const { status, body } = await get(proxyPort, `/${CONTEXT}/XUIsomething`);
        assert.equal(status, 404);
        assert.match(body, /is not served by the local API server/);
        assert.doesNotMatch(body, /upstream/);
    });
});

describe("what is not proxied", () => {
    it("still answers the REST surface itself", async () => {
        // The whole of D14: one origin, and the API half is this server's. A dev server would 404
        // /openam/json/… as a missing static file, and serverinfo/* is the only request gating
        // EVENT_APP_INITIALIZED -- so a proxy that captured it would not merely misbehave.
        const { status, body } = await get(proxyPort, `/${CONTEXT}/json/serverinfo/*`);
        assert.equal(status, 200);
        assert.match(body, /iPlanetDirectoryPro/);
        assert.doesNotMatch(body, /upstream/);
    });

    it("still answers its own control surface", async () => {
        const { status, body } = await get(proxyPort, "/local-api-server/reset", {
            method: "POST",
        });
        assert.equal(status, 200);
        assert.equal(JSON.parse(body).reset, true);
    });

    it("still redirects the context root to the XUI", async () => {
        const { status } = await get(proxyPort, `/${CONTEXT}/`);
        assert.equal(status, 302);
    });
});

describe("the HMR WebSocket upgrade", () => {
    it("reaches the upstream, with the handshake intact", async () => {
        // The path carries a ?token=: Vite 5's shouldHandle takes hasValidToken whenever an Origin
        // is present, which a browser always sends, so a proxy that forwarded the path but dropped
        // the query would get a refused handshake and silently dead HMR.
        const path = `${XUI_MOUNT}/?token=abc123`;
        const { socket, key, received } = await upgradeRequest(proxyPort, path);

        assert.match(received, /^HTTP\/1\.1 101 Switching Protocols\r\n/);
        // includes, not match: a base64 accept contains `+`, `/` and `=`, and `+` in a RegExp
        // built from it is a quantifier -- a test that passes or fails on the peer's random key.
        assert.ok(received.includes(`Sec-WebSocket-Accept: ${accept(key)}`), received);
        // The subprotocol Vite discriminates its own socket by. Dropped, the connection is up and
        // HMR is dead.
        assert.match(received, /Sec-WebSocket-Protocol: vite-hmr/);
        assert.equal(seen.url, path);
        assert.equal(seen.protocol, "vite-hmr");
        assert.equal(seen.host, `127.0.0.1:${proxyPort}`);

        socket.destroy();
    });

    it("delivers the upstream's buffered head to the client", async () => {
        // The upstream wrote its 101 and this marker in one write and says nothing else, so these
        // bytes exist only as the `upHead` argument. Dropped, they are lost rather than late.
        const { socket, received } = await upgradeRequest(proxyPort, `${XUI_MOUNT}/?token=abc`);
        assert.ok(received.includes(UPSTREAM_HEAD), received);
        socket.destroy();
    });

    it("delivers the client's buffered head to the upstream", async () => {
        // The mirror image: written past the client's handshake in the same write, so it reaches
        // this server only as `head`.
        const { socket } = await upgradeRequest(proxyPort, `${XUI_MOUNT}/?token=abc`);
        assert.ok(upstreamData.includes(CLIENT_HEAD), upstreamData);
        socket.destroy();
    });

    it("carries bytes both ways once it is up", async () => {
        const { socket } = await upgradeRequest(proxyPort, `${XUI_MOUNT}/?token=abc`);
        upstreamData = "";
        socket.write("A-FRAME-FROM-THE-BROWSER");
        await until(() => /A-FRAME-FROM-THE-BROWSER/.test(upstreamData), "the frame to be relayed");
        socket.destroy();
    });

    it("clears the idle timeout on both ends, because an HMR socket is idle by definition",
        async () => {
            // An HMR socket says nothing between edits, so any inherited idle timeout eventually
            // closes it and the symptom is "HMR works for a minute and then stops". Asserted on
            // the tracked sockets rather than through behaviour on purpose: a server timeout is
            // not in fact armed on a socket an upgrade has detached in this Node, so the only
            // honest way to pin `setTimeout(0)` is to look at what it set.
            const { server, live, out } = startProxy({
                origin: `http://127.0.0.1:${upstreamPort}`,
                hostname: "127.0.0.1",
                port: upstreamPort,
            });
            server.setTimeout(80);
            const port = await listen(server);
            try {
                const { socket } = await upgradeRequest(port, `${XUI_MOUNT}/?token=abc`);
                const pair = [...live].find((each) => each.upSocket !== null);
                assert.ok(pair, "the upgraded pair is tracked");
                assert.equal(pair.socket.timeout, 0, "the browser's end inherited server.timeout");
                assert.equal(pair.upSocket.timeout, 0, "the dev server's end has a timeout");
                socket.destroy();
            } finally {
                closeProxyConnections({ upgrades: live, inflight: out });
                await close(server);
            }
        });

    it("closes the browser's end when the dev server drops its own, so it can reconnect",
        async () => {
            // Restarting Vite. The outcome is what matters and it is what is asserted; three
            // things in proxyUpgrade produce it together (the pipe's end-on-end, the error
            // handlers and the symmetric close handlers), so this pins the behaviour rather than
            // any one of them -- see the note on defence in depth in this file's header.
            const { socket } = await upgradeRequest(proxyPort, `${XUI_MOUNT}/?token=abc`);
            assert.equal(socket.destroyed, false);

            upstreamSocket.destroy();
            await until(() => socket.destroyed, "the client end to be closed with the upstream");
        });

    it("refuses an upgrade outside the XUI mount with a status line, not a bare reset", async () => {
        // A reset with no reason is indistinguishable to a client from this server not existing.
        const { socket, received } = await upgradeRequest(proxyPort, `/${CONTEXT}/json/notify`);
        assert.match(received, /^HTTP\/1\.1 404 Not Found/);
        socket.destroy();
    });
});

describe("when the dev server is not there", () => {
    it("says so, on the request path, instead of an ECONNREFUSED stack", async () => {
        // Two terminals and an ordering rule: "not up yet" is an ordinary state of this mode, not
        // a fault, so it has to read as one.
        const { status, body } = await get(deadProxyPort, `${XUI_MOUNT}/index.html`);
        assert.equal(status, 502);
        assert.match(body, /is not answering: ECONNREFUSED/);
        assert.ok(body.includes(`${XUI_MOUNT}/ is proxied to a Vite dev server`), body);
    });

    it("says so on the upgrade path too, where there is no response object", async () => {
        const { socket, received } = await upgradeRequest(deadProxyPort, `${XUI_MOUNT}/?token=a`);
        assert.match(received, /^HTTP\/1\.1 502 Bad Gateway/);
        assert.match(received, /is not answering: ECONNREFUSED/);
        socket.destroy();
    });
});

describe("an upstream that misbehaves", () => {
    it("closes the client when the dev server dies mid-body, instead of hanging it", async () => {
        // Once the headers are through, node:http delivers the failure to the IncomingMessage, and
        // an IncomingMessage swallows 'error' when nothing is listening; `pipe` ends the
        // destination on 'end', which never arrives. Without the handlers on `up`, the browser
        // holds a half-written response open for ever and the request log says nothing. Restarting
        // Vite while a page is loading is the ordinary way to cause this.
        upstreamMode = "dies-mid-body";
        try {
            const outcome = await Promise.race([
                get(proxyPort, `${XUI_MOUNT}/big.js`).then(() => "answered", () => "closed"),
                wait(2500).then(() => "HUNG"),
            ]);
            // Either ending is fine and both are diagnosable -- a truncated body the client rejects,
            // or a 502 if the death beat the headers across. What must not happen is neither.
            assert.notEqual(outcome, "HUNG",
                "the client was left holding a half-written response with no way to know");
        } finally {
            upstreamMode = "normal";
        }
    });

    it("relays a refusal to upgrade rather than leaving the client waiting", async () => {
        // `out` emits 'response', not 'upgrade'. This is what a base/--context disagreement looks
        // like on the HMR path, and it is the first thing the README's troubleshooting names.
        upstreamMode = "refuses-upgrade";
        try {
            const { socket, received } = await upgradeRequest(proxyPort,
                `${XUI_MOUNT}/?token=abc`);
            assert.match(received, /^HTTP\/1\.1 404 Not Found/);
            assert.match(received, /no HMR here/);
            socket.destroy();
        } finally {
            upstreamMode = "normal";
        }
    });
});

describe("headers that belong to one hop", () => {
    it("does not relay the upstream's Connection or Keep-Alive to the browser", async () => {
        // `agent: false` puts `Connection: close` on every outbound request, so an upstream
        // answering in kind would tear down the browser's keep-alive after every response -- and a
        // single XUI page fetches well over a hundred modules.
        const response = await fetch(`http://127.0.0.1:${proxyPort}${XUI_MOUNT}/index.html`);
        await response.text();
        // node:http writes a Connection and a Keep-Alive of its own for this hop, so the assertion
        // is that the *upstream's* did not survive -- it said close, and this hop is not closing.
        assert.notEqual(response.headers.get("connection"), "close");
        assert.notEqual(response.headers.get("keep-alive"), "timeout=99");
        // The end-to-end headers are still there.
        assert.match(response.headers.get("content-type"), /application\/json/);
    });

    it("does not relay the client's Connection to the dev server", async () => {
        await get(proxyPort, `${XUI_MOUNT}/index.html`, {
            headers: { Connection: "keep-alive" },
        });
        // node:http writes its own Connection for the outbound hop; what must not survive is the
        // client's, forwarded as if it applied to a connection it knows nothing about.
        assert.notEqual(seen.connection, "keep-alive");
    });
});

describe("the loop guard", () => {
    it("refuses a request that has already been through one of these proxies", async () => {
        // options.mjs compares --dev-server against this server's own address as strings, which
        // cannot see `localhost` against `127.0.0.1` and cannot know a `--port 0` before listen.
        // This is the half that is total: an actual loop is one header away from being visible.
        const { status, body } = await get(proxyPort, `${XUI_MOUNT}/index.html`, {
            headers: { [LOOP_GUARD]: "1" },
        });
        assert.equal(status, 508);
        assert.match(body, /points back at this server/);
    });

    it("marks what it forwards, so the next proxy in the loop can see it", async () => {
        await get(proxyPort, `${XUI_MOUNT}/index.html`);
        assert.equal(seen.guard, "1");
    });

    it("refuses a marked upgrade too, where options.mjs's string check cannot help", async () => {
        // The startup check compares --dev-server against this server's address as strings, so it
        // cannot see `localhost` against `127.0.0.1` and cannot know a `--port 0` before listen.
        // On the upgrade path there is no response object to say so with, so the status line is
        // written by hand.
        const socket = connect(proxyPort, "127.0.0.1");
        let received = "";
        socket.on("data", (chunk) => { received += chunk.toString(); });
        await new Promise((done) => socket.once("connect", done));
        socket.write(`GET ${XUI_MOUNT}/?token=abc HTTP/1.1\r\n`
            + `Host: 127.0.0.1:${proxyPort}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n`
            + `Sec-WebSocket-Key: ${randomBytes(16).toString("base64")}\r\n`
            + `Sec-WebSocket-Version: 13\r\n${LOOP_GUARD}: 1\r\n\r\n`);
        await until(() => received.includes("\r\n\r\n") || socket.destroyed, "a status line");
        assert.match(received, /^HTTP\/1\.1 508 Loop Detected/);
        socket.destroy();
    });
});

describe("shutdown", () => {
    it("does not close an upgraded socket via closeAllConnections, and so must track it",
        async () => {
            // Measured, not assumed, and the reason server.mjs keeps a Set. One browser tab with
            // HMR connected would otherwise keep the process alive after server.close(): Ctrl-C
            // appears to hang and nothing on screen says why.
            const { socket } = await upgradeRequest(proxyPort, `${XUI_MOUNT}/?token=abc`);
            // The live pair, not a count: an earlier case's socket is removed when its 'close'
            // propagates, which is not something this assertion should be racing.
            assert.ok([...upgrades].some((pair) => !pair.socket.destroyed),
                "the upgraded pair is tracked while it is open");

            proxy.closeAllConnections();
            await wait(150);
            assert.equal(socket.destroyed, false,
                "an upgraded socket is one the server has handed away, not one it still owns");

            closeProxyConnections({ upgrades, inflight });
            await until(() => socket.destroyed, "the tracked socket to be destroyed");
            assert.equal(upgrades.size, 0);
        });
});
