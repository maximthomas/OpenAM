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
 * The other way this server can serve `/{context}/XUI/`: hand it to a Vite dev server (task 4.10).
 *
 * `static-tree.mjs` serves a built tree, which is what a deployment gets and therefore what a run
 * that means anything is made of. This serves the same prefix out of a dev server instead, so a
 * source edit is visible without a build — and the REST half beside it is byte-identical, because
 * only the XUI branch of the router changes. D14 is why it has to be a proxy at all rather than a
 * second port: `Constants.host` is `""` and `Constants.context` comes from `location.pathname`, so
 * the XUI asks whatever origin served it, under the path it was served from. A dev server on 5173
 * that the browser talked to directly would be a second origin, and the UI would address its REST
 * calls at `/json/…` on 5173, where nothing answers.
 *
 * **The path is not rewritten, in either direction, and the query is not dropped.** Vite is started
 * with `base` equal to this server's XUI mount, so it expects the whole `/{context}/XUI/…` path;
 * stripping the mount would be correct only for `base: "/"`, which D14 forbids. The query matters
 * twice over: `index.html` configures RequireJS with `urlArgs`, so nearly every module URL on a
 * page carries `?v=…`, and Vite's HMR handshake carries a `?token=` it refuses the socket without.
 *
 * **`Host` is forwarded, not rewritten** — the one header this file sets deliberately, because
 * `node:http` otherwise synthesises it from the target. Vite's HMR client builds the socket URL it
 * connects back to out of the host it was served under, so rewriting `Host` to `127.0.0.1:5173`
 * points the browser's HMR socket straight at Vite and around this server: a second origin again,
 * by a longer road. The cost is that Vite sees a host it was not started on and applies its
 * `server.allowedHosts` check to it; its default admits IPv4 literals and `localhost`, so the
 * loopback default passes and a non-loopback `--host` reached by name may not. local/README.md
 * says so where a contributor will meet it.
 *
 * **The upgrade is not a request.** `node:http` does not route `Connection: Upgrade` through the
 * request handler — it emits `'upgrade'` on the server and destroys the socket if nothing is
 * listening. So HMR needs `proxyUpgrade` wired in server.mjs as well as `proxyRequest` wired in the
 * router, and omitting the second one fails in the quietest way available: the page loads, HMR
 * never connects, and the request log says nothing because it is written from `res.on("finish")`
 * and there is no `res`.
 *
 * Node standard library only. See the note in server.mjs for why that constraint is load-bearing
 * rather than a preference — no `http-proxy`, no `ws`; the handshake is the peers' to negotiate and
 * this file only has to not corrupt it.
 */

import { request } from "node:http";

/**
 * Set on every outbound request, refused on any inbound one that already carries it.
 *
 * `--dev-server` pointed at this server's own origin is an infinite loop, and it presents as memory
 * exhaustion rather than as an error. options.mjs refuses the spellings it can compare as strings;
 * this catches the rest — `localhost` against `127.0.0.1`, a `--port 0` whose bound port was not
 * knowable at parse time, or two of these servers pointed at each other — at a cost of one header.
 */
export const LOOP_GUARD = "x-openam-local-api-server-proxy";

/**
 * Headers that belong to one hop and must not be relayed to the next (RFC 9110 s7.6.1).
 *
 * `agent: false` makes `node:http` put `Connection: close` on every outbound request, so an
 * upstream that answers in kind used to have that relayed to the browser — which then tore down its
 * keep-alive connection after *every* response. A single XUI page fetches well over a hundred
 * modules, so that is the connection reuse the built-tree mode has and this one was quietly losing.
 *
 * `transfer-encoding` is deliberately **not** here: the client parser hands the body over already
 * decoded and `node:http` re-chunks it on the way out, so relaying the header is correct.
 */
const HOP_BY_HOP = new Set([
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
    "te", "trailer", "upgrade",
]);

/** Whatever the peer named in its own `Connection`, which is hop-by-hop by that peer's say-so. */
function hopByHopFor (connectionHeader) {
    const named = String(connectionHeader ?? "").split(",")
        .map((name) => name.trim().toLowerCase()).filter(Boolean);
    return new Set([...HOP_BY_HOP, ...named]);
}

/** A request's headers, minus this hop's, plus the loop guard. */
function forwardRequestHeaders (headers) {
    const drop = hopByHopFor(headers.connection);
    const forwarded = {};
    for (const [name, value] of Object.entries(headers)) {
        if (!drop.has(name.toLowerCase())) {
            forwarded[name] = value;
        }
    }
    forwarded[LOOP_GUARD] = "1";
    return forwarded;
}

/**
 * A response's raw headers, minus that hop's.
 *
 * Kept as the flat `rawHeaders` array `writeHead` accepts, because that is what preserves header
 * case and a repeated header — Vite sends more than one `set-cookie` — which the parsed object
 * flattens into one.
 */
function forwardResponseHeaders (rawHeaders, connectionHeader) {
    const drop = hopByHopFor(connectionHeader);
    const forwarded = [];
    for (let i = 0; i < rawHeaders.length; i += 2) {
        if (!drop.has(rawHeaders[i].toLowerCase())) {
            forwarded.push(rawHeaders[i], rawHeaders[i + 1]);
        }
    }
    return forwarded;
}

/** Plain text, the shape router.mjs's own sender uses, for the failures only this file can have. */
function sendText (req, res, status, body) {
    const payload = Buffer.from(body, "utf8");
    res.writeHead(status, {
        "Content-Type": "text/plain;charset=UTF-8",
        "Content-Length": payload.length,
        "Cache-Control": "no-store",
    });
    res.end(req.method === "HEAD" ? undefined : payload);
}

/** The status line a raw socket needs, written by hand because an upgrade has no `res`. */
function statusLine (status, reason) {
    return `HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\n\r\n`;
}

/**
 * Why the dev server did not answer, as a sentence.
 *
 * The failure this mode has that the built-tree mode does not: the contributor starts Vite in one
 * terminal and this in another, so "not up yet" and "up on a different port than you said" are
 * ordinary states, not faults. An `ECONNREFUSED` on its own reads as a bug in this server.
 */
function unreachable (devServer, mount, error) {
    return `${devServer.origin} is not answering: ${error.code ?? error.message}.

${mount}/ is proxied to a Vite dev server, and this server does not start one -- start it
yourself with a base of ${mount}/, or drop --dev-server to serve a built tree instead.
`;
}

/**
 * `/{context}/XUI/…` answered by the dev server instead of by a tree on disk.
 *
 * Called from the router's existing XUI branch and nowhere else, so the REST surface, the control
 * mount, the `/{context}/` redirect and the 404 that names all three are untouched by construction
 * rather than by a path filter here that could disagree with them.
 */
export function proxyRequest (req, res, { devServer, mount, inflight }) {
    if (req.headers[LOOP_GUARD] !== undefined) {
        return sendText(req, res, 508, `this request has already been through a local API server `
            + `proxy, so --dev-server ${devServer.origin} points back at this server (or at `
            + "another one pointing here). Point it at the Vite dev server instead.\n");
    }

    const out = request({
        host: devServer.hostname,
        port: devServer.port,
        path: req.url,                        // verbatim: path AND query
        method: req.method,
        headers: forwardRequestHeaders(req.headers),
        // Never pool: a dev server restart leaves a pooled socket that fails the next request for
        // reasons belonging to the previous one.
        agent: false,
    });

    inflight?.add(out);
    const forget = () => inflight?.delete(out);

    out.on("response", (up) => {
        res.writeHead(up.statusCode, up.statusMessage,
            forwardResponseHeaders(up.rawHeaders, up.headers.connection));
        up.pipe(res);

        // **The response is where an upstream death has to be caught, not the request.** Once the
        // headers are through, `node:http` delivers a socket failure to `up`, and an
        // IncomingMessage only emits 'error' when something is listening -- otherwise it is
        // swallowed. `pipe` ends the destination on 'end', which never comes, so without these two
        // the browser holds a half-written response open for ever and the request log says nothing.
        // Restarting Vite while a page is loading is the ordinary way to cause it.
        up.on("error", () => res.destroy());
        up.on("close", () => {
            if (!up.complete && !res.writableEnded) {
                res.destroy();
            }
        });
    });

    out.on("error", (error) => {
        forget();
        if (res.headersSent) {
            // The upstream died mid-body. Nothing can be said that the client will parse.
            return res.destroy();
        }
        sendText(req, res, 502, unreachable(devServer, mount, error));
    });

    out.on("close", forget);
    // A browser that navigated away mid-download; without this the outbound request outlives it.
    res.on("close", () => { if (!res.writableEnded) { out.destroy(); } });

    req.pipe(out);
}

/**
 * The HMR WebSocket: `server.on("upgrade")` in server.mjs, not a route in the router.
 *
 * Everything here is written to a raw socket by hand. There is no `res`, so there is no
 * `writeHead`, no automatic status line and no logging — which is exactly why this is the half that
 * gets silently left out.
 */
export function proxyUpgrade (req, socket, head, { devServer, mount, upgrades, inflight, log }) {
    const say = (line) => log?.(`${line} ${req.method} ${req.url}`);

    if (req.headers[LOOP_GUARD] !== undefined) {
        say(508);
        socket.write(statusLine(508, "Loop Detected"));
        return socket.destroy();
    }

    // An HMR socket is idle by definition between edits, so the default timeout would close it
    // during any pause in editing -- "HMR works for a minute and then stops". Nagle would add
    // latency to every frame of what is an interactive duplex.
    socket.setNoDelay(true);
    socket.setTimeout(0);
    socket.setKeepAlive(true, 0);

    const out = request({
        host: devServer.hostname,
        port: devServer.port,
        path: req.url,                        // verbatim: Vite's handshake carries a ?token=
        method: req.method,
        // Verbatim here, unlike the request path above: `Connection: Upgrade` and `Upgrade:
        // websocket` are hop-by-hop headers that *are* the handshake, so filtering them would
        // leave an ordinary GET. Also carried: Host, Origin, Sec-WebSocket-Key/-Version, and the
        // `vite-hmr` subprotocol Vite discriminates its own socket by. Dropping any of the last
        // three leaves the connection up and HMR dead.
        headers: { ...req.headers, [LOOP_GUARD]: "1" },
        agent: false,
    });

    // Tracked from here, not from the handshake. Between this event and the upstream answering,
    // the client socket has already been detached from the http server -- `closeAllConnections()`
    // cannot reach it -- so a shutdown in that window would strand both ends with nothing on
    // screen. An upstream that accepts TCP and is slow to answer (Vite mid-optimize) is exactly
    // that window. `upSocket` is filled in below; `closeProxyConnections` allows for it being null.
    const pair = { socket, upSocket: null };
    upgrades?.add(pair);
    inflight?.add(out);
    const forget = () => {
        upgrades?.delete(pair);
        inflight?.delete(out);
    };
    // Untracked when the client socket is actually gone, and not a moment before -- every branch
    // below ends by destroying or ending it, so this is the one place that cannot be forgotten.
    socket.on("close", forget);
    out.on("close", () => inflight?.delete(out));

    out.on("upgrade", (up, upSocket, upHead) => {
        upSocket.setNoDelay(true);
        upSocket.setTimeout(0);
        upSocket.setKeepAlive(true, 0);

        pair.upSocket = upSocket;
        inflight?.delete(out);
        say(up.statusCode);

        const lines = [`HTTP/1.1 ${up.statusCode} ${up.statusMessage}`];
        for (let i = 0; i < up.rawHeaders.length; i += 2) {
            lines.push(`${up.rawHeaders[i]}: ${up.rawHeaders[i + 1]}`);
        }
        socket.write(`${lines.join("\r\n")}\r\n\r\n`);

        // The bytes each parser read past the end of its header block and buffered. They are empty
        // most of the time, so dropping them yields a proxy that passes every test written without
        // thinking about it and loses the first frame whenever a peer put the frame in the same TCP
        // segment as the handshake. dev-proxy.test.mjs forces both, in both directions.
        if (upHead?.length) {
            socket.write(upHead);
        }
        if (head?.length) {
            upSocket.write(head);
        }

        socket.on("error", () => upSocket.destroy());
        upSocket.on("error", () => socket.destroy());
        // Symmetric, and both halves: destroying only the client side on a Vite restart leaves the
        // outbound socket open and the browser never reconnects.
        socket.on("close", () => upSocket.destroy());
        upSocket.on("close", () => socket.destroy());

        socket.pipe(upSocket);
        upSocket.pipe(socket);
    });

    // Up, but answering this path with an ordinary response rather than upgrading -- a 404 from a
    // dev server whose base does not match this server's mount is the way to get here. Relay the
    // status and end, or the client waits for a handshake that is never coming. Minimal on purpose:
    // the body has already been decoded by the client parser, so forwarding a `Transfer-Encoding`
    // from the upstream would leave the peer parsing chunk headers that are no longer there.
    out.on("response", (up) => {
        say(up.statusCode);
        socket.write(statusLine(up.statusCode, up.statusMessage ?? ""));
        up.on("data", (chunk) => socket.write(chunk));
        up.on("end", () => socket.end());
        up.on("error", () => socket.destroy());
    });

    out.on("error", (error) => {
        say(502);
        socket.write(statusLine(502, "Bad Gateway") + unreachable(devServer, mount, error));
        socket.destroy();
    });

    // A bare destroy gives the client a connection reset with no reason, which is indistinguishable
    // from this server not existing.
    socket.on("error", () => out.destroy());

    out.end();
}

/**
 * Everything this mode is holding open, destroyed. Called from server.mjs's shutdown.
 *
 * `server.closeAllConnections()` does **not** close a socket that has been detached by an upgrade
 * — measured, not assumed; dev-proxy.test.mjs asserts it. So one browser tab with HMR connected
 * keeps the process alive after `server.close()`, Ctrl-C appears to hang, and nothing on screen
 * says why. Both halves of each pair: destroying only the client side leaves the socket to Vite.
 */
export function closeProxyConnections ({ upgrades, inflight }) {
    for (const { socket, upSocket } of upgrades ?? []) {
        socket.destroy();
        // null while the handshake is still outstanding; see proxyUpgrade.
        upSocket?.destroy();
    }
    upgrades?.clear();
    for (const out of inflight ?? []) {
        out.destroy();
    }
    inflight?.clear();
}
