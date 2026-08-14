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
 * Two AM surfaces on one origin, this server's own control surface, and nothing else.
 *
 * `/{context}/XUI/` is the built UI tree and `/{context}/json/` is the AM REST API (administrative
 * reads from task 2.6, authentication from 2.7, session resolution and logout from 2.8, server and
 * site configuration from 2.9, realm administration from 2.10, service administration from 2.11 and
 * the user profile from 2.12; 501 for the rest). Everything outside them is a 404 that names them.
 * It would be friendlier to proxy the unknown paths to a real AM, and wrong — the
 * local backend's scope is the request list in local/REQUESTS.md, and a silent fallthrough to
 * something else is how that scope stops being true without anyone noticing.
 *
 * **`/local-api-server/` is the third surface, and it is deliberately not spelled like an AM path**
 * (task 2.13). Reset is an operation on *this process*, not a resource AM has: no deployed AM
 * answers it, no spec that is also valid against a deployed instance may call it, and the request
 * log is where that distinction gets read. Under `/{context}/json/` — as `.../json/reset`, or worse
 * a `_action=reset` on a real collection — it would sit in the log looking like an AM call that the
 * deployed instance had somehow failed to serve, and the next person to read that log would go
 * looking for the AM endpoint. Named this way it can only be one thing, and it names which server
 * it is an operation on. The mount is checked before the two AM mounts, so `--context
 * local-api-server` cannot capture the reset path — but it would lose *both* of its own mounts to
 * that check, since the prefix test does not stop at the reset path. So the collision is refused
 * where the handler is built, which server.mjs does before it takes the port. The alternative is a
 * server that starts with a normal banner and 404s every request it was started to serve, and whose
 * only diagnostic is the 404 below telling the reader the AM surface is at a path it just refused.
 *
 * The request target is parsed against a fixed base rather than the `Host` header. Nothing
 * downstream reads the host, and taking it from the request made a malformed `Host` — which the
 * HTTP parser allows through — look like a malformed URL.
 */

import { serveRest } from "./rest.mjs";
import { serveStatic } from "./static-tree.mjs";

const PARSE_BASE = "http://localhost";

/** This server's own operations. Not an AM path, by design; see above. */
export const CONTROL_MOUNT = "/local-api-server";
export const RESET_PATH = `${CONTROL_MOUNT}/reset`;

/**
 * `state` is what the server starts from — already built, so a capture this server cannot read
 * stops it before it takes the port. `rebuildState` is how the reset endpoint gets another one:
 * a zero-argument call answering with a *fresh* baseline, built the same way the first one was.
 */
export function createRequestHandler ({ root, context, state, rebuildState }) {
    // Both refusals are at construction rather than at the request that trips over them, because
    // server.mjs builds the handler before it binds the socket: the operator gets the same
    // one-line startup error a bad --port gives them, instead of a listening server that answers
    // every request wrongly, or answers the reset with a 500 the first time a test asks for one.
    if (context === CONTROL_MOUNT.slice(1)) {
        throw new Error(`--context ${context} is this server's own control prefix `
            + `(${RESET_PATH}), so /${context}/XUI/ and /${context}/json/ would both be `
            + "unreachable. Serve the AM surfaces under some other context.");
    }
    if (typeof rebuildState !== "function") {
        throw new Error(`createRequestHandler needs rebuildState: it is how ${RESET_PATH} builds `
            + "the baseline it returns to.");
    }

    const xuiMount = `/${context}/XUI`;
    const jsonMount = `/${context}/json`;

    /**
     * The only mutable binding in this server, and the whole of the reset mechanism.
     *
     * Every store the REST layer can write to hangs off this one object — realms, their services,
     * the global services, the user profiles, and the sessions and in-flight logins in `state.auth`
     * — and no module holds state of its own outside it. So replacing it with a newly built
     * baseline is a total reset by construction rather than by enumeration: there is no "and also
     * clear X" list to keep up to date as later tasks add stores, because a store a future task
     * adds to the state is a store the swap already discards. That is the property `state.mjs`
     * builds `auth` into the same object for, and the reason reset is not a set of per-store
     * `clear()` calls, which is the shape that leaves residue the first time someone adds a Map and
     * forgets the corresponding line.
     *
     * Read once at dispatch and handed on by value, so a request already in flight — one still
     * reading its body when the reset lands — finishes against the graph it started on, and its
     * writes go to an object nothing will answer from again. That is the correct reading of
     * "discard everything since startup": a write that had not finished when the reset arrived is
     * exactly the half-finished write reset exists to erase.
     *
     * Two properties are what make that safe to state without a lock, and only one of them is
     * Node's single thread. `buildBaselineState` is synchronous end to end, so the assignment below
     * occupies one uninterrupted turn of the event loop and no request can be dispatched into a
     * half-built baseline. And a handler that *does* await mid-request — `serveRest` awaits the
     * body before it writes — holds the state it was handed rather than re-reading this binding, so
     * it cannot find a different one on the far side of the await. Making `buildBaselineState`
     * asynchronous would cost the first of those quietly, and buy back the need for a lock.
     */
    let current = state;

    /**
     * `POST /local-api-server/reset` — discard everything since startup and rebuild the baseline.
     *
     * Rebuilt from the capture on disk rather than from a snapshot taken at startup, and that is
     * the residue question answered rather than assumed: `capture-store.mjs` caches each resolved
     * body and hands out *the same object* every time, so the documents the store holds are the
     * capture's own. Some of them are cloned on write and some are replaced wholesale, and a reset
     * whose correctness depended on getting that inventory right would be wrong the first time a
     * route mutated a document in place. Re-reading gives every reset a fresh object graph with
     * nothing shared with the one it replaces, which needs no inventory to be true. It also makes
     * reset the same operation as startup, so there is one definition of "baseline" and not two
     * that can drift.
     *
     * Assignment only on success: a `rebuildState` that throws — the capture being re-recorded
     * underneath a running server is the realistic way, task 2.15's job — leaves `current` as it
     * was, so the server carries on serving the state it had rather than answering out of a
     * half-built baseline that resembles a reset. The 500 says so in as many words instead of
     * falling through to server.mjs's generic handler, because "did that reset half-apply?" is the
     * only question this failure raises, and a caller cannot answer it from an error message.
     *
     * POST because it changes everything; anything else is 405 rather than a redirect or a quiet
     * 404, so a GET typed into a browser bar says what to send instead of silently not resetting.
     */
    function serveReset (req, res) {
        if (req.method !== "POST") {
            return sendText(req, res, 405,
                `${RESET_PATH} resets the local API server, so it takes POST, not `
                + `${req.method}.\n\n  curl -X POST http://<host>:<port>${RESET_PATH}\n`,
                { Allow: "POST" });
        }

        const started = process.hrtime.bigint();
        let rebuilt;
        try {
            rebuilt = rebuildState();
        } catch (error) {
            return sendJson(req, res, 500, {
                reset: false,
                serving: "the state from before this call, unchanged",
                message: `the baseline could not be rebuilt: ${error.message}`,
            });
        }
        current = rebuilt;
        const milliseconds = Number(process.hrtime.bigint() - started) / 1e6;

        return sendJson(req, res, 200, {
            reset: true,
            // The same count the startup banner reports, so "back to baseline" is checkable from
            // the response without a follow-up read.
            realms: current.realms.size,
            milliseconds: Number(milliseconds.toFixed(1)),
        });
    }

    /** The control surface: reset, and nothing else. A 404 here names what it does serve. */
    function serveControl (req, res, url) {
        if (url.pathname === RESET_PATH) {
            return serveReset(req, res);
        }
        return sendText(req, res, 404, `${url.pathname} is not an operation of the local API `
            + `server.\n\n  POST ${RESET_PATH}   back to the baseline built from local/capture\n\n`
            + "This prefix is this server's own control surface, not part of the AM REST API -- "
            + `the AM surface is under /${context}/json/.\n`);
    }

    return async function handle (req, res) {
        let url;
        try {
            url = new URL(req.url, PARSE_BASE);
        } catch {
            return sendText(req, res, 400, "unparseable request target\n");
        }

        const isUnder = (mount) => url.pathname === mount || url.pathname.startsWith(`${mount}/`);

        if (isUnder(CONTROL_MOUNT)) {
            return serveControl(req, res, url);
        }
        if (isUnder(xuiMount)) {
            return serveStatic(req, res, { root, mount: xuiMount, url });
        }
        if (isUnder(jsonMount)) {
            // The path below the context, which is the path the capture records and the only one
            // the REST layer reasons about -- it never has to know what `--context` was chosen.
            const apiPath = url.pathname.slice(`/${context}`.length);
            return serveRest(req, res, { url, apiPath, state: current });
        }
        // A convenience for a human who opened the port: the deployed AM answers `/openam/` with
        // its own console, which is not in scope, so send them where the UI actually is.
        if (url.pathname === "/" || url.pathname === `/${context}`
            || url.pathname === `/${context}/`) {
            res.writeHead(302, {
                Location: `${xuiMount}/`,
                "Content-Length": 0,
                "Cache-Control": "no-store",
            });
            return res.end();
        }

        return sendText(req, res, 404, `${url.pathname} is not served by the local API server.\n\n`
            + `  XUI    ${xuiMount}/\n`
            + `  REST   ${jsonMount}/   (501 outside the reads, authentication, sessions and `
            + "realm, service and profile admin)\n"
            + `  RESET  POST ${RESET_PATH}   (this server's own, not an AM route)\n`);
    };
}

function sendText (req, res, status, body, headers = {}) {
    const payload = Buffer.from(body, "utf8");
    res.writeHead(status, {
        "Content-Type": "text/plain;charset=UTF-8",
        "Content-Length": payload.length,
        "Cache-Control": "no-store",
        ...headers,
    });
    res.end(req.method === "HEAD" ? undefined : payload);
}

/**
 * The control surface's own JSON, kept here rather than shared with rest.mjs's sender.
 *
 * Same eight lines, deliberately not the same function: rest.mjs's exists to answer *as AM would*,
 * cookies and all, and a control response that borrowed it would acquire whatever that one grows
 * for AM's sake. These two surfaces have no format to keep in step.
 */
function sendJson (req, res, status, body) {
    const payload = Buffer.from(`${JSON.stringify(body, null, 2)}\n`, "utf8");
    res.writeHead(status, {
        "Content-Type": "application/json;charset=UTF-8",
        "Content-Length": payload.length,
        "Cache-Control": "no-store",
    });
    res.end(req.method === "HEAD" ? undefined : payload);
}
