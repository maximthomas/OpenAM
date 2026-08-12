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
 * Two surfaces on one origin, and nothing else.
 *
 * `/{context}/XUI/` is the built UI tree and `/{context}/json/` is the AM REST API (administrative
 * reads from task 2.6, authentication from 2.7; 501 for the rest until 2.13). Everything outside
 * them is a 404 that names the two. It would be friendlier to
 * proxy the unknown paths to a real AM, and wrong — the local backend's scope is the request list
 * in local/REQUESTS.md, and a silent fallthrough to something else is how that scope stops being
 * true without anyone noticing.
 *
 * The request target is parsed against a fixed base rather than the `Host` header. Nothing
 * downstream reads the host, and taking it from the request made a malformed `Host` — which the
 * HTTP parser allows through — look like a malformed URL.
 */

import { serveRest } from "./rest.mjs";
import { serveStatic } from "./static-tree.mjs";

const PARSE_BASE = "http://localhost";

export function createRequestHandler ({ root, context, state }) {
    const xuiMount = `/${context}/XUI`;
    const jsonMount = `/${context}/json`;

    return async function handle (req, res) {
        let url;
        try {
            url = new URL(req.url, PARSE_BASE);
        } catch {
            return sendText(req, res, 400, "unparseable request target\n");
        }

        const isUnder = (mount) => url.pathname === mount || url.pathname.startsWith(`${mount}/`);

        if (isUnder(xuiMount)) {
            return serveStatic(req, res, { root, mount: xuiMount, url });
        }
        if (isUnder(jsonMount)) {
            // The path below the context, which is the path the capture records and the only one
            // the REST layer reasons about -- it never has to know what `--context` was chosen.
            const apiPath = url.pathname.slice(`/${context}`.length);
            return serveRest(req, res, { url, apiPath, state });
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
            + `  XUI   ${xuiMount}/\n`
            + `  REST  ${jsonMount}/   (501 outside the reads and authentication)\n`);
    };
}

function sendText (req, res, status, body) {
    const payload = Buffer.from(body, "utf8");
    res.writeHead(status, {
        "Content-Type": "text/plain;charset=UTF-8",
        "Content-Length": payload.length,
        "Cache-Control": "no-store",
    });
    res.end(req.method === "HEAD" ? undefined : payload);
}
