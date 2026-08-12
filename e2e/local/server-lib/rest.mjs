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
 * The REST surface: not implemented yet, and saying so.
 *
 * This is the seam the rest of task group 2 grows into — the in-memory state from the capture
 * (2.6), authentication (2.7), sessions (2.8), `serverinfo` (2.9), realms (2.10), services
 * (2.11), profile (2.12), reset (2.13). Until then every call under `/{context}/json/` answers
 * 501.
 *
 * **501 rather than something the XUI can proceed past, deliberately.** The obvious shortcut here
 * is to answer the two bootstrap calls — a 401 from `users?_action=idFromSession`, a plausible
 * `serverinfo` — and get the login form to render, which looks like progress. It is not: a UI
 * that is past the login form on invented responses cannot tell you whether 2.7's real
 * authentication works, and the four tasks after it are verified by exactly that. A stub that
 * cannot be mistaken for a working backend is worth more than a demo.
 *
 * The envelope matches AM's own error shape — `{code, message, reason}` at
 * `application/json;charset=UTF-8`, as recorded in local/capture — so a caller that parses AM
 * errors gets something it understands, and 501 is a status AM never returns, so it can only mean
 * this server.
 */

const NOT_IMPLEMENTED_REASON = "Not Implemented";

/**
 * Answer one REST call with a labelled 501.
 *
 * `path` is reported as the caller sent it, because the first question asked of an unexpected 501
 * is "which request was that?", and the answer has to be in the response body — the browser
 * console is where it will be read, not this process's stdout.
 */
export function serveRestStub (req, res, { url }) {
    const payload = Buffer.from(`${JSON.stringify({
        code: 501,
        message: `The local API server does not implement ${req.method} ${url.pathname} yet. `
            + "Its REST surface arrives in tasks 2.6-2.13 of modernize-openam-ui-build; until "
            + "then, run the suite against a deployed AM (e2e/local/openam-up.sh).",
        reason: NOT_IMPLEMENTED_REASON,
    }, null, 2)}\n`, "utf8");

    res.writeHead(501, {
        "Content-Type": "application/json;charset=UTF-8",
        "Content-Length": payload.length,
        "Cache-Control": "no-store",
    });
    res.end(req.method === "HEAD" ? undefined : payload);
}
