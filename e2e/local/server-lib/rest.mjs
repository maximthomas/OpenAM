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
 * The REST surface: which request is which resource, and what is not answered yet.
 *
 * Task 2.6 answers the administrative *reads* out of the baseline state in state.mjs — realms, the
 * global REST service, and a realm's authentication config and service instances — plus the SMS
 * schema and template documents served verbatim. Task 2.7 adds the authentication exchange
 * (auth.mjs) and the no-session half of `users?_action=idFromSession`. Everything else is still a
 * labelled 501: session resolution and logout (2.8), `serverinfo` (2.9), every write (2.10-2.12)
 * and reset (2.13).
 *
 * **501 rather than something the XUI can proceed past, deliberately.** The shortcut task 2.6
 * refused was to answer the two bootstrap calls with something plausible and get the login form to
 * render, which looks like progress and is not: a UI past the login form on invented responses
 * cannot tell you whether the real authentication works. That rule is unchanged, and it is why 2.7
 * implements the exchange rather than faking its outcome — the callbacks document, the credential
 * check and the token are real, and they come from the recording (D15).
 *
 * It is also why `idFromSession` is split rather than answered whole. Its no-session answer is
 * task 2.7's, because a rejected login proves itself by it; resolving a session that exists is task
 * 2.8's, and until then a request that carries a credential gets the 501. Answering 401 to those
 * as well would have this server tell a logged-in browser it has no session — which the reload and
 * logout specs would then appear to confirm.
 *
 * **Both path shapes route to one resource.** REQUESTS.md §2: `fetchUrl.jsm` produces the
 * realm-scoped form and the fixtures use the legacy realm-in-query form, both appear in the same
 * run, and a server that answers only one of them cannot let the `@local-server` specs provision
 * themselves. So `/json/realms/root/realms/alpha/realm-config/services/baseurl` and
 * `/json/realm-config/services/baseurl?realm=/alpha` parse to the same route.
 *
 * That equivalence holds for the reads. It does *not* extend to the verbatim documents, which are
 * found by the path they were recorded under: a schema was only ever recorded at the realm-scoped
 * shape, so asking for one at the legacy shape answers 501. No request in REQUESTS.md does, and
 * this is here so the next reader does not take that 501 for a routing bug.
 *
 * **`Accept-API-Version` is still not read, and one route now has to discriminate without it.** The
 * administrative reads were recorded at `resource=1.0`, `idFromSession` at `2.0`, and the
 * authenticate callbacks exchange at `2.1` -- one version each, nothing to choose between. The
 * exception is the `authenticate` route, which covers two recorded calls: the callbacks exchange
 * the XUI drives, and the fixtures' one-call header authentication recorded at
 * `resource=2.0, protocol=1.0`. Those are told apart by the credential *headers*, not by the
 * version, because the headers are what makes a request the second kind while a client may send any
 * version it likes. See `serveAuthenticate`.
 *
 * The version remains a real input -- REQUESTS.md notes `GET /json/serverinfo/*` returns different
 * fields depending on it, and the capture holds both -- and task 2.9, which owns that route, is
 * where honouring it starts.
 *
 * The envelope matches AM's own error shape — `{code, message, reason}` at
 * `application/json;charset=UTF-8`, as recorded in local/capture — so a caller that parses AM
 * errors gets something it understands, and 501 is a status AM never returns, so it can only mean
 * this server.
 */

const NOT_IMPLEMENTED_REASON = "Not Implemented";

/** A requirements document is a few hundred bytes; this is only here so nothing is unbounded. */
const MAX_BODY_BYTES = 1 << 20;

/**
 * Which resource a request addresses, in the capture's own route vocabulary.
 *
 * `routePath` is the path with realm segments replaced by the placeholders the capture tree uses
 * as directory names, so a schema recorded once under `{realm}` answers for every realm a spec
 * invents at run time — the routes-versus-transcripts asymmetry capture/README.md sets out.
 */
export function parseRoute (apiPath, query) {
    const segments = apiPath.split("/").filter((segment) => segment !== "").map(decodeSegment);
    // The router only reaches here for paths under the json mount, so segments[0] is "json".
    const rest = segments.slice(1);

    if (rest[0] === "global-config") {
        if (rest[1] === "realms") {
            if (rest.length === 2) {
                return { kind: "realms-collection", routePath: apiPath };
            }
            if (rest.length === 3) {
                return {
                    kind: "realms-member",
                    realmId: rest[2],
                    routePath: "/json/global-config/realms/{realmId}",
                };
            }
        }
        if (rest[1] === "services" && rest.length === 3) {
            return { kind: "global-service", serviceId: rest[2], routePath: apiPath };
        }
        return { kind: "other", routePath: apiPath };
    }

    // The realm-scoped shape the XUI produces: /json/realms/root[/realms/<realm>]/realm-config/…
    if (rest[0] === "realms" && rest[1] === "root") {
        let after = rest.slice(2);
        const routeSegments = ["json", "realms", "root"];
        let realmPath = "/";

        if (after[0] === "realms" && after.length > 1) {
            realmPath = `/${after[1]}`;
            routeSegments.push("realms", "{realm}");
            after = after.slice(2);
        }
        routeSegments.push(...after);

        return { ...realmScopedRoute(after, realmPath, query),
            routePath: `/${routeSegments.join("/")}` };
    }

    // The legacy shape the fixtures produce: the realm travels in a query parameter. `authenticate`
    // and `users` reach it by a second route as well -- `fetchUrl` drops the realm segment entirely
    // while `store.getState().session.realm` is unset, which is every request before a session
    // exists. So the bare `/json/authenticate` and `/json/users` are not a legacy shape here but
    // the *bootstrap's* shape, and answering only the realm-scoped one would leave a cold load with
    // no way to reach the login form at all.
    if (["realm-config", "authenticate", "users"].includes(rest[0])) {
        return { ...realmScopedRoute(rest, realmPathFromQuery(query), query), routePath: apiPath };
    }

    return { kind: "other", routePath: apiPath };
}

/**
 * A path segment as the resource is actually named.
 *
 * A realm the specs invent at run time is a store key on one side of this and a URL segment on the
 * other, so `%20` has to stop being an escape before the two are compared. It costs nothing today,
 * when the only realm is `/`, and it decides whether task 2.10's created realms can be read back.
 */
function decodeSegment (segment) {
    try {
        return decodeURIComponent(segment);
    } catch {
        // A malformed escape is not a resource this server has. Leaving it as sent means the 404
        // quotes what was asked for rather than something that was never in the request.
        return segment;
    }
}

/** `?realm=/alpha`, `?realm=alpha` and an absent parameter all name a realm path. */
function realmPathFromQuery (query) {
    const realm = (query.realm ?? "").trim();
    if (realm === "" || realm === "/") {
        return "/";
    }
    return realm.startsWith("/") ? realm : `/${realm}`;
}

/** The tail below the realm, which is identical under both path shapes. */
function realmScopedRoute (segments, realmPath, query) {
    // The two-leg credential exchange. One endpoint, and which leg it is depends on the body.
    //
    // `authIndexType`/`authIndexValue` select a chain or a module other than the realm's default,
    // and this server has no chain but the recorded `DataStore1` one. Answering such a request with
    // that chain's callbacks would be this file's own cardinal sin -- something the XUI can proceed
    // past that is not what was asked for. Every spec that drives a named chain or module is
    // @deployed-am (REQUESTS.md), so the labelled 501 is both correct and unreachable in practice.
    if (segments[0] === "authenticate" && segments.length === 1) {
        return query.authIndexType === undefined && query.authIndexValue === undefined
            ? { kind: "authenticate", realmPath }
            : { kind: "other", realmPath };
    }
    // `?_action=idFromSession`. The member path below it -- `users/<name>`, the profile read that
    // decides where the XUI routes a logged-in user -- is task 2.12's and stays a 501 here.
    if (segments[0] === "users" && segments.length === 1) {
        return { kind: "users-collection", realmPath };
    }
    if (segments[0] !== "realm-config") {
        return { kind: "other", realmPath };
    }
    if (segments[1] === "authentication" && segments.length === 2) {
        return { kind: "realm-authentication", realmPath };
    }
    if (segments[1] === "services") {
        if (segments.length === 2) {
            return { kind: "realm-services", realmPath };
        }
        if (segments.length === 3) {
            return { kind: "realm-service", realmPath, serviceId: segments[2] };
        }
    }
    // Deeper paths are the authentication chains and modules, which every spec that uses them
    // tags @deployed-am — out of this server's scope by construction (REQUESTS.md).
    return { kind: "other", realmPath };
}

/**
 * The read for a route, or `undefined` when this server does not answer it.
 *
 * A collection is answered only with `_queryFilter`, because that is the only form the request
 * list contains and an unfiltered collection GET is a request AM would answer differently.
 */
function read (route, query, state) {
    switch (route.kind) {
    case "realms-collection":
        return query._queryFilter === undefined ? undefined : state.realmsListing();
    case "realms-member":
        return state.realmById(route.realmId);
    case "global-service":
        return state.globalService(route.serviceId);
    case "realm-authentication":
        return state.realmAuthentication(route.realmPath);
    case "realm-services":
        return query._queryFilter === undefined
            ? undefined
            : state.realmServicesListing(route.realmPath);
    case "realm-service":
        return state.realmService(route.realmPath, route.serviceId);
    default:
        return undefined;
    }
}

/**
 * Answer one REST call.
 *
 * `apiPath` is the path below the context — `/json/…`, the same path the capture records — so this
 * module never has to know what `--context` the server was started under.
 */
export async function serveRest (req, res, { url, apiPath, state }) {
    const query = Object.fromEntries(url.searchParams);
    const route = parseRoute(apiPath, query);

    if (route.kind === "authenticate" && req.method === "POST") {
        return serveAuthenticate(req, res, { url, route, state });
    }
    if (route.kind === "users-collection" && req.method === "POST"
        && query._action === "idFromSession") {
        return serveIdFromSession(req, res, { url, state });
    }

    // Any action at all is offered to the store, which holds only the documents state.mjs decided
    // to serve verbatim and answers `undefined` for everything else. Keeping a second copy of that
    // list here would let the two disagree, and the disagreement is invisible: when task 2.11 adds
    // an action to the store, a gate here that had not been updated would keep answering 501, and
    // a 501 reads as "out of scope" rather than as a bug.
    if (req.method === "POST" && query._action !== undefined) {
        const body = state.verbatim({ method: "POST", path: route.routePath, query });
        if (body !== undefined) {
            return sendJson(req, res, 200, body);
        }
    }

    if (req.method === "GET" || req.method === "HEAD") {
        const answer = read(route, query, state);
        if (answer !== undefined) {
            return sendJson(req, res, answer.status, answer.body);
        }
    }

    return sendNotImplemented(req, res, url);
}

/**
 * The authentication exchange (task 2.7). Which leg this is depends on the body, not the URL.
 *
 * `AuthNService.begin` posts an **empty string** — not `{}` and not an absent body — and
 * `submitRequirements` posts the document it was given back, `authId` and all. So a body that names
 * an in-flight login is a submission and anything else starts one, which also makes a stray POST
 * from a human with curl do the useful thing rather than fail.
 *
 * Not read, deliberately: `Accept-API-Version`, as everywhere else in this file, and the
 * `X-NoSession` / `X-Username` / `X-Password` headers the browser sends on every call here. See
 * auth.mjs on why honouring the last three would authenticate nobody.
 */
async function serveAuthenticate (req, res, { url, route, state }) {
    // The one-call authentication the fixtures use -- `getAuthToken` in common/openam-commons.mjs
    // posts the credentials as headers and reads `tokenId` straight out of the answer. It is a real
    // request on this server's list, it is not implemented (NOTES-auth.md §9.6 on why zero-page
    // login stays out), and it must keep saying so: answering it with a callbacks document would
    // hand `getAuthToken` an `undefined` token that surfaces several calls later as an unexplained
    // 401. Tasks 2.10-2.12 are the ones that will need it, and a 501 naming itself is what they
    // should find. Detected by the headers rather than by `Accept-API-Version`, because the headers
    // are what makes it this call -- the version differs too, but a client is free to send any.
    if (req.headers["x-openam-username"] !== undefined
        || req.headers["x-openam-password"] !== undefined) {
        return sendNotImplemented(req, res, url);
    }

    let raw;
    try {
        raw = await readBody(req);
    } catch (error) {
        if (!error.oversize) {
            // A socket that died mid-body is not a bad request, and reporting it as one puts a
            // message no caller recognises in front of whoever is reading the log. Let the router's
            // own handler have it.
            throw error;
        }
        return sendJson(req, res, 400, {
            code: 400, message: error.message, reason: "Bad Request",
        });
    }

    let requirements;
    if (raw.trim() !== "") {
        try {
            requirements = JSON.parse(raw);
        } catch {
            return sendJson(req, res, 400, {
                code: 400,
                message: "The authenticate body must be the requirements document, as JSON.",
                reason: "Bad Request",
            });
        }
    }

    const answer = requirements?.authId === undefined
        ? state.auth.begin(route.realmPath)
        // No realm on this leg: the login's realm was fixed by the `begin` its `authId` names.
        : state.auth.submit(requirements);

    return sendJson(req, res, answer.status, answer.body, answer.sessionToken === undefined
        ? []
        : [sessionCookie(state.auth.cookieName, answer.sessionToken)]);
}

/**
 * `POST …/users?_action=idFromSession` — but only its no-session half, which is task 2.7's.
 *
 * Resolving a session that *does* exist is task 2.8, so a request that carries a credential gets
 * the labelled 501 rather than a guess. That split is the honest one: answering 401 for every call
 * would let this server tell a logged-in browser it has no session, which is a lie the reload and
 * logout specs would then appear to confirm, and answering 501 for every call would break the two
 * negative assertions that are the whole point of the rejected-credential test.
 */
function serveIdFromSession (req, res, { url, state }) {
    if (hasSessionCredential(req, url, state.auth.cookieName)) {
        return sendNotImplemented(req, res, url);
    }
    const answer = state.auth.anonymous();
    return sendJson(req, res, answer.status, answer.body);
}

/**
 * Does this request carry something that could name a session?
 *
 * The three ways one arrives, in the precedence NOTES-auth.md §7 sets out: the `tokenId` query
 * parameter the XUI adds when it can read the cookie, the cookie itself, and the bare
 * `iPlanetDirectoryPro` request header, which is how the Playwright `APIRequestContext` fixtures
 * pass a token (REQUESTS.md Fact 6). Whether the value resolves to a live session is task 2.8's
 * question; this only asks whether one was offered.
 */
function hasSessionCredential (req, url, cookieName) {
    // All three tested the same way. An empty value is not a credential, whichever carrier it
    // arrives in -- and the carriers disagreeing about that is how one of them ends up answering a
    // question the other two would have declined.
    return [
        url.searchParams.get("tokenId"),
        req.headers[cookieName.toLowerCase()],
        cookieValue(req.headers.cookie, cookieName),
    ].some(Boolean);
}

/** One cookie out of a `Cookie` header, or `undefined`. */
function cookieValue (header, name) {
    for (const pair of (header ?? "").split(";")) {
        const separator = pair.indexOf("=");
        if (separator !== -1 && pair.slice(0, separator).trim() === name) {
            return pair.slice(separator + 1).trim();
        }
    }
    return undefined;
}

/**
 * The session cookie, as a server on a host that is not AM's may set it.
 *
 * Three attributes, and the reasoning for each is in NOTES-auth.md §3:
 *
 *   - `Path=/` — AM's, and safe to copy: both surfaces live under one origin here.
 *   - `SameSite=Lax` — AM's, and safe to copy. It is also what `serverinfo/*` reports as
 *     `cookieSameSite`, so the XUI's own client-side write uses the same value.
 *   - *(no `Domain`)* — **AM's `domain=example.org` must not be copied.** It names the recording
 *     deployment's cookie domain, an origin on `localhost` cannot set it, and a browser discards
 *     the whole cookie when it tries. Omitting the attribute is what makes this host-only. The
 *     symptom of getting it wrong is the one worth recognising: a login that appears to work, and a
 *     reload that logs you out.
 *
 * And three AM sets, or could, that are deliberately absent:
 *
 *   - *(no `Secure`)* — the local server is plain HTTP; a `Secure` cookie would be dropped.
 *   - *(no `HttpOnly`)* — this deployment records `cookieHttpOnly: false`, which is what puts
 *     `SessionToken` on its readable-cookie path. Setting it would switch the XUI to the HttpOnly
 *     code path, which is what xui-httponly.spec.mjs asserts against a real AM and is deployed-AM
 *     only by design (design.md D16, NOTES-auth.md §9).
 *   - *(no `Expires`/`Max-Age`)* — AM's is a browser-session cookie.
 *
 * Not emitted at all: `amlbcookie`, a load balancer's stickiness cookie naming the recording
 * container's server id, and `AMAuthCookie`, AM's own in-flight authentication handle. Nothing in
 * the XUI reads either, and the exchange was observed to complete without both.
 */
function sessionCookie (name, token) {
    return `${name}=${token}; Path=/; SameSite=Lax`;
}

/** A request body, with a cap. Nothing the XUI posts here is within two orders of it. */
async function readBody (req) {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
            // Flagged rather than matched on by message: the caller has to tell this apart from a
            // connection that died, and the two mean different things to whoever reads the answer.
            throw Object.assign(new Error(`The request body exceeds ${MAX_BODY_BYTES} bytes.`),
                { oversize: true });
        }
        chunks.push(chunk);
    }
    return Buffer.concat(chunks).toString("utf8");
}

function sendJson (req, res, status, body, cookies = []) {
    const payload = Buffer.from(`${JSON.stringify(body)}\n`, "utf8");
    res.writeHead(status, {
        "Content-Type": "application/json;charset=UTF-8",
        "Content-Length": payload.length,
        "Cache-Control": "no-store",
        ...(cookies.length === 0 ? {} : { "Set-Cookie": cookies }),
    });
    res.end(req.method === "HEAD" ? undefined : payload);
}

/**
 * The labelled 501.
 *
 * `path` is reported as the caller sent it, because the first question asked of an unexpected 501
 * is "which request was that?", and the answer has to be in the response body — the browser
 * console is where it will be read, not this process's stdout.
 */
function sendNotImplemented (req, res, url) {
    const payload = Buffer.from(`${JSON.stringify({
        code: 501,
        message: `The local API server does not implement ${req.method} ${url.pathname} yet. `
            + "Its administrative reads arrive in task 2.6 of modernize-openam-ui-build, "
            + "authentication in 2.7 and the rest of its REST surface in 2.8-2.13; until then, run "
            + "the suite against a deployed AM (e2e/local/openam-up.sh).",
        reason: NOT_IMPLEMENTED_REASON,
    }, null, 2)}\n`, "utf8");

    res.writeHead(501, {
        "Content-Type": "application/json;charset=UTF-8",
        "Content-Length": payload.length,
        "Cache-Control": "no-store",
    });
    res.end(req.method === "HEAD" ? undefined : payload);
}
