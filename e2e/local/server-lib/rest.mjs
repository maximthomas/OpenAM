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
 * schema and template documents served verbatim. Everything else is still a labelled 501:
 * authentication (2.7), sessions (2.8), `serverinfo` (2.9), every write (2.10-2.12) and reset
 * (2.13).
 *
 * **501 rather than something the XUI can proceed past, deliberately.** The obvious shortcut is to
 * answer the two bootstrap calls — a 401 from `users?_action=idFromSession`, a plausible
 * `serverinfo` — and get the login form to render, which looks like progress. It is not: a UI that
 * is past the login form on invented responses cannot tell you whether 2.7's real authentication
 * works, and the four tasks after it are verified by exactly that. Nothing routed here can put the
 * XUI past a login that does not exist yet; the reads below are all administrative resources that
 * a session-less browser never reaches.
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
 * **`Accept-API-Version` is not read.** Every request this task answers was recorded at
 * `protocol=1.0,resource=1.0`, so there is nothing yet to choose between. It is a real input --
 * REQUESTS.md notes `GET /json/serverinfo/*` returns different fields depending on it -- and task
 * 2.9, which owns that route, is where honouring it starts.
 *
 * The envelope matches AM's own error shape — `{code, message, reason}` at
 * `application/json;charset=UTF-8`, as recorded in local/capture — so a caller that parses AM
 * errors gets something it understands, and 501 is a status AM never returns, so it can only mean
 * this server.
 */

const NOT_IMPLEMENTED_REASON = "Not Implemented";

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

        return { ...realmConfigRoute(after, realmPath), routePath: `/${routeSegments.join("/")}` };
    }

    // The legacy shape the fixtures produce: the realm travels in a query parameter.
    if (rest[0] === "realm-config") {
        return { ...realmConfigRoute(rest, realmPathFromQuery(query)), routePath: apiPath };
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

/** The `realm-config/…` tail, which is identical under both path shapes. */
function realmConfigRoute (segments, realmPath) {
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
export function serveRest (req, res, { url, apiPath, state }) {
    const query = Object.fromEntries(url.searchParams);
    const route = parseRoute(apiPath, query);

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

function sendJson (req, res, status, body) {
    const payload = Buffer.from(`${JSON.stringify(body)}\n`, "utf8");
    res.writeHead(status, {
        "Content-Type": "application/json;charset=UTF-8",
        "Content-Length": payload.length,
        "Cache-Control": "no-store",
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
            + "Its administrative reads arrive in task 2.6 of modernize-openam-ui-build and the "
            + "rest of its REST surface in 2.7-2.13; until then, run the suite against a deployed "
            + "AM (e2e/local/openam-up.sh).",
        reason: NOT_IMPLEMENTED_REASON,
    }, null, 2)}\n`, "utf8");

    res.writeHead(501, {
        "Content-Type": "application/json;charset=UTF-8",
        "Content-Length": payload.length,
        "Cache-Control": "no-store",
    });
    res.end(req.method === "HEAD" ? undefined : payload);
}
