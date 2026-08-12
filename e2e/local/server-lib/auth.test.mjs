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
 * The authentication exchange, over a real socket.
 *
 *     node --test local/server-lib/
 *
 * Over HTTP rather than against `createAuthState` directly, because half of what task 2.7 owes is
 * in the response headers: a `Set-Cookie` that a browser on `localhost` will actually keep. A unit
 * test of the state machine would agree with a cookie carrying AM's `Domain=example.org`, and a
 * browser would silently discard it — the failure this suite exists to catch, and one that surfaces
 * as a login that appears to work and a reload that logs you out.
 *
 * The credentials are the suite's own (common/openam-commons.mjs), which is what this server's
 * directory is built from; they are imported here for the same reason state.mjs imports them, so a
 * run that overrides `OPENAM_USERNAME` moves the test with the server.
 *
 * xui-login.spec.mjs is the acceptance test and it drives a browser. This is the wire-level check
 * underneath it: what the two legs carry, and what a rejected credential does not carry.
 */

import assert from "node:assert/strict";
import { createServer } from "node:http";
import { after, before, describe, it } from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { PASSWORD, USERNAME } from "../../common/openam-commons.mjs";
import { createRequestHandler } from "./router.mjs";
import { buildBaselineState } from "./state.mjs";

const CAPTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "capture");

/** The version the XUI sends on every call here. Recorded, and not read — see rest.mjs. */
const AUTHN_VERSION = "protocol=1.0,resource=2.1";

/**
 * The realm-scoped path the XUI builds once its bootstrap has a realm, and the bare one it builds
 * before that. Both are live shapes, not one legacy form: `fetchUrl` drops the realm segment while
 * `session.realm` is unset, which is every request before a session exists.
 */
const PATHS = ["/openam/json/realms/root/authenticate", "/openam/json/authenticate"];

let server;
let origin;
let state;

/** POST to the authenticate endpoint the way `AuthNService` does, and unpack the answer. */
async function authenticate (path, body, headers = {}) {
    const response = await fetch(`${origin}${path}`, {
        method: "POST",
        headers: { "Accept-API-Version": AUTHN_VERSION, ...headers },
        body,
    });
    return {
        status: response.status,
        cookies: response.headers.getSetCookie(),
        body: await response.json(),
    };
}

/** The first leg: an empty string body, as `AuthNService.begin` sends. */
const begin = (path = PATHS[0]) => authenticate(path, "");

/** The second leg: the document from the first, with the values typed into it. */
function submit (requirements, user, pass, path = PATHS[0]) {
    const filled = structuredClone(requirements);
    filled.callbacks[0].input[0].value = user;
    filled.callbacks[1].input[0].value = pass;
    return authenticate(path, JSON.stringify(filled));
}

before(async () => {
    state = buildBaselineState(CAPTURE_DIR, { context: "openam", hostname: "localhost" });
    const handle = createRequestHandler({ root: CAPTURE_DIR, context: "openam", state });
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

describe("presenting the credential requirements", () => {
    it("answers an empty body with the recorded callbacks document", async () => {
        const response = await begin();

        assert.equal(response.status, 200);
        // The fields the XUI reads: `stage` selects the login template, and the input names are
        // what the rendered form's #idToken1 / #idToken2 ids derive from.
        assert.equal(response.body.stage, "DataStore1");
        assert.deepEqual(response.body.callbacks.map((callback) => callback.type),
            ["NameCallback", "PasswordCallback"]);
        assert.deepEqual(response.body.callbacks.map((callback) => callback.input[0].name),
            ["IDToken1", "IDToken2"]);
        assert.deepEqual(response.body.callbacks.map((callback) => callback.input[0].value),
            ["", ""]);
        assert.equal(response.body.header, "Sign in to OpenAM");
    });

    it("mints an authId, and a different one each time", async () => {
        const [first, second] = [await begin(), await begin()];

        assert.equal(typeof first.body.authId, "string");
        assert.notEqual(first.body.authId, "");
        assert.notEqual(first.body.authId, second.body.authId);
        // The recording's marker for a value minted per call must not reach a client.
        assert.notEqual(first.body.authId, "<AUTHID>");
    });

    it("establishes no session", async () => {
        assert.deepEqual((await begin()).cookies, []);
    });

    it("answers at both path shapes, because a cold load uses the bare one", async () => {
        for (const path of PATHS) {
            assert.equal((await begin(path)).status, 200, path);
        }
    });

    it("does not hand out the same document twice", async () => {
        // Returned by reference, the template would carry the previous login's typed-in values
        // into the next form.
        const first = await begin();
        await submit(first.body, USERNAME, PASSWORD);

        assert.deepEqual((await begin()).body.callbacks.map((c) => c.input[0].value), ["", ""]);
    });
});

describe("accepting a submission", () => {
    it("completes the authentication with exactly AM's three fields", async () => {
        const response = await submit((await begin()).body, USERNAME, PASSWORD);

        assert.equal(response.status, 200);
        assert.deepEqual(Object.keys(response.body).sort(), ["realm", "successUrl", "tokenId"]);
        assert.equal(response.body.realm, "/");
        assert.equal(response.body.successUrl, "/openam/console");
        assert.notEqual(response.body.tokenId, "<TOKEN>");
    });

    it("records the session under the token it returned", async () => {
        const response = await submit((await begin()).body, USERNAME, PASSWORD);

        assert.equal(state.auth.sessions.get(response.body.tokenId)?.username, USERNAME);
    });

    it("resolves the principal case-insensitively, keeping the directory's spelling", async () => {
        const response = await submit((await begin()).body, USERNAME.toUpperCase(), PASSWORD);

        assert.equal(response.status, 200);
        assert.equal(state.auth.sessions.get(response.body.tokenId)?.username, USERNAME);
    });

    it("ignores the anonymous headers the browser sends on every call", async () => {
        // X-NoSession / X-Username / X-Password ride along on the call carrying real credentials
        // too. A server that honoured them would authenticate nobody.
        const requirements = (await begin()).body;
        const filled = structuredClone(requirements);
        filled.callbacks[0].input[0].value = USERNAME;
        filled.callbacks[1].input[0].value = PASSWORD;

        const response = await authenticate(PATHS[0], JSON.stringify(filled), {
            "X-NoSession": "true", "X-Username": "anonymous", "X-Password": "anonymous",
        });

        assert.equal(response.status, 200);
        assert.equal(typeof response.body.tokenId, "string");
    });

    it("reads the values by callback type, not by their position", async () => {
        const requirements = (await begin()).body;
        requirements.callbacks[0].input[0].value = USERNAME;
        requirements.callbacks[1].input[0].value = PASSWORD;
        requirements.callbacks.reverse();

        assert.equal((await authenticate(PATHS[0], JSON.stringify(requirements))).status, 200);
    });

    it("refuses a submission naming no login it started", async () => {
        const requirements = (await begin()).body;
        requirements.authId = "not-an-authId-this-server-issued";

        const response = await submit(requirements, USERNAME, PASSWORD);

        assert.equal(response.status, 401);
        assert.deepEqual(response.cookies, []);
    });

    it("keeps the login in the realm its begin was made in", async () => {
        // AM fixes the realm at `begin` and carries it inside the authId, so a second leg cannot
        // move a login to another realm by being posted somewhere else.
        const requirements = (await begin("/openam/json/realms/root/authenticate")).body;
        const filled = structuredClone(requirements);
        filled.callbacks[0].input[0].value = USERNAME;
        filled.callbacks[1].input[0].value = PASSWORD;

        const response = await authenticate(
            "/openam/json/realms/root/realms/alpha/authenticate", JSON.stringify(filled));

        assert.equal(response.status, 200);
        assert.equal(response.body.realm, "/");
        assert.equal(state.auth.sessions.get(response.body.tokenId)?.realmPath, "/");
    });

    it("answers a malformed body with 400 rather than a callbacks document", async () => {
        const response = await authenticate(PATHS[0], "{not json");

        assert.equal(response.status, 400);
        assert.equal(response.body.reason, "Bad Request");
    });
});

describe("what authenticate does not implement", () => {
    it("keeps saying 501 to the fixtures' one-call header authentication", async () => {
        // common/openam-commons.mjs's getAuthToken posts the credentials as headers and reads
        // `tokenId` off the answer. Answering it with a callbacks document would hand it an
        // `undefined` token that surfaces several calls later as an unexplained 401 -- which is
        // what tasks 2.10-2.12 would then have to debug. It is not implemented, and it says so.
        const response = await fetch(`${origin}/openam/json/authenticate`, {
            method: "POST",
            headers: {
                "Accept-API-Version": "resource=2.0, protocol=1.0",
                "X-OpenAM-Username": USERNAME,
                "X-OpenAM-Password": PASSWORD,
            },
        });

        assert.equal(response.status, 501);
        assert.equal((await response.json()).reason, "Not Implemented");
        assert.deepEqual(response.headers.getSetCookie(), []);
    });

    it("refuses a named chain or module rather than answering with the default one", async () => {
        // Every spec that drives one is @deployed-am; this server has only the recorded DataStore1
        // chain, and handing that back would be answering a question nobody asked.
        for (const query of ["authIndexType=module&authIndexValue=HOTP",
            "authIndexType=service&authIndexValue=ldapService"]) {
            const response = await authenticate(`${PATHS[0]}?${query}`, "");

            assert.equal(response.status, 501, query);
        }
    });
});

describe("a rejected credential", () => {
    it("answers 401 with AM's recorded body and no session", async () => {
        const response = await submit((await begin()).body, USERNAME, "not-the-password");

        assert.equal(response.status, 401);
        assert.deepEqual(response.body,
            { code: 401, message: "Authentication Failed", reason: "Unauthorized" });
        assert.deepEqual(response.cookies, []);
    });

    it("says something different from an unauthenticated request", async () => {
        // Two 401s with two messages, and both are recorded. The XUI renders this one verbatim as
        // the danger alert xui-login.spec.mjs asserts on.
        const rejected = await submit((await begin()).body, USERNAME, "not-the-password");
        const anonymous = await fetch(`${origin}/openam/json/users?_action=idFromSession`,
            { method: "POST" });

        assert.equal(anonymous.status, 401);
        assert.equal((await anonymous.json()).message, "Access Denied");
        assert.equal(rejected.body.message, "Authentication Failed");
    });

    it("rejects an unknown user the same way, saying nothing about which half was wrong",
        async () => {
            const response = await submit((await begin()).body, "nobody-here", PASSWORD);

            assert.equal(response.status, 401);
            assert.equal(response.body.message, "Authentication Failed");
        });

    it("leaves the login in flight, because a mistyped password is what a user retries",
        async () => {
            const requirements = (await begin()).body;
            await submit(requirements, USERNAME, "not-the-password");

            assert.equal((await submit(requirements, USERNAME, PASSWORD)).status, 200);
        });
});

describe("the session cookie", () => {
    /** The `Set-Cookie` from a successful authentication, split into its attributes. */
    async function cookie () {
        const response = await submit((await begin()).body, USERNAME, PASSWORD);
        assert.equal(response.cookies.length, 1, "exactly one cookie establishes the session");
        const [pair, ...attributes] = response.cookies[0].split(";").map((part) => part.trim());
        return { pair, attributes, token: response.body.tokenId };
    }

    it("carries the token under the name the XUI will look for", async () => {
        const { pair, token } = await cookie();

        // Not hardcoded on either side: the server reads the name from the capture's serverinfo
        // recording, and the XUI reads it from the same field once task 2.9 serves that document.
        assert.equal(state.auth.cookieName, "iPlanetDirectoryPro");
        assert.equal(pair, `${state.auth.cookieName}=${token}`);
    });

    it("sets Path and SameSite, which are AM's and safe to copy", async () => {
        assert.deepEqual((await cookie()).attributes.sort(), ["Path=/", "SameSite=Lax"]);
    });

    it("sets no Domain, so the browser keeps it on localhost", async () => {
        // The one attribute of AM's that must not be copied. `domain=example.org` names the
        // recording deployment; an origin on localhost cannot set it and a browser discards the
        // whole cookie when it tries.
        const { attributes } = await cookie();

        assert.equal(attributes.find((a) => /^domain=/i.test(a)), undefined);
    });

    it("sets neither Secure nor HttpOnly", async () => {
        // Secure would be dropped over plain HTTP. HttpOnly would switch the XUI to its
        // HttpOnly code path, which is what xui-httponly.spec.mjs asserts against a real AM and
        // is deployed-AM-only by design (design.md D16).
        const { attributes } = await cookie();

        assert.equal(attributes.find((a) => /^(secure|httponly)$/i.test(a)), undefined);
    });

    it("expires with the browser session, as AM's does", async () => {
        const { attributes } = await cookie();

        assert.equal(attributes.find((a) => /^(expires|max-age)=/i.test(a)), undefined);
    });

    it("emits neither amlbcookie nor AMAuthCookie", async () => {
        // AM sets both. Nothing in the XUI reads either, and the exchange completes without them.
        const response = await submit((await begin()).body, USERNAME, PASSWORD);

        assert.deepEqual(response.cookies.filter((c) => !c.startsWith(state.auth.cookieName)), []);
    });

    it("mints a distinct token per login", async () => {
        const [first, second] = [await cookie(), await cookie()];

        assert.notEqual(first.token, second.token);
    });
});

describe("idFromSession, the half task 2.7 owns", () => {
    it("answers a request carrying no session with AM's 401", async () => {
        for (const path of ["/openam/json/users", "/openam/json/realms/root/users"]) {
            const response = await fetch(`${origin}${path}?_action=idFromSession`,
                { method: "POST" });

            assert.equal(response.status, 401, path);
            assert.deepEqual(await response.json(),
                { code: 401, message: "Access Denied", reason: "Unauthorized" }, path);
        }
    });

    it("does not read an empty value as a session, whichever carrier it arrives in", async () => {
        // The three carriers have to agree about this, or one of them answers a question the other
        // two would have declined.
        const empty = [
            { query: "&tokenId=" },
            { headers: { Cookie: "iPlanetDirectoryPro=" } },
            { headers: { iPlanetDirectoryPro: "" } },
        ];
        for (const carrier of empty) {
            const response = await fetch(
                `${origin}/openam/json/users?_action=idFromSession${carrier.query ?? ""}`,
                { method: "POST", headers: carrier.headers ?? {} },
            );

            assert.equal(response.status, 401, JSON.stringify(carrier));
        }
    });

    it("leaves a request that does carry one to task 2.8, rather than calling it anonymous",
        async () => {
            const { token } = await (async () => {
                const response = await submit((await begin()).body, USERNAME, PASSWORD);
                return { token: response.body.tokenId };
            })();

            // The three ways a session credential arrives. None of them resolves yet, and none of
            // them may be answered "no session" -- that would be this server telling a logged-in
            // browser it is logged out.
            const carriers = [
                { query: `&tokenId=${token}` },
                { headers: { Cookie: `${state.auth.cookieName}=${token}` } },
                { headers: { [state.auth.cookieName]: token } },
            ];
            for (const carrier of carriers) {
                const response = await fetch(
                    `${origin}/openam/json/users?_action=idFromSession${carrier.query ?? ""}`,
                    { method: "POST", headers: carrier.headers ?? {} },
                );

                assert.equal(response.status, 501, JSON.stringify(carrier));
            }
        });
});
