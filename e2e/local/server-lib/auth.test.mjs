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
 * The authentication exchange and the session it establishes, over a real socket.
 *
 *     npm run test:server
 *
 * Over HTTP rather than against `createAuthState` directly, because half of what task 2.7 owes is
 * in the response headers: a `Set-Cookie` that a browser on `localhost` will actually keep. A unit
 * test of the state machine would agree with a cookie carrying AM's `Domain=example.org`, and a
 * browser would silently discard it — the failure this suite exists to catch, and one that surfaces
 * as a login that appears to work and a reload that logs you out. Task 2.8's half needs the same
 * reach for the same reason: what a reload resolves a session from is a request header nobody in
 * the browser chose to send, so a test that passed the token in would be proving something else.
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

import { ADMIN_PASS, ADMIN_USER, PASSWORD, USERNAME } from "../../common/openam-commons.mjs";
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

/**
 * The fixtures' one-call header authentication (task 2.10).
 *
 * `getAuthToken` in common/openam-commons.mjs posts the credentials as headers and reads `tokenId`
 * straight out of the answer, and every `@local-server` spec that provisions anything goes through
 * it. Task 2.7 left it out, and the failure mode it warned about is what these pin: a callbacks
 * document answered here hands the caller an `undefined` token that surfaces several calls later as
 * an unexplained 401.
 */
describe("the one-call header authentication", () => {
    /** Post credentials as headers, the way `getAuthToken` does. */
    const headerLogin = (user, pass) => fetch(`${origin}/openam/json/authenticate`, {
        method: "POST",
        headers: {
            "Accept-API-Version": "resource=2.0, protocol=1.0",
            "X-OpenAM-Username": user,
            "X-OpenAM-Password": pass,
        },
    });

    it("answers a token directly, with no callbacks to submit", async () => {
        const response = await headerLogin(USERNAME, PASSWORD);
        const body = await response.json();

        assert.equal(response.status, 200);
        assert.deepEqual(Object.keys(body).sort(), ["realm", "successUrl", "tokenId"]);
        assert.ok(body.tokenId, "the token is what getAuthToken reads");
        assert.equal(body.realm, "/");
    });

    it("establishes a session the rest of the server resolves", async () => {
        // The point of routing both doors through one `establish`: a fixture's token has to work
        // everywhere a browser's does, or a spec can provision and then not read back what it made.
        const { tokenId } = await (await headerLogin(USERNAME, PASSWORD)).json();
        const resolved = await fetch(`${origin}/openam/json/users?_action=idFromSession`, {
            method: "POST",
            headers: { "iPlanetDirectoryPro": tokenId },
        });

        assert.equal(resolved.status, 200);
        assert.equal((await resolved.json()).id, USERNAME);
    });

    it("sets the session cookie as the callback exchange does", async () => {
        const response = await headerLogin(USERNAME, PASSWORD);

        assert.deepEqual(response.headers.getSetCookie().map((c) => c.split("=")[0]),
            ["iPlanetDirectoryPro"]);
    });

    it("rejects a wrong password without establishing anything", async () => {
        const response = await headerLogin(USERNAME, "not-the-password");

        assert.equal(response.status, 401);
        assert.deepEqual(response.headers.getSetCookie(), []);
    });
});

describe("what authenticate does not implement", () => {
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

describe("idFromSession without a session", () => {
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

    it("does not read a token this server never issued as one", async () => {
        // A stale cookie left over from an earlier run, which is what a browser holds after the
        // server it logged into was restarted. NOTES-auth.md §5: both bootstrap calls must 401,
        // and the XUI then falls through to the login form.
        for (const path of ["/openam/json/users?_action=idFromSession",
            "/openam/json/sessions?_action=getSessionInfo"]) {
            const response = await fetch(`${origin}${path}`, {
                method: "POST",
                headers: { Cookie: `${state.auth.cookieName}=not-a-token-from-this-server` },
            });

            assert.equal(response.status, 401, path);
            assert.equal((await response.json()).message, "Access Denied", path);
        }
    });
});

/**
 * Task 2.8: what a logged-in browser gets on its next page load.
 *
 * A fresh page has no JavaScript state at all -- only the cookie jar -- so these drive the two
 * bootstrap calls with the carriers a browser and the fixtures actually use, rather than with the
 * token in hand.
 */
describe("resolving a session", () => {
    /** Log in, and keep only what a browser would still have after a reload. */
    async function loggedIn (user = USERNAME, pass = PASSWORD) {
        const response = await submit((await begin()).body, user, pass);
        assert.equal(response.status, 200, "precondition: the login completed");
        const [pair] = response.cookies[0].split(";");
        return { token: response.body.tokenId, cookie: pair };
    }

    /** A session-bearing call, made the way one carrier makes it. */
    function call (path, { query = "", headers = {} } = {}) {
        return fetch(`${origin}${path}${query}`, { method: "POST", headers });
    }

    it("resolves from the session cookie alone, which is all a reload has", async () => {
        // The requirement, in one assertion: no tokenId, no header, nothing this client chose to
        // send -- only the cookie the browser attaches on its own.
        const { cookie } = await loggedIn();

        const identity = await call("/openam/json/users?_action=idFromSession",
            { headers: { Cookie: cookie } });
        const session = await call("/openam/json/sessions?_action=getSessionInfo",
            { headers: { Cookie: cookie } });

        assert.equal(identity.status, 200);
        assert.equal((await identity.json()).id, USERNAME);
        assert.equal(session.status, 200);
        assert.equal((await session.json()).username, USERNAME);
    });

    it("resolves the same session from any one carrier on its own", async () => {
        // The precedence in NOTES-auth.md §7. What matters is not the order -- nothing under test
        // sends two that disagree -- but that no carrier is weaker than the others: the cookie is
        // what a reloaded page has, and the bare header is what the Playwright fixtures send.
        const { token, cookie } = await loggedIn();

        for (const carrier of [
            { query: `&tokenId=${token}` },
            { headers: { Cookie: cookie } },
            { headers: { [state.auth.cookieName]: token } },
        ]) {
            const response = await call("/openam/json/users?_action=idFromSession", carrier);

            assert.equal(response.status, 200, JSON.stringify(carrier));
            assert.equal((await response.json()).id, USERNAME, JSON.stringify(carrier));
        }
    });

    it("finds its own cookie among the several a browser sends", async () => {
        // Every test above sends the session cookie by itself, which no browser does: the XUI sets
        // `i18next`, and against a deployed AM there is `amlbcookie` and `AMAuthCookie` besides. A
        // parser that read the whole header, or only the first pair, passes those tests and fails
        // every real page load.
        const { cookie } = await loggedIn();

        const response = await call("/openam/json/users?_action=idFromSession", {
            headers: { Cookie: `i18next=en; ${cookie}; amlbcookie=01` },
        });

        assert.equal(response.status, 200);
        assert.equal((await response.json()).id, USERNAME);
    });

    it("does not read a cookie whose name merely contains its own", async () => {
        // `iPlanetDirectoryPro` is a substring of both of these. Matching on the pair's whole name
        // is what keeps them out; matching with `includes`, or on the header as one string, would
        // let either of them authenticate.
        const { token } = await loggedIn();

        const response = await call("/openam/json/users?_action=idFromSession", {
            headers: {
                Cookie: `X${state.auth.cookieName}=${token}; ${state.auth.cookieName}X=${token}`,
            },
        });

        assert.equal(response.status, 401);
    });

    it("treats a blank cookie as no cookie, and falls through to the carrier behind it", async () => {
        // What a browser holds after a write that failed -- and the XUI writes this cookie itself
        // on some paths. An empty value is not a credential, so the header behind it is the one
        // that answers; reading the blank as "a session named by nothing" would 401 a request that
        // carries a perfectly good token.
        const { token } = await loggedIn();

        const response = await call("/openam/json/users?_action=idFromSession", {
            headers: {
                Cookie: `${state.auth.cookieName}=; i18next=en`,
                [state.auth.cookieName]: token,
            },
        });

        assert.equal(response.status, 200);
        assert.equal((await response.json()).id, USERNAME);
    });

    it("takes the tokenId parameter ahead of the cookie, as AM does", async () => {
        // The only assertion that can see the precedence at all: two carriers that disagree. AM
        // reads the parameter first (NOTES-auth.md §7), so a stale tokenId is not quietly rescued
        // by a live cookie sitting behind it -- which is the direction that would hide a bug.
        const { cookie } = await loggedIn();

        const response = await call("/openam/json/users?_action=idFromSession", {
            query: "&tokenId=not-a-token-from-this-server",
            headers: { Cookie: cookie },
        });

        assert.equal(response.status, 401);
    });

    it("answers at both path shapes, as a single login hits both", async () => {
        const { cookie } = await loggedIn();

        for (const path of ["/openam/json/users", "/openam/json/realms/root/users"]) {
            const response = await call(`${path}?_action=idFromSession`,
                { headers: { Cookie: cookie } });

            assert.equal(response.status, 200, path);
        }
    });

    it("names the user who logged in, not the one the capture was recorded as", async () => {
        // The recorded documents are amadmin's. Serving them as they stand would tell a demo
        // session it is logged in as the administrator -- and xui-login.spec.mjs asserts the id.
        const { cookie } = await loggedIn();
        const identity = await (await call("/openam/json/users?_action=idFromSession",
            { headers: { Cookie: cookie } })).json();
        const session = await (await call("/openam/json/sessions?_action=getSessionInfo",
            { headers: { Cookie: cookie } })).json();

        assert.equal(identity.id, USERNAME);
        assert.equal(identity.dn, `id=${USERNAME},ou=user,dc=openam,dc=openidentityplatform,dc=org`);
        assert.equal(session.username, USERNAME);
        assert.equal(session.universalId, identity.dn);
        // The fields that are the recording's, unchanged.
        assert.equal(identity.successURL, "/openam/console");
        assert.equal(identity.realm, "/");
        assert.equal(session.realm, "/");
        assert.equal(identity.fullLoginURL, "/openam/UI/Login?realm=%2F");
    });

    it("puts this session's realm into fullLoginURL, which the XUI parses back out", async () => {
        // `getSuccessfulLoginUrlParams` reads the query string of this field, so a realm left at
        // the recorded one is a wrong answer rather than an unused field. Root encodes to the same
        // `%2F` the recording carries, so the substitution is only observable from another realm.
        const requirements = (await begin("/openam/json/realms/root/realms/alpha/authenticate")).body;
        const filled = structuredClone(requirements);
        filled.callbacks[0].input[0].value = USERNAME;
        filled.callbacks[1].input[0].value = PASSWORD;
        const login = await authenticate(
            "/openam/json/realms/root/realms/alpha/authenticate", JSON.stringify(filled));

        const identity = await (await fetch(`${origin}/openam/json/users?_action=idFromSession`, {
            method: "POST",
            headers: { Cookie: `${state.auth.cookieName}=${login.body.tokenId}` },
        })).json();

        assert.equal(identity.realm, "/alpha");
        assert.equal(identity.fullLoginURL, "/openam/UI/Login?realm=%2Falpha");
    });

    it("reports a session with time left on it, in AM's instant format", async () => {
        // SessionService.getTimeLeft subtracts both expiries from `moment()`, so a recorded
        // instant -- which the capture strips as volatile anyway -- would be in the past.
        const { cookie } = await loggedIn();
        const session = await (await call("/openam/json/sessions?_action=getSessionInfo",
            { headers: { Cookie: cookie } })).json();

        for (const field of ["latestAccessTime", "maxIdleExpirationTime",
            "maxSessionExpirationTime"]) {
            assert.match(session[field], /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, field);
        }
        assert.ok(Date.parse(session.maxIdleExpirationTime) > Date.now(), "idle expiry is ahead");
        assert.ok(Date.parse(session.maxSessionExpirationTime) > Date.now(), "max expiry is ahead");
        assert.ok(Date.parse(session.maxSessionExpirationTime)
            > Date.parse(session.maxIdleExpirationTime), "the session outlasts one idle period");
    });

    it("keeps one session handle for the life of the session", async () => {
        // `updateSessionInfo` puts it in the store and SessionsService invalidates *by* it, so a
        // handle that changed between two reads would name a session nothing could act on.
        const { cookie } = await loggedIn();
        const read = async () => (await (await call(
            "/openam/json/sessions?_action=getSessionInfo", { headers: { Cookie: cookie } })
        ).json()).sessionHandle;

        const handle = await read();
        assert.match(handle, /^shandle:/);
        assert.equal(await read(), handle);
    });

    it("tells two live sessions apart", async () => {
        const demo = await loggedIn();
        const admin = await loggedIn(ADMIN_USER, ADMIN_PASS);

        const asDemo = await call("/openam/json/users?_action=idFromSession",
            { headers: { Cookie: demo.cookie } });
        const asAdmin = await call("/openam/json/users?_action=idFromSession",
            { headers: { Cookie: admin.cookie } });

        assert.equal((await asDemo.json()).id, USERNAME);
        assert.equal((await asAdmin.json()).id, ADMIN_USER);
    });

    it("establishes nothing of its own", async () => {
        // Only a successful authenticate sets a cookie. A resolution that set one would make a
        // stale token self-renewing.
        const { cookie } = await loggedIn();
        const response = await call("/openam/json/users?_action=idFromSession",
            { headers: { Cookie: cookie } });

        assert.deepEqual(response.headers.getSetCookie(), []);
    });
});

describe("logout", () => {
    /** Log in, then log out the way SessionService does, and hold on to both. */
    async function loggedOut (carrier = "cookie") {
        const login = await submit((await begin()).body, USERNAME, PASSWORD);
        const token = login.body.tokenId;
        const [cookie] = login.cookies[0].split(";");
        const response = await fetch(
            `${origin}/openam/json/sessions?_action=logout${
                carrier === "token" ? `&tokenId=${token}` : ""}`,
            { method: "POST", headers: carrier === "cookie" ? { Cookie: cookie } : {} },
        );
        return { token, cookie, response };
    }

    it("answers AM's recorded confirmation", async () => {
        const { response } = await loggedOut();

        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), { result: "Successfully logged out" });
    });

    it("accepts the cookie-only form, which is what an HttpOnly deployment sends", async () => {
        // `SessionService.logout` omits tokenId whenever the token is not client-readable.
        assert.equal((await loggedOut("cookie")).response.status, 200);
    });

    it("ends a session named by the tokenId parameter alone, which AM does not", async () => {
        // Pinned as the divergence it is, in its own test rather than inside the one above: §7's
        // precedence is applied to logout exactly as it is to the two read routes, where AM instead
        // wants an authenticated request context on this route and answers this shape 401 (§6).
        // Nothing under test sends it. See serveLogout in rest.mjs for why it is left open.
        assert.equal((await loggedOut("token")).response.status, 200);
    });

    it("stops the session resolving, whichever carrier asks", async () => {
        // The point of the whole task, and what xui-login.spec.mjs checks rather than the browser
        // cookie: the token must die server-side.
        const { token, cookie } = await loggedOut();

        for (const carrier of [
            { query: `&tokenId=${token}` },
            { headers: { Cookie: cookie } },
            { headers: { [state.auth.cookieName]: token } },
        ]) {
            for (const path of ["/openam/json/users?_action=idFromSession",
                "/openam/json/sessions?_action=getSessionInfo"]) {
                const response = await fetch(`${origin}${path}${carrier.query ?? ""}`,
                    { method: "POST", headers: carrier.headers ?? {} });

                assert.equal(response.status, 401, `${path} ${JSON.stringify(carrier)}`);
                assert.equal((await response.json()).message, "Access Denied");
            }
        }
    });

    it("answers a replay as an unauthenticated request", async () => {
        const { cookie, response } = await loggedOut();
        assert.equal(response.status, 200, "precondition: the first logout succeeded");

        const replay = await fetch(`${origin}/openam/json/sessions?_action=logout`,
            { method: "POST", headers: { Cookie: cookie } });

        assert.equal(replay.status, 401);
        assert.equal((await replay.json()).message, "Access Denied");
    });

    it("refuses a logout that names no session at all", async () => {
        const response = await fetch(`${origin}/openam/json/sessions?_action=logout`,
            { method: "POST" });

        assert.equal(response.status, 401);
    });

    it("clears no cookie, because AM does not either", async () => {
        // AM's logout response carries no cookie headers at all; the XUI's own SessionToken.remove
        // clears the browser's copy. Expiring it here would be harmless -- and would make it
        // possible to pass the spec with a token that still resolved, which is the one thing it
        // checks.
        const { response } = await loggedOut();

        assert.deepEqual(response.headers.getSetCookie(), []);
    });

    it("ends one session without touching another", async () => {
        const staying = await submit((await begin()).body, ADMIN_USER, ADMIN_PASS);
        const [stayingCookie] = staying.cookies[0].split(";");

        await loggedOut();

        const response = await fetch(`${origin}/openam/json/users?_action=idFromSession`,
            { method: "POST", headers: { Cookie: stayingCookie } });

        assert.equal(response.status, 200);
        assert.equal((await response.json()).id, ADMIN_USER);
    });
});
