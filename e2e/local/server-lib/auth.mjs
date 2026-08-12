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
 * Authentication: the callback exchange, and the session it establishes.
 *
 * Task 2.7. The XUI's login is two round trips against one endpoint (local/NOTES-auth.md §1):
 *
 *     POST …/authenticate            body ""                    -> 200 the callbacks document
 *     POST …/authenticate            that document, values in   -> 200 {tokenId, successUrl, realm}
 *                                                               -> 401 {code, reason, message}
 *
 * There is no redirect, no form post and no servlet anywhere in it. The first call presents the
 * credential *requirements*; the second submits them and gets either the next requirement or a
 * completed authentication. Only the second sets the session cookie.
 *
 * **Shapes from the capture, values minted here** — D15, and the division capture-store.mjs already
 * draws: `{{DOUBLE_BRACE}}` markers are this deployment's values and are resolved at load, while
 * `<ANGLE>` markers stand for what varies per call and are left for the task that mints them. All
 * three bodies below are recorded, and this module fills in exactly the two angle markers in them:
 * `<AUTHID>` and `<TOKEN>`. Nothing here hand-authors a response.
 *
 * **`authId` is an opaque handle into `inFlight`, not AM's JWT.** Real AM signs an HS256 token
 * carrying `otk`, the realm in DN form and its own session id, and answers a tampered one with
 * `400 "AuthId JWT Signature not valid"` (NOTES-auth.md §2, §9.1). Reproducing that would be
 * modelling AM's internals: the XUI never parses the value, it only echoes it back, so from the
 * client's side the two are indistinguishable. What this must *not* do is ignore it — with two
 * logins in flight it is the only thing correlating a submission with its own `begin`, because the
 * cookies do not: AM accepts a submit with no cookies at all, and with an `AMAuthCookie` belonging
 * to a different `begin`.
 *
 * **An `authId` here is reusable; in AM it is single-use.** AM consumes it and answers a replay
 * `408 "Session has timed out"`, which drives an explicit retry branch in `AuthNService`.
 * NOTES-auth.md §2 records that a stand-in may leave it reusable and that nothing in
 * xui-login.spec.mjs exercises the branch, so this expires nothing — a server that timed out an
 * `authId` would be inventing a clock the specs would then race against.
 *
 * The consequence, seen and accepted: **`inFlight` only ever shrinks on a completed login.** A
 * `begin` nobody submits, and every rejected credential, leaves an entry for the life of the
 * process. That is tens of bytes per login against a server that is started for a test run and
 * stopped after it, and task 2.13's reset rebuilds this state wholesale. Evicting on a timer would
 * buy nothing and would reintroduce exactly the clock the paragraph above declines to invent.
 *
 * **The anonymous headers are ignored, and that is load-bearing.** The browser sends
 * `X-NoSession: true`, `X-Username: anonymous` and `X-Password: anonymous` on *every* authenticate
 * call, including the one carrying real credentials (REQUESTS.md Fact 3, NOTES-auth.md §1). A
 * server that honoured them would authenticate nobody, ever. The real principal is only ever in the
 * `NameCallback` input value.
 *
 * **Deliberately not implemented: the one-call header authentication.**
 * `common/openam-commons.mjs`'s `getAuthToken` posts `X-OpenAM-Username`/`X-OpenAM-Password` to
 * `/json/authenticate` and reads `tokenId` straight out of the answer. That is how the fixtures
 * provision, and it is out of scope here (NOTES-auth.md §9.6): nothing xui-login.spec.mjs does
 * reaches it. Note the failure mode for whoever picks it up — this endpoint answers such a call
 * with a *callbacks document*, so `getAuthToken` reads `tokenId` as `undefined` rather than getting
 * an error. The fixtures that need it belong to tasks 2.10-2.12.
 */

import { randomBytes } from "node:crypto";

/** The recorded exchange. Named as files so a re-record that drops one fails naming it. */
const RECORDED = {
    /** order 4 — the initial callbacks document, `<AUTHID>` unfilled. */
    callbacks: "json/realms/root/authenticate/POST.callbacks.json",
    /** order 5 — a completed authentication, `<TOKEN>` unfilled. */
    success: "json/realms/root/authenticate/POST.success.json",
    /** order 6 — a rejected credential. No markers; served as recorded. */
    failure: "json/realms/root/authenticate/POST.failure.json",
    /** order 1 — the bootstrap's own 401, which is not an error state. See `anonymous` below. */
    anonymous: "json/users/POST.action=idFromSession.401.json",
    /**
     * order 2 — read for its `cookieName` field alone. Serving this document is task 2.9's, and
     * the field is consulted rather than served; see `capture.bodyField`.
     */
    serverInfo: "json/serverinfo/star/GET.resource=1.1.json",
};

/**
 * An opaque value no client may parse. 24 bytes rather than a UUID: this is a bearer token in a
 * cookie, and base64url keeps it a single cookie-safe word.
 */
function opaque () {
    return randomBytes(24).toString("base64url");
}

/**
 * The username and password out of a submitted requirements document.
 *
 * Read by callback *type*, not by input name or position. `IDToken1`/`IDToken2` are what the
 * rendered form's field ids derive from and they are stable for this one module, but the type is
 * what actually says which value is which — the same reading AM does, and the one that stays
 * correct if a stage ever presents its callbacks in another order.
 */
function credentialsFrom (callbacks) {
    const valueOf = (type) => {
        const callback = (callbacks ?? []).find((entry) => entry?.type === type);
        const value = callback?.input?.[0]?.value;
        return typeof value === "string" ? value : undefined;
    };
    return { username: valueOf("NameCallback"), password: valueOf("PasswordCallback") };
}

/**
 * Build the authentication state.
 *
 * `credentials` maps a username to its password. Held by lowercased name because AM resolves a
 * principal case-insensitively and xui-login.spec.mjs compares the resolved id case-insensitively
 * for the same reason; storing the directory's own spelling keeps that spelling in the session.
 *
 * Rebuilt whenever the baseline state is, which is what makes task 2.13's reset clear the sessions
 * and in-flight logins along with the rest of the store rather than leaving them to accumulate.
 */
export function createAuthState (capture, { credentials }) {
    const directory = new Map(Object.entries(credentials)
        .map(([username, password]) => [username.toLowerCase(), { username, password }]));

    const callbacksDocument = capture.body(RECORDED.callbacks);
    const successDocument = capture.body(RECORDED.success);
    const failureBody = capture.body(RECORDED.failure);
    const anonymousBody = capture.body(RECORDED.anonymous);

    /** authId -> the login it belongs to. */
    const inFlight = new Map();
    /** token -> the session it names. Task 2.8 resolves these; 2.7 only creates them. */
    const sessions = new Map();

    return {
        /**
         * The session cookie's name, read from the recording rather than hardcoded.
         *
         * The XUI learns it from `serverinfo/*` too — `SiteConfigurator.processConfiguration` puts
         * it on `Configuration.globalData.auth.cookieName` and every `SessionToken` read and write
         * goes through it (NOTES-auth.md §3). Taking it from the same recorded field is what keeps
         * the cookie this server sets and the cookie the XUI looks for the same string once task
         * 2.9 serves that document.
         */
        cookieName: capture.bodyField(RECORDED.serverInfo, "cookieName"),

        sessions,

        /**
         * `POST …/authenticate` with an empty body: present the credential requirements.
         *
         * The document is cloned because it is handed to a caller that serialises it, and the
         * template has to survive for the next login unmodified.
         */
        begin (realmPath) {
            const authId = opaque();
            inFlight.set(authId, { realmPath });
            return { status: 200, body: { ...structuredClone(callbacksDocument), authId } };
        },

        /**
         * `POST …/authenticate` with the requirements filled in: accept the submission.
         *
         * Returns the completed authentication and the token to set as the session cookie, or the
         * recorded rejection. `stage`, `header`, `infoText`, `template` and every `output` come
         * back in the submission unchanged and are ignored, as AM ignores them.
         *
         * An unrecognised `authId` is answered as a rejected credential. AM distinguishes the
         * cases — `400` for a bad signature, `408` for one already consumed — but both belong to
         * the JWT semantics above, which are out of scope, and both are unreachable from anything
         * under test. What matters is that an unknown handle cannot authenticate, which this gets
         * right; the status it says so with is the recorded one rather than an invented shape.
         */
        submit (requirements) {
            const authId = requirements?.authId;
            const flight = typeof authId === "string" ? inFlight.get(authId) : undefined;
            if (!flight) {
                return { status: 401, body: failureBody };
            }

            const { username, password } = credentialsFrom(requirements.callbacks);
            const account = username === undefined
                ? undefined
                : directory.get(username.toLowerCase());
            if (!account || account.password !== password) {
                // The handle is left in flight on purpose: a mistyped password is the one failure
                // a user retries, and the XUI's own recovery is to call `begin` again anyway.
                return { status: 401, body: failureBody };
            }

            inFlight.delete(authId);
            const token = opaque();
            // The realm the login *began* in, not the one this leg was posted to. AM fixes it at
            // `begin` and carries it inside the `authId`, so a submission cannot move a login to
            // another realm by changing its path; keying off the flight is how that holds here
            // without the JWT.
            sessions.set(token, { username: account.username, realmPath: flight.realmPath });

            // `successUrl` is the recorded one, with this server's context already substituted. It
            // does not decide where the user lands -- that is the XUI's own default-route decision,
            // taken from the profile's roles -- but it is one of exactly three fields AM returns,
            // and `SessionToken.isAuthenticated` reads the response as a whole.
            return {
                status: 200,
                body: { ...successDocument, tokenId: token, realm: flight.realmPath },
                sessionToken: token,
            };
        },

        /**
         * The answer to a session-bearing call made without a session.
         *
         * Not an error state: `POST /json/users?_action=idFromSession` answering 401 is the
         * bootstrap's normal path on every cold load (REQUESTS.md Fact 1), and it is also how a
         * rejected login and a completed logout prove themselves to the specs -- `sessionInfo` in
         * common/xui-commons.mjs reads 401 or 403 as "no session" and anything else as a hard
         * failure, so answering 500, or 200 with nothing in it, breaks the negative assertions
         * rather than the positive ones.
         *
         * Note the message: AM says "Access Denied" here and "Authentication Failed" for a rejected
         * credential. Two different 401 bodies, and both are recorded (NOTES-auth.md §4).
         */
        anonymous () {
            return { status: 401, body: anonymousBody };
        },
    };
}
