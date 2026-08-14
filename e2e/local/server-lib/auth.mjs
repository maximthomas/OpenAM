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
 * Authentication: the callback exchange, the session it establishes, and how that session is
 * resolved afterwards and ended.
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
 * Task 2.8 is the other end of that session's life (NOTES-auth.md §5, §6):
 *
 *     POST …/users?_action=idFromSession       -> 200 {id, realm, dn, successURL, fullLoginURL}
 *     POST /json/sessions?_action=getSessionInfo -> 200 {username, realm, sessionHandle, 3×time}
 *     POST /json/sessions?_action=logout       -> 200 {result} and the token stops resolving
 *
 * **A session resolves from the token, and the token may arrive three ways — but the cookie alone
 * has to be enough.** That is the requirement's actual content: a page reload re-bootstraps the XUI
 * with no in-memory state, so whatever resolves the session has to be something the browser sends
 * on its own. Which carrier a token came in is rest.mjs's question; this module is handed a token
 * and never learns how it arrived, which is what stops one carrier resolving a session another
 * would have declined.
 *
 * **Logout invalidates server-side, and nothing else ends a session.** AM sends no `Set-Cookie` on
 * the logout response at all — the browser's copy is cleared by the XUI's own `SessionToken.remove`
 * — so the token dying here is the whole mechanism (NOTES-auth.md §6). xui-login.spec.mjs says so
 * in as many words: "The browser cookie is not the thing to check … What matters is that the server
 * stops resolving it."
 *
 * **No clock expires a session, deliberately** — the same refusal as the `authId` below. The three
 * timestamps `getSessionInfo` reports are computed per call and, for the length of any run that
 * exists, lie in the future, because `SessionService.getTimeLeft` subtracts two of them from
 * `moment()` and the XUI's session validator acts on the result; but nothing here *enforces* them.
 * The one exception is deliberate and is AM's own: `maxSessionExpirationTime` is anchored at the
 * session's creation, so past `MAX_SESSION_MINUTES` the XUI would log itself out while this server
 * still resolved the token — which is what AM does too, and which no spec comes close to reaching.
 * A stand-in that *expired* sessions would be inventing a deadline every spec then races against,
 * and no spec asks for one.
 *
 * **Shapes from the capture, values minted here** — D15, and the division capture-store.mjs already
 * draws: `{{DOUBLE_BRACE}}` markers are this deployment's values and are resolved at load, while
 * `<ANGLE>` markers stand for what varies per call and are left for the task that mints them. Every
 * body in `RECORDED` below is recorded, and this module fills in exactly the angle markers they
 * carry: `<AUTHID>`, `<TOKEN>`, `<SESSION-HANDLE>` and `<TS>` ×3. Nothing here hand-authors a
 * response, and the per-principal fields that cannot be markers are rebuilt from the recorded value
 * rather than restated — see `principalIn`.
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
 * **The one-call header authentication is implemented, as of task 2.10.**
 * `common/openam-commons.mjs`'s `getAuthToken` posts `X-OpenAM-Username`/`X-OpenAM-Password` to
 * `/json/authenticate` and reads `tokenId` straight out of the answer. Task 2.7 left it out because
 * nothing xui-login.spec.mjs does reaches it (NOTES-auth.md §9.6) and named 2.10-2.12 as the tasks
 * that would need it: it is how every Playwright fixture provisions, so a spec that creates a realm
 * to drive cannot set itself up without it. See `headerLogin`.
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
    /**
     * order 7 — the one-call header authentication, `<TOKEN>` unfilled.
     *
     * Three fields and no callbacks: `{realm, successUrl, tokenId}`. It is the same answer the
     * callbacks exchange ends with, which is the point — a session is a session however it was
     * established, so what this records is the *shape of the shortcut*, not a second kind of login.
     */
    headerLogin: "json/authenticate/POST.json",
    /** order 1 — the bootstrap's own 401, which is not an error state. See `anonymous` below. */
    anonymous: "json/users/POST.action=idFromSession.401.json",
    /**
     * order 10 — a resolved session's identity. Recorded for `amadmin`, so the fields that name the
     * principal are rebuilt per session; see `principalIn` and `idFromSession`.
     */
    identity: "json/users/POST.action=idFromSession.json",
    /** order 12 — the session document, `<TS>` ×3 and `<SESSION-HANDLE>` unfilled. */
    sessionInfo: "json/sessions/POST.action=getSessionInfo.json",
    /** order 48 — the answer to a logout that ended a session. No markers. */
    logout: "json/sessions/POST.action=logout.json",
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
 * How long a session claims to have left, as the recording showed AM answering.
 *
 * NOTES-auth.md §1 #6 is the measurement — "Idle +30 min, max +2 h [live]" — and the sample document
 * quoted just above it is what says *from when*: `latestAccessTime` `16:56:22Z`, `maxIdleExpiration`
 * `17:26:22Z`, `maxSessionExpiration` `18:56:21Z`. The idle expiry is thirty minutes from that
 * access; the maximum is two hours from a moment one second *earlier* than it, which is the session
 * being created and then accessed a second later. So the idle one moves per call and the maximum
 * does not, and that is why `createdAt` is on the session record at all.
 *
 * NOTES-volatility.md rules 2-4 are consistent with this but could not establish it alone: they
 * record two samples ten seconds apart in which all three instants moved by ten seconds, which two
 * *different* sessions would also produce. The absolute values cannot come from the capture in any
 * case — they are the volatile half, stripped by design — so the deltas are what is reproduced.
 *
 * §1 #6 also says both expiries "must keep moving", which is the XUI's requirement rather than AM's
 * behaviour: `SessionValidator` reschedules on `min(idle, max) − now`, and the idle one moving is
 * enough to keep that rescheduling forever. Anchoring the maximum is what makes it a maximum.
 */
const MAX_IDLE_MINUTES = 30;
const MAX_SESSION_MINUTES = 120;

/** AM's instants are second-precision UTC — `2026-08-12T02:40:41Z`, no milliseconds. */
function instant (epochMillis) {
    return `${new Date(epochMillis).toISOString().slice(0, 19)}Z`;
}

/**
 * A principal's distinguished name for this session, from the one the recording carries.
 *
 * `id=amadmin,ou=user,dc=…` is recorded twice — as `dn` in `idFromSession` and as `universalId` in
 * `getSessionInfo` — and only the first component names the user. Rewriting that component and
 * keeping the rest takes the container's directory layout and config suffix from the recording
 * rather than restating them here, which matters because they are exactly the sort of value that is
 * plausible to invent and wrong: `ou=user` is not `ou=people`, and the config store's suffix is not
 * the user store's (capture/README.md's placeholder table warns about that pair specifically).
 *
 * The replacement is a function rather than a string because `String.replace` reads `$&`, `` $` ``
 * and `$1` out of a string one — and the username here comes from `OPENAM_USERNAME`, which an
 * operator can set to anything. Nothing in the suite has a `$` in it; this is a two-character
 * defence against a value that arrives from outside the repo. A username carrying `,`, `+` or `=`
 * would still need RFC 4514 escaping to be a valid DN, and is left alone: AM's own directory would
 * not hold such an account, so escaping it here would be inventing a shape the recording never had.
 */
function principalIn (recordedDn, username) {
    return recordedDn.replace(/^id=[^,]*/, () => `id=${username}`);
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
    const headerLoginDocument = capture.body(RECORDED.headerLogin);
    const anonymousBody = capture.body(RECORDED.anonymous);
    const identityDocument = capture.body(RECORDED.identity);
    const sessionInfoDocument = capture.body(RECORDED.sessionInfo);
    const logoutBody = capture.body(RECORDED.logout);

    /** authId -> the login it belongs to. */
    const inFlight = new Map();
    /** token -> the session it names. Created by `submit`, read by `resolve`, ended by `logout`. */
    const sessions = new Map();

    /** The answer to a session-bearing call with no live session behind it. See `anonymous`. */
    const accessDenied = () => ({ status: 401, body: anonymousBody });

    /**
     * The one rule for "is this token a session", behind both `resolve` and `logout`.
     *
     * Logout could delete straight out of the map and be right today, because there is nothing to
     * this beyond a lookup. It goes through here anyway so that there is no second place holding an
     * opinion: the moment a later task puts a condition in — an idle timer, a realm scope — a logout
     * that had its own copy would start answering 200 for a session the two read routes were already
     * answering 401 for, and that divergence is invisible until something happens to test both.
     * Task 2.13's reset turned out not to need a condition here at all: it replaces the state this
     * map hangs off, so every session goes at once and no lookup has to know that it happened.
     */
    const sessionFor = (token) =>
        (typeof token === "string" && token !== "" ? sessions.get(token) : undefined);

    /**
     * Open a session for an account that has just proved who it is, and return its token.
     *
     * Both ways in end here — the callback exchange and the fixtures' one-call header
     * authentication — so a session cannot differ by the door it came through. That matters more
     * than it sounds: `getSessionInfo` and `idFromSession` read these fields, and a header login
     * that built a session missing one of them would answer the same specs differently depending on
     * whether the browser or a fixture had logged in.
     */
    function establish (account, realmPath) {
        const token = opaque();
        sessions.set(token, {
            username: account.username,
            realmPath,
            // Minted with the session rather than per call, because `updateSessionInfo` puts it
            // in the store and `SessionsService` invalidates *by handle*: one that changed
            // between two reads of the same session would name a session nothing could act on.
            // `shandle:` is the form AM's takes (NOTES-volatility.md rule 10).
            sessionHandle: `shandle:${opaque()}`,
            // What `maxSessionExpirationTime` counts from. The idle expiry counts from now on
            // every call, as AM's does; this one does not move.
            createdAt: Date.now(),
        });
        return token;
    }

    /** The account a username and password name, or `undefined`. One rule, both doors. */
    function accountFor (username, password) {
        const account = typeof username === "string"
            ? directory.get(username.toLowerCase())
            : undefined;
        return account?.password === password ? account : undefined;
    }

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
         *
         * **Two things this does not do, both of which 2.8 made reachable rather than introduced.**
         * It does not check that `realmPath` names a realm, so a login into a realm that does not
         * exist now succeeds *and* gets reported back as that realm by `idFromSession` and
         * `getSessionInfo` — nothing under test does it, and realm existence is 2.10's, which owns
         * the realm collection. And it ignores `?sessionUpgradeSSOTokenId=`, which NOTES-auth.md
         * §9.5 flags as "worth a deliberate decision rather than an accident": AM upgrades the named
         * session, this answers a fresh callbacks document. It is unreachable until a browser can
         * hold a session across a load of `#login/`, which is exactly what task 2.9 unblocks — so it
         * is 2.9's to decide, and this comment is the handover.
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
            const account = accountFor(username, password);
            if (!account) {
                // The handle is left in flight on purpose: a mistyped password is the one failure
                // a user retries, and the XUI's own recovery is to call `begin` again anyway.
                return { status: 401, body: failureBody };
            }

            inFlight.delete(authId);
            // The realm the login *began* in, not the one this leg was posted to. AM fixes it at
            // `begin` and carries it inside the `authId`, so a submission cannot move a login to
            // another realm by changing its path; keying off the flight is how that holds here
            // without the JWT.
            const token = establish(account, flight.realmPath);

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
         * `POST /json/authenticate` with the credentials in `X-OpenAM-Username` /
         * `X-OpenAM-Password` — AM's zero-page login, and how every Playwright fixture provisions.
         *
         * Task 2.7 left this out and named 2.10-2.12 as the tasks that would need it; this is that
         * task. `getAdminToken` is the first thing xui-realms.spec.mjs does, and every realm the
         * spec creates, reads back or sweeps up in teardown is addressed with the token it returns.
         *
         * **One call, one session, and no `authId` anywhere.** There is no in-flight state to hold
         * because there is no second leg: the credentials arrive with the request, so this either
         * establishes a session or rejects. That is the whole of the difference from `submit`, which
         * is why both go through `establish` — a fixture's session and a browser's are the same
         * object, and `getSessionInfo`, `idFromSession` and `logout` cannot tell them apart.
         *
         * **The rejection is `submit`'s recorded one, and that is a divergence.** AM answers a bad
         * zero-page credential 401 with its own body, which the capture does not hold — the
         * recording only ever sent this endpoint credentials that worked. Nothing in the suite
         * authenticates a fixture with a wrong password, so the body is unobservable; reusing the
         * recorded "Authentication Failed" keeps the status right and does not invent a message.
         *
         * Not read: `X-NoSession`, and the realm. The browser sends the first on every authenticate
         * call and honouring it would authenticate nobody (REQUESTS.md Fact 3); the second is absent
         * from this shape entirely — the fixtures post to the bare `/json/authenticate`, and the
         * recorded answer's `realm` is `/`, which is the realm the administrator lives in.
         *
         * **The realm is the recorded one whatever path asked, and that is invented.** The two
         * headers are answered at every authenticate route this server parses, not only the bare one
         * the recording holds, and the session lands in `/` even if the URL named a realm. The
         * capture has nothing to be faithful to here — no fixture posts these headers anywhere else,
         * and the only account this server holds lives in `/` — so the alternative was inventing a
         * realm-scoped answer instead of an over-broad one. Task 2.12 owns the principals, and this
         * narrows with them.
         */
        headerLogin (username, password) {
            const account = accountFor(username, password);
            if (!account) {
                return { status: 401, body: failureBody };
            }
            const token = establish(account, headerLoginDocument.realm);
            return {
                status: 200,
                body: { ...headerLoginDocument, tokenId: token },
                sessionToken: token,
            };
        },

        /**
         * The session a token names, or `undefined`.
         *
         * The single point at which a token becomes a session, which is what makes "resolvable from
         * the cookie alone" a property of this server rather than of one route: every carrier
         * rest.mjs accepts arrives here as the same string, so no carrier can resolve a session
         * another would have declined. An empty or absent token is not a session — a blank cookie
         * is what a browser sends after something failed to write one, and reading it as anything
         * else would authenticate a request that carries no credential at all.
         */
        resolve (token) {
            return sessionFor(token);
        },

        /**
         * `POST …/users?_action=idFromSession` for a session that exists — NOTES-auth.md §5 #2.
         *
         * The recorded document with the four session-dependent fields rebuilt — `dn`, `id` and
         * `realm` name the principal, and `fullLoginURL` carries the realm a second time. It was
         * recorded for `amadmin` in the root realm, and serving that for a `demo` session would tell
         * the XUI it is logged in as somebody else. `successURL` and the shape of `fullLoginURL` are
         * the recording's, with only the realm this session actually belongs to substituted into the
         * latter — the XUI parses its query string back out (`getSuccessfulLoginUrlParams`), so a
         * realm left at the recorded one would be a wrong answer rather than an unused field.
         *
         * The `realm=` pattern is anchored on its delimiter so it cannot match the tail of some
         * other parameter name (`?xrealm=`). The recorded URL has one parameter and could not, but a
         * regex that is right only for the value it was written against is the kind that survives
         * into a task where it is wrong.
         */
        idFromSession (session) {
            return {
                status: 200,
                body: {
                    ...identityDocument,
                    dn: principalIn(identityDocument.dn, session.username),
                    id: session.username,
                    realm: session.realmPath,
                    fullLoginURL: identityDocument.fullLoginURL.replace(
                        /([?&])realm=[^&]*/,
                        (_whole, delimiter) =>
                            `${delimiter}realm=${encodeURIComponent(session.realmPath)}`),
                },
            };
        },

        /**
         * `POST /json/sessions?_action=getSessionInfo` — NOTES-auth.md §5 #3, and the guard the XUI
         * puts in front of its own logout.
         *
         * `username` is what makes this answer a session at all: `SessionService.isSessionValid`
         * tests for that field and nothing else. The three timestamps are computed here rather than
         * recorded, because the recording's are the volatile half the capture strips by design and
         * a fixed instant would be in the past by the second run — `getTimeLeft` would then report a
         * negative number to the session validator.
         */
        getSessionInfo (session) {
            const now = Date.now();
            return {
                status: 200,
                body: {
                    ...sessionInfoDocument,
                    latestAccessTime: instant(now),
                    maxIdleExpirationTime: instant(now + MAX_IDLE_MINUTES * 60_000),
                    maxSessionExpirationTime:
                        instant(session.createdAt + MAX_SESSION_MINUTES * 60_000),
                    realm: session.realmPath,
                    sessionHandle: session.sessionHandle,
                    universalId: principalIn(sessionInfoDocument.universalId, session.username),
                    username: session.username,
                },
            };
        },

        /**
         * `POST /json/sessions?_action=logout` — NOTES-auth.md §6.
         *
         * Ends the session by forgetting the token, which is the entire mechanism: no cookie is
         * cleared here because AM clears none either, and a stand-in that ended the session by
         * expiring the cookie would pass the spec's assertion while leaving a token that still
         * resolves for anything not holding that cookie.
         *
         * A replay — or a logout naming a token this server never issued — is `Access Denied`, as
         * AM answers it. That is the same 401 an anonymous call gets, and it has to be: the specs
         * prove a logout by asking `idFromSession` afterwards, so the two must agree about what
         * "there is no session here" looks like.
         */
        logout (token) {
            if (sessionFor(token) === undefined) {
                return accessDenied();
            }
            sessions.delete(token);
            return { status: 200, body: logoutBody };
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
        anonymous: accessDenied,
    };
}
