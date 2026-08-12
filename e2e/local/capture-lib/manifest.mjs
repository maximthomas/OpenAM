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
 * The capture plan: every in-scope request, in the order it has to be issued.
 *
 * This is REQUESTS.md's in-scope table plus the four things that table deliberately does not carry —
 * a capture order, request bodies, bindings for its `<realm>` and `<token>` placeholders, and the
 * expansion of rows that cover two statuses into the separate calls that produce them. Each entry
 * names its REQUESTS.md row in `row`, and capture-lib/requests-md.mjs refuses to run a capture
 * unless every documented row is covered and no entry names a row that is not documented.
 *
 * The order is not a matter of taste. NOTES-volatility.md records four dependencies that constrain
 * it, and one of them is why `PUT users/demo` is issued before `GET users/demo`: the PUT permanently
 * adds a `modifyTimestamp` key to every later GET, so a capture that read before writing would
 * record a different *shape* on a fresh instance than on a used one. Issuing the write first makes
 * the starting state irrelevant, which is what lets a re-record match byte for byte.
 *
 * Write bodies come from AM rather than from us wherever AM will supply one — `_action=template` for
 * a create, the resource's own GET for an update — with only the identifying field overridden. That
 * is D15's argument applied to requests as well as responses: a hand-authored body that is subtly
 * wrong records a subtly wrong response, and nothing downstream would notice.
 */

/** The realm the capture creates, uses and deletes. */
export const CAPTURE_REALM = "e2e-capture";

/** The alias the realm edit adds, so the edit is observable rather than a no-op round trip. */
const CAPTURE_REALM_ALIAS = "e2e-capture-alias";

const SMS = "protocol=1.0,resource=1.0";
const ENTITY = "protocol=1.0,resource=2.0";
const AUTHN = "protocol=1.0,resource=2.1";

/**
 * The realm path's REST resource id: base64url, unpadded.
 *
 * btoa and not Buffer, matching common/realms-commons.mjs — btoa is latin1 and is what the console
 * calls, so a realm name outside that range fails here the same way it fails there rather than being
 * quietly encoded into an id the console could never produce.
 */
export function encodeRealmId (path) {
    return btoa(path).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** The headers the XUI sends on every authenticate call (REQUESTS.md, Fact 3). */
const XUI_AUTHN_HEADERS = {
    "X-Username": "anonymous",
    "X-Password": "anonymous",
    "X-NoSession": "true",
};

/**
 * Fill the callbacks AM returned from step one.
 *
 * The real principal only ever travels in the NameCallback's input value — the `X-Username` and
 * `X-Password` headers above say `anonymous` even on the calls that log someone in.
 */
function fillCallbacks (challenge, username, password) {
    const filled = structuredClone(challenge);
    for (const callback of filled.callbacks ?? []) {
        if (callback.type === "NameCallback") {
            callback.input[0].value = username;
        } else if (callback.type === "PasswordCallback") {
            callback.input[0].value = password;
        }
    }
    return filled;
}

/**
 * The capture plan, in order.
 *
 * `body` may be a value or an async function of the run context, which exposes `raw(id)` for a
 * response already captured in this run and `get(path, version)` for a read the capture itself does
 * not record. The second is needed twice: to build the `PUT users/demo` body without recording a GET
 * that has to come after it, and to obtain a fresh `authId` for the deliberate 401, because an
 * authId is one-shot and the successful login upstream already consumed the one it was issued.
 */
export function buildManifest ({ realm = CAPTURE_REALM, demoUser, demoPassword, adminUser,
    adminPassword }) {
    const realmPath = `/${realm}`;
    const realmId = encodeRealmId(realmPath);
    const realmScoped = `/json/realms/root/realms/{realm}`;

    return [
        // ── Anonymous bootstrap ──────────────────────────────────────────────────────────────
        {
            id: "users-idfromsession-anonymous",
            row: { method: "POST", path: "/json/users", query: "_action=idFromSession" },
            method: "POST", path: "/json/users", query: { _action: "idFromSession" },
            version: ENTITY, session: "none", body: {}, tag: "401", expect: 401,
            note: "The XUI fires this on every page load before it has a session. 60 of 72 "
                + "occurrences in the recording were anonymous and every one got a 401 — the "
                + "bootstrap's normal path, not an error path (REQUESTS.md, Fact 1).",
        },
        {
            id: "serverinfo-star-1.1",
            row: { method: "GET", path: "/json/serverinfo/*", query: "" },
            method: "GET", path: "/json/serverinfo/*", query: {},
            version: "protocol=1.0,resource=1.1", session: "none", tag: "resource=1.1", expect: 200,
        },
        {
            id: "serverinfo-star-1.0",
            row: { method: "GET", path: "/json/serverinfo/*", query: "" },
            method: "GET", path: "/json/serverinfo/*", query: {},
            version: SMS, session: "none", tag: "resource=1.0", expect: 200,
            note: "The same path at a second resource version. AM answers both; a strict stand-in "
                + "would not, and `_id`/`_rev` presence depends on the negotiation.",
        },

        // ── Authentication ───────────────────────────────────────────────────────────────────
        {
            id: "authenticate-callbacks",
            row: { method: "POST", path: "/json/realms/root/authenticate", query: "" },
            method: "POST", path: "/json/realms/root/authenticate", query: {},
            version: AUTHN, session: "none", headers: XUI_AUTHN_HEADERS, body: "",
            tag: "callbacks", expect: 200,
        },
        {
            id: "authenticate-success",
            row: { method: "POST", path: "/json/realms/root/authenticate", query: "" },
            method: "POST", path: "/json/realms/root/authenticate", query: {},
            version: AUTHN, session: "none", headers: XUI_AUTHN_HEADERS,
            body: (ctx) => fillCallbacks(ctx.raw("authenticate-callbacks"), demoUser, demoPassword),
            tag: "success", expect: 200, provides: "demo",
        },
        {
            id: "authenticate-failure",
            row: { method: "POST", path: "/json/realms/root/authenticate", query: "" },
            method: "POST", path: "/json/realms/root/authenticate", query: {},
            version: AUTHN, session: "none", headers: XUI_AUTHN_HEADERS,
            // A fresh challenge: the authId from step one above was consumed by the login that
            // succeeded, and replaying a spent one answers 408, not 401.
            body: async (ctx) => fillCallbacks(
                await ctx.get("/json/realms/root/authenticate", AUTHN,
                    { method: "POST", session: "none", headers: XUI_AUTHN_HEADERS, body: "" }),
                demoUser, "not-the-password"),
            tag: "failure", expect: 401,
        },
        {
            id: "authenticate-legacy-admin",
            row: { method: "POST", path: "/json/authenticate", query: "" },
            method: "POST", path: "/json/authenticate", query: {},
            version: "resource=2.0, protocol=1.0", session: "none",
            headers: { "X-OpenAM-Username": adminUser, "X-OpenAM-Password": adminPassword },
            body: "", expect: 200, provides: "admin",
            note: "The legacy realm-in-query shape the Playwright fixtures use, header spelling "
                + "included — reversed order and a space, which is semantically the same request "
                + "and textually a different one (REQUESTS.md, 'Header spelling is not canonical').",
        },

        // ── Admin bootstrap reads ────────────────────────────────────────────────────────────
        {
            id: "serverinfo-version",
            row: { method: "GET", path: "/json/serverinfo/version", query: "" },
            method: "GET", path: "/json/serverinfo/version", query: {},
            version: SMS, session: "admin", expect: 200,
        },
        {
            id: "users-idfromsession-realm",
            row: { method: "POST", path: "/json/realms/root/users", query: "_action=idFromSession" },
            method: "POST", path: "/json/realms/root/users", query: { _action: "idFromSession" },
            version: ENTITY, session: "admin", body: {}, expect: 200,
        },
        {
            id: "users-idfromsession-admin",
            row: { method: "POST", path: "/json/users", query: "_action=idFromSession" },
            method: "POST", path: "/json/users", query: { _action: "idFromSession" },
            version: ENTITY, session: "admin", body: {}, expect: 200,
        },
        {
            id: "users-amadmin",
            row: { method: "GET", path: "/json/realms/root/users/amadmin", query: "" },
            method: "GET", path: "/json/realms/root/users/amadmin", query: {},
            version: ENTITY, session: "admin", expect: 200,
        },
        {
            id: "sessions-getsessioninfo",
            row: { method: "POST", path: "/json/sessions",
                query: "_action=getSessionInfo&tokenId=<token>" },
            method: "POST", path: "/json/sessions",
            query: { _action: "getSessionInfo", tokenId: "{token}" },
            version: ENTITY, session: "admin", body: {}, expect: 200,
        },

        // ── Global configuration ─────────────────────────────────────────────────────────────
        {
            id: "global-services-rest",
            row: { method: "GET", path: "/json/global-config/services/rest", query: "" },
            method: "GET", path: "/json/global-config/services/rest", query: {},
            version: SMS, session: "admin", expect: 200,
        },
        {
            id: "global-services-rest-schema",
            row: { method: "POST", path: "/json/global-config/services/rest",
                query: "_action=schema" },
            method: "POST", path: "/json/global-config/services/rest",
            query: { _action: "schema" },
            version: SMS, session: "admin", body: {}, expect: 200,
        },
        {
            id: "global-realms-list",
            row: { method: "GET", path: "/json/global-config/realms", query: "_queryFilter=true" },
            method: "GET", path: "/json/global-config/realms", query: { _queryFilter: "true" },
            version: SMS, session: "admin", expect: 200,
        },
        {
            id: "global-realms-schema",
            row: { method: "POST", path: "/json/global-config/realms", query: "_action=schema" },
            method: "POST", path: "/json/global-config/realms", query: { _action: "schema" },
            version: SMS, session: "admin", body: {}, expect: 200,
        },
        {
            id: "global-realms-template",
            row: { method: "POST", path: "/json/global-config/realms", query: "_action=template" },
            method: "POST", path: "/json/global-config/realms", query: { _action: "template" },
            version: SMS, session: "admin", body: {}, expect: 200,
        },
        {
            id: "global-authentication-schema",
            row: { method: "POST", path: "/json/global-config/authentication",
                query: "_action=schema" },
            method: "POST", path: "/json/global-config/authentication", query: { _action: "schema" },
            version: SMS, session: "admin", body: {}, expect: 200,
            note: "The largest payload in the capture, and the one that reorders its `properties` "
                + "keys on every single call. Rule 14 is what makes it stable.",
        },
        {
            id: "global-authentication-template",
            row: { method: "POST", path: "/json/global-config/authentication",
                query: "_action=template" },
            method: "POST", path: "/json/global-config/authentication",
            query: { _action: "template" },
            version: SMS, session: "admin", body: {}, expect: 200,
        },
        {
            id: "root-authentication",
            row: { method: "GET", path: "/json/realms/root/realm-config/authentication", query: "" },
            method: "GET", path: "/json/realms/root/realm-config/authentication", query: {},
            version: SMS, session: "admin", expect: 200,
        },
        {
            id: "root-authentication-schema",
            row: { method: "POST", path: "/json/realms/root/realm-config/authentication",
                query: "_action=schema" },
            method: "POST", path: "/json/realms/root/realm-config/authentication",
            query: { _action: "schema" },
            version: SMS, session: "admin", body: {}, expect: 200,
        },

        // ── Realm lifecycle ──────────────────────────────────────────────────────────────────
        {
            id: "realm-get-missing",
            row: { method: "GET", path: "/json/global-config/realms/<realm>", query: "" },
            method: "GET", path: "/json/global-config/realms/{realmId}", query: {},
            version: SMS, session: "admin", tag: "404", expect: 404,
            note: "The 'does it exist yet' probe. Only answers 404 before the create below, which "
                + "is why capture order is recorded rather than inferred.",
        },
        {
            id: "realm-create",
            row: { method: "POST", path: "/json/global-config/realms", query: "_action=create" },
            method: "POST", path: "/json/global-config/realms", query: { _action: "create" },
            version: SMS, session: "admin", expect: 201,
            // AM's own template, plus the two fields it cannot supply: the name, and an `aliases`
            // that must be present even when empty — the template omits it and the create rejects
            // a body without it.
            body: (ctx) => ({ ...ctx.raw("global-realms-template"), name: realm, aliases: [] }),
        },
        {
            id: "realm-get",
            row: { method: "GET", path: "/json/global-config/realms/<realm>", query: "" },
            method: "GET", path: "/json/global-config/realms/{realmId}", query: {},
            version: SMS, session: "admin", expect: 200,
        },
        {
            id: "realm-authentication",
            row: { method: "GET", path: "/json/realms/root/realms/<realm>/realm-config/authentication",
                query: "" },
            method: "GET", path: `${realmScoped}/realm-config/authentication`, query: {},
            version: SMS, session: "admin", expect: 200,
        },
        {
            id: "realm-authentication-schema",
            row: { method: "POST",
                path: "/json/realms/root/realms/<realm>/realm-config/authentication",
                query: "_action=schema" },
            method: "POST", path: `${realmScoped}/realm-config/authentication`,
            query: { _action: "schema" },
            version: SMS, session: "admin", body: {}, expect: 200,
        },
        {
            id: "realm-authentication-put",
            row: { method: "PUT",
                path: "/json/realms/root/realms/<realm>/realm-config/authentication", query: "" },
            method: "PUT", path: `${realmScoped}/realm-config/authentication`, query: {},
            version: SMS, session: "admin", expect: 200,
            // A value-preserving round trip: the service's own current state written straight back.
            // The console's realm screens save the whole document, so this is the shape they send.
            body: (ctx) => ctx.raw("realm-authentication"),
        },
        {
            id: "realm-services-list",
            row: { method: "GET", path: "/json/realms/root/realms/<realm>/realm-config/services",
                query: "_queryFilter=true" },
            method: "GET", path: `${realmScoped}/realm-config/services`,
            query: { _queryFilter: "true" },
            version: SMS, session: "admin", expect: 200,
        },
        {
            id: "realm-services-creatable",
            row: { method: "POST", path: "/json/realms/root/realms/<realm>/realm-config/services",
                query: "_action=getCreatableTypes&forUI=true" },
            method: "POST", path: `${realmScoped}/realm-config/services`,
            query: { _action: "getCreatableTypes", forUI: "true" },
            version: SMS, session: "admin", body: {}, expect: 200,
            note: "19 entries in a deliberately non-alphabetical order, which survived a full "
                + "destroy-and-reconfigure. Listings must not be sorted.",
        },
        {
            id: "legacy-services-creatable",
            row: { method: "POST", path: "/json/realm-config/services",
                query: "_action=getCreatableTypes&forUI=true&realm=<realm>" },
            method: "POST", path: "/json/realm-config/services",
            query: { _action: "getCreatableTypes", forUI: "true", realm: realmPath },
            version: SMS, session: "admin", body: {}, expect: 200,
            note: "The legacy realm-in-query shape. Fixture-only, but in scope: a @local-server "
                + "spec cannot provision itself if these go unanswered (REQUESTS.md, Fact 2).",
        },

        // ── Base URL service, both path shapes ───────────────────────────────────────────────
        {
            id: "baseurl-getalltypes",
            row: { method: "POST",
                path: "/json/realms/root/realms/<realm>/realm-config/services/baseurl",
                query: "_action=getAllTypes" },
            method: "POST", path: `${realmScoped}/realm-config/services/baseurl`,
            query: { _action: "getAllTypes" },
            version: SMS, session: "admin", body: {}, expect: 200,
        },
        {
            id: "baseurl-schema",
            row: { method: "POST",
                path: "/json/realms/root/realms/<realm>/realm-config/services/baseurl",
                query: "_action=schema" },
            method: "POST", path: `${realmScoped}/realm-config/services/baseurl`,
            query: { _action: "schema" },
            version: SMS, session: "admin", body: {}, expect: 200,
        },
        {
            id: "baseurl-template",
            row: { method: "POST",
                path: "/json/realms/root/realms/<realm>/realm-config/services/baseurl",
                query: "_action=template" },
            method: "POST", path: `${realmScoped}/realm-config/services/baseurl`,
            query: { _action: "template" },
            version: SMS, session: "admin", body: {}, expect: 200,
        },
        {
            id: "legacy-baseurl-missing",
            row: { method: "GET", path: "/json/realm-config/services/baseurl",
                query: "realm=<realm>" },
            method: "GET", path: "/json/realm-config/services/baseurl",
            query: { realm: realmPath },
            version: SMS, session: "admin", tag: "404", expect: 404,
        },
        {
            id: "baseurl-create",
            row: { method: "POST",
                path: "/json/realms/root/realms/<realm>/realm-config/services/baseurl",
                query: "_action=create" },
            method: "POST", path: `${realmScoped}/realm-config/services/baseurl`,
            query: { _action: "create" },
            version: SMS, session: "admin", expect: 201,
            body: (ctx) => ctx.raw("baseurl-template"),
        },
        {
            id: "baseurl-get",
            row: { method: "GET",
                path: "/json/realms/root/realms/<realm>/realm-config/services/baseurl", query: "" },
            method: "GET", path: `${realmScoped}/realm-config/services/baseurl`, query: {},
            version: SMS, session: "admin", expect: 200,
        },
        {
            id: "legacy-baseurl-get",
            row: { method: "GET", path: "/json/realm-config/services/baseurl",
                query: "realm=<realm>" },
            method: "GET", path: "/json/realm-config/services/baseurl",
            query: { realm: realmPath },
            version: SMS, session: "admin", expect: 200,
        },
        {
            id: "baseurl-put",
            row: { method: "PUT",
                path: "/json/realms/root/realms/<realm>/realm-config/services/baseurl", query: "" },
            method: "PUT", path: `${realmScoped}/realm-config/services/baseurl`, query: {},
            version: SMS, session: "admin", expect: 200,
            // The resource as AM just returned it, with the one attribute an edit changes. Every
            // other field is AM's own, so the write cannot be subtly wrong in a way the capture
            // would then enshrine.
            body: (ctx) => ({ ...ctx.raw("baseurl-get"), source: "FORWARDED_HEADER" }),
        },
        {
            id: "baseurl-delete",
            row: { method: "DELETE",
                path: "/json/realms/root/realms/<realm>/realm-config/services/baseurl", query: "" },
            method: "DELETE", path: `${realmScoped}/realm-config/services/baseurl`, query: {},
            version: SMS, session: "admin", expect: 200,
        },
        {
            id: "legacy-baseurl-create",
            row: { method: "POST", path: "/json/realm-config/services/baseurl",
                query: "_action=create&realm=<realm>" },
            method: "POST", path: "/json/realm-config/services/baseurl",
            query: { _action: "create", realm: realmPath },
            version: SMS, session: "admin", expect: 201,
            // Issued after the realm-scoped delete above: the two shapes address the same resource,
            // and a create against one that already exists answers a conflict, not a 201.
            body: (ctx) => ctx.raw("baseurl-template"),
        },
        {
            id: "dashboard-schema",
            row: { method: "POST",
                path: "/json/realms/root/realms/<realm>/realm-config/services/dashboard",
                query: "_action=schema" },
            method: "POST", path: `${realmScoped}/realm-config/services/dashboard`,
            query: { _action: "schema" },
            version: SMS, session: "admin", body: {}, expect: 200,
        },
        {
            id: "dashboard-template",
            row: { method: "POST",
                path: "/json/realms/root/realms/<realm>/realm-config/services/dashboard",
                query: "_action=template" },
            method: "POST", path: `${realmScoped}/realm-config/services/dashboard`,
            query: { _action: "template" },
            version: SMS, session: "admin", body: {}, expect: 200,
        },

        // ── Realm teardown ───────────────────────────────────────────────────────────────────
        {
            id: "realm-put",
            row: { method: "PUT", path: "/json/global-config/realms/<realm>", query: "" },
            method: "PUT", path: "/json/global-config/realms/{realmId}", query: {},
            version: SMS, session: "admin", expect: 200,
            // Last of the realm-scoped work on purpose: an edit that changes what the realm answers
            // to would otherwise change every capture after it.
            body: (ctx) => ({ ...ctx.raw("realm-get"), aliases: [CAPTURE_REALM_ALIAS] }),
        },
        {
            id: "realm-delete",
            row: { method: "DELETE", path: "/json/global-config/realms/<realm>", query: "" },
            method: "DELETE", path: "/json/global-config/realms/{realmId}", query: {},
            version: SMS, session: "admin", expect: 200,
        },
        {
            id: "realm-delete-missing",
            row: { method: "DELETE", path: "/json/global-config/realms/<realm>", query: "" },
            method: "DELETE", path: "/json/global-config/realms/{realmId}", query: {},
            version: SMS, session: "admin", tag: "404", expect: 404,
            note: "The 'is it gone' probe the realm teardown fixture makes, which treats an already "
                + "deleted realm as the successful case.",
        },

        // ── User profile: write before read, deliberately ────────────────────────────────────
        {
            id: "users-demo-put",
            row: { method: "PUT", path: "/json/realms/root/users/demo", query: "" },
            method: "PUT", path: "/json/realms/root/users/demo", query: {},
            version: ENTITY, session: "admin", expect: 200,
            // Four profile fields read back and written unchanged. Deliberately not the whole
            // document: echoing `modifyTimestamp` back would put a volatile value in the *request*,
            // where no response rule would reach it.
            body: async (ctx) => {
                const current = await ctx.get("/json/realms/root/users/demo", ENTITY);
                return {
                    givenName: current.givenName,
                    sn: current.sn,
                    cn: current.cn,
                    mail: current.mail,
                };
            },
        },
        {
            id: "users-demo-get",
            row: { method: "GET", path: "/json/realms/root/users/demo", query: "" },
            method: "GET", path: "/json/realms/root/users/demo", query: {},
            version: ENTITY, session: "admin", expect: 200,
            note: "After the PUT above, always. The PUT creates a `modifyTimestamp` key that never "
                + "goes away, so reading first would record one shape on a fresh instance and a "
                + "different one on every later run — a field appearing, which no rule should hide.",
        },

        // ── Session teardown ─────────────────────────────────────────────────────────────────
        {
            id: "sessions-logout",
            row: { method: "POST", path: "/json/sessions",
                query: "_action=logout&tokenId=<token>" },
            method: "POST", path: "/json/sessions",
            query: { _action: "logout", tokenId: "{token}" },
            version: ENTITY, session: "demo", body: {}, expect: 200, ends: "demo",
            note: "The end-user row. Logging the admin out here would destroy the tool's own "
                + "credential mid-capture, so it runs against the demo session and the admin "
                + "session is ended after the capture finishes.",
        },
    ];
}
