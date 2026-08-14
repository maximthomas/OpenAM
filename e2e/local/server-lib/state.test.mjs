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
 * What the baseline state must answer, against the recording it was built from.
 *
 *     node --test local/server-lib/
 *
 * The claim under test is specs/ui-local-backend/spec.md's "Capture is the source of response
 * shapes": a read this server answers is structurally the same as the recorded response for that
 * request. It is checked by rendering from state and comparing to the payload on disk — not by
 * comparing the server to itself, which is why `recorded()` below resolves the deployment markers
 * with its own six-line substitution rather than importing capture-store.mjs's. A test that shares
 * the implementation's resolver would still pass with that resolver broken.
 *
 * The other half of D15 is here too, and it is the half replay cannot do: a realm put into the
 * store appears in the next listing, with the count following it. That is the state machine, in
 * the smallest form that shows it works, and it is what tasks 2.10-2.12 build their writes on.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { after, describe, it } from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

import { captureFileFor, loadCapture } from "./capture-store.mjs";
import { parseRoute } from "./rest.mjs";
import { buildBaselineState, realmIdFor, realmPathFor } from "./state.mjs";

const CAPTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "capture");

const DEPLOYMENT = { context: "openam", hostname: "localhost" };

/**
 * The deployment markers as this deployment resolves them, written out rather than derived. The
 * point of the duplication is in the header note.
 */
const RESOLVED = {
    "{{CONTEXT}}": "openam",
    "{{HOSTNAME}}": "localhost",
    "{{HOST_ALIAS}}": "localhost",
    "{{CONFIG_SUFFIX}}": "dc=openam,dc=openidentityplatform,dc=org",
};

/** A recorded response body, with the markers this server substitutes already substituted. */
function recorded (file) {
    let text = JSON.stringify(
        JSON.parse(readFileSync(join(CAPTURE_DIR, file), "utf8")).response.body,
    );
    for (const [marker, value] of Object.entries(RESOLVED)) {
        text = text.replaceAll(marker, value);
    }
    return JSON.parse(text);
}

const baseline = () => buildBaselineState(CAPTURE_DIR, DEPLOYMENT);

const temporary = [];
after(() => Promise.all(temporary.map((dir) => rm(dir, { recursive: true, force: true }))));

/**
 * A capture directory holding just enough to build a baseline from.
 *
 * The committed capture cannot exercise the loader's guards -- it is, by construction, a recording
 * that satisfies them -- and it has exactly one realm, so it cannot show what happens to a second.
 * Both are properties of a *re-record*, which is task 2.15's job to produce and this server's job
 * to survive, so they are worth a synthetic tree.
 */
async function syntheticCapture ({ realms, listingOrder = 1, createOrder = 9, omit = [] }) {
    const dir = await mkdtemp(join(tmpdir(), "openam-capture-"));
    temporary.push(dir);

    const paging = { pagedResultsCookie: null, remainingPagedResults: -1 };
    const bodies = {
        "json/global-config/realms/GET.queryFilter=true.json": {
            ...paging,
            result: realms,
            resultCount: realms.length,
            totalPagedResults: -1,
            totalPagedResultsPolicy: "NONE",
        },
        "json/realms/root/realm-config/authentication/GET.json": { _id: "", core: {} },
        "json/global-config/services/rest/GET.json": { _id: "", defaultVersion: "Latest" },
        // What a realm created through the console is made of (task 2.10): the defaults AM declares
        // for a realm document, and the authentication configuration a realm holds the moment it
        // exists. Loaded by buildBaselineState like the rest, so a synthetic tree without them
        // builds nothing.
        "json/global-config/realms/POST.action=template.json": { active: true, parentPath: "/" },
        "json/realms/root/realms/{realm}/realm-config/authentication/GET.json": {
            _id: "", core: {}, general: { statelessSessionsEnabled: false },
        },
        // The fixtures' one-call header authentication (task 2.10, auth.mjs), here for the same
        // reason as the exchange below it: every real recording has it.
        "json/authenticate/POST.json": {
            realm: "/", successUrl: "/{{CONTEXT}}/console", tokenId: "<TOKEN>",
        },
        // The administrator's profile -- task 2.12's resource, loaded by 2.10 because its `roles`
        // are what let a browser off the login route at all. See BASELINE.adminProfile.
        "json/realms/root/users/amadmin/GET.json": {
            realm: "/", roles: ["ui-global-admin", "ui-realm-admin"], username: "amadmin",
        },
        // What a realm holds the moment it exists, and what it may still be given (task 2.11). The
        // two are read as a pair: a realm created through the console is seeded from the first, and
        // every `_action=getCreatableTypes` answer is the second minus whatever the realm now holds.
        // Empty here rather than realistic -- the tests in this file that use a synthetic tree are
        // about the loader's guards, and state.test.mjs's service tests run against the committed
        // capture, where these are the recorded documents.
        "json/realms/root/realms/{realm}/realm-config/services/GET.queryFilter=true.json": {
            ...paging,
            result: [],
            resultCount: 0,
            totalPagedResults: 0,
            totalPagedResultsPolicy: "EXACT",
        },
        "json/realms/root/realms/{realm}/realm-config/services/POST.action=getCreatableTypes.json": {
            result: [],
        },
        // What a service delete answers. Read rather than written out by the store, so a synthetic
        // tree without it builds nothing -- see BASELINE.serviceDelete.
        "json/realms/root/realms/{realm}/realm-config/services/baseurl/DELETE.json": {
            success: true,
        },
        // The authentication exchange (task 2.7, auth.mjs), which buildBaselineState loads along
        // with the rest. Here because every real recording has it and a state built without it
        // could log nobody in -- not because these tests exercise it. auth.test.mjs does that,
        // against the committed capture, where the bodies are the recorded ones.
        "json/realms/root/authenticate/POST.callbacks.json": {
            authId: "<AUTHID>",
            callbacks: [
                { input: [{ name: "IDToken1", value: "" }], output: [], type: "NameCallback" },
                { input: [{ name: "IDToken2", value: "" }], output: [], type: "PasswordCallback" },
            ],
            stage: "DataStore1",
        },
        "json/realms/root/authenticate/POST.success.json": {
            realm: "/", successUrl: "/{{CONTEXT}}/console", tokenId: "<TOKEN>",
        },
        "json/realms/root/authenticate/POST.failure.json": {
            code: 401, message: "Authentication Failed", reason: "Unauthorized",
        },
        "json/users/POST.action=idFromSession.401.json": {
            code: 401, message: "Access Denied", reason: "Unauthorized",
        },
        // The rest of a session's life (task 2.8), loaded by the same call and here for the same
        // reason as the three above.
        "json/users/POST.action=idFromSession.json": {
            dn: "id=amadmin,ou=user,{{CONFIG_SUFFIX}}",
            fullLoginURL: "/{{CONTEXT}}/UI/Login?realm=%2F",
            id: "amadmin",
            realm: "/",
            successURL: "/{{CONTEXT}}/console",
        },
        "json/sessions/POST.action=getSessionInfo.json": {
            latestAccessTime: "<TS>",
            maxIdleExpirationTime: "<TS>",
            maxSessionExpirationTime: "<TS>",
            realm: "/",
            sessionHandle: "<SESSION-HANDLE>",
            universalId: "id=amadmin,ou=user,{{CONFIG_SUFFIX}}",
            username: "amadmin",
        },
        "json/sessions/POST.action=logout.json": { result: "Successfully logged out" },
        // The site configuration (task 2.9), read for its `cookieName` field and served whole.
        //
        // `domains` carries the unresolvable marker deliberately. This test's deployment map has no
        // `COOKIE_DOMAIN`, so a loader that resolved the document *before* applying the server's
        // override would throw here -- which makes every test that builds against this synthetic
        // capture an assertion that it does not, rather than needing one that asks directly.
        "json/serverinfo/star/GET.resource=1.1.json": {
            cookieName: "iPlanetDirectoryPro", domains: ["{{COOKIE_DOMAIN}}"], realm: "/",
        },
        "json/serverinfo/version/GET.json": {
            date: "2026-August-04 10:48", revision: "fc8e2e67c7", version: "16.2.0-SNAPSHOT",
        },
    };

    const orders = {
        "json/global-config/realms/GET.queryFilter=true.json": listingOrder,
        "json/global-config/realms/POST.action=create.json": createOrder,
    };
    const calls = [];
    let next = 2;

    for (const file of [...Object.keys(bodies), "json/global-config/realms/POST.action=create.json"]) {
        if (omit.includes(file)) {
            continue;
        }
        calls.push({ order: orders[file] ?? (next += 1), file, method: "GET", query: {} });
        if (bodies[file]) {
            await mkdir(join(dir, dirname(file)), { recursive: true });
            await writeFile(
                join(dir, file),
                JSON.stringify({ request: {}, response: { status: 200, body: bodies[file] } }),
                "utf8",
            );
        }
    }

    await writeFile(join(dir, "index.json"), JSON.stringify({ callCount: calls.length, calls }));
    return dir;
}

/** The realm documents AM returns in a listing, for the synthetic tree above. */
const realmDocument = (path, name, parentPath) => ({
    _id: realmIdFor(path),
    active: true,
    aliases: [],
    name,
    parentPath,
});

describe("the baseline built from the capture", () => {
    it("holds the root realm and nothing the capture itself created", () => {
        // The capture creates and deletes `e2e-capture` in the middle of its run. A baseline that
        // picked the listing up from after the create would carry a realm no reset AM has --
        // capture/README.md's "permanent phantom", and the reason state.mjs asserts the order.
        assert.deepEqual([...baseline().realms.keys()], ["/"]);
    });

    it("resolves the deployment markers into this server's own values", () => {
        const root = baseline().realmAuthentication("/").body;
        assert.deepEqual(root.postauthprocess.loginSuccessUrl, ["/openam/console"]);
        assert.doesNotMatch(JSON.stringify(root), /\{\{[A-Z_]+\}\}/);
    });

    it("takes the context from the server's settings, not from the recording", () => {
        const state = buildBaselineState(CAPTURE_DIR, { context: "am", hostname: "localhost" });
        assert.deepEqual(
            state.realmAuthentication("/").body.postauthprocess.loginSuccessUrl,
            ["/am/console"],
        );
    });

    it("does not split an address literal into a realm alias no browser sends", () => {
        // The default bind address is 127.0.0.1, and the recording's "bare first label" rule
        // applied to it yields "127". AM resolves a realm by matching the incoming host against
        // these, so the alias has to be something a browser could actually send.
        const onAddress = buildBaselineState(CAPTURE_DIR, {
            context: "openam",
            hostname: "127.0.0.1",
        });
        assert.deepEqual(onAddress.realmsListing().body.result[0].aliases,
            ["127.0.0.1", "127.0.0.1"]);

        const onName = buildBaselineState(CAPTURE_DIR, {
            context: "openam",
            hostname: "openam.example.org",
        });
        assert.deepEqual(onName.realmsListing().body.result[0].aliases,
            ["openam", "openam.example.org"]);
    });

    it("refuses to serve a payload carrying a marker it has no value for", () => {
        // The guard that stops a re-record introducing a placeholder which would otherwise reach
        // the browser as a literal `{{SOMETHING}}` and fail far from its cause.
        const capture = loadCapture(CAPTURE_DIR, {});
        assert.throws(
            () => capture.body("json/realms/root/realm-config/authentication/GET.json"),
            /\{\{CONTEXT\}\}, which the local API server has no value for/,
        );
    });

    it("names the file when the capture does not have it", () => {
        assert.throws(
            () => loadCapture(CAPTURE_DIR, {}).body("json/nothing/GET.json"),
            /The capture has no json\/nothing\/GET\.json/,
        );
    });

    it("reads one field without resolving the markers in the rest of the document", () => {
        // How the session cookie's name is taken from `serverinfo/*` without deciding anything
        // about the `domains` array beside it, which carries a marker and belongs to task 2.9.
        const capture = loadCapture(CAPTURE_DIR, {});
        const file = "json/serverinfo/star/GET.resource=1.1.json";

        assert.equal(capture.bodyField(file, "cookieName"), "iPlanetDirectoryPro");
        assert.throws(() => capture.body(file), /\{\{COOKIE_DOMAIN\}\}/);
    });

    it("refuses a field the recording does not have, rather than answering undefined", () => {
        // A re-record that dropped `cookieName` would otherwise put a cookie named `undefined` on
        // every login, which says nothing about which field stopped being recorded.
        assert.throws(
            () => loadCapture(CAPTURE_DIR, {})
                .bodyField("json/serverinfo/star/GET.resource=1.1.json", "notARecordedField"),
            /has no "notARecordedField" in its response body/,
        );
    });

    it("refuses to override a field the recording does not have", () => {
        // An override exists to disagree with a recorded field. A field that is not there is not a
        // disagreement but a recording that changed shape, and letting the override supply it would
        // serve an invented document that reads as a recorded one.
        assert.throws(
            () => loadCapture(CAPTURE_DIR, {})
                .bodyWith("json/serverinfo/star/GET.resource=1.1.json", { notARecordedField: [] }),
            /which the recorded response body does not have/,
        );
    });

    it("still refuses a marker outside the field it was told to override", () => {
        // What keeps the override from being a hole in the fatal-marker guard. Replacing `domains`
        // is what takes `{{COOKIE_DOMAIN}}` out of the document; replace anything else and the
        // marker is still there, still unresolvable, and still fatal -- exactly as `body` has it.
        assert.throws(
            () => loadCapture(CAPTURE_DIR, {})
                .bodyWith("json/serverinfo/star/GET.resource=1.1.json", { realm: "/" }),
            /\{\{COOKIE_DOMAIN\}\}/,
        );
    });
});

describe("a recording that is not the committed one", () => {
    it("keys every realm by its path, not by its name", () => {
        // The two agree only for root, whose name *is* "/". A realm keyed by the bare name it
        // carries in a listing would be visible in that listing and 404 at every realm-scoped
        // route -- and the committed capture, whose baseline is root alone, cannot show it.
        const state = () => syntheticCapture({
            realms: [realmDocument("/", "/", null), realmDocument("/alpha", "alpha", "/")],
        }).then((dir) => buildBaselineState(dir, DEPLOYMENT));

        return state().then((built) => {
            assert.deepEqual([...built.realms.keys()], ["/", "/alpha"]);
            assert.equal(built.realmServicesListing("/alpha").status, 200);
            assert.equal(built.realmById(realmIdFor("/alpha")).status, 200);
        });
    });

    it("is inverse to the id in the URL", () => {
        for (const path of ["/", "/alpha", "/e2e-capture", "/a-realm.with.dots"]) {
            assert.equal(realmPathFor({ _id: realmIdFor(path) }), path);
        }
    });

    it("refuses a listing recorded after the create it is meant to precede", async () => {
        // The guard against capture/README.md's "permanent phantom": a baseline holding a realm
        // the recording itself created, which no reset AM has.
        const dir = await syntheticCapture({
            realms: [realmDocument("/", "/", null)],
            listingOrder: 30,
            createOrder: 23,
        });
        assert.throws(
            () => buildBaselineState(dir, DEPLOYMENT),
            /recorded at order 30, after the realm create at 23/,
        );
    });

    it("says which call went missing rather than blaming the recording's contents", async () => {
        // A dropped call is what a 2.15 re-record can produce. Reported as an absent order, it
        // used to come out as the phantom-realm complaint above, which names the wrong cause.
        const dir = await syntheticCapture({
            realms: [realmDocument("/", "/", null)],
            omit: ["json/global-config/realms/POST.action=create.json"],
        });
        assert.throws(
            () => buildBaselineState(dir, DEPLOYMENT),
            /The capture has no json\/global-config\/realms\/POST\.action=create\.json/,
        );
    });

    it("names the index when it cannot be read at all", async () => {
        const dir = await mkdtemp(join(tmpdir(), "openam-capture-"));
        temporary.push(dir);
        assert.throws(
            () => buildBaselineState(dir, DEPLOYMENT),
            /cannot read its capture index at .*index\.json/,
        );
    });
});

describe("a read is structurally the same as the recorded response", () => {
    it("the realm collection", () => {
        assert.deepEqual(
            baseline().realmsListing(),
            { status: 200, body: recorded("json/global-config/realms/GET.queryFilter=true.json") },
        );
    });

    it("the global REST service singleton", () => {
        assert.deepEqual(
            baseline().globalService("rest"),
            { status: 200, body: recorded("json/global-config/services/rest/GET.json") },
        );
    });

    it("the footer's version document", () => {
        assert.deepEqual(
            baseline().serverVersion(),
            { status: 200, body: recorded("json/serverinfo/version/GET.json") },
        );
    });

    it("the root realm's authentication singleton", () => {
        assert.deepEqual(
            baseline().realmAuthentication("/"),
            {
                status: 200,
                body: recorded("json/realms/root/realm-config/authentication/GET.json"),
            },
        );
    });

    it("the 404 the capture recorded for a realm that does not exist", () => {
        // Recorded at order 22, before the create -- so it is a baseline observation, and the
        // baseline has to agree with it.
        assert.deepEqual(
            baseline().realmById("L2UyZS1jYXB0dXJl"),
            { status: 404, body: recorded("json/global-config/realms/{realmId}/GET.404.json") },
        );
    });

    it("a realm's service listing, once the realm exists", () => {
        const state = baseline();
        // The realm and the one service a freshly created realm has, as the capture recorded them
        // at orders 24 and 28. Seeding the store directly is what task 2.10's create will do.
        state.realms.set("/e2e-capture", {
            document: recorded("json/global-config/realms/{realmId}/GET.json"),
            authentication: recorded(
                "json/realms/root/realms/{realm}/realm-config/authentication/GET.json",
            ),
            services: new Map([["policyconfiguration", {
                _id: "",
                _type: { _id: "policyconfiguration", collection: false, name: "Policy Configuration" },
            }]]),
        });

        assert.deepEqual(
            state.realmServicesListing("/e2e-capture"),
            {
                status: 200,
                body: recorded(
                    "json/realms/root/realms/{realm}/realm-config/services/GET.queryFilter=true.json",
                ),
            },
        );
    });
});

/**
 * The one document this server serves *nearly* as recorded, and the one field it does not.
 *
 * These are assertions about values rather than shapes, which the rest of this file avoids -- but
 * NOTES-siteconfig.md's point is that the values here are what the UI's behaviour is made of, and
 * that a wrong one produces a UI that renders and is wrong rather than one that fails. The two the
 * suite reads hardest are asserted by name for that reason.
 */
describe("the site configuration the XUI bootstraps from", () => {
    it("is the recorded document, but for the cookie domains", () => {
        const { status, body } = baseline().siteConfiguration();
        const asRecorded = JSON.parse(
            readFileSync(join(CAPTURE_DIR, "json/serverinfo/star/GET.resource=1.1.json"), "utf8"),
        ).response.body;

        assert.equal(status, 200);
        assert.deepEqual(Object.keys(body).sort(), Object.keys(asRecorded).sort());
        assert.deepEqual({ ...body, domains: undefined }, { ...asRecorded, domains: undefined });
    });

    it("serves no cookie domain, so the XUI's own write is host-only", () => {
        // The recorded value is another deployment's cookie domain and cannot be copied here; see
        // SITE_CONFIGURATION_OVERRIDES. `[]` is CookieHelper's documented way to ask for host-only,
        // and it has to agree with rest.mjs's Set-Cookie, which omits Domain for the same reason.
        assert.deepEqual(baseline().siteConfiguration().body.domains, []);
        assert.equal(
            JSON.stringify(baseline().siteConfiguration()).includes("{{"),
            false,
            "no unresolved deployment marker may reach the browser",
        );
    });

    it("reports the flags the phase-0 specs read, at the values they were recorded at", () => {
        const { body } = baseline().siteConfiguration();

        // xui-httponly.spec.mjs asserts the real cookie's httpOnly equals this, and skips a test on
        // it; xui-profile.spec.mjs asserts the profile has exactly [basicInfo, password] tabs, which
        // a kbaEnabled of "true" would add a third to; and its edit test saves givenName, which a
        // protectedUserAttributes naming a details field would put behind a password dialog.
        assert.equal(body.cookieHttpOnly, false);
        assert.equal(body.kbaEnabled, "false");
        assert.deepEqual(body.protectedUserAttributes, []);
        // Not a flag but the two structural fields: absent, `realm` throws in the reducer and takes
        // every other field with it, and `cookieName` is silently the string "undefined".
        assert.equal(body.realm, "/");
        assert.equal(body.cookieName, "iPlanetDirectoryPro");
        // A string on the wire, compared `=== "true"`. Serving a JSON `false` here would pin the
        // feature permanently off in a way nothing notices until someone turns it on.
        assert.equal(typeof body.selfRegistration, "string");
        // And the trap in the other direction, which is the expensive one: `secureCookie` is a real
        // boolean, and a re-record that turned it into the string "false" would be truthy, so the
        // XUI would write its cookie with `;secure` and the browser would drop it over plain HTTP.
        // Every login in the suite fails, and nothing in the failure says why (NOTES-auth.md §3).
        assert.equal(body.secureCookie, false);
    });

    it("the cookie the server sets is the cookie the XUI looks for", () => {
        // The two ends of NOTES-auth.md §3, which are only the same string as long as both read the
        // recording: auth.mjs takes the name from `serverinfo/*` via bodyField, and this document is
        // that same recorded field served to the browser.
        const state = baseline();
        assert.equal(state.auth.cookieName, state.siteConfiguration().body.cookieName);
    });
});

describe("reads come from state, not from replay", () => {
    it("reflects a realm added to the store in the next listing", () => {
        // specs/ui-local-backend/spec.md, "Creation is reflected in subsequent reads". The write
        // itself is task 2.10; what is proved here is that the read path will show it, which a
        // server replaying json/global-config/realms/GET.queryFilter=true.json never could.
        const state = baseline();
        const realmPath = "/alpha";
        state.realms.set(realmPath, {
            document: {
                _id: realmIdFor(realmPath),
                active: true,
                aliases: [],
                name: "alpha",
                parentPath: "/",
            },
            authentication: undefined,
            services: new Map(),
        });

        const listing = state.realmsListing().body;
        assert.deepEqual(listing.result.map((realm) => realm.name), ["/", "alpha"]);
        assert.equal(listing.resultCount, 2);
        // NONE policy: the recorded -1 is the answer, not a count this server made up.
        assert.equal(listing.totalPagedResults, -1);
        assert.deepEqual(state.realmById(realmIdFor(realmPath)).status, 200);
    });

    it("counts an EXACT-policy collection but not a NONE-policy one", () => {
        const state = baseline();
        state.realms.set("/alpha", { document: {}, services: new Map() });
        const services = state.realmServicesListing("/alpha").body;
        assert.equal(services.resultCount, 0);
        assert.equal(services.totalPagedResults, 0);
        assert.equal(services.totalPagedResultsPolicy, "EXACT");
    });

    it("answers a realm that is not there with AM's own message", () => {
        assert.deepEqual(baseline().realmAuthentication("/gone"), {
            status: 404,
            body: { code: 404, message: "Realm cannot be read: /gone", reason: "Not Found" },
        });
    });

    it("returns a service instance once the realm holds one", () => {
        const state = baseline();
        const instance = {
            _id: "",
            _type: { _id: "baseurl", collection: false, name: "Base URL Source" },
            contextPath: "/openam",
            source: "REQUEST_VALUES",
        };
        state.realms.set("/alpha", { document: {}, services: new Map([["baseurl", instance]]) });

        assert.deepEqual(state.realmService("/alpha", "baseurl"), { status: 200, body: instance });
        // AM does not name the service it could not find, unlike the realm case.
        assert.deepEqual(state.realmService("/alpha", "dashboard"), {
            status: 404,
            body: { code: 404, message: "Not Found", reason: "Not Found" },
        });
        assert.deepEqual(state.realmServicesListing("/alpha").body.result,
            [{ _id: "baseurl", name: "Base URL Source" }]);
    });

    it("quotes a realm id that is not one, rather than what it decodes to", () => {
        // Node's base64url decoder discards what it cannot use instead of rejecting it, so an id
        // like this used to come back as the mojibake it decoded to.
        assert.match(baseline().realmById("@@@not-base64@@@").body.message,
            /Realm cannot be read: @@@not-base64@@@/);
    });
});

/**
 * Task 2.10. The requirement in specs/ui-local-backend/spec.md is one sentence — a realm created
 * through the console appears in the next listing and a deleted one disappears — and the tests below
 * are that sentence plus the rules this server had to *choose*, which are the ones D15 warns can be
 * wrong in ways the re-record diff will never catch.
 */
describe("the realm writes", () => {
    /** Create through the store, the way the console's `_action=create` arrives. */
    const create = (state, name, extra = {}) => state.createRealm({ name, ...extra });

    it("puts a created realm in the next listing and takes a deleted one out", () => {
        const state = baseline();
        const created = create(state, "alpha", { aliases: ["alpha.example.invalid"] });

        assert.equal(created.status, 201);
        assert.equal(created.body._id, realmIdFor("/alpha"));
        assert.deepEqual(state.realmsListing().body.result.map((realm) => realm.name),
            ["/", "alpha"]);
        assert.equal(state.realmById(created.body._id).status, 200);

        const deleted = state.deleteRealm(created.body._id);
        assert.equal(deleted.status, 200);
        // As recorded: AM answers a delete with the realm as it last was, not with an empty body.
        assert.deepEqual(deleted.body, created.body);
        assert.deepEqual(state.realmsListing().body.result.map((realm) => realm.name), ["/"]);
        assert.equal(state.realmById(created.body._id).status, 404);
    });

    it("takes the defaults it does not receive from the recorded template", () => {
        // `{active: true, parentPath: "/"}` is AM's own answer to `_action=template`, which is also
        // where the console's new-realm form gets its defaults -- so the two cannot disagree.
        const { body } = create(baseline(), "alpha");

        assert.equal(body.active, true);
        assert.equal(body.parentPath, "/");
        assert.deepEqual(body.aliases, []);
    });

    it("stores a realm under the path its id decodes to", () => {
        // The property every realm-scoped route depends on: the store key and the id in the URL are
        // inverses, so a realm that lists can also be read, edited and deleted.
        const state = baseline();
        const { body } = create(state, "beta", { parentPath: "/" });

        assert.ok(state.realms.has("/beta"));
        assert.equal(realmPathFor(body), "/beta");
    });

    it("gives a created realm the authentication document a created realm has", () => {
        // Seeded from the capture's order-25 read -- a realm that had just been created and never
        // written to. Without it the console's second write, and every read of the edit form, 404s.
        const state = baseline();
        create(state, "alpha");

        const authentication = state.realmAuthentication("/alpha");
        assert.equal(authentication.status, 200);
        assert.equal(authentication.body.general.statelessSessionsEnabled, false);
    });

    it("does not let two realms share one authentication document", () => {
        const state = baseline();
        create(state, "alpha");
        create(state, "beta");
        state.updateRealmAuthentication("/alpha", { statelessSessionsEnabled: true });

        assert.equal(
            state.realmAuthentication("/beta").body.general.statelessSessionsEnabled, false);
    });

    it("merges an authentication write over the document rather than replacing it", () => {
        // The body is the flat one the console really PUTs: `JSONEditorView.getData` picks the
        // schema's `defaultProperties`, so the realm form's second subview sends this single key
        // and no section around it. Replacing would leave the document missing everything it did
        // not send, and the next render of the edit form reads it back.
        const state = baseline();
        create(state, "alpha");
        const answer = state.updateRealmAuthentication("/alpha",
            { statelessSessionsEnabled: true });

        assert.equal(answer.status, 200);
        // In `general`, where the schema declares it and where the form's next render looks --
        // not at the top level, which is where a flat merge would have left it.
        assert.equal(answer.body.general.statelessSessionsEnabled, true);
        assert.ok(!Object.hasOwn(answer.body, "statelessSessionsEnabled"));
        assert.ok(answer.body.accountlockout, "the untouched blocks survive a partial write");
        assert.equal(state.realmAuthentication("/alpha").body.general.statelessSessionsEnabled,
            true);
    });

    it("keeps the identity the URL decided, whatever an update's body says", () => {
        // `_id`, `name` and `parentPath` *are* the key this realm is filed under. A body that moved
        // one would leave the realm addressable at an id that no longer decodes to its store key.
        const state = baseline();
        const realmId = create(state, "alpha").body._id;
        const updated = state.updateRealm(realmId,
            { _id: "Lw", active: false, name: "renamed", parentPath: "/elsewhere" });

        assert.deepEqual(updated.body,
            { _id: realmId, active: false, aliases: [], name: "alpha", parentPath: "/" });
        assert.equal(state.realmById(realmId).body.active, false);
        assert.ok(state.realms.has("/alpha"));
    });

    it("answers a write to a realm that is not there with AM's own message", () => {
        const state = baseline();
        const gone = realmIdFor("/gone");

        for (const answer of [state.updateRealm(gone, {}), state.deleteRealm(gone)]) {
            assert.equal(answer.status, 404);
            assert.deepEqual(answer.body,
                { code: 404, message: "Realm cannot be read: /gone", reason: "Not Found" });
        }
    });

    it("refuses a realm with no name rather than filing one under a path it invented", () => {
        // The one field with no default and no way to derive one. Everything else a malformed body
        // could get wrong is defaulted from the template or dropped.
        const state = baseline();

        for (const document of [{}, { name: "  " }, { name: 42 }, undefined]) {
            assert.equal(state.createRealm(document).status, 400);
        }
        assert.deepEqual([...state.realms.keys()], ["/"]);
    });

    it("keeps only the properties the recorded schema declares", () => {
        // AM validates a create against that schema. This drops what it does not know instead,
        // which is the weaker rule -- and the one that cannot answer a request the specs do send
        // with a status the recording has no example of.
        const { body } = create(baseline(), "alpha", { active: false, notARealmProperty: true });

        assert.deepEqual(Object.keys(body).sort(),
            ["_id", "active", "aliases", "name", "parentPath"]);
    });
});

describe("the payloads served verbatim", () => {
    it("is exactly the schema, template and sub-schema-type documents", () => {
        // Every payload served verbatim is one that cannot reflect a write, so the list is meant
        // to stay at the SMS documents that describe a service rather than record its state. This
        // is what would notice it growing.
        const state = baseline();
        // No bodies are read here, so the deployment map is irrelevant to the selection.
        const served = loadCapture(CAPTURE_DIR, {})
            .filesForActions(["schema", "template", "getAllTypes"]);
        assert.equal(served.length, 12);
        assert.equal(served.filter((file) => file.includes("action=schema")).length, 7);
        assert.equal(served.filter((file) => file.includes("action=template")).length, 4);
        assert.equal(served.filter((file) => file.includes("action=getAllTypes")).length, 1);
        assert.notEqual(state.verbatim({
            method: "POST",
            path: "/json/global-config/realms",
            query: { _action: "schema" },
        }), undefined);
    });

    it("answers getAllTypes with the recorded empty list, on every edit-form render", () => {
        // Task 2.11's one sub-schema-adjacent call. `EditSchemaComponent.render` fans it out
        // unconditionally, so it is issued by every edit form the spec opens even though `baseurl`
        // has no sub-schema types. Both failure modes are silent in different ways: a non-empty
        // answer draws a tab bar the spec asserts is absent, and no answer at all leaves the outer
        // Promise.all pending, so the edit form never renders and every test that reaches one fails
        // somewhere with nothing to say about this call.
        assert.deepEqual(baseline().verbatim({
            method: "POST",
            path: "/json/realms/root/realms/{realm}/realm-config/services/baseurl",
            query: { _action: "getAllTypes" },
        }), { result: [] });
    });

    it("answers a schema for a realm the capture never saw", () => {
        // The capture stores this document under the directory `{realm}` precisely so one
        // recording answers every realm a spec invents at run time.
        const state = baseline();
        const forInvented = state.verbatim({
            method: "POST",
            path: parseRoute(
                "/json/realms/root/realms/spec-made-this-up/realm-config/services/baseurl",
                {},
            ).routePath,
            query: { _action: "schema" },
        });
        assert.deepEqual(forInvented, recorded(
            "json/realms/root/realms/{realm}/realm-config/services/baseurl/POST.action=schema.json",
        ));
    });

    it("derives the file the recorder wrote, for every document it serves", () => {
        // capture-store.mjs's file derivation is a hand-copy of capture-lib/tree.mjs's, and the
        // two are the write and read ends of one naming scheme. Nothing makes them stay identical,
        // and a divergence surfaces as a 501 rather than as a failure -- so this walks the real
        // index and checks the whole chain: the transcript path AM was asked, through parseRoute's
        // route form, to the file name the recorder chose.
        const index = JSON.parse(readFileSync(join(CAPTURE_DIR, "index.json"), "utf8"));
        const documents = index.calls
            .filter((call) => ["schema", "template", "getAllTypes"].includes(call.query?._action));

        assert.equal(documents.length, 12);
        for (const call of documents) {
            const route = parseRoute(call.path, call.query);
            assert.equal(
                captureFileFor({ method: call.method, path: route.routePath, query: call.query }),
                call.file,
            );
        }
    });

    it("does not serve an action outside the list", () => {
        // getCreatableTypes is the action that must *not* be in here: task 2.11 established that it
        // is state-dependent -- the question capture/README.md's "Known limits" left open -- so the
        // recorded body is a catalogue to recompute from rather than an answer to serve. Serving it
        // verbatim would be right for the recorded realm and wrong for every other.
        assert.equal(baseline().verbatim({
            method: "POST",
            path: "/json/realms/root/realms/{realm}/realm-config/services",
            query: { _action: "getCreatableTypes" },
        }), undefined);
    });
});

/**
 * Task 2.11. The requirement in specs/ui-local-backend/spec.md is that an administrative form is
 * generated from a schema and that a deletion is reflected in subsequent reads; what is below is
 * that, plus the rules this server had to *choose* — which are the D15 class the re-record diff
 * cannot catch — plus the one rule xui-services.spec.mjs will fail loudly on if it is got wrong.
 */
describe("the service writes", () => {
    /** A realm as the console's realm create leaves it: holding whatever a fresh realm holds. */
    function realmWith (state, name = "alpha") {
        state.createRealm({ name });
        return `/${name}`;
    }

    const idsOf = (answer) => answer.body.result.map((entry) => entry._id);

    it("gives a created realm the services a recorded fresh realm has", () => {
        // The order-28 recording, and the assertion xui-services.spec.mjs's `openServiceList` makes
        // before it looks at anything else: a realm the console creates has `policyconfiguration`.
        // A realm seeded with nothing fails every test in that spec at its first wait, with a
        // message about a list that did not render.
        const state = baseline();
        const listing = state.realmServicesListing(realmWith(state));

        assert.equal(listing.status, 200);
        assert.deepEqual(listing.body.result,
            [{ _id: "policyconfiguration", name: "Policy Configuration" }]);
    });

    it("offers every type the realm does not have, recomputed on each call", () => {
        // The rule the spec's own structure rests on, and the one a fixed list passes the create
        // test with and fails the test after it: "the create form stops offering a type the realm
        // already has". Recomputed rather than cached, so create and delete both move it.
        const state = baseline();
        const realmPath = realmWith(state);

        const fresh = state.realmCreatableTypes(realmPath);
        assert.equal(fresh.status, 200);
        // Byte-identical to the recording: the catalogue was recorded against a realm holding
        // exactly what a fresh realm holds, so nothing is subtracted from it here.
        assert.deepEqual(fresh.body, recorded(
            "json/realms/root/realms/{realm}/realm-config/services/"
            + "POST.action=getCreatableTypes.json",
        ));
        assert.ok(idsOf(fresh).includes("baseurl"));

        state.createRealmService(realmPath, "baseurl", {});
        const afterCreate = state.realmCreatableTypes(realmPath);
        assert.ok(!idsOf(afterCreate).includes("baseurl"));
        assert.equal(idsOf(afterCreate).length, idsOf(fresh).length - 1);
        assert.ok(idsOf(afterCreate).length > 0, "the other types must still be on offer");

        // And back again, which is what makes the spec idempotent across runs rather than only
        // within one.
        state.deleteRealmService(realmPath, "baseurl");
        assert.deepEqual(idsOf(state.realmCreatableTypes(realmPath)), idsOf(fresh));
    });

    it("leads with a type whose schema and template it can serve", () => {
        // An ordering constraint, and an easy one to break by "tidying" the catalogue into sorted
        // order. The rebuild test picks its second type with
        // `offered.find((candidate) => candidate._id !== "baseurl")` over the *raw* result, then
        // drives the create form onto it -- so whatever is first here must have a recorded schema
        // and template. The console sorts by name for display; the fixture does not.
        const state = baseline();
        const offered = state.realmCreatableTypes(realmWith(state)).body.result;
        const second = offered.find((type) => type._id !== "baseurl");

        for (const action of ["schema", "template"]) {
            assert.notEqual(state.verbatim({
                method: "POST",
                path: `/json/realms/root/realms/{realm}/realm-config/services/${second._id}`,
                query: { _action: action },
            }), undefined, `the rebuild test would ask for ${second._id}'s ${action}`);
        }
    });

    it("merges a create over the template, so a withheld property is still stored", () => {
        // `showOnlyRequiredAndEmpty` means the console posts only the two properties it showed, and
        // the spec then asserts the service reads back with `source: "REQUEST_VALUES"` -- which the
        // console never sent and which is what makes the created service inert. The template is
        // where it comes from.
        const state = baseline();
        const realmPath = realmWith(state);
        const created = state.createRealmService(realmPath, "baseurl", {
            extensionClassName: "",
            fixedValue: "https://created.example.invalid",
        });

        assert.equal(created.status, 201);
        assert.equal(created.body.fixedValue, "https://created.example.invalid");
        assert.equal(created.body.source, "REQUEST_VALUES");
        // Resolved, not the recorded marker: `contextPath` is `/{{CONTEXT}}` in the recording.
        assert.equal(created.body.contextPath, `/${DEPLOYMENT.context}`);
        // The identity the listing, the create form and the edit form's <h1> all read, and which
        // the spec cross-checks against each other. Taken from the catalogue, not composed.
        assert.deepEqual(created.body._type,
            { _id: "baseurl", collection: false, name: "Base URL Source" });
        assert.equal(created.body._id, "");
        assert.deepEqual(state.realmService(realmPath, "baseurl"), { status: 200, body: created.body });
    });

    it("shows a created service in the next listing and a deleted one in neither", () => {
        // specs/ui-local-backend/spec.md, "Deletion is reflected in subsequent reads" -- and its
        // inverse, which the create test asserts by re-opening the list at its end.
        const state = baseline();
        const realmPath = realmWith(state);
        state.createRealmService(realmPath, "baseurl", {});

        assert.deepEqual(state.realmServicesListing(realmPath).body.result, [
            { _id: "policyconfiguration", name: "Policy Configuration" },
            { _id: "baseurl", name: "Base URL Source" },
        ]);

        const deleted = state.deleteRealmService(realmPath, "baseurl");
        // Not the document, unlike a realm delete. Two conventions in one API, both recorded.
        assert.deepEqual(deleted, { status: 200, body: { success: true } });
        assert.deepEqual(state.realmServicesListing(realmPath).body.result,
            [{ _id: "policyconfiguration", name: "Policy Configuration" }]);
        assert.equal(state.realmService(realmPath, "baseurl").status, 404);
    });

    it("persists an update and keeps the identity the URL decided", () => {
        const state = baseline();
        const realmPath = realmWith(state);
        state.createRealmService(realmPath, "baseurl", { fixedValue: "first" });

        // The whole document, as the edit form really sends it back -- and with the identity
        // fields tampered with, which the store must ignore: `_type.name` is the edit form's title
        // and the listing's row text, so a body that changed it would rename the service.
        const updated = state.updateRealmService(realmPath, "baseurl", {
            _id: "not-this",
            _type: { _id: "dashboard", collection: true, name: "Not This" },
            contextPath: "/openam",
            extensionClassName: null,
            fixedValue: "https://edited.example.invalid",
            source: "REQUEST_VALUES",
        });

        assert.equal(updated.status, 200);
        assert.equal(updated.body.fixedValue, "https://edited.example.invalid");
        assert.equal(updated.body._id, "");
        assert.deepEqual(updated.body._type,
            { _id: "baseurl", collection: false, name: "Base URL Source" });
        assert.equal(state.realmService(realmPath, "baseurl").body.fixedValue,
            "https://edited.example.invalid");
        assert.deepEqual(state.realmServicesListing(realmPath).body.result.at(-1),
            { _id: "baseurl", name: "Base URL Source" });
    });

    it("keeps the identity the URL decided on a create too, not only on an update", () => {
        // The same guard as the test above, on the other write. It is asserted separately because
        // the two build their document differently -- the update merges over what is stored, the
        // create over the recorded template -- so one of them holding the line says nothing about
        // the other. A create whose body renamed the type would file the instance under the type in
        // the URL while the listing rendered it as something else, leaving a row whose edit link
        // 404s: the same broken console the update test is guarding against, one write earlier.
        const state = baseline();
        const realmPath = realmWith(state);
        const created = state.createRealmService(realmPath, "baseurl", {
            _id: "not-this",
            _type: { _id: "dashboard", collection: true, name: "Not This" },
            fixedValue: "https://created.example.invalid",
        });

        assert.equal(created.status, 201);
        assert.equal(created.body._id, "");
        assert.deepEqual(created.body._type,
            { _id: "baseurl", collection: false, name: "Base URL Source" });
        // And the instance really is under the type the URL named, not the one the body asked for.
        assert.deepEqual(state.realmServicesListing(realmPath).body.result.at(-1),
            { _id: "baseurl", name: "Base URL Source" });
        assert.equal(state.realmService(realmPath, "dashboard").status, 404);
        // Where the recording puts them, which a spread would otherwise decide by insertion order.
        assert.deepEqual(Object.keys(created.body).slice(0, 2), ["_id", "_type"]);
    });

    it("does not let two realms share a template's own mutable values", () => {
        // `capture.body` caches, so every caller of a template gets the same object back. A shallow
        // merge would therefore hand two realms the same array: `dashboard`'s only property is one.
        // Nothing writes through such a reference today, which is exactly why this is pinned here --
        // the aliasing would be invisible until something did, and then it would look like a bug in
        // whatever wrote rather than in the create that shared.
        const state = baseline();
        const alpha = realmWith(state, "alpha");
        const beta = realmWith(state, "beta");
        const first = state.createRealmService(alpha, "dashboard", {});
        const second = state.createRealmService(beta, "dashboard", {});

        assert.equal(first.status, 201);
        assert.deepEqual(first.body.assignedDashboard, second.body.assignedDashboard);
        assert.notEqual(first.body.assignedDashboard, second.body.assignedDashboard);

        first.body.assignedDashboard.push("written-through");
        assert.deepEqual(state.realmService(beta, "dashboard").body.assignedDashboard, [""]);
        // And the baseline the next create reads from is still the recorded one.
        assert.deepEqual(
            state.createRealmService(realmWith(state, "gamma"), "dashboard", {}).body
                .assignedDashboard,
            [""],
        );
    });

    it("overwrites a service the realm already has, following createRealm's precedent", () => {
        // Not modelled, deliberately: AM answers 409 and this answers 201. The console cannot make
        // this request -- the create form only offers what `getCreatableTypes` returned, and that
        // subtracts what the realm holds -- so the status is pinned here rather than invented to
        // match AM. What matters is what it does *not* do: leave a second row, or a row whose type
        // came from the second body.
        const state = baseline();
        const realmPath = realmWith(state);
        state.createRealmService(realmPath, "baseurl", { fixedValue: "first" });
        const again = state.createRealmService(realmPath, "baseurl", { fixedValue: "second" });

        assert.equal(again.status, 201);
        assert.equal(state.realmService(realmPath, "baseurl").body.fixedValue, "second");
        assert.deepEqual(state.realmServicesListing(realmPath).body.result, [
            { _id: "policyconfiguration", name: "Policy Configuration" },
            { _id: "baseurl", name: "Base URL Source" },
        ]);
    });

    it("does not let two realms share the services of one", () => {
        // The seeded documents are cloned per realm, for the reason the authentication document is:
        // every test in xui-services.spec.mjs gets a scratch realm of its own precisely so that one
        // cannot affect another, and a shared object would defeat that inside a single run.
        const state = baseline();
        const alpha = realmWith(state, "alpha");
        const beta = realmWith(state, "beta");

        state.createRealmService(alpha, "baseurl", { fixedValue: "alpha's" });

        assert.equal(state.realmService(beta, "baseurl").status, 404);
        assert.ok(!idsOf(state.realmCreatableTypes(alpha)).includes("baseurl"));
        assert.ok(idsOf(state.realmCreatableTypes(beta)).includes("baseurl"));

        state.updateRealmService(alpha, "policyconfiguration", { marker: true });
        assert.ok(!Object.hasOwn(state.realmService(beta, "policyconfiguration").body, "marker"));
    });

    it("answers a service write to a realm that is not there with AM's own message", () => {
        const state = baseline();

        for (const answer of [
            state.realmCreatableTypes("/gone"),
            state.createRealmService("/gone", "baseurl", {}),
            state.updateRealmService("/gone", "baseurl", {}),
            state.deleteRealmService("/gone", "baseurl"),
        ]) {
            assert.equal(answer.status, 404);
            assert.deepEqual(answer.body,
                { code: 404, message: "Realm cannot be read: /gone", reason: "Not Found" });
        }
    });

    it("answers a service the realm does not have without naming it, as recorded", () => {
        // AM does not name the service it could not find here, unlike the realm case. `readService`
        // in common/services-commons.mjs reads this 404 as null, which is what the delete tests
        // assert and what the create test's precondition rests on.
        const state = baseline();
        const realmPath = realmWith(state);

        for (const answer of [
            state.updateRealmService(realmPath, "baseurl", {}),
            state.deleteRealmService(realmPath, "baseurl"),
            state.realmService(realmPath, "baseurl"),
        ]) {
            assert.deepEqual(answer, {
                status: 404,
                body: recorded("json/realm-config/services/baseurl/GET.404.json"),
            });
        }
    });

    it("refuses to create a type it could not have generated a form for", () => {
        // `undefined` is the labelled 501, not a 404: a type with no recorded schema is a request
        // outside the capture's scope rather than a resource that is missing. The same answer
        // `_action=schema` already gives for it, so a type cannot become creatable through a form
        // this server could not have produced.
        const state = baseline();
        const realmPath = realmWith(state);

        assert.equal(state.createRealmService(realmPath, "audit", {}), undefined);
        assert.equal(state.createRealmService(realmPath, "notAType", {}), undefined);
        assert.deepEqual(state.realmServicesListing(realmPath).body.result,
            [{ _id: "policyconfiguration", name: "Policy Configuration" }]);
    });
});

describe("both path shapes reach one resource", () => {
    // REQUESTS.md §2: the XUI produces the realm-scoped form and the fixtures the legacy one, both
    // in the same run, so a server that routes only one cannot let the specs provision themselves.
    const cases = [
        [
            "/json/realms/root/realms/alpha/realm-config/services/baseurl", {},
            "/json/realm-config/services/baseurl", { realm: "/alpha" },
        ],
        [
            "/json/realms/root/realm-config/services", {},
            "/json/realm-config/services", { realm: "/" },
        ],
    ];

    for (const [scopedPath, scopedQuery, legacyPath, legacyQuery] of cases) {
        it(`${scopedPath} and ${legacyPath}`, () => {
            const scoped = parseRoute(scopedPath, scopedQuery);
            const legacy = parseRoute(legacyPath, legacyQuery);
            assert.equal(legacy.kind, scoped.kind);
            assert.equal(legacy.realmPath, scoped.realmPath);
            assert.equal(legacy.serviceId, scoped.serviceId);
        });
    }

    it("treats an absent realm parameter as root", () => {
        assert.equal(parseRoute("/json/realm-config/authentication", {}).realmPath, "/");
    });

    it("leaves the chains and modules endpoints unrouted", () => {
        // Every spec that uses them is tagged @deployed-am, so they are out of scope by
        // construction rather than merely unimplemented.
        assert.equal(
            parseRoute("/json/realms/root/realm-config/authentication/modules", {}).kind,
            "other",
        );
    });
});
