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
        "json/realms/root/realms/{realm}/realm-config/services/GET.queryFilter=true.json": {
            ...paging,
            result: [],
            resultCount: 0,
            totalPagedResults: 0,
            totalPagedResultsPolicy: "EXACT",
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

describe("the payloads served verbatim", () => {
    it("is exactly the schema and template documents", () => {
        // Every payload served verbatim is one that cannot reflect a write, so the list is meant
        // to stay at the SMS documents that describe a service rather than record its state. This
        // is what would notice it growing.
        const state = baseline();
        // No bodies are read here, so the deployment map is irrelevant to the selection.
        const served = loadCapture(CAPTURE_DIR, {}).filesForActions(["schema", "template"]);
        assert.equal(served.length, 11);
        assert.equal(served.filter((file) => file.includes("action=schema")).length, 7);
        assert.equal(served.filter((file) => file.includes("action=template")).length, 4);
        assert.notEqual(state.verbatim({
            method: "POST",
            path: "/json/global-config/realms",
            query: { _action: "schema" },
        }), undefined);
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
            .filter((call) => ["schema", "template"].includes(call.query?._action));

        assert.equal(documents.length, 11);
        for (const call of documents) {
            const route = parseRoute(call.path, call.query);
            assert.equal(
                captureFileFor({ method: call.method, path: route.routePath, query: call.query }),
                call.file,
            );
        }
    });

    it("does not serve an action outside the list", () => {
        // getCreatableTypes is task 2.11's: capture/README.md's "Known limits" records that
        // whether it is state-dependent was never determined.
        assert.equal(baseline().verbatim({
            method: "POST",
            path: "/json/realms/root/realms/{realm}/realm-config/services",
            query: { _action: "getCreatableTypes" },
        }), undefined);
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
