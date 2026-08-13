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
 * The baseline state, built from the capture at startup — and the reads answered out of it.
 *
 * D15: the capture pins response *shapes*; this holds the *content*. The server is not a replayer.
 * A read renders a response from what the store currently holds, so a realm created through the
 * console in task 2.10 appears in the next listing — which replay cannot express, and which
 * specs/ui-local-backend/spec.md requires under "Creation is reflected in subsequent reads".
 *
 *     capture/ ── recorded from the real AM ──▶ baseline state ──▶ in-memory store ──▶ responses
 *
 * ## The baseline is the recording's *first* observation of each resource
 *
 * capture/README.md: the capture is a transcript in capture order, and that order is load-bearing.
 * It records a realm being created, read, updated and deleted; a baseline built from the wrong end
 * of that sequence would carry a realm no reset instance has — "a permanent phantom in the
 * baseline the local server is built from", which the README warns re-recorders about and which
 * applies exactly as much to this loader.
 *
 * So each source below is the call recorded *before* the first mutation of its resource, and the
 * one that could silently poison the whole tree — the realm listing — is asserted to precede the
 * create rather than trusted to. The consequence is worth stating plainly: **the baseline holds
 * the root realm and nothing else.** Every realm-scoped route answers 404 until task 2.10 can
 * create one, and the capture's own recorded realm 404 — order 22, the probe taken before the
 * create — is what that agrees with. Note it is the *only* one it agrees with: the other recorded
 * 404, order 34, was taken after the realm existed and reports a missing *service* inside it, so
 * against this baseline that request answers "Realm cannot be read" instead. Both are correct for
 * the state they are answered from, which is the point of not replaying them.
 *
 * ## What is served verbatim, and why only this
 *
 * Every payload served verbatim is one that cannot reflect a write, so the list is kept to the one
 * category where that is not a defect: **the SMS schema and template documents** — the 7
 * `_action=schema` and 4 `_action=template` responses. They describe what a service *is* — the
 * fields, types and ranges the console generates its administrative forms from — rather than
 * recording what any instance of it currently holds. Nothing a write can do changes them, so
 * deriving them from state would be modelling a document that does not vary.
 *
 * That is the whole list, and it is *narrower* than the capture's own. capture/README.md puts the
 * verbatim-servable set at "every `_action=schema` (7), every `_action=template` (4),
 * `_action=getAllTypes` (1), and the three `serverinfo` responses" — so two of its entries are
 * deliberately left out here:
 *
 *   - `serverinfo` (3 calls) is task 2.9's, and it is *nearly* verbatim rather than verbatim: the
 *     site configuration is served as recorded but for `domains`, which this server decides for
 *     itself because the recorded value names another deployment's cookie domain. See
 *     `SITE_CONFIGURATION_OVERRIDES` below. It is built here rather than added to the verbatim set
 *     so that the one field this server does not agree with has somewhere to be argued.
 *   - `_action=getAllTypes` (1 call, REQUESTS.md's `…/services/baseurl` row) belongs to task 2.11
 *     with the rest of service administration, and answers 501 today.
 *
 * A third, `_action=getCreatableTypes`, is not in the capture's verbatim set either and is left to
 * 2.11 for a stronger reason: the README's "Known limits" records that whether it is
 * state-dependent was never determined — in AM a type should drop out of it once the realm has an
 * instance, which would make serving it verbatim wrong for every realm but the recorded one.
 *
 * The 11 are selected by predicate from `index.json` rather than listed by name, so a re-record
 * that adds a service to the request list gets its schema served without an edit here.
 *
 * ## Shape from the capture, content from state
 *
 * A collection response is rendered from the recorded envelope with `result` replaced: the two
 * listings in the capture do not agree on their paging fields — realms answers
 * `totalPagedResultsPolicy: "NONE"` with `totalPagedResults: -1`, realm services answers `"EXACT"`
 * with the real count — and inventing one convention for both would produce a shape neither AM
 * returns.
 */

import { ADMIN_PASS, ADMIN_USER, PASSWORD, USERNAME } from "../../common/openam-commons.mjs";
import { createAuthState } from "./auth.mjs";
import { captureFileFor, loadCapture } from "./capture-store.mjs";

/**
 * Who can log in, taken from the suite's own constants rather than restated here.
 *
 * The stand-in has to accept exactly the credentials the specs log in with, and those are already
 * declared once — with their environment overrides — in common/openam-commons.mjs, because the
 * deployed instance needs the same two accounts. Importing them is what stops the two copies
 * drifting: a run that points the suite at a different user by exporting `OPENAM_USERNAME` moves
 * this server's directory with it, where a second hardcoded pair would quietly fail every login.
 *
 * The passwords are the container instance's well-known ones, not secrets. This server holds them
 * in memory, compares them in the clear and has no password policy, lockout or expiry — see
 * NOTES-auth.md §9.7 on why lockout in particular must stay absent: xui-login.spec.mjs fails a
 * login as the same user its other tests use, and a stand-in that locked the account would poison
 * every test after it.
 */
const CREDENTIALS = { [USERNAME]: PASSWORD, [ADMIN_USER]: ADMIN_PASS };

/**
 * Where each part of the baseline is read from, and the capture order that makes it the baseline.
 *
 * Named as files rather than searched for, so that a re-record which drops one of these fails at
 * startup naming the file, and so this list can be checked against capture/README.md's resource
 * table by eye.
 */
const BASELINE = {
    /** order 15 — before the create at 23, so this is the realm set of a reset instance. */
    realms: "json/global-config/realms/GET.queryFilter=true.json",
    /** order 20 — root's authentication config; the only PUT in the capture is on another realm. */
    rootAuthentication: "json/realms/root/realm-config/authentication/GET.json",
    /** order 13 — the global REST service; never mutated anywhere in the capture. */
    restService: "json/global-config/services/rest/GET.json",
    /** order 28 — a realm's service listing, kept for its paging envelope only; see below. */
    realmServices: "json/realms/root/realms/{realm}/realm-config/services/GET.queryFilter=true.json",
    /** order 23 — not loaded; its order is what proves `realms` above is pre-mutation. */
    realmCreate: "json/global-config/realms/POST.action=create.json",
    /**
     * order 2 — the site configuration, at the `resource=1.1` the XUI negotiates.
     *
     * The capture holds this document twice, recorded at `resource=1.1` and `resource=1.0`, and the
     * two bodies are byte-identical; AM answered both with `content-api-version: resource=1.1`.
     * rest.mjs's header anticipated task 2.9 as "where honouring the version starts", and the
     * recording says there is nothing here to honour. The one variant that does differ —
     * capture/README.md:99-100, `_id` and `_rev` returned when *no* version is negotiated — is not
     * recorded and is never asked for: the XUI always negotiates. So one file answers both calls,
     * and a server that discriminated on the version would be modelling a difference the recording
     * does not contain.
     */
    siteConfiguration: "json/serverinfo/star/GET.resource=1.1.json",
    /** order 8 — `version`, `revision`, `date`, for the footer of a realm administrator. */
    serverVersion: "json/serverinfo/version/GET.json",
};

/**
 * The fields of `serverinfo/*` this server serves differently from the recording. Exactly one.
 *
 * **`domains: []`, not the recorded `["{{COOKIE_DOMAIN}}"]`.** The recorded array names the cookie
 * domain of the deployment the capture was taken against, and this server is not that deployment:
 * a browser discards a cookie whose `Domain` does not match the origin it came from, so the XUI's
 * own client-side write — `SessionToken.set` → `CookieHelper.setCookie`, which writes once per entry
 * in this array — would be silently dropped. `CookieHelper.setCookie` documents the empty array as
 * the way to ask for a host-only cookie, and that is what this server's `Set-Cookie` already is
 * (rest.mjs `sessionCookie`, which omits `Domain` for the same reason). The two have to agree:
 * `SessionToken.remove()` on logout deletes per domain as well, so a non-empty array here would
 * leave logout unable to delete the host-only cookie the server set.
 *
 * NOTES-auth.md:268-274 argues for `[]` and NOTES-siteconfig.md files it as the one value task 2.9
 * has to *choose* rather than derive. This is that choice, and the symptom of having chosen wrong
 * is worth recognising: a login that appears to work, and a reload that logs you out.
 *
 * It is spelled as an override rather than by giving `{{COOKIE_DOMAIN}}` a value in `deploymentFor`
 * because there is no string that resolves to an empty array — and because a marker resolved to a
 * value nothing serves is exactly what that map's own note refuses to hold.
 */
const SITE_CONFIGURATION_OVERRIDES = { domains: [] };

/** The actions whose responses are pure static description. See the header note. */
const VERBATIM_ACTIONS = ["schema", "template"];

/**
 * An AM error envelope, as recorded. Not served from the capture even though two are recorded:
 * `json/global-config/realms/{realmId}/GET.404.json` puts the realm's own path in its message, so
 * the recorded body is right for exactly one realm and the message has to be built. Those two
 * files are the shape this matches.
 */
function notFound (message) {
    return { code: 404, message, reason: "Not Found" };
}

/** A realm id is unpadded base64url of the realm path — REQUESTS.md §5. `/` is `Lw`. */
export function realmIdFor (realmPath) {
    return Buffer.from(realmPath, "utf8").toString("base64url");
}

/** Only `A-Z a-z 0-9 - _`, so a client's id can be told apart from something that is not one. */
const REALM_ID = /^[A-Za-z0-9_-]+$/;

/**
 * The realm path a realm document is stored under: its `_id` decoded, the inverse of `realmIdFor`.
 *
 * **Not `name`.** Root is the one realm for which the two agree — its `name` is literally `"/"` —
 * and every other realm's `name` is the bare label (`e2e-capture`) while every read here looks a
 * realm up by its *path* (`/e2e-capture`). Keying on `name` therefore works for the committed
 * capture, whose baseline is root alone, and puts any further realm in the store under a key
 * nothing queries: it would list, and 404 at every realm-scoped route. `_id` is the path already,
 * which also makes the store key and the id in the URL inverses of one another — the property
 * task 2.10's create needs.
 */
export function realmPathFor (document) {
    return Buffer.from(document._id, "base64url").toString("utf8");
}

/**
 * The placeholder values this server substitutes into recorded payloads.
 *
 * Deliberately only the four the payloads served here actually contain. A value invented for a
 * placeholder in a payload no route serves is a decision taken where nothing can test it —
 * `{{USER_SUFFIX}}` is the live example: it appears only in `demo`'s user document, whose route is
 * task 2.12's, so 2.12 chooses it when it has a read that would notice a wrong choice.
 * capture-store.mjs throws on any placeholder missing from this map, which is what stops that
 * deferral turning into a marker served to the browser.
 */
function deploymentFor ({ context, hostname }) {
    return {
        CONTEXT: context,
        HOSTNAME: hostname,
        // The config store's LDAP suffix, which task 2.8 needs because it is in the distinguished
        // name every resolved session reports (`dn`, `universalId`). Not a choice: it is the value
        // the recording had stripped out of it, and both ends of that stripping are in this
        // repository -- openam-up.sh sets `ROOT_SUFFIX` to it when it brings the container up, and
        // capture-lib/normalise.mjs's LDAP_SUFFIXES maps that exact string to the placeholder. The
        // user store's suffix is a *different* one, which is why this resolves only the one it can
        // account for.
        CONFIG_SUFFIX: "dc=openam,dc=openidentityplatform,dc=org",
        // The bare first label, as the recording's rule took it from the AM host's FQDN -- but
        // only where the host *has* labels. This server's default bind address is 127.0.0.1, and
        // splitting an address on its dots yields "127", which would go into the root realm's
        // aliases as a host no browser will ever send. An address is its own alias.
        HOST_ALIAS: isAddressLiteral(hostname) ? hostname : hostname.split(".")[0],
    };
}

/** An IPv4 or IPv6 literal, as opposed to a host name with labels. */
function isAddressLiteral (hostname) {
    return /^[\d.]+$/.test(hostname) || hostname.includes(":");
}

/**
 * Build the baseline.
 *
 * `hostname` is how the XUI reaches this server, which is what the root realm's aliases have to
 * agree with: AM matches an incoming host against them to resolve the realm, and task 1.9's
 * theme-by-realm specs are the ones that would notice a mismatch.
 */
export function buildBaselineState (captureDir, { context, hostname }) {
    const capture = loadCapture(captureDir, deploymentFor({ context, hostname }));

    // The one ordering assumption worth proving rather than trusting: if a re-record ever put the
    // realm listing after the create, the baseline would gain a realm that no reset AM has, and
    // every realm test would start from a state the deployed instance never reaches.
    const listedAt = capture.order(BASELINE.realms);
    const createdAt = capture.order(BASELINE.realmCreate);
    if (!(listedAt < createdAt)) {
        throw new Error(
            `${BASELINE.realms} is recorded at order ${listedAt}, after the realm create at `
            + `${createdAt}. The baseline is meant to be the realm set of a reset AM, and this `
            + "recording's listing already contains a realm the capture itself created.",
        );
    }

    const realmsListing = capture.body(BASELINE.realms);
    const realms = new Map();
    for (const document of realmsListing.result) {
        const realmPath = realmPathFor(document);
        realms.set(realmPath, {
            document,
            // Root's is recorded; a realm task 2.10 creates gets its own, for which the capture's
            // order-25 read of the created realm is the prototype.
            authentication: realmPath === "/"
                ? capture.body(BASELINE.rootAuthentication)
                : undefined,
            // Empty because the capture records no service listing for root, not because AM's root
            // realm has no services: no spec asks for one, so the request list task 2.1 fixed as
            // this server's scope does not contain it (REQUESTS.md has only the
            // `/realms/root/realms/<realm>/realm-config/services` form). A realm created in 2.10
            // is seeded from the order-28 listing, where a fresh realm has `policyconfiguration`.
            services: new Map(),
        });
    }

    const globalServices = new Map([["rest", capture.body(BASELINE.restService)]]);

    // Shape only. `result` is always rendered from state; these supply the paging fields, which
    // differ between the two collections.
    const listingEnvelopes = {
        realms: realmsListing,
        realmServices: capture.body(BASELINE.realmServices),
    };

    const statics = new Map(capture.filesForActions(VERBATIM_ACTIONS)
        .map((file) => [file, capture.body(file)]));

    // The bootstrap document. Held as one built object rather than in the store, because nothing a
    // write can do changes it: the flags describe what this deployment *is*, and the two that a
    // spec could otherwise expect to move — `realm` and `cookieName` — are the two the rest of the
    // server is already keyed to. If a later task needs a flag to vary per run, this is the value
    // to make configurable, not the document to make mutable.
    const siteConfiguration = capture.bodyWith(BASELINE.siteConfiguration,
        SITE_CONFIGURATION_OVERRIDES);
    const serverVersion = capture.body(BASELINE.serverVersion);

    // Built from the same capture handle and returned as part of the same state, so the sessions
    // and in-flight logins of task 2.7 are cleared by whatever clears the rest of the store.
    const auth = createAuthState(capture, { credentials: CREDENTIALS });

    return createState({
        realms, globalServices, listingEnvelopes, statics, auth, siteConfiguration, serverVersion,
    });
}

/**
 * Render a collection response: the recorded envelope, with the result set and the counts derived
 * from it. `totalPagedResults` is recomputed only under an `EXACT` policy — under `NONE` the
 * recorded `-1` is the answer, and computing a count there would report a total AM does not claim.
 */
function renderListing (envelope, result) {
    return {
        ...envelope,
        result,
        resultCount: result.length,
        ...(envelope.totalPagedResultsPolicy === "EXACT"
            ? { totalPagedResults: result.length }
            : {}),
    };
}

/**
 * The reads, over the store.
 *
 * Every accessor returns `{status, body}` so the HTTP layer stays free of resource knowledge: what
 * is missing, and what AM says when it is, is a property of the resource and belongs here.
 *
 * The store is exposed as `realms` / `globalServices` because tasks 2.10-2.13 mutate it. It is
 * mutable on purpose: that mutability is the whole difference between this and a replayer.
 *
 * **A document in the store is the object the loader cached, not a copy of it.** That is safe only
 * because `buildBaselineState` opens the capture afresh each time it is called, so a state that has
 * been written to shares nothing with the next one. Task 2.13's reset therefore has to go back
 * through `buildBaselineState` rather than hold a `loadCapture` handle and re-read from it — reusing
 * one would hand the new state documents an earlier state had already mutated in place.
 */
function createState ({
    realms, globalServices, listingEnvelopes, statics, auth, siteConfiguration, serverVersion,
}) {
    return {
        realms,
        globalServices,
        /** The authentication exchange and the sessions it establishes; see auth.mjs. */
        auth,

        /**
         * `GET /json/serverinfo/*` — the site configuration, and the first request the XUI makes.
         *
         * Everything the bootstrap does is chained off this one answering: `SiteConfigurator` fires
         * `EVENT_APP_INITIALIZED` on success *and* on failure, so a server that got this wrong
         * would not produce an error screen but a plausible login page with no session behind it
         * (NOTES-siteconfig.md, "If the whole request fails"). That is why it is served from the
         * recording rather than assembled: the failure mode is invisible, so the fixture has to be
         * right by construction rather than by inspection.
         *
         * Only the bare path. The realm-scoped shape the XUI builds from a `?realm=` URL parameter
         * — `/json/realms/root/realms/<realm>/serverinfo/*` — is not recorded (REQUESTS.md:151-152
         * files it out of scope; only xui-theming reaches it, and that spec is `@deployed-am`) and
         * is deliberately left as a labelled 501 rather than answered with a realm this server made
         * up. See rest.mjs `parseRoute`.
         */
        siteConfiguration () {
            return { status: 200, body: siteConfiguration };
        },

        /**
         * `GET /json/serverinfo/version` — the footer's version line.
         *
         * Not part of the bootstrap: `Footer.render` fetches it only for a user with
         * `ui-realm-admin`, so it is reached by the administrator login and by nothing before a
         * session exists. Served exactly as recorded, `version`/`revision`/`date` included —
         * capture/README.md:235-238 leaves those un-normalised on purpose, so that task 2.15's
         * re-record-and-diff goes red when the container image is rebuilt. Nothing reads them for
         * behaviour.
         *
         * Answered without a session, where the recording had one: capture/index.json marks this
         * call `"session": "admin"` and REQUESTS.md lists it session- and admin-required, against
         * `serverinfo/*`'s "optional". Nothing under test notices, because its only caller is
         * behind `ui-realm-admin` already — and gating it here would be this server inventing an
         * authorisation rule rather than reproducing one, which is how a local backend starts
         * disagreeing with AM in the direction nobody checks. It is still a divergence, so it is
         * written down. Same treatment as serveLogout's in rest.mjs.
         */
        serverVersion () {
            return { status: 200, body: serverVersion };
        },

        /** `GET /json/global-config/realms?_queryFilter=true` */
        realmsListing () {
            const result = [...realms.values()].map((realm) => realm.document);
            return { status: 200, body: renderListing(listingEnvelopes.realms, result) };
        },

        /** `GET /json/global-config/realms/{realmId}` */
        realmById (realmId) {
            for (const realm of realms.values()) {
                if (realm.document._id === realmId) {
                    return { status: 200, body: realm.document };
                }
            }
            // AM names the realm it could not read, so the message is built from the id rather
            // than taken from the recorded 404, which names the realm that recording created.
            // Checked rather than decoded blindly: Node's base64url decoder does not reject a
            // string that is not base64url, it discards what it cannot use, so an id like `@@@`
            // would otherwise be reported back as the mojibake it decodes to.
            const realmPath = REALM_ID.test(realmId)
                ? Buffer.from(realmId, "base64url").toString("utf8")
                : realmId;
            return { status: 404, body: notFound(`Realm cannot be read: ${realmPath}`) };
        },

        /** `GET /json/global-config/services/{id}` */
        globalService (serviceId) {
            const document = globalServices.get(serviceId);
            return document
                ? { status: 200, body: document }
                : { status: 404, body: notFound("Not Found") };
        },

        /** `GET /json/realms/root[/realms/{realm}]/realm-config/authentication` */
        realmAuthentication (realmPath) {
            const realm = realms.get(realmPath);
            if (!realm?.authentication) {
                return { status: 404, body: notFound(`Realm cannot be read: ${realmPath}`) };
            }
            return { status: 200, body: realm.authentication };
        },

        /** `GET …/realm-config/services?_queryFilter=true` */
        realmServicesListing (realmPath) {
            const realm = realms.get(realmPath);
            if (!realm) {
                return { status: 404, body: notFound(`Realm cannot be read: ${realmPath}`) };
            }
            // A listing entry is the instance's type identity, not the instance: the capture's
            // entries are `{_id, name}` while the instance document carries its settings under a
            // `_type` of the same two fields.
            const result = [...realm.services.values()]
                .map((document) => ({ _id: document._type._id, name: document._type.name }));
            return { status: 200, body: renderListing(listingEnvelopes.realmServices, result) };
        },

        /** `GET …/realm-config/services/{id}` */
        realmService (realmPath, serviceId) {
            const realm = realms.get(realmPath);
            if (!realm) {
                return { status: 404, body: notFound(`Realm cannot be read: ${realmPath}`) };
            }
            const document = realm.services.get(serviceId);
            // As recorded in json/realm-config/services/baseurl/GET.404.json: AM does not name the
            // service it could not find here, unlike the realm case above.
            return document
                ? { status: 200, body: document }
                : { status: 404, body: notFound("Not Found") };
        },

        /**
         * A schema or template document, served verbatim. `undefined` means this request is not
         * one of the 11 — the HTTP layer answers 501, because an unrecorded schema is a request
         * outside the capture's scope rather than a resource that is missing.
         */
        verbatim (request) {
            return statics.get(captureFileFor(request));
        },
    };
}
