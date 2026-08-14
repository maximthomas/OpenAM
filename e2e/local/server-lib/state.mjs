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
 * category where that is not a defect: **the SMS description documents** — the 7 `_action=schema`,
 * 4 `_action=template` and 1 `_action=getAllTypes` responses. They describe what a service *is* —
 * the fields, types and ranges the console generates its administrative forms from, and the
 * sub-schema types it decides whether to draw a tab bar for — rather than recording what any
 * instance of it currently holds. Nothing a write can do changes them, so deriving them from state
 * would be modelling a document that does not vary.
 *
 * That is the whole list, and it is *narrower* than the capture's own. capture/README.md puts the
 * verbatim-servable set at "every `_action=schema` (7), every `_action=template` (4),
 * `_action=getAllTypes` (1), and the three `serverinfo` responses" — so one of its entries is
 * deliberately left out here:
 *
 *   - `serverinfo` (3 calls) is task 2.9's, and it is *nearly* verbatim rather than verbatim: the
 *     site configuration is served as recorded but for `domains`, which this server decides for
 *     itself because the recorded value names another deployment's cookie domain. See
 *     `SITE_CONFIGURATION_OVERRIDES` below. It is built here rather than added to the verbatim set
 *     so that the one field this server does not agree with has somewhere to be argued.
 *
 * `_action=getCreatableTypes` is not in the capture's verbatim set either, and task 2.11 is where
 * the README's "Known limits" question about it gets closed rather than inherited. It **is**
 * state-dependent: `SmsRouteTree.handleAction` dispatches it to `readTypes(context,
 * NOT_CREATED_SINGLETONS, forUI)`, whose predicate reads each singleton in the realm and includes
 * the type only when that read 404s. Serving the recorded answer verbatim would therefore be wrong
 * for every realm but the recorded one — and wrong in the direction that matters, because
 * xui-services.spec.mjs asserts a type stops being offered once the realm has it. So the recorded
 * body is loaded as a *catalogue* and the answer is recomputed per call; see `realmCreatableTypes`.
 *
 * The 12 verbatim payloads are selected by predicate from `index.json` rather than listed by name,
 * so a re-record that adds a service to the request list gets its schema served without an edit
 * here.
 *
 * ## What task 2.11 does not serve
 *
 * **Sub-schemas.** `baseurl` has none, xui-services.spec.mjs never opens a sub-schema screen — it
 * asserts the absence of the tab bar that would lead to one — and NOTES-sms.md confirms the six
 * sub-schema endpoints are never called. `parseRoute` leaves `…/services/{type}/{sub}` at the
 * labelled 501, which is what "nothing asks for this" has meant everywhere else in this server. The
 * one sub-schema-adjacent call that *is* made is `_action=getAllTypes`, which
 * `EditSchemaComponent.render` fans out on every edit-form render regardless; it is in the verbatim
 * set above, answering the recorded `{"result":[]}`.
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
    /**
     * order 17 — the defaults AM itself declares for a new realm, and the reason `createRealm`
     * invents none of them. `{active: true, parentPath: "/"}`: a create body that omits either gets
     * the value the console's own new-realm form would have been pre-filled with, because it is the
     * same document the form takes its defaults from (`SMSServiceUtils.schemaWithDefaults`).
     */
    realmTemplate: "json/global-config/realms/POST.action=template.json",
    /** order 20 — root's authentication config; the only PUT in the capture is on another realm. */
    rootAuthentication: "json/realms/root/realm-config/authentication/GET.json",
    /**
     * order 25 — a *created* realm's authentication config, and the document every realm task 2.10
     * creates starts life holding.
     *
     * The order is the whole reason this file and not the PUT at 27: 25 is the read AM answered for
     * a realm that had just been created and never written to, which is exactly the state a realm
     * created through the console is in. Reading 27's would seed every new realm with the edit that
     * recording happened to make.
     */
    createdRealmAuthentication:
        "json/realms/root/realms/{realm}/realm-config/authentication/GET.json",
    /** order 13 — the global REST service; never mutated anywhere in the capture. */
    restService: "json/global-config/services/rest/GET.json",
    /**
     * order 28 — a realm's service listing, for its paging envelope *and* for its contents.
     *
     * Both halves are load-bearing, and the second is task 2.11's. Recorded at 28, before the
     * service create at 35, so this is what a realm holds the moment it exists rather than what the
     * recording went on to put in it: exactly `policyconfiguration`. A realm created through the
     * console is seeded from it (see `realmPrototype`), which is the half task 2.10 deferred here
     * because no read it implemented could tell an empty realm from a seeded one.
     *
     * xui-services.spec.mjs can. `openServiceList` waits for the `policyconfiguration` row before
     * asserting anything else, on the reasoning that "the row I am looking for is absent" is equally
     * true of a list that never rendered — so against a realm seeded with nothing, every test in
     * that spec fails at its first assertion with a message about the wrong thing.
     */
    realmServices: "json/realms/root/realms/{realm}/realm-config/services/GET.queryFilter=true.json",
    /**
     * order 29 — the service types a realm may still be given, and the catalogue every answer to
     * `_action=getCreatableTypes` is recomputed from.
     *
     * Also recorded before the create at 35, and against the same realm as the listing above, which
     * is what makes the two consistent: this is the answer for a realm holding
     * `policyconfiguration`, so `policyconfiguration` is the one type absent from its 19 entries.
     * Serving `catalogue − what the realm holds` therefore reproduces this recording byte for byte
     * for a freshly created realm, without this server having to decide whether the type is missing
     * because the realm has it or because it is `hiddenFromUI` — a question NOTES-sms.md records as
     * untraced and which no request in scope can distinguish.
     *
     * An entry is `{_id, collection, name}`, which is also exactly the `_type` an instance document
     * carries. `createRealmService` takes it from here rather than composing one, so the display
     * name the create form offered, the one the listing renders and the one the edit form puts in
     * its `<h1>` cannot come apart — the spec cross-checks all three against this single string.
     */
    realmServiceTypes:
        "json/realms/root/realms/{realm}/realm-config/services/POST.action=getCreatableTypes.json",
    /**
     * order 39 — what a service delete answers, read rather than written out.
     *
     * Sixteen bytes that could not plausibly drift, and taken from the recording anyway for the
     * reason `capture-store.mjs` gives about the cookie name: a value this server can read is a
     * value it does not get to decide. The type is incidental — a delete answers the same
     * `{"success": true}` whichever instance it removed, and `baseurl` is simply the one instance
     * the capture ever deletes.
     */
    serviceDelete: "json/realms/root/realms/{realm}/realm-config/services/baseurl/DELETE.json",
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
    /**
     * order 11 — the administrator's profile, and the read that decides whether a browser ever
     * lands anywhere.
     *
     * Loaded early by task 2.10, which cannot be verified without it:
     * `RESTLoginHelper.getLoggedUser` fetches it as the last step of a login and puts it on
     * `Configuration.loggedUser`; the `roles` it carries — `ui-global-admin`, `ui-realm-admin` —
     * are what every admin route in `RealmsRoutes.js` is gated on, so without it a completed
     * authentication leaves the browser on `#login` and no console spec can run at all.
     *
     * **Recorded through the administrator's own session, which is why it carries `roles` at all.**
     * That is the half of this document that is not a plain read of a directory entry, and
     * `profileFor` below is where the two halves are separated.
     */
    adminProfile: "json/realms/root/users/amadmin/GET.json",
    /**
     * order 47 — the end user's profile, and the record xui-profile.spec.mjs reads, edits and
     * restores.
     *
     * Recorded through the *administrator's* session, not the end user's, which is the whole reason
     * it carries no `roles` key where the document above carries two: `roles` is virtual on this
     * resource and depends on who is asking. See `profileFor`.
     *
     * Recorded at 47 rather than at the GET that precedes the PUT because there is no such GET —
     * capture/index.json is explicit that the read is taken *after* the write, since the PUT adds a
     * `modifyTimestamp` key that never goes away and reading first would record one shape on a fresh
     * instance and another on every later run. So this is a document that has been written to once,
     * with the recording's own values put back; the four attributes that PUT sent are the four it
     * had already.
     */
    demoProfile: "json/realms/root/users/demo/GET.json",
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
const VERBATIM_ACTIONS = ["schema", "template", "getAllTypes"];

/**
 * A recorded `_action=template` that belongs to a *service type*, capturing which type.
 *
 * `filesForActions(["template"])` also finds the realm template at
 * `json/global-config/realms/POST.action=template.json`, which is a different resource entirely, and
 * would find a sub-schema's template — `…/services/{type}/{sub}/POST.action=template.json` — if one
 * were ever recorded. Requiring the action to sit directly below a single segment under `services/`
 * excludes both, so the map this builds holds service types and only service types.
 */
const SERVICE_TEMPLATE_FILE = /\/realm-config\/services\/([^/]+)\/POST\.action=template\.json$/;

/**
 * An AM error envelope, as recorded. Not served from the capture even though two are recorded:
 * `json/global-config/realms/{realmId}/GET.404.json` puts the realm's own path in its message, so
 * the recorded body is right for exactly one realm and the message has to be built. Those two
 * files are the shape this matches.
 */
function notFound (message) {
    return { code: 404, message, reason: "Not Found" };
}

/**
 * The same envelope for a request this server cannot act on at all.
 *
 * Not recorded: the capture holds no 400, because nothing the capture tool or the console sends is
 * malformed. It is the shape of the two recorded 404s with the status changed, which is as close to
 * the recording as an unrecorded status can be — and it is reachable only by a client that sent a
 * realm with no name, which is not a request the console can produce.
 */
function badRequest (message) {
    return { code: 400, message, reason: "Bad Request" };
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

/** The realm every AM has. Its path, its `name`, and the parent of everything created below it. */
const TOP_LEVEL_REALM = "/";

/**
 * The path a realm gets from its name and its parent's path — `RealmsService.getRealmPath`'s rule,
 * which is the console's and the fixtures' both (`realmPathOf` in common/realms-commons.mjs).
 *
 * A child of the top level realm is `/name` rather than `//name`, and that single special case is
 * the whole of it. It is restated here rather than derived because the store key and the id the
 * console addresses a realm by have to be the same string as the one the browser computed, and the
 * browser computed it with this rule.
 */
function realmPathOf (name, parentPath) {
    return parentPath === TOP_LEVEL_REALM ? `${TOP_LEVEL_REALM}${name}` : `${parentPath}/${name}`;
}

/**
 * Whether a property of an SMS service document is one of the named blocks its `_action=schema`
 * declares — `general`, `security` and the rest — rather than the `_id` and `_type` metadata AM
 * carries beside them. Underscore-prefixed is the whole distinction, and it matters because `_type`
 * holds a `name` of its own that a value routed by key alone would otherwise land in.
 */
function isSection (name, value) {
    return !name.startsWith("_") && value !== null && typeof value === "object"
        && !Array.isArray(value);
}

/**
 * The roles a self-read reports for an account whose recorded document carries none.
 *
 * **The one value in this file that neither REQUESTS.md nor the capture supplies.** Both recorded
 * reads of `demo` were made through the administrator's session, so the recording holds no example
 * of what AM answers a user reading their own profile and there is nothing here to derive it from.
 * It is taken instead from what consumes it: commons' `UserRoutesConfig` declares
 * `role: "ui-self-service-user"` on the `profile/?` route, and `Router` refuses a route whose role
 * is not in `uiroles`, so this is the string that has to be here for an end user to reach their own
 * profile at all.
 *
 * `ui-user` is deliberately not listed — `UserModel.parse` appends it to `uiroles` itself, and a
 * server that also sent it would be answering a question the client already answers.
 *
 * A divergence worth knowing about rather than hiding: a real AM computes this set per user, and
 * this server states it. D15 says these rules are ours and can be wrong; this is one of them.
 */
const SELF_SERVICE_ROLES = ["ui-self-service-user"];

/** A recorded value that *is* the recorded account's name, as a directory compares the two. */
function isName (value, recordedName) {
    return typeof value === "string" && value.toLowerCase() === recordedName.toLowerCase();
}

/**
 * A recorded distinguished name with the value of its first component replaced.
 *
 * The same rule as `principalIn` in auth.mjs, which rebuilds the two DNs a *session* reports, and
 * for the same reason: only the first component names the principal, so rewriting it keeps the
 * directory layout around it — `ou=people`, `ou=user`, and the two different LDAP suffixes — from
 * the recording rather than restating values that are plausible to invent and wrong. It is
 * restated here rather than shared because auth.mjs belongs to tasks 2.7 and 2.8, and this task
 * does not edit an approved one. The attribute type is carried through the replacement because a
 * profile's `dn` begins `uid=` where a session's `universalId` begins `id=`.
 *
 * The replacement is a function rather than a string for auth.mjs's reason: `String.replace` reads
 * `$&`, `` $` `` and `$1` out of a string one, and the name arrives from `OPENAM_USERNAME`.
 */
function principalDn (recordedDn, username) {
    return recordedDn.replace(/^([A-Za-z]+)=[^,]*/,
        (_whole, attribute) => `${attribute}=${username}`);
}

/**
 * A profile as this server holds it: `{username, document, selfRoles}`.
 *
 * **`roles` is split off the document because it is virtual on this resource and depends on who is
 * asking**, and the capture proves that in both directions at once. `amadmin`'s document was
 * recorded through `amadmin`'s own session and carries `ui-global-admin` and `ui-realm-admin`;
 * `demo`'s was recorded through the administrator's and carries no `roles` key at all. One rule
 * reproduces both recordings: a read carries `roles` when the reader is the subject, and omits the
 * key entirely when it is not. See `readAs`.
 *
 * That rule is also what xui-profile.spec.mjs cannot run without. `UserModel.parse` turns `roles`
 * into `uiroles`, `AMConfig`'s default-route handler sends anyone holding `ui-realm-admin` to the
 * console, and commons' `Router` gates `profile/?` on `ui-self-service-user` — so a server that
 * answered every reader the recorded administrator document would land the end user in the console,
 * and one that answered every reader the recorded `demo` document would leave them nowhere at all.
 *
 * The rest of the work here is the **per-principal rebuild**, and it is a no-op under the default
 * configuration — with `OPENAM_ADMIN_USER` and `OPENAM_USERNAME` unset these are the recorded
 * documents unchanged, which is the property to keep. It stops being one when a run points the
 * suite at differently-named accounts, and then the profile has to follow: auth.mjs authenticates
 * whatever those variables name, and a directory whose credentials and whose records name different
 * people is one that logs a user in and then serves them somebody else's profile.
 *
 * Four fields carry the name, and each is rewritten by what it *is* rather than by substring:
 *
 *   - `username` — the login name, and a plain string where the rest of the document is arrays.
 *   - `uid` — load-bearing rather than cosmetic. `UserModel.parse` sets the model's id to
 *     `user.uid || user.username`, so a stale `uid` would address the profile save to the recorded
 *     user's URL instead of this one's. Absent from the administrator's document, present in the
 *     end user's.
 *   - `dn` and `universalid` — first component only; see `principalDn`.
 *   - `cn` — rewritten only where the recorded value *is* the recorded name. That is the
 *     administrator's case (`cn: ["amAdmin"]`) and not the end user's (`cn: ["Demo Demo"]`, a
 *     display name that never followed the login name), so the test is on the value rather than on
 *     which account it belongs to.
 *
 * `givenName`, `sn` and `mail` stay as recorded even for the administrator, whose recorded given
 * name and surname are also literally `amAdmin`. Renaming an account does not tell us what its
 * owner is called, and inventing a given name for a renamed principal would be modelling a
 * directory rather than reproducing one. Nothing reads the administrator's; the end user's are what
 * xui-profile.spec.mjs asserts the form against, and those come from the recording either way.
 */
export function profileFor (recorded, username) {
    const recordedName = recorded.username;
    if (typeof recordedName !== "string") {
        throw new Error("A recorded user document carries no `username`, so there is no name to "
            + "rebuild it around. A re-record that dropped or renamed the attribute is the thing to "
            + "look at; this server cannot guess whose record it holds.");
    }

    // Cloned out of the capture store, which caches the parsed body it hands back. The cache is per
    // store, so this is not about two states sharing one -- it is that the record built here is the
    // only long-lived alias of a recorded body anywhere in this file, and an in-place write to it
    // would change what the *recording* reads as for the life of the process. `updateUser` replaces
    // rather than mutates, so nothing needs this today. It is here because `seededServices` and
    // `createRealm` clone at exactly this boundary for exactly this reason -- and because task
    // 2.13's reset discards this whole state rather than repairing any part of it, so a record that
    // had written through to the recording would be residue no reset could reach.
    const document = structuredClone(recorded);

    // The administrator's roles are recorded because that document is a self-read; the end user's
    // are not, because that one is not. A re-record taken through the end user's own session would
    // carry them and this fallback would go unused, which is the right way round.
    const selfRoles = document.roles ?? SELF_SERVICE_ROLES;

    // The same account, and therefore the recorded document as recorded. AM resolves a principal
    // case-insensitively -- auth.mjs keys its directory lowercased for that reason, and
    // xui-login.spec.mjs compares the resolved id the same way -- so a run that spells the login
    // name differently is naming the same person, not a different one.
    //
    // It has to be tested case-insensitively rather than by equality, because the administrator's
    // recorded document spells its own name three ways: `username` is `amadmin`, `universalid` is
    // `id=amadmin`, and `cn` and `dn` are `amAdmin`. `ADMIN_USER` defaults to the first, so an
    // exact test would rewrite the other two under the *default* configuration and this would stop
    // being the no-op it is meant to be there. A directory's own spelling of a name it holds is
    // the directory's, and it comes from the recording.
    if (isName(username, recordedName)) {
        return { username, document, selfRoles };
    }

    document.username = username;

    if (Array.isArray(document.uid)) {
        document.uid = [username];
    }
    if (Array.isArray(document.cn)) {
        document.cn = document.cn.map((value) => (isName(value, recordedName) ? username : value));
    }
    for (const field of ["dn", "universalid"]) {
        if (Array.isArray(document[field])) {
            document[field] = document[field].map((value) => principalDn(value, username));
        }
    }

    return { username, document, selfRoles };
}

/**
 * The placeholder values this server substitutes into recorded payloads.
 *
 * Deliberately only the five the payloads served here actually contain. A value invented for a
 * placeholder in a payload no route serves is a decision taken where nothing can test it, and
 * capture-store.mjs throws on any placeholder missing from this map, which is what stops such a
 * deferral turning into a marker served to the browser. `{{USER_SUFFIX}}` was the live example
 * until task 2.12: it appears only in `demo`'s user document, which nothing served until this task
 * put that document on a route.
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
        // The user store's LDAP suffix, which task 2.12 needs because it is the tail of `demo`'s
        // `dn`, the one place in the capture it appears. A *different* suffix from the config
        // store's, which is the pair capture/README.md's placeholder table warns about by name --
        // and not a choice either, for the same reason CONFIG_SUFFIX is not: both ends of the
        // stripping are committed here. openam-up.sh sets `USERSTORE_SUFFIX` to this string when it
        // brings the container up, and capture-lib/normalise.mjs's LDAP_SUFFIXES maps that exact
        // string to this placeholder. Nothing under test asserts a `dn`, so what would catch a wrong
        // value is task 2.15's re-record-and-diff, plus the fact that the two ends can be read
        // against each other by eye.
        USER_SUFFIX: "dc=example,dc=com",
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
            // Root's is recorded; a realm task 2.10 creates gets its own, seeded from the capture's
            // order-25 read of the created realm. See `realmPrototype` below.
            authentication: realmPath === "/"
                ? capture.body(BASELINE.rootAuthentication)
                : undefined,
            // Empty because the capture records no service listing for root, not because AM's root
            // realm has no services: no spec asks for one, so the request list task 2.1 fixed as
            // this server's scope does not contain it (REQUESTS.md has only the
            // `/realms/root/realms/<realm>/realm-config/services` form).
            //
            // Left empty by task 2.11 as well, and that is the deliberate half. A realm the console
            // *creates* is seeded from the order-28 listing (see `realmPrototype`), because a
            // recording of a freshly created realm is evidence of what one holds. There is no such
            // recording for root, so seeding it would mean assuming root looks like a child realm —
            // and the only read that would notice is a service listing for root, which nothing in
            // REQUESTS.md requests. The divergence to know about: `getCreatableTypes` on root offers
            // the catalogue's 19 where a real AM would also offer `policyconfiguration`. Unreachable
            // for the same reason, and written down rather than guessed at.
            //
            // Seeding is not, however, the only thing between this and service administration on
            // root. The capture is keyed by path, so root's schema and template resolve to
            // `json/realms/root/realm-config/services/…`, which is not recorded — root's create and
            // edit forms would answer 501 at the schema whatever this Map held. Both gaps have the
            // same cause and the same fix, and neither is worth closing until a spec asks.
            services: new Map(),
        });
    }

    const globalServices = new Map([["rest", capture.body(BASELINE.restService)]]);

    // What a realm created through the console is made of, all three parts taken from the
    // recording: the defaults AM declares for a realm document, the authentication configuration a
    // realm has the moment it exists, and the services it already holds at that moment. None is
    // hand-authored, which is the D15 rule applied to a resource that is created rather than read.
    const realmPrototype = {
        document: capture.body(BASELINE.realmTemplate),
        authentication: capture.body(BASELINE.createdRealmAuthentication),
        // The listing's own entries, `{_id, name}` each. See BASELINE.realmServices.
        services: capture.body(BASELINE.realmServices).result,
    };

    // The type catalogue, and the per-type starting values a create merges over. Both are read from
    // the recording rather than declared here, so the set of types this server knows about and the
    // set whose schemas it can serve stay the same set.
    const serviceTypes = capture.body(BASELINE.realmServiceTypes).result;
    const serviceTemplates = new Map(capture.filesForActions(["template"])
        .map((file) => [SERVICE_TEMPLATE_FILE.exec(file)?.[1], file])
        .filter(([type]) => type !== undefined)
        .map(([type, file]) => [type, capture.body(file)]));
    const serviceDeleteResponse = capture.body(BASELINE.serviceDelete);

    // The profiles this server can answer a read for, keyed by the name the account logs in under.
    // Exactly the two accounts `CREDENTIALS` lets in, under exactly those names, so the directory
    // this serves and the directory `auth` authenticates against name the same two people -- and so
    // a session can never name a user with no profile. See `profileFor` for what the rebuild does
    // when those names are not the recorded ones.
    const users = new Map([
        [ADMIN_USER.toLowerCase(), profileFor(capture.body(BASELINE.adminProfile), ADMIN_USER)],
        [USERNAME.toLowerCase(), profileFor(capture.body(BASELINE.demoProfile), USERNAME)],
    ]);

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
        realmPrototype, users, serviceTypes, serviceTemplates, serviceDeleteResponse,
    });
}

/**
 * The service instances a realm holds the moment it is created, keyed by type.
 *
 * A listing entry is a type identity — `{_id, name}` — and an instance document is that identity
 * under `_type` beside the settings it holds, so the two are converted rather than equated. The
 * settings are genuinely absent here: the capture records that a fresh realm *has*
 * `policyconfiguration`, and never reads it, so there is nothing recorded to seed them from and
 * nothing in scope that asks. A `GET …/services/policyconfiguration` would answer this thin
 * document; no request in REQUESTS.md makes one, and inventing settings for a service whose schema
 * this server does not serve would be modelling AM rather than reproducing a recording.
 *
 * Fresh objects per realm, for the reason `createRealm` clones the authentication document: two
 * realms created in one run must not share state that a write to either mutates.
 */
function seededServices (entries) {
    return new Map(entries.map((entry) => [entry._id, { _id: "", _type: structuredClone(entry) }]));
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
 * The store is exposed as `realms` / `globalServices` because tasks 2.10-2.12 write to it. It is
 * mutable on purpose: that mutability is the whole difference between this and a replayer. Task
 * 2.13's reset is the exception that proves it — the one operation that does not write to the
 * store, because it replaces the object the whole store hangs off.
 *
 * **A document in the store is the object the loader cached, not a copy of it.** That is safe only
 * because `buildBaselineState` opens the capture afresh each time it is called, so a state that has
 * been written to shares nothing with the next one. Task 2.13's reset therefore goes back through
 * `buildBaselineState` rather than holding a `loadCapture` handle and re-reading from it — reusing
 * one would hand the new state documents an earlier state had already mutated in place.
 */
function createState ({
    realms, globalServices, listingEnvelopes, statics, auth, siteConfiguration, serverVersion,
    realmPrototype, users, serviceTypes, serviceTemplates, serviceDeleteResponse,
}) {
    /**
     * The realm an id addresses, as the `[path, record]` pair the store holds it under.
     *
     * The store is keyed by path and the URL names a realm by id, so every route that addresses one
     * realm needs this translation. It searches rather than decoding the id, because the id in the
     * store is the authority on what a realm is called: decoding would answer with a path for an id
     * no realm has, and the write routes have to tell "no such realm" from "some realm".
     */
    function entryById (realmId) {
        for (const [realmPath, realm] of realms) {
            if (realm.document._id === realmId) {
                return [realmPath, realm];
            }
        }
        return undefined;
    }

    /**
     * AM's own message for a realm it could not read, built from the id asked for.
     *
     * The recorded 404s name the realm the recording created, so the message is composed rather
     * than served. Checked rather than decoded blindly: Node's base64url decoder does not reject a
     * string that is not base64url, it discards what it cannot use, so an id like `@@@` would
     * otherwise be reported back as the mojibake it decodes to.
     */
    function noSuchRealm (realmId) {
        const realmPath = REALM_ID.test(realmId)
            ? Buffer.from(realmId, "base64url").toString("utf8")
            : realmId;
        return notFound(`Realm cannot be read: ${realmPath}`);
    }

    /**
     * The profile record an id addresses, or `undefined` for one this server does not hold.
     *
     * Lowercased on the way in because AM resolves a principal case-insensitively, and the store is
     * keyed the way `auth`'s directory is for the same reason: `#profile` reaches this route with
     * whatever spelling `idFromSession` reported, and a fixture with whatever spelling a human
     * typed. See `user` on why a miss is not a 404.
     */
    function profileRecord (realmPath, userId) {
        return realmPath === TOP_LEVEL_REALM ? users.get(userId.toLowerCase()) : undefined;
    }

    /**
     * A profile as one session sees it: with `roles`, when the reader is the subject, and without
     * the key at all when it is not.
     *
     * The key is deleted rather than left empty because that is what the recording shows — the
     * administrator's read of `demo` has no `roles` key, not an empty one, and `UserModel.parse`
     * branches on `_.has(user, "roles")`. Assigning over the spread rather than appending keeps the
     * administrator's self-read in the recorded key order, since that document carries `roles`
     * already.
     */
    function readAs (record, reader) {
        if (isName(reader?.username, record.username)) {
            return { ...record.document, roles: record.selfRoles };
        }
        const seenByAnother = { ...record.document };
        delete seenByAnother.roles;
        return seenByAnother;
    }

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
            const entry = entryById(realmId);
            return entry
                ? { status: 200, body: entry[1].document }
                : { status: 404, body: noSuchRealm(realmId) };
        },

        /**
         * `POST /json/global-config/realms?_action=create` — task 2.10, and the write the whole
         * store exists to make expressible: the realm this adds is in the next listing.
         *
         * **The document is assembled from the recording, not hand-authored.** The recorded
         * template supplies `active` and `parentPath` for a body that omits them, which is not a
         * courtesy — it is the same document the console's new-realm form took its own defaults
         * from, so the server and the form cannot disagree about what a new realm is. Only the four
         * properties the recorded schema declares are kept, and `_id` is derived rather than
         * accepted: the id is base64url of the path, so a client that sent one could otherwise put
         * a realm in the store under an id that does not address it.
         *
         * `name` is the one field with no default and no way to invent one, so a body without it is
         * the single request this refuses. Everything else a malformed body could get wrong is
         * either defaulted or dropped.
         *
         * Trimming it is invented too, and it is the one place the store key and the id can come
         * apart: a name with an edge space is filed under the trimmed path while a client that
         * encoded the untrimmed one addresses a realm that is not there. Unreachable — the console's
         * `checkPattern` refuses a space outright and `uniqueRealmName` never makes one — and the
         * same holds for the other way these two encodings can disagree, `btoa` being latin1 where
         * `Buffer` is utf8, which needs a non-ASCII name no spec produces.
         *
         * **Not modelled, deliberately, because no request in REQUESTS.md makes them:** creating a
         * realm whose parent does not exist, and creating one that already exists. AM answers the
         * first 400 and the second 409; this answers 201 to both, and the second overwrites. See
         * D15 — these are the invented-rule class the re-record diff cannot catch, and inventing a
         * status for a request the specs never send would be modelling AM rather than reproducing
         * a recording.
         */
        createRealm (document) {
            const name = typeof document?.name === "string" ? document.name.trim() : "";
            if (name === "") {
                return { status: 400, body: badRequest("Realm name is required") };
            }

            const values = { ...realmPrototype.document, ...document, name };
            const realmPath = realmPathOf(name, values.parentPath);
            const stored = {
                _id: realmIdFor(realmPath),
                active: values.active,
                // The one field the recorded template does not carry a default for. The recorded
                // create body sends `[]`, which is also what the console's aliases editor produces
                // when nothing was entered, so an absent one is an empty one.
                aliases: Array.isArray(values.aliases) ? values.aliases : [],
                name,
                parentPath: values.parentPath,
            };

            realms.set(realmPath, {
                document: stored,
                // Its own copy: two realms created in one run must not share the document that a
                // PUT on either of them mutates.
                authentication: structuredClone(realmPrototype.authentication),
                // What the capture's order-28 listing says a realm holds the moment it exists:
                // `policyconfiguration`, and nothing else. Task 2.11's half of this create -- 2.10
                // left it empty because no read it implemented could tell the two apart, and
                // xui-services.spec.mjs's `openServiceList` is the read that can.
                services: seededServices(realmPrototype.services),
            });
            return { status: 201, body: stored };
        },

        /**
         * `PUT /json/global-config/realms/{realmId}` — the realm's own fields, as the edit form
         * sends them back.
         *
         * The URL decides which realm this is and the body decides what it holds, and where the two
         * disagree the URL wins: `_id`, `name` and `parentPath` are taken from the realm that is
         * already there rather than from the body. That is not a validation rule but the store's
         * own arithmetic — the three of them *are* the path this realm is filed under, so a body
         * that changed one would leave the realm addressable at an id that no longer decodes to its
         * key. The console makes `name` and `parentPath` readonly on this form for its own reasons,
         * so nothing under test sends a different one; AM refuses such a request rather than
         * ignoring the fields, and that difference is invisible to every request in REQUESTS.md.
         */
        updateRealm (realmId, document) {
            const entry = entryById(realmId);
            if (!entry) {
                return { status: 404, body: noSuchRealm(realmId) };
            }
            const [realmPath, realm] = entry;
            const stored = {
                ...realm.document,
                ...document,
                _id: realm.document._id,
                name: realm.document.name,
                parentPath: realm.document.parentPath,
            };
            realms.set(realmPath, { ...realm, document: stored });
            return { status: 200, body: stored };
        },

        /**
         * `DELETE /json/global-config/realms/{realmId}` — 200 with the realm as it last was, which
         * is what the recording answers, and 404 for one that is already gone.
         *
         * Both statuses are load-bearing to the spec rather than to the console: `removeRealm` in
         * common/realms-commons.mjs treats 404 as the successful case, because teardown sweeps
         * every realm a test caused to exist including the ones the test deleted through the UI.
         *
         * Deletes the one realm and nothing below it. No spec creates a child realm, so a realm
         * with children is unreachable; AM refuses to delete one (409, which EditRealmView has a
         * branch for) and this would orphan them.
         */
        deleteRealm (realmId) {
            const entry = entryById(realmId);
            if (!entry) {
                return { status: 404, body: noSuchRealm(realmId) };
            }
            const [realmPath, realm] = entry;
            realms.delete(realmPath);
            return { status: 200, body: realm.document };
        },

        /**
         * `PUT /json/realms/root[/realms/{realm}]/realm-config/authentication`.
         *
         * Realm administration reaches this because creating *or* editing a realm in the console is
         * two writes, not one: EditRealmView saves the realm, then PUTs the authentication
         * service's stateless-sessions values, and treats a failure of the second as a failed
         * create. So this is task 2.10's even though the resource is an authentication one — the
         * chains and modules under it stay out of scope (REQUESTS.md).
         *
         * The submitted fields are merged over the stored document rather than replacing it, and
         * that is an invented rule: AM validates a write here against the service's SMS schema and
         * writes what it is given, while the console sends only the subview's own values. Replacing
         * would leave the document missing everything the console did not send, and every later read
         * of it — the edit form's own — would render from a document with no `general` block. The
         * merge is the choice that keeps a partial write from destroying the recorded shape.
         *
         * *Where* a submitted field lands is not invented, though — the recording says. The console
         * sends its values flat (`JSONEditorView.getData` picks the schema's `defaultProperties`,
         * so the realm form's second subview PUTs `{ statelessSessionsEnabled }` and nothing else),
         * while the document holds them in the sections `POST.action=schema` declares, which is
         * where the edit form's next render reads them back from. So a key goes to the section that
         * already holds it, and a top-level merge would file the console's write where no read of
         * it will ever look.
         */
        updateRealmAuthentication (realmPath, document) {
            const realm = realms.get(realmPath);
            if (!realm?.authentication) {
                return { status: 404, body: notFound(`Realm cannot be read: ${realmPath}`) };
            }

            // Which section owns a key is read off the stored document rather than off the schema:
            // the two agree, and the document is the thing being written to.
            const merged = structuredClone(realm.authentication);
            for (const [key, value] of Object.entries(document)) {
                const section = Object.keys(merged).find((name) => isSection(name, merged[name])
                    && Object.hasOwn(merged[name], key));
                if (section) {
                    merged[section][key] = value;
                } else {
                    merged[key] = value;
                }
            }

            realm.authentication = merged;
            return { status: 200, body: merged };
        },

        /**
         * `GET /json/realms/root/users/{id}` — a profile, and the last step of a browser login.
         *
         * **`reader` is the session that asked**, already resolved by rest.mjs, which answers a
         * request carrying no live session before this is reached (see `serveUser`). It is a
         * session rather than a boolean because `roles` depends on *which* session and not merely
         * on there being one — see `profileFor`, and `readAs` below for the rule.
         *
         * A user this server holds no profile for answers `undefined`, which the HTTP layer turns
         * into the labelled 501 rather than a 404. The store holds exactly the accounts that can
         * authenticate, so "the session names a user with no profile" is unreachable by
         * construction; a request for some third name is asking this stand-in for a directory entry
         * it was never given, which is what the 501 says. AM's 404 for a missing user is not
         * recorded, and `RESTLoginHelper` reads a 404 here specifically as "the session names a user
         * who does not exist" and clears the cookie for it — so inventing one would be inventing the
         * shape of a login failure on a path nothing under test can reach.
         *
         * The root realm only, because that is the only path the recording covers. The realm-scoped
         * shape below a created realm is not in REQUESTS.md and answers the same 501.
         */
        user (realmPath, userId, reader) {
            const record = profileRecord(realmPath, userId);
            return record === undefined
                ? undefined
                : { status: 200, body: readAs(record, reader) };
        },

        /**
         * `PUT /json/realms/root/users/{id}` — the profile save, and the write this resource exists
         * for: an edit made through the console is what the next read answers with.
         *
         * **A merge, not a replace**, and that is the recording's own evidence rather than a choice:
         * the PUT at order 46 sent four attributes and AM answered with the whole document — `dn`,
         * `objectClass`, `uid`, `createTimestamp` and the rest intact. xui-profile.spec.mjs leans on
         * it twice: its teardown PUTs five attributes after every test, and `demo` has to still
         * authenticate afterwards, which it would not if a save replaced the record.
         *
         * **An empty array removes the attribute, and that one is a choice rather than a reading.**
         * The console does send `[]`: `UserModel.sync` PUTs `val || []` over whichever of its five
         * attributes the model holds, so a field the user cleared arrives empty — and so does
         * `telephoneNumber`, which `demo` has never had and which the openam-ui-ria template renders
         * as an empty input regardless, on *every* save. What the recording does not say is what AM
         * then stores, and it is mild evidence the other way: the administrator's own document is
         * recorded with `mail`, `telephoneNumber` and `employeeNumber` as present-but-empty keys, so
         * AM plainly serves that shape too. Removing is chosen because it keeps a saved record
         * shaped like the one the capture holds for `demo`, which carries no such keys. Nothing
         * under test can tell the two apart: `readFormAttributes` normalises a missing attribute to
         * `[]` before it compares.
         *
         * **A value is stored as it arrives, scalar or array, and AM would not do that.** The
         * console sends scalars — `UserModel.sync` picks its five attributes off the *flattened*
         * model, so `givenName` goes out as `"Edited"` where every recorded read of that attribute
         * answers `["Demo"]` — and AM normalises a single value back to a one-element array. This
         * server leaves it as sent, so an attribute saved through the console stays a scalar until
         * the next reset. Nothing under test can see it: `UserModel.parse` flattens both shapes and
         * the spec's own reader normalises before it asserts. The rule that would close it is itself
         * an invention — "array in the recorded document means array on write" would have to exempt
         * `username` and `realm`, which are scalars in the recording, by name.
         *
         * `If-Match` is not read. The console sends `*` — `AbstractModel.getMVCCRev` falls back to
         * it when the record carries no `_rev`, and no recorded user document carries one — and so
         * does the spec's own fixture, so there is no revision here for the two ends to disagree
         * about.
         *
         * Which attributes may be written is deliberately not restricted. The recording shows a PUT
         * of four keys merging and says nothing about a fifth being refused, so any rule about what
         * AM would have rejected is one this server would be inventing — and D13's Non-Goal is that
         * this is a stand-in, not a second AM. The consequence to know: a caller may write `dn` or
         * `username` here and this server will store it. Nothing under test sends either.
         */
        updateUser (realmPath, userId, document, writer) {
            const record = profileRecord(realmPath, userId);
            if (record === undefined) {
                return undefined;
            }
            // Not recorded, because nothing the console or the fixtures send is malformed: a body
            // that parsed as JSON but is not an object has no attributes to merge, and answering
            // the 400 shape is closer than letting `Object.entries` decide what a string's
            // attributes are. A bodyless PUT lands here too, since `readDocument` reports no
            // document as `undefined`. `updateRealm` answers that one 200-unchanged instead, by
            // spreading the `undefined`; the two disagree, and this is the better of them, but
            // updateRealm belongs to an approved task and nothing sends either shape.
            if (document === null || typeof document !== "object" || Array.isArray(document)) {
                return { status: 400,
                    body: badRequest("A profile update must be a JSON object of attributes.") };
            }

            const merged = { ...record.document };
            for (const [attribute, value] of Object.entries(document)) {
                // `JSON.parse` makes `__proto__` an own key, where an object literal would not, so
                // it arrives here like any other attribute -- and assigning it would hand it to
                // `Object.prototype`'s setter instead of storing it, silently re-parenting the
                // record. Dropped rather than stored: nothing sends it, and a document off the wire
                // does not get to decide what this one inherits.
                if (attribute === "__proto__") {
                    continue;
                }
                if (Array.isArray(value) && value.length === 0) {
                    delete merged[attribute];
                } else {
                    merged[attribute] = value;
                }
            }
            record.document = merged;

            // Answered as a read by the same caller, which is what the recording shows: the PUT
            // response and the GET that followed it are the same document, and that document was
            // the administrator reading somebody else -- so no `roles`. A user saving their own
            // profile gets theirs back, which matters because Backbone feeds this response straight
            // through `UserModel.parse` and `uiroles` is rebuilt from it.
            return { status: 200, body: readAs(record, writer) };
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
         * `POST …/realm-config/services?_action=getCreatableTypes&forUI=true` — the types this realm
         * may still be given, and the one answer in this file that must never be cached.
         *
         * **Recomputed from live state on every call**, which is the whole of the rule: the
         * catalogue minus every type the named realm currently holds. A fixed list would pass
         * xui-services.spec.mjs's create test and fail the one after it — the spec says so in as
         * many words — and would fail it the way that costs the most to diagnose, by passing on a
         * clean instance and failing on the second run against the same one. Group 1 hit exactly
         * that against the real AM in task 1.7.
         *
         * The console does no filtering of its own (`ServicesService.type.getCreatables` only
         * sorts), so whatever is returned here is what the create form offers, and the spec asserts
         * the rendered dropdown has exactly as many options as this answer has entries.
         *
         * `forUI` is accepted and ignored. It suppresses `hiddenFromUI` types in AM, and the
         * recorded catalogue is already a `forUI=true` answer, so honouring it would mean applying
         * a filter twice; a `forUI=false` caller would get the filtered list, which is a request
         * nothing in scope makes (NOTES-sms.md).
         *
         * A realm this server does not have answers with the realm 404 rather than an empty list,
         * so that a mistyped realm is not reported as one with nothing left to create.
         */
        realmCreatableTypes (realmPath) {
            const realm = realms.get(realmPath);
            if (!realm) {
                return { status: 404, body: notFound(`Realm cannot be read: ${realmPath}`) };
            }
            return {
                status: 200,
                body: { result: serviceTypes.filter((type) => !realm.services.has(type._id)) },
            };
        },

        /**
         * `POST …/realm-config/services/{id}?_action=create` — 201 with the stored instance.
         *
         * **The posted values are merged over the recorded template, not stored alone**, and that is
         * the rule the create test turns on. `showOnlyRequiredAndEmpty` means the console sends only
         * the properties it showed — for `baseurl`, `extensionClassName` and `fixedValue` — and the
         * spec then asserts the service reads back with `source === "REQUEST_VALUES"`, which the
         * console never sent. The template is where it comes from, and it is the same document the
         * create form took its own starting values from, so the server and the form cannot disagree
         * about what an unset property is.
         *
         * `_type` is the catalogue's entry for the type, whose three fields are exactly `_type`'s.
         * `_id` is the empty string every recorded singleton instance carries.
         *
         * `undefined` — the labelled 501 — for a type the recording covers neither a catalogue entry
         * nor a template for. That is not a missing resource but a request outside the capture's
         * scope, and it is the same answer `_action=schema` already gives for such a type, which
         * keeps a type from being creatable through a form this server could not have generated.
         *
         * **Not modelled, deliberately, following `createRealm`'s precedent:** creating a service
         * the realm already has. AM answers 409; this answers 201 and overwrites. No request in
         * REQUESTS.md makes one — the console cannot, since the form only offers what
         * `getCreatableTypes` returned — so inventing the status would be modelling AM rather than
         * reproducing a recording. Likewise a posted property the schema does not declare is stored
         * rather than rejected; AM validates, and nothing under test sends one.
         */
        createRealmService (realmPath, serviceId, values) {
            const realm = realms.get(realmPath);
            if (!realm) {
                return { status: 404, body: notFound(`Realm cannot be read: ${realmPath}`) };
            }
            const type = serviceTypes.find((candidate) => candidate._id === serviceId);
            const template = serviceTemplates.get(serviceId);
            if (type === undefined || template === undefined) {
                return undefined;
            }

            // `identity` is spread twice, and both times are load-bearing. First, because the
            // recording puts `_id` and `_type` before the settings and a spread fixes a key's
            // position at its first occurrence. Last, so the body cannot change them -- the same
            // guard `updateRealmService` puts on its own merge, and for the same reason: `_type.name`
            // is what the listing renders as the row and the edit form as its title, `_id` is what
            // the row's link addresses, and a body that set either would file the instance under the
            // type from the URL while the console read it back as something else.
            //
            // The template is cloned rather than spread, because `capture.body` caches and returns
            // the same object for every caller: `dashboard`'s only property is an array, and a
            // shallow spread would leave every realm that created one sharing it with the baseline.
            // Same rule as `seededServices` -- two realms in one run share nothing a write reaches.
            const identity = { _id: "", _type: structuredClone(type) };
            const document = { ...identity, ...structuredClone(template), ...values, ...identity };
            realm.services.set(serviceId, document);
            return { status: 201, body: document };
        },

        /**
         * `PUT …/realm-config/services/{id}` — the edit form's save, and an echo of what was stored.
         *
         * The console sends the whole document back rather than the edited field alone
         * (`values.extend(getData()).raw`), so this is a merge only to keep a property the form did
         * not carry from being dropped. Identity comes from the store rather than the body, for the
         * reason `updateRealm` takes a realm's: `_type.name` is what the edit form renders as its
         * title and what the listing renders as the row, so a body that changed it would rename the
         * service in the console's own next read.
         *
         * AM answers this with no message; the "Changes saved" the spec waits for is the console's
         * own. So this only has to succeed.
         */
        updateRealmService (realmPath, serviceId, document) {
            const realm = realms.get(realmPath);
            if (!realm) {
                return { status: 404, body: notFound(`Realm cannot be read: ${realmPath}`) };
            }
            const stored = realm.services.get(serviceId);
            if (!stored) {
                return { status: 404, body: notFound("Not Found") };
            }

            const merged = { ...stored, ...document, _id: stored._id, _type: stored._type };
            realm.services.set(serviceId, merged);
            return { status: 200, body: merged };
        },

        /**
         * `DELETE …/realm-config/services/{id}` — the recorded body, read from `BASELINE.serviceDelete`.
         *
         * Note the shape: a realm delete answers with the realm as it last was, and a service delete
         * answers with `{"success": true}` instead. Two conventions in one API, both recorded,
         * neither invented — which is why this reads the sixteen bytes rather than writing them out.
         *
         * All three of the console's delete routes arrive here — the edit form's button, the list's
         * per-row button and the toolbar's bulk delete, which issues one of these per checked id.
         * What the spec asserts of each is that the row is gone from the *next* listing and that
         * `getCreatableTypes` offers the type again, so the removal has to be from state rather than
         * merely reported.
         */
        deleteRealmService (realmPath, serviceId) {
            const realm = realms.get(realmPath);
            if (!realm) {
                return { status: 404, body: notFound(`Realm cannot be read: ${realmPath}`) };
            }
            if (!realm.services.delete(serviceId)) {
                return { status: 404, body: notFound("Not Found") };
            }
            return { status: 200, body: serviceDeleteResponse };
        },

        /**
         * A schema, template or sub-schema-type document, served verbatim. `undefined` means this
         * request is not one of the 12 — the HTTP layer answers 501, because an unrecorded schema is
         * a request outside the capture's scope rather than a resource that is missing.
         */
        verbatim (request) {
            return statics.get(captureFileFor(request));
        },
    };
}
