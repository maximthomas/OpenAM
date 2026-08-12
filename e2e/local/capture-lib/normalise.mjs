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
 * The normalisation rules that make a re-record byte-identical, and the two smaller sets of rules
 * that decide what the committed capture is allowed to say.
 *
 * Three categories live here, and they are kept apart on purpose because they answer three different
 * questions:
 *
 *   1. **Volatility** (rules 1–14) — *what moves between two identical calls?* local/NOTES-volatility.md
 *      is the specification, and the rule numbers below are that document's numbering. It surveyed two
 *      full passes against one instance and a third against a rebuilt one; every rule is something
 *      that was measured to move, not something that looked like it might.
 *   2. **Secrecy** (`maskCredentials`) — *what may not be committed at all?*
 *   3. **Portability** (`normalisePortableText`, `normalisePortableValues`, and the cookie rules
 *      marked as such) — *what pins the capture to one box?* Reviewed in task 2.3 and recorded in
 *      local/capture/README.md. None of these can affect determinism: every value they touch was
 *      measured STABLE, so they neither create nor hide a re-record diff on one machine.
 *
 * Nothing else belongs in here. A rule invented at implementation time to make a diff come out
 * empty is a rule nobody reviewed, and it would silently discard exactly the signal task 2.15's
 * drift job exists to catch.
 */

export const TS = "<TS>";
export const TOKEN = "<TOKEN>";
export const AUTHID = "<AUTHID>";
export const AUTH_COOKIE = "<AUTH-COOKIE>";
export const SESSION_HANDLE = "<SESSION-HANDLE>";

/**
 * Portability placeholders.
 *
 * `<ANGLE>` marks a value that was removed because it was volatile or secret; `{{DOUBLE_BRACE}}`
 * marks one that was removed because it belongs to a deployment. The two shapes are different so a
 * reader meeting one in a response knows immediately which kind of substitution they are looking at,
 * and so the local server can tell what it is expected to fill in from its own configuration.
 */
export const BASE_URL = "{{BASE_URL}}";
export const HOSTNAME = "{{HOSTNAME}}";
export const HOST_ALIAS = "{{HOST_ALIAS}}";
export const PORT = "{{PORT}}";
export const COOKIE_DOMAIN = "{{COOKIE_DOMAIN}}";
export const CONTEXT = "{{CONTEXT}}";
export const CONFIG_SUFFIX = "{{CONFIG_SUFFIX}}";
export const USER_SUFFIX = "{{USER_SUFFIX}}";
export const SERVER_ID = "{{SERVER_ID}}";

/**
 * Rules 1, 12 and 13 — headers dropped outright.
 *
 * `ETag` is the subtle one: it moves between calls on a byte-identical body, so it is not a content
 * hash in any usable sense and must never be derived from or validated against the body.
 * `Content-Length` goes because normalisation changes the body's length anyway.
 */
const DROPPED_HEADERS = new Set(["date", "etag", "content-length"]);

/** Rules 2, 3, 4, 7, 10 and 11 — scalar fields replaced wherever they appear, at any depth. */
const SCALAR_RULES = new Map([
    ["latestAccessTime", TS],               // 2
    ["maxIdleExpirationTime", TS],          // 3
    ["maxSessionExpirationTime", TS],       // 4
    ["tokenId", TOKEN],                     // 7
    ["sessionHandle", SESSION_HANDLE],      // 10
    ["authId", AUTHID],                     // 11
]);

/**
 * Rules 5 and 6 — LDAP timestamps, which AM returns as single-element arrays.
 *
 * Rule 6 (`createTimestamp`) is the one a two-run diff cannot justify: it is fixed for the life of a
 * container and only moves when the configurator runs again. A tool that normalised just what a
 * two-run diff surfaces would pass its own tests and fail the first real re-record.
 */
const ARRAY_RULES = new Map([
    ["modifyTimestamp", TS],                // 5
    ["createTimestamp", TS],                // 6
]);

/** Rules 8 and 9 — the cookie value only; `path` and `SameSite` are stable and stay. */
const COOKIE_RULES = new Map([
    ["iPlanetDirectoryPro", TOKEN],         // 8
    ["AMAuthCookie", AUTH_COOKIE],          // 9
]);

/**
 * Portability, not volatility: the load-balancer cookie carries the server id.
 *
 * NOTES-volatility.md measured `01` surviving a full destroy-and-reconfigure in all three places it
 * appears, so this cannot change a re-record diff. It is here because the server id is this
 * container's, and the local server has one of its own.
 */
const PORTABLE_COOKIE_RULES = new Map([
    ["amlbcookie", SERVER_ID],
]);

/*
 * NOTES-volatility.md:202 records the same server id in three places: the `amlbcookie` value handled
 * here, the `SI` segment of every session token (which rule 7 replaces wholesale), and
 * `servers[0]._id`. The third is out of scope only because no in-scope request reads
 * `/json/global-config/servers`; whoever adds that call needs a rule for it, and `auditPortability`
 * will not catch its absence.
 */

/**
 * Rule 14 — sort object keys recursively, and never sort arrays.
 *
 * The asymmetry is load-bearing. All five `_action=schema` responses reorder their `properties`
 * objects on every single call while staying deep-equal, so object keys must be sorted; display
 * order survives because it is carried explicitly in each property's `propertyOrder`. Listings, by
 * contrast, came back in identical order across a full destroy-and-reconfigure, so their order is
 * real API signal and sorting them would throw it away.
 *
 * Applying the sort to every object rather than only to `properties` is equivalent and simpler,
 * since JSON objects are unordered by definition.
 */
export function normaliseJson (value) {
    if (Array.isArray(value)) {
        return value.map(normaliseJson);
    }
    if (value === null || typeof value !== "object") {
        return value;
    }

    const out = {};
    for (const key of Object.keys(value).sort()) {
        const raw = value[key];

        if (SCALAR_RULES.has(key) && typeof raw === "string") {
            out[key] = SCALAR_RULES.get(key);
        } else if (ARRAY_RULES.has(key) && Array.isArray(raw)) {
            out[key] = raw.map(() => ARRAY_RULES.get(key));
        } else {
            out[key] = normaliseJson(raw);
        }
    }
    return out;
}

/**
 * The `domain=` attribute, whatever it happens to be — portability, not volatility.
 *
 * Replaced blindly rather than matched against a domain derived from `--base-url`, because a derived
 * value can be wrong (AM's cookie domain is configured, not deduced from the host name) and a rule
 * that silently matches nothing is the failure mode this whole file exists to avoid. The attribute
 * name is preserved from the capture: AM spells it `domain=` on the login cookies and `Domain=` on
 * the expiry line, and flattening that difference would be a change nobody asked for.
 */
function normaliseCookieAttributes (attributes) {
    return attributes.replace(/(;\s*)(domain=)[^;]*/gi, `$1$2${COOKIE_DOMAIN}`);
}

/**
 * Rules 8 and 9 applied to one `Set-Cookie` line, plus the two portability rules above.
 *
 * `AMAuthCookie=LOGOUT` on a successful login is a constant sentinel rather than a token, and the
 * notes call it out as needing no rule — replacing it would hide the difference between a login that
 * cleared the auth cookie and one that did not. Its attributes are still normalised: the sentinel is
 * the *value*, and the `Domain=` beside it is as host-bound as any other.
 */
export function normaliseSetCookie (raw) {
    const semicolon = raw.indexOf(";");
    const pair = semicolon === -1 ? raw : raw.slice(0, semicolon);
    const attributes = normaliseCookieAttributes(semicolon === -1 ? "" : raw.slice(semicolon));

    const equals = pair.indexOf("=");
    if (equals === -1) {
        return `${pair}${attributes}`;
    }

    const name = pair.slice(0, equals).trim();
    const value = pair.slice(equals + 1).trim();
    const placeholder = COOKIE_RULES.get(name) ?? PORTABLE_COOKIE_RULES.get(name);

    // `AMAuthCookie=LOGOUT` is a sentinel, and an empty value means the cookie is being cleared.
    // Both are statements about what AM did, not values that identify anything; rendering either as a
    // placeholder would say the cookie carried something it did not.
    const sentinel = (COOKIE_RULES.has(name) && value === "LOGOUT") || value === "";

    if (placeholder === undefined || sentinel) {
        return `${name}=${value}${attributes}`;
    }
    return `${name}=${placeholder}${attributes}`;
}

/**
 * Response headers, with rules 1, 8, 9, 12 and 13 applied and the survivors sorted by name.
 *
 * `set-cookie` is taken from the raw list rather than from iteration, because iterating a Headers
 * object folds multiple cookies into one comma-joined string that cannot be split back apart
 * reliably.
 */
export function normaliseHeaders (headers, setCookies) {
    const out = {};

    for (const name of [...headers.keys()].sort()) {
        if (DROPPED_HEADERS.has(name) || name === "set-cookie") {
            continue;
        }
        out[name] = headers.get(name);
    }

    if (setCookies.length > 0) {
        out["set-cookie"] = setCookies.map(normaliseSetCookie);
    }
    return out;
}

/* ================================================================================================
 * Portability — not among the fourteen, and deliberately kept separate from them.
 *
 * NOTES-volatility.md measured every value below as STABLE across a full destroy-and-reconfigure, so
 * none of this can affect the two-run determinism check either way. It is here because task 2.3
 * reviews the capture for host-specific values before it is committed, and because the local server
 * serves these shapes back under its own origin, its own context path and its own cookie domain —
 * where `openam.example.org:8080`, `/openam` and `domain=example.org` would all be wrong.
 *
 * **What is deliberately NOT normalised: the AM version, build revision and build date.** They are
 * host-bound in the same sense as the rest, and pinning them is how task 2.15 notices that the
 * instance under test changed. The review in task 2.3 measured the revision moving between two image
 * builds, so the drift job will go red on a rebuild — that is a true positive worth a human look, and
 * it is one line in one file. Nothing downstream reads them for behaviour.
 * ============================================================================================== */

/** Escape a literal for use inside a `RegExp`, since the context path arrives from `--base-url`. */
function escapeRegExp (text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * The LDAP suffixes, which are the one pair of targets that cannot be derived from `--base-url`.
 *
 * Two of them, not one: NOTES-volatility.md measured the config store's suffix in every
 * `universalid` and in `getSessionInfo.universalId`, and a *different* one in the user store, in
 * `demo`'s `dn`. A rule assuming a single suffix silently commits the other.
 *
 * Hard-coded because they are what this container was configured with, and unlike the host name there
 * is nothing to read them off. `auditPortability` is what makes that safe: it fails the run on any
 * surviving `dc=` chain, so a differently-configured deployment stops the tool instead of committing
 * its directory layout.
 */
const LDAP_SUFFIXES = new Map([
    ["dc=openam,dc=openidentityplatform,dc=org", CONFIG_SUFFIX],
    ["dc=example,dc=com", USER_SUFFIX],
]);

/**
 * What a capture taken against `baseUrl` has to have removed from it.
 *
 * Derived from the one flag rather than declared separately, so `--base-url` stays the single knob:
 * `http://openam.example.org:8080/openam` yields host name `openam.example.org`, its bare first label
 * `openam` (which AM also carries as a root-realm DNS alias), the cookie domain `example.org`, port
 * `8080`, and the deployment URI `openam`.
 *
 * A host that is an IP address or has no dot has no meaningful bare label or parent domain, and
 * splitting one on `.` invents both — `192.168.1.10` would yield the alias `192` and the domain
 * `168.1.10`, sending the audit hunting a substring that means nothing. Those cases fall back to the
 * host name itself, so the rules and the audit agree on a real value or on none.
 */
export function portabilityTargets (baseUrl) {
    const url = new URL(baseUrl);
    const labels = url.hostname.split(".");
    const named = labels.length > 1 && !/^[0-9.]+$/.test(url.hostname);

    return {
        baseUrl: baseUrl.replace(/\/$/, ""),
        hostname: url.hostname,
        port: url.port,
        hostAlias: named ? labels[0] : url.hostname,
        cookieDomain: named ? labels.slice(1).join(".") : url.hostname,
        context: url.pathname.replace(/^\//, "").replace(/\/$/, ""),
    };
}

/**
 * The substitutions that are safe to make on the serialised JSON, in the order they must run.
 *
 * Text rather than a structural walk because these values are embedded in longer strings —
 * `"/openam/console"`, `"id=demo,ou=user,dc=openam,…"` — where a key-name rule would have nothing to
 * key on. The bare host alias is the one target too common to match this way, and is handled
 * structurally in `normalisePortableValues` instead. That distinction is not theoretical: the capture
 * carries eighteen `org.forgerock.openam.*` class names, every one of which a blind replacement of
 * `openam` would corrupt.
 *
 * The other targets are distinctive, but the host-name match is a plain substring and so is unanchored
 * on both sides: a hypothetical `notopenam.example.org` would become `not{{HOSTNAME}}`. Nothing in the
 * capture is shaped like that, and anchoring it would need to know every delimiter AM might put a host
 * name next to, so this is recorded rather than defended against.
 *
 * Order is load-bearing. The base URL contains the authority, which contains the host name, which
 * contains the cookie domain, and the base URL ends with the deployment URI; replacing the longest
 * first leaves the shorter rules nothing of it to match.
 *
 * `{{HOSTNAME}}:{{PORT}}` covers the authority appearing without its scheme, or under a scheme other
 * than the recorded one — neither of which the base URL rule can catch, and both of which would commit
 * a port the local server does not listen on.
 *
 * The deployment URI is anchored on what may follow it: a path separator, a query, a fragment, the
 * `;jsessionid=` a servlet container appends when cookies are off, whitespace, or the closing quote of
 * a JSON string. So `/openam` matches where it is a path prefix and not inside `/openam-extra`.
 */
export function normalisePortableText (text, targets) {
    let out = text.split(targets.baseUrl).join(BASE_URL);

    if (targets.port) {
        out = out.split(`${targets.hostname}:${targets.port}`).join(`${HOSTNAME}:${PORT}`);
    }
    out = out.split(targets.hostname).join(HOSTNAME);

    if (targets.context) {
        out = out.replace(
            new RegExp(`/${escapeRegExp(targets.context)}(?=[/"?#;\\s]|$)`, "g"),
            `/${CONTEXT}`,
        );
    }

    // Case-insensitively: LDAP attribute type names are case-insensitive, and a directory echoes back
    // whatever case its suffix was configured with. A `split`/`join` here would pass `DC=example,DC=com`
    // straight through, and `auditPortability` would then have to be the only thing standing between it
    // and the repository.
    for (const [suffix, placeholder] of LDAP_SUFFIXES) {
        out = out.replace(new RegExp(escapeRegExp(suffix), "gi"), placeholder);
    }
    return out;
}

/**
 * The two substitutions that have to be made by key rather than by value.
 *
 * `aliases` holds the root realm's DNS aliases, `["openam", "openam.example.org"]` — the bare label is
 * indistinguishable from any other use of the word, so it is matched only as a whole alias, and only
 * inside that array. The realm the capture creates carries an alias of its own
 * (`e2e-capture-alias`), which matches neither target and is left exactly as recorded: it is the
 * tool's own value, and the CRUD calls that assert on it are the reason it is there.
 *
 * `domains` is `serverinfo/*`'s cookie-domain list, which the XUI reads to decide what domain to write
 * its session cookie for. Served verbatim from a local origin it would send the browser looking for a
 * cookie that can never be set, so the value goes and the arity stays.
 *
 * Keys are rebuilt in arrival order: rule 14 has already sorted them, and this must not re-sort.
 */
export function normalisePortableValues (value, targets) {
    if (Array.isArray(value)) {
        return value.map((item) => normalisePortableValues(item, targets));
    }
    if (value === null || typeof value !== "object") {
        return value;
    }

    const out = {};
    for (const [key, item] of Object.entries(value)) {
        if (key === "aliases" && Array.isArray(item)) {
            out[key] = item.map((alias) => {
                if (alias === targets.hostname || alias === HOSTNAME) {
                    return HOSTNAME;
                }
                return alias === targets.hostAlias ? HOST_ALIAS : alias;
            });
        } else if (key === "domains" && Array.isArray(item)) {
            out[key] = item.map((domain) => (typeof domain === "string" ? COOKIE_DOMAIN : domain));
        } else {
            out[key] = normalisePortableValues(item, targets);
        }
    }
    return out;
}

/**
 * What the rules above were supposed to remove, checked after they ran.
 *
 * Every rule here is a literal or a shape the tool was configured to erase, so this cannot fail on a
 * capture it has just normalised — it fails when the instance stops matching the tool's assumptions:
 * a differently-configured cookie domain, a second LDAP suffix, a new response embedding the host
 * name. That is precisely the case where a silent rule and a committed leak look identical from the
 * outside, and this is the one artefact in the change where a mistake outlives a revert.
 *
 * The AM version triple is deliberately absent from these checks; see the section header.
 *
 * Returns the survivors rather than throwing, so the caller can name the call they came from.
 */
export function auditPortability (text, targets) {
    const survivors = [];

    /** Quote the hit with what surrounds it, so an unattended failure is diagnosable from the log. */
    const quote = (match) => {
        const at = text.indexOf(match);
        const from = Math.max(0, at - 40);
        return `…${text.slice(from, at + match.length + 40).replace(/\s+/g, " ")}…`;
    };

    for (const [label, needle] of [
        ["the base URL", targets.baseUrl],
        ["the host name", targets.hostname],
        ["the cookie domain", targets.cookieDomain],
    ]) {
        if (needle && text.includes(needle)) {
            survivors.push(`${label} "${needle}" in ${quote(needle)}`);
        }
    }

    // The port survives the host-name rule wherever the authority appeared without its scheme.
    const port = text.match(new RegExp(`${escapeRegExp(HOSTNAME)}:[0-9]+`));
    if (port) {
        survivors.push(`a port in "${port[0]}"`);
    }

    if (targets.context) {
        const context = text.match(
            new RegExp(`/${escapeRegExp(targets.context)}(?=[/"?#;\\s]|$)`),
        );
        if (context) {
            survivors.push(`the deployment URI "/${targets.context}" in ${quote(context[0])}`);
        }
    }

    // Case-insensitive, and with a left boundary so `abcdc=foo` is not read as a DN. This is the one
    // check that can fire on something legitimate: AM's SMS schemas carry example DNs in their
    // `description` prose, and a later task widening REQUESTS.md may pull one in. That is deliberate —
    // stopping to have a human look at a `dc=` chain is cheap, and the alternative is a real suffix
    // committed silently. The quoted context is there so telling the two apart takes seconds.
    const suffix = text.match(/(?<![A-Za-z0-9])dc=[A-Za-z0-9-]+(?:,dc=[A-Za-z0-9-]+)*/i);
    if (suffix) {
        survivors.push(`an LDAP suffix "${suffix[0]}" that LDAP_SUFFIXES does not list, `
            + `in ${quote(suffix[0])}`);
    }

    const serverId = text.match(/amlbcookie=(?!\{\{)[^;"]+/);
    if (serverId) {
        survivors.push(`a server id "${serverId[0]}"`);
    }
    return survivors;
}

export const SECRET = "<PASSWORD>";

/**
 * Not one of the fourteen either, and for a third reason: this is about what may be committed, not
 * about what varies or where it points.
 *
 * The exposure is entirely in the *request*. AM never echoes a credential back, but the login the
 * capture performs fills a `PasswordCallback` with a working password, and that body is recorded.
 * `changeit` is public, but the tool reads `$OPENAM_PASSWORD`, so a capture taken against a hardened
 * instance would commit a real one — and the secrets review in task 2.3 would be the only thing
 * standing between it and the repository.
 *
 * Deliberately narrow on both axes: only a `PasswordCallback` input, and only where its value is a
 * credential this run actually authenticated with. A blanket search-and-replace for the password
 * string would corrupt any response that happened to contain it, and masking every callback input
 * would take the deliberately-wrong password of the 401 probe with it — that one is documentation,
 * not a secret, and it is what makes the failure leg readable.
 *
 * D15 is why this costs nothing downstream: the local server is a state machine over recorded
 * shapes, not a replayer matching request bodies, so it has no use for the real value.
 */
export function maskCredentials (value, credentials) {
    if (Array.isArray(value)) {
        return value.map((item) => maskCredentials(item, credentials));
    }
    if (value === null || typeof value !== "object") {
        return value;
    }

    // Rebuilt in the order it arrived: rule 14 has already sorted these, and reassigning an existing
    // key below leaves its position alone.
    const out = {};
    for (const [key, item] of Object.entries(value)) {
        out[key] = maskCredentials(item, credentials);
    }

    if (out.type === "PasswordCallback" && Array.isArray(out.input)) {
        out.input = out.input.map((field) => (credentials.has(field?.value)
            ? { ...field, value: SECRET }
            : field));
    }
    return out;
}

/**
 * What each placeholder stands for, carried into index.json so the capture explains itself.
 *
 * Descriptions, not the values they replaced. Recording `openam.example.org` here would put the host
 * name straight back into the committed tree and make a re-record on another machine diff dirty,
 * which is the whole thing the portability rules exist to prevent. What the capture *was* taken
 * against is recorded where it belongs: the AM version triple in `json/serverinfo/version/GET.json`,
 * left unpinned on purpose.
 */
export const PLACEHOLDERS = {
    [TS]: "a timestamp AM regenerates on every call",
    [TOKEN]: "an SSO token minted for this run",
    [AUTHID]: "the JWT carrying authentication-chain state between callback exchanges",
    [AUTH_COOKIE]: "the in-progress authentication cookie",
    [SESSION_HANDLE]: "the session handle returned by getSessionInfo",
    [SECRET]: "a password this run authenticated with; never recorded",
    [BASE_URL]: "the AM origin and deployment URI the capture was recorded against",
    [HOSTNAME]: "the fully-qualified name of the AM host",
    [HOST_ALIAS]: "the AM host's bare name, carried as a root-realm DNS alias",
    [PORT]: "the port AM was reached on",
    [COOKIE_DOMAIN]: "the domain AM writes its cookies for",
    [CONTEXT]: "the servlet context AM is deployed under, without its leading slash",
    [CONFIG_SUFFIX]: "the config store's LDAP suffix",
    [USER_SUFFIX]: "the user store's LDAP suffix",
    [SERVER_ID]: "the AM server id, as carried by the load-balancer cookie",
};
