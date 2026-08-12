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
 * The normalisation rules that make a re-record byte-identical.
 *
 * local/NOTES-volatility.md is the specification for this file, and the rule numbers in the
 * comments below are that document's numbering. It surveyed two full passes against one instance
 * and a third against a rebuilt one; every rule here is something that was measured to move, not
 * something that looked like it might.
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

/** Rules 8 and 9 — the cookie value only; `path`, `domain` and `SameSite` are stable and stay. */
const COOKIE_RULES = new Map([
    ["iPlanetDirectoryPro", TOKEN],         // 8
    ["AMAuthCookie", AUTH_COOKIE],          // 9
]);

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
 * Rules 8 and 9 applied to one `Set-Cookie` line.
 *
 * `AMAuthCookie=LOGOUT` on a successful login is a constant sentinel rather than a token, and the
 * notes call it out as needing no rule — replacing it would hide the difference between a login that
 * cleared the auth cookie and one that did not.
 */
export function normaliseSetCookie (raw) {
    const semicolon = raw.indexOf(";");
    const pair = semicolon === -1 ? raw : raw.slice(0, semicolon);
    const attributes = semicolon === -1 ? "" : raw.slice(semicolon);

    const equals = pair.indexOf("=");
    if (equals === -1) {
        return raw;
    }

    const name = pair.slice(0, equals).trim();
    const value = pair.slice(equals + 1).trim();
    const placeholder = COOKIE_RULES.get(name);

    if (placeholder === undefined || value === "LOGOUT") {
        return raw;
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

/**
 * Not one of the fourteen, and deliberately kept separate from them.
 *
 * NOTES-volatility.md measured the base URL as *stable* between runs, so this cannot affect the
 * two-run determinism check either way — it is here because task 2.3 reviews the capture for
 * "host-specific URLs" before it is committed, and because the local server serves the capture back
 * under its own origin, where a hard-coded `openam.example.org:8080` would be wrong.
 *
 * Narrow on purpose. The AM version, build revision, realm DNS aliases and the two LDAP suffixes are
 * host-bound too, and are deliberately left alone: pinning them is how task 2.15 notices that the
 * instance under test changed, which is the entire point of the drift job this capture feeds.
 */
export function normaliseBaseUrl (text, baseUrl, placeholder = "{{BASE_URL}}") {
    return text.split(baseUrl).join(placeholder);
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
