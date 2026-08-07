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
 * Realm fixtures for the console specs: creating, reading and removing a realm over AM's REST API,
 * and the two different encodings the console uses to name one.
 *
 * These exist so that a spec about the console does not have to establish its own premise through
 * the console. xui-realms.spec.mjs drives create, edit and delete through the UI, and each of those
 * tests needs a realm that either already exists or is gone afterwards; doing that over REST is what
 * keeps a test from depending on the one before it having passed.
 *
 * Unlike oauth2-commons.mjs, everything here is torn down. Those fixtures are shared realm
 * configuration; a realm is a spec's own scratch object, and one left behind changes what the next
 * run's realm list contains — which is exactly what the specs assert on.
 */

import { OPENAM_BASE, describeFailure } from "./openam-commons.mjs";

/** The realm every instance has, as both the REST API and the console's routes name it. */
export const TOP_LEVEL_REALM = "/";

const REALMS_URL = `${OPENAM_BASE}/json/global-config/realms`;

/** The version the console's RealmsService asks this endpoint for. */
const API_VERSION = "protocol=1.0,resource=1.0";

function headers (adminToken, withBody = false) {
    return {
        "iPlanetDirectoryPro": adminToken,
        "Accept-API-Version": API_VERSION,
        ...(withBody ? { "Content-Type": "application/json" } : {}),
    };
}

/**
 * The path of a realm, composed the way RealmsService.getRealmPath composes it: a child of the top
 * level realm is "/name" rather than "//name", and the top level realm itself — which has no parent
 * — is "/" whatever it is called.
 */
export function realmPathOf (name, parentPath) {
    if (parentPath === TOP_LEVEL_REALM) {
        return `${TOP_LEVEL_REALM}${name}`;
    } else if (parentPath) {
        return `${parentPath}/${name}`;
    }
    return TOP_LEVEL_REALM;
}

/**
 * The REST resource id for a realm path: base64url, matching RealmsService.encodePath. Note this is
 * not the encoding the console's own routes use — see realmHash.
 *
 * btoa and not Buffer, deliberately: btoa is latin1 and is what the console calls, so a realm name
 * outside that range has to fail here the same way it fails there rather than being quietly encoded
 * into an id the console could never produce.
 */
export function encodeRealmId (path) {
    return btoa(path)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

/**
 * The console's hash for a realm route, which encodes the path with encodeURIComponent rather than
 * base64url: realmHash("/alpha", "edit") is "#realms/%2Falpha/edit".
 */
export function realmHash (path, fragment) {
    const encoded = encodeURIComponent(path);
    return fragment ? `#realms/${encoded}/${fragment}` : `#realms/${encoded}`;
}

let sequence = 0;

/**
 * A realm name unique to this run.
 *
 * Realm names are a flat namespace under their parent and the suite runs against a long-lived
 * instance, so a fixed name collides with whatever a previous failed run left behind. The counter is
 * there because two fixtures in one test can land in the same millisecond.
 */
export function uniqueRealmName (prefix = "e2e-realm") {
    sequence += 1;
    return `${prefix}-${Date.now().toString(36)}-${sequence}`;
}

/** Create a realm and return its path. */
export async function createRealm (adminToken, request, { name, parentPath = TOP_LEVEL_REALM,
    active = true, aliases = [] }) {
    const response = await request.post(`${REALMS_URL}?_action=create`, {
        headers: headers(adminToken, true),
        data: { name, parentPath, active, aliases },
    });

    if (!response.ok()) {
        throw await describeFailure(`Failed to create the realm "${name}"`, response);
    }
    return realmPathOf(name, parentPath);
}

/** Read a realm back, or null if there is no such realm. */
export async function readRealm (adminToken, request, path) {
    const response = await request.get(`${REALMS_URL}/${encodeRealmId(path)}`, {
        headers: headers(adminToken),
    });

    if (response.status() === 404) {
        return null;
    }
    if (!response.ok()) {
        throw await describeFailure(`Failed to read the realm "${path}"`, response);
    }
    return response.json();
}

/**
 * Remove a realm, tolerating one that is already gone.
 *
 * Teardown calls this for every realm a test caused to exist, including the ones the test deleted
 * through the console — so "already gone" is the successful case, not an error to report.
 */
export async function removeRealm (adminToken, request, path) {
    const response = await request.delete(`${REALMS_URL}/${encodeRealmId(path)}`, {
        headers: headers(adminToken),
    });

    if (!response.ok() && response.status() !== 404) {
        throw await describeFailure(`Failed to remove the realm "${path}"`, response);
    }
}
