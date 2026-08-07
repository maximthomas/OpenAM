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
 * Realm-scoped service fixtures for the console specs: which service types a realm may still be
 * given, and creating and reading one over AM's REST API.
 *
 * The same reasoning as realms-commons.mjs — a spec about the console should not have to establish
 * its premise through the console. xui-services.spec.mjs drives create, edit and delete through the
 * UI, and the tests whose subject is editing or deleting need a service that already exists.
 *
 * Nothing here removes a service. It does not need to: a service belongs to a realm, and the specs
 * give every test its own scratch realm, so removing the realm removes anything configured in it.
 * That matters more here than it does for realms, because a leftover service does not merely
 * pollute a listing — getCreatableTypes stops offering a type the realm already has, so it changes
 * what the create form can do on the next run. See the idempotency note in xui-services.spec.mjs.
 */

import { OPENAM_BASE, describeFailure } from "./openam-commons.mjs";

const SERVICES_URL = `${OPENAM_BASE}/json/realm-config/services`;

/** The version the console's ServicesService asks these endpoints for. */
const API_VERSION = "protocol=1.0,resource=1.0";

function headers (adminToken, withBody = false) {
    return {
        "iPlanetDirectoryPro": adminToken,
        "Accept-API-Version": API_VERSION,
        ...(withBody ? { "Content-Type": "application/json" } : {}),
    };
}

/**
 * A service endpoint for a realm.
 *
 * The realm travels as a query parameter rather than in the path, and it is the realm *path*
 * ("/alpha") rather than the base64url id realms are addressed by — services are the other of the
 * two conventions this console uses to name a realm.
 */
function serviceUrl (realmPath, type = "", query = "") {
    const realm = `realm=${encodeURIComponent(realmPath)}`;
    return `${SERVICES_URL}${type ? `/${type}` : ""}?${query ? `${query}&` : ""}${realm}`;
}

/**
 * The service types the console may still offer to create in a realm, as `{ _id, name }` entries.
 *
 * This is the list behind the create form's type selector, and it is computed from what the realm
 * already has: a type present in the realm is not returned. `forUI=true` is the console's own call —
 * it is what sorts the result and resolves each type's display name.
 */
export async function creatableServiceTypes (adminToken, request, realmPath) {
    const response = await request.post(
        serviceUrl(realmPath, "", "_action=getCreatableTypes&forUI=true"),
        { headers: headers(adminToken, true) }
    );

    if (!response.ok()) {
        throw await describeFailure(`Failed to list creatable service types in "${realmPath}"`, response);
    }
    return (await response.json()).result;
}

/** Create a service in a realm and return what AM stored. */
export async function createService (adminToken, request, realmPath, type, values) {
    const response = await request.post(serviceUrl(realmPath, type, "_action=create"), {
        headers: headers(adminToken, true),
        data: values,
    });

    if (!response.ok()) {
        throw await describeFailure(`Failed to create the "${type}" service in "${realmPath}"`, response);
    }
    return response.json();
}

/** Read a service back, or null if the realm does not have one of that type. */
export async function readService (adminToken, request, realmPath, type) {
    const response = await request.get(serviceUrl(realmPath, type), {
        headers: headers(adminToken),
    });

    if (response.status() === 404) {
        return null;
    }
    if (!response.ok()) {
        throw await describeFailure(`Failed to read the "${type}" service in "${realmPath}"`, response);
    }
    return response.json();
}
