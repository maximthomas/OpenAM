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
 * Realm-scoped authentication module fixtures for the console specs: the module types a realm may be
 * given, and creating, reading, listing and removing a module instance over AM's REST API — plus the
 * per-type schema the console generates its edit form from.
 *
 * The same reasoning as services-commons.mjs: a spec about the console should not establish its own
 * premise through the console. xui-auth-modules.spec.mjs drives create, edit and delete through the
 * UI, and the tests whose subject is editing or deleting need a module that already exists.
 *
 * Two differences from services-commons.mjs are worth naming here, because they are why this is a
 * separate module rather than a few more exports there:
 *
 *   - a realm holds at most one service of a type, but any number of *named instances* of a module
 *     type. Everything below is addressed by (type, name) rather than by type alone;
 *   - the realm travels in the path rather than as a `?realm=` query parameter. See realmRestBase.
 *
 * Nothing here removes a module in the normal course of things. It does not need to: a module belongs
 * to a realm, and the spec gives every test its own scratch realm, so removing the realm removes
 * every module in it — verified, a realm deletes cleanly with modules still configured. removeModule
 * is for a future test that needs an instance gone without its realm going with it; teardown has no
 * use for it. Asserting that a deletion happened is moduleExists, not this.
 *
 * Task 1.15 (authentication chains) assembles a chain out of module instances and will need
 * createModule in particular, which is why these live here rather than inside the spec.
 */

import { OPENAM_BASE, describeFailure } from "./openam-commons.mjs";
import { TOP_LEVEL_REALM } from "./realms-commons.mjs";

/** The version the console's authentication services ask these endpoints for. */
const API_VERSION = "protocol=1.0,resource=1.0";

function headers (adminToken, withBody = false) {
    return {
        "iPlanetDirectoryPro": adminToken,
        "Accept-API-Version": API_VERSION,
        ...(withBody ? { "Content-Type": "application/json" } : {}),
    };
}

/**
 * The REST base for a realm's own configuration, composed the way the console's `fetchUrl` composes
 * it: the realm is a path of nested `/realms/` segments rather than the `?realm=` query parameter
 * that realm-config/services takes, and the top level realm is `realms/root` rather than empty.
 *
 * So "/" is ".../json/realms/root" and "/alpha" is ".../json/realms/root/realms/alpha". This is the
 * third of the three ways this codebase names a realm — realms-commons has the other two, the
 * base64url resource id and the encodeURIComponent console hash.
 */
export function realmRestBase (realmPath) {
    const segments = (realmPath ?? TOP_LEVEL_REALM).split("/").filter(Boolean);
    const nested = segments.map((segment) => `/realms/${encodeURIComponent(segment)}`).join("");

    return `${OPENAM_BASE}/json/realms/root${nested}`;
}

function modulesUrl (realmPath, path = "", query = "") {
    return `${realmRestBase(realmPath)}/realm-config/authentication/modules${path}${query ? `?${query}` : ""}`;
}

function instancePath (type, name) {
    return `/${encodeURIComponent(type)}/${encodeURIComponent(name)}`;
}

/**
 * Every authentication module type the realm can be given, as `{ _id, name }` entries.
 *
 * Note what this is *not*: unlike getCreatableTypes for services, this list does not depend on what
 * the realm already contains — a type stays on offer however many instances of it exist, because
 * instances are named. That is the whole of why this spec's idempotency story differs from the
 * service spec's, and xui-auth-modules.spec.mjs asserts it rather than trusting this comment.
 */
export async function moduleTypes (adminToken, request, realmPath) {
    const response = await request.post(modulesUrl(realmPath, "", "_action=getAllTypes"), {
        headers: headers(adminToken, true),
    });

    if (!response.ok()) {
        throw await describeFailure(`Failed to list module types in "${realmPath}"`, response);
    }
    return (await response.json()).result;
}

/**
 * The JSON schema for a module type, which is what the console's edit form is generated from.
 *
 * Fetched by the spec so the rendered fields can be checked against the schema's own property names
 * rather than against a list of them copied into the spec: that is the difference between asserting
 * the form was generated and asserting it looks like it did on the day the test was written.
 */
export async function moduleSchema (adminToken, request, realmPath, type) {
    const response = await request.post(
        modulesUrl(realmPath, `/${encodeURIComponent(type)}`, "_action=schema"),
        { headers: headers(adminToken, true) }
    );

    if (!response.ok()) {
        throw await describeFailure(`Failed to read the "${type}" module schema in "${realmPath}"`, response);
    }
    return response.json();
}

/**
 * Create a named module instance and return what AM stored.
 *
 * `values` is optional and usually omitted: AM fills an instance created with nothing but a name from
 * the type's template, which is exactly what the console's create form does — it posts `{_id}` and no
 * configuration at all.
 */
export async function createModule (adminToken, request, realmPath, type, name, values = {}) {
    const response = await request.post(
        modulesUrl(realmPath, `/${encodeURIComponent(type)}`, "_action=create"),
        { headers: headers(adminToken, true), data: { _id: name, ...values } }
    );

    if (!response.ok()) {
        throw await describeFailure(
            `Failed to create the "${type}" module "${name}" in "${realmPath}"`, response);
    }
    return response.json();
}

/**
 * Read a module instance back, or null if there is no such instance.
 *
 * The type segment genuinely selects the instance rather than merely decorating the URL: a GET with
 * the wrong type for an existing name is a 404, not the instance.
 *
 * The `_id` check is not belt and braces, and this is the one piece of AM behaviour in this file that
 * a caller cannot guess. A GET for a name that never existed is a 404 — but a GET for a name that
 * existed and was *deleted* answers 200 with the type's template defaults and an **empty `_id`**:
 *
 *     GET .../modules/securid/neverExisted   -> 404
 *     GET .../modules/securid/deletedName    -> 200 {"serverConfigPath":"/usr/openam/...",
 *                                                    "authenticationLevel":0,"_id":""}
 *
 * while `_queryFilter` and the list agree in both cases that the instance is gone. So a bare status
 * check would report a deleted module as present, with plausible-looking configuration — which is
 * precisely the assertion a delete test makes. Anything whose `_id` is not the name that was asked
 * for is AM declining to say there is such an instance, and is reported here as absence.
 */
export async function readModule (adminToken, request, realmPath, type, name) {
    const response = await request.get(modulesUrl(realmPath, instancePath(type, name)), {
        headers: headers(adminToken),
    });

    if (response.status() === 404) {
        return null;
    }
    if (!response.ok()) {
        throw await describeFailure(
            `Failed to read the "${type}" module "${name}" in "${realmPath}"`, response);
    }
    const module = await response.json();

    return module._id === name ? module : null;
}

/**
 * Whether a realm has a module instance of that name, asked the way the console asks it.
 *
 * This is AddModuleView's own pre-flight check, and it queries the name across *every* type rather
 * than within one — which is why the console refuses a duplicate name under a different type that AM
 * itself would accept. It is also the authoritative answer to "is it gone", for the reason readModule
 * documents above.
 */
export async function moduleExists (adminToken, request, realmPath, name) {
    const filter = encodeURIComponent(`_id eq "${name}"`);
    const response = await request.get(
        modulesUrl(realmPath, "", `_queryFilter=${filter}&_fields=_id`),
        { headers: headers(adminToken) }
    );

    if (!response.ok()) {
        throw await describeFailure(
            `Failed to check for the module "${name}" in "${realmPath}"`, response);
    }
    return (await response.json()).result.length > 0;
}

/** Every module instance configured in a realm, including the ones a new realm is seeded with. */
export async function listModules (adminToken, request, realmPath) {
    const response = await request.get(modulesUrl(realmPath, "", "_queryFilter=true"), {
        headers: headers(adminToken),
    });

    if (!response.ok()) {
        throw await describeFailure(`Failed to list the modules in "${realmPath}"`, response);
    }
    return (await response.json()).result;
}

/** Remove a module instance, tolerating one that is already gone. */
export async function removeModule (adminToken, request, realmPath, type, name) {
    const response = await request.delete(modulesUrl(realmPath, instancePath(type, name)), {
        headers: headers(adminToken),
    });

    if (!response.ok() && response.status() !== 404) {
        throw await describeFailure(
            `Failed to remove the "${type}" module "${name}" in "${realmPath}"`, response);
    }
}
