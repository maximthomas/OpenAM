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
 * The capture, read from disk once — and the two ways a recorded payload may reach a client.
 *
 * This module does the reading and nothing else: it resolves a capture file to its recorded
 * response body with this deployment's values substituted in. What becomes *state* and what is
 * served *verbatim* is state.mjs's decision; see the note there.
 *
 * **Only the files a route needs are read.** `index.json` is small and always parsed; the 48
 * payloads are opened lazily and cached, so starting the server does not pull 136 KB of recorded
 * JSON — 56 % of which is three SMS schema documents — through the process for routes that will
 * never be called. A file named but absent throws at the point of use, naming it, because the
 * capture is re-recorded by task 2.15 and a call that quietly stopped being recorded would
 * otherwise surface as an empty response much later.
 *
 * **`{{DOUBLE_BRACE}}` placeholders are resolved here, and an unknown one is fatal.** The capture
 * has the recording host's origin, context path, cookie domain and LDAP suffixes stripped out of
 * it (capture/README.md, "Portability"), so every payload carries markers that mean "the serving
 * deployment's value goes here". Substituting them is what makes a body recorded against a
 * container correct under this server's own origin and `--context`. Throwing on a name this server
 * has no value for is the load-bearing half: a re-record that introduces a new placeholder must
 * stop the server rather than send `{{SOMETHING}}` to the browser, where it would arrive as a
 * plausible-looking string and fail somewhere with no connection to the cause.
 *
 * `<ANGLE>` markers are deliberately left alone. They stand for values that are volatile or secret
 * per call — session tokens, timestamps, the authentication `authId` — which a server mints per
 * request rather than substitutes at load. Nothing task 2.6 serves contains one; the routes that
 * do are tasks 2.7, 2.8 and 2.12, and each mints its own.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

/** `{{NAME}}` — the deployment placeholders. `<NAME>` is left for the task that mints it. */
const DEPLOYMENT_PLACEHOLDER = /\{\{([A-Z_]+)\}\}/g;

/**
 * `*` is a legal AM path segment and an illegal filename on some platforms, so the capture tree
 * spells it `star`. Same substitution as capture-lib/tree.mjs's, and it has to stay the same one:
 * these two functions are the write and read ends of one naming scheme.
 */
function segment (text) {
    return text.replaceAll("*", "star").replaceAll(":", "_");
}

/**
 * The capture file a request would have been recorded in.
 *
 * The mirror of capture-lib/tree.mjs's `relativePathFor`, which is why a recorded response can be
 * found by walking the URL you would have typed into curl. `path` is expected already in *route*
 * form — realm segments replaced by `{realm}` / `{realmId}` — because that substitution needs to
 * know which segment is a realm, which is routing knowledge and lives in rest.mjs.
 *
 * The discriminators derivable from a request are the two query ones. The capture's other tags
 * (`404`, `success`, `resource=1.1`) distinguish calls that a request alone cannot tell apart, so
 * they are addressed by naming the file, not by deriving it.
 */
export function captureFileFor ({ method, path, query = {} }) {
    const directory = path.replace(/^\//, "").split("/").map(segment).join("/");
    const parts = [method];

    if (query._action !== undefined) {
        parts.push(`action=${segment(query._action)}`);
    } else if (query._queryFilter !== undefined) {
        parts.push(`queryFilter=${segment(query._queryFilter)}`);
    }

    return `${directory}/${parts.join(".")}.json`;
}

/** Substitute this deployment's values, refusing to serve a marker this server cannot resolve. */
function resolveDeployment (value, deployment, file) {
    if (Array.isArray(value)) {
        return value.map((item) => resolveDeployment(item, deployment, file));
    }
    if (value && typeof value === "object") {
        return Object.fromEntries(Object.entries(value)
            .map(([key, item]) => [key, resolveDeployment(item, deployment, file)]));
    }
    if (typeof value !== "string") {
        return value;
    }
    return value.replaceAll(DEPLOYMENT_PLACEHOLDER, (marker, name) => {
        if (!(name in deployment)) {
            throw new Error(
                `${file} contains ${marker}, which the local API server has no value for. It is a `
                + "deployment placeholder (capture/README.md, \"Portability\"), so serving the "
                + "payload unresolved would send the marker to the browser. Give it a value in "
                + "server-lib/state.mjs's DEPLOYMENT, or stop serving this payload.",
            );
        }
        return deployment[name];
    });
}

/**
 * Open the capture.
 *
 * `deployment` maps placeholder names to this server's values — see DEPLOYMENT in state.mjs for
 * why the map is deliberately small.
 */
export function loadCapture (captureDir, deployment) {
    const indexFile = join(captureDir, "index.json");
    let index;
    try {
        index = JSON.parse(readFileSync(indexFile, "utf8"));
    } catch (error) {
        // Named, because the two ways this fails -- no capture directory at all, and an index a
        // half-finished re-record left unparseable -- both arrive here as a message that says
        // neither which file nor what it was for.
        throw new Error(`The local API server cannot read its capture index at ${indexFile}: `
            + `${error.message}`);
    }
    const calls = new Map(index.calls.map((call) => [call.file, call]));
    const bodies = new Map();

    /** The same complaint for a call that is named but not recorded, wherever it is asked for. */
    function requireCall (file) {
        const call = calls.get(file);
        if (!call) {
            throw new Error(
                `The capture has no ${file}. The local API server is built from that recording `
                + `(${captureDir}); if a re-record dropped the call, the server has to stop `
                + "serving it rather than answer with nothing.",
            );
        }
        return call;
    }

    /** The recorded response body for one capture file, resolved and cached. */
    function body (file) {
        if (!bodies.has(file)) {
            requireCall(file);
            const envelope = JSON.parse(readFileSync(join(captureDir, file), "utf8"));
            bodies.set(file, resolveDeployment(envelope.response.body, deployment, file));
        }
        return bodies.get(file);
    }

    return {
        /**
         * The order a call was recorded at — baseline state depends on it; see state.mjs.
         *
         * Throws for a call the capture does not have rather than answering `undefined`: the one
         * caller compares two orders to prove the baseline predates a mutation, and `undefined`
         * fails that comparison silently, reporting a recording that contains something it does
         * not instead of a call that has gone missing. A dropped call is exactly what task 2.15's
         * re-record can produce, so the guard must not misname it.
         */
        order: (file) => requireCall(file).order,
        /** Every recorded call whose `_action` is one of `actions`, as capture file paths. */
        filesForActions (actions) {
            return index.calls
                .filter((call) => actions.includes(call.query?._action))
                .map((call) => call.file);
        },
        body,
    };
}
