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
 * Where each recorded call lands on disk, and how it is written.
 *
 * The tree mirrors the request path, so finding a response means walking the URL you would have
 * typed into curl. Capture order is not encoded in file names — it lives in index.json — because a
 * numeric prefix would renumber every later file the first time a request is inserted in the middle,
 * turning a one-line change into a whole-tree diff.
 *
 * **Directories keep `{realm}` and `{realmId}`; the recorded `request.path` inside resolves them.**
 * That asymmetry is deliberate, and it is the one thing about this layout that surprises people.
 * A directory name is a *route*: the local server has to answer requests for realms the specs invent
 * at run time under unique names, so a tree keyed on the one realm this capture happened to use
 * would answer none of them. The envelope inside is a *transcript*: it says what was actually sent
 * to produce this exact response, which is what makes the recording auditable rather than merely
 * plausible. index.json carries what the placeholders stood for on the day.
 *
 * Everything here exists to keep the output reviewable by a human: one call per file so a reordered
 * schema payload touches exactly one of them, keys in a fixed order, and a trailing newline so the
 * files behave in a diff.
 */

import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, sep } from "node:path";

/** `*` is a legal path segment for AM and an illegal filename on some platforms. */
function segment (text) {
    return text.replaceAll("*", "star").replaceAll(":", "_");
}

/**
 * The file a call is recorded in, relative to the capture root.
 *
 * Derived from the manifest entry, whose path still carries `{realm}` and `{realmId}` — see the
 * routes-versus-transcripts note above; this is where that decision is actually taken.
 *
 * The name is derived rather than declared, so it cannot drift from the request it describes. Where
 * derivation alone would collide — the same path and method at two API versions, or the 404 probe
 * that precedes a create — the manifest entry supplies an explicit `tag`, and writeCapture refuses
 * to write two calls to one path.
 */
export function relativePathFor (entry) {
    const directory = entry.path
        .replace(/^\//, "")
        .split("/")
        .map(segment)
        .join("/");

    const parts = [entry.method];
    const query = entry.query ?? {};

    if (query._action !== undefined) {
        parts.push(`action=${segment(query._action)}`);
    } else if (query._queryFilter !== undefined) {
        parts.push(`queryFilter=${segment(query._queryFilter)}`);
    }
    if (entry.tag) {
        parts.push(segment(entry.tag));
    }

    return join(directory, `${parts.join(".")}.json`);
}

/** Serialise with a trailing newline, so the file ends the way a text file should. */
function serialise (value) {
    return `${JSON.stringify(value, null, 2)}\n`;
}

/**
 * Remove what this run is about to write, and nothing else.
 *
 * A blanket delete of the output directory would take `capture/README.md` with it — the document
 * tasks 2.6, 2.10 and 2.11 read *instead of* the capture — and it would come back only if whoever
 * re-recorded happened to notice it had gone. Task 2.15 re-records on a schedule, with nobody
 * watching, so "happened to notice" is not a mechanism.
 *
 * Scoped to `index.json` plus the top-level directory each recorded call lands under, derived from the
 * records rather than hard-coded to `json/`, so a request path that does not begin `/json` cleans up
 * after itself too. Note the consequence of deriving it: a top-level directory that a *previous* run
 * wrote and this one no longer produces is left behind. Staleness inside `json/` is fully handled,
 * since that whole subtree goes; only a request path losing its first segment entirely would strand
 * anything, and a re-record then leaves a directory the index no longer references.
 *
 * The segment is checked before it reaches a recursive delete. It is assembled by string manipulation
 * from a manifest path, and `..` would resolve to the parent of `--out` — for the default that is
 * `local/`, holding the tool itself. Nothing in the manifest can produce it and nothing should have
 * to prove that again.
 */
export async function removeGenerated (outDir, records) {
    const generated = new Set(["index.json"]);
    for (const record of records) {
        const segment = relativePathFor(record.entry).split(sep)[0];
        if (segment === "" || segment === "." || segment === ".." || isAbsolute(segment)) {
            throw new Error(
                `Refusing to delete "${segment}" under ${outDir}: ${record.entry.id} derives a `
                + "capture path whose first segment escapes the output directory.",
            );
        }
        generated.add(segment);
    }

    for (const name of generated) {
        await rm(join(outDir, name), { recursive: true, force: true });
    }
    return [...generated];
}

/**
 * One recorded call.
 *
 * The request is recorded alongside the response and not merely referenced, because the response
 * shape sometimes depends on it: `GET /json/serverinfo/*` returns `_id` and `_rev` only when no
 * `Accept-API-Version` is negotiated, so a capture that dropped the request header would record a
 * shape nobody could explain later.
 *
 * Key order here is fixed by construction rather than sorted. Rule 14's recursive sort applies to
 * what AM sent; this envelope is ours, and request-before-response reads better than body-first.
 */
function envelope (record) {
    return {
        request: {
            method: record.request.method,
            path: record.request.path,
            query: record.request.query,
            acceptApiVersion: record.request.acceptApiVersion,
            session: record.request.session,
            body: record.request.body,
        },
        response: {
            status: record.response.status,
            headers: record.response.headers,
            body: record.response.body,
        },
    };
}

/**
 * Write the capture tree.
 *
 * `index.json` carries the capture order, which is not decoration: the authenticate exchange is
 * stateful, realm-scoped requests need the realm to exist, the `404` probes only answer `404` before
 * their create, and `PUT users/demo` permanently adds a `modifyTimestamp` key to every later `GET`.
 * Replaying these in a different order does not reproduce them.
 */
export async function writeCapture (outDir, records, meta) {
    const seen = new Map();
    const index = [];

    for (const [order, record] of records.entries()) {
        const relative = relativePathFor(record.entry);

        if (seen.has(relative)) {
            throw new Error(
                `Two calls derive the same capture file "${relative}": ${seen.get(relative)} and `
                + `${record.entry.id}. Give one of them a distinct "tag" in the manifest.`,
            );
        }
        seen.set(relative, record.entry.id);

        const absolute = join(outDir, relative);
        await mkdir(dirname(absolute), { recursive: true });
        await writeFile(absolute, serialise(envelope(record)), "utf8");

        index.push({
            order: order + 1,
            id: record.entry.id,
            file: relative,
            method: record.request.method,
            path: record.request.path,
            query: record.request.query,
            acceptApiVersion: record.request.acceptApiVersion,
            session: record.request.session,
            status: record.response.status,
            row: record.entry.row,
            // Why this call is here and why it looks the way it does, carried through from the
            // manifest. The capture is the artefact people read; leaving the explanation behind in
            // the tool that produced it helps nobody looking at a response and wondering.
            ...(record.entry.note ? { note: record.entry.note } : {}),
        });
    }

    await mkdir(outDir, { recursive: true });
    await writeFile(
        join(outDir, "index.json"),
        serialise({
            rules: meta.rules,
            // Every placeholder the capture can contain and what it stands for, so a reader who meets
            // one in a response body knows it is a substitution and not something AM said, and the
            // local server knows which of its own values to fill in. Meanings rather than the values
            // that were replaced — see PLACEHOLDERS in capture-lib/normalise.mjs.
            placeholders: meta.placeholders,
            // The placeholders that survive in file paths, and what they resolved to when this
            // capture was taken. A file path is a route and keeps them; the `path` recorded inside
            // each file is a transcript and does not.
            pathPlaceholders: meta.pathPlaceholders,
            callCount: index.length,
            calls: index,
        }),
        "utf8",
    );

    return index.length;
}
