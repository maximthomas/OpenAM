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
 * Reads the in-scope table out of local/REQUESTS.md, and checks the manifest against it.
 *
 * REQUESTS.md is the scope document — "a request absent from this document is out of scope by
 * construction" — but it is prose, and it deliberately carries neither request bodies, nor a capture
 * order, nor a binding for its `<realm>` and `<token>` placeholders. Several of its rows also expand
 * to more than one call: the `200, 404` probes are two calls whose order is the whole point.
 *
 * So the manifest carries that extra information, and this module is what stops the two drifting.
 * Every manifest entry names the REQUESTS.md row it implements, and a capture refuses to run unless
 * the two sides agree exactly: no in-scope row left uncovered, and no manifest entry pointing at a
 * row that no longer exists. Adding a request to the local server's surface is a scope decision that
 * REQUESTS.md documents; this check makes taking that decision in code alone impossible.
 */

import { readFile } from "node:fs/promises";

const IN_SCOPE_HEADING = "## In scope";
const OUT_OF_SCOPE_HEADING = "## Out of scope";

/** The em dash REQUESTS.md uses for "this column does not apply". */
const NOT_APPLICABLE = "—";

/**
 * Strip the markdown a cell is dressed in. Cells carry backticks, and the four `fixture only` rows
 * carry bold as well; neither is part of the value.
 */
function cellText (cell) {
    return cell.replaceAll("`", "").replaceAll("**", "").trim();
}

/** The key both sides agree on: method, path and the query that varies the response. */
export function rowKey ({ method, path, query }) {
    return `${method} ${path}${query ? ` ?${query}` : ""}`;
}

/**
 * Parse the in-scope table. Returns one entry per row, in document order.
 *
 * A row whose Status column lists more than one status is still one row — the expansion into
 * separate calls is the manifest's business, not this file's.
 */
export function parseInScope (markdown) {
    const start = markdown.indexOf(IN_SCOPE_HEADING);
    if (start === -1) {
        throw new Error(`REQUESTS.md has no "${IN_SCOPE_HEADING}" heading`);
    }
    const end = markdown.indexOf(OUT_OF_SCOPE_HEADING, start);
    if (end === -1) {
        throw new Error(`REQUESTS.md has no "${OUT_OF_SCOPE_HEADING}" heading`);
    }

    const rows = [];
    for (const line of markdown.slice(start, end).split("\n")) {
        if (!line.startsWith("|")) {
            continue;
        }

        const cells = line.split("|").slice(1, -1).map(cellText);
        const [method, path, query] = cells;

        // The header row and the |---|---| separator beneath it.
        if (method === "Method" || /^-+$/.test(method)) {
            continue;
        }
        if (!/^(GET|POST|PUT|DELETE)$/.test(method)) {
            continue;
        }

        // Column 8 is Status. A cell listing more than one — "200, 404" — is a row that only makes
        // sense as two calls, and checkCoverage holds the manifest to producing both.
        const statuses = cellText(cells[7] ?? "")
            .split(",")
            .map((status) => Number(status.trim()))
            .filter((status) => Number.isInteger(status));

        rows.push({ method, path, query: query === NOT_APPLICABLE ? "" : query, statuses });
    }

    if (rows.length === 0) {
        throw new Error("REQUESTS.md's in-scope table parsed to zero rows");
    }
    return rows;
}

/** Read and parse REQUESTS.md from disk. */
export async function readInScope (path) {
    return parseInScope(await readFile(path, "utf8"));
}

/**
 * Check the manifest covers the in-scope table exactly, and throw with the full picture if not.
 *
 * Three ways to disagree, failing for three different reasons. An uncovered row means the capture is
 * incomplete and the local server will be missing a response the specs need. An entry naming a row
 * that does not exist means either a typo or a request that quietly left the documented scope. And a
 * status mismatch means the row and the calls implementing it describe different behaviour — most
 * often a `200, 404` row whose expansion into two calls was only half done, which is the failure that
 * would otherwise show up as a capture that is quietly missing its error case.
 */
export function checkCoverage (rows, entries) {
    const documented = new Map(rows.map((row) => [rowKey(row), row]));
    const implemented = new Set(entries.map((entry) => rowKey(entry.row)));

    const uncovered = [...documented.keys()].filter((key) => !implemented.has(key));
    const unknown = [...implemented].filter((key) => !documented.has(key));

    const statusProblems = [];
    for (const entry of entries) {
        const row = documented.get(rowKey(entry.row));
        if (row && !row.statuses.includes(entry.expect)) {
            statusProblems.push(`  - ${entry.id} expects ${entry.expect}; REQUESTS.md lists `
                + `${row.statuses.join(", ")} for ${rowKey(entry.row)}`);
        }
    }
    for (const [key, row] of documented) {
        const produced = new Set(
            entries.filter((entry) => rowKey(entry.row) === key).map((entry) => entry.expect),
        );
        for (const status of row.statuses) {
            if (!produced.has(status)) {
                statusProblems.push(`  - ${key} documents ${status}; no manifest entry produces it`);
            }
        }
    }

    if (uncovered.length === 0 && unknown.length === 0 && statusProblems.length === 0) {
        return { rows: documented.size, calls: entries.length };
    }

    const complaint = ["The capture manifest and REQUESTS.md disagree."];
    if (uncovered.length > 0) {
        complaint.push(
            "",
            `${uncovered.length} in-scope row(s) no manifest entry covers:`,
            ...uncovered.map((key) => `  - ${key}`),
        );
    }
    if (unknown.length > 0) {
        complaint.push(
            "",
            `${unknown.length} manifest entr(y/ies) naming a row REQUESTS.md does not list:`,
            ...unknown.map((key) => `  - ${key}`),
            "",
            "Adding a request to the local server's surface is a scope decision (REQUESTS.md,",
            "\"This list is the scope\"). Record it there first.",
        );
    }
    if (statusProblems.length > 0) {
        complaint.push("", `${statusProblems.length} status mismatch(es):`, ...statusProblems);
    }
    throw new Error(complaint.join("\n"));
}
