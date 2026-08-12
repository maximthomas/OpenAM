#!/usr/bin/env node
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
 * Record the local backend's capture from a real AM.
 *
 *     node local/capture.mjs [--out DIR] [--base-url URL] [--realm NAME]
 *
 * Drives the instance from local/openam-up.sh through every in-scope request in local/REQUESTS.md,
 * normalises what AM varies between identical calls, and writes a capture tree that a re-record
 * against an unchanged instance reproduces byte for byte. See local/NOTES-volatility.md for why each
 * rule exists, and D15 for why the shapes are recorded rather than hand-authored.
 *
 * The run is re-runnable rather than one-shot: it removes a realm an earlier failed run left behind
 * before it starts, and it ends every session it opened even when the capture itself throws. A tool
 * whose recovery path is "work out by hand what the last failure left on the instance" is not one
 * that can sit behind a CI job.
 *
 * Node standard library only, deliberately: e2e/package.json's single devDependency is the cache key
 * for the Playwright browser download in .github/workflows/xui-e2e.yml, and a capture tool is not a
 * good enough reason to invalidate it.
 */

import { readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
    ADMIN_PASS, ADMIN_USER, OPENAM_BASE, PASSWORD, USERNAME,
} from "../common/openam-commons.mjs";
import { buildManifest, CAPTURE_REALM, encodeRealmId } from "./capture-lib/manifest.mjs";
import {
    auditPortability, maskCredentials, normaliseHeaders, normaliseJson, normalisePortableText,
    normalisePortableValues, PLACEHOLDERS, portabilityTargets,
} from "./capture-lib/normalise.mjs";
import { checkCoverage, readInScope } from "./capture-lib/requests-md.mjs";
import { removeGenerated, writeCapture } from "./capture-lib/tree.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

const USAGE = "node local/capture.mjs [--out DIR] [--base-url URL] [--realm NAME]";

/**
 * Where the instance is and who to talk to it as.
 *
 * Taken from common/openam-commons.mjs rather than re-declared, so the capture tool and the
 * Playwright fixtures cannot end up authenticating against the same instance with different
 * credentials — a divergence that surfaces as a 401 naming no cause.
 */
const DEFAULTS = {
    out: join(HERE, "capture"),
    baseUrl: OPENAM_BASE,
    realm: CAPTURE_REALM,
    adminUser: ADMIN_USER,
    adminPassword: ADMIN_PASS,
    demoUser: USERNAME,
    demoPassword: PASSWORD,
};

/** The versions the tool's own housekeeping calls negotiate; the manifest carries the rest. */
const SMS_VERSION = "protocol=1.0,resource=1.0";
const SESSION_VERSION = "protocol=1.0,resource=2.0";
const LEGACY_AUTHN_VERSION = "resource=2.0, protocol=1.0";

function parseArgs (argv) {
    const options = { ...DEFAULTS };
    for (let i = 0; i < argv.length; i += 1) {
        const flag = argv[i];
        const value = argv[i + 1];
        if (flag === "--out" || flag === "--base-url" || flag === "--realm") {
            if (value === undefined) {
                throw new Error(`${flag} needs a value`);
            }
            options[flag === "--base-url" ? "baseUrl" : flag.slice(2)] = value;
            i += 1;
        } else if (flag === "--help" || flag === "-h") {
            options.help = true;
        } else {
            throw new Error(`Unknown argument "${flag}". Try --help.`);
        }
    }
    options.out = resolve(options.out);
    options.baseUrl = options.baseUrl.replace(/\/$/, "");
    return options;
}

const log = (message) => process.stdout.write(`${message}\n`);

/**
 * Refuse to run on a Node too old for the APIs the capture depends on.
 *
 * `Headers.getSetCookie()` landed in Node 18.16. Where it is missing a capture still runs and still
 * looks plausible — it just silently drops every `Set-Cookie` line, because iterating a Headers
 * object folds them into one comma-joined string. A stable but wrong output is the single failure
 * mode a fixture source must not have, so this is a hard error rather than a fallback.
 */
function checkRuntime () {
    if (typeof new Headers().getSetCookie !== "function") {
        throw new Error(
            `Node ${process.version} has no Headers.getSetCookie(), which the capture needs to `
            + "record Set-Cookie without folding the cookies together. Use Node 20 or later.",
        );
    }
}

/**
 * Check the output directory is one we may overwrite, without touching it yet.
 *
 * Called before the first request so a mistyped `--out` fails immediately, while the delete itself
 * waits until the capture is complete in memory — the default `--out` is the tree task 2.3 commits,
 * and a re-record against an unreachable instance should not destroy the baseline it failed to
 * replace.
 */
async function checkOutput (outDir) {
    let existing;
    try {
        existing = await readdir(outDir);
    } catch (error) {
        if (error.code === "ENOENT") {
            return;
        }
        throw error;
    }

    // README.md does not count towards "looks like a capture": it is committed alongside the tree and
    // is not written by this tool, so on its own it says nothing about what the directory is.
    const written = existing.filter((name) => name !== "README.md");

    if (written.length > 0 && !written.includes("index.json")) {
        throw new Error(
            `${outDir} is not empty and does not look like a capture (no index.json). Refusing to `
            + "delete it. If a previous run died partway through writing, restore the directory "
            + `(git checkout -- ${outDir}) or empty it; otherwise pass --out somewhere else.`,
        );
    }
}

/** Build the query string, substituting the one placeholder that varies per run. */
function resolveQuery (query, token) {
    const resolved = {};
    for (const [key, value] of Object.entries(query ?? {})) {
        resolved[key] = value === "{token}" ? token : value;
    }
    return resolved;
}

function resolvePath (path, { realm, realmId }) {
    return path.replaceAll("{realm}", realm).replaceAll("{realmId}", realmId);
}

async function main () {
    const options = parseArgs(process.argv.slice(2));
    if (options.help) {
        log(USAGE);
        return 0;
    }

    checkRuntime();

    const realmId = encodeRealmId(`/${options.realm}`);
    const manifest = buildManifest(options);

    /** What about this deployment must not survive into the committed capture. */
    const targets = portabilityTargets(options.baseUrl);

    // Refuse to record anything until the plan and the scope document agree.
    const rows = await readInScope(join(HERE, "REQUESTS.md"));
    const coverage = checkCoverage(rows, manifest);
    log(`REQUESTS.md: ${coverage.rows} in-scope rows, covered by ${coverage.calls} calls`);

    await checkOutput(options.out);

    const sessions = { none: null };
    const raw = new Map();
    const records = [];

    /** What must not reach the committed capture: the passwords this run authenticates with. */
    const credentials = new Set([options.demoPassword, options.adminPassword].filter(Boolean));

    /** Issue a request. Callers outside the manifest loop are housekeeping and are not recorded. */
    async function issue ({ method, path, query, version, session, headers, body }) {
        const token = sessions[session] ?? null;
        const search = new URLSearchParams(resolveQuery(query, token));
        const url = `${options.baseUrl}${resolvePath(path, { realm: options.realm, realmId })}`
            + `${search.size > 0 ? `?${search}` : ""}`;

        const sent = {
            "Content-Type": "application/json",
            ...(version ? { "Accept-API-Version": version } : {}),
            ...(token ? { iPlanetDirectoryPro: token } : {}),
            ...headers,
        };

        let response;
        try {
            response = await fetch(url, {
                method,
                headers: sent,
                body: body === undefined ? undefined : (typeof body === "string" ? body
                    : JSON.stringify(body)),
                redirect: "manual",
            });
        } catch (error) {
            // Node's fetch throws a bare "fetch failed" that names neither the URL nor the reason.
            // Both are in `cause`, which main()'s handler walks.
            throw new Error(`${method} ${url} failed before AM answered`, { cause: error });
        }

        const text = await response.text();
        let parsed = null;
        if (text.length > 0) {
            try {
                parsed = JSON.parse(text);
            } catch {
                throw new Error(`${method} ${url} answered ${response.status} with a non-JSON body:`
                    + `\n${text.slice(0, 400)}`);
            }
        }
        return { response, parsed };
    }

    /** The context a manifest body resolver sees. */
    const context = {
        raw: (id) => {
            if (!raw.has(id)) {
                throw new Error(`No captured response for "${id}" — is it ordered after this call?`);
            }
            return structuredClone(raw.get(id));
        },
        get: async (path, version, extra = {}) => {
            const { response, parsed } = await issue({
                method: extra.method ?? "GET",
                path,
                query: extra.query ?? {},
                version,
                session: extra.session ?? "admin",
                headers: extra.headers,
                body: extra.body,
            });
            if (!response.ok) {
                throw new Error(`Setup read ${path} answered ${response.status}`);
            }
            return parsed;
        },
    };

    /** Authenticate as the admin, on a session of our own. */
    async function login (name) {
        const { response, parsed } = await issue({
            method: "POST",
            path: "/json/authenticate",
            version: LEGACY_AUTHN_VERSION,
            session: "none",
            headers: {
                "X-OpenAM-Username": options.adminUser,
                "X-OpenAM-Password": options.adminPassword,
            },
            body: "",
        });
        if (typeof parsed?.tokenId !== "string") {
            throw new Error(`Could not authenticate ${options.adminUser} against `
                + `${options.baseUrl}: HTTP ${response.status}. Is the instance up and configured?`);
        }
        sessions[name] = parsed.tokenId;
    }

    /**
     * What the run failed to give back. Collected rather than thrown, because the cleanup that
     * discovers it runs in a `finally` and must not replace the failure that sent it there.
     */
    const problems = [];

    /** End one session, reporting rather than throwing. */
    async function logout (name) {
        if (!sessions[name]) {
            return;
        }
        try {
            const { response } = await issue({
                method: "POST",
                path: "/json/sessions",
                query: { _action: "logout", tokenId: "{token}" },
                version: SESSION_VERSION,
                session: name,
                body: {},
            });
            log(`logout ${name}: ${response.status}`);
            if (response.status === 200) {
                sessions[name] = null;
            } else {
                problems.push(`logout ${name} answered ${response.status}, not 200`);
            }
        } catch (error) {
            problems.push(`logout ${name} failed: ${error.message}`);
        }
    }

    /**
     * Remove what an earlier failed run left on the instance.
     *
     * A capture that dies between the realm create and the realm delete leaves the capture realm
     * behind, and the next run then fails at `realm-get-missing` — which expects a 404 and wants the
     * realm absent anyway. Clearing it here makes the run idempotent instead of needing a hand
     * cleanup nobody would deduce from the error. The realm is this tool's own: it creates, uses and
     * deletes it, so removing a stale one is not a surprise.
     *
     * It doubles as the reachability check, which is why it authenticates first: "cannot log in to
     * this instance" is a better first failure than the same thing reported from call 8.
     */
    async function preflight () {
        await login("preflight");
        const { response } = await issue({
            method: "DELETE",
            path: "/json/global-config/realms/{realmId}",
            version: SMS_VERSION,
            session: "preflight",
        });
        if (response.status === 200) {
            log(`preflight: removed a leftover /${options.realm} from an earlier run`);
        } else if (response.status !== 404) {
            throw new Error(`preflight: DELETE /${options.realm} answered ${response.status}; `
                + "expected 200 (a leftover realm) or 404 (a clean instance).");
        }

        // Ended before the recording starts rather than in teardown, so the capture runs against an
        // instance holding exactly the sessions it opened itself and none of the tool's own
        // housekeeping. Teardown is still the safety net if this is never reached.
        await logout("preflight");
    }

    /**
     * Give the instance back as it was found.
     *
     * Runs in a `finally`, so it must not throw — an error here would replace the failure that
     * caused it. What it could not undo goes into `problems`, which the caller raises only when the
     * capture itself succeeded: a session left open is a real failure, but not the one to report
     * first when something else already went wrong.
     */
    async function teardown (completed) {
        // Only when the run did not reach its own `realm-delete`. After a clean run the realm is
        // already gone and this would be a pointless 404.
        if (!completed && sessions.admin) {
            try {
                const { response } = await issue({
                    method: "DELETE",
                    path: "/json/global-config/realms/{realmId}",
                    version: SMS_VERSION,
                    session: "admin",
                });
                if (response.status === 200) {
                    log(`teardown: removed /${options.realm}`);
                }
            } catch (error) {
                problems.push(`could not remove /${options.realm}: ${error.message}`);
            }
        }

        for (const name of ["preflight", "demo", "admin"]) {
            await logout(name);
        }
    }

    let written = 0;
    let completed = false;

    try {
        await preflight();

        for (const entry of manifest) {
            const body = typeof entry.body === "function" ? await entry.body(context) : entry.body;
            // Read before issuing: the logout row ends its own session, and the recorded request
            // still has to show the token it was sent with rather than the null it left behind.
            const usedToken = sessions[entry.session] ?? null;
            const { response, parsed } = await issue({ ...entry, body });

            if (response.status !== entry.expect) {
                throw new Error(
                    `${entry.id}: expected HTTP ${entry.expect} from ${entry.method} ${entry.path}, `
                    + `got ${response.status}.\n${JSON.stringify(parsed)?.slice(0, 400) ?? ""}`,
                );
            }

            raw.set(entry.id, parsed);
            if (entry.provides) {
                if (typeof parsed?.tokenId !== "string") {
                    throw new Error(`${entry.id} is what establishes the "${entry.provides}" `
                        + `session, but its ${response.status} carried no tokenId. Every later call `
                        + "on that session would fail with an unexplained 401.");
                }
                sessions[entry.provides] = parsed.tokenId;
            }
            // One of the in-scope rows *is* a logout, so that session is already ended and must not
            // be logged out again in teardown: the call is one-shot and answers 401 the second time.
            if (entry.ends) {
                sessions[entry.ends] = null;
            }

            // The rules that are not about volatility, kept out of the fourteen on purpose: what may
            // not be committed at all (the password this run authenticated with) and what pins the
            // capture to this box (its origin, deployment URI, cookie domain, DNS aliases, LDAP
            // suffixes and server id). Every value either one touches was measured stable across a
            // reconfigure, so neither can create or hide a re-record diff.
            const scrub = (value) => (value === null || value === undefined
                ? value
                : maskCredentials(
                    normalisePortableValues(
                        JSON.parse(normalisePortableText(JSON.stringify(value), targets)),
                        targets,
                    ),
                    credentials,
                ));

            const record = {
                entry,
                request: {
                    method: entry.method,
                    path: resolvePath(entry.path, { realm: options.realm, realmId }),
                    query: scrub(normaliseJson(resolveQuery(entry.query, usedToken))),
                    acceptApiVersion: entry.version ?? null,
                    session: entry.session,
                    body: body === undefined || body === "" ? null : scrub(normaliseJson(body)),
                },
                response: {
                    status: response.status,
                    headers: scrub(normaliseHeaders(response.headers,
                        response.headers.getSetCookie())),
                    body: scrub(normaliseJson(parsed)),
                },
            };

            // Checked here rather than over the finished tree so the failure names the call that
            // produced it, and so nothing is written at all: a capture is committed once and read for
            // the rest of the change, and a host value that reaches it outlives the revert.
            const survivors = auditPortability(
                JSON.stringify({ request: record.request, response: record.response }),
                targets,
            );
            if (survivors.length > 0) {
                throw new Error(
                    `${entry.id}: after normalisation the response still carries `
                    + `${survivors.join(", ")}. The instance no longer matches what `
                    + "local/capture-lib/normalise.mjs was told to erase. Fix the rule, not the "
                    + "recorded file — task 2.15 re-records this capture and a hand edit is lost.",
                );
            }

            records.push(record);
            log(`  ${String(records.length).padStart(2)} ${response.status} ${entry.id}`);
        }

        // Only now: the whole capture is in memory, so the previous one can be replaced rather than
        // destroyed on the way to a run that might not finish. Scoped to what this tool generates, so
        // the README committed alongside the tree survives a re-record.
        const removed = await removeGenerated(options.out, records);
        log(`\nreplacing ${removed.sort().join(", ")} in ${options.out}`);
        written = await writeCapture(options.out, records, {
            rules: "local/NOTES-volatility.md",
            placeholders: PLACEHOLDERS,
            pathPlaceholders: { "{realm}": options.realm, "{realmId}": realmId },
        });
        completed = true;
    } finally {
        await teardown(completed);
    }

    if (problems.length > 0) {
        throw new Error("The capture was written, but the instance was not fully given back:\n"
            + problems.map((problem) => `  - ${problem}`).join("\n"));
    }

    log(`\nWrote ${written} calls to ${options.out}`);
    return 0;
}

process.exitCode = await main().catch((error) => {
    process.stderr.write(`${error.stack ?? error}\n`);
    // Node's fetch reports "fetch failed" and puts the reason that matters — ECONNREFUSED, a DNS
    // failure, a TLS error — in `cause`. Unwalked, the tool's most common failure has no diagnosis
    // at all, and the sibling CI job in task 2.15 is exactly where nobody can attach a debugger.
    let cause = error.cause;
    for (let depth = 0; cause && depth < 8; depth += 1) {
        process.stderr.write(`  caused by: ${cause.stack ?? cause}\n`);
        cause = cause.cause;
    }
    return 1;
});
