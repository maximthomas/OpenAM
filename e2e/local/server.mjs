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
 * The local API server: the XUI and the AM REST surface on one origin, with no AM.
 *
 *     npm run local-server                       # serve the built openam-ui-ria-*-www.zip
 *     npm run local-server -- path/to/www.zip    # serve some other zip
 *     npm run local-server -- path/to/outDir     # serve a directory, e.g. a Vite outDir
 *     node local/server.mjs --port 9000 --context am
 *
 * The second backend from D13. `openam-up.sh` gives you a real AM in three to eight minutes and a
 * container runtime; this gives you the same URLs in about a second and neither. It is what the
 * inner loop and the pull-request checks run against, and it is deliberately *not* the acceptance
 * oracle — tasks 1.13 and 10.1 stay on the deployed instance.
 *
 * **One origin, and the path prefix is not negotiable** (D14). `Constants.host` is `""` and
 * `Constants.context` is derived from `location.pathname`, so the XUI has no configurable backend
 * URL: it asks whatever origin served it, under the path it was served from. Serving the UI here
 * and the API somewhere else would need a UI change to reach, which would forfeit the "one build,
 * either backend" property that makes comparing the two backends mean anything. Hence `/{context}/
 * XUI/` and `/{context}/json/` on a single port, with `{context}` defaulting to the `openam` the
 * container instance uses.
 *
 * **One artifact, either backend.** What it serves is a `www` zip or a directory — the same two
 * inputs `xui-deploy.sh` takes, so the build proved against this server is the build deployed to
 * AM rather than something assumed to match it. A zip is unpacked to a temp directory that this
 * file removes on the way out; see server-lib/xui-source.mjs.
 *
 * **What it answers today: the XUI tree, the administrative reads, a session's whole life, the two
 * documents the bootstrap reads, and realm administration.** Task 2.6 builds an in-memory baseline
 * from local/capture at startup and answers realm and service reads out of it
 * (server-lib/state.mjs); task 2.7 adds the credential exchange and the session cookie, and 2.8 the
 * resolution of that cookie and the logout that ends it (server-lib/auth.mjs); 2.9 adds
 * `serverinfo/*`, which is the site configuration, and the footer's `serverinfo/version`; 2.10 adds
 * the realm writes, the one-call header authentication the fixtures provision through, and the
 * administrator's profile read. Service administration, the rest of the profile and reset are tasks
 * 2.11-2.13 and still answer a labelled 501. See server-lib/rest.mjs for why this stops where it
 * does rather than faking the rest.
 *
 * **A browser now bootstraps, logs in and lands in the admin console.** `serverinfo/*` is the only
 * request gating `EVENT_APP_INITIALIZED`, so answering it is what starts the UI at all; the profile
 * read task 2.10 borrowed from 2.12 is what carries the `roles` that get the default route off
 * `#login` [observed: xui/xui-realms.spec.mjs, 7 passed against this server]. What stops it next is
 * whatever a spec beyond realm administration reaches for — service administration is 2.11, the
 * `demo` profile and its update 2.12.
 *
 * `npm run test:server` demonstrates the surface directly; xui/xui-realms.spec.mjs is the first
 * `@local-server` spec that drives it through a browser (local/NOTES-auth.md §5, §8;
 * local/NOTES-siteconfig.md for the bootstrap order).
 *
 * This file is the process: settings, startup guards, the socket, the log and the shutdown. What
 * it answers with is in server-lib/, which is also where the tests are — same split as capture.mjs
 * and capture-lib.
 *
 * Node standard library only, deliberately: `e2e/package.json`'s single devDependency is the cache
 * key for the Playwright browser download in .github/workflows/xui-e2e.yml, so a dependency added
 * here costs every CI run a browser download. Same constraint as capture.mjs, same reason.
 */

import { createServer } from "node:http";
import { rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parseArgs, USAGE } from "./server-lib/options.mjs";
import { createRequestHandler } from "./server-lib/router.mjs";
import { buildBaselineState } from "./server-lib/state.mjs";
import { resolveXuiSource } from "./server-lib/xui-source.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
// As in lib.sh: this file sits at <repo>/e2e/local/.
const REPO_ROOT = resolve(HERE, "..", "..");
/** The recording the REST surface is built from. Committed alongside the server, by design (D15). */
const CAPTURE_DIR = resolve(HERE, "capture");

const log = (message) => process.stdout.write(`${message}\n`);

/**
 * One line per request that carries information, written when the response is done.
 *
 * From the response rather than from the handler, for two reasons. A response that dies after its
 * headers — the file that vanished mid-read — keeps its status here and so gets logged, where a
 * status threaded back through the call chain reported the 200 that was already a lie. And every
 * REST handler tasks 2.6-2.13 adds is now one that cannot forget to report itself.
 *
 * Every REST call is logged, with its query string: `?_action=idFromSession` is not a detail of
 * the request, it *is* the request. A static hit is logged only when it is not a plain 200 — a
 * single XUI page load fetches well over a hundred modules, and burying the one 404 among them in
 * the name of completeness would make the log worth reading exactly once.
 */
function logRequest (req, res, jsonMount) {
    if (req.url.split("?")[0].startsWith(jsonMount) || res.statusCode !== 200) {
        log(`${res.statusCode} ${req.method} ${req.url}`);
    }
}

async function main () {
    const options = parseArgs(process.argv.slice(2));
    if (options.help) {
        log(USAGE);
        return;
    }

    // Armed before the source is resolved, not after the socket is up, because unpacking a zip
    // *is* most of startup: ~650 files, and for that whole window a Ctrl-C used to meet Node's
    // default handler, which kills the process without running a `finally` and leaves the staging
    // directory on disk for good. That is also the likeliest Ctrl-C there is -- you start the
    // server, read the artifact it names in the banner, and stop it because it is the wrong one.
    //
    // One controller rather than two signal handlers per phase: every stage below asks the same
    // question, and asking it in one place is what stops a stage being added later that answers
    // it differently.
    const stopping = new AbortController();
    let staging = null;
    let stopped = false;

    const onSignal = (signal) => {
        // A second Ctrl-C means the graceful stop is taking longer than the operator is willing to
        // wait -- an unresponsive close, or the rm of ~650 files the first one started. Honour it,
        // but not by leaving the tree behind: remove it synchronously, because an async rm started
        // here would be abandoned unfinished, and then go. 128 + SIGINT, as a shell expects.
        if (stopped) {
            if (staging) {
                rmSync(staging, { recursive: true, force: true });
            }
            process.exit(130);
        }
        stopped = true;
        log(`\n${signal} -- stopping`);
        stopping.abort();
    };
    // `on` rather than `once`: the second signal has work to do above, and letting it reach Node's
    // default handler instead is what used to strand the tree. SIGKILL is now the only leak left,
    // and nothing in a process can do anything about that one.
    process.on("SIGINT", () => onSignal("SIGINT"));
    process.on("SIGTERM", () => onSignal("SIGTERM"));

    const xui = await resolveXuiSource(options.xui, {
        repoRoot: REPO_ROOT,
        signal: stopping.signal,
        // Not `xui.staging` after the fact: the handler above may need this while the unpack it
        // belongs to is still running, which is before there is an `xui` to read it from.
        onStaging: (dir) => { staging = dir; },
    });
    try {
        await serve(options, xui, stopping.signal);
    } finally {
        await xui.cleanup();
    }
}

/** Everything from the socket to the shutdown, with `root` already a canonical directory. */
async function serve (options, { root, source, staging }, stopping) {
    // Stopped during the unpack above: there is a tree staged and nothing else, and binding a port
    // only to close it again would put a banner on screen after the "stopping" line.
    if (stopping.aborted) {
        return;
    }

    // The host as the XUI will reach it, which is what the root realm's aliases have to agree
    // with. It depends on --host alone, so it is known before the socket is bound; the bound port
    // is not, and deliberately does not matter here -- capture/README.md records that `{{PORT}}`
    // appears nowhere in the capture and `{{BASE_URL}}` only in the `location` header of the realm
    // create, which is task 2.10's to serve and 2.10's to resolve from the bound port.
    const displayHost = ["0.0.0.0", "::"].includes(options.host) ? "localhost" : options.host;

    // Before the socket, so a capture that cannot be loaded stops the server without first taking
    // the port -- the failure an operator then has to diagnose is the one that happened, not an
    // EADDRINUSE from the corpse of this start.
    const state = buildBaselineState(CAPTURE_DIR, {
        context: options.context,
        hostname: displayHost,
    });

    const handle = createRequestHandler({ root, context: options.context, state });
    const jsonMount = `/${options.context}/json`;

    const server = createServer((req, res) => {
        res.on("finish", () => logRequest(req, res, jsonMount));
        handle(req, res).catch((error) => {
            log(`500 ${req.method} ${req.url}  ${error.message}`);
            if (!res.headersSent) {
                res.writeHead(500, { "Content-Type": "text/plain;charset=UTF-8" });
                res.end(`the local API server failed to handle this request: ${error.message}\n`);
                return;
            }
            // Too late to say anything the client will parse as a response.
            res.destroy();
        });
    });

    await new Promise((resolveListening, rejectListening) => {
        const onStartupError = (error) => rejectListening(error.code === "EADDRINUSE"
            ? new Error(`port ${options.port} is already in use.

Something is on it -- an earlier run of this server, or the AM container if you pointed this at
8080. Free it, or use --port / OPENAM_LOCAL_PORT.`)
            : error);

        server.once("error", onStartupError);
        server.listen(options.port, options.host, () => {
            // The startup listener has done its job; leaving it attached means a later error
            // rejects a settled promise, which is a no-op, while still counting as "handled" --
            // so the process would carry on with something wrong and nothing said.
            server.removeListener("error", onStartupError);
            server.on("error", (error) => process.stderr.write(`server error ${error.message}\n`));
            resolveListening();
        });
    });

    // Port 0 means "any free port", which is how a test harness starts one without picking.
    const boundPort = server.address().port;
    const origin = `http://${displayHost}:${boundPort}`;

    // The source, not the root: after a zip, `root` is a temp path that names nothing anyone
    // pointed at. The staging line is there so an unpacked tree is never a mystery directory.
    log(`local API server -- serving ${source}${staging
        ? `\n  unpacked to ${staging}  (removed on stop)`
        : ""}

  XUI   ${origin}/${options.context}/XUI/
  REST  ${origin}/${options.context}/json/   (${state.realms.size} realm(s) from the capture; 501
                                              outside the reads, authentication, sessions,
                                              the bootstrap's configuration and realm admin)

Point the suite or a fixture at it with:
  OPENAM_BASE_URL=${origin}/${options.context}

Ctrl-C to stop.`);

    await new Promise((resolveClosed) => {
        const close = () => {
            // Without this, an idle keep-alive connection from the browser holds the port for its
            // full timeout after close() is called, and the next start fails with EADDRINUSE for
            // reasons that look nothing like the cause. Node 18.2 and later.
            server.closeAllConnections();
            server.close(() => resolveClosed());
        };
        // Checked before the listener is attached, not only inside it: a signal delivered between
        // `listen` resolving and this line has already fired `abort`, and waiting for a second one
        // that is never coming would hang the process with the port still held.
        if (stopping.aborted) {
            return close();
        }
        stopping.addEventListener("abort", close, { once: true });
    });
}

try {
    await main();
} catch (error) {
    // A stop asked for during startup unwinds through here. It is not a failure, and reporting it
    // as one would make an ordinary Ctrl-C look like a broken zip.
    if (error.name !== "AbortError") {
        process.stderr.write(`error ${error.message}\n`);
        process.exitCode = 1;
    }
}
