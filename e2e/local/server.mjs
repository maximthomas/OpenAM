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
 *     npm run local-server                       # serve the built XUI from target/compiled
 *     npm run local-server -- path/to/outDir     # serve some other tree
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
 * **What it answers today: the XUI tree, and 501 for every REST call.** The REST surface is tasks
 * 2.6-2.13. See server-lib/rest.mjs for why this stops at a labelled 501 rather than faking enough
 * of a backend to get the login form to render.
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
import { realpath, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parseArgs, USAGE } from "./server-lib/options.mjs";
import { createRequestHandler } from "./server-lib/router.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
// As in lib.sh: this file sits at <repo>/e2e/local/.
const REPO_ROOT = resolve(HERE, "..", "..");

const log = (message) => process.stdout.write(`${message}\n`);

/**
 * Refuse to start on something that is not a deployed XUI tree.
 *
 * The failure this prevents is a server that starts happily and answers 404 for every module, at
 * which point the browser console blames RequireJS and the tree that was never there is the last
 * thing anyone checks. Same guard, and mostly the same wording, as xui-deploy.sh.
 */
async function checkXuiTree (dir) {
    let info;
    try {
        info = await stat(dir);
    } catch {
        throw new Error(`no XUI tree at ${dir}

Build it first:
    cd ${REPO_ROOT}/openam-ui/openam-ui-ria && mvn -DskipTests package

or name a tree to serve:
    npm run local-server -- path/to/outDir`);
    }

    if (!info.isDirectory()) {
        throw new Error(`${dir} is a file, not a directory.`
            + (dir.endsWith(".zip")
                ? " Unpacking a www zip is task 2.5; until then, pass a directory."
                : ""));
    }

    const index = join(dir, "index.html");
    try {
        await stat(index);
    } catch {
        throw new Error(`${dir} does not look like an XUI build -- no index.html at its root`);
    }
}

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
    const options = parseArgs(process.argv.slice(2), { repoRoot: REPO_ROOT });
    if (options.help) {
        log(USAGE);
        return;
    }

    await checkXuiTree(options.xui);
    // Links resolved once, here, so every containment check downstream compares against a path
    // the filesystem agrees is canonical -- including on macOS, where it also settles the casing.
    const root = await realpath(options.xui);

    const handle = createRequestHandler({ root, context: options.context });
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
    const displayHost = ["0.0.0.0", "::"].includes(options.host) ? "localhost" : options.host;
    const origin = `http://${displayHost}:${boundPort}`;

    log(`local API server -- serving ${root}

  XUI   ${origin}/${options.context}/XUI/
  REST  ${origin}/${options.context}/json/   (501 until tasks 2.6-2.13)

Point the suite or a fixture at it with:
  OPENAM_BASE_URL=${origin}/${options.context}

Ctrl-C to stop.`);

    await new Promise((resolveClosed) => {
        const shutdown = (signal) => {
            log(`\n${signal} -- stopping`);
            // Without this, an idle keep-alive connection from the browser holds the port for its
            // full timeout after close() is called, and the next start fails with EADDRINUSE for
            // reasons that look nothing like the cause. Node 18.2 and later.
            server.closeAllConnections();
            server.close(() => resolveClosed());
        };
        process.once("SIGINT", () => shutdown("SIGINT"));
        process.once("SIGTERM", () => shutdown("SIGTERM"));
    });
}

try {
    await main();
} catch (error) {
    process.stderr.write(`error ${error.message}\n`);
    process.exitCode = 1;
}
