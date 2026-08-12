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
 * Serve a deployed XUI tree as Tomcat would serve it out of `webapps/openam/XUI`.
 *
 * The XUI is deployed unbundled — 652 individually addressable files fetched one at a time by
 * RequireJS — so "serve a directory" is the whole of what the UI needs from a web server, and
 * the details below are the ones that stop it booting when they are wrong:
 *
 *   - **The query string is not part of the file name.** `index.html` configures RequireJS with
 *     `urlArgs : "v=<build version>"`, so every module and every runtime-fetched template arrives
 *     as `…/Foo.js?v=16.2.0-SNAPSHOT`. Resolution therefore works off `URL.pathname` and ignores
 *     `URL.search` entirely.
 *   - **A directory URL keeps its trailing slash.** `index.html` loads `libs/base64-1.0.0-min.js`
 *     and `libs/requirejs-2.3.7-min.js` with relative `src` attributes, so a browser sitting at
 *     `/openam/XUI` (no slash) resolves them against `/openam/` and RequireJS is never loaded at
 *     all. A directory reached without the slash is redirected rather than served.
 *
 *     Not, as this said before it was checked, because the AM context would derive as `""`:
 *     `Constants.js` strips a leading *and* trailing slash before dropping the last segment, so
 *     `/openam/XUI` and `/openam/XUI/` both yield `openam`. The hazard that derivation does carry
 *     is `/openam/XUI/index.html`, which yields `openam/XUI` and addresses every REST call at
 *     `/openam/XUI/json/…` — a deployed AM behaves identically, so it is the XUI's to own, but
 *     this is where someone will come looking for it.
 *
 * Node standard library only. See the note in server.mjs for why that constraint is load-bearing
 * rather than a preference.
 */

import { open, realpath, stat } from "node:fs/promises";
import { join, resolve, sep } from "node:path";

/**
 * Extension to content type.
 *
 * Hand-written because the alternative — `mime`, `serve-static`, `sirv` — is a runtime dependency
 * in a package.json that is a CI cache key, for a mapping the deployed tree exercises twelve
 * entries of. The extras beyond those twelve (`.mjs`, `.ttf`, `.webp`, `.wasm`) are there so a
 * Vite `outDir` from phase 2 does not arrive as `application/octet-stream`, which the browser
 * refuses to execute as a module.
 */
const CONTENT_TYPES = {
    ".css": "text/css;charset=UTF-8",
    ".eot": "application/vnd.ms-fontobject",
    ".gif": "image/gif",
    ".htm": "text/html;charset=UTF-8",
    ".html": "text/html;charset=UTF-8",
    ".ico": "image/x-icon",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".js": "text/javascript;charset=UTF-8",
    ".json": "application/json;charset=UTF-8",
    // Source maps are JSON, and are only ever fetched by devtools.
    ".map": "application/json;charset=UTF-8",
    ".mjs": "text/javascript;charset=UTF-8",
    ".otf": "font/otf",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ttf": "font/ttf",
    ".txt": "text/plain;charset=UTF-8",
    ".wasm": "application/wasm",
    ".webp": "image/webp",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".xml": "application/xml;charset=UTF-8",
};

const FALLBACK_CONTENT_TYPE = "application/octet-stream";

/** The content type for a path, by extension, case-insensitively. */
export function contentTypeFor (filePath) {
    const dot = filePath.lastIndexOf(".");
    const slash = filePath.lastIndexOf(sep);
    if (dot < 0 || dot < slash) {
        return FALLBACK_CONTENT_TYPE;
    }
    return CONTENT_TYPES[filePath.slice(dot).toLowerCase()] ?? FALLBACK_CONTENT_TYPE;
}

/** Is `candidate` the tree itself, or inside it? Both must already be absolute. */
function isInside (root, candidate) {
    const rootPrefix = root.endsWith(sep) ? root : root + sep;
    return candidate === root || candidate.startsWith(rootPrefix);
}

/**
 * Map the part of the request path below the mount onto a file inside the tree, or refuse.
 *
 * The containment check is not decoration. Segments are percent-decoded before they are joined,
 * so `..%2f..%2f` arrives here as a path fragment that `resolve` will happily walk out of the
 * tree with; comparing the resolved path against the root is what makes that a 400 rather than a
 * read of an arbitrary file on the contributor's machine.
 *
 * It is *only* the spelling of the path that is checked here, because `resolve` is string
 * arithmetic and never touches the filesystem. A symlink inside the tree pointing out of it
 * passes this and is caught later, against the real path — see `serveStatic`.
 */
export function resolveInTree (root, relativePath) {
    let segments;
    try {
        segments = relativePath.split("/").map(decodeURIComponent);
    } catch {
        return { error: "path is not valid percent-encoding" };
    }
    if (segments.some((segment) => segment.includes("\0"))) {
        return { error: "path contains a NUL byte" };
    }

    const target = resolve(root, ...segments);
    if (!isInside(root, target)) {
        return { error: "path escapes the served tree" };
    }
    return { path: target };
}

async function statOrNull (path) {
    try {
        return await stat(path);
    } catch {
        return null;
    }
}

/**
 * Answer a request for a file in the tree.
 *
 * `root` must be a real path — `server.mjs` resolves it once at startup — because the symlink
 * check below compares against it.
 *
 * `no-store` on everything, deliberately: the tree under this server is swapped while it runs —
 * that is the inner loop the whole local backend exists for — and a module the browser kept from
 * the previous build produces a failure that looks exactly like a bug in the new one.
 *
 * **The file is opened before the headers go out.** It used to be `stat`, then `writeHead(200)`,
 * then `createReadStream`, which meant anything that failed between the stat and the read — no
 * permission, or the rebuild that deleted the file mid-request, which is the loop this server is
 * *for* — produced a 200 with its length announced and no body. The browser reports that as an
 * empty reply, RequireJS reports it as a script that would not load, and the cause is nowhere.
 * Opening first turns both into an ordinary status with a message.
 */
export async function serveStatic (req, res, { root, mount, url }) {
    if (req.method !== "GET" && req.method !== "HEAD") {
        return sendText(req, res, 405, `${req.method} is not allowed on the XUI tree.\n`,
            { Allow: "GET, HEAD" });
    }

    // "" when the request is for the bare mount, "/…" otherwise.
    const relativePath = url.pathname.slice(mount.length);
    if (relativePath === "") {
        return redirect(res, `${mount}/${url.search}`);
    }

    const resolved = resolveInTree(root, relativePath);
    if (resolved.error) {
        return sendText(req, res, 400, `${resolved.error}\n`);
    }

    let filePath = resolved.path;
    let info = await statOrNull(filePath);

    if (info?.isDirectory()) {
        if (!url.pathname.endsWith("/")) {
            return redirect(res, `${url.pathname}/${url.search}`);
        }
        // index.html or nothing. No directory listing: this stands in for a servlet container
        // serving a deployed application, and that does not list directories either.
        filePath = join(filePath, "index.html");
        info = await statOrNull(filePath);
    }

    if (!info?.isFile()) {
        return sendText(req, res, 404, `${url.pathname} is not in the served XUI tree.\n`);
    }

    // What the lexical check could not see. `target/compiled` contains no links today, so this
    // costs one `realpath` per request and catches nothing — until the tree being served is
    // something else, which is the whole point of `--xui`, and a linked asset directory in a
    // bundler's output is an ordinary thing to find there.
    const realPath = await realpathOrNull(filePath);
    if (realPath === null || !isInside(root, realPath)) {
        return sendText(req, res, 403, `${url.pathname} links out of the served XUI tree.\n`);
    }

    let file;
    try {
        file = await open(filePath, "r");
    } catch (error) {
        return error.code === "EACCES"
            ? sendText(req, res, 403, `${url.pathname} is in the tree but cannot be read.\n`)
            : sendText(req, res, 404, `${url.pathname} is not in the served XUI tree.\n`);
    }

    let size;
    try {
        // From the descriptor, not the path: it is the length of what is about to be sent even if
        // the file is replaced between here and the last chunk.
        ({ size } = await file.stat());
    } catch (error) {
        await file.close();
        return sendText(req, res, 500, `${url.pathname} could not be read: ${error.code}\n`);
    }

    res.writeHead(200, {
        "Content-Type": contentTypeFor(filePath),
        "Content-Length": size,
        "Cache-Control": "no-store",
    });
    if (req.method === "HEAD") {
        await file.close();
        return res.end();
    }

    const stream = file.createReadStream({ autoClose: true });
    // The headers are already out, so a read failure now can only be reported by breaking the
    // connection -- and to stderr, or it is invisible. Destroying the stream when the client goes
    // away first keeps an aborted page load from leaving a descriptor open per request.
    stream.on("error", (error) => {
        process.stderr.write(`read failed mid-response for ${url.pathname}: ${error.message}\n`);
        res.destroy();
    });
    res.on("close", () => stream.destroy());
    stream.pipe(res);
}

async function realpathOrNull (path) {
    try {
        return await realpath(path);
    } catch {
        return null;
    }
}

function redirect (res, location) {
    // 302, not 301: a permanent redirect is cached by the browser past the life of this process,
    // and everything else here is `no-store` for the same reason -- the tree is swapped underneath
    // a running server, and nothing about one run should survive into the next.
    res.writeHead(302, { Location: location, "Content-Length": 0, "Cache-Control": "no-store" });
    res.end();
}

function sendText (req, res, status, body, extraHeaders = {}) {
    const payload = Buffer.from(body, "utf8");
    res.writeHead(status, {
        "Content-Type": "text/plain;charset=UTF-8",
        "Content-Length": payload.length,
        "Cache-Control": "no-store",
        ...extraHeaders,
    });
    res.end(req.method === "HEAD" ? undefined : payload);
}
