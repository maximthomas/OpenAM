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
 * What may and may not be resolved to a file, and what each file is served as.
 *
 *     node --test local/server-lib/
 *
 * `resolveInTree` is the only function in this server whose failure mode is reading a file it was
 * never asked for. It takes a string and returns a string, so the whole of it can be checked here,
 * cheaply, without a socket — which is the argument for it being a separate function at all. The
 * cases are the shapes an attacker writes rather than the shapes a browser sends: a request that
 * escapes the tree does not arrive looking like `../`, it arrives percent-encoded, doubly encoded,
 * or with a NUL byte pasted after a name that ends in `.html`.
 *
 * The symlink case is deliberately *not* here — `resolve` is string arithmetic and cannot see a
 * link. That check needs a filesystem, and it is in router.test.mjs with the rest of the behaviour
 * that does.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { contentTypeFor, resolveInTree } from "./static-tree.mjs";

const ROOT = "/srv/xui";

describe("resolveInTree", () => {
    it("maps an ordinary path onto a file in the tree", () => {
        assert.deepEqual(resolveInTree(ROOT, "/main.js"), { path: "/srv/xui/main.js" });
        assert.deepEqual(resolveInTree(ROOT, "/config/Constants.js"),
            { path: "/srv/xui/config/Constants.js" });
    });

    it("decodes the percent-encoding a browser applies to a legitimate name", () => {
        assert.deepEqual(resolveInTree(ROOT, "/themes/dark%20theme/main.css"),
            { path: "/srv/xui/themes/dark theme/main.css" });
    });

    it("resolves the tree itself, which is how the index is reached", () => {
        assert.deepEqual(resolveInTree(ROOT, "/"), { path: ROOT });
    });

    it("refuses every spelling of a path that leaves the tree", () => {
        const escapes = [
            "/../../../etc/passwd",              // literal, if it survives URL normalisation
            "/..%2f..%2f..%2fetc/passwd",        // encoded separator
            "/%2e%2e%2f%2e%2e%2fetc/passwd",     // encoded dots and separator
            "/%2Fetc%2Fpasswd",                  // an absolute path in one segment
            "/config/../../../../etc/passwd",    // back out through a real directory
            "/..",                               // the parent itself
        ];
        for (const path of escapes) {
            assert.deepEqual(resolveInTree(ROOT, path), { error: "path escapes the served tree" },
                path);
        }
    });

    it("does not decode twice, so an encoded percent stays a file name", () => {
        // %252e%252e decodes once to %2e%2e -- a name, not a traversal. Decoding again would
        // turn a request that must 404 into one that escapes.
        assert.deepEqual(resolveInTree(ROOT, "/%252e%252e/passwd"),
            { path: "/srv/xui/%2e%2e/passwd" });
    });

    it("refuses a NUL byte rather than letting it truncate the name", () => {
        assert.deepEqual(resolveInTree(ROOT, "/main.js%00.txt"),
            { error: "path contains a NUL byte" });
    });

    it("refuses percent-encoding that does not decode", () => {
        assert.deepEqual(resolveInTree(ROOT, "/%zz"),
            { error: "path is not valid percent-encoding" });
    });

    it("does not mistake a sibling directory with the same prefix for the tree", () => {
        // The containment check compares against the root plus a separator for exactly this:
        // "/srv/xui-old/secret" starts with "/srv/xui".
        assert.deepEqual(resolveInTree(ROOT, "/../xui-old/secret"),
            { error: "path escapes the served tree" });
    });
});

describe("contentTypeFor", () => {
    it("serves scripts and modules as JavaScript, or the browser will not run them", () => {
        assert.equal(contentTypeFor("/srv/xui/main.js"), "text/javascript;charset=UTF-8");
        assert.equal(contentTypeFor("/srv/xui/main.mjs"), "text/javascript;charset=UTF-8");
    });

    it("covers what the deployed tree actually contains", () => {
        const expected = {
            "index.html": "text/html;charset=UTF-8",
            "css/styles.css": "text/css;charset=UTF-8",
            "locales/en/translation.json": "application/json;charset=UTF-8",
            "images/login-logo.png": "image/png",
            "images/logo.svg": "image/svg+xml",
            "favicon.ico": "image/x-icon",
            "fonts/fontawesome-webfont.woff2": "font/woff2",
            "fonts/fontawesome-webfont.woff": "font/woff",
            "fonts/fontawesome-webfont.ttf": "font/ttf",
            "fonts/fontawesome-webfont.eot": "application/vnd.ms-fontobject",
            "main.js.map": "application/json;charset=UTF-8",
        };
        for (const [path, type] of Object.entries(expected)) {
            assert.equal(contentTypeFor(`/srv/xui/${path}`), type, path);
        }
    });

    it("ignores the case of the extension", () => {
        assert.equal(contentTypeFor("/srv/xui/LOGO.PNG"), "image/png");
    });

    it("falls back for an extension it does not know", () => {
        assert.equal(contentTypeFor("/srv/xui/data.bin"), "application/octet-stream");
    });

    it("does not read a dot in a directory as the file's extension", () => {
        // "/srv/xui/v1.2/LICENSE" has a dot before the last separator and no extension of its own.
        assert.equal(contentTypeFor("/srv/xui/v1.2/LICENSE"), "application/octet-stream");
        assert.equal(contentTypeFor("/srv/xui/LICENSE"), "application/octet-stream");
    });
});
