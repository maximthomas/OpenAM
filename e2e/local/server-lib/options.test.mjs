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
 * What the server's settings must resolve to.
 *
 *     node --test local/server-lib/
 *
 * Three settings here decide what the server is reachable at and one decides what it serves, and
 * every one of them fails quietly when it is wrong: a blank `OPENAM_LOCAL_HOST` binds every
 * interface instead of loopback, a blank port takes an ephemeral one, and a context with a stray
 * slash moves both surfaces somewhere the XUI will not look. None of those announce themselves —
 * the server starts, prints a banner, and is simply not where you expected. The cases below are
 * mostly about the empty string, because that is the value a CI expression produces for an input
 * nobody set.
 */

import assert from "node:assert/strict";
import { resolve } from "node:path";
import { describe, it } from "node:test";

import { defaults, parseArgs, USAGE } from "./options.mjs";

const NO_ENV = {};

/** parseArgs with the one thing the process would otherwise supply. */
const parse = (argv, env = NO_ENV) => parseArgs(argv, { env });

describe("defaults", () => {
    it("serves the built www zip, on 8090, under openam, on loopback", () => {
        // xui is null rather than a path: naming the zip means reading the version out of the
        // reactor pom, which xui-source.mjs does at startup and this must not do for --help.
        assert.deepEqual(defaults(NO_ENV), {
            xui: null,
            // Serving a built tree is the mode this server had before task 4.10, and the only one
            // that resembles a deployment. Live reload is asked for, never fallen into.
            devServer: null,
            port: "8090",
            context: "openam",
            host: "127.0.0.1",
        });
    });

    it("takes every setting from the environment when it is set", () => {
        assert.deepEqual(defaults({
            OPENAM_LOCAL_XUI: "/elsewhere",
            OPENAM_LOCAL_DEV_SERVER: "http://127.0.0.1:5173",
            OPENAM_LOCAL_PORT: "9999",
            OPENAM_LOCAL_CONTEXT: "am",
            OPENAM_LOCAL_HOST: "0.0.0.0",
        }), {
            xui: "/elsewhere",
            devServer: "http://127.0.0.1:5173",
            port: "9999",
            context: "am",
            host: "0.0.0.0",
        });
    });

    it("treats a set-but-blank variable as unset, rather than as a value", () => {
        // The one that matters: "" reaches server.listen(port, "") and binds every interface.
        assert.deepEqual(defaults({
            OPENAM_LOCAL_XUI: "",
            OPENAM_LOCAL_PORT: "",
            OPENAM_LOCAL_CONTEXT: "  ",
            OPENAM_LOCAL_HOST: "",
        }), defaults(NO_ENV));
    });
});

describe("parseArgs precedence", () => {
    it("lets an argument beat the environment", () => {
        const options = parse(["--port", "9000"], { OPENAM_LOCAL_PORT: "9999" });
        assert.equal(options.port, 9000);
    });

    it("takes the zip or tree positionally, as xui-deploy.sh does", () => {
        assert.equal(parse(["/some/tree"]).xui, "/some/tree");
        assert.equal(parse(["/some/build-www.zip"]).xui, "/some/build-www.zip");
    });

    it("takes it by name too, and the two agree", () => {
        assert.equal(parse(["--xui", "/some/tree"]).xui, parse(["/some/tree"]).xui);
    });

    it("resolves a relative path against the working directory", () => {
        assert.equal(parse(["target/compiled"]).xui, `${process.cwd()}/target/compiled`);
    });

    it("leaves the unnamed default unresolved, rather than resolving null to the cwd", () => {
        assert.equal(parse([]).xui, null);
    });

    it("refuses a second positional rather than silently ignoring it", () => {
        assert.throws(() => parse(["/one", "/two"]), /Unexpected argument "\/two"/);
    });

    it("refuses an unknown flag", () => {
        assert.throws(() => parse(["--proxy", "x"]), /Unknown argument "--proxy"/);
    });

    it("refuses a flag with nothing after it", () => {
        assert.throws(() => parse(["--port"]), /--port needs a value/);
    });
});

describe("parseArgs --help", () => {
    it("is answered before the arguments are validated", () => {
        // The usual reason for asking is that an argument was wrong, so this is the worst possible
        // moment to report the argument instead of the usage.
        assert.equal(parse(["--port", "not-a-port", "--help"]).help, true);
        assert.equal(parse(["-h"]).help, true);
    });

    it("documents every flag it accepts", () => {
        for (const flag of ["--xui", "--port", "--context", "--host", "--help"]) {
            assert.ok(USAGE.includes(flag), `${flag} is accepted but undocumented`);
        }
        for (const variable of ["OPENAM_LOCAL_XUI", "OPENAM_LOCAL_PORT", "OPENAM_LOCAL_CONTEXT",
            "OPENAM_LOCAL_HOST"]) {
            assert.ok(USAGE.includes(variable), `${variable} is read but undocumented`);
        }
    });
});

describe("parseArgs port", () => {
    it("accepts a port, as a number", () => {
        assert.equal(parse(["--port", "8090"]).port, 8090);
    });

    it("accepts 0, which is how a harness asks for any free port", () => {
        assert.equal(parse(["--port", "0"]).port, 0);
    });

    it("refuses what Number would accept but a socket would not", () => {
        // Number("0x1f9a") is 8090 and Number("8090.0") is 8090; neither is a port number.
        for (const port of ["0x1f9a", "8090.0", "8090abc", "-1", "65536", "", " ", "eight"]) {
            assert.throws(() => parse(["--port", port]), /is not a port number/, port);
        }
    });
});

describe("parseArgs context", () => {
    it("stores the context without slashes, however it was written", () => {
        for (const written of ["openam", "/openam", "openam/", "//openam//"]) {
            assert.equal(parse(["--context", written]).context, "openam", written);
        }
    });

    it("keeps an interior slash, which a nested deployment path needs", () => {
        assert.equal(parse(["--context", "/apps/openam/"]).context, "apps/openam");
    });

    it("refuses a context that is empty or cannot survive a URL", () => {
        for (const context of ["", "/", "//", "open am", "open?am", "open#am"]) {
            assert.throws(() => parse(["--context", context]), /not usable as a context path/,
                JSON.stringify(context));
        }
    });
});

describe("parseArgs host", () => {
    it("keeps the address it was given", () => {
        assert.equal(parse(["--host", "0.0.0.0"]).host, "0.0.0.0");
    });

    it("refuses a blank address instead of binding every interface with it", () => {
        for (const host of ["", "  ", "127.0.0.1 8080"]) {
            assert.throws(() => parse(["--host", host]), /--host needs an address/,
                JSON.stringify(host));
        }
    });

    it("does not let a blank OPENAM_LOCAL_HOST widen the bind", () => {
        assert.equal(parse([], { OPENAM_LOCAL_HOST: "" }).host, "127.0.0.1");
    });
});

/**
 * `--dev-server`, task 4.10.
 *
 * The exclusivity is the whole of the difficulty: what serves `/{context}/XUI/` is a built tree or
 * a Vite dev server and never both, and the built tree already has two spellings. So the rule is
 * between three spellings of two settings, and it has to hold without breaking the per-setting
 * precedence the rest of this file is about — an exported `OPENAM_LOCAL_XUI` must not make
 * `--dev-server` unusable.
 */
describe("parseArgs dev-server", () => {
    it("resolves an origin into what the proxy dials", () => {
        assert.deepEqual(parse(["--dev-server", "http://127.0.0.1:5173"]).devServer, {
            origin: "http://127.0.0.1:5173",
            hostname: "127.0.0.1",
            port: 5173,
        });
    });

    it("leaves the port, context and host meaning what they meant", () => {
        // They configure *this* server's socket and mount. Nothing about them becomes ambiguous,
        // because --dev-server always names another origin and always carries a scheme.
        const options = parse([
            "--dev-server", "http://127.0.0.1:5173", "--port", "9000", "--context", "am",
        ]);
        assert.equal(options.port, 9000);
        assert.equal(options.context, "am");
        assert.equal(options.host, "127.0.0.1");
        assert.equal(options.devServer.port, 5173);
    });

    it("tolerates a trailing slash, and takes the default port when there is none", () => {
        assert.deepEqual(parse(["--dev-server", "http://localhost/"]).devServer, {
            origin: "http://localhost",
            hostname: "localhost",
            port: 80,
        });
    });

    it("refuses the bare port a contributor will type, and names a good value", () => {
        // `new URL("5173")` throws a TypeError whose message names neither the flag nor the shape
        // of a right answer, which is the entire reason this is caught rather than left to bubble.
        assert.throws(() => parse(["--dev-server", "5173"]),
            /"5173" is not a dev-server origin\. Use http:\/\/127\.0\.0\.1:5173\./);
    });

    it("refuses an origin with a path, because the path is this server's to decide", () => {
        for (const value of ["http://127.0.0.1:5173/openam/XUI/", "http://127.0.0.1:5173/x"]) {
            assert.throws(() => parse(["--dev-server", value]), /takes an origin, not a URL/,
                value);
        }
    });

    it("refuses https, saying node:http cannot dial it", () => {
        assert.throws(() => parse(["--dev-server", "https://127.0.0.1:5173"]),
            /node:http cannot dial TLS/);
    });

    it("refuses both spellings of what serves the XUI on one command line", () => {
        for (const argv of [
            ["www.zip", "--dev-server", "http://127.0.0.1:5173"],
            ["--dev-server", "http://127.0.0.1:5173", "www.zip"],
            ["--xui", "www.zip", "--dev-server", "http://127.0.0.1:5173"],
            ["--dev-server", "http://127.0.0.1:5173", "--xui", "www.zip"],
        ]) {
            assert.throws(() => parse(argv), /Give one or the other/, argv.join(" "));
        }
    });

    it("lets an argument beat the other setting's environment variable, in both directions", () => {
        // The failure this prevents: a contributor with OPENAM_LOCAL_XUI exported could otherwise
        // never pass --dev-server without unsetting it first, which is the documented per-setting
        // precedence abandoned for a pair.
        const dev = parse(["--dev-server", "http://127.0.0.1:5173"],
            { OPENAM_LOCAL_XUI: "/elsewhere" });
        assert.equal(dev.xui, null);
        assert.equal(dev.devServer.port, 5173);

        const tree = parse(["--xui", "/tree"], { OPENAM_LOCAL_DEV_SERVER: "http://127.0.0.1:5173" });
        assert.equal(tree.devServer, null);
        assert.equal(tree.xui, resolve("/tree"));

        // Positionally too, which is the spelling npm run local-server -- <path> produces.
        const positional = parse(["/tree"], { OPENAM_LOCAL_DEV_SERVER: "http://127.0.0.1:5173" });
        assert.equal(positional.devServer, null);
        assert.equal(positional.xui, resolve("/tree"));
    });

    it("refuses both environment variables, because there is no tie to break", () => {
        assert.throws(() => parse([], {
            OPENAM_LOCAL_XUI: "/elsewhere",
            OPENAM_LOCAL_DEV_SERVER: "http://127.0.0.1:5173",
        }), /both set, and they are alternatives/);
    });

    it("refuses a dev server that is this server, which would loop until memory ran out", () => {
        assert.throws(() => parse(["--dev-server", "http://127.0.0.1:8090"]),
            /is this server's own address/);
        assert.throws(() => parse(["--dev-server", "http://127.0.0.1:9000", "--port", "9000"]),
            /is this server's own address/);
        // Binding every interface makes a loopback dev server on the same port this server too.
        assert.throws(
            () => parse(["--dev-server", "http://127.0.0.1:8090", "--host", "0.0.0.0"]),
            /is this server's own address/);
    });

    it("does not mistake a different port or a different machine for a loop", () => {
        assert.equal(parse(["--dev-server", "http://127.0.0.1:5173"]).devServer.port, 5173);
        assert.equal(
            parse(["--dev-server", "http://elsewhere:8090", "--host", "0.0.0.0"]).devServer.port,
            8090);
    });

    it("answers --help before any of it, since a bad argument is why you asked", () => {
        assert.equal(parse(["--dev-server", "5173", "--help"]).help, true);
        assert.match(USAGE, /--dev-server ORIGIN/);
        // Two synopsis lines, which is what makes the exclusivity readable: [XUI] is on one of
        // them and not the other.
        assert.match(USAGE, /^node local\/server\.mjs \[XUI\] \[options\]\nnode local\/server\.mjs --dev-server ORIGIN \[options\]/);
    });
});
