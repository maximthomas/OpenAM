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
            port: "8090",
            context: "openam",
            host: "127.0.0.1",
        });
    });

    it("takes every setting from the environment when it is set", () => {
        assert.deepEqual(defaults({
            OPENAM_LOCAL_XUI: "/elsewhere",
            OPENAM_LOCAL_PORT: "9999",
            OPENAM_LOCAL_CONTEXT: "am",
            OPENAM_LOCAL_HOST: "0.0.0.0",
        }), { xui: "/elsewhere", port: "9999", context: "am", host: "0.0.0.0" });
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
