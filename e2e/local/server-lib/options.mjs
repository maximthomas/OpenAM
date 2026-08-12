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
 * Where the local API server's four settings come from, and what counts as a usable value.
 *
 * Argument beats environment beats default, each setting independently.
 *
 * **One default is deliberately not resolved here.** With nothing named, the XUI to serve is the
 * built `www` zip, whose file name carries the project version — so working it out reads the
 * reactor pom. That must not happen for `--help`, which is answered before anything is validated
 * precisely because a wrong argument is the usual reason for asking, and it must not happen when a
 * path was named anyway. So `xui` stays `null` here, meaning "the built distributable", and
 * xui-source.mjs turns that into a path at startup.
 *
 * **Blank is not a value.** `??` falls back only on `undefined`, so an exported-but-empty variable
 * used to pass straight through, and each of them fails in a direction nobody asked for:
 * `OPENAM_LOCAL_HOST=` reaches `server.listen(port, "")`, which binds *every* interface rather than
 * the deliberate loopback default, and `OPENAM_LOCAL_PORT=` becomes `Number("") === 0`, an
 * ephemeral port nothing can find. An unset input in a GitHub Actions expression interpolates as
 * exactly this empty string, and starting this server from a workflow is task 2.16, so it is the
 * shape that would have arrived here first.
 *
 * Kept apart from server.mjs so it can be tested without starting a server — the same split as
 * capture.mjs and capture-lib.
 */

import { resolve } from "node:path";

export const USAGE = `node local/server.mjs [XUI] [options]

  XUI               the built XUI to serve, as xui-deploy.sh takes it: a www zip,
                    which is unpacked, or a directory, which is served as it is
                    [openam-ui/openam-ui-ria/target/openam-ui-ria-<version>-www.zip]
                                                                (OPENAM_LOCAL_XUI)
  --xui SOURCE      the same, named rather than positional
  --port N          listen on N; 0 takes any free port  [8090]  (OPENAM_LOCAL_PORT)
  --context NAME    serve both surfaces under /NAME/  [openam]  (OPENAM_LOCAL_CONTEXT)
  --host ADDRESS    bind address; 0.0.0.0 for every interface
                    [127.0.0.1]                                 (OPENAM_LOCAL_HOST)
  --help`;

const FLAGS = ["--port", "--context", "--host", "--xui"];

/** Bare decimal only: `Number` also accepts "0x1f9a" and "8090.0", and neither is a port. */
const PORT_PATTERN = /^\d+$/;

/** An environment override, or `undefined` — including when it is set but blank. */
function fromEnv (env, name) {
    const value = env[name];
    return value === undefined || value.trim() === "" ? undefined : value;
}

/**
 * The settings before any argument is applied.
 *
 * *Port 8090:* 8080 is the AM container from openam-up.sh and 8081 is `sp.mycompany.org` in
 * saml/saml-test.spec.mjs. Both backends need to be able to run at once — comparing them is the
 * point — so this takes a third port rather than either of theirs.
 *
 * *Context `openam`:* what the container deploys under, so one `OPENAM_BASE_URL` shape works
 * against both backends and the XUI derives the same context from either.
 *
 * *XUI, the built `www` zip:* the distributable itself, so what is served here is what a
 * deployment would get — not a tree that resembles it. `target/compiled`, which the zip is packed
 * from, works too and is a directory; `target/XUI` next to it does *not* — it is the pre-filter
 * composition directory, still carrying the literal `urlArgs : "v=${version}"`.
 *
 * *Host 127.0.0.1:* this serves a build tree off the contributor's disk; reaching it from the
 * network should be something you asked for.
 *
 * The `OPENAM_LOCAL_` prefix is deliberately its own namespace rather than joining the `OPENAM_*`
 * variables common/openam-commons.mjs reads: those point a test run at a backend, these configure
 * one, and a run that does both at once must be able to set them independently.
 */
export function defaults (env) {
    return {
        xui: fromEnv(env, "OPENAM_LOCAL_XUI") ?? null,
        port: fromEnv(env, "OPENAM_LOCAL_PORT") ?? "8090",
        context: fromEnv(env, "OPENAM_LOCAL_CONTEXT") ?? "openam",
        host: fromEnv(env, "OPENAM_LOCAL_HOST") ?? "127.0.0.1",
    };
}

/**
 * Resolve arguments, environment and defaults into the settings the server starts from.
 *
 * `--help` is answered before anything is validated: a wrong argument is the usual reason for
 * asking, and printing the error instead of the usage would be the least helpful moment to be
 * strict.
 */
export function parseArgs (argv, { env = process.env } = {}) {
    const options = { ...defaults(env), help: false };
    let positional = 0;

    for (let i = 0; i < argv.length; i += 1) {
        const flag = argv[i];
        const value = argv[i + 1];
        if (FLAGS.includes(flag)) {
            if (value === undefined) {
                throw new Error(`${flag} needs a value`);
            }
            options[flag.slice(2)] = value;
            i += 1;
        } else if (flag === "--help" || flag === "-h") {
            options.help = true;
        } else if (flag.startsWith("-")) {
            throw new Error(`Unknown argument "${flag}". Try --help.`);
        } else if (positional === 0) {
            // The zip or tree to serve, positionally, as xui-deploy.sh takes it.
            options.xui = flag;
            positional += 1;
        } else {
            throw new Error(`Unexpected argument "${flag}".\n\n${USAGE}`);
        }
    }

    if (options.help) {
        return options;
    }

    // null stays null: it is not a path yet, and resolve() would turn it into the cwd.
    if (options.xui !== null) {
        options.xui = resolve(options.xui);
    }

    if (!PORT_PATTERN.test(options.port.trim()) || Number(options.port) > 65535) {
        throw new Error(`"${options.port}" is not a port number`);
    }
    options.port = Number(options.port);

    // The context is a path prefix, so it is stored without its slashes and rebuilt with them.
    options.context = options.context.replace(/^\/+|\/+$/g, "");
    if (options.context === "" || /[\s?#]/.test(options.context)) {
        throw new Error(`"${options.context}" is not usable as a context path`);
    }

    options.host = options.host.trim();
    if (options.host === "" || /\s/.test(options.host)) {
        throw new Error("--host needs an address. Use 0.0.0.0 to bind every interface.");
    }

    return options;
}
