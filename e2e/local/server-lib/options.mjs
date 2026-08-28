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
 * Where the local API server's settings come from, and what counts as a usable value.
 *
 * Argument beats environment beats default, each setting independently.
 *
 * **One pair is not independent, and that is the whole subtlety of `--dev-server`** (task 4.10).
 * What serves `/{context}/XUI/` is either a built tree or a Vite dev server, never both, and the
 * built tree is already spelled two ways — positionally and as `--xui`. So the exclusivity is
 * between *three* spellings of two settings. It is enforced at the same precedence level rather
 * than across levels: a contributor with `OPENAM_LOCAL_XUI` exported would otherwise never be able
 * to pass `--dev-server` without first unsetting it, which is exactly the per-setting precedence
 * above, broken. Two environment variables with no argument to break the tie is the one case with
 * no answer, and is an error rather than a silent pick.
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
node local/server.mjs --dev-server ORIGIN [options]

  XUI               the built XUI to serve, as xui-deploy.sh takes it: a www zip,
                    which is unpacked, or a directory, which is served as it is
                    [openam-ui/openam-ui-ria/target/openam-ui-ria-<version>-www.zip]
                                                                (OPENAM_LOCAL_XUI)
  --xui SOURCE      the same, named rather than positional
  --dev-server ORIGIN
                    proxy /{context}/XUI/ to a Vite dev server already running
                    at ORIGIN instead of serving a built tree; the REST surface
                    is unaffected. Not usable with XUI or --xui
                    [off]                                  (OPENAM_LOCAL_DEV_SERVER)
  --port N          listen on N; 0 takes any free port  [8090]  (OPENAM_LOCAL_PORT)
  --context NAME    serve both surfaces under /NAME/  [openam]  (OPENAM_LOCAL_CONTEXT)
  --host ADDRESS    bind address; 0.0.0.0 for every interface
                    [127.0.0.1]                                 (OPENAM_LOCAL_HOST)
  --help`;

const FLAGS = ["--port", "--context", "--host", "--xui", "--dev-server"];

/** The one flag whose option key is not simply its name: `dev-server` is not an identifier. */
const OPTION_KEYS = { "--dev-server": "devServer" };

/**
 * Loopback by any spelling this check can recognise without resolving a name.
 *
 * `127.0.0.0/8` in full, not just `127.0.0.1`: the whole block is loopback and `127.0.0.2` is a
 * perfectly ordinary way to write one. Brackets are not here because the hostname has already had
 * them stripped by the time this is consulted.
 */
const isLoopback = (hostname) => hostname === "::1" || hostname === "localhost"
    || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);

/** Binds every interface, so a loopback dev server on the same port is this server. */
const WILDCARD = ["0.0.0.0", "::", "[::]"];

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
        // null means "serve a built tree", which is the mode this server had before task 4.10 and
        // the only one a deployment resembles.
        devServer: fromEnv(env, "OPENAM_LOCAL_DEV_SERVER") ?? null,
        port: fromEnv(env, "OPENAM_LOCAL_PORT") ?? "8090",
        context: fromEnv(env, "OPENAM_LOCAL_CONTEXT") ?? "openam",
        host: fromEnv(env, "OPENAM_LOCAL_HOST") ?? "127.0.0.1",
    };
}

/**
 * `--dev-server`'s value into the origin the proxy dials, or a message saying why it is not one.
 *
 * A bare port is what a contributor types, and `new URL("5173")` throws a `TypeError` whose message
 * names neither the flag nor what a good value looks like, so it is caught and answered here.
 *
 * **http only.** `node:http` cannot dial a TLS origin, and a Vite dev server started with `https`
 * serves a self-signed certificate that would then have to be either trusted or ignored -- a
 * decision worth taking deliberately rather than as a side effect of this task. Vite's dev server
 * is http unless asked otherwise, so the refusal below is a message rather than a limitation
 * anybody meets by accident.
 */
function resolveDevServer (value) {
    let url;
    try {
        url = new URL(value);
    } catch {
        throw new Error(`"${value}" is not a dev-server origin. Use http://127.0.0.1:5173.`);
    }
    if (url.protocol !== "http:") {
        throw new Error(`--dev-server takes an http origin; "${value}" is ${url.protocol}. `
            + "node:http cannot dial TLS, so a dev server behind https is not proxied.");
    }
    if (url.username !== "" || url.password !== "") {
        // Dropped silently otherwise: `origin` below is built from `url.host`, so credentials typed
        // here would never reach the dev server and nothing would say so.
        throw new Error("--dev-server takes a bare origin; credentials in it are not forwarded. "
            + "A Vite dev server does not authenticate.");
    }
    if (url.hostname === "" || url.pathname !== "/" || url.search !== "" || url.hash !== "") {
        throw new Error(`--dev-server takes an origin, not a URL with a path: "${value}". `
            + "The path is this server's to decide -- it is /{context}/XUI/, and Vite's `base` "
            + "has to match it.");
    }

    const port = Number(url.port === "" ? "80" : url.port);
    return {
        // What the messages name, so an operator reads back what they typed rather than a
        // normalisation of it. `URL` drops a default port, which is the only difference.
        origin: `http://${url.host}`,
        // Without brackets: `node:http` wants the bare address, and `URL.hostname` keeps them
        // for an IPv6 literal.
        hostname: url.hostname.replace(/^\[|\]$/g, ""),
        port,
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
    // Which of the two exclusive settings arrived as an *argument*, which is what makes the
    // exclusivity a comparison at one precedence level rather than across two. See the header.
    let sawXui = false;
    let sawDevServer = false;

    for (let i = 0; i < argv.length; i += 1) {
        const flag = argv[i];
        const value = argv[i + 1];
        if (FLAGS.includes(flag)) {
            if (value === undefined) {
                throw new Error(`${flag} needs a value`);
            }
            options[OPTION_KEYS[flag] ?? flag.slice(2)] = value;
            sawXui ||= flag === "--xui";
            sawDevServer ||= flag === "--dev-server";
            i += 1;
        } else if (flag === "--help" || flag === "-h") {
            options.help = true;
        } else if (flag.startsWith("-")) {
            throw new Error(`Unknown argument "${flag}". Try --help.`);
        } else if (positional === 0) {
            // The zip or tree to serve, positionally, as xui-deploy.sh takes it.
            options.xui = flag;
            sawXui = true;
            positional += 1;
        } else {
            throw new Error(`Unexpected argument "${flag}".\n\n${USAGE}`);
        }
    }

    if (options.help) {
        return options;
    }

    // Both spellings of "what serves the XUI", named on one command line. Refused with the reason
    // rather than resolved by a precedence nobody would guess.
    if (sawXui && sawDevServer) {
        throw new Error("--dev-server serves the XUI from a running Vite dev server, and "
            + `XUI / --xui serves it from a built tree. Give one or the other.\n\n${USAGE}`);
    }
    // An argument beats the other setting's environment variable, which is the documented
    // precedence applied to a pair rather than abandoned for one.
    if (sawDevServer) {
        options.xui = null;
    }
    if (sawXui) {
        options.devServer = null;
    }
    // Both from the environment, with nothing on the command line to break the tie. There is no
    // right answer here, and picking one quietly is how a contributor spends an afternoon
    // wondering why their zip is being ignored.
    if (options.xui !== null && options.devServer !== null) {
        throw new Error("OPENAM_LOCAL_XUI and OPENAM_LOCAL_DEV_SERVER are both set, and they are "
            + "alternatives. Unset one, or override it with XUI / --xui / --dev-server.");
    }

    // null stays null: it is not a path yet, and resolve() would turn it into the cwd.
    if (options.xui !== null) {
        options.xui = resolve(options.xui);
    }
    if (options.devServer !== null) {
        options.devServer = resolveDevServer(options.devServer);
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

    // A --dev-server naming this server is an infinite proxy loop, and it presents as memory
    // exhaustion rather than as an error. Last, because it needs the resolved port and host.
    //
    // **This is a courtesy, not the guard.** It compares strings, so `localhost` and `127.0.0.1`
    // are the same socket and will not compare equal -- resolving names here would make parseArgs
    // asynchronous, which it must not be. And with `--port 0` the bound port is not known until
    // listen. dev-proxy.mjs's LOOP_GUARD header is the complete answer; this one turns the common
    // spelling into a startup error instead of a runtime one.
    if (options.devServer !== null && options.devServer.port === options.port
        && (options.devServer.hostname === options.host
            || (WILDCARD.includes(options.host) && isLoopback(options.devServer.hostname)))) {
        throw new Error(`--dev-server ${options.devServer.origin} is this server's own address, `
            + "so every XUI request would be proxied back here. Point it at the Vite dev server, "
            + "or move this server with --port.");
    }

    return options;
}
