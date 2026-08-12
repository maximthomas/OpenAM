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
 * Turn "the built XUI" into a directory the server can serve — from a `www` zip or from a
 * directory, the same two inputs `xui-deploy.sh` takes.
 *
 * That sameness is the whole requirement (task 2.5, and "Backend selectable without changing the
 * UI" in specs/ui-local-backend). One artifact has to be pointable at either backend, so the two
 * things that point at them must accept the artifact in the same forms:
 *
 *   - nothing named — the built `openam-ui-ria-<version>-www.zip` under `openam-ui-ria/target/`,
 *     the distributable the server build consumes;
 *   - a zip — unpacked to a staging directory, which is then what gets served;
 *   - a directory — served as it stands. This is the phase-2 Vite `outDir` case.
 *
 * A second convention here would be worse than useless: it would mean the zip proved to work
 * against the local server and the zip deployed to AM were only assumed to be the same thing.
 *
 * **The zip has no top-level directory.** `openam-ui-ria/src/main/assembly/zip.xml` sets
 * `<baseDirectory>/</baseDirectory>` and maps `target/compiled` to `/`, so its entries map straight
 * onto a deployed `/XUI` and the staging directory *is* the tree. The `index.html` check below is
 * what says so out loud, and it is the same guard, in the same words, as xui-deploy.sh's.
 *
 * **Unpacking shells out to `unzip`**, as xui-deploy.sh does. Node has no zip reader, and the
 * alternatives were an npm dependency — ruled out, `e2e/package.json` is the CI cache key for the
 * Playwright browser download — or a hand-rolled reader over `node:zlib`, which is a hundred-odd
 * lines of format parsing and a zip-slip guard to own, where `unzip` already refuses to write
 * outside its `-d`. `common/deployed-xui-commons.mjs` and `saml/saml-test.spec.mjs` already reach
 * for a system binary the same way.
 *
 * **Staging is a temp directory, removed when the server stops** — `mkdtemp` and the shutdown path
 * standing in for xui-deploy.sh's `mktemp -d` and its `trap`. Nothing is cached between runs: a
 * stale unpacked tree outliving the zip it came from is exactly the failure xui-deploy.sh replaces
 * rather than merges to avoid, and re-unpacking 652 files costs a fraction of a second.
 *
 * Unpacking therefore takes an `AbortSignal`, and it is not optional decoration: unpacking *is*
 * startup, so a Ctrl-C aimed at a server that has not finished starting lands here, and it is the
 * likeliest Ctrl-C there is — you start the server, read the artifact it names, and stop it because
 * it is the wrong one. Aborting kills `unzip` and unwinds through the same failure path that
 * removes the directory, rather than letting the process die with the tree still on disk. With
 * that and the impatient second Ctrl-C server.mjs handles, `SIGKILL` is the only signal that can
 * strand a tree — and nothing inside a process can help with that one.
 */

import { execFile } from "node:child_process";
import { mkdtemp, readFile, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/**
 * The project version, as `am_version()` in lib.sh reads it: the first `<version>` in the reactor
 * root pom, which is the project's because that pom declares no `<parent>`.
 *
 * Resolved rather than globbed because `target/` accumulates: this checkout holds both
 * `openam-ui-ria-16.1.2-SNAPSHOT-www.zip` and `openam-ui-ria-16.2.0-SNAPSHOT-www.zip`, and a glob
 * would have to guess between them. It also means a version bump needs no edit here.
 */
const POM_VERSION = /<version>([^<]+)<\/version>/;

async function projectVersion (repoRoot) {
    const pom = join(repoRoot, "pom.xml");
    let text;
    try {
        text = await readFile(pom, "utf8");
    } catch {
        throw new Error(`cannot read ${pom}, so the built XUI's name cannot be worked out.

Name the tree or zip to serve instead:
    npm run local-server -- path/to/www.zip`);
    }

    const match = POM_VERSION.exec(text);
    if (!match) {
        throw new Error(`no <version> in ${pom}, so the built XUI's name cannot be worked out.`);
    }
    return match[1].trim();
}

/** Where `mvn package` leaves the distributable — xui-deploy.sh's default, spelled the same way. */
export async function defaultSource (repoRoot) {
    const version = await projectVersion(repoRoot);
    return join(repoRoot, "openam-ui", "openam-ui-ria", "target",
        `openam-ui-ria-${version}-www.zip`);
}

/**
 * Unpack a zip into a fresh temp directory, and clean up after a failure rather than leaving a
 * half-unpacked tree behind for the caller to serve.
 *
 * `realpath` because `os.tmpdir()` is `/var/folders/…` on macOS and `/var` is a link to
 * `/private/var`: static-tree.mjs decides what is inside the served tree by string comparison
 * against this path, so it has to be the one the filesystem agrees is canonical. Same reason
 * router.test.mjs realpaths its fixture root.
 */
async function unpack (zip, signal, onStaging) {
    const stage = await realpath(await mkdtemp(join(tmpdir(), "xui-www-")));
    // Announced the moment it exists, before a single file is written into it: between here and
    // the return below is the window where this function does not yet own a way to tell anyone
    // what to delete, and that is exactly the window a second Ctrl-C arrives in.
    onStaging?.(stage);
    try {
        // The signal kills `unzip`, and execFile does not settle until it is dead -- so the rm
        // below can never race a child still writing files back into the directory.
        await execFileAsync("unzip", ["-q", zip, "-d", stage], { signal });
    } catch (error) {
        await rm(stage, { recursive: true, force: true });

        // Asked to stop, not failed. Distinguished by name so the caller can exit quietly rather
        // than reporting a deliberate Ctrl-C as a broken zip.
        if (signal?.aborted) {
            const stopped = new Error(`stopped while unpacking ${zip}`);
            stopped.name = "AbortError";
            throw stopped;
        }

        // ENOENT here is the binary, not the zip -- a missing zip was already reported above.
        throw error.code === "ENOENT"
            ? new Error(`unzip not found, and the local API server needs it to unpack ${zip}.

Install it, or pass an already-unpacked tree:
    npm run local-server -- path/to/outDir`)
            : new Error(`could not unpack ${zip}: ${(error.stderr || error.message).trim()}`);
    }
    return stage;
}

/**
 * Refuse to serve something that is not a deployed XUI tree.
 *
 * The failure this prevents is a server that starts happily and answers 404 for every module, at
 * which point the browser console blames RequireJS and the tree that was never there is the last
 * thing anyone checks.
 */
async function requireXuiTree (dir, source) {
    try {
        await stat(join(dir, "index.html"));
    } catch {
        throw new Error(`${source} does not look like an XUI build -- no index.html at its root`);
    }
}

/**
 * Resolve what to serve into a canonical directory, plus the cleanup that undoes it.
 *
 * `source` is a path, or `null` for "the built distributable" — options.mjs leaves the default
 * unresolved because working it out reads the pom, which must not happen for `--help` or when a
 * path was named anyway.
 *
 * `signal` aborts an unpack in progress; see the note above on why startup is the window that
 * matters. Nothing else here is long enough to be worth interrupting. `onStaging` reports the
 * staging directory as soon as it exists rather than on return, so a caller that has to tear down
 * without waiting — a second Ctrl-C, which cannot await anything — knows what to remove.
 *
 * Returns `{ root, source, staging, cleanup }`: `root` is the directory to serve, `source` is what
 * the operator actually pointed at (worth logging — after a zip, `root` is a temp path that says
 * nothing), `staging` is that temp directory or `null`, and `cleanup` is idempotent and safe to
 * call on the directory case, where it does nothing.
 */
export async function resolveXuiSource (source, { repoRoot, signal, onStaging } = {}) {
    const named = source !== null && source !== undefined;
    const path = named ? source : await defaultSource(repoRoot);

    let info;
    try {
        info = await stat(path);
    } catch {
        throw new Error(named
            ? `not a file or directory: ${path}`
            : `no built XUI at ${path}

Build it first:
    cd ${repoRoot}/openam-ui/openam-ui-ria && mvn -DskipTests package

or name one to serve:
    npm run local-server -- path/to/www.zip
    npm run local-server -- path/to/outDir`);
    }

    if (info.isDirectory()) {
        const root = await realpath(path);
        await requireXuiTree(root, path);
        return { root, source: path, staging: null, cleanup: async () => {} };
    }

    if (!info.isFile()) {
        throw new Error(`not a file or directory: ${path}`);
    }

    const staging = await unpack(path, signal, onStaging);
    const cleanup = () => rm(staging, { recursive: true, force: true });
    try {
        await requireXuiTree(staging, path);
    } catch (error) {
        await cleanup();
        throw error;
    }
    return { root: staging, source: path, staging, cleanup };
}
