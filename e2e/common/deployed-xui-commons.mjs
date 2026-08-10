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
 * Reading and writing the `/XUI` tree inside the running container, for the specs that have to
 * assert on what an operator can do to a *deployed* instance.
 *
 * Most of this suite drives the XUI from the outside and never touches the deployment. Two specs
 * cannot: theme template overrides (task 1.10) and an operator-supplied module named by
 * `AppConfiguration` (task 1.11) are both about files an operator adds to the deployed webapp, so
 * proving they work means putting a file there. `context.route(...).fulfill(...)` is the right tool
 * when the question is "what does the browser do with these bytes"; it is the wrong tool when the
 * question is "can an operator add this to a deployed instance at all", because intercepting the
 * response answers it by assuming it.
 *
 * Everything here shells out to `docker exec`, so it only works against the local container from
 * `local/openam-up.sh`. Specs using it are `@deployed-am` by construction.
 *
 * Two rules are encoded in these functions rather than left to their callers, because both failure
 * modes are silent:
 *
 *   - **write from inside the container, never `docker cp`.** The deployed files are
 *     `640 openam:root` and Tomcat runs as `openam`; `docker cp` replaces the file with a
 *     root-owned one the server can no longer read. See writeDeployedFile for how the mode and the
 *     owner are carried across a replacement.
 *   - **poll for what you wrote, never sleep.** See waitForServed.
 */

import { expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

/** The container the deployed `/XUI` lives in — `AM_CONTAINER` in local/lib.sh. */
export const AM_CONTAINER = process.env.OPENAM_CONTAINER ?? "openam-idp";

/** The deployed webapp's XUI root — also RequireJS's `baseUrl`, since index.html sets none. */
export const XUI_ROOT = process.env.OPENAM_XUI_ROOT ?? "/usr/local/tomcat/webapps/openam/XUI";

export function sha256 (text) {
    return createHash("sha256").update(text).digest("hex");
}

export function readDeployedFile (path) {
    return execFileSync("docker", ["exec", AM_CONTAINER, "cat", path], { encoding: "utf8" });
}

/**
 * Overwrite a file that already exists in the deployed tree, in place.
 *
 * For a file the product ships, which a fixture is temporarily editing. Take the pristine bytes
 * first and write them back in teardown; `deployedSha256` is how you prove the restore landed.
 *
 * Written through a sibling temp file and `mv` rather than straight into the target. A plain
 * `cat > "$1"` truncates before it writes, so the file is empty for the length of the write, and a
 * process death inside that window leaves a zero-length `AppConfiguration.js` deployed — which is
 * not a degraded UI but a dead one, exactly the state the operator-module spec's ordering rules
 * exist to avoid. `mv` within the same directory is a rename, so the file is only ever the old
 * bytes or the new ones.
 *
 * The temp file is seeded with `cp -p` rather than created empty, because `mv` installs *its* inode
 * and with it its mode and owner. Created fresh it would land as the container umask default, and
 * the deployed file would come out `644` where the product ships `640 openam:root` — permanently,
 * and a "restore" that changes the product's permissions is not a restore. `-p` copies both off the
 * file being replaced, so the mode travels with the bytes.
 */
export function writeDeployedFile (path, contents) {
    execFileSync("docker", ["exec", "-i", AM_CONTAINER, "sh", "-c",
        "tmp=\"$1.e2e-tmp\"; cp -p \"$1\" \"$tmp\" && cat > \"$tmp\" && mv -f \"$tmp\" \"$1\"",
        "sh", path], { input: contents });
}

export function deployedSha256 (path) {
    const output = execFileSync("docker", ["exec", AM_CONTAINER, "sha256sum", path], {
        encoding: "utf8",
    });
    return output.trim().split(/\s+/)[0];
}

/**
 * Add a file to the deployed tree, creating the directories above it.
 *
 * The path goes to `sh` as a positional argument rather than being interpolated into the script:
 * every value here is a caller's own constant today, and passing it as `$1` keeps that from
 * mattering the day one of them comes from a realm name or an environment variable.
 *
 * No backup is taken because nothing is being replaced — the files these fixtures place do not
 * exist in the shipped tree, so the restore is a removal (below), not a byte restore.
 */
export function placeDeployedFile (path, contents) {
    execFileSync("docker", ["exec", "-i", AM_CONTAINER, "sh", "-c",
        "mkdir -p \"$(dirname \"$1\")\" && cat > \"$1\"", "sh", path], { input: contents });
}

/**
 * Take a placed file, and optionally the directories it needed, back out of the deployed tree.
 *
 * `rmdir` rather than `rm -r`: it removes an empty directory and refuses a populated one, so this
 * can only ever take away directories the fixture itself created. A directory that has something
 * else in it survives, and the caller then fails on it — which is the right outcome, because the
 * tree no longer matches what the product ships.
 *
 * The script's exit status is always 0, so a failing `rm` is swallowed as silently as a failing
 * `rmdir`. That is not relied on: nothing here reports success, and every caller establishes the
 * outcome afterwards with `waitForServed` or `deployedPathExists`.
 *
 * Callable when nothing was placed, which is what lets a teardown run unconditionally.
 */
export function removeDeployedFile (path, dirs = []) {
    const args = ["exec", AM_CONTAINER, "sh", "-c",
        "target=\"$1\"; shift; rm -f \"$target\"; [ $# -eq 0 ] || rmdir \"$@\" 2>/dev/null || true",
        "sh", path, ...dirs];
    execFileSync("docker", args);
}

export function deployedPathExists (path) {
    const output = execFileSync("docker", ["exec", AM_CONTAINER, "sh", "-c",
        "if [ -e \"$1\" ]; then echo yes; else echo no; fi", "sh", path], { encoding: "utf8" });
    return output.trim() === "yes";
}

let probe = 0;

/**
 * Wait until the bytes served at a URL satisfy a predicate.
 *
 * Not decoration, and not replaceable by a sleep. Tomcat's WebResourceRoot caches static resources
 * for `cacheTtl` — 5s by default — so for several seconds after a write the file on disk and the
 * file on the wire disagree, and a page opened in that window silently gets the previous bytes. The
 * same cache makes a *removed* file take as long to disappear: Tomcat caches the miss as readily as
 * the hit, which is why teardown polls for the 404 too. There is no way round it from the client:
 * RequireJS's `urlArgs` is the fixed build version, the same string before and after the edit, so
 * the request URL cannot be varied to miss the cache.
 *
 * The probe parameter is not an attempt to dodge that cache — Tomcat keys it on the path, so it
 * cannot be dodged. It is there so that no client-side cache answers this poll instead of Tomcat.
 */
export async function waitForServed (request, url, predicate, what) {
    await expect.poll(async () => {
        probe += 1;
        const response = await request.get(`${url}?probe=${probe}`);
        return predicate(response.status(), response.ok() ? await response.text() : "");
    }, {
        message: `${url} must be served ${what}`,
        timeout: 30_000,
        intervals: [250, 500, 1000],
    }).toBe(true);
}
