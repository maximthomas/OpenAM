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
 * What "the built XUI" has to resolve to, from each of the three forms.
 *
 *     node --test local/server-lib/
 *
 * The property under test is the one task 2.5 exists for: a zip and the directory it unpacks to
 * are the same tree, so pointing this server at either serves the same bytes. The zips here are
 * built in-process rather than by shelling out to `zip`, so the test needs no more tooling than
 * the server does.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, readdir, realpath, rm, stat, writeFile }
    from "node:fs/promises";
import { after, describe, it } from "node:test";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { USAGE } from "./options.mjs";
import { defaultSource, resolveXuiSource } from "./xui-source.mjs";

const INDEX_HTML = "<!DOCTYPE html><title>XUI</title>\n";
const APP_CONFIG = "define([], function () { return { moduleDefinition: [] }; });\n";

const created = [];

/** A temp directory this file will remove, however the test that asked for it ends. */
async function scratch () {
    const dir = await mkdtemp(join(tmpdir(), "xui-source-test-"));
    created.push(dir);
    return dir;
}

after(async () => {
    await Promise.all(created.map((dir) => rm(dir, { recursive: true, force: true })));
});

/** A minimal XUI build: an index.html at the root, and one file below it. */
const XUI_ENTRIES = [
    { name: "index.html", data: INDEX_HTML },
    { name: "config/AppConfiguration.js", data: APP_CONFIG },
];

async function buildDir (entries = XUI_ENTRIES) {
    const root = join(await scratch(), "compiled");
    for (const { name, data } of entries) {
        const file = join(root, name);
        await mkdir(join(file, ".."), { recursive: true });
        await writeFile(file, data);
    }
    return root;
}

async function buildZip (entries = XUI_ENTRIES) {
    const zip = join(await scratch(), "openam-ui-ria-1.0-www.zip");
    await writeFile(zip, zipOf(entries));
    return zip;
}

/** Every file under `dir`, as `relative path -> sha256`. */
async function digest (dir, prefix = "") {
    const out = {};
    for (const entry of await readdir(dir, { withFileTypes: true })) {
        const name = prefix + entry.name;
        if (entry.isDirectory()) {
            Object.assign(out, await digest(join(dir, entry.name), `${name}/`));
        } else {
            out[name] = createHash("sha256").update(await readFile(join(dir, entry.name))).digest("hex");
        }
    }
    return out;
}

describe("a directory", () => {
    it("is served as it stands, with nothing staged", async () => {
        const dir = await buildDir();
        const resolved = await resolveXuiSource(dir, {});

        assert.equal(resolved.staging, null);
        assert.equal(resolved.source, dir);
        // realpath, not the argument: /var is a link to /private/var on macOS, and static-tree.mjs
        // decides what is inside the tree by comparing against this string.
        assert.equal(resolved.root, await realpath(dir));
    });

    it("survives its own cleanup, which has nothing to undo", async () => {
        const dir = await buildDir();
        const resolved = await resolveXuiSource(dir, {});
        await resolved.cleanup();
        assert.ok((await stat(join(dir, "index.html"))).isFile());
    });

    it("is refused when it holds no index.html, rather than 404ing every module later", async () => {
        const dir = await buildDir([{ name: "main.js", data: "" }]);
        await assert.rejects(() => resolveXuiSource(dir, {}), /does not look like an XUI build/);
    });
});

describe("a zip", () => {
    it("is unpacked, and the staged tree is what gets served", async () => {
        const zip = await buildZip();
        const resolved = await resolveXuiSource(zip, {});

        assert.equal(resolved.source, zip);
        assert.equal(resolved.root, resolved.staging);
        assert.equal(await readFile(join(resolved.root, "index.html"), "utf8"), INDEX_HTML);
        await resolved.cleanup();
    });

    it("unpacks with no top-level directory, as zip.xml's baseDirectory promises", async () => {
        // If this ever stopped holding, the index.html guard would catch it -- this says which
        // shape is being relied on, so the failure names the assembly descriptor.
        const resolved = await resolveXuiSource(await buildZip(), {});
        assert.deepEqual((await readdir(resolved.root)).sort(), ["config", "index.html"]);
        await resolved.cleanup();
    });

    it("produces byte-for-byte what the same build in a directory produces", async () => {
        // Task 2.5's whole point: one artifact, either backend. If these two ever differ, "the
        // build that passed against the local server" and "the build deployed to AM" are not the
        // same thing, and every comparison drawn between the backends is worth less than it looks.
        const fromZip = await resolveXuiSource(await buildZip(), {});
        const fromDir = await resolveXuiSource(await buildDir(), {});

        assert.deepEqual(await digest(fromZip.root), await digest(fromDir.root));
        await fromZip.cleanup();
    });

    it("removes the staged tree on cleanup", async () => {
        const resolved = await resolveXuiSource(await buildZip(), {});
        await resolved.cleanup();
        await assert.rejects(() => stat(resolved.staging), { code: "ENOENT" });
    });

    it("cleans up after itself when the zip is not an XUI build", async () => {
        // The staging directory must not outlive a start that failed -- a temp tree per rejected
        // zip is exactly the litter the ephemeral-staging choice was meant to avoid.
        const zip = await buildZip([{ name: "XUI/index.html", data: INDEX_HTML }]);
        const before = await stagingDirs();

        await assert.rejects(() => resolveXuiSource(zip, {}), /does not look like an XUI build/);

        // Counted rather than listed: an earlier crashed run's directory is the OS's to reap, and
        // failing this test over one would be reporting the wrong thing.
        assert.deepEqual(await stagingDirs(), before,
            "a rejected zip left a staging directory behind");
    });

    it("reports a file that is not a zip at all, rather than serving an empty tree", async () => {
        const notAZip = join(await scratch(), "notes.txt");
        await writeFile(notAZip, "this is not a zip\n");
        await assert.rejects(() => resolveXuiSource(notAZip, {}), /could not unpack/);
    });

    it("leaves nothing staged when it is told to stop mid-unpack", async () => {
        // Unpacking is most of startup, so this is where a Ctrl-C lands. Before the signal was
        // threaded through, the process died on Node's default handler with the tree still on
        // disk -- and a leak per aborted start is unbounded, since nothing ever reclaims it.
        const zip = await buildZip();
        const before = await stagingDirs();

        await assert.rejects(() => resolveXuiSource(zip, { signal: AbortSignal.abort() }),
            { name: "AbortError" });

        assert.deepEqual(await stagingDirs(), before,
            "an aborted unpack left a staging directory behind");
    });

    it("names the staging directory before unpacking into it, not on the way out", async () => {
        // What a teardown that cannot wait -- a second Ctrl-C, which has no way to await anything
        // -- uses to find the tree. Reported on return instead, it would be unavailable for the
        // whole of the unpack, which is the window such a teardown happens in.
        const announced = [];
        const resolved = await resolveXuiSource(await buildZip(),
            { onStaging: (dir) => announced.push(dir) });

        assert.deepEqual(announced, [resolved.staging]);
        await resolved.cleanup();
    });

    it("names it even when the unpack then fails", async () => {
        const announced = [];
        await assert.rejects(() => resolveXuiSource(join("nowhere", "x.zip"),
            { onStaging: (dir) => announced.push(dir) }));

        const zip = await buildZip();
        await assert.rejects(
            () => resolveXuiSource(zip, { signal: AbortSignal.abort(),
                onStaging: (dir) => announced.push(dir) }),
            { name: "AbortError" });

        // One entry: the missing zip never got as far as staging, the aborted one did.
        assert.equal(announced.length, 1);
        await assert.rejects(() => stat(announced[0]), { code: "ENOENT" });
    });

    it("reports a stop as a stop, not as a broken zip", async () => {
        // The caller exits quietly on this name; a "could not unpack" here would send someone
        // looking at the artifact when all that happened is that they pressed Ctrl-C.
        const zip = await buildZip();
        await assert.rejects(() => resolveXuiSource(zip, { signal: AbortSignal.abort() }),
            (error) => error.name === "AbortError" && !/could not unpack/.test(error.message));
    });

    it("names unzip when unzip is what is missing, and offers the way round it", async () => {
        // The one dependency this server has outside Node, so the message an operator without it
        // gets has to say which of the two things -- the binary or the zip -- was not found.
        const zip = await buildZip();
        const path = process.env.PATH;
        process.env.PATH = "";
        try {
            await assert.rejects(() => resolveXuiSource(zip, {}),
                /unzip not found[\s\S]*path\/to\/outDir/);
        } finally {
            process.env.PATH = path;
        }
    });
});

describe("nothing named", () => {
    it("is the www zip for the version in the reactor root pom", async () => {
        const repo = await scratch();
        await writeFile(join(repo, "pom.xml"),
            "<project>\n  <artifactId>openam</artifactId>\n  <version>16.2.0-SNAPSHOT</version>\n");

        assert.equal(await defaultSource(repo),
            join(repo, "openam-ui", "openam-ui-ria", "target",
                "openam-ui-ria-16.2.0-SNAPSHOT-www.zip"));
    });

    it("takes the first version, as am_version() in lib.sh does", async () => {
        // The root pom declares no <parent>, so the first <version> is the project's; the ones
        // further down are plugin and dependency versions.
        const repo = await scratch();
        await writeFile(join(repo, "pom.xml"), `<project>
  <version>16.2.0-SNAPSHOT</version>
  <build><plugins><plugin><version>1.6</version></plugin></plugins></build>
</project>`);

        assert.match(await defaultSource(repo), /openam-ui-ria-16\.2\.0-SNAPSHOT-www\.zip$/);
    });

    it("is at the path --help says it is at", async () => {
        // These drifted apart once already: the usage line lost its leading openam-ui/ segment and
        // sent anyone whose start had just failed to a path that does not exist in the checkout.
        const repo = await scratch();
        await writeFile(join(repo, "pom.xml"), "<project><version>9.9.9</version></project>");

        const real = await defaultSource(repo);
        const documented = real.slice(repo.length + 1).replace("9.9.9", "<version>");
        assert.ok(USAGE.includes(documented),
            `--help documents a default the code does not use:\n  code  ${documented}\n${USAGE}`);
    });

    it("says to build it, when the zip the pom names is not there", async () => {
        const repo = await scratch();
        await writeFile(join(repo, "pom.xml"), "<project><version>9.9.9</version></project>");

        await assert.rejects(() => resolveXuiSource(null, { repoRoot: repo }),
            /no built XUI at .*openam-ui-ria-9\.9\.9-www\.zip[\s\S]*mvn -DskipTests package/);
    });

    it("says so when there is no pom to read the version from", async () => {
        const repo = await scratch();
        await assert.rejects(() => resolveXuiSource(null, { repoRoot: repo }),
            /cannot read .*pom\.xml/);
    });
});

describe("a path that is neither", () => {
    it("is reported as such, in xui-deploy.sh's words", async () => {
        const missing = join(await scratch(), "nowhere");
        await assert.rejects(() => resolveXuiSource(missing, {}),
            new RegExp(`not a file or directory: ${missing}`));
    });
});

/** The staging directories present in the temp directory right now, sorted. */
async function stagingDirs () {
    return (await readdir(tmpdir())).filter((name) => name.startsWith("xui-www-")).sort();
}

/**
 * A zip holding `entries`, stored rather than deflated.
 *
 * Written out by hand so the tests need no `zip` binary: the server's one system dependency is
 * `unzip`, and adding a second one to prove the first works would be a poor trade. Stored entries
 * are the format's simplest case -- local header, bytes, central directory, end record -- and
 * `unzip` reads them the same way it reads Maven's deflated output, including the CRC check that
 * is the reason for the table below.
 */
function zipOf (entries) {
    const locals = [];
    const central = [];
    let offset = 0;

    for (const { name, data } of entries) {
        const nameBytes = Buffer.from(name, "utf8");
        const body = Buffer.from(data, "utf8");
        const crc = crc32(body);

        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0);   // local file header signature
        local.writeUInt16LE(20, 4);           // version needed to extract
        local.writeUInt16LE(0, 8);            // compression method: stored
        local.writeUInt16LE(0x0021, 12);      // modified date: 1980-01-01, the epoch of the format
        local.writeUInt32LE(crc, 14);
        local.writeUInt32LE(body.length, 18); // compressed size
        local.writeUInt32LE(body.length, 22); // uncompressed size
        local.writeUInt16LE(nameBytes.length, 26);
        locals.push(local, nameBytes, body);

        const entry = Buffer.alloc(46);
        entry.writeUInt32LE(0x02014b50, 0);   // central directory header signature
        entry.writeUInt16LE(20, 4);           // version made by
        entry.writeUInt16LE(20, 6);           // version needed to extract
        entry.writeUInt16LE(0, 10);           // compression method: stored
        entry.writeUInt16LE(0x0021, 14);
        entry.writeUInt32LE(crc, 16);
        entry.writeUInt32LE(body.length, 20);
        entry.writeUInt32LE(body.length, 24);
        entry.writeUInt16LE(nameBytes.length, 28);
        entry.writeUInt32LE(offset, 42);      // offset of the local header above
        central.push(entry, nameBytes);

        offset += local.length + nameBytes.length + body.length;
    }

    const directory = Buffer.concat(central);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);         // end of central directory signature
    end.writeUInt16LE(entries.length, 8);     // entries on this disk
    end.writeUInt16LE(entries.length, 10);    // entries in total
    end.writeUInt32LE(directory.length, 12);
    end.writeUInt32LE(offset, 16);            // where the central directory starts

    return Buffer.concat([...locals, directory, end]);
}

const CRC_TABLE = Array.from({ length: 256 }, (unused, index) => {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
        value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    return value >>> 0;
});

function crc32 (buffer) {
    let crc = 0xffffffff;
    for (const byte of buffer) {
        crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
    }
    return (crc ^ 0xffffffff) >>> 0;
}
