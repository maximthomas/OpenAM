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
 * What the normalisation rules must and must not do.
 *
 *     node --test local/capture-lib/
 *
 * These are string-rewriting rules over a fixture that is committed once and read for the rest of the
 * change, and both of their failure modes are silent: a rule that corrupts something legitimate
 * produces a capture that still parses, and a rule that quietly matches nothing produces one that
 * still looks redacted. Neither shows up in a re-record diff, because a rule that is consistently
 * wrong is consistently wrong twice. So the cases below are mostly *negative* — the things that must
 * survive untouched, and the things the audit must still catch.
 *
 * `node --test` from the standard library, deliberately: e2e/package.json's single devDependency is
 * the cache key for the Playwright browser download in .github/workflows/xui-e2e.yml, and a unit test
 * is not a good enough reason to invalidate it.
 */

import assert from "node:assert/strict";
import { mkdtemp, mkdir, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
    auditPortability, maskCredentials, normaliseHeaders, normaliseJson, normalisePortableText,
    normalisePortableValues, normaliseSetCookie, PLACEHOLDERS, portabilityTargets,
} from "./normalise.mjs";
import { removeGenerated } from "./tree.mjs";

const BASE = "http://openam.example.org:8080/openam";
const T = portabilityTargets(BASE);

/** Run the two portability passes the way capture.mjs composes them. */
function scrub (value, targets = T) {
    return normalisePortableValues(
        JSON.parse(normalisePortableText(JSON.stringify(value), targets)),
        targets,
    );
}

describe("portabilityTargets", () => {
    it("derives every target from the base URL alone", () => {
        assert.deepEqual(T, {
            baseUrl: BASE,
            hostname: "openam.example.org",
            port: "8080",
            hostAlias: "openam",
            cookieDomain: "example.org",
            context: "openam",
        });
    });

    it("does not invent an alias or a domain for an IP address", () => {
        const ip = portabilityTargets("http://192.168.1.10:8080/openam");
        assert.equal(ip.hostAlias, "192.168.1.10");
        assert.equal(ip.cookieDomain, "192.168.1.10");
    });

    it("does not invent them for a host with no dot either", () => {
        const bare = portabilityTargets("http://am:8080/openam");
        assert.equal(bare.hostAlias, "am");
        assert.equal(bare.cookieDomain, "am");
    });

    it("reports no context for a deployment at the servlet root", () => {
        assert.equal(portabilityTargets("http://am:8080/").context, "");
        assert.equal(portabilityTargets("http://am:8080").context, "");
    });

    it("ignores a trailing slash on the base URL", () => {
        assert.equal(portabilityTargets(`${BASE}/`).baseUrl, BASE);
    });
});

describe("normalisePortableText — what must survive", () => {
    // The capture carries eighteen of these. A blind replacement of the bare host alias corrupts
    // every one, which is why the alias is matched structurally instead.
    it("leaves AM's Java class names alone", () => {
        const classes = {
            a: "org.forgerock.openam.core.rest.IdentityResourceV2",
            b: "org.openidentityplatform.openam.authentication.modules.oauth2.OAuth",
        };
        assert.deepEqual(scrub(classes), classes);
    });

    it("leaves the JSON Schema spec identifier alone", () => {
        const schema = { $schema: "http://json-schema.org/draft-04/schema#" };
        assert.deepEqual(scrub(schema), schema);
    });

    it("does not treat a longer path segment as the deployment URI", () => {
        assert.deepEqual(scrub({ u: "/openam-extra/thing" }), { u: "/openam-extra/thing" });
    });

    it("leaves the realm the capture created alone", () => {
        const realm = { aliases: ["e2e-capture-alias"], name: "e2e-capture" };
        assert.deepEqual(scrub(realm), realm);
    });

    it("does nothing at all when the deployment has no context path", () => {
        const root = portabilityTargets("http://am:8080/");
        assert.deepEqual(scrub({ u: "/json/anything" }, root), { u: "/json/anything" });
    });
});

describe("normalisePortableText — what must be replaced", () => {
    it("replaces the base URL, and the authority under another scheme", () => {
        assert.deepEqual(scrub({
            a: `${BASE}/json/x`,
            b: "https://openam.example.org:8080/openam/console",
            c: "openam.example.org:8080",
        }), {
            a: "{{BASE_URL}}/json/x",
            b: "https://{{HOSTNAME}}:{{PORT}}/{{CONTEXT}}/console",
            c: "{{HOSTNAME}}:{{PORT}}",
        });
    });

    it("replaces the deployment URI at every delimiter AM uses", () => {
        assert.deepEqual(scrub({
            a: "/openam",
            b: "/openam/console",
            c: "/openam?realm=%2F",
            d: "/openam#/profile",
            e: "/openam;jsessionid=1",
        }), {
            a: "/{{CONTEXT}}",
            b: "/{{CONTEXT}}/console",
            c: "/{{CONTEXT}}?realm=%2F",
            d: "/{{CONTEXT}}#/profile",
            e: "/{{CONTEXT}};jsessionid=1",
        });
    });

    it("replaces both LDAP suffixes, whatever case the directory used", () => {
        assert.deepEqual(scrub({
            a: "uid=demo,ou=people,dc=example,dc=com",
            b: "id=demo,ou=user,dc=openam,dc=openidentityplatform,dc=org",
            c: "uid=demo,ou=people,DC=Example,DC=Com",
        }), {
            a: "uid=demo,ou=people,{{USER_SUFFIX}}",
            b: "id=demo,ou=user,{{CONFIG_SUFFIX}}",
            c: "uid=demo,ou=people,{{USER_SUFFIX}}",
        });
    });

    it("escapes a context path containing regex metacharacters", () => {
        const meta = portabilityTargets("http://h:8080/a+b(c)");
        assert.deepEqual(
            scrub({ s: "/a+b(c)/x and /aab(c)/x" }, meta),
            { s: "/{{CONTEXT}}/x and /aab(c)/x" },
        );
    });

    it("is idempotent, so a re-run cannot drift", () => {
        const once = scrub({ u: `${BASE}/console`, dn: "uid=demo,dc=example,dc=com" });
        assert.deepEqual(scrub(once), once);
    });
});

describe("normalisePortableValues", () => {
    it("replaces the host aliases but not a schema property called aliases", () => {
        assert.deepEqual(scrub({
            root: { aliases: ["openam", "openam.example.org"] },
            schema: { aliases: { type: "array" } },
            required: ["aliases"],
        }), {
            root: { aliases: ["{{HOST_ALIAS}}", "{{HOSTNAME}}"] },
            schema: { aliases: { type: "array" } },
            required: ["aliases"],
        });
    });

    it("replaces the cookie-domain list while keeping its arity", () => {
        assert.deepEqual(scrub({ domains: ["example.org", "other.net"] }),
            { domains: ["{{COOKIE_DOMAIN}}", "{{COOKIE_DOMAIN}}"] });
    });

    // Rule 14 sorts object keys so a re-record diffs clean. Rebuilding an object here in any other
    // order would reintroduce a diff on every single call.
    it("preserves the key order rule 14 established", () => {
        const sorted = normaliseJson({ b: 1, a: 2, 10: 3, 2: 4, C: 5 });
        assert.deepEqual(Object.keys(normalisePortableValues(sorted, T)), Object.keys(sorted));
    });
});

describe("normaliseSetCookie", () => {
    it("masks the session cookie value and its domain", () => {
        assert.equal(
            normaliseSetCookie("iPlanetDirectoryPro=AQIC5w…;path=/;domain=example.org;SameSite=Lax"),
            "iPlanetDirectoryPro=<TOKEN>;path=/;domain={{COOKIE_DOMAIN}};SameSite=Lax",
        );
    });

    it("masks the server id", () => {
        assert.equal(normaliseSetCookie("amlbcookie=01;path=/;domain=example.org"),
            "amlbcookie={{SERVER_ID}};path=/;domain={{COOKIE_DOMAIN}}");
    });

    // The sentinel is what distinguishes a login that cleared the auth cookie from one that did not.
    it("keeps the LOGOUT sentinel while still normalising its domain", () => {
        assert.equal(
            normaliseSetCookie(
                "AMAuthCookie=LOGOUT; Expires=Thu, 01 Jan 1970 00:00:10 GMT; Domain=example.org; Path=/",
            ),
            "AMAuthCookie=LOGOUT; Expires=Thu, 01 Jan 1970 00:00:10 GMT; Domain={{COOKIE_DOMAIN}}; Path=/",
        );
    });

    it("does not render a cleared cookie as if it carried a value", () => {
        assert.equal(normaliseSetCookie("amlbcookie=;path=/"), "amlbcookie=;path=/");
    });

    it("preserves the attribute name's case, which AM varies", () => {
        assert.match(normaliseSetCookie("x=1;Domain=example.org"), /Domain=\{\{COOKIE_DOMAIN\}\}/);
        assert.match(normaliseSetCookie("x=1;domain=example.org"), /domain=\{\{COOKIE_DOMAIN\}\}/);
    });

    it("leaves an unknown cookie's value alone", () => {
        assert.equal(normaliseSetCookie("other=keepme;path=/"), "other=keepme;path=/");
    });

    it("does not match an attribute merely ending in domain=", () => {
        assert.equal(normaliseSetCookie("x=1;xdomain=example.org"), "x=1;xdomain=example.org");
    });

    it("round-trips a line with no value", () => {
        assert.equal(normaliseSetCookie("novalue"), "novalue");
    });
});

describe("auditPortability", () => {
    const audit = (value, targets = T) => auditPortability(JSON.stringify(value), targets);

    it("passes what the rules have normalised", () => {
        assert.deepEqual(audit(scrub({
            u: `${BASE}/console`,
            dn: "uid=demo,dc=example,dc=com",
            aliases: ["openam", "openam.example.org"],
            domains: ["example.org"],
        })), []);
    });

    // One leaked value often trips several checks — a full base URL contains the host name, the cookie
    // domain and the deployment URI — so these assert on the survivor reported, not on how many.
    for (const [what, value, reported] of [
        ["the base URL", { u: `${BASE}/json/x` }, /the base URL/],
        ["the host name", { aliases: ["openam.example.org"] }, /the host name/],
        ["the cookie domain", { domains: ["example.org"] }, /the cookie domain/],
        ["the deployment URI", { u: "/openam/console" }, /the deployment URI/],
        ["an unlisted LDAP suffix", { dn: "uid=x,dc=other,dc=net" }, /an LDAP suffix "dc=other,dc=net"/],
        ["an uppercase LDAP suffix", { dn: "uid=x,DC=Other,DC=Net" }, /an LDAP suffix "DC=Other,DC=Net"/],
        ["a server id", { h: ["amlbcookie=01;path=/"] }, /a server id "amlbcookie=01"/],
    ]) {
        it(`catches ${what}`, () => {
            assert.ok(audit(value).some((survivor) => reported.test(survivor)),
                `${JSON.stringify(value)} reported ${JSON.stringify(audit(value))}`);
        });
    }

    it("catches a port left behind by an authority without its scheme", () => {
        assert.equal(auditPortability('{"u":"{{HOSTNAME}}:8080/x"}', T).length, 1);
    });

    it("does not read a word ending in dc= as a DN", () => {
        assert.deepEqual(audit({ x: "abcdc=foo" }), []);
    });

    it("does not flag a cleared load-balancer cookie", () => {
        assert.deepEqual(audit({ h: ["amlbcookie=;path=/"] }), []);
    });

    it("quotes the surrounding text, so an unattended failure is diagnosable", () => {
        const [survivor] = audit({ dn: "uid=someone,ou=people,dc=other,dc=net" });
        assert.match(survivor, /uid=someone,ou=people/);
    });

    // A root-context deployment must not turn every path into a hit.
    it("stays quiet when there is no context to look for", () => {
        assert.deepEqual(audit({ u: "/json/anything" }, portabilityTargets("http://am:8080/")), []);
    });
});

describe("maskCredentials", () => {
    const credentials = new Set(["changeit"]);
    const callback = (value) => ({ callbacks: [{ type: "PasswordCallback", input: [{ value }] }] });

    it("masks a password the run authenticated with", () => {
        assert.equal(maskCredentials(callback("changeit"), credentials)
            .callbacks[0].input[0].value, "<PASSWORD>");
    });

    // The 401 leg is documentation: masking it would leave nobody able to see why it failed.
    it("keeps the deliberately wrong password of the failure case", () => {
        assert.equal(maskCredentials(callback("not-the-password"), credentials)
            .callbacks[0].input[0].value, "not-the-password");
    });

    it("does not touch the same string outside a PasswordCallback", () => {
        assert.deepEqual(maskCredentials({ note: "changeit" }, credentials), { note: "changeit" });
    });
});

describe("normaliseHeaders", () => {
    it("drops the headers that move on a byte-identical body, and sorts the rest", () => {
        const headers = new Headers({
            "x-frame-options": "SAMEORIGIN",
            "content-type": "application/json",
            date: "Tue, 12 Aug 2026 09:00:00 GMT",
            etag: "\"-546398656\"",
            "content-length": "42",
        });
        assert.deepEqual(Object.keys(normaliseHeaders(headers, [])),
            ["content-type", "x-frame-options"]);
    });
});

describe("normaliseJson — the war build stamp (rules 15, 16)", () => {
    // The exact shape of json/serverinfo/version/GET.json's body. `date` and `revision` are
    // regenerated by the `mvn install` the drift job runs before it records, so pinning them makes
    // that job red on every run; `version` moves only on a version bump, which is the signal the job
    // exists to raise. Getting this backwards in either direction is silent: masking `version` loses
    // the only notice that AM was upgraded, and pinning the other two loses the whole job.
    it("replaces the build date and revision, and leaves the version pinned", () => {
        assert.deepEqual(normaliseJson({
            date: "2026-August-04 10:48",
            revision: "fc8e2e67c7",
            version: "16.2.0-SNAPSHOT",
        }), {
            date: "<BUILD-DATE>",
            revision: "<REVISION>",
            version: "16.2.0-SNAPSHOT",
        });
    });

    // `date` is a generic key, and an SMS schema is entitled to a property called that. The rule
    // fires on strings only, so a property *named* `date` — whose value is its schema object — is
    // untouched. This is the guard that keeps rule 15 narrow enough to live in SCALAR_RULES.
    it("leaves a schema property named date alone, because its value is not a string", () => {
        const schema = { properties: { date: { type: "string", title: "Date" } } };
        assert.deepEqual(normaliseJson(schema), schema);
    });

    it("describes both placeholders it can emit", () => {
        for (const placeholder of ["<BUILD-DATE>", "<REVISION>"]) {
            assert.ok(PLACEHOLDERS[placeholder], `${placeholder} has no entry in PLACEHOLDERS`);
        }
    });
});

describe("PLACEHOLDERS", () => {
    it("describes every placeholder the rules can emit", () => {
        const emitted = new Set(Object.values(scrub({
            u: `${BASE}/console`,
            dn: "uid=demo,dc=example,dc=com",
            id: "id=x,dc=openam,dc=openidentityplatform,dc=org",
            aliases: ["openam", "openam.example.org"],
            domains: ["example.org"],
            authority: "openam.example.org:8080",
        })).flat().flatMap((v) => String(v).match(/\{\{[A-Z_]+\}\}/g) ?? []));

        for (const placeholder of emitted) {
            assert.ok(PLACEHOLDERS[placeholder], `${placeholder} has no entry in PLACEHOLDERS`);
        }
    });

    it("records what each placeholder means, never the value it replaced", () => {
        for (const description of Object.values(PLACEHOLDERS)) {
            assert.doesNotMatch(description, /openam\.example\.org|8080|dc=/);
        }
    });
});

describe("removeGenerated", () => {
    const record = (path) => ({ entry: { id: "x", method: "GET", path } });

    it("removes what the run writes and leaves the committed README", async () => {
        const dir = await mkdtemp(join(tmpdir(), "capture-test-"));
        await mkdir(join(dir, "json", "a"), { recursive: true });
        await writeFile(join(dir, "json", "a", "GET.json"), "{}");
        await writeFile(join(dir, "index.json"), "{}");
        await writeFile(join(dir, "README.md"), "# kept");

        await removeGenerated(dir, [record("/json/a")]);
        assert.deepEqual(await readdir(dir), ["README.md"]);
    });

    // Assembled from a manifest path and handed to a recursive delete: ".." would resolve to the
    // parent of --out, which for the default is the directory holding the tool itself.
    it("refuses a path whose first segment escapes the output directory", async () => {
        await assert.rejects(() => removeGenerated("/nonexistent", [record("/../escape")]),
            /escapes the output directory/);
    });
});
