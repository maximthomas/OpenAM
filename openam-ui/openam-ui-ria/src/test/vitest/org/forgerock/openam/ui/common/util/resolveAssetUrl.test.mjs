/**
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

/*
 * ES module port of src/test/js/org/forgerock/openam/ui/common/util/resolveAssetUrlTest.js --
 * same tests, same names, same order. Task 9.2 (D12).
 *
 * THE ONLY FILE OF THE TEN THAT MOCKED NOTHING. It used Squire purely as a module-registry
 * reset: `new Squire().require([subject])` per case, no .mock() call anywhere, because the
 * subject holds `urlArgs` and `resolved` at module scope and each case needs them unset. So
 * there is no vi.mock in this port at all -- vi.resetModules() replaces the whole of what Squire
 * was doing here, and the seven cases that never touch `require` pass unchanged.
 *
 * ============================================================================================
 * FOUR OF THESE TWELVE CASES FAIL, DELIBERATELY LEFT FAILING. Read this before "fixing" them.
 * ============================================================================================
 *
 * Five cases touch `require.toUrl`; four of them fail and the fifth is the green-for-the-wrong-
 * reason described at the end. They cannot be expressed under Vitest at all. Measured, not
 * assumed:
 *
 *   - Vitest gives EVERY SSR-transformed module its own Node CJS require, minted per module by
 *     vite-node (`require: createRequire(href)`, vite-node/dist/client.mjs:371). Its keys are
 *     resolve, main, extensions, cache.
 *   - That module-scope binding SHADOWS the global, so assigning globalThis.require is invisible
 *     to the subject. Measured: the require this test file sees and the require resolveAssetUrl.js
 *     sees are different objects, and neither is globalThis.require.
 *   - So the subject's guard `typeof require !== "undefined" && require.toUrl` takes the WORST
 *     branch: the typeof is true, toUrl is undefined, and it throws the configure() error.
 *
 * There is no seam to redirect this to, which is what makes it different from ThemeManagerTest:
 * there the stand-in moved to resolveAssetUrl, the module that now owns asset-url resolution.
 * Here `require` IS the subject of the five cases.
 *
 * THE BRANCH IS NOT DEAD CODE and these five are not obsolete. The six openam-oauth2 .ftl entry
 * points still load RequireJS by literal script tag and still reach the delegating branch, per
 * the subject's own header. What is gone is any way for a Vitest module scope to reach it.
 *
 * THE FOUR FAIL IN THREE DIFFERENT WAYS, all downstream of the same cause:
 *
 *   "delegates to require.toUrl ..."          TypeError: Cannot stub non-existent own property
 *                                             toUrl -- sinon never gets as far as the subject
 *   "does not consult require.toUrl once      AssertionError: expected undefined to be false --
 *    configured"                              sandbox.stub returned no spy to read .called from
 *   "throws when it lands after a url ..."    the subject's own configure() error, thrown from
 *   "restores the unconfigured state ..."     the branch that should have delegated
 *
 * The first two differ from each other only through an ORDER DEPENDENCE this port introduces, and
 * the file is order-dependent where the original was not. The green-for-the-wrong-reason case that
 * sits between them does `const original = require.toUrl; require.toUrl = undefined; ... finally
 * { require.toUrl = original; }`. Under Karma `original` was a real function; under Vitest it is
 * undefined, so the finally CREATES an own `toUrl` property whose value is undefined. sinon then
 * stops throwing: collection.js:88-98 takes its "own property exists but is not a function" branch,
 * assigns and returns a bare {restore} carrying no .called. Hence "cannot stub" for the case that
 * runs before it and "expected undefined to be false" for the one that runs after.
 *
 * COVERAGE CONSEQUENCE, recorded here because this is the file someone will open: ThemeManagerTest
 * used to cover the same delegating branch through its own require.toUrl stub, and this task moved
 * that stand-in onto a vi.mock of THIS module. With these four red, the require.toUrl branch of
 * resolveAssetUrl.js has NO passing unit coverage anywhere in the suite. The e2e specs
 * (xui-authorize, xui-device, xui-cache-busting) are the only remaining check on it.
 *
 * AND THE FIFTH PASSES FOR THE WRONG REASON, so do not read that green as coverage:
 * "throws when there is no require.toUrl to delegate to" sets require.toUrl = undefined on THIS
 * file's require and asserts the subject throws. The subject does throw -- but because its own
 * require never had a toUrl, not because this file removed one.
 *
 * Recorded here rather than repaired because task 9.2 replaces a mocking mechanism and changes
 * nothing else. The fix, if one is wanted, is a one-line source change (`globalThis.require`),
 * and that is a decision for whoever owns resolveAssetUrl.js, not for this port.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import sinon from "sinon";

describe("org/forgerock/openam/ui/common/util/resolveAssetUrl", () => {
    const stubbedBase = "toUrl:";
    let resolveAssetUrl;
    let sandbox;

    beforeEach(async () => {
        sandbox = sinon.sandbox.create();
        /*
         * A fresh module per test, because the module holds `urlArgs` and `resolved` at
         * module scope. Squire gave each injector its own RequireJS context; ES modules cache
         * one instance per process, so resetting the registry is what buys the same
         * isolation. resolveAssetUrl.reset() would also do it -- the module ships that hook
         * naming this migration -- but the file has a case that tests reset() itself, and a
         * harness resting on the thing under test is worth avoiding for one line.
         */
        vi.resetModules();
        resolveAssetUrl = (await import("org/forgerock/openam/ui/common/util/resolveAssetUrl")).default;
    });

    afterEach(() => {
        sandbox.restore();
    });

    describe("unconfigured", () => {
        it("delegates to require.toUrl, which is what applies urlArgs under RequireJS", () => {
            sandbox.stub(require, "toUrl", (url) => stubbedBase + url);

            expect(resolveAssetUrl("templates/common/LoginBaseTemplate.html"))
                .to.equal(`${stubbedBase}templates/common/LoginBaseTemplate.html`);
        });

        it("throws when there is no require.toUrl to delegate to", () => {
            const original = require.toUrl;
            require.toUrl = undefined;

            try {
                expect(() => resolveAssetUrl("templates/common/LoginBaseTemplate.html"))
                    .to.throw(/called before configure\(\)/);
            } finally {
                require.toUrl = original;
            }
        });
    });

    describe("configured", () => {
        it("appends urlArgs after a ? when the url carries no query", () => {
            resolveAssetUrl.configure({ urlArgs: "v=14.8.4" });

            expect(resolveAssetUrl("templates/common/LoginBaseTemplate.html"))
                .to.equal("templates/common/LoginBaseTemplate.html?v=14.8.4");
        });

        it("appends urlArgs after an & when the url already carries a query", () => {
            resolveAssetUrl.configure({ urlArgs: "v=14.8.4" });

            expect(resolveAssetUrl("templates/common/Foo.html?a=1"))
                .to.equal("templates/common/Foo.html?a=1&v=14.8.4");
        });

        it("resolves without a cache-buster when urlArgs is empty", () => {
            resolveAssetUrl.configure({ urlArgs: "" });

            expect(resolveAssetUrl("css/structure.css")).to.equal("css/structure.css");
        });

        it("does not consult require.toUrl once configured", () => {
            const toUrl = sandbox.stub(require, "toUrl", (url) => stubbedBase + url);
            resolveAssetUrl.configure({ urlArgs: "v=14.8.4" });

            resolveAssetUrl("images/login-logo.png");

            expect(toUrl.called).to.be.false;
        });

        it("leaves a library's unexpanded placeholders untouched", () => {
            // i18next hands resGetPath through verbatim and substitutes __lng__/__ns__ itself,
            // so the string this receives is not yet a valid url and must not be parsed.
            resolveAssetUrl.configure({ urlArgs: "v=14.8.4" });

            expect(resolveAssetUrl("locales/__lng__/__ns__.json"))
                .to.equal("locales/__lng__/__ns__.json?v=14.8.4");
        });

        it("appends to a theme-prefixed path, which is what compileTemplate passes", () => {
            resolveAssetUrl.configure({ urlArgs: "v=14.8.4" });

            expect(resolveAssetUrl("themes/acme/templates/common/FooterTemplate.html"))
                .to.equal("themes/acme/templates/common/FooterTemplate.html?v=14.8.4");
        });
    });

    describe("configure", () => {
        it("rejects a missing options object", () => {
            expect(() => resolveAssetUrl.configure())
                .to.throw(/requires \{ urlArgs: <string> \}/);
        });

        it("rejects a non-string urlArgs", () => {
            expect(() => resolveAssetUrl.configure({ urlArgs: 14 }))
                .to.throw(/requires \{ urlArgs: <string> \}/);
        });

        it("throws when it lands after a url has already been resolved", () => {
            // The ordering hazard recorded in NOTES-resolve-asset-url.md section 4b: urls
            // already written into a <link href> cannot be recalled, so a late configure
            // would leave those without a cache-buster while every later url carried one.
            sandbox.stub(require, "toUrl", (url) => stubbedBase + url);
            resolveAssetUrl("themes/acme/favicon.ico");

            expect(() => resolveAssetUrl.configure({ urlArgs: "v=14.8.4" }))
                .to.throw(/after the first URL was already resolved/);
        });
    });

    describe("reset", () => {
        it("restores the unconfigured state so a later configure is accepted", () => {
            sandbox.stub(require, "toUrl", (url) => stubbedBase + url);
            resolveAssetUrl("css/structure.css");

            resolveAssetUrl.reset();
            resolveAssetUrl.configure({ urlArgs: "v=14.8.4" });

            expect(resolveAssetUrl("css/structure.css")).to.equal("css/structure.css?v=14.8.4");
        });
    });
});
