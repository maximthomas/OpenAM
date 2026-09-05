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
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2026 3A Systems, LLC.
 */

/*
 * ES module port of src/test/js/org/forgerock/openam/ui/common/util/RealmHelperTest.js -- same
 * tests, same names, same order. Task 9.2 (D12).
 *
 * THE ONLY FILE THAT USED Squire's `.store()`, AND IT HAS NO vi.mock EQUIVALENT. `.store()` did
 * not substitute a module: it asked for the REAL commons module and handed it back through a
 * "mocks" pseudo-module so the test could stub methods on it, isolated to that injector's
 * RequireJS context. vi.mock only substitutes, so the replacement is different in kind -- import
 * the real modules and stub them directly.
 *
 * That works because both commons modules end `export default obj` where obj is a plain mutable
 * object (checked in node_modules/@openidentityplatform/ui-commons/esm/...), so a stub planted
 * here is visible to RealmHelper, which imports the same instance. No frozen namespace, no
 * vi.spyOn needed. What is lost is the isolation: under Squire the stubs lived in a private
 * context, here they are on the module every other file in this process shares. The sandbox
 * below is what makes that safe, and it is why the sandbox is not optional the way the original's
 * per-case sinon.test sandbox looked like it was.
 *
 * `this.stub(...)` BECAME `sandbox.stub(...)`, ELEVEN TIMES, AND IT HAD TO. The original wrapped
 * each case in `sinon.test(function () { ... })`, which under Mocha was called with a Context as
 * `this` carrying a sandbox that auto-restored. Vitest passes a TestContext as the first ARGUMENT
 * and leaves `this` unbound, so every one of those eleven `this.stub` calls would throw
 * "Cannot read properties of undefined (reading 'stub')" before asserting anything. An explicit
 * sandbox in beforeEach with restore in afterEach is the same lifetime, spelled out.
 *
 * ============================================================================================
 * SIX OF THESE TWELVE CASES FAIL, AND NOT BECAUSE OF THE PORT. Read this before touching them.
 * ============================================================================================
 *
 * All six fail with one error, in the commons package rather than in AM:
 *
 *     TypeError: default.object is not a function
 *       node_modules/@openidentityplatform/ui-commons/esm/.../util/URIUtils.js:56
 *
 * That file does `import _ from "lodash"` and calls `_.object`, which is an underscore API that
 * lodash 4 does not have. It is a known defect, already catalogued: `npm run verify:lib-split`
 * reports it by name ("_.object is not on lodash -- this module binds lodash, which has no such
 * export") as one of its 17 ERRORS, and EXITS 1. Do not misread that count: the same report also
 * prints 17 semantic warnings, which are a separate, non-failing list -- this is the failing one.
 * So the lodash/underscore split gate is currently RED, and because RealmHelper.getOverrideRealm
 * is reached by the shipped application this is a live product defect, not a test artifact. This
 * suite is simply the first thing that EXECUTES it: RealmHelperTest is the only one of the eighteen
 * that lets a real commons module through instead of mocking it, which is exactly what `.store()`
 * was for.
 *
 * The six are the ones that route through URIUtils.parseQueryString -- #decorateURLWithOverrideRealm
 * (both), #decorateURIWithRealm, and all three of #getOverrideRealm. The other six pass, which is
 * also what proves the port itself works: they exercise the same sandbox.stub replacement for
 * this.stub on the same imported-and-stubbed real modules.
 *
 * Not repaired here. The fix belongs to the commons package's lodash/underscore split, not to a
 * test port, and task 9.2 changes a mocking mechanism and nothing else.
 *
 * `before` BECOMES `beforeAll` AND STAYS ONCE-PER-FILE. That makes the file order-dependent --
 * cases mutate Configuration.globalData.auth.subRealm and nothing resets it between them -- which
 * is exactly as true of the original. Transcribed, not repaired.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import sinon from "sinon";
import Configuration from "org/forgerock/commons/ui/common/main/Configuration";
import URIUtils from "org/forgerock/commons/ui/common/util/URIUtils";
import RealmHelper from "org/forgerock/openam/ui/common/util/RealmHelper";

describe("org/forgerock/openam/ui/common/util/RealmHelper", () => {
    let sandbox;

    beforeAll(() => {
        Configuration.globalData = {
            auth: {
                subRealm: undefined
            }
        };
    });

    beforeEach(() => {
        sandbox = sinon.sandbox.create();
    });

    afterEach(() => {
        sandbox.restore();
    });

    describe("#decorateURLWithOverrideRealm", () => {
        it("appends the current query string to the URL", () => {
            sandbox.stub(URIUtils, "getCurrentQueryString").returns("realm=realm1");

            expect(RealmHelper.decorateURLWithOverrideRealm("http://www.example.com"))
                .to.equal("http://www.example.com?realm=realm1");
        });

        it("merges any existing query string with the current query string", () => {
            sandbox.stub(URIUtils, "getCurrentQueryString").returns("realm=realm1");

            expect(RealmHelper.decorateURLWithOverrideRealm("http://www.example.com?key=value"))
                .to.equal("http://www.example.com?key=value&realm=realm1");
        });
    });

    describe("#decorateURIWithRealm", () => {
        it("appends as a query parameter the realm from the current query string", () => {
            Configuration.globalData.auth.subRealm = "realm1";
            sandbox.stub(URIUtils, "getCurrentQueryString").returns("realm=realm2");

            expect(RealmHelper.decorateURIWithRealm("http://www.example.com/__subrealm__/"))
                .to.equal("http://www.example.com/realm1/?realm=realm2");
        });
    });

    describe("#decorateURIWithSubRealm", () => {
        it("replaces __subrealm__ with the sub realm from global configuration", () => {
            Configuration.globalData.auth.subRealm = "realm1";

            expect(RealmHelper.decorateURIWithSubRealm("http://www.example.com/__subrealm__/"))
                .to.equal("http://www.example.com/realm1/");
        });

        it("strips out __subrealm__ when there is no sub realm", () => {
            Configuration.globalData.auth.subRealm = "";

            expect(RealmHelper.decorateURIWithSubRealm("http://www.example.com/__subrealm__/"))
                .to.equal("http://www.example.com/");
        });
    });

    describe("#getOverrideRealm", () => {
        it("returns the realm from the current query string", () => {
            sandbox.stub(URIUtils, "getCurrentQueryString").returns("realm=realm1");

            expect(RealmHelper.getOverrideRealm()).to.equal("realm1");
        });

        it("returns the realm from the fragment query when it is present", () => {
            sandbox.stub(URIUtils, "getCurrentFragmentQueryString").returns("realm=realm1");

            expect(RealmHelper.getOverrideRealm()).to.equal("realm1");
        });

        it("prefers the realm from the query string over the fragment query", () => {
            sandbox.stub(URIUtils, "getCurrentQueryString").returns("realm=realm1");
            sandbox.stub(URIUtils, "getCurrentFragmentQueryString").returns("realm=realm2");

            expect(RealmHelper.getOverrideRealm()).to.equal("realm1");
        });
    });

    describe("#getSubRealm", () => {
        it("returns the realm from the fragment path", () => {
            sandbox.stub(URIUtils, "getCurrentFragment").returns("login/realm1");

            expect(RealmHelper.getSubRealm()).to.equal("realm1");
        });

        it("prefers the realm in the global configuration over the fragment path", () => {
            sandbox.stub(URIUtils, "getCurrentFragment").returns("other");
            Configuration.globalData.auth.subRealm = "realm1";

            expect(RealmHelper.getSubRealm()).to.equal("realm1");
        });

        it("prefers the realm int he global configuration even if it is empty", () => {
            sandbox.stub(URIUtils, "getCurrentFragment").returns("other");
            Configuration.globalData.auth.subRealm = "";

            expect(RealmHelper.getSubRealm()).to.equal("");
        });

        it("normalizes the url with a subrealm by removing the trailing slash", () => {
            sandbox.stub(URIUtils, "getCurrentFragment").returns("login/realm1/");

            expect(RealmHelper.getSubRealm()).to.equal("realm1");
        });
    });
});
