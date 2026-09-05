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
 * ES module port of
 * src/test/js/org/forgerock/openam/ui/common/sessions/strategies/MaxIdleTimeLeftStrategyTest.js
 * -- same tests, same names, same order.
 *
 * THE ONE Squire FILE IN TASK 9.1, and it is here on purpose: it is the smallest of the ten (two
 * cases, one mocked id, no sinon-chai, no module-scope state), so it turns "does vi.mock work
 * against this alias table at all" from a 9.2 risk into a 9.1 fact. The other nine convert in
 * 9.2.
 *
 * WHAT REPLACED Squire. The original built a fresh RequireJS context per case
 * (`new Squire().mock(id, stub).require([subject], cb)`) and finished its beforeEach with the
 * `done` callback. Here `vi.mock` intercepts the id instead. Three things about that:
 *
 * - THE SPECIFIER IS THE BARE AMD ID, deliberately, and it is the same string the subject
 *   imports. A vi.mock specifier that does not resolve is a SILENT no-op -- no error, no
 *   warning, the test simply runs against the real module -- and the commonest way to get one is
 *   an extension, since a good number of these sources are .jsm rather than .js. The bare id
 *   goes through resolve.extensions and cannot get that wrong.
 *
 * - THE MOCK IS A NAMED EXPORT, not a default. The subject does
 *   `import { getTimeLeft } from ".../SessionService"`, so the factory returns { getTimeLeft }.
 *   Under AMD the module value was the whole object and `getTimeLeft` was read off it, which is
 *   why the original could hand Squire a plain object.
 *
 * - THE FACTORY DELEGATES rather than closing over the stub. vi.mock is hoisted above every
 *   import and runs once per file, while the stub and its deferred are rebuilt once per case;
 *   a factory that captured the stub directly would pin case 1's stub for the whole file. So the
 *   factory closes over a vi.hoisted holder whose contents beforeEach replaces -- stable
 *   identity, per-case contents. This is the shape every one of the remaining nine will need.
 *
 * The mock is provably live and needs no extra assertion to prove it: 300 reaches the second
 * case only through the deferred below, and the real SessionService would issue an HTTP request
 * rather than resolve to it (SessionService.jsm routes the real getTimeLeft through
 * obj.serviceCall).
 *
 * ONE THING TO CARRY INTO 9.2 BEFORE COPYING THIS SHAPE: `vi.mock` replaces the WHOLE module.
 * The factory below publishes `getTimeLeft` and nothing else, so inside this file's graph
 * SessionService has exactly one export, where the real module has four (`getTimeLeft`,
 * `updateSessionInfo`, `isSessionValid`, `logout`). That is fine here because the subject imports
 * only `getTimeLeft`. A port whose graph reaches another export of a mocked module will get
 * `undefined` rather than the real function, and will need `vi.importActual` to put the rest
 * back.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import $ from "jquery";
import sinon from "sinon";
import MaxIdleTimeLeftStrategy from
    "org/forgerock/openam/ui/common/sessions/strategies/MaxIdleTimeLeftStrategy";

const context = describe;

const mocks = vi.hoisted(() => ({ getTimeLeft: null }));

vi.mock("org/forgerock/openam/ui/user/services/SessionService", () => ({
    getTimeLeft: (token) => mocks.getTimeLeft(token)
}));

let getTimeLeftPromise;

describe("org/forgerock/openam/ui/common/sessions/strategies/MaxIdleTimeLeftStrategy", () => {
    beforeEach(() => {
        getTimeLeftPromise = $.Deferred();

        mocks.getTimeLeft = sinon.stub().returns(getTimeLeftPromise);
    });

    it("returns a promise", () => {
        getTimeLeftPromise.resolve();
        const func = MaxIdleTimeLeftStrategy();

        expect(func.then).to.not.be.undefined;

        return func;
    });

    context("when invoked", () => {
        it("returns the idle expiration time from session service", () => {
            getTimeLeftPromise.resolve(300);
            return MaxIdleTimeLeftStrategy().then((seconds) => {
                expect(seconds).to.be.eq(300);
            });
        });
    });
});
