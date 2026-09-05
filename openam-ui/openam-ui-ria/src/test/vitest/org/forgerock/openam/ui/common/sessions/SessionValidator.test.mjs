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
 * ES module port of src/test/js/org/forgerock/openam/ui/common/sessions/SessionValidatorTest.js
 * -- same tests, same names, same order. Task 9.2 (D12).
 *
 * A FRESH SUBJECT PER CASE IS MANDATORY HERE, and this is the file that proves why. The subject
 * holds `let delay` at module scope and `start()` throws "Validator has already been started"
 * whenever it is truthy. The "#start > when invoked for the 2nd time" beforeEach starts the
 * validator and nothing ever stops it, so with the single instance ES modules cache per process,
 * the NEXT case's first start() throws in a test that expects it not to. The module exports no
 * reset, so vi.resetModules() plus a dynamic import is the only lever; Squire got the same effect
 * from a new RequireJS context per injector.
 *
 * THE MOCK KEEPS THE `{ default: ... }` SHAPE THE ORIGINAL ASSERTS ON. The subject calls
 * `logout()` on a default import, and the original mocked the id with an object whose sole key is
 * "default" -- a shape inherited from Babel's AMD output -- then asserted on `logout.default`.
 * Both halves are preserved: the holder below IS the object the assertions read, and the factory
 * forwards to whatever `.default` it currently carries rather than capturing one, so the stub
 * beforeEach installs is the stub the subject calls. Bind them any less carefully and this file
 * goes green while testing nothing.
 *
 * `sinon.spy(window, "clearTimeout")` IN THE LAST CASE IS NEVER RESTORED, exactly as in the
 * original. It is the final case in the file and Vitest isolates module state and globals per
 * file, so the leak stops at this file's boundary; it is transcribed rather than tidied because
 * this task changes the mocking mechanism and nothing else.
 *
 * Router is left unmocked, as the original left it.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import $ from "jquery";
import sinon from "sinon";

const context = describe;

const mocks = vi.hoisted(() => ({ logout: { "default": null } }));

vi.mock("org/forgerock/openam/ui/user/login/logout", () => ({
    "default": (...args) => mocks.logout.default(...args)
}));

let logout;
let Strategy;
let validatePromise;
let Validator;
describe("org/forgerock/openam/ui/common/sessions/SessionValidator", () => {
    beforeEach(async () => {
        validatePromise = $.Deferred();

        Strategy = sinon.stub().returns(validatePromise);

        logout = mocks.logout;

        logout.default = sinon.stub().returns($.Deferred());

        vi.resetModules();
        Validator = (await import("org/forgerock/openam/ui/common/sessions/SessionValidator")).default;
    });

    describe("#start", () => {
        let clock;

        beforeEach(() => {
            clock = sinon.useFakeTimers();
        });

        afterEach(() => {
            clock.restore();
        });

        it("invokes strategy immediately", () => {
            Validator.start("token", Strategy);

            clock.tick(1000);

            expect(Strategy).be.calledOnce.calledWith("token");
        });

        context("when strategy rejects", () => {
            it("invokes #logout", () => {
                validatePromise.reject();

                Validator.start("token", Strategy);

                clock.tick(1000);

                expect(logout.default).to.be.calledOnce;
            });
        });

        context("when invoked for the 2nd time", () => {
            beforeEach(() => {
                Validator.start("token", Strategy);
            });

            it("throws error", () => {
                expect(() => {
                    Validator.start("token", Strategy);
                }).to.throw(Error, "Validator has already been started");
            });

            context("when #stop has been invoked beforehand", () => {
                it("doesn not throw error", () => {
                    Validator.stop();

                    expect(() => {
                        Validator.start("token", Strategy);
                    }).to.not.throw(Error);
                });
            });
        });
    });

    describe("#stop", () => {
        it("invokes #clearTimeout", () => {
            sinon.spy(window, "clearTimeout");

            Validator.stop();

            expect(clearTimeout).to.be.calledOnce;
        });

    });
});
