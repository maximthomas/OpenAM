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
 * Portions copyright 2025 3A Systems LLC.
 * Portions copyright 2026 3A Systems, LLC.
 */

/*
 * ES module port of src/test/js/org/forgerock/openam/ui/common/util/PromiseTest.js -- same
 * tests, same names, same order. Two departures, both forced, both recorded here.
 *
 * 1. THE `done` CALLBACK IS GONE, AND IT HAD TO GO. The four `whenPassed` cases were written as
 *    `it("rejects the promise", (done) => { ... done(); })`. Vitest 2.1.9 does NOT implement
 *    Mocha's done callback, and the way it does not is worth being precise about, because the
 *    obvious reading -- "the callback is ignored" -- is wrong and would make the next person
 *    trust it. The first argument is the TestContext, which @vitest/runner builds as a CALLABLE
 *    object whose body is
 *    `throw new Error("done() callback is deprecated, use promise instead")`.
 *
 *    So `done` is not ignored: calling it throws. The throw is simply never seen. It happens
 *    inside a jQuery Deferred handler, which swallows an exception into a rejected derived
 *    promise that nobody consumes, and by then the test function has long since returned
 *    `undefined` synchronously and been marked passed.
 *
 *    Measured four ways: `done()` after a setTimeout passes; `done(new Error(...))` also passes,
 *    exit code 0; a test that never calls `done` passes instantly rather than timing out; and a
 *    trace through the exact original shape showed the rejection handler had not run AT ALL by
 *    the time `afterAll` fired -- jQuery 3 schedules `.then` handlers on a macrotask and the file
 *    is over before it arrives.
 *
 *    (With NATIVE promises the same shape surfaces as an unhandled rejection and the run exits
 *    non-zero. These four cases go through the module's `Promise.all`, which hands back a jQuery
 *    promise, so the loud failure mode is not the one available here. This is the quiet one.)
 *
 *    A transcription that kept the callback would therefore be four tests that pass while their
 *    assertions never run, which is worse than deleting them, because it looks like coverage.
 *
 *    So each returns its promise instead, and `done(new Error(...))` becomes a `throw` from the
 *    fulfilment handler -- jQuery 3's promises are Promises/A+ compliant, so the throw rejects
 *    the returned promise and Vitest fails the test with that message. The assertion, its
 *    message and the name of the test are unchanged.
 *
 * 2. `lodash` IS NOT IMPORTED. The original listed it as a define() dependency and bound it to
 *    `_`, which the file never used. As an AMD parameter that was invisible; as an ES import it
 *    is an unused binding.
 *
 * NOT CHANGED, THOUGH IT LOOKS WRONG: "returns a pending promise while the passed in promise is
 * pending" calls `t.then(...)` without returning it, so its two assertions never run -- `t` is
 * still pending when the test ends. That is exactly what the case did under Mocha. It is a
 * pre-existing wart, not something this port introduced, and fixing it here would be a rewrite
 * rather than a transcription. Left as found, flagged for whoever owns the suite next.
 */

import { describe, it, expect, beforeEach } from "vitest";
import $ from "jquery";
import sinon from "sinon";
import Promise from "org/forgerock/openam/ui/common/util/Promise";

const context = describe;

describe("org/forgerock/openam/ui/common/util/Promise", () => {
    describe("#all", () => {
        function whenPassed (value) {
            return () => {
                it("rejects the promise", () => Promise.all(value).then(() => {
                    throw new Error("Excepted the promise to be rejected");
                }, (value) => {
                    expect(value).to.be.an.instanceOf(TypeError);
                }));
            };
        }

        context("when passed null", whenPassed(null));
        context("when passed undefined", whenPassed(undefined));
        context("when passed a number", whenPassed(3));
        context("when passed an object", whenPassed({ a: 1, b: 2 }));

        context("when passed an array", () => {
            context("which is empty", () => {
                it("resolves with empty array", () => Promise.all([]).then((value) => {
                    expect(value).to.be.an.instanceOf(Array).and.to.be.empty;
                }));
            });
            context("of 1 promise", () => {
                let d;
                let p;
                let resolvedSpy;
                let rejectedSpy;
                let t;

                beforeEach(() => {
                    d = $.Deferred();
                    p = Promise.all([d.promise()]);
                    resolvedSpy = sinon.spy();
                    rejectedSpy = sinon.spy();
                    t = p.then(resolvedSpy, rejectedSpy);
                });
                it("returns a pending promise while the passed in promise is pending", () => {
                    t.then(() => {
                        expect(resolvedSpy).to.not.be.called;
                        expect(rejectedSpy).to.not.be.called;
                    });

                });
                it("resolves the returned promise when the passed in promise is resolved", () => {
                    d.resolve();
                    return t.then(() => {
                        expect(resolvedSpy).to.be.called;
                        expect(rejectedSpy).to.not.be.called;
                    });
                });
                it("rejects the returned promise when the passed in promise is rejected", () => {
                    d.reject();
                    return t.then(() => {
                        expect(resolvedSpy).to.not.be.called;
                        expect(rejectedSpy).to.be.called;
                    });
                });
                it("resolves the promise with an array containing the value of the resolved promise", () => {
                    d.resolve(1);
                    return t.then(() => {
                        expect(resolvedSpy).to.be.calledWith([1]);
                    });
                });
                it("groups multiple resolved values into an array", () => {
                    d.resolve(1, 2, 3);
                    return t.then(() => {
                        expect(resolvedSpy).to.be.calledWith([[1, 2, 3]]);
                    });
                });
                it("rejects the returned promise if the passed in promise is rejected", () => {
                    d.reject();
                    return t.then(() => {
                        expect(resolvedSpy).to.not.be.called;
                        expect(rejectedSpy).to.be.called;
                    });
                });
            });
            context("of 2 promises", () => {
                let d1;
                let d2;
                let p;
                let resolvedSpy;
                let rejectedSpy;
                let t;
                beforeEach(() => {
                    d1 = $.Deferred();
                    d2 = $.Deferred();
                    p = Promise.all([d1.promise(), d2.promise()]);
                    resolvedSpy = sinon.spy();
                    rejectedSpy = sinon.spy();
                    t = p.then(resolvedSpy, rejectedSpy);
                });
                it("doesn't resolve the returned promise if neither of the promises are resolved", () => {
                    expect(resolvedSpy).to.not.be.called;
                    expect(rejectedSpy).to.not.be.called;
                });
                it("doesn't resolve the returned promise if only the first promise is resolved", () => {
                    d1.resolve();
                    expect(resolvedSpy).to.not.be.called;
                    expect(rejectedSpy).to.not.be.called;
                });
                it("doesn't resolve the returned promise if only the second promise is resolved", () => {
                    d2.resolve();
                    expect(resolvedSpy).to.not.be.called;
                    expect(rejectedSpy).to.not.be.called;
                });
                it("resolves the returned promise when both of the promises are resolved", () => {
                    d1.resolve();
                    d2.resolve();
                    return t.then(() => {
                        expect(resolvedSpy).to.be.called;
                        expect(rejectedSpy).to.not.be.called;
                    });
                });
                it("resolves the promise with an array containing the value of the resolved promise", () => {
                    d1.resolve(1);
                    d2.resolve(2);
                    return t.then(() => {
                        expect(resolvedSpy).to.be.calledWith([1, 2]);
                    });
                });
                it("groups multiple resolved values into an array", () => {
                    d1.resolve(1, 2, 3);
                    d2.resolve(4);
                    return t.then(() => {
                        expect(resolvedSpy).to.be.calledWith([[1, 2, 3], 4]);
                    });
                });
                it("rejects the returned promise if the first promise is rejected", () => {
                    d1.reject();
                    return t.then(() => {
                        expect(resolvedSpy).to.not.be.called;
                        expect(rejectedSpy).to.be.called;
                    });
                });
                it("rejects the returned promise if the second promise is rejected", () => {
                    d2.reject();
                    return t.then(() => {
                        expect(resolvedSpy).to.not.be.called;
                        expect(rejectedSpy).to.be.called;
                    });
                });
            });
        });
    });
});
