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
 * Copyright 2016 ForgeRock AS.
 * Portions copyright 2026 3A Systems, LLC.
 */

/*
 * ES module port of src/test/js/org/forgerock/openam/ui/common/util/uri/queryTest.js -- same
 * tests, same names, same order. Task 9.2 (D12): Squire's injector is replaced by vi.mock, and
 * nothing else changes.
 *
 * THE SPECIFIER IS THE BARE AMD ID, not a path to the file. The subject is query.jsm, and a
 * vi.mock specifier that does not resolve is a silent no-op -- the test would run against the
 * real URIUtils and this file's last two cases would then be asserting about the jsdom URL. The
 * bare id goes through resolve.extensions and cannot get the extension wrong.
 *
 * THE MOCK OBJECT HAS FILE LIFETIME, ITS CONTENTS HAVE CASE LIFETIME. vi.mock is hoisted above
 * every import and its factory runs once, so it cannot close over an object beforeEach rebuilds.
 * The holder below keeps one identity for the whole file and beforeEach replaces what is on it,
 * which is what Squire got for free by building a new injector per case.
 *
 * The subject is imported statically: it holds no module-scope state, so one instance per file
 * is the same thing Squire's fresh context gave it. `import * as query` rather than a default,
 * because query.jsm exports named functions and getCurrentQueryParameters reaches its sibling
 * through `this`.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import sinon from "sinon";
import * as query from "org/forgerock/openam/ui/common/util/uri/query";

const mocks = vi.hoisted(() => ({ URIUtils: {} }));

vi.mock("org/forgerock/commons/ui/common/util/URIUtils", () => ({ "default": mocks.URIUtils }));

let URIUtils;

beforeEach(() => {
    URIUtils = mocks.URIUtils;

    Object.keys(URIUtils).forEach((key) => delete URIUtils[key]);

    URIUtils.getCurrentQueryString = sinon.stub();
});

describe("org/forgerock/openam/ui/common/uri/query", () => {
    describe("#urlParamsFromObject", () => {
        describe("when the argument is an object of key value pairs", () => {
            it("returns a query string", () => {
                const params = { foo:"bar", alice:"bob" };
                expect(query.urlParamsFromObject(params)).eql("foo=bar&alice=bob");
            });
        });
        describe("when the argument is an empty object", () => {
            it("returns an empty string", () => {
                const params = {};
                expect(query.urlParamsFromObject(params)).eql("");
            });
        });
        describe("when no argument is provided", () => {
            it("returns an empty string", () => {
                expect(query.urlParamsFromObject()).eql("");
            });
        });
    });

    describe("#parseParameters", () => {
        describe("when param string is provided", () => {
            it("returns an empty object.", () => {
                const string = "";
                expect(query.parseParameters(string)).eql({});
            });
        });

        describe("when a param string is provided", () => {
            it("returns an object of key pair values", () => {
                const string = "foo=bar&alice=bob";
                expect(query.parseParameters(string)).eql({ foo:"bar", alice:"bob" });
            });
        });
    });

    describe("#getCurrentQueryParameters", () => {
        describe("when the current url contains a query", () => {
            it("returns an object of key pair values", () => {
                URIUtils.getCurrentQueryString.returns("foo=bar&alice=bob");
                expect(query.getCurrentQueryParameters()).eql({ foo:"bar", alice:"bob" });
            });
        });

        describe("when the current url has no query", () => {
            it("returns an empty object.", () => {
                URIUtils.getCurrentQueryString.returns("");
                expect(query.getCurrentQueryParameters()).eql({});
            });
        });
    });
});
