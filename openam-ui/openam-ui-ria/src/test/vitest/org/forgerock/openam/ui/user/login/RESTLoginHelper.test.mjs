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
 * ES module port of src/test/js/org/forgerock/openam/ui/user/login/RESTLoginHelperTest.js --
 * same tests, same names, same order. Task 9.2 (D12).
 *
 * THE THREE MOCKS ASSERT NOTHING AND ARE NOT DECORATION. They exist to keep the subject's import
 * graph from being pulled in whole: RESTLoginHelper, AuthNService, UserModel and ViewManager
 * reach each other, and the five cases below exercise filterUrlParams, which touches none of
 * them. Squire was handed `{}` for each; the ESM equivalent is a namespace whose default is
 * `{}`, because the importers do `import X from <id>` and a factory returning a bare `{}` would
 * give them `undefined` instead.
 *
 * THIS FILE IS THE ONE WHERE A MISTYPED SPECIFIER WOULD GO UNNOTICED, which is why the check was
 * made deliberately and is written down rather than left to the reader. A vi.mock id that does
 * not resolve is a silent no-op, and everywhere else in this suite the mock is asserted on, so a
 * dud shows up as a failure. Nothing here is asserted on them, so a dud would simply load the
 * real modules -- and, as it turns out, these five cases would still pass. Both halves were
 * measured during the port with throwaway probes:
 *
 * 1. The mocks ARE applied. Importing each of the three ids from inside this file's graph
 *    returns an object with no keys, where the real modules have many.
 * 2. They are NOT load-bearing any more. Deleting all three vi.mock calls leaves the file
 *    passing 5/5 -- the import cycle Squire was breaking is not a cycle under ES modules, where
 *    the graph is resolved before any of it evaluates.
 *
 * They stay because this task replaces a mechanism and nothing else: the original mocked these
 * three ids, so the port mocks these three ids. But (2) is the reason a typo here would be
 * invisible, so re-run (1) rather than the suite if these ids are ever edited.
 *
 * `before` becomes `beforeAll` -- Vitest exports no `before`. It stays once-per-file rather than
 * being promoted to beforeEach: the subject holds no state these cases touch, and the original's
 * lifetime is part of what is being transcribed.
 */

import { describe, it, expect, beforeAll, vi } from "vitest";

const context = describe;

vi.mock("org/forgerock/openam/ui/user/services/AuthNService", () => ({ "default": {} }));
vi.mock("org/forgerock/openam/ui/user/UserModel", () => ({ "default": {} }));
vi.mock("org/forgerock/commons/ui/common/main/ViewManager", () => ({ "default": {} }));

describe("org/forgerock/openam/ui/user/login/RESTLoginHelper", () => {
    let RESTLoginHelper;

    beforeAll(async () => {
        RESTLoginHelper = (await import("org/forgerock/openam/ui/user/login/RESTLoginHelper")).default;
    });

    describe("#filterUrlParams", () => {
        it("returns a string", () => {
            expect(RESTLoginHelper.filterUrlParams()).to.be.a("string");
        });

        it("coverts an object to parameter string", () => {
            const params = {
                arg: "argValue",
                locale: "localeValue"
            };

            expect(RESTLoginHelper.filterUrlParams(params)).to.eq("&arg=argValue&locale=localeValue");
        });

        it("filters out non-allowed parameters", () => {
            const params = {
                arg: "argValue",
                authIndexType: "authIndexTypeValue",
                authIndexValue: "authIndexValueValue",
                "goto": "gotoValue",
                gotoOnFail: "gotoOnFailValue",
                ForceAuth: "ForceAuthValue",
                locale: "localeValue",
                unknown: "unknown"
            };
            const expected = "&arg=argValue&authIndexType=authIndexTypeValue&authIndexValue=authIndexValueValue" +
                           "&goto=gotoValue&gotoOnFail=gotoOnFailValue&ForceAuth=ForceAuthValue&locale=localeValue";

            expect(RESTLoginHelper.filterUrlParams(params)).to.eq(expected);
        });

        context("when all parameters are filtered out", () => {
            it("returns an empty string", () => {
                const params = {
                    unknown: "unknown"
                };

                expect(RESTLoginHelper.filterUrlParams(params)).to.eq("");
            });
        });

        context("when params is \"undefined\"", () => {
            it("returns an empty string", () => {
                expect(RESTLoginHelper.filterUrlParams(undefined)).to.eq("");
            });
        });
    });
});
