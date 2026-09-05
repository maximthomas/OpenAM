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
 * ES module port of src/test/js/store/reducers/sessionTest.js -- same tests, same names, same
 * order. The original's `reducer = reducer.default` line is gone: it was unwrapping Babel's AMD
 * output for an ES module default export, which a default import now does directly.
 */

import { describe, it, expect } from "vitest";
import * as types from "store/actions/types";
import reducer from "store/reducers/session";

describe("store/reducers/session", () => {
    it("returns the initial state", () => {
        expect(
            reducer(undefined, {})
        ).eql({
            realm: undefined,
            sessionHandle: undefined
        });
    });

    it(`handles ${types.SESSION_ADD_INFO}`, () => {
        const realm = "/realmA";
        const sessionHandle = "sessionHandle";

        expect(
            reducer({}, {
                type: types.SESSION_ADD_INFO,
                realm,
                sessionHandle
            })
        ).eql({
            realm: realm.toLowerCase(),
            sessionHandle
        });
    });

    it(`handles ${types.SESSION_REMOVE_INFO}`, () => {
        expect(
            reducer({}, {
                type: types.SESSION_REMOVE_INFO
            })
        ).eql({});
    });
});
