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
 * src/test/js/org/forgerock/openam/ui/common/util/object/flattenValuesTest.js -- same tests,
 * same names, same order.
 */

import { describe, it, expect } from "vitest";
import flattenValues from "org/forgerock/openam/ui/common/util/object/flattenValues";

describe("org/forgerock/openam/ui/common/object/flattenValues", () => {
    it("unwraps an object's single element array values", () => {
        const object = {
            none: "none",
            one: ["one"],
            many: ["one", "two"]
        };

        expect(flattenValues(object)).to.be.eql({
            none: "none",
            one: "one",
            many: ["one", "two"]
        });
    });
});
