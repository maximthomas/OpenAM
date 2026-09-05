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
 * ES module port of src/test/js/org/forgerock/openam/ui/common/models/JSONSchemaTest.js -- same
 * tests, same names, same order. Task 9.2 (D12).
 *
 * "i18next" IS NOT THE NPM PACKAGE HERE. The id resolves through vite.config.js's alias table to
 * src/main/js/shims/i18next.js, which is the shim that loads the browser build and re-exports it
 * as both a default and a named `t`. Mocking the bare id therefore replaces the shim, which is
 * what the subject imports (`import i18next from "i18next"`), and is why the factory below
 * publishes a default rather than a bare object.
 *
 * THE MOCK OBJECT HAS FILE LIFETIME, ITS CONTENTS HAVE CASE LIFETIME -- vi.mock is hoisted above
 * every import and its factory runs once, so it cannot close over an object beforeEach rebuilds.
 * Squire got a new one per case by building a new injector; here the identity is fixed and the
 * contents are replaced.
 *
 * THE SUBJECT IS IMPORTED STATICALLY. It holds no module-scope state, so the one instance ES
 * modules cache per process is the same thing Squire's fresh context gave it. Note this does
 * change one thing the original could not help: under Squire, JSONValues came from the outer
 * RequireJS context while JSONSchema's own copy came from the injector, so the two were
 * different module instances. Here they are one, which is what the product has always had.
 *
 * `sinon.stub().withArgs(...).returns(...)` IS PRESERVED AS WRITTEN, and it does not do what it
 * reads as: withArgs returns the filtered behaviour, not the stub, so `i18next.t` is that filter
 * and the configured return value is not reachable through it. That is a wart in the original
 * and this is a transcription, so it is carried across rather than repaired -- see the second
 * case below, which asserts on the call rather than on the value.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import sinon from "sinon";
import JSONValues from "org/forgerock/openam/ui/common/models/JSONValues";
import JSONSchema from "org/forgerock/openam/ui/common/models/JSONSchema";

const context = describe;

const mocks = vi.hoisted(() => ({ i18next: {} }));

vi.mock("i18next", () => ({ "default": mocks.i18next }));

let i18next;
describe("org/forgerock/openam/ui/common/models/JSONSchema", () => {
    beforeEach(() => {
        i18next = mocks.i18next;

        Object.keys(i18next).forEach((key) => delete i18next[key]);

        i18next.t = sinon.stub().withArgs("console.common.global").returns("Global Attributes");
    });

    describe("#constructor", () => {
        let schemaWithGlobalProps;
        let schemaWithDefaultsProps;
        let schemaWithDefaultsCollectionProps;

        beforeEach(() => {
            schemaWithGlobalProps = new JSONSchema({
                "properties": {
                    "globalSimpleProperty": {},
                    "globalCollectionProperty": {
                        "type": "object",
                        "title": "",
                        "properties": {}
                    },
                    "dynamic": {}
                },
                "type": "object"
            });

            schemaWithDefaultsProps = new JSONSchema({
                "properties": {
                    "defaults": {
                        "type": "object",
                        "title": "",
                        "properties": {
                            "defaultsSimpleProperty": {},
                            "defaultsCollectionProperty": {
                                type: "object",
                                title: "",
                                properties: {}
                            }
                        }
                    }
                },
                "type": "object"
            });

            schemaWithDefaultsCollectionProps = new JSONSchema({
                "properties": {
                    "defaults": {
                        "type": "object",
                        "title": "",
                        "properties": {
                            "defaultsCollectionProperty": {
                                type: "object",
                                title: "",
                                properties: {}
                            }
                        }
                    }
                },
                "type": "object"
            });
        });

        // Global properties
        it("groups the top-level simple properties under a \"global\" property", () => {
            expect(schemaWithGlobalProps.raw.properties).to.contain.keys("global");
            expect(schemaWithGlobalProps.raw.properties.global.properties).to.contain.keys("globalSimpleProperty");
        });

        it("groups the top-level simple properties with title", () => {
            expect(i18next.t).to.be.calledWith("console.common.globalAttributes");
            expect(schemaWithGlobalProps.raw.properties.global.title).eq("Global Attributes");
        });

        it("groups the top-level simple properties with property order", () => {
            expect(schemaWithGlobalProps.raw.properties.global.propertyOrder).eq(-10);
        });

        it("does not group the top-level collection properties under a \"global\" property", () => {
            expect(schemaWithGlobalProps.raw.properties).to.contain.keys("global");
            expect(schemaWithGlobalProps.raw.properties.global.properties).to.not.have
                .keys("globalCollectionProperty");
        });

        //Defaults properties
        it("ungroups \"defaults\" collection properties, moving them one level up", () => {
            expect(schemaWithDefaultsProps.raw.properties).to.contain.keys("defaultsCollectionProperty");
        });

        it("does not ungroup \"defaults\" simple properties", () => {
            expect(schemaWithDefaultsProps.raw.properties.defaults.properties).to.contain
                .keys("defaultsSimpleProperty");
        });

        it("ungroups \"defaults\" collection properties, moving them one level up (collection props only)", () => {
            expect(schemaWithDefaultsCollectionProps.raw.properties).to.contain.keys("defaultsCollectionProperty");
        });

        it("removes \"defaults\" property when there are no simple props", () => {
            expect(schemaWithDefaultsCollectionProps.raw.properties).to.not.have.keys("defaults");
        });
    });

    describe("#hasInheritance", () => {
        context("schema has inheritance", () => {
            it("returns true", () => {
                const jsonSchema = new JSONSchema({
                    type: "object",
                    properties: {
                        propertyCollection: {
                            type: "object",
                            title: "",
                            properties: {
                                inherited: {}
                            }
                        }
                    }
                });

                expect(jsonSchema.hasInheritance()).to.be.true;
            });
        });

        it("returns true when the schema has all inherited properties", () => {
            const jsonSchema = new JSONSchema({
                type: "object",
                properties: {
                    propertyCollection: {
                        type: "object",
                        title: "",
                        properties: {
                            property: {}
                        }
                    }
                }
            });

            expect(jsonSchema.hasInheritance()).to.be.false;
        });
    });

    describe("#removeNonRequiredProperties", () => {
        let schema;

        beforeEach(() => {
            const jsonSchema = new JSONSchema({
                "type": "object",
                "properties": {
                    propertyCollection: {
                        title: "",
                        type: "object",
                        properties: {
                            "propertyKeyRequired": {
                                required: true
                            },
                            "propertyKeyNonRequired": {
                                required: false
                            }
                        }
                    }
                }
            });
            schema = jsonSchema.removeUnrequiredProperties();
        });

        it("removes properties where \"required\" is \"false\"", () => {
            expect(schema.raw.properties.propertyCollection).to.not.have.keys("propertyKeyNonRequired");
        });
    });

    describe("#toFlatWithInheritanceMeta", () => {
        const jsonValues = new JSONValues({
            "com.iplanet.am.smtphost":{
                "value":"localhost",
                "inherited":true
            },
            "com.iplanet.am.smtpport":{
                "value":25,
                "inherited":true
            }
        });
        let schema;

        beforeEach(() => {
            const jsonSchema = new JSONSchema({
                "title":"Mail Server",
                "type":"object",
                "propertyOrder":3,
                "properties":{
                    "com.iplanet.am.smtphost":{
                        "title":"Mail Server Host Name",
                        "type":"object",
                        "propertyOrder":0,
                        "description":"(property name: com.iplanet.am.smtphost)",
                        "properties":{
                            "value":{
                                "type":"string",
                                "required":false
                            },
                            "inherited":{
                                "type":"boolean",
                                "required":true
                            }
                        }
                    }
                }
            });
            schema = jsonSchema.toFlatWithInheritanceMeta(jsonValues);
        });

        it("flattens inherited property values onto the top-level properties", () => {
            expect(schema.raw.properties).to.contain.keys("com.iplanet.am.smtphost");
            expect(schema.raw.properties["com.iplanet.am.smtphost"]).to.contain
                .keys("type", "required");
        });

        it("sets the title on the flattened properties", () => {
            expect(schema.raw.properties["com.iplanet.am.smtphost"].title).eq("Mail Server Host Name");
        });

        it("adds 'isInherited' key to each property of the schema", () => {
            expect(schema.raw.properties["com.iplanet.am.smtphost"]).to.contain.keys("isInherited");
            expect(schema.raw.properties["com.iplanet.am.smtphost"].isInherited).eq(true);
        });
    });
});
