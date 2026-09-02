/*
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
 */

/**
 * Represents a JSON Schema.
 * <p/>
 * <h2>Function naming conventions</h2>
 * Refer to the following naming convention, when adding new functions to this class:
 * <ul>
 *   <li>For <strong>query</strong> functions, which do not return a new instance of <code>JSONSchema</code>, use <code>#get*</code></li>
 *   <li>For <strong>transform</strong> functions, which do not loose data, use <code>#to*</code> and <code>#from*</code></li>
 *   <li>For <strong>modification</strong> functions, which loose the data, use <code>add*</code> and <code>#remove*</code></li>
 *   <li>For functions, which <strong>check for presense</strong>, use <code>#has*</code> and <code>#is*</code></li>
 *   <li>For <strong>utility</strong> functions use simple verbs, e.g. <code>#omit</code>, <code>#pick</code>, etc.</li>
 * </ul>
 * @module
 * @example
 * // The structure of JSON Schema documents emitted from OpenAM is expected to be the following:
 * {
 *   properties: {
 *     globalProperty: true, // Global properties (OpenAM wide) are listed at the top-level
 *     default: { ... }, // Default properties are organisation (Realm) level properties and are nested under "default"
 *     dynamic: { ... } // Dynamic properties are user level properties (OpenAM wide) and are nested under "dynamic"
 *   },
 *   type: "object"
 * }
 */
import i18next from "i18next";
import _ from "lodash";
import transformBooleanTypeToCheckboxFormat from
    "org/forgerock/openam/ui/common/models/schemaTransforms/transformBooleanTypeToCheckboxFormat";
import transformEnumTypeToString from
    "org/forgerock/openam/ui/common/models/schemaTransforms/transformEnumTypeToString";
import warnOnInferredPasswordWithoutFormat from
    "org/forgerock/openam/ui/common/models/schemaTransforms/warnOnInferredPasswordWithoutFormat";

/**
 * lodash 4 removed predicate support from `omit`, moving it to `omitBy`, which lodash 3 does not have.
 * Selecting the keys to keep instead behaves identically under both majors.
 * @param {Object} object Object to omit properties from.
 * @param {Function|string|string[]} predicate Predicate invoked per property, or the key(s) to omit.
 * @returns {Object} Object without the omitted properties.
 */
function omitByPredicate (object, predicate) {
    if (_.isFunction(predicate)) {
        return _.pick(object, _.filter(_.keys(object), (key) => !predicate(object[key], key, object)));
    }
    return _.omit(object, predicate);
}

/**
 * Determines whether the specified object is of type <code>object</code>
 * @param   {Object}  object Object to determine the type of
 * @returns {Boolean}        Whether the object is of type <code>object</code>
 */
function isObjectType (object) {
    return object.type === "object";
}

function groupTopLevelSimpleProperties (raw) {
    const collectionProperties = _.filter(_.keys(raw.properties), (key) =>
        _.has(raw.properties[key], "properties"));

    const predicate = ["defaults", ...collectionProperties];
    const simplePropertiesToGroup = _.omit(raw.properties, ...predicate);

    if (_.isEmpty(simplePropertiesToGroup)) {
        return raw;
    }

    const schema = _.cloneDeep(raw);

    schema.properties = {
        ..._.omit(schema.properties, _.keys(simplePropertiesToGroup)),
        global: {
            properties: simplePropertiesToGroup,
            propertyOrder: -10,
            title: i18next.t("console.common.globalAttributes"),
            type: "object"
        }
    };

    return schema;
}

function throwOnNoSchemaRootType (schema) {
    if (!schema.type) {
        throw new Error("[JSONSchema] No \"type\" attribute found on schema root object.");
    }
}

/**
* Ungroups collection properties, moving them one level up.
*
* @param   {Object} raw Schema
* @param   {string} groupKey Group key of the property value object
* @returns {JSONSchema} JSONSchema new JSONSchema object
*/
function ungroupCollectionProperties (raw, groupKey) {
    const groupProperties = raw.properties[groupKey].properties;
    const collectionProperties = _.pick(groupProperties, _.filter(_.keys(groupProperties), (key) => {
        const value = groupProperties[key];
        return value.type === "object" && _.has(value, "properties");
    }));

    if (_.isEmpty(collectionProperties)) {
        return raw;
    }

    const schema = _.cloneDeep(raw);
    schema.properties = { ...schema.properties, ...collectionProperties };
    schema.properties[groupKey].properties =
        _.omit(schema.properties[groupKey].properties, _.keys(collectionProperties));

    if (_.isEmpty(schema.properties[groupKey].properties)) {
        delete schema.properties[groupKey];
    }

    return schema;
}

/**
 * Recursively invokes the specified functions over each object's properties
 * @param {Object} object   Object with properties
 * @param {Array} callbacks Array of functions
 */
function eachProperty (object, callbacks) {
    if (isObjectType(object)) {
        _.forEach(object.properties, (property, key) => {
            _.forEach(callbacks, (callback) => {
                callback(property, key);
            });

            if (isObjectType(property)) {
                eachProperty(property, callbacks);
            }
        });
    }
}

/**
 * Iterates over a scheam, transforming adding appropriate warnings.
 * @param {Object} schema the schema to be transformed
 * @returns {Object} the transformed schema
 */
function cleanJSONSchema (schema) {
    eachProperty(schema, [transformBooleanTypeToCheckboxFormat,
                          transformEnumTypeToString,
                          warnOnInferredPasswordWithoutFormat]);

    return schema;
}

export default class JSONSchema {
    constructor (schema) {
        throwOnNoSchemaRootType(schema);

        const hasDefaults = _.has(schema, "properties.defaults");
        const hasDynamic = _.has(schema, "properties.dynamic");

        if (hasDefaults || hasDynamic) {
            schema = groupTopLevelSimpleProperties(schema);
        }

        if (hasDefaults) {
            schema = ungroupCollectionProperties(schema, "defaults");
        }

        schema = cleanJSONSchema(schema);

        this.raw = Object.freeze(schema);
    }
    addDefaultProperties (keys) {
        const schema = _.cloneDeep(this.raw);
        schema.defaultProperties = keys;
        return new JSONSchema(schema);
    }
    hasDefaultProperties () {
        return !_.isUndefined(this.raw.defaultProperties);
    }
    getEnableKey () {
        const key = `${_.camelCase(this.raw.title)}Enabled`;
        if (this.raw.properties[key]) {
            return key;
        }
    }
    getEnableProperty () {
        return this.pick(this.getEnableKey());
    }
    getKeys (sort) {
        sort = typeof sort !== "undefined" ? sort : false;

        if (sort) {
            const sortedSchemas = _.sortBy(_.map(this.raw.properties), "propertyOrder");
            return _.map(sortedSchemas, (schema) => _.findKey(this.raw.properties, schema));
        } else {
            return _.keys(this.raw.properties);
        }
    }
    getPasswordKeys () {
        const isPasswordProperty = _.matches({ format: "password" });

        return _.filter(_.keys(this.raw.properties), (key) => isPasswordProperty(this.raw.properties[key]));
    }
    getPropertiesAsSchemas () {
        return _.mapValues(this.raw.properties, (property) => new JSONSchema(property));
    }
    getRequiredPropertyKeys () {
        const isRequiredProperty = _.matches({ required: true });

        return _.filter(_.keys(this.raw.properties), (key) => isRequiredProperty(this.raw.properties[key]));
    }
    hasEnableProperty () {
        return !_.isUndefined(this.raw.properties[`${_.camelCase(this.raw.title)}Enabled`]);
    }
    hasInheritance () {
        return !_.isEmpty(this.raw.properties) && _.every(this.raw.properties, (property) =>
            property.type === "object" && _.has(property, "properties.inherited"));
    }
    /**
     * Whether this schema objects' properties are all schemas in their own right.
     * If true, this object is a simply a container for other schemas.
     * @returns {Boolean} Whether this object is a collection
     */
    isCollection () {
        return _.every(this.raw.properties, (property) => property.type === "object");
    }
    isEmpty () {
        return _.isEmpty(this.raw.properties);
    }
    pick (predicate) {
        const schema = _.cloneDeep(this.raw);
        schema.properties = _.pick(this.raw.properties, predicate);

        return new JSONSchema(schema);
    }
    omit (predicate) {
        const schema = _.cloneDeep(this.raw);
        schema.properties = omitByPredicate(this.raw.properties, predicate);

        return new JSONSchema(schema);
    }
    /**
     * Returns a new JSONSchema with all non-required properties removed.
     * @returns {JSONSchema} JSONSchema object with non-required properties removed.
     */
    removeUnrequiredProperties () {
        return this.omit((property) => property.required === false);
    }
    /**
     * Flattens schema properties to enable schema to be renderable. Adds inheritance metadata to each property of
     * the schema, so JSONEditor knows whether to enable or disable the input field.
     * @param {JSONValues} values JSONValues object to take inheritance metadata from.
     * @returns {JSONSchema} Flattened JSONSchema object with inheritance metadata.
     */
    toFlatWithInheritanceMeta (values) {
        const schema = _.cloneDeep(this.raw);
        schema.properties = _.mapValues(this.raw.properties, (originalValue, propName) => {
            const property = originalValue.properties.value;
            property.title = originalValue.title;
            property.description = originalValue.description;

            const valueIsInherited = Boolean(values.raw[propName] && values.raw[propName].inherited);
            property.isInherited = valueIsInherited;
            return property;
        });

        return new JSONSchema(schema);
    }
}
