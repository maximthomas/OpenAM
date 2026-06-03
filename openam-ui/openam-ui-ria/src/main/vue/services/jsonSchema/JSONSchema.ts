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

import _ from "lodash";
import { t as i18nT } from "@/services/i18n";
import {
  defaultTransforms,
  type SchemaProperty,
  type SchemaTransform,
} from "./schemaTransforms";
import type { JSONValues } from "./JSONValues";

/**
 * Lodash 3's _.omit with predicate was recursive (operated on nested objects).
 * Lodash 4's _.omitBy is NOT recursive. This helper replicates the lodash 3 behavior.
 */
function recursiveOmitBy(
  obj: Record<string, unknown>,
  predicate: (value: unknown, key: string) => boolean
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (predicate(value, key)) {
      continue;
    }
    if (_.isPlainObject(value)) {
      result[key] = recursiveOmitBy(value as Record<string, unknown>, predicate);
    } else {
      result[key] = value;
    }
  }
  return result;
}

function isObjectType(object: SchemaProperty): boolean {
  return object.type === "object";
}

function groupTopLevelSimpleProperties(raw: SchemaProperty): SchemaProperty {
  const collectionProperties = _(raw.properties)
    .pickBy((property: SchemaProperty) => _.has(property, "properties"))
    .keys()
    .value();

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
      title: i18nT("console.common.globalAttributes"),
      type: "object",
    },
  };

  return schema;
}

function throwOnNoSchemaRootType(schema: SchemaProperty): void {
  if (!schema.type) {
    throw new Error('[JSONSchema] No "type" attribute found on schema root object.');
  }
}

function ungroupCollectionProperties(
  raw: SchemaProperty,
  groupKey: string
): SchemaProperty {
  const collectionProperties = _.pickBy(
    raw.properties![groupKey].properties,
    (value: SchemaProperty) => {
      return value.type === "object" && _.has(value, "properties");
    }
  );

  if (_.isEmpty(collectionProperties)) {
    return raw;
  }

  const schema = _.cloneDeep(raw);
  schema.properties = { ...schema.properties, ...collectionProperties };
  schema.properties![groupKey].properties = _.omit(
    schema.properties![groupKey].properties,
    _.keys(collectionProperties)
  );

  if (_.isEmpty(schema.properties![groupKey].properties)) {
    delete schema.properties![groupKey];
  }

  return schema;
}

function eachProperty(
  object: SchemaProperty,
  callbacks: SchemaTransform[]
): void {
  if (isObjectType(object)) {
    _.forEach(object.properties, (property: SchemaProperty, key: string) => {
      _.forEach(callbacks, (callback: SchemaTransform) => {
        callback(property, key);
      });

      if (isObjectType(property)) {
        eachProperty(property, callbacks);
      }
    });
  }
}

function cleanJSONSchema(schema: SchemaProperty): SchemaProperty {
  eachProperty(schema, defaultTransforms);
  return schema;
}

export class JSONSchema {
  readonly raw: Readonly<SchemaProperty>;

  constructor(schema: SchemaProperty) {
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

  addDefaultProperties(keys: string[]): JSONSchema {
    const schema = _.cloneDeep(this.raw) as SchemaProperty;
    schema.defaultProperties = keys;
    return new JSONSchema(schema);
  }

  hasDefaultProperties(): boolean {
    return !_.isUndefined(this.raw.defaultProperties);
  }

  getEnableKey(): string | undefined {
    const key = `${_.camelCase(this.raw.title)}Enabled`;
    if (this.raw.properties && this.raw.properties[key]) {
      return key;
    }
    return undefined;
  }

  getEnableProperty(): JSONSchema {
    return this.pick(this.getEnableKey()!);
  }

  getKeys(sort?: boolean): string[] {
    if (sort) {
      const sortedSchemas = _.sortBy(_.map(this.raw.properties), "propertyOrder");
      return _.map(sortedSchemas, (schema: SchemaProperty) =>
        _.findKey(this.raw.properties, schema) as string
      );
    }
    return _.keys(this.raw.properties);
  }

  getPasswordKeys(): string[] {
    const passwordProperties = _.pickBy(
      this.raw.properties,
      _.matches({ format: "password" })
    );
    return _.keys(passwordProperties);
  }

  getPropertiesAsSchemas(): Record<string, JSONSchema> {
    return _.mapValues(this.raw.properties, (property) => new JSONSchema(property));
  }

  getRequiredPropertyKeys(): string[] {
    return _.keys(_.pickBy(this.raw.properties, _.matches({ required: true })));
  }

  hasEnableProperty(): boolean {
    return !_.isUndefined(
      this.raw.properties![`${_.camelCase(this.raw.title)}Enabled`]
    );
  }

  hasInheritance(): boolean {
    return (
      !_.isEmpty(this.raw.properties) &&
      _.every(this.raw.properties, (property: SchemaProperty) =>
        property.type === "object" && _.has(property, "properties.inherited")
      )
    );
  }

  isCollection(): boolean {
    return _.every(this.raw.properties, (property: SchemaProperty) => property.type === "object");
  }

  isEmpty(): boolean {
    return _.isEmpty(this.raw.properties);
  }

  pick(predicate: string | string[] | ((value: unknown, key: string) => boolean)): JSONSchema {
    const schema = _.cloneDeep(this.raw) as SchemaProperty;
    if (typeof predicate === "function") {
      schema.properties = _.pickBy(this.raw.properties, predicate as (value: unknown, key: string) => boolean) as Record<string, SchemaProperty>;
    } else {
      schema.properties = _.pick(this.raw.properties, predicate as string | string[]) as Record<string, SchemaProperty>;
    }
    return new JSONSchema(schema);
  }

  omit(predicate: string | string[] | ((value: unknown, key: string) => boolean)): JSONSchema {
    const schema = _.cloneDeep(this.raw) as SchemaProperty;
    if (typeof predicate === "function") {
      schema.properties = recursiveOmitBy(
        this.raw.properties as Record<string, unknown>,
        predicate as (value: unknown, key: string) => boolean
      ) as Record<string, SchemaProperty>;
    } else {
      schema.properties = _.omit(this.raw.properties, predicate as string | string[]);
    }
    return new JSONSchema(schema);
  }

  removeUnrequiredProperties(): JSONSchema {
    return this.omit((property: unknown) => (property as SchemaProperty).required === false);
  }

  toFlatWithInheritanceMeta(values: JSONValues): JSONSchema {
    const schema = _.cloneDeep(this.raw) as SchemaProperty;
    schema.properties = _.mapValues(
      this.raw.properties,
      (originalValue: SchemaProperty, propName: string) => {
        const property = _.cloneDeep(originalValue.properties!.value) as SchemaProperty;
        property.title = originalValue.title;
        property.description = originalValue.description;

        const valueIsInherited = Boolean(
          (values.raw[propName] as Record<string, unknown>) &&
            (values.raw[propName] as Record<string, unknown>).inherited
        );
        property.isInherited = valueIsInherited;
        return property;
      }
    ) as Record<string, SchemaProperty>;

    return new JSONSchema(schema);
  }
}
