export { JSONSchema } from "./JSONSchema";
export { JSONValues } from "./JSONValues";
export {
  transformBooleanTypeToCheckboxFormat,
  transformEnumTypeToString,
  warnOnInferredPasswordWithoutFormat,
  defaultTransforms,
} from "./schemaTransforms";
export type { SchemaProperty, SchemaTransform } from "./schemaTransforms";

export interface SchemaValuePair {
  key: string;
  schema: import("./JSONSchema").JSONSchema;
  values: import("./JSONValues").JSONValues;
}

export function emptyProperties(pair: SchemaValuePair): boolean {
  return _.isEmpty(pair.schema.raw.defaultProperties);
}

export function setDefaultPropertiesToRequiredAndEmpty(pair: SchemaValuePair): SchemaValuePair {
  const requiredSchemaKeys = pair.schema.getRequiredPropertyKeys();
  const emptyValueKeys = pair.values.getEmptyValueKeys();
  const requiredAndEmptyKeys = _.intersection(requiredSchemaKeys, emptyValueKeys);
  return {
    ...pair,
    schema: pair.schema.addDefaultProperties(requiredAndEmptyKeys),
  };
}

export function showEnablePropertyIfAllPropertiesHidden(
  pair: SchemaValuePair
): SchemaValuePair {
  const allPropertiesHidden = _.isEmpty(pair.schema.raw.defaultProperties);

  if (allPropertiesHidden && pair.schema.hasEnableProperty()) {
    return {
      ...pair,
      schema: pair.schema
        .getEnableProperty()
        .addDefaultProperties([pair.schema.getEnableKey()!]),
    };
  }

  return pair;
}

import _ from "lodash";
