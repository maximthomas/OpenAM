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
 * Portions copyright 2019 Open Source Solution Technology Corporation
 */

import _ from "lodash";

function groupTopLevelSimpleValues(raw: Record<string, unknown>): Record<string, unknown> {
  const collectionProperties = _(raw)
    .pickBy((property) => _.isObject(property) && !_.isArray(property))
    .keys()
    .value();

  const predicate = ["_id", "_type", "defaults", ...collectionProperties];
  const simplePropertiesToGroup = _.omit(raw, ...predicate);

  if (_.isEmpty(simplePropertiesToGroup)) {
    return raw;
  }

  return {
    ..._.omit(raw, _.keys(simplePropertiesToGroup)),
    global: simplePropertiesToGroup,
  };
}

function ungroupCollectionProperties(
  raw: Record<string, unknown>,
  groupKey: string
): Record<string, unknown> {
  const collectionProperties = _.pickBy(raw[groupKey] as Record<string, unknown>, (value) => {
    return _.isObject(value) && !_.isArray(value);
  });

  if (_.isEmpty(collectionProperties)) {
    return raw;
  }

  const values = { ...raw, ...collectionProperties };

  const collectionPropertiesKeys = _.keys(collectionProperties);
  values[`_${groupKey}CollectionProperties`] = collectionPropertiesKeys;
  values[groupKey] = _.omit(values[groupKey] as Record<string, unknown>, collectionPropertiesKeys);

  if (_.isEmpty(values[groupKey])) {
    delete values[groupKey];
  }

  return values;
}

export class JSONValues {
  readonly raw: Readonly<Record<string, unknown>>;

  constructor(values: Record<string, unknown>) {
    const hasDefaults = _.has(values, "defaults");
    const hasDynamic = _.has(values, "dynamic");

    if (hasDefaults || hasDynamic) {
      values = groupTopLevelSimpleValues(values);
    }

    if (hasDefaults) {
      values = ungroupCollectionProperties(values, "defaults");
    }

    if (values) {
      this.raw = Object.freeze(values);
    } else {
      this.raw = Object.freeze({});
    }
  }

  addInheritance(inheritance: Record<string, { inherited: boolean }>): JSONValues {
    const valuesWithInheritance = _.mapValues(this.raw, (value, key) => ({
      value,
      inherited: inheritance[key].inherited,
    }));

    return new JSONValues(valuesWithInheritance as Record<string, unknown>);
  }

  addValueForKey(path: string, key: string, value: unknown): JSONValues {
    const clone = _.cloneDeep(this.raw) as Record<string, unknown>;
    (clone[path] as Record<string, unknown>)[key] = value;
    return new JSONValues(clone);
  }

  extend(object: Record<string, unknown>): JSONValues {
    return new JSONValues(_.extend({}, this.raw, object) as Record<string, unknown>);
  }

  getEmptyValueKeys(): string[] {
    function isEmpty(value: unknown): boolean {
      if (_.isNumber(value)) {
        return false;
      } else if (_.isBoolean(value)) {
        return false;
      }
      return _.isEmpty(value);
    }

    const keys: string[] = [];

    _.forIn(this.raw, (value, key) => {
      if (isEmpty(value)) {
        keys.push(key);
      }
    });

    return keys;
  }

  omit(predicate: string | string[] | ((value: unknown, key: string) => boolean)): JSONValues {
    if (typeof predicate === "function") {
      return new JSONValues(_.omitBy(this.raw, predicate as (value: unknown, key: string) => boolean) as Record<string, unknown>);
    }
    return new JSONValues(_.omit(this.raw, predicate as string | string[]) as Record<string, unknown>);
  }

  pick(predicate: string | string[] | ((value: unknown, key: string) => boolean)): JSONValues {
    if (typeof predicate === "function") {
      return new JSONValues(_.pickBy(this.raw, predicate as (value: unknown, key: string) => boolean) as Record<string, unknown>);
    }
    return new JSONValues(_.pick(this.raw, predicate as string | string[]) as Record<string, unknown>);
  }

  removeInheritance(): JSONValues {
    return new JSONValues(_.mapValues(this.raw, "value") as Record<string, unknown>);
  }

  toJSON(): string {
    let json = _.cloneDeep(this.raw) as Record<string, unknown>;

    const wrapCollectionProperties = (
      data: Record<string, unknown>,
      propertyKey: string
    ): Record<string, unknown> => {
      const cloned = _.cloneDeep(data) as Record<string, unknown>;

      const collectionPropertiesKeys = cloned[`_${propertyKey}CollectionProperties`] as string[];
      const collectionProperties = _.pick(cloned, collectionPropertiesKeys);
      cloned[propertyKey] = { ...(cloned[propertyKey] as Record<string, unknown>), ...collectionProperties };
      return _.omit(cloned, collectionPropertiesKeys) as Record<string, unknown>;
    };

    const collectionPropertiesPresent = (
      data: Record<string, unknown>,
      propertyKey: string
    ): boolean => {
      const collectionPropertiesKeys = data[`_${propertyKey}CollectionProperties`] as string[];
      return collectionPropertiesKeys && !_.isEmpty(collectionPropertiesKeys);
    };

    if (collectionPropertiesPresent(json, "defaults")) {
      json = wrapCollectionProperties(json, "defaults");
      delete json._defaultsCollectionProperties;
    }

    json = { ...json, ...(json.global as Record<string, unknown>) };
    delete json.global;

    return JSON.stringify(json);
  }
}
