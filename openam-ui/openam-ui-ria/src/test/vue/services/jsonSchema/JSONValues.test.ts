import { describe, it, expect, beforeEach } from 'vitest';
import { JSONValues } from '@/services/jsonSchema/JSONValues';

describe('JSONValues', () => {
  describe('constructor', () => {
    let globalValues: JSONValues;
    let defaultsValues: JSONValues;
    let defaultsCollectionValues: JSONValues;

    beforeEach(() => {
      globalValues = new JSONValues({
        _id: '',
        _type: {},
        globalSimpleKey: 'globalSimpleValue',
        globalCollectionKey: {
          collectionItem_1: 'collectionItemValue_1',
          collectionItem_2: 'collectionItemValue_12',
        },
        dynamic: {},
      });

      defaultsValues = new JSONValues({
        _id: '',
        _type: {},
        defaults: {
          defaultsCollection: {
            collectionItem1: 'value1',
            collectionItem2: 'value2',
          },
          defaultsSimple: 'simpleValue',
        },
      });

      defaultsCollectionValues = new JSONValues({
        _id: '',
        _type: {},
        defaults: {
          defaultsCollection: {
            collectionItem1: 'value1',
            collectionItem2: 'value2',
          },
        },
      });
    });

    it('groups the top-level simple values under a "global" value', () => {
      expect(globalValues.raw).toHaveProperty('global');
      expect(globalValues.raw.global as Record<string, unknown>).toHaveProperty('globalSimpleKey');
    });

    it('does not group the top-level collection values under a "global" value', () => {
      expect(globalValues.raw).toHaveProperty('global');
      expect(globalValues.raw.global as Record<string, unknown>).not.toHaveProperty(
        'globalCollectionKey'
      );
    });

    it('does not ungroup "defaults" simple values', () => {
      expect(defaultsValues.raw).toHaveProperty('defaults');
      expect((defaultsValues.raw.defaults as Record<string, unknown>)).toHaveProperty(
        'defaultsSimple'
      );
    });

    it('ungroups "defaults" collection values, moving them one level up', () => {
      expect(defaultsValues.raw).toHaveProperty('defaultsCollection');
    });

    it('contains "_defaultsCollectionProperties"', () => {
      expect(defaultsValues.raw).toHaveProperty('_defaultsCollectionProperties');
    });

    it('ungroups "defaults" collection values, moving them one level up (collection props only)', () => {
      expect(defaultsCollectionValues.raw).toHaveProperty('defaultsCollection');
    });

    it('removes "defaults" property when there are no simple props', () => {
      expect(defaultsCollectionValues.raw).not.toHaveProperty('defaults');
    });
  });

  describe('addInheritance', () => {
    it('creates an object for each property key', () => {
      const jsonValues = new JSONValues({ propertyKey: 'value' });
      const values = jsonValues.addInheritance({ propertyKey: { inherited: true } });
      expect(typeof values.raw.propertyKey).toBe('object');
    });

    it('creates a "value" attribute on the property object', () => {
      const jsonValues = new JSONValues({ propertyKey: 'value' });
      const values = jsonValues.addInheritance({ propertyKey: { inherited: true } });
      expect((values.raw.propertyKey as Record<string, unknown>).value).toBe('value');
    });

    it('creates a "inherited" attribute on the property object', () => {
      const jsonValues = new JSONValues({ propertyKey: 'value' });
      const values = jsonValues.addInheritance({ propertyKey: { inherited: true } });
      expect((values.raw.propertyKey as Record<string, unknown>).inherited).toBe(true);
    });
  });

  describe('removeInheritance', () => {
    it('flattens each inherited property into a single value', () => {
      const jsonValues = new JSONValues({
        propertyKey: {
          value: 'value',
          inherited: true,
        },
      });

      const values = jsonValues.removeInheritance();
      expect(values.raw.propertyKey).toBe('value');
    });
  });

  describe('toJSON', () => {
    let values: string;
    let valueWithDefaultsCollectionProperties: string;

    beforeEach(() => {
      values = new JSONValues({
        _id: {},
        _type: {},
        globalValue: {},
        defaults: {
          defaultsSimple: 'simpleValue',
        },
        dynamic: {
          dynamicSimple: 'simpleValue',
        },
      }).toJSON();

      valueWithDefaultsCollectionProperties = new JSONValues({
        _id: {},
        _type: {},
        _defaultsCollectionProperties: ['defaultsCollection', 'defaultsCollection2'],
        defaultsCollection: {
          collectionItem1: 'value1',
          collectionItem2: 'value2',
        },
        defaultsCollection2: {
          collectionItem1: 'value1',
          collectionItem2: 'value2',
        },
      }).toJSON();
    });

    it('returns a JSON string', () => {
      expect(typeof values).toBe('string');
      expect(() => JSON.parse(values)).not.toThrow();
    });

    it('returns global values at the top-level', () => {
      expect(JSON.parse(values)).toHaveProperty('globalValue');
    });

    it('returns defaults values under a "defaults" property', () => {
      const parsed = JSON.parse(values);
      expect(parsed).toHaveProperty('defaults');
      expect(parsed.defaults).toHaveProperty('defaultsSimple');
    });

    it('returns "_id" at the top-level', () => {
      expect(JSON.parse(values)).toHaveProperty('_id');
    });

    it('returns "_type" at the top-level', () => {
      expect(JSON.parse(values)).toHaveProperty('_type');
    });

    it('constructs "defaults" property from the defaults collection values', () => {
      expect(JSON.parse(valueWithDefaultsCollectionProperties)).toHaveProperty('defaults');
    });

    it('returns defaults collection values under a "defaults" property', () => {
      const parsed = JSON.parse(valueWithDefaultsCollectionProperties);
      expect(parsed.defaults).toHaveProperty('defaultsCollection');
      expect(parsed.defaults).toHaveProperty('defaultsCollection2');
    });

    it('deletes meta info key "_defaultsCollectionProperties" from the values', () => {
      expect(JSON.parse(valueWithDefaultsCollectionProperties)).not.toHaveProperty(
        '_defaultsCollectionProperties'
      );
    });
  });
});
