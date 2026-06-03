import { describe, it, expect, vi, beforeEach } from 'vitest';
import { JSONSchema } from '@/services/jsonSchema/JSONSchema';
import { JSONValues } from '@/services/jsonSchema/JSONValues';

vi.mock('@/services/i18n', () => ({
  t: vi.fn((key: string) => {
    const messages: Record<string, string> = {
      'console.common.globalAttributes': 'Global Attributes',
    };
    return messages[key] || key;
  }),
}));

describe('JSONSchema', () => {
  describe('constructor', () => {
    let schemaWithGlobalProps: JSONSchema;
    let schemaWithDefaultsProps: JSONSchema;
    let schemaWithDefaultsCollectionProps: JSONSchema;

    beforeEach(() => {
      schemaWithGlobalProps = new JSONSchema({
        properties: {
          globalSimpleProperty: {},
          globalCollectionProperty: {
            type: 'object',
            title: '',
            properties: {},
          },
          dynamic: {},
        },
        type: 'object',
      });

      schemaWithDefaultsProps = new JSONSchema({
        properties: {
          defaults: {
            type: 'object',
            title: '',
            properties: {
              defaultsSimpleProperty: {},
              defaultsCollectionProperty: {
                type: 'object',
                title: '',
                properties: {},
              },
            },
          },
        },
        type: 'object',
      });

      schemaWithDefaultsCollectionProps = new JSONSchema({
        properties: {
          defaults: {
            type: 'object',
            title: '',
            properties: {
              defaultsCollectionProperty: {
                type: 'object',
                title: '',
                properties: {},
              },
            },
          },
        },
        type: 'object',
      });
    });

    it('groups the top-level simple properties under a "global" property', () => {
      expect(schemaWithGlobalProps.raw.properties).toHaveProperty('global');
      expect(schemaWithGlobalProps.raw.properties!.global!.properties).toHaveProperty(
        'globalSimpleProperty'
      );
    });

    it('groups the top-level simple properties with title', () => {
      expect(schemaWithGlobalProps.raw.properties!.global!.title).toBe('Global Attributes');
    });

    it('groups the top-level simple properties with property order', () => {
      expect(schemaWithGlobalProps.raw.properties!.global!.propertyOrder).toBe(-10);
    });

    it('does not group the top-level collection properties under a "global" property', () => {
      expect(schemaWithGlobalProps.raw.properties).toHaveProperty('global');
      expect(schemaWithGlobalProps.raw.properties!.global!.properties).not.toHaveProperty(
        'globalCollectionProperty'
      );
    });

    it('ungroups "defaults" collection properties, moving them one level up', () => {
      expect(schemaWithDefaultsProps.raw.properties).toHaveProperty('defaultsCollectionProperty');
    });

    it('does not ungroup "defaults" simple properties', () => {
      expect(schemaWithDefaultsProps.raw.properties!.defaults!.properties).toHaveProperty(
        'defaultsSimpleProperty'
      );
    });

    it('ungroups "defaults" collection properties, moving them one level up (collection props only)', () => {
      expect(schemaWithDefaultsCollectionProps.raw.properties).toHaveProperty(
        'defaultsCollectionProperty'
      );
    });

    it('removes "defaults" property when there are no simple props', () => {
      expect(schemaWithDefaultsCollectionProps.raw.properties).not.toHaveProperty('defaults');
    });
  });

  describe('hasInheritance', () => {
    it('returns true when the schema has inherited properties', () => {
      const jsonSchema = new JSONSchema({
        type: 'object',
        properties: {
          propertyCollection: {
            type: 'object',
            title: '',
            properties: {
              inherited: {},
            },
          },
        },
      });

      expect(jsonSchema.hasInheritance()).toBe(true);
    });

    it('returns false when the schema has no inherited properties', () => {
      const jsonSchema = new JSONSchema({
        type: 'object',
        properties: {
          propertyCollection: {
            type: 'object',
            title: '',
            properties: {
              property: {},
            },
          },
        },
      });

      expect(jsonSchema.hasInheritance()).toBe(false);
    });
  });

  describe('removeUnrequiredProperties', () => {
    it('removes properties where "required" is "false"', () => {
      const jsonSchema = new JSONSchema({
        type: 'object',
        properties: {
          propertyCollection: {
            title: '',
            type: 'object',
            properties: {
              propertyKeyRequired: {
                required: true,
              },
              propertyKeyNonRequired: {
                required: false,
              },
            },
          },
        },
      });

      const schema = jsonSchema.removeUnrequiredProperties();
      expect(schema.raw.properties!.propertyCollection!.properties).not.toHaveProperty(
        'propertyKeyNonRequired'
      );
    });
  });

  describe('toFlatWithInheritanceMeta', () => {
    const jsonValues = new JSONValues({
      'com.iplanet.am.smtphost': {
        value: 'localhost',
        inherited: true,
      },
      'com.iplanet.am.smtpport': {
        value: 25,
        inherited: true,
      },
    });

    let schema: JSONSchema;

    beforeEach(() => {
      const jsonSchema = new JSONSchema({
        title: 'Mail Server',
        type: 'object',
        propertyOrder: 3,
        properties: {
          'com.iplanet.am.smtphost': {
            title: 'Mail Server Host Name',
            type: 'object',
            propertyOrder: 0,
            description: '(property name: com.iplanet.am.smtphost)',
            properties: {
              value: {
                type: 'string',
                required: false,
              },
              inherited: {
                type: 'boolean',
                required: true,
              },
            },
          },
        },
      });
      schema = jsonSchema.toFlatWithInheritanceMeta(jsonValues);
    });

    it('flattens inherited property values onto the top-level properties', () => {
      expect(schema.raw.properties).toHaveProperty('com.iplanet.am.smtphost');
      expect(schema.raw.properties!['com.iplanet.am.smtphost']).toHaveProperty('type');
      expect(schema.raw.properties!['com.iplanet.am.smtphost']).toHaveProperty('required');
    });

    it('sets the title on the flattened properties', () => {
      expect(schema.raw.properties!['com.iplanet.am.smtphost'].title).toBe('Mail Server Host Name');
    });

    it("adds 'isInherited' key to each property of the schema", () => {
      expect(schema.raw.properties!['com.iplanet.am.smtphost']).toHaveProperty('isInherited');
      expect(schema.raw.properties!['com.iplanet.am.smtphost'].isInherited).toBe(true);
    });
  });
});
