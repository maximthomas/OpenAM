import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getDifferences } from '@/services/api';

describe('api', () => {
  describe('getDifferences', () => {
    it('returns differences between objects', () => {
      const oldObj = { name: 'old', age: 10 };
      const newObj = { name: 'new', age: 10 };
      const result = getDifferences(oldObj, newObj);
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({ operation: 'replace', field: 'name', value: 'new' });
    });

    it('returns empty array when objects are equal', () => {
      const obj = { name: 'same', age: 10 };
      const result = getDifferences(obj, obj);
      expect(result).toHaveLength(0);
    });

    it('handles added fields', () => {
      const oldObj = { name: 'test' };
      const newObj = { name: 'test', email: 'test@example.com' };
      const result = getDifferences(oldObj, newObj);
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({ operation: 'replace', field: 'email', value: 'test@example.com' });
    });

    it('uses custom method', () => {
      const oldObj = { name: 'old' };
      const newObj = { name: 'new' };
      const result = getDifferences(oldObj, newObj, 'add');
      expect(result[0].operation).toBe('add');
    });

    it('skips empty new values when old is also empty', () => {
      const oldObj = { name: '' };
      const newObj = { name: '' };
      const result = getDifferences(oldObj, newObj);
      expect(result).toHaveLength(0);
    });

    it('includes empty new value when old is not empty', () => {
      const oldObj = { name: 'old' };
      const newObj = { name: '' };
      const result = getDifferences(oldObj, newObj);
      expect(result).toHaveLength(1);
      expect(result[0].value).toBe('');
    });
  });
});
