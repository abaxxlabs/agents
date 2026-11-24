import { describe, it, expect } from 'vitest';
import { asColumnName, asIssuerUrl } from '#types/domain.js';

describe('domain-types factory functions', () => {
  describe('asColumnName', () => {
    it('rejects empty string', () => {
      expect(() => asColumnName('')).toThrow('Invalid column name');
    });
  });

  describe('asIssuerUrl', () => {
    it('rejects HTTP URL', () => {
      expect(() => asIssuerUrl('http://insecure.example.com')).toThrow('Invalid issuer URL');
    });
  });
});
