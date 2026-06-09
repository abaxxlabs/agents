import { describe, it, expect } from 'vitest';
import { asDid, asColumnName, asTableName, asJti, asIssuerUrl } from '#types/domain.js';

describe('domain-types factory functions', () => {
  describe('asDid', () => {
    it('accepts a valid DID', () => {
      expect(asDid('did:dht:abc123')).toBe('did:dht:abc123');
    });

    it('accepts did:key', () => {
      expect(asDid('did:key:z6Mk...')).toBe('did:key:z6Mk...');
    });

    it('rejects empty string', () => {
      expect(() => asDid('')).toThrow('Invalid DID');
    });

    it('rejects string without did: prefix', () => {
      expect(() => asDid('not-a-did')).toThrow('Invalid DID');
    });
  });

  describe('asColumnName', () => {
    it('accepts a valid column name', () => {
      expect(asColumnName('patient_id')).toBe('patient_id');
    });

    it('rejects empty string', () => {
      expect(() => asColumnName('')).toThrow('Invalid column name');
    });

    it('accepts SQL-injection-like strings (shape validation only)', () => {
      expect(asColumnName('"; DROP TABLE --')).toBe('"; DROP TABLE --');
    });
  });

  describe('asTableName', () => {
    it('accepts a simple table name', () => {
      expect(asTableName('patients')).toBe('patients');
    });

    it('accepts a schema-qualified name', () => {
      expect(asTableName('public.patients')).toBe('public.patients');
    });

    it('rejects empty string', () => {
      expect(() => asTableName('')).toThrow('Invalid table name');
    });

    it('accepts SQL-injection-like strings (shape validation only)', () => {
      expect(asTableName('"; DROP TABLE --')).toBe('"; DROP TABLE --');
    });
  });

  describe('asJti', () => {
    it('accepts a valid JTI', () => {
      expect(asJti('urn:uuid:abc-123')).toBe('urn:uuid:abc-123');
    });

    it('rejects empty string', () => {
      expect(() => asJti('')).toThrow('Invalid JTI');
    });
  });

  describe('asIssuerUrl', () => {
    it('accepts an HTTPS URL', () => {
      expect(asIssuerUrl('https://issuer.example.com')).toBe('https://issuer.example.com');
    });

    it('rejects empty string', () => {
      expect(() => asIssuerUrl('')).toThrow('Invalid issuer URL');
    });

    it('rejects HTTP URL', () => {
      expect(() => asIssuerUrl('http://insecure.example.com')).toThrow('Invalid issuer URL');
    });

    it('rejects non-URL string', () => {
      expect(() => asIssuerUrl('not-a-url')).toThrow('Invalid issuer URL');
    });
  });
});
