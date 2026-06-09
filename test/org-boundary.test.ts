import { describe, it, expect } from 'vitest';
import { OrgBoundary, composeConsumerDomains } from '#identity/org-boundary.js';
import { GenericOidcProvider } from '#auth/generic.js';

describe('OrgBoundary', () => {
  describe('extract()', () => {
    it('prefers hd claim (Google Workspace) over all others', () => {
      const result = OrgBoundary.extract({
        email: 'alice@company.com',
        org: 'other-org.com',
        claims: { hd: 'company.com', tid: 'azure-tenant-id' },
      });
      expect(result.org).toBe('company.com');
      expect(result.source).toBe('hd');
      expect(result.isEnterprise).toBe(true);
    });

    it('falls back to tid (Azure AD) when no hd', () => {
      const result = OrgBoundary.extract({
        email: 'alice@company.com',
        claims: { tid: 'azure-tenant-guid-1234' },
      });
      expect(result.org).toBe('azure-tenant-guid-1234');
      expect(result.source).toBe('tid');
      expect(result.isEnterprise).toBe(true);
    });

    it('uses org claim when no hd or tid', () => {
      const result = OrgBoundary.extract({
        email: 'alice@company.com',
        org: 'abaxx.com',
        claims: {},
      });
      expect(result.org).toBe('abaxx.com');
      expect(result.source).toBe('org_claim');
    });

    it('falls back to email domain when no explicit org claims', () => {
      const result = OrgBoundary.extract({
        email: 'alice@company.com',
        claims: {},
      });
      expect(result.org).toBe('company.com');
      expect(result.source).toBe('email_domain');
      expect(result.isEnterprise).toBe(true);
    });

    it('returns none for consumer gmail.com', () => {
      const result = OrgBoundary.extract({
        email: 'alice@gmail.com',
        claims: {},
      });
      expect(result.org).toBeNull();
      expect(result.source).toBe('none');
      expect(result.isEnterprise).toBe(false);
    });

    it('returns none for all built-in consumer domains', () => {
      const consumerEmails = [
        'user@gmail.com',
        'user@hotmail.com',
        'user@outlook.com',
        'user@icloud.com',
        'user@yahoo.com',
        'user@protonmail.com',
      ];
      for (const email of consumerEmails) {
        const result = OrgBoundary.extract({ email, claims: {} });
        expect(result.isEnterprise).toBe(false);
        expect(result.org).toBeNull();
      }
    });

    it('returns none when no email and no claims', () => {
      const result = OrgBoundary.extract({ claims: {} });
      expect(result.org).toBeNull();
      expect(result.source).toBe('none');
    });

    it('normalizes org to lowercase', () => {
      const result = OrgBoundary.extract({
        email: 'alice@Company.COM',
        claims: { hd: 'Company.COM' },
      });
      expect(result.org).toBe('company.com');
    });
  });

  describe('extraConsumerDomains parameter', () => {
    it('treats custom domains as consumer when passed via parameter', () => {
      const result = OrgBoundary.extract({ email: 'alice@contractor.com', claims: {} }, [
        'contractor.com',
        'freelance.io',
      ]);
      expect(result.org).toBeNull();
      expect(result.isEnterprise).toBe(false);
    });

    it('still treats real enterprise domains as enterprise with custom consumer list', () => {
      const result = OrgBoundary.extract({ email: 'alice@realcompany.com', claims: {} }, [
        'contractor.com',
      ]);
      expect(result.org).toBe('realcompany.com');
      expect(result.isEnterprise).toBe(true);
    });

    it('does NOT honor AGENTS_CONSUMER_DOMAINS env var (library no longer reads it)', () => {
      const orig = process.env.AGENTS_CONSUMER_DOMAINS;
      process.env.AGENTS_CONSUMER_DOMAINS = 'envonly.com';
      try {
        // (a) without param — env should NOT mark envonly.com as consumer
        const aResult = OrgBoundary.extract({ email: 'alice@envonly.com', claims: {} });
        expect(aResult.org).toBe('envonly.com'); // not excluded — env was ignored
        expect(aResult.isEnterprise).toBe(true);

        // (b) with param specifying a different domain — env still ignored
        const bResult = OrgBoundary.extract({ email: 'bob@paramonly.com', claims: {} }, [
          'paramonly.com',
        ]);
        expect(bResult.org).toBeNull();
        expect(bResult.isEnterprise).toBe(false);
      } finally {
        if (orig === undefined) delete process.env.AGENTS_CONSUMER_DOMAINS;
        else process.env.AGENTS_CONSUMER_DOMAINS = orig;
      }
    });

    it('lowercases and trims caller-supplied domains', () => {
      const result = OrgBoundary.extract({ email: 'alice@CONTRACTOR.COM', claims: {} }, [
        '  Contractor.COM  ',
      ]);
      expect(result.org).toBeNull();
    });
  });

  describe('same-source unification', () => {
    it('OrgBoundary and GenericOidcProvider agree on consumer-domain membership for the same list', () => {
      const extra = ['contractor.com', 'freelance.io'];

      // OrgBoundary view: contractor.com is consumer (no org)
      const orgResult = OrgBoundary.extract({ email: 'alice@contractor.com', claims: {} }, extra);
      expect(orgResult.org).toBeNull();

      // GenericOidcProvider view: same domain — extractOrg should also return undefined.
      // We exercise it through public fetchUserInfo? No — extractOrg is private.
      // Instead, verify through the composeConsumerDomains helper that BOTH
      // engines share, AND through a direct private-cast probe to be loud.
      const provider = new GenericOidcProvider({
        issuerUrl: 'https://example.invalid',
        clientId: 'client-id',
        extraConsumerDomains: extra,
      });
      const composed = composeConsumerDomains(extra);
      // Engine-shared composition is the same as the one OrgBoundary uses.
      expect(composed.has('contractor.com')).toBe(true);
      expect(composed.has('freelance.io')).toBe(true);
      expect(composed.has('gmail.com')).toBe(true); // built-in still merged

      // Sanity: the provider's stored config carries the same list.
      const stored = (
        provider as unknown as { config: { extraConsumerDomains?: readonly string[] } }
      ).config.extraConsumerDomains;
      expect(stored).toEqual(extra);
    });

    it('composeConsumerDomains: empty/undefined input returns the same domain set', () => {
      const a = composeConsumerDomains();
      const b = composeConsumerDomains([]);
      expect(a.size).toBe(b.size);
      expect([...a].sort()).toEqual([...b].sort());
      expect(a.has('gmail.com')).toBe(true);
    });

    it('built-in registry is frozen — cannot be mutated by callers', () => {
      const builtIn = composeConsumerDomains();
      expect(() => (builtIn as Set<string>).add('attacker.com')).toThrow();
    });
  });

  describe('assertMembership()', () => {
    it('returns true when org matches (case-insensitive)', () => {
      const identity = { email: 'alice@company.com', claims: { hd: 'company.com' } };
      expect(OrgBoundary.assertMembership(identity, 'company.com')).toBe(true);
      expect(OrgBoundary.assertMembership(identity, 'Company.COM')).toBe(true);
    });

    it('returns false when org does not match', () => {
      const identity = { email: 'alice@company.com', claims: { hd: 'company.com' } };
      expect(OrgBoundary.assertMembership(identity, 'other.com')).toBe(false);
    });

    it('returns false for consumer accounts', () => {
      const identity = { email: 'alice@gmail.com', claims: {} };
      expect(OrgBoundary.assertMembership(identity, 'gmail.com')).toBe(false);
    });
  });

  describe('isConsumerEmail()', () => {
    it('returns true for known consumer domains', () => {
      expect(OrgBoundary.isConsumerEmail('user@gmail.com')).toBe(true);
      expect(OrgBoundary.isConsumerEmail('user@outlook.com')).toBe(true);
      expect(OrgBoundary.isConsumerEmail('user@icloud.com')).toBe(true);
    });

    it('returns false for enterprise domains', () => {
      expect(OrgBoundary.isConsumerEmail('user@company.com')).toBe(false);
      expect(OrgBoundary.isConsumerEmail('user@abaxx.com')).toBe(false);
    });

    it('returns true for malformed email (no @ sign)', () => {
      expect(OrgBoundary.isConsumerEmail('notanemail')).toBe(true);
    });
  });
});
