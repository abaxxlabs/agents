import { describe, it, expect } from 'vitest';
import { OrgBoundary } from '#identity/org-boundary.js';

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
  });
});
