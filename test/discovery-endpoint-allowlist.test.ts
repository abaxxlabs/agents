import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { validateDiscoveredEndpoint } from '#auth/discovery-utils.js';
import { DiscoveryEndpointBlockedError } from '#errors/index.js';

describe('validateDiscoveredEndpoint — cross-origin allowlist', () => {
  let origNodeEnv: string | undefined;

  beforeEach(() => {
    origNodeEnv = process.env.NODE_ENV;
  });

  afterEach(() => {
    if (origNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = origNodeEnv;
  });

  const ISSUER_ORIGIN = 'https://accounts.example.com';

  it('allows same-origin endpoint with no allowlist configured', () => {
    expect(() =>
      validateDiscoveredEndpoint(
        'https://accounts.example.com/token',
        'token_endpoint',
        ISSUER_ORIGIN,
      ),
    ).not.toThrow();
  });

  it('allows cross-origin endpoint when host is on the allowlist', () => {
    expect(() =>
      validateDiscoveredEndpoint(
        'https://oauth2.example.com/token',
        'token_endpoint',
        ISSUER_ORIGIN,
        'Test',
        ['other.example.com', 'oauth2.example.com'],
      ),
    ).not.toThrow();
  });

  it('rejects cross-origin endpoint not on the allowlist', () => {
    const err = getBlockedError(() =>
      validateDiscoveredEndpoint(
        'https://evil.attacker.com/token',
        'token_endpoint',
        ISSUER_ORIGIN,
        'Test',
        ['oauth2.example.com'],
      ),
    );
    expect(err.configMissing).toBe(false);
    expect(err.code).toBe('DISCOVERY_ENDPOINT_BLOCKED');
    expect(err.message).toContain('evil.attacker.com');
    expect(err.message).toContain('allowedCrossOriginHosts');
  });

  it('rejects cross-origin endpoint when no allowlist is configured', () => {
    const err = getBlockedError(() =>
      validateDiscoveredEndpoint(
        'https://oauth2.example.com/token',
        'token_endpoint',
        ISSUER_ORIGIN,
        'Test',
      ),
    );
    expect(err.configMissing).toBe(true);
    expect(err.code).toBe('DISCOVERY_ENDPOINT_BLOCKED');
    expect(err.message).toContain('no allowedCrossOriginHosts configured');
  });

  it('allows localhost cross-origin in development mode without an allowlist', () => {
    process.env.NODE_ENV = 'development';
    expect(() =>
      validateDiscoveredEndpoint(
        'http://localhost:3001/token',
        'token_endpoint',
        'http://localhost:3000',
      ),
    ).not.toThrow();
  });

  it('rejects non-HTTPS non-localhost endpoint regardless of allowlist', () => {
    process.env.NODE_ENV = 'production';
    expect(() =>
      validateDiscoveredEndpoint(
        'http://accounts.example.com/token',
        'token_endpoint',
        ISSUER_ORIGIN,
        'Test',
        ['accounts.example.com'],
      ),
    ).toThrow(/not HTTPS/);
  });
});

function getBlockedError(fn: () => void): DiscoveryEndpointBlockedError {
  try {
    fn();
    throw new Error('Expected DiscoveryEndpointBlockedError but no error was thrown');
  } catch (err) {
    if (err instanceof DiscoveryEndpointBlockedError) return err;
    throw err;
  }
}
