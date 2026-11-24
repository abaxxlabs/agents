import { describe, it, expect } from 'vitest';
import {
  evaluateMcpHttpBearerBoot,
  resolveMcpHttpBearerTokenCount,
} from '#mcp/http-bearer-boot.js';

describe('resolveMcpHttpBearerTokenCount', () => {
  it('rejects missing bearerAuth', () => {
    expect(resolveMcpHttpBearerTokenCount({})).toEqual({
      ok: false,
      reason: 'bearerAuth is not configured',
    });
  });

  it('rejects empty token list', () => {
    expect(
      resolveMcpHttpBearerTokenCount({
        bearerAuth: { getValidTokens: () => [] },
      }),
    ).toEqual({ ok: false, reason: 'getValidTokens() returned no non-empty tokens' });
  });
});

describe('evaluateMcpHttpBearerBoot', () => {
  it('exits when allowNoAuth outside dev/test', () => {
    const r = evaluateMcpHttpBearerBoot({ allowNoAuth: true }, 'production');
    expect(r.action).toBe('exit');
    if (r.action === 'exit') {
      expect(r.stderrLines[0]).toContain('--allow-no-auth');
    }
  });
});
