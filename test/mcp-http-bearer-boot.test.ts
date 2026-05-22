import { describe, it, expect } from 'vitest';
import { evaluateMcpHttpBearerBoot, resolveMcpHttpBearerTokenCount } from '../src/mcp/http-bearer-boot.js';

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

  it('rejects whitespace-only tokens', () => {
    expect(
      resolveMcpHttpBearerTokenCount({
        bearerAuth: { getValidTokens: () => ['  ', '\t'] },
      }),
    ).toEqual({ ok: false, reason: 'getValidTokens() returned no non-empty tokens' });
  });

  it('accepts one trimmed token', () => {
    expect(
      resolveMcpHttpBearerTokenCount({
        bearerAuth: { getValidTokens: () => ['  abc  '] },
      }),
    ).toEqual({ ok: true, count: 1 });
  });
});

describe('evaluateMcpHttpBearerBoot', () => {
  it('returns ok when tokens present', () => {
    expect(
      evaluateMcpHttpBearerBoot(
        { bearerAuth: { getValidTokens: () => ['t'] } },
        'production',
      ),
    ).toEqual({ action: 'ok' });
  });

  it('exits in production when bearerAuth missing', () => {
    const r = evaluateMcpHttpBearerBoot({}, 'production');
    expect(r.action).toBe('exit');
    if (r.action === 'exit') {
      expect(r.code).toBe(1);
      expect(r.stderrLines.join('\n')).toContain('bearerAuth');
      expect(r.stderrLines.join('\n')).toContain('getValidTokens()');
    }
  });

  it('exits in production when token list empty', () => {
    const r = evaluateMcpHttpBearerBoot(
      { bearerAuth: { getValidTokens: () => [] } },
      'production',
    );
    expect(r.action).toBe('exit');
    if (r.action === 'exit') {
      expect(r.stderrLines.join('\n')).toContain('no non-empty tokens');
    }
  });

  it('warns in development with allowNoAuth and no bearer', () => {
    const r = evaluateMcpHttpBearerBoot({ allowNoAuth: true }, 'development');
    expect(r.action).toBe('warn_no_auth');
    if (r.action === 'warn_no_auth') {
      expect(r.stderrLines[0]).toContain('--allow-no-auth');
    }
  });

  it('exits when allowNoAuth outside dev/test', () => {
    const r = evaluateMcpHttpBearerBoot({ allowNoAuth: true }, 'production');
    expect(r.action).toBe('exit');
    if (r.action === 'exit') {
      expect(r.stderrLines[0]).toContain('--allow-no-auth');
    }
  });

  it('exits in staging when no bearer and no allowNoAuth', () => {
    const r = evaluateMcpHttpBearerBoot({}, 'staging');
    expect(r.action).toBe('exit');
  });
});
