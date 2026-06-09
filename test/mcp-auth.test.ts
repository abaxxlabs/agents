import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  createMcpBearerAuth,
  OVERLAP_WINDOW_SECONDS,
  type McpBearerAuth,
} from '#mcp/auth.js';

// ─── Test Helpers ───────────────────────────────────────────────────────────

/**
 * Create a minimal mock for IncomingMessage with the given Authorization header.
 *
 * Bun's IncomingMessage constructor does not initialize headers as a plain
 * writable object, so we use a lightweight mock that satisfies the auth module's
 * contract: it reads req.headers.authorization and nothing else.
 */
function mockRequest(authHeader?: string): IncomingMessage {
  const headers: Record<string, string | undefined> = {};
  if (authHeader !== undefined) {
    headers.authorization = authHeader;
  }
  return { headers } as unknown as IncomingMessage;
}

/**
 * Create a mock ServerResponse that captures writeHead and end calls.
 * Used to verify 401 response format and headers.
 */
type MockResponse = ServerResponse & {
  _statusCode: number | undefined;
  _headers: Record<string, string>;
  _body: string;
};

function mockResponse(): MockResponse {
  const res = {
    _statusCode: undefined as number | undefined,
    _headers: {} as Record<string, string>,
    _body: '',
    writeHead: vi.fn(function (
      this: MockResponse,
      statusCode: number,
      headers?: Record<string, string>,
    ) {
      this._statusCode = statusCode;
      if (headers) Object.assign(this._headers, headers);
      return this;
    }),
    end: vi.fn(function (this: MockResponse, body?: string) {
      if (body) this._body = body;
      return this;
    }),
  };
  return res as unknown as MockResponse;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('MCP Bearer Auth', () => {
  const VALID_TOKEN = 'test-bearer-token-abc123';
  const VALID_TOKEN_2 = 'rotated-bearer-token-xyz789';
  let auth: McpBearerAuth;
  let currentTokens: string[];

  beforeEach(() => {
    currentTokens = [VALID_TOKEN];
    auth = createMcpBearerAuth({
      getValidTokens: () => currentTokens,
    });
  });

  // ── OVERLAP_WINDOW_SECONDS constant ──────────────────────────────

  describe('OVERLAP_WINDOW_SECONDS', () => {
    it('is 30 seconds', () => {
      expect(OVERLAP_WINDOW_SECONDS).toBe(30);
    });

    it('is a positive integer', () => {
      expect(Number.isInteger(OVERLAP_WINDOW_SECONDS)).toBe(true);
      expect(OVERLAP_WINDOW_SECONDS).toBeGreaterThan(0);
    });
  });

  // ── extractToken ─────────────────────────────────────────────────

  describe('extractToken', () => {
    it('extracts token from valid Bearer header', () => {
      const req = mockRequest(`Bearer ${VALID_TOKEN}`);
      expect(auth.extractToken(req)).toBe(VALID_TOKEN);
    });

    it('returns undefined when Authorization header is missing', () => {
      const req = mockRequest();
      expect(auth.extractToken(req)).toBeUndefined();
    });

    it('returns undefined for empty Authorization header', () => {
      const req = mockRequest('');
      expect(auth.extractToken(req)).toBeUndefined();
    });

    it('returns undefined for non-Bearer scheme (Basic)', () => {
      const req = mockRequest('Basic dXNlcjpwYXNz');
      expect(auth.extractToken(req)).toBeUndefined();
    });

    it('returns undefined for Bearer with no token', () => {
      // "Bearer " with only whitespace after — no \S+ match
      const req = mockRequest('Bearer ');
      expect(auth.extractToken(req)).toBeUndefined();
    });

    it('handles case-insensitive Bearer prefix', () => {
      const req = mockRequest(`bearer ${VALID_TOKEN}`);
      expect(auth.extractToken(req)).toBe(VALID_TOKEN);
    });

    it('handles BEARER uppercase prefix', () => {
      const req = mockRequest(`BEARER ${VALID_TOKEN}`);
      expect(auth.extractToken(req)).toBe(VALID_TOKEN);
    });

    it('handles multiple spaces between Bearer and token', () => {
      // RFC 6750 allows optional whitespace: "Bearer" 1*SP b64token
      // Our regex uses \s+ which matches multiple spaces
      const req = mockRequest(`Bearer   ${VALID_TOKEN}`);
      expect(auth.extractToken(req)).toBe(VALID_TOKEN);
    });

    it('rejects token with embedded spaces (returns first part only would be wrong — our regex rejects)', () => {
      // "Bearer token with spaces" — the regex \S+ stops at the first space
      // after the Bearer prefix, so it would match "token" only. But the full
      // match requires the token to extend to end of string ($), so this
      // should NOT match (there's extra content after the first space-delimited token).
      const req = mockRequest('Bearer token with spaces');
      expect(auth.extractToken(req)).toBeUndefined();
    });
  });

  // ── validateToken ────────────────────────────────────────────────

  describe('validateToken', () => {
    it('returns true for a valid token', () => {
      expect(auth.validateToken(VALID_TOKEN)).toBe(true);
    });

    it('returns false for undefined', () => {
      expect(auth.validateToken(undefined)).toBe(false);
    });

    it('returns false for empty string', () => {
      expect(auth.validateToken('')).toBe(false);
    });

    it('returns false for an invalid token', () => {
      expect(auth.validateToken('wrong-token')).toBe(false);
    });

    it('returns false for a token that is a prefix of the valid token', () => {
      expect(auth.validateToken(VALID_TOKEN.slice(0, 10))).toBe(false);
    });

    it('returns false for a token that is the valid token with extra chars', () => {
      expect(auth.validateToken(VALID_TOKEN + 'extra')).toBe(false);
    });

    it('validates against multiple tokens during rotation', () => {
      // Simulate token rotation: both old and new tokens are valid
      currentTokens = [VALID_TOKEN_2, VALID_TOKEN];
      expect(auth.validateToken(VALID_TOKEN)).toBe(true);
      expect(auth.validateToken(VALID_TOKEN_2)).toBe(true);
      expect(auth.validateToken('neither-token')).toBe(false);
    });

    it('rejects old token after rotation window expires', () => {
      // Simulate post-rotation: only new token is valid
      currentTokens = [VALID_TOKEN_2];
      expect(auth.validateToken(VALID_TOKEN)).toBe(false);
      expect(auth.validateToken(VALID_TOKEN_2)).toBe(true);
    });

    it('handles empty token array (all tokens revoked)', () => {
      currentTokens = [];
      expect(auth.validateToken(VALID_TOKEN)).toBe(false);
    });
  });

  // ── httpGuard ────────────────────────────────────────────────────

  describe('httpGuard', () => {
    it('returns true for valid bearer token (authorized)', () => {
      const req = mockRequest(`Bearer ${VALID_TOKEN}`);
      const res = mockResponse();
      expect(auth.httpGuard(req, res)).toBe(true);
      // Should NOT have sent any response
      expect(res.writeHead).not.toHaveBeenCalled();
      expect(res.end).not.toHaveBeenCalled();
    });

    it('returns false and sends 401 for missing Authorization header', () => {
      const req = mockRequest();
      const res = mockResponse();
      expect(auth.httpGuard(req, res)).toBe(false);
      expect(res._statusCode).toBe(401);
    });

    it('returns false and sends 401 for invalid token', () => {
      const req = mockRequest('Bearer wrong-token');
      const res = mockResponse();
      expect(auth.httpGuard(req, res)).toBe(false);
      expect(res._statusCode).toBe(401);
    });

    it('returns false and sends 401 for non-Bearer auth scheme', () => {
      const req = mockRequest('Basic dXNlcjpwYXNz');
      const res = mockResponse();
      expect(auth.httpGuard(req, res)).toBe(false);
      expect(res._statusCode).toBe(401);
    });

    it('401 response body is JSON with { error, code }', () => {
      const req = mockRequest('Bearer wrong');
      const res = mockResponse();
      auth.httpGuard(req, res);

      const body = JSON.parse(res._body);
      expect(body).toEqual({ error: 'unauthorized', code: 401 });
    });

    it('401 response includes Content-Type: application/json', () => {
      const req = mockRequest('Bearer wrong');
      const res = mockResponse();
      auth.httpGuard(req, res);

      expect(res._headers['Content-Type']).toBe('application/json');
    });

    it('401 response includes WWW-Authenticate header (RFC 6750)', () => {
      const req = mockRequest('Bearer wrong');
      const res = mockResponse();
      auth.httpGuard(req, res);

      expect(res._headers['WWW-Authenticate']).toBe('Bearer realm="agents-mcp"');
    });

    it('401 response body does NOT contain token hints or counts', () => {
      const req = mockRequest('Bearer wrong');
      const res = mockResponse();
      auth.httpGuard(req, res);

      const body = res._body;
      // Must not contain valid token values, token count, or hints
      expect(body).not.toContain(VALID_TOKEN);
      expect(body).not.toContain('token');
      // Only 'error' and 'code' keys
      const parsed = JSON.parse(body);
      expect(Object.keys(parsed)).toEqual(['error', 'code']);
    });
  });

  // ── Token Rotation (E6) ──────────────────────────────────────────

  describe('token rotation', () => {
    it('accepts both old and new tokens during overlap window', () => {
      // Pre-rotation: only old token valid
      expect(auth.validateToken(VALID_TOKEN)).toBe(true);
      expect(auth.validateToken(VALID_TOKEN_2)).toBe(false);

      // Rotation begins: both tokens valid
      currentTokens = [VALID_TOKEN_2, VALID_TOKEN];
      expect(auth.validateToken(VALID_TOKEN)).toBe(true);
      expect(auth.validateToken(VALID_TOKEN_2)).toBe(true);

      // Overlap expires: only new token valid
      currentTokens = [VALID_TOKEN_2];
      expect(auth.validateToken(VALID_TOKEN)).toBe(false);
      expect(auth.validateToken(VALID_TOKEN_2)).toBe(true);
    });

    it('httpGuard works with rotated tokens', () => {
      currentTokens = [VALID_TOKEN_2, VALID_TOKEN];

      // Old token still works
      const req1 = mockRequest(`Bearer ${VALID_TOKEN}`);
      const res1 = mockResponse();
      expect(auth.httpGuard(req1, res1)).toBe(true);

      // New token works
      const req2 = mockRequest(`Bearer ${VALID_TOKEN_2}`);
      const res2 = mockResponse();
      expect(auth.httpGuard(req2, res2)).toBe(true);
    });

    it('getValidTokens is called on every validation (not cached)', () => {
      const getTokensSpy = vi.fn(() => currentTokens);
      const freshAuth = createMcpBearerAuth({ getValidTokens: getTokensSpy });

      freshAuth.validateToken(VALID_TOKEN);
      freshAuth.validateToken(VALID_TOKEN);
      freshAuth.validateToken(VALID_TOKEN);

      // Called once per validateToken — not cached between calls
      expect(getTokensSpy).toHaveBeenCalledTimes(3);
    });
  });

  // ── Security Properties ──────────────────────────────────────────

  describe('security properties', () => {
    it('constant-time comparison — different-length tokens do not short-circuit', () => {
      // This is a behavioral test, not a timing test. We verify that tokens
      // of different lengths are correctly rejected (the constant-time comparison
      // handles length mismatch internally with a dummy buffer comparison).
      expect(auth.validateToken('short')).toBe(false);
      expect(auth.validateToken(VALID_TOKEN + 'x'.repeat(1000))).toBe(false);
      expect(auth.validateToken('')).toBe(false);
    });

    it('does not accept null or non-string values', () => {
      // Testing edge case: validateToken receives non-string input despite types
      expect(auth.validateToken(null as unknown as string)).toBe(false);
      expect(auth.validateToken(undefined as unknown as string)).toBe(false);
      expect(auth.validateToken(123 as unknown as string)).toBe(false);
    });
  });

  // ── createMcpBearerAuth factory ──────────────────────────────────

  describe('createMcpBearerAuth', () => {
    it('returns an object with extractToken, validateToken, httpGuard', () => {
      const auth = createMcpBearerAuth({ getValidTokens: () => [] });
      expect(typeof auth.extractToken).toBe('function');
      expect(typeof auth.validateToken).toBe('function');
      expect(typeof auth.httpGuard).toBe('function');
    });

    it('works with empty token list (rejects all)', () => {
      const auth = createMcpBearerAuth({ getValidTokens: () => [] });
      expect(auth.validateToken('any-token')).toBe(false);
    });
  });
});
