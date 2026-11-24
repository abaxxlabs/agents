import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createMcpBearerAuth, type McpBearerAuth } from '#mcp/auth.js';

// Bun's IncomingMessage does not expose writable headers; use a minimal mock.
function mockRequest(authHeader?: string): IncomingMessage {
  const headers: Record<string, string | undefined> = {};
  if (authHeader !== undefined) {
    headers.authorization = authHeader;
  }
  return { headers } as unknown as IncomingMessage;
}

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

  describe('extractToken', () => {
    it('extracts token from valid Bearer header', () => {
      const req = mockRequest(`Bearer ${VALID_TOKEN}`);
      expect(auth.extractToken(req)).toBe(VALID_TOKEN);
    });
  });

  describe('validateToken', () => {
    it('returns false for an invalid token', () => {
      expect(auth.validateToken('wrong-token')).toBe(false);
    });
  });

  describe('httpGuard', () => {
    it('401 response body does NOT contain token hints or counts', () => {
      const req = mockRequest('Bearer wrong');
      const res = mockResponse();
      auth.httpGuard(req, res);

      const body = res._body;
      expect(body).not.toContain(VALID_TOKEN);
      expect(body).not.toContain('token');
      const parsed = JSON.parse(body);
      expect(Object.keys(parsed)).toEqual(['error', 'code']);
    });
  });

  describe('token rotation', () => {
    it('accepts both old and new tokens during overlap window', () => {
      expect(auth.validateToken(VALID_TOKEN)).toBe(true);
      expect(auth.validateToken(VALID_TOKEN_2)).toBe(false);

      currentTokens = [VALID_TOKEN_2, VALID_TOKEN];
      expect(auth.validateToken(VALID_TOKEN)).toBe(true);
      expect(auth.validateToken(VALID_TOKEN_2)).toBe(true);

      currentTokens = [VALID_TOKEN_2];
      expect(auth.validateToken(VALID_TOKEN)).toBe(false);
      expect(auth.validateToken(VALID_TOKEN_2)).toBe(true);
    });
  });
});
