// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

vi.mock('@modelcontextprotocol/sdk/server/sse.js', () => {
  class FakeSSEServerTransport {
    sessionId = randomUUID();
    onclose: (() => void) | undefined;
    handlePostMessage = vi.fn(async () => undefined);
    close = vi.fn(async () => {
      this.onclose?.();
    });
    constructor(
      public endpoint: string,
      public res: unknown,
    ) {}
  }
  return { SSEServerTransport: FakeSSEServerTransport };
});

import { createMcpHttpHandler } from '../src/mcp/http-handler.js';
import type { McpBearerAuth } from '../src/mcp/auth.js';

interface MockReq extends EventEmitter {
  url: string;
  method: string;
  headers: Record<string, string>;
  socket: { encrypted?: boolean; remoteAddress: string };
}

interface MockRes extends EventEmitter {
  writeHead: ReturnType<typeof vi.fn>;
  write: ReturnType<typeof vi.fn>;
  end: ReturnType<typeof vi.fn>;
  setHeader: ReturnType<typeof vi.fn>;
  getHeader: ReturnType<typeof vi.fn>;
  socket: { remoteAddress: string };
}

function makeReq(
  url: string,
  method: 'GET' | 'POST' = 'GET',
  opts?: { encrypted?: boolean },
): MockReq {
  const r = new EventEmitter() as MockReq;
  r.url = url;
  r.method = method;
  r.headers = {};
  r.socket = { encrypted: opts?.encrypted, remoteAddress: '127.0.0.1' };
  return r;
}

function makeRes(): MockRes {
  const r = new EventEmitter() as MockRes;
  r.writeHead = vi.fn();
  r.write = vi.fn();
  r.end = vi.fn();
  r.setHeader = vi.fn();
  r.getHeader = vi.fn();
  r.socket = { remoteAddress: '127.0.0.1' };
  return r;
}

function makeMcpServer() {
  return { connect: vi.fn(async () => undefined) };
}

const noLog = () => undefined;

describe('createMcpHttpHandler — multi-session routing', () => {
  let mcpServer: ReturnType<typeof makeMcpServer>;

  beforeEach(() => {
    mcpServer = makeMcpServer();
    vi.clearAllMocks();
  });

  it('AC1: two concurrent /sse clients each get their own transport; POST routes by sessionId', async () => {
    const handler = createMcpHttpHandler({
      mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
      bearerGuard: null,
      log: noLog,
    });

    const sseResA = makeRes();
    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      sseResA as unknown as ServerResponse,
    );
    const sseResB = makeRes();
    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      sseResB as unknown as ServerResponse,
    );

    expect(handler.activeSessionCount()).toBe(2);
    expect(mcpServer.connect).toHaveBeenCalledTimes(2);

    const transportA = mcpServer.connect.mock.calls[0][0] as unknown as {
      sessionId: string;
      handlePostMessage: ReturnType<typeof vi.fn>;
    };
    const transportB = mcpServer.connect.mock.calls[1][0] as unknown as {
      sessionId: string;
      handlePostMessage: ReturnType<typeof vi.fn>;
    };
    expect(transportA.sessionId).not.toBe(transportB.sessionId);

    const postReqA = makeReq(`/messages?sessionId=${transportA.sessionId}`, 'POST');
    handler.handle(postReqA as unknown as IncomingMessage, makeRes() as unknown as ServerResponse);

    const postReqB = makeReq(`/messages?sessionId=${transportB.sessionId}`, 'POST');
    handler.handle(postReqB as unknown as IncomingMessage, makeRes() as unknown as ServerResponse);

    expect(transportA.handlePostMessage).toHaveBeenCalledTimes(1);
    expect(transportB.handlePostMessage).toHaveBeenCalledTimes(1);
    expect(transportA.handlePostMessage.mock.calls[0][0]).toBe(postReqA);
    expect(transportB.handlePostMessage.mock.calls[0][0]).toBe(postReqB);
  });

  it('AC2: POST /messages with no sessionId returns 400; no transport invoked', () => {
    const handler = createMcpHttpHandler({
      mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
      bearerGuard: null,
      log: noLog,
    });

    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      makeRes() as unknown as ServerResponse,
    );
    const transport = mcpServer.connect.mock.calls[0][0] as unknown as {
      handlePostMessage: ReturnType<typeof vi.fn>;
    };

    const res = makeRes();
    handler.handle(
      makeReq('/messages', 'POST') as unknown as IncomingMessage,
      res as unknown as ServerResponse,
    );

    expect(res.writeHead).toHaveBeenCalledWith(
      400,
      expect.objectContaining({ 'Content-Type': 'application/json' }),
    );
    const body = res.end.mock.calls[0][0] as string;
    expect(JSON.parse(body)).toMatchObject({ error: 'invalid_session', code: 400 });
    expect(transport.handlePostMessage).not.toHaveBeenCalled();
  });

  it('AC2: POST /messages with bogus sessionId returns 400; no transport invoked', () => {
    const handler = createMcpHttpHandler({
      mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
      bearerGuard: null,
      log: noLog,
    });

    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      makeRes() as unknown as ServerResponse,
    );
    const transport = mcpServer.connect.mock.calls[0][0] as unknown as {
      handlePostMessage: ReturnType<typeof vi.fn>;
    };

    const res = makeRes();
    handler.handle(
      makeReq('/messages?sessionId=not-a-real-session', 'POST') as unknown as IncomingMessage,
      res as unknown as ServerResponse,
    );

    expect(res.writeHead).toHaveBeenCalledWith(400, expect.any(Object));
    expect(transport.handlePostMessage).not.toHaveBeenCalled();
  });

  it('AC4: a reconnect after a notional bearer rotation does not hijack the existing client', () => {
    const handler = createMcpHttpHandler({
      mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
      bearerGuard: null,
      log: noLog,
    });

    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      makeRes() as unknown as ServerResponse,
    );
    const transportA = mcpServer.connect.mock.calls[0][0] as unknown as {
      sessionId: string;
      handlePostMessage: ReturnType<typeof vi.fn>;
    };

    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      makeRes() as unknown as ServerResponse,
    );
    const transportB = mcpServer.connect.mock.calls[1][0] as unknown as {
      sessionId: string;
      handlePostMessage: ReturnType<typeof vi.fn>;
    };

    const postReqA = makeReq(`/messages?sessionId=${transportA.sessionId}`, 'POST');
    handler.handle(postReqA as unknown as IncomingMessage, makeRes() as unknown as ServerResponse);

    expect(transportA.handlePostMessage).toHaveBeenCalledTimes(1);
    expect(transportB.handlePostMessage).not.toHaveBeenCalled();
    expect(transportA.handlePostMessage.mock.calls[0][0]).toBe(postReqA);
  });

  it('AC3: second /sse while one is open returns 409 Conflict in single-session mode', () => {
    const handler = createMcpHttpHandler({
      mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
      bearerGuard: null,
      log: noLog,
      singleSessionMode: true,
    });

    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      makeRes() as unknown as ServerResponse,
    );
    expect(handler.activeSessionCount()).toBe(1);

    const conflictRes = makeRes();
    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      conflictRes as unknown as ServerResponse,
    );

    expect(conflictRes.writeHead).toHaveBeenCalledWith(
      409,
      expect.objectContaining({ 'Content-Type': 'application/json' }),
    );
    expect(JSON.parse(conflictRes.end.mock.calls[0][0] as string)).toMatchObject({
      error: 'session_conflict',
      code: 409,
    });
    expect(handler.activeSessionCount()).toBe(1);
    expect(mcpServer.connect).toHaveBeenCalledTimes(1);
  });

  it('AC3: reconnect succeeds in single-session mode after the previous session closes', () => {
    const handler = createMcpHttpHandler({
      mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
      bearerGuard: null,
      log: noLog,
      singleSessionMode: true,
    });

    const firstRes = makeRes();
    handler.handle(makeReq('/sse') as unknown as IncomingMessage, firstRes as unknown as ServerResponse);
    expect(handler.activeSessionCount()).toBe(1);

    firstRes.emit('close');
    expect(handler.activeSessionCount()).toBe(0);

    const secondRes = makeRes();
    handler.handle(makeReq('/sse') as unknown as IncomingMessage, secondRes as unknown as ServerResponse);

    expect(secondRes.writeHead).not.toHaveBeenCalledWith(409, expect.anything());
    expect(handler.activeSessionCount()).toBe(1);
    expect(mcpServer.connect).toHaveBeenCalledTimes(2);
  });

  it("cleanup: response 'close' event removes the session; subsequent POST returns 400", () => {
    const handler = createMcpHttpHandler({
      mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
      bearerGuard: null,
      log: noLog,
    });

    const sseRes = makeRes();
    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      sseRes as unknown as ServerResponse,
    );
    const transport = mcpServer.connect.mock.calls[0][0] as unknown as {
      sessionId: string;
      handlePostMessage: ReturnType<typeof vi.fn>;
    };

    expect(handler.activeSessionCount()).toBe(1);
    sseRes.emit('close');
    expect(handler.activeSessionCount()).toBe(0);

    const res = makeRes();
    handler.handle(
      makeReq(`/messages?sessionId=${transport.sessionId}`, 'POST') as unknown as IncomingMessage,
      res as unknown as ServerResponse,
    );
    expect(res.writeHead).toHaveBeenCalledWith(400, expect.any(Object));
    expect(transport.handlePostMessage).not.toHaveBeenCalled();
  });

  it('bearer guard rejection: handler returns before any transport allocation', () => {
    const bearerGuard: McpBearerAuth = {
      extractToken: vi.fn(() => undefined),
      validateToken: vi.fn(() => false),
      httpGuard: vi.fn((_req, res) => {
        (res as unknown as MockRes).writeHead(401);
        (res as unknown as MockRes).end('unauthorized');
        return false;
      }),
    };
    const handler = createMcpHttpHandler({
      mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
      bearerGuard,
      log: noLog,
    });

    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      makeRes() as unknown as ServerResponse,
    );

    expect(bearerGuard.httpGuard).toHaveBeenCalled();
    expect(mcpServer.connect).not.toHaveBeenCalled();
    expect(handler.activeSessionCount()).toBe(0);
  });

  it('/health: not gated by bearer guard (load balancer probe path)', () => {
    const bearerGuard: McpBearerAuth = {
      extractToken: vi.fn(),
      validateToken: vi.fn(),
      httpGuard: vi.fn(() => false),
    };
    const handler = createMcpHttpHandler({
      mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
      bearerGuard,
      log: noLog,
    });

    const res = makeRes();
    handler.handle(
      makeReq('/health') as unknown as IncomingMessage,
      res as unknown as ServerResponse,
    );

    expect(res.writeHead).toHaveBeenCalledWith(200);
    expect(res.end).toHaveBeenCalledWith('ok');
    expect(bearerGuard.httpGuard).not.toHaveBeenCalled();
  });

  it('rejects /sse with 503 when concurrent session cap is reached', () => {
    const handler = createMcpHttpHandler({
      mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
      bearerGuard: null,
      log: noLog,
      maxConcurrentSessions: 2,
    });

    handler.handle(makeReq('/sse') as unknown as IncomingMessage, makeRes() as unknown as ServerResponse);
    handler.handle(makeReq('/sse') as unknown as IncomingMessage, makeRes() as unknown as ServerResponse);
    expect(handler.activeSessionCount()).toBe(2);

    const overflowRes = makeRes();
    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      overflowRes as unknown as ServerResponse,
    );

    expect(overflowRes.writeHead).toHaveBeenCalledWith(
      503,
      expect.objectContaining({ 'Content-Type': 'application/json' }),
    );
    expect(JSON.parse(overflowRes.end.mock.calls[0][0] as string)).toMatchObject({
      error: 'too_many_sessions',
      code: 503,
    });
    expect(handler.activeSessionCount()).toBe(2);
    expect(mcpServer.connect).toHaveBeenCalledTimes(2);
  });

  it('unknown path returns 404', () => {
    const handler = createMcpHttpHandler({
      mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
      bearerGuard: null,
      log: noLog,
    });

    const res = makeRes();
    handler.handle(
      makeReq('/random/path') as unknown as IncomingMessage,
      res as unknown as ServerResponse,
    );
    expect(res.writeHead).toHaveBeenCalledWith(404);
  });

  it('closeAll(): drains every open transport and clears the map', async () => {
    const handler = createMcpHttpHandler({
      mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
      bearerGuard: null,
      log: noLog,
    });

    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      makeRes() as unknown as ServerResponse,
    );
    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      makeRes() as unknown as ServerResponse,
    );
    expect(handler.activeSessionCount()).toBe(2);

    const transports = mcpServer.connect.mock.calls.map(
      (c) => c[0] as unknown as { close: ReturnType<typeof vi.fn> },
    );

    await handler.closeAll();

    expect(handler.activeSessionCount()).toBe(0);
    for (const t of transports) {
      expect(t.close).toHaveBeenCalledTimes(1);
    }
  });

  describe('security headers (ABXAGNTS-379)', () => {
    const EXPECTED_BASELINE: Array<[string, string]> = [
      ['X-Content-Type-Options', 'nosniff'],
      ['Cache-Control', 'no-store'],
      ['Referrer-Policy', 'no-referrer'],
      ['Cross-Origin-Resource-Policy', 'same-origin'],
    ];

    function headerMap(res: MockRes): Map<string, string> {
      const m = new Map<string, string>();
      for (const call of res.setHeader.mock.calls as Array<[string, string]>) {
        m.set(call[0], call[1]);
      }
      return m;
    }

    it('every HTTP response carries baseline security headers', () => {
      const handler = createMcpHttpHandler({
        mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
        bearerGuard: null,
        log: noLog,
      });

      const res = makeRes();
      handler.handle(makeReq('/health') as unknown as IncomingMessage, res as unknown as ServerResponse);

      const headers = headerMap(res);
      for (const [name, value] of EXPECTED_BASELINE) {
        expect(headers.get(name)).toBe(value);
      }
    });

    it('HSTS is omitted over plain HTTP', () => {
      const handler = createMcpHttpHandler({
        mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
        bearerGuard: null,
        log: noLog,
      });

      const res = makeRes();
      handler.handle(makeReq('/health') as unknown as IncomingMessage, res as unknown as ServerResponse);

      const headers = headerMap(res);
      expect(headers.has('Strict-Transport-Security')).toBe(false);
    });

    it('HSTS is present over HTTPS', () => {
      const handler = createMcpHttpHandler({
        mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
        bearerGuard: null,
        log: noLog,
      });

      const res = makeRes();
      handler.handle(
        makeReq('/health', 'GET', { encrypted: true }) as unknown as IncomingMessage,
        res as unknown as ServerResponse,
      );

      const headers = headerMap(res);
      expect(headers.get('Strict-Transport-Security')).toBe('max-age=63072000; includeSubDomains');
    });

    it('error responses carry security headers', () => {
      const handler = createMcpHttpHandler({
        mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
        bearerGuard: null,
        log: noLog,
      });

      const res = makeRes();
      handler.handle(
        makeReq('/random/path') as unknown as IncomingMessage,
        res as unknown as ServerResponse,
      );

      const headers = headerMap(res);
      for (const [name, value] of EXPECTED_BASELINE) {
        expect(headers.get(name)).toBe(value);
      }
    });
  });
});
