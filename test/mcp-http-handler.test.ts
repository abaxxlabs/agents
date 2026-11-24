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

import { createMcpHttpHandler } from '#mcp/http-handler.js';
import type { McpBearerAuth } from '#mcp/auth.js';

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
  return { connect: vi.fn(async (_transport: unknown) => undefined) };
}

const noLog = () => undefined;

describe('createMcpHttpHandler — multi-session routing', () => {
  let mcpServer: ReturnType<typeof makeMcpServer>;

  beforeEach(() => {
    mcpServer = makeMcpServer();
    vi.clearAllMocks();
  });

  it('two concurrent /sse clients each get their own transport; POST routes by sessionId', async () => {
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

  it('single-session mode rejects a second /sse until close and rejects the stale session after reconnect', () => {
    const handler = createMcpHttpHandler({
      mcpServer: mcpServer as unknown as Parameters<typeof createMcpHttpHandler>[0]['mcpServer'],
      bearerGuard: null,
      log: noLog,
      singleSessionMode: true,
    });

    const firstRes = makeRes();
    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      firstRes as unknown as ServerResponse,
    );
    expect(handler.activeSessionCount()).toBe(1);
    const firstTransport = mcpServer.connect.mock.calls[0][0] as unknown as {
      sessionId: string;
      handlePostMessage: ReturnType<typeof vi.fn>;
    };

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

    firstRes.emit('close');
    expect(handler.activeSessionCount()).toBe(0);

    handler.handle(
      makeReq('/sse') as unknown as IncomingMessage,
      makeRes() as unknown as ServerResponse,
    );
    expect(handler.activeSessionCount()).toBe(1);
    expect(mcpServer.connect).toHaveBeenCalledTimes(2);
    const secondTransport = mcpServer.connect.mock.calls[1][0] as unknown as {
      sessionId: string;
      handlePostMessage: ReturnType<typeof vi.fn>;
    };
    expect(secondTransport.sessionId).not.toBe(firstTransport.sessionId);

    const staleRes = makeRes();
    handler.handle(
      makeReq(
        `/messages?sessionId=${firstTransport.sessionId}`,
        'POST',
      ) as unknown as IncomingMessage,
      staleRes as unknown as ServerResponse,
    );
    expect(staleRes.writeHead).toHaveBeenCalledWith(400, expect.any(Object));
    expect(firstTransport.handlePostMessage).not.toHaveBeenCalled();
    expect(secondTransport.handlePostMessage).not.toHaveBeenCalled();

    const postReq = makeReq(`/messages?sessionId=${secondTransport.sessionId}`, 'POST');
    handler.handle(postReq as unknown as IncomingMessage, makeRes() as unknown as ServerResponse);
    expect(secondTransport.handlePostMessage).toHaveBeenCalledExactlyOnceWith(
      postReq,
      expect.anything(),
    );
  });

  it('bearer guard rejection: handler returns before any transport allocation', () => {
    const bearerGuard: McpBearerAuth = {
      extractToken: vi.fn(() => undefined),
      validateToken: vi.fn(() => false),
      httpGuard: vi.fn((_req, res) => {
        res.writeHead(401);
        res.end('unauthorized');
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
});
