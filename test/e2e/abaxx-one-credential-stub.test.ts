import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { AbaxxOneOidcProvider } from '#auth/abaxx-one.js';
import { issueCredential, issueCredentialFromParent } from '#auth/credential-issuance.js';
import { generateDidKey } from '#auth/did-key.js';
import { extractMaxDepth } from '#auth/delegation-policy.js';
import { decodeJwt } from '#crypto/jwt.js';

const CREDENTIAL_PATH = '/api/v1/credentials/agent';

interface AgentCredentialRequest {
  agentDid: string;
  scope: { columns: string[]; actions: string[] };
  expiresIn: string | number;
  maxDepth?: number;
}

interface ObservedRequest {
  method: string;
  path: string;
  authorization: string | undefined;
  contentType: string | undefined;
  body: AgentCredentialRequest;
}

/** Binds port 0; the org is a fresh did:key, so verification needs no DHT or relay. */
class AbaxxOneCredentialStub {
  private server?: Server;
  private boundPort = 0;

  readonly orgDid: string;
  private readonly orgPrivateKey: Uint8Array;

  readonly received: ObservedRequest[] = [];

  constructor() {
    const orgKey = generateDidKey();
    this.orgDid = orgKey.did;
    this.orgPrivateKey = orgKey.privateKey;
  }

  get url(): string {
    return `http://127.0.0.1:${this.boundPort}`;
  }

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = createServer((req, res) => {
        this.handle(req, res).catch((err: unknown) => {
          // A 500 here would read as a client-side contract failure.
          console.error('[AbaxxOneCredentialStub] handler threw:', err);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'stub_internal_error' }));
        });
      });
      this.server.on('error', reject);
      this.server.listen(0, '127.0.0.1', () => {
        const addr = this.server?.address();
        if (addr === null || addr === undefined || typeof addr === 'string') {
          return reject(new Error('Stub failed to bind a TCP port'));
        }
        this.boundPort = addr.port;
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
    });
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const path = new URL(req.url ?? '/', this.url).pathname;

    if (req.method !== 'POST' || path !== CREDENTIAL_PATH) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not_found' }));
      return;
    }

    const body = (await readJsonBody(req)) as AgentCredentialRequest;
    this.received.push({
      method: req.method,
      path,
      authorization: req.headers.authorization,
      contentType: req.headers['content-type'],
      body,
    });

    // The org DID in the humanDid slot makes `iss` the org.
    const jwt = await issueCredential(this.orgDid, this.orgPrivateKey, {
      agent: body.agentDid,
      columns: body.scope.columns,
      actions: body.scope.actions as 'read'[],
      expiresIn: body.expiresIn,
      ...(body.maxDepth !== undefined ? { maxDepth: body.maxDepth } : {}),
    });

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ jwt }));
  }
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

const AGENT_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const ACCESS_TOKEN = 'dummy-access-token';

const ORDER_BOOK_COLUMNS = [
  'order_book.ticker',
  'order_book.side',
  'order_book.quantity',
  'order_book.price',
  'order_book.client_id',
  'order_book.strategy',
  'order_book.model_version',
];

describe('AbaxxOne agent credential — HTTP contract (stub)', () => {
  let stub: AbaxxOneCredentialStub;
  let provider: AbaxxOneOidcProvider;

  beforeAll(async () => {
    stub = new AbaxxOneCredentialStub();
    await stub.start();

    // clientId is required by the config type but unused on this path.
    provider = new AbaxxOneOidcProvider({
      tenantUrl: stub.url,
      clientId: 'stub-client',
    });
  });

  afterAll(async () => {
    await stub.stop();
  });

  it('issues a credential over HTTP with the org DID as issuer', async () => {
    const result = await issueCredentialFromParent(provider, ACCESS_TOKEN, AGENT_DID, {
      columns: ORDER_BOOK_COLUMNS,
      actions: ['read'],
      expiresIn: '4h',
      // Not 2: that's the default, so it would pass even if forwarding broke.
      maxDepth: 3,
    });

    expect(result.issuerDid).toBe(stub.orgDid);
    expect(typeof result.jwt).toBe('string');

    const { payload } = decodeJwt(result.jwt);
    expect(payload.iss).toBe(stub.orgDid);
    expect(payload.sub).toBe(AGENT_DID);
    expect(payload.jti).toBeTruthy();
    expect(extractMaxDepth(payload)).toBe(3);

    const vc = payload.vc as {
      type: string[];
      credentialSubject: {
        id: string;
        scope: { columns: string[]; actions: string[] };
      };
    };
    expect(vc.type).toEqual(['VerifiableCredential', 'AgentScopeCredential']);
    expect(vc.credentialSubject.id).toBe(AGENT_DID);
    expect(vc.credentialSubject.scope.columns).toEqual(ORDER_BOOK_COLUMNS);
    expect(vc.credentialSubject.scope.actions).toEqual(['read']);
  });

  it('reaches the tenant over a real socket with the documented request shape', () => {
    expect(stub.received).toHaveLength(1);

    const observed = stub.received[0];
    expect(observed.method).toBe('POST');
    expect(observed.path).toBe(CREDENTIAL_PATH);
    expect(observed.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
    expect(observed.contentType).toBe('application/json');

    expect(observed.body).toEqual({
      agentDid: AGENT_DID,
      scope: { columns: ORDER_BOOK_COLUMNS, actions: ['read'] },
      expiresIn: '4h',
      maxDepth: 3,
    });
  });
});
