import { describe, it, expect, vi, type Mock } from 'vitest';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Pool } from 'pg';
import { createMcpServer, getVersion } from '../src/mcp/server.js';
import { AuditLogger } from '../src/audit-logger.js';
import { AgentScope } from '../src/sql/index.js';
import { generateDidKey, createSigner } from '../src/auth/index.js';
import type { AuditStore } from '../src/storage/types.js';
import type { AuthenticatedSession } from '../src/types/index.js';

const fixturesDir = join(
  dirname(fileURLToPath(import.meta.url)),
  'fixtures',
  'version-resolution',
);
const stub = join(fixturesDir, 'stub-package.json');
const real = join(fixturesDir, 'real-package.json');
const emptyVersion = join(fixturesDir, 'empty-version-package.json');
const missing = join(fixturesDir, 'does-not-exist.json');

describe('getVersion', () => {
  it('returns the version when the first candidate has a valid version field', () => {
    expect(getVersion([real])).toBe('9.9.9');
  });

  it('skips candidates whose package.json lacks a version field (CJS stub case)', () => {
    expect(getVersion([stub, real])).toBe('9.9.9');
  });

  it('skips candidates whose version field is an empty string', () => {
    expect(getVersion([emptyVersion, real])).toBe('9.9.9');
  });

  it('skips missing files and continues to the next candidate', () => {
    expect(getVersion([missing, real])).toBe('9.9.9');
  });

  it('returns "0.0.0" when no candidate yields a usable version', () => {
    expect(getVersion([stub, emptyVersion, missing])).toBe('0.0.0');
  });

  it('returns "0.0.0" when given an empty candidate list', () => {
    expect(getVersion([])).toBe('0.0.0');
  });

  it('resolves a non-empty version string with the default candidates (dev tree)', () => {
    const v = getVersion();
    expect(typeof v).toBe('string');
    expect(v.length).toBeGreaterThan(0);
    expect(v).not.toBe('0.0.0');
  });

  it('regression: dist/cjs/package.json stub does not poison version resolution', () => {
    const distCjsStub = stub;
    const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'package.json');
    expect(getVersion([distCjsStub, repoRoot])).not.toBe('0.0.0');
    expect(getVersion([distCjsStub, repoRoot])).not.toBe(undefined);
  });
});

describe('createMcpServer — serverInfo handshake', () => {
  it('produces a server with a non-empty string version in serverInfo', () => {
    const { scope, session, auditLogger } = makeMinimalDeps();
    const server = createMcpServer({ scope, session, auditLogger });

    const serverInfo = (server.server as unknown as { _serverInfo: { name: string; version: unknown } })
      ._serverInfo;
    expect(typeof serverInfo.version).toBe('string');
    expect(serverInfo.version).not.toBe('');
    expect(serverInfo.name).toBe('agents');
  });
});

function makeMinimalDeps() {
  const human = generateDidKey();
  const agent = generateDidKey();

  const pool = {
    query: vi.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
    end: vi.fn(),
  } as unknown as Pool;

  const mockAuditStore: AuditStore = {
    append: vi.fn().mockResolvedValue(undefined),
    loadLastRecord: vi.fn().mockResolvedValue(null),
    loadLastRecordLocked: vi.fn().mockResolvedValue(null),
    query: vi.fn().mockResolvedValue([]),
    count: vi.fn().mockResolvedValue(0),
  };
  const auditLogger = new AuditLogger({ auditStore: mockAuditStore, enabled: true });

  const scope = {
    query: vi.fn(),
    createAgent: vi.fn(),
    verify: vi.fn(),
    listAgents: vi.fn(),
    getServerStatus: vi.fn(),
    close: vi.fn(),
    auditLoggerInstance: auditLogger,
  } as unknown as AgentScope & {
    query: Mock;
    createAgent: Mock;
    verify: Mock;
    listAgents: Mock;
    getServerStatus: Mock;
    close: Mock;
  };

  const session = {
    humanDid: human.did,
    issueCredential: vi.fn(),
    revokeCredential: vi.fn(),
  } as unknown as AuthenticatedSession & {
    issueCredential: Mock;
    revokeCredential: Mock;
  };

  // signer kept to mirror the shape used elsewhere; not invoked here
  void createSigner(agent.privateKey);

  return { scope, session, auditLogger, pool };
}
