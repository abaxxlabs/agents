import { describe, it, expect, vi } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startMcpServer } from '#mcp/index.js';
import { AgentScope } from '#sql/index.js';

describe('MCP Server', () => {
  it('injects the persistent DID and public key when only an extension needs host identity', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-host-boot-'));
    const halted = new Error('halted before the database');
    const create = vi.spyOn(AgentScope, 'create').mockRejectedValue(halted);
    vi.stubEnv('HOME', dir);
    vi.stubEnv('NODE_ENV', 'test');
    vi.stubEnv('AGENTS_MASTER_KEY', 'ab'.repeat(32));
    const attach = vi.fn(async () => null);
    const options = {
      db: 'postgresql://localhost/test',
      logger: { warn: vi.fn(), error: vi.fn() },
      extensions: [{ name: 'needs-identity', needsHostIdentity: true, attach }],
    };

    try {
      await expect(startMcpServer(options)).rejects.toThrow(halted);
      const serverIdentity = create.mock.calls[0][1].serverIdentity;
      expect(serverIdentity?.did).toMatch(/^did:key:z6Mk/);
      expect(serverIdentity?.publicKey).toHaveLength(32);
      expect(existsSync(join(dir, '.agents', 'keystore.json'))).toBe(true);

      await expect(startMcpServer(options)).rejects.toThrow(halted);
      expect(create).toHaveBeenCalledTimes(2);
      expect(create.mock.calls[1][1].serverIdentity).toEqual(serverIdentity);
      expect(attach).not.toHaveBeenCalled();
    } finally {
      create.mockRestore();
      vi.unstubAllEnvs();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  describe('HTTP bearer auth boot', () => {
    const tlsCert = 'unused-test-cert.pem';
    const tlsKey = 'unused-test-key.pem';

    it('exits in production with HTTP TLS and no bearer auth before DB work', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {
        throw new Error('process.exit called');
      }) as never);
      const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      try {
        await startMcpServer({
          db: 'postgresql://localhost/test',
          transport: 'http',
          port: 9999,
          tlsCert,
          tlsKey,
          singleInstance: true,
        });
      } catch (e) {
        expect((e as Error).message).toBe('process.exit called');
      }

      expect(exitSpy).toHaveBeenCalledWith(1);
      const stderr = errSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(stderr).toMatch(/bearerAuth|getValidTokens/);

      errSpy.mockRestore();
      exitSpy.mockRestore();
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('TLS enforcement', () => {
    it('HTTP without --insecure exits with error in production', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {
        throw new Error('process.exit called');
      }) as never);

      try {
        await startMcpServer({
          db: 'postgresql://localhost/test',
          transport: 'http',
          port: 9999,
          insecure: true,
          singleInstance: true,
        });
      } catch (e) {
        const err = e as Error;
        expect(err.message).toBe('process.exit called');
      }

      expect(exitSpy).toHaveBeenCalledWith(1);
      exitSpy.mockRestore();
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Production storage gate', () => {
    it('refuses to start in production with default storage and no --single-instance', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {
        throw new Error('process.exit called');
      }) as never);

      try {
        await startMcpServer({
          db: 'postgresql://localhost/test',
        });
      } catch (e) {
        const err = e as Error;
        expect(err.message).toBe('process.exit called');
      }

      expect(exitSpy).toHaveBeenCalledWith(1);
      const refusalCall = errorSpy.mock.calls.find((c) =>
        String(c[0]).includes('Refusing to start: NODE_ENV=production with default storage'),
      );
      expect(refusalCall).toBeDefined();
      expect(String(refusalCall![0])).toContain('--single-instance');
      expect(String(refusalCall![0])).toContain('StorageBackend');

      exitSpy.mockRestore();
      errorSpy.mockRestore();
      process.env.NODE_ENV = originalEnv;
    });
  });
});
