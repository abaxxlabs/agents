import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type {
  McpHostAttachment,
  McpHostExtension,
  McpHostExtensionContext,
} from '#mcp/extension.js';
import { attachHostExtensions, createHostShutdown, loadHostIdentity } from '#mcp/host-boot.js';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'mcp-host-boot-'));
});

afterEach(() => {
  vi.unstubAllEnvs();
  rmSync(dir, { recursive: true, force: true });
});

function logger() {
  return { warn: vi.fn(), error: vi.fn() };
}

function extension(name: string, attachment: McpHostAttachment | null): McpHostExtension {
  return { name, attach: vi.fn(async () => attachment) };
}

const context = { log: vi.fn() } as unknown as McpHostExtensionContext;

describe('loadHostIdentity', () => {
  it('keeps the server DID across restarts and seeds the trusted servers', async () => {
    const keystorePath = join(dir, 'keystore.json');
    const load = (trustedServers?: string[]) =>
      loadHostIdentity({ keystorePath, trustedServers, devMode: true, logger: logger() });
    const first = await load(['did:key:z6MkPeer']);
    const second = await load();

    expect(existsSync(keystorePath)).toBe(true);
    expect(first?.serverIdentity.did).toMatch(/^did:key:z6Mk/);
    expect(second?.serverIdentity.did).toBe(first?.serverIdentity.did);
    expect(first?.trustAnchors.isTrusted(first.serverIdentity.did)).toBe(true);
    expect(first?.trustAnchors.isTrusted('did:key:z6MkPeer')).toBe(true);
    expect(first?.trustAnchors.list()).toHaveLength(2);
  });
});

describe('attachHostExtensions', () => {
  it('lets an attach failure propagate', async () => {
    const failing: McpHostExtension = {
      name: 'broken',
      attach: vi.fn(async () => {
        throw new Error('missing setting');
      }),
    };
    const after = extension('after', {});

    await expect(attachHostExtensions([failing, after], context)).rejects.toThrow(
      'missing setting',
    );
    expect(after.attach).not.toHaveBeenCalled();
  });
});

describe('createHostShutdown', () => {
  it('runs the steps once, newest first, then exits with 0', async () => {
    const calls: string[] = [];
    const exit = vi.fn();
    const shutdown = createHostShutdown({ log: vi.fn(), exit });
    shutdown.defer(() => calls.push('scope'));
    shutdown.defer(async () => {
      calls.push('extension');
    });
    shutdown.defer(() => calls.push('transport'));

    await Promise.all([shutdown.run(), shutdown.run()]);
    await shutdown.run();

    expect(calls).toEqual(['transport', 'extension', 'scope']);
    expect(exit).toHaveBeenCalledOnce();
    expect(exit).toHaveBeenCalledWith(0);
  });
});
