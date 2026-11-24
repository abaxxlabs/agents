import { describe, expect, it } from 'vitest';
import { resolveMcpHostOptionsFromEnv } from '#mcp/host-env.js';

const FULL_ENV = {
  AGENTS_KEYSTORE_PATH: '/var/lib/agents/keystore.json',
  AGENTS_TRUSTED_SERVERS: ' did:key:z6MkPeerA , did:key:z6MkPeerB,,did:key:z6MkPeerA ',
};

describe('resolveMcpHostOptionsFromEnv', () => {
  it('maps every variable, trimming and de-duplicating the lists', () => {
    expect(resolveMcpHostOptionsFromEnv(FULL_ENV)).toEqual({
      keystorePath: '/var/lib/agents/keystore.json',
      trustedServers: ['did:key:z6MkPeerA', 'did:key:z6MkPeerB'],
    });
  });

  it('treats blank values as unset', () => {
    expect(
      resolveMcpHostOptionsFromEnv({
        AGENTS_KEYSTORE_PATH: '  ',
        AGENTS_TRUSTED_SERVERS: ' , ,',
      }),
    ).toEqual({});
  });
});
