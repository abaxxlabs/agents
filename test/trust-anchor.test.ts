import { describe, it, expect } from 'vitest';
import { LocalTrustAnchorStore } from '#discovery/trust-anchor.js';

const OWN_DID = 'did:key:z6MkownServerAbc123';

describe('LocalTrustAnchorStore', () => {
  it('own DID is trusted immediately after construction', () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    expect(store.isTrusted(OWN_DID)).toBe(true);
  });

  it('throws when attempting to remove own server DID', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await expect(store.removeTrustedServer(OWN_DID)).rejects.toThrow(
      /cannot remove own server DID/,
    );
  });
});
