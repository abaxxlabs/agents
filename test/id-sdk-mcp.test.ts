import { describe, expect, it } from 'vitest';
import { createIdSdkMcpAdapter } from '#mcp/id-sdk.js';

describe('createIdSdkMcpAdapter', () => {
  it('maps VC issuance calls onto id-sdk-mcp tools', async () => {
    const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
    const sdk = createIdSdkMcpAdapter(async (name, args) => {
      calls.push({ name, args });
      if (name === 'vc_create_credential') return { credential: true };
      if (name === 'vc_get_signer_options') {
        return {
          issuerDid: args.issuerDid,
          subjectDid: args.subjectDid,
          signer: 'server-side-only',
        };
      }
      if (name === 'vc_sign_credential') return 'signed.jwt';
      return null;
    });

    const vc = await sdk.vc.createCredential(
      'did:dht:issuer',
      'did:key:subject',
      { scope: { columns: ['desk'], actions: ['read'] } },
      'AgentScopeCredential',
    );
    const signerOptions = await sdk.vc.getSignerOptions('did:dht:issuer', 'did:key:subject');
    const jwt = await sdk.vc.signCredential(vc, {
      ...signerOptions,
      signer: async () => new Uint8Array(),
      expirationDate: '2026-05-01T00:00:00.000Z',
    });

    expect(jwt).toBe('signed.jwt');
    expect(calls).toEqual([
      {
        name: 'vc_create_credential',
        args: {
          issuer: 'did:dht:issuer',
          subject: 'did:key:subject',
          data: { scope: { columns: ['desk'], actions: ['read'] } },
          type: 'AgentScopeCredential',
        },
      },
      {
        name: 'vc_get_signer_options',
        args: {
          issuerDid: 'did:dht:issuer',
          subjectDid: 'did:key:subject',
        },
      },
      {
        name: 'vc_sign_credential',
        args: {
          vc: { credential: true },
          signOptions: {
            issuerDid: 'did:dht:issuer',
            subjectDid: 'did:key:subject',
            expirationDate: '2026-05-01T00:00:00.000Z',
          },
        },
      },
    ]);
  });

  it('sends both issuer and subject DIDs to vc_get_signer_options', async () => {
    const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
    const sdk = createIdSdkMcpAdapter(async (name, args) => {
      calls.push({ name, args });
      return { issuerDid: args.issuerDid, subjectDid: args.subjectDid };
    });

    await sdk.vc.getSignerOptions('did:dht:issuer', 'did:dht:subject');

    expect(calls).toEqual([
      {
        name: 'vc_get_signer_options',
        args: { issuerDid: 'did:dht:issuer', subjectDid: 'did:dht:subject' },
      },
    ]);
  });

  it('maps verifier and revocation calls onto id-sdk-mcp tools', async () => {
    const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
    const sdk = createIdSdkMcpAdapter(async (name, args) => {
      calls.push({ name, args });
      if (name === 'did_resolve') return { didDocument: { id: args.didUrl } };
      if (name === 'vc_verify_jwt') return true;
      if (name === 'vc_check_credential_status') return { revoked: false, suspended: false };
      if (name === 'vc_revoke_credential') return { ok: true };
      return null;
    });

    await expect(sdk.did.resolve('did:dht:issuer')).resolves.toEqual({
      didDocument: { id: 'did:dht:issuer' },
    });
    await expect(sdk.vc.verifyJWT('header.payload.signature')).resolves.toBe(true);
    await expect(sdk.vc.checkCredentialStatus({ credentialId: 'vc-1' })).resolves.toEqual({
      revoked: false,
      suspended: false,
    });
    await expect(
      sdk.vc.revokeCredential({
        credentialId: 'vc-1',
        signOptions: { signer: async () => new Uint8Array(), issuerDid: 'did:dht:issuer' },
      }),
    ).resolves.toEqual({ ok: true });

    expect(calls).toEqual([
      { name: 'did_resolve', args: { didUrl: 'did:dht:issuer' } },
      { name: 'vc_verify_jwt', args: { jwt: 'header.payload.signature' } },
      {
        name: 'vc_check_credential_status',
        args: { options: { credentialId: 'vc-1' } },
      },
      {
        name: 'vc_revoke_credential',
        args: {
          options: {
            credentialId: 'vc-1',
            signOptions: { issuerDid: 'did:dht:issuer' },
          },
        },
      },
    ]);
  });
});
