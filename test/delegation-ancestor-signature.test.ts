import { describe, it, expect, beforeEach } from 'vitest';
import { randomUUID } from 'node:crypto';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { createJwt, type JwtPayload } from '#crypto/jwt.js';
import { generateDidKey } from '#auth/index.js';
import { zbase32Encode } from '#crypto/zbase32.js';
import { createMockSdk } from './mocks/index.js';

function setup() {
  const human = generateDidKey();
  const supervisor = generateDidKey();
  const worker = generateDidKey();

  const store = new InMemoryRevocationStore();
  const verifier = new VcVerifier({ revocationStore: store });
  verifier.registerKey(human.did, human.publicKey);
  verifier.registerKey(supervisor.did, supervisor.publicKey);
  verifier.registerKey(worker.did, worker.publicKey);

  return { human, supervisor, worker, store, verifier };
}

function generateDidDht(): ReturnType<typeof generateDidKey> {
  const key = generateDidKey();
  return { ...key, did: `did:dht:${zbase32Encode(key.publicKey)}` };
}

function rootCredentialPayload(opts: {
  issuerDid: string;
  subjectDid: string;
  columns: string[];
  jti?: string;
}): JwtPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: opts.issuerDid,
    sub: opts.subjectDid,
    jti: opts.jti ?? randomUUID(),
    iat: now,
    exp: now + 3600,
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'AgentScopeCredential'],
      credentialSubject: {
        id: opts.subjectDid,
        scope: { columns: opts.columns, actions: ['read'] },
        owner: opts.issuerDid,
      },
    },
  };
}

function delegatedLeafPayload(opts: {
  issuerDid: string;
  subjectDid: string;
  ancestorJwt: string;
  columns: string[];
  ancestorJti: string;
}): JwtPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: opts.issuerDid,
    sub: opts.subjectDid,
    jti: randomUUID(),
    iat: now,
    exp: now + 3600,
    delegationChain: [opts.ancestorJwt],
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'DelegatedAgentScopeCredential'],
      credentialSubject: {
        id: opts.subjectDid,
        scope: { columns: opts.columns, actions: ['read'] },
        grantedBy: opts.issuerDid,
        grantedTo: opts.subjectDid,
        delegatedGrantId: opts.ancestorJti,
        delegated: false,
      },
    },
  };
}

describe('Delegation chain ancestor signature verification', () => {
  let env: ReturnType<typeof setup>;
  beforeEach(() => {
    env = setup();
  });

  it('accepts a leaf whose ancestor issuer is a self-certifying DID never registered with the verifier', async () => {
    const { supervisor, worker, verifier } = env;
    const owner = generateDidKey();

    const rootPayload = rootCredentialPayload({
      issuerDid: owner.did,
      subjectDid: supervisor.did,
      columns: ['patients.name'],
    });
    const root = await createJwt(rootPayload, owner.privateKey);
    const leaf = await createJwt(
      delegatedLeafPayload({
        issuerDid: supervisor.did,
        subjectDid: worker.did,
        ancestorJwt: root,
        columns: ['patients.name'],
        ancestorJti: rootPayload.jti!,
      }),
      supervisor.privateKey,
    );

    const result = await verifier.verify(leaf, { expectedSubject: worker.did });
    expect(result.status).toBe('VALID');
  });

  it('rejects a leaf whose ancestor JWT claims a registered DID but is signed by a different key', async () => {
    const { supervisor, worker, verifier } = env;
    const attacker = generateDidKey();

    const impersonatedRootPayload = rootCredentialPayload({
      issuerDid: supervisor.did,
      subjectDid: worker.did,
      columns: ['patients.ssn', 'patients.diagnosis'],
    });
    const impersonatedRoot = await createJwt(impersonatedRootPayload, attacker.privateKey);

    const leaf = await createJwt(
      delegatedLeafPayload({
        issuerDid: worker.did,
        subjectDid: worker.did,
        ancestorJwt: impersonatedRoot,
        columns: ['patients.ssn'],
        ancestorJti: impersonatedRootPayload.jti!,
      }),
      worker.privateKey,
    );

    const result = await verifier.verify(leaf, { expectedSubject: worker.did });
    expect(result.valid).toBe(false);
    expect(result.status).toBe('INVALID_SIGNATURE');
    expect(result.error).toMatch(/ancestor signature invalid/i);
  });

  it('rejects a leaf whose ancestor JWT has a tampered payload but the original signature', async () => {
    const { human, supervisor, worker, verifier } = env;

    const legitRootPayload = rootCredentialPayload({
      issuerDid: human.did,
      subjectDid: supervisor.did,
      columns: ['patients.name'],
    });
    const legitRoot = await createJwt(legitRootPayload, human.privateKey);
    const [legitHeader, , legitSig] = legitRoot.split('.');

    const tamperedRootPayload: JwtPayload = {
      ...legitRootPayload,
      vc: {
        ...legitRootPayload.vc!,
        credentialSubject: {
          ...legitRootPayload.vc!.credentialSubject!,
          scope: { columns: ['patients.ssn', 'patients.diagnosis'], actions: ['read'] },
        },
      },
    };
    const tamperedPayloadB64 = Buffer.from(JSON.stringify(tamperedRootPayload)).toString(
      'base64url',
    );
    const tamperedRoot = `${legitHeader}.${tamperedPayloadB64}.${legitSig}`;

    const leaf = await createJwt(
      delegatedLeafPayload({
        issuerDid: supervisor.did,
        subjectDid: worker.did,
        ancestorJwt: tamperedRoot,
        columns: ['patients.ssn'],
        ancestorJti: legitRootPayload.jti!,
      }),
      supervisor.privateKey,
    );

    const result = await verifier.verify(leaf, { expectedSubject: worker.did });
    expect(result.valid).toBe(false);
    expect(result.status).toBe('INVALID_SIGNATURE');
    expect(result.error).toMatch(/ancestor signature invalid/i);
  });

  it('rejects a leaf whose ancestor JWT is missing the issuer claim', async () => {
    const { supervisor, worker, verifier } = env;

    const now = Math.floor(Date.now() / 1000);
    const issuerlessRootPayload: JwtPayload = {
      sub: supervisor.did,
      jti: randomUUID(),
      iat: now,
      exp: now + 3600,
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'AgentScopeCredential'],
        credentialSubject: {
          id: supervisor.did,
          scope: { columns: ['patients.name'], actions: ['read'] },
        },
      },
    };
    const issuerlessRoot = await createJwt(issuerlessRootPayload, supervisor.privateKey);

    const leaf = await createJwt(
      delegatedLeafPayload({
        issuerDid: worker.did,
        subjectDid: worker.did,
        ancestorJwt: issuerlessRoot,
        columns: ['patients.name'],
        ancestorJti: issuerlessRootPayload.jti!,
      }),
      worker.privateKey,
    );

    const result = await verifier.verify(leaf, { expectedSubject: worker.did });
    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toMatch(/ancestor missing issuer/i);
  });
});

const SECP256K1_VM = {
  id: '#1',
  publicKeyJwk: { crv: 'secp256k1', kty: 'EC', x: 'cfsr6o8Pi_yQdDISlNNEXwYi-CnDK8n4qRE-e4HBxKY' },
};

function ed25519Vm(publicKey: Uint8Array) {
  return {
    id: '#0',
    publicKeyJwk: { crv: 'Ed25519', kty: 'OKP', x: Buffer.from(publicKey).toString('base64url') },
  };
}

function verifierWithResolver(resolve: () => Promise<unknown>): VcVerifier {
  const verifier = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
  verifier.setSdk(createMockSdk({ did: { resolve } } as never));
  return verifier;
}

describe('Delegation chain ancestor key resolution', () => {
  let env: ReturnType<typeof setup>;
  beforeEach(() => {
    env = setup();
  });

  async function rootSignedBy(
    signer: { privateKey: Uint8Array },
    issuerDid: string,
    subjectDid: string,
  ): Promise<{ payload: JwtPayload; jwt: string }> {
    const payload = rootCredentialPayload({ issuerDid, subjectDid, columns: ['patients.name'] });
    return { payload, jwt: await createJwt(payload, signer.privateKey) };
  }

  function leafOver(ancestors: string[], ancestorJti: string): Promise<string> {
    const { supervisor, worker } = env;
    const payload = delegatedLeafPayload({
      issuerDid: supervisor.did,
      subjectDid: worker.did,
      ancestorJwt: ancestors[0],
      columns: ['patients.name'],
      ancestorJti,
    });
    return createJwt({ ...payload, delegationChain: ancestors }, supervisor.privateKey);
  }

  it('verifies a did:dht ancestor offline with its identity key', async () => {
    const { supervisor, worker, verifier } = env;
    const owner = generateDidDht();
    expect(await verifier.resolvePublicKey(owner.did)).toEqual(owner.publicKey);

    const root = await rootSignedBy(owner, owner.did, supervisor.did);
    const result = await verifier.verify(await leafOver([root.jwt], root.payload.jti!), {
      expectedSubject: worker.did,
    });
    expect(result.status).toBe('VALID');
  });

  it('reports a resolver failure as UNKNOWN_ISSUER without deriving the key offline', async () => {
    const { supervisor, worker } = env;
    const owner = generateDidKey();
    const root = await rootSignedBy(owner, owner.did, supervisor.did);
    const leaf = await leafOver([root.jwt], root.payload.jti!);

    const unreachable = verifierWithResolver(async () => {
      throw new Error('relay unreachable');
    });
    const failed = await unreachable.verify(leaf, { expectedSubject: worker.did });
    expect(failed.status).toBe('UNKNOWN_ISSUER');
    expect(failed.error).toContain('relay unreachable');

    const empty = verifierWithResolver(async () => ({
      didDocument: { verificationMethod: [] },
      didResolutionMetadata: {},
    }));
    const noMethods = await empty.verify(leaf, { expectedSubject: worker.did });
    expect(noMethods.status).toBe('UNKNOWN_ISSUER');
    expect(noMethods.error).toMatch(/no verification methods/i);
  });

  it('selects the Ed25519 key of an ancestor document that lists secp256k1 first', async () => {
    const { supervisor, worker } = env;
    const owner = generateDidKey();
    const root = await rootSignedBy(owner, owner.did, supervisor.did);

    const verifier = verifierWithResolver(async () => ({
      didDocument: { verificationMethod: [SECP256K1_VM, ed25519Vm(owner.publicKey)] },
      didResolutionMetadata: {},
    }));
    const result = await verifier.verify(await leafOver([root.jwt], root.payload.jti!), {
      expectedSubject: worker.did,
    });
    expect(result.status).toBe('VALID');
  });

  it('rejects a leaf whose ancestor JWT carries a non-string issuer claim', async () => {
    const { supervisor, worker, verifier } = env;
    const payload: JwtPayload = {
      ...rootCredentialPayload({
        issuerDid: 'ignored',
        subjectDid: supervisor.did,
        columns: ['patients.name'],
      }),
      iss: 42 as unknown as string,
    };
    const root = await createJwt(payload, supervisor.privateKey);

    const result = await verifier.verify(await leafOver([root], payload.jti!), {
      expectedSubject: worker.did,
    });
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toMatch(/ancestor missing issuer/i);
  });
});
