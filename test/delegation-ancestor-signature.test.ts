import { describe, it, expect, beforeEach } from 'vitest';
import { randomUUID } from 'node:crypto';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { createJwt, decodeJwt, type JwtPayload } from '#crypto/jwt.js';
import {
  generateDidKey,
  issueCredential,
  issueDelegatedCredential,
  createSigner,
} from '#auth/index.js';
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

  it('accepts a legitimate delegated credential whose ancestor is signed by a registered issuer', async () => {
    const { human, supervisor, worker, verifier } = env;

    const parentCred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });
    const workerCred = await issueDelegatedCredential(
      supervisor.did,
      createSigner(supervisor.privateKey),
      parentCred,
      decodeJwt(parentCred).payload.jti!,
      { columns: ['patients.name', 'patients.dob'], actions: ['read'] },
      {
        targetAgent: worker.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      },
    );

    const result = await verifier.verify(workerCred, { expectedSubject: worker.did });
    expect(result.valid).toBe(true);
    expect(result.status).toBe('VALID');
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

  it('treats an ancestor signed with a key other than its did:dht identity key as a signature failure', async () => {
    const { supervisor, worker, verifier } = env;
    const owner = generateDidDht();

    const root = await rootSignedBy(generateDidKey(), owner.did, supervisor.did);
    const result = await verifier.verify(await leafOver([root.jwt], root.payload.jti!), {
      expectedSubject: worker.did,
    });
    expect(result.status).toBe('INVALID_SIGNATURE');
    expect(result.error).toMatch(/ancestor signature invalid/i);
  });

  it('resolves an unregistered did:key ancestor exactly as the direct path does', async () => {
    const { supervisor, worker, verifier } = env;
    const owner = generateDidKey();
    const root = await rootSignedBy(owner, owner.did, supervisor.did);

    const direct = await verifier.verify(root.jwt, { expectedSubject: supervisor.did });
    const delegated = await verifier.verify(await leafOver([root.jwt], root.payload.jti!), {
      expectedSubject: worker.did,
    });
    expect(direct.status).toBe('VALID');
    expect(delegated.status).toBe(direct.status);
  });

  it.each([
    ['an unsupported DID method', 'did:ion:EiAunknown123'],
    ['a did:key that is not valid base58', 'did:key:zInvalid0OIl'],
    ['a did:dht with characters outside z-base-32', 'did:dht:0l2v'],
    ['a did:dht that does not decode to 32 bytes', `did:dht:${'y'.repeat(51)}`],
    ['a did:dht alias that is not the canonical encoding', `${generateDidDht().did.slice(0, -1)}b`],
  ])(
    'reports an unresolvable ancestor (%s) with the status and message of the direct path',
    async (_label, issuerDid) => {
      const { supervisor, worker, verifier } = env;
      const root = await rootSignedBy(generateDidKey(), issuerDid, supervisor.did);

      const direct = await verifier.verify(root.jwt, { expectedSubject: supervisor.did });
      const delegated = await verifier.verify(await leafOver([root.jwt], root.payload.jti!), {
        expectedSubject: worker.did,
      });
      expect(direct.status).toBe('UNKNOWN_ISSUER');
      expect(delegated.status).toBe('UNKNOWN_ISSUER');
      expect(delegated.error).toBe(direct.error);
      expect(delegated.error).toContain(issuerDid);
    },
  );

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

  it('uses a registered key for an ancestor before the key its identifier commits to', async () => {
    const { supervisor, worker, verifier } = env;
    const owner = generateDidDht();
    const custodial = generateDidKey();
    verifier.registerKey(owner.did, custodial.publicKey);

    const byRegistered = await rootSignedBy(custodial, owner.did, supervisor.did);
    const accepted = await verifier.verify(
      await leafOver([byRegistered.jwt], byRegistered.payload.jti!),
      { expectedSubject: worker.did },
    );
    expect(accepted.status).toBe('VALID');

    const byIdentity = await rootSignedBy(owner, owner.did, supervisor.did);
    const refused = await verifier.verify(
      await leafOver([byIdentity.jwt], byIdentity.payload.jti!),
      { expectedSubject: worker.did },
    );
    expect(refused.status).toBe('INVALID_SIGNATURE');
  });

  it('refuses a flat chain when any entry has an unresolvable issuer, naming that issuer', async () => {
    const { human, supervisor, worker, verifier } = env;
    const good = await rootSignedBy(human, human.did, supervisor.did);
    const bad = await rootSignedBy(generateDidKey(), 'did:ion:EiAunknown123', supervisor.did);

    const result = await verifier.verify(await leafOver([good.jwt, bad.jwt], good.payload.jti!), {
      expectedSubject: worker.did,
    });
    expect(result.status).toBe('UNKNOWN_ISSUER');
    expect(result.error).toContain('did:ion:EiAunknown123');
  });

  it('walks a legacy nested chain and refuses an unresolvable issuer at its second level', async () => {
    const { human, supervisor, worker, verifier } = env;
    const bad = await rootSignedBy(generateDidKey(), 'did:ion:EiAunknown123', human.did);
    const middlePayload: JwtPayload = {
      ...rootCredentialPayload({
        issuerDid: human.did,
        subjectDid: supervisor.did,
        columns: ['patients.name'],
      }),
      delegationChain: [bad.jwt],
    };
    const middle = await createJwt(middlePayload, human.privateKey);

    const result = await verifier.verify(await leafOver([middle], middlePayload.jti!), {
      expectedSubject: worker.did,
    });
    expect(result.status).toBe('UNKNOWN_ISSUER');
    expect(result.error).toContain('did:ion:EiAunknown123');
  });

  it('verifies a flat chain of ten ancestors from unregistered self-certifying issuers', async () => {
    const { supervisor, worker, verifier } = env;
    const roots = await Promise.all(
      Array.from({ length: 10 }, () => {
        const owner = generateDidKey();
        return rootSignedBy(owner, owner.did, supervisor.did);
      }),
    );

    const result = await verifier.verify(
      await leafOver(
        roots.map((r) => r.jwt),
        roots[0].payload.jti!,
      ),
      { expectedSubject: worker.did },
    );
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
