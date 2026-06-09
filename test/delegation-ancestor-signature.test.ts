import { describe, it, expect, beforeEach } from 'vitest';
import { randomUUID } from 'node:crypto';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import {
  createJwt,
  decodeJwt,
  type JwtPayload,
} from '#crypto/jwt.js';
import {
  generateDidKey,
  issueCredential,
  issueDelegatedCredential,
  createSigner,
} from '#auth/index.js';

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

  it('rejects a leaf whose ancestor issuer is not registered with the verifier', async () => {
    const { worker, verifier } = env;
    const attacker = generateDidKey();

    const forgedRootPayload = rootCredentialPayload({
      issuerDid: attacker.did,
      subjectDid: worker.did,
      columns: ['patients.ssn', 'patients.diagnosis'],
    });
    const forgedRoot = await createJwt(forgedRootPayload, attacker.privateKey);

    const leaf = await createJwt(
      delegatedLeafPayload({
        issuerDid: worker.did,
        subjectDid: worker.did,
        ancestorJwt: forgedRoot,
        columns: ['patients.ssn'],
        ancestorJti: forgedRootPayload.jti!,
      }),
      worker.privateKey,
    );

    const result = await verifier.verify(leaf, { expectedSubject: worker.did });
    expect(result.valid).toBe(false);
    expect(result.status).toBe('UNKNOWN_ISSUER');
    expect(result.error).toMatch(/ancestor issuer not registered/i);
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
    const tamperedPayloadB64 = Buffer.from(JSON.stringify(tamperedRootPayload)).toString('base64url');
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
