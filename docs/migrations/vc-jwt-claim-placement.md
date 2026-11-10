# Migration: delegation claims moved inside the credential

**Audience:** applications that decode issued credentials and read their claims directly. Applications that only call `issueCredential`, `issueDelegatedCredential`, or the verifier require no changes.

The delegation ceiling and ancestor chain were previously stored at the JWT top level, alongside `iss`, `sub`, and `exp`. In VC-JWT, the verifiable credential is the object under `vc`; claims outside that object describe the token rather than the credential. Both delegation claims are now stored within `vc`, in the locations defined by the specification.

---

## Summary {#tldr}

Applications that read `payload.maxDepth` or `payload.delegationChain` directly from a decoded credential must update those access paths. Both top-level fields return `undefined` on newly issued credentials.

Issuance options are unchanged, and previously issued credentials remain verifiable.

---

## 1. Updated claim locations {#1-where-the-claims-live-now}

```jsonc
// before
{
  "iss": "did:key:…",
  "sub": "did:key:…",
  "maxDepth": 2,
  "delegationChain": ["eyJhbGciOi…"],
  "vc": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "DelegatedAgentScopeCredential"],
    "credentialSubject": {
      "id": "did:key:…",
      "scope": { "columns": ["…"], "actions": ["read"] },
      "owner": "did:key:…",
      "delegated": false
    }
  }
}

// after
{
  "iss": "did:key:…",
  "sub": "did:key:…",
  "vc": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "DelegatedAgentScopeCredential"],
    "credentialSubject": {
      "id": "did:key:…",
      "scope": { "columns": ["…"], "actions": ["read"] }
    },
    "termsOfUse": [{ "type": "DelegationPolicy", "maxDepth": 2 }],
    "evidence": [{ "type": "DelegationChain", "credentials": ["eyJhbGciOi…"] }]
  }
}
```

`termsOfUse` and `evidence` are both defined by the W3C credentials context. `termsOfUse` carries constraints the issuer places on use, which is what a delegation ceiling is; `evidence` carries provenance, which is what an ancestor chain is.

## 2. Removed fields {#2-two-fields-are-gone}

`credentialSubject.owner` duplicated `iss` in every issuance path and was not used during verification. Ownership is checked by comparing the credential's issuer against the agent's registered owner.

`credentialSubject.delegated` was always `false`, including on delegated credentials, where it contradicted the `type` array declaring `DelegatedAgentScopeCredential`. This field was also unused during verification.

## 3. If you read the claims yourself

```ts
// before
const { payload } = decodeJwt(credential);
const ceiling = payload.maxDepth;
const chain = payload.delegationChain;

// after
const { payload } = decodeJwt(credential);
const findTyped = (value: unknown, expected: string) =>
  ((Array.isArray(value) ? value : [value]) as unknown[]).find(
    (entry): entry is Record<string, unknown> => {
      if (!entry || typeof entry !== 'object') return false;
      const type = (entry as { type?: unknown }).type;
      return Array.isArray(type) ? type.includes(expected) : type === expected;
    },
  );
const ceiling = findTyped(payload.vc?.termsOfUse, 'DelegationPolicy')?.maxDepth;
const chain = findTyped(payload.vc?.evidence, 'DelegationChain')?.credentials;
```

Both `type` values may be a string or an array of strings, as VC sub-objects are allowed to carry several types. The reader above accepts both and reads a single object or an array of entries.

## 4. Compatibility

Credentials issued before this release remain verifiable. The verifier checks the current claim location first and falls back to the legacy top-level claim, supporting both credential formats without a migration.

The fallback is transitional. It will be removed once no unexpired credential can still carry the legacy shape, which is bounded by the longest credential lifetime you issue. If you decode credentials yourself, move to the reader above before then.

## 5. No change at issuance

```ts
// unchanged
await scope.issueCredential({
  agent: agentDid,
  columns: ['patients.name'],
  actions: ['read'],
  expiresIn: '4h',
  maxDepth: 2,
});
```

The option name, meaning, and default are unchanged. Only the location of the value within the issued JWT has changed.
