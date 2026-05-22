import { describe, it, expect } from 'vitest';
import {
  CapabilityEngine,
  createCapabilityEngine,
  CapabilityParseError,
  CapabilitySetTooLargeError,
  type CapabilityAction,
} from '../src/capability/index.js';
import { testVectors } from './fixtures/capability-vectors.js';

// ─── checkCapability Vectors ─────────────────────────────────────

describe('checkCapability — canonical vectors', () => {
  for (const vec of testVectors.check) {
    it(`#${vec.id}: ${vec.description}`, () => {
      const eng = createCapabilityEngine();
      const { expected } = vec;
      // Vectors 28/29 intentionally pass non-string values to test runtime type guards.
      const action = vec.action as unknown as CapabilityAction;

      if ('throws' in expected) {
        const ErrorClass =
          expected.throws === 'CapabilityParseError'
            ? CapabilityParseError
            : CapabilitySetTooLargeError;
        expect(() => eng.checkCapability(action, vec.scope, vec.capabilitySet)).toThrow(ErrorClass);
      } else if (expected.allowed) {
        const result = eng.checkCapability(action, vec.scope, vec.capabilitySet);
        expect(result.allowed).toBe(true);
        expect(result.matchedCapability).toBeDefined();
        expect(result.matchedCapability?.action).toBe(expected.matchedAction);
        expect(result.reason.length).toBeGreaterThan(0);
      } else {
        const result = eng.checkCapability(action, vec.scope, vec.capabilitySet);
        expect(result.allowed).toBe(false);
        expect(result.matchedCapability).toBeUndefined();
        expect(result.reason.length).toBeGreaterThan(0);
      }
    });
  }
});

// ─── isSubsetOf Vectors ──────────────────────────────────────────

describe('isSubsetOf — canonical vectors', () => {
  for (const vec of testVectors.subset) {
    it(`#${vec.id}: ${vec.description}`, () => {
      const eng = createCapabilityEngine();
      const { expected } = vec;

      if (typeof expected === 'boolean') {
        expect(eng.isSubsetOf(vec.childSet, vec.parentSet)).toBe(expected);
      } else {
        expect(() => eng.isSubsetOf(vec.childSet, vec.parentSet)).toThrow(
          CapabilitySetTooLargeError,
        );
      }
    });
  }
});

// ─── resolveRole Vectors ─────────────────────────────────────────

describe('resolveRole — canonical vectors', () => {
  for (const vec of testVectors.role) {
    it(`#${vec.id}: ${vec.description}`, () => {
      const eng = createCapabilityEngine();
      const { expected } = vec;

      if (Array.isArray(expected)) {
        // expected: CapabilitySet
        expect(eng.resolveRole(vec.role, vec.roleMap)).toEqual(expected);
      } else {
        // expected: { throws: 'CapabilityParseError' | 'CapabilitySetTooLargeError' }
        const ErrorClass =
          expected.throws === 'CapabilityParseError'
            ? CapabilityParseError
            : CapabilitySetTooLargeError;
        expect(() => eng.resolveRole(vec.role, vec.roleMap)).toThrow(ErrorClass);
      }
    });
  }
});

// ─── Factory ─────────────────────────────────────────────────────

describe('createCapabilityEngine — factory', () => {
  it('returns a CapabilityEngine instance', () => {
    const eng = createCapabilityEngine();
    expect(eng).toBeInstanceOf(CapabilityEngine);
  });

  it('each call returns an independent instance', () => {
    const a = createCapabilityEngine();
    const b = createCapabilityEngine();
    expect(a).not.toBe(b);
  });

  it('instance has all three public methods', () => {
    const eng = createCapabilityEngine();
    expect(typeof eng.checkCapability).toBe('function');
    expect(typeof eng.isSubsetOf).toBe('function');
    expect(typeof eng.resolveRole).toBe('function');
  });
});

// ─── Security Regressions ─────────────────────────────────────────

describe('security — denial reason must not enumerate granted capabilities', () => {
  it('denial reason names requested action but does not list caps in the set', () => {
    const eng = createCapabilityEngine();
    const result = eng.checkCapability('jira:write', 'project/PROJ', [
      { action: 'jira:read', scope: 'project/PROJ' },
      { action: 'github:push', scope: '/main' },
    ]);
    expect(result.allowed).toBe(false);
    // Must mention what was requested (so the caller can log it)
    expect(result.reason).toContain('jira:write');
    // Must NOT enumerate what IS granted
    expect(result.reason).not.toContain('jira:read');
    expect(result.reason).not.toContain('github:push');
  });

  it('denial reason for empty set does not enumerate an empty list', () => {
    const eng = createCapabilityEngine();
    const result = eng.checkCapability('jira:read', undefined, []);
    expect(result.allowed).toBe(false);
    // Reason should reference the action and indicate the set is empty
    expect(result.reason).toContain('jira:read');
    // Must not include array syntax or an explicit "[]"
    expect(result.reason).not.toContain('[]');
  });

  it('denial reason with undefined scope does not expose the scope as undefined or null', () => {
    const eng = createCapabilityEngine();
    const result = eng.checkCapability('vc:verify', undefined, [{ action: 'vc:issue' }]);
    expect(result.allowed).toBe(false);
    expect(result.reason).not.toContain('undefined');
    expect(result.reason).not.toContain('null');
  });
});

describe('security — resolveRole error must not enumerate valid role names', () => {
  it('error names the unknown role but does not list valid roles', () => {
    const eng = createCapabilityEngine();
    const roleMap = {
      viewer: [{ action: 'jira:read' }],
      editor: [{ action: 'jira:read' }, { action: 'jira:write' }],
    };
    let caughtError: unknown;
    try {
      eng.resolveRole('superadmin', roleMap);
    } catch (e) {
      caughtError = e;
    }
    expect(caughtError).toBeInstanceOf(CapabilityParseError);
    const msg = (caughtError as CapabilityParseError).message;
    // Must name what was requested (helpful for debugging)
    expect(msg).toContain('superadmin');
    // Must NOT enumerate what IS available
    expect(msg).not.toContain('viewer');
    expect(msg).not.toContain('editor');
  });
});

// ─── Integration ─────────────────────────────────────────────────

describe('integration — resolveRole → checkCapability', () => {
  it('resolved role caps can be passed directly into checkCapability', () => {
    const eng = createCapabilityEngine();
    const roleMap = {
      editor: [
        { action: 'jira:read', scope: 'project/PROJ' },
        { action: 'jira:write', scope: 'project/PROJ' },
      ],
    };
    const caps = eng.resolveRole('editor', roleMap);

    const readResult = eng.checkCapability('jira:read', 'project/PROJ', caps);
    expect(readResult.allowed).toBe(true);
    expect(readResult.matchedCapability?.action).toBe('jira:read');

    const writeResult = eng.checkCapability('jira:write', 'project/PROJ', caps);
    expect(writeResult.allowed).toBe(true);

    const adminResult = eng.checkCapability('jira:admin', 'project/PROJ', caps);
    expect(adminResult.allowed).toBe(false);
  });

  it('UPPERCASE action in resolved caps is normalized and matches at checkCapability', () => {
    const eng = createCapabilityEngine();
    const roleMap = {
      viewer: [{ action: 'jira:read' }],
    };
    const caps = eng.resolveRole('viewer', roleMap);
    const result = eng.checkCapability('JIRA:READ' as CapabilityAction, undefined, caps);
    expect(result.allowed).toBe(true);
  });

  it('isSubsetOf validates that a resolved role is within a parent grant', () => {
    const eng = createCapabilityEngine();
    const roleMap = {
      viewer: [{ action: 'jira:read' }],
    };
    const viewerCaps = eng.resolveRole('viewer', roleMap);
    const parentCaps = [{ action: 'jira:read' }, { action: 'jira:write' }];

    expect(eng.isSubsetOf(viewerCaps, parentCaps)).toBe(true);
    expect(eng.isSubsetOf(parentCaps, viewerCaps)).toBe(false);
  });
});
