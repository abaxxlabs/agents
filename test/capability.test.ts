import { describe, it, expect } from 'vitest';
import {
  createCapabilityEngine,
  CapabilityParseError,
  CapabilitySetTooLargeError,
  type CapabilityAction,
} from '#capability/index.js';
import { testVectors } from './fixtures/capability-vectors.js';

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

describe('resolveRole — canonical vectors', () => {
  for (const vec of testVectors.role) {
    it(`#${vec.id}: ${vec.description}`, () => {
      const eng = createCapabilityEngine();
      const { expected } = vec;

      if (Array.isArray(expected)) {
        expect(eng.resolveRole(vec.role, vec.roleMap)).toEqual(expected);
      } else {
        const ErrorClass =
          expected.throws === 'CapabilityParseError'
            ? CapabilityParseError
            : CapabilitySetTooLargeError;
        expect(() => eng.resolveRole(vec.role, vec.roleMap)).toThrow(ErrorClass);
      }
    });
  }
});

describe('security — denial reason must not enumerate granted capabilities', () => {
  it('denial reason names requested action but does not list caps in the set', () => {
    const eng = createCapabilityEngine();
    const result = eng.checkCapability('jira:write', 'project/PROJ', [
      { action: 'jira:read', scope: 'project/PROJ' },
      { action: 'github:push', scope: '/main' },
    ]);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('jira:write');
    expect(result.reason).not.toContain('jira:read');
    expect(result.reason).not.toContain('github:push');
  });
});
