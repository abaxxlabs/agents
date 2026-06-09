import type { VcVerifier } from '#identity/index.js';
import type { VerificationResult } from '#types/index.js';

export function createMockVcVerifier(result: VerificationResult): VcVerifier {
  return {
    verify: async (): Promise<VerificationResult> => result,
  } as unknown as VcVerifier;
}
