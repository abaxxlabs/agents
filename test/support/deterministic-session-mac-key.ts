import { hkdfSync } from 'node:crypto';

const TEST_IKM = Buffer.from('test-ikm-do-not-use-in-prod', 'utf8');

export function deterministicSessionMacKey(seed = 'default'): Buffer {
  return Buffer.from(hkdfSync('sha256', TEST_IKM, Buffer.from(seed), Buffer.alloc(0), 32));
}
