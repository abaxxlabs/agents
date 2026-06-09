import { vi } from 'vitest';
import type { AuditRecord } from '#types/index.js';
import type { AuditStore } from '#storage/types.js';

export function createMockAuditStore(
  options: { failOnAppend?: boolean; records?: AuditRecord[] } = {},
): AuditStore {
  return {
    append: vi.fn().mockImplementation(async () => {
      if (options.failOnAppend) throw new Error('disk full');
    }),
    loadLastRecord: vi.fn().mockResolvedValue(null),
    loadLastRecordLocked: vi.fn().mockResolvedValue(null),
    query: vi.fn().mockResolvedValue(options.records ?? []),
    count: vi.fn().mockResolvedValue(0),
  };
}
