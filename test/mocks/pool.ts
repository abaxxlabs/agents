import { vi, type Mock } from 'vitest';
import type { Pool } from 'pg';

export interface MockClient {
  query: Mock;
  release: Mock;
}

export function createMockClient(
  queryImpl?: (sql: string, params?: unknown[]) => unknown,
): MockClient {
  return {
    query: vi.fn().mockImplementation(async (sql: string, params?: unknown[]) => {
      if (queryImpl) return queryImpl(sql, params);
      return { rows: [], rowCount: 0 };
    }),
    release: vi.fn(),
  };
}

export function createMockPool(options: {
  queryImpl?: (sql: string, params?: unknown[]) => unknown;
  client?: MockClient;
} = {}): Pool {
  return {
    query: vi.fn().mockImplementation(async (sql: string, params?: unknown[]) => {
      if (options.queryImpl) return options.queryImpl(sql, params);
      return { rows: [], rowCount: 0 };
    }),
    connect: options.client ? vi.fn().mockResolvedValue(options.client) : vi.fn(),
  } as unknown as Pool;
}

export function createMockPoolThrowing(error: unknown): Pool {
  return {
    query: vi.fn(async () => {
      throw error;
    }),
    connect: vi.fn(),
  } as unknown as Pool;
}
