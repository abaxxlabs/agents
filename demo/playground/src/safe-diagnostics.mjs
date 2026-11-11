export function safeErrorDetails(error) {
  const type = error instanceof AggregateError
    ? 'AggregateError'
    : error instanceof Error && /^[A-Za-z][A-Za-z0-9]*Error$/.test(error.constructor?.name ?? '')
      ? error.constructor.name
      : 'Error';
  const code = typeof error?.code === 'string' && /^[A-Z0-9]{5}$/.test(error.code)
    ? error.code
    : undefined;
  return { type, ...(code ? { code } : {}) };
}

export function logSafeError(logger, level, context, error, details = {}) {
  logger[level](context, { ...details, ...safeErrorDetails(error) });
}
