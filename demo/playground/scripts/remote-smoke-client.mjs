/** Minimal HTTP client for the remote Playground smoke. */
const DEFAULT_TIMEOUT_MS = 30_000;
const SESSION_COOKIE = '__Host-visitorSessionId';

export class RemoteSmokeError extends Error {
  constructor(operation, reason) {
    super(`remote smoke: ${operation} failed: ${reason}`);
    this.name = 'RemoteSmokeError';
  }
}

function requestTarget(base, path, operation) {
  // A malformed internal path must never be able to move the request, and its
  // cookies, to another host.
  if (typeof path !== 'string' || !path.startsWith('/')) {
    throw new RemoteSmokeError(operation, 'path must start with /');
  }
  const url = new URL(path, base);
  if (url.origin !== base) {
    throw new RemoteSmokeError(operation, 'path must stay within the configured origin');
  }
  return url.toString();
}

function classifyFetchError(operation, error, timeoutMs) {
  if (error?.name === 'TimeoutError') {
    return new RemoteSmokeError(operation, `timed out after ${timeoutMs}ms`);
  }
  if (typeof error?.cause?.message === 'string' && /redirect/i.test(error.cause.message)) {
    return new RemoteSmokeError(operation, 'attempted a redirect');
  }
  const code = error?.cause?.code;
  return new RemoteSmokeError(operation,
    typeof code === 'string' && /^[A-Z][A-Z0-9_]*$/.test(code) ? code : 'network error');
}

function storeSetCookies(response, jar) {
  // Only the public-mode session cookie is replayed; the other set-cookie
  // headers (e.g. the legacy expiry) are browser cleanup the client never needs.
  for (const header of response.headers.getSetCookie()) {
    const attributes = header.split(';').map((part) => part.trim());
    const separator = attributes[0].indexOf('=');
    if (separator < 0 || attributes[0].slice(0, separator) !== SESSION_COOKIE) continue;
    const maxAge = attributes.find((part) => /^max-age=/i.test(part));
    if (maxAge && Number(maxAge.split('=')[1]) <= 0) jar.delete(SESSION_COOKIE);
    else jar.set(SESSION_COOKIE, attributes[0].slice(separator + 1));
  }
}

function cookieHeader(jar) {
  return [...jar.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
}

async function readJson(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export function createRemoteSmokeClient(origin, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const base = new URL(origin).origin;

  function createVisitor() {
    const jar = new Map();
    async function request(method, path, body) {
      const operation = `${method} ${path}`;
      const target = requestTarget(base, path, operation);
      const headers = {};
      if (method === 'POST') {
        // The public HTTP boundary rejects POST /api/* without a matching Origin.
        headers.origin = base;
        headers['content-type'] = 'application/json';
      }
      if (jar.size > 0) headers.cookie = cookieHeader(jar);
      let response;
      try {
        response = await fetch(target, {
          method,
          headers,
          body: body === undefined ? undefined : JSON.stringify(body),
          redirect: 'error',
          signal: AbortSignal.timeout(timeoutMs),
        });
        storeSetCookies(response, jar);
        return { status: response.status, json: await readJson(response) };
      } catch (error) {
        throw classifyFetchError(operation, error, timeoutMs);
      }
    }
    return {
      get: (path) => request('GET', path),
      post: (path, body) => request('POST', path, body),
      // Read-only accessor for the public session cookie; callers must treat it
      // as opaque and never render it into a log or assertion message.
      get cookie() {
        return jar.get(SESSION_COOKIE) ?? null;
      },
    };
  }

  return { origin: base, visitor: createVisitor };
}
