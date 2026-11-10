import { lookup } from 'node:dns/promises';
import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';

export const ORDER_TABLE = 'orders';
export const ORDER_COLUMNS = Object.freeze([
  'orders.instrument',
  'orders.side',
  'orders.quantity',
  'orders.status',
  'orders.price',
  'orders.counterparty',
]);

const ORDER_COLUMN_SET = new Set(ORDER_COLUMNS);
const MOCK_USERS = new Set(['alice', 'bob']);

export function isConfiguredMockUser(value) {
  return typeof value === 'string' && MOCK_USERS.has(value);
}

export function isValidAgentName(value) {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(value);
}

export function areKnownOrderColumns(value) {
  return Array.isArray(value) && value.length > 0 && value.every((column) => ORDER_COLUMN_SET.has(column));
}

export function isLoopbackAddress(address) {
  return address === 'localhost' || address === '::1' || /^127\./.test(address ?? '') || /^::ffff:127\./.test(address ?? '');
}

function isLoopbackHostname(hostname) {
  return ['localhost', '127.0.0.1', '::1'].includes(hostname?.replace(/^\[|\]$/g, ''));
}

export function isExpectedLoopbackHost(value) {
  try {
    if (typeof value !== 'string') return false;
    const host = new URL(`http://${value}`);
    return !host.username && !host.password && host.pathname === '/' && !host.search && !host.hash &&
      isLoopbackHostname(host.hostname);
  } catch {
    return false;
  }
}

export function isExpectedLoopbackOrigin(value) {
  try {
    const origin = new URL(value);
    return (origin.protocol === 'http:' || origin.protocol === 'https:') && !origin.username && !origin.password &&
      origin.pathname === '/' && !origin.search && !origin.hash && isLoopbackHostname(origin.hostname);
  } catch {
    return false;
  }
}

function matchesHost(value, expectedHost) {
  try {
    if (typeof value !== 'string' || value !== value.trim()) return false;
    const host = new URL(`https://${value}`);
    return !host.username && !host.password && host.pathname === '/' && !host.search && !host.hash &&
      host.host.toLowerCase() === expectedHost.toLowerCase();
  } catch {
    return false;
  }
}

function matchesOrigin(value, expectedOrigin) {
  try {
    if (typeof value !== 'string' || value !== value.trim()) return false;
    const origin = new URL(value);
    return !origin.username && !origin.password && origin.pathname === '/' && !origin.search && !origin.hash &&
      origin.origin === expectedOrigin;
  } catch {
    return false;
  }
}

export function isJsonContentType(value) {
  return typeof value === 'string' && value.split(';', 1)[0].trim().toLowerCase() === 'application/json';
}

// Connections from the host reach a Compose service through the container
// network's default gateway. Docker does not always populate host-gateway
// with that address, so the default route is read first and the DNS entry
// is kept as a second source.
function defaultRouteGateway() {
  try {
    const lines = readFileSync('/proc/net/route', 'utf8').trim().split('\n');
    for (const line of lines.slice(1)) {
      const [, destination, gateway] = line.split(/\s+/);
      if (destination === '00000000' && gateway !== '00000000') {
        const bytes = Buffer.from(gateway, 'hex');
        return `${bytes[3]}.${bytes[2]}.${bytes[1]}.${bytes[0]}`;
      }
    }
  } catch {
    // Not Linux, or no default route.
  }
  return null;
}

export async function resolveHostGatewayIps(resolveDns = lookup) {
  const ips = new Set();
  const routeGateway = defaultRouteGateway();
  if (routeGateway) ips.add(routeGateway);
  try {
    const { address } = await resolveDns('host.docker.internal');
    ips.add(address);
  } catch {
    // Not running on a Docker host that provides host-gateway.
  }
  return ips.size > 0 ? [...ips] : null;
}

// Canonicalize IPv6 before comparing proxy and socket addresses.
export function normalizeRemoteAddress(address) {
  if (typeof address !== 'string') return address;
  if (!isLiteralIpAddress(address)) return address;
  if (address.startsWith('::ffff:') && isIP(address.slice('::ffff:'.length)) === 4) {
    return address.slice('::ffff:'.length);
  }
  if (isIP(address) !== 6) return address;

  const normalized = new URL(`http://[${address}]/`).hostname.slice(1, -1);
  const mappedIpv4 = normalized.match(/^::ffff:([\da-f]{1,4}):([\da-f]{1,4})$/);
  if (!mappedIpv4) return normalized;
  const high = Number.parseInt(mappedIpv4[1], 16);
  const low = Number.parseInt(mappedIpv4[2], 16);
  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
}

export function isLiteralIpAddress(address) {
  return typeof address === 'string' && !address.includes('%') && isIP(address) !== 0;
}

function ipToBytes(address, family) {
  if (family === 4) return address.split('.').map(Number);
  const [head, tail] = address.includes('::') ? address.split('::') : [address, ''];
  const toHalves = (segment) => {
    const halves = [];
    for (const group of segment ? segment.split(':') : []) {
      if (group.includes('.')) {
        const [a, b, c, d] = group.split('.').map(Number);
        halves.push((a << 8) | b, (c << 8) | d);
      } else {
        halves.push(Number.parseInt(group, 16));
      }
    }
    return halves;
  };
  const headHalves = toHalves(head);
  const tailHalves = toHalves(tail);
  const missing = 8 - headHalves.length - tailHalves.length;
  if (missing < 0) throw new Error('invalid IPv6 address');
  const bytes = [];
  for (const half of [...headHalves, ...Array(missing).fill(0), ...tailHalves]) {
    bytes.push((half >> 8) & 0xff, half & 0xff);
  }
  return bytes;
}

/**
 * Parses one PLAYGROUND_TRUSTED_PROXY_IPS entry into a network. Bare
 * addresses behave as IPv4 /32 or IPv6 /128. Zero-width prefixes are
 * rejected: they would trust every peer on the family.
 *
 * The stored address is masked to the prefix boundary so that
 * `10.0.0.5/24` and `10.0.0.0/24` produce the same network identity.
 *
 * @returns {{ family: number, prefix: number, net: number[] } | null}
 */
export function parseTrustedProxyNetwork(value) {
  if (typeof value !== 'string' || value === '') return null;
  let address = value;
  let prefix = null;
  const slash = value.indexOf('/');
  if (slash !== -1) {
    address = value.slice(0, slash);
    const candidate = value.slice(slash + 1);
    if (!/^(0|[1-9][0-9]*)$/.test(candidate)) return null;
    prefix = Number(candidate);
  }
  const rawFamily = isLiteralIpAddress(address) ? isIP(address) : 0;
  if (rawFamily === 0) return null;
  const normalized = normalizeRemoteAddress(address);
  const family = isIP(normalized);
  const isMappedV4 = rawFamily === 6 && family === 4;
  if (prefix === null) prefix = isMappedV4 ? 128 : family === 4 ? 32 : 128;
  if (isMappedV4) {
    // A v4-mapped entry counts its prefix from the mapped boundary: /96 is
    // the entire IPv4 space, /128 the single host, and 97-127 keep IPv6
    // host bits outside the mapped field, so all are rejected.
    if (prefix < 97 || prefix > 128) return null;
    prefix -= 96;
  }
  if (prefix < 1 || prefix > (family === 4 ? 32 : 128)) return null;
  const net = ipToBytes(normalized, family);
  const fullBytes = prefix >> 3;
  const remBits = prefix & 7;
  if (remBits > 0) net[fullBytes] &= (0xff << (8 - remBits)) & 0xff;
  for (let i = fullBytes + (remBits > 0 ? 1 : 0); i < net.length; i += 1) net[i] = 0;
  return { family, prefix, net };
}

function isTrustedProxyPeer(address, trustedProxyNetworks) {
  const normalized = normalizeRemoteAddress(address);
  if (!isLiteralIpAddress(normalized)) return false;
  const peer = ipToBytes(normalized, isIP(normalized));
  return Array.isArray(trustedProxyNetworks) && trustedProxyNetworks.some((network) => {
    if (network.family !== isIP(normalized)) return false;
    const fullBytes = network.prefix >> 3;
    for (let i = 0; i < fullBytes; i += 1) {
      if (peer[i] !== network.net[i]) return false;
    }
    const remBits = network.prefix & 7;
    if (remBits > 0) {
      const mask = (0xff << (8 - remBits)) & 0xff;
      if ((peer[fullBytes] & mask) !== (network.net[fullBytes] & mask)) return false;
    }
    return true;
  });
}

export function requestClientAddress(req, config) {
  const remoteAddress = normalizeRemoteAddress(req.socket.remoteAddress) ?? 'unknown';
  if (config?.mode !== 'public' || !isTrustedProxyPeer(remoteAddress, config.trustedProxyNetworks)) {
    return remoteAddress;
  }

  const forwardedFor = req.headers['x-forwarded-for'];
  if (typeof forwardedFor !== 'string') return remoteAddress;
  const chain = forwardedFor.split(',').map((address) => address.trim());

  for (let index = chain.length - 1; index >= 0; index -= 1) {
    const address = normalizeRemoteAddress(chain[index]);
    if (!isLiteralIpAddress(address)) return remoteAddress;
    if (!isTrustedProxyPeer(address, config.trustedProxyNetworks)) return address;
  }
  return remoteAddress;
}

// The Host header is client-supplied text and is never trusted. Locality
// comes from the network-assigned source address.
export function isLocalConnection(remoteAddress, hostGatewayIps) {
  const address = normalizeRemoteAddress(remoteAddress);
  return isLoopbackAddress(address) ||
    (hostGatewayIps !== null && hostGatewayIps.includes(address));
}

export function requestPassesBoundary(req, config, hostGatewayIps = null) {
  // Local mode never relies on forwarded headers; public mode checks the peer first.
  if (config?.mode === 'local') {
    return isLocalConnection(req.socket.remoteAddress, hostGatewayIps) &&
      isExpectedLoopbackHost(req.headers.host) &&
      (req.headers.origin === undefined || isExpectedLoopbackOrigin(req.headers.origin));
  }

  if (config?.mode !== 'public' || !config.publicOrigin) return false;

  const remoteAddress = normalizeRemoteAddress(req.socket.remoteAddress);
  if (!isTrustedProxyPeer(remoteAddress, config.trustedProxyNetworks)) return false;

  let expected;
  try {
    expected = new URL(config.publicOrigin);
  } catch {
    return false;
  }

  if (!matchesHost(req.headers.host, expected.host)) return false;
  if (req.headers.origin !== undefined && !matchesOrigin(req.headers.origin, expected.origin)) return false;

  if (req.method === 'POST') {
    let pathname;
    try {
      pathname = new URL(req.url, 'http://localhost').pathname;
    } catch {
      return false;
    }
    if (pathname.startsWith('/api/') && req.headers.origin === undefined) return false;
  }

  const forwardedHost = req.headers['x-forwarded-host'];
  if (forwardedHost !== undefined && !matchesHost(forwardedHost, expected.host)) return false;

  const forwardedProto = req.headers['x-forwarded-proto'];
  if (typeof forwardedProto !== 'string' || forwardedProto.toLowerCase() !== 'https') return false;

  return true;
}

export const MAX_BODY_BYTES = 64 * 1024;

export class RequestBodyTooLargeError extends Error {}

// The request stream is one-shot. The dispatcher calls this for every POST
// /api/* request before dispatch, so the limit also covers unknown routes.
// Bytes are counted as they arrive;
// Content-Length is client-supplied and never trusted.
export async function consumeBody(req) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += Buffer.byteLength(chunk);
    if (bytes > MAX_BODY_BYTES) {
      throw new RequestBodyTooLargeError('Body exceeds the 64 KiB limit');
    }
    chunks.push(chunk);
  }
  req.bodyRaw = Buffer.concat(chunks).toString('utf8');
}

// Parses the already-consumed body; routes without a payload never call it.
export function parseBody(req) {
  return req.bodyRaw ? JSON.parse(req.bodyRaw) : {};
}
