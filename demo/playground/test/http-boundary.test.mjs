import assert from 'node:assert/strict';
import test from 'node:test';
import {
  HttpBoundaryConfigurationError,
  resolveHttpBoundaryConfig,
} from '../src/env-file.mjs';
import {
  parseTrustedProxyNetwork,
  requestClientAddress,
  requestPassesBoundary,
} from '../src/request-policy.mjs';

const PUBLIC_ORIGIN = 'https://playground.example.com';

function publicConfig(trustedProxyIps) {
  return resolveHttpBoundaryConfig({
    PLAYGROUND_HTTP_MODE: 'public',
    PLAYGROUND_PUBLIC_ORIGIN: PUBLIC_ORIGIN,
    PLAYGROUND_TRUSTED_PROXY_IPS: trustedProxyIps,
  });
}

function publicReq({ remoteAddress, headers = {}, method = 'GET', url = '/' }) {
  return { socket: { remoteAddress }, headers, method, url };
}

function passingPublicHeaders() {
  return { host: 'playground.example.com', 'x-forwarded-proto': 'https' };
}

test('parseTrustedProxyNetwork reads bare addresses as host-sized networks', () => {
  assert.deepEqual(parseTrustedProxyNetwork('10.0.0.12'), { family: 4, prefix: 32, net: [10, 0, 0, 12] });
  assert.deepEqual(parseTrustedProxyNetwork('2001:db8::9'), {
    family: 6, prefix: 128, net: [32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
  });
});

test('parseTrustedProxyNetwork accepts CIDRs with explicit prefix', () => {
  assert.equal(parseTrustedProxyNetwork('10.0.0.0/24').prefix, 24);
  assert.equal(parseTrustedProxyNetwork('10.0.0.12/32').prefix, 32);
  assert.equal(parseTrustedProxyNetwork('2001:db8::/32').prefix, 32);
  assert.equal(parseTrustedProxyNetwork('2001:db8::9/128').prefix, 128);
  // Host bits are masked so equivalent spellings share one network identity.
  assert.deepEqual(parseTrustedProxyNetwork('10.0.0.5/24'), { family: 4, prefix: 24, net: [10, 0, 0, 0] });
  assert.deepEqual(parseTrustedProxyNetwork('2001:db8:abcd::1/32'), {
    family: 6, prefix: 32, net: [32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  });
});

test('parseTrustedProxyNetwork counts v4-mapped CIDR prefixes from the mapped boundary', () => {
  // 10.0.0.0/24 written as ::ffff:10.0.0.0/120 (120 - 96 = 24).
  const mapped = parseTrustedProxyNetwork('::ffff:10.0.0.0/120');
  assert.equal(mapped.family, 4);
  assert.equal(mapped.prefix, 24);
  assert.deepEqual(mapped.net, [10, 0, 0, 0]);
  // A bare mapped address is a single host, /128 from the mapped boundary.
  assert.deepEqual(parseTrustedProxyNetwork('::ffff:10.0.0.5'), { family: 4, prefix: 32, net: [10, 0, 0, 5] });
  // /96 covers the whole IPv4 space, so it is a zero-width network, as are
  // sub-mapped prefixes that do not fully cover the ::ffff: marker.
  for (const prefix of [0, 95, 96]) {
    assert.equal(parseTrustedProxyNetwork(`::ffff:10.0.0.0/${prefix}`), null);
  }
  // 97-128 map to IPv4 /1-/32, counted from the mapped boundary.
  assert.equal(parseTrustedProxyNetwork('::ffff:10.0.0.0/97').prefix, 1);
  assert.equal(parseTrustedProxyNetwork('::ffff:10.0.0.0/127').prefix, 31);
  assert.deepEqual(parseTrustedProxyNetwork('::ffff:10.0.0.0/128'), { family: 4, prefix: 32, net: [10, 0, 0, 0] });
});

test('parseTrustedProxyNetwork rejects zero-width, out-of-range, and malformed entries', () => {
  assert.equal(parseTrustedProxyNetwork('0.0.0.0/0'), null);
  assert.equal(parseTrustedProxyNetwork('::/0'), null);
  assert.equal(parseTrustedProxyNetwork('10.0.0.0/33'), null);
  assert.equal(parseTrustedProxyNetwork('2001:db8::/129'), null);
  assert.equal(parseTrustedProxyNetwork('10.0.0.0/'), null);
  assert.equal(parseTrustedProxyNetwork('10.0.0.0/-1'), null);
  assert.equal(parseTrustedProxyNetwork('10.0.0.0/2 4'), null);
  assert.equal(parseTrustedProxyNetwork('10.0.0.0.1/24'), null);
  assert.equal(parseTrustedProxyNetwork('not-an-ip/24'), null);
  assert.equal(parseTrustedProxyNetwork('10.0.0.0/24%eth0'), null);
  assert.equal(parseTrustedProxyNetwork(''), null);
});

test('resolveHttpBoundaryConfig parses a mixed literal and CIDR list', () => {
  const config = publicConfig('10.0.0.12, 10.1.0.0/16, 2001:db8::/32');
  assert.equal(config.trustedProxyNetworks.length, 3);
  assert.deepEqual(
    config.trustedProxyNetworks.map((n) => `${n.family === 4 ? '4' : '6'}:${n.prefix}:${n.net.join('.')}`),
    ['4:32:10.0.0.12', '4:16:10.1.0.0', '6:32:32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.0'],
  );
});

test('resolveHttpBoundaryConfig deduplicates equivalent networks', () => {
  const config = publicConfig('10.0.0.0/24, 10.0.0.0/24, 10.0.0.5/24');
  assert.equal(config.trustedProxyNetworks.length, 1);
  assert.deepEqual(config.trustedProxyNetworks[0].net, [10, 0, 0, 0]);
  const exactDupe = publicConfig('10.0.0.0/24, 10.0.0.0/24');
  assert.equal(exactDupe.trustedProxyNetworks.length, 1);
});

test('resolveHttpBoundaryConfig fails startup on empty or invalid trust lists', () => {
  for (const value of ['', '   ', '10.0.0.0/0', '::/0', '10.0.0.0/24,not-an-ip']) {
    assert.throws(
      () => publicConfig(value),
      (err) => err instanceof HttpBoundaryConfigurationError
        && err.code === 'PLAYGROUND_TRUSTED_PROXY_IPS_INVALID',
    );
  }
});

test('AC1 trusted proxy CIDR serves the public UI instead of the boundary 403', () => {
  const config = publicConfig('10.0.0.0/24');
  const inside = publicReq({ remoteAddress: '10.0.0.7', headers: passingPublicHeaders() });
  assert.equal(requestPassesBoundary(inside, config), true);

  const insideV6 = requestPassesBoundary(
    publicReq({ remoteAddress: '2001:db8::7', headers: passingPublicHeaders() }),
    publicConfig('2001:db8::/32'),
  );
  assert.equal(insideV6, true);
});

test('AC2 untrusted peers cannot spoof forwarded identity', () => {
  const config = publicConfig('10.0.0.0/24');
  // Peer outside the network; forwarded headers are otherwise perfectly valid.
  const spoofed = publicReq({
    remoteAddress: '203.0.113.7',
    headers: { ...passingPublicHeaders(), 'x-forwarded-for': '10.0.0.7' },
  });
  assert.equal(requestPassesBoundary(spoofed, config), false);
  // The spoofed X-Forwarded-For is not treated as a trusted client address.
  assert.equal(requestClientAddress(spoofed, config), '203.0.113.7');
});

test('AC3 existing public origin checks remain fail-closed for a trusted peer', () => {
  const config = publicConfig('10.0.0.0/24');
  const base = passingPublicHeaders();

  assert.equal(requestPassesBoundary(publicReq({
    remoteAddress: '10.0.0.7', headers: { ...base, host: 'other.example.com' },
  }), config), false);

  assert.equal(requestPassesBoundary(publicReq({
    remoteAddress: '10.0.0.7', headers: { ...base, origin: 'https://other.example.com' },
  }), config), false);

  assert.equal(requestPassesBoundary(publicReq({
    remoteAddress: '10.0.0.7', headers: { ...base, 'x-forwarded-host': 'other.example.com' },
  }), config), false);

  assert.equal(requestPassesBoundary(publicReq({
    remoteAddress: '10.0.0.7', headers: { ...base, 'x-forwarded-proto': 'http' },
  }), config), false);

  assert.equal(requestPassesBoundary(publicReq({
    remoteAddress: '10.0.0.7', headers: { host: 'playground.example.com' },
  }), config), false);
});

test('AC3 POST /api requires the exact public Origin from a trusted peer', () => {
  const config = publicConfig('10.0.0.0/24');
  const withOrigin = publicReq({
    remoteAddress: '10.0.0.7',
    headers: { ...passingPublicHeaders(), origin: PUBLIC_ORIGIN },
    method: 'POST',
    url: '/api/query',
  });
  assert.equal(requestPassesBoundary(withOrigin, config), true);

  const withoutOrigin = publicReq({
    remoteAddress: '10.0.0.7',
    headers: passingPublicHeaders(),
    method: 'POST',
    url: '/api/query',
  });
  assert.equal(requestPassesBoundary(withoutOrigin, config), false);
});

test('AC4 literal IPv4 and IPv6 entries keep exact-match semantics', () => {
  assert.equal(requestPassesBoundary(
    publicReq({ remoteAddress: '10.0.0.12', headers: passingPublicHeaders() }),
    publicConfig('10.0.0.12'),
  ), true);
  assert.equal(requestPassesBoundary(
    publicReq({ remoteAddress: '10.0.0.13', headers: passingPublicHeaders() }),
    publicConfig('10.0.0.12'),
  ), false);
  assert.equal(requestPassesBoundary(
    publicReq({ remoteAddress: '2001:db8::9', headers: passingPublicHeaders() }),
    publicConfig('2001:db8::9'),
  ), true);
  assert.equal(requestPassesBoundary(
    publicReq({ remoteAddress: '2001:db8::a', headers: passingPublicHeaders() }),
    publicConfig('2001:db8::9'),
  ), false);
});

test('IPv4-mapped peers normalize to the same family before CIDR matching', () => {
  const config = publicConfig('10.0.0.0/24');
  assert.equal(requestPassesBoundary(
    publicReq({ remoteAddress: '::ffff:10.0.0.7', headers: passingPublicHeaders() }), config), true);
  assert.equal(requestPassesBoundary(
    publicReq({ remoteAddress: '::ffff:a00:7', headers: passingPublicHeaders() }), config), true);
});

test('AC6 local mode is unchanged and forwarded headers cannot grant access', () => {
  const localConfig = resolveHttpBoundaryConfig({ PLAYGROUND_HTTP_MODE: 'local' });
  assert.equal(localConfig.mode, 'local');
  assert.ok(!('trustedProxyNetworks' in localConfig));

  const loopback = { socket: { remoteAddress: '127.0.0.1' }, headers: { host: '127.0.0.1' }, method: 'GET', url: '/' };
  assert.equal(requestPassesBoundary(loopback, localConfig), true);

  const mappedLoopback = { socket: { remoteAddress: '::ffff:127.0.0.1' }, headers: { host: 'localhost' }, method: 'GET', url: '/' };
  assert.equal(requestPassesBoundary(mappedLoopback, localConfig), true);

  // A non-local peer cannot pass local mode even with loopback Host and a forged proto.
  const external = {
    socket: { remoteAddress: '203.0.113.7' },
    headers: { host: '127.0.0.1', 'x-forwarded-proto': 'https' },
    method: 'GET',
    url: '/',
  };
  assert.equal(requestPassesBoundary(external, localConfig), false);
});

test('local mode requires a loopback Host for a loopback peer', () => {
  const localConfig = resolveHttpBoundaryConfig({});
  const wrongHost = { socket: { remoteAddress: '127.0.0.1' }, headers: { host: 'evil.example.com' }, method: 'GET', url: '/' };
  assert.equal(requestPassesBoundary(wrongHost, localConfig), false);
});

test('requestClientAddress walks trusted XFF hops and stops at the client', () => {
  const config = publicConfig('10.0.0.0/24');
  // Peer trusted; rightmost hop is the public client.
  const single = publicReq({ remoteAddress: '10.0.0.7', headers: { 'x-forwarded-for': '203.0.113.9' } });
  assert.equal(requestClientAddress(single, config), '203.0.113.9');

  // All hops inside the trusted network, so the trusted proxy is the principal.
  const allTrusted = publicReq({
    remoteAddress: '10.0.0.7',
    headers: { 'x-forwarded-for': '10.0.0.9, 10.0.0.8' },
  });
  assert.equal(requestClientAddress(allTrusted, config), '10.0.0.7');

  // An untrusted peer never consults XFF.
  const untrusted = publicReq({ remoteAddress: '203.0.113.7', headers: { 'x-forwarded-for': '10.0.0.9' } });
  assert.equal(requestClientAddress(untrusted, config), '203.0.113.7');

  // A non-literal hop aborts the walk and reports the trusted proxy.
  const hostnameHop = publicReq({ remoteAddress: '10.0.0.7', headers: { 'x-forwarded-for': 'unknown' } });
  assert.equal(requestClientAddress(hostnameHop, config), '10.0.0.7');
});
