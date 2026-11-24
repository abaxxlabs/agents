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

test('resolveHttpBoundaryConfig fails startup on empty or invalid trust lists', () => {
  for (const value of ['', '   ', '10.0.0.0/0', '::/0', '10.0.0.0/24,not-an-ip']) {
    assert.throws(
      () => publicConfig(value),
      (err) => err instanceof HttpBoundaryConfigurationError
        && err.code === 'PLAYGROUND_TRUSTED_PROXY_IPS_INVALID',
    );
  }
});

test('AC2 untrusted peers cannot spoof forwarded identity', () => {
  const config = publicConfig('10.0.0.0/24');
  const spoofed = publicReq({
    remoteAddress: '203.0.113.7',
    headers: { ...passingPublicHeaders(), 'x-forwarded-for': '10.0.0.7' },
  });
  assert.equal(requestPassesBoundary(spoofed, config), false);
  assert.equal(requestClientAddress(spoofed, config), '203.0.113.7');
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

test('AC6 local mode is unchanged and forwarded headers cannot grant access', () => {
  const localConfig = resolveHttpBoundaryConfig({ PLAYGROUND_HTTP_MODE: 'local' });
  assert.equal(localConfig.mode, 'local');
  assert.ok(!('trustedProxyNetworks' in localConfig));

  const loopback = { socket: { remoteAddress: '127.0.0.1' }, headers: { host: '127.0.0.1' }, method: 'GET', url: '/' };
  assert.equal(requestPassesBoundary(loopback, localConfig), true);

  const mappedLoopback = { socket: { remoteAddress: '::ffff:127.0.0.1' }, headers: { host: 'localhost' }, method: 'GET', url: '/' };
  assert.equal(requestPassesBoundary(mappedLoopback, localConfig), true);

  const external = {
    socket: { remoteAddress: '203.0.113.7' },
    headers: { host: '127.0.0.1', 'x-forwarded-proto': 'https' },
    method: 'GET',
    url: '/',
  };
  assert.equal(requestPassesBoundary(external, localConfig), false);
});
