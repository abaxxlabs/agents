import assert from 'node:assert/strict';
import test from 'node:test';
import { createPlaygroundMetrics } from '../src/playground-metrics.mjs';

test('renders counters, gauges and cumulative histograms in Prometheus text form', () => {
  const metrics = createPlaygroundMetrics();
  metrics.counter('playground_admissions_total', { origin: 'abc' });
  metrics.counter('playground_admissions_total', { origin: 'abc' });
  metrics.counter('playground_admission_rejections_total', { origin: 'abc', reason: 'capacity' });
  metrics.gauge('playground_sessions_active', {}, 2);
  metrics.observe('playground_request_duration_seconds', { route: 'login', status: '200' }, 0.01);
  metrics.observe('playground_request_duration_seconds', { route: 'login', status: '200' }, 3);

  const text = metrics.render();
  assert.match(text, /^# TYPE playground_admissions_total counter$/m);
  assert.match(text, /^playground_admissions_total\{origin="abc"\} 2$/m);
  assert.match(text, /^playground_admission_rejections_total\{origin="abc",reason="capacity"\} 1$/m);
  assert.match(text, /^playground_sessions_active 2$/m);
  assert.match(text, /^# TYPE playground_request_duration_seconds histogram$/m);
  assert.match(text, /playground_request_duration_seconds_count\{route="login",status="200"\} 2/);
  assert.match(text, /playground_request_duration_seconds_sum\{route="login",status="200"\} 3.01/);
  assert.match(text, /playground_request_duration_seconds_bucket\{route="login",status="200",le="0.005"\} 0/);
  assert.match(text, /playground_request_duration_seconds_bucket\{route="login",status="200",le="0.025"\} 1/);
  assert.match(text, /playground_request_duration_seconds_bucket\{route="login",status="200",le="\+Inf"\} 2/);
});

test('bounds origin label cardinality with a fallback bucket', () => {
  const metrics = createPlaygroundMetrics();
  assert.equal(metrics.bucketLabel('origin', 'a', { max: 2 }), 'a');
  assert.equal(metrics.bucketLabel('origin', 'b', { max: 2 }), 'b');
  assert.equal(metrics.bucketLabel('origin', 'c', { max: 2 }), 'other');
  assert.equal(metrics.bucketLabel('origin', 'a', { max: 2 }), 'a');
});

test('escapes label values and drops secret-shaped labels', () => {
  const metrics = createPlaygroundMetrics();
  metrics.counter('playground_test_total', { origin: 'a"b\\c', secret: 'do-not-publish', token: 'nope' });
  const text = metrics.render();

  assert.match(text, /origin="a\\"b\\\\c"/);
  assert.doesNotMatch(text, /secret|token|do-not-publish|nope/);
});
