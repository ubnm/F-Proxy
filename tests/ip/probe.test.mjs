import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import https from 'node:https';
import { readFile } from 'node:fs/promises';
import { probeOnce, summarize, measure, testURL } from '../../src/ip/probe.mjs';

const candidate = { ip: '104.16.1.1', port: 443 };
const options = { url: 'https://health.example/health?a=1', expect: 'healthy',
  maxBytes: 100, timeout: 100, download: true, attempts: 3, concurrency: 2 };

test('real local TLS verifies hostname and CA while preserving measured target Host/SNI', async () => {
  const cert = await readFile(new URL('./fixtures/test-only-cert.pem', import.meta.url));
  const key = await readFile(new URL('./fixtures/test-only-key.pem', import.meta.url));
  const server = https.createServer({ cert, key }, (req, res) => {
    assert.equal(req.headers.host, 'health.example');
    assert.equal(req.socket.servername, 'health.example');
    res.end('healthy');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const requester = trusted => (requestOptions, callback) => https.request({ ...requestOptions,
    hostname: '127.0.0.1', port: server.address().port, ...(trusted ? { ca: cert } : {}) }, callback);
  try {
    const result = await probeOnce(candidate, { ...options, timeout: 2000 }, requester(true));
    assert.equal(result.ok, true);
    assert.ok(result.tcpMs >= 0); assert.ok(result.tlsMs >= 0);
    const untrusted = await probeOnce(candidate, { ...options, timeout: 2000 }, requester(false));
    assert.equal(untrusted.ok, false);
    const mismatch = await probeOnce(candidate, { ...options, url: 'https://wrong.example/health', timeout: 2000 }, requester(true));
    assert.equal(mismatch.ok, false);
    assert.equal(mismatch.error, 'ERR_TLS_CERT_ALTNAME_INVALID');
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

function transport(status = 200, body = 'healthy', mode = '') {
  return (requestOptions, callback) => {
    assert.equal(requestOptions.hostname, candidate.ip);
    assert.equal(requestOptions.servername, 'health.example');
    assert.equal(requestOptions.headers.Host, 'health.example');
    assert.equal(requestOptions.path, '/health?a=1');
    assert.equal(requestOptions.rejectUnauthorized, true);
    assert.equal(requestOptions.agent, false);
    const req = new EventEmitter();
    req.destroy = () => {};
    req.end = () => setImmediate(() => {
      if (mode === 'timeout') return;
      if (mode === 'cert-error') { req.emit('error', { code: 'CERT_HAS_EXPIRED' }); return; }
      const socket = new EventEmitter();
      req.emit('socket', socket); socket.emit('connect'); socket.emit('secureConnect');
      const res = new EventEmitter();
      res.statusCode = status; res.headers = {}; res.destroy = () => {};
      callback(res);
      res.emit('data', Buffer.from(body));
      if (mode === 'aborted') res.emit('aborted');
      else res.emit('end');
    });
    return req;
  };
}

test('HTTPS probe retains Host/SNI, validates certs, bounds bytes and measures stage timings', async () => {
  const result = await probeOnce(candidate, options, transport());
  assert.equal(result.ok, true);
  assert.equal(result.status, 200);
  assert.equal(result.bytes, 7);
  for (const key of ['tcpMs', 'tlsMs', 'httpMs', 'transferMbps']) assert.ok(result[key] >= 0, key);
  const bounded = await probeOnce(candidate, { ...options, maxBytes: 7 }, transport(200, 'healthy' + 'x'.repeat(200)));
  assert.equal(bounded.bytes, 7);
  assert.equal(bounded.ok, true);
});

test('redirects, forbidden pages, content mismatch, broken TLS, partial responses and deadlines fail', async () => {
  for (const [status, body, mode, expected] of [
    [302, '', '', 'http-status'], [403, 'healthy', '', 'http-status'], [200, 'blocked', '', 'content-mismatch'],
    [200, 'healthy', 'cert-error', 'CERT_HAS_EXPIRED'], [200, 'healthy', 'aborted', 'response-aborted'],
    [200, '', 'timeout', 'deadline-exceeded'],
  ]) {
    const result = await probeOnce(candidate, { ...options, timeout: 20 }, transport(status, body, mode));
    assert.equal(result.ok, false); assert.equal(result.error, expected);
  }
  assert.throws(() => probeOnce({ ip: '127.0.0.1', port: 443 }, options), /public IP/);
  assert.throws(() => probeOnce({ ip: 'fec0::1', port: 443 }, options), /public IP/);
  for (const url of ['http://example.com', 'https://user:pass@example.com', 'https://example.com:8443', 'https://example.com/#x']) {
    assert.throws(() => testURL(url));
  }
});

test('report aggregates success, latency/jitter and throughput without claiming BPB or exit verification', () => {
  const samples = [100, 200].map(httpMs => ({ ok: true, tcpMs: 10, tlsMs: 20, httpMs, transferMbps: 2 }));
  samples.push({ ok: false });
  const q = summarize(samples);
  assert.equal(q.successRate, 2 / 3); assert.equal(q.httpMs, 150); assert.equal(q.jitterMs, 50);
  assert.equal(q.bpbForwardingVerified, false); assert.equal(q.exitCountry, null);
  assert.equal(summarize([{ ok: false }]).httpMs, null);
});

test('measurement bounds concurrency and ranks successful fast candidates first', async () => {
  let active = 0, peak = 0, calls = 0;
  const candidates = [1, 2, 3, 4].map(n => ({ ...candidate, n }));
  const result = await measure(candidates, options, async row => {
    active++; peak = Math.max(peak, active); calls++;
    await new Promise(resolve => setTimeout(resolve, 2)); active--;
    return { ok: row.n !== 1, tcpMs: 1, tlsMs: 1, httpMs: row.n * 10, transferMbps: null };
  });
  assert.equal(peak, 2); assert.equal(calls, 12);
  assert.deepEqual(result.map(r => r.n), [2, 3, 4, 1]);
});
