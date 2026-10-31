import https from 'node:https';
import { performance } from 'node:perf_hooks';
import { publicIP } from './network.mjs';

export function testURL(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.port && url.port !== '443') {
    throw new Error('Test URL must be HTTPS on port 443 without credentials or fragment');
  }
  if (/[\r\n]/.test(url.hostname)) throw new Error('Invalid test hostname');
  return url;
}

// Connect directly to the candidate; retain the target hostname for SNI, certificate
// verification and Host. Never follow redirects to a different/unmeasured endpoint.
export function probeOnce(candidate, options, requester = https.request) {
  if (!publicIP(candidate.ip) || candidate.port !== 443) throw new Error('Probe requires a public IP on 443');
  const url = testURL(options.url);
  const start = performance.now();
  const sample = { ok: false, tcpMs: null, tlsMs: null, httpMs: null,
    bytes: 0, transferMbps: null, status: null, error: null };
  return new Promise(resolve => {
    let settled = false, req, res, bodyStart, timer;
    const chunks = [];
    const finish = error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sample.error = error;
      const elapsed = performance.now() - bodyStart;
      if (options.download && sample.bytes > 0 && elapsed > 0) {
        sample.transferMbps = sample.bytes * 8 / elapsed / 1000;
      }
      res?.destroy();
      req?.destroy();
      resolve(sample);
    };
    const complete = () => {
      const text = Buffer.concat(chunks).toString('utf8');
      sample.ok = sample.status >= 200 && sample.status < 300 &&
        (!options.expect || text.includes(options.expect));
      finish(sample.ok ? null : sample.status >= 200 && sample.status < 300 ? 'content-mismatch' : 'http-status');
    };
    timer = setTimeout(() => finish('deadline-exceeded'), options.timeout);
    req = requester({ hostname: candidate.ip, port: candidate.port, servername: url.hostname,
      method: 'GET', path: url.pathname + url.search, agent: false, rejectUnauthorized: true,
      headers: { Host: url.host, 'User-Agent': 'F-Proxy-IP/0.1', 'Accept-Encoding': 'identity', Connection: 'close' },
    }, response => {
      res = response;
      bodyStart = performance.now();
      sample.httpMs = bodyStart - start;
      sample.status = res.statusCode;
      if (res.headers['content-encoding'] && res.headers['content-encoding'] !== 'identity') {
        finish('unsupported-content-encoding'); return;
      }
      res.on('data', chunk => {
        const remaining = options.maxBytes - sample.bytes;
        const bytes = chunk.subarray(0, remaining);
        sample.bytes += bytes.length;
        chunks.push(bytes);
        if (sample.bytes >= options.maxBytes) complete();
      });
      res.on('end', complete);
      res.on('error', () => finish('response-error'));
      res.on('aborted', () => finish('response-aborted'));
    });
    req.on('socket', socket => {
      socket.once('connect', () => { sample.tcpMs = performance.now() - start; });
      socket.once('secureConnect', () => { sample.tlsMs = performance.now() - start - sample.tcpMs; });
    });
    req.on('error', error => finish(/^[A-Z0-9_]{1,60}$/.test(error.code ?? '') ? error.code : 'request-error'));
    req.end();
  });
}

function median(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b), mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

export function summarize(samples) {
  const successful = samples.filter(s => s.ok);
  const http = successful.map(s => s.httpMs);
  const average = http.reduce((a, b) => a + b, 0) / (http.length || 1);
  return { attempts: samples.length, successes: successful.length,
    successRate: samples.length ? successful.length / samples.length : 0,
    tcpMs: median(successful.map(s => s.tcpMs)), tlsMs: median(successful.map(s => s.tlsMs)),
    httpMs: median(http), jitterMs: http.length ? Math.sqrt(http.reduce((sum, x) => sum + (x - average) ** 2, 0) / http.length) : null,
    transferMbps: median(successful.map(s => s.transferMbps).filter(n => n !== null)),
    // Direct HTTPS checks do not establish Worker/BPB reverse-proxy capability or exit geography.
    bpbForwardingVerified: false, exitCountry: null };
}

export async function measure(candidates, options, once = probeOnce) {
  const results = new Array(candidates.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(options.concurrency, candidates.length) }, async () => {
    while (cursor < candidates.length) {
      const index = cursor++, candidate = candidates[index], samples = [];
      for (let i = 0; i < options.attempts; i++) samples.push(await once(candidate, options));
      results[index] = { ...candidate, testedAt: new Date().toISOString(), samples, quality: summarize(samples) };
    }
  }));
  return results.sort((a, b) => b.quality.successRate - a.quality.successRate ||
    (a.quality.httpMs ?? Infinity) - (b.quality.httpMs ?? Infinity));
}
