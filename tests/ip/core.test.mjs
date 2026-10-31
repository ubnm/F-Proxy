import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildQuery, discover, searchFofa, loadRanges, FOFA_FIELDS } from '../../src/ip/discover.mjs';
import { cidrList, classify, matchesRegion, publicIP, endpoint } from '../../src/ip/network.mjs';
import { buildExport } from '../../src/ip/export.mjs';
import { parseOptions } from '../../ip.mjs';

const ranges = { cidrs: ['104.16.0.0/13', '2606:4700::/32'], fetchedAt: '2026-11-01T00:00:00Z' };
const cf = cidrList(ranges.cidrs);
const row = (ip = '104.16.1.1', extra = {}) => ({ ip, port: 443, country: 'JP', region: 'Tokyo',
  city: 'Tokyo', asn: '13335', server: 'cloudflare', ...extra });

test('classification uses CIDRs, excludes private/mapped targets and does not treat Google as Cloudflare', () => {
  assert.equal(classify(row(), cf).kind, 'clean');
  assert.equal(classify(row('2606:4700::1111'), cf).kind, 'clean');
  assert.equal(classify(row('34.146.18.2', { asn: '396982' }), cf).kind, 'proxy');
  assert.equal(classify(row('8.8.8.8'), cf).kind, 'unknown');
  assert.equal(classify(row('8.8.8.8', { asn: '', server: '' }), cf).kind, 'unknown');
  for (const ip of ['127.0.0.1', '10.1.2.3', '::1', '::ffff:127.0.0.1', 'fe80::1', '192.0.2.1', 'garbage']) {
    assert.equal(publicIP(ip), false, ip);
  }
  assert.equal(publicIP('1.1.1.1'), true);
  assert.throws(() => cidrList(['1.1.1.1/no']));
  assert.throws(() => cidrList([]));
  assert.equal(endpoint(row('2606:4700::1111')), '[2606:4700::1111]:443');
});

test('query and local geography checks use exact labels and escaped values', () => {
  assert.match(buildQuery('clean', { country: 'JP' }), /country=="JP"/);
  assert.match(buildQuery('proxy'), /asn!="13335"/);
  assert.match(buildQuery('clean', { city: 'a" || port="22' }), /city=="a\\"/);
  assert.throws(() => buildQuery('proxy', { city: '\n' }));
  assert.equal(matchesRegion(row(), { country: 'jp', city: 'tokyo' }), true);
  assert.equal(matchesRegion(row(), { country: 'HK' }), false);
});

test('FOFA pagination deduplicates and rejects wrong geography, ports and invalid targets', async () => {
  const calls = [];
  const result = await discover({ kind: 'both', country: 'JP', size: 3, pages: 2 }, { ranges,
    search: async options => {
      calls.push(options);
      if (options.query.includes('asn!=')) return [row('34.146.18.2', { asn: '396982' })];
      if (options.page === 1) return [row(), row(), row('104.16.1.2', { country: 'HK' })];
      return [row('127.0.0.1'), row('104.16.1.3', { port: 80 })];
    } });
  assert.equal(calls.length, 3);
  assert.deepEqual(result.candidates.map(r => r.classification.kind), ['clean', 'proxy']);
  assert.equal(result.stats.duplicates, 1);
  assert.equal(result.stats.rejected, 3);
  assert.equal(result.stats.fetched, 6);
});

test('FOFA sends field order and credentials only to official HTTPS; errors never echo key or URL', async () => {
  const key = 'test-secret-only';
  const rows = await searchFofa({ key, query: 'country=="JP"' }, async (url, options) => {
    assert.equal(url.origin, 'https://fofa.info');
    assert.equal(url.searchParams.get('key'), key);
    assert.equal(options.redirect, 'error');
    assert.equal(url.searchParams.get('fields'), FOFA_FIELDS.join(','));
    assert.equal(Buffer.from(url.searchParams.get('qbase64'), 'base64').toString(), 'country=="JP"');
    return { ok: true, json: async () => ({ results: [['104.16.1.1', '443', 'JP', 'Tokyo', 'Tokyo', '13335', 'CF', 'cloudflare']] }) };
  });
  assert.equal(rows[0].asn, '13335');
  for (const fetcher of [async url => { throw new Error(String(url)); },
    async () => ({ ok: true, json: async () => ({ error: true, errmsg: key, errcode: key }) })]) {
    await assert.rejects(searchFofa({ key, query: '' }, fetcher), error => !error.message.includes(key));
  }
  await assert.rejects(searchFofa({ key, query: '' }, async () => ({ ok: true,
    json: async () => ({ results: [['wrong']] }) })), /row shape/);
  await assert.rejects(loadRanges(async () => ({ ok: true, text: async () => '<html>error</html>' })), /CIDR/);
});

const exportOptions = { top: 10, minSuccess: 1, maxLatency: 1500, minMbps: 0, maxAgeHours: 24 };
const measured = (ip, extra = {}) => ({ ...row(ip), testedAt: new Date().toISOString(),
  quality: { attempts: 3, successes: 3, successRate: 1, httpMs: 100, transferMbps: null }, ...extra });
const report = candidates => ({ schemaVersion: 1, type: 'report', ranges, candidates });

test('export ranks fresh passing candidates, brackets IPv6, preserves template fields and omits unverified proxies', () => {
  const candidates = [measured('104.16.1.1'), measured('2606:4700::1111'),
    measured('34.146.18.2', { asn: '396982' }), measured('104.16.1.3', { testedAt: '2000-01-01' }),
    measured('104.16.1.4', { quality: { attempts: 3, successes: 0, successRate: 0, httpMs: null } })];
  const result = buildExport(report(candidates), exportOptions, { cleanIPs: ['old'], ports: [443], custom: 'keep' });
  assert.deepEqual(result.patch, { cleanIPs: ['104.16.1.1', '[2606:4700::1111]'] });
  assert.equal(result.settings.custom, 'keep');
  assert.equal(result.metadata.bpbForwardingVerified, false);
  assert.equal(result.proxy.length, 1);
  const proxyOnly = buildExport(report(candidates), { ...exportOptions, country: 'JP', includeProxyCandidates: true });
  assert.deepEqual(proxyOnly.patch.proxyIPs, ['34.146.18.2:443']);
  assert.equal(proxyOnly.patch.proxyIpMode, 'proxyip');
  const filtered = buildExport(report(candidates), { ...exportOptions, kind: 'proxy', includeProxyCandidates: true });
  assert.equal(filtered.clean.length, 0);
  assert.equal(filtered.patch.cleanIPs, undefined);
  assert.deepEqual(filtered.patch.proxyIPs, ['34.146.18.2:443']);
});

test('empty, stale, failed or geographically excluded results cannot replace a usable BPB export', () => {
  assert.throws(() => buildExport(report([]), exportOptions), /preserved/);
  assert.throws(() => buildExport(report([measured('104.16.1.1')]), { ...exportOptions, country: 'HK' }), /preserved/);
  assert.throws(() => buildExport(report([measured('34.146.18.2', { asn: '396982' })]), exportOptions), /include-proxy/);
  assert.throws(() => buildExport(report([measured('104.16.1.1')]), exportOptions, { data: {} }), /template/);
  assert.throws(() => buildExport({ type: 'discovery', schemaVersion: 1, candidates: [] }, exportOptions), /quality report/);
});

test('CLI validates bounds, countries, unknown flags and required test URL before spending quota', () => {
  for (const args of [['run'], ['probe', '--test-url', 'http://localhost', '--input', 'x'],
    ['discover', '--size', 'NaN'], ['discover', '--country', 'Japan'], ['discover', '--pages', '0'],
    ['discover', '--concurrency', '33'], ['discover', '--cf-asns', '13335,xxx'], ['discover', '--oops']]) {
    assert.throws(() => parseOptions(args), args.join(' '));
  }
  assert.equal(parseOptions(['discover', '--country', 'jp']).country, 'JP');
});
