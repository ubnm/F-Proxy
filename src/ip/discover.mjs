import { CF_ASNS, cidrList, classify, matchesRegion, publicIP } from './network.mjs';

export const FOFA_FIELDS = ['ip', 'port', 'country', 'region', 'city', 'asn', 'org', 'server'];
export const RANGE_URLS = ['https://www.cloudflare.com/ips-v4', 'https://www.cloudflare.com/ips-v6'];

export function buildQuery(kind, filters = {}, asns = CF_ASNS) {
  if (!['clean', 'proxy'].includes(kind)) throw new Error('Invalid pool kind');
  if (!asns.length || asns.some(a => !/^\d+$/.test(a))) throw new Error('Invalid ASN list');
  const quote = value => {
    if (/[\x00-\x1f\x7f]/.test(value)) throw new Error('Invalid query filter');
    return JSON.stringify(value);
  };
  const clauses = ['server=="cloudflare"', 'port=="443"'];
  clauses.push(kind === 'clean'
    ? `(${asns.map(a => `asn=="${a}"`).join(' || ')})`
    : asns.map(a => `asn!="${a}"`).join(' && '));
  for (const key of ['country', 'region', 'city']) {
    if (filters[key]) clauses.push(`${key}==${quote(filters[key])}`);
  }
  return clauses.join(' && ');
}

// API keys are sent only to the official FOFA endpoint. Do not expose URL/error bodies.
export async function searchFofa({ key, query, size = 20, page = 1 }, fetcher = fetch) {
  if (!key) throw new Error('FOFA_KEY is required');
  const url = new URL('https://fofa.info/api/v1/search/all');
  url.search = new URLSearchParams({ key, qbase64: Buffer.from(query).toString('base64'),
    fields: FOFA_FIELDS.join(','), size: String(size), page: String(page), full: 'false' });
  let response;
  try {
    response = await fetcher(url, { signal: AbortSignal.timeout(20000), redirect: 'error' });
  } catch {
    throw new Error('FOFA network request failed (URL and credentials redacted)');
  }
  if (!response.ok) throw new Error(`FOFA HTTP ${response.status}`);
  let body;
  try { body = await response.json(); } catch { throw new Error('FOFA returned invalid JSON'); }
  if (body.error) {
    const code = /^\d{1,6}$/.test(String(body.errcode)) ? body.errcode : 'unknown';
    throw new Error(`FOFA API error ${code}; check key, quota and field permissions`);
  }
  if (!Array.isArray(body.results)) throw new Error('FOFA results missing');
  return body.results.map(values => {
    if (!Array.isArray(values) || values.length !== FOFA_FIELDS.length) {
      throw new Error('Unexpected FOFA row shape');
    }
    return Object.fromEntries(FOFA_FIELDS.map((field, i) => [field, values[i]]));
  });
}

export async function loadRanges(fetcher = fetch) {
  const parts = await Promise.all(RANGE_URLS.map(async url => {
    const res = await fetcher(url, { signal: AbortSignal.timeout(15000), redirect: 'error' });
    if (!res.ok) throw new Error('Cloudflare CIDR download failed');
    return (await res.text()).trim().split(/\s+/);
  }));
  const cidrs = parts.flat();
  cidrList(cidrs); // fail closed when the published range data is malformed
  return { cidrs, sources: RANGE_URLS, fetchedAt: new Date().toISOString() };
}

export async function discover(options, { search = searchFofa, ranges } = {}) {
  ranges ??= await loadRanges();
  const cfRanges = cidrList(ranges.cidrs);
  const asns = options.asns ?? CF_ASNS;
  const kinds = options.kind === 'both' ? ['clean', 'proxy'] : [options.kind];
  const byEndpoint = new Map();
  const queries = [];
  const stats = { fetched: 0, rejected: 0, duplicates: 0, rejectedByReason: {} };
  // Bounded, sequential pagination avoids bursts and unexpected quota consumption.
  for (const kind of kinds) {
    const query = buildQuery(kind, options, asns);
    queries.push({ kind, query });
    for (let page = 1; page <= options.pages; page++) {
      const rows = await search({ key: options.key, query, size: options.size, page });
      stats.fetched += rows.length;
      for (const row of rows) {
        const candidate = { ip: String(row.ip), port: Number(row.port),
          country: String(row.country ?? ''), region: String(row.region ?? ''), city: String(row.city ?? ''),
          asn: String(row.asn ?? '').replace(/^AS/i, ''), org: String(row.org ?? ''),
          server: String(row.server ?? ''), source: 'fofa', discoveredAt: new Date().toISOString() };
        const classification = classify(candidate, cfRanges, asns);
        const reason = !publicIP(candidate.ip) ? 'non-public-or-invalid-ip' : candidate.port !== 443 ? 'unsupported-port' :
          !matchesRegion(candidate, options) ? 'region-mismatch' : classification.kind !== kind ? classification.reason : null;
        if (reason) {
          stats.rejected++;
          stats.rejectedByReason[reason] = (stats.rejectedByReason[reason] ?? 0) + 1;
          continue;
        }
        candidate.classification = classification;
        const id = `${candidate.ip}:${candidate.port}`;
        if (byEndpoint.has(id)) stats.duplicates++;
        else byEndpoint.set(id, candidate);
      }
      if (rows.length < options.size) break;
    }
  }
  return { schemaVersion: 1, type: 'discovery', createdAt: new Date().toISOString(),
    filters: Object.fromEntries(['country', 'region', 'city'].filter(k => options[k]).map(k => [k, options[k]])),
    ranges, asns, queries, stats, candidates: [...byEndpoint.values()] };
}
