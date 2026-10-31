import { cidrList, classify, endpoint, matchesRegion, publicIP } from './network.mjs';

export function buildExport(report, options, template) {
  if (report.schemaVersion !== 1 || report.type !== 'report' || !Array.isArray(report.candidates)) {
    throw new Error('A version 1 quality report is required');
  }
  const ranges = cidrList(report.ranges?.cidrs);
  const now = Date.now();
  const passing = report.candidates.filter(row => {
    const age = now - Date.parse(row.testedAt);
    const q = row.quality;
    return publicIP(row.ip) && row.port === 443 && matchesRegion(row, options) &&
      Number.isFinite(age) && age >= -60000 && age <= options.maxAgeHours * 3600000 &&
      q?.attempts > 0 && q.successes > 0 && q.successRate >= options.minSuccess &&
      Number.isFinite(q.httpMs) && q.httpMs <= options.maxLatency &&
      (!options.minMbps || Number.isFinite(q.transferMbps) && q.transferMbps >= options.minMbps);
  }).sort((a, b) => b.quality.successRate - a.quality.successRate || a.quality.httpMs - b.quality.httpMs);
  const select = kind => [...new Map(passing.filter(row => classify(row, ranges, report.asns).kind === kind)
    .map(row => [row.ip, row])).values()].slice(0, options.top);
  const clean = select('clean'), proxy = select('proxy');
  const patch = {};
  if (clean.length) patch.cleanIPs = clean.map(row => endpoint(row, false));
  if (proxy.length && options.includeProxyCandidates) {
    patch.proxyIpMode = 'proxyip';
    patch.proxyIPs = proxy.map(row => endpoint(row));
  }
  if (!Object.keys(patch).length) {
    throw new Error('No exportable results; existing BPB configuration files were preserved. Proxy candidates require --include-proxy-candidates.');
  }
  if (template !== undefined && (!template || Array.isArray(template) || typeof template !== 'object' ||
      !Array.isArray(template.cleanIPs))) {
    throw new Error('BPB template must be a plain settings export containing cleanIPs');
  }
  return { patch, settings: template === undefined ? undefined : { ...template, ...patch }, clean, proxy,
    metadata: { schemaVersion: 1, createdAt: new Date().toISOString(),
      bpbSchema: 'v5-panel-settings', cleanCount: clean.length, proxyCandidateCount: proxy.length,
      proxyCandidatesIncluded: Boolean(proxy.length && options.includeProxyCandidates),
      bpbForwardingVerified: false, exitCountryVerified: false,
      warnings: ['Region labels come from FOFA, not measured exit geography.',
        'Proxy IPs are HTTPS-tested candidates; BPB forwarding is not verified.',
        'The patch is partial settings; merge with a backup or use the text fields. Do not import it as a full panel backup.'] } };
}
