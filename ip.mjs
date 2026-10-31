import { parseArgs } from 'node:util';
import { readFile, mkdir, writeFile, rename } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discover } from './src/ip/discover.mjs';
import { cidrList, CF_ASNS, classify, matchesRegion, publicIP } from './src/ip/network.mjs';
import { measure, testURL } from './src/ip/probe.mjs';
import { buildExport } from './src/ip/export.mjs';

const HELP = `F-Proxy Cloudflare IP tools (Node.js >=20, no dependencies)
  node --env-file=.env.local ip.mjs run --country JP --test-url https://YOUR-WORKER/health --expect healthy
  node ip.mjs discover --country JP --out out/ip
  node ip.mjs probe --input out/ip/discovery.json --test-url https://YOUR-WORKER/health --expect healthy
  node ip.mjs export --input out/ip/report.json [--bpb-template backup.json]

Commands: discover | probe | export | run (discover + probe + export)
FOFA_KEY comes only from the environment. API requests use the official HTTPS endpoint.
Options:
  --kind both|clean|proxy (both)   --country JP   --region Tokyo   --city Tokyo
  --size 20 (1..100)  --pages 1 (1..5)  --cf-asns 13335,209242
  --cf-ranges ranges.json        Offline snapshot: {cidrs:[...],fetchedAt:...}
  --input FILE                  Discovery/report JSON from this tool
  --test-url HTTPS_URL           Required for run/probe; target Host/SNI
  --expect TEXT                 Expected response text (recommended)
  --concurrency 5 (1..32)        --attempts 3 (1..10)  --timeout 5000 (100..30000 ms)
  --download                    Measure bounded response transfer speed
  --max-bytes 65536 (1..8388608)  --out out/ip
  --top 10 (1..100)              --min-success 1 (0..1)
  --max-latency 1500 (ms)        --min-mbps 0   --max-age-hours 24
  --include-proxy-candidates     Opt in to exporting unverified Proxy IPs
  --bpb-template FILE            Merge fields into a plain BPB v5 settings backup
  --help

Classification and region are discovery evidence; HTTPS success does not prove BPB
forwarding, stable exit country, reputation, or target-service access.
No deployment or account configuration is changed.
`;

export function parseOptions(args) {
  const strings = ['kind', 'country', 'region', 'city', 'size', 'pages', 'cf-asns', 'cf-ranges',
    'input', 'test-url', 'expect', 'concurrency', 'attempts', 'timeout', 'max-bytes', 'out',
    'top', 'min-success', 'max-latency', 'min-mbps', 'max-age-hours', 'bpb-template'];
  const booleans = ['help', 'download', 'include-proxy-candidates'];
  const { values: v, positionals } = parseArgs({ args, allowPositionals: true, strict: true,
    options: Object.fromEntries([...strings.map(k => [k, { type: 'string' }]), ...booleans.map(k => [k, { type: 'boolean' }])]) });
  if (v.help) return { help: true };
  const command = positionals[0];
  if (positionals.length !== 1 || !['discover', 'probe', 'export', 'run'].includes(command)) {
    throw new Error('Specify discover, probe, export or run; use --help');
  }
  const number = (key, fallback, min, max, integer = true) => {
    const n = v[key] === undefined ? fallback : Number(v[key]);
    if (!Number.isFinite(n) || n < min || n > max || integer && !Number.isInteger(n)) throw new Error(`Invalid --${key}`);
    return n;
  };
  const options = { command, kind: v.kind ?? 'both', country: v.country?.toUpperCase(), region: v.region, city: v.city,
    key: process.env.FOFA_KEY, size: number('size', 20, 1, 100), pages: number('pages', 1, 1, 5),
    asns: (v['cf-asns'] ?? CF_ASNS.join(',')).split(','), rangesFile: v['cf-ranges'],
    input: v.input, url: v['test-url'], expect: v.expect ?? '', concurrency: number('concurrency', 5, 1, 32),
    attempts: number('attempts', 3, 1, 10), timeout: number('timeout', 5000, 100, 30000),
    download: Boolean(v.download), maxBytes: number('max-bytes', 65536, 1, 8388608),
    out: resolve(v.out ?? 'out/ip'), top: number('top', 10, 1, 100),
    minSuccess: number('min-success', 1, 0, 1, false), maxLatency: number('max-latency', 1500, 1, 300000),
    minMbps: number('min-mbps', 0, 0, 100000, false), maxAgeHours: number('max-age-hours', 24, 0.001, 720, false),
    includeProxyCandidates: Boolean(v['include-proxy-candidates']), templateFile: v['bpb-template'] };
  if (!['both', 'clean', 'proxy'].includes(options.kind)) throw new Error('Invalid --kind');
  if (options.country && !/^[A-Z]{2}$/.test(options.country)) throw new Error('--country must be a two-letter code');
  if (options.asns.some(a => !/^\d+$/.test(a))) throw new Error('Invalid --cf-asns');
  for (const key of ['region', 'city']) if (options[key] && /[\x00-\x1f\x7f]/.test(options[key])) throw new Error(`Invalid --${key}`);
  if (['run', 'probe'].includes(command)) {
    if (!options.url) throw new Error('--test-url is required');
    testURL(options.url);
  }
  if (['probe', 'export'].includes(command) && !options.input) throw new Error('--input is required');
  return options;
}

async function readJSON(file) { return JSON.parse(await readFile(file, 'utf8')); }
async function save(file, value) {
  const temp = `${file}.${process.pid}.tmp`;
  await writeFile(temp, value, { mode: 0o600 });
  await rename(temp, file);
}

export async function main(args = process.argv.slice(2)) {
  const options = parseOptions(args);
  if (options.help) { console.log(HELP); return; }
  const { command } = options;
  // Validate locally before creating output files or spending API quota.
  if (['run', 'discover'].includes(command) && !options.key) throw new Error('FOFA_KEY is required');
  const ranges = options.rangesFile ? await readJSON(options.rangesFile) : undefined;
  const template = options.templateFile ? await readJSON(options.templateFile) : undefined;
  let data;
  if (['run', 'discover'].includes(command)) {
    data = await discover(options, { ranges });
    await mkdir(options.out, { recursive: true });
    await save(join(options.out, 'discovery.json'), JSON.stringify(data, null, 2));
    console.log(`FOFA: ${data.stats.fetched} rows; ${data.candidates.length} classified candidates; ${data.stats.rejected} rejected`);
  } else data = await readJSON(options.input);
  if (['run', 'probe'].includes(command)) {
    if (data.schemaVersion !== 1 || !['discovery', 'report'].includes(data.type) || !Array.isArray(data.candidates)) {
      throw new Error('A version 1 discovery/report document is required');
    }
    const cfRanges = cidrList(data.ranges?.cidrs);
    const candidates = data.candidates.filter(row => matchesRegion(row, options) &&
      (options.kind === 'both' || classify(row, cfRanges, data.asns).kind === options.kind));
    if (candidates.length > 1000 || candidates.some(row => !publicIP(row.ip) || row.port !== 443)) {
      throw new Error('Invalid probe targets or more than 1000 candidates');
    }
    const measured = await measure(candidates, options);
    data = { ...data, type: 'report', testedAt: new Date().toISOString(),
      probe: { url: options.url, expect: options.expect, attempts: options.attempts, timeout: options.timeout,
        download: options.download, maxBytes: options.maxBytes, vantage: 'local-direct-connection' }, candidates: measured };
    await mkdir(options.out, { recursive: true });
    await save(join(options.out, 'report.json'), JSON.stringify(data, null, 2));
    console.log(`HTTPS: ${measured.filter(row => row.quality.successes > 0).length}/${measured.length} candidates succeeded; BPB forwarding remains unverified`);
  }
  if (['run', 'export'].includes(command)) {
    const result = buildExport(data, options, template);
    await mkdir(options.out, { recursive: true });
    const files = {
      'bpb-settings.patch.json': JSON.stringify(result.patch, null, 2),
      'export-metadata.json': JSON.stringify(result.metadata, null, 2),
      'clean-ips.txt': result.clean.map(row => row.ip.includes(':') ? `[${row.ip}]` : row.ip).join('\n'),
      'proxy-candidates.txt': result.proxy.map(row => `${row.ip.includes(':') ? `[${row.ip}]` : row.ip}:${row.port}`).join('\n'),
    };
    if (result.settings) files['bpb-settings.json'] = JSON.stringify(result.settings, null, 2);
    for (const [name, value] of Object.entries(files)) await save(join(options.out, name), value + '\n');
    console.log(`Exported ${result.clean.length} Clean IPs and ${result.proxy.length} Proxy candidates to ${options.out}`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    // Redact the supplied key even if a local path/argument happens to contain it.
    const message = String(error.message).split(process.env.FOFA_KEY || '\0').join('[REDACTED]');
    console.error(`IP tools: ${message}`);
    process.exitCode = 1;
  });
}
