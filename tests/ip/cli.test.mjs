import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
const cli = fileURLToPath(new URL('../../ip.mjs', import.meta.url));
test('CLI exports a quality report offline, preserves unrelated settings and protects existing output on no results', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'f-proxy-test-'));
  try {
    const reportFile = join(dir, 'report.json'), templateFile = join(dir, 'template.json');
    const report = { schemaVersion: 1, type: 'report', ranges: { cidrs: ['104.16.0.0/13'] }, candidates: [{
      ip: '104.16.1.1', port: 443, asn: '13335', country: 'JP', testedAt: new Date().toISOString(),
      quality: { attempts: 3, successes: 3, successRate: 1, httpMs: 100, transferMbps: 3 },
    }] };
    await writeFile(reportFile, JSON.stringify(report));
    await writeFile(templateFile, JSON.stringify({ cleanIPs: ['old'], ports: [443], chainProxy: 'keep' }));
    await exec(process.execPath, [cli, 'export', '--input', reportFile, '--out', dir, '--bpb-template', templateFile]);
    const output = join(dir, 'bpb-settings.patch.json');
    const previous = await readFile(output, 'utf8');
    assert.deepEqual(JSON.parse(previous), { cleanIPs: ['104.16.1.1'] });
    assert.equal(JSON.parse(await readFile(join(dir, 'bpb-settings.json'), 'utf8')).chainProxy, 'keep');
    report.candidates = [];
    await writeFile(reportFile, JSON.stringify(report));
    await assert.rejects(exec(process.execPath, [cli, 'export', '--input', reportFile, '--out', dir]), /preserved/);
    assert.equal(await readFile(output, 'utf8'), previous);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('missing FOFA key fails locally without creating output or leaking environment values', async () => {
  await assert.rejects(exec(process.execPath, [cli, 'discover'], { env: { ...process.env, FOFA_KEY: '' } }), /FOFA_KEY is required/);
});
