import { BlockList, isIP } from 'node:net';

export const CF_ASNS = ['13335', '209242'];
const NON_PUBLIC = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
  '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
  '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
  '224.0.0.0/3', '::/96', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48',
  '100::/64', '2001::/32', '2001:db8::/32', '2002::/16', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8',
];

export function cidrList(cidrs) {
  if (!Array.isArray(cidrs) || !cidrs.length) throw new Error('CIDR list is empty');
  const list = new BlockList();
  for (const cidr of cidrs) {
    const [ip, prefix, extra] = String(cidr).split('/');
    const version = isIP(ip);
    if (!version || extra || !/^\d+$/.test(prefix ?? '') || Number(prefix) > (version === 4 ? 32 : 128)) {
      throw new Error('Invalid CIDR entry');
    }
    list.addSubnet(ip, Number(prefix), version === 4 ? 'ipv4' : 'ipv6');
  }
  return list;
}

// BlockList also maps IPv4 to ::ffff/96 internally. Keep the two families
// separate so an IPv6 mapped-address exclusion does not reject all IPv4.
const blockedV4 = cidrList(NON_PUBLIC.filter(cidr => !cidr.includes(':')));
const blockedV6 = cidrList(NON_PUBLIC.filter(cidr => cidr.includes(':')));
export function publicIP(ip) {
  const version = isIP(ip);
  return Boolean(version) && !(version === 4 ? blockedV4 : blockedV6).check(ip, version === 4 ? 'ipv4' : 'ipv6');
}

export function matchesRegion(row, filters = {}) {
  return ['country', 'region', 'city'].every(key => !filters[key] ||
    String(row[key] ?? '').toLowerCase() === filters[key].toLowerCase());
}

export function classify(row, cfRanges, asns = CF_ASNS) {
  if (!publicIP(row.ip)) return { kind: 'unknown', reason: 'non-public-or-invalid-ip' };
  if (cfRanges.check(row.ip, isIP(row.ip) === 4 ? 'ipv4' : 'ipv6')) {
    return { kind: 'clean', reason: 'official-cloudflare-cidr', verified: false };
  }
  const asn = String(row.asn ?? '').replace(/^AS/i, '');
  if (asns.includes(asn)) return { kind: 'unknown', reason: 'cloudflare-asn-outside-published-cidrs' };
  if (asn && /cloudflare/i.test(row.server ?? '')) {
    return { kind: 'proxy', reason: 'non-cloudflare-asn-with-cloudflare-header', verified: false };
  }
  return { kind: 'unknown', reason: 'insufficient-evidence' };
}

export function endpoint(row, includePort = true) {
  const ip = isIP(row.ip) === 6 ? `[${row.ip}]` : row.ip;
  return includePort ? `${ip}:${row.port}` : ip;
}
