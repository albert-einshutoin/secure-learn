'use strict';

const net = require('node:net');

const SERVICE_NAME = /^[a-z0-9][a-z0-9-]*$/;
const IPV4_DECIMAL = /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/;
const CIDR = /^((?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3})\/(0|[1-9]|[12]\d|3[0-2])$/;

function parseIpv4(address, label = 'IPv4 address') {
  if (typeof address !== 'string' || !IPV4_DECIMAL.test(address) || net.isIP(address) !== 4) {
    throw new TypeError(`invalid ${label}`);
  }

  // Bitwise operators are signed in JavaScript. `>>> 0` preserves the full
  // IPv4 domain so addresses above 127.255.255.255 compare deterministically.
  return address.split('.').reduce((value, octet) => ((value << 8) | Number(octet)) >>> 0, 0);
}

function parseCidr(cidr) {
  if (typeof cidr !== 'string') throw new TypeError('invalid CIDR');
  const match = CIDR.exec(cidr);
  if (!match || net.isIP(match[1]) !== 4) throw new TypeError('invalid CIDR');

  const network = parseIpv4(match[1], 'CIDR');
  const prefix = Number(match[2]);
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  if ((network & mask) >>> 0 !== network) throw new TypeError('invalid CIDR: host bits must be zero');
  return { address: match[1], network, prefix, mask, broadcast: (network | (~mask >>> 0)) >>> 0 };
}

function ipv4InCidr(address, cidr) {
  const value = parseIpv4(address);
  const { network, mask } = parseCidr(cidr);
  return ((value & mask) >>> 0) === network;
}

const PRIVATE_RANGES = [
  ['10.0.0.0', '10.255.255.255'],
  ['172.16.0.0', '172.31.255.255'],
  ['192.168.0.0', '192.168.255.255'],
].map(([start, end]) => [parseIpv4(start), parseIpv4(end)]);

function validateSafety(safety) {
  // Policies are executable trust boundaries. A malformed policy must never
  // degrade into an allow-by-default result.
  if (
    safety === null
    || typeof safety !== 'object'
    || Array.isArray(safety)
    || Object.getPrototypeOf(safety) !== Object.prototype
    || Object.keys(safety).some((key) => !['target_services', 'allowed_cidrs', 'external_network'].includes(key))
    || safety.external_network !== false
    || !Array.isArray(safety.target_services)
    || !Array.isArray(safety.allowed_cidrs)
    || safety.target_services.some((service) => typeof service !== 'string' || !SERVICE_NAME.test(service))
  ) {
    throw new Error('invalid safety policy');
  }

  for (const cidr of safety.allowed_cidrs) {
    let parsed;
    try {
      parsed = parseCidr(cidr);
    } catch {
      throw new Error('invalid safety policy');
    }
    const isPrivate = PRIVATE_RANGES.some(([start, end]) => parsed.network >= start && parsed.broadcast <= end);
    const isExplicitLoopback = parsed.address === '127.0.0.1' && parsed.prefix === 32;
    if (!isPrivate && !isExplicitLoopback) throw new Error('invalid safety policy');
  }
}

function assertAllowedTarget(target, safety) {
  validateSafety(safety);
  if (typeof target !== 'string' || target.length === 0) throw new Error('prohibited target');

  if (net.isIP(target) === 4 && IPV4_DECIMAL.test(target)) {
    if (safety.allowed_cidrs.some((cidr) => ipv4InCidr(target, cidr))) return;
    throw new Error('prohibited target');
  }

  if (SERVICE_NAME.test(target) && safety.target_services.includes(target)) return;
  throw new Error('prohibited target');
}

module.exports = { assertAllowedTarget, ipv4InCidr };
