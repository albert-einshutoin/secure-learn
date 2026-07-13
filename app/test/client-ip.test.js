const assert = require('node:assert/strict');
const test = require('node:test');

const { getClientIp } = require('../dist/common/network/client-ip');

test('ignores x-forwarded-for when no trusted proxy is configured', () => {
  const req = {
    headers: { 'x-forwarded-for': '203.0.113.10, 10.0.0.1' },
    socket: { remoteAddress: '172.23.0.30' },
  };

  assert.equal(getClientIp(req), '172.23.0.30');
});

test('uses the IP resolved by Express after trusted-proxy processing', () => {
  const req = {
    headers: { 'x-forwarded-for': '203.0.113.10' },
    ip: '203.0.113.10',
    socket: { remoteAddress: '172.23.0.30' },
  };

  assert.equal(getClientIp(req), '203.0.113.10');
});

test('normalizes Docker IPv4-mapped IPv6 addresses for Fail2ban', () => {
  const req = {
    headers: {},
    socket: { remoteAddress: '::ffff:172.23.0.30' },
  };

  assert.equal(getClientIp(req), '172.23.0.30');
});

test('falls back to unknown when no address is available', () => {
  const req = {
    headers: {},
    socket: {},
  };

  assert.equal(getClientIp(req), 'unknown');
});

test('rejects malformed addresses before writing security logs', () => {
  const req = {
    ip: '203.0.113.10\nforged-log-entry',
    headers: {},
    socket: { remoteAddress: 'also-not-an-ip' },
  };

  assert.equal(getClientIp(req), 'unknown');
});
