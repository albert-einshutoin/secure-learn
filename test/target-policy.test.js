const assert = require('node:assert/strict');
const test = require('node:test');
const { assertAllowedTarget, ipv4InCidr } = require('../scripts/lib/target-policy');

const safety = {
  target_services: ['app', 'target-api'],
  allowed_cidrs: ['172.23.0.0/24'],
  external_network: false,
};

test('allows only exact declared service names and addresses in declared private CIDRs', () => {
  assert.doesNotThrow(() => assertAllowedTarget('app', safety));
  assert.doesNotThrow(() => assertAllowedTarget('target-api', safety));
  assert.doesNotThrow(() => assertAllowedTarget('172.23.0.20', safety));

  for (const target of ['App', 'app2', 'target', 'target-api.example']) {
    assert.throws(() => assertAllowedTarget(target, safety), /prohibited target/);
  }
});

test('rejects loopback, public, link-local, undeclared private, URLs, and command fragments', () => {
  for (const target of [
    '127.0.0.1', '8.8.8.8', '169.254.169.254', '10.0.0.1',
    'https://example.com', 'app; id', '$(id)', '${PATH}', '-oN',
    'app/path', 'app:80', 'app\nnext', 'app\\next',
  ]) {
    assert.throws(() => assertAllowedTarget(target, safety), /prohibited target/);
  }
});

test('allows loopback only when the manifest declares the exact S14 boundary', () => {
  const incidentSafety = {
    target_services: ['localhost'],
    allowed_cidrs: ['127.0.0.1/32'],
    external_network: false,
  };
  assert.doesNotThrow(() => assertAllowedTarget('localhost', incidentSafety));
  assert.doesNotThrow(() => assertAllowedTarget('127.0.0.1', incidentSafety));
  assert.throws(
    () => assertAllowedTarget('127.0.0.2', { ...incidentSafety, allowed_cidrs: ['127.0.0.0/8'] }),
    /invalid safety policy/,
  );
});

test('compares unsigned IPv4 values at CIDR boundaries', () => {
  assert.equal(ipv4InCidr('0.0.0.0', '0.0.0.0/0'), true);
  assert.equal(ipv4InCidr('255.255.255.255', '0.0.0.0/0'), true);
  assert.equal(ipv4InCidr('172.23.0.0', '172.23.0.0/24'), true);
  assert.equal(ipv4InCidr('172.23.0.255', '172.23.0.0/24'), true);
  assert.equal(ipv4InCidr('172.23.1.0', '172.23.0.0/24'), false);
  assert.equal(ipv4InCidr('127.0.0.1', '127.0.0.1/32'), true);
  assert.equal(ipv4InCidr('127.0.0.2', '127.0.0.1/32'), false);
});

test('rejects malformed or non-canonical IPv4 and CIDR input', () => {
  for (const cidr of [
    '172.23.0.0', '172.23.0.0/-1', '172.23.0.0/33', '172.23.0.0/24 extra',
    '172.23.0.1/24', '172.023.0.0/24', '2001:db8::/32',
  ]) {
    assert.throws(() => ipv4InCidr('172.23.0.1', cidr), /invalid CIDR/);
  }
  for (const address of ['172.023.0.1', '172.23.0.1 extra', '2001:db8::1']) {
    assert.throws(() => ipv4InCidr(address, '172.23.0.0/24'), /invalid IPv4 address/);
  }
});

test('fails closed when the manifest safety policy is malformed or unsafe', () => {
  const policies = [
    null,
    { ...safety, external_network: true },
    { ...safety, undocumented_override: true },
    { ...safety, target_services: ['app;id'] },
    { ...safety, allowed_cidrs: ['172.23.0.1/24'] },
    { ...safety, allowed_cidrs: ['8.8.8.0/24'] },
    { ...safety, allowed_cidrs: ['169.254.0.0/16'] },
    { ...safety, allowed_cidrs: ['0.0.0.0/0'] },
    { ...safety, target_services: ['localhost'] },
  ];
  for (const policy of policies) {
    assert.throws(() => assertAllowedTarget('app', policy), /invalid safety policy/);
  }
});
