const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const {
  inspectVirtualization,
  provisionVmAdapter,
  validateVmAdapterMarker,
} = require('../scripts/lib/vm-adapter');

const root = path.resolve(__dirname, '..');
const NOW = new Date('2026-07-18T00:00:00.000Z');

function signals(values = {}) {
  return {
    platform: 'linux',
    exists: (source) => Boolean(values[source]),
    readText: (source) => values[source] || '',
  };
}

function validMarker(overrides = {}) {
  return {
    version: 1,
    adapter: 'secure-learn-linux-vm',
    snapshot_id: 'snapshot-001',
    provisioned_at: NOW.toISOString(),
    disposable_snapshot_acknowledged: true,
    virtualization_provider: 'qemu-kvm',
    provisioning_nonce: 'a'.repeat(64),
    ...overrides,
  };
}

test('accepts known local VM evidence and rejects bare metal, containers, and cloud VMs', () => {
  assert.deepEqual(inspectVirtualization(signals({
    '/sys/class/dmi/id/product_name': 'Standard PC (Q35 + ICH9, 2009)',
    '/sys/class/dmi/id/sys_vendor': 'QEMU',
  })), { provider: 'qemu-kvm' });
  assert.deepEqual(inspectVirtualization(signals({
    '/sys/class/dmi/id/product_name': 'VMware Virtual Platform',
  })), { provider: 'vmware' });

  assert.throws(() => inspectVirtualization(signals()), /local virtual machine/);
  assert.throws(() => inspectVirtualization(signals({ '/.dockerenv': 'present' })), /container/);
  assert.throws(() => inspectVirtualization(signals({
    '/proc/1/cgroup': '0::/docker/abc',
    '/sys/class/dmi/id/product_name': 'QEMU',
  })), /container/);
  for (const cloud of ['Amazon EC2', 'Google Compute Engine', 'Microsoft Corporation Virtual Machine']) {
    assert.throws(() => inspectVirtualization(signals({
      '/sys/class/dmi/id/product_name': cloud,
    })), /cloud virtual machine/);
  }
  assert.throws(() => inspectVirtualization(signals({
    '/sys/class/dmi/id/product_name': 'Virtual Machine',
    '/sys/class/dmi/id/sys_vendor': 'Microsoft Corporation',
  })), /cloud virtual machine/);
});

test('provisioning requires Linux root, explicit disposable acknowledgement, and local VM evidence', () => {
  const base = {
    platform: 'linux',
    euid: 0,
    now: () => NOW,
    randomBytes: () => Buffer.alloc(32, 0xab),
    inspect: () => ({ provider: 'qemu-kvm' }),
    writeMarker: (marker) => marker,
  };
  assert.throws(() => provisionVmAdapter({ snapshotId: 'snapshot-001', acknowledge: false }, base), /acknowledge/);
  assert.throws(() => provisionVmAdapter({ snapshotId: 'snapshot-001', acknowledge: true }, { ...base, platform: 'darwin' }), /Linux/);
  assert.throws(() => provisionVmAdapter({ snapshotId: 'snapshot-001', acknowledge: true }, { ...base, euid: 501 }), /root/);

  const marker = provisionVmAdapter({ snapshotId: 'snapshot-001', acknowledge: true }, base);
  assert.deepEqual(marker, validMarker({ provisioning_nonce: 'ab'.repeat(32) }));
});

test('marker validation rejects missing, unsafe, stale, mismatched, and provider-divergent markers', () => {
  const raw = Buffer.from(`${JSON.stringify(validMarker())}\n`);
  const base = {
    platform: 'linux',
    now: NOW,
    inspect: () => ({ provider: 'qemu-kvm' }),
    readMarker: () => ({ marker: validMarker(), raw, stat: { uid: 0, mode: 0o100644 } }),
  };
  const binding = validateVmAdapterMarker('snapshot-001', base);
  assert.equal(binding.marker.virtualization_provider, 'qemu-kvm');
  assert.match(binding.markerSha256, /^[0-9a-f]{64}$/);

  assert.throws(() => validateVmAdapterMarker('snapshot-002', base), /snapshot/);
  assert.throws(() => validateVmAdapterMarker('snapshot-001', {
    ...base,
    readMarker: () => { throw new Error('missing'); },
  }), /missing/);
  assert.throws(() => validateVmAdapterMarker('snapshot-001', {
    ...base,
    readMarker: () => ({ marker: validMarker(), raw, stat: { uid: 501, mode: 0o100666 } }),
  }), /owner|permissions/);
  assert.throws(() => validateVmAdapterMarker('snapshot-001', {
    ...base,
    now: new Date('2026-08-20T00:00:00.000Z'),
  }), /stale/);
  assert.throws(() => validateVmAdapterMarker('snapshot-001', {
    ...base,
    inspect: () => ({ provider: 'vmware' }),
  }), /provider/);
});

test('provisioning CLI fails safely outside a Linux root VM and never reflects input', { skip: process.platform === 'linux' }, () => {
  const script = path.join(root, 'scripts', 'provision-vm-adapter');
  const result = spawnSync(process.execPath, [script, 'snapshot-secret', '--acknowledge-disposable-snapshot'], {
    encoding: 'utf8',
  });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, 'VM adapter could not be provisioned.\n');
  assert.doesNotMatch(result.stderr, /snapshot-secret/);
  assert.notEqual(fs.statSync(script).mode & 0o111, 0);
});

test('published marker schema locks the exact local adapter contract', () => {
  const schema = JSON.parse(fs.readFileSync(
    path.join(root, 'curriculum', 'schema', 'vm-adapter-marker.schema.json'),
    'utf8',
  ));
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(schema.required.sort(), Object.keys(validMarker()).sort());
  assert.deepEqual(schema.properties.virtualization_provider.enum, [
    'qemu-kvm', 'vmware', 'virtualbox', 'parallels', 'apple-virtualization', 'utm',
  ]);
  assert.equal(schema.properties.disposable_snapshot_acknowledged.const, true);
});
