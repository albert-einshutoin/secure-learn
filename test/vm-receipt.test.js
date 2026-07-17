const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  createVmReceipt,
  readIdentityFile,
  validateVmReceipt,
  writeVmReceiptAtomic,
} = require('../scripts/lib/vm-receipt');

const NOW = new Date('2026-07-18T00:00:00.000Z');
const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const root = path.resolve(__dirname, '..');

function validReceipt(overrides = {}) {
  return {
    version: 1,
    platform: 'linux-vm',
    lab_id: 's5',
    snapshot_id: 'snapshot-001',
    issuer: 'secure-learn-vm-bootstrap',
    issued_at: '2026-07-17T23:59:00.000Z',
    expires_at: '2026-07-18T00:59:00.000Z',
    nonce: '1'.repeat(64),
    machine_id_sha256: HASH_A,
    boot_id_sha256: HASH_B,
    assurance: 'operator-attested-local-vm',
    adapter_marker_sha256: 'c'.repeat(64),
    provisioning_nonce: 'd'.repeat(64),
    virtualization_provider: 'qemu-kvm',
    ...overrides,
  };
}

function makeRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-learn-vm-receipt-'));
  fs.mkdirSync(path.join(root, 'evidence'), { mode: 0o755 });
  fs.mkdirSync(path.join(root, 'evidence', 'vm-receipts'), { mode: 0o700 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function writeReceipt(root, receipt = validReceipt(), name = 's5.json') {
  const target = path.join(root, 'evidence', 'vm-receipts', name);
  fs.writeFileSync(target, `${JSON.stringify(receipt)}\n`, { mode: 0o600 });
  return target;
}

function validationOptions(root, overrides = {}) {
  return {
    repositoryRoot: root,
    expectedLabId: 's5',
    now: NOW,
    identityHashes: { machine: HASH_A, boot: HASH_B },
    validateAdapter: () => ({
      marker: {
        snapshot_id: 'snapshot-001',
        provisioning_nonce: 'd'.repeat(64),
        virtualization_provider: 'qemu-kvm',
      },
      markerSha256: 'c'.repeat(64),
    }),
    ...overrides,
  };
}

test('validates a fresh local readiness receipt bound to the requested lab', (t) => {
  const root = makeRoot(t);
  const target = writeReceipt(root);
  const result = validateVmReceipt(target, validationOptions(root));
  assert.deepEqual(result, validReceipt());

  assert.deepEqual(
    validateVmReceipt('evidence/vm-receipts/s5.json', validationOptions(root)),
    validReceipt(),
  );
});

test('rejects receipt path escape, symlink file, symlink parent, unsafe modes, and oversized input', (t) => {
  const root = makeRoot(t);
  const target = writeReceipt(root);
  const options = validationOptions(root);

  const outside = path.join(root, 'outside.json');
  fs.writeFileSync(outside, JSON.stringify(validReceipt()), { mode: 0o600 });
  assert.throws(() => validateVmReceipt(outside, options), /trusted receipt directory/);

  const link = path.join(root, 'evidence', 'vm-receipts', 'link.json');
  fs.symlinkSync(target, link);
  assert.throws(() => validateVmReceipt(link, options), /symbolic link/);

  const alternate = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-learn-vm-alternate-'));
  t.after(() => fs.rmSync(alternate, { recursive: true, force: true }));
  fs.rmSync(path.join(root, 'evidence', 'vm-receipts'), { recursive: true });
  fs.symlinkSync(alternate, path.join(root, 'evidence', 'vm-receipts'));
  assert.throws(() => validateVmReceipt(link, options), /symbolic link/);

  fs.unlinkSync(path.join(root, 'evidence', 'vm-receipts'));
  fs.mkdirSync(path.join(root, 'evidence', 'vm-receipts'), { mode: 0o700 });
  const unsafe = writeReceipt(root);
  fs.chmodSync(unsafe, 0o640);
  assert.throws(() => validateVmReceipt(unsafe, options), /permissions/);
  fs.chmodSync(unsafe, 0o600);
  fs.writeFileSync(unsafe, Buffer.alloc(16 * 1024 + 1));
  assert.throws(() => validateVmReceipt(unsafe, options), /too large/);

  fs.writeFileSync(unsafe, JSON.stringify(validReceipt()), { mode: 0o600 });
  fs.chmodSync(path.dirname(unsafe), 0o777);
  assert.throws(() => validateVmReceipt(unsafe, options), /ancestry.*permissions/);
});

test('rejects unknown fields, wrong lab, invalid time windows, identifiers, and digests', (t) => {
  const cases = [
    [validReceipt({ extra: true }), /unsupported contract/],
    [validReceipt({ lab_id: 's6' }), /requested lab/],
    [validReceipt({ snapshot_id: '../escape' }), /snapshot/],
    [validReceipt({ issued_at: '2026-07-17T23:59:00Z' }), /timestamp/],
    [validReceipt({ issued_at: '2026-07-18T00:06:00.000Z' }), /not yet valid/],
    [validReceipt({ expires_at: '2026-07-17T23:59:00.000Z' }), /time window/],
    [validReceipt({ expires_at: '2026-07-18T05:00:00.000Z' }), /four hours/],
    [validReceipt({ expires_at: '2026-07-17T23:59:30.000Z' }), /expired/],
    [validReceipt({ nonce: 'x'.repeat(64) }), /nonce/],
    [validReceipt({ machine_id_sha256: 'a'.repeat(63) }), /machine/],
    [validReceipt({ boot_id_sha256: 'B'.repeat(64) }), /boot/],
    [validReceipt({ assurance: 'cryptographic-attestation' }), /unsupported contract/],
    [validReceipt({ adapter_marker_sha256: 'c'.repeat(63) }), /adapter marker/],
    [validReceipt({ provisioning_nonce: 'D'.repeat(64) }), /provisioning nonce/],
    [validReceipt({ virtualization_provider: 'aws' }), /virtualization provider/],
  ];

  for (const [receipt, error] of cases) {
    const root = makeRoot(t);
    const target = writeReceipt(root, receipt);
    assert.throws(
      () => validateVmReceipt(target, validationOptions(root)),
      error,
    );
  }
});

test('rejects a receipt copied from another VM boot', (t) => {
  const root = makeRoot(t);
  const target = writeReceipt(root);
  assert.throws(() => validateVmReceipt(target, validationOptions(root, {
    identityHashes: { machine: HASH_A, boot: 'c'.repeat(64) },
  })), /current VM boot/);
});

test('receipt validation rechecks the current adapter marker and exact provenance binding', (t) => {
  const tempRoot = makeRoot(t);
  const target = writeReceipt(tempRoot);
  let requestedSnapshot;
  const options = validationOptions(tempRoot, {
    validateAdapter: (snapshotId) => {
      requestedSnapshot = snapshotId;
      return {
        marker: {
          snapshot_id: snapshotId,
          provisioning_nonce: 'd'.repeat(64),
          virtualization_provider: 'qemu-kvm',
        },
        markerSha256: 'c'.repeat(64),
      };
    },
  });
  assert.doesNotThrow(() => validateVmReceipt(target, options));
  assert.equal(requestedSnapshot, 'snapshot-001');

  const mismatches = [
    { markerSha256: 'e'.repeat(64) },
    { marker: { snapshot_id: 'snapshot-002', provisioning_nonce: 'd'.repeat(64), virtualization_provider: 'qemu-kvm' } },
    { marker: { snapshot_id: 'snapshot-001', provisioning_nonce: 'e'.repeat(64), virtualization_provider: 'qemu-kvm' } },
    { marker: { snapshot_id: 'snapshot-001', provisioning_nonce: 'd'.repeat(64), virtualization_provider: 'vmware' } },
  ];
  for (const mismatch of mismatches) {
    assert.throws(() => validateVmReceipt(target, validationOptions(tempRoot, {
      validateAdapter: () => ({
        marker: {
          snapshot_id: 'snapshot-001',
          provisioning_nonce: 'd'.repeat(64),
          virtualization_provider: 'qemu-kvm',
        },
        markerSha256: 'c'.repeat(64),
        ...mismatch,
      }),
    })), /current VM adapter/);
  }
});

test('handwritten receipts fail when current adapter evidence is missing or unsafe', (t) => {
  const failures = [
    'VM adapter marker is missing.',
    'VM adapter marker permissions are invalid.',
    'No supported local virtual machine evidence was found.',
    'VM adapter cannot run inside a container.',
    'A cloud virtual machine is outside the local disposable VM contract.',
  ];
  for (const message of failures) {
    const tempRoot = makeRoot(t);
    const target = writeReceipt(tempRoot);
    assert.throws(() => validateVmReceipt(target, validationOptions(tempRoot, {
      validateAdapter: () => { throw new Error(message); },
    })), new RegExp(message.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});

test('issuer creates a Linux-only, lab-bound receipt without external commands', () => {
  const receipt = createVmReceipt({ labId: 's6', snapshotId: 'snapshot-002' }, {
    platform: 'linux',
    now: () => NOW,
    randomBytes: () => Buffer.alloc(32, 0xcd),
    readIdentity: (source) => source.includes('machine-id') ? Buffer.from('machine-id-001\n') : Buffer.from('boot-id-001\n'),
    validateAdapter: () => ({
      marker: { provisioning_nonce: 'e'.repeat(64), virtualization_provider: 'qemu-kvm' },
      markerSha256: 'f'.repeat(64),
    }),
  });
  assert.equal(receipt.lab_id, 's6');
  assert.equal(receipt.issued_at, NOW.toISOString());
  assert.equal(receipt.expires_at, '2026-07-18T01:00:00.000Z');
  assert.equal(receipt.nonce, 'cd'.repeat(32));
  assert.match(receipt.machine_id_sha256, /^[0-9a-f]{64}$/);
  assert.match(receipt.boot_id_sha256, /^[0-9a-f]{64}$/);
  assert.equal(receipt.assurance, 'operator-attested-local-vm');
  assert.equal(receipt.adapter_marker_sha256, 'f'.repeat(64));

  assert.throws(() => createVmReceipt({ labId: 's5', snapshotId: 'snapshot-001' }, {
    platform: 'darwin',
  }), /Linux VM/);
});

test('issuer writes a private receipt atomically without replacing an existing receipt', (t) => {
  const root = makeRoot(t);
  const output = path.join(root, 'evidence', 'vm-receipts', 'issued.json');
  writeVmReceiptAtomic(output, validReceipt(), { repositoryRoot: root, now: NOW });
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(fs.readFileSync(output, 'utf8')), validReceipt());
  assert.throws(() => writeVmReceiptAtomic(output, validReceipt(), { repositoryRoot: root, now: NOW }), /already exists/);
  assert.deepEqual(
    fs.readdirSync(path.dirname(output)).filter((name) => name.includes('.tmp-')),
    [],
  );
});

test('identity reader consumes size-zero procfs content from one bounded descriptor', () => {
  const content = Buffer.from('boot-id-001\n');
  let offset = 0;
  let closes = 0;
  const fsImpl = {
    constants: { O_RDONLY: 0, O_NOFOLLOW: 0x100 },
    openSync: () => 17,
    fstatSync: () => ({ isFile: () => true, size: 0 }),
    readSync: (_fd, buffer, bufferOffset, length) => {
      const count = Math.min(length, content.length - offset);
      if (count === 0) return 0;
      content.copy(buffer, bufferOffset, offset, offset + count);
      offset += count;
      return count;
    },
    closeSync: () => { closes += 1; },
  };
  assert.deepEqual(readIdentityFile('/proc/fake-boot-id', { fsImpl }), content);
  assert.equal(closes, 1);
});

test('identity reader rejects empty and over-limit streams even when stat size is zero', () => {
  function fakeFs(byteCount) {
    let remaining = byteCount;
    return {
      constants: { O_RDONLY: 0, O_NOFOLLOW: 0x100 },
      openSync: () => 18,
      fstatSync: () => ({ isFile: () => true, size: 0 }),
      readSync: (_fd, buffer, offset, length) => {
        const count = Math.min(length, remaining);
        buffer.fill(0x61, offset, offset + count);
        remaining -= count;
        return count;
      },
      closeSync: () => {},
    };
  }
  assert.throws(() => readIdentityFile('/proc/empty', { fsImpl: fakeFs(0) }), /identity source/);
  assert.throws(() => readIdentityFile('/proc/large', { fsImpl: fakeFs(4 * 1024 + 1) }), /identity source/);
});

test('real Linux procfs boot ID can be read despite reporting zero size', { skip: process.platform !== 'linux' }, () => {
  assert.match(readIdentityFile('/proc/sys/kernel/random/boot_id').toString('utf8').trim(), /^[0-9a-f-]{36}$/);
});

test('receipt output accepts only a direct JSON basename in the trusted directory', (t) => {
  const tempRoot = makeRoot(t);
  const outside = path.join(tempRoot, 'outside.json');
  const externalDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-learn-receipt-external-'));
  const externalTarget = path.join(externalDirectory, 'receipt.json');
  fs.symlinkSync(externalDirectory, path.join(tempRoot, 'evidence', 'vm-receipts', 'nested'));
  t.after(() => fs.rmSync(externalDirectory, { recursive: true, force: true }));
  for (const output of [
    'evidence/vm-receipts/nested/receipt.json',
    'evidence/vm-receipts/../outside.json',
    'evidence/vm-receipts/bad\\name.json',
    'evidence/vm-receipts/not-json.txt',
  ]) {
    assert.throws(() => writeVmReceiptAtomic(output, validReceipt(), {
      repositoryRoot: tempRoot,
      now: NOW,
    }), /direct JSON file|trusted receipt/);
  }
  assert.equal(fs.existsSync(outside), false);
  assert.equal(fs.existsSync(externalTarget), false);
});

test('receipt issuer is executable, dependency-free, and keeps generated receipts ignored', () => {
  const issuer = path.join(root, 'scripts', 'issue-vm-receipt');
  assert.notEqual(fs.statSync(issuer).mode & 0o111, 0);
  assert.doesNotMatch(fs.readFileSync(issuer, 'utf8'), /child_process|spawn|exec/);
  assert.match(fs.readFileSync(path.join(root, '.gitignore'), 'utf8'), /^\/evidence\/vm-receipts\/$/m);
});
