'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const MARKER_PATH = '/etc/secure-learn/vm-adapter.json';
const MAX_MARKER_BYTES = 16 * 1024;
const MAX_SIGNAL_BYTES = 64 * 1024;
const MAX_MARKER_AGE_MS = 30 * 24 * 60 * 60 * 1000;
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const SNAPSHOT_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const PROVIDERS = new Set([
  'qemu-kvm',
  'vmware',
  'virtualbox',
  'parallels',
  'apple-virtualization',
  'utm',
]);
const MARKER_FIELDS = [
  'version',
  'adapter',
  'snapshot_id',
  'provisioned_at',
  'disposable_snapshot_acknowledged',
  'virtualization_provider',
  'provisioning_nonce',
];
const SIGNAL_PATHS = [
  '/sys/class/dmi/id/product_name',
  '/sys/class/dmi/id/sys_vendor',
  '/sys/class/dmi/id/board_vendor',
  '/sys/class/dmi/id/bios_vendor',
  '/proc/device-tree/model',
  '/proc/device-tree/compatible',
];

function readBoundedFile(sourcePath, maxBytes, fsImpl = fs) {
  let descriptor;
  try {
    descriptor = fsImpl.openSync(sourcePath, fsImpl.constants.O_RDONLY | fsImpl.constants.O_NOFOLLOW);
    const stat = fsImpl.fstatSync(descriptor);
    if (!stat.isFile()) throw new Error('Unsafe VM adapter input.');
    const chunks = [];
    let total = 0;
    while (total <= maxBytes) {
      const buffer = Buffer.alloc(Math.min(1024, maxBytes + 1 - total));
      const count = fsImpl.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      chunks.push(buffer.subarray(0, count));
      total += count;
    }
    if (total === 0 || total > maxBytes) throw new Error('Unsafe VM adapter input.');
    return { raw: Buffer.concat(chunks, total), stat };
  } finally {
    if (descriptor !== undefined) fsImpl.closeSync(descriptor);
  }
}

function defaultReadText(sourcePath) {
  try {
    return readBoundedFile(sourcePath, MAX_SIGNAL_BYTES).raw.toString('utf8');
  } catch {
    return '';
  }
}

function inspectVirtualization(options = {}) {
  const platform = options.platform || process.platform;
  const exists = options.exists || fs.existsSync;
  const readText = options.readText || defaultReadText;
  if (platform !== 'linux') throw new Error('VM adapter requires Linux.');

  if (exists('/.dockerenv') || exists('/run/.containerenv')) {
    throw new Error('VM adapter cannot run inside a container.');
  }
  const cgroups = `${readText('/proc/1/cgroup')}\n${readText('/proc/self/cgroup')}`.toLowerCase();
  if (/(?:docker|containerd|kubepods|libpod|podman|lxc|systemd-nspawn)/.test(cgroups)) {
    throw new Error('VM adapter cannot run inside a container.');
  }

  const evidence = SIGNAL_PATHS.map((source) => readText(source)).join('\n').toLowerCase();
  if (/(?:amazon ec2|google compute engine|google cloud|azure|microsoft corporation[\s\S]*virtual machine|virtual machine[\s\S]*microsoft corporation)/.test(evidence)) {
    throw new Error('A cloud virtual machine is outside the local disposable VM contract.');
  }
  const providerPatterns = [
    ['utm', /\butm\b/],
    ['apple-virtualization', /apple virtualization|virtualmac/],
    ['parallels', /parallels/],
    ['virtualbox', /virtualbox|innotek/],
    ['vmware', /vmware/],
    ['qemu-kvm', /\bqemu\b|\bkvm\b|bochs/],
  ];
  const match = providerPatterns.find(([, pattern]) => pattern.test(evidence));
  if (!match) throw new Error('No supported local virtual machine evidence was found.');
  return { provider: match[0] };
}

function parseTimestamp(value) {
  if (typeof value !== 'string') throw new Error('VM adapter marker timestamp is invalid.');
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new Error('VM adapter marker timestamp is invalid.');
  }
  return parsed;
}

function validateMarkerContract(marker, expectedSnapshotId, provider, now) {
  if (
    marker === null
    || typeof marker !== 'object'
    || Array.isArray(marker)
    || Object.keys(marker).sort().join(',') !== [...MARKER_FIELDS].sort().join(',')
    || marker.version !== 1
    || marker.adapter !== 'secure-learn-linux-vm'
    || marker.disposable_snapshot_acknowledged !== true
    || !PROVIDERS.has(marker.virtualization_provider)
    || !SHA256.test(marker.provisioning_nonce)
  ) {
    throw new Error('VM adapter marker has an unsupported contract.');
  }
  if (!SNAPSHOT_ID.test(marker.snapshot_id) || marker.snapshot_id.includes('..')) {
    throw new Error('VM adapter marker snapshot is invalid.');
  }
  if (marker.snapshot_id !== expectedSnapshotId) throw new Error('VM adapter marker snapshot does not match.');
  if (marker.virtualization_provider !== provider) throw new Error('VM adapter marker provider does not match current evidence.');
  const provisionedAt = parseTimestamp(marker.provisioned_at);
  const current = now instanceof Date ? now : new Date(now);
  if (provisionedAt.getTime() - current.getTime() > CLOCK_SKEW_MS) throw new Error('VM adapter marker is from the future.');
  if (current.getTime() - provisionedAt.getTime() > MAX_MARKER_AGE_MS) throw new Error('VM adapter marker is stale.');
}

function readMarkerFile(markerPath = MARKER_PATH) {
  const markerDirectory = path.dirname(markerPath);
  let directoryStat;
  try {
    directoryStat = fs.lstatSync(markerDirectory);
  } catch {
    throw new Error('VM adapter marker is missing.');
  }
  if (
    directoryStat.isSymbolicLink()
    || !directoryStat.isDirectory()
    || directoryStat.uid !== 0
    || (directoryStat.mode & 0o022) !== 0
  ) {
    throw new Error('VM adapter marker directory is unsafe.');
  }
  let linkStat;
  try {
    linkStat = fs.lstatSync(markerPath);
  } catch {
    throw new Error('VM adapter marker is missing.');
  }
  if (linkStat.isSymbolicLink()) throw new Error('VM adapter marker must not be a symbolic link.');
  const { raw, stat } = readBoundedFile(markerPath, MAX_MARKER_BYTES);
  let marker;
  try {
    marker = JSON.parse(raw.toString('utf8'));
  } catch {
    throw new Error('VM adapter marker JSON is invalid.');
  }
  return { marker, raw, stat };
}

function validateVmAdapterMarker(expectedSnapshotId, options = {}) {
  const platform = options.platform || process.platform;
  if (platform !== 'linux') throw new Error('VM adapter marker requires Linux.');
  const inspect = options.inspect || inspectVirtualization;
  const readMarker = options.readMarker || readMarkerFile;
  const now = options.now || new Date();
  const environment = inspect();
  const result = readMarker();
  if (!result || !result.stat || result.stat.uid !== 0) throw new Error('VM adapter marker owner is invalid.');
  if ((result.stat.mode & 0o022) !== 0 || (result.stat.mode & 0o111) !== 0) {
    throw new Error('VM adapter marker permissions are invalid.');
  }
  validateMarkerContract(result.marker, expectedSnapshotId, environment.provider, now);
  return {
    marker: result.marker,
    markerSha256: crypto.createHash('sha256').update(result.raw).digest('hex'),
  };
}

function writeMarkerAtomic(marker) {
  const directory = path.dirname(MARKER_PATH);
  if (!fs.existsSync(directory)) fs.mkdirSync(directory, { mode: 0o755 });
  const directoryStat = fs.lstatSync(directory);
  if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory() || directoryStat.uid !== 0 || (directoryStat.mode & 0o022) !== 0) {
    throw new Error('VM adapter marker directory is unsafe.');
  }
  if (fs.existsSync(MARKER_PATH) && fs.lstatSync(MARKER_PATH).isSymbolicLink()) {
    throw new Error('VM adapter marker must not be a symbolic link.');
  }

  const temporary = path.join(directory, `.vm-adapter.json.tmp-${crypto.randomBytes(8).toString('hex')}`);
  let descriptor;
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      0o600,
    );
    fs.writeFileSync(descriptor, `${JSON.stringify(marker, null, 2)}\n`, 'utf8');
    fs.fsyncSync(descriptor);
    fs.fchmodSync(descriptor, 0o644);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, MARKER_PATH);
    const finalStat = fs.lstatSync(MARKER_PATH);
    if (!finalStat.isFile() || finalStat.isSymbolicLink() || finalStat.uid !== 0 || (finalStat.mode & 0o777) !== 0o644) {
      throw new Error('VM adapter marker publication failed.');
    }
    const directoryDescriptor = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
      fs.fsyncSync(directoryDescriptor);
    } finally {
      fs.closeSync(directoryDescriptor);
    }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    fs.rmSync(temporary, { force: true });
  }
}

function provisionVmAdapter(input, dependencies = {}) {
  const platform = dependencies.platform || process.platform;
  const euid = dependencies.euid ?? (typeof process.geteuid === 'function' ? process.geteuid() : null);
  if (platform !== 'linux') throw new Error('VM adapter provisioning requires Linux.');
  if (euid !== 0) throw new Error('VM adapter provisioning requires root.');
  if (input.acknowledge !== true) throw new Error('Disposable snapshot acknowledgement is required.');
  if (!SNAPSHOT_ID.test(input.snapshotId) || input.snapshotId.includes('..')) {
    throw new Error('VM adapter snapshot is invalid.');
  }
  const environment = (dependencies.inspect || inspectVirtualization)();
  if (!environment || !PROVIDERS.has(environment.provider)) {
    throw new Error('VM adapter provider evidence is unsupported.');
  }
  const now = (dependencies.now || (() => new Date()))();
  const nonce = (dependencies.randomBytes || crypto.randomBytes)(32);
  if (!(now instanceof Date) || !Number.isFinite(now.getTime()) || !Buffer.isBuffer(nonce) || nonce.length !== 32) {
    throw new Error('VM adapter provisioning inputs are invalid.');
  }
  const marker = {
    version: 1,
    adapter: 'secure-learn-linux-vm',
    snapshot_id: input.snapshotId,
    provisioned_at: now.toISOString(),
    disposable_snapshot_acknowledged: true,
    virtualization_provider: environment.provider,
    provisioning_nonce: nonce.toString('hex'),
  };
  (dependencies.writeMarker || writeMarkerAtomic)(marker);
  return marker;
}

module.exports = {
  inspectVirtualization,
  provisionVmAdapter,
  validateVmAdapterMarker,
};
