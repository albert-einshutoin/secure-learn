'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const MAX_RECEIPT_BYTES = 16 * 1024;
const MAX_IDENTITY_BYTES = 4 * 1024;
const MAX_LIFETIME_MS = 4 * 60 * 60 * 1000;
const DEFAULT_LIFETIME_MS = 60 * 60 * 1000;
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const RECEIPT_FIELDS = [
  'version',
  'platform',
  'lab_id',
  'snapshot_id',
  'issuer',
  'issued_at',
  'expires_at',
  'nonce',
  'machine_id_sha256',
  'boot_id_sha256',
];
const SNAPSHOT_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const LAB_IDS = new Set(['s5', 's6']);
const ISSUER = 'secure-learn-vm-bootstrap';

function isInside(parent, child) {
  const relative = path.relative(parent, child);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function resolveReceiptPath(receiptPath, repositoryRoot) {
  if (typeof receiptPath !== 'string' || receiptPath.length === 0 || receiptPath.includes('\u0000')) {
    throw new Error('Linux VM receipt path is required.');
  }
  const lexicalRoot = path.resolve(repositoryRoot);
  const root = fs.realpathSync(lexicalRoot);
  const trustedDirectory = path.join(root, 'evidence', 'vm-receipts');
  let requested;
  if (path.isAbsolute(receiptPath)) {
    const lexicalRequested = path.resolve(receiptPath);
    requested = isInside(lexicalRoot, lexicalRequested)
      ? path.join(root, path.relative(lexicalRoot, lexicalRequested))
      : lexicalRequested;
  } else {
    requested = path.resolve(root, receiptPath);
  }
  if (!isInside(trustedDirectory, requested)) {
    throw new Error('Linux VM receipt must be inside the trusted receipt directory.');
  }
  return { root, trustedDirectory, requested };
}

function assertSecureAncestry(root, parent) {
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  const relative = path.relative(root, parent);
  const components = relative === '' ? [] : relative.split(path.sep);
  let current = root;
  for (const component of [null, ...components]) {
    if (component !== null) current = path.join(current, component);
    let stat;
    try {
      stat = fs.lstatSync(current);
    } catch {
      throw new Error('Linux VM receipt ancestry does not exist.');
    }
    if (stat.isSymbolicLink()) throw new Error('Linux VM receipt ancestry must not contain a symbolic link.');
    if (!stat.isDirectory()) throw new Error('Linux VM receipt ancestry must contain only directories.');
    if (uid !== null && stat.uid !== uid) throw new Error('Linux VM receipt ancestry must be owned by the current user.');
    if ((stat.mode & 0o022) !== 0) throw new Error('Linux VM receipt ancestry has unsafe permissions.');
  }
}

function parseCanonicalTimestamp(value) {
  if (typeof value !== 'string') throw new Error('Linux VM receipt timestamp is invalid.');
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) {
    throw new Error('Linux VM receipt timestamp is invalid.');
  }
  return date;
}

function validateReceiptContract(receipt, expectedLabId, now) {
  if (
    receipt === null
    || typeof receipt !== 'object'
    || Array.isArray(receipt)
    || Object.keys(receipt).sort().join(',') !== [...RECEIPT_FIELDS].sort().join(',')
    || receipt.version !== 1
    || receipt.platform !== 'linux-vm'
    || receipt.issuer !== ISSUER
    || !LAB_IDS.has(receipt.lab_id)
  ) {
    throw new Error('Linux VM receipt has an unsupported contract.');
  }
  if (receipt.lab_id !== expectedLabId) throw new Error('Linux VM receipt is not bound to the requested lab.');
  if (!SNAPSHOT_ID.test(receipt.snapshot_id) || receipt.snapshot_id.includes('..')) {
    throw new Error('Linux VM receipt snapshot identifier is invalid.');
  }
  if (!SHA256.test(receipt.nonce)) throw new Error('Linux VM receipt nonce is invalid.');
  if (!SHA256.test(receipt.machine_id_sha256)) throw new Error('Linux VM receipt machine identifier is invalid.');
  if (!SHA256.test(receipt.boot_id_sha256)) throw new Error('Linux VM receipt boot identifier is invalid.');

  const issuedAt = parseCanonicalTimestamp(receipt.issued_at);
  const expiresAt = parseCanonicalTimestamp(receipt.expires_at);
  if (expiresAt <= issuedAt) throw new Error('Linux VM receipt time window is invalid.');
  if (expiresAt - issuedAt > MAX_LIFETIME_MS) throw new Error('Linux VM receipt lifetime exceeds four hours.');
  const current = now instanceof Date ? now : new Date(now);
  if (!Number.isFinite(current.getTime())) throw new Error('Linux VM receipt validation time is invalid.');
  if (issuedAt.getTime() - current.getTime() > CLOCK_SKEW_MS) throw new Error('Linux VM receipt is not yet valid.');
  if (current >= expiresAt) throw new Error('Linux VM receipt is expired.');
}

function validateVmReceipt(receiptPath, options = {}) {
  const repositoryRoot = options.repositoryRoot || fs.realpathSync(path.resolve(__dirname, '../..'));
  const expectedLabId = options.expectedLabId;
  const now = options.now || new Date();
  if (!LAB_IDS.has(expectedLabId)) throw new Error('Linux VM receipt requested lab is invalid.');

  const { root, requested } = resolveReceiptPath(receiptPath, repositoryRoot);
  assertSecureAncestry(root, path.dirname(requested));
  let linkStat;
  try {
    linkStat = fs.lstatSync(requested);
  } catch {
    throw new Error('Linux VM receipt does not exist.');
  }
  if (linkStat.isSymbolicLink()) throw new Error('Linux VM receipt must not be a symbolic link.');

  let descriptor;
  try {
    // O_NOFOLLOW plus all reads through one descriptor closes the validation/
    // read race; no pathname is re-opened after its security checks.
    descriptor = fs.openSync(requested, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) throw new Error('Linux VM receipt must be a regular file.');
    if (stat.size > MAX_RECEIPT_BYTES) throw new Error('Linux VM receipt is too large.');
    if ((stat.mode & 0o777) !== 0o600) throw new Error('Linux VM receipt has unsafe permissions.');
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
      throw new Error('Linux VM receipt must be owned by the current user.');
    }

    const content = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < content.length) {
      const read = fs.readSync(descriptor, content, offset, content.length - offset, offset);
      if (read === 0) break;
      offset += read;
    }
    if (offset !== content.length) throw new Error('Linux VM receipt could not be read completely.');
    let receipt;
    try {
      receipt = JSON.parse(content.toString('utf8'));
    } catch {
      throw new Error('Linux VM receipt must contain valid JSON.');
    }
    validateReceiptContract(receipt, expectedLabId, now);
    const identity = options.identityHashes || {
      machine: hashIdentity(readIdentityFile('/etc/machine-id')),
      boot: hashIdentity(readIdentityFile('/proc/sys/kernel/random/boot_id')),
    };
    if (receipt.machine_id_sha256 !== identity.machine || receipt.boot_id_sha256 !== identity.boot) {
      throw new Error('Linux VM receipt does not match the current VM boot.');
    }
    return receipt;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readIdentityFile(sourcePath) {
  let descriptor;
  try {
    descriptor = fs.openSync(sourcePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.size === 0 || stat.size > MAX_IDENTITY_BYTES) {
      throw new Error('Linux VM identity source is invalid.');
    }
    return fs.readFileSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function hashIdentity(value) {
  if (!Buffer.isBuffer(value) || value.length === 0 || value.length > MAX_IDENTITY_BYTES) {
    throw new Error('Linux VM identity source is invalid.');
  }
  const normalized = value.toString('utf8').trim();
  if (!/^[0-9A-Za-z-]{8,128}$/.test(normalized)) throw new Error('Linux VM identity source is invalid.');
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

function createVmReceipt(input, dependencies = {}) {
  const platform = dependencies.platform || process.platform;
  if (platform !== 'linux') throw new Error('Receipts can only be issued inside a Linux VM.');
  if (!LAB_IDS.has(input.labId)) throw new Error('Receipt lab must be s5 or s6.');
  if (!SNAPSHOT_ID.test(input.snapshotId) || input.snapshotId.includes('..')) {
    throw new Error('Receipt snapshot identifier is invalid.');
  }
  const lifetimeMs = dependencies.lifetimeMs ?? DEFAULT_LIFETIME_MS;
  if (!Number.isInteger(lifetimeMs) || lifetimeMs <= 0 || lifetimeMs > MAX_LIFETIME_MS) {
    throw new Error('Receipt lifetime must be between one millisecond and four hours.');
  }
  const now = (dependencies.now || (() => new Date()))();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error('Receipt issue time is invalid.');
  const randomBytes = dependencies.randomBytes || crypto.randomBytes;
  const nonce = randomBytes(32);
  if (!Buffer.isBuffer(nonce) || nonce.length !== 32) throw new Error('Receipt nonce source is invalid.');
  const readIdentity = dependencies.readIdentity || readIdentityFile;

  return {
    version: 1,
    platform: 'linux-vm',
    lab_id: input.labId,
    snapshot_id: input.snapshotId,
    issuer: ISSUER,
    issued_at: now.toISOString(),
    expires_at: new Date(now.getTime() + lifetimeMs).toISOString(),
    nonce: nonce.toString('hex'),
    machine_id_sha256: hashIdentity(readIdentity('/etc/machine-id')),
    boot_id_sha256: hashIdentity(readIdentity('/proc/sys/kernel/random/boot_id')),
  };
}

function ensureReceiptDirectory(repositoryRoot) {
  const root = fs.realpathSync(repositoryRoot);
  const evidence = path.join(root, 'evidence');
  const trusted = path.join(evidence, 'vm-receipts');
  if (!fs.existsSync(evidence)) fs.mkdirSync(evidence, { mode: 0o755 });
  if (!fs.existsSync(trusted)) fs.mkdirSync(trusted, { mode: 0o700 });
  assertSecureAncestry(root, trusted);
  return trusted;
}

function writeVmReceiptAtomic(outputPath, receipt, options = {}) {
  const repositoryRoot = options.repositoryRoot || fs.realpathSync(path.resolve(__dirname, '../..'));
  validateReceiptContract(receipt, receipt && receipt.lab_id, options.now || new Date());
  const { requested } = resolveReceiptPath(outputPath, repositoryRoot);
  ensureReceiptDirectory(repositoryRoot);
  if (fs.existsSync(requested)) throw new Error('Linux VM receipt already exists.');

  const temporary = path.join(
    path.dirname(requested),
    `.${path.basename(requested)}.tmp-${crypto.randomBytes(8).toString('hex')}`,
  );
  let descriptor;
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      0o600,
    );
    const payload = `${JSON.stringify(receipt, null, 2)}\n`;
    if (Buffer.byteLength(payload, 'utf8') > MAX_RECEIPT_BYTES) {
      throw new Error('Linux VM receipt is too large.');
    }
    fs.fchmodSync(descriptor, 0o600);
    fs.writeFileSync(descriptor, payload, 'utf8');
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    try {
      // Hard-link creation is atomic and refuses to replace an existing path.
      fs.linkSync(temporary, requested);
    } catch (error) {
      if (error.code === 'EEXIST') throw new Error('Linux VM receipt already exists.');
      throw error;
    }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    fs.rmSync(temporary, { force: true });
  }
}

module.exports = {
  createVmReceipt,
  ensureReceiptDirectory,
  validateVmReceipt,
  writeVmReceiptAtomic,
};
