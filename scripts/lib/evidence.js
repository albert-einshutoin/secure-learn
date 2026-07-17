const { createHash, timingSafeEqual } = require('node:crypto');

const FAILURE_STAGES = Object.freeze([
  'environment',
  'safety',
  'startup',
  'attack',
  'telemetry',
  'pipeline',
  'control',
  'regression',
  'evidence',
  'cleanup',
]);

const INPUT_FIELDS = Object.freeze([
  'lab',
  'manifest_version',
  'platform',
  'started_at',
  'ended_at',
  'target',
  'results',
]);
const RECEIPT_FIELDS = Object.freeze([...INPUT_FIELDS, 'outcome', 'sha256']);
const OUTCOMES = new Set([...FAILURE_STAGES, 'verified']);

const MAX_DURATION_MS = 24 * 60 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const CANONICAL_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;
const SAFE_IDENTIFIER = /^[a-z][a-z0-9-]{0,63}$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const SHA256 = /^[a-f0-9]{64}$/u;

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object') return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertDataProperties(value, label) {
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new TypeError(`${label} must not contain symbol keys`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(`${label}.${key} must be an enumerable data property`);
    }
  }
}

function assertExactOwnFields(value, expected, label) {
  assertDataProperties(value, label);
  const expectedSet = new Set(expected);
  for (const field of Object.keys(value)) {
    if (!expectedSet.has(field)) throw new TypeError(`unknown ${label} field: ${field}`);
  }
  for (const field of expected) {
    if (!Object.hasOwn(value, field)) throw new TypeError(`${field} must be an own ${label} field`);
  }
}

function classifyOutcome(results) {
  if (!isPlainRecord(results)) throw new TypeError('results must be a plain object');
  assertDataProperties(results, 'results');
  const expected = new Set(FAILURE_STAGES);
  for (const field of Object.keys(results)) {
    if (!expected.has(field)) throw new TypeError(`unknown result field: ${field}`);
  }

  // Validate the complete record before classifying. Otherwise an early false
  // could hide a later inherited or missing stage and overstate assurance.
  for (const stage of FAILURE_STAGES) {
    if (!Object.hasOwn(results, stage)) throw new TypeError(`${stage} must be an own boolean field`);
    if (typeof results[stage] !== 'boolean') throw new TypeError(`${stage} must be a boolean`);
  }

  // This order is part of the learning contract: report the earliest broken
  // prerequisite so learners fix environment and safety before later signals.
  for (const stage of FAILURE_STAGES) if (!results[stage]) return stage;
  return 'verified';
}

function codePointCompare(left, right) {
  const leftPoints = [...left].map((character) => character.codePointAt(0));
  const rightPoints = [...right].map((character) => character.codePointAt(0));
  const sharedLength = Math.min(leftPoints.length, rightPoints.length);

  for (let index = 0; index < sharedLength; index += 1) {
    if (leftPoints[index] !== rightPoints[index]) return leftPoints[index] - rightPoints[index];
  }
  return leftPoints.length - rightPoints.length;
}

function stableSerialize(value) {
  if (value !== null && typeof value === 'object') {
    const entries = Object.keys(value)
      .sort(codePointCompare)
      .map((key) => `${JSON.stringify(key)}:${stableSerialize(value[key])}`);
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value);
}

function parseCanonicalTimestamp(value, field) {
  if (typeof value !== 'string' || CONTROL_CHARACTERS.test(value) || !CANONICAL_UTC.test(value)) {
    throw new TypeError(`${field} must be a canonical UTC timestamp`);
  }
  const milliseconds = Date.parse(value);
  const roundTrip = Number.isFinite(milliseconds)
    ? new Date(milliseconds).toISOString().replace('.000Z', 'Z')
    : '';
  if (roundTrip !== value) throw new TypeError(`${field} must be a canonical UTC timestamp`);
  return { value, milliseconds };
}

function isCanonicalIPv4(value) {
  const octets = value.split('.');
  return octets.length === 4 && octets.every((octet) => {
    if (!/^(?:0|[1-9]\d{0,2})$/u.test(octet)) return false;
    return Number(octet) <= 255;
  });
}

function validateTarget(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 128
    || value !== value.trim() || CONTROL_CHARACTERS.test(value)) {
    throw new TypeError('target must be a trimmed local service or canonical IPv4 descriptor');
  }
  if (/^[0-9.]+$/u.test(value)) {
    if (!isCanonicalIPv4(value)) throw new TypeError('target must use canonical dotted-decimal IPv4');
    return value;
  }
  if (value.split('.').some((label) => /^0x[0-9a-f]+$/u.test(label))) {
    throw new TypeError('target must not use alternate numeric address notation');
  }
  if (!value.split('.').every((label) => DNS_LABEL.test(label))) {
    throw new TypeError('target must be a lowercase local service descriptor');
  }
  return value;
}

function readClock(options) {
  if (!isPlainRecord(options)) throw new TypeError('options must be a plain object');
  assertDataProperties(options, 'options');
  for (const field of Object.keys(options)) {
    if (field !== 'clock') throw new TypeError(`unknown options field: ${field}`);
  }
  const clock = Object.hasOwn(options, 'clock') ? options.clock : Date.now;
  if (typeof clock !== 'function') throw new TypeError('clock must be a function');

  let now;
  try {
    now = clock();
  } catch {
    throw new TypeError('clock must return a valid Unix timestamp');
  }
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new TypeError('clock must return a valid Unix timestamp');
  }
  return now;
}

function canonicalizeInput(input, now) {
  if (!isPlainRecord(input)) throw new TypeError('evidence input must be a plain object');
  assertExactOwnFields(input, INPUT_FIELDS, 'evidence');

  if (typeof input.lab !== 'string' || !SAFE_IDENTIFIER.test(input.lab)) {
    throw new TypeError('lab must be a lowercase identifier');
  }
  if (!Number.isSafeInteger(input.manifest_version) || input.manifest_version < 1) {
    throw new TypeError('manifest_version must be a positive integer');
  }
  if (typeof input.platform !== 'string' || !SAFE_IDENTIFIER.test(input.platform)) {
    throw new TypeError('platform must be a lowercase identifier');
  }

  const started = parseCanonicalTimestamp(input.started_at, 'started_at');
  const ended = parseCanonicalTimestamp(input.ended_at, 'ended_at');
  if (ended.milliseconds < started.milliseconds) {
    throw new TypeError('ended_at must not precede started_at');
  }
  if (ended.milliseconds - started.milliseconds > MAX_DURATION_MS) {
    throw new TypeError('evidence duration must not exceed 24 hours');
  }
  if (ended.milliseconds > now + MAX_FUTURE_SKEW_MS) {
    throw new TypeError('ended_at must not be more than five minutes in the future');
  }

  const target = validateTarget(input.target);
  const outcome = classifyOutcome(input.results);
  const results = Object.fromEntries(
    FAILURE_STAGES.map((stage) => [stage, input.results[stage]]).sort(([left], [right]) => codePointCompare(left, right)),
  );
  return Object.fromEntries([
    ['ended_at', ended.value],
    ['lab', input.lab],
    ['manifest_version', input.manifest_version],
    ['outcome', outcome],
    ['platform', input.platform],
    ['results', results],
    ['started_at', started.value],
    ['target', target],
  ].sort(([left], [right]) => codePointCompare(left, right)));
}

function hashBody(body) {
  // A digest cannot include itself without a fixed-point problem. Hash the
  // complete canonical receipt body, then attach its lowercase SHA-256.
  return createHash('sha256').update(stableSerialize(body)).digest('hex');
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function createEvidence(input, options = {}) {
  const body = canonicalizeInput(input, readClock(options));
  return deepFreeze({ ...body, sha256: hashBody(body) });
}

function verifyEvidence(receipt, options = {}) {
  if (!isPlainRecord(receipt)) throw new TypeError('evidence must be a plain object');
  assertExactOwnFields(receipt, RECEIPT_FIELDS, 'evidence');
  if (typeof receipt.outcome !== 'string' || !OUTCOMES.has(receipt.outcome)) {
    throw new TypeError('outcome must be a supported evidence outcome');
  }
  if (typeof receipt.sha256 !== 'string' || !SHA256.test(receipt.sha256)) {
    throw new TypeError('sha256 must be 64 lowercase hexadecimal characters');
  }

  // Revalidate the public receipt as if it were new input. Old receipts remain
  // valid, while evidence beyond the same five-minute clock-skew bound fails.
  const input = Object.fromEntries(INPUT_FIELDS.map((field) => [field, receipt[field]]));
  const body = canonicalizeInput(input, readClock(options));
  if (receipt.outcome !== body.outcome) return false;

  const expected = Buffer.from(hashBody(body), 'hex');
  const actual = Buffer.from(receipt.sha256, 'hex');
  return timingSafeEqual(actual, expected);
}

module.exports = { classifyOutcome, createEvidence, verifyEvidence };
