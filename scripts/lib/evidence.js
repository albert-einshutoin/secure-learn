const { createHash } = require('node:crypto');

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

const EVIDENCE_FIELDS = Object.freeze([
  'lab',
  'manifest_version',
  'platform',
  'started_at',
  'ended_at',
  'target',
  'results',
]);

const MAX_DURATION_MS = 24 * 60 * 60 * 1000;
const MAX_DEPTH = 64;
const MAX_NODES = 10_000;
const MAX_STRING_LENGTH = 16_384;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const CANONICAL_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;
const SAFE_IDENTIFIER = /^[a-z][a-z0-9-]{0,63}$/u;
const DANGEROUS_FIELDS = new Set(['__proto__', 'constructor', 'prototype']);
const SECRET_LIKE_FIELD = /api[_-]?key|authorization|cookie|credential|password|private[_-]?key|secret|token/iu;

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
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

function assertDataProperties(value, path) {
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new TypeError(`${path} must not contain symbol keys`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(`${path}.${key} must be an enumerable data property`);
    }
  }
}

function assertDenseDataArray(value, path) {
  for (const key of Reflect.ownKeys(value)) {
    if (key === 'length') continue;
    if (typeof key !== 'string' || !/^(?:0|[1-9]\d*)$/u.test(key) || Number(key) >= value.length) {
      throw new TypeError(`${path} must not contain custom or symbol properties`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(`${path}[${key}] must be an enumerable data property`);
    }
  }
  if (Object.keys(value).length !== value.length) throw new TypeError(`${path} must not contain array holes`);
}

function assertExactFields(value, expected, label) {
  assertDataProperties(value, label);
  const expectedSet = new Set(expected);
  for (const field of Object.keys(value)) {
    if (!expectedSet.has(field)) throw new TypeError(`unknown ${label} field: ${field}`);
  }
}

function classifyOutcome(results) {
  if (!isPlainObject(results)) throw new TypeError('results must be a plain object');
  assertExactFields(results, FAILURE_STAGES, 'result');

  // This order is part of the learning contract: report the earliest broken
  // prerequisite so learners fix environment and safety before later signals.
  for (const stage of FAILURE_STAGES) {
    if (typeof results[stage] !== 'boolean') throw new TypeError(`${stage} must be a boolean`);
  }
  for (const stage of FAILURE_STAGES) if (!results[stage]) return stage;
  return 'verified';
}

function normalizeString(value, path, { allowEmpty = true } = {}) {
  if (CONTROL_CHARACTERS.test(value)) throw new TypeError(`${path} must not contain control characters`);
  const normalized = value.normalize('NFC');
  if (!allowEmpty && normalized.length === 0) throw new TypeError(`${path} must not be empty`);
  if (normalized.length > MAX_STRING_LENGTH) throw new TypeError(`${path} is too long`);
  return normalized;
}

function normalizeJsonValue(value, path, state, depth = 0) {
  if (depth > MAX_DEPTH) throw new TypeError(`${path} exceeds the maximum nesting depth`);
  state.nodes += 1;
  if (state.nodes > MAX_NODES) throw new TypeError(`${path} exceeds the maximum evidence size`);

  if (typeof value === 'string') return normalizeString(value, path);
  if (typeof value === 'boolean' || value === null) return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError(`${path} must contain only finite numbers`);
    if (Object.is(value, -0)) throw new TypeError(`${path} must not contain negative zero`);
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new TypeError(`${path} must contain only safe integers`);
    }
    return value;
  }
  if (value === undefined || ['bigint', 'function', 'symbol'].includes(typeof value)) {
    throw new TypeError(`${path} must contain only JSON-compatible values`);
  }

  if (state.ancestors.has(value)) throw new TypeError(`${path} must not contain a cycle`);
  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      assertDenseDataArray(value, path);
      return value.map((item, index) => normalizeJsonValue(item, `${path}[${index}]`, state, depth + 1));
    }
    if (!isPlainObject(value)) throw new TypeError(`${path} must contain only plain objects and arrays`);
    assertDataProperties(value, path);

    const normalizedEntries = [];
    const normalizedKeys = new Set();
    for (const rawKey of Object.keys(value)) {
      const key = normalizeString(rawKey, `${path} key`, { allowEmpty: false });
      if (normalizedKeys.has(key)) throw new TypeError(`${path} has a duplicate key after Unicode normalization`);
      if (DANGEROUS_FIELDS.has(key)) throw new TypeError(`${path} contains dangerous field: ${key}`);
      if (SECRET_LIKE_FIELD.test(key)) throw new TypeError(`${path} contains secret-like field: ${key}`);
      normalizedKeys.add(key);
      normalizedEntries.push([key, normalizeJsonValue(value[rawKey], `${path}.${key}`, state, depth + 1)]);
    }
    normalizedEntries.sort(([left], [right]) => codePointCompare(left, right));
    return Object.fromEntries(normalizedEntries);
  } finally {
    state.ancestors.delete(value);
  }
}

function stableSerialize(value) {
  if (Array.isArray(value)) return `[${value.map(stableSerialize).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const entries = Object.keys(value)
      .sort(codePointCompare)
      .map((key) => `${JSON.stringify(key)}:${stableSerialize(value[key])}`);
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value);
}

function parseCanonicalTimestamp(value, field) {
  if (typeof value !== 'string') throw new TypeError(`${field} must be a canonical UTC timestamp`);
  const normalized = normalizeString(value, field, { allowEmpty: false });
  if (!CANONICAL_UTC.test(normalized)) throw new TypeError(`${field} must be a canonical UTC timestamp`);

  const milliseconds = Date.parse(normalized);
  const roundTrip = Number.isFinite(milliseconds)
    ? new Date(milliseconds).toISOString().replace('.000Z', 'Z')
    : '';
  if (roundTrip !== normalized) throw new TypeError(`${field} must be a canonical UTC timestamp`);
  return { normalized, milliseconds };
}

function createEvidence(input) {
  if (!isPlainObject(input)) throw new TypeError('evidence input must be a plain object');
  assertExactFields(input, EVIDENCE_FIELDS, 'evidence');

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

  if (typeof input.target !== 'string' && !isPlainObject(input.target)) {
    throw new TypeError('target must be a non-empty string or plain object');
  }
  const state = { ancestors: new WeakSet(), nodes: 0 };
  const target = normalizeJsonValue(input.target, 'target', state);
  if ((typeof target === 'string' && target.length === 0)
    || (isPlainObject(target) && Object.keys(target).length === 0)) {
    throw new TypeError('target must not be empty');
  }

  // Clone and normalize results before classifying so the returned receipt
  // never shares mutable learner-owned references.
  const results = normalizeJsonValue(input.results, 'results', state);
  const outcome = classifyOutcome(results);
  const body = Object.fromEntries([
    ['ended_at', ended.normalized],
    ['lab', input.lab],
    ['manifest_version', input.manifest_version],
    ['outcome', outcome],
    ['platform', input.platform],
    ['results', results],
    ['started_at', started.normalized],
    ['target', target],
  ].sort(([left], [right]) => codePointCompare(left, right)));

  // A digest cannot include itself without a fixed-point problem. Hash the
  // complete canonical receipt body, then attach its lowercase SHA-256.
  const sha256 = createHash('sha256').update(stableSerialize(body)).digest('hex');
  return { ...body, sha256 };
}

module.exports = { classifyOutcome, createEvidence };
