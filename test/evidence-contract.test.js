const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');

const { classifyOutcome, createEvidence } = require('../scripts/lib/evidence');

const STAGES = [
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
];

function passingResults() {
  return Object.fromEntries(STAGES.map((stage) => [stage, true]));
}

function validInput(overrides = {}) {
  return {
    lab: 's1',
    manifest_version: 1,
    platform: 'docker-desktop',
    started_at: '2026-07-17T00:00:00Z',
    ended_at: '2026-07-17T00:01:00Z',
    target: { service: 'app', endpoints: ['/health', '/api'] },
    results: passingResults(),
    ...overrides,
  };
}

function sortForHash(value) {
  if (Array.isArray(value)) return value.map(sortForHash);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort((left, right) => {
          const leftPoints = [...left].map((character) => character.codePointAt(0));
          const rightPoints = [...right].map((character) => character.codePointAt(0));
          for (let index = 0; index < Math.min(leftPoints.length, rightPoints.length); index += 1) {
            if (leftPoints[index] !== rightPoints[index]) return leftPoints[index] - rightPoints[index];
          }
          return leftPoints.length - rightPoints.length;
        })
        .map((key) => [key, sortForHash(value[key])]),
    );
  }
  return value;
}

test('keeps every failure stage separate and uses the documented first-failure order', () => {
  assert.equal(classifyOutcome(passingResults()), 'verified');

  for (const [index, expected] of STAGES.entries()) {
    const results = passingResults();
    for (const stage of STAGES.slice(index)) results[stage] = false;
    assert.equal(classifyOutcome(results), expected);
  }

  assert.equal(classifyOutcome({ ...passingResults(), telemetry: false, pipeline: false }), 'telemetry');
  assert.equal(classifyOutcome({ ...passingResults(), control: false }), 'control');
  assert.equal(classifyOutcome({ ...passingResults(), cleanup: false }), 'cleanup');
});

test('keeps the plan examples explicit without treating omitted stages as success', () => {
  assert.equal(classifyOutcome({
    environment: true, safety: true, startup: true, attack: true, telemetry: true,
    pipeline: true, control: true, regression: true, evidence: true, cleanup: true,
  }), 'verified');
  assert.equal(classifyOutcome({
    environment: true, safety: true, startup: true, attack: true, telemetry: false,
    pipeline: false, control: true, regression: true, evidence: true, cleanup: true,
  }), 'telemetry');
  assert.equal(classifyOutcome({
    environment: true, safety: true, startup: true, attack: true, telemetry: true,
    pipeline: true, control: false, regression: true, evidence: true, cleanup: true,
  }), 'control');
  assert.equal(classifyOutcome({
    environment: true, safety: true, startup: true, attack: true, telemetry: true,
    pipeline: true, control: true, regression: true, evidence: true, cleanup: false,
  }), 'cleanup');

  assert.throws(() => classifyOutcome({
    attack: true, telemetry: true, pipeline: true, control: true, regression: true, cleanup: true,
  }), /environment must be a boolean/);
});

test('fails closed for missing, non-boolean, or unknown outcome fields', () => {
  assert.throws(() => classifyOutcome({ ...passingResults(), attack: 1 }), /attack must be a boolean/);
  assert.throws(() => classifyOutcome({ ...passingResults(), attack: undefined }), /attack must be a boolean/);
  assert.throws(() => {
    const results = passingResults();
    delete results.evidence;
    classifyOutcome(results);
  }, /evidence must be a boolean/);
  assert.throws(() => classifyOutcome({ ...passingResults(), extra: true }), /unknown result field: extra/);
  const invalidAfterFailure = { ...passingResults(), environment: false };
  delete invalidAfterFailure.cleanup;
  assert.throws(() => classifyOutcome(invalidAfterFailure), /cleanup must be a boolean/);
  assert.throws(() => classifyOutcome([]), /results must be a plain object/);
});

test('creates deterministic evidence hashes without hashing the hash field', () => {
  const input = validInput({
    results: { ...passingResults(), control: false, regression: false },
  });
  const first = createEvidence(input);
  const second = createEvidence(input);

  assert.equal(first.sha256, second.sha256);
  assert.match(first.sha256, /^[a-f0-9]{64}$/);
  assert.equal(first.outcome, 'control');
  assert.match(createEvidence(validInput({ target: 'app' })).sha256, /^[a-f0-9]{64}$/);

  const { sha256, ...body } = first;
  const recreated = createHash('sha256').update(JSON.stringify(sortForHash(body))).digest('hex');
  assert.equal(sha256, recreated);
});

test('sorts nested object keys while preserving array order and semantic changes', () => {
  const first = createEvidence(validInput({ target: { z: { b: 2, a: 1 }, a: ['first', 'second'] } }));
  const reordered = createEvidence(validInput({ target: { a: ['first', 'second'], z: { a: 1, b: 2 } } }));
  const reversedArray = createEvidence(validInput({ target: { a: ['second', 'first'], z: { a: 1, b: 2 } } }));

  assert.equal(first.sha256, reordered.sha256);
  assert.notEqual(first.sha256, reversedArray.sha256);
  assert.deepEqual(Object.keys(first.target), ['a', 'z']);
});

test('normalizes Unicode to NFC and rejects normalized-key ambiguity', () => {
  const decomposed = createEvidence(validInput({ target: { label: 'Cafe\u0301' } }));
  const composed = createEvidence(validInput({ target: { label: 'Caf\u00e9' } }));
  assert.equal(decomposed.sha256, composed.sha256);
  assert.equal(decomposed.target.label, 'Caf\u00e9');

  assert.throws(
    () => createEvidence(validInput({ target: { 'Cafe\u0301': 1, 'Caf\u00e9': 2 } })),
    /duplicate key after Unicode normalization/,
  );
});

test('does not mutate or retain references from learner input', () => {
  const input = validInput();
  const original = structuredClone(input);
  const evidence = createEvidence(input);
  assert.deepEqual(input, original);

  input.target.endpoints[0] = '/changed';
  input.results.attack = false;
  assert.equal(evidence.target.endpoints[0], '/health');
  assert.equal(evidence.results.attack, true);
});

test('rejects unsupported JSON values, cycles, negative zero, and dangerous keys', () => {
  for (const target of [undefined, Number.NaN, Infinity, -0, 1n, () => {}, Symbol('x')]) {
    assert.throws(() => createEvidence(validInput({ target })), /target/);
  }

  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => createEvidence(validInput({ target: cyclic })), /cycle/);
  assert.throws(() => createEvidence(validInput({ target: { api_token: 'do-not-store' } })), /secret-like field/);
  assert.throws(() => createEvidence(validInput({ target: { apiKey: 'do-not-store' } })), /secret-like field/);
  assert.throws(() => createEvidence(validInput({ target: { nested: undefined } })), /JSON-compatible/);
  const accessor = {};
  Object.defineProperty(accessor, 'service', { enumerable: true, get: () => 'app' });
  assert.throws(() => createEvidence(validInput({ target: accessor })), /enumerable data property/);
  assert.throws(
    () => createEvidence(validInput({ target: JSON.parse('{"__proto__":{"polluted":true}}') })),
    /dangerous field/,
  );
  assert.equal({}.polluted, undefined);
});

test('validates strict root fields, canonical timestamps, and bounded duration', () => {
  assert.throws(() => createEvidence(validInput({ lab: '' })), /lab/);
  assert.throws(() => createEvidence(validInput({ manifest_version: 0 })), /manifest_version/);
  assert.throws(() => createEvidence(validInput({ platform: 'Docker Desktop' })), /platform/);
  assert.throws(() => createEvidence(validInput({ started_at: '2026-07-17T09:00:00+09:00' })), /canonical UTC/);
  assert.throws(() => createEvidence(validInput({ started_at: '2026-02-30T00:00:00Z' })), /canonical UTC/);
  assert.throws(() => createEvidence(validInput({ ended_at: '2026-07-16T23:59:59Z' })), /ended_at must not precede started_at/);
  assert.throws(() => createEvidence(validInput({ ended_at: '2026-07-19T00:00:01Z' })), /duration/);
  assert.throws(() => createEvidence({ ...validInput(), sha256: 'injected' }), /unknown evidence field: sha256/);
  assert.throws(() => createEvidence({ ...validInput(), outcome: 'verified' }), /unknown evidence field: outcome/);
  assert.throws(() => createEvidence({ ...validInput(), note: 'x\ncontrol' }), /unknown evidence field: note/);
});

test('rejects non-plain objects and prototype-polluted input', () => {
  const pollutedPrototype = { polluted: true };
  const input = Object.assign(Object.create(pollutedPrototype), validInput());
  assert.throws(() => createEvidence(input), /evidence input must be a plain object/);
  assert.throws(() => createEvidence(validInput({ target: new Date() })), /target must be.*plain object/);
});
