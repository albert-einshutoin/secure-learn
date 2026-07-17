'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');

const { classifyOutcome, createEvidence, verifyEvidence } = require('../scripts/lib/evidence');

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
    target: 'app',
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

test('sorts result keys deterministically while preserving meaningful changes', () => {
  const first = createEvidence(validInput());
  const reordered = createEvidence(validInput({ results: Object.fromEntries(Object.entries(passingResults()).reverse()) }));
  const changedTarget = createEvidence(validInput({ target: 'api' }));
  assert.equal(first.sha256, reordered.sha256);
  assert.notEqual(first.sha256, changedTarget.sha256);
});

test('does not mutate or retain references and deeply freezes the receipt', () => {
  const input = validInput();
  const original = structuredClone(input);
  const evidence = createEvidence(input);
  assert.deepEqual(input, original);

  input.results.attack = false;
  assert.equal(evidence.results.attack, true);
  assert.equal(Object.isFrozen(evidence), true);
  assert.equal(Object.isFrozen(evidence.results), true);
  assert.throws(() => { evidence.results.attack = false; }, TypeError);
  assert.throws(() => { evidence.sha256 = '0'.repeat(64); }, TypeError);
  assert.equal(evidence.results.attack, true);
});

test('restricts target to an explicit local service or canonical IPv4 descriptor', () => {
  for (const target of ['app', 'localhost', 'secure-learn-api', 'app.internal', '172.23.0.20']) {
    assert.equal(createEvidence(validInput({ target })).target, target);
  }
  for (const target of ['', ' app', 'app ', 'APP', '-app', 'app-', 'http://app', 'user@app', 'app/path',
    'app;id', '127.1', '0177.0.0.1', '2130706433', '256.1.1.1', 'Cafe\u0301']) {
    assert.throws(() => createEvidence(validInput({ target })), /target/);
  }
});

test('rejects unsupported target types and unknown schema fields without secret guessing', () => {
  for (const target of [undefined, Number.NaN, Infinity, -0, 1n, () => {}, Symbol('x')]) {
    assert.throws(() => createEvidence(validInput({ target })), /target/);
  }
  assert.throws(() => createEvidence(validInput({ target: {} })), /target/);
  assert.throws(() => createEvidence({ ...validInput(), api_token: 'do-not-store' }), /unknown evidence field: api_token/);
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

test('requires every field to be an own property and accepts null-prototype records', () => {
  const pollutedPrototype = { polluted: true };
  const input = Object.assign(Object.create(pollutedPrototype), validInput());
  assert.throws(() => createEvidence(input), /evidence input must be a plain object/);

  Object.prototype.environment = true;
  Object.prototype.lab = 's1';
  try {
    const inheritedResult = passingResults();
    delete inheritedResult.environment;
    assert.throws(() => classifyOutcome(inheritedResult), /environment must be an own boolean field/);
    const inheritedRoot = validInput();
    delete inheritedRoot.lab;
    assert.throws(() => createEvidence(inheritedRoot), /lab must be an own evidence field/);
  } finally {
    delete Object.prototype.environment;
    delete Object.prototype.lab;
  }

  const nullResults = Object.assign(Object.create(null), passingResults());
  const nullInput = Object.assign(Object.create(null), validInput({ results: nullResults }));
  assert.equal(createEvidence(nullInput).outcome, 'verified');
});

test('verifies canonical receipts and returns false for integrity tampering', () => {
  const evidence = createEvidence(validInput());
  assert.equal(verifyEvidence(evidence), true);

  for (const change of [
    { outcome: 'control' },
    { sha256: `${evidence.sha256.slice(0, 63)}${evidence.sha256.endsWith('0') ? '1' : '0'}` },
    { target: 'api' },
    { results: { ...evidence.results, attack: false } },
  ]) {
    assert.equal(verifyEvidence({ ...structuredClone(evidence), ...change }), false);
  }
});

test('rejects malformed receipt shapes before integrity comparison', () => {
  const evidence = structuredClone(createEvidence(validInput()));
  const { sha256, ...missingHash } = evidence;
  assert.throws(() => verifyEvidence(missingHash), /sha256 must be an own evidence field/);
  assert.throws(() => verifyEvidence({ ...evidence, sha256: 'not-a-hash' }), /sha256/);
  assert.throws(() => verifyEvidence({ ...evidence, extra: true }), /unknown evidence field: extra/);
  assert.throws(() => verifyEvidence(null), /evidence must be a plain object/);
});

test('bounds creation and verification against an injectable valid clock', () => {
  const now = Date.parse('2026-07-17T00:10:00Z');
  const input = validInput({ ended_at: '2026-07-17T00:15:00Z' });
  const boundary = createEvidence(input, { clock: () => now });
  assert.equal(verifyEvidence(boundary, { clock: () => now }), true);
  assert.equal(verifyEvidence(boundary, { clock: () => Date.parse('2027-07-17T00:00:00Z') }), true);

  assert.throws(
    () => createEvidence(validInput({ ended_at: '2026-07-17T00:15:00.001Z' }), { clock: () => now }),
    /future/,
  );
  assert.throws(() => verifyEvidence(boundary, { clock: () => Date.parse('2026-07-17T00:09:59Z') }), /future/);
  assert.throws(() => createEvidence(validInput(), { clock: () => Number.NaN }), /clock/);
  assert.throws(() => createEvidence(validInput(), { clock: 'now' }), /clock/);
});
