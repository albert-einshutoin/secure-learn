'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { loadManifests } = require('../scripts/lib/curriculum');
const {
  classifyOutcome,
  createEvidence,
  runVerifiedEvidence,
  verifyEvidence,
} = require('../scripts/lib/evidence');

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

const repositoryRoot = path.resolve(__dirname, '..');
const manifests = loadManifests(repositoryRoot);
const S1_MANIFEST = manifests.find((manifest) => manifest.id === 's1');
const S5_MANIFEST = manifests.find((manifest) => manifest.id === 's5');
const S14_MANIFEST = manifests.find((manifest) => manifest.id === 's14');

function context(overrides = {}) {
  return { manifest: S1_MANIFEST, ...overrides };
}

function createReceipt(input, trustedContext = context()) {
  return createEvidence(input, trustedContext);
}

function verifyReceipt(receipt, trustedContext = context()) {
  return verifyEvidence(receipt, trustedContext);
}

function passingResults() {
  return Object.fromEntries(STAGES.map((stage) => [stage, true]));
}

function validInput(overrides = {}) {
  return {
    lab: 's1',
    manifest_version: 1,
    platform: 'docker-desktop-macos',
    started_at: '2026-07-17T00:00:00Z',
    ended_at: '2026-07-17T00:01:00Z',
    target: 'app',
    results: { ...passingResults(), cleanup: false },
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
  }), /environment must be an own boolean field/);
});

test('fails closed for missing, non-boolean, or unknown outcome fields', () => {
  assert.throws(() => classifyOutcome({ ...passingResults(), attack: 1 }), /attack must be a boolean/);
  assert.throws(() => classifyOutcome({ ...passingResults(), attack: undefined }), /attack must be a boolean/);
  assert.throws(() => {
    const results = passingResults();
    delete results.evidence;
    classifyOutcome(results);
  }, /evidence must be an own boolean field/);
  assert.throws(() => classifyOutcome({ ...passingResults(), extra: true }), /unknown result field: extra/);
  const invalidAfterFailure = { ...passingResults(), environment: false };
  delete invalidAfterFailure.cleanup;
  assert.throws(() => classifyOutcome(invalidAfterFailure), /cleanup must be an own boolean field/);
  assert.throws(() => classifyOutcome([]), /results must be a plain object/);
});

test('creates deterministic evidence hashes without hashing the hash field', () => {
  const input = validInput({
    results: { ...passingResults(), control: false, regression: false },
  });
  const first = createReceipt(input);
  const second = createReceipt(input);

  assert.equal(first.sha256, second.sha256);
  assert.match(first.sha256, /^[a-f0-9]{64}$/);
  assert.equal(first.outcome, 'control');
  assert.match(createReceipt(validInput({ target: 'app' })).sha256, /^[a-f0-9]{64}$/);

  const { sha256, ...body } = first;
  const recreated = createHash('sha256').update(JSON.stringify(sortForHash(body))).digest('hex');
  assert.equal(sha256, recreated);
});

test('caller booleans cannot promote runnable or unobserved verified manifests', () => {
  assert.throws(
    () => createEvidence(validInput({ results: passingResults() }), context()),
    /verified outcome issuance is closed/,
  );

  const verifiedManifest = structuredClone(S1_MANIFEST);
  verifiedManifest.maturity = 'verified';
  verifiedManifest.workflow.verify = { path: 'verify/scripts/s1_verify.sh', args: [] };
  verifiedManifest.workflow.remediate = { path: 'remediate/scripts/s1_remediate.sh', args: [] };
  verifiedManifest.workflow.regress = { path: 'regress/scripts/s1_regress.sh', args: [] };
  verifiedManifest.assessment.verifier = { path: 'assessment/scripts/s1_assess.sh', args: [] };
  verifiedManifest.evidence.required = [...STAGES];

  assert.throws(
    () => createEvidence(validInput({ results: passingResults() }), { manifest: verifiedManifest }),
    /verified outcome issuance is closed/,
  );
  assert.throws(
    () => createEvidence(validInput({ results: passingResults() }), { manifest: verifiedManifest, observation: { trusted: true } }),
    /verified outcome issuance is closed|unknown context field/,
  );
});

test('verified issuance stays closed for arbitrary roots, caller results, claimed platforms, and PATH interpreters', (t) => {
  const attackFixture = JSON.parse(fs.readFileSync(
    path.join(repositoryRoot, 'test', 'fixtures', 'evidence-invalid', 'printf-only-verified-runner.json'),
    'utf8',
  ));
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-learn-evidence-runner-'));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  fs.mkdirSync(path.join(fixtureRoot, 'curriculum', 'labs'), { recursive: true });
  const fakeBin = path.join(fixtureRoot, 'fake-bin');
  const marker = path.join(fixtureRoot, 'fake-bash-ran');
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(
    path.join(fakeBin, 'bash'),
    `#!/bin/sh\nprintf used > '${marker}'\nexec /bin/sh "$@"\n`,
    { mode: 0o755 },
  );

  const manifest = structuredClone(S1_MANIFEST);
  manifest.maturity = 'verified';
  manifest.evidence.required = [...STAGES];
  const commands = {
    attack: ['runner/attack.sh', ['startup', 'attack']],
    verify: ['runner/verify.sh', ['telemetry', 'pipeline']],
    remediate: ['runner/remediate.sh', ['control']],
    regress: ['runner/regress.sh', ['regression']],
    verifier: ['runner/assess.sh', ['evidence', 'cleanup']],
  };
  fs.mkdirSync(path.join(fixtureRoot, 'runner'));
  for (const [name, [relativePath, stages]] of Object.entries(commands)) {
    const observations = Object.fromEntries(stages.map((stage) => [stage, true]));
    const script = `#!${attackFixture.interpreter}\nprintf '%s\\n' '${JSON.stringify({ observations })}'\n`;
    fs.writeFileSync(path.join(fixtureRoot, relativePath), script, { mode: 0o755 });
    const spec = { path: relativePath, args: [] };
    if (name === 'verifier') manifest.assessment.verifier = spec;
    else manifest.workflow[name] = spec;
  }
  fs.writeFileSync(
    path.join(fixtureRoot, 'curriculum', 'labs', 's1.json'),
    JSON.stringify(manifest),
  );
  const loaded = loadManifests(fixtureRoot)[0];
  const originalPath = process.env.PATH;
  process.env.PATH = `${fakeBin}${path.delimiter}${originalPath}`;
  try {
    assert.throws(
      () => runVerifiedEvidence(
        validInput({
          platform: attackFixture.claimed_platform,
          results: attackFixture.results,
        }),
        { manifest: loaded },
      ),
      /verified evidence issuance is closed/,
    );
  } finally {
    process.env.PATH = originalPath;
  }
  assert.equal(fs.existsSync(marker), false, 'closed issuer must not resolve a caller PATH interpreter');
});

test('sorts result keys deterministically while preserving meaningful changes', () => {
  const first = createReceipt(validInput());
  const reorderedResults = { ...passingResults(), cleanup: false };
  const reordered = createReceipt(validInput({ results: Object.fromEntries(Object.entries(reorderedResults).reverse()) }));
  const changedTarget = createReceipt(validInput({ target: '172.23.0.20' }));
  assert.equal(first.sha256, reordered.sha256);
  assert.notEqual(first.sha256, changedTarget.sha256);
});

test('requires a complete trusted manifest and hashes its canonical safety snapshot', () => {
  assert.throws(() => createEvidence(validInput()), /context/);
  assert.throws(() => createEvidence(validInput(), {}), /manifest must be an own context field/);
  assert.throws(() => createEvidence(validInput(), { safety: S1_MANIFEST.safety }), /unknown context field/);
  assert.throws(() => createEvidence(validInput(), { manifest: S1_MANIFEST, extra: true }), /unknown context field/);
  Object.prototype.manifest = S1_MANIFEST;
  try {
    assert.throws(() => createEvidence(validInput(), {}), /manifest must be an own context field/);
  } finally {
    delete Object.prototype.manifest;
  }
  Object.prototype.title = S1_MANIFEST.title;
  try {
    const inheritedTitle = structuredClone(S1_MANIFEST);
    delete inheritedTitle.title;
    assert.throws(() => createEvidence(validInput(), { manifest: inheritedTitle }), /invalid manifest/);
  } finally {
    delete Object.prototype.title;
  }
  assert.throws(
    () => createEvidence(validInput(), { manifest: { ...S1_MANIFEST, safety: { ...S1_MANIFEST.safety, external_network: true } } }),
    /invalid manifest/,
  );
  assert.throws(
    () => createEvidence(validInput(), { manifest: { ...S1_MANIFEST, title: '' } }),
    /invalid manifest/,
  );

  const firstSafety = {
    target_services: ['target-api', 'app'],
    allowed_cidrs: ['192.168.10.0/24', '172.23.0.0/24'],
    external_network: false,
  };
  const secondSafety = {
    target_services: [...firstSafety.target_services].reverse(),
    allowed_cidrs: [...firstSafety.allowed_cidrs].reverse(),
    external_network: false,
  };
  const firstManifest = structuredClone(S1_MANIFEST);
  firstManifest.safety = firstSafety;
  const reorderedManifest = structuredClone(S1_MANIFEST);
  reorderedManifest.safety = secondSafety;
  const first = createEvidence(validInput(), { manifest: firstManifest });
  const reordered = createEvidence(validInput(), { manifest: reorderedManifest });
  assert.equal(first.sha256, reordered.sha256);
  assert.deepEqual(first.target_policy, {
    allowed_cidrs: ['172.23.0.0/24', '192.168.10.0/24'],
    external_network: false,
    target_services: ['app', 'target-api'],
  });
  assert.equal(Object.isFrozen(first.target_policy), true);
  assert.equal(Object.isFrozen(first.target_policy.allowed_cidrs), true);
  firstSafety.target_services[0] = 'changed';
  assert.deepEqual(first.target_policy.target_services, ['app', 'target-api']);
});

test('does not mutate or retain references and deeply freezes the receipt', () => {
  const input = validInput();
  const original = structuredClone(input);
  const evidence = createReceipt(input);
  assert.deepEqual(input, original);

  input.results.attack = false;
  assert.equal(evidence.results.attack, true);
  assert.equal(Object.isFrozen(evidence), true);
  assert.equal(Object.isFrozen(evidence.results), true);
  assert.throws(() => { evidence.results.attack = false; }, TypeError);
  assert.throws(() => { evidence.sha256 = '0'.repeat(64); }, TypeError);
  assert.equal(evidence.results.attack, true);
});

test('binds targets to the trusted manifest safety boundary', () => {
  for (const target of ['app', '172.23.0.20']) {
    assert.equal(createReceipt(validInput({ target })).target, target);
  }
  for (const target of ['', ' app', 'app ', 'APP', '-app', 'app-', 'http://app', 'user@app', 'app/path',
    'app;id', '127.1', '0177.0.0.1', '2130706433', '0x7f000001', '0x7f.0.0.1',
    '256.1.1.1', 'Cafe\u0301', '8.8.8.8', '1.1.1.1', '169.254.169.254', '224.0.0.1',
    '0.0.0.0', 'evil.attacker.com', 'localhost', '127.0.0.1']) {
    assert.throws(() => createReceipt(validInput({ target })), /target|prohibited/);
  }
  const incidentReceipt = createReceipt(validInput({ lab: 's14', target: 'localhost' }), { manifest: S14_MANIFEST });
  assert.equal(incidentReceipt.target, 'localhost');
  assert.equal(verifyReceipt(incidentReceipt, { manifest: S14_MANIFEST }), true);
  assert.throws(() => verifyReceipt(incidentReceipt, context()), /manifest id must match evidence lab/);
  assert.equal(createReceipt(validInput({ lab: 's14', target: '127.0.0.1' }), { manifest: S14_MANIFEST }).target, '127.0.0.1');
  assert.throws(
    () => createReceipt(validInput({ lab: 's14', target: 'localhost' }), context()),
    /manifest id must match evidence lab/,
  );
});

test('binds platform to the trusted manifest platform contract', () => {
  assert.equal(createReceipt(validInput({ platform: 'docker-desktop-macos' })).platform, 'docker-desktop-macos');
  for (const platform of ['windows', 'cloud', 'local-linux-vm', 'linux-vm']) {
    assert.throws(() => createReceipt(validInput({ platform })), /platform must be declared by trusted manifest/);
  }

  assert.throws(
    () => createEvidence(validInput({ lab: 's5', platform: 'linux-vm' }), { manifest: S5_MANIFEST }),
    /prohibited target/,
  );
  assert.throws(
    () => createEvidence(validInput({ lab: 's5', platform: 'docker-desktop-macos' }), { manifest: S5_MANIFEST }),
    /platform must be declared by trusted manifest/,
  );

  const tampered = structuredClone(createReceipt(validInput()));
  tampered.platform = 'cloud';
  const { sha256, ...body } = tampered;
  tampered.sha256 = createHash('sha256').update(JSON.stringify(sortForHash(body))).digest('hex');
  assert.throws(() => verifyReceipt(tampered), /platform must be declared by trusted manifest/);
});

test('rejects unsupported target types and unknown schema fields without secret guessing', () => {
  for (const target of [undefined, Number.NaN, Infinity, -0, 1n, () => {}, Symbol('x')]) {
    assert.throws(() => createReceipt(validInput({ target })), /target/);
  }
  assert.throws(() => createReceipt(validInput({ target: {} })), /target/);
  assert.throws(() => createReceipt({ ...validInput(), api_token: 'do-not-store' }), /unknown evidence field: api_token/);
});

test('validates strict root fields, canonical timestamps, and bounded duration', () => {
  assert.throws(() => createReceipt(validInput({ lab: '' })), /lab/);
  assert.throws(() => createReceipt(validInput({ manifest_version: 0 })), /manifest_version/);
  assert.throws(() => createReceipt(validInput({ platform: 'Docker Desktop' })), /platform/);
  assert.throws(() => createReceipt(validInput({ started_at: '2026-07-17T09:00:00+09:00' })), /canonical UTC/);
  assert.throws(() => createReceipt(validInput({ started_at: '2026-02-30T00:00:00Z' })), /canonical UTC/);
  assert.throws(() => createReceipt(validInput({ ended_at: '2026-07-16T23:59:59Z' })), /ended_at must not precede started_at/);
  assert.throws(() => createReceipt(validInput({ ended_at: '2026-07-19T00:00:01Z' })), /duration/);
  assert.throws(() => createReceipt({ ...validInput(), sha256: 'injected' }), /unknown evidence field: sha256/);
  assert.throws(() => createReceipt({ ...validInput(), outcome: 'verified' }), /unknown evidence field: outcome/);
  assert.throws(() => createReceipt({ ...validInput(), note: 'x\ncontrol' }), /unknown evidence field: note/);
});

test('requires every field to be an own property and accepts null-prototype records', () => {
  const pollutedPrototype = { polluted: true };
  const input = Object.assign(Object.create(pollutedPrototype), validInput());
  assert.throws(() => createReceipt(input), /evidence input must be a plain object/);

  for (const stage of STAGES) {
    Object.prototype[stage] = true;
    try {
      const inheritedResult = passingResults();
      delete inheritedResult[stage];
      assert.throws(() => classifyOutcome(inheritedResult), new RegExp(`${stage} must be an own boolean field`));
    } finally {
      delete Object.prototype[stage];
    }
  }

  for (const [field, inheritedValue] of Object.entries(validInput())) {
    Object.prototype[field] = inheritedValue;
    try {
      const inheritedRoot = validInput();
      delete inheritedRoot[field];
      assert.throws(() => createReceipt(inheritedRoot), new RegExp(`${field} must be an own evidence field`));
    } finally {
      delete Object.prototype[field];
    }
  }

  const nullResults = Object.assign(Object.create(null), { ...passingResults(), cleanup: false });
  const nullInput = Object.assign(Object.create(null), validInput({ results: nullResults }));
  assert.equal(createReceipt(nullInput).outcome, 'cleanup');
});

test('verifies canonical receipts and returns false for integrity tampering', () => {
  const evidence = createReceipt(validInput());
  assert.equal(verifyReceipt(evidence), true);

  for (const change of [
    { outcome: 'control' },
    { sha256: `${evidence.sha256.slice(0, 63)}${evidence.sha256.endsWith('0') ? '1' : '0'}` },
    { target: '172.23.0.20' },
    { results: { ...evidence.results, attack: false } },
  ]) {
    assert.equal(verifyReceipt({ ...structuredClone(evidence), ...change }), false);
  }
});

test('rejects trusted-policy mismatch even if an embedded permissive policy is rehashed', () => {
  const evidence = structuredClone(createReceipt(validInput()));
  assert.throws(() => verifyEvidence(evidence, { manifest: S14_MANIFEST }), /manifest id must match evidence lab/);

  const wrongVersion = structuredClone(S1_MANIFEST);
  wrongVersion.version += 1;
  assert.throws(
    () => verifyEvidence(evidence, { manifest: wrongVersion }),
    /manifest version must match evidence manifest_version/,
  );
  assert.throws(
    () => createEvidence(validInput({ manifest_version: 2 }), { manifest: S1_MANIFEST }),
    /manifest version must match evidence manifest_version/,
  );

  evidence.target_policy.allowed_cidrs.push('10.0.0.0/8');
  evidence.target_policy.allowed_cidrs.sort();
  const { sha256, ...body } = evidence;
  evidence.sha256 = createHash('sha256').update(JSON.stringify(sortForHash(body))).digest('hex');
  assert.equal(verifyReceipt(evidence), false);
});

test('rejects malformed receipt shapes before integrity comparison', () => {
  const evidence = structuredClone(createReceipt(validInput()));
  for (const [field, inheritedValue] of Object.entries(evidence)) {
    Object.prototype[field] = inheritedValue;
    try {
      const missingOwnField = { ...evidence };
      delete missingOwnField[field];
      assert.throws(() => verifyReceipt(missingOwnField), new RegExp(`${field} must be an own evidence field`));
    } finally {
      delete Object.prototype[field];
    }
  }
  assert.throws(() => verifyReceipt({ ...evidence, sha256: 'not-a-hash' }), /sha256/);
  assert.throws(() => verifyReceipt({ ...evidence, extra: true }), /unknown evidence field: extra/);
  assert.throws(
    () => verifyReceipt({
      ...evidence,
      outcome: 'control',
      target_policy: { ...evidence.target_policy, external_network: true },
    }),
    /invalid safety policy/,
  );
  assert.throws(() => verifyReceipt(null), /evidence must be a plain object/);
});

test('bounds creation and verification against an injectable valid clock', () => {
  const now = Date.parse('2026-07-17T00:10:00Z');
  const input = validInput({ ended_at: '2026-07-17T00:15:00Z' });
  const boundary = createReceipt(input, context({ now: () => now }));
  assert.equal(verifyReceipt(boundary, context({ now: () => now })), true);
  assert.equal(verifyReceipt(boundary, context({ now: () => Date.parse('2027-07-17T00:00:00Z') })), true);

  assert.throws(
    () => createReceipt(validInput({ ended_at: '2026-07-17T00:15:00.001Z' }), context({ now: () => now })),
    /future/,
  );
  assert.throws(() => verifyReceipt(boundary, context({ now: () => Date.parse('2026-07-17T00:09:59Z') })), /future/);
  assert.throws(() => createReceipt(validInput(), context({ now: () => Number.NaN })), /now/);
  assert.throws(() => createReceipt(validInput(), context({ now: 'now' })), /now/);
});
