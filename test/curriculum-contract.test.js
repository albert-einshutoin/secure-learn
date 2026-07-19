const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { loadManifests, loadStandards, validateManifest } = require('../scripts/lib/curriculum');
const test = require('node:test');

const root = path.resolve(__dirname, '..');
const learnScript = path.join(root, 'scripts', 'learn');
const coverageGenerator = path.join(root, 'scripts', 'generate_curriculum_coverage.js');
const {
  checkCoverageFile,
  renderCoverage,
  writeCoverageAtomically,
} = require('../scripts/generate_curriculum_coverage');

function createCoverageFixture(t) {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-learn-coverage-repo-'));
  for (const directory of ['scripts/lib', 'curriculum/labs', 'docs/curriculum']) {
    fs.mkdirSync(path.join(fixtureRoot, directory), { recursive: true });
  }
  fs.copyFileSync(coverageGenerator, path.join(fixtureRoot, 'scripts', 'generate_curriculum_coverage.js'));
  fs.copyFileSync(
    path.join(root, 'scripts', 'lib', 'curriculum.js'),
    path.join(fixtureRoot, 'scripts', 'lib', 'curriculum.js'),
  );
  fs.cpSync(path.join(root, 'curriculum', 'labs'), path.join(fixtureRoot, 'curriculum', 'labs'), {
    recursive: true,
  });
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  return fixtureRoot;
}

function fileFingerprint(file) {
  const stat = fs.statSync(file, { bigint: true });
  return {
    ino: stat.ino,
    mode: stat.mode,
    size: stat.size,
    mtimeNs: stat.mtimeNs,
    bytes: fs.readFileSync(file),
  };
}

function runProcess(command, args, options) {
  return new Promise((resolve) => {
    const child = spawn(command, args, options);
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

function runLearn(args, options = {}) {
  return require('node:child_process').spawnSync(process.execPath, [learnScript, ...args], {
    cwd: options.cwd || root,
    encoding: 'utf8',
    env: options.env || process.env,
  });
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), 'utf8'));
}

function validManifest() {
  return {
    id: 's1',
    version: 1,
    title: 'Port scan',
    track: 'soc',
    mode: 'docker-lab',
    maturity: 'runnable',
    platforms: {
      required: ['docker-desktop-macos', 'docker-desktop-windows', 'docker-engine-linux'],
      optional: [],
    },
    standards: {
      mitre_attack: ['T1595'],
      owasp_api: [],
      cwe: [],
      nist_csf: ['DE.CM'],
    },
    prerequisites: ['p0'],
    safety: {
      target_services: ['app'],
      allowed_cidrs: ['172.23.0.0/24'],
      external_network: false,
    },
    workflow: {
      attack: { path: 'attack/scripts/s1_portscan.sh', args: [] },
      verify: null,
      remediate: null,
      regress: null,
    },
    evidence: {
      required: ['attack', 'telemetry'],
    },
    assessment: {
      mode: 'guided-only',
      verifier: null,
    },
  };
}

function verifiedManifest() {
  const manifest = validManifest();
  manifest.maturity = 'verified';
  manifest.workflow = {
    attack: { path: 'attack/scripts/s1_attack.sh', args: [] },
    verify: { path: 'verify/scripts/s1_verify.sh', args: [] },
    remediate: { path: 'remediate/scripts/s1_remediate.sh', args: [] },
    regress: { path: 'regress/scripts/s1_regress.sh', args: [] },
  };
  manifest.evidence.required = [
    'environment', 'safety', 'startup', 'attack', 'telemetry',
    'pipeline', 'control', 'regression', 'evidence', 'cleanup',
  ];
  manifest.assessment.verifier = { path: 'assessment/scripts/s1_assess.sh', args: [] };
  return manifest;
}

test('lab manifest validator accepts the runnable contract', () => {
  assert.deepEqual(validateManifest(validManifest()), []);
});

test('lab manifest validator rejects unsupported maturity and external networking', () => {
  const manifest = validManifest();
  manifest.maturity = 'complete';
  manifest.safety.external_network = true;

  assert.deepEqual(validateManifest(manifest), [
    'maturity must be one of documented, runnable, verified, external',
    'external_network must be false for bundled labs',
  ]);
});

test('platform alternatives use a closed one-of host contract', () => {
  assert.deepEqual(validateManifest(validManifest()), []);

  const unsupported = validManifest();
  unsupported.platforms.required = ['docker-desktop'];
  assert.ok(validateManifest(unsupported).includes(
    'platforms.required contains unsupported platform: docker-desktop',
  ));

  const duplicate = validManifest();
  duplicate.platforms.required.push('docker-engine-linux');
  assert.ok(validateManifest(duplicate).includes('platforms.required must not contain duplicates'));

  const ambiguousOptional = validManifest();
  ambiguousOptional.platforms.optional = ['docker-engine-linux'];
  assert.ok(validateManifest(ambiguousOptional).includes(
    'platforms.optional is reserved and must be empty',
  ));

  const mixedVm = validManifest();
  mixedVm.platforms.required = ['linux-vm', 'docker-engine-linux'];
  assert.ok(validateManifest(mixedVm).includes(
    'linux-vm cannot be combined with Docker platform alternatives',
  ));
});

test('verified lab manifests require their complete quality workflow', () => {
  const manifest = validManifest();
  manifest.maturity = 'verified';

  assert.deepEqual(validateManifest(manifest), [
    'verified lab requires workflow.verify',
    'verified lab requires workflow.remediate',
    'verified lab requires workflow.regress',
    'verified lab requires assessment.verifier',
    'verified lab requires evidence.required to contain every evidence stage exactly once',
  ]);
});

test('verified workflow identities must be independent and cannot reuse learn or no-op entrypoints', () => {
  const duplicate = verifiedManifest();
  duplicate.workflow.verify.path = duplicate.workflow.attack.path;
  assert.ok(validateManifest(duplicate).includes(
    'verified workflow execution paths must be distinct',
  ));

  const learnReuse = verifiedManifest();
  learnReuse.workflow.verify = { path: 'scripts/learn', args: ['validate'] };
  assert.ok(validateManifest(learnReuse).includes(
    'verified workflow must not reuse the learn CLI',
  ));

  const noOp = verifiedManifest();
  noOp.workflow.remediate = { path: 'scripts/no-op.sh', args: [] };
  assert.ok(validateManifest(noOp).includes(
    'verified workflow must not use a no-op execution path',
  ));
});

test('evidence.required is a unique known-stage contract and verified requires every stage', () => {
  assert.deepEqual(validateManifest(verifiedManifest()), []);

  const unknown = verifiedManifest();
  unknown.evidence.required = ['attack', 'attack-result'];
  const unknownErrors = validateManifest(unknown);
  assert.ok(unknownErrors.includes('evidence.required contains unknown stage: attack-result'));
  assert.ok(unknownErrors.includes('verified lab requires evidence.required to contain every evidence stage exactly once'));

  const duplicate = verifiedManifest();
  duplicate.evidence.required.push('attack');
  assert.ok(validateManifest(duplicate).includes('evidence.required must not contain duplicate stages'));
});

test('CI negative fixtures reject verified workflow and evidence shortcuts', () => {
  const fixtureDirectory = path.join(root, 'test', 'fixtures', 'curriculum-invalid');
  const fixtureNames = fs.readdirSync(fixtureDirectory).sort();
  assert.deepEqual(fixtureNames, [
    'duplicate-workflow-path.json',
    'learn-cli-reuse.json',
    'no-op-workflow.json',
    'unknown-evidence-stage.json',
  ]);

  for (const fixtureName of fixtureNames) {
    const fixture = JSON.parse(fs.readFileSync(path.join(fixtureDirectory, fixtureName), 'utf8'));
    const manifest = verifiedManifest();
    for (const [propertyPath, value] of Object.entries(fixture.set)) {
      const segments = propertyPath.split('.');
      const final = segments.pop();
      let destination = manifest;
      for (const segment of segments) destination = destination[segment];
      destination[final] = value;
    }
    assert.ok(
      validateManifest(manifest).includes(fixture.expected),
      `${fixtureName} must fail with ${fixture.expected}`,
    );
  }
});

test('verified lab manifests require a safe attack workflow path', () => {
  const manifest = validManifest();
  manifest.maturity = 'verified';
  manifest.workflow.attack = null;
  manifest.workflow.verify = { path: 'verify/scripts/s1_verify.sh', args: [] };
  manifest.workflow.remediate = { path: 'remediate/scripts/s1_remediate.sh', args: [] };
  manifest.workflow.regress = { path: 'regress/scripts/s1_regress.sh', args: [] };
  manifest.assessment.verifier = { path: 'assessment/scripts/s1_verify.sh', args: [] };
  manifest.evidence.required = [...verifiedManifest().evidence.required];

  assert.deepEqual(validateManifest(manifest), [
    'verified lab requires workflow.attack',
  ]);
});

test('runnable lab manifests require a safe attack workflow path', () => {
  const manifest = validManifest();
  manifest.workflow.attack = null;

  assert.deepEqual(validateManifest(manifest), [
    'runnable lab requires workflow.attack',
  ]);
});

test('execution specs preserve argv boundaries without accepting unsafe paths or control characters', () => {
  const manifest = validManifest();
  manifest.workflow.attack = {
    path: 'scripts/scenario_e2e_check.sh',
    args: ['S1', '$literal-shell-metacharacter'],
  };
  assert.deepEqual(validateManifest(manifest), []);

  manifest.workflow.attack = { path: '../attack.sh', args: ['bad\u0000arg'] };
  assert.deepEqual(validateManifest(manifest), [
    'workflow.attack.path must be a safe repository-relative path',
    'workflow.attack.args must be an array of strings without control characters',
    'runnable lab requires workflow.attack',
  ]);

  manifest.workflow.attack = { path: 'scripts/scenario_e2e_check.sh', args: ['bad\u009Barg'] };
  assert.deepEqual(validateManifest(manifest), [
    'workflow.attack.args must be an array of strings without control characters',
    'runnable lab requires workflow.attack',
  ]);
});

test('lab manifest validator rejects malformed fields, unknown keys, and unsafe paths', () => {
  const manifest = validManifest();
  manifest.version = 0;
  manifest.title = '';
  manifest.platforms = {};
  manifest.standards = {};
  manifest.prerequisites = 'p0';
  manifest.platforms.extra = true;
  manifest.extra = true;
  manifest.workflow.attack = { path: '../attack.sh', args: [] };
  manifest.maturity = 'verified';

  const errors = validateManifest(manifest);
  assert.ok(errors.includes('version must be a positive integer'));
  assert.ok(errors.includes('title must be a non-empty string'));
  assert.ok(errors.includes('missing required field: platforms.required'));
  assert.ok(errors.includes('missing required field: standards.mitre_attack'));
  assert.ok(errors.includes('prerequisites must be an array of non-empty strings'));
  assert.ok(errors.includes('platforms contains unknown field: extra'));
  assert.ok(errors.includes('manifest contains unknown field: extra'));
  assert.ok(errors.includes('workflow.attack.path must be a safe repository-relative path'));
  assert.deepEqual(errors.slice(-4), [
    'verified lab requires workflow.remediate',
    'verified lab requires workflow.regress',
    'verified lab requires assessment.verifier',
    'verified lab requires evidence.required to contain every evidence stage exactly once',
  ]);
});

test('manifest ownership cannot be satisfied by polluted prototypes', () => {
  Object.prototype.mode = 'docker-lab';
  Object.prototype.attack = { path: 'attack/scripts/s1_portscan.sh', args: [] };
  Object.prototype.mitre_attack = ['T1595'];
  try {
    const missingMode = validManifest();
    delete missingMode.mode;
    assert.deepEqual(validateManifest(missingMode), ['missing required field: mode']);

    const missingAttack = validManifest();
    delete missingAttack.workflow.attack;
    assert.ok(validateManifest(missingAttack).includes('missing required field: workflow.attack'));

    const missingStandard = validManifest();
    delete missingStandard.standards.mitre_attack;
    assert.ok(validateManifest(missingStandard).includes('missing required field: standards.mitre_attack'));
  } finally {
    delete Object.prototype.mode;
    delete Object.prototype.attack;
    delete Object.prototype.mitre_attack;
  }
});

test('manifest ownership rejects accessors, symbols, non-enumerable fields, and sparse arrays without getters', () => {
  let getterCalled = false;
  const accessor = validManifest();
  Object.defineProperty(accessor.workflow, 'attack', {
    enumerable: true,
    get() {
      getterCalled = true;
      return { path: 'attack/scripts/s1_portscan.sh', args: [] };
    },
  });
  assert.deepEqual(validateManifest(accessor), ['workflow.attack must be an enumerable data property']);
  assert.equal(getterCalled, false);

  let inheritedGetterCalled = false;
  Object.defineProperty(Object.prototype, 'attack', {
    configurable: true,
    get() {
      inheritedGetterCalled = true;
      return { path: 'attack/scripts/s1_portscan.sh', args: [] };
    },
  });
  try {
    const inheritedAccessor = validManifest();
    delete inheritedAccessor.workflow.attack;
    assert.ok(validateManifest(inheritedAccessor).includes('missing required field: workflow.attack'));
    assert.equal(inheritedGetterCalled, false);
  } finally {
    delete Object.prototype.attack;
  }

  const symbol = validManifest();
  symbol.platforms[Symbol('hidden')] = true;
  assert.deepEqual(validateManifest(symbol), ['platforms must not contain symbol properties']);

  const nonEnumerable = validManifest();
  Object.defineProperty(nonEnumerable.safety, 'external_network', { value: false, enumerable: false });
  assert.deepEqual(validateManifest(nonEnumerable), ['safety.external_network must be an enumerable data property']);

  const sparse = validManifest();
  sparse.platforms.required = new Array(1);
  Object.prototype[0] = 'docker-desktop';
  try {
    assert.deepEqual(validateManifest(sparse), ['platforms.required must be a dense own array']);
  } finally {
    delete Object.prototype[0];
  }
});

test('loadManifests validates files, ignores non-JSON files, and preserves safe diagnostics', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-learn-curriculum-'));
  const labs = path.join(tempRoot, 'curriculum', 'labs');
  fs.mkdirSync(labs, { recursive: true });
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

  const invalid = validManifest();
  invalid.id = '';
  fs.writeFileSync(path.join(labs, 'invalid.json'), JSON.stringify(invalid));
  assert.throws(() => loadManifests(tempRoot), /invalid\.json: id must be a non-empty string/);
  fs.unlinkSync(path.join(labs, 'invalid.json'));

  for (const id of ['s10', 'named', 's2', 's1']) {
    const manifest = validManifest();
    manifest.id = id;
    fs.writeFileSync(path.join(labs, `${id}.json`), JSON.stringify(manifest));
  }
  fs.writeFileSync(path.join(labs, 'ignore.txt'), 'not a manifest');
  const manifests = loadManifests(tempRoot);
  assert.deepEqual(manifests.map((manifest) => manifest.id), ['s1', 's2', 's10', 'named']);
  const descriptor = Object.getOwnPropertyDescriptor(manifests[0], 'sourcePath');
  assert.equal(descriptor.enumerable, false);
  assert.equal(descriptor.writable, false);
  assert.deepEqual(validateManifest(manifests[0]), []);
  manifests[0].sourcePath = 'changed';
  assert.notEqual(manifests[0].sourcePath, 'changed');
});

test('loadManifests rejects duplicate IDs and handles missing lab directories', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-learn-curriculum-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  assert.deepEqual(loadManifests(tempRoot), []);

  const labs = path.join(tempRoot, 'curriculum', 'labs');
  fs.mkdirSync(labs, { recursive: true });
  fs.writeFileSync(path.join(labs, 'one.json'), JSON.stringify(validManifest()));
  fs.writeFileSync(path.join(labs, 'two.json'), JSON.stringify(validManifest()));
  assert.throws(() => loadManifests(tempRoot), /duplicate lab manifest ID: s1/);
});

test('loadStandards exposes catalog ID sets', () => {
  const standards = loadStandards(root);
  assert.ok(standards.owaspApiIds instanceof Set);
  assert.ok(standards.mitreAttackIds instanceof Set);
  assert.ok(standards.owaspApiIds.has('API1:2023'));
  assert.ok(standards.mitreAttackIds.has('T1595'));
});

test('OWASP API Security Top 10 2023 catalog preserves the official category contract', () => {
  const catalog = readJson('curriculum/standards/owasp-api-2023.json');

  assert.equal(catalog.framework, 'OWASP API Security Top 10');
  assert.equal(catalog.version, '2023');
  assert.equal(catalog.source, 'https://owasp.org/API-Security/editions/2023/en/0x11-t10/');
  assert.deepEqual(
    catalog.categories.map(({ id, name }) => ({ id, name })),
    [
      { id: 'API1:2023', name: 'Broken Object Level Authorization' },
      { id: 'API2:2023', name: 'Broken Authentication' },
      { id: 'API3:2023', name: 'Broken Object Property Level Authorization' },
      { id: 'API4:2023', name: 'Unrestricted Resource Consumption' },
      { id: 'API5:2023', name: 'Broken Function Level Authorization' },
      { id: 'API6:2023', name: 'Unrestricted Access to Sensitive Business Flows' },
      { id: 'API7:2023', name: 'Server Side Request Forgery' },
      { id: 'API8:2023', name: 'Security Misconfiguration' },
      { id: 'API9:2023', name: 'Improper Inventory Management' },
      { id: 'API10:2023', name: 'Unsafe Consumption of APIs' },
    ],
  );
});

test('MITRE ATT&CK Enterprise v19 catalog preserves its supported tactic and technique contract', () => {
  const catalog = readJson('curriculum/standards/mitre-attack-v19.json');

  assert.equal(catalog.framework, 'MITRE ATT&CK Enterprise');
  assert.equal(catalog.version, '19');
  assert.equal(catalog.source, 'https://attack.mitre.org/');
  assert.deepEqual(catalog.tactics, [
    'Reconnaissance',
    'Resource Development',
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Stealth',
    'Defense Impairment',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact',
  ]);

  assert.deepEqual(
    Object.entries(catalog.techniques).map(([id, { name, tactics }]) => ({ id, name, tactics })),
    [
      { id: 'T1595', name: 'Active Scanning', tactics: ['Reconnaissance'] },
      { id: 'T1110', name: 'Brute Force', tactics: ['Credential Access'] },
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactics: ['Initial Access'] },
      { id: 'T1499', name: 'Endpoint Denial of Service', tactics: ['Impact'] },
      { id: 'T1565', name: 'Data Manipulation', tactics: ['Impact'] },
      { id: 'T1548.003', name: 'Sudo and Sudo Caching', tactics: ['Privilege Escalation'] },
      { id: 'T1046', name: 'Network Service Discovery', tactics: ['Discovery'] },
      { id: 'T1040', name: 'Network Sniffing', tactics: ['Credential Access', 'Discovery'] },
      { id: 'T1573', name: 'Encrypted Channel', tactics: ['Command and Control'] },
      { id: 'T1018', name: 'Remote System Discovery', tactics: ['Discovery'] },
    ],
  );
});

test('legacy inventory has exactly one manifest for S1-S15', () => {
  const manifests = loadManifests(root);

  assert.deepEqual(
    manifests.map(({ id }) => id),
    Array.from({ length: 15 }, (_, index) => `s${index + 1}`),
  );
  assert.ok(manifests.every((manifest) => validateManifest(manifest).length === 0));
});

test('legacy inventory records its execution and maturity without overstatement', () => {
  const manifests = loadManifests(root);
  const expected = [
    ['s1', 'Port Scan', 'soc', 'docker-lab', 'runnable', ['T1595'], ['attack/scripts/s1_portscan.sh', []], ['scripts/scenario_e2e_check.sh', ['S1']]],
    ['s2', 'API Brute Force', 'appsec', 'docker-lab', 'runnable', ['T1110'], ['attack/scripts/s2_bruteforce.sh', []], ['scripts/scenario_e2e_check.sh', ['S2']]],
    ['s3', 'SQL Injection Attempt', 'appsec', 'docker-lab', 'runnable', ['T1190'], ['attack/scripts/s3_sqli.sh', []], ['scripts/scenario_e2e_check.sh', ['S3']]],
    ['s4', 'HTTP Denial of Service', 'soc', 'docker-lab', 'runnable', ['T1499'], ['attack/scripts/s4_dos.sh', []], ['scripts/scenario_e2e_check.sh', ['S4']]],
    ['s5', 'Important File Tampering', 'dfir', 'host-assisted', 'external', ['T1565'], ['attack/scripts/s5_file_tamper.sh', []], null],
    ['s6', 'Sudo Activity Detection', 'dfir', 'host-assisted', 'external', ['T1548.003'], ['attack/scripts/s6_privesc.sh', []], null],
    ['s7', 'Cross-Layer Incident', 'soc', 'docker-lab', 'runnable', ['T1595', 'T1110', 'T1190'], ['attack/scripts/s7_lateral.sh', []], ['scripts/scenario_e2e_check.sh', ['S7']]],
    ['s8', 'ARP Observation', 'foundation', 'docker-lab', 'runnable', ['T1018'], ['attack/scripts/s8_l2_arp_observe.sh', []], null],
    ['s9', 'ICMP Reconnaissance', 'foundation', 'docker-lab', 'runnable', ['T1595'], ['attack/scripts/s9_l3_icmp_recon.sh', []], null],
    ['s10', 'TCP State Observation', 'foundation', 'docker-lab', 'runnable', ['T1595'], ['attack/scripts/s10_l4_tcp_state.sh', []], null],
    ['s11', 'Session Pressure', 'foundation', 'docker-lab', 'runnable', ['T1499'], ['attack/scripts/s11_l5_session_stress.sh', []], null],
    ['s12', 'TLS Visibility Boundary', 'foundation', 'docker-lab', 'runnable', [], ['attack/scripts/s12_l6_tls_boundary.sh', []], null],
    ['s13', 'DNS Service Discovery', 'foundation', 'docker-lab', 'runnable', ['T1018'], ['attack/scripts/s13_l7_dns_observe.sh', []], null],
    ['s14', 'SRE Incident Response', 'sre', 'operator-workflow', 'runnable', ['T1499'], ['scripts/incident_drill.sh', []], null],
    ['s15', 'Integrated Capstone', 'governance', 'operator-workflow', 'documented', ['T1595', 'T1190', 'T1499'], null, null],
  ];

  assert.deepEqual(
    manifests.map((manifest) => [
      manifest.id,
      manifest.title,
      manifest.track,
      manifest.mode,
      manifest.maturity,
      manifest.standards.mitre_attack,
      manifest.workflow.attack
        ? [manifest.workflow.attack.path, manifest.workflow.attack.args]
        : null,
      manifest.workflow.verify
        ? [manifest.workflow.verify.path, manifest.workflow.verify.args]
        : null,
    ]),
    expected,
  );
  assert.equal(manifests.some(({ maturity }) => maturity === 'verified'), false);
  assert.deepEqual(
    manifests.filter(({ maturity }) => maturity === 'external').map(({ id }) => id),
    ['s5', 's6'],
  );
});

test('legacy manifest standard references exist in the pinned catalogs', () => {
  const manifests = loadManifests(root);
  const standards = loadStandards(root);

  for (const manifest of manifests) {
    for (const id of manifest.standards.mitre_attack) {
      assert.ok(standards.mitreAttackIds.has(id), `${manifest.id} references unknown MITRE ATT&CK technique ${id}`);
    }
    for (const id of manifest.standards.owasp_api) {
      assert.ok(standards.owaspApiIds.has(id), `${manifest.id} references unknown OWASP API category ${id}`);
    }
  }
});

test('legacy manifests preserve platform, evidence, and safe workflow boundaries', () => {
  const manifests = loadManifests(root);
  const hostAssisted = new Set(['s5', 's6']);
  const endToEndChecked = new Set(['s1', 's2', 's3', 's4', 's7']);

  assert.deepEqual(
    manifests.filter(({ maturity }) => maturity === 'runnable').map(({ id }) => id),
    ['s1', 's2', 's3', 's4', 's7', 's8', 's9', 's10', 's11', 's12', 's13', 's14'],
  );
  assert.deepEqual(manifests.filter(({ maturity }) => maturity === 'external').map(({ id }) => id), ['s5', 's6']);
  assert.deepEqual(manifests.filter(({ maturity }) => maturity === 'documented').map(({ id }) => id), ['s15']);

  for (const manifest of manifests) {
    assert.deepEqual(manifest.platforms, hostAssisted.has(manifest.id) ? {
      required: ['linux-vm'],
      optional: [],
    } : {
      required: ['docker-desktop-macos', 'docker-desktop-windows', 'docker-engine-linux'],
      optional: [],
    });
    assert.equal(manifest.version, 1);
    assert.equal(manifest.safety.external_network, false);
    assert.equal(manifest.workflow.remediate, null);
    assert.equal(manifest.workflow.regress, null);
    assert.equal(manifest.assessment.verifier, null);

    if (manifest.maturity === 'runnable') {
      assert.ok(manifest.workflow.attack, `${manifest.id} must declare an attack execution spec`);
      assert.ok(manifest.evidence.required.includes('attack'));
    }
    if (endToEndChecked.has(manifest.id)) {
      assert.ok(manifest.evidence.required.includes('telemetry'));
      assert.ok(manifest.evidence.required.includes('pipeline'));
    }
    if (hostAssisted.has(manifest.id)) {
      assert.deepEqual(manifest.evidence.required, ['environment', 'safety', 'evidence', 'cleanup']);
      assert.deepEqual(manifest.safety.target_services, []);
      assert.deepEqual(manifest.safety.allowed_cidrs, []);
    } else if (manifest.id === 's14') {
      assert.deepEqual(manifest.safety.target_services, ['localhost']);
      assert.deepEqual(manifest.safety.allowed_cidrs, ['127.0.0.1/32']);
    } else if (manifest.id !== 's15') {
      assert.deepEqual(manifest.safety.target_services, ['app']);
      assert.deepEqual(manifest.safety.allowed_cidrs, ['172.23.0.0/24']);
    }
  }
});

test('legacy manifest prerequisites refer only to earlier labs without cycles', () => {
  const manifests = loadManifests(root);
  const position = new Map(manifests.map(({ id }, index) => [id, index]));

  for (const manifest of manifests) {
    for (const prerequisite of manifest.prerequisites) {
      assert.ok(position.has(prerequisite), `${manifest.id} references unknown prerequisite ${prerequisite}`);
      assert.ok(position.get(prerequisite) < position.get(manifest.id), `${manifest.id} prerequisite ${prerequisite} must appear earlier`);
    }
  }
});

test('declared execution specs resolve to executable regular files inside the repository', () => {
  const repositoryRoot = fs.realpathSync(root);
  const manifests = loadManifests(root);

  for (const manifest of manifests) {
    const specs = [...Object.values(manifest.workflow), manifest.assessment.verifier];
    for (const spec of specs) {
      if (spec === null) continue;
      const resolved = fs.realpathSync(path.resolve(root, spec.path));
      assert.ok(
        resolved.startsWith(`${repositoryRoot}${path.sep}`),
        `${manifest.id} execution path escapes the repository: ${spec.path}`,
      );
      assert.ok(fs.statSync(resolved).isFile(), `${manifest.id} execution path is not a regular file: ${spec.path}`);
      fs.accessSync(resolved, fs.constants.X_OK);
    }
  }
});

test('S1 port scan executes argv directly without shell evaluation', () => {
  const source = fs.readFileSync(path.join(root, 'attack/scripts/s1_portscan.sh'), 'utf8');

  assert.doesNotMatch(source, /\beval\b/);
  assert.match(source, /"\$@"/);
});

test('manifest schema conditionals retain object type constraints for portable validators', () => {
  const schema = readJson('curriculum/schema/lab.schema.json');
  const runnableWorkflow = schema.allOf[0].then.properties.workflow;
  const verifiedWorkflow = schema.allOf[1].then.properties.workflow;
  const verifiedAssessment = schema.allOf[1].then.properties.assessment;

  assert.equal(runnableWorkflow.type, 'object');
  assert.equal(verifiedWorkflow.type, 'object');
  assert.equal(verifiedAssessment.type, 'object');
  assert.equal(schema.$defs.nonEmptyStringArray.allOf[1].type, 'array');
  assert.equal(schema.$defs.nonEmptyStringArray.allOf[1].minItems, 1);
});

test('learner CLI lists labs deterministically from any working directory', () => {
  const result = runLearn(['list'], { cwd: os.tmpdir() });
  assert.equal(result.status, 0, result.stderr);
  const lines = result.stdout.trimEnd().split('\n');
  assert.equal(lines.length, 15);
  assert.equal(lines[0], 's1\trunnable\tdocker-desktop-macos,docker-desktop-windows,docker-engine-linux\tPort Scan');
  assert.equal(lines[4], 's5\texternal\tlinux-vm\tImportant File Tampering');
  assert.equal(lines[14], 's15\tdocumented\tdocker-desktop-macos,docker-desktop-windows,docker-engine-linux\tIntegrated Capstone');
  assert.equal(result.stderr, '');
});

test('learner CLI shows exact manifests and validates the complete catalog', () => {
  const show = runLearn(['show', 's14']);
  assert.equal(show.status, 0, show.stderr);
  assert.deepEqual(JSON.parse(show.stdout), readJson('curriculum/labs/s14.json'));

  const validate = runLearn(['validate']);
  assert.equal(validate.status, 0, validate.stderr);
  assert.equal(validate.stdout, 'Validated 15 lab manifests.\n');
});

test('learner CLI separates unknown labs from reserved commands', () => {
  const unknown = runLearn(['show', 'S1']);
  assert.equal(unknown.status, 2);
  assert.equal(unknown.stdout, '');
  assert.equal(unknown.stderr, "Unknown lab 'S1'.\n");

  const reserved = runLearn(['attack', 's1']);
  assert.equal(reserved.status, 2);
  assert.equal(reserved.stdout, '');
  assert.equal(reserved.stderr, "Command 'attack' is reserved for the executable-lab slices.\n");
});

test('learner CLI ignores bypass variables and attacker-controlled PATH entries', () => {
  const fakeBin = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-learn-fake-bin-'));
  const marker = path.join(fakeBin, 'executed');
  fs.writeFileSync(path.join(fakeBin, 'docker'), `#!/bin/sh\ntouch "${marker}"\n`, { mode: 0o755 });
  const result = runLearn(['doctor', 's1'], {
    env: {
      ...process.env,
      NODE_ENV: 'test',
      SECURE_LEARN_SKIP_DOCKER_CHECK: '1',
      PATH: fakeBin,
    },
  });
  assert.equal(fs.existsSync(marker), false, 'doctor must not resolve docker from an attacker-controlled PATH');
  assert.doesNotMatch(fs.readFileSync(learnScript, 'utf8'), /SECURE_LEARN_SKIP_DOCKER_CHECK|NODE_ENV/);
  assert.ok(result.status === 0 || result.status === 1, 'real local Docker readiness alone determines the result');
  if (result.status === 0) {
    assert.match(result.stdout, /^Platform ready: /);
    assert.equal(result.stderr, '');
  } else {
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'Docker platform is not ready.\n');
  }
  fs.rmSync(fakeBin, { recursive: true, force: true });
});

test('learner CLI rejects untrusted argv without reflecting it', () => {
  for (const value of ['bad\nsecret', '\u001b[31msecret', 'x'.repeat(65)]) {
    const result = runLearn([value]);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'Invalid command input.\n');
    assert.doesNotMatch(result.stderr, /secret|\u001b|xxxx/);
  }
});

test('curriculum coverage is deterministic and reflects every manifest without overstatement', () => {
  const manifests = loadManifests(root);
  const first = renderCoverage(manifests);
  const second = renderCoverage(manifests);
  assert.equal(second, first);

  const report = second;
  assert.match(report, /^# Curriculum Runtime Coverage$/m);
  assert.match(report, /\| documented \| 1 \|\n\| runnable \| 12 \|\n\| verified \| 0 \|\n\| external \| 2 \|/);
  assert.match(report, /Documentation does not count as runtime verification\./);

  const rows = report
    .split('\n')
    .filter((line) => /^\| s(?:[1-9]|1[0-5]) \|/.test(line));
  assert.deepEqual(
    rows.map((line) => line.match(/^\| (s(?:[1-9]|1[0-5])) \|/)[1]),
    Array.from({ length: 15 }, (_, index) => `s${index + 1}`),
  );
});

test('curriculum coverage escapes manifest values before placing them in Markdown cells', () => {
  const manifest = validManifest();
  manifest.title = 'Title | <unsafe>\nnext line';
  const report = renderCoverage([manifest]);

  assert.match(report, /Title &#124; &lt;unsafe&gt; next line/);
  assert.doesNotMatch(report, /\| Title \| <unsafe>/);
});

test('curriculum coverage writer and checker operate only on isolated fixtures', (t) => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-learn-coverage-output-'));
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  const reportPath = path.join(fixture, 'coverage.md');
  const expected = renderCoverage(loadManifests(root));

  writeCoverageAtomically(reportPath, expected, fixture);
  assert.equal(checkCoverageFile(reportPath, expected, fixture), true);
  assert.equal(fs.statSync(reportPath).mode & 0o777, 0o644);

  const drifted = Buffer.from('# stale coverage\n');
  fs.writeFileSync(reportPath, drifted);
  const before = fileFingerprint(reportPath);
  assert.equal(checkCoverageFile(reportPath, expected, fixture), false);
  assert.deepEqual(fileFingerprint(reportPath), before);
});

test('curriculum coverage generator rejects unknown arguments and unsafe output links', (t) => {
  const unknown = spawnSync(process.execPath, [coverageGenerator, '--output', '/tmp/report'], {
    cwd: os.tmpdir(),
    encoding: 'utf8',
  });
  assert.equal(unknown.status, 2);
  assert.equal(unknown.stdout, '');
  assert.equal(unknown.stderr, 'Usage: node scripts/generate_curriculum_coverage.js [--check]\n');

  const fixtureRoot = createCoverageFixture(t);
  const reportPath = path.join(fixtureRoot, 'docs', 'curriculum', 'coverage.md');
  const target = path.join(os.tmpdir(), `secure-learn-coverage-target-${process.pid}-${Date.now()}`);
  fs.writeFileSync(target, 'outside\n');
  fs.symlinkSync(target, reportPath);
  t.after(() => {
    fs.rmSync(target, { force: true });
  });

  const fixtureGenerator = path.join(fixtureRoot, 'scripts', 'generate_curriculum_coverage.js');
  const linked = spawnSync(process.execPath, [fixtureGenerator], {
    cwd: os.tmpdir(),
    encoding: 'utf8',
  });
  assert.equal(linked.status, 1);
  assert.equal(linked.stdout, '');
  assert.equal(linked.stderr, 'Refusing to write curriculum coverage through an unsafe path.\n');
  assert.equal(fs.readFileSync(target, 'utf8'), 'outside\n');
});

test('coverage CLI reports stale isolated fixtures without mutating them', (t) => {
  const fixtureRoot = createCoverageFixture(t);
  const fixtureGenerator = path.join(fixtureRoot, 'scripts', 'generate_curriculum_coverage.js');
  const reportPath = path.join(fixtureRoot, 'docs', 'curriculum', 'coverage.md');
  fs.writeFileSync(reportPath, '# stale coverage\n', { mode: 0o640 });
  const before = fileFingerprint(reportPath);

  const result = spawnSync(process.execPath, [fixtureGenerator, '--check'], {
    cwd: os.tmpdir(),
    encoding: 'utf8',
  });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(
    result.stderr,
    'Curriculum coverage is stale. Run node scripts/generate_curriculum_coverage.js and commit the result.\n',
  );
  assert.deepEqual(fileFingerprint(reportPath), before);
});

test('curriculum gates derive maturity only from manifests', (t) => {
  const curriculumCheck = fs.readFileSync(path.join(root, 'scripts', 'curriculum_check.sh'), 'utf8');
  const worldClass = fs.readFileSync(path.join(root, 'scripts', 'world_class_curriculum_check.sh'), 'utf8');
  const handsOn = fs.readFileSync(path.join(root, 'scripts', 'world_class_hands_on_check.sh'), 'utf8');

  assert.match(curriculumCheck, /generate_curriculum_coverage\.js" --check/);
  assert.doesNotMatch(worldClass, /required_terms|missing required curriculum term/);
  assert.match(worldClass, /curriculum_check\.sh/);
  assert.match(handsOn, /loadManifests/);
  assert.doesNotMatch(handsOn, /verified_count|present_count|documented_count|warn_count/);

  fs.mkdirSync(path.join(root, 'reports'), { recursive: true });
  const reportDir = path.join(root, 'reports', `task6-${process.pid}-${Date.now()}`);
  t.after(() => fs.rmSync(reportDir, { recursive: true, force: true }));
  const result = spawnSync(path.join(root, 'scripts', 'world_class_hands_on_check.sh'), ['linux'], {
    cwd: os.tmpdir(),
    encoding: 'utf8',
    env: { ...process.env, REPORT_DIR: reportDir },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Curriculum maturity: documented=1 runnable=12 verified=0 external=2/);
  assert.match(result.stdout, /Supporting material:/);
  const report = fs.readFileSync(path.join(reportDir, 'summary.md'), 'utf8');
  assert.match(report, /## Curriculum maturity\n\n- documented: 1\n- runnable: 12\n- verified: 0\n- external: 2/);
  assert.match(report, /## Supporting material/);
});

test('CI regenerates and diffs curriculum coverage before the read-only world-class gate', () => {
  const workflow = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  const generate = workflow.indexOf('node scripts/generate_curriculum_coverage.js');
  const diff = workflow.indexOf('git diff --exit-code -- docs/curriculum/coverage.md');
  const worldClass = workflow.indexOf('scripts/world_class_curriculum_check.sh');

  assert.ok(generate >= 0, 'CI must regenerate curriculum coverage');
  assert.ok(diff > generate, 'CI must diff coverage immediately after regeneration');
  assert.ok(worldClass > diff, 'the read-only curriculum gate must run only after drift detection');
  assert.doesNotMatch(workflow.slice(generate, diff), /world_class_curriculum_check|curriculum_check\.sh/);
  assert.doesNotMatch(workflow.slice(diff, worldClass), /node scripts\/generate_curriculum_coverage\.js/);
});

test('curriculum coverage contract tests never mutate the tracked report', () => {
  const reportPath = path.join(root, 'docs', 'curriculum', 'coverage.md');
  const before = fileFingerprint(reportPath);
  assert.equal(checkCoverageFile(reportPath, renderCoverage(loadManifests(root)), root), true);
  assert.deepEqual(fileFingerprint(reportPath), before);
});

test('hands-on reports reject unsafe explicit destinations without touching external targets', (t) => {
  const reportRoot = path.join(root, 'reports');
  fs.mkdirSync(reportRoot, { recursive: true });
  const external = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-learn-external-report-'));
  const marker = path.join(external, 'marker');
  fs.writeFileSync(marker, 'unchanged\n');
  const link = path.join(reportRoot, `task6-link-${process.pid}-${Date.now()}`);
  fs.symlinkSync(external, link);
  const existing = path.join(reportRoot, `task6-existing-${process.pid}-${Date.now()}`);
  fs.mkdirSync(existing);
  t.after(() => {
    fs.unlinkSync(link);
    fs.rmSync(existing, { recursive: true, force: true });
    fs.rmSync(external, { recursive: true, force: true });
  });

  for (const reportDir of [link, existing, path.join(os.tmpdir(), 'outside-report')]) {
    const result = spawnSync(path.join(root, 'scripts', 'world_class_hands_on_check.sh'), ['linux'], {
      cwd: os.tmpdir(),
      encoding: 'utf8',
      env: { ...process.env, REPORT_DIR: reportDir },
    });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'world-class hands-on check failed: unsafe report destination\n');
  }
  assert.equal(fs.readFileSync(marker, 'utf8'), 'unchanged\n');
});

test('parallel default hands-on reports use distinct exclusive directories', async (t) => {
  const command = path.join(root, 'scripts', 'world_class_hands_on_check.sh');
  const options = { cwd: os.tmpdir(), env: process.env };
  const [first, second] = await Promise.all([
    runProcess(command, ['linux'], options),
    runProcess(command, ['linux'], options),
  ]);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(second.status, 0, second.stderr);
  const firstPath = first.stdout.match(/Report written to: (.+)\/summary\.md\n/)[1];
  const secondPath = second.stdout.match(/Report written to: (.+)\/summary\.md\n/)[1];
  t.after(() => {
    fs.rmSync(firstPath, { recursive: true, force: true });
    fs.rmSync(secondPath, { recursive: true, force: true });
  });
  assert.notEqual(firstPath, secondPath);
  assert.equal(fs.statSync(path.join(firstPath, 'summary.md')).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.join(secondPath, 'summary.md')).mode & 0o777, 0o600);
});
