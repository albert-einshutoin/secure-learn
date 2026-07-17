const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadManifests, loadStandards, validateManifest } = require('../scripts/lib/curriculum');
const test = require('node:test');

const root = path.resolve(__dirname, '..');

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
      required: ['docker-desktop'],
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
      required: ['attack-result', 'suricata-event'],
    },
    assessment: {
      mode: 'guided-only',
      verifier: null,
    },
  };
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

test('verified lab manifests require their complete quality workflow', () => {
  const manifest = validManifest();
  manifest.maturity = 'verified';

  assert.deepEqual(validateManifest(manifest), [
    'verified lab requires workflow.verify',
    'verified lab requires workflow.remediate',
    'verified lab requires workflow.regress',
    'verified lab requires assessment.verifier',
  ]);
});

test('verified lab manifests require a safe attack workflow path', () => {
  const manifest = validManifest();
  manifest.maturity = 'verified';
  manifest.workflow.attack = null;
  manifest.workflow.verify = { path: 'verify/scripts/s1_verify.sh', args: [] };
  manifest.workflow.remediate = { path: 'remediate/scripts/s1_remediate.sh', args: [] };
  manifest.workflow.regress = { path: 'regress/scripts/s1_regress.sh', args: [] };
  manifest.assessment.verifier = { path: 'assessment/scripts/s1_verify.sh', args: [] };

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
    'verified lab requires workflow.verify',
    'verified lab requires workflow.remediate',
    'verified lab requires workflow.regress',
    'verified lab requires assessment.verifier',
  ]);
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
    assert.deepEqual(manifest.platforms, {
      required: [hostAssisted.has(manifest.id) ? 'linux-vm' : 'docker-desktop'],
      optional: [],
    });
    assert.equal(manifest.version, 1);
    assert.equal(manifest.safety.external_network, false);
    assert.equal(manifest.workflow.remediate, null);
    assert.equal(manifest.workflow.regress, null);
    assert.equal(manifest.assessment.verifier, null);

    if (manifest.maturity === 'runnable') {
      assert.ok(manifest.workflow.attack, `${manifest.id} must declare an attack execution spec`);
      assert.ok(manifest.evidence.required.includes('attack-result'));
    }
    if (endToEndChecked.has(manifest.id)) {
      assert.ok(manifest.evidence.required.includes('application-or-network-event'));
      assert.ok(manifest.evidence.required.includes('elasticsearch-event'));
    }
    if (hostAssisted.has(manifest.id)) {
      assert.deepEqual(manifest.evidence.required, ['vm-receipt', 'audit-event', 'cleanup-result']);
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
