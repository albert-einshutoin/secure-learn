# Security Learning Platform v2 Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace prose- and keyword-based curriculum claims with validated standards data, honest lab manifests, a safe learner CLI, deterministic evidence, and generated runtime coverage.

**Architecture:** Node.js 24 CommonJS modules use only built-in APIs so the repository does not gain a second dependency tree. JSON manifests under `curriculum/` become product truth; small validators, generators, and the `scripts/learn` CLI consume them. Existing S1-S15 entry points remain compatible while later plans add new executable labs.

**Tech Stack:** Node.js 24 built-ins, JSON, Bash, Docker Compose, Node test runner, existing HTML generators and GitHub Actions.

---

## Scope Decomposition

The approved design covers independent subsystems. Implement them in this order, each with a separate plan and releasable result:

1. This plan: truth, standards, safety, evidence, coverage, and compatibility foundation.
2. Portable AppSec core.
3. Portable Container and Kubernetes core.
4. SOC, DFIR, and recovery.
5. Linux VM and optional cloud extensions.

Do not add new attack labs in this foundation slice. Its job is to make later lab maturity measurable and impossible to overstate.

## File Structure

### Create

- `curriculum/schema/lab.schema.json`: documented manifest contract used by the validator.
- `curriculum/standards/owasp-api-2023.json`: authoritative API category identifiers.
- `curriculum/standards/mitre-attack-v19.json`: supported tactics and legacy scenario technique identifiers.
- `curriculum/labs/s1.json` through `curriculum/labs/s15.json`: one honest manifest per published legacy scenario.
- `scripts/lib/curriculum.js`: load, validate, and sort manifests and standards.
- `scripts/lib/target-policy.js`: reject targets outside manifest-declared services and CIDRs.
- `scripts/lib/evidence.js`: classify outcomes and create deterministic evidence hashes.
- `scripts/learn`: public list, show, validate, and doctor command surface.
- `scripts/generate_curriculum_coverage.js`: generate the tracked maturity report.
- `scripts/curriculum_check.sh`: one static curriculum contract gate.
- `test/curriculum-contract.test.js`: schema, standards, maturity, and compatibility tests.
- `test/target-policy.test.js`: safety-boundary tests.
- `test/evidence-contract.test.js`: result and hashing tests.
- `docs/curriculum/coverage.md`: generated manifest-based report.

### Modify

- `docs/curriculum/owasp-api-security-track.md`: correct API6-API8 and label design versus executable state.
- `docs/curriculum/world-class-scenario-evaluation.md`: remove the S1-S15 execution overclaim.
- `scenarios/S5_file_tamper.md`: correct T1565 name and tactic.
- `scenarios/S7_lateral.md`: describe a cross-layer incident, not genuine lateral movement.
- `scenarios/S8_l2_arp_observe.md`: map T1046 to Discovery.
- `attack/scripts/s7_lateral.sh`: retain filename compatibility but correct displayed scenario name and claims.
- `scripts/generate_scenario_html.js`: use the corrected labels and expose manifest maturity.
- `scripts/world_class_curriculum_check.sh`: delegate truth checks to `curriculum_check.sh` and retain HTML checks.
- `scripts/world_class_hands_on_check.sh`: derive status from manifests instead of matching prose.
- `scripts/lab_quality_gate.sh`: run all root contract tests and the curriculum gate.
- `.github/workflows/ci.yml`: run the same contract and freshness checks in CI.
- `.gitignore`: ignore learner evidence while retaining schemas and templates.
- `README.md`: document the new truth model and CLI without claiming new labs exist.

## Task 1: Pin Standards and Correct Their Contract

**Files:**
- Create: `curriculum/standards/owasp-api-2023.json`
- Create: `curriculum/standards/mitre-attack-v19.json`
- Test: `test/curriculum-contract.test.js`

- [ ] **Step 1: Write the failing standards tests**

Create `test/curriculum-contract.test.js` with these initial tests:

```js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..');
const readJson = (file) => JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));

test('OWASP API catalog matches the 2023 category identifiers', () => {
  const catalog = readJson('curriculum/standards/owasp-api-2023.json');
  assert.equal(catalog.version, '2023');
  assert.deepEqual(catalog.categories.map(({ id }) => id), [
    'API1:2023', 'API2:2023', 'API3:2023', 'API4:2023', 'API5:2023',
    'API6:2023', 'API7:2023', 'API8:2023', 'API9:2023', 'API10:2023',
  ]);
  assert.equal(catalog.categories[5].name, 'Unrestricted Access to Sensitive Business Flows');
  assert.equal(catalog.categories[6].name, 'Server Side Request Forgery');
  assert.equal(catalog.categories[7].name, 'Security Misconfiguration');
});

test('MITRE catalog pins Enterprise ATT&CK v19 tactics and supported techniques', () => {
  const catalog = readJson('curriculum/standards/mitre-attack-v19.json');
  assert.equal(catalog.version, '19');
  assert.deepEqual(catalog.tactics, [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Stealth', 'Defense Impairment',
    'Credential Access', 'Discovery', 'Lateral Movement', 'Collection',
    'Command and Control', 'Exfiltration', 'Impact',
  ]);
  assert.deepEqual(catalog.techniques.T1565, { name: 'Data Manipulation', tactics: ['Impact'] });
  assert.deepEqual(catalog.techniques.T1046, { name: 'Network Service Discovery', tactics: ['Discovery'] });
  assert.deepEqual(catalog.techniques['T1548.003'], {
    name: 'Sudo and Sudo Caching',
    tactics: ['Privilege Escalation'],
  });
});
```

- [ ] **Step 2: Run the tests and verify missing-file failures**

Run:

```bash
node --test test/curriculum-contract.test.js
```

Expected: both tests fail with `ENOENT` for files under `curriculum/standards/`.

- [ ] **Step 3: Add the complete OWASP API catalog**

Create `curriculum/standards/owasp-api-2023.json`:

```json
{
  "framework": "OWASP API Security Top 10",
  "version": "2023",
  "source": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
  "categories": [
    { "id": "API1:2023", "name": "Broken Object Level Authorization" },
    { "id": "API2:2023", "name": "Broken Authentication" },
    { "id": "API3:2023", "name": "Broken Object Property Level Authorization" },
    { "id": "API4:2023", "name": "Unrestricted Resource Consumption" },
    { "id": "API5:2023", "name": "Broken Function Level Authorization" },
    { "id": "API6:2023", "name": "Unrestricted Access to Sensitive Business Flows" },
    { "id": "API7:2023", "name": "Server Side Request Forgery" },
    { "id": "API8:2023", "name": "Security Misconfiguration" },
    { "id": "API9:2023", "name": "Improper Inventory Management" },
    { "id": "API10:2023", "name": "Unsafe Consumption of APIs" }
  ]
}
```

- [ ] **Step 4: Add the pinned MITRE subset catalog**

Create `curriculum/standards/mitre-attack-v19.json` with the 15 tactics asserted above and this technique map:

```json
{
  "T1595": { "name": "Active Scanning", "tactics": ["Reconnaissance"] },
  "T1110": { "name": "Brute Force", "tactics": ["Credential Access"] },
  "T1190": { "name": "Exploit Public-Facing Application", "tactics": ["Initial Access"] },
  "T1499": { "name": "Endpoint Denial of Service", "tactics": ["Impact"] },
  "T1565": { "name": "Data Manipulation", "tactics": ["Impact"] },
  "T1548.003": { "name": "Sudo and Sudo Caching", "tactics": ["Privilege Escalation"] },
  "T1046": { "name": "Network Service Discovery", "tactics": ["Discovery"] },
  "T1040": { "name": "Network Sniffing", "tactics": ["Credential Access", "Discovery"] },
  "T1573": { "name": "Encrypted Channel", "tactics": ["Command and Control"] },
  "T1018": { "name": "Remote System Discovery", "tactics": ["Discovery"] }
}
```

Wrap it with `framework`, `version`, `source`, `tactics`, and `techniques` fields matching the test.

- [ ] **Step 5: Run tests and commit**

Run:

```bash
node --test test/curriculum-contract.test.js
git diff --check
```

Expected: 2 tests pass and no whitespace errors.

Commit:

```bash
git add curriculum/standards test/curriculum-contract.test.js
git commit -m "fix(curriculum): pin current security standards"
```

## Task 2: Define and Enforce the Lab Manifest Schema

**Files:**
- Create: `curriculum/schema/lab.schema.json`
- Create: `scripts/lib/curriculum.js`
- Modify: `test/curriculum-contract.test.js`

- [ ] **Step 1: Add failing validator tests**

Append:

```js
const { validateManifest } = require('../scripts/lib/curriculum');

function validManifest() {
  return {
    id: 's1',
    version: 1,
    title: 'Port scan',
    track: 'soc',
    mode: 'docker-lab',
    maturity: 'runnable',
    platforms: { required: ['docker-desktop'], optional: [] },
    standards: { mitre_attack: ['T1595'], owasp_api: [], cwe: [], nist_csf: ['DE.CM'] },
    prerequisites: ['p0'],
    safety: {
      target_services: ['app'],
      allowed_cidrs: ['172.23.0.0/24'],
      external_network: false,
    },
    workflow: { attack: 'attack/scripts/s1_portscan.sh', verify: null, remediate: null, regress: null },
    evidence: { required: ['attack-result', 'suricata-event'] },
    assessment: { mode: 'guided-only', verifier: null },
  };
}

test('manifest validator accepts the complete contract', () => {
  assert.deepEqual(validateManifest(validManifest()), []);
});

test('manifest validator rejects unsupported maturity and unsafe external networking', () => {
  const manifest = validManifest();
  manifest.maturity = 'complete';
  manifest.safety.external_network = true;
  assert.deepEqual(validateManifest(manifest), [
    'maturity must be one of documented, runnable, verified, external',
    'external_network must be false for bundled labs',
  ]);
});

test('verified maturity requires attack, verification, remediation, regression, evidence, and assessment', () => {
  const manifest = validManifest();
  manifest.maturity = 'verified';
  assert.deepEqual(validateManifest(manifest), [
    'verified lab requires workflow.verify',
    'verified lab requires workflow.remediate',
    'verified lab requires workflow.regress',
    'verified lab requires assessment.verifier',
  ]);
});
```

- [ ] **Step 2: Verify the module-not-found failure**

Run `node --test test/curriculum-contract.test.js`.

Expected: failure with `Cannot find module '../scripts/lib/curriculum'`.

- [ ] **Step 3: Create the documented JSON Schema**

Create `curriculum/schema/lab.schema.json` with draft 2020-12, `additionalProperties: false`, and required top-level fields:

```json
[
  "id", "version", "title", "track", "mode", "maturity", "platforms",
  "standards", "prerequisites", "safety", "workflow", "evidence", "assessment"
]
```

Constrain maturity to `documented`, `runnable`, `verified`, or `external`; mode to `docker-lab`, `host-assisted`, `operator-workflow`, or `design-exercise`; and set `external_network` to JSON Schema `const: false`.

- [ ] **Step 4: Implement a dependency-free validator**

Create `scripts/lib/curriculum.js` exporting `validateManifest`, `loadManifests`, and `loadStandards`. The validator must:

```js
const fs = require('node:fs');
const path = require('node:path');

const MATURITIES = new Set(['documented', 'runnable', 'verified', 'external']);
const MODES = new Set(['docker-lab', 'host-assisted', 'operator-workflow', 'design-exercise']);
const REQUIRED_FIELDS = [
  'id', 'version', 'title', 'track', 'mode', 'maturity', 'platforms',
  'standards', 'prerequisites', 'safety', 'workflow', 'evidence', 'assessment',
];

function validateManifest(manifest) {
  const errors = [];
  for (const field of REQUIRED_FIELDS) {
    if (!(field in manifest)) errors.push(`missing required field: ${field}`);
  }
  if (errors.length) return errors;
  if (!MATURITIES.has(manifest.maturity)) {
    errors.push('maturity must be one of documented, runnable, verified, external');
  }
  if (!MODES.has(manifest.mode)) errors.push('mode is not supported');
  if (manifest.safety.external_network !== false) {
    errors.push('external_network must be false for bundled labs');
  }
  if (manifest.maturity === 'verified') {
    for (const field of ['verify', 'remediate', 'regress']) {
      if (!manifest.workflow[field]) errors.push(`verified lab requires workflow.${field}`);
    }
    if (!manifest.assessment.verifier) errors.push('verified lab requires assessment.verifier');
  }
  return errors;
}
```

`loadManifests(root)` reads only `curriculum/labs/*.json`, attaches a non-enumerable source path for diagnostics, rejects duplicate IDs, and sorts numeric `s` IDs before named future labs. `loadStandards(root)` returns sets of valid OWASP and MITRE IDs.

- [ ] **Step 5: Run all contract tests and commit**

Run:

```bash
node --test test/curriculum-contract.test.js
node --check scripts/lib/curriculum.js
git diff --check
```

Expected: 5 tests pass.

Commit:

```bash
git add curriculum/schema scripts/lib/curriculum.js test/curriculum-contract.test.js
git commit -m "feat(curriculum): validate lab maturity contracts"
```

## Task 3: Import S1-S15 with Honest Maturity

**Files:**
- Create: `curriculum/labs/s1.json` through `curriculum/labs/s15.json`
- Modify: `test/curriculum-contract.test.js`

- [ ] **Step 1: Add failing inventory and standards tests**

Append tests that call `loadManifests(root)` and assert:

```js
test('legacy inventory has exactly one manifest for S1-S15', () => {
  const { loadManifests } = require('../scripts/lib/curriculum');
  const manifests = loadManifests(root);
  assert.deepEqual(manifests.map(({ id }) => id), Array.from({ length: 15 }, (_, i) => `s${i + 1}`));
  assert.ok(manifests.every((manifest) => validateManifest(manifest).length === 0));
});

test('legacy inventory does not overstate behavioral verification', () => {
  const { loadManifests } = require('../scripts/lib/curriculum');
  const manifests = loadManifests(root);
  assert.equal(manifests.some(({ maturity }) => maturity === 'verified'), false);
  assert.deepEqual(
    manifests.filter(({ maturity }) => maturity === 'external').map(({ id }) => id),
    ['s5', 's6'],
  );
});
```

Add a standards-reference test that rejects every OWASP or MITRE ID absent from the catalogs.

- [ ] **Step 2: Verify the empty-inventory failure**

Run `node --test test/curriculum-contract.test.js`.

Expected: inventory assertion receives `[]` instead of S1-S15.

- [ ] **Step 3: Create the 15 manifests using this exact inventory**

All manifests use `version: 1`, `external_network: false`, required platform `docker-desktop` unless shown as `linux-vm`, and optional platforms `[]`.

| ID | Title | Track | Mode | Maturity | MITRE | Attack | Verify |
|---|---|---|---|---|---|---|---|
| s1 | Port Scan | soc | docker-lab | runnable | T1595 | `attack/scripts/s1_portscan.sh` | `scripts/scenario_e2e_check.sh S1` |
| s2 | API Brute Force | appsec | docker-lab | runnable | T1110 | `attack/scripts/s2_bruteforce.sh` | `scripts/scenario_e2e_check.sh S2` |
| s3 | SQL Injection Attempt | appsec | docker-lab | runnable | T1190 | `attack/scripts/s3_sqli.sh` | `scripts/scenario_e2e_check.sh S3` |
| s4 | HTTP Denial of Service | soc | docker-lab | runnable | T1499 | `attack/scripts/s4_dos.sh` | `scripts/scenario_e2e_check.sh S4` |
| s5 | Important File Tampering | dfir | host-assisted | external | T1565 | `attack/scripts/s5_file_tamper.sh` | null |
| s6 | Sudo Activity Detection | dfir | host-assisted | external | T1548.003 | `attack/scripts/s6_privesc.sh` | null |
| s7 | Cross-Layer Incident | soc | docker-lab | runnable | T1595,T1110,T1190 | `attack/scripts/s7_lateral.sh` | `scripts/scenario_e2e_check.sh S7` |
| s8 | ARP Observation | foundation | docker-lab | runnable | T1046 | `attack/scripts/s8_l2_arp_observe.sh` | null |
| s9 | ICMP Reconnaissance | foundation | docker-lab | runnable | T1595 | `attack/scripts/s9_l3_icmp_recon.sh` | null |
| s10 | TCP State Observation | foundation | docker-lab | runnable | T1595 | `attack/scripts/s10_l4_tcp_state.sh` | null |
| s11 | Session Pressure | foundation | docker-lab | runnable | T1499 | `attack/scripts/s11_l5_session_stress.sh` | null |
| s12 | TLS Visibility Boundary | foundation | docker-lab | runnable | T1040,T1573 | `attack/scripts/s12_l6_tls_boundary.sh` | null |
| s13 | DNS Service Discovery | foundation | docker-lab | runnable | T1018 | `attack/scripts/s13_l7_dns_observe.sh` | null |
| s14 | SRE Incident Response | sre | operator-workflow | runnable | T1499 | `scripts/incident_drill.sh` | null |
| s15 | Integrated Capstone | governance | operator-workflow | documented | T1595,T1190,T1499 | null | null |

For all `runnable` manifests, set `workflow.remediate`, `workflow.regress`, and `assessment.verifier` to null so they cannot be mistaken for `verified`. Use evidence requirements appropriate to the row: every runnable attack requires `attack-result`; S1-S4/S7 additionally require `application-or-network-event` and `elasticsearch-event`; host-assisted labs require `vm-receipt`, `audit-event`, and `cleanup-result`.

- [ ] **Step 4: Run the inventory tests and commit**

Run:

```bash
node --test test/curriculum-contract.test.js
```

Expected: all tests pass and exactly 15 manifests load.

Commit:

```bash
git add curriculum/labs test/curriculum-contract.test.js
git commit -m "feat(curriculum): inventory legacy labs honestly"
```

## Task 4: Enforce Target Safety and Platform Readiness

**Files:**
- Create: `scripts/lib/target-policy.js`
- Create: `test/target-policy.test.js`
- Create: `scripts/learn`

- [ ] **Step 1: Write failing safety tests**

Create `test/target-policy.test.js`:

```js
const assert = require('node:assert/strict');
const test = require('node:test');
const { assertAllowedTarget } = require('../scripts/lib/target-policy');

const safety = {
  target_services: ['app', 'target-api'],
  allowed_cidrs: ['172.23.0.0/24'],
  external_network: false,
};

test('allows declared service names and addresses inside declared CIDRs', () => {
  assert.doesNotThrow(() => assertAllowedTarget('app', safety));
  assert.doesNotThrow(() => assertAllowedTarget('172.23.0.20', safety));
});

test('rejects loopback, public, link-local, undeclared private, URLs, and command fragments', () => {
  for (const target of [
    '127.0.0.1', '8.8.8.8', '169.254.169.254', '10.0.0.1',
    'https://example.com', 'app; id', '$(id)', '-oN',
  ]) {
    assert.throws(() => assertAllowedTarget(target, safety), /prohibited target/);
  }
});
```

- [ ] **Step 2: Verify module-not-found failure**

Run `node --test test/target-policy.test.js`.

- [ ] **Step 3: Implement strict IPv4 and service-name validation**

Create `scripts/lib/target-policy.js` using `node:net.isIP`. Convert IPv4 addresses to unsigned integers and compare with each CIDR mask. Service names must exactly match `/^[a-z0-9][a-z0-9-]*$/` and a declared entry. Reject any target beginning with `-` or containing URL, shell, whitespace, slash, colon, or interpolation syntax.

Export only:

```js
module.exports = { assertAllowedTarget, ipv4InCidr };
```

- [ ] **Step 4: Write the initial learner CLI**

Create executable `scripts/learn` in Node.js. Implement:

- `list`: tab-separated ID, maturity, platform, title.
- `show <id>`: pretty JSON manifest.
- `validate`: load catalogs and all manifests; print `Validated 15 lab manifests.`.
- `doctor <id>`: validate the manifest, require `docker info` for Docker Desktop labs, require Linux plus `SECURE_LEARN_VM_RECEIPT` for Linux VM labs, and print the safety boundary.
- all other commands: exit 2 with `Command '<name>' is reserved for the executable-lab slices.`.

Use `spawnSync` with argument arrays; never use `shell: true`.

- [ ] **Step 5: Add CLI contract tests**

Append to `test/curriculum-contract.test.js` using `spawnSync(process.execPath, ['scripts/learn', ...])` and assert list, show, validate, unknown lab, and reserved-command exit codes. Set a test-only `SECURE_LEARN_SKIP_DOCKER_CHECK=1` for doctor and implement that bypass only when `NODE_ENV === 'test'`.

- [ ] **Step 6: Run tests and commit**

Run:

```bash
chmod +x scripts/learn
node --test test/curriculum-contract.test.js test/target-policy.test.js
node --check scripts/learn
```

Expected: all tests pass.

Commit:

```bash
git add scripts/learn scripts/lib/target-policy.js test
git commit -m "feat(cli): add safe curriculum discovery"
```

## Task 5: Add Evidence Classification and Integrity

**Files:**
- Create: `scripts/lib/evidence.js`
- Create: `test/evidence-contract.test.js`
- Modify: `.gitignore`

- [ ] **Step 1: Write failing evidence tests**

Create `test/evidence-contract.test.js`:

```js
const assert = require('node:assert/strict');
const test = require('node:test');
const { classifyOutcome, createEvidence } = require('../scripts/lib/evidence');

test('keeps attack, telemetry, pipeline, control, regression, and cleanup separate', () => {
  assert.equal(classifyOutcome({ attack: true, telemetry: true, pipeline: true, control: true, regression: true, cleanup: true }), 'verified');
  assert.equal(classifyOutcome({ attack: true, telemetry: false, pipeline: false, control: true, regression: true, cleanup: true }), 'telemetry');
  assert.equal(classifyOutcome({ attack: true, telemetry: true, pipeline: true, control: false, regression: true, cleanup: true }), 'control');
  assert.equal(classifyOutcome({ attack: true, telemetry: true, pipeline: true, control: true, regression: true, cleanup: false }), 'cleanup');
});

test('creates deterministic evidence hashes without hashing the hash field', () => {
  const input = {
    lab: 's1', manifest_version: 1, platform: 'docker-desktop',
    started_at: '2026-07-17T00:00:00Z', ended_at: '2026-07-17T00:01:00Z',
    target: 'app', results: { attack: true, telemetry: true, pipeline: true, control: false, regression: false, cleanup: true },
  };
  const first = createEvidence(input);
  const second = createEvidence(input);
  assert.equal(first.sha256, second.sha256);
  assert.match(first.sha256, /^[a-f0-9]{64}$/);
  assert.equal(first.outcome, 'control');
});
```

- [ ] **Step 2: Verify module-not-found failure**

Run `node --test test/evidence-contract.test.js`.

- [ ] **Step 3: Implement stable serialization and ordered failure classification**

Create `scripts/lib/evidence.js`. `classifyOutcome` checks in this order: environment, safety, startup, attack, telemetry, pipeline, control, regression, evidence, cleanup, then verified. `createEvidence` recursively sorts object keys, computes SHA-256 over the evidence without `sha256`, and returns the object with `outcome` and `sha256`.

Add comments explaining why failure ordering is stable and why the hash excludes its own field.

- [ ] **Step 4: Ignore learner evidence**

Add:

```gitignore
# Learner evidence can contain local paths, timestamps, and lab-only identifiers.
evidence/results/
```

Keep the existing `reports/` rule. Do not ignore `evidence/schema`, `docs/templates`, or tracked release artifacts.

- [ ] **Step 5: Run tests and commit**

Run `node --test test/evidence-contract.test.js` and expect 2 passing tests.

Commit:

```bash
git add scripts/lib/evidence.js test/evidence-contract.test.js .gitignore
git commit -m "feat(evidence): classify and hash learning outcomes"
```

## Task 6: Generate Honest Coverage and Replace Keyword Success

**Files:**
- Create: `scripts/generate_curriculum_coverage.js`
- Create: `scripts/curriculum_check.sh`
- Create: `docs/curriculum/coverage.md`
- Modify: `scripts/world_class_curriculum_check.sh`
- Modify: `scripts/world_class_hands_on_check.sh`
- Modify: `test/curriculum-contract.test.js`

- [ ] **Step 1: Add failing generation tests**

Test that running the generator twice produces byte-identical output and the report contains:

```markdown
# Curriculum Runtime Coverage

| Maturity | Count |
| documented | 1 |
| runnable | 12 |
| verified | 0 |
| external | 2 |
```

Also assert the report lists every S1-S15 row and contains the sentence `Documentation does not count as runtime verification.`.

- [ ] **Step 2: Verify generator-not-found failure**

Run `node --test test/curriculum-contract.test.js`.

- [ ] **Step 3: Implement deterministic Markdown generation**

Create `scripts/generate_curriculum_coverage.js` using `loadManifests`. It writes only `docs/curriculum/coverage.md`, with fixed headings, counts in maturity order, and rows in manifest order. Do not include generation timestamps because they break deterministic output.

- [ ] **Step 4: Add the canonical curriculum gate**

Create executable `scripts/curriculum_check.sh` that:

```bash
node --test "$ROOT_DIR/test/curriculum-contract.test.js" "$ROOT_DIR/test/target-policy.test.js" "$ROOT_DIR/test/evidence-contract.test.js"
node "$ROOT_DIR/scripts/learn" validate
snapshot="$(mktemp)"
cp "$ROOT_DIR/docs/curriculum/coverage.md" "$snapshot"
node "$ROOT_DIR/scripts/generate_curriculum_coverage.js"
cmp "$snapshot" "$ROOT_DIR/docs/curriculum/coverage.md"
rm -f "$snapshot"
```

Use a trap to remove the snapshot on failure.

- [ ] **Step 5: Retain compatibility without keyword-based maturity**

Modify `world_class_curriculum_check.sh` to run `curriculum_check.sh` first. Keep HTML accessibility and structure checks, but delete `required_terms` as a completion signal.

Modify `world_class_hands_on_check.sh` so its top summary is calculated from manifests. Topic prose/file checks may remain under a separate `Supporting material` heading, but they must not increment maturity totals.

- [ ] **Step 6: Generate, test, and commit**

Run:

```bash
chmod +x scripts/curriculum_check.sh
node scripts/generate_curriculum_coverage.js
scripts/curriculum_check.sh
scripts/world_class_curriculum_check.sh
```

Expected: coverage reports 1 documented, 12 runnable, 0 verified, and 2 external; all gates pass.

Commit:

```bash
git add scripts docs/curriculum/coverage.md test/curriculum-contract.test.js
git commit -m "fix(curriculum): derive coverage from runtime maturity"
```

## Task 7: Correct Public Curriculum Semantics

**Files:**
- Modify: `docs/curriculum/owasp-api-security-track.md`
- Modify: `docs/curriculum/world-class-scenario-evaluation.md`
- Modify: `scenarios/S5_file_tamper.md`
- Modify: `scenarios/S7_lateral.md`
- Modify: `scenarios/S8_l2_arp_observe.md`
- Modify: `attack/scripts/s7_lateral.sh`
- Modify: `scripts/generate_scenario_html.js`
- Modify: `test/product-readiness.test.js`

- [ ] **Step 1: Write failing copy and mapping regressions**

Add product-readiness assertions that:

- API6 is Sensitive Business Flows, API7 is SSRF, API8 is Security Misconfiguration.
- API8 is not Injection.
- S5 calls T1565 Data Manipulation / Impact.
- S8 calls T1046 Discovery.
- S7 title is Cross-Layer Incident and public copy does not claim genuine APT or Lateral Movement.
- scenario evaluation does not call all S1-S15 executable labs.

- [ ] **Step 2: Run the focused test and verify failures**

Run:

```bash
node --test --test-name-pattern "OWASP|MITRE|cross-layer|curriculum" test/product-readiness.test.js
```

Expected: failures cite the current API6-API8 table, S5/S8 mappings, S7 copy, and evaluation table.

- [ ] **Step 3: Correct source documentation and generators**

Apply these exact semantic changes:

- API6 `Unrestricted Access to Sensitive Business Flows` with inventory/automation abuse exercise.
- API7 `Server Side Request Forgery`.
- API8 `Security Misconfiguration`.
- Injection remains a supporting secure-coding topic, not API8:2023.
- S5 `Impact - Data Manipulation (T1565)`.
- S8 `Discovery - Network Service Discovery (T1046)`.
- S7 `Cross-Layer Incident`; explain it chains events against one trust zone and is not lateral movement.
- Keep `s7_lateral.sh` as a compatibility filename, but print `Cross-Layer Incident` and remove `APT`/`Lateral Movement` success claims.
- Scenario evaluation uses the same 11 Docker, 2 host-assisted, 2 workflow, 18 design split as README.

- [ ] **Step 4: Regenerate HTML and run regressions**

Run:

```bash
node scripts/generate_scenario_html.js
scripts/scenario_html_check.sh
node --test test/product-readiness.test.js
git diff --check
```

Expected: all product tests and HTML checks pass.

- [ ] **Step 5: Commit**

```bash
git add docs scenarios attack/scripts/s7_lateral.sh scripts/generate_scenario_html.js test/product-readiness.test.js
git commit -m "fix(curriculum): correct security framework semantics"
```

## Task 8: Integrate the Foundation into Local and CI Gates

**Files:**
- Modify: `scripts/lab_quality_gate.sh`
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`
- Modify: `.github/PULL_REQUEST_TEMPLATE.md`
- Modify: `test/product-readiness.test.js`

- [ ] **Step 1: Write failing gate-contract tests**

Assert that:

- local quality gate runs `node --test test/*.test.js` and `scripts/curriculum_check.sh`;
- CI runs `scripts/curriculum_check.sh`;
- CI regenerates coverage and fails on a diff;
- README links `docs/curriculum/coverage.md` and documents `scripts/learn list`, `show`, `validate`, and `doctor`;
- PR template asks for manifest maturity and platform evidence when a lab changes.

- [ ] **Step 2: Verify focused failures**

Run `node --test --test-name-pattern "curriculum foundation gate" test/product-readiness.test.js`.

- [ ] **Step 3: Update the local gate**

Run root tests before Docker builds and add `curriculum_check.sh` before generated HTML checks. Renumber the displayed steps consistently. Do not weaken `REQUIRE_RUNTIME` behavior.

- [ ] **Step 4: Update CI**

In the Compose validation job, replace the single product-readiness invocation with:

```yaml
- name: Product and curriculum contract tests
  run: scripts/curriculum_check.sh
```

In the docs job, regenerate `docs/curriculum/coverage.md` and include it in the committed-output diff check.

- [ ] **Step 5: Update public entry points and PR evidence**

README must explain the four maturity values, link the generated coverage report, and state that `verified` requires attack, observation/control, remediation, regression, assessment, evidence, and cleanup checks.

The PR template adds checkboxes for affected lab IDs, platform, maturity transition, and cleanup evidence.

- [ ] **Step 6: Run the complete static gate and commit**

Run:

```bash
scripts/curriculum_check.sh
node --test test/*.test.js
scripts/learning_phase_check.sh
scripts/world_class_curriculum_check.sh
find attack/scripts scripts elk -type f -name '*.sh' -print0 | xargs -0 bash -n
git diff --check
```

Expected: all commands pass.

Commit:

```bash
git add scripts/lab_quality_gate.sh .github README.md test/product-readiness.test.js
git commit -m "ci(curriculum): enforce manifest-based readiness"
```

## Task 9: Foundation Self-Review and Release Evidence

**Files:**
- Modify only files required to fix discovered defects.

- [ ] **Step 1: Verify spec coverage**

Confirm this slice implements:

- versioned standards data;
- one manifest per S1-S15;
- honest maturity with no verified legacy lab;
- safety target validation;
- platform doctor behavior;
- separate outcome classification;
- deterministic evidence hashing;
- generated coverage;
- corrected public taxonomy;
- local and CI enforcement.

- [ ] **Step 2: Run security and repository checks**

Run:

```bash
npm --prefix app audit --omit=dev --audit-level=high
node --test test/*.test.js
scripts/curriculum_check.sh
scripts/k8s_static_check.sh
docker compose config -q
git diff --check main...HEAD
git status --short --branch
```

Expected: audits and tests pass; Compose is valid; only intentional branch commits differ from main; worktree is clean.

- [ ] **Step 3: Review dangerous execution paths**

Run:

```bash
rg -n "shell:\s*true|exec\(|eval\(|child_process|docker\.sock|network_mode:\s*host|privileged:\s*true" scripts curriculum
```

Expected: the learner CLI has no `shell: true`, `exec`, or `eval`; any existing Docker socket use remains outside the launcher and is documented for release tooling only.

- [ ] **Step 4: Record completion**

Add a changelog entry describing the foundation without claiming the later AppSec, Kubernetes, DFIR, Linux, or cloud labs are implemented.

Commit:

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): record curriculum truth foundation"
```

## Completion Gate

The foundation slice is complete only when:

```bash
scripts/curriculum_check.sh
node --test test/*.test.js
scripts/world_class_curriculum_check.sh
scripts/learning_phase_check.sh
scripts/k8s_static_check.sh
docker compose config -q
git diff --check main...HEAD
```

all pass, the worktree is clean, and the generated report shows `verified: 0` until later executable-lab plans satisfy the full contract.
