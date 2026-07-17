'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const root = path.resolve(__dirname, '..');
const bash = '/bin/bash';
const attackScripts = [
  'attack/scripts/s1_portscan.sh',
  'attack/scripts/s2_bruteforce.sh',
  'attack/scripts/s3_sqli.sh',
  'attack/scripts/s4_dos.sh',
  'attack/scripts/s7_lateral.sh',
  'attack/scripts/s8_l2_arp_observe.sh',
  'attack/scripts/s9_l3_icmp_recon.sh',
  'attack/scripts/s10_l4_tcp_state.sh',
  'attack/scripts/s11_l5_session_stress.sh',
  'attack/scripts/s12_l6_tls_boundary.sh',
  'attack/scripts/s13_l7_dns_observe.sh',
];
const interceptedTools = [
  'arping', 'awk', 'cat', 'curl', 'cut', 'date', 'dig', 'docker', 'getent',
  'dirname', 'grep', 'head', 'hostname', 'hydra', 'ip', 'jq', 'mkdir', 'nc', 'nmap',
  'openssl', 'ping', 'seq', 'sleep', 'sqlmap', 'tail', 'tee', 'timeout',
  'traceroute',
];

function makeFakePath(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-learn-fake-tools-'));
  const marker = path.join(directory, 'invoked.log');
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  for (const tool of interceptedTools) {
    const executable = path.join(directory, tool);
    fs.writeFileSync(executable, '#!/bin/sh\nprintf "%s\\n" "$0" >> "$TOOL_MARKER"\nexit 0\n');
    fs.chmodSync(executable, 0o755);
  }
  return { directory, marker };
}

function runScript(relativePath, fake, overrides = {}, args = []) {
  return spawnSync(bash, [path.join(root, relativePath), ...args], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: fake.directory,
      TOOL_MARKER: fake.marker,
      OUTPUT_DIR: path.join(fake.directory, 'results'),
      ...overrides,
    },
  });
}

function networkBlock(source, name) {
  const match = source.match(new RegExp(`^  ${name}:\\n((?: {4}.*\\n|\\s*\\n)*)`, 'm'));
  assert.ok(match, `missing network ${name}`);
  return match[1];
}

test('shared target guard accepts only the two enumerated lab profiles', () => {
  const guard = path.join(root, 'scripts/lib/target_guard.sh');
  const runGuard = (environment) => spawnSync(bash, ['-c', `source "$1"; secure_learn_validate_target`, '_', guard], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH, ...environment },
  });

  assert.equal(runGuard({}).status, 0);
  assert.equal(runGuard({ TARGET: 'app', TARGET_IP: '172.23.0.20', TARGET_PORT: '3000' }).status, 0);
  assert.equal(runGuard({ SECURE_LEARN_TARGET_PROFILE: 'exercise', TARGET: 'target-app', TARGET_IP: '172.32.0.100', TARGET_PORT: '3000' }).status, 0);

  for (const environment of [
    { SECURE_LEARN_TARGET_PROFILE: 'custom' },
    { TARGET: '' },
    { TARGET: 'example.com' },
    { TARGET: 'http://app:3000' },
    { TARGET: 'user@app' },
    { TARGET: 'app target' },
    { TARGET: '-app' },
    { TARGET_IP: '8.8.8.8' },
    { TARGET_IP: '169.254.169.254' },
    { TARGET_PORT: '80' },
  ]) {
    assert.notEqual(runGuard(environment).status, 0, `guard accepted ${JSON.stringify(environment)}`);
  }
});

test('S1-S4 and S7-S13 reject undeclared targets before invoking any external tool', (t) => {
  for (const relativePath of attackScripts) {
    const fake = makeFakePath(t);
    const result = runScript(relativePath, fake, { TARGET: 'example.com' });
    assert.notEqual(result.status, 0, `${relativePath} accepted an external target`);
    assert.equal(fs.existsSync(fake.marker), false, `${relativePath} invoked a tool before rejecting its target`);
  }
});

test('attack scripts reject unknown target profiles before invoking any external tool', (t) => {
  for (const relativePath of attackScripts) {
    const fake = makeFakePath(t);
    const result = runScript(relativePath, fake, { SECURE_LEARN_TARGET_PROFILE: '172.23.0.0/24' });
    assert.notEqual(result.status, 0, `${relativePath} accepted a caller-defined profile`);
    assert.equal(fs.existsSync(fake.marker), false, `${relativePath} invoked a tool before rejecting its profile`);
  }
});

test('attack scripts treat target command substitutions as inert rejected data', (t) => {
  for (const relativePath of attackScripts) {
    const fake = makeFakePath(t);
    const payloadMarker = path.join(fake.directory, 'target-payload-executed');
    const result = runScript(relativePath, fake, {
      TARGET: `$(printf owned > ${payloadMarker})`,
    });
    assert.notEqual(result.status, 0, `${relativePath} accepted a target payload`);
    assert.equal(fs.existsSync(payloadMarker), false, `${relativePath} evaluated its target payload`);
    assert.equal(fs.existsSync(fake.marker), false, `${relativePath} invoked a tool for its target payload`);
  }
});

test('bounded decimal validator accepts every documented boundary as decimal', () => {
  const guard = path.join(root, 'scripts/lib/target_guard.sh');
  const accepted = [
    ['CONCURRENT', '1', '1', '50'], ['CONCURRENT', '50', '1', '50'],
    ['REQUESTS', '1', '1', '500'], ['REQUESTS', '500', '1', '500'],
    ['DELAY', '0', '0', '10'], ['DELAY', '10', '0', '10'],
    ['BURST', '1', '1', '20'], ['BURST', '20', '1', '20'],
    ['PING_COUNT', '1', '1', '20'], ['PING_COUNT', '20', '1', '20'],
    ['COUNT', '1', '1', '20'], ['COUNT', '20', '1', '20'],
    ['SESSIONS', '1', '1', '50'], ['SESSIONS', '50', '1', '50'],
    ['HOLD_SECONDS', '1', '1', '15'], ['HOLD_SECONDS', '15', '1', '15'],
    ['SLO_MS', '1', '1', '10000'], ['SLO_MS', '10000', '1', '10000'],
    // Leading zeroes are intentionally accepted and interpreted in base 10.
    ['DELAY', '00', '0', '10'], ['REQUESTS', '0500', '1', '500'],
  ];

  for (const [name, value, minimum, maximum] of accepted) {
    const result = spawnSync(bash, ['-c', 'source "$1"; secure_learn_validate_bounded_decimal "$2" "$3" "$4" "$5"', '_', guard, name, value, minimum, maximum], {
      encoding: 'utf8',
      env: { PATH: process.env.PATH },
    });
    assert.equal(result.status, 0, `${name}=${value}: ${result.stderr}`);
  }
});

test('quality gate rejects every non-canonical runtime endpoint before tools run', (t) => {
  const cases = [
    { APP_BASE_URL: 'https://example.com' },
    { APP_HEALTH_URL: 'http://127.0.0.1:3000/health?next=https://example.com' },
    { ELASTICSEARCH_URL: 'http://169.254.169.254:9200' },
    { KIBANA_URL: 'http://user@127.0.0.1:5601' },
  ];
  for (const overrides of cases) {
    const fake = makeFakePath(t);
    const result = runScript('scripts/lab_quality_gate.sh', fake, overrides);
    assert.notEqual(result.status, 0, `quality gate accepted ${JSON.stringify(overrides)}`);
    assert.equal(fs.existsSync(fake.marker), false, 'quality gate invoked a tool before endpoint validation');
  }
});

test('shared endpoint validator accepts only canonical local quality endpoints', () => {
  const guard = path.join(root, 'scripts/lib/target_guard.sh');
  for (const [name, value, expected] of [
    ['APP_BASE_URL', 'http://127.0.0.1:3000', 'http://127.0.0.1:3000'],
    ['APP_HEALTH_URL', 'http://127.0.0.1:3000/health', 'http://127.0.0.1:3000/health'],
    ['ELASTICSEARCH_URL', 'http://127.0.0.1:9200', 'http://127.0.0.1:9200'],
    ['KIBANA_URL', 'http://127.0.0.1:5601', 'http://127.0.0.1:5601'],
  ]) {
    const result = spawnSync(bash, ['-c', 'source "$1"; secure_learn_validate_exact_loopback_endpoint "$2" "$3" "$4"', '_', guard, name, value, expected], {
      encoding: 'utf8',
      env: { PATH: process.env.PATH },
    });
    assert.equal(result.status, 0, `${name}: ${result.stderr}`);
  }
});

test('S11 rejects unsafe or excessive load values without evaluating payloads', (t) => {
  const unsafeValues = ['0', '-1', '51', '1.5'];
  for (const value of unsafeValues) {
    const fake = makeFakePath(t);
    const payloadMarker = path.join(fake.directory, 'payload-executed');
    const result = runScript('attack/scripts/s11_l5_session_stress.sh', fake, {
      SESSIONS: value,
    });
    assert.notEqual(result.status, 0, `S11 accepted SESSIONS=${value}`);
    assert.equal(fs.existsSync(payloadMarker), false, `S11 evaluated SESSIONS=${value}`);
    assert.equal(fs.existsSync(fake.marker), false, `S11 invoked a tool for SESSIONS=${value}`);
  }

  for (const value of ['0', '-1', '16', '1.5']) {
    const fake = makeFakePath(t);
    const payloadMarker = path.join(fake.directory, 'payload-executed');
    const result = runScript('attack/scripts/s11_l5_session_stress.sh', fake, {
      HOLD_SECONDS: value,
    });
    assert.notEqual(result.status, 0, `S11 accepted HOLD_SECONDS=${value}`);
    assert.equal(fs.existsSync(payloadMarker), false, `S11 evaluated HOLD_SECONDS=${value}`);
    assert.equal(fs.existsSync(fake.marker), false, `S11 invoked a tool for HOLD_SECONDS=${value}`);
  }
});

test('arithmetic payload detection uses shell builtins and catches pre-validation evaluation', (t) => {
  for (const parameter of ['SESSIONS', 'HOLD_SECONDS']) {
    const fake = makeFakePath(t);
    const payloadMarker = path.join(fake.directory, `${parameter.toLowerCase()}-payload-executed`);
    const payload = `x[$(printf owned > ${payloadMarker})]`;
    const result = runScript('attack/scripts/s11_l5_session_stress.sh', fake, { [parameter]: payload });
    assert.notEqual(result.status, 0, `S11 accepted an arithmetic payload in ${parameter}`);
    assert.equal(fs.existsSync(payloadMarker), false, `S11 evaluated ${parameter} before validating it`);
    assert.equal(fs.existsSync(fake.marker), false, `S11 invoked an external tool for ${parameter}`);
  }
});

test('bounded attack parameters are rejected before tools or output files', (t) => {
  const cases = [
    ['attack/scripts/s4_dos.sh', { CONCURRENT: '51' }],
    ['attack/scripts/s4_dos.sh', { CONCURRENT: '1.5' }],
    ['attack/scripts/s4_dos.sh', { REQUESTS: '501' }],
    ['attack/scripts/s4_dos.sh', { REQUESTS: '-1' }],
    ['attack/scripts/s7_lateral.sh', { DELAY: '11' }],
    ['attack/scripts/s7_lateral.sh', { DELAY: '1.5' }],
    ['attack/scripts/s8_l2_arp_observe.sh', { BURST: '21' }],
    ['attack/scripts/s8_l2_arp_observe.sh', { BURST: 'many' }],
    ['attack/scripts/s9_l3_icmp_recon.sh', { PING_COUNT: '21' }],
    ['attack/scripts/s9_l3_icmp_recon.sh', { PING_COUNT: '-1' }],
    ['attack/scripts/s10_l4_tcp_state.sh', { SCAN_PORTS: '1-65535' }],
    ['attack/scripts/s13_l7_dns_observe.sh', { COUNT: '21' }],
    ['attack/scripts/s13_l7_dns_observe.sh', { COUNT: '1.5' }],
  ];

  for (const [relativePath, overrides] of cases) {
    const fake = makeFakePath(t);
    const result = runScript(relativePath, fake, overrides);
    assert.notEqual(result.status, 0, `${relativePath} accepted ${JSON.stringify(overrides)}`);
    assert.equal(fs.existsSync(fake.marker), false, `${relativePath} invoked a tool for ${JSON.stringify(overrides)}`);
    assert.equal(fs.existsSync(path.join(fake.directory, 'results')), false, `${relativePath} created output for invalid input`);
  }
});

test('S14 validates load and chaos controls before invoking children or creating reports', (t) => {
  const cases = [
    { REQUESTS: '501' },
    { REQUESTS: '1.5' },
    { CONCURRENCY: '51' },
    { CONCURRENCY: '-1' },
    { SLO_MS: '10001' },
    { RUN_CHAOS: 'yes' },
  ];
  for (const overrides of cases) {
    const fake = makeFakePath(t);
    const reportDir = path.join(fake.directory, 'incident-report');
    const result = runScript('scripts/incident_drill.sh', fake, { REPORT_DIR: reportDir, ...overrides });
    assert.notEqual(result.status, 0, `S14 accepted ${JSON.stringify(overrides)}`);
    assert.equal(fs.existsSync(reportDir), false);
    assert.equal(fs.existsSync(fake.marker), false);
  }
});

test('direct S14 child runners enforce the same loopback and bounded-load contract', (t) => {
  const cases = [
    ['scripts/load_hands_on_tests.sh', { BASE_URL: 'https://example.com' }],
    ['scripts/load_hands_on_tests.sh', { REQUESTS: '501' }],
    ['scripts/load_hands_on_tests.sh', { CONCURRENCY: '51' }],
    ['scripts/load_hands_on_tests.sh', { SLO_MS: '10001' }],
    ['scripts/backend_hands_on_tests.sh', { BASE_URL: 'file:///tmp/lab' }],
    ['scripts/chaos_hands_on_tests.sh', { BASE_URL: 'http://user@127.0.0.1:3000' }],
  ];
  for (const [relativePath, overrides] of cases) {
    const fake = makeFakePath(t);
    const reportDir = path.join(fake.directory, 'child-report');
    const result = runScript(relativePath, fake, { REPORT_DIR: reportDir, ...overrides });
    assert.notEqual(result.status, 0, `${relativePath} accepted ${JSON.stringify(overrides)}`);
    assert.equal(fs.existsSync(reportDir), false);
    assert.equal(fs.existsSync(fake.marker), false);
  }
});

test('S14 rejects non-loopback URLs before reports, child scripts, or Docker can run', (t) => {
  for (const baseUrl of ['https://example.com', 'http://user@127.0.0.1:3000', 'file:///tmp/lab']) {
    const fake = makeFakePath(t);
    const reportDir = path.join(fake.directory, 'incident-report');
    const result = runScript('scripts/incident_drill.sh', fake, { BASE_URL: baseUrl, REPORT_DIR: reportDir });
    assert.notEqual(result.status, 0, `S14 accepted ${baseUrl}`);
    assert.equal(fs.existsSync(reportDir), false, `S14 created output before rejecting ${baseUrl}`);
    assert.equal(fs.existsSync(fake.marker), false, `S14 invoked a tool before rejecting ${baseUrl}`);
  }
});

test('S14 fixes its endpoint and Compose project to repository-controlled locations', () => {
  const source = fs.readFileSync(path.join(root, 'scripts/incident_drill.sh'), 'utf8');
  const chaosSource = fs.readFileSync(path.join(root, 'scripts/chaos_hands_on_tests.sh'), 'utf8');
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'curriculum/labs/s14.json'), 'utf8'));

  assert.match(source, /BASE_URL="\$\{BASE_URL:-http:\/\/127\.0\.0\.1:3000\}"/);
  assert.match(source, /unset COMPOSE_PROJECT_DIR/);
  assert.doesNotMatch(source, /\$\{COMPOSE_PROJECT_DIR:-/);
  assert.match(source, /ROOT_DIR="\$\(cd "\$SCRIPT_DIR\/\.\." && pwd -P\)"/);
  assert.match(chaosSource, /unset COMPOSE_PROJECT_DIR/);
  assert.doesNotMatch(chaosSource, /\$\{COMPOSE_PROJECT_DIR:-/);
  assert.deepEqual(manifest.safety.target_services, ['localhost']);
  assert.deepEqual(manifest.safety.allowed_cidrs, ['127.0.0.1/32']);
});

test('attack connections use the validated IP while service identity stays separate', () => {
  for (const relativePath of attackScripts.filter((name) => !name.includes('s13_'))) {
    const source = fs.readFileSync(path.join(root, relativePath), 'utf8');
    const executableLines = source.split('\n').filter((line) => !/^\s*(?:#|echo\b)/.test(line)).join('\n');
    assert.doesNotMatch(executableLines, /https?:\/\/\$TARGET:/, `${relativePath} connects by unverified service name`);
    assert.doesNotMatch(executableLines, /"\$TARGET"\s+"\$TARGET_PORT"/, `${relativePath} connects by unverified service name`);
  }

  const dnsSource = fs.readFileSync(path.join(root, 'attack/scripts/s13_l7_dns_observe.sh'), 'utf8');
  assert.match(dnsSource, /resolved_target_ip/);
  assert.match(dnsSource, /!= "\$TARGET_IP"/);
});

test('attack networks are internal even when Docker Compose is unavailable', () => {
  const base = fs.readFileSync(path.join(root, 'docker-compose.yml'), 'utf8');
  const exercise = fs.readFileSync(path.join(root, 'docker-compose.exercise.yml'), 'utf8');

  assert.match(networkBlock(base, 'app_net'), /^ {4}internal: true$/m);
  assert.match(networkBlock(exercise, 'red_team'), /^ {4}internal: true$/m);
  assert.match(networkBlock(exercise, 'shared_target'), /^ {4}internal: true$/m);
  assert.match(exercise, /^ {6}- SECURE_LEARN_TARGET_PROFILE=exercise$/m);
  assert.match(exercise, /^ {6}- TARGET=target-app$/m);
});

test('IPS helper installs iptables at build time and never fetches packages at runtime', () => {
  const compose = fs.readFileSync(path.join(root, 'docker-compose.ips.yml'), 'utf8');
  const dockerfile = fs.readFileSync(path.join(root, 'docker/ips-iptables/Dockerfile'), 'utf8');

  assert.match(compose, /ips-iptables:\n\s+build:\n\s+context: \.\/docker\/ips-iptables/);
  assert.doesNotMatch(compose, /apk add/);
  assert.match(dockerfile, /^FROM alpine:3\.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce$/m);
  assert.match(dockerfile, /^RUN apk add --no-cache iptables=1\.8\.11-r1$/m);
});

test('CI and release evidence cover the privileged IPS helper image', () => {
  const ci = fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8');
  const releaseWorkflow = fs.readFileSync(path.join(root, '.github/workflows/release.yml'), 'utf8');
  const releaseArtifacts = fs.readFileSync(path.join(root, 'scripts/release_artifacts.sh'), 'utf8');
  const releasePolicy = fs.readFileSync(path.join(root, 'docs/release-policy.md'), 'utf8');

  assert.match(ci, /scripts\/release_artifacts\.sh/);
  assert.doesNotMatch(ci, /docker run --rm --network none "secure-learn-ips-iptables/);
  assert.match(releaseArtifacts, /IPS_IMAGE="secure-learn-ips-iptables:\$VERSION"/);
  assert.match(releaseArtifacts, /"\$ROOT_DIR\/scripts\/verify_ips_helper\.sh" "\$IPS_IMAGE"/);
  assert.match(releaseArtifacts, /secure-learn-ips-iptables-\$VERSION\.trivy\.json/);
  assert.match(releaseArtifacts, /secure-learn-ips-iptables-\$VERSION\.spdx\.json/);
  assert.match(releaseWorkflow, /scripts\/release_artifacts\.sh/);
  assert.match(releaseWorkflow, /ips=.*secure-learn-ips-iptables:/);
  assert.match(releaseWorkflow, /subject-name: secure-learn-ips-iptables:/);
  assert.match(releaseWorkflow, /sbom-path: release\/secure-learn-ips-iptables-\$\{\{ steps\.version\.outputs\.version \}\}\.spdx\.json/);
  assert.match(releasePolicy, /three images/i);
  assert.match(releasePolicy, /networkless.*NFQUEUE/i);
  assert.match(releasePolicy, /three.*SBOM/i);
  assert.match(releasePolicy, /three.*attestation/i);
});

test('shared IPS verifier uses fixed Docker argv and rejects unsafe image references', (t) => {
  const fake = makeFakePath(t);
  const docker = path.join(fake.directory, 'docker');
  fs.writeFileSync(docker, '#!/bin/sh\nprintf "<call>\\n" >> "$TOOL_MARKER"\nprintf "%s\\n" "$@" >> "$TOOL_MARKER"\n');
  fs.chmodSync(docker, 0o755);

  const image = 'secure-learn-ips-iptables:1.0.0';
  const accepted = runScript('scripts/verify_ips_helper.sh', fake, {}, [image]);
  assert.equal(accepted.status, 0, accepted.stderr);
  const calls = fs.readFileSync(fake.marker, 'utf8');
  assert.equal((calls.match(/^<call>$/gm) || []).length, 2);
  assert.match(calls, /--network\nnone\nsecure-learn-ips-iptables:1\.0\.0\niptables\n--version/);
  assert.match(calls, /--network\nnone\n--cap-add\nNET_ADMIN\nsecure-learn-ips-iptables:1\.0\.0\nsh\n-euc/);
  assert.match(calls, /NFQUEUE/);
  assert.match(calls, /iptables -C/);

  for (const malicious of ['-evil', 'image;id', '$(id)', 'https://example.com/image', 'UPPER/repo:tag', 'repo tag']) {
    fs.rmSync(fake.marker, { force: true });
    const rejected = runScript('scripts/verify_ips_helper.sh', fake, {}, [malicious]);
    assert.notEqual(rejected.status, 0, `accepted ${malicious}`);
    assert.equal(fs.existsSync(fake.marker), false, `invoked docker for ${malicious}`);
  }
});

test('Docker Compose accepts the contained network configuration when available', (t) => {
  const available = spawnSync('docker', ['compose', 'version'], { cwd: root, encoding: 'utf8' });
  if (available.status !== 0) {
    t.skip('docker compose is unavailable');
    return;
  }

  const configurations = [
    ['-f', 'docker-compose.yml'],
    ['-f', 'docker-compose.exercise.yml'],
    ['-f', 'docker-compose.yml', '-f', 'docker-compose.ips.yml'],
  ];
  for (const composeArgs of configurations) {
    const result = spawnSync('docker', ['compose', ...composeArgs, 'config', '--quiet'], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, `${composeArgs.join(' ')}: ${result.stderr}`);
  }
});
