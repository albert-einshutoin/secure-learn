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
  'grep', 'head', 'hostname', 'hydra', 'ip', 'jq', 'mkdir', 'nc', 'nmap',
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

function runScript(relativePath, fake, overrides = {}) {
  return spawnSync(bash, [path.join(root, relativePath)], {
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
      PAYLOAD_MARKER: payloadMarker,
      TARGET: '$(touch "$PAYLOAD_MARKER")',
    });
    assert.notEqual(result.status, 0, `${relativePath} accepted a target payload`);
    assert.equal(fs.existsSync(payloadMarker), false, `${relativePath} evaluated its target payload`);
    assert.equal(fs.existsSync(fake.marker), false, `${relativePath} invoked a tool for its target payload`);
  }
});

test('S11 rejects unsafe or excessive load values without evaluating payloads', (t) => {
  const unsafeValues = ['0', '-1', '51', '1.5', '$(touch "$PAYLOAD_MARKER")'];
  for (const value of unsafeValues) {
    const fake = makeFakePath(t);
    const payloadMarker = path.join(fake.directory, 'payload-executed');
    const result = runScript('attack/scripts/s11_l5_session_stress.sh', fake, {
      PAYLOAD_MARKER: payloadMarker,
      SESSIONS: value,
    });
    assert.notEqual(result.status, 0, `S11 accepted SESSIONS=${value}`);
    assert.equal(fs.existsSync(payloadMarker), false, `S11 evaluated SESSIONS=${value}`);
    assert.equal(fs.existsSync(fake.marker), false, `S11 invoked a tool for SESSIONS=${value}`);
  }

  for (const value of ['0', '-1', '16', '1.5', '$(touch "$PAYLOAD_MARKER")']) {
    const fake = makeFakePath(t);
    const payloadMarker = path.join(fake.directory, 'payload-executed');
    const result = runScript('attack/scripts/s11_l5_session_stress.sh', fake, {
      PAYLOAD_MARKER: payloadMarker,
      HOLD_SECONDS: value,
    });
    assert.notEqual(result.status, 0, `S11 accepted HOLD_SECONDS=${value}`);
    assert.equal(fs.existsSync(payloadMarker), false, `S11 evaluated HOLD_SECONDS=${value}`);
    assert.equal(fs.existsSync(fake.marker), false, `S11 invoked a tool for HOLD_SECONDS=${value}`);
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

  assert.match(source, /BASE_URL="\$\{BASE_URL:-http:\/\/127\.0\.0\.1:3000\}"/);
  assert.match(source, /unset COMPOSE_PROJECT_DIR/);
  assert.doesNotMatch(source, /\$\{COMPOSE_PROJECT_DIR:-/);
  assert.match(source, /ROOT_DIR="\$\(cd "\$SCRIPT_DIR\/\.\." && pwd -P\)"/);
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

test('Docker Compose accepts the contained network configuration when available', (t) => {
  const available = spawnSync('docker', ['compose', 'version'], { cwd: root, encoding: 'utf8' });
  if (available.status !== 0) {
    t.skip('docker compose is unavailable');
    return;
  }

  for (const composeFile of ['docker-compose.yml', 'docker-compose.exercise.yml']) {
    const result = spawnSync('docker', ['compose', '-f', composeFile, 'config', '--quiet'], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, `${composeFile}: ${result.stderr}`);
  }
});
