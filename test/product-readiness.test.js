const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..');

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

test('all published Compose ports are restricted to localhost', () => {
  const composeFiles = fs
    .readdirSync(root)
    .filter((name) => /^docker-compose.*\.yml$/.test(name));

  const unsafeMappings = [];
  for (const file of composeFiles) {
    for (const [index, line] of read(file).split('\n').entries()) {
      const match = line.match(/^\s*-\s*["']?(\d[^"']*:\d+)["']?\s*$/);
      if (match && !match[1].startsWith('127.0.0.1:')) {
        unsafeMappings.push(`${file}:${index + 1}:${match[1]}`);
      }
    }
  }

  assert.deepEqual(unsafeMappings, []);
});

test('Filebeat uses regular daily indices with a compatible lifecycle policy', () => {
  const config = read('elk/filebeat/filebeat.yml');

  assert.match(config, /setup\.ilm\.enabled:\s*false/);
  assert.match(config, /setup\.template\.enabled:\s*false/);
  assert.doesNotMatch(config, /setup\.ilm\.rollover_alias/);
  assert.doesNotMatch(config, /setup\.template\.pattern/);
});

test('base Compose bootstraps Elasticsearch and Kibana before Filebeat starts', () => {
  const compose = read('docker-compose.yml');

  assert.match(compose, /\n\s{2}siem-setup:\n/);
  assert.match(compose, /siem-bootstrap\.sh/);
  assert.match(compose, /service_completed_successfully/);
  assert.match(compose, /\.\/elk\/kibana\/kibana\.yml:\/usr\/share\/kibana\/config\/kibana\.yml:ro/);
  assert.equal(fs.existsSync(path.join(root, 'elk/siem-bootstrap.sh')), true);
});

test('traffic inspection, application, and banning share a stable namespace anchor', () => {
  for (const file of ['docker-compose.yml', 'docker-compose.exercise.yml']) {
    const compose = read(file);
    const sharedNamespaceReferences = compose.match(/network_mode:\s*["']service:target-netns["']/g) || [];

    assert.match(compose, /\n\s{2}target-netns:\n/);
    assert.equal(sharedNamespaceReferences.length, 3, file);

    const sharedServices = file === 'docker-compose.yml' ? ['suricata', 'app', 'fail2ban'] : ['suricata', 'target_app', 'fail2ban'];
    for (const service of sharedServices) {
      const section = compose.match(new RegExp(`\\n  ${service}:[\\s\\S]*?(?=\\n  [a-zA-Z]|\\n#)`))?.[0] || '';
      assert.doesNotMatch(section, /\n\s+hostname:/, `${file}:${service}`);
    }
  }

  const exercise = read('docker-compose.exercise.yml');
  const fail2banSection = exercise.match(/\n\s{2}fail2ban:[\s\S]*?\n\s{2}elasticsearch:/)?.[0] || '';
  const filebeatSection = exercise.match(/\n\s{2}filebeat:[\s\S]*?\n\s{2}exercise_controller:/)?.[0] || '';

  assert.match(fail2banSection, /fail2ban_logs:\/var\/log\/fail2ban/);
  assert.match(filebeatSection, /fail2ban_logs:\/var\/log\/fail2ban:ro/);
});

test('Kibana objects reference the bundled all-events data view', () => {
  for (const file of [
    'elk/kibana/exports/saved-searches.ndjson',
    'elk/kibana/exports/dashboards.ndjson',
    'elk/kibana/exports/kpi-dashboard.ndjson',
  ]) {
    const contents = read(file);
    assert.doesNotMatch(contents, /soc-lab-\*/, file);
    assert.match(contents, /"id":"soc-lab-all"/, file);
  }
});

test('Fail2ban evaluates UTC application timestamps in UTC', () => {
  const base = read('docker-compose.yml');
  const exercise = read('docker-compose.exercise.yml');

  assert.match(base, /- TZ=UTC/);
  assert.match(exercise, /- TZ=UTC/);
  assert.doesNotMatch(`${base}\n${exercise}`, /- TZ=Asia\/Tokyo/);
});

test('advanced curriculum evidence cannot pass by matching its own checker', () => {
  const checker = read('scripts/world_class_hands_on_check.sh');

  assert.match(checker, /--exclude=['"]world_class_hands_on_check\.sh['"]/);
  assert.match(checker, /DOCUMENTED/);
  assert.match(checker, /VERIFIED/);
  assert.doesNotMatch(checker, /record PASS \"\$topic\" \"\$detail\"/);
});

test('container definitions avoid floating latest and rolling base images', () => {
  const files = [
    ...fs.readdirSync(root).filter((name) => /^docker-compose.*\.yml$/.test(name)),
    'attack/Dockerfile',
    'fail2ban/Dockerfile',
    'alerting/elastalert/Dockerfile',
  ];

  for (const file of files) {
    const contents = read(file);
    assert.doesNotMatch(contents, /(?:FROM|image:)\s+\S+:latest(?:\s|$)/m, file);
    assert.doesNotMatch(contents, /^\s*image:\s+alpine\s*$/m, file);
  }

  assert.match(read('attack/Dockerfile'), /kali-rolling@sha256:[a-f0-9]{64}/);
});

test('the API does not advertise the Express implementation', () => {
  assert.match(read('app/src/main.ts'), /\.disable\(['"]x-powered-by['"]\)/);
});

test('the runtime SIEM gate verifies ingestion, data views, and dashboards', () => {
  const checker = read('scripts/siem_e2e_check.sh');

  assert.match(checker, /soc-lab-\*\/_count/);
  assert.match(checker, /wait_for_event_count/);
  assert.match(checker, /type=dashboard/);
  assert.match(checker, /type=index-pattern/);
  assert.match(checker, /EXPECTED_DASHBOARDS/);
});

test('Suricata telemetry is rotated and cannot grow without retention', () => {
  for (const file of ['suricata/suricata.yaml', 'suricata/suricata-ips.yaml']) {
    const config = read(file);
    assert.match(config, /filename:\s+eve-%Y-%m-%d\.json/);
    assert.match(config, /rotate-interval:\s+day/);
    assert.match(config, /interval:\s+60/);
  }

  assert.match(read('docker-compose.yml'), /\n\s{2}suricata-log-pruner:\n/);
  assert.match(read('elk/filebeat/filebeat.yml'), /tail_files:\s+true/);
});

test('the local quality gate checks generator idempotency on a dirty branch', () => {
  const gate = read('scripts/lab_quality_gate.sh');

  assert.match(gate, /mktemp -d/);
  assert.match(gate, /diff -r/);
  assert.doesNotMatch(gate, /git -C "\$ROOT_DIR" diff --exit-code -- docs\//);
});

test('public product copy matches the remediated API and avoids job-level guarantees', () => {
  const publicCopy = [
    read('README.md'),
    read('app/package.json'),
    read('app/public/readme.txt'),
    read('learning/phases.json'),
    read('scripts/generate_scenario_html.js'),
  ].join('\n');

  assert.doesNotMatch(publicCopy, /intentionally vulnerable/i);
  assert.doesNotMatch(publicCopy, /Vulnerable NestJS application/);
  assert.doesNotMatch(publicCopy, /大手セキュアインフラ相当/);
  assert.doesNotMatch(publicCopy, /世界レベルへ足す課題|世界レベル課題/);
});

test('application runtime and CI use the supported Node.js LTS line', () => {
  const dockerfile = read('app/Dockerfile');
  const workflow = read('.github/workflows/ci.yml');
  const appPackage = JSON.parse(read('app/package.json'));

  assert.match(dockerfile, /FROM node:24-alpine@sha256:[a-f0-9]{64}/);
  assert.doesNotMatch(dockerfile, /FROM node:26-alpine/);
  assert.equal((workflow.match(/node-version:\s*24/g) || []).length, 3);
  assert.doesNotMatch(workflow, /node-version:\s*20/);
  assert.equal(appPackage.engines.node, '>=24 <25');
});
