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

test('curriculum foundation gate is enforced locally and in CI before generated outputs', () => {
  const gate = read('scripts/lab_quality_gate.sh');
  const workflow = read('.github/workflows/ci.yml');
  const rootTests = gate.indexOf('node --test test/*.test.js');
  const firstDockerCommand = gate.search(/^\s*docker\b/m);
  const curriculumCheck = gate.indexOf('scripts/curriculum_check.sh');
  const firstHtmlGeneration = Math.min(
    ...[
      gate.indexOf('scripts/generate_learning_phase_html.js'),
      gate.indexOf('scripts/generate_scenario_html.js'),
    ].filter((index) => index >= 0),
  );

  assert.ok(rootTests >= 0, 'the local gate must run every root contract test');
  assert.ok(rootTests < firstDockerCommand, 'root contract tests must run before Docker builds or validation');
  assert.ok(curriculumCheck >= 0, 'the local gate must run the canonical curriculum check');
  assert.ok(curriculumCheck < firstHtmlGeneration, 'curriculum validation must precede generated HTML checks');
  assert.deepEqual(
    [...gate.matchAll(/\[(\d+)\/(\d+)\]/g)].map((match) => `${match[1]}/${match[2]}`),
    Array.from({ length: 12 }, (_, index) => `${index + 1}/12`),
  );

  const composeJob = workflow.match(/\n  compose:\n[\s\S]*?(?=\n  docs:)/)?.[0] || '';
  const ciRootTests = composeJob.indexOf('node --test test/*.test.js');
  const ciCurriculumCheck = composeJob.indexOf('scripts/curriculum_check.sh');
  assert.match(composeJob, /name:\s*Product and curriculum contract tests/);
  assert.ok(ciRootTests >= 0, 'CI must retain non-curriculum root product and safety tests');
  assert.ok(ciRootTests < ciCurriculumCheck, 'CI must finish root contracts before the canonical curriculum check');
  assert.doesNotMatch(composeJob, /Product readiness regression tests/);

  const docsJob = workflow.match(/\n  docs:\n[\s\S]*?(?=\n  suricata:)/)?.[0] || '';
  const generateCoverage = docsJob.indexOf('node scripts/generate_curriculum_coverage.js');
  const diffCoverage = docsJob.indexOf('git diff --exit-code -- docs/curriculum/coverage.md');
  const worldClass = docsJob.indexOf('scripts/world_class_curriculum_check.sh');
  assert.ok(generateCoverage >= 0 && generateCoverage < diffCoverage);
  assert.ok(diffCoverage < worldClass);
});

test('curriculum foundation gate exposes honest learner and contribution contracts', () => {
  const readme = read('README.md');
  const template = read('.github/PULL_REQUEST_TEMPLATE.md');

  assert.match(readme, /\[.*(?:Coverage|カバレッジ).*\]\(docs\/curriculum\/coverage\.md\)/i);
  for (const command of [
    'scripts/learn list',
    'scripts/learn show s3',
    'scripts/learn validate',
    'scripts/learn doctor s3',
  ]) {
    assert.match(readme, new RegExp(command.replaceAll('/', '\\/')));
  }
  for (const maturity of ['documented', 'runnable', 'verified', 'external']) {
    assert.match(readme, new RegExp('\\| `' + maturity + '` \\|'));
  }
  for (const requirement of [
    /environment|環境/i,
    /safety|安全/i,
    /startup|起動/i,
    /attack|攻撃/i,
    /telemetry|観測/i,
    /pipeline/i,
    /control|remediation|修正/i,
    /regression|回帰/i,
    /assessment|評価/i,
    /evidence integrity|証跡の完全性/i,
    /cleanup|クリーンアップ/i,
  ]) {
    assert.match(readme, requirement);
  }
  assert.match(readme, /Docker Desktop[\s\S]*scripts\/learn doctor/i);
  assert.match(readme, /Linux VM[\s\S]*scripts\/learn doctor/i);
  assert.match(readme, /S5[^\n]*S6[^\n]*(?:operator-attested|運用者)/i);
  assert.match(readme, /not cryptographic|暗号学的[^\n]*(?:証明|attestation)/i);
  assert.match(readme, /verified[^\n]*(?:0件|0 labs|存在し)/i);
  assert.doesNotMatch(readme, /S1-S15[^\n]*(?:verified|検証済み)/i);

  for (const label of [
    /affected lab IDs|対象ラボID/i,
    /platform|プラットフォーム/i,
    /maturity transition|成熟度の変更/i,
    /manifest.*schema.*standards|マニフェスト.*スキーマ.*標準/i,
    /attack target boundary|攻撃対象境界/i,
    /evidence stages|証跡ステージ/i,
    /cleanup evidence|クリーンアップ証跡/i,
    /generated coverage|生成カバレッジ/i,
    /generated outputs|生成物/i,
  ]) {
    assert.match(template, label);
  }
  assert.match(template, /`node --test test\/\*\.test\.js`/);
  assert.match(template, /`scripts\/curriculum_check\.sh`/);
  assert.doesNotMatch(template, /`node --test test\/product-readiness\.test\.js`/);
  assert.match(template, /N\/A[^\n]*(?:reason|理由)/i);
  assert.ok((template.match(/- \[ \]/g) || []).length >= 12);
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
  const dependabot = read('.github/dependabot.yml');
  const appPackage = JSON.parse(read('app/package.json'));

  assert.match(dockerfile, /FROM node:24-alpine@sha256:[a-f0-9]{64}/);
  assert.doesNotMatch(dockerfile, /FROM node:26-alpine/);
  const configuredNodeVersions = [...workflow.matchAll(/node-version:\s*(\d+)/g)]
    .map((match) => match[1]);
  assert.ok(configuredNodeVersions.length >= 4);
  assert.deepEqual([...new Set(configuredNodeVersions)], ['24']);
  assert.equal(appPackage.engines.node, '>=24 <25');
  assert.match(appPackage.devDependencies['@types/node'], /^\^24\./);
  assert.match(dependabot, /package-ecosystem: npm[\s\S]*?dependency-name: "@types\/node"[\s\S]*?version-update:semver-major/);
  assert.match(dependabot, /package-ecosystem: docker\n\s+directory: \/app[\s\S]*?dependency-name: node[\s\S]*?version-update:semver-major/);
});

test('security telemetry images use maintained releases pinned by digest', () => {
  const composeFiles = ['docker-compose.yml', 'docker-compose.exercise.yml'];
  const elasticImages = [];

  for (const file of composeFiles) {
    const compose = read(file);
    elasticImages.push(
      ...(compose.match(/docker\.elastic\.co\/(?:elasticsearch\/elasticsearch|kibana\/kibana|beats\/filebeat):[^\s]+/g) || []),
    );
    assert.doesNotMatch(compose, /8\.11\.0/, file);
  }

  assert.equal(elasticImages.length, 7);
  for (const image of elasticImages) {
    assert.match(image, /:8\.19\.17@sha256:[a-f0-9]{64}$/, image);
  }

  const suricata = read('suricata/Dockerfile');
  assert.match(
    suricata,
    /^FROM jasonish\/suricata:8\.0\.6@sha256:73728b916f4be9f9b5b84012221ffa6feac1653cf663f8acd65b6c98b8ae797b/m,
  );
  assert.doesNotMatch(suricata, /jasonish\/suricata:7\./);
});

test('Dependabot monitors root Compose images', () => {
  const dependabot = read('.github/dependabot.yml');

  assert.match(dependabot, /package-ecosystem: docker\n\s+directory: \/\n/);
});

test('Red versus Blue exercise has an isolated Compose identity and host surface', () => {
  const exercise = read('docker-compose.exercise.yml');
  const start = read('scripts/start_exercise.sh');
  const stop = read('scripts/stop_exercise.sh');

  assert.match(exercise, /^name:\s*secure-learn-exercise/m);
  assert.match(exercise, /127\.0\.0\.1:3100:3000/);
  assert.match(exercise, /127\.0\.0\.1:9201:9200/);
  assert.match(exercise, /127\.0\.0\.1:5603:5601/);
  assert.doesNotMatch(exercise, /subnet:\s*172\.2[34]\.0\.0\/24/);
  assert.match(start, /--project-name[= ]"?secure-learn-exercise/);
  assert.match(stop, /--project-name[= ]"?secure-learn-exercise/);
});

test('host-assisted scenarios never instruct learners to mutate account-control files', () => {
  const safetySources = [
    'scenarios/S5_file_tamper.md',
    'scenarios/S6_privesc.md',
    'scenarios/S7_lateral.md',
    'attack/scripts/s5_file_tamper.sh',
    'attack/scripts/s6_privesc.sh',
  ];
  const dangerousCommands = /(?:sudo\s+(?:touch|cp|visudo|passwd|pkill)|\bsu\s+-\s+root).*\/(?:etc\/)?(?:passwd|shadow|sudoers)?|sudo\s+(?:touch|cp|visudo|passwd|pkill)\b/;

  for (const file of safetySources) {
    assert.doesNotMatch(read(file), dangerousCommands, file);
  }

  assert.doesNotMatch(read('scenarios/S1_portscan.md'), /172\.19\.0\.20/);
  assert.doesNotMatch(read('scenarios/S7_lateral.md'), /172\.19\.0\.20/);
});

test('curriculum copy distinguishes container labs, host-assisted work, and operator workflows', () => {
  const generator = read('scripts/generate_scenario_html.js');
  const readme = read('README.md');

  assert.match(generator, /host-assisted/);
  assert.match(generator, /operator-workflow/);
  assert.doesNotMatch(generator, /S1-S15を同梱環境で再現できる実行型ラボ/);
  assert.doesNotMatch(readme, /S1-S15は同梱Docker環境で実行でき/);
  assert.doesNotMatch(readme, /意図的に脆弱性を含んでいます/);
});

test('OWASP API 2023 curriculum uses the canonical API6 through API8 semantics', () => {
  const track = read('docs/curriculum/owasp-api-security-track.md');
  const row = (module) => track.split('\n').find((line) => line.startsWith(`| ${module} |`)) || '';

  assert.match(row('API-6'), /Unrestricted Access to Sensitive Business Flows/);
  assert.match(row('API-6'), /inventory|automation/i);
  assert.match(row('API-7'), /Server Side Request Forgery/);
  assert.match(row('API-8'), /Security Misconfiguration/);
  assert.doesNotMatch(row('API-8'), /Injection/i);
  assert.match(track, /Injection[^\n]*supporting secure-coding topic/i);
});

test('generated public benchmark copy describes the OWASP API 2023 categories accurately', () => {
  const generator = read('scripts/generate_scenario_html.js');
  const index = read('docs/scenario-guides/index.html');

  for (const copy of [generator, index]) {
    assert.match(copy, /API6[^\n<]*Sensitive Business Flows/i);
    assert.match(copy, /API7[^\n<]*Server Side Request Forgery/i);
    assert.match(copy, /API8[^\n<]*Security Misconfiguration/i);
    assert.doesNotMatch(copy, /resource consumption、injectionの抜け漏れ確認/);
  }
});

test('MITRE scenario mappings describe only behavior the exercises demonstrate', () => {
  const s5 = read('scenarios/S5_file_tamper.md');
  const s8 = read('scenarios/S8_l2_arp_observe.md');

  assert.match(s5, /Impact - Data Manipulation \(T1565\)/);
  assert.match(s8, /Discovery - Remote System Discovery \(T1018\)/);
  assert.doesNotMatch(s8, /T1046|Network Service Discovery/i);
  assert.match(s8, /service scan[^\n]*(?:行わ|does not)/i);
  assert.match(s8, /ARP[^\n]*(?:neighbor|近隣)[^\n]*(?:観測|observation)/i);
  assert.match(s8, /(?:物理|physical)[^\n]*(?:switch|スイッチ)[^\n]*(?:見え|観測でき)/i);
});

test('S7 is presented as a cross-layer event chain within one trust zone', () => {
  const scenario = read('scenarios/S7_lateral.md');
  const generator = read('scripts/generate_scenario_html.js');
  const script = read('attack/scripts/s7_lateral.sh');

  assert.match(scenario, /^# S7: Cross-Layer Incident/m);
  assert.match(scenario, /one trust zone/i);
  assert.match(scenario, /not (?:an? )?(?:APT|lateral movement)/i);
  assert.doesNotMatch(scenario, /APT模擬|実際のAPT|横移動を再現/i);
  assert.match(generator, /id: 'S7',[\s\S]*?title: 'Cross-Layer Incident'/);
  assert.doesNotMatch(script, /\bAPT\b|Lateral Movement/i);
  assert.match(script, /Cross-Layer Incident/);
  assert.match(script, /Event Chain Report/);
  assert.doesNotMatch(script, /Open ports discovered|Attack Chain Complete|S5 Related|\| Completed \||Valid credentials found|Successful:/i);
  assert.doesNotMatch(script, /(?:echo|printf)[^\n]*(?:password|token|credential|\$pass)|REPORT_FILE[^\n]*(?:password|token|credential|\$pass)/i);
});

test('public evaluation language is self-assessment rather than certification', () => {
  const checklist = read('docs/templates/evaluation-checklist.md');
  const readme = read('README.md');
  const scenario = read('scenarios/S15_capstone.md');
  const generator = read('scripts/generate_scenario_html.js');
  const guide = read('docs/scenario-guides/s15-capstone.html');
  const publicCopy = [readme, scenario, generator, guide].join('\n');

  assert.match(checklist, /教材内セルフ評価レベル/);
  assert.match(checklist, /外部資格|技能や職位/);
  assert.doesNotMatch(checklist, /認定レベル|初級認定|中級認定|上級認定|ホワイトハット\/SRE修了/);
  assert.match(readme, /\| S15 \| 統合キャップストーン \|/);
  assert.match(scenario, /^# S15: 統合キャップストーン/m);
  assert.match(generator, /id: 'S15',[\s\S]{0,120}title: '統合キャップストーン'/);
  assert.match(guide, /S15 統合キャップストーン/);
  assert.doesNotMatch(publicCopy, /ホワイトハット\/SRE\s*修了課題/);
});

test('scenario evaluation reports the honest execution-format split and maturity source', () => {
  const evaluation = read('docs/curriculum/world-class-scenario-evaluation.md');

  assert.match(evaluation, /Docker実行型ラボ\s*\|\s*11/);
  assert.match(evaluation, /Linuxホスト補助演習\s*\|\s*2/);
  assert.match(evaluation, /運用ワークフロー演習\s*\|\s*2/);
  assert.match(evaluation, /ガイド型設計演習\s*\|\s*18/);
  assert.match(evaluation, /\[.*maturity.*coverage.*\]\(coverage\.md\)/i);
  assert.doesNotMatch(evaluation, /実行型ラボ\s*S1-S15|S1-S15[^\n]*(?:executable|runnable|verified|実行型ラボ)/i);
});

test('generated scenario guides retain public URLs while using corrected S7 and S8 semantics', () => {
  const s5 = read('docs/scenario-guides/s5-file-tamper.html');
  const s7 = read('docs/scenario-guides/s7-lateral.html');
  const s8 = read('docs/scenario-guides/s8-arp.html');

  assert.match(s5, /Impact - Data Manipulation \(T1565\)/);
  assert.match(s7, /Cross-Layer Incident/);
  const s7Claims = s7
    .split('\n')
    .filter((line) => !/主張せず|not (?:an? )?(?:APT|lateral movement)|compatibility filename/i.test(line))
    .join('\n');
  assert.doesNotMatch(s7Claims, /APT模擬|実際のAPT|genuine APT|Lateral Movement/i);
  assert.match(s8, /Remote System Discovery \(T1018\)/);
  assert.doesNotMatch(s8, /T1046|Network Service Discovery/i);
  for (const guide of [s5, s7, s8]) {
    assert.match(guide, /Manifest maturity/);
    assert.match(guide, /Maturity coverageと判定根拠/);
  }
});

test('scenario scripts do not report unverified success', () => {
  const attackScripts = fs
    .readdirSync(path.join(root, 'attack/scripts'))
    .filter((name) => name.endsWith('.sh'));

  for (const file of attackScripts) {
    assert.doesNotMatch(read(`attack/scripts/${file}`), /\[✓\]/, file);
  }

  const checker = read('scripts/scenario_e2e_check.sh');
  assert.match(checker, /verify_application_event/);
  assert.match(checker, /verify_suricata_event/);
  assert.match(checker, /verify_elasticsearch_event/);
  assert.match(checker, /exit 1/);
});

test('runtime verification is mandatory in CI and can be required locally', () => {
  const gate = read('scripts/lab_quality_gate.sh');
  const workflow = read('.github/workflows/ci.yml');
  const freshStack = read('scripts/fresh_stack_e2e.sh');

  assert.match(gate, /REQUIRE_RUNTIME/);
  assert.match(gate, /runtime verification is required/i);
  assert.match(workflow, /name:\s*Fresh stack E2E/);
  assert.match(workflow, /scripts\/fresh_stack_e2e\.sh/);
  assert.match(freshStack, /docker compose/);
  assert.match(freshStack, /scenario_e2e_check\.sh/);
  assert.match(freshStack, /down --volumes/);
});

test('fresh-stack CI pins a compatible Docker Engine and verifies its local contract before E2E', () => {
  const workflow = read('.github/workflows/ci.yml');
  const setup = 'docker/setup-docker-action@6d7cfa65f60a9dda7b46e5513fa982536f3c9877';
  const setupIndex = workflow.indexOf(setup);
  const contractIndex = workflow.indexOf('name: Verify local Docker runtime contract', setupIndex);
  const e2eIndex = workflow.indexOf('scripts/fresh_stack_e2e.sh', contractIndex);

  assert.ok(setupIndex >= 0, 'fresh-stack must use the immutable setup-docker-action v5.3.0 commit');
  assert.match(workflow.slice(setupIndex), /with:\n\s+version:\s*v29\.6\.2\n\s+context:\s*secure-learn-ci/);
  assert.doesNotMatch(workflow.slice(setupIndex, e2eIndex), /version:\s*latest|tcp-port:|set-host:\s*true/);
  assert.ok(contractIndex > setupIndex, 'Docker contract gate must run after engine setup');
  assert.ok(e2eIndex > contractIndex, 'Docker contract gate must run before fresh-stack E2E');
  const contract = workflow.slice(contractIndex, e2eIndex);
  assert.match(contract, /EXPECTED_DOCKER_SOCKET:\s*\$\{\{ steps\.setup-docker\.outputs\.sock \}\}/);
  assert.match(contract, /run:\s*scripts\/verify_ci_docker_runtime\.sh/);
  assert.doesNotMatch(contract, /docker context show|docker context inspect|docker version/);
});

test('public setup docs state the Engine, API, and Compose requirements for deterministic IDS interfaces', () => {
  const readme = read('README.md');
  const setup = read('docs/setup.md');
  for (const document of [readme, setup]) {
    assert.match(document, /Docker Engine 28\.1\.0(?:以上|／API 1\.49)/);
    assert.match(document, /API 1\.49/);
    assert.match(document, /Docker Compose 2\.36\.0以上/);
    assert.match(document, /interface_name/);
    assert.doesNotMatch(document, /Docker Engine 20\.10\.0|API 1\.41/);
  }
});

test('release contract includes version, changelog, SBOM, and vulnerability scanning', () => {
  assert.match(read('VERSION').trim(), /^\d+\.\d+\.\d+$/);
  assert.match(read('CHANGELOG.md'), /## \[1\.0\.0\]/);
  const releasePolicy = read('docs/release-policy.md');
  assert.match(releasePolicy, /SBOM/i);
  assert.match(releasePolicy, /release_artifacts\.sh/);
  assert.match(releasePolicy, /Docker socket/i);
  assert.match(releasePolicy, /host-equivalent|Docker daemon/i);
  assert.match(releasePolicy, /release tooling only/i);

  const workflow = read('.github/workflows/release.yml');
  assert.match(workflow, /tags:\s*\n\s+- ['"]v\*['"]/);
  assert.match(workflow, /VERSION/);
  assert.match(workflow, /SBOM/i);
  assert.match(workflow, /Trivy/i);
  assert.match(workflow, /attest/i);
  assert.match(workflow, /fetch-depth:\s*0/);
  assert.match(workflow, /merge-base --is-ancestor/);
  assert.match(workflow, /actions\/setup-node@[a-f0-9]{40}/);
  assert.match(workflow, /node-version:\s*24/);
  assert.match(workflow, /gh release create[\s\S]*--draft/);
  assert.match(workflow, /gh release edit[\s\S]*--draft=false/);
});

test('release policy records the CI Docker archive verification residual risk and follow-up gate', () => {
  const policy = read('docs/release-policy.md');
  const changelog = read('CHANGELOG.md');

  assert.match(policy, /setup-docker-action/);
  assert.match(policy, /CDN[\s\S]*(?:checksum|provenance)/i);
  assert.match(policy, /does not independently verify|独立[^\n]*検証しない/i);
  assert.match(policy, /future[\s\S]*(?:checksum|signature|provenance)|将来[\s\S]*(?:checksum|署名|provenance)/i);
  assert.match(changelog, /Docker CE 29\.6\.2[\s\S]*security/i);
  assert.doesNotMatch(changelog, /fresh-stack CI daemon to Docker CE 28\.5\.2/);
});

test('GitHub Actions dependencies are pinned to immutable commits', () => {
  const workflowFiles = fs
    .readdirSync(path.join(root, '.github/workflows'))
    .filter((name) => name.endsWith('.yml'));

  for (const file of workflowFiles) {
    const uses = [...read(`.github/workflows/${file}`).matchAll(/^\s*uses:\s*([^\s#]+)/gm)];
    for (const match of uses) {
      assert.match(match[1], /@[a-f0-9]{40}$/, `${file}: ${match[1]}`);
    }
  }
});

test('artifact uploads use the Node.js 24-based action generation', () => {
  const workflows = fs
    .readdirSync(path.join(root, '.github/workflows'))
    .filter((name) => name.endsWith('.yml'))
    .map((name) => read(`.github/workflows/${name}`))
    .join('\n');
  const majors = [...workflows.matchAll(/actions\/upload-artifact@[a-f0-9]{40}\s+# v(\d+)/g)]
    .map((match) => Number(match[1]));

  assert.ok(majors.length > 0);
  assert.ok(majors.every((major) => major >= 7), majors.join(','));
});

test('CI performs pinned JavaScript and TypeScript CodeQL analysis', () => {
  const workflow = read('.github/workflows/ci.yml');

  assert.match(workflow, /name:\s*CodeQL analysis/);
  assert.match(workflow, /github\/codeql-action\/init@[a-f0-9]{40}/);
  assert.match(workflow, /github\/codeql-action\/analyze@[a-f0-9]{40}/);
  assert.match(workflow, /languages:\s*javascript-typescript/);
  assert.match(workflow, /security-events:\s*write/);
});

test('example environment only advertises configuration consumed by Compose', () => {
  const example = read('.env.example');
  const compose = `${read('docker-compose.yml')}\n${read('docker-compose.exercise.yml')}\n${read('docker-compose.alerting.yml')}`;
  const variables = [...example.matchAll(/^([A-Z][A-Z0-9_]*)=/gm)].map((match) => match[1]);

  for (const variable of variables) {
    assert.match(compose, new RegExp(`\\$\\{${variable}(?=[:}])`), variable);
  }

  assert.doesNotMatch(example, /APP_NET_SUBNET=172\.19/);
  assert.doesNotMatch(example, /TZ=Asia\/Tokyo/);
});
