#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const phaseFile = path.join(root, 'learning', 'phases.json');
const outDir = path.join(root, 'docs', 'learning-phases');
const phases = JSON.parse(fs.readFileSync(phaseFile, 'utf8'));

// Phase HTML is generated from the same source used by the Docker phase CLI so
// beginner-to-lead curriculum changes cannot drift from runnable profiles.
function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function list(items) {
  return `<ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`;
}

function commandBlock(commands) {
  return `<pre><code>${escapeHtml(commands.join('\n'))}</code></pre>`;
}

function phaseConcept(phase) {
  return phase.concept || `${phase.title}では、個別のコマンド暗記ではなく、${phase.objectives[0]}ための判断軸を学びます。`;
}

function phaseExamples(phase) {
  return phase.examples || phase.hands_on.map((item) => `具体例: ${item}`);
}

function phasePrerequisites(phase) {
  if (phase.id === 'P0') {
    return phase.prerequisites || [
      'README、SECURITY、CONTRIBUTINGを読み、許可範囲を確認する。',
      `scripts/learning_phase.sh config ${phase.id.toLowerCase()} で起動対象profileを確認する。`,
      'Docker DesktopまたはDocker Engineが起動し、docker compose config -q が通る。',
    ];
  }

  return phase.prerequisites || [
    '前フェーズの合格証跡を確認し、未完了のまま次へ進まない。',
    `scripts/learning_phase.sh config ${phase.id.toLowerCase()} で起動対象profileを確認する。`,
    'Docker DesktopまたはDocker Engineが起動し、docker compose config -q が通る。',
  ];
}

function phaseSafety(phase) {
  const context = `${phase.title} ${phase.skills.join(' ')}`;
  const safety = [
    '許可されたローカルDockerラボだけを対象にする。',
    '外部IP、第三者service、実本番accountにscan、payload、負荷を向けない。',
  ];

  if (/cloud|AWS|GCP|Azure|IAM|KMS|BGP|CDN|Terraform|Org policy/i.test(context)) {
    safety.push('実cloud、BGP、CDN、組織policyの変更は行わず、設計レビューとサンプル証跡で練習する。');
  }
  if (/load|burn-rate|performance|backpressure|capacity|SLO/i.test(context)) {
    safety.push('負荷試験は小さい値から始め、SLO悪化を確認したら停止して復旧を記録する。');
  }
  if (/RCE|SSRF|BOLA|unsafe upload|privilege|auditd|EDR/i.test(context)) {
    safety.push('攻撃再現は教材内の明示されたendpoint、file、containerに限定する。');
  }

  return phase.safety || safety;
}

function phaseObservationPoints(phase) {
  return phase.observations || [
    '開始時刻、対象profile、実行コマンド、終了時刻を記録する。',
    'service health、ログ、メトリクス、テスト結果のどれで進捗を判断するかを決める。',
    `次フェーズ判定「${phase.next_gate}」を満たした根拠を残す。`,
  ];
}

function phaseCommonMistakes(phase) {
  return phase.commonMistakes || [
    'profileを理解しないまま起動し、どのserviceを検証しているか説明できない。',
    'コマンドが通った事実だけを残し、何を守ったか、何を観測したかを書かない。',
    '設計だけで完了扱いにし、実行可能な証跡または安全上の制約を明記しない。',
  ];
}

function phaseSelfReview(phase) {
  return phase.selfReview || [
    `${phase.title}の到達目標を、Whitehat/SRE/Backendのどの観点で達成したか説明できるか。`,
    '失敗した場合に最初に見るログ、テスト、メトリクスを言えるか。',
    '本番相当へ進める時の追加権限、承認、rollback、ownerを定義できるか。',
  ];
}

function nav(currentId) {
  return phases
    .map((phase) => {
      const current = phase.id === currentId ? ' aria-current="page"' : '';
      return `<a${current} href="${phase.slug}.html">${phase.id}</a>`;
    })
    .join('');
}

function layout(title, body, currentId = '') {
  return `<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} - Secure Learn</title>
  <link rel="stylesheet" href="../scenario-guides/assets/scenario.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="index.html">Secure Learn Learning Phases</a>
    <nav aria-label="Learning phase navigation">${nav(currentId)}</nav>
  </header>
  <main>
${body}
  </main>
</body>
</html>
`;
}

function phasePage(phase) {
  return layout(
    `${phase.id} ${phase.title}`,
    `    <section class="scenario-head">
      <p class="eyebrow">${escapeHtml(phase.id)} / ${escapeHtml(phase.level)} / ${escapeHtml(phase.profile)}</p>
      <h1>${escapeHtml(phase.title)}</h1>
      <p class="lead">${escapeHtml(phase.next_gate)}</p>
      <div class="meta-row">
        ${phase.roles.map((role) => `<span class="pill">${escapeHtml(role)}</span>`).join('')}
      </div>
    </section>

    <section class="grid two">
      <article>
        <h2>抽象的に何を学ぶか</h2>
        <p>${escapeHtml(phaseConcept(phase))}</p>
      </article>
      <article>
        <h2>具体例</h2>
        ${list(phaseExamples(phase))}
      </article>
    </section>

    <section class="grid two">
      <article>
        <h2>到達目標</h2>
        ${list(phase.objectives)}
      </article>
      <article>
        <h2>カバー領域</h2>
        ${list(phase.skills)}
      </article>
    </section>

    <section class="grid two">
      <article>
        <h2>事前準備</h2>
        ${list(phasePrerequisites(phase))}
      </article>
      <article>
        <h2>安全境界</h2>
        ${list(phaseSafety(phase))}
      </article>
    </section>

    <section>
      <h2>Hands-on Flow</h2>
      ${list(phase.hands_on)}
    </section>

    <section class="grid two">
      <article>
        <h2>Docker実行</h2>
        ${commandBlock([
          `scripts/learning_phase.sh config ${phase.id.toLowerCase()}`,
          `scripts/learning_phase.sh start ${phase.id.toLowerCase()}`,
          `scripts/learning_phase.sh status ${phase.id.toLowerCase()}`,
        ])}
      </article>
      <article>
        <h2>実行コマンド</h2>
        ${commandBlock(phase.commands)}
      </article>
    </section>

    <section class="grid three">
      <article>
        <h2>観測ポイント</h2>
        ${list(phaseObservationPoints(phase))}
      </article>
      <article>
        <h2>よくある失敗</h2>
        ${list(phaseCommonMistakes(phase))}
      </article>
      <article>
        <h2>セルフレビュー</h2>
        ${list(phaseSelfReview(phase))}
      </article>
    </section>

    <section class="grid two">
      <article>
        <h2>合格証跡</h2>
        ${list(phase.evidence)}
      </article>
      <article>
        <h2>次フェーズ判定</h2>
        <p>${escapeHtml(phase.next_gate)}</p>
      </article>
    </section>
`,
    phase.id,
  );
}

function indexPage() {
  const rows = phases
    .map(
      (phase) => `<tr>
        <td><a href="${phase.slug}.html">${phase.id}</a></td>
        <td>${escapeHtml(phase.level)}</td>
        <td>${escapeHtml(phase.title)}</td>
        <td>${escapeHtml(phase.profile)}</td>
        <td>${phase.roles.map(escapeHtml).join(', ')}</td>
        <td>${phase.skills.map(escapeHtml).join(', ')}</td>
      </tr>`,
    )
    .join('');

  return layout(
    'Learning Phase Index',
    `    <section class="scenario-head">
      <p class="eyebrow">Junior to secure infrastructure lead</p>
      <h1>フェーズ別 Learning Docker</h1>
      <p class="lead">初学者がDocker、Linux、Backend、Whitehat、SRE、Kubernetes、Observability、分散システム、Supply Chainまで段階的に進むための実行可能な学習導線です。</p>
    </section>

    <section class="grid three">
      <article><h2>Phases</h2><p class="big">${phases.length}</p><p>Junior 0 から Principal まで。</p></article>
      <article><h2>Docker</h2><p class="big">Profiles</p><p>baseからcloud、IaC、Kubernetes、observability、distributed、capstoneまで。</p></article>
      <article><h2>Gate</h2><p class="big">Evidence</p><p>各フェーズで合格証跡を要求。</p></article>
    </section>

    <section>
      <h2>起動方法</h2>
      ${commandBlock([
        'scripts/learning_phase.sh list',
        'scripts/learning_phase.sh start p10',
        'scripts/learning_phase.sh status p10',
        'scripts/world_class_hands_on_check.sh all',
        'scripts/learning_phase.sh stop p10',
      ])}
    </section>

    <section>
      <h2>フェーズ一覧</h2>
      <table>
        <thead><tr><th>Phase</th><th>Level</th><th>Title</th><th>Docker profile</th><th>Roles</th><th>Skills</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </section>

    <section>
      <h2>主要URL</h2>
      <table>
        <thead><tr><th>Service</th><th>URL</th><th>Phase</th></tr></thead>
        <tbody>
          <tr><td>App</td><td>http://localhost:3000</td><td>P1+</td></tr>
          <tr><td>Kibana</td><td>http://localhost:5601</td><td>P4+</td></tr>
          <tr><td>Prometheus</td><td>http://localhost:9090</td><td>P5/P15/P19</td></tr>
          <tr><td>Grafana</td><td>http://localhost:3001</td><td>P5/P15/P19</td></tr>
          <tr><td>Edge proxy</td><td>http://localhost:8080</td><td>P6/P11/P12/P19</td></tr>
          <tr><td>Redis</td><td>127.0.0.1:6380</td><td>P8/P16/P19</td></tr>
        </tbody>
      </table>
    </section>
`,
  );
}

function main() {
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'index.html'), indexPage());
  for (const phase of phases) {
    fs.writeFileSync(path.join(outDir, `${phase.slug}.html`), phasePage(phase));
  }
  console.log(`Generated ${phases.length + 1} HTML files in ${path.relative(root, outDir)}`);
}

main();
