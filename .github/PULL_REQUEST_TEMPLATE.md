## Why

Explain the user or maintainer problem, its impact, and why the change belongs in Secure Learn.

## Before / After

- Before:
- After:

## Implementation decisions

Describe the architecture, security boundary, and non-obvious tradeoffs. Call out why the chosen approach is appropriate for a local OSS training lab.

## Verification

- [ ] Test was added or updated before the implementation (TDD)
- [ ] `npm --prefix app run check`
- [ ] `npm --prefix app test`
- [ ] `node --test test/product-readiness.test.js`
- [ ] Relevant Compose and runtime flows were verified
- [ ] Generated guides were regenerated and checked when applicable
- [ ] `npm --prefix app audit --omit=dev --audit-level=high`

## Lab contract evidence

ラボを変更しないPRは各欄を `N/A` とし、理由を記載してください。

- [ ] 対象ラボID (affected lab IDs):
- [ ] プラットフォーム (platform: Docker Desktop / Linux VM / N/A):
- [ ] 成熟度の変更 (maturity transition, before → after):
- [ ] manifest / schema / standards の変更と互換性を確認した
- [ ] 攻撃対象境界 (attack target boundary) がラボ所有の対象だけに限定される
- [ ] 証跡ステージ (evidence stages) の成否と未実行項目を記録した
- [ ] クリーンアップ証跡 (cleanup evidence) を添付またはN/A理由を記載した
- [ ] 生成カバレッジ (generated coverage) を更新・検証した
- [ ] ドキュメント生成物 (generated outputs) を更新・検証した

## Safety and OSS quality

- [ ] Host ports remain restricted to localhost
- [ ] No real credentials, webhooks, packet captures, logs, or local environment files are included
- [ ] Attack behavior remains limited to systems and networks controlled by the learner
- [ ] Documentation explains any changed behavior and its limitations
