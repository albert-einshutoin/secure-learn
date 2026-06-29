# Branch Plan

このリポジトリは GitHub Flow で運用します。`main` は常に起動可能な状態に保ち、教材や演習は短命の feature branch で作成して Pull Request で統合します。

## 今回の統合ブランチ

| ブランチ | 目的 |
|----------|------|
| `feature/osi-sre-learning-layers` | OSI 補完シナリオ、SRE ゲート、カリキュラム文書をまとめて追加する |

## 必要になった場合の分割単位

空のブランチだけを増やすと OSS 参加者が追いづらくなるため、実装やレビューの責務が分かれた時点で分割します。

| 分割ブランチ案 | 対象 | 分割する判断基準 |
|----------------|------|------------------|
| `feature/osi-l2-l4-network-foundations` | S8-S10, Suricata L2-L4 rules | ネットワーク検知ルールだけを先にレビューしたい |
| `feature/osi-l5-l7-protocol-security` | S11-S13, session/TLS/DNS labs | プロトコル教材と攻撃スクリプトを分離したい |
| `feature/sre-incident-response-capstone` | S14-S15, SLO, incident report | SRE評価と最終課題を別PRにしたい |
| `fix/lab-stability-*` | Compose, Dockerfile, CI | 教材追加とは独立した安定稼働修正が必要になった |

## PR 完了条件

- `docker compose config -q` が通る
- `npm ci && npm run build` が通る
- `npm audit --omit=dev --audit-level=high` が通る
- `bash -n` で演習スクリプトの構文が通る
- Suricata ルールの `-T` が通る
- README、PRD、評価チェックリストが新シナリオと一致している

