# Secure Learn / SOC-Lab

**Dockerベース統合セキュリティ学習・SOC訓練環境**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/albert-einshutoin/secure-learn/actions/workflows/ci.yml/badge.svg)](https://github.com/albert-einshutoin/secure-learn/actions/workflows/ci.yml)

## 概要

SOC-Labは、セキュリティオペレーションセンター（SOC）の訓練を目的とした、ローカル専用の学習環境です。S1-S4/S7-S13は同梱Docker環境、S5-S6は使い捨てLinux VM、S14-S15は複数の証跡を統合する運用ワークフロー、S16-S33は設計レビューとして提供します。

**攻撃 → 検知 → 対応 → 報告 → 改善** の一連のサイクルを体験できます。

## 特徴

- 🐳 **Docker Compose一発起動** - 複雑な環境構築不要
- 🎯 **11のDockerラボ + 2のLinuxホスト補助演習 + 2の運用ワークフロー + 18のガイド型設計演習** - 必要な実行環境を明示して33領域を学習
- 📊 **リアルタイム可視化** - Kibanaダッシュボードで攻撃を観察
- 🔔 **自動アラート** - ElastAlert + Slack通知
- 📝 **証跡テンプレート** - incident、postmortem、remediation PRへ学習結果を整理

## アーキテクチャ

```
[ Kali Linux ]        (攻撃)
      |
      v
[ Suricata ]          (L3-7 IDS/IPS + L2補助観測)
      |
      v
[ NestJS App ]        (攻撃検知 + 修正済みAPI)
      |
      +--> App Log --> Fail2ban (自動BAN)
      |
[ Linux Host ]
      |
      +--> Auditd (OS監査)
      |
[ Filebeat ]
      |
[ Elasticsearch ] <---> [ Kibana ]
        (SIEM / SOC)
```

## クイックスタート

### 前提条件

- Docker & Docker Compose
- 8GB以上のメモリ
- 20GB以上のディスク空き容量

### 起動

```bash
# リポジトリをクローン
git clone https://github.com/albert-einshutoin/secure-learn.git
cd secure-learn

# 環境を起動
docker compose up -d --build

# 起動確認
docker compose ps
```

初回起動時は `siem-setup` が Elasticsearch の保持ポリシー/index template と Kibana の data view/dashboard を自動投入します。`docker compose ps -a siem-setup` が `Exited (0)`、KibanaのDashboard一覧に4件が表示されれば初期化完了です。

### アクセス

| サービス | URL |
|---------|-----|
| Kibana | http://localhost:5601 |
| NestJS App | http://localhost:3000 |
| Elasticsearch | http://localhost:9200 |

### ヘルスチェック

```bash
curl http://localhost:3000/health
curl http://localhost:3000/health/ready
docker compose ps
```

### 攻撃の実行

```bash
# Kaliコンテナに接続
docker exec -it soc-lab-kali /bin/bash

# シナリオを実行
/scripts/s1_portscan.sh
/scripts/s2_bruteforce.sh
/scripts/s3_sqli.sh
/scripts/s4_dos.sh
/scripts/s7_lateral.sh
/scripts/s8_l2_arp_observe.sh
/scripts/s9_l3_icmp_recon.sh
/scripts/s10_l4_tcp_state.sh
/scripts/s11_l5_session_stress.sh
/scripts/s12_l6_tls_boundary.sh
/scripts/s13_l7_dns_observe.sh
```

Kali コンテナはこのリポジトリの `attack/Dockerfile` からビルドされ、`nmap`、`hydra`、`sqlmap`、`curl`、`arping`、`traceroute`、`tcpdump`、`openssl`、`jq` を含みます。

### SREスモークチェック

```bash
scripts/sre_smoke.sh
```

### バックエンド・ハンズオンテスト

```bash
# 軽量ユニットテスト
npm --prefix app test

# Docker起動後のAPI/セキュリティ観測
scripts/backend_hands_on_tests.sh

# p95 latency/SLOの負荷ハンズオン
scripts/load_hands_on_tests.sh

# DB停止/復旧を含むincident drill
RUN_CHAOS=1 scripts/incident_drill.sh

# ローカル総合ゲート
scripts/lab_quality_gate.sh

# 起動済み環境を必須にしてruntime検証まで実行
REQUIRE_RUNTIME=1 scripts/lab_quality_gate.sh

# 空Volumeから起動、S3検知、SIEM投入まで検証（専用環境を自動削除）
scripts/fresh_stack_e2e.sh
```

### フェーズ別 Learning Docker

初学者から発展領域の設計演習まで、段階ごとに必要なDocker profileを起動できます。教材の完了は本番技能や職務レベルの認定ではありません。

```bash
scripts/learning_phase.sh list
scripts/learning_phase.sh start p10
scripts/learning_phase.sh status p10
scripts/learning_phase.sh stop p10
scripts/world_class_hands_on_check.sh all
```

HTMLガイドは `docs/learning-phases/index.html` と `docs/scenario-guides/index.html` から辿れます。各ページに「抽象的に何を学ぶか」「具体例」「Hands-on Flow」「合格証跡」を入れています。

## 学習ドキュメントの使い方

このリポジトリは、READMEだけを読む教材ではなく、HTMLガイド、カリキュラムMarkdown、runbook、テンプレートを行き来しながら学ぶ構成です。迷ったら、次の順番で進めてください。

| 順番 | 使うドキュメント | 役割 | 学び方 |
|------|------------------|------|--------|
| 1 | [README](README.md) | 全体像、起動方法、主要ドキュメントへの入口 | まず環境を起動し、どの学習入口を使うか決める |
| 2 | [Learning Phase Guides](docs/learning-phases/index.html) | P0-P19を順番に進めるメイン教材 | 初学者はP0から、経験者は弱い領域のphaseから始める |
| 3 | [Scenario HTML Guides](docs/scenario-guides/index.html) | Docker実行型、Linuxホスト補助型、運用ワークフロー型、ガイド型を区別したS1-S33 | 各ページの`実行形式`を確認し、再現または設計レビューの証跡を作る |
| 4 | [Scenario Evidence Evaluation](docs/curriculum/world-class-scenario-evaluation.md) | Whitehat、SRE、Backend、Platform、Detectionの自己評価 | 教材内の証跡と、本番環境で追加検証すべき項目を分ける |
| 5 | [Competency Matrix](docs/curriculum/competency-matrix.md) | スキル棚卸し表 | 自分の不足領域を見つけ、次に読むphaseやscenarioを選ぶ |
| 6 | [Templates](docs/templates/) | incident、postmortem、remediation PR、評価チェックリスト | ハンズオン結果を第三者がレビューできる成果物に変換する |

### HTMLガイドの役割

| HTML | 何を見るか | 使うタイミング |
|------|------------|----------------|
| [docs/learning-phases/index.html](docs/learning-phases/index.html) | `Learning Docker全体像`、P0-P19の順番、Docker profile、合格証跡 | 学習計画を立てるとき、または段階的に進めるとき |
| `docs/learning-phases/p*.html` | `学習フロー図`、`Dockerと証跡の図`、到達目標、観測ポイント | 各phaseを実行する直前、実行中、セルフレビュー時 |
| [docs/scenario-guides/index.html](docs/scenario-guides/index.html) | `全体学習図`、`役割と証跡の図`、`通信レイヤー共通図`、S1-S33一覧 | どのシナリオを選ぶか決めるとき |
| `docs/scenario-guides/s*.html` | `学習フロー図`、`環境と証跡の図`、`OSI / HTTP / 到達前の図`、Hands-on Flow | 具体的な攻撃、障害、検知、修正、運用判断を練習するとき |

`learning-phases` は「何をどの順番で学ぶか」を示す道筋です。`scenario-guides` は「その概念を手元でどう再現し、何を証跡にするか」を示す実践手順です。

### Markdownドキュメントの役割

| ドキュメント | 役割 | 使い方 |
|--------------|------|--------|
| [Setup Guide](docs/setup.md) | 環境構築と初回起動 | Docker、Kibana、Appの起動で詰まったら読む |
| [Curriculum Overview](docs/curriculum/overview.md) | カリキュラム全体の考え方 | READMEより少し詳しく全体像を把握する |
| [OSI Learning Map](docs/curriculum/osi-learning-map.md) | OSI L2-L7の対応表 | 通信のどの層を学んでいるか確認する |
| [Secure Infrastructure Learning Docker](docs/curriculum/secure-infra-learning-docker.md) | P0-P19とDocker profileの設計 | `scripts/learning_phase.sh`で何を起動するか確認する |
| [Professional Readiness Roadmap](docs/curriculum/professional-readiness-roadmap.md) | 業務レベル到達までの道筋 | 面接、配属初期、実務訓練で説明できる状態を確認する |
| [Backend Test Hands-on](docs/curriculum/backend-engineer-test-hands-on.md) | Backend視点のテスト設計 | SQLi、path traversal、OpenAPI、DB integrationを練習する |
| [OWASP API Security Track](docs/curriculum/owasp-api-security-track.md) | API security集中トラック | BOLA、SSRF、unsafe upload、RCE、business logic abuseを深掘りする |
| [SRE Production Track](docs/curriculum/sre-production-track.md) | SRE集中トラック | SLI/SLO、incident、capacity、rollback、observabilityを深掘りする |
| [Supply Chain Security Track](docs/curriculum/supply-chain-security-track.md) | Supply chain/release集中トラック | SBOM、SAST/DAST/SCA、artifact signing、release gateを学ぶ |
| [SOC Playbook](docs/soc-playbook.md) | SOC運用手順 | 検知後のtriage、記録、対応判断を練習する |
| [Incident Drill Runbook](docs/runbooks/incident-drill.md) | 障害注入と対応訓練 | SRE incidentやcapstoneで使う |
| [Kubernetes Operations Runbook](docs/runbooks/kubernetes-operations.md) | Kubernetes運用観点 | Platform/Kubernetes系phaseやscenarioで使う |
| [OpenAPI Contract](docs/api/openapi.yaml) | API契約 | Backendテスト、contract review、破壊的変更チェックに使う |

### おすすめの勉強手順

1. `docker compose up -d --build` と `docker compose ps` で環境を起動する。
2. [Learning Phase Guides](docs/learning-phases/index.html) を開き、P0から順に読む。経験者は [Competency Matrix](docs/curriculum/competency-matrix.md) で不足領域を選んでよい。
3. 各phaseのHTMLで、`抽象的に何を学ぶか`、`具体例`、`学習フロー図`、`Dockerと証跡の図` を読む。
4. `scripts/learning_phase.sh start <phase>` で必要なDocker profileを起動し、phase内のHands-on Flowを実行する。
5. 対応する [Scenario HTML Guides](docs/scenario-guides/index.html) のS1-S33を開き、`OSI / HTTP / 到達前の図` で通信やアプリ境界のどこを扱うか確認する。
6. S1-S4/S7-S13はDockerで観測し、S5-S6は使い捨てLinux VMでAuditd証跡を作り、S14-S15は複数の観測結果を統合する。S16-S33は設計レビュー、静的検証、tabletopの証跡を作る。
7. `合格証跡` を [Incident Report](docs/templates/incident-report.md)、[Postmortem](docs/templates/postmortem.md)、[Vulnerability Remediation PR](docs/templates/vulnerability-remediation-pr.md)、[Backend Test Report](docs/templates/backend-test-report.md) のいずれかにまとめる。
8. `scripts/lab_quality_gate.sh` で実装を検証し、`scripts/world_class_hands_on_check.sh all` で実行確認済み・存在確認・文書化・不足を区別したレポートを作る。
9. [Scenario Evidence Evaluation](docs/curriculum/world-class-scenario-evaluation.md) と [Professional Readiness Roadmap](docs/curriculum/professional-readiness-roadmap.md) で、説明できない領域を次の学習対象にする。

### 目的別の入口

| 目的 | 最初に読む | 次にやる |
|------|------------|----------|
| 完全初学者として始める | [Learning Phase Guides](docs/learning-phases/index.html) | P0-P4、S1-S4を順に実行する |
| OSI/通信を理解する | [OSI Learning Map](docs/curriculum/osi-learning-map.md) | S8-S13と各シナリオの`OSI / HTTP / 到達前の図`を見る |
| Backend Engineerとして鍛える | [Backend Test Hands-on](docs/curriculum/backend-engineer-test-hands-on.md) | P2、P3、S3、S27、S28、OpenAPI contract testを実行する |
| SREとして鍛える | [SRE Production Track](docs/curriculum/sre-production-track.md) | P5、P15、S14、S24、S25、incident drillを実行する |
| Whitehat/SOCとして鍛える | [SOC Playbook](docs/soc-playbook.md) | S1-S7、S28-S31を実行し、検知と報告を作る |
| Platform/Cloud/IaCを学ぶ | [Secure Infrastructure Learning Docker](docs/curriculum/secure-infra-learning-docker.md) | P10-P14、S16-S23を実行する |
| OSS公開・運用観点を学ぶ | [Supply Chain Security Track](docs/curriculum/supply-chain-security-track.md) | P18-P19、S29、S33、SECURITY/CONTRIBUTINGを確認する |

## 学習シナリオ

| No | シナリオ | 主レイヤー | 難易度 |
|----|---------|----------|--------|
| S1 | ポートスキャン | L3/L4 | 初級 |
| S2 | APIブルートフォース | L7 | 初級 |
| S3 | SQLインジェクション | L7 | 中級 |
| S4 | DoS攻撃 | L7 | 初級 |
| S5 | 重要ファイル改変 | OS | 中級 |
| S6 | 権限昇格 | OS | 中級 |
| S7 | 横断インシデント | 全体 | 上級 |
| S8 | ARP観測 | L2 | 初級 |
| S9 | ICMP到達性・偵察 | L3 | 初級 |
| S10 | TCP状態・フラグ異常 | L4 | 中級 |
| S11 | セッション圧迫 | L5 | 中級 |
| S12 | TLS可視性境界 | L6 | 中級 |
| S13 | DNS観測 | L7 | 初級 |
| S14 | SREインシデント対応 | 横断/SRE | 上級 |
| S15 | 統合キャップストーン | 全体 | 上級 |

## ディレクトリ構造

```
soc-lab/
├── docker-compose.yml      # メイン構成
├── app/                    # NestJSアプリ
├── suricata/              # IDS設定・ルール
├── fail2ban/              # BAN設定
├── auditd/                # 監査ルール
├── elk/                   # ELK Stack設定
├── attack/                # 攻撃スクリプト
├── k8s/                   # Kubernetes manifests
├── scenarios/             # シナリオ手順書
├── scripts/               # 起動/停止/SRE検証スクリプト
└── docs/                  # ドキュメント・カリキュラム
```

## Phase別機能

### Phase 1（基本）
- IDS（検知のみ）
- Fail2ban自動BAN
- SIEM可視化

### Phase 2（高度）
- IPS（自動遮断）
- Slack通知
- OS監査

```bash
# IPSモード
docker compose -f docker-compose.yml -f docker-compose.ips.yml up -d --build

# Slack通知を含むアラートモード
cp .env.example .env
# .env の SLACK_WEBHOOK_URL を設定
docker compose -f docker-compose.yml -f docker-compose.alerting.yml up -d --build
```

### Phase 3（演習）
- Red vs Blue 分離環境
- KPIダッシュボード
- 自動レポート生成

## 使用技術

- **攻撃**: Kali Linux, nmap, hydra, sqlmap
- **検知**: Suricata, Fail2ban, Auditd
- **SIEM**: Elasticsearch, Kibana, Filebeat
- **通知**: ElastAlert, Slack
- **アプリ**: NestJS, PostgreSQL

## ドキュメント

- [セットアップガイド](docs/setup.md)
- [変更履歴](CHANGELOG.md)
- [リリースポリシー](docs/release-policy.md)
- [SOCプレイブック](docs/soc-playbook.md)
- [カリキュラム概要](docs/curriculum/overview.md)
- [OSI学習マップ](docs/curriculum/osi-learning-map.md)
- [フェーズ別 Learning Docker](docs/curriculum/secure-infra-learning-docker.md)
- [フェーズ別HTMLガイド](docs/learning-phases/index.html)
- [シナリオ別HTMLハンズオン](docs/scenario-guides/index.html)
- [シナリオ証跡の自己評価](docs/curriculum/world-class-scenario-evaluation.md)
- [スキル評価マトリクス](docs/curriculum/competency-matrix.md)
- [業務レベル到達ロードマップ](docs/curriculum/professional-readiness-roadmap.md)
- [バックエンドテスト・ハンズオン](docs/curriculum/backend-engineer-test-hands-on.md)
- [OWASP API Security Track](docs/curriculum/owasp-api-security-track.md)
- [SRE Production Track](docs/curriculum/sre-production-track.md)
- [Supply Chain Security Track](docs/curriculum/supply-chain-security-track.md)
- [Hands-on HTML Self Review](docs/curriculum/hands-on-self-review-2026-06-29.md)
- [ブランチ分割方針](docs/curriculum/branch-plan.md)
- [インシデントレポートテンプレート](docs/templates/incident-report.md)
- [評価チェックリスト](docs/templates/evaluation-checklist.md)

## ライセンス

MIT License

## 注意事項

⚠️ **このプロジェクトは学習目的専用です**

- 本番環境では絶対に使用しないでください
- 閉域ネットワークでのみ使用してください
- APIは修正済みの防御契約を実装しています。攻撃スクリプトは拒否・検知・運用判断を学ぶための安全な試行です
- 攻撃スクリプトを第三者の環境に向けて実行しないでください
- `.env`、実際のWebhook URL、秘密鍵、実データをコミットしないでください

## 貢献

Issue、Pull Requestを歓迎します。

## 作者

SOC-Lab Project
