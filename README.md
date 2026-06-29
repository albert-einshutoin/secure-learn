# Secure Learn / SOC-Lab

**Dockerベース統合セキュリティ学習・SOC訓練環境**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/albert-einshutoin/secure-learn/actions/workflows/ci.yml/badge.svg)](https://github.com/albert-einshutoin/secure-learn/actions/workflows/ci.yml)

## 概要

SOC-Labは、セキュリティオペレーションセンター（SOC）の訓練を目的とした、Dockerで完結する実戦型学習環境です。

**攻撃 → 検知 → 対応 → 報告 → 改善** の一連のサイクルを体験できます。

## 特徴

- 🐳 **Docker Compose一発起動** - 複雑な環境構築不要
- 🎯 **33の学習シナリオ** - OSI L2-L7、Linux internals、Cloud/IaC、Supply Chain、EDR、Release Governanceまで
- 📊 **リアルタイム可視化** - Kibanaダッシュボードで攻撃を観察
- 🔔 **自動アラート** - ElastAlert + Slack通知
- 📝 **評価システム** - 初級・中級・上級のレベル別評価

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
```

### フェーズ別 Learning Docker

初学者から大手セキュアインフラ実務レベルまで、段階ごとに必要なDocker profileを起動できます。

```bash
scripts/learning_phase.sh list
scripts/learning_phase.sh start p10
scripts/learning_phase.sh status p10
scripts/learning_phase.sh stop p10
scripts/world_class_hands_on_check.sh all
```

HTMLガイドは `docs/learning-phases/index.html` と `docs/scenario-guides/index.html` から辿れます。各ページに「抽象的に何を学ぶか」「具体例」「Hands-on Flow」「合格証跡」を入れています。

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
| S15 | ホワイトハット/SRE修了課題 | 全体 | 上級 |

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
- [SOCプレイブック](docs/soc-playbook.md)
- [カリキュラム概要](docs/curriculum/overview.md)
- [OSI学習マップ](docs/curriculum/osi-learning-map.md)
- [フェーズ別 Learning Docker](docs/curriculum/secure-infra-learning-docker.md)
- [フェーズ別HTMLガイド](docs/learning-phases/index.html)
- [シナリオ別HTMLハンズオン](docs/scenario-guides/index.html)
- [世界レベル到達度評価](docs/curriculum/world-class-scenario-evaluation.md)
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
- 意図的に脆弱性を含んでいます
- 攻撃スクリプトを第三者の環境に向けて実行しないでください
- `.env`、実際のWebhook URL、秘密鍵、実データをコミットしないでください

## 貢献

Issue、Pull Requestを歓迎します。

## 作者

SOC-Lab Project

