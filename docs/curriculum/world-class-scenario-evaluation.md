# Scenario Evidence Evaluation

Secure Learn は、実行型ラボ S1-S15 とガイド型設計演習 S16-S33 により、ホワイトハット、SRE、バックエンド、検知、Cloud/IaC、Supply Chain、Release Governance を順番に学ぶ構成です。S16-S33の専用実クラウド、実BGP、実Kubernetesクラスタ、商用EDRは同梱していません。

重要な前提として、このリポジトリは安全なローカル/コンテナ教材です。教材内の点数やチェック結果は、技能、職位、本番適合性を認定しません。本物の業務熟達には、許可された実cloud account、production-like telemetry、組織のreview/incident processで追加訓練が必要です。

| 実行形式 | 範囲 | このリポジトリで確認できること |
|----------|------|--------------------------------|
| 実行型ラボ | S1-S15 | 同梱コンテナ、攻撃/検証スクリプト、ログ、SIEM、回帰テストによる再現 |
| ガイド型設計演習 | S16-S33 | 設計レビュー、静的検証、tabletop、証跡テンプレート作成 |

## 評価軸

| 評価軸 | 確認すること |
|--------|--------------|
| Whitehat | 許可された閉域環境で再現し、攻撃手順、検知、影響、修正確認を証跡化できる |
| SRE | SLI/SLO、可用性、レイテンシ、MTTD/MTTR、暫定対応、恒久対応へ接続できる |
| Backend | 入力検証、認証認可、DB境界、契約、テスト、エラー安全性で再発を止められる |
| Platform | Kubernetes、Cloud、IaC、Network Edgeをguardrailとrollback込みで説明できる |
| Detection | Sigma/YARA/Suricata、MITRE mapping、SIEM query、case managementを運用へ落とせる |
| Release/OSS | SBOM、SAST/DAST/SCA、artifact signing、CVE/CVSS、responsible disclosure、license complianceを扱える |
| Evidence | コマンド、ログ、スクリーンショット、テスト結果、PR本文、postmortem が揃う |

## シナリオ範囲

| Range | 主な領域 | 到達点 |
|-------|----------|--------|
| S1-S7 | 偵察、認証攻撃、SQLi、DoS、OS監査、横断インシデント | 攻撃、検知、修正、運用判断を一つのtimelineで説明する |
| S8-S13 | OSI L2-L7、ARP、ICMP、TCP、session、TLS、DNS | 通信レイヤーごとの観測境界と証跡不足を説明する |
| S14-S15 | SRE incident、capstone | SLO、MTTD/MTTR、postmortem、改善PRへ接続する |
| S16-S21 | Linux internals、eBPF/perf、TCP/LB、TLS/mTLS、Edge、Kubernetes platform | OS/network/platformのguardrailを設計演習として扱う |
| S22-S23 | Cloud IAM/KMS/VPC/Audit、Terraform/OPA/drift | cloud/IaC変更をidentity、network、key、audit、policyでreviewする |
| S24-S27 | Burn-rate、OpenTelemetry、queue/idempotency、migration/API compatibility | observability、分散システム、backend productionをSLOと契約で守る |
| S28-S33 | API business logic、supply chain、detection/EDR、performance、GitOps/OSS governance | secure SDLCとrelease/開示運用の設計レビューへ接続する |

## HTMLハンズオン

各シナリオの実行フロー、抽象説明、具体例、初学者の見方、経験者の深掘り、学習フロー図、環境と証跡の図、OSI / HTTP / 到達前の図、事前準備、安全境界、観測ポイント、よくある失敗、セルフレビュー、ツール活用、合格証跡は [Scenario HTML Guides](../scenario-guides/index.html) で確認できます。

各フェーズの順番、Docker profile、初学者の見方、経験者の深掘り、学習フロー図、Dockerと証跡の図、事前準備、安全境界、観測ポイント、よくある失敗、セルフレビュー、合格証跡は [Learning Phase Guides](../learning-phases/index.html) で確認できます。

再レビューで見つけた説明の不足と修正方針は [Hands-on HTML Self Review](hands-on-self-review-2026-06-29.md) に残しています。

## 教材の整合性判定

この教材内での完成判定は、次のコマンドが通ることです。

```bash
node scripts/generate_scenario_html.js
node scripts/generate_learning_phase_html.js
scripts/scenario_html_check.sh
scripts/learning_phase_check.sh
scripts/world_class_curriculum_check.sh
scripts/world_class_hands_on_check.sh all
```

`scripts/world_class_hands_on_check.sh all` は、各領域を `VERIFIED`（コマンドで確認）、`PRESENT`（成果物が存在）、`DOCUMENTED`（説明を確認）、`WARN`（不足）に分けます。文書中に単語があるだけで実装済み・習熟済みとは判定しません。
