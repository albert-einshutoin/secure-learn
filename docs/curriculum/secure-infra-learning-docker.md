# Secure Infrastructure Learning Docker

このトラックは、初学者が `docker compose up` から始めて、Whitehat、SRE、Backend、Detection、Cloud/IaC、Supply Chain、Release Governance まで段階的に進むためのフェーズ制カリキュラムです。

各フェーズのHTMLガイドは [Learning Phase Guides](../learning-phases/index.html) を正とします。HTMLには、抽象的に何を学ぶか、具体例、Hands-on Flow、Docker実行、合格証跡を入れています。

## 実行入口

```bash
scripts/learning_phase.sh list
scripts/learning_phase.sh start p10
scripts/learning_phase.sh status p10
scripts/learning_phase.sh stop p10
```

## フェーズ設計

| Phase | レベル | 主な狙い | Docker profile |
|-------|--------|----------|----------------|
| P0 | Junior 0 | 倫理、安全範囲、GitHub Flow、証跡管理 | base |
| P1 | Junior 1 | Linux、Docker、container network、L2-L4観測 | base |
| P2 | Junior 2 | Backend TDD、API契約、DB integration | base |
| P3 | Operator 1 | OWASP API Security、認証認可、安全な失敗 | base |
| P4 | Operator 2 | Detection engineering、SOC相関、誤検知調整 | base |
| P5 | Independent 1 | Prometheus、Grafana、OpenTelemetry、SLO | phase5-observability |
| P6 | Independent 2 | Kubernetes、IaC、edge proxy、release/rollback | phase6-release |
| P7 | Independent 3 | Endpoint/EDR観点、auditd、process timeline | base |
| P8 | Lead 1 | Redis、queue/cache、性能、容量計画 | phase8-distributed |
| P9 | Lead 2 | Capstone、secure infrastructure portfolio | capstone |
| P10 | Lead 3 | Linux internals、cgroups、namespaces、seccomp、capabilities | phase10-linux-internals |
| P11 | Lead 4 | TCP再送、TLS/mTLS、BGP/Anycast、QUIC、CDN edge | phase11-network-edge |
| P12 | Lead 5 | Helm、Kustomize、Operator/CRD、Admission、RBAC、NetworkPolicy | phase12-kubernetes-platform |
| P13 | Lead 6 | Cloud IAM、KMS、VPC、Audit Logs、Org policy、secret rotation | phase13-cloud-security |
| P14 | Lead 7 | Terraform、state、drift、OPA/Conftest、plan review | phase14-iac-policy |
| P15 | Lead 8 | burn-rate、RED/USE、trace/log correlation、alert fatigue | phase15-advanced-observability |
| P16 | Lead 9 | Kafka/PubSub/Temporal、retry、idempotency、backpressure | phase16-distributed-reliability |
| P17 | Lead 10 | migration/rollback、transaction、race condition、API compatibility | base |
| P18 | Lead 11 | SSRF/BOLA/upload/RCE、SBOM、SAST/DAST/SCA、signing、canary | phase18-security-supply-chain |
| P19 | Principal | Sigma/YARA、EDR telemetry、CVE/CVSS、responsible disclosure、OSS governance | capstone |

## Docker profiles

| Profile | 追加サービス | 学習すること |
|---------|--------------|--------------|
| `phase5-observability` | Prometheus、Grafana、Blackbox Exporter、OpenTelemetry Collector、toolbox | SLO、blackbox probe、metrics/logs/traces |
| `phase6-release` | Nginx edge proxy、toolbox | edge routing、release gate、rollback判断 |
| `phase8-distributed` | Redis、toolbox | cache/queue依存、backpressure、capacity planning |
| `phase10-linux-internals` | toolbox | ss、lsof、strace、capability確認 |
| `phase11-network-edge` | Nginx edge proxy、toolbox | direct/proxy比較、TLS probe、edge routing設計 |
| `phase12-kubernetes-platform` | Nginx edge proxy、toolbox | Kubernetes manifest review、platform guardrail |
| `phase13-cloud-security` | toolbox | IAM/KMS/VPC/Auditの設計レビュー |
| `phase14-iac-policy` | toolbox | IaC plan review、OPA/Conftest相当のpolicy設計 |
| `phase15-advanced-observability` | Prometheus、Grafana、Blackbox Exporter、OpenTelemetry Collector、toolbox | burn-rate、trace/log/metric correlation |
| `phase16-distributed-reliability` | Redis、toolbox | queue、idempotency、backpressure |
| `phase18-security-supply-chain` | toolbox | SBOM/SAST/DAST/SCA、artifact signing、release gate |
| `capstone` | 上記すべて | 攻撃、検知、修正、SLO、release、postmortem、OSS governance |

## 修了判定

全フェーズで「実行した」だけでは合格にしません。次の証跡を揃えます。

- 実行コマンド、対象、時刻、期待結果、実結果
- 抽象説明: 何を守り、何を観測し、どの意思決定に使うか
- 具体例: payload、HTTP結果、ログ、metric、manifest差分、policy違反など
- 攻撃/障害の影響範囲、検知方法、復旧判断
- 修正PR、テスト結果、rollback方針
- SLO/SLI、MTTD/MTTR、postmortem
- Cloud/IaC/Supply Chain/Release/OSS governance の運用証跡

## 検証

```bash
node scripts/generate_learning_phase_html.js
scripts/learning_phase_check.sh
scripts/world_class_curriculum_check.sh
scripts/world_class_hands_on_check.sh all
```

フェーズ定義は `learning/phases.json` を正とします。HTMLは `scripts/generate_learning_phase_html.js` で生成し、`scripts/learning_phase_check.sh` とCIで、Docker profile、生成HTML、抽象説明、具体例、未完了プレースホルダ、`:latest` タグ混入を検査します。
