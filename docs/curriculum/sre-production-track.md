# SRE Production Track

このトラックは、Secure Learn を「動くラボ」から「運用できるサービス」へ引き上げるためのSREハンズオンです。

## SLI/SLO

| SLI | 測定方法 | 初期SLO |
|-----|----------|---------|
| Availability | `/health` 200 ratio | 99.9% |
| Latency | p95 `/health`, `/auth/login`, `/users` | p95 < 500ms |
| Error rate | 5xx / total requests | < 1% |
| Detection latency | attack start -> first alert | < 60s |
| Response latency | first alert -> containment | < 15min |

## ハンズオン

| Module | 内容 | 合格証跡 |
|--------|------|----------|
| SRE-1 | `scripts/sre_smoke.sh` をSLO gateとして使う | smoke report |
| SRE-2 | DoS前後のlatency/errorを測る | before/after evidence |
| SRE-3 | MTTD/MTTRを計算する | incident report |
| SRE-4 | burn-rate alert設計 | alert table |
| SRE-5 | canary/rollback手順を書く | release checklist |
| SRE-6 | DB backup/restore演習 | restore log |
| SRE-7 | postmortem作成 | postmortem template |

## 業務レベルで必要な追加実装

- Prometheus/Grafana または OpenTelemetry Collector
- request id と trace id のログ相関
- p95/p99 レイテンシ集計
- structured incident severity
- release rollback scripts
- backup/restore script
- capacity/load test runner

