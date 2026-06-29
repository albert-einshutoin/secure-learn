# Secure Infrastructure Learning Docker

このトラックは、初学者が `docker compose up` から始めて、大手セキュアインフラ企業で求められる Whitehat、SRE、Backend、Detection、Cloud/Supply Chain の判断まで段階的に進むためのフェーズ制カリキュラムです。

## 実行入口

```bash
scripts/learning_phase.sh list
scripts/learning_phase.sh start p5
scripts/learning_phase.sh status p5
scripts/learning_phase.sh stop p5
```

各フェーズのHTMLガイドは [Learning Phase Guides](../learning-phases/index.html) から確認できます。

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

## Docker profiles

| Profile | 追加サービス | 学習すること |
|---------|--------------|--------------|
| `phase5-observability` | Prometheus、Grafana、Blackbox Exporter、OpenTelemetry Collector、toolbox | SLO、blackbox probe、metrics/logs/tracesの役割 |
| `phase6-release` | Nginx edge proxy、toolbox | edge routing、release gate、rollback判断 |
| `phase8-distributed` | Redis、toolbox | cache/queue依存、backpressure、capacity planning |
| `capstone` | 上記すべて | 攻撃、検知、修正、SLO、release、postmortemの統合 |

## 修了判定

全フェーズで「実行した」だけでは合格にしません。次の証跡を揃えます。

- 実行コマンド、対象、時刻、期待結果、実結果
- 攻撃/障害の影響範囲、検知方法、復旧判断
- 修正PR、テスト結果、rollback方針
- SLO/SLI、MTTD/MTTR、postmortem
- 次に実装すべきcloud/IaC/supply chain課題

## 運用ルール

フェーズ定義は `learning/phases.json` を正とします。HTMLは `scripts/generate_learning_phase_html.js` で生成し、`scripts/learning_phase_check.sh` とCIで、Docker profile、生成HTML、未完了プレースホルダ、`:latest` タグ混入を検査します。
