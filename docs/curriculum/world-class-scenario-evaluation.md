# World-class Scenario Evaluation

Secure Learn は、ホワイトハット、SRE、バックエンドエンジニアが同じラボで攻撃、検知、修正、運用、報告を通す教材としては実務上級の入口に到達しています。世界レベルと言い切るには、API business logic、cloud/IAM、observability、release engineering、supply chain をさらに実測できる形へ伸ばす必要があります。

## 評価軸

| 評価軸 | 確認すること |
|--------|--------------|
| Whitehat | 許可された閉域環境で再現し、攻撃手順、検知、影響、修正確認を証跡化できる |
| SRE | SLI/SLO、可用性、レイテンシ、MTTD/MTTR、暫定対応、恒久対応へ接続できる |
| Backend | 入力検証、認証認可、DB境界、契約、テスト、エラー安全性で再発を止められる |
| Evidence | コマンド、ログ、スクリーンショット、テスト結果、PR本文、postmortem が揃う |
| OSS | Issue、PR、CI、レビュー、ライセンス、貢献導線として第三者が再実行できる |

## シナリオ別評価

| Scenario | 現在の到達度 | 強い点 | 世界レベルへ足す課題 |
|----------|--------------|--------|----------------------|
| S1 ポートスキャン | 3/5 | nmap、Suricata、Kibanaで偵察から検知まで追える | 許可済みscanner、threat intel、誤検知調整、資産台帳連携 |
| S2 APIブルートフォース | 4/5 | lockout、Fail2ban、ログ相関、認証契約を確認できる | credential stuffing、MFA、分散攻撃、rate limit bypass |
| S3 SQLインジェクション | 4/5 | SQLi再現、400契約、parameterized query、DB integrationを証明できる | blind/time-based/second-order payload、DAST CI、ORM境界 |
| S4 DoS攻撃 | 3/5 | 安全な負荷、p95、availability、BAN判断へ接続できる | autoscaling、backpressure、queue、resource exhaustion、cost guard |
| S5 重要ファイル改変 | 3/5 | Auditdで改変者、時刻、対象、復旧判断を追える | immutable infrastructure、FIM、署名検証、復旧RTO/RPO |
| S6 権限昇格 | 3/5 | sudo/su/SUIDを最小権限と監査証跡へ接続できる | container escape、kernel hardening、RBAC、PAM、endpoint response |
| S7 横断インシデント | 4/5 | attack chainとして偵察、認証、SQLi、OSイベントを相関できる | MITRE ATT&CK mapping、case management、timeline自動化 |
| S8 L2 ARP観測 | 2/5 | Docker bridgeのARP/neighbor cacheとL2可視性限界を説明できる | VLAN、802.1X、ARP spoofing防御、switch telemetry |
| S9 L3 ICMP到達性 | 3/5 | 到達性、traceroute、ネットワーク障害とアプリ障害の切り分けができる | firewall/asymmetric routing、packet loss、multi-region drill |
| S10 L4 TCP状態 | 3/5 | TCP flag差分、state、Suricata ruleを観測できる | SYN flood耐性、conntrack、kernel tuning、load balancer log |
| S11 L5セッション圧迫 | 3/5 | timeout、connection limit、SLO影響を確認できる | slowloris対策、proxy timeout、pool枯渇、graceful degradation |
| S12 L6 TLS可視性境界 | 2/5 | TLS境界、ClientHello、IDS可視性の制約を説明できる | mTLS、certificate rotation、TLS policy、WAF/proxy observability |
| S13 L7 DNS観測 | 2/5 | Docker DNS、service discovery、内部偵察を扱える | DNS tunneling、NXDOMAIN spike、egress policy、resolver telemetry |
| S14 SREインシデント対応 | 4/5 | SLO、DB停止、incident report、MTTD/MTTRへ接続できる | burn-rate alert、tracing、backup/restore、canary/rollback |
| S15 修了課題 | 4/5 | 攻撃、検知、修正、運用、報告を一つの成果物にできる | cloud/IAM、supply chain、red-team report、executive brief |

## 結論

現状は「実務で戦える上級入口」です。特に S2、S3、S7、S14、S15 は、ホワイトハット、SRE、バックエンドの複合判断を要求するため価値が高いです。一方で、世界レベルを主張するなら、次の領域をハンズオン化する必要があります。

- API business logic: IDOR/BOLA、SSRF、unsafe upload、CSRF/CORS、state machine abuse
- Observability: metrics、logs、traces の相関、burn-rate alert、dashboard evidence
- Release engineering: canary、blue-green、rollback、migration rollback、compatibility test
- Cloud security: IAM/RBAC、NetworkPolicy、Ingress/TLS、secret rotation、policy-as-code
- Supply chain: SBOM、image scan、SAST/DAST/SCA、provenance、signed release

## HTMLハンズオン

各シナリオの実行フロー、確認項目、ツール活用、合格証跡は [Scenario HTML Guides](../scenario-guides/index.html) で確認できます。HTMLは `scripts/generate_scenario_html.js` から生成し、`scripts/scenario_html_check.sh` とCIで欠落を検出します。
