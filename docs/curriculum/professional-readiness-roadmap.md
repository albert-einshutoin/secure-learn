# Professional Readiness Roadmap

このロードマップは、Secure Learn を「入門〜中級のSOCラボ」から、ホワイトハット、SRE、バックエンドエンジニアが業務で使う判断と成果物まで伸ばすための不足領域一覧です。

## 判定基準

「一人前」と呼ぶには、攻撃を再現できるだけでは不足です。次の5つをセットで証明します。

| 領域 | 証明すること |
|------|--------------|
| 発見 | 脆弱性、障害、運用リスクを安全な範囲で再現できる |
| 修正 | 原因を潰す最小実装を設計し、TDDで回帰を防げる |
| 運用 | SLO、ログ、メトリクス、アラート、オンコール判断に接続できる |
| 報告 | CVSS/CWE、影響範囲、残リスク、再発防止を第三者に説明できる |
| OSS | Issue、PR、CI、レビュー、リリースノートとして追跡できる |

## Track 1: OWASP/API Security

| 必須テーマ | ハンズオン化する内容 | 合格証跡 |
|------------|----------------------|----------|
| IDOR/BOLA | 他ユーザーのID指定で情報を読める状態を作り、認可チェックで修正する | 失敗する攻撃テスト、修正PR、認可テスト |
| SSRF | 内部メタデータ風URLへのアクセスを再現し、allowlistで制限する | URL検証テスト、拒否ログ |
| JWT/OAuth | 署名なし/期限切れ/role改ざんを検証する | token validation unit/API tests |
| CORS/CSRF | unsafe origin と state-changing request を検証する | CORS policy test, CSRF design note |
| Upload/XXE | MIME/拡張子/サイズ/XML entity を検証する | negative tests, parser config |
| RCE/Command injection | シェル引数の危険パターンを再現し、spawn引数配列へ修正する | red test, secure implementation |
| Business logic abuse | rate limitだけでは防げない連続操作、残高、状態遷移を検証する | state machine tests |

## Track 2: Secure Remediation TDD

| 必須テーマ | ハンズオン化する内容 | 合格証跡 |
|------------|----------------------|----------|
| SQLi remediation | 文字列連結SQLをパラメータ化クエリへ修正 | before/after test, DB integration test |
| Path traversal remediation | `path.resolve` と baseDir containment を実装 | traversal regression test |
| Auth hardening | password hash、lockout、generic error を設計 | unit/API tests, migration note |
| Error handling | DB errorやstack traceを外部へ出さない | error contract tests |
| Logging safety | PII/secret をログに出さない | log redaction tests |
| Rate limit hardening | shared store前提、429 contract、bypass検証 | API and abuse tests |

## Track 3: Backend Engineering

| 必須テーマ | ハンズオン化する内容 | 合格証跡 |
|------------|----------------------|----------|
| Controller/Service分離 | controllerはHTTP、serviceはbusiness logicに限定 | unit tests, review checklist |
| Repository/DB boundary | DBアクセスを抽象化し、SQL生成を集約する | repository tests |
| Transaction/data consistency | 複数更新の原子性とrollbackを検証 | integration tests |
| Pagination/filtering | limit/offset/sort の境界値を検証 | contract tests |
| Concurrency | 同時リクエスト、重複処理、race conditionを検証 | parallel test script |
| Performance | p95 latency、N+1、connection poolを検証 | load test report |
| Compatibility | API contract と backward compatibility を検証 | OpenAPI/contract test |

## Track 4: Cloud, Container, Kubernetes

| 必須テーマ | ハンズオン化する内容 | 合格証跡 |
|------------|----------------------|----------|
| Container hardening | non-root、read-only FS、capabilities、image scan | Dockerfile diff, Trivy report |
| Kubernetes basics | Deployment/Service/ConfigMap/Secretを追加 | k8s manifests, smoke test |
| NetworkPolicy | attacker namespaceからの到達制御 | allowed/denied evidence |
| Secret management | env secret禁止、sealed/external secret設計 | policy doc |
| IAM/RBAC | least privilege service account | RBAC review |
| Ingress/TLS | TLS終端、証明書期限、WAF/Proxy log | TLS/SNI test evidence |

## Track 5: SRE Production Operations

| 必須テーマ | ハンズオン化する内容 | 合格証跡 |
|------------|----------------------|----------|
| SLIs/SLOs | availability, latency, error rate を定義 | SLO doc, smoke script |
| Error budget | burn rate と対応条件を作る | alert routing table |
| Observability | metrics/logs/traces を相関する | dashboard, trace evidence |
| Release safety | canary/blue-green/rollbackを設計 | release checklist |
| Capacity planning | load testからCPU/Memory/DBの限界を読む | capacity report |
| DR/Backup | backup/restore、RTO/RPOを検証 | restore log |
| Incident command | severity、roles、postmortemを実施 | postmortem |

## Track 6: Supply Chain and CI Security

| 必須テーマ | ハンズオン化する内容 | 合格証跡 |
|------------|----------------------|----------|
| SAST | Semgrep等のルールをCIで走らせる | CI run |
| DAST | running appに対する安全なスキャンを走らせる | DAST report |
| SCA/OSV | npm/container依存の脆弱性を検出する | audit/OSV report |
| Secret scanning | Gitleaks/GitGuardianの検出と除外管理 | clean run |
| SBOM | CycloneDX/SPDXを生成し保管する | SBOM artifact |
| Image scan | Trivy等でimageを評価する | scan report |
| Branch protection | required checks, review, signed releaseを設計 | repo settings note |

## Track 7: Evidence Portfolio

| 成果物 | 内容 |
|--------|------|
| Vulnerability report | CWE/CVSS/再現/影響/修正/残リスク |
| Remediation PR | failing test -> fix -> passing test -> rollback |
| Incident report | timeline, MTTD, MTTR, customer impact |
| SLO report | p95/p99, error budget, alert threshold |
| Architecture Decision Record | なぜその防御・運用設計にしたか |

