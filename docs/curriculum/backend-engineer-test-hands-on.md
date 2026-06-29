# Backend Engineer Test Hands-on

バックエンドエンジニア視点では、セキュリティ演習を「攻撃ができた」で終わらせません。業務では、壊れる条件をテストで固定し、修正後に二度と戻らないことをCIで証明します。

## テスト階層

| 階層 | 目的 | このリポジトリでの入口 |
|------|------|------------------------|
| Unit | 純粋な関数、service、境界値を高速に検証 | `npm --prefix app test` |
| API contract | HTTP status、response shape、error shapeを検証 | `scripts/backend_hands_on_tests.sh` |
| Security regression | SQLi、path traversal、auth bypassを再発防止する | `scripts/backend_hands_on_tests.sh` |
| Integration | DB、transaction、migration、repository境界を検証 | `npm --prefix app run test:integration` |
| Observability | logs、request id、PII redaction、alertを検証 | Suricata/Fail2ban/Kibana evidence |
| Performance | latency、throughput、connection pool、N+1を検証 | `scripts/sre_smoke.sh` から load test へ拡張 |
| Resilience | timeout、retry、partial failure、rollbackを検証 | S14/S15 の incident exercise |

## 追加済みの実行テスト

```bash
npm --prefix app test
```

現在の unit test は次を確認します。

- valid login で credential material を返さない
- invalid login は `null`
- bearer token の署名検証
- 連続失敗による account lockout
- Docker/Fowarded IP を Fail2ban が扱いやすい形に正規化
- public file は読める
- path traversal が 403 で拒否される
- SQLi payload が service 境界で 400 になる
- OpenAPI contract の必須パス

## Docker起動後のハンズオンテスト

```bash
docker compose up -d --build
scripts/backend_hands_on_tests.sh
```

このスクリプトは、次をレポートします。

| テスト | 観点 | 期待 |
|--------|------|------|
| health endpoint | SRE smoke前提 | `PASS` |
| readiness endpoint | DB dependency確認 | `PASS` |
| auth success | tokenを返しcredential materialを返さない | `PASS` |
| auth failure | 401 contract | `PASS` |
| SQLi remediation | injection payload拒否 | `PASS` |
| path traversal remediation | encoded traversal拒否 | `PASS` |
| authorization role guard | 非admin token拒否 | `PASS` |
| root endpoint | service identity | `PASS` |

`FAIL` が出た場合は修正PRの blocker として扱います。攻撃が検知されるだけでなく、アプリの安全なHTTP契約も満たす必要があります。

## 業務レベルで追加すべきテスト

| カテゴリ | ハンズオン課題 | 合格条件 |
|----------|----------------|----------|
| SQLi修正 | `UsersService` を parameterized query にする | SQLi payload がデータを返さず、Suricata/App log に証跡が残る |
| Path traversal修正 | `FilesService` で baseDir containment を強制する | `../` と encoded traversal が 403 |
| Auth hardening | credential hash と account lockout を実装する | hash検証、lockout、generic error test |
| Authorization | admin/user/guest の権限差をAPIで検証する | IDOR/BOLAが再現できず、403になる |
| Validation | DTO/schema validation を追加する | invalid body/queryが 400 と安全なerror shape |
| Error handling | DBエラーを外部に漏らさない | responseにSQL/stack traceが出ない |
| Logging | PII/secret redaction を実装する | password/tokenがログに出ない |
| DB integration | DB境界を実DBで検証する | parameterized query と valid lookup のテスト |
| API contract | OpenAPIまたは固定JSON schemaを導入 | breaking change をCIで検知 |
| Performance | p95 latency under load | `scripts/load_hands_on_tests.sh` がSLO内 |
| Concurrency | 同時ログイン/検索/ファイルアクセス | race conditionなし、ログ相関可能 |
| Migration | schema migration と rollback | forward/backward両方の手順が通る |

## TDDの進め方

1. 攻撃や障害を再現するハンズオンを実行する
2. 期待する安全な振る舞いをテストとして書く
3. 最小の修正を入れる
4. unit/API/security/SRE smoke をすべて通す
5. 変更理由、残リスク、ロールバック方針をPRに書く
