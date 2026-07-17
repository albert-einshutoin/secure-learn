# OWASP API Security Track

このトラックは、ホワイトハットとバックエンドエンジニアの両方が理解すべきAPI脆弱性を Secure Learn に追加していくための設計メモです。

| Module | 脆弱性 | 攻撃ハンズオン | 修正ハンズオン | テスト |
|--------|--------|----------------|----------------|--------|
| API-1 | BOLA/IDOR | 他ユーザーIDで取得 | ownership check | 200 -> 403 regression |
| API-2 | Broken Authentication | weak password, brute force | hash, lockout, session policy | auth unit/API tests |
| API-3 | Broken Object Property Authorization | role/body改ざん | allowlist DTO | schema tests |
| API-4 | Unrestricted Resource Consumption | high cost query, large body | pagination, timeout, body limit | load and 413 tests |
| API-5 | Broken Function Level Authorization | guestがadmin操作 | RBAC guard | role matrix tests |
| API-6 | Unrestricted Access to Sensitive Business Flows | inventory reservationや購入フローのautomation abuse | business flowのrate/velocity制限、bot対策 | inventory/automation abuse regression |
| API-7 | Server Side Request Forgery | internal URL fetch | URL allowlist, DNS/IP block | metadata URL deny tests |
| API-8 | Security Misconfiguration | verbose errors, permissive CORS | secure headers, explicit CORS、generic errors | header/error tests |
| API-9 | Inventory Management | undocumented endpoint | route inventory | OpenAPI diff |
| API-10 | Unsafe API Consumption | untrusted upstream data | timeout/schema validation | upstream mock tests |

Injection is a supporting secure-coding topic in this track; it is not API8:2023. SQLiとcommand injectionは、parameterized queryや安全なprocess APIをTDDで学ぶ補助課題として維持します。

## 追加する順序

1. SQLi / path traversal の修正TDD
2. IDOR/BOLA の新規シナリオ
3. JWT/OAuth の認証基盤
4. SSRF と outbound policy
5. OpenAPI contract と breaking-change CI
