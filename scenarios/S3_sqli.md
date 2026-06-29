# S3: SQLインジェクション

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S3 |
| 攻撃名 | SQLインジェクション |
| 主レイヤー | L7 |
| MITRE ATT&CK | Initial Access - Exploit Public-Facing Application (T1190) |
| 検知コンポーネント | Suricata, NestJS App, Fail2ban |
| 難易度 | 中級 |

---

## 攻撃手順

### 1. 環境の起動

```bash
# SOC-Lab環境を起動
docker compose up -d

# Kaliコンテナに接続
docker exec -it soc-lab-kali /bin/bash
```

### 2. 攻撃の実行

```bash
# スクリプトを使用
/scripts/s3_sqli.sh

# または手動で実行
sqlmap -u "http://app:3000/users?id=1" --batch --level=3
```

### 3. 攻撃バリエーション

| 攻撃タイプ | ペイロード | 目的 |
|-----------|----------|------|
| 認証バイパス | `' OR '1'='1` | 全レコード取得 |
| UNION攻撃 | `1 UNION SELECT * FROM users--` | 他テーブルのデータ取得 |
| エラーベース | `'` | エラーメッセージからDB情報取得 |
| 時間ベース | `1; WAITFOR DELAY '0:0:5'--` | ブラインドSQLi |

### 4. 脆弱なエンドポイント

| エンドポイント | パラメータ | 脆弱性 |
|---------------|----------|--------|
| GET /users | id | 直接SQLクエリ連結 |
| GET /users/search | name | LIKE句への直接挿入 |

---

## ログ観測点

| レイヤー | ログファイル | 確認内容 |
|---------|-------------|---------|
| L7 | `/var/log/suricata/eve.json` | alert.signature: "SQLI" |
| L7 | `/var/log/app/error.log` | event.action: "sqli_attempt" |
| L7 | `/var/log/app/access.log` | 不正クエリパターン |

---

## 成功判定表

| 判定項目 | 成功条件 | 検証方法 |
|---------|---------|---------|
| Suricata検知 | `SQLI`アラート発生 | `grep "SQLI" eve.json` |
| アプリログ | SQLiパターンが記録 | `grep "sqli_attempt" error.log` |
| Fail2ban BAN | 閾値超過でBAN | `fail2ban-client status nestjs-sqli` |
| 攻撃失敗（防御成功） | DBエラーが発生しない | HTTP 400応答 |

### 検証コマンド

```bash
# Suricataアラート確認
docker exec soc-lab-suricata grep SQLI /var/log/suricata/fast.log

# アプリエラーログ確認
docker exec soc-lab-app cat /var/log/app/error.log | grep sqli_attempt

# Fail2ban状態確認
docker exec soc-lab-fail2ban fail2ban-client status nestjs-sqli
```

---

## 対応手順（Respond Runbook）

### 1. 検知確認

```bash
# SQLiアラート確認
docker exec soc-lab-suricata grep SQLI /var/log/suricata/fast.log | tail -10
```

### 2. 攻撃詳細確認

```bash
# 対象エンドポイント特定
docker exec soc-lab-app cat /var/log/app/error.log | grep sqli_attempt | jq '.["url.path"]'
```

### 3. 影響評価

```bash
# 攻撃が成功したか確認（DBエラー有無）
docker exec soc-lab-app cat /var/log/app/error.log | grep "Database error"
```

### 4. 対応

```bash
# 一時的にエンドポイント無効化（アプリ側で対応）
# または攻撃元IPをBAN
docker exec soc-lab-fail2ban fail2ban-client set nestjs-sqli banip <攻撃IP>
```

### 5. 根本対策

- パラメータ化クエリへの修正
- 入力検証の追加
- WAFルールの追加

---

## 改善点

| 項目 | 改善内容 |
|------|---------|
| パラメータ化クエリ | 全SQLをプリペアドステートメントに変更 |
| 入力検証 | ホワイトリストベースの検証 |
| WAFルール | ModSecurityルールの追加 |
| エラーハンドリング | 詳細エラーを非表示に |

---

## 評価チェックリスト

### 初級評価

- [ ] sqlmapを正しく実行できた
- [ ] Suricataログでアラートを確認できた
- [ ] アプリログでSQLiパターンを確認できた
- [ ] Kibanaで検索クエリを作成できた

→ **4項目中3項目以上で合格**

### 中級評価

- [ ] 検知回避のペイロードを特定できた
- [ ] Suricataルールを調整/追加できた
- [ ] Fail2banフィルターを最適化できた
- [ ] 変更の影響範囲を説明できた

→ **4項目中3項目以上で合格**

### 上級評価

- [ ] 攻撃手法と影響を詳細に説明できた
- [ ] パラメータ化クエリへの修正を設計できた
- [ ] 多層防御（入力検証+WAF+IDS）を設計できた
- [ ] SOCレポートを作成できた

→ **4項目すべてで合格**

---

## 参考資料

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [sqlmap Documentation](https://sqlmap.org/)
- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

