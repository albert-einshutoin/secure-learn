# S2: APIブルートフォース

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S2 |
| 攻撃名 | APIブルートフォース |
| 主レイヤー | L7 |
| MITRE ATT&CK | Credential Access - Brute Force (T1110) |
| 検知コンポーネント | NestJS App, Fail2ban, Suricata |
| 難易度 | 初級 |

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
/scripts/s2_bruteforce.sh

# または手動で実行
hydra -l admin -P /wordlists/passwords.txt \
  -s 3000 app \
  http-post-form "/auth/login:username=^USER^&password=^PASS^:Invalid"
```

### 3. 攻撃バリエーション

| 攻撃タイプ | コマンド | 説明 |
|-----------|---------|------|
| 単一ユーザー | `hydra -l admin -P passwords.txt ...` | 特定ユーザーを狙う |
| 複数ユーザー | `hydra -L users.txt -P passwords.txt ...` | ユーザーリストを使用 |
| 低速攻撃 | `hydra -l admin -P passwords.txt -t 1 -w 5 ...` | 検知回避 |

---

## ログ観測点

| レイヤー | ログファイル | 確認内容 |
|---------|-------------|---------|
| L7 | `/var/log/app/auth.log` | event.action: "login_failed" |
| L7 | `/var/log/fail2ban/fail2ban.log` | Ban <IP> |
| SIEM | Kibana | 失敗→BANの相関 |

---

## 成功判定表

| 判定項目 | 成功条件 | 検証方法 |
|---------|---------|---------|
| アプリログ出力 | auth.logに失敗ログ5件以上 | `grep "login_failed" auth.log \| wc -l` |
| Fail2ban BAN | IPがjailに存在 | `fail2ban-client status nestjs-auth` |
| 通信遮断 | curlがtimeout/connection refused | `curl --connect-timeout 5 http://<ip>:3000/auth/login` |
| SIEM相関 | 失敗→BANの時系列が確認可能 | Kibana Timeline |

### 検証コマンド

```bash
# アプリログ確認
docker exec soc-lab-app cat /var/log/app/auth.log | grep login_failed | tail -10

# Fail2ban状態確認
docker exec soc-lab-fail2ban fail2ban-client status nestjs-auth

# BAN済みIP一覧
docker exec soc-lab-fail2ban fail2ban-client status nestjs-auth | grep "Banned IP"

# 接続テスト（BAN確認）
curl --connect-timeout 5 http://localhost:3000/auth/login
```

---

## 対応手順（Respond Runbook）

### 1. 検知確認

```bash
# Fail2banアラート確認
docker exec soc-lab-fail2ban fail2ban-client status nestjs-auth
```

### 2. 攻撃履歴確認

```bash
# BANされたIPの攻撃履歴
docker exec soc-lab-app grep "<攻撃IP>" /var/log/app/auth.log
```

### 3. 誤検知判断

- 社内IPからの連続失敗 → ユーザー確認
- 不明IPからの大量試行 → 正当な攻撃

### 4. 対応

```bash
# 誤検知の場合：UNBAN
docker exec soc-lab-fail2ban fail2ban-client set nestjs-auth unbanip <IP>

# 正当な攻撃の場合：永続BAN検討
# jail.localのbantimeを-1に設定
```

### 5. 再発防止

```bash
# findtime/maxretry調整
vim fail2ban/jail.local
docker compose restart fail2ban
```

---

## 改善点

| 項目 | 改善内容 |
|------|---------|
| maxretry最適化 | ビジネス要件に合わせて閾値調整 |
| アカウントロックアウト | アプリ側でN回失敗後のロック実装 |
| CAPTCHA | 連続失敗後にCAPTCHA要求 |
| 多要素認証 | MFA導入でパスワード単体攻撃を無効化 |

---

## 評価チェックリスト

### 初級評価

- [ ] hydraコマンドを正しく実行できた
- [ ] auth.logに失敗ログが記録されることを確認できた
- [ ] Fail2banでBANされることを確認できた
- [ ] Kibanaでログを検索できた

→ **4項目中3項目以上で合格**

### 中級評価

- [ ] BAN回避の方法（低速攻撃）を特定できた
- [ ] maxretry/findtimeを最適化できた
- [ ] 調整後の動作を検証できた
- [ ] 変更の影響範囲を説明できた

→ **4項目中3項目以上で合格**

### 上級評価

- [ ] 攻撃→検知→BANの時系列を説明できた
- [ ] アカウントロックアウト機能を設計できた
- [ ] 多層防御戦略を文書化できた
- [ ] SOCレポートを作成できた

→ **4項目すべてで合格**

---

## 参考資料

- [Hydra Documentation](https://github.com/vanhauser-thc/thc-hydra)
- [Fail2ban Manual](https://www.fail2ban.org/wiki/index.php/MANUAL_0_8)
- [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/)
- [OWASP Credential Stuffing](https://owasp.org/www-community/attacks/Credential_stuffing)

