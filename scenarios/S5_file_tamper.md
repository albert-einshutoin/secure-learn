# S5: 重要ファイル改変

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S5 |
| 攻撃名 | 重要ファイル改変 |
| 主レイヤー | OS |
| MITRE ATT&CK | Defense Evasion - File and Directory Modification (T1565) |
| 検知コンポーネント | Auditd |
| 難易度 | 中級 |

---

## 前提条件

> **重要**: AuditdはLinuxカーネル機能に依存するため、Docker内では動作しません。
> このシナリオはホストOS上でAuditdを実行する必要があります。

### ホストでのAuditd設定

```bash
# Auditdインストール
sudo apt-get install auditd audispd-plugins

# ルールをコピー
sudo cp auditd/audit.rules /etc/audit/rules.d/soc-lab.rules

# Auditd再起動
sudo systemctl restart auditd

# ルール確認
sudo auditctl -l
```

---

## 攻撃手順

### 1. 環境確認

```bash
# Auditdが動作しているか確認
sudo systemctl status auditd

# ルールが読み込まれているか確認
sudo auditctl -l | grep passwd
```

### 2. 攻撃の実行（ホスト上）

```bash
# /etc/passwd の読み取り（監査対象）
sudo cat /etc/passwd

# /etc/passwd の変更（テスト用）
# 警告: 本番環境では実行しないでください
sudo touch /etc/passwd

# /etc/shadow の読み取り
sudo cat /etc/shadow

# /etc/sudoers の変更
sudo visudo  # :wq で保存
```

### 3. 攻撃バリエーション

| 対象ファイル | コマンド | 検知キー |
|-------------|---------|---------|
| /etc/passwd | `sudo touch /etc/passwd` | passwd_changes |
| /etc/shadow | `sudo touch /etc/shadow` | shadow_changes |
| /etc/sudoers | `sudo visudo` | sudoers_changes |
| /etc/crontab | `sudo touch /etc/crontab` | cron_changes |
| /etc/ssh/sshd_config | `sudo touch /etc/ssh/sshd_config` | sshd_config_changes |

---

## ログ観測点

| レイヤー | ログファイル | 確認内容 |
|---------|-------------|---------|
| OS | `/var/log/audit/audit.log` | SYSCALL + PATH |

---

## 成功判定表

| 判定項目 | 成功条件 | 検証方法 |
|---------|---------|---------|
| Auditd記録 | SYSCALLレコード出力 | `ausearch -k passwd_changes` |
| ファイル特定 | 変更ファイルパスが記録 | `ausearch -f /etc/passwd` |
| ユーザー特定 | auid（実ユーザー）が記録 | Auditログのauidフィールド |
| SIEM可視化 | Kibanaでイベント表示 | `event.module:auditd AND file.path:/etc/passwd` |

### 検証コマンド

```bash
# キーで検索
sudo ausearch -k passwd_changes

# ファイルで検索
sudo ausearch -f /etc/passwd

# 時間範囲で検索（過去1時間）
sudo ausearch -ts recent -k passwd_changes

# レポート生成
sudo aureport --file --summary
sudo aureport --file --start today
```

---

## 対応手順（Respond Runbook）

### 1. 検知確認

```bash
# ファイル改変アラート確認
sudo ausearch -k passwd_changes -i | head -50
```

### 2. 変更内容確認

```bash
# 変更されたファイルの差分確認
sudo diff /etc/passwd /etc/passwd-

# バックアップとの比較
sudo diff /etc/shadow /etc/shadow-
```

### 3. 変更者特定

```bash
# auidからユーザーを特定
sudo ausearch -f /etc/passwd | grep auid
# auid=1000 → UID 1000のユーザー

# ユーザー名取得
getent passwd 1000
```

### 4. 対応

```bash
# 不正な変更をロールバック
sudo cp /etc/passwd- /etc/passwd

# 変更者のアクセス権確認
sudo passwd -l <username>  # アカウントロック
```

### 5. 根本対策

- ファイルのimmutableフラグ設定
- FIM（File Integrity Monitoring）の導入
- 最小権限原則の徹底

---

## 改善点

| 項目 | 改善内容 |
|------|---------|
| FIM導入 | AIDE/Tripwireで整合性監視 |
| immutableフラグ | `chattr +i /etc/passwd` |
| アラート通知 | 変更時に即座にSlack通知 |
| バックアップ | 定期的なバックアップと差分チェック |

---

## 評価チェックリスト

### 初級評価

- [ ] ファイル変更を実行できた
- [ ] Auditdログで変更を確認できた
- [ ] 変更されたファイルパスを特定できた
- [ ] Kibanaでイベントを検索できた

→ **4項目中3項目以上で合格**

### 中級評価

- [ ] 監査ルールの追加方法を理解できた
- [ ] 新しいファイルを監視対象に追加できた
- [ ] ausearchの様々なオプションを使用できた
- [ ] aureportでレポートを生成できた

→ **4項目中3項目以上で合格**

### 上級評価

- [ ] FIM戦略を設計できた
- [ ] 監査ログからインシデントタイムラインを作成できた
- [ ] 変更防止の多層防御を設計できた
- [ ] SOCレポートを作成できた

→ **4項目すべてで合格**

---

## 参考資料

- [Linux Audit Documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing)
- [auditd Rules](https://linux.die.net/man/8/auditctl)
- [MITRE ATT&CK T1565](https://attack.mitre.org/techniques/T1565/)

