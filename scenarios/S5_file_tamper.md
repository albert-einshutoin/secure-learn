# S5: 重要ファイル改変

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S5 |
| 攻撃名 | 重要ファイル改変 |
| 主レイヤー | OS |
| MITRE ATT&CK | Impact - Data Manipulation (T1565) |
| 検知コンポーネント | Auditd |
| 難易度 | 中級 |

---

## 前提条件

> **重要**: AuditdはLinuxカーネル機能に依存するため、Docker内では動作しません。
> このシナリオはスナップショットから破棄できるLinux VMだけで実行してください。
> 日常利用中のホストや共有環境のアカウント制御ファイルは変更しません。

### ホストでのAuditd設定

```bash
# Auditdインストール
sudo apt-get install auditd audispd-plugins

# 教材ルールを読み取り専用権限で配置
sudo install -m 0640 auditd/audit.rules /etc/audit/rules.d/soc-lab.rules

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

# 使い捨てテストファイルだけを監視対象へ追加
TEST_FILE=/tmp/secure-learn-audit-target
touch "$TEST_FILE"
sudo auditctl -w "$TEST_FILE" -p wa -k secure_learn_test_file
```

### 2. 攻撃の実行（ホスト上）

```bash
# 一般ユーザー権限で使い捨てファイルを変更
TEST_FILE=/tmp/secure-learn-audit-target
printf 'baseline\n' > "$TEST_FILE"
printf 'tamper simulation\n' >> "$TEST_FILE"
chmod 600 "$TEST_FILE"
```

### 3. 攻撃バリエーション

| 対象ファイル | コマンド | 検知キー |
|-------------|---------|---------|
| 内容変更 | `printf 'change\n' >> "$TEST_FILE"` | secure_learn_test_file |
| 権限変更 | `chmod 640 "$TEST_FILE"` | secure_learn_test_file |
| 名前変更 | `mv "$TEST_FILE" "${TEST_FILE}.moved"` | secure_learn_test_file |

---

## ログ観測点

| レイヤー | ログファイル | 確認内容 |
|---------|-------------|---------|
| OS | `/var/log/audit/audit.log` | SYSCALL + PATH |

---

## 成功判定表

| 判定項目 | 成功条件 | 検証方法 |
|---------|---------|---------|
| Auditd記録 | SYSCALLレコード出力 | `ausearch -k secure_learn_test_file` |
| ファイル特定 | 変更ファイルパスが記録 | `ausearch -f /tmp/secure-learn-audit-target` |
| ユーザー特定 | auid（実ユーザー）が記録 | Auditログのauidフィールド |
| SIEM可視化 | Kibanaでイベント表示 | `event.module:auditd AND file.path:/tmp/secure-learn-audit-target` |

### 検証コマンド

```bash
# キーで検索
sudo ausearch -k secure_learn_test_file

# ファイルで検索
sudo ausearch -f /tmp/secure-learn-audit-target

# 時間範囲で検索（過去1時間）
sudo ausearch -ts recent -k secure_learn_test_file

# レポート生成
sudo aureport --file --summary
sudo aureport --file --start today
```

---

## 対応手順（Respond Runbook）

### 1. 検知確認

```bash
# ファイル改変アラート確認
sudo ausearch -k secure_learn_test_file -i | head -50
```

### 2. 変更内容確認

```bash
# 事前に保存したテスト用baselineと比較
diff /tmp/secure-learn-audit-target.baseline /tmp/secure-learn-audit-target
```

### 3. 変更者特定

```bash
# auidからユーザーを特定
sudo ausearch -f /tmp/secure-learn-audit-target | grep auid
# auid=1000 → UID 1000のユーザー

# ユーザー名取得
getent passwd 1000
```

### 4. 対応

テストファイルを隔離して証跡を保存し、実システムでは組織の承認済みインシデント対応手順に従います。教材内ではアカウント停止やシステムファイル復元を実行しません。

### 5. 根本対策

- ファイルのimmutableフラグ設定
- FIM（File Integrity Monitoring）の導入
- 最小権限原則の徹底

---

## 改善点

| 項目 | 改善内容 |
|------|---------|
| FIM導入 | AIDE/Tripwireで整合性監視 |
| immutableフラグ | 使い捨てテストファイルで動作と解除手順を検証 |
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

