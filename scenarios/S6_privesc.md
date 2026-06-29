# S6: 権限昇格

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S6 |
| 攻撃名 | 権限昇格 |
| 主レイヤー | OS |
| MITRE ATT&CK | Privilege Escalation - Sudo and Sudo Caching (T1548) |
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
sudo auditctl -l | grep privilege
```

---

## 攻撃手順

### 1. 環境確認

```bash
# 現在のユーザー情報
id
whoami

# Auditd動作確認
sudo systemctl status auditd
```

### 2. 攻撃の実行（ホスト上）

```bash
# sudo による権限昇格
sudo whoami
sudo id
sudo -u root /bin/bash -c "whoami"

# su による権限昇格
su - root -c "whoami"

# 特権コマンド実行
sudo cat /etc/shadow
```

### 3. 攻撃バリエーション

| 手法 | コマンド | 検知キー |
|------|---------|---------|
| sudo | `sudo whoami` | sudo_usage |
| su | `su - root` | su_usage |
| SUID悪用 | `/usr/bin/passwd` | setuid_execution |
| setuid syscall | カスタムバイナリ | privilege_escalation |

### 4. SUID探索（偵察）

```bash
# SUID ビットが設定されたファイルを検索
find / -perm -4000 2>/dev/null

# SGID ビットが設定されたファイルを検索
find / -perm -2000 2>/dev/null

# 両方
find / -perm /6000 2>/dev/null
```

---

## ログ観測点

| レイヤー | ログファイル | 確認内容 |
|---------|-------------|---------|
| OS | `/var/log/audit/audit.log` | execve + euid=0 |
| OS | `/var/log/auth.log` | sudo/su ログ |

---

## 成功判定表

| 判定項目 | 成功条件 | 検証方法 |
|---------|---------|---------|
| Auditd記録 | execve + euid=0が記録 | `ausearch -k privilege_escalation` |
| プロセス特定 | 実行コマンドが記録 | `ausearch -c sudo` |
| ユーザー特定 | auidが記録 | Auditログ確認 |
| SIEM可視化 | Kibanaでイベント表示 | `event.module:auditd AND user.effective.id:0` |

### 検証コマンド

```bash
# 権限昇格イベント検索
sudo ausearch -k privilege_escalation

# sudo使用検索
sudo ausearch -k sudo_usage

# su使用検索
sudo ausearch -k su_usage

# euid=0での実行検索
sudo ausearch -sc execve -ui 0

# 認証レポート
sudo aureport --auth --summary
```

---

## 対応手順（Respond Runbook）

### 1. 検知確認

```bash
# 権限昇格イベント確認
sudo ausearch -k privilege_escalation -i | head -50
```

### 2. 実行者特定

```bash
# auidからユーザーを特定
sudo ausearch -k privilege_escalation | grep auid

# ユーザー名取得
getent passwd <uid>
```

### 3. 実行内容確認

```bash
# 実行されたコマンド確認
sudo ausearch -k privilege_escalation | grep -A5 execve | grep "a0="
```

### 4. 判断

| 状況 | 判断 | 対応 |
|------|------|------|
| 管理者の正当な操作 | 正常 | 記録のみ |
| 非管理者による昇格 | 要調査 | 経緯確認 |
| 不正な昇格 | 攻撃 | セッション終了・アカウントロック |

### 5. 対応（不正の場合）

```bash
# セッション強制終了
sudo pkill -u <username>

# アカウントロック
sudo passwd -l <username>

# sudoers から削除
sudo visudo
```

---

## 改善点

| 項目 | 改善内容 |
|------|---------|
| 最小権限原則 | 必要最小限のsudo権限のみ付与 |
| NOPASSWD削除 | sudoersからNOPASSWDを削除 |
| sudo制限 | 特定コマンドのみ許可 |
| 監査強化 | すべてのsudo使用をログ |
| MFA | sudo実行時にMFA要求 |

### sudoersベストプラクティス

```bash
# 特定コマンドのみ許可（例）
username ALL=(root) /usr/bin/systemctl restart nginx, /usr/bin/tail /var/log/nginx/*

# グループベースの管理
%developers ALL=(root) NOPASSWD: /usr/bin/docker
%sysadmins ALL=(ALL) ALL
```

---

## 評価チェックリスト

### 初級評価

- [ ] sudo/suを実行できた
- [ ] Auditdログで権限昇格を確認できた
- [ ] 実行されたコマンドを特定できた
- [ ] Kibanaでイベントを検索できた

→ **4項目中3項目以上で合格**

### 中級評価

- [ ] SUIDバイナリを列挙できた
- [ ] 監査ルールを追加できた
- [ ] ausearchで詳細な情報を抽出できた
- [ ] 正常/異常の判断基準を説明できた

→ **4項目中3項目以上で合格**

### 上級評価

- [ ] 権限昇格経路を説明できた
- [ ] 最小権限原則に基づくsudoers設計ができた
- [ ] 監査・検知・対応の一連の流れを設計できた
- [ ] SOCレポートを作成できた

→ **4項目すべてで合格**

---

## 参考資料

- [Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [sudo Security](https://www.sudo.ws/docs/security/)
- [MITRE ATT&CK T1548](https://attack.mitre.org/techniques/T1548/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

