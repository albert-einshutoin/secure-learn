# S1: ポートスキャン

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S1 |
| 攻撃名 | ポートスキャン |
| 主レイヤー | L3/L4 |
| MITRE ATT&CK | Reconnaissance - Active Scanning (T1595) |
| 検知コンポーネント | Suricata |
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
/scripts/s1_portscan.sh

# または手動で実行
nmap -sS -p 1-1000 172.23.0.20
```

### 3. 攻撃バリエーション

| スキャンタイプ | コマンド | 検知難易度 |
|--------------|---------|-----------|
| SYN Scan | `nmap -sS <target>` | 低 |
| FIN Scan | `nmap -sF <target>` | 中 |
| XMAS Scan | `nmap -sX <target>` | 中 |
| NULL Scan | `nmap -sN <target>` | 中 |
| UDP Scan | `nmap -sU <target>` | 高 |
| Stealth Scan | `nmap -sS -T2 <target>` | 高 |

---

## ログ観測点

| レイヤー | ログファイル | 確認内容 |
|---------|-------------|---------|
| L3/L4 | `/var/log/suricata/eve.json` | alert.signature: "SCAN" |
| L3/L4 | `/var/log/suricata/fast.log` | SCAN関連アラート |

---

## 成功判定表

| 判定項目 | 成功条件 | 検証方法 |
|---------|---------|---------|
| Suricata検知 | eve.jsonに`SCAN`アラート存在 | `jq 'select(.alert.signature \| contains("SCAN"))' eve.json` |
| SIEM可視化 | Kibanaで`event.module:suricata AND rule.name:*SCAN*`表示 | Kibana Discover |
| 攻撃元特定 | `source.ip`が正しく記録 | KQL検索 |

### 検証コマンド

```bash
# Suricataログ確認
docker exec soc-lab-suricata cat /var/log/suricata/fast.log | grep SCAN

# eve.json確認
docker exec soc-lab-suricata jq 'select(.alert)' /var/log/suricata/eve.json

# アラート数カウント
docker exec soc-lab-suricata grep -c "SCAN" /var/log/suricata/fast.log
```

---

## 対応手順（Respond Runbook）

### 1. 検知確認

```bash
# アラート確認
docker exec soc-lab-suricata tail -20 /var/log/suricata/fast.log
```

### 2. 攻撃元特定

```bash
# source.ipを確認
docker exec soc-lab-suricata jq '.src_ip' /var/log/suricata/eve.json | sort | uniq -c
```

### 3. 判断

- 社内IPからの定期スキャン → 運用確認
- 不明IPからのスキャン → 遮断検討

### 4. 対応（必要な場合）

```bash
# 手動でIPをブロック（Fail2ban経由）
docker exec soc-lab-fail2ban fail2ban-client set nestjs-auth banip <攻撃IP>
```

---

## 改善点

| 項目 | 改善内容 |
|------|---------|
| threshold調整 | 誤検知削減のためカウント閾値を調整 |
| 自動BAN | Phase2でスキャン検知後の自動BAN追加 |
| アラート通知 | Phase2でSlack通知を追加 |

---

## 評価チェックリスト

### 初級評価

- [ ] nmapコマンドを正しく実行できた
- [ ] Suricataログファイルを特定できた
- [ ] アラートが記録されていることを確認できた
- [ ] Kibanaで検索クエリを作成できた

→ **4項目中3項目以上で合格**

### 中級評価

- [ ] 検知漏れするスキャンタイプを特定できた
- [ ] Suricataルールのthreshold値を調整できた
- [ ] 調整後の動作を検証できた
- [ ] 変更の影響範囲を説明できた

→ **4項目中3項目以上で合格**

### 上級評価

- [ ] 攻撃の時系列を説明できた
- [ ] ステルススキャン検知のカスタムルールを作成できた
- [ ] 新規ルールをテストできた
- [ ] SOCレポートを作成できた

→ **4項目すべてで合格**

---

## 参考資料

- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Suricata Rules Documentation](https://docs.suricata.io/en/latest/rules/)
- [MITRE ATT&CK T1595](https://attack.mitre.org/techniques/T1595/)

