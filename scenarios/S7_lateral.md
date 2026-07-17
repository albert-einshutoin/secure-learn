# S7: Cross-Layer Incident

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S7 |
| 攻撃名 | Cross-Layer Incident |
| 主レイヤー | 全レイヤー |
| MITRE ATT&CK | T1595 Reconnaissance / T1110 Credential Access / T1190 Initial Access |
| 検知コンポーネント | Suricata, Fail2ban, Application logs, SIEM |
| 難易度 | 上級 |

---

## 概要

このシナリオは、one trust zoneの同じローカル対象に対して、偵察、認証試行、入力攻撃、負荷イベントを順番に発生させ、複数レイヤーのログを一つの時系列へ結びます。This is not an APT or lateral movement exercise. 別ホストへの侵入拡大や永続化が成立したと主張せず、成立したイベントと拒否されたイベントを証跡で区別します。

公開URLと既存利用者のコマンドを壊さないため、スクリプト名 `s7_lateral.sh` はcompatibility filenameとして維持しています。ファイル名は演習内容の分類を意味しません。

### 攻撃チェーン

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: Reconnaissance (S1)                               │
│   └─> Port Scan (nmap)                                     │
│       └─> Detected by: Suricata                            │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 2: Initial Access Attempt (S2)                       │
│   └─> Brute Force (hydra)                                  │
│       └─> Detected by: NestJS App, Fail2ban                │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 3: Exploitation (S3)                                 │
│   └─> SQL Injection (sqlmap)                               │
│       └─> Detected by: Suricata, NestJS App                │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 4: Path Traversal Attempt                            │
│   └─> Encoded file path requests                           │
│       └─> Detected by: Suricata, NestJS App                │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 5: Bounded High-Rate Requests                        │
│   └─> Local request burst                                  │
│       └─> Detected by: NestJS App, Fail2ban                │
└─────────────────────────────────────────────────────────────┘
```

---

## 攻撃手順

### 1. 環境の起動

```bash
# SOC-Lab環境を起動
docker compose up -d

# Kaliコンテナに接続
docker exec -it soc-lab-kali /bin/bash
```

### 2. 自動攻撃スクリプト実行

```bash
# 横断攻撃スクリプトを実行
/scripts/s7_lateral.sh
```

### 3. 手動実行（段階別）

#### Phase 1: Reconnaissance

```bash
# ポートスキャン
nmap -sS -p 1-1000 172.23.0.20
```

#### Phase 2: Credential Attack

```bash
# ブルートフォース
hydra -l admin -P /wordlists/passwords.txt \
  172.23.0.20 -s 3000 \
  http-post-form "/auth/login:username=^USER^&password=^PASS^:Invalid"
```

#### Phase 3: Exploitation

```bash
# SQLインジェクション
sqlmap -u "http://172.23.0.20:3000/users?id=1" --batch --level=3
```

#### Phase 4: Path Traversal Attempt

```bash
# 閉域の教材APIに対して、拒否される入力を送る
curl -H 'Host: app' 'http://172.23.0.20:3000/files/../../../etc/passwd'
```

---

## ログ観測点

| Phase | レイヤー | ログ | 確認内容 |
|-------|---------|------|---------|
| 1 | L3/L4 | Suricata | SCAN alerts |
| 2 | L7 | auth.log, Fail2ban | login_failed, Ban |
| 3 | L7 | Suricata, error.log | SQLI alerts |
| 4 | L7 | Suricata, error.log | path traversal attempt |
| 5 | L7 | access.log, Fail2ban | bounded request burst, rate limit |

---

## 成功判定表

| 判定項目 | 成功条件 | 検証方法 |
|---------|---------|---------|
| 複数レイヤー検知 | Suricata+Fail2ban+Application logsに関連イベント | 各ログファイル確認 |
| 時系列相関 | 同一IPの活動が追跡可能 | Kibana Timeline |
| 攻撃フロー可視化 | 攻撃進行が説明可能 | SOCダッシュボード |
| MTTD算出 | 各フェーズの検知時間測定 | タイムスタンプ比較 |
| MTTR算出 | 対応（BAN）までの時間測定 | タイムスタンプ比較 |

### 検証コマンド

```bash
# Suricataアラート確認
docker exec soc-lab-suricata cat /var/log/suricata/fast.log | wc -l
docker exec soc-lab-suricata cat /var/log/suricata/fast.log | tail -30

# Fail2ban確認
docker exec soc-lab-fail2ban fail2ban-client status

# アプリログ確認
docker exec soc-lab-app cat /var/log/app/auth.log | grep login_failed | wc -l
docker exec soc-lab-app cat /var/log/app/error.log | grep sqli | wc -l

# 同じsource.ipと時間帯のイベントを検索
docker exec soc-lab-app grep -E 'login_failed|sqli|path_traversal' /var/log/app/*.log
```

---

## 対応手順（Respond Runbook）

### 1. 初期確認

```bash
# 攻撃の検知確認
# Kibanaでクエリ: source.ip:<攻撃IP>
```

### 2. タイムライン作成

```markdown
| 時刻 | イベント | 検知ソース |
|------|---------|-----------|
| HH:MM:SS | Port Scan開始 | Suricata |
| HH:MM:SS | Brute Force開始 | NestJS |
| HH:MM:SS | BAN実行 | Fail2ban |
| HH:MM:SS | SQLi試行 | Suricata |
| ... | ... | ... |
```

### 3. 影響範囲評価

- 認証突破: あり/なし
- データアクセス: あり/なし
- 権限昇格: あり/なし
- データ改ざん: あり/なし

### 4. 封じ込め

```bash
# 攻撃IPの完全遮断
docker exec soc-lab-fail2ban fail2ban-client set nestjs-auth banip <IP>
docker exec soc-lab-fail2ban fail2ban-client set nestjs-sqli banip <IP>
docker exec soc-lab-fail2ban fail2ban-client set nestjs-dos banip <IP>
```

### 5. 恒久対策

- 認証rate limitとlockoutの回帰テスト
- SQLi/path traversalの入力検証と回帰テスト
- 検知閾値、ログ項目、runbookの改善

### 6. 復旧

- サービスの正常性確認
- 監視強化

### 7. 教訓

- インシデントレポート作成
- 検知ルールの改善
- プレイブックの更新

---

## KPI測定

### MTTD（Mean Time To Detect）

```
MTTD = 最初のアラート時刻 - 攻撃開始時刻

例:
- 攻撃開始: 10:00:00
- 最初のSuricataアラート: 10:00:05
- MTTD = 5秒
```

### MTTR（Mean Time To Respond）

```
MTTR = 対応完了時刻 - 最初のアラート時刻

例:
- 最初のアラート: 10:00:05
- Fail2ban BAN: 10:01:30
- MTTR = 85秒
```

### 検知率

```
検知率 = 検知されたフェーズ数 / 総フェーズ数 × 100

例:
- 総フェーズ: 5
- 検知フェーズ: 5
- 検知率 = 100%
```

---

## 評価チェックリスト

### 初級評価

- [ ] 複数攻撃を順番に実行できた
- [ ] 各レイヤーでログを確認できた
- [ ] Kibanaで相関検索ができた
- [ ] 攻撃元IPを追跡できた

→ **4項目中3項目以上で合格**

### 中級評価

- [ ] 攻撃の進行を時系列で説明できた
- [ ] 各検知ポイントの役割を説明できた
- [ ] 検知の抜け穴を特定できた
- [ ] 改善策を提案できた

→ **4項目中3項目以上で合格**

### 上級評価

- [ ] 攻撃チェーン全体を文書化できた
- [ ] SOCプレイブックを作成できた
- [ ] KPI（MTTD/MTTR）を算出できた
- [ ] 包括的なSOCレポートを作成できた

→ **4項目すべてで合格**

---

## 参考資料

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [NIST Incident Response](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)

