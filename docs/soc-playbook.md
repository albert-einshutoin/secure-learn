# SOC Playbook

## 概要

このドキュメントはSOC-Labでのインシデント対応手順を定義します。

---

## KPI（Key Performance Indicators）

### 定義

| KPI | 定義 | 目標値 |
|-----|------|--------|
| MTTD (Mean Time To Detect) | 攻撃開始〜最初のアラート | < 5分 |
| MTTR (Mean Time To Respond) | アラート〜BAN/対応完了 | < 15分 |
| 検知率 | 検知された攻撃 / 全攻撃 | > 90% |
| 誤検知率 | 誤検知数 / 全アラート数 | < 10% |

### 算出方法

#### MTTD

```kql
# 特定IPの最初の攻撃イベントと最初の検知アラートの差分
source.ip: "<攻撃IP>" 
| stats min(@timestamp) as first_event by event.type
| where event.type == "alert"
```

#### MTTR

```kql
# 検知から対応（BAN）までの時間
source.ip: "<攻撃IP>"
| stats min(@timestamp) as first_alert WHERE event.type:alert
| stats min(@timestamp) as ban_time WHERE event.action:ban
| eval mttr = ban_time - first_alert
```

---

## インシデント対応フロー

### Phase 1: 検知（Detect）

```
┌─────────────────────────────────────────────┐
│ アラート発生                                 │
│ - Suricata: IDS/IPS alert                  │
│ - Fail2ban: IP banned                       │
│ - Auditd: Privilege escalation              │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│ 初期確認                                     │
│ - アラートタイプ確認                          │
│ - 攻撃元IP確認                               │
│ - 影響範囲の初期評価                          │
└─────────────────────────────────────────────┘
```

### Phase 2: 分析（Analyze）

```
質問項目：
- いつ（When）: 最初のイベント時刻
- 誰が（Who）: 攻撃元IP、ユーザー
- どこから（Where）: 攻撃経路
- 何を（What）: 攻撃タイプ、対象

確認コマンド：
# Kibanaで時系列確認
source.ip:<攻撃IP> | sort @timestamp asc

# Suricataアラート詳細
docker exec soc-lab-suricata jq 'select(.src_ip=="<攻撃IP>")' /var/log/suricata/eve.json

# 認証ログ確認
docker exec soc-lab-app grep "<攻撃IP>" /var/log/app/auth.log
```

### Phase 3: 対応（Respond）

#### 自動対応（既に実施済みの場合）

- Fail2ban: 自動BAN
- Suricata IPS: パケットDROP

#### 手動対応

```bash
# 追加のIPブロック
docker exec soc-lab-fail2ban fail2ban-client set nestjs-auth banip <IP>

# 永続BAN（jail.localに追加）
echo "<IP>" >> /etc/fail2ban/jail.d/permanent-bans.conf

# アカウントロック（必要な場合）
# アプリ側でユーザーを無効化
```

### Phase 4: 報告（Report）

#### 報告テンプレート

```markdown
# インシデントレポート

## 概要
- 日時: 
- インシデントタイプ:
- 重大度: 

## タイムライン
| 時刻 | イベント |
|------|---------|
| HH:MM | 攻撃開始 |
| HH:MM | 検知 |
| HH:MM | 対応完了 |

## 影響
- 影響を受けたシステム:
- データ漏洩: あり/なし
- サービス中断: あり/なし

## 対応
- 実施した対応:
- 対応者:

## 根本原因
-

## 再発防止策
-
```

### Phase 5: 改善（Improve）

- 検知ルールの見直し
- 閾値の調整
- ダッシュボードの更新
- プレイブックの更新

---

## シナリオ別対応手順

### S1: ポートスキャン

1. Suricataアラート確認
2. 攻撃元IP特定
3. 脅威インテリジェンスでIP評価
4. 必要に応じてブロック

### S2: ブルートフォース

1. auth.logで失敗回数確認
2. Fail2ban BANステータス確認
3. 対象アカウントの確認
4. パスワードリセット検討

### S3: SQLインジェクション

1. Suricata SQLI アラート確認
2. 攻撃対象エンドポイント特定
3. データベース整合性確認
4. 脆弱性修正の優先対応

### S4: DoS攻撃

1. トラフィック量確認
2. 正当なトラフィックか判断
3. レート制限発動確認
4. 必要に応じてWAF/CDN対応

### S5: ファイル改変

1. Auditdログで変更確認
2. 変更内容の確認
3. 変更者の特定
4. ロールバック判断

### S6: 権限昇格

1. Auditdで権限昇格確認
2. 正当な操作か確認
3. 不正の場合セッション終了
4. アカウントロック

---

## エスカレーション基準

| 重大度 | 条件 | エスカレーション先 |
|--------|------|------------------|
| Critical | データ漏洩、システム侵害 | CSIRT、経営層 |
| High | 攻撃成功、サービス影響 | セキュリティチームリーダー |
| Medium | 検知されたが阻止済み | チーム内共有 |
| Low | 偵察行為のみ | 記録のみ |

---

## 連絡先

| 役割 | 連絡先 |
|------|--------|
| SOCリーダー | soc-leader@example.com |
| CSIRTチーム | csirt@example.com |
| システム管理者 | sysadmin@example.com |

---

## 改訂履歴

| 日付 | バージョン | 変更内容 |
|------|----------|---------|
| 2024-01-01 | 1.0 | 初版作成 |

