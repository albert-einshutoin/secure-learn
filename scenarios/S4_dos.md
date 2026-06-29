# S4: DoS攻撃

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S4 |
| 攻撃名 | DoS攻撃（Denial of Service） |
| 主レイヤー | L7 |
| MITRE ATT&CK | Impact - Endpoint Denial of Service (T1499) |
| 検知コンポーネント | Suricata, NestJS App, Fail2ban |
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
/scripts/s4_dos.sh

# または手動で実行
for i in {1..1000}; do curl -s http://app:3000/ &; done
```

### 3. 攻撃バリエーション

| 攻撃タイプ | コマンド | 特徴 |
|-----------|---------|------|
| HTTP Flood | `for i in {1..1000}; do curl -s http://app:3000/ &; done` | 大量リクエスト |
| Slowloris | `slowloris -p 3000 app` | 接続維持型 |
| SYN Flood | `hping3 -S --flood -p 3000 app` | L4攻撃 |
| Apache Bench | `ab -n 10000 -c 100 http://app:3000/` | ベンチマークツール |

---

## ログ観測点

| レイヤー | ログファイル | 確認内容 |
|---------|-------------|---------|
| L7 | `/var/log/suricata/eve.json` | alert.signature: "DOS" |
| L7 | NestJSログ | HTTP 429応答 |
| L7 | `/var/log/fail2ban/fail2ban.log` | Ban <IP> |

---

## 成功判定表

| 判定項目 | 成功条件 | 検証方法 |
|---------|---------|---------|
| Suricata検知 | `DOS`アラート発生 | `grep "DOS" eve.json` |
| レート制限発動 | HTTP 429返却 | `curl -w "%{http_code}" http://<ip>:3000/` |
| Fail2ban BAN | 高頻度アクセスでBAN | `fail2ban-client status nestjs-dos` |
| サービス継続 | 攻撃後もサービス応答 | `curl http://<ip>:3000/` |

### 検証コマンド

```bash
# Suricataアラート確認
docker exec soc-lab-suricata grep DOS /var/log/suricata/fast.log

# レート制限確認
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/

# Fail2ban状態確認
docker exec soc-lab-fail2ban fail2ban-client status nestjs-dos

# サービス状態確認
docker exec soc-lab-app curl -s http://localhost:3000/
```

---

## 対応手順（Respond Runbook）

### 1. 検知確認

```bash
# トラフィック急増確認
docker exec soc-lab-suricata grep DOS /var/log/suricata/fast.log | wc -l
```

### 2. 攻撃元特定

```bash
# Top攻撃元IP
docker exec soc-lab-app cat /var/log/app/access.log | jq -r '.["source.ip"]' | sort | uniq -c | sort -rn | head -10
```

### 3. 判断

| 状況 | 判断 | 対応 |
|------|------|------|
| キャンペーン等の正当トラフィック | 正常 | スケーリング検討 |
| 単一IPからの異常トラフィック | 攻撃 | IP遮断 |
| 分散攻撃（DDoS） | 攻撃 | CDN/WAFで吸収 |

### 4. 対応

```bash
# 攻撃元IPをBAN
docker exec soc-lab-fail2ban fail2ban-client set nestjs-dos banip <攻撃IP>

# 緊急時：レート制限強化
# app/src/main.tsのmax値を下げる
```

### 5. 事後対応

- レート制限閾値の見直し
- CDN導入検討
- オートスケーリング設計

---

## 改善点

| 項目 | 改善内容 |
|------|---------|
| レート制限調整 | ビジネス要件に合わせて閾値最適化 |
| CDN導入 | CloudflareやAWS CloudFrontで吸収 |
| WAF | AWS WAF/ModSecurityでレート制限 |
| オートスケーリング | 負荷に応じたスケールアウト |

---

## 評価チェックリスト

### 初級評価

- [ ] 高頻度リクエストを送信できた
- [ ] HTTP 429（レート制限）を確認できた
- [ ] Suricataログでアラートを確認できた
- [ ] Kibanaでイベントを検索できた

→ **4項目中3項目以上で合格**

### 中級評価

- [ ] レート制限を回避する方法を特定できた
- [ ] express-rate-limitの設定を調整できた
- [ ] Fail2banのDoS用jail設定を最適化できた
- [ ] 変更の影響範囲を説明できた

→ **4項目中3項目以上で合格**

### 上級評価

- [ ] DDoS対策アーキテクチャを説明できた
- [ ] CDN/WAF連携の設計ができた
- [ ] オートスケーリング戦略を文書化できた
- [ ] SOCレポートを作成できた

→ **4項目すべてで合格**

---

## 参考資料

- [OWASP DoS Guide](https://owasp.org/www-community/attacks/Denial_of_Service)
- [express-rate-limit](https://www.npmjs.com/package/express-rate-limit)
- [MITRE ATT&CK T1499](https://attack.mitre.org/techniques/T1499/)
- [AWS DDoS Best Practices](https://docs.aws.amazon.com/whitepapers/latest/aws-best-practices-ddos-resiliency/)

