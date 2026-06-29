# S13: L7 DNS 観測

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S13 |
| 攻撃名 | Docker DNS service discovery observation |
| 主レイヤー | L7 |
| MITRE ATT&CK | Remote System Discovery (T1018) |
| 検知コンポーネント | Docker DNS, resolver configuration |
| 難易度 | 初級 |

---

## 目的

Docker Compose のサービス名解決を観測し、DNS がアプリケーション層のサービス発見としてどのように使われるかを理解します。

## 攻撃手順

```bash
docker compose up -d
docker exec -it soc-lab-kali /bin/bash
/scripts/s13_l7_dns_observe.sh
```

## ログ観測点

| レイヤー | ログ/コマンド | 確認内容 |
|----------|---------------|----------|
| L7 | `getent hosts`, `dig` | service name と IP |
| L7 | `/etc/resolv.conf` | Docker embedded DNS |
| L7 | `/etc/resolv.conf` | Docker embedded DNS が 127.0.0.11 で動くこと |

## 成功判定

- [ ] `app` の名前解決結果を確認できた
- [ ] Docker DNS の nameserver を説明できた
- [ ] Docker embedded DNS は Suricata の eth0 では安定観測できない理由を説明できた
- [ ] DNS クエリが偵察や横展開の入口になる理由を説明できた
- [ ] DNS ログを長期保全する価値を説明できた

## 改善課題

- 内部DNSログを SIEM に入れる運用設計を提案する
- service discovery の異常を検知する KQL を作成する
