# S9: L3 ICMP 到達性・偵察

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S9 |
| 攻撃名 | ICMP 到達性確認とホスト発見 |
| 主レイヤー | L3 |
| MITRE ATT&CK | Active Scanning (T1595) |
| 検知コンポーネント | Suricata |
| 難易度 | 初級 |

---

## 目的

ICMP echo、traceroute、host discovery を使い、IP レイヤーの到達性確認がどのように検知されるかを学びます。

## 攻撃手順

```bash
docker compose up -d
docker exec -it soc-lab-kali /bin/bash
/scripts/s9_l3_icmp_recon.sh
```

## ログ観測点

| レイヤー | ログ/コマンド | 確認内容 |
|----------|---------------|----------|
| L3 | `ping`, `traceroute` | 到達性、経路、遅延 |
| L3 | Suricata fast.log | `L3 ICMP` アラート |
| SIEM | Kibana Discover | `event.module:suricata AND rule.name:*L3*` |

## 成功判定

- [ ] `ping` の応答可否を説明できた
- [ ] ICMP アラートを Suricata で確認できた
- [ ] ICMP が無効な環境で代替確認に何を使うか説明できた
- [ ] 到達性問題とアプリ障害を切り分けられた

## 改善課題

- ICMP を完全遮断する前に、監視・運用で必要な通信を整理する
- 偵察検知の閾値を調整し、正常監視と攻撃を区別する

