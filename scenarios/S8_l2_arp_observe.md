# S8: L2 ARP 観測

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S8 |
| 攻撃名 | ARP/Neighbor Cache 観測 |
| 主レイヤー | L2 |
| MITRE ATT&CK | Reconnaissance - Network Service Discovery (T1046) |
| 検知コンポーネント | Linux neighbor cache, Suricata flow（補助） |
| 難易度 | 初級 |

---

## 目的

Docker bridge 上で ARP と neighbor cache を観測し、L2 の事象が L3/L4 以降の到達性にどう影響するかを理解します。実ネットワークでの ARP spoofing は第三者環境に影響するため、このラボでは観測と検知に限定します。

## 攻撃手順

```bash
docker compose up -d
docker exec -it soc-lab-kali /bin/bash
/scripts/s8_l2_arp_observe.sh
```

## ログ観測点

| レイヤー | ログ/コマンド | 確認内容 |
|----------|---------------|----------|
| L2 | `ip neigh show` | IP と MAC の対応 |
| L2 | `arping` 出力 | ARP reply の有無 |
| L2/L3 | `/var/log/suricata/eve.json` | flow イベント（環境によりARPは未出力） |

## 成功判定

- [ ] `app` の IP が neighbor cache に登録された
- [ ] ARP の応答元を説明できた
- [ ] Suricata で関連する flow イベント、または neighbor cache の変化を確認できた
- [ ] 実ネットワークで ARP spoofing を実行してはいけない理由を説明できた

## 改善課題

- 重要セグメントでは ARP だけに依存せず、スイッチの DHCP snooping / Dynamic ARP Inspection を検討する
- Docker ラボで見えない物理スイッチ側の証跡を、実運用ならどの機器で取るか整理する
