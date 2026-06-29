# S10: L4 TCP 状態・フラグ異常

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S10 |
| 攻撃名 | TCP flag scan / connection state 観測 |
| 主レイヤー | L4 |
| MITRE ATT&CK | Active Scanning (T1595) |
| 検知コンポーネント | Suricata |
| 難易度 | 中級 |

---

## 目的

SYN、connect、FIN、NULL、XMAS の違いを観測し、L4 の状態がポート露出と検知にどう現れるかを理解します。

## 攻撃手順

```bash
docker compose up -d
docker exec -it soc-lab-kali /bin/bash
/scripts/s10_l4_tcp_state.sh
```

## ログ観測点

| レイヤー | ログ/コマンド | 確認内容 |
|----------|---------------|----------|
| L4 | `nmap -sS/-sT/-sF/-sN/-sX` | TCP flags と結果差分 |
| L4 | Suricata fast.log | `L4` または `SCAN` アラート |
| L7 | App access.log | connect scan がアプリまで到達したか |

## 成功判定

- [ ] SYN scan と connect scan の違いを説明できた
- [ ] FIN/NULL/XMAS が IDS で検知される理由を説明できた
- [ ] オープンポートと閉じたポートの応答差を確認できた
- [ ] L4 の遮断が L7 の可用性に与える影響を説明できた

## 改善課題

- 露出ポートを最小化する Compose/Firewall 設計を提案する
- 検知閾値を正常なヘルスチェックや監視通信と衝突しない値に調整する

