# S11: L5 セッション圧迫

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S11 |
| 攻撃名 | Incomplete HTTP session pressure |
| 主レイヤー | L5 |
| MITRE ATT&CK | Endpoint Denial of Service (T1499) |
| 検知コンポーネント | Suricata, App Log |
| 難易度 | 中級 |

---

## 目的

少数の不完全な HTTP セッションを保持し、接続維持・タイムアウト・リソース消費を観測します。大量負荷ではなく、セッション管理の理解を目的に安全な既定値にしています。

## 攻撃手順

```bash
docker compose up -d
docker exec -it soc-lab-kali /bin/bash
/scripts/s11_l5_session_stress.sh
```

## ログ観測点

| レイヤー | ログ/コマンド | 確認内容 |
|----------|---------------|----------|
| L5 | `nc` session | 接続保持時間 |
| L4/L5 | Suricata fast.log | session pressure / DOS 系アラート |
| SRE | `/health` | レイテンシと可用性 |

## 成功判定

- [ ] 不完全なセッションを安全な件数で生成できた
- [ ] セッション圧迫時も `/health` を確認できた
- [ ] タイムアウト、connection limit、rate limit の違いを説明できた
- [ ] SLO 影響の有無を記録できた

## 改善課題

- reverse proxy を置く場合の keepalive timeout / header timeout を設計する
- アプリ、proxy、IDS のどこで検知・制限するのが妥当か比較する

