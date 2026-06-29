# S14: SRE インシデント対応

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S14 |
| 攻撃名 | SLO degradation and incident response |
| 主レイヤー | 横断/SRE |
| MITRE ATT&CK | Impact / Service Degradation |
| 検知コンポーネント | Health check, Suricata, Fail2ban, Kibana |
| 難易度 | 上級 |

---

## 目的

攻撃検知を SRE の可用性判断に接続します。`/health`、レイテンシ、Compose 状態、アラートを合わせて、顧客影響と対応優先度を判断します。

## 手順

```bash
docker compose up -d
scripts/sre_smoke.sh
docker exec -it soc-lab-kali /bin/bash
/scripts/s4_dos.sh
exit
scripts/sre_smoke.sh
```

## 観測点

| 観点 | コマンド/ログ | 判断 |
|------|---------------|------|
| 可用性 | `scripts/sre_smoke.sh` | health とレイテンシが SLO 内か |
| 防御 | `fail2ban-client status` | BAN が発生したか |
| 検知 | Suricata/Kibana | DOS/SCAN/SQLI などのアラート有無 |
| 影響 | access.log/error.log | 正常ユーザーへの影響 |

## 成功判定

- [ ] 攻撃前後の health/SLO 差分を記録した
- [ ] MTTD と MTTR を算出した
- [ ] 暫定対応と恒久対応を分けて説明した
- [ ] インシデントレポートを作成した

## 改善課題

- SLO を `availability >= 99.9%`、`p95 latency < 500ms` のように明文化する
- アラート疲れを避けるため、ページング条件とチケット条件を分ける

