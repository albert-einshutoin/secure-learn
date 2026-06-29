# S12: L6 TLS 可視性境界

## 概要

| 項目 | 内容 |
|------|------|
| シナリオID | S12 |
| 攻撃名 | TLS handshake boundary probe |
| 主レイヤー | L6 |
| MITRE ATT&CK | Network Sniffing / Encrypted Channel 理解 |
| 検知コンポーネント | Suricata, App Log |
| 難易度 | 中級 |

---

## 目的

HTTP サービスに TLS ClientHello を送り、暗号化・復号・終端位置が IDS の可視性に与える影響を理解します。このラボの NestJS App は平文 HTTP のため、TLS 接続は失敗するのが正しい結果です。

## 攻撃手順

```bash
docker compose up -d
docker exec -it soc-lab-kali /bin/bash
/scripts/s12_l6_tls_boundary.sh
```

## ログ観測点

| レイヤー | ログ/コマンド | 確認内容 |
|----------|---------------|----------|
| L6 | `openssl s_client` | TLS handshake が失敗する理由 |
| L7 | `curl -vk https://...` | 平文HTTPサービスへのHTTPSアクセス失敗 |
| 設計 | Suricata/Proxy | TLS 終端前後で見える情報の差 |

## 成功判定

- [ ] TLS ではないポートに TLS 接続した失敗を説明できた
- [ ] TLS 終端前の IDS が見られる情報と見られない情報を説明できた
- [ ] TLS 終端後に見るべきログを整理できた
- [ ] SNI、証明書、HTTP body の可視性の違いを説明できた

## 改善課題

- 本番相当では reverse proxy で TLS 終端し、証明書期限、SNI、HTTP access log を別々に監視する
- 暗号化通信の検査はプライバシー、法務、運用負荷を含めて判断する

