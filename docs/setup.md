# セットアップガイド

## 前提条件

### システム要件

| 項目 | 最小 | 推奨 |
|------|------|------|
| CPU | 2コア | 4コア以上 |
| メモリ | 8GB | 16GB以上 |
| ディスク | 20GB | 50GB以上 |
| OS | Linux/macOS/Windows | Linux |

### 必要なソフトウェア

| ホストOS | 対応するローカル実行環境 | doctorが許可する接続先 |
|----------|--------------------------|------------------------|
| macOS | Docker Desktop 4.42.0以上を導入目安 | `desktop-linux` と `$HOME/.docker/run/docker.sock` |
| Windows | Docker Desktop 4.42.0以上を導入目安 | `desktop-linux` と `dockerDesktopLinuxEngine` named pipe |
| Linux | ローカルまたはrootless Docker Engine 20.10.0以上（API 1.41以上） | `/var/run/docker.sock` または実行ユーザーの `/run/user/<uid>/docker.sock` |

全OSでDocker Engine 20.10.0／API 1.41と正式版Docker Compose 2.36.0以上が必要です。Docker Desktop 4.42.0は対応Composeを同梱する導入目安であり、doctorはDesktop製品バージョンではなくEngine/APIとruntime capabilityを直接判定します。`interface_name` を解釈できないComposeではIDSの監視interfaceを決定できないため、doctorはバージョン番号、Compose設定の構文展開、一時コンテナ内で `eth0` / `eth1` が存在し `eth2` が存在しないことを実測します。一時projectは呼出ごとのランダム名で分離され、成功・失敗を問わず同じ完全一致名だけがcleanupされます。

`DOCKER_HOST` / `DOCKER_CONTEXT`、SSH、TCP、HTTP(S)、cloud context、列挙されていないUnix socket／named pipeはローカル教材の安全境界外であり、doctorが拒否します。POSIX socketは種別、所有者、modeも検査しますが、socket peerやDocker daemonの真正性を暗号学的にattestするものではありません。
- Git

## インストール

### 1. リポジトリのクローン

```bash
git clone https://github.com/albert-einshutoin/secure-learn.git
cd secure-learn
```

### 2. 環境変数の設定（オプション）

```bash
# .envファイルを作成
cp .env.example .env

# Slack通知を使用する場合
# SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### 3. Docker Composeで起動

```bash
# 現在のOSに対応するローカルengine、Compose、interface_nameを検査
scripts/learn doctor s1

# Phase 1: 基本環境
docker compose up -d --build

# 起動確認
docker compose ps
```

### 4. 自動初期化の確認

```bash
# Compose起動時にsiem-setupがtemplate、保持ポリシー、Kibana objectを投入
docker compose ps -a siem-setup
docker compose logs siem-setup
```

`siem-setup` が `Exited (0)` でなければ初期化は未完了です。手動importを成功条件にせず、原因を解消してserviceを再実行してください。

## Phase別起動

### Phase 1: 基本（IDS + SIEM）

```bash
docker compose up -d --build
```

### Phase 2: IPS + アラート

```bash
# IPS設定を追加
docker compose -f docker-compose.yml -f docker-compose.ips.yml up -d --build

# アラート設定を追加
docker compose -f docker-compose.yml -f docker-compose.alerting.yml up -d --build
```

### Phase 3: Red vs Blue 演習

```bash
# 演習環境を起動
docker compose --project-name secure-learn-exercise -f docker-compose.exercise.yml up -d --build --wait

# または演習スクリプトを使用
./scripts/start_exercise.sh
```

## 動作確認

### サービスの確認

```bash
# 全コンテナのステータス
docker compose ps

# 各サービスのログ
docker compose logs -f suricata
docker compose logs -f app
docker compose logs -f fail2ban
docker compose logs -f filebeat

# アプリのヘルスチェック
curl http://localhost:3000/health
```

### Kibanaへのアクセス

1. ブラウザで http://localhost:5601 を開く
2. "Discover" で `soc-lab-*` インデックスを確認
3. "Dashboard" で事前定義ダッシュボードを開く

### 攻撃テスト

```bash
# Kaliコンテナに接続
docker exec -it soc-lab-kali /bin/bash

# 簡単な攻撃テスト
nmap -sS -p 3000 app
curl http://app:3000/users?id=1
```

## トラブルシューティング

### Elasticsearchが起動しない

```bash
# メモリ不足の場合
sudo sysctl -w vm.max_map_count=262144

# 永続化
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### Filebeatがログを収集しない

```bash
# Filebeatログ確認
docker compose logs -f filebeat

# パーミッション確認
docker exec soc-lab-filebeat ls -la /var/log/suricata/
```

### Fail2banがBANしない

```bash
# Fail2banステータス確認
docker exec soc-lab-fail2ban fail2ban-client status

# ログ確認
docker exec soc-lab-fail2ban cat /var/log/fail2ban/fail2ban.log
```

## 停止・クリーンアップ

### 環境の停止

```bash
docker compose down
```

### データを含めて完全削除

```bash
docker compose down -v
```

### イメージも含めて削除

```bash
docker compose down -v --rmi all
```

## 次のステップ

1. [S1: ポートスキャン](../scenarios/S1_portscan.md) から始める
2. Kibanaダッシュボードで攻撃を観察
3. 評価チェックリストで自己評価

