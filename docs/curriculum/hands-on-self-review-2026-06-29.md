# Hands-on HTML Self Review - 2026-06-29

## 判定

Secure Learn は、S1-S33 のシナリオHTMLと P0-P19 のLearning Phase HTMLにより、ホワイトハット、SRE、バックエンド、検知、Cloud/IaC、Supply Chain、OSS governanceを順番に学べる状態です。

ただし再レビュー時点では、初学者が安全に手を動かすための「事前準備」「安全境界」「観測ポイント」「よくある失敗」「セルフレビュー」が全ページで明示されていませんでした。内容は揃っていても、実務で必要な再現性、安全範囲、失敗時の切り分け、第三者レビュー可能性をHTMLだけで追うには不足がありました。

## 足りていたもの

- 抽象説明と具体例があり、単なるコマンド集ではなく判断軸を学べる。
- シナリオごとにHands-on Flow、ツール活用、合格証跡、世界レベルへ足す課題がある。
- Learning PhaseごとにDocker profile、実行コマンド、合格証跡、次フェーズ判定がある。
- `scripts/scenario_html_check.sh`、`scripts/learning_phase_check.sh`、`scripts/world_class_curriculum_check.sh` で生成HTMLを検証している。

## 不足していたもの

- 事前準備: Docker、profile、対象範囲、前フェーズ証跡の確認がHTML上で明示されていなかった。
- 安全境界: 第三者環境、公共IP、実cloud、BGP/CDN、負荷試験、危険payloadをどこまで禁止するかがページ単位で弱かった。
- 観測ポイント: HTTP status、ログ、検知イベント、メトリクス、テスト結果のどれで判断するかが初学者に見えづらかった。
- よくある失敗: 攻撃成功と防御成功の混同、timestamp/source不足、設計だけで完了扱いにする問題が明示されていなかった。
- セルフレビュー: 守る資産、失敗条件、本番追加統制、owner、rollbackを自問する導線が不足していた。

## 拡充方針

全シナリオHTMLと全フェーズHTMLに、次の共通セクションを追加します。

- 事前準備
- 安全境界
- 観測ポイント
- よくある失敗
- セルフレビュー

これにより、ユーザーは各ページを上から順に読み、開始前の安全確認、実行、観測、証跡化、自己評価までを同じ流れで進められます。

## 実務レベルへの注意

このリポジトリは安全なローカル/コンテナ教材です。実cloud account、production-like telemetry、商用EDR、実BGP/CDN、組織のincident commandやchange advisory processは、許可された実務環境またはsandboxで追加訓練が必要です。

教材内では危険な操作を外部に向けず、設計レビュー、サンプルログ、ローカル検証、tabletop exerciseとして扱います。これは弱点ではなく、OSS教材として安全に配布するための境界です。

## 完成判定

この自己レビューで追加した導線は、次のチェックで守ります。

```bash
node scripts/generate_scenario_html.js
node scripts/generate_learning_phase_html.js
scripts/scenario_html_check.sh
scripts/learning_phase_check.sh
scripts/world_class_curriculum_check.sh
scripts/world_class_hands_on_check.sh all
```
