#!/bin/bash
# Validate generated scenario guides without requiring a browser runtime.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUIDE_DIR="$ROOT_DIR/docs/scenario-guides"

fail() {
  echo "scenario html check failed: $*" >&2
  exit 1
}

[[ -f "$GUIDE_DIR/assets/scenario.css" ]] || fail "missing assets/scenario.css"
[[ -f "$GUIDE_DIR/index.html" ]] || fail "missing index.html"
grep -q '<!doctype html>' "$GUIDE_DIR/index.html" || fail "index.html does not look like HTML"
grep -q '<html lang="ja">' "$GUIDE_DIR/index.html" || fail "index.html must declare Japanese language"
grep -q '<meta name="description"' "$GUIDE_DIR/index.html" || fail "index.html is missing meta description"
grep -q 'class="skip-link"' "$GUIDE_DIR/index.html" || fail "index.html is missing skip link"
grep -q '<h1>' "$GUIDE_DIR/index.html" || fail "index.html is missing h1"
grep -q '通信レイヤー共通図' "$GUIDE_DIR/index.html" || fail "index.html is missing protocol layer overview"
grep -q '実行型ラボ 15' "$GUIDE_DIR/index.html" || fail "index.html must disclose the runnable lab count"
grep -q 'ガイド型設計演習 18' "$GUIDE_DIR/index.html" || fail "index.html must disclose the guided exercise count"

grep -q ':focus-visible' "$GUIDE_DIR/assets/scenario.css" || fail "scenario.css is missing keyboard focus styles"
grep -q 'min-width: 0' "$GUIDE_DIR/assets/scenario.css" || fail "scenario.css is missing grid overflow containment"

scenario_pages=("$GUIDE_DIR"/s*.html)
[[ "${#scenario_pages[@]}" -ge 33 ]] || fail "expected at least 33 scenario pages, found ${#scenario_pages[@]}"

for file in "${scenario_pages[@]}"; do
  grep -q '<!doctype html>' "$file" || fail "$(basename "$file") does not look like HTML"
  grep -q '<html lang="ja">' "$file" || fail "$(basename "$file") must declare Japanese language"
  grep -q '<meta name="description"' "$file" || fail "$(basename "$file") is missing meta description"
  grep -q 'class="skip-link"' "$file" || fail "$(basename "$file") is missing skip link"
  grep -q '<h1>' "$file" || fail "$(basename "$file") is missing h1"
  grep -q '実行形式' "$file" || fail "$(basename "$file") is missing exercise type disclosure"
  grep -q '抽象的に何を学ぶか' "$file" || fail "$(basename "$file") is missing abstract concept"
  grep -q '具体例' "$file" || fail "$(basename "$file") is missing concrete examples"
  grep -q '初学者の見方' "$file" || fail "$(basename "$file") is missing beginner guidance"
  grep -q '経験者の深掘り' "$file" || fail "$(basename "$file") is missing experienced guidance"
  grep -q '学習フロー図' "$file" || fail "$(basename "$file") is missing learning diagram"
  grep -q '環境と証跡の図' "$file" || fail "$(basename "$file") is missing environment evidence diagram"
  grep -q 'OSI / HTTP / 到達前の図' "$file" || fail "$(basename "$file") is missing protocol layer diagram"
  grep -q 'HTTP通信の中の位置' "$file" || fail "$(basename "$file") is missing HTTP request anatomy"
  grep -q 'Server / Middleware 到達前後' "$file" || fail "$(basename "$file") is missing pre-app delivery map"
  grep -q '事前準備' "$file" || fail "$(basename "$file") is missing prerequisites"
  grep -q '安全境界' "$file" || fail "$(basename "$file") is missing safety boundary"
  grep -q 'Hands-on Flow' "$file" || fail "$(basename "$file") is missing hands-on flow"
  grep -q 'ツール活用' "$file" || fail "$(basename "$file") is missing tool guidance"
  grep -q '観測ポイント' "$file" || fail "$(basename "$file") is missing observation points"
  grep -q 'よくある失敗' "$file" || fail "$(basename "$file") is missing common mistakes"
  grep -q 'セルフレビュー' "$file" || fail "$(basename "$file") is missing self-review prompts"
  grep -q '合格証跡' "$file" || fail "$(basename "$file") is missing evidence criteria"
  grep -q '本番導入へ追加する課題' "$file" || fail "$(basename "$file") is missing production extension tasks"
done

grep -q 'href="s32-performance-flamegraph-db.html"' "$GUIDE_DIR/s33-gitops-progressive-delivery.html" \
  || fail "S33 should link to its adjacent prerequisite instead of generic early scenarios"

if grep -R -n -E 'TODO|TBD|PLACEHOLDER' "$GUIDE_DIR"; then
  fail "placeholder text remains in generated guides"
fi

echo "Scenario HTML check passed."
