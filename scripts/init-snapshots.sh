#!/usr/bin/env bash
# scripts/init-snapshots.sh
# E2E 視覚的回帰テストの基準画像を生成する。
#
# 初回セットアップ、または意図的な UI 変更後に実行。
# このスクリプトはローカル環境または CI で実行し、
# 生成されたスナップショットを git commit する。
#
# 前提条件:
#   - npm run dev (フロントエンド) が起動していること
#   - cargo run -p kaname-mockserver --bin jmap-mock が起動していること
#   - npx playwright install を実行済みであること

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "=== Kaname E2E スナップショット初期化 ==="
echo ""
echo "[1] モックサーバーを起動..."
cargo run -p kaname-mockserver --bin jmap-mock &
MOCK_PID=$!
trap "kill $MOCK_PID 2>/dev/null" EXIT

echo "[2] フロントエンドをビルド..."
npm run build

echo "[3] スナップショットを生成 (--update-snapshots)..."
npx playwright test \
  e2e/north-star-demo.spec.ts \
  --project="Chromium (Desktop)" \
  --update-snapshots

echo ""
echo "[4] 生成されたスナップショット:"
find e2e/__snapshots__ -name "*.png" | while read f; do
  echo "  $f ($(wc -c < "$f") bytes)"
done

echo ""
echo "完了。以下のコマンドで変更をコミットしてください:"
echo "  git add e2e/__snapshots__/"
echo "  git commit -m 'test(e2e): update visual snapshots'"
