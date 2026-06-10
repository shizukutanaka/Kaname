# Visual Regression Snapshots

## 現状

このディレクトリはスナップショット基準画像を格納する。
初回は CI 環境で自動生成される。

## 初回生成

```bash
# 1. JMAP モックサーバーを起動
cargo run -p kaname-mockserver --bin jmap-mock &

# 2. フロントエンドを起動
npm run dev &

# 3. スナップショットを生成 (初回は --update-snapshots が必要)
npx playwright test --update-snapshots

# 4. 生成されたスナップショットをコミット
git add e2e/__snapshots__/
git commit -m "test(e2e): initialize visual regression snapshots"
```

## 更新

UI を意図的に変更した場合:

```bash
# ブランチで更新
npx playwright test --update-snapshots
git add e2e/__snapshots__/
git commit -m "test(e2e): update snapshots for new design"
```

## CI での自動更新

GitHub Actions で `workflow_dispatch` → `update_snapshots: true` を設定して実行。

## 注意

スナップショットは OS・ブラウザ・解像度依存。
CI (Ubuntu 22.04 + Chromium) で生成した基準画像のみをコミットすること。
