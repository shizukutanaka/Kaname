#!/usr/bin/env sh
# .husky/pre-commit
#
# コミット前に実行される自動チェック。
# 失敗するとコミットがブロックされる。

. "$(dirname -- "$0")/_/husky.sh"

set -e

echo "→ Pre-commit checks..."

# 1. フォーマットチェック
echo "  rustfmt..."
if ! cargo fmt --all --check; then
  echo "✗ Rust コードがフォーマットされていません。"
  echo "  実行: cargo fmt --all"
  exit 1
fi

# 2. Clippy (高速モード - 軽い警告のみ)
echo "  clippy..."
if ! cargo clippy --workspace --all-targets --quiet -- -D warnings; then
  echo "✗ Clippy 警告があります。"
  exit 1
fi

# 3. TypeScript 型チェック
if [ -f "package.json" ]; then
  echo "  typescript..."
  if ! npx tsc --noEmit; then
    echo "✗ TypeScript 型エラーがあります。"
    exit 1
  fi
fi

# 4. i18n キー一致検証
if [ -f "src/i18n/index.ts" ]; then
  echo "  i18n keys..."
  if ! npx tsx src/i18n/index.ts --validate 2>/dev/null; then
    echo "✗ i18n キーが言語間で不一致です。"
    exit 1
  fi
fi

# 5. AGPL ライセンスヘッダー検証 (新規 .rs ファイル)
echo "  license headers..."
new_rs_files=$(git diff --cached --diff-filter=A --name-only | grep '\.rs$' || true)
for f in $new_rs_files; do
  if [ -f "$f" ] && ! head -3 "$f" | grep -q "//"; then
    echo "  注意: $f にコメントヘッダーがありません"
  fi
done

# 6. 機密情報の検出 (簡易)
echo "  secret scan..."
staged=$(git diff --cached --name-only)
for f in $staged; do
  if [ -f "$f" ]; then
    # API キー / 秘密鍵 / パスワードのパターンを検出
    if git diff --cached "$f" | grep -E "^[+].*(api[_-]?key|secret[_-]?key|private[_-]?key|password)\s*=\s*['\"][^'\"]+['\"]" | grep -v "// example\|// test\|// mock"; then
      echo "✗ $f に機密情報の疑いがあります。コミットしないでください。"
      exit 1
    fi
  fi
done

# 7. デバッグコードの検出
echo "  debug code..."
if git diff --cached | grep -E "^[+].*(println!|console\.log|debugger|TODO|FIXME)" | grep -v "// allow"; then
  echo "  警告: デバッグコードまたは TODO が含まれています。"
  echo "  続行する場合は無視できます (git commit -n でスキップも可能)"
fi

echo "✓ All pre-commit checks passed"
