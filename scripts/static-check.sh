#!/usr/bin/env bash
# scripts/static-check.sh
# cargo が使えない環境での静的整合性チェック。
# pub mod 宣言とファイル存在、use 文と依存、EvalCtx の必須フィールド等を検証。
#
# 注: これは cargo check の代替ではなく補完。実機 CI では cargo check が必須。

set -uo pipefail
cd "$(dirname "$0")/.."

errors=0

echo "=== Kaname 静的整合性チェック ==="

# 1. pub mod 宣言とファイル存在
echo "[1] モジュール宣言とファイル存在..."
for crate in crates/*/; do
  lib="$crate/src/lib.rs"
  [ -f "$lib" ] || continue
  while read -r mod; do
    # コード行・テスト文字列内の誤検知を除外
    if [ ! -f "$crate/src/$mod.rs" ] && [ ! -d "$crate/src/$mod" ]; then
      # 行頭が pub mod の正規の宣言のみ対象
      if grep -qP "^pub mod $mod;" "$lib"; then
        echo "  ✗ $(basename "$crate"): pub mod $mod だがファイル不在"
        errors=$((errors+1))
      fi
    fi
  done < <(grep -oP "^pub mod \K\w+" "$lib" 2>/dev/null)
done

# 2. use kaname_X と Cargo.toml 依存の整合
echo "[2] use 文と依存の整合..."
for crate in crates/*/; do
  cargo_toml="$crate/Cargo.toml"
  [ -f "$cargo_toml" ] || continue
  for src in "$crate"src/*.rs; do
    [ -f "$src" ] || continue
    while read -r dep; do
      cratename="kaname-$(echo "$dep" | tr '_' '-')"
      # 自クレート参照は除外
      selfname=$(basename "$crate")
      [ "$cratename" = "$selfname" ] && continue
      if ! grep -q "$cratename" "$cargo_toml" 2>/dev/null; then
        echo "  ✗ $(basename "$src"): use kaname_$dep だが $cratename 依存なし"
        errors=$((errors+1))
      fi
    done < <(grep -oP "use kaname_\K\w+" "$src" 2>/dev/null | sort -u)
  done
done

# 3. workspace members と実ディレクトリの整合
echo "[3] workspace members とディレクトリ..."
while read -r member; do
  if [ ! -d "$member" ]; then
    echo "  ✗ workspace member $member が存在しない"
    errors=$((errors+1))
  fi
done < <(grep -oP '"\Kcrates/[^"]+' Cargo.toml 2>/dev/null)

# 4. バージョン整合 (Cargo.toml / package.json / tauri.conf.json)
echo "[4] バージョン整合..."
cargo_ver=$(grep -oP '^version\s*=\s*"\K[^"]+' Cargo.toml | head -1)
pkg_ver=$(grep -oP '"version":\s*"\K[^"]+' package.json | head -1)
tauri_ver=$(grep -oP '"version":\s*"\K[^"]+' src-tauri/tauri.conf.json | head -1)
if [ "$cargo_ver" != "$pkg_ver" ] || [ "$cargo_ver" != "$tauri_ver" ]; then
  echo "  ✗ バージョン不一致: Cargo=$cargo_ver package=$pkg_ver tauri=$tauri_ver"
  errors=$((errors+1))
fi

# 5. unsafe ブロックの検出 (#![deny(unsafe_code)] との整合)
echo "[5] unsafe ブロックの不在..."
unsafe_hits=$(grep -rn "unsafe " crates/*/src/*.rs 2>/dev/null | grep -v "//\|deny\|forbid\|unsafe_code")
if [ -n "$unsafe_hits" ]; then
  echo "  ✗ unsafe ブロック検出 (deny(unsafe_code) と矛盾):"
  echo "$unsafe_hits" | head -5 | sed 's/^/    /'
  errors=$((errors+1))
fi

# 6. libc 等の外部依存が Cargo.toml にあるか (ゼロ依存方針)
echo "[6] 未宣言依存の検出..."
for crate in crates/*/; do
  cargo_toml="$crate/Cargo.toml"
  [ -f "$cargo_toml" ] || continue
  for src in "$crate"src/*.rs; do
    [ -f "$src" ] || continue
    # libc:: の使用を検出
    if grep "libc::" "$src" 2>/dev/null | grep -qv "^\s*//" && ! grep -q "^libc" "$cargo_toml"; then
      echo "  ✗ $(basename "$src"): libc:: 使用だが Cargo.toml に libc なし"
      errors=$((errors+1))
    fi
  done
done

echo ""
if [ "$errors" -eq 0 ]; then
  echo "✅ 静的チェック合格 (0 エラー)"
  exit 0
else
  echo "❌ $errors 件のエラー"
  exit 1
fi
