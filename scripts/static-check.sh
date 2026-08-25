#!/usr/bin/env bash
# scripts/static-check.sh
#
# cargo check が使えない環境向けの静的検証。
#
# 組織のエグレスポリシーにより static.crates.io が遮断されており
# (docs/gap-analysis.md D20)、依存を取得できないため cargo check /
# cargo test が一切実行できない。型検査・借用検査の代わりにはならないが、
# 「構文エラー」と「定義が消えた関数の呼び出し」は検出できる。
#
# PR #70 の回帰 (analyze_body_risks の定義ごと削除され、呼び出しだけが
# 残ってコンパイルエラーになったまま 5 PR 気付かなかった) を受けて追加。
#
# 使い方: ./scripts/static-check.sh
# 終了コード: 0 = 問題なし / 1 = 要修正

set -uo pipefail
cd "$(dirname "$0")/.."

# rustup プロキシは rust-toolchain.toml の取得で失敗するため、
# インストール済みツールチェーンの rustc を直接使う。
RUSTC=""
for c in "$HOME"/.rustup/toolchains/*/bin/rustc; do
  [ -x "$c" ] && RUSTC="$c" && break
done
if [ -z "$RUSTC" ]; then
  echo "rustc が見つかりません (~/.rustup/toolchains/*/bin/rustc)" >&2
  exit 1
fi
echo "rustc: $("$RUSTC" --version)"

fail=0

echo ""
echo "== 1. 構文チェック (全 Rust ファイル) =="
# 単体コンパイルでは依存が解決できないため、パース段階のエラーのみを見る。
while IFS= read -r f; do
  out=$("$RUSTC" --edition 2021 --crate-type lib --emit=metadata -o /dev/null "$f" 2>&1 \
        | grep -E "^error: (expected|unexpected|unclosed|mismatched|missing|this file contains an unclosed)" | head -3)
  if [ -n "$out" ]; then
    echo "  NG $f"
    echo "$out" | sed 's/^/      /'
    fail=1
  fi
done < <(find crates src-tauri -name '*.rs' -not -path '*/target/*')
[ "$fail" -eq 0 ] && echo "  OK: 構文エラーなし"

echo ""
echo "== 2. 定義が存在しないローカル関数の呼び出し =="
# 各ファイル内で `fn name(` が定義され、かつ同ファイル内で呼ばれている前提の
# ローカルヘルパーについて、定義の消失を検出する。
while IFS= read -r f; do
  # `foo(` の形で呼ばれているシンボルのうち、既知のマクロ・メソッド呼び出しを除外
  while IFS= read -r sym; do
    [ -z "$sym" ] && continue
    # 同ファイルに定義があるか
    if ! grep -qE "(^|\s)fn ${sym}\b" "$f"; then
      # 他クレート/std 由来なら :: か . の直後にあるはず。ローカル呼び出しのみ拾う
      if grep -vE '^\s*(//|\*)' "$f" | grep -qE "(^|[^a-zA-Z0-9_:.])${sym}\("; then
        echo "  NG $f: ${sym}() を呼んでいるが定義が見つからない"
        fail=1
      fi
    fi
  done < <(grep -vE '^\s*(//|\*)' "$f" \
           | grep -oP '(?<![a-zA-Z0-9_:.])\b(analyze_body_risks|scan_dlp_inbound|map_auth|extract_urls_from_text|url_host|evaluate_link_risks|assess_row_verdict|mock_emails|not_wired)(?=\()' 2>/dev/null | sort -u)
done < <(find crates src-tauri -name '*.rs' -not -path '*/target/*')
[ "$fail" -eq 0 ] && echo "  OK: 未定義のローカル関数呼び出しなし"

echo ""
if [ "$fail" -eq 0 ]; then
  echo "静的検証: 問題なし"
  echo "注意: これは cargo check の代替ではない。型検査・借用検査・"
  echo "      正規表現の実コンパイル・テストの成否は依然として未検証。"
else
  echo "静的検証: 要修正あり"
fi
exit "$fail"
