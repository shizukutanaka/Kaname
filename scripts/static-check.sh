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
echo "== 3. フロントエンド到達可能性 (src/main.tsx からの import 閉包) =="
python3 - <<'PY' || fail=1
import re, os, glob, sys
files = {os.path.relpath(f): open(f).read()
         for f in glob.glob('src/**/*.tsx', recursive=True) + glob.glob('src/**/*.ts', recursive=True)
         if '__tests__' not in f}
def imports(cur):
    out = set()
    for m in re.findall(r'from\s+"(\.[^"]+)"', files[cur]):
        base = os.path.normpath(os.path.join(os.path.dirname(cur), m))
        for ext in ('.tsx', '.ts', '/index.tsx', '/index.ts'):
            if base + ext in files:
                out.add(base + ext)
    return out
seen, stack = set(), ['src/main.tsx']
while stack:
    cur = stack.pop()
    if cur in seen or cur not in files: continue
    seen.add(cur); stack += list(imports(cur))
dead = sorted(set(files) - seen)
print(f"  到達可能: {len(seen)}/{len(files)}")
for d in dead:
    print(f"  NG {d}: src/main.tsx から到達できない (死蔵コード)")
sys.exit(1 if dead else 0)
PY
[ "$fail" -eq 0 ] && echo "  OK: 死蔵しているフロントエンドモジュールなし"

echo ""
echo "== 4. invoke とTauriコマンドの整合 (名前・引数) =="
python3 - <<'PY' || fail=1
import re, os, glob, sys
files = {os.path.relpath(f): open(f).read()
         for f in glob.glob('src/**/*.tsx', recursive=True) + glob.glob('src/**/*.ts', recursive=True)
         if '__tests__' not in f}
def imports(cur):
    out = set()
    for m in re.findall(r'from\s+"(\.[^"]+)"', files[cur]):
        base = os.path.normpath(os.path.join(os.path.dirname(cur), m))
        for ext in ('.tsx', '.ts', '/index.tsx', '/index.ts'):
            if base + ext in files: out.add(base + ext)
    return out
seen, stack = set(), ['src/main.tsx']
while stack:
    cur = stack.pop()
    if cur in seen or cur not in files: continue
    seen.add(cur); stack += list(imports(cur))

main_rs = open('src-tauri/src/main.rs').read()
reg = set(re.findall(r'^\s*([a-z_][a-z0-9_]*),\s*$', 
          main_rs[main_rs.index('generate_handler!['):main_rs.index('generate_handler![')+3000], re.M))
# fn シグネチャからパラメータ名を集める
sigs = {}
for m in re.finditer(r'(?:async\s+)?fn\s+([a-z_][a-z0-9_]*)\s*\(([^)]*)\)', main_rs):
    params = set(re.findall(r'([a-z_][a-z0-9_]*)\s*:', m.group(2)))
    sigs[m.group(1)] = params

def camel_to_snake(k):
    return re.sub(r'(?<!^)(?=[A-Z])', '_', k).lower()

bad = 0
for f in sorted(seen):
    src = files[f]
    for m in re.finditer(r'invoke(?:<[^>]*>)?\s*\(\s*"([a-z_]+)"\s*(,\s*\{)?', src):
        line_start = src.rfind('\n', 0, m.start()) + 1
        line = src[line_start:src.find('\n', m.start())]
        if line.lstrip().startswith('//') or line.lstrip().startswith('*'):
            continue
        name = m.group(1)
        if name not in reg:
            print(f"  NG {f}: invoke(\"{name}\") が generate_handler! に未登録")
            bad = 1; continue
        if not m.group(2):
            continue
        # 引数オブジェクトのトップレベルキーを取る
        depth, i = 0, src.index('{', m.end() - 1)
        start = i
        while i < len(src):
            if src[i] == '{': depth += 1
            elif src[i] == '}':
                depth -= 1
                if depth == 0: break
            i += 1
        obj = src[start+1:i]
        keys = set()
        d = 0
        # `key: value` と shorthand `key` の両方を拾う
        for km in re.finditer(r'([{}\[\]()]|(?:^|,)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(?=:|,|$))', obj, re.M):
            t = km.group(1)
            if t in '{[(': d += 1
            elif t in '}])': d -= 1
            elif km.group(2) and d == 0: keys.add(camel_to_snake(km.group(2)))
        expected = sigs.get(name)
        if expected is None: continue
        missing, extra = expected - keys, keys - expected
        if missing or extra:
            print(f"  NG {f}: invoke(\"{name}\") の引数不一致 "
                  f"(不足={sorted(missing) or '-'} 余剰={sorted(extra) or '-'})")
            bad = 1
if not bad: print("  検査した invoke はすべて登録済みで引数も一致")
sys.exit(bad)
PY
[ "$fail" -eq 0 ] && echo "  OK: invoke とコマンド定義が整合"

echo ""
echo "== 5. 登録済みだが到達可能 UI から呼ばれないコマンド (警告) =="
python3 - <<'PY'
import re, os, glob
files = {os.path.relpath(f): open(f).read()
         for f in glob.glob('src/**/*.tsx', recursive=True) + glob.glob('src/**/*.ts', recursive=True)
         if '__tests__' not in f}
def imports(cur):
    out = set()
    for m in re.findall(r'from\s+"(\.[^"]+)"', files[cur]):
        base = os.path.normpath(os.path.join(os.path.dirname(cur), m))
        for ext in ('.tsx', '.ts', '/index.tsx', '/index.ts'):
            if base + ext in files: out.add(base + ext)
    return out
seen, stack = set(), ['src/main.tsx']
while stack:
    cur = stack.pop()
    if cur in seen or cur not in files: continue
    seen.add(cur); stack += list(imports(cur))
called = set()
for f in seen:
    for m in re.finditer(r'invoke(?:<[^>]*>)?\s*\(\s*"([a-z_]+)"', files[f]):
        ls = files[f].rfind('\n', 0, m.start()) + 1
        if files[f][ls:m.start()].lstrip().startswith('//'): continue
        called.add(m.group(1))
main_rs = open('src-tauri/src/main.rs').read()
blk = main_rs[main_rs.index('generate_handler!['):main_rs.index('generate_handler![')+3000]
reg = set(re.findall(r'^\s*([a-z_][a-z0-9_]*),\s*$', blk, re.M))
unused = sorted(reg - called)
print(f"  登録 {len(reg)} 件 / UI から呼ばれている {len(reg & called)} 件")
for u in unused:
    print(f"  WARN 登録済みだが UI から呼ばれていない: {u}")
PY

echo ""
if [ "$fail" -eq 0 ]; then
  echo "静的検証: 問題なし"
  echo "注意: これは cargo check の代替ではない。型検査・借用検査・"
  echo "      正規表現の実コンパイル・テストの成否は依然として未検証。"
else
  echo "静的検証: 要修正あり"
fi
exit "$fail"
