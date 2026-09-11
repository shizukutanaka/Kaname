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
# 以前はハードコードされたシンボル一覧 (analyze_body_risks 等) だけを見ていた。
# そのため mail_list を削除した PR #86 で、同じ関数をまだ呼んでいた
# テスト 2 件を検出できなかった (シンボルが一覧に無かったため)。
# 一覧を都度更新する運用は同じ穴を繰り返すので、リポジトリ全体から
# 「裸で呼ばれているが、どこにも定義されておらず import もされていない」
# シンボルを機械的に洗い出す方式に一般化する。
python3 - <<'PY' || fail=1
import re, glob, sys

files = {f: open(f, encoding='utf-8', errors='replace').read()
         for f in glob.glob('crates/**/*.rs', recursive=True) + glob.glob('src-tauri/**/*.rs', recursive=True)
         if '/target/' not in f}

# リポジトリ全体で定義されている fn 名 (可視性・async 問わず)。
defined = set()
for src in files.values():
    defined.update(re.findall(r'(?:^|\s)fn\s+([a-zA-Z_][a-zA-Z0-9_]*)', src))

# Rust の組み込み・prelude 由来で「裸呼び出し」されうるもの。
# use 文で明示 import されていれば defined 判定に頼らず許可する。
BUILTIN_ALLOW = {
    'drop', 'print', 'eprint', 'format', 'panic', 'min', 'max', 'swap',
    'replace', 'take', 'size_of', 'align_of', 'default',
}

# Rust の予約語。`if (x)` `for (a, b) in` `match (a, b)` `let (a, b) =`
# `pub(crate)` のように、キーワード直後に括弧が続く構文が普通にあり、
# 関数呼び出しではない。
KEYWORDS = {
    'if', 'for', 'while', 'loop', 'match', 'let', 'return', 'pub',
    'else', 'in', 'move', 'unsafe', 'async', 'await', 'box', 'yield',
    'where', 'as', 'ref', 'mut', 'crate', 'super', 'self', 'Self',
    'true', 'false', 'impl', 'trait', 'fn', 'type', 'struct', 'enum',
    'const', 'static', 'dyn', 'do',
}

# 属性・コメント・文字列/char リテラルは、その中身が関数呼び出しに似た
# 形になりうる (kaname-screen 等は検出パターンをそのまま文字列で持ち、
# コメントには「// unlimited (Enterprise)」のような自然文が入る)。
# 呼び出し判定の前に、文字列 → コメントの順で取り除く
# (コメント除去を先にすると "http://foo" のようなURL文字列内の `//` を
# コメント開始と誤認するため、必ず文字列を先に潰す)。
def strip_noise(src: str) -> str:
    src = re.sub(r'#!?\[.*?\]', ' ', src, flags=re.S)  # 属性
    # raw 文字列: r#*"..."#* は開始と同じ個数の # で閉じる必要がある
    # (Rust の実際の構文どおり、バックリファレンスで揃える)。
    # 'r' の直前が識別子の一部 (例: "tr", "for") だと誤爆するので
    # 単語境界を要求する ("tr", "td" の並びを raw 文字列と誤認しない)。
    src = re.sub(r'(?<![a-zA-Z0-9_])r(#*)"(?:.*?)"\1', '""', src, flags=re.S)
    # char リテラルを文字列より先に剥がす。`'"'` (ダブルクォート 1 文字の
    # char リテラル) を先に文字列側の正規表現に処理させると、中の `"` を
    # 文字列の開始と誤認し、次に見つかる無関係な `"` までを丸ごと呑み込んで
    # 以降の文字列境界が全部ズレる (実際に発生した)。
    src = re.sub(r"'(?:[^'\\]|\\.)'", "''", src, flags=re.S)
    # 通常の文字列。DOTALL 必須: `\<改行>` によるバックスラッシュ行継続
    # (複数行文字列リテラルで使われる) は `\\.` が改行にマッチできないと
    # 消費できず、以降の文字列境界がすべてズレる
    # (MIME フィクスチャの複数行バイト文字列で実際に発生した)。
    src = re.sub(r'"(?:[^"\\]|\\.)*"', '""', src, flags=re.S)
    # ブロックコメント (文字列を潰した後なので安全)。
    src = re.sub(r'/\*.*?\*/', ' ', src, flags=re.S)
    # 行コメント。以前は「行頭が // のコメント専用行」しか除去しておらず、
    # 実コードに続く行末コメント (`pub seat_limit: ..., // unlimited (...)`
    # のような) を取りこぼしていた。文字列を潰した後なので、残る `//` は
    # すべて本物のコメント開始とみなしてよい。
    src = re.sub(r'//[^\n]*', '', src)
    return src

bad = 0
for f, src in files.items():
    body = strip_noise(src)
    # `use` 文に現れる識別子はすべて import 済みとみなす (別クレート由来を許可)。
    # `use axum::{\n routing::{get, post},\n ... \n};` のように複数行にまたがる
    # 波括弧 import があるため、DOTALL + 非貪欲で `use` から最初の `;` までを拾う。
    imported = set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*',
                   ' '.join(re.findall(r'^\s*(?:pub\s+)?use\s+.*?;', body, re.M | re.S))))
    # `fn NAME` に加えて `let NAME = |...` / `let NAME = move |...` の
    # クロージャ束縛も局所的な「定義」として扱う (テストの make_req 等)。
    local_defs = set(re.findall(r'(?:^|\s)fn\s+([a-zA-Z_][a-zA-Z0-9_]*)', src))
    local_defs |= set(re.findall(r'\blet\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?::[^=]*)?=\s*(?:move\s*)?\|', body))
    # `!` の直前 (マクロ) と `.`/`::` の直後 (メソッド・パス) を除く裸呼び出しのみを拾う。
    calls = set(re.findall(r'(?<![a-zA-Z0-9_:.])\b([a-z_][a-z0-9_]*)\s*\(', body))
    for sym in sorted(calls):
        if sym in local_defs or sym in imported or sym in BUILTIN_ALLOW or sym in KEYWORDS:
            continue
        if sym in defined:
            continue  # 同クレート内の別ファイルで定義されている
        print(f"  NG {f}: {sym}() を呼んでいるが定義も import も見つからない")
        bad = 1
sys.exit(bad)
PY
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
