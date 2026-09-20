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
# 呼び出し判定の前に取り除く。文字列内の `//` (URL) とコメント内の `"`
# が相互に干渉するため、正規表現の連鎖ではなく単一パスで処理する。
def strip_noise(src: str) -> str:
    src = re.sub(r'#!?\[.*?\]', ' ', src, flags=re.S)  # 属性
    # raw 文字列: r#*"..."#* は開始と同じ個数の # で閉じる必要がある
    # (Rust の実際の構文どおり、バックリファレンスで揃える)。
    # 'r' の直前が識別子の一部 (例: "tr", "for") だと誤爆するので
    # 単語境界を要求する ("tr", "td" の並びを raw 文字列と誤認しない)。
    src = re.sub(r'(?<![a-zA-Z0-9_])r(#*)"(?:.*?)"\1', '""', src, flags=re.S)
    # 文字列・文字リテラル・コメントを状態機械の単一パスで除去する。
    # 以前は「文字列 → char → コメント」の正規表現連鎖だったが、
    # コメント内の孤立 `"` (例: /// 表示名の `"` は〜) が文字列の
    # 開閉パリティを崩し、以降の文字列がコードとして誤検出される
    # バグがあった (kaname-store の SQL 内 strftime()/accounts() が
    # 「未定義関数呼び出し」と報告された)。パリティに依存しない
    # 一文字ずつの走査なら同類の誤爆は発生しない。
    out = []
    i, n = 0, len(src)
    NORMAL, IN_STR, IN_LINE, IN_BLOCK = 0, 1, 2, 3
    state = NORMAL
    block_depth = 0
    while i < n:
        c = src[i]
        if state == NORMAL:
            if c == '/' and i + 1 < n and src[i + 1] == '/':
                state = IN_LINE; i += 2; continue
            if c == '/' and i + 1 < n and src[i + 1] == '*':
                state = IN_BLOCK; block_depth = 1; i += 2; continue
            if c == '"':
                out.append('"'); state = IN_STR; i += 1; continue
            if c == "'":
                # char リテラルは 'x'/'\\n'/'\"' など1要素のみ。
                # ライフタイム 'a / 'static は閉じ ' が無いので残す。
                m = re.match(r"'(?:[^'\\]|\\.)'", src[i:])
                if m:
                    out.append("''"); i += m.end(); continue
                out.append(c); i += 1; continue
            out.append(c); i += 1; continue
        if state == IN_STR:
            if c == '\\':
                i += 2; continue          # \" \\ \<改行> 等のエスケープ/継続
            if c == '"':
                out.append('"'); state = NORMAL; i += 1; continue
            if c == '\n':
                out.append('\n')          # 行番号をずらさないため改行は残す
            i += 1; continue
        if state == IN_LINE:
            if c == '\n':
                out.append('\n'); state = NORMAL
            i += 1; continue
        # IN_BLOCK: Rust のブロックコメントはネストする
        if src.startswith('/*', i):
            block_depth += 1; i += 2; continue
        if src.startswith('*/', i):
            block_depth -= 1; i += 2
            if block_depth == 0: state = NORMAL
            continue
        if c == '\n':
            out.append('\n')
        i += 1
    return ''.join(out)

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
    # `name: impl Fn...` / `mut name: impl FnMut` のように引数として
    # 渡されたクロージャも局所的な定義として扱う (progress コールバック等)。
    local_defs |= set(re.findall(
        r'(?:^|[,(]\s*)(?:mut\s+)?([a-z_][a-z0-9_]*)\s*:\s*(?:impl|&impl|Box<dyn)\s+Fn',
        body))
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
    # 引数名のみ抽出。「name: Type」の name のみ (パス内の `::` 区切りは
    # `(?!:)` で除外)。`tauri::State`/`AppHandle` などフレームワーク注入の
    # 引数は invoke 呼び出し側が送らないため除外する。`use tauri::AppHandle`
    # で裸名にもなるため、型パスに `tauri::` を含まなくても注入型名自体も除外。
    INJECTED = {'AppHandle', 'State', 'Window', 'WebviewWindow', 'Manager', 'Emitter'}
    params = set()
    for pm in re.finditer(r'([a-z_][a-z0-9_]*)\s*:(?!:)\s*([^,)]+)', m.group(2)):
        ty = pm.group(2)
        if 'tauri::' not in ty and not any(t in ty for t in INJECTED):
            params.add(pm.group(1))
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
echo "== 6. 本番コードに .unwrap() が無いこと (CLAUDE.md 不変条件 I6) =="
# I6: 「unwrap() は本番コードに使用禁止」。各クレートの
# #![deny(clippy::unwrap_used)] と [lints] workspace = true 継承で
# clippy レベルでも強制される (2026-09-20 に全クレートへ有効化)。
# この検査は clippy が実行できない環境向けの代替として残す。
# テストコード (#[cfg(test)] mod / 個々の #[test] 関数) は対象外。
python3 - <<'PY' || fail=1
import re, glob, sys

def _blank(text: str) -> str:
    # 除去した範囲を同じ改行数の空白に置き換える (行番号がズレないように)。
    return '\n' * text.count('\n')

def strip_strings_comments(src: str) -> str:
    # 文字列・char・コメントを単一パスで空白化する (改行は保持し行番号を維持)。
    # 検査2の strip_noise と同じ状態機械だが、#[cfg(test)] / #[test] の検出に
    # 必要なため属性テキストは残す (属性内の文字列は通常通り空白化される)。
    # 旧 strip_comments_and_strings は「raw文字列→char→文字列→コメント」の
    # 正規表現カスケードで、コメント内の孤立 " が後続の文字列リテラルと
    # ペア化して parity を反転させ、本番 .unwrap() を文字列内に飲み込んで
    # 見逃す欠陥があった (合成テストで実証: 検出行なし)。
    src = re.sub(r'(?<![a-zA-Z0-9_])r(#*)"(?:.*?)"\1',
                 lambda m: _blank(m.group(0)), src, flags=re.S)
    out = []
    i, n = 0, len(src)
    NORMAL, IN_STR, IN_LINE, IN_BLOCK = 0, 1, 2, 3
    state = NORMAL
    block_depth = 0
    while i < n:
        c = src[i]
        if state == NORMAL:
            if c == '/' and i + 1 < n and src[i + 1] == '/':
                state = IN_LINE; i += 2; continue
            if c == '/' and i + 1 < n and src[i + 1] == '*':
                state = IN_BLOCK; block_depth = 1; i += 2; continue
            if c == '"':
                state = IN_STR; i += 1; continue
            if c == "'":
                # char リテラルは 'x'/'\\n'/'}' 等1要素のみ。
                # ライフタイム 'a / 'static は閉じ ' が無いので残す。
                m = re.match(r"'(?:[^'\\]|\\.)'", src[i:])
                if m:
                    out.append(' ' * m.end()); i += m.end(); continue
                out.append(c); i += 1; continue
            out.append(c); i += 1; continue
        if state == IN_STR:
            if c == '\\':
                i += 2; continue          # \" \\ \<改行> 等のエスケープ/継続
            if c == '"':
                state = NORMAL; i += 1; continue
            if c == '\n':
                out.append('\n')
            i += 1; continue
        if state == IN_LINE:
            if c == '\n':
                out.append('\n'); state = NORMAL
            i += 1; continue
        # IN_BLOCK: Rust のブロックコメントはネストする
        if src.startswith('/*', i):
            block_depth += 1; i += 2; continue
        if src.startswith('*/', i):
            block_depth -= 1; i += 2
            if block_depth == 0: state = NORMAL
            continue
        if c == '\n':
            out.append('\n')
        i += 1
    return ''.join(out)

def strip_cfg_test_mods(src):
    out, i, n = [], 0, len(src)
    while i < n:
        m = re.compile(r'#\[cfg\(test\)\]').search(src, i)
        if not m:
            out.append(src[i:]); break
        out.append(src[i:m.start()])
        mod_m = re.compile(r'\bmod\s+\w+\s*\{').search(src, m.end())
        if not mod_m:
            out.append(src[m.start():m.end()]); i = m.end(); continue
        depth, j = 0, mod_m.end() - 1
        while j < n:
            if src[j] == '{': depth += 1
            elif src[j] == '}':
                depth -= 1
                if depth == 0: j += 1; break
            j += 1
        out.append(_blank(src[m.start():j]))
        i = j
    return ''.join(out)

def strip_single_test_fns(src):
    # #[test] / #[tokio::test] / #[rstest] が付いた個々の関数本体を、
    # ブレース対応で除去する (mod tests { } の外に単発で置かれるテスト用)。
    # 属性引数 `#[tokio::test(flavor = "...")]` は `]` が1つなので
    # `[^\]\n]*` で閉じ `]` まで読む。旧パターンの `[^\]]*` は改行も
    # 飲んでしまい、`#[test]\nfn t() { ... }` の関数本体全体を「属性」として
    # 貪欲に消費してテスト除去が一切機能していなかった (合成テストで実証)。
    out, i, n = [], 0, len(src)
    pat = re.compile(r'#\[(?:(?:tokio|async_std)::)?(?:test|rstest)\b[^\]\n]*\]\s*\n')
    while i < n:
        m = pat.search(src, i)
        if not m:
            out.append(src[i:]); break
        out.append(src[i:m.start()])
        brace = src.find('{', m.end())
        if brace == -1:
            out.append(src[m.start():m.end()]); i = m.end(); continue
        depth, j = 0, brace
        while j < n:
            if src[j] == '{': depth += 1
            elif src[j] == '}':
                depth -= 1
                if depth == 0: j += 1; break
            j += 1
        out.append(_blank(src[m.start():j]))
        i = j
    return ''.join(out)

def strip_comments_and_strings(src):
    # 行番号を報告するため、複数行にまたがりうる置換 (raw文字列・複数行
    # 文字列・ブロックコメント) は改行数を保った置換にする。
    src = re.sub(r'(?<![a-zA-Z0-9_])r(#*)"(?:.*?)"\1',
                  lambda m: '"' + _blank(m.group(0)) + '"', src, flags=re.S)
    src = re.sub(r"'(?:[^'\\]|\\.)'", "''", src, flags=re.S)
    src = re.sub(r'"(?:[^"\\]|\\.)*"',
                  lambda m: '"' + _blank(m.group(0)) + '"', src, flags=re.S)
    src = re.sub(r'/\*.*?\*/', lambda m: _blank(m.group(0)), src, flags=re.S)
    src = re.sub(r'//[^\n]*', '', src)
    return src

bad = 0
for f in glob.glob('crates/**/*.rs', recursive=True) + glob.glob('src-tauri/**/*.rs', recursive=True):
    if '/target/' in f:
        continue
    src = open(f, encoding='utf-8', errors='replace').read()
    # 先に文字列/コメントを空白化してからブレース対応を取る。
    # 生ソースでブレース対応を取ると、テスト内の "}" や '}' が
    # 深さカウンタを壊して mod/fn が早期に閉じ、テストコードが本番扱いで
    # 誤検知される (合成テストで実証: '}': char の後の unwrap が NG 報告)。
    masked = strip_strings_comments(src)
    prod = strip_single_test_fns(strip_cfg_test_mods(masked))
    if re.search(r'\.unwrap\(\)', prod):
        for m in re.finditer(r'\.unwrap\(\)', prod):
            ln = prod[:m.start()].count('\n') + 1
            print(f"  NG {f}:{ln}: 本番コードで .unwrap() を使用 (I6 違反)")
        bad = 1
sys.exit(bad)
PY
[ "$fail" -eq 0 ] && echo "  OK: 本番コードに .unwrap() なし"

echo ""
echo "== 7. TypeScript: 未 import・未定義の型参照 (src/__tests__ 含む) =="
# Rust 側の検査2と同じ欠陥クラスがフロントエンドにもあった: app.test.ts の
# makeEmail() が、削除済み KanameApp.tsx の Email 型を import せず参照して
# いた。tsc/vitest は D20 により実行できないため、これも tsc が無ければ
# 一生気付けない。型検査そのものの代替にはならないが、「大文字始まりの
# 識別子が import も同一ファイル内定義も無いまま型位置で使われている」
# ケースだけは機械的に検出できる。
python3 - <<'PY' || fail=1
import re, glob, sys

files = {f: open(f, encoding='utf-8', errors='replace').read()
         for f in glob.glob('src/**/*.ts', recursive=True) + glob.glob('src/**/*.tsx', recursive=True)}

# TS 標準ライブラリ・DOM・vitest/solid-js が提供する型で、各ファイルに
# import が無くても使える名前。
BUILTIN_TYPES = {
    'String','Number','Boolean','Object','Array','Promise','Record','Partial',
    'Required','Readonly','Pick','Omit','Exclude','Extract','ReturnType',
    'Parameters','InstanceType','Map','Set','WeakMap','WeakSet','Date','Error',
    'RegExp','JSON','Math','Symbol','Function','Iterable','Iterator',
    'IterableIterator','Generator','AsyncGenerator','ArrayBuffer','ArrayLike',
    'Uint8Array','Int8Array','Float32Array','Float64Array','DataView',
    'HTMLElement','HTMLInputElement','HTMLDivElement','HTMLButtonElement',
    'HTMLTextAreaElement','HTMLIFrameElement','Element','Event','CustomEvent',
    'MouseEvent','KeyboardEvent','EventTarget','Node','Window','Document',
    'NodeJS','ReturnType','ReadonlyArray','NonNullable','PromiseLike',
    'ThisType','Awaited',
    # vitest / solid-js の型としてよく使われるもの
    'Component','JSXElement','Accessor','Setter','Signal',
}

def strip_ts_noise(src: str) -> str:
    # Rust 側と同じく単一パスで文字列/コメントを除去する。
    # 旧実装は正規表現カスケードで、コメント内の孤立 ' (don't 等) が
    # 後続のリテラルとペア化して parity を反転させ、リテラル間のコードを
    # 見えなくする欠陥があった。また先頭の r#*"..."#* パターンは Rust の
    # 生文字列のもので、TS には存在しない構文を誤って持ち込んでいた。
    # `...` テンプレート内の ${...} は式なので、中身は残して再帰的に除去する
    # (${x as Foo} の Foo のような型参照を検出対象に含めるため)。
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == '/' and src[i + 1:i + 2] == '/':
            j = src.find('\n', i)
            i = n if j < 0 else j
            continue
        if c == '/' and src[i + 1:i + 2] == '*':
            j = src.find('*/', i + 2)
            i = n if j < 0 else j + 2
            continue
        if c in '\'"':
            # 引用符は残す — import 抽出 (`from "..."`) が引用符の有無で
            # 文を識別するため、消すと import が見えなくなる (誤検知になる)。
            out.append(c)
            q = c; i += 1
            while i < n:
                if src[i] == '\\': i += 2; continue
                if src[i] == q: out.append(src[i]); i += 1; break
                if src[i] == '\n': break  # '...' "..." は改行を跨げない
                i += 1
            continue
        if c == '`':
            out.append(c); i += 1
            while i < n:
                if src[i] == '\\': i += 2; continue
                if src[i] == '`': out.append(src[i]); i += 1; break
                if src.startswith('${', i):
                    j, depth = i + 2, 1
                    while j < n and depth:
                        ch = src[j]
                        if ch == '{': depth += 1
                        elif ch == '}': depth -= 1
                        elif ch in '\'"`':
                            q = ch; j += 1
                            while j < n:
                                if src[j] == '\\': j += 2; continue
                                if src[j] == q: break
                                j += 1
                        elif ch == '/' and src[j+1:j+2] == '/':
                            k = src.find('\n', j); j = n if k < 0 else k; continue
                        elif ch == '/' and src[j+1:j+2] == '*':
                            k = src.find('*/', j+2); j = n if k < 0 else k+2; continue
                        j += 1
                    out.append(strip_ts_noise(src[i + 2:j - 1]))
                    i = j
                    continue
                i += 1
            continue
        out.append(c); i += 1
    return ''.join(out)

bad = 0
for f, raw in files.items():
    src = strip_ts_noise(raw)

    # このファイル内の import で得られる名前すべて (default/named/type import)。
    imported = set()
    for use in re.findall(r'^\s*import\s+(?:type\s+)?.*?from\s+["\'][^"\']*["\']\s*;?', src, re.M):
        imported.update(re.findall(r'[A-Za-z_][A-Za-z0-9_]*', use))

    # このファイル内で定義されている型・値の名前。
    local_defs = set()
    local_defs.update(re.findall(r'\b(?:interface|type|class|enum)\s+([A-Za-z_][A-Za-z0-9_]*)', src))
    local_defs.update(re.findall(r'\b(?:export\s+)?(?:const|function)\s+([A-Za-z_][A-Za-z0-9_]*)', src))
    # ジェネリクス宣言 (`function f<T extends X>` 等) もローカルの型名として
    # 許可する。`Partial<Email>` のような「ジェネリクスの使用側」まで拾って
    # しまわないよう、宣言側にしか現れない `function`/`class` 直後の
    # `<...>` に限定する (最初のテスト実装は `<Name>` を無条件に許可して
    # おり、まさに検出したかった `Partial<Email>` 型の誤参照を素通りさせて
    # いた。合成的な回帰テストで発覚)。
    local_defs.update(re.findall(
        r'\b(?:function|class)\s+[A-Za-z_][A-Za-z0-9_]*\s*<\s*([A-Za-z_][A-Za-z0-9_]*)', src))

    # 型位置での参照: `: TypeName` および `<TypeName` (ジェネリクス引数)。
    # 変数の値としての大文字始まり参照 (JSX コンポーネント等) と混同しない
    # よう、コロンの後ろか、Partial</Array< 等ジェネリクスの内側に限定する。
    refs = set(re.findall(r':\s*([A-Z][A-Za-z0-9_]*)', src))
    refs |= set(re.findall(r'<\s*([A-Z][A-Za-z0-9_]*)\s*[>,]', src))

    for sym in sorted(refs):
        if sym in imported or sym in local_defs or sym in BUILTIN_TYPES:
            continue
        print(f"  NG {f}: 型 {sym} が import も同一ファイル内定義も無いまま使われている")
        bad = 1
sys.exit(bad)
PY
[ "$fail" -eq 0 ] && echo "  OK: 未 import の型参照なし"

echo ""
echo "== 8. ビルドマニフェスト3箇所のバージョン番号が一致していること =="
# v0.7.0/v0.7.1 のリリースカットで README/CHANGELOG/maturity.md は
# 更新したが、実際のビルド成果物に埋め込まれる Cargo.toml/package.json/
# tauri.conf.json のバージョンを更新し忘れ、3箇所とも v0.6.0 のまま
# 放置されていた。README 上は最新版を名乗りながら、ビルドすれば
# 旧バージョンを名乗るアプリができる状態だった。再発防止として検証する。
python3 - <<'PY' || fail=1
import re, json, sys

def read_toml_version(path):
    # Cargo.toml は TOML なので簡易パーサは使わず、[workspace.package] の
    # version だけを正規表現で拾う。トップレベルの他の "version" 的な
    # 文字列 (依存バージョン指定等) と混同しないよう、セクション見出しの
    # 直後から次の [ セクション見出しまでに限定して探す。
    try:
        src = open(path, encoding='utf-8').read()
    except FileNotFoundError:
        return None
    m = re.search(r'\[workspace\.package\](.*?)(?=\n\[|\Z)', src, re.S)
    if not m:
        return None
    m2 = re.search(r'^\s*version\s*=\s*"([^"]+)"', m.group(1), re.M)
    return m2.group(1) if m2 else None

def read_json_version(path):
    # JSON は正規表現ではなくパーサで読む。"version" キーが devDependencies
    # 等ネストした場所に先に現れても、トップレベルの値だけを正しく拾う。
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    v = data.get('version')
    return v if isinstance(v, str) else None

versions = {
    'Cargo.toml':                 read_toml_version('Cargo.toml'),
    'package.json':                read_json_version('package.json'),
    'src-tauri/tauri.conf.json':   read_json_version('src-tauri/tauri.conf.json'),
}
missing = [f for f, v in versions.items() if v is None]
for f in missing:
    print(f"  NG {f}: version フィールドが見つからない")
present = {f: v for f, v in versions.items() if v is not None}
distinct = set(present.values())
if len(distinct) > 1:
    for f, v in present.items():
        print(f"  NG {f}: version = {v}")
    print(f"  NG バージョン番号が一致していない: {sorted(distinct)}")
    sys.exit(1)
sys.exit(1 if missing else 0)
PY
[ "$fail" -eq 0 ] && echo "  OK: 3ファイルのバージョンが一致"

echo ""
echo '== 9. fuzz ターゲットの use kaname_*:: が実在すること =='
# fuzz/ は workspace から exclude されており cargo check/test が届かない
# ため、import 名が対象クレートの lib.rs に pub 宣言として実在するかを
# 静的に照合する (kaname_render::mime / ::sanitize のような消滅参照は
# D98 で実際に全ターゲットをコンパイル不能にしていた)。
python3 - <<'PY' || fail=1
import re, sys, glob, os

# シェルの冒頭で repo root に cd 済み (chdir は不要 — stdin 実行の
# __file__ は <stdin> であり abspath からの dirname が repo の親を
# 指してしまい glob が空ヒットで空転する欠陥があった)。
def public_names(lib_rs):
    """lib.rs のルートで公開されている名前を集める。"""
    names = set()
    try:
        src = open(lib_rs, encoding='utf-8').read()
    except FileNotFoundError:
        return names
    for m in re.finditer(r'pub\s+(?:mod|fn|struct|enum|trait|type|const|static)\s+([A-Za-z_][A-Za-z0-9_]*)', src):
        names.add(m.group(1))
    # pub use path::Name / pub use path::{A, B, ...}
    for m in re.finditer(r'pub\s+use\s+[^;]+;', src):
        tail = m.group(0)
        brace = re.search(r'\{([^}]*)\}', tail)
        if brace:
            for part in brace.group(1).split(','):
                part = part.strip()
                if not part:
                    continue
                # `Name` or `path::Name` or `Name as Alias`
                alias = re.search(r'\bas\s+([A-Za-z_][A-Za-z0-9_]*)$', part)
                if alias:
                    names.add(alias.group(1))
                else:
                    names.add(part.split('::')[-1].strip())
        else:
            single = re.search(r'pub\s+use\s+.*?::([A-Za-z_][A-Za-z0-9_]*)\s*;', tail)
            if single:
                names.add(single.group(1))
    return names

bad = 0
for target in glob.glob('fuzz/fuzz_targets/*.rs'):
    src = open(target, encoding='utf-8').read()
    # use kaname_x::{A, B, C} / use kaname_x::Name / use kaname_x::mod::...
    for m in re.finditer(r'use\s+(kaname_[a-z_]+)::([^;]+);', src):
        crate, path = m.group(1), m.group(2)
        lib = os.path.join('crates', crate.replace('_', '-'), 'src', 'lib.rs')
        names = public_names(lib)
        # `use crate::{A, B}` はブレース内の各名前を、`use crate::mod::X`
        # は先頭セグメント (モジュール) をルートで検査する。
        if path.lstrip().startswith('{'):
            inner = re.search(r'\{([^}]*)\}', path)
            segs = [p.strip().split('::')[0].strip()
                    for p in inner.group(1).split(',') if p.strip()] if inner else []
        else:
            first = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', path)
            segs = first[:1]
        for seg in segs:
            if seg and seg not in names:
                print(f"  NG {target}: `use {crate}::{seg}` は {lib} に存在しない")
                bad += 1
if bad:
    sys.exit(1)
print("  OK: 全ての fuzz ターゲットの kaname_* import が実在する")
PY

echo ""
echo "== 10. fuzz コーパス ↔ ターゲット ↔ Cargo.toml bin の対応関係 =="
# D103: corpus/aitm_urls 等の種は作られたが対応ターゲットが fuzz_targets に
# 無く (Cargo.toml の [[bin]] にも登録なし)、一度も実行されなかった。
# 逆方向も検査: ターゲット .rs があっても [[bin]] 未登録なら cargo fuzz の
# 対象にならない。コーパス無しの bin は許容 (初実行で自動生成される)。
python3 - <<'PY' || fail=1
import re, os, sys, glob

toml = open('fuzz/Cargo.toml', encoding='utf-8').read()
# [[bin]] ブロックの name = "..." を集める。
bins = set(re.findall(r'\[\[bin\]\]\s*name\s*=\s*"([^"]+)"', toml))
targets = {os.path.splitext(os.path.basename(p))[0]
           for p in glob.glob('fuzz/fuzz_targets/*.rs')}
corpora = {d for d in os.listdir('fuzz/corpus')
           if os.path.isdir(os.path.join('fuzz/corpus', d))} \
    if os.path.isdir('fuzz/corpus') else set()

bad = 0
for name in sorted(corpora - targets):
    print(f"  NG fuzz/corpus/{name}: 対応する fuzz_targets/{name}.rs が無い (D103 型の孤立コーパス)")
    bad += 1
for name in sorted(targets - bins):
    print(f"  NG fuzz_targets/{name}.rs: fuzz/Cargo.toml の [[bin]] に未登録 — cargo fuzz の対象外")
    bad += 1
for name in sorted(bins - targets):
    print(f"  NG fuzz/Cargo.toml [[bin]] \"{name}\": 対応する fuzz_targets/{name}.rs が無い")
    bad += 1
if bad:
    sys.exit(1)
print(f"  OK: corpus {len(corpora)} 件 / target {len(targets)} 件 / bin {len(bins)} 件の対応が一致")
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
