"""文字列・char・コメントを単一パスで除去する字句解析ヘルパー。

static-check.sh の検査2 (未定義関数呼び出し)・検査6 (本番 unwrap)・
検査7 (TS 型参照) で共通利用する。

なぜ正規表現カスケードではなく単一パスか:
「文字列→コメント」の順で剥がす旧実装は、doc コメント中の孤立した `"`
(例: /// 表示名の `"` は除外する) を文字列開始と誤認し、以後の parity が
反転してコードを文字列扱い・文字列をコード扱いしていた (検査2 の
accounts()/strftime() 誤検知の原因)。逆順 (コメント→文字列) も
`"http://x"` のような文字列内 `//` で破綻するため、どちらの順序も
成立しない。トークンを先頭から1回だけ読む字句解析ならこの競合は起きない。
"""

import re


def _blank(text: str, keep_lines: bool, fallback: str) -> str:
    """除去範囲の置換文字列。keep_lines 時は改行と桁位置を保つ。"""
    if keep_lines:
        return re.sub(r'[^\n]', ' ', text)
    return fallback


def _ident_char(ch: str) -> bool:
    return ch.isalnum() or ch == '_'


def _skip_string(src: str, i: int, n: int) -> int:
    """`"` または `b"` で始まる文字列の終端位置を返す (閉じ `"` の次)。"""
    i += 2 if src.startswith('b"', i) else 1
    while i < n:
        if src[i] == '\\':
            i += 2  # エスケープ・行継続 \<改行> をまとめて消費
        elif src[i] == '"':
            return i + 1
        else:
            i += 1
    return n


def _skip_raw_string(src: str, i: int, n: int):
    """r".." / r#".."# / br".." / br#".."# の終端位置を返す。該当しなければ None。"""
    m = re.match(r'(?:br|b?r)(#*)"', src[i:])
    if not m:
        return None
    end = '"' + (m.group(1) or '')
    j = src.find(end, i + len(m.group(0)))
    return n if j == -1 else j + len(end)


def _skip_char(src: str, i: int, n: int):
    """`'` / `b'` で始まる char リテラルの終端を返す。lifetime なら None。

    'x' / '\\n' / '\\u{1F600}' / b'x' は char。
    'a / 'static のように閉じ `'` が無いものは lifetime として扱う。
    """
    k = i + (2 if src.startswith("b'", i) else 1)
    if k < n and src[k] == '\\':
        # エスケープ形式: 次の ' まで (上限 14 文字で lifetime との誤認を防ぐ)
        j = src.find("'", k + 2, min(k + 14, n))
        return (j + 1) if j != -1 else None
    if k + 1 < n and src[k + 1] == "'":
        return k + 2
    return None


def _skip_line_comment(src: str, i: int, n: int) -> int:
    j = src.find('\n', i)
    return n if j == -1 else j


def _skip_block_comment(src: str, i: int, n: int) -> int:
    """Rust ブロックコメントはネストする。"""
    depth, j = 1, i + 2
    while j < n and depth:
        if src.startswith('/*', j):
            depth += 1
            j += 2
        elif src.startswith('*/', j):
            depth -= 1
            j += 2
        else:
            j += 1
    return j


def _scan_attribute(src: str, i: int, n: int):
    """`#[...]` / `#![...]` 属性を走査し (終端, 内部を潰したテキスト) を返す。

    属性の中にも文字列 (`#[doc = "..."]`) や char が現れうるので、
    内部は文字列/char/コメントを潰しながら `[]` の深さを追う。
    属性でなければ None。
    """
    j = i + 1
    if j < n and src[j] == '!':
        j += 1
    if j >= n or src[j] != '[':
        return None
    depth, k = 1, j + 1
    inner = []
    while k < n and depth:
        if src.startswith('//', k):
            e = _skip_line_comment(src, k, n)
            inner.append(_blank(src[k:e], True, ' '))
            k = e
            continue
        if src.startswith('/*', k):
            e = _skip_block_comment(src, k, n)
            inner.append(_blank(src[k:e], True, ' '))
            k = e
            continue
        prev_ident = _ident_char(src[k - 1]) if k else False
        if src[k] == '"' or (src.startswith('b"', k) and not prev_ident):
            e = _skip_string(src, k, n)
            inner.append(_blank(src[k:e], True, '""'))
            k = e
            continue
        e = None if prev_ident else _skip_raw_string(src, k, n)
        if e is not None:
            inner.append(_blank(src[k:e], True, '""'))
            k = e
            continue
        if src[k] == "'" or (src.startswith("b'", k) and not prev_ident):
            e = _skip_char(src, k, n)
            if e is not None:
                inner.append(_blank(src[k:e], True, "''"))
                k = e
                continue
        if src[k] == '[':
            depth += 1
        elif src[k] == ']':
            depth -= 1
        inner.append(src[k])
        k += 1
    return k, src[i:j] + '[' + ''.join(inner)


def strip_rust(src: str, keep_lines: bool = False, keep_attrs: bool = False) -> str:
    """Rust ソースから文字列/char/コメントを除去する。

    keep_lines=True では除去範囲を空白に置換して行番号を保つ
    (検査6 の違反箇所の行番号報告用)。False では文字列は `""`、
    char は `''`、コメントは空白に潰す (検査2 用)。

    keep_attrs=True では `#[...]` 属性の形 (名前と括弧構造) を残し、
    内部の文字列/コメントだけを潰す。`#[cfg(test)]`/`#[test]` を
    後段の検査が見つけられるようにするため (検査6 用)。
    keep_attrs=False では属性ごと潰す (検査2 では `#[derive(..)]` の
    中身が関数呼び出しに見えるのを防ぐ)。
    """
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        prev_ident = i > 0 and _ident_char(src[i - 1])
        if src.startswith('//', i):
            j = _skip_line_comment(src, i, n)
            out.append(_blank(src[i:j], keep_lines, ' '))
            i = j
        elif src.startswith('/*', i):
            j = _skip_block_comment(src, i, n)
            out.append(_blank(src[i:j], keep_lines, ' '))
            i = j
        elif c == '#':
            scanned = _scan_attribute(src, i, n)
            if scanned is None:
                out.append(c)
                i += 1
            else:
                e, cleaned = scanned
                out.append(cleaned if keep_attrs else _blank(src[i:e], keep_lines, ' '))
                i = e
        elif c == '"' or (src.startswith('b"', i) and not prev_ident):
            j = _skip_string(src, i, n)
            out.append(_blank(src[i:j], keep_lines, '""'))
            i = j
        elif not prev_ident:
            e = _skip_raw_string(src, i, n)
            if e is not None:
                out.append(_blank(src[i:e], keep_lines, '""'))
                i = e
                continue
            if c == "'" or src.startswith("b'", i):
                e = _skip_char(src, i, n)
                if e is not None:
                    out.append(_blank(src[i:e], keep_lines, "''"))
                    i = e
                    continue
            out.append(c)
            i += 1
        elif c == "'":
            e = _skip_char(src, i, n)
            if e is not None:
                out.append(_blank(src[i:e], keep_lines, "''"))
                i = e
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def rust_test_spans(masked: str):
    """mask 済みソース上で `#[cfg(test)]` 付き mod / `#[test]` 系 fn の範囲を返す。

    引数は strip_rust(src, keep_lines=True, keep_attrs=True) の出力を想定。
    文字列・コメントが潰れているため、`{`/`}` の対応と属性マーカーが
    どちらも文字列内容に汚染されず正しく対応付けできる
    (旧実装は生ソースでブレース対応を取っており、テスト内の "}" を含む
    文字列で早期に閉じる欠陥があった)。
    """
    spans = []
    n = len(masked)

    def brace_end(open_brace: int) -> int:
        depth, j = 0, open_brace
        while j < n:
            if masked[j] == '{':
                depth += 1
            elif masked[j] == '}':
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return n

    # #[cfg(test)] に続く `mod name { ... }`
    for m in re.finditer(r'#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]', masked):
        mod_m = re.compile(r'\bmod\s+\w+\s*\{').search(masked, m.end())
        if not mod_m:
            continue
        spans.append((m.start(), brace_end(mod_m.end() - 1)))

    # #[test] / #[tokio::test] / #[rstest] 等に続く fn
    for m in re.finditer(
            r'#\s*\[\s*(?:[a-zA-Z_][a-zA-Z0-9_:]*::)?(?:test|rstest)[^\]]*\]\s*',
            masked):
        brace = masked.find('{', m.end())
        if brace == -1:
            continue
        spans.append((m.start(), brace_end(brace)))
    return spans


def strip_ts(src: str) -> str:
    """TS/TSX ソースから文字列・テンプレート・コメントを除去する。

    ブロックコメントはネストしない。テンプレートリテラルは `${...}` の
    中に式 (ネストしたテンプレートを含む) を持てるため、ブレース深さを
    追跡する。旧実装の `r#*"..."#*` パターンは Rust 生文字列の誤った
    持ち込みであり TS には存在しないため廃止した。
    """
    out = []
    i, n = 0, len(src)

    def skip_ts_string(j: int, q: str) -> int:
        j += 1
        while j < n:
            if src[j] == '\\':
                j += 2
            elif src[j] == q:
                return j + 1
            else:
                j += 1
        return n

    def skip_template(j: int) -> int:
        # j は ` の位置。${} 内は式なので再帰的に深さを追う
        j += 1
        while j < n:
            if src[j] == '\\':
                j += 2
                continue
            if src[j] == '`':
                return j + 1
            if src.startswith('${', j):
                depth, k = 1, j + 2
                while k < n and depth:
                    if src.startswith('//', k):
                        k = _skip_line_comment(src, k, n)
                        continue
                    if src.startswith('/*', k):
                        e = src.find('*/', k + 2)
                        k = n if e == -1 else e + 2
                        continue
                    if src[k] in "'\"":
                        k = skip_ts_string(k, src[k])
                        continue
                    if src[k] == '`':
                        k = skip_template(k)
                        continue
                    if src[k] == '{':
                        depth += 1
                    elif src[k] == '}':
                        depth -= 1
                    k += 1
                j = k
                continue
            j += 1
        return n

    while i < n:
        c = src[i]
        if src.startswith('//', i):
            i = _skip_line_comment(src, i, n)
            out.append(' ')
        elif src.startswith('/*', i):
            e = src.find('*/', i + 2)
            i = n if e == -1 else e + 2
            out.append(' ')
        elif c in "'\"":
            i = skip_ts_string(i, c)
            out.append('""')
        elif c == '`':
            i = skip_template(i)
            out.append('``')
        else:
            out.append(c)
            i += 1
    return ''.join(out)
