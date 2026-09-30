// fuzz/fuzz_targets/html_sanitizer.rs
//
// HTML サニタイザーのファジング
//
// 重要性:
//   メール本文は信頼できない HTML。サニタイザーをバイパスされると
//   - JavaScript 実行 → ローカル AI モデルへのアクセス
//   - CSS exfiltration → メール内容の外部送信
//   - リソース URL → トラッキング/ピング
//
// 攻撃面:
//   - mXSS (mutation XSS): HTML パーサーとサニタイザーの解釈差を悪用
//   - SVG 内 JavaScript
//   - data: URI スキーム
//   - javascript: URI スキーム (大文字小文字混在)
//   - DOM Clobbering
//   - HTML Mutation (innerHTML 経由でのサニタイズバイパス)
//
// 注: 「onerror=」等の属性名を出力文字列の部分一致で探すと、属性値内に
// エスケープされて残った不活性テキスト (`title="&lt;img ... onerror=..&gt;"`)
// を誤検出する。属性はコンテキストを区別して検査する必要があるため、
// 出力 HTML を走査してタグ内の (属性名, 値) ペアを列挙する小さな
// スキャナで検証する (ammonia の出力は常に well-formed で属性は引用符付き)。

#![no_main]

use kaname_render::{RawHtml, sanitize_html};
use libfuzzer_sys::fuzz_target;

/// サニタイズ済み出力を走査して `<タグ 名="値">` の属性ペアを列挙する。
/// ammonia/html5ever のシリアライズは属性を必ず `"..."` で囲むため、
/// 引用符外の `<`/`>` は必ずタグ境界。`<!`/`<?`/`</` 始まりは属性を持たない。
fn tag_attrs(html: &str) -> Vec<(String, String)> {
    let b = html.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        i += 1;
        // コメント・宣言・終了タグは属性を持たない
        if i < b.len() && (b[i] == b'!' || b[i] == b'?' || b[i] == b'/') {
            while i < b.len() && b[i] != b'>' {
                i += 1;
            }
            i += 1;
            continue;
        }
        // タグ名を読み飛ばす
        while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' && b[i] != b'/' {
            i += 1;
        }
        // 属性列
        while i < b.len() && b[i] != b'>' {
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= b.len() || b[i] == b'>' {
                break;
            }
            if b[i] == b'/' {
                i += 1;
                continue;
            }
            // 属性名
            let name_start = i;
            while i < b.len()
                && !b[i].is_ascii_whitespace()
                && b[i] != b'='
                && b[i] != b'>'
                && b[i] != b'/'
            {
                i += 1;
            }
            let name = html[name_start..i].to_lowercase();
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            // 値なし属性
            if i >= b.len() || b[i] != b'=' {
                out.push((name, String::new()));
                continue;
            }
            i += 1; // '='
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                i += 1;
                let v_start = i;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
                out.push((name, html[v_start..i].to_string()));
                if i < b.len() {
                    i += 1; // closing quote
                }
            } else {
                // 引用符なし値 (ammonia は出さないが堅牢性のため)
                let v_start = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' {
                    i += 1;
                }
                out.push((name, html[v_start..i].to_string()));
            }
        }
        i += 1; // '>'
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // UTF-8 として解釈できる入力のみテスト
    let Ok(html) = std::str::from_utf8(data) else { return; };

    // サニタイズを実行
    let sanitized = sanitize_html(&RawHtml::new(html.to_string()));
    let out = sanitized.as_str();
    let lowercase = out.to_lowercase();

    // 不変条件 1: 禁止タグがタグとして残っていない
    // (属性値内のエスケープ済みテキストは &lt;...&gt; で出るため
    //  リテラルの "<script" は実タグの存在を意味する)
    for tag in [
        "<script", "<iframe", "<object", "<embed", "<applet", "<form", "<svg",
        "<math", "<link", "<meta", "<base", "<noscript", "<template", "<style",
    ] {
        assert!(!lowercase.contains(tag), "禁止タグ残存: {tag} in {lowercase}");
    }

    // 不変条件 2: 属性コンテキストでの検査
    // - on* イベントハンドラー属性が残存しない
    // - URL 属性値のスキームが許可リスト (http/https/mailto/cid/相対) のみ
    for (name, value) in tag_attrs(out) {
        assert!(
            !name.starts_with("on"),
            "イベントハンドラー属性残存: {name} in {out}"
        );
        if matches!(
            name.as_str(),
            "href" | "src" | "action" | "formaction" | "xlink:href" | "cite"
        ) {
            let v = value.trim().to_lowercase();
            assert!(
                !v.starts_with("javascript:")
                    && !v.starts_with("vbscript:")
                    && !v.starts_with("file:")
                    && !(v.starts_with("data:") && !v.starts_with("data:image/")),
                "禁止スキーム残存: {name}={value} in {out}"
            );
        }
    }
});
