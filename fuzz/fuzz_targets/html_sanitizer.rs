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

#![no_main]

use libfuzzer_sys::fuzz_target;
use kaname_render::sanitize;

fuzz_target!(|data: &[u8]| {
    // UTF-8 として解釈できる入力のみテスト
    let Ok(html) = std::str::from_utf8(data) else { return; };

    // サニタイズを実行
    let sanitized = sanitize::sanitize_html(html);

    // 不変条件: サニタイズ後の HTML は危険なタグを含まない
    let lowercase = sanitized.to_lowercase();

    // <script> タグが残っていないこと
    assert!(!lowercase.contains("<script"), "script タグが残存: {sanitized}");

    // インラインイベントハンドラー
    let dangerous_handlers = [
        "onclick=", "onerror=", "onload=", "onmouseover=", "onfocus=",
        "onblur=", "onsubmit=", "onchange=", "onkeyup=", "onkeydown=",
    ];
    for handler in &dangerous_handlers {
        assert!(!lowercase.contains(handler),
            "イベントハンドラー残存: {handler} in {sanitized}");
    }

    // javascript: URI
    assert!(!lowercase.contains("javascript:"),
        "javascript: URI 残存: {sanitized}");

    // data: URI (画像以外)
    if lowercase.contains("data:") {
        assert!(
            lowercase.contains("data:image/"),
            "image 以外の data: URI 残存: {sanitized}"
        );
    }

    // <iframe>, <object>, <embed>
    for tag in ["<iframe", "<object", "<embed", "<applet", "<form"] {
        assert!(!lowercase.contains(tag),
            "禁止タグ残存: {tag} in {sanitized}");
    }
});
