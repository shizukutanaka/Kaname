//! ヘッダー値の CRLF インジェクション対策 (Round6 P1)。
//!
//! RFC 5322 のヘッダー値に `\r\n` や `\n` を含む入力を UI に表示すると、
//! メールヘッダーインジェクションや UI スプーフィングが起きる可能性がある。
//! 表示前に必ずこのモジュールを通すこと。

/// CRLF インジェクション検出結果。
#[derive(Debug, PartialEq, Eq)]
pub struct HeaderSanitizeResult {
    /// 正規化後の値 (改行文字を除去済み)。
    pub sanitized: String,
    /// 元の値に CRLF または LF が含まれていたか。
    pub had_injection_attempt: bool,
}

/// メールヘッダー値を表示用に安全化する。
///
/// # 処理内容
///
/// 1. `\r\n` (CRLF) を空白 1 つに置換
/// 2. 残余の `\r` と `\n` を空白に置換
/// 3. NUL バイト (`\0`) を除去
/// 4. 連続する空白を 1 つに正規化 (オプション: `collapse_whitespace = true`)
///
/// # 用途
///
/// - From: / Reply-To: / Subject: の表示前サニタイズ
/// - ログに書き込む前のヘッダー値サニタイズ
pub fn sanitize_header_value(value: &str, collapse_whitespace: bool) -> HeaderSanitizeResult {
    let mut had_injection = false;
    let mut result = String::with_capacity(value.len());

    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                had_injection = true;
                // CRLF → スペース (peek して \n を吸収)
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                result.push(' ');
            }
            '\n' => {
                had_injection = true;
                result.push(' ');
            }
            '\0' => {
                had_injection = true;
                // NUL バイトは除去
            }
            c => result.push(c),
        }
    }

    if collapse_whitespace {
        // 連続スペースを 1 つに正規化
        let mut collapsed = String::with_capacity(result.len());
        let mut prev_space = false;
        for c in result.chars() {
            if c == ' ' {
                if !prev_space {
                    collapsed.push(c);
                }
                prev_space = true;
            } else {
                collapsed.push(c);
                prev_space = false;
            }
        }
        result = collapsed;
    }

    HeaderSanitizeResult {
        sanitized: result.trim().to_string(),
        had_injection_attempt: had_injection,
    }
}

/// 複数のヘッダー値をまとめてサニタイズする。
///
/// `(sanitized, had_any_injection)` を返す。
pub fn sanitize_header_values<'a>(
    values: impl Iterator<Item = &'a str>,
    collapse_whitespace: bool,
) -> (Vec<String>, bool) {
    let mut any_injection = false;
    let sanitized = values.map(|v| {
        let r = sanitize_header_value(v, collapse_whitespace);
        if r.had_injection_attempt {
            any_injection = true;
        }
        r.sanitized
    }).collect();
    (sanitized, any_injection)
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_value_unchanged() {
        let r = sanitize_header_value("Alice <alice@example.com>", false);
        assert_eq!(r.sanitized, "Alice <alice@example.com>");
        assert!(!r.had_injection_attempt);
    }

    #[test]
    fn crlf_injection_removed() {
        let r = sanitize_header_value("Alice\r\nX-Injected: evil", false);
        assert!(r.had_injection_attempt);
        assert!(!r.sanitized.contains('\r'));
        assert!(!r.sanitized.contains('\n'));
        assert!(r.sanitized.contains("X-Injected"));
    }

    #[test]
    fn bare_lf_injection_removed() {
        let r = sanitize_header_value("Alice\nBcc: attacker@evil.com", false);
        assert!(r.had_injection_attempt);
        assert!(!r.sanitized.contains('\n'));
    }

    #[test]
    fn nul_byte_removed() {
        let r = sanitize_header_value("Alice\0<alice@example.com>", false);
        assert!(r.had_injection_attempt);
        assert!(!r.sanitized.contains('\0'));
        assert!(r.sanitized.contains("Alice"));
    }

    #[test]
    fn whitespace_collapse() {
        let r = sanitize_header_value("Alice  <alice@example.com>", true);
        assert_eq!(r.sanitized, "Alice <alice@example.com>");
    }

    #[test]
    fn crlf_becomes_single_space_with_collapse() {
        let r = sanitize_header_value("Header\r\n value", true);
        assert_eq!(r.sanitized, "Header value");
    }

    #[test]
    fn japanese_subject_unchanged() {
        let r = sanitize_header_value("請求書について (2026年6月)", false);
        assert_eq!(r.sanitized, "請求書について (2026年6月)");
        assert!(!r.had_injection_attempt);
    }

    #[test]
    fn multiple_crlf_attacks_all_caught() {
        let r = sanitize_header_value("x\r\nHeader1: a\r\nHeader2: b", false);
        assert!(r.had_injection_attempt);
        assert!(!r.sanitized.contains('\r'));
        assert!(!r.sanitized.contains('\n'));
    }

    #[test]
    fn batch_sanitize() {
        let values = vec!["Alice <alice@example.com>", "Bob\r\nX-Evil: 1"];
        let (sanitized, any) = sanitize_header_values(values.into_iter(), false);
        assert!(any);
        assert!(!sanitized[1].contains('\r'));
    }
}
