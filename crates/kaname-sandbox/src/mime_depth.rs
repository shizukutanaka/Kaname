//! MIME ネスト深度チェック — スタックオーバーフロー防止 (Qiita osanshouo 由来)。
//!
//! Safe Rust でも再帰でスタックオーバーフローが起きる。
//! MIME パート / MLS ツリーをたどる際は深度を明示的に制限する。

/// MIME ネストの最大許容深度。
pub const MAX_MIME_DEPTH: u8 = 50;

/// MIME 深度チェックエラー。
#[derive(Debug, PartialEq, Eq)]
pub struct MimeDepthError {
    /// 検出された深度。
    pub depth: usize,
    /// 許容最大深度。
    pub max: u8,
}

impl std::fmt::Display for MimeDepthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MIME 深度超過: {} > {}", self.depth, self.max)
    }
}

/// `multipart/` 境界をたどって最大ネスト深度を計算する (非再帰)。
///
/// 再帰を使わずスタック枯渇を防ぐイテレーティブ実装。
///
/// # アルゴリズム
///
/// バイト列を線形スキャンし、`Content-Type: multipart/` ヘッダーが
/// 出現するたびに深度カウンタをインクリメント。対応する `--boundary--`
/// (終端境界) で深度をデクリメント。
///
/// 簡易実装のため正確な RFC 2046 パーサーではなく、
/// `multipart/` の出現回数を深度として近似する。
///
/// # Errors
///
/// 深度が `MAX_MIME_DEPTH` を超えると `MimeDepthError` を返す。
pub fn check_mime_depth(data: &[u8], max_depth: u8) -> Result<u8, MimeDepthError> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Ok(0); // バイナリ — MIME ヘッダーなし
    };

    let mut depth: usize = 0;
    let mut max_seen: usize = 0;

    // 行ごとにスキャン
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("content-type:") && lower.contains("multipart/") {
            depth = depth.saturating_add(1);
            if depth > max_seen {
                max_seen = depth;
            }
            if max_seen > usize::from(max_depth) {
                return Err(MimeDepthError {
                    depth: max_seen,
                    max: max_depth,
                });
            }
        }
        // 終端境界 "--...--" (シンプルなヒューリスティック)
        let trimmed = line.trim();
        if trimmed.starts_with("--") && trimmed.ends_with("--") && trimmed.len() > 4 {
            depth = depth.saturating_sub(1);
        }
    }

    Ok(u8::try_from(max_seen).unwrap_or(u8::MAX))
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn flat_message_depth_zero() {
        let data = b"From: alice@example.com\r\nContent-Type: text/plain\r\n\r\nHello";
        let depth = check_mime_depth(data, MAX_MIME_DEPTH).unwrap();
        assert_eq!(depth, 0);
    }

    #[test]
    fn single_multipart_depth_one() {
        let data = b"Content-Type: multipart/mixed; boundary=\"b\"\r\n\
                    \r\n\
                    --b\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    hello\r\n\
                    --b--\r\n";
        let depth = check_mime_depth(data, MAX_MIME_DEPTH).unwrap();
        assert_eq!(depth, 1);
    }

    #[test]
    fn nested_multipart_detected() {
        let data = b"Content-Type: multipart/mixed; boundary=\"a\"\r\n\
                    \r\n\
                    --a\r\n\
                    Content-Type: multipart/alternative; boundary=\"b\"\r\n\
                    \r\n\
                    --b\r\n\
                    Content-Type: text/plain\r\n\
                    hello\r\n\
                    --b--\r\n\
                    --a--\r\n";
        let depth = check_mime_depth(data, MAX_MIME_DEPTH).unwrap();
        assert_eq!(depth, 2);
    }

    #[test]
    fn excessive_nesting_is_rejected() {
        // 51 段ネストの MIME を生成
        let mut data = String::new();
        for i in 0..51u8 {
            use std::fmt::Write as _;
            let _ = write!(data, "Content-Type: multipart/mixed; boundary=\"b{i}\"\r\n\r\n--b{i}\r\n");
        }
        let result = check_mime_depth(data.as_bytes(), MAX_MIME_DEPTH);
        assert!(result.is_err(), "過剰なネストは拒否されるべき");
        let err = result.unwrap_err();
        assert!(err.depth > usize::from(MAX_MIME_DEPTH));
    }

    #[test]
    fn binary_data_returns_zero() {
        let data = [0xFFu8, 0xFE, 0x00, 0x01, 0xAB, 0xCD];
        let depth = check_mime_depth(&data, MAX_MIME_DEPTH).unwrap();
        assert_eq!(depth, 0, "バイナリデータは深度 0 を返すべき");
    }

    #[test]
    fn custom_max_depth_respected() {
        let data = b"Content-Type: multipart/mixed; boundary=\"a\"\r\n\r\n--a\r\n\
                    Content-Type: multipart/alternative; boundary=\"b\"\r\n\r\n--b--\r\n--a--\r\n";
        // max_depth=1 の場合、深度 2 は拒否
        let result = check_mime_depth(data, 1);
        assert!(result.is_err());
    }
}
