//! kaname-crypto — 定数時間比較ユーティリティ。
//!
//! 元々は「ML-KEM-768 + X25519 ハイブリッド PQC」のトレイト定義クレートだったが、
//! 実暗号バックエンドは一度も存在せず (D47)、実在する唯一の利用者は
//! `kaname-oobv` の `ct_eq`/`ct_eq_ascii_ci` だけだった — 残り全シンボル
//! (Kem/Sig トレイト・HybridX25519MlKem・Argon2Params・NonceCounter 等) は
//! 呼出元ゼロだったため削除した (D143 — git 履歴で復元可能)。
//!
//! 現行の実暗号:
//! - MLS 群鍵暗号 + PQ ハイブリッド (X-Wing) → `kaname-mls` (openmls)
//! - ストア暗号化 → `kaname-store` (SQLCipher)

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(missing_docs)]

// ============================================================================
// 定数時間比較 (タイミングサイドチャネル防止)
// ============================================================================

/// 2 つのバイト列を定数時間で比較する。
///
/// DKIM/SPF HMAC 値の検証など、タイミング攻撃が問題になる場面で使用する。
/// 長さが異なる場合は即座に `false` を返すが、これは長さ自体は秘密でないため許容。
///
/// # 実装
///
/// XOR アキュムレーターパターン: 全バイトをXORし続け、最後に0かどうかを確認。
/// 短絡評価がないため全バイトを必ず処理する。
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 文字列を定数時間で比較する (ASCII 大文字小文字を区別しない)。
///
/// DKIM `h=` タグのアルゴリズム名比較など大文字小文字を無視する場合に使用。
#[must_use]
pub fn ct_eq_ascii_ci(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x.to_ascii_lowercase() ^ y.to_ascii_lowercase();
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_equal() {
        assert!(ct_eq(b"abc", b"abc"));
    }

    #[test]
    fn ct_eq_different() {
        assert!(!ct_eq(b"abc", b"abd"));
    }

    #[test]
    fn ct_eq_different_length() {
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    #[test]
    fn ct_eq_ascii_ci_case_insensitive() {
        assert!(ct_eq_ascii_ci("Example.COM", "example.com"));
    }

    #[test]
    fn ct_eq_ascii_ci_different() {
        assert!(!ct_eq_ascii_ci("example.com", "example.org"));
    }
}
