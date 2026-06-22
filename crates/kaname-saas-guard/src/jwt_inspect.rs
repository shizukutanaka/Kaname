//! JWT 構造インスペクター (algorithm confusion 攻撃対策)。
//!
//! # 脅威
//!
//! JWT の `alg` ヘッダーを攻撃者が書き換えることで認証をバイパスする。
//!
//! ## alg:none 攻撃 (CVE-2025-4692, CVSS 9.8)
//! `{"alg":"nOnE","typ":"JWT"}` — 大文字小文字変形で署名検証をスキップ。
//!
//! ## RS256→HS256 混乱攻撃
//! 公開鍵を HMAC シークレットとして使い、`alg: HS256` トークンを生成。
//! 検証側が公開鍵を HS256 の鍵として使ってしまうと受け入れる。
//!
//! # 実装方針
//!
//! Kaname は JWT を直接発行しないため、`alg` フィールドの**事前検査**のみ実装。
//! 検証は外部 IdP (OIDC) に委ねる。このモジュールはトークンが
//! 想定アルゴリズムを使っているかを確認する入口チェックを提供する。

use thiserror::Error;

/// JWT アルゴリズム検査エラー。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum JwtInspectError {
    /// JWT の形式が不正 (ピリオドが 2 個ない)。
    #[error("JWT の形式が不正です")]
    MalformedToken,
    /// Base64 デコードに失敗した。
    #[error("JWT ヘッダーのデコードに失敗しました")]
    DecodeError,
    /// `alg` フィールドが見つからない。
    #[error("JWT ヘッダーに alg フィールドがありません")]
    MissingAlg,
    /// `alg: none` または類似の危険なアルゴリズムが指定されている。
    #[error("危険なアルゴリズム指定: {0:?}")]
    NoneAlgorithm(String),
    /// 想定外のアルゴリズムが指定されている。
    #[error("許可されていないアルゴリズム: {got:?} (期待: {expected:?})")]
    UnexpectedAlgorithm {
        /// 実際に使われていたアルゴリズム。
        got: String,
        /// 期待していたアルゴリズム。
        expected: String,
    },
}

/// JWT が指定アルゴリズムを使っているかを事前検査する。
///
/// 署名検証は行わない。`alg` ヘッダーフィールドの確認のみ。
///
/// # 引数
///
/// - `token`: `header.payload.signature` 形式の JWT 文字列
/// - `expected_alg`: 期待するアルゴリズム名 (例: `"RS256"`, `"ES256"`)
///
/// # Errors
///
/// - `alg: none` (大文字小文字変形を含む) → `NoneAlgorithm`
/// - 期待と異なるアルゴリズム → `UnexpectedAlgorithm`
/// - JWT 形式不正 → `MalformedToken` / `DecodeError` / `MissingAlg`
pub fn inspect_alg(token: &str, expected_alg: &str) -> Result<(), JwtInspectError> {
    let header_b64 = token.split('.').next().ok_or(JwtInspectError::MalformedToken)?;

    // ピリオドが 2 個あることを確認
    if token.split('.').count() != 3 {
        return Err(JwtInspectError::MalformedToken);
    }

    // Base64url デコード (パディングなし)
    let decoded = base64url_decode(header_b64).map_err(|()| JwtInspectError::DecodeError)?;
    let header_str = std::str::from_utf8(&decoded).map_err(|_| JwtInspectError::DecodeError)?;

    // `alg` フィールドを JSON から手動抽出
    let alg = extract_alg_field(header_str).ok_or(JwtInspectError::MissingAlg)?;

    // none 攻撃検出 (大文字小文字バリエーション含む)
    if alg.eq_ignore_ascii_case("none") {
        return Err(JwtInspectError::NoneAlgorithm(alg));
    }

    // アルゴリズム一致チェック (大文字小文字非依存)
    if !alg.eq_ignore_ascii_case(expected_alg) {
        return Err(JwtInspectError::UnexpectedAlgorithm {
            got: alg,
            expected: expected_alg.to_string(),
        });
    }

    Ok(())
}

/// `alg` フィールド値を JSON ヘッダー文字列から抽出する (簡易パーサー)。
///
/// 完全な JSON パーサーは使わず、`"alg"` キーの直後の文字列値を探す。
fn extract_alg_field(header_json: &str) -> Option<String> {
    // "alg" : "value" パターンを探す
    let pos = header_json.find("\"alg\"")?;
    let rest = &header_json[pos + 5..]; // `"alg"` の後

    // `:` を探す
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();

    // 文字列値を取得
    if let Some(inner) = after_colon.strip_prefix('"') {
        let end = inner.find('"')?;
        Some(inner[..end].to_string())
    } else {
        None
    }
}

/// Base64url (パディングなし) をデコードする。
fn base64url_decode(input: &str) -> Result<Vec<u8>, ()> {
    // パディングを追加
    let pad = match input.len() % 4 {
        2 => "==",
        3 => "=",
        _ => "",
    };
    let padded = format!("{input}{pad}");
    // URL-safe base64 → standard base64 変換
    let standard: String = padded.chars().map(|c| match c {
        '-' => '+',
        '_' => '/',
        other => other,
    }).collect();

    base64_decode(&standard)
}

/// 標準 Base64 デコード (依存クレートなし)。
fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    const TABLE: &[u8; 128] = b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\
                                  \x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\
                                  \x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x3E\x80\x80\x80\x3F\
                                  \x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x80\x80\x80\x40\x80\x80\
                                  \x80\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\
                                  \x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x80\x80\x80\x80\x80\
                                  \x80\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\
                                  \x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x80\x80\x80\x80\x80";

    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    if bytes.len() % 4 == 1 {
        return Err(());
    }

    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let vals: Vec<u8> = chunk.iter().map(|&b| {
            if b < 128 { TABLE[b as usize] } else { 0x80 }
        }).collect();

        if vals.contains(&0x80) {
            return Err(());
        }

        match chunk.len() {
            4 => {
                result.push((vals[0] << 2) | (vals[1] >> 4));
                result.push((vals[1] << 4) | (vals[2] >> 2));
                result.push((vals[2] << 6) | vals[3]);
            }
            3 => {
                result.push((vals[0] << 2) | (vals[1] >> 4));
                result.push((vals[1] << 4) | (vals[2] >> 2));
            }
            2 => {
                result.push((vals[0] << 2) | (vals[1] >> 4));
            }
            _ => return Err(()),
        }
    }
    Ok(result)
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// `{"alg":"RS256","typ":"JWT"}` の base64url エンコード
    const HEADER_RS256: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
    /// `{"alg":"HS256","typ":"JWT"}` の base64url エンコード
    const HEADER_HS256: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    /// `{"alg":"none","typ":"JWT"}` の base64url エンコード
    const HEADER_NONE: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
    /// `{"alg":"nOnE","typ":"JWT"}` の base64url エンコード (大文字小文字バリエーション)
    const HEADER_NONE_CASE: &str = "eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0";

    fn make_token(header_b64: &str) -> String {
        format!("{header_b64}.payload.signature")
    }

    #[test]
    fn rs256_token_passes_rs256_check() {
        assert!(inspect_alg(&make_token(HEADER_RS256), "RS256").is_ok());
    }

    #[test]
    fn hs256_token_fails_rs256_check() {
        let err = inspect_alg(&make_token(HEADER_HS256), "RS256").unwrap_err();
        assert!(matches!(err, JwtInspectError::UnexpectedAlgorithm { .. }),
            "HS256 トークンは RS256 期待時に拒否されるべき");
    }

    #[test]
    fn none_algorithm_rejected() {
        let err = inspect_alg(&make_token(HEADER_NONE), "RS256").unwrap_err();
        assert!(matches!(err, JwtInspectError::NoneAlgorithm(_)),
            "alg:none は拒否されるべき");
    }

    #[test]
    fn none_case_variation_rejected() {
        let err = inspect_alg(&make_token(HEADER_NONE_CASE), "RS256").unwrap_err();
        assert!(matches!(err, JwtInspectError::NoneAlgorithm(_)),
            "alg:nOnE の大文字小文字バリエーションも拒否されるべき");
    }

    #[test]
    fn malformed_token_two_parts_rejected() {
        let err = inspect_alg("header.payload", "RS256").unwrap_err();
        assert_eq!(err, JwtInspectError::MalformedToken);
    }

    #[test]
    fn malformed_token_one_part_rejected() {
        let err = inspect_alg("onlyheader", "RS256").unwrap_err();
        assert_eq!(err, JwtInspectError::MalformedToken);
    }

    #[test]
    fn hs256_accepts_hs256_expected() {
        assert!(inspect_alg(&make_token(HEADER_HS256), "HS256").is_ok());
    }

    #[test]
    fn algorithm_check_case_insensitive() {
        // 期待値が小文字でも一致する
        assert!(inspect_alg(&make_token(HEADER_RS256), "rs256").is_ok());
    }

    #[test]
    fn extract_alg_basic() {
        assert_eq!(
            extract_alg_field(r#"{"alg":"RS256","typ":"JWT"}"#),
            Some("RS256".to_string())
        );
    }

    #[test]
    fn extract_alg_missing_returns_none() {
        assert_eq!(extract_alg_field(r#"{"typ":"JWT"}"#), None);
    }

    #[test]
    fn base64url_decode_roundtrip() {
        // "Hello" → "SGVsbG8"
        let decoded = base64url_decode("SGVsbG8").unwrap();
        assert_eq!(decoded, b"Hello");
    }
}
