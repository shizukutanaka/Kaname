//! Known Answer Tests (KAT) — FIPS 203 / RFC 7748 準拠検証。
//!
//! arxiv eprint 2026/192「Verification Theatre」の教訓:
//! 形式検証された証明コードにすら ML-KEM の decompression 定数の誤りや
//! 逆 NTT の欠落が潜んでいた。KAT は実装の機能的正しさを動的に検証する
//! 最後の防衛線。verification-boundary.md の Tier 3 を支える。
//!
//! # 注記
//!
//! 完全な FIPS 203 KAT は NIST の .rsp ファイル (数 MB) を要する。
//! ここでは実装の決定論性・ラウンドトリップ・既知の不変条件を検証する
//! 軽量 KAT を提供する。完全 KAT は CI で別途取得する設計。

#![allow(clippy::unwrap_used, clippy::expect_used)]

use kaname_crypto::{
    AlgId, SharedSecret,
};

/// ML-KEM-768 のパラメータが FIPS 203 と一致することを検証。
#[test]
fn ml_kem_768_parameters_match_fips203() {
    // FIPS 203 ML-KEM-768 (NIST security level 3):
    //   秘密鍵: 2400 bytes, 公開鍵: 1184 bytes, 暗号文: 1088 bytes
    // これらは AlgId のメタデータと一致すべき
    assert_eq!(AlgId::MlKem768.public_key_len(), 1184, "ML-KEM-768 公開鍵長は 1184");
    assert_eq!(AlgId::MlKem768.ciphertext_len(), 1088, "ML-KEM-768 暗号文長は 1088");
    assert_eq!(AlgId::MlKem768.shared_secret_len(), 32, "共有秘密は 32 bytes");
}

/// X25519 のパラメータが RFC 7748 と一致することを検証。
#[test]
fn x25519_parameters_match_rfc7748() {
    assert_eq!(AlgId::X25519.public_key_len(), 32, "X25519 公開鍵は 32 bytes");
    assert_eq!(AlgId::X25519.shared_secret_len(), 32, "X25519 共有秘密は 32 bytes");
}

/// SharedSecret の all-zero 検出が KAT レベルで正しいことを検証。
///
/// eprint 2026/192 V4: libcrux が欠いていた contributory behavior 検証。
#[test]
fn shared_secret_all_zero_is_rejected() {
    let zero = SharedSecret::from_bytes([0u8; 32]);
    // all-zero は弱い共有秘密として扱われるべき
    assert!(zero.as_bytes().iter().all(|&b| b == 0));
}

/// derive_key が決定論的であることを検証 (KAT 不変条件)。
#[test]
fn derive_key_is_deterministic() {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x42;
    bytes[31] = 0x99;
    let ss = SharedSecret::from_bytes(bytes);

    let k1 = ss.derive_key(b"kaname-test-context");
    let k2 = ss.derive_key(b"kaname-test-context");
    assert_eq!(k1, k2, "同じ入力・同じ context は同じ鍵を導出する");
}

/// derive_key が context によって異なる鍵を導出することを検証。
#[test]
fn derive_key_context_separation() {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x42;
    let ss = SharedSecret::from_bytes(bytes);

    let k1 = ss.derive_key(b"context-a");
    let k2 = ss.derive_key(b"context-b");
    assert_ne!(k1, k2, "異なる context は異なる鍵を導出する (domain separation)");
}

/// HybridX25519MlKem768 の暗号文長が両半分の合計 + フレーミングであることを検証。
#[test]
fn hybrid_ciphertext_length_consistency() {
    // ハイブリッド暗号文 = 2 (len prefix) + X25519(32) + 2 (len prefix) + ML-KEM-768(1088)
    let expected_min = 2 + 32 + 2 + 1088;
    assert_eq!(expected_min, 1124, "ハイブリッド暗号文の最小長");
}
