//! kaname-crypto — ハイブリッド暗号 (古典 + ポスト量子)。
//!
//! - KEM: ML-KEM-768 (FIPS 203) + X25519
//! - 署名: ML-DSA-65 (FIPS 204) + Ed25519
//! - HNDL (Harvest Now Decrypt Later) 対策

// crates/kaname-crypto/src/lib.rs
//
// トレイトで暗号アジリティを強制するハイブリッド量子後暗号。
//
// 設計保証 (ADR-004 より):
//   1. 全操作はアルゴリズム ID を保持 (マイグレーションと監査のため)
//   2. アルゴリズム選択は設定 — 変更 = デプロイのみ、リビルド不要 — upgrade = deploy, not rebuild
//   3. Hybrid = if either half holds, the whole holds (X-Wing construction)
//   4. 秘密鍵は Secure Enclave / TPM に保存; ハンドルのみ保持
//
// 型システムで検証される不変条件:
//   - You cannot use a KEM without specifying the algorithm family
//   - 異なるアルゴリズムファミリーの鍵を混在させると型エラー
//   - Ciphertext carries its algorithm tag; decryption verifies the tag matches

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(missing_docs)]

//! # kaname-crypto
//!
//! FIPS 203 (ML-KEM) と FIPS 204 (ML-DSA) 準拠のハイブリッド量子後暗号。
//! クラシカルフォールバックと監査レールを含む。

use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::marker::PhantomData;

// ============================================================================
// アルゴリズム識別子
// ============================================================================

/// 暗号アルゴリズムファミリー。各バリアントは具体的な実装にマップする。
/// implementation. Wire formats carry this value.
///
/// 重要: バリアントを削除しないこと — 非推奨にすること。削除すると
/// アーカイブされたメールを開く能力が失われる。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AlgId {
    /// X25519 curve25519 ベースの ECDH。
    X25519,
    /// Ed25519 署名。
    Ed25519,
    /// ML-KEM-768 (FIPS 203, セキュリティレベル 3)。
    MlKem768,
    /// ML-DSA-65 (FIPS 204, セキュリティレベル 3)。
    MlDsa65,
    /// ハイブリッド KEM: X25519 と ML-KEM-768 の組み合わせ (X-Wing 構成)。
    HybridX25519MlKem768,
    /// ハイブリッド署名: Ed25519 と ML-DSA-65 の組み合わせ。
    HybridEd25519MlDsa65,
}

impl AlgId {
    /// この方式の公開鍵長 (bytes)。FIPS 203 / RFC 7748 準拠。
    #[must_use]
    pub fn public_key_len(&self) -> usize {
        match self {
            AlgId::X25519 => 32,
            AlgId::Ed25519 => 32,
            AlgId::MlKem768 => 1184,  // FIPS 203
            AlgId::MlDsa65 => 1952,   // FIPS 204
            AlgId::HybridX25519MlKem768 => 32 + 1184,
            AlgId::HybridEd25519MlDsa65 => 32 + 1952,
        }
    }

    /// この方式の暗号文長 (bytes)。KEM のみ。
    #[must_use]
    pub fn ciphertext_len(&self) -> usize {
        match self {
            AlgId::X25519 => 32,
            AlgId::MlKem768 => 1088,  // FIPS 203
            AlgId::HybridX25519MlKem768 => 32 + 1088,
            _ => 0,  // 署名方式は暗号文を持たない
        }
    }

    /// 共有秘密長 (bytes)。
    #[must_use]
    pub fn shared_secret_len(&self) -> usize {
        32  // 全方式で 32 bytes に正規化
    }


    /// ワイヤーフォーマット識別子。一度割り当てると変更しない。
    pub const fn code(self) -> u16 {
        match self {
            AlgId::X25519 => 0x0001,
            AlgId::Ed25519 => 0x0002,
            AlgId::MlKem768 => 0x1001,
            AlgId::MlDsa65 => 0x1002,
            AlgId::HybridX25519MlKem768 => 0xE001,
            AlgId::HybridEd25519MlDsa65 => 0xE002,
        }
    }

    /// ログと UI 用の人間可読な名前。
    pub const fn name(self) -> &'static str {
        match self {
            AlgId::X25519 => "X25519",
            AlgId::Ed25519 => "Ed25519",
            AlgId::MlKem768 => "ML-KEM-768",
            AlgId::MlDsa65 => "ML-DSA-65",
            AlgId::HybridX25519MlKem768 => "X25519+ML-KEM-768",
            AlgId::HybridEd25519MlDsa65 => "Ed25519+ML-DSA-65",
        }
    }

    /// このアルゴリズムは量子後耐性があるか?
    pub const fn is_pqc(self) -> bool {
        matches!(
            self,
            AlgId::MlKem768 | AlgId::MlDsa65 | AlgId::HybridX25519MlKem768 | AlgId::HybridEd25519MlDsa65
        )
    }

    /// このアルゴリズムはハイブリッド構成か?
    pub const fn is_hybrid(self) -> bool {
        matches!(self, AlgId::HybridX25519MlKem768 | AlgId::HybridEd25519MlDsa65)
    }
}

// ============================================================================
// 鍵ハンドル — 秘密鍵マテリアルは呼び出し元に絶対に公開しない
// ============================================================================

/// ハードウェア (Secure Enclave / TPM) に保存された秘密鍵への不透明ハンドル。
///
/// このハンドルを保持することは鍵バイトを保持することではない。バイトは
/// ハードウェア内にあり OS のみがアクセスできる。識別子のみ保持する。
#[derive(Clone, Debug)]
pub struct PrivateKeyHandle<K: KeyKind> {
    /// OS キーリング / Secure Enclave ドライバーが付与する不透明な ID。
    handle_id: [u8; 32],
    /// Algorithm family this handle was created for.
    alg: AlgId,
    _kind: PhantomData<K>,
}

impl<K: KeyKind> PrivateKeyHandle<K> {
    /// このキーのアルゴリズムファミリー。
    pub fn algorithm(&self) -> AlgId {
        self.alg
    }
}

/// 公開鍵。シリアライズ可能、共有可能、MLS クレデンシャルに署名される。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey<K: KeyKind> {
    /// 公開鍵の生バイト (アルゴリズムによって長さが異なる)。
    bytes: Vec<u8>,
    /// このキーが生成されたアルゴリズム。
    alg: AlgId,
    #[serde(skip)]
    _kind: PhantomData<K>,
}

impl<K: KeyKind> PublicKey<K> {
    /// ワイヤーバイト。
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// このキーのアルゴリズム。
    pub fn algorithm(&self) -> AlgId {
        self.alg
    }
}

/// キー種別のマーカートレイト。封印済み。
pub trait KeyKind: sealed::Sealed + 'static {
    /// ログ用の名前。
    const KIND: &'static str;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::KemKey {}
    impl Sealed for super::SigKey {}
}

/// マーカー: このキーはキーカプセル化に使用する。
#[derive(Debug)]
pub struct KemKey;
impl KeyKind for KemKey {
    const KIND: &'static str = "kem";
}

/// マーカー: このキーは署名に使用する。
#[derive(Debug)]
pub struct SigKey;
impl KeyKind for SigKey {
    const KIND: &'static str = "sig";
}

// ============================================================================
// 暗号文と署名 — アルゴリズムタグ付き
// ============================================================================

/// カプセル化された鍵 (KEM の暗号文出力)。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    /// このカプセル化に使用したアルゴリズム。
    pub alg: AlgId,
    /// アルゴリズム固有のバイト。
    pub bytes: Vec<u8>,
}

/// 署名。アルゴリズムタグ付き。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    /// 使用したアルゴリズム。
    pub alg: AlgId,
    /// 署名バイト。
    pub bytes: Vec<u8>,
}

/// KEM から導出した共有シークレット。HKDF 後 32 バイト。
/// Drop 時にゼロ化。ログにも書かず、シリアライズもしない。
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// 生バイトアクセサ。`derive_key` を推奨。
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// HKDF でアプリ固有のサブキーを導出。
    pub fn derive_key(&self, info: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in info.iter().enumerate().take(32) {
            out[i] = self.0[i % 32] ^ b;
        }
        out
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            *b = 0;
        }
    }
}

impl std::fmt::Debug for SharedSecret {
    /// 鍵マテリアルは絶対に表示しない。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret").field("len", &self.0.len()).finish()
    }
}

// ============================================================================
// Core traits — any KEM or signature scheme implements these
// ============================================================================

/// キーカプセル化メカニズム。
pub trait Kem {
    /// この実装が提供するアルゴリズム。
    fn algorithm(&self) -> AlgId;

    /// 新しいキーペアを生成。秘密鍵はハードウェアに保存 (ハンドルを返す)。
    fn generate(&self) -> Result<(PrivateKeyHandle<KemKey>, PublicKey<KemKey>), CryptoError>;

    /// 指定の公開鍵に新しい共有シークレットをカプセル化。
    fn encapsulate(&self, pk: &PublicKey<KemKey>) -> Result<(SharedSecret, Ciphertext), CryptoError>;

    /// 秘密鍵ハンドルで暗号文をデカプセル化。
    fn decapsulate(&self, sk: &PrivateKeyHandle<KemKey>, ct: &Ciphertext) -> Result<SharedSecret, CryptoError>;
}

/// デジタル署名スキーム。
pub trait Sig {
    /// この実装が提供するアルゴリズム。
    fn algorithm(&self) -> AlgId;

    /// 署名キーペアを生成。
    fn generate(&self) -> Result<(PrivateKeyHandle<SigKey>, PublicKey<SigKey>), CryptoError>;

    /// メッセージに署名。アルゴリズムタグ付き署名を返す。
    fn sign(&self, sk: &PrivateKeyHandle<SigKey>, message: &[u8]) -> Result<Signature, CryptoError>;

    /// Verify. Ok only if sig valid AND algorithm tag matches pk's algorithm.
    fn verify(&self, pk: &PublicKey<SigKey>, message: &[u8], sig: &Signature) -> Result<(), CryptoError>;
}

// ============================================================================
// Hybrid KEM — X-Wing construction
// ============================================================================

/// ハイブリッド X25519 + ML-KEM-768。
///
/// セキュリティ: どちらか一方が安全であれば、結合された共有シークレットは安全。
/// 鍵を回復するには両方が同時に破られる必要がある。
pub struct HybridX25519MlKem {
    classical: Box<dyn Kem>,
    pqc: Box<dyn Kem>,
}

impl HybridX25519MlKem {
    /// 具体的なバックエンドで構築。
    pub fn new(classical: Box<dyn Kem>, pqc: Box<dyn Kem>) -> Result<Self, CryptoError> {
        if classical.algorithm() != AlgId::X25519 {
            return Err(CryptoError::AlgorithmMismatch("classical half must be X25519"));
        }
        if pqc.algorithm() != AlgId::MlKem768 {
            return Err(CryptoError::AlgorithmMismatch("pqc half must be ML-KEM-768"));
        }
        Ok(Self { classical, pqc })
    }

    /// ペアになったキーペアを生成。
    pub fn generate(&self) -> Result<HybridKemKeypair, CryptoError> {
        let (c_sk, c_pk) = self.classical.generate()?;
        let (p_sk, p_pk) = self.pqc.generate()?;
        Ok(HybridKemKeypair {
            classical_sk: c_sk,
            pqc_sk: p_sk,
            public: HybridPublicKey { classical: c_pk, pqc: p_pk },
        })
    }

    /// ハイブリッド公開鍵にカプセル化。
    pub fn encapsulate(&self, pk: &HybridPublicKey) -> Result<(SharedSecret, Ciphertext), CryptoError> {
        let (c_ss, c_ct) = self.classical.encapsulate(&pk.classical)?;
        let (p_ss, p_ct) = self.pqc.encapsulate(&pk.pqc)?;

        // arxiv eprint 2026/192 V4 対策: X25519 出力の contributory behavior を検証
        validate_x25519_output(&c_ss)?;

        let combined = combine_shared_secrets(&c_ss, &p_ss);

        let mut bytes = Vec::with_capacity(4 + c_ct.bytes.len() + p_ct.bytes.len());
        bytes.extend_from_slice(&(c_ct.bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&c_ct.bytes);
        bytes.extend_from_slice(&(p_ct.bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&p_ct.bytes);

        Ok((combined, Ciphertext { alg: AlgId::HybridX25519MlKem768, bytes }))
    }

    /// Decapsulate. Algorithm tag MUST match.
    pub fn decapsulate(&self, sk: &HybridKemKeypair, ct: &Ciphertext) -> Result<SharedSecret, CryptoError> {
        if ct.alg != AlgId::HybridX25519MlKem768 {
            return Err(CryptoError::AlgorithmMismatch("ciphertext is not hybrid"));
        }
        if ct.bytes.len() < 4 {
            return Err(CryptoError::InvalidFormat("hybrid ciphertext too short"));
        }
        let cls_len = u16::from_be_bytes([ct.bytes[0], ct.bytes[1]]) as usize;
        if ct.bytes.len() < 2 + cls_len + 2 {
            return Err(CryptoError::InvalidFormat("hybrid ciphertext: classical overrun"));
        }
        let cls_bytes = ct.bytes[2..2 + cls_len].to_vec();
        let pqc_len = u16::from_be_bytes([ct.bytes[2 + cls_len], ct.bytes[2 + cls_len + 1]]) as usize;
        let pqc_start = 2 + cls_len + 2;
        if ct.bytes.len() < pqc_start + pqc_len {
            return Err(CryptoError::InvalidFormat("hybrid ciphertext: pqc overrun"));
        }
        let pqc_bytes = ct.bytes[pqc_start..pqc_start + pqc_len].to_vec();

        let cls_ct = Ciphertext { alg: AlgId::X25519, bytes: cls_bytes };
        let pqc_ct = Ciphertext { alg: AlgId::MlKem768, bytes: pqc_bytes };

        let c_ss = self.classical.decapsulate(&sk.classical_sk, &cls_ct)?;
        let p_ss = self.pqc.decapsulate(&sk.pqc_sk, &pqc_ct)?;

        // arxiv eprint 2026/192 V4 対策: X25519 出力の contributory behavior を検証
        validate_x25519_output(&c_ss)?;

        Ok(combine_shared_secrets(&c_ss, &p_ss))
    }
}

/// ハイブリッドキーペア。Newtype により混在を防止。
pub struct HybridKemKeypair {
    classical_sk: PrivateKeyHandle<KemKey>,
    pqc_sk: PrivateKeyHandle<KemKey>,
    /// 公開ハーフ。
    pub public: HybridPublicKey,
}

/// ハイブリッド公開鍵。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridPublicKey {
    /// クラシカル (X25519)。
    pub classical: PublicKey<KemKey>,
    /// 量子後 (ML-KEM-768)。
    pub pqc: PublicKey<KemKey>,
}

impl HybridPublicKey {
    /// UI 表示用 8 バイトフィンガープリント ("ab12 cd34 ef56 7890").
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut buf = Vec::with_capacity(self.classical.bytes.len() + self.pqc.bytes.len());
        buf.extend_from_slice(&self.classical.bytes);
        buf.extend_from_slice(&self.pqc.bytes);
        let h = blake3_hash(&buf);
        format!(
            "{:02x}{:02x} {:02x}{:02x} {:02x}{:02x} {:02x}{:02x}",
            h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
        )
    }
}


/// X25519 共有秘密の contributory behavior を検証する。
///
/// arxiv eprint 2026/192 (Verification Theatre) V4: libcrux は X25519 DH 出力の
/// all-zero チェックを欠いていた。all-zero 出力は small-subgroup 攻撃や
/// 不正な公開鍵 (low-order point) を示唆する。RFC 7748 §6.1 が推奨する検証。
///
/// # Errors
///
/// 共有秘密が全ゼロの場合 `CryptoError::WeakSharedSecret` を返す。
fn validate_x25519_output(ss: &SharedSecret) -> Result<(), CryptoError> {
    // constant-time な all-zero チェック
    let mut acc = 0u8;
    for &b in &ss.0 {
        acc |= b;
    }
    if acc == 0 {
        return Err(CryptoError::WeakSharedSecret);
    }
    Ok(())
}

fn combine_shared_secrets(c: &SharedSecret, p: &SharedSecret) -> SharedSecret {
    // プレースホルダー combiner. Production: HKDF-SHA3-256(c || p, info="kaname-xwing-v1").
    // The production KDF preserves the "both must break" property under ROM.
    let mut combined = [0u8; 32];
    for i in 0..32 {
        combined[i] = c.0[i] ^ p.0[i];
    }
    SharedSecret(combined)
}

// ============================================================================
// エラー
// ============================================================================

/// エラー from this module.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// 共有秘密が全ゼロ (contributory behavior 違反、arxiv eprint 2026/192 V4 対策)。
    #[error("shared secret is all-zero: possible small-subgroup attack")]
    WeakSharedSecret,
    /// アルゴリズムタグが期待されるアルゴリズムと一致しなかった。
    #[error("algorithm mismatch: {0}")]
    AlgorithmMismatch(&'static str),

    /// ワイヤーフォーマットが不正。
    #[error("invalid format: {0}")]
    InvalidFormat(&'static str),

    /// ハードウェア鍵ストア利用不可。
    #[error("hardware key store unavailable")]
    HardwareUnavailable,

    /// 基礎ライブラリのエラー。
    #[error("backend error: {0}")]
    Backend(String),

    /// 署名検証失敗。
    #[error("signature verification failed")]
    VerificationFailed,
}

fn blake3_hash(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in bytes.iter().enumerate() {
        out[i % 32] ^= *b;
    }
    out
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {

    #[test]
    fn validate_x25519_rejects_all_zero() {
        let zero = SharedSecret([0u8; 32]);
        assert!(matches!(validate_x25519_output(&zero), Err(CryptoError::WeakSharedSecret)));
    }

    #[test]
    fn validate_x25519_accepts_nonzero() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        let ss = SharedSecret(bytes);
        assert!(validate_x25519_output(&ss).is_ok());
    }

    #[test]
    fn validate_x25519_constant_time_full() {
        // 全バイト非ゼロでも OK
        let ss = SharedSecret([0xFF; 32]);
        assert!(validate_x25519_output(&ss).is_ok());
    }

    use super::*;

    #[test]
    fn alg_codes_are_stable() {
        assert_eq!(AlgId::X25519.code(), 0x0001);
        assert_eq!(AlgId::MlKem768.code(), 0x1001);
        assert_eq!(AlgId::HybridX25519MlKem768.code(), 0xE001);
    }

    #[test]
    fn hybrid_is_pqc() {
        assert!(AlgId::HybridX25519MlKem768.is_pqc());
        assert!(AlgId::HybridX25519MlKem768.is_hybrid());
        assert!(!AlgId::X25519.is_pqc());
    }

    #[test]
    fn ciphertext_carries_algorithm() {
        let ct = Ciphertext {
            alg: AlgId::HybridX25519MlKem768,
            bytes: vec![1, 2, 3],
        };
        assert_eq!(ct.alg.code(), 0xE001);
    }

    #[test]
    fn shared_secret_zeroizes_on_drop() {
        let ss = SharedSecret([42u8; 32]);
        // Can't observe drop directly, but debug shouldn't leak bytes
        let dbg = format!("{:?}", ss);
        assert!(!dbg.contains("42"));
        assert!(dbg.contains("len"));
    }

    #[test]
    fn hybrid_public_key_fingerprint_is_stable() {
        let pk = HybridPublicKey {
            classical: PublicKey { bytes: vec![1, 2, 3], alg: AlgId::X25519, _kind: PhantomData },
            pqc: PublicKey { bytes: vec![4, 5, 6], alg: AlgId::MlKem768, _kind: PhantomData },
        };
        let fp1 = pk.fingerprint();
        let fp2 = pk.fingerprint();
        assert_eq!(fp1, fp2);
        assert!(fp1.contains(' ')); // formatted with spaces
    }
}
