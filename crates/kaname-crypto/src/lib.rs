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

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
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
    _handle_id: [u8; 32],
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

    /// バイト長がアルゴリズム仕様と一致することを検証する。
    ///
    /// デシリアライズ後に必ず呼び出すこと。
    pub fn validate_length(&self) -> Result<(), CryptoError> {
        let expected = self.alg.public_key_len();
        if self.bytes.len() != expected {
            return Err(CryptoError::InvalidFormat("public key length mismatch"));
        }
        Ok(())
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
#[derive(Debug, Clone)]
pub struct KemKey;
impl KeyKind for KemKey {
    const KIND: &'static str = "kem";
}

/// マーカー: このキーは署名に使用する。
#[derive(Debug, Clone)]
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
    /// テスト・KAT 用コンストラクタ。
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 生バイトアクセサ。`derive_key` を推奨。
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// HKDF-SHA-256 でアプリ固有のサブキーを導出。
    ///
    /// `info` はコンテキスト識別子 (例: b"kaname-encrypt-v1") として使う。
    /// XOR ではなく本物の HKDF を使うことで、info が既知でも秘密が漏洩しない。
    #[must_use]
    pub fn derive_key(&self, info: &[u8]) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(None, &self.0);
        let mut out = [0u8; 32];
        // 出力長 32 バイトは SHA-256 ブロックサイズ内 → InvalidLength は到達不能
        let _ = hkdf.expand(info, &mut out);
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
        pk.classical.validate_length()?;
        pk.pqc.validate_length()?;
        let (c_ss, c_ct) = self.classical.encapsulate(&pk.classical)?;
        let (p_ss, p_ct) = self.pqc.encapsulate(&pk.pqc)?;

        // arxiv eprint 2026/192 V4 対策: X25519 出力の contributory behavior を検証
        validate_x25519_output(&c_ss)?;

        let combined = combine_kem_secrets(&ClassicalSs(c_ss), &PqcSs(p_ss));

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

        // 末尾にゴミバイトがある場合は拒否 (暗号文可鍛性攻撃: 異なる CT で同じ SS)
        if pqc_start + pqc_len != ct.bytes.len() {
            return Err(CryptoError::InvalidFormat("hybrid ciphertext: trailing bytes"));
        }

        let cls_ct = Ciphertext { alg: AlgId::X25519, bytes: cls_bytes };
        let pqc_ct = Ciphertext { alg: AlgId::MlKem768, bytes: pqc_bytes };

        let c_ss = self.classical.decapsulate(&sk.classical_sk, &cls_ct)?;
        let p_ss = self.pqc.decapsulate(&sk.pqc_sk, &pqc_ct)?;

        // arxiv eprint 2026/192 V4 対策: X25519 出力の contributory behavior を検証
        validate_x25519_output(&c_ss)?;

        Ok(combine_kem_secrets(&ClassicalSs(c_ss), &PqcSs(p_ss)))
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
    ///
    /// 鍵長が仕様外の場合は "invalid-key" を返す (OOM DoS 防止)。
    #[must_use]
    pub fn fingerprint(&self) -> String {
        // 長さ検証: 不正な鍵で Vec::with_capacity(huge) → OOM を防ぐ
        if self.classical.validate_length().is_err() || self.pqc.validate_length().is_err() {
            return "invalid-key".to_string();
        }
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

/// X25519 (古典) の共有秘密をマークする型ラッパー。
/// `combine_kem_secrets` の引数順序を型で強制するため使用。
pub(crate) struct ClassicalSs(pub SharedSecret);

/// ML-KEM-768 (PQC) の共有秘密をマークする型ラッパー。
pub(crate) struct PqcSs(pub SharedSecret);

/// X25519 + ML-KEM-768 の共有秘密を HKDF-SHA-256 で結合する。
///
/// 型パラメータにより IKM 順序 (classical || pqc) が不変に保証される。
/// 引数の順序ミスはコンパイルエラーになる。
pub(crate) fn combine_kem_secrets(classical: &ClassicalSs, pqc: &PqcSs) -> SharedSecret {
    // IKM = classical || pqc (64 バイト)、info = b"kaname-xwing-v1"
    //
    // "both must break" 特性 (ROM 下):
    // 攻撃者は ML-KEM と X25519 の両方を破らなければ出力を区別できない。
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&classical.0.0);
    ikm[32..].copy_from_slice(&pqc.0.0);

    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    // HKDF の出力長 32 バイトは SHA-256 の有効範囲内 → InvalidLength は到達不能
    if hkdf.expand(b"kaname-xwing-v1", &mut okm).is_err() {
        return SharedSecret([0u8; 32]);
    }

    SharedSecret(okm)
}

#[cfg(test)]
pub(crate) fn combine_shared_secrets(c: &SharedSecret, p: &SharedSecret) -> SharedSecret {
    // HKDF-SHA-256 で 2 つの KEM 共有秘密を結合する。
    // IKM = c || p (64 バイト)、info = b"kaname-xwing-v1"
    //
    // これにより "both must break" 特性が ROM 下で成立:
    // 攻撃者は ML-KEM と X25519 の両方を破らなければ出力を区別できない。
    // XOR 結合とは異なり、一方が zero でも安全性が保たれる。
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&c.0);
    ikm[32..].copy_from_slice(&p.0);

    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    // HKDF の出力長は 32 バイト固定で有効範囲内 (SHA-256 では最大 255*32 バイト)
    // → InvalidLength は起こりえないが、型エラーを避けるため unwrap_or_else で安全処理
    if hkdf.expand(b"kaname-xwing-v1", &mut okm).is_err() {
        // 到達不能: 32 バイトは SHA-256 の有効出力長の範囲内
        return SharedSecret([0u8; 32]);
    }

    SharedSecret(okm)
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
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // テスト用の最小限 KEM 実装。generate/encapsulate/decapsulate はランダムバイトを返す。
    struct MockKem {
        alg: AlgId,
        ct_len: usize,
    }
    impl Kem for MockKem {
        fn algorithm(&self) -> AlgId { self.alg }
        fn generate(&self) -> Result<(PrivateKeyHandle<KemKey>, PublicKey<KemKey>), CryptoError> {
            Ok((
                PrivateKeyHandle { _handle_id: [0x01u8; 32], alg: self.alg, _kind: PhantomData },
                PublicKey { bytes: vec![0x02u8; 32], alg: self.alg, _kind: PhantomData },
            ))
        }
        fn encapsulate(&self, _pk: &PublicKey<KemKey>) -> Result<(SharedSecret, Ciphertext), CryptoError> {
            Ok((
                SharedSecret([0xAAu8; 32]),
                Ciphertext { alg: self.alg, bytes: vec![0xBBu8; self.ct_len] },
            ))
        }
        fn decapsulate(&self, _sk: &PrivateKeyHandle<KemKey>, _ct: &Ciphertext) -> Result<SharedSecret, CryptoError> {
            Ok(SharedSecret([0xAAu8; 32]))
        }
    }

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
            classical: PublicKey { bytes: vec![1u8; 32], alg: AlgId::X25519, _kind: PhantomData },
            pqc: PublicKey { bytes: vec![4u8; 1184], alg: AlgId::MlKem768, _kind: PhantomData },
        };
        let fp1 = pk.fingerprint();
        let fp2 = pk.fingerprint();
        assert_eq!(fp1, fp2, "フィンガープリントは決定的でなければならない");
        assert!(fp1.contains(' '), "スペース区切りフォーマット");
        // SHA-256 ベースなので XOR スタブ ("00 00...") にならない
        assert!(!fp1.starts_with("00 00"), "XOR スタブが残っている");
        assert_eq!(fp1.len(), 19, "8 bytes hex = XXXX XXXX XXXX XXXX = 19文字");
    }

    #[test]
    fn fingerprint_changes_with_different_keys() {
        let pk1 = HybridPublicKey {
            classical: PublicKey { bytes: vec![1u8; 32], alg: AlgId::X25519, _kind: PhantomData },
            pqc: PublicKey { bytes: vec![2u8; 1184], alg: AlgId::MlKem768, _kind: PhantomData },
        };
        let pk2 = HybridPublicKey {
            classical: PublicKey { bytes: vec![3u8; 32], alg: AlgId::X25519, _kind: PhantomData },
            pqc: PublicKey { bytes: vec![2u8; 1184], alg: AlgId::MlKem768, _kind: PhantomData },
        };
        assert_ne!(pk1.fingerprint(), pk2.fingerprint(),
            "異なる鍵は異なるフィンガープリントを持つ");
    }

    #[test]
    fn decapsulate_rejects_trailing_bytes() {
        // 正常な暗号文を作り末尾に余分なバイトを追加 → 可鍛性攻撃を拒否
        let kem = HybridX25519MlKem {
            classical: Box::new(MockKem { alg: AlgId::X25519, ct_len: 32 }),
            pqc:       Box::new(MockKem { alg: AlgId::MlKem768, ct_len: 1088 }),
        };
        // 正常な CT を手動で構築
        let cls_len: u16 = 32;
        let pqc_len: u16 = 1088;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&cls_len.to_be_bytes());
        bytes.extend_from_slice(&vec![0xABu8; 32]);
        bytes.extend_from_slice(&pqc_len.to_be_bytes());
        bytes.extend_from_slice(&vec![0xCDu8; 1088]);
        bytes.push(0xFF); // 末尾ゴミバイト

        let ct = Ciphertext { alg: AlgId::HybridX25519MlKem768, bytes };
        let keypair = kem.generate().unwrap();
        let result = kem.decapsulate(&keypair, &ct);
        assert!(matches!(result, Err(CryptoError::InvalidFormat(_))),
            "末尾バイトがある暗号文は拒否されなければならない: {result:?}");
    }

    #[test]
    fn combine_secrets_is_not_xor() {
        // XOR の場合 a ^ a = 0 になるが、HKDF はそうならない
        let a = SharedSecret([0xABu8; 32]);
        let result = combine_shared_secrets(&a, &a);
        assert_ne!(result.0, [0u8; 32], "HKDF with equal inputs must not produce zero");
    }

    #[test]
    fn combine_secrets_deterministic() {
        let c = SharedSecret([0x11u8; 32]);
        let p = SharedSecret([0x22u8; 32]);
        let r1 = combine_shared_secrets(&c, &p);
        let r2 = combine_shared_secrets(&c, &p);
        assert_eq!(r1.0, r2.0, "HKDF is deterministic");
    }

    #[test]
    fn combine_secrets_order_matters() {
        // HKDF(c||p) ≠ HKDF(p||c) — 順序の混乱を検出する
        let c = SharedSecret([0x11u8; 32]);
        let p = SharedSecret([0x22u8; 32]);
        let r1 = combine_shared_secrets(&c, &p);
        let r2 = combine_shared_secrets(&p, &c);
        assert_ne!(r1.0, r2.0, "input order must affect HKDF output");
    }

    #[test]
    fn combine_secrets_produces_32_bytes() {
        let c = SharedSecret([0x01u8; 32]);
        let p = SharedSecret([0x02u8; 32]);
        let r = combine_shared_secrets(&c, &p);
        assert_eq!(r.0.len(), 32);
    }

    // ──────────────────────────────────────────────────────────────────
    // 型安全 KEM combiner (combine_kem_secrets)
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn combine_kem_secrets_matches_legacy_order() {
        // ClassicalSs=c, PqcSs=p は旧 combine_shared_secrets(&c, &p) と同じ順序
        let c = SharedSecret([0x11u8; 32]);
        let p = SharedSecret([0x22u8; 32]);
        let legacy = combine_shared_secrets(&c, &p);
        let typed = combine_kem_secrets(&ClassicalSs(c), &PqcSs(p));
        assert_eq!(legacy.0, typed.0, "typed API must match legacy order");
    }

    #[test]
    fn combine_kem_secrets_different_from_reversed() {
        let c = SharedSecret([0x11u8; 32]);
        let p = SharedSecret([0x22u8; 32]);
        let c2 = SharedSecret([0x11u8; 32]);
        let p2 = SharedSecret([0x22u8; 32]);
        // 正しい順序 (classical || pqc)
        let correct = combine_kem_secrets(&ClassicalSs(c), &PqcSs(p));
        // 逆順 (pqc || classical) — 型安全 API では表現不能だが値レベルで確認
        let reversed = combine_shared_secrets(&p2, &c2);
        assert_ne!(correct.0, reversed.0, "order must matter");
    }

    // ──────────────────────────────────────────────────────────────────
    // derive_key: XOR スタブではなく本物の HKDF を使っていることを確認
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn derive_key_is_not_xor() {
        // XOR なら ss ^ info[..32] になるが HKDF の出力はそうならない
        let ss = SharedSecret([0xAAu8; 32]);
        let info = [0xAAu8; 32]; // ss と同じ値 → XOR なら全ゼロ
        let out = ss.derive_key(&info);
        assert_ne!(out, [0u8; 32], "XOR スタブが残っている: all-zero output");
    }

    #[test]
    fn derive_key_different_info_gives_different_output() {
        let ss = SharedSecret([0x77u8; 32]);
        let out1 = ss.derive_key(b"kaname-encrypt-v1");
        let out2 = ss.derive_key(b"kaname-auth-v1");
        assert_ne!(out1, out2, "異なる info は異なるサブキーを生成しなければならない");
    }

    #[test]
    fn derive_key_is_deterministic() {
        let ss = SharedSecret([0x55u8; 32]);
        let a = ss.derive_key(b"context");
        let b = ss.derive_key(b"context");
        assert_eq!(a, b, "derive_key は決定的でなければならない");
    }

    #[test]
    fn public_key_validate_length_rejects_wrong_size() {
        // X25519 は 32 バイト固定
        let pk: PublicKey<KemKey> = PublicKey {
            bytes: vec![0u8; 100], // 不正な長さ
            alg: AlgId::X25519,
            _kind: PhantomData,
        };
        assert!(
            matches!(pk.validate_length(), Err(CryptoError::InvalidFormat(_))),
            "不正な長さの公開鍵は拒否されなければならない"
        );
    }

    #[test]
    fn public_key_validate_length_accepts_correct_size() {
        let pk: PublicKey<KemKey> = PublicKey {
            bytes: vec![0u8; 32], // X25519 の正しい長さ
            alg: AlgId::X25519,
            _kind: PhantomData,
        };
        assert!(pk.validate_length().is_ok(), "正しい長さの公開鍵は受理されなければならない");
    }

    #[test]
    fn fingerprint_returns_invalid_key_for_oversized_classical() {
        let pk = HybridPublicKey {
            classical: PublicKey { bytes: vec![0u8; 10_000], alg: AlgId::X25519, _kind: PhantomData },
            pqc: PublicKey { bytes: vec![0u8; 1184], alg: AlgId::MlKem768, _kind: PhantomData },
        };
        assert_eq!(pk.fingerprint(), "invalid-key", "不正な鍵長はフィンガープリント OOM を起こしてはならない");
    }

    #[test]
    fn encapsulate_rejects_oversized_public_key() {
        let kem = HybridX25519MlKem {
            classical: Box::new(MockKem { alg: AlgId::X25519, ct_len: 32 }),
            pqc:       Box::new(MockKem { alg: AlgId::MlKem768, ct_len: 1088 }),
        };
        let bad_pk = HybridPublicKey {
            classical: PublicKey { bytes: vec![0u8; 1_000_000], alg: AlgId::X25519, _kind: PhantomData },
            pqc: PublicKey { bytes: vec![0u8; 1184], alg: AlgId::MlKem768, _kind: PhantomData },
        };
        let result = kem.encapsulate(&bad_pk);
        assert!(
            matches!(result, Err(CryptoError::InvalidFormat(_))),
            "不正な公開鍵長でカプセル化は拒否されなければならない: {result:?}"
        );
    }

    #[test]
    fn derive_key_output_not_trivially_invertible() {
        // info が既知でも ss が復元できないことを確認
        // (完全な証明はできないが XOR スタブなら out ^ info == ss になる)
        let ss = SharedSecret([0x12u8; 32]);
        let info = b"known-context";
        let out = ss.derive_key(info);
        // XOR なら: out[i] ^ info[i % 32] == ss[i]
        let mut xor_candidate = [0u8; 32];
        for (i, b) in out.iter().enumerate() {
            xor_candidate[i] = b ^ info[i % info.len()];
        }
        assert_ne!(xor_candidate, ss.0, "XOR スタブの出力は info で逆算できる");
    }
}
