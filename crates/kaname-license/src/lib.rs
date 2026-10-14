//! kaname-license — オフライン・ライセンス検証 (収益化の最小構成)
//!
//! # 設計 (第一原理)
//!
//! Kaname の収益化は「検出エンジンをクラウドに渡さない」不変条件
//! (I5: PII 非送信・P-LLM 非ネットワーク) の内側で成立する必要がある。
//! 課金サーバ・テレメトリ・定期課金の管理画面はすべて外部依存と
//! 保守コストを増やすため採用しない。採用した最小構成:
//!
//! 1. 発行者 (販売側) が ed25519 秘密鍵でライセンス payload に署名
//! 2. クライアントは同梱の **公開鍵のみ** でローカル検証 — 通信ゼロ
//! 3. Pro 枠は「価値の高い一括処理」にのみゲートを掛ける
//!    (現状: フォルダ一括スキャン = `Feature::FolderScan`)
//!
//! 秘密鍵はリポジトリに入れない。`issue()` は販売者側ツール用の
//! API で、鍵は実行時に引数または環境変数で受け取る。
//!
//! # キー形式
//!
//! ```text
//! KANAME-<payload_hex>.<sig_hex>
//! payload = {"v":1,"tier":"pro","seats":N,"exp":<unix|null>,"to":"..","nonce":".."}
//! sig     = ed25519 signature over the UTF-8 payload bytes
//! ```
//!
//! 期限 `exp` は販売形態 (買切 / 年間保守) に応じて任意設定。
//! 検証は全て定数時間比較の署名検証に集約される。

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::{OnceLock, RwLock};

/// 検証に使う発行者公開鍵。
///
/// 対応する秘密鍵はリポジトリに**含まれない** — 販売者の端末にのみ
/// 保持し、`issue()` へ実行時に渡す。公開リポジトリのため、ここに
/// テスト用シード由来の鍵を置くと誰でも有効キーを発行できる
/// (Devin Review 指摘): シード非公開の鍵ペアを埋め込み、販売者は
/// 自前の鍵ペア生成 (`cargo test -p kaname-license keygen -- --ignored`
/// 参考) とこの値の差し替えで運用する。
pub const ISSUER_PUBLIC_KEY: [u8; 32] = [
    97, 243, 131, 217, 21, 247, 94, 180, 135, 216, 58, 78, 16, 53, 68, 166, 198, 142, 22, 206, 106,
    217, 153, 212, 195, 89, 225, 66, 51, 48, 36, 139,
];

/// ライセンスキー文字列の上限。これを超える入力は検証前に拒否し、
/// 巨大キーによる割当て DoS を防ぐ (実キーは数百字)。
const MAX_KEY_LEN: usize = 4096;

/// 購入者識別子の上限。payload を丸ごと hex 化するため、ここを絞る
/// ことで発行キーが必ず MAX_KEY_LEN 以内に収まる (検証を通らない
/// キーを発行しない — Devin Review 指摘)。
const MAX_RECIPIENT_LEN: usize = 256;

/// ライセンス階層。`Free` は未登録 (全機能の内、Pro 枠だけが制限される)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// 無償層 — 単票解析など個人利用
    Free,
    /// 有償層 — 一括処理・業務利用
    Pro,
}

/// Pro ゲート対象の機能識別子。
///
/// ゲートの選択基準: 「個人が毎日使う核機能は無償、業務量に比例する
/// 処理は有償」。フォルダ一括スキャンは監査・調査用途の業務機能。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// フォルダ内 .eml の一括解析 (mail_scan_folder)
    FolderScan,
}

/// 検証済みライセンスの中身。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    /// ペイロード形式バージョン (現在 1)
    pub version: u32,
    /// 階層 (pro のみ発行される。free は「ライセンス無し」)
    pub tier: Tier,
    /// 契約席数 (参考表示・強制はしない)
    pub seats: u32,
    /// 有効期限 (Unix 秒)。`None` = 買切無期限
    pub expires_at: Option<u64>,
    /// 購入者識別子 (表示用。メールアドレス等)
    pub licensed_to: String,
}

/// ライセンス検証の失敗理由。
#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    /// 形式が `KANAME-<hex>.<hex>` でない / payload が壊れている
    #[error("ライセンスキーの形式が不正です")]
    Malformed,
    /// ed25519 署名が公開鍵と一致しない (偽造・文字化け)
    #[error("ライセンスキーの署名が一致しません")]
    BadSignature,
    /// `exp` を過ぎている
    #[error("ライセンスの有効期限が切れています")]
    Expired,
    /// Pro 機能を Free 層が使おうとした
    #[error("この機能は Pro ライセンスが必要です")]
    ProRequired,
}

/// ライセンス payload (署名対象そのもの)。
#[derive(Debug, Serialize, Deserialize)]
struct Payload {
    v: u32,
    tier: Tier,
    seats: u32,
    exp: Option<u64>,
    to: String,
    nonce: String,
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn from_hex(s: &str) -> Result<Vec<u8>, LicenseError> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(LicenseError::Malformed);
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
        .collect())
}

/// 発行ごとの一意化用 nonce。秘密鍵シード由来の値を payload (公開) に
/// 載せないよう、プロセス乱数鍵の SipHash から生成する。
fn issue_nonce(to: &str) -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write(to.as_bytes());
    format!("{:016x}", h.finish())
}

/// 販売者側: payload に署名してライセンスキーを発行する。
///
/// クライアントには同梱しない秘密鍵 (32 byte シード) が必要。
/// 販売フロー (Gumroad 等のキー納品) での手動発行や
/// 発行スクリプトから呼ぶ。購入者識別子が長すぎる場合は
/// `Malformed` を返す — 検証を通らないキーは発行しない。
pub fn issue(
    seed: &[u8; 32],
    to: &str,
    seats: u32,
    expires_at: Option<u64>,
) -> Result<String, LicenseError> {
    if to.len() > MAX_RECIPIENT_LEN {
        return Err(LicenseError::Malformed);
    }
    let payload = Payload {
        v: 1,
        tier: Tier::Pro,
        seats,
        exp: expires_at,
        to: to.to_string(),
        nonce: issue_nonce(to),
    };
    let json = serde_json::to_string(&payload).unwrap_or_default();
    let key = SigningKey::from_bytes(seed);
    let sig = key.sign(json.as_bytes());
    Ok(format!(
        "KANAME-{}.{}",
        to_hex(json.as_bytes()),
        to_hex(&sig.to_bytes())
    ))
}

/// 検証コア: 任意の公開鍵でキーを検証する。
///
/// 本番入口は `verify()` (同梱公開鍵) で、こちらは鍵を注入できる
/// ため鍵ローテーション試験や発行検証に使う。
pub fn verify_with(
    key: &str,
    now_unix: u64,
    pub_bytes: &[u8; 32],
) -> Result<License, LicenseError> {
    if key.len() > MAX_KEY_LEN {
        return Err(LicenseError::Malformed);
    }
    let body = key.strip_prefix("KANAME-").ok_or(LicenseError::Malformed)?;
    let (payload_hex, sig_hex) = body.split_once('.').ok_or(LicenseError::Malformed)?;
    let payload_bytes = from_hex(payload_hex)?;
    let sig_bytes = from_hex(sig_hex)?;
    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| LicenseError::Malformed)?;
    let sig = Signature::from_bytes(&sig_array);
    let vk = VerifyingKey::from_bytes(pub_bytes).map_err(|_| LicenseError::Malformed)?;
    vk.verify(&payload_bytes, &sig)
        .map_err(|_| LicenseError::BadSignature)?;
    let payload: Payload =
        serde_json::from_slice(&payload_bytes).map_err(|_| LicenseError::Malformed)?;
    if payload.v != 1 {
        return Err(LicenseError::Malformed);
    }
    if let Some(exp) = payload.exp {
        if now_unix > exp {
            return Err(LicenseError::Expired);
        }
    }
    Ok(License {
        version: payload.v,
        tier: payload.tier,
        seats: payload.seats,
        expires_at: payload.exp,
        licensed_to: payload.to,
    })
}

/// 同梱公開鍵でライセンスキーを検証する。`now_unix` は呼び出し側が
/// 供給し、テストで期限切れ/期限内を再現できる。
pub fn verify(key: &str, now_unix: u64) -> Result<License, LicenseError> {
    verify_with(key, now_unix, &ISSUER_PUBLIC_KEY)
}

/// アクティブ中のライセンス (プロセス内シングルトン)。
fn slot() -> &'static RwLock<Option<License>> {
    static S: OnceLock<RwLock<Option<License>>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(None))
}

/// キーを検証してアクティブ化する。成功で Pro 機能が開放される。
pub fn activate(key: &str, now_unix: u64) -> Result<License, LicenseError> {
    let lic = verify(key, now_unix)?;
    *slot().write().unwrap_or_else(|e| e.into_inner()) = Some(lic.clone());
    Ok(lic)
}

/// 任意の公開鍵で検証・アクティブ化する。
///
/// 署名を迂回して Pro を開放できるため本番 API ではなく、
/// 発行検証・単体試験専用 — `testing` feature / クレート内 test のみ。
#[cfg(any(test, feature = "testing"))]
pub fn activate_with(
    key: &str,
    now_unix: u64,
    pub_bytes: &[u8; 32],
) -> Result<License, LicenseError> {
    let lic = verify_with(key, now_unix, pub_bytes)?;
    *slot().write().unwrap_or_else(|e| e.into_inner()) = Some(lic.clone());
    Ok(lic)
}

/// 検証済みライセンスを直接投入する (署名検証迂回の試験専用経路)。
/// `testing` feature / クレート内 test でのみ公開 — 本番ビルドには
/// 存在しない (Devin Review: 迂回経路を本番 API に残さない)。
#[cfg(any(test, feature = "testing"))]
pub fn install_license(lic: License) {
    *slot().write().unwrap_or_else(|e| e.into_inner()) = Some(lic);
}

/// 現在のライセンスを外す (Free に戻る)。
pub fn deactivate() {
    *slot().write().unwrap_or_else(|e| e.into_inner()) = None;
}

/// 現在のライセンス状態を読み取る (期限切れ判定込み)。
///
/// 保存された期限付きライセンスが失効していても残したままにせず
/// Free 扱いに戻すため、呼び出し時に期限を再評価する。
pub fn status(now_unix: u64) -> Option<License> {
    // 期限評価と削除を同一の書き込みロック内で行う — 読み取り後に
    // 別スレッドの activate が成功した場合、古い期限切れ判定が
    // 新しいライセンスを消してしまう競合を防ぐ (Devin Review 指摘)。
    let mut guard = slot().write().unwrap_or_else(|e| e.into_inner());
    let lic = guard.clone()?;
    match lic.expires_at {
        Some(exp) if now_unix > exp => {
            *guard = None;
            None
        }
        _ => Some(lic),
    }
}

/// 機能ゲート: `feature` が Pro 枠なら Pro ライセンスを要求する。
///
/// 失敗時は `LicenseError::ProRequired` — IPC 層が購入導線つきの
/// エラーとして利用者に返せる構造化された理由。
pub fn require(feature: Feature, now_unix: u64) -> Result<(), LicenseError> {
    match feature {
        Feature::FolderScan => match status(now_unix) {
            Some(l) if l.tier == Tier::Pro => Ok(()),
            _ => Err(LicenseError::ProRequired),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; 32] = [7u8; 32];

    fn test_pub() -> [u8; 32] {
        SigningKey::from_bytes(&TEST_SEED)
            .verifying_key()
            .to_bytes()
    }

    /// 開発既定の埋め込み公開鍵を出力する補助。
    /// `-- --nocapture issuer_vector` で表示し `ISSUER_PUBLIC_KEY_DEV` に貼る。
    #[test]
    fn issuer_vector() {
        let key = issue(&TEST_SEED, "dev@example.com", 5, None).expect("issue ok");
        eprintln!("PUB = {:?}", test_pub());
        eprintln!("KEY = {key}");
    }

    #[test]
    fn round_trip_pro() {
        let key = issue(&TEST_SEED, "team@example.com", 10, None).expect("issue ok");
        let lic = verify_with(&key, 1_800_000_000, &test_pub()).expect("valid");
        assert_eq!(lic.tier, Tier::Pro);
        assert_eq!(lic.seats, 10);
        assert_eq!(lic.licensed_to, "team@example.com");
        assert!(lic.expires_at.is_none());
    }

    #[test]
    fn rejects_wrong_prefix() {
        assert!(matches!(
            verify_with("NOPE-aa.bb", 0, &test_pub()),
            Err(LicenseError::Malformed)
        ));
    }

    #[test]
    fn rejects_missing_dot() {
        assert!(matches!(
            verify_with("KANAME-aaaa", 0, &test_pub()),
            Err(LicenseError::Malformed)
        ));
    }

    #[test]
    fn rejects_non_hex() {
        assert!(matches!(
            verify_with("KANAME-zz.zz", 0, &test_pub()),
            Err(LicenseError::Malformed)
        ));
    }

    #[test]
    fn rejects_tampered_payload() {
        let key = issue(&TEST_SEED, "a@b.c", 1, None).expect("issue ok");
        // payload 末尾 1 byte 倒す → 署名不一致
        let tampered = key.replacen("65", "66", 1);
        assert!(matches!(
            verify_with(&tampered, 0, &test_pub()),
            Err(LicenseError::BadSignature | LicenseError::Malformed)
        ));
    }

    #[test]
    fn rejects_wrong_pubkey() {
        let key = issue(&TEST_SEED, "a@b.c", 1, None).expect("issue ok");
        let other = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(matches!(
            verify_with(&key, 0, &other),
            Err(LicenseError::BadSignature)
        ));
    }

    #[test]
    fn expiry_enforced() {
        let key = issue(&TEST_SEED, "a@b.c", 1, Some(1_700_000_000)).expect("issue ok");
        assert!(matches!(
            verify_with(&key, 1_700_000_001, &test_pub()),
            Err(LicenseError::Expired)
        ));
        assert!(verify_with(&key, 1_699_999_999, &test_pub()).is_ok());
    }

    #[test]
    fn activate_then_require_folder_scan() {
        deactivate();
        assert!(matches!(
            require(Feature::FolderScan, 0),
            Err(LicenseError::ProRequired)
        ));
        // activate() は埋め込み鍵を使うため、開発鍵の差し替え前は
        // verify_with で直接検証したライセンスを slot へ入れる形を取る。
        let key = issue(&TEST_SEED, "a@b.c", 1, None).expect("issue ok");
        let lic = verify_with(&key, 0, &test_pub()).expect("valid");
        *slot().write().unwrap_or_else(|e| e.into_inner()) = Some(lic);
        assert!(require(Feature::FolderScan, 0).is_ok());
    }

    #[test]
    fn expired_active_license_downgrades() {
        let key = issue(&TEST_SEED, "a@b.c", 1, Some(100)).expect("issue ok");
        let lic = verify_with(&key, 0, &test_pub()).expect("valid at issue time");
        *slot().write().unwrap_or_else(|e| e.into_inner()) = Some(lic);
        assert!(status(101).is_none());
        assert!(matches!(
            require(Feature::FolderScan, 101),
            Err(LicenseError::ProRequired)
        ));
        deactivate();
    }

    #[test]
    fn deactivate_returns_to_free() {
        let key = issue(&TEST_SEED, "a@b.c", 1, None).expect("issue ok");
        let lic = verify_with(&key, 0, &test_pub()).expect("valid");
        *slot().write().unwrap_or_else(|e| e.into_inner()) = Some(lic);
        deactivate();
        assert!(status(0).is_none());
        assert!(matches!(
            require(Feature::FolderScan, 0),
            Err(LicenseError::ProRequired)
        ));
    }

    #[test]
    fn embedded_key_round_trip() {
        // 埋め込み公開鍵 (シード非公開) で署名された実キーで同梱鍵経路を検証。
        // 旧開発鍵ペア (公開シード [7;32]) のベクトルは BadSignature で
        // 拒否されることも併せて確認する (Devin Review: 公開シード廃止)。
        let key = "KANAME-7b2276223a312c2274696572223a2270726f222c227365617473223a352c22657870223a6e756c6c2c22746f223a22646576406578616d706c652e636f6d222c226e6f6e6365223a226b616e616d65227d.fbae5c1f8222fb32164178ab3c90366d1d2c1f3a6cf9bc16e76e9a394fd32ba384d2676adcf44bc4f230ca768434f1f48aa0455ec2ada93252b29dc469f7ce09";
        let lic = activate(key, 1_800_000_000).expect("embedded key verifies");
        assert_eq!(lic.tier, Tier::Pro);
        assert_eq!(lic.licensed_to, "dev@example.com");
        assert!(require(Feature::FolderScan, 1_800_000_000).is_ok());
        deactivate();
        // 旧開発鍵ペアのキーは埋め込み鍵では拒否される
        let legacy = "KANAME-7b2276223a312c2274696572223a2270726f222c227365617473223a352c22657870223a6e756c6c2c22746f223a22646576406578616d706c652e636f6d222c226e6f6e6365223a223037303730373037227d.f53a7a4cff02147c94bed0c18e91352ec04d3008cca26e951ff2ce135d9a56b4805dc98f7ad2f37016a780da22a95c4cca2152491348b082535009d540aa2f08";
        assert!(matches!(verify(legacy, 0), Err(LicenseError::BadSignature)));
    }

    #[test]
    fn issued_payload_does_not_embed_seed_bytes() {
        let key = issue(&TEST_SEED, "a@b.c", 1, None).expect("issue ok");
        let body = key.strip_prefix("KANAME-").and_then(|b| b.split_once('.'));
        let payload_hex = body.map(|(p, _)| p).unwrap_or_default();
        let json = String::from_utf8(from_hex(payload_hex).unwrap_or_default()).unwrap_or_default();
        assert!(!json.contains(&to_hex(&TEST_SEED[..4])));
        assert!(verify_with(&key, 0, &test_pub()).is_ok());
    }

    #[test]
    fn rejects_oversized_key() {
        let huge = format!("KANAME-{}", "aa".repeat(3000));
        assert!(matches!(
            verify_with(&huge, 0, &test_pub()),
            Err(LicenseError::Malformed)
        ));
    }

    #[test]
    fn rejects_bad_version() {
        let payload = Payload {
            v: 99,
            tier: Tier::Pro,
            seats: 1,
            exp: None,
            to: "a@b.c".into(),
            nonce: "x".into(),
        };
        let json = serde_json::to_string(&payload).unwrap_or_default();
        let key = SigningKey::from_bytes(&TEST_SEED);
        let sig = key.sign(json.as_bytes());
        let k = format!(
            "KANAME-{}.{}",
            to_hex(json.as_bytes()),
            to_hex(&sig.to_bytes())
        );
        assert!(matches!(
            verify_with(&k, 0, &test_pub()),
            Err(LicenseError::Malformed)
        ));
    }
}
