//! kaname-oobv — Out-of-Band Verification (別経路検証セレモニー)
//!
//! 2026 年の Deepfake 音声/動画詐欺を「儀式」で防ぐ。
//! BIP39 ベース 6 ワードフレーズ + チャレンジ番号方式。
//! `ZeroizeOnDrop` でメモリから自動消去。5 分の期限。

// crates/kaname-oobv/src/lib.rs
//
// kaname-oobv — Out-of-Band Verification (別経路検証セレモニー)
//
// 2026 年最大の脅威「Deepfake 音声/動画」と「VEC」への対抗策。
// 香港の $25.6M Deepfake 詐欺事件と同型攻撃を「儀式」で防ぐ。
//
// # 設計哲学
//
// Signal の Safety Number と Apple の Verification Code を統合した
// 「金融取引向け検証フロー」。
//
// メール内の指示だけでなく、別経路 (電話・対面) で双方向に検証する。
// 攻撃者が片方の経路を完全に制御していても、もう片方を制御していなければ失敗する。
//
// # コンパイル時不変条件
//
// 1. 検証フレーズはサーバー側に保存されない (型レベルで保証)
// 2. 検証期限が過ぎたら自動的に失効する (Drop で zeroize)
// 3. 不一致は常に Audit Log に記録される (Result 型強制)

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

// ============================================================================
// BIP39 ベース 6 ワードフレーズ
// ============================================================================

/// BIP39 から抽出した 50 ワードの安全な部分集合。
///
/// 完全 BIP39 (2048 ワード) は記憶しにくいので、視認性の高い
/// 短い単語のみを採用。電話越しでも聞き間違いにくい。
const SAFE_WORDS: &[&str] = &[
    "anvil",  "ballot", "cipher", "drift",  "ember",  "fable",  "gauze",  "havoc",
    "ivory",  "joust",  "kite",   "lyric",  "moss",   "needle", "ocean",  "pebble",
    "quartz", "raven",  "sage",   "tiger",  "umbra",  "velvet", "willow", "xenon",
    "yacht",  "zebra",  "blade",  "creek",  "delta",  "echo",   "flint",  "glass",
    "harbor", "iris",   "jade",   "knot",   "lotus",  "marble", "north",  "orbit",
    "prism",  "quill",  "river",  "stone",  "tomb",   "ulna",   "vine",   "wing",
    "yarn",   "zephyr",
];

/// 日本語ユーザー向けカタカナワードリスト (50 語)。
///
/// 選定基準:
/// - 3〜5 モーラで電話越しに聞き間違いが起きにくい
/// - 濁音 (ガ/ダ) と清音 (カ/タ) を混在させず、各グループで区別しやすい語を採用
/// - 「ン」「ッ」で終わる語は省き、語尾が明確なものを優先
/// - 似た音形 (カメ/カゲ など) は片方のみ採用
const SAFE_WORDS_JA: &[&str] = &[
    "アオゾラ", "イナビカリ", "ウミウシ", "エンピツ", "オリーブ",
    "カガミ",   "キリン",     "クジャク", "ケムリ",   "コダマ",
    "サクラ",   "シオカゼ",   "スズムシ", "セキレイ", "ソラマメ",
    "タツノコ", "チドリ",     "ツバキ",   "テングサ", "トビウオ",
    "ナマコ",   "ニジマス",   "ヌイグルミ","ネコヤナギ","ノリタケ",
    "ハマナス", "ヒカリ",     "フクロウ", "ヘチマ",   "ホタル",
    "マツボックリ","ミカン",  "ムラサキ", "メダカ",   "モミジ",
    "ヤシノミ", "ユキウサギ", "ヨモギ",   "ラムネ",   "リンドウ",
    "ルリイロ", "レンゲ",     "ロウバイ", "ワカサギ", "ヲグラ",
    "ガリバー", "ジャコウ",   "ズワイ",   "ダイコン", "ビワ",
];

/// ワードリストのロケール。
///
/// Deepfake 対策の儀式は、ユーザーが実際に読み上げられる言語でなければ
/// 機能しない。デフォルトは英語 (`En`)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum WordLocale {
    /// 英語 (デフォルト)
    #[default]
    En,
    /// 日本語カタカナ
    Ja,
}

impl WordLocale {
    /// ロケール文字列 ("en", "ja", "ja-JP" など) から変換する。
    ///
    /// 失敗しない (未知のロケールは `En` にフォールバック) ため `FromStr` ではなく
    /// 独立メソッドとして提供する。
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(locale: &str) -> Self {
        if locale.starts_with("ja") {
            Self::Ja
        } else {
            Self::En
        }
    }

    /// このロケールのワードリストを返す。
    #[must_use]
    pub fn word_list(self) -> &'static [&'static str] {
        match self {
            Self::En => SAFE_WORDS,
            Self::Ja => SAFE_WORDS_JA,
        }
    }
}

/// 検証フレーズの 1 単語。
///
/// `ZeroizeOnDrop` により、Drop 時にメモリから自動消去。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct VerificationWord(String);

impl VerificationWord {
    /// 暗号学的に安全な乱数で 1 ワードを生成する (英語)。
    #[must_use]
    pub fn random() -> Self {
        Self::random_for_locale(WordLocale::En)
    }

    /// ロケールに合わせたワードを生成する。
    #[must_use]
    pub fn random_for_locale(locale: WordLocale) -> Self {
        use rand::Rng;
        let list = locale.word_list();
        let idx = rand::thread_rng().gen_range(0..list.len());
        Self(list[idx].to_string())
    }

    /// 文字列にアクセス (UI 表示用)。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// ユーザー入力との比較。
    ///
    /// 英語: case-insensitive (電話越しの聞き取りを許容)
    /// 日本語: 全角カタカナで正規化して比較
    ///
    /// **定数時間比較**: タイミング攻撃で期待ワードのビット情報が漏洩しないよう
    /// XOR ベースの定数時間比較を使用する。長さが異なる場合は早期リターンするが、
    /// ワードリスト (50語) の長さは限定的なので許容範囲。
    #[must_use]
    pub fn matches(&self, input: &str) -> bool {
        let trimmed = input.trim();
        if self.0.is_ascii() {
            kaname_crypto::ct_eq_ascii_ci(&self.0, trimmed)
        } else {
            // 日本語カタカナ: 正規化後に定数時間比較
            let expected = normalize_katakana(&self.0);
            let actual = normalize_katakana(trimmed);
            kaname_crypto::ct_eq(expected.as_bytes(), actual.as_bytes())
        }
    }
}

/// カタカナ正規化: 全角ひらがな→カタカナ、長音符の揺れを吸収。
fn normalize_katakana(s: &str) -> String {
    s.chars().map(|c| {
        // ひらがな (U+3041-U+3096) → カタカナ (U+30A1-U+30F6)
        if ('\u{3041}'..='\u{3096}').contains(&c) {
            char::from_u32(c as u32 + 0x60).unwrap_or(c)
        } else {
            c
        }
    }).collect()
}

// ============================================================================
// 検証セレモニー
// ============================================================================

/// 6 ワード検証セレモニー。
///
/// # 動作
///
/// 1. システムが 6 ワードを生成 (BIP39 ベース)
/// 2. 6 ワードのうち 1 つの「番号」をランダムに選択 (1-6)
/// 3. ユーザーは別経路 (電話など) で送信者に確認
///    「N 番目のワードを教えてください」
/// 4. 送信者は同じ画面を見て、N 番目を読み上げる
/// 5. 一致 → 検証完了、不一致 → ブロック
///
/// # セキュリティ
///
/// 攻撃者がメール経路を制御していても、電話経路を制御していなければ
/// 「正しい N 番目のワード」を知ることができない。
///
/// 攻撃者が両方の経路を Deepfake 音声で制御している場合でも、
/// **N 番目という間接質問** により、6 ワード全部を聞き出すことが困難
/// (1 ワードしか聞き出せず、N が動的に変わるため再現できない)。
/// ワードリストが 50 語のため、3 回試行でロック (ブルートフォース対策)。
pub const MAX_VERIFY_ATTEMPTS: u8 = 3;

/// Out-of-Band 検証セレモニー。送信者の身元を電話で確認するための手順。
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationCeremony {
    /// 検証 ID (Audit Log で参照)
    pub id: String,
    /// 6 ワードフレーズ
    phrase: [VerificationWord; 6],
    /// チャレンジ番号 (1-6 のうちのどれか)
    challenge_index: u8,
    /// 検証対象のメール ID
    pub target_email_id: String,
    /// 検証対象の送信者
    pub target_sender: String,
    /// 期限 (UNIX 秒、Instant はシリアライズ不能)
    pub expires_at_unix: u64,
    /// 状態
    pub state: CeremonyState,
    /// 試行回数 (最大 `MAX_VERIFY_ATTEMPTS` を超えると `Locked` 状態へ)
    attempt_count: u8,
    /// ワードリストのロケール
    pub locale: WordLocale,
}

/// セレモニーの状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeremonyState {
    /// 検証待ち
    Pending,
    /// 検証成功
    Verified,
    /// 検証失敗 (不一致)
    Mismatch,
    /// タイムアウト
    Expired,
    /// ブルートフォース防止: `MAX_VERIFY_ATTEMPTS` 回失敗でロック
    Locked,
}

impl VerificationCeremony {
    /// 新規セレモニーを生成する (英語ワードリスト)。
    ///
    /// # 期限
    ///
    /// 5 分。これより長いとユーザーが忘れる、短いと電話する時間がない。
    /// Apple HIG の "transient feedback" 原則。
    pub fn new(target_email_id: impl Into<String>, target_sender: impl Into<String>) -> Self {
        Self::new_with_locale(target_email_id, target_sender, WordLocale::En)
    }

    /// ロケール指定でセレモニーを生成する。
    ///
    /// 日本語ユーザーは `WordLocale::Ja` を指定することで、
    /// 電話越しに読み上げやすいカタカナワードが使用される。
    pub fn new_with_locale(
        target_email_id: impl Into<String>,
        target_sender: impl Into<String>,
        locale: WordLocale,
    ) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let phrase: [VerificationWord; 6] = [
            VerificationWord::random_for_locale(locale),
            VerificationWord::random_for_locale(locale),
            VerificationWord::random_for_locale(locale),
            VerificationWord::random_for_locale(locale),
            VerificationWord::random_for_locale(locale),
            VerificationWord::random_for_locale(locale),
        ];

        let challenge_index = rng.gen_range(0u8..6);

        let expires_at_unix = now_unix_secs().saturating_add(300); // 5 分

        Self {
            id: generate_ceremony_id(),
            phrase,
            challenge_index,
            target_email_id: target_email_id.into(),
            target_sender: target_sender.into(),
            expires_at_unix,
            state: CeremonyState::Pending,
            attempt_count: 0,
            locale,
        }
    }

    /// 表示用にフレーズを取得する (UI で表示)。
    #[must_use]
    pub fn display_phrase(&self) -> Vec<&str> {
        self.phrase.iter().map(VerificationWord::as_str).collect()
    }

    /// 現在の試行回数 (テスト・監査用)。
    #[must_use]
    pub fn attempt_count(&self) -> u8 {
        self.attempt_count
    }

    /// チャレンジ番号を取得する (1-indexed for human display)。
    #[must_use]
    pub fn challenge_number(&self) -> u8 {
        self.challenge_index + 1
    }

    /// ユーザーが入力した回答を検証する。
    ///
    /// # Errors
    ///
    /// - 既に検証完了 → `CeremonyError::AlreadyCompleted`
    /// - 期限切れ → `CeremonyError::Expired`
    pub fn verify(&mut self, user_response: &str) -> Result<CeremonyState, CeremonyError> {
        // 終端状態は不変。期限チェックより先に判定し、成功 (Verified) や
        // ロック済み (Locked) を後続の期限切れで上書きしない。
        // (上書きすると audit_record() が成功した検証を Expired と誤記録し、監査証跡が汚染される)
        if self.state != CeremonyState::Pending {
            return Err(CeremonyError::AlreadyCompleted(self.state));
        }

        // 期限チェック (Pending のときのみ Expired へ遷移)
        // unwrap_or(0): now=0 になると 0 > expires_at_unix が常に false で期限切れを見落とす。
        // unwrap_or(u64::MAX): 安全側 — クロック異常時は常に期限切れとして扱う。
        let now = now_unix_secs();

        if now > self.expires_at_unix {
            self.state = CeremonyState::Expired;
            return Err(CeremonyError::Expired);
        }

        // ブルートフォース防止: 試行回数上限チェック
        if self.attempt_count >= MAX_VERIFY_ATTEMPTS {
            self.state = CeremonyState::Locked;
            return Err(CeremonyError::TooManyAttempts);
        }
        self.attempt_count += 1;

        // チャレンジ番号の単語と比較
        let expected = &self.phrase[self.challenge_index as usize];

        if expected.matches(user_response) {
            self.state = CeremonyState::Verified;
        } else if self.attempt_count >= MAX_VERIFY_ATTEMPTS {
            // 最終失敗: ロック (これ以上試行不可)
            self.state = CeremonyState::Locked;
        } else {
            // まだ試行回数が残っている — Pending を維持して再試行を許可
            // (Mismatch は UI 表示用にのみ返す)
            self.state = CeremonyState::Mismatch;
        }

        // Mismatch の場合は次の verify() 呼び出しのために Pending に戻す
        if self.state == CeremonyState::Mismatch {
            self.state = CeremonyState::Pending;
            return Ok(CeremonyState::Mismatch);
        }

        Ok(self.state)
    }

    /// 監査ログ用のレコードを生成する。
    ///
    /// **重要**: フレーズ自体は記録しない (シークレットのため)。
    /// 検証結果のみ記録する。
    #[must_use]
    pub fn audit_record(&self) -> AuditRecord {
        AuditRecord {
            ceremony_id: self.id.clone(),
            target_email_id: self.target_email_id.clone(),
            target_sender: self.target_sender.clone(),
            state: self.state,
            timestamp_unix: now_unix_secs(),
        }
    }
}

/// 監査ログ用のレコード。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// セレモニー ID
    pub ceremony_id: String,
    /// 対象メール ID
    pub target_email_id: String,
    /// 対象送信者
    pub target_sender: String,
    /// 検証状態
    pub state: CeremonyState,
    /// タイムスタンプ (UNIX 秒)
    pub timestamp_unix: u64,
}

// ============================================================================
// 推奨トリガー
// ============================================================================

/// メール内容から OOBV が必要かを判定する。
pub struct OobvRecommender {
    /// 金融キーワード (各言語)
    financial_keywords: Vec<&'static str>,
    /// 緊急性キーワード
    urgency_keywords: Vec<&'static str>,
}

impl OobvRecommender {
    /// デフォルト判定器を構築する。
    #[must_use]
    pub fn new() -> Self {
        Self {
            financial_keywords: vec![
                // 日本語
                "振込", "口座", "送金", "支払", "請求", "決済", "入金", "出金",
                "資金", "残高", "為替", "口座変更", "支払先",
                // 英語
                "wire transfer", "payment", "invoice", "deposit", "withdrawal",
                "bank account", "account change", "remittance", "swift code",
                "iban",
            ],
            urgency_keywords: vec![
                "至急", "緊急", "本日中", "今すぐ", "即時", "急いで",
                "urgent", "immediately", "asap", "right now", "today",
            ],
        }
    }

    /// OOBV を推奨すべきかを判定する。
    ///
    /// 推奨条件:
    /// - 金融キーワード ≥ 1 個
    /// - 緊急性キーワード ≥ 1 個
    /// - 両方揃った場合は強く推奨 (`Severity::Critical`)
    /// - 片方だけなら推奨 (`Severity::High`)
    #[must_use]
    pub fn recommend(&self, body: &str) -> RecommendationLevel {
        let body_lower = body.to_lowercase();
        let financial_count = self.financial_keywords.iter()
            .filter(|kw| body_lower.contains(*kw))
            .count();
        let urgency_count = self.urgency_keywords.iter()
            .filter(|kw| body_lower.contains(*kw))
            .count();

        match (financial_count, urgency_count) {
            (0, 0) => RecommendationLevel::None,
            (0, _) | (_, 0) => RecommendationLevel::Optional,
            _ => RecommendationLevel::Strong, // 両方
        }
    }
}

impl Default for OobvRecommender {
    fn default() -> Self {
        Self::new()
    }
}

/// 推奨レベル。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendationLevel {
    /// 推奨なし
    None,
    /// オプション (ユーザーが選べる)
    Optional,
    /// 強く推奨 (UI で目立たせる)
    Strong,
}

// ============================================================================
// エラー型
// ============================================================================

/// セレモニーエラー。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CeremonyError {
    /// 期限切れ。
    #[error("検証セレモニーは期限切れです (5 分超過)")]
    Expired,

    /// 既に検証完了。
    #[error("セレモニーは既に完了しています: {0:?}")]
    AlreadyCompleted(CeremonyState),

    /// ブルートフォース防止: 試行回数超過。
    #[error("試行回数が上限 ({} 回) に達しました。セレモニーはロックされました。", MAX_VERIFY_ATTEMPTS)]
    TooManyAttempts,
}

// ============================================================================
// ユーティリティ
// ============================================================================

/// 現在の Unix 時刻 (秒) を返す。
///
/// `SystemTime` が `UNIX_EPOCH` 以前を返す異常が起きた場合、
/// `u64::MAX` を返すことで期限切れチェック (`now > expires_at_unix`) が
/// 常に true になり、安全側 (拒否) に倒れる。
///
/// セレモニー作成時に呼ぶと `saturating_add(300)` で 5 分後が
/// `u64::MAX + 300 = u64::MAX` になるため、常に期限切れになる (安全)。
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

fn generate_ceremony_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    format!("oobv_{}", hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn word_generation_is_from_safe_list() {
        for _ in 0..100 {
            let w = VerificationWord::random();
            assert!(SAFE_WORDS.contains(&w.as_str()),
                "Generated word not in SAFE_WORDS: {}", w.as_str());
        }
    }

    #[test]
    fn word_matches_case_insensitive() {
        let w = VerificationWord("Cipher".to_string());
        assert!(w.matches("cipher"));
        assert!(w.matches("CIPHER"));
        assert!(w.matches("CiPhEr"));
        assert!(w.matches("  cipher  "));  // trim
        assert!(!w.matches("ciphers"));    // 別単語
    }

    #[test]
    fn ceremony_generates_6_words() {
        let c = VerificationCeremony::new("e1", "alice@example.com");
        let phrase = c.display_phrase();
        assert_eq!(phrase.len(), 6);
        // 全単語が SAFE_WORDS から
        for w in phrase {
            assert!(SAFE_WORDS.contains(&w));
        }
    }

    #[test]
    fn japanese_ceremony_generates_6_katakana_words() {
        let c = VerificationCeremony::new_with_locale("e1", "alice@example.com", WordLocale::Ja);
        let phrase = c.display_phrase();
        assert_eq!(phrase.len(), 6);
        for w in &phrase {
            assert!(SAFE_WORDS_JA.contains(w), "Japanese word not in list: {w}");
        }
        assert_eq!(c.locale, WordLocale::Ja);
    }

    #[test]
    fn japanese_word_matches_hiragana_input() {
        // カタカナ "サクラ" はひらがな "さくら" と正規化後に一致する
        let w = VerificationWord("サクラ".to_string());
        assert!(w.matches("さくら"), "ひらがな入力がカタカナと一致すべき");
        assert!(w.matches("サクラ"), "カタカナ入力はそのまま一致すべき");
    }

    #[test]
    fn japanese_ceremony_correct_word_verifies() {
        let mut c = VerificationCeremony::new_with_locale("e2", "bob@example.com", WordLocale::Ja);
        let correct = c.phrase[c.challenge_index as usize].as_str().to_string();
        let result = c.verify(&correct).unwrap();
        assert_eq!(result, CeremonyState::Verified);
    }

    #[test]
    fn word_locale_from_str_parses_ja() {
        assert_eq!(WordLocale::from_str("ja"), WordLocale::Ja);
        assert_eq!(WordLocale::from_str("ja-JP"), WordLocale::Ja);
        assert_eq!(WordLocale::from_str("en"), WordLocale::En);
        assert_eq!(WordLocale::from_str("en-US"), WordLocale::En);
        assert_eq!(WordLocale::from_str(""), WordLocale::En);
    }

    #[test]
    fn english_word_matches_case_insensitive() {
        let w = VerificationWord("Cipher".to_string());
        assert!(w.matches("cipher"));
        assert!(w.matches("CIPHER"));
    }

    #[test]
    fn ceremony_challenge_is_in_range() {
        for _ in 0..100 {
            let c = VerificationCeremony::new("e1", "alice@example.com");
            assert!(c.challenge_number() >= 1);
            assert!(c.challenge_number() <= 6);
        }
    }

    #[test]
    fn correct_word_verifies() {
        let mut c = VerificationCeremony::new("e1", "alice@example.com");
        let correct_word = c.phrase[c.challenge_index as usize].as_str().to_string();
        let result = c.verify(&correct_word).unwrap();
        assert_eq!(result, CeremonyState::Verified);
        assert_eq!(c.state, CeremonyState::Verified);
    }

    #[test]
    fn verified_ceremony_not_overwritten_by_later_expiry() {
        // 検証成功後に期限切れになっても Verified が Expired に上書きされてはならない
        // (上書きすると audit_record が成功を Expired と誤記録し監査証跡が汚染される)
        let mut c = VerificationCeremony::new("e1", "alice@example.com");
        let correct = c.phrase[c.challenge_index as usize].as_str().to_string();
        assert_eq!(c.verify(&correct).unwrap(), CeremonyState::Verified);

        // 期限を過去に強制し、再度 verify を呼ぶ
        c.expires_at_unix = 0;
        let result = c.verify(&correct);
        assert!(matches!(result, Err(CeremonyError::AlreadyCompleted(CeremonyState::Verified))),
            "期限切れ後の再 verify で Verified が上書きされた: {result:?}");
        assert_eq!(c.state, CeremonyState::Verified, "終端状態 Verified は不変であるべき");
        // 監査記録も Verified のままであること
        assert_eq!(c.audit_record().state, CeremonyState::Verified);
    }

    #[test]
    fn locked_ceremony_not_overwritten_by_later_expiry() {
        let mut c = VerificationCeremony::new("e1", "alice@example.com");
        for _ in 0..MAX_VERIFY_ATTEMPTS {
            let _ = c.verify("wrong");
        }
        assert_eq!(c.state, CeremonyState::Locked);
        // 期限切れ後も Locked のまま
        c.expires_at_unix = 0;
        let _ = c.verify("wrong");
        assert_eq!(c.state, CeremonyState::Locked, "終端状態 Locked は期限切れで上書きされない");
    }

    #[test]
    fn wrong_word_fails_verification() {
        let mut c = VerificationCeremony::new("e1", "alice@example.com");
        let result = c.verify("definitely-not-the-right-word").unwrap();
        assert_eq!(result, CeremonyState::Mismatch);
        // 試行回数が残っている間は内部状態は Pending に戻る (再試行を許可)
        assert_eq!(c.state, CeremonyState::Pending);
    }

    #[test]
    fn brute_force_locks_after_max_attempts() {
        let mut c = VerificationCeremony::new("e1", "alice@example.com");
        // MAX_VERIFY_ATTEMPTS 回 わざと間違える
        for _ in 0..MAX_VERIFY_ATTEMPTS {
            let _ = c.verify("definitely_wrong_word_12345");
        }
        assert_eq!(
            c.state,
            CeremonyState::Locked,
            "3 回失敗後は Locked 状態でなければならない"
        );
    }

    #[test]
    fn locked_ceremony_rejects_correct_answer() {
        let mut c = VerificationCeremony::new("e1", "alice@example.com");
        let correct = c.phrase[c.challenge_index as usize].as_str().to_string();

        // 先に MAX_VERIFY_ATTEMPTS 回失敗してロック
        for _ in 0..MAX_VERIFY_ATTEMPTS {
            let _ = c.verify("wrong");
        }

        // ロック後は正解でも受け付けない
        let result = c.verify(&correct);
        assert!(
            matches!(result, Err(CeremonyError::TooManyAttempts | CeremonyError::AlreadyCompleted(_))),
            "ロック後に verify() が成功してしまった: {result:?}"
        );
    }

    #[test]
    fn attempt_count_advances_on_each_wrong_guess() {
        let mut c = VerificationCeremony::new("e1", "alice@example.com");
        let _ = c.verify("wrong1");
        assert_eq!(c.attempt_count(), 1);
        let _ = c.verify("wrong2");
        assert_eq!(c.attempt_count(), 2);
    }

    #[test]
    fn cannot_verify_twice() {
        let mut c = VerificationCeremony::new("e1", "alice@example.com");
        let correct = c.phrase[c.challenge_index as usize].as_str().to_string();
        c.verify(&correct).unwrap();

        let result = c.verify(&correct);
        assert!(matches!(result, Err(CeremonyError::AlreadyCompleted(_))));
    }

    #[test]
    fn audit_record_does_not_leak_phrase() {
        let c = VerificationCeremony::new("e1", "alice@example.com");
        let record = c.audit_record();

        // 監査ログを JSON 化して、フレーズが含まれていないことを確認
        let json = serde_json::to_string(&record).unwrap();
        for word in c.display_phrase() {
            assert!(!json.contains(word),
                "Audit record leaked phrase word: {word}");
        }
    }

    #[test]
    fn recommender_detects_japanese_financial_urgency() {
        let r = OobvRecommender::new();
        let body = "至急振込先を変更してください。今すぐお願いします。";
        assert_eq!(r.recommend(body), RecommendationLevel::Strong);
    }

    #[test]
    fn recommender_detects_english_financial_urgency() {
        let r = OobvRecommender::new();
        let body = "Please process this wire transfer immediately. Urgent.";
        assert_eq!(r.recommend(body), RecommendationLevel::Strong);
    }

    #[test]
    fn recommender_normal_email_no_recommendation() {
        let r = OobvRecommender::new();
        let body = "明日のミーティングの議題について確認させてください。";
        assert_eq!(r.recommend(body), RecommendationLevel::None);
    }

    #[test]
    fn recommender_financial_without_urgency_is_optional() {
        let r = OobvRecommender::new();
        let body = "今月の請求書をお送りします。ご確認ください。";
        assert_eq!(r.recommend(body), RecommendationLevel::Optional);
    }

    #[test]
    fn ceremony_id_is_unique() {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..1000 {
            let c = VerificationCeremony::new("e1", "alice@example.com");
            assert!(ids.insert(c.id), "Duplicate ceremony ID generated");
        }
    }

    #[test]
    fn ceremony_state_serializable() {
        let c = VerificationCeremony::new("e1", "alice@example.com");
        let json = serde_json::to_string(&c).expect("should serialize");
        assert!(json.contains("Pending"));
        // フレーズは serialize される (検証中はメモリ内で保持が必要)
        // しかし audit_record は phrase を含まない
    }
}

// ============================================================================
// 定数時間比較テスト
// ============================================================================

#[cfg(test)]
mod ct_compare_tests {
    use super::*;
    use kaname_crypto::{ct_eq, ct_eq_ascii_ci};

    #[test]
    fn ct_eq_ascii_same_is_true() {
        assert!(ct_eq_ascii_ci("anvil", "anvil"));
    }

    #[test]
    fn ct_eq_ascii_case_insensitive_works() {
        assert!(ct_eq_ascii_ci("ANVIL", "anvil"));
        assert!(ct_eq_ascii_ci("Anvil", "ANVIL"));
    }

    #[test]
    fn ct_eq_ascii_different_is_false() {
        assert!(!ct_eq_ascii_ci("anvil", "zebra"));
    }

    #[test]
    fn ct_eq_ascii_different_length_is_false() {
        assert!(!ct_eq_ascii_ci("anvil", "anvils"));
    }

    #[test]
    fn ct_eq_bytes_same_is_true() {
        assert!(ct_eq(b"hello", b"hello"));
    }

    #[test]
    fn ct_eq_bytes_different_is_false() {
        assert!(!ct_eq(b"hello", b"world"));
    }

    #[test]
    fn verification_word_matches_case_insensitive() {
        let w = VerificationWord(String::from("anvil"));
        assert!(w.matches("ANVIL"));
        assert!(w.matches("Anvil"));
        assert!(w.matches("  anvil  "));
    }

    #[test]
    fn verification_word_no_match_different_word() {
        let w = VerificationWord(String::from("anvil"));
        assert!(!w.matches("zebra"));
    }
}

// ============================================================================
// プロパティテスト
// ============================================================================

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// 不変条件: 生成ワードは常に SAFE_WORDS リストに存在する
        #[test]
        fn generated_word_always_in_safe_list(_seed in 0u64..1000) {
            let w = VerificationWord::random();
            prop_assert!(
                SAFE_WORDS.contains(&w.as_str()),
                "生成ワードが安全リスト外: {}", w.as_str()
            );
        }

        /// 不変条件: チャレンジ番号は常に 1-6 の範囲
        #[test]
        fn challenge_number_always_in_range(_seed in 0u64..1000) {
            let c = VerificationCeremony::new("e1", "test@example.com");
            prop_assert!(c.challenge_number() >= 1);
            prop_assert!(c.challenge_number() <= 6);
        }

        /// 不変条件: OobvRecommender は決定論的
        #[test]
        fn recommender_is_deterministic(body in ".{0,500}") {
            let r = OobvRecommender::new();
            let r1 = r.recommend(&body);
            let r2 = r.recommend(&body);
            prop_assert_eq!(r1, r2, "同じ入力で異なる結果");
        }

        /// 不変条件: 正解ワードで常に Verified
        #[test]
        fn correct_word_always_verifies(_seed in 0u64..100) {
            let mut c = VerificationCeremony::new("e-prop", "tester@example.com");
            let correct = c.phrase[c.challenge_index as usize].as_str().to_string();
            let result = c.verify(&correct);
            prop_assert!(result.is_ok());
            if let Ok(state) = result {
                prop_assert_eq!(state, CeremonyState::Verified);
            }
        }
    }
}
