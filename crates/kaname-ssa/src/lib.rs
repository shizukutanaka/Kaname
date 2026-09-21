//! kaname-ssa — Sender Style Authentication (送信者文体認証)
//!
//! AI 生成フィッシングは文法完璧でも送信者の文体に一致しない。
//! 30+ 通の過去メールから 7 次元の文体指紋を構築。
//! コンテンツは保存しない — 数値ベクトルのみ。

// crates/kaname-ssa/src/lib.rs
//
// kaname-ssa — Sender Style Authentication (送信者文体認証)
//
// 2026 年、AI 生成フィッシングは文法が完璧で、ドメインも正当、SPF/DKIM も通過する。
// しかし AI が生成した文章は「その人固有の文体」に完全には一致しない。
//
// # 着想
//
// 人間の書き方には「指紋」がある:
//   - 文の長さのリズム
//   - 句読点の使い方
//   - 敬語レベルの一貫性
//   - 送信する時間帯
//   - 署名のスタイル
//
// 30 通の過去メールからこの指紋を構築し、
// 新着メールとの「スタイル距離」を計算する。
//
// # プライバシー設計
//
// - コンテンツを保存しない: スタイル特徴ベクトル (数値のみ) を保存
// - ローカル処理: クラウド AI 不使用、Dual-LLM 境界の外側
// - 削除可能: ユーザーが送信者プロファイルを任意削除
// - 10 通未満ではプロファイルを使用しない (信頼性不足)
//
// # コンパイル時保証
//
// SenderStyleProfile はメール本文テキストをフィールドとして持たない。
// 数値ベクトルのみ。型レベルでコンテンツ保存が不可能。

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::doc_markdown)]

use serde::{Deserialize, Serialize};

// ============================================================================
// 送信者スタイルプロファイル
// ============================================================================

/// 送信者の文体指紋。
///
/// **重要**: このスキーマにメール本文テキストは存在しない。
/// 全フィールドが統計的な数値表現のみ。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SenderStyleProfile {
    /// 送信者のメールアドレス
    pub sender: String,
    /// プロファイル構築に使ったメール数
    pub sample_count: u32,
    /// 1 メールあたりの平均段落数
    pub avg_paragraphs: f32,
    /// 1 段落あたりの平均文数
    pub avg_sentences_per_paragraph: f32,
    /// 1 文の平均文字数
    pub avg_chars_per_sentence: f32,
    /// 読点密度 (100 文字あたりの読点数)
    pub punctuation_density: f32,
    /// フォーマリティスコア (0.0=カジュアル, 1.0=超丁寧)
    pub formality_score: f32,
    /// 平均メール文字数
    pub avg_email_length: f32,
    /// 送信時刻分布 (0-23 時、各値は過去の送信確率)
    pub send_hour_distribution: [f32; 24],
    /// 署名の平均行数
    pub avg_signature_lines: f32,
    /// 最終更新時刻 (UNIX 秒)
    pub last_updated_unix: u64,
}

/// 比率ベースの次元距離: `avg` を基準にした `val` の相対乖離を [0,1] に丸める。
/// `avg == 0` (プロファイル上その次元が観測ゼロ) で `val > 0` の場合は
/// 「存在しないはずの特徴が現れた」= 構造的異常として最大距離 1.0 を返す。
fn ratio_dist(avg: f32, val: f32) -> f32 {
    if avg > 0.0 {
        (val / avg - 1.0).abs().min(1.0)
    } else if val <= 0.0 {
        0.0
    } else {
        1.0
    }
}

impl SenderStyleProfile {
    /// 新規空プロファイルを作成。
    #[must_use]
    pub fn new(sender: impl Into<String>) -> Self {
        Self {
            sender: sender.into(),
            sample_count: 0,
            avg_paragraphs: 0.0,
            avg_sentences_per_paragraph: 0.0,
            avg_chars_per_sentence: 0.0,
            punctuation_density: 0.0,
            formality_score: 0.5,
            avg_email_length: 0.0,
            send_hour_distribution: [0.0; 24],
            avg_signature_lines: 0.0,
            last_updated_unix: now_unix(),
        }
    }

    /// プロファイルが信頼できるか (最低 10 通)。
    #[must_use]
    pub fn is_reliable(&self) -> bool {
        self.sample_count >= 10
    }

    /// メール特徴量でプロファイルを更新する (指数移動平均)。
    pub fn update(&mut self, features: &EmailStyleFeatures) {
        // NaN/Infinity の f32 フィールドを持つ features を拒否する。
        // lerp に NaN/Inf が入るとプロファイル全体が NaN に汚染され、
        // style_distance が NaN を返して warning_level が None になるバイパスが生じる。
        if !features.is_finite() {
            tracing::warn!("SSA: NaN/Infinity を含む EmailStyleFeatures を無視しました");
            return;
        }
        let n = self.sample_count as f32;
        let alpha = 1.0 / (n + 1.0); // 新規サンプルの重み

        self.avg_paragraphs = lerp(self.avg_paragraphs, features.paragraphs as f32, alpha);
        self.avg_sentences_per_paragraph = lerp(
            self.avg_sentences_per_paragraph,
            features.sentences_per_paragraph,
            alpha,
        );
        self.avg_chars_per_sentence = lerp(
            self.avg_chars_per_sentence,
            features.chars_per_sentence,
            alpha,
        );
        self.punctuation_density = lerp(
            self.punctuation_density,
            features.punctuation_density,
            alpha,
        );
        self.formality_score = lerp(self.formality_score, features.formality_score, alpha);
        self.avg_email_length = lerp(self.avg_email_length, features.email_length as f32, alpha);
        self.avg_signature_lines = lerp(
            self.avg_signature_lines,
            features.signature_lines as f32,
            alpha,
        );

        // 送信時刻分布を更新 (% 24 で範囲外の send_hour を正規化)
        let hour = (features.send_hour as usize) % 24;
        for (i, slot) in self.send_hour_distribution.iter_mut().enumerate() {
            if i == hour {
                *slot = lerp(*slot, 1.0, alpha);
            } else {
                *slot = lerp(*slot, 0.0, alpha * 0.1); // 他の時間帯は緩やかに減衰
            }
        }

        // saturating_add でオーバーフロー防止。
        // u32::MAX に達したらそれ以上増加せず、alpha が 0 に近い安定状態を維持する。
        self.sample_count = self.sample_count.saturating_add(1);
        self.last_updated_unix = now_unix();
    }

    /// 新着メールとのスタイル距離を計算。
    ///
    /// 戻り値: 0.0 (完全一致) 〜 1.0 (完全乖離)
    /// 0.60 以上で警告を推奨。
    #[must_use]
    pub fn style_distance(&self, features: &EmailStyleFeatures) -> f32 {
        if !self.is_reliable() {
            return 0.0; // 信頼性不足のプロファイルは使わない
        }
        if !features.is_finite() {
            return 1.0; // NaN/Inf 特徴量は最大距離 (最悪ケース) として扱う
        }

        // 距離は各軸の重み付き寄与の「和」を 1.0 でキャップ (正規化しない)。
        // 軸を追加しても既存軸の寄与が希釈されず、D9 Phase 2 で実測した
        // 検出面 (1軸 0.25 / 最強3軸 0.65 / 全軸 1.0) が保存される。
        let mut weighted_dist = 0.0_f32;

        // 送信時刻 (重み: 0.25) — AiTM/なりすましで深夜送信が多い
        // send_hour は u8 (0-255) かつ EmailStyleFeatures のフィールドは pub のため、
        // 24 以上の値で配列インデックスがパニックしうる。% 24 で必ず範囲内に収める。
        let hour = (features.send_hour as usize) % 24;
        let hour_prob = self.send_hour_distribution[hour];
        let hour_dist = 1.0 - hour_prob.clamp(0.0, 1.0);
        weighted_dist += 0.25 * hour_dist;

        // フォーマリティ (重み: 0.25) — AI は過丁寧になりやすい
        let form_dist = (self.formality_score - features.formality_score).abs();
        weighted_dist += 0.25 * form_dist.min(1.0);

        // 文の長さ (重み: 0.20)
        let sent_dist = ratio_dist(self.avg_chars_per_sentence, features.chars_per_sentence);
        weighted_dist += 0.20 * sent_dist;

        // メール長 (重み: 0.15)
        let len_dist = ratio_dist(self.avg_email_length, features.email_length as f32);
        weighted_dist += 0.15 * len_dist;

        // 句読点密度 (重み: 0.15)
        let punct_dist = (self.punctuation_density - features.punctuation_density)
            .abs()
            .min(1.0);
        weighted_dist += 0.15 * punct_dist;

        // 段落数・段落あたり文数・署名行数 (各 0.05) — D9 Phase 2 の実測で
        // 抽出・EMA 保持済みだが距離に未寄与のデッド次元と判明したため配線。
        // 単独では警告に届かない補強次元として、攻撃者が文体を真似る際の
        // コストを上げる。
        weighted_dist += 0.05 * ratio_dist(self.avg_paragraphs, features.paragraphs as f32);
        weighted_dist += 0.05
            * ratio_dist(
                self.avg_sentences_per_paragraph,
                features.sentences_per_paragraph,
            );
        weighted_dist +=
            0.05 * ratio_dist(self.avg_signature_lines, features.signature_lines as f32);

        weighted_dist.min(1.0)
    }

    /// スタイル距離から警告レベルを判定する。
    #[must_use]
    pub fn warning_level(&self, distance: f32) -> StyleWarning {
        if !self.is_reliable() {
            return StyleWarning::InsufficientData;
        }
        match distance {
            d if d >= 0.75 => StyleWarning::High,
            d if d >= 0.60 => StyleWarning::Medium,
            d if d >= 0.40 => StyleWarning::Low,
            _ => StyleWarning::None,
        }
    }
}

// ============================================================================
// 自己送信メールのなりすまし検出 (アカウント乗っ取り対策)
// ============================================================================

/// 「自分自身のアカウントが乗っ取られていないか」を送信メールで検査する。
///
/// # 背景
///
/// 従来の SSA は受信メールの送信者を検証する用途のみを想定していた
/// (他者が自分になりすましていないか)。しかし BEC の実被害では、
/// AiTM (Adversary-in-the-Middle) によるセッションクッキー窃取等で
/// **自分自身のアカウントが乗っ取られ**、正規の認証情報を持つ攻撃者が
/// 取引先や経理部門へ送金指示メールを送るケースが多い。
/// この場合 SPF/DKIM/DMARC は全て正規に通過するため、受信側の対策
/// (kaname-bec) だけでは検出できない。
///
/// 対策として、送信メール (Sent) にも同じ文体プロファイル手法を適用し、
/// 「自分の普段の文体から逸脱」かつ「金融/緊急性の高い要求を含む」の
/// 複合条件が揃った場合に警告を強める。
///
/// # 引数
///
/// - `own_profile`: 自分自身の過去の送信メールから構築した文体プロファイル。
/// - `features`: 今回送信しようとしているメールの特徴量。
/// - `contains_financial_request`: 件名/本文に金融・緊急送金系のキーワードが
///   含まれるか (呼び出し側で判定し渡す。本文そのものはこの関数に渡さない)。
#[must_use]
pub fn assess_self_send_anomaly(
    own_profile: &SenderStyleProfile,
    features: &EmailStyleFeatures,
    contains_financial_request: bool,
) -> StyleWarning {
    if !own_profile.is_reliable() {
        return StyleWarning::InsufficientData;
    }
    let dist = own_profile.style_distance(features);
    let base = own_profile.warning_level(dist);
    if contains_financial_request {
        // 文体逸脱 + 金融要求の複合は、片方だけの場合より深刻な
        // アカウント乗っ取りシグナルのため、警告レベルを一段階引き上げる。
        escalate_warning(base)
    } else {
        base
    }
}

/// `StyleWarning` を一段階深刻な方向へ引き上げる。
/// `InsufficientData` は判断材料不足を意味するため対象外 (そのまま維持)。
fn escalate_warning(w: StyleWarning) -> StyleWarning {
    match w {
        StyleWarning::None => StyleWarning::Low,
        StyleWarning::Low => StyleWarning::Medium,
        StyleWarning::Medium | StyleWarning::High => StyleWarning::High,
        StyleWarning::InsufficientData => StyleWarning::InsufficientData,
    }
}

// ============================================================================
// メールスタイル特徴量
// ============================================================================

/// メール本文から抽出した文体特徴量。
///
/// コンテンツ (本文テキスト) は含まない。数値のみ。
#[derive(Debug, Clone, PartialEq)]
pub struct EmailStyleFeatures {
    /// 段落数
    pub paragraphs: u32,
    /// 1 段落あたりの文数
    pub sentences_per_paragraph: f32,
    /// 1 文あたりの文字数
    pub chars_per_sentence: f32,
    /// 読点密度 (100 文字あたり)
    pub punctuation_density: f32,
    /// フォーマリティ (0.0-1.0)
    pub formality_score: f32,
    /// メール全体の文字数
    pub email_length: u32,
    /// 署名の行数
    pub signature_lines: u32,
    /// 送信時刻 (0-23)
    pub send_hour: u8,
}

impl EmailStyleFeatures {
    /// 全 f32 フィールドが有限値 (NaN でも Infinity でもない) か確認する。
    #[must_use]
    pub fn is_finite(&self) -> bool {
        self.sentences_per_paragraph.is_finite()
            && self.chars_per_sentence.is_finite()
            && self.punctuation_density.is_finite()
            && self.formality_score.is_finite()
    }

    /// テキストと送信時刻から特徴量を抽出する。
    #[must_use]
    pub fn extract(body: &str, send_hour: u8) -> Self {
        const MAX_BODY_BYTES: usize = 500_000; // 500 KB
        let body = if body.len() > MAX_BODY_BYTES {
            // UTF-8 マルチバイト境界を壊さないよう char 境界で切り捨てる
            let end = body
                .char_indices()
                .map(|(i, _)| i)
                .take_while(|&i| i < MAX_BODY_BYTES)
                .last()
                .unwrap_or(0);
            &body[..end]
        } else {
            body
        };
        let paragraphs = count_paragraphs(body);
        let sentences = count_sentences(body);
        let chars = body.chars().count() as u32;
        let punctuation = count_punctuation(body);
        let signature_lines = estimate_signature_lines(body);
        let formality = estimate_formality(body);

        let sentences_per_paragraph = if paragraphs > 0 {
            sentences as f32 / paragraphs as f32
        } else {
            sentences as f32
        };

        let chars_per_sentence = if sentences > 0 {
            chars as f32 / sentences as f32
        } else {
            chars as f32
        };

        let punctuation_density = if chars > 0 {
            (punctuation as f32 * 100.0) / chars as f32
        } else {
            0.0
        };

        Self {
            paragraphs,
            sentences_per_paragraph,
            chars_per_sentence,
            punctuation_density,
            formality_score: formality,
            email_length: chars,
            signature_lines,
            send_hour: send_hour % 24, // 範囲外の時刻を正規化 (配列パニック防止)
        }
    }
}

// ============================================================================
// 警告レベル
// ============================================================================

/// 文体距離に基づく警告レベル。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StyleWarning {
    /// 問題なし
    None,
    /// 軽微な乖離 (念のため表示)
    Low,
    /// 有意な乖離 (警告)
    Medium,
    /// 強い乖離 (強く警告)
    High,
    /// サンプル不足でプロファイル未確立
    InsufficientData,
}

// ============================================================================
// ユーティリティ
// ============================================================================

fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a * (1.0 - t) + b * t
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn count_paragraphs(text: &str) -> u32 {
    // 空行で区切られた段落
    text.split("\n\n").filter(|p| !p.trim().is_empty()).count() as u32
}

fn count_sentences(text: &str) -> u32 {
    // 句点・ピリオド・感嘆符・疑問符で区切る
    text.chars()
        .filter(|c| matches!(c, '。' | '．' | '.' | '!' | '?' | '！' | '？'))
        .count() as u32
}

fn count_punctuation(text: &str) -> u32 {
    // 読点・カンマ
    text.chars()
        .filter(|c| matches!(c, '、' | '，' | ','))
        .count() as u32
}

fn estimate_signature_lines(text: &str) -> u32 {
    // 最後の 5 行が署名と仮定 (典型的なパターン)
    let lines: Vec<&str> = text.lines().collect();
    let last_lines = &lines[lines.len().saturating_sub(5)..];
    last_lines.iter().filter(|l| !l.trim().is_empty()).count() as u32
}

fn estimate_formality(text: &str) -> f32 {
    // 丁寧語・敬語の出現頻度で判定 (単純な存在フラグではなく出現回数を使う)
    // これにより AI が "please" を 1 回だけ挿入しても高フォーマリティと誤判定されない
    let polite_japanese = ["ます", "です", "いただ", "ございます", "申し", "存じ"];
    let casual_japanese = ["だよ", "じゃん", "ね〜", "かな", "だな"];
    let polite_english = ["please", "kindly", "would you", "sincerely", "regards"];
    let casual_english = ["hey", "thanks", "cheers", "gonna", "wanna"];

    let lower = text.to_lowercase();

    // 出現回数を数える (binary ではなく frequency)
    let polite_count: u32 = polite_japanese
        .iter()
        .map(|kw| count_occurrences(text, kw))
        .chain(
            polite_english
                .iter()
                .map(|kw| count_occurrences(&lower, kw)),
        )
        .sum();
    let casual_count: u32 = casual_japanese
        .iter()
        .map(|kw| count_occurrences(text, kw))
        .chain(
            casual_english
                .iter()
                .map(|kw| count_occurrences(&lower, kw)),
        )
        .sum();

    let total = (polite_count + casual_count) as f32;
    if total == 0.0 {
        0.5 // 不明
    } else {
        polite_count as f32 / total
    }
}

/// テキスト内のパターン出現回数を数える。
fn count_occurrences(text: &str, pattern: &str) -> u32 {
    let mut count = 0u32;
    let mut start = 0;
    while let Some(pos) = text[start..].find(pattern) {
        count += 1;
        start += pos + pattern.len();
    }
    count
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;

    pub(crate) fn make_profile(sample_count: u32) -> SenderStyleProfile {
        let mut p = SenderStyleProfile::new("cfo@company.co.jp");
        // 典型的な CFO のメールパターン
        for i in 0..sample_count {
            p.update(&EmailStyleFeatures {
                paragraphs: 2,
                sentences_per_paragraph: 2.0,
                chars_per_sentence: 40.0,
                punctuation_density: 2.5,
                formality_score: 0.8,
                email_length: 200,
                signature_lines: 3,
                send_hour: if i % 5 == 0 { 11 } else { 10 }, // 時々 11 時
            });
        }
        p
    }

    #[test]
    fn new_profile_is_not_reliable() {
        let p = SenderStyleProfile::new("test@example.com");
        assert!(!p.is_reliable());
    }

    #[test]
    fn profile_becomes_reliable_at_10_samples() {
        let p = make_profile(10);
        assert!(p.is_reliable());
    }

    #[test]
    fn out_of_range_send_hour_does_not_panic() {
        // 細工メール: Date ヘッダが範囲外の時刻 (99) にパースされた、または
        // pub フィールド経由で send_hour=99 を直接構築されたケース。
        // 配列インデックス [99] でパニックしてはならない (untrusted 入力での DoS 防止)。
        let profile = make_profile(30);
        let crafted = EmailStyleFeatures {
            paragraphs: 2,
            sentences_per_paragraph: 2.0,
            chars_per_sentence: 40.0,
            punctuation_density: 2.5,
            formality_score: 0.8,
            email_length: 200,
            signature_lines: 3,
            send_hour: 99, // 範囲外
        };
        // パニックせず有限のスコアを返すこと
        let dist = profile.style_distance(&crafted);
        assert!(
            dist.is_finite() && (0.0..=1.0).contains(&dist),
            "dist={dist}"
        );

        // update も範囲外 send_hour でパニックしないこと
        let mut p2 = SenderStyleProfile::new("x@y.com");
        p2.update(&crafted); // send_hour=99
    }

    #[test]
    fn extract_normalizes_out_of_range_hour() {
        // 範囲外の send_hour は extract で 0-23 に正規化される (99 % 24 = 3)
        let f = EmailStyleFeatures::extract("こんにちは。", 99);
        assert!(
            f.send_hour < 24,
            "send_hour が正規化されていない: {}",
            f.send_hour
        );
        assert_eq!(f.send_hour, 99 % 24);
    }

    #[test]
    fn identical_style_has_low_distance() {
        let profile = make_profile(30);
        let same_style = EmailStyleFeatures {
            paragraphs: 2,
            sentences_per_paragraph: 2.0,
            chars_per_sentence: 40.0,
            punctuation_density: 2.5,
            formality_score: 0.8,
            email_length: 200,
            signature_lines: 3,
            send_hour: 10,
        };
        let dist = profile.style_distance(&same_style);
        assert!(dist < 0.30, "dist={dist:.3}");
    }

    #[test]
    fn ai_generated_style_has_high_distance() {
        let profile = make_profile(30);
        // AI 生成の特徴: 深夜送信、過丁寧、長文
        let ai_style = EmailStyleFeatures {
            paragraphs: 5,
            sentences_per_paragraph: 4.0,
            chars_per_sentence: 80.0, // 2x 長い
            punctuation_density: 5.0, // 2x 多い
            formality_score: 0.98,    // 過丁寧
            email_length: 800,        // 4x 長い
            signature_lines: 1,
            send_hour: 23, // 深夜送信
        };
        let dist = profile.style_distance(&ai_style);
        assert!(dist > 0.50, "dist={dist:.3}");
    }

    #[test]
    fn midnight_send_increases_distance() {
        let profile = make_profile(20);
        let normal = EmailStyleFeatures {
            paragraphs: 2,
            sentences_per_paragraph: 2.0,
            chars_per_sentence: 40.0,
            punctuation_density: 2.5,
            formality_score: 0.8,
            email_length: 200,
            signature_lines: 3,
            send_hour: 10,
        };
        let midnight = EmailStyleFeatures {
            send_hour: 23,
            ..normal
        };
        assert!(
            profile.style_distance(&midnight) > profile.style_distance(&normal),
            "深夜送信はスタイル距離を高める"
        );
    }

    #[test]
    fn insufficient_samples_return_zero_distance() {
        let profile = make_profile(5); // 10 未満
        let features = EmailStyleFeatures {
            paragraphs: 2,
            sentences_per_paragraph: 2.0,
            chars_per_sentence: 40.0,
            punctuation_density: 2.5,
            formality_score: 0.8,
            email_length: 200,
            signature_lines: 3,
            send_hour: 10,
        };
        // 信頼性不足 → 距離 0.0 (無視)
        assert_eq!(profile.style_distance(&features), 0.0);
    }

    #[test]
    fn warning_level_high_above_075() {
        let profile = make_profile(20);
        assert_eq!(profile.warning_level(0.80), StyleWarning::High);
    }

    #[test]
    fn warning_level_medium_060_to_075() {
        let profile = make_profile(20);
        assert_eq!(profile.warning_level(0.65), StyleWarning::Medium);
    }

    #[test]
    fn warning_level_none_below_040() {
        let profile = make_profile(20);
        assert_eq!(profile.warning_level(0.20), StyleWarning::None);
    }

    #[test]
    fn insufficient_data_on_new_profile() {
        let profile = make_profile(3);
        assert_eq!(profile.warning_level(0.9), StyleWarning::InsufficientData);
    }

    #[test]
    fn extract_features_works_on_japanese() {
        let body = "お世話になっております。\nご確認をお願いいたします。\n\n田中部長";
        let features = EmailStyleFeatures::extract(body, 10);
        assert!(features.email_length > 0);
        assert!(
            features.formality_score > 0.5,
            "敬語が多い文章のフォーマリティは高い"
        );
    }

    #[test]
    fn extract_features_works_on_english() {
        let body = "Hi there,\nPlease review the attached document at your earliest convenience.\n\nBest regards,\nJohn";
        let features = EmailStyleFeatures::extract(body, 14);
        assert_eq!(features.send_hour, 14);
        assert!(features.paragraphs >= 1);
    }

    #[test]
    fn formality_uses_frequency_not_presence() {
        // 従来の実装 (存在フラグ) なら 1 回の "please" で formality=1.0 になる
        // 新実装 (出現頻度) では頻度が低ければ casual に引っ張られる
        let heavy_casual = "gonna get this done. wanna check cheers hey thanks done.";
        let with_one_please = format!("please {heavy_casual}");
        let features = EmailStyleFeatures::extract(&with_one_please, 10);
        // "please" 1 回 vs casual 5 回 → formality は 0.5 以下のはず
        assert!(
            features.formality_score < 0.5,
            "1 回 please に対して casual が多いとき formality は低いはず: {}",
            features.formality_score
        );
    }

    #[test]
    fn profile_serialization_round_trip() {
        let p = make_profile(15);
        let json = serde_json::to_string(&p).expect("serialize");
        let restored: SenderStyleProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p.sender, restored.sender);
        assert_eq!(p.sample_count, restored.sample_count);
        // コンテンツが入ってないことを確認 (数値のみ)
        assert!(!json.contains("メール本文"), "本文テキストが漏洩している");
    }

    #[test]
    fn sample_count_does_not_overflow() {
        let mut p = SenderStyleProfile::new("alice@example.com");
        p.sample_count = u32::MAX;
        // saturating_add: u32::MAX + 1 = u32::MAX (not 0)
        p.update(&EmailStyleFeatures {
            paragraphs: 1,
            sentences_per_paragraph: 1.0,
            chars_per_sentence: 30.0,
            punctuation_density: 1.0,
            formality_score: 0.5,
            email_length: 100,
            signature_lines: 0,
            send_hour: 10,
        });
        assert_eq!(p.sample_count, u32::MAX, "saturating_add が機能していない");
        // オーバーフロー後も is_reliable() は true のまま
        assert!(
            p.is_reliable(),
            "オーバーフロー後に is_reliable() が false になった"
        );
    }

    #[test]
    fn alpha_near_zero_at_saturation() {
        // sample_count = u32::MAX のとき alpha ≈ 2.3e-10 → lerp はほぼ old 値を返す
        let mut p = SenderStyleProfile::new("alice@example.com");
        p.sample_count = u32::MAX - 1;
        p.avg_paragraphs = 3.0;
        p.update(&EmailStyleFeatures {
            paragraphs: 100, // 極端な値を入れても avg は変わらないはず
            sentences_per_paragraph: 1.0,
            chars_per_sentence: 30.0,
            punctuation_density: 1.0,
            formality_score: 0.5,
            email_length: 100,
            signature_lines: 0,
            send_hour: 10,
        });
        // avg_paragraphs は 3.0 からほとんど動かないはず (alpha ≈ 2.3e-10)
        assert!(
            (p.avg_paragraphs - 3.0).abs() < 0.01,
            "alpha が大きすぎる: avg_paragraphs = {}",
            p.avg_paragraphs
        );
    }

    // ── NaN / Infinity 攻撃回帰テスト ───────────────────────────────────────

    fn nan_features() -> EmailStyleFeatures {
        EmailStyleFeatures {
            paragraphs: 2,
            sentences_per_paragraph: f32::NAN,
            chars_per_sentence: f32::INFINITY,
            punctuation_density: f32::NAN,
            formality_score: f32::NAN,
            email_length: 200,
            signature_lines: 3,
            send_hour: 10,
        }
    }

    #[test]
    fn nan_features_do_not_corrupt_profile() {
        let mut profile = make_profile(30);
        let original_formality = profile.formality_score;
        profile.update(&nan_features());
        assert!(
            profile.formality_score.is_finite(),
            "NaN update 後も有限値でなければならない"
        );
        assert!(
            (profile.formality_score - original_formality).abs() < 1e-3,
            "NaN update はプロファイルを変更してはならない"
        );
    }

    #[test]
    fn nan_features_style_distance_returns_max() {
        let profile = make_profile(30);
        let dist = profile.style_distance(&nan_features());
        assert!(
            (dist - 1.0).abs() < 1e-6,
            "NaN 特徴量の距離は 1.0 でなければならない: {dist}"
        );
    }

    #[test]
    fn nan_features_warning_level_is_high() {
        let profile = make_profile(30);
        let dist = profile.style_distance(&nan_features());
        let warn = profile.warning_level(dist);
        assert_eq!(
            warn,
            StyleWarning::High,
            "NaN 特徴量は High 警告でなければならない"
        );
    }

    #[test]
    fn large_body_extract_does_not_oom() {
        let huge = "は".repeat(200_000);
        let features = EmailStyleFeatures::extract(&huge, 10);
        assert!(features.is_finite(), "大入力でも有限の特徴量が返るべき");
    }

    // ── 組織ベースライン Cold-Start 対策テスト ──────────────────────────────

    #[test]
    fn self_send_matching_own_style_is_none() {
        let own = make_profile(30);
        let normal = EmailStyleFeatures {
            paragraphs: 2,
            sentences_per_paragraph: 2.0,
            chars_per_sentence: 40.0,
            punctuation_density: 2.5,
            formality_score: 0.8,
            email_length: 200,
            signature_lines: 3,
            send_hour: 10,
        };
        let warning = assess_self_send_anomaly(&own, &normal, false);
        assert_eq!(
            warning,
            StyleWarning::None,
            "普段の文体と一致する自己送信は警告なしであるべき"
        );
    }

    #[test]
    fn self_send_style_deviation_without_financial_request_is_moderate() {
        // 文体逸脱のみ (金融要求なし) — 通常の warning_level のまま
        let own = make_profile(30);
        let deviated = EmailStyleFeatures {
            paragraphs: 5,
            sentences_per_paragraph: 4.0,
            chars_per_sentence: 80.0,
            punctuation_density: 5.0,
            formality_score: 0.98,
            email_length: 800,
            signature_lines: 1,
            send_hour: 23,
        };
        let warning = assess_self_send_anomaly(&own, &deviated, false);
        assert!(
            matches!(warning, StyleWarning::Medium | StyleWarning::High),
            "文体逸脱のみでも通常の警告は出るべき: {warning:?}"
        );
    }

    #[test]
    fn self_send_style_deviation_with_financial_request_is_escalated() {
        // アカウント乗っ取りの典型パターン: 文体逸脱 + 金融/緊急要求の複合
        // → escalate_warning により通常より一段階深刻な警告になるべき
        let own = make_profile(30);
        // わずかな逸脱 (通常なら Low 程度) だが金融要求と組み合わさる
        let slight_deviation = EmailStyleFeatures {
            paragraphs: 2,
            sentences_per_paragraph: 2.0,
            chars_per_sentence: 40.0,
            punctuation_density: 2.5,
            formality_score: 0.55,
            email_length: 200,
            signature_lines: 3,
            send_hour: 10,
        };
        let without_financial = assess_self_send_anomaly(&own, &slight_deviation, false);
        let with_financial = assess_self_send_anomaly(&own, &slight_deviation, true);
        assert_ne!(
            with_financial, without_financial,
            "金融要求が絡む場合は文体逸脱のみのケースよりエスカレートすべき: \
             without={without_financial:?} with={with_financial:?}"
        );
    }

    #[test]
    fn self_send_cold_start_returns_insufficient_data() {
        // 自己プロファイルが未確立 (新規アカウント) の場合は判断材料不足
        let own = SenderStyleProfile::new("me@company.com");
        let features = EmailStyleFeatures {
            paragraphs: 2,
            sentences_per_paragraph: 2.0,
            chars_per_sentence: 40.0,
            punctuation_density: 2.5,
            formality_score: 0.8,
            email_length: 200,
            signature_lines: 3,
            send_hour: 10,
        };
        let warning = assess_self_send_anomaly(&own, &features, true);
        assert_eq!(warning, StyleWarning::InsufficientData);
    }

    #[test]
    fn escalate_warning_caps_at_high() {
        assert_eq!(escalate_warning(StyleWarning::None), StyleWarning::Low);
        assert_eq!(escalate_warning(StyleWarning::Low), StyleWarning::Medium);
        assert_eq!(escalate_warning(StyleWarning::Medium), StyleWarning::High);
        assert_eq!(escalate_warning(StyleWarning::High), StyleWarning::High);
        assert_eq!(
            escalate_warning(StyleWarning::InsufficientData),
            StyleWarning::InsufficientData
        );
    }
}

// ============================================================================
// 校正ハーネス (D9): 閾値の検出面を敵対的列挙で実測
// ============================================================================
//
// `docs/design-d9-ssa-calibration.md` Phase 2 (測定) のうちモデル不要の
// 決定論的部分をテストとして固定する。「被害者プロファイルを完全に知る
// 攻撃者が、任意の軸を最大限に外したメールを送ったとき、どの軸の組合せで
// 警告が出るか」を全 31 通りの軸サブセットについて列挙する。
//
// style_distance の有効次元は 5 軸のみ (send_hour 0.25 / formality 0.25 /
// chars_per_sentence 0.20 / email_length 0.15 / punctuation_density 0.15)。
// paragraphs / sentences_per_paragraph / signature_lines は抽出されるが
// 距離計算に一切寄与しない (抽出のみのデッド次元)。
//
// 実測された検出面 (下のテストが回帰ガードとして固定):
//   - 1 軸のみを完全に外す攻撃: 最大 0.25 — **警告すら出ない** (Low 0.40
//     にも届かない)。「文体を完全に真似たが深夜送信」は検出対象外
//   - 2 軸を完全に外す攻撃: 最大 ~0.45 — Low まで。**Medium には到達不能**
//   - 3 軸を完全に外す攻撃: 0.50-0.65 — 一部のみ Medium に到達
//   - 全 5 軸を外す攻撃: 1.0 — High
// これが閾値 0.40/0.60/0.75 の実際の検出面であり、D9 校正の基線である。

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod calibration_tests {
    use super::tests::make_profile;
    use super::*;

    /// 距離に寄与する 8 軸の識別子 (D9: 段落/段落あたり文数/署名行数は
    /// かつてデッド次元だったが配線済み)。
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Axis {
        Hour,
        Formality,
        SentLen,
        Length,
        Punct,
        Paragraphs,
        SentPerPara,
        Signature,
    }

    const AXES: [Axis; 8] = [
        Axis::Hour,
        Axis::Formality,
        Axis::SentLen,
        Axis::Length,
        Axis::Punct,
        Axis::Paragraphs,
        Axis::SentPerPara,
        Axis::Signature,
    ];

    /// プロファイルの想定文体を完全に真似た特徴量を返し、指定された軸
    /// だけを「その軸で到達可能な最大乖離」に書き換える。
    /// (プロファイル値: cps=40, len=200, punct=2.5, formality=0.8, hour=10,
    ///  paragraphs=2, spp=2.0, sig=3)
    fn mimicry(overrides: &[Axis]) -> EmailStyleFeatures {
        let mut f = EmailStyleFeatures {
            paragraphs: 2,
            sentences_per_paragraph: 2.0,
            chars_per_sentence: 40.0,
            punctuation_density: 2.5,
            formality_score: 0.8,
            email_length: 200,
            signature_lines: 3,
            send_hour: 10,
        };
        for axis in overrides {
            match axis {
                // 深夜 3 時 — プロファイル上ほぼ 0% の時間帯
                Axis::Hour => f.send_hour = 3,
                // 超丁寧な CFO が完全な口語に (dist = 0.8 が最大)
                Axis::Formality => f.formality_score = 0.0,
                // 1 文 200 文字の極端に長い文 (ratio 4.0 → cap 1.0)
                Axis::SentLen => f.chars_per_sentence = 200.0,
                // 20 倍の長文 (ratio cap 1.0)
                Axis::Length => f.email_length = 4000,
                // 読点 20/100文字 (|2.5-20| → cap 1.0)
                Axis::Punct => f.punctuation_density = 20.0,
                // 10 倍の段落数 (ratio cap 1.0)
                Axis::Paragraphs => f.paragraphs = 20,
                // 1 段落 10 文 (ratio 4.0 → cap 1.0)
                Axis::SentPerPara => f.sentences_per_paragraph = 10.0,
                // 署名 30 行 (ratio 9.0 → cap 1.0)
                Axis::Signature => f.signature_lines = 30,
            }
        }
        f
    }

    /// 全軸サブセット (255 通り) の距離を実測して返す。
    fn enumerate_surface() -> Vec<(Vec<Axis>, f32, StyleWarning)> {
        let profile = make_profile(30);
        assert!(profile.is_reliable());
        let mut out = Vec::new();
        // 部分集合を bitmask で列挙
        for mask in 1u32..(1 << AXES.len()) {
            let axes: Vec<Axis> = AXES
                .iter()
                .copied()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, a)| a)
                .collect();
            let f = mimicry(&axes);
            let d = profile.style_distance(&f);
            out.push((axes, d, profile.warning_level(d)));
        }
        out
    }

    /// 検出面の基線: 1 軸のみを最大乖離しても警告は **一切出ない**。
    /// 「文体を完璧に真似たが送信時刻だけ異常」な BEC は素通しになる。
    #[test]
    fn 単一軸の最大乖離は警告に届かない() {
        for (axes, d, w) in enumerate_surface() {
            if axes.len() == 1 {
                assert!(
                    matches!(w, StyleWarning::None),
                    "{axes:?} が {d} で警告 {w:?} — 単一軸攻撃が可視化されてしまった (これは良い変化だが検出面の記録を更新すること)"
                );
            }
        }
    }

    /// 検出面の基線: 2 軸まで同時に完全に外されても Medium 以上には
    /// 到達しない (最大でも Low)。
    #[test]
    fn 二軸の最大乖離はlowまででmediumに届かない() {
        for (axes, _d, w) in enumerate_surface() {
            if axes.len() == 2 {
                assert!(
                    matches!(w, StyleWarning::None | StyleWarning::Low),
                    "{axes:?} が {w:?} — 二軸攻撃が Medium に到達"
                );
            }
        }
    }

    /// 検出面の基線: 最強の 3 軸組合せ (送信時刻+フォーマリティ+文長)
    /// で初めて Medium に到達する。
    #[test]
    fn 最強三軸で初めてmediumに到達する() {
        for (axes, _d, w) in enumerate_surface() {
            if axes == [Axis::Hour, Axis::Formality, Axis::SentLen] {
                assert_eq!(w, StyleWarning::Medium, "最強3軸は Medium のはず");
            }
        }
    }

    /// 検出面の基線: 全軸を外すと必ず High。
    #[test]
    fn 全軸乖離はhighに到達する() {
        for (axes, _d, w) in enumerate_surface() {
            if axes.len() == AXES.len() {
                assert_eq!(w, StyleWarning::High);
            }
        }
    }

    /// 段落/段落あたり文数/署名行数は距離に寄与する (デッド次元の再発防止)。
    /// ただし補強次元なので、これら 3 軸だけを外した攻撃は単独では警告に
    /// 届かない (0.15/1.15 ≈ 0.13 < Low 0.40)。
    #[test]
    fn 旧デッド次元は配線済みだが単独では警告に届かない() {
        let profile = make_profile(30);
        let f = mimicry(&[Axis::Paragraphs, Axis::SentPerPara, Axis::Signature]);
        let d = profile.style_distance(&f);
        assert!(d > 0.0, "3 軸乖離が距離に寄与していない (再デッド化)");
        assert!(
            matches!(profile.warning_level(d), StyleWarning::None),
            "補強次元のみの乖離が警告になった (d={d})"
        );
    }

    /// 誤検知面の基線: 正当なばらつき (数値 ±20%・formality -0.05・
    /// 1 時間ずれ) の同時発生では警告が出ないこと。
    #[test]
    fn 正当なばらつきでは警告が出ない() {
        let profile = make_profile(30);
        let legit = EmailStyleFeatures {
            paragraphs: 3,
            sentences_per_paragraph: 2.4,
            chars_per_sentence: 48.0, // +20%
            punctuation_density: 3.0, // +20%
            formality_score: 0.75,
            email_length: 240, // +20%
            signature_lines: 3,
            send_hour: 11, // プロファイルに稀に存在する時間帯
        };
        let d = profile.style_distance(&legit);
        assert!(
            matches!(
                profile.warning_level(d),
                StyleWarning::None | StyleWarning::Low
            ),
            "正当なばらつきが {w:?} (d={d}) — 誤検知",
            w = profile.warning_level(d),
        );
    }
}

// ============================================================================
// プロパティテスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// 不変条件: スタイル距離は常に 0.0-1.0 の範囲
        #[test]
        fn style_distance_always_in_range(
            send_hour in 0u8..24,
            formality in 0.0f32..1.0,
            email_len in 10u32..5000,
        ) {
            let profile = {
                let mut p = SenderStyleProfile::new("test@example.com");
                for _ in 0..15 {
                    p.update(&EmailStyleFeatures {
                        paragraphs: 2,
                        sentences_per_paragraph: 2.0,
                        chars_per_sentence: 40.0,
                        punctuation_density: 2.0,
                        formality_score: 0.7,
                        email_length: 200,
                        signature_lines: 3,
                        send_hour: 10,
                    });
                }
                p
            };

            let features = EmailStyleFeatures {
                paragraphs: 2,
                sentences_per_paragraph: 2.0,
                chars_per_sentence: 40.0,
                punctuation_density: 2.0,
                formality_score: formality,
                email_length: email_len,
                signature_lines: 3,
                send_hour,
            };

            let dist = profile.style_distance(&features);
            prop_assert!(
                (0.0..=1.0).contains(&dist),
                "style_distance 範囲外: {dist}"
            );
        }

        /// 不変条件: 信頼性閾値は決定論的
        #[test]
        fn reliability_threshold_is_deterministic(n in 0u32..30) {
            let mut p = SenderStyleProfile::new("test@example.com");
            for _ in 0..n {
                p.update(&EmailStyleFeatures {
                    paragraphs: 1,
                    sentences_per_paragraph: 1.0,
                    chars_per_sentence: 30.0,
                    punctuation_density: 1.0,
                    formality_score: 0.5,
                    email_length: 100,
                    signature_lines: 2,
                    send_hour: 9,
                });
            }
            // 同じ n で同じ結果
            let r1 = p.is_reliable();
            let r2 = p.is_reliable();
            prop_assert_eq!(r1, r2, "is_reliable は決定論的でなければならない");
            // 10 通以上で信頼できる
            if n >= 10 {
                prop_assert!(p.is_reliable(), "10通以上で is_reliable = true");
            }
        }

        /// 不変条件: StyleWarning は連続的 (lower dist → lower warning)
        #[test]
        fn warning_monotone_with_distance(d in 0.0f32..1.0) {
            let profile = {
                let mut p = SenderStyleProfile::new("test@example.com");
                for _ in 0..15 {
                    p.update(&EmailStyleFeatures {
                        paragraphs: 1, sentences_per_paragraph: 1.0,
                        chars_per_sentence: 30.0, punctuation_density: 1.0,
                        formality_score: 0.5, email_length: 100,
                        signature_lines: 1, send_hour: 9,
                    });
                }
                p
            };
            let w = profile.warning_level(d);
            // High → Medium → Low → None の順序が維持される
            if d >= 0.75 {
                prop_assert_eq!(w, StyleWarning::High);
            } else if d >= 0.60 {
                prop_assert_eq!(w, StyleWarning::Medium);
            } else if d >= 0.40 {
                prop_assert_eq!(w, StyleWarning::Low);
            } else {
                prop_assert_eq!(w, StyleWarning::None);
            }
        }
    }
}
