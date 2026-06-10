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
        let n = self.sample_count as f32;
        let alpha = 1.0 / (n + 1.0); // 新規サンプルの重み

        self.avg_paragraphs = lerp(self.avg_paragraphs, features.paragraphs as f32, alpha);
        self.avg_sentences_per_paragraph =
            lerp(self.avg_sentences_per_paragraph, features.sentences_per_paragraph, alpha);
        self.avg_chars_per_sentence =
            lerp(self.avg_chars_per_sentence, features.chars_per_sentence, alpha);
        self.punctuation_density =
            lerp(self.punctuation_density, features.punctuation_density, alpha);
        self.formality_score =
            lerp(self.formality_score, features.formality_score, alpha);
        self.avg_email_length =
            lerp(self.avg_email_length, features.email_length as f32, alpha);
        self.avg_signature_lines =
            lerp(self.avg_signature_lines, features.signature_lines as f32, alpha);

        // 送信時刻分布を更新
        let hour = features.send_hour as usize;
        for (i, slot) in self.send_hour_distribution.iter_mut().enumerate() {
            if i == hour {
                *slot = lerp(*slot, 1.0, alpha);
            } else {
                *slot = lerp(*slot, 0.0, alpha * 0.1); // 他の時間帯は緩やかに減衰
            }
        }

        self.sample_count += 1;
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

        let mut weighted_dist = 0.0_f32;
        let mut weight_sum = 0.0_f32;

        // 送信時刻 (重み: 0.25) — AiTM/なりすましで深夜送信が多い
        let hour = features.send_hour as usize;
        let hour_prob = self.send_hour_distribution[hour];
        let hour_dist = 1.0 - hour_prob.clamp(0.0, 1.0);
        weighted_dist += 0.25 * hour_dist;
        weight_sum += 0.25;

        // フォーマリティ (重み: 0.25) — AI は過丁寧になりやすい
        let form_dist = (self.formality_score - features.formality_score).abs();
        weighted_dist += 0.25 * form_dist.min(1.0);
        weight_sum += 0.25;

        // 文の長さ (重み: 0.20)
        let sent_dist = if self.avg_chars_per_sentence > 0.0 {
            let ratio = (features.chars_per_sentence / self.avg_chars_per_sentence - 1.0).abs();
            ratio.min(1.0)
        } else {
            0.0
        };
        weighted_dist += 0.20 * sent_dist;
        weight_sum += 0.20;

        // メール長 (重み: 0.15)
        let len_dist = if self.avg_email_length > 0.0 {
            let ratio = (features.email_length as f32 / self.avg_email_length - 1.0).abs();
            ratio.min(1.0)
        } else {
            0.0
        };
        weighted_dist += 0.15 * len_dist;
        weight_sum += 0.15;

        // 句読点密度 (重み: 0.15)
        let punct_dist = (self.punctuation_density - features.punctuation_density).abs().min(1.0);
        weighted_dist += 0.15 * punct_dist;
        weight_sum += 0.15;

        if weight_sum > 0.0 {
            weighted_dist / weight_sum
        } else {
            0.0
        }
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
            _              => StyleWarning::None,
        }
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
    /// テキストと送信時刻から特徴量を抽出する。
    #[must_use]
    pub fn extract(body: &str, send_hour: u8) -> Self {
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
            send_hour,
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
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn count_paragraphs(text: &str) -> u32 {
    // 空行で区切られた段落
    text.split("\n\n")
        .filter(|p| !p.trim().is_empty())
        .count() as u32
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
    // 丁寧語・敬語の出現で判定
    let polite_japanese = ["ます", "です", "いただ", "ございます", "申し", "存じ"];
    let casual_japanese = ["だよ", "じゃん", "ね〜", "かな", "だな"];
    let polite_english = ["please", "kindly", "would you", "sincerely", "regards"];
    let casual_english = ["hey", "thanks", "cheers", "gonna", "wanna"];

    let lower = text.to_lowercase();
    let mut polite_count = 0u32;
    let mut casual_count = 0u32;

    for kw in &polite_japanese { if text.contains(kw) { polite_count += 1; } }
    for kw in &casual_japanese { if text.contains(kw) { casual_count += 1; } }
    for kw in &polite_english  { if lower.contains(kw) { polite_count += 1; } }
    for kw in &casual_english  { if lower.contains(kw) { casual_count += 1; } }

    let total = (polite_count + casual_count) as f32;
    if total == 0.0 {
        0.5 // 不明
    } else {
        polite_count as f32 / total
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;

    fn make_profile(sample_count: u32) -> SenderStyleProfile {
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
            send_hour: 23,            // 深夜送信
        };
        let dist = profile.style_distance(&ai_style);
        assert!(dist > 0.50, "dist={dist:.3}");
    }

    #[test]
    fn midnight_send_increases_distance() {
        let profile = make_profile(20);
        let normal = EmailStyleFeatures {
            paragraphs: 2, sentences_per_paragraph: 2.0, chars_per_sentence: 40.0,
            punctuation_density: 2.5, formality_score: 0.8, email_length: 200,
            signature_lines: 3, send_hour: 10,
        };
        let midnight = EmailStyleFeatures { send_hour: 23, ..normal };
        assert!(
            profile.style_distance(&midnight) > profile.style_distance(&normal),
            "深夜送信はスタイル距離を高める"
        );
    }

    #[test]
    fn insufficient_samples_return_zero_distance() {
        let profile = make_profile(5); // 10 未満
        let features = EmailStyleFeatures {
            paragraphs: 2, sentences_per_paragraph: 2.0, chars_per_sentence: 40.0,
            punctuation_density: 2.5, formality_score: 0.8, email_length: 200,
            signature_lines: 3, send_hour: 10,
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
        assert!(features.formality_score > 0.5, "敬語が多い文章のフォーマリティは高い");
    }

    #[test]
    fn extract_features_works_on_english() {
        let body = "Hi there,\nPlease review the attached document at your earliest convenience.\n\nBest regards,\nJohn";
        let features = EmailStyleFeatures::extract(body, 14);
        assert_eq!(features.send_hour, 14);
        assert!(features.paragraphs >= 1);
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
