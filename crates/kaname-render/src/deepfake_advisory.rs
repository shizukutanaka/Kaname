//! kaname-render/deepfake_advisory — Deepfake 添付ファイル警告
//!
//! 2026 年急増する Deepfake 攻撃 (音声/動画) に対するプロアクティブ警告。
//!
//! # 設計方針
//!
//! - **判定はしない** (Deepfake 検出は誤検出が多く、信頼性を損なう)
//! - **警告のみ表示** (ユーザーに判断を委ねる、Apple HIG 原則)
//! - **金融キーワードと組み合わせて警告レベルを上げる**
//! - Deepfake 検出 ML 統合は v0.3 以降に延期 (技術的成熟を待つ)
//!
//! # 検出する添付タイプ
//!
//! - 音声: mp3, wav, m4a, ogg, opus, flac
//! - 動画: mp4, mov, avi, mkv, webm, m4v

#![deny(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

// ============================================================================
// メディア種別
// ============================================================================

/// 添付ファイルのメディア種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaKind {
    /// 音声
    Audio,
    /// 動画
    Video,
    /// その他 (画像、文書等 — Deepfake 警告対象外)
    Other,
}

impl MediaKind {
    /// MIME タイプから判定する。
    #[must_use]
    pub fn from_mime(mime: &str) -> Self {
        let lower = mime.to_lowercase();
        if lower.starts_with("audio/") {
            return Self::Audio;
        }
        if lower.starts_with("video/") {
            return Self::Video;
        }
        Self::Other
    }

    /// ファイル拡張子から判定する (MIME 不明時のフォールバック)。
    #[must_use]
    pub fn from_extension(ext: &str) -> Self {
        let lower = ext.to_lowercase();
        let lower = lower.trim_start_matches('.');
        match lower {
            "mp3" | "wav" | "m4a" | "ogg" | "opus" | "flac" | "aac" | "wma" => Self::Audio,
            "mp4" | "mov" | "avi" | "mkv" | "webm" | "m4v" | "wmv" | "flv" => Self::Video,
            _ => Self::Other,
        }
    }

    /// 人間可読名 (UI 表示用)。
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Audio => "音声",
            Self::Video => "動画",
            Self::Other => "その他",
        }
    }

    /// Deepfake 警告対象か。
    #[must_use]
    pub fn is_deepfake_risk(&self) -> bool {
        matches!(self, Self::Audio | Self::Video)
    }
}

// ============================================================================
// 警告レベル
// ============================================================================

/// Deepfake 警告のレベル。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AdvisorySeverity {
    /// 警告なし (添付が音声/動画でない場合)
    None,
    /// 情報提供 (添付が音声/動画だが金融文脈なし)
    Info,
    /// 中レベル (音声/動画 + 軽い緊急性)
    Medium,
    /// 高レベル (音声/動画 + 金融キーワード + 緊急性)
    High,
}

impl AdvisorySeverity {
    /// UI で表示するアイコン。
    #[must_use]
    pub fn icon(&self) -> &'static str {
        match self {
            Self::None => "",
            Self::Info => "🎙️",
            Self::Medium => "⚠️",
            Self::High => "🚨",
        }
    }

    /// UI で表示する i18n キー。
    #[must_use]
    pub fn i18n_key(&self) -> &'static str {
        match self {
            Self::None => "",
            Self::Info => "deepfake.advisory.info",
            Self::Medium => "deepfake.advisory.medium",
            Self::High => "deepfake.advisory.high",
        }
    }
}

// ============================================================================
// 警告生成
// ============================================================================

/// Deepfake 警告判定エンジン。
#[derive(Debug, Default)]
pub struct DeepfakeAdvisory {
    financial_keywords: Vec<&'static str>,
    urgency_keywords: Vec<&'static str>,
}

impl DeepfakeAdvisory {
    /// 新規エンジンを構築する。
    #[must_use]
    pub fn new() -> Self {
        Self {
            financial_keywords: vec![
                // 日本語
                "振込", "口座", "送金", "支払", "請求", "決済",
                "入金", "出金", "資金", "残高", "為替",
                // 英語
                "wire transfer", "payment", "invoice", "deposit",
                "bank account", "remittance", "swift", "iban",
            ],
            urgency_keywords: vec![
                "至急", "緊急", "本日中", "今すぐ", "急いで",
                "urgent", "immediately", "asap", "right now",
            ],
        }
    }

    /// 添付ファイルから警告レベルを判定する。
    ///
    /// # Arguments
    ///
    /// - `attachments`: 添付ファイルの (filename, mime_type) のリスト
    /// - `body`: メール本文 (文脈判定用)
    #[must_use]
    pub fn evaluate(
        &self,
        attachments: &[(String, String)],
        body: &str,
    ) -> AdvisoryReport {
        let media_attachments: Vec<MediaAttachment> = attachments
            .iter()
            .map(|(filename, mime)| {
                let kind = if !mime.is_empty() {
                    MediaKind::from_mime(mime)
                } else if let Some(ext) = filename.rsplit('.').next() {
                    MediaKind::from_extension(ext)
                } else {
                    MediaKind::Other
                };
                MediaAttachment {
                    filename: filename.clone(),
                    mime: mime.clone(),
                    kind,
                }
            })
            .filter(|m| m.kind.is_deepfake_risk())
            .collect();

        if media_attachments.is_empty() {
            return AdvisoryReport {
                severity: AdvisorySeverity::None,
                affected_attachments: vec![],
                has_financial_context: false,
                has_urgency: false,
                recommended_action: RecommendedAction::None,
            };
        }

        let body_lower = body.to_lowercase();
        let has_financial = self
            .financial_keywords
            .iter()
            .any(|kw| body_lower.contains(kw));
        let has_urgency = self
            .urgency_keywords
            .iter()
            .any(|kw| body_lower.contains(kw));

        let severity = match (has_financial, has_urgency) {
            (true, true) => AdvisorySeverity::High,
            (true, false) | (false, true) => AdvisorySeverity::Medium,
            (false, false) => AdvisorySeverity::Info,
        };

        let recommended_action = match severity {
            AdvisorySeverity::High => RecommendedAction::OobvBeforePlay,
            AdvisorySeverity::Medium => RecommendedAction::PlayInSandbox,
            AdvisorySeverity::Info => RecommendedAction::ShowAdvisory,
            AdvisorySeverity::None => RecommendedAction::None,
        };

        AdvisoryReport {
            severity,
            affected_attachments: media_attachments,
            has_financial_context: has_financial,
            has_urgency,
            recommended_action,
        }
    }
}

// ============================================================================
// レポート
// ============================================================================

/// メディア添付ファイル。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaAttachment {
    /// ファイル名
    pub filename: String,
    /// MIME タイプ
    pub mime: String,
    /// メディア種別
    pub kind: MediaKind,
}

/// Deepfake 警告レポート。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryReport {
    /// 警告レベル
    pub severity: AdvisorySeverity,
    /// 影響を受けた添付ファイル
    pub affected_attachments: Vec<MediaAttachment>,
    /// 金融キーワードが本文にあるか
    pub has_financial_context: bool,
    /// 緊急性キーワードが本文にあるか
    pub has_urgency: bool,
    /// 推奨アクション
    pub recommended_action: RecommendedAction,
}

/// UI が取るべきアクション。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendedAction {
    /// 何もしない
    None,
    /// 情報バナーを表示
    ShowAdvisory,
    /// サンドボックスでのみ再生を許可
    PlayInSandbox,
    /// 再生前に OOBV 検証を強く推奨
    OobvBeforePlay,
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mime_audio_detected() {
        assert_eq!(MediaKind::from_mime("audio/mpeg"), MediaKind::Audio);
        assert_eq!(MediaKind::from_mime("audio/wav"), MediaKind::Audio);
        assert_eq!(MediaKind::from_mime("AUDIO/MP3"), MediaKind::Audio);
    }

    #[test]
    fn mime_video_detected() {
        assert_eq!(MediaKind::from_mime("video/mp4"), MediaKind::Video);
        assert_eq!(MediaKind::from_mime("video/quicktime"), MediaKind::Video);
    }

    #[test]
    fn extension_audio_detected() {
        assert_eq!(MediaKind::from_extension("mp3"), MediaKind::Audio);
        assert_eq!(MediaKind::from_extension(".wav"), MediaKind::Audio);
        assert_eq!(MediaKind::from_extension("M4A"), MediaKind::Audio);
    }

    #[test]
    fn extension_video_detected() {
        assert_eq!(MediaKind::from_extension("mp4"), MediaKind::Video);
        assert_eq!(MediaKind::from_extension(".mov"), MediaKind::Video);
    }

    #[test]
    fn unknown_extension_is_other() {
        assert_eq!(MediaKind::from_extension("pdf"), MediaKind::Other);
        assert_eq!(MediaKind::from_extension("docx"), MediaKind::Other);
        assert_eq!(MediaKind::from_extension(""), MediaKind::Other);
    }

    #[test]
    fn no_media_no_advisory() {
        let advisory = DeepfakeAdvisory::new();
        let attachments = vec![("report.pdf".to_string(), "application/pdf".to_string())];
        let report = advisory.evaluate(&attachments, "");
        assert_eq!(report.severity, AdvisorySeverity::None);
    }

    #[test]
    fn audio_attachment_with_normal_body_is_info() {
        let advisory = DeepfakeAdvisory::new();
        let attachments = vec![("voice.mp3".to_string(), "audio/mpeg".to_string())];
        let body = "明日の会議の議題について";
        let report = advisory.evaluate(&attachments, body);
        assert_eq!(report.severity, AdvisorySeverity::Info);
    }

    #[test]
    fn audio_with_financial_keyword_is_medium() {
        let advisory = DeepfakeAdvisory::new();
        let attachments = vec![("instruction.mp3".to_string(), "audio/mpeg".to_string())];
        let body = "振込先について音声で説明しました";
        let report = advisory.evaluate(&attachments, body);
        assert_eq!(report.severity, AdvisorySeverity::Medium);
        assert!(report.has_financial_context);
    }

    #[test]
    fn audio_with_financial_and_urgency_is_high() {
        let advisory = DeepfakeAdvisory::new();
        let attachments = vec![("urgent.mp3".to_string(), "audio/mpeg".to_string())];
        let body = "至急振込先を変更してください。詳細は音声を確認してください。";
        let report = advisory.evaluate(&attachments, body);
        assert_eq!(report.severity, AdvisorySeverity::High);
        assert_eq!(report.recommended_action, RecommendedAction::OobvBeforePlay);
    }

    #[test]
    fn video_attachment_treated_same_as_audio() {
        let advisory = DeepfakeAdvisory::new();
        let attachments = vec![("ceo-message.mp4".to_string(), "video/mp4".to_string())];
        let body = "緊急wire transferの指示です";
        let report = advisory.evaluate(&attachments, body);
        assert_eq!(report.severity, AdvisorySeverity::High);
    }

    #[test]
    fn extension_fallback_when_mime_empty() {
        let advisory = DeepfakeAdvisory::new();
        let attachments = vec![("voice.mp3".to_string(), "".to_string())];
        let body = "確認してください";
        let report = advisory.evaluate(&attachments, body);
        assert!(report.severity > AdvisorySeverity::None);
    }

    #[test]
    fn multiple_media_attachments_all_listed() {
        let advisory = DeepfakeAdvisory::new();
        let attachments = vec![
            ("voice1.mp3".to_string(), "audio/mpeg".to_string()),
            ("video.mp4".to_string(), "video/mp4".to_string()),
            ("report.pdf".to_string(), "application/pdf".to_string()),
        ];
        let report = advisory.evaluate(&attachments, "");
        // PDF は除外、音声+動画のみ
        assert_eq!(report.affected_attachments.len(), 2);
    }

    #[test]
    fn severity_ordering() {
        assert!(AdvisorySeverity::High > AdvisorySeverity::Medium);
        assert!(AdvisorySeverity::Medium > AdvisorySeverity::Info);
        assert!(AdvisorySeverity::Info > AdvisorySeverity::None);
    }
}
