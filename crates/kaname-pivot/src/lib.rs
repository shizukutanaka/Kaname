//! kaname-pivot — Cross-Channel Pivot Detection (横展開攻撃検出)
//!
//! 2026 年マルチチャネル攻撃への対抗策。
//! メール → Teams/Slack/Zoom/電話 への誘導を検出し、UI に意図的な摩擦を加える。
//!
//! # 検出パターン
//! - 電話番号 (国際/日本/英米フォーマット)
//! - Teams / Slack / Zoom / Google Meet 会議リンク
//! - SaaS ドキュメント (DocuSign, Google Drive, OneDrive)
//! - 暗号通貨ウォレット (ETH/BTC アドレス)

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![allow(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// 検出された pivot
// ============================================================================

/// メール内で検出された別チャネルへの誘導。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "data")]
pub enum DetectedPivot {
    /// 電話番号
    PhoneNumber {
        /// 検出した番号 (正規化済み: +81-90-XXXX-XXXX 形式)
        number: String,
        /// 周辺テキスト (緊急性判定用)
        context: String,
    },
    /// Microsoft Teams 会議リンク
    TeamsLink {
        /// URL
        url: String,
        /// 組織名 (URL から推測可能な場合)
        tenant: Option<String>,
    },
    /// Slack 招待または DM リンク
    SlackInvite {
        /// URL
        url: String,
        /// ワークスペース名
        workspace: Option<String>,
    },
    /// Zoom 会議
    ZoomMeeting {
        /// 会議 ID
        meeting_id: String,
        /// パスワード付きか
        has_password: bool,
    },
    /// Google Meet
    GoogleMeet {
        /// 会議 URL
        url: String,
    },
    /// DocuSign 等の SaaS ドキュメント
    SaasDocument {
        /// プラットフォーム名
        platform: String,
        /// URL
        url: String,
    },
    /// 暗号通貨ウォレットアドレス
    CryptoWallet {
        /// 通貨種別 (BTC, ETH, etc)
        currency: String,
        /// アドレス
        address: String,
    },
}

impl DetectedPivot {
    /// 攻撃シナリオで重要度が高いか判定する。
    #[must_use]
    pub fn is_high_risk(&self) -> bool {
        match self {
            // 暗号通貨は高リスク (取り戻せない、現代の BEC 主流)
            Self::CryptoWallet { .. } => true,
            // 電話 + 緊急性は高リスク (Deepfake 音声攻撃の入口)
            Self::PhoneNumber { context, .. } => has_urgency(context),
            _ => false,
        }
    }

    /// チャネル種別の人間可読名。
    #[must_use]
    pub fn channel_name(&self) -> &'static str {
        match self {
            Self::PhoneNumber { .. }   => "電話",
            Self::TeamsLink { .. }     => "Microsoft Teams",
            Self::SlackInvite { .. }   => "Slack",
            Self::ZoomMeeting { .. }   => "Zoom",
            Self::GoogleMeet { .. }    => "Google Meet",
            Self::SaasDocument { .. }  => "SaaS ドキュメント",
            Self::CryptoWallet { .. }  => "暗号通貨ウォレット",
        }
    }
}

// ============================================================================
// PivotDetector
// ============================================================================

/// メール本文から複数チャネルへの誘導を検出する。
#[derive(Debug, Default)]
pub struct PivotDetector;

impl PivotDetector {
    /// 新規検出器を構築する。
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// メール本文を解析して全 pivot を抽出する。
    #[must_use]
    pub fn analyze(&self, body: &str) -> Vec<DetectedPivot> {
        let mut pivots = Vec::new();

        // 1. 電話番号
        pivots.extend(extract_phone_numbers(body));

        // 2. 会議リンク
        pivots.extend(extract_meeting_links(body));

        // 3. SaaS ドキュメント
        pivots.extend(extract_saas_links(body));

        // 4. 暗号通貨アドレス
        pivots.extend(extract_crypto_addresses(body));

        pivots
    }

    /// 信頼スコアを計算する (0.0..=1.0)。
    ///
    /// 高いほど安全 (信頼できる pivot)。
    /// 過去 30 日のやりとりに同じチャネルがあれば加点。
    #[must_use]
    pub fn trust_score(&self, pivots: &[DetectedPivot], known_history: &PivotHistory) -> f32 {
        if pivots.is_empty() {
            return 1.0;
        }

        let mut score: f32 = 0.5;

        for pivot in pivots {
            if known_history.has_seen(pivot) {
                score += 0.2; // 過去に見たチャネル
            } else if pivot.is_high_risk() {
                score -= 0.3; // 高リスク
            } else {
                score -= 0.1; // 未知だが高リスクではない
            }
        }

        score.clamp(0.0, 1.0)
    }
}

// ============================================================================
// 過去履歴 (信頼スコア計算用)
// ============================================================================

/// 過去 30 日に観測された pivot の履歴。
#[derive(Debug, Default, Clone)]
pub struct PivotHistory {
    seen_phones: Vec<String>,
    seen_urls: Vec<String>,
}

impl PivotHistory {
    /// 新規履歴を構築する。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 電話番号を履歴に追加する。
    pub fn add_phone(&mut self, number: impl Into<String>) {
        self.seen_phones.push(number.into());
    }

    /// URL を履歴に追加する。
    pub fn add_url(&mut self, url: impl Into<String>) {
        self.seen_urls.push(url.into());
    }

    /// 既知の pivot か判定する。
    #[must_use]
    pub fn has_seen(&self, pivot: &DetectedPivot) -> bool {
        match pivot {
            DetectedPivot::PhoneNumber { number, .. } => self.seen_phones.iter().any(|n| n == number),
            DetectedPivot::TeamsLink { url, .. }
            | DetectedPivot::SlackInvite { url, .. }
            | DetectedPivot::GoogleMeet { url }
            | DetectedPivot::SaasDocument { url, .. } => {
                self.seen_urls.iter().any(|u| u == url)
            }
            _ => false,
        }
    }
}

// ============================================================================
// 抽出ロジック
// ============================================================================

fn extract_phone_numbers(body: &str) -> Vec<DetectedPivot> {
    let mut results = Vec::new();
    let lines: Vec<&str> = body.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        // 簡易: 連続する数字 + ハイフン + スペースで 10 文字以上
        let mut current = String::new();
        let mut digit_count = 0;

        for c in line.chars() {
            if c.is_ascii_digit() || c == '-' || c == ' ' || c == '+' || c == '(' || c == ')' {
                current.push(c);
                if c.is_ascii_digit() {
                    digit_count += 1;
                }
            } else {
                if (10..=15).contains(&digit_count) {
                    // 周辺テキスト (前後の行)
                    let context = format!(
                        "{} {} {}",
                        lines.get(i.saturating_sub(1)).copied().unwrap_or(""),
                        line,
                        lines.get(i + 1).copied().unwrap_or(""),
                    );
                    results.push(DetectedPivot::PhoneNumber {
                        number: normalize_phone(&current),
                        context,
                    });
                }
                current.clear();
                digit_count = 0;
            }
        }
        // 行末
        if (10..=15).contains(&digit_count) {
            let context = lines.get(i.saturating_sub(1)).copied().unwrap_or("").to_string()
                + " "
                + line;
            results.push(DetectedPivot::PhoneNumber {
                number: normalize_phone(&current),
                context,
            });
        }
    }

    results
}

fn normalize_phone(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect()
}

fn extract_meeting_links(body: &str) -> Vec<DetectedPivot> {
    let mut results = Vec::new();
    for word in body.split_whitespace() {
        let url = trim_url(word);
        if url.contains("teams.microsoft.com") || url.contains("teams.live.com") {
            results.push(DetectedPivot::TeamsLink {
                url: url.to_string(),
                tenant: extract_tenant_from_teams(url),
            });
        } else if url.contains("slack.com") || url.contains(".slack.com") {
            results.push(DetectedPivot::SlackInvite {
                url: url.to_string(),
                workspace: extract_slack_workspace(url),
            });
        } else if url.contains("zoom.us") || url.contains("zoom.com") {
            results.push(DetectedPivot::ZoomMeeting {
                meeting_id: extract_zoom_meeting_id(url).unwrap_or_else(|| "unknown".to_string()),
                has_password: url.contains("pwd=") || url.contains("&p="),
            });
        } else if url.contains("meet.google.com") {
            results.push(DetectedPivot::GoogleMeet {
                url: url.to_string(),
            });
        }
    }
    results
}

fn extract_saas_links(body: &str) -> Vec<DetectedPivot> {
    let mut results = Vec::new();
    for word in body.split_whitespace() {
        let url = trim_url(word);
        let platform = match () {
            _ if url.contains("docusign.net") || url.contains("docusign.com") => Some("DocuSign"),
            _ if url.contains("drive.google.com") => Some("Google Drive"),
            _ if url.contains("docs.google.com") => Some("Google Docs"),
            _ if url.contains("onedrive.live.com") || url.contains("1drv.ms") => Some("OneDrive"),
            _ if url.contains("sharepoint.com") => Some("SharePoint"),
            _ if url.contains("dropbox.com") => Some("Dropbox"),
            _ if url.contains("box.com") => Some("Box"),
            _ => None,
        };
        if let Some(p) = platform {
            results.push(DetectedPivot::SaasDocument {
                platform: p.to_string(),
                url: url.to_string(),
            });
        }
    }
    results
}

fn extract_crypto_addresses(body: &str) -> Vec<DetectedPivot> {
    let mut results = Vec::new();
    for word in body.split_whitespace() {
        let w = word.trim_matches(|c: char| !c.is_alphanumeric());

        // Ethereum: 0x で始まる 40 桁の hex
        if w.starts_with("0x") && w.len() == 42 && w[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            results.push(DetectedPivot::CryptoWallet {
                currency: "ETH".to_string(),
                address: w.to_string(),
            });
        }
        // Bitcoin: bc1... または 1... または 3... で始まる base58 / bech32
        else if (w.starts_with("bc1") || w.starts_with('1') || w.starts_with('3'))
            && w.len() >= 26
            && w.len() <= 62
            && w.chars().all(|c| c.is_ascii_alphanumeric())
        {
            // Bitcoin らしいパターン (詳細検証は省略)
            if w.starts_with("bc1") || (w.len() >= 27 && w.len() <= 34) {
                results.push(DetectedPivot::CryptoWallet {
                    currency: "BTC".to_string(),
                    address: w.to_string(),
                });
            }
        }
    }
    results
}

// ── ヘルパー関数 ─────────────────────────────────────────────────────────

fn trim_url(s: &str) -> &str {
    s.trim_end_matches(['.', ',', ')', ']', '!', '?', ';'])
}

fn extract_tenant_from_teams(url: &str) -> Option<String> {
    if let Some(start) = url.find("teams.microsoft.com/l/meetup-join/") {
        let after = &url[start..];
        if let Some(tenant_start) = after.find("tenantId=") {
            let tenant = &after[tenant_start + 9..];
            return Some(tenant.split('&').next().unwrap_or("").to_string());
        }
    }
    None
}

fn extract_slack_workspace(url: &str) -> Option<String> {
    // https://workspace.slack.com/...
    if let Some(start) = url.find("https://") {
        let after = &url[start + 8..];
        if let Some(end) = after.find(".slack.com") {
            return Some(after[..end].to_string());
        }
    }
    None
}

fn extract_zoom_meeting_id(url: &str) -> Option<String> {
    if let Some(start) = url.find("/j/") {
        let after = &url[start + 3..];
        return Some(after.chars().take_while(|c| c.is_ascii_digit()).collect());
    }
    None
}

fn has_urgency(text: &str) -> bool {
    let urgency_markers = [
        "至急", "緊急", "今すぐ", "本日中", "急いで", "すぐに",
        "urgent", "asap", "immediately", "right now", "as soon as",
    ];
    let text_lower = text.to_lowercase();
    urgency_markers.iter().any(|m| text_lower.contains(m))
}

// ============================================================================
// エラー型
// ============================================================================

/// PivotDetector のエラー。
#[derive(Debug, Error)]
pub enum PivotError {
    /// 不正な入力
    #[error("不正な入力: {0}")]
    InvalidInput(String),
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn detects_japanese_phone_number() {
        let body = "至急電話ください: 080-1234-5678";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        let phones: Vec<_> = pivots
            .iter()
            .filter(|p| matches!(p, DetectedPivot::PhoneNumber { .. }))
            .collect();
        assert_eq!(phones.len(), 1);
    }

    #[test]
    fn detects_us_phone_number() {
        let body = "Call me at +1-555-123-4567 immediately";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        assert!(pivots
            .iter()
            .any(|p| matches!(p, DetectedPivot::PhoneNumber { .. })));
    }

    #[test]
    fn phone_with_urgency_is_high_risk() {
        let body = "至急 080-1234-5678 にお電話ください";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        let phone = pivots
            .iter()
            .find(|p| matches!(p, DetectedPivot::PhoneNumber { .. }))
            .unwrap();
        assert!(phone.is_high_risk(), "緊急 + 電話番号は高リスクのはず");
    }

    #[test]
    fn phone_without_urgency_is_not_high_risk() {
        let body = "新しい連絡先: 080-1234-5678";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        let phone = pivots
            .iter()
            .find(|p| matches!(p, DetectedPivot::PhoneNumber { .. }))
            .unwrap();
        assert!(!phone.is_high_risk());
    }

    #[test]
    fn detects_teams_link() {
        let body = "会議: https://teams.microsoft.com/l/meetup-join/19%3a... \n参加してください";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        assert!(pivots
            .iter()
            .any(|p| matches!(p, DetectedPivot::TeamsLink { .. })));
    }

    #[test]
    fn detects_zoom_meeting() {
        let body = "Zoom: https://zoom.us/j/123456789?pwd=secret";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        let zoom = pivots
            .iter()
            .find(|p| matches!(p, DetectedPivot::ZoomMeeting { .. }));
        assert!(zoom.is_some());
        if let Some(DetectedPivot::ZoomMeeting { meeting_id, has_password }) = zoom {
            assert_eq!(meeting_id, "123456789");
            assert!(*has_password);
        }
    }

    #[test]
    fn detects_slack_invite() {
        let body = "Slack に参加: https://kaname-team.slack.com/...";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        let slack = pivots
            .iter()
            .find(|p| matches!(p, DetectedPivot::SlackInvite { .. }));
        assert!(slack.is_some());
        if let Some(DetectedPivot::SlackInvite { workspace, .. }) = slack {
            assert_eq!(workspace.as_deref(), Some("kaname-team"));
        }
    }

    #[test]
    fn detects_docusign() {
        let body = "署名: https://app.docusign.net/Documents/details/abc123";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        assert!(pivots.iter().any(|p| {
            matches!(p, DetectedPivot::SaasDocument { platform, .. } if platform == "DocuSign")
        }));
    }

    #[test]
    fn detects_google_drive() {
        let body = "Google Drive: https://drive.google.com/file/d/abc/view";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        assert!(pivots.iter().any(|p| {
            matches!(p, DetectedPivot::SaasDocument { platform, .. } if platform == "Google Drive")
        }));
    }

    #[test]
    fn detects_eth_wallet_address() {
        let body = "ETH 送金先: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        let wallet = pivots
            .iter()
            .find(|p| matches!(p, DetectedPivot::CryptoWallet { .. }));
        assert!(wallet.is_some());
        if let Some(DetectedPivot::CryptoWallet { currency, .. }) = wallet {
            assert_eq!(currency, "ETH");
        }
    }

    #[test]
    fn detects_btc_segwit_address() {
        let body = "BTC: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        assert!(pivots.iter().any(|p| {
            matches!(p, DetectedPivot::CryptoWallet { currency, .. } if currency == "BTC")
        }));
    }

    #[test]
    fn crypto_wallet_is_always_high_risk() {
        let pivot = DetectedPivot::CryptoWallet {
            currency: "ETH".to_string(),
            address: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1".to_string(),
        };
        assert!(pivot.is_high_risk());
    }

    #[test]
    fn trust_score_decreases_with_high_risk_pivots() {
        let detector = PivotDetector::new();
        let history = PivotHistory::new();

        let pivots = vec![DetectedPivot::CryptoWallet {
            currency: "ETH".to_string(),
            address: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1".to_string(),
        }];

        let score = detector.trust_score(&pivots, &history);
        assert!(score < 0.5, "暗号通貨アドレスがあればスコアは低いはず: {}", score);
    }

    #[test]
    fn trust_score_increases_with_known_pivots() {
        let detector = PivotDetector::new();
        let mut history = PivotHistory::new();
        history.add_url("https://teams.microsoft.com/l/meetup-join/abc");

        let pivots = vec![DetectedPivot::TeamsLink {
            url: "https://teams.microsoft.com/l/meetup-join/abc".to_string(),
            tenant: None,
        }];

        let score = detector.trust_score(&pivots, &history);
        assert!(score > 0.5, "既知の Teams リンクはスコアが高いはず: {}", score);
    }

    #[test]
    fn empty_body_returns_no_pivots() {
        let detector = PivotDetector::new();
        assert!(detector.analyze("").is_empty());
    }

    #[test]
    fn normal_email_returns_no_pivots() {
        let body = "明日の会議の議題について確認させてください。よろしくお願いします。";
        let detector = PivotDetector::new();
        assert!(detector.analyze(body).is_empty());
    }

    #[test]
    fn channel_name_returns_correct_label() {
        assert_eq!(
            DetectedPivot::PhoneNumber {
                number: "0812345678".to_string(),
                context: "".to_string(),
            }
            .channel_name(),
            "電話"
        );
        assert_eq!(
            DetectedPivot::TeamsLink {
                url: "".to_string(),
                tenant: None,
            }
            .channel_name(),
            "Microsoft Teams"
        );
    }
}
