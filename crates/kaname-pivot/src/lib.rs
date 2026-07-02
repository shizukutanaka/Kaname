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
    /// WhatsApp 招待/連絡先リンク
    ///
    /// 2025-2026 BEC で急増: CEO になりすまし WhatsApp グループに誘導後、
    /// フィルタ監視外で不正振込指示を行う手口。
    WhatsAppLink {
        /// 検出された URL または電話番号リンク
        url: String,
    },
    /// Telegram ボット/チャンネル/グループ招待
    ///
    /// フィッシングキット配布や送金指示に Telegram ボットが使われる事例が増加。
    TelegramLink {
        /// t.me または telegram.me の URL
        url: String,
        /// ボット招待か (@xxx_bot 形式)
        is_bot: bool,
    },
    /// Signal 連絡先/グループ招待
    SignalLink {
        /// signal.me または signal.group URL
        url: String,
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
            // WhatsApp/Telegram/Signal は CEO 詐欺の典型的な誘導先 (2025-2026 急増)
            Self::WhatsAppLink { .. } | Self::TelegramLink { .. } | Self::SignalLink { .. } => true,
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
            Self::WhatsAppLink { .. }  => "WhatsApp",
            Self::TelegramLink { .. }  => "Telegram",
            Self::SignalLink { .. }    => "Signal",
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
        const MAX_BODY_LEN: usize = 1_000_000; // 1 MB
        let body = if body.len() > MAX_BODY_LEN {
            tracing::warn!("PivotDetector: body が {}B を超えたため先頭 {}B のみ解析", MAX_BODY_LEN, MAX_BODY_LEN);
            &body[..MAX_BODY_LEN]
        } else {
            body
        };
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

    /// `trust_score` に BEC 検出結果のリスクスコアを組み合わせた複合信頼スコア。
    ///
    /// # 背景
    ///
    /// `kaname-bec` はテキストベースのチャネル移行フレーズ
    /// (「LINEグループを作って」等) を検出し、`kaname-pivot` は
    /// URL ベースの実際のチャネルリンク (`wa.me`, `t.me` 等) を検出するが、
    /// 依存グラフ上 `kaname-pivot` が下流にあるにも関わらず両者は
    /// 連携しておらず、それぞれ独立に判定されていた。
    ///
    /// 「BEC スコアが高いメールに実際のチャットアプリ誘導リンクが
    /// 含まれる」という複合は、片方だけの判定より遥かに強い
    /// シグナルであるため、BEC リスクスコアが高いほど pivot の
    /// 信頼スコアをより強く減点する。
    ///
    /// `kaname-pivot` は `kaname-bec` の具体的な型に依存させない設計とし
    /// (クレート結合を避ける)、呼び出し側が `Assessment.score` (0.0-1.0)
    /// を渡す。
    ///
    /// # 引数
    ///
    /// - `bec_risk_score`: `kaname-bec::Assessment.score` 相当の値 (0.0=安全, 1.0=確実に BEC)。
    #[must_use]
    pub fn trust_score_with_bec_context(
        &self,
        pivots: &[DetectedPivot],
        known_history: &PivotHistory,
        bec_risk_score: f32,
    ) -> f32 {
        let base = self.trust_score(pivots, known_history);
        if pivots.is_empty() {
            return base;
        }
        let bec_risk_score = bec_risk_score.clamp(0.0, 1.0);
        // BEC リスクが高いメールにチャネル誘導が含まれる場合、追加でペナルティを課す。
        // BEC が Safe (低スコア) なら影響を与えない。
        let penalty = bec_risk_score * 0.4;
        (base - penalty).clamp(0.0, 1.0)
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
    ///
    /// 検出側の `DetectedPivot::PhoneNumber.number` は `normalize_phone` で
    /// 正規化済み (数字と `+` のみ) のため、履歴も同じ正規形で保存する。
    /// そうしないと "+1 (800) 555-1234" のような書式付き番号が検出値
    /// "+18005551234" と一致せず、既知の正規チャネルを未知の高リスク pivot と
    /// 誤判定し、誤検知・アラート疲れを招く。
    pub fn add_phone(&mut self, number: impl Into<String>) {
        self.seen_phones.push(normalize_phone(&number.into()));
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
            | DetectedPivot::SaasDocument { url, .. }
            | DetectedPivot::WhatsAppLink { url }
            | DetectedPivot::TelegramLink { url, .. }
            | DetectedPivot::SignalLink { url } => {
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
        let host = extract_hostname(url);
        if host_is(host, "teams.microsoft.com") || host_is(host, "teams.live.com") {
            results.push(DetectedPivot::TeamsLink {
                url: url.to_string(),
                tenant: extract_tenant_from_teams(url),
            });
        } else if host_is(host, "slack.com") {
            results.push(DetectedPivot::SlackInvite {
                url: url.to_string(),
                workspace: extract_slack_workspace(url),
            });
        } else if host_is(host, "zoom.us") || host_is(host, "zoom.com") {
            results.push(DetectedPivot::ZoomMeeting {
                meeting_id: extract_zoom_meeting_id(url).unwrap_or_else(|| "unknown".to_string()),
                has_password: url.contains("pwd=") || url.contains("&p="),
            });
        } else if host_is(host, "meet.google.com") {
            results.push(DetectedPivot::GoogleMeet {
                url: url.to_string(),
            });
        // WhatsApp: wa.me (短縮), api.whatsapp.com, chat.whatsapp.com
        } else if host_is(host, "wa.me")
            || host_is(host, "api.whatsapp.com")
            || host_is(host, "chat.whatsapp.com")
            || host_is(host, "whatsapp.com")
        {
            results.push(DetectedPivot::WhatsAppLink {
                url: url.to_string(),
            });
        // Telegram: t.me (短縮), telegram.me, telegram.org
        } else if host_is(host, "t.me")
            || host_is(host, "telegram.me")
            || host_is(host, "telegram.org")
        {
            let is_bot = url.contains("_bot") || url.contains("bot?");
            results.push(DetectedPivot::TelegramLink {
                url: url.to_string(),
                is_bot,
            });
        // Signal: signal.me, signal.group
        } else if host_is(host, "signal.me") || host_is(host, "signal.group") {
            results.push(DetectedPivot::SignalLink {
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
        let host = extract_hostname(url);
        let platform = match () {
            _ if host_is(host, "docusign.net") || host_is(host, "docusign.com") => Some("DocuSign"),
            _ if host_is(host, "drive.google.com") => Some("Google Drive"),
            _ if host_is(host, "docs.google.com") => Some("Google Docs"),
            _ if host_is(host, "onedrive.live.com") || host_is(host, "1drv.ms") => Some("OneDrive"),
            _ if host_is(host, "sharepoint.com") => Some("SharePoint"),
            _ if host_is(host, "dropbox.com") => Some("Dropbox"),
            _ if host_is(host, "box.com") => Some("Box"),
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

        // Ethereum: 0x/0X で始まる 40 桁の hex (大文字プレフィックスもバイパス防止)
        let w_lower = w.to_lowercase();
        if w_lower.starts_with("0x") && w.len() == 42 && w[2..].chars().all(|c| c.is_ascii_hexdigit()) {
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

/// URL からホスト名を抽出する。
///
/// `"https://foo.example.com/path?q=1"` → `"foo.example.com"`
/// スキームなし (`"foo.example.com/path"`) にも対応。
fn extract_hostname(url: &str) -> &str {
    let after_scheme = url
        .find("://")
        .map(|i| &url[i + 3..])
        .unwrap_or(url);
    // ホスト部分: 最初の '/', '?', '#', ':' まで
    let end = after_scheme
        .find(['/', '?', '#', ':'])
        .unwrap_or(after_scheme.len());
    &after_scheme[..end]
}

/// ホスト名が指定ドメイン (または そのサブドメイン) か判定する。
///
/// `host_is("foo.example.com", "example.com")` → true
/// `host_is("notexample.com", "example.com")` → false
/// `host_is("example.com.evil.com", "example.com")` → false
fn host_is(hostname: &str, domain: &str) -> bool {
    hostname == domain || hostname.ends_with(&format!(".{domain}"))
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

/// 否定フレーズ。直後に付くと緊急扱いしない。
const NEGATION_SUFFIXES: &[&str] = &[
    "ではありません", "ではない", "じゃない", "ではなく", "でない",
    "ではないので", "ではなかった",
];

/// 英語の否定: "not urgent", "no urgency" などを検出するために
/// urgency marker の前後に "not" / "no " が付く形を検出するペア。
const EN_NEGATION_PREFIXES: &[&str] = &["not ", "no ", "non-", "isn't", "aren't"];

fn has_urgency(text: &str) -> bool {
    let urgency_markers = [
        "至急", "緊急", "今すぐ", "本日中", "急いで", "すぐに",
        "urgent", "asap", "immediately", "right now", "as soon as",
    ];
    let text_lower = text.to_lowercase();
    // 文字単位でトークン化して境界問題を回避
    let chars: Vec<char> = text_lower.chars().collect();
    let char_str: String = chars.iter().collect();

    urgency_markers.iter().any(|marker| {
        let mut rest = char_str.as_str();
        while let Some(pos) = rest.find(marker) {
            let after = &rest[pos + marker.len()..];

            // 日本語否定: マーカーの直後
            let ja_negated = NEGATION_SUFFIXES.iter().any(|neg| after.starts_with(neg));

            // 英語否定: マーカーの直前 8 文字以内
            let before_start = rest[..pos].char_indices()
                .rev()
                .nth(7)
                .map(|(i, _)| i)
                .unwrap_or(0);
            let before = &rest[before_start..pos];
            let en_negated = EN_NEGATION_PREFIXES.iter().any(|neg| before.contains(neg));

            if !ja_negated && !en_negated {
                return true;
            }
            // 次の出現を探す
            rest = &rest[pos + marker.len()..];
        }
        false
    })
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
    fn bec_context_penalizes_pivot_when_bec_risk_high() {
        // BEC リスクが高いメールにチャネル誘導があれば、通常より強く減点される
        let detector = PivotDetector::new();
        let history = PivotHistory::new();
        let pivots = vec![DetectedPivot::WhatsAppLink {
            url: "https://wa.me/819012345678".to_string(),
        }];

        let base = detector.trust_score(&pivots, &history);
        let with_bec = detector.trust_score_with_bec_context(&pivots, &history, 0.9);
        assert!(with_bec < base,
            "BEC リスクが高い場合はベーススコアより低くなるべき: base={base} with_bec={with_bec}");
    }

    #[test]
    fn bec_context_no_effect_when_bec_safe() {
        // BEC が Safe (低スコア) ならベーススコアと同じ
        let detector = PivotDetector::new();
        let history = PivotHistory::new();
        let pivots = vec![DetectedPivot::TeamsLink {
            url: "https://teams.microsoft.com/l/meetup-join/xyz".to_string(),
            tenant: None,
        }];

        let base = detector.trust_score(&pivots, &history);
        let with_bec = detector.trust_score_with_bec_context(&pivots, &history, 0.0);
        assert!((base - with_bec).abs() < f32::EPSILON,
            "BEC が Safe ならベーススコアと変わらないべき: base={base} with_bec={with_bec}");
    }

    #[test]
    fn bec_context_no_pivots_returns_base() {
        // pivot がなければ BEC スコアに関わらず 1.0 (安全)
        let detector = PivotDetector::new();
        let history = PivotHistory::new();
        let score = detector.trust_score_with_bec_context(&[], &history, 0.9);
        assert!((score - 1.0).abs() < f32::EPSILON, "pivot がなければ 1.0: {score}");
    }

    #[test]
    fn bec_context_clamps_out_of_range_bec_score() {
        // 範囲外の bec_risk_score でもパニックせず 0.0..=1.0 に収まる
        let detector = PivotDetector::new();
        let history = PivotHistory::new();
        let pivots = vec![DetectedPivot::SignalLink {
            url: "https://signal.me/#p/+819012345678".to_string(),
        }];
        let score = detector.trust_score_with_bec_context(&pivots, &history, 99.0);
        assert!((0.0..=1.0).contains(&score), "スコアは範囲内に収まるべき: {score}");
    }

    #[test]
    fn known_formatted_phone_matches_normalized_detection() {
        // 履歴に書式付きで登録された番号が、検出側の正規化済み番号と一致すること
        let mut history = PivotHistory::new();
        history.add_phone("+1 (800) 555-1234");

        // 検出側が生成する正規形 (digits + '+')
        let detected = DetectedPivot::PhoneNumber {
            number: normalize_phone("+1 (800) 555-1234"),
            context: String::new(),
        };
        assert!(history.has_seen(&detected),
            "書式付きで登録された既知番号が正規化検出値と一致しない");
    }

    #[test]
    fn known_phone_raises_trust_despite_formatting() {
        let detector = PivotDetector::new();
        let mut history = PivotHistory::new();
        history.add_phone("080-1234-5678"); // ハイフン付きで登録

        // 検出側は正規化済み ("08012345678")
        let pivots = vec![DetectedPivot::PhoneNumber {
            number: normalize_phone("080-1234-5678"),
            context: String::new(),
        }];
        let score = detector.trust_score(&pivots, &history);
        assert!(score > 0.5,
            "書式違いでも既知番号は信頼スコアを上げるべき (誤検知防止): {score}");
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
    fn negated_urgency_does_not_flag_as_high_risk() {
        // "緊急ではありません" — NOT urgent (否定) は高リスクにならない
        let body = "本件は緊急ではありませんので、お時間のある時にご確認ください。080-1234-5678";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        let phone_high_risk = pivots.iter().any(|p| {
            matches!(p, DetectedPivot::PhoneNumber { .. }) && p.is_high_risk()
        });
        assert!(!phone_high_risk, "否定された緊急表現は高リスク扱いにしてはならない");
    }

    #[test]
    fn genuine_urgency_is_still_high_risk() {
        // 否定なし "至急" は高リスクのまま
        let body = "至急ご確認ください。080-1234-5678";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        let phone_high_risk = pivots.iter().any(|p| {
            matches!(p, DetectedPivot::PhoneNumber { .. }) && p.is_high_risk()
        });
        assert!(phone_high_risk, "否定なし 至急 + 電話番号は高リスクでなければならない");
    }

    // ── ドメイン混同バイパス回帰テスト ──────────────────────────────────────

    #[test]
    fn fake_teams_domain_is_not_detected_as_teams() {
        // 攻撃: "teams.microsoft.com.attacker.com" は Teams ではない
        let body = "会議: https://teams.microsoft.com.attacker.com/l/meetup-join/19...";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        assert!(
            !pivots.iter().any(|p| matches!(p, DetectedPivot::TeamsLink { .. })),
            "偽ドメインを Teams リンクと誤検知してはならない"
        );
    }

    #[test]
    fn path_containing_teams_domain_is_not_detected_as_teams() {
        // 攻撃: パスに "teams.microsoft.com" を含む別ドメインの URL
        let body = "リダイレクト: https://evil.example.com/redirect?to=teams.microsoft.com";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        assert!(
            !pivots.iter().any(|p| matches!(p, DetectedPivot::TeamsLink { .. })),
            "パス部分に Teams ドメインを含む URL を Teams リンクと誤検知してはならない"
        );
    }

    #[test]
    fn legitimate_teams_subdomain_is_detected() {
        // 正規: subdomain.teams.microsoft.com は検出すべき
        let body = "会議: https://subdomain.teams.microsoft.com/l/meetup-join/19...";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        assert!(
            pivots.iter().any(|p| matches!(p, DetectedPivot::TeamsLink { .. })),
            "正規サブドメインは Teams リンクとして検出されるべき"
        );
    }

    #[test]
    fn fake_slack_domain_not_detected() {
        // 攻撃: "slack.com.evil.com" は Slack ではない
        let body = "DM: https://slack.com.evil.com/archives/C123";
        let detector = PivotDetector::new();
        let pivots = detector.analyze(body);
        assert!(
            !pivots.iter().any(|p| matches!(p, DetectedPivot::SlackInvite { .. })),
            "偽ドメインを Slack 招待と誤検知してはならない"
        );
    }

    #[test]
    fn host_is_helper_dot_boundary() {
        assert!(host_is("example.com", "example.com"));
        assert!(host_is("foo.example.com", "example.com"));
        assert!(!host_is("notexample.com", "example.com"));
        assert!(!host_is("example.com.evil.com", "example.com"));
    }

    #[test]
    fn oversized_body_is_truncated_and_does_not_panic() {
        let huge = "A".repeat(2_000_000);
        let detector = PivotDetector::new();
        let _pivots = detector.analyze(&huge); // パニックしないこと
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

    #[test]
    fn ethereum_uppercase_prefix_detected() {
        // 0X (大文字) バイパス対策テスト
        let body = "ETH 送金先: 0X742d35Cc6634C0532925a3b844Bc9e7595f0bEb1";
        let pivots = extract_crypto_addresses(body);
        assert!(!pivots.is_empty(), "0X プレフィックスの Ethereum アドレスも検出すべき");
        assert!(pivots.iter().any(|p| matches!(p, DetectedPivot::CryptoWallet { currency, .. } if currency == "ETH")));
    }

    #[test]
    fn ethereum_lowercase_prefix_still_detected() {
        // 元々の 0x も引き続き検出できること
        let body = "送金: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1";
        let pivots = extract_crypto_addresses(body);
        assert!(!pivots.is_empty(), "0x プレフィックスの Ethereum アドレスは検出されるべき");
    }

    // ── WhatsApp / Telegram / Signal 検出 ─────────────────────────────────

    #[test]
    fn detects_whatsapp_wa_me_link() {
        let body = "Please contact me on WhatsApp: https://wa.me/819012345678";
        let d = PivotDetector::new();
        let pivots = d.analyze(body);
        assert!(
            pivots.iter().any(|p| matches!(p, DetectedPivot::WhatsAppLink { .. })),
            "wa.me リンクが検出されなかった: {pivots:?}"
        );
    }

    #[test]
    fn whatsapp_link_is_high_risk() {
        let pivot = DetectedPivot::WhatsAppLink { url: "https://wa.me/819012345678".to_string() };
        assert!(pivot.is_high_risk(), "WhatsApp は高リスクチャネル");
        assert_eq!(pivot.channel_name(), "WhatsApp");
    }

    #[test]
    fn detects_telegram_t_me_link() {
        let body = "Join our Telegram: https://t.me/ceoinstructions";
        let d = PivotDetector::new();
        let pivots = d.analyze(body);
        assert!(
            pivots.iter().any(|p| matches!(p, DetectedPivot::TelegramLink { .. })),
            "t.me リンクが検出されなかった: {pivots:?}"
        );
    }

    #[test]
    fn detects_telegram_bot_link() {
        let body = "Message the bot: https://t.me/payment_bot?start=ref123";
        let d = PivotDetector::new();
        let pivots = d.analyze(body);
        assert!(
            pivots.iter().any(|p| matches!(p, DetectedPivot::TelegramLink { is_bot: true, .. })),
            "Telegram ボットリンクが検出されなかった"
        );
    }

    #[test]
    fn detects_signal_link() {
        let body = "Let's talk privately: https://signal.me/#p/+819012345678";
        let d = PivotDetector::new();
        let pivots = d.analyze(body);
        assert!(
            pivots.iter().any(|p| matches!(p, DetectedPivot::SignalLink { .. })),
            "signal.me リンクが検出されなかった: {pivots:?}"
        );
    }

    #[test]
    fn signal_link_is_high_risk() {
        let pivot = DetectedPivot::SignalLink { url: "https://signal.me/#p/+819012345678".to_string() };
        assert!(pivot.is_high_risk());
        assert_eq!(pivot.channel_name(), "Signal");
    }

    #[test]
    fn telegram_link_is_high_risk() {
        let pivot = DetectedPivot::TelegramLink {
            url: "https://t.me/attacker".to_string(),
            is_bot: false,
        };
        assert!(pivot.is_high_risk());
        assert_eq!(pivot.channel_name(), "Telegram");
    }
}
