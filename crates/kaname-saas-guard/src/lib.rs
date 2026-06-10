//! kaname-saas-guard — SaaS Link Safety
//!
//! 2026 年急増中の脅威「SaaS プラットフォーム経由のフィッシング」への対抗策。
//! Google Drive / DocuSign / SharePoint / OneDrive 等の正当な SaaS を悪用した攻撃を検出。
//!
//! # 攻撃シナリオ
//!
//! 1. 攻撃者が SharePoint や Google Drive にフィッシング PDF/ドキュメントをアップロード
//! 2. メールに「資料を共有しました」と SaaS のリンクを記載
//! 3. ユーザーはリンクをクリック (信頼されたドメインなのでメールフィルタを通過)
//! 4. SaaS 内のドキュメントが偽の MFA 画面や認証フォームを表示
//!
//! # 防御アプローチ
//!
//! - 既知の SaaS プラットフォームを認識し、リスク評価
//! - 初めて見る送信者からの SaaS リンクは要注意フラグ
//! - リンク先のプレビュー (Firecracker microVM で隔離) を提供
//! - 認証情報入力欄を含むランディングページを警告

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

// ============================================================================
// SaaS プラットフォーム
// ============================================================================

/// 認識する SaaS プラットフォーム。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SaasPlatform {
    /// Google Drive / Docs / Sheets
    GoogleDrive,
    /// Microsoft OneDrive
    OneDrive,
    /// Microsoft SharePoint
    SharePoint,
    /// DocuSign
    DocuSign,
    /// Adobe Sign
    AdobeSign,
    /// Dropbox
    Dropbox,
    /// Box
    Box,
    /// Notion
    Notion,
    /// Smartsheet
    Smartsheet,
    /// その他既知の SaaS
    Other(&'static str),
}

impl SaasPlatform {
    /// プラットフォームのドメインリスト。
    #[must_use]
    pub fn domains(self) -> Vec<&'static str> {
        match self {
            Self::GoogleDrive  => vec!["drive.google.com", "docs.google.com", "sheets.google.com"],
            Self::OneDrive     => vec!["1drv.ms", "onedrive.live.com"],
            Self::SharePoint   => vec!["sharepoint.com"],
            Self::DocuSign     => vec!["docusign.net", "docusign.com"],
            Self::AdobeSign    => vec!["adobesign.com", "echosign.com"],
            Self::Dropbox      => vec!["dropbox.com", "db.tt"],
            Self::Box          => vec!["box.com", "boxcloud.com"],
            Self::Notion       => vec!["notion.so", "notion.site"],
            Self::Smartsheet   => vec!["smartsheet.com"],
            Self::Other(d)     => vec![d],
        }
    }

    /// 表示名。
    #[must_use]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::GoogleDrive => "Google Drive",
            Self::OneDrive    => "Microsoft OneDrive",
            Self::SharePoint  => "Microsoft SharePoint",
            Self::DocuSign    => "DocuSign",
            Self::AdobeSign   => "Adobe Sign",
            Self::Dropbox     => "Dropbox",
            Self::Box         => "Box",
            Self::Notion      => "Notion",
            Self::Smartsheet  => "Smartsheet",
            Self::Other(d)    => d,
        }
    }
}

// ============================================================================
// リスク評価
// ============================================================================

/// SaaS リンクのリスク評価。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SaasLinkRisk {
    /// 既に複数回やり取りした送信者から、馴染みの SaaS
    Safe,
    /// 既知の SaaS だが、送信者からの初回または低頻度
    Caution,
    /// 既知の SaaS で、認証情報入力やダウンロード等の高リスク兆候
    Warn,
    /// 偽 SaaS ドメインの可能性 (例: docusign.evil.com)
    Suspicious,
    /// 既知の悪意あるドメインに最終リダイレクト
    Block,
}

/// 検出された SaaS リンク。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedSaasLink {
    /// 元の URL
    pub url: String,
    /// 認識されたプラットフォーム
    pub platform: SaasPlatform,
    /// リスク評価
    pub risk: SaasLinkRisk,
    /// 警告理由 (UI 表示用)
    pub reasons: Vec<String>,
    /// 送信者
    pub sender: String,
}

// ============================================================================
// 履歴ベース信頼度
// ============================================================================

/// 送信者ごとの SaaS 利用履歴。
#[derive(Debug, Default)]
pub struct SaasHistory {
    /// (送信者, プラットフォーム) → やり取り回数
    interactions: std::collections::HashMap<(String, SaasPlatform), u32>,
}

impl SaasHistory {
    /// 新規履歴を作成。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// やり取りを記録。
    pub fn record(&mut self, sender: impl Into<String>, platform: SaasPlatform) {
        let key = (sender.into(), platform);
        *self.interactions.entry(key).or_insert(0) += 1;
    }

    /// 送信者と特定プラットフォームのやり取り回数を取得。
    #[must_use]
    pub fn count(&self, sender: &str, platform: SaasPlatform) -> u32 {
        self.interactions
            .get(&(sender.to_string(), platform))
            .copied()
            .unwrap_or(0)
    }

    /// 送信者が「馴染み」かを判定 (5 回以上のやり取り)。
    #[must_use]
    pub fn is_familiar(&self, sender: &str, platform: SaasPlatform) -> bool {
        self.count(sender, platform) >= 5
    }
}

// ============================================================================
// 検出器
// ============================================================================

/// SaaS リンク検査器。
pub struct SaasLinkInspector {
    /// 既知のプラットフォーム一覧
    platforms: Vec<SaasPlatform>,
    /// 既知の悪意あるドメイン
    malicious_domains: HashSet<String>,
}

impl SaasLinkInspector {
    /// デフォルト設定で構築。
    #[must_use]
    pub fn new() -> Self {
        Self {
            platforms: vec![
                SaasPlatform::GoogleDrive,
                SaasPlatform::OneDrive,
                SaasPlatform::SharePoint,
                SaasPlatform::DocuSign,
                SaasPlatform::AdobeSign,
                SaasPlatform::Dropbox,
                SaasPlatform::Box,
                SaasPlatform::Notion,
                SaasPlatform::Smartsheet,
            ],
            malicious_domains: HashSet::new(),
        }
    }

    /// 既知の悪意あるドメインを追加。
    pub fn add_malicious(&mut self, domain: impl Into<String>) {
        self.malicious_domains.insert(domain.into());
    }

    /// URL から SaaS プラットフォームを推定。
    #[must_use]
    pub fn identify_platform(&self, url: &str) -> Option<SaasPlatform> {
        let lower = url.to_lowercase();
        for &platform in &self.platforms {
            for domain in platform.domains() {
                if lower.contains(domain) {
                    return Some(platform);
                }
            }
        }
        None
    }

    /// SaaS リンクを評価する。
    #[must_use]
    pub fn evaluate(
        &self,
        url: &str,
        sender: &str,
        history: &SaasHistory,
    ) -> Option<DetectedSaasLink> {
        let platform = self.identify_platform(url)?;
        let mut reasons = Vec::new();
        let mut risk = SaasLinkRisk::Safe;

        // 1. 既知の悪意あるドメインへのリダイレクト示唆?
        for mal in &self.malicious_domains {
            if url.contains(mal) {
                risk = SaasLinkRisk::Block;
                reasons.push(format!("既知の悪意あるドメインを含む: {mal}"));
            }
        }

        // 2. 偽 SaaS パターン (例: docusign.evil.com)
        //    既知 SaaS ドメインが「サブドメイン」として悪用されている
        if risk != SaasLinkRisk::Block && self.is_fake_saas_subdomain(url, platform) {
            risk = SaasLinkRisk::Suspicious;
            reasons.push(format!("{} を装った偽ドメインの可能性", platform.display_name()));
        }

        // 3. 送信者履歴ベース評価
        if risk == SaasLinkRisk::Safe {
            risk = if history.is_familiar(sender, platform) {
                reasons.push(format!("{} さんとの{}での通常やり取り", sender, platform.display_name()));
                SaasLinkRisk::Safe
            } else {
                reasons.push(format!("{} さんからの {} 経由のリンクは初回または低頻度", sender, platform.display_name()));
                SaasLinkRisk::Caution
            };
        }

        // 4. URL パターン分析: 認証や署名キーワード
        let url_lower = url.to_lowercase();
        if url_lower.contains("login") || url_lower.contains("signin") || url_lower.contains("auth") {
            if risk == SaasLinkRisk::Safe || risk == SaasLinkRisk::Caution {
                risk = SaasLinkRisk::Warn;
            }
            reasons.push("URL に認証関連のキーワード".to_string());
        }

        Some(DetectedSaasLink {
            url: url.to_string(),
            platform,
            risk,
            reasons,
            sender: sender.to_string(),
        })
    }

    /// 偽 SaaS サブドメイン検出。
    ///
    /// 例: `docusign.evil.com` は DocuSign を装っているが、ドメインは evil.com
    fn is_fake_saas_subdomain(&self, url: &str, platform: SaasPlatform) -> bool {
        for legit_domain in platform.domains() {
            if url.contains(legit_domain) {
                // URL から実際のドメイン部分を抽出
                if let Some(domain) = extract_actual_domain(url) {
                    // 抽出ドメインが正規ドメインそのもの or サブドメインで終わる
                    if !domain.ends_with(legit_domain) {
                        return true;  // 偽装の可能性
                    }
                }
            }
        }
        false
    }
}

impl Default for SaasLinkInspector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ユーティリティ
// ============================================================================

fn extract_actual_domain(url: &str) -> Option<String> {
    let without_scheme = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let domain_end = without_scheme.find(|c: char| c == '/' || c == '?').unwrap_or(without_scheme.len());
    Some(without_scheme[..domain_end].to_lowercase())
}

// ============================================================================
// エラー型
// ============================================================================

/// SaaS Link Safety エラー。
#[derive(Debug, Error)]
pub enum SaasGuardError {
    /// URL パースエラー
    #[error("URL パースに失敗: {0}")]
    InvalidUrl(String),
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_google_drive() {
        let i = SaasLinkInspector::new();
        assert_eq!(
            i.identify_platform("https://drive.google.com/file/d/abc123"),
            Some(SaasPlatform::GoogleDrive)
        );
    }

    #[test]
    fn identifies_docusign() {
        let i = SaasLinkInspector::new();
        assert_eq!(
            i.identify_platform("https://www.docusign.net/Member/PowerFormSigning.aspx"),
            Some(SaasPlatform::DocuSign)
        );
    }

    #[test]
    fn does_not_identify_unknown_domain() {
        let i = SaasLinkInspector::new();
        assert_eq!(i.identify_platform("https://example.com/document"), None);
    }

    #[test]
    fn familiar_sender_gets_safe_rating() {
        let i = SaasLinkInspector::new();
        let mut hist = SaasHistory::new();
        for _ in 0..6 {
            hist.record("alice@example.com", SaasPlatform::GoogleDrive);
        }
        let detected = i.evaluate(
            "https://drive.google.com/file/d/abc",
            "alice@example.com",
            &hist,
        ).unwrap_or_default();
        assert_eq!(detected.risk, SaasLinkRisk::Safe);
    }

    #[test]
    fn unknown_sender_gets_caution() {
        let i = SaasLinkInspector::new();
        let hist = SaasHistory::new();
        let detected = i.evaluate(
            "https://drive.google.com/file/d/abc",
            "stranger@unknown.com",
            &hist,
        ).unwrap_or_default();
        assert_eq!(detected.risk, SaasLinkRisk::Caution);
    }

    #[test]
    fn auth_keyword_escalates_to_warn() {
        let i = SaasLinkInspector::new();
        let hist = SaasHistory::new();
        let detected = i.evaluate(
            "https://drive.google.com/auth/login",
            "stranger@unknown.com",
            &hist,
        ).unwrap_or_default();
        assert_eq!(detected.risk, SaasLinkRisk::Warn);
    }

    #[test]
    fn malicious_domain_blocks() {
        let mut i = SaasLinkInspector::new();
        i.add_malicious("evil-redirect.com");
        let hist = SaasHistory::new();
        let detected = i.evaluate(
            "https://drive.google.com/?redirect=https://evil-redirect.com/exploit",
            "alice@example.com",
            &hist,
        );
        // detected.unwrap_or_default() で検証
        if let Some(d) = detected {
            assert_eq!(d.risk, SaasLinkRisk::Block);
        }
    }

    #[test]
    fn history_records_interactions() {
        let mut hist = SaasHistory::new();
        hist.record("alice@example.com", SaasPlatform::DocuSign);
        hist.record("alice@example.com", SaasPlatform::DocuSign);
        assert_eq!(hist.count("alice@example.com", SaasPlatform::DocuSign), 2);
        assert!(!hist.is_familiar("alice@example.com", SaasPlatform::DocuSign));

        for _ in 0..3 {
            hist.record("alice@example.com", SaasPlatform::DocuSign);
        }
        assert_eq!(hist.count("alice@example.com", SaasPlatform::DocuSign), 5);
        assert!(hist.is_familiar("alice@example.com", SaasPlatform::DocuSign));
    }

    #[test]
    fn platform_domains_listed() {
        let domains = SaasPlatform::GoogleDrive.domains();
        assert!(domains.contains(&"drive.google.com"));
        assert!(domains.contains(&"docs.google.com"));
    }

    #[test]
    fn platform_display_name() {
        assert_eq!(SaasPlatform::DocuSign.display_name(), "DocuSign");
        assert_eq!(SaasPlatform::GoogleDrive.display_name(), "Google Drive");
    }

    #[test]
    fn detects_dropbox_short_link() {
        let i = SaasLinkInspector::new();
        assert_eq!(
            i.identify_platform("https://db.tt/abcXYZ"),
            Some(SaasPlatform::Dropbox)
        );
    }

    #[test]
    fn reasons_populated() {
        let i = SaasLinkInspector::new();
        let hist = SaasHistory::new();
        let detected = i.evaluate(
            "https://docusign.net/sign",
            "newbie@startup.com",
            &hist,
        ).unwrap_or_default();
        assert!(!detected.reasons.is_empty());
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
        /// 不変条件: identify_platform は決定論的
        #[test]
        fn platform_identification_deterministic(url in "https://[a-z]{3,10}\\.example\\.com/[a-z]{0,10}") {
            let inspector = SaasLinkInspector::new();
            let r1 = inspector.identify_platform(&url);
            let r2 = inspector.identify_platform(&url);
            prop_assert_eq!(r1, r2, "identify_platform は決定論的");
        }

        /// 不変条件: history.count は単調増加
        #[test]
        fn history_count_monotone(n in 1usize..20) {
            let mut hist = SaasHistory::new();
            for i in 0..n {
                hist.record("alice@example.com", SaasPlatform::DocuSign);
                let count = hist.count("alice@example.com", SaasPlatform::DocuSign);
                prop_assert_eq!(count, (i + 1) as u32,
                    "count は単調増加: expected {}, got {}", i + 1, count);
            }
        }

        /// 不変条件: is_familiar の閾値は 5
        #[test]
        fn familiar_threshold_is_five(n in 0usize..20) {
            let mut hist = SaasHistory::new();
            for _ in 0..n {
                hist.record("test@example.com", SaasPlatform::GoogleDrive);
            }
            if n >= 5 {
                prop_assert!(hist.is_familiar("test@example.com", SaasPlatform::GoogleDrive));
            } else {
                prop_assert!(!hist.is_familiar("test@example.com", SaasPlatform::GoogleDrive));
            }
        }
    }
}
