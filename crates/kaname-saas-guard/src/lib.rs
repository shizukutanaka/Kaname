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
#![allow(clippy::doc_markdown)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

// ============================================================================
// SaaS プラットフォーム
// ============================================================================

/// 認識する SaaS プラットフォーム。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    Other(String),
}

impl SaasPlatform {
    /// プラットフォームのドメインリスト。
    #[must_use]
    pub fn domains(&self) -> Vec<&'static str> {
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
            Self::Other(_)     => vec![],
        }
    }

    /// 表示名。
    #[must_use]
    pub fn display_name(&self) -> String {
        match self {
            Self::GoogleDrive => "Google Drive".into(),
            Self::OneDrive    => "Microsoft OneDrive".into(),
            Self::SharePoint  => "Microsoft SharePoint".into(),
            Self::DocuSign    => "DocuSign".into(),
            Self::AdobeSign   => "Adobe Sign".into(),
            Self::Dropbox     => "Dropbox".into(),
            Self::Box         => "Box".into(),
            Self::Notion      => "Notion".into(),
            Self::Smartsheet  => "Smartsheet".into(),
            Self::Other(d)    => d.clone(),
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

impl Default for DetectedSaasLink {
    fn default() -> Self {
        Self {
            url: String::new(),
            platform: SaasPlatform::Other(String::new()),
            risk: SaasLinkRisk::Safe,
            reasons: Vec::new(),
            sender: String::new(),
        }
    }
}

// ============================================================================
// 履歴ベース信頼度
// ============================================================================

/// 送信者ごとの SaaS 利用履歴。
#[derive(Debug)]
pub struct SaasHistory {
    /// (送信者, プラットフォーム) → やり取り回数
    interactions: std::collections::HashMap<(String, SaasPlatform), u32>,
    /// エントリ数上限 (OOM DoS 防止)
    max_senders: usize,
}

impl Default for SaasHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl SaasHistory {
    /// 新規履歴を作成。
    #[must_use]
    pub fn new() -> Self {
        Self { interactions: std::collections::HashMap::new(), max_senders: 100_000 }
    }

    /// やり取りを記録。
    ///
    /// `max_senders` に達した場合は新規送信者を無視する (既存送信者のカウント更新は許可)。
    pub fn record(&mut self, sender: impl Into<String>, platform: SaasPlatform) {
        let sender = sender.into();
        let key = (sender, platform);
        // 既存エントリの更新は常に許可
        if self.interactions.contains_key(&key) {
            *self.interactions.entry(key).or_insert(0) += 1;
            return;
        }
        // 新規エントリは容量内のみ受け入れる
        if self.interactions.len() < self.max_senders {
            self.interactions.insert(key, 1);
        }
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
        for platform in &self.platforms {
            for domain in platform.domains() {
                if lower.contains(domain) {
                    return Some(platform.clone());
                }
            }
        }
        None
    }

    /// URL が短縮サービスを経由しているかを確認する。
    ///
    /// 短縮 URL はサンドボックス内で展開してから再評価すべき。
    /// この関数は展開前の一次フィルターとして使用する。
    #[must_use]
    pub fn check_shortened(&self, url: &str) -> Option<DetectedSaasLink> {
        if !is_shortened_url(url) {
            return None;
        }
        Some(DetectedSaasLink {
            url: url.to_string(),
            platform: SaasPlatform::Other("shortened-url".to_string()),
            risk: SaasLinkRisk::Warn,
            reasons: vec![
                "短縮 URL を検出 — 展開前の評価不可能。サンドボックスで展開後に再評価が必要".to_string(),
            ],
            sender: String::new(),
        })
    }

    /// SaaS リンクを評価する。
    ///
    /// URL 長を 8192 文字に制限する (異常に長い URL による過剰な文字列検索 DoS 防止)。
    #[must_use]
    pub fn evaluate(
        &self,
        url: &str,
        sender: &str,
        history: &SaasHistory,
    ) -> Option<DetectedSaasLink> {
        const MAX_URL_LEN: usize = 8192;
        if url.len() > MAX_URL_LEN {
            return Some(DetectedSaasLink {
                url: url.chars().take(64).collect::<String>() + "…",
                platform: SaasPlatform::Other("unknown".to_string()),
                risk: SaasLinkRisk::Suspicious,
                reasons: vec![format!("URL が異常に長い: {} 文字 (上限 {MAX_URL_LEN})", url.len())],
                sender: sender.to_string(),
            });
        }
        // 短縮 URL は SaaS 判定より先にチェック
        if let Some(short_finding) = self.check_shortened(url) {
            return Some(short_finding);
        }
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
        if risk != SaasLinkRisk::Block && self.is_fake_saas_subdomain(url, &platform) {
            risk = SaasLinkRisk::Suspicious;
            reasons.push(format!("{} を装った偽ドメインの可能性", platform.display_name()));
        }

        // 3. 送信者履歴ベース評価
        if risk == SaasLinkRisk::Safe {
            risk = if history.is_familiar(sender, platform.clone()) {
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
    ///
    /// # ドット境界チェック
    ///
    /// `ends_with("docusign.com")` だけでは `notdocusign.com` も通過してしまう。
    /// 正規ドメインの前にドットが来ることを確認する。
    #[allow(clippy::unused_self)]
    fn is_fake_saas_subdomain(&self, url: &str, platform: &SaasPlatform) -> bool {
        for legit_domain in platform.domains() {
            if url.contains(legit_domain) {
                if let Some(domain) = extract_actual_domain(url) {
                    // 正規ドメインそのもの、またはドット区切りのサブドメインのみ許可
                    let is_legitimate = domain == legit_domain
                        || domain.ends_with(&format!(".{legit_domain}"));
                    if !is_legitimate {
                        return true; // 偽装の可能性
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
// 短縮 URL 検出
// ============================================================================

/// 既知の短縮 URL サービスのドメイン一覧。
const URL_SHORTENER_DOMAINS: &[&str] = &[
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly",
    "buff.ly", "dlvr.it", "ift.tt", "short.link", "rebrand.ly",
    "cutt.ly", "tiny.cc", "is.gd", "rb.gy", "clck.ru",
    "qr.ae", "po.st", "shorturl.at",
];

/// 短縮 URL かどうかを判定する。
///
/// 短縮 URL は展開前の評価が不可能なため、`kaname-render` の
/// サンドボックスで展開してから再評価する必要がある。
#[must_use]
pub fn is_shortened_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    URL_SHORTENER_DOMAINS
        .iter()
        .any(|d| lower.contains(&format!("://{d}/")) || lower.contains(&format!("://{d}")))
}

// ============================================================================
// ユーティリティ
// ============================================================================

#[allow(clippy::unnecessary_wraps)]
fn extract_actual_domain(url: &str) -> Option<String> {
    let without_scheme = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let domain_end = without_scheme.find(['/', '?']).unwrap_or(without_scheme.len());
    let host_port = &without_scheme[..domain_end];
    // ポート番号を除去: "docusign.com:8443" → "docusign.com"
    // ポート付き正規ドメインを偽ドメインと誤判定する偽陽性を防ぐ
    let domain = host_port.split(':').next().unwrap_or(host_port);
    Some(domain.to_lowercase())
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

    #[test]
    fn shortened_url_detected_as_warn() {
        assert!(is_shortened_url("https://bit.ly/3xAbCdE"));
        assert!(is_shortened_url("https://t.co/XyZ123"));
        assert!(is_shortened_url("https://tinyurl.com/yy4qr3m9"));
        assert!(!is_shortened_url("https://docusign.net/sign"));
        assert!(!is_shortened_url("https://example.com/path"));
    }

    #[test]
    fn evaluate_returns_warn_for_shortened_url() {
        let inspector = SaasLinkInspector::new();
        let hist = SaasHistory::new();
        let result = inspector.evaluate("https://bit.ly/3xAbCdE", "attacker@evil.com", &hist);
        let found = result.expect("should return a finding");
        assert_eq!(found.risk, SaasLinkRisk::Warn, "短縮URL はWarn");
        assert!(found.reasons[0].contains("短縮"));
    }

    #[test]
    fn evaluate_non_shortened_saas_link_not_overridden() {
        let inspector = SaasLinkInspector::new();
        let hist = SaasHistory::new();
        // 通常のドキュサインリンクは短縮URL検出でブロックされない
        let result = inspector.evaluate("https://docusign.net/sign", "alice@corp.com", &hist);
        let found = result.expect("should detect DocuSign");
        // 短縮URLではないのでWarnではなく適切なリスク評価
        assert_ne!(found.reasons[0], "短縮 URL を検出");
    }

    // ── ポート偽陽性テスト ────────────────────────────────────────────────

    #[test]
    fn ポート付き正規ドメインを偽ドメイン扱いにしない() {
        let inspector = SaasLinkInspector::new();
        let hist = SaasHistory::new();
        // docusign.com:8443 は正規 DocuSign のポート変更版
        // → 偽ドメインと誤判定 (Suspicious) しないこと
        let result = inspector.evaluate("https://docusign.com:8443/sign", "sender@corp.com", &hist);
        if let Some(found) = result {
            assert_ne!(found.risk, SaasLinkRisk::Suspicious,
                "正規ドメインのポート付き URL を偽ドメインと誤判定してはならない");
        }
    }

    // ── URL 長さ制限テスト ────────────────────────────────────────────────

    #[test]
    fn 異常に長いurlをsuspiciousとして返す() {
        let inspector = SaasLinkInspector::new();
        let hist = SaasHistory::new();
        let long_url = format!("https://evil.com/{}", "a".repeat(10_000));
        let result = inspector.evaluate(&long_url, "attacker@evil.com", &hist);
        let found = result.expect("長すぎる URL は Suspicious を返すべき");
        assert_eq!(found.risk, SaasLinkRisk::Suspicious,
            "8192 文字超の URL は Suspicious でなければならない");
        assert!(found.reasons[0].contains("異常に長い"),
            "理由に長さの説明が含まれるべき: {:?}", found.reasons);
    }

    // ── SaasHistory 容量制限テスト ────────────────────────────────────────

    #[test]
    fn history_容量制限で新規送信者を拒否する() {
        let mut hist = SaasHistory::new();
        hist.max_senders = 3;
        hist.record("a@a.com", SaasPlatform::GoogleDrive);
        hist.record("b@b.com", SaasPlatform::GoogleDrive);
        hist.record("c@c.com", SaasPlatform::GoogleDrive);
        // 容量上限到達 → 新規送信者は無視
        hist.record("d@d.com", SaasPlatform::GoogleDrive);
        assert_eq!(hist.count("d@d.com", SaasPlatform::GoogleDrive), 0,
            "上限到達後の新規送信者はカウントされてはならない");
    }

    // ── ドット境界バイパステスト ──────────────────────────────────────────

    #[test]
    fn prefix_spoof_notdocusign_com_is_suspicious() {
        // "notdocusign.com" は ends_with("docusign.com") == true だが偽ドメイン
        let inspector = SaasLinkInspector::new();
        let hist = SaasHistory::new();
        let result = inspector.evaluate(
            "https://notdocusign.com/sign/document",
            "attacker@evil.com",
            &hist,
        );
        if let Some(found) = result {
            assert_eq!(found.risk, SaasLinkRisk::Suspicious,
                "notdocusign.com は Suspicious でなければならない: {:?}", found.risk);
        }
    }

    #[test]
    fn prefix_spoof_notdropbox_com_is_suspicious() {
        let inspector = SaasLinkInspector::new();
        let hist = SaasHistory::new();
        let result = inspector.evaluate(
            "https://notdropbox.com/sh/abc123",
            "attacker@evil.com",
            &hist,
        );
        if let Some(found) = result {
            assert_eq!(found.risk, SaasLinkRisk::Suspicious,
                "notdropbox.com は Suspicious でなければならない: {:?}", found.risk);
        }
    }

    #[test]
    fn legitimate_subdomain_not_flagged_as_suspicious() {
        // www.docusign.com は正規サブドメイン → Suspicious にしてはならない
        let inspector = SaasLinkInspector::new();
        let hist = SaasHistory::new();
        let result = inspector.evaluate(
            "https://www.docusign.com/sign",
            "sender@corp.com",
            &hist,
        );
        if let Some(found) = result {
            assert_ne!(found.risk, SaasLinkRisk::Suspicious,
                "www.docusign.com は正規サブドメインなので Suspicious にしてはならない");
        }
    }

    #[test]
    fn exact_legit_domain_not_flagged() {
        let inspector = SaasLinkInspector::new();
        let hist = SaasHistory::new();
        let result = inspector.evaluate(
            "https://dropbox.com/sh/abc123",
            "sender@corp.com",
            &hist,
        );
        if let Some(found) = result {
            assert_ne!(found.risk, SaasLinkRisk::Suspicious,
                "dropbox.com そのものを偽ドメイン扱いしてはならない");
        }
    }

    #[test]
    fn history_容量上限でも既存送信者カウントは更新する() {
        let mut hist = SaasHistory::new();
        hist.max_senders = 1;
        hist.record("alice@corp.com", SaasPlatform::DocuSign);
        // 容量上限 (1) 到達後でも alice のカウント更新は許可
        hist.record("alice@corp.com", SaasPlatform::DocuSign);
        hist.record("alice@corp.com", SaasPlatform::DocuSign);
        assert_eq!(hist.count("alice@corp.com", SaasPlatform::DocuSign), 3,
            "既存送信者のカウントは上限後も更新されるべき");
    }
}

// ============================================================================
// プロパティテスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
