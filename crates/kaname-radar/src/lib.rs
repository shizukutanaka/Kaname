//! kaname-radar — Polymorphic Campaign Radar (PCR)
//!
//! 2026 年のポリモーフィックフィッシング対策。
//!
//! # 発見した洞察 (Cofense 2026年2月)
//!
//! ```text
//! 個々のメール: URL 76% が一意、ハッシュ 82% が一意
//!              → シグネチャ検出は完全に無効
//!
//! インフラ:     94% が同一 IP アドレスを共有
//!              → インフラ fingerprinting は有効
//! ```
//!
//! # 設計原則
//!
//! **AI はコンテンツを読まない。メタデータのみを解析する。**
//!
//! 解析対象:
//! - メールヘッダーのドメイン (From:, Return-Path:, Reply-To:)
//! - 本文内リンクのドメイン
//! - DKIM 署名ドメイン
//!
//! 非解析対象 (プライバシー保護):
//! - メール本文テキスト
//! - 添付ファイル内容
//! - 件名
//!
//! # Dual-LLM 境界との関係
//!
//! PCR は Dual-LLM の外側で動作する。
//! AI がコンテンツを読むのではなく、ドメイン→IP の機械的なマッピングのみ。
//! これは北極星「AIが受信箱全体を読まない」と完全に整合する。

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// メールメタデータ (コンテンツなし)
// ============================================================================

/// PCR が解析するメールのメタデータ。
///
/// **重要**: 本文・件名・添付内容は含まない。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMetadata {
    /// メール識別子 (JMAP ID)
    pub email_id: String,
    /// From: ヘッダーのドメイン
    pub from_domain: String,
    /// Return-Path: ヘッダーのドメイン (省略可)
    pub return_path_domain: Option<String>,
    /// DKIM 署名ドメイン (d=タグ)
    pub dkim_domain: Option<String>,
    /// 本文内リンクのドメイン一覧 (最大 20)
    pub link_domains: Vec<String>,
    /// 受信時刻 (UNIX 秒)
    pub received_at: u64,
}

impl EmailMetadata {
    /// 全ドメインをフラットなリストで返す (重複除去)。
    #[must_use]
    pub fn all_domains(&self) -> Vec<&str> {
        let mut domains: Vec<&str> = vec![self.from_domain.as_str()];
        if let Some(d) = &self.return_path_domain {
            domains.push(d.as_str());
        }
        if let Some(d) = &self.dkim_domain {
            domains.push(d.as_str());
        }
        for d in &self.link_domains {
            domains.push(d.as_str());
        }
        domains.sort_unstable();
        domains.dedup();
        domains
    }
}

// ============================================================================
// インフラストラクチャグループ
// ============================================================================

/// 同一インフラを共有する疑わしいメールのグループ。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignGroup {
    /// グループ ID
    pub id: String,
    /// 共有されているインフラ (疑似 IP またはドメインキー)
    pub shared_infrastructure: String,
    /// このグループのメール ID 一覧
    pub email_ids: Vec<String>,
    /// 最初の検出時刻 (UNIX 秒)
    pub first_detected_unix: u64,
    /// 最後の更新時刻 (UNIX 秒)
    pub last_updated_unix: u64,
    /// 脅威スコア (0.0 = 低リスク, 1.0 = 高リスク)
    pub threat_score: f32,
}

impl CampaignGroup {
    fn new(infra: impl Into<String>, first_email_id: impl Into<String>) -> Self {
        let now = now_unix();
        let infra = infra.into();
        let id = format!("pcr_{}", &infra[..infra.len().min(8)]);
        Self {
            id,
            shared_infrastructure: infra,
            email_ids: vec![first_email_id.into()],
            first_detected_unix: now,
            last_updated_unix: now,
            threat_score: 0.3, // 初期は低め
        }
    }

    fn add_email(&mut self, email_id: impl Into<String>) {
        self.email_ids.push(email_id.into());
        self.last_updated_unix = now_unix();
        // メール数が増えるほど脅威スコアが上がる (最大 1.0)
        #[allow(clippy::cast_precision_loss)]
        { self.threat_score = (0.3 + 0.1 * self.email_ids.len() as f32).min(1.0); }
    }

    /// グループが警告に値するか (3 通以上の場合)
    #[must_use]
    pub fn is_alertable(&self) -> bool {
        self.email_ids.len() >= 3
    }
}

// ============================================================================
// キャンペーン検出結果
// ============================================================================

/// 新規メールがグループにマッチした結果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignMatch {
    /// 新規メール ID
    pub new_email_id: String,
    /// マッチしたグループ
    pub group: CampaignGroup,
    /// このグループが初めて警告レベルに達したか
    pub newly_alertable: bool,
}

// ============================================================================
// Polymorphic Campaign Radar
// ============================================================================

/// ポリモーフィックキャンペーン検出器。
pub struct CampaignRadar {
    /// ドメイン → インフラキー のキャッシュ
    /// (本番では DNS 解決を行うが、ここでは決定論的なハッシュを使用)
    domain_to_infra: HashMap<String, String>,
    /// インフラキー → グループ のマップ
    groups: HashMap<String, CampaignGroup>,
    /// 解析済みメール ID のセット (重複処理防止)
    seen_emails: HashSet<String>,
    /// グループの保持期間 (デフォルト 30 日)
    retention: Duration,
}

impl CampaignRadar {
    /// 新規レーダーを構築。
    #[must_use]
    pub fn new() -> Self {
        Self {
            domain_to_infra: HashMap::new(),
            groups: HashMap::new(),
            seen_emails: HashSet::new(),
            retention: Duration::from_secs(30 * 24 * 3600),
        }
    }

    /// 保持期間を設定 (テスト用)。
    #[must_use]
    pub fn with_retention(mut self, retention: Duration) -> Self {
        self.retention = retention;
        self
    }

    /// ドメインとインフラキーの対応を追加 (シミュレーション / テスト用)。
    ///
    /// 本番では DNS 解決で自動的にマッピングする。
    pub fn register_domain(&mut self, domain: impl Into<String>, infra_key: impl Into<String>) {
        self.domain_to_infra.insert(domain.into(), infra_key.into());
    }

    /// メールメタデータを解析して既存グループと照合する。
    ///
    /// # 戻り値
    ///
    /// - `Some(CampaignMatch)`: 既存グループにマッチした
    /// - `None`: 新規の孤立したメール (グループなし)
    #[must_use]
    pub fn analyze(&mut self, metadata: &EmailMetadata) -> Option<CampaignMatch> {
        // 重複処理防止
        if !self.seen_emails.insert(metadata.email_id.clone()) {
            return None;
        }

        // 期限切れグループを削除
        self.evict_expired();

        // 全ドメインをインフラキーに変換
        let infra_keys: Vec<String> = metadata
            .all_domains()
            .iter()
            .filter_map(|d| self.resolve_infra(d))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        if infra_keys.is_empty() {
            // 未知のインフラ → 新規グループ候補として保存
            let key = format!("unknown:{}", metadata.from_domain);
            self.groups
                .entry(key.clone())
                .or_insert_with(|| CampaignGroup::new(key, &metadata.email_id));
            return None;
        }

        // 既存グループとのマッチング
        let mut matched_group_key: Option<String> = None;
        for key in &infra_keys {
            if self.groups.contains_key(key) {
                matched_group_key = Some(key.clone());
                break;
            }
        }

        if let Some(key) = matched_group_key {
            let was_alertable = self.groups[&key].is_alertable();
            if let Some(group) = self.groups.get_mut(&key) {
                group.add_email(&metadata.email_id);
                let now_alertable = group.is_alertable();

                return Some(CampaignMatch {
                    new_email_id: metadata.email_id.clone(),
                    group: group.clone(),
                    newly_alertable: !was_alertable && now_alertable,
                });
            }
            return None;
        }
        {
            // 新規グループを作成 (次回マッチングの準備)
            for key in infra_keys {
                self.groups
                    .entry(key.clone())
                    .or_insert_with(|| CampaignGroup::new(key, &metadata.email_id));
            }
            None
        }
    }

    /// 全アクティブグループを返す。
    #[must_use]
    pub fn groups(&self) -> Vec<&CampaignGroup> {
        self.groups.values().collect()
    }

    /// 警告レベルのグループのみを返す (3 通以上)。
    #[must_use]
    pub fn alertable_groups(&self) -> Vec<&CampaignGroup> {
        self.groups.values().filter(|g| g.is_alertable()).collect()
    }

    /// グループ数を返す。
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// ドメインをインフラキーに解決する。
    ///
    /// 本番では DNS A/AAAA ルックアップを非同期で実行。
    /// ここでは事前登録されたマッピングを使用。
    fn resolve_infra(&self, domain: &str) -> Option<String> {
        // 登録済みマッピングから検索
        if let Some(key) = self.domain_to_infra.get(domain) {
            return Some(key.clone());
        }

        // 二次レベルドメイン (SLD) でも検索
        let sld = extract_sld(domain);
        if sld != domain {
            if let Some(key) = self.domain_to_infra.get(sld) {
                return Some(key.clone());
            }
        }

        None
    }

    /// 期限切れグループを削除する。
    fn evict_expired(&mut self) {
        let cutoff = now_unix().saturating_sub(self.retention.as_secs());
        self.groups
            .retain(|_, g| g.last_updated_unix >= cutoff);
    }
}

impl Default for CampaignRadar {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ユーティリティ
// ============================================================================

/// セカンドレベルドメインを抽出する (例: mail.evil.com → evil.com)。
#[must_use]
pub fn extract_sld(domain: &str) -> &str {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        let start = parts.len() - 2;
        let byte_offset = parts[..start].iter().map(|p| p.len() + 1).sum::<usize>();
        &domain[byte_offset..]
    } else {
        domain
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(unused_must_use, clippy::needless_pass_by_value, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn email(id: &str, from: &str, links: Vec<&str>) -> EmailMetadata {
        EmailMetadata {
            email_id: id.to_string(),
            from_domain: from.to_string(),
            return_path_domain: None,
            dkim_domain: None,
            link_domains: links.iter().map(ToString::to_string).collect(),
            received_at: now_unix(),
        }
    }

    fn radar_with_infra() -> CampaignRadar {
        let mut r = CampaignRadar::new();
        // 3 つの異なるドメインが同一インフラ (攻撃者の IP) を共有
        r.register_domain("phish-1.com", "attacker-infra-42");
        r.register_domain("phish-2.com", "attacker-infra-42");
        r.register_domain("phish-3.com", "attacker-infra-42");
        // 正規ドメイン
        r.register_domain("example.com", "legitimate-cloud-99");
        r
    }

    #[test]
    fn single_email_no_match() {
        let mut r = radar_with_infra();
        let result = r.analyze(&email("e1", "sender.com", vec!["phish-1.com"]));
        // 最初の 1 通はマッチしない (グループに追加されるだけ)
        assert!(result.is_none(), "最初の 1 通でマッチしないはず");
    }

    #[test]
    fn second_email_same_infra_matches() {
        let mut r = radar_with_infra();
        r.analyze(&email("e1", "attacker.com", vec!["phish-1.com"]));
        let result = r.analyze(&email("e2", "attacker2.com", vec!["phish-2.com"]));
        // 2 通目は同じインフラ → マッチ
        assert!(result.is_some(), "同一インフラの 2 通目はマッチするはず");
    }

    #[test]
    fn group_becomes_alertable_at_third_email() {
        let mut r = radar_with_infra();
        r.analyze(&email("e1", "x.com", vec!["phish-1.com"]));
        r.analyze(&email("e2", "y.com", vec!["phish-2.com"]));
        let result = r.analyze(&email("e3", "z.com", vec!["phish-3.com"]));
        assert!(result.is_some());
        let m = result.unwrap();
        assert!(m.group.is_alertable(), "3 通でアラートレベルに達するはず");
        assert!(m.newly_alertable, "新たにアラートレベルに達したはず");
        assert_eq!(m.group.email_ids.len(), 3);
    }

    #[test]
    fn threat_score_increases_with_count() {
        let mut r = radar_with_infra();
        r.analyze(&email("e1", "x.com", vec!["phish-1.com"]));
        let m2 = r.analyze(&email("e2", "y.com", vec!["phish-2.com"])).unwrap();
        let score_2 = m2.group.threat_score;
        let m3 = r.analyze(&email("e3", "z.com", vec!["phish-3.com"])).unwrap();
        let score_3 = m3.group.threat_score;
        assert!(score_3 > score_2, "メール数増加でスコアが上がるはず: {score_3} > {score_2}");
    }

    #[test]
    fn threat_score_capped_at_1() {
        let mut r = radar_with_infra();
        // 10 通送る
        for i in 0..10 {
            r.analyze(&email(&format!("e{i}"), "x.com", vec!["phish-1.com"]));
        }
        let groups = r.alertable_groups();
        assert!(!groups.is_empty());
        for g in groups {
            assert!(g.threat_score <= 1.0, "スコアは 1.0 を超えない: {}", g.threat_score);
        }
    }

    #[test]
    fn duplicate_email_id_ignored() {
        let mut r = radar_with_infra();
        r.analyze(&email("e1", "x.com", vec!["phish-1.com"]));
        // 同じ ID を再度送る
        let result = r.analyze(&email("e1", "x.com", vec!["phish-1.com"]));
        assert!(result.is_none(), "重複 ID は無視されるはず");
    }

    #[test]
    fn different_infra_no_match() {
        let mut r = radar_with_infra();
        r.analyze(&email("e1", "x.com", vec!["phish-1.com"]));
        // 全く別のインフラからのメール
        let result = r.analyze(&email("e2", "clean.org", vec!["example.com"]));
        // 別インフラなのでマッチしない
        assert!(result.is_none(), "別インフラはマッチしないはず");
    }

    #[test]
    fn alertable_groups_filtered() {
        let mut r = radar_with_infra();
        r.analyze(&email("e1", "x.com", vec!["phish-1.com"]));
        assert_eq!(r.alertable_groups().len(), 0, "2 通未満はアラートなし");
        r.analyze(&email("e2", "y.com", vec!["phish-2.com"]));
        assert_eq!(r.alertable_groups().len(), 0, "2 通はアラートなし");
        r.analyze(&email("e3", "z.com", vec!["phish-3.com"]));
        assert_eq!(r.alertable_groups().len(), 1, "3 通でアラートグループ出現");
    }

    #[test]
    fn all_domains_deduplicates() {
        let meta = EmailMetadata {
            email_id: "e1".into(),
            from_domain: "evil.com".into(),
            return_path_domain: Some("evil.com".into()),
            dkim_domain: Some("evil.com".into()),
            link_domains: vec!["evil.com".into(), "other.com".into()],
            received_at: 0,
        };
        let domains = meta.all_domains();
        let unique: HashSet<&&str> = domains.iter().collect();
        assert_eq!(domains.len(), unique.len(), "重複が除去されているはず");
    }

    #[test]
    fn extract_sld_basic() {
        assert_eq!(extract_sld("mail.evil.com"), "evil.com");
        assert_eq!(extract_sld("evil.com"), "evil.com");
        assert_eq!(extract_sld("a.b.c.evil.co.jp"), "co.jp");
    }

    #[test]
    fn sld_fallback_matching() {
        let mut r = CampaignRadar::new();
        // SLD レベルで登録
        r.register_domain("evil.com", "infra-x");
        // サブドメインで解析
        r.analyze(&email("e1", "mail.evil.com", vec![]));
        // SLD フォールバックで e1 がグループに入る
        assert!(r.group_count() > 0);
    }

    #[test]
    fn groups_all_returns_all() {
        let mut r = radar_with_infra();
        r.analyze(&email("e1", "x.com", vec!["phish-1.com"]));
        r.analyze(&email("e2", "y.com", vec!["example.com"]));
        assert!(!r.groups().is_empty());
    }

    #[test]
    fn radar_group_id_is_deterministic() {
        // 同じインフラキーから作られたグループは同じ ID プレフィックス
        let mut r = radar_with_infra();
        r.analyze(&email("e1", "x.com", vec!["phish-1.com"]));
        r.analyze(&email("e2", "y.com", vec!["phish-2.com"]));
        let g = r.groups();
        assert!(!g.is_empty());
        assert!(g[0].id.starts_with("pcr_"), "ID は pcr_ で始まる");
    }
}

// ============================================================================
// プロパティテスト
// ============================================================================

#[cfg(test)]
#[allow(unused_must_use, clippy::unwrap_used, clippy::expect_used)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_email(id: &str, infra: &str) -> EmailMetadata {
        EmailMetadata {
            email_id: id.to_string(),
            from_domain: format!("sender-{id}.com"),
            return_path_domain: None,
            dkim_domain: None,
            link_domains: vec![format!("evil-{infra}.com")],
            received_at: 0,
        }
    }

    proptest! {
        /// 不変条件: 重複メール ID は無視される
        #[test]
        fn duplicate_emails_ignored(n in 2usize..10) {
            let mut radar = CampaignRadar::new();
            radar.register_domain("evil-test.com", "test-infra");
            // 同じ ID で n 回送る
            for _ in 0..n {
                radar.analyze(&arb_email("same-id", "test"));
            }
            // グループのメール数は 1 のまま
            let groups = radar.groups();
            for g in &groups {
                prop_assert!(g.email_ids.len() <= 1,
                    "重複IDが処理されている: {} 件", g.email_ids.len());
            }
        }

        /// 不変条件: threat_score は常に 0.0-1.0
        #[test]
        fn threat_score_always_valid(n in 1usize..20) {
            let mut radar = CampaignRadar::new();
            for i in 0..n {
                radar.register_domain(format!("phish-{i}.com"), "shared-infra");
            }
            let email = arb_email("test", "0");
            radar.analyze(&email);
            for g in radar.groups() {
                prop_assert!(
                    g.threat_score >= 0.0 && g.threat_score <= 1.0,
                    "threat_score 範囲外: {}", g.threat_score
                );
            }
        }
    }
}

// ============================================================================
// DNS 解決 (本番統合用)
// ============================================================================

/// DNS ルックアップのトレイト。
///
/// 本番実装は `tokio::net::lookup_host()` で IP を取得する。
/// テスト実装はハッシュマップでシミュレートする。
pub trait DnsResolver: Send + Sync {
    /// ドメイン名を IP アドレスのリストに解決する。
    fn resolve(&self, domain: &str) -> Vec<String>;
}

/// テスト用の静的 DNS リゾルバー。
#[derive(Default)]
pub struct StaticDnsResolver {
    records: std::collections::HashMap<String, Vec<String>>,
}

impl StaticDnsResolver {
    /// 新規リゾルバーを作成。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// レコードを追加 (テスト用)。
    pub fn add(&mut self, domain: impl Into<String>, ips: Vec<impl Into<String>>) {
        self.records.insert(
            domain.into(),
            ips.into_iter().map(Into::into).collect(),
        );
    }
}

impl DnsResolver for StaticDnsResolver {
    fn resolve(&self, domain: &str) -> Vec<String> {
        self.records.get(domain).cloned().unwrap_or_default()
    }
}

// ============================================================================
// 追加プロパティテスト
// ============================================================================

#[cfg(test)]
#[allow(unused_must_use, clippy::unwrap_used, clippy::expect_used)]
mod dns_tests {
    use super::*;

    #[test]
    fn static_resolver_returns_registered_ips() {
        let mut r = StaticDnsResolver::new();
        r.add("evil.com", vec!["203.0.113.42", "203.0.113.43"]);
        let ips = r.resolve("evil.com");
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"203.0.113.42".to_string()));
    }

    #[test]
    fn static_resolver_returns_empty_for_unknown() {
        let r = StaticDnsResolver::new();
        assert!(r.resolve("unknown.com").is_empty());
    }

    #[test]
    fn extract_sld_handles_edge_cases() {
        assert_eq!(extract_sld("com"), "com");
        assert_eq!(extract_sld("example.com"), "example.com");
        assert_eq!(extract_sld("sub.example.com"), "example.com");
        assert_eq!(extract_sld("a.b.example.com"), "example.com");
    }
}
