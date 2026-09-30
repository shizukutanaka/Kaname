//! kaname-radar — Polymorphic Campaign Radar (PCR)
//!
//! ポリモーフィックフィッシング対策のキャンペーンクラスタリング。
//!
//! # 設計原則
//!
//! **AI はコンテンツを読まない。メタデータのみを解析する。**
//!
//! 現行の検出経路 (実装済みのもののみ):
//! - `unknown:<from_domain>` バケット — 同一送信ドメインからの連続送信を蓄積
//! - `pattern:auth_fail:subject_<bucket>` — SPF/DKIM/DMARC 部分失敗 +
//!   件名長バケットが一致するメールを構造パターンでクラスタ
//!
//! 3 通以上で `alertable_groups()` が返し、`mail_scan_folder` の
//! `campaigns` フィールド経由で UI に警告表示される。
//!
//! 非解析対象 (プライバシー保護):
//! - メール本文テキスト
//! - 添付ファイル内容
//! - 件名
//!
//! # 削除済みの設計 (D144)
//!
//! ドメイン→共有インフラ解決 (`register_domain`/`resolve_infra`/
//! `domain_to_infra`) は DNS 実装が存在せず注入経路もゼロだったため削除。
//! ユーザー報告 API (`report_email_malicious`/`is_email_in_reported_campaign`/
//! `ReportImpact`/`user_reported_count`) と `with_retention`/`group_count`/
//! `seen_email_count`/`extract_sld`/`all_domains` も呼出元ゼロのため削除。
//! 復元する場合は git 履歴を参照。

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    /// 件名の長さカテゴリ (コンテンツ非依存のメタデータ)。
    /// PCR が未知インフラでも構造パターンを検出するために使用。
    pub subject_length_bucket: SubjectLengthBucket,
    /// SPF/DKIM/DMARC のうち少なくとも 1 つが失敗しているか
    pub auth_partial_fail: bool,
}

/// 件名の長さを大まかなカテゴリに分類する (プライバシー保護のため実際の件名は保存しない)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubjectLengthBucket {
    /// 0–10 文字 (空メールや極短)
    VeryShort,
    /// 11–30 文字
    Short,
    /// 31–60 文字
    Medium,
    /// 61–100 文字
    Long,
    /// 100 文字超
    VeryLong,
}

impl SubjectLengthBucket {
    /// 件名文字列からバケットを分類する (件名本体は保存しない)。
    #[must_use]
    pub fn from_subject(subject: &str) -> Self {
        match subject.chars().count() {
            0..=10 => Self::VeryShort,
            11..=30 => Self::Short,
            31..=60 => Self::Medium,
            61..=100 => Self::Long,
            _ => Self::VeryLong,
        }
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

/// 1 キャンペーングループが保持するメール ID の上限。
/// 超えた分は破棄 (脅威スコアは継続して更新)。
const MAX_EMAILS_PER_GROUP: usize = 10_000;

impl CampaignGroup {
    fn new(infra: impl Into<String>, first_email_id: impl Into<String>) -> Self {
        let now = now_unix();
        let infra = infra.into();
        // UUID v4 で衝突のない一意 ID を生成 (旧実装の先頭 8 文字では衝突リスクあり)
        let id = format!("pcr_{}", uuid::Uuid::new_v4().simple());
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
        let id = email_id.into();
        // 重複追加を防ぐ (同一 email_id が複数回 push されると threat_score が水増しされる)
        if self.email_ids.contains(&id) {
            return;
        }
        // メモリ DoS 防止: 上限を超えた場合は追跡を継続しつつ ID は保存しない
        if self.email_ids.len() < MAX_EMAILS_PER_GROUP {
            self.email_ids.push(id);
        }
        self.last_updated_unix = now_unix();
        self.recompute_threat_score();
    }

    /// 脅威スコアを再計算する (メール数が増えるほど上昇、最大 1.0)。
    #[allow(clippy::cast_precision_loss)]
    fn recompute_threat_score(&mut self) {
        self.threat_score = (0.3 + 0.1 * self.email_ids.len() as f32).min(1.0);
    }

    /// グループが警告に値するか (3 通以上で即座に)
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
    /// インフラキー → グループ のマップ
    groups: HashMap<String, CampaignGroup>,
    /// 解析済みメール ID → 初回解析時刻 (重複処理防止)。
    /// グループと同じ保持期間で退避し、無限肥大化 (メモリ `DoS`) を防ぐ。
    seen_emails: HashMap<String, u64>,
    /// グループの保持期間 (デフォルト 30 日)
    retention: Duration,
}

impl CampaignRadar {
    /// 新規レーダーを構築。
    #[must_use]
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            seen_emails: HashMap::new(),
            retention: Duration::from_secs(30 * 24 * 3600),
        }
    }

    /// メールメタデータを解析して既存グループと照合する。
    ///
    /// # 戻り値
    ///
    /// - `Some(CampaignMatch)`: 既存グループにマッチした
    /// - `None`: 新規の孤立したメール (グループなし)
    #[must_use]
    pub fn analyze(&mut self, metadata: &EmailMetadata) -> Option<CampaignMatch> {
        const MAX_EMAIL_ID_LEN: usize = 1024;
        const MAX_SEEN_EMAILS: usize = 50_000;

        // email_id が異常に長い場合はスキップ (DoS 防止)
        if metadata.email_id.len() > MAX_EMAIL_ID_LEN {
            tracing::warn!(
                "CampaignRadar: email_id が長すぎます ({} bytes), スキップ",
                metadata.email_id.len()
            );
            return None;
        }

        // 重複処理防止
        if self.seen_emails.contains_key(&metadata.email_id) {
            return None;
        }

        // 期限切れグループ・dedup エントリを削除
        self.evict_expired();

        // seen_emails が上限に達している場合、最古エントリを削除してから挿入する。
        // retention 期間内に大量ユニーク email_id を送りつける DoS を防ぐ。
        if self.seen_emails.len() >= MAX_SEEN_EMAILS {
            // 最古エントリを 1 件削除 (FIFO)
            if let Some(oldest_key) = self
                .seen_emails
                .iter()
                .min_by_key(|(_, &ts)| ts)
                .map(|(k, _)| k.clone())
            {
                self.seen_emails.remove(&oldest_key);
            }
        }

        // 解析済みとして記録 (退避基準のタイムスタンプ付き)
        self.seen_emails
            .insert(metadata.email_id.clone(), now_unix());

        {
            // 構造パターンでクラスタリングする。
            // 件名長バケット + 認証失敗パターンをキーとして使用。
            // コンテンツ (件名本体・本文) は一切保存しない — 北極星維持。
            if metadata.auth_partial_fail {
                let pattern_key = format!(
                    "pattern:auth_fail:subject_{}",
                    pattern_key_for_bucket(metadata.subject_length_bucket)
                );
                let was_alertable = self
                    .groups
                    .get(&pattern_key)
                    .is_some_and(CampaignGroup::is_alertable);
                let group = self
                    .groups
                    .entry(pattern_key.clone())
                    .or_insert_with(|| CampaignGroup::new(pattern_key.clone(), &metadata.email_id));
                group.add_email(&metadata.email_id);
                let now_alertable = group.is_alertable();
                if now_alertable {
                    return Some(CampaignMatch {
                        new_email_id: metadata.email_id.clone(),
                        group: group.clone(),
                        newly_alertable: !was_alertable && now_alertable,
                    });
                }
                // auth_partial_fail の場合は unknown: バケットにも追記して将来の相関に使う
                // (新規攻撃キャンペーンでも両方のグルーピングを維持する)
            }
            // 未知ドメインでも unknown: バケットに記録 (将来のインフラ特定に備える)。
            // 以前は or_insert_with の返り値を捨てており、同一未解決ドメインからの
            // 2通目以降が email_ids/threat_score/last_updated に一切反映されず、
            // 継続キャンペーンの蓄積が機能していなかった (pattern_key 分岐と同じ
            // 「挿入または取得 → add_email」の形に揃える)。
            let key = format!("unknown:{}", metadata.from_domain);
            let group = self
                .groups
                .entry(key.clone())
                .or_insert_with(|| CampaignGroup::new(key, &metadata.email_id));
            group.add_email(&metadata.email_id);
            None
        }
    }

    /// 全アクティブグループを返す。
    #[must_use]
    pub fn groups(&self) -> Vec<&CampaignGroup> {
        self.groups.values().collect()
    }

    /// 警告レベルのグループのみを返す (3 通以上、またはユーザー報告あり)。
    #[must_use]
    pub fn alertable_groups(&self) -> Vec<&CampaignGroup> {
        self.groups.values().filter(|g| g.is_alertable()).collect()
    }

    /// 期限切れグループと dedup エントリを削除する。
    ///
    /// `seen_emails` も同じ保持期間で退避することで、ユニークな `email_id` による
    /// メール爆撃で dedup セットが無限肥大化する (メモリ `DoS`) のを防ぐ。
    fn evict_expired(&mut self) {
        let cutoff = now_unix().saturating_sub(self.retention.as_secs());
        self.groups.retain(|_, g| g.last_updated_unix >= cutoff);
        self.seen_emails.retain(|_, ts| *ts >= cutoff);
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
/// 件名長バケットをキー文字列に変換する (内部関数)。
fn pattern_key_for_bucket(bucket: SubjectLengthBucket) -> &'static str {
    match bucket {
        SubjectLengthBucket::VeryShort => "veryshort",
        SubjectLengthBucket::Short => "short",
        SubjectLengthBucket::Medium => "medium",
        SubjectLengthBucket::Long => "long",
        SubjectLengthBucket::VeryLong => "verylong",
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(unused_must_use, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn email(id: &str, from: &str) -> EmailMetadata {
        EmailMetadata {
            email_id: id.to_string(),
            from_domain: from.to_string(),
            subject_length_bucket: SubjectLengthBucket::Medium,
            auth_partial_fail: false,
        }
    }

    /// 認証失敗パターンを持つメール (構造パターンクラスタ経路)。
    fn auth_fail_email(id: &str, from: &str) -> EmailMetadata {
        EmailMetadata {
            auth_partial_fail: true,
            ..email(id, from)
        }
    }

    #[test]
    fn single_email_no_match() {
        let mut r = CampaignRadar::new();
        let result = r.analyze(&email("e1", "sender.com"));
        assert!(result.is_none(), "最初の 1 通でマッチしないはず");
    }

    #[test]
    fn same_domain_emails_share_group() {
        // 同一送信ドメインのメールは unknown:<domain> バケットに集約される
        let mut r = CampaignRadar::new();
        r.analyze(&email("e1", "attacker.com"));
        r.analyze(&email("e2", "attacker.com"));
        let g = r.groups();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].shared_infrastructure, "unknown:attacker.com");
        assert_eq!(g[0].email_ids.len(), 2);
    }

    #[test]
    fn unknown_bucket_never_returns_match() {
        // unknown: バケットは analyze の戻り値を返さない (alertable_groups で観測)
        let mut r = CampaignRadar::new();
        for i in 0..3 {
            let result = r.analyze(&email(&format!("e{i}"), "attacker.com"));
            assert!(
                result.is_none(),
                "unknown バケットは CampaignMatch を返さない"
            );
        }
        assert_eq!(r.alertable_groups().len(), 1, "3 通でアラート対象になる");
    }

    #[test]
    fn auth_fail_pattern_becomes_alertable_at_third_email() {
        let mut r = CampaignRadar::new();
        r.analyze(&auth_fail_email("e1", "x.com"));
        r.analyze(&auth_fail_email("e2", "y.com"));
        let result = r.analyze(&auth_fail_email("e3", "z.com"));
        let m = result.expect("3 通目の構造パターン一致でマッチするはず");
        assert!(m.group.is_alertable(), "3 通でアラートレベルに達するはず");
        assert!(m.newly_alertable, "新たにアラートレベルに達したはず");
        assert_eq!(m.group.email_ids.len(), 3);
        assert!(m
            .group
            .shared_infrastructure
            .starts_with("pattern:auth_fail:"));
    }

    #[test]
    fn threat_score_increases_with_count() {
        let mut r = CampaignRadar::new();
        r.analyze(&email("e1", "attacker.com"));
        let score_1 = r.groups()[0].threat_score;
        r.analyze(&email("e2", "attacker.com"));
        let score_2 = r.groups()[0].threat_score;
        assert!(
            score_2 > score_1,
            "メール数増加でスコアが上がるはず: {score_2} > {score_1}"
        );
    }

    #[test]
    fn threat_score_capped_at_1() {
        let mut r = CampaignRadar::new();
        for i in 0..10 {
            r.analyze(&email(&format!("e{i}"), "attacker.com"));
        }
        let groups = r.alertable_groups();
        assert!(!groups.is_empty());
        for g in groups {
            assert!(
                g.threat_score <= 1.0,
                "スコアは 1.0 を超えない: {}",
                g.threat_score
            );
        }
    }

    #[test]
    fn duplicate_email_id_ignored() {
        let mut r = CampaignRadar::new();
        r.analyze(&email("e1", "x.com"));
        let result = r.analyze(&email("e1", "x.com"));
        assert!(result.is_none(), "重複 ID は無視されるはず");
        assert_eq!(r.groups()[0].email_ids.len(), 1);
    }

    #[test]
    fn duplicate_does_not_grow_seen_set() {
        let mut r = CampaignRadar::new();
        r.analyze(&email("e1", "x.com"));
        let before = r.seen_emails.len();
        for _ in 0..10 {
            r.analyze(&email("e1", "x.com"));
        }
        assert_eq!(
            r.seen_emails.len(),
            before,
            "重複 ID で dedup セットが肥大化してはならない"
        );
    }

    #[test]
    fn expired_seen_entries_are_evicted() {
        // 保持期間を 0 にし、過去タイムスタンプのエントリが退避されることを確認
        let mut r = CampaignRadar::new();
        r.retention = Duration::from_secs(0);
        r.seen_emails.insert("old".to_string(), 0);
        r.groups.insert(
            "old-group".to_string(),
            CampaignGroup {
                id: "pcr_old".to_string(),
                shared_infrastructure: "old-group".to_string(),
                email_ids: vec!["old".to_string()],
                first_detected_unix: 0,
                last_updated_unix: 0,
                threat_score: 0.5,
            },
        );
        r.analyze(&email("new-1", "x.com"));
        assert!(
            !r.seen_emails.contains_key("old"),
            "古い dedup エントリは退避される"
        );
        assert!(
            r.groups().iter().all(|g| g.id != "pcr_old"),
            "古いグループは退避される"
        );
    }

    #[test]
    fn different_domains_form_separate_groups() {
        let mut r = CampaignRadar::new();
        r.analyze(&email("e1", "a.com"));
        r.analyze(&email("e2", "b.com"));
        assert_eq!(r.groups().len(), 2, "別ドメインは別バケット");
    }

    #[test]
    fn alertable_groups_filtered() {
        let mut r = CampaignRadar::new();
        r.analyze(&email("e1", "attacker.com"));
        assert_eq!(r.alertable_groups().len(), 0, "1 通はアラートなし");
        r.analyze(&email("e2", "attacker.com"));
        assert_eq!(r.alertable_groups().len(), 0, "2 通はアラートなし");
        r.analyze(&email("e3", "attacker.com"));
        assert_eq!(r.alertable_groups().len(), 1, "3 通でアラートグループ出現");
    }

    #[test]
    fn groups_all_returns_all() {
        let mut r = CampaignRadar::new();
        r.analyze(&email("e1", "x.com"));
        r.analyze(&email("e2", "y.com"));
        assert_eq!(r.groups().len(), 2);
    }

    #[test]
    fn duplicate_email_id_does_not_inflate_threat_score() {
        // 同じ email_id を 2 回渡しても threat_score は 1 通分しか計上されない
        let mut g = CampaignGroup::new("pcr_test".to_string(), "e1");
        let score_after_first = g.threat_score;
        g.add_email("e1"); // 重複
        assert_eq!(g.email_ids.len(), 1, "重複 email_id はカウントされない");
        assert!(
            (g.threat_score - score_after_first).abs() < f32::EPSILON,
            "重複追加でスコアが変わらない"
        );
    }

    #[test]
    fn radar_group_id_has_pcr_prefix() {
        let mut r = CampaignRadar::new();
        r.analyze(&email("e1", "x.com"));
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

    fn arb_email(id: &str, domain_tag: &str) -> EmailMetadata {
        EmailMetadata {
            email_id: id.to_string(),
            from_domain: format!("sender-{domain_tag}.com"),
            subject_length_bucket: SubjectLengthBucket::Medium,
            auth_partial_fail: false,
        }
    }

    proptest! {
        /// 不変条件: 重複メール ID は無視される
        #[test]
        fn duplicate_emails_ignored(n in 2usize..10) {
            let mut radar = CampaignRadar::new();
            for _ in 0..n {
                radar.analyze(&arb_email("same-id", "test"));
            }
            for g in radar.groups() {
                prop_assert!(g.email_ids.len() <= 1,
                    "重複IDが処理されている: {} 件", g.email_ids.len());
            }
        }

        /// 不変条件: threat_score は常に 0.0-1.0
        #[test]
        fn threat_score_always_valid(n in 1usize..20) {
            let mut radar = CampaignRadar::new();
            for i in 0..n {
                radar.analyze(&arb_email(&format!("id-{i}"), &format!("d{i}")));
            }
            for g in radar.groups() {
                prop_assert!(
                    g.threat_score >= 0.0 && g.threat_score <= 1.0,
                    "threat_score 範囲外: {}", g.threat_score
                );
            }
        }
    }
}
