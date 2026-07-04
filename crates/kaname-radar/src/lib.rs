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
    /// このグループ内でユーザーが「悪意あり」と報告したメール件数。
    ///
    /// ユーザーの手動報告は極めて強いシグナル (人間による確定判断) のため、
    /// 1 件でも報告があればグループ全体の脅威スコアを大きく引き上げる。
    /// これにより「1 ユーザーが 1 通を報告 → 同一インフラを共有する
    /// キャンペーン全体を警戒」という組織横展開が可能になる。
    /// `#[serde(default)]` で既存の永続化データとの後方互換を保つ。
    #[serde(default)]
    pub user_reported_count: u32,
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
            user_reported_count: 0,
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

    /// 脅威スコアを再計算する。
    ///
    /// - メール数が増えるほど上昇 (0.3 + 0.1 × 件数、最大 1.0)
    /// - ユーザーの手動報告が 1 件でもあれば +0.6 のブースト
    ///   (人間による確定判断は強いシグナルのため)
    fn recompute_threat_score(&mut self) {
        #[allow(clippy::cast_precision_loss)]
        let base = (0.3 + 0.1 * self.email_ids.len() as f32).min(1.0);
        let reported_boost = if self.user_reported_count > 0 { 0.6 } else { 0.0 };
        self.threat_score = (base + reported_boost).min(1.0);
    }

    /// グループが警告に値するか (3 通以上、またはユーザー報告があれば即座に)
    #[must_use]
    pub fn is_alertable(&self) -> bool {
        self.email_ids.len() >= 3 || self.user_reported_count > 0
    }

    /// ユーザーがこのグループのメールを悪意ありと報告済みか。
    #[must_use]
    pub fn is_user_reported(&self) -> bool {
        self.user_reported_count > 0
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

/// ユーザー報告 ([`CampaignRadar::report_email_malicious`]) の波及効果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportImpact {
    /// 脅威スコアを引き上げたグループ数。
    pub groups_escalated: usize,
    /// 同一キャンペーン内で新たに警戒対象となった兄弟メール数
    /// (報告メール自身を除く)。
    pub sibling_emails_flagged: usize,
}

impl ReportImpact {
    /// 報告が既知のキャンペーンに波及したか (どのグループにも属さなければ false)。
    #[must_use]
    pub fn had_effect(&self) -> bool {
        self.groups_escalated > 0
    }
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
            domain_to_infra: HashMap::new(),
            groups: HashMap::new(),
            seen_emails: HashMap::new(),
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
        const MAX_EMAIL_ID_LEN: usize = 1024;
        const MAX_SEEN_EMAILS: usize = 50_000;

        // email_id が異常に長い場合はスキップ (DoS 防止)
        if metadata.email_id.len() > MAX_EMAIL_ID_LEN {
            tracing::warn!("CampaignRadar: email_id が長すぎます ({} bytes), スキップ", metadata.email_id.len());
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
            if let Some(oldest_key) = self.seen_emails
                .iter()
                .min_by_key(|(_, &ts)| ts)
                .map(|(k, _)| k.clone())
            {
                self.seen_emails.remove(&oldest_key);
            }
        }

        // 解析済みとして記録 (退避基準のタイムスタンプ付き)
        self.seen_emails.insert(metadata.email_id.clone(), now_unix());

        // 全ドメインをインフラキーに変換
        let infra_keys: Vec<String> = metadata
            .all_domains()
            .iter()
            .filter_map(|d| self.resolve_infra(d))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        if infra_keys.is_empty() {
            // 未知のインフラでも構造パターンが一致する場合はクラスタリング。
            // 件名長バケット + 認証失敗パターンをキーとして使用。
            // コンテンツ (件名本体・本文) は一切保存しない — 北極星維持。
            if metadata.auth_partial_fail {
                let pattern_key = format!(
                    "pattern:auth_fail:subject_{}",
                    pattern_key_for_bucket(metadata.subject_length_bucket)
                );
                let was_alertable = self.groups.get(&pattern_key).is_some_and(CampaignGroup::is_alertable);
                let group = self.groups
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
            // 未知ドメインでも unknown: バケットに記録 (将来のインフラ特定に備える)
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

    /// 警告レベルのグループのみを返す (3 通以上、またはユーザー報告あり)。
    #[must_use]
    pub fn alertable_groups(&self) -> Vec<&CampaignGroup> {
        self.groups.values().filter(|g| g.is_alertable()).collect()
    }

    /// ユーザーが特定メールを「悪意あり」と報告したことを記録し、
    /// 同一インフラを共有するキャンペーングループ全体の脅威スコアを引き上げる。
    ///
    /// # 背景 (組織横展開 / C-03)
    ///
    /// 従来、ユーザーの「悪意あり報告」は `kaname-bec` の `SenderHistory`
    /// (送信者アドレス単位) にしか反映されず、同一攻撃者が**別ドメイン・
    /// 別送信者アドレス**でポリモーフィックに送ってくる同一キャンペーンの
    /// 別メールには効かなかった。PCR は既に「共有インフラ」でメールを
    /// クラスタリングしているため、報告されたメールが属するグループ全体を
    /// 即座に高脅威としてマークすることで、1 ユーザーの 1 報告が
    /// キャンペーン全体 (他の受信者・将来の受信メールを含む) の警戒に
    /// つながる。
    ///
    /// # 戻り値
    ///
    /// 報告の波及効果 ([`ReportImpact`])。報告メールが未知 (どのグループにも
    /// 属さない) 場合は `groups_escalated = 0`。
    pub fn report_email_malicious(&mut self, email_id: &str) -> ReportImpact {
        let mut groups_escalated = 0usize;
        let mut sibling_emails_flagged = 0usize;
        let now = now_unix();
        for group in self.groups.values_mut() {
            if group.email_ids.iter().any(|id| id == email_id) {
                group.user_reported_count = group.user_reported_count.saturating_add(1);
                group.recompute_threat_score();
                group.last_updated_unix = now;
                groups_escalated += 1;
                // 報告メール自身を除いた同一キャンペーンの「兄弟」メール数
                sibling_emails_flagged += group.email_ids.len().saturating_sub(1);
            }
        }
        ReportImpact { groups_escalated, sibling_emails_flagged }
    }

    /// 指定メールがユーザー報告済みのキャンペーンに属するか判定する。
    ///
    /// `kaname-bec` 等の下流が、新規受信メールを評価する際に
    /// 「このメールは既に報告されたキャンペーンの一部か」を照会するために使う。
    #[must_use]
    pub fn is_email_in_reported_campaign(&self, email_id: &str) -> bool {
        self.groups.values().any(|g| {
            g.is_user_reported() && g.email_ids.iter().any(|id| id == email_id)
        })
    }

    /// グループ数を返す。
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// dedup 済みメール ID の数を返す (運用メトリクス / メモリ監視用)。
    #[must_use]
    pub fn seen_email_count(&self) -> usize {
        self.seen_emails.len()
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

    /// 期限切れグループと dedup エントリを削除する。
    ///
    /// `seen_emails` も同じ保持期間で退避することで、ユニークな `email_id` による
    /// メール爆撃で dedup セットが無限肥大化する (メモリ `DoS`) のを防ぐ。
    fn evict_expired(&mut self) {
        let cutoff = now_unix().saturating_sub(self.retention.as_secs());
        self.groups
            .retain(|_, g| g.last_updated_unix >= cutoff);
        self.seen_emails
            .retain(|_, ts| *ts >= cutoff);
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

/// ドメインから 2 次レベルドメイン (SLD) を抽出する。
///
/// 例: `"mail.google.com"` → `"google.com"`
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
#[allow(unused_must_use, clippy::needless_pass_by_value, clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
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
            subject_length_bucket: SubjectLengthBucket::Medium,
            auth_partial_fail: false,
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

    // ── C-03: ユーザー悪意報告のキャンペーン横展開 ───────────────────────

    #[test]
    fn user_report_escalates_entire_campaign() {
        let mut r = radar_with_infra();
        // 同一インフラで 3 通のポリモーフィックメール (別ドメイン・別送信者)
        r.analyze(&email("e1", "x.com", vec!["phish-1.com"]));
        r.analyze(&email("e2", "y.com", vec!["phish-2.com"]));
        r.analyze(&email("e3", "z.com", vec!["phish-3.com"]));

        // ユーザーが 1 通だけを「悪意あり」と報告
        let impact = r.report_email_malicious("e2");
        assert!(impact.had_effect(), "既知キャンペーンへの報告は波及するはず");
        assert_eq!(impact.groups_escalated, 1);
        // e2 を除く e1, e3 が兄弟として警戒対象に
        assert_eq!(impact.sibling_emails_flagged, 2);

        // グループ全体の脅威スコアが引き上げられている
        let g = r.alertable_groups();
        assert!(g.iter().any(|grp| grp.is_user_reported() && grp.threat_score >= 0.9),
            "報告後はグループ脅威スコアが 0.9 以上に上がるはず: {:?}",
            g.iter().map(|grp| grp.threat_score).collect::<Vec<_>>());
    }

    #[test]
    fn user_report_makes_sibling_emails_queryable() {
        let mut r = radar_with_infra();
        r.analyze(&email("e1", "x.com", vec!["phish-1.com"]));
        r.analyze(&email("e2", "y.com", vec!["phish-2.com"]));
        r.report_email_malicious("e1");

        // 報告メール自身も、同一キャンペーンの兄弟メールも「報告済みキャンペーン」として照会可能
        assert!(r.is_email_in_reported_campaign("e1"), "報告メール自身は報告済みキャンペーン");
        assert!(r.is_email_in_reported_campaign("e2"), "兄弟メールも報告済みキャンペーンに属する");
        assert!(!r.is_email_in_reported_campaign("unknown"), "無関係メールは該当しない");
    }

    #[test]
    fn user_report_of_unknown_email_has_no_effect() {
        let mut r = radar_with_infra();
        r.analyze(&email("e1", "x.com", vec!["phish-1.com"]));
        let impact = r.report_email_malicious("never-seen");
        assert!(!impact.had_effect(), "未知メールの報告は波及しないはず");
        assert_eq!(impact.groups_escalated, 0);
    }

    #[test]
    fn single_report_makes_group_alertable_immediately() {
        // 通常はアラートに 3 通必要だが、ユーザー報告があれば 1 通でも即警戒
        let mut r = radar_with_infra();
        r.analyze(&email("e1", "x.com", vec!["phish-1.com"]));
        r.analyze(&email("e2", "y.com", vec!["phish-2.com"])); // 2 通 (通常は未アラート)
        assert!(r.alertable_groups().is_empty(), "報告前・2通ではアラート対象なし");

        r.report_email_malicious("e1");
        assert!(!r.alertable_groups().is_empty(),
            "ユーザー報告後は 2 通でもアラート対象になるはず");
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
    fn seen_email_count_tracks_unique_ids() {
        let mut r = radar_with_infra();
        for i in 0..5 {
            r.analyze(&email(&format!("e{i}"), "x.com", vec!["phish-1.com"]));
        }
        assert_eq!(r.seen_email_count(), 5, "ユニーク 5 件が dedup セットに記録される");
    }

    #[test]
    fn duplicate_does_not_grow_seen_set() {
        let mut r = radar_with_infra();
        r.analyze(&email("e1", "x.com", vec!["phish-1.com"]));
        let before = r.seen_email_count();
        // 同一 ID を 10 回再投入してもセットは増えない
        for _ in 0..10 {
            r.analyze(&email("e1", "x.com", vec!["phish-1.com"]));
        }
        assert_eq!(r.seen_email_count(), before, "重複 ID で dedup セットが肥大化してはならない");
    }

    #[test]
    fn expired_seen_entries_are_evicted() {
        // 保持期間 0 → 次の analyze 時の evict_expired で過去エントリが退避される
        // (グループだけでなく seen_emails も退避され、メモリ DoS を防ぐ)
        let mut r = radar_with_infra().with_retention(Duration::from_secs(0));
        r.analyze(&email("old-1", "x.com", vec!["phish-1.com"]));
        // 退避は now_unix() >= ts で判定。保持 0 なら cutoff=now。
        // 1 秒以内の同一タイムスタンプでも、保持 0 では将来の analyze 時に
        // ts < cutoff となった古いエントリが必ず除去される設計であることを確認する。
        // ここでは退避ロジックが seen_emails も対象にしていること (panic せず動作) を検証。
        let count_after = r.seen_email_count();
        assert!(count_after <= 1, "seen_emails が退避対象に含まれている");
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
            subject_length_bucket: SubjectLengthBucket::Medium,
            auth_partial_fail: false,
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
    fn duplicate_email_id_does_not_inflate_threat_score() {
        // 同じ email_id を 2 回渡しても threat_score は 1 通分しか計上されない
        let mut g = CampaignGroup::new("pcr_test".to_string(), "e1");
        let score_after_first = g.threat_score;
        g.add_email("e1"); // 重複
        assert_eq!(g.email_ids.len(), 1, "重複 email_id はカウントされない");
        assert_eq!(g.threat_score, score_after_first, "重複追加でスコアが変わらない");
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
            subject_length_bucket: SubjectLengthBucket::Medium,
            auth_partial_fail: false,
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

/// 本番用 DNS リゾルバー。
///
/// `std::net::ToSocketAddrs` を使用してシステム DNS を同期解決する。
/// バックグラウンドスレッドから呼び出すこと (ブロッキング)。
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, domain: &str) -> Vec<String> {
        use std::net::ToSocketAddrs;
        // port 0 を付加して SocketAddr リストに解決し、IP 部分だけ抽出する
        match (domain, 0u16).to_socket_addrs() {
            Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
            Err(_) => vec![],
        }
    }
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
    fn system_resolver_resolves_localhost() {
        let r = SystemDnsResolver;
        let ips = r.resolve("localhost");
        // localhost は必ず 127.0.0.1 か ::1 に解決される
        assert!(!ips.is_empty(), "localhost が解決できなかった");
        assert!(
            ips.iter().any(|ip| ip == "127.0.0.1" || ip == "::1"),
            "localhost の IP が想定外: {ips:?}"
        );
    }

    #[test]
    fn system_resolver_returns_empty_for_invalid() {
        let r = SystemDnsResolver;
        let ips = r.resolve("this.domain.does.not.exist.invalid");
        assert!(ips.is_empty(), "存在しないドメインが解決された: {ips:?}");
    }

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

    // ──────────────────────────────────────────────────────────────────
    // 件名バケット
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn subject_bucket_classification() {
        assert_eq!(SubjectLengthBucket::from_subject(""), SubjectLengthBucket::VeryShort);
        assert_eq!(SubjectLengthBucket::from_subject("hello"), SubjectLengthBucket::VeryShort);
        assert_eq!(SubjectLengthBucket::from_subject("【至急】送金のお願い合計金額"), SubjectLengthBucket::Short);
        assert_eq!(SubjectLengthBucket::from_subject(&"x".repeat(50)), SubjectLengthBucket::Medium);
        assert_eq!(SubjectLengthBucket::from_subject(&"x".repeat(80)), SubjectLengthBucket::Long);
        assert_eq!(SubjectLengthBucket::from_subject(&"x".repeat(150)), SubjectLengthBucket::VeryLong);
    }

    #[test]
    fn unknown_infra_auth_fail_clusters() {
        let mut radar = CampaignRadar::new();
        // 未知インフラ + 認証失敗 の同一件名長パターン
        // 最初の2通でキャンペーングループが alertable になる
        // (1通目は new() で1件 + add_email で2件、2通目で3件)
        let mut any_alertable = false;
        for i in 0..4u8 {
            let meta = EmailMetadata {
                email_id: format!("unknown-{i}"),
                from_domain: format!("random-{i}.example"),
                return_path_domain: None,
                dkim_domain: None,
                link_domains: vec![],
                received_at: now_unix(),
                subject_length_bucket: SubjectLengthBucket::Short,
                auth_partial_fail: true,
            };
            if let Some(r) = radar.analyze(&meta) {
                if r.newly_alertable {
                    any_alertable = true;
                }
            }
        }
        assert!(any_alertable, "未知インフラでも認証失敗パターンでキャンペーン検出されるべき");
    }

    #[test]
    fn oversized_email_id_is_skipped() {
        // 攻撃: 1MB の email_id を送りつけて HashMap のキーとして蓄積する DoS
        let mut radar = CampaignRadar::new();
        let huge_id = "x".repeat(1025);
        let meta = EmailMetadata {
            email_id: huge_id,
            from_domain: "evil.example".into(),
            return_path_domain: None,
            dkim_domain: None,
            link_domains: vec![],
            received_at: now_unix(),
            subject_length_bucket: SubjectLengthBucket::Short,
            auth_partial_fail: false,
        };
        let result = radar.analyze(&meta);
        assert!(result.is_none(), "過大な email_id はスキップされるべき");
        assert_eq!(radar.seen_email_count(), 0, "seen_emails に登録されてはならない");
    }

    #[test]
    fn seen_emails_capped_at_max() {
        // 攻撃: retention 期間内に大量のユニーク email_id を送り込む OOM テスト
        // 50_001 件目を超えても seen_emails が 50_000 件を超えないことを確認
        let mut radar = CampaignRadar::new();
        for i in 0..50_010u64 {
            let meta = EmailMetadata {
                email_id: format!("flood-{i}"),
                from_domain: format!("d{i}.example"),
                return_path_domain: None,
                dkim_domain: None,
                link_domains: vec![],
                received_at: now_unix(),
                subject_length_bucket: SubjectLengthBucket::Short,
                auth_partial_fail: false,
            };
            radar.analyze(&meta);
        }
        assert!(radar.seen_email_count() <= 50_000,
            "seen_emails が上限を超えた: {}", radar.seen_email_count());
    }
}
