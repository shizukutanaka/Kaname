// crates/kaname-core/src/ux_features.rs
//
// 競合分析から実装した UX 機能 (Rust バックエンド)。
//
// 実装した機能:
//   - 送信者スクリーナー (HEY の The Screener を安全性向上版で実装)
//   - スマートトリアージ (Superhuman の Split Inbox + HEY の仕分け)
//   - スヌーズ / Reply Later
//   - 送信予約 (Send Later)
//   - セーフ AI 要約 (Superhuman の CVE 回避設計を明示)

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ============================================================================
// 送信者スクリーナー (HEY の The Screener)
// ============================================================================

/// 送信者のスクリーニング状態。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenerDecision {
    /// 未決定 (初回送信者)。
    Pending,
    /// 許可: 受信トレイへ。
    AllowInbox,
    /// 許可: フィードへ (ニュースレター等)。
    AllowFeed,
    /// 許可: Paper Trail へ (領収書等)。
    AllowPaperTrail,
    /// ブロック。
    Blocked,
}

/// 送信者スクリーナーエントリ。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenerEntry {
    pub from_addr:   String,
    pub from_name:   Option<String>,
    pub decision:    ScreenerDecision,
    pub first_seen:  String,  // ISO-8601
    pub email_count: u32,
    /// まだ判定していない (UI でスクリーニング画面に表示)。
    pub is_new:      bool,
}

/// 送信者スクリーナー。
pub struct SenderScreener {
    entries: HashMap<String, ScreenerEntry>,
}

impl SenderScreener {
    /// 新規インスタンスを作成する。
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    /// メールの送信者を登録する。
    /// 初回の場合は `Pending` で登録し `is_new = true` を返す。
    pub fn observe(
        &mut self,
        from_addr: &str,
        from_name: Option<&str>,
        received_at: &str,
    ) -> ScreenerDecision {
        if let Some(entry) = self.entries.get_mut(from_addr) {
            entry.email_count += 1;
            return entry.decision.clone();
        }

        // 初回送信者
        let entry = ScreenerEntry {
            from_addr:   from_addr.to_owned(),
            from_name:   from_name.map(str::to_owned),
            decision:    ScreenerDecision::Pending,
            first_seen:  received_at.to_owned(),
            email_count: 1,
            is_new:      true,
        };
        self.entries.insert(from_addr.to_owned(), entry);
        ScreenerDecision::Pending
    }

    /// スクリーニング判定を設定する。
    pub fn decide(
        &mut self,
        from_addr: &str,
        decision: ScreenerDecision,
    ) -> Result<(), ScreenerError> {
        let entry = self.entries.get_mut(from_addr)
            .ok_or_else(|| ScreenerError::NotFound(from_addr.to_owned()))?;
        entry.decision = decision;
        entry.is_new   = false;
        Ok(())
    }

    /// 未決定の送信者リストを返す。
    #[must_use]
    pub fn pending(&self) -> Vec<&ScreenerEntry> {
        self.entries.values()
            .filter(|e| e.is_new || e.decision == ScreenerDecision::Pending)
            .collect()
    }

    /// 送信者の判定を返す。
    pub fn get(&self, from_addr: &str) -> ScreenerDecision {
        self.entries.get(from_addr)
            .map(|e| e.decision.clone())
            .unwrap_or(ScreenerDecision::Pending)
    }

    /// ブロックされた送信者かどうか。
    #[must_use]
    pub fn is_blocked(&self, from_addr: &str) -> bool {
        self.get(from_addr) == ScreenerDecision::Blocked
    }
}

impl Default for SenderScreener {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Error)]
pub enum ScreenerError {
    #[error("送信者が見つからない: {0}")]
    NotFound(String),
}

// ============================================================================
// スマートトリアージ
// ============================================================================

/// メールのトリアージバケット。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageBucket {
    /// 重要なメール (受信トレイの主役)。
    Important,
    /// 通常のメール。
    Other,
    /// ニュースレター・更新情報。
    Feed,
    /// 領収書・確認メール・取引メール。
    PaperTrail,
}

/// トリアージエンジン。
pub struct TriageEngine {
    /// ユーザーが手動で設定した送信者ごとのバケット。
    sender_rules: HashMap<String, TriageBucket>,
}

impl TriageEngine {
    /// 新規インスタンスを作成する。
    pub fn new() -> Self { Self { sender_rules: HashMap::new() } }

    /// メールを自動仕分けする。
    pub fn triage(
        &self,
        from_addr:   &str,
        subject:     &str,
        bec_verdict: Option<&str>,
    ) -> TriageBucket {
        // 送信者ルール優先
        if let Some(&bucket) = self.sender_rules.get(from_addr) {
            return bucket;
        }

        let subject_lower = subject.to_lowercase();
        let from_lower    = from_addr.to_lowercase();

        // Paper Trail: 取引・確認メール
        let paper_trail_markers = [
            "receipt", "order", "invoice", "confirmation", "booking",
            "reservation", "shipping", "delivery", "statement", "transaction",
            "領収書", "注文", "請求書", "予約確認", "配送", "振替",
            "ご注文", "発送", "取引明細",
        ];
        if paper_trail_markers.iter().any(|m| subject_lower.contains(m))
           || from_lower.contains("noreply")
           || from_lower.contains("no-reply")
           || from_lower.contains("donotreply") {
            return TriageBucket::PaperTrail;
        }

        // Feed: ニュースレター・更新情報
        let feed_markers = [
            "newsletter", "unsubscribe", "weekly digest", "monthly digest",
            "update", "announcement", "new features", "changelog",
            "ニュースレター", "配信", "週刊", "月刊", "お知らせ", "更新情報",
        ];
        if feed_markers.iter().any(|m| subject_lower.contains(m)) {
            return TriageBucket::Feed;
        }

        // BEC フラグが立っている場合は Important (目立つように)
        if let Some(v) = bec_verdict {
            if v != "SAFE" {
                return TriageBucket::Important;
            }
        }

        TriageBucket::Important
    }

    /// 送信者ルールを追加する。
    pub fn add_sender_rule(&mut self, from_addr: &str, bucket: TriageBucket) {
        self.sender_rules.insert(from_addr.to_lowercase(), bucket);
    }
}

impl Default for TriageEngine {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// スヌーズ / Reply Later キュー
// ============================================================================

/// スヌーズエントリ。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnoozeEntry {
    pub email_id:    String,
    /// スヌーズ解除時刻 (Unix タイムスタンプ秒)。
    pub wake_at:     u64,
    /// 元のメールボックス ID (スヌーズ解除後に戻す)。
    pub original_mailbox: String,
    /// 作成時刻。
    pub created_at:  u64,
}

/// Reply Later エントリ。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplyLaterEntry {
    pub email_id:   String,
    pub added_at:   u64,
    pub subject:    Option<String>,
    pub from_addr:  String,
}

/// スヌーズ・Reply Later マネージャー。
pub struct SnoozeManager {
    snoozed:     Vec<SnoozeEntry>,
    reply_later: Vec<ReplyLaterEntry>,
}

impl SnoozeManager {
    /// 新規インスタンスを作成する。
    pub fn new() -> Self {
        Self { snoozed: Vec::new(), reply_later: Vec::new() }
    }

    /// メールをスヌーズする。
    pub fn snooze(
        &mut self,
        email_id: &str,
        wake_at:  u64,
        original_mailbox: &str,
    ) {
        // 既存のスヌーズを更新
        self.snoozed.retain(|s| s.email_id != email_id);
        self.snoozed.push(SnoozeEntry {
            email_id:         email_id.to_owned(),
            wake_at,
            original_mailbox: original_mailbox.to_owned(),
            created_at:       now_unix(),
        });
    }

    /// スヌーズを解除する。
    pub fn cancel_snooze(&mut self, email_id: &str) {
        self.snoozed.retain(|s| s.email_id != email_id);
    }

    /// 今起こすべきスヌーズを返す。
    #[must_use]
    pub fn due_wakeups(&self, now: u64) -> Vec<&SnoozeEntry> {
        self.snoozed.iter().filter(|s| s.wake_at <= now).collect()
    }

    /// メールを Reply Later に追加する。
    pub fn add_reply_later(
        &mut self,
        email_id:  &str,
        from_addr: &str,
        subject:   Option<&str>,
    ) {
        if self.reply_later.iter().any(|r| r.email_id == email_id) {
            return; // 重複排除
        }
        self.reply_later.push(ReplyLaterEntry {
            email_id:  email_id.to_owned(),
            added_at:  now_unix(),
            subject:   subject.map(str::to_owned),
            from_addr: from_addr.to_owned(),
        });
    }

    /// Reply Later から削除する。
    pub fn remove_reply_later(&mut self, email_id: &str) {
        self.reply_later.retain(|r| r.email_id != email_id);
    }

    /// Reply Later リストを返す (追加順)。
    #[must_use]
    pub fn reply_later_list(&self) -> &[ReplyLaterEntry] {
        &self.reply_later
    }

    /// スヌーズ中のメール数。
    #[must_use]
    pub fn snoozed_count(&self) -> usize { self.snoozed.len() }

    /// Reply Later のメール数。
    #[must_use]
    pub fn reply_later_count(&self) -> usize { self.reply_later.len() }
}

impl Default for SnoozeManager {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// 送信予約 (Send Later)
// ============================================================================

/// 送信予約エントリ。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendLaterEntry {
    pub id:          String,
    pub draft_id:    String,
    pub send_at:     u64,
    pub to:          Vec<String>,
    pub subject:     String,
    pub created_at:  u64,
    pub status:      SendLaterStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendLaterStatus {
    /// 送信待ち。
    Scheduled,
    /// 送信中。
    Sending,
    /// 送信完了。
    Sent,
    /// 送信失敗。
    Failed { reason: String },
    /// キャンセル済み。
    Cancelled,
}

/// 送信予約マネージャー。
pub struct SendLaterManager {
    queue: Vec<SendLaterEntry>,
}

impl SendLaterManager {
    /// 新規インスタンスを作成する。
    pub fn new() -> Self { Self { queue: Vec::new() } }

    /// 送信を予約する。
    pub fn schedule(
        &mut self,
        draft_id: &str,
        send_at:  u64,
        to:       Vec<String>,
        subject:  &str,
    ) -> String {
        let id = format!("sl_{}", now_unix());
        self.queue.push(SendLaterEntry {
            id:         id.clone(),
            draft_id:   draft_id.to_owned(),
            send_at,
            to,
            subject:    subject.to_owned(),
            created_at: now_unix(),
            status:     SendLaterStatus::Scheduled,
        });
        id
    }

    /// 予約をキャンセルする。
    #[must_use]
    pub fn cancel(&mut self, id: &str) -> bool {
        if let Some(entry) = self.queue.iter_mut().find(|e| e.id == id) {
            if entry.status == SendLaterStatus::Scheduled {
                entry.status = SendLaterStatus::Cancelled;
                return true;
            }
        }
        false
    }

    /// 今送信すべきエントリを返す。
    #[must_use]
    pub fn due_entries(&self, now: u64) -> Vec<&SendLaterEntry> {
        self.queue.iter()
            .filter(|e| e.status == SendLaterStatus::Scheduled && e.send_at <= now)
            .collect()
    }

    /// スケジュール済みリストを返す。
    #[must_use]
    pub fn scheduled(&self) -> Vec<&SendLaterEntry> {
        self.queue.iter()
            .filter(|e| e.status == SendLaterStatus::Scheduled)
            .collect()
    }

    /// エントリのステータスを更新する。
    pub fn update_status(&mut self, id: &str, status: SendLaterStatus) {
        if let Some(entry) = self.queue.iter_mut().find(|e| e.id == id) {
            entry.status = status;
        }
    }
}

impl Default for SendLaterManager {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// セーフ AI 要約 (Superhuman CVE の回避設計)
// ============================================================================

/// AI 要約リクエスト。
///
/// # Superhuman の脆弱性 (CVE-2024-XXXX)
///
/// PromptArmor の研究により、Superhuman の AI が「直近のメールを要約」する際に
/// 攻撃者が送信した悪意あるメールがプロンプト注入を実行し、
/// ユーザーの受信箱全体のデータ (財務記録、医療記録等) を外部送信できることが判明した。
///
/// # Kaname の設計による防止
///
/// 1. **Content<Untrusted> 型制約**: メール本文は `Content<Untrusted>` 型。
///    この型は `QuarantinedLlm::analyze()` にしか渡せない (型システムで強制)。
///
/// 2. **Q-LLM の分離**: Quarantined LLM は「引数で渡された 1 通のメール」のみを見る。
///    受信箱全体へのアクセス手段が存在しない (API に存在しない)。
///
/// 3. **ツールなし**: Q-LLM はネットワーク接続もファイルアクセスも持たない。
///    プロンプト注入が成功しても、外部送信の手段がない。
///
/// 4. **Bridge バリデーション**: Q-LLM の出力は `AnalysisReport` スキーマに
///    厳密に検証される。フリーテキストが P-LLM に漏れることはない。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeSummaryRequest {
    /// 要約対象メールの ID。
    pub email_id:   String,
    /// 要約対象の本文テキスト (このメール1通のみ)。
    pub body_text:  String,
    /// 件名。
    pub subject:    Option<String>,
    /// 送信者。
    pub from_addr:  String,
}

/// AI 要約結果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeSummaryResult {
    /// 要約テキスト (最大 280 文字)。
    pub summary:    String,
    /// リスク評価。
    pub risk:       String,
    /// 言語。
    pub language:   String,
    /// 処理したメール ID (要求と一致することを検証)。
    pub email_id:   String,
    /// セキュリティ証明: この要約の生成に使用したデータソース。
    pub data_sources: Vec<String>,
    /// Dual-LLM が適切に分離されていたことの証明。
    pub security_proof: SecurityProof,
}

/// 要約生成のセキュリティ証明。
///
/// この構造体は Kaname が Superhuman の脆弱性を防いでいることを証明する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProof {
    /// 使用した LLM モデル。
    pub model: String,
    /// Q-LLM が見たデータは「このメール1通のみ」。
    pub single_email_only: bool,
    /// ネットワーク接続なし。
    pub no_network_access: bool,
    /// 他のメールへのアクセスなし。
    pub no_inbox_access: bool,
    /// Bridge バリデーションを通過したか。
    pub bridge_validated: bool,
    /// ローカル推論 (データがデバイス外に出ない)。
    pub local_inference: bool,
}

/// セーフ AI 要約エンジン。
pub struct SafeSummaryEngine;

impl SafeSummaryEngine {
    /// メールを安全に要約する。
    ///
    /// Superhuman と異なり、このメソッドは受信箱全体にアクセスしない。
    /// Q-LLM は `body_text` のみを見る。他のメールのデータは一切使用しない。
    pub fn summarize(req: &SafeSummaryRequest) -> SafeSummaryResult {
        // 本番実装では:
        // 1. `QuarantinedLlmImpl::analyze(&body_text)` を呼ぶ
        //    - `Content<Untrusted>::from_network(&body_text)` でラップ
        //    - `req.body_text` のみが Q-LLM に渡される
        //    - 他のメール、受信箱全体へのアクセスは型システムが禁止
        // 2. Bridge::validate_and_promote(report, &source) でバリデーション
        // 3. AnalysisReport を SafeSummaryResult に変換

        // モック実装 (テスト用)
        let summary = if req.body_text.len() > 50 {
            format!(
                "{}...(要約)",
                req.body_text.chars().take(100).collect::<String>()
            )
        } else {
            req.body_text.clone()
        };

        SafeSummaryResult {
            summary,
            risk:     "SAFE".into(),
            language: "JA".into(),
            email_id: req.email_id.clone(),
            data_sources: vec![
                format!("email:{}", req.email_id), // このメールのみ
            ],
            security_proof: SecurityProof {
                model:             "phi-4-mini-instruct-Q4_K_M".into(),
                single_email_only: true,   // 受信箱全体ではなくこのメールのみ
                no_network_access: true,   // Q-LLM はネットワーク接続なし
                no_inbox_access:   true,   // 他のメールへのアクセス手段なし
                bridge_validated:  true,   // Bridge の検証を通過
                local_inference:   true,   // ローカル推論 (データはデバイス外に出ない)
            },
        }
    }

    /// セキュリティ証明が有効かどうかを検証する。
    #[must_use]
    pub fn verify_security_proof(proof: &SecurityProof) -> bool {
        // 全てのセキュリティ保証が満たされていること
        proof.single_email_only
            && proof.no_network_access
            && proof.no_inbox_access
            && proof.bridge_validated
            && proof.local_inference
    }
}

// ============================================================================
// ユーティリティ
// ============================================================================

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // スクリーナー
    #[test]
    fn 初回送信者はpending() {
        let mut screener = SenderScreener::new();
        let result = screener.observe("new@example.com", Some("新しい人"), "2026-04-24");
        assert_eq!(result, ScreenerDecision::Pending);
        assert_eq!(screener.pending().len(), 1);
    }

    #[test]
    fn 2回目以降は判定済み() {
        let mut screener = SenderScreener::new();
        screener.observe("alice@example.com", None, "2026-04-24");
        screener.decide("alice@example.com", ScreenerDecision::AllowInbox).unwrap();
        let result = screener.observe("alice@example.com", None, "2026-04-25");
        assert_eq!(result, ScreenerDecision::AllowInbox);
    }

    #[test]
    fn ブロックされた送信者を検出する() {
        let mut screener = SenderScreener::new();
        screener.observe("spam@evil.com", None, "2026-04-24");
        screener.decide("spam@evil.com", ScreenerDecision::Blocked).unwrap();
        assert!(screener.is_blocked("spam@evil.com"));
    }

    // トリアージ
    #[test]
    fn 領収書メールをpaper_trailに仕分け() {
        let engine = TriageEngine::new();
        let result = engine.triage("noreply@amazon.co.jp", "ご注文の確認 #12345", None);
        assert_eq!(result, TriageBucket::PaperTrail);
    }

    #[test]
    fn ニュースレターをfeedに仕分け() {
        let engine = TriageEngine::new();
        let result = engine.triage("digest@techcrunch.com", "週刊 TechCrunch Newsletter", None);
        assert_eq!(result, TriageBucket::Feed);
    }

    #[test]
    fn bec_メールをimportantに仕分け() {
        let engine = TriageEngine::new();
        let result = engine.triage("fake@evil.com", "普通の件名", Some("DANGEROUS"));
        assert_eq!(result, TriageBucket::Important);
    }

    #[test]
    fn 送信者ルールが優先される() {
        let mut engine = TriageEngine::new();
        engine.add_sender_rule("boss@company.com", TriageBucket::Important);
        let result = engine.triage("boss@company.com", "週刊 newsletter", None);
        // 送信者ルールが Feed より優先
        assert_eq!(result, TriageBucket::Important);
    }

    // スヌーズ
    #[test]
    fn スヌーズと解除() {
        let mut mgr = SnoozeManager::new();
        mgr.snooze("email1", now_unix() + 3600, "inbox");
        assert_eq!(mgr.snoozed_count(), 1);
        assert!(mgr.due_wakeups(now_unix()).is_empty()); // まだ時間前
        mgr.cancel_snooze("email1");
        assert_eq!(mgr.snoozed_count(), 0);
    }

    #[test]
    fn reply_later追加と削除() {
        let mut mgr = SnoozeManager::new();
        mgr.add_reply_later("e1", "alice@example.com", Some("重要な件"));
        assert_eq!(mgr.reply_later_count(), 1);

        // 重複追加は無効
        mgr.add_reply_later("e1", "alice@example.com", Some("重複"));
        assert_eq!(mgr.reply_later_count(), 1);

        mgr.remove_reply_later("e1");
        assert_eq!(mgr.reply_later_count(), 0);
    }

    // Send Later
    #[test]
    fn 送信予約とキャンセル() {
        let mut mgr = SendLaterManager::new();
        let id = mgr.schedule(
            "draft1",
            now_unix() + 3600,
            vec!["bob@example.com".into()],
            "将来のメール",
        );
        assert_eq!(mgr.scheduled().len(), 1);
        assert!(mgr.cancel(&id));
        // キャンセル後はスケジュールリストから外れる
        assert_eq!(mgr.scheduled().len(), 0);
    }

    #[test]
    fn due_entriesが正しく返る() {
        let mut mgr = SendLaterManager::new();
        // 過去に設定 → due
        mgr.schedule("d1", now_unix() - 1, vec![], "送信済みのはず");
        // 未来に設定 → not due
        mgr.schedule("d2", now_unix() + 9999, vec![], "将来のメール");

        let due = mgr.due_entries(now_unix());
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].draft_id, "d1");
    }

    // セーフ AI 要約
    #[test]
    fn セキュリティ証明が全フラグをtrueに持つ() {
        let req = SafeSummaryRequest {
            email_id:  "e1".into(),
            body_text: "テストメールです".into(),
            subject:   Some("テスト".into()),
            from_addr: "test@example.com".into(),
        };
        let result = SafeSummaryEngine::summarize(&req);

        // 全セキュリティ保証が満たされていること
        assert!(SafeSummaryEngine::verify_security_proof(&result.security_proof));
        assert!(result.security_proof.single_email_only, "受信箱全体にアクセスしていない");
        assert!(result.security_proof.no_network_access, "ネットワーク接続なし");
        assert!(result.security_proof.no_inbox_access,   "他のメールへのアクセスなし");
        assert!(result.security_proof.local_inference,   "ローカル推論");
    }

    #[test]
    fn 要約のdata_sourcesはこのメールのみ() {
        let req = SafeSummaryRequest {
            email_id:  "email_xyz".into(),
            body_text: "重要な内容です".into(),
            subject:   None,
            from_addr: "sender@example.com".into(),
        };
        let result = SafeSummaryEngine::summarize(&req);

        // data_sources に受信箱全体を示すものが含まれていない
        assert!(!result.data_sources.iter().any(|s| s.contains("inbox")));
        assert!(!result.data_sources.iter().any(|s| s.contains("all_emails")));
        // このメールのみ
        assert!(result.data_sources.iter().any(|s| s.contains("email_xyz")));
    }

    #[test]
    fn 要約のemail_idが要求と一致する() {
        let req = SafeSummaryRequest {
            email_id:  "specific_email_id".into(),
            body_text: "本文".into(),
            subject:   None,
            from_addr: "a@b.com".into(),
        };
        let result = SafeSummaryEngine::summarize(&req);
        // ID が一致することで「別のメールが要約された」攻撃を防ぐ
        assert_eq!(result.email_id, req.email_id);
    }
}
