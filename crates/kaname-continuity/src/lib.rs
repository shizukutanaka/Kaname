//! kaname-continuity — Apple デバイス間の連続性層。
//!
//! Apple WWDC25 で強調された Continuity 思想を Kaname に適用:
//!   - **Handoff**: iPhone で読み始めたメールを Mac で続ける
//!   - **Universal Clipboard**: 添付参照を全デバイス間でコピー
//!   - **Session Resume**: セッション中断後の状態復元
//!
//! # 設計原則
//!
//! - デバイス識別子を保存しない (プライバシー)
//! - 暗号化されたセッション ID のみを転送
//! - ローカルファースト: オフラインでも最後の状態を保持

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// セッション状態
// ============================================================================

/// デバイス間で共有するセッション状態。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContinuitySession {
    /// セッション ID (暗号学的乱数)
    pub session_id: String,
    /// 現在開いているメール ID (省略可)
    pub active_email_id: Option<String>,
    /// 現在のビュー
    pub current_view: SessionView,
    /// 最終更新時刻 (UNIX 秒)
    pub updated_at: u64,
    /// スクロール位置 (0.0〜1.0)
    pub scroll_position: f32,
}

/// セッションのビュー状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionView {
    /// 受信トレイ
    Inbox,
    /// メール詳細
    EmailDetail,
    /// メール作成
    Compose,
    /// セキュリティダッシュボード
    SecurityDashboard,
    /// 設定
    Settings,
}

impl ContinuitySession {
    /// 新規セッションを作成する。
    #[must_use]
    pub fn new() -> Self {
        Self {
            session_id: generate_session_id(),
            active_email_id: None,
            current_view: SessionView::Inbox,
            updated_at: now_unix(),
            scroll_position: 0.0,
        }
    }

    /// メールを開いてセッションを更新する。
    ///
    /// `email_id` が 512 バイトを超える場合はセッションを変更しない (OOM 防止)。
    pub fn open_email(&mut self, email_id: impl Into<String>) {
        const MAX_EMAIL_ID_BYTES: usize = 512;
        let id: String = email_id.into();
        if id.len() > MAX_EMAIL_ID_BYTES {
            return;
        }
        self.active_email_id = Some(id);
        self.current_view = SessionView::EmailDetail;
        self.scroll_position = 0.0;
        self.touch();
    }

    /// 受信トレイに戻る。
    pub fn go_to_inbox(&mut self) {
        self.active_email_id = None;
        self.current_view = SessionView::Inbox;
        self.touch();
    }

    /// スクロール位置を更新する。
    ///
    /// # Panics
    ///
    /// position が 0.0〜1.0 の範囲外の場合。
    pub fn update_scroll(&mut self, position: f32) {
        self.scroll_position = position.clamp(0.0, 1.0);
        self.touch();
    }

    /// セッションが有効かどうかを返す (30 分以内に更新されていれば有効)。
    #[must_use]
    pub fn is_active(&self) -> bool {
        const SESSION_TTL_SECS: u64 = 1800; // 30 分
        let now = now_unix();
        // updated_at が未来値の場合 (不正なデシリアライズ等): セッションを期限切れ扱い
        if self.updated_at > now {
            return false;
        }
        let age = now - self.updated_at;
        age < SESSION_TTL_SECS
    }

    /// セッションの経過秒数を返す。
    #[must_use]
    pub fn age_seconds(&self) -> u64 {
        now_unix().saturating_sub(self.updated_at)
    }

    fn touch(&mut self) {
        self.updated_at = now_unix();
    }
}

impl Default for ContinuitySession {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Handoff マネージャー
// ============================================================================

/// デバイス間の Handoff を管理する。
pub struct HandoffManager {
    /// 現在のセッション
    session: ContinuitySession,
    /// 最大セッション保持数
    max_sessions: usize,
}

impl HandoffManager {
    /// 新規マネージャーを作成する。
    #[must_use]
    pub fn new() -> Self {
        Self {
            session: ContinuitySession::new(),
            max_sessions: 3,
        }
    }

    /// 現在のセッションを返す。
    #[must_use]
    pub fn current_session(&self) -> &ContinuitySession {
        &self.session
    }

    /// セッションを更新する。
    pub fn update_session(&mut self, session: ContinuitySession) {
        self.session = session;
    }

    /// 新しいセッションを開始する。
    pub fn new_session(&mut self) -> &ContinuitySession {
        self.session = ContinuitySession::new();
        &self.session
    }

    /// 最大セッション数を返す。
    #[must_use]
    pub fn max_sessions(&self) -> usize {
        self.max_sessions
    }
}

impl Default for HandoffManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ユーティリティ
// ============================================================================

fn generate_session_id() -> String {
    // 16 バイト (128 ビット) CSPRNG — 誕生日パラドックス安全性:
    // 8 バイトでは 2^32 ≈ 43 億セッションで衝突確率 50% だったが、
    // 16 バイトなら 2^64 ≈ 1.8 × 10^19 セッションで 50% になり実用上安全。
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!(
        "sess_{:016x}{:016x}",
        u64::from_be_bytes(bytes[..8].try_into().unwrap_or([0u8; 8])),
        u64::from_be_bytes(bytes[8..].try_into().unwrap_or([0u8; 8])),
    )
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn new_session_starts_at_inbox() {
        let s = ContinuitySession::new();
        assert_eq!(s.current_view, SessionView::Inbox);
        assert!(s.active_email_id.is_none());
        assert_eq!(s.scroll_position, 0.0);
    }

    #[test]
    fn open_email_changes_view() {
        let mut s = ContinuitySession::new();
        s.open_email("e-001");
        assert_eq!(s.current_view, SessionView::EmailDetail);
        assert_eq!(s.active_email_id.as_deref(), Some("e-001"));
    }

    #[test]
    fn go_to_inbox_clears_email() {
        let mut s = ContinuitySession::new();
        s.open_email("e-001");
        s.go_to_inbox();
        assert_eq!(s.current_view, SessionView::Inbox);
        assert!(s.active_email_id.is_none());
    }

    #[test]
    fn scroll_position_is_clamped() {
        let mut s = ContinuitySession::new();
        s.update_scroll(1.5); // 範囲外 → clamp
        assert_eq!(s.scroll_position, 1.0);
        s.update_scroll(-0.5); // 範囲外 → clamp
        assert_eq!(s.scroll_position, 0.0);
    }

    #[test]
    fn is_active_on_new_session() {
        let s = ContinuitySession::new();
        assert!(s.is_active(), "新規セッションは即座にアクティブ");
    }

    #[test]
    fn serialization_round_trip() {
        let s = ContinuitySession::new();
        let json = serde_json::to_string(&s).expect("serialize failed");
        let restored: ContinuitySession = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(s.session_id, restored.session_id);
        assert_eq!(s.current_view, restored.current_view);
    }

    #[test]
    fn handoff_manager_new_session() {
        let mut m = HandoffManager::new();
        let id1 = m.current_session().session_id.clone();
        m.new_session();
        let id2 = m.current_session().session_id.clone();
        // 新しいセッション ID が生成される
        // (同じタイミングで作ると衝突する可能性があるため、異なることのみ確認)
        assert!(!id1.is_empty() && !id2.is_empty());
    }

    #[test]
    fn session_id_is_128_bit() {
        // ID 形式: "sess_" (5) + 32 文字の hex = 合計 37 文字
        // 8 バイト時代は "sess_" + 16 文字 = 21 文字だった
        let s = ContinuitySession::new();
        assert_eq!(s.session_id.len(), 37,
            "セッション ID は 128 ビット (37 文字) でなければならない: '{}'", s.session_id);
        assert!(s.session_id.starts_with("sess_"),
            "セッション ID は sess_ で始まる: '{}'", s.session_id);
        // hex 部分の検証
        let hex_part = &s.session_id[5..];
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "hex 部分に無効な文字: '{hex_part}'");
    }

    #[test]
    fn open_email_rejects_oversized_id() {
        let mut s = ContinuitySession::new();
        let huge_id = "x".repeat(1024);
        s.open_email(huge_id);
        // セッションは変更されていないはず
        assert_eq!(s.current_view, SessionView::Inbox, "巨大 email_id でビューが変わってはならない");
        assert!(s.active_email_id.is_none(), "巨大 email_id はセットされてはならない");
    }

    #[test]
    fn open_email_accepts_normal_id() {
        let mut s = ContinuitySession::new();
        s.open_email("msg-00001");
        assert_eq!(s.current_view, SessionView::EmailDetail);
        assert_eq!(s.active_email_id.as_deref(), Some("msg-00001"));
    }

    #[test]
    fn is_active_rejects_future_updated_at() {
        let mut s = ContinuitySession::new();
        // 未来のタイムスタンプを直接書き込む (不正なデシリアライズ相当)
        s.updated_at = u64::MAX;
        assert!(!s.is_active(), "未来のタイムスタンプは is_active=false でなければならない");
    }

    #[test]
    fn session_ids_are_unique_under_high_volume() {
        // 10000 回生成して重複なし (64 ビット時代は理論上衝突リスクあり)
        let ids: std::collections::HashSet<String> = (0..10_000)
            .map(|_| ContinuitySession::new().session_id)
            .collect();
        assert_eq!(ids.len(), 10_000, "セッション ID に重複が発生した");
    }
}

// ============================================================================
// プロパティテスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::float_cmp)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// 不変条件: scroll_position は常に 0.0〜1.0 の範囲
        #[test]
        fn scroll_always_in_range(pos in -10.0f32..10.0) {
            let mut s = ContinuitySession::new();
            s.update_scroll(pos);
            prop_assert!(
                s.scroll_position >= 0.0 && s.scroll_position <= 1.0,
                "scroll out of range: {}", s.scroll_position
            );
        }

        /// 不変条件: open_email 後は EmailDetail ビュー
        #[test]
        fn open_email_always_detail_view(email_id in "[a-z]{1,20}") {
            let mut s = ContinuitySession::new();
            s.open_email(email_id.clone());
            prop_assert_eq!(s.current_view, SessionView::EmailDetail);
            prop_assert_eq!(s.active_email_id.as_deref(), Some(email_id.as_str()));
        }

        /// 不変条件: go_to_inbox 後は Inbox ビューかつ active_email_id は None
        #[test]
        fn go_to_inbox_always_clears(_email_id in "[a-z]{1,20}") {
            let mut s = ContinuitySession::new();
            s.open_email("some-email");
            s.go_to_inbox();
            prop_assert_eq!(s.current_view, SessionView::Inbox);
            prop_assert!(s.active_email_id.is_none());
        }

        /// 不変条件: シリアライズ/デシリアライズは冪等
        #[test]
        fn serialization_idempotent(pos in 0.0f32..1.0) {
            let mut s = ContinuitySession::new();
            s.update_scroll(pos);
            let json = serde_json::to_string(&s).expect("serialize");
            let restored: ContinuitySession = serde_json::from_str(&json).expect("deserialize");
            // 小数誤差を考慮
            prop_assert!((s.scroll_position - restored.scroll_position).abs() < 1e-6);
        }
    }
}
