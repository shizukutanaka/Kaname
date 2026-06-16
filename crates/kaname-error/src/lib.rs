//! kaname-error — Kaname 共通エラー型。
//!
//! - severity(): Critical / High / Medium / Low
//! - user_message(): 内部詳細を含まない安全なメッセージ
//! - code(): 安定したエラーコード (メトリクス用)

// crates/kaname-error/src/lib.rs
//
// Kaname 共通エラー型。
// 全クレートが String ではなくこの型を使う。
// フロントエンドには serde_json でシリアライズして返す。

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Kaname のトップレベルエラー型。
#[derive(Debug, Error, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "kind", content = "detail")]
pub enum KanameError {
    // ── AI ──
    #[error("AI モデルが利用できません: {0}")]
    AiUnavailable(String),

    #[error("プロンプト注入の疑いを検出してブロックしました")]
    PromptInjectionBlocked,

    #[error("DLP ポリシーにより AI 処理をブロックしました: {label}")]
    DlpBlocked { label: String },

    // ── メール ──
    #[error("JMAP 接続エラー: {0}")]
    JmapConnection(String),

    #[error("メールが見つかりません: {id}")]
    EmailNotFound { id: String },

    #[error("BEC 検出: {verdict}")]
    BecDetected { verdict: String },

    // ── 暗号 ──
    #[error("MLS 鍵交換に失敗しました")]
    MlsKeyExchange,

    #[error("暗号化に失敗しました: {0}")]
    Encryption(String),

    #[error("安全番号が一致しません")]
    SafetyNumberMismatch,

    // ── ストレージ ──
    #[error("データベースエラー: {0}")]
    Database(String),

    #[error("ストレージ容量不足")]
    StorageFull,

    // ── 認証 ──
    #[error("認証が必要です")]
    Unauthenticated,

    #[error("この操作には権限がありません")]
    Forbidden,

    // ── ネットワーク ──
    #[error("サーバーに接続できません")]
    ServerOffline,

    #[error("タイムアウト")]
    Timeout,

    // ── 汎用 ──
    #[error("内部エラー: {0}")]
    Internal(String),

    #[error("設定エラー: {0}")]
    Config(String),
}

impl KanameError {
    /// エラーコードを返す (ログ・メトリクス用)。
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::AiUnavailable(_)     => "AI_UNAVAILABLE",
            Self::PromptInjectionBlocked => "PROMPT_INJECTION_BLOCKED",
            Self::DlpBlocked { .. }    => "DLP_BLOCKED",
            Self::JmapConnection(_)    => "JMAP_CONNECTION",
            Self::EmailNotFound { .. } => "EMAIL_NOT_FOUND",
            Self::BecDetected { .. }   => "BEC_DETECTED",
            Self::MlsKeyExchange       => "MLS_KEY_EXCHANGE",
            Self::Encryption(_)        => "ENCRYPTION",
            Self::SafetyNumberMismatch => "SAFETY_NUMBER_MISMATCH",
            Self::Database(_)          => "DATABASE",
            Self::StorageFull          => "STORAGE_FULL",
            Self::Unauthenticated      => "UNAUTHENTICATED",
            Self::Forbidden            => "FORBIDDEN",
            Self::ServerOffline        => "SERVER_OFFLINE",
            Self::Timeout              => "TIMEOUT",
            Self::Internal(_)          => "INTERNAL",
            Self::Config(_)            => "CONFIG",
        }
    }

    /// セキュリティ上の重要度 (ログフィルタリング用)。
    pub fn severity(&self) -> Severity {
        match self {
            Self::PromptInjectionBlocked | Self::DlpBlocked { .. } | Self::BecDetected { .. } | Self::SafetyNumberMismatch => Severity::Critical,
            Self::Unauthenticated | Self::Forbidden | Self::MlsKeyExchange | Self::Encryption(_) => Severity::High,
            Self::JmapConnection(_) | Self::Database(_) | Self::Internal(_) => Severity::Medium,
            _ => Severity::Low,
        }
    }

    /// ユーザーに表示して安全なメッセージ。
    /// 内部実装の詳細を含まない。
    #[must_use]
    pub fn user_message(&self) -> &str {
        match self {
            Self::AiUnavailable(_)     => "AI機能は現在利用できません",
            Self::PromptInjectionBlocked => "セキュリティ上の理由でこの操作をブロックしました",
            Self::DlpBlocked { .. }    => "このメールはセキュリティポリシーによりAI処理できません",
            Self::JmapConnection(_)    => "メールサーバーに接続できません。ネットワークを確認してください",
            Self::EmailNotFound { .. } => "メールが見つかりません",
            Self::BecDetected { .. }   => "このメールはBEC攻撃の可能性があります",
            Self::MlsKeyExchange       => "暗号化鍵の交換に失敗しました",
            Self::Encryption(_)        => "暗号化処理に失敗しました",
            Self::SafetyNumberMismatch => "安全番号が一致しません。送信者の身元を確認してください",
            Self::Database(_)          => "データの保存中にエラーが発生しました",
            Self::StorageFull          => "ストレージが不足しています",
            Self::Unauthenticated      => "サインインが必要です",
            Self::Forbidden            => "この操作の権限がありません",
            Self::ServerOffline        => "サーバーに接続できません",
            Self::Timeout              => "接続がタイムアウトしました",
            Self::Internal(_)          => "内部エラーが発生しました",
            Self::Config(_)            => "設定にエラーがあります",
        }
    }
}

/// エラーの重要度。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity { Low, Medium, High, Critical }

/// Tauri コマンドは `Result<T, String>` を返すため、変換を提供。
///
/// # セキュリティ
///
/// `user_message()` のみを返す。`serde_json::to_string(&e)` では
/// `Internal("SQL details...")` のような内部詳細がフロントエンドに
/// 漏洩する可能性があるため使用しない。
/// デバッグ詳細が必要な場合は `tracing::error!("{e:?}")` を使うこと。
impl From<KanameError> for String {
    fn from(e: KanameError) -> Self {
        // エラーコードと安全なユーザーメッセージのみを JSON に変換する
        serde_json::json!({
            "code":    e.code(),
            "message": e.user_message(),
        }).to_string()
    }
}

/// Result エイリアス。
pub type KanameResult<T> = Result<T, KanameError>;

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn error_code_unique() {
        let errors: Vec<(&str, KanameError)> = vec![
            ("AI_UNAVAILABLE",         KanameError::AiUnavailable("test".into())),
            ("PROMPT_INJECTION_BLOCKED", KanameError::PromptInjectionBlocked),
            ("DLP_BLOCKED",            KanameError::DlpBlocked { label: "極秘".into() }),
            ("BEC_DETECTED",           KanameError::BecDetected { verdict: "DANGEROUS".into() }),
            ("EMAIL_NOT_FOUND",        KanameError::EmailNotFound { id: "e1".into() }),
        ];
        for (expected_code, err) in errors {
            assert_eq!(err.code(), expected_code);
        }
    }

    #[test]
    fn security_errors_are_critical_or_high() {
        assert_eq!(KanameError::PromptInjectionBlocked.severity(), Severity::Critical);
        assert_eq!(KanameError::BecDetected { verdict: "DANGEROUS".into() }.severity(), Severity::Critical);
        assert_eq!(KanameError::SafetyNumberMismatch.severity(), Severity::Critical);
        assert_eq!(KanameError::Unauthenticated.severity(), Severity::High);
    }

    #[test]
    fn user_message_has_no_internal_detail() {
        // 内部エラーはユーザーに詳細を見せない
        let e = KanameError::Internal("SQL constraint violation on table emails".into());
        assert!(!e.user_message().contains("SQL"));
        assert!(!e.user_message().contains("constraint"));
        assert!(!e.user_message().contains("table"));
    }

    #[test]
    fn dlp_blocked_preserves_label() {
        let e = KanameError::DlpBlocked { label: "HighlyConfidential".into() };
        assert!(e.to_string().contains("HighlyConfidential"));
        // ユーザーメッセージは一般的な文言
        assert!(!e.user_message().contains("HighlyConfidential"));
    }

    #[test]
    fn serializes_to_json() {
        let e = KanameError::BecDetected { verdict: "DANGEROUS".into() };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("BEC_DETECTED") || json.contains("BecDetected") || json.contains("DANGEROUS"));
    }

    #[test]
    fn string_conversion_omits_internal_detail() {
        // Internal エラーの詳細がフロントエンドに漏洩しないこと
        let e = KanameError::Internal("SQL constraint violation on table emails".into());
        let s: String = e.into();
        assert!(!s.contains("SQL"), "内部実装の詳細が String 変換に含まれてはならない: {s}");
        assert!(!s.contains("constraint"), "内部詳細が漏洩: {s}");
        assert!(s.contains("INTERNAL"), "エラーコードは含まれるべき: {s}");
        // user_message() の安全な文言が含まれること
        assert!(s.contains("内部エラー") || s.contains("message"), "安全なメッセージが含まれるべき: {s}");
    }

    #[test]
    fn string_conversion_database_detail_not_leaked() {
        let e = KanameError::Database("UNIQUE constraint failed: contacts.email".into());
        let s: String = e.into();
        assert!(!s.contains("UNIQUE"), "DB スキーマ詳細が漏洩してはならない: {s}");
        assert!(!s.contains("contacts.email"), "テーブル名が漏洩してはならない: {s}");
        assert!(s.contains("DATABASE"), "エラーコードは含まれるべき: {s}");
    }

    #[test]
    fn string_conversion_is_valid_json() {
        let e = KanameError::Internal("crash".into());
        let s: String = e.into();
        assert!(!s.is_empty());
        // JSON としてパース可能なこと
        let v: serde_json::Value = serde_json::from_str(&s).expect("有効な JSON であるべき");
        assert!(v.get("code").is_some(), "code フィールドが必要: {s}");
        assert!(v.get("message").is_some(), "message フィールドが必要: {s}");
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High    > Severity::Medium);
        assert!(Severity::Medium  > Severity::Low);
    }
}
