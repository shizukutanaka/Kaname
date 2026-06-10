//! Tiered-Risk Access Model — Green/Yellow/Red の3段階リスク制御。
//!
//! arxiv 2505.22852 §3 の実装。
//!
//! # 問題
//!
//! CaMeL (Dual-LLM) は「Untrusted データを含むツール呼び出しを全て拒否」する。
//! しかし全ての操作を同じリスクとして扱うため、正当な操作も阻害される
//! (AgentDojo で 67% 完了率)。さらに過剰な確認は prompt fatigue を招く。
//!
//! # 解決: 操作を 3 段階に分類
//!
//! - **Green**: read-only / 公開データ → 基本チェックのみで許可
//! - **Yellow**: 自環境の変更 → 軽い確認 (Untrusted データを含む場合)
//! - **Red**: 不可逆 / 外部送信 → 完全な capability チェック + 多要素承認
//!
//! arxiv によると、この階層化で正当ワークフローの 90% 以上を保ちつつ
//! 全シミュレート攻撃をブロックできる。

use serde::{Deserialize, Serialize};

/// 操作のリスク階層。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskTier {
    /// 読み取り専用・公開データ。基本チェックのみ。
    Green,
    /// 自環境の変更。軽い確認。
    Yellow,
    /// 不可逆・外部送信。多要素承認。
    Red,
}

/// エージェントが実行しうる操作の種別。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentAction {
    /// メール一覧の取得。
    ListEmails,
    /// メール本文の閲覧。
    ReadEmail,
    /// カレンダー閲覧。
    ViewCalendar,
    /// 下書き保存 (自環境)。
    SaveDraft,
    /// フォルダ移動 (自環境)。
    MoveToFolder,
    /// ラベル付与 (自環境)。
    ApplyLabel,
    /// メール送信 (外部・不可逆)。
    SendEmail,
    /// 添付ファイルの外部共有 (不可逆)。
    ShareAttachment,
    /// 連絡先の一括エクスポート (不可逆)。
    ExportContacts,
}

impl AgentAction {
    /// この操作のリスク階層を返す。
    #[must_use]
    pub fn risk_tier(&self) -> RiskTier {
        match self {
            // Green: 読み取り専用
            Self::ListEmails | Self::ReadEmail | Self::ViewCalendar => RiskTier::Green,
            // Yellow: 自環境の変更
            Self::SaveDraft | Self::MoveToFolder | Self::ApplyLabel => RiskTier::Yellow,
            // Red: 不可逆・外部送信
            Self::SendEmail | Self::ShareAttachment | Self::ExportContacts => RiskTier::Red,
        }
    }
}

/// アクセス判定の結果。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AccessDecision {
    /// 即座に許可。
    Allow,
    /// 軽い確認を要求 (Yellow + Untrusted データ)。
    ConfirmLightweight {
        /// 確認メッセージ。
        prompt: String,
    },
    /// 多要素承認を要求 (Red)。
    RequireMultiFactor {
        /// 承認理由。
        reason: String,
    },
}

/// Tiered-Risk アクセスコントローラー。
pub struct TieredRiskController;

impl TieredRiskController {
    /// 操作と「Untrusted データを含むか」からアクセス判定を行う。
    ///
    /// arxiv 2505.22852 §3 の階層ポリシー:
    /// - Green: 常に許可
    /// - Yellow: Untrusted データを含む場合のみ軽い確認
    /// - Red: 常に多要素承認
    #[must_use]
    pub fn decide(action: &AgentAction, involves_untrusted: bool) -> AccessDecision {
        match action.risk_tier() {
            RiskTier::Green => AccessDecision::Allow,
            RiskTier::Yellow => {
                if involves_untrusted {
                    AccessDecision::ConfirmLightweight {
                        prompt: format!(
                            "この操作 ({action:?}) は信頼できないデータを含みます。続行しますか？"
                        ),
                    }
                } else {
                    AccessDecision::Allow
                }
            }
            RiskTier::Red => AccessDecision::RequireMultiFactor {
                reason: format!(
                    "操作 ({action:?}) は不可逆または外部送信のため、多要素承認が必要です。"
                ),
            },
        }
    }

    /// prompt fatigue 低減のため、確認が必要な操作かを判定する。
    ///
    /// Green は確認不要。Yellow は Untrusted の場合のみ。Red は常に確認。
    #[must_use]
    pub fn requires_confirmation(action: &AgentAction, involves_untrusted: bool) -> bool {
        !matches!(Self::decide(action, involves_untrusted), AccessDecision::Allow)
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn read_only_is_green() {
        assert_eq!(AgentAction::ListEmails.risk_tier(), RiskTier::Green);
        assert_eq!(AgentAction::ReadEmail.risk_tier(), RiskTier::Green);
        assert_eq!(AgentAction::ViewCalendar.risk_tier(), RiskTier::Green);
    }

    #[test]
    fn self_env_change_is_yellow() {
        assert_eq!(AgentAction::SaveDraft.risk_tier(), RiskTier::Yellow);
        assert_eq!(AgentAction::MoveToFolder.risk_tier(), RiskTier::Yellow);
    }

    #[test]
    fn irreversible_is_red() {
        assert_eq!(AgentAction::SendEmail.risk_tier(), RiskTier::Red);
        assert_eq!(AgentAction::ShareAttachment.risk_tier(), RiskTier::Red);
        assert_eq!(AgentAction::ExportContacts.risk_tier(), RiskTier::Red);
    }

    #[test]
    fn green_always_allowed() {
        let d = TieredRiskController::decide(&AgentAction::ListEmails, true);
        assert_eq!(d, AccessDecision::Allow);
    }

    #[test]
    fn yellow_with_untrusted_needs_confirm() {
        let d = TieredRiskController::decide(&AgentAction::SaveDraft, true);
        assert!(matches!(d, AccessDecision::ConfirmLightweight { .. }));
    }

    #[test]
    fn yellow_without_untrusted_allowed() {
        let d = TieredRiskController::decide(&AgentAction::SaveDraft, false);
        assert_eq!(d, AccessDecision::Allow);
    }

    #[test]
    fn red_always_multifactor() {
        let d1 = TieredRiskController::decide(&AgentAction::SendEmail, true);
        let d2 = TieredRiskController::decide(&AgentAction::SendEmail, false);
        assert!(matches!(d1, AccessDecision::RequireMultiFactor { .. }));
        assert!(matches!(d2, AccessDecision::RequireMultiFactor { .. }));
    }

    #[test]
    fn prompt_fatigue_reduction() {
        // Green は確認不要 (prompt fatigue 低減)
        assert!(!TieredRiskController::requires_confirmation(&AgentAction::ReadEmail, true));
        // Red は確認必要
        assert!(TieredRiskController::requires_confirmation(&AgentAction::SendEmail, false));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_action() -> impl Strategy<Value = AgentAction> {
        prop_oneof![
            Just(AgentAction::ListEmails),
            Just(AgentAction::ReadEmail),
            Just(AgentAction::ViewCalendar),
            Just(AgentAction::SaveDraft),
            Just(AgentAction::MoveToFolder),
            Just(AgentAction::ApplyLabel),
            Just(AgentAction::SendEmail),
            Just(AgentAction::ShareAttachment),
            Just(AgentAction::ExportContacts),
        ]
    }

    proptest! {
        /// 不変条件: Red 操作は常に多要素承認 (Untrusted の有無に関わらず)
        #[test]
        fn red_always_multifactor(action in arb_action(), untrusted in any::<bool>()) {
            if action.risk_tier() == RiskTier::Red {
                let d = TieredRiskController::decide(&action, untrusted);
                prop_assert!(matches!(d, AccessDecision::RequireMultiFactor { .. }));
            }
        }

        /// 不変条件: Green 操作は常に許可
        #[test]
        fn green_always_allow(action in arb_action(), untrusted in any::<bool>()) {
            if action.risk_tier() == RiskTier::Green {
                let d = TieredRiskController::decide(&action, untrusted);
                prop_assert_eq!(d, AccessDecision::Allow);
            }
        }
    }
}
