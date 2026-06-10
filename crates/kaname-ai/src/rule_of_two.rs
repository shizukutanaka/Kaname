//! Rule of Two — Meta の agentic セキュリティ原則。
//!
//! arxiv 2601.17548 が引用する Meta の "Rule of Two":
//! エージェントは以下の 3 つの能力のうち、**最大 2 つまで**しか
//! 同時に持ってはならない。3 つ揃うと深刻な被害が可能になる。
//!
//! 1. **Untrusted 入力の処理** (例: 受信メール本文)
//! 2. **機密データへのアクセス** (例: 過去のメール、連絡先)
//! 3. **外部通信** (例: メール送信、外部 API)
//!
//! # なぜ効くか
//!
//! プロンプト注入が成立する典型は「untrusted 入力 (1) で機密データ (2) を
//! 読み、外部 (3) に流出させる」という 3 段。どれか 1 つを断てば連鎖が切れる。
//!
//! CaMeL/Dual-LLM を補完する、シンプルで強力な不変条件。

use serde::{Deserialize, Serialize};

/// エージェントの能力。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// 信頼できない入力を処理する (受信メール本文など)。
    ProcessUntrustedInput,
    /// 機密データにアクセスする (過去メール、連絡先など)。
    AccessSensitiveData,
    /// 外部と通信する (送信、外部 API)。
    ExternalCommunication,
}

/// Rule of Two の検証結果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleOfTwoVerdict {
    /// 安全 (2 つ以下)。
    Safe,
    /// 違反 (3 つすべて) — ブロックすべき。
    Violation {
        /// 違反の説明。
        explanation: String,
    },
}

/// Rule of Two のチェッカー。
pub struct RuleOfTwo;

impl RuleOfTwo {
    /// 現在の能力集合が Rule of Two を満たすか検証する。
    ///
    /// 3 つすべてが揃うと Violation。
    #[must_use]
    pub fn check(capabilities: &[Capability]) -> RuleOfTwoVerdict {
        let has_untrusted = capabilities.contains(&Capability::ProcessUntrustedInput);
        let has_sensitive = capabilities.contains(&Capability::AccessSensitiveData);
        let has_external = capabilities.contains(&Capability::ExternalCommunication);

        let count = [has_untrusted, has_sensitive, has_external]
            .iter()
            .filter(|&&x| x)
            .count();

        if count >= 3 {
            RuleOfTwoVerdict::Violation {
                explanation: "エージェントが untrusted 入力・機密データ・外部通信の \
                    3 能力を同時に保持しています。プロンプト注入による情報流出の \
                    完全な連鎖が可能なため、いずれか 1 つを分離する必要があります。"
                    .to_string(),
            }
        } else {
            RuleOfTwoVerdict::Safe
        }
    }

    /// 違反を解消するために削除すべき能力を提案する。
    ///
    /// 外部通信を最優先で分離 (最も被害が大きいため)。
    #[must_use]
    pub fn suggest_mitigation(capabilities: &[Capability]) -> Option<Capability> {
        if matches!(Self::check(capabilities), RuleOfTwoVerdict::Violation { .. }) {
            // 外部通信を断つのが最も効果的 (流出経路を塞ぐ)
            Some(Capability::ExternalCommunication)
        } else {
            None
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn two_capabilities_safe() {
        let caps = vec![
            Capability::ProcessUntrustedInput,
            Capability::AccessSensitiveData,
        ];
        assert_eq!(RuleOfTwo::check(&caps), RuleOfTwoVerdict::Safe);
    }

    #[test]
    fn three_capabilities_violation() {
        let caps = vec![
            Capability::ProcessUntrustedInput,
            Capability::AccessSensitiveData,
            Capability::ExternalCommunication,
        ];
        assert!(matches!(RuleOfTwo::check(&caps), RuleOfTwoVerdict::Violation { .. }));
    }

    #[test]
    fn single_capability_safe() {
        let caps = vec![Capability::ProcessUntrustedInput];
        assert_eq!(RuleOfTwo::check(&caps), RuleOfTwoVerdict::Safe);
    }

    #[test]
    fn empty_capabilities_safe() {
        assert_eq!(RuleOfTwo::check(&[]), RuleOfTwoVerdict::Safe);
    }

    #[test]
    fn mitigation_suggests_external_comm() {
        let caps = vec![
            Capability::ProcessUntrustedInput,
            Capability::AccessSensitiveData,
            Capability::ExternalCommunication,
        ];
        assert_eq!(
            RuleOfTwo::suggest_mitigation(&caps),
            Some(Capability::ExternalCommunication)
        );
    }

    #[test]
    fn no_mitigation_when_safe() {
        let caps = vec![Capability::ProcessUntrustedInput];
        assert_eq!(RuleOfTwo::suggest_mitigation(&caps), None);
    }

    #[test]
    fn duplicate_capabilities_handled() {
        // 重複しても 2 種類なら安全
        let caps = vec![
            Capability::ProcessUntrustedInput,
            Capability::ProcessUntrustedInput,
            Capability::AccessSensitiveData,
        ];
        assert_eq!(RuleOfTwo::check(&caps), RuleOfTwoVerdict::Safe);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_cap() -> impl Strategy<Value = Capability> {
        prop_oneof![
            Just(Capability::ProcessUntrustedInput),
            Just(Capability::AccessSensitiveData),
            Just(Capability::ExternalCommunication),
        ]
    }

    proptest! {
        /// 不変条件: 3 種すべて揃ったときのみ Violation
        #[test]
        fn violation_iff_all_three(caps in prop::collection::vec(arb_cap(), 0..10)) {
            let has_all = caps.contains(&Capability::ProcessUntrustedInput)
                && caps.contains(&Capability::AccessSensitiveData)
                && caps.contains(&Capability::ExternalCommunication);
            let verdict = RuleOfTwo::check(&caps);
            if has_all {
                prop_assert!(matches!(verdict, RuleOfTwoVerdict::Violation { .. }));
            } else {
                prop_assert_eq!(verdict, RuleOfTwoVerdict::Safe);
            }
        }
    }
}
