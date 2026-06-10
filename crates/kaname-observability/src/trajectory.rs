//! Agent Trajectory Monitoring — AI エージェント行動軌跡の監視。
//!
//! arxiv の AgentDoG / trajectory monitoring 研究に基づく。
//! OWASP Agentic Top 10 の ASI-09 (監視・追跡可能性の欠如) に対応。
//!
//! # 目的
//!
//! エージェントの行動を時系列で記録し、危険なパターンを検出する:
//! - Rule of Two 違反への接近 (3 能力の段階的取得)
//! - 異常な操作シーケンス (read → read → 大量送信)
//! - 短時間の高頻度操作 (自動化された攻撃の兆候)
//!
//! # プライバシー設計 (I5)
//!
//! 軌跡にはメール本文・PII を含めない。操作の種別とタイムスタンプのみ。

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// エージェントの 1 操作ステップ。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrajectoryStep {
    /// 操作の種別 (PII を含まない列挙的な名前)。
    pub action: String,
    /// untrusted データに触れたか。
    pub touched_untrusted: bool,
    /// 機密データにアクセスしたか。
    pub accessed_sensitive: bool,
    /// 外部通信を行ったか。
    pub external_comm: bool,
    /// タイムスタンプ (Unix ミリ秒)。
    pub timestamp_ms: u64,
}

/// 軌跡の異常検出結果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrajectoryAlert {
    /// Rule of Two 違反 (3 能力が軌跡内で揃った)。
    RuleOfTwoViolation,
    /// 高頻度操作 (短時間に閾値超の操作)。
    HighFrequency { ops_per_sec: u32 },
    /// 危険なシーケンス (大量読み取り後の外部送信)。
    SuspiciousSequence,
}

/// エージェント軌跡モニター。
pub struct TrajectoryMonitor {
    /// 直近の操作履歴 (リングバッファ)。
    history: VecDeque<TrajectoryStep>,
    /// 履歴の最大保持数。
    max_history: usize,
    /// 高頻度判定の閾値 (ops/sec)。
    freq_threshold: u32,
}

impl TrajectoryMonitor {
    /// 新規モニターを作成する。
    #[must_use]
    pub fn new() -> Self {
        Self {
            history: VecDeque::new(),
            max_history: 100,
            freq_threshold: 10,
        }
    }

    /// 操作ステップを記録し、検出されたアラートを返す。
    pub fn record(&mut self, step: TrajectoryStep) -> Vec<TrajectoryAlert> {
        self.history.push_back(step);
        if self.history.len() > self.max_history {
            self.history.pop_front();
        }
        self.analyze()
    }

    /// 現在の軌跡を分析してアラートを返す。
    #[must_use]
    pub fn analyze(&self) -> Vec<TrajectoryAlert> {
        let mut alerts = Vec::new();

        // 1. Rule of Two: 軌跡全体で 3 能力が揃ったか
        let any_untrusted = self.history.iter().any(|s| s.touched_untrusted);
        let any_sensitive = self.history.iter().any(|s| s.accessed_sensitive);
        let any_external = self.history.iter().any(|s| s.external_comm);
        if any_untrusted && any_sensitive && any_external {
            alerts.push(TrajectoryAlert::RuleOfTwoViolation);
        }

        // 2. 高頻度操作: 直近 1 秒間の操作数
        if let (Some(first), Some(last)) = (self.history.front(), self.history.back()) {
            let span_ms = last.timestamp_ms.saturating_sub(first.timestamp_ms);
            if span_ms > 0 && self.history.len() >= 2 {
                let ops_per_sec = (self.history.len() as u64 * 1000 / span_ms.max(1)) as u32;
                if ops_per_sec > self.freq_threshold {
                    alerts.push(TrajectoryAlert::HighFrequency { ops_per_sec });
                }
            }
        }

        // 3. 危険シーケンス: 機密アクセス直後の外部通信
        let steps: Vec<_> = self.history.iter().collect();
        for window in steps.windows(2) {
            if window[0].accessed_sensitive && window[1].external_comm {
                alerts.push(TrajectoryAlert::SuspiciousSequence);
                break;
            }
        }

        alerts
    }

    /// 軌跡をリセットする (新セッション開始時)。
    pub fn reset(&mut self) {
        self.history.clear();
    }

    /// 記録された操作数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.history.len()
    }

    /// 軌跡が空か。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.history.is_empty()
    }
}

impl Default for TrajectoryMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn step(action: &str, u: bool, s: bool, e: bool, ts: u64) -> TrajectoryStep {
        TrajectoryStep {
            action: action.into(),
            touched_untrusted: u,
            accessed_sensitive: s,
            external_comm: e,
            timestamp_ms: ts,
        }
    }

    #[test]
    fn empty_monitor_no_alerts() {
        let m = TrajectoryMonitor::new();
        assert!(m.analyze().is_empty());
    }

    #[test]
    fn single_capability_no_alert() {
        let mut m = TrajectoryMonitor::new();
        let alerts = m.record(step("read", true, false, false, 1000));
        assert!(!alerts.contains(&TrajectoryAlert::RuleOfTwoViolation));
    }

    #[test]
    fn three_capabilities_triggers_rule_of_two() {
        let mut m = TrajectoryMonitor::new();
        m.record(step("read_email", true, false, false, 1000));
        m.record(step("access_contacts", false, true, false, 2000));
        let alerts = m.record(step("send", false, false, true, 3000));
        assert!(alerts.contains(&TrajectoryAlert::RuleOfTwoViolation));
    }

    #[test]
    fn suspicious_sequence_detected() {
        let mut m = TrajectoryMonitor::new();
        m.record(step("access_sensitive", false, true, false, 1000));
        let alerts = m.record(step("external_send", false, false, true, 2000));
        assert!(alerts.contains(&TrajectoryAlert::SuspiciousSequence));
    }

    #[test]
    fn high_frequency_detected() {
        let mut m = TrajectoryMonitor::new();
        // 100ms 間に 5 操作 = 50 ops/sec
        for i in 0..5 {
            m.record(step("op", false, false, false, 1000 + i * 20));
        }
        let alerts = m.analyze();
        assert!(alerts.iter().any(|a| matches!(a, TrajectoryAlert::HighFrequency { .. })));
    }

    #[test]
    fn reset_clears_history() {
        let mut m = TrajectoryMonitor::new();
        m.record(step("op", true, true, true, 1000));
        m.reset();
        assert!(m.is_empty());
        assert!(m.analyze().is_empty());
    }

    #[test]
    fn history_capped_at_max() {
        let mut m = TrajectoryMonitor::new();
        for i in 0..150 {
            m.record(step("op", false, false, false, 1000 + i * 1000));
        }
        assert!(m.len() <= 100);
    }

    #[test]
    fn trajectory_no_pii() {
        let s = step("read_email", true, false, false, 1000);
        let json = serde_json::to_string(&s).unwrap();
        // action は列挙名のみ、本文や PII を含まない
        assert!(json.contains("read_email"));
        assert!(!json.contains("@"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// 不変条件: 履歴は max_history を超えない
        #[test]
        fn history_never_exceeds_max(n in 0usize..300) {
            let mut m = TrajectoryMonitor::new();
            for i in 0..n {
                m.record(TrajectoryStep {
                    action: "op".into(),
                    touched_untrusted: false,
                    accessed_sensitive: false,
                    external_comm: false,
                    timestamp_ms: 1000 + i as u64 * 1000,
                });
            }
            prop_assert!(m.len() <= 100);
        }

        /// 不変条件: 3 能力が揃わなければ RuleOfTwoViolation は出ない
        #[test]
        fn no_violation_without_all_three(
            u in any::<bool>(), s in any::<bool>(), e in any::<bool>()
        ) {
            let mut m = TrajectoryMonitor::new();
            m.record(TrajectoryStep {
                action: "op".into(),
                touched_untrusted: u,
                accessed_sensitive: s,
                external_comm: e,
                timestamp_ms: 1000,
            });
            let alerts = m.analyze();
            if !(u && s && e) {
                prop_assert!(!alerts.contains(&TrajectoryAlert::RuleOfTwoViolation));
            }
        }
    }
}
