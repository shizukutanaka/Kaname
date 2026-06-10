//! kaname-render の `DlpScanner` trait を `DlpEngine` 用に実装するブリッジ。
//!
//! 依存グラフは render → dlp の単方向なので、render 側は trait のみを定義し、
//! 具体的な実装 (このモジュール) は dlp 側に置く。
//!
//! 使用例:
//! ```
//! use kaname_dlp::{DlpEngine, render_bridge::EnvelopeScanner};
//! let engine = DlpEngine::default_engine();
//! let scanner = EnvelopeScanner::new(engine);
//! // kaname_render::render_with_dlp(raw, Some(&scanner))
//! ```

use crate::{Action, Direction, DlpEngine, EvalCtx};
use kaname_render::{DlpScanner, DlpVerdict, Envelope};
use std::collections::HashMap;

/// `DlpEngine` を `kaname_render::DlpScanner` として使うためのラッパー。
pub struct EnvelopeScanner {
    engine: DlpEngine,
}

impl EnvelopeScanner {
    /// エンジンをラップする。
    #[must_use]
    pub fn new(engine: DlpEngine) -> Self {
        Self { engine }
    }

    /// 内部エンジンへの参照。
    #[must_use]
    pub fn engine(&self) -> &DlpEngine {
        &self.engine
    }
}

impl DlpScanner for EnvelopeScanner {
    fn scan(&self, envelope: &Envelope) -> DlpVerdict {
        // Envelope → EvalCtx 変換
        let body = envelope.text_body.as_deref().unwrap_or("");
        let subject = envelope.subject.as_deref().unwrap_or("");
        let to: Vec<String> = envelope.to.iter()
            .map(|a| a.addr.as_string())
            .collect();
        let from = envelope.from.first()
            .map(|a| a.addr.as_string())
            .unwrap_or_default();
        let attachment_mimes: Vec<String> = envelope.attachments.iter()
            .map(|a| a.declared_mime.clone())
            .collect();
        let size_bytes = body.len() as u64
            + envelope.attachments.iter().map(|a| a.size_bytes).sum::<u64>();
        let edm_sets = HashMap::new();

        let ctx = EvalCtx {
            body,
            subject,
            size_bytes,
            to: &to,
            from: &from,
            attachment_mimes: &attachment_mimes,
            edm_sets: &edm_sets,
        };

        let result = self.engine.evaluate(&ctx, Direction::Inbound);

        match result.verdict {
            Action::Allow => DlpVerdict::Allow,
            Action::Warn => {
                let f = result.findings.first();
                DlpVerdict::Warn {
                    policy:  f.map(|f| f.rule_name.clone()).unwrap_or_default(),
                    excerpt: f.map(|f| f.excerpt.clone()).unwrap_or_default(),
                }
            }
            Action::Block => {
                // Block findings の中で最初のものをポリシー名として返す
                let policy = result.findings.iter()
                    .find(|f| f.action == Action::Block)
                    .map(|f| f.rule_name.clone())
                    .unwrap_or_default();
                DlpVerdict::Block { policy }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{Condition, PatternLibrary, Predicate, Rule, RuleBuilder};

    fn confidential_block_rule() -> Rule {
        RuleBuilder::new("conf-block", "Confidential marker")
            .inbound()
            .block()
            .priority(1)
            .when(Condition::matches(Predicate::Keyword {
                words: vec!["社外秘".to_string()],
                min_count: 1,
            }))
            .build()
    }

    fn parse_mail(subject: &str, body: &str) -> Envelope {
        let raw = format!(
            "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: {subject}\r\n\r\n{body}"
        );
        kaname_render::parse(raw.as_bytes()).expect("parse failed")
    }

    #[test]
    fn scanner_blocks_confidential_inbound() {
        let engine = DlpEngine::new(vec![confidential_block_rule()], PatternLibrary::default());
        let scanner = EnvelopeScanner::new(engine);
        let env = parse_mail("FW: report", "この資料は社外秘です。取り扱いに注意。");
        match scanner.scan(&env) {
            DlpVerdict::Block { policy } => assert_eq!(policy, "Confidential marker"),
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn scanner_allows_clean_mail() {
        let engine = DlpEngine::new(vec![confidential_block_rule()], PatternLibrary::default());
        let scanner = EnvelopeScanner::new(engine);
        let env = parse_mail("Lunch?", "ランチに行きませんか。");
        assert_eq!(scanner.scan(&env), DlpVerdict::Allow);
    }

    #[test]
    fn render_with_dlp_blocks_pipeline() {
        let engine = DlpEngine::new(vec![confidential_block_rule()], PatternLibrary::default());
        let scanner = EnvelopeScanner::new(engine);
        let raw = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: x\r\n\r\n\xe7\xa4\xbe\xe5\xa4\x96\xe7\xa7\x98 data";
        let result = kaname_render::render_with_dlp(raw, Some(&scanner));
        assert!(result.is_err(), "Block 判定でレンダリングが中断されるべき");
    }

    #[test]
    fn render_with_dlp_passes_clean_mail() {
        let engine = DlpEngine::new(vec![confidential_block_rule()], PatternLibrary::default());
        let scanner = EnvelopeScanner::new(engine);
        let raw = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: hi\r\n\r\nhello there";
        let result = kaname_render::render_with_dlp(raw, Some(&scanner));
        assert!(result.is_ok());
        let (_, _, verdict) = result.unwrap();
        assert_eq!(verdict, DlpVerdict::Allow);
    }
}
