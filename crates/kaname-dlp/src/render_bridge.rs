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

use crate::{Action, Direction, DlpEngine, EvalCtx, edm::EdmFingerprints};
use kaname_render::{DlpScanner, DlpVerdict, Envelope};
use std::collections::HashMap;

/// `DlpEngine` を `kaname_render::DlpScanner` として使うためのラッパー。
///
/// `edm_sets` を保持することで `Predicate::ExactDataMatch` が機能する。
/// 空のまま渡すと EDM ルールは常にミスになる (無効化と同じ)。
pub struct EnvelopeScanner {
    engine:   DlpEngine,
    /// 登録済み EDM フィンガープリントセット (set_id → fingerprints)
    edm_sets: HashMap<String, EdmFingerprints>,
}

impl EnvelopeScanner {
    /// エンジンをラップする。EDM フィンガープリントなし。
    #[must_use]
    pub fn new(engine: DlpEngine) -> Self {
        Self { engine, edm_sets: HashMap::new() }
    }

    /// EDM フィンガープリントを追加する。
    ///
    /// `fingerprint_set_id` は `Predicate::ExactDataMatch` のセット ID と一致させること。
    pub fn add_edm_set(&mut self, id: impl Into<String>, fp: EdmFingerprints) {
        self.edm_sets.insert(id.into(), fp);
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
        let ctx = EvalCtx {
            body,
            subject,
            size_bytes,
            to: &to,
            from: &from,
            attachment_mimes: &attachment_mimes,
            edm_sets: &self.edm_sets,
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
    fn edm_detection_fires_through_envelope_scanner() {
        use crate::{Condition, Predicate, RuleBuilder};

        // EDM フィンガープリントを登録
        let mut fp = EdmFingerprints::new("test-salt", 1);
        fp.register_dataset(&["secret@corp.example.com"]);

        // EDM ルール作成
        let edm_rule = RuleBuilder::new("edm-leak", "EDM customer email leak")
            .inbound()
            .block()
            .priority(1)
            .when(Condition::matches(Predicate::ExactDataMatch {
                fingerprint_set_id: "customers".to_string(),
            }))
            .build();

        let engine = DlpEngine::new(vec![edm_rule], PatternLibrary::default());
        let mut scanner = EnvelopeScanner::new(engine);
        scanner.add_edm_set("customers", fp);

        // フィンガープリントに登録されたアドレスが本文に含まれる → Block
        let env = parse_mail("FW", "Contact: secret@corp.example.com");
        match scanner.scan(&env) {
            DlpVerdict::Block { policy } => assert_eq!(policy, "EDM customer email leak"),
            other => panic!("EDM 検出が機能しなかった: {other:?}"),
        }
    }

    #[test]
    fn edm_empty_sets_allows_everything() {
        use crate::{Condition, Predicate, RuleBuilder};

        let edm_rule = RuleBuilder::new("edm-rule", "EDM rule")
            .inbound()
            .block()
            .priority(1)
            .when(Condition::matches(Predicate::ExactDataMatch {
                fingerprint_set_id: "customers".to_string(),
            }))
            .build();

        let engine = DlpEngine::new(vec![edm_rule], PatternLibrary::default());
        // edm_sets を追加しない → EDM ルールは発火しない
        let scanner = EnvelopeScanner::new(engine);
        let env = parse_mail("FW", "Contact: secret@corp.example.com");
        // フィンガープリント未登録なので Allow
        assert_eq!(scanner.scan(&env), DlpVerdict::Allow,
            "edm_sets 未登録なのに Block になった");
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
