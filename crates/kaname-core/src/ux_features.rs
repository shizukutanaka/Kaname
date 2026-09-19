// crates/kaname-core/src/ux_features.rs
//
// スマートトリアージ (Superhuman の Split Inbox + HEY の仕分け)。

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

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
#[derive(Debug, Default)]
pub struct TriageEngine;

impl TriageEngine {
    /// 新規インスタンスを作成する。
    pub fn new() -> Self { Self }

    /// メールを自動仕分けする。
    pub fn triage(
        &self,
        from_addr:   &str,
        subject:     &str,
        bec_verdict: Option<&str>,
    ) -> TriageBucket {
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
}
