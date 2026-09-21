//! kaname-radar プロパティテスト

use kaname_radar::{CampaignRadar, EmailMetadata, SubjectLengthBucket};
use proptest::prelude::*;
fn meta(id: &str, domain: &str) -> EmailMetadata {
    EmailMetadata {
        email_id: id.to_string(),
        from_domain: domain.to_string(),
        subject_length_bucket: SubjectLengthBucket::Medium,
        auth_partial_fail: false,
    }
}

proptest! {
    /// 脅威スコアは常に 0.0..=1.0
    #[test]
    fn threat_score_in_range(n in 1usize..=20) {
        let mut r = CampaignRadar::new();
        for i in 0..n { let _ = r.analyze(&meta(&format!("e{i}"), "evil.com")); }
        for g in r.groups() {
            prop_assert!((0.0..=1.0).contains(&g.threat_score));
        }
    }

    /// alertable は email_ids.len() >= 3 のときのみ
    #[test]
    fn alertable_iff_three_or_more(n in 0usize..=10) {
        let mut r = CampaignRadar::new();
        for i in 0..n { let _ = r.analyze(&meta(&format!("e{i}"), "evil.com")); }
        for g in r.groups() {
            prop_assert_eq!(g.is_alertable(), g.email_ids.len() >= 3);
        }
    }

    /// 同じ email_id は重複しない
    #[test]
    fn no_duplicate_ids(n in 1usize..=5) {
        let mut r = CampaignRadar::new();
        for _ in 0..n { let _ = r.analyze(&meta("same-id", "evil.com")); }
        for g in r.groups() {
            let unique: std::collections::HashSet<_> = g.email_ids.iter().collect();
            prop_assert_eq!(g.email_ids.len(), unique.len());
        }
    }

    /// 異なる送信ドメインは異なるグループに振り分けられる
    #[test]
    fn distinct_domains_form_distinct_groups(n in 1usize..=8) {
        let mut r = CampaignRadar::new();
        for i in 0..n { let _ = r.analyze(&meta(&format!("e{i}"), &format!("d{i}.com"))); }
        prop_assert_eq!(r.groups().len(), n);
    }
}
