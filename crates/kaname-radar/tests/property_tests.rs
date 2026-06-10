//! kaname-radar プロパティテスト

use proptest::prelude::*;
use kaname_radar::{CampaignRadar, EmailMetadata, extract_sld};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn meta(id: &str, domain: &str) -> EmailMetadata {
    EmailMetadata {
        email_id: id.to_string(),
        from_domain: domain.to_string(),
        return_path_domain: None,
        dkim_domain: None,
        link_domains: vec![],
        received_at: now_unix(),
    }
}

proptest! {
    /// 脅威スコアは常に 0.0..=1.0
    #[test]
    fn threat_score_in_range(n in 1usize..=20) {
        let mut r = CampaignRadar::new();
        r.register_domain("evil.com", "infra-x");
        for i in 0..n { r.analyze(&meta(&format!("e{i}"), "evil.com")); }
        for g in r.groups() {
            prop_assert!((0.0..=1.0).contains(&g.threat_score));
        }
    }

    /// alertable は email_ids.len() >= 3 のときのみ
    #[test]
    fn alertable_iff_three_or_more(n in 0usize..=10) {
        let mut r = CampaignRadar::new();
        r.register_domain("evil.com", "infra-y");
        for i in 0..n { r.analyze(&meta(&format!("e{i}"), "evil.com")); }
        for g in r.groups() {
            prop_assert_eq!(g.is_alertable(), g.email_ids.len() >= 3);
        }
    }

    /// 同じ email_id は重複しない
    #[test]
    fn no_duplicate_ids(n in 1usize..=5) {
        let mut r = CampaignRadar::new();
        r.register_domain("evil.com", "infra-z");
        for _ in 0..n { r.analyze(&meta("same-id", "evil.com")); }
        for g in r.groups() {
            let unique: std::collections::HashSet<_> = g.email_ids.iter().collect();
            prop_assert_eq!(g.email_ids.len(), unique.len());
        }
    }

    /// extract_sld は常に空でなく元以下の長さ
    #[test]
    fn sld_length(domain in "[a-z]{2,8}\\.[a-z]{2,4}") {
        let sld = extract_sld(&domain);
        prop_assert!(!sld.is_empty());
        prop_assert!(sld.len() <= domain.len());
    }
}
