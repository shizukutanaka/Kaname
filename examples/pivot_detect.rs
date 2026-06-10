//! Cross-Channel Pivot Detection の使用例
//!
//! メール本文に埋め込まれた「別チャネルへの誘導」を検出する。

fn main() {
    println!("=== Pivot Detection Example ===\n");

    let emails = vec![
        "Please join our Teams meeting: https://teams.microsoft.com/l/meetup-join/abc",
        "Call me urgently: 080-1234-5678",
        "Review the Slack thread: https://slack.com/archives/C12345",
        "Normal message with no pivot patterns",
        "Zoom meeting: https://zoom.us/j/123456789",
        "Bitcoin wallet: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    ];

    for (i, email) in emails.iter().enumerate() {
        let pivots = detect_pivots(email);
        println!("Email {}: {:.50}...", i + 1, email);
        if pivots.is_empty() {
            println!("  → Pivot なし");
        } else {
            for p in &pivots { println!("  → Pivot 検出: {p}"); }
        }
        println!();
    }
}

fn detect_pivots(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut found = Vec::new();

    if lower.contains("teams.microsoft.com") { found.push("Microsoft Teams".into()); }
    if lower.contains("slack.com/archives") || lower.contains("slack.com/join") {
        found.push("Slack".into());
    }
    if lower.contains("zoom.us/j/") { found.push("Zoom Meeting".into()); }
    if lower.contains("meet.google.com") { found.push("Google Meet".into()); }

    // 日本の電話番号パターン
    if text.contains("080-") || text.contains("090-") || text.contains("070-") ||
       text.contains("03-") || text.contains("06-") {
        found.push("電話番号".into());
    }

    // 暗号通貨ウォレット
    if text.starts_with("bc1") || text.contains(" bc1") || text.contains("0x") {
        found.push("暗号通貨ウォレット".into());
    }

    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_teams_link() {
        let r = detect_pivots("Join https://teams.microsoft.com/l/meetup-join/abc");
        assert!(r.iter().any(|s| s.contains("Teams")));
    }

    #[test]
    fn detects_slack_link() {
        let r = detect_pivots("See https://slack.com/archives/C12345");
        assert!(r.iter().any(|s| s.contains("Slack")));
    }

    #[test]
    fn detects_zoom_link() {
        let r = detect_pivots("Zoom: https://zoom.us/j/987654321");
        assert!(r.iter().any(|s| s.contains("Zoom")));
    }

    #[test]
    fn detects_japanese_phone() {
        let r = detect_pivots("電話ください: 080-1234-5678");
        assert!(r.iter().any(|s| s.contains("電話")));
    }

    #[test]
    fn no_pivot_in_normal_email() {
        let r = detect_pivots("Would you like to meet for coffee tomorrow?");
        assert!(r.is_empty(), "普通のメールに pivot なし: {:?}", r);
    }

    #[test]
    fn detects_crypto_wallet() {
        let r = detect_pivots("Send to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh");
        assert!(r.iter().any(|s| s.contains("暗号")));
    }

    #[test]
    fn multiple_pivots_in_one_email() {
        let r = detect_pivots(
            "Call 090-1111-2222 or join https://teams.microsoft.com/abc"
        );
        assert!(r.len() >= 2, "複数の pivot が検出されるはず: {:?}", r);
    }
}
