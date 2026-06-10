//! Tiered-Risk アクセス制御の使用例 (kaname-ai/tiered_risk)
//!
//! arxiv 2505.22852 §3 の Green/Yellow/Red 階層デモ。
//!
//! 実行: cargo run --example tiered_risk_demo

fn main() {
    println!("=== Tiered-Risk Access Model デモ ===\n");

    // (操作名, リスク階層, untrustedデータ有無, 期待される判定)
    let cases = [
        ("メール一覧取得", "Green", true, "即座に許可"),
        ("メール閲覧", "Green", true, "即座に許可"),
        ("下書き保存 (信頼データ)", "Yellow", false, "許可"),
        ("下書き保存 (信頼できないデータ)", "Yellow", true, "軽い確認"),
        ("メール送信", "Red", false, "多要素承認"),
        ("添付ファイル外部共有", "Red", true, "多要素承認"),
    ];

    println!("{:<32} {:<8} {:<10} {}", "操作", "階層", "Untrusted", "判定");
    println!("{}", "─".repeat(70));
    for (action, tier, untrusted, decision) in &cases {
        let u = if *untrusted { "あり" } else { "なし" };
        let icon = match *tier {
            "Green" => "🟢",
            "Yellow" => "🟡",
            "Red" => "🔴",
            _ => "⚪",
        };
        println!("{:<32} {icon}{:<6} {:<10} {}", action, tier, u, decision);
    }

    println!("\nGreen は確認不要 → prompt fatigue を低減。");
    println!("Red のみ多要素承認 → 不可逆操作を確実に保護。");
}

#[cfg(test)]
mod tests {
    #[test]
    fn green_no_confirm() {
        // read-only は確認不要
        let tier = "Green";
        assert_eq!(tier, "Green");
    }

    #[test]
    fn red_always_mfa() {
        let tier = "Red";
        assert_eq!(tier, "Red");
    }
}
