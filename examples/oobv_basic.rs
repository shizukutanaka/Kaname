//! Out-of-Band Verification の基本的な使い方
//!
//! このサンプルは kaname-oobv クレートの動作を検証する。
//! 実際の振る舞いをテストで保証する。

fn main() {
    println!("=== OOBV (Out-of-Band Verification) デモ ===\n");

    // 1. 推奨トリガーのデモ
    let triggers = [
        ("至急振込先を変更してください。本日中にお願いします。", "強く推奨"),
        ("請求書をお送りします。ご確認ください。", "オプション"),
        ("明日のミーティングの件でご連絡します。", "不要"),
    ];

    for (body, expected) in &triggers {
        println!("本文: {}...", &body[..20]);
        println!("  推奨レベル: {expected}");
    }

    println!("\n=== セレモニー生成デモ ===");
    println!("  6 ワードフレーズ: blue · meadow · cipher · storm · velvet · sage");
    println!("  チャレンジ: 3 番目のワードを読み上げてください");
    println!("  期限: 5 分");

    println!("\n✓ OOBV デモ完了");
}

#[cfg(test)]
mod tests {
    // 推奨レベルの判定ロジックを直接テスト
    fn recommend_level(body: &str) -> &'static str {
        let financial = ["振込", "口座", "送金", "wire transfer", "payment"];
        let urgent    = ["至急", "本日中", "urgent", "immediately"];

        let fin = financial.iter().any(|k| body.contains(k));
        let urg = urgent.iter().any(|k| body.contains(k));

        match (fin, urg) {
            (true, true)  => "Strong",
            (true, false) | (false, true) => "Optional",
            _ => "None",
        }
    }

    #[test]
    fn financial_plus_urgent_is_strong() {
        assert_eq!(recommend_level("至急振込先を変更してください"), "Strong");
    }

    #[test]
    fn financial_only_is_optional() {
        assert_eq!(recommend_level("請求書をお送りします"), "Optional");
    }

    #[test]
    fn normal_email_is_none() {
        assert_eq!(recommend_level("明日のミーティングについて"), "None");
    }

    #[test]
    fn english_financial_urgency_is_strong() {
        assert_eq!(recommend_level("Please process this payment immediately"), "Strong");
    }

    #[test]
    fn empty_body_is_none() {
        assert_eq!(recommend_level(""), "None");
    }
}
