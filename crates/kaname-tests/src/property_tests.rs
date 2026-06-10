// crates/kaname-bec/tests/property_tests.rs
//
// プロパティテスト (proptest)
//
// ユニットテストは「個別ケース」を検証するが、プロパティテストは
// 「全ての入力に対する不変条件」を検証する。
//
// 例: 「BEC スコアは常に 0.0..=1.0 の範囲内」
//     ユニットテストで 100 ケース検証しても、101 ケース目で破綻するかもしれない。
//     proptest は数千ケースを自動生成して反例を見つける。

use proptest::prelude::*;

// ── BEC スコアリング不変条件 ─────────────────────────────────────────────

#[allow(dead_code)]
fn evaluate_bec_score(from_addr: &str, subject: &str, body: &str) -> f32 {
    let mut score = 0.0f32;

    // 緊急性マーカー
    let urgency = ["至急", "urgent", "今すぐ", "本日中", "immediately"];
    for marker in &urgency {
        if subject.to_lowercase().contains(marker) || body.to_lowercase().contains(marker) {
            score += 0.15;
        }
    }

    // 振込パターン
    if subject.contains("振込") || subject.contains("口座変更") || subject.contains("wire") {
        score += 0.30;
    }

    // ドメイン疑惑 (簡易)
    let domain = from_addr.split('@').nth(1).unwrap_or("");
    let suspicious_domains = ["arnazon", "amaz0n", "g00gle", "rakuten-secure"];
    for d in &suspicious_domains {
        if domain.contains(d) { score += 0.40; break; }
    }

    score.min(1.0)
}

proptest! {
    /// 不変条件1: スコアは常に 0.0..=1.0
    #[test]
    fn bec_score_in_range(
        from in "[a-z]+@[a-z]+\\.(com|jp|net)",
        subject in ".{0,200}",
        body in ".{0,1000}"
    ) {
        let score = evaluate_bec_score(&from, &subject, &body);
        prop_assert!((0.0..=1.0).contains(&score),
            "score out of range: {} for from={}, subject={}", score, from, subject);
    }

    /// 不変条件2: 空入力でもパニックしない
    #[test]
    fn empty_inputs_no_panic(addr in "[a-z]+@example\\.com") {
        let _ = evaluate_bec_score(&addr, "", "");
        let _ = evaluate_bec_score("", "subject", "");
        let _ = evaluate_bec_score("", "", "");
    }

    /// 不変条件3: 同じ入力は同じスコアを返す (決定性)
    #[test]
    fn deterministic(
        from in "[a-z]+@[a-z]+\\.com",
        subject in ".{0,100}",
        body in ".{0,500}"
    ) {
        let s1 = evaluate_bec_score(&from, &subject, &body);
        let s2 = evaluate_bec_score(&from, &subject, &body);
        prop_assert_eq!(s1, s2);
    }

    /// 不変条件4: 単調性 — 既知の悪い特徴を追加するとスコアは下がらない
    #[test]
    fn adding_bad_features_does_not_decrease_score(
        from in "[a-z]+@example\\.com",
        base_subject in "[a-z ]{0,50}",
        body in ".{0,200}"
    ) {
        let baseline = evaluate_bec_score(&from, &base_subject, &body);

        // 緊急マーカーを追加
        let urgent_subject = format!("{}至急", base_subject);
        let with_urgent = evaluate_bec_score(&from, &urgent_subject, &body);

        prop_assert!(with_urgent >= baseline,
            "緊急マーカー追加でスコア低下: {} → {}", baseline, with_urgent);

        // 振込パターン追加
        let wire_subject = format!("{}振込", base_subject);
        let with_wire = evaluate_bec_score(&from, &wire_subject, &body);

        prop_assert!(with_wire >= baseline);
    }
}

// ── Levenshtein 距離の不変条件 ──────────────────────────────────────────

#[allow(dead_code)]
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let m = a.len();
    let n = b.len();
    if m == 0 { return n; }
    if n == 0 { return m; }
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for (i, row) in dp.iter_mut().enumerate() { row[0] = i; }
    for (j, cell) in dp[0].iter_mut().enumerate() { *cell = j; }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i-1] == b[j-1] {
                dp[i-1][j-1]
            } else {
                1 + dp[i-1][j].min(dp[i][j-1]).min(dp[i-1][j-1])
            };
        }
    }
    dp[m][n]
}

proptest! {
    /// 不変条件1: 同じ文字列の距離は 0
    #[test]
    fn levenshtein_self_is_zero(s in ".{0,100}") {
        prop_assert_eq!(levenshtein(&s, &s), 0);
    }

    /// 不変条件2: 距離は対称的 — d(a, b) == d(b, a)
    #[test]
    fn levenshtein_symmetric(a in ".{0,50}", b in ".{0,50}") {
        prop_assert_eq!(levenshtein(&a, &b), levenshtein(&b, &a));
    }

    /// 不変条件3: 距離は max(|a|, |b|) を超えない
    #[test]
    fn levenshtein_bounded(a in ".{0,50}", b in ".{0,50}") {
        let d = levenshtein(&a, &b);
        let max_len = a.chars().count().max(b.chars().count());
        prop_assert!(d <= max_len, "distance {} > max len {}", d, max_len);
    }

    /// 不変条件4: 距離は |a| - |b| 以上
    #[test]
    fn levenshtein_lower_bound(a in ".{0,50}", b in ".{0,50}") {
        let d = levenshtein(&a, &b);
        let len_diff = (a.chars().count() as i64 - b.chars().count() as i64).unsigned_abs() as usize;
        prop_assert!(d >= len_diff,
            "distance {} < length diff {}", d, len_diff);
    }

    /// 不変条件5: 三角不等式 — d(a, c) <= d(a, b) + d(b, c)
    #[test]
    fn levenshtein_triangle_inequality(
        a in ".{0,30}", b in ".{0,30}", c in ".{0,30}"
    ) {
        let ab = levenshtein(&a, &b);
        let bc = levenshtein(&b, &c);
        let ac = levenshtein(&a, &c);
        prop_assert!(ac <= ab + bc,
            "三角不等式違反: d(a,c)={} > d(a,b)+d(b,c)={}", ac, ab + bc);
    }
}

// ── タイポスクワッティング検出 ─────────────────────────────────────────

#[allow(dead_code)]
fn is_typosquat(legitimate: &str, suspect: &str) -> bool {
    let dist = levenshtein(legitimate, suspect);
    // 1〜3 文字の差で完全一致でない場合は疑わしい
    legitimate != suspect && (1..=3).contains(&dist)
}

proptest! {
    /// 不変条件: 同じドメインは typosquat ではない
    #[test]
    fn same_domain_not_typosquat(d in "[a-z]+\\.com") {
        prop_assert!(!is_typosquat(&d, &d));
    }

    /// 不変条件: 1 文字違いは typosquat として検出される (短すぎなければ)
    #[test]
    fn one_char_diff_detected(base in "[a-z]{8,15}\\.com") {
        // 最後の1文字を変更
        let mut chars: Vec<char> = base.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == 'a' { 'b' } else { 'a' };
        }
        let mutated: String = chars.iter().collect();

        if base != mutated {
            prop_assert!(is_typosquat(&base, &mutated),
                "1文字違いを検出失敗: {} vs {}", base, mutated);
        }
    }
}
