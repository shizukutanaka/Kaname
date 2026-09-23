//! Reply-To スプーフィング + 表示名詐称の検出。
//!
//! BEC の典型手口:
//! 1. **Reply-To スプーフィング** — `From: ceo@company.com` だが
//!    `Reply-To: ceo@gmail.com` で返信を横取り
//! 2. **表示名詐称** — `From: "CEO 山田" <attacker@evil.com>` で
//!    正規アドレスに見せかける

/// Reply-To スプーフィング + 表示名詐称の評価結果。
#[derive(Debug, PartialEq)]
pub struct SpoofAnalysis {
    /// Reply-To ドメインが From ドメインと一致しない (スプーフィング)。
    pub reply_to_domain_mismatch: bool,
    /// Reply-To のドメイン (不一致の場合のみ Some)。
    pub reply_to_domain: Option<String>,
    /// 表示名が既知の連絡先名と一致するが、メールアドレスのドメインが異なる。
    pub display_name_impersonation: bool,
    /// 詐称が疑われる表示名。
    pub suspicious_display_name: Option<String>,
    /// 表示名が有名ブランド名を名乗るが、送信ドメインがそのブランドの
    /// 正規ドメイン (またはそのサブドメイン) でない (ブランドなりすまし)。
    pub brand_impersonation: bool,
    /// なりすまされたブランド名 (詐称の場合のみ Some)。
    pub impersonated_brand: Option<String>,
    /// スコア寄与 (0.0..=1.0)。
    pub risk_score: f32,
}

impl SpoofAnalysis {
    /// リスクが高いか (スコア ≥ 0.6)。
    pub fn is_high_risk(&self) -> bool {
        self.risk_score >= 0.6
    }
}

/// Reply-To スプーフィングと表示名詐称を検出する。
///
/// # 引数
///
/// - `from_header`: RFC 5322 の From ヘッダー全体 (例: `"CEO 山田" <ceo@company.com>`)
/// - `reply_to_header`: Reply-To ヘッダー (省略可)
/// - `known_contacts`: 既知の連絡先 `(表示名, 期待ドメイン)` ペア一覧。
///   表示名が一致し**かつ**送信元ドメインが期待ドメインと異なる場合のみ詐称と判定する。
pub fn analyze_spoof(
    from_header: &str,
    reply_to_header: Option<&str>,
    known_contacts: &[(&str, &str)],
) -> SpoofAnalysis {
    let from_domain = extract_domain_from_header(from_header);
    let display_name = extract_display_name(from_header);

    // 1. Reply-To ドメイン不一致チェック
    let (reply_to_domain_mismatch, reply_to_domain) = if let Some(rt) = reply_to_header {
        let rt_domain = extract_domain_from_header(rt);
        match (&from_domain, &rt_domain) {
            (Some(fd), Some(rd)) if fd != rd => (true, Some(rd.clone())),
            _ => (false, None),
        }
    } else {
        (false, None)
    };

    // 2. 表示名詐称チェック
    // 表示名が既知連絡先と一致し、かつ送信元ドメインが期待ドメインと異なる場合のみ詐称。
    // 正規ドメインから送られた場合 (from_domain == expected_domain) は詐称ではない。
    let display_name_impersonation =
        if let (Some(ref name), Some(ref fd)) = (&display_name, &from_domain) {
            // ホモグリフを畳み込んでから比較する。`to_lowercase()` だけでは
            // `"СЕО 山田"` (Cyrillic С/Е/О) が `"CEO 山田"` と一致せず、
            // 視覚的に同一の表示名によるなりすましを素通りさせていた。
            // 2025-2026 の観測ではホモグリフ悪用の主戦場が URL から
            // From ヘッダーの表示名へ移っている (crate::idn_homograph 参照)。
            let folded = crate::idn_homograph::fold_homoglyphs(name);
            let name_lower = folded.trim();
            known_contacts.iter().any(|(known_name, expected_domain)| {
                let known_lower = crate::idn_homograph::fold_homoglyphs(known_name);
                let name_matches = name_lower == known_lower.trim()
                    || name_lower.contains(known_lower.trim())
                    || known_lower.trim().contains(name_lower);
                // 名前が一致し、かつ送信元ドメインが期待ドメインと異なれば詐称
                name_matches && fd != &expected_domain.to_lowercase().trim().to_string()
            })
        } else {
            false
        };

    // 3. ブランドなりすましチェック
    // 表示名が有名ブランド名を名乗るが、送信ドメインがそのブランドの
    // 正規ドメイン (またはサブドメイン) でない場合。
    // `From: "PayPal Support" <attacker@evil.xyz>` — 表示名は自由記述で
    // ユーザーはブランド名を差出人と誤認する (display name spoofing —
    // Valimail/Avanan/Proofpoint 各社が BEC 常用手口として報告)。
    // 既知連絡先に依存しない汎用検出として、ブランド語彙と正規ドメイン
    // マッピングで検査する。
    let mut brand_impersonation = false;
    let mut impersonated_brand = None;
    if let (Some(ref name), Some(ref fd)) = (&display_name, &from_domain) {
        if let Some((brand, _)) = detect_brand_impersonation(name, fd) {
            brand_impersonation = true;
            impersonated_brand = Some(brand.to_string());
        }
    }

    // スコア計算
    let mut score = 0.0f32;
    if reply_to_domain_mismatch {
        score += 0.5;
        // フリーメールドメインへの Reply-To は特に危険
        if let Some(ref rd) = reply_to_domain {
            if is_free_mail_domain(rd) {
                score += 0.2;
            }
        }
    }
    if display_name_impersonation {
        score += 0.3;
    }
    if brand_impersonation {
        // ブランド名を名乗る表示名は強いなりすまし兆候。
        // 送信元がフリーメールドメインの場合はさらに危険。
        score += 0.35;
        if let Some(ref fd) = from_domain {
            if is_free_mail_domain(fd) {
                score += 0.15;
            }
        }
    }

    SpoofAnalysis {
        reply_to_domain_mismatch,
        reply_to_domain,
        display_name_impersonation,
        suspicious_display_name: if display_name_impersonation {
            display_name
        } else {
            None
        },
        brand_impersonation,
        impersonated_brand,
        risk_score: score.min(1.0),
    }
}

/// フリーメールドメインか判定 (Reply-To がフリーメールなら高リスク)。
fn is_free_mail_domain(domain: &str) -> bool {
    let d = domain.to_lowercase();
    matches!(
        d.as_str(),
        "gmail.com"
            | "yahoo.com"
            | "yahoo.co.jp"
            | "hotmail.com"
            | "outlook.com"
            | "live.com"
            | "icloud.com"
            | "protonmail.com"
            | "yandex.com"
            | "aol.com"
    )
}

// ============================================================================
// ブランドなりすまし検出 (D163)
// ============================================================================

/// 有名ブランド → 正規ドメイン一覧。
///
/// 表示名に現れるブランド名と、そのブランドが本来使う送信ドメインの対応表。
/// BEC/フィッシングで最も悪用されるブランド群 (APWG 報告・各社観測) と、
/// 日本の利用者を狙う主要サービスを含める。
/// サブドメインからの送信も正規扱いとするため、比較は
/// `sender == domain || sender.ends_with("."+domain)` で行う。
const BRAND_DOMAINS: &[(&str, &[&str])] = &[
    ("microsoft", &["microsoft.com", "microsoft.net", "office.com", "live.com", "microsoftonline.com"]),
    ("office365", &["microsoft.com", "office.com", "microsoftonline.com"]),
    ("outlook", &["outlook.com", "microsoft.com", "live.com", "microsoftonline.com"]),
    ("google", &["google.com", "googlemail.com"]),
    ("gmail", &["google.com", "gmail.com", "googlemail.com"]),
    ("amazon", &["amazon.com", "amazon.co.jp", "aws.com", "amazonses.com"]),
    ("apple", &["apple.com", "icloud.com"]),
    ("paypal", &["paypal.com"]),
    ("linkedin", &["linkedin.com"]),
    ("dropbox", &["dropbox.com"]),
    ("docusign", &["docusign.com", "docusign.net"]),
    ("salesforce", &["salesforce.com"]),
    ("zoom", &["zoom.us"]),
    ("netflix", &["netflix.com"]),
    ("facebook", &["facebook.com", "fb.com", "meta.com"]),
    ("instagram", &["instagram.com", "facebook.com", "meta.com"]),
    ("whatsapp", &["whatsapp.com", "facebook.com", "meta.com"]),
    ("yahoo", &["yahoo.com", "yahoo.co.jp"]),
    ("rakuten", &["rakuten.co.jp", "rakuten.com"]),
    ("mercari", &["mercari.com", "mercari.jp"]),
];

/// 表示名に含まれるブランド名を検出し、ブランド名と正規ドメインを返す。
///
/// 検出しない条件:
/// - 送信ドメインがそのブランドの正規ドメイン (またはそのサブドメイン)
/// - ブランド名がトークン境界を持たない部分一致 (`"applebee"` ≠ `"apple"`)
///
/// トークンは ASCII 数字→対応文字の正規化 (`0`→`o`、`1`→`l`、`3`→`e`、
/// `5`→`s`、`7`→`t`) とホモグリフ畳み込みで比較する。
/// `"micr0soft"`・`"PаyPal"` (Cyrillic) のような表記ゆれも捕捉する。
fn detect_brand_impersonation(
    display_name: &str,
    from_domain: &str,
) -> Option<(&'static str, &'static [&'static str])> {
    let folded_name = crate::idn_homograph::fold_homoglyphs(display_name);
    // ブランド名は半角英数字のみ — トークンをそれに限定して取り出す。
    for token in folded_name.split(|c: char| !c.is_ascii_alphanumeric()) {
        let norm = normalize_brand_token(token);
        if norm.len() < 4 {
            continue;
        }
        for &(brand, domains) in BRAND_DOMAINS {
            if norm == brand || (norm.len() >= 5 && levenshtein1(&norm, brand)) {
                if !sender_within_brand_domains(from_domain, domains) {
                    return Some((brand, domains));
                }
            }
        }
    }
    None
}

/// 送信ドメインがブランドの正規ドメインのいずれか (またはサブドメイン) か。
fn sender_within_brand_domains(from_domain: &str, domains: &[&str]) -> bool {
    domains.iter().any(|d| {
        from_domain == *d
            || from_domain
                .strip_suffix(d)
                .is_some_and(|head| head.ends_with('.'))
    })
}

/// ブランド名比較用のトークン正規化 — 小文字化 + 数字→対応英字変換。
/// `"micr0soft"`→`"microsoft"`、`"paypa1"`→`"paypal"` のような
/// 視覚的な数字置換を吸収する。
fn normalize_brand_token(token: &str) -> String {
    token
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | '!' | '|' => 'l',
            '3' => 'e',
            '5' | '$' => 's',
            '7' => 't',
            '8' => 'b',
            '@' => 'a',
            _ => c,
        })
        .collect::<String>()
        .to_lowercase()
}

/// 二つの文字列のレーベンシュタイン距離がちょうど 1 のとき true。
/// 短いブランド名 (`"micrsoft"`, `"paypa"`) の 1 文字タイポを捕捉する。
/// `lib.rs` の `levenshtein1` と同一アルゴリズム (プライベートのため複製)。
fn levenshtein1(a: &str, b: &str) -> bool {
    const MAX: usize = 64;
    if a.chars().count() > MAX || b.chars().count() > MAX {
        return false;
    }
    let al: Vec<char> = a.chars().collect();
    let bl: Vec<char> = b.chars().collect();
    let diff = (al.len() as isize - bl.len() as isize).abs();
    if diff > 1 {
        return false;
    }
    if al.len() == bl.len() {
        // 同じ長さ: 置換のみ
        let diffs = al.iter().zip(bl.iter()).filter(|(x, y)| x != y).count();
        diffs == 1
    } else {
        // 1 つずれ: 挿入/削除
        let (long, short) = if al.len() > bl.len() { (&al, &bl) } else { (&bl, &al) };
        let mut i = 0;
        let mut j = 0;
        let mut used = false;
        while i < short.len() && j < long.len() {
            if short[i] == long[j] {
                i += 1;
                j += 1;
            } else {
                if used {
                    return false;
                }
                used = true;
                j += 1;
            }
        }
        true
    }
}

/// ヘッダー文字列からドメイン部分を抽出する。
///
/// `"Display Name" <user@domain.com>` または `user@domain.com` に対応。
fn extract_domain_from_header(header: &str) -> Option<String> {
    let email = if let Some(start) = header.rfind('<') {
        let end = header.rfind('>')?;
        if end > start {
            &header[start + 1..end]
        } else {
            return None;
        }
    } else {
        header.trim()
    };

    let at = email.rfind('@')?;
    Some(email[at + 1..].trim().to_lowercase())
}

/// ヘッダーから表示名を抽出する。
///
/// `"表示名" <email>` → `Some("表示名")`
/// `<email>` または `email` → `None`
fn extract_display_name(header: &str) -> Option<String> {
    let lt_pos = header.find('<')?;
    let name_part = header[..lt_pos].trim();
    if name_part.is_empty() {
        return None;
    }
    // クォートを除去
    let name = name_part.trim_matches('"').trim_matches('\'').trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_email_no_risk() {
        // 正規ドメインから送られた CEO 山田 は詐称ではない
        let result = analyze_spoof(
            "\"CEO 山田\" <ceo@company.com>",
            None,
            &[("CEO 山田", "company.com")],
        );
        assert!(!result.reply_to_domain_mismatch);
        assert!(
            !result.display_name_impersonation,
            "正規ドメインからの送信は詐称ではない"
        );
        assert_eq!(result.risk_score, 0.0);
    }

    #[test]
    fn reply_to_different_domain_is_suspicious() {
        let result = analyze_spoof("\"CEO 山田\" <ceo@company.com>", Some("ceo@gmail.com"), &[]);
        assert!(result.reply_to_domain_mismatch);
        assert_eq!(result.reply_to_domain.as_deref(), Some("gmail.com"));
        assert!(result.risk_score >= 0.5);
    }

    #[test]
    fn reply_to_free_mail_increases_score() {
        let result = analyze_spoof("ceo@company.com", Some("ceo@gmail.com"), &[]);
        assert!(result.reply_to_domain_mismatch);
        assert!(
            result.risk_score >= 0.7,
            "フリーメール Reply-To はスコア 0.7 以上: {}",
            result.risk_score
        );
        assert!(result.is_high_risk());
    }

    #[test]
    fn reply_to_same_domain_is_ok() {
        let result = analyze_spoof("alice@company.com", Some("alice@company.com"), &[]);
        assert!(!result.reply_to_domain_mismatch);
        assert_eq!(result.risk_score, 0.0);
    }

    #[test]
    fn display_name_impersonation_detected() {
        // 既知の CEO 山田 が evil.com から送信 → 詐称
        let result = analyze_spoof(
            "\"CEO 山田\" <attacker@evil.com>",
            None,
            &[("CEO 山田", "company.com"), ("CFO 鈴木", "company.com")],
        );
        assert!(result.display_name_impersonation);
        assert!(result.risk_score > 0.0);
    }

    #[test]
    fn cyrillic_homoglyph_display_name_impersonation_detected() {
        // 回帰: 表示名にキリル文字ホモグリフを使うと to_lowercase() 比較を
        // 完全に回避できていた。"СЕО" は Cyrillic С(U+0421)/Е(U+0415)/О(U+041E) で
        // 人間には ASCII "CEO" と区別できないが、従来は一致せず素通りしていた。
        let result = analyze_spoof(
            "\"\u{0421}\u{0415}\u{041E} 山田\" <attacker@evil.com>",
            None,
            &[("CEO 山田", "company.com")],
        );
        assert!(
            result.display_name_impersonation,
            "キリル文字ホモグリフによる表示名なりすましが検出されていない: {result:?}"
        );
    }

    #[test]
    fn fullwidth_display_name_impersonation_detected() {
        // 全角ラテンによる回避も畳み込みで検出されるべき
        let result = analyze_spoof(
            "\"\u{FF23}\u{FF25}\u{FF2F} 山田\" <attacker@evil.com>",
            None,
            &[("CEO 山田", "company.com")],
        );
        assert!(
            result.display_name_impersonation,
            "全角ラテンによる表示名なりすましが検出されていない: {result:?}"
        );
    }

    #[test]
    fn homoglyph_fold_does_not_create_false_positive() {
        // 畳み込みによって無関係な表示名が誤って一致してはならない
        let result = analyze_spoof(
            "\"経理部 佐藤\" <keiri@partner.co.jp>",
            None,
            &[("CEO 山田", "company.com")],
        );
        assert!(
            !result.display_name_impersonation,
            "無関係な表示名を誤検出した: {result:?}"
        );
    }

    #[test]
    fn display_name_impersonation_false_positive_fixed() {
        // 正規ドメインからなら詐称ではない (修正前はここが false positive だった)
        let result = analyze_spoof(
            "\"CEO 山田\" <ceo@company.com>",
            None,
            &[("CEO 山田", "company.com")],
        );
        assert!(
            !result.display_name_impersonation,
            "正規ドメインは詐称ではない"
        );
    }

    #[test]
    fn display_name_unknown_no_impersonation() {
        let result = analyze_spoof(
            "\"Unknown Person\" <unknown@evil.com>",
            None,
            &[("CEO 山田", "company.com")],
        );
        assert!(!result.display_name_impersonation);
    }

    #[test]
    fn domain_extraction_with_display_name() {
        assert_eq!(
            extract_domain_from_header("\"CEO\" <ceo@company.com>"),
            Some("company.com".to_string())
        );
    }

    #[test]
    fn domain_extraction_bare_email() {
        assert_eq!(
            extract_domain_from_header("ceo@company.com"),
            Some("company.com".to_string())
        );
    }

    #[test]
    fn display_name_extraction() {
        assert_eq!(
            extract_display_name("\"CEO 山田\" <ceo@company.com>"),
            Some("CEO 山田".to_string())
        );
        assert_eq!(extract_display_name("<ceo@company.com>"), None);
        assert_eq!(extract_display_name("ceo@company.com"), None);
    }

    #[test]
    fn combined_reply_to_and_display_name_is_very_high_risk() {
        let result = analyze_spoof(
            "\"CEO 山田\" <attacker@evil.com>",
            Some("attacker@gmail.com"),
            &[("CEO 山田", "company.com")],
        );
        assert!(result.reply_to_domain_mismatch);
        assert!(result.display_name_impersonation);
        assert!(result.is_high_risk());
    }

    #[test]
    fn free_mail_domain_detection() {
        assert!(is_free_mail_domain("gmail.com"));
        assert!(is_free_mail_domain("YAHOO.CO.JP"));
        assert!(!is_free_mail_domain("company.com"));
    }

    // ── D163: ブランドなりすまし ──────────────────────────────────────────

    #[test]
    fn brand_impersonation_paypal_detected() {
        let result = analyze_spoof(
            "\"PayPal Support\" <attacker@evil.xyz>",
            None,
            &[],
        );
        assert!(result.brand_impersonation);
        assert_eq!(result.impersonated_brand.as_deref(), Some("paypal"));
    }

    #[test]
    fn brand_impersonation_microsoft_detected() {
        let result = analyze_spoof(
            "\"Microsoft アカウントチーム\" <notice@secure-login.xyz>",
            None,
            &[],
        );
        assert!(result.brand_impersonation);
        assert_eq!(result.impersonated_brand.as_deref(), Some("microsoft"));
    }

    #[test]
    fn brand_impersonation_japanese_rakuten_detected() {
        let result = analyze_spoof(
            "\"楽天カード Rakuten\" <info@billing-alert.top>",
            None,
            &[],
        );
        assert!(result.brand_impersonation);
        assert_eq!(result.impersonated_brand.as_deref(), Some("rakuten"));
    }

    #[test]
    fn brand_legit_domain_is_clean() {
        // 正規ドメイン (サブドメイン含む) からの送信は詐称ではない
        for from in [
            "\"PayPal\" <service@paypal.com>",
            "\"Microsoft Teams\" <noreply@teams.microsoft.com>",
            "\"Amazon.co.jp\" <auto-confirm@amazon.co.jp>",
            "\"Apple\" <no_reply@email.apple.com>",
            "\"AWS\" <no-reply@aws.com>",
        ] {
            let result = analyze_spoof(from, None, &[]);
            assert!(
                !result.brand_impersonation,
                "正規ドメインからの送信を誤検出: {from}"
            );
        }
    }

    #[test]
    fn brand_free_mail_sender_bonus_score() {
        // フリーメールドメインからブランド名を名乗る場合はより危険
        let spoofed = analyze_spoof("\"PayPal\" <attacker@gmail.com>", None, &[]);
        assert!(spoofed.brand_impersonation);
        assert!(
            spoofed.risk_score >= 0.5,
            "フリーメール + ブランドなりすましは高スコア: {}",
            spoofed.risk_score
        );
    }

    #[test]
    fn brand_digit_substitution_detected() {
        // micr0soft, paypa1 等の数字置換
        for name in ["micr0soft", "paypa1", "amaz0n", "g00gle"] {
            let from = format!("\"{name}\" <attacker@evil.xyz>");
            let result = analyze_spoof(&from, None, &[]);
            assert!(
                result.brand_impersonation,
                "数字置換ブランド名を検出できない: {name}"
            );
        }
    }

    #[test]
    fn brand_cyrillic_homoglyph_detected() {
        // Cyrillic 'а' (U+0430) を含む "PаyPal"
        let result = analyze_spoof(
            "\"P\u{0430}yPal\" <attacker@evil.xyz>",
            None,
            &[],
        );
        assert!(result.brand_impersonation);
        assert_eq!(result.impersonated_brand.as_deref(), Some("paypal"));
    }

    #[test]
    fn brand_one_char_typo_detected() {
        // 1 文字タイポも捕捉 (levenshtein-1)
        for name in ["micrsoft", "paypa", "netflx", "amazn"] {
            let from = format!("\"{name}\" <attacker@evil.xyz>");
            let result = analyze_spoof(&from, None, &[]);
            assert!(
                result.brand_impersonation,
                "1文字タイポを検出できない: {name}"
            );
        }
    }

    #[test]
    fn brand_partial_token_no_match() {
        // "applebee" は "apple" ではない — トークン境界が必要
        let result = analyze_spoof(
            "\"Applebee Support\" <info@applebee.com>",
            None,
            &[],
        );
        assert!(!result.brand_impersonation);
    }

    #[test]
    fn brand_non_brand_display_name_clean() {
        let result = analyze_spoof(
            "\"経理部 佐藤\" <keiri@partner.co.jp>",
            None,
            &[],
        );
        assert!(!result.brand_impersonation);
        assert!(result.impersonated_brand.is_none());
    }

    #[test]
    fn brand_name_in_middle_of_text_detected() {
        // テキスト中にブランド名を含む表示名
        let result = analyze_spoof(
            "\"PayPal セキュリティセンター\" <alert@secure-check.xyz>",
            None,
            &[],
        );
        assert!(result.brand_impersonation);
        assert_eq!(result.impersonated_brand.as_deref(), Some("paypal"));
    }

    #[test]
    fn brand_subdomain_of_brand_clean() {
        // ブランドの正規ドメインの深いサブドメインは正規扱い
        let result = analyze_spoof(
            "\"PayPal\" <noreply@mail.paypal.com>",
            None,
            &[],
        );
        assert!(!result.brand_impersonation);
    }

    #[test]
    fn brand_suffix_attack_flagged() {
        // paypal.com.evil.com — サフィックスで見せかけるがブランドドメインではない
        let result = analyze_spoof(
            "\"PayPal\" <x@paypal.com.evil.xyz>",
            None,
            &[],
        );
        assert!(result.brand_impersonation);
    }

    #[test]
    fn brand_case_insensitive() {
        let result = analyze_spoof("\"PAYPAL\" <attacker@evil.xyz>", None, &[]);
        assert!(result.brand_impersonation);
    }
}
