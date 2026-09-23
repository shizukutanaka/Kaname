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
    /// From アドレスのローカル部がドメイン形をなす場合の、
    /// 見せかけのドメイントークン (例: `paypal.com@evil.example` の
    /// `paypal.com`)。表示名詐称とは独立のベクター — 表示名を
    /// 見ないクライアントや一覧表示でもアドレスの左側は常に
    /// 見えるため、ここを既知ドメイン形にして「正規発信元」らしく
    /// 見せる手口 (BEC の local part spoofing として Agari/
    /// IRONSCALES 系レポートで観測)。
    pub local_part_domain_mimicry: Option<String>,
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

    // 3. ローカル部ドメイン偽装チェック
    // `paypal.com@evil.example` のようにローカル部自体をドメイン形に
    // する手口。ローカル部の末尾が既知のパブリックサフィックス系
    // ラベルで終わるドット付きトークンを「見せかけドメイン」とみなす。
    // ローカル部がそのまま実送信ドメインと同じ場合 (例:
    // `paypal.com@paypal.com`) は偽装ではない。
    let local_part_domain_mimicry = extract_addr_spec(from_header)
        .and_then(|addr| addr.rfind('@').map(|at| addr[..at].to_string()))
        .and_then(|local| mimicked_domain_token(&local))
        .filter(|mimic| from_domain.as_deref() != Some(mimic.as_str()));

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
    if local_part_domain_mimicry.is_some() {
        score += 0.3;
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
        local_part_domain_mimicry,
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

/// ヘッダーから addr-spec (`user@domain`) を抽出する。
fn extract_addr_spec(header: &str) -> Option<String> {
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
    let trimmed = email.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// ローカル部が「見せかけのドメイン」かどうかを判定し、
/// 該当する場合はそのドメイン形トークンを返す。
///
/// ローカル部 (`@` の前) がドットを含み、末尾が既知の
/// パブリックサフィックス系ラベルで終わる場合にドメイン形と
/// みなす — `paypal.com` / `support.paypal.com` / `secure-login.net`
/// のような見せかけ送信元を捕捉する。`john.doe` (末尾が
/// サフィックスでない人名形) や `reply.to` (非サフィックス) は
/// 誤検出しない。
fn mimicked_domain_token(local: &str) -> Option<String> {
    let l = local
        .trim_matches(|c| matches!(c, '"' | '\''))
        .to_lowercase();
    if !l.contains('.') {
        return None;
    }
    let last = l.rsplit('.').next()?;
    // 末尾が既知サフィックスでなければドメイン形でない
    const KNOWN_SUFFIXES: &[&str] = &[
        "com", "net", "org", "jp", "io", "app", "dev", "info", "biz", "me", "co", "de", "uk", "au",
        "fr", "ru", "cn", "kr", "br", "in", "it", "es", "nl", "se", "ch", "us", "ca", "xyz", "top",
        "site", "online",
    ];
    if !KNOWN_SUFFIXES.contains(&last) {
        return None;
    }
    // 先頭ラベルも必要 — `.com` だけのローカル部はドメイン形でない
    if l.split('.').count() < 2 || l.split('.').next().is_none_or(|f| f.is_empty()) {
        return None;
    }
    Some(l)
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

    // ---- D172: ローカル部ドメイン偽装 ----

    #[test]
    fn local_part_domain_mimicry_detected() {
        // paypal.com@evil.example — ローカル部がドメイン形
        let result = analyze_spoof("paypal.com@evil.example", None, &[]);
        assert_eq!(
            result.local_part_domain_mimicry.as_deref(),
            Some("paypal.com")
        );
        assert!(result.risk_score >= 0.3);
    }

    #[test]
    fn local_part_subdomain_mimicry_detected() {
        let result = analyze_spoof("\"PayPal\" <support.paypal.com@evil.example>", None, &[]);
        assert!(result.local_part_domain_mimicry.is_some());
    }

    #[test]
    fn local_part_matching_own_domain_not_flagged() {
        // paypal.com@paypal.com — 見せかけでも実ドメインでも同じ
        let result = analyze_spoof("paypal.com@paypal.com", None, &[]);
        assert!(result.local_part_domain_mimicry.is_none());
    }

    #[test]
    fn normal_local_part_not_flagged() {
        for h in [
            "john.doe@company.com",
            "support@example.net",
            "noreply@list.co.jp",
            "user.name+tag@mail.io",
            "a.b@x.com",
        ] {
            let r = analyze_spoof(h, None, &[]);
            assert!(
                r.local_part_domain_mimicry.is_none(),
                "{h} should not be flagged"
            );
        }
    }

    #[test]
    fn quoted_from_addr_local_part_mimicry() {
        let r = analyze_spoof("\"営業部\" <secure-login.net@bad.xyz>", None, &[]);
        assert_eq!(
            r.local_part_domain_mimicry.as_deref(),
            Some("secure-login.net")
        );
    }
}
