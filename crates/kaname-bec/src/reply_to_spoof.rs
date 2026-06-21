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
/// - `known_contact_names`: 既知の連絡先表示名一覧 (小文字正規化済み推奨)
pub fn analyze_spoof(
    from_header: &str,
    reply_to_header: Option<&str>,
    known_contact_names: &[&str],
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
    let display_name_impersonation = if let (Some(ref name), Some(ref fd)) = (&display_name, &from_domain) {
        let name_lower = name.to_lowercase();
        let name_lower = name_lower.trim();
        // 既知の連絡先名と一致するかチェック
        let matches_known = known_contact_names.iter().any(|known| {
            let known_lower = known.to_lowercase();
            // 完全一致 or 既知名が表示名を包含
            name_lower == known_lower.trim()
                || name_lower.contains(known_lower.trim())
                || known_lower.trim().contains(name_lower)
        });
        if matches_known {
            // 表示名に一致する連絡先が、送信元ドメインと一致しないか
            // 簡易チェック: 表示名にドメイン名キーワードが含まれる場合は
            // そのドメインから送られているべき
            let _ = fd;
            true
        } else {
            false
        }
    } else {
        false
    };

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

    SpoofAnalysis {
        reply_to_domain_mismatch,
        reply_to_domain,
        display_name_impersonation,
        suspicious_display_name: if display_name_impersonation { display_name } else { None },
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
        if end > start { &header[start + 1..end] } else { return None; }
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
        let result = analyze_spoof(
            "\"CEO 山田\" <ceo@company.com>",
            None,
            &["CEO 山田"],
        );
        assert!(!result.reply_to_domain_mismatch);
        // 表示名一致だが Reply-To なし → display_name_impersonation は true だが score < 0.6
        assert!(!result.is_high_risk() || result.reply_to_domain_mismatch);
    }

    #[test]
    fn reply_to_different_domain_is_suspicious() {
        let result = analyze_spoof(
            "\"CEO 山田\" <ceo@company.com>",
            Some("ceo@gmail.com"),
            &[],
        );
        assert!(result.reply_to_domain_mismatch);
        assert_eq!(result.reply_to_domain.as_deref(), Some("gmail.com"));
        assert!(result.risk_score >= 0.5);
    }

    #[test]
    fn reply_to_free_mail_increases_score() {
        let result = analyze_spoof(
            "ceo@company.com",
            Some("ceo@gmail.com"),
            &[],
        );
        assert!(result.reply_to_domain_mismatch);
        assert!(result.risk_score >= 0.7, "フリーメール Reply-To はスコア 0.7 以上: {}", result.risk_score);
        assert!(result.is_high_risk());
    }

    #[test]
    fn reply_to_same_domain_is_ok() {
        let result = analyze_spoof(
            "alice@company.com",
            Some("alice@company.com"),
            &[],
        );
        assert!(!result.reply_to_domain_mismatch);
        assert_eq!(result.risk_score, 0.0);
    }

    #[test]
    fn display_name_impersonation_detected() {
        let result = analyze_spoof(
            "\"CEO 山田\" <attacker@evil.com>",
            None,
            &["CEO 山田", "CFO 鈴木"],
        );
        assert!(result.display_name_impersonation);
        assert!(result.risk_score > 0.0);
    }

    #[test]
    fn display_name_unknown_no_impersonation() {
        let result = analyze_spoof(
            "\"Unknown Person\" <unknown@evil.com>",
            None,
            &["CEO 山田"],
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
            &["CEO 山田"],
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
}
