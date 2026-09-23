//! Reply-To スプーフィング + 表示名詐称の検出。
//!
//! BEC の典型手口:
//! 1. **Reply-To スプーフィング** — `From: ceo@company.com` だが
//!    `Reply-To: ceo@gmail.com` で返信を横取り
//! 2. **表示名詐称** — `From: "CEO 山田" <attacker@evil.com>` で
//!    正規アドレスに見せかける
//! 3. **フレンドリ名アドレス詐称** — `From: "support@paypal.com"
//!    <attacker@evil.xyz>` で、クライアントが表示名を差出人として見せるため
//!    ユーザーに `support@paypal.com` からのメールと誤認させる
//!    (RFC 5322 では表示名は任意テキスト。Valimail「friendly name spoofing」、
//!    JPCERT/CC の BEC 解析で頻出する手口)

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
    /// 表示名にメールアドレスが埋め込まれ、かつそのドメインが実際の
    /// 送信ドメインと異なる (フレンドリ名アドレス詐称)。
    pub display_name_email_spoof: bool,
    /// 表示名に埋め込まれていたアドレスのドメイン (詐称の場合のみ Some)。
    pub embedded_domain: Option<String>,
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

    // 3. フレンドリ名アドレス詐称チェック
    // 表示名がそのものメールアドレスである (`"support@paypal.com"
    // <attacker@evil.xyz>`) 場合、クライアントが表示名を差出人名として
    // 見せるため、ユーザーは実アドレスではなく埋め込まれたアドレスを
    // 差出人と誤認する。既知連絡先との一致を問わず、埋め込みドメインが
    // 実送信ドメインと異なれば詐称。
    let embedded_domain = display_name
        .as_deref()
        .and_then(extract_embedded_email_domain);
    let display_name_email_spoof = match (&embedded_domain, &from_domain) {
        // 両方ホモグリフ畳み込みして比較 — `"support@раypal.com" <x@paypal.com>`
        // (Cyrillic) のようなケースで畳み込み後に一致すれば詐称ではない
        (Some(emb), Some(fd)) => emb != &crate::idn_homograph::fold_homoglyphs(fd),
        _ => false,
    };
    // 埋め込みドメインが既知連絡先のドメインと一致する場合は、
    // その連絡先を狙った詐称 (より悪質)。
    let embedded_targets_contact = if display_name_email_spoof {
        embedded_domain.as_ref().is_some_and(|emb| {
            known_contacts
                .iter()
                .any(|(_, d)| emb == &d.to_lowercase().trim().to_string())
        })
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
    if display_name_email_spoof {
        score += 0.35;
        if embedded_targets_contact {
            score += 0.15;
        }
    }

    SpoofAnalysis {
        reply_to_domain_mismatch,
        reply_to_domain,
        display_name_impersonation,
        suspicious_display_name: if display_name_impersonation {
            display_name.clone()
        } else {
            None
        },
        display_name_email_spoof,
        embedded_domain: if display_name_email_spoof {
            embedded_domain
        } else {
            None
        },
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

/// 表示名からメールアドレスの区切り文字判定。
/// アドレストークン内に現れない文字のみを境界とする (空白・クォート・
/// 括弧・山括弧・区切り記号)。Unicode 文字は区切りではないので
/// `"support@раypal.com"` (Cyrillic) のような埋め込みドメインも
/// 丸ごと拾える。
fn is_addr_delim(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
        )
}

/// 表示名文字列に埋め込まれたメールアドレスのドメインを抽出する。
///
/// `From: "support@paypal.com" <attacker@evil.xyz>` のような
/// フレンドリ名アドレス詐称用。複数候補がある場合は最初の有効なものを返す。
/// 戻り値はホモグリフ畳み込み済み・小文字正規化済みのドメイン。
///
/// 有効条件: `local@domain` の local が 1 文字以上、domain が
/// `label.label` 形 (ラベルは ASCII 英数字・ハイフン) — 畳み込み後に判定。
fn extract_embedded_email_domain(display_name: &str) -> Option<String> {
    for (at, _) in display_name.match_indices('@') {
        // local: '@' から左へ、区切り文字に当たるまで遡る。
        // rfind は byte offset を返す — 区切り文字は全て ASCII なので
        // +1 で区切り文字の直後 (char 境界) になる。
        let start = display_name[..at]
            .rfind(is_addr_delim)
            .map(|i| i + 1)
            .unwrap_or(0);
        let local = &display_name[start..at];
        if local.is_empty() {
            continue;
        }

        // domain: '@' の右へ、区切り文字に当たるまで進む
        let rest = &display_name[at + 1..];
        let domain_len = rest.find(is_addr_delim).unwrap_or(rest.len());
        let raw_domain = &rest[..domain_len];
        // 末尾の句読点・閉じ括弧などを除去
        let raw_domain = raw_domain.trim_end_matches(|c: char| {
            matches!(c, '.' | ',' | '!' | '?' | ':' | ';' | ')' | ']' | '}')
        });
        if raw_domain.is_empty() {
            continue;
        }

        let folded = crate::idn_homograph::fold_homoglyphs(raw_domain).to_lowercase();
        if !is_plausible_domain(&folded) {
            continue;
        }
        return Some(folded);
    }
    None
}

/// `label(.label)+` 形の妥当なドメインか (ASCII 英数字・ハイフンのみ)。
fn is_plausible_domain(domain: &str) -> bool {
    let mut labels = domain.split('.');
    let mut count = 0usize;
    for label in &mut labels {
        count += 1;
        if label.is_empty()
            || label.len() > 63
            || !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return false;
        }
    }
    count >= 2
}

/// ヘッダーから表示名を抽出する。
///
/// `"表示名" <email>` → `Some("表示名")`
/// `<email>` または `email` → `None`
fn extract_display_name(header: &str) -> Option<String> {
    // 最後の '<' を使う — 表示名自体が `"<support@paypal.com>"` のような
    // 山括弧を含む場合に最初の '<' で切ると表示名が空になってしまう。
    // 実アドレスの addr-spec は常に最後の山括弧ペア。
    let lt_pos = header.rfind('<')?;
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

    // ── D161: フレンドリ名アドレス詐称 ──────────────────────────────────────

    #[test]
    fn display_name_email_spoof_detected() {
        // `"support@paypal.com" <attacker@evil.xyz>` — 表示名がアドレスで
        // そのドメインが実送信ドメインと異なる → 詐称
        let result = analyze_spoof(
            "\"support@paypal.com\" <attacker@evil.xyz>",
            None,
            &[],
        );
        assert!(result.display_name_email_spoof);
        assert_eq!(result.embedded_domain.as_deref(), Some("paypal.com"));
    }

    #[test]
    fn display_name_email_same_domain_is_clean() {
        // 表示名のアドレスが実アドレスと同ドメイン → 正当 (自分のアドレスを
        // 表示名に設定する利用者は多い)
        let result = analyze_spoof(
            "\"alice@company.com\" <alice@company.com>",
            None,
            &[],
        );
        assert!(!result.display_name_email_spoof);
        assert!(result.embedded_domain.is_none());
    }

    #[test]
    fn display_name_email_targets_known_contact() {
        // 埋め込みドメインが既知連絡先のドメイン → より高スコア
        let result = analyze_spoof(
            "\"ceo@company.com\" <attacker@evil.xyz>",
            None,
            &[("CEO 山田", "company.com")],
        );
        assert!(result.display_name_email_spoof);
        assert!(result.risk_score >= 0.5);
    }

    #[test]
    fn display_name_email_cyrillic_homoglyph_detected() {
        // 埋め込みドメインの Cyrillic 類似字も畳み込みで拾う
        // "support@раypal.com" の 'а' は Cyrillic
        let result = analyze_spoof(
            "\"support@раypal.com\" <attacker@evil.xyz>",
            None,
            &[],
        );
        assert!(result.display_name_email_spoof);
        assert_eq!(result.embedded_domain.as_deref(), Some("paypal.com"));
    }

    #[test]
    fn display_name_email_cyrillic_homoglyph_same_domain_clean() {
        // 埋め込みが Cyrillic で書かれていても畳み込み後に実ドメインと
        // 一致すれば詐称ではない
        let result = analyze_spoof(
            "\"alice@соmpany.com\" <alice@company.com>",
            None,
            &[],
        );
        // "соmpany.com" の 'о' が Cyrillic → fold すると "company.com"
        assert!(!result.display_name_email_spoof);
    }

    #[test]
    fn display_name_email_inside_text_detected() {
        // 表示名がテキスト + アドレス混在でも埋め込みを拾う
        let result = analyze_spoof(
            "\"PayPal サポート support@paypal.com\" <attacker@evil.xyz>",
            None,
            &[],
        );
        assert!(result.display_name_email_spoof);
        assert_eq!(result.embedded_domain.as_deref(), Some("paypal.com"));
    }

    #[test]
    fn display_name_email_in_angle_brackets_detected() {
        // 表示名内の <addr> 形式
        let result = analyze_spoof(
            "\"<support@paypal.com>\" <attacker@evil.xyz>",
            None,
            &[],
        );
        assert!(result.display_name_email_spoof);
        assert_eq!(result.embedded_domain.as_deref(), Some("paypal.com"));
    }

    #[test]
    fn display_name_email_trailing_punctuation_trimmed() {
        // 末尾のピリオド等を除去してドメインを抽出
        let result = analyze_spoof(
            "\"連絡先: support@paypal.com.\" <attacker@evil.xyz>",
            None,
            &[],
        );
        assert!(result.display_name_email_spoof);
        assert_eq!(result.embedded_domain.as_deref(), Some("paypal.com"));
    }

    #[test]
    fn display_name_email_domain_without_tld_ignored() {
        // "a@b" のような TLD なしはメールアドレスとして妥当ではない
        let result = analyze_spoof("\"a@b\" <attacker@evil.xyz>", None, &[]);
        assert!(!result.display_name_email_spoof);
    }

    #[test]
    fn display_name_email_no_display_name_clean() {
        // 表示名がない From は対象外
        let result = analyze_spoof("attacker@evil.xyz", None, &[]);
        assert!(!result.display_name_email_spoof);
    }

    #[test]
    fn display_name_email_free_mail_embedded_detected() {
        // フリーメールアドレスの埋め込みも検出 (ドメイン不一致なら)
        let result = analyze_spoof(
            "\"経理 keiri@gmail.com\" <attacker@evil.xyz>",
            None,
            &[],
        );
        assert!(result.display_name_email_spoof);
        assert_eq!(result.embedded_domain.as_deref(), Some("gmail.com"));
    }

    #[test]
    fn extract_embedded_email_domain_unit() {
        assert_eq!(
            extract_embedded_email_domain("support@paypal.com").as_deref(),
            Some("paypal.com")
        );
        assert_eq!(
            extract_embedded_email_domain("PayPal support@paypal.com").as_deref(),
            Some("paypal.com")
        );
        assert_eq!(
            extract_embedded_email_domain("a@b").as_deref(),
            None,
            "TLD なしはドメインではない"
        );
        assert_eq!(
            extract_embedded_email_domain("plain name").as_deref(),
            None
        );
        assert_eq!(
            extract_embedded_email_domain("@nodomain.com").as_deref(),
            None,
            "local なし"
        );
    }
}
