//! 宛先ミス検出 (Misdirected Recipient Detection)。
//!
//! # 背景
//!
//! 実世界のメール起因データ漏洩の最大要因は悪意ある攻撃ではなく
//! 「宛先間違い」である (Tessian/Egress 等の調査で一貫して報告)。
//! 典型パターン:
//!
//! - オートコンプリートで類似名の別人・別社の連絡先を誤選択
//! - 取引先ドメインのタイポドメインへ誤送信 (例: `crop.com` vs `corp.com`)
//! - 社内ドメインのみのスレッドにフリーメールが混入 (私用アドレスへの誤送信)
//! - 過去に一度もやり取りのない新規宛先が、既知の連絡先と酷似したドメイン
//!
//! # 設計
//!
//! - 過去の通信履歴 (`known_recipient_domains`) と Levenshtein 距離 1-2 で
//!   類似するが完全一致しない送信先ドメインを「疑わしい」と判定
//! - 社内ドメインのみのスレッドにフリーメールドメインが混在する場合も検出
//! - 本文/件名は一切解析しない (宛先ドメインのみ、プライバシー配慮)

use std::collections::HashSet;

/// 宛先ミスの疑いがある個別の宛先。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspiciousRecipient {
    /// 疑わしい宛先メールアドレス。
    pub address: String,
    /// 疑いの種別。
    pub reason: MisdirectReason,
}

/// 宛先ミスの疑いの種別。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MisdirectReason {
    /// 既知の連絡先ドメインに酷似するが完全一致しない (タイポの疑い)。
    LookalikeDomain {
        /// 類似していると判定された既知ドメイン。
        similar_to: String,
    },
    /// 社内ドメインのみのスレッドにフリーメールドメインが混在。
    FreeMailInInternalThread,
}

/// フリーメールドメイン一覧 (社内スレッドへの混入検出用)。
const FREE_MAIL_DOMAINS: &[&str] = &[
    "gmail.com", "yahoo.com", "yahoo.co.jp", "hotmail.com", "outlook.com",
    "live.com", "icloud.com", "protonmail.com", "yandex.com", "aol.com",
    "qq.com", "163.com",
];

/// 宛先リストを評価し、宛先ミスの疑いがある宛先を検出する。
///
/// # 引数
///
/// - `recipients`: 送信しようとしている宛先メールアドレス一覧 (To/Cc/Bcc 全て)。
/// - `our_domain`: 自組織のドメイン (自己送信は対象外にするため)。
/// - `known_recipient_domains`: 過去にやり取りした実績のあるドメイン一覧。
///
/// # 戻り値
///
/// 疑わしい宛先のリスト。空なら問題なし。
#[must_use]
pub fn detect_misdirected_recipients(
    recipients: &[String],
    our_domain: &str,
    known_recipient_domains: &[String],
) -> Vec<SuspiciousRecipient> {
    let our_domain_lower = our_domain.to_lowercase();
    let known_lower: Vec<String> = known_recipient_domains
        .iter()
        .map(|d| d.to_lowercase())
        .filter(|d| d != &our_domain_lower)
        .collect();
    let known_set: HashSet<&str> = known_lower.iter().map(String::as_str).collect();

    // このスレッドの宛先が全て社内ドメインか (フリーメール混在検出用)
    let recipient_domains: Vec<String> = recipients
        .iter()
        .filter_map(|r| extract_domain(r))
        .collect();
    let all_internal_except_last = recipient_domains.len() > 1
        && recipient_domains[..recipient_domains.len().saturating_sub(1)]
            .iter()
            .all(|d| d == &our_domain_lower);

    let mut suspicious = Vec::new();

    for recipient in recipients {
        let Some(domain) = extract_domain(recipient) else { continue };
        if domain == our_domain_lower {
            continue; // 自己送信は対象外
        }
        if known_set.contains(domain.as_str()) {
            continue; // 既知の実績あるドメインは問題なし
        }

        // 1. 既知ドメインとのタイポスクワット類似度チェック (距離 1-2)
        if let Some(similar) = known_lower.iter().find(|k| levenshtein_le_2(&domain, k) && &domain != *k) {
            suspicious.push(SuspiciousRecipient {
                address: recipient.clone(),
                reason: MisdirectReason::LookalikeDomain { similar_to: similar.clone() },
            });
            continue;
        }

        // 2. 社内のみのスレッドにフリーメールが混入
        if all_internal_except_last && FREE_MAIL_DOMAINS.contains(&domain.as_str()) {
            suspicious.push(SuspiciousRecipient {
                address: recipient.clone(),
                reason: MisdirectReason::FreeMailInInternalThread,
            });
        }
    }

    suspicious
}

/// メールアドレスからドメイン部分を抽出する (小文字化)。
fn extract_domain(address: &str) -> Option<String> {
    let at = address.rfind('@')?;
    let domain = &address[at + 1..];
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_lowercase())
    }
}

/// レーベンシュタイン距離が 1 または 2 以内かを判定する (タイポドメイン検出)。
///
/// 完全一致 (距離 0) は呼び出し側で別途 known_set チェック済みのため対象外。
fn levenshtein_le_2(a: &str, b: &str) -> bool {
    // 長さ差が 3 以上なら距離 2 を超えるので早期リターン (DoS 対策 + 高速化)
    if a.len().abs_diff(b.len()) > 2 {
        return false;
    }
    // 極端に長い入力は DP テーブル確保を避ける (DoS 対策)
    const MAX_LEN: usize = 64;
    if a.len() > MAX_LEN || b.len() > MAX_LEN {
        return false;
    }
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for (i, row) in dp.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in dp[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1]
            } else {
                1 + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1])
            };
        }
    }
    dp[m][n] > 0 && dp[m][n] <= 2
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn typo_domain_detected() {
        let recipients = vec!["alice@crop.com".to_string()];
        let known = vec!["corp.com".to_string()];
        let result = detect_misdirected_recipients(&recipients, "us.com", &known);
        assert_eq!(result.len(), 1, "タイポドメインが検出されるべき");
        assert!(matches!(result[0].reason, MisdirectReason::LookalikeDomain { .. }));
    }

    #[test]
    fn known_domain_not_flagged() {
        let recipients = vec!["alice@corp.com".to_string()];
        let known = vec!["corp.com".to_string()];
        let result = detect_misdirected_recipients(&recipients, "us.com", &known);
        assert!(result.is_empty(), "既知の実績あるドメインは検出されるべきではない");
    }

    #[test]
    fn own_domain_not_flagged() {
        let recipients = vec!["bob@us.com".to_string()];
        let known: Vec<String> = vec![];
        let result = detect_misdirected_recipients(&recipients, "us.com", &known);
        assert!(result.is_empty(), "自己ドメイン宛は検出されるべきではない");
    }

    #[test]
    fn completely_unrelated_new_domain_not_flagged() {
        // 既知ドメインと全く似ていない新規ドメインは (タイポではないので) 検出しない
        let recipients = vec!["contact@newvendor.io".to_string()];
        let known = vec!["corp.com".to_string()];
        let result = detect_misdirected_recipients(&recipients, "us.com", &known);
        assert!(result.is_empty(), "無関係な新規ドメインは誤検知されるべきではない");
    }

    #[test]
    fn free_mail_in_internal_thread_detected() {
        // 社内ドメインのみのスレッドにフリーメールが混入
        let recipients = vec![
            "alice@us.com".to_string(),
            "bob@us.com".to_string(),
            "leak@gmail.com".to_string(),
        ];
        let known: Vec<String> = vec![];
        let result = detect_misdirected_recipients(&recipients, "us.com", &known);
        assert!(
            result.iter().any(|r| r.address == "leak@gmail.com"
                && matches!(r.reason, MisdirectReason::FreeMailInInternalThread)),
            "社内スレッドへのフリーメール混入が検出されるべき: {result:?}"
        );
    }

    #[test]
    fn single_free_mail_recipient_not_flagged() {
        // 宛先がフリーメール1件のみ (社内スレッドではない) なら検出しない
        let recipients = vec!["someone@gmail.com".to_string()];
        let known: Vec<String> = vec![];
        let result = detect_misdirected_recipients(&recipients, "us.com", &known);
        assert!(result.is_empty(), "単独のフリーメール宛先は検出対象外");
    }

    #[test]
    fn subdomain_of_known_not_flagged_as_typo() {
        // "mail.corp.com" は "corp.com" のタイポではなく別ドメインとして扱われるため
        // Levenshtein 距離が大きく検出されない
        let recipients = vec!["alice@mail-department-server.corp.com".to_string()];
        let known = vec!["corp.com".to_string()];
        let result = detect_misdirected_recipients(&recipients, "us.com", &known);
        assert!(result.is_empty());
    }

    #[test]
    fn levenshtein_le_2_basic() {
        assert!(levenshtein_le_2("corp.com", "crop.com")); // 距離2 (transposition = 2 substitutions)
        assert!(levenshtein_le_2("corp.com", "corq.com")); // 距離1
        assert!(!levenshtein_le_2("corp.com", "corp.com")); // 距離0は対象外
        assert!(!levenshtein_le_2("corp.com", "totally-different.org"));
    }

    #[test]
    fn levenshtein_le_2_rejects_oversized_input() {
        let huge = "a".repeat(1000);
        assert!(!levenshtein_le_2(&huge, "corp.com"), "巨大入力はDoS対策で早期拒否されるべき");
    }

    #[test]
    fn multiple_known_domains_each_checked() {
        let recipients = vec!["x@vendorr.com".to_string()];
        let known = vec!["corp.com".to_string(), "vendor.com".to_string()];
        let result = detect_misdirected_recipients(&recipients, "us.com", &known);
        assert_eq!(result.len(), 1);
        assert!(matches!(
            &result[0].reason,
            MisdirectReason::LookalikeDomain { similar_to } if similar_to == "vendor.com"
        ));
    }
}
