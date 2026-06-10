// crates/kaname-render/src/calendar_guard.rs
//
// カレンダー招待 (.ics) 安全検査器
//
// 2026 年に急増: 悪意ある URL を含む .ics ファイルをメールに添付し、
// 「会議招待」に見せかけてフィッシングサイトへ誘導する攻撃。
//
// # 攻撃の仕組み
//
// ```text
// 攻撃者が .ics 添付を送信 (「来週のミーティング」等)
//   ↓
// ユーザーがカレンダーアプリで開く
//   ↓
// DESCRIPTION や URL フィールドに悪意ある URL が埋め込まれている
//   ↓
// ユーザーが「参加リンク」をクリック → フィッシングサイト
// ```
//
// # 検出アプローチ
//
// .ics ファイルを開く前に主催者ドメイン、URL、緊急キーワードを検査する。

use serde::{Deserialize, Serialize};

/// カレンダー招待のリスク種別。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CalendarRisk {
    /// 疑わしい URL が含まれる
    SuspiciousUrl {
        /// 問題の URL
        url: String,
        /// 疑わしい理由
        reason: String,
    },
    /// 主催者のドメインが疑わしい
    SuspiciousOrganizer {
        /// 主催者の email/name
        organizer: String,
        /// 問題の詳細
        reason: String,
    },
    /// 緊急性を偽装したキーワード
    UrgencyManipulation {
        /// 検出されたキーワード
        keyword: String,
    },
    /// 会議参加リンクが外部の怪しいドメインを指す
    SuspiciousMeetingLink {
        /// 問題のリンク
        link: String,
    },
}

/// カレンダー招待スキャン結果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarScan {
    /// 検出されたリスク一覧
    pub risks: Vec<CalendarRisk>,
    /// 総合リスクレベル
    pub risk_level: CalendarRiskLevel,
}

/// 総合リスクレベル。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CalendarRiskLevel {
    /// 安全
    Safe,
    /// 確認推奨
    Caution,
    /// 危険
    Danger,
}

/// カレンダー招待検査器。
pub struct CalendarGuard;

impl CalendarGuard {
    /// .ics ファイルの内容を解析してリスクを検出する。
    #[must_use]
    pub fn analyze(&self, ics_content: &str) -> CalendarScan {
        let mut risks = Vec::new();

        // 1. URL フィールドを抽出して検査
        for url in extract_ics_urls(ics_content) {
            if let Some(reason) = self.evaluate_url(&url) {
                risks.push(CalendarRisk::SuspiciousUrl { url, reason });
            }
        }

        // 2. 主催者を抽出して検査
        if let Some(organizer) = extract_organizer(ics_content) {
            if let Some(reason) = self.evaluate_organizer(&organizer) {
                risks.push(CalendarRisk::SuspiciousOrganizer { organizer, reason });
            }
        }

        // 3. 緊急性の偽装キーワード
        let desc = extract_field(ics_content, "DESCRIPTION").unwrap_or_default().to_lowercase();
        let summary = extract_field(ics_content, "SUMMARY").unwrap_or_default().to_lowercase();
        let combined = format!("{desc} {summary}");

        let urgency_keywords = [
            ("account suspended", "アカウント停止を装う"),
            ("verify now", "即時確認を要求"),
            ("immediate action required", "緊急アクションを要求"),
            ("your account will be deleted", "アカウント削除を脅す"),
            ("click to confirm", "クリックを促す"),
            ("password expiring", "パスワード期限切れを装う"),
            ("アカウントが停止", "アカウント停止を装う"),
            ("至急確認", "緊急確認を要求"),
        ];

        for (keyword, reason) in &urgency_keywords {
            if combined.contains(keyword) {
                risks.push(CalendarRisk::UrgencyManipulation {
                    keyword: keyword.to_string(),
                });
                let _ = reason; // UI で別途説明
                break; // 1つ検出すれば十分
            }
        }

        // 4. 会議リンク (CONFERENCE/LOCATION フィールド)
        for field in ["CONFERENCE", "LOCATION", "X-GOOGLE-CONFERENCE", "X-ZOOM-JOIN-URL"] {
            if let Some(value) = extract_field(ics_content, field) {
                if value.starts_with("http") {
                    if let Some(_reason) = self.evaluate_url(&value) {
                        risks.push(CalendarRisk::SuspiciousMeetingLink { link: value });
                        break;
                    }
                }
            }
        }

        let risk_level = Self::calculate_level(&risks);
        CalendarScan { risks, risk_level }
    }

    /// URL が疑わしい場合に理由を返す。
    fn evaluate_url(&self, url: &str) -> Option<String> {
        let lower = url.to_lowercase();

        // 無料 TLD
        let free_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".download"];
        for tld in &free_tlds {
            if lower.contains(tld) {
                return Some(format!("無料 TLD ({tld}) は悪用が多い"));
            }
        }

        // 数字混入 (amaz0n, g00gle 等)
        let suspicious = [
            ("amaz0n", "amazon を模倣"),
            ("paypa1", "paypal を模倣"),
            ("g00gle", "google を模倣"),
            ("micr0soft", "microsoft を模倣"),
            ("0ffice365", "office365 を模倣"),
        ];
        for (pattern, reason) in &suspicious {
            if lower.contains(pattern) {
                return Some(reason.to_string());
            }
        }

        // 正規ドメインを装った偽サブドメイン
        let legit = ["microsoft.com", "google.com", "zoom.us", "teams.microsoft.com"];
        for domain in &legit {
            if lower.contains(domain) {
                let host = extract_host(&lower).unwrap_or_default();
                if !host.ends_with(domain) && !host.is_empty() {
                    return Some(format!("{domain} を装った偽ドメインの可能性: {host}"));
                }
            }
        }

        None
    }

    /// 主催者ドメインを評価する。
    fn evaluate_organizer(&self, organizer: &str) -> Option<String> {
        let lower = organizer.to_lowercase();
        // mailto: から email を抽出
        let email = if lower.contains("mailto:") {
            lower.split("mailto:").nth(1)
                .map(|s| s.split('"').next().unwrap_or(s).trim().to_string())
        } else {
            Some(lower.clone())
        };

        if let Some(email) = email {
            // フリーメール (法人招待としては不自然)
            let free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "qq.com"];
            for provider in &free_providers {
                if email.ends_with(provider) {
                    return Some(format!("法人会議にフリーメール ({provider}) を使用"));
                }
            }
        }

        None
    }

    fn calculate_level(risks: &[CalendarRisk]) -> CalendarRiskLevel {
        if risks.is_empty() {
            return CalendarRiskLevel::Safe;
        }

        let has_suspicious_url = risks.iter().any(|r| matches!(r, CalendarRisk::SuspiciousUrl { .. }));
        let has_suspicious_meeting = risks.iter().any(|r| matches!(r, CalendarRisk::SuspiciousMeetingLink { .. }));

        if has_suspicious_url || has_suspicious_meeting {
            CalendarRiskLevel::Danger
        } else {
            CalendarRiskLevel::Caution
        }
    }
}

impl Default for CalendarGuard {
    fn default() -> Self { Self }
}

// ============================================================================
// ICS パーサーユーティリティ
// ============================================================================

fn extract_ics_urls(content: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        for prefix in ["URL:", "URL;", "ATTACH;"] {
            if trimmed.to_uppercase().starts_with(prefix) {
                let value = trimmed.split_once(':').map_or("", |x| x.1).trim();
                if value.starts_with("http") {
                    urls.push(value.to_string());
                }
            }
        }
        // DESCRIPTION や LOCATION 内の URL
        if trimmed.to_uppercase().starts_with("DESCRIPTION:") || trimmed.to_uppercase().starts_with("LOCATION:") {
            let value = trimmed.split_once(':').map_or("", |x| x.1);
            // 簡易 URL 抽出
            if let Some(start) = value.find("http") {
                let url_part: String = value[start..].chars().take_while(|c| !c.is_whitespace()).collect();
                if !url_part.is_empty() {
                    urls.push(url_part);
                }
            }
        }
    }
    urls
}

fn extract_organizer(content: &str) -> Option<String> {
    for line in content.lines() {
        let upper = line.to_uppercase();
        if upper.starts_with("ORGANIZER") {
            return Some(line.to_string());
        }
    }
    None
}

fn extract_field(content: &str, field_name: &str) -> Option<String> {
    let prefix = format!("{}:", field_name.to_uppercase());
    for line in content.lines() {
        if line.to_uppercase().starts_with(&prefix) {
            return Some(line[prefix.len()..].trim().to_string());
        }
    }
    None
}

fn extract_host(url: &str) -> Option<String> {
    let without_scheme = url.trim_start_matches("https://").trim_start_matches("http://");
    let end = without_scheme.find(['/', '?']).unwrap_or(without_scheme.len());
    if end > 0 {
        Some(without_scheme[..end].to_string())
    } else {
        None
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const NORMAL_ICS: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
SUMMARY:週次チームミーティング
ORGANIZER:mailto:alice@company.co.jp
DTSTART:20260515T100000Z
DTEND:20260515T110000Z
DESCRIPTION:通常のミーティングです
URL:https://teams.microsoft.com/l/meetup-join/abc123
END:VEVENT
END:VCALENDAR"#;

    const PHISHING_ICS: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
SUMMARY:Account Suspended - Verify Now
ORGANIZER:mailto:support@gmail.com
DESCRIPTION:Your account will be deleted. Verify now: http://amaz0n.tk/verify
URL:http://phishing.tk/steal
END:VEVENT
END:VCALENDAR"#;

    fn guard() -> CalendarGuard { CalendarGuard }

    #[test]
    fn normal_meeting_is_safe() {
        let g = guard();
        // Teams リンクは正規ドメインなので Safe
        let scan = g.analyze(NORMAL_ICS);
        // 正規 Teams URL は危険でない
        assert!(
            scan.risk_level == CalendarRiskLevel::Safe || scan.risks.is_empty(),
            "通常の会議は安全: {:?}", scan.risks
        );
    }

    #[test]
    fn phishing_ics_is_dangerous() {
        let g = guard();
        let scan = g.analyze(PHISHING_ICS);
        assert_eq!(scan.risk_level, CalendarRiskLevel::Danger);
        assert!(!scan.risks.is_empty());
    }

    #[test]
    fn detects_free_tld() {
        let g = guard();
        let ics = "BEGIN:VCALENDAR\nURL:http://meeting.tk/join\nEND:VCALENDAR";
        let scan = g.analyze(ics);
        assert!(scan.risks.iter().any(|r| matches!(r, CalendarRisk::SuspiciousUrl { .. })));
    }

    #[test]
    fn detects_digit_substitution_in_url() {
        let g = guard();
        let ics = "BEGIN:VCALENDAR\nURL:https://amaz0n.com/verify\nEND:VCALENDAR";
        let scan = g.analyze(ics);
        assert!(scan.risks.iter().any(|r| matches!(r, CalendarRisk::SuspiciousUrl { .. })));
    }

    #[test]
    fn detects_urgency_keyword() {
        let g = guard();
        let ics = "BEGIN:VCALENDAR\nSUMMARY:Account Suspended - verify now\nEND:VCALENDAR";
        let scan = g.analyze(ics);
        assert!(scan.risks.iter().any(|r| matches!(r, CalendarRisk::UrgencyManipulation { .. })));
    }

    #[test]
    fn detects_free_mail_organizer() {
        let g = guard();
        let ics = "BEGIN:VCALENDAR\nORGANIZER:mailto:cfo@gmail.com\nEND:VCALENDAR";
        let scan = g.analyze(ics);
        assert!(scan.risks.iter().any(|r| matches!(r, CalendarRisk::SuspiciousOrganizer { .. })));
    }

    #[test]
    fn extract_urls_from_description() {
        let ics = "BEGIN:VCALENDAR\nDESCRIPTION:Join at http://evil.tk/meet\nEND:VCALENDAR";
        let urls = extract_ics_urls(ics);
        assert!(!urls.is_empty(), "URL が description から抽出される");
        assert!(urls.iter().any(|u| u.contains("evil.tk")));
    }

    #[test]
    fn risk_level_danger_with_suspicious_url() {
        let risks = vec![CalendarRisk::SuspiciousUrl {
            url: "http://phish.tk".into(),
            reason: "free TLD".into(),
        }];
        assert_eq!(CalendarGuard::calculate_level(&risks), CalendarRiskLevel::Danger);
    }

    #[test]
    fn risk_level_caution_with_urgency_only() {
        let risks = vec![CalendarRisk::UrgencyManipulation {
            keyword: "verify now".into(),
        }];
        assert_eq!(CalendarGuard::calculate_level(&risks), CalendarRiskLevel::Caution);
    }

    #[test]
    fn empty_ics_is_safe() {
        let g = guard();
        let scan = g.analyze("BEGIN:VCALENDAR\nEND:VCALENDAR");
        assert_eq!(scan.risk_level, CalendarRiskLevel::Safe);
    }
}
