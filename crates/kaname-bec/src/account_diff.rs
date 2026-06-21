//! 口座番号差分検出 — スレッドハイジャック型 BEC 対策。
//!
//! 攻撃シナリオ:
//! 1. 攻撃者が正規アカウントを乗っ取り、数週間〜数ヶ月会話を観察する。
//! 2. 振込タイミングを狙って「銀行口座変更のお知らせ」を送信。
//! 3. ヘッダ (In-Reply-To / References) は正規の返信、本文の口座番号だけ差し替わる。
//!
//! DMARC・SPF・DKIM はすべて通るため、本文レベルの差分検出が唯一の砦。
//!
//! 出典: PSI スレッド乗っ取り攻撃解説 (2026-01)、Cybernet Valimail BEC ガイド、
//! IPA BEC 対策。
//!
//! # 設計
//!
//! - 過去スレッドから「銀行口座らしき数字パターン」を抽出
//! - 現在メールから同様に抽出し集合差分を取る
//! - 「変更」「振込先」「口座」キーワードが本文にあれば重み付け倍化

#![allow(clippy::module_name_repetitions)]

use std::collections::HashSet;

/// スレッドハイジャック検出結果。
#[derive(Debug, Clone, PartialEq)]
pub struct AccountDiffResult {
    /// 過去スレッドに無く現在メールに現れた口座番号 (新規追加)。
    pub new_accounts: Vec<String>,
    /// 過去スレッドにあり現在メールで失われた口座番号 (置換されたか)。
    pub removed_accounts: Vec<String>,
    /// 本文に「変更」「振込先」等のキーワードが含まれるか。
    pub has_change_keyword: bool,
    /// 0.0..=1.0 のリスクスコア。
    pub risk_score: f32,
}

impl AccountDiffResult {
    /// 高リスク判定 (0.7 以上)。
    #[must_use]
    pub fn is_high_risk(&self) -> bool {
        self.risk_score >= 0.7
    }
}

/// メール本文から銀行口座番号パターンを抽出する。
///
/// 対応パターン:
/// - 7 桁連続数字 (一般的な普通預金口座番号)
/// - 4 桁数字 + 3 桁数字 (銀行コード + 支店コード)
/// - IBAN (将来拡張)
///
/// 全角数字は ASCII に正規化済みとして扱う (DLP 同様の前処理を期待)。
#[must_use]
pub fn extract_accounts(body: &str) -> HashSet<String> {
    let normalized = normalize_digits(body);
    let mut accounts = HashSet::new();

    // 7 桁の連続数字 (口座番号)
    let bytes = normalized.as_bytes();
    let mut i = 0;
    while i + 7 <= bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // 前の文字が数字ならスキップ (中央検出を避ける)
        if i > 0 && bytes[i - 1].is_ascii_digit() {
            i += 1;
            continue;
        }
        let mut end = i;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        let run_len = end - i;
        // 後続が数字でなければ確定 (run の長さで分類)
        if (7..=8).contains(&run_len) {
            // 普通預金口座番号として登録
            if let Ok(s) = std::str::from_utf8(&bytes[i..end]) {
                accounts.insert(s.to_string());
            }
        }
        i = end.max(i + 1);
    }

    accounts
}

/// メール本文に「口座変更」「振込先変更」等の典型キーワードが含まれるか。
#[must_use]
pub fn has_account_change_keyword(body: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        // 日本語
        "口座変更", "振込先変更", "振込先が変更", "口座が変わりました",
        "新しい口座", "新口座", "振込先を変更", "口座番号変更",
        "支払先変更", "送金先変更",
        // 英語
        "account change", "new account", "updated account",
        "wire transfer details have changed", "banking details updated",
        "remittance information has been updated",
    ];
    let lower = body.to_lowercase();
    KEYWORDS.iter().any(|k| {
        let kl = k.to_lowercase();
        lower.contains(&kl) || body.contains(*k)
    })
}

/// 過去スレッドと現在メールの口座番号差分を計算する。
///
/// `past_bodies` は時系列順 (古い→新しい) のスレッド本文リスト。
/// `current_body` は現在 (判定対象) のメール本文。
#[must_use]
pub fn detect_account_diff(past_bodies: &[&str], current_body: &str) -> AccountDiffResult {
    let mut historical: HashSet<String> = HashSet::new();
    for past in past_bodies {
        historical.extend(extract_accounts(past));
    }
    let current_accounts = extract_accounts(current_body);

    let new_accounts: Vec<String> = current_accounts
        .difference(&historical)
        .cloned()
        .collect();
    let removed_accounts: Vec<String> = historical
        .difference(&current_accounts)
        .cloned()
        .collect();

    let has_change_keyword = has_account_change_keyword(current_body);

    // スコアリング:
    //   - 過去に口座あり ∧ 現在に新規口座 → 高リスク (差替の典型)
    //   - 変更キーワードあれば +0.3
    //   - 過去口座が消えていれば +0.2 (置換の兆候)
    let mut risk: f32 = 0.0;
    if !historical.is_empty() && !new_accounts.is_empty() {
        risk += 0.5;
    }
    if has_change_keyword {
        risk += 0.3;
    }
    if !removed_accounts.is_empty() && !new_accounts.is_empty() {
        risk += 0.2;
    }
    let risk_score = risk.min(1.0);

    AccountDiffResult {
        new_accounts,
        removed_accounts,
        has_change_keyword,
        risk_score,
    }
}

fn normalize_digits(s: &str) -> String {
    s.chars()
        .map(|c| {
            // 全角数字 U+FF10..=U+FF19 → ASCII
            if ('\u{FF10}'..='\u{FF19}').contains(&c) {
                char::from_u32(c as u32 - 0xFEE0).unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn extract_seven_digit_account() {
        let body = "口座番号: 1234567 までお振り込みください。";
        let acc = extract_accounts(body);
        assert!(acc.contains("1234567"));
    }

    #[test]
    fn extract_ignores_short_numbers() {
        let body = "電話 03-1234-5678 までご連絡ください";
        let acc = extract_accounts(body);
        // 4 桁の 1234 や 03 は登録されない (7 桁未満)
        assert!(!acc.contains("1234"));
    }

    #[test]
    fn extract_handles_fullwidth_digits() {
        let body = "口座番号: １２３４５６７ です";
        let acc = extract_accounts(body);
        assert!(acc.contains("1234567"),
            "全角数字が正規化されていない: {acc:?}");
    }

    #[test]
    fn keyword_detected_japanese() {
        assert!(has_account_change_keyword("振込先変更のお知らせ"));
        assert!(has_account_change_keyword("新しい口座にお振込みください"));
        assert!(!has_account_change_keyword("通常の業務連絡です"));
    }

    #[test]
    fn keyword_detected_english() {
        assert!(has_account_change_keyword("Please note: account change required"));
        assert!(has_account_change_keyword("Wire transfer details have changed"));
    }

    #[test]
    fn thread_hijack_typical_pattern_high_risk() {
        // 過去スレッドでは 1111111 が使われていた
        let past = vec![
            "請求書送付いたします。口座 1111111 までお振込お願いします。",
            "ご確認ありがとうございます。引き続き 1111111 でお願いします。",
        ];
        // 攻撃者が口座を 9999999 に差し替え、キーワード「変更」を含む
        let current = "重要: 振込先変更のお知らせ。新口座 9999999 にお振込ください。";
        let r = detect_account_diff(&past, current);
        assert!(r.is_high_risk(),
            "口座差替 + 変更キーワード = 高リスクでなければならない: {r:?}");
        assert!(r.new_accounts.contains(&"9999999".to_string()));
        assert!(r.removed_accounts.contains(&"1111111".to_string()));
        assert!(r.has_change_keyword);
    }

    #[test]
    fn same_account_in_thread_low_risk() {
        let past = vec!["口座 1234567 までお振込ください"];
        let current = "1234567 への振込確認しました";
        let r = detect_account_diff(&past, current);
        assert!(!r.is_high_risk(),
            "同一口座継続は低リスク: {r:?}");
        assert_eq!(r.risk_score, 0.0);
    }

    #[test]
    fn first_email_in_thread_no_history() {
        // 過去スレッドなし → ベースライン確立フェーズ、リスクなし
        let r = detect_account_diff(&[], "口座 1234567 までお振込ください");
        assert_eq!(r.risk_score, 0.0,
            "履歴ゼロのスレッドではリスクスコアは 0: {r:?}");
    }

    #[test]
    fn keyword_alone_without_diff_is_moderate() {
        // キーワードはあるが過去履歴と整合 → 中程度
        let past = vec!["1234567 にお振込ください"];
        let current = "口座変更しました。1234567 のままです。"; // 同じ口座
        let r = detect_account_diff(&past, current);
        // new_accounts は空、change keyword はある
        assert!(r.has_change_keyword);
        assert!(!r.is_high_risk(),
            "差分なしならキーワードのみで高リスクにはしない: {r:?}");
    }

    #[test]
    fn ten_digit_run_not_extracted_as_account() {
        // 10 桁の文字列は 7-8 桁レンジ外なので口座として抽出しない
        let body = "ID: 1234567890123 は社内番号です";
        let acc = extract_accounts(body);
        assert!(acc.is_empty(),
            "範囲外の数字列は口座扱いしない: {acc:?}");
    }

    #[test]
    fn account_diff_result_is_high_risk_threshold() {
        let r = AccountDiffResult {
            new_accounts: vec!["9999999".to_string()],
            removed_accounts: vec![],
            has_change_keyword: true,
            risk_score: 0.7,
        };
        assert!(r.is_high_risk());

        let r2 = AccountDiffResult {
            new_accounts: vec![],
            removed_accounts: vec![],
            has_change_keyword: false,
            risk_score: 0.69,
        };
        assert!(!r2.is_high_risk());
    }
}
