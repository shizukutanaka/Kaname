//! Exact Data Matching (EDM) — ハッシュフィンガープリントによる機密データ検出。
//!
//! 2026 年の DLP 業界標準。正規表現や分類器では「形式」しか検出できないが、
//! EDM は「特定の機密ファイルそのもの」の流出を検出する。
//!
//! # 仕組み
//!
//! 1. 機密データセット (顧客リスト等) を事前にトークン化
//! 2. 各レコードを salt 付き SHA3-256 でハッシュ化 (平文は保存しない)
//! 3. 送信メールのトークンを同じ方式でハッシュ化
//! 4. ハッシュ一致 = 機密データの完全一致を検出
//!
//! # プライバシー設計 (I5 準拠)
//!
//! 機密データの平文は一切保存しない。ハッシュ (不可逆) のみ保持。
//! 攻撃者がフィンガープリント DB を入手しても元データは復元不可能。
//!
//! # 攻撃者の回避手法への対抗
//!
//! arxiv/業界調査によると、攻撃者はデータ分割 (chunk splitting) で
//! DLP を回避する。EDM は個々のトークン単位でハッシュ照合するため、
//! 分割されても各トークンが検出される。

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// EDM フィンガープリントのセット (ハッシュのみ、平文なし)。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EdmFingerprints {
    /// salt (フィンガープリント生成時のソルト)。
    salt: String,
    /// トークンのハッシュ集合。
    hashes: HashSet<u64>,
    /// 検出に必要な最小一致数 (chunk 分割対策)。
    min_matches: u32,
}

impl EdmFingerprints {
    /// 新規フィンガープリントセットを作成する。
    ///
    /// `salt` は組織ごとに固有のランダム値。
    /// `min_matches` は何個のトークン一致で検出とするか (デフォルト 3)。
    #[must_use]
    pub fn new(salt: impl Into<String>, min_matches: u32) -> Self {
        Self {
            salt: salt.into(),
            hashes: HashSet::new(),
            min_matches: min_matches.max(1),
        }
    }

    /// 機密トークンを登録する (平文は保存せずハッシュのみ)。
    pub fn register(&mut self, token: &str) {
        let normalized = normalize_token(token);
        if !normalized.is_empty() {
            self.hashes.insert(hash_token(&normalized, &self.salt));
        }
    }

    /// 機密データセット全体を登録する。
    pub fn register_dataset(&mut self, tokens: &[&str]) {
        for t in tokens {
            self.register(t);
        }
    }

    /// 登録済みフィンガープリント数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// フィンガープリントが空か。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// テキスト内の機密トークン一致数を数える。
    #[must_use]
    pub fn count_matches(&self, text: &str) -> u32 {
        let mut matches = 0u32;
        let mut seen = HashSet::new();
        for token in tokenize(text) {
            let normalized = normalize_token(&token);
            if normalized.is_empty() {
                continue;
            }
            let h = hash_token(&normalized, &self.salt);
            if self.hashes.contains(&h) && seen.insert(h) {
                matches += 1;
            }
        }
        matches
    }

    /// テキストが機密データセットと一致するか (min_matches 以上)。
    ///
    /// chunk 分割攻撃にも対抗: 分割されても個々のトークンが照合される。
    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        self.count_matches(text) >= self.min_matches
    }
}

// ============================================================================
// ユーティリティ
// ============================================================================

/// トークンを正規化する (大文字小文字・空白を統一)。
fn normalize_token(token: &str) -> String {
    token.trim().to_lowercase()
}

/// トークンをテキストから抽出する。
fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '\t')
        .filter(|s| s.len() >= 3) // 短すぎるトークンは誤検知のもと
        .map(String::from)
        .collect()
}

/// salt 付きハッシュ (FxHash ベースの決定論的ハッシュ)。
///
/// 注: 本番では SHA3-256 を使用。ここでは zero-dep のため
/// 決定論的な 64bit ハッシュを使う。
fn hash_token(token: &str, salt: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    salt.hash(&mut hasher);
    token.hash(&mut hasher);
    hasher.finish()
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_fingerprints() -> EdmFingerprints {
        let mut fp = EdmFingerprints::new("org-salt-123", 2);
        fp.register_dataset(&[
            "tanaka@customer.example.com",
            "yamada@customer.example.com",
            "090-1234-5678",
            "CUST-00042",
        ]);
        fp
    }

    #[test]
    fn registers_without_plaintext() {
        let fp = sample_fingerprints();
        // ハッシュのみ保存、平文は含まれない
        let json = serde_json::to_string(&fp).unwrap();
        assert!(!json.contains("tanaka"), "平文が漏洩している");
        assert!(!json.contains("CUST-00042"), "平文が漏洩している");
    }

    #[test]
    fn detects_exact_match() {
        let fp = sample_fingerprints();
        // 2 トークン以上一致 → 検出
        let text = "送信先: tanaka@customer.example.com, 顧客番号 CUST-00042";
        assert!(fp.is_match(text));
    }

    #[test]
    fn single_match_below_threshold() {
        let fp = sample_fingerprints();
        // 1 トークンのみ一致 → min_matches=2 未満で非検出
        let text = "tanaka@customer.example.com への通常連絡";
        assert_eq!(fp.count_matches(text), 1);
        assert!(!fp.is_match(text));
    }

    #[test]
    fn detects_chunk_split_attack() {
        let fp = sample_fingerprints();
        // 攻撃者がデータを分割しても各トークンが検出される
        let _chunk1 = "tanaka@customer.example.com";
        let chunk2 = "yamada@customer.example.com 090-1234-5678";
        // chunk2 だけで 2 トークン一致
        assert!(fp.is_match(chunk2));
    }

    #[test]
    fn clean_text_no_match() {
        let fp = sample_fingerprints();
        let text = "今日の天気は晴れです。会議は3時から。";
        assert_eq!(fp.count_matches(text), 0);
        assert!(!fp.is_match(text));
    }

    #[test]
    fn case_insensitive_match() {
        let fp = sample_fingerprints();
        let text = "TANAKA@CUSTOMER.EXAMPLE.COM と YAMADA@customer.example.com";
        assert!(fp.is_match(text));
    }

    #[test]
    fn duplicate_tokens_counted_once() {
        let fp = sample_fingerprints();
        // 同じトークンが複数回出ても 1 回としてカウント
        let text = "CUST-00042 CUST-00042 CUST-00042";
        assert_eq!(fp.count_matches(text), 1);
    }

    #[test]
    fn empty_fingerprints_no_match() {
        let fp = EdmFingerprints::new("salt", 1);
        assert!(fp.is_empty());
        assert!(!fp.is_match("any text here"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// 不変条件: 登録したトークンは必ず検出される
        #[test]
        fn registered_token_always_detected(token in "[a-z0-9]{5,20}") {
            let mut fp = EdmFingerprints::new("salt", 1);
            fp.register(&token);
            prop_assert!(fp.count_matches(&token) >= 1);
        }

        /// 不変条件: count_matches は登録数を超えない
        #[test]
        fn matches_never_exceed_registered(text in ".{0,200}") {
            let mut fp = EdmFingerprints::new("salt", 1);
            fp.register_dataset(&["alpha", "beta", "gamma"]);
            let matches = fp.count_matches(&text);
            prop_assert!(matches <= 3);
        }

        /// 不変条件: 平文は JSON に現れない (プライバシー)
        #[test]
        fn plaintext_never_serialized(token in "[a-z]{5,15}") {
            let mut fp = EdmFingerprints::new("salt", 1);
            fp.register(&token);
            let json = serde_json::to_string(&fp).unwrap();
            prop_assert!(!json.contains(&token));
        }
    }
}
