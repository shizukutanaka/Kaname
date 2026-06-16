//! QR Code Quishing 防御
//!
//! 2026 年急増中の脅威「QR コードフィッシング (Quishing)」への対抗策。
//! メール本文の画像内に隠された URL を OCR + QR デコードで検出する。
//!
//! # 攻撃シナリオ
//!
//! 1. 攻撃者がメール本文を「文字なし、画像のみ」で送信
//! 2. 画像内に QR コードが埋め込まれている
//! 3. ユーザーがスマホでスキャンするとフィッシングサイトへ
//! 4. 従来のメールフィルタはテキスト解析のため画像内 URL を検出できない
//!
//! # 防御アプローチ
//!
//! - 全画像添付を `rqrr` クレートで QR デコード試行
//! - デコードされた URL を `BadDomainDetector` で評価
//! - 怪しい URL (typosquatting、free TLD、最近登録) を警告
//! - UI に「QR コード発見」バナーを表示

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ============================================================================
// 検出結果
// ============================================================================

/// メール内で検出された QR コード。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectedQrCode {
    /// 画像添付の ID
    pub image_id: String,
    /// デコードされた内容 (URL の可能性が高い)
    pub decoded_text: String,
    /// URL 形式かどうか
    pub is_url: bool,
    /// URL 信頼性評価
    pub url_reputation: UrlReputation,
    /// 検出位置 (将来 OCR と統合する際の座標)
    pub position: Option<BoundingBox>,
}

/// URL 信頼性評価。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum UrlReputation {
    /// 既知の信頼できるドメイン (Amazon、Google 等)
    Trusted,
    /// 中立 (新規ドメインだが特に怪しくない)
    Neutral,
    /// 疑わしい (typosquatting、free TLD)
    Suspicious,
    /// 危険 (既知の悪意あるドメイン)
    Malicious,
}

/// 画像内の検出位置。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct BoundingBox {
    /// X 座標
    pub x: u32,
    /// Y 座標
    pub y: u32,
    /// 幅
    pub width: u32,
    /// 高さ
    pub height: u32,
}

// ============================================================================
// 検出器
// ============================================================================

/// Quishing 検出器。
pub struct QuishingDefense {
    /// 信頼できるドメインの許可リスト
    trusted_domains: HashSet<&'static str>,
    /// 既知の悪意あるドメイン (CTI フィード由来)
    known_malicious: HashSet<String>,
    /// 自由 TLD (悪用が多い)
    free_tlds: HashSet<&'static str>,
}

impl QuishingDefense {
    /// デフォルト設定で構築。
    #[must_use]
    pub fn new() -> Self {
        let trusted_domains: HashSet<&'static str> = [
            "amazon.com", "amazon.co.jp", "google.com", "microsoft.com",
            "apple.com", "github.com", "stripe.com", "anthropic.com",
        ].into_iter().collect();

        let free_tlds: HashSet<&'static str> = [
            ".tk", ".ml", ".ga", ".cf", ".gq",  // 無料ドメイン
            ".click", ".download", ".loan",     // 悪用多発 TLD
        ].into_iter().collect();

        Self {
            trusted_domains,
            known_malicious: HashSet::new(),
            free_tlds,
        }
    }

    /// 既知の悪意あるドメインを追加 (CTI フィードからの動的更新用)。
    pub fn add_malicious_domain(&mut self, domain: impl Into<String>) {
        self.known_malicious.insert(domain.into());
    }

    /// 画像バイト列から QR コードをデコードして検査する。
    ///
    /// # Errors
    ///
    /// 画像デコード失敗時にエラーを返す。
    pub fn scan_image(&self, _image_id: &str, _image_bytes: &[u8])
        -> Result<Option<DetectedQrCode>, QuishingError>
    {
        // 実装では `rqrr::PreparedImage` でデコード
        // ここではスケルトンのため、テスト可能な形でロジックを示す
        Ok(None)
    }

    /// デコード済みの QR テキストを評価する (テスト・統合用)。
    #[must_use]
    pub fn evaluate_decoded(&self, image_id: &str, decoded: &str) -> DetectedQrCode {
        let is_url = decoded.starts_with("http://") || decoded.starts_with("https://");
        let reputation = if is_url {
            self.evaluate_url(decoded)
        } else {
            UrlReputation::Neutral
        };

        DetectedQrCode {
            image_id: image_id.to_string(),
            decoded_text: decoded.to_string(),
            is_url,
            url_reputation: reputation,
            position: None,
        }
    }

    /// URL の信頼性を評価する。
    #[must_use]
    pub fn evaluate_url(&self, url: &str) -> UrlReputation {
        // ドメイン抽出 (簡易、本番は url クレートを使う)
        let domain = extract_domain(url).unwrap_or_default();

        // 1. 既知の悪意あるドメイン
        if self.known_malicious.contains(&domain) {
            return UrlReputation::Malicious;
        }

        // 2. 信頼できるドメイン
        if self.is_trusted(&domain) {
            return UrlReputation::Trusted;
        }

        // 3. 自由 TLD (悪用多発)
        for tld in &self.free_tlds {
            if domain.ends_with(tld) {
                return UrlReputation::Suspicious;
            }
        }

        // 4. ブランド・サブドメイン偽装検出
        //    例: `amazon.com.attacker.io` — 信頼ドメインが登録可能ドメインではなく
        //    サブドメインのプレフィックスとして現れる。実ホストは attacker.io。
        //    (正規のサブドメインは `.amazon.com` で *終わる* ため is_trusted で既に Trusted 判定済み)
        if self.has_trusted_brand_as_subdomain(&domain) {
            return UrlReputation::Suspicious;
        }

        // 5. Typosquatting 検出 (Levenshtein 距離)
        if self.is_typosquat(&domain) {
            return UrlReputation::Suspicious;
        }

        // 6. 数字混在の疑わしいパターン (例: amaz0n.com)
        if has_digit_substitution(&domain) {
            return UrlReputation::Suspicious;
        }

        UrlReputation::Neutral
    }

    fn is_trusted(&self, domain: &str) -> bool {
        self.trusted_domains.iter().any(|t| domain == *t || domain.ends_with(&format!(".{t}")))
    }

    /// 信頼ドメインがサブドメインのプレフィックスとして悪用されているか判定する。
    ///
    /// `amazon.com.attacker.io` のように `{信頼ドメイン}.` で始まるホストは、
    /// 実際の登録可能ドメインが別物 (attacker.io) であるため偽装の可能性が高い。
    /// 正規のサブドメイン (`aws.amazon.com`) は `.amazon.com` で終わるため
    /// この関数ではなく `is_trusted` 側で Trusted 判定される。
    fn has_trusted_brand_as_subdomain(&self, domain: &str) -> bool {
        self.trusted_domains
            .iter()
            .any(|t| domain.starts_with(&format!("{t}.")))
    }

    fn is_typosquat(&self, domain: &str) -> bool {
        // 信頼ドメインからの編集距離 1-3 で完全一致しないもの
        self.trusted_domains.iter().any(|trusted| {
            let dist = levenshtein(domain, trusted);
            (1..=3).contains(&dist) && domain != *trusted
        })
    }
}

impl Default for QuishingDefense {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ユーティリティ
// ============================================================================

/// URL からホスト名 (ドメイン) を抽出する。
///
/// セキュリティ考慮:
/// - `https://legit.com@attacker.com/` → userinfo を除去して `attacker.com`
/// - `http://`, `https://` 以外のスキームは None (data:, ftp:, javascript: 等)
/// - `//evil.com` (プロトコル相対) は None
/// - port (:443) を除去してホスト名のみ返す
fn extract_domain(url: &str) -> Option<String> {
    // スキームのみ http/https を許可
    let after_scheme = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else {
        return None; // ftp/data/javascript/protocol-relative 等は除外
    };

    // パスを除去: 最初の `/` または `?` または `#` まで
    let authority_end = after_scheme.find(['/', '?', '#']).unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];

    // userinfo を除去: `user:pass@host` → `host`
    // 攻撃例: `https://legit.com@attacker.com/` → authority = `legit.com@attacker.com`
    let host_with_port = if let Some(at_pos) = authority.rfind('@') {
        &authority[at_pos + 1..]
    } else {
        authority
    };

    // port を除去: `evil.com:8080` → `evil.com`
    // IPv6 は [::1]:443 形式なので '[' で判別
    let host = if host_with_port.starts_with('[') {
        // IPv6: [::1] or [::1]:443
        if let Some(close) = host_with_port.find(']') {
            &host_with_port[1..close] // brackets stripped
        } else {
            host_with_port
        }
    } else {
        host_with_port.split(':').next().unwrap_or(host_with_port)
    };

    if host.is_empty() {
        return None;
    }
    Some(host.to_lowercase())
}

fn has_digit_substitution(domain: &str) -> bool {
    // amaz0n, g00gle のような数字混入
    let known_patterns = [
        ("amaz0n",  "amazon"),
        ("amaz", "amazon"),  // partial だが追加検出
        ("g00gle",  "google"),
        ("micr0soft", "microsoft"),
        ("paypa1",  "paypal"),
        ("0ffice",  "office"),
    ];
    for (bad, _good) in &known_patterns {
        if domain.contains(bad) && !domain.contains(&bad.replace('0', "o").replace('1', "l")) {
            return true;
        }
    }
    false
}

fn levenshtein(a: &str, b: &str) -> usize {
    // 入力長ガード: QR コードは最大 ~2953 バイトをエンコードできるため、
    // デコードされた巨大ホスト名で O(m*n) の DP テーブルが無駄に確保されるのを防ぐ。
    // typosquat 判定は短いドメイン (信頼ドメインは最長 ~15 文字) が対象なので、
    // 一方が極端に長い場合は編集距離も大きく typosquat ではあり得ない → 早期 return。
    const MAX_DOMAIN_LEN: usize = 64;
    if a.len() > MAX_DOMAIN_LEN || b.len() > MAX_DOMAIN_LEN {
        return a.len().abs_diff(b.len()).max(1);
    }
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

// ============================================================================
// エラー型
// ============================================================================

/// Quishing 検出時のエラー。
#[derive(Debug, thiserror::Error)]
pub enum QuishingError {
    /// 画像デコード失敗
    #[error("画像デコードに失敗: {0}")]
    ImageDecode(String),

    /// QR デコード失敗 (画像に QR がない or 破損)
    #[error("QR コードが画像内に検出されませんでした")]
    NoQrCode,
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_trusted_domain() {
        let d = QuishingDefense::new();
        assert_eq!(d.evaluate_url("https://amazon.co.jp/order"), UrlReputation::Trusted);
        assert_eq!(d.evaluate_url("https://www.google.com/search"), UrlReputation::Trusted);
    }

    #[test]
    fn detects_free_tld_as_suspicious() {
        let d = QuishingDefense::new();
        assert_eq!(d.evaluate_url("https://amazon-secure.tk/login"), UrlReputation::Suspicious);
        assert_eq!(d.evaluate_url("https://login.ml/auth"),         UrlReputation::Suspicious);
    }

    #[test]
    fn detects_digit_substitution() {
        let d = QuishingDefense::new();
        assert_eq!(d.evaluate_url("https://amaz0n.com/login"), UrlReputation::Suspicious);
        assert_eq!(d.evaluate_url("https://paypa1.com/auth"), UrlReputation::Suspicious);
    }

    #[test]
    fn detects_typosquatting() {
        let d = QuishingDefense::new();
        // 1 文字違い (amzon = amazon - a)
        assert_eq!(d.evaluate_url("https://amzon.com/login"), UrlReputation::Suspicious);
        // 文字入れ替え
        assert_eq!(d.evaluate_url("https://amaozn.com/login"), UrlReputation::Suspicious);
    }

    #[test]
    fn known_malicious_takes_precedence() {
        let mut d = QuishingDefense::new();
        d.add_malicious_domain("evil-corp.com");
        assert_eq!(d.evaluate_url("https://evil-corp.com/exploit"), UrlReputation::Malicious);
    }

    #[test]
    fn neutral_unknown_domain() {
        let d = QuishingDefense::new();
        assert_eq!(d.evaluate_url("https://random-startup-2026.io/"), UrlReputation::Neutral);
    }

    #[test]
    fn evaluate_decoded_non_url() {
        let d = QuishingDefense::new();
        let r = d.evaluate_decoded("img-1", "WIFI:T:WPA;S:MyNet;P:pass123;;");
        assert!(!r.is_url);
        assert_eq!(r.url_reputation, UrlReputation::Neutral);
    }

    #[test]
    fn evaluate_decoded_phishing_url() {
        let d = QuishingDefense::new();
        let r = d.evaluate_decoded("img-1", "https://amaz0n-secure.tk/login");
        assert!(r.is_url);
        assert_eq!(r.url_reputation, UrlReputation::Suspicious); // free TLD
    }

    #[test]
    fn extract_domain_works() {
        assert_eq!(extract_domain("https://example.com/path"), Some("example.com".to_string()));
        assert_eq!(extract_domain("http://example.com"),       Some("example.com".to_string()));
        assert_eq!(extract_domain("https://example.com?q=1"),  Some("example.com".to_string()));
        assert_eq!(extract_domain("https://EXAMPLE.com/"),     Some("example.com".to_string()));
    }

    // ── URL パース セキュリティテスト ───────────────────────────────────────────

    #[test]
    fn extract_domain_strips_userinfo_confusion_attack() {
        // 攻撃: https://legit-bank.com@attacker.com/
        // 実際のホストは attacker.com — Levenshtein は attacker.com に対して実行すべき
        assert_eq!(
            extract_domain("https://legit-bank.com@attacker.com/"),
            Some("attacker.com".to_string()),
            "userinfo 部分を除去できていない"
        );
    }

    #[test]
    fn extract_domain_rejects_non_http_schemes() {
        assert_eq!(extract_domain("data:text/html,<script>alert(1)</script>"), None, "data: を許可した");
        assert_eq!(extract_domain("ftp://evil.com/file"), None, "ftp: を許可した");
        assert_eq!(extract_domain("javascript:void(0)"), None, "javascript: を許可した");
        assert_eq!(extract_domain("//evil.com/path"), None, "プロトコル相対を許可した");
    }

    #[test]
    fn extract_domain_strips_port() {
        assert_eq!(extract_domain("https://evil.com:8443/login"), Some("evil.com".to_string()));
        assert_eq!(extract_domain("http://evil.com:80/"), Some("evil.com".to_string()));
    }

    #[test]
    fn extract_domain_handles_ipv6() {
        // IPv6 ブラケット記法
        assert_eq!(extract_domain("http://[::1]/path"), Some("::1".to_string()));
        assert_eq!(extract_domain("http://[::1]:8080/path"), Some("::1".to_string()));
    }

    #[test]
    fn extract_domain_returns_none_for_empty_host() {
        assert_eq!(extract_domain("https:///path"), None);
        assert_eq!(extract_domain(""), None);
    }

    #[test]
    fn quishing_url_confusion_via_userinfo_flagged() {
        // QR コード内の URL が userinfo 混乱攻撃を含む場合も Suspicious になるはず
        let d = QuishingDefense::new();
        // amaz0n は Suspicious なドメイン — userinfo に合法ドメイン名を混ぜても無効
        let r = d.evaluate_decoded("qr-1", "https://legitimate.com@amaz0n.tk/login");
        // 実際のホスト amaz0n.tk は Suspicious (digit substitution + free TLD)
        assert_eq!(r.url_reputation, UrlReputation::Suspicious,
            "userinfo 混乱攻撃で Suspicious が検出されなかった");
    }

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("amazon", "amzon"), 1);
        assert_eq!(levenshtein("amazon", "amazon"), 0);
        assert_eq!(levenshtein("amazon", "amaozn"), 2);
    }

    // ── ブランド・サブドメイン偽装検出 ──────────────────────────────────────

    #[test]
    fn detects_trusted_brand_as_subdomain_prefix() {
        let d = QuishingDefense::new();
        // 実ホストは attacker.io だが amazon.com をプレフィックスに偽装
        assert_eq!(
            d.evaluate_url("https://amazon.com.attacker.io/login"),
            UrlReputation::Suspicious,
            "amazon.com.* のサブドメイン偽装が Neutral になっている"
        );
        // google.com も同様
        assert_eq!(
            d.evaluate_url("https://google.com.phish.example/verify"),
            UrlReputation::Suspicious
        );
        // 多段サブドメイン
        assert_eq!(
            d.evaluate_url("https://apple.com.secure-login.co/auth"),
            UrlReputation::Suspicious
        );
    }

    #[test]
    fn legit_subdomain_of_trusted_stays_trusted() {
        let d = QuishingDefense::new();
        // 正規のサブドメインは `.amazon.com` で終わる → Trusted のまま
        assert_eq!(
            d.evaluate_url("https://aws.amazon.com/console"),
            UrlReputation::Trusted,
            "正規サブドメインが誤って Suspicious になった"
        );
        assert_eq!(
            d.evaluate_url("https://mail.google.com/inbox"),
            UrlReputation::Trusted
        );
    }

    #[test]
    fn brand_subdomain_in_qr_is_flagged() {
        let d = QuishingDefense::new();
        let r = d.evaluate_decoded("qr-2", "https://microsoft.com.login-verify.tk/");
        // free TLD でもブランド偽装でも Suspicious になる
        assert_eq!(r.url_reputation, UrlReputation::Suspicious);
    }

    // ── Levenshtein 入力長ガード ────────────────────────────────────────────

    #[test]
    fn levenshtein_caps_oversized_input() {
        // 64 文字超の入力では DP テーブルを確保せず長さ差を返す
        let huge = "a".repeat(3000);
        let dist = levenshtein(&huge, "amazon");
        assert!(dist > 3, "巨大入力は typosquat 距離 (1-3) に入ってはならない");
    }

    #[test]
    fn oversized_qr_host_does_not_panic_and_is_not_typosquat() {
        let d = QuishingDefense::new();
        // 巨大なホスト名を持つ URL (QR は最大 ~2953 バイト)
        let host = "x".repeat(2900);
        let url = format!("https://{host}.com/");
        // パニックせず、typosquat にも誤判定しないこと
        let rep = d.evaluate_url(&url);
        assert_eq!(rep, UrlReputation::Neutral,
            "巨大ホストは typosquat ではなく Neutral であるべき: {rep:?}");
    }
}
