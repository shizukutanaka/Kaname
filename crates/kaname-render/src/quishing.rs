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
//! - 危険スキーム (`blob:`/`data:`/`javascript:`) の QR ペイロードを格上げ検出
//! - 分割 QR (Structured Append) の兆候をメール内 QR 個数から検出 (`assess_multi_qr`)
//! - 画像デコードを経由しない ASCII アート QR の兆候をテキスト解析で検出 (`detect_ascii_qr`)

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

/// 同一メール内の複数 QR コードの構造的リスク評価。
///
/// 分割 QR (Structured Append) 攻撃対策。個々の QR ペイロードとは独立に、
/// 「1 通のメールに QR が何個あるか」だけで判定する。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MultiQrRisk {
    /// QR は 0-1 個 (通常)
    Normal,
    /// QR が 2 個 (正規メールでも稀にあるが注意)
    Elevated,
    /// QR が 3 個以上 (分割 QR 攻撃の疑い)
    SplitQrSuspected,
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
        } else if has_dangerous_scheme(decoded) {
            // blob:/data:/javascript: は http(s) ではないが、QR 経由で開かせると
            // ブラウザ内でペイロードが実行され得る (2025-26 年の quishing 亜種)。
            // Neutral で素通りさせず Suspicious に格上げする。
            UrlReputation::Suspicious
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

    /// 本文プレーンテキスト中に ASCII アート QR コードらしき塊がないか判定する。
    ///
    /// 2025-26 年に観測された亜種: QR を画像ではなくブロック文字
    /// (`█`, `▀`, `▄` 等) や `#`/`@` の羅列で描画し、画像スキャン型の
    /// 検出 (`scan_image`) を回避する。画像デコードは不要で、
    /// メール本文の構造 (連続する等幅っぽい正方形ブロック) から検知できる。
    #[must_use]
    pub fn detect_ascii_qr(&self, body: &str) -> bool {
        const QR_BLOCK_CHARS: &[char] = &['█', '▀', '▄', '▌', '▐', '░', '▒', '▓'];
        const MIN_QR_LINES: usize = 8; // 実用的な QR は最低 21x21 モジュールだが、
                                       // ASCII 縮小表現でも最低限の行数を要求する
        const MIN_DENSITY: f64 = 0.5; // ブロック文字が行の半分以上を占める

        let mut consecutive_block_lines = 0usize;

        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                consecutive_block_lines = 0;
                continue;
            }
            let total = trimmed.chars().count();
            if total == 0 {
                continue;
            }
            let block_count = trimmed.chars().filter(|c| QR_BLOCK_CHARS.contains(c)).count();
            let density = block_count as f64 / total as f64;

            if density >= MIN_DENSITY && total >= 8 {
                consecutive_block_lines += 1;
                if consecutive_block_lines >= MIN_QR_LINES {
                    return true;
                }
            } else {
                consecutive_block_lines = 0;
            }
        }
        false
    }

    /// 同一メール内の複数 QR コードを構造的リスクとして評価する。
    ///
    /// 2025-26 年に観測された「分割 QR (Structured Append)」攻撃では、
    /// 悪意ある URL を複数の QR に分割し、単一画像スキャンを回避する。
    /// 個々の QR の中身が Neutral でも、1 通に複数の QR がある事実そのものが
    /// 攻撃の兆候になる。
    #[must_use]
    pub fn assess_multi_qr(&self, qr_count: usize) -> MultiQrRisk {
        match qr_count {
            0 | 1 => MultiQrRisk::Normal,
            2 => MultiQrRisk::Elevated,
            _ => MultiQrRisk::SplitQrSuspected,
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

    /// 信頼ドメインがサブドメインのプレフィックスまたは中間ラベルとして悪用されているか判定する。
    ///
    /// 検出パターン:
    /// - プレフィックス: `amazon.com.attacker.io` — `{trusted}.` で始まる
    /// - インフィックス: `sub.amazon.com.evil.io` — `.{trusted}.` を含む
    ///
    /// 正規のサブドメイン (`aws.amazon.com`) は `.amazon.com` で*終わる*ため
    /// `is_trusted` 側で Trusted 判定済みであり、この関数には届かない。
    fn has_trusted_brand_as_subdomain(&self, domain: &str) -> bool {
        self.trusted_domains.iter().any(|t| {
            domain.starts_with(&format!("{t}.")) || domain.contains(&format!(".{t}."))
        })
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

/// QR ペイロードが http(s) 以外の危険スキームで始まるか判定する。
///
/// `blob:` はローカル Blob URI 経由でフィッシングページを表示する亜種
/// (メールフィルタは URL を外部照会できない)、`data:` はページ全体を
/// ペイロードに内包する亜種、`javascript:` はスキャナアプリ内 WebView での
/// スクリプト実行を狙う。大文字小文字のバリエーションも吸収する。
fn has_dangerous_scheme(payload: &str) -> bool {
    const DANGEROUS: [&str; 3] = ["blob:", "data:", "javascript:"];
    let lower = payload.trim_start().to_lowercase();
    DANGEROUS.iter().any(|s| lower.starts_with(s))
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

    #[test]
    fn detects_trusted_brand_as_infix_subdomain() {
        let d = QuishingDefense::new();
        // インフィックスパターン: `sub.amazon.com.evil.io` — starts_with では検出できない
        assert_eq!(
            d.evaluate_url("https://sub.amazon.com.evil.io/login"),
            UrlReputation::Suspicious,
            "sub.amazon.com.evil.io のインフィックスブランド偽装が検出されなかった"
        );
        assert_eq!(
            d.evaluate_url("https://account.google.com.phisher.net/auth"),
            UrlReputation::Suspicious,
            "account.google.com.phisher.net のインフィックス偽装が検出されなかった"
        );
        assert_eq!(
            d.evaluate_url("https://secure.microsoft.com.login.ru/verify"),
            UrlReputation::Suspicious,
            "secure.microsoft.com.login.ru のインフィックス偽装が検出されなかった"
        );
    }

    #[test]
    fn deep_infix_brand_in_qr_is_flagged() {
        let d = QuishingDefense::new();
        let r = d.evaluate_decoded("qr-3", "https://one.two.apple.com.badactor.cn/download");
        assert_eq!(r.url_reputation, UrlReputation::Suspicious,
            "QR 内の深い階層インフィックス偽装が検出されなかった");
    }

    // ── 危険スキーム検出 (blob:/data:/javascript:) ──────────────────────────

    #[test]
    fn blob_uri_qr_is_suspicious() {
        let d = QuishingDefense::new();
        let r = d.evaluate_decoded("qr-blob", "blob:https://evil.example/uuid-1234");
        assert!(!r.is_url, "blob: は http(s) URL として扱わない");
        assert_eq!(r.url_reputation, UrlReputation::Suspicious,
            "blob: URI が Neutral で素通りしている");
    }

    #[test]
    fn data_uri_qr_is_suspicious() {
        let d = QuishingDefense::new();
        let r = d.evaluate_decoded("qr-data", "data:text/html;base64,PHNjcmlwdD4=");
        assert_eq!(r.url_reputation, UrlReputation::Suspicious,
            "data: URI が Neutral で素通りしている");
    }

    #[test]
    fn javascript_uri_qr_is_suspicious() {
        let d = QuishingDefense::new();
        let r = d.evaluate_decoded("qr-js", "javascript:fetch('https://evil.example')");
        assert_eq!(r.url_reputation, UrlReputation::Suspicious);
    }

    #[test]
    fn dangerous_scheme_case_variation_detected() {
        let d = QuishingDefense::new();
        // 大文字小文字のバリエーションでの回避を防ぐ
        assert_eq!(d.evaluate_decoded("q1", "BLOB:https://x.example/z").url_reputation,
            UrlReputation::Suspicious);
        assert_eq!(d.evaluate_decoded("q2", "Data:text/html,hello").url_reputation,
            UrlReputation::Suspicious);
        assert_eq!(d.evaluate_decoded("q3", "JavaScript:void(0)").url_reputation,
            UrlReputation::Suspicious);
    }

    #[test]
    fn dangerous_scheme_leading_whitespace_detected() {
        let d = QuishingDefense::new();
        let r = d.evaluate_decoded("q4", "  data:text/html,x");
        assert_eq!(r.url_reputation, UrlReputation::Suspicious,
            "先頭空白で危険スキーム検出を回避できてしまう");
    }

    #[test]
    fn wifi_payload_stays_neutral() {
        // 正規の非 URL ペイロード (WiFi 設定等) は引き続き Neutral
        let d = QuishingDefense::new();
        let r = d.evaluate_decoded("q5", "WIFI:T:WPA;S:MyNet;P:pass123;;");
        assert_eq!(r.url_reputation, UrlReputation::Neutral);
    }

    // ── ASCII アート QR 検出 ─────────────────────────────────────────────────

    #[test]
    fn detects_ascii_qr_block() {
        let d = QuishingDefense::new();
        let line = "█▀▄▀█▄▀█▀▄▀█▄▀█▀▄▀█▄▀█";
        let body: String = std::iter::repeat(line).take(10).collect::<Vec<_>>().join("\n");
        assert!(d.detect_ascii_qr(&body), "ブロック文字の羅列が ASCII QR として検出されなかった");
    }

    #[test]
    fn normal_text_is_not_ascii_qr() {
        let d = QuishingDefense::new();
        let body = "こんにちは、\n来週の会議についてですが、\n資料を添付します。\nよろしくお願いします。";
        assert!(!d.detect_ascii_qr(body), "通常の文章を ASCII QR と誤検出した");
    }

    #[test]
    fn short_block_run_not_flagged() {
        let d = QuishingDefense::new();
        // MIN_QR_LINES (8) 未満の連続では検出しない
        let line = "████████████████";
        let body: String = std::iter::repeat(line).take(3).collect::<Vec<_>>().join("\n");
        assert!(!d.detect_ascii_qr(&body), "短すぎるブロック行の連続を誤検出した");
    }

    #[test]
    fn blank_line_resets_consecutive_count() {
        let d = QuishingDefense::new();
        let block_line = "█▀▄▀█▄▀█▀▄▀█▄▀█▀▄▀█▄▀█";
        // 5行 + 空行 + 5行 (空行で連続カウントがリセットされ 8 行連続に届かない)
        let mut lines: Vec<&str> = std::iter::repeat(block_line).take(5).collect();
        lines.push("");
        lines.extend(std::iter::repeat(block_line).take(5));
        let body = lines.join("\n");
        assert!(!d.detect_ascii_qr(&body), "空行を挟んだ分断ブロックを誤検出した");
    }

    // ── 分割 QR (Structured Append) 検出 ────────────────────────────────────

    #[test]
    fn single_qr_is_normal() {
        let d = QuishingDefense::new();
        assert_eq!(d.assess_multi_qr(0), MultiQrRisk::Normal);
        assert_eq!(d.assess_multi_qr(1), MultiQrRisk::Normal);
    }

    #[test]
    fn two_qr_is_elevated() {
        let d = QuishingDefense::new();
        assert_eq!(d.assess_multi_qr(2), MultiQrRisk::Elevated);
    }

    #[test]
    fn three_or_more_qr_suspected_split_attack() {
        let d = QuishingDefense::new();
        assert_eq!(d.assess_multi_qr(3), MultiQrRisk::SplitQrSuspected);
        assert_eq!(d.assess_multi_qr(10), MultiQrRisk::SplitQrSuspected);
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
