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
    /// URL 短縮・リダイレクトサービス (動的 QR の実現手段)。
    url_shorteners: HashSet<&'static str>,
    /// 剥がせないメールセキュリティ URL 書き換えサービス (検証不能の間接参照)。
    url_rewriters: HashSet<&'static str>,
}

impl QuishingDefense {
    /// デフォルト設定で構築。
    #[must_use]
    pub fn new() -> Self {
        let trusted_domains: HashSet<&'static str> = [
            "amazon.com",
            "amazon.co.jp",
            "google.com",
            "microsoft.com",
            "apple.com",
            "github.com",
            "stripe.com",
            "anthropic.com",
        ]
        .into_iter()
        .collect();

        let free_tlds: HashSet<&'static str> = [
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".gq", // 無料ドメイン
            ".click",
            ".download",
            ".loan", // 悪用多発 TLD
        ]
        .into_iter()
        .collect();

        // URL 短縮・リダイレクトサービス。
        //
        // # 動的 QR (dynamic QR) 攻撃
        //
        // 攻撃者は QR の中身に短縮 URL / QR 生成サービスのリダイレクタを埋め、
        // **配信直後は無害なページを指しておく**。メールがセキュリティ検査を
        // 通過した後で、同じ URL のリダイレクト先をフィッシングサイトへ差し替える。
        // 検査時点の宛先が無害でも意味がないため、スキャン時に最終宛先を
        // 検証できない参照そのものを疑わしいものとして扱う。
        //
        // 出典: 2026 年の quishing 動向 (上半期に約 146% 増)、
        // FBI 警告 (2026-01, Kimsuky/APT43 が MFA 耐性のある侵入経路として使用)。
        let url_shorteners: HashSet<&'static str> = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "rebrand.ly",
            "cutt.ly",
            "shorturl.at",
            "rb.gy",
            "s.id",
            "tiny.cc",
            "lnkd.in",
            "t.ly",
            "shrtco.de",
            // QR 生成/リダイレクトサービス (動的 QR の中核)
            "qrco.de",
            "qr.codes",
            "scanova.io",
            "qrfy.com",
            "flowcode.com",
        ]
        .into_iter()
        .collect();

        // メールセキュリティゲートウェイの URL 書き換えホスト (D786)。
        // `unwrap_protected_url` で剥がせたものは内側を評価するためここに
        // 来ない。ここに残るのは「復元にサーバ側情報が要る」系で、宛先を
        // 一切検証できない間接参照 — 短縮 URL と同じく Suspicious 扱い。
        let url_rewriters: HashSet<&'static str> = [
            // 剥がしに失敗した場合のフォールバック (本則は unwrap で復元)
            "safelinks.protection.outlook.com", // Microsoft SafeLinks
            "urldefense.com",                  // Proofpoint URL Defense
            "urldefense.proofpoint.com",
            // 宛先をサーバ側でしか復元できない書き換えサービス
            "linkprotect.cudasvc.com",   // Barracuda Link Protection
            "secure-web.cisco.com",      // Cisco Secure Email
            "clicktime.trendmicro.com",  // Trend Micro ClickTime
            "protection.sophos.com",     // Sophos Email
            "websense.com",              // Forcepoint/Websense
            "wsed.org",                  // Websense Email Security
            "mimecastprotect.com",       // Mimecast URL Protection
            "avanan.net",                // Check Point Avanan
        ]
        .into_iter()
        .collect();

        Self {
            trusted_domains,
            known_malicious: HashSet::new(),
            free_tlds,
            url_shorteners,
            url_rewriters,
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
    pub fn scan_image(
        &self,
        _image_id: &str,
        _image_bytes: &[u8],
    ) -> Result<Option<DetectedQrCode>, QuishingError> {
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
        // QR をテキストで描画する際に使われる文字。
        //
        // Barracuda の観測では、攻撃者は QR を画像ではなく **ASCII/Unicode 文字**で
        // 構成し、画像添付だけを走査するフィルタを回避する。罫線ブロックだけでなく
        // 幾何学記号・全角記号・点字ブロックも同じ用途で使われるため対象に含める。
        const QR_BLOCK_CHARS: &[char] = &[
            // 罫線ブロック
            '█', '▀', '▄', '▌', '▐', '░', '▒', '▓',
            // 幾何学記号 (黒/白の塗り分けで QR を表現)
            '■', '□', '▪', '▫', '◼', '◻', '●', '○', '◾', '◽',
            // 絵文字ブロック (メール本文でよく使われる)
            '⬛', '⬜', '🟥', '🟦', // 全角記号
            '　',
        ];
        // 点字ブロック (U+2800..U+28FF) は 2x4 ドットを 1 文字で表現できるため
        // テキスト QR レンダラで最も多用される。範囲判定で一括して扱う。
        fn is_braille_block(c: char) -> bool {
            ('\u{2800}'..='\u{28FF}').contains(&c)
        }
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
            let block_count = trimmed
                .chars()
                .filter(|c| QR_BLOCK_CHARS.contains(c) || is_braille_block(*c))
                .count();
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
    ///
    /// メールセキュリティゲートウェイ (SafeLinks/URLDefense/Mimecast 等) が
    /// リンクを自社ドメインで書き換える「保護 URL」は、**外側のドメインで
    /// 評価すると「信頼済みベンダーのドメインだから安全」と誤判定する**。
    /// 攻撃者はこの「信頼ドメインの外套」を使い、既知の悪意ドメインや
    /// ラッパ経由でしか辿れない宛先を隠蔽する (2025 年の URLDefense/
    /// SafeLinks 悪用 — ラッパ経由で URL スキャンを迂回する手法として
    /// Cofense/Trustwave 等が報告)。復元できるラッパは剥がして最終宛先を
    /// 評価し、復元できない書き換えホストは「検証不能の間接参照」として
    /// Suspicious にする (D786)。
    #[must_use]
    pub fn evaluate_url(&self, url: &str) -> UrlReputation {
        self.evaluate_url_inner(url, 0)
    }

    /// `depth` はラッパ剥がしの再帰上限管理用。メールが複数の
    /// ゲートウェイを通ると URL が二重に包まれることがあるため
    /// 2 段まで許容し、それ以上は評価不能として打ち切る。
    fn evaluate_url_inner(&self, url: &str, depth: u8) -> UrlReputation {
        const MAX_UNWRAP_DEPTH: u8 = 2;

        // 0. 保護/書き換えラッパの剥がし — 内側の最終宛先を評価する (D786)
        if depth < MAX_UNWRAP_DEPTH {
            if let Some(inner) = unwrap_protected_url(url) {
                return self.evaluate_url_inner(&inner, depth + 1);
            }
        }

        // ドメイン抽出 (簡易、本番は url クレートを使う)
        let domain = extract_domain(url).unwrap_or_default();

        // 0.5 剥がせない書き換えサービス — 宛先を検証できない間接参照
        if self.is_unverifiable_rewriter(&domain) {
            return UrlReputation::Suspicious;
        }

        // 1. 既知の悪意あるドメイン
        if self.known_malicious.contains(&domain) {
            return UrlReputation::Malicious;
        }

        // 2. 信頼できるドメイン
        if self.is_trusted(&domain) {
            return UrlReputation::Trusted;
        }

        // 2.5 IDN / Punycode ドメイン (D792 — ホモグラフ攻撃)
        //    `xn--` ラベルはブラウザが Unicode 化して表示するため、
        //    ASCII 文字列として読む利用者・スキャナには別ドメインに見える
        //    (paypal → pаypal のキリル а 等、UTS#39 の紛らわしい文字)。
        //    また Unicode を直接含むホストも同型のホモグラフ経路。
        //    正規 IDN (日本語ドメイン等) も存在するが、未検査では絞り込め
        //    ないため Suspicious (審査してから開け、という水準) に倒す。
        if domain.split('.').any(|l| l.starts_with("xn--"))
            || domain.chars().any(|c| !c.is_ascii())
        {
            return UrlReputation::Suspicious;
        }

        // 3. 短縮 URL / リダイレクタ (動的 QR の実現手段)
        //    スキャン時点の宛先が無害でも、後から差し替えられるため検証不能。
        //    QR という「人間が中身を読めない」文脈では特にリスクが高い。
        if self.is_url_shortener(&domain) {
            return UrlReputation::Suspicious;
        }

        // 4. 自由 TLD (悪用多発)
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
        self.trusted_domains
            .iter()
            .any(|t| domain == *t || domain.ends_with(&format!(".{t}")))
    }

    /// URL 短縮・リダイレクトサービスのドメインか判定する。
    ///
    /// サブドメイン形式のカスタム短縮 (`go.bit.ly` 等) も対象に含める。
    fn is_url_shortener(&self, domain: &str) -> bool {
        self.url_shorteners
            .iter()
            .any(|s| domain == *s || domain.ends_with(&format!(".{s}")))
    }

    /// 宛先を復元できないメールセキュリティ URL 書き換えホストか判定する (D786)。
    ///
    /// Mimecast は `protect-<region>.mimecast.com` 系のホスト名を使うため
    /// サフィックス一致に加えて接頭辞条件を個別に判定する。
    fn is_unverifiable_rewriter(&self, domain: &str) -> bool {
        if domain.starts_with("protect-") && domain.ends_with(".mimecast.com") {
            return true;
        }
        self.url_rewriters
            .iter()
            .any(|h| domain == *h || domain.ends_with(&format!(".{h}")))
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
        self.trusted_domains
            .iter()
            .any(|t| domain.starts_with(&format!("{t}.")) || domain.contains(&format!(".{t}.")))
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
    } else {
        // ftp/data/javascript/protocol-relative 等は除外
        url.strip_prefix("http://")?
    };

    // パスを除去: 最初の `/` または `?` または `#` まで
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
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
        ("amaz0n", "amazon"),
        ("amaz", "amazon"), // partial だが追加検出
        ("g00gle", "google"),
        ("micr0soft", "microsoft"),
        ("paypa1", "paypal"),
        ("0ffice", "office"),
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
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
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
    dp[m][n]
}

// ============================================================================
// URL 書き換えラッパの剥がし (D786)
// ============================================================================

/// メールセキュリティゲートウェイやリダイレクタが URL を包む
/// 「保護 URL」を剥がして内側の最終宛先を返す。
///
/// 対応形式:
/// - Microsoft SafeLinks: `*.safelinks.protection.outlook.com/?url=<percent>`
/// - Proofpoint URLDefense v1/v2/v3 (公式 `urldecoder.py` 準拠)
/// - Google リダイレクタ: `google.*/url?q=` `/imgres?imgurl=`
/// - Slack リダイレクタ: `slack-redir.net/?url=`
/// - Bing リダイレクタ: `bing.com/ck/a?...&u=a1<urlsafe-b64>`
/// - Mimecast: `protect-*.mimecast.com/...?domain=<宛先ドメイン>`
///
/// 返り値: 剥がせた内側 URL。ラッパでない、または復元不能なら `None`。
fn unwrap_protected_url(url: &str) -> Option<String> {
    let domain = extract_domain(url)?;

    // --- Microsoft SafeLinks ---
    if domain == "safelinks.protection.outlook.com"
        || domain.ends_with(".safelinks.protection.outlook.com")
    {
        return query_param(url, "url")
            .map(|v| html_unescape(&percent_decode(&v)))
            .filter(|u| u.starts_with("http://") || u.starts_with("https://"));
    }

    // --- Proofpoint URLDefense (v1/v2/v3) ---
    if domain == "urldefense.com" || domain == "urldefense.proofpoint.com" {
        return decode_urldefense(url);
    }

    // --- Mimecast URL Protection ---
    // protect-<region>.mimecast.com / *.mimecastprotect.com
    // 宛先ドメインは `?domain=` クエリに書かれる (パス全体は復元不能)。
    if (domain.starts_with("protect-") && domain.ends_with(".mimecast.com"))
        || domain.ends_with(".mimecastprotect.com")
        || domain == "mimecastprotect.com"
    {
        let dest = query_param(url, "domain").map(|v| percent_decode(&v))?;
        // ドメインとして妥当な形だけを受け付ける (クエリ混入を防ぐ)
        if !dest.is_empty()
            && !dest.contains(['/', '?', '&', '#', '@', ' '])
            && dest.contains('.')
        {
            return Some(format!("https://{dest}"));
        }
        return None;
    }

    // --- Google リダイレクタ ---
    // google.com/url?q= / /imgres?imgurl= (国別ドメイン含む)
    if is_google_host(&domain) && (url.contains("/url?") || url.contains("/imgres?")) {
        for name in ["q", "url", "imgurl"] {
            if let Some(v) = query_param(url, name) {
                let inner = html_unescape(&percent_decode(&v));
                if inner.starts_with("http://") || inner.starts_with("https://") {
                    return Some(inner);
                }
            }
        }
        return None;
    }

    // --- Slack リダイレクタ ---
    if domain == "slack-redir.net" || domain.ends_with(".slack-redir.net") {
        return query_param(url, "url")
            .map(|v| html_unescape(&percent_decode(&v)))
            .filter(|u| u.starts_with("http://") || u.starts_with("https://"));
    }

    // --- Bing リダイレクタ ---
    // bing.com/ck/a?...&u=a1<urlsafe-base64> — `a1` 接頭辞 + base64url の宛先
    if domain == "bing.com" || domain.ends_with(".bing.com") {
        let u = query_param(url, "u")?;
        let b64 = u.strip_prefix("a1")?;
        let inner = String::from_utf8_lossy(&urlsafe_b64_decode(b64)).into_owned();
        if inner.starts_with("http://") || inner.starts_with("https://") {
            return Some(inner);
        }
        return None;
    }

    None
}

/// `google.com`・`google.co.jp` 等の国別ドメインを含む Google ホストか判定する。
fn is_google_host(domain: &str) -> bool {
    domain == "google.com"
        || domain.ends_with(".google.com")
        || domain.starts_with("google.")
        || domain.contains(".google.")
}

/// Proofpoint URLDefense の書き換え URL を復元する。
/// 公式 `urldecoder.py` (Proofpoint, GPL v3) の v1/v2/v3 アルゴリズムに準拠。
///
/// - v1: `u=<percent-encoded>&k=` → percent-decode → html-unescape
/// - v2: `u=<translated>&[dc]=` → `-`→`%`, `_`→`/` 置換 → percent-decode → html-unescape
/// - v3: `/v3/__<マングル URL>__;<urlsafe-b64>!` → 単一スラッシュ修復 →
///       percent-decode → `*` (1 文字) / `**X` (run 長マッピング) トークンを
///       base64 デコード済みバイト列で置換
fn decode_urldefense(url: &str) -> Option<String> {
    // v3: /v3/__(マングル URL)__;(urlsafe-b64)!
    if let Some(v3_pos) = url.find("/v3/") {
        let rest = url[v3_pos + 4..].strip_prefix("__")?;
        // `(?P<url>.+?)__;` — 最初に `__;` が現れる位置までが宛先
        let mangled_end = rest.find("__;")?;
        let mangled = &rest[..mangled_end];
        let enc_b64 = rest[mangled_end + 2..]
            .strip_prefix(';')?
            .split('!')
            .next()
            .unwrap_or("");
        let fixed = fix_v3_single_slash(mangled);
        let decoded_url = percent_decode(&fixed);
        let enc_bytes = urlsafe_b64_decode(enc_b64);
        let dec: Vec<char> = String::from_utf8_lossy(&enc_bytes).chars().collect();
        let inner = substitute_v3_tokens(&decoded_url, &dec)?;
        if inner.starts_with("http://") || inner.starts_with("https://") {
            return Some(inner);
        }
        return None;
    }
    let is_v2 = url.contains("/v2/");
    // v1/v2 ともに宛先は u= パラメータ
    let u = query_param(url, "u")?;
    // v2 は `-`→`%`、`_`→`/` の独自変換 (公式 urldecoder の maketrans)
    let translated: String = if is_v2 {
        u.chars()
            .map(|c| match c {
                '-' => '%',
                '_' => '/',
                _ => c,
            })
            .collect()
    } else {
        u
    };
    let inner = html_unescape(&percent_decode(&translated));
    if inner.starts_with("http://") || inner.starts_with("https://") {
        Some(inner)
    } else {
        None
    }
}

/// URLDefense v3 が `https:/example.com` のように単一スラッシュへ潰す
/// スキーム区切りを `://` に復元する (公式 v3_single_slash 相当):
/// `^([a-z0-9+.-]+:/)([^/].+)` → `\1/\2`。
fn fix_v3_single_slash(url: &str) -> String {
    if let Some(colon) = url.find(':') {
        let scheme = &url[..colon];
        let valid = !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
        let rest = &url[colon + 1..];
        if valid && rest.starts_with('/') && !rest.starts_with("//") && rest.len() > 1 {
            return format!("{scheme}:/{rest}");
        }
    }
    url.to_string()
}

/// URLDefense v3 の `*` 系トークンを、base64 復元したバイト列 (文字)
/// で置換する。`*` = 1 文字、`**X` = run_mapping (A-Z=2..27, a-z=28..53,
/// 0-9=54..63, '-'=64, '_'=65) 個の連続文字。
///
/// トークンが解決できない (マッピング外・バイト不足) 場合は `None` を
/// 返す — 部分復元した URL を評価すると宛先を誤認するため。
fn substitute_v3_tokens(text: &str, dec_bytes: &[char]) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut marker = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '*' {
            if i + 2 < chars.len() && chars[i + 1] == '*' {
                // `**X` — X は run 長マッピング
                let run = v3_run_value(chars[i + 2])?;
                if marker + run > dec_bytes.len() {
                    return None;
                }
                for &b in &dec_bytes[marker..marker + run] {
                    out.push(b);
                }
                marker += run;
                i += 3;
            } else {
                // 単一 `*` — 1 文字
                if marker >= dec_bytes.len() {
                    return None;
                }
                out.push(dec_bytes[marker]);
                marker += 1;
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    Some(out)
}

/// 公式 urldecoder の v3_run_mapping: A-Z=2..=27, a-z=28..=53,
/// 0-9=54..=63, '-'=64, '_'=65。
fn v3_run_value(c: char) -> Option<usize> {
    match c {
        'A'..='Z' => Some(c as usize - 'A' as usize + 2),
        'a'..='z' => Some(c as usize - 'a' as usize + 28),
        '0'..='9' => Some(c as usize - '0' as usize + 54),
        '-' => Some(64),
        '_' => Some(65),
        _ => None,
    }
}

/// `?`/`&` 区切りのクエリから `name=` の値を取り出す。
/// 値は `&` または `#` まで。パラメータ名の前方一致だけを見るため
/// `imgurl=` の中の `url=` 等の誤検出は起きない。
fn query_param(url: &str, name: &str) -> Option<String> {
    let q = url.find('?')?;
    let query = &url[q + 1..];
    let query = query.split('#').next().unwrap_or(query);
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
}

/// パーセントデコード (`%XX` → バイト、`+` → 空白)。
/// URL 解析用の外部クレートを追加しない方針のため自前で実装する。
fn percent_decode(s: &str) -> String {
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// URL 書き換えで使われる最小限の HTML エスケープだけを戻す。
/// (`&amp;` → `&` が本筋 — SafeLinks/urldefense の u= 値で頻出)
fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&#38;", "&")
        .replace("&#x26;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

/// RFC 4648 の URL-safe base64 をデコードする (`-`/`_` 版、`=` パディング可)。
/// アルファベット外の文字は読み飛ばす (末尾 `=` や混入の空白を許容)。
fn urlsafe_b64_decode(s: &str) -> Vec<u8> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for &b in s.as_bytes() {
        let Some(v) = val(b) else {
            continue;
        };
        acc = (acc << 6) | u32::from(v);
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    out
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn detects_trusted_domain() {
        let d = QuishingDefense::new();
        assert_eq!(
            d.evaluate_url("https://amazon.co.jp/order"),
            UrlReputation::Trusted
        );
        assert_eq!(
            d.evaluate_url("https://www.google.com/search"),
            UrlReputation::Trusted
        );
    }

    #[test]
    fn detects_free_tld_as_suspicious() {
        let d = QuishingDefense::new();
        assert_eq!(
            d.evaluate_url("https://amazon-secure.tk/login"),
            UrlReputation::Suspicious
        );
        assert_eq!(
            d.evaluate_url("https://login.ml/auth"),
            UrlReputation::Suspicious
        );
    }

    #[test]
    fn detects_digit_substitution() {
        let d = QuishingDefense::new();
        assert_eq!(
            d.evaluate_url("https://amaz0n.com/login"),
            UrlReputation::Suspicious
        );
        assert_eq!(
            d.evaluate_url("https://paypa1.com/auth"),
            UrlReputation::Suspicious
        );
    }

    #[test]
    fn detects_typosquatting() {
        let d = QuishingDefense::new();
        // 1 文字違い (amzon = amazon - a)
        assert_eq!(
            d.evaluate_url("https://amzon.com/login"),
            UrlReputation::Suspicious
        );
        // 文字入れ替え
        assert_eq!(
            d.evaluate_url("https://amaozn.com/login"),
            UrlReputation::Suspicious
        );
    }

    #[test]
    fn known_malicious_takes_precedence() {
        let mut d = QuishingDefense::new();
        d.add_malicious_domain("evil-corp.com");
        assert_eq!(
            d.evaluate_url("https://evil-corp.com/exploit"),
            UrlReputation::Malicious
        );
    }

    #[test]
    fn neutral_unknown_domain() {
        let d = QuishingDefense::new();
        assert_eq!(
            d.evaluate_url("https://random-startup-2026.io/"),
            UrlReputation::Neutral
        );
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
        assert_eq!(
            extract_domain("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_domain("http://example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_domain("https://example.com?q=1"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_domain("https://EXAMPLE.com/"),
            Some("example.com".to_string())
        );
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
        assert_eq!(
            extract_domain("data:text/html,<script>alert(1)</script>"),
            None,
            "data: を許可した"
        );
        assert_eq!(
            extract_domain("ftp://evil.com/file"),
            None,
            "ftp: を許可した"
        );
        assert_eq!(
            extract_domain("javascript:void(0)"),
            None,
            "javascript: を許可した"
        );
        assert_eq!(
            extract_domain("//evil.com/path"),
            None,
            "プロトコル相対を許可した"
        );
    }

    #[test]
    fn extract_domain_strips_port() {
        assert_eq!(
            extract_domain("https://evil.com:8443/login"),
            Some("evil.com".to_string())
        );
        assert_eq!(
            extract_domain("http://evil.com:80/"),
            Some("evil.com".to_string())
        );
    }

    #[test]
    fn extract_domain_handles_ipv6() {
        // IPv6 ブラケット記法
        assert_eq!(extract_domain("http://[::1]/path"), Some("::1".to_string()));
        assert_eq!(
            extract_domain("http://[::1]:8080/path"),
            Some("::1".to_string())
        );
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
        assert_eq!(
            r.url_reputation,
            UrlReputation::Suspicious,
            "userinfo 混乱攻撃で Suspicious が検出されなかった"
        );
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
        assert_eq!(
            r.url_reputation,
            UrlReputation::Suspicious,
            "QR 内の深い階層インフィックス偽装が検出されなかった"
        );
    }

    // ── 危険スキーム検出 (blob:/data:/javascript:) ──────────────────────────

    #[test]
    fn blob_uri_qr_is_suspicious() {
        let d = QuishingDefense::new();
        let r = d.evaluate_decoded("qr-blob", "blob:https://evil.example/uuid-1234");
        assert!(!r.is_url, "blob: は http(s) URL として扱わない");
        assert_eq!(
            r.url_reputation,
            UrlReputation::Suspicious,
            "blob: URI が Neutral で素通りしている"
        );
    }

    #[test]
    fn data_uri_qr_is_suspicious() {
        let d = QuishingDefense::new();
        let r = d.evaluate_decoded("qr-data", "data:text/html;base64,PHNjcmlwdD4=");
        assert_eq!(
            r.url_reputation,
            UrlReputation::Suspicious,
            "data: URI が Neutral で素通りしている"
        );
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
        assert_eq!(
            d.evaluate_decoded("q1", "BLOB:https://x.example/z")
                .url_reputation,
            UrlReputation::Suspicious
        );
        assert_eq!(
            d.evaluate_decoded("q2", "Data:text/html,hello")
                .url_reputation,
            UrlReputation::Suspicious
        );
        assert_eq!(
            d.evaluate_decoded("q3", "JavaScript:void(0)")
                .url_reputation,
            UrlReputation::Suspicious
        );
    }

    #[test]
    fn dangerous_scheme_leading_whitespace_detected() {
        let d = QuishingDefense::new();
        let r = d.evaluate_decoded("q4", "  data:text/html,x");
        assert_eq!(
            r.url_reputation,
            UrlReputation::Suspicious,
            "先頭空白で危険スキーム検出を回避できてしまう"
        );
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
        let body: String = std::iter::repeat_n(line, 10).collect::<Vec<_>>().join("\n");
        assert!(
            d.detect_ascii_qr(&body),
            "ブロック文字の羅列が ASCII QR として検出されなかった"
        );
    }

    #[test]
    fn url_shortener_is_suspicious() {
        // 動的 QR: 短縮 URL はスキャン後に宛先を差し替え可能なため疑わしい
        let d = QuishingDefense::new();
        assert_eq!(
            d.evaluate_url("https://bit.ly/3xYz"),
            UrlReputation::Suspicious
        );
        assert_eq!(
            d.evaluate_url("https://tinyurl.com/abcd"),
            UrlReputation::Suspicious
        );
    }

    #[test]
    fn qr_redirect_service_is_suspicious() {
        // QR 生成/リダイレクトサービス (動的 QR の中核)
        let d = QuishingDefense::new();
        assert_eq!(
            d.evaluate_url("https://qrco.de/xyz"),
            UrlReputation::Suspicious
        );
        assert_eq!(
            d.evaluate_url("https://flowcode.com/p/abc"),
            UrlReputation::Suspicious
        );
    }

    #[test]
    fn shortener_subdomain_is_suspicious() {
        // カスタム短縮のサブドメイン形式も対象
        let d = QuishingDefense::new();
        assert_eq!(
            d.evaluate_url("https://go.bit.ly/promo"),
            UrlReputation::Suspicious
        );
    }

    #[test]
    fn trusted_domain_not_flagged_as_shortener() {
        // 回帰: 信頼ドメインが短縮判定に巻き込まれないこと
        let d = QuishingDefense::new();
        assert_eq!(
            d.evaluate_url("https://github.com/anthropics"),
            UrlReputation::Trusted
        );
    }

    #[test]
    fn detects_braille_qr() {
        // Barracuda が観測した点字ブロックによるテキスト QR
        let d = QuishingDefense::new();
        let line =
            "\u{2801}\u{28FF}\u{2847}\u{28B6}\u{2809}\u{28FE}\u{2840}\u{28DB}\u{2807}\u{28F0}";
        let body: String = std::iter::repeat_n(line, 10).collect::<Vec<_>>().join("\n");
        assert!(
            d.detect_ascii_qr(&body),
            "点字ブロックのテキスト QR が検出されなかった"
        );
    }

    #[test]
    fn detects_geometric_qr() {
        // 幾何学記号による QR
        let d = QuishingDefense::new();
        let line = "■□■■□■□■□■■□■□■■□■□■";
        let body: String = std::iter::repeat_n(line, 10).collect::<Vec<_>>().join("\n");
        assert!(
            d.detect_ascii_qr(&body),
            "幾何学記号のテキスト QR が検出されなかった"
        );
    }

    #[test]
    fn normal_text_is_not_ascii_qr() {
        let d = QuishingDefense::new();
        let body =
            "こんにちは、\n来週の会議についてですが、\n資料を添付します。\nよろしくお願いします。";
        assert!(
            !d.detect_ascii_qr(body),
            "通常の文章を ASCII QR と誤検出した"
        );
    }

    #[test]
    fn short_block_run_not_flagged() {
        let d = QuishingDefense::new();
        // MIN_QR_LINES (8) 未満の連続では検出しない
        let line = "████████████████";
        let body: String = std::iter::repeat_n(line, 3).collect::<Vec<_>>().join("\n");
        assert!(
            !d.detect_ascii_qr(&body),
            "短すぎるブロック行の連続を誤検出した"
        );
    }

    #[test]
    fn blank_line_resets_consecutive_count() {
        let d = QuishingDefense::new();
        let block_line = "█▀▄▀█▄▀█▀▄▀█▄▀█▀▄▀█▄▀█";
        // 5行 + 空行 + 5行 (空行で連続カウントがリセットされ 8 行連続に届かない)
        let mut lines: Vec<&str> = std::iter::repeat_n(block_line, 5).collect();
        lines.push("");
        lines.extend(std::iter::repeat_n(block_line, 5));
        let body = lines.join("\n");
        assert!(
            !d.detect_ascii_qr(&body),
            "空行を挟んだ分断ブロックを誤検出した"
        );
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
        assert!(
            dist > 3,
            "巨大入力は typosquat 距離 (1-3) に入ってはならない"
        );
    }

    #[test]
    fn oversized_qr_host_does_not_panic_and_is_not_typosquat() {
        let d = QuishingDefense::new();
        // 巨大なホスト名を持つ URL (QR は最大 ~2953 バイト)
        let host = "x".repeat(2900);
        let url = format!("https://{host}.com/");
        // パニックせず、typosquat にも誤判定しないこと
        let rep = d.evaluate_url(&url);
        assert_eq!(
            rep,
            UrlReputation::Neutral,
            "巨大ホストは typosquat ではなく Neutral であるべき: {rep:?}"
        );
    }

    // ── D786: 保護 URL ラッパの剥がし ─────────────────────────────────────

    #[test]
    fn safelinks_wrapper_unwraps_to_inner() {
        let d = QuishingDefense::new();
        // SafeLinks で包まれた悪意ドメイン — 外側は Microsoft 系ドメイン
        let wrapped = "https://nam04.safelinks.protection.outlook.com/?url=https%3A%2F%2Famazon-secure.tk%2Flogin&data=05";
        assert_eq!(
            d.evaluate_url(wrapped),
            UrlReputation::Suspicious,
            "SafeLinks 内側の自由 TLD を評価すべき"
        );
    }

    #[test]
    fn safelinks_wrapper_unwraps_to_trusted() {
        let d = QuishingDefense::new();
        let wrapped = "https://nam04.safelinks.protection.outlook.com/?url=https%3A%2F%2Fgithub.com%2Forg%2Frepo&data=05";
        assert_eq!(d.evaluate_url(wrapped), UrlReputation::Trusted);
    }

    #[test]
    fn urldefense_v2_unwraps_to_inner() {
        let d = QuishingDefense::new();
        // v2 形式: - → %, _ → /  (ドメイン内の . はそのまま残る)
        let wrapped = "https://urldefense.com/v2/url?u=https-3a__evil-2dcorp.tk_login&d=DwMFAg&c=xyz";
        // 復元後 https://evil-corp.tk/login → .tk 自由 TLD で Suspicious
        assert_eq!(d.evaluate_url(wrapped), UrlReputation::Suspicious);
    }

    #[test]
    fn urldefense_v3_single_token_unwraps() {
        let d = QuishingDefense::new();
        // v3 形式: 単一 `*` トークンを enc_bytes (base64 復元) の 1 文字で置換。
        // "dg" → urlsafe b64 of 'v' — `e*il` → `evil`
        let wrapped = "https://urldefense.com/v3/__https://e*il.tk/login__;dg!x";
        assert_eq!(
            d.evaluate_url(wrapped),
            UrlReputation::Suspicious,
            "v3 の単一トークン置換で evil.tk に復元されるべき"
        );
    }

    #[test]
    fn urldefense_v3_run_token_unwraps() {
        let d = QuishingDefense::new();
        // `**B` (run=3) トークンを enc_bytes の 3 文字で置換。
        // "bXBs" → urlsafe b64 of "mpl" — `exa**Ble` → `example`
        let wrapped = "https://urldefense.com/v3/__https://exa**Ble.com/__;bXBs!x";
        assert_eq!(
            d.evaluate_url(wrapped),
            UrlReputation::Neutral,
            "v3 の run トークン置換で example.com に復元されるべき"
        );
    }

    #[test]
    fn urldefense_v3_single_slash_scheme_restored() {
        let d = QuishingDefense::new();
        // v3 は `https:/` を単一スラッシュに潰す — 修復して評価する
        let wrapped = "https://urldefense.com/v3/__https:/evil.tk/x__;!!x";
        assert_eq!(d.evaluate_url(wrapped), UrlReputation::Suspicious);
    }

    #[test]
    fn google_redirect_unwraps_q_param() {
        let d = QuishingDefense::new();
        let wrapped = "https://www.google.co.jp/url?q=https%3A%2F%2Fevil.tk%2F";
        assert_eq!(d.evaluate_url(wrapped), UrlReputation::Suspicious);
    }

    #[test]
    fn google_search_is_not_a_redirect() {
        let d = QuishingDefense::new();
        // /search?q= はリダイレクタでなく検索 — 従来どおり Trusted
        assert_eq!(
            d.evaluate_url("https://www.google.com/search?q=rust"),
            UrlReputation::Trusted
        );
    }

    #[test]
    fn bing_cka_unwraps_u_param() {
        let d = QuishingDefense::new();
        // u=a1<base64url("https://evil.tk/x")>
        let b64 = "aHR0cHM6Ly9ldmlsLnRrL3g";
        let wrapped = format!("https://www.bing.com/ck/a?u=a1{b64}&p=1");
        assert_eq!(d.evaluate_url(&wrapped), UrlReputation::Suspicious);
    }

    #[test]
    fn slack_redir_unwraps_url_param() {
        let d = QuishingDefense::new();
        let wrapped = "https://slack-redir.net/link?url=https%3A%2F%2Fevil.tk%2F";
        assert_eq!(d.evaluate_url(wrapped), UrlReputation::Suspicious);
    }

    #[test]
    fn mimecast_domain_param_unwraps() {
        let d = QuishingDefense::new();
        let wrapped = "https://protect-eu.mimecast.com/s/AbCd/xYz?domain=evil.tk";
        assert_eq!(d.evaluate_url(wrapped), UrlReputation::Suspicious);
    }

    #[test]
    fn unverifiable_rewriter_is_suspicious() {
        let d = QuishingDefense::new();
        // 宛先をサーバ側でしか復元できない書き換えホスト
        for u in [
            "https://linkprotect.cudasvc.com/url?a=https%3a%2f%2fexample.com",
            "https://secure-web.cisco.com/abc/click",
            "https://clicktime.trendmicro.com/abc",
            "https://x.wsed.org/y",
            "https://data.protection.sophos.com/z",
            "https://xxx.mimecastprotect.com/y",
            "https://protect-us.mimecast.com/s/XyZ/noDomainParam",
        ] {
            assert_eq!(
                d.evaluate_url(u),
                UrlReputation::Suspicious,
                "{u} は検証不能の間接参照として Suspicious であるべき"
            );
        }
    }

    #[test]
    fn double_wrapped_url_still_evaluates_inner() {
        let d = QuishingDefense::new();
        // SafeLinks が urldefense を包む二重ラッパ (複数ゲートウェイ通過)
        let inner_defense = "https%3A%2F%2Furldefense.com%2Fv2%2Furl%3Fu%3Dhttps-3a__evil-2dcorp.tk%26d%3D1";
        let wrapped = format!(
            "https://nam04.safelinks.protection.outlook.com/?url={inner_defense}"
        );
        assert_eq!(d.evaluate_url(&wrapped), UrlReputation::Suspicious);
    }

    #[test]
    fn plain_unwrapped_url_unchanged() {
        let d = QuishingDefense::new();
        // ラッパでない URL は従来どおりの評価
        assert_eq!(
            d.evaluate_url("https://example.org/page"),
            UrlReputation::Neutral
        );
    }

    // ── D792: IDN / Punycode ホモグラフ ─────────────────────────────────

    #[test]
    fn punycode_domain_is_suspicious() {
        let d = QuishingDefense::new();
        // xn-- ラベルは表示側で Unicode 化され、ASCII のままでは別ドメインに見える
        assert_eq!(
            d.evaluate_url("https://xn--nxasmq6b.example.com/"),
            UrlReputation::Suspicious
        );
        assert_eq!(
            d.evaluate_url("https://sub.xn--p1ai/"),
            UrlReputation::Suspicious
        );
    }

    #[test]
    fn unicode_homoglyph_domain_is_suspicious() {
        let d = QuishingDefense::new();
        // キリル文字 а (U+0430) を含む — 見た目は example.com でも別ドメイン
        assert_eq!(
            d.evaluate_url("https://еxample.com/"),
            UrlReputation::Suspicious,
            "非 ASCII を直接含むホストはホモグラフ経路として Suspicious であるべき"
        );
    }

    #[test]
    fn ascii_domain_not_flagged_as_idn() {
        let d = QuishingDefense::new();
        assert_eq!(
            d.evaluate_url("https://example.org/x"),
            UrlReputation::Neutral
        );
    }
}
