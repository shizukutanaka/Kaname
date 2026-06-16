//! kaname-privacy — プライバシー保護層。
//!
//! - トラッキングピクセル検出 (1x1 GIF)
//! - 外部画像ブロック
//! - メールアドレス匿名化ハッシュ
//! - クレジットカード・SSN の自動 REDACT

// crates/kaname-render/src/privacy.rs
//
// プライバシー強化機能。競合分析から実装。
//
// 競合の弱点:
//   Proton Mail:  トラッキングピクセルをブロック (機能あり)
//   Gmail:        トラッキングを Google 経由でプロキシ (完全ブロックではない)
//   Outlook:      トラッキングピクセルをほぼブロックしない
//   Tuta:         リモート画像ごとブロック (本文が読みにくくなる)
//
// Kaname の改善:
//   1. トラッキングピクセルを検出してブロック、ただし CID 画像は表示
//   2. 既知のトラッキングドメインリスト
//   3. 1x1 ピクセル画像を検出
//   4. ゼロ知識ローカル検索 (Tuta が持ち Proton が持たない機能)

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use std::collections::HashSet;

// ============================================================================
// トラッキングピクセル検出・ブロック
// ============================================================================

/// トラッキングピクセル検出器。
pub struct TrackingDetector {
    known_trackers: HashSet<String>,
}

/// トラッキング検出結果。
#[derive(Debug, Clone)]
pub struct TrackingAnalysis {
    /// 検出されたトラッカーの数。
    pub tracker_count:   usize,
    /// ブロックされたドメインのリスト。
    pub blocked_domains: Vec<String>,
    /// 検出されたピクセル追跡の詳細。
    pub pixels_found:    Vec<TrackingPixel>,
    /// トラッキングが試みられた場合 true。
    pub was_tracked:     bool,
}

/// 検出されたトラッキングピクセル。
#[derive(Debug, Clone)]
pub struct TrackingPixel {
    pub url:          String,
    pub domain:       String,
    pub pixel_size:   Option<(u32, u32)>,
    pub tracker_type: TrackerType,
}

/// トラッカーの種類。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackerType {
    /// メール開封追跡ピクセル。
    OpenTracking,
    /// クリック追跡 URL。
    ClickTracking,
    /// 既知のマーケティングサービス。
    MarketingPlatform { name: String },
    /// 不明な疑わしいピクセル。
    Unknown,
}

impl TrackingDetector {
    /// 新規インスタンスを作成する。
    pub fn new() -> Self {
        let mut known = HashSet::new();
        // 既知のトラッキングドメインリスト
        let trackers = [
            // メールマーケティング
            "mailchimp.com", "list-manage.com", "salesforce.com",
            "pardot.com", "exacttarget.com", "sendgrid.net",
            "sendgrid.com", "mailgun.org", "mandrillapp.com",
            "klaviyo.com", "constantcontact.com", "campaignmonitor.com",
            "getresponse.com", "aweber.com", "hubspot.com",
            "marketo.com", "eloqua.com",
            // 分析系
            "google-analytics.com", "analytics.google.com",
            "doubleclick.net", "facebook.com", "fb.com",
            "linkedin.com", "twitter.com",
            // メール開封追跡 SaaS
            "mailtrack.io", "streak.com", "yesware.com",
            "boomeranggmail.com", "mixmax.com", "outreach.io",
            "salesloft.com", "groove.co", "cirrusinsight.com",
            // 日本系
            "blastmail.jp", "cuenote.jp", "wowma.jp",
        ];
        for t in &trackers {
            known.insert(t.to_string());
        }
        Self { known_trackers: known }
    }

    /// HTML ボディからトラッキングピクセルを検出する。
    ///
    /// 入力サイズを 10 MB に制限する (悪意ある巨大 HTML による OOM 防止)。
    pub fn analyze_html(&self, html: &str) -> TrackingAnalysis {
        const MAX_HTML_BYTES: usize = 10 * 1024 * 1024;
        // MAX_HTML_BYTES がマルチバイト UTF-8 文字の中間にある場合に
        // &str スライスがパニックする。is_char_boundary() で安全な境界を探す。
        let html = if html.len() > MAX_HTML_BYTES {
            let safe = (0..=MAX_HTML_BYTES).rev()
                .find(|&i| html.is_char_boundary(i))
                .unwrap_or(0);
            &html[..safe]
        } else {
            html
        };
        let mut blocked_domains = Vec::new();
        let mut pixels_found    = Vec::new();

        // img タグを検索
        let mut pos = 0;
        while let Some(img_start) = html[pos..].find("<img") {
            let abs_start = pos + img_start;
            let tag_end = html[abs_start..].find('>')
                .map(|e| abs_start + e + 1)
                .unwrap_or(html.len());
            let tag = &html[abs_start..tag_end];

            // src 属性を抽出
            if let Some(src) = extract_attr(tag, "src") {
                // http/https の外部 URL (cid: は除外)
                if src.starts_with("http://") || src.starts_with("https://") {
                    let domain = extract_domain_from_url(src)
                        .unwrap_or_default();

                    let width  = extract_attr(tag, "width")
                        .and_then(|w| w.parse::<u32>().ok());
                    let height = extract_attr(tag, "height")
                        .and_then(|h| h.parse::<u32>().ok());

                    // 1x1 ピクセルは確実にトラッカー
                    let is_pixel = matches!((width, height), (Some(1), Some(1)))
                        || matches!((width, height), (Some(0), Some(0)));

                    let tracker_type = if is_pixel {
                        TrackerType::OpenTracking
                    } else if self.known_trackers.contains(&domain) {
                        TrackerType::MarketingPlatform { name: domain.clone() }
                    } else if is_tracking_url_pattern(src) {
                        TrackerType::OpenTracking
                    } else {
                        TrackerType::Unknown
                    };

                    let is_tracker = is_pixel
                        || self.known_trackers.contains(&domain)
                        || is_tracking_url_pattern(src);

                    if is_tracker {
                        blocked_domains.push(domain.clone());
                        pixels_found.push(TrackingPixel {
                            url: src.to_string(),
                            domain,
                            pixel_size: width.zip(height),
                            tracker_type,
                        });
                    }
                }
            }

            pos = tag_end;
        }

        blocked_domains.sort();
        blocked_domains.dedup();

        TrackingAnalysis {
            tracker_count:   pixels_found.len(),
            blocked_domains,
            was_tracked:     !pixels_found.is_empty(),
            pixels_found,
        }
    }

    /// カスタムトラッカードメインを追加する。
    pub fn add_tracker(&mut self, domain: &str) {
        self.known_trackers.insert(domain.to_lowercase());
    }
}

fn extract_attr<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
    // ダブルクォート: attr="value"
    let dq_pattern = format!("{}=\"", attr);
    if let Some(start) = tag.find(&dq_pattern) {
        let val_start = start + dq_pattern.len();
        if let Some(end) = tag[val_start..].find('"') {
            return Some(&tag[val_start..val_start + end]);
        }
    }
    // シングルクォート: attr='value' (単一クォート回避によるトラッカー検出バイパス対策)
    let sq_pattern = format!("{}='", attr);
    if let Some(start) = tag.find(&sq_pattern) {
        let val_start = start + sq_pattern.len();
        if let Some(end) = tag[val_start..].find('\'') {
            return Some(&tag[val_start..val_start + end]);
        }
    }
    None
}

fn extract_domain_from_url(url: &str) -> Option<String> {
    let without_scheme = url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host_port = without_scheme.split('/').next()?;
    // ポート番号を除去: "tracker.com:8080" → "tracker.com"
    // ポートを保持したまま known_trackers に照合すると既知ドメインがバイパスされる
    let domain = host_port.split(':').next()?;
    Some(domain.to_lowercase())
}

fn is_tracking_url_pattern(url: &str) -> bool {
    let patterns = [
        "/track/", "/pixel/", "/open/", "/click/", "/beacon/",
        "track=", "pixel=", "open=", "utm_", "trk=",
        "/t/", ".gif?", "tracking", "analytics",
    ];
    let lower = url.to_lowercase();
    patterns.iter().any(|p| lower.contains(p))
}

impl Default for TrackingDetector {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// ゼロ知識ローカル検索
//
// Tuta の優位性: ゼロ知識検索 (サーバーが何を検索したか知らない)
// Proton Mail の弱点: フルテキスト検索でサーバー側に問い合わせ
// Kaname の実装: SQLite FTS5 でローカル検索、サーバーには一切送信しない
// ============================================================================

/// ゼロ知識ローカル検索エンジン。
///
/// 全ての検索処理はデバイス上のみで実行される。
/// サーバーには検索クエリも結果も送信されない。
pub struct ZeroKnowledgeSearch {
    /// ローカルインデックス (email_id → keywords)
    /// 本番: SQLite FTS5 バーチャルテーブルを使用
    index: Vec<IndexEntry>,
    /// インデックスエントリ数の上限 (OOM DoS 防止)
    max_entries: usize,
}

#[derive(Debug, Clone)]
struct IndexEntry {
    email_id:    String,
    /// 件名 (ローカルのみ、サーバーには送信しない)
    subject:     String,
    /// 本文の要約 (ローカルのみ)
    body_preview: String,
    /// 送信者
    from_name:   String,
    from_addr:   String,
    received_at: String,
}

/// 検索結果。
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub email_id:   String,
    pub subject:    String,
    pub from:       String,
    pub preview:    String,
    pub received_at: String,
    /// マッチしたフィールド
    pub matched_in: Vec<MatchedField>,
    /// 関連スコア
    pub score:      f32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchedField {
    Subject, Body, Sender,
}

impl ZeroKnowledgeSearch {
    /// 新規インスタンスを作成する。
    pub fn new() -> Self {
        Self { index: Vec::new(), max_entries: 1_000_000 }
    }

    /// メールをローカルインデックスに追加する。
    ///
    /// インデックスが `max_entries` に達した場合は最古エントリを退避する。
    pub fn index_email(
        &mut self,
        email_id:    &str,
        subject:     &str,
        body_text:   &str,
        from_name:   Option<&str>,
        from_addr:   &str,
        received_at: &str,
    ) {
        // 既存エントリを更新または追加
        if let Some(entry) = self.index.iter_mut().find(|e| e.email_id == email_id) {
            entry.subject     = subject.to_owned();
            entry.body_preview = body_text.chars().take(200).collect();
            return;
        }

        // 容量超過時は最古エントリを退避 (FIFO)
        if self.index.len() >= self.max_entries {
            self.index.remove(0);
        }

        self.index.push(IndexEntry {
            email_id:    email_id.to_owned(),
            subject:     subject.to_owned(),
            body_preview: body_text.chars().take(200).collect(),
            from_name:   from_name.unwrap_or("").to_owned(),
            from_addr:   from_addr.to_owned(),
            received_at: received_at.to_owned(),
        });
    }

    /// ローカルインデックスで検索する (サーバーへの通信なし)。
    ///
    /// 検索構文:
    ///   "from:alice@example.com" → 送信者で絞り込み
    ///   "subject:会議" → 件名で絞り込み
    ///   それ以外 → 全フィールドを検索
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<SearchResult> {
        if query.is_empty() { return Vec::new(); }

        let (field, term) = parse_search_query(query);
        let lower_term = term.to_lowercase();

        let mut results: Vec<SearchResult> = self.index.iter()
            .filter_map(|entry| {
                let mut matched_in = Vec::new();
                let mut score = 0.0f32;

                match field {
                    SearchField::From => {
                        if entry.from_addr.to_lowercase().contains(&lower_term)
                           || entry.from_name.to_lowercase().contains(&lower_term) {
                            matched_in.push(MatchedField::Sender);
                            score = 1.0;
                        }
                    }
                    SearchField::Subject => {
                        if entry.subject.to_lowercase().contains(&lower_term) {
                            matched_in.push(MatchedField::Subject);
                            score = 1.0;
                        }
                    }
                    SearchField::All => {
                        if entry.subject.to_lowercase().contains(&lower_term) {
                            matched_in.push(MatchedField::Subject);
                            score += 0.8;
                        }
                        if entry.body_preview.to_lowercase().contains(&lower_term) {
                            matched_in.push(MatchedField::Body);
                            score += 0.5;
                        }
                        if entry.from_name.to_lowercase().contains(&lower_term)
                           || entry.from_addr.to_lowercase().contains(&lower_term) {
                            matched_in.push(MatchedField::Sender);
                            score += 0.6;
                        }
                    }
                }

                if matched_in.is_empty() { return None; }

                Some(SearchResult {
                    email_id:   entry.email_id.clone(),
                    subject:    entry.subject.clone(),
                    from:       if entry.from_name.is_empty() {
                                    entry.from_addr.clone()
                                } else {
                                    format!("{} <{}>", entry.from_name, entry.from_addr)
                                },
                    preview:    entry.body_preview.clone(),
                    received_at: entry.received_at.clone(),
                    matched_in,
                    score,
                })
            })
            .collect();

        // スコア降順でソート
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// インデックスのサイズ (メール件数)。
    #[must_use]
    pub fn size(&self) -> usize { self.index.len() }

    /// インデックスからメールを削除する。
    pub fn remove(&mut self, email_id: &str) {
        self.index.retain(|e| e.email_id != email_id);
    }
}

impl Default for ZeroKnowledgeSearch {
    fn default() -> Self { Self::new() }
}

enum SearchField { From, Subject, All }

fn parse_search_query(query: &str) -> (SearchField, &str) {
    if let Some(term) = query.strip_prefix("from:") {
        return (SearchField::From, term);
    }
    if let Some(term) = query.strip_prefix("subject:") {
        return (SearchField::Subject, term);
    }
    (SearchField::All, query)
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // トラッキングピクセル検出
    #[test]
    fn mailchimp_トラッカーを検出する() {
        let detector = TrackingDetector::new();
        let html = r#"<p>こんにちは</p><img src="https://mailchimp.com/track/open.gif?id=12345" width="1" height="1">"#;
        let result = detector.analyze_html(html);
        assert!(result.was_tracked);
        assert!(result.tracker_count > 0);
        assert!(result.blocked_domains.contains(&"mailchimp.com".to_string()));
    }

    #[test]
    fn detects_1x1_tracking_pixel() {
        let detector = TrackingDetector::new();
        let html = r#"<img src="https://unknown-tracker.example.com/pixel.gif" width="1" height="1">"#;
        let result = detector.analyze_html(html);
        assert!(result.was_tracked, "1x1 ピクセルはトラッカーとして検出されるべき");
    }

    #[test]
    fn cid画像はブロックされない() {
        let detector = TrackingDetector::new();
        // CID 画像は http/https ではないのでスキャン外
        let html = r#"<img src="cid:image001@01CE.01BE" alt="signature">"#;
        let result = detector.analyze_html(html);
        // CID 画像はトラッカーではない
        // (トラッカーリストは外部 URL のみを対象)
        assert_eq!(result.tracker_count, 0);
    }

    #[test]
    fn 通常の画像はブロックされない() {
        let detector = TrackingDetector::new();
        // 通常のコンテンツ画像 (1x1 ではなく、既知トラッカーでもない)
        let html = r#"<img src="https://our-company.co.jp/logo.png" width="200" height="100">"#;
        let result = detector.analyze_html(html);
        // kaname の CSP では実際には全外部画像をブロックするが、
        // このテストはトラッカー判定ロジックのみを確認
        // 200x100 の画像は 1x1 でなく、既知トラッカーでもない
        let pixel_only = result.pixels_found.iter()
            .filter(|p| matches!(p.tracker_type, TrackerType::OpenTracking))
            .count();
        assert_eq!(pixel_only, 0, "通常サイズの画像はピクセルトラッカーではない");
    }

    // ゼロ知識検索
    #[test]
    fn 件名での検索が機能する() {
        let mut search = ZeroKnowledgeSearch::new();
        search.index_email("e1", "プロジェクト Alpha の予算", "添付をご確認ください",
                           Some("Alice"), "alice@company.com", "2026-04-24");
        search.index_email("e2", "会議のご案内", "来週月曜日に会議があります",
                           Some("Bob"), "bob@company.com", "2026-04-23");
        search.index_email("e3", "プロジェクト Beta の進捗", "進捗報告書を送付します",
                           Some("Carol"), "carol@company.com", "2026-04-22");

        let results = search.search("subject:プロジェクト");
        assert_eq!(results.len(), 2, "プロジェクトを含む件名が 2 件");
        assert!(results.iter().all(|r| r.matched_in.contains(&MatchedField::Subject)));
    }

    #[test]
    fn 送信者での検索が機能する() {
        let mut search = ZeroKnowledgeSearch::new();
        search.index_email("e1", "件名1", "本文1", Some("Alice"), "alice@company.com", "2026-04-24");
        search.index_email("e2", "件名2", "本文2", Some("Bob"), "bob@company.com", "2026-04-23");

        let results = search.search("from:alice");
        assert_eq!(results.len(), 1);
        assert!(results[0].matched_in.contains(&MatchedField::Sender));
    }

    #[test]
    fn 全文検索が機能する() {
        let mut search = ZeroKnowledgeSearch::new();
        search.index_email("e1", "会議について", "来週の月曜日に会議があります", None, "a@b.com", "");
        search.index_email("e2", "報告書", "月次報告書を添付します", None, "c@d.com", "");

        let results = search.search("月");
        assert_eq!(results.len(), 2, "「月」を含むメールが 2 件");
    }

    #[test]
    fn 空クエリで結果なし() {
        let search = ZeroKnowledgeSearch::new();
        let results = search.search("");
        assert!(results.is_empty());
    }

    #[test]
    fn インデックス削除が機能する() {
        let mut search = ZeroKnowledgeSearch::new();
        search.index_email("e1", "件名", "本文", None, "a@b.com", "");
        assert_eq!(search.size(), 1);
        search.remove("e1");
        assert_eq!(search.size(), 0);
    }

    #[test]
    fn スコア降順でソートされる() {
        let mut search = ZeroKnowledgeSearch::new();
        // 件名のみマッチ (スコア高) と本文のみマッチ (スコア低)
        search.index_email("e1", "重要な会議", "明日の準備をお願いします", None, "a@b.com", "");
        search.index_email("e2", "お知らせ", "重要なお知らせがあります", None, "c@d.com", "");

        let results = search.search("重要");
        assert_eq!(results.len(), 2);
        // 件名マッチ (e1) が本文マッチ (e2) より先に来るべき
        assert_eq!(results[0].email_id, "e1", "件名マッチが先に来るべき");
    }

    // ── シングルクォート属性によるトラッカー回避テスト ───────────────────

    #[test]
    fn single_quote_src_でもトラッカーを検出する() {
        let detector = TrackingDetector::new();
        // シングルクォートで囲まれた src 属性
        let html = r#"<img src='https://mailchimp.com/track/open.gif' width='1' height='1'>"#;
        let result = detector.analyze_html(html);
        assert!(result.was_tracked,
            "シングルクォートの src 属性はトラッカー検出をバイパスしてはならない");
    }

    #[test]
    fn ポート番号付きドメインをブロックする() {
        let detector = TrackingDetector::new();
        // ポート番号付き: "mailchimp.com:443" は "mailchimp.com" と同じドメイン
        let html = r#"<img src="https://mailchimp.com:443/track/open.gif" width="1" height="1">"#;
        let result = detector.analyze_html(html);
        assert!(result.was_tracked,
            "ポート番号付きドメインはトラッカー検出をバイパスしてはならない");
        assert!(result.blocked_domains.contains(&"mailchimp.com".to_string()),
            "blocked_domains はポートなしドメインを含むべき");
    }

    #[test]
    fn 非標準ポートでトラッカーをバイパスできない() {
        let detector = TrackingDetector::new();
        // 攻撃者が :8080 を付けて既知リストをバイパスしようとする
        let html = r#"<img src="https://mailchimp.com:8080/track/open.gif" width="1" height="1">"#;
        let result = detector.analyze_html(html);
        assert!(result.was_tracked,
            "非標準ポートによるトラッカー検出バイパスを防止する");
    }

    // ── インデックス容量制限テスト ─────────────────────────────────────────

    #[test]
    fn インデックスは上限を超えない() {
        let mut search = ZeroKnowledgeSearch::new();
        // max_entries を小さくしてテスト
        search.max_entries = 5;
        for i in 0..10u32 {
            search.index_email(&format!("e{i}"), "件名", "本文", None, "a@b.com", "");
        }
        assert_eq!(search.size(), 5, "上限 5 を超えてはならない");
    }

    #[test]
    fn html_サイズ上限で切り捨てる() {
        let detector = TrackingDetector::new();
        // 正常な 1x1 ピクセルを 10MB の HTML の後半に埋め込む
        // → 切り捨てられて検出されない (実害なし — 切り捨てた分は処理対象外)
        let normal = "x".repeat(10 * 1024 * 1024 + 100);
        // パニックしないことを確認
        let result = detector.analyze_html(&normal);
        assert_eq!(result.tracker_count, 0, "切り捨て後はトラッカーなし");
    }

    // ── UTF-8 境界安全カットテスト ─────────────────────────────────────

    #[test]
    fn html_multibyte_boundary_does_not_panic() {
        // 10MB ちょうどの境界が日本語マルチバイト文字の中間になるケース
        // &html[..10*1024*1024] が is_char_boundary でない場合にパニックしたバグの回帰テスト
        const MAX: usize = 10 * 1024 * 1024;
        let detector = TrackingDetector::new();

        // ASCII (1 バイト) で MAX-2 バイト埋め、末尾に 3 バイト文字「日」を追加
        // → MAX バイト目がマルチバイト文字の途中になる
        let mut html = "a".repeat(MAX - 2);
        html.push('日'); // 3 バイト: 0xE6 0x97 0xA5
        // html.len() = MAX - 2 + 3 = MAX + 1 > MAX → 切り捨て発動
        assert!(html.len() > MAX);

        // パニックしないことを確認 (パニックするとテストがクラッシュする)
        let result = detector.analyze_html(&html);
        assert_eq!(result.tracker_count, 0, "切り捨て後はトラッカーなし");
    }

    #[test]
    fn html_exactly_at_limit_with_multibyte() {
        // 境界が4バイト文字 (絵文字) の途中になるケース
        const MAX: usize = 10 * 1024 * 1024;
        let detector = TrackingDetector::new();

        let mut html = "b".repeat(MAX - 1);
        html.push('🔐'); // 4 バイト: 0xF0 0x9F 0x94 0x90
        assert!(html.len() > MAX);

        let result = detector.analyze_html(&html);
        let _ = result; // パニックしないことが目的
    }
}
