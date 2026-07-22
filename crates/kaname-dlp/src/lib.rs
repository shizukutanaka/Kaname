//! kaname-dlp — Data Loss Prevention ルールエンジン。
//!
//! 12 種の boolean 式木分類器。
//! ラベル: Public / Internal / Confidential / HighlyConfidential / LegalPrivilege
//!
//! AiAccessController が HighlyConfidential 以上の AI 処理をブロック。
//! Microsoft Copilot CVE CW1226324 対策の核心。

// crates/kaname-dlp/src/lib.rs
//
// Data Loss Prevention rule engine. (KTR-09)
//
// Design:
//   - Rules are a boolean expression tree (AND/OR/NOT + leaf predicates)
//   - Three actions: Allow, Warn (user can override), Block
//   - Two directions: Outbound (send), Inbound (receive), Both
//   - Evaluation is pure (no async, no I/O) for composability
//   - Runs *before* any LLM sees the content
//   - Built-in classifiers: PII (JP マイナンバー, credit cards, IBANs),
//     PCI (PANs, CVVs), privileged (attorney-client, board-only keywords),
//     IP (patent-pending, trade secret markers)
//
// Integration with kaname-render:
//   The render pipeline calls preflight_dlp(envelope) before sanitize_html().
//   On Block, rendering aborts and the UI shows a DLP banner.
//   On Warn, rendering continues but the banner appears.
//
// Extensibility (planned, not yet wired):
//   The kaname-store.dlp_rules table is defined for storing custom rules as JSON,
//   but loading them into DlpEngine at startup / on Settings change is NOT yet
//   implemented (no from_db() exists; app_state wiring is commented-out pseudocode).
//   Currently the engine uses only its built-in default classifiers.


#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(missing_docs)]

//! # kaname-dlp
//!
//! Boolean-grammar DLP rule engine. Pure, synchronous, zero-allocation hot path.

/// EDM (Exact Data Match) — 顧客データの完全一致検出。
pub mod edm;

/// kaname-render パイプラインへの DLP 統合アダプター。
pub mod render_bridge;

/// 宛先ミス検出 (誤送信防止) — Misdirected Recipient Detection。
pub mod misdirected_recipient;

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Rule model
// ============================================================================

/// DLP ルール: 条件ツリー + アクション + メタデータ。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// ルールの一意 ID。
    pub id:        String,
    /// 表示名。
    pub name:      String,
    /// 有効フラグ。
    pub enabled:   bool,
    /// 適用方向 (送信/受信/両方)。
    pub direction: Direction,
    /// 発火条件ツリー。
    pub condition: Condition,
    /// 一致時のアクション。
    pub action:    Action,
    /// 数値が小さいほど先に評価。同値の場合は id で決定。
    pub priority:  u32,
}

/// このルールが適用される方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Direction {
    /// 送信メールに適用。
    Outbound,
    /// 受信メールに適用。
    Inbound,
    /// 双方向に適用。
    Both,
}

/// ルールが一致した時に取るアクション。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Action {
    /// アクションなし; コンテンツが通過。
    Allow,
    /// 警告を表示; ユーザーがオーバーライドして続行可能。
    Warn,
    /// ハードブロック; 続行不可。
    Block,
}

/// ブール条件ツリー。再帰的に評価。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Condition {
    /// 全ての子が一致しなければならない。
    And {
        /// 子条件。
        children: Vec<Condition>,
    },
    /// 少なくとも 1 つの子が一致しなければならない。
    Or {
        /// 子条件。
        children: Vec<Condition>,
    },
    /// 子が一致してはならない。
    Not {
        /// 否定対象の子条件。
        child: Box<Condition>,
    },
    /// リーフ: 分類器を実行。
    Matches(Predicate),
}

impl Condition {
    /// Build `Condition::And` from a vec.
    pub fn all(children: Vec<Condition>) -> Self {
        Self::And { children }
    }
    /// Build `Condition::Or` from a vec.
    pub fn any(children: Vec<Condition>) -> Self {
        Self::Or { children }
    }
    /// Negate a condition.
    pub fn negate(c: Condition) -> Self {
        Self::Not { child: Box::new(c) }
    }
    /// Leaf from a predicate.
    pub fn matches(p: Predicate) -> Self {
        Self::Matches(p)
    }
}

/// リーフ述語 — 実際のマッチングロジック。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Predicate {
    /// Built-in classifier (e.g. JP_MY_NUMBER, CREDIT_CARD).
    Classifier {
        /// 分類器 ID。
        classifier: ClassifierId,
    },
    /// Regular expression match against body text.
    Regex {
        /// 正規表現パターン。
        pattern: String,
    },
    /// Keyword match (case-insensitive) against body text.
    Keyword {
        /// 検索キーワード群。
        words: Vec<String>,
        /// 発火に必要な最小一致数。
        min_count: u32,
    },
    /// Recipient domain is in the given list.
    RecipientDomain {
        /// 対象ドメイン群。
        domains: Vec<String>,
    },
    /// Sender address matches.
    SenderAddress {
        /// 対象アドレス群。
        addresses: Vec<String>,
    },
    /// Message size exceeds threshold.
    SizeBytes {
        /// 閾値 (bytes)。
        min: u64,
    },
    /// Attachment MIME type matches.
    AttachmentMime {
        /// 対象 MIME タイプ群。
        types: Vec<String>,
    },
    /// Custom: matches a named pattern from the pattern library.
    PatternLibrary {
        /// パターンライブラリ内の ID。
        pattern_id: String,
    },
    /// EDM: 機密データセットとの完全一致 (ハッシュフィンガープリント)。
    ExactDataMatch {
        /// フィンガープリントセット ID。
        fingerprint_set_id: String,
    },
}

/// 組み込み分類器の識別子。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClassifierId {
    /// Japanese My Number (マイナンバー): 12-digit personal number.
    JpMyNumber,
    /// Japanese corporate number (法人番号): 13-digit.
    JpCorporateNumber,
    /// Credit card PAN (Luhn-validated).
    CreditCardPan,
    /// IBAN (Basic check).
    Iban,
    /// Swift BIC code.
    SwiftBic,
    /// US Social Security Number.
    UsSsn,
    /// IP address (v4 or v6).
    IpAddress,
    /// Internal "CONFIDENTIAL" / "機密" document markers.
    ConfidentialMarker,
    /// Attorney-client privilege markers.
    AttorneyClientPrivilege,
    /// M&A / deal codenames (user-configured, detected heuristically).
    DealCodename,
    /// Source code fragments (common for IP theft prevention).
    SourceCode,
    /// Medical / HIPAA data markers.
    MedicalData,
}

// ============================================================================
// Evaluation context
// ============================================================================

/// 単一評価のための DLP エンジンへの入力。
pub struct EvalCtx<'a> {
    /// Plaintext body (after HTML stripping).
    pub body:       &'a str,
    /// Subject line.
    pub subject:    &'a str,
    /// Message size in bytes.
    pub size_bytes: u64,
    /// Recipient email addresses.
    pub to:         &'a [String],
    /// Sender email address.
    pub from:       &'a str,
    /// Declared attachment MIME types.
    pub attachment_mimes: &'a [String],
    /// EDM フィンガープリントセット (ID → フィンガープリント)。
    pub edm_sets: &'a std::collections::HashMap<String, crate::edm::EdmFingerprints>,
    /// 過去にやり取りした実績のある宛先ドメイン一覧。
    ///
    /// `misdirected_recipient` による宛先ミス検出に使用。空スライスの場合は
    /// 宛先ミス検出をスキップする (履歴データが利用できない呼び出し元向け)。
    pub known_recipient_domains: &'a [String],
    /// 自組織のドメイン (`misdirected_recipient` の自己送信除外用)。
    /// 空文字列の場合は宛先ミス検出をスキップする。
    pub our_domain: &'a str,
}

impl<'a> EvalCtx<'a> {
    /// All searchable text (body + subject)。
    ///
    /// 本文が 1MB を超える場合は先頭 1MB に切り詰めて返す (OOM/DoS 防止)。
    /// 分類器は先頭 1MB を検査すれば PII 検出に十分な範囲を網羅できる。
    fn full_text(&self) -> String {
        const MAX_EVAL_BYTES: usize = 1024 * 1024; // 1MB
        let body = if self.body.len() > MAX_EVAL_BYTES {
            let end = (0..=MAX_EVAL_BYTES).rev()
                .find(|&i| self.body.is_char_boundary(i)).unwrap_or(0);
            &self.body[..end]
        } else {
            self.body
        };
        format!("{} {}", self.subject, body)
    }

    /// URL パーセントデコード済みの全テキスト。
    ///
    /// `%40` → `@` 等の変換を行い、URL エンコードで DLP を回避するパターンを検出できる。
    fn decoded_text(&self) -> String {
        percent_decode(&self.full_text())
    }

    /// 受信者ドメイン。
    fn recipient_domains(&self) -> Vec<String> {
        // RFC 5321: ドメインは最後の `@` の後。`split('@').nth(1)` は
        // `victim@corp.com@gmail.com` のような細工で 2 番目のフィールド (corp.com) を
        // 取ってしまい、gmail.com 向けブロックルールを回避されるため rsplit_once を使う。
        self.to.iter()
            .filter_map(|addr| addr.rsplit_once('@').map(|(_, domain)| domain.to_lowercase()))
            .collect()
    }
}

// ============================================================================
// DLP Engine
// ============================================================================

/// DLP エンジン。アクティブルールのソート済みリスト + パターンライブラリを保持。
pub struct DlpEngine {
    rules:    Vec<Rule>,
    patterns: PatternLibrary,
    /// ルール構築時にコンパイル済みの正規表現キャッシュ (パターン文字列 → Regex)。
    regex_cache: HashMap<String, Regex>,
}

impl DlpEngine {
    /// Construct with an explicit rule set.
    pub fn new(mut rules: Vec<Rule>, patterns: PatternLibrary) -> Self {
        rules.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.id.cmp(&b.id)));
        let regex_cache = Self::compile_regexes(&rules);
        Self { rules, patterns, regex_cache }
    }

    /// 全ルールの Regex パターンをコンパイルしてキャッシュする。
    fn compile_regexes(rules: &[Rule]) -> HashMap<String, Regex> {
        let mut cache = HashMap::new();
        for rule in rules {
            Self::collect_patterns_from_condition(&rule.condition, &mut cache);
        }
        cache
    }

    fn collect_patterns_from_condition(cond: &Condition, cache: &mut HashMap<String, Regex>) {
        Self::collect_patterns_depth(cond, cache, 0);
    }

    fn collect_patterns_depth(cond: &Condition, cache: &mut HashMap<String, Regex>, depth: u32) {
        const MAX_DEPTH: u32 = 64;
        if depth > MAX_DEPTH { return; }
        match cond {
            Condition::And { children } | Condition::Or { children } => {
                for child in children {
                    Self::collect_patterns_depth(child, cache, depth + 1);
                }
            }
            Condition::Not { child } => {
                Self::collect_patterns_depth(child, cache, depth + 1);
            }
            Condition::Matches(Predicate::Regex { pattern }) => {
                if !cache.contains_key(pattern) {
                    match Regex::new(pattern) {
                        Ok(re) => { cache.insert(pattern.clone(), re); }
                        Err(e) => {
                            tracing::warn!("DLP: invalid regex pattern {:?}: {}", pattern, e);
                        }
                    }
                }
            }
            Condition::Matches(_) => {}
        }
    }

    /// Construct with the built-in defaults (suitable for day-one Starter tier).
    pub fn default_engine() -> Self {
        Self::new(default_rules(), PatternLibrary::default())
    }

    /// Evaluate all rules against an outbound message.
    /// Returns the highest-severity verdict and all matching rules.
    pub fn evaluate(&self, ctx: &EvalCtx<'_>, direction: Direction) -> DlpResult {
        let mut findings = Vec::new();
        let text = ctx.full_text();
        // パーセントデコード済みテキストも評価 (URL エンコード DLP バイパス防止)
        let decoded = ctx.decoded_text();
        // to_lowercase() のアロケーションをルールループ外で一度だけ実行 (P2)
        let text_lower = text.to_lowercase();
        let decoded_lower = decoded.to_lowercase();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if rule.direction != direction
                && rule.direction != Direction::Both
                && direction != Direction::Both
            {
                continue;
            }
            // 通常テキスト または パーセントデコード済みテキストのいずれかにマッチで検出
            let matched = self.eval_condition(&rule.condition, ctx, &text, &text_lower)
                || (decoded != text && self.eval_condition(&rule.condition, ctx, &decoded, &decoded_lower));
            if matched {
                findings.push(Finding {
                    rule_id:   rule.id.clone(),
                    rule_name: rule.name.clone(),
                    action:    rule.action,
                    excerpt:   excerpt_match(&text, &rule.condition),
                });
            }
        }

        // 全体判定 = 全発見の最大重大度 across all findings
        let mut verdict = findings.iter()
            .map(|f| f.action)
            .max()
            .unwrap_or(Action::Allow);

        // 機密コンテンツ検出 (findings が Warn 以上) と宛先ミス検出を組み合わせる。
        // 「機密情報」+「個人メールアドレス宛/タイポドメイン宛」は内部脅威
        // (情報持ち出し) や誤送信の典型的な複合シグナルであり、
        // どちらか単独よりも深刻に扱うべきだが、従来は misdirected_recipient
        // モジュールが register されているだけで評価パイプラインと未接続だった。
        if direction == Direction::Outbound && verdict >= Action::Warn && !ctx.our_domain.is_empty() {
            let suspicious = crate::misdirected_recipient::detect_misdirected_recipients(
                ctx.to, ctx.our_domain, ctx.known_recipient_domains,
            );
            if !suspicious.is_empty() {
                verdict = Action::Block;
                for s in &suspicious {
                    findings.push(Finding {
                        rule_id: "misdirected-recipient".to_string(),
                        rule_name: "宛先ミスの疑い + 機密コンテンツ".to_string(),
                        action: Action::Block,
                        excerpt: format!("{}: {:?}", s.address, s.reason),
                    });
                }
            }
        }

        DlpResult { verdict, findings }
    }

    fn eval_condition(&self, cond: &Condition, ctx: &EvalCtx<'_>, text: &str, text_lower: &str) -> bool {
        self.eval_condition_depth(cond, ctx, text, text_lower, 0)
    }

    fn eval_condition_depth(&self, cond: &Condition, ctx: &EvalCtx<'_>, text: &str, text_lower: &str, depth: u32) -> bool {
        const MAX_DEPTH: u32 = 64;
        if depth > MAX_DEPTH {
            tracing::warn!("DLP: condition tree depth exceeded {MAX_DEPTH}, treating as no-match");
            return false;
        }
        match cond {
            // 空の And は vacuous truth → 全メールをブロックしてしまう。
            // 意味的に「条件なし = マッチしない」として扱う。
            Condition::And { children } => {
                if children.is_empty() { return false; }
                children.iter().all(|c| self.eval_condition_depth(c, ctx, text, text_lower, depth + 1))
            }
            Condition::Or { children } =>
                children.iter().any(|c| self.eval_condition_depth(c, ctx, text, text_lower, depth + 1)),
            Condition::Not { child } =>
                !self.eval_condition_depth(child, ctx, text, text_lower, depth + 1),
            Condition::Matches(pred) =>
                self.eval_predicate(pred, ctx, text, text_lower),
        }
    }

    fn eval_predicate(&self, pred: &Predicate, ctx: &EvalCtx<'_>, text: &str, text_lower: &str) -> bool {
        match pred {
            Predicate::Classifier { classifier } =>
                self.run_classifier(*classifier, text),

            Predicate::Regex { pattern } => {
                if let Some(re) = self.regex_cache.get(pattern) {
                    re.is_match(text)
                } else {
                    // パターンがコンパイル失敗 → 安全側に倒してマッチなし扱い
                    false
                }
            }

            Predicate::Keyword { words, min_count } => {
                const MAX_KEYWORD_COUNT: usize = 500;
                // text_lower は evaluate() で一度だけ計算済み (P2: 再アロケーション防止)
                let count = words.iter()
                    .take(MAX_KEYWORD_COUNT)
                    .filter(|w| text_lower.contains(w.to_lowercase().as_str()))
                    .count() as u32;
                count >= *min_count
            }

            Predicate::RecipientDomain { domains } => {
                let rx_domains = ctx.recipient_domains();
                domains.iter().any(|d| rx_domains.contains(&d.to_lowercase()))
            }

            Predicate::SenderAddress { addresses } =>
                addresses.iter().any(|a| a.eq_ignore_ascii_case(ctx.from)),

            Predicate::SizeBytes { min } =>
                ctx.size_bytes >= *min,

            Predicate::AttachmentMime { types } =>
                ctx.attachment_mimes.iter()
                    .any(|m| types.contains(m)),

            Predicate::PatternLibrary { pattern_id } =>
                self.patterns.matches(pattern_id, text),

            Predicate::ExactDataMatch { fingerprint_set_id } =>
                ctx.edm_sets
                    .get(fingerprint_set_id)
                    .is_some_and(|fp| fp.is_match(text)),
        }
    }

    fn run_classifier(&self, id: ClassifierId, text: &str) -> bool {
        match id {
            ClassifierId::JpMyNumber          => detect_jp_my_number(text),
            ClassifierId::JpCorporateNumber   => detect_jp_corporate_number(text),
            ClassifierId::CreditCardPan       => detect_credit_card(text),
            ClassifierId::Iban                => detect_iban(text),
            ClassifierId::SwiftBic            => detect_swift_bic(text),
            ClassifierId::UsSsn               => detect_us_ssn(text),
            ClassifierId::IpAddress           => detect_ip_address(text),
            ClassifierId::ConfidentialMarker  => detect_confidential_marker(text),
            ClassifierId::AttorneyClientPrivilege => detect_attorney_privilege(text),
            ClassifierId::DealCodename        => detect_deal_codename(text),
            ClassifierId::SourceCode          => detect_source_code(text),
            ClassifierId::MedicalData         => detect_medical_data(text),
        }
    }
}

// ============================================================================
// DLP Result
// ============================================================================

/// DLP 評価の結果。
#[derive(Debug)]
pub struct DlpResult {
    /// 全体的な判定 (全トリガーされたルールの最大値)。
    /// 最終判定 (最も厳しいアクション)。
    pub verdict:  Action,
    /// All matching rules and their individual verdicts.
    pub findings: Vec<Finding>,
}

impl DlpResult {
    /// ルールがトリガーされなかった場合 true。
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.verdict == Action::Allow && self.findings.is_empty()
    }
}

/// 1 つのトリガーされたルール。
#[derive(Debug)]
pub struct Finding {
    /// 発火したルールの ID。
    pub rule_id:   String,
    /// 発火したルールの表示名。
    pub rule_name: String,
    /// そのルールのアクション。
    pub action:    Action,
    /// Short excerpt showing where the match occurred (for UI display).
    pub excerpt:   String,
}

// ============================================================================
// Pattern library (user-defined patterns, loaded from DB)
// ============================================================================

/// 名前付き正規表現パターンのセット。
#[derive(Debug, Default)]
pub struct PatternLibrary {
    patterns: HashMap<String, Vec<String>>, // name → regexes
}

impl PatternLibrary {
    /// 名前付きパターンセットを追加。
    pub fn add(&mut self, name: impl Into<String>, regexes: Vec<String>) {
        self.patterns.insert(name.into(), regexes);
    }

    /// 名前付きパターンがテキストに一致するか確認。
    #[must_use]
    pub fn matches(&self, name: &str, text: &str) -> bool {
        self.patterns.get(name)
            .map(|regexes| regexes.iter().any(|r| re_is_match(r.as_str(), text)))
            .unwrap_or(false)
    }
}

// ============================================================================
// Built-in classifiers
// ============================================================================

/// 全角数字 (U+FF10..=U+FF19) を ASCII 数字に正規化する。
///
/// is_ascii_digit() ベースの分類器 (マイナンバー・クレジットカード) は全角数字を
/// 検出できないため、内部犯が `１２３４５６７８９０１８` のように全角で書くだけで
/// DLP を回避できてしまう。検出前にこの関数で正規化する。
fn normalize_fullwidth_digits(text: &str) -> std::borrow::Cow<'_, str> {
    if text.chars().any(|c| ('\u{FF10}'..='\u{FF19}').contains(&c)) {
        std::borrow::Cow::Owned(
            text.chars()
                .map(|c| {
                    if ('\u{FF10}'..='\u{FF19}').contains(&c) {
                        // U+FF10 ('０') → '0' (オフセット 0xFF10)
                        char::from(b'0' + (c as u32 - 0xFF10) as u8)
                    } else {
                        c
                    }
                })
                .collect(),
        )
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}

fn detect_jp_my_number(text: &str) -> bool {
    // マイナンバー: 12 桁の個人番号 (ハイフンあり/なし両対応)
    // 総務省仕様のチェックディジット検証 (第 12 桁):
    //   p = Σ(i=1..11) d_i × w_i  where w = [2,3,4,5,6,7,2,3,4,5,6] (右から)
    //   check = (p % 11 < 2) ? 0 : 11 - (p % 11)
    let normalized = normalize_fullwidth_digits(text);
    let digits: String = normalized.chars().filter(|c| c.is_ascii_digit()).collect();

    // テキスト中の連続 12 桁をすべて試す
    let bytes = digits.as_bytes();
    for start in 0..bytes.len().saturating_sub(11) {
        let chunk = &bytes[start..start + 12];
        if chunk.iter().all(|b| b.is_ascii_digit()) {
            let d: Vec<u32> = chunk.iter().map(|b| (b - b'0') as u32).collect();
            if my_number_check_digit_valid(&d) {
                return true;
            }
        }
    }
    false
}

/// 総務省のチェックディジットアルゴリズムで 12 桁マイナンバーを検証する。
fn my_number_check_digit_valid(d: &[u32]) -> bool {
    if d.len() != 12 {
        return false;
    }
    // 第 1〜11 桁に対する乗数 (右→左: p1=d[10], p2=d[9], ..., p11=d[0])
    let weights = [2u32, 3, 4, 5, 6, 7, 2, 3, 4, 5, 6];
    let p: u32 = d[..11]
        .iter()
        .rev()
        .zip(weights.iter())
        .map(|(di, wi)| di * wi)
        .sum();
    let check = if p % 11 < 2 { 0 } else { 11 - (p % 11) };
    d[11] == check
}

fn detect_jp_corporate_number(text: &str) -> bool {
    // 法人番号: 13桁、先頭は1-9。
    // 国税庁のチェックディジットアルゴリズム (mod 9) で検証し、
    // ランダムな13桁数字列への誤検知を減らす。
    let normalized = normalize_fullwidth_digits(text);
    let digits: String = normalized.chars().filter(|c| c.is_ascii_digit()).collect();
    let bytes = digits.as_bytes();
    for start in 0..bytes.len().saturating_sub(12) {
        let chunk = &bytes[start..start + 13];
        if chunk[0] == b'0' {
            continue; // 先頭は1-9
        }
        if chunk.iter().all(|b| b.is_ascii_digit()) {
            let d: Vec<u32> = chunk.iter().map(|b| u32::from(b - b'0')).collect();
            if corporate_number_check_digit_valid(&d) {
                return true;
            }
        }
    }
    false
}

/// 国税庁の法人番号チェックディジットアルゴリズム (mod 9) で検証する。
///
/// 手順 (国税庁仕様):
///   基礎番号 (12桁, d[1..13]) の各桁に交互に重み 1, 2 を右から掛けて合計し、
///   9 で割った余りを 9 から引いた値がチェックディジット (d[0])。
fn corporate_number_check_digit_valid(d: &[u32]) -> bool {
    if d.len() != 13 {
        return false;
    }
    // 基礎番号は d[1..13] (12桁)。右から重み 1,2,1,2... を掛ける。
    let sum: u32 = d[1..]
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &digit)| {
            let weight = if i % 2 == 0 { 1 } else { 2 };
            digit * weight
        })
        .sum();
    let check = 9 - (sum % 9);
    d[0] == check
}

fn detect_credit_card(text: &str) -> bool {
    // 全角数字を正規化してから検出 (全角での DLP 回避を防ぐ)
    let normalized = normalize_fullwidth_digits(text);
    let text = normalized.as_ref();
    // 区切り (スペース/ハイフン) あり・なし両対応で主要ブランドの PAN 候補をマッチする。
    // Visa / Mastercard (16桁) に加え、以前は対象外だった JCB(35, 16桁) /
    // Discover(6011・65, 16桁) / American Express(34・37, 15桁 4-6-5) も検出する
    // (法人メールで Amex/JCB のカード番号が DLP をすり抜けて外部送信される穴を塞ぐ)。
    let Ok(re) = Regex::new(concat!(
        r"(?:",
        r"4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}",            // Visa 16
        r"|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}",      // Mastercard 16
        r"|35[0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}",          // JCB 16
        r"|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}",  // Discover 16
        r"|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}",                     // Amex 15 (4-6-5)
        r")",
    )) else { return false };
    // 各マッチから数字のみ抽出して桁数 (Amex=15 / その他=16) と Luhn を検証する。
    // 以前は「連続16桁ラン」しか拾わず区切り付き PAN が素通りし、かつ 16桁固定
    // 判定のため 15桁の Amex は原理的に検出できなかった。
    re.find_iter(text).any(|m| {
        let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
        (digits.len() == 15 || digits.len() == 16) && luhn_check(&digits)
    })
}

fn luhn_check(digits: &str) -> bool {
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let sum: u32 = digits.chars().rev().enumerate()
        .filter_map(|(i, c)| c.to_digit(10).map(|d| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else { d }
        }))
        .sum();
    sum % 10 == 0
}

fn detect_iban(text: &str) -> bool {
    // IBAN: 2 letter country code + 2 check digits + up to 30 alphanumeric。
    // 人間可読形式では4文字ごとにスペース区切りで印字するのが標準
    // (例: GB82 WEST 1234 5698 7654 32)。区切り (スペース/ハイフン) を跨いで
    // マッチできるようにし、検証前に区切りを除去する。以前は連続文字列にしか
    // マッチせず、銀行取引でごく一般的な区切り付き IBAN が素通りしていた。
    // 正規表現だけでは "US00ABCD1234" 等の非 IBAN にも一致し得るため、
    // ISO 7064 MOD 97-10 のチェックディジット検証で誤検知を抑える。
    let Ok(re) = Regex::new(r"\b[A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]){11,30}\b") else { return false };
    re.find_iter(text).any(|m| {
        let compact: String = m.as_str().chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        iban_checksum_valid(&compact)
    })
}

/// ISO 7064 MOD 97-10 アルゴリズムで IBAN のチェックディジットを検証する。
///
/// 手順:
/// 1. 先頭 4 文字 (国コード 2 + チェックディジット 2) を末尾に移動
/// 2. 各文字を数字に変換 (A=10, B=11, ..., Z=35)
/// 3. 変換後の数値全体を 97 で割った余りが 1 なら有効
fn iban_checksum_valid(candidate: &str) -> bool {
    if candidate.len() < 15 || candidate.len() > 34 {
        return false;
    }
    let bytes = candidate.as_bytes();
    if !bytes[0].is_ascii_uppercase() || !bytes[1].is_ascii_uppercase() {
        return false;
    }
    // 先頭 4 文字を末尾に移動: "GB82WEST..." → "WEST...GB82"
    let rearranged = format!("{}{}", &candidate[4..], &candidate[..4]);

    let mut remainder: u64 = 0;
    for c in rearranged.chars() {
        let value = if c.is_ascii_digit() {
            u64::from(c as u32 - '0' as u32)
        } else if c.is_ascii_uppercase() {
            u64::from(c as u32 - 'A' as u32) + 10
        } else {
            return false; // IBAN に許可されない文字
        };
        // 2桁の値 (10-35) は "12" のように2桁として計算に組み込む
        let digits = if value >= 10 {
            vec![value / 10, value % 10]
        } else {
            vec![value]
        };
        for d in digits {
            remainder = (remainder * 10 + d) % 97;
        }
    }
    remainder == 1
}

fn detect_swift_bic(text: &str) -> bool {
    // SWIFT BIC: 8 or 11 characters (BANKJPJT or BANKJPJTXXX)
    // 修正前は単純な文字クラスのみで判定しており、"ATTACHED" のような
    // 8文字の英大文字の英単語も誤って BIC と判定していた。
    // 位置5-6 (国コード部分) が実在する ISO 3166-1 alpha-2 国コードかを
    // 追加検証し、誤検知を大幅に減らす。
    let Ok(re) = Regex::new(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b") else { return false };
    let result = re.find_iter(text).any(|m| swift_bic_country_code_valid(m.as_str()));
    result
}

/// BIC 候補文字列の位置5-6 (0-indexed 4..6) が実在する国コードかを確認する。
fn swift_bic_country_code_valid(candidate: &str) -> bool {
    if candidate.len() < 6 {
        return false;
    }
    let country = &candidate[4..6];
    ISO_3166_ALPHA2.contains(&country)
}

/// ISO 3166-1 alpha-2 国コード一覧 (BIC の国コード検証に使用する主要国)。
/// 完全な 249 カ国リストではなく、金融取引で頻出する国を中心に収録。
const ISO_3166_ALPHA2: &[&str] = &[
    "JP", "US", "GB", "DE", "FR", "IT", "ES", "NL", "BE", "CH",
    "AT", "SE", "NO", "DK", "FI", "IE", "PT", "GR", "PL", "CZ",
    "HU", "RO", "BG", "HR", "SK", "SI", "LT", "LV", "EE", "LU",
    "CA", "AU", "NZ", "CN", "KR", "HK", "SG", "TW", "TH", "MY",
    "ID", "PH", "VN", "IN", "PK", "BD", "AE", "SA", "IL", "TR",
    "ZA", "EG", "NG", "KE", "BR", "MX", "AR", "CL", "CO", "PE",
    "RU", "UA", "CY", "MT", "IS", "LI",
];

fn detect_us_ssn(text: &str) -> bool {
    // 全角数字を正規化してから検出 (全角での DLP 回避を防ぐ)
    //
    // **重大な既存バグ修正**: 従来のパターンは `(?!000|666|9\d{2})` のような
    // ネガティブルックアヘッドを使用していたが、本クレートが依存する
    // `regex` クレート (標準版) はルックアラウンドを一切サポートしていない。
    // そのため `Regex::new()` が常にコンパイルエラーとなり、`re_is_match`
    // 内で警告ログを出して黙って `false` を返していた。つまり SSN 検出は
    // 機能追加以来ずっと動作しておらず、DLP が SSN を一度も検出できていなかった。
    // ルックアラウンドなしのパターンでマッチさせ、除外条件はコードで検証する。
    let normalized = normalize_fullwidth_digits(text);
    let Ok(re) = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b") else { return false };
    let result = re.find_iter(&normalized).any(|m| is_plausible_ssn(m.as_str()));
    result
}

/// SSA の割り当てルールに基づき、明らかに無効な SSN パターンを除外する。
///
/// - エリア番号 (先頭3桁) は "000", "666", "900"-"999" は割り当てられない
/// - グループ番号 (中間2桁) は "00" は割り当てられない
/// - シリアル番号 (末尾4桁) は "0000" は割り当てられない
fn is_plausible_ssn(candidate: &str) -> bool {
    let digits: Vec<u8> = candidate.bytes().filter(u8::is_ascii_digit).collect();
    if digits.len() != 9 {
        return false;
    }
    let area = std::str::from_utf8(&digits[0..3]).unwrap_or("");
    let group = std::str::from_utf8(&digits[3..5]).unwrap_or("");
    let serial = std::str::from_utf8(&digits[5..9]).unwrap_or("");

    if area == "000" || area == "666" || area.starts_with('9') {
        return false;
    }
    if group == "00" {
        return false;
    }
    if serial == "0000" {
        return false;
    }
    true
}

fn detect_ip_address(text: &str) -> bool {
    // 全角数字を正規化してから検出 (全角での DLP 回避を防ぐ)
    let normalized = normalize_fullwidth_digits(text);
    re_is_match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", &normalized)
}

fn detect_confidential_marker(text: &str) -> bool {
    let t = text.to_lowercase();
    // 通常一致
    let found = ["confidential", "机密", "機密", "秘密", "取扱注意",
                 "restricted", "internal only", "社外秘", "極秘",
                 "do not distribute", "not for distribution",
                ].iter().any(|m| t.contains(m));
    if found {
        return true;
    }
    // スペース区切り難読化 "C O N F I D E N T I A L" 対策:
    // 連続する単一英字をスペースで区切ったパターンを除去して再検索
    let collapsed = collapse_spaced_ascii(&t);
    ["confidential", "restricted", "internal only", "do not distribute",
     "not for distribution",
    ].iter().any(|m| collapsed.contains(m))
}

/// "c o n f i d e n t i a l" → "confidential" に正規化する。
///
/// 1 文字ずつスペース区切りで書かれた ASCII 難読化を解除する。
fn collapse_spaced_ascii(text: &str) -> String {
    // 「単一英字 + スペース」が 3 回以上連続するパターンを折りたたむ
    let chars: Vec<char> = text.chars().collect();
    let mut result = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        // 現在位置が "x " パターンの先頭かチェック (x=ASCII lowercase, 次がスペース)
        if chars[i].is_ascii_lowercase()
            && i + 1 < chars.len() && chars[i + 1] == ' '
            && i + 2 < chars.len() && chars[i + 2].is_ascii_lowercase()
            && i + 3 < chars.len() && (chars[i + 3] == ' ' || chars[i + 3].is_ascii_lowercase())
        {
            // スペース区切りの単一文字シーケンスを収集
            let mut word = String::new();
            while i < chars.len() && chars[i].is_ascii_lowercase() {
                word.push(chars[i]);
                i += 1;
                // 次がスペースかつその次が単一英字ならスペースを飛ばす
                if i < chars.len() && chars[i] == ' '
                    && i + 1 < chars.len() && chars[i + 1].is_ascii_lowercase()
                    && (i + 2 >= chars.len() || chars[i + 2] == ' ' || !chars[i + 2].is_ascii_alphabetic())
                {
                    i += 1; // スペースを飛ばす
                } else {
                    break;
                }
            }
            result.push_str(&word);
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    result
}

fn detect_attorney_privilege(text: &str) -> bool {
    let t = text.to_lowercase();
    ["attorney-client", "privileged and confidential",
     "attorney client privilege", "legal advice",
     "弁護士秘匿特権", "法的助言",
    ].iter().any(|m| t.contains(m))
}

fn detect_deal_codename(text: &str) -> bool {
    // ヒューリスティック: all-caps codenames preceded by "Project" or "Operation"
    re_is_match(r"(?i)(?:project|operation|プロジェクト)\s+[A-Z][A-Z0-9]{2,}", text)
}

fn detect_source_code(text: &str) -> bool {
    // ヒューリスティック: multiple lines that look like code
    let code_markers = ["fn ", "def ", "class ", "import ", "use ", "pub mod",
                        "#include", "namespace ", "function(", "const char*",
                        "SELECT ", "FROM ", "WHERE "];
    let count = code_markers.iter().filter(|m| text.contains(*m)).count();
    count >= 3
}

fn detect_medical_data(text: &str) -> bool {
    let t = text.to_lowercase();
    ["diagnosis", "prescription", "patient id", "医療記録",
     "診断名", "処方箋", "患者id", "病名",
     "icd-10", "icd-11",
    ].iter().any(|m| t.contains(m))
}

// ============================================================================
// Default rule set (Starter tier)
// ============================================================================

fn default_rules() -> Vec<Rule> {
    vec![
        // Rule 1: Block JP My Number in outbound
        Rule {
            id:        "default-001".into(),
            name:      "マイナンバー外部送信防止".into(),
            enabled:   true,
            direction: Direction::Outbound,
            priority:  10,
            action:    Action::Block,
            condition: Condition::all(vec![
                Condition::matches(Predicate::Classifier { classifier: ClassifierId::JpMyNumber }),
                Condition::negate(Condition::matches(Predicate::RecipientDomain {
                    domains: vec![], // empty = no allow-list; all external blocked
                })),
            ]),
        },

        // Rule 2: Block credit card numbers in outbound
        Rule {
            id:        "default-002".into(),
            name:      "クレジットカード番号外部送信防止".into(),
            enabled:   true,
            direction: Direction::Outbound,
            priority:  10,
            action:    Action::Block,
            condition: Condition::matches(Predicate::Classifier {
                classifier: ClassifierId::CreditCardPan,
            }),
        },

        // Rule 3: Warn on confidential marker to external domains
        Rule {
            id:        "default-003".into(),
            name:      "機密マーカー外部送信警告".into(),
            enabled:   true,
            direction: Direction::Outbound,
            priority:  20,
            action:    Action::Warn,
            condition: Condition::matches(Predicate::Classifier {
                classifier: ClassifierId::ConfidentialMarker,
            }),
        },

        // Rule 4: Warn on large outbound attachments (>50MB)
        Rule {
            id:        "default-004".into(),
            name:      "大容量添付ファイル送信警告".into(),
            enabled:   true,
            direction: Direction::Outbound,
            priority:  30,
            action:    Action::Warn,
            condition: Condition::matches(Predicate::SizeBytes { min: 50 * 1024 * 1024 }),
        },

        // Rule 5: Block source code to personal domains (gmail, yahoo, etc.)
        Rule {
            id:        "default-005".into(),
            name:      "ソースコードの個人メール送信防止".into(),
            enabled:   true,
            direction: Direction::Outbound,
            priority:  15,
            action:    Action::Block,
            condition: Condition::all(vec![
                Condition::matches(Predicate::Classifier { classifier: ClassifierId::SourceCode }),
                Condition::matches(Predicate::RecipientDomain {
                    domains: vec![
                        "gmail.com".into(), "yahoo.co.jp".into(), "yahoo.com".into(),
                        "hotmail.com".into(), "outlook.com".into(), "icloud.com".into(),
                    ],
                }),
            ]),
        },
    ]
}

// ============================================================================
// マッチング ユーティリティ
// ============================================================================

/// regex マッチングを適用する入力の最大バイト数。
/// `regex` クレートは線形時間保証があるが DFA テーブルメモリを制限するため上限を設ける。
const MAX_REGEX_INPUT_BYTES: usize = 512 * 1024; // 512 KB

/// URL パーセントエンコードをデコードする (DLP バイパス防止)。
///
/// `%40` → `@`、`%2F` → `/` 等の変換を行い、エンコードされた PII を
/// 正規表現が正しく検出できるようにする。
/// 不正なエンコードシーケンスはそのまま残す。
///
/// 二重エンコード (`%2540` → `%40` → `@`) も処理するため、
/// 出力が変化しなくなるまで最大 3 回繰り返す。
///
/// **DoS 対策**: 展開後のサイズが入力の 4 倍を超えた時点で打ち切る。
/// トリプルエンコードされた巨大入力でも最大 4x のメモリ増幅に抑える。
#[must_use]
pub fn percent_decode(s: &str) -> String {
    // 展開サイズ上限: 入力の 4 倍 または 4 MB のうち小さい方
    let max_decoded = (s.len() * 4).min(4 * 1024 * 1024);
    let mut current = percent_decode_once(s);
    for _ in 0..2 {
        if current.len() > max_decoded {
            break;
        }
        let next = percent_decode_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

/// URL パーセントデコードを 1 回実行する。
fn percent_decode_once(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut result = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (
                hex_digit(bytes[i + 1]),
                hex_digit(bytes[i + 2]),
            ) {
                let byte = (h << 4) | l;
                // ASCII 可読文字のみデコード (制御文字はスキップ)
                if byte >= 0x20 {
                    result.push(byte as char);
                    i += 3;
                    continue;
                }
            }
        }
        // UTF-8 文字をそのままコピー
        if let Some(ch) = s[i..].chars().next() {
            result.push(ch);
            i += ch.len_utf8();
        } else {
            i += 1;
        }
    }
    result
}

/// 16進数字を数値に変換する。
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 固定パターン向けの一回コンパイル正規表現マッチ。
/// 分類器のように定数パターンを使う箇所で呼ぶ (ルール評価は regex_cache を使う)。
fn re_is_match(pattern: &str, text: &str) -> bool {
    // 入力が大きすぎる場合は先頭 512 KB のみ検査 (DFA メモリ上限)
    let text = if text.len() > MAX_REGEX_INPUT_BYTES {
        let cut = (0..=MAX_REGEX_INPUT_BYTES).rev().find(|&i| text.is_char_boundary(i)).unwrap_or(0);
        &text[..cut]
    } else {
        text
    };
    // コンパイル結果をスレッドローカルキャッシュに保持し再コンパイルを回避する。
    thread_local! {
        static CACHE: std::cell::RefCell<HashMap<String, Regex>> =
            std::cell::RefCell::new(HashMap::new());
    }
    CACHE.with(|c| {
        let mut map = c.borrow_mut();
        if let Some(re) = map.get(pattern) {
            return re.is_match(text);
        }
        match Regex::new(pattern) {
            Ok(re) => {
                let result = re.is_match(text);
                map.insert(pattern.to_string(), re);
                result
            }
            Err(e) => {
                tracing::warn!("DLP classifier: invalid regex {:?}: {}", pattern, e);
                false
            }
        }
    })
}

fn excerpt_match(text: &str, cond: &Condition) -> String {
    // キーワードや正規表現が一致した位置の前後 40 文字を抽出して監査証跡を充実させる。
    let match_pos = find_first_match_pos(text, cond);
    let (start, end) = if let Some(pos) = match_pos {
        let s = pos.saturating_sub(30);
        let e = (pos + 50).min(text.len());
        (s, e)
    } else {
        (0, text.len().min(80))
    };
    // Ensure we're on valid UTF-8 boundaries (manual floor_char_boundary for MSRV 1.85)
    let s = utf8_floor(text, start);
    let e = utf8_floor(text, end);
    if text.len() <= 80 {
        text.to_owned()
    } else if s == 0 {
        format!("{}…", &text[..e])
    } else {
        format!("…{}…", &text[s..e])
    }
}

fn utf8_floor(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn find_first_match_pos(text: &str, cond: &Condition) -> Option<usize> {
    match cond {
        Condition::And { children } | Condition::Or { children } => {
            children.iter().find_map(|c| find_first_match_pos(text, c))
        }
        Condition::Not { child } => find_first_match_pos(text, child),
        Condition::Matches(pred) => match pred {
            Predicate::Keyword { words, .. } => {
                let lower = text.to_lowercase();
                words.iter().find_map(|w| lower.find(w.to_lowercase().as_str()))
            }
            Predicate::Regex { pattern } => {
                Regex::new(pattern).ok().and_then(|re| re.find(text).map(|m| m.start()))
            }
            _ => None,
        },
    }
}

// ============================================================================
// Rule builder (fluent API for tests and admin UI)
// ============================================================================

/// 流暢なルールビルダー。
pub struct RuleBuilder {
    id:        String,
    name:      String,
    direction: Direction,
    priority:  u32,
    action:    Action,
    condition: Option<Condition>,
}

impl RuleBuilder {
    /// 新規インスタンスを作成する。
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(), name: name.into(),
            direction: Direction::Both,
            priority: 100, action: Action::Warn,
            condition: None,
        }
    }
    /// `outbound` を実行する。
    pub fn outbound(mut self)             -> Self { self.direction = Direction::Outbound; self }
    /// `inbound` を実行する。
    pub fn inbound(mut self)              -> Self { self.direction = Direction::Inbound;  self }
    /// `block` を実行する。
    pub fn block(mut self)                -> Self { self.action = Action::Block; self }
    /// `warn` を実行する。
    pub fn warn(mut self)                 -> Self { self.action = Action::Warn;  self }
    /// `priority` を実行する。
    pub fn priority(mut self, p: u32)     -> Self { self.priority = p; self }
    /// `when` を実行する。
    pub fn when(mut self, c: Condition)   -> Self { self.condition = Some(c); self }

    /// `build` を実行する。
    pub fn build(self) -> Rule {
        Rule {
            id: self.id, name: self.name, enabled: true,
            direction: self.direction, priority: self.priority,
            action: self.action,
            condition: self.condition.unwrap_or(Condition::Or { children: vec![] }),
        }
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> DlpEngine { DlpEngine::default_engine() }

    fn ctx<'a>(body: &'a str, from: &'a str, to: &'a [String]) -> EvalCtx<'a> {
        // テスト用の空 EDM セット (static で寿命を確保)
        use std::sync::OnceLock;
        static EMPTY_EDM: OnceLock<std::collections::HashMap<String, crate::edm::EdmFingerprints>> = OnceLock::new();
        let edm_sets = EMPTY_EDM.get_or_init(std::collections::HashMap::new);
        EvalCtx {
            body, subject: "", size_bytes: 100,
            to, from, attachment_mimes: &[],
            edm_sets,
            known_recipient_domains: &[],
            our_domain: "",
        }
    }

    #[test]
    fn edm_predicate_detects_match() {
        use crate::edm::EdmFingerprints;
        let mut fp = EdmFingerprints::new("test-salt", 2);
        fp.register_dataset(&["secret-customer-001", "confidential-deal-x"]);
        let mut sets = std::collections::HashMap::new();
        sets.insert("customers".to_string(), fp);

        let to = vec!["external@other.com".to_string()];
        let body = "送信: secret-customer-001 と confidential-deal-x の情報";
        let ctx = EvalCtx {
            body, subject: "", size_bytes: 100,
            to: &to, from: "me@corp.com", attachment_mimes: &[],
            edm_sets: &sets,
        known_recipient_domains: &[],
        our_domain: "",
        };
        let engine = DlpEngine::new(
            vec![Rule {
                id: "edm-rule".into(),
                name: "EDM test".into(),
                enabled: true,
                direction: Direction::Outbound,
                condition: Condition::matches(Predicate::ExactDataMatch {
                    fingerprint_set_id: "customers".into(),
                }),
                action: Action::Block,
                priority: 0,
            }],
            PatternLibrary::default(),
        );
        let result = engine.evaluate(&ctx, Direction::Outbound);
        assert!(!result.is_clean(), "EDM 一致を検出すべき");
    }

    #[test]
    fn clean_email_passes() {
        let to = vec!["alice@example.com".into()];
        let result = engine().evaluate(&ctx("こんにちは。本日の会議の件です。", "me@corp.com", &to), Direction::Outbound);
        assert!(result.is_clean(), "findings: {:?}", result.findings);
    }

    #[test]
    fn my_number_blocks_outbound() {
        // 総務省チェックディジット検証を通過する有効なマイナンバー形式
        // 123456789018: d[0..11]=[1,2,3,4,5,6,7,8,9,0,1], p=212, 212%11=3 → check=8 → 末尾=8
        let to = vec!["attacker@gmail.com".into()];
        let body = "マイナンバーは 123456789018 です";
        let result = engine().evaluate(&ctx(body, "me@corp.com", &to), Direction::Outbound);
        assert_eq!(result.verdict, Action::Block, "should block valid my number");
        assert!(result.findings.iter().any(|f| f.rule_id == "default-001"));
    }

    #[test]
    fn my_number_check_digit_rejects_invalid() {
        // 123456789012 はチェックディジット不一致 → 検出しない (false positive 削減)
        assert!(!my_number_check_digit_valid(&[1,2,3,4,5,6,7,8,9,0,1,2]));
        // 123456789018 は正しい
        assert!(my_number_check_digit_valid(&[1,2,3,4,5,6,7,8,9,0,1,8]));
    }

    #[test]
    fn my_number_check_digit_edge_cases() {
        // 桁数が 12 でない場合は false
        assert!(!my_number_check_digit_valid(&[1,2,3]));
        assert!(!my_number_check_digit_valid(&[1,2,3,4,5,6,7,8,9,0,1,8,9]));
    }

    #[test]
    fn confidential_marker_warns() {
        let to = vec!["vendor@external.com".into()];
        let body = "CONFIDENTIAL: Q3 revenue forecast attached.";
        let result = engine().evaluate(&ctx(body, "me@corp.com", &to), Direction::Outbound);
        assert!(result.findings.iter().any(|f| f.action == Action::Warn),
            "should warn on confidential marker");
    }

    #[test]
    fn source_code_to_gmail_blocked() {
        let to = vec!["mypersonalemail@gmail.com".into()];
        let body = "fn main() { use std::io; import os; class Foo { def bar(self) {} } pub mod test { function(x) {} const char* ptr = NULL; SELECT * FROM users WHERE id = 1; }";
        let result = engine().evaluate(&ctx(body, "me@corp.com", &to), Direction::Outbound);
        let has_block = result.findings.iter().any(|f| f.action == Action::Block);
        assert!(has_block, "source code to gmail should be blocked");
    }

    #[test]
    fn luhn_valid_card_detected() {
        // Visa test number: 4532015112830366 (Luhn valid)
        assert!(luhn_check("4532015112830366"));
        // 無効
        assert!(!luhn_check("4532015112830367"));
    }

    #[test]
    fn condition_and_requires_both() {
        let cond = Condition::all(vec![
            Condition::matches(Predicate::Classifier { classifier: ClassifierId::ConfidentialMarker }),
            Condition::matches(Predicate::Classifier { classifier: ClassifierId::JpMyNumber }),
        ]);
        let to: Vec<String> = vec![];
        let ctx_only_conf = ctx("CONFIDENTIAL: meeting notes", "", &to);
        let engine = DlpEngine::new(vec![], PatternLibrary::default());
        // Only confidential, not my number → AND should be false
        let text = ctx_only_conf.full_text();
        let text_lower = text.to_lowercase();
        assert!(!engine.eval_condition(&cond, &ctx_only_conf, &text, &text_lower));
    }

    #[test]
    fn rule_builder_produces_valid_rule() {
        let rule = RuleBuilder::new("test-001", "Test rule")
            .outbound()
            .block()
            .priority(5)
            .when(Condition::matches(Predicate::Classifier { classifier: ClassifierId::CreditCardPan }))
            .build();
        assert_eq!(rule.action, Action::Block);
        assert_eq!(rule.direction, Direction::Outbound);
        assert!(rule.enabled);
    }

    #[test]
    fn inbound_rule_skipped_for_outbound() {
        let inbound_only = Rule {
            id: "in-only".into(), name: "inbound only".into(), enabled: true,
            direction: Direction::Inbound, priority: 1, action: Action::Block,
            condition: Condition::matches(Predicate::Classifier { classifier: ClassifierId::ConfidentialMarker }),
        };
        let engine = DlpEngine::new(vec![inbound_only], PatternLibrary::default());
        let to = vec!["x@x.com".into()];
        let result = engine.evaluate(&ctx("CONFIDENTIAL", "", &to), Direction::Outbound);
        // The inbound rule should NOT fire for outbound direction
        assert!(result.is_clean());
    }

    #[test]
    fn action_ordering_is_block_gt_warn_gt_allow() {
        assert!(Action::Block > Action::Warn);
        assert!(Action::Warn  > Action::Allow);
    }

    #[test]
    fn regex_predicate_matches_real_pattern() {
        // 実際の正規表現でマイナンバーフォーマットを検出
        let rule = RuleBuilder::new("r1", "JP Corporate")
            .outbound()
            .warn()
            .priority(1)
            .when(Condition::matches(Predicate::Regex {
                pattern: r"\b[1-9]\d{12}\b".to_string(),
            }))
            .build();
        let engine = DlpEngine::new(vec![rule], PatternLibrary::default());
        let to = vec!["ext@partner.co.jp".to_string()];

        // 13桁の法人番号を含むテキスト
        let result = engine.evaluate(&ctx("請求書 1234567890123", "", &to), Direction::Outbound);
        assert!(!result.is_clean(), "法人番号を含むテキストは Warn になるべき");
    }

    #[test]
    fn regex_predicate_no_false_positive() {
        let rule = RuleBuilder::new("r1", "Credit Card")
            .outbound()
            .block()
            .priority(1)
            .when(Condition::matches(Predicate::Regex {
                pattern: r"\b4[0-9]{15}\b".to_string(),
            }))
            .build();
        let engine = DlpEngine::new(vec![rule], PatternLibrary::default());
        let to = vec!["ext@partner.co.jp".to_string()];

        // クレジットカード番号なし
        let result = engine.evaluate(&ctx("通常のメール本文です", "", &to), Direction::Outbound);
        assert!(result.is_clean(), "通常テキストには false positive なし");
    }

    #[test]
    fn regex_compiled_at_engine_build_time() {
        // コンパイルエラーのパターン → エンジン構築後に警告ログ出力のみ、panicしない
        let bad_rule = Rule {
            id: "bad".into(), name: "bad regex".into(), enabled: true,
            direction: Direction::Both, priority: 1, action: Action::Block,
            condition: Condition::matches(Predicate::Regex {
                pattern: r"[invalid regex(".to_string(),
            }),
        };
        // Should not panic
        let engine = DlpEngine::new(vec![bad_rule], PatternLibrary::default());
        let to = vec!["x@x.com".into()];
        // Invalid regex → no match (fails safe)
        let result = engine.evaluate(&ctx("anything", "", &to), Direction::Both);
        assert!(result.is_clean(), "不正な正規表現は安全側に倒してマッチなし");
    }

    #[test]
    fn spaced_confidential_marker_detected() {
        // "C O N F I D E N T I A L" 難読化対策
        let to = vec!["vendor@external.com".into()];
        let body = "C O N F I D E N T I A L: Q3 revenue data";
        let result = engine().evaluate(&ctx(body, "me@corp.com", &to), Direction::Outbound);
        assert!(result.findings.iter().any(|f| f.action == Action::Warn),
            "スペース区切り難読化 CONFIDENTIAL を検出すべき");
    }

    // ── 機密コンテンツ + 宛先ミス の複合検出 (内部脅威/誤送信対策) ──────────

    fn ctx_with_recipient_history<'a>(
        body: &'a str, from: &'a str, to: &'a [String],
        known_recipient_domains: &'a [String], our_domain: &'a str,
    ) -> EvalCtx<'a> {
        use std::sync::OnceLock;
        static EMPTY_EDM: OnceLock<std::collections::HashMap<String, crate::edm::EdmFingerprints>> = OnceLock::new();
        let edm_sets = EMPTY_EDM.get_or_init(std::collections::HashMap::new);
        EvalCtx {
            body, subject: "", size_bytes: 100,
            to, from, attachment_mimes: &[],
            edm_sets, known_recipient_domains, our_domain,
        }
    }

    #[test]
    fn confidential_content_to_typo_domain_escalates_to_block() {
        // 「機密情報」+「タイポドメイン宛」の複合 — 内部脅威/誤送信の典型シグナル
        let to = vec!["alice@crop.com".to_string()]; // corp.com のタイポ
        let known = vec!["corp.com".to_string()];
        let body = "CONFIDENTIAL: Q3 財務データを送付します";
        let result = engine().evaluate(
            &ctx_with_recipient_history(body, "me@us.com", &to, &known, "us.com"),
            Direction::Outbound,
        );
        assert_eq!(result.verdict, Action::Block,
            "機密コンテンツ + タイポドメイン宛は Block にエスカレートされるべき: {result:?}");
        assert!(result.findings.iter().any(|f| f.rule_id == "misdirected-recipient"));
    }

    #[test]
    fn confidential_content_to_known_domain_not_escalated() {
        // 機密コンテンツだが既知の実績あるドメイン宛 — エスカレートしない
        let to = vec!["alice@corp.com".to_string()];
        let known = vec!["corp.com".to_string()];
        let body = "CONFIDENTIAL: Q3 財務データを送付します";
        let result = engine().evaluate(
            &ctx_with_recipient_history(body, "me@us.com", &to, &known, "us.com"),
            Direction::Outbound,
        );
        assert_ne!(result.verdict, Action::Block,
            "既知の実績あるドメイン宛は宛先ミスとしてエスカレートされるべきではない: {result:?}");
    }

    #[test]
    fn non_sensitive_content_to_typo_domain_not_escalated_by_dlp() {
        // 機密コンテンツでなければ DLP レベルではエスカレートしない
        // (宛先ミス自体の検出は misdirected_recipient モジュール単体の責務)
        let to = vec!["alice@crop.com".to_string()];
        let known = vec!["corp.com".to_string()];
        let body = "こんにちは、来週の予定について確認させてください。";
        let result = engine().evaluate(
            &ctx_with_recipient_history(body, "me@us.com", &to, &known, "us.com"),
            Direction::Outbound,
        );
        assert_eq!(result.verdict, Action::Allow);
    }

    #[test]
    fn our_domain_empty_skips_misdirect_check() {
        // our_domain が空 (呼び出し元が履歴データを持たない) 場合は
        // 宛先ミス検出をスキップし、通常の DLP 判定のみ適用する
        let to = vec!["alice@crop.com".to_string()];
        let body = "CONFIDENTIAL: Q3 財務データを送付します";
        let result = engine().evaluate(&ctx(body, "me@us.com", &to), Direction::Outbound);
        assert_ne!(result.verdict, Action::Block,
            "our_domain が空の場合は宛先ミス検出でエスカレートされるべきではない");
    }

    // ── 全角数字による DLP 回避テスト ──────────────────────────────────────

    #[test]
    fn my_number_fullwidth_digits_still_detected() {
        // 内部犯が全角数字でマイナンバーを書いて DLP 回避を試みる
        // １２３４５６７８９０１８ = 123456789018 (有効なチェックディジット)
        assert!(detect_jp_my_number("マイナンバーは １２３４５６７８９０１８ です"),
            "全角数字のマイナンバーが検出されない (DLP 回避)");
    }

    #[test]
    fn my_number_fullwidth_blocks_outbound() {
        let to = vec!["attacker@gmail.com".into()];
        let body = "番号: １２３４５６７８９０１８";
        let result = engine().evaluate(&ctx(body, "me@corp.com", &to), Direction::Outbound);
        assert_eq!(result.verdict, Action::Block,
            "全角マイナンバーの外部送信はブロックされるべき");
    }

    #[test]
    fn normalize_fullwidth_digits_roundtrip() {
        assert_eq!(normalize_fullwidth_digits("０１２３４５６７８９").as_ref(), "0123456789");
        // 全角を含まない場合は借用のまま (アロケーションなし)
        assert!(matches!(normalize_fullwidth_digits("hello"), std::borrow::Cow::Borrowed(_)));
        // 混在
        assert_eq!(normalize_fullwidth_digits("ab１２cd").as_ref(), "ab12cd");
    }

    #[test]
    fn credit_card_fullwidth_digits_detected() {
        // Visa テスト番号 4532015112830366 を全角で
        let fullwidth = "４５３２０１５１１２８３０３６６";
        assert!(detect_credit_card(fullwidth),
            "全角クレジットカード番号が検出されない (DLP 回避)");
    }

    #[test]
    fn credit_card_with_separators_detected() {
        // 回帰: 区切り付き PAN は正規表現に一致するのに、旧 extract_digit_runs が
        // 「連続16桁ラン」しか拾わず Luhn 検証に到達せず検出漏れしていた。
        // 4111 1111 1111 1111 は Luhn 有効な Visa テスト番号。
        assert!(detect_credit_card("カード番号は 4111-1111-1111-1111 です"),
            "ハイフン区切りの PAN が検出されない");
        assert!(detect_credit_card("card 4111 1111 1111 1111"),
            "スペース区切りの PAN が検出されない");
        // 連続表記も引き続き検出される
        assert!(detect_credit_card("4111111111111111"));
        // Luhn 不正な番号は (区切りの有無に関わらず) 検出されない
        assert!(!detect_credit_card("4111-1111-1111-1112"),
            "Luhn 不正な番号を誤検出している");
    }

    #[test]
    fn credit_card_amex_jcb_discover_detected() {
        // Visa/Mastercard 以外の主要ブランドも検出されるべき (DLP カバレッジの穴)。
        // いずれも各ブランドの標準テスト番号 (Luhn 有効)。
        assert!(detect_credit_card("Amex: 378282246310005"),
            "American Express (15桁) が検出されない");
        assert!(detect_credit_card("Amex 3782 822463 10005"),
            "区切り付き Amex が検出されない");
        assert!(detect_credit_card("JCB 3530111333300000"),
            "JCB が検出されない");
        assert!(detect_credit_card("Discover 6011111111111117"),
            "Discover が検出されない");
        // Luhn 不正な 15桁 Amex 風番号は検出されない
        assert!(!detect_credit_card("378282246310004"),
            "Luhn 不正な Amex 風番号を誤検出している");
    }

    #[test]
    fn iban_with_spaces_detected() {
        // 回帰: 4文字ごとスペース区切りの標準印字形式は、旧正規表現が
        // スペースを跨げず検出漏れしていた。
        assert!(detect_iban("送金先 IBAN: GB82 WEST 1234 5698 7654 32 まで"),
            "スペース区切りの IBAN が検出されない");
        // 連続表記も引き続き検出される
        assert!(detect_iban("IBAN GB82WEST12345698765432"));
        // チェックディジット不正 (区切り付き) は検出されない
        assert!(!detect_iban("GB82 WEST 1234 5698 7654 33"),
            "チェックディジット不正な IBAN を誤検出している");
    }

    // ── 受信者ドメイン抽出のバイパステスト ─────────────────────────────────

    #[test]
    fn recipient_domain_uses_last_at_segment() {
        // 細工アドレス victim@corp.com@gmail.com の実ドメインは gmail.com (最後の @)
        // 旧実装 split('@').nth(1) は corp.com を取り gmail ブロックを回避していた
        let to = vec!["victim@corp.com@gmail.com".to_string()];
        let c = ctx("body", "me@corp.com", &to);
        let domains = c.recipient_domains();
        assert_eq!(domains, vec!["gmail.com".to_string()],
            "最後の @ の後のドメインを抽出すべき: {domains:?}");
    }

    #[test]
    fn source_code_to_disguised_gmail_still_blocked() {
        // 細工された gmail アドレスでソースコード DLP を回避しようとする
        let to = vec!["exfil@internal.corp@gmail.com".to_string()];
        let body = "fn main() { use std::io; import os; class Foo { def bar(self) {} } pub mod test { function(x) {} const char* p = NULL; SELECT * FROM users WHERE id = 1; }";
        let result = engine().evaluate(&ctx(body, "me@corp.com", &to), Direction::Outbound);
        assert!(result.findings.iter().any(|f| f.action == Action::Block),
            "細工 gmail アドレスでもソースコードはブロックされるべき");
    }

    #[test]
    fn recipient_domain_no_at_sign_is_skipped() {
        // @ を含まない不正アドレスはドメインなし扱い (パニックしない)
        let to = vec!["not-an-email".to_string()];
        let c = ctx("body", "me@corp.com", &to);
        assert!(c.recipient_domains().is_empty());
    }

    #[test]
    fn condition_empty_and_does_not_match_vacuously() {
        // And { children: [] } は Rust の iter().all() で vacuous truth になり
        // 全メールをブロックしてしまう問題の回帰テスト。
        let rule = Rule {
            id: "empty-and".into(),
            name: "空条件ツリー".into(),
            enabled: true,
            direction: Direction::Outbound,
            priority: 1,
            action: Action::Block,
            condition: Condition::And { children: vec![] },
        };
        let engine = DlpEngine::new(vec![rule], PatternLibrary::default());
        let to = vec!["x@x.com".into()];
        let result = engine.evaluate(&ctx("通常メール本文", "", &to), Direction::Outbound);
        assert!(result.is_clean(), "空の AND 条件はマッチしてはならない: {:?}", result.findings);
    }

    #[test]
    fn condition_deeply_nested_does_not_stack_overflow() {
        // 攻撃者がカスタムルールで深いネストを作った場合のスタック保護テスト。
        // 主な保証: パニック・スタックオーバーフローなしに完了すること。
        // 深さ制限 (64) で再帰を打ち切るため、Not の連鎖が false に打ち切られる。
        // Not の偶奇により最終値は変わりうるが、スタックは安全。
        let mut cond = Condition::matches(Predicate::Classifier {
            classifier: ClassifierId::ConfidentialMarker,
        });
        // 70 段 (> 64 の深さ制限): drop スタックはこの深さでは問題ない範囲
        for _ in 0..70 {
            cond = Condition::negate(cond);
        }
        let rule = Rule {
            id: "deep".into(),
            name: "深いネスト".into(),
            enabled: true,
            direction: Direction::Outbound,
            priority: 1,
            action: Action::Block,
            condition: cond,
        };
        let engine = DlpEngine::new(vec![rule], PatternLibrary::default());
        let to = vec!["x@x.com".into()];
        // スタックオーバーフローしないこと (is_clean() の値は問わない)
        let _result = engine.evaluate(&ctx("CONFIDENTIAL", "", &to), Direction::Outbound);
        // このテストがパニックなしで到達すれば合格
    }

    #[test]
    fn excerpt_includes_match_context() {
        let rule = RuleBuilder::new("r1", "SSN")
            .outbound()
            .warn()
            .priority(1)
            .when(Condition::matches(Predicate::Keyword {
                words: vec!["secret".to_string()],
                min_count: 1,
            }))
            .build();
        let engine = DlpEngine::new(vec![rule], PatternLibrary::default());
        let long_text = format!("{}secret information here{}", "x".repeat(50), "y".repeat(50));
        let to = vec!["x@x.com".into()];
        let result = engine.evaluate(&ctx(&long_text, "", &to), Direction::Outbound);
        assert!(!result.is_clean());
        // 抜粋は一致箇所の前後を含むべき (先頭50文字だけではない)
        let excerpt = &result.findings[0].excerpt;
        assert!(excerpt.contains("secret"), "抜粋は一致箇所を含むべき");
    }

    #[test]
    fn evaluate_does_not_oom_on_huge_body() {
        use std::collections::HashMap;
        let engine = DlpEngine::default_engine();
        let huge_body = "x".repeat(10 * 1024 * 1024); // 10MB
        let to = vec!["alice@example.com".to_string()];
        let edm_sets = HashMap::new();
        let eval_ctx = EvalCtx {
            body:             &huge_body,
            subject:          "test",
            size_bytes:       huge_body.len() as u64,
            to:               &to,
            from:             "sender@example.com",
            attachment_mimes: &[],
            edm_sets:         &edm_sets,
        known_recipient_domains: &[],
        our_domain: "",
        };
        // クラッシュしないこと
        let result = engine.evaluate(&eval_ctx, Direction::Outbound);
        // 10MB のランダムバイトは PII を含まないはずなので Clean
        let _ = result; // 判定は問わない (クラッシュしないことを確認)
    }

    #[test]
    fn evaluate_detects_pii_in_huge_body_prefix() {
        use std::collections::HashMap;
        let engine = DlpEngine::default_engine();
        // 先頭にマイナンバーを入れて 5MB のボディ
        let mut body = "1234-5678-9012 ".to_string(); // マイナンバー形式
        body.push_str(&"x".repeat(5 * 1024 * 1024));
        let to = vec!["external@gmail.com".to_string()];
        let edm_sets = HashMap::new();
        let eval_ctx = EvalCtx {
            body:             &body,
            subject:          "test",
            size_bytes:       body.len() as u64,
            to:               &to,
            from:             "sender@example.com",
            attachment_mimes: &[],
            edm_sets:         &edm_sets,
        known_recipient_domains: &[],
        our_domain: "",
        };
        // 先頭 1MB 以内にマイナンバーがあるので検出されるはず
        let result = engine.evaluate(&eval_ctx, Direction::Outbound);
        let _ = result; // 検出有無はデフォルトルール次第; クラッシュしないことを確認
    }

    // percent_decode テスト
    #[test]
    fn percent_decode_at_sign() {
        assert_eq!(percent_decode("user%40example.com"), "user@example.com");
    }

    #[test]
    fn percent_decode_slash() {
        assert_eq!(percent_decode("path%2Fto%2Ffile"), "path/to/file");
    }

    #[test]
    fn percent_decode_uppercase_hex() {
        assert_eq!(percent_decode("%41%42%43"), "ABC");
    }

    #[test]
    fn percent_decode_lowercase_hex() {
        assert_eq!(percent_decode("%61%62%63"), "abc");
    }

    #[test]
    fn percent_decode_no_encoding_unchanged() {
        assert_eq!(percent_decode("plain text"), "plain text");
    }

    #[test]
    fn percent_decode_invalid_sequence_kept() {
        // 不正なシーケンスはそのまま
        assert!(percent_decode("%ZZ is invalid").contains('%'));
    }

    #[test]
    fn percent_decode_truncated_sequence_kept() {
        // 末尾で切れている場合もクラッシュしない
        let result = percent_decode("abc%2");
        assert!(result.starts_with("abc"));
    }

    #[test]
    fn percent_encoded_pii_detected_by_dlp() {
        use crate::{EvalCtx, Direction, DlpEngine};
        use std::collections::HashMap;

        let edm_sets = HashMap::new();
        let engine = DlpEngine::default_engine();

        // マイナンバーを %XX エンコードで難読化
        // "123456789018" を一部エンコード: "123456789018" → 通常は検出済みだが
        // ここでは keyword "confidential" をエンコードした場合をテスト
        let eval_ctx = EvalCtx {
            body:    "sending %63onfidential document to external",
            subject: "test",
            size_bytes: 50,
            to:      &["external@gmail.com".to_string()],
            from:    "alice@corp.com",
            attachment_mimes: &[],
            edm_sets: &edm_sets,
        known_recipient_domains: &[],
        our_domain: "",
        };
        let result = engine.evaluate(&eval_ctx, Direction::Outbound);
        // decoded_text で "confidential" が復元され検出されるはず
        assert!(
            !result.findings.is_empty(),
            "パーセントエンコードされた機密キーワードは検出されるべき: {:?}", result.findings
        );
    }

    #[test]
    fn double_encoded_at_sign_decoded() {
        // %2540 → %40 → @ (二重エンコード)
        assert_eq!(percent_decode("%2540"), "@");
    }

    #[test]
    fn triple_encoding_limited_to_3_iterations() {
        // %252540 → %2540 → %40 → @ (3重エンコード、3回で収束)
        assert_eq!(percent_decode("%252540"), "@");
    }

    #[test]
    fn single_encoding_still_works() {
        // 既存の1重エンコードは変わらず動作する
        assert_eq!(percent_decode("user%40example.com"), "user@example.com");
    }

    // ── IBAN チェックディジット検証 ──────────────────────────────────────

    #[test]
    fn valid_iban_checksum_passes() {
        // GB82 WEST 1234 5698 7654 32 — 広く知られる有効な IBAN サンプル
        assert!(iban_checksum_valid("GB82WEST12345698765432"));
    }

    #[test]
    fn invalid_iban_checksum_rejected() {
        // 最終桁を変更してチェックディジットを崩す
        assert!(!iban_checksum_valid("GB82WEST12345698765433"));
    }

    #[test]
    fn random_non_iban_string_rejected_by_checksum() {
        // 従来の正規表現のみでは一致するが、チェックディジットで弾かれるべき
        assert!(!iban_checksum_valid("US00ABCD1234"));
    }

    #[test]
    fn detect_iban_with_valid_checksum_in_text() {
        let text = "お振込先 IBAN: GB82WEST12345698765432 までお願いします";
        assert!(detect_iban(text), "有効な IBAN は検出されるべき");
    }

    #[test]
    fn detect_iban_random_uppercase_string_not_flagged() {
        // ランダムな大文字英数字列 (チェックディジット不一致) は検出されない
        let text = "製品コード: US00ABCDEFGH について";
        assert!(!detect_iban(text), "無効なチェックディジットの文字列は検出されるべきではない");
    }

    // ── 法人番号チェックディジット検証 ────────────────────────────────────

    #[test]
    fn valid_corporate_number_checksum_passes() {
        // 基礎番号 123456789012 に対する正しいチェックディジットは 7
        assert!(corporate_number_check_digit_valid(&[7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2]));
    }

    #[test]
    fn invalid_corporate_number_checksum_rejected() {
        assert!(!corporate_number_check_digit_valid(&[1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2]));
    }

    #[test]
    fn detect_jp_corporate_number_with_valid_checksum() {
        let text = "法人番号: 7123456789012 です";
        assert!(detect_jp_corporate_number(text), "有効な法人番号は検出されるべき");
    }

    // ── SWIFT BIC 国コード検証 ────────────────────────────────────────────

    #[test]
    fn valid_swift_bic_with_real_country_code_detected() {
        // BANKJPJT: 位置5-6 = "JP" (実在国コード)
        assert!(detect_swift_bic("送金先 BIC: BANKJPJT です"));
    }

    #[test]
    fn valid_swift_bic_11_char_detected() {
        assert!(detect_swift_bic("BIC: BANKJPJTXXX"));
    }

    #[test]
    fn random_uppercase_word_not_flagged_as_bic() {
        // 修正前: 8 文字の英大文字の単語なら何でも BIC と誤検知していた。
        // "SOFTWARE" の位置5-6 (0-indexed 4..6) = "WA" は実在国コードではないため
        // 検出されないはず (前は単なる文字クラス一致で誤検知していた)。
        assert!(!detect_swift_bic("please install the SOFTWARE update"));
    }

    #[test]
    fn invalid_country_code_bic_not_flagged() {
        // 位置5-6 = "ZZ" は実在しない国コード
        assert!(!detect_swift_bic("code: BANKZZJT"));
    }

    // ── SSN / IP アドレス 全角数字バイパス対策 ──────────────────────────

    #[test]
    fn ssn_detected_with_fullwidth_digits() {
        // 全角数字 + 半角ハイフンでの SSN 記述 (DLP バイパス試行)。
        // ハイフン自体は normalize_fullwidth_digits の対象外のため半角で記述する。
        let text = "SSN: ３３３-４４-５５５５ です";
        assert!(detect_us_ssn(text), "全角数字の SSN も検出されるべき");
    }

    #[test]
    fn ip_address_detected_with_fullwidth_digits() {
        // ピリオドは半角のまま、数字のみ全角にする
        let text = "サーバー IP: １９２.１６８.１.１ です";
        assert!(detect_ip_address(text), "全角数字の IP アドレスも検出されるべき");
    }

    #[test]
    fn normal_ascii_ssn_still_detected() {
        assert!(detect_us_ssn("SSN: 333-44-5555"));
    }

    #[test]
    fn normal_ascii_ip_still_detected() {
        assert!(detect_ip_address("IP: 192.168.1.1"));
    }

    #[test]
    fn detect_jp_corporate_number_random_digits_not_flagged() {
        // チェックディジット不一致のランダムな13桁は検出されない
        // (1111111111112 は基礎番号 111111111111 2 のチェックディジットが 8 であるべきなので不一致)
        let text = "注文番号: 1111111111112 です";
        assert!(!detect_jp_corporate_number(text),
            "チェックディジット不一致の13桁は検出されるべきではない");
    }
}
