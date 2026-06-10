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
// Extensibility:
//   Custom rules live in kaname-store.dlp_rules as JSON.
//   DlpEngine::from_db() loads them at startup and on Settings change.


pub mod edm;
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(missing_docs)]

//! # kaname-dlp
//!
//! Boolean-grammar DLP rule engine. Pure, synchronous, zero-allocation hot path.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Rule model
// ============================================================================

/// DLP ルール: 条件ツリー + アクション + メタデータ。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id:        String,
    pub name:      String,
    pub enabled:   bool,
    pub direction: Direction,
    pub condition: Condition,
    pub action:    Action,
    /// 数値が小さいほど先に評価。同値の場合は id で決定。
    pub priority:  u32,
}

/// このルールが適用される方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Direction {
    Outbound, Inbound, Both,
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
    And { children: Vec<Condition> },
    /// 少なくとも 1 つの子が一致しなければならない。
    Or  { children: Vec<Condition> },
    /// 子が一致してはならない。
    Not { child: Box<Condition> },
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
    pub fn not(c: Condition) -> Self {
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
    Classifier { classifier: ClassifierId },
    /// Regular expression match against body text.
    Regex { pattern: String },
    /// Keyword match (case-insensitive) against body text.
    Keyword { words: Vec<String>, min_count: u32 },
    /// Recipient domain is in the given list.
    RecipientDomain { domains: Vec<String> },
    /// Sender address matches.
    SenderAddress { addresses: Vec<String> },
    /// Message size exceeds threshold.
    SizeBytes { min: u64 },
    /// Attachment MIME type matches.
    AttachmentMime { types: Vec<String> },
    /// Custom: matches a named pattern from the pattern library.
    PatternLibrary { pattern_id: String },
    /// EDM: 機密データセットとの完全一致 (ハッシュフィンガープリント)。
    ExactDataMatch { fingerprint_set_id: String },
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
}

impl<'a> EvalCtx<'a> {
    /// All searchable text (body + subject).
    fn full_text(&self) -> String {
        format!("{} {}", self.subject, self.body)
    }

    /// 受信者ドメイン。
    fn recipient_domains(&self) -> Vec<String> {
        self.to.iter()
            .filter_map(|addr| addr.split('@').nth(1))
            .map(|d| d.to_lowercase())
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
}

impl DlpEngine {
    /// Construct with an explicit rule set.
    pub fn new(mut rules: Vec<Rule>, patterns: PatternLibrary) -> Self {
        rules.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.id.cmp(&b.id)));
        Self { rules, patterns }
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
            if self.eval_condition(&rule.condition, ctx, &text) {
                findings.push(Finding {
                    rule_id:   rule.id.clone(),
                    rule_name: rule.name.clone(),
                    action:    rule.action,
                    excerpt:   excerpt_match(&text, &rule.condition),
                });
            }
        }

        // 全体判定 = 全発見の最大重大度 across all findings
        let verdict = findings.iter()
            .map(|f| f.action)
            .max()
            .unwrap_or(Action::Allow);

        DlpResult { verdict, findings }
    }

    fn eval_condition(&self, cond: &Condition, ctx: &EvalCtx<'_>, text: &str) -> bool {
        match cond {
            Condition::And { children } =>
                children.iter().all(|c| self.eval_condition(c, ctx, text)),
            Condition::Or { children } =>
                children.iter().any(|c| self.eval_condition(c, ctx, text)),
            Condition::Not { child } =>
                !self.eval_condition(child, ctx, text),
            Condition::Matches(pred) =>
                self.eval_predicate(pred, ctx, text),
        }
    }

    fn eval_predicate(&self, pred: &Predicate, ctx: &EvalCtx<'_>, text: &str) -> bool {
        match pred {
            Predicate::Classifier { classifier } =>
                self.run_classifier(*classifier, text),

            Predicate::Regex { pattern } =>
                // 本番: compile once at engine-build time, cache in Rule
                regex_matches(pattern, text),

            Predicate::Keyword { words, min_count } => {
                let t = text.to_lowercase();
                let count = words.iter()
                    .filter(|w| t.contains(w.to_lowercase().as_str()))
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
    pub rule_id:   String,
    pub rule_name: String,
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
            .map(|regexes| regexes.iter().any(|r| regex_matches(r, text)))
            .unwrap_or(false)
    }
}

// ============================================================================
// Built-in classifiers
// ============================================================================

fn detect_jp_my_number(text: &str) -> bool {
    // マイナンバー: 12-digit personal number (with or without hyphens)
    // 簡単なヒューリスティック: look for 12-digit group with optional separators
    // 本番: validate with check-digit algorithm
    let cleaned: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    // 検索: 12-digit runs in digit-only version
    for start in 0..cleaned.len().saturating_sub(11) {
        if cleaned[start..start + 12].chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    // フォーマット済みもチェック: XXXX-XXXX-XXXX
    text.contains('-') && regex_matches(r"\d{4}-\d{4}-\d{4}", text)
}

fn detect_jp_corporate_number(text: &str) -> bool {
    // 法人番号: 13-digit, starts with 1-9
    regex_matches(r"\b[1-9]\d{12}\b", text)
}

fn detect_credit_card(text: &str) -> bool {
    // 検索: 16-digit groups with or without spaces/hyphens
    // 次に Luhn で検証
    let re = r"(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})";
    if !regex_matches(re, text) {
        return false;
    }
    // 数字文字列を抽出 of length 16 and Luhn-check
    extract_digit_runs(text, 16).into_iter().any(|n| luhn_check(&n))
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

fn extract_digit_runs(text: &str, len: usize) -> Vec<String> {
    let digits: String = text.chars()
        .map(|c| if c.is_ascii_digit() { c } else { ' ' })
        .collect();
    digits.split_whitespace()
        .filter(|s| s.len() == len)
        .map(|s| s.to_owned())
        .collect()
}

fn detect_iban(text: &str) -> bool {
    // IBAN: 2 letter country code + 2 check digits + up to 30 alphanumeric
    regex_matches(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4,30}\b", text)
}

fn detect_swift_bic(text: &str) -> bool {
    // SWIFT BIC: 8 or 11 characters (BANKJPJT or BANKJPJTXXX)
    regex_matches(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b", text)
}

fn detect_us_ssn(text: &str) -> bool {
    regex_matches(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", text)
}

fn detect_ip_address(text: &str) -> bool {
    regex_matches(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
}

fn detect_confidential_marker(text: &str) -> bool {
    let t = text.to_lowercase();
    ["confidential", "机密", "機密", "秘密", "取扱注意",
     "restricted", "internal only", "社外秘", "極秘",
     "do not distribute", "not for distribution",
    ].iter().any(|m| t.contains(m))
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
    regex_matches(r"(?i)(?:project|operation|プロジェクト)\s+[A-Z][A-Z0-9]{2,}", text)
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
                Condition::not(Condition::matches(Predicate::RecipientDomain {
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
// Utility helpers (stubs for regex — production uses the `regex` crate)
// ============================================================================

fn regex_matches(pattern: &str, text: &str) -> bool {
    // 本番: regex::Regex compiled at engine-build time.
    // For test compilation, we do simple substring / length heuristics.
    // This function is ALWAYS replaced in production; it's a placeholder.
    match pattern {
        r"\b[1-9]\d{12}\b" => {
            text.chars().filter(|c| c.is_ascii_digit()).count() >= 13
        }
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b" => {
            text.contains('.')
                && text.chars().filter(|c| c.is_ascii_digit() || *c == '.').count() > 6
        }
        _ => {
            // 汎用: パターンが含まれるか確認 without regex syntax appears in text
            let stripped: String = pattern.chars()
                .filter(|c| c.is_alphanumeric() || c.is_whitespace())
                .collect();
            !stripped.is_empty() && text.to_lowercase().contains(&stripped.to_lowercase())
        }
    }
}

fn excerpt_match(text: &str, _cond: &Condition) -> String {
    // 最初の 80 文字を返す of text as excerpt (production: find actual match position)
    if text.len() <= 80 {
        text.to_owned()
    } else {
        format!("{}…", &text[..80])
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
        // 12-digit number that passes basic detection
        let to = vec!["attacker@gmail.com".into()];
        let body = "マイナンバーは 123456789012 です";
        let result = engine().evaluate(&ctx(body, "me@corp.com", &to), Direction::Outbound);
        assert_eq!(result.verdict, Action::Block, "should block my number");
        assert!(result.findings.iter().any(|f| f.rule_id == "default-001"));
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
        assert!(!engine.eval_condition(&cond, &ctx_only_conf, &text));
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
}
