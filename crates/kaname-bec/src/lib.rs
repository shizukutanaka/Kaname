//! kaname-bec — BEC (Business Email Compromise) 多信号検出器。
//!
//! # 検出する信号
//! - Levenshtein 距離によるドメインタイポスクワット
//! - 緊急性マーカー (至急、urgent 等)
//! - 振込先変更パターン
//! - QR フィッシング、VEC、多ペルソナ、メール爆撃
//!
//! # 出力
//! Verdict (Safe / Advisory / Suspicious / Dangerous) + 0..=1 のスコア

// crates/kaname-bec/src/lib.rs
//
// Business Email Compromise (BEC) detector.
//
// Architecture (per ADR-001 + threat-model §3.7):
//   - Runs entirely local; uses the Quarantined LLM (kaname-ai) internally
//   - Combines LLM scoring with static signals (DKIM, SPF, DMARC, domain)
//   - Produces a numeric score 0.0..=1.0 and a structured Risk verdict
//   - Every signal contributes an explanation in the output
//
// Design rule: the detector MUST be explainable. "Black-box ML score: 0.94"
// is not acceptable. Every contribution must be human-readable.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(missing_docs)]

//! # kaname-bec
//!
//! Multi-signal BEC detector. Local-only. Explainable.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Input to the detector
// ============================================================================

/// 1 通の受信メッセージを評価するために必要なデータ。
#[derive(Debug)]
pub struct AssessmentRequest<'a> {
    /// From header (raw, as received). We analyze both display-name and addr.
    pub from_header: &'a str,
    /// Return-path / envelope sender (may differ from From).
    pub return_path: Option<&'a str>,
    /// Subject line.
    pub subject: &'a str,
    /// 抽出された平文本文 (レンダーサンドボックス内の HTML 除去後)。
    pub body_text: &'a str,
    /// Authentication-Results header parsed into a structure.
    pub auth: AuthResults,
    /// Historical context about the purported sender, if we have any.
    pub sender_history: Option<&'a SenderHistory>,
    /// User's own domain (for suggesting homoglyph matches).
    pub our_domain: &'a str,
    /// User's known contact list (for homoglyph comparison).
    pub known_contacts: &'a [String],
}

/// パースされた SPF/DKIM/DMARC の判定。
#[derive(Debug, Clone)]
pub struct AuthResults {
    /// SPF result.
    pub spf: AuthVerdict,
    /// DKIM result.
    pub dkim: AuthVerdict,
    /// DMARC result.
    pub dmarc: AuthVerdict,
    /// ARC chain result if present.
    pub arc: Option<AuthVerdict>,
}

/// 認証の 1 軸。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthVerdict {
    /// Passed.
    Pass,
    /// Failed.
    Fail,
    /// Neutral / softfail.
    Neutral,
    /// Missing header.
    None,
    /// Policy rejected.
    Reject,
}

/// 送信者の過去の知識。
#[derive(Debug, Clone)]
pub struct SenderHistory {
    /// How many messages we've seen from this address.
    pub prior_message_count: u32,
    /// Most recent interaction age in days. None = first contact.
    pub days_since_last: Option<u32>,
    /// Typical topics / entities (used for semantic anomaly detection).
    pub typical_topic_summary: Option<String>,
    /// Has the user previously marked this sender as verified?
    pub user_verified: bool,
}

// ============================================================================
// Output
// ============================================================================

/// メッセージ評価の結果。
#[derive(Debug, Serialize, Deserialize)]
pub struct Assessment {
    /// Overall risk score, 0.0 (safe) .. 1.0 (certain BEC).
    pub score: f32,
    /// Coarse verdict derived from score + signals.
    pub verdict: Verdict,
    /// Ordered list of signals that contributed, most impactful first.
    pub signals: Vec<Signal>,
    /// Total latency of assessment in ms.
    pub latency_ms: u32,
}

/// UI バナーに表示する全体的な判定。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Verdict {
    /// 緑 — 問題なさそう。
    Safe,
    /// 黄 — 確認の価値あり。
    Advisory,
    /// 橙 — 不審。
    Suspicious,
    /// 赤 — 高確度 BEC。UI は返信/転送を無効化。
    Dangerous,
}

/// スコアへの寄与付きの人間可読なシグナル 1 つ。
#[derive(Debug, Serialize, Deserialize)]
pub struct Signal {
    /// Which family of check produced this.
    pub family: SignalFamily,
    /// How much this signal moved the score (positive = more suspicious).
    pub contribution: f32,
    /// Short label shown in UI (under 40 chars).
    pub label: String,
    /// Longer explanation for the detail pane.
    pub rationale: String,
}

/// シグナルファミリー。UI グループ化と分析に使用。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignalFamily {
    /// SPF/DKIM/DMARC results.
    Authentication,
    /// Domain reputation / homoglyph / Levenshtein.
    Domain,
    /// Content analysis (urgency, money, unusual routing).
    Content,
    /// Sender history (new contact, sudden topic shift).
    History,
    /// Attachment-borne signals.
    Attachment,
    /// LLM-based overall assessment.
    Llm,
}

// ============================================================================
// The detector
// ============================================================================

/// Thresholds defining where verdicts fall. Tunable; defaults are conservative.
pub struct Thresholds {
    /// Score ≥ this → Advisory.
    pub advisory: f32,
    /// Score ≥ this → Suspicious.
    pub suspicious: f32,
    /// Score ≥ this → Dangerous.
    pub dangerous: f32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self { advisory: 0.30, suspicious: 0.60, dangerous: 0.85 }
    }
}

/// BEC 検出器。
pub struct BecDetector {
    thresholds: Thresholds,
    // handle to Quarantined LLM — injected for testability
    llm: Box<dyn LocalLlm>,
}

/// Trait for the local LLM used for semantic scoring.
/// Abstracted so we can swap models and mock in tests.
pub trait LocalLlm: Send + Sync {
    /// Score a message for BEC. Must be deterministic given same input.
    fn score_bec(&self, subject: &str, body: &str, context: Option<&str>) -> LlmScore;
}

/// The LLM's output.
#[derive(Debug, Clone)]
pub struct LlmScore {
    /// 0.0..=1.0 probability of BEC.
    pub probability: f32,
    /// Short explanation (≤ 120 chars). Pre-validated to contain no instructions.
    pub explanation: String,
}

impl BecDetector {
    /// Construct with default thresholds.
    pub fn new(llm: Box<dyn LocalLlm>) -> Self {
        Self { thresholds: Thresholds::default(), llm }
    }

    /// Construct with custom thresholds.
    pub fn with_thresholds(llm: Box<dyn LocalLlm>, thresholds: Thresholds) -> Self {
        Self { thresholds, llm }
    }

    /// Assess a message. Runs all signal families and combines.
    pub fn assess(&self, req: AssessmentRequest<'_>) -> Result<Assessment, BecError> {
        let start = std::time::Instant::now();
        let mut signals: Vec<Signal> = Vec::with_capacity(12);

        // --- 1. Authentication signals
        self.check_auth(&req, &mut signals);

        // --- 2. Domain signals (homoglyph, typosquat, freshness)
        self.check_domain(&req, &mut signals);

        // --- 3. History signals
        self.check_history(&req, &mut signals);

        // --- 4. Content signals (simple heuristics, cheap)
        self.check_content_heuristics(&req, &mut signals);

        // --- 5. LLM signal (the expensive one; done last)
        self.check_llm(&req, &mut signals)?;

        // Sort by contribution descending for UI.
        signals.sort_by(|a, b| {
            b.contribution.partial_cmp(&a.contribution).unwrap_or(std::cmp::Ordering::Equal)
        });

        // 結合: clamp the sum. A better approach is logistic regression
        // on calibrated features; this is a conservative v1.
        let raw: f32 = signals.iter().map(|s| s.contribution).sum();
        let score = raw.clamp(0.0, 1.0);

        let verdict = if score >= self.thresholds.dangerous {
            Verdict::Dangerous
        } else if score >= self.thresholds.suspicious {
            Verdict::Suspicious
        } else if score >= self.thresholds.advisory {
            Verdict::Advisory
        } else {
            Verdict::Safe
        };

        Ok(Assessment {
            score,
            verdict,
            signals,
            latency_ms: start.elapsed().as_millis() as u32,
        })
    }

    // --- Signal family implementations ---

    fn check_auth(&self, req: &AssessmentRequest<'_>, signals: &mut Vec<Signal>) {
        let fail_count = [&req.auth.spf, &req.auth.dkim, &req.auth.dmarc]
            .iter()
            .filter(|v| matches!(***v, AuthVerdict::Fail | AuthVerdict::Reject))
            .count();

        if fail_count >= 2 {
            signals.push(Signal {
                family: SignalFamily::Authentication,
                contribution: 0.40,
                label: "認証失敗".to_string(),
                rationale: format!("SPF/DKIM/DMARC のうち {} が失敗", fail_count),
            });
        } else if fail_count == 1 {
            signals.push(Signal {
                family: SignalFamily::Authentication,
                contribution: 0.15,
                label: "認証一部失敗".to_string(),
                rationale: "1 つの認証が失敗".to_string(),
            });
        }

        if let AuthVerdict::Reject = req.auth.dmarc {
            signals.push(Signal {
                family: SignalFamily::Authentication,
                contribution: 0.20,
                label: "DMARC 拒否ポリシー".to_string(),
                rationale: "送信ドメインが DMARC reject を指定".to_string(),
            });
        }
    }

    fn check_domain(&self, req: &AssessmentRequest<'_>, signals: &mut Vec<Signal>) {
        // from_header からドメインを抽出。
        let domain = extract_domain(req.from_header).unwrap_or("");
        if domain.is_empty() {
            return;
        }

        // 自身のドメインと既知の連絡先に対するホモグリフ検出。
        if let Some(lookalike) = homoglyph_match(domain, req.our_domain, req.known_contacts) {
            signals.push(Signal {
                family: SignalFamily::Domain,
                contribution: 0.35,
                label: "類似ドメイン".to_string(),
                rationale: format!("'{}' は '{}' に酷似 (Levenshtein=1)", domain, lookalike),
            });
        }

        // Punycode / IDN.
        if domain.contains("xn--") {
            signals.push(Signal {
                family: SignalFamily::Domain,
                contribution: 0.15,
                label: "IDN ドメイン".to_string(),
                rationale: "Punycode エンコードされた国際化ドメイン。homoglyph の可能性".to_string(),
            });
        }

        // Return-Path 不一致。
        if let Some(rp) = req.return_path {
            let rp_domain = extract_domain(rp).unwrap_or("");
            if !rp_domain.is_empty() && rp_domain != domain {
                signals.push(Signal {
                    family: SignalFamily::Domain,
                    contribution: 0.10,
                    label: "Return-Path 不一致".to_string(),
                    rationale: format!("From={} vs Return-Path={}", domain, rp_domain),
                });
            }
        }
    }

    fn check_history(&self, req: &AssessmentRequest<'_>, signals: &mut Vec<Signal>) {
        match req.sender_history {
            None => {
                signals.push(Signal {
                    family: SignalFamily::History,
                    contribution: 0.05,
                    label: "初回受信".to_string(),
                    rationale: "この差出人からは初めての受信".to_string(),
                });
            }
            Some(h) => {
                if h.prior_message_count >= 5
                    && h.typical_topic_summary.is_some()
                    && contains_unusual_topic(req.subject, h.typical_topic_summary.as_deref().unwrap_or(""))
                {
                    signals.push(Signal {
                        family: SignalFamily::History,
                        contribution: 0.15,
                        label: "話題の急変".to_string(),
                        rationale: "過去の対話パターンから大きく外れた話題".to_string(),
                    });
                }

                if h.user_verified {
                    // マイナス寄与 — リスクを下げる。
                    signals.push(Signal {
                        family: SignalFamily::History,
                        contribution: -0.20,
                        label: "検証済み差出人".to_string(),
                        rationale: "ユーザーが以前この差出人を信頼済みと記録".to_string(),
                    });
                }
            }
        }
    }

    fn check_content_heuristics(&self, req: &AssessmentRequest<'_>, signals: &mut Vec<Signal>) {
        let b = req.body_text.to_lowercase();

        // 緊急性 + 金銭の組み合わせ (典型的な BEC)。
        let urgency_markers = ["urgent", "asap", "至急", "本日中", "今すぐ", "immediately"];
        let money_markers = ["wire", "transfer", "invoice", "送金", "振込", "振り込み", "請求書"];

        let has_urgency = urgency_markers.iter().any(|m| b.contains(m));
        let has_money = money_markers.iter().any(|m| b.contains(m));

        if has_urgency && has_money {
            signals.push(Signal {
                family: SignalFamily::Content,
                contribution: 0.25,
                label: "送金 + 緊急性".to_string(),
                rationale: "送金関連の語と緊急性を示す表現が同時に出現".to_string(),
            });
        }

        // 「電話しないで」/ 経路変更。
        let route_change = [
            "don't call", "do not call",
            "電話しないで", "電話せず",
            "メールでのみ", "メールのみ",
            "change of bank",
            "振込先が変更",
        ];
        if route_change.iter().any(|m| b.contains(m)) {
            signals.push(Signal {
                family: SignalFamily::Content,
                contribution: 0.30,
                label: "連絡経路の強制変更".to_string(),
                rationale: "通常の連絡経路を回避する表現".to_string(),
            });
        }
    }

    fn check_llm(&self, req: &AssessmentRequest<'_>, signals: &mut Vec<Signal>) -> Result<(), BecError> {
        // LLM はコンテンツのみを見る。 It does not see the signals we've
        // already gathered, to keep the dimensions independent.
        let ctx = req
            .sender_history
            .and_then(|h| h.typical_topic_summary.as_deref())
            .map(|s| s.to_string());
        let llm_result = self.llm.score_bec(req.subject, req.body_text, ctx.as_deref());

        // Map LLM probability into a contribution.
        // 0.45 でスケールすることで LLM 単独では Dangerous 領域に達しない。
        let contribution = llm_result.probability * 0.45;

        signals.push(Signal {
            family: SignalFamily::Llm,
            contribution,
            label: format!("AI 意味解析 {:.0}%", llm_result.probability * 100.0),
            rationale: llm_result.explanation,
        });
        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn extract_domain(header: &str) -> Option<&str> {
    // ドメインを抽出: "Name <user@domain.com>" or "user@domain.com".
    let at = header.rfind('@')?;
    let rest = &header[at + 1..];
    let end = rest.find(|c: char| c == '>' || c.is_whitespace()).unwrap_or(rest.len());
    Some(&rest[..end])
}

fn homoglyph_match<'a>(
    domain: &str,
    our_domain: &'a str,
    known_contacts: &'a [String],
) -> Option<&'a str> {
    // 自身のドメインと連絡先ドメインに対する簡易レーベンシュタイン-1 チェック。
    if levenshtein1(domain, our_domain) {
        return Some(our_domain);
    }
    for contact in known_contacts {
        if let Some(contact_domain) = extract_domain(contact) {
            if levenshtein1(domain, contact_domain) && domain != contact_domain {
                // ライフタイムが結びつくよう元のスライスから見つけて返す。
                return known_contacts
                    .iter()
                    .find_map(|c| c.as_str().rsplit('@').next().filter(|d| *d == contact_domain));
            }
        }
    }
    None
}

/// a と b のレーベンシュタイン距離がちょうど 1 の場合 true。
fn levenshtein1(a: &str, b: &str) -> bool {
    let al: Vec<char> = a.chars().collect();
    let bl: Vec<char> = b.chars().collect();
    let diff = (al.len() as isize - bl.len() as isize).abs();
    if diff > 1 {
        return false;
    }
    // 2 つのパス: 同じ長さ (置換)、1 つずれ (挿入/削除)。
    if al.len() == bl.len() {
        let mismatches = al.iter().zip(bl.iter()).filter(|(x, y)| x != y).count();
        return mismatches == 1;
    }
    let (shorter, longer) = if al.len() < bl.len() { (&al, &bl) } else { (&bl, &al) };
    let mut i = 0;
    let mut j = 0;
    let mut used_edit = false;
    while i < shorter.len() && j < longer.len() {
        if shorter[i] == longer[j] {
            i += 1;
            j += 1;
        } else {
            if used_edit {
                return false;
            }
            used_edit = true;
            j += 1;
        }
    }
    true
}

fn contains_unusual_topic(subject: &str, typical: &str) -> bool {
    // スタブ: a production implementation uses embedding distance against
    // the typical_topic_summary.
    let s = subject.to_lowercase();
    let t = typical.to_lowercase();
    s.len() > 0 && t.len() > 0 && !s.split_whitespace().any(|w| t.contains(w))
}

// ============================================================================
// エラー
// ============================================================================

/// エラー from BEC detection.
#[derive(Debug, Error)]
pub enum BecError {
    /// LLM backend failed.
    #[error("llm error: {0}")]
    LlmError(String),
    /// Input malformed.
    #[error("input error: {0}")]
    InputError(String),
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    struct MockLlm { prob: f32, expl: String }
    impl LocalLlm for MockLlm {
        fn score_bec(&self, _subject: &str, _body: &str, _ctx: Option<&str>) -> LlmScore {
            LlmScore { probability: self.prob, explanation: self.expl.clone() }
        }
    }

    fn baseline_auth_all_pass() -> AuthResults {
        AuthResults {
            spf: AuthVerdict::Pass,
            dkim: AuthVerdict::Pass,
            dmarc: AuthVerdict::Pass,
            arc: None,
        }
    }

    fn fail_auth() -> AuthResults {
        AuthResults {
            spf: AuthVerdict::Fail,
            dkim: AuthVerdict::Fail,
            dmarc: AuthVerdict::Fail,
            arc: None,
        }
    }

    #[test]
    fn benign_message_scores_safe() {
        let det = BecDetector::new(Box::new(MockLlm { prob: 0.05, expl: "looks normal".into() }));
        let contacts = vec!["friend@example.com".to_string()];
        let req = AssessmentRequest {
            from_header: "Alice <alice@ally-corp.com>",
            return_path: Some("alice@ally-corp.com"),
            subject: "Coffee next week?",
            body_text: "Hey, free for coffee Tuesday?",
            auth: baseline_auth_all_pass(),
            sender_history: Some(&SenderHistory {
                prior_message_count: 50,
                days_since_last: Some(3),
                typical_topic_summary: Some("coffee meetings scheduling".into()),
                user_verified: true,
            }),
            our_domain: "ally-corp.com",
            known_contacts: &contacts,
        };
        let a = det.assess(req).expect("BEC assessment failed");
        assert_eq!(a.verdict, Verdict::Safe);
    }

    #[test]
    fn classic_bec_scores_dangerous() {
        let det = BecDetector::new(Box::new(MockLlm {
            prob: 0.92,
            expl: "Urgent wire transfer with route change; strong BEC indicators".into(),
        }));
        let contacts = vec!["finance@mitsui-global.co.jp".to_string()];
        let req = AssessmentRequest {
            from_header: "経理部 <accounting@mitsui-g1obal.co.jp>",
            return_path: Some("attacker@evil.com"),
            subject: "【至急】請求書送金のお願い",
            body_text: "本日中に下記口座へ振り込みをお願いします。電話でのご確認は不要です。",
            auth: fail_auth(),
            sender_history: None,
            our_domain: "mitsui-global.co.jp",
            known_contacts: &contacts,
        };
        let a = det.assess(req).expect("BEC assessment failed");
        assert_eq!(a.verdict, Verdict::Dangerous, "score={}, signals={:?}", a.score, a.signals);
        assert!(a.signals.iter().any(|s| s.family == SignalFamily::Domain));
        assert!(a.signals.iter().any(|s| s.family == SignalFamily::Authentication));
        assert!(a.signals.iter().any(|s| s.family == SignalFamily::Content));
    }

    #[test]
    fn homoglyph_match_detects_single_char_diff() {
        assert!(levenshtein1("mitsui-g1obal.co.jp", "mitsui-global.co.jp"));
        assert!(levenshtein1("paypa1.com", "paypal.com"));
        assert!(!levenshtein1("example.com", "example.com"));  // identical
        assert!(!levenshtein1("a", "abc"));                     // distance 2
    }

    #[test]
    fn extract_domain_handles_formats() {
        assert_eq!(extract_domain("alice@example.com"), Some("example.com"));
        assert_eq!(extract_domain("Alice <alice@example.com>"), Some("example.com"));
        assert_eq!(extract_domain("no at sign"), None);
    }
}

pub mod aitm;
