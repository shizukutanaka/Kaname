//! スレッド乗っ取り (Thread Hijacking) 検出。
//!
//! # 脅威
//!
//! 攻撃者が正規の電子メールスレッドに割り込み、信頼を利用して被害者を騙す手法。
//!
//! ## パターン
//!
//! ### 1. 送信者ドリフト
//! スレッドの途中でドメインが突然変わる。
//! 例: `alice@example.com` → `alice@examp1e.com`
//!
//! ### 2. トピックジャンプ
//! 雑談スレッドに突然「緊急送金」の話題が挿入される。
//!
//! ### 3. 言語切り替え
//! 日本語スレッドに突然英語のみのメールが来る。
//!
//! ### 4. Re: プレフィックス偽装
//! `In-Reply-To` ヘッダーなしで `Re:` 件名を使い、
//! 既存スレッドの参加者を装う。
//!
//! # 使用方法
//!
//! ```rust
//! use kaname_bec::thread_hijack::{ThreadContext, ThreadLanguage, analyze_thread_hijack};
//!
//! let ctx = ThreadContext {
//!     in_reply_to: Some("<abc@example.com>"),
//!     known_thread_message_ids: &["<abc@example.com>".to_string()],
//!     thread_sender_domains: &["example.com".to_string()],
//!     current_sender_domain: "examp1e.com",
//!     prior_subject: Some("週次ミーティングについて"),
//!     current_subject: "Re: 週次ミーティングについて",
//!     prior_language: Some(ThreadLanguage::Japanese),
//!     current_body_snippet: "Please wire $50,000 immediately.",
//! };
//!
//! let result = analyze_thread_hijack(&ctx);
//! assert!(result.risk_score > 0.0);
//! ```

/// スレッドで検出された言語。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadLanguage {
    /// 主に日本語テキスト。
    Japanese,
    /// 主に英語テキスト。
    English,
    /// その他または混在。
    Other,
}

/// スレッドコンテキスト (乗っ取り検出に必要な情報)。
#[derive(Debug)]
pub struct ThreadContext<'a> {
    /// 現メールの In-Reply-To ヘッダー値。
    pub in_reply_to: Option<&'a str>,
    /// ユーザーが実際に送受信した既知のメッセージID一覧。
    pub known_thread_message_ids: &'a [String],
    /// スレッド内でこれまでに見られた送信者ドメイン一覧。
    pub thread_sender_domains: &'a [String],
    /// 現メールの送信者ドメイン。
    pub current_sender_domain: &'a str,
    /// スレッド内の直前の件名 (比較用)。
    pub prior_subject: Option<&'a str>,
    /// 現メールの件名。
    pub current_subject: &'a str,
    /// スレッド内で使われていた主要言語。
    pub prior_language: Option<ThreadLanguage>,
    /// 現メールの本文冒頭 (最初の 500 文字)。
    pub current_body_snippet: &'a str,
}

/// スレッド乗っ取り解析結果。
#[derive(Debug)]
pub struct ThreadHijackResult {
    /// 総合リスクスコア (0.0 = 安全, 1.0 = 確実な乗っ取り)。
    pub risk_score: f32,
    /// 検出されたシグナル一覧。
    pub signals: Vec<ThreadHijackSignal>,
}

/// 検出シグナルの種別。
#[derive(Debug, Clone, PartialEq)]
pub enum ThreadHijackSignal {
    /// In-Reply-To が既知スレッドに存在しないメッセージIDを参照。
    UnknownMessageIdReferenced { message_id: String },
    /// Re: 件名なのに In-Reply-To ヘッダーがない。
    ReplySubjectWithoutInReplyTo,
    /// 送信者ドメインがスレッド内で突然変わった。
    SenderDomainChanged { from: String, to: String },
    /// スレッド内で言語が急変した。
    LanguageShift { from: ThreadLanguage, to: ThreadLanguage },
    /// 返信スレッドに高リスクトピックが突然出現。
    HighRiskTopicInjected { keyword: String },
    /// 件名に Re: が付いているが元件名との一致度が低い。
    SubjectManipulated { similarity: f32 },
}

/// スレッド乗っ取りリスクを解析する。
///
/// # 引数
///
/// - `ctx`: 現メールとスレッドのコンテキスト情報
///
/// # 戻り値
///
/// `ThreadHijackResult` にリスクスコアとシグナル一覧を返す。
#[must_use]
pub fn analyze_thread_hijack(ctx: &ThreadContext<'_>) -> ThreadHijackResult {
    let mut signals = Vec::new();
    let mut score: f32 = 0.0;

    // 1. In-Reply-To 参照チェック
    if let Some(ref_id) = ctx.in_reply_to {
        let ref_id_clean = ref_id.trim();
        // RFC 5322: Message-ID はケースセンシティブだが実装上は大文字小文字を無視して比較
        // (攻撃者が <ABC@example.com> vs 既知 <abc@example.com> でバイパスする手法を防ぐ)
        if !ref_id_clean.is_empty()
            && !ctx.known_thread_message_ids.iter().any(|id| id.eq_ignore_ascii_case(ref_id_clean))
        {
            signals.push(ThreadHijackSignal::UnknownMessageIdReferenced {
                message_id: ref_id_clean.to_string(),
            });
            score += 0.30;
        }
    }

    // 2. Re: 件名 + In-Reply-To なし
    let subject_lower = ctx.current_subject.to_ascii_lowercase();
    let is_reply_subject = subject_lower.starts_with("re:") || subject_lower.starts_with("re：");
    if is_reply_subject && ctx.in_reply_to.is_none() {
        signals.push(ThreadHijackSignal::ReplySubjectWithoutInReplyTo);
        score += 0.25;
    }

    // 3. 送信者ドメイン変化
    if !ctx.thread_sender_domains.is_empty() {
        let current = ctx.current_sender_domain.to_ascii_lowercase();
        let known = ctx
            .thread_sender_domains
            .iter()
            .any(|d| d.to_ascii_lowercase() == current);
        if !known {
            // 最も近いスレッドドメインを探して「変化元」として記録
            let from_domain = ctx
                .thread_sender_domains
                .first()
                .map(String::as_str)
                .unwrap_or("unknown")
                .to_string();
            signals.push(ThreadHijackSignal::SenderDomainChanged {
                from: from_domain,
                to: current,
            });
            score += 0.35;
        }
    }

    // 4. 言語シフト検出
    if let Some(prior_lang) = ctx.prior_language {
        let current_lang = detect_language(ctx.current_body_snippet);
        if prior_lang != current_lang && current_lang != ThreadLanguage::Other {
            signals.push(ThreadHijackSignal::LanguageShift {
                from: prior_lang,
                to: current_lang,
            });
            score += 0.20;
        }
    }

    // 5. 高リスクトピック注入
    if is_reply_subject || ctx.in_reply_to.is_some() {
        if let Some(keyword) = detect_high_risk_keyword(ctx.current_body_snippet) {
            signals.push(ThreadHijackSignal::HighRiskTopicInjected {
                keyword: keyword.to_string(),
            });
            score += 0.25;
        }
    }

    // 6. 件名操作 (Re: プレフィックス付きで元件名との乖離が大きい)
    if is_reply_subject {
        if let Some(prior) = ctx.prior_subject {
            let current_base = strip_reply_prefix(ctx.current_subject);
            let prior_base = strip_reply_prefix(prior);
            let sim = subject_similarity(current_base, prior_base);
            if sim < 0.30 {
                signals.push(ThreadHijackSignal::SubjectManipulated { similarity: sim });
                score += 0.15;
            }
        }
    }

    // スコアを [0, 1] にクランプ
    let risk_score = score.min(1.0);
    ThreadHijackResult { risk_score, signals }
}

/// テキストの主要言語を推定する (簡易ヒューリスティック)。
fn detect_language(text: &str) -> ThreadLanguage {
    let total_chars: usize = text.chars().count();
    if total_chars == 0 {
        return ThreadLanguage::Other;
    }
    let jp_chars: usize = text
        .chars()
        .filter(|&c| {
            // ひらがな: U+3041-U+309F / カタカナ: U+30A0-U+30FF / CJK: U+4E00-U+9FFF
            ('\u{3041}'..='\u{309F}').contains(&c)
                || ('\u{30A0}'..='\u{30FF}').contains(&c)
                || ('\u{4E00}'..='\u{9FFF}').contains(&c)
        })
        .count();
    let ascii_alpha: usize = text.chars().filter(|c| c.is_ascii_alphabetic()).count();

    let jp_ratio = jp_chars as f32 / total_chars as f32;
    let ascii_ratio = ascii_alpha as f32 / total_chars as f32;

    if jp_ratio > 0.15 {
        ThreadLanguage::Japanese
    } else if ascii_ratio > 0.40 {
        ThreadLanguage::English
    } else {
        ThreadLanguage::Other
    }
}

/// 高リスクキーワードを本文から検索する。
fn detect_high_risk_keyword(text: &str) -> Option<&'static str> {
    const HIGH_RISK: &[&str] = &[
        "wire transfer", "bank transfer", "urgent payment", "send money",
        "bitcoin", "cryptocurrency", "wallet address", "gift card",
        "invoice attached", "overdue payment", "immediate action",
        "至急", "緊急", "送金", "振込", "口座番号", "ビットコイン",
        "仮想通貨", "暗号資産", "プレゼントカード",
    ];
    let lower = text.to_ascii_lowercase();
    HIGH_RISK.iter().find(|&&kw| lower.contains(kw)).copied()
}

/// 件名から Re:/Fwd: プレフィックスを除去する。
fn strip_reply_prefix(subject: &str) -> &str {
    let s = subject.trim();
    // ASCII と全角コロン両方を処理
    for prefix in &["re:", "Re:", "RE:", "re：", "Re：", "fw:", "fwd:", "Fwd:"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return rest.trim();
        }
    }
    s
}

/// 2 つの件名の類似度を計算する (単純な語彙重複率)。
///
/// Jaccard 係数を単語セットに適用する。
fn subject_similarity(a: &str, b: &str) -> f32 {
    let a_words: std::collections::HashSet<&str> =
        a.split_whitespace().filter(|w| w.len() > 1).collect();
    let b_words: std::collections::HashSet<&str> =
        b.split_whitespace().filter(|w| w.len() > 1).collect();
    if a_words.is_empty() && b_words.is_empty() {
        return 1.0;
    }
    let intersection = a_words.intersection(&b_words).count();
    let union = a_words.union(&b_words).count();
    if union == 0 {
        return 1.0;
    }
    intersection as f32 / union as f32
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx<'a>(
        in_reply_to: Option<&'a str>,
        known_ids: &'a [String],
        thread_domains: &'a [String],
        current_domain: &'a str,
        prior_subject: Option<&'a str>,
        current_subject: &'a str,
        prior_lang: Option<ThreadLanguage>,
        body: &'a str,
    ) -> ThreadContext<'a> {
        ThreadContext {
            in_reply_to,
            known_thread_message_ids: known_ids,
            thread_sender_domains: thread_domains,
            current_sender_domain: current_domain,
            prior_subject,
            current_subject,
            prior_language: prior_lang,
            current_body_snippet: body,
        }
    }

    #[test]
    fn clean_reply_is_safe() {
        let known_ids = vec!["<abc123@example.com>".to_string()];
        let domains = vec!["example.com".to_string()];
        let ctx = make_ctx(
            Some("<abc123@example.com>"),
            &known_ids,
            &domains,
            "example.com",
            Some("週次ミーティング"),
            "Re: 週次ミーティング",
            Some(ThreadLanguage::Japanese),
            "来週の議事録を確認しました。よろしくお願いします。",
        );
        let r = analyze_thread_hijack(&ctx);
        assert!(r.risk_score < 0.20, "正規返信はスコアが低いべき: {}", r.risk_score);
        assert!(r.signals.is_empty(), "シグナルなしであるべき: {:?}", r.signals);
    }

    #[test]
    fn unknown_message_id_flagged() {
        let known_ids = vec!["<real@example.com>".to_string()];
        let domains = vec!["example.com".to_string()];
        let ctx = make_ctx(
            Some("<forged@attacker.com>"),
            &known_ids,
            &domains,
            "example.com",
            None,
            "Re: 週次レポート",
            None,
            "よろしくお願いします。",
        );
        let r = analyze_thread_hijack(&ctx);
        assert!(
            r.signals.iter().any(|s| matches!(s, ThreadHijackSignal::UnknownMessageIdReferenced { .. })),
            "未知の MessageID はシグナルを発するべき"
        );
        assert!(r.risk_score >= 0.30);
    }

    #[test]
    fn reply_subject_without_in_reply_to_flagged() {
        let known_ids: Vec<String> = vec![];
        let domains = vec!["example.com".to_string()];
        let ctx = make_ctx(
            None, // In-Reply-To なし
            &known_ids,
            &domains,
            "example.com",
            None,
            "Re: 重要なお知らせ",
            None,
            "please confirm.",
        );
        let r = analyze_thread_hijack(&ctx);
        assert!(
            r.signals.contains(&ThreadHijackSignal::ReplySubjectWithoutInReplyTo),
            "In-Reply-To なし Re: はシグナルを発するべき"
        );
    }

    #[test]
    fn sender_domain_change_flagged() {
        let known_ids: Vec<String> = vec![];
        let domains = vec!["example.com".to_string()];
        let ctx = make_ctx(
            None,
            &known_ids,
            &domains,
            "examp1e.com", // タイポスクワット
            None,
            "Re: プロジェクト状況",
            None,
            "通常通りの報告です。",
        );
        let r = analyze_thread_hijack(&ctx);
        assert!(
            r.signals.iter().any(|s| matches!(s, ThreadHijackSignal::SenderDomainChanged { .. })),
            "ドメイン変化はシグナルを発するべき"
        );
        assert!(r.risk_score >= 0.35);
    }

    #[test]
    fn language_shift_flagged() {
        let known_ids: Vec<String> = vec![];
        let domains: Vec<String> = vec![];
        let ctx = make_ctx(
            Some("<abc@example.com>"),
            &known_ids,
            &domains,
            "example.com",
            None,
            "Re: ミーティング",
            Some(ThreadLanguage::Japanese), // 日本語スレッド
            "Please wire $50,000 to the following bank account immediately.", // 英語
        );
        let r = analyze_thread_hijack(&ctx);
        assert!(
            r.signals.iter().any(|s| matches!(s, ThreadHijackSignal::LanguageShift { .. })),
            "言語シフトはシグナルを発するべき"
        );
    }

    #[test]
    fn high_risk_topic_in_reply_flagged() {
        let known_ids = vec!["<abc@example.com>".to_string()];
        let domains = vec!["example.com".to_string()];
        let ctx = make_ctx(
            Some("<abc@example.com>"),
            &known_ids,
            &domains,
            "example.com",
            Some("プロジェクトの進捗"),
            "Re: プロジェクトの進捗",
            Some(ThreadLanguage::Japanese),
            "至急、送金をお願いします。口座番号は以下の通りです。", // 高リスクトピック
        );
        let r = analyze_thread_hijack(&ctx);
        assert!(
            r.signals.iter().any(|s| matches!(s, ThreadHijackSignal::HighRiskTopicInjected { .. })),
            "返信に高リスクトピックが注入された場合はシグナルを発するべき"
        );
    }

    #[test]
    fn subject_manipulation_flagged() {
        let known_ids = vec!["<abc@example.com>".to_string()];
        let domains = vec!["example.com".to_string()];
        let ctx = make_ctx(
            Some("<abc@example.com>"),
            &known_ids,
            &domains,
            "example.com",
            Some("週次ミーティングの日程調整"),
            "Re: 緊急の銀行送金手続きについて", // 元件名と全く無関係
            None,
            "普通のメール本文です。",
        );
        let r = analyze_thread_hijack(&ctx);
        assert!(
            r.signals.iter().any(|s| matches!(s, ThreadHijackSignal::SubjectManipulated { .. })),
            "件名が大きく変化した場合はシグナルを発するべき"
        );
    }

    #[test]
    fn compound_attack_high_score() {
        // 複数シグナルの組み合わせで高スコア
        let known_ids = vec!["<real@example.com>".to_string()];
        let domains = vec!["example.com".to_string()];
        let ctx = make_ctx(
            Some("<forged@attacker.com>"), // 未知 MessageID
            &known_ids,
            &domains,
            "examp1e.com",               // ドメイン変化
            Some("通常業務の報告"),
            "Re: 通常業務の報告",
            Some(ThreadLanguage::Japanese),
            "Please wire transfer $100,000 immediately to account 1234567890.", // 言語シフト + 高リスク
        );
        let r = analyze_thread_hijack(&ctx);
        assert!(r.risk_score >= 0.80, "複合攻撃はリスクスコアが高いべき: {}", r.risk_score);
        assert!(r.signals.len() >= 3, "複数シグナルが検出されるべき: {:?}", r.signals);
    }

    #[test]
    fn detect_language_japanese() {
        assert_eq!(detect_language("こんにちは、お世話になっております。"), ThreadLanguage::Japanese);
    }

    #[test]
    fn detect_language_english() {
        assert_eq!(detect_language("Please send the invoice immediately."), ThreadLanguage::English);
    }

    #[test]
    fn subject_similarity_identical() {
        assert!((subject_similarity("weekly meeting", "weekly meeting") - 1.0).abs() < 0.01);
    }

    #[test]
    fn subject_similarity_unrelated() {
        let sim = subject_similarity("wire transfer urgent", "weekly meeting agenda");
        assert!(sim < 0.10, "無関係な件名の類似度は低いべき: {sim}");
    }

    #[test]
    fn strip_reply_prefix_removes_re() {
        assert_eq!(strip_reply_prefix("Re: hello"), "hello");
        assert_eq!(strip_reply_prefix("re: hello"), "hello");
        assert_eq!(strip_reply_prefix("hello"), "hello");
    }

    #[test]
    fn message_id_case_insensitive_match() {
        // 大文字 MessageID は既知エントリと大文字小文字を無視して照合されるべき
        let known_ids = vec!["<abc123@example.com>".to_string()];
        let domains = vec!["example.com".to_string()];
        let ctx = make_ctx(
            Some("<ABC123@example.com>"), // 大文字バリアント
            &known_ids,
            &domains,
            "example.com",
            None,
            "Re: ミーティング",
            None,
            "よろしくお願いします。",
        );
        let r = analyze_thread_hijack(&ctx);
        // 大文字小文字のみ異なる既知 MessageID は「未知」として扱わない
        assert!(
            !r.signals.iter().any(|s| matches!(s, ThreadHijackSignal::UnknownMessageIdReferenced { .. })),
            "大文字小文字のみ異なる MessageID は既知として扱われるべき: {:?}", r.signals
        );
    }

    #[test]
    fn truly_unknown_message_id_still_flagged() {
        // 完全に異なる MessageID は従来通りフラグを立てる
        let known_ids = vec!["<real@example.com>".to_string()];
        let domains = vec!["example.com".to_string()];
        let ctx = make_ctx(
            Some("<forged@attacker.com>"),
            &known_ids,
            &domains,
            "example.com",
            None,
            "Re: プロジェクト",
            None,
            "よろしく。",
        );
        let r = analyze_thread_hijack(&ctx);
        assert!(
            r.signals.iter().any(|s| matches!(s, ThreadHijackSignal::UnknownMessageIdReferenced { .. })),
            "完全に異なる MessageID は依然としてフラグを立てるべき"
        );
    }
}
