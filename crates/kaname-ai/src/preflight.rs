//! 入力プリフライト検査。
//!
//! `kaname-screen` の `PromptScreener` を Dual-LLM パイプラインに統合する薄いラッパー。
//! Untrusted コンテンツを Q-LLM に渡す前に呼び出す。

use kaname_screen::{PromptScreener, ScreenRisk, ScreenVerdict};

use crate::dual_llm::{Content, Untrusted};

/// プリフライト検査で検出された問題。
#[derive(Debug, Clone)]
pub enum Finding {
    /// 命令上書きフレーズ。
    OverridePhrase(String),
    /// 疑わしい URL。
    SuspiciousUrl(String),
    /// 高エントロピー文字列 (難読化の兆候)。
    HighEntropy(f32),
    /// 特殊トークン注入。
    SpecialToken(String),
    /// 既知のプロンプトインジェクションパターン。
    KnownInjectionPattern(String),
    /// Bidi 制御文字によるテキスト偽装。
    BidiOverride,
    /// BOM・ゼロ幅文字による難読化。
    ZeroWidthSeparator,
}

/// プリフライト検査の結果。
#[derive(Debug, Clone)]
pub enum PreflightResult {
    /// 問題なし。処理を続行してよい。
    Clean,
    /// 注意が必要だが処理を続行する (ログのみ)。
    Advisory(Vec<Finding>),
    /// ブロック。Q-LLM に渡してはいけない。
    Block(Vec<Finding>),
}

/// Bidi 制御文字 (テキスト偽装に使われる Unicode)。
const BIDI_OVERRIDE_CHARS: &[char] = &[
    '\u{202A}', // LEFT-TO-RIGHT EMBEDDING
    '\u{202B}', // RIGHT-TO-LEFT EMBEDDING
    '\u{202C}', // POP DIRECTIONAL FORMATTING
    '\u{202D}', // LEFT-TO-RIGHT OVERRIDE
    '\u{202E}', // RIGHT-TO-LEFT OVERRIDE
    '\u{2066}', // LEFT-TO-RIGHT ISOLATE
    '\u{2067}', // RIGHT-TO-LEFT ISOLATE
    '\u{2068}', // FIRST STRONG ISOLATE
    '\u{2069}', // POP DIRECTIONAL ISOLATE
];

fn screen_risk_to_finding(r: &ScreenRisk) -> Finding {
    match r {
        // OverridePhrase はプロンプトインジェクションパターンとして再分類
        ScreenRisk::OverridePhrase(s) => Finding::KnownInjectionPattern(s.clone()),
        ScreenRisk::SuspiciousUrl(s) => Finding::SuspiciousUrl(s.clone()),
        ScreenRisk::HighEntropy(f) => Finding::HighEntropy(*f),
        ScreenRisk::SpecialToken(s) => Finding::SpecialToken(s.clone()),
        // 新規追加パターン (P3 絵文字区切り / Base64 / Unicode タグ) は
        // すべて高リスクの注入として KnownInjectionPattern にマップ
        ScreenRisk::EmojiSeparatedInjection(s)
        | ScreenRisk::Base64EncodedInstruction(s)
        | ScreenRisk::UnicodeTagInjection(s) => Finding::KnownInjectionPattern(s.clone()),
    }
}

/// Untrusted コンテンツをプリフライト検査する。
///
/// Q-LLM に渡す前に必ず呼び出すこと (CLAUDE.md I1)。
#[must_use]
pub fn preflight_untrusted(content: &Content<Untrusted>) -> PreflightResult {
    let text = content.as_text();
    let screener = PromptScreener::new();
    let result = screener.screen(text);
    let mut findings: Vec<Finding> = result.risks.iter().map(screen_risk_to_finding).collect();

    // Bidi 制御文字検出
    if text.chars().any(|c| BIDI_OVERRIDE_CHARS.contains(&c)) {
        findings.push(Finding::BidiOverride);
    }

    // BOM・ゼロ幅文字検出
    let zero_width = ['\u{FEFF}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}'];
    if text.chars().any(|c| zero_width.contains(&c)) {
        findings.push(Finding::ZeroWidthSeparator);
    }

    // 判定: Bidi/BOM は Block、それ以外は kaname-screen の verdict に従う
    let has_bidi = findings.iter().any(|f| matches!(f, Finding::BidiOverride));
    let has_injection = findings.iter().any(|f| matches!(
        f, Finding::KnownInjectionPattern(_) | Finding::SpecialToken(_)
    ));
    if findings.is_empty() {
        PreflightResult::Clean
    } else if has_bidi || has_injection || matches!(result.verdict, ScreenVerdict::Blocked) {
        PreflightResult::Block(findings)
    } else {
        PreflightResult::Advisory(findings)
    }
}
