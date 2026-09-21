//! kaname-memory-guard — テキスト正規化ユーティリティ。
//!
//! 元々は arxiv 2601.05504「Memory Poisoning Attack and Defense」の
//! メモリ信頼スコア・サニタイズを実装するクレートだったが、製品に
//! エージェントメモリの基盤が存在せず TrustScorer/MemorySanitizer は
//! 呼出元ゼロだったため削除した (D142 — git 履歴で復元可能)。
//! 現行の実体は `normalize_for_matching` / `normalize_for_matching_spaced`
//! の回避対策正規化のみで、kaname-bec / kaname-oobv / kaname-ui が利用する。

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

// ============================================================================
// 正規化ユーティリティ (回避対策)
// ============================================================================

/// 注入パターン照合用にテキストを正規化する。
///
/// `to_lowercase().contains()` は全角 Unicode やゼロ幅文字による回避に弱い。
/// 全角 ASCII を ASCII に折り返し、全角空白を半角に、ゼロ幅/フォーマット文字を
/// 除去したうえで小文字化する。
///
/// キーワード照合の前処理として他クレート (`kaname-oobv` 等) からも再利用できる
/// よう公開している。全角ラテン文字やゼロ幅文字挿入によるキーワード回避
/// (例: `ＵＲＧＥＮＴ`、`urg\u{200B}ent`) を防ぐ共通の入口正規化。
#[must_use]
pub fn normalize_for_matching(s: &str) -> String {
    s.chars()
        .filter_map(|c| {
            if is_zero_width_or_format(c) {
                return None;
            }
            // 全角 ASCII (U+FF01..=U+FF5E) → ASCII (U+0021..=U+007E)
            if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
                return char::from_u32(c as u32 - 0xFEE0).or(Some(c));
            }
            // 全角スペース (U+3000) → 半角スペース
            if c == '\u{3000}' {
                return Some(' ');
            }
            Some(c)
        })
        .collect::<String>()
        .to_lowercase()
}

/// `normalize_for_matching` の語境界保持版。
///
/// `normalize_for_matching` はゼロ幅/フォーマット文字を**削除**するため、
/// 単語内挿入回避 (`urg\u{200B}ent`) には有効だが、複数単語キーワードの
/// **単語間**にゼロ幅文字を挿入する回避 (`wire\u{200B}transfer`) には
/// 逆効果になる — 削除により `wiretransfer` に結合され、スペース区切りを
/// 前提とするフレーズの部分一致が成立しなくなる (docs/gap-analysis.md D45)。
///
/// 本関数はゼロ幅/フォーマット文字を**削除せず単一スペースに置換**し、
/// 連続する空白を1つに畳み込む。複数単語キーワードを照合する呼び出し側は
/// `normalize_for_matching` (削除版) と本関数 (スペース化版) の両方で照合
/// すること (単語内挿入は削除版、単語間挿入はスペース化版がそれぞれ捕捉)。
#[must_use]
pub fn normalize_for_matching_spaced(s: &str) -> String {
    let replaced: String = s
        .chars()
        .map(|c| {
            if is_zero_width_or_format(c) {
                return ' ';
            }
            // 全角 ASCII (U+FF01..=U+FF5E) → ASCII (U+0021..=U+007E)
            if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
                return char::from_u32(c as u32 - 0xFEE0).unwrap_or(c);
            }
            // 全角スペース (U+3000) → 半角スペース
            if c == '\u{3000}' {
                return ' ';
            }
            c
        })
        .collect();
    replaced
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// ゼロ幅・フォーマット文字 (回避に悪用される不可視文字) を判定する。
fn is_zero_width_or_format(c: char) -> bool {
    matches!(c,
        '\u{00AD}'                // Soft Hyphen
        | '\u{200B}'..='\u{200F}' // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | '\u{202A}'..='\u{202E}' // BiDi embedding/override
        | '\u{2060}'..='\u{2064}' // Word Joiner, 不可視演算子
        | '\u{2066}'..='\u{2069}' // BiDi isolate
        | '\u{FEFF}'              // BOM / ZWNBSP
    )
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn normalize_for_matching_folds_fullwidth_and_strips_zero_width() {
        assert_eq!(normalize_for_matching("ＡＬＷＡＹＳ"), "always");
        assert_eq!(
            normalize_for_matching("always\u{200B}recommend"),
            "alwaysrecommend"
        );
        assert_eq!(normalize_for_matching("Ａ\u{3000}Ｂ"), "a b");
    }

    #[test]
    fn spaced_normalization_restores_word_boundaries() {
        // D45: ゼロ幅文字を単語区切りとして使う回避は、スペース化版で
        // 語境界を復元して捕捉する。
        assert_eq!(
            normalize_for_matching_spaced("wire\u{200B}transfer"),
            "wire transfer"
        );
        assert_eq!(
            normalize_for_matching_spaced("always\u{200B}recommend"),
            "always recommend"
        );
        assert_eq!(
            normalize_for_matching_spaced("ＡＬＷＡＹＳ\u{200B}ＲＥＣＯＭＭＥＮＤ"),
            "always recommend"
        );
        assert_eq!(normalize_for_matching_spaced("a\u{200B}\u{200B}  b"), "a b");
    }
}
