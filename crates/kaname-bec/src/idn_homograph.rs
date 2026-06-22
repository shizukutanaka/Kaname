//! IDN ホモグラフ攻撃検出 (Internationalized Domain Name Homograph Attack)。
//!
//! # 脅威
//!
//! 攻撃者は視覚的に区別困難な Unicode 文字を使い、正規ドメインに見せかけた
//! フィッシングドメインを作成する。
//!
//! 例:
//! - `mіcrosoft.com` (Cyrillic 'і' U+0456 ≠ ASCII 'i')
//! - `xn--mcrsoft-k2d.com` (punycode で "mіcrosoft")
//! - `аmazon.com` (Cyrillic 'а' U+0430 ≠ ASCII 'a')
//!
//! # 防御アプローチ
//!
//! 1. `xn--` で始まる punycode ラベルを検出して警告
//! 2. 複数スクリプト混在 (Latin + Cyrillic/Greek) を検出
//! 3. 高リスクホモグリフ文字リスト (Latin に見える非 Latin 文字) を検出

/// IDN ホモグラフリスク。
#[derive(Debug, Clone, PartialEq)]
pub enum IdnRisk {
    /// punycode エンコードされたラベルを含む (`xn--` プレフィックス)。
    PunycodeLabel {
        /// 問題のあるラベル。
        label: String,
    },
    /// ASCII に見える Unicode 文字 (ホモグリフ) を含む。
    HomoglyphCharacters {
        /// 検出されたホモグリフ文字の一覧。
        chars: Vec<char>,
    },
    /// 複数の Unicode スクリプトが混在している (Latin + Cyrillic 等)。
    MixedScript {
        /// 検出されたスクリプト名の一覧。
        scripts: Vec<&'static str>,
    },
}

impl std::fmt::Display for IdnRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PunycodeLabel { label } =>
                write!(f, "punycode ラベル検出: {label:?}"),
            Self::HomoglyphCharacters { chars } => {
                let s: String = chars.iter().collect();
                write!(f, "ホモグリフ文字検出: {s:?}")
            }
            Self::MixedScript { scripts } =>
                write!(f, "混在スクリプト検出: {}", scripts.join(", ")),
        }
    }
}

/// ドメイン名の IDN ホモグラフリスクを分析する。
///
/// `domain` は `example.com` 形式 (スキームなし)。
#[must_use]
pub fn analyze_domain(domain: &str) -> Vec<IdnRisk> {
    let mut risks = Vec::new();

    // punycode ラベル検出
    for label in domain.split('.') {
        let lower = label.to_ascii_lowercase();
        if lower.starts_with("xn--") {
            risks.push(IdnRisk::PunycodeLabel { label: label.to_string() });
        }
    }

    // ホモグリフ文字検出
    let homoglyphs: Vec<char> = domain.chars().filter(|c| is_homoglyph(*c)).collect();
    if !homoglyphs.is_empty() {
        risks.push(IdnRisk::HomoglyphCharacters { chars: homoglyphs });
    }

    // 混在スクリプト検出
    let scripts = detect_mixed_scripts(domain);
    if scripts.len() >= 2 {
        risks.push(IdnRisk::MixedScript { scripts });
    }

    risks
}

/// IDN ホモグラフのリスクスコアを返す (0.0〜1.0)。
#[must_use]
pub fn idn_risk_score(risks: &[IdnRisk]) -> f32 {
    let mut score: f32 = 0.0;
    for risk in risks {
        score += match risk {
            IdnRisk::PunycodeLabel { .. }      => 0.4,
            IdnRisk::HomoglyphCharacters { .. } => 0.5,
            IdnRisk::MixedScript { .. }         => 0.4,
        };
    }
    score.min(1.0)
}

/// ASCII に見えるが Latin でない文字 (ホモグリフ) かどうかを判定する。
///
/// 代表的な Cyrillic/Greek/Armenian の Latin 類似文字をリストアップ。
/// 完全なリストは Unicode Confusables (https://unicode.org/reports/tr36/) に準拠。
fn is_homoglyph(c: char) -> bool {
    matches!(c,
        // Cyrillic: Latin に酷似
        '\u{0430}' // а (Cyrillic a)
        | '\u{0435}' // е (Cyrillic e)
        | '\u{0456}' // і (Cyrillic і)
        | '\u{043E}' // о (Cyrillic o)
        | '\u{0440}' // р (Cyrillic r)
        | '\u{0441}' // с (Cyrillic c)
        | '\u{0445}' // х (Cyrillic x)
        | '\u{0443}' // у (Cyrillic y)
        | '\u{0455}' // ѕ (Cyrillic dze)
        | '\u{0454}' // є (Cyrillic Ukrainian ie, ≈ є)
        | '\u{0458}' // ј (Cyrillic je ≈ j)
        | '\u{0433}' // г (Cyrillic ghe ≈ r)
        // Greek: Latin に酷似
        | '\u{03BF}' // ο (Greek omicron)
        | '\u{03C1}' // ρ (Greek rho ≈ p/r)
        | '\u{03BD}' // ν (Greek nu ≈ v)
        | '\u{03C9}' // ω (Greek omega ≈ w)
        | '\u{03B1}' // α (Greek alpha ≈ a)
        // Armenian
        | '\u{0585}' // փ (Armenian ≈ q)
        | '\u{0578}' // ո (Armenian ≈ o)
        // Fullwidth Latin (ａ, ｂ 等)
        | '\u{FF01}'..='\u{FF5E}'
        // Latin Extended lookalikes
        | '\u{01A1}' // ơ
        | '\u{0261}' // ɡ (script small g)
    )
}

/// ドメインに含まれる Unicode スクリプトを検出する。
fn detect_mixed_scripts(domain: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    let mut has_latin = false;
    let mut has_cyrillic = false;
    let mut has_greek = false;
    let mut has_armenian = false;

    for c in domain.chars() {
        if c.is_ascii_alphabetic() && !has_latin {
            has_latin = true; found.push("Latin");
        } else if matches!(c, '\u{0400}'..='\u{04FF}') && !has_cyrillic {
            has_cyrillic = true; found.push("Cyrillic");
        } else if matches!(c, '\u{0370}'..='\u{03FF}') && !has_greek {
            has_greek = true; found.push("Greek");
        } else if matches!(c, '\u{0530}'..='\u{058F}') && !has_armenian {
            has_armenian = true; found.push("Armenian");
        }
    }

    found
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_domain_is_clean() {
        let risks = analyze_domain("microsoft.com");
        assert!(risks.is_empty(), "ASCII ドメインはリスクなし: {risks:?}");
    }

    #[test]
    fn punycode_label_detected() {
        let risks = analyze_domain("xn--mcrsoft-k2d.com");
        assert!(
            risks.iter().any(|r| matches!(r, IdnRisk::PunycodeLabel { .. })),
            "xn-- ラベルは検出されるべき"
        );
    }

    #[test]
    fn cyrillic_a_detected_as_homoglyph() {
        // Cyrillic 'а' (U+0430) を含むドメイン
        let domain = "\u{0430}mazon.com";
        let risks = analyze_domain(domain);
        assert!(
            risks.iter().any(|r| matches!(r, IdnRisk::HomoglyphCharacters { .. })),
            "Cyrillic 'а' は ホモグリフとして検出されるべき"
        );
    }

    #[test]
    fn cyrillic_i_detected_as_homoglyph() {
        // Cyrillic 'і' (U+0456)
        let domain = "m\u{0456}crosoft.com";
        let risks = analyze_domain(domain);
        assert!(
            risks.iter().any(|r| matches!(r, IdnRisk::HomoglyphCharacters { .. })),
        );
    }

    #[test]
    fn mixed_script_cyrillic_latin_detected() {
        // Cyrillic 'а' + ASCII 'mazon' = mixed script
        let domain = "\u{0430}mazon.com";
        let risks = analyze_domain(domain);
        assert!(
            risks.iter().any(|r| matches!(r, IdnRisk::MixedScript { .. })),
            "Latin + Cyrillic 混在は MixedScript として検出されるべき"
        );
    }

    #[test]
    fn greek_omicron_detected() {
        // Greek ο (U+03BF)
        let domain = "micr\u{03BF}s\u{03BF}ft.com";
        let risks = analyze_domain(domain);
        assert!(risks.iter().any(|r| matches!(r, IdnRisk::HomoglyphCharacters { .. })));
    }

    #[test]
    fn idn_risk_score_clean() {
        assert_eq!(idn_risk_score(&[]), 0.0);
    }

    #[test]
    fn idn_risk_score_multiple_risks_capped_at_1() {
        let risks = vec![
            IdnRisk::PunycodeLabel { label: "xn--test".to_string() },
            IdnRisk::HomoglyphCharacters { chars: vec!['\u{0430}'] },
            IdnRisk::MixedScript { scripts: vec!["Latin", "Cyrillic"] },
        ];
        assert_eq!(idn_risk_score(&risks), 1.0, "スコアは 1.0 を超えない");
    }

    #[test]
    fn subdomain_punycode_detected() {
        // サブドメインの xn-- も検出
        let risks = analyze_domain("xn--e1afmkfd.example.com");
        assert!(risks.iter().any(|r| matches!(r, IdnRisk::PunycodeLabel { .. })));
    }

    #[test]
    fn display_formats_readable() {
        let risk = IdnRisk::PunycodeLabel { label: "xn--test".to_string() };
        let s = risk.to_string();
        assert!(s.contains("punycode"));
    }

    #[test]
    fn multiple_punycode_labels_detected() {
        // 複数の xn-- ラベル
        let risks = analyze_domain("xn--test.xn--foo.example");
        let punycode_count = risks.iter()
            .filter(|r| matches!(r, IdnRisk::PunycodeLabel { .. }))
            .count();
        assert_eq!(punycode_count, 2, "2 つの xn-- ラベルが検出されるべき");
    }
}
