//! DKIM 署名ヘッダの安全性チェック。
//!
//! # 攻撃クラス
//!
//! ## DKIM `l=` タグ濫用 (DKIM Length Limit Tag Abuse)
//!
//! RFC 6376 §3.5 で定義される `l=` タグは「本文の先頭 N バイトのみを署名対象とする」
//! という意味を持つ。つまり攻撃者は署名済みメールの本文末尾に任意のテキストを追加
//! しても DKIM 署名は有効なまま維持できる。
//!
//! 攻撃シナリオ:
//! 1. 正規送信者が `l=200; ...` 付きで本文 200B を署名して送信
//! 2. メーリングリスト or 攻撃者がメールを中継
//! 3. 本文末尾に `<br>\n振込先を変更しました: 9999-9999` を追加
//! 4. DKIM 検証は通過 → 受信者は正規メールと信じる
//!
//! ## DKIM Replay Attack
//!
//! Google OAuth フィッシング (2024-2025 で多発) のように、攻撃者は正規署名済み
//! メールを取得し、同じ署名のまま大量配布する手法。同一 `b=` (署名値) を
//! 短期間に複数回受信した場合に検出する。
//!
//! 出典:
//! - innovatopia (2025): <https://innovatopia.jp/cyber-security/cyber-security-news/52148/>
//! - zenn (suyasuya): <https://zenn.dev/suyasuya/articles/07c87cf8153eef>

/// DKIM-Signature ヘッダ値の解析結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimHeaderAnalysis {
    /// `l=` タグが存在するか (本文長制限による追記攻撃のリスク)。
    pub has_length_tag: bool,
    /// `l=` の値 (バイト数)。
    pub length_value: Option<u64>,
    /// ドメイン (`d=` タグ)。
    pub domain: Option<String>,
    /// セレクタ (`s=` タグ)。
    pub selector: Option<String>,
    /// 署名値 (`b=` タグ) の先頭 32 文字 (リプレイ追跡用)。
    pub signature_prefix: Option<String>,
}

impl DkimHeaderAnalysis {
    /// 本ヘッダがリスクを内包しているか。
    #[must_use]
    pub fn is_risky(&self) -> bool {
        self.has_length_tag
    }
}

/// DKIM-Signature ヘッダ値をパースする。
///
/// 入力例: `v=1; a=rsa-sha256; d=example.com; s=sel; l=2048; b=ABC...`
#[must_use]
pub fn analyze_dkim_header(header_value: &str) -> DkimHeaderAnalysis {
    let mut has_length_tag = false;
    let mut length_value = None;
    let mut domain = None;
    let mut selector = None;
    let mut signature_prefix = None;

    for raw_part in header_value.split(';') {
        let part = raw_part.trim();
        let Some((k, v)) = part.split_once('=') else { continue };
        let k = k.trim();
        let v = v.trim();
        match k {
            "l" => {
                has_length_tag = true;
                length_value = v.parse::<u64>().ok();
            }
            "d" => domain = Some(v.to_string()),
            "s" => selector = Some(v.to_string()),
            "b" => {
                // 署名値は途中で改行・空白を含む可能性 → 連結して先頭 32 文字
                let cleaned: String = v.chars()
                    .filter(|c| !c.is_whitespace())
                    .take(32)
                    .collect();
                if !cleaned.is_empty() {
                    signature_prefix = Some(cleaned);
                }
            }
            _ => {}
        }
    }

    DkimHeaderAnalysis {
        has_length_tag,
        length_value,
        domain,
        selector,
        signature_prefix,
    }
}

/// DKIM 署名のリプレイカウンタ。
///
/// 同一 `(domain, signature_prefix)` を短時間に複数回受信したら警告する。
/// インメモリ実装 — 本番では Redis 等で永続化推奨。
#[derive(Debug, Default)]
pub struct DkimReplayTracker {
    seen: std::collections::HashMap<(String, String), u32>,
}

impl DkimReplayTracker {
    /// 新規トラッカー。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 観測した署名を記録し、これが何回目の出現か返す。
    /// 戻り値 >= 2 はリプレイの兆候。
    pub fn observe(&mut self, analysis: &DkimHeaderAnalysis) -> u32 {
        let (Some(d), Some(b)) = (&analysis.domain, &analysis.signature_prefix) else {
            return 1;
        };
        let key = (d.clone(), b.clone());
        let count = self.seen.entry(key).or_insert(0);
        *count = count.saturating_add(1);
        *count
    }

    /// 観測数 (テスト用)。
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// 空判定。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_dkim_header() {
        let h = "v=1; a=rsa-sha256; d=example.com; s=sel1; b=AbCdEfGh1234567890XYZ==";
        let a = analyze_dkim_header(h);
        assert_eq!(a.domain.as_deref(), Some("example.com"));
        assert_eq!(a.selector.as_deref(), Some("sel1"));
        assert!(!a.has_length_tag);
        assert!(!a.is_risky());
    }

    #[test]
    fn detects_length_tag() {
        let h = "v=1; a=rsa-sha256; d=evil.com; s=s; l=2048; b=AAAA";
        let a = analyze_dkim_header(h);
        assert!(a.has_length_tag,
            "l= タグが検出されていない");
        assert_eq!(a.length_value, Some(2048));
        assert!(a.is_risky(), "l= 付きはリスクと判定すべき");
    }

    #[test]
    fn signature_prefix_strips_whitespace() {
        // 実際の DKIM 署名は折り返しで空白を含む
        let h = "d=ex.com; b=AbCd Ef\n  Gh12 34;";
        let a = analyze_dkim_header(h);
        assert_eq!(a.signature_prefix.as_deref(), Some("AbCdEfGh1234"),
            "署名から空白・改行を除去すべき");
    }

    #[test]
    fn replay_tracker_counts_repeats() {
        let mut t = DkimReplayTracker::new();
        let h = "d=example.com; b=ABC123";
        let a = analyze_dkim_header(h);

        assert_eq!(t.observe(&a), 1, "初回観測");
        assert_eq!(t.observe(&a), 2, "2 回目 → リプレイ兆候");
        assert_eq!(t.observe(&a), 3, "3 回目");
    }

    #[test]
    fn replay_tracker_distinguishes_signatures() {
        let mut t = DkimReplayTracker::new();
        let a1 = analyze_dkim_header("d=ex.com; b=AAA");
        let a2 = analyze_dkim_header("d=ex.com; b=BBB");
        assert_eq!(t.observe(&a1), 1);
        assert_eq!(t.observe(&a2), 1, "別署名は別カウント");
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn replay_tracker_ignores_incomplete_signatures() {
        let mut t = DkimReplayTracker::new();
        let a = analyze_dkim_header("v=1; a=rsa");
        // domain も signature_prefix もない → トラッキング不可
        assert_eq!(t.observe(&a), 1);
        assert!(t.is_empty(),
            "domain/b 不完全な署名は記録しない");
    }

    #[test]
    fn malformed_l_tag_is_safe() {
        // l= の値が数値でない場合
        let h = "d=ex.com; l=abc; b=XYZ";
        let a = analyze_dkim_header(h);
        assert!(a.has_length_tag, "タグ存在は検出");
        assert_eq!(a.length_value, None, "数値でない値は None");
    }
}
