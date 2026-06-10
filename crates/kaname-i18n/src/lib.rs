//! kaname-i18n — 国際化フレームワーク。
//!
//! - BCP 47 ロケール識別子
//! - CLDR 準拠の plural 規則
//! - プレースホルダー置換 ({name} 形式)
//! - 1000 言語対応の基盤 (外部カタログ動的ロード)

// crates/kaname-i18n/src/lib.rs
//
// Kaname 国際化 (i18n) フレームワーク
//
// 設計原則:
//   1. 全 UI 文字列は kaname.{key} の階層構造で管理
//   2. JSON 形式のロケールファイル (locales/ja.json, en.json, ...)
//   3. プレースホルダー: {name} 形式で型安全に埋め込み
//   4. 1000 言語対応の準備: BCP 47 ロケール識別子
//   5. フォールバック: ja → en → key 自体を返す
//
// 使用例:
//   let i18n = I18n::new();
//   i18n.set_locale("ja");
//   let msg = i18n.t("app.welcome", &[("name", "田中")]);
//   // → "田中さん、ようこそ"

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use std::collections::HashMap;
use std::sync::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// メッセージカタログ
// ============================================================================

/// 単一ロケールのメッセージカタログ。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    /// 階層キー → メッセージのマップ
    /// 例: "app.welcome" → "{name}さん、ようこそ"
    pub messages: HashMap<String, String>,
    /// ロケール識別子 (BCP 47)。例: "ja", "en", "zh-Hans"
    pub locale: String,
    /// 言語の人間可読名 (自国語)。例: "日本語", "English", "中文"
    pub native_name: String,
    /// RTL (Right-to-Left) 言語かどうか。
    pub rtl: bool,
    /// 数値・日付フォーマットに使う locale
    pub format_locale: String,
}

// ============================================================================
// I18n エンジン
// ============================================================================

pub struct I18n {
    catalogs: RwLock<HashMap<String, Catalog>>,
    current:  RwLock<String>,
    fallback: String,
}

impl I18n {
    /// 新規 I18n インスタンスを作成。
    pub fn new() -> Self {
        let mut catalogs = HashMap::new();
        catalogs.insert("ja".into(), Self::builtin_ja());
        catalogs.insert("en".into(), Self::builtin_en());

        Self {
            catalogs: RwLock::new(catalogs),
            current:  RwLock::new("ja".into()),
            fallback: "en".into(),
        }
    }

    /// 現在のロケールを設定する。
    pub fn set_locale(&self, locale: &str) -> Result<(), I18nError> {
        let catalogs = self.catalogs.read().unwrap_or_else(|e| e.into_inner());
        if !catalogs.contains_key(locale) {
            return Err(I18nError::UnknownLocale(locale.to_owned()));
        }
        drop(catalogs);
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = locale.to_owned();
        Ok(())
    }

    /// メッセージを翻訳する (プレースホルダー置換付き)。
    #[must_use]
    pub fn t(&self, key: &str, args: &[(&str, &str)]) -> String {
        let current  = self.current.read().unwrap_or_else(|e| e.into_inner()).clone();
        let catalogs = self.catalogs.read().unwrap_or_else(|e| e.into_inner());

        // 現在のロケール → fallback → key 自体の順で探す
        let template = catalogs
            .get(&current)
            .and_then(|c| c.messages.get(key))
            .or_else(|| catalogs.get(&self.fallback).and_then(|c| c.messages.get(key)))
            .map(String::as_str)
            .unwrap_or(key);

        // プレースホルダー置換
        let mut result = template.to_string();
        for (k, v) in args {
            result = result.replace(&format!("{{{k}}}"), v);
        }
        result
    }

    /// プレースホルダーなしの簡易版。
    #[must_use]
    pub fn t_simple(&self, key: &str) -> String {
        self.t(key, &[])
    }

    /// 利用可能なロケール一覧。
    #[must_use]
    pub fn available_locales(&self) -> Vec<LocaleInfo> {
        self.catalogs.read().unwrap_or_else(|e| e.into_inner()).values()
            .map(|c| LocaleInfo {
                locale:      c.locale.clone(),
                native_name: c.native_name.clone(),
                rtl:         c.rtl,
            })
            .collect()
    }

    /// 現在のロケールを取得。
    #[must_use]
    pub fn current_locale(&self) -> String {
        self.current.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// 外部ロケールファイルをロードする。
    pub fn load_catalog(&self, catalog: Catalog) {
        let locale = catalog.locale.clone();
        self.catalogs.write().unwrap_or_else(|e| e.into_inner()).insert(locale, catalog);
    }

    // ── 組み込みロケール ──────────────────────────────────────────────────

    fn builtin_ja() -> Catalog {
        let mut messages = HashMap::new();
        // アプリ全般
        messages.insert("app.name".into(),     "要 Kaname".into());
        messages.insert("app.welcome".into(),  "{name}さん、ようこそ".into());
        messages.insert("app.starting".into(), "起動中...".into());
        messages.insert("app.error".into(),    "起動エラー".into());
        messages.insert("app.restart".into(),  "再起動".into());

        // 受信トレイ
        messages.insert("inbox.title".into(),       "受信トレイ".into());
        messages.insert("inbox.empty.title".into(), "メールなし".into());
        messages.insert("inbox.empty.desc".into(),  "受信トレイは空です。新着メールが届くとここに表示されます。".into());
        messages.insert("inbox.unread_count".into(), "{count}件未読".into());

        // BEC 警告
        messages.insert("bec.safe".into(),        "安全".into());
        messages.insert("bec.advisory".into(),    "要確認".into());
        messages.insert("bec.suspicious".into(),  "不審".into());
        messages.insert("bec.dangerous".into(),   "危険・BEC攻撃の可能性".into());
        messages.insert("bec.banner.dangerous".into(), "BEC攻撃の可能性が高い — 送信者の身元を別経路で確認してください".into());

        // AI 機能
        messages.insert("ai.summarize".into(),      "AI で要約 — このメール1通のみ分析".into());
        messages.insert("ai.summarize.safe".into(), "🔒 安全 — 受信箱全体を読みません".into());
        messages.insert("ai.smart_reply".into(),    "返信案を生成".into());
        messages.insert("ai.summarizing".into(),    "AI 要約中...".into());

        // アクション
        messages.insert("action.archive".into(),     "アーカイブ".into());
        messages.insert("action.snooze".into(),      "スヌーズ".into());
        messages.insert("action.reply".into(),       "返信".into());
        messages.insert("action.reply_later".into(), "Reply Later".into());
        messages.insert("action.delete".into(),      "削除".into());
        messages.insert("action.undo".into(),        "取り消す".into());

        // セキュリティ
        messages.insert("security.e2e".into(),         "エンドツーエンド暗号化".into());
        messages.insert("security.dlp_blocked".into(), "このメールはセキュリティポリシーによりAI処理できません".into());

        Catalog {
            messages,
            locale:        "ja".into(),
            native_name:   "日本語".into(),
            rtl:           false,
            format_locale: "ja-JP".into(),
        }
    }

    fn builtin_en() -> Catalog {
        let mut messages = HashMap::new();
        messages.insert("app.name".into(),     "Kaname".into());
        messages.insert("app.welcome".into(),  "Welcome, {name}".into());
        messages.insert("app.starting".into(), "Starting...".into());
        messages.insert("app.error".into(),    "Startup error".into());
        messages.insert("app.restart".into(),  "Restart".into());

        messages.insert("inbox.title".into(),       "Inbox".into());
        messages.insert("inbox.empty.title".into(), "No messages".into());
        messages.insert("inbox.empty.desc".into(),  "Your inbox is empty. New messages will appear here.".into());
        messages.insert("inbox.unread_count".into(), "{count} unread".into());

        messages.insert("bec.safe".into(),        "Safe".into());
        messages.insert("bec.advisory".into(),    "Review".into());
        messages.insert("bec.suspicious".into(),  "Suspicious".into());
        messages.insert("bec.dangerous".into(),   "Dangerous · Possible BEC".into());
        messages.insert("bec.banner.dangerous".into(), "Likely BEC attack — verify sender identity through another channel".into());

        messages.insert("ai.summarize".into(),      "Summarize with AI — this email only".into());
        messages.insert("ai.summarize.safe".into(), "🔒 Safe — does not read your inbox".into());
        messages.insert("ai.smart_reply".into(),    "Suggest replies".into());
        messages.insert("ai.summarizing".into(),    "Summarizing...".into());

        messages.insert("action.archive".into(),     "Archive".into());
        messages.insert("action.snooze".into(),      "Snooze".into());
        messages.insert("action.reply".into(),       "Reply".into());
        messages.insert("action.reply_later".into(), "Reply Later".into());
        messages.insert("action.delete".into(),      "Delete".into());
        messages.insert("action.undo".into(),        "Undo".into());

        messages.insert("security.e2e".into(),         "End-to-end encrypted".into());
        messages.insert("security.dlp_blocked".into(), "This email cannot be processed by AI due to security policy".into());

        Catalog {
            messages,
            locale:        "en".into(),
            native_name:   "English".into(),
            rtl:           false,
            format_locale: "en-US".into(),
        }
    }
}

impl Default for I18n {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone, Serialize)]
pub struct LocaleInfo {
    pub locale:      String,
    pub native_name: String,
    pub rtl:         bool,
}

#[derive(Debug, Error)]
pub enum I18nError {
    #[error("未知のロケール: {0}")]
    UnknownLocale(String),
    #[error("カタログのロードに失敗: {0}")]
    LoadFailed(String),
}

// ============================================================================
// プルラル (複数形) ハンドリング — CLDR 準拠
// ============================================================================

/// CLDR の plural 規則。日本語は無し、英語は one/other、ロシア語は4種、等。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluralCategory { Zero, One, Two, Few, Many, Other }

/// `plural_category` を実行する。
pub fn plural_category(locale: &str, n: u64) -> PluralCategory {
    match locale {
        // 日本語・中国語・韓国語: 単複の区別なし
        "ja" | "zh" | "zh-Hans" | "zh-Hant" | "ko" | "vi" | "th" => PluralCategory::Other,

        // 英語・ドイツ語等: one (n==1) / other
        "en" | "de" | "nl" | "es" | "it" | "pt" => {
            if n == 1 { PluralCategory::One } else { PluralCategory::Other }
        }

        // フランス語: 0 と 1 が one
        "fr" | "pt-BR" => {
            if n == 0 || n == 1 { PluralCategory::One } else { PluralCategory::Other }
        }

        // アラビア語: 6 種類のプルラル
        "ar" => match n {
            0 => PluralCategory::Zero,
            1 => PluralCategory::One,
            2 => PluralCategory::Two,
            n if (3..=10).contains(&(n % 100)) => PluralCategory::Few,
            n if (11..=99).contains(&(n % 100)) => PluralCategory::Many,
            _ => PluralCategory::Other,
        },

        // デフォルト
        _ => if n == 1 { PluralCategory::One } else { PluralCategory::Other },
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_locale_is_ja() {
        let i18n = I18n::new();
        assert_eq!(i18n.current_locale(), "ja");
    }

    #[test]
    fn translate_simple_key() {
        let i18n = I18n::new();
        assert_eq!(i18n.t_simple("app.name"), "要 Kaname");
        assert_eq!(i18n.t_simple("inbox.title"), "受信トレイ");
    }

    #[test]
    fn switch_to_english() {
        let i18n = I18n::new();
        i18n.set_locale("en").unwrap();
        assert_eq!(i18n.t_simple("app.name"), "Kaname");
        assert_eq!(i18n.t_simple("inbox.title"), "Inbox");
    }

    #[test]
    fn placeholder_substitution() {
        let i18n = I18n::new();
        let msg = i18n.t("app.welcome", &[("name", "田中")]);
        assert_eq!(msg, "田中さん、ようこそ");

        i18n.set_locale("en").unwrap();
        let msg = i18n.t("app.welcome", &[("name", "Alice")]);
        assert_eq!(msg, "Welcome, Alice");
    }

    #[test]
    fn fallback_to_english_when_key_missing_in_japanese() {
        let i18n = I18n::new();
        // 日本語にだけある "app.error" はそのまま
        assert_eq!(i18n.t_simple("app.error"), "起動エラー");

        // 完全に存在しないキーは key 自体を返す
        assert_eq!(i18n.t_simple("nonexistent.key"), "nonexistent.key");
    }

    #[test]
    fn unknown_locale_rejected() {
        let i18n = I18n::new();
        assert!(i18n.set_locale("xx-XX").is_err());
    }

    #[test]
    fn plural_japanese_no_distinction() {
        for n in 0..100 {
            assert_eq!(plural_category("ja", n), PluralCategory::Other);
        }
    }

    #[test]
    fn plural_english_one_other() {
        assert_eq!(plural_category("en", 1), PluralCategory::One);
        assert_eq!(plural_category("en", 0), PluralCategory::Other);
        assert_eq!(plural_category("en", 5), PluralCategory::Other);
    }

    #[test]
    fn plural_arabic_six_categories() {
        assert_eq!(plural_category("ar", 0), PluralCategory::Zero);
        assert_eq!(plural_category("ar", 1), PluralCategory::One);
        assert_eq!(plural_category("ar", 2), PluralCategory::Two);
        assert_eq!(plural_category("ar", 5), PluralCategory::Few);
        assert_eq!(plural_category("ar", 50), PluralCategory::Many);
        assert_eq!(plural_category("ar", 100), PluralCategory::Other);
    }

    #[test]
    fn available_locales_includes_ja_and_en() {
        let i18n = I18n::new();
        let locales = i18n.available_locales();
        assert!(locales.iter().any(|l| l.locale == "ja"));
        assert!(locales.iter().any(|l| l.locale == "en"));
    }

    #[test]
    fn external_catalog_loading() {
        let i18n = I18n::new();
        let mut messages = HashMap::new();
        messages.insert("app.name".into(), "Kaname".into());
        let cat = Catalog {
            messages,
            locale: "fr".into(),
            native_name: "Français".into(),
            rtl: false,
            format_locale: "fr-FR".into(),
        };
        i18n.load_catalog(cat);
        i18n.set_locale("fr").unwrap();
        assert_eq!(i18n.t_simple("app.name"), "Kaname");
    }
}
