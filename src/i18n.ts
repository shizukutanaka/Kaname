// src/i18n/index.ts
//
// Kaname 多言語化システム
//
// 設計原則:
//   - すべての翻訳キーは ja.json (基準) に存在しなければならない
//   - 他言語は ja.json のキーをすべてカバーすること (CI が検証)
//   - フォールバック: 翻訳がなければ ja → key 名そのもの
//   - 補間: {name} 形式のプレースホルダー対応
//   - SolidJS リアクティブシグナル経由

import { createSignal, createMemo } from "solid-js";
import jaTranslations from "./locales/ja.json";
import enTranslations from "./locales/en.json";

// ── 型定義 ──

type Language = "ja" | "en" | "zh-CN" | "ko";

const TRANSLATIONS: Record<string, unknown> = {
  ja: jaTranslations,
  en: enTranslations,
  // 将来追加: "zh-CN": zhCnTranslations, "ko": koTranslations,
};

// ── 言語検出 ──

/** ブラウザの言語設定から最適な言語を選ぶ */
export function detectLanguage(): Language {
  // 1. localStorage に保存された設定があればそれを使う
  if (typeof localStorage !== "undefined") {
    const saved = localStorage.getItem("kaname-language") as Language | null;
    if (saved && saved in TRANSLATIONS) return saved;
  }

  // 2. ブラウザの navigator.language から推測
  if (typeof navigator !== "undefined") {
    const nav = navigator.language.toLowerCase();
    if (nav.startsWith("ja")) return "ja";
    if (nav.startsWith("zh")) return "zh-CN" as Language;
    if (nav.startsWith("ko")) return "ko" as Language;
    if (nav.startsWith("en")) return "en";
  }

  // 3. デフォルト: 日本語
  return "ja";
}

// ── リアクティブな現在言語 ──

const [currentLanguage, setCurrentLanguage] = createSignal<Language>(detectLanguage());

export { currentLanguage };

/**
 * i18n システムを初期化する。
 *
 * 現在は言語検出・翻訳データの読み込みがモジュールロード時に同期完了する
 * 設計のため、呼び出し自体は no-op に近い。将来的にリモート翻訳データの
 * 取得等で非同期処理が必要になった場合に備え、呼び出し元 (main.tsx の
 * 起動シーケンス) が `await initI18n()` できる形にしておく。
 */
export async function initI18n(): Promise<void> {
  // <html lang="..."> をブート時点の検出言語で確実に同期しておく
  if (typeof document !== "undefined") {
    document.documentElement.lang = currentLanguage();
  }
}

/** 言語を変更し、選択を永続化する */
export function setLanguage(lang: Language) {
  setCurrentLanguage(lang);
  if (typeof localStorage !== "undefined") {
    localStorage.setItem("kaname-language", lang);
  }
  // <html lang="..."> 属性も更新 (アクセシビリティ + Spell check)
  if (typeof document !== "undefined") {
    document.documentElement.lang = lang;
  }
}

// ── キー解決 ──

/** ドット記法のキーパスでネストオブジェクトをたどる */
function resolveKey(obj: unknown, key: string): string | undefined {
  const parts = key.split(".");
  let cur: unknown = obj;
  for (const part of parts) {
    if (cur && typeof cur === "object" && part in cur) {
      cur = (cur as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
  }
  return typeof cur === "string" ? cur : undefined;
}

/** {name} のようなプレースホルダーを置換する */
function interpolate(template: string, params?: Record<string, string | number>): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (_, key) =>
    key in params ? String(params[key]) : `{${key}}`
  );
}

// ── パブリック API ──

/**
 * 翻訳キーから現在言語の文字列を取得する。
 *
 * @example
 * t("nav.inbox")                              // "受信トレイ" / "Inbox"
 * t("screener.description", { count: 3 })     // "3 人の送信者..."
 * t("nonexistent.key")                        // "nonexistent.key" (フォールバック)
 */
export function t(key: string, params?: Record<string, string | number>): string {
  const lang = currentLanguage();

  // 現在言語で解決を試みる
  let resolved = resolveKey(TRANSLATIONS[lang], key);

  // フォールバック: 日本語
  if (!resolved && lang !== "ja") {
    resolved = resolveKey(TRANSLATIONS.ja, key);
  }

  // それでも見つからなければキー名を返す (デバッグしやすい)
  if (!resolved) {
    if (typeof console !== "undefined") {
      console.warn(`[i18n] Missing translation for key: ${key} (lang: ${lang})`);
    }
    return key;
  }

  return interpolate(resolved, params);
}

/** リアクティブな翻訳ヘルパー (シグナル変更で再計算される) */
export function useT() {
  return createMemo(() => (key: string, params?: Record<string, string | number>) =>
    t(key, params)
  );
}

// ── 利用可能言語の一覧 ──

export interface LanguageInfo {
  code: Language;
  name: string;
  isBase: boolean;
  completion: number;
}

export function listLanguages(): LanguageInfo[] {
  return Object.entries(TRANSLATIONS).map(([code, obj]) => {
    const meta = (obj as { _meta?: { language_name: string; is_base: boolean; completion: number } })._meta;
    return {
      code: code as Language,
      name: meta?.language_name ?? code,
      isBase: meta?.is_base ?? false,
      completion: meta?.completion ?? 0,
    };
  });
}

// ── キー一覧の検証 (CI で実行) ──

/**
 * 全言語が ja.json と同じキーを持つことを検証する。
 * 不足キーがあれば配列で返す。
 */
export function validateTranslations(): { lang: string; missing: string[] }[] {
  const baseKeys = collectKeys(TRANSLATIONS.ja);
  const result: { lang: string; missing: string[] }[] = [];

  for (const [lang, translations] of Object.entries(TRANSLATIONS)) {
    if (lang === "ja") continue;
    const langKeys = collectKeys(translations);
    const missing = [...baseKeys].filter(k => !langKeys.has(k));
    if (missing.length > 0) {
      result.push({ lang, missing });
    }
  }

  return result;
}

function collectKeys(obj: unknown, prefix = ""): Set<string> {
  const keys = new Set<string>();
  if (obj && typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      if (k === "_meta") continue;
      const path = prefix ? `${prefix}.${k}` : k;
      if (typeof v === "string") {
        keys.add(path);
      } else if (typeof v === "object") {
        collectKeys(v, path).forEach(k2 => keys.add(k2));
      }
    }
  }
  return keys;
}

// CI で使うヘルパー (ブラウザでも node でも動く)
if (typeof process !== "undefined" && process.argv?.[2] === "--validate") {
  const issues = validateTranslations();
  if (issues.length > 0) {
    console.error("Translation validation failed:");
    for (const { lang, missing } of issues) {
      console.error(`  ${lang}: missing ${missing.length} keys:`);
      missing.slice(0, 10).forEach(k => console.error(`    - ${k}`));
      if (missing.length > 10) console.error(`    ... and ${missing.length - 10} more`);
    }
    process.exit(1);
  } else {
    console.log("✓ All translations are complete");
  }
}
