// src/__tests__/app.test.ts
//
// Kaname フロントエンドユニットテスト (vitest)
//
// **重要**: 以前の実装は全ロジックをテストファイル内にインラインで
// 再実装しており (実ソースからインポートしていなかった)、実際の
// UI コンポーネントのコードを一切検証していなかった (false confidence)。
// 例えば `triageEmail` はテスト内で架空のシグネチャで再実装されており、
// `parseNaturalQuery`/`BEC_COLORS`/`formatSafetyNumber` に至っては
// 対応する実装が UI コードに存在しない架空の関数だった。
//
// このファイルは実際にエクスポートされた関数・クラスをインポートして
// テストする。テスト対象を実コードに追従させるため、UI 側の
// private だった関数・型に `export` を追加した
// (src/ui/Inbox.tsx: formatDate)。

import { describe, it, expect } from "vitest";
import { formatDate } from "../ui/Inbox";

// ── 1. トリアージ (判定は Rust 側へ集約済み) ────────────────────────────

// 注: triageEmail の TypeScript 実装 (src/ui/KanameApp.tsx) は削除した。
// 同じ仕分けロジックが kaname-core::ux_features::TriageEngine に実装されており、
// バックエンドの mail_fetch が返す EmailRow.triage が唯一の判定元になった。
// テストは crates/kaname-core/src/ux_features.rs の #[cfg(test)] 側にあり、
// paper_trail / feed / BEC important / 送信者ルール / 大小文字回避まで
// TypeScript 版より広くカバーしている。二重実装は二重の真実を生むため残さない。
//
// 併せて、上記の削除で使い道を失っていた makeEmail() ヘルパーも削除した。
// どこからも呼ばれていない未使用コードでありながら、消えた KanameApp.tsx
// の Email 型を import せずに参照しており、tsc/vitest が動く環境であれば
// 型エラーになっていたはずの状態だった (D20 により未実行のため放置されて
// いた。crates/kaname-ui/src/commands.rs の mail_list 巻き添え放置
// (docs/gap-analysis.md D25) と同じ欠陥クラスの、フロントエンド版)。

// ── 2. formatDate (実 src/ui/Inbox.tsx をインポート) ─────────────────────────

describe("formatDate", () => {
  it("null → 空文字列", () => {
    expect(formatDate(null)).toBe("");
  });

  it("1分未満 → 「今」", () => {
    const iso = new Date(Date.now() - 10 * 1000).toISOString();
    expect(formatDate(iso)).toBe("今");
  });

  it("30分前 → X分前", () => {
    const iso = new Date(Date.now() - 30 * 60 * 1000).toISOString();
    expect(formatDate(iso)).toMatch(/分前$/);
  });

  it("2時間前 → X時間前", () => {
    const iso = new Date(Date.now() - 2 * 3600 * 1000).toISOString();
    expect(formatDate(iso)).toMatch(/時間前$/);
  });

  it("3日前 → 曜日表示", () => {
    const iso = new Date(Date.now() - 3 * 86400 * 1000).toISOString();
    const r = formatDate(iso);
    expect(["日","月","火","水","木","金","土"]).toContain(r);
  });

  it("8日以上前 → M/D 形式", () => {
    const iso = new Date(Date.now() - 10 * 86400 * 1000).toISOString();
    expect(formatDate(iso)).toMatch(/^\d+\/\d+$/);
  });
});

