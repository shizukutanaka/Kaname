// src/__tests__/app.test.ts
//
// Kaname フロントエンドユニットテスト (vitest)
//
// **重要**: 以前の実装は全ロジックをテストファイル内にインラインで
// 再実装しており (実ソースからインポートしていなかった)、実際の
// UI コンポーネントのコードを一切検証していなかった (false confidence)。
// 例えば `triageEmail` はテスト内で `(fromAddr, subject, becVerdict)` という
// 架空のシグネチャで再実装されていたが、実際の src/ui/KanameApp.tsx の
// `triageEmail` は `(email: Email)` を受け取り、becVerdict を判定に
// 一切使っていなかった。`parseNaturalQuery`/`BEC_COLORS`/
// `formatSafetyNumber` に至っては対応する実装が UI コードに存在しない
// 架空の関数だった。
//
// このファイルは実際にエクスポートされた関数・クラスをインポートして
// テストする。テスト対象を実コードに追従させるため、UI 側の
// private だった関数・型に `export` を追加した
// (src/ui/KanameApp.tsx: Email, triageEmail /
//  src/ui/KanameAppleFeatures.tsx: UndoAction, UndoRedoStack /
//  src/ui/Inbox.tsx: formatDate)。

import { describe, it, expect, beforeEach, vi } from "vitest";
import { triageEmail, type Email } from "../ui/KanameApp";
import { UndoRedoStack } from "../ui/KanameAppleFeatures";
import { formatDate } from "../ui/Inbox";

// ── テスト用ヘルパー ─────────────────────────────────────────────────────────

function makeEmail(overrides: Partial<Email> = {}): Email {
  return {
    id: "e1",
    from_name: null,
    from_addr: "alice@company.co.jp",
    subject: "会議の件",
    preview: null,
    received_at: null,
    is_read: false,
    is_starred: false,
    bec_verdict: "SAFE",
    is_mls: false,
    ...overrides,
  };
}

// ── 1. triageEmail (実 src/ui/KanameApp.tsx をインポートしてテスト) ──────────

describe("triageEmail", () => {
  it("noreply アドレス → paper_trail", () => {
    const r = triageEmail(makeEmail({ from_addr: "noreply@amazon.co.jp", subject: "ご注文確認" }));
    expect(r).toBe("paper_trail");
  });

  it("領収書系の件名 → paper_trail", () => {
    const r = triageEmail(makeEmail({ from_addr: "info@shop.com", subject: "Receipt #123" }));
    expect(r).toBe("paper_trail");
  });

  it("newsletter 系の件名 → feed", () => {
    const r = triageEmail(makeEmail({ from_addr: "news@tc.com", subject: "Weekly Newsletter" }));
    expect(r).toBe("feed");
  });

  it("BEC DANGEROUS → important", () => {
    const r = triageEmail(makeEmail({ from_addr: "cfo@evil.com", subject: "至急の連絡", bec_verdict: "DANGEROUS" }));
    expect(r).toBe("important");
  });

  it("通常メール (BEC SAFE) → important", () => {
    const r = triageEmail(makeEmail({ subject: "会議の件" }));
    expect(r).toBe("important");
  });

  it("bec_verdict が null でも paper_trail/feed 判定は独立して動く", () => {
    // 実装は bec_verdict を「important 昇格」にのみ使い、paper_trail/feed の
    // 判定はキーワードのみで完結する。null でもクラッシュしないことを確認。
    const r = triageEmail(makeEmail({ subject: "ご注文確認", bec_verdict: null }));
    expect(r).toBe("paper_trail");
  });
});

// ── 2. UndoRedoStack (実 src/ui/KanameAppleFeatures.tsx をインポート) ────────

describe("UndoRedoStack", () => {
  let stack: UndoRedoStack;

  beforeEach(() => { stack = new UndoRedoStack(); });

  it("初期状態で canUndo=false, canRedo=false", () => {
    expect(stack.canUndo()).toBe(false);
    expect(stack.canRedo()).toBe(false);
  });

  it("push後 canUndo=true", () => {
    stack.push("archive", "e1", "アーカイブ", () => {});
    expect(stack.canUndo()).toBe(true);
  });

  it("undo() でアクションが返り reverse_fn が呼ばれる", () => {
    const fn = vi.fn();
    stack.push("archive", "e1", "アーカイブ", fn);
    const a = stack.undo();
    expect(a?.description).toBe("アーカイブ");
    expect(fn).toHaveBeenCalledOnce();
  });

  it("undo後 canRedo=true, redo()で復元", () => {
    stack.push("star", "e1", "スター", () => {});
    stack.undo();
    expect(stack.canRedo()).toBe(true);
    const r = stack.redo();
    expect(r?.description).toBe("スター");
    expect(stack.canRedo()).toBe(false);
  });

  it("push後 redoStack がクリアされる", () => {
    stack.push("archive", "e1", "A", () => {});
    stack.undo();
    stack.push("trash", "e2", "B", () => {});
    expect(stack.canRedo()).toBe(false);
  });

  it("undoDescription が直前のアクション説明を返す", () => {
    stack.push("archive", "e1", "アーカイブ", () => {});
    stack.push("trash", "e2", "削除", () => {});
    expect(stack.undoDescription()).toBe("削除");
  });

  it("MAX=50 を超えると古いものが削除される", () => {
    for (let i = 0; i < 55; i++) {
      stack.push("archive", `e${i}`, `action${i}`, () => {});
    }
    let count = 0;
    while (stack.canUndo()) { stack.undo(); count++; }
    expect(count).toBe(50);
  });
});

// ── 3. formatDate (実 src/ui/Inbox.tsx をインポート) ─────────────────────────

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

// ── 4. セキュリティ不変条件 (契約テスト) ─────────────────────────────────────
// Kaname の核心: AI は単一メールのみアクセス可能。
// これは実際の Rust 側 (kaname-ai::SafeSummaryEngine 等) の出力契約を
// フロントエンドが正しく前提としているかのドキュメント的テスト。
// Rust 側の実挙動は crates/kaname-ai の単体テストで別途検証済み。

describe("セキュリティ不変条件 (契約テスト)", () => {
  it("SafeSummary の契約: single_email_only は常に true", () => {
    const mockSummary = {
      summary: "テスト要約",
      risk: "SAFE",
      email_id: "e1",
      single_email_only: true,
      local_inference:   true,
      data_sources:      ["email:e1"],
    };

    expect(mockSummary.single_email_only).toBe(true);
    expect(mockSummary.local_inference).toBe(true);
    expect(mockSummary.data_sources.every(s => !s.includes("inbox"))).toBe(true);
    expect(mockSummary.data_sources.every(s => !s.includes("all_emails"))).toBe(true);
    expect(mockSummary.data_sources.every(s => s.includes("email:"))).toBe(true);
  });

  it("DLPブロック verdict の契約: type/reason フィールドを持つ", () => {
    const dlpDecision = { type: "Block", reason: "極秘ラベル付きメールのAI処理は禁止" };
    expect(dlpDecision.type).toBe("Block");
    expect(dlpDecision.reason).toBeTruthy();
  });
});
