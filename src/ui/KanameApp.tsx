// src/ui/KanameApp.tsx
//
// Kaname メインアプリ — 競合分析から実装した UX 改善。
//
// 実装した競合対抗機能:
//   Superhuman → キーボードショートカット + コマンドパレット (⌘K)
//   HEY        → 送信者スクリーナー + Reply Later + Paper Trail
//   全競合      → セーフ AI 要約 (Dual-LLM で Superhuman の脆弱性を防ぐ)
//
// Superhuman の致命的欠陥への対抗:
//   Superhuman: AI が受信箱全体を読める → プロンプト注入でデータ漏洩
//   Kaname:     Q-LLM は「今開いているメール1通のみ」を見る
//               ツールなし・ネットワークなし・他メールへのアクセスなし
//               型システムが Content<Untrusted> の漏れをコンパイル時に阻止

import { createSignal, createEffect, For, Show, Switch, Match, onMount, onCleanup } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

// ============================================================================
// 型定義
// ============================================================================

interface Email {
  id:          string;
  from_name:   string | null;
  from_addr:   string;
  subject:     string | null;
  preview:     string | null;
  received_at: string | null;
  is_read:     boolean;
  is_starred:  boolean;
  bec_verdict: string | null;
  is_mls:      boolean;
  triage_bucket?: "important" | "other" | "paper_trail" | "feed";
  snoozed_until?: string;
  reply_later?: boolean;
}

interface ScreenerEntry {
  from_addr:    string;
  from_name:    string | null;
  first_seen:   string;
  email_count:  number;
  is_new:       boolean; // まだ判定していない
}

// ============================================================================
// キーボードショートカットシステム
// ============================================================================

const SHORTCUTS: Record<string, string> = {
  "j":       "次のメール",
  "k":       "前のメール",
  "o":       "開く / 閉じる",
  "r":       "返信",
  "f":       "転送",
  "e":       "アーカイブ",
  "#":       "ゴミ箱",
  "u":       "未読にする",
  "s":       "スター",
  "h":       "スヌーズ",
  "l":       "Reply Later",
  "x":       "選択",
  "n":       "新規作成",
  "/":       "検索",
  "?":       "ショートカット一覧",
  "Escape":  "キャンセル",
  "Meta+k":  "コマンドパレット",
  "Meta+Enter": "送信",
};

const ShortcutsModal = (props: { onClose: () => void }) => (
  <div style={{
    position: "fixed", inset: "0",
    background: "#00000088",
    display: "flex", "align-items": "center", "justify-content": "center",
    "z-index": "100",
  }} onClick={props.onClose}>
    <div
      style={{
        background: "#0D1219",
        border: "1px solid #1F2833",
        "border-radius": "12px",
        padding: "24px",
        width: "480px",
        "max-height": "80vh",
        "overflow-y": "auto",
      }}
      onClick={e => e.stopPropagation()}
    >
      <div style={{ "font-size": "15px", "font-weight": "700", "margin-bottom": "16px" }}>
        キーボードショートカット
      </div>
      <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "8px" }}>
        <For each={Object.entries(SHORTCUTS)}>
          {([key, desc]) => (
            <>
              <div style={{
                "font-family": "monospace",
                "font-size": "12px",
                background: "#1A2129",
                padding: "3px 8px",
                "border-radius": "4px",
                color: "#00C4CC",
              }}>
                {key}
              </div>
              <div style={{ "font-size": "12px", color: "#8B96A5", "line-height": "1.8" }}>
                {desc}
              </div>
            </>
          )}
        </For>
      </div>
    </div>
  </div>
);

// ============================================================================
// コマンドパレット (⌘K)
// ============================================================================

interface Command {
  id:      string;
  label:   string;
  desc?:   string;
  icon?:   string;
  action:  () => void;
}

const CommandPalette = (props: {
  onClose:  () => void;
  commands: Command[];
}) => {
  const [query, setQuery]     = createSignal("");
  const [cursor, setCursor]   = createSignal(0);

  const filtered = () => {
    const q = query().toLowerCase();
    return q
      ? props.commands.filter(c =>
          c.label.toLowerCase().includes(q) ||
          (c.desc || "").toLowerCase().includes(q)
        )
      : props.commands;
  };

  const handleKey = (e: KeyboardEvent) => {
    if (e.key === "ArrowDown") { setCursor(c => Math.min(c + 1, filtered().length - 1)); }
    if (e.key === "ArrowUp")   { setCursor(c => Math.max(c - 1, 0)); }
    if (e.key === "Enter") {
      const cmd = filtered()[cursor()];
      if (cmd) { cmd.action(); props.onClose(); }
    }
    if (e.key === "Escape") props.onClose();
  };

  return (
    <div
      style={{
        position: "fixed", inset: "0",
        background: "#00000088",
        display: "flex", "align-items": "flex-start", "justify-content": "center",
        "padding-top": "20vh",
        "z-index": "200",
      }}
      onClick={props.onClose}
    >
      <div
        style={{
          background: "#0D1219",
          border: "1px solid #2A3441",
          "border-radius": "10px",
          width: "540px",
          "box-shadow": "0 20px 60px #00000088",
          overflow: "hidden",
        }}
        onClick={e => e.stopPropagation()}
        onKeyDown={handleKey}
      >
        {/* 検索欄 */}
        <div style={{
          display: "flex",
          "align-items": "center",
          padding: "12px 16px",
          "border-bottom": "1px solid #1F2833",
          gap: "10px",
        }}>
          <span style={{ color: "#5A6473", "font-size": "16px" }}>⌘</span>
          <input
            autofocus
            type="text"
            placeholder="コマンドを検索..."
            value={query()}
            onInput={e => { setQuery(e.currentTarget.value); setCursor(0); }}
            style={{
              flex: "1",
              background: "none",
              border: "none",
              color: "#F5F7FA",
              "font-size": "14px",
              outline: "none",
            }}
          />
          <span style={{ "font-size": "11px", color: "#5A6473" }}>Esc で閉じる</span>
        </div>

        {/* コマンドリスト */}
        <div style={{ "max-height": "320px", "overflow-y": "auto" }}>
          <For each={filtered()}>
            {(cmd, i) => (
              <div
                onClick={() => { cmd.action(); props.onClose(); }}
                style={{
                  padding: "10px 16px",
                  display: "flex",
                  "align-items": "center",
                  gap: "12px",
                  cursor: "pointer",
                  background: cursor() === i() ? "#1A2129" : "transparent",
                  transition: "background 0.1s",
                }}
                onMouseEnter={() => setCursor(i())}
              >
                <span style={{ "font-size": "16px", width: "24px", "text-align": "center" }}>
                  {cmd.icon || "⚡"}
                </span>
                <div>
                  <div style={{ "font-size": "13px", color: "#F5F7FA" }}>{cmd.label}</div>
                  <Show when={cmd.desc}>
                    <div style={{ "font-size": "11px", color: "#5A6473" }}>{cmd.desc}</div>
                  </Show>
                </div>
              </div>
            )}
          </For>
          <Show when={filtered().length === 0}>
            <div style={{ padding: "20px", "text-align": "center", color: "#5A6473", "font-size": "13px" }}>
              「{query()}」に一致するコマンドなし
            </div>
          </Show>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// 送信者スクリーナー (HEY の The Screener を安全性向上版で実装)
// ============================================================================

const SenderScreener = (props: {
  entries: ScreenerEntry[];
  onDecision: (addr: string, allow: boolean, destination?: string) => void;
}) => {
  const newEntries = () => props.entries.filter(e => e.is_new);

  return (
    <div style={{
      flex: "1",
      display: "flex",
      "flex-direction": "column",
      background: "#0A0E14",
      overflow: "hidden",
    }}>
      {/* ヘッダー */}
      <div style={{
        padding: "20px 24px 16px",
        "border-bottom": "1px solid #1F2833",
      }}>
        <div style={{ "font-size": "18px", "font-weight": "700", "margin-bottom": "6px" }}>
          スクリーナー
        </div>
        <div style={{ "font-size": "13px", color: "#5A6473" }}>
          初めて連絡してきた {newEntries().length} 人の送信者。
          許可するか、ブロックするか選択してください。
        </div>
      </div>

      {/* スクリーナーリスト */}
      <div style={{ flex: "1", "overflow-y": "auto" }}>
        <Show
          when={newEntries().length > 0}
          fallback={
            <div style={{
              display: "flex", "flex-direction": "column",
              "align-items": "center", "justify-content": "center",
              height: "300px", gap: "12px",
            }}>
              <div style={{ "font-size": "48px", opacity: "0.2" }}>✓</div>
              <div style={{ color: "#5A6473", "font-size": "14px" }}>
                スクリーニング待ちの送信者なし
              </div>
            </div>
          }
        >
          <For each={newEntries()}>
            {(entry) => (
              <div style={{
                padding: "16px 24px",
                "border-bottom": "1px solid #1F2833",
                display: "flex",
                "align-items": "center",
                gap: "16px",
              }}>
                {/* アバター */}
                <div style={{
                  width: "44px", height: "44px",
                  "border-radius": "50%",
                  background: "#1A2129",
                  display: "flex", "align-items": "center", "justify-content": "center",
                  "font-size": "16px", "font-weight": "600", color: "#8B96A5",
                  "flex-shrink": "0",
                }}>
                  {(entry.from_name || entry.from_addr)[0]?.toUpperCase()}
                </div>

                {/* 情報 */}
                <div style={{ flex: "1", "min-width": "0" }}>
                  <div style={{ "font-size": "14px", "font-weight": "500", "margin-bottom": "2px" }}>
                    {entry.from_name || entry.from_addr}
                  </div>
                  <div style={{ "font-size": "12px", color: "#5A6473" }}>
                    {entry.from_addr} · {entry.email_count} 通 · {entry.first_seen} から
                  </div>
                </div>

                {/* アクションボタン */}
                <div style={{ display: "flex", gap: "8px" }}>
                  {/* 許可 → どこに? */}
                  <button
                    onClick={() => props.onDecision(entry.from_addr, true, "inbox")}
                    style={{
                      background: "#00C4CC20",
                      color: "#00C4CC",
                      border: "1px solid #00C4CC40",
                      "border-radius": "6px",
                      padding: "6px 14px",
                      "font-size": "12px",
                      cursor: "pointer",
                      "font-weight": "500",
                    }}
                  >
                    受信トレイへ ↓
                  </button>
                  <button
                    onClick={() => props.onDecision(entry.from_addr, true, "feed")}
                    style={{
                      background: "#1A2129",
                      color: "#8B96A5",
                      border: "1px solid #2A3441",
                      "border-radius": "6px",
                      padding: "6px 14px",
                      "font-size": "12px",
                      cursor: "pointer",
                    }}
                  >
                    フィードへ
                  </button>
                  <button
                    onClick={() => props.onDecision(entry.from_addr, false)}
                    style={{
                      background: "#E5484D10",
                      color: "#E5484D",
                      border: "1px solid #E5484D30",
                      "border-radius": "6px",
                      padding: "6px 14px",
                      "font-size": "12px",
                      cursor: "pointer",
                    }}
                  >
                    ブロック
                  </button>
                </div>
              </div>
            )}
          </For>
        </Show>
      </div>
    </div>
  );
};

// ============================================================================
// セーフ AI 要約 (Superhuman の脆弱性を防ぐ)
// ============================================================================

const SafeAiSummary = (props: { emailId: string }) => {
  const [summary, setSummary] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);

  const handleSummarize = async () => {
    setLoading(true);
    try {
      // Kaname の安全な要約:
      // 1. mail_get_body → 本文を取得
      // 2. Q-LLM (Quarantined) が「このメール1通のみ」を解析
      //    - 他のメールへのアクセスなし
      //    - ツールなし、ネットワーク接続なし
      //    - Content<Untrusted> 型でコンパイル時に境界を強制
      // 3. Bridge が要約を検証してから P-LLM に渡す
      //    (P-LLM は生の要約を見ない — 構造化データのみ)
      //
      // Superhuman の脆弱性との違い:
      // Superhuman: AI が受信箱全体を読める
      //             → "直近のメールを要約して" → 全メールを外部送信
      // Kaname:    Q-LLM は「このウィンドウのこのメール1通のみ」
      //            他のメールにはアクセス不可能 (型で強制)
      const result = await invoke<{ summary: string; risk: string }>(
        "ai_summarize_email",
        { emailId: props.emailId }
      );
      setSummary(result.summary);
    } catch {
      setSummary("要約を生成できませんでした");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      margin: "8px 16px",
      background: "#12181F",
      border: "1px solid #1F2833",
      "border-radius": "8px",
      overflow: "hidden",
    }}>
      <Show when={!summary()}>
        <button
          onClick={handleSummarize}
          disabled={loading()}
          style={{
            width: "100%",
            padding: "10px 16px",
            background: "none",
            border: "none",
            cursor: loading() ? "not-allowed" : "pointer",
            color: "#5A6473",
            "font-size": "12px",
            display: "flex",
            "align-items": "center",
            gap: "8px",
            opacity: loading() ? 0.6 : 1,
          }}
        >
          <span>✨</span>
          {loading() ? "AI 要約中..." : "AI で要約 (このメールのみ — 他のメールは読みません)"}
          <span style={{ "margin-left": "auto", "font-size": "10px", color: "#00C4CC" }}>
            🔒 安全
          </span>
        </button>
      </Show>
      <Show when={summary()}>
        <div style={{ padding: "12px 16px" }}>
          <div style={{
            display: "flex", "align-items": "center", gap: "8px",
            "margin-bottom": "8px",
          }}>
            <span style={{ "font-size": "11px", color: "#00C4CC", "font-weight": "600" }}>
              AI 要約
            </span>
            <span style={{
              "font-size": "10px", color: "#00B368",
              background: "#00B36820", padding: "1px 6px", "border-radius": "3px",
            }}>
              このメールのみ分析 · データ外部送信なし
            </span>
          </div>
          <div style={{ "font-size": "13px", color: "#D0D5DD", "line-height": "1.6" }}>
            {summary()}
          </div>
          <button
            onClick={() => setSummary(null)}
            style={{
              "margin-top": "8px", background: "none", border: "none",
              color: "#5A6473", "font-size": "11px", cursor: "pointer",
            }}
          >
            ✕ 閉じる
          </button>
        </div>
      </Show>
    </div>
  );
};

// ============================================================================
// スヌーズ / Reply Later パネル
// ============================================================================

const SnoozePanel = (props: {
  emailId: string;
  onSnooze: (until: Date) => void;
  onReplyLater: () => void;
  onClose: () => void;
}) => {
  const options = [
    { label: "今日の夕方",      hours: 6 },
    { label: "明日の朝",        hours: 16 },
    { label: "明後日",          hours: 40 },
    { label: "来週月曜日",      hours: nextMonday() },
    { label: "2週間後",         hours: 14 * 24 },
  ];

  function nextMonday(): number {
    const now = new Date();
    const day = now.getDay();
    const daysUntil = day === 0 ? 1 : 8 - day;
    return daysUntil * 24;
  }

  return (
    <div style={{
      position: "absolute",
      background: "#0D1219",
      border: "1px solid #2A3441",
      "border-radius": "8px",
      padding: "8px",
      "box-shadow": "0 8px 30px #00000088",
      "min-width": "200px",
      "z-index": "50",
    }}>
      <div style={{ "padding": "4px 8px 8px", "font-size": "11px", color: "#5A6473" }}>
        スヌーズ
      </div>
      <For each={options}>
        {(opt) => (
          <button
            onClick={() => {
              const d = new Date();
              d.setHours(d.getHours() + opt.hours);
              props.onSnooze(d);
              props.onClose();
            }}
            style={{
              display: "block", width: "100%",
              padding: "8px 12px", background: "none", border: "none",
              cursor: "pointer", color: "#D0D5DD", "font-size": "13px",
              "text-align": "left", "border-radius": "4px",
              transition: "background 0.1s",
            }}
            onMouseEnter={e => (e.currentTarget.style.background = "#1A2129")}
            onMouseLeave={e => (e.currentTarget.style.background = "none")}
          >
            {opt.label}
          </button>
        )}
      </For>
      <div style={{ "border-top": "1px solid #1F2833", "margin-top": "4px", "padding-top": "4px" }}>
        <button
          onClick={() => { props.onReplyLater(); props.onClose(); }}
          style={{
            display: "block", width: "100%",
            padding: "8px 12px", background: "none", border: "none",
            cursor: "pointer", color: "#00C4CC", "font-size": "13px",
            "text-align": "left", "border-radius": "4px",
          }}
        >
          📌 Reply Later に追加
        </button>
      </div>
    </div>
  );
};

// ============================================================================
// スマートトリアージ (Superhuman の Split Inbox + HEY の仕分け)
// ============================================================================

/** メールを自動仕分けする */
function triageEmail(email: Email): "important" | "other" | "paper_trail" | "feed" {
  const subject = (email.subject || "").toLowerCase();
  const from    = email.from_addr.toLowerCase();

  // Paper Trail: 領収書・確認メール
  const paperTrailKeywords = [
    "receipt", "order", "invoice", "confirmation", "booking",
    "領収書", "注文", "請求書", "予約確認", "ご注文",
    "noreply", "no-reply", "donotreply",
  ];
  if (paperTrailKeywords.some(k => subject.includes(k) || from.includes(k))) {
    return "paper_trail";
  }

  // Feed: ニュースレター・更新情報
  const feedKeywords = [
    "newsletter", "unsubscribe", "subscribe", "digest",
    "weekly", "monthly", "update", "announcement",
    "ニュースレター", "配信", "週刊", "月刊",
  ];
  if (feedKeywords.some(k => subject.includes(k))) {
    return "feed";
  }

  // BEC フラグが立っている場合は "important" (要確認)
  if (email.bec_verdict && email.bec_verdict !== "SAFE") {
    return "important";
  }

  // デフォルト: important
  return "important";
}

// ============================================================================
// Send Later (スケジュール送信)
// ============================================================================

const SendLaterPicker = (props: {
  onSchedule: (date: Date) => void;
  onClose: () => void;
}) => {
  const [customDate, setCustomDate] = createSignal("");

  const presets = [
    { label: "今日の夕方 18:00",          hours: () => { const d = new Date(); d.setHours(18,0,0,0); return d; } },
    { label: "明日の朝 9:00",             hours: () => { const d = new Date(); d.setDate(d.getDate()+1); d.setHours(9,0,0,0); return d; } },
    { label: "月曜日の朝 9:00",           hours: () => {
        const d = new Date();
        const daysUntil = d.getDay() === 0 ? 1 : 8 - d.getDay();
        d.setDate(d.getDate() + daysUntil);
        d.setHours(9, 0, 0, 0);
        return d;
      }},
  ];

  return (
    <div style={{
      position: "absolute", bottom: "48px", right: "0",
      background: "#0D1219",
      border: "1px solid #2A3441",
      "border-radius": "8px",
      padding: "12px",
      "box-shadow": "0 8px 30px #00000088",
      width: "260px",
      "z-index": "50",
    }}>
      <div style={{ "font-size": "12px", "font-weight": "600", "margin-bottom": "10px" }}>
        送信予約
      </div>
      <For each={presets}>
        {(preset) => (
          <button
            onClick={() => { props.onSchedule(preset.hours()); props.onClose(); }}
            style={{
              display: "block", width: "100%",
              padding: "8px 12px", background: "none", border: "none",
              cursor: "pointer", color: "#D0D5DD", "font-size": "13px",
              "text-align": "left", "border-radius": "4px",
            }}
          >
            {preset.label}
          </button>
        )}
      </For>
      <div style={{ "margin-top": "8px" }}>
        <input
          type="datetime-local"
          value={customDate()}
          onInput={e => setCustomDate(e.currentTarget.value)}
          style={{
            width: "100%", background: "#12181F",
            border: "1px solid #2A3441", "border-radius": "4px",
            padding: "6px 8px", color: "#F5F7FA", "font-size": "12px",
            "box-sizing": "border-box",
          }}
        />
        <button
          onClick={() => {
            if (customDate()) {
              props.onSchedule(new Date(customDate()));
              props.onClose();
            }
          }}
          style={{
            "margin-top": "6px", width: "100%",
            background: "#00C4CC20", color: "#00C4CC",
            border: "1px solid #00C4CC40", "border-radius": "4px",
            padding: "7px", "font-size": "12px", cursor: "pointer",
          }}
        >
          この日時に送信予約
        </button>
      </div>
    </div>
  );
};

// ============================================================================
// メインアプリ統合
// ============================================================================

export const KanameApp = () => {
  const [showShortcuts,   setShowShortcuts]   = createSignal(false);
  const [showPalette,     setShowPalette]     = createSignal(false);
  const [activeView,      setActiveView]      = createSignal<
    "inbox" | "screener" | "reply_later" | "feed" | "paper_trail" | "snoozed"
  >("inbox");
  const [selectedEmail,   setSelectedEmail]   = createSignal<string | null>(null);
  const [emailIndex,      setEmailIndex]      = createSignal(0);
  const [emails,          setEmails]          = createSignal<Email[]>([]);
  const [showSnooze,      setShowSnooze]      = createSignal(false);
  const [screenerEntries, setScreenerEntries] = createSignal<ScreenerEntry[]>([]);
  const [replyLaterIds,   setReplyLaterIds]   = createSignal<Set<string>>(new Set());

  // デモデータ
  onMount(() => {
    setEmails([
      {
        id: "e1", from_name: "田中 花子", from_addr: "hanako@company.co.jp",
        subject: "Q2 予算会議のご案内", preview: "来週火曜日に会議を設定しました",
        received_at: new Date().toISOString(), is_read: false, is_starred: false,
        bec_verdict: "SAFE", is_mls: true, triage_bucket: "important",
      },
      {
        id: "e2", from_name: "Amazon注文確認", from_addr: "order-update@amazon.co.jp",
        subject: "ご注文の確認", preview: "ご注文 #123-456 を受け付けました",
        received_at: new Date().toISOString(), is_read: true, is_starred: false,
        bec_verdict: "SAFE", is_mls: false, triage_bucket: "paper_trail",
      },
      {
        id: "e3", from_name: null, from_addr: "cfo-urgent@srnazons.com",
        subject: "至急: 振込先変更のご連絡", preview: "新しい口座番号に今日中に送金をお願いします",
        received_at: new Date().toISOString(), is_read: false, is_starred: false,
        bec_verdict: "DANGEROUS", is_mls: false, triage_bucket: "important",
      },
      {
        id: "e4", from_name: "TechCrunch Japan", from_addr: "newsletter@techcrunch.com",
        subject: "週間ニュースレター: AI 最新動向", preview: "今週の注目ニュースをお届けします",
        received_at: new Date().toISOString(), is_read: true, is_starred: false,
        bec_verdict: "SAFE", is_mls: false, triage_bucket: "feed",
      },
    ]);

    setScreenerEntries([
      {
        from_addr: "sales@vendor-unknown.co.jp", from_name: "未知のベンダー",
        first_seen: "今日", email_count: 1, is_new: true,
      },
      {
        from_addr: "newsletter@medium.com", from_name: "Medium Daily Digest",
        first_seen: "昨日", email_count: 3, is_new: true,
      },
    ]);
  });

  // コマンドパレットのコマンド定義
  const commands: Command[] = [
    { id: "compose",      label: "新規作成",         icon: "✏️", action: () => {} },
    { id: "search",       label: "検索",             icon: "🔍", action: () => {} },
    { id: "inbox",        label: "受信トレイへ",      icon: "📥", action: () => setActiveView("inbox") },
    { id: "screener",     label: "スクリーナーへ",    icon: "🛡️", action: () => setActiveView("screener") },
    { id: "reply_later",  label: "Reply Later へ",   icon: "📌", action: () => setActiveView("reply_later") },
    { id: "feed",         label: "フィードへ",        icon: "📰", action: () => setActiveView("feed") },
    { id: "paper_trail",  label: "Paper Trail へ",   icon: "🗂️", action: () => setActiveView("paper_trail") },
    { id: "archive",      label: "アーカイブ",        icon: "📦", action: () => archiveSelected() },
    { id: "snooze",       label: "スヌーズ",          icon: "⏰", action: () => setShowSnooze(true) },
    { id: "shortcuts",    label: "ショートカット一覧", icon: "⌨️", action: () => setShowShortcuts(true) },
    { id: "mark_read",    label: "既読にする",        icon: "✓",  action: () => markRead() },
    { id: "bec_report",   label: "BEC レポートを見る", icon: "⚠️", action: () => {} },
  ];

  const archiveSelected = async () => {
    const id = selectedEmail();
    if (!id) return;
    await invoke("mail_trash", { emailId: id }).catch(() => {});
    setSelectedEmail(null);
  };

  const markRead = async () => {
    const id = selectedEmail();
    if (!id) return;
    await invoke("mail_mark_read", { ids: [id] }).catch(() => {});
  };

  // グローバルキーボードハンドラー
  const handleGlobalKey = (e: KeyboardEvent) => {
    const target = e.target as HTMLElement;
    if (target.tagName === "INPUT" || target.tagName === "TEXTAREA") return;

    if ((e.metaKey || e.ctrlKey) && e.key === "k") {
      e.preventDefault();
      setShowPalette(p => !p);
      return;
    }

    const visibleEmails = emails().filter(em => {
      if (activeView() === "inbox")        return em.triage_bucket === "important";
      if (activeView() === "feed")         return em.triage_bucket === "feed";
      if (activeView() === "paper_trail")  return em.triage_bucket === "paper_trail";
      if (activeView() === "reply_later")  return replyLaterIds().has(em.id);
      return true;
    });

    switch (e.key) {
      case "j": {
        const next = Math.min(emailIndex() + 1, visibleEmails.length - 1);
        setEmailIndex(next);
        setSelectedEmail(visibleEmails[next]?.id ?? null);
        break;
      }
      case "k": {
        const prev = Math.max(emailIndex() - 1, 0);
        setEmailIndex(prev);
        setSelectedEmail(visibleEmails[prev]?.id ?? null);
        break;
      }
      case "e": archiveSelected(); break;
      case "u": markRead(); break;
      case "h": setShowSnooze(true); break;
      case "l": {
        const id = selectedEmail();
        if (id) setReplyLaterIds(s => { const n = new Set(s); n.add(id); return n; });
        break;
      }
      case "?": setShowShortcuts(true); break;
    }
  };

  onMount(() => {
    window.addEventListener("keydown", handleGlobalKey);
  });
  onCleanup(() => {
    window.removeEventListener("keydown", handleGlobalKey);
  });

  const viewEmails = () => {
    const all = emails();
    switch (activeView()) {
      case "inbox":       return all.filter(e => e.triage_bucket === "important");
      case "feed":        return all.filter(e => e.triage_bucket === "feed");
      case "paper_trail": return all.filter(e => e.triage_bucket === "paper_trail");
      case "reply_later": return all.filter(e => replyLaterIds().has(e.id));
      default:            return all;
    }
  };

  const becColor = (v: string | null) => ({
    DANGEROUS: "#E5484D", SUSPICIOUS: "#E5A500", ADVISORY: "#F5A623"
  })[v || ""] || "#5A6473";

  const screenerNewCount = () => screenerEntries().filter(e => e.is_new).length;
  const replyLaterCount  = () => replyLaterIds().size;

  return (
    <div style={{
      display: "flex", height: "100vh",
      background: "#0A0E14", color: "#F5F7FA",
      "font-family": "-apple-system, 'Hiragino Sans', sans-serif",
      position: "relative", overflow: "hidden",
    }}>
      {/* モーダル類 */}
      <Show when={showShortcuts()}><ShortcutsModal onClose={() => setShowShortcuts(false)} /></Show>
      <Show when={showPalette()}>
        <CommandPalette commands={commands} onClose={() => setShowPalette(false)} />
      </Show>

      {/* ── サイドバー ── */}
      <aside style={{
        width: "200px", "flex-shrink": "0",
        background: "#0D1219",
        "border-right": "1px solid #1F2833",
        display: "flex", "flex-direction": "column",
      }}>
        {/* ロゴ */}
        <div style={{ padding: "16px", "border-bottom": "1px solid #1F2833" }}>
          <div style={{ "font-size": "17px", "font-weight": "700", color: "#00C4CC" }}>要</div>
          <div style={{ "font-size": "10px", color: "#5A6473", "margin-top": "1px" }}>Kaname</div>
        </div>

        {/* ⌘K ヒント */}
        <button
          onClick={() => setShowPalette(true)}
          style={{
            margin: "10px 8px 4px",
            background: "#12181F", border: "1px solid #2A3441",
            "border-radius": "6px", padding: "7px 10px",
            cursor: "pointer", color: "#5A6473", "font-size": "12px",
            display: "flex", "align-items": "center", gap: "8px",
          }}
        >
          <span>⌘</span>
          <span style={{ flex: "1", "text-align": "left" }}>コマンド検索</span>
          <span style={{ "font-size": "10px" }}>K</span>
        </button>

        {/* ナビゲーション */}
        <nav style={{ flex: "1", padding: "8px 6px" }}>
          {[
            { id: "inbox",       label: "受信トレイ",     icon: "📥", count: emails().filter(e => !e.is_read && e.triage_bucket === "important").length },
            { id: "screener",    label: "スクリーナー",   icon: "🛡️", count: screenerNewCount() },
            { id: "reply_later", label: "Reply Later",   icon: "📌", count: replyLaterCount() },
            { id: "feed",        label: "フィード",       icon: "📰", count: 0 },
            { id: "paper_trail", label: "Paper Trail",   icon: "🗂️", count: 0 },
          ].map(item => (
            <button
              onClick={() => setActiveView(item.id as "inbox" | "screener" | "reply_later" | "feed" | "paper_trail" | "snoozed")}
              style={{
                width: "100%", padding: "7px 10px",
                display: "flex", "align-items": "center", gap: "8px",
                background: activeView() === item.id ? "#1A2129" : "transparent",
                border: "none", cursor: "pointer",
                color: activeView() === item.id ? "#F5F7FA" : "#8B96A5",
                "font-size": "13px", "border-radius": "5px",
                "text-align": "left",
              }}
            >
              <span style={{ "font-size": "14px" }}>{item.icon}</span>
              <span style={{ flex: "1" }}>{item.label}</span>
              <Show when={item.count > 0}>
                <span style={{
                  background: activeView() === item.id ? "#00C4CC" : "#00C4CC30",
                  color: activeView() === item.id ? "#0A0E14" : "#00C4CC",
                  "border-radius": "8px", "font-size": "10px", "font-weight": "700",
                  padding: "1px 5px",
                }}>
                  {item.count}
                </span>
              </Show>
            </button>
          ))}
        </nav>

        {/* ショートカットヒント */}
        <button
          onClick={() => setShowShortcuts(true)}
          style={{
            padding: "10px 12px",
            "border-top": "1px solid #1F2833",
            background: "none", border: "none", cursor: "pointer",
            color: "#5A6473", "font-size": "11px",
            display: "flex", "align-items": "center", gap: "6px",
          }}
        >
          <span>⌨️</span> ショートカット (?)
        </button>
      </aside>

      {/* ── メインコンテンツ ── */}
      <div style={{ flex: "1", display: "flex", overflow: "hidden" }}>
        <Switch>
          <Match when={activeView() === "screener"}>
            <SenderScreener
              entries={screenerEntries()}
              onDecision={(addr, allow, dest) => {
                setScreenerEntries(es => es.map(e =>
                  e.from_addr === addr ? { ...e, is_new: false } : e
                ));
                invoke("settings_set", {
                  accountId: "current",
                  key: `screener:${addr}`,
                  value: allow ? (dest || "inbox") : "blocked",
                }).catch(() => {});
              }}
            />
          </Match>

          <Match when={true}>
            {/* メールリスト */}
            <div style={{
              width: "340px", "flex-shrink": "0",
              "border-right": "1px solid #1F2833",
              display: "flex", "flex-direction": "column",
            }}>
              <div style={{ padding: "12px 16px", "border-bottom": "1px solid #1F2833" }}>
                <div style={{ "font-size": "14px", "font-weight": "600" }}>
                  {{ inbox: "受信トレイ", feed: "フィード", paper_trail: "Paper Trail", reply_later: "Reply Later", screener: "スクリーナー" }[activeView()] || ""}
                </div>
              </div>
              <div style={{ flex: "1", "overflow-y": "auto" }}>
                <For each={viewEmails()}>
                  {(email, i) => (
                    <div
                      onClick={() => { setSelectedEmail(email.id); setEmailIndex(i()); }}
                      style={{
                        padding: "12px 14px",
                        "border-bottom": "1px solid #1F2833",
                        cursor: "pointer",
                        background: selectedEmail() === email.id ? "#1A2129" :
                                    email.bec_verdict === "DANGEROUS" ? "#E5484D08" : "transparent",
                        display: "flex", gap: "10px",
                        position: "relative",
                      }}
                    >
                      {/* 未読ドット */}
                      <Show when={!email.is_read}>
                        <div style={{
                          position: "absolute", left: "4px", top: "50%",
                          transform: "translateY(-50%)",
                          width: "5px", height: "5px",
                          "border-radius": "50%", background: "#00C4CC",
                        }} />
                      </Show>

                      <div style={{ flex: "1", "min-width": "0" }}>
                        <div style={{
                          display: "flex", "align-items": "center", gap: "6px",
                          "margin-bottom": "3px",
                        }}>
                          <span style={{
                            "font-size": "13px",
                            "font-weight": email.is_read ? "400" : "600",
                            color: becColor(email.bec_verdict) !== "#5A6473"
                                   ? becColor(email.bec_verdict) : "#F5F7FA",
                            flex: "1", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap",
                          }}>
                            {email.from_name || email.from_addr}
                          </span>
                          <Show when={email.is_mls}>
                            <span style={{ "font-size": "9px", color: "#00C4CC" }}>E2E</span>
                          </Show>
                          <Show when={replyLaterIds().has(email.id)}>
                            <span style={{ "font-size": "10px" }}>📌</span>
                          </Show>
                        </div>
                        <div style={{
                          "font-size": "12px", color: "#8B96A5",
                          overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap",
                        }}>
                          {email.subject || "(件名なし)"}
                        </div>
                        <Show when={email.bec_verdict && email.bec_verdict !== "SAFE"}>
                          <div style={{
                            "font-size": "10px", "font-weight": "600",
                            color: becColor(email.bec_verdict), "margin-top": "2px",
                          }}>
                            ⚠ {email.bec_verdict === "DANGEROUS" ? "BEC 危険" : "要確認"}
                          </div>
                        </Show>
                      </div>
                    </div>
                  )}
                </For>
              </div>
            </div>

            {/* メール詳細 */}
            <div style={{ flex: "1", display: "flex", "flex-direction": "column", overflow: "hidden" }}>
              <Show when={selectedEmail()} fallback={
                <div style={{
                  flex: "1", display: "flex", "flex-direction": "column",
                  "align-items": "center", "justify-content": "center",
                  color: "#5A6473", gap: "10px",
                }}>
                  <div style={{ "font-size": "40px", opacity: "0.2" }}>✉</div>
                  <div style={{ "font-size": "13px" }}>メールを選択 (j/k で移動)</div>
                  <div style={{ "font-size": "11px", color: "#3A4451" }}>⌘K でコマンドパレット</div>
                </div>
              }>
                {/* AI 要約 */}
                <SafeAiSummary emailId={selectedEmail()!} />

                {/* メール本文 (iframe) */}
                <div style={{ flex: "1", overflow: "hidden", padding: "0 16px 8px" }}>
                  <div style={{
                    height: "100%", background: "#12181F",
                    "border-radius": "6px", border: "1px solid #1F2833",
                    overflow: "hidden",
                  }}>
                    <iframe
                      srcdoc="<p style='color:#8B96A5;font-family:sans-serif;padding:20px;font-size:13px'>本文を読み込んでいます...</p>"
                      sandbox="allow-popups allow-popups-to-escape-sandbox allow-same-origin"
                      style={{ width: "100%", height: "100%", border: "none" }}
                      title="メール本文"
                    />
                  </div>
                </div>

                {/* アクションバー */}
                <div style={{
                  padding: "8px 16px 12px",
                  display: "flex", gap: "8px",
                  "border-top": "1px solid #1F2833",
                }}>
                  <button onClick={() => {}} style={{ background: "#1A2129", border: "1px solid #2A3441", "border-radius": "6px", padding: "7px 16px", color: "#F5F7FA", "font-size": "12px", cursor: "pointer" }}>
                    返信 (r)
                  </button>
                  <button onClick={archiveSelected} style={{ background: "none", border: "none", color: "#5A6473", "font-size": "12px", cursor: "pointer", padding: "7px 12px" }}>
                    アーカイブ (e)
                  </button>
                  <div style={{ position: "relative" }}>
                    <button
                      onClick={() => setShowSnooze(s => !s)}
                      style={{ background: "none", border: "none", color: "#5A6473", "font-size": "12px", cursor: "pointer", padding: "7px 12px" }}
                    >
                      スヌーズ (h)
                    </button>
                    <Show when={showSnooze()}>
                      <SnoozePanel
                        emailId={selectedEmail()!}
                        onSnooze={(d) => {
                          setEmails(es => es.map(e =>
                            e.id === selectedEmail()
                              ? { ...e, snoozed_until: d.toISOString() }
                              : e
                          ));
                        }}
                        onReplyLater={() => {
                          const id = selectedEmail();
                          if (id) setReplyLaterIds(s => { const n = new Set(s); n.add(id); return n; });
                        }}
                        onClose={() => setShowSnooze(false)}
                      />
                    </Show>
                  </div>
                  <button
                    onClick={() => {
                      const id = selectedEmail();
                      if (id) setReplyLaterIds(s => { const n = new Set(s); n.add(id); return n; });
                    }}
                    style={{ background: "none", border: "none", color: "#5A6473", "font-size": "12px", cursor: "pointer", padding: "7px 12px" }}
                  >
                    📌 Reply Later (l)
                  </button>
                </div>
              </Show>
            </div>
          </Match>
        </Switch>
      </div>

      <style>{`
        * { -webkit-font-smoothing: antialiased; box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #2A3441; border-radius: 2px; }
      `}</style>
    </div>
  );
};

export default KanameApp;
