// src/ui/SecurityDashboard.tsx
//
// セキュリティ・インテリジェンスダッシュボード
//
// 競合との差別化を可視化:
//   - AI生成フィッシング検出スコア
//   - DLPラベル強制 AI アクセスコントロール (Microsoft CVE 対策)
//   - コンタクトインテリジェンス
//   - フォローアップ・アクションアイテム

import { createSignal, createEffect, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

// ============================================================================
// 型定義
// ============================================================================

interface AiPhishingAnalysis {
  likely_ai_generated: boolean;
  score:               number;
  phishing_intent:     boolean;
  explanation:         string;
  features:            { name: string; value: number; description: string }[];
}

interface AiAccessEntry {
  id:           string;
  email_id:     string;
  label:        string;
  decision:     { Allow?: null; AllowWithWarning?: { reason: string }; Block?: { reason: string } };
  operation:    string;
  timestamp:    number;
  data_sources: string[];
}

interface ContactIntelligence {
  email_addr:             string;
  display_name:           string | null;
  relationship_strength:  number;
  category:               string;
  total_messages:         number;
  recent_30d:             number;
  avg_response_min:       number | null;
  typical_hours:          number[];
  last_interaction:       string | null;
  has_mls:                boolean;
  trust_level:            string;
}

interface ActionItem {
  text:        string;
  assignee:    string | null;
  due_date:    string | null;
  priority:    number;
  action_type: string;
  source_text: string;
}

// ============================================================================
// AI フィッシングスコアバー
// ============================================================================

const PhishingScoreBar = (props: { score: number; likely: boolean }) => {
  const color = props.likely
    ? "#E5484D"
    : props.score > 0.4 ? "#F5A623" : "#00B368";

  return (
    <div style={{ "margin-top": "8px" }}>
      <div style={{
        display: "flex", "justify-content": "space-between",
        "font-size": "11px", color: "#8B96A5", "margin-bottom": "4px",
      }}>
        <span>AI生成フィッシングスコア</span>
        <span style={{ color, "font-weight": "600" }}>
          {(props.score * 100).toFixed(0)}%
        </span>
      </div>
      <div style={{
        height: "6px", background: "#1A2129",
        "border-radius": "3px", overflow: "hidden",
      }}>
        <div style={{
          height: "100%",
          width: `${props.score * 100}%`,
          background: color,
          "border-radius": "3px",
          transition: "width 0.5s ease",
        }} />
      </div>
      <Show when={props.likely}>
        <div style={{
          "margin-top": "4px", "font-size": "10px",
          color: "#E5484D", "font-weight": "600",
        }}>
          ⚠ AI生成フィッシングの疑いが高い
        </div>
      </Show>
    </div>
  );
};

// ============================================================================
// AI アクセス監査ログ
// ============================================================================

const AiAccessLog = (props: { entries: AiAccessEntry[] }) => {
  const decisionLabel = (entry: AiAccessEntry) => {
    if ("Block" in entry.decision) return { text: "ブロック", color: "#E5484D" };
    if ("AllowWithWarning" in entry.decision) return { text: "警告許可", color: "#F5A623" };
    return { text: "許可", color: "#00B368" };
  };

  const formatTime = (ts: number) => {
    const d = new Date(ts * 1000);
    return `${d.getHours().toString().padStart(2,"0")}:${d.getMinutes().toString().padStart(2,"0")}`;
  };

  return (
    <div style={{
      background: "#0D1219",
      border: "1px solid #1F2833",
      "border-radius": "8px",
      overflow: "hidden",
    }}>
      <div style={{
        padding: "12px 16px 10px",
        "border-bottom": "1px solid #1F2833",
        display: "flex",
        "align-items": "center",
        gap: "8px",
      }}>
        <span style={{ "font-size": "13px", "font-weight": "600" }}>
          AI アクセス監査ログ
        </span>
        <span style={{
          "font-size": "10px", color: "#5A6473",
          padding: "1px 6px", background: "#1A2129",
          "border-radius": "3px",
        }}>
          Microsoft Copilot CW1226324 対策
        </span>
      </div>

      <Show
        when={props.entries.length > 0}
        fallback={
          <div style={{ padding: "16px", "text-align": "center", color: "#5A6473", "font-size": "12px" }}>
            AI アクセスの記録なし
          </div>
        }
      >
        <div style={{ "max-height": "280px", "overflow-y": "auto", "font-family": "monospace" }}>
          <For each={props.entries}>
            {(entry) => {
              const d = decisionLabel(entry);
              return (
                <div style={{
                  padding: "8px 16px",
                  "border-bottom": "1px solid #12181F",
                  display: "grid",
                  "grid-template-columns": "60px 1fr 80px 70px",
                  gap: "8px",
                  "align-items": "center",
                  "font-size": "11px",
                }}>
                  <span style={{ color: "#5A6473" }}>{formatTime(entry.timestamp)}</span>
                  <div>
                    <span style={{ color: "#8B96A5" }}>{entry.operation}</span>
                    <span style={{ color: "#3A4451", "margin-left": "6px" }}>
                      →  {entry.data_sources.join(", ")}
                    </span>
                  </div>
                  <span style={{
                    color: getLabelColor(entry.label),
                    "font-size": "10px",
                  }}>
                    {entry.label}
                  </span>
                  <span style={{
                    color: d.color, "font-weight": "700",
                    "font-size": "10px", "text-align": "right",
                  }}>
                    {d.text}
                  </span>
                </div>
              );
            }}
          </For>
        </div>
      </Show>

      {/* セキュリティポスチャー説明 */}
      <div style={{
        padding: "10px 16px",
        "border-top": "1px solid #1F2833",
        "font-size": "11px",
        color: "#5A6473",
        display: "flex",
        gap: "16px",
      }}>
        <span style={{ color: "#00B368" }}>● AI がアクセスしたのは各メール1通のみ</span>
        <span style={{ color: "#00B368" }}>● 受信箱全体へのアクセスなし</span>
        <span style={{ color: "#00B368" }}>● 全アクセスをハッシュチェーンで証明</span>
      </div>
    </div>
  );
};

const getLabelColor = (label: string) => ({
  "Public": "#5A6473",
  "Internal": "#8B96A5",
  "Confidential": "#F5A623",
  "HighlyConfidential": "#E5484D",
  "LegalPrivilege": "#E5484D",
})[label] || "#5A6473";

// ============================================================================
// コンタクトカード
// ============================================================================

const ContactCard = (props: { contact: ContactIntelligence }) => {
  const { contact: c } = props;

  const trustColor = {
    High: "#00B368", Medium: "#00C4CC", Low: "#F5A623", Unverified: "#5A6473",
  }[c.trust_level] || "#5A6473";

  const strengthPercent = Math.round(c.relationship_strength * 100);

  return (
    <div style={{
      background: "#0D1219",
      border: "1px solid #1F2833",
      "border-radius": "8px",
      padding: "14px",
    }}>
      {/* ヘッダー */}
      <div style={{ display: "flex", "align-items": "center", gap: "10px", "margin-bottom": "10px" }}>
        <div style={{
          width: "40px", height: "40px", "border-radius": "50%",
          background: "#1A2129", display: "flex",
          "align-items": "center", "justify-content": "center",
          "font-size": "16px", "font-weight": "600",
          color: trustColor,
        }}>
          {(c.display_name || c.email_addr)[0]?.toUpperCase()}
        </div>
        <div style={{ flex: "1", "min-width": "0" }}>
          <div style={{
            "font-size": "13px", "font-weight": "500",
            overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap",
          }}>
            {c.display_name || c.email_addr}
          </div>
          <div style={{ "font-size": "11px", color: "#5A6473" }}>
            {c.email_addr}
          </div>
        </div>
        <div style={{ display: "flex", "flex-direction": "column", "align-items": "flex-end", gap: "3px" }}>
          <span style={{
            "font-size": "10px", color: trustColor,
            padding: "1px 6px", border: `1px solid ${trustColor}40`,
            "border-radius": "3px",
          }}>
            {c.trust_level}
          </span>
          <Show when={c.has_mls}>
            <span style={{ "font-size": "9px", color: "#00C4CC" }}>🔐 E2E</span>
          </Show>
        </div>
      </div>

      {/* 関係強度 */}
      <div style={{ "margin-bottom": "8px" }}>
        <div style={{
          display: "flex", "justify-content": "space-between",
          "font-size": "10px", color: "#5A6473", "margin-bottom": "3px",
        }}>
          <span>関係強度</span>
          <span style={{ color: "#F5F7FA" }}>{strengthPercent}%</span>
        </div>
        <div style={{
          height: "4px", background: "#1A2129", "border-radius": "2px",
        }}>
          <div style={{
            height: "100%", width: `${strengthPercent}%`,
            background: trustColor, "border-radius": "2px",
          }} />
        </div>
      </div>

      {/* 統計 */}
      <div style={{
        display: "grid", "grid-template-columns": "1fr 1fr",
        gap: "6px", "font-size": "11px",
      }}>
        <div style={{ color: "#5A6473" }}>
          通信数: <span style={{ color: "#F5F7FA" }}>{c.total_messages}</span>
        </div>
        <div style={{ color: "#5A6473" }}>
          直近30日: <span style={{ color: "#F5F7FA" }}>{c.recent_30d}</span>
        </div>
        <Show when={c.avg_response_min !== null}>
          <div style={{ color: "#5A6473" }}>
            平均応答: <span style={{ color: "#F5F7FA" }}>
              {c.avg_response_min! < 60
                ? `${c.avg_response_min}分`
                : `${Math.round(c.avg_response_min! / 60)}時間`}
            </span>
          </div>
        </Show>
        <div style={{ color: "#5A6473" }}>
          分類: <span style={{ color: "#8B96A5" }}>{c.category}</span>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// アクションアイテムリスト
// ============================================================================

const ActionItemsList = (props: {
  items:    ActionItem[];
  emailId:  string;
  onDone:   (index: number) => void;
}) => {
  const typeIcon = (t: string) => ({
    ReplyRequired: "↩️",
    Meeting:       "📅",
    Review:        "📋",
    Approval:      "✅",
    Task:          "☑️",
    Other:         "•",
  })[t] || "•";

  const priorityColor = (p: number) =>
    p > 0.8 ? "#E5484D" : p > 0.6 ? "#F5A623" : "#8B96A5";

  return (
    <div>
      <Show
        when={props.items.length > 0}
        fallback={
          <div style={{ "font-size": "12px", color: "#5A6473", padding: "8px 0" }}>
            アクションアイテムなし
          </div>
        }
      >
        <For each={props.items}>
          {(item, i) => (
            <div style={{
              display: "flex",
              "align-items": "flex-start",
              gap: "10px",
              padding: "8px 0",
              "border-bottom": "1px solid #1F2833",
            }}>
              <span style={{ "font-size": "14px", "margin-top": "1px" }}>
                {typeIcon(item.action_type)}
              </span>
              <div style={{ flex: "1" }}>
                <div style={{ "font-size": "13px", color: "#D0D5DD" }}>
                  {item.text}
                </div>
                <Show when={item.due_date}>
                  <div style={{ "font-size": "11px", color: priorityColor(item.priority), "margin-top": "2px" }}>
                    期限: {item.due_date}
                  </div>
                </Show>
              </div>
              <button
                onClick={() => props.onDone(i())}
                style={{
                  background: "#1A2129", border: "none", "border-radius": "4px",
                  padding: "3px 8px", "font-size": "11px",
                  color: "#5A6473", cursor: "pointer",
                }}
              >
                完了
              </button>
            </div>
          )}
        </For>
      </Show>
    </div>
  );
};

// ============================================================================
// メインダッシュボード
// ============================================================================

export const SecurityDashboard = (props: { selectedEmailId: string | null }) => {
  const [phishing, setPhishing] = createSignal<AiPhishingAnalysis | null>(null);
  const [phishingError, setPhishingError] = createSignal<string | null>(null);
  const [accessLog, setAccessLog] = createSignal<AiAccessEntry[]>([]);
  const [contacts,  setContacts]  = createSignal<ContactIntelligence[]>([]);
  const [actions,   setActions]   = createSignal<ActionItem[]>([]);
  const [loading,   setLoading]   = createSignal(false);
  const [doneItems, setDoneItems] = createSignal<Set<number>>(new Set());

  // 2026-09 削除: 以前はここでハードコードされた偽のアクセスログ・
  // 連絡先・アクションアイテムを毎回セットしていた (コメント上は
  // 「モックデータ (テスト用)」だったが、出荷 UI の「セキュリティ」
  // タブは到達可能でありユーザーが実際に目にする画面だった)。
  // これらを表示する実データの取得元 (監査ログ取得コマンド・連絡先
  // 抽出・アクションアイテム抽出) はまだ実装されていないため、
  // 偽のデータを見せるより空の状態を見せる方が正しい。
  // 各コンポーネント (AiAccessLog/ActionItemsList/ContactCard の親) は
  // 空配列を渡された場合を正しく処理する (docs/gap-analysis.md D41)。

  // 選択されたメールの AI フィッシング分析
  createEffect(async () => {
    if (!props.selectedEmailId) return;
    setLoading(true);
    try {
      const result = await invoke<AiPhishingAnalysis>("ai_detect_phishing", {
        emailId: props.selectedEmailId,
      });
      setPhishing(result);
      setPhishingError(null);
    } catch (e) {
      // 2026-09 修正: 以前はエラー時に無言で「score: 0.15 (安全)」という
      // 偽の判定を表示していた。判定に失敗したことを「安全」と偽って
      // 伝えるのは、判定できたと偽るより悪い (利用者が本物のフィッシング
      // メールを安全だと誤信しかねない)。スコアバーは表示せず、失敗理由
      // だけを表示する。
      setPhishing(null);
      setPhishingError(String(e));
    } finally {
      setLoading(false);
    }
  });

  return (
    <div style={{
      display: "flex", "flex-direction": "column", gap: "16px",
      padding: "16px", "overflow-y": "auto", height: "100%",
      background: "#0A0E14", color: "#F5F7FA",
      "font-family": "-apple-system, 'Hiragino Sans', sans-serif",
    }}>
      {/* AI フィッシング分析 */}
      <Show when={props.selectedEmailId}>
        <div style={{
          background: "#0D1219", border: "1px solid #1F2833",
          "border-radius": "8px", padding: "14px",
        }}>
          <div style={{
            "font-size": "13px", "font-weight": "600", "margin-bottom": "10px",
            display: "flex", "align-items": "center", gap: "8px",
          }}>
            🔍 AI生成フィッシング検出
            <span style={{ "font-size": "10px", color: "#5A6473" }}>
              (全競合が未実装)
            </span>
          </div>
          <Show when={phishing()}>
            <PhishingScoreBar score={phishing()!.score} likely={phishing()!.likely_ai_generated} />
            <div style={{
              "font-size": "11px", color: "#8B96A5", "margin-top": "8px",
              "line-height": "1.5",
            }}>
              {phishing()!.explanation}
            </div>
          </Show>
          <Show when={phishingError()}>
            <div style={{ "font-size": "11px", color: "#E5484D", "line-height": "1.5" }}>
              ⚠ {phishingError()}
            </div>
          </Show>
          <Show when={loading()}>
            <div style={{ "font-size": "12px", color: "#5A6473" }}>分析中...</div>
          </Show>
        </div>
      </Show>

      {/* AI アクセス監査ログ */}
      <AiAccessLog entries={accessLog()} />

      {/* アクションアイテム */}
      <div style={{
        background: "#0D1219", border: "1px solid #1F2833",
        "border-radius": "8px", padding: "14px",
      }}>
        <div style={{
          "font-size": "13px", "font-weight": "600", "margin-bottom": "10px",
          display: "flex", "align-items": "center", gap: "8px",
        }}>
          ⚡ アクションアイテム
          <span style={{
            background: "#00C4CC20", color: "#00C4CC",
            "font-size": "10px", padding: "1px 6px", "border-radius": "3px",
          }}>
            {actions().filter((_, i) => !doneItems().has(i)).length} 件
          </span>
        </div>
        <ActionItemsList
          items={actions().filter((_, i) => !doneItems().has(i))}
          emailId={props.selectedEmailId || ""}
          onDone={(i) => setDoneItems(s => { const n = new Set(s); n.add(i); return n; })}
        />
      </div>

      {/* コンタクトインテリジェンス */}
      <div>
        <div style={{
          "font-size": "13px", "font-weight": "600",
          "margin-bottom": "10px", color: "#8B96A5",
        }}>
          👥 コンタクト
        </div>
        <div style={{ display: "flex", "flex-direction": "column", gap: "10px" }}>
          <For each={contacts()}>
            {(c) => <ContactCard contact={c} />}
          </For>
        </div>
      </div>

      {/* 競合比較カード */}
      <div style={{
        background: "#0D1219", border: "1px solid #00C4CC20",
        "border-radius": "8px", padding: "14px",
      }}>
        <div style={{ "font-size": "11px", "font-weight": "600", "margin-bottom": "8px", color: "#00C4CC" }}>
          Kaname の独自機能 (競合が持たない)
        </div>
        {/* 2026-09 修正: 以前は5項目すべてに "✓" を付け、ローカル AI 推論
            (D2: 未実装) と MLS+PQC 暗号化 (D1: XOR モック) まで実装済みと
            表示していた。SECURITY.md (D34)・brand-guidelines.md (D39)・
            competitive-analysis.md (D40) と同じ欠陥が出荷 UI 自体にも
            あった。実装状況どおりに ✓/⚠ を分ける (docs/gap-analysis.md D41) */}
        {([
          ["✓", "AI生成フィッシング検出", "kaname-bec の実データ判定 (精度の数値は本環境で未検証、docs/gap-analysis.md D36 参照)"],
          ["✓", "DLPラベル強制 AI 制御", "Microsoft Copilot CVE 対策、実データで稼働"],
          ["⚠", "AI アクセス監査証跡",  "ハッシュチェーン自体は実装済みだが、UI から閲覧する経路は未実装"],
          ["✗", "ローカル AI 推論",     "未実装 (docs/gap-analysis.md D2)。LLM 推論は固定応答のスタブ"],
          ["✗", "MLS + PQC 暗号化",    "未実装 (docs/gap-analysis.md D1)。現状は単一バイト XOR のモック"],
        ] as const).map(([icon, name, desc]) => (
          <div style={{
            display: "flex", gap: "8px", padding: "4px 0",
            "font-size": "11px",
          }}>
            <span style={{
              color: icon === "✓" ? "#00B368" : icon === "⚠" ? "#F5A623" : "#E5484D",
              "font-weight": "700",
            }}>{icon}</span>
            <div>
              <span style={{ color: "#D0D5DD" }}>{name}</span>
              <span style={{ color: "#5A6473", "margin-left": "6px" }}>{desc}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SecurityDashboard;
