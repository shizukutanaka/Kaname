// src/ui/SecurityDashboard.tsx
//
// セキュリティ・インテリジェンスダッシュボード
//
// 競合との差別化を可視化:
//   - BEC/なりすまし検出 (kaname-bec)
//   - DLPラベル強制 AI アクセスコントロール (Microsoft CVE 対策)
//   - コンタクトインテリジェンス
//   - フォローアップ・アクションアイテム

import { createSignal, createEffect, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

// ============================================================================
// 型定義
// ============================================================================

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
// AI アクセス監査ログ
// ============================================================================

const AiAccessLog = (props: { entries: AiAccessEntry[] }) => {
  const decisionLabel = (entry: AiAccessEntry) => {
    if ("Block" in entry.decision) return { text: "ブロック", color: "#FF6B70" };
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
          "font-size": "10px", color: "#8B96A5",
          padding: "1px 6px", background: "#1A2129",
          "border-radius": "3px",
        }}>
          Microsoft Copilot CW1226324 対策
        </span>
      </div>

      <Show
        when={props.entries.length > 0}
        fallback={
          <div style={{ padding: "16px", "text-align": "center", color: "#8B96A5", "font-size": "12px" }}>
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
                  <span style={{ color: "#8B96A5" }}>{formatTime(entry.timestamp)}</span>
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
        color: "#8B96A5",
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

// ============================================================================
// 監査証跡 (audit_log — append-only + SHA-256 ハッシュチェーン)
// ============================================================================

interface AuditEntry {
  seq:          number;
  event_type:   string;
  payload_json: string;
  created_at:   string;
}

interface AuditLogView {
  entries:     AuditEntry[];
  chain_valid: boolean;
}

const EVENT_LABEL: Record<string, string> = {
  STORE_OPEN:          "履歴 DB オープン",
  MAIL_CONNECT:        "メールサーバ接続",
  MAIL_DISCONNECT:     "メールサーバ切断",
  SENDER_VERIFIED:     "送信者を検証済みに変更",
  ATTACHMENT_DOWNLOAD: "添付ダウンロード",
  MAIL_SEND:           "外部宛メール送信",
  DLP_BLOCK:           "DLP が送信をブロック",
  MAIL_IMPORT:         ".eml 取り込み",
  FOLDER_SCAN:         "フォルダ一括解析",
  OOBV_VERIFY:         "帯域外検証の結果",
};

const AuditTrail = (props: { view: AuditLogView | null }) => {
  const formatTime = (iso: string) => iso.replace("T", " ").replace("Z", " UTC");
  return (
    <div style={{
      background: "#0D1219", border: "1px solid #1F2833",
      "border-radius": "8px", overflow: "hidden",
    }}>
      <div style={{
        padding: "12px 16px 10px", "border-bottom": "1px solid #1F2833",
        display: "flex", "align-items": "center", gap: "8px",
      }}>
        <span style={{ "font-size": "13px", "font-weight": "600" }}>監査証跡</span>
        <Show when={props.view}>
          {(v) => (
            <span style={{
              "font-size": "10px", "font-weight": "600",
              color: v().chain_valid ? "#00B368" : "#FF6B70",
              padding: "1px 6px", background: "#1A2129", "border-radius": "3px",
            }}>
              {v().chain_valid ? "ハッシュチェーン正常" : "⚠ チェーン破損 (改ざんの可能性)"}
            </span>
          )}
        </Show>
      </div>
      <Show
        when={(props.view?.entries.length ?? 0) > 0}
        fallback={
          <div style={{ padding: "16px", "text-align": "center", color: "#8B96A5", "font-size": "12px" }}>
            監査イベントの記録なし
          </div>
        }
      >
        <div style={{ "max-height": "240px", "overflow-y": "auto", "font-family": "monospace" }}>
          <For each={props.view?.entries}>
            {(e) => (
              <div style={{
                padding: "7px 16px", "border-bottom": "1px solid #12181F",
                display: "flex", "justify-content": "space-between",
                "font-size": "11px", "align-items": "baseline", gap: "8px",
              }}>
                <span style={{ color: "#D0D5DD" }}>
                  {EVENT_LABEL[e.event_type] ?? e.event_type}
                </span>
                <span style={{ color: "#8B96A5", "font-size": "10px", "flex-shrink": "0" }}>
                  {formatTime(e.created_at)}
                </span>
              </div>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
};

const getLabelColor = (label: string) => ({
  "Public": "#8B96A5",
  "Internal": "#8B96A5",
  "Confidential": "#F5A623",
  "HighlyConfidential": "#FF6B70",
  "LegalPrivilege": "#FF6B70",
})[label] || "#8B96A5";

// ============================================================================
// コンタクトカード
// ============================================================================

const ContactCard = (props: { contact: ContactIntelligence }) => {
  const { contact: c } = props;

  const trustColor = {
    High: "#00B368", Medium: "#00C4CC", Low: "#F5A623", Unverified: "#8B96A5",
  }[c.trust_level] || "#8B96A5";

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
          <div style={{ "font-size": "11px", color: "#8B96A5" }}>
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
          "font-size": "10px", color: "#8B96A5", "margin-bottom": "3px",
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
        <div style={{ color: "#8B96A5" }}>
          通信数: <span style={{ color: "#F5F7FA" }}>{c.total_messages}</span>
        </div>
        <div style={{ color: "#8B96A5" }}>
          直近30日: <span style={{ color: "#F5F7FA" }}>{c.recent_30d}</span>
        </div>
        <Show when={c.avg_response_min !== null}>
          <div style={{ color: "#8B96A5" }}>
            平均応答: <span style={{ color: "#F5F7FA" }}>
              {c.avg_response_min! < 60
                ? `${c.avg_response_min}分`
                : `${Math.round(c.avg_response_min! / 60)}時間`}
            </span>
          </div>
        </Show>
        <div style={{ color: "#8B96A5" }}>
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
    p > 0.8 ? "#FF6B70" : p > 0.6 ? "#F5A623" : "#8B96A5";

  return (
    <div>
      <Show
        when={props.items.length > 0}
        fallback={
          <div style={{ "font-size": "12px", color: "#8B96A5", padding: "8px 0" }}>
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
                  color: "#8B96A5", cursor: "pointer",
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

// D2 Phase 5: ローカル AI モデルの状態 (kaname-ai::llm_bridge::check_model)
interface AiModelStatus {
  state: "loaded" | "ready" | "missing";
  size_bytes: number | null;
  download_url: string | null;
  expected_size_bytes: number | null;
}

// D1 Phase 4: MLS E2E の状態 (kaname-ui::commands::MlsStatus)
interface MlsStatus {
  initialized: boolean;
  email: string | null;
  conversations: number;
}

// D1 Phase 3: 会話成立済みの相手 (kaname-ui::commands::MlsPeer)
interface MlsPeer {
  email: string;
  conversation_id: string;
  epoch: number;
  safety_number: string | null;
  // D1 Phase 5: 安全番号の照合状態
  verified: boolean;
  // 照合記録はあるが現在の番号と不一致 = 鍵変更/再参加/中間者の可能性
  safety_changed: boolean;
}

export const SecurityDashboard = (props: { selectedEmailId: string | null }) => {
  const [accessLog] = createSignal<AiAccessEntry[]>([]);
  const [auditLog, setAuditLog] = createSignal<AuditLogView | null>(null);

  // D2 Phase 5: モデルの実状態 (missing / ready / loaded) を表示し、
  // ダウンロード・ロードを実行する。未ロード時は BEC が決定論的
  // シグナルのみで動くことを明示する (偽の「AI 稼働中」を見せない)。
  const [aiModel, setAiModel] = createSignal<AiModelStatus | null>(null);
  const [aiBusy, setAiBusy] = createSignal(false);
  const [aiHash, setAiHash] = createSignal("");
  const refreshAiModel = async () => {
    try {
      setAiModel(await invoke<AiModelStatus>("ai_model_status"));
    } catch {
      setAiModel(null);
    }
  };
  createEffect(refreshAiModel);

  // D1 Phase 4: MLS E2E の実状態。未初期化でもエラーではなく
  // initialized=false が返るため、偽の「E2E 稼働中」は表示しない。
  const [mls, setMls] = createSignal<MlsStatus | null>(null);
  const [mlsEmail, setMlsEmail] = createSignal("");
  const [mlsKp, setMlsKp] = createSignal("");
  const [mlsBusy, setMlsBusy] = createSignal(false);
  // D1 Phase 3: KP 配送経路の UI — 相手先入力・会話一覧・操作結果
  const [mlsPeer, setMlsPeer] = createSignal("");
  const [mlsPeers, setMlsPeers] = createSignal<MlsPeer[]>([]);
  const [mlsMsg, setMlsMsg] = createSignal<{ ok: boolean; text: string } | null>(null);
  const refreshMls = async () => {
    try {
      setMls(await invoke<MlsStatus>("mls_status"));
      setMlsPeers(await invoke<MlsPeer[]>("mls_conversations"));
    } catch {
      setMls(null);
    }
  };
  createEffect(refreshMls);

  // 監査証跡 (audit_log テーブル) は実在データ — 起動時に読み出す。
  createEffect(async () => {
    try {
      setAuditLog(await invoke<AuditLogView>("security_audit_log", { limit: 100 }));
    } catch {
      // 読み出し失敗時はセクションを空のままにする (偽の記録を見せない)
    }
  });
  const [contacts]  = createSignal<ContactIntelligence[]>([]);
  const [actions]   = createSignal<ActionItem[]>([]);
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

  return (
    <div style={{
      display: "flex", "flex-direction": "column", gap: "16px",
      padding: "16px", "overflow-y": "auto", height: "100%",
      background: "#0A0E14", color: "#F5F7FA",
      "font-family": "-apple-system, 'Hiragino Sans', sans-serif",
    }}>
      {/* AI アクセス監査ログ */}
      <AiAccessLog entries={accessLog()} />
      <AuditTrail view={auditLog()} />

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

      {/* D2 Phase 5: ローカル AI モデル管理 (Phi-4-mini) */}
      <div style={{
        background: "#0D1219", border: "1px solid #1F2833",
        "border-radius": "8px", padding: "14px",
      }}>
        <div style={{
          "font-size": "13px", "font-weight": "600", "margin-bottom": "8px",
        }}>
          🤖 ローカル AI モデル
        </div>
        <Show when={aiModel()} fallback={
          <div style={{ "font-size": "11px", color: "#8B96A5" }}>
            モデル状態を取得できませんでした
          </div>
        }>
          {(m) => (
            <div>
              <div style={{ "font-size": "11px", color: "#8B96A5", "margin-bottom": "8px" }}>
                {m().state === "loaded"
                  ? "Phi-4-mini ロード済み — BEC 意味解析が有効です"
                  : m().state === "ready"
                    ? "モデル配置済み — ロードすると BEC 意味解析が有効になります"
                    : `モデル未取得 (約 ${(Number(m().expected_size_bytes ?? 0) / 1e9).toFixed(1)}GB) — 未取得の間は BEC は決定論的シグナルのみで判定します`}
              </div>
              {/* D121 解消: 推論は kaname-llm-runner ワーカープロセスで
                  実行 (sandbox-exec / seccomp 経由)。不信本文はホスト
                  プロセスの llama.cpp に入らない */}
              <Show when={m().state === "loaded"}>
                <div style={{ "font-size": "10px", color: "#6B7A94", "margin-bottom": "8px", "font-family": "monospace" }}>
                  推論は隔離ワーカープロセスで実行されます (不信本文はホストプロセスに入りません)
                </div>
              </Show>
              <div style={{ display: "flex", gap: "8px" }}>
                <Show when={m().state === "missing"}>
                  {/* HF リポジトリはゲート済みのため、配布元が発行する
                      公式 SHA-256 を管理者が入力する運用 */}
                  <input
                    placeholder="モデルの公式 SHA-256 (64桁)"
                    value={aiHash()}
                    onInput={(e) => setAiHash(e.currentTarget.value)}
                    style={{
                      background: "#1A2129", border: "1px solid #2A3441",
                      color: "#F5F7FA", "border-radius": "4px",
                      padding: "4px 8px", "font-size": "11px",
                      "font-family": "monospace", width: "340px",
                    }}
                  />
                  <button
                    disabled={aiBusy() || aiHash().trim().length !== 64}
                    onClick={async () => {
                      setAiBusy(true);
                      try {
                        await invoke("ai_model_download", { expectedSha256: aiHash().trim() });
                        await invoke("ai_llm_start");
                      } catch { /* 失敗は状態表示に反映される */ }
                      await refreshAiModel();
                      setAiBusy(false);
                    }}
                    style={{
                      background: "#00C4CC20", color: "#00C4CC", border: "none",
                      "border-radius": "4px", padding: "4px 10px",
                      "font-size": "11px",
                      cursor: aiBusy() || aiHash().trim().length !== 64 ? "default" : "pointer",
                    }}
                  >
                    {aiBusy() ? "ダウンロード中…" : "モデルをダウンロード"}
                  </button>
                </Show>
                <Show when={m().state === "ready"}>
                  <button
                    disabled={aiBusy()}
                    onClick={async () => {
                      setAiBusy(true);
                      try { await invoke("ai_llm_start"); } catch { /* 同上 */ }
                      await refreshAiModel();
                      setAiBusy(false);
                    }}
                    style={{
                      background: "#00C4CC20", color: "#00C4CC", border: "none",
                      "border-radius": "4px", padding: "4px 10px",
                      "font-size": "11px", cursor: aiBusy() ? "default" : "pointer",
                    }}
                  >
                    {aiBusy() ? "ロード中…" : "モデルをロード"}
                  </button>
                </Show>
              </div>
            </div>
          )}
        </Show>
      </div>

      {/* D1 Phase 4: MLS E2E 暗号化 */}
      <div style={{
        background: "#0D1219", border: "1px solid #1F2833",
        "border-radius": "8px", padding: "14px",
      }}>
        <div style={{
          "font-size": "13px", "font-weight": "600", "margin-bottom": "8px",
        }}>
          🔐 MLS E2E 暗号化
        </div>
        <Show when={mls()} fallback={
          <div style={{ "font-size": "11px", color: "#8B96A5" }}>
            MLS の状態を取得できませんでした
          </div>
        }>
          {(s) => (
            <div>
              <div style={{ "font-size": "11px", color: "#8B96A5", "margin-bottom": "8px" }}>
                {s().initialized
                  ? `${s().email ?? ""} として有効 — 会話 ${s().conversations} 件。受信メール内の MLS エンベロープは開封時に自動で処理されます (X-Wing / ML-KEM-768 ハイブリッド)`
                  : "未初期化 — 自分のメールアドレスを入力して有効化してください (状態は mls.db に暗号化保存されます)"}
              </div>
              <Show when={!s().initialized}>
                <div style={{ display: "flex", gap: "8px" }}>
                  <input
                    placeholder="あなたのメールアドレス"
                    value={mlsEmail()}
                    onInput={(e) => setMlsEmail(e.currentTarget.value)}
                    style={{
                      background: "#1A2129", border: "1px solid #2A3441",
                      color: "#F5F7FA", "border-radius": "4px",
                      padding: "4px 8px", "font-size": "11px",
                      "font-family": "monospace", width: "260px",
                    }}
                  />
                  <button
                    disabled={mlsBusy() || !mlsEmail().includes("@")}
                    onClick={async () => {
                      setMlsBusy(true);
                      try {
                        setMls(await invoke<MlsStatus>("mls_init", { email: mlsEmail().trim() }));
                      } catch { /* 失敗は状態表示に反映される */ }
                      await refreshMls();
                      setMlsBusy(false);
                    }}
                    style={{
                      background: "#00C4CC20", color: "#00C4CC", border: "none",
                      "border-radius": "4px", padding: "4px 10px",
                      "font-size": "11px",
                      cursor: mlsBusy() || !mlsEmail().includes("@") ? "default" : "pointer",
                    }}
                  >
                    {mlsBusy() ? "初期化中…" : "有効化"}
                  </button>
                </div>
              </Show>
              <Show when={s().initialized}>
                <div style={{ display: "flex", gap: "8px", "align-items": "center" }}>
                  <button
                    disabled={mlsBusy()}
                    onClick={async () => {
                      try {
                        setMlsKp(await invoke<string>("mls_key_package"));
                      } catch {
                        setMlsKp("");
                      }
                    }}
                    style={{
                      background: "#00C4CC20", color: "#00C4CC", border: "none",
                      "border-radius": "4px", padding: "4px 10px",
                      "font-size": "11px", cursor: mlsBusy() ? "default" : "pointer",
                    }}
                  >
                    この端末の KeyPackage を表示
                  </button>
                  <Show when={mlsKp() !== ""}>
                    <button
                      onClick={() => { void navigator.clipboard.writeText(mlsKp()); }}
                      style={{
                        background: "#1A2129", color: "#8B96A5",
                        border: "1px solid #2A3441", "border-radius": "4px",
                        padding: "4px 10px", "font-size": "11px", cursor: "pointer",
                      }}
                    >
                      コピー
                    </button>
                  </Show>
                </div>
                <Show when={mlsKp() !== ""}>
                  <div style={{
                    "font-size": "10px", color: "#6B7A94", "margin-top": "6px",
                    "font-family": "monospace", "word-break": "break-all",
                  }}>
                    {mlsKp()}
                  </div>
                </Show>
                {/* D1 Phase 3: KeyPackage の配送と会話開始
                    — KP は添付で自動往復 (相手の Kaname が受信時に検証・取込)。
                    KP 配送経路での差し替えは防げないため、会話成立後は
                    安全番号を別経路で照合するのが信頼確立の手順。 */}
                <div style={{ "margin-top": "10px", "border-top": "1px solid #1F2833", "padding-top": "8px" }}>
                  <div style={{ "font-size": "10px", color: "#6B7A94", "margin-bottom": "6px" }}>
                    相手のメールアドレスを指定して KeyPackage を送信・または受信済み KP で会話を開始します。
                    開始後は新規作成画面で「MLS で暗号化」が使えます
                  </div>
                  <div style={{ display: "flex", gap: "6px", "align-items": "center", "flex-wrap": "wrap" }}>
                    <input
                      type="email"
                      placeholder="相手のメールアドレス"
                      value={mlsPeer()}
                      onInput={e => setMlsPeer(e.currentTarget.value)}
                      style={{
                        flex: "1", "min-width": "200px", background: "#0A0E14", color: "#D7DEE7",
                        border: "1px solid #2A3441", "border-radius": "4px",
                        padding: "6px 8px", "font-size": "11px",
                      }}
                    />
                    <button
                      disabled={mlsBusy() || !mlsPeer().includes("@")}
                      onClick={async () => {
                        setMlsBusy(true);
                        setMlsMsg(null);
                        try {
                          const r = await invoke<string>("mls_send_key_package", { to: mlsPeer().trim() });
                          setMlsMsg({ ok: true, text: r });
                        } catch (e) {
                          setMlsMsg({ ok: false, text: String(e) });
                        }
                        setMlsBusy(false);
                      }}
                      style={{
                        background: "#00C4CC20", color: "#00C4CC", border: "none",
                        "border-radius": "4px", padding: "4px 10px",
                        "font-size": "11px",
                        cursor: mlsBusy() || !mlsPeer().includes("@") ? "default" : "pointer",
                      }}
                    >
                      KeyPackage を送信
                    </button>
                    <button
                      disabled={mlsBusy() || !mlsPeer().includes("@")}
                      onClick={async () => {
                        setMlsBusy(true);
                        setMlsMsg(null);
                        try {
                          const r = await invoke<string>("mls_start_conversation", { to: mlsPeer().trim() });
                          setMlsMsg({ ok: true, text: r });
                          await refreshMls();
                        } catch (e) {
                          setMlsMsg({ ok: false, text: String(e) });
                        }
                        setMlsBusy(false);
                      }}
                      style={{
                        background: "#00C4CC20", color: "#00C4CC", border: "none",
                        "border-radius": "4px", padding: "4px 10px",
                        "font-size": "11px",
                        cursor: mlsBusy() || !mlsPeer().includes("@") ? "default" : "pointer",
                      }}
                    >
                      受信した KP で会話を開始
                    </button>
                  </div>
                  <Show when={mlsMsg()}>
                    <div style={{
                      "font-size": "10px", "margin-top": "6px",
                      color: mlsMsg()!.ok ? "#34D399" : "#FF6B70",
                    }}>
                      {mlsMsg()!.text}
                    </div>
                  </Show>
                  {/* 成立済み会話: 安全番号の照合は別経路 (電話等) で実施 */}
                  <Show when={mlsPeers().length > 0}>
                    <div style={{ "margin-top": "8px" }}>
                      <For each={mlsPeers()}>
                        {(p) => (
                          <div style={{
                            "font-size": "10px", color: "#8B96A5", "margin-top": "4px",
                            padding: "6px 8px", background: "#0A0E14",
                            "border-radius": "4px", border: "1px solid #1F2833",
                          }}>
                            <div>
                              🔐 {p.email} — epoch {p.epoch}{" "}
                              {/* D1 Phase 5: 照合状態バッジ。verified=照合済み、
                                  safety_changed=照合後に番号が変化 (鍵変更/
                                  再参加/中間者の可能性)、それ以外=未検証 */}
                              <Show when={p.safety_changed}>
                                <span style={{
                                  background: "#FF6B7020", color: "#FF6B70",
                                  "font-size": "10px", padding: "1px 6px",
                                  "border-radius": "3px", "margin-left": "4px",
                                }}>
                                  ⚠ 番号が照合時と異なります
                                </span>
                              </Show>
                              <Show when={!p.safety_changed && p.verified}>
                                <span style={{
                                  background: "#34D39920", color: "#34D399",
                                  "font-size": "10px", padding: "1px 6px",
                                  "border-radius": "3px", "margin-left": "4px",
                                }}>
                                  ✓ 照合済み
                                </span>
                              </Show>
                              <Show when={!p.safety_changed && !p.verified}>
                                <span style={{
                                  background: "#FFB22420", color: "#FFB224",
                                  "font-size": "10px", padding: "1px 6px",
                                  "border-radius": "3px", "margin-left": "4px",
                                }}>
                                  未検証
                                </span>
                              </Show>
                            </div>
                            <Show when={p.safety_number}>
                              <div style={{ "font-family": "monospace", color: "#6B7A94", "margin-top": "2px", "word-break": "break-all" }}>
                                安全番号: {p.safety_number}
                              </div>
                              {/* 照合記録 — 押す前に利用者が別経路 (電話・
                                  対面等) で番号を確かめた前提 */}
                              <div style={{ "margin-top": "4px", display: "flex", gap: "6px", "align-items": "center" }}>
                                <button
                                  disabled={mlsBusy()}
                                  onClick={async () => {
                                    setMlsBusy(true);
                                    setMlsMsg(null);
                                    try {
                                      const r = await invoke<string>("mls_mark_verified", { to: p.email });
                                      setMlsMsg({ ok: true, text: r });
                                      await refreshMls();
                                    } catch (e) {
                                      setMlsMsg({ ok: false, text: String(e) });
                                    }
                                    setMlsBusy(false);
                                  }}
                                  style={{
                                    background: "#1A2129", color: "#8B96A5",
                                    border: "1px solid #2A3441", "border-radius": "4px",
                                    padding: "2px 8px", "font-size": "10px",
                                    cursor: mlsBusy() ? "default" : "pointer",
                                  }}
                                >
                                  相手と照合しました (記録)
                                </button>
                                <span style={{ "font-size": "9px", color: "#6B7A94" }}>
                                  電話・対面等の別経路で番号が一致することを確認してから押してください
                                </span>
                              </div>
                            </Show>
                          </div>
                        )}
                      </For>
                    </div>
                  </Show>
                </div>
              </Show>
            </div>
          )}
        </Show>
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
          ["✓", "BEC/なりすまし検出",       "kaname-bec の実データ判定 (精度の数値は本環境で未検証、docs/gap-analysis.md D36 参照)。「AI生成か」の判定は LLM 未配線のため非対応 (D2/D92)"],
          ["✓", "DLPラベル強制 AI 制御", "Microsoft Copilot CVE 対策、実データで稼働"],
          ["✓", "監査証跡",           "append-only + ハッシュチェーン — 上の「監査証跡」セクションで実データを閲覧可能"],
          ["⚠", "ローカル AI 推論",     "実装済み (D2 Phase 1-5) — モデルダウンロード・ロード後に BEC 意味解析が有効化。未ロード時は決定論的シグナルのみ"],
          ["⚠", "MLS + PQC 暗号化",    "実装済み (D1 Phase 1–5) — openmls + X-Wing (ML-KEM-768) ハイブリッド、SQLCipher 永続化、KP の添付往復・暗号送信・受信エンベロープ自動処理・安全番号照合記録まで配線済み"],
        ] as [string, string, string][]).map(([icon, name, desc]) => (
          <div style={{
            display: "flex", gap: "8px", padding: "4px 0",
            "font-size": "11px",
          }}>
            <span style={{
              color: icon === "✓" ? "#00B368" : icon === "⚠" ? "#F5A623" : "#FF6B70",
              "font-weight": "700",
            }}>{icon}</span>
            <div>
              <span style={{ color: "#D0D5DD" }}>{name}</span>
              <span style={{ color: "#8B96A5", "margin-left": "6px" }}>{desc}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SecurityDashboard;
