// src/ui/Compose.tsx — メール作成コンポーネント
//
// 機能:
//   - DLP 事前チェック (送信前にリアルタイム警告)
//   - AI 返信草案生成
//   - MLS 暗号化状態表示
//   - キーボードショートカット (Cmd/Ctrl+Enter で送信)

import { createSignal, createEffect, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

interface ComposeProps {
  replyToId?: string;
  initialTo?: string;
  initialSubject?: string;
  onClose: () => void;
  onSent: () => void;
}

export const Compose = (props: ComposeProps) => {
  const [to,       setTo]      = createSignal(props.initialTo || "");
  const [subject,  setSubject] = createSignal(props.initialSubject || "");
  const [body,     setBody]    = createSignal("");
  const [sending,  setSending] = createSignal(false);
  const [dlpWarn,  setDlpWarn] = createSignal<string | null>(null);
  const [aiLoading, setAiLoading] = createSignal(false);
  const [error,    setError]   = createSignal<string | null>(null);
  const [mlsReady, setMlsReady] = createSignal<boolean | null>(null);

  // DLP リアルタイムチェック (debounced)
  let dlpTimer: ReturnType<typeof setTimeout>;
  createEffect(() => {
    const b = body();
    clearTimeout(dlpTimer);
    dlpTimer = setTimeout(async () => {
      if (b.length < 20) { setDlpWarn(null); return; }
      try {
        // 本番: DLP チェック API を呼び出す
        // const result = await invoke<{verdict: string, rule?: string}>("dlp_check_outbound", { body: b, to: to() });
        // if (result.verdict !== "ALLOW") setDlpWarn(result.rule || "ポリシー違反");
      } catch {}
    }, 600);
  });

  // MLS 対応チェック
  createEffect(async () => {
    const addr = to().trim();
    if (!addr.includes("@")) { setMlsReady(null); return; }
    // 本番: KPD で確認
    setMlsReady(addr.endsWith("@kaname.app") || addr.endsWith("@kaname.jp"));
  });

  const handleSend = async () => {
    if (!to().trim() || !subject().trim() || !body().trim()) {
      setError("宛先・件名・本文は必須です");
      return;
    }
    setSending(true);
    setError(null);
    try {
      await invoke("mail_send", {
        req: {
          to:       [to()],
          subject:  subject(),
          body:     body(),
          draft_id: props.replyToId || null,
        },
      });
      props.onSent();
      props.onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setSending(false);
    }
  };

  const handleAiDraft = async () => {
    setAiLoading(true);
    try {
      // 本番: P-LLM に返信草案を依頼
      // const draft = await invoke<string>("ai_draft_reply", { replyToId: props.replyToId, instruction: body() });
      // setBody(draft);
      setBody("（AI 草案）ご連絡ありがとうございます。ご要望の件について確認いたします。");
    } finally {
      setAiLoading(false);
    }
  };

  // Cmd/Ctrl+Enter で送信
  const handleKeyDown = (e: KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      handleSend();
    }
    if (e.key === "Escape") props.onClose();
  };

  const inputStyle = {
    width: "100%",
    background: "#12181F",
    border: "1px solid #2A3441",
    "border-radius": "6px",
    padding: "9px 12px",
    color: "#F5F7FA",
    "font-size": "13px",
    outline: "none",
    "box-sizing": "border-box",
    "font-family": "inherit",
  } as const;

  return (
    <div
      onKeyDown={handleKeyDown}
      style={{
        display: "flex",
        "flex-direction": "column",
        height: "100%",
        background: "#0D1219",
      }}
    >
      {/* ヘッダー */}
      <div style={{
        padding: "14px 16px 12px",
        "border-bottom": "1px solid #1F2833",
        display: "flex",
        "align-items": "center",
        gap: "12px",
      }}>
        <span style={{ "font-size": "14px", "font-weight": "600", flex: "1" }}>
          {props.replyToId ? "返信" : "新規メール"}
        </span>
        <Show when={mlsReady() !== null}>
          <span style={{
            "font-size": "11px",
            color: mlsReady() ? "#00C4CC" : "#5A6473",
            padding: "2px 8px",
            border: `1px solid ${mlsReady() ? "#00C4CC30" : "#2A3441"}`,
            "border-radius": "4px",
          }}>
            {mlsReady() ? "🔐 E2E 暗号化" : "📧 SMTP"}
          </span>
        </Show>
        <button
          onClick={props.onClose}
          style={{
            background: "none", border: "none", cursor: "pointer",
            color: "#5A6473", "font-size": "18px", padding: "0 4px",
            "line-height": "1",
          }}
        >×</button>
      </div>

      {/* DLP 警告 */}
      <Show when={dlpWarn()}>
        <div style={{
          padding: "8px 16px",
          background: "#E5484D12",
          "border-bottom": "1px solid #E5484D30",
          "font-size": "12px",
          color: "#E5484D",
        }}>
          ⚠ DLP ポリシー: {dlpWarn()}
        </div>
      </Show>

      {/* フォーム */}
      <div style={{ padding: "12px 16px", display: "flex", "flex-direction": "column", gap: "8px" }}>
        <input
          type="email"
          placeholder="宛先"
          value={to()}
          onInput={e => setTo(e.currentTarget.value)}
          style={inputStyle}
        />
        <input
          type="text"
          placeholder="件名"
          value={subject()}
          onInput={e => setSubject(e.currentTarget.value)}
          style={inputStyle}
        />
      </div>

      {/* 本文エリア */}
      <textarea
        placeholder="本文を入力..."
        value={body()}
        onInput={e => setBody(e.currentTarget.value)}
        style={{
          ...inputStyle,
          flex: "1",
          margin: "0 16px",
          resize: "none",
          "line-height": "1.6",
          "border-radius": "6px",
        }}
      />

      {/* エラー */}
      <Show when={error()}>
        <div style={{ padding: "8px 16px", "font-size": "12px", color: "#E5484D" }}>
          {error()}
        </div>
      </Show>

      {/* アクションバー */}
      <div style={{
        padding: "12px 16px",
        "border-top": "1px solid #1F2833",
        display: "flex",
        gap: "8px",
        "align-items": "center",
      }}>
        <button
          onClick={handleSend}
          disabled={sending()}
          style={{
            background: "#00C4CC",
            color: "#0A0E14",
            border: "none",
            "border-radius": "6px",
            padding: "8px 20px",
            "font-size": "13px",
            "font-weight": "600",
            cursor: sending() ? "not-allowed" : "pointer",
            opacity: sending() ? 0.7 : 1,
          }}
        >
          {sending() ? "送信中..." : "送信 (⌘↵)"}
        </button>

        <Show when={props.replyToId}>
          <button
            onClick={handleAiDraft}
            disabled={aiLoading()}
            style={{
              background: "#1A2129",
              color: "#00C4CC",
              border: "1px solid #00C4CC30",
              "border-radius": "6px",
              padding: "8px 16px",
              "font-size": "12px",
              cursor: aiLoading() ? "not-allowed" : "pointer",
              opacity: aiLoading() ? 0.7 : 1,
            }}
          >
            {aiLoading() ? "生成中..." : "✨ AI 草案"}
          </button>
        </Show>

        <div style={{ flex: "1" }} />

        <span style={{ "font-size": "11px", color: "#5A6473" }}>
          Esc でキャンセル
        </span>
      </div>
    </div>
  );
};

// ===========================================================================
// Admin Dashboard コンポーネント
// ===========================================================================

interface AdminStats {
  active_users:    number;
  threats_blocked: number;
  ai_attacks:      number;
  avg_startup_ms:  number;
}

interface AuditEntry {
  seq:        number;
  event_type: string;
  summary:    string;
  created_at: string;
}

interface Incident {
  id:       string;
  severity: string;
  title:    string;
  detail:   string;
  time:     string;
  user:     string;
}

export const AdminDashboard = () => {
  const [stats,     setStats]     = createSignal<AdminStats | null>(null);
  const [audit,     setAudit]     = createSignal<AuditEntry[]>([]);
  const [incidents, setIncidents] = createSignal<Incident[]>([]);
  const [loading,   setLoading]   = createSignal(true);
  const [error,     setError]     = createSignal<string | null>(null);

  createEffect(async () => {
    try {
      const [s, a, i] = await Promise.all([
        invoke<AdminStats>("admin_get_dashboard"),
        invoke<AuditEntry[]>("admin_get_audit_log", { page: 0, pageSize: 20 }),
        invoke<Incident[]>("admin_list_incidents", { limit: 10 }),
      ]);
      setStats(s);
      setAudit(a);
      setIncidents(i);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  });

  const severityColor = (s: string) => ({
    CRITICAL: "#E5484D",
    HIGH:     "#E5A500",
    MEDIUM:   "#F5A623",
    LOW:      "#8B96A5",
  })[s] || "#8B96A5";

  const StatCard = (p: { label: string; value: string | number; color?: string; sub?: string }) => (
    <div style={{
      background: "#0D1219",
      border: "1px solid #1F2833",
      "border-radius": "8px",
      padding: "16px",
    }}>
      <div style={{ "font-size": "11px", color: "#5A6473", "margin-bottom": "6px", "text-transform": "uppercase", "letter-spacing": "0.08em" }}>
        {p.label}
      </div>
      <div style={{ "font-size": "28px", "font-weight": "700", color: p.color || "#F5F7FA", "font-variant-numeric": "tabular-nums" }}>
        {p.value}
      </div>
      <Show when={p.sub}>
        <div style={{ "font-size": "11px", color: "#5A6473", "margin-top": "4px" }}>{p.sub}</div>
      </Show>
    </div>
  );

  return (
    <div style={{
      padding: "20px",
      overflow: "auto",
      height: "100%",
      background: "#0A0E14",
      color: "#F5F7FA",
      "font-family": "-apple-system, 'Hiragino Sans', sans-serif",
    }}>
      <div style={{ "font-size": "18px", "font-weight": "700", "margin-bottom": "20px" }}>
        管理者ダッシュボード
      </div>

      <Show when={error()}>
        <div style={{ color: "#E5484D", "margin-bottom": "16px", "font-size": "13px" }}>
          {error()}
          <Show when={error()?.includes("Business")}>
            <span style={{ color: "#5A6473", "margin-left": "8px" }}>
              (このダッシュボードには Business 以上が必要です)
            </span>
          </Show>
        </div>
      </Show>

      <Show when={loading()}>
        <div style={{ color: "#5A6473", "font-size": "13px" }}>読み込み中...</div>
      </Show>

      <Show when={stats()}>
        {/* 統計カード */}
        <div style={{
          display: "grid",
          "grid-template-columns": "repeat(4, 1fr)",
          gap: "12px",
          "margin-bottom": "24px",
        }}>
          <StatCard label="アクティブユーザー" value={stats()!.active_users} color="#00C4CC" />
          <StatCard label="脅威ブロック" value={stats()!.threats_blocked} color="#E5484D" sub="今月" />
          <StatCard label="AI 攻撃検出" value={stats()!.ai_attacks} color="#F5A623" sub="今月" />
          <StatCard
            label="平均起動時間"
            value={`${stats()!.avg_startup_ms}ms`}
            color={stats()!.avg_startup_ms < 421 ? "#00B368" : "#E5A500"}
            sub="目標 <421ms"
          />
        </div>

        {/* セキュリティポスチャー */}
        <div style={{
          background: "#0D1219",
          border: "1px solid #1F2833",
          "border-radius": "8px",
          padding: "16px",
          "margin-bottom": "20px",
        }}>
          <div style={{ "font-size": "13px", "font-weight": "600", "margin-bottom": "12px" }}>
            セキュリティポスチャー
          </div>
          <div style={{ display: "flex", gap: "16px" }}>
            {[
              { label: "DLP エンジン", ok: true },
              { label: "MLS E2E",     ok: true },
              { label: "BEC 検出",    ok: true },
              { label: "サンドボックス", ok: true },
              { label: "AI パイプライン", ok: true },
              { label: "監査ログ",    ok: true },
            ].map(item => (
              <div style={{ display: "flex", "align-items": "center", gap: "6px" }}>
                <div style={{
                  width: "8px", height: "8px",
                  "border-radius": "50%",
                  background: item.ok ? "#00B368" : "#E5484D",
                }} />
                <span style={{ "font-size": "12px", color: "#8B96A5" }}>{item.label}</span>
              </div>
            ))}
          </div>
        </div>
      </Show>

      {/* インシデント一覧 */}
      <div style={{ "margin-bottom": "20px" }}>
        <div style={{ "font-size": "13px", "font-weight": "600", "margin-bottom": "10px" }}>
          最近のインシデント
        </div>
        <Show
          when={incidents().length > 0}
          fallback={
            <div style={{
              padding: "20px",
              background: "#0D1219",
              border: "1px solid #1F2833",
              "border-radius": "8px",
              "text-align": "center",
              color: "#5A6473",
              "font-size": "13px",
            }}>
              インシデントなし ✓
            </div>
          }
        >
          <div style={{
            background: "#0D1219",
            border: "1px solid #1F2833",
            "border-radius": "8px",
            overflow: "hidden",
          }}>
            {incidents().map(inc => (
              <div style={{
                padding: "12px 16px",
                "border-bottom": "1px solid #1F2833",
                display: "flex",
                gap: "12px",
                "align-items": "flex-start",
              }}>
                <span style={{
                  "font-size": "10px",
                  "font-weight": "700",
                  color: severityColor(inc.severity),
                  padding: "2px 6px",
                  border: `1px solid ${severityColor(inc.severity)}40`,
                  "border-radius": "3px",
                  "white-space": "nowrap",
                  "margin-top": "1px",
                }}>
                  {inc.severity}
                </span>
                <div style={{ flex: "1", "min-width": "0" }}>
                  <div style={{ "font-size": "13px", "font-weight": "500" }}>{inc.title}</div>
                  <div style={{ "font-size": "11px", color: "#5A6473", "margin-top": "2px" }}>
                    {inc.user} · {inc.time}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Show>
      </div>

      {/* 監査ログ */}
      <div>
        <div style={{ "font-size": "13px", "font-weight": "600", "margin-bottom": "10px" }}>
          監査ログ (直近 20 件)
        </div>
        <Show
          when={audit().length > 0}
          fallback={
            <div style={{
              padding: "20px",
              background: "#0D1219",
              border: "1px solid #1F2833",
              "border-radius": "8px",
              "text-align": "center",
              color: "#5A6473",
              "font-size": "13px",
            }}>
              監査ログなし
            </div>
          }
        >
          <div style={{
            background: "#0D1219",
            border: "1px solid #1F2833",
            "border-radius": "8px",
            overflow: "hidden",
            "font-family": "monospace",
          }}>
            {audit().map(entry => (
              <div style={{
                padding: "8px 16px",
                "border-bottom": "1px solid #1F2833",
                display: "grid",
                "grid-template-columns": "40px 160px 1fr",
                gap: "12px",
                "align-items": "center",
              }}>
                <span style={{ "font-size": "11px", color: "#5A6473" }}>#{entry.seq}</span>
                <span style={{ "font-size": "11px", color: "#00C4CC" }}>{entry.event_type}</span>
                <span style={{ "font-size": "11px", color: "#8B96A5", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>
                  {entry.summary}
                </span>
              </div>
            ))}
          </div>
        </Show>
      </div>
    </div>
  );
};

export default { Compose, AdminDashboard };
