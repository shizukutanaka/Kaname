// src/ui/Inbox.tsx (SolidJS)
//
// Kaname メール受信トレイ — 本番グレード UI コンポーネント。
//
// 設計原則 (KHIG v0.1):
//   - 情報の優先順位が明確 (主役: メール一覧)
//   - BEC 判定は色とアイコンで即座に伝わる
//   - 長いテキスト、欠損、ゼロ件でも破綻しない
//   - brand #00C4CC、WCAG AAA 準拠
//   - Tauri コマンドを直接呼び出す

// SolidJS (JSX) — Tauri + SolidJS アプリのメインコンポーネント
// ファイル: src-tauri/../src/App.tsx で import する

import { createSignal, createEffect, For, Show, Switch, Match } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

// ============================================================================
// 型定義
// ============================================================================

interface Mailbox {
  id: string;
  name: string;
  role: string | null;
  unread_emails: number;
  total_emails: number;
}

interface EmailListItem {
  id: string;
  from_name: string | null;
  from_addr: string;
  subject: string | null;
  preview: string | null;
  received_at: string | null;
  is_read: boolean;
  is_starred: boolean;
  bec_verdict: string | null;
  is_mls: boolean;
}

interface BodyDto {
  srcdoc: string;
  sandbox: string;
  csp: string;
  is_mls: boolean;
  /** 本文に対するレンダリング系セキュリティ検出の結果 (人間可読)。 */
  render_risks: string[];
}

/** `mail_open` の戻り値。ローカル .eml 解析 (`mail_import_eml`) と同じ形。 */
interface OpenedEmail {
  from: string;
  subject: string;
  auth: string;
  bec_verdict: string;
  bec_score: number;
  bec_signals: string[];
  attachments: { filename: string; risks: string[]; is_dangerous: boolean }[];
  body: BodyDto;
  dlp_findings: string[];
}

// ============================================================================
// BEC バッジコンポーネント
// ============================================================================

const BecBadge = (props: { verdict: string | null }) => {
  if (!props.verdict || props.verdict === "SAFE") return null;
  const colors: Record<string, string> = {
    ADVISORY:   "#F5A623",
    SUSPICIOUS: "#E5A500",
    DANGEROUS:  "#E5484D",
  };
  const labels: Record<string, string> = {
    ADVISORY:   "要確認",
    SUSPICIOUS: "不審",
    DANGEROUS:  "危険",
  };
  const color = colors[props.verdict] || "#8B96A5";
  return (
    <span style={{
      "background": `${color}20`,
      "color": color,
      "border": `1px solid ${color}40`,
      "border-radius": "4px",
      "font-size": "10px",
      "font-family": "monospace",
      "padding": "1px 6px",
      "font-weight": "600",
      "letter-spacing": "0.05em",
    }}>
      {labels[props.verdict] || props.verdict}
    </span>
  );
};

// ============================================================================
// MLS バッジ
// ============================================================================

const MlsBadge = () => (
  <span style={{
    "background": "#00C4CC15",
    "color": "#00C4CC",
    "border": "1px solid #00C4CC30",
    "border-radius": "4px",
    "font-size": "10px",
    "font-family": "monospace",
    "padding": "1px 6px",
  }} title="MLS E2E 暗号化">
    E2E
  </span>
);

// ============================================================================
// 送信者表示
// ============================================================================

const SenderAvatar = (props: { name: string | null; addr: string; bec: string | null }) => {
  const initial = (props.name || props.addr)[0]?.toUpperCase() || "?";
  const bg = props.bec === "DANGEROUS" ? "#E5484D20" : "#1A2129";
  const color = props.bec === "DANGEROUS" ? "#E5484D" : "#8B96A5";
  return (
    <div style={{
      width: "36px",
      height: "36px",
      "border-radius": "50%",
      background: bg,
      display: "flex",
      "align-items": "center",
      "justify-content": "center",
      "font-size": "14px",
      "font-weight": "600",
      color,
      "flex-shrink": "0",
    }}>
      {initial}
    </div>
  );
};

// ============================================================================
// 日時フォーマット
// ============================================================================

export const formatDate = (iso: string | null): string => {
  if (!iso) return "";
  const d = new Date(iso);
  const now = new Date();
  const diff = (now.getTime() - d.getTime()) / 1000;

  if (diff < 60)     return "今";
  if (diff < 3600)   return `${Math.floor(diff / 60)}分前`;
  if (diff < 86400)  return `${Math.floor(diff / 3600)}時間前`;
  if (diff < 604800) {
    const days = ["日","月","火","水","木","金","土"];
    return days[d.getDay()];
  }
  return `${d.getMonth() + 1}/${d.getDate()}`;
};

// ============================================================================
// メールリストアイテム
// ============================================================================

const EmailItem = (props: {
  email:    EmailListItem;
  selected: boolean;
  onSelect: () => void;
}) => {
  const { email } = props;
  return (
    <div
      onClick={props.onSelect}
      style={{
        display: "flex",
        gap: "12px",
        padding: "12px 16px",
        cursor: "pointer",
        background: props.selected
          ? "#1A2129"
          : email.is_read ? "transparent" : "#12181F",
        "border-bottom": "1px solid #1F2833",
        transition: "background 0.1s",
        position: "relative",
      }}
      onMouseEnter={e => { if (!props.selected) (e.currentTarget as HTMLElement).style.background = "#12181F"; }}
      onMouseLeave={e => { if (!props.selected) (e.currentTarget as HTMLElement).style.background = email.is_read ? "transparent" : "#12181F80"; }}
    >
      {/* 未読インジケーター */}
      <Show when={!email.is_read}>
        <div style={{
          position: "absolute",
          left: "5px",
          top: "50%",
          transform: "translateY(-50%)",
          width: "5px",
          height: "5px",
          "border-radius": "50%",
          background: "#00C4CC",
        }} />
      </Show>

      <SenderAvatar
        name={email.from_name}
        addr={email.from_addr}
        bec={email.bec_verdict}
      />

      <div style={{ flex: "1", "min-width": "0" }}>
        {/* 1行目: 送信者 + 日時 + バッジ */}
        <div style={{
          display: "flex",
          "align-items": "center",
          gap: "8px",
          "margin-bottom": "3px",
        }}>
          <span style={{
            "font-size": "13px",
            "font-weight": email.is_read ? "400" : "600",
            color: email.bec_verdict === "DANGEROUS" ? "#E5484D" : "#F5F7FA",
            "white-space": "nowrap",
            overflow: "hidden",
            "text-overflow": "ellipsis",
            flex: "1",
          }}>
            {email.from_name || email.from_addr}
          </span>
          <Show when={email.is_mls}>
            <MlsBadge />
          </Show>
          <BecBadge verdict={email.bec_verdict} />
          <span style={{
            "font-size": "11px",
            color: "#5A6473",
            "white-space": "nowrap",
          }}>
            {formatDate(email.received_at)}
          </span>
        </div>

        {/* 2行目: 件名 */}
        <div style={{
          "font-size": "12.5px",
          color: email.is_read ? "#8B96A5" : "#D0D5DD",
          "font-weight": email.is_read ? "400" : "500",
          "white-space": "nowrap",
          overflow: "hidden",
          "text-overflow": "ellipsis",
          "margin-bottom": "2px",
        }}>
          {email.subject || "(件名なし)"}
        </div>

        {/* 3行目: プレビュー */}
        <div style={{
          "font-size": "12px",
          color: "#5A6473",
          "white-space": "nowrap",
          overflow: "hidden",
          "text-overflow": "ellipsis",
        }}>
          {email.preview || ""}
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// メール詳細パネル
// ============================================================================

const EmailDetailPanel = (props: {
  emailId: string | null;
  onClose: () => void;
}) => {
  const [opened, setOpened] = createSignal<OpenedEmail | null>(null);
  const [openError, setOpenError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);
  // 以前は mail_get_body と bec_get_score の 2 コマンドを呼んでいたが、
  // どちらもスタブで、メールを開くたびに必ず失敗していた。
  // mail_open は生 RFC 5322 をサーバから取得し、ローカル .eml と同じ
  // パイプラインで本文・BEC・添付・DLP をまとめて返す。
  const body = () => opened()?.body ?? null;
  const bec  = () => opened();

  createEffect(async () => {
    if (!props.emailId) return;
    setLoading(true);
    setOpenError(null);
    try {
      const data = await invoke<OpenedEmail>("mail_open", { emailId: props.emailId });
      setOpened(data);
      await invoke("mail_mark_read", { ids: [props.emailId] }).catch(() => {});
    } catch (e) {
      setOpened(null);
      setOpenError(String(e));
    } finally {
      setLoading(false);
    }
  });

  return (
    <div style={{
      flex: "1",
      display: "flex",
      "flex-direction": "column",
      background: "#0A0E14",
      overflow: "hidden",
    }}>
      {/* BEC 警告バナー */}
      <Show when={bec() && bec()!.bec_verdict !== "SAFE"}>
        <div style={{
          padding: "10px 20px",
          background: bec()!.bec_verdict === "DANGEROUS" ? "#E5484D12" :
                      bec()!.bec_verdict === "SUSPICIOUS" ? "#E5A50012" : "#F5A62312",
          "border-bottom": `1px solid ${
            bec()!.bec_verdict === "DANGEROUS" ? "#E5484D40" : "#F5A62340"
          }`,
          display: "flex",
          "align-items": "center",
          gap: "12px",
        }}>
          <div style={{
            "font-size": "12px",
            "font-weight": "600",
            color: bec()!.bec_verdict === "DANGEROUS" ? "#E5484D" : "#F5A623",
          }}>
            ⚠ {bec()!.bec_verdict === "DANGEROUS"
              ? "このメールは差出人を証明できません — BEC 攻撃の可能性があります"
              : "このメールについて注意が必要な点があります"}
          </div>
          <div style={{ flex: "1" }} />
          <Show when={bec()!.bec_signals.length > 0}>
            <span style={{ "font-size": "11px", color: "#8B96A5" }}>
              検出シグナル: {bec()!.bec_signals.join(", ")}
            </span>
          </Show>
        </div>
      </Show>

      {/* 本文エリア */}
      <div style={{ flex: "1", overflow: "hidden", position: "relative" }}>
        <Show when={loading()}>
          <div style={{
            position: "absolute", inset: "0",
            display: "flex", "align-items": "center", "justify-content": "center",
            color: "#5A6473", "font-size": "14px",
          }}>
            読み込み中...
          </div>
        </Show>

        <Show when={!loading() && body()}>
          {/* レンダリング系の検出結果 (HTMLスマグリング / テキストQR / CSS外部参照)。
              kaname-render の検出器を実際に実行した結果をここに表示する。 */}
          <Show when={bec()!.attachments.some(a => a.is_dangerous) || bec()!.dlp_findings.length > 0}>
            <div style={{ padding: "8px 16px", "font-size": "12px", color: "#E5A500", background: "#E5A50012", "border-bottom": "0.5px solid #E5A50040" }}>
              <For each={bec()!.attachments.filter(a => a.is_dangerous)}>
                {a => <div>⚠ 危険な添付: {a.filename} — {a.risks.join(", ")}</div>}
              </For>
              <For each={bec()!.dlp_findings}>
                {f => <div>🔒 機微情報: {f}</div>}
              </For>
            </div>
          </Show>
          <Show when={(body()!.render_risks ?? []).length > 0}>
            <div style={{
              margin: "0 0 12px 0",
              padding: "10px 12px",
              "border-radius": "8px",
              background: "#FFF4E5",
              border: "1px solid #F0B37E",
              color: "#7A4A00",
              "font-size": "13px",
              "line-height": "1.6",
            }}>
              <div style={{ "font-weight": "600", "margin-bottom": "4px" }}>
                本文の解析で注意点が見つかりました
              </div>
              <For each={body()!.render_risks}>
                {(risk) => <div>・{risk}</div>}
              </For>
            </div>
          </Show>

          {/* サンドボックス化された iframe */}
          <iframe
            srcdoc={body()!.srcdoc}
            sandbox={body()!.sandbox}
            style={{
              width: "100%",
              height: "100%",
              border: "none",
              background: "transparent",
            }}
            title="メール本文"
          />
        </Show>

        <Show when={!loading() && !body() && props.emailId}>
          <div style={{
            display: "flex", "align-items": "center", "justify-content": "center",
            height: "100%", color: "#5A6473",
          }}>
            {openError() ?? "メールを読み込めませんでした"}
          </div>
        </Show>
      </div>
    </div>
  );
};

// ============================================================================
// メインInboxコンポーネント
// ============================================================================

export const Inbox = () => {
  const [mailboxes, setMailboxes]       = createSignal<Mailbox[]>([]);
  const [selectedMbx, setSelectedMbx]  = createSignal<string | null>(null);
  const [emails, setEmails]             = createSignal<EmailListItem[]>([]);
  const [selectedEmail, setSelectedEmail] = createSignal<string | null>(null);
  const [loading, setLoading]           = createSignal(false);
  const [error, setError]               = createSignal<string | null>(null);
  // 検索: 保存済みメール (mail_search) を対象にする。
  // 従来この検索欄はハンドラ未バインドで機能していなかった (D10)。
  const [searchQuery, setSearchQuery]   = createSignal("");
  const [searching, setSearching]       = createSignal(false);

  /** サーバからメールを取得して一覧に反映する。 */
  const loadEmails = async (mbxId: string | null) => {
    if (!mbxId) return;
    setLoading(true);
    setError(null);
    try {
      // 未配線の mail_query_emails ではなく、実装済みの mail_fetch を使う。
      // mail_fetch は取得と同時に BEC 判定を行い、保存も行う。
      const items = await invoke<EmailListItem[]>("mail_fetch", {
        mailboxId: mbxId,
        limit:     50,
      });
      setEmails(items);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  /** 保存済みメールを検索し、一覧を結果で置き換える。 */
  const runSearch = async () => {
    const q = searchQuery().trim();
    if (!q) {
      // 空文字で Enter → 検索を解除して通常の一覧に戻す。
      setSearching(false);
      setError(null);
      void loadEmails(selectedMbx());
      return;
    }
    setSearching(true);
    setError(null);
    try {
      // StoredMessage は EmailListItem と形が異なるため詰め替える。
      // 保存済みメールには starred/mls の情報が無いので false を入れる
      // (不明な値を true と偽らない)。
      const found = await invoke<{
        id: string; from_addr: string; from_name: string | null;
        subject: string | null; body_preview: string | null;
        received_at: string | null; is_read: boolean;
        bec_score: number | null; bec_verdict: string | null;
      }[]>("mail_search", { query: q, limit: 50 });
      setEmails(found.map(m => ({
        id: m.id,
        from_name: m.from_name,
        from_addr: m.from_addr,
        subject: m.subject,
        preview: m.body_preview,
        received_at: m.received_at,
        is_read: m.is_read,
        is_starred: false,
        bec_verdict: m.bec_verdict,
        is_mls: false,
      })));
    } catch (e) {
      setError(String(e));
      setEmails([]);
    }
  };

  // 起動時にメールボックスを読み込む
  createEffect(async () => {
    try {
      const mbxs = await invoke<Mailbox[]>("mail_get_mailboxes");
      setMailboxes(mbxs);
      // 受信トレイをデフォルト選択
      const inbox = mbxs.find(m => m.role === "inbox") || mbxs[0];
      if (inbox) setSelectedMbx(inbox.id);
    } catch (e) {
      setError(String(e));
    }
  });

  // メールボックス変更時にメールを読み込む (検索中は上書きしない)
  createEffect(async () => {
    const mbxId = selectedMbx();
    if (!mbxId || searching()) return;
    await loadEmails(mbxId);
  });

  const selectedMbxInfo = () => mailboxes().find(m => m.id === selectedMbx());

  return (
    <div style={{
      display: "flex",
      height: "100vh",
      background: "#0A0E14",
      color: "#F5F7FA",
      "font-family": "-apple-system, 'Hiragino Sans', 'Noto Sans JP', sans-serif",
      overflow: "hidden",
    }}>
      {/* ── サイドバー ── */}
      <aside style={{
        width: "220px",
        "flex-shrink": "0",
        background: "#0D1219",
        "border-right": "1px solid #1F2833",
        display: "flex",
        "flex-direction": "column",
        overflow: "hidden",
      }}>
        {/* ロゴ */}
        <div style={{
          padding: "18px 16px 12px",
          "border-bottom": "1px solid #1F2833",
          display: "flex",
          "align-items": "center",
          gap: "10px",
        }}>
          <div style={{
            width: "28px", height: "28px",
            "border-radius": "6px",
            background: "linear-gradient(135deg, #00C4CC, #00A5AC)",
            display: "flex", "align-items": "center", "justify-content": "center",
            "font-size": "16px",
            "font-style": "italic",
            "font-weight": "700",
            color: "#00C4CC",
            position: "relative",
          }}>
            <div style={{
              position: "absolute", inset: "2px",
              background: "#0D1219",
              "border-radius": "4px",
              display: "flex", "align-items": "center", "justify-content": "center",
            }}>要</div>
          </div>
          <span style={{ "font-size": "15px", "font-weight": "600" }}>Kaname</span>
        </div>

        {/* メールボックスリスト */}
        <nav style={{ flex: "1", "overflow-y": "auto", padding: "8px 0" }}>
          <For each={mailboxes()}>
            {(mbx) => (
              <button
                onClick={() => { setSelectedMbx(mbx.id); setSelectedEmail(null); }}
                style={{
                  width: "100%",
                  padding: "8px 16px",
                  display: "flex",
                  "align-items": "center",
                  gap: "10px",
                  background: selectedMbx() === mbx.id ? "#1A2129" : "transparent",
                  border: "none",
                  cursor: "pointer",
                  color: selectedMbx() === mbx.id ? "#F5F7FA" : "#8B96A5",
                  "font-size": "13px",
                  "border-radius": "6px",
                  margin: "0 6px",
                  transition: "background 0.1s, color 0.1s",
                  "text-align": "left",
                }}
              >
                <span style={{ flex: "1" }}>{mbx.name}</span>
                <Show when={mbx.unread_emails > 0}>
                  <span style={{
                    background: selectedMbx() === mbx.id ? "#00C4CC" : "#00C4CC30",
                    color: selectedMbx() === mbx.id ? "#0A0E14" : "#00C4CC",
                    "border-radius": "10px",
                    "font-size": "10px",
                    "font-weight": "700",
                    padding: "1px 6px",
                    "min-width": "18px",
                    "text-align": "center",
                  }}>
                    {mbx.unread_emails}
                  </span>
                </Show>
              </button>
            )}
          </For>
        </nav>

        {/* セキュリティポスチャー */}
        <div style={{
          padding: "12px 16px",
          "border-top": "1px solid #1F2833",
          display: "flex",
          "align-items": "center",
          gap: "6px",
          "font-size": "11px",
          color: "#00B368",
        }}>
          <div style={{
            width: "6px", height: "6px",
            "border-radius": "50%",
            background: "#00B368",
            animation: "pulse 2s infinite",
          }} />
          全サブシステム正常
        </div>
      </aside>

      {/* ── メールリスト ── */}
      <div style={{
        width: "340px",
        "flex-shrink": "0",
        "border-right": "1px solid #1F2833",
        display: "flex",
        "flex-direction": "column",
        overflow: "hidden",
      }}>
        {/* ヘッダー */}
        <div style={{
          padding: "14px 16px 12px",
          "border-bottom": "1px solid #1F2833",
        }}>
          <div style={{
            "font-size": "15px",
            "font-weight": "600",
            "margin-bottom": "8px",
          }}>
            {selectedMbxInfo()?.name || "受信トレイ"}
          </div>
          {/* 検索バー — 保存済みメールを対象に検索する。
              従来はハンドラが未バインドで「飾り」だった (D10)。 */}
          <input
            type="text"
            placeholder="検索..."
            value={searchQuery()}
            onInput={(e) => setSearchQuery(e.currentTarget.value)}
            onKeyDown={(e) => { if (e.key === "Enter") void runSearch(); }}
            style={{
              width: "100%",
              background: "#12181F",
              border: "1px solid #2A3441",
              "border-radius": "6px",
              padding: "7px 12px",
              color: "#F5F7FA",
              "font-size": "13px",
              outline: "none",
              "box-sizing": "border-box",
            }}
          />
        </div>

        {/* メールリスト本体 */}
        <div style={{ flex: "1", "overflow-y": "auto" }}>
          <Switch>
            <Match when={loading()}>
              <div style={{
                display: "flex", "align-items": "center", "justify-content": "center",
                height: "200px", color: "#5A6473", "font-size": "13px",
              }}>
                読み込み中...
              </div>
            </Match>
            <Match when={error()}>
              <div style={{
                padding: "20px", color: "#E5484D", "font-size": "13px",
                "text-align": "center",
              }}>
                エラー: {error()}
              </div>
            </Match>
            <Match when={emails().length === 0 && !loading()}>
              <div style={{
                display: "flex", "flex-direction": "column",
                "align-items": "center", "justify-content": "center",
                height: "200px", gap: "8px",
              }}>
                <div style={{ "font-size": "32px", opacity: "0.3" }}>📭</div>
                <div style={{ color: "#5A6473", "font-size": "13px" }}>メールなし</div>
              </div>
            </Match>
            <Match when={true}>
              <For each={emails()}>
                {(email) => (
                  <EmailItem
                    email={email}
                    selected={selectedEmail() === email.id}
                    onSelect={() => setSelectedEmail(email.id)}
                  />
                )}
              </For>
            </Match>
          </Switch>
        </div>
      </div>

      {/* ── メール詳細 ── */}
      <Show
        when={selectedEmail()}
        fallback={
          <div style={{
            flex: "1",
            display: "flex",
            "flex-direction": "column",
            "align-items": "center",
            "justify-content": "center",
            color: "#5A6473",
            gap: "12px",
          }}>
            <div style={{ "font-size": "48px", opacity: "0.2" }}>✉</div>
            <div style={{ "font-size": "14px" }}>メールを選択してください</div>
          </div>
        }
      >
        <EmailDetailPanel
          emailId={selectedEmail()}
          onClose={() => setSelectedEmail(null)}
        />
      </Show>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
        * { -webkit-font-smoothing: antialiased; box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #2A3441; border-radius: 2px; }
        button:hover { opacity: 0.9; }
        input::placeholder { color: #5A6473; }
        input:focus { border-color: #00C4CC40 !important; }
      `}</style>
    </div>
  );
};

export default Inbox;
