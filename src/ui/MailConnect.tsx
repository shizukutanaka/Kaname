// src/ui/MailConnect.tsx
//
// JMAP サーバへ接続し、受信したメールを解析する画面。
//
// これまで本製品はサーバへ到達する経路自体を持っていなかった
// (kaname-ui が kaname-jmap に依存しておらず、コンパイル時点で到達不能
//  — docs/gap-analysis.md D10)。kaname-jmap 自体は RFC 8621 準拠の実装が
// 揃っていたため、配線するコードを書くことで受信・送信が動く。
//
// 認証情報はプロセスのメモリ内にのみ保持し、ディスクへは書かない。
// 安全に保管できないものは保管しない方針 (詳細は commands.rs の
// JMAP_SESSION の doc を参照)。

import { createSignal, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

interface ConnectResult {
  account_id: string;
  /** [id, 名前, 未読数] */
  mailboxes: [string, string, number][];
}

interface EmailRow {
  id: string;
  from_name: string | null;
  from_addr: string;
  subject: string | null;
  preview: string | null;
  received_at: string | null;
  is_read: boolean;
  is_starred: boolean;
  bec_verdict: string;
  is_mls: boolean;
  triage: string;
}

function verdictStyle(v: string): { bg: string; fg: string; border: string } {
  switch (v) {
    case "DANGEROUS":  return { bg: "#FDECEA", fg: "#8B1A10", border: "#E5A29B" };
    case "SUSPICIOUS": return { bg: "#FFF4E5", fg: "#7A4A00", border: "#F0B37E" };
    case "ADVISORY":   return { bg: "#FFF9E5", fg: "#6B5600", border: "#E8D07A" };
    case "SAFE":       return { bg: "#EAF6EC", fg: "#1E5B2A", border: "#9CC9A6" };
    // UNKNOWN は判定できなかったことを安全と見せない中間色。
    default:           return { bg: "#EEF1F4", fg: "#3D4650", border: "#C3CBD4" };
  }
}

export function MailConnect() {
  const [url, setUrl] = createSignal("");
  const [token, setToken] = createSignal("");
  const [session, setSession] = createSignal<ConnectResult | null>(null);
  const [emails, setEmails] = createSignal<EmailRow[]>([]);
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const connect = async () => {
    if (!url().trim() || !token().trim()) {
      setError("サーバ URL と認証トークンを入力してください。");
      return;
    }
    setBusy(true); setError(null); setEmails([]);
    try {
      const r = await invoke<ConnectResult>("mail_connect", {
        baseUrl: url().trim(), token: token().trim(),
      });
      setSession(r);
      // 接続できたらトークンは画面からも消す (残しておく理由がない)
      setToken("");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const disconnect = async () => {
    await invoke("mail_disconnect").catch(() => {});
    setSession(null); setEmails([]); setError(null);
  };

  const fetchMailbox = async (mailboxId: string) => {
    setBusy(true); setError(null);
    try {
      const rows = await invoke<EmailRow[]>("mail_fetch", { mailboxId, limit: 50 });
      setEmails(rows);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ padding: "24px", "max-width": "900px", margin: "0 auto" }}>
      <h2 style={{ "font-size": "20px", "font-weight": "600", "margin-bottom": "6px" }}>
        サーバに接続
      </h2>
      <p style={{ color: "#5A6473", "font-size": "13px", "margin-bottom": "16px", "line-height": "1.7" }}>
        JMAP サーバに接続してメールを受信し、各通に BEC 判定を付けて表示します。
        <strong>認証トークンはメモリ内にのみ保持し、ディスクには保存しません</strong>
        （安全に保管できるまで保存しない方針のため、起動のたびに接続が必要です）。
      </p>

      <Show when={!session()}>
        <div style={{ display: "grid", gap: "8px", "margin-bottom": "16px" }}>
          <input
            type="text" value={url()}
            onInput={(e) => setUrl(e.currentTarget.value)}
            placeholder="https://mail.example.com"
            style={{ padding: "10px 12px", "border-radius": "8px", border: "1px solid #C3CBD4", "font-size": "14px" }}
          />
          <input
            type="password" value={token()}
            onInput={(e) => setToken(e.currentTarget.value)}
            onKeyDown={(e) => { if (e.key === "Enter") void connect(); }}
            placeholder="Bearer トークン"
            style={{ padding: "10px 12px", "border-radius": "8px", border: "1px solid #C3CBD4", "font-size": "14px" }}
          />
          <button
            onClick={() => void connect()} disabled={busy()}
            style={{
              padding: "10px 18px", "border-radius": "8px", border: "none",
              background: busy() ? "#9AA5B1" : "#1F6FEB", color: "#fff",
              "font-size": "14px", "font-weight": "600",
              cursor: busy() ? "default" : "pointer",
            }}
          >
            {busy() ? "接続中..." : "接続する"}
          </button>
        </div>
      </Show>

      <Show when={error()}>
        <div style={{
          padding: "10px 12px", "border-radius": "8px",
          background: "#FDECEA", border: "1px solid #E5A29B",
          color: "#8B1A10", "font-size": "13px", "margin-bottom": "16px",
        }}>{error()}</div>
      </Show>

      <Show when={session()}>
        {(s) => (
          <div>
            <div style={{
              display: "flex", "align-items": "center", gap: "12px",
              "margin-bottom": "12px", "font-size": "13px",
            }}>
              <span style={{ color: "#1E5B2A", "font-weight": "600" }}>接続中</span>
              <span style={{ color: "#5A6473" }}>アカウント: {s().account_id}</span>
              <button
                onClick={() => void disconnect()}
                style={{
                  padding: "4px 12px", "border-radius": "6px",
                  border: "1px solid #C3CBD4", background: "#fff",
                  "font-size": "12px", cursor: "pointer",
                }}
              >切断</button>
            </div>

            <div style={{ display: "flex", gap: "8px", "flex-wrap": "wrap", "margin-bottom": "16px" }}>
              <For each={s().mailboxes}>
                {([id, name, unread]) => (
                  <button
                    onClick={() => void fetchMailbox(id)} disabled={busy()}
                    style={{
                      padding: "6px 14px", "border-radius": "999px",
                      border: "1px solid #1F6FEB", background: "#fff",
                      color: "#1F6FEB", "font-size": "13px",
                      cursor: busy() ? "default" : "pointer",
                    }}
                  >
                    {name}{unread > 0 ? ` (${unread})` : ""}
                  </button>
                )}
              </For>
            </div>

            <Show when={emails().length > 0}>
              <div style={{ border: "1px solid #C3CBD4", "border-radius": "8px", overflow: "hidden" }}>
                <For each={emails()}>
                  {(e) => {
                    const st = verdictStyle(e.bec_verdict);
                    return (
                      <div style={{
                        display: "flex", gap: "10px", "align-items": "center",
                        padding: "8px 12px", "border-bottom": "1px solid #E6EAEE",
                        "font-size": "13px",
                        background: e.is_read ? "#fff" : "#F7F9FB",
                      }}>
                        <span style={{
                          padding: "2px 8px", "border-radius": "999px",
                          background: st.bg, color: st.fg, border: `1px solid ${st.border}`,
                          "font-size": "11px", "font-weight": "700", "white-space": "nowrap",
                        }}>{e.bec_verdict}</span>
                        <span style={{ flex: "1", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>
                          {e.subject || "(件名なし)"}
                        </span>
                        <span style={{ color: "#5A6473", "white-space": "nowrap" }}>
                          {e.from_name || e.from_addr}
                        </span>
                      </div>
                    );
                  }}
                </For>
              </div>
            </Show>
          </div>
        )}
      </Show>
    </div>
  );
}
