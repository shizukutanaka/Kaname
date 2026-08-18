// src/ui/EmlImport.tsx
//
// ローカルの .eml ファイルを読み込み、**実際のメール**を Kaname の
// パイプライン全体 (MIME 解析 → 認証評価 → BEC 判定 → サニタイズ →
// レンダリング系検出) に通して結果を表示する画面。
//
// これまで本製品には実メールの入口が存在せず、すべての検出器は
// モックデータしか見ていなかった (docs/gap-analysis.md D10)。
// JMAP 受信の配線を待たずに実データで動かせる唯一の経路である。
//
// ネイティブのファイル選択ダイアログ (tauri-plugin-dialog) は未導入のため、
// パスを直接入力する方式にしている。

import { createSignal, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

interface BodyDto {
  srcdoc: string;
  sandbox: string;
  csp: string;
  is_mls: boolean;
  render_risks: string[];
}

interface ImportedEmail {
  from: string;
  subject: string;
  auth: string;
  bec_verdict: string;
  bec_score: number;
  bec_signals: string[];
  attachments: string[];
  body: BodyDto;
  /** 本文中に検出された機微情報 (DLP)。転送・返信時の漏洩リスク。 */
  dlp_findings: string[];
}

/** 判定に応じた配色。危険なものほど強い色にする。 */
function verdictStyle(v: string): { bg: string; fg: string; border: string } {
  switch (v) {
    case "DANGEROUS":
      return { bg: "#FDECEA", fg: "#8B1A10", border: "#E5A29B" };
    case "SUSPICIOUS":
      return { bg: "#FFF4E5", fg: "#7A4A00", border: "#F0B37E" };
    case "ADVISORY":
      return { bg: "#FFF9E5", fg: "#6B5600", border: "#E8D07A" };
    case "SAFE":
      return { bg: "#EAF6EC", fg: "#1E5B2A", border: "#9CC9A6" };
    default:
      // UNKNOWN 等。判定できなかったことを安全と見せない中間色。
      return { bg: "#EEF1F4", fg: "#3D4650", border: "#C3CBD4" };
  }
}

interface FolderScanEntry {
  file: string;
  from: string;
  subject: string;
  verdict: string;
  score: number;
}

interface CampaignSummary {
  shared_infrastructure: string;
  email_count: number;
  threat_score: number;
}

interface FolderScanResult {
  analyzed: number;
  failed: [string, string][];
  verdict_counts: [string, number][];
  emails: FolderScanEntry[];
  campaigns: CampaignSummary[];
}

export function EmlImport() {
  const [path, setPath] = createSignal("");
  const [result, setResult] = createSignal<ImportedEmail | null>(null);
  const [folder, setFolder] = createSignal<FolderScanResult | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);

  // フォルダ一括解析。kaname-radar (PCR) は複数メールを見比べて初めて
  // 機能するため、この経路でのみキャンペーン検出が有効になる。
  const scanFolder = async () => {
    const p = path().trim();
    if (!p) {
      setError("フォルダのパスを入力してください。");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    setFolder(null);
    try {
      const r = await invoke<FolderScanResult>("mail_scan_folder", { path: p });
      setFolder(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const analyze = async () => {
    const p = path().trim();
    if (!p) {
      setError("ファイルパスを入力してください。");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    setFolder(null);
    try {
      const r = await invoke<ImportedEmail>("mail_import_eml", { path: p });
      setResult(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "24px", "max-width": "900px", margin: "0 auto" }}>
      <h2 style={{ "font-size": "20px", "font-weight": "600", "margin-bottom": "6px" }}>
        メールファイルを解析
      </h2>
      <p style={{ color: "#5A6473", "font-size": "13px", "margin-bottom": "16px", "line-height": "1.7" }}>
        ローカルの <code>.eml</code> ファイルを Kaname の解析パイプライン
        (MIME 解析 → 送信ドメイン認証の評価 → BEC 判定 → サニタイズ →
        本文のリスク検出) に通します。サーバ接続もアカウント設定も不要です。
      </p>

      <div style={{ display: "flex", gap: "8px", "margin-bottom": "16px" }}>
        <input
          type="text"
          value={path()}
          onInput={(e) => setPath(e.currentTarget.value)}
          onKeyDown={(e) => { if (e.key === "Enter") void analyze(); }}
          placeholder="/path/to/message.eml"
          style={{
            flex: "1",
            padding: "10px 12px",
            "border-radius": "8px",
            border: "1px solid #C3CBD4",
            "font-size": "14px",
          }}
        />
        <button
          onClick={() => void analyze()}
          disabled={loading()}
          style={{
            padding: "10px 18px",
            "border-radius": "8px",
            border: "none",
            background: loading() ? "#9AA5B1" : "#1F6FEB",
            color: "#fff",
            "font-size": "14px",
            "font-weight": "600",
            cursor: loading() ? "default" : "pointer",
          }}
        >
          {loading() ? "解析中..." : "1通を解析"}
        </button>
        <button
          onClick={() => void scanFolder()}
          disabled={loading()}
          title="フォルダ内の .eml をまとめて解析し、キャンペーン検出も行います"
          style={{
            padding: "10px 18px",
            "border-radius": "8px",
            border: "1px solid #1F6FEB",
            background: "#fff",
            color: "#1F6FEB",
            "font-size": "14px",
            "font-weight": "600",
            cursor: loading() ? "default" : "pointer",
          }}
        >
          フォルダを一括解析
        </button>
      </div>

      <Show when={error()}>
        <div style={{
          padding: "10px 12px", "border-radius": "8px",
          background: "#FDECEA", border: "1px solid #E5A29B",
          color: "#8B1A10", "font-size": "13px", "margin-bottom": "16px",
        }}>
          {error()}
        </div>
      </Show>

      <Show when={folder()}>
        {(f) => (
          <div style={{ "margin-bottom": "20px" }}>
            <div style={{ "font-size": "15px", "font-weight": "600", "margin-bottom": "8px" }}>
              {f().analyzed} 件を解析しました
            </div>

            {/* 判定の内訳 */}
            <div style={{ display: "flex", gap: "8px", "flex-wrap": "wrap", "margin-bottom": "12px" }}>
              <For each={f().verdict_counts}>
                {([v, n]) => {
                  const st = verdictStyle(v);
                  return (
                    <span style={{
                      padding: "4px 10px", "border-radius": "999px",
                      background: st.bg, border: `1px solid ${st.border}`,
                      color: st.fg, "font-size": "12px", "font-weight": "600",
                    }}>{v}: {n}</span>
                  );
                }}
              </For>
            </div>

            {/* キャンペーン検出 (複数メール横断) */}
            <Show when={f().campaigns.length > 0}>
              <div style={{
                padding: "10px 12px", "border-radius": "8px",
                background: "#FDECEA", border: "1px solid #E5A29B",
                color: "#8B1A10", "font-size": "13px",
                "line-height": "1.6", "margin-bottom": "12px",
              }}>
                <div style={{ "font-weight": "600", "margin-bottom": "4px" }}>
                  複数メールにまたがるキャンペーンを検出しました
                </div>
                <For each={f().campaigns}>
                  {(c) => (
                    <div>
                      ・共有インフラ: {c.shared_infrastructure}（{c.email_count} 通 / 脅威スコア {c.threat_score.toFixed(2)}）
                    </div>
                  )}
                </For>
              </div>
            </Show>

            {/* 危険度順の一覧 */}
            <div style={{ border: "1px solid #C3CBD4", "border-radius": "8px", overflow: "hidden" }}>
              <For each={f().emails}>
                {(e) => {
                  const st = verdictStyle(e.verdict);
                  return (
                    <div style={{
                      display: "flex", gap: "10px", "align-items": "center",
                      padding: "8px 12px", "border-bottom": "1px solid #E6EAEE",
                      "font-size": "13px",
                    }}>
                      <span style={{
                        padding: "2px 8px", "border-radius": "999px",
                        background: st.bg, color: st.fg, border: `1px solid ${st.border}`,
                        "font-size": "11px", "font-weight": "700", "white-space": "nowrap",
                      }}>{e.verdict}</span>
                      <span style={{ flex: "1", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>
                        {e.subject || "(件名なし)"}
                      </span>
                      <span style={{ color: "#5A6473", "white-space": "nowrap" }}>{e.from}</span>
                    </div>
                  );
                }}
              </For>
            </div>

            {/* 失敗したファイルも隠さず表示する */}
            <Show when={f().failed.length > 0}>
              <div style={{ "margin-top": "10px", "font-size": "12px", color: "#8B1A10" }}>
                <div style={{ "font-weight": "600" }}>解析できなかったファイル:</div>
                <For each={f().failed}>{([file, why]) => <div>・{file}: {why}</div>}</For>
              </div>
            </Show>
          </div>
        )}
      </Show>

      <Show when={result()}>
        {(r) => {
          const s = verdictStyle(r().bec_verdict);
          return (
            <div>
              {/* 判定サマリ */}
              <div style={{
                padding: "14px 16px", "border-radius": "10px",
                background: s.bg, border: `1px solid ${s.border}`, color: s.fg,
                "margin-bottom": "16px",
              }}>
                <div style={{ "font-size": "16px", "font-weight": "700", "margin-bottom": "4px" }}>
                  BEC 判定: {r().bec_verdict}（スコア {r().bec_score.toFixed(2)}）
                </div>
                <Show when={r().bec_signals.length > 0} fallback={
                  <div style={{ "font-size": "13px" }}>危険な兆候は検出されませんでした。</div>
                }>
                  <div style={{ "font-size": "13px", "line-height": "1.7" }}>
                    <For each={r().bec_signals}>{(sig) => <div>・{sig}</div>}</For>
                  </div>
                </Show>
              </div>

              {/* メタ情報 */}
              <dl style={{
                display: "grid", "grid-template-columns": "120px 1fr",
                gap: "6px 12px", "font-size": "13px", "margin-bottom": "16px",
              }}>
                <dt style={{ color: "#5A6473" }}>差出人</dt>
                <dd style={{ margin: "0" }}>{r().from || "(不明)"}</dd>
                <dt style={{ color: "#5A6473" }}>件名</dt>
                <dd style={{ margin: "0" }}>{r().subject || "(件名なし)"}</dd>
                <dt style={{ color: "#5A6473" }}>送信ドメイン認証</dt>
                <dd style={{ margin: "0" }}>{r().auth}</dd>
                <Show when={r().attachments.length > 0}>
                  <dt style={{ color: "#5A6473" }}>添付</dt>
                  <dd style={{ margin: "0" }}>{r().attachments.join(", ")}</dd>
                </Show>
              </dl>

              {/* 機微情報の検出 (DLP) */}
              <Show when={(r().dlp_findings ?? []).length > 0}>
                <div style={{
                  padding: "10px 12px", "border-radius": "8px",
                  background: "#EAF1FB", border: "1px solid #9DBDEA",
                  color: "#123B75", "font-size": "13px",
                  "line-height": "1.6", "margin-bottom": "12px",
                }}>
                  <div style={{ "font-weight": "600", "margin-bottom": "4px" }}>
                    本文に機微情報が含まれています（転送・返信時は注意）
                  </div>
                  <For each={r().dlp_findings}>{(d) => <div>・{d}</div>}</For>
                </div>
              </Show>

              {/* 本文のリスク検出 */}
              <Show when={(r().body.render_risks ?? []).length > 0}>
                <div style={{
                  padding: "10px 12px", "border-radius": "8px",
                  background: "#FFF4E5", border: "1px solid #F0B37E",
                  color: "#7A4A00", "font-size": "13px",
                  "line-height": "1.6", "margin-bottom": "12px",
                }}>
                  <div style={{ "font-weight": "600", "margin-bottom": "4px" }}>
                    本文の解析で注意点が見つかりました
                  </div>
                  <For each={r().body.render_risks}>{(risk) => <div>・{risk}</div>}</For>
                </div>
              </Show>

              {/* サニタイズ済み本文 */}
              <div style={{ "font-size": "13px", color: "#5A6473", "margin-bottom": "6px" }}>
                サニタイズ済み本文（サンドボックス内で表示）
              </div>
              <iframe
                srcdoc={r().body.srcdoc}
                sandbox={r().body.sandbox}
                style={{
                  width: "100%", height: "360px",
                  border: "1px solid #C3CBD4", "border-radius": "8px",
                  background: "#fff",
                }}
                title="サニタイズ済みメール本文"
              />
            </div>
          );
        }}
      </Show>
    </div>
  );
}
