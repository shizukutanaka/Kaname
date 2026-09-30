// src/ui/OobvCeremony.tsx
//
// 帯域外検証 (OOBV) セレモニーの UI。`oobv_level` が "optional"/"strong" の
// メールに表示される 📞 バナーから開始できる。
//
// 流れ: 「電話で確認を開始」→ バックエンドが6単語の合い言葉と挑戦番号を
// 発行 (oobv_start) → 利用者が電話等の別経路で送信者に当該番号の単語を
// 読み上げてもらい入力 → 照合 (oobv_verify) → 結果を表示する。
// メールの内容をこちらが話すのではなく「相手だけが知り得る単語」を
// 確認するため、なりすましは合い言葉を答えられない。

import { createSignal, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

interface OobvStartResponse {
  ceremony_id: string;
  phrase: string[];
  challenge_number: number;
  expires_at_unix: number;
}

type CeremonyState = "Pending" | "Verified" | "Mismatch" | "Expired" | "Locked";

interface OobvVerifyResponse {
  state: CeremonyState;
  message_i18n_key: string;
}

function resultText(state: CeremonyState): { text: string; ok: boolean } {
  switch (state) {
    case "Verified":
      return { text: "✓ 本人確認が取れました", ok: true };
    case "Mismatch":
      return { text: "✗ 単語が一致しませんでした — 送信者が本人ではない可能性があります", ok: false };
    case "Expired":
      return { text: "合い言葉の有効期限が切れました。もう一度開始してください", ok: false };
    case "Locked":
      return { text: "試行回数の上限に達しました。もう一度開始してください", ok: false };
    default:
      return { text: "確認待ちです", ok: false };
  }
}

export function OobvCeremony(props: {
  level: string;
  message: string;
  emailId: string;
  sender: string;
}) {
  const [ceremony, setCeremony] = createSignal<OobvStartResponse | null>(null);
  const [word, setWord] = createSignal("");
  const [result, setResult] = createSignal<CeremonyState | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const strong = () => props.level === "strong";

  const start = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const r = await invoke<OobvStartResponse>("oobv_start", {
        req: { email_id: props.emailId, sender: props.sender },
      });
      setCeremony(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const verify = async () => {
    const c = ceremony();
    const w = word().trim();
    if (!c || !w) return;
    setBusy(true);
    setError(null);
    try {
      const r = await invoke<OobvVerifyResponse>("oobv_verify", {
        req: { ceremony_id: c.ceremony_id, user_word: w },
      });
      setResult(r.state);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{
      padding: strong() ? "10px 12px" : "8px 12px",
      "border-radius": "8px",
      background: strong() ? "#FDECEC" : "#FBF6E9",
      border: `1px solid ${strong() ? "#FF6B7060" : "#E5A50060"}`,
      color: strong() ? "#8A1F22" : "#6B4E00",
      "font-size": strong() ? "13px" : "12px",
      "line-height": "1.6",
      "margin-bottom": "12px",
      "font-weight": strong() ? "600" : "400",
    }}>
      📞 {props.message}

      <Show when={!ceremony()}>
        <div style={{ "margin-top": "8px" }}>
          <button
            onClick={() => void start()}
            disabled={busy()}
            style={{
              padding: "6px 12px", "border-radius": "6px",
              border: `1px solid ${strong() ? "#8A1F22" : "#6B4E00"}`,
              background: "#fff",
              color: strong() ? "#8A1F22" : "#6B4E00",
              "font-size": "12px", "font-weight": "600",
              cursor: busy() ? "default" : "pointer",
            }}
          >
            {busy() ? "開始中..." : "電話で確認を開始"}
          </button>
        </div>
      </Show>

      <Show when={ceremony()}>
        {(c) => (
          <div style={{ "margin-top": "8px", "font-weight": "400" }}>
            <div style={{ "margin-bottom": "6px" }}>
              送信者に電話など別の手段で連絡し、次の合い言葉の
              <strong> {c().challenge_number} 番目</strong>の単語を
              読み上げてもらってください:
            </div>
            <div style={{
              display: "flex", gap: "6px", "flex-wrap": "wrap",
              "margin-bottom": "8px",
            }}>
              <For each={c().phrase}>
                {(w, i) => (
                  <span style={{
                    padding: "2px 8px", "border-radius": "4px",
                    background: i() + 1 === c().challenge_number ? "#1F6FEB" : "#fff",
                    color: i() + 1 === c().challenge_number ? "#fff" : "inherit",
                    border: "1px solid #C3CBD4",
                    "font-family": "monospace", "font-size": "12px",
                  }}>
                    {i() + 1}. {w}
                  </span>
                )}
              </For>
            </div>
            <div style={{ display: "flex", gap: "6px", "align-items": "center" }}>
              <input
                type="text"
                value={word()}
                onInput={(e) => setWord(e.currentTarget.value)}
                onKeyDown={(e) => { if (e.key === "Enter") void verify(); }}
                placeholder="相手が読み上げた単語"
                aria-label="相手が読み上げた合い言葉の単語"
                style={{
                  padding: "6px 10px", "border-radius": "6px",
                  border: "1px solid #C3CBD4", "font-size": "12px",
                  width: "200px",
                }}
              />
              <button
                onClick={() => void verify()}
                disabled={busy() || !word().trim()}
                style={{
                  padding: "6px 12px", "border-radius": "6px", border: "none",
                  background: busy() || !word().trim() ? "#9AA5B1" : "#1F6FEB",
                  color: "#fff", "font-size": "12px", "font-weight": "600",
                  cursor: busy() || !word().trim() ? "default" : "pointer",
                }}
              >
                照合
              </button>
            </div>
          </div>
        )}
      </Show>

      <Show when={result()}>
        {(st) => {
          const r = resultText(st());
          return (
            <div style={{
              "margin-top": "8px", "font-weight": "600",
              color: r.ok ? "#1E5B2A" : "#8A1F22",
            }}>
              {r.text}
            </div>
          );
        }}
      </Show>

      <Show when={error()}>
        <div style={{ "margin-top": "6px", color: "#8A1F22" }}>{error()}</div>
      </Show>
    </div>
  );
}
