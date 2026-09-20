// src/ui/Compose.tsx — メール作成コンポーネント
//
// 機能:
//   - 送信前アドバイザリ (oobv_recommend で別経路確認推奨の文脈を検出)
//   - (AI 返信草案は LLM 推論がスタブのため提供しない。以前は定型文を
//      「AI 草案」と表示して挿入しており、AI 出力を偽っていた)
//   - MLS 暗号化状態表示
//   - キーボードショートカット (Cmd/Ctrl+Enter で送信)

import { createSignal, createEffect, createMemo, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

// D1 Phase 3: MLS 会話が成立している相手 (kaname-ui::commands::MlsPeer)
interface MlsPeer {
  email: string;
  conversation_id: string;
  epoch: number;
  safety_number: string | null;
  verified: boolean;
  safety_changed: boolean;
}

interface ComposeProps {
  onClose: () => void;
  onSent: () => void;
}

export const Compose = (props: ComposeProps) => {
  // 差出人: JMAP セッションはアカウントのメールアドレスを公開しないため
  // (Session.primary_accounts は accountId のみ)、利用者に入力してもらう。
  const [from,     setFrom]    = createSignal("");
  const [to,       setTo]      = createSignal("");
  const [subject,  setSubject] = createSignal("");
  const [body,     setBody]    = createSignal("");
  const [sending,  setSending] = createSignal(false);
  const [advice,   setAdvice]  = createSignal<string | null>(null);
  const [error,    setError]   = createSignal<string | null>(null);
  // 送信前 DLP の Warn 所見 (mail_send は Block のみ止めるため、
  // 警告は送信ボタン経由の事前チェックで表示する)。
  const [dlpWarnings,  setDlpWarnings]  = createSignal<string[]>([]);

  // D1 Phase 3/4: MLS 会話が成立している相手一覧。
  // 単一宛先が会話を持つときだけ「MLS で暗号化」選択肢を出す。
  const [mlsPeers, setMlsPeers] = createSignal<MlsPeer[]>([]);
  const [useMls,  setUseMls]  = createSignal(false);
  createEffect(async () => {
    try {
      setMlsPeers(await invoke<MlsPeer[]>("mls_conversations"));
    } catch {
      setMlsPeers([]);
    }
  });
  const mlsPeer = createMemo<MlsPeer | null>(() => {
    const list = to().split(/[,;]/).map(s => s.trim().toLowerCase()).filter(Boolean);
    if (list.length !== 1) return null;
    return mlsPeers().find(p => p.email.toLowerCase() === list[0]) ?? null;
  });

  // 送信前アドバイザリ (debounced): 本文が「受信側で別経路確認を推奨」
  // される文脈 (送金要求・急迫表現等) に一致するかを `oobv_recommend`
  // で判定し、送信者が事前に確認経路を明記できるよう助言する。
  // ブロックではなく助言。送信時の DLP Block 判定は別途 mail_send が実行。
  let adviceTimer: ReturnType<typeof setTimeout>;
  createEffect(() => {
    const b = body();
    clearTimeout(adviceTimer);
    adviceTimer = setTimeout(async () => {
      if (b.length < 20) { setAdvice(null); return; }
      try {
        const res = await invoke<{ level: string; message_i18n_key: string }>(
          "oobv_recommend",
          { req: { email_body: b } },
        );
        setAdvice(
          res.level === "Strong"
            ? "本文が送金要求・急迫表現を含み、受信側で別経路確認が必要と判断される可能性が高い内容です"
            : res.level === "Optional"
              ? "本文の内容は受信側で別経路確認が推奨される可能性があります"
              : null,
        );
      } catch {
        // アドバイザリの失敗で送信を妨げない
        setAdvice(null);
      }
    }, 600);
  });

  // MLS で暗号化するかの選択 (D1 Phase 3)。選択肢は宛先が単一かつ
  // その相手と会話が成立しているときのみ出す (mlsPeer メモ)。

  // 入力が変わったら DLP 確認をやり直す (確認済みのまま本文を変えて
  // 警告を回避できないようにする)
  createEffect(() => {
    from(); to(); subject(); body();
    setDlpWarnings([]);
  });

  const handleSend = async (skipPrecheck = false) => {
    if (!from().trim() || !to().trim() || !subject().trim() || !body().trim()) {
      setError("差出人・宛先・件名・本文は必須です");
      return;
    }
    const toList = to().split(/[,;]/).map(s => s.trim()).filter(Boolean);
    setSending(true);
    setError(null);
    if (!skipPrecheck) {
      try {
        const res = await invoke<{ warnings: string[] }>("mail_dlp_precheck", {
          req: { from: from(), to: toList, subject: subject(), body: body() },
        });
        if (res.warnings.length > 0) {
          setDlpWarnings(res.warnings);
          setSending(false);
          return;
        }
      } catch {
        // 事前チェックの失敗で送信を妨げない (Block は mail_send が実行)
      }
    }
    try {
      if (useMls() && mlsPeer()) {
        // MLS E2E: 実件名・本文はエンベロープ内にのみ封入され、
        // 外側メールにはプレースホルダのみ出る。DLP は実本文で済ませた。
        await invoke("mls_send_encrypted", {
          to:      mlsPeer()!.email,
          subject: subject(),
          body:    body(),
        });
      } else {
        await invoke("mail_send", {
          from:    from(),
          to:      toList,
          subject: subject(),
          body:    body(),
        });
      }
      props.onSent();
      props.onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setSending(false);
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
          新規メール
        </span>
        <button
          onClick={props.onClose}
          aria-label="閉じる"
          style={{
            background: "none", border: "none", cursor: "pointer",
            color: "#8B96A5", "font-size": "18px", padding: "0 4px",
            "line-height": "1",
          }}
        >×</button>
      </div>

      {/* 送信前アドバイザリ (OOBV 推奨判定) */}
      <Show when={advice()}>
        <div style={{
          padding: "8px 16px",
          background: "#FFB22412",
          "border-bottom": "1px solid #FFB22430",
          "font-size": "12px",
          color: "#FFB224",
        }}>
          📞 {advice()}
        </div>
      </Show>

      {/* DLP 警告確認 (送信前チェックの所見) */}
      <Show when={dlpWarnings().length > 0}>
        <div style={{
          padding: "10px 16px",
          background: "#FF6B7012",
          "border-bottom": "1px solid #FF6B7030",
          "font-size": "12px",
          color: "#FF6B70",
        }}>
          <div style={{ "font-weight": "600", "margin-bottom": "4px" }}>
            ⚠ DLP 警告 — 機微情報が含まれている可能性があります
          </div>
          <ul style={{ margin: "0 0 8px", "padding-left": "18px" }}>
            <For each={dlpWarnings()}>{w => <li>{w}</li>}</For>
          </ul>
          <div style={{ display: "flex", gap: "8px" }}>
            <button
              onClick={() => { setDlpWarnings([]); handleSend(true); }}
              style={{
                background: "#FF6B70", color: "#0A0E14", border: "none",
                "border-radius": "4px", padding: "4px 12px",
                "font-size": "11px", "font-weight": "600", cursor: "pointer",
              }}
            >それでも送信</button>
            <button
              onClick={() => setDlpWarnings([])}
              style={{
                background: "none", color: "#8B96A5",
                border: "1px solid #2A3441", "border-radius": "4px",
                padding: "4px 12px", "font-size": "11px", cursor: "pointer",
              }}
            >内容を修正する</button>
          </div>
        </div>
      </Show>

      {/* フォーム */}
      <div style={{ padding: "12px 16px", display: "flex", "flex-direction": "column", gap: "8px" }}>
        <input
          type="email"
          placeholder="差出人 (自分のメールアドレス)"
          value={from()}
          onInput={e => setFrom(e.currentTarget.value)}
          style={inputStyle}
        />
        <input
          type="email"
          placeholder="宛先 (カンマ区切りで複数可)"
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
        <div style={{ padding: "8px 16px", "font-size": "12px", color: "#FF6B70" }}>
          {error()}
        </div>
      </Show>

      {/* MLS 暗号化の選択 — 宛先が会話成立済みの単一相手のときのみ表示 */}
      <Show when={mlsPeer()}>
        <div style={{
          padding: "6px 16px", "font-size": "11px",
          display: "flex", "align-items": "center", gap: "8px",
        }}>
          <label style={{ display: "flex", "align-items": "center", gap: "6px", cursor: "pointer", color: "#00C4CC" }}>
            <input
              type="checkbox"
              checked={useMls()}
              onChange={e => setUseMls(e.currentTarget.checked)}
            />
            🔐 MLS で暗号化して送信
          </label>
          <span style={{ color: "#6B7A94" }}>
            件名・本文はサーバにも表示されません (相手の Kaname のみ復号)
          </span>
          {/* Phase 5: 照合状態を送信直前に表示 — 番号変更は警告、未検証は注意 */}
          <Show when={mlsPeer()?.safety_changed}>
            <span style={{ color: "#FF6B70" }}>
              ⚠ 安全番号が照合時から変わっています — 鍵変更または中間者の可能性。別経路で再確認してください
            </span>
          </Show>
          <Show when={!mlsPeer()?.safety_changed && !mlsPeer()?.verified}>
            <span style={{ color: "#FFB224" }}>
              この相手とは安全番号が未照合です (セキュリティ画面で照合できます)
            </span>
          </Show>
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
          onClick={() => handleSend()}
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


        <div style={{ flex: "1" }} />

        <span style={{ "font-size": "11px", color: "#8B96A5" }}>
          Esc でキャンセル
        </span>
      </div>
    </div>
  );
};

// ===========================================================================
// Admin Dashboard コンポーネント
// ===========================================================================

export default Compose;
