// src/ui/Compose.tsx — メール作成コンポーネント
//
// 機能:
//   - 送信前アドバイザリ (oobv_recommend で別経路確認推奨の文脈を検出)
//   - (AI 返信草案は LLM 推論がスタブのため提供しない。以前は定型文を
//      「AI 草案」と表示して挿入しており、AI 出力を偽っていた)
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
  // 差出人: JMAP セッションはアカウントのメールアドレスを公開しないため
  // (Session.primary_accounts は accountId のみ)、利用者に入力してもらう。
  const [from,     setFrom]    = createSignal("");
  const [to,       setTo]      = createSignal(props.initialTo || "");
  const [subject,  setSubject] = createSignal(props.initialSubject || "");
  const [body,     setBody]    = createSignal("");
  const [sending,  setSending] = createSignal(false);
  const [advice,   setAdvice]  = createSignal<string | null>(null);
  const [error,    setError]   = createSignal<string | null>(null);
  const [mlsReady, setMlsReady] = createSignal<boolean | null>(null);

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

  // MLS 対応チェック
  //
  // 以前はドメイン名の接尾辞だけを見て「MLS 対応」と表示していたが、
  // kaname-mls は XOR モック段階 (gap-analysis D1) であり、宛先が何であれ
  // 実際に MLS 暗号化は行われない。実装されていない保護を UI が
  // 「対応済み」と示すのは利用者を欺くため、常に null (非対応) を返す。
  // KPD による実確認は MLS 本実装と同時に入れる。
  createEffect(() => {
    to();
    setMlsReady(null);
  });

  const handleSend = async () => {
    if (!from().trim() || !to().trim() || !subject().trim() || !body().trim()) {
      setError("差出人・宛先・件名・本文は必須です");
      return;
    }
    setSending(true);
    setError(null);
    try {
      await invoke("mail_send", {
        from:    from(),
        to:      [to()],
        subject: subject(),
        body:    body(),
      });
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

export default Compose;
