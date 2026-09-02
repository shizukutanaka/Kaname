// src/ui/Compose.tsx — メール作成コンポーネント
//
// 機能:
//   - DLP 事前チェック (送信前にリアルタイム警告)
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
  const [dlpWarn,  setDlpWarn] = createSignal<string | null>(null);
  const [error,    setError]   = createSignal<string | null>(null);
  const [mlsReady, setMlsReady] = createSignal<boolean | null>(null);

  // DLP リアルタイムチェック (debounced)
  let dlpTimer: ReturnType<typeof setTimeout>;
  createEffect(() => {
    const b = body();
    clearTimeout(dlpTimer);
    dlpTimer = setTimeout(async () => {
      if (b.length < 20) { setDlpWarn(null); return; }
      // 注: 入力中のリアルタイム DLP 警告用コマンドは未実装。ただし
      // **送信時には mail_send が Direction::Outbound の DLP を実行し、
      // Block 判定なら送信せずエラーを返す** (commands.rs: mail_send_real)。
      // 保護は効いており、ここで欠けているのは事前警告の UX のみ。
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
