// src/main.tsx
//
// Kaname フロントエンド エントリポイント
//
// 全コンポーネントを統合するルーター。
// Tauri の invoke コマンドとリアルタイムイベントを接続。
//
// アーキテクチャ:
//   main.tsx → KanameApp (state management)
//            → KanameDesign (Liquid Glass UI)
//            → SecurityDashboard (BEC/DLP/AI監査)
//            → KanameAppleFeatures (Quick Look/Undo/Smart Reply)
//            → KanameAppleV5 (Swipe/Focus/Natural Search/Safety Number)

import { render } from "solid-js/web";
import { createSignal, createEffect, onMount, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { initI18n, t } from "./i18n";

// ── コンポーネントインポート ──
import { KanameDesign }        from "./ui/KanameDesign";
import { SecurityDashboard }   from "./ui/SecurityDashboard";
import { KanameAppleFeatures } from "./ui/KanameAppleFeatures";
import { KanameAppleV5 }       from "./ui/KanameAppleV5";

// ── 型定義 ──

type View =
  | "inbox"
  | "security"
  | "features_demo"
  | "v5_demo";

interface AppState {
  initialized:    boolean;
  selectedEmailId: string | null;
  activeView:     View;
  unreadCount:    number;
  becAlertCount:  number;
  serverOnline:   boolean;
}

// ── グローバルエラーハウンダリ ──

window.addEventListener("unhandledrejection", (e) => {
  console.error("[Kaname] Unhandled Promise rejection:", e.reason);
  // 本番: Tauri コマンドでクラッシュレポートを送信
  invoke("log_error", { message: String(e.reason) }).catch(() => {});
});

window.onerror = (msg, src, line, col, err) => {
  console.error("[Kaname] Global error:", msg, err);
  invoke("log_error", { message: `${msg} @ ${src}:${line}` }).catch(() => {});
  return false;
};

// ── メインアプリコンポーネント ──

const App = () => {
  const [state, setState] = createSignal<AppState>({
    initialized:     false,
    selectedEmailId: null,
    activeView:      "inbox",
    unreadCount:     0,
    becAlertCount:   0,
    serverOnline:    false,
  });

  const [initError, setInitError] = createSignal<string | null>(null);

  // ── 起動シーケンス ──
  onMount(async () => {
    try {
      // 0. i18n 初期化 (ブラウザ言語自動検出)
      await initI18n();

      // 1. バックエンド接続確認
      const health = await invoke<{ ok: boolean; version: string }>("health_check")
        .catch(() => ({ ok: false, version: "unknown" }));

      // 2. 初期状態ロード
      const summary = await invoke<{
        unread: number;
        bec_alerts: number;
      }>("mail_get_summary").catch(() => ({ unread: 0, bec_alerts: 0 }));

      setState(s => ({
        ...s,
        initialized:   true,
        serverOnline:  health.ok,
        unreadCount:   summary.unread,
        becAlertCount: summary.bec_alerts,
      }));

      // 3. リアルタイムイベント購読
      await listen<{ unread: number; bec: number }>("mail:summary_updated", (event) => {
        setState(s => ({
          ...s,
          unreadCount:   event.payload.unread,
          becAlertCount: event.payload.bec,
        }));
      });

      await listen<{ email_id: string; verdict: string }>("bec:alert", (event) => {
        console.warn("[BEC]", event.payload.verdict, event.payload.email_id);
        setState(s => ({ ...s, becAlertCount: s.becAlertCount + 1 }));
      });

    } catch (err) {
      setInitError(String(err));
      setState(s => ({ ...s, initialized: true }));
    }
  });

  // ── ローディング ──
  const Loading = () => (
    <div style={{
      height: "100vh",
      display: "flex",
      "flex-direction": "column",
      "align-items": "center",
      "justify-content": "center",
      background: "#080C11",
      color: "rgba(255,255,255,.4)",
      gap: "16px",
      "font-family": "-apple-system, 'Hiragino Sans', system-ui, sans-serif",
    }}>
      <div style={{
        width: "48px", height: "48px",
        background: "linear-gradient(135deg, #00C4CC, #005C62)",
        "border-radius": "12px",
        display: "flex", "align-items": "center", "justify-content": "center",
        "font-size": "24px", "font-weight": "700", color: "#001A1B",
        animation: "pulse 1.5s ease-in-out infinite",
      }}>
        要
      </div>
      <div style={{ "font-size": "13px" }}>Kaname を起動中...</div>
      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }`}</style>
    </div>
  );

  // ── エラー状態 ──
  const ErrorState = (props: { message: string }) => (
    <div style={{
      height: "100vh",
      display: "flex",
      "flex-direction": "column",
      "align-items": "center",
      "justify-content": "center",
      background: "#080C11",
      color: "rgba(255,255,255,.6)",
      gap: "12px",
      "font-family": "-apple-system, 'Hiragino Sans', system-ui, sans-serif",
    }}>
      <div style={{ "font-size": "32px" }}>⚠</div>
      <div style={{ "font-size": "15px", "font-weight": "500" }}>起動エラー</div>
      <div style={{
        "font-size": "12px",
        "font-family": "monospace",
        color: "rgba(255,100,100,.7)",
        "max-width": "400px",
        "text-align": "center",
        "line-height": "1.5",
      }}>
        {props.message}
      </div>
      <button
        onClick={() => location.reload()}
        style={{
          padding: "8px 20px",
          background: "rgba(0,196,204,.15)",
          border: "0.5px solid rgba(0,196,204,.3)",
          "border-radius": "9999px",
          color: "#00C4CC",
          "font-size": "13px",
          cursor: "pointer",
          "margin-top": "8px",
        }}
      >
        再起動
      </button>
    </div>
  );

  // ── ナビゲーションバー (デモ用ビュー切り替え) ──
  const NavBar = () => (
    <div style={{
      position: "fixed",
      bottom: "0",
      left: "0",
      right: "0",
      height: "44px",
      background: "rgba(8,12,17,.95)",
      "backdrop-filter": "blur(20px)",
      "border-top": "0.5px solid rgba(255,255,255,.07)",
      display: "flex",
      "align-items": "center",
      "justify-content": "center",
      gap: "4px",
      "z-index": "9999",
    }}>
      {(["inbox", "security", "features_demo", "v5_demo"] as View[]).map(v => (
        <button
          onClick={() => setState(s => ({ ...s, activeView: v }))}
          style={{
            padding: "5px 14px",
            background: state().activeView === v
              ? "rgba(0,196,204,.15)"
              : "transparent",
            border: state().activeView === v
              ? "0.5px solid rgba(0,196,204,.3)"
              : "none",
            "border-radius": "9999px",
            color: state().activeView === v
              ? "#00C4CC"
              : "rgba(255,255,255,.3)",
            "font-size": "11px",
            cursor: "pointer",
          }}
        >
          {{ inbox:"受信トレイ", security:"セキュリティ", features_demo:"機能デモ", v5_demo:"V5デモ" }[v]}
        </button>
      ))}
    </div>
  );

  return (
    <Show
      when={state().initialized}
      fallback={<Loading />}
    >
      <Show
        when={!initError()}
        fallback={<ErrorState message={initError()!} />}
      >
        <div style={{ "padding-bottom": "44px" }}>
          <Show when={state().activeView === "inbox"}>
            <KanameDesign />
          </Show>
          <Show when={state().activeView === "security"}>
            <SecurityDashboard selectedEmailId={state().selectedEmailId} />
          </Show>
          <Show when={state().activeView === "features_demo"}>
            <KanameAppleFeatures />
          </Show>
          <Show when={state().activeView === "v5_demo"}>
            <KanameAppleV5 />
          </Show>
          <NavBar />
        </div>
      </Show>
    </Show>
  );
};

// ── DOM マウント ──
const root = document.getElementById("root");
if (!root) {
  throw new Error("#root 要素が見つかりません");
}
render(() => <App />, root);
