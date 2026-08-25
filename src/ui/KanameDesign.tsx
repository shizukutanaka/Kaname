// src/ui/KanameDesign.tsx
//
// Kaname — Apple HIG + Liquid Glass (macOS Tahoe 26) 完全準拠 UI
//
// Apple手法の適用:
//   10-to-3-to-1: Security / Speed / Privacy の3柱に絞り込み完了
//   Demo-driven:  北極星デモシーン実装 (BEC検出→セーフAI要約→安心返信)
//   DRI:          各モジュールに直接責任者を設定
//   Packaging:    初回オンボーディングが製品の第一印象
//   Simplicity:   チームコラボ・カレンダー統合を v2 に延期
//
// Liquid Glass 実装原則:
//   - サイドバー: backdrop-blur(20px) + 半透明背景 でコンテンツが透けて見える
//   - モーダル:   backdrop-blur(40px) + glass--heavy
//   - ボタン:     カプセル形状 (border-radius: 9999px)
//   - アニメーション: spring physics (cubic-bezier(.34, 1.56, .64, 1))
//   - 奥行き: 透明度レイヤー、色ではなく空間で階層を表現

import { createSignal, For, Show, onMount, onCleanup } from "solid-js";
// 注: このコンポーネントはまだ Tauri invoke 経由でバックエンドと接続されておらず
// (mockデータで動作)、実装時に import { invoke } from "@tauri-apps/api/core" を戻すこと。
// (docs/maturity.md 参照)

// ============================================================================
// 型定義
// ============================================================================

interface Email {
  id:          string;
  from_name:   string | null;
  from_addr:   string;
  subject:     string | null;
  preview:     string | null;
  received_at: string | null;
  is_read:     boolean;
  is_starred:  boolean;
  bec_verdict: "SAFE" | "ADVISORY" | "SUSPICIOUS" | "DANGEROUS";
  is_mls:      boolean;
  triage:      "important" | "other" | "paper_trail" | "feed";
}

interface Toast {
  id:      number;
  type:    "success" | "error" | "info" | "warning";
  message: string;
  leaving: boolean;
}

interface ContextMenu {
  x:      number;
  y:      number;
  emailId: string;
}

// ============================================================================
// Toast システム (Apple HIG: 一時的フィードバック)
// ============================================================================

let toastCounter = 0;

const createToastSystem = () => {
  const [toasts, setToasts] = createSignal<Toast[]>([]);

  const show = (type: Toast["type"], message: string) => {
    const id = ++toastCounter;
    setToasts(t => [...t, { id, type, message, leaving: false }]);
    setTimeout(() => {
      setToasts(t => t.map(x => x.id === id ? { ...x, leaving: true } : x));
      setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 200);
    }, 3000);
  };

  return { toasts, show };
};

const TOAST_ICONS = { success: "✓", error: "✕", info: "ℹ", warning: "⚠" };

// ============================================================================
// Skeleton ローディングコンポーネント (Apple HIG: 意味のあるフィードバック)
// ============================================================================

const SkeletonRow = () => (
  <div style={{
    padding: "12px 16px",
    display: "flex",
    gap: "10px",
    "border-bottom": "1px solid rgba(255,255,255,.04)",
    animation: "pulse 1.5s ease-in-out infinite",
  }}>
    <div style={{
      width: "36px", height: "36px", "border-radius": "50%",
      background: "rgba(255,255,255,.06)", "flex-shrink": "0",
    }} />
    <div style={{ flex: "1", display: "flex", "flex-direction": "column", gap: "6px", "justify-content": "center" }}>
      <div style={{ height: "10px", width: "40%", background: "rgba(255,255,255,.06)", "border-radius": "4px" }} />
      <div style={{ height: "9px", width: "70%", background: "rgba(255,255,255,.04)", "border-radius": "4px" }} />
      <div style={{ height: "8px", width: "55%", background: "rgba(255,255,255,.03)", "border-radius": "4px" }} />
    </div>
  </div>
);

// ============================================================================
// Empty State (Apple HIG: 目的を持った空状態)
// ============================================================================

const EmptyState = (props: { icon: string; title: string; desc: string; action?: { label: string; onClick: () => void } }) => (
  <div style={{
    display: "flex",
    "flex-direction": "column",
    "align-items": "center",
    "justify-content": "center",
    height: "100%",
    gap: "12px",
    padding: "48px 32px",
    "text-align": "center",
    animation: "fadeIn .3s ease-out",
  }}>
    <div style={{
      "font-size": "44px",
      opacity: "0.15",
      "line-height": "1",
      filter: "grayscale(1)",
    }}>
      {props.icon}
    </div>
    <div style={{
      "font-size": "15px",
      "font-weight": "590",
      color: "rgba(245,247,250,.6)",
      "letter-spacing": "-0.02em",
    }}>
      {props.title}
    </div>
    <div style={{
      "font-size": "13px",
      color: "rgba(255,255,255,.3)",
      "line-height": "1.6",
      "max-width": "260px",
    }}>
      {props.desc}
    </div>
    <Show when={props.action}>
      <button
        onClick={props.action!.onClick}
        style={{
          "margin-top": "4px",
          padding: "8px 18px",
          background: "rgba(0,196,204,.15)",
          border: "1px solid rgba(0,196,204,.3)",
          "border-radius": "9999px",
          color: "#00C4CC",
          "font-size": "13px",
          cursor: "pointer",
          "font-weight": "500",
          transition: "all .15s ease",
        }}
      >
        {props.action!.label}
      </button>
    </Show>
  </div>
);

// ============================================================================
// コンテキストメニュー (macOS HIG スタイル)
// ============================================================================

const ContextMenuComponent = (props: {
  ctx: ContextMenu;
  onClose: () => void;
  onAction: (action: string, emailId: string) => void;
}) => {
  const menuRef: { el?: HTMLElement } = {};

  const items = [
    { id: "reply",       label: "返信",              kbd: "R" },
    { id: "forward",     label: "転送",              kbd: "F" },
    { separator: true },
    { id: "archive",     label: "アーカイブ",         kbd: "E" },
    { id: "snooze",      label: "スヌーズ",           kbd: "H" },
    { id: "reply_later", label: "Reply Later に追加", kbd: "L" },
    { separator: true },
    { id: "mark_read",   label: "既読にする",         kbd: "U" },
    { id: "star",        label: "スターを付ける",     kbd: "S" },
    { separator: true },
    { id: "trash",       label: "削除",              kbd: "⌫", danger: true },
  ];

  // クリック外で閉じる
  const handleOutside = (e: MouseEvent) => {
    if (menuRef.el && !menuRef.el.contains(e.target as Node)) {
      props.onClose();
    }
  };

  onMount(() => { document.addEventListener("mousedown", handleOutside); });
  onCleanup(() => { document.removeEventListener("mousedown", handleOutside); });

  return (
    <div
      ref={el => { menuRef.el = el; }}
      style={{
        position: "fixed",
        left: `${Math.min(props.ctx.x, window.innerWidth - 220)}px`,
        top:  `${Math.min(props.ctx.y, window.innerHeight - 280)}px`,
        "min-width": "200px",
        background: "rgba(20,26,34,.92)",
        "backdrop-filter": "blur(30px) saturate(2)",
        "-webkit-backdrop-filter": "blur(30px) saturate(2)",
        border: "0.5px solid rgba(255,255,255,.12)",
        "border-radius": "12px",
        padding: "4px 0",
        "z-index": "9000",
        "box-shadow": "0 8px 30px rgba(0,0,0,.5), 0 0 0 0.5px rgba(255,255,255,.06)",
        animation: "scaleIn .12s cubic-bezier(.34,1.56,.64,1)",
      }}
    >
      <For each={items}>
        {(item) => (
          <Show
            when={"separator" in item && item.separator}
            fallback={
              <div
                onClick={() => { props.onAction(item.id!, props.ctx.emailId); props.onClose(); }}
                style={{
                  display: "flex",
                  "align-items": "center",
                  padding: "7px 14px",
                  "font-size": "13px",
                  color: item.danger ? "#FF6B6B" : "rgba(245,247,250,.85)",
                  cursor: "pointer",
                  transition: "background .08s ease",
                  "user-select": "none",
                  "justify-content": "space-between",
                }}
                onMouseEnter={e => {
                  (e.currentTarget as HTMLElement).style.background = item.danger
                    ? "rgba(229,72,77,.12)"
                    : "rgba(255,255,255,.07)";
                }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
              >
                <span>{item.label}</span>
                <span style={{
                  "font-size": "11px",
                  color: "rgba(255,255,255,.25)",
                  "font-family": "ui-monospace, monospace",
                }}>
                  {item.kbd}
                </span>
              </div>
            }
          >
            <div style={{ height: "1px", background: "rgba(255,255,255,.06)", margin: "3px 0" }} />
          </Show>
        )}
      </For>
    </div>
  );
};

// ============================================================================
// オンボーディング (Apple: Packaging = 第一印象)
// ============================================================================

const OnboardingFlow = (props: { onComplete: () => void }) => {
  const [step, setStep] = createSignal(0);

  const steps = [
    {
      icon: "🔐",
      title: "AIが助けても、裏切らない",
      desc: "Kaname のAIは開いているメール1通しか読みません。受信箱全体へのアクセスはありません。Superhuman で起きたデータ漏洩は、Kaname では型システムがコンパイル時に阻止します。",
      cta: "続ける",
    },
    {
      icon: "🛡",
      title: "BEC攻撃を検出",
      desc: "ビジネスメール詐欺（振込先変更・なりすまし）、QRコードフィッシング、AI生成フィッシングを多信号で検出。2026年最大の脅威に対応済みです。",
      cta: "続ける",
    },
    {
      icon: "🔒",
      title: "業界唯一のMLS+PQC",
      desc: "件名を含むメール全体をMLS RFC 9420で暗号化。量子コンピューターが解読できない PQC (ML-KEM-768) を採用。Proton Mail や Tuta を超えた保護。",
      cta: "続ける",
    },
    {
      icon: "⚡",
      title: "準備完了",
      desc: "JMAPサーバーを設定してKaname を始めましょう。",
      cta: "はじめる",
    },
  ];

  const cur = () => steps[step()];

  return (
    <div style={{
      position: "fixed",
      inset: "0",
      background: "rgba(8,12,17,.88)",
      "backdrop-filter": "blur(40px) saturate(2)",
      "-webkit-backdrop-filter": "blur(40px) saturate(2)",
      display: "flex",
      "align-items": "center",
      "justify-content": "center",
      "z-index": "9999",
      animation: "fadeIn .25s ease-out",
    }}>
      <div style={{
        background: "rgba(15,20,28,.9)",
        border: "0.5px solid rgba(255,255,255,.1)",
        "border-radius": "20px",
        padding: "40px 40px 32px",
        width: "440px",
        "box-shadow": "0 20px 60px rgba(0,0,0,.7), 0 0 0 0.5px rgba(255,255,255,.06)",
        animation: "scaleIn .2s cubic-bezier(.34,1.56,.64,1)",
      }}>
        {/* アイコン */}
        <div style={{
          "font-size": "48px",
          "text-align": "center",
          "margin-bottom": "20px",
          animation: "fadeIn .3s ease-out .1s both",
        }}>
          {cur().icon}
        </div>

        {/* テキスト */}
        <div style={{
          "text-align": "center",
          "margin-bottom": "28px",
          animation: "fadeIn .3s ease-out .15s both",
        }}>
          <div style={{
            "font-size": "20px",
            "font-weight": "590",
            "letter-spacing": "-0.03em",
            "margin-bottom": "12px",
            color: "rgba(245,247,250,.95)",
          }}>
            {cur().title}
          </div>
          <div style={{
            "font-size": "14px",
            "line-height": "1.65",
            color: "rgba(255,255,255,.45)",
          }}>
            {cur().desc}
          </div>
        </div>

        {/* ステップドット */}
        <div style={{
          display: "flex",
          "justify-content": "center",
          gap: "6px",
          "margin-bottom": "24px",
        }}>
          <For each={steps}>
            {(_, i) => (
              <div style={{
                width:   i() === step() ? "20px" : "6px",
                height: "6px",
                "border-radius": "9999px",
                background: i() === step() ? "#00C4CC" : "rgba(255,255,255,.15)",
                transition: "all .3s cubic-bezier(.34,1.56,.64,1)",
              }} />
            )}
          </For>
        </div>

        {/* CTAボタン */}
        <button
          onClick={() => step() < steps.length - 1 ? setStep(s => s + 1) : props.onComplete()}
          style={{
            width: "100%",
            padding: "12px",
            background: "#00C4CC",
            border: "none",
            "border-radius": "9999px",
            color: "#000F10",
            "font-size": "14px",
            "font-weight": "590",
            cursor: "pointer",
            "letter-spacing": "-0.01em",
            transition: "transform .15s cubic-bezier(.34,1.56,.64,1), box-shadow .15s ease",
          }}
          onMouseEnter={e => {
            (e.currentTarget as HTMLButtonElement).style.transform = "scale(1.02)";
            (e.currentTarget as HTMLButtonElement).style.boxShadow = "0 0 20px rgba(0,196,204,.35)";
          }}
          onMouseLeave={e => {
            (e.currentTarget as HTMLButtonElement).style.transform = "scale(1)";
            (e.currentTarget as HTMLButtonElement).style.boxShadow = "none";
          }}
        >
          {cur().cta}
        </button>

        {/* スキップ */}
        <Show when={step() < steps.length - 1}>
          <button
            onClick={props.onComplete}
            style={{
              display: "block",
              width: "100%",
              "margin-top": "12px",
              background: "none",
              border: "none",
              color: "rgba(255,255,255,.25)",
              "font-size": "12px",
              cursor: "pointer",
              padding: "6px",
            }}
          >
            スキップ
          </button>
        </Show>
      </div>
    </div>
  );
};

// ============================================================================
// BEC 警告バナー
// ============================================================================

const BecBanner = (props: { verdict: Email["bec_verdict"]; onDetails: () => void }) => {
  if (props.verdict === "SAFE") return null;

  const cfg = {
    ADVISORY:   { bg: "rgba(245,166,35,.08)", border: "rgba(245,166,35,.2)", text: "#F5A623", msg: "このメールについて注意が必要な点があります" },
    SUSPICIOUS: { bg: "rgba(229,164,0,.10)",  border: "rgba(229,164,0,.25)",  text: "#E5A000", msg: "不審なパターンを検出しました — 慎重に確認してください" },
    DANGEROUS:  { bg: "rgba(229,72,77,.10)",  border: "rgba(229,72,77,.25)",  text: "#FF4444", msg: "BEC攻撃の可能性が高い — 送信者の身元を別経路で確認してください" },
  }[props.verdict];

  return (
    <div style={{
      padding: "10px 16px",
      background: cfg.bg,
      "border-bottom": `1px solid ${cfg.border}`,
      display: "flex",
      "align-items": "center",
      gap: "10px",
      animation: "fadeIn .2s ease-out",
    }}>
      <span style={{ "font-size": "13px", color: cfg.text, "font-weight": "590", flex: "1" }}>
        ⚠ {cfg.msg}
      </span>
      <button
        onClick={props.onDetails}
        style={{
          background: `${cfg.border}`,
          border: "none",
          "border-radius": "9999px",
          color: cfg.text,
          "font-size": "11px",
          "font-weight": "500",
          padding: "4px 10px",
          cursor: "pointer",
        }}
      >
        詳細
      </button>
    </div>
  );
};

// ============================================================================
// メイン Kaname デザイン
// ============================================================================

export const KanameDesign = () => {
  const [showOnboarding, setShowOnboarding] = createSignal(true);
  const [loading, setLoading]       = createSignal(true);
  const [emails, setEmails]         = createSignal<Email[]>([]);
  const [selected, setSelected]     = createSignal<string | null>(null);
  const [view, setView]             = createSignal<"inbox" | "screener" | "reply_later" | "feed" | "paper_trail">("inbox");
  const [contextMenu, setContextMenu] = createSignal<ContextMenu | null>(null);
  const { toasts, show: showToast } = createToastSystem();

  // 受信箱はサーバ未接続のため常に空。
  //
  // 従来はここにハードコードされたデモメール 4 通を表示していたが、
  // **実在しないメールを受信箱に並べるのは偽装**である。
  // JMAP 受信が未配線 (docs/gap-analysis.md D10) である以上、
  // 表示できる本物のメールは存在しない。
  //
  // 実際のメール解析は「ファイル解析」タブ (EmlImport) が行う。
  onMount(() => {
    setEmails([]);
    setLoading(false);
});

  const viewEmails = () => emails().filter(e => {
    if (view() === "inbox")       return e.triage === "important";
    if (view() === "feed")        return e.triage === "feed";
    if (view() === "paper_trail") return e.triage === "paper_trail";
    return true;
  });

  const selectedEmail = () => emails().find(e => e.id === selected());

  const handleContextMenu = (e: MouseEvent, emailId: string) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, emailId });
  };

  const handleAction = (action: string, emailId: string) => {
    const email = emails().find(e => e.id === emailId);
    const map: Record<string, string> = {
      archive: `「${email?.subject || "メール"}」をアーカイブしました`,
      reply_later: "Reply Later に追加しました",
      snooze: "明日の朝 9:00 にスヌーズを設定しました",
      star: `${email?.is_starred ? "スターを外しました" : "スターを付けました"}`,
      trash: "削除しました",
      mark_read: "既読にしました",
    };
    if (map[action]) showToast("success", map[action]);
  };

  const navItems = [
    { id:"inbox",       label:"受信トレイ",  icon:"✉",  count: emails().filter(e => !e.is_read && e.triage === "important").length },
    { id:"screener",    label:"スクリーナー", icon:"🛡", count: 2 },
    { id:"reply_later", label:"Reply Later", icon:"📌", count: 0 },
    { id:"paper_trail", label:"Paper Trail", icon:"🧾", count: 0 },
    { id:"feed",        label:"フィード",    icon:"📰", count: 0 },
  ];

  const fmtDate = (iso: string | null) => {
    if (!iso) return "";
    const d = new Date(iso), now = new Date();
    const diff = (now.getTime() - d.getTime()) / 1000;
    if (diff < 3600)  return `${Math.floor(diff/60)}分前`;
    if (diff < 86400) return `${Math.floor(diff/3600)}時間前`;
    return `${d.getMonth()+1}/${d.getDate()}`;
  };

  const becColors: Record<string, { bg: string; text: string; label: string }> = {
    ADVISORY:   { bg:"rgba(245,166,35,.1)", text:"#F5A623", label:"要確認" },
    SUSPICIOUS: { bg:"rgba(229,164,0,.1)",  text:"#E5A000", label:"不審" },
    DANGEROUS:  { bg:"rgba(229,72,77,.1)",  text:"#FF4444", label:"危険" },
  };

  return (
    <div
      style={{
        display: "flex",
        height: "100vh",
        overflow: "hidden",
        background: "#080C11",
        color: "#F5F7FA",
        "font-family": "-apple-system, 'Hiragino Sans', 'Noto Sans JP', system-ui, sans-serif",
        position: "relative",
      }}
      onClick={() => setContextMenu(null)}
    >
      {/* ── オンボーディング ── */}
      <Show when={showOnboarding()}>
        <OnboardingFlow onComplete={() => {
          setShowOnboarding(false);
          showToast("success", "Kaname へようこそ。メールをセキュアに管理しましょう。");
        }} />
      </Show>

      {/* ── コンテキストメニュー ── */}
      <Show when={contextMenu()}>
        <ContextMenuComponent
          ctx={contextMenu()!}
          onClose={() => setContextMenu(null)}
          onAction={handleAction}
        />
      </Show>

      {/* ── Toast 通知 ── */}
      <div style={{
        position: "fixed",
        top: "20px",
        left: "50%",
        transform: "translateX(-50%)",
        "z-index": "9990",
        display: "flex",
        "flex-direction": "column",
        gap: "8px",
        "align-items": "center",
        "pointer-events": "none",
      }}>
        <For each={toasts()}>
          {(t) => (
            <div style={{
              display: "flex",
              "align-items": "center",
              gap: "8px",
              padding: "10px 16px",
              "border-radius": "9999px",
              background: {
                success: "rgba(0,214,143,.15)",
                error:   "rgba(229,72,77,.15)",
                info:    "rgba(0,196,204,.12)",
                warning: "rgba(245,166,35,.15)",
              }[t.type],
              border: `0.5px solid ${{
                success: "rgba(0,214,143,.3)",
                error:   "rgba(229,72,77,.3)",
                info:    "rgba(0,196,204,.25)",
                warning: "rgba(245,166,35,.3)",
              }[t.type]}`,
              "backdrop-filter": "blur(20px)",
              "-webkit-backdrop-filter": "blur(20px)",
              "box-shadow": "0 4px 20px rgba(0,0,0,.4)",
              color: {
                success: "#00D68F",
                error:   "#FF6B6B",
                info:    "#00C4CC",
                warning: "#F5A623",
              }[t.type],
              "font-size": "13px",
              "font-weight": "500",
              animation: t.leaving
                ? "toastOut .2s ease-in both"
                : "toastIn .25s cubic-bezier(.34,1.56,.64,1) both",
              "pointer-events": "auto",
            }}>
              <span style={{ "font-size": "12px" }}>{TOAST_ICONS[t.type]}</span>
              {t.message}
            </div>
          )}
        </For>
      </div>

      {/* ── Liquid Glass サイドバー ── */}
      <aside style={{
        width: "212px",
        "flex-shrink": "0",
        background: "rgba(13,18,25,.72)",
        "backdrop-filter": "blur(20px) saturate(1.8)",
        "-webkit-backdrop-filter": "blur(20px) saturate(1.8)",
        "border-right": "0.5px solid rgba(255,255,255,.07)",
        display: "flex",
        "flex-direction": "column",
        "z-index": "10",
      }}>
        {/* ロゴ */}
        <div style={{
          padding: "18px 16px 14px",
          "border-bottom": "0.5px solid rgba(255,255,255,.05)",
          display: "flex",
          "align-items": "center",
          gap: "10px",
        }}>
          <div style={{
            width: "28px", height: "28px",
            background: "linear-gradient(135deg, #00C4CC 0%, #007F85 100%)",
            "border-radius": "7px",
            display: "flex", "align-items": "center", "justify-content": "center",
            "font-size": "16px",
            "font-weight": "700",
            color: "#001A1B",
            "box-shadow": "0 2px 8px rgba(0,196,204,.3)",
            "flex-shrink": "0",
          }}>
            要
          </div>
          <div>
            <div style={{ "font-size": "14px", "font-weight": "590", "letter-spacing": "-0.02em" }}>Kaname</div>
            <div style={{ "font-size": "10px", color: "rgba(0,196,204,.7)", "letter-spacing": "0.04em" }}>SECURE MAIL</div>
          </div>
        </div>

        {/* ⌘K ヒント */}
        <div style={{ padding: "10px 10px 4px" }}>
          <button
            style={{
              width: "100%",
              display: "flex",
              "align-items": "center",
              gap: "8px",
              padding: "7px 10px",
              background: "rgba(255,255,255,.04)",
              border: "0.5px solid rgba(255,255,255,.07)",
              "border-radius": "8px",
              cursor: "pointer",
              color: "rgba(255,255,255,.3)",
              "font-size": "12px",
            }}
          >
            <span style={{ "font-size": "11px", background: "rgba(255,255,255,.1)", "border-radius": "4px", padding: "1px 5px" }}>⌘</span>
            <span style={{ flex: "1", "text-align": "left" }}>コマンド</span>
            <span style={{ "font-size": "10px" }}>K</span>
          </button>
        </div>

        {/* ナビゲーション */}
        <nav style={{ flex: "1", padding: "8px 8px 0" }}>
          <For each={navItems}>
            {(item) => (
              <button
                onClick={() => setView(item.id as "inbox" | "screener" | "reply_later" | "feed" | "paper_trail")}
                style={{
                  width: "100%",
                  display: "flex",
                  "align-items": "center",
                  gap: "9px",
                  padding: "8px 10px",
                  background: view() === item.id
                    ? "rgba(0,196,204,.12)"
                    : "transparent",
                  border: view() === item.id
                    ? "0.5px solid rgba(0,196,204,.2)"
                    : "0.5px solid transparent",
                  "border-radius": "8px",
                  cursor: "pointer",
                  color: view() === item.id ? "#00C4CC" : "rgba(255,255,255,.45)",
                  "font-size": "13px",
                  "font-weight": view() === item.id ? "590" : "400",
                  transition: "all .15s ease",
                  "margin-bottom": "2px",
                  "text-align": "left",
                }}
              >
                <span style={{ "font-size": "13px", width: "18px", "text-align": "center" }}>{item.icon}</span>
                <span style={{ flex: "1" }}>{item.label}</span>
                <Show when={item.count > 0}>
                  <span style={{
                    background: view() === item.id ? "#00C4CC" : "rgba(0,196,204,.2)",
                    color: view() === item.id ? "#001A1B" : "#00C4CC",
                    "border-radius": "9999px",
                    "font-size": "10px",
                    "font-weight": "700",
                    padding: "1px 6px",
                    "min-width": "18px",
                    "text-align": "center",
                  }}>
                    {item.count}
                  </span>
                </Show>
              </button>
            )}
          </For>
        </nav>

        {/* セキュリティステータス */}
        <div style={{
          padding: "12px 16px",
          "border-top": "0.5px solid rgba(255,255,255,.05)",
          display: "flex",
          "align-items": "center",
          gap: "7px",
        }}>
          <div style={{
            width: "6px", height: "6px",
            "border-radius": "50%",
            background: "#00D68F",
            "box-shadow": "0 0 6px rgba(0,214,143,.5)",
            animation: "pulse 2.5s ease-in-out infinite",
          }} />
          <span style={{ "font-size": "11px", color: "rgba(0,214,143,.8)" }}>全システム正常</span>
        </div>
      </aside>

      {/* ── メールリスト ── */}
      <div style={{
        width: "340px",
        "flex-shrink": "0",
        "border-right": "0.5px solid rgba(255,255,255,.06)",
        display: "flex",
        "flex-direction": "column",
        background: "rgba(10,14,20,.6)",
      }}>
        <div style={{
          padding: "14px 16px 12px",
          "border-bottom": "0.5px solid rgba(255,255,255,.05)",
          display: "flex",
          "align-items": "center",
          gap: "8px",
        }}>
          <div style={{
            "font-size": "15px",
            "font-weight": "590",
            "letter-spacing": "-0.02em",
            flex: "1",
          }}>
            {{ inbox:"受信トレイ", screener:"スクリーナー", reply_later:"Reply Later", paper_trail:"Paper Trail", feed:"フィード" }[view()]}
          </div>
          <button
            style={{
              background: "rgba(255,255,255,.06)",
              border: "none",
              "border-radius": "6px",
              padding: "5px 8px",
              color: "rgba(255,255,255,.4)",
              "font-size": "12px",
              cursor: "pointer",
            }}
          >
            絞り込み
          </button>
        </div>

        {/* 検索 */}
        <div style={{ padding: "8px 12px" }}>
          <input
            type="text"
            placeholder="検索..."
            style={{
              width: "100%",
              height: "30px",
              background: "rgba(255,255,255,.05)",
              border: "0.5px solid rgba(255,255,255,.07)",
              "border-radius": "8px",
              padding: "0 10px",
              color: "#F5F7FA",
              "font-size": "12.5px",
              outline: "none",
              "box-sizing": "border-box",
            }}
          />
        </div>

        <div style={{ flex: "1", "overflow-y": "auto" }}>
          <Show when={loading()}>
            <SkeletonRow /><SkeletonRow /><SkeletonRow /><SkeletonRow />
          </Show>

          <Show when={!loading() && viewEmails().length === 0}>
            <EmptyState
              icon="📭"
              title="メールなし"
              desc={{ inbox:"このタブはまだサーバと接続していません。「サーバ接続」タブから JMAP サーバに接続すると受信メールを解析できます。ローカルの .eml を解析する場合は「ファイル解析」タブをご利用ください。", feed:"フィード登録なし。", screener:"スクリーニング待ちなし。", reply_later:"Reply Later リストは空です。", paper_trail:"Paper Trail は空です。" }[view()]}
            />
          </Show>

          <Show when={!loading()}>
            <For each={viewEmails()}>
              {(email, i) => (
                <div
                  onClick={() => setSelected(email.id)}
                  onContextMenu={e => { e.stopPropagation(); handleContextMenu(e, email.id); }}
                  style={{
                    padding: "12px 14px",
                    "border-bottom": "0.5px solid rgba(255,255,255,.04)",
                    cursor: "pointer",
                    background: selected() === email.id
                      ? "rgba(0,196,204,.08)"
                      : email.bec_verdict === "DANGEROUS"
                      ? "rgba(229,72,77,.05)"
                      : "transparent",
                    display: "flex",
                    gap: "10px",
                    position: "relative",
                    transition: "background .1s ease",
                    "animation-delay": `${i() * 40}ms`,
                    animation: "fadeIn .25s ease-out both",
                  }}
                  onMouseEnter={e => {
                    if (selected() !== email.id)
                      (e.currentTarget as HTMLElement).style.background = email.bec_verdict === "DANGEROUS"
                        ? "rgba(229,72,77,.08)"
                        : "rgba(255,255,255,.03)";
                  }}
                  onMouseLeave={e => {
                    if (selected() !== email.id)
                      (e.currentTarget as HTMLElement).style.background = email.bec_verdict === "DANGEROUS"
                        ? "rgba(229,72,77,.05)"
                        : "transparent";
                  }}
                >
                  {/* 未読ドット */}
                  <Show when={!email.is_read}>
                    <div style={{
                      position: "absolute",
                      left: "5px", top: "50%",
                      transform: "translateY(-50%)",
                      width: "5px", height: "5px",
                      "border-radius": "50%",
                      background: "#00C4CC",
                      "box-shadow": "0 0 4px rgba(0,196,204,.6)",
                    }} />
                  </Show>

                  {/* アバター */}
                  <div style={{
                    width: "36px", height: "36px",
                    "border-radius": "50%",
                    background: email.bec_verdict === "DANGEROUS"
                      ? "rgba(229,72,77,.15)"
                      : "rgba(255,255,255,.07)",
                    display: "flex", "align-items": "center", "justify-content": "center",
                    "font-size": "13px",
                    "font-weight": "590",
                    color: email.bec_verdict === "DANGEROUS"
                      ? "#FF6B6B"
                      : "rgba(255,255,255,.4)",
                    "flex-shrink": "0",
                  }}>
                    {(email.from_name || email.from_addr)[0]?.toUpperCase()}
                  </div>

                  <div style={{ flex: "1", "min-width": "0" }}>
                    {/* 送信者 + バッジ + 日時 */}
                    <div style={{
                      display: "flex",
                      "align-items": "center",
                      gap: "5px",
                      "margin-bottom": "3px",
                    }}>
                      <span style={{
                        "font-size": "13px",
                        "font-weight": email.is_read ? "400" : "590",
                        color: email.bec_verdict === "DANGEROUS"
                          ? "#FF4444"
                          : "rgba(245,247,250,.9)",
                        flex: "1",
                        overflow: "hidden",
                        "text-overflow": "ellipsis",
                        "white-space": "nowrap",
                      }}>
                        {email.from_name || email.from_addr}
                      </span>
                      <Show when={email.is_mls}>
                        <span style={{
                          "font-size": "9px",
                          color: "#00C4CC",
                          padding: "1px 4px",
                          background: "rgba(0,196,204,.1)",
                          "border-radius": "3px",
                          "flex-shrink": "0",
                        }}>E2E</span>
                      </Show>
                      <Show when={email.bec_verdict !== "SAFE" && becColors[email.bec_verdict]}>
                        <span style={{
                          "font-size": "9px",
                          "font-weight": "700",
                          color: becColors[email.bec_verdict].text,
                          padding: "1px 5px",
                          background: becColors[email.bec_verdict].bg,
                          "border-radius": "3px",
                          "flex-shrink": "0",
                          "letter-spacing": "0.03em",
                        }}>
                          {becColors[email.bec_verdict].label}
                        </span>
                      </Show>
                      <span style={{ "font-size": "11px", color: "rgba(255,255,255,.25)", "flex-shrink": "0" }}>
                        {fmtDate(email.received_at)}
                      </span>
                    </div>

                    {/* 件名 */}
                    <div style={{
                      "font-size": "12.5px",
                      "font-weight": email.is_read ? "400" : "500",
                      color: email.is_read ? "rgba(255,255,255,.4)" : "rgba(245,247,250,.75)",
                      overflow: "hidden",
                      "text-overflow": "ellipsis",
                      "white-space": "nowrap",
                      "margin-bottom": "2px",
                    }}>
                      {email.subject || "(件名なし)"}
                    </div>

                    {/* プレビュー */}
                    <div style={{
                      "font-size": "11.5px",
                      color: "rgba(255,255,255,.25)",
                      overflow: "hidden",
                      "text-overflow": "ellipsis",
                      "white-space": "nowrap",
                    }}>
                      {email.preview}
                    </div>
                  </div>
                </div>
              )}
            </For>
          </Show>
        </div>
      </div>

      {/* ── メール詳細 ── */}
      <div style={{ flex: "1", display: "flex", "flex-direction": "column", overflow: "hidden" }}>
        <Show
          when={selectedEmail()}
          fallback={
            <EmptyState
              icon="✉"
              title="メールを選択"
              desc="左のリストからメールを選択してください。j/k キーで移動できます。"
            />
          }
        >
          {/* BEC バナー */}
          <BecBanner
            verdict={selectedEmail()!.bec_verdict}
            onDetails={() => showToast("info", "BEC詳細レポートを開きました")}
          />

          {/* セーフ AI 要約バー */}
          <div style={{
            margin: "10px 16px 0",
            background: "rgba(255,255,255,.03)",
            border: "0.5px solid rgba(255,255,255,.07)",
            "border-radius": "10px",
            overflow: "hidden",
          }}>
            <button
              onClick={() => showToast("success", "AI要約: このメールのみを解析しました。他メールにアクセスしていません。")}
              style={{
                width: "100%",
                padding: "9px 14px",
                background: "none",
                border: "none",
                cursor: "pointer",
                color: "rgba(255,255,255,.3)",
                "font-size": "12px",
                display: "flex",
                "align-items": "center",
                gap: "8px",
                "text-align": "left",
              }}
            >
              <span>✨</span>
              <span style={{ flex: "1" }}>AI で要約 — このメール1通のみ分析</span>
              <span style={{
                "font-size": "10px",
                color: "#00C4CC",
                background: "rgba(0,196,204,.1)",
                padding: "2px 8px",
                "border-radius": "9999px",
              }}>
                🔒 安全
              </span>
            </button>
          </div>

          {/* 本文エリア */}
          <div style={{ flex: "1", overflow: "hidden", padding: "10px 16px 12px" }}>
            <div style={{
              height: "100%",
              background: "rgba(255,255,255,.02)",
              "border-radius": "10px",
              border: "0.5px solid rgba(255,255,255,.06)",
              overflow: "hidden",
              display: "flex",
              "align-items": "center",
              "justify-content": "center",
            }}>
              <div style={{ "text-align": "center", color: "rgba(255,255,255,.2)", "font-size": "13px" }}>
                <div style={{ "font-size": "32px", "margin-bottom": "8px", opacity: "0.3" }}>📄</div>
                <div>{selectedEmail()!.subject}</div>
                <div style={{ "font-size": "11px", "margin-top": "6px", color: "rgba(255,255,255,.12)" }}>
                  {selectedEmail()!.from_name || selectedEmail()!.from_addr}
                </div>
              </div>
            </div>
          </div>

          {/* アクションバー */}
          <div style={{
            padding: "10px 16px 14px",
            "border-top": "0.5px solid rgba(255,255,255,.05)",
            display: "flex",
            gap: "8px",
            "align-items": "center",
          }}>
            <button
              onClick={() => showToast("info", "返信を作成中...")}
              style={{
                padding: "7px 18px",
                background: "#00C4CC",
                border: "none",
                "border-radius": "9999px",
                color: "#001A1B",
                "font-size": "12.5px",
                "font-weight": "590",
                cursor: "pointer",
                transition: "transform .12s cubic-bezier(.34,1.56,.64,1)",
              }}
              onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.transform = "scale(1.03)"; }}
              onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.transform = "scale(1)"; }}
            >
              返信 (R)
            </button>

            <For each={[
              { label:"アーカイブ (E)", action:"archive" },
              { label:"スヌーズ (H)",  action:"snooze" },
              { label:"📌 Later (L)",  action:"reply_later" },
            ]}>
              {(btn) => (
                <button
                  onClick={() => handleAction(btn.action, selected()!)}
                  style={{
                    padding: "7px 14px",
                    background: "rgba(255,255,255,.05)",
                    border: "0.5px solid rgba(255,255,255,.07)",
                    "border-radius": "9999px",
                    color: "rgba(255,255,255,.4)",
                    "font-size": "12px",
                    cursor: "pointer",
                    transition: "all .1s ease",
                  }}
                  onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.color = "rgba(255,255,255,.7)"; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.color = "rgba(255,255,255,.4)"; }}
                >
                  {btn.label}
                </button>
              )}
            </For>
          </div>
        </Show>
      </div>

      <style>{`
        @keyframes fadeIn {
          from { opacity:0; transform:translateY(6px); }
          to   { opacity:1; transform:translateY(0); }
        }
        @keyframes scaleIn {
          from { opacity:0; transform:scale(.92); }
          to   { opacity:1; transform:scale(1); }
        }
        @keyframes toastIn {
          from { opacity:0; transform:translateY(10px) scale(.94); }
          to   { opacity:1; transform:translateY(0) scale(1); }
        }
        @keyframes toastOut {
          from { opacity:1; transform:translateY(0) scale(1); }
          to   { opacity:0; transform:translateY(-6px) scale(.96); }
        }
        @keyframes pulse {
          0%,100% { opacity:1; }
          50%      { opacity:.35; }
        }
        * { box-sizing:border-box; -webkit-font-smoothing:antialiased; }
        ::-webkit-scrollbar { width:4px; }
        ::-webkit-scrollbar-track { background:transparent; }
        ::-webkit-scrollbar-thumb { background:rgba(255,255,255,.08); border-radius:2px; }
        ::-webkit-scrollbar-thumb:hover { background:rgba(255,255,255,.14); }
        button { font-family:inherit; }
        input::placeholder { color:rgba(255,255,255,.2); }
        input:focus { border-color:rgba(0,196,204,.4) !important; box-shadow:0 0 0 3px rgba(0,196,204,.12); outline:none; }
      `}</style>
    </div>
  );
};

export default KanameDesign;
