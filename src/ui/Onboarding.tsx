// src/ui/Onboarding.tsx
//
// Kaname オンボーディングフロー
//
// Apple の "Packaging = First Impression" 哲学を体現する。
// Tim Cook: "包装を開ける瞬間、ユーザーはあなたの信念を感じる"
//
// 設計原則:
//   1. 最初の 60 秒で **北極星** を伝える
//   2. ユーザーが何かを失う前に何かを得る
//   3. すべての選択肢に **明確な意図** を表示
//   4. 戻れる、スキップできる、後で変更できる
//   5. 終わった瞬間にユーザーは **すでに価値を得ている**

import { Component, createSignal, Show, onMount } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

// ── 型定義 ───────────────────────────────────────────────────────────────

type Step = "welcome" | "principles" | "permissions" | "first_email" | "ready";

interface OnboardingState {
  step: Step;
  emailConsent:        boolean;
  telemetryOptIn:      boolean;
  continuityEnabled:   boolean;
  notificationsAllowed: boolean;
}

// ── オンボーディングコンポーネント ───────────────────────────────────────────

export const Onboarding: Component<{ onComplete: () => void }> = (props) => {
  const [state, setState] = createSignal<OnboardingState>({
    step: "welcome",
    emailConsent: false,
    telemetryOptIn: false,
    continuityEnabled: false,
    notificationsAllowed: false,
  });

  const next = (step: Step) =>
    setState(s => ({ ...s, step }));

  // ── Step 1: WELCOME ─────────────────────────────────────────────
  // 60 秒の北極星伝達

  const Welcome = () => (
    <div class="k-onboard-step k-onboard-welcome">
      <div class="k-icon-large">要</div>
      <h1>要 Kaname へようこそ</h1>
      <p class="k-tagline">
        AI が助けても裏切らない、唯一のメールクライアント
      </p>

      {/* 30 秒で見せる: 3 つの柱 */}
      <div class="k-pillars">
        <Pillar emoji="🛡" title="Security" desc="型システムが AI 境界を強制" />
        <Pillar emoji="⚡" title="Speed" desc="HEY + Superhuman の最高体験" />
        <Pillar emoji="🔒" title="Privacy" desc="データはデバイスを離れない" />
      </div>

      <button
        class="k-btn-primary"
        onClick={() => next("principles")}
        autofocus
      >
        始める
      </button>

      <button
        class="k-btn-text"
        onClick={() => props.onComplete()}
      >
        後で設定する
      </button>
    </div>
  );

  // ── Step 2: PRINCIPLES ──────────────────────────────────────────
  // Kaname がどう違うかを 90 秒で伝える

  const Principles = () => (
    <div class="k-onboard-step">
      <h2>Kaname の約束</h2>

      <div class="k-principle">
        <div class="k-principle-icon">🤖</div>
        <div class="k-principle-content">
          <h3>AI は 1 通だけ読む</h3>
          <p>
            AI でメールを要約する時、AI はそのメール
            <strong>1 通のみ</strong>を読みます。
            受信箱全体ではありません。
            これは型システムでコンパイル時に保証されています。
          </p>
        </div>
      </div>

      <div class="k-principle">
        <div class="k-principle-icon">🔍</div>
        <div class="k-principle-content">
          <h3>BEC 攻撃を防ぐ</h3>
          <p>
            ビジネスメール詐欺 (BEC) は世界で年間 510 億ドルの被害。
            Kaname は 7 つの信号を組み合わせて検出。
            危険なメールには赤いバナーで警告します。
          </p>
        </div>
      </div>

      <div class="k-principle">
        <div class="k-principle-icon">🌐</div>
        <div class="k-principle-content">
          <h3>サーバーは中身を読めない</h3>
          <p>
            あなたのメールは MLS RFC 9420 で暗号化されます。
            <strong>件名も含めて</strong>。
            Kaname サーバーは暗号化された箱だけを保存します。
          </p>
        </div>
      </div>

      <div class="k-step-controls">
        <button class="k-btn-text" onClick={() => next("welcome")}>戻る</button>
        <button class="k-btn-primary" onClick={() => next("permissions")}>
          続ける
        </button>
      </div>
    </div>
  );

  // ── Step 3: PERMISSIONS ─────────────────────────────────────────
  // すべて明示的、すべてオプトイン

  const Permissions = () => (
    <div class="k-onboard-step">
      <h2>権限を設定する</h2>
      <p class="k-subtitle">
        いずれも後で変更できます。すべてオプトインです。
      </p>

      <PermissionToggle
        title="通知を表示する"
        description="新着メールと BEC 警告のシステム通知"
        checked={state().notificationsAllowed}
        onChange={v => setState(s => ({ ...s, notificationsAllowed: v }))}
        recommended={true}
      />

      <PermissionToggle
        title="Continuity を有効化"
        description="iPhone と Mac で同じメールを引き継ぐ (Handoff)"
        checked={state().continuityEnabled}
        onChange={v => setState(s => ({ ...s, continuityEnabled: v }))}
        recommended={false}
      />

      <PermissionToggle
        title="匿名利用統計を送信"
        description="クラッシュレポートと匿名のクリック数のみ。メール本文は絶対に送りません"
        checked={state().telemetryOptIn}
        onChange={v => setState(s => ({ ...s, telemetryOptIn: v }))}
        recommended={false}
        privacyNote="送信されるデータは https://kaname.app/privacy/telemetry で確認できます"
      />

      <div class="k-step-controls">
        <button class="k-btn-text" onClick={() => next("principles")}>戻る</button>
        <button class="k-btn-primary" onClick={() => next("first_email")}>
          続ける
        </button>
      </div>
    </div>
  );

  // ── Step 4: FIRST EMAIL ─────────────────────────────────────────
  // **重要**: 終わった瞬間にユーザーは価値を得ている
  // BEC 攻撃メールのデモを見せる

  const FirstEmail = () => (
    <div class="k-onboard-step">
      <h2>実際の脅威を見てみましょう</h2>
      <p class="k-subtitle">
        これは実際の BEC 攻撃メールの例です
      </p>

      {/* 模擬メールカード */}
      <div class="k-demo-mail-card k-bec-danger">
        <div class="k-demo-banner">
          ⚠ 危険・BEC攻撃の可能性 (信頼度: 92%)
        </div>
        <div class="k-demo-from">
          From: <strong>CFO</strong> &lt;cfo@<span class="k-typo">arnazon</span>-billing.com&gt;
        </div>
        <div class="k-demo-subject">
          【至急】振込先変更のご連絡
        </div>
        <div class="k-demo-body">
          新しい銀行口座に 200 万円をご送金ください。本日中の処理をお願いします。
        </div>
      </div>

      <div class="k-detection-explanation">
        <h3>Kaname が検出した信号</h3>
        <ul>
          <li>✓ ドメイン偽装 (amazon → arnazon の Levenshtein 距離 1)</li>
          <li>✓ 緊急性マーカー (「至急」「本日中」)</li>
          <li>✓ 振込パターン (「振込先変更」「200 万円」)</li>
          <li>✓ 送信者名と実ドメインの不一致</li>
        </ul>
      </div>

      <p class="k-callout">
        💡 Kaname はこのようなメールを毎日防いでいます。
        実際の受信トレイで動作を確認できます。
      </p>

      <div class="k-step-controls">
        <button class="k-btn-text" onClick={() => next("permissions")}>戻る</button>
        <button class="k-btn-primary" onClick={() => next("ready")}>
          理解しました
        </button>
      </div>
    </div>
  );

  // ── Step 5: READY ──────────────────────────────────────────────
  // **完了の瞬間**: ユーザーはすでに価値を得ている
  // 「Set up」ではなく「すでに守られている」状態

  const Ready = () => {
    // 設定を保存 (副作用として非同期実行。JSX を返す前に await すると
    // コンポーネントの戻り値が Promise<Element> になり、SolidJS の
    // 同期コンポーネント契約に違反する — 従来は @ts-ignore で
    // この型エラーを隠していたが、根本原因はこの async 構造だった)。
    onMount(() => {
      invoke("settings_save_onboarding", {
        notifications: state().notificationsAllowed,
        continuity:    state().continuityEnabled,
        telemetry:     state().telemetryOptIn,
      }).catch(() => {
        // オンボーディング設定保存の失敗は致命的ではないため無視して続行するが、
        // 完全に沈黙させず開発時に気付けるようログだけ残す。
        console.warn("[Onboarding] settings_save_onboarding failed");
      });
    });

    return (
      <div class="k-onboard-step k-onboard-ready">
        <div class="k-success-icon">✓</div>
        <h1>準備完了</h1>
        <p class="k-tagline">
          あなたはすでに守られています
        </p>

        <div class="k-ready-features">
          <div>🛡 BEC 検出は<strong>すでに動いています</strong></div>
          <div>🤖 Phi-4-mini AI モデルは<strong>すでに準備されています</strong></div>
          <div>🔒 ローカル DB は<strong>すでに暗号化されています</strong></div>
        </div>

        <button class="k-btn-primary" onClick={props.onComplete} autofocus>
          受信トレイを開く
        </button>

        <p class="k-tip">
          💡 ⌘K でいつでもコマンドパレットを開けます
        </p>
      </div>
    );
  };

  // ── ルーティング ─────────────────────────────────────────────────

  return (
    <div class="k-onboarding-overlay">
      {/* 2026-09: k-* クラスはアーカイブ移行時にスタイル定義が欠落しており
          オンボーディング全体が無スタイルで描画されていた。他コンポーネントと
          同じダークパレット (#0A0E14/#00C4CC 系) で本ファイル内に定義する。 */}
      <style>{`
        .k-onboarding-overlay {
          position: fixed; inset: 0; background: #080C11;
          display: flex; flex-direction: column; align-items: center;
          justify-content: center; z-index: 100; overflow-y: auto;
          font-family: -apple-system, "Hiragino Sans", "Noto Sans JP", system-ui, sans-serif;
        }
        .k-onboarding-progress {
          position: absolute; top: 32px; left: 50%; transform: translateX(-50%);
          display: flex; gap: 8px;
        }
        .k-progress-dot {
          width: 8px; height: 8px; border-radius: 50%;
          background: #2A3441; transition: background .2s;
        }
        .k-progress-dot.active { background: #00C4CC; }
        .k-onboard-step {
          max-width: 560px; width: 100%; padding: 48px 32px;
          display: flex; flex-direction: column; align-items: center;
          text-align: center;
        }
        .k-onboard-step h1 { font-size: 28px; font-weight: 600; color: #F5F7FA; margin: 16px 0 8px; }
        .k-onboard-step h2 { font-size: 20px; font-weight: 600; color: #F5F7FA; margin-bottom: 8px; }
        .k-onboard-step h3 { font-size: 14px; font-weight: 600; color: #F5F7FA; margin-bottom: 8px; }
        .k-icon-large { font-size: 64px; line-height: 1; margin-bottom: 8px; color: #00C4CC; }
        .k-tagline { font-size: 15px; color: #8B96A5; margin-bottom: 32px; }
        .k-subtitle { font-size: 13px; color: #8B96A5; margin-bottom: 24px; }
        .k-pillars { display: flex; gap: 24px; margin: 24px 0 40px; }
        .k-pillar { max-width: 160px; }
        .k-pillar-emoji { font-size: 28px; margin-bottom: 8px; }
        .k-pillar-title { font-size: 14px; font-weight: 600; color: #F5F7FA; margin-bottom: 4px; }
        .k-pillar-desc { font-size: 12px; color: #8B96A5; line-height: 1.5; }
        .k-principle {
          display: flex; gap: 12px; text-align: left;
          background: #1A2129; border: 0.5px solid #2A3441; border-radius: 10px;
          padding: 14px 16px; margin-bottom: 10px; width: 100%;
        }
        .k-principle-icon { font-size: 20px; flex-shrink: 0; }
        .k-principle-content { font-size: 13px; color: #C9D2DC; line-height: 1.6; }
        .k-permission-row {
          display: flex; align-items: center; justify-content: space-between;
          gap: 16px; width: 100%; text-align: left;
          background: #1A2129; border: 0.5px solid #2A3441; border-radius: 10px;
          padding: 14px 16px; margin-bottom: 10px;
        }
        .k-permission-content { flex: 1; }
        .k-permission-title { font-size: 13px; font-weight: 600; color: #F5F7FA; display: flex; align-items: center; gap: 8px; }
        .k-permission-desc { font-size: 12px; color: #8B96A5; margin-top: 4px; line-height: 1.5; }
        .k-privacy-note { font-size: 11px; color: #00C4CC; margin-top: 6px; }
        .k-recommended-badge {
          font-size: 10px; font-weight: 600; color: #080C11; background: #00C4CC;
          border-radius: 4px; padding: 1px 6px;
        }
        .k-toggle { position: relative; width: 40px; height: 22px; flex-shrink: 0; }
        .k-toggle input { opacity: 0; width: 0; height: 0; position: absolute; }
        .k-toggle-slider {
          position: absolute; inset: 0; border-radius: 22px;
          background: #2A3441; cursor: pointer; transition: background .15s;
        }
        .k-toggle-slider::before {
          content: ""; position: absolute; width: 16px; height: 16px;
          left: 3px; top: 3px; border-radius: 50%; background: #8B96A5;
          transition: transform .15s, background .15s;
        }
        .k-toggle input:checked + .k-toggle-slider { background: #00C4CC; }
        .k-toggle input:checked + .k-toggle-slider::before { transform: translateX(18px); background: #080C11; }
        .k-toggle input:focus-visible + .k-toggle-slider { outline: 2px solid #00C4CC; outline-offset: 2px; }
        .k-demo-mail-card {
          width: 100%; text-align: left; background: #1A2129;
          border: 1px solid #2A3441; border-radius: 10px; overflow: hidden;
          margin-bottom: 20px;
        }
        .k-bec-danger { border-color: #FF6B70; }
        .k-demo-banner {
          background: #FF6B7018; color: #FF6B70; font-size: 12px; font-weight: 600;
          padding: 8px 14px; border-bottom: 0.5px solid #FF6B7040;
        }
        .k-demo-from { padding: 12px 14px 4px; font-size: 13px; color: #C9D2DC; }
        .k-demo-subject { padding: 0 14px 4px; font-size: 14px; font-weight: 600; color: #F5F7FA; }
        .k-demo-body { padding: 8px 14px 14px; font-size: 13px; color: #8B96A5; line-height: 1.6; }
        .k-typo { color: #FF6B70; text-decoration: underline wavy #FF6B70; }
        .k-detection-explanation {
          width: 100%; text-align: left; background: #1A2129;
          border: 0.5px solid #2A3441; border-radius: 10px; padding: 14px 16px;
          margin-bottom: 20px;
        }
        .k-detection-explanation ul { list-style: none; }
        .k-detection-explanation li { font-size: 12px; color: #C9D2DC; padding: 3px 0; }
        .k-callout {
          font-size: 12px; color: #F5A623; background: #F5A62312;
          border: 0.5px solid #F5A62330; border-radius: 8px;
          padding: 10px 14px; width: 100%; text-align: left; margin-bottom: 20px;
        }
        .k-ready-features {
          display: flex; flex-direction: column; gap: 10px;
          font-size: 14px; color: #C9D2DC; margin: 16px 0 32px;
        }
        .k-ready-features strong { color: #00C4CC; }
        .k-success-icon {
          width: 64px; height: 64px; border-radius: 50%;
          background: #00C4CC18; border: 2px solid #00C4CC;
          color: #00C4CC; font-size: 32px; display: flex;
          align-items: center; justify-content: center; margin-bottom: 8px;
        }
        .k-tip { font-size: 12px; color: #8B96A5; margin-top: 24px; }
        .k-step-controls {
          display: flex; justify-content: space-between; align-items: center;
          width: 100%; margin-top: 8px;
        }
        .k-btn-primary {
          background: #00C4CC; color: #080C11; border: none; border-radius: 8px;
          font-size: 14px; font-weight: 600; padding: 10px 24px; cursor: pointer;
          margin-left: auto;
        }
        .k-btn-primary:hover { background: #00D6DE; }
        .k-btn-primary:disabled { opacity: .4; cursor: not-allowed; }
        .k-btn-text {
          background: transparent; border: none; color: #8B96A5;
          font-size: 13px; cursor: pointer; padding: 10px 12px;
        }
        .k-btn-text:hover { color: #F5F7FA; }
      `}</style>
      <div class="k-onboarding-progress">
        <ProgressDot active={state().step === "welcome"} />
        <ProgressDot active={state().step === "principles"} />
        <ProgressDot active={state().step === "permissions"} />
        <ProgressDot active={state().step === "first_email"} />
        <ProgressDot active={state().step === "ready"} />
      </div>

      <Show when={state().step === "welcome"}>     <Welcome /> </Show>
      <Show when={state().step === "principles"}>  <Principles /> </Show>
      <Show when={state().step === "permissions"}> <Permissions /> </Show>
      <Show when={state().step === "first_email"}> <FirstEmail /> </Show>
      <Show when={state().step === "ready"}>
        <Ready />
      </Show>
    </div>
  );
};

// ── サブコンポーネント ──────────────────────────────────────────────────

const Pillar: Component<{ emoji: string; title: string; desc: string }> = (p) => (
  <div class="k-pillar">
    <div class="k-pillar-emoji">{p.emoji}</div>
    <div class="k-pillar-title">{p.title}</div>
    <div class="k-pillar-desc">{p.desc}</div>
  </div>
);

const PermissionToggle: Component<{
  title: string;
  description: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  recommended: boolean;
  privacyNote?: string;
}> = (p) => (
  <div class="k-permission-row">
    <div class="k-permission-content">
      <div class="k-permission-title">
        {p.title}
        <Show when={p.recommended}>
          <span class="k-recommended-badge">推奨</span>
        </Show>
      </div>
      <div class="k-permission-desc">{p.description}</div>
      <Show when={p.privacyNote}>
        <div class="k-privacy-note">🔒 {p.privacyNote}</div>
      </Show>
    </div>
    <label class="k-toggle">
      <input
        type="checkbox"
        checked={p.checked}
        onChange={(e) => p.onChange(e.currentTarget.checked)}
      />
      <span class="k-toggle-slider"></span>
    </label>
  </div>
);

const ProgressDot: Component<{ active: boolean }> = (p) => (
  <div class={`k-progress-dot ${p.active ? "active" : ""}`} />
);

// ── デフォルトエクスポート ─────────────────────────────────────────────

export default Onboarding;
