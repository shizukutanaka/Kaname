// e2e/tauri-mock.ts
//
// Tauri IPC のブラウザ内モック。
//
// `npm run dev` (vite 単体) で起動したフロントエンドは Tauri ランタイムを
// 持たないため、本来 `invoke`/`listen` はすべて失敗する。E2E では
// `page.addInitScript` で `window.__TAURI_INTERNALS__` を差し替え、
// @tauri-apps/api の公式 mock (`mocks.js` の mockIPC と同じ内部構造) と
// 同等の IPC 層を注入して UI 層をテストする。
//
// スコープ: これは UI 層の E2E。Rust 側ロジック (BEC/DLP/MLS) の正しさは
// cargo nextest と実機の `tauri dev` で検証する。

import type { Page } from "@playwright/test";

const NOW = new Date().toISOString();

/** 一覧に表示するテストメール。DANGEROUS / SAFE / MLS を含む。 */
const EMAILS = [
  {
    id: "m-1", from_name: "営業部 田中", from_addr: "tanaka@example.co.jp",
    subject: "Q2予算レビューのお願い", preview: "来週の会議でご確認ください",
    received_at: NOW, is_read: true, is_starred: false,
    bec_verdict: "SAFE", is_mls: false,
  },
  {
    id: "m-2", from_name: "経理担当 鈴木", from_addr: "suzuki@examp1e.co.jp",
    subject: "【至急】振込先口座変更のご連絡", preview: "口座情報が変更になりました",
    received_at: NOW, is_read: false, is_starred: false,
    bec_verdict: "DANGEROUS", is_mls: false,
  },
  {
    id: "m-3", from_name: "佐藤", from_addr: "sato@example.co.jp",
    subject: "週次レポート (暗号化)", preview: "MLS 暗号化メールです",
    received_at: NOW, is_read: false, is_starred: false,
    bec_verdict: null, is_mls: true,
  },
];

const MAILBOXES = [
  { id: "mbx-inbox", name: "受信トレイ", role: "inbox", unread_emails: 2, total_emails: 3 },
  { id: "mbx-sent",  name: "送信済み",   role: "sent",  unread_emails: 0, total_emails: 1 },
];

const OPENED_SAFE = {
  from: "営業部 田中 <tanaka@example.co.jp>",
  subject: "Q2予算レビューのお願い",
  auth: "spf=pass dkim=pass",
  bec_verdict: "SAFE", bec_score: 5, bec_signals: [],
  attachments: [],
  body: {
    srcdoc: "<p>来週の会議でご確認ください。</p>",
    sandbox: "allow-popups allow-popups-to-escape-sandbox allow-same-origin", csp: "default-src 'none'", is_mls: false,
    render_risks: [],
  },
  dlp_findings: [], oobv_level: "none", oobv_message: "",
  deepfake_advisory: {
    severity: "None", affected_attachments: [],
    has_financial_context: false, has_urgency: false,
    recommended_action: "None",
  },
};

const OPENED_DANGEROUS = {
  from: "経理担当 鈴木 <suzuki@examp1e.co.jp>",
  subject: "【至急】振込先口座変更のご連絡",
  auth: "dkim=fail",
  bec_verdict: "DANGEROUS", bec_score: 85,
  bec_signals: ["similar_domain", "urgency_language"],
  attachments: [
    { filename: "請求書.pdf", risks: [], is_dangerous: false },
  ],
  body: {
    srcdoc: "<p>振込先口座が変更になりました。至急お手続きください。</p>",
    sandbox: "allow-popups allow-popups-to-escape-sandbox allow-same-origin", csp: "default-src 'none'", is_mls: false,
    render_risks: [],
  },
  dlp_findings: [],
  oobv_level: "strong",
  oobv_message: "金銭に関わる内容のため、別経路での確認を推奨します",
  deepfake_advisory: {
    severity: "None", affected_attachments: [],
    has_financial_context: true, has_urgency: true,
    recommended_action: "ShowAdvisory",
  },
};

/** .eml インポート用: DLP 機微情報を含む危険メール (パスに dlp/danger 等で選択)。 */
const OPENED_DANGEROUS_DLP = {
  ...OPENED_DANGEROUS,
  dlp_findings: ["クレジットカード番号の可能性: 4111-****-****-1111", "マイナンバーの可能性: ****-****-1234"],
};

/** `mail_scan_folder` の FolderScanResult 形状 (commands.rs と一致)。 */
const FOLDER_SCAN = {
  analyzed: 2,
  failed: [],
  verdict_counts: [["DANGEROUS", 1], ["SAFE", 1]] as [string, number][],
  emails: [
    {
      file: "invoice.eml", from: "suzuki@examp1e.co.jp",
      subject: "【至急】振込先口座変更のご連絡",
      verdict: "DANGEROUS", score: 85, dlp_count: 1, attachment_risk_count: 1,
    },
    {
      file: "budget.eml", from: "tanaka@example.co.jp",
      subject: "Q2予算レビューのお願い",
      verdict: "SAFE", score: 5, dlp_count: 0, attachment_risk_count: 0,
    },
  ],
  campaigns: [
    { shared_infrastructure: "examp1e.co.jp", email_count: 2, threat_score: 0.82 },
  ],
};

const OOBV_PHRASE = ["apple", "river", "mountain", "bridge", "silver", "garden"];

const STORED = [
  {
    id: "s-1", from_addr: "tanaka@example.co.jp", from_name: "営業部 田中",
    subject: "Q2予算レビューのお願い", body_preview: "来週の会議で…",
    received_at: NOW, is_read: true, bec_score: 5, bec_verdict: "SAFE",
    to_addrs: ["me@example.co.jp"],
  },
  {
    id: "s-2", from_addr: "suzuki@examp1e.co.jp", from_name: "経理担当 鈴木",
    subject: "【至急】振込先口座変更のご連絡", body_preview: "口座情報が…",
    received_at: NOW, is_read: false, bec_score: 85, bec_verdict: "DANGEROUS",
    to_addrs: ["me@example.co.jp"],
  },
];

/** テストが覆せる応答の差分。キーは Tauri コマンド名。 */
export interface MockOverrides {
  /** `settings_is_onboarded` の戻り値。false でオンボーディングが出る。 */
  onboarded?: boolean;
  /** `mail_fetch` を失敗させてオフライン経路 (mail_list_stored) を試す。 */
  mailFetchFails?: boolean;
  /** `oobv_recommend` の戻り値。 */
  oobvLevel?: string;
  /** `mail_dlp_precheck` の戻り値。 */
  dlpWarnings?: string[];
}

/**
 * ページに Tauri IPC モックを注入する。`page.goto` より前に呼ぶこと。
 * 呼び出されたコマンドは `window.__KANAME_MOCK_LOG` に記録され、
 * テストから `page.evaluate` で読める。
 */
export async function installTauriMock(page: Page, ov: MockOverrides = {}) {
  await page.addInitScript(
    ({ ov, emails, mailboxes, openedSafe, openedDangerous, openedDangerousDlp, folderScan, oobvPhrase, stored }) => {
      // mockIPC (@tauri-apps/api/mocks) と同じ内部構造。
      // @tauri-apps/api のグローバル型はこのコンテキストでは読み込まれない
      // ため、内部 API の形だけをローカルに宣言する。
      const w = window as unknown as {
        __TAURI_INTERNALS__: Record<string, unknown>;
        __TAURI_EVENT_PLUGIN_INTERNALS__: Record<string, unknown>;
        __KANAME_MOCK_LOG: { cmd: string; args: unknown }[];
      };
      const internals = (w.__TAURI_INTERNALS__ = {} as typeof w.__TAURI_INTERNALS__);
      const callbacks = new Map<number, (data: unknown) => void>();
      w.__TAURI_EVENT_PLUGIN_INTERNALS__ = {
        unregisterListener: (_event: string, eventId: number) => {
          callbacks.delete(eventId);
        },
      };

      // コマンド呼び出しのログ (テストから観察可能)
      const log: { cmd: string; args: unknown }[] = [];
      w.__KANAME_MOCK_LOG = log;

      const listeners = new Map<string, number[]>();
      const register = (cb: (d: unknown) => void, once = false) => {
        const id = window.crypto.getRandomValues(new Uint32Array(1))[0];
        callbacks.set(id, (data) => {
          if (once) callbacks.delete(id);
          return cb && cb(data);
        });
        return id;
      };
      internals.transformCallback = register;
      internals.unregisterCallback = (id: number) => callbacks.delete(id);
      internals.runCallback = (id: number, data: unknown) => {
        callbacks.get(id)?.(data);
      };
      internals.callbacks = callbacks;
      internals.convertFileSrc = (p: string) => p;

      internals.invoke = async (cmd: string, args: Record<string, unknown>) => {
        log.push({ cmd, args });
        // イベントプラグインは listen をモック (emit は emit() で購読者に届く)
        if (cmd === "plugin:event|listen") {
          const ev = args.event as string;
          const h = args.handler as number;
          (listeners.get(ev) ?? listeners.set(ev, []).get(ev)!).push(h);
          return h;
        }
        if (cmd === "plugin:event|unlisten") {
          const ev = args.event as string;
          const id = args.id as number;
          const l = listeners.get(ev);
          if (l) l.splice(l.indexOf(id), 1);
          return null;
        }
        if (cmd === "plugin:event|emit") {
          for (const h of listeners.get(args.event as string) ?? []) {
            callbacks.get(h)?.(args);
          }
          return null;
        }

        if (ov.mailFetchFails && cmd === "mail_fetch") {
          throw new Error("mock: mail server unreachable");
        }

        switch (cmd) {
          case "settings_is_onboarded":   return ov.onboarded ?? true;
          case "history_open_default":    return "/mock/history.db";
          case "health_check":            return { ok: true, version: "0.7.1-mock" };
          case "mail_get_summary":        return { unread: 2, bec_alerts: 1 };
          case "mail_get_mailboxes":      return mailboxes;
          case "mail_fetch":              return emails;
          case "mail_list_stored":        return stored;
          case "mail_search":
            return stored.filter((m) =>
              (m.subject ?? "").includes(args.query as string));
          case "mail_open":
            return args.emailId === "m-2" ? openedDangerous : openedSafe;
          case "mail_import_eml":
            // パス名で切替: "dlp|danger|bec|phish" を含む → 危険+DLP版
            return /dlp|danger|bec|phish/i.test(String(args.path ?? ""))
              ? openedDangerousDlp
              : openedSafe;
          case "mail_scan_folder":        return folderScan;
          case "oobv_start":
            return {
              ceremony_id: "mock-ceremony-1",
              phrase: oobvPhrase,
              challenge_number: 3,
              expires_at_unix: Math.floor(Date.now() / 1000) + 600,
            };
          case "oobv_verify": {
            const req = (args.req ?? {}) as { user_word?: string };
            return {
              state: req.user_word === oobvPhrase[2] ? "Verified" : "Mismatch",
              message_i18n_key: "",
            };
          }
          case "mail_connect":
            return { account_id: "acc-1", mailboxes: [["mbx-inbox", "受信トレイ", 2]] };
          case "oobv_recommend":
            return { level: ov.oobvLevel ?? "None", message_i18n_key: "" };
          case "mail_dlp_precheck":
            return { warnings: ov.dlpWarnings ?? [] };
          case "ai_detect_phishing":      return { verdict: "SAFE", score: 0 };
          // 副作用系: 成功を返すだけ
          case "mail_mark_read":
          case "mail_trash":
          case "mail_disconnect":
          case "mail_send":
          case "settings_save_onboarding":
          case "history_mark_verified":
          case "log_error":
            return null;
          default:
            return null;
        }
      };
    },
    {
      ov,
      emails: EMAILS,
      mailboxes: MAILBOXES,
      openedSafe: OPENED_SAFE,
      openedDangerous: OPENED_DANGEROUS,
      openedDangerousDlp: OPENED_DANGEROUS_DLP,
      folderScan: FOLDER_SCAN,
      oobvPhrase: OOBV_PHRASE,
      stored: STORED,
    },
  );
}

/** モックに記録されたコマンド呼び出しを読み出す。 */
export function mockCalls(page: Page, cmd: string): Promise<unknown[]> {
  return page.evaluate(
    (c) =>
      ((window as unknown as { __KANAME_MOCK_LOG: { cmd: string; args: unknown }[] })
        .__KANAME_MOCK_LOG ?? [])
        .filter((e) => e.cmd === c)
        .map((e) => e.args),
    cmd,
  );
}
