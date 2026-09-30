// e2e/north-star-demo.spec.ts
//
// ゴールデンパス E2E テスト — 実装済み UI の主要導線を検証する。
//
// シナリオ (実 UI に対応):
//   1. 起動時にバックエンド初期化コマンドが呼ばれる
//   2. 受信トレイにメールボックスとメール一覧が出る
//   3. BEC 危険メールに「危険」バッジが付き、開くと警告バナーが出る
//   4. 「本人確認済みにする」が履歴DBに記録される
//   5. 検索欄が保存済みメールを検索する
//   6. 作成画面から mail_send が正しい引数で呼ばれる
//   7. サーバ接続画面から mail_connect が呼ばれる
//   8. サーバ取得失敗時は保存済みメールにフォールバックする
//   9. 未オンボーディング時はオンボーディングが表示される
//
// 注: Tauri ランタイムのない vite 起動のため IPC は `tauri-mock.ts` で
// モックしている。Rust 側ロジックの検証は cargo nextest が担う。

import { test, expect } from "@playwright/test";
import { installTauriMock, mockCalls } from "./tauri-mock";

// ── 共通セットアップ ─────────────────────────────────────────────────
test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
  await page.goto("/");
  await expect(page.getByText("Q2予算レビューのお願い")).toBeVisible({
    timeout: 10_000,
  });
});

// ── テスト 1: 起動時にバックエンド初期化が走る ───────────────────────

test("起動時に履歴DB・オンボーディング判定・ヘルスチェックが呼ばれる", async ({
  page,
}) => {
  const calls = async (cmd: string) =>
    (await mockCalls(page, cmd)).length;

  expect(await calls("history_open_default")).toBe(1);
  expect(await calls("settings_is_onboarded")).toBe(1);
  expect(await calls("health_check")).toBe(1);
  expect(await calls("mail_get_summary")).toBe(1);
});

// ── テスト 2: 受信トレイに一覧が出る ─────────────────────────────────

test("メールボックスとメール一覧が表示される", async ({ page }) => {
  // メールボックス (サイドバーの <nav> 内 — ナビバーと同名のためスコープする)
  const sidebar = page.locator("nav");
  await expect(sidebar.getByRole("button", { name: /受信トレイ/ })).toBeVisible();
  await expect(sidebar.getByRole("button", { name: "送信済み" })).toBeVisible();

  // メール行 (送信者・件名が見える)
  await expect(page.getByText("週次レポート (暗号化)")).toBeVisible();
  await expect(page.getByText("経理担当 鈴木")).toBeVisible();
});

// ── テスト 3: BEC 危険メールの検出表示 ───────────────────────────────

test("DANGEROUS メールに「危険」バッジと警告バナーが出る", async ({ page }) => {
  const subject = page.getByText("【至急】振込先口座変更のご連絡");
  // 一覧のバッジ
  await expect(subject.locator("..").getByText("危険")).toBeVisible();

  await subject.click();
  // 詳細の警告バナーと検出シグナル
  await expect(
    page.getByText(/このメールは差出人を証明できません.*BEC 攻撃の可能性/),
  ).toBeVisible();
  await expect(page.getByText(/検出シグナル/)).toBeVisible();
  // 帯域外検証の推奨メッセージ
  await expect(page.getByText(/別経路での確認を推奨/)).toBeVisible();
});

// ── テスト 4: 本人確認済みの記録 ─────────────────────────────────────

test("「本人確認済みにする」が history_mark_verified を呼ぶ", async ({
  page,
}) => {
  // 実装は confirm() ダイアログで確認する — accept して続行
  page.on("dialog", (d) => void d.accept());
  await page.getByText("【至急】振込先口座変更のご連絡").click();
  await page.getByRole("button", { name: "本人確認済みにする" }).click();

  const calls = await mockCalls(page, "history_mark_verified");
  expect(calls).toHaveLength(1);
  expect(calls[0]).toEqual({ email: "suzuki@examp1e.co.jp" });
});

// ── テスト 5: 検索 ───────────────────────────────────────────────────

test("検索欄で mail_search が呼ばれ結果が表示される", async ({ page }) => {
  await page.getByPlaceholder("検索...").fill("振込");
  await page.getByPlaceholder("検索...").press("Enter");

  const calls = await mockCalls(page, "mail_search");
  expect(calls).toHaveLength(1);
  expect(calls[0]).toMatchObject({ query: "振込" });

  // クエリに一致する行のみ残る
  await expect(page.getByText("【至急】振込先口座変更のご連絡")).toBeVisible();
  await expect(page.getByText("週次レポート (暗号化)")).toBeHidden();
});

// ── テスト 6: 作成 → mail_send ───────────────────────────────────────

test("作成画面から mail_send が正しい引数で呼ばれる", async ({ page }) => {
  await page.getByRole("button", { name: "作成" }).click();
  await expect(page.getByText("新規メール")).toBeVisible();

  await page.getByPlaceholder("差出人 (自分のメールアドレス)").fill("me@example.co.jp");
  await page.getByPlaceholder("宛先").fill("tanaka@example.co.jp");
  await page.getByPlaceholder("件名").fill("テスト送信");
  await page.getByPlaceholder("本文を入力...").fill("本文のテストです。");
  await page.getByRole("button", { name: /送信/ }).click();

  const calls = await mockCalls(page, "mail_send");
  expect(calls).toHaveLength(1);
  expect(calls[0]).toEqual({
    from: "me@example.co.jp",
    to: ["tanaka@example.co.jp"],
    subject: "テスト送信",
    body: "本文のテストです。",
  });
});

// ── テスト 7: サーバ接続 ────────────────────────────────────────────

test("サーバ接続画面から mail_connect が呼ばれる", async ({ page }) => {
  await page.getByRole("button", { name: "サーバ接続" }).click();
  await expect(
    page.getByRole("heading", { name: "サーバに接続" }),
  ).toBeVisible();

  await page.getByPlaceholder("https://mail.example.com").fill(
    "https://mail.example.com",
  );
  await page.getByPlaceholder("Bearer トークン").fill("test-token-123");
  await page.getByRole("button", { name: "接続する" }).click();

  const calls = await mockCalls(page, "mail_connect");
  expect(calls.length).toBeGreaterThanOrEqual(1);
  expect(calls[0]).toMatchObject({
    baseUrl: "https://mail.example.com",
    token: "test-token-123",
  });
});

// ── テスト 8: オフライン時フォールバック ────────────────────────────

test("mail_fetch 失敗時は保存済みメールにフォールバックする", async ({
  browser,
}) => {
  const page = await browser.newPage();
  await installTauriMock(page, { mailFetchFails: true });
  await page.goto("/");

  // mail_list_stored の結果 (s-1) が一覧に出る
  await expect(page.getByText("Q2予算レビューのお願い")).toBeVisible({
    timeout: 10_000,
  });
  const calls = await mockCalls(page, "mail_list_stored");
  expect(calls.length).toBeGreaterThanOrEqual(1);
  await page.close();
});

// ── テスト 9: オンボーディングゲート ────────────────────────────────

test("未オンボーディング時はオンボーディングが表示される", async ({
  browser,
}) => {
  const page = await browser.newPage();
  await installTauriMock(page, { onboarded: false });
  await page.goto("/");

  // オンボーディング画面 (受信トレイではない)
  await expect(page.getByText("Q2予算レビューのお願い")).toBeHidden();
  await page.close();
});
