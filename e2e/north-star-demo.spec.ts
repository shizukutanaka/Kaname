// e2e/north-star-demo.spec.ts
//
// 北極星デモシーン E2E テスト
//
// このテストは Apple "Demo-driven development" の中核。
// 1 つのテストでプロダクトの全価値を検証する。
//
// シナリオ:
//   1. ユーザーが BEC 攻撃メールを受信
//   2. UI が DANGEROUS バナーを表示
//   3. ユーザーが「AI で要約」をクリック
//   4. 「このメール 1 通のみ分析」のセキュリティ証明が表示される
//   5. 安全な要約が表示される
//   6. ユーザーが安心して返信案を生成
//   7. Cmd+Z で全アクションを取り消せる

import { test, expect } from "@playwright/test";

// ── 共通セットアップ ─────────────────────────────────────────────────────
test.beforeEach(async ({ page }) => {
  // モックサーバーを起動した状態でフロントエンドを開く
  await page.goto("http://localhost:1420");

  // オンボーディングをスキップ (E2E では不要)
  const skipBtn = page.locator('button', { hasText: 'スキップ' });
  if (await skipBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
    await skipBtn.click();
  }

  // メールリストが読み込まれるまで待つ
  await expect(page.locator('text=受信トレイ').first()).toBeVisible({ timeout: 10_000 });
});

// ── テスト 1: BEC メール検出 ─────────────────────────────────────────────

test("BEC 攻撃メールが赤色バナーで表示される", async ({ page }) => {
  // BEC メール (fix-002) を選択
  const becMail = page.locator('[data-testid="email-row"]', {
    hasText: /至急/,
  }).first();

  await expect(becMail).toBeVisible();
  await becMail.click();

  // DANGEROUS バナーが表示される
  await expect(page.locator('text=/BEC.*可能性/')).toBeVisible();

  // 「危険」または「DANGEROUS」のラベル
  await expect(page.locator('text=/危険|DANGEROUS/')).toBeVisible();

  // 視覚的特徴: 赤系の色が使われている
  const banner = page.locator('[role="alert"]').first();
  if (await banner.count() > 0) {
    const color = await banner.evaluate(el => getComputedStyle(el).color);
    // 赤系の RGB であることを確認 (R > G + B/2 程度)
    expect(color).toMatch(/rgb\((2[0-9]{2}|255).*[0-9]/);
  }
});

// ── テスト 2: AI 要約のセキュリティ証明 ─────────────────────────────────

test("AI 要約は「このメール 1 通のみ」を明示する", async ({ page }) => {
  // 通常メールを選択
  const normalMail = page.locator('[data-testid="email-row"]', {
    hasText: /Q2予算/,
  }).first();
  await normalMail.click();

  // AI 要約ボタンをクリック
  const summarizeBtn = page.locator('button', { hasText: /AI.*要約|Summarize/ });
  await expect(summarizeBtn).toBeVisible();
  await summarizeBtn.click();

  // セキュリティ証明が表示される
  await expect(page.locator('text=/このメール.*1.*通|this email only/')).toBeVisible({ timeout: 5000 });
  await expect(page.locator('text=/受信箱全体.*読みません|does not read.*inbox/')).toBeVisible();

  // 🔒 安全マーカー
  await expect(page.locator('text=/🔒.*安全|🔒.*Safe/')).toBeVisible();

  // 要約結果が表示される
  await expect(page.locator('[data-testid="summary-text"]')).toBeVisible({ timeout: 10_000 });
});

// ── テスト 3: Smart Reply で 3 候補が表示される ──────────────────────────

test("Smart Reply は 3 つの候補を表示し、トーンが分かれている", async ({ page }) => {
  const mail = page.locator('[data-testid="email-row"]').first();
  await mail.click();

  const smartReplyBtn = page.locator('button', { hasText: /返信案を生成|Suggest replies/ });
  await smartReplyBtn.click();

  // 3 つの候補が表示される
  const replies = page.locator('[data-testid="smart-reply-candidate"]');
  await expect(replies).toHaveCount(3, { timeout: 5000 });

  // 各候補に異なるテキストが含まれる
  const texts: string[] = [];
  for (let i = 0; i < 3; i++) {
    const text = await replies.nth(i).textContent();
    if (text) texts.push(text);
  }
  // 重複なし
  expect(new Set(texts).size).toBe(3);
});

// ── テスト 4: Cmd+Z で操作を取り消せる ──────────────────────────────────

test("メールアーカイブを Cmd+Z で取り消せる", async ({ page }) => {
  // 最初のメールをアーカイブ
  const mail = page.locator('[data-testid="email-row"]').first();
  const originalSubject = await mail.locator('[data-testid="email-subject"]').textContent();

  await mail.click();
  await page.keyboard.press("e"); // アーカイブショートカット

  // トーストが表示される
  await expect(page.locator('text=/アーカイブ.*しました|Archived/')).toBeVisible();

  // 取り消し
  await page.keyboard.press("Meta+z");

  // 元のメールが復元される
  await expect(page.locator('text=/取り消し|Undone/')).toBeVisible();

  // メールが受信トレイに戻る
  if (originalSubject) {
    await expect(page.locator(`text=${originalSubject}`).first()).toBeVisible();
  }
});

// ── テスト 5: スワイプジェスチャーでアーカイブ ────────────────────────

test("メール行を左にスワイプしてアーカイブできる", async ({ page }) => {
  const mail = page.locator('[data-testid="email-row"]').first();
  const box = await mail.boundingBox();

  if (!box) throw new Error("メール行が見つからない");

  // 左にスワイプ (中心から左へ 200px)
  await page.mouse.move(box.x + box.width - 50, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x + 50, box.y + box.height / 2, { steps: 20 });
  await page.mouse.up();

  // アーカイブされた
  await expect(page.locator('text=/アーカイブ|Archive/')).toBeVisible({ timeout: 2000 });
});

// ── テスト 6: 自然言語検索 ─────────────────────────────────────────────

test("「先週のメール」で日付フィルターが適用される", async ({ page }) => {
  const search = page.locator('[data-testid="natural-search"]').or(
    page.locator('input[placeholder*="検索"]').or(
      page.locator('input[type="search"]')
    )
  );
  await search.fill("先週のメール");
  await search.press("Enter");

  // フィルターチップに「先週」が表示される
  await expect(page.locator('text="先週"').first()).toBeVisible({ timeout: 3000 });
});

// ── テスト 7: アクセシビリティ — キーボードのみで全操作 ───────────────

test("マウスを使わずに j/k/e/r で全操作できる", async ({ page }) => {
  // j で次のメールへ
  await page.keyboard.press("j");
  await page.waitForTimeout(100);

  // 選択されたメールに ARIA selected が付く
  const selected = page.locator('[aria-selected="true"]').first();
  await expect(selected).toBeVisible();

  // k で前のメール
  await page.keyboard.press("k");
  await page.waitForTimeout(100);

  // ? でヘルプ
  await page.keyboard.press("Shift+/");
  await expect(page.locator('text=/ショートカット|Shortcut/')).toBeVisible({ timeout: 2000 });

  // Escape で閉じる
  await page.keyboard.press("Escape");
});

// ── テスト 8: 視覚的回帰 — Liquid Glass UI のスクリーンショット ──────

test("Liquid Glass UI のスクリーンショットが期待値と一致", async ({ page }) => {
  await page.waitForTimeout(500); // アニメーション完了を待つ

  // 受信トレイのスクリーンショット
  await expect(page).toHaveScreenshot("liquid-glass-inbox.png", {
    maxDiffPixels: 100,
    threshold: 0.2,  // 20% の差まで許容
  });

  // メール詳細を開いてスクリーンショット
  await page.locator('[data-testid="email-row"]').first().click();
  await page.waitForTimeout(300);

  await expect(page).toHaveScreenshot("liquid-glass-detail.png", {
    maxDiffPixels: 100,
    threshold: 0.2,
  });
});

// ── テスト 9: パフォーマンス — 起動時間 ────────────────────────────────

test("コールドスタートから操作可能まで < 800ms (Apple HIG 準拠)", async ({ page }) => {
  const start = Date.now();

  await page.goto("http://localhost:1420");

  // 受信トレイが操作可能になるまで待つ
  await expect(page.locator('text=受信トレイ').first()).toBeVisible();
  await expect(page.locator('[data-testid="email-row"]').first()).toBeVisible();

  const duration = Date.now() - start;
  console.log(`コールドスタート: ${duration}ms`);

  expect(duration).toBeLessThan(800);
});

// ── テスト 10: セキュリティ証明の不変条件 (型レベル + ランタイム) ─────

test("AI 要約レスポンスに single_email_only=true が含まれる", async ({ page }) => {
  // フェッチを傍受
  const responses: Record<string, unknown>[] = [];
  await page.route("**/ai_summarize_email**", async (route) => {
    const response = await route.fetch();
    const json = await response.json();
    responses.push(json);
    await route.fulfill({ response });
  });

  await page.goto("http://localhost:1420");
  await page.locator('[data-testid="email-row"]').first().click();
  await page.locator('button', { hasText: /AI.*要約/ }).click();

  await page.waitForResponse(/ai_summarize_email/, { timeout: 10_000 });

  // セキュリティ証明が含まれている
  expect(responses.length).toBeGreaterThan(0);
  const summary = responses[0];
  expect(summary.single_email_only).toBe(true);
  expect(summary.local_inference).toBe(true);
});
