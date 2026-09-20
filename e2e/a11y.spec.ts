// e2e/a11y.spec.ts
//
// アクセシビリティ自動テスト (axe-core)
//
// Apple Accessibility Nutrition Labels の評価項目:
//   - VoiceOver サポート (ランドマーク・ARIA ラベル)
//   - Reduce Motion 尊重
//   - 十分なコントラスト
//   - キーボードナビゲーション
//   - 色覚多様性配慮 (色だけでなくテキストでも状態を示す)
//
// 実行: npx playwright test e2e/a11y.spec.ts
//
// 注: Tauri ランタイムのない vite 単体起動のため、`tauri-mock.ts` で
// IPC をモックした UI 層のテスト。Rust 側の振る舞いはここでは検証しない。

import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { installTauriMock } from "./tauri-mock";

test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
  await page.goto("/");
  // 受信トレイが描画されるまで待つ (バックエンド呼び出し完了の目印)
  await expect(page.getByText("Q2予算レビューのお願い")).toBeVisible();
});

// ── テスト 1: 受信トレイの WCAG 準拠 ─────────────────────────────────

test("受信トレイは WCAG 2.x に違反しない", async ({ page }) => {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "best-practice"])
    .analyze();

  expect(results.violations).toEqual([]);
});

// ── テスト 2: メール詳細ビューも違反なし ─────────────────────────────

test("メール詳細ビューは WCAG 2.x に違反しない", async ({ page }) => {
  await page.getByText("【至急】振込先口座変更のご連絡").click();
  // BEC 警告バナーが出てから検査する
  await expect(
    page.getByText(/このメールは差出人を証明できません/),
  ).toBeVisible();

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa"])
    .exclude("[data-iframe-content]") // iframe 内はサンドボックス側で検証
    .analyze();

  expect(results.violations).toEqual([]);
});

// ── テスト 3: キーボードフォーカスでリングが見える ───────────────────

test("Tab 移動した要素にフォーカスインジケーターが出る", async ({
  page,
  browserName,
}) => {
  // WebKit/Safari は OS 設定なしに Tab でボタンへフォーカスしない
  // (ブラウザ仕様でありアプリ側の欠陥ではない) ためスキップ。
  test.skip(browserName === "webkit", "WebKit は既定で Tab フォーカスしない");
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");

  const active = page.locator(":focus");
  await expect(active.first()).toBeVisible();

  const indicator = await active.first().evaluate((el) => {
    const cs = getComputedStyle(el);
    return { outline: cs.outline, boxShadow: cs.boxShadow };
  });
  const has =
    (indicator.outline !== "none" && !indicator.outline.startsWith("0px")) ||
    indicator.boxShadow !== "none";
  expect(has, "フォーカスインジケーターがない").toBe(true);
});

// ── テスト 4: コントラスト (WCAG AA) ─────────────────────────────────

test("テキストのコントラスト比は WCAG AA 基準を満たす", async ({ page }) => {
  const results = await new AxeBuilder({ page })
    .withRules(["color-contrast"])
    .analyze();

  expect(results.violations).toEqual([]);
});

// ── テスト 5: アイコンのみのボタンに ARIA ラベル ─────────────────────

test("アイコンのみのボタンには ARIA ラベルがある", async ({ page }) => {
  // 作成ビューにもアイコンボタンがあるため両ビューで検査
  for (const nav of ["/", null]) {
    if (nav === null) {
      await page.getByRole("button", { name: "作成" }).click();
      await expect(page.getByText("新規メール")).toBeVisible();
    }
    for (const btn of await page.locator("button:visible").all()) {
      const text = ((await btn.textContent()) || "").trim();
      // 絵文字・記号のみ (文字・数字を含まない) = アイコンボタン
      if (!/[\p{L}\p{N}]/u.test(text)) {
        const label = await btn.getAttribute("aria-label");
        const title = await btn.getAttribute("title");
        expect(
          label || title,
          `アイコンボタンに aria-label も title もない: "${text}"`,
        ).toBeTruthy();
      }
    }
  }
});

// ── テスト 6: 状態変化が色だけでなくテキストでも示される ─────────────

test("BEC 警告は色だけでなくテキストでも示される (色覚多様性配慮)", async ({ page }) => {
  // DANGEROUS メールの行に「危険」バッジのテキストが入っている
  const row = page.getByText("【至急】振込先口座変更のご連絡").locator("..");
  await expect(row.getByText("危険")).toBeVisible();
});

// ── テスト 7: Reduce Motion 尊重 ────────────────────────────────────

test("prefers-reduced-motion でアニメーションが停止する", async ({ browser }) => {
  const context = await browser.newContext({ reducedMotion: "reduce" });
  const page = await context.newPage();
  await installTauriMock(page);
  await page.goto("/");
  await expect(page.getByText("Q2予算レビューのお願い")).toBeVisible();

  const transitions = await page.evaluate(() =>
    Array.from(document.querySelectorAll("*"))
      .map((el) => getComputedStyle(el).transitionDuration)
      .filter((d) => d !== "0s"),
  );
  for (const dur of transitions) {
    const ms = parseFloat(dur) * (dur.includes("ms") ? 1 : 1000);
    expect(ms, `transition が短縮されていない: ${dur}`).toBeLessThanOrEqual(10);
  }
  await context.close();
});

// ── テスト 8: 言語宣言 ──────────────────────────────────────────────

// i18n 基盤は E9 で削除済み — UI は日本語固定。スクリーンリーダーが正しい
// 発話規則を使えるよう <html lang="ja"> が常に宣言されていることを保証する。
test("html lang が ja に固定されている", async ({ browser }) => {
  const context = await browser.newContext({ locale: "en-US" });
  const page = await context.newPage();
  await installTauriMock(page);
  await page.goto("/");
  await expect(page.locator("html")).toHaveAttribute("lang", "ja");
  await context.close();
});

// ── テスト 9: ランドマークロール ────────────────────────────────────

test("ランドマークロールが正しく定義されている", async ({ page }) => {
  const landmarks = await page
    .locator(
      '[role="main"], [role="navigation"], [role="banner"], main, nav, header',
    )
    .count();
  expect(landmarks, "ランドマークロールが少なすぎる").toBeGreaterThanOrEqual(2);
});
