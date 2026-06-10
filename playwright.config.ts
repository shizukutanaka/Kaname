// playwright.config.ts
//
// Kaname E2E テスト設定
//
// 機能:
//   - クロスブラウザ (Chromium / WebKit / Firefox)
//   - 視覚的回帰 (toHaveScreenshot)
//   - アクセシビリティ (axe-core)
//   - モックサーバー連携 (kaname-mockserver)
//   - CI 並列実行

import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",

  // 並列実行 — CI では 4 並列
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 4 : undefined,

  // レポーター
  reporter: [
    ["html", { open: "never" }],
    ["junit", { outputFile: "test-results/junit.xml" }],
    ["list"],
  ],

  // 共通設定
  use: {
    baseURL: "http://localhost:1420",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    locale: "ja-JP",
    timezoneId: "Asia/Tokyo",
  },

  // Web サーバー (テスト前に起動)
  webServer: [
    {
      command: "npm run dev",
      port: 1420,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
    {
      command: "cargo run -p kaname-mockserver --bin jmap-mock",
      port: 8080,
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
  ],

  // ブラウザマトリクス
  projects: [
    {
      name: "Chromium (Desktop)",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "WebKit (Desktop)",
      use: { ...devices["Desktop Safari"] },
    },
    {
      name: "Firefox (Desktop)",
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "Mobile Safari",
      use: { ...devices["iPhone 15 Pro"] },
      // モバイルではスワイプテストのみ実行
      testMatch: /swipe.*\.spec\.ts/,
    },
    // アクセシビリティ専用 (axe-core)
    {
      name: "Accessibility",
      testMatch: /a11y.*\.spec\.ts/,
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  // 視覚的回帰テスト設定
  expect: {
    toHaveScreenshot: {
      threshold: 0.2,           // 20% のピクセル差まで許容
      maxDiffPixels: 100,       // 最大 100 ピクセル差
      animations: "disabled",   // アニメーション無効化
    },
  },

  // 出力ディレクトリ
  outputDir: "test-results",
});
