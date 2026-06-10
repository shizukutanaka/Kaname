/// <reference types="vitest" />
import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

export default defineConfig({
  plugins: [solid()],
  test: {
    globals:     true,
    environment: "jsdom",
    include:     ["src/**/*.{test,spec}.{ts,tsx}"],
    coverage: {
      provider:   "v8",
      reporter:   ["text", "json", "html"],
      thresholds: { lines: 80, functions: 80, branches: 70 },
    },
  },
});
