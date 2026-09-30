// vite.config.ts
import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import { resolve } from "path";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [solid()],
  
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },

  // Tauri: 固定ポートとホスト設定
  server: {
    port:        1420,
    strictPort:  true,
    host:        host || false,
    hmr:         host
      ? { protocol: "ws", host, port: 1421 }
      : undefined,
    watch: {
      // Windows: ファイル変更検知のために必要
      ignored: ["**/src-tauri/**"],
    },
  },

  // ビルド最適化
  build: {
    target:        "esnext",
    outDir:        "dist",
    emptyOutDir:   true,
    rollupOptions: {
      input: resolve(__dirname, "index.html"),
      output: {
        // アセットの分割 (rolldown ではオブジェクト形式は廃止 — 関数形式)
        manualChunks(id: string) {
          if (id.includes("node_modules/solid-js"))       return "solid";
          if (id.includes("node_modules/@tauri-apps/api")) return "tauri";
        },
      },
    },
  },

  // 環境変数プレフィックス
  envPrefix: ["VITE_", "TAURI_"],
});
