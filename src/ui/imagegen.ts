// src/ui/imagegen.ts — 画像生成 (Drop 統合) の純粋ロジック
//
// 旧 Drop の生成パラメータ設計 (プロンプト/ネガティブ、サンプラー、
// ステップ、CFG、サイズ、バッチ、シード、Hires. fix 等) を Kaname の
// 画像生成パネル向けに写したもの。UI コンポーネント (ImageGenPanel.tsx)
// から分離し、vitest で検証できるようにしてある。
//
// 実際の生成は Rust 側 `imagegen_generate` が利用者自身のエンドポイント
// (AUTOMATIC1111 互換) へ送る。このファイルは値の保持・整形だけを行う。

/** Rust 側 ImageGenRequest と同形 (serde の snake_case フィールド名)。 */
export interface ImageGenRequest {
  prompt: string;
  negative_prompt: string;
  model: string | null;
  sampler_name: string;
  steps: number;
  cfg_scale: number;
  width: number;
  height: number;
  batch_count: number;
  batch_size: number;
  seed: number;
  enable_hr: boolean;
  restore_faces: boolean;
  tiling: boolean;
}

/** Rust 側 GeneratedImage と同形。 */
export interface GeneratedImage {
  mime_type: string;
  base64: string;
}

/** Rust 側 ImageGenHistoryEntry と同形 (Drop の履歴形式の踏襲)。 */
export interface ImageGenHistoryEntry {
  prompt: string;
  negative_prompt: string;
  model: string;
  sampler_name: string;
  steps: number;
  cfg_scale: number;
  width: number;
  height: number;
  seed: number;
  timestamp: string;
}

/** Drop にあったサンプラー一覧 (A1111 の sampler_name と一致する)。 */
export const IMAGE_SAMPLERS = [
  "DPM++ 2M Karras",
  "DPM++ SDE Karras",
  "Euler a",
  "Euler",
  "DDIM",
] as const;

/** Drop にあったサイズプリセット (カスタムは幅/高さの直接指定)。 */
export const IMAGE_SIZES = [
  { label: "512 × 512", width: 512, height: 512 },
  { label: "768 × 768", width: 768, height: 768 },
  { label: "1024 × 1024", width: 1024, height: 1024 },
  { label: "1024 × 576 (16:9)", width: 1024, height: 576 },
  { label: "576 × 1024 (9:16)", width: 576, height: 1024 },
] as const;

/** パネルのフォーム状態 (文字列入力を含むため request とは分ける)。 */
export interface ImageGenForm {
  prompt: string;
  negativePrompt: string;
  model: string;
  samplerName: string;
  steps: number;
  cfgScale: number;
  width: number;
  height: number;
  batchCount: number;
  batchSize: number;
  seed: number;
  enableHr: boolean;
  restoreFaces: boolean;
  tiling: boolean;
}

export const defaultImageGenForm = (): ImageGenForm => ({
  prompt: "",
  negativePrompt: "",
  model: "",
  samplerName: IMAGE_SAMPLERS[0],
  steps: 20,
  cfgScale: 7.0,
  width: 1024,
  height: 1024,
  batchCount: 1,
  batchSize: 1,
  seed: -1,
  enableHr: false,
  restoreFaces: false,
  tiling: false,
});

const clampInt = (v: number, min: number, max: number, fallback: number): number => {
  if (!Number.isFinite(v)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(v)));
};

/**
 * フォーム状態を生成リクエストへ変換する。範囲の最終検証は Rust 側でも
 * 行うが、ここでも UI の入力範囲 (Drop のスライダー範囲) に丸める。
 */
export const buildImageGenRequest = (form: ImageGenForm): ImageGenRequest => ({
  prompt: form.prompt,
  negative_prompt: form.negativePrompt,
  model: form.model.trim() === "" ? null : form.model.trim(),
  sampler_name: form.samplerName,
  steps: clampInt(form.steps, 1, 150, 20),
  cfg_scale: Math.min(30, Math.max(1, Number.isFinite(form.cfgScale) ? form.cfgScale : 7)),
  width: clampInt(form.width, 64, 2048, 1024),
  height: clampInt(form.height, 64, 2048, 1024),
  batch_count: clampInt(form.batchCount, 1, 4, 1),
  batch_size: clampInt(form.batchSize, 1, 4, 1),
  seed: Number.isFinite(form.seed) ? Math.trunc(form.seed) : -1,
  enable_hr: form.enableHr,
  restore_faces: form.restoreFaces,
  tiling: form.tiling,
});

/** 生成結果とフォームから履歴エントリを作る (Drop の履歴項目の相当物)。 */
export const makeHistoryEntry = (
  form: ImageGenForm,
  usedSeed: number | null,
  modelFallback: string,
  now: Date = new Date(),
): ImageGenHistoryEntry => ({
  prompt: form.prompt,
  negative_prompt: form.negativePrompt,
  model: form.model.trim() === "" ? modelFallback : form.model.trim(),
  sampler_name: form.samplerName,
  steps: form.steps,
  cfg_scale: form.cfgScale,
  width: form.width,
  height: form.height,
  seed: usedSeed ?? form.seed,
  timestamp: now.toISOString(),
});

/** 履歴エントリをフォームへ復元する (履歴クリックで再生成できる Drop の挙動)。 */
export const formFromHistory = (entry: ImageGenHistoryEntry): ImageGenForm => ({
  prompt: entry.prompt,
  negativePrompt: entry.negative_prompt,
  model: entry.model,
  samplerName: entry.sampler_name,
  steps: entry.steps,
  cfgScale: entry.cfg_scale,
  width: entry.width,
  height: entry.height,
  batchCount: 1,
  batchSize: 1,
  seed: entry.seed,
  enableHr: false,
  restoreFaces: false,
  tiling: false,
});

/** Drop の「履歴エクスポート (JSON)」と同じ形の書き出し文字列。 */
export const exportHistoryJson = (entries: ImageGenHistoryEntry[]): string =>
  JSON.stringify(entries, null, 2);

/** 生成画像の表示・ダウンロード用 data URL。 */
export const imageDataUrl = (img: GeneratedImage): string =>
  `data:${img.mime_type};base64,${img.base64}`;

/** 拡張子 (ダウンロードファイル名・添付表示用)。 */
export const imageExtension = (mimeType: string): string => {
  switch (mimeType) {
    case "image/jpeg":
      return "jpg";
    case "image/webp":
      return "webp";
    default:
      return "png";
  }
};
