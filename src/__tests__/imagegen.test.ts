// src/__tests__/imagegen.test.ts
//
// 画像生成 (Drop 統合) の純粋ロジック (src/ui/imagegen.ts) のテスト。
// 実ソースからインポートして検証する (app.test.ts の方針と同じ)。

import { describe, it, expect } from "vitest";
import {
  buildImageGenRequest,
  defaultImageGenForm,
  exportHistoryJson,
  formFromHistory,
  imageDataUrl,
  imageExtension,
  makeHistoryEntry,
  type ImageGenHistoryEntry,
} from "../ui/imagegen";

describe("buildImageGenRequest", () => {
  it("既定フォーム → A1111 向けリクエスト (モデル未指定は null)", () => {
    const req = buildImageGenRequest({
      ...defaultImageGenForm(),
      prompt: "a cat",
    });
    expect(req.prompt).toBe("a cat");
    expect(req.model).toBeNull();
    expect(req.steps).toBe(20);
    expect(req.cfg_scale).toBe(7.0);
    expect(req.width).toBe(1024);
    expect(req.seed).toBe(-1);
    expect(req.sampler_name).toBe("DPM++ 2M Karras");
  });

  it("モデル指定は trim して渡す", () => {
    const req = buildImageGenRequest({
      ...defaultImageGenForm(),
      prompt: "x",
      model: "  sdxl-base  ",
    });
    expect(req.model).toBe("sdxl-base");
  });

  it("範囲外の数値は UI 範囲へ丸める (最終検証は Rust 側)", () => {
    const req = buildImageGenRequest({
      ...defaultImageGenForm(),
      prompt: "x",
      steps: 9999,
      cfgScale: 100,
      width: 10,
      batchCount: 99,
    });
    expect(req.steps).toBe(150);
    expect(req.cfg_scale).toBe(30);
    expect(req.width).toBe(64);
    expect(req.batch_count).toBe(4);
  });
});

describe("履歴 (Drop の生成履歴)", () => {
  const entry: ImageGenHistoryEntry = {
    prompt: "sunset",
    negative_prompt: "blurry",
    model: "sdxl-base",
    sampler_name: "Euler a",
    steps: 30,
    cfg_scale: 8.5,
    width: 768,
    height: 512,
    seed: 123,
    timestamp: "2026-11-16T00:00:00.000Z",
  };

  it("makeHistoryEntry は使用シードを優先し、モデルはフォーム優先", () => {
    const form = { ...defaultImageGenForm(), prompt: "sunset", model: "" };
    const e = makeHistoryEntry(form, 777, "fallback-model", new Date("2026-11-16T00:00:00.000Z"));
    expect(e.seed).toBe(777);
    expect(e.model).toBe("fallback-model");
    expect(e.timestamp).toBe("2026-11-16T00:00:00.000Z");
  });

  it("formFromHistory で条件を復元できる (往復)", () => {
    const form = formFromHistory(entry);
    expect(form.prompt).toBe("sunset");
    expect(form.negativePrompt).toBe("blurry");
    expect(form.samplerName).toBe("Euler a");
    expect(form.steps).toBe(30);
    expect(form.seed).toBe(123);
    expect(form.width).toBe(768);
    expect(form.height).toBe(512);
  });

  it("exportHistoryJson は JSON 配列として往復できる", () => {
    const json = exportHistoryJson([entry]);
    expect(JSON.parse(json)).toEqual([entry]);
  });
});

describe("画像ユーティリティ", () => {
  it("imageDataUrl は mime と base64 から data URL を作る", () => {
    expect(imageDataUrl({ mime_type: "image/png", base64: "AAA" })).toBe(
      "data:image/png;base64,AAA",
    );
  });

  it("imageExtension は既知の mime を拡張子へ変換する", () => {
    expect(imageExtension("image/png")).toBe("png");
    expect(imageExtension("image/jpeg")).toBe("jpg");
    expect(imageExtension("image/webp")).toBe("webp");
    expect(imageExtension("image/unknown")).toBe("png");
  });
});
