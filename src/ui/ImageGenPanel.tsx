// src/ui/ImageGenPanel.tsx — 画像生成パネル (Drop 統合)
//
// 旧 Drop (画像生成 AI の操作画面) の機能をメール作成画面に組み込んだもの。
// 生成は利用者自身の画像生成エンドポイント (AUTOMATIC1111 互換) に対して
// Rust 側 `imagegen_generate` が実行する。生成した画像はそのままメールに
// 添付できる (送信経路は通常送信と同じで、送信前 DLP・監査も効く)。
//
// 注意:
//   - プロンプトは利用者が設定したエンドポイントへ送信される (画面にも明記)。
//   - API キーはアプリのメモリ内にのみ保持され、端末にも保存されない。
//   - 履歴は端末内にのみ保存され、画像そのものは含まない (Drop と同じ)。

import { createSignal, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import {
  buildImageGenRequest,
  defaultImageGenForm,
  exportHistoryJson,
  formFromHistory,
  imageDataUrl,
  imageExtension,
  IMAGE_SAMPLERS,
  IMAGE_SIZES,
  makeHistoryEntry,
  type GeneratedImage,
  type ImageGenForm,
  type ImageGenHistoryEntry,
} from "./imagegen";

interface ImageGenConfigView {
  base_url: string;
  model: string;
  has_api_key: boolean;
}

interface ImageGenResultView {
  images: GeneratedImage[];
  used_seed: number | null;
}

interface ImageGenPanelProps {
  attached: GeneratedImage[];
  onAttachedChange: (images: GeneratedImage[]) => void;
}

export const ImageGenPanel = (props: ImageGenPanelProps) => {
  const [open, setOpen] = createSignal(false);
  const [loaded, setLoaded] = createSignal(false);

  // 接続設定
  const [baseUrl, setBaseUrl] = createSignal("");
  const [configModel, setConfigModel] = createSignal("");
  const [hasApiKey, setHasApiKey] = createSignal(false);
  const [apiKeyInput, setApiKeyInput] = createSignal("");
  const [configMsg, setConfigMsg] = createSignal<string | null>(null);

  // 生成フォームと結果
  const [form, setForm] = createSignal<ImageGenForm>(defaultImageGenForm());
  const [generating, setGenerating] = createSignal(false);
  const [genError, setGenError] = createSignal<string | null>(null);
  const [results, setResults] = createSignal<GeneratedImage[]>([]);

  // 履歴
  const [history, setHistory] = createSignal<ImageGenHistoryEntry[]>([]);

  const patchForm = (patch: Partial<ImageGenForm>) =>
    setForm(f => ({ ...f, ...patch }));

  const loadOnce = async () => {
    if (loaded()) return;
    setLoaded(true);
    try {
      const cfg = await invoke<ImageGenConfigView>("imagegen_get_config");
      setBaseUrl(cfg.base_url);
      setConfigModel(cfg.model);
      setHasApiKey(cfg.has_api_key);
      if (cfg.model) patchForm({ model: cfg.model });
    } catch {
      // 未設定として表示する (設定欄は常に入力可能)
    }
    try {
      setHistory(await invoke<ImageGenHistoryEntry[]>("imagegen_history_list"));
    } catch {
      setHistory([]);
    }
  };

  const toggleOpen = () => {
    setOpen(!open());
    if (!open()) void loadOnce();
  };

  const saveConfig = async () => {
    setConfigMsg(null);
    try {
      const key = apiKeyInput();
      const cfg = await invoke<ImageGenConfigView>("imagegen_set_config", {
        baseUrl: baseUrl(),
        model: configModel(),
        apiKey: key === "" ? null : key,
      });
      setBaseUrl(cfg.base_url);
      setConfigModel(cfg.model);
      setHasApiKey(cfg.has_api_key);
      setApiKeyInput("");
      patchForm({ model: cfg.model });
      setConfigMsg("接続設定を保存しました (API キーはメモリ内にのみ保持されます)");
    } catch (e) {
      setConfigMsg(String(e));
    }
  };

  const clearApiKey = async () => {
    try {
      await invoke("imagegen_clear_api_key");
      setHasApiKey(false);
      setConfigMsg("API キーを破棄しました");
    } catch (e) {
      setConfigMsg(String(e));
    }
  };

  const generate = async () => {
    setGenError(null);
    setGenerating(true);
    try {
      const req = buildImageGenRequest(form());
      const res = await invoke<ImageGenResultView>("imagegen_generate", { req });
      setResults(res.images);
      // 履歴へ追加 (Drop の生成履歴。画像そのものは残さない)。
      const entry = makeHistoryEntry(form(), res.used_seed, configModel());
      const next = [entry, ...history()].slice(0, 100);
      setHistory(next);
      await invoke("imagegen_history_save", { entries: next }).catch(() => {});
    } catch (e) {
      setGenError(String(e));
    } finally {
      setGenerating(false);
    }
  };

  const isAttached = (img: GeneratedImage) =>
    props.attached.some(a => a.base64 === img.base64);

  const toggleAttach = (img: GeneratedImage) => {
    if (isAttached(img)) {
      props.onAttachedChange(props.attached.filter(a => a.base64 !== img.base64));
    } else {
      props.onAttachedChange([...props.attached, img]);
    }
  };

  const downloadImage = (img: GeneratedImage, index: number) => {
    const a = document.createElement("a");
    a.href = imageDataUrl(img);
    a.download = `generated-image-${index + 1}.${imageExtension(img.mime_type)}`;
    a.click();
  };

  const exportHistory = () => {
    const blob = new Blob([exportHistoryJson(history())], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "imagegen-history.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const clearHistory = async () => {
    setHistory([]);
    await invoke("imagegen_history_save", { entries: [] }).catch(() => {});
  };

  const inputStyle = {
    width: "100%",
    background: "#12181F",
    border: "1px solid #2A3441",
    "border-radius": "6px",
    padding: "7px 10px",
    color: "#F5F7FA",
    "font-size": "12px",
    outline: "none",
    "box-sizing": "border-box",
    "font-family": "inherit",
  } as const;

  const labelStyle = {
    "font-size": "11px",
    color: "#8B96A5",
    display: "block",
    "margin-bottom": "4px",
  } as const;

  const smallBtn = {
    background: "#1F2833",
    color: "#F5F7FA",
    border: "1px solid #2A3441",
    "border-radius": "4px",
    padding: "4px 10px",
    "font-size": "11px",
    cursor: "pointer",
  } as const;

  return (
    <div style={{ "border-top": "1px solid #1F2833" }}>
      <button
        onClick={toggleOpen}
        style={{
          width: "100%",
          background: "none",
          border: "none",
          cursor: "pointer",
          color: "#F5F7FA",
          "font-size": "12px",
          "font-weight": "600",
          padding: "10px 16px",
          "text-align": "left",
        }}
      >
        🎨 画像を生成して添付 {open() ? "▾" : "▸"}
        <span style={{ color: "#6B7A94", "font-weight": "400", "margin-left": "8px" }}>
          自分の画像生成エンドポイント (Stable Diffusion WebUI 互換) を使います
        </span>
      </button>

      <Show when={open()}>
        <div style={{
          padding: "4px 16px 14px",
          display: "flex",
          "flex-direction": "column",
          gap: "10px",
        }}>
          {/* 接続設定 */}
          <div style={{
            background: "#0A0E14",
            border: "1px solid #1F2833",
            "border-radius": "6px",
            padding: "10px 12px",
            display: "flex",
            "flex-direction": "column",
            gap: "8px",
          }}>
            <div style={{ "font-size": "11px", "font-weight": "600", color: "#8B96A5" }}>
              接続設定 (利用者自身のエンドポイント)
            </div>
            <div>
              <label style={labelStyle}>エンドポイント URL</label>
              <input
                type="text"
                placeholder="http://localhost:7860 または https://…"
                value={baseUrl()}
                onInput={e => setBaseUrl(e.currentTarget.value)}
                style={inputStyle}
              />
            </div>
            <div style={{ display: "flex", gap: "8px" }}>
              <div style={{ flex: "1" }}>
                <label style={labelStyle}>
                  API キー (任意 — 端末に保存されず、起動中のみ保持)
                </label>
                <input
                  type="password"
                  placeholder={hasApiKey() ? "設定済み (変更する場合のみ入力)" : "未設定"}
                  value={apiKeyInput()}
                  onInput={e => setApiKeyInput(e.currentTarget.value)}
                  style={inputStyle}
                />
              </div>
              <div style={{ flex: "1" }}>
                <label style={labelStyle}>モデル (チェックポイント名)</label>
                <input
                  type="text"
                  placeholder="例: sdxl-base"
                  value={configModel()}
                  onInput={e => setConfigModel(e.currentTarget.value)}
                  style={inputStyle}
                />
              </div>
            </div>
            <div style={{ display: "flex", gap: "8px", "align-items": "center" }}>
              <button onClick={saveConfig} style={smallBtn}>接続設定を保存</button>
              <Show when={hasApiKey()}>
                <button onClick={clearApiKey} style={smallBtn}>API キーを破棄</button>
              </Show>
              <span style={{ "font-size": "11px", color: "#6B7A94" }}>
                http はこの端末内のエンドポイントだけに使えます
              </span>
            </div>
            <Show when={configMsg()}>
              <div style={{ "font-size": "11px", color: "#8B96A5" }}>{configMsg()}</div>
            </Show>
          </div>

          {/* 生成フォーム (Drop のパラメータ一式) */}
          <div>
            <label style={labelStyle}>プロンプト (設定したエンドポイントへ送信されます)</label>
            <textarea
              rows={2}
              placeholder="例: masterpiece, best quality, sunset over the sea"
              value={form().prompt}
              onInput={e => patchForm({ prompt: e.currentTarget.value })}
              style={{ ...inputStyle, resize: "vertical" }}
            />
          </div>
          <div>
            <label style={labelStyle}>ネガティブプロンプト</label>
            <textarea
              rows={1}
              placeholder="例: low quality, blurry"
              value={form().negativePrompt}
              onInput={e => patchForm({ negativePrompt: e.currentTarget.value })}
              style={{ ...inputStyle, resize: "vertical" }}
            />
          </div>

          <div style={{ display: "flex", gap: "12px", "flex-wrap": "wrap" }}>
            <div style={{ flex: "1 1 160px" }}>
              <label style={labelStyle}>サンプラー</label>
              <select
                value={form().samplerName}
                onChange={e => patchForm({ samplerName: e.currentTarget.value })}
                style={inputStyle}
              >
                <For each={IMAGE_SAMPLERS}>{s => <option value={s}>{s}</option>}</For>
              </select>
            </div>
            <div style={{ flex: "1 1 160px" }}>
              <label style={labelStyle}>画像サイズ</label>
              <select
                value={`${form().width}×${form().height}`}
                onChange={e => {
                  const s = IMAGE_SIZES.find(
                    x => `${x.width}×${x.height}` === e.currentTarget.value,
                  );
                  if (s) patchForm({ width: s.width, height: s.height });
                }}
                style={inputStyle}
              >
                <For each={IMAGE_SIZES}>
                  {s => <option value={`${s.width}×${s.height}`}>{s.label}</option>}
                </For>
              </select>
            </div>
            <div style={{ flex: "1 1 120px" }}>
              <label style={labelStyle}>シード (-1 = ランダム)</label>
              <input
                type="number"
                value={form().seed}
                onInput={e => patchForm({ seed: Number(e.currentTarget.value) })}
                style={inputStyle}
              />
            </div>
          </div>

          <div style={{ display: "flex", gap: "16px", "flex-wrap": "wrap" }}>
            <div style={{ flex: "1 1 180px" }}>
              <label style={labelStyle}>
                サンプリングステップ: {form().steps}
              </label>
              <input
                type="range"
                min={1}
                max={150}
                value={form().steps}
                onInput={e => patchForm({ steps: Number(e.currentTarget.value) })}
                style={{ width: "100%" }}
              />
            </div>
            <div style={{ flex: "1 1 180px" }}>
              <label style={labelStyle}>CFG Scale: {form().cfgScale.toFixed(1)}</label>
              <input
                type="range"
                min={1}
                max={30}
                step={0.5}
                value={form().cfgScale}
                onInput={e => patchForm({ cfgScale: Number(e.currentTarget.value) })}
                style={{ width: "100%" }}
              />
            </div>
            <div style={{ flex: "0 1 90px" }}>
              <label style={labelStyle}>バッチ数</label>
              <input
                type="number"
                min={1}
                max={4}
                value={form().batchCount}
                onInput={e => patchForm({ batchCount: Number(e.currentTarget.value) })}
                style={inputStyle}
              />
            </div>
            <div style={{ flex: "0 1 90px" }}>
              <label style={labelStyle}>バッチサイズ</label>
              <input
                type="number"
                min={1}
                max={4}
                value={form().batchSize}
                onInput={e => patchForm({ batchSize: Number(e.currentTarget.value) })}
                style={inputStyle}
              />
            </div>
          </div>

          <div style={{ display: "flex", gap: "16px", "font-size": "12px", color: "#F5F7FA" }}>
            <label style={{ display: "flex", gap: "6px", "align-items": "center", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={form().enableHr}
                onChange={e => patchForm({ enableHr: e.currentTarget.checked })}
              />
              Hires. fix
            </label>
            <label style={{ display: "flex", gap: "6px", "align-items": "center", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={form().restoreFaces}
                onChange={e => patchForm({ restoreFaces: e.currentTarget.checked })}
              />
              Restore faces
            </label>
            <label style={{ display: "flex", gap: "6px", "align-items": "center", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={form().tiling}
                onChange={e => patchForm({ tiling: e.currentTarget.checked })}
              />
              Tiling
            </label>
          </div>

          <div>
            <button
              onClick={generate}
              disabled={generating() || form().prompt.trim() === ""}
              style={{
                background: "#00C4CC",
                color: "#0A0E14",
                border: "none",
                "border-radius": "6px",
                padding: "8px 20px",
                "font-size": "13px",
                "font-weight": "600",
                cursor: generating() ? "not-allowed" : "pointer",
                opacity: generating() || form().prompt.trim() === "" ? 0.6 : 1,
              }}
            >
              {generating() ? "生成中… (エンドポイントの処理を待っています)" : "生成"}
            </button>
            <Show when={genError()}>
              <div style={{ "font-size": "12px", color: "#FF6B70", "margin-top": "6px" }}>
                {genError()}
              </div>
            </Show>
          </div>

          {/* 生成結果 */}
          <Show when={results().length > 0}>
            <div style={{
              display: "grid",
              "grid-template-columns": "repeat(auto-fill, minmax(140px, 1fr))",
              gap: "10px",
            }}>
              <For each={results()}>
                {(img, i) => (
                  <div style={{
                    background: "#0A0E14",
                    border: isAttached(img)
                      ? "1px solid #00C4CC"
                      : "1px solid #1F2833",
                    "border-radius": "6px",
                    padding: "6px",
                    display: "flex",
                    "flex-direction": "column",
                    gap: "6px",
                  }}>
                    <img
                      src={imageDataUrl(img)}
                      alt={`生成画像 ${i() + 1}`}
                      style={{ width: "100%", "border-radius": "4px" }}
                    />
                    <div style={{ display: "flex", gap: "6px" }}>
                      <button onClick={() => toggleAttach(img)} style={{ ...smallBtn, flex: "1" }}>
                        {isAttached(img) ? "添付を外す" : "添付に追加"}
                      </button>
                      <button onClick={() => downloadImage(img, i())} style={smallBtn}>
                        保存
                      </button>
                    </div>
                  </div>
                )}
              </For>
            </div>
          </Show>

          {/* 履歴 (Drop の履歴パネル) */}
          <Show when={history().length > 0}>
            <div>
              <div style={{
                display: "flex",
                gap: "8px",
                "align-items": "center",
                "margin-bottom": "6px",
              }}>
                <span style={{ "font-size": "11px", "font-weight": "600", color: "#8B96A5" }}>
                  生成履歴 (端末内のみ・画像は含みません)
                </span>
                <div style={{ flex: "1" }} />
                <button onClick={exportHistory} style={smallBtn}>
                  履歴エクスポート (JSON)
                </button>
                <button onClick={clearHistory} style={smallBtn}>履歴クリア</button>
              </div>
              <div style={{ display: "flex", "flex-direction": "column", gap: "6px" }}>
                <For each={history()}>
                  {h => (
                    <button
                      onClick={() => setForm(formFromHistory(h))}
                      title="クリックで条件を復元"
                      style={{
                        background: "#0A0E14",
                        border: "1px solid #1F2833",
                        "border-radius": "6px",
                        padding: "6px 10px",
                        "text-align": "left",
                        cursor: "pointer",
                        color: "#F5F7FA",
                      }}
                    >
                      <div style={{
                        "font-size": "12px",
                        overflow: "hidden",
                        "text-overflow": "ellipsis",
                        "white-space": "nowrap",
                      }}>
                        {h.prompt}
                      </div>
                      <div style={{ "font-size": "10px", color: "#6B7A94" }}>
                        {h.timestamp} • {h.model || "(既定モデル)"} • {h.width}×{h.height} • seed {h.seed}
                      </div>
                    </button>
                  )}
                </For>
              </div>
            </div>
          </Show>
        </div>
      </Show>
    </div>
  );
};

export default ImageGenPanel;
