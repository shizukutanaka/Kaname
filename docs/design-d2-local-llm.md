# D2 解体: ローカル LLM 推論の実装計画

> 2026-09-20 監査セッションからの派生文書。
> gap-analysis.md D2 の「llama.cpp か candle で実推論を実装」を、
> 現行コードの構造に沿って実行可能な単位に分解する。
> **本書は設計案であり実装ではない** — kaname-ai の変更は
> CLAUDE.md の規則により security-lead 承認が必須。

---

## 現状 (実測)

| 要素 | 状態 | 場所 |
|---|---|---|
| `LocalLlmRunner` | 構造体+load/infer API 完備、内部は `ModelStub` (常に固定文字列) | `crates/kaname-ai/src/llm_bridge.rs` |
| `ModelConfig` | model_path/ctx_size/threads/gpu_layers/temperature/max_tokens を定義済み | 同上 |
| プロンプト構築 | `build_phi4_prompt` + `strip_phi4_special_tokens` (特殊トークン注入防御済み) | 同上 |
| 推論結果 | `InferenceResult { text, tokens_in, tokens_out, latency_ms }` — tokens_* は常に 0 | 同上 |
| サブプロセス分離 | `subprocess.rs`: JSON-Lines over stdin/stdout、seccomp プロファイル (quarantined.json / privileged.json) の設計済み | `crates/kaname-ai/src/subprocess.rs` |
| BEC 側 I/F | `trait LocalLlm { score_bec(...) -> LlmScore }` + `NullLlm` (決定論シグナルのみで出荷中) | `crates/kaname-bec/src/lib.rs` |
| 出荷状態 | **kaname-ai は出荷 closure に含まれない** (kaname-ui → 依存辺なし)。製品が LLM を装っていない点は正直 | `Cargo.toml` 推移閉包 (2026-09-20 実測) |

つまり「型・I/F・分離設計・注入防御」は揃っており、欠けているのは
**推論バックエンドの接続とモデル配布経路**のみ。

---

## 分解 (5 フェーズ)

### Phase 1 — 推論バックエンド接続 (kaname-ai)

- `llama-cpp-2` を kaname-ai の依存に追加 (llama.cpp FFI の safe wrapper)。
  代替: `candle` (pure Rust, unsafe 削減)。**判断基準**: Q-LLM プロセスは
  `#![deny(unsafe_code)]` 方針と seccomp で縛るため、C 依存は
  サブプロセス境界の内側に閉じ込められる — llama-cpp-2 で可。
- `LocalLlmRunner::load` の `ModelStub` を実 `LlamaModel` に置換
  (コードコメントの pseudo-code を実装化)。
- `infer()` 実装: `build_phi4_prompt` → tokenize → forward → decode。
  `tokens_in`/`tokens_out` を実値化 (現行は常に 0 — D2 の一部)。
- セキュリティ判定パスは `temperature = 0.0` (ModelConfig に既にある)。
- 完了条件: `infer()` が実モデルで JSON 出力を返し、既存テスト
  (`strip_phi4_special_tokens` 系) に加えて「実推論が有限の tokens_out を
  返す」統合テスト (model 不在環境では `#[ignore]`) が通る。

### Phase 2 — モデル配布 (kaname-ai + UI)

- Phi-4-mini-instruct Q4_K_M (~2.4 GB)。**モデルをリポジトリに入れない**。
- 初回起動時または設定画面からダウンロード: Hugging Face から取得し、
  SHA-256 チェックサムをコード内定数で検証 (改ざんモデル対策)。
- 保存先: `~/Library/Application Support/app.kaname/models/` (macOS)。
- 未ダウンロード時の挙動: BEC は `NullLlm` 経路 (現行と同じ決定論的判定)
  にフォールバック — **LLM 不在でも製品が動く設計を維持**。

### Phase 3 — サブプロセス分離の実接続 (kaname-ai)

- `subprocess.rs` の `LlmRequest`/`LlmResponse` JSON-Lines プロトコルを
  実プロセスに接続: Q-LLM 専用バイナリ `kaname-qllm` (workspace bin) を
  spawn し、seccomp `quarantined.json` を適用 (Linux)。
- macOS は seccomp 非対応 → Seatbelt プロファイル (sandbox-exec) で
  同等の制限 (network deny / file read 限定) を適用。ADR-020 の更新要。
- I1 の型境界維持: Q-LLM プロセスの出力は `AnalysisReport` スキーマに
  バリデーションしてから Trusted へ昇格 (JSON schema 検証を Bridge に集約)。

### Phase 4 — BEC 統合 (kaname-bec)

- `LocalLlmRunner` → `LocalLlm` trait impl: `score_bec` は
  Q-LLM プロンプトを構築し、出力 JSON (`{probability, explanation}`) を
  スキーマ検証。パース失敗・スキーマ違反は `NullLlm` 同等の 0 寄与に
  フォールバック (LLM 失敗で BEC 全体を壊さない)。
- しきい値校正は D9 の範囲 (敵対的サンプル必須) — 本フェーズでは
  `explanation` の文字列サニタイズ (説明文への指示注入防御) まで。
- 完了条件: `BecDetector` に実 LLM を差しても決定論テストが全て通る
  (LLM 寄与 0.45 重みの結合テスト追加)。

### Phase 5 — 出荷統合 (kaname-ui + src-tauri)

- kaname-ui → kaname-ai 依存辺を追加 (現在 closure 外)。
- IPC: `ai_status` (モデル有無/読込状態)、`mail_open` の BodyDto に
  `ai_summary` フィールド追加 — UI は未接続時「未解析」を表示
  (偽装禁止: モデル未導入ならバッジを出さない)。
- 遅延読込: モデルは初回 `mail_open` または設定で有効化時にロード
  (起動を遅くしない)。`tokio::task::spawn_blocking` で UI スレッド保護。

---

## リスクと既知の制約

| リスク | 対処 |
|---|---|
| 2.4 GB モデルの初回 DL が離脱を招く | 明示的な「有効化」操作 + 進捗表示。既定は NullLlm |
| C FFI (llama.cpp) の unsafe | サブプロセス境界の内側に限定、ホスト側は `#![deny(unsafe_code)]` 維持 |
| LLM 出力の注入 (`<|end|>` 脱出) | `strip_phi4_special_tokens` 済み + 出力は JSON スキーマ検証のみ受理 |
| 推論レイテンシ (421ms first-token) | 一覧は LLM なしで描画、開封時に非同期で追記する UI 設計 |
| モデルの再現性 (temperature=0 でも非決定) | セキュリティ判定は LlmScore を「寄与 0.45 の1シグナル」として扱い、閾値は決定論シグナル単独でも成立するよう設計 (現行 NullLlm 動作がそのまま下限) |

## 前提・ブロッカー

- D9 (SSA 校正) は Phase 4 完了が前提。
- D1 (MLS) とは独立。並行着手可。
- security-lead 承認必須 (CLAUDE.md: kaname-ai/bec 変更)。
- macOS/Windows でのサンドボックス差分 (seccomp 非対応) は
  Phase 3 の最大の設計論点。
