# 機能マチュリティ・マトリクス

> このドキュメントは `crates/kaname-ai/src/lib.rs` の doc コメントが参照する
> マチュリティ表を実体化したもの。市販/本番出荷の可否判断材料として、
> 「実際に動作する本番実装」と「開発中のモック実装」を明確に区別する。
>
> 方針: 実コードの根拠 (file:line) に基づき記載する。誇張・希望的観測を避ける。

---

## 本番出荷可 (実装 + 実テストで検証済み)

| 機能 | クレート | 備考 |
|---|---|---|
| BEC 多信号検出 (認証/ドメイン/履歴/内容/AiTM/Reply-To/スレッド乗っ取り/口座差替/DKIM検証) | `kaname-bec` | 110+ テスト |
| DLP 12分類器 + 宛先ミス検出 (誤送信防止) | `kaname-dlp` | チェックディジット検証 (Luhn/マイナンバー/IBAN/法人番号/BIC) |
| ホモグリフ/タイポスクワット/IDN Punycode検出 | `kaname-bec` | |
| Quishing・カレンダー招待(.ics)・HTMLスマグリング検出 | `kaname-render` | |
| SaaSリンク安全性・OAuth state検証 | `kaname-saas-guard` | |
| Dual-LLM 型境界 (`Content<Untrusted>`/`Bridge`/preflight) | `kaname-ai::dual_llm` | 型レベルでプロンプト注入経路を遮断。**LLM 推論本体は下記モック段階** |
| プライバシー保護 (PCR メタデータのみ/SSA数値ベクトルのみ/トラッキング遮断) | `kaname-radar`, `kaname-ssa`, `kaname-privacy` | 本文非解析設計 |
| Out-of-Band Verification (電話確認セレモニー) | `kaname-oobv` | |
| 入力スクリーニング (プロンプト注入検出) | `kaname-screen` | |
| SSRF 対策 (DNS再検証込みリダイレクトガード) | `kaname-jmap::ssrf_guard` | |
| 監査ログ (HMAC-SHA256 鍵付きハッシュチェーン) | `kaname-ai::threat_intel` | |
| PQC ハイブリッド鍵カプセル化 (X25519 + ML-KEM) | `kaname-crypto` | |

---

## モック/スタブ段階 (要外部クレート統合、本セッションのネットワーク制限では実装不能)

これらは**コアロジックが実際には動作しない**。誤って本番運用しないよう、
呼び出し箇所には目立つログ (`tracing::error!`) を仕込んである場合はその旨を記載する。

| 機能 | クレート | 現状 | 実装に必要なもの |
|---|---|---|---|
| MLS グループ E2E 暗号化 | `kaname-mls` | 単一バイト XOR (鍵=公開 ConversationId 先頭バイト、鍵空間256)。`INSECURE_MOCK_CRYPTO` ログで検知可能 | `openmls` クレート統合 |
| ローカル LLM 推論 (Q-LLM/P-LLM) | `kaname-ai::llm_bridge` | 固定文字列応答 (`{"risk":"SAFE",...}` 等)、`tokens_in/out` は常に 0 | `llama.cpp`/`candle` 等での実推論、Phi-4-mini 等のモデル配布 |
| Q-LLM/P-LLM プロセス分離 | `kaname-ai::subprocess` | seccomp プロファイルのパス文字列を生成するのみ。実際の seccomp 適用は外部バイナリ `kaname-llm-runner` 側に委譲 (存在未確認) | `kaname-llm-runner` バイナリの実装、seccomp-bpf/sandbox-exec/Job Object の実適用 |
| Firecracker microVM サンドボックス | `kaname-sandbox` | `spawn_vm`/`VsockChannel` が no-op。セマフォ管理・プール衛生は実装済みだが VM 自体は起動しない | Firecracker バイナリ統合、vsock 通信実装 |
| 自動アップデート | `src-tauri` | `tauri.conf.json` から `updater` 設定を削除済み (2026-07 修正)。`tauri-plugin-updater` 未導入 | プラグイン導入 + 署名鍵生成 + 配信サーバー構築 |
| 課金基盤の永続化 | `kaname-billing` | エンタイトルメント/冪等性キーが in-memory のみ (プロセス再起動で消失)。Stripe webhook ペイロードを直接信頼 (ライブAPI再取得なし) | `kaname-store` 連携、Redis 分散重複排除、台帳ハッシュチェーン検証 |

---

## 2026-07 に判明・修正した設定不整合

出荷直前の監査で発見し修正した項目 (履歴として記録):

- `src-tauri/tauri.conf.json` の `vibrancy` フィールドが Tauri 2.x スキーマに
  存在せず `cargo check --workspace` が **exit 101 で失敗**していた
  (`windowEffects.effects: ["underWindowBackground"]` へ移行して解消)。
- 同ファイルの `bundle.linux.depends`/`desktopTemplate` も現行 tauri-build の
  スキーマに存在せず削除。
- `bundle.updater` も現行スキーマから廃止済み (プラグイン化) のため削除。
  加えて `pubkey: ""` (空の署名鍵) のまま `active: true` になっており、
  仮にスキーマが通っても機能しない/危険な設定だった。
- `macOSPrivateApi: true` に対応する Cargo 側 `macos-private-api` フィーチャーが
  未指定でビルド不能だった (`Cargo.toml` の `tauri` 依存に追加して解消)。
- `TrayIconBuilder::menu_on_left_click` が非推奨 API のままで
  `-D warnings` (deny(deprecated) 相当) ビルドが失敗していた。
  `show_menu_on_left_click` へ移行。
- `main.rs` の `.icon(...unwrap())` がアイコン取得失敗時にアプリ全体を
  クラッシュさせる設計だった。`if let Some(icon) = ...` による条件分岐に変更し、
  取得失敗時は警告ログを出しつつトレイ生成を継続するよう修正。
- `src-tauri/src/legacy_main.rs` が `[[bin]]` からもコードからも参照されない
  デッドコードだったため削除。

これらの修正前は **`cargo check --workspace` が完走せず、CI・リリースビルドの
どちらも実行不可能**な状態だった。
