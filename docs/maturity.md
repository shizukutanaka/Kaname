# 機能マチュリティ・マトリクス

> このドキュメントは `crates/kaname-ai/src/lib.rs` の doc コメントが参照する
> マチュリティ表を実体化したもの。市販/本番出荷の可否判断材料として、
> 「実際に動作する本番実装」と「開発中のモック実装」を明確に区別する。
>
> 方針: 実コードの根拠 (file:line) に基づき記載する。誇張・希望的観測を避ける。

---

## ⚠️ 最重要: メールクライアントとしての配線が存在しない (2026-07 検証)

**下表の「本番出荷可」は個々のクレートが純粋関数/ライブラリとして動作することを
意味するに過ぎない。出荷バイナリはメールを送受信できない。** First Principles
監査 (2026-07) で以下を実コード確認した:

| 検証項目 | 結果 (根拠) |
|---|---|
| Tauri コマンド層の依存 | `crates/kaname-ui/Cargo.toml` に **`kaname-jmap`/`kaname-store`/`kaname-core` が無い** → 出荷バイナリからネットワークにも DB にも**コンパイル時点で到達経路が存在しない** |
| メール永続化 | `messages`/`mailboxes`/`attachments` テーブルへの **INSERT/SELECT がワークスペース全体でゼロ件** (スキーマ定義のみ) |
| メール受信 | `kaname-jmap` は RFC 8621 準拠の**本物の HTTP 実装**だが、**呼び出し元が存在しない**。`app_state.rs` の同期ループはフラグを上下させるだけでネットワーク I/O をしない |
| メール送信 | `JmapClient::send_email()` は実装済みだが Tauri コマンド未登録。UI が呼ぶ `mail_send` は**未定義** |
| アカウント設定 | `app_state.rs` の `let accounts: Vec<AccountConfig> = vec![];` で**常に空**。サーバ URL/認証情報を入力する UI が存在しない |
| 検索 | 検索 `<input>` にハンドラ未バインド。FTS も JMAP テキストフィルタも無し |
| 添付ダウンロード | blob download 実装なし (`download_url` は保持されるだけで参照ゼロ) |

**したがって現状は「メールクライアント」ではなく、「メールセキュリティ・
ライブラリ集 + デモ UI」である。** 実配線 (受信→保存→表示→送信) は
`docs/gap-analysis.md` の D10 を参照 (次セッションの最優先課題)。

### 2026-07 の是正 (部分的)
- 実装済みだが `invoke_handler` 未登録で**到達不能だった arxiv 防御コマンド10件**
  (入力スクリーニング/出力監査/Tiered-Risk/メモリ信頼/Rule of Two/引数検証/
  トラジェクトリ/OOBV推奨/Deepfake判定) を登録し、実際に呼び出せるようにした。
- UI が呼ぶが未定義だった5コマンド (`mail_send`/`mail_get_mailboxes`/
  `mail_query_emails`/`bec_get_score`/`settings_save_onboarding`) を、
  **明示的な「未配線」エラーを返す実装**として追加 (偽データは返さない)。
  これにより Inbox が起動時に無言で永久に空になる問題が、原因表示に変わった。

---

## 本番出荷可 (ライブラリ単体として実装 + 実テストで検証済み。上記の通りアプリには未配線)

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
| PQC ハイブリッド鍵カプセル化 (X25519 + ML-KEM) | `kaname-crypto` | **注意**: コード内の "X-Wing" 表記は独自 HKDF 合成 (`combine_kem_secrets`, info=`kaname-xwing-v1`) であり、IETF 標準の X-Wing (draft-connolly-cfrg-xwing-kem) とはワイヤ非互換。外部監査時に名称で混同しないこと。また X25519/ML-KEM の実体は `Kem` トレイト経由のバックエンド注入で、テストは MockKem のみ (実アルゴリズムバックエンドの結合は未検証) |

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

## 2026-07 追加調査: フロントエンド (SolidJS/TS) も同様にビルド不能だった

バックエンドと並行して `npm run build` (`tsc && vite build`) を検証したところ、
**フロントエンドも本番ビルドが失敗する状態**だった。主な原因と修正:

- `src/main.tsx` が実在しない `./ui/KanameAppleV5` をインポートしていた
  (未実装のデモビュー「V5デモ」への参照)。当該ビュー・ナビ項目を削除。
- `src/i18n.ts` に `main.tsx` が呼び出す `initI18n` が定義されておらず
  型エラー。薄い非同期ラッパーとして追加。同ファイルの `Set.filter()` 呼び出し
  ( `Set` に `filter` メソッドは存在しない) も配列変換して修正。
- **`src/ui/` 配下の全 `.tsx` コンポーネントに未使用の `.jsx` 重複ファイルが
  併存していた** (`KanameApp.jsx`, `KanameDesign.jsx` 等 8 ファイル + `main.jsx`)。
  `index.html` の実エントリポイントは `main.tsx` のみで `.jsx` 群はどこからも
  参照されないデッドコードと確認の上、全削除。
- `src/ui/KanameDesign.tsx` の `view` 状態に `"paper_trail"` 用のフィルタ
  ロジックは実装済みだったが、対応するナビゲーション項目 (`navItems`) が
  存在せず**永久に到達不可能な機能**になっていた (HEY 風 Paper Trail 機能が
  UI から到達できなかった)。ナビ項目・型定義・ラベルマップを追加して結線。
- `package.json` に `jsdom`(vitest の jsdom 環境で必須)、
  `@playwright/test`/`@axe-core/playwright` (e2e/a11y テストで使用) が
  devDependency として宣言されておらず、`npm install` 後もテスト実行が
  失敗する状態だった。追加。
- ESLint 設定ファイル (`.eslintrc.json`) が存在せず `npm run lint` が
  一度も実行できない状態だった。新規作成し、実際に検出された
  `no-empty`(空 catch ブロック) と `@typescript-eslint/ban-ts-comment`
  (`@ts-ignore` の使用) の 2 件を修正。特に後者は `src/ui/Onboarding.tsx` の
  `Ready` コンポーネントが誤って `async` 関数として定義され
  `Promise<Element>` を返していた実バグを隠していた
  (JSX コンポーネントは同期的に要素を返す契約に違反)。`onMount` 内で
  非同期処理を行う設計に修正。

検証: `npx tsc --noEmit` (exit 0) / `npx eslint src ... --max-warnings 0` (exit 0) /
`npm run build` 成功 / `npx vitest run` 21 テスト全パス。
