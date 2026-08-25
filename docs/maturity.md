# 機能マチュリティ・マトリクス

> このドキュメントは `crates/kaname-ai/src/lib.rs` の doc コメントが参照する
> マチュリティ表を実体化したもの。市販/本番出荷の可否判断材料として、
> 「実際に動作する本番実装」と「開発中のモック実装」を明確に区別する。
>
> 方針: 実コードの根拠 (file:line) に基づき記載する。誇張・希望的観測を避ける。

---

## 製品スコープ (2026-07 確定)

Kaname は現在 **「ローカル・メールセキュリティ解析ツール」** として完結している。
サーバ接続もアカウント設定も不要で、以下が**実際に動作する**:

| 機能 | 状態 | 入口 |
|---|---|---|
| MIME 解析 (RFC 5322) | ✅ 動作 | 「ファイル解析」タブ |
| 送信ドメイン認証の評価 (SPF/DKIM/DMARC) | ✅ 動作 (ヘッダ由来) | 同上 |
| BEC 多信号検出 (決定論的 9 シグナル) | ✅ 動作 | 同上 |
| HTML サニタイズ (mXSS/CSS exfil/トラッキング) | ✅ 動作 | 同上 |
| 本文リスク検出 (HTMLスマグリング/テキストQR/CSS外部参照/リンク評判判定/**SaaSリンク安全性**) | ✅ 動作 | 同上 |
| 機微情報検出 (DLP, Inbound) | ✅ 動作 | 同上 |
| **添付ファイル検査** (MIME偽装/polyglot/危険拡張子/SVGスクリプト/メタデータ/**カレンダー招待**) | ✅ 動作 | 同上 |
| キャンペーン検出 (複数メール横断) | ✅ 動作 | 「フォルダを一括解析」 |
| **JMAP サーバ接続・受信** (各通に BEC 判定) | ✅ 実装済 (要サーバ) | 「サーバ接続」タブ |
| **メール送信** (送信前 DLP `Outbound` でブロック) | ✅ 実装済 (要サーバ) | 同上 |
| **送信者履歴の永続化** (BEC の履歴シグナルに供給) | ✅ 実装済 (SQLCipher) | `history_open` コマンド |
| **メール本体の永続化** (オフライン閲覧) | ✅ 実装済 (SQLCipher) | 受信時に自動保存 |
| **検索** (件名/送信者/本文プレビュー) | ✅ 実装済 | 受信箱の検索欄 |
| **送信者文体認証 (SSA)** — アカウント乗っ取り検出 | ✅ 動作 (同一セッション内で学習) | 「ファイル解析」タブ |
| **トラッキングピクセル検出** | ✅ 動作 | 同上 |

動作確認用のサンプルを [`examples/emails/`](../examples/) に同梱している。

**このスコープの外にあるもの** (次段階):
添付ダウンロード、MLS 暗号化、ローカル LLM 推論。
※ **送信者履歴の永続化は実装済み** (BEC の履歴シグナルが有効になる)。

**認証情報を永続化しない設計**: Bearer トークンはプロセスのメモリ内にのみ
保持し、ディスクへは書かない。`kaname-store` の鍵管理が keyfile への
フォールバックを含む現状では平文同然で置くことになるため、
**安全に保管できないものは保管しない**方針を採っている。
OS キーチェーン統合が入るまで、起動のたびに接続し直す。

---

## 出荷バイナリに含まれないクレートとその理由 (2026-07 仕分け)

依存グラフ実測で「到達可能 10/27」だった状態から組み立てを進め、
現在 **18/27** が出荷バイナリに含まれる。残る 9 個は**意図的に含めていない**:

| クレート | 含めない理由 |
|---|---|
| `kaname-mls` | **モック暗号 (単一バイト XOR)**。組み込むと「暗号化されている」と偽ることになる。`openmls` 統合まで含めない方が安全 |
| `kaname-sandbox` | **no-op** (`spawn_vm` が VM を起動しない)。同上、隔離されていないものを隔離済みと見せない |
| `kaname-mockserver` | 開発用の JMAP モックサーバ。製品に含めるものではない |
| `kaname-tests` | 統合テスト・敵対テスト用クレート。同上 |
| `kaname-billing` | 課金基盤。本製品のスコープ (メールセキュリティ解析) に不要。永続化も未実装 (D6) |
| `kaname-core` | UX 機能 (スクリーナー/トリアージ/スヌーズ)。受信箱 UI が本格稼働してから接続する |
| `kaname-continuity` | デバイス間ハンドオフ。単一デバイスで完結する現スコープでは不要 |
| `kaname-i18n` | 翻訳カタログ。UI 文言の外部化は本体機能が固まってから |
| `kaname-tray` | トレイアイコンの描画/メニュー生成。`src-tauri` が独自にトレイを持つため重複 |

**モック実装を組み込まない判断が最も重要**である。`kaname-mls` や
`kaname-sandbox` を「到達可能クレート数」のために繋ぐと、
動かない暗号・隔離を動いているかのように見せることになる。

---

## サーバとの送受信が未配線である件 (2026-07 検証)

**上記スコープ内の解析機能は実際に動作するが、サーバとのメール送受信はできない。**
First Principles 監査 (2026-07) で以下を実コード確認した:

| 検証項目 | 結果 (根拠) |
|---|---|
| Tauri コマンド層の依存 | `crates/kaname-ui/Cargo.toml` に **`kaname-jmap`/`kaname-store`/`kaname-core` が無い** → 出荷バイナリからネットワークにも DB にも**コンパイル時点で到達経路が存在しない** |
| メール永続化 | `messages`/`mailboxes`/`attachments` テーブルへの **INSERT/SELECT がワークスペース全体でゼロ件** (スキーマ定義のみ) |
| メール受信 | `kaname-jmap` は RFC 8621 準拠の**本物の HTTP 実装**だが、**呼び出し元が存在しない**。`app_state.rs` の同期ループはフラグを上下させるだけでネットワーク I/O をしない |
| メール送信 | `JmapClient::send_email()` は実装済みだが Tauri コマンド未登録。UI が呼ぶ `mail_send` は**未定義** |
| アカウント設定 | `app_state.rs` の `let accounts: Vec<AccountConfig> = vec![];` で**常に空**。サーバ URL/認証情報を入力する UI が存在しない |
| 検索 | 検索 `<input>` にハンドラ未バインド。FTS も JMAP テキストフィルタも無し |
| 添付ダウンロード | blob download 実装なし (`download_url` は保持されるだけで参照ゼロ) |

**したがって Kaname は「サーバ接続型のメールクライアント」ではなく、
上記スコープの「ローカル・メールセキュリティ解析ツール」である。**
実配線 (受信→保存→表示→送信) は `docs/gap-analysis.md` の D10 を参照
(ネットワーク解放後の最優先課題)。

### 2026-07 の「組み立て」フェーズ (依存グラフ実測を受けて)

依存グラフの実測により、**出荷バイナリに到達可能なのは 27 クレート中 10 個のみ**で、
`kaname-bec` (看板機能) すら製品に含まれていないことが判明した (D19)。
「部品を作る」のをやめ「組み立てる」方針に転換し、以下を実施:

| 対象 | 従来 | 現在 |
|---|---|---|
| `ai_detect_phishing` | `score: 0.12` の固定値 | **`BecDetector::assess()` の実際の判定** |
| `mail_list` の `bec_verdict` | モックに手書きした固定文字列 | **実際の判定結果で上書き** |
| `mail_get_summary` | `{unread:3, bec_alerts:1, total:42}` 固定 | **同じ検出器で実集計** |
| `mail_get_body` | `format!("<p>メール {} の本文</p>")` | **`sanitize_html` → `to_srcdoc` の実経路** (型契約不一致も解消) |
| `ai_summarize_email` | 固定要約 + `local_inference: true` と偽装 | **risk は本物、要約は未実装と明示、`local_inference: false`** |
| `ai_smart_reply` | 内容と無関係な固定3文 | **未実装を明示的にエラーで返す (偽物を削除)** |

到達可能クレートは 10 → **13** に増加 (`kaname-bec` / `kaname-radar` / `kaname-dlp`)。
さらにローカル `.eml` インポートにより**実メールがパイプラインを流れる**ようになり、
モックに依存しない解析経路が確立した。LLM 未配線でも BEC が動くよう
`BecDetector::deterministic_only()` (`NullLlm`) を追加し、**LLM という要件自体を削除**した
(10 シグナルファミリーのうち 9 つはモデル不要の決定論的ロジックであるため)。

その後 `mock_emails()` は**完全に削除**した (PR #64)。受信箱タブはサーバ未接続を
正直に表示して空を返し、実データを扱うのは「ファイル解析」タブのみである。
製品内に偽データを返す経路は存在しない。

### 2026-07 の是正 (部分的)
- 実装済みだが `invoke_handler` 未登録で**到達不能だった arxiv 防御コマンド10件**
  (入力スクリーニング/出力監査/Tiered-Risk/メモリ信頼/Rule of Two/引数検証/
  トラジェクトリ/OOBV推奨/Deepfake判定) を登録し、実際に呼び出せるようにした。
- UI が呼ぶが未定義だった5コマンド (`mail_send`/`mail_get_mailboxes`/
  `mail_query_emails`/`bec_get_score`/`settings_save_onboarding`) を、
  **明示的な「未配線」エラーを返す実装**として追加 (偽データは返さない)。
  これにより Inbox が起動時に無言で永久に空になる問題が、原因表示に変わった。

---

## 実装済み機能 (ライブラリとして実装 + 実テストで検証済み)

> ✅ = 出荷バイナリに組み込み済みで「ファイル解析」タブから実際に動作する
> ⬜ = ライブラリとしては動作するが、まだ製品に組み付けられていない

| 機能 | クレート | 備考 |
|---|---|---|
| BEC 多信号検出 (認証/ドメイン/履歴/内容/AiTM/Reply-To/スレッド乗っ取り/口座差替/DKIM検証) | `kaname-bec` | ✅ 組込済 / 110+ テスト |
| DLP 12分類器 + 宛先ミス検出 (誤送信防止) | `kaname-dlp` | ✅ 組込済 (Inbound) / チェックディジット検証 (Luhn/マイナンバー/IBAN/法人番号/BIC) |
| ホモグリフ/タイポスクワット/IDN Punycode検出 | `kaname-bec` | ✅ 組込済 | |
| Quishing・カレンダー招待(.ics)・HTMLスマグリング検出 | `kaname-render` | ✅ 組込済 | |
| SaaSリンク安全性・OAuth state検証 | `kaname-saas-guard` | ✅ 組込済 (本文リンクに適用) | |
| Dual-LLM 型境界の**定義** (`Content<Untrusted>`/`Bridge`) | `kaname-ai::dual_llm` | フィールド private・`Content<Trusted>` の公開コンストラクタは2つのみ・Bridge 昇格路は `pub(crate)`・`unsafe` ゼロ・`compile_fail` テスト有り。**ただし (a) trait を実装するコードが 0 件で実推論経路 `llm_bridge` は生 `&str` API、(b) `as_text()` が `pub` で規約依存、(c) serde derive により `Content<Trusted>` を JSON 偽造可能。したがって「型で強制」は現状**未達**。詳細は gap-analysis D17 |
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
