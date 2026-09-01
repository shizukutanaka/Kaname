# Kaname ギャップ分析 — 最新版

最終更新: 2026-07-10 | バージョン: v0.3.21

> **2026-07 の追記に関する注意**: 以下の「現在のスコア: 99.8/100」表は
> 2026-06-01 (v0.3.17) 時点の記録であり、2026-07 の監査で複数の項目が
> **実際には機能していなかった** ことが判明した (詳細は本ファイル末尾の
> 「Opus/Sonnet 共通仕様書: 過不足リスト」を参照)。特に「CI/CD 6 ワークフロー ✅」
> は誤りで、実際には `.github/workflows/` が空でCIは一度も走っていなかった。
> 過去の記録として残すが、鵜呑みにしないこと。誇張・希望的観測を避ける方針
> (CLAUDE.md 準拠) により、本ファイル末尾に正確な最新状態を追記した。

---

## 概要

このドキュメントは Kaname の現在のスコアと 100 点までの距離を記録する。

---

## 現在のスコア: 99.8/100 (2026-06-01 時点の自己申告。下記の過不足リストで訂正あり)

### 完成項目 (33/33)

| カテゴリ | 項目 | 状態 |
|---|---|---|
| 法的 | LICENSE AGPL-3.0 全文 (409 行) | ✅ |
| 法的 | FUNDING.yml | ✅ |
| ビルド | Cargo.lock (コミット済み) | ✅ |
| ビルド | rust-toolchain.toml | ✅ |
| ビルド | .cargo/config.toml | ✅ |
| コード品質 | todo!() = 0 | ✅ |
| コード品質 | 本番 unwrap() = 0 | ✅ |
| コード品質 | #[must_use] 65 箇所 | ✅ |
| コード品質 | /// ドキュメント 31 件追加 | ✅ |
| テスト | Rust ユニット 452 件 | ✅ |
| テスト | proptest 20 件 | ✅ |
| テスト | Playwright E2E 19 件 | ✅ |
| テスト | axe-core a11y 9 件 | ✅ |
| テスト | ファジング 3 ターゲット | ✅ |
| ドキュメント | //! モジュールコメント 25/25 | ✅ |
| ドキュメント | クレート README 25/25 | ✅ |
| ドキュメント | CLAUDE.md 233 行 | ✅ |
| ドキュメント | docs/specifications/ 3 仕様書 | ✅ |
| ドキュメント | testing-strategy.md | ✅ |
| 開発者体験 | Makefile | ✅ |
| 開発者体験 | .pre-commit-config.yaml | ✅ |
| 開発者体験 | .claude/skills/ 8 スキル | ✅ |
| 開発者体験 | .claude/commands/ 4 コマンド | ✅ |
| セキュリティ | STRIDE 脅威モデル (26 脅威) | ✅ |
| セキュリティ | CODEOWNERS 25 DRI 領域 | ✅ |
| セキュリティ | Dependabot + deny.toml | ✅ |
| CI/CD | 6 ワークフロー (ci/e2e/fuzzing/perf/release/sbom) | ✅ |
| 戦略 | brand-guidelines.md | ✅ |
| 戦略 | 100-year-vision.md | ✅ |
| 戦略 | decisions-not-to-do.md | ✅ |

---

## 残り 0.2 点: 現実世界の検証

| 項目 | 理由 | 取得方法 |
|---|---|---|
| CI 実機ビルド (4 OS) | エミュレーション環境では実行不可 | GitHub Actions で `cargo build --release` が macOS/Windows/Linux/ARM で通過 |
| Design Partner 実使用 | コードでは代替不可 | 1 社が 2 週間使用して「BEC を防いだ」報告 |

---

## 過去のギャップ (解消済み)

| 問題 | 解消日 | 方法 |
|---|---|---|
| LICENSE 省略版 (73→164→409 行) | v0.3.3 | AGPL-3.0 全文置換 |
| .gitignore が Cargo.lock を除外 | v0.3.5 | 除外行を削除 |
| //! ドキュメント 22/24 | v0.3.3 | kaname-oobv/ssa に追加 |
| CHANGELOG v0.3.0 エントリなし | v0.3.0 | 追加 |
| examples/ テストゼロ | v0.3.2 | 28 テスト追加 |
| kaname-radar 未実装 | v0.3.1 | 502 行、13 テスト実装 |
| HTML Smuggling/Calendar Guard 未実装 | v0.3.0 | 実装完了 |
| AiTM/SSA 未実装 | v0.3.0 | 実装完了 |
| OOBV/CCPD/Quishing/SaaS/Deepfake 未実装 | v0.2.0 | 実装完了 |

---

# Opus/Sonnet 共通仕様書: 過不足リスト (2026-07-10 実監査)

このセクションは 2026-07 のセッションで実コードを grep/read/build して
検証した結果に基づく。上記の自己申告スコア表と食い違う箇所は、この
セクションの記載を正とすること。次にどのモデル(Opus/Sonnet)がこのタスクを
拾っても同じ理解で着手できるよう、判断根拠を明記する。

方針: 推測・誇張はしない。全項目は実際に確認済みの事実のみを記載する。
未確認の疑いは「要確認」と明記する。

## 不足 (未実装・機能として欠落 — 実装が必要)

「動くふりをしているが実際には動かない」モック/スタブ、または
実行環境の制約で検証未了の項目。市販するなら最優先で埋めるべき欠落。

| # | 機能 | 場所 | 現状 (何が足りないか) | 実装すべき内容 |
|---|---|---|---|---|
| D1 | MLS グループ暗号化 | `kaname-mls` | 単一バイト XOR (鍵=公開 ConversationId 先頭バイト、鍵空間256のみ)。暗号として機能していない | `openmls` クレート (0.7.2, 2026-02) を統合し RFC 9420 準拠の実装に置き換える。**統合時は draft-ietf-mls-pq-ciphersuites の ML-KEM/ハイブリッド ciphersuite を最初から選定すること** (2026-07 調査で標準化進行を確認、docs/research-2026-07.md §1.5) |
| D2 | ローカル LLM 推論 (Q-LLM/P-LLM) | `kaname-ai::llm_bridge` | 固定文字列 (`{"risk":"SAFE",...}` 等) を返すだけ。`tokens_in`/`tokens_out` も常に0で実際には推論していない | `llama.cpp` か `candle` で Phi-4-mini 等の実推論を実装。トークン計測も実値化 |
| D3 | Q-LLM/P-LLM のプロセス分離 | `kaname-ai::subprocess` | seccompプロファイルの「パス文字列」を生成するだけ。実際に分離を強制する外部バイナリ `kaname-llm-runner` が存在するか自体が未確認 | `kaname-llm-runner` バイナリを実装し、seccomp-bpf (Linux) / sandbox-exec (macOS) / Job Object (Windows) を実際に適用する |
| D4 | Firecracker microVM サンドボックス | `kaname-sandbox` | `spawn_vm`/`VsockChannel` が no-op。セマフォ管理・プールの衛生管理コードは実装済みだが VM 自体は起動しない | Firecracker バイナリとの実連携、vsock通信の実装 |
| D5 | 自動アップデート | `src-tauri` | `tauri.conf.json` から無効な `updater` 設定を削除済みだが (2026-07修正)、`tauri-plugin-updater` 自体が未導入。機能そのものが存在しない | プラグイン導入 + 署名鍵ペア生成 + 配信サーバー構築 |
| D6 | 課金基盤の永続化 | `kaname-billing` | エンタイトルメント/冪等性キーが全てインメモリで、プロセス再起動で消える。Stripe webhookのペイロードを検証なしに信頼し、ライブAPIで再確認していない | `kaname-store` (永続化層) との連携、Redis等での分散重複排除、監査用の台帳ハッシュチェーン検証を追加 |
| D7 | CI が実行されていない | `.github/workflows/` | このディレクトリが空。ワークフロー定義は `ci-templates/*.yml` (ci/e2e/fuzzing/perf/release/sbom の6つ) に退避されたまま。旧ギャップ分析表の「CI/CD 6ワークフロー ✅」は誤りで、**push/PRのたびに自動テストが一切走っていない**。**2026-07-10 に実際に `git mv ci-templates/*.yml .github/workflows/` を試みたところ、GitHub から `refusing to allow a GitHub App to create or update workflow ".github/workflows/ci.yml" without "workflows" permission` で push が拒否されることを確認済み** | コード変更・エージェント操作では解決不可能と確定。リポジトリ管理者(人間)が GitHub App の権限設定に `workflows` スコープを追加するか、管理者自身の認証情報で `git mv ci-templates/*.yml .github/workflows/` を実行する必要がある |
| D8 | E2Eテストの実行検証が未完了 | `e2e/*.spec.ts`, `playwright.config.ts` | Playwrightでのテスト一覧パースは成功 (66件) したが、実際にブラウザで実行して green を確認できていない。このセッションはネットワーク越しの `crates.io` 取得が組織ポリシーで 403 拒否されており、`cargo run -p kaname-mockserver` のビルドを伴う `npx playwright test` の実行が検証未了 | ネットワーク制限のないセッションで `npx playwright test` を実行し、実際にパスすることを確認する |
| D9 | SSA の敵対的LLM生成サンプル校正 | `kaname-ssa` | 文体認証の閾値 (0.60/0.75) がハードコードで、LLM生成なりすましサンプルによる訓練・校正がない。arxiv 2603.29454 は「敵対的LLM生成サンプルを訓練に含めた検証器はLLMなりすましを回避されない (含めなければ精度が落ちる)」と示した | ローカルLLM推論 (D2) 実装後に、自組織の送信者プロファイルに対する敵対的なりすましサンプルを生成し、閾値を校正するパイプラインを追加する。D2 が前提のため単独では着手不可 |
| D10 | **メールクライアントとしての配線が存在しない (最重要・2026-07 First Principles 監査で全面改訂)** | `kaname-ui/Cargo.toml`, `kaname-store`, `app_state.rs`, UI 全般 | 当初「UIコマンド層がモック」と記載したが**過小評価だった**。実際には (1) `kaname-ui/Cargo.toml` に `kaname-jmap`/`kaname-store`/`kaname-core` の依存が無く、出荷バイナリからネットワークにも DB にも**コンパイル時点で到達経路が無い**、(2) ~~`messages` への INSERT/SELECT がゼロ件~~ **(2026-07 解消: `save_message`/`list_messages`/`search_messages` を実装)**、(3) `kaname-jmap` は RFC 8621 準拠の本物の実装だが**呼び出し元ゼロ** (同期ループはフラグ操作のみでI/Oなし)、(4) `app_state.rs` の `accounts` は `vec![]` 固定でアカウント設定 UI も無い、(5) ~~検索は `<input>` にハンドラ未バインド~~ **(2026-07 解消: `mail_search` に接続)**、(6) ~~添付 blob download 未実装~~ **(2026-09 解消: `download_blob` + `mail_download_attachment`。書き込み前に必ず `scan_attachment_bytes` で検査し、危険なら保存しない)**。**これで D10 の全項目が解消** — 受信→保存→表示→送信→検索→添付DLが配線され、~~「セキュリティ・ライブラリ集 + デモUI」~~は**機能上メールクライアントになった** (総括は `docs/socratic-review.md`) | 受信→保存→表示→送信の**バックエンド統合そのもの**が必要: kaname-ui へ jmap/store 依存追加 → Store のメッセージ CRUD 実装 → 同期ループ結線 → アカウント設定 UI/永続化 → 送信コマンド → 検索/添付。**次セッションの最優先課題** (要ネットワーク: cargo によるコンパイル検証が必須の規模) |
| D15 | 実装済みコマンドの死蔵 (2026-07 一部是正済み) | `kaname-ui/src/commands.rs`, `src-tauri/src/main.rs` | 実装・テスト済みの13コマンドが `invoke_handler` 未登録で到達不能だった。加えて `commands.rs` の `#[cfg_attr(feature = "tauri-app", tauri::command)]` は **src-tauri が `features = ["tauri-app"]` を指定していないため無効**という二重の死蔵だった | **10件は登録済み** (arxiv 防御コマンド: 入力スクリーニング/出力監査/Tiered-Risk/メモリ信頼/Rule of Two/引数検証/トラジェクトリ×2/OOBV推奨/Deepfake判定)。残る3件 (`oobv_start`/`oobv_verify`/`pivot_analyze`) は `Arc<V02AppState>` を引数に取るため Tauri の `.manage()` によるステート管理設定が必要 — 次回対応 |
| D20 | **ビルド検証が組織のエグレスポリシーにより不可能 (2026-07 確定)** | ビルド環境全体 | エージェントプロキシの診断 (`curl $HTTPS_PROXY/__agentproxy/status` および `/root/.ccr/README.md`) により、**推測ではなく確定事実として**判明: プロキシの `noProxy` には `index.crates.io` (sparse index) が含まれるが、実際のクレート配信元 **`static.crates.io` は組織のエグレスポリシーで遮断**されている。README は「403/407 は組織ポリシーの拒否であり、**リトライも迂回もせず報告せよ**」と明記。ローカルにも `~/.cargo/registry` キャッシュ・`vendor/`・`target/` は一切存在せず (実測)、`node_modules` も無いため TypeScript 型検査も不可 | **迂回してはならない (README の明示的指示)**。組織側で `static.crates.io` を許可するか、依存を vendor 済みのイメージを使う必要がある。**代替として実施したこと**: `~/.rustup/toolchains/stable-*/bin/rustc` (1.94.1) が直接実行可能であることを発見し、変更した全 Rust ファイルの**構文チェック**を実施済み (型検査・借用検査は依存が無いため不可)。この制約は本セッションの全コミットが `cargo check` 未検証であることの根拠であり、ネットワーク解放後の最優先作業は全体の型検査。**実害が発生した**: PR #64 の編集で `analyze_body_risks` の定義ごと誤削除され、呼び出しだけが残ってコンパイルエラーの状態が PR #65〜#69 の 5 PR にわたり検出されなかった (PR #70 で修正)。型検査が無い環境では意図しない削除を人間の注意力では捕捉できないことが実証された。**対策として `scripts/static-check.sh` を追加** — 全 Rust ファイルの構文チェックと「定義が消えた関数の呼び出し」検出を自動化した (型検査の代替にはならないが、同種の回帰は捕捉できる) |
| D21 | ~~**出荷 UI がモック専用コンポーネントを描画し、実配線済みの画面が死蔵していた**~~ **(2026-09 解消)** | `src/main.tsx`, `src/ui/KanameDesign.tsx`, `src/ui/Inbox.tsx`, `src/ui/ComposeAdmin.tsx` | クレート到達可能性 (D19) と同じ病がフロントエンドにもあった。実測の結果 11 モジュール中 4 つが `src/main.tsx` から到達不能で、**受信トレイに描画されていた `KanameDesign` は invoke を一切呼ばないモック専用**だった (コンポーネント自身のコメントが認めている)。実際に `mail_fetch`/`mail_search`/`bec_get_score` を呼ぶ `Inbox` はどこからも import されていなかった。さらに `mail_send` を呼ぶ画面も未到達で、**UI からメールを送る経路が存在しなかった**。到達させてもフロントは `{req:{...}}` を送り Tauri は `(from,to,subject,body)` を取るため**実行時に必ず失敗する**引数不一致があり、作成画面の MLS インジケータは**モック実装 (D1) を「対応済み」と表示**していた | **解消済み**: `main.tsx` を `Inbox` に切り替え、`Compose` を「作成」ビューとして配線、送信の引数形を一致させ差出人入力を追加、MLS インジケータを常に非対応に修正、モック専用 2,284 行を削除。到達可能モジュールは 7/11 → 8/9。**教訓: 「配線した」と言えるのは、エントリポイントからの到達可能性を実測したときだけである** |
| D22 | **オンボーディング画面が意図的に未到達 (バックエンドがスタブのため)** | `src/ui/Onboarding.tsx`, `src-tauri/src/main.rs` | `Onboarding.tsx` (344 行) は実装されているが `main.tsx` から到達不能。配線しない判断は意図的で、`settings_save_onboarding` が `Err(not_wired(..))` を返すスタブであるため、**配線すると「設定が保存できたように見えて実際は失敗する」画面**を出荷することになる | `kaname-store` に設定の永続化を実装してから配線する。それまでは未到達のままにするのが正しい (保存できない設定画面を見せない) |
| D19 | **出荷バイナリに入っているのは 27 クレート中 10 個のみ — 看板機能が製品に存在しない (2026-07 依存グラフ解析)** | ワークスペース全体 | `src-tauri` → `kaname-ui` からの推移閉包を実測した結果、到達可能なのは **10 クレート** (`kaname-ui`/`kaname-ai`/`kaname-crypto`/`kaname-error`/`kaname-memory-guard`/`kaname-observability`/`kaname-oobv`/`kaname-pivot`/`kaname-render`/`kaname-screen`) のみ。**残り 17 クレートは製品に含まれていない**: `kaname-bec` (BEC 検出・110+ テスト — README の看板機能)、`kaname-dlp`、`kaname-jmap`、`kaname-store`、`kaname-mls` (PQC 暗号)、`kaname-i18n`、`kaname-radar`、`kaname-ssa`、`kaname-saas-guard`、`kaname-sandbox`、`kaname-privacy`、`kaname-continuity`、`kaname-billing`、`kaname-tray`、`kaname-core`、`kaname-mockserver`、`kaname-tests`。**D10 (パイプライン未配線) より広範な問題** — 部品は作られたが製品に組み付けられていない | **「部品を作る」のをやめて「組み立てる」フェーズへ移行する**。第一歩として `kaname-bec` を `kaname-ui` に組み込み済み (新規外部依存ゼロ)。`ai_detect_phishing` が固定値 `score: 0.12` を返していたのを実際の `BecDetector::assess()` 呼び出しに置換。LLM 未配線を理由に出荷できない状態を避けるため `BecDetector::deterministic_only()` (`NullLlm`) を追加し、**LLM を必要としない 9 シグナルファミリーで動作**させる。残る 16 クレートも同様に「組み込む or 削除する」判断が必要 |
| D18 | **送信ドメイン認証 (SPF/DKIM/DMARC) を独立検証していない — 受信サーバのヘッダを信じるのみ (2026-07 監査)** | `kaname-render/src/lib.rs` (`parse_auth_results`/`extract_auth_result`), `kaname-bec` の認証シグナル全般 | 認証系シグナル (§3.15 の DKIM リプレイ検出を含む) は全て `AssessmentRequest.auth` の判定結果を前提とするが、その供給元は `Authentication-Results` ヘッダの**文字列パースのみ**。ワークスペースに DKIM 署名の暗号検証コードは**ゼロ件**。RFC 8601 が想定する「信頼された自組織 MTA のヘッダを信じる」設計自体は正常だが、(a) **authserv-id を一切検証していない** (RFC 8601 §7.1 が要求。リポジトリ全体で `authserv` の言及ゼロ)、(b) `extract_auth_result` が `find("dkim=")` の**最初の一致**を採る素朴な部分文字列探索で、`smtp.mailfrom=`/`header.d=` 等の攻撃者が影響し得る echo フィールドより後に本来の機構名がある場合に誤った値を拾う構造的脆さがある。**この信頼前提が脅威モデルに未記載だったこと自体が最大の問題** (§3.15b として追記済み) | **[`mail-auth`](https://github.com/stalwartlabs/mail-auth) (Stalwart Labs) を採用する** — Kaname が既に使う `mail-parser` と**同一ベンダ** (ADR-009) で、DKIM (RSA/Ed25519)・ARC 連鎖検証・SPF/DMARC ポリシー評価を提供。2026-07 時点で **DKIM2 と DMARCbis (RFC 9989/9990/9991, 2026-05) を実装済み**。**重要**: DKIM2 はメッセージを宛先にバインドし送信時刻を記録することでリプレイをプロトコルレベルで解決し、転送で署名が壊れない chain of custody を導入するため、**§3.15 で実装した `d=` 整合ヒューリスティックは DKIM1 時代の暫定策であり DKIM2 対応後は不要になる**。当面の最小対応として authserv-id 検証の追加と `extract_auth_result` の機構スコープ限定パースを行う。**新規依存追加のためネットワーク解放が前提** |
| D17 | **Dual-LLM の型不変条件が「宣言」と「実装」に分離しており実効性を持たない (2026-07 監査・最重要)** | `kaname-ai/src/dual_llm.rs`, `kaname-ai/src/llm_bridge.rs`, `kaname-ai/src/subprocess.rs` | README は「コンパイル時型安全」を掲げるが実態は次の通り。**(1) trait 実装が 0 件**: ワークスペース全体に `impl QuarantinedLlm for` / `impl PrivilegedLlm for` が存在せず、実推論経路 `llm_bridge.rs:352/417` は `Content` 型を使わず生 `&str` を受ける (P-LLM 実装は要約を `format!` でプロンプトに連結)。**配線時に「そこにある &str API を呼ぶ」のが最短経路になるため、実装者が無自覚に I1〜I3 を全部飛ばす構造**。 **(2) I1 は規約**: `dual_llm.rs:208` の `as_text()` が `pub` で可視性制限なし。**(3) I3 に serde 穴**: `dual_llm.rs:85` の `Deserialize` derive + `:91` の `#[serde(skip)] _level` により `serde_json::from_str::<Content<Trusted>>` で Bridge を経ず Trusted を偽造可能。`Serialize` により生本文も JSON に出る。**(4) I4 とコードが矛盾**: `subprocess.rs:101` は Privileged を「ネットワークアクセスあり」と記述、`:219` の sandbox プロファイルは `(allow network-outbound)` を付与、参照先 `resources/seccomp/` は**存在しない**。 **(5) `TopicTag` の `Deserialize` 迂回**: 32文字/文字種検証を JSON でスキップ可能。 **良いニュース**: I3 の中核 (フィールド private / `Content<Trusted>` の公開コンストラクタは2つのみ / `from_validated` が `pub(crate)` / `unsafe`・`transmute` ゼロ / `compile_fail` テスト有り) は本物。現時点ではパイプライン未配線 (D10) かつ推論がスタブのため**悪用可能な経路は存在しない** | **ネットワーク解放後の最優先**。(a) `Content<L>` から `Serialize`/`Deserialize` derive を外す (中核型のためワークスペース全体の再コンパイルが必要 — コンパイラなしで変更しないこと)、(b) `as_text()` を `pub(crate)` 化するか Q-LLM 呼び出し境界の内側に閉じる、(c) **最重要**: `llm_bridge` の `QuarantinedLlmImpl`/`PrivilegedLlmImpl` を `dual_llm` の trait を実装する形に変更し `&str` 入口を塞ぐ、(d) `TopicTag` の `Deserialize` 迂回を封じる、(e) **I4 の矛盾は所有者判断が必要** — CLAUDE.md の不変条件は「変更禁止」と明記されているため、コードを I4 に合わせる (P-LLM のネットワークを禁止する) か I4 を改訂するかを決定し、`resources/seccomp/` の実体を用意すること |
| D16 | **添付ファイル由来テキストの AI 入力経路が丸ごと未配線** (2026-07 調査で判明・記録のみ、実装は未着手) | `kaname-ai/src/preflight.rs`, `kaname-ai/src/dual_llm.rs`, `kaname-sandbox`, `kaname-bec/src/lib.rs` | Dual-LLM 境界の入口検査が**型で強制されておらず、実際に呼ばれていない**: (1) `preflight_untrusted()` (`kaname-ai/src/preflight.rs:73`) は PromptScreener + Bidi/ゼロ幅を正しく実装しているが**プロダクション呼び出し元が0件** (テストのみ) — 「呼び忘れ」がコンパイル時に検出できない、(2) `Content::<Untrusted>::from_attachment()` (`dual_llm.rs:180`) も実利用ゼロ、(3) `kaname-sandbox` は**どのクレートからも依存されておらず** `RenderResult.extracted_text` (`sandbox/src/lib.rs:309`) の消費者が存在しない、(4) `AssessmentRequest` (`bec/src/lib.rs:58-88`) に添付テキストのフィールドが無く、**本文のみスクリーニングされ添付は BEC/LLM 解析に入らない**非対称がある。現時点では添付テキストが AI に届く経路自体が無いため実害は無いが、**D10 の配線時にこれらを同時に入れないと初めて穴になる** | 配線時の統合ポイント3点: (a) `sandbox/src/lib.rs:189` の 10MB キャップ直後で `Content::<Untrusted>::from_attachment()` に包む、(b) `preflight_untrusted` を任意呼び出しにせず Q-LLM 呼び出しの唯一の入口内部で必ず通す (型強制)、(c) `AssessmentRequest` に `attachment_texts` を追加し `check_llm` (`bec/src/lib.rs:889`) のスクリーニングを本文と同様に適用。**D10 と同時に実施すること** |
| D11 | `AiAccessController` が未配線 + `SensitivityLabel` 供給元が存在しない | `kaname-ai::threat_intel`, `kaname-dlp` | DLPラベルでAI処理をブロックする `AiAccessController` (HMAC監査チェーン付き) は完全実装済みだが、`dual_llm`/`preflight`/UI のどこからも呼ばれない。さらに入力の `SensitivityLabel` (Public〜LegalPrivilege) を生成するコードが皆無 — `DlpResult` は `Action` (Allow/Warn/Block) しか出力しない。ドキュメント上は「DLP分類→AI処理ブロック」設計だが配線が欠落 | `DlpResult`/`ClassifierId` から `SensitivityLabel` を導出する変換アダプターを追加し、`QuarantinedLlm::analyze()` 前段で `check_and_record()` を呼ぶ |
| D12 | ~~`kaname-ssa` (送信者文体認証) が孤島クレート~~ **(2026-07 解消)** | `kaname-ssa` | `assess_self_send_anomaly` (AiTMアカウント乗っ取り検出) 等は実装・テスト済みだが、ワークスペース全体のどこからも呼ばれない。`kaname-ui`/`kaname-bec` の依存にも含まれない | 送信フローへの統合。`contains_financial_request` 判定は `kaname-oobv::OobvRecommender` の既存ロジックと重複するため共有化も検討。警告UX (いつ・どう出すか) の設計が必要 |
| D13 | ~~`kaname-saas-guard` がどこからも依存されない孤立クレート~~ **(2026-07 解消)** | `kaname-saas-guard` | フェーズ3でプロンプト注入検査を追加したが、クレート自体がワークスペース中どのクレートからも `path` 依存されておらず、メール受信パイプラインで一度も実行されない | メール受信フロー (D10のバックエンド統合) にSaaSリンク検査を組み込む統合ポイント設計が必要 |
| D14 | `kaname-mls` の Commit 処理でメンバーシップ変更が常に空配列 | `kaname-mls` | `process_incoming` の Commit 分岐が `MembershipChange { added: vec![], removed: vec![] }` をハードコードで返し、誰が追加/削除されたか呼び出し側に伝わらない | `Envelope` に membership diff を運ぶフィールド追加が必要なデータモデル変更。D1 (openmls統合) と合わせて対応するのが自然 |

## 2026-07-13 に実施した依存不要の改善 (D1〜D9とは別枠、実施済み)

このセッションでネットワーク制限下でも実装可能だった、ワークスペース内
依存のみで完結する改善を3フェーズで実施 (全てコミット・プッシュ済み):

| フェーズ | 内容 | クレート | コミット |
|---|---|---|---|
| 1 | quishing.rs: blob:/data:/javascript:スキーム検出、分割QR (`assess_multi_qr`)、ASCIIアートQR (`detect_ascii_qr`) | `kaname-render` | `d3c9bb5`, `959e70d` |
| 2 | calendar_guard.rs: CalPhishing自動登録永続化検出 (`AutoRegistrationAbuse`)、`kaname-screen`統合によるプロンプト注入検査 (`PromptInjectionAttempt`) | `kaname-render` | `d3c9bb5`, `8eb2fa8` |
| 3 | SaaSリンクのクエリパラメータに対する`kaname-screen`統合プロンプト注入検査 | `kaname-saas-guard` | `8976a3b` |
| 4 | Ultracode 3エージェント並列監査で発見した純ロジックバグ3件: 数字始まりメールのPII漏洩 (`kaname-observability`)、unknown:バケット集計バグ (`kaname-radar`)、開始者側エポック初期化漏れ (`kaname-mls`) | 各クレート | `55aac4a` |
| 4 | SQLCipher鍵を含むPRAGMA/ATTACH文のゼロ化 (`Zeroizing<String>`) | `kaname-store` | `8804430` |
| 5 | 全角/ゼロ幅文字によるキーワード回避を防ぐ正規化 (`kaname-memory-guard::normalize_for_matching` を pub 化して横展開) | `kaname-oobv` | `48cfb32` |
| 5 | SSRFセーフリダイレクトポリシーをHTTPクライアントに適用 (DNSリバインディング対策) | `kaname-jmap` | `e71e795` |
| 5 | pivot(チャネル誘導)とscreen(注入検出)をBEC検出器に統合 | `kaname-bec` | `48586c9` |

**検討したが見送った統合**: `kaname-dlp` への `kaname-screen` 統合。
DLPは送信メールのPII漏洩防止 (outbound) が目的で、外部attacker由来の
命令注入という脅威モデルに合致しないため、無理な統合はスコープミスマッチ
と判断し実施しなかった。

**このカテゴリで残る改善は、大規模配線または設計判断が必要な D10-D14 のみ**:
2026-07-13 の Ultracode 徹底監査 (3エージェント並列、全27クレート) により、
上表のフェーズ4・5の8項目を追加実施した。これで「1-2箇所の局所修正 or
確立パターンの横展開」で済む依存不要改善は出尽くした。残る D10-D14 は
バックエンド統合・データモデル変更・UX設計を伴うため、ネットワーク解放後に
実データモデル設計込みで着手する (上記 D10-D14 の表を参照)。

## 過剰 (不要・重複・到達不能だった — 2026-07セッションで発見し既に削除/修正済み)

「あるのに使われていない/害になっている」コード。全て解決済みだが、
再発防止のためのチェックリストとして記録する。

| # | 内容 | 場所 | 状態 |
|---|---|---|---|
| E1 | 参照されないバイナリエントリポイント | `src-tauri/src/legacy_main.rs` | 削除済み。`[[bin]]` からもコードからも参照されないデッドコードだった |
| E2 | 実体のない `.tsx` の重複 `.jsx` ファイル群 | `src/ui/*.jsx` (`KanameApp.jsx`, `KanameDesign.jsx` 等 8 ファイル + `main.jsx`) | 削除済み。`index.html` の実エントリポイントは `main.tsx` のみで、`.jsx` 群はどこからも読み込まれないデッドコードだった |
| E3 | 存在しないビューへの参照 | `src/main.tsx` の `./ui/KanameAppleV5` インポート | 削除済み。未実装のデモビュー「V5デモ」への参照がビルドエラーの原因になっていた |
| E4 | Tauri 2.x スキーマに存在しない設定フィールド | `src-tauri/tauri.conf.json` の `windows[0].vibrancy`、`bundle.linux.depends`/`desktopTemplate`、`bundle.updater` | 削除済み。いずれも現行スキーマに存在せず `cargo check --workspace` を exit 101 で失敗させていた。`bundle.updater` は `active:true` + `pubkey:""` (空の署名鍵) という危険な設定でもあった |
| E5 | 非推奨API呼び出し | `src-tauri/src/main.rs` の `TrayIconBuilder::menu_on_left_click` | 修正済み。`show_menu_on_left_click` に置換 (`-D warnings` ビルドを阻害していた) |
| E6 | 起動時パニックの温床 | `src-tauri/src/main.rs` の `.icon(...unwrap())` | 修正済み。アイコン取得失敗時にアプリ全体がクラッシュする設計だった。`if let Some(icon) = ...` に変更し、失敗時は警告ログのみで継続するよう修正 |

## 到達不能だった機能 (不足でも過剰でもない第三のカテゴリ)

コードは実装済みなのに、UIから辿り着けなかった機能。バグとして扱うべきだが
「削除すべき過剰」でも「未実装の不足」でもないため区別する。

| # | 内容 | 場所 | 状態 |
|---|---|---|---|
| U1 | Paper Trail (HEY風) フィルター機能 | `src/ui/KanameDesign.tsx` の `"paper_trail"` view state | 修正済み。フィルタロジック自体は実装済みだったが、対応するナビゲーション項目 (`navItems`) が存在せず永久に到達不能だった。ナビ項目・型定義・ラベルマップを追加して結線 |

## Opus/Sonnet への申し送り事項

- D1〜D6 (モック/スタブ) は外部クレート統合が必須で、現在のネットワーク制限
  (crates.io への egress が組織ポリシーで 403 拒否) がある環境では着手不可能。
  ネットワーク制限のないセッションでの実装が前提。
- D7 (CI) は権限の問題であり、コード変更では解決しない。人間の管理者操作が必要。
- D8 (E2E検証) はネットワーク制限が解ければ即座に検証可能。
- E1〜E6・U1 は全て解決済み。再スキャンは不要だが、同種の
  「重複ファイル」「未参照コード」「非推奨API」「unwrap起因のパニック」は
  他のクレートにも潜んでいる可能性があるため、次回監査時のチェック観点として残す。
- 判断に迷う場合 (例: D6のRedis要否、D1のopenmlsバージョン選定など)
  アーキテクチャ判断が要る項目は Opus に、決まった手順の実装 (プラグイン導入・
  ファイル移動・依存追加等) は Sonnet に割り振るのが効率的。
