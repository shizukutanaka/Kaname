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
| D24 | **登録済みコマンド 37 件のうち 19 件が UI から呼ばれない (2026-09 検査5 で自動検出)** | `src-tauri/src/main.rs`, `src/ui/*` | D21 の**鏡像**。「UI が呼ぶ先はすべて実装」は達成したが、逆方向は未達で、実装済みコマンドの半数に到達経路が無い。内訳: ~~**(a) LLM 依存で意図的に未配線 (10)** — `ai_smart_reply`/`ai_summarize_email`/`audit_ai_output`/`check_action_risk`/`check_memory_trust`/`check_rule_of_two`/`validate_tool_argument`/`record_agent_step`/`reset_trajectory`/`screen_user_input`。LLM 推論がスタブ (D2) の現状で配線すると**偽の AI 出力を表示する**ため配線しないのが正しい。~~ **この分類も一部誤りだった (2026-09 訂正、D30)**: 実際に LLM 生成を必要とするのは `ai_smart_reply`/`ai_summarize_email` の**2件のみ**で、両方とも「未実装」を明示するエラーを正しく返している。残り8件 (`audit_ai_output`/`check_action_risk`/`check_memory_trust`/`check_rule_of_two`/`validate_tool_argument`/`record_agent_step`/`reset_trajectory`/`screen_user_input`) は **LLM 生成そのものではなく、LLM 呼び出しの前後に置く決定論的な防衛策** (入力スクリーニング・出力監査・Tiered-Risk アクセス制御・Rule of Two・引数検証・メモリ信頼スコア・トラジェクトリ記録) であり、`kaname-ai::llm_bridge` や `QuarantinedLlm`/`PrivilegedLlm` を一切呼んでいない。「配線すると偽のAI出力を表示する」という理由は成り立たない。**ただし配線しない判断自体は正しい**: `kaname-ui/src/commands.rs` を検索した限り、防衛すべき実際の LLM 呼び出し経路が製品内に一つも無いため (D2)、今これらを UI に繋いでも守るものが無い「先出しの防具」になるだけである。**(b) 配線すべき (5)** — ~~`mail_download_attachment`~~・~~`mail_trash`~~ **(2026-09 解消: 受信トレイ詳細パネルにツールバーと添付ダウンロードボタンを追加)**、`oobv_recommend`、`deepfake_evaluate`、`history_mark_verified`。~~**(c) 内部 API として正当 (4)** — `history_open`/`history_close` (起動時は `history_open_default` を使う)、`settings_get`/`settings_set` (他コマンドから使用)~~ **この分類は誤りだった (2026-09 訂正、D29)**: `settings_get`/`settings_set` は「他コマンドから使用」ではなく、**引数を無視して `Ok(())`/`Ok(None)` を返すだけのスタブで、呼び手も一つも無かった**。検証せずに分類したのが原因。`history_open`/`history_close` の分類は正しい (起動時経路が別に存在する) | (a) のうち `ai_smart_reply`/`ai_summarize_email` の2件は LLM 本実装まで据え置き (配線したら嘘になる)。残り8件は「配線したら嘘になる」からではなく「守るべき LLM 呼び出しが製品内にまだ無いから」据え置く — LLM 本実装と同時に、それを呼ぶ経路の入出力に組み込むのが正しい順序である。(b) は 5 件中 2 件を配線済み。**(b) の 5 件は全件解消**。`history_mark_verified` は 2026-09 に配線済み (詳細パネルの BEC 警告バナーに「本人確認済みにする」ボタンを追加。`account_id` はフロントエンドが持っていなかったため、他コマンドと同様に `current_account_id()` で内部解決するようシグネチャを簡素化した)。`oobv_recommend`・`deepfake_evaluate` の**判定ロジック**も 2026-09 に配線済みだが、**コマンド自体は今も未到達のまま**である: `analyze_raw_email` が本文と添付を既に手元に持っている時点で `OobvRecommender::recommend()` / `DeepfakeAdvisory::evaluate()` を直接呼び、判定結果 (`oobv_level`/`oobv_message`/`deepfake_advisory`) を `ImportedEmail` に埋め込んだ。素の本文・添付一覧をフロントに渡してから往復で判定させるより、露出も往復も増えない。独立コマンドとしての両者は将来の直接呼び出し (例: 作成画面での送信前チェック) に備えたテスト済みの内部 API として残し、静的検査の WARN は「意図して未到達」として許容する。(c) のうち `history_open`/`history_close` は現状維持。`settings_get`/`settings_set` は D29 でスタブから実装に修正したが、呼び出す UI がまだ無いため WARN は残る (これは今回、正直な状態)。**再発防止は自動化済み**: `scripts/static-check.sh` の検査5が WARN として毎回列挙するため、数が増えれば必ず気付く |
| D25 | **`mail_list` 削除 (PR #86) の際、同じ関数をまだ呼んでいたテスト2件がコンパイルエラーのまま残った** | `crates/kaname-ui/src/commands.rs`, `scripts/static-check.sh` | `static-check.sh` の検査2はハードコードされたシンボル一覧 (`analyze_body_risks` 等) しか見ておらず、一覧に無い `mail_list` への参照消失を検出できなかった。D20 (cargo check 不可) が実証されるたびに「一覧を都度足す」運用をしていたが、それ自体が同じ穴を繰り返す設計だった | **解消済み**: 検査2をリポジトリ全体スキャン方式に一般化した (ハードコード一覧を廃止)。一般化の過程で、属性・raw文字列・char リテラル・行末コメント・複数行 `use`・クロージャ束縛を正しく除外できず 70 件超の誤検知が出たため、これらをすべて修正 (詳細はコミットメッセージ)。修正後は誤検知ゼロで、合成的に「削除済み関数への参照」を注入したテストでも正しく検出できることを確認済み。壊れていた2テスト (`mail_list_respects_limit`/`bec_dangerous_in_mock`) はモック実装 (D10 解消で既に削除済みの `mail_list`) を前提にしていたため削除した |
| D26 | **D25 と同じ欠陥クラスのフロントエンド版: `app.test.ts` の `makeEmail()` が削除済み `KanameApp.tsx` の `Email` 型を import せず参照していた** | `src/__tests__/app.test.ts`, `scripts/static-check.sh` | `KanameApp.tsx` 削除 (PR #82) の際、同ファイルからしか import されていなかった `Email` 型への参照が `app.test.ts` に残った。`makeEmail()` はどこからも呼ばれない未使用コードでもあった。`tsc`/`vitest` が動けば型エラーで即発覚するが D20 により実行できず、3セッション気付かれなかった | **解消済み**: `makeEmail()` を削除。再発防止として `static-check.sh` に検査6を追加し、「大文字始まりの識別子が import も同一ファイル内定義も無いまま型位置で使われている」ケースを機械的に検出する。最初の実装は `Partial<Email>` のようなジェネリクス**使用**側まで「ローカル宣言」として誤って許可しており、まさに検出したかったバグを素通りさせていた (合成的な回帰テストで発覚し修正)。ワークスペース全体で誤検知ゼロ、合成回帰で検出できることを確認済み |
| D27 | **CLAUDE.md 不変条件 I6 (「`unwrap()` は本番コードに使用禁止」) が一度も検証されていなかった** | 全クレート、`scripts/static-check.sh` | `#[deny(clippy::unwrap_used)]` で強制する設計だが `clippy` は D20 により実行不可。手動で全ワークスペースを走査した結果、**本番コードでの `.unwrap()` 使用は 0 件**であることを確認した (テストコード `#[cfg(test)] mod` / 個々の `#[test]` 関数を正しく除外した上で)。I6 は現状守られている | **解消済み (検証のみ、コード変更なし)**。再発防止として `static-check.sh` に検査6として自動化し、以後の変更で違反が入れば即座に検出される。合成的に本番コードへ `.unwrap()` を注入して検出されること、テストコード内では誤検知しないことの両方を確認済み |
| D28 | **CLAUDE.md I5 (「ログに PII を含めない」) を守るはずの `PrivacyLayer` が、どの tracing subscriber にも登録されておらず一度も実行されていなかった。さらにコード自体も docstring が主張する「イベントをドロップ」を実装しておらず、警告を追加発行するだけだった (最重要・2026-09 発見)** | `crates/kaname-observability/src/lib.rs` (`PrivacyLayer`), `crates/kaname-ui/src/lib.rs` (`run()`) | `kaname-ui` は `kaname-observability` に依存しているが、実際に import していたのは `trajectory::TrajectoryMonitor` のみ。ロガー初期化 (`kaname_ui::run()`, `src-tauri/main.rs:371` から実際に呼ばれている) は `tracing_subscriber::fmt()...init()` だけで `PrivacyLayer` を組み込んでいなかった。加えて `PrivacyLayer::on_event` は PII 検出時に `target: "kaname::privacy"` で警告ログを**追加発行するだけ**で、元のイベント (PII を含む) は他の Layer にそのまま伝播し出力される。`tracing-subscriber` の `Layer::on_event` には他レイヤーへの伝播を止める権限が無く、真にブロックするには `Filter::event_enabled` でイベント構築前に判定する設計が要る。docstring は「ドロップする」と誤って主張していた。I5 は正規表現による手動監査では違反ゼロを確認済み (D27 と同様の走査) だが、これは**プログラマの注意力のみに依存する脆い保証**であり、多重防衛層として設計された `PrivacyLayer` が完全に無効だったのは重大 | `tracing_subscriber::registry().with(env_filter).with(fmt::layer()).with(PrivacyLayer).init()` に変更し、`PrivacyLayer` を実際の subscriber に組み込んだ。docstring を実装どおり (検知のみ・非ブロック) に修正。**残作業 (要ネットワーク)**: (a) `cargo check` でこの `registry()` 構成が型検査を通ることを確認 (D20 により未検証)、(b) `PrivacyLayer` を `Filter::event_enabled` ベースに再設計し、検出時に実際にイベントを抑制できるようにする |
| D29 | **D24 (c) の分類が誤りだった: `settings_get`/`settings_set` は「他コマンドから使用される内部 API」と書いたが、実際は引数を無視して `Ok(())`/`Ok(None)` を返すだけのスタブで、呼び手は一つも無かった (2026-09 発見)** | `crates/kaname-ui/src/commands.rs` | D24 を書いた時点で、この2コマンドの実装を確認せず「内部APIとして正当」と分類していた。実際には `_account_id`/`_key`/`_value` と、使わない引数に `_` を付けたまま何もしないスタブだった。対照的に `settings_save_onboarding`/`settings_is_onboarded` (オンボーディング専用) は既に `kaname_store::Store::set_setting`/`get_setting` を実際に呼んでいた — 同じ store が実在するのに、汎用版だけがスタブのまま放置されていた | **解消済み**: `Store::set_setting`/`get_setting` を呼ぶ実装に置き換えた。ただし呼び出す UI は依然として存在しないため、`static-check.sh` 検査5の WARN は残る — これは「配線しないのが正しい」(a) とも「内部APIとして正当」(c) とも違う、**「実装はしたが UI 未着手」という3つ目の正直な状態**であり、そのまま記録する |
| D30 | **D24 (a) の分類も一部誤りだった: 「LLM 依存で意図的に未配線」10 件のうち 8 件は LLM 生成そのものではなく、LLM 呼び出しの前後に置く決定論的な防衛策だった (2026-09 発見)** | `crates/kaname-ui/src/commands.rs`, `crates/kaname-screen`, `crates/kaname-ai`, `crates/kaname-observability/src/trajectory.rs` | D24 (a) は「配線すると偽の AI 出力を表示する」という理由で10件すべてを一括りにしていたが、`audit_ai_output`/`check_action_risk`/`check_memory_trust`/`check_rule_of_two`/`validate_tool_argument`/`record_agent_step`/`reset_trajectory`/`screen_user_input` の実装を確認すると、どれも `PromptScreener`/`OutputAuditor`/`TieredRisk`/`ArgumentValidator`/`TrajectoryMonitor` 等の**決定論的なチェッカー**を呼んでいるだけで、`kaname-ai::llm_bridge` や `Dual-LLM` の trait を一切呼んでいない。本当に LLM 生成を要するのは `ai_smart_reply`/`ai_summarize_email` の2件のみで、この2件は既に「未実装」を明示するエラーを正しく返している | **配線しない判断自体は維持する (実装の訂正は不要)**。`kaname-ui/src/commands.rs` に実際の LLM 呼び出し経路が一つも無いため (D2)、防衛すべき対象が無い現状でこれらを UI に繋いでも意味を持たない。**LLM 本実装 (要ネットワーク) と同時に、その入出力の境界にこれら8件を組み込むのが正しい順序**であり、D24 の分類理由のみを訂正した |
| D31 | **README のバッジ・clone 手順が `kaname-app/kaname` (このセッションの GitHub アクセス範囲外のリポジトリ) を指していた** | `README.md` (CI/Security Audit/Platform バッジ、`git clone` コマンド) | 実際にこのセッションが操作しているリポジトリは `shizukutanaka/kaname` である。`README.md` の4箇所が `kaname-app/kaname` を参照しており、新規利用者が README どおりに `git clone` すると**現在到達可能なコードに辿り着けない**。`Cargo.toml` の `repository` フィールドと `authors` の `security@kaname.app` (ブランドドメイン)、`CLAUDE.md` の `@kaname-app/security-lead` (レビューチーム) など、他 13 ファイルにも同じ `kaname-app` への言及が残る | **README のみ修正した** (バッジ4箇所を `shizukutanaka/kaname` に訂正)。`Cargo.toml`/`CLAUDE.md`/その他ドキュメントは**意図的に変更していない**: `kaname-app` が製品の恒久的なブランド/組織名で `shizukutanaka/kaname` が開発中の一時的な置き場である可能性があり、この区別はコードからは判断できない (人間の意思決定が必要)。README の `git clone` 手順だけは「今日この repo を使う人」に対して実害が確定していたため先に直した |
| D32 | **リリースカット時にビルドマニフェスト3箇所 (Cargo.toml/package.json/tauri.conf.json) のバージョン更新を手順として忘れる、を再発防止せず前セッションで口頭反省だけして終えていた** | `scripts/static-check.sh` | v0.6.0 のまま放置されていた3箇所を修正した直後、「次のセッションのために記憶しておくべき事項」と書いただけで、実際には何も自動化していなかった。これは D25/D26 で学んだはずの教訓 (「一度見つけた欠陥クラスは自動化するまで再発防止にならない」) を、その場で忘れていたことになる | **解消済み**: `static-check.sh` に検査8として追加し、3ファイルの version フィールドが一致していることを機械的に検証する。合成的に `package.json` を `0.6.0` に戻して検出されることを確認し (実際に起きたバグをそのまま再現)、復元後に誤検知が無いことも確認済み |
| D33 | **CONTRIBUTING.md の i18n 節が実態と3点ズレていた: 存在しないディレクトリ (`src/i18n/`, 実際は `src/locales/`)、存在しない言語ファイル (`zh-CN.json`/`ko.json`)、存在しない CI 検証 (D7 により CI 自体が無い)** | `CONTRIBUTING.md`, `src/i18n.ts` | `src/i18n.ts` の `Language` 型は `"zh-CN"`/`"ko"` を宣言し、ブラウザ言語判定 (`nav.startsWith("zh"/"ko")`) で自動選択されうるが、対応する翻訳 JSON は未作成。実害は無い (`t()` の `resolveKey` は `undefined` を安全に処理し日本語へフォールバックする。クラッシュ・空表示にはならない) が、CONTRIBUTING.md はこの状態を反映していなかった。`git clone` の URL も D31 と同じ誤りを含んでいた (`kaname-app/kaname`) | **解消済み**: パス・言語ファイル一覧・CI 主張を実態に合わせて訂正し、`git clone` を `shizukutanaka/kaname` に訂正 (D31 と同じ理由: 実行可能な手順としての実害が確定していたため)。`src/i18n.ts` 冒頭コメントの誤ったファイルパス表記・CI 主張も訂正した |
| D34 | **`SECURITY.md` (脆弱性報告者が最初に読む文書) が、実装されていない保護機構3件を「実装済み」と主張していた (最重要)** | `SECURITY.md` | 「主要保護メカニズム」節が (1) Dual-LLM 型安全を「`Content<Untrusted>` を `PrivilegedLlm` に渡すことはコンパイル時に不可能」と断定 (実際は D17: trait 実装0件で型を経由しない生 `&str` API が実推論経路)、(2) MLS を「件名を含む全暗号化」と主張 (実際は D1: 単一バイト XOR モック)、(3) Firecracker サンドボックスを実装済みと主張 (実際は D4: no-op) していた。サポート対象バージョン表も v0.3.x を最新と記載したまま (実際は v0.7.1) だった。**セキュリティ方針文書自体が、この製品の README・threat-model・gap-analysis が総力で正そうとしてきた「誇張」を体現していた** | **解消済み**: 3項目を `docs/gap-analysis.md`/`docs/threat-model.md` の実態に合わせて訂正し、脆弱性報告者が誤った前提で判断しないようにした。バージョン表も v0.7.x に更新。報告経路・SLA・重大度分類・報奨・監査計画等の運用面は変更していない (人間の意思決定領域) |
| D35 | **CHANGELOG.md 末尾のバージョン比較リンクが誤ったリポジトリ (`kaname-app/kaname`) を指し、かつ v0.1.4 以降更新されていなかった。さらに git tag が一つも作成されていないため訂正後も404になる** | `CHANGELOG.md` | D31/D33 と同じ欠陥クラス。加えて `git tag -l` が空を返すことを確認した — v0.1.0〜v0.7.1 のどのリリースにもタグが付いていない。Keep a Changelog 形式の比較リンクは GitHub の tag 間比較機能に依存するため、タグが無ければリポジトリを訂正しても機能しない | **リポジトリ参照のみ訂正**。タグ作成はリリース権限を持つ人間の判断領域のため本セッションでは行わない (release-approval スキルが `push main`/`tag`/`ship` を人間承認必須としている)。v0.5.0 以降のリンクは追加していない — 存在しないタグへのリンクを増やすだけになるため |
| D36 | **`docs/testing-strategy.md` がテスト件数・カバレッジ「現状」(91%/87%/85%等) をあたかも実測済みであるかのように主張していた** (SECURITY.md D34 と同種) | `docs/testing-strategy.md` | 「CI 実行マトリクス」節は D7 (CI ワークフロー自体が存在しない) を、「カバレッジ目標」表の「現状」列は D20 (`cargo test`/`cargo nextest`/`npm test` のいずれもこの環境で実行不可) を前提にしており、どちらも本環境では検証不能な主張だった。テストコード自体は実在し `static-check.sh` の構文検証は通るが、実行結果 (合格・失敗・カバレッジ率) は一切確認できていない | **解消済み**: 文書冒頭に、テスト件数・CI マトリクス・カバレッジ「現状」列がこの環境で未検証であることを明記する訂正を追加した。数値そのものは書き換えていない (このリポジトリの実測値かどうか本セッションでは判定不能なため、削除も訂正もせず「未検証」と明示するに留めた) |
| D37 | **`docs/performance-history.md` が「実測は v0.2.0 リリース時に追記」と予告したまま、v0.7.1 に至るまで一度も追記されていなかった** | `docs/performance-history.md` | v0.1.0/v0.1.4 は実測の歴史的記録として正しく残されているが、それ以降 (v0.2.0〜v0.7.1) のベンチマーク実測セクションが存在しない。`cargo bench` は D20 により本環境で実行不可、`.github/workflows/perf.yml` が想定する CI ベンチマークも D7 により存在しないため、この空白は今後も埋まらない可能性が高い | **解消済み (記録のみ)**: 「追記」が一度も行われていない事実と、D7/D20 によりこの環境では埋められないことを明記した。v0.1.0/v0.1.4 の歴史的記録は変更していない |
| D38 | **`SETUP.md` に D7/D31 と同じ欠陥クラスが3箇所あった: 誤ったリポジトリへの `git clone`、存在しない `.github/workflows/*.yml` をディレクトリツリーに記載、CI が自動ビルド・配布すると主張** | `SETUP.md` | `git clone https://github.com/kaname-app/kaname.git` (D31/D33/D35 と同じ誤リポジトリ)。ディレクトリツリー図が `workflows/` に `ci.yml`/`sbom.yml`/`release.yml` が存在すると記載していたが `.github/workflows/` は空 (D7)。リリース手順が `git push origin vX.Y.Z` で「CI が自動的にビルド・配布」すると説明していたが、CI 自体が存在しないため配布は起きない | **解消済み**: clone URL を `shizukutanaka/kaname` に訂正。ディレクトリツリー図と配布手順の記載を D7 の実態 (CI 不在、手動配布が必要) に合わせて訂正した。`scripts/release.sh` 自体は実在することを確認済み (9ステップの一部は動くが、配布の自動化部分だけが機能しない) |
| D39 | **`docs/brand-guidelines.md` の「推奨表現」リストが、未実装の機能を主張するマーケティング文言を執筆者に使うよう指示していた (最重要級)** | `docs/brand-guidelines.md` | 「推奨表現」に `"型システムで保証"`/`"コンパイル時に検証"` (D17: trait 実装0件で型を経由しない生 `&str` API が実推論経路) と `"RFC 9420 準拠"` (D1: MLS は単一バイト XOR モック) が含まれていた。SECURITY.md (D34)・testing-strategy.md (D36) は「既に書かれた文書が誇張していた」問題だったが、これは**将来書かれるマーケティング文言・UI 文言が誇張することを積極的に推奨する**という、より先行的な害を持っていた | **解消済み**: 該当2表現を取り消し線付きで「使用禁止」に変更し、D1/D17 解消後にのみ使用可能と明記した。他の推奨表現 ("ローカルで実行"/"受信箱を読みません") は実態と一致しており変更していない |
| D40 | **`docs/competitive-analysis.md` の「実装した改善」「独自優位性」表に、モック/スタブ/未配線の機能が実装済みとして6項目含まれていた。加えて発見: `ZeroKnowledgeSearch` は実装されているが出荷経路 (`mail_search`) に一度も配線されておらず、実際の検索は平文 LIKE 検索だった** | `docs/competitive-analysis.md`, `docs/launch-keynote-2026.md`, `docs/vision-keynote.md`, `docs/product-film-script.md` | 件名 MLS 暗号化 (D1)・Dual-LLM 型安全 (D17)・Firecracker 添付分離 (D4)・ローカル AI 推論 (D2) が実装済みと主張。ゼロ知識検索は `kaname-privacy::ZeroKnowledgeSearch` として実在するが `kaname-ui` から一度も呼ばれておらず、D12/D13/D21 と同じ「実装したが組み付けていない」パターンだった。一方 `launch-keynote-2026.md`/`vision-keynote.md`/`product-film-script.md` は Amazon/Apple 流「Working Backwards」(製品化前に発表の言葉を先に書く) を自ら明記した到達目標であり、SECURITY.md/testing-strategy.md/brand-guidelines.md とは性質が異なるため全面修正はしていない | **competitive-analysis.md は該当6項目に実態を注記** (⚠️/✅ で区別)。**3本の keynote/vision 脚本は本文を書き換えず、冒頭に `docs/maturity.md`/`docs/gap-analysis.md` を参照するよう促す注記のみ追加** (Working Backwards の性質上、詳細な行単位の訂正は目的に反するため)。**追跡調査で `ZeroKnowledgeSearch` 自体の doc コメントも「本番: SQLite FTS5 使用」と誤って主張していた (実際はインメモリ `Vec` で永続化されない) ことが判明し、これも訂正済み**。配線については、永続化を失う退行になるため見送りが正しい判断と結論した (`kaname_store::search_messages` は SQLCipher 永続化済み) |
| D41 | **出荷 UI (`src/ui/SecurityDashboard.tsx`、到達可能な9モジュールの一つ) がハードコードされた偽データと、実装されていない保護機構を「Kaname の独自機能」として表示していた (このセッション最重要)** | `src/ui/SecurityDashboard.tsx` | 「セキュリティ」タブを開くたびに (1) 偽の AI アクセスログ (架空の email_id・判定)・偽の連絡先インテリジェンス (架空の氏名「田中 花子」「佐藤 太郎」)・偽のアクションアイテムをハードコードで表示、(2) `ai_detect_phishing` がエラーになった場合に無言で `score: 0.15 (安全)` という偽の判定にフォールバック (本物のフィッシングメールを安全と誤信させかねない)、(3) 「競合比較カード」で「ローカル AI 推論」(D2: 未実装) と「MLS + PQC 暗号化」(D1: XOR モック) を実装済みの独自機能として表示 — していた。SECURITY.md (D34)・brand-guidelines.md (D39)・competitive-analysis.md (D40) と同じ欠陥だが、**これは文書ではなく実際にユーザーが操作する出荷画面**であり、影響が最も直接的だった | **解消済み**: (1) 偽データ注入を削除し、実データ取得元が無いため空状態を表示する (各サブコンポーネントは空配列を正しく処理する)。(2) エラー時は専用のエラーメッセージを表示し、スコアバー・偽の安全判定は出さない。(3) 5項目を実装状況どおりに ✓ (実装済み) / ⚠ (部分実装、UI 未接続) / ✗ (未実装) に区分し直した |
| D42 | **D41 の追跡監査: バックエンドの BEC 判定エラー時フォールバックは正しく "UNKNOWN" を返していた (SAFE と偽らない) が、フロントエンドの `BecBadge` がこのケースをラベルマップに含めておらず内部の生文字列 "UNKNOWN" がそのまま UI に漏れていた** | `crates/kaname-ui/src/commands.rs` (`assess_listing`)、`src/ui/Inbox.tsx` (`BecBadge`) | D41 発見後、同種のパターン (エラー時の偽装) がバックエンドにも無いか確認したところ、`assess_listing` は `Err` 分岐で正しく `"UNKNOWN"` を返し `tracing::warn!` でログも残しており、**この部分は最初から正しく実装されていた**。ただし `BecBadge` (Inbox.tsx) のラベル/色マップに `UNKNOWN` が無く、バッジ自体は非表示にならず生の英字コードがそのまま表示される、軽微な UX の粗さがあった (安全と誤認させる問題ではない) | **解消済み**: `BecBadge` に `UNKNOWN` → 「判定失敗」のラベルとグレー配色を追加した。D41 と異なり本項目は誤情報ではなく表示品質の改善であり、D41 ほどの重大度ではない |
| D43 | **Dependabot の cargo エコシステムが `open-pull-requests-limit: 10` の上限に達しており、新規の依存更新 PR を開けなくなっている** | `.github/dependabot.yml`, GitHub の Open PR 一覧 | 2026-09 時点で cargo 由来の未マージ Dependabot PR がちょうど10件 (#37/#38/#39/#40/#41/#42/#43/#44/#45/#95) 存在し、設定上限と一致する。これらは D20 (`cargo build`/`cargo check` がこの環境で実行不可) により安全にマージ判断ができず、本セッションでは意図的に未着手のまま残した。npm 由来も3件 (#66/#87/#94) 未マージ。D7 (CI 不在) により、たとえマージしてもビルド検証が自動で走らない | **コード変更は行っていない (記録のみ)**。ネットワークが解放され `cargo build`/`cargo test`/`npm test` が実行できる環境で、これら13件をまとめてレビュー・マージする必要がある。それまで cargo レーンは新規 PR を生成できない状態が続く。`dependabot.yml` の `reviewers: kaname-app/security-lead` 等のチームハンドルが実在しない場合、レビュー依頼も機能していない可能性がある (D31 と同じ理由で本セッションでは未検証・未変更) |
| D44 | **DLP/BEC の `our_domain` (自組織ドメイン) が全呼び出し箇所で `"example.com"` にハードコードされており、自組織ドメインの概念が一切永続化されていない** | `crates/kaname-ui/src/commands.rs` (行324, 432, 566, 1822, 1869), `crates/kaname-dlp/src/misdirected_recipient.rs`, `crates/kaname-bec/src/lib.rs` | `kaname_dlp::EvalCtx.our_domain` は宛先ミス検出 (`misdirected_recipient::detect_misdirected_recipients`) の自己送信除外に、`kaname_bec::AssessmentRequest.our_domain` はなりすまし送信元のホモグリフ (ルックアライク) ドメイン検出に使われる。いずれも `commands.rs` の全呼び出し箇所で文字列リテラル `"example.com"` が渡されており、実際にログインしているアカウントのドメインを一切反映しない。結果として (1) 送信 DLP の宛先ミス検出は自社ドメイン宛のメールを常に「未知の外部ドメイン」として扱う(誤検知方向)、(2) BEC のルックアライクドメイン検出は自社ドメインに似せた攻撃ドメインを実質検出できない (見逃し方向、より深刻)。根本原因は `commands.rs`/`kaname-jmap::JmapClient` のどこにも「自組織のメールドメイン」を保持するフィールドや設定キーが存在しないこと — `JmapClient` は `account_id` (JMAP 内部 ID) のみ保持し、ログインメールアドレスや設定画面での組織ドメイン入力も存在しない | **未修正 (このセッションでは意図的に見送り)**。`settings_get`/`settings_set` (D24/D29 で実配線済み) を使えば `org_domain` 設定キーを永続化する土台はあるが、(a) 設定 UI に入力項目を追加する、(b) 未設定時に空文字へフォールバックし検出を安全にスキップする、(c) 5箇所の呼び出しを新ヘルパー経由に統一する、という3点セットの実装が必要で、UI 変更を伴うため単純なバグ修正の範囲を超えると判断した。空文字列を渡した場合 `misdirected_recipient` 側の検出は安全にスキップされる (`our_domain.is_empty()` ガード) ため、少なくとも `"example.com"` という**実在ドメイン**を渡し続けるより空文字にするほうが安全側だが、それでもホモグリフ検出が機能しない問題は残る。要 UI 対応 (設定画面に「組織ドメイン」入力欄の追加) |
| D21 | ~~**出荷 UI がモック専用コンポーネントを描画し、実配線済みの画面が死蔵していた**~~ **(2026-09 解消)** | `src/main.tsx`, `src/ui/KanameDesign.tsx`, `src/ui/Inbox.tsx`, `src/ui/ComposeAdmin.tsx` | クレート到達可能性 (D19) と同じ病がフロントエンドにもあった。実測の結果 11 モジュール中 4 つが `src/main.tsx` から到達不能で、**受信トレイに描画されていた `KanameDesign` は invoke を一切呼ばないモック専用**だった (コンポーネント自身のコメントが認めている)。実際に `mail_fetch`/`mail_search`/`bec_get_score` を呼ぶ `Inbox` はどこからも import されていなかった。さらに `mail_send` を呼ぶ画面も未到達で、**UI からメールを送る経路が存在しなかった**。到達させてもフロントは `{req:{...}}` を送り Tauri は `(from,to,subject,body)` を取るため**実行時に必ず失敗する**引数不一致があり、作成画面の MLS インジケータは**モック実装 (D1) を「対応済み」と表示**していた | **解消済み**: `main.tsx` を `Inbox` に切り替え、`Compose` を「作成」ビューとして配線、送信の引数形を一致させ差出人入力を追加、MLS インジケータを常に非対応に修正、モック専用 2,284 行を削除。到達可能モジュールは 7/11 → 8/9。**続報 (同月)**: 到達させた `Inbox` が呼ぶ `mail_get_body`/`bec_get_score`/`mail_get_mailboxes` が **3 つともスタブ**だったため、`mail_open` (blobId → `analyze_raw_email`) と `mail_get_mailboxes` を実装。到達可能 UI が呼ぶコマンド ∩ `not_wired` = ∅ を実測で確認。**教訓: 「配線した」と言えるのは、エントリポイントからの到達可能性を実測したときだけである** |
| D22 | ~~**オンボーディング画面が意図的に未到達 (バックエンドがスタブのため)**~~ **(2026-09 解消: `settings` テーブルへ保存し初回起動時に表示)** | `src/ui/Onboarding.tsx`, `src-tauri/src/main.rs` | `Onboarding.tsx` (344 行) は実装されているが `main.tsx` から到達不能。配線しない判断は意図的で、`settings_save_onboarding` が `Err(not_wired(..))` を返すスタブであるため、**配線すると「設定が保存できたように見えて実際は失敗する」画面**を出荷することになる | `kaname-store` に設定の永続化を実装してから配線する。それまでは未到達のままにするのが正しい (保存できない設定画面を見せない) |
| D23 | ~~**永続化は一度も成功し得ない状態だった**~~ **(2026-09 解消)** | `kaname-store`, `kaname-ui/commands.rs`, `src/main.tsx` | 二重の欠陥。(1) `history_open` を呼ぶ UI が無く Store が開かれない → 「Store 未接続なら何もしない」設計により永続化・検索・履歴が**無言で無効**。(2) `PRAGMA foreign_keys = ON` なのに `accounts`/`mailboxes` への本番 INSERT が無く (テストの `seed_account` のみ)、開いても `save_message` 等は **FK 違反で必ず失敗**。D10 で「永続化を実装した」と記録したが、**一度も動いていなかった**。サイレント失敗設計が欠陥を隠した | 起動時 `history_open_default` で既定パスに開く。書き込み前に `ensure_account`/`ensure_mailbox`。鍵は `history.key` 0600 (キーチェーン未統合は明記)。**教訓: 「失敗しても続行」は失敗を見えなくする。少なくとも警告ログは残す** |
| D19 | **出荷バイナリに入っているのは 27 クレート中 10 個のみ — 看板機能が製品に存在しない (2026-07 依存グラフ解析)** | ワークスペース全体 | `src-tauri` → `kaname-ui` からの推移閉包を実測した結果、到達可能なのは **10 クレート** (`kaname-ui`/`kaname-ai`/`kaname-crypto`/`kaname-error`/`kaname-memory-guard`/`kaname-observability`/`kaname-oobv`/`kaname-pivot`/`kaname-render`/`kaname-screen`) のみ。**残り 17 クレートは製品に含まれていない**: `kaname-bec` (BEC 検出・110+ テスト — README の看板機能)、`kaname-dlp`、`kaname-jmap`、`kaname-store`、`kaname-mls` (PQC 暗号)、`kaname-i18n`、`kaname-radar`、`kaname-ssa`、`kaname-saas-guard`、`kaname-sandbox`、`kaname-privacy`、`kaname-continuity`、`kaname-billing`、`kaname-tray`、`kaname-core`、`kaname-mockserver`、`kaname-tests`。**D10 (パイプライン未配線) より広範な問題** — 部品は作られたが製品に組み付けられていない | **「部品を作る」のをやめて「組み立てる」フェーズへ移行する**。第一歩として `kaname-bec` を `kaname-ui` に組み込み済み (新規外部依存ゼロ)。`ai_detect_phishing` が固定値 `score: 0.12` を返していたのを実際の `BecDetector::assess()` 呼び出しに置換。LLM 未配線を理由に出荷できない状態を避けるため `BecDetector::deterministic_only()` (`NullLlm`) を追加し、**LLM を必要としない 9 シグナルファミリーで動作**させる。残る 16 クレートも同様に「組み込む or 削除する」判断が必要 |
| D18 | **送信ドメイン認証 (SPF/DKIM/DMARC) を独立検証していない — 受信サーバのヘッダを信じるのみ (2026-07 監査、2026-09 に悪用可能な状態へ格上げ)** | `kaname-render/src/lib.rs` (`parse_auth_results`/`extract_auth_result`), `kaname-bec` の認証シグナル全般 | 認証系シグナル (§3.15 の DKIM リプレイ検出を含む) は全て `AssessmentRequest.auth` の判定結果を前提とするが、その供給元は `Authentication-Results` ヘッダの**文字列パースのみ**。ワークスペースに DKIM 署名の暗号検証コードは**ゼロ件**。RFC 8601 が想定する「信頼された自組織 MTA のヘッダを信じる」設計自体は正常だが、(a) **authserv-id を一切検証していない** (RFC 8601 §7.1 が要求。リポジトリ全体で `authserv` の言及ゼロ)、(b) `extract_auth_result` が `find("dkim=")` の**最初の一致**を採る素朴な部分文字列探索で、`smtp.mailfrom=`/`header.d=` 等の攻撃者が影響し得る echo フィールドより後に本来の機構名がある場合に誤った値を拾う構造的脆さがある。**この信頼前提が脅威モデルに未記載だったこと自体が最大の問題** (§3.15b として追記済み)。**2026-09 更新**: 監査時点では D10 (メールパイプライン未配線) により `parse_auth_results` に実メールが流れておらず理論上の懸念だったが、**D10 解消によりこの経路は現在実際に稼働している** (ローカル `.eml` 取込みと JMAP サーバ受信の両方)。攻撃条件は「ユーザーが接続する JMAP サーバまたは経路上の中継を攻撃者が制御・偽装できること」に限られ影響範囲は限定的だが、もはや理論上の懸念ではない。詳細は `docs/threat-model.md` §3.15b を参照 | **[`mail-auth`](https://github.com/stalwartlabs/mail-auth) (Stalwart Labs) を採用する** — Kaname が既に使う `mail-parser` と**同一ベンダ** (ADR-009) で、DKIM (RSA/Ed25519)・ARC 連鎖検証・SPF/DMARC ポリシー評価を提供。2026-07 時点で **DKIM2 と DMARCbis (RFC 9989/9990/9991, 2026-05) を実装済み**。**重要**: DKIM2 はメッセージを宛先にバインドし送信時刻を記録することでリプレイをプロトコルレベルで解決し、転送で署名が壊れない chain of custody を導入するため、**§3.15 で実装した `d=` 整合ヒューリスティックは DKIM1 時代の暫定策であり DKIM2 対応後は不要になる**。当面の最小対応として authserv-id 検証の追加と `extract_auth_result` の機構スコープ限定パースを行う。**新規依存追加のためネットワーク解放が前提** |
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
