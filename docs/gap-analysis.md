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
| D1 | MLS グループ暗号化 | `kaname-mls` | 単一バイト XOR (鍵=公開 ConversationId 先頭バイト、鍵空間256のみ)。暗号として機能していない | `openmls` クレートを統合し RFC 9420 準拠の実装に置き換える |
| D2 | ローカル LLM 推論 (Q-LLM/P-LLM) | `kaname-ai::llm_bridge` | 固定文字列 (`{"risk":"SAFE",...}` 等) を返すだけ。`tokens_in`/`tokens_out` も常に0で実際には推論していない | `llama.cpp` か `candle` で Phi-4-mini 等の実推論を実装。トークン計測も実値化 |
| D3 | Q-LLM/P-LLM のプロセス分離 | `kaname-ai::subprocess` | seccompプロファイルの「パス文字列」を生成するだけ。実際に分離を強制する外部バイナリ `kaname-llm-runner` が存在するか自体が未確認 | `kaname-llm-runner` バイナリを実装し、seccomp-bpf (Linux) / sandbox-exec (macOS) / Job Object (Windows) を実際に適用する |
| D4 | Firecracker microVM サンドボックス | `kaname-sandbox` | `spawn_vm`/`VsockChannel` が no-op。セマフォ管理・プールの衛生管理コードは実装済みだが VM 自体は起動しない | Firecracker バイナリとの実連携、vsock通信の実装 |
| D5 | 自動アップデート | `src-tauri` | `tauri.conf.json` から無効な `updater` 設定を削除済みだが (2026-07修正)、`tauri-plugin-updater` 自体が未導入。機能そのものが存在しない | プラグイン導入 + 署名鍵ペア生成 + 配信サーバー構築 |
| D6 | 課金基盤の永続化 | `kaname-billing` | エンタイトルメント/冪等性キーが全てインメモリで、プロセス再起動で消える。Stripe webhookのペイロードを検証なしに信頼し、ライブAPIで再確認していない | `kaname-store` (永続化層) との連携、Redis等での分散重複排除、監査用の台帳ハッシュチェーン検証を追加 |
| D7 | CI が実行されていない | `.github/workflows/` | このディレクトリが空。ワークフロー定義は `ci-templates/*.yml` (ci/e2e/fuzzing/perf/release/sbom の6つ) に退避されたまま。README曰く「GitHub Appの権限に workflows 権限がないため退避」。旧ギャップ分析表の「CI/CD 6ワークフロー ✅」は誤りで、**push/PRのたびに自動テストが一切走っていない** | リポジトリ管理者が `git mv ci-templates/*.yml .github/workflows/` を実行し、GitHub App側の権限設定を見直す。コード変更では解決しない、人間の管理者操作が必須 |
| D8 | E2Eテストの実行検証が未完了 | `e2e/*.spec.ts`, `playwright.config.ts` | Playwrightでのテスト一覧パースは成功 (66件) したが、実際にブラウザで実行して green を確認できていない。このセッションはネットワーク越しの `crates.io` 取得が組織ポリシーで 403 拒否されており、`cargo run -p kaname-mockserver` のビルドを伴う `npx playwright test` の実行が検証未了 | ネットワーク制限のないセッションで `npx playwright test` を実行し、実際にパスすることを確認する |

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
