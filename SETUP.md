# Kaname — 開発環境セットアップ

新規開発者が **5 分で動くプロダクト** を体験できる手順書。

---

## 必要環境

| ソフトウェア | 最小バージョン | macOS インストール | Windows |
|---|---|---|---|
| Rust | 1.82 | `brew install rustup-init && rustup-init` | rustup-init.exe |
| Node.js | 22 | `brew install node` | nodejs.org |
| Git | 2.40+ | `brew install git` | git-scm.com |

### macOS 追加要件
- Xcode Command Line Tools: `xcode-select --install`

### Linux 追加要件 (Ubuntu 22.04+)
```bash
sudo apt install -y \
  libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
  librsvg2-dev libssl-dev pkg-config build-essential
```

### Windows 追加要件
- WebView2: Windows 11 にプリインストール
- Visual Studio Build Tools 2022 (C++ ツール)

---

## クイックスタート (3 コマンド)

```bash
git clone https://github.com/kaname-app/kaname.git
cd kaname
npm install && cargo build --workspace
```

開発モードで起動:
```bash
npm run tauri:dev
```

---

## プロジェクト構造

```
kaname/
├── Cargo.toml              # Rust workspace (19 クレート)
├── package.json            # Node 依存
├── index.html              # Vite エントリ
├── vite.config.ts          # Vite 設定 (ポート 1420 固定)
├── tauri.conf.json         # → src-tauri/
│
├── src/                    # SolidJS フロントエンド
│   ├── main.tsx            # エントリポイント (4 ビューのルーター)
│   ├── ui/                 # UI コンポーネント
│   │   ├── KanameDesign.tsx       # Liquid Glass メイン UI
│   │   ├── KanameAppleFeatures.tsx # Quick Look / Undo / Smart Reply
│   │   ├── KanameApp.tsx          # スワイプ / Focus / 自然言語検索
│   │   └── SecurityDashboard.tsx  # セキュリティポスチャー
│   ├── locales/            # i18n カタログ (ja / en)
│   └── __tests__/          # vitest ユニットテスト
│
├── src-tauri/              # Tauri バックエンド
│   ├── src/main.rs         # #[tauri::command] ラッパー
│   ├── tauri.conf.json     # アプリ設定
│   ├── icons/              # アイコン (.icns / .ico / .png)
│   └── capabilities/       # Tauri 権限ポリシー
│
├── crates/                 # Rust クレート (単方向依存グラフ)
│   ├── kaname-core/        # 基礎型・AppState・UX 機能
│   ├── kaname-error/       # 共通エラー型
│   ├── kaname-ai/          # ★ Dual-LLM 型安全 (北極星)
│   │   └── src/dual_llm.rs # Content<Untrusted> + Bridge
│   ├── kaname-bec/         # BEC 多信号検出器
│   ├── kaname-mls/         # MLS RFC 9420 + ML-KEM-768
│   ├── kaname-crypto/      # ハイブリッド KEM/Sig
│   ├── kaname-dlp/         # DLP ルールエンジン
│   ├── kaname-store/       # SQLCipher 永続化
│   ├── kaname-render/      # MIME + HTML サニタイズ
│   ├── kaname-jmap/        # JMAP クライアント
│   ├── kaname-sandbox/     # Firecracker microVM
│   ├── kaname-billing/     # Stripe ライセンス
│   ├── kaname-tray/        # macOS メニューバー
│   ├── kaname-i18n/        # 国際化
│   ├── kaname-observability/ # Metrics + Privacy フィルター
│   ├── kaname-privacy/     # トラッキング検出・匿名化
│   ├── kaname-mockserver/  # JMAP モックサーバー (E2E 用)
│   ├── kaname-ui/          # Tauri コマンド層
│   └── kaname-tests/       # 統合・敵対・プロパティ・ベンチ
│
├── e2e/                    # Playwright E2E テスト
│   ├── north-star-demo.spec.ts # 北極星デモ完全自動化
│   └── a11y.spec.ts        # WCAG AAA 自動検証 (axe-core)
│
├── fuzz/                   # cargo-fuzz ターゲット
│   ├── fuzz_targets/
│   │   ├── mime_parser.rs
│   │   ├── html_sanitizer.rs
│   │   └── prompt_injection.rs
│   └── corpus/             # 攻撃シードコーパス
│
├── docs/                   # 設計・運用ドキュメント
│   ├── threat-model.md     # STRIDE 完全分析
│   ├── adr/                # Architecture Decision Records
│   ├── runbook/            # インシデント対応手順
│   ├── design.md           # デザインシステム
│   ├── competitive-analysis.md
│   └── product-film-script.md
│
├── scripts/                # 自動化スクリプト
│   ├── release.sh          # 9 ステップリリース自動化
│   └── generate-icons.sh   # アイコン生成
│
├── .github/                # GitHub 統合
│   ├── workflows/          # CI: ci.yml + sbom.yml + release.yml
│   ├── ISSUE_TEMPLATE/     # バグ・機能要望
│   └── pull_request_template.md
│
└── public/                 # 静的アセット
    ├── khig-tokens.css     # Apple HIG + Liquid Glass トークン
    ├── app-icon.svg        # アプリアイコン
    └── tray-icon.svg       # トレイアイコン
```

---

## よく使うコマンド

### 開発
```bash
npm run tauri:dev              # ホットリロード付きで起動
npm run dev                    # フロントエンドのみ (Vite)
cargo run -p kaname-mockserver # JMAP モック起動 (E2E 用)
```

### テスト
```bash
cargo nextest run --workspace  # Rust 全テスト (3x 高速)
npm run test:unit              # vitest ユニットテスト
npm run test:e2e               # Playwright E2E
npm run test:a11y              # アクセシビリティ自動検証
```

### Lint / 型チェック
```bash
cargo clippy --workspace -- -D warnings
cargo fmt --all --check
npm run typecheck && npm run lint
```

### セキュリティ監査
```bash
cargo audit                    # 脆弱性スキャン
cargo deny check all           # ライセンス + 禁止クレート
npm audit
```

### ファジング (nightly Rust 必要)
```bash
rustup install nightly
cargo install cargo-fuzz
npm run fuzz:prompt            # プロンプト注入耐性テスト
npm run fuzz:html              # XSS サニタイザ
npm run fuzz:mime              # MIME パーサー
```

### ベンチマーク
```bash
cargo bench --bench core_bench
```

### リリース
```bash
./scripts/release.sh 0.2.0     # 9 ステップ自動化 + git tag
git push origin v0.2.0         # CI が自動的にビルド・配布
```

---

## 北極星デモシーン (3 分体験)

新規開発者にプロダクトの価値を 3 分で伝える:

```bash
# 1. 起動
npm run tauri:dev

# 2. オンボーディングを進める (4 ステップ)
#    ↑ Apple "Packaging = 第一印象" の実装

# 3. 受信トレイで「fix-002」(BEC メール) を選択
#    → 赤色バナー表示
#    → 「危険・BEC攻撃の可能性」テキスト

# 4. 「AI で要約」をクリック
#    → 「このメール 1 通のみ分析」セキュリティ証明
#    → 受信箱全体にアクセスしないことが UI で明示

# 5. 視覚的確認
#    Liquid Glass サイドバー (backdrop-blur)
#    Spring アニメーション (cubic-bezier(.34, 1.56, .64, 1))
#    WCAG AAA コントラスト
```

---

## トラブルシューティング

| 症状 | 原因 | 解決 |
|---|---|---|
| `cargo build` が遅い | LTO 有効化 | `cargo build` (debug)、release は CI で |
| Tauri 起動失敗 (Linux) | webkit2gtk 不足 | 上記 Linux 追加要件を実行 |
| `npm run tauri:dev` で port 1420 使用中 | Vite が掴んでいる | `lsof -ti:1420 \| xargs kill` |
| プロンプト注入テストが失敗 | Bridge ポリシーが厳格すぎ | `crates/kaname-ai/src/dual_llm.rs` の `attack_markers` を確認 |

---

## 次のステップ

- 設計を理解する: `docs/design.md`、`docs/adr/`
- 脅威モデル: `docs/threat-model.md`
- 製品ビジョン: `docs/keynote.md`
- リリースプロセス: `LAUNCH.md`
- セキュリティ報告: `SECURITY.md`

---

## テスト失敗時のリカバリ

### 「Rust テストが失敗した」

```bash
# 1. 詳細を見る
cargo nextest run --workspace --no-fail-fast 2>&1 | tee test-output.txt

# 2. 特定クレートだけ再実行
cargo nextest run -p kaname-bec

# 3. 単一テストを詳細に
cargo test -p kaname-ai --test '*' -- test_name --nocapture --test-threads=1

# 4. デバッガで止める
cargo test -p kaname-ai test_name -- --nocapture
# (lldb / gdb で起動可能)
```

### 「vitest が DOM API で失敗」

`vitest.config.ts` で `environment: "jsdom"` を確認。
```bash
npm run test:unit -- --reporter=verbose
```

### 「Playwright が起動失敗」

```bash
# ブラウザを再インストール
npx playwright install --with-deps

# モックサーバーが起動しているか確認
cargo run -p kaname-mockserver --bin jmap-mock &
# 別ターミナル
curl http://localhost:8080/health

# Playwright を UI モードで起動
npm run test:e2e:ui
```

### 「ファジングがクラッシュ」

これは **歓迎すべきこと** (ファジングの目的)。

```bash
# クラッシュデータを保存
cd fuzz
cp artifacts/mime_parser/crash-* corpus/mime_parser/regression-$(date +%s).bin

# デバッグ実行
cargo +nightly fuzz run mime_parser corpus/mime_parser/regression-*.bin

# 修正後はリグレッションテストとして残す
```

### 「プロパティテストの反例が出た」

`proptest` は反例を `proptest-regressions/*.txt` に保存する。
**この .txt は git にコミット必須**: 同じ反例が再現してしまわないよう。

```bash
git add crates/kaname-bec/proptest-regressions/
git commit -m "test: regression for property test failure"
```

