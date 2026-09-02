# 要 Kaname

> AIが助けてくれるのに、裏切らない唯一のメールクライアント

[![CI](https://github.com/kaname-app/kaname/actions/workflows/ci.yml/badge.svg)](https://github.com/kaname-app/kaname/actions/workflows/ci.yml)
[![Security Audit](https://github.com/kaname-app/kaname/actions/workflows/ci.yml/badge.svg?job=audit)](https://github.com/kaname-app/kaname/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey)](https://github.com/kaname-app/kaname/releases)
[![Status](https://img.shields.io/badge/status-v0.6.0-orange.svg)](docs/maturity.md)

---

## ⚠️ 実装ステータス (公開前に必読)

**本リポジトリは v0.6.0 です。メールの解析・受信・送信・永続化・検索・添付ダウンロードは
実装され配線済みですが、MLS 暗号化とローカル LLM 推論はモック/スタブのままです。
また開発環境の制約により型検査 (`cargo check`) が未実施です。**
製品の長所・短所・改善点と「完成の定義」は [`docs/socratic-review.md`](docs/socratic-review.md) に
自問形式でまとめています。
機能ごとの成熟度は [`docs/maturity.md`](docs/maturity.md) と [`docs/gap-analysis.md`](docs/gap-analysis.md) に
実コード根拠付きで正直に記載しています。要点:

- **実装済み・実テストで検証済み (本番出荷可)**: BEC 多信号検出 (`kaname-bec`)、DLP 分類器 (`kaname-dlp`)、
  Quishing / カレンダー招待 / HTML スマグリング検出 (`kaname-render`)、Out-of-Band Verification (`kaname-oobv`)、入力スクリーニング (`kaname-screen`)、SSRF 対策 (`kaname-jmap`)、
  Dual-LLM の**型境界** (`kaname-ai::dual_llm`)。
- **モック / スタブ段階 (本番運用不可)**: MLS グループ暗号化 (`kaname-mls` — 現状は XOR モック)、
  ローカル LLM 推論 (`kaname-ai::llm_bridge` — 固定応答)、Firecracker サンドボックス (`kaname-sandbox` — no-op)、
  自動アップデート、課金基盤の永続化 (`kaname-billing`)。これらは外部クレート統合が必要。
- **組み立て状況 (2026-07 更新)**: 依存グラフを実測したところ、出荷バイナリに到達可能なのは
  **27 クレート中 18 個**です (当初 10 個)。「部品を作る」のをやめ「組み立てる」方針に転換し、
  実装済みで眠っていた検出器を順次接続しました。
- **実メールを解析できます**: 「**ファイル解析**」タブからローカルの `.eml` を指定すると、
  MIME 解析 → 送信ドメイン認証の評価 → BEC 判定 → サニタイズ → 本文リスク検出
  (HTMLスマグリング/テキストQR/CSS外部参照/リンク評判) → DLP → 添付検査
  (MIME偽装/polyglot/危険拡張子/SVG/メタデータ/カレンダー招待) が動きます。
  フォルダ一括解析では**複数メール横断のキャンペーン検出**も。
  動作確認用サンプルを [`examples/emails/`](examples/) に7通同梱しています
  (使い方: [`examples/README.md`](examples/README.md))。
- **サーバとの送受信も配線済み**: 「**サーバ接続**」タブから JMAP サーバに接続すると、
  受信したメールが**ファイル解析と同じ検出器**を通ります。送信時は
  **DLP (Outbound) が機微情報を検出したらブロック**します。
  認証トークンは**メモリ内にのみ保持しディスクに書きません**
  (安全に保管できるまで保管しない方針。OS キーチェーン統合は今後)。
- **永続化・検索・添付ダウンロードも配線済み**: 受信したメールは SQLCipher に保存され
  (MLS がモックのため暗号化列には書かず `body_preview` のみ)、検索欄から LIKE 検索できます。
  添付は **ディスクに書く前に必ず検査**し、危険と判定したものは**保存せず**理由だけ返します
  (`kaname-sandbox` が no-op のため実行は許さず「検査して警告」に徹する方針)。
- **まだ無いもの**: MLS 暗号化 (XOR モック)、ローカル LLM 推論 (要約・スマートリプライ、固定応答)、
  Firecracker サンドボックス (no-op)、OS キーチェーン統合は未実装です。
  詳細は [`docs/maturity.md`](docs/maturity.md) / [`docs/gap-analysis.md`](docs/gap-analysis.md)。
- **ビルド検証の制約**: 本リポジトリの開発環境は組織のエグレスポリシーにより
  `static.crates.io` が遮断されており、`cargo check` / `cargo test` を実行できません
  (gap-analysis D20)。代替として `./scripts/static-check.sh` で構文検証を行っていますが、
  **型検査は未実施**です。ネットワークのある環境での検証が必要です。

比較表の記号: **✅ = 実データで稼働中**、**⚠ = 一部稼働 (制約付き)**、
**🔶 = 設計のみ・実装はモック/スタブ**。🔶 は到達目標であって現時点の能力ではありません。

---

## なぜ Kaname か

2026年の脅威モデルは2010年代とは全く異なる。しかし既存のメールクライアントはすべて旧時代の設計のままだ。

| 脅威 | Superhuman | Proton Mail | Microsoft 365 | **Kaname** |
|---|---|---|---|---|
| プロンプト注入 (CVE確認済) | ✗ 脆弱 | N/A | ✗ 脆弱 | ✅ 型で防止 |
| DLP バイパス (CW1226324) | N/A | N/A | ✗ 発生 | ✅ ラベル強制 |
| AI生成フィッシング | ✗ 未対応 | ✗ 未対応 | ✗ 未対応 | ⚠ 決定論的検出のみ (LLM 未接続) |
| BEC 多信号検出 | ✗ | ✗ | △ | ✅ 7信号 |
| 量子コンピューター対策 | ✗ | △ (PQC研究中) | ✗ | 🔶 ML-KEM-768 (設計のみ・実装はモック) |
| ローカル AI 推論 | ✗ (クラウド) | ✗ | ✗ (Copilot) | 🔶 Phi-4-mini (スタブ・固定応答) |
| 件名暗号化 | ✗ 平文 | ✗ 平文 | ✗ 平文 | 🔶 MLS RFC 9420 (設計のみ・実装はモック) |

---

## 3 つの柱

### 🛡 Security — Dual-LLM の型境界 (設計は完成・LLM 実装は未接続)

```
Untrusted メール本文
    ↓
Content<Untrusted> 型  ← 型システムで境界を強制
    ↓
QuarantinedLlm::analyze()  ← Q-LLM: このメール1通のみ
    ↓
AnalysisReport (構造化済み)
    ↓
Bridge::validate_and_promote()  ← 型変換で境界を越える
    ↓
Content<Trusted>  ← P-LLM が受け取る
```

上図は `kaname-ai::dual_llm` が定義する**設計上の境界**であり、`PrivilegedLlm` trait は
`&Content<Trusted>` しか受け取らないため、`Content<Untrusted>` をそのまま渡すコードは
確かにコンパイルエラーになる。

**ただし現状の実装はこの型境界を通っていない (2026-07 監査で判明)。** 正直に書くと:

- ワークスペース全体で **`impl QuarantinedLlm for` / `impl PrivilegedLlm for` は 0 件**。
  実際の推論経路 `kaname-ai::llm_bridge` は `Content` 型を使わず生の `&str` を受け取る
  API になっており、上記の型境界を迂回できる。
- `Content<Untrusted>::as_text()` は `pub` であり、doc は「Q-LLM 内部のみ」と書いているが
  **可視性では強制されていない**（規約であって型ではない）。
- `Content<L>` は `Serialize`/`Deserialize` を derive しており、`_level` が `#[serde(skip)]`
  のため **JSON 経由で `Content<Trusted>` を Bridge を経ずに構築できる**。
- 一方で **I3 の中核は本物**: `Content` のフィールドは全て private、`Content<Trusted>` の
  公開コンストラクタは `from_user_input`/`from_system` のみ、Bridge 専用の昇格路は
  `pub(crate)`、`unsafe`/`transmute` はゼロで `compile_fail` テストも存在する。

現時点でローカル LLM 推論自体がスタブ (`llm_bridge` は固定応答) のため
**悪用可能な経路は存在しない**が、実推論を入れる際に上記を塞がないと
型境界は実効性を持たない。残作業は
[`docs/gap-analysis.md`](docs/gap-analysis.md) の D17 を参照。

### ⚡ Speed — HEY + Superhuman の統合

- **送信者スクリーナー**: 初回送信者を承認するまでブロック
- **スマートトリアージ**: Paper Trail / Feed / Important に自動仕分け
- **スヌーズ + Reply Later**: 適切な時間に適切なメールを
- **⌘K コマンドパレット**: キーボードのみで全操作

### 🔒 Privacy — データがデバイスを離れない

- 全 AI 推論: ローカル (Phi-4-mini-instruct Q4_K_M)
- 全メールデータ: SQLCipher で暗号化
- サーバー: 暗号化 BLOB のみを保持 (中身を読めない)
- トラッキングピクセル: デフォルトでブロック

---

## クイックスタート

### 必要環境

- macOS 14 (Sonoma) 以上 / Windows 11 / Ubuntu 22.04
- Rust 1.82 以上
- Node.js 22 以上

### 開発環境セットアップ

```bash
# リポジトリをクローン
git clone https://github.com/kaname-app/kaname.git
cd kaname

# 依存関係インストール
npm ci

# 開発サーバー起動 (ホットリロード付き)
npm run tauri dev
```

### ビルド

```bash
# リリースビルド
npm run tauri build

# テスト実行
cargo nextest run --workspace

# Lint
cargo clippy --workspace -- -D warnings

# セキュリティ監査
cargo audit
cargo deny check all
```

---

## アーキテクチャ

```
kaname/
├── src/                    # SolidJS フロントエンド
│   ├── main.tsx            # エントリポイント
│   └── ui/                 # コンポーネント
│       ├── KanameDesign.tsx        # Liquid Glass メイン UI
│       ├── SecurityDashboard.tsx   # セキュリティダッシュボード
│       ├── KanameAppleFeatures.tsx # Quick Look / Undo / Smart Reply
│       └── KanameAppleV5.tsx       # スワイプ / Focus / 自然言語検索
├── src-tauri/              # Tauri エントリポイント
│   └── src/main.rs
├── crates/                 # Rust クレート (単方向依存)
│   ├── kaname-core/        # 基礎型・UX機能
│   ├── kaname-crypto/      # ML-KEM-768 + Ed25519 + X25519
│   ├── kaname-store/       # SQLite + SQLCipher
│   ├── kaname-render/      # MIME パーサー + HTML サンドボックス
│   ├── kaname-ai/          # Dual-LLM 型安全 AI パイプライン
│   ├── kaname-bec/         # BEC 多信号検出器
│   ├── kaname-dlp/         # DLP ルールエンジン
│   ├── kaname-mls/         # MLS RFC 9420 E2E 暗号化
│   ├── kaname-sandbox/     # Firecracker microVM
│   ├── kaname-billing/     # Stripe + エンタイトルメント
│   ├── kaname-tray/        # macOS メニューバー Extra
│   ├── kaname-ui/          # Tauri コマンド層
│   └── kaname-tests/       # 統合テスト + 敵対テスト
├── .github/workflows/
│   └── ci.yml              # CI/CD (check/test/clippy/audit/build/release)
├── deny.toml               # ライセンス + 脆弱性管理
├── CHANGELOG.md
└── CLAUDE.md               # AI ペアプログラミング向け設定
```

---

## セキュリティ

### 脅威モデル

詳細は [threat-model.md](docs/threat-model.md) を参照。

### 脆弱性の報告

セキュリティ脆弱性を発見した場合は **公開 Issue ではなく** security@kaname.app へメールで報告してください。

- 暗号化推奨: [PGP キー](https://kaname.app/security.asc)
- 対応期限: 報告から 48 時間以内に確認、30 日以内に修正

### AI アクセス監査ログ

Kaname の全 AI 処理は改ざん防止ハッシュチェーン (FNV-1a) で記録される。`設定 > セキュリティ > AI アクセスログ` から確認可能。

---



## セキュリティアーキテクチャ

Kaname は arxiv の最新研究を継続的に反映している:

| 防御層 | 実装 | 出典 |
|---|---|---|
| Dual-LLM 型境界 | `Content<Untrusted>` / `Content<Trusted>` | CaMeL (2503.18813) |
| 入力スクリーニング | kaname-screen `PromptScreener` | 2505.22852 §2.1 |
| 出力監査 | kaname-screen `OutputAuditor` | 2505.22852 §2.2 |
| Tiered-Risk 制御 | kaname-ai `tiered_risk` | 2505.22852 §3 |
| メモリ汚染防御 | kaname-memory-guard | 2601.05504 |
| X25519 出力検証 | kaname-crypto `validate_x25519_output` | eprint 2026/192 |

検証境界は [docs/verification-boundary.md](docs/verification-boundary.md) に明示。
「形式検証済み」を盲信せず、独自 sanity check + KAT + microVM 分離で多層防御する。

## プロジェクト統計 (v0.3.20)

| 項目 | 数値 |
|---|---|
| Rust クレート | 27 |
| Rust LOC | 約 22,000 |
| Rust ユニットテスト | 452 |
| KAT + AgentDojo + 統合テスト | 16 |
| Playwright E2E | 19 |
| vitest | 31 |
| ファジングターゲット | 3 (corpus 23 シード) |
| プロパティテスト | 20 |
| unsafe ブロック | 0 |
| 本番 unwrap() | 0 |
| docs/ 文書数 | 24 (索引付き) |

詳細なドキュメントは [docs/README.md](docs/README.md) を参照。


## ライセンス

AGPL-3.0-or-later

Copyright (C) 2026 Kaname Team

---

## 謝辞

- [OpenMLS](https://github.com/openmls/openmls) — MLS RFC 9420 実装
- [Tauri](https://tauri.app) — クロスプラットフォームデスクトップフレームワーク
- [Apple HIG](https://developer.apple.com/design/human-interface-guidelines/) — デザイン原則
- PromptArmor — Superhuman プロンプト注入の研究 (Kaname の設計動機)
