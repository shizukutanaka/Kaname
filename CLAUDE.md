# CLAUDE.md — Kaname AI ペアプログラミングガイド

> このファイルは Claude Code や Cursor で Kaname を開発する際の指示書。
> セッション開始時に必ず参照すること。

---

## プロダクト概要

**Kaname (要)** — AIが助けても裏切らない、法人向けセキュアメールクライアント。

北極星: 「AIが受信箱全体を読まない。メール1通のみ解析する。」

技術スタック: Rust (23 クレート) + SolidJS + Tauri 2.x + MLS RFC 9420 + ML-KEM-768

---

## READ ORDER (必須)

```
CLAUDE.md → Cargo.toml → docs/threat-model.md → 対象クレートの lib.rs
```

---

## 絶対不変条件 (変更禁止)

| ID | ルール |
|----|--------|
| I1 | `Content<Untrusted>` は `QuarantinedLlm` にのみ渡す |
| I2 | Q-LLM の出力は `AnalysisReport` スキーマのみ。自由テキスト不可 |
| I3 | `Bridge` を通らない Untrusted→Trusted 変換は型エラー |
| I4 | P-LLM はネットワーク呼び出し不可 (`#[deny(unsafe_code)]` + seccomp) |
| I5 | ログに PII を含めない (`PrivacySanitizer` 経由) |
| I6 | `unwrap()` は本番コードに使用禁止 (`#[deny(clippy::unwrap_used)]`) |

---

## クレート依存グラフ (単方向)

実測の依存関係 (D101 — 以前の記述は設計意図であり実装と一致していなかった):

```
葉クレート (kaname-* への依存なし):
  kaname-screen, kaname-pivot, kaname-memory-guard, kaname-crypto,
  kaname-store, kaname-jmap, kaname-privacy, kaname-observability,
  kaname-radar, kaname-ssa, kaname-mls, kaname-sandbox, kaname-mockserver,
  kaname-error (依存先・被依存ともにゼロの孤立。D85 で削除予定)

kaname-render     → kaname-screen
kaname-saas-guard → kaname-screen
kaname-ai         → kaname-screen
kaname-bec        → kaname-screen, kaname-pivot, kaname-memory-guard
kaname-dlp        → kaname-render
kaname-oobv       → kaname-crypto, kaname-memory-guard
kaname-tests      → kaname-ai, kaname-screen (テスト専用)
kaname-ui         → kaname-bec, kaname-dlp, kaname-jmap, kaname-memory-guard,
                    kaname-oobv, kaname-privacy, kaname-radar, kaname-render,
                    kaname-saas-guard, kaname-ssa, kaname-store,
                    kaname-observability
src-tauri         → kaname-ui
```

循環依存は禁止 (Cargo 自体が検出する)。新クレート追加時はグラフを更新すること。

---

## テスト基準

```bash
# 全テスト実行 (CI と同じ)
cargo nextest run --workspace

# 特定クレートのみ
cargo nextest run -p kaname-ai

# フォーマット確認
cargo fmt --all --check

# Lint
cargo clippy --workspace --all-targets -- -D warnings
```

カバレッジ目標: `kaname-ai` 90%以上、その他 70%以上。

---

## 新機能追加のチェックリスト

- [ ] `crates/kaname-xxx/src/lib.rs` に `//!` ドキュメント追加
- [ ] `crates/kaname-xxx/README.md` に機能説明追加
- [ ] `Cargo.toml` の workspace members に追加
- [ ] `crates/kaname-xxx/Cargo.toml` に `kaname-error` 依存追加
- [ ] ユニットテスト ≥ 10 件
- [ ] `CHANGELOG.md` の `[Unreleased]` に追記
- [ ] `docs/threat-model.md` に新しい攻撃面を追記 (必要な場合)

---

## セキュリティクリティカルなコード変更

以下は変更前に `docs/threat-model.md` を必ず確認:

- `crates/kaname-ai/` — Dual-LLM 境界
- `crates/kaname-bec/` — BEC 検出ロジック
- `crates/kaname-mls/` — 暗号実装
- `crates/kaname-crypto/` — PQC ハイブリッド
- `crates/kaname-dlp/` — DLP ルール

**これらのクレートへの PR は `@kaname-app/security-lead` の承認が必須。**

---

## よくあるミスと対処

### `Content<Untrusted>` をそのまま表示しようとする

```rust
// ❌ コンパイルエラー
let text = untrusted_content.as_text(); // Untrusted は UI に直接渡せない

// ✅ Bridge を経由
let trusted = bridge.validate_and_promote(report, &untrusted)?;
ui.display(trusted.as_text());
```

### unwrap() を使ってしまう

```rust
// ❌ 本番コードで禁止
let value = option.unwrap();

// ✅
let value = option.ok_or(KanameError::Missing("field"))?;

// ✅ RwLock の場合
let guard = lock.read().unwrap_or_else(|e| e.into_inner());
```

### UI 文字列

UI 文言はコンポーネント内の日本語ハードコード文字列が正規。
i18n 基盤 (`src/i18n.ts` + `src/locales/`、Rust 側の kaname-i18n) は
いずれも呼び出し実績ゼロのため削除済み (E9/D19)。多言語化が必要になったら
git 履歴から復元すること。

---

## コミット規約

```
feat(kaname-ai): Bridge にカスタム攻撃マーカー登録機能を追加
fix(kaname-bec): Levenshtein 距離の三角不等式テストを修正
docs(kaname-radar): PCR のアルゴリズム説明を追記
test(kaname-oobv): タイムアウト時のゼロ化を確認するテストを追加
chore(deps): serde を 1.0.197 に更新
```

---

## 参照文書

| 文書 | 用途 |
|---|---|
| `docs/threat-model.md` | STRIDE 脅威分析 |
| `docs/new-features-v0.2.md` | v0.2 新機能設計 |
| `docs/new-features-v0.3.md` | v0.3 新機能設計 |
| `docs/brand-guidelines.md` | UI テキストのトーン |
| `docs/decisions-not-to-do.md` | 実装しないことの一覧 |
| `docs/performance-history.md` | ベンチマーク履歴 |
| `SETUP.md` | 開発環境のセットアップ |

---

## セッション開始時のチェック

```bash
# 現在のプロジェクト状態を確認
./scripts/stats.sh

# テストが全て通ることを確認
cargo nextest run --workspace --no-fail-fast 2>&1 | tail -5
```

---

## v0.3 新機能の実装場所

| 機能 | クレート | 主要ファイル |
|---|---|---|
| AiTM 検出 | kaname-bec | `src/aitm.rs` |
| 送信者文体認証 | kaname-ssa | `src/lib.rs` |
| HTML スマグリング | kaname-render | `src/html_smuggling.rs` |
| Calendar Guard | kaname-render | `src/calendar_guard.rs` |
| PCR (ポリモーフィックキャンペーン) | kaname-radar | `src/lib.rs` |
| QR Quishing | kaname-render | `src/quishing.rs` |
| SaaS Link Safety | kaname-saas-guard | `src/lib.rs` |
| Out-of-Band Verification | kaname-oobv | `src/lib.rs` |
| Pivot Detection | kaname-pivot | `src/lib.rs` |

---


## arxiv 研究反映機能 (v0.3.8+)

| 機能 | クレート/モジュール | 出典 |
|---|---|---|
| 入力スクリーニング | kaname-screen `PromptScreener` | arxiv 2505.22852 §2.1 |
| 出力監査 | kaname-screen `OutputAuditor` | arxiv 2505.22852 §2.2 |
| UserUpload provenance | kaname-ai `Provenance::UserUpload` | arxiv 2505.22852 §2.3 |
| Tiered-Risk アクセス制御 | kaname-ai `tiered_risk` | arxiv 2505.22852 §3 |
| メモリ汚染防御 | kaname-memory-guard | arxiv 2601.05504 |

これらのクレートはライブラリとして残っているが、エージェント監視 UI が
製品に存在しないため IPC コマンド層 (screen_user_input / audit_ai_output /
check_action_risk / check_memory_trust / check_rule_of_two /
validate_tool_argument / record_agent_step / reset_trajectory) は
呼び出し元ゼロで削除済み (2026-09, gap-analysis E11)。クレートの機能は
`kaname_memory_guard::normalize_for_matching*` 等として解析経路で利用中。

## よく使うコマンド (Makefile)

```bash
make dev       # 開発サーバー起動 (Tauri + Vite)
make test      # 全テスト (nextest + vitest)
make bench     # ベンチマーク
make security  # セキュリティ監査 (audit + deny + clippy)
make release   # リリースビルド (scripts/release.sh 呼び出し)
make stats     # プロジェクト統計
```

---

## スキルとコマンド

```
.claude/skills/
  bec-detection.md    BEC/AiTM/PCR の仕組み
  dual-llm.md         Content<Untrusted> の使い方
  new-crate.md        新規クレート作成チェックリスト
  performance.md      Apple HIG 目標値と計測
  security-review.md  セキュリティレビューチェックリスト

.claude/commands/
  /commit             Conventional Commits メッセージ生成
  /security-audit     セキュリティ境界の審査
  /new-crate <name>   新規クレート作成
  /bench [target]     ベンチマーク実行
```

---

## セッション開始プロトコル

1. `make stats` で現状を確認
2. `git log --oneline -5` で最近の変更を確認  
3. `.claude/skills/<relevant>.md` を参照してから実装開始
4. 実装後 `cargo clippy --workspace -- -D warnings` で確認
5. テスト追加 → `cargo nextest run -p <crate>` で確認
6. セキュリティに関わる変更は `docs/threat-model.md` を更新
