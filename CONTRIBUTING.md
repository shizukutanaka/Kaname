# Kaname への貢献ガイド

歓迎します。Kaname は AGPL-3.0 で OSS 化されており、商用利用と貢献の両方を歓迎します。

## 貢献の種類

| 種類 | プロセス |
|---|---|
| バグ報告 | GitHub Issues `bug` ラベル |
| 機能要望 | GitHub Discussions → Issue 化 |
| ドキュメント改善 | PR 直接 |
| コード貢献 | Issue で議論 → PR |
| セキュリティ脆弱性 | [SECURITY.md](SECURITY.md) 参照、公開しない |
| 翻訳 | `src/locales/` |

## 開発環境

```bash
git clone https://github.com/shizukutanaka/kaname.git
cd kaname
npm ci
npm run tauri:dev

# テスト
cargo nextest run --workspace
npm run test:unit

# Lint
cargo clippy --workspace -- -D warnings
npm run lint

# Pre-commit hooks
npm run prepare
```

## 必要環境
- Rust 1.82+ / Node.js 22+
- macOS 14+ / Windows 11 / Ubuntu 22.04

## ブランチ命名

```
feat/add-foo       # 新機能
fix/typo-bar       # バグ修正
docs/update-readme # ドキュメント
refactor/extract-x # リファクタリング
test/add-y-tests   # テスト
chore/bump-deps    # 雑務
```

## コミットメッセージ

[Conventional Commits](https://www.conventionalcommits.org/) 準拠:

```
feat(bec): add QR code phishing detection
fix(mls): handle empty roster gracefully
docs(readme): add screenshots
test(dlp): cover boundary cases
refactor(ai): extract Bridge module
chore(deps): bump tokio to 1.42
```

## PR 要件

- [ ] `cargo nextest run` 全通過
- [ ] 新規コードのテスト追加 (カバレッジ ≥ 80%)
- [ ] `cargo clippy -- -D warnings` 通過
- [ ] `cargo fmt --check` 通過
- [ ] CHANGELOG.md `[Unreleased]` 更新
- [ ] 公開 API 変更時 ADR 追加 (`docs/adr/`)
- [ ] UI 変更時スクリーンショット添付

## レビュー要件

- 通常: 1名
- **セキュリティ重要モジュール 2名**: kaname-ai, kaname-mls, kaname-crypto, kaname-dlp

## コーディング規約

### Rust
- `rustfmt.toml` 準拠 (max_width=100)
- `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic` エラー
- 全 pub 関数に `///` ドキュメントコメント
- エラーは `kaname_error::KanameError` (生 String 禁止)
- `#![deny(unsafe_code)]`
- 非同期ランタイムは tokio のみ

### TypeScript
- ESLint strict mode
- `any` 禁止 (`unknown` または明示的型)
- Solid.js パターン (React パターンではない)
- inline style props (Tauri CSP 互換)

## 重要モジュール変更ルール

### kaname-ai
**型制約を緩めない。** `Content<Untrusted>` → `Content<Trusted>` の変換は `Bridge::validate_and_promote()` 経由のみ。変更時は2名レビュー + ADR 更新必須。

### kaname-mls
RFC 9420 準拠を維持。プロトコル変更は ADR + 相互運用性テスト必須。

### kaname-crypto
全 crypto 操作は `subtle` (constant-time) または `zeroize` を使う。新プリミティブ追加は暗号設計レビュー必須。

### kaname-dlp
ルール追加は false positive < 5% を維持。

## i18n

`src/locales/` に言語ごと JSON (2026-09 訂正: 旧記述の `src/i18n/` は誤り):
```
src/locales/ja.json   # 日本語 (基準)
src/locales/en.json
```
`src/i18n.ts` の `Language` 型は `"zh-CN"`/`"ko"` も宣言しているが、
対応する JSON ファイルは未作成。ブラウザ言語が中国語/韓国語の場合、
自動選択された言語に翻訳が無いため `t()` は日本語へフォールバックする
(クラッシュや空表示にはならない。`src/i18n.ts` の `resolveKey`/`t` 参照)。
**CI による自動検証は存在しない** (`.github/workflows/` が空、
`docs/gap-analysis.md` D7)。キーの一致は目視レビューで確認すること。

## CLA

初回 PR で CLA Bot がコメント。同意で AGPL-3.0 配布に承諾。

## 連絡先

- 一般: GitHub Discussions
- セキュリティ: security@kaname.app
- 商用ライセンス: licensing@kaname.app
