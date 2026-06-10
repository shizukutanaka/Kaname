# /new-crate <name> <description>

新しい Rust クレートを Kaname の規約に従って作成する。

## 実行ステップ
1. `crates/kaname-<name>/` ディレクトリ作成
2. `Cargo.toml` (workspace 継承形式)
3. `src/lib.rs` (#![deny(unsafe_code)] 等の標準アトリビュート)
4. `README.md` (標準テンプレート)
5. `Cargo.toml` (workspace の members に追加)
6. `.github/CODEOWNERS` に DRI 追加を提案

## スキル参照
- `.claude/skills/new-crate.md`
