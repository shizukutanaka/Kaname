# New Crate Checklist

## 新規クレート作成時の必須ステップ

### 1. Cargo.toml
```toml
[package]
name             = "kaname-<name>"
version.workspace     = true
edition.workspace     = true
rust-version.workspace = true

[dependencies]
serde        = { workspace = true }
thiserror    = { workspace = true }
tracing      = { workspace = true }
kaname-error = { path = "../kaname-error" }

[dev-dependencies]
proptest = { workspace = true }
```

### 2. src/lib.rs の冒頭
```rust
//! kaname-<name> — <1行の説明>
//!
//! # <主要機能>
//! - <機能1>
//! - <機能2>
//!
//! # <不変条件があれば>
//! - <保証1>

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
```

### 3. workspace/Cargo.toml に登録
`"crates/kaname-<name>",` を members に追加

### 4. README.md を作成
テンプレート: `crates/kaname-error/README.md` を参照

### 5. CODEOWNERS に DRI を追加

### 6. テスト
- ユニットテスト最低 5 件
- proptest で不変条件をカバー
- pub fn に `#[must_use]` を追加

## Gotchas

- `kaname-error` は全クレートが依存する (循環しない限り)
- `unsafe` は `#![deny(unsafe_code)]` で禁止
- 新クレートは `docs/` に設計メモを残す
