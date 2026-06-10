# kaname-store

> SQLCipher 暗号化永続化

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- AES-256 で全データ暗号化
- OS Keychain でデータベースキー保管
- 監査ログのハッシュチェーン (FNV-1a)
- WAL モードで並行アクセス

## ワークスペース内依存

- `kaname-error`
- `kaname-crypto`

## テストカバレッジ

6 ユニットテスト

## 使用例

```rust
use kaname_store::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
