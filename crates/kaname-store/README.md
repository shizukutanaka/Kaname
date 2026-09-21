# kaname-store

> SQLCipher 暗号化永続化

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- AES-256 で全データ暗号化
- DB キーは `history.key` (0600 ファイル) で保管 — OS Keychain/Secure Enclave 統合は未実装
- 監査ログのハッシュチェーン (SHA-256)
- WAL モードで並行アクセス

## ワークスペース内依存

- なし (外部依存のみ: rusqlite/sha2/serde 等)

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
