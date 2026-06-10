# kaname-error

> Kaname 共通エラー型

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- 17 種の型付きエラー
- severity() で Critical/High/Medium/Low
- user_message() は内部詳細を含まない
- JSON シリアライゼーション対応

## ワークスペース内依存

依存なし

## テストカバレッジ

7 ユニットテスト

## 使用例

```rust
use kaname_error::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
