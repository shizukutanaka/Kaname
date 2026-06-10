# kaname-tests

> 統合テスト・敵対テスト・プロパティテスト・ベンチマーク

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- 敵対テスト: 50 ペイロード × 7 カテゴリ
- 統合テスト: 全クレート横断
- プロパティテスト: BEC スコア・Levenshtein 不変条件
- criterion ベンチマーク

## ワークスペース内依存

- `全クレート (dev-dependency)`

## テストカバレッジ

50 統合 + 14 プロパティ + ベンチ

## 使用例

```rust
use kaname_tests::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
