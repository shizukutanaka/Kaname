# kaname-i18n

> 国際化フレームワーク

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- BCP 47 ロケール識別子
- CLDR 準拠の plural 規則 (アラビア語 6 カテゴリ等)
- プレースホルダー型安全置換
- 1000 言語対応の基盤

## ワークスペース内依存

依存なし

## テストカバレッジ

11 ユニットテスト

## 使用例

```rust
use kaname_i18n::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
