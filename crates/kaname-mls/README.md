# kaname-mls

> MLS RFC 9420 グループ暗号化

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- Email-over-MLS (件名を含む全体を暗号化)
- openmls 統合 (Welcome / Commit / Application)
- Safety Number 検証セレモニー
- エポック単位のキーローテーション

## ワークスペース内依存

- `kaname-error`
- `kaname-crypto`

## テストカバレッジ

10 ユニットテスト

## 使用例

```rust
use kaname_mls::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
