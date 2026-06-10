# kaname-core

> 基礎型・AppState・UX 機能

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- AppState 状態管理
- SenderScreener (HEY 風スクリーナー)
- TriageEngine (Important / Paper Trail / Feed)
- SnoozeManager / SendLaterManager / SafeSummaryEngine

## ワークスペース内依存

- `kaname-error`

## テストカバレッジ

18 ユニットテスト

## 使用例

```rust
use kaname_core::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
