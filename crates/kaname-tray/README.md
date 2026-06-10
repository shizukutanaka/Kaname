# kaname-tray

> macOS メニューバー Extra

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- 状態応じたアイコン: Normal / Alert / Focus / Offline
- 未読バッジ (99+ 対応)
- BEC アラートドット
- Apple Notification Center 統合 (inline reply)
- StartupMetrics (FMP < 421ms)

## ワークスペース内依存

- `kaname-error`

## テストカバレッジ

11 ユニットテスト

## 使用例

```rust
use kaname_tray::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
