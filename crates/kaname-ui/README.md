# kaname-ui

> Tauri コマンド層

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- 12 個の Tauri コマンドハンドラー
- 純粋 async fn 実装 (テスト容易)
- src-tauri が #[tauri::command] でラップ
- Threat Intel: AI フィッシング検出 + DLP 強制

## ワークスペース内依存

- `kaname-ai`
- `kaname-bec`
- `kaname-dlp`
- `kaname-store`

## テストカバレッジ

8 ユニットテスト

## 使用例

```rust
use kaname_ui::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
