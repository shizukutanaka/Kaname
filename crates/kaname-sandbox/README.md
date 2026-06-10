# kaname-sandbox

> Firecracker microVM サンドボックス

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- 添付ファイルを isolated VM でレンダリング
- リソース制限: CPU 1 core / Memory 256MB
- vsock 経由のメッセージング
- 起動時間 < 200ms (warm pool)

## ワークスペース内依存

- `kaname-error`
- `kaname-render`

## テストカバレッジ

3 ユニットテスト

## 使用例

```rust
use kaname_sandbox::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
