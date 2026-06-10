# kaname-privacy

> プライバシー保護層

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- トラッキングピクセル検出 (1x1 GIF)
- 外部画像ブロック (デフォルト)
- メールアドレス匿名化ハッシュ
- PII の自動 REDACT

## ワークスペース内依存

- `kaname-error`
- `kaname-render`

## テストカバレッジ

10 ユニットテスト

## 使用例

```rust
use kaname_privacy::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
