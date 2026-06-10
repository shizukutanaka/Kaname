# kaname-bec

> BEC 多信号検出器

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- Levenshtein 距離によるドメインタイポスクワット
- 緊急性マーカー検出 (至急、urgent)
- 振込先変更パターン
- QR フィッシング、VEC、メール爆撃

## ワークスペース内依存

- `kaname-error`
- `kaname-i18n`

## テストカバレッジ

4 ユニット + 14 プロパティテスト

## 使用例

```rust
use kaname_bec::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
