# kaname-dlp

> DLP ルールエンジン

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- 12 種の boolean 式木分類器
- 個人番号 / クレカ番号 / 銀行口座等の検出
- ラベル: Public / Internal / Confidential / HighlyConfidential / LegalPrivilege
- Microsoft Copilot CVE CW1226324 対策

## ワークスペース内依存

- `kaname-error`
- `kaname-ai`

## テストカバレッジ

9 ユニットテスト

## 使用例

```rust
use kaname_dlp::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
