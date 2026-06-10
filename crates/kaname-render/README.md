# kaname-render

> MIME パーサー + HTML サニタイザー

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- RFC 2045-2049 MIME 完全実装
- RFC 2047 件名エンコーディング
- HTML サニタイズ (許可リスト方式)
- mXSS / SVG XSS / data: URI 攻撃対策

## ワークスペース内依存

- `kaname-error`

## テストカバレッジ

6 ユニット + ファジング 2 ターゲット

## 使用例

```rust
use kaname_render::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
