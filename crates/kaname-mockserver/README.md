# kaname-mockserver

> JMAP モックサーバー

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- 開発環境: 実 JMAP なしで動作確認
- E2E テスト用フィクスチャ 5 種
- axum 実装、ポート 8080
- `cargo run -p kaname-mockserver --bin jmap-mock`

## ワークスペース内依存

依存なし

## テストカバレッジ

6 ユニットテスト

## 使用例

```rust
use kaname_mockserver::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
