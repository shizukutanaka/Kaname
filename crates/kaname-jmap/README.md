# kaname-jmap

> JMAP RFC 8620/8621 クライアント

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- HTTPS over TLS 1.3 のみ
- Email/get、Email/query、Email/set、Mailbox/get
- Push/EventSource でリアルタイム同期
- レート制限自動調整

## ワークスペース内依存

- `kaname-error`
- `kaname-render`

## テストカバレッジ

4 ユニット + モックサーバー統合テスト

## 使用例

```rust
use kaname_jmap::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
