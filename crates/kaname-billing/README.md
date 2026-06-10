# kaname-billing

> Stripe ライセンス検証

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- Webhook の HMAC-SHA256 署名検証
- エンタイトルメント管理 (プラン、有効期限)
- オフライン時の継続動作 (ローカルキャッシュ)

## ワークスペース内依存

- `kaname-error`
- `kaname-store`

## テストカバレッジ

8 ユニットテスト

## 使用例

```rust
use kaname_billing::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
