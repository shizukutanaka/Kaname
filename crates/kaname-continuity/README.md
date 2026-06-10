# kaname-continuity

> Apple デバイス間の連続性層

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- **Handoff**: iPhone で読み始めたメールを Mac で続ける
- **Universal Clipboard**: 添付参照を全デバイス間でコピー
- **Universal Drafts**: MLS 暗号化されたドラフトを iCloud で同期
- **Notification Continuity**: 通知から最適デバイスへ遷移

## ワークスペース内依存

- `kaname-error`

## テストカバレッジ

11 ユニットテスト

## 使用例

```rust
use kaname_continuity::*;

let mut handoff = HandoffEngine::new();
handoff.enable();
let activity = HandoffActivity::ReadingEmail {
    email_id: "e1".into(),
    scroll_position: 0.5,
    summary_shown: true,
    started_at: 1714000000,
};
handoff.advertise(activity)?;
```

## 関連文書

- [統一デザイン仕様書](../../docs/design-v0.2-apple-platforms.md)
- [プロジェクト全体 README](../../README.md)
