# kaname-saas-guard

> SaaS Link Safety - SaaS 経由フィッシング対策

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)

Google Drive / DocuSign / SharePoint / OneDrive 等の正当な SaaS を悪用したフィッシング攻撃を検出。

## 主要機能

- 9 種類の SaaS プラットフォーム認識 (Google Drive、OneDrive、SharePoint、DocuSign、AdobeSign、Dropbox、Box、Notion、Smartsheet)
- 送信者ごとの SaaS 利用履歴管理 (馴染み度判定)
- 偽サブドメイン検出 (docusign.evil.com 形式)
- リスク 5 段階評価 (Safe / Caution / Warn / Suspicious / Block)
- 既知悪意ドメインリスト (CTI フィード動的更新可)

## ワークスペース内依存

- `kaname-error`

## テストカバレッジ

11 ユニットテスト

## 使用例

```rust
use kaname_saas_guard::{SaasLinkInspector, SaasHistory, SaasPlatform};

let inspector = SaasLinkInspector::new();
let mut history = SaasHistory::new();

// 過去 6 回 DocuSign でやり取り済み (馴染み判定)
for _ in 0..6 {
    history.record("alice@example.com", SaasPlatform::DocuSign);
}

let detected = inspector.evaluate(
    "https://docusign.net/sign?token=abc",
    "alice@example.com",
    &history,
).unwrap();

println!("Platform: {}", detected.platform.display_name());
println!("Risk: {:?}", detected.risk);  // Safe
for reason in &detected.reasons {
    println!("  - {}", reason);
}
```

## 関連文書

- [新機能設計書 v0.2](../../docs/new-features-v0.2.md)
- [脅威モデル](../../docs/threat-model.md)
