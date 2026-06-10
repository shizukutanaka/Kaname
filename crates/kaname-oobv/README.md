# kaname-oobv

> Out-of-Band Verification (別経路検証セレモニー)

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)

2026 年最大の脅威「Deepfake 音声/動画」と「VEC」への対抗策。
香港の $25.6M Deepfake 詐欺事件と同型攻撃を「儀式」で防ぐ。

## 主要機能

- 6 ワード BIP39 ベース検証フレーズ (50 ワードの安全な部分集合)
- チャレンジ番号方式 (N 番目だけを答えさせる、Deepfake 攻撃で全部聞き出せない)
- 5 分の期限 (Apple HIG transient feedback)
- 監査ログ用 AuditRecord (フレーズは記録しない、結果のみ)
- 多言語金融キーワード検出 (日本語 + 英語)

## ワークスペース内依存

- `kaname-error`

## テストカバレッジ

12 ユニットテスト

## 使用例

```rust
use kaname_oobv::{VerificationCeremony, OobvRecommender, RecommendationLevel};

let recommender = OobvRecommender::new();
let body = "至急振込先を変更してください";

if recommender.recommend(body) == RecommendationLevel::Strong {
    let mut ceremony = VerificationCeremony::new("e1", "alice@example.com");
    let phrase = ceremony.display_phrase();
    let challenge = ceremony.challenge_number();
    
    println!("以下を送信者に電話で確認:");
    for (i, word) in phrase.iter().enumerate() {
        println!("  {}: {}", i + 1, word);
    }
    println!("{}番目のワードを読み上げてもらってください", challenge);
    
    // ユーザーが入力した回答を検証
    let user_input = "cipher";
    let result = ceremony.verify(user_input);
}
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [新機能設計書 v0.2](../../docs/new-features-v0.2.md)
- [脅威モデル](../../docs/threat-model.md)
