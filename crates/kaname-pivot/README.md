# kaname-pivot

> Cross-Channel Pivot Detection (横展開攻撃検出)

2026 年マルチチャネル攻撃への対抗策。
メール → Teams/Slack/Zoom/電話 への誘導を検出し、UI に意図的な摩擦を加える。

## 検出パターン

- 電話番号 (国際/日本/英米フォーマット)
- Microsoft Teams 会議リンク
- Slack 招待・DM リンク
- Zoom 会議 (パスワード付き判定)
- Google Meet
- DocuSign / Google Drive / OneDrive / SharePoint
- Bitcoin / Ethereum ウォレットアドレス

## 主要 API

```rust
let detector = PivotDetector::new();
let pivots = detector.analyze(email_body);
let trust = detector.trust_score(&pivots, &history);
```

## テストカバレッジ

16 ユニットテスト
