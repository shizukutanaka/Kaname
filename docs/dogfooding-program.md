# Kaname Dogfooding Program

> "Eating your own dog food" — Apple の核心的開発文化。
> 開発者は自分が作っているプロダクトを **毎日使う**。

最終更新: 2026-04-29 | DRI: engineering-lead

---

## 1. なぜ Dogfooding か

Tim Cook は Apple 社員に常に伝えた:

> 「You can't ask customers what they want and then try to give that to them.
>  By the time you get it built, they'll want something new.」 — Steve Jobs

Apple では、新機能はまず **社内ベータ** で全 Apple 社員にロールアウトされる。
- iOS のベータは Apple 社員の iPhone に
- macOS のベータは Apple 社員の Mac に
- 自分達でバグを見つけ、ユーザーより先に修正する

**Kaname も同じことをする。** 開発者がメインメールクライアントとして使う。

---

## 2. Dogfooding 原則

### 2.1 No Dogfooding, No Release

リリース前の **6 週間以上** チーム全員が業務メールに使用する。
6 週間使ってバグが減り、UI 改善案が枯れたら初めてリリース可能。

### 2.2 開発者全員が対象

DRI 制度との整合: 全 DRI が自分の領域を **毎日触れている**ことが前提。
触れていない DRI は領域を委譲するか、立場を返上する。

### 2.3 Bug Reports は 24 時間以内に Triage

Dogfooding で発見したバグは GitHub Issue に登録 → DRI が 24 時間以内に triage。

---

## 3. 段階的ロールアウト

### Stage 1: Internal Alpha (社内 5 名)

期間: 2 週間以上
対象: コア開発者 + DRI

入手方法: GitHub Actions の `dev` ブランチビルドアーティファクト

### Stage 2: Internal Beta (社内 + 信頼できる外部 20 名)

期間: 4 週間以上
対象: 全社員 + アドバイザー + 投資家

入手方法: TestFlight (macOS) / App Store Connect

### Stage 3: Design Partner Beta (Design Partner 100 社)

期間: 2 週間以上
対象: kaname.app/dp で承認済みパートナー

### Stage 4: Public Beta

期間: 1 週間
対象: 早期アクセス希望者 (waitlist)

### Stage 5: General Availability

App Store / 公式サイト経由で全世界配布

---

## 4. Dogfooding 計測

### 必須メトリクス

| メトリクス | 目標 | 計測方法 |
|---|---|---|
| Daily Active Devs | 100% (全コア開発者) | アプリ起動ログ (オプトイン) |
| Avg Session Time | > 30 分/日 | テレメトリ |
| Reported Bugs/Week | < 5 (Stage 5 で) | GitHub Issue カウント |
| Crash-Free Rate | > 99.95% | クラッシュレポート |
| Time-to-Triage | < 24h | GitHub Actions metrics |

### Slack #kaname-dogfood チャンネル

毎日、開発者が以下を投稿:
- 🐛 見つけたバグ
- 💡 改善アイデア
- 📊 体感的なパフォーマンス
- 🔒 セキュリティ気づき

DRI がチャンネルを毎朝チェックして該当領域を triage。

---

## 5. Dogfooding ルール (誓約)

開発者は以下を誓約する:

```
私は Kaname の開発者として、以下を誓約します:

1. 自分のメインメールクライアントとして Kaname を使う
2. 1 日最低 30 分以上、Kaname を業務で使う
3. 見つけたバグや改善案を 24 時間以内に GitHub Issue に登録
4. 自分が DRI のクレートに関連する Issue を 24 時間以内に triage
5. 月次レビューで Dogfooding 体験を共有
6. リリース前に 6 週間以上 Dogfooding に参加する
```

新しいチームメンバーはこの誓約に署名 (`docs/dogfooding/oaths/{name}.md`)

---

## 6. Dogfooding チェックリスト

毎週月曜の朝、各開発者は以下を確認:

```
[  ] Kaname が起動している (ビルドが壊れていない)
[  ] 受信トレイに新着メールが届いている (JMAP 接続維持)
[  ] BEC 警告が正しく表示される (検出器の精度)
[  ] AI 要約が 3 秒以内に完了する (パフォーマンス回帰なし)
[  ] スワイプジェスチャーが反応する
[  ] Cmd+Z で取り消せる
[  ] 通知が iPhone と Mac の両方に届く (Continuity 動作)
[  ] バッテリー消費が異常でない (アイドル時 < 5%/h)
```

不具合があれば Slack に投稿。

---

## 7. Bug Bash (リリース前イベント)

リリース 2 週間前に **Bug Bash** を開催:

- 期間: 1 日 (8 時間)
- 全社員参加
- Kaname を意図的に**壊す**
- 5,000 円のバグ賞金 (重大バグ発見者に)

**ルール:**
1. 通常の使用シナリオでバグを探す (90 分)
2. 異常な使用シナリオでバグを探す (90 分)
3. アクセシビリティ監査 (60 分)
4. パフォーマンス計測 (60 分)
5. セキュリティテスト (60 分)
6. Bug Triage Session (90 分)

---

## 8. Crash-Free Rate のトラッキング

Apple は iOS のクラッシュ率を **99.99%** 以上に維持している。
Kaname の目標は **99.95%** (約 100 セッションに 1 回のクラッシュまで許容)。

### 自動レポート

`kaname-observability` クレートが crash report を自動収集:
- スタックトレース
- 直前の操作
- 環境情報 (OS, Rust バージョン)
- メール ID は **送らない** (プライバシー)

### Triage SLA

| 重大度 | 反応 |
|---|---|
| Crash on launch | 4 時間以内に hotfix |
| Data loss | 8 時間以内に hotfix |
| Crash > 1% sessions | 24 時間以内 |
| Crash < 1% sessions | 7 日以内 |

---

## 9. Dogfood Build の設定

`Cargo.toml` に dogfood feature を追加:

```toml
[features]
default = []
dogfood = [
    "kaname-observability/local-telemetry",
    "kaname-observability/crash-reports",
    "kaname-ui/dev-tools",
]
```

`cargo build --features dogfood` で社内ビルド。

このビルドは:
- ローカルでのみクラッシュレポート保存 (送信先サーバーなし)
- 開発者用デバッグツール
- 詳細ログレベル (debug)

---

## 10. Dogfood イベントカレンダー

```
Week 1-2:    Stage 1 — Internal Alpha
Week 3-6:    Stage 2 — Internal Beta + Bug Bash 1
Week 7-8:    Stage 3 — Design Partner Beta
Week 9:      Stage 4 — Public Beta
Week 10:     Stage 5 — GA Release Day
Week 11-12:  Post-Launch Monitoring
```

これを四半期サイクルで繰り返す。

---

## 11. 失敗事例 (Apple から学ぶ)

### Apple Maps 2012 (反面教師)

iOS 6 で Google Maps を Apple Maps に置換。
**社内 Dogfooding が不十分**で、ユーザー離反事件に。

教訓:
- Dogfooding 期間を短くしてはならない (6 週間以上)
- 「動く」と「使える」は違う
- DRI が責任を持ち続ける必要

### iOS 8.0.1 (緊急)

リリース後 1 時間でバッテリードレインバグが発覚。
すぐに iOS 8.0.2 がリリースされた。

教訓:
- Crash-Free Rate を必ず計測
- ロールバック手順を事前に準備
- Hotfix プロセスを定期演習

---

## 12. Dogfood 体験のレポーティング

毎月最終金曜の Design Review で、各 DRI が Dogfood 体験を 3 分で共有:

- 今月一番気持ちよかった機能
- 今月一番ストレスだった瞬間
- ユーザーが気づきにくい改善案

これがプロダクト改善の **最重要シグナル**。
ベンチマークやテレメトリよりも質的に深い。

---

## 13. 改訂履歴

| 日付 | 改訂者 | 内容 |
|---|---|---|
| 2026-04-29 | engineering-lead | 初版 — Apple Dogfooding 文化採用 |
