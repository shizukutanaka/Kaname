# Runbook: BEC アラート対応

このドキュメントは Kaname のサポートチームが BEC アラートの問い合わせに対応する手順を示す。

## 概要

ユーザーから「BEC アラートが誤検出された」または「実際に BEC 攻撃を受けた」報告を受けたときの初動対応。

## 対応フロー

```
① ユーザーから報告受付
       ↓
② アラートの種類を判別 (誤検知 / 真の攻撃 / 不明)
       ↓
   ┌──┴──┐
   ↓     ↓
 誤検知   真の攻撃
   │       │
   ④A      ④B
       ↓
   ⑤ 共通: ユーザー教育・ログ記録
```

## ① 報告受付

### 必要情報の収集
- メール ID (UI の「BEC 詳細」から取得可能)
- アラート種別 (DANGEROUS / SUSPICIOUS / ADVISORY)
- ユーザーの主張 (誤検知 / 攻撃を受けた)
- 送信者アドレス
- 件名 (機密性に応じてマスク)

### 受付テンプレート
```
件名: [BEC 報告 #YYYY-NNNN] {ユーザー報告概要}

ユーザー: {email}
報告日時: {ISO timestamp}
メールID: {email_id}
アラート: {DANGEROUS | SUSPICIOUS | ADVISORY}
ユーザー主張: {誤検知 | 攻撃 | 不明}
```

## ② アラートの種類判別

### 自動判定支援

```bash
# 監査ログから該当メールの BEC スコアと信号を取得
kaname-cli audit query --email-id={id} --include-bec-signals
```

出力例:
```
email_id: e_abc123
verdict: DANGEROUS
signals:
  domain_similarity:    0.45 (CFO@arnazon.com vs CFO@amazon.com)
  spoofing_indicator:   YES (DKIM fail)
  urgency_markers:      3 (至急, 今すぐ, 本日中)
  qr_phishing:          NO
  vec_indicator:        YES (vendor change request)
  multi_persona:        NO
  email_bombing:        NO
total_score:            0.78 (threshold: 0.65)
```

### 判別フロー

| 信号パターン | 判定 |
|---|---|
| 全信号スコア低 + ユーザー「誤検知」と主張 | おそらく誤検知 |
| domain_similarity > 0.3 + spoofing YES | 真の攻撃の可能性高 |
| vec_indicator YES + urgency_markers ≥ 2 | VEC (ベンダーメール詐欺) の可能性高 |
| multi_persona YES | 多ペルソナキャンペーンの可能性高 |

## ④A 誤検知の場合

### 確認すべきこと
- ユーザーが本当に送信者を知っているか
- 過去のメール履歴で類似メールがあったか (`kaname-cli mail history`)
- 送信者ドメインが正規のものか

### アクション
1. **即座にホワイトリスト追加** (再発防止):
   ```bash
   kaname-cli screener decide \
     --user={user_email} \
     --sender={sender_email} \
     --decision=allow_inbox
   ```

2. **ユーザーへの説明**:
   - なぜ誤検知が起きたか (どの信号が反応したか)
   - 今後どうすれば誤検知を減らせるか (送信者ホワイトリスト機能)

3. **モデル改善ログ**:
   - `false_positives.jsonl` に追加 (個人情報マスク済み)
   - 月次で BEC モデルチームがレビュー → ルール更新

### ユーザー返信テンプレート
```
{ユーザー名} 様

ご報告ありがとうございます。{送信者} からのメール (件名: {マスク件名}) について確認しました。

このメールは Kaname の BEC 検出が誤って警告したもので、実際には安全です。
理由: {主信号の説明、例: 送信者ドメインが過去に少数しか使われていなかったため}

今後同じ送信者からのメールが警告されないよう、ホワイトリストに追加しました。

誤検知の発生を抑えるため、報告をモデル改善チームと共有しました。

ご不便をおかけして申し訳ありません。
Kaname サポート
```

## ④B 真の攻撃の場合

### 即座のアクション (5分以内)

1. **ユーザーが既に行動した場合の被害判定**:
   - 振り込みを実行したか?
   - 添付を開いたか?
   - リンクをクリックしたか?
   - 返信したか?

2. **被害ありの場合**:
   - **送金**: ユーザーの銀行に即座連絡指示。組み戻し依頼。
   - **マルウェア感染**: デバイス隔離指示。IT セキュリティチームへエスカレーション。
   - **認証情報漏洩**: パスワード即時変更。MFA 全有効化。

### 同組織内の他ユーザーへの影響確認

```bash
# 同じ送信者からのメールを受け取った他ユーザーを検索
kaname-cli admin search \
  --sender={attacker_email} \
  --org={organization_id} \
  --since=7d
```

該当ユーザーには即座に警告メールを送信。

### 攻撃インテリジェンスの収集

1. **メールサンプルの保存** (改ざん防止形式):
   ```bash
   kaname-cli forensics export \
     --email-id={id} \
     --format=eml-with-headers \
     --output=/forensics/{date}/{ticket}.eml
   ```

2. **共有インテリジェンス DB に登録**:
   - 送信者ドメイン
   - 件名パターン
   - 添付ハッシュ
   - リンク URL (defanged)

3. **法執行機関への連絡判断**:
   - 被害額 ≥ 100万円: 警察庁サイバー犯罪相談窓口へ報告勧奨
   - 被害額 ≥ 1,000万円: FBI IC3 (国際攻撃の場合) へ報告

### ユーザー返信テンプレート (緊急)
```
件名: 【至急】BEC 攻撃の確認 - 対応のお願い

{ユーザー名} 様

ご報告いただいた {送信者} からのメールは、
ビジネスメール詐欺 (BEC) と確認されました。

【すぐにご対応ください】
1. このメールに返信しない
2. 記載されたリンク・添付を開かない
3. 振り込みを行った場合: 銀行へ即座に組み戻し依頼
4. 同じ攻撃を受けた可能性のある同僚に注意喚起

【Kaname の対応】
- 同送信者からの今後のメールを全ユーザー宛にブロック
- セキュリティチームへエスカレーション完了
- 必要に応じて法執行機関への報告を支援

ご不安な点があればすぐにご連絡ください。
24時間対応: support-emergency@kaname.app

Kaname セキュリティチーム
```

## ⑤ 共通対応

### ログ記録 (必須)
すべてのインシデントは `incidents.jsonl` に記録:
```json
{
  "id": "INC-2026-04-26-0123",
  "type": "bec_alert",
  "verdict": "true_positive",
  "user_email": "***@example.com",
  "sender_email": "cfo@arnazon-billing.com",
  "subject_hash": "abc123...",
  "reported_at": "2026-04-26T14:23:00Z",
  "resolved_at": "2026-04-26T14:45:00Z",
  "actions_taken": ["whitelist_no", "law_enforcement_contacted", "internal_alert_sent"],
  "damage_jpy": 0,
  "lessons_learned": "VEC indicator was correct"
}
```

### 月次レビュー
- 全 BEC アラートの **誤検知率** を計算 (目標: < 3%)
- **真陽性率** を計算 (目標: > 95%)
- 漏れた攻撃の事後分析

### モデル改善
- 誤検知ログを月次で BEC モデルチームに渡す
- 真陽性ログを攻撃インテリジェンス DB に統合

## エスカレーション基準

| 条件 | エスカレーション先 |
|---|---|
| 被害額 ≥ 1,000万円 | CTO + 法務 |
| 同組織内 ≥ 5 ユーザーが標的 | CSO |
| 新しい攻撃手法 (既知パターンに該当しない) | BEC モデルチーム |
| 法執行機関の協力要請 | 法務 |

## 関連ドキュメント
- [docs/threat-model.md](../threat-model.md) — BEC 脅威モデル
- [docs/adr/0001-dual-llm-type-safety.md](../adr/0001-dual-llm-type-safety.md)
- [SECURITY.md](../../SECURITY.md) — 脆弱性報告ポリシー

---

**最終更新**: 2026-04-26
**Runbook 版**: 1.0
**DRI**: kaname-bec チーム + サポートリード
