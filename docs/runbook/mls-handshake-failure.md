# Runbook: MLS ハンドシェイク失敗

> 想定対応時間: 15 分以内
> リスク: 暗号化メールが送受信不能

## 症状

- 受信した E2E メールが「復号できません」表示
- `kaname-mls` が `MlsKeyExchange` エラー
- 安全番号の変更通知が表示される
- ログに `openmls::treesync::TreeSyncError`

## 即時対応

1. **状況の特定**
   - 自分のキーが変更されたか? (デバイス追加/削除)
   - 相手のキーが変更されたか? (相手のデバイス追加)
   - 単一の相手だけか、全員か?

2. **Safety Number 検証**
   - 設定 → セキュリティ → Safety Number Ceremony
   - 別経路 (電話・対面) で番号確認
   - 一致しない場合: **送信者の身元を疑え**

## 復旧手順

### キーローテーション直後

```
ユーザー操作:
  1. 受信トレイ → 復号失敗メール → 「再要求」
  2. 相手側で MLS Update commit を生成
  3. Welcome メッセージ受領後、エポックが揃う
```

### グループメンバーシップ不一致

`kaname-mls::IncomingResult::EpochMismatch` の場合:
- 過去のエポックは復号できない (Forward Secrecy 保証)
- 新しいメッセージは正常に復号できることを確認

### 攻撃の可能性

Safety Number が一致しない場合:
- メッセージを開かない
- 送信者に別経路で連絡
- `kaname-observability` の `safety_number_mismatch` メトリクスを記録
- セキュリティチームに報告

## 根本原因

- `kaname-mls::Client::commit()` の実装バグ
- openmls のバージョン不整合
- 中間者攻撃 (極めて稀、Safety Number で検出される)
