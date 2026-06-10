# Runbook: JMAP サーバー切断

> 想定対応時間: 5 分以内

## 症状

- アプリ右下に「オフライン」インジケーター
- 新着メールが届かない
- `mail_get_summary` が `KanameError::JmapConnection` を返す
- ログに `reqwest::Error: connection refused` 等

## 即時対応

1. **ユーザー側ネットワーク確認**
   - DNS 解決: `nslookup mail.example.com`
   - TLS 接続: `openssl s_client -connect mail.example.com:443`
   - HTTPS 到達: `curl -v https://mail.example.com/.well-known/jmap`

2. **オフラインモード確認**
   - 設定 → アカウント → 同期一時停止 中ではないか
   - フォーカスフィルターで JMAP が無効化されていないか

3. **認証トークン期限確認**
   - 設定 → アカウント → 「再認証が必要」の表示有無
   - OAuth トークンの期限切れは自動再認証されるが、IMAP/JMAP API キーは手動更新必要

## 復旧手順

```
ユーザー操作:
  1. メニューバー → 「再接続」をクリック
  2. ステータスダッシュボードで接続状態を確認
  3. 30 秒以内に「オンライン」に戻ることを確認

復旧しない場合:
  1. アプリ再起動 (Cmd+Q → 再起動)
  2. それでも復旧しない: docs/runbook/escalation.md へ
```

## オフライン中の動作保証

Kaname はオフラインファースト設計:
- ローカルキャッシュからメール読み取り可能
- 下書き保存・編集は SQLCipher にローカル保存
- 復旧時に自動同期 (変更は保持される)

## 根本原因の調査

サーバー側の問題か、ユーザー側か:
- サーバー応答ヘッダーを `Network` ペインで確認
- `kaname-observability` のメトリクス `jmap_errors` をチェック
- 直近 1 時間の `jmap_requests` 成功率
