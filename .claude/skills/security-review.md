# Security Review Skill

## トリガー
セキュリティレビューが必要な変更: 認証/暗号/AI/バリデーション/入力処理

## チェックリスト

### Dual-LLM 境界
- [ ] Content<Untrusted> が PrivilegedLlm に渡っていない
- [ ] Bridge の 6 段階検証を通過していない Untrusted データが存在しない
- [ ] 新しい `pub fn` が適切な型で境界を強制している

### 入力検証
- [ ] 全外部入力がホワイトリストバリデーションを通過する
- [ ] SQL は ORM またはプリペアドステートメントのみ
- [ ] ファイルパストラバーサルが防止されている

### 暗号
- [ ] 新しい暗号プリミティブが ML-KEM-768/Ed25519/AES-256 を使用
- [ ] ハードコードされた秘密情報がない (gitleaks で確認)
- [ ] 乱数が `rand::thread_rng()` (CSPRNG) を使用

### プライバシー (I5)
- [ ] PII がログに出力されない (PrivacySanitizer を通している)
- [ ] メール本文テキストが kaname-ssa/kaname-radar で保存されない

### エラー処理
- [ ] `.unwrap()` が本番コードにない
- [ ] エラーメッセージに内部詳細が含まれない

## Gotchas

- `Content<Untrusted>` を `as_text()` で取り出してもそのまま DB に保存しない
- Bridge の attack_markers リストは大文字小文字無視比較 (`.to_lowercase()`)
- PhaaS ドメインパターンは定期的に更新が必要 (Tycoon2FA 等は頻繁に変化)
