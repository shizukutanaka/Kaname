# Runbook: SQLCipher データベース破損

> 想定対応時間: 30 分以内
> リスク: ユーザーデータ消失の可能性

## 症状

- アプリ起動時に SQLCipher エラー
- `KanameError::Database` がスポラディックに発生
- 一部メールが消失
- 検索結果が不整合

## 即時対応

1. **アプリを停止** (これ以上の書き込みを防ぐ)

2. **DB ファイル特定**
   ```
   macOS:   ~/Library/Application Support/kaname/history.db
   Linux:   ~/.local/share/kaname/history.db
   Windows: %APPDATA%\kaname\history.db
   
   ※ ファイル名は `history.db` (`kaname.db` ではない)。同じディレクトリの
   `history.key` (64桁 hex, 0600) が SQLCipher 鍵。
   ```

3. **バックアップ作成** (必須、これ以上の操作前)
   ```bash
   cp history.db history.db.bak.$(date +%Y%m%d-%H%M%S)
   ```

## 復旧手順

### 軽度な破損 (整合性チェック失敗)

```bash
# DB は SQLCipher 暗号化のため平文では開けない。key は history.key の hex。
sqlcipher history.db
> PRAGMA key = "x'$(cat history.key | tr -d '\n')'";
> PRAGMA integrity_check;
> .recover
> .save history.db.recovered
> .quit
```

### 重度な破損 (ヘッダー破損)

1. JMAP サーバーから完全再同期
2. ローカル下書きは `history.db.bak` から手動抽出 (要 SQL クエリ)
3. ユーザーには「メールは安全、ローカルキャッシュを再構築中」と通知

## データ消失防止

- 自動バックアップは未実装 — `history.db` の定期的な手動バックアップを推奨
- 監査ログのハッシュチェーンで改ざん検出 (`AuditLog::verify_chain`)
- WAL モードで電源断耐性

## エスカレーション

DB 破損が頻発する場合:
- `kaname-store` の `WAL` 設定を確認
- ファイルシステム自体の問題 (smartctl, fsck)
