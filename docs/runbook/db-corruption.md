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
   macOS:   ~/Library/Application Support/Kaname/kaname.db
   Linux:   ~/.local/share/kaname/kaname.db
   Windows: %APPDATA%\Kaname\kaname.db
   ```

3. **バックアップ作成** (必須、これ以上の操作前)
   ```bash
   cp kaname.db kaname.db.bak.$(date +%Y%m%d-%H%M%S)
   ```

## 復旧手順

### 軽度な破損 (整合性チェック失敗)

```bash
sqlcipher kaname.db
> .recover
> .save kaname.db.recovered
> .quit
```

### 重度な破損 (ヘッダー破損)

1. JMAP サーバーから完全再同期
2. ローカル下書きは `kaname.db.bak` から手動抽出 (要 SQL クエリ)
3. ユーザーには「メールは安全、ローカルキャッシュを再構築中」と通知

## データ消失防止

- 自動バックアップ: 毎日深夜、最新 7 日分を保持
- 監査ログのハッシュチェーンで改ざん検出 (`AuditLog::verify_chain`)
- WAL モードで電源断耐性

## エスカレーション

DB 破損が頻発する場合:
- `kaname-store` の `WAL` 設定を確認
- ファイルシステム自体の問題 (smartctl, fsck)
