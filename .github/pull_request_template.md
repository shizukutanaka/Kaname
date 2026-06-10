## 概要

<!-- このPRが何を変更するか、なぜ必要か -->

## 変更タイプ

- [ ] バグ修正 (既存機能の修正)
- [ ] 新機能 (互換性を保つ機能追加)
- [ ] 破壊的変更 (既存 API の変更)
- [ ] セキュリティ修正 (脆弱性対応)
- [ ] ドキュメント
- [ ] パフォーマンス
- [ ] リファクタリング
- [ ] 依存関係の更新

## DRI 確認

このPRは以下のモジュールに影響します:

- [ ] kaname-ai (要 2 名レビュー)
- [ ] kaname-mls (要 2 名レビュー)
- [ ] kaname-bec
- [ ] kaname-dlp
- [ ] kaname-store
- [ ] kaname-render
- [ ] kaname-sandbox
- [ ] kaname-billing
- [ ] フロントエンド (TSX)
- [ ] CI / ビルド

## チェックリスト

### コード品質
- [ ] `cargo nextest run --workspace` 通過
- [ ] `cargo clippy --workspace -- -D warnings` 通過
- [ ] `cargo fmt --check` 通過
- [ ] `npm run typecheck && npm run lint` 通過
- [ ] 新規コードに対するテストを追加

### セキュリティ
- [ ] `Content<Untrusted>` の取り扱いに変更がない、または安全に検証済
- [ ] `unsafe` ブロックを追加していない (追加した場合は justification を記述)
- [ ] 新しい依存を追加していない、または `deny.toml` で許可済み
- [ ] 機密情報をログに出力していない

### ドキュメント
- [ ] CHANGELOG.md を更新
- [ ] 公開 API に変更がある場合は doc コメントを更新
- [ ] threat-model.md に影響がある場合は更新

## 関連 Issue

Closes #

## テスト方法

<!-- レビュアーが手動で確認する手順 -->

## スクリーンショット (UI 変更時)

<!-- 変更前後のスクリーンショット -->
