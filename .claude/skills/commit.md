# skill: commit

コミットメッセージを Conventional Commits 形式で生成する。

## 発火条件
- 「コミットして」「commit」「変更を保存」

## フォーマット
```
<type>(<scope>): <summary>

[body: 必要な場合のみ]

[footer: BREAKING CHANGE or closes #XX]
```

## type 一覧
- feat: 新機能
- fix: バグ修正
- security: セキュリティ修正 (最優先)
- refactor: リファクタリング
- test: テスト追加・修正
- docs: ドキュメント
- chore: ビルド・依存更新
- perf: パフォーマンス改善

## scope 一覧 (Kaname クレート名)
kaname-ai, kaname-bec, kaname-mls, kaname-crypto, kaname-dlp,
kaname-oobv, kaname-pivot, kaname-radar, kaname-ssa, kaname-saas-guard,
kaname-render, kaname-store, kaname-ui, kaname-tray, kaname-billing

## 例
```
feat(kaname-radar): add SLD fallback matching for subdomain campaigns
fix(kaname-ai): Bridge rejects NaN score without panicking
security(kaname-bec): add Tycoon2FA PhaaS domain patterns
test(kaname-oobv): verify ceremony ZeroizeOnDrop at timeout
```

## Gotchas
- security タイプは通常の PR プロセスを迂回してもよい
- BREAKING CHANGE は必ず footer に明記
- scope は変更した主要クレートのみ (複数なら最重要 1 つ)
