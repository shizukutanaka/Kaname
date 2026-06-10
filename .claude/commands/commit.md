# /commit

コードを分析して Conventional Commits 形式のメッセージを生成する。

## 形式
```
<type>(<scope>): <subject>

<body>

<footer>
```

## タイプ
- feat: 新機能
- fix: バグ修正
- security: セキュリティ修正 (脆弱性対応)
- refactor: リファクタリング
- test: テスト追加/修正
- docs: ドキュメント
- chore: ビルド/CI/依存関係

## スコープ
kaname-ai / kaname-bec / kaname-ui / kaname-render / kaname-radar 等

## 例
```
security(kaname-bec): add AiTM proxy detection for Tycoon2FA

Detect AiTM phishing proxies via URL parameter analysis.
Matches Tycoon2FA PhaaS infrastructure patterns.

Closes #42
```
