# CI テンプレート

GitHub App の権限制約 (`workflows` 権限なし) のため、`.github/workflows/` から退避したワークフロー定義。

リポジトリ管理者が手動で `.github/workflows/` へ戻すこと:

```bash
git mv ci-templates/*.yml .github/workflows/
```
