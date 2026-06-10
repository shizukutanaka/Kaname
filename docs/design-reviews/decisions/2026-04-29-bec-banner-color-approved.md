# 決定: BEC 警告バナーの色 — Option A 承認

レビュー日: 2026-04-29
決定: ✅ **Approved**
DRI: design-lead

## 決定内容

**Option A** (プラットフォーム別 native red) を採用。

## 決定理由

1. WWDC25 で強調された "Universal Design across platforms" との整合
2. Apple ネイティブアプリの品質感を実現
3. Linux でのカスタム色も WCAG AAA を満たす
4. CSS-only 実装で工数最小

## 反対意見の検討

ai-safety-lead から「色の一貫性が薄まる懸念」が出されたが、
プラットフォーム別の native 色を使うことは Apple HIG が明確に推奨しており、
ユーザーが期待する挙動である。

## 実装担当

- DRI: frontend-lead
- 期限: v0.1.3 リリース時 (2026-05-15)
- PR: TBD

## 検証方法

- e2e/a11y.spec.ts に色変更テスト追加
- 視覚的回帰スナップショット更新
- macOS / iPhone / Linux で実機確認

## 学んだこと

- 細かいデザイン判断も DRI が決める方が速い
- プラットフォーム別の native トークンを使うパターンを他にも適用検討
