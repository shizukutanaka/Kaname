# BEC 警告バナーの色

## 提案者
- DRI: design-lead
- 日付: 2026-04-29

## 解決したい問題

現在の BEC 警告バナーの赤色 `#FF4444` は Apple iOS の System Red `#FF453A` と
わずかに異なる。プラットフォーム横断統一性 (WWDC25 Liquid Glass 哲学) を
最優先するなら、OS native red を使うべき。

しかし `#FF4444` のほうが暗い背景でわずかにコントラスト比が高く、
WCAG AAA をマージンを持って満たす。

## 提案する解決策

### Option A (推奨)
**iOS / macOS では System Red `#FF453A`、Linux では `#FF4444` を使う**

各プラットフォームの native red トークンを使用。
プラットフォーム横断統一性とアクセシビリティを両立。

```css
:root {
  --k-bec-danger: #FF4444;          /* デフォルト */
}

@supports (-apple-system: red) {
  :root {
    --k-bec-danger: -apple-system-red;  /* iOS/macOS native */
  }
}
```

### Option B
**全プラットフォームで `#FF4444` を維持**

Kaname 独自の色として一貫性を保つ。
プラットフォーム独立性の観点では強い。

### Option C
**全プラットフォームで System Red `#FF453A` に統一**

Apple HIG 準拠を最優先。Linux も同じ赤を使用。
WCAG AAA は引き続き満たす (5% コントラスト差)。

## なぜこの北極星に整合するか

> AI が助けても裏切らない

直接の関連は低いが、Liquid Glass デザイン言語の一貫性は
ユーザーに「Apple ネイティブアプリの品質」を伝える。
Kaname の信頼性に間接的に貢献。

## 競合との比較

| プロダクト | 警告色 |
|---|---|
| Outlook | カスタム赤 (`#A4262C`) |
| Gmail | Material Red (`#D93025`) |
| Spark | iOS System Red |
| Superhuman | カスタム赤 (`#FF3B30`) |
| **Kaname (Option A)** | **iOS System Red + Kaname Red** |

## アクセシビリティ

| Option | macOS contrast | iOS contrast | Linux contrast |
|---|---|---|---|
| A | 7.6:1 (System) | 7.6:1 (System) | 8.1:1 (Custom) |
| B | 8.1:1 | 8.1:1 | 8.1:1 |
| C | 7.6:1 | 7.6:1 | 7.6:1 |

全 Option で WCAG AAA (7:1) を満たす。

## セキュリティ影響

なし (色のみ)

## パフォーマンス影響

なし (CSS 変数のみ)

## 実装コスト

- フロントエンド: 0.5 人日
- テスト追加: 視覚的回帰スナップショット更新
- ドキュメント: design-v0.2 の表を更新

## リリース計画

v0.1.3 で実装 (緊急性なし)
