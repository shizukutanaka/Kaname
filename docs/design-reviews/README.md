# Kaname Design Review System

> Apple "Friday Design Reviews" のジョナサン・アイブ時代に確立されたプロセスを踏襲。
> Steve Jobs/Tim Cook が出席して全プロダクトを精査した文化を再現する。

最終更新: 2026-04-29 | DRI: design-lead

---

## 1. なぜ Design Review か

Apple の Friday Design Reviews は、ジョナサン・アイブと Steve Jobs (後に Tim Cook) が
**全プロダクトを精査する** 場として機能した。

特徴:
- **CEO が出席する** (誰も委任しない)
- **小さい部屋** (8〜12 人) で集中
- **過去のデザインも振り返る** (毎週同じプロダクトを見る)
- **何でも変更可能** (リリース前まで)

Kaname もこれを実装する。週 1 で必ず開催。

---

## 2. 形式

### 開催頻度

毎週金曜日 14:00 - 16:00 (JST)

### 参加者 (固定 5〜8 名)

- **Design Lead** (司会、議事録)
- **Frontend Lead** (実装責任者)
- **AI Safety Lead** (型安全性レビュー)
- **CEO / Founder** (最終決定権、必ず出席)
- **Architecture Lead**
- **任意ゲスト**: 該当機能の DRI

### スコープ

毎回最大 3 機能まで。深く議論する。

---

## 3. レビュー対象

以下のすべてを Design Review にかける:

✓ **新機能の UI 提案** (実装前)
✓ **Spring Animation の感触** (実装後の調整)
✓ **エラーメッセージの文言**
✓ **オンボーディングフロー**
✓ **アイコンとカラー**
✓ **既存機能の改善** (毎月最低 1 つ)
✓ **競合プロダクトの分析**
✓ **Apple HIG 違反の確認**

レビュー**しない**もの:
- 純粋なバグ修正
- ライブラリ更新
- 内部リファクタリング (UI に影響しない)
- セキュリティパッチ (緊急対応)

---

## 4. 提案テンプレート

レビューに持ち込む全提案は、以下のテンプレートで提出 (`docs/design-reviews/proposals/{YYYY-MM-DD}-{slug}.md`):

```markdown
# {タイトル}

## 提案者
- DRI: {名前}
- 日付: {YYYY-MM-DD}

## 解決したい問題
{1-2 段落で具体的に}

## 提案する解決策

### Option A (推奨)
{詳細 + スクリーンショット/モックアップ}

### Option B (代替)
{詳細 + 比較}

### Option C (最小実装)
{詳細}

## なぜこの北極星に整合するか

> AI が助けても裏切らない

{なぜこの提案が北極星に近づくか?}

## 競合との比較

| 機能 | Outlook | Spark | Superhuman | Kaname (提案後) |
|---|---|---|---|---|
| {機能} | △ | ✓ | ✓ | ✅ |

## アクセシビリティ

- WCAG AAA 準拠 ?
- VoiceOver 対応 ?
- Reduce Motion 対応 ?
- キーボード操作可能 ?

## セキュリティ影響

{攻撃面の変化、新規リスク、緩和策}

## パフォーマンス影響

{Apple HIG 目標との整合)
- 起動時間 (FMP < 800ms) 影響: {} ms
- BEC 検出 (< 50ms) 影響: {} ms
- AI 要約 (< 3s) 影響: {} ms

## 実装コスト

- フロントエンド: {人日}
- バックエンド: {人日}
- テスト追加: {件}
- ドキュメント: {ページ}

## リリース計画

- v0.X で実装
- マイグレーション必要 ? Yes/No
```

---

## 5. レビュー進行 (40 分/機能)

### Phase 1: Context (5 分)
提案者が問題と解決策を概説。詳細スライド禁止 (議論時間を圧迫する)。

### Phase 2: Demo (10 分)
動くプロトタイプを実機/エミュレータで触る。**Mock の絵だけは禁止**。
動かない提案は審議すらしない (Apple の鉄則)。

### Phase 3: Critical Discussion (15 分)

各参加者が以下の観点で**短く** (各 1 分以内) コメント:

- **Visual** — Liquid Glass、色、スペーシング
- **Interaction** — 操作の自然さ、エラー回復
- **Performance** — Apple HIG 目標との整合
- **Accessibility** — WCAG AAA、Reduce Motion
- **Security** — 攻撃面、データフロー
- **Strategic** — 北極星との整合、競合との差異化

司会 (Design Lead) は議論をタイムボックスに収める。

### Phase 4: Decision (10 分)

**3 つの結論のいずれか**:

1. ✅ **Approved** — 実装に進む
2. 🔄 **Iterate** — 修正点を明確にして次週再提出 (最大 3 回)
3. ❌ **Killed** — 北極星と合わない、または ROI が低い

CEO が最終決定権を持つ。**多数決ではない**。

決定は同日中に `docs/design-reviews/decisions/{YYYY-MM-DD}-{slug}.md` に記録。

---

## 6. アンチパターン

### ❌ やってはいけないこと

- **「もっと議論しましょう」を 3 週連続** → タイムリミットを設けて Kill する
- **「全員が同意するまで」** → 全員一致は不可能。CEO が判断
- **「他社もやっている」** → Kaname の北極星と関係ない
- **「とりあえず実装して様子を見る」** → デザインリソース浪費、ユーザー混乱
- **絵だけのモック** → 動くプロトタイプ必須

### ✅ やるべきこと

- **動くプロトタイプ** で議論
- **タイムボックス** を厳守 (40 分超過したら次週)
- **書記** が議事録を即時公開
- **過去の決定をひっくり返してよい** (Apple の哲学)
- **小さく速く** 反復する

---

## 7. レビュー履歴の管理

### ディレクトリ構造

```
docs/design-reviews/
├── README.md                 # この文書へのリンク
├── proposals/                # 提案書
│   ├── 2026-04-29-bec-banner-color.md
│   ├── 2026-05-06-quick-look-shortcut.md
│   └── ...
└── decisions/                # 決定書 (Approved/Iterated/Killed)
    ├── 2026-04-29-bec-banner-color-approved.md
    ├── 2026-05-06-quick-look-shortcut-iterated.md
    └── ...
```

### 命名規則

`{YYYY-MM-DD}-{kebab-case-title}-{decision}.md`

decision: `approved` / `iterated-1` / `iterated-2` / `iterated-3` / `killed`

### 検索可能性

- `grep -r "approved" docs/design-reviews/` で承認済み一覧
- `git log --diff-filter=A docs/design-reviews/` で歴史追跡

---

## 8. メトリクス (Quarterly Review)

四半期に 1 度、以下のメトリクスを集計:

- レビューした提案数
- Approved / Iterated / Killed の比率 (理想: 30/50/20)
- 1 提案あたりの議論時間 (中央値)
- リリース後にデザイン変更が必要だった機能の比率
- リリース後 90 日のユーザーフィードバックスコア

これを `docs/design-reviews/quarterly/{YYYY-Q#}.md` に記録。

---

## 9. 例: 初回 Design Review (2026-04-29)

### アジェンダ

1. **BEC 警告バナーの色** (DRI: design-lead)
   - Option A: Apple iOS Red `#FF453A` (システム標準)
   - Option B: Kaname Custom Red `#FF4444` (現行)
   - Option C: グラデーション (現行 → ダーク)

2. **AI 要約セキュリティ証明の文言** (DRI: ai-safety-lead)
   - Option A: 「このメール 1 通のみ分析」
   - Option B: 「他のメールは読みません」
   - Option C: 両方表示

3. **Cmd+Z トースト表示時間** (DRI: frontend-lead)
   - 現行: 5 秒
   - Option A: 3 秒 (Apple HIG 推奨)
   - Option B: 7 秒 (高齢者対応)
   - Option C: ユーザー設定

### 期待する成果

- 3 つすべて決定
- 議事録を当日中に公開
- Approved されたものは翌週から実装

---

## 10. 参考文献

- "Designed by Apple in California" (Apple book)
- Walter Isaacson "Steve Jobs"
- Tony Fadell "Build" (Chapter on design reviews)
- Jony Ive's Vogue interview (2018)

---

## 11. 改訂履歴

| 日付 | 改訂者 | 内容 |
|---|---|---|
| 2026-04-29 | design-lead | 初版 — Apple Friday Reviews 採用 |
