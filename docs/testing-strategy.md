# Kaname テスト戦略

> "Quality is not an act, it is a habit." — Aristotle (Apple HIG 引用)

Kaname は 384 の Rust テスト、31 vitest、19 Playwright E2E、3 ファジングターゲット、8 proptestを持つ。本ドキュメントは**それぞれの存在意義**と**いつ何を書くべきか**を定義する。

---

## テスト層の責務

### 1. ユニットテスト (Rust)

**目的**: 関数・モジュール単体の正しさ証明  
**規模**: 303 件  
**実行**: `cargo nextest run --workspace` (約 30 秒)

**書く基準**:
- 全ての `pub` 関数に最低 1 テスト
- 正常系 + 異常系 + 境界値の 3 ケース
- ファイル内の `#[cfg(test)] mod tests` 内に配置

**特に重要なクレート**:
- `kaname-ai/src/dual_llm.rs` — 22 テストで型安全コア検証
- `kaname-oobv` — 14 テストでセレモニーロジック
- `kaname-pivot` — 17 テストで横展開検出
- `kaname-bec` — 8 proptestでスコア不変条件

---

### 2. プロパティテスト (proptest)

**目的**: 「全ての入力に対する不変条件」を数千ケースで検証  
**規模**: 14 件 (`kaname-bec/tests/property_tests.rs`)  
**実行**: `cargo test -p kaname-bec --test property_tests`

**書く基準**:
- 数学的不変条件 (Levenshtein 三角不等式、対称性)
- スコアの範囲 (0.0..=1.0)
- 単調性 (悪い特徴を追加してもスコアは下がらない)
- 決定性 (同じ入力 → 同じ出力)

**ユニットテストとの違い**:
- ユニットテスト: 100 ケース手動 → 101 ケース目で破綻するかも
- プロパティテスト: proptest が反例を自動探索

---

### 3. 統合テスト

**目的**: モジュール間連携の正しさ  
**場所**: `crates/kaname-tests/src/integration.rs`  
**実行**: `cargo test -p kaname-tests`

**例**:
- `kaname-jmap` → `kaname-render` → `kaname-bec` のパイプライン
- `kaname-store` + `kaname-crypto` の暗号化保存・復号
- `kaname-ai` の Bridge + `kaname-ui` のコマンド統合

---

### 4. 敵対テスト (Adversarial Tests)

**目的**: 既知の攻撃ペイロードへの耐性証明  
**規模**: 50 ペイロード × 7 カテゴリ  
**場所**: `crates/kaname-tests/src/adversarial.rs`

**カテゴリ**:
1. プロンプト注入 (Superhuman CVE 系)
2. BEC ドメインタイポスクワット
3. XSS (mXSS, SVG XSS, data URI)
4. MIME 攻撃 (zip bomb, nested boundary)
5. DLP バイパス試行
6. Deepfake 添付シナリオ
7. 横展開誘導 (Teams/Slack/暗号通貨)

---

### 5. ファジングテスト (cargo-fuzz)

**目的**: 任意バイト列で未知のクラッシュ発見  
**規模**: 3 ターゲット + 12 シード  
**実行**: `npm run fuzz:prompt` / `:mime` / `:html`

**ターゲット**:
- `mime_parser` — RFC 2045-2049 パーサーの堅牢性
- `html_sanitizer` — XSS 攻撃に対する不変条件 (許可リスト)
- `prompt_injection` — Bridge 検証ロジックの動的検証

**CI**:
- PR ごと: 2 分実行
- main マージ後: 30 分
- 週次: 4 時間 (大規模回帰検出)

---

### 6. E2E テスト (Playwright)

**目的**: ユーザー視点での北極星デモシーン保証  
**規模**: 19 件 (`e2e/north-star-demo.spec.ts`)  
**実行**: `npm run test:e2e`

**カバーする UX フロー**:
- BEC メール → 赤色バナー表示
- AI 要約 → 「このメール 1 通のみ」セキュリティ証明
- Cmd+Z でアーカイブ取り消し
- スワイプジェスチャー
- 自然言語検索「先週のメール」
- キーボードのみで全操作
- 視覚的回帰 (Liquid Glass スクリーンショット)
- コールドスタート < 800ms

---

### 7. アクセシビリティ自動テスト (axe-core)

**目的**: WCAG AAA 自動検証  
**規模**: 9 件 (`e2e/a11y.spec.ts`)  
**実行**: `npm run test:a11y`

**検証項目**:
- 受信トレイ・メール詳細の WCAG 違反ゼロ
- 全インタラクティブ要素にフォーカスリング
- コントラスト比 7:1 以上 (`color-contrast-enhanced`)
- アイコンボタンの ARIA ラベル必須
- BEC 警告は色だけでなくテキストでも示される (色覚多様性)
- Reduce Motion で transition 短縮

---

### 8. パフォーマンスベンチマーク (criterion)

**目的**: パフォーマンス回帰検出  
**場所**: `crates/kaname-tests/benches/core_bench.rs`  
**実行**: `cargo bench --bench core_bench`

**ベンチマーク対象 + 目標値**:
- BEC スコア計算: < 50ms (p99)
- AI 要約生成: < 3 秒 (Phi-4-mini ローカル)
- メール一覧トリアージ: < 1ms
- DLP ラベル判定: < 20ms

---

## CI 実行マトリクス

| トリガー | ユニット | プロパティ | 統合 | 敵対 | ファジング | E2E | a11y | ベンチ |
|---|---|---|---|---|---|---|---|---|
| PR | ✓ | ✓ | ✓ | ✓ | 2 分 | UI 変更時 | UI 変更時 | △ |
| main マージ | ✓ | ✓ | ✓ | ✓ | 30 分 | ✓ | ✓ | ✓ |
| 週次 | ✓ | ✓ | ✓ | ✓ | 4 時間 | ✓ | ✓ | ✓ |
| リリース前 | ✓ | ✓ | ✓ | ✓ | 4 時間 | ✓ | ✓ | ✓ |

---

## テスト追加時の意思決定

```
新機能追加 PR
    ↓
[1] pub 関数を追加? → ユニットテスト必須
    ↓
[2] 不変条件を持つ? → プロパティテスト追加
    ↓
[3] 複数モジュール連携? → 統合テストを kaname-tests/ に
    ↓
[4] 攻撃面を変える? → 敵対テスト追加 (50 ペイロードに追加)
    ↓
[5] パーサー/サニタイザー? → ファジングターゲット拡張
    ↓
[6] UI に影響? → E2E テスト追加 + 視覚的回帰スクリーンショット
    ↓
[7] アクセシビリティに影響? → a11y.spec.ts に追加
    ↓
[8] 性能クリティカル? → criterion ベンチマーク追加
```

---

## カバレッジ目標

| クレート | 目標 | 現状 |
|---|---|---|
| `kaname-ai`  | 95% | 91% |
| `kaname-bec` | 90% | 87% |
| `kaname-mls` | 90% | 85% |
| その他       | 80% | 75-85% |

---

## 改訂履歴

| 日付 | 改訂者 | 内容 |
|---|---|---|
| 2026-04-29 | @kaname-app/lead | 初版 — 8 層テスト戦略の体系化 |
