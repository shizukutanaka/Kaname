# Kaname デザインシステム

> v0.2 — Apple Platforms 準拠版 (2026-04-29 採用)  
> 旧版 v0.1 は `archive/design-v0.1-deprecated.md` に保管


> 「One design language, every Apple platform」
> WWDC25 のプラットフォーム横断デザイン哲学を Kaname に適用

最終更新: 2026-04-28 | DRI: kaname-design

---

## 1. 設計原則

Apple は WWDC25 で iOS 26 / macOS 26 / iPadOS 26 / watchOS 26 / tvOS 26 / visionOS 26 を **単一の Liquid Glass デザイン言語** で統一した。Kaname も同じ哲学に従う。

### 北極星デザイン原則

1. **Continuity (連続性)** — どのデバイスでも同じユーザー体験
2. **Adaptive (適応性)** — 各プラットフォームの特性に合わせる
3. **Glass (ガラス性)** — Liquid Glass マテリアルで奥行きと質感を表現
4. **Privacy by Design** — セキュリティ可視化が UI の中心

### Kaname Design DNA

```
                ┌──────────────────────┐
                │   Liquid Glass       │  ← マテリアル
                │   #00C4CC ベース    │  ← ブランド色
                │   Spring physics    │  ← アニメーション
                │   WCAG AAA          │  ← アクセシビリティ
                └──────────┬───────────┘
                           │
        ┌──────────┬───────┴───┬────────────┐
        ▼          ▼           ▼            ▼
     macOS      iOS         iPadOS       visionOS
   (主戦場)    (Reading)   (Triage)     (Future)
```

---

## 2. プラットフォーム別適応

### 2.1 macOS (主プラットフォーム)

**スコープ:** 全機能を網羅。デスクトップでメール処理を行う前提。

**特徴:**
- 3 ペインレイアウト (サイドバー / リスト / 詳細)
- ⌘K コマンドパレット
- メニューバー Extra で常駐
- Spotlight 統合 (将来)
- スワイプジェスチャー (トラックパッド)

**Liquid Glass 実装:**
```css
.k-sidebar {
  background: rgba(13,18,25,.72);
  backdrop-filter: blur(20px) saturate(1.8);
}

.k-modal {
  background: rgba(15,20,28,.95);
  backdrop-filter: blur(40px);
}
```

**ウィンドウ:**
- titleBarStyle: "overlay"
- vibrancy: "under-window"
- Apple HIG: 最小 900×600

### 2.2 iOS (Reading + Triage)

**スコープ:** 受信 / 既読 / Reply Later への送り / アーカイブ / 危険警告。返信や送信は最小限。

**特徴:**
- 単一カラムレイアウト
- スワイプジェスチャー (左→アーカイブ、右→既読)
- Long Press でクイックアクション
- 通知センターの Inline Reply
- Focus Filter 統合 (Work / Personal で表示メール切替)

**Continuity:**
- iPhone で読み始め → Mac で返信 (Handoff)
- 通知スワイプ → Mac の Kaname にフォーカス遷移

**設計判断:**
- macOS の 3 ペインを iOS では深いナビゲーションに変換
- Liquid Glass トランスペアレント効果は維持
- BEC 警告は **画面上部の固定バナー** (スクロールに追従)

### 2.3 iPadOS (Triage 中心)

**スコープ:** macOS と iOS の中間。受信トレイ整理、AI 要約、簡易返信。

**特徴:**
- 2 ペインレイアウト (リスト / 詳細)
- Apple Pencil で手書きメモ → 返信添付
- Stage Manager 対応
- キーボードショートカット
- Slide Over でクイックビュー

**Continuity:**
- 全デバイスでのドラフト保存共有
- Universal Clipboard で添付ファイル共有

### 2.4 visionOS (将来 v3)

**スコープ:** 空間メールクライアント。深層 (Volumetric) UI で受信箱を 3D グリッドに。

**v3 で検討する機能:**
- 空間オーディオで送信者識別 (左から田中、右から佐藤)
- BEC 警告は**赤い空間オーラ**で危険を可視化
- Eye Tracking でキーボード不要のトリアージ
- メール本文を**ピンする**ことで複数同時表示

**WWDC25 哲学の反映:**
> "Vision OS の物理性と豊かさにインスピレーションを得て、デジタルなものを自然で生きているように感じさせる"

Kaname の v3 ビジョンは visionOS の力を最大活用する。

---

## 3. デザイントークン (プラットフォーム横断)

### カラーシステム

| トークン | macOS | iOS | iPadOS | 用途 |
|---|---|---|---|---|
| `--k-brand-primary` | `#00C4CC` | `#00C4CC` | `#00C4CC` | ブランド一貫 |
| `--k-bg-primary` | `#080C11` | dynamic system | dynamic system | 背景 (OS 適応) |
| `--k-bec-danger` | `#FF4444` | `#FF453A` (iOS Red) | `#FF453A` | OS native red |
| `--k-bec-safe` | `#00D68F` | `#34C759` (iOS Green) | `#34C759` | OS native green |

### タイポグラフィ

```
macOS / iPadOS:    -apple-system, "Hiragino Sans", "Noto Sans JP"
iOS:               SF Pro (system), "Hiragino Sans" (Japanese fallback)
visionOS:          SF Pro Display (空間最適化)
```

### モーション (Spring Physics)

全プラットフォームで統一:
```
default-spring: cubic-bezier(.34, 1.56, .64, 1)
duration:       0.2s (UI), 0.3s (transition)
prefers-reduced-motion: 0.01ms 強制
```

---

## 4. Continuity (連続性) 実装計画

### 4.1 Handoff — iPhone → Mac

**シナリオ:**
1. ユーザーが iPhone でメールを読み始める
2. Mac の前に座る
3. Mac の Dock に Kaname アイコンが現れる
4. クリックすると iPhone と同じメールが開く

**実装:**
- `NSUserActivity` (macOS) / `UIUserActivity` (iOS)
- `activityType: "app.kaname.mail.reading"`
- ペイロード: `email_id`, `scroll_position`, `cursor_in_compose`

### 4.2 Universal Clipboard

メール本文・添付ファイル参照を全デバイス間でコピー&ペースト。
**セキュリティ考慮:** クリップボードは E2E 暗号化されない (OS の制約)。
**緩和策:** メール本文をクリップボード送信時に警告ダイアログ表示。

### 4.3 Universal Drafts

ドラフトメールを iCloud で同期し、どこから書いていても続けられる。
**セキュリティ:** ドラフトは MLS で暗号化されてから iCloud に保存 (本文は Apple が読めない)。

### 4.4 Notification Continuity

iPhone で BEC 警告を受信 → 通知をスワイプ → Mac の Kaname にフォーカス → 詳細表示。

---

## 5. プラットフォーム別 UI コンポーネント表

| コンポーネント | macOS | iOS | iPadOS |
|---|---|---|---|
| サイドバー | 3 ペイン左端、Liquid Glass | なし (タブバー) | 2 ペイン左 |
| メールリスト | 中央、340px 固定 | 全画面、スワイプ対応 | 左 380px |
| メール詳細 | 右、伸縮 | プッシュ遷移 | 右、伸縮 |
| AI 要約バー | 詳細上部、固定 | 詳細上部、固定 | 詳細上部、固定 |
| BEC 警告 | バナー (詳細内) | 固定上部バナー | バナー (詳細内) |
| 検索 | ⌘K コマンドパレット | 上部スクロール検索 | 上部検索 |
| Compose | モーダル右下 | 全画面シート | 右上ポップオーバー |
| 設定 | システム設定スタイル | 標準設定アプリスタイル | 標準設定アプリスタイル |

---

## 6. アクセシビリティ統一基準

全プラットフォームで:
- **WCAG AAA** コントラスト比 7:1 以上
- **VoiceOver / TalkBack** 完全対応
- **Dynamic Type** 全テキストが OS のフォントサイズ設定に追従
- **Reduce Motion** で Spring → クロスフェード
- **Reduce Transparency** で Liquid Glass → ソリッド背景

---

## 7. 実装ロードマップ

### v0.1 (現在)
- ✅ macOS: Liquid Glass 完全実装
- ⬜ iOS: 仕様書のみ (実装は v0.3)
- ⬜ iPadOS: 仕様書のみ (実装は v0.3)
- ⬜ visionOS: ビジョンのみ (実装は v3.0)

### v0.2
- iOS Universal Binary 開始 (Reading のみ)
- Handoff 実装
- Universal Clipboard 実装

### v0.3
- iPadOS フル機能
- Stage Manager 対応
- iOS Compose 機能追加

### v1.0
- 全 Apple プラットフォーム動作 (visionOS を除く)
- Universal Drafts (MLS 暗号化付き)

### v3.0
- visionOS 空間メールクライアント

---

## 8. 競合との差異

| 機能 | Outlook | Spark | Superhuman | **Kaname** |
|---|---|---|---|---|
| プラットフォーム横断デザイン | ✗ | ✓ | ✓ | ✅ Liquid Glass |
| Handoff | △ | △ | ✗ | ✅ Native |
| Apple Watch 通知 | ✓ | ✓ | ✗ | ✅ inline reply |
| visionOS 対応 | ✗ | ✗ | ✗ | ✅ 計画済み |
| Liquid Glass マテリアル | ✗ | ✗ | ✗ | ✅ 完全実装 |

---

## 9. 改訂履歴

| 日付 | 改訂者 | 内容 |
|---|---|---|
| 2026-04-28 | kaname-design | 初版 — WWDC25 哲学を踏まえた統一仕様 |
