# BEC Detection Skill

## BEC (Business Email Compromise) 検出の仕組み

### 7 信号 (kaname-bec)

1. **Levenshtein 距離** — ドメインの 1-3 文字差
2. **緊急性マーカー** — 至急、urgent、本日中、immediately
3. **振込パターン** — 振込、口座変更、wire transfer
4. **送信時刻異常** — 深夜・早朝・休日
5. **QR フィッシング** — 画像内 QR コード
6. **VEC パターン** — 既知取引先ドメインの偽装
7. **メール爆撃** — 大量送信で受信箱を埋める

### AiTM 検出 (kaname-bec/aitm)

追加で URL 内の AiTM プロキシを検出:
- 認証トークンパラメーター (`?id_token=`, `?code=`)
- 偽ブランドドメイン (`microsoft.com.evil.tk`)
- PhaaS パターン (tycoon, mfa-relay)
- リダイレクト埋め込み (`?redirect=https://...`)

### PCR (kaname-radar)

インフラ共有で同一キャンペーンを検出:
- 94% の攻撃が同一 IP を共有 (Cofense 2026)
- 3通以上の同一インフラ → 警告

## スコア解釈

| スコア | 意味 | UI 表示 |
|---|---|---|
| < 0.3 | Safe | なし |
| 0.3-0.5 | Advisory | 黄色バナー |
| 0.5-0.7 | Suspicious | オレンジバナー |
| > 0.7 | Dangerous | 赤バナー + 送信ブロック |

## Gotchas

- `assess()` は同期。非同期ラッパーは `kaname-ui/commands.rs`
- Levenshtein は ASCII 文字のみ対応 (日本語ドメインは別処理)
- PhaaS パターンリストは頻繁に更新が必要
