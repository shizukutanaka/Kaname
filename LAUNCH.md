# Kaname — 設計思想書・リリースチェックリスト
# Apple "Rules of the Road" 相当

作成: 2026-04-25 | Apple手法適用: 10-to-3-to-1完了

---

## North Star (北極星)

> 「AIが助けてくれるのに、裏切らない唯一のメールクライアント」

Kaname の全機能は、この1文に答えるものだけを残す。答えない機能は v2 に延期するか削除する。

---

## 10-to-3-to-1 分析結果

### 10 コンセプト (全候補)
1. BEC多信号検出
2. MLS RFC 9420 + PQC
3. DLPラベル強制AI制御
4. AI安全要約 (Dual-LLM型安全)
5. 送信者スクリーナー
6. Liquid Glass UI (macOS Tahoe 26準拠)
7. スヌーズ / Reply Later
8. 多アカウント対応
9. チームコラボ (共有受信箱)
10. カレンダー統合

### 3 柱 (v1スコープ)

| 柱 | 機能群 | 競合との差 |
|---|---|---|
| 🛡 Security | BEC + MLS + DLP + AI監査 | コンパイル時型安全 (競合は実行時チェック) |
| ⚡ Speed | Screener + Triage + Snooze | HEY + Superhuman の統合 |
| 🔒 Privacy | TrackingBlock + LocalAI + E2E | データがデバイス外に出ない |

### 1 北極星デモシーン (Steve Jobs デモ相当)
```
1. BECメール受信
2. 危険バナーが出現 (DANGEROUS)
3. ユーザーが「AI要約」をクリック
4. 「このメール1通のみ分析 / 受信箱全体に触れていない」を表示
5. 安全な要約が表示される
6. ユーザーが安心して返信を作成
```

---

## DRI (Directly Responsible Individual)

| モジュール | DRI | 変更時の承認者 |
|---|---|---|
| kaname-ai_lib.rs (Dual-LLM型安全) | kaname-ai | 2名レビュー必須 |
| kaname-bec-*.rs (BEC検出) | kaname-bec | 1名レビュー |
| kaname-mls-lib.rs (E2E暗号化) | kaname-mls | 2名レビュー必須 |
| kaname-dlp-lib.rs (DLP) | kaname-dlp | 1名レビュー |
| KanameDesign.tsx (UI) | UI チーム | デザインレビュー |
| khig-tokens.css (デザイントークン) | UI チーム | デザインレビュー |

---

## リリースチェックリスト (Rules of the Road)

### 設計品質
- [ ] 北極星デモシーンが 30 秒以内に体験できる
- [ ] 初回オンボーディングが < 2 分で完了する
- [ ] BEC DANGEROUS メールが受信トレイで即座に目立つ
- [ ] AI要約ボタン押下後 < 3 秒でレスポンス
- [ ] 空状態が意味のあるコンテンツを持つ (文字列「データなし」は NG)

### セキュリティ
- [ ] cargo test --workspace 全通過 (171+ テスト)
- [ ] todo!() 実装残 ゼロ
- [ ] `Content<Untrusted>` を `PrivilegedLlm` に渡すコードが存在しない
- [ ] DLP DANGEROUS ラベルでAI処理がブロックされる
- [ ] 監査ログのハッシュチェーンが valid
- [ ] cargo audit (脆弱性ゼロ)
- [ ] cargo deny (ライセンス違反ゼロ)

### パフォーマンス
- [ ] アプリ起動 < 421 ms (コールドスタート)
- [ ] メールリスト 50 件のレンダリング < 16 ms
- [ ] BEC評価 < 100 ms (ローカル)
- [ ] AI要約 < 3,000 ms (Phi-4-mini)

### アクセシビリティ (WCAG AAA)
- [ ] 全テキスト/背景ペアのコントラスト比 ≥ 7:1
- [ ] キーボードのみで全操作が可能 (j/k/e/r 等)
- [ ] フォーカスリングが全インタラクティブ要素に表示される
- [ ] スクリーンリーダー対応 (aria-label)

### UX (Apple HIG チェック)
- [ ] Clarity: 警告は警告らしく見える
- [ ] Deference: UIがコンテンツと競合しない
- [ ] Depth: 透明度レイヤーで階層が分かる
- [ ] アニメーションが Spring physics (linear 禁止)
- [ ] 空状態が存在する (全リストビュー)
- [ ] エラーメッセージが技術的文字列でなく日本語の親切な文章
- [ ] Toast通知が < 3 秒で消える

### 配布
- [ ] macOS DMG (Universal Binary arm64 + x86_64) + notarize
- [ ] Windows MSI + Authenticode署名
- [ ] Linux AppImage + DEB
- [ ] SLSA Level 3 Build Provenance
- [ ] PQC デュアル署名マニフェスト (Ed25519 + ML-DSA-65)
- [ ] SHA-256 ハッシュリスト
- [ ] latest.json 更新完了

---

## 削除した機能 (v2 に延期)

Apple手法の最重要教訓: **「やりたいことを止める勇気」**

| 機能 | 削除理由 | 再評価時期 |
|---|---|---|
| チームコラボ (共有受信箱) | Missiveが既に支配、スコープ外 | v2 Q3 |
| カレンダー統合 | 北極星に答えない | v2 Q2 |
| マルチアカウント | 初期は1アカウント集中で十分 | v2 Q1 |
| ウィジェット拡張機能 | 実装コスト高、差別化低 | v3 |
| Androidアプリ | macOS 本命が先 | v2 |

---

## 設計原則 (Carmack + Martin + Pike + Apple)

### John Carmack (性能)
- BEC評価はメインスレッドをブロックしない
- AI推論はバックグラウンドタスク、UIは常に応答可能
- Firecracker VMプールで添付サンドボックスのレイテンシを最小化

### Robert C. Martin (クリーンアーキテクチャ)
- 依存方向: UI → Core → Infra (逆方向は禁止)
- 各クレートは単一責任原則
- `Content<Trusted>` と `Content<Untrusted>` の型境界を破らない

### Rob Pike (シンプル)
- 1ファイルで動作するものは1ファイルで
- 標準ライブラリを使える場合は外部クレートを追加しない
- コンカレンシーはチャネルで、共有メモリより

### Apple HIG (使いやすさ)
- 北極星デモシーンが 30 秒で体験できること
- 初回起動の第一印象 = 最高の製品体験
- 削ぎ落とすことが追加より難しく、価値が高い
