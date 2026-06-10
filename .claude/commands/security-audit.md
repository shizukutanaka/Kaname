# /security-audit

kaname-security の Dual-LLM / BEC / 暗号境界を中心にコードをレビュー。

## 実行内容
1. Content<Untrusted> の型境界チェック
2. Bridge の攻撃マーカーリスト更新の提案
3. 本番 unwrap() の検出
4. 新しい PhaaS パターンの提案
5. STRIDE 脅威モデルへの影響評価

## 出力形式
- 🔴 CRITICAL: 即時対応が必要
- 🟡 HIGH: 次のスプリントで対応
- 🟢 MEDIUM: 次のリリースで対応
- ℹ️ INFO: 将来の検討事項
