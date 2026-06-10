# kaname-memory-guard

> メモリ汚染攻撃への防御 — arxiv 2601.05504, 2512.16962 の実装

Kaname が将来「過去メール文脈」を RAG/メモリで提供する際の防御基盤。

## 脅威

- **MINJA**: クエリのみで悪意レコードを注入 (95% 成功率)
- **MemoryGraft**: トリガー不要の永続的 behavioral drift
- セッションを跨いで持続、手動削除まで残存

## 防御 (2 手法)

1. **Composite Trust Scoring** (`TrustScorer`): 複数の直交シグナルで信頼度算出
   - 出所の基準信頼度 (UserAction 0.9 / SystemGenerated 0.6 / EmailDerived 0.3)
   - 注入パターン検出で減点
   - 異常に長い指示文を減点
2. **Memory Sanitization** (`MemorySanitizer`): 時間減衰 + パターンフィルタ
   - 指数減衰 (半減期 30 日) で古い汚染エントリの影響を低減
   - retrieval 時に閾値未満を除外

## 北極星との整合

メモリは「メタデータのみ」を維持。本文は保存しない。

## テスト: 11 ユニット + 3 proptest

## 出典

- Sunil et al., "Memory Poisoning Attack and Defense on Memory Based
  LLM-Agents", arXiv:2601.05504, 2026.
- "MemoryGraft: Persistent Compromise of LLM Agents via Poisoned
  Experience Retrieval", arXiv:2512.16962, 2025.
