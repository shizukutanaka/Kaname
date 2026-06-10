# Performance Skill

## トリガー
レイテンシ要件に影響する変更、ベンチマーク失敗、ホットパスの変更

## Apple HIG 目標値

| 操作 | 目標 | 計測場所 |
|---|---|---|
| Cold start (FMP) | < 800ms | StartupMetrics |
| BEC 判定 | < 50ms | kaname-bec bench |
| AI 要約 | < 3s | Dual-LLM pipeline |
| AiTM 検出 (5 URL) | < 10ms | aitm bench |
| SSA スタイル距離 | < 1ms | ssa bench |
| HTML スマグリング | < 5ms | render bench |
| メール選択→表示 | < 100ms | UI response |

## 計測コマンド

```bash
cargo bench --bench core_bench
cargo bench --bench core_bench -- aitm  # 特定のベンチのみ
```

## 回帰検出

PR で 5% 以上の遅化 → `performance-regression` ラベルが自動付与される。
`.github/workflows/perf.yml` が担当。

## Gotchas

- `cargo bench` は release ビルド (debug より 10-100x 速い)
- `#[inline(always)]` は乱用しない (I-cache を圧迫)
- `Arc<Mutex<T>>` はホットパスで避ける → `RwLock` か lock-free を検討
- HashMap は `FxHashMap` (Rust 標準より 2-3x 速い) に交換可能
