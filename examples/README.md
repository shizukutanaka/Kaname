# Kaname Examples

Kaname の各機能の動作確認・デモ用サンプル。全サンプルにテストが付属。

## 実行

```bash
cargo run --example oobv_basic
cargo run --example html_smuggling_check
cargo run --example dual_llm_safety
cargo run --example pivot_detect
```

## テスト実行

```bash
cargo test --examples
```

## ファイル一覧

| ファイル | 機能 | テスト数 |
|---|---|---|
| `oobv_basic.rs` | Out-of-Band Verification | 5 |
| `html_smuggling_check.rs` | HTML スマグリング検出 | 6 |
| `dual_llm_safety.rs` | Dual-LLM 型安全 | デモ |
| `pivot_detect.rs` | Cross-Channel Pivot Detection | デモ |
