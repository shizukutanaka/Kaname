# Dual-LLM Safety Skill

## 型境界の説明

```
Email (ネットワーク)
    ↓
Content<Untrusted>  ← from_network() で作成
    ↓ Q-LLM にのみ渡せる (型で強制)
QuarantinedLlm::analyze()
    ↓ AnalysisReport を返す (自由テキストなし)
Bridge::validate_and_promote()  ← 6段階検証
    ↓ 全てパスした場合のみ
Content<Trusted>  ← P-LLM / UI に渡せる
```

## よくある間違い

### NG: Untrusted を直接使う
```rust
// ❌ コンパイルエラーになる (型が違う)
fn needs_trusted(c: &Content<Trusted>) { ... }
let untrusted = Content::from_network("evil", "e1");
needs_trusted(&untrusted);  // error[E0308]
```

### OK: Bridge を通す
```rust
// ✅ 正しい使い方
let report = q_llm.analyze(&untrusted)?;
let trusted_summary = bridge.validate_and_promote(report, &untrusted)?;
// trusted_summary は Content<Trusted>
```

## Bridge の攻撃マーカーを追加する場合

`crates/kaname-ai/src/dual_llm.rs` の `BridgePolicy::default()` の
`attack_markers` ベクターに追加。大文字小文字無視で比較される。

## Gotchas

- `Content<Trusted>::from_validated()` は `pub(crate)` — Bridge 以外から呼べない
- `AnalysisReport` に String フィールドを追加しない (プロンプト注入経路になる)
- Q-LLM サブプロセスは seccomp でネットワーク禁止 (実装側で強制)
