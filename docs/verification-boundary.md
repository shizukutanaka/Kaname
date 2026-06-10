# Kaname 検証境界 (Verification Boundary)

> arxiv eprint 2026/192「Verification Theatre」の教訓を受け、Kaname の
> 「何が検証済みで、何が信頼ベースか」を明示する文書。

最終更新: 2026-05-30

---

## なぜこの文書が必要か

eprint 2026/192 (Kobeissi 2026) は、「形式検証済み」と銘打たれた libcrux で
13 個の脆弱性を発見した。重要な教訓:

> **形式検証された主張と検証の現実の間のギャップ = "verification theatre"**

形式検証は「検証境界」を持つ。境界の内側は機械チェック済み、外側は信頼ベース。
この境界が明示されないと、ユーザーは「全体が検証済み」と誤解する。

Kaname はこの教訓に従い、検証境界を明示する。

---

## Kaname の検証レベル

### Tier 1: 型システムで強制 (コンパイル時保証)

| 保証 | 強制方法 |
|---|---|
| Untrusted → Trusted は Bridge 経由のみ | `Content<Untrusted>` / `Content<Trusted>` 型 + `pub(crate)` |
| unsafe コードなし | `#![deny(unsafe_code)]` 全 27 クレート |
| 本番 unwrap なし | `#![deny(clippy::unwrap_used)]` 全 27 クレート |
| メモリ安全性 | Rust 所有権モデル (借用チェッカ) |

**境界**: Rust コンパイラ (rustc/LLVM) は信頼ベース。eprint 2026/192 が指摘する通り、
コンパイラ自体は形式検証されていない。

### Tier 2: テストで検証 (実行時保証)

| 対象 | 検証方法 | カバレッジ |
|---|---|---|
| Dual-LLM Bridge | 22 ユニット + compile_fail doctest | 高 |
| BEC スコアリング | プロパティテスト | 中 |
| 暗号 (HybridKEM) | ラウンドトリップテスト + X25519 検証 | 中 |
| 全機能 | 412 ユニット + 14 proptest | 中〜高 |

**境界**: テストは存在するパスのみ検証。網羅性は保証しない。

### Tier 3: 信頼ベース (検証なし、依存)

| 対象 | リスク | 緩和策 |
|---|---|---|
| ML-KEM-768 実装 (外部クレート) | eprint 2026/192 が ML-KEM 実装の証明バグを発見 | KAT (既知応答テスト) + X25519 検証で多層防御 |
| X25519 実装 (外部クレート) | DH 出力検証の欠落 (libcrux V4) | `validate_x25519_output()` で all-zero を独自検証 |
| Rust コンパイラ | コンパイラバグ | 複数バージョンでのビルド検証 (CI) |
| OS / ハードウェア | サイドチャネル | Firecracker microVM 分離 |

---

## eprint 2026/192 の 13 脆弱性への Kaname の対応

| libcrux の脆弱性 | Kaname の対応状況 |
|---|---|
| V1: SHA-3 intrinsics の platform 依存出力 | KAT で検出可能 (CI) |
| V2: X25519 DH 出力検証の欠落 | ✅ `validate_x25519_output()` 実装済み |
| V3: 整数オーバーフローによる nonce 再利用 | Rust の checked 演算 + デバッグ時 overflow panic |
| V4: ML-KEM decompression 定数の誤り | KAT (FIPS 203 ベクトル) で検出 |
| V5: ML-DSA 乗算仕様の誤り | Kaname は ML-DSA-65 を署名に使用 → KAT 必須 |
| その他 | verification boundary の明示で対応 |

---

## 多層防御の原則

Kaname は「形式検証を盲信しない」原則を採用:

1. **暗号プリミティブは外部の検証済みクレートを使う** が、
2. **独自の sanity check を追加** (X25519 all-zero 検証など)、
3. **KAT で FIPS 準拠を動的に確認**、
4. **Firecracker で実行を分離** し、万一の侵害の影響を限定する。

「検証済み」の一語に依存せず、複数の独立した防御層で守る。

---

## 今後の課題

- ML-KEM-768 / ML-DSA-65 の KAT (FIPS 203/204 既知応答ベクトル) を CI に追加
- 複数 Rust バージョンでのビルド検証
- 100 年ビジョン: Bert13 (eprint 2025/980) のような F* ベース形式検証の検討
