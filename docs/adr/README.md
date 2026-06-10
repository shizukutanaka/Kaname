# Architecture Decision Records (ADR)

> 設計判断の理由を未来の自分と新しいメンバーに伝える。
>
> Format: [Michael Nygard ADR template](https://github.com/joelparkerhenderson/architecture-decision-record).

## Index

| ADR | Title                                              | Status   | Date       |
|-----|----------------------------------------------------|----------|------------|
| 001 | Tauri 2 を選択する                                  | Accepted | 2026-04-20 |
| 002 | SolidJS を React より優先する                       | Accepted | 2026-04-20 |
| 003 | Cargo workspace で 13 クレート構造                  | Accepted | 2026-04-20 |
| 004 | Dual-LLM 型安全境界をコンパイル時で強制              | Accepted | 2026-04-20 |
| 005 | MLS (RFC 9420) を PGP より優先                     | Accepted | 2026-04-20 |
| 006 | 全 AI 推論をローカルで実行                          | Accepted | 2026-04-20 |
| 007 | rusqlite + SQLCipher を選択                        | Accepted | 2026-04-20 |
| 008 | JMAP プロトコルのみサポート (IMAP は v2 検討)       | Accepted | 2026-04-21 |
| 009 | Firecracker を添付サンドボックスに採用              | Accepted | 2026-04-21 |
| 010 | AGPL-3.0-or-later ライセンス                        | Accepted | 2026-04-21 |
| 011 | Phi-4-mini を Q-LLM のデフォルトモデルに            | Accepted | 2026-04-22 |
| 012 | DLP ラベルを件名暗号化と同じレイヤーで管理          | Accepted | 2026-04-22 |
| 013 | チームコラボ機能を v1 から除外                      | Accepted | 2026-04-23 |
| 014 | Apple HIG + Liquid Glass を UI 言語として採用       | Accepted | 2026-04-23 |
| 015 | nextest を CI のテストランナーに採用                | Accepted | 2026-04-25 |
| 016 | Stripe を決済プロバイダに採用                       | Accepted | 2026-04-25 |
| 017 | KanameError 型エラーを全クレートで共有              | Accepted | 2026-04-26 |

---

## ADR-001: Tauri 2 を選択する

**Status**: Accepted

**Date**: 2026-04-20

### Context

クロスプラットフォーム (macOS/Windows/Linux) のデスクトップメールクライアントを構築する必要がある。候補:

| フレームワーク | バンドル | 性能 | 配布性 |
|---|---|---|---|
| Electron | ~150 MB | 中 | 容易 |
| Tauri 2 | ~10 MB | 高 | 容易 |
| SwiftUI | ~5 MB | 最高 | macOS のみ |
| Qt | ~30 MB | 高 | 複雑 |

### Decision

Tauri 2 を採用する。

### Rationale

- バイナリサイズ 10MB (Electron の 1/15)
- システム WebView 利用 → メモリ消費が低い
- Rust バックエンドが Kaname のセキュリティ要件と整合
- Tauri 2 で macOS Vibrancy・トレイ・更新が安定
- 単一コードベースで 3 OS 配布

### Consequences

- ✅ メモリ使用量がメールクライアントとして許容範囲 (200MB 目標)
- ✅ Rust エコシステム (kaname-mls, kaname-bec) との直接統合
- ⚠️ Linux WebKit のレンダリング差異対応が必要
- ⚠️ Tauri 2 はリリース直後でエコシステム未成熟

---

## ADR-004: Dual-LLM 型安全境界をコンパイル時で強制

**Status**: Accepted

**Date**: 2026-04-20

### Context

2024年の Superhuman プロンプト注入 CVE が示したように、AI メールクライアントの最大リスクは「攻撃者のメールが受信箱全体を読む権限を持つ AI を乗っ取る」ことだ。

ランタイム文字列フィルタリングは回避され続けている。Microsoft Copilot CW1226324 (2026) も DLP ラベル付きメールに対するチェックをバイパスされた。

### Decision

Rust の型システムで AI 境界を強制する。`Content<Trusted>` と `Content<Untrusted>` という newtype を導入し、`PrivilegedLlm` には `Content<Trusted>` のみ、`QuarantinedLlm` には `Content<Untrusted>` のみが渡せるようにする。

```rust
// コンパイルエラー: untrusted を privileged に渡せない
let untrusted: Content<Untrusted> = Content::from_network(email_body);
PrivilegedLlm::analyze(&untrusted); // ❌ コンパイルエラー
```

### Rationale

- **コンパイル時** に検証するため攻撃者が「この実行パスだけ回避」が不可能
- newtype は `Provenance: Sealed` トレイトでクレート外からの作成を制限
- Bridge は構造化スキーマでのみ promote (自由形式テキスト不可)

### Consequences

- ✅ Superhuman/Copilot CVE と同クラスの攻撃を**型システムが防ぐ**
- ✅ レビュー時に「`Content<Untrusted>` を `PrivilegedLlm` に渡す箇所を探す」だけで監査が完了
- ⚠️ `kaname-ai` API への変更は **2 名レビュー必須** (CLAUDE.md)
- ⚠️ 開発者が型を理解していないと「とりあえず unsafe で回避」を試みる可能性

### Implementation
- `crates/kaname-ai/src/ai_lib.rs` 23-105 行
- テスト: `tests-adversarial.rs` の 50 ペイロード x 7 カテゴリ

---

## ADR-005: MLS (RFC 9420) を PGP より優先

**Status**: Accepted

**Date**: 2026-04-20

### Context

エンドツーエンド暗号化の選択肢:
- **PGP/GPG**: Proton Mail が採用。デファクト標準。
- **S/MIME**: Microsoft 365 が採用。証明書ベース。
- **MLS (RFC 9420)**: 2023 IETF 標準化。Signal/WhatsApp 系列。

### Decision

MLS RFC 9420 をデフォルトの E2E プロトコルとする。PGP は法人連携用にオプションサポート。

### Rationale

PGP の致命的問題:
- **件名が平文**: PGP は本文のみ暗号化。件名は SMTP レベルで露出。
- **前方秘匿性なし**: 鍵が漏洩すると過去全メールが復号される。
- **メタデータ漏洩**: 添付ファイル名・MIME 構造が見える。

MLS の優位性:
- **Email-over-MLS**: 件名を含むメッセージ全体が暗号化される。
- **前方秘匿性**: エポックごとに鍵が更新される。過去のメールは保護される。
- **PQC ハイブリッド**: ML-KEM-768 + X25519 で量子コンピューター攻撃に耐える。
- **マルチデバイス**: グループメンバーシップが鍵管理の仕組みになる。

### Consequences

- ✅ Proton Mail を超える暗号保護
- ✅ ML-KEM-768 採用で 2028+ の量子脅威に対応
- ⚠️ MLS の interop は他のメールクライアントと不可能
- ⚠️ `openmls` はまだ crates.io 未公開 → git 依存 (deny.toml で例外指定)

---

## ADR-006: 全 AI 推論をローカルで実行

**Status**: Accepted

**Date**: 2026-04-20

### Context

Superhuman は OpenAI API を使う。Copilot は Azure OpenAI を使う。両方とも:
1. ユーザーのメール内容がクラウドに送信される
2. プロバイダのプライバシーポリシーに依存する
3. ネットワーク障害で AI 機能が止まる

### Decision

全 AI 推論をローカルで実行する。デフォルトモデル: Phi-4-mini-instruct-Q4_K_M (3.8GB)。

### Rationale

- **データ主権**: メール本文がデバイスを離れない
- **GDPR/個人情報保護法対応**: 国境を越えるデータ転送なし
- **完全オフライン動作**: 飛行機・遠隔地でも AI 機能が使える
- **応答時間**: ローカル < 3秒 vs OpenAI ~5-15秒
- **コスト**: 無料 (推論コストなし)

### Consequences

- ✅ プライバシー保護を競合の追随困難なレベルに引き上げ
- ⚠️ M1 Mac 8GB では性能が限定的 → メモリ要件を 16GB 以上に推奨
- ⚠️ モデルサイズ 3.8GB がアプリ初回ダウンロードを遅らせる → オンデマンド DL に分離

---

## ADR-013: チームコラボ機能を v1 から除外

**Status**: Accepted

**Date**: 2026-04-23

### Context

メールクライアント市場のチームコラボ機能 (Missive、HEY for Work) は強い競合がいる。Kaname の北極星「AI が裏切らないメールクライアント」と直接整合しない。

### Decision

v1 では個人/プロフェッショナル向けに集中する。チームコラボ (共有受信箱、内部コメント) は v2 以降で再評価。

### Rationale

- Apple の「フォーカス」原則: やりたいことを止める勇気
- v1 の North Star デモシーン (BEC検出 → AI要約 → 安心返信) はチーム機能を必要としない
- リソース集中で Security/Speed/Privacy の3柱を完璧にする

### Consequences

- ✅ 開発スコープが明確化、リリース日が確定可能に
- ⚠️ Missive ユーザーから移行希望があっても受け入れられない
- ⚠️ v2 でチーム機能を追加する際にデータモデル拡張が必要

---

## ADR-017: KanameError 型エラーを全クレートで共有

**Status**: Accepted

**Date**: 2026-04-26

### Context

Tauri コマンドは `Result<T, String>` を返す。各クレートが個別の `thiserror` Error を持つと、フロントエンドへのエラー伝播時に重要な情報 (severity、ユーザー安全メッセージ) が失われる。

### Decision

`kaname-error` クレートを新設し、`KanameError` 型を全クレートで共有する。

### Rationale

- フロントエンドはエラーコード (例: `BEC_DETECTED`) で UI を切り替えられる
- `severity()` でログのフィルタリングが可能
- `user_message()` は内部詳細 (SQLクエリ等) を露出しない
- serde で JSON 化してフロントエンドに伝達

### Consequences

- ✅ ログメトリクスがエラーコードベースで集計可能
- ✅ 内部実装の詳細がユーザーに漏れない (`user_message()` 経由)
- ⚠️ 新しいエラー種別を追加するときは全クレートでビルドが通り直しになる
- ⚠️ 既存の `String` エラーを使っている箇所を全て移行する必要がある (今後のタスク)

### Implementation

`crates/kaname-error/src/lib.rs` (200行、テスト 7件)

---

## ADR インデックス

| 番号 | タイトル | 状態 |
|---|---|---|
| [0001](0001-mls-rfc-9420.md) | MLS RFC 9420 を E2E 暗号化に採用 | ✅ Accepted |
| [0002](0002-pqc-hybrid.md)   | ML-KEM-768 + X25519 ハイブリッド | ✅ Accepted |

## ADR 命名規則

```
NNNN-short-title.md
```

- `NNNN`: 4桁ゼロパディングの連番
- `short-title`: ハイフン区切りの短い英語タイトル
- 番号は降番せず、廃止された ADR は `Status: Superseded by NNNN` を残す

## 新しい ADR の作成

```bash
cp docs/adr/0001-mls-rfc-9420.md docs/adr/00NN-your-decision.md
$EDITOR docs/adr/00NN-your-decision.md
```

テンプレート: [Michael Nygard's ADR template](https://github.com/joelparkerhenderson/architecture-decision-record)
