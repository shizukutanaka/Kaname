# arxiv 研究調査と Kaname への反映 (2026-05)

> arxiv.org から Kaname の核心技術に関連する最新研究を調査し、改善点を実装した記録。

---

## 調査した主要論文

### 1. CaMeL: Defeating Prompt Injections by Design (2503.18813, Google Research)

Kaname の Dual-LLM とほぼ同一アーキテクチャ。Privileged LLM + Quarantined LLM +
Controller + capability (provenance metadata)。AgentDojo で 77% のタスクを
provable security で解決 (無防備 84%)。

**Kaname との関係**: Kaname の `Content<Untrusted>` / `Content<Trusted>` 型境界、
`Bridge` 検証は CaMeL の設計思想と一致。独立に同じ結論に到達していたことを確認。

### 2. Operationalizing CaMeL (2505.22852, SentinelAI)

CaMeL の弱点と 5 つの改善提案。**Kaname に直接適用できる改善点を多数含む**。

| 提案 | 内容 | Kaname 実装 |
|---|---|---|
| §2.1 Initial Prompt Screening | ユーザー初期プロンプトも信頼しない | ✅ kaname-screen |
| §2.2 Output-Side Auditing | AI 最終出力の隠れ命令を検出 | ✅ kaname-screen |
| §2.3 from_user_upload provenance | アップロード由来データに専用タグ | ✅ Provenance::UserUpload |
| §3 Tiered-Risk Access Model | Green/Yellow/Red の3段階 | ✅ kaname-ai/tiered_risk |
| §4 Side-Channel 対策 | loop/exception/timing | 🔶 将来対応 (Q-LLM サブプロセス分離で部分緩和) |

### 3. AgentDojo (2406.13352, NeurIPS 2024)

プロンプト注入評価ベンチマーク。97 タスク + 629 セキュリティテストケース。
メールクライアント管理タスクを含む。正規攻撃: "Ignore Previous Instructions",
"System Message", "Important Messages", "Tool Knowledge"。
GPT-4o は benign 69% → 攻撃下 45% に低下。

**Kaname への示唆**: kaname-screen の override_phrases は AgentDojo の
正規攻撃パターンをカバー。将来は AgentDojo 互換テストスイートの追加が有効。

### 4. ML-KEM/MLS PQ cipher suites (draft-ietf-mls-pq-ciphersuites)

MLS の post-quantum cipher suite。ML-KEM + 楕円曲線 KEM hybrid。
harvest-now-decrypt-later 対策。

**Kaname との関係**: Kaname の ML-KEM-768 + X25519 HybridKEM 選択が
IETF ドラフトの方向性と一致していることを裏付け。

---

## 実装した改善 (v0.3.8)

### kaname-screen (新クレート)

入力スクリーニングと出力監査の 2 層防御:

- `PromptScreener`: 命令上書きフレーズ・特殊トークン・高エントロピー文字列を検出 (< 5ms 目標)
- `OutputAuditor`: 隠れた "## System:" 命令・外部送信先を検出

### Provenance::UserUpload (kaname-ai)

添付ファイル由来データに専用 provenance タグを付与。
不可逆操作 (外部送信等) に流れる前に grant-exception を要求する基盤。

### Tiered-Risk Access Model (kaname-ai/tiered_risk)

操作を Green/Yellow/Red に分類:
- Green (read-only): 即座に許可 → prompt fatigue 低減
- Yellow (自環境変更): Untrusted データを含む場合のみ軽い確認
- Red (不可逆/外部送信): 常に多要素承認

---

## 北極星との整合性

全ての改善が「AI が受信箱全体を読まない。メール 1 通のみ解析する。」と整合:

- kaname-screen は検査のみ。コンテンツ生成や横断的読み取りをしない
- UserUpload タグはデータフロー制御。AI の読み取り範囲を拡大しない
- Tiered-Risk は操作の認可制御。AI の権限を拡大せず、むしろ制限する

---

## 今後の検討 (Side-Channel 対策、§4)

arxiv 2505.22852 §4 が指摘する side-channel は Kaname では部分的に緩和済み:

- **Loop-counting**: Q-LLM はサブプロセス分離されており、ループ回数の
  外部観測が困難
- **Exception-based leak**: Rust の `Result<T, E>` 型で統一済み (panic を使わない)
- **Timing channel**: 将来、Q-LLM 推論時間の定数化を検討

完全な mechanized noninterference proof (Coq/Isabelle) は 100 年ビジョンの範疇。

---

## 第2回調査 (2026-05-30): メモリ汚染とサイドチャネル

### 調査した追加論文

#### MINJA: Memory Injection Attack (2503.03704)

クエリのみの相互作用で悪意ある指示をエージェントの長期メモリに注入。
理想条件下で 95% 超の注入成功率、70% の攻撃成功率。

#### MemoryGraft (2512.16962)

トリガー不要の永続的 behavioral drift を生む。良性に見えるドキュメントに
隠れた汚染 success 例を埋め込み、エージェントが取り込むと汚染された RAG
メモリストアを構築。将来のクリーンタスクで semantic retrieval が汚染
エントリを引き、エージェントが unsafe パターンを模倣。手動削除まで持続。

#### Memory Poisoning Defense (2601.05504)

2 つの防御手法を提案:
1. Input/Output Moderation — 複数の直交シグナルでの composite trust scoring
2. Memory Sanitization — temporal decay + pattern-based filtering の trust-aware retrieval

**重要な発見**: 現実条件 (既存の正当なメモリが存在) では攻撃効果が大幅に低下。
ただし trust 閾値の慎重な調整が必要 (過度に保守的だと全拒否、緩すぎると見逃し)。

### 実装した防御 (v0.3.9)

#### kaname-memory-guard (新クレート)

Kaname は現在メモリ機能を持たないが、将来の「過去メール文脈」機能に備えて
防御基盤を先行実装:

- `TrustScorer`: composite trust scoring
  - 出所別基準信頼度 (UserAction/SystemGenerated/EmailDerived)
  - 注入パターン検出 ("always recommend", "from now on" 等)
  - 異常長コンテンツの減点
- `MemorySanitizer`: temporal decay + filtering
  - 指数減衰 (半減期 30 日)
  - retrieval 時の閾値フィルタ

### 北極星との整合

メモリは「メタデータのみ」を維持し、メール本文を保存しない設計を堅持。
EmailDerived ソースは最低信頼度 (0.3) を割り当て、汚染の主経路を構造的に抑制。

### サイドチャネル対策 (前回 §4 の続報)

arxiv 2505.22852 §4 が指摘した side-channel について、Kaname の現状を再評価:

| サイドチャネル | Kaname の状態 |
|---|---|
| Loop-counting | Q-LLM サブプロセス分離で外部観測困難 |
| Exception-based leak | Rust `Result<T,E>` 型で統一済み (panic 不使用) |
| Timing channel | 将来: Q-LLM 推論時間の定数化を検討 |

完全な対策は 100 年ビジョンの mechanized noninterference proof (Coq/Isabelle) の範疇。

---

## 第3回調査 (2026-05-30): 暗号実装の検証境界

### 調査した論文

#### Verification Theatre (eprint 2026/192, Kobeissi)

「形式検証済み」と銘打たれた libcrux / hpke-rs で 13 個の脆弱性を発見。
うち 9 個は未検証コード、4 個は形式検証された仕様・証明コード内に存在:
- X25519 DH 出力の検証欠落 (all-zero チェックなし)
- 整数オーバーフローによる nonce 再利用
- ML-KEM の誤った decompression 定数、逆 NTT の欠落、誤ったシリアライゼーション証明
- ML-DSA の誤った乗算仕様 (AVX2 証明が unsound に)

**核心概念**: "verification boundary" — 機械チェック済みコードと信頼ベースコードの境界。
これが明示されないと「全体が検証済み」という誤解 (verification theatre) を生む。

#### Bert13 / Formal Verification of Rust Crypto (eprint 2025/980)

Rust で書かれた post-quantum TLS 1.3 を F*/ProVerif/SSProve で形式検証。
Rust 製プロトコル実装初のセキュリティ検証結果。100 年ビジョンの参考。

### 実装した改善 (v0.3.11)

#### X25519 出力検証 (kaname-crypto)

eprint 2026/192 V2/V4 への直接対応:
- `validate_x25519_output()`: 共有秘密の all-zero を constant-time で検出
- `CryptoError::WeakSharedSecret`: small-subgroup 攻撃の兆候を報告
- `encapsulate` / `decapsulate` 両方で検証を実施

#### docs/verification-boundary.md

Kaname の検証レベルを 3 Tier で明示:
- Tier 1: 型システムで強制 (コンパイル時)
- Tier 2: テストで検証 (実行時)
- Tier 3: 信頼ベース (外部依存)

「形式検証を盲信しない」多層防御の原則を文書化。

### 北極星との整合

「AIが裏切らない」は暗号層の正しさが前提。verification theatre の罠を避け、
独自 sanity check + KAT + microVM 分離で多層防御することは、北極星を支える基盤。
