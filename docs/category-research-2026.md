# Kaname 10 カテゴリ別研究調査 (2026-05-31)

> Kaname を 10 カテゴリに分類し、各カテゴリで arxiv / GitHub から最新研究を調査、
> 改善点を洗い出した記録。

---

## カテゴリ分類と調査結果

### 1. AI セキュリティ (Dual-LLM / プロンプト注入防御)

**調査**: CaMeL (2503.18813), SEAgent (2601.11893), Progent (2504.11703)

**重要発見**:
- CaMeL の plan-then-execute は **argument manipulation** でバイパス可能 (2601.11893)
  - 制御フローは固定でも、引数に untrusted データが混入する経路が残る
- Progent は programmable privilege control で攻撃成功率を 41.2% → 2.2% に低減

**実装**: `kaname-screen::ArgumentValidator`
- `validate_recipient`: untrusted データによる宛先すり替えを検出
- `detect_smuggled_target`: 許可外ドメインの紛れ込みを検出

### 2. エージェント認可 (Capability / Privilege Control)

**調査**: Meta "Rule of Two" (2601.17548), OWASP Agentic Top 10 (2026)

**重要発見**:
- **Rule of Two**: エージェントは [untrusted入力, 機密アクセス, 外部通信] の
  3 能力のうち最大 2 つまで。3 つ揃うと流出の完全な連鎖が成立。

**実装**: `kaname-ai::rule_of_two`
- `RuleOfTwo::check`: 3 能力同時保持を Violation として検出
- `suggest_mitigation`: 外部通信の分離を最優先で提案

### 3. 暗号 (PQC / ML-KEM / MLS)

**調査**: draft-ietf-mls-pq-ciphersuites, MLS combiner (draft-ietf-mls-combiner),
eprint 2022/1533 (メタデータ秘匿), awslabs/mls-rs

**重要発見**:
- MLS WG は 2026年12月に PQ security マイルストーン (draft-ietf-mls-combiner)
- Kaname の ML-KEM-768 + X25519 HybridKEM は IETF 方向性と一致
- zeroization (秘密鍵のメモリ消去) が業界標準

**現状**: Kaname は既に HybridKEM + X25519 検証 (eprint 2026/192 対策) を実装済み。
将来 MLS combiner ドラフト確定時に追従。

### 4. メール脅威検知 (BEC / フィッシング)

**調査**: 月間 6600万 BEC 検出 (context-aware detection), polymorphic phishing

**現状**: kaname-bec (7信号) + kaname-radar (PCR) + kaname-screen で対応済み。

### 5. データ保護 (DLP / プライバシー)

**調査**: EDM (Exact Data Matching, hash fingerprinting), chunk 分割回避

**重要発見**:
- 攻撃者は暗号化・難読化・**データ分割**で DLP を回避する
- EDM は hash-based fingerprinting で機密ファイルの複製を検出

**現状**: kaname-dlp (12分類器) で対応。将来 EDM 追加を検討。

### 6. サンドボックス分離

**調査**: Rule of Two の能力分離、Firecracker microVM

**現状**: kaname-sandbox (Firecracker, network禁止強制) で対応済み。

### 7. メールプロトコル (JMAP)

**現状**: kaname-jmap (RFC 8620/8621) で対応。変更不要。

### 8. 可観測性 (ログ / メトリクス)

**調査**: AgentDoG (trajectory monitoring), AgentDojo

**現状**: kaname-observability (OpenTelemetry) で対応。将来 trajectory 監視を検討。

### 9. 国際化 (i18n)

**現状**: kaname-i18n (BCP47 + CLDR) で対応。変更不要。

### 10. 課金 (Stripe)

**現状**: kaname-billing (HMAC 検証) で対応。変更不要。

---

## 実装した改善 (v0.3.13)

| カテゴリ | 改善 | 出典 |
|---|---|---|
| 1. AI セキュリティ | ArgumentValidator | arxiv 2601.11893 |
| 2. エージェント認可 | Rule of Two | arxiv 2601.17548 (Meta) |

両者とも Dual-LLM / Tiered-Risk を補完する独立した防御層。
多層防御 (defense in depth) を強化する。

---

## 今後の検討 (優先度順)

1. **EDM (Exact Data Matching)** — kaname-dlp に hash fingerprinting 追加
2. **MLS combiner** — IETF ドラフト確定後に PQ MLS へ追従
3. **Trajectory monitoring** — kaname-observability にエージェント軌跡監視 (将来)
4. ~~OWASP Agentic Top 10 (2026) マッピング~~ ✅ 完了 (v0.3.14)
5. ~~AgentDojo 互換テスト~~ ✅ 完了 (v0.3.16)
6. ~~EDM (Exact Data Matching)~~ ✅ 完了 (v0.3.14, 配線 v0.3.15)
