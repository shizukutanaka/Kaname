# OWASP Agentic Top 10 (2026) — Kaname 対応マッピング

> OWASP が 2025年12月に公開した「Top 10 for Agentic Applications 2026」
> (ASI: Agentic Security Issue) に対する Kaname の防御マッピング。

最終更新: 2026-09-20 (D140/D142/E11 の削除を反映)

---

## 背景

OWASP は LLM アプリ向け Top 10 (2025) に続き、自律エージェント特化の
Agentic Top 10 (2026) を公開した。識別子は "ASI" (Agentic Security Issue)。
Kaname の AI 機能 (Dual-LLM、ツール実行) はこの脅威モデルの対象。

---

## マッピング表

| ASI | 脅威 | Kaname の防御 | 状態 |
|---|---|---|---|
| ASI-01 | エージェント制御ハイジャック (プロンプト注入) | Dual-LLM 型境界 + Bridge 6段階検証 + kaname-screen | ✅ |
| ASI-02 | ツール誤用・過剰権限 | ~~Tiered-Risk + Rule of Two~~ (D140 で削除 — 呼出元ゼロ) | ⚠️ |
| ASI-03 | 認可・権限昇格 | ~~Tiered-Risk Red tier 多要素承認~~ (D140 で削除) | ⚠️ |
| ASI-04 | メモリ・コンテキスト汚染 | ~~kaname-memory-guard (trust scoring + decay)~~ (D142 で削除 — エージェントメモリ基盤が製品に存在せず呼出元ゼロ。残存は正規化ユーティリティのみ) | ⚠️ |
| ASI-05 | 引数操作 (argument manipulation) | ~~kaname-screen `ArgumentValidator`~~ (D142 で削除 — ツール呼出し経路が製品に存在せず呼出元ゼロ) | ⚠️ |
| ASI-06 | 出力からの情報漏洩 | kaname-screen `OutputAuditor` | ✅ |
| ASI-07 | データ流出 (exfiltration) | ~~Rule of Two~~ (D140 削除) + DLP + EDM | ⚠️ |
| ASI-08 | サプライチェーン (プラグイン/MCP) | サンドボックス分離 + 審査済みのみ | ✅ |
| ASI-09 | 監視・追跡可能性の欠如 | kaname-observability (OpenTelemetry + 監査ハッシュチェーン) — Trajectory Monitor は E11 で削除済み | ⚠️ |
| ASI-10 | リソース枯渇 (DoS) | ~~kaname-screen `RateLimiter`~~ (D142 で削除 — 呼出元ゼロ) + Q-LLM サブプロセス分離 + 各種コレクション上限 (D124–D134) | ⚠️ |

---

## 各 ASI への対応詳細

### ASI-01: エージェント制御ハイジャック

最も深刻。受信メール本文 (untrusted) でエージェントの行動を乗っ取る攻撃。

Kaname の多層防御:
1. **型境界**: `Content<Untrusted>` は P-LLM に型レベルで渡せない
2. **Bridge**: Q-LLM 出力を 6 段階検証
3. **入力スクリーニング**: kaname-screen で命令上書きを検出

### ASI-05: 引数操作

CaMeL/Dual-LLM の既知バイパス (arxiv 2601.11893)。制御フローは固定でも
引数に untrusted データが混入する。~~`ArgumentValidator` で宛先すり替え・
許可外ドメイン紛れ込みを検出~~ — **D142 で削除済み**: 製品にツール呼出し
(引数を持つエージェント経路) が存在せず防御対象がなかった。LLM が
ツールを呼ぶ機能を実装する際に git 履歴から復元すべき防御。

### ASI-07: データ流出

Rule of Two が核心: [untrusted入力, 機密アクセス, 外部通信] の 3 つを
同時に持たせない。EDM (Exact Data Matching) が機密データセットの
完全一致を hash fingerprinting で検出 (chunk 分割攻撃にも対抗)。

### ASI-10: リソース枯渇

~~入力ゲートに `kaname-screen::RateLimiter` (トークンバケット) を配置し、
大量の untrusted メールによる Q-LLM サブプロセス枯渇を抑制する~~ —
**D142 で削除済み** (呼出元ゼロ)。実際の DoS 防御は D124–D134 の
コレクション上限 (kp_cache・seen_welcomes・scan ファイル数等) と
JMAP 応答サイズ上限 (D129) が担う。
設定でき、時刻巻き戻り (悪意あるクロック操作) でもトークンを増やさない。

Q-LLM はサブプロセス分離されており、リソース上限も設定可能。
auto-healing (SHIELD 風) はさらなる将来拡張の余地。

---

## 残課題

- **ASI-10 auto-healing**: SHIELD 風の自己回復は拡張余地
  (RateLimiter は D142 で削除 — 呼出元ゼロだった)
- **継続的検証**: OWASP の更新に追従 (Top 10 は定期改訂)
- **AgentDojo 互換テスト**: ASI-01/05 の自動検証スイート

---

## 出典

- OWASP Top 10 for Agentic Applications 2026 (2025年12月公開)
- arxiv 2601.17548 (OWASP Agentic マッピング参照)
- arxiv 2601.11893 (argument manipulation)
