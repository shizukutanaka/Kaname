# Agentic Defense Skill

## トリガー
エージェントセキュリティ・プロンプト注入・ツール実行に関わる変更

## Kaname の多層エージェント防御 (2026 研究反映)

### 防御層 (実行順)

```
受信メール (untrusted)
  ↓
[1] 入力スクリーニング (kaname-screen::PromptScreener)
  ↓ 命令上書き・特殊トークン・高エントロピーを検出
[2] Dual-LLM 型境界 (kaname-ai)
  ↓ Content<Untrusted> は Q-LLM のみ
[3] Bridge 6 段階検証
  ↓ AnalysisReport を昇格
[4] Tiered-Risk 判定 (kaname-ai::tiered_risk)
  ↓ Green/Yellow/Red
[5] Rule of Two チェック (kaname-ai::rule_of_two)
  ↓ 3 能力同時保持を禁止
[6] ArgumentValidator (kaname-screen)
  ↓ 引数すり替えを検出
[7] 出力監査 (kaname-screen::OutputAuditor)
  ↓ 隠れ命令・流出先を検出
[8] Trajectory Monitor (kaname-observability)
  ↓ 行動軌跡の異常検出
ユーザーに表示
```

### OWASP Agentic Top 10 対応

| ASI | 担当 |
|---|---|
| ASI-01 制御ハイジャック | [1][2][3] |
| ASI-02 ツール誤用 | [4][5] |
| ASI-04 メモリ汚染 | kaname-memory-guard |
| ASI-05 引数操作 | [6] |
| ASI-06 出力漏洩 | [7] |
| ASI-07 データ流出 | [5] + DLP/EDM |
| ASI-09 追跡可能性 | [8] |

## Gotchas

- Rule of Two は単一時点、Trajectory Monitor は時系列。両方必要。
- 新しいツール操作を追加したら AgentAction enum と risk_tier を更新
- attack_markers / override_phrases は定期更新 (新しい注入手法に追従)
- EDM フィンガープリントは salt をローテーションしない (既存照合が壊れる)

## 出典

docs/category-research-2026.md, docs/owasp-agentic-mapping.md
