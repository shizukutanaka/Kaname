# kaname-screen

> 入力スクリーニングと出力監査 — arxiv 2505.22852 §2.1, §2.2 の実装

CaMeL (Dual-LLM) が見落とす 2 つの経路を防御する。

## 2 つの防御層

1. **入力スクリーニング** (`PromptScreener`): ユーザーの初期プロンプトを検査。
   命令上書きフレーズ・特殊トークン・高エントロピー文字列を検出。< 5ms。
2. **出力監査** (`OutputAuditor`): AI の最終出力を検査。
   隠れた "## System:" 命令・外部送信先・タスク矛盾を検出。

## 北極星との整合

どちらもコンテンツ生成ではなく検査のみ。AI が受信箱全体を読むことはない。

## テスト: 13 ユニット + 3 proptest

## 出典

Tallam & Miller, "Operationalizing CaMeL: Strengthening LLM Defenses for
Enterprise Deployment", arXiv:2505.22852, 2025.
