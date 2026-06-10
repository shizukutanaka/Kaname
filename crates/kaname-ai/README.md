# kaname-ai

> Dual-LLM 型安全 AI 層

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- Phantom Type による信頼レベル (Trusted / Untrusted)
- Bridge: Untrusted → Trusted への唯一の橋
- Q-LLM (隔離) と P-LLM (特権) の型レベル分離
- プロンプト注入をコンパイル時に防止

## ワークスペース内依存

- `kaname-error`
- `kaname-render`

## テストカバレッジ

57 ユニットテスト + ファジング 1 ターゲット

## 使用例

```rust
use kaname_ai::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
