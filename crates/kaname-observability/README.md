# kaname-observability

> 観測性 3 本柱

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- Logs: tracing-subscriber JSON 構造化
- Metrics: Prometheus 互換
- Latency: RAII LatencyTimer (Apple HIG 目標と比較)
- PrivacySanitizer がメール本文を除外

## ワークスペース内依存

- `kaname-error`

## テストカバレッジ

9 ユニットテスト

## 使用例

```rust
use kaname_observability::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
