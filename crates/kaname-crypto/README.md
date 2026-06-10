# kaname-crypto

> ハイブリッド暗号 (古典 + ポスト量子)

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](../../LICENSE)
[![Workspace](https://img.shields.io/badge/Workspace-Kaname-00C4CC.svg)](../../README.md)

## 主要機能

- ML-KEM-768 (FIPS 203) + X25519
- ML-DSA-65 (FIPS 204) + Ed25519 署名
- HNDL 攻撃対策 (Harvest Now Decrypt Later)

## ワークスペース内依存

- `kaname-error`

## テストカバレッジ

5 ユニットテスト

## 使用例

```rust
use kaname_crypto::*;
// 詳細は src/lib.rs の doc コメントを参照
```

## 関連文書

- [プロジェクト全体 README](../../README.md)
- [脅威モデル](../../docs/threat-model.md)
- [CHANGELOG](../../CHANGELOG.md)
