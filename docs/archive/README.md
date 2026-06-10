# Archive

このディレクトリは Kaname プロジェクトの「歴史」を保管する。
廃止された設計、古いバージョンの文書を保持し、なぜ廃止されたかを記録する。

## ファイル

| ファイル | 元の名前 | 廃止日 | 廃止理由 |
|---|---|---|---|
| `design-v0.1-deprecated.md` | `design.md` | 2026-04-29 | Apple Platforms 準拠版 (v0.2) で完全置換 |
| `threat-model-original.md` | (元の脅威モデル) | 2026-04-26 | STRIDE 完全分析版で置換 |
| `old-workflows/release-workflow-v0-old.yml` | `release-workflow.yml` | 2026-04-29 | `release.yml` (デュアル署名版) で置換 |

## 取り扱い原則

- **削除しない**: なぜ廃止したかの根拠を将来のメンテナーに残す
- **CI 対象外**: archive 内のファイルはビルド・テスト対象から除外
- **検索性維持**: 過去の文書から現在の文書へのポインタを `Now in →` で記録
