# kaname-license

Kaname の収益化レイヤ — オフライン署名ライセンス検証。

## 設計

- **ローカルファースト不変条件との整合**: 課金サーバ・テレメトリ・ネットワーク呼出しは一切なし。ed25519 署名を同梱公開鍵のみでローカル検証する。
- **キー形式**: `KANAME-<hex(payload)>.<hex(ed25519 signature)>`。payload は `{"v":1,"tier":"pro","seats":N,"exp":unix|null,"to":"...","nonce":"..."}` の JSON。
- **Pro ゲート**: 業務量に比例する機能のみ。現状は `Feature::FolderScan` (フォルダ一括スキャン)。
- **発行**: `issue(seed, to, seats, expires_at)` は販売者側 API。秘密鍵シードは引数/環境変数で渡し、リポジトリに含めない。
- **期限**: `exp` 任意。期限付きライセンスは `status()` 呼出し時に再評価され、失効後は自動で Free に戻る。

## 使い方

```rust
use kaname_license::{activate, require, Feature};

// アプリ起動時や設定画面から
activate("KANAME-…", now_unix)?;

// ゲートしたい機能の入口で
require(Feature::FolderScan, now_unix)?;
```
