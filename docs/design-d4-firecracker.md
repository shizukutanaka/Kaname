# D4 解体: Firecracker microVM サンドボックスの実装計画

> 2026-09-20 監査セッションからの派生文書。
> gap-analysis.md D4 の「Firecracker バイナリとの実連携、vsock 通信の実装」を
> 現行コードの構造に沿って実行可能な単位に分解する。
> **本書は設計案であり実装ではない** — kaname-sandbox の変更は
> security-lead 承認が必須ではないが脅威モデル接面のため
> `docs/threat-model.md` の更新を必須とする。

---

## 現状 (実測)

| 要素 | 状態 | 場所 |
|---|---|---|
| `FirecrackerConfig` | pool_size/memory/vcpus/kernel/rootfs/network_allowed + `validated()` で不変条件を Err 返し (network_allowed=true は絶対拒否) | `crates/kaname-sandbox/src/lib.rs` |
| `SandboxPool` | ウォーム VM プール・オンデマンドスポーン・max_lifetime リーパー・セマフォ同時実行制限 — 制御ロジックは全て実装済み | 同上 |
| `RunningVm` | Drop で teardown_tx 通知 + セマフォパーミット自動解放 (自己 DoS 修正済み) | 同上 |
| `VsockChannel` | **no-op** — send が即 Ok、recv が常に `VsockMsg::Ready` を返すスタブ | 同上 |
| `spawn_vm` | Firecracker バイナリの実 spawn は未実装 (VM は実際には起動しない) | 同上 |
| `mime_depth` | MIME 再帰深度の制限ロジック (実装済み) | `crates/kaname-sandbox/src/mime_depth.rs` |
| 出荷状態 | **kaname-sandbox は出荷 closure に含まれない** — 添付ビューアのサンドボックス化は製品上未提供で、UI/ドキュメントともその旨正直 | Cargo.toml 推移閉包 (2026-09-20 実測) |

「プール制御・設定検証・ライフサイクル・メッセージ型」は揃っており、
欠けるのは **Firecracker プロセス制御と vsock 実通信**のみ。

---

## 分解 (4 フェーズ)

### Phase 1 — Firecracker プロセス制御 (Linux のみ)

- `spawn_vm` 実装: `firecracker` バイナリを Command で spawn、
  API ソケット (`--api-sock`) 経由で設定 PUT (kernel/rootfs/drives/vsock/
  network-config=空)。boot-source/machine-config/drives/vsock の
  4 エンドポイント PUT で起動。
- Firecracker バイナリの取得: リリース tarball をダウンロードし
  SHA-256 検証 (D2 のモデル配布と同じパターン)。
  **バンドルしない — 初回セットアップ時に明示取得**。
- `kernel_path`/`rootfs_path` の既定イメージ: Alpine 最小 rootfs +
  ビューア (mime 解析・HTML サニタイズ・PDF レンダラ) を焼き込む。
  rootfs 構築スクリプト (`scripts/build-rootfs.sh`) を新設。

### Phase 2 — vsock 通信 (kaname-sandbox)

- `VsockChannel` を `vsock` クレートの `VsockStream` に置換:
  length-prefixed CBOR フレーミング (コメント記載の設計どおり)。
  CID は Firecracker 側が `vsock` 設定で割当。
- VM 内側のゲストエージェント (`kaname-guest-agent`、新規 bin):
  vsock listen → `VsockMsg::RenderJob` 受信 → 添付を解析 →
  `RenderResult` を返す。ゲスト側も `#![deny(unsafe_code)]` +
  読み取り専用 rootfs + ネットワーク無し (FirecrackerConfig の
  不変条件と一致)。
- 失敗時: タイムアウト (render job に max_secs) + VM 強制 kill →
  プールへ補充通知。ホスト側は Err を返し「開けませんでした」と
  表示 (サイレント成功はしない)。

### Phase 3 — プラットフォーム分岐

- Firecracker は **Linux/KVM 専用**。macOS/Windows では本機能を
  提供しない (ホスト VM 技術が異なる: macOS = Virtualization.framework,
  Windows = Hyper-V — 別実装が必要でスコープ外)。
- `#[cfg(target_os = "linux")]` で spawn_vm/vsock を実装し、
  他 OS では `acquire()` が `SandboxError::Unsupported` を返す。
  UI は「この OS では安全ビューア未対応」と明示 (偽装しない)。
- 現行 macOS 開発環境では Phase 1-2 のコードは書けるが**実行検証は
  Linux が必要** — CI (D63) が復活するまで実機テストは保留。

### Phase 4 — 統合 (kaname-ui + src-tauri)

- 添付ファイル「安全に開く」ボタン → `mail_download_attachment` 後に
  `SandboxPool::acquire` → `render_attachment` → 結果を表示。
- 添付サイズ上限・filename 長制限・RenderHints クランプは実装済み —
  IPC コマンドに公開するのみ (`sandbox_render_attachment`)。
- メトリクス: VM 起動数/タイムアウト数/プール枯渇を audit_event に記録。

---

## リスクと既知の制約

| リスク | 対処 |
|---|---|
| Linux/KVM 依存 — 開発機 (macOS) で動作確認不可 | Phase 1-2 はコードのみ。動作検証は CI (D63) の Linux runner か Linux 実機が必要 — 人間の環境依存 |
| Firecracker/rootfs の配布 (~100MB+) | アプリにバンドルせず初回セットアップで明示 DL + SHA-256 検証 |
| ウォーム VM のメモリコスト | pool_size 既定 1-2、memory_mb 128-256 の推奨レンジ (validated() で 128-2048 に制約済み) |
| ゲストエージェントのビルドが別ターゲット (musl 静的) | rootfs 構築スクリプト内で `cargo build --target x86_64-unknown-linux-musl` |
| 現行の no-op は「動いているように見える」 | acquire が Unsupported を返すようになれば、機能の有無が API で判定可能になり誤解を防げる |

## 前提・ブロッカー

- **実行検証には Linux 環境が必須** (D63 の CI 復活が実質ブロッカー。
  または Linux 実機での手動検証)。
- D1/D2 と独立。脅威モデルへの追加 (サンドボックス内で何を許すか)
  は Phase 1 着手時に必須。
- 優先度判断: 添付のリスクは現状 kaname-render (svg_guard/html_smuggling/
  quishing) が多層防御しており、VM 隔離は「さらに強い防御」の追加層。
  D1/D2 より製品差別化への寄与は小さい可能性が高い。
