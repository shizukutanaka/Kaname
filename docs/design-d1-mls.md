# D1 解体: MLS グループ暗号化の実装計画

> 2026-09-20 監査セッションからの派生文書。
> gap-analysis.md D1 の「openmls 統合」を、現行コードの構造に沿って
> 実行可能な単位に分解する。**本書は設計案であり実装ではない** —
> kaname-mls の変更は CLAUDE.md の規則により security-lead 承認が必須。

---

## 現状 (実測)

| 要素 | 状態 | 場所 |
|---|---|---|
| `MlsMailClient` | API 完備: `start_one_to_one` / `add_member` / `encrypt_message` / `process_incoming` / `generate_key_package` / `recipient_policy` | `crates/kaname-mls/src/lib.rs` |
| 暗号 | **単一バイト XOR モック** (鍵=ConversationId 先頭バイト、鍵空間256)。コード内に「本番では絶対に使わない」の警告文あり | 同上 (`encrypt_message`/`process_incoming`) |
| リプレイ防止 | `seen_welcomes` (group_id, epoch) + `epochs` マップ — openmls が検知しない Welcome 重複を上位層で追跡する設計済み | 同上 |
| KeyPackage 配送 | `KeyPackageCache` (add/consume/has) 実装済み。配送経路は未定義 | 同上 |
| Envelope | `Envelope`/`EnvelopeKind` + CBOR 直列化済み。`application/mls-envelope+cbor` MIME は D116 で検出配線済み (kaname-render::is_mls_message) | 同上 + `crates/kaname-render` |
| Safety Number | `compute_safety_number` 実装済み、Conversation に `safety_number` フィールドあり | 同上 |
| 永続化 | `mls_conversations` テーブルはスキーマ存在・**書き込み経路なし** (設計済みシーム) | `crates/kaname-store` |
| 出荷状態 | **kaname-mls は出荷 closure に含まれない** — 製品は E2E 暗号化を装っていない (Compose/Onboarding/SecurityDashboard に「未実装 (D1)」明記) | Cargo.toml 推移閉包 (2026-09-20 実測) |

つまり「型・セレモニー・リプレイ防止・MIME 検出・フォールバック方針」は
揃っており、欠けるのは **openmls による実暗号と永続化・配布経路**。

---

## 分解 (5 フェーズ)

### Phase 1 — openmls 統合 (kaname-mls)

- `openmls` + `openmls_rust_crypto` を依存に追加。コードコメントの
  pseudo-code (MlsGroup::new / add_members / create_message / process_message)
  を実装化。
- ciphersuite 選定 (D1 台帳の指定): ベースラインは
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`。
  **統合時に draft-ietf-mls-pq-ciphersuites の ML-KEM/ハイブリッド
  ciphersuite の対応状況を openmls 側で確認し、利用可能なら最初から
  採用する** (2026-07 調査: docs/research-2026-07.md §1.5)。
  openmls 未対応なら「後方互換なしで切替可能」な設計に留め、
  ciphersuite を Credential/GroupState に記録して将来移行できるようにする。
- `GroupState`/`Welcome`/`KeyPackage`/`MlsMessage` の不透明 blob を
  openmls 実型に置換 (Serialize 境界は維持)。
- XOR モックは `#[cfg(test)]` または削除。**本番バイナリに暗号モックを
  残さないことが完了条件** (出荷時に XOR が生き残る経路を断つ)。

### Phase 2 — 永続化 (kaname-store + kaname-mls)

- `mls_conversations` テーブルに書き込み経路を追加:
  `save_mls_state(conversation_id, epoch, group_state_blob)`。
  GroupState blob は機密性が高い → テーブル自体は SQLCipher で保護済み
  だが、blob をアプリ層でも暗号化するかは脅威モデルで要決定
  (DB 鍵が history.key ファイル方式の現状では多層防御の価値あり)。
- `seen_welcomes`/`epochs` の永続化 — メモリのみだと再起動後に
  Welcome リプレイが通る。**これはセキュリティ要件**であり Phase 2 の
  必須項目。

### Phase 3 — KeyPackage 配送経路 (kaname-mls + kaname-jmap)

- 未解決の設計論点: 相手の KeyPackage をどこから得るか。
  選択肢:
  a) **添付 KeyPackage**: 初回送信時に自分の KP を MIME パート
     (`application/mls-key-package`) として添付し、相手が同様に返す
     (design-v0.1 の Welcome-via-attachment 拡張と整合)。
  b) **サーバ配布**: JMAP サーバ上の KP ストア (現行 JMAP 実装にない
     ため自作 or IETF 標準化待ち)。
  推奨は (a) — 既存のエンベロープ経路に載り、サーバ変更不要。
- `KeyPackageCache` の TTL/消費ポリシー確定 (一度使い切りの KP は
  consume 済みマーク、再利用させない)。

### Phase 4 — 暗号化セレモニー統合 (kaname-ui)

- 送信側: Compose で宛先の KP がキャッシュにあれば MLS 暗号化を
  提案/実行、なければ平文+「暗号化未対応相手」の明示ラベル
  (RecipientPolicy で制御 — 既に enum あり)。
- 受信側: `is_mls_message` (D116 で配線済み) が true のメールは
  `process_incoming` に流し、復号結果を BodyDto に反映。
  Welcome パートの処理 → グループ加入 → 次回以降暗号化。
- UI: E2E バッジは実際に MLS 経路を通ったメッセージのみに表示
  (I1 精神: バッジは構造的事実から導出、ユーザー入力で付けない)。

### Phase 5 — Safety Number セレモニー

- `compute_safety_number` 済みの数値を UI で比較できる画面
  (SecurityDashboard または OOBV セレモニーに統合)。
- 検証済みの相手は store に `verified` フラグを記録し、
  鍵変更時に警告を出す経路。

---

## リスクと既知の制約

| リスク | 対処 |
|---|---|
| openmls の PQ ciphersuite 対応が不完全 | Phase 1 で対応状況を最初に確認。未対応なら切替可能設計に留める |
| `mls_conversations` への書込は store スキーマ変更ではなく INSERT 経路の追加で済む | 設計済みシーム (D69 と同じ留保クラス) |
| 非対応相手への平文フォールバックが E2E 主張を弱める | 平文送信時は UI に明示ラベル (実装済みの方針) — 「暗号化した」の主張と「届けた」事実を分離 |
| Welcome リプレイ | `seen_welcomes` の永続化が必須 (Phase 2) — メモリのみのまま出荷しない |
| openmls API の破壊的変更 (0.6→0.7) | 1 つのバージョンに固定 (`Cargo.toml` にピン)、更新は明示作業 |

## 前提・ブロッカー

- security-lead 承認必須 (kaname-mls 変更)。
- D2 とは独立。並行着手可。
- 実装完了まで「E2E 暗号化」の主張は UI・ドキュメントともに
  「未実装」のまま維持する (現行通り、これは正しい状態)。
