# MLS メール — 言語非依存仕様

バージョン: 1.0 | 作成日: 2026-11-18

本書は、MLS (RFC 9420) を通常の電子メールで運ぶ方式「MLS メール」の
相互運用仕様である。主張はすべて参照実装 Kaname の現行コード
(`crates/kaname-mls` / `crates/kaname-ui` / `crates/kaname-render`) の
実態と一致させてあり、実装されていないものは「未実装」と明記する。
設計経緯は [design-d1-mls.md](../design-d1-mls.md) (D1 の Phase 1–5 分解。
本方式はその実装結果) と `docs/gap-analysis.md` D1 を参照。

---

## 1. 概要

MLS は本来、メッセージ配送を担う Delivery Service の存在を前提とする。
MLS メールは **Delivery Service をメール網そのもので置き換える**:
KeyPackage・Welcome・Commit・Application メッセージはすべて MIME パート
として通常のメールに載り、既存のメールサーバがそのまま配送する。
サーバ側の変更・専用インフラは不要であり、サーバから見れば暗号化された
添付を持つ通常のメールである。

- 暗号化の中核は MLS (RFC 9420) そのものであり、独自暗号は追加しない。
- 本書が規定するのは「メールへの載せ方」: MIME 形式、交換手順、
  エンベロープ形式、平文ペイロード規約、安全番号の導出と照合。
- メールトランスポート (JMAP / SMTP 等) は規定しない。MIME メッセージ
  として配送できる経路であればよい。参照実装は JMAP で送受信する。

---

## 2. プロトコルスタック

| 層 | 採用 |
|---|---|
| グループ暗号化 | MLS (RFC 9420)、ProtocolVersion = MLS 1.0 |
| Credential | BasicCredential。identity はメールアドレスの UTF-8 バイト列 |
| グループ ID | 32 バイトの乱数 (後述の ConversationId と同一視) |
| グループ設定 | Ratchet Tree Extension を使用 |

### Ciphersuite

エンベロープは使用した ciphersuite を名前で申告する (→ §7)。
定義済みは次の 2 つ:

| 名前 (エンベロープ上の表記) | MLS ciphersuite | 備考 |
|---|---|---|
| `MlsX25519Aes128GcmSha256Ed25519` | MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 | MLS の MTI ベースライン |
| `KanameHybridPqc` | MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 | X-Wing (ML-KEM-768 + X25519 ハイブリッド)、draft-ietf-mls-pq-ciphersuites |

参照実装の製品経路 (Kaname の MLS 初期化) は `KanameHybridPqc` を
既定とする。署名鍵は ciphersuite の署名方式 (いずれも Ed25519) で生成する。

参照実装の構成: OpenMLS 0.9 + libcrux 暗号プロバイダ
(`openmls_libcrux_crypto`)。相互運用に特定の MLS 実装は要求しないが、
KeyPackage / Welcome / MLS メッセージのワイヤ形式は RFC 9420 の
TLS プレゼンテーション言語による符号化そのものである。

---

## 3. MIME 形式

MLS メールは 2 種類の MIME パートで構成される。いずれも
`multipart/mixed` 内のパートとして送り、転送符号化は base64 とする。

| Content-Type | 内容 | 符号化前の実体 |
|---|---|---|
| `application/mls-key-package` | KeyPackage (§4) | RFC 9420 の TLS 直列化バイト列 |
| `application/mls-envelope+cbor` | エンベロープ (§7) | CBOR バイト列 |

受信側の判定は Content-Type のみで行い、ファイル名には依存しない。
参照実装の送信側ファイル名規約は次のとおり (受信処理には使わない):

| ファイル名 | 用途 |
|---|---|
| `kaname-mls-key-package.bin` | KeyPackage の送付 |
| `kaname-mls-invite.cbor` | 会話の招待 (Commit + Welcome のエンベロープ) |
| `kaname-mls-message.cbor` | 暗号化メッセージ (Application のエンベロープ) |

受信側は `Content-Disposition` を問わず全 MIME パートを走査し、
入れ子の `message/rfc822` も再帰的にたどる (相手クライアントが
インラインでパートを挿入する可能性に備えるため)。

### 受信側の資源制限 (参照実装の値)

悪意ある 1 通のメールで暗号演算やメモリを大量消費させないため、
参照実装は次の上限を持つ。相互運用の必須要件ではないが、同種の
制限を持つことを推奨する。

| 対象 | 上限 |
|---|---|
| 1 通あたりの同種 MLS パート数 | 32 |
| `message/rfc822` の入れ子深度 | 16 |
| エンベロープの復号対象サイズ | 4 MB |
| KeyPackage 1 件のサイズ | 64 KB |
| アドレスごとの KeyPackage 保有数 | 100 |

---

## 4. KeyPackage の交換

KeyPackage はグループへの招待に使う 1 回限りの公開鍵素材である。
秘密鍵素材は端末内の MLS ストレージに残り、決して送出しない。

1. **生成**: MLS スタックで KeyPackage を生成し、TLS 直列化する。
2. **送付**: §3 の `application/mls-key-package` パートとして通常の
   メールで相手に送る。KeyPackage は公開情報であり、秘匿は不要。
   カバー本文や件名は平文でよい。
3. **受信**: 受信側は TLS パースと MLS 1.0 としての検証 (形式と署名)
   を通過した KeyPackage だけを、送信者 (From アドレス) に紐付けて
   キャッシュする。検証に失敗したものは破棄する。
4. **消費**: KeyPackage は 1 回限りである。会話開始時に 1 つを消費し、
   同じ KeyPackage で二度会話を開始しない。

**信頼についての正直な限定**: KeyPackage の配送経路 (メール) 自体は
差し替えを検出できない。受け取った KeyPackage が「本当に相手のものか」
の確認は §8 の安全番号照合で行う。本方式は KeyPackage の配布を
認証しない。

---

## 5. 会話の確立 (招待)

1. 開始側は相手の KeyPackage を 1 つ消費し (§4)、新しいグループを
   作成する。グループ ID は新規の 32 バイト乱数とする。
2. 相手を追加する Commit と、相手が参加に使う Welcome を生成する。
3. エンベロープ `kind = Commit` に Welcome の TLS バイト列を
   `welcome` フィールドへ同梱し (§7)、`application/mls-envelope+cbor`
   パートとして送信する。
4. 受信側は Welcome を処理してグループに参加する。以後、双方向の
   暗号化メッセージ (§6) が可能になる。

### Welcome のリプレイ防止

受信側は処理済み Welcome の帳簿 `(conversation_id, epoch)` を保持し、
同一の組み合わせの再送を拒否しなければならない。openmls 自体は
Welcome の重複を検知しないため、この追跡は上位層の責務である。

- 帳簿への記録は **参加に成功した後にのみ** 行う。壊れた Welcome で
  帳簿の枠を消費させ、正規の再送を拒否させる攻撃を防ぐためである。
- 帳簿は再起動を跨いで永続化する (§9)。メモリ上だけの帳簿では
  再起動後にリプレイが通ってしまう。

---

## 6. 暗号化メッセージ

### 平文ペイロード規約

MLS Application メッセージの平文は次の形式とする:

```
平文 = 件名 (UTF-8) ‖ 0x00 ‖ 本文 (UTF-8)
```

受信側は最初の `0x00` で分割する。**件名も暗号化対象に含める** —
外側メールの件名・本文には実内容を一切置かず、定型のプレースホルダ
のみとする (参照実装は外側の件名を「(暗号化メッセージ)」、本文を
開封方法の案内文にしている)。

### 送信と受信の検証

- 送信側は平文を MLS Application メッセージとして暗号化し、
  エンベロープ `kind = Application` で送る (§7)。
  参照実装の平文上限は 25 MB。
- 受信側は次の検証を行う:
  - 未知の会話 (Welcome / Commit を先に受けていない会話) への
    Application は拒否する。
  - Application の epoch が最後に処理した epoch より小さい場合は
    拒否する (巻き戻し・リプレイの防止)。
  - Commit の epoch は最後に処理した epoch より厳密に前進して
    いなければならない。

---

## 7. エンベロープ形式

エンベロープは MLS メッセージと、その解釈に必要な最小限のメタデータを
運ぶ CBOR 構造である。符号化は CBOR マップ (キーはフィールド名の
テキスト文字列) で、バイト列フィールドは CBOR byte string、
列挙値はテキスト文字列、`welcome` が無い場合は null とする。
参照符号化は serde / ciborium による `Envelope` 構造体の直列化である。

| キー | 型 | 内容 |
|---|---|---|
| `conversation_id` | byte string (32 バイト) | グループ ID |
| `epoch` | unsigned int | エンベロープ生成時点のグループ epoch |
| `kind` | text | `Application` / `Commit` / `Welcome` / `ExternalJoin` |
| `ciphersuite` | text | §2 の名前 (`MlsX25519Aes128GcmSha256Ed25519` / `KanameHybridPqc`) |
| `wire_bytes` | byte string | TLS 直列化された MLS メッセージ |
| `welcome` | byte string または null | Welcome を同梱する場合のみ (招待時) |

`kind` の使い分け:

- `Application`: 暗号化メッセージ (§6)。
- `Commit`: グループ管理 (追加・削除・更新)。招待時は `welcome`
  フィールドを伴う (§5)。
- `Welcome`: Welcome 単独の運搬。受信処理は定義されているが、
  参照実装の送信経路は `Commit` + `welcome` フィールドを使う。
- `ExternalJoin`: 形式上定義されているが、**参照実装では処理未実装**
  であり、受信しても制御メッセージとして無視される。相互運用の
  対象外とする。

---

## 8. 安全番号 (Safety Number)

KeyPackage 配布が認証されない (§4) ため、相手の同一性は安全番号の
帯域外照合で確認する。

### 導出

```
digest = SHA-256(
    len16(first)  ‖ first  ‖ 0x00 ‖
    len16(second) ‖ second ‖ 0x00 ‖
    epoch_authenticator
)
```

- `first` / `second` は 2 者のメールアドレス (UTF-8) をバイト順で
  正準化したもの (小さい方を `first`)。呼出側の自他に依存せず、
  両側で同じ入力になる。
- `len16(x)` は `x` のバイト長を u16 ビッグエンディアンで表したもの。
  長さプレフィックスと `0x00` 区切りにより、フィールド境界を
  あいまいにする連結攻撃を防ぐ。
- `epoch_authenticator` は MLS グループの epoch authenticator
  (全メンバーが同一値を共有する)。

### 表示

ダイジェストの先頭 30 バイトを 5 バイトずつ 6 グループに分け、
各グループを 40 ビット整数として読み、`100000` で割った余りを
5 桁ゼロ埋めで表示する (Signal 方式の 30 桁):

```
##### ##### ##### ##### ##### #####
```

### 照合の運用

- 照合は電話・対面等の別経路で行い、照合した時点の番号を記録する。
- 記録した番号と現在の番号が食い違えば、鍵変更・再参加・中間者の
  可能性として警告する。
- 安全番号は epoch_authenticator から導出されるため、epoch が
  変われば値も変わりうる。参照実装では会話の確立・参加時に計算する。

---

## 9. 永続化 (参照実装)

相互運用の要件ではないが、再起動で状態が消えると §5 のリプレイ防止が
成立しないため、参照実装の永続化範囲を明記する。

- OpenMLS のグループ状態・署名鍵、会話メタ (種類・epoch・安全番号・
  メンバー)、Welcome 帳簿は SQLCipher データベースに永続化する
  (鍵は 64 桁の 16 進文字列、`PRAGMA key`)。
- KeyPackage キャッシュは永続化しない。他人の公開 KeyPackage であり、
  失われても再送で再取得できるためである。

---

## 10. 非対応相手へのフォールバック

MLS メールは全員が対応している前提には立たない。受信者は次の 3 つに
分類し、対応できない相手には通常の平文メールを送る (暗号化されない
ことが送信者に分かる形で送る — 「暗号化したつもり」を作らない)。

| 分類 | 条件 | 動作 |
|---|---|---|
| MLS 可能 | KeyPackage を保持している | MLS メールで送る |
| KeyPackage が必要 | MLS 対応と見込まれるが KeyPackage が無い | §4 の交換から始める |
| 非対応 | 上記のいずれでもない | 通常の平文メール |

対応可否の判定方法は実装依存である。参照実装は KeyPackage キャッシュ
の有無とドメインのヒューリスティクスで分類する (`RecipientPolicy`)。

---

## 11. セキュリティ考慮

- **サーバと配送経路に見えるもの**: 宛先・時刻・サイズ等のメタデータと
  暗号化されたパートのみ。件名・本文は見えない (§6)。
- **前方秘匿と侵害後安全性**: MLS プロトコル自体の性質として得られる
  (RFC 9420)。PGP のような「1 つの長期鍵で全履歴が解ける」構造はない。
- **KeyPackage 差し替え**: 配送経路での差し替えは §8 の安全番号照合で
  検出する。本方式単体では検出できない。
- **Welcome リプレイ**: §5 の帳簿で防ぐ。
- **epoch の巻き戻し**: §6 の検証で拒否する。
- **改変されたパート**: MLS の認証で復号・処理は失敗する。内容の
  漏洩にはつながらない (配送不能になるだけである)。
- **リソース枯渇**: §3 の資源制限で緩和する。

---

## 12. 実装状況 (参照実装 Kaname、2026-11 時点)

実装済み:

- KeyPackage の生成・検証・添付往復・1 回限り消費 (§4)
- 招待による 1:1 会話の確立 (Commit + Welcome) と Welcome
  リプレイ防止 (§5)
- 暗号化メッセージ (件名を含むペイロード規約) (§6)
- 受信メールからのエンベロープ / KeyPackage パートの自動抽出と処理
- 安全番号の導出・照合記録・変化時の警告 (§8)
- SQLCipher への永続化と再起動後の復元 (§9)
- 送信時の DLP 評価は暗号化前の実件名・本文に対して行う
  (E2EE と情報漏洩防止を両立させるための参照実装の配線)

未実装・対象外:

- `ExternalJoin` エンベロープの処理 (§7)
- グループ (Team) 会話: `kaname-mls` の型・API レベルでは用意されるが、
  製品の送信経路は 1:1 会話のみ。本書の相互運用対象は 1:1 の確立と
  メッセージ交換とする。
- KeyPackage のサーバ配布 (ディレクトリ) 経路。本方式は添付往復のみを
  規定する。

---

## 13. 参照

- RFC 9420: The Messaging Layer Security (MLS) Protocol
- RFC 9750: The Messaging Layer Security (MLS) Architecture
- draft-ietf-mls-pq-ciphersuites (X-Wing ハイブリッド ciphersuite)
- RFC 5322 / MIME (RFC 2045–2049)
- 参照実装: `crates/kaname-mls` (方式のコア)、
  `crates/kaname-ui/src/commands.rs` (送受信配線)、
  `crates/kaname-render` (MIME パート抽出)
