# サンプルメール — Kaname を実データで動かす

`examples/emails/` には、Kaname の解析パイプラインを**実際に動かして確かめる**ための
`.eml` サンプルが入っています。サーバ接続もアカウント設定も不要です。

## 使い方

1. アプリを起動する

   ```bash
   npm run tauri dev
   ```

2. ナビゲーションの「**ファイル解析**」タブを開く

3. 1 通だけ解析する場合 — パス欄に `.eml` のフルパスを入力し「**1通を解析**」

   ```
   /path/to/kaname/examples/emails/02-bec-wire-transfer.eml
   ```

4. まとめて解析する場合 — パス欄に**フォルダ**のフルパスを入力し「**フォルダを一括解析**」

   ```
   /path/to/kaname/examples/emails
   ```

## 各サンプルが何を試すか

| ファイル | 想定される判定 | 検出されるはずのもの |
|---|---|---|
| `01-safe-meeting.eml` | SAFE | SPF/DKIM/DMARC がすべて pass。緊急性も金銭要求もない通常の業務メール |
| `02-bec-wire-transfer.eml` | SUSPICIOUS 〜 DANGEROUS | 認証の全失敗、`arnazon-billing.com` (`amazon` のタイポスクワット)、緊急性 + 送金要求の共起、Reply-To がフリーメールで送信元ドメインと不一致 |
| `03-quishing-textqr.eml` | SUSPICIOUS 以上 + 本文リスク | 認証失敗に加え、**本文に文字で描かれた QR コード** (画像スキャンを回避する quishing) を検出 |
| `04-sensitive-data.eml` | SAFE + **DLP 検出あり** | 認証はすべて pass の正規メールだが、本文に**区切り付きのクレジットカード番号と IBAN** が含まれる。転送・返信時の漏洩リスクとして DLP が検出する (区切り付き表記は検出漏れしやすい典型例) |
| `05-malicious-link.eml` | SUSPICIOUS 以上 + **リンク警告** | 認証失敗に加え、本文のリンクが**短縮 URL (`bit.ly`)** と **`amaz0n-verify.tk` (数字置換タイポスクワット + 自由 TLD)**。本文リンクの評判判定と BEC の URL シグナルの両方が発火する |

### フォルダ一括解析でのみ見えるもの

`02` と `03` は**同じ攻撃インフラ (`arnazon-billing.com`) を共有**しています。
1 通ずつ解析しても分かりませんが、フォルダ一括解析では
`kaname-radar` (ポリモーフィック・キャンペーン検出) が両者を結び付け、
「**複数メールにまたがるキャンペーン**」として警告します。

これは「複数のメールを見比べて初めて意味を持つ」検出であり、
一括解析がこの機能を使う唯一の入口です。

## 実装状況について

これらのサンプルは**実際のメールファイル**であり、モックデータではありません。
MIME 解析・送信ドメイン認証の評価・BEC 判定・HTML サニタイズ・本文リスク検出は
すべて本物の実装が動きます。

一方で、**サーバとのメール送受信 (JMAP) は未配線**です。
詳細は [`docs/maturity.md`](../docs/maturity.md) と
[`docs/gap-analysis.md`](../docs/gap-analysis.md) を参照してください。
