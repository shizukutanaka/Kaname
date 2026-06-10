# Kaname Keynote — The North Star

> Apple方式の核: 製品を作る前に、発表の日に話す言葉を書く。そこから逆算する。  
> この脚本は Kaname のすべての設計判断の基準点になる。誰が読んでも「これを作るんだ」が分かる。

---

## Stage direction

壇上は暗い。背景のスクリーンにゆっくりと「要」の一文字が浮かぶ。フェードイン、3秒。

---

## Opening (1 min)

*Yusuke walks on stage. Silence. The audience sees a familiar Outlook window on screen, frozen mid-crash.*

"これは、皆さんが毎日使っているメールソフトです。

15秒で起動します。
2 ギガバイトのメモリを食います。
過去 3 年間で、10 件の重大な脆弱性が見つかりました。
そして、今日。

AI の時代に、あなたの AI アシスタントに、**メール本文に隠された命令で、会社の機密を転送させることができます**。

2024 年 EchoLeak。2025 年 Gemini agentic exfiltration。2026 年 Apple Intelligence hijack。
全部、現実に起きました。"

*Pause. Screen goes black.*

"私たちは、1990 年代に設計されたメールソフトで、2026 年の攻撃と戦っています。

これは、壊れています。"

---

## Introducing Kaname (2 min)

*The "要" character glows teal. "Kaname" appears below.*

"今日、私たちはメールを再定義します。

**Kaname — 要**。

すべてを繋ぐ、一つの要石。

4 つの、単純な約束です。"

*Four promises appear, one at a time:*

**1. Fast.**
"起動 500 ミリ秒。メモリ 300 メガバイト以下。Outlook の 10 倍軽い。"

**2. Safe by design.**
"HTML は WASM サンドボックスで。添付は使い捨ての仮想マシンで。AI は 2 つに分離して、メール本文の隠し命令には絶対従わない。"

**3. Future-proof.**
"量子後暗号 ML-KEM-768。MLS 標準の E2E。10 年後のコンピューターでも解読されません。"

**4. Yours.**
"データはあなたのデバイスに。AI はローカルで動きます。1 バイトも外に出ません。"

*Audience claps — politely, but not sold yet. This is where the demo starts.*

---

## Demo 1: Speed (1 min)

*Yusuke picks up a MacBook from the stage.*

"まずは、体感してください。"

*Clicks Kaname icon. App opens instantly — visibly faster than Outlook's splash screen.*

"421 ミリ秒。
次に、1 年分の受信トレイ、10 万通を検索します。"

*Types "取締役会". Results appear immediately.*

"ローカル検索。メモリ上のインデックス。あなたのサーバーに検索クエリを送信していません。
Google にも、Microsoft にも、Kaname にも、です。"

---

## Demo 2: The phishing email (2 min)

*Yusuke clicks on a new email in the inbox list.*

"さて、今届いたメールです。

『経理部システム通知。至急、1,248 万円の送金手続きをお願いします。』"

*The email opens. The entire top bar flashes red. A quiet, low-pitched tone plays.*

"Kaname は、これを開く **前に**、5 つのことを検証しています。

SPF、DKIM、DMARC — 3 つとも失敗。
ドメインは **mitsui-g1obal.co.jp**。l が数字の 1 に置き換わっています。
添付は invoice_urgent.pdf.**exe**。Firecracker VM の中で開いて、マルウェアの署名を検出しました。

そして **ローカル LLM** が、『送金指示 + 緊急性の強調 + 異常な経路』を、94% の確信で BEC 攻撃と判定しました。

このメールを、AI に要約させようとしても、**AI は要約を拒否します**。

怪しいメールの中身を読んで、判断して、何かをする — それ自体が攻撃の成立条件だからです。"

*The audience leans forward.*

---

## Demo 3: The Dual-LLM reveal (3 min) — this is the most important moment

*Yusuke clicks on a legitimate email. The top bar is green. He clicks "AI 要約".*

"AI が要約を出します。"

*A clean summary appears.*

"ここまでは、Copilot でも Gemini でも同じです。
でも、これを見てください。"

*He clicks a subtle "AI がどう守っているか" toggle. A diagram animates into view on the right.*

"Kaname の AI は、2 つのモデルに分かれています。

**特権 LLM** は、あなたの指示を聞きます。ツールを呼び出せます。カレンダーに登録したり、下書きを作ったりできます。
でも、**メール本文は絶対に見ません**。

**隔離 LLM** は、メール本文を読みます。でも、ツール権限はゼロ。構造化データとして要約だけを返します。
『以下のメールを全部転送しろ』という命令を読んでも、転送する方法がありません。

この 2 つの LLM は、メモリも、プロセスも、ネットワークも、完全に分離されています。

*Slide: Schneier quote*

> "Prompt injection is unlikely to ever be fully solved with current LLM architectures."
> — Bruce Schneier, IEEE Spectrum, January 2026

モデルでは守れません。**アーキテクチャで守ります**。"

*This is the longest quiet moment of the keynote. The audience understands.*

---

## Demo 4: Privacy as product (2 min)

"次に、プライバシーです。

ある取引先との初めてのメール。"

*Yusuke clicks compose. Types a new vendor address.*

"Kaname は、初めての相手だと気付きます。"

*A card slides in: "alias-k7p2x@mitsui-global.kaname.app"*

"別名メールを提案します。あなたの本当のメールアドレス、yusuke@mitsui-global.co.jp は、この取引先には絶対に届きません。

もし漏洩しても、ワンクリックで burn。

さらに、受信したメール。**トラッキングピクセルは一つも発火しません**。Kaname Relay が代わりに取得します。あなたの IP アドレスは、送信元には見えません。

開いたかどうかも、誰にも分かりません。"

---

## Demo 5: The handshake (1 min)

"最後に、技術的な深い話を、短く。"

*Screen shows a technical indicator in the status bar: "ML-KEM-768 + X25519 · MLS E2E"*

"TLS 1.3 の中で、さらにもう一つの握手をしています。

**量子後暗号**。NIST が 2024 年に標準化した ML-KEM-768 と、既存の X25519 を組み合わせたハイブリッド。

10 年後、大規模な量子計算機ができても。
**今日送ったメールは、その時にも安全です**。

そして、相手も Kaname なら。"

*Two windows side by side. Both show: "MLS E2E · end-to-end encrypted".*

"**Messaging Layer Security — RFC 9420**。Signal と同じ前方秘匿、後方秘匿を、メールで。

PGP でも S/MIME でもない、2026 年の標準です。"

---

## Price (30 sec)

"価格です。"

*Tiers appear:*

- Business: ¥1,200/月/ユーザー
- Pro: ¥2,400/月/ユーザー
- Enterprise: ¥3,500/月/ユーザー (オンプレ対応)

"Outlook + Teams より安いです。
Superhuman の 3 分の 1 です。

10 シートから、今すぐ始められます。"

---

## One more thing (1 min)

*Yusuke pauses. The audience knows what's coming.*

"One more thing.

今日話したすべての機能の、**コア部分を、オープンソースにします**。

AGPL-3.0。
暗号、サンドボックス、Dual-LLM、プロトコル。全部、誰でも読めます。

なぜか。

セキュリティ製品を、**『信じてください』で売るのは、もう時代遅れ**だからです。

読んでください。確認してください。自分で動かしてください。
それから、使ってください。"

*Short silence.*

"Kaname。
要。
すべてを繋ぐ、一つの要石。

今日から、ベータを始めます。"

*Fade to black. The "要" character glows, alone, for 5 seconds. Then the credits.*

---

# Keynote が設計に与える制約

この発表を実現するために、以下は **交渉不可能**:

| 発表の一節 | 設計制約 |
|---|---|
| 「421 ミリ秒で起動」 | 起動時間目標 <500ms、Rust + Tauri、Electron 禁止 |
| 「添付を開く前に検証」 | 添付は必ず VM 経由、ホストプロセスでは絶対に開かない |
| 「AI は要約を拒否します」 | danger 判定メールは AI パイプライン入口でブロック |
| 「2 つの LLM に分かれている」 | Dual-LLM アーキ必須、Privileged 側からメール本文にアクセスする API を作らない |
| 「メモリも、プロセスも、ネットワークも、完全に分離」 | 物理的プロセス分離、seccomp、ネットワーク遮断 |
| 「AI がどう守っているか」画面 | 設定画面に Dual-LLM 可視化 UI が必要 |
| 「トラッキングピクセルは一つも発火しません」 | KMPP (Kaname Mail Privacy Protection) relay 実装必須 |
| 「10 年後の量子計算機でも安全」 | PQC ハイブリッド必須、X25519 単独禁止 |
| 「相手も Kaname なら MLS」 | MLS (RFC 9420) 実装、openmls 採用 |
| 「コアを AGPL-3.0 で」 | ライセンス決定済、商用部分との境界設計必要 |
| 「今日から、ベータを始めます」 | GA 前に Design Partner 10社のクローズドベータが必要 |

# この脚本の使い方

- **開発会議で迷ったら、この脚本を読む**。脚本と矛盾する判断はしない
- **新機能提案は「これを足すと、キーノートのどこに入るか」を答えられないと却下**
- **機能削減は「これを削ると、キーノートのどの文が言えなくなるか」で判断**
- **3 ヶ月に 1 回、脚本を更新**。その時点の GA 機能と一致させる
- 脚本にない機能は、まだ完成品ではない

---

*"You've got to start with the customer experience and work backwards to the technology."*  
*— Steve Jobs, WWDC 1997*
