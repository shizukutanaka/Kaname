# メール事情ランドスケープ — 改善候補レポート

`scripts/mail-landscape/landscape.py collect` が生成。手編集しないこと。

生成日時 (UTC): 2026-10-15T06:31:17Z
対象期間: 過去 90 日

収集件数:
- arxiv: 8
- ietf: 19
- zenn: 23
- qiita: 29
- github: 40
- hn: 42

収集失敗:
- なし

## 1. ギャップ (未カバーの話題)

### dmarcbis-dkim2 — DMARCbis / DKIM2 (送信ドメイン認証の独立検証)
- 件数: 8
- note: Authentication-Results の文字列パースに依存し、独立検証していない (docs/research-2026-07-part2.md §1.4)
- [marmot7775/dns-audit](https://github.com/marmot7775/dns-audit) (github, 2026-10-15)
- [A Diagnostic Header Field for DKIM2 Implementations](https://datatracker.ietf.org/doc/draft-gondwana-dkim2-debug-header/) (ietf, 2026-10-01)
- [DKIM2 Sender Policy](https://datatracker.ietf.org/doc/draft-chuang-dkim2-sender-policy/) (ietf, 2026-09-21)

### ai-generated-phishing — 生成 AI で書かれたフィッシング文面
- 件数: 1
- note: 文面が AI 生成かどうかを判定する検出器はない
- [Engineered Persuasion: Evaluating Personalized Pretexts in LLM-Generated Spear Phishing](http://arxiv.org/abs/2609.04410v1) (arxiv, 2026-09-03)

## 2. カバレッジのずれ

なし

## 3. 話題量ランキング

| 話題 | 件数 | カバー |
| --- | ---: | :---: |
| DMARCbis / DKIM2 (送信ドメイン認証の独立検証) | 8 | — |
| BIMI / VMC | 5 | ✓ |
| AiTM / MFA 回避フィッシングキット | 4 | ✓ |
| メール経由の (間接) プロンプトインジェクション | 3 | ✓ |
| 生成 AI で書かれたフィッシング文面 | 1 | — |
| 大量送信者要件 (ワンクリック登録解除など) | 1 | ✓ |
| カレンダー招待の自動登録悪用 (CalPhishing) | 1 | ✓ |
| 文体変化によるアカウント乗っ取り検出 | 1 | ✓ |
| ARC (転送時の認証連鎖) | 0 | ✓ |
| bidi 制御文字 / ANSI エスケープ | 0 | ✓ |
| 電話誘導型 (TOAD / コールバック) フィッシング | 0 | ✓ |
| deepfake 併用 BEC | 0 | ✓ |
| DKIM リプレイ | 0 | ✓ |
| ホモグラフ (ドメイン・表示名) | 0 | ✓ |
| HTML スマグリング | 0 | ✓ |
| QR コードフィッシング (分割/ネスト QR 含む) | 0 | ✓ |
| SVG 添付によるフィッシング | 0 | ✓ |
| スレッド乗っ取り | 0 | ✓ |

## 4. 新出語の候補 (どの話題にも未登録)

- ドメイン (14)
- レコード (9)
- gmail (8)
- mta-sts (7)
- domainkeys (6)
- google (6)
- smtp (6)
- verification (6)
- サイト (6)
- access (5)
- across (5)
- address (5)
- addresses (5)
- checks (5)
- cloudflare (5)

## 5. 話題別の最新記事

### dmarcbis-dkim2 — DMARCbis / DKIM2 (送信ドメイン認証の独立検証)
- [marmot7775/dns-audit](https://github.com/marmot7775/dns-audit) (github, 2026-10-15)
- [A Diagnostic Header Field for DKIM2 Implementations](https://datatracker.ietf.org/doc/draft-gondwana-dkim2-debug-header/) (ietf, 2026-10-01)
- [DKIM2 Sender Policy](https://datatracker.ietf.org/doc/draft-chuang-dkim2-sender-policy/) (ietf, 2026-09-21)

### bimi — BIMI / VMC
- [marmot7775/dns-audit](https://github.com/marmot7775/dns-audit) (github, 2026-10-15)
- [DavidAslanyan/email-auth-observatory](https://github.com/DavidAslanyan/email-auth-observatory) (github, 2026-10-13)
- [maksimtech/mailradar](https://github.com/maksimtech/mailradar) (github, 2026-10-12)

### aitm — AiTM / MFA 回避フィッシングキット
- [Detecting and mitigating a multi-stage AiTM phishing and BEC campaign (2023)](https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/) (hn, 2026-09-19)
- [$10k phishing kit enrolls Google passkeys that survive pw resets](https://abnormal.ai/blog/iauthflow-v2-phishing-google-passkeys) (hn, 2026-08-25)
- [$10K phishing kit claims it can plant rogue passkeys for persistent access](https://www.theregister.com/cyber-crime/2026/08/21/10k-phishing-kit-claims-it-can-plant-rogue-passkeys-for-persistent-access-to-pwned-accounts/5291006) (hn, 2026-08-21)

### prompt-injection — メール経由の (間接) プロンプトインジェクション
- [domainlab-app/domain-lab-mcp](https://github.com/domainlab-app/domain-lab-mcp) (github, 2026-10-14)
- [Phishing emails are now baiting your AI assistant](https://www.malwarebytes.com/blog/ai/2026/10/phishing-emails-are-baiting-your-ai-assistant) (hn, 2026-10-12)
- [ASCII smuggling crosses over from AI prompt injection to phishing evasion](https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/) (hn, 2026-09-07)

### ai-generated-phishing — 生成 AI で書かれたフィッシング文面
- [Engineered Persuasion: Evaluating Personalized Pretexts in LLM-Generated Spear Phishing](http://arxiv.org/abs/2609.04410v1) (arxiv, 2026-09-03)

### bulk-sender-rules — 大量送信者要件 (ワンクリック登録解除など)
- [Gmail1強時代に、自前ドメインでメールをセルフホスティングするということ](https://zenn.dev/akagifreeez/articles/gmail-era-selfhost-email-two-routes) (zenn, 2026-09-22)

### calendar-phishing — カレンダー招待の自動登録悪用 (CalPhishing)
- ['You have a meeting': the calendar phishing scam growing exponentially](https://www.theguardian.com/money/2026/oct/11/calendar-phishing-scam-meeting-renewal-google-microsoft-paypal) (hn, 2026-10-11)

### style-ato — 文体変化によるアカウント乗っ取り検出
- [日経で約9000通、正規アカウント乗っ取りのなりすましメール。SPF/DKIM/DMARCでは防げない「本物から来た偽メール」への備え](https://qiita.com/harupython/items/674701489fcd8035e6d4) (qiita, 2026-10-05)
