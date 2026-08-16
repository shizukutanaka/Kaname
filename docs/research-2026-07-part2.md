# 2026-07 追加研究調査 (Part 2) — セッション横断の反映マップと構造的発見

> `docs/research-2026-07.md` (Part 1) の続編。Part 1 以降のセッションで調査した
> 2026 年の研究・技術情報と、それに基づく実装 (PR #25〜#33)、および調査の過程で
> 判明した**構造的な配線ギャップ (D10/D16/D17)** を、所有者向けの優先ロードマップ
> として統合する。
>
> **最重要の結論を先に**: 検出器の強化は着実に進んだが、調査を重ねるほど
> 「Kaname は優れたセキュリティ**ライブラリ集**であって、まだメールクライアント
> としては配線されておらず、中核の型境界も実効化されていない」という同じ根に
> 繰り返し突き当たった。次に価値があるのは新しい検出器ではなく、
> **(1) ネットワーク解放による全コミットの `cargo test` 検証、(2) D17 の型境界
> 実効化、(3) D10/D16 の配線** である。いずれもネットワークが前提。

---

## 1. 2026 年研究動向の総括 (Part 1 以降に調査した範囲)

### 1.1 防御はアーキテクチャ保証へ収束
- **CaMeL** ([csail 2026 講読版](https://css.csail.mit.edu/6.5660/2026/readings/camel.pdf))、
  **FIDES**、Progent、RTBAS、FORGE — いずれも「モデル外の決定論的ポリシー」で
  防御し、AgentDojo で攻撃をほぼ排除。**振る舞いではなくアーキテクチャによる保証**。
- [適応的評価 2606.26479](https://arxiv.org/html/2606.26479v1) が out-of-band 防御を横断比較。
- **Kaname の位置づけ**: Dual-LLM + `Content<Untrusted>` の型境界はこの系譜の
  さらに強い「型レベル保証」を志向している。**ただし §3 の通り現状は未実効**。

### 1.2 マルチモーダル / 間接プロンプト注入
- [LLMail-Inject 2605.17634](https://arxiv.org/pdf/2605.17634) — 良性メールに埋め込まれた
  4,300 件の人手作成注入。**エージェントの判定チャネル自体が攻撃対象**になる。
- [ARGUS 2605.03378](https://arxiv.org/abs/2605.03378v1) — 影響伝播グラフで
  「決定が信頼できる根拠に裏付けられているか」を実行前に検証 (ASR 3.8%)。
- [画像ベース注入 2603.03637](https://arxiv.org/abs/2603.03637) / CSA note (2026-03) —
  画像埋め込み命令がテキスト層のサニタイズを迂回、ステルス下で最大 64%。
  XML/SVG では CDATA 悪用・XXE 形式ペイロードが名指し。

### 1.3 メール固有の攻撃進化
- **DKIM リプレイ / DMARC OR trap** — 正規署名済みメールを再送。DMARC は
  SPF/DKIM の OR 判定のため通過。2025 年に Google スプーフィング実被害。
- **動的 QR / テキスト QR** — quishing 2026 上半期 146% 増。FBI が 2026-01 に
  Kimsuky/APT43 の利用を警告。短縮 URL/リダイレクタで配信後に差し替え、
  点字/幾何学記号で画像スキャン回避 (Barracuda)。
- **表示名ホモグラフ** — ホモグリフ悪用の主戦場が URL から From 表示名へ移行
  (Unit 42 / arxiv 2604.04926)。
- **deepfake 増強 BEC** — deepfake が BEC の **40%** に関与 (2023 年は 5% 未満)。
  メール + 「CEO を騙る音声メモ」で確認を偽装する複合攻撃。

---

## 2. このセッションの実装マップ (研究 → PR)

| 研究・動向 | 実装 | クレート | PR |
|---|---|---|---|
| LLMail-Inject / ARGUS (判定チャネルの詐称) | AI 出力の「セキュリティ判定詐称」検出 | kaname-screen | #25 |
| 表示名ホモグラフ (Unit42/2604.04926) | `analyze_display_name`/`fold_homoglyphs`、reply_to_spoof の畳み込み照合 | kaname-bec | #26 |
| RFC 2047 soft hyphen 難読化 | 件名・本文の照合を正規化経由に統一 | kaname-bec | #27 |
| SVG 添付急増 (SANS/OPSWAT/MS) | `svg_guard` (script/handler/scheme/foreignObject/多層エンコード) | kaname-render | #28 |
| DKIM リプレイ / DMARC OR trap | `d=` と From ドメインの整合検証 | kaname-bec | #29 |
| 動的 QR / テキスト QR (Barracuda/FBI) | 短縮URL・点字/幾何学記号の検出 | kaname-render | #31 |
| 画像ベース注入 2603.03637 (CDATA/XXE) | `svg_guard` に PromptScreener + XXE 検出 | kaname-render | #32 |
| CaMeL/FIDES (アーキテクチャ保証) | **Dual-LLM 型境界の実効性監査と正直化** | (docs) | #33 |

補足: いずれの検出器も**添付/メール処理パイプラインには未配線** (下記 D10/D16)。
研究反映は「その脅威が来たとき正しく判定できるロジックを用意した」段階であり、
実メールに適用されるには配線が必要。

---

## 3. 構造的発見 (検出器強化より優先すべき根本課題)

調査を重ねる中で、個々の検出漏れよりも重大な**構造的ギャップ**が判明した。
これらは `docs/gap-analysis.md` に D10/D16/D17 として file:line 付きで記録済み。

### D10 — メールクライアントとしての配線が存在しない
`kaname-ui` が `kaname-jmap`/`kaname-store` に依存しておらず、出荷バイナリから
ネットワークにも DB にもコンパイル時点で到達経路が無い。`messages` テーブルへの
INSERT/SELECT はワークスペース全体でゼロ件。**現状は「メールクライアント」では
なく「メールセキュリティ・ライブラリ集 + デモ UI」**。

### D16 — 添付由来テキストの AI 入力経路が丸ごと未配線
`preflight_untrusted()` は正しく実装されているが**プロダクション呼び出し元が
0 件**。`kaname-sandbox` はどのクレートからも依存されておらず、`AssessmentRequest`
に添付テキストのフィールドが無く**本文のみスクリーニングされる非対称**がある。

### D17 — Dual-LLM の型不変条件が「宣言」と「実装」に分離
README は「コンパイル時型安全」を掲げるが、**`impl QuarantinedLlm`/`PrivilegedLlm`
が 0 件**で実推論経路 `llm_bridge` は生 `&str` API。`as_text()` は `pub` で I1 は
規約、`Content<L>` の `Deserialize` derive で `Content<Trusted>` を JSON 偽造可能、
`subprocess.rs` は P-LLM に `(allow network-outbound)` を与え CLAUDE.md I4 と矛盾
(参照先 `resources/seccomp/` は不在)。**I3 の中核 (private フィールド / 公開
コンストラクタ 2 つ / `pub(crate)` 昇格路 / unsafe ゼロ / compile_fail テスト) は
本物**。現時点で悪用経路は無い (未配線・推論スタブ) が、配線時に確実に穴になる。

---

## 4. 優先ロードマップ (ネットワーク解放が前提)

| 優先 | 作業 | 根拠 | 前提 |
|---|---|---|---|
| **P0** | 全コミット (#24〜#33) の `cargo check --workspace` + `cargo nextest run` | このセッションの実装は全て crates.io 403 で**検証未了**。#24 は main.rs に 160 行、#28/#32 は新規モジュール | crates.io egress 解放 |
| **P1** | D17(c): `llm_bridge` を `dual_llm` の trait を実装する形に変更し `&str` 入口を塞ぐ | 配線時の最短経路を型安全側へ倒す。**最も重要** | P0 |
| **P1** | D17(a,b,d): `Content` の serde derive 除去 / `as_text` を `pub(crate)` / `TopicTag` の Deserialize 迂回封じ | 中核型のため要ワークスペース再コンパイル | P0 |
| **P2** | D10 + D16 の配線 (jmap 受信 → store 永続化 → 表示 → 送信、添付テキストの preflight 強制) | 検出器に初めて実メールが流れる | P1 |
| **P3** | I4 の矛盾解消 (所有者判断: コードを I4 に合わせるか I4 改訂か)、`resources/seccomp/` 実体作成 | CLAUDE.md I4 は「変更禁止」 | 所有者判断 |
| P4 | 画素 typographic 注入 (OCR)、自前ドメインの動的 QR 追跡 (要ネットワーク) | 今回の実装で原理的に届かない残余リスク | 設計判断 |

---

## 5. 正直な総括

- **長所 (研究に照らして裏付けられた)**: 検出ロジック (BEC/DLP/quishing/SVG/
  CSS exfil/MIME/SSRF/homograph/DKIM) は 2026 年の最新動向を反映し世界水準。
  OOBV の N 番目ワード・チャレンジは deepfake 音声を実際に無効化する堅牢な設計。
  Dual-LLM の型境界「定義」と I3 の中核は本物。
- **短所 (繰り返し突き当たった根)**: それらが**アプリに配線されておらず** (D10/D16)、
  中核の型境界が**実効化されていない** (D17)。そして全実装が**未検証** (crates.io 403)。
- **改善の要点**: これ以上検出器を増やすより、**P0 (検証) → P1 (型実効化) →
  P2 (配線)** の順で「持っている力を実際に効かせる」ことが桁違いに価値が高い。
  いずれもネットワーク解放が律速。

## 出典 (Part 1 と重複しないもの)

- CaMeL: https://css.csail.mit.edu/6.5660/2026/readings/camel.pdf
- 適応的評価 (out-of-band 防御): https://arxiv.org/html/2606.26479v1
- LLMail-Inject: https://arxiv.org/pdf/2605.17634
- ARGUS: https://arxiv.org/abs/2605.03378v1
- 画像ベースプロンプト注入 / CSA note (2026-03): https://arxiv.org/abs/2603.03637
- User Deception Techniques in Emails: https://arxiv.org/pdf/2604.04926
- DMARC OR trap: https://dstreefkerk.github.io/2026-03-the-dmarc-or-trap-how-attackers-bypass-dkim/
- SVG 配信マルウェア (OPSWAT): https://www.opswat.com/blog/svg-delivered-malware-is-flooding-emails-here-is-what-actually-blocks-it
- deepfake 増強 BEC (40%): https://www.digitalapplied.com/blog/ai-deepfake-attacks-surge-40-percent-email-compromise
