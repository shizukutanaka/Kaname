# 2026-07 最新研究調査 — Kaname への反映マップ

調査日: 2026-07-10。関連論文・業界レポート・IETF標準化動向を調査し、
実装状況 (実コード確認済み) と突き合わせた結果。長所・短所・改善点を
1ファイルに集約する。

方針: 出典を明記し、推測と事実を区別する。「対応済み」は実コードを
確認したもののみ。

---

## 1. 調査で判明した脅威・技術動向

### 1.1 Quishing (QRフィッシング) の構造的進化

- 分割QR (Structured Append)・ネストQR・ASCIIアートQR・Blob URI により
  「画像1枚をスキャンして中のURLを照会する」型の防御を回避する亜種が
  2025-26年に急増。2026-03 には28通のquishingメールが全てセキュリティ
  ツールを素通りした3波キャンペーンが報告された。
- 出典: ReversingLabs "QR Code Phishing Evolves"、Acronis 2026、
  Barracuda (split/nested QR)、FBI (Kimsuky のQRスピアフィッシング 2026-01)。
- **Kaname への反映 (今回実装)**: `kaname-render::quishing` に
  (a) `blob:`/`data:`/`javascript:` スキームの Suspicious 格上げ、
  (b) `assess_multi_qr()` による分割QR兆候検出 (`MultiQrRisk`) を追加。

### 1.2 CalPhishing — カレンダー自動登録の永続化悪用

- `METHOD:REQUEST` の .ics は Outlook 等で受信時に自動 tentative 登録され、
  **元メールをスパム判定・削除してもカレンダーエントリだけが残る**。
  この永続化を悪用した CalPhishing キャンペーンが2026年初から活発化。
  カレンダー招待型フィッシングは直近6か月で49%増。
- 出典: SC Media (CalPhishing)、KnowBe4 "The Silent Invitation"、
  Cofense、Security Today (トークン窃取型 2026-05)。
- **Kaname への反映 (今回実装)**: `kaname-render::calendar_guard` に
  `CalendarRisk::AutoRegistrationAbuse` を追加。METHOD:REQUEST/PUBLISH と
  他のフィッシング兆候の併存で検出し、「メール削除では消えない」旨を
  ユーザーへ警告する文言を含める。

### 1.3 BEC の検出手法研究

- arxiv 2511.20944 (深層学習 vs 心理言語学の比較): LLM生成BECは
  「数学的に一意だが意味的に同一」のプリテキストを量産し、ハッシュ・
  シグネチャベースの検出を無効化する。
- deepfake は BEC の40%に関与 (2023年は5%未満)。AI 増強型BECの
  1件あたり被害額は $4.1M (従来型フィッシング $1.3M)。
- Mandiant M-Trends 2026: フィッシングは初期侵入の6%まで低下し、攻撃は
  アイデンティティ・ヘルプデスク・音声チャネルへ移動。
- **Kaname の現状評価**: PCR (メタデータのみのポリモーフィックキャンペーン
  検出) と kaname-pivot (メール外チャネル誘導検出) の設計方向が研究動向と
  一致している (= 長所として確認)。追加実装は不要と判断。

### 1.4 文体なりすまし (SSA関連)

- arxiv 2603.29454: LLMプロンプトによる著者なりすましは、**敵対的LLM生成
  サンプルを訓練データに含めた検証器を回避できない**。逆に含めなければ
  検出精度が落ちる。人間の識別精度は15%程度。
- **Kaname への反映 (記録のみ)**: kaname-ssa は7次元の文体特徴+送信時刻
  分布で本人プロファイルからの距離を測る設計だが、閾値がハードコードで
  敵対的サンプルによる校正がない。→ gap-analysis に D9 として追加。
  実装にはローカルLLM推論 (D2、モック段階) が前提となるため今回は見送り。

### 1.5 MLS の PQ 暗号スイート標準化

- draft-ietf-mls-pq-ciphersuites-05: ML-KEM/ハイブリッドの MLS ciphersuite
  が IETF で標準化進行中。openmls は 0.7.2 (2026-02) が最新。
- eprint 2026/1374 "Analysing the Post-Quantum Security of S/MIME":
  マルチ受信者 CMS では「全ての有効な経路が PQ 方針を満たす」必要がある
  (1つでも古典経路が残ると CEK が古典攻撃で回収可能)。
- **Kaname への反映 (記録)**: D1 (openmls統合) 実施時には最初から PQ
  ciphersuite を選定すべき。また kaname-crypto の "X-Wing" 表記は
  標準 X-Wing (draft-connolly-cfrg-xwing-kem) とは異なる独自 HKDF 合成
  であるため、名称の混同に注意 (maturity.md に注記追加)。

### 1.6 エージェントのメモリ攻撃 (最新防御研究)

- MAGE (arxiv 2605.03228, shadow memory)、AgentSentry (arxiv 2602.22724,
  時間因果診断+コンテキスト浄化)、Provably Secure Agent Guardrail
  (arxiv 2605.29251) 等が2026年上半期の主要提案。
- **Kaname の現状評価**: kaname-memory-guard は provenance ベース信頼
  スコア+時間減衰+注入パターン検出を実装済み (arxiv 2601.05504 ベース)
  で概ね最新水準 (= 長所)。shadow memory 型の二重台帳は費用対効果が
  低いため見送り。

### 1.7 Dual-LLM パターンの位置づけ

- "Design Patterns for Securing LLM Agents against Prompt Injections"
  (arxiv 2506.08837, IBM/ETH/Google/Microsoft 共著) が引き続き参照標準。
  Dual-LLM は2026-27年にデフォルトのアーキテクチャ選択になるとの業界予測。
- 新しめの理論研究: LLMbda Calculus (arxiv 2602.20064, 情報フロー型付け)、
  プロンプト注入の分類学 (arxiv 2602.10453)。
- **Kaname の現状評価**: `Content<Untrusted>`/`Bridge` の型レベル境界は
  この設計パターンの Rust 型システムによる実装であり、業界の方向性と
  一致 (= 中核的な長所)。ただし LLM 推論本体がモック (D2) である限り
  「境界は本物、中身は空」という状態。

---

## 2. 長所・短所・改善点の総括

### 長所 (研究動向と照らして裏付けられたもの)

1. **Dual-LLM 型境界の型システム実装** — 業界がこれから向かう先を
   型レベルで先取り (§1.7)。
2. **メタデータのみの PCR / 数値ベクトルのみの SSA** — LLM生成攻撃が
   シグネチャ検出を無効化する時代に有効な設計 (§1.3)。
3. **kaname-pivot のチャネル誘導検出** — 攻撃がメール外へ移動する
   トレンド (M-Trends 2026) に既に対応した設計 (§1.3)。
4. **memory-guard が最新論文水準** (§1.6)。
5. **BEC/DLP/render 系の検出器群が実テスト付きで動作する** (maturity.md
   の「本番出荷可」表参照)。

### 短所 (依然として残る弱点)

1. **コア暗号 (MLS) と LLM 推論がモック** — D1/D2。境界設計が良くても
   中身が動かないため、製品の中核価値が未達 (maturity.md 参照)。
2. **CI が一度も走っていない** — D7。GitHub App 権限で push 拒否を実証済み。
   人間の管理者操作が必須。
3. **E2E テストの実行実績なし** — D8。ネットワーク制限で検証未了。
4. **SSA が敵対的サンプル未校正** — D9 (新規、§1.4)。
5. **"X-Wing" の名称が標準と乖離** — 監査時の混乱リスク (§1.5)。

### 改善点 (優先順)

| 優先 | 改善 | 状態 |
|---|---|---|
| 済 | Quishing: blob/data/javascript スキーム + 分割QR検出 | **今回実装** |
| 済 | CalPhishing: 自動登録永続化の検出と警告 | **今回実装** |
| 高 | D1: openmls 統合 (PQ ciphersuite 前提で) | ネットワーク解放待ち |
| 高 | D2: ローカルLLM実推論 | 同上 |
| 高 | D7: CI 有効化 | 管理者操作待ち |
| 中 | D8: E2E 実行検証 | ネットワーク解放待ち |
| 中 | D9: SSA 敵対的校正 | D2 が前提 |
| 低 | shadow memory 型メモリ防御 | 費用対効果低で見送り |

---

## 3. 出典一覧

- arxiv 2506.08837 — Design Patterns for Securing LLM Agents against Prompt Injections
- arxiv 2511.20944 — Semantic Superiority vs. Forensic Efficiency (BEC検出比較)
- arxiv 2603.29454 — Authorship Impersonation via LLM Prompting does not Evade AV Methods
- arxiv 2605.03228 (MAGE) / 2602.22724 (AgentSentry) / 2605.29251 (Provably Secure Guardrail)
- arxiv 2602.20064 (LLMbda Calculus) / 2602.10453 (プロンプト注入分類学)
- eprint 2026/1374 — Analysing the Post-Quantum Security of S/MIME
- draft-ietf-mls-pq-ciphersuites-05 — ML-KEM and Hybrid Cipher Suites for MLS
- ReversingLabs / Acronis / Barracuda — QR フィッシング進化レポート
- SC Media / KnowBe4 / Cofense — CalPhishing・カレンダーフィッシング解説
- Mandiant M-Trends 2026 / deepstrike.io BEC統計 2026
- openmls 0.7.2 (crates.io, 2026-02-04)
