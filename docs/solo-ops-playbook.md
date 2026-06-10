# docs/solo-ops-playbook.md

# Kaname Solo Operation Playbook

Version 1.0 · 2026-04-24 · Owner: Founder

**前提**: 創業者 1 人。Apple 品質。エンタープライズ対象。日本発、グローバル。
**目標**: 10 億円 ARR まで組織を拡大せずに運営できる最大限の自動化。

---

## 0. 鉄則 4 条

1. **コードを書かないことに時間を使うな** — 自動化できる全ての運用は自動化する
2. **24 時間対応の幻想を捨てる** — SLA は誠実に設計し、嘘をつかない
3. **最初の 10 社は創業者が直接売る** — CRM もエージェントも要らない
4. **1 人のうちに全部やろうとしない** — 「今月の 1 つの仕事」に集中する

---

## 1. 法人・財務スタック (Week 1 に完了)

### 法人格

| 選択 | 理由 |
|---|---|
| **合同会社 (LLC) → 株式会社 (KK)** に段階移行 | LLC は設立費 6 万円・迅速・社会保険回避可; エンタープライズ営業で「株式会社」が必要になったら転換 |
| **設立初年度は LLC のまま** | 官公庁向け営業が始まる M8 以降に KK 転換検討 |
| **外国法人設立は後回し** | 海外顧客が 20% を超えた時点で Delaware C-Corp か Singapore Pte. Ltd. |

### 銀行・決済

```
日本円   : GMO あおぞらネット銀行 (API 連携、freee 自動仕訳)
USD      : Wise Business (受取口座、手数料最安)
EUR/GBP  : Wise Business (同上)
クレカ   : 三井住友ビジネスカード (年会費無料、明細 API 対応)
Stripe   : Kaname 課金の全商取引
```

### 会計

```
freee 会計スタンダード (月 ¥3,316)
  - Stripe ↔ freee 自動連携 (リアルタイム)
  - GMO あおぞら ↔ freee 自動連携
  - 経費精算: Staple または freee 経費
  - 消費税: Qualified Invoice (適格請求書) 発行は freee で自動生成
  - 確定申告: freee で完結 (税理士は ARR ¥3,000 万超えたら検討)
```

### 請求書・入金

```
¥500–¥120,000/月 の SMB : Stripe 自動請求、Customer Portal
¥120,000– の Enterprise  : freee 請求書 + Stripe Invoicing (NET30)
官公庁                    : freee 請求書 PDF + 振込入金 + 手動消込
```

---

## 2. 技術運用スタック (Month 1 に完了)

### CI/CD

```yaml
# .github/workflows/ci.yml の最小必要項目
jobs:
  test:
    - cargo test --workspace --all-features
    - cargo clippy -- -D warnings
    - cargo fmt --check
    - cargo audit            # 脆弱性スキャン (cargo-audit)
    - cargo deny check       # ライセンス + supply chain
    
  security_scan:
    - cargo fuzz run kaname_mime_parse -- -max_total_time=60   # nightly のみ
    - trivy fs . --exit-code 1                                  # container scan
    
  release:
    - 本番用: release.yml (既実装の Apple notarize + dual-sign)
```

### インフラ (最小構成 — ¥15,000/月 以下)

```
Kaname KPD / MLS DS サーバー:
  Cloudflare Workers (¥0–¥1,500)   - KPD API (key package fetch/publish)
  Cloudflare KV                     - Key package storage
  Cloudflare R2                     - Attachment blob (サンドボックス結果 PNG)
  Cloudflare D1                     - テナント / 課金状態の薄いレプリカ

Heavy compute (Firecracker):
  Hetzner Cloud CCX13 (8vCPU/32GB) ¥9,000/月 × 1 台
  → sandbox pool = 6 warm VMs; 添付スキャン専用
  → 自動スケール: KEDA + K3s で月 100 社以上になったら追加

監視:
  BetterUptime (無料枠) + Cloudflare Analytics
  Sentry (エラートラッキング、無料 5k events/月)
  PagerDuty 代替: ntfy.sh self-hosted + Telegram bot (¥0)
```

### オンコール (1 人でも回る設計)

```
P0 (全サービス停止):   Telegram に即通知 → 15 分以内に確認
P1 (一機能停止):       Telegram 通知 → 2 時間以内
P2 (パフォーマンス低下): 朝のダッシュボード確認で対応
P3 (軽微):             週次 Monday Review で対応

重要: エンタープライズ SLA は "Business Hours 09:00-18:00 JST" を誠実に定義する
     "24/7" を 1 人で約束しない。誠実な SLA の方が顧客の信頼を得る。
```

### バックアップ

```bash
# cron: 毎日 03:00 JST
rclone sync cloudflare-r2:kaname-prod s3-glacier:kaname-backup-$(date +%Y%m%d)
pg_dump $DATABASE_URL | gzip | aws s3 cp - s3://kaname-backup/db/$(date +%Y%m%d).sql.gz
# 7 年保持 (日本法人税法 + GDPR 要件)
```

---

## 3. カスタマーサポートスタック

### 規模別ツール選択

| フェーズ | ツール | 月額 |
|---|---|---|
| ¥0–¥1,000 万 ARR | **Plain** (シンプル、Slack 統合、AI 返信草案) | ¥0–¥15,000 |
| ¥1,000–¥5,000 万 ARR | Plain → Linear Issues 連携 (バグ管理) | ¥15,000–¥30,000 |
| ¥5,000 万+ ARR | Intercom (AI サポート、シーケンス自動化) | ¥50,000+ |

### AI サポート自動化 (2026 年現在)

```
1. Docs サイト: Mintlify (¥0–¥9,000、AI 検索付き)
2. 一次回答: Claude API + Mintlify docs でインコンテキスト自動返信
   - "Kaname の暗号方式は？" → 即答
   - 不明 → "担当者から 2 営業日以内" と通知
3. バグレポート自動化: Sentry → Linear の自動連携
4. オンボーディング: メール自動シーケンス (Loops.so、¥0–¥5,000)
```

### エンタープライズサポートの境界線

```
Starter / Business: メール返信 2 営業日以内 (AI 草案 → 人間確認)
Pro:                メール返信 8 時間以内 (Business Hours)
Enterprise:         専任 CSM (自分) + 月次 30 分 1:1
                    → 5 社以上になったら fractional CSM を契約 (¥50,000/月 × 人)
```

---

## 4. 営業・マーケティング (1 人体制)

### ファネル設計

```
認知: OSS + セキュリティブログ + 登壇 (CODE BLUE / SECCON)
     └→ GitHub Star → 試用 → Starter 課金 (PLG)

中堅企業: LinkedIn / Findy Teams でインバウンド
         └→ 14 日 Pro トライアル → Business 転換

エンタープライズ: 創業者直接営業 (最初の 10 社)
                 └→ Design Partner Program → GA 時に正式契約
```

### CRM (¥0 スタック)

```
顧客数 < 50 社:  Notion データベース (カスタムプロパティ: 企業名/担当/ARR/Next Action)
顧客数 50–200:   HubSpot 無料版 + Notion 補完
顧客数 200+:     HubSpot Starter ¥5,000/月

重要: CRM に時間を使い過ぎない。商談メモはその日中に書く。それだけでいい。
```

### 日本エンタープライズ営業の 3 つの真実

1. **稟議書は自分で書く** — 担当者が稟議を書けるよう「稟議書テンプレ」を事前提供する
2. **根回し (nemawashi) を助ける** — 「情シス向け」「CISO 向け」「経営層向け」の 3 種類の資料を用意
3. **最初の 6 ヶ月は無料 POC** — 「購入」の前に「使ってもらう」こと。大手企業は試してから買う

### コンテンツ戦略 (週 1 本が上限)

```
優先度高:
  - セキュリティブログ (BEC 事例、PQC 解説、Dual-LLM アーキテクチャ)
  - CVE アドバイザリ (外部からの指摘を迅速に公開 → 信頼構築)
  - GitHub README + Discussions

優先度中:
  - Zenn / Qiita (日本語技術記事)
  - CODE BLUE / SECCON 登壇提案

優先度低 (後回し):
  - Twitter/X (ADV より時間効率が悪い)
  - 展示会出展 (費用対効果が低い段階では不要)
```

---

## 5. 法務・コンプライアンス (1 人体制)

### 最低限の契約書セット

```
今すぐ用意 (テンプレート購入 or AI 生成 + 弁護士レビュー ¥30,000–¥50,000):
  1. 利用規約 (ToS) + プライバシーポリシー
  2. データ処理契約書 (DPA) — GDPR/APPI 対応
  3. NDA テンプレート (Design Partner 用)
  4. SaaS 契約書 (エンタープライズ用)

Design Partner 前に追加:
  5. Design Partner 評価契約 (既に draft 済: dp-program.md)

官公庁営業前に追加:
  6. 情報セキュリティ基本方針 (ISMAP 申請で必須)
  7. 再委託契約書テンプレート
```

### APPI / GDPR 対応 (1 人でできる最小)

```
即実施:
  - プライバシーポリシーに APPI/GDPR 準拠文言
  - Stripe の DPA に署名 (Dashboard → Settings → Legal)
  - データ処理台帳 (Notion で管理)
  - Cookie 同意 (landing page に Cookieyes.com ¥0 枠)

DPO は不要 (従業員なし、個人データ処理は Stripe/Cloudflare に委託)
```

### SOC 2 の現実的計画

```
Month 0–6:  Vanta ($3,600/年) でエビデンス自動収集を始める
            → Cloudflare/AWS/Stripe のクラウドコントロール自動チェック
            → GitHub access review 自動化
            → 結果: 審査前に "80% ready" 状態を維持

Month 6–12: A-LIGN か Prescient Assurance で Type II 審査
            費用: ¥3,000,000–¥8,000,000
            → エンタープライズ営業のブロッカーが消える

1 人でやること: Vanta のダッシュボードを週 30 分見る。それだけ。
1 人でやらないこと: 証拠収集の手動作業 (Vanta に自動化させる)
```

### 輸出管理 (Export Control)

```
今すぐ実施:
  1. ECCN 自己分類: 暗号ソフトウェア → ECCN 5D002.c.1 (大量市場扱い可能性大)
     → SNAP-R 年次自己分類報告 (2/1 〆切)
  2. 日本 FEFTA 分類: 通産省令別表 → 外為法に基づく大量破壊兵器関連リスト確認
  3. OFAC スクリーニング: 顧客登録時に ComplyAdvantage 無料枠で自動スクリーニング

確認不要 (PQC は NIST 標準準拠なので "標準暗号" として large-market 免除対象):
  ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204) → 独自実装でないため EAR 免除対象
```

---

## 6. メンタルモデルと週次リズム

### OMTM (One Metric That Matters) — フェーズ別

| フェーズ | OMTM | なぜ |
|---|---|---|
| 〜MRR ¥100 万 | **週次 Active User 数** | 誰が本当に使っているかを知る |
| ¥100 万–¥500 万 MRR | **NPS (月次)** | 口コミが唯一のグロースエンジン |
| ¥500 万–¥3,000 万 MRR | **NDR (Net Dollar Retention)** | 既存顧客拡大が新規獲得より効率的 |
| ¥3,000 万+ MRR | **CAC Payback Period** | スケールのためのユニットエコノミクス |

### 週次リズム (1 人用)

```
月曜 09:00–11:00  Monday Design Review (ADR / 仕様 / コード品質)
月曜 11:00–12:00  顧客メール / サポート返信
火曜–木曜         コーディング集中 (通知オフ)
金曜 09:00–10:00  週次指標確認 (OMTM / MRR / 未解決サポート)
金曜 10:00–11:00  翌週の優先度 1 つを決める
金曜 11:00–       ブログ / ドキュメント / OSS contributions
土日              コーディング可だが意思決定しない
```

### 「1 人の限界」が来るサイン — この時だけ採用する

```
サイン 1: 顧客対応に週 20 時間以上使っている → CSM/サポート 1 人採用
サイン 2: セキュリティ審査 (SOC 2 / ISMAP) で月 40 時間使っている → セキュリティエンジニア 1 人
サイン 3: 企業営業のパイプラインが 20 社を超えた → AE (Account Executive) 1 人
サイン 4: サーバー障害対応に月 10 時間以上使っている → SRE 1 人

採用順: CSM → SRE → AE → Security Engineer (この順でビジネスインパクト大)
```

---

## 7. AI ツールによる業務代替 (2026 年版)

### 開発

```
Claude Code (claude-code CLI):   コーディング、リファクタリング、PR レビュー草案
GitHub Copilot:                  インラインコード補完 (Claude Code の補完として)
cargo-machete:                   不要依存の自動検出
cargo-expand:                    マクロデバッグ
bacon:                           バックグラウンドコンパイルウォッチャー
```

### コンプライアンス / セキュリティ

```
Vanta AI Questionnaire:         セキュリティ質問票 (CAIQ/SIG) の自動回答
  → 顧客から届く 200 問の質問票を 30 分で処理
Drata Evidence Automation:      SOC 2 エビデンス収集自動化 (Vanta 代替)
Wiz (クラウド CSPM):             クラウド設定ミスの自動検出
```

### セールス / マーケティング

```
Clay + Apollo:                   見込み顧客リスト作成 + パーソナライズメール
Notion AI:                       提案書・稟議書テンプレートのドラフト
Perplexity / Claude:             競合リサーチ、業界動向把握
Otter.ai / Notta:                顧客商談の自動文字起こし + サマリ
```

### カスタマーサポート

```
Plain + Claude API:              一次返信の自動草案生成
Mintlify + AI 検索:              セルフサービスドキュメント
Loom:                            非同期デモ動画 (テキストより速く解説できる)
```

### 財務

```
freee AI:                        仕訳自動化、経費承認
Stripe Sigma:                    ARR / MRR / NDR の自動計算クエリ
Mercury (将来の USD 口座):        USD キャッシュフロー管理
```

---

## 8. ソロ創業者が絶対にやらないこと

```
✗ 全顧客に 24/7 サポートを約束する
✗ 機能追加の全要望に「検討します」と言う
✗ 競合分析に週 5 時間以上使う
✗ プレスリリースを外部 PR 会社に任せる (最初の 2 年)
✗ オフィスを借りる (フルリモートで十分)
✗ 株主ではない VC/エンジェルの意見で製品方向を変える
✗ SOC 2 の前に FedRAMP を目指す (順序が命)
✗ 10 社以上の Design Partner を抱える
✗ 本番データベースに直接アクセスするシェルスクリプトを書く
```

---

## 9. 政府案件 — 1 人で対応できる最大範囲

```
できること (1 人で):
  - ISMAP-LIU 申請 (IPA/デジタル庁 + 監査法人との連携)
  - 自治体・準政府機関への営業 (Proof of Concept レベル)
  - G-Cloud 14/15 登録 (英国)
  - AusTender / Digital Marketplace 登録 (豪州)

できないこと (パートナーが必要):
  - ISMAP full 本審査 (監査法人対応で月 40h+ 必要 → 契約社員必要)
  - FedRAMP 申請 (3PAO 選定・ConMon が専任必要)
  - 官公庁の大型入札 (代理店 — 東京エレクトロン、NTT データなど — が必要)

パートナー候補 (官公庁代理店):
  - NTT データ (クラウドサービス代理店)
  - 伊藤忠テクノソリューションズ (CTC)
  - 富士通ジャパン
  → 最初の 1 社を Design Partner として 50% OFF で獲得し、ケーススタディを作る
```

---

## 10. Week 1 アクションチェックリスト

- [ ] 合同会社設立 (電子定款 → freee 会社設立: ¥60,000)
- [ ] GMO あおぞらネット銀行 開設
- [ ] Wise Business アカウント (USD / EUR 受取)
- [ ] freee 会計スタンダード 契約 + Stripe 連携設定
- [ ] GitHub Actions CI (cargo test + clippy + audit + deny)
- [ ] Sentry 無料枠セットアップ
- [ ] BetterUptime 無料枠 (uptime 監視)
- [ ] ntfy.sh + Telegram bot (PagerDuty 代替)
- [ ] Mintlify ドキュメントサイト (無料枠)
- [ ] Plain サポートツール セットアップ
- [ ] 利用規約 + プライバシーポリシー (AI 生成 + 弁護士レビュー)
- [ ] ECCN 自己分類ドキュメント作成
- [ ] OFAC スクリーニング設定 (ComplyAdvantage 無料枠)
- [ ] Vanta 契約 ($3,600/年 — SOC 2 への投資として最優先)
- [ ] Notion CRM テンプレート作成 (顧客管理)

**Month 1 の唯一の仕事**: 最初の 3 社の Design Partner の確約を取る。それだけ。

---

## Appendix: コスト試算 (¥0 ARR 時点)

| カテゴリ | 月額 (概算) |
|---|---|
| インフラ (Hetzner + Cloudflare) | ¥12,000 |
| freee 会計 | ¥3,400 |
| Vanta (SOC2) | ¥30,000 |
| Plain (サポート) | ¥0 |
| Sentry (エラー監視) | ¥0 |
| BetterUptime (監視) | ¥0 |
| Mintlify (ドキュメント) | ¥0 |
| GitHub Team | ¥4,000 |
| Stripe 手数料 (3.6%) | ARR の 3.6% |
| **固定費合計** | **¥49,400/月** |

月額 5 万円以下で商用グレードの運用インフラが整う。初月 MRR ¥150,000 で収支均衡。
