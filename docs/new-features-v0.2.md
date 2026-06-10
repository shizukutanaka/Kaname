# Kaname v0.2 新機能設計書

> 2026 年最新脅威ランドスケープに対応する 5 つの新機能  
> 採用基準: 北極星 (AIが助けても裏切らない) に整合 / 既存機能と重複しない / 競合不在 / 実装 6 ヶ月以内

最終更新: 2026-04-29 | 作成者: @kaname-app/lead + @kaname-app/security-lead

---

## 0. 2026 年 脅威ランドスケープの再評価

Web リサーチで判明した直近の脅威動向:

| 脅威 | 2026 年の状況 | 既存 Kaname 対応 |
|---|---|---|
| AI 生成フィッシング | **2025 末から 14 倍急増**、半数を占める | ✅ AiPhishingDetector (94%) |
| Business Email Compromise (BEC) | 2024 年だけで $27.7 億の損失 | ✅ kaname-bec 7 信号 |
| Vendor Email Compromise (VEC) | **新興**、本物の取引先を乗っ取る | ⚠️ 部分対応 |
| Deepfake 音声/動画 | $25.6M 香港事件で実証、1,633% 急増 | ❌ **未対応** |
| QR コードフィッシング (Quishing) | 画像で URL 解析を回避、急増中 | ⚠️ kaname-bec で部分検出 |
| マルチチャネル攻撃 | メール → Teams/Slack/電話 への横展開 | ❌ **未対応** |
| AitM (Adversary in the Middle) | リアルタイムプロキシで MFA バイパス | ❌ **未対応** |
| SaaS 経由フィッシング | Google Drive/DocuSign を悪用 | ❌ **未対応** |

**判明した 4 つの新攻撃面 + 1 つの既存強化 = 5 つの新機能を設計**。

---

## 機能 #1: Out-of-Band Verification (OOBV) - 別経路検証セレモニー

### 解決する脅威
- Deepfake 音声/動画 ($25.6M 事件と同型攻撃)
- VEC (取引先アカウント乗っ取り)
- 高額送金詐欺の最終段階

### 着想

Apple の Safety Number 検証セレモニーと、Signal の Safety Number を統合した「金融取引向け」検証フロー。

**核心**: メール本文だけでなく、**別経路で双方向に検証**する儀式を UI に組み込む。

### UX 設計

```
受信メール: 「振込先口座を変更します」(田中さんから)
                ↓
        Kaname が金融キーワードを検出
                ↓
   [💎 Safety Verification 必要]  バナー表示
                ↓
   ボタン: 「田中さんに別経路で確認する」
                ↓
   ┌──────────────────────────┐
   │ 6 ワード フレーズが生成    │
   │                         │
   │  blue · meadow · cipher │
   │  storm · velvet · sage  │
   │                         │
   │  田中さんに電話して、    │
   │  この 6 ワードのうち     │
   │  「3 番目」を読み上げて  │
   │  もらってください        │
   └──────────────────────────┘
                ↓
   一致したら ✅ Verified
   不一致なら ❌ Blocked (送金不可)
```

### 技術設計

```rust
// crates/kaname-oobv/src/lib.rs
pub struct VerificationCeremony {
    /// 6 ワードフレーズ (BIP39 から派生)
    phrase: [Word; 6],
    /// 検証対象のメール ID
    target_email: String,
    /// 検証する「ワード番号」(攻撃者が 6 ワード全部を抜けないように)
    challenge_index: u8,
    /// 期限 (5 分以内に検証完了)
    expires_at: Instant,
}

impl VerificationCeremony {
    pub fn generate(target: &str) -> Self {
        let phrase = generate_bip39_phrase(6);
        let challenge_index = secure_random_u8(0..6);
        // ...
    }
    
    pub fn verify(&self, response_word: &str) -> Verdict {
        match self.phrase[self.challenge_index as usize].as_str() == response_word {
            true  => Verdict::Verified,
            false => Verdict::Mismatch, // → ハッシュチェーンに記録 (攻撃の証拠)
        }
    }
}
```

### 監査ログ

検証イベント (成功/失敗/タイムアウト) を `kaname-store` の改ざん防止ログに記録。法務監査・規制対応で証拠として使える。

### Apple HIG 適用

- **モーダル + 触覚フィードバック** (検証成功時に Notification Sound)
- **Reduce Motion 対応** (アニメーション無効化)
- **Dynamic Type 完全対応** (シニア向け)

---

## 機能 #2: Cross-Channel Pivot Detection (CCPD) - 横展開攻撃の検出

### 解決する脅威
- マルチチャネル攻撃 (メール → Teams/Slack/電話)
- 「メールで合意 → 別経路で実行」パターン

### 着想

Apple の Continuity フレームワーク + Microsoft の脅威インテリジェンスの「pivot detection」を統合。

**核心**: メールに「他チャネルへの誘導」が含まれていたら、UI が**意図的に摩擦**を入れる。

### UX 設計

メール本文に以下のパターンを検出:
- 「Teams で会議しましょう」(リンク付き)
- 「至急電話ください: 080-XXXX-XXXX」(本文に電話番号)
- 「Slack で続きを」(共有リンク)

```
        ⚠️ Cross-Channel Pivot Detected
   ┌────────────────────────────────────┐
   │ このメールは別チャネルへ           │
   │ 移動するよう促しています:           │
   │                                  │
   │ • Microsoft Teams 会議 (リンク)  │
   │ • 電話番号 080-1234-5678         │
   │                                  │
   │ 2026 年の攻撃の 67% は           │
   │ チャネル切り替えで発生しています  │
   │                                  │
   │ 信頼スコア: 7/10                  │
   │                                  │
   │ [ 続行 ]  [ Safety Verify ]      │
   └────────────────────────────────────┘
```

### 技術設計

```rust
// crates/kaname-pivot/src/lib.rs
pub struct PivotDetector {
    /// 既知の正当なチャネル (許可リスト)
    trusted_channels: HashSet<ChannelDescriptor>,
}

#[derive(Debug, Clone)]
pub enum DetectedPivot {
    PhoneNumber { number: String, urgency_score: f32 },
    TeamsLink { url: Url, organizer: Option<String> },
    SlackInvite { workspace: String, channel: Option<String> },
    ZoomMeeting { meeting_id: String, password: Option<String> },
    SaasDocument { platform: SaasPlatform, url: Url },
}

impl PivotDetector {
    pub fn analyze(&self, content: &Content<Untrusted>) -> Vec<DetectedPivot> {
        let mut pivots = Vec::new();
        // 1. 電話番号パターン (国際フォーマット, 日本語, 英語)
        pivots.extend(extract_phone_numbers(content.as_text()));
        // 2. Teams/Slack/Zoom リンク
        pivots.extend(extract_meeting_links(content.as_text()));
        // 3. SaaS ドキュメントリンク (DocuSign, Google Drive, etc)
        pivots.extend(extract_saas_links(content.as_text()));
        pivots
    }
    
    pub fn trust_score(&self, pivots: &[DetectedPivot], sender: &str) -> f32 {
        // 過去 30 日のやりとりに同じチャネルが出現しているか
        // 出現していれば信頼スコア + 0.3
        // ...
    }
}
```

### 既知パターンへの適応

機械学習 (オンライン学習) で「正常な pivot」を学習。**例**: 「毎週金曜の経理ミーティング for Teams」は信頼スコア高、初めて出現した Teams 招待は信頼スコア低。

---

## 機能 #3: QR Code Quishing 防御

### 解決する脅威
- QR コードフィッシング (Quishing)、急増中
- メール内画像で URL を隠蔽し、テキストベースの解析を回避

### 着想

メール本文内の全画像を **OCR + QR デコード**で解析し、隠された URL を発見する。

### 技術設計

```rust
// crates/kaname-render/src/quishing.rs
use image::DynamicImage;

pub struct QuishingDefense;

impl QuishingDefense {
    pub fn scan_email(&self, attachments: &[Attachment]) -> Vec<DetectedQrCode> {
        let mut found = Vec::new();
        for att in attachments {
            if !is_image(&att.mime_type) { continue; }
            let img = decode_image(&att.data);
            // 1. QR コードデコード (rqrr crate)
            if let Some(decoded) = decode_qr(&img) {
                found.push(DetectedQrCode {
                    image_id: att.id.clone(),
                    decoded_text: decoded.clone(),
                    is_url: decoded.starts_with("http"),
                    url_reputation: check_url_reputation(&decoded),
                });
            }
            // 2. OCR でテキスト URL (実装フェーズで tesseract か Vision API)
        }
        found
    }
}
```

### UX 設計

QR コードを発見した場合、メール下部にバナー表示:

```
┌──────────────────────────────────────┐
│ 🔍 このメール内の画像に QR コードが │
│    含まれています                    │
│                                    │
│ デコード結果: https://amaz0n-secure.tk │
│                                    │
│ ⚠️ 怪しい URL の特徴:               │
│ • Amazon に似たドメイン (amaz0n)    │
│ • .tk は無料 TLD で悪用が多い        │
│                                    │
│ [ 詳細 ]  [ ブロック ]               │
└──────────────────────────────────────┘
```

### コーパス

`fuzz/corpus/quishing/` に既知の Quishing 攻撃画像を保管。ファジングで未知の QR エンコーディングに対する堅牢性検証。

---

## 機能 #4: SaaS Link Safety - SaaS 経由配信フィッシング対策

### 解決する脅威
- Google Drive / DocuSign / OneDrive / SharePoint 経由のフィッシング
- 「信頼されたプラットフォーム」を悪用してメールフィルタ回避

### 着想

メール本文の SaaS リンクを「Tauri sidecar process」で**プレロード**して、最終的なランディングページを検査する。

### 技術設計

```rust
// crates/kaname-saas-guard/src/lib.rs
pub struct SaasLinkInspector {
    /// 既知の SaaS プラットフォーム + リスクスコア
    platforms: HashMap<Domain, SaasPlatformRisk>,
}

pub enum SaasPlatformRisk {
    Safe,           // 例: 自社内部のみで使う Notion
    Common,         // 例: Google Drive (組織内なら普通)
    Suspicious,     // 例: 初めて見る DocuSign リクエスト
    HighRisk,       // 例: PDF 内に外部リンクを多用
}

impl SaasLinkInspector {
    pub async fn inspect(&self, url: &Url) -> Result<SaasReport, Error> {
        // Firecracker microVM で URL をプレロード
        // 1. 最終リダイレクト先を取得
        // 2. ページ内の <script> や form action を検査
        // 3. 認証情報入力欄があれば WARN
        // 4. .exe / .docm 等のダウンロードリンクがあれば BLOCK
        
        let sandbox = self.spawn_inspector_vm().await?;
        let result = sandbox.fetch_and_analyze(url).await?;
        Ok(result)
    }
}
```

### UX 設計

SaaS リンクを開く前に**プレビュー**を表示:

```
ユーザーがクリック
    ↓
[ DocuSign Preview ]
┌──────────────────────────────────────┐
│ 📄 DocuSign 経由のリンク             │
│                                    │
│ 送信者: hr@company.co.jp           │
│ ドキュメント名: "新規契約書"        │
│ 最終リダイレクト: docusign.net (正常)│
│                                    │
│ ⚠️ 検出された要素:                  │
│ • 認証情報入力欄あり (パスワード)    │
│ • 外部ドメインへのフォーム送信       │
│                                    │
│ 信頼スコア: 4/10                    │
│                                    │
│ [ サンドボックスで開く ]  [ ブロック ]│
└──────────────────────────────────────┘
```

「サンドボックスで開く」を選んでも、Firecracker microVM 内で隔離表示。

---

## 機能 #5: Deepfake Audio/Video Warning Banner

### 解決する脅威
- メール添付の音声/動画ファイル (Deepfake の可能性)
- 「電話で確認」と書いた後に Deepfake 音声で実際に電話する攻撃

### 着想

メールに音声 (.mp3, .wav) や動画 (.mp4) の添付があった場合、**プロアクティブな警告**を表示。

### UX 設計

```
受信メール: "私の声をメッセージに残しました。聞いてください"
            (audio.mp3 添付)
                ↓
┌──────────────────────────────────────┐
│ 🎙️ 音声添付が含まれています          │
│                                    │
│ ⚠️ 2026 年 4月時点、AI 音声クローン │
│    技術により、わずか 3-10 秒の音声  │
│    から声を複製できます。            │
│                                    │
│ この音声が本人のものか?:            │
│ • [ 安全な別経路で本人確認する ]    │
│ • [ 検証スコアを表示する ]          │
│ • [ それでも再生する (隔離環境) ]   │
│                                    │
│ 重要な取引の指示が含まれている可能性 │
│ がある場合は別経路で確認を。         │
└──────────────────────────────────────┘
```

### 技術設計

```rust
// crates/kaname-render/src/deepfake_advisory.rs
pub struct DeepfakeAdvisory;

impl DeepfakeAdvisory {
    pub fn should_warn(&self, attachment: &Attachment, body: &str) -> Option<Warning> {
        let is_audio = is_audio_mime(&attachment.mime_type);
        let is_video = is_video_mime(&attachment.mime_type);
        
        if !is_audio && !is_video { return None; }
        
        // 本文にも金融キーワードがある場合、警告レベルを上げる
        let has_financial_context = FINANCIAL_KEYWORDS.iter()
            .any(|kw| body.contains(kw));
        
        Some(Warning {
            severity: if has_financial_context { Severity::High } else { Severity::Medium },
            message_key: "deepfake.audio_advisory",
            recommended_action: RecommendedAction::OutOfBandVerification,
        })
    }
}
```

### 補完: Deepfake 検出 (Phase 2)

将来的に、音声/動画ファイルから「AI 生成の痕跡」を検出するローカル ML モデル統合。ただし v0.2 では **「警告は出すが判定はしない」** 方針 (誤検出のリスクを避ける)。

---

## 採用しなかった候補 (Apple 流「No」)

| 候補 | 却下理由 |
|---|---|
| 受信箱全体の AI 解析モード | 北極星「単一メールのみ」と矛盾 |
| クラウドベース AI 判定の追加 | プライバシー原則と矛盾 |
| 取引先データベース統合 (Salesforce 等) | 外部依存、ベンダーロックイン |
| ブロックチェーン送信履歴 | オーバーエンジニアリング、UX 劣化 |
| メール内 AI チャットボット | 攻撃面拡大、北極星から逸脱 |
| 行動分析ベース異常検出 | ユーザーデータ収集が必要、Privacy 原則違反 |

---

## 実装ロードマップ

### Phase 1 (v0.2.0) - 2026 Q3 リリース
- ✅ #1 Out-of-Band Verification (新クレート: `kaname-oobv`)
- ✅ #2 Cross-Channel Pivot Detection (新クレート: `kaname-pivot`)
- ✅ #5 Deepfake Advisory Banner (kaname-render 拡張)

### Phase 2 (v0.3.0) - 2026 Q4 リリース  
- ✅ #3 QR Code Quishing (kaname-render に統合)
- ✅ #4 SaaS Link Safety (新クレート: `kaname-saas-guard`)

### Phase 3 (v1.0.0) - 2027 Q1 リリース
- 上記 5 機能の Design Partner 30 社による実証データ
- ローカル ML 統合 (Deepfake 検出)

---

## メトリクス目標

| 機能 | 検出精度目標 | レイテンシ目標 | 偽陽性率 |
|---|---|---|---|
| OOBV | N/A (儀式) | < 1s (フレーズ生成) | N/A |
| Pivot Detection | 92% | < 50ms | < 5% |
| Quishing | 96% (QR デコード) | < 100ms | < 1% |
| SaaS Link Safety | 88% | < 2s (sandbox 起動) | < 8% |
| Deepfake Banner | N/A (警告) | < 10ms | N/A |

---

## 改訂履歴

| 日付 | 改訂者 | 内容 |
|---|---|---|
| 2026-04-29 | @kaname-app/lead + @kaname-app/security-lead | 初版 - 2026 年最新脅威に対応する 5 機能設計 |
