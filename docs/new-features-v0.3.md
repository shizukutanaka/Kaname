# Kaname v0.3 新機能設計書

> 2026 Q1 Deep Research (Microsoft / Cofense / Barracuda / Group-IB) + Ultrathink  
> 採用基準: 北極星整合 / 競合不在 / ローカルファースト / 実装 6 ヶ月以内

最終更新: 2026-05-12 | 作成者: @kaname-app/security-lead

---

## 0. Deep Research: 2026 Q1 脅威ランドスケープ

### 最新データ (2026 年 1〜4 月)

<cite: Microsoft Q1 2026 Email Threat Report, 2週間前>

| 脅威 | Q1 2026 の状況 | 既存対応 |
|---|---|---|
| **AiTM (Adversary-in-the-Middle)** | Tycoon2FA: 3日で35,000人・13,000組織・26か国被害 | ❌ **未対応** |
| ポリモーフィック フィッシング | 204%急増。76%のURLが一意だが94%が同一IPを共有 | ❌ **未対応** |
| CAPTCHA ゲート フィッシング | 自動スキャンを欺く人間専用フィッシング | ❌ **未対応** |
| HTML スマグリング | JS を HTML 内に隠蔽、デコードはブラウザ内で実行 | ❌ **未対応** |
| 送信者スタイル偽装 | AI 生成で文法完璧だが「文体が違う」 | ❌ **未対応** |
| QR Quishing | ✅ (v0.2 対応済み) | ✅ |
| Deepfake | ✅ (v0.2 対応済み) | ✅ |

### 最重要発見: 94% 共有インフラ

Cofense のデータが示す決定的な洞察:

```
個々のメール:  URL 76% が一意, ハッシュ 82% が一意
                 → シグネチャ検出: 無効
                 
インフラ:       94% が同じ IP アドレスを共有
                 → インフラ fingerprinting: 有効
```

これは Kaname に革命的な機会を与える。AI がメール 1 通のみ処理するという
北極星を守りながら、**メタデータレベルのインフラ解析**は複数メールを横断できる。
AI はコンテンツを読まず、ドメイン・IP・構造のみを解析するから。

---

## 機能 #1: AiTM Link Detector

### 解決する脅威

<cite: Microsoft, AiTM 35,000+ victims April 2026>

AiTM (Adversary-in-the-Middle): 攻撃者がリバースプロキシとして
ユーザーと正規サービスの間に介入。MFA トークンとセッション Cookie を
リアルタイムで窃取。パスワードリセット後も持続する。

**現在 Kaname が防げないシナリオ:**
1. ユーザーが「Microsoft 365 ログイン確認」メールを受信
2. リンクをクリック → 見た目は本物の Microsoft ログインページ
3. 実際はリバースプロキシ (Evilginx2/Modlishka) が中継
4. ユーザーが MFA を完了 → トークンごと窃取
5. 攻撃者はユーザーのアカウントに無制限アクセス

### 技術設計

```rust
// crates/kaname-bec/src/aitm.rs

/// AiTM プロキシの特徴を検出する
pub struct AitmDetector {
    // リバースプロキシの既知パターン
    proxy_indicators: Vec<AitmIndicator>,
}

#[derive(Debug, Clone)]
pub enum AitmIndicator {
    /// evilginx2/Modlishka のドメインパターン
    ProxyDomain { pattern: Regex },
    /// セッション捕捉 URL パラメーター
    SessionTokenParam { key: &'static str },
    /// 多段リダイレクトチェーン (3+ ホップ)
    ExcessiveRedirects { threshold: u8 },
    /// auth/token を URL パラメーターに含む
    AuthInQueryString,
    /// HTTPS → HTTP へのダウングレード試行
    TlsDowngrade,
}

impl AitmDetector {
    pub fn analyze(&self, url: &Url) -> AitmRisk {
        let mut score = 0u32;
        let mut signals = Vec::new();

        // 1. URL パラメーター解析
        //    ?token=... ?session=... ?code=... は MFA リレーの証拠
        for (key, _) in url.query_pairs() {
            if matches!(key.as_ref(), "token" | "session" | "state" | "code" | "id_token") {
                score += 30;
                signals.push(format!("認証パラメーターを URL に含む: {key}"));
            }
        }

        // 2. ドメイン解析
        //    microsoft-auth-365.com → 「microsoft」を含むが正規でない
        if let Some(domain) = url.domain() {
            for legit in LEGITIMATE_AUTH_DOMAINS {
                if domain.contains(legit) && !is_legitimate_subdomain(domain, legit) {
                    score += 50;
                    signals.push(format!("{legit} を装った偽ドメイン: {domain}"));
                }
            }
        }

        // 3. パス解析
        //    /auth/relay /proxy/login などの典型的プロキシパス
        let path_lower = url.path().to_lowercase();
        for proxy_path in PROXY_PATH_PATTERNS {
            if path_lower.contains(proxy_path) {
                score += 20;
                signals.push(format!("プロキシ特有のパス: {proxy_path}"));
            }
        }

        // 4. 既知の PhaaS ドメインとの照合
        if self.matches_phaas_infrastructure(url) {
            score += 100; // 確実
            signals.push("既知 PhaaS (Tycoon2FA/Storm-1747) インフラと一致".to_string());
        }

        AitmRisk { score, signals, verdict: Self::score_to_verdict(score) }
    }
}

const LEGITIMATE_AUTH_DOMAINS: &[&str] = &[
    "microsoft.com", "live.com", "microsoftonline.com",
    "google.com", "accounts.google.com",
    "github.com",
];

const PROXY_PATH_PATTERNS: &[&str] = &[
    "/relay", "/proxy", "/auth-relay", "/token-relay",
    "/mfa-bypass",
];
```

### UX

```
┌─────────────────────────────────────────────┐
│ ⚠️ AiTM (中間者) 攻撃の可能性               │
│                                             │
│ このリンクはリバースプロキシ経由で           │
│ Microsoft 365 に見せかけています。           │
│                                             │
│ 検出シグナル:                               │
│ • URL に認証トークンパラメーター            │
│ • 「microsoft」を含む非正規ドメイン         │
│ • 既知の PhaaS インフラと一致               │
│                                             │
│ このリンクをクリックすると、MFA を完了       │
│ しても攻撃者にアクセスを奪われます。         │
│                                             │
│ Q1 2026 の最多脅威です。                    │
│                                             │
│ [ ブロック ]   [ 別経路で URL を確認する ]  │
└─────────────────────────────────────────────┘
```

### 実装クレート: `kaname-bec/src/aitm.rs`

---

## 機能 #2: Polymorphic Campaign Radar (PCR)

### 解決する脅威

<cite: Cofense 2026年2月>
「76% の初感染 URL が一意だが、94% が同一 IP を共有する」

個別シグネチャ検出は無効だが、**インフラ共有パターン**は有効。

### 着想: 点から線へ

```
従来の検出:
  メール A (URL: phish-1.com) → 悪意なし (未知)
  メール B (URL: phish-2.com) → 悪意なし (未知)
  メール C (URL: phish-3.com) → 悪意なし (未知)
  
  ↑ それぞれ独立に見えるから素通り

PCR:
  phish-1.com → IP 203.0.113.42 → 解決
  phish-2.com → IP 203.0.113.42 → 同一!
  phish-3.com → IP 203.0.113.42 → 同一!
  
  ↑「同じ攻撃者が 3 通送ってきた」と判定
```

### 設計原則: AI は読まない、メタデータだけ

```rust
// crates/kaname-radar/src/lib.rs

pub struct CampaignRadar {
    /// DNS → IP キャッシュ (プライバシー安全: ドメインのみ)
    ip_cache: HashMap<String, Vec<IpAddr>>,
    /// インフラ共有グループ
    infrastructure_groups: Vec<InfrastructureGroup>,
}

/// インフラが共有されているメールのグループ。
pub struct InfrastructureGroup {
    pub shared_ip: IpAddr,
    pub member_emails: Vec<EmailId>,
    pub first_seen: SystemTime,
    pub threat_score: f32,
}

impl CampaignRadar {
    /// 新規受信メールを解析し、既存グループとの共有インフラを検出。
    ///
    /// **重要**: メール本文/件名/本文テキストは読まない。
    /// 解析するのは以下のみ:
    ///   - リンクのドメイン
    ///   - 送信者ドメイン (From: ヘッダー)
    ///   - DKIM/SPF レコードの署名ドメイン
    ///   - MX レコードのサーバー
    pub async fn analyze(&mut self, email_id: EmailId, metadata: EmailMetadata)
        -> Option<CampaignMatch>
    {
        let domains = metadata.extract_domains();
        let mut matched_groups = Vec::new();

        for domain in &domains {
            // ローカル DNS ルックアップ (サードパーティ API 不使用)
            if let Ok(ips) = resolve_domain(domain).await {
                for ip in ips {
                    if let Some(group) = self.find_group_by_ip(ip) {
                        matched_groups.push(group.id.clone());
                        self.add_to_group(group.id, email_id.clone());
                    } else {
                        // 新グループ作成
                        self.create_group(ip, email_id.clone());
                    }
                }
            }
        }

        if !matched_groups.is_empty() {
            Some(CampaignMatch {
                email_id,
                matched_groups,
                confidence: self.calculate_confidence(&matched_groups),
            })
        } else {
            None
        }
    }
}
```

### UX

```
受信トレイのバナー (週次):

┌─────────────────────────────────────────────────┐
│ 🔍 今週のキャンペーン解析                        │
│                                                 │
│ 同一インフラから 3 通のメールを受信しています:   │
│                                                 │
│ • 「請求書の確認」(月曜、sender-a.com)           │
│ • 「アカウント確認が必要」(水曜、verify-now.tk)  │
│ • 「至急：支払い変更」(金曜、payment-update.cc)  │
│                                                 │
│ → 全て IP 203.0.113.42 から配信                 │
│ → 1 つの攻撃キャンペーンの可能性が高い          │
│                                                 │
│ [ 全てをアーカイブ ]  [ 詳細を見る ]            │
└─────────────────────────────────────────────────┘
```

### 実装クレート: `kaname-radar` (新規)

---

## 機能 #3: Sender Style Authentication (SSA)

### 解決する脅威

AI 生成フィッシングで「文法が完璧で、ドメインも正当、SPF/DKIM も通過」するメールが増加。
しかし AI が生成した文章は「CFO の文体」に完全には一致しない。

**核心洞察**: 30 通の過去メールから送信者の「文体指紋」を構築し、
新着メールの文体との距離を計算する。

```
CFO の過去メール 30 通:
  - 平均文長: 2.3 文/パラグラフ
  - 句読点スタイル: 読点少なめ
  - 敬語パターン: 「〜でしょうか」を多用
  - 送信時刻: 9-17時 (平日)
  - 署名形式: 3 行形式

今日の「CFO から」のメール:
  - 平均文長: 4.1 文/パラグラフ ← 乖離
  - 句読点スタイル: 読点多め ← 乖離
  - 敬語パターン: 「〜いただきたく存じます」← 使わない
  - 送信時刻: 22:47 (夜間) ← 乖離
  - 署名形式: 1 行のみ ← 乖離

→ スタイル距離スコア: 0.73 (閾値 0.60 以上で警告)
```

### プライバシー設計

- **コンテンツを保存しない**: スタイル特徴ベクトル (数値のみ) を保存
- **ローカル処理**: クラウド AI 不使用
- **削除可能**: 送信者ごとのスタイルプロファイルをユーザーが削除可能

```rust
// crates/kaname-ssa/src/lib.rs

/// 送信者の文体特徴ベクトル (コンテンツは含まない)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderStyleProfile {
    /// 送信者ドメイン (例: company.co.jp)
    pub sender: String,
    /// サンプル数 (信頼性の指標)
    pub sample_count: u32,
    /// 平均文数/パラグラフ
    pub avg_sentences_per_paragraph: f32,
    /// 読点密度 (文字数あたりの読点数)
    pub punctuation_density: f32,
    /// 平均メール文字数
    pub avg_email_length: f32,
    /// 典型的な送信時刻 (0-23, 分布)
    pub send_hour_distribution: [f32; 24],
    /// 署名行数 (平均)
    pub avg_signature_lines: f32,
    /// 敬語レベル (0.0=カジュアル, 1.0=超丁寧)
    pub formality_score: f32,
    /// よく使う文末表現 (上位 5 個のハッシュ、テキストは保存しない)
    pub sentence_ending_hashes: [u64; 5],
}

impl SenderStyleProfile {
    /// プロファイルが信頼できるか (最低 10 通)
    pub fn is_reliable(&self) -> bool {
        self.sample_count >= 10
    }

    /// 新着メールとのスタイル距離を計算 (0.0=完全一致, 1.0=完全乖離)
    pub fn style_distance(&self, email: &IncomingEmail) -> f32 {
        let features = email.extract_style_features();
        let mut total_dist = 0.0_f32;
        let mut weight_sum = 0.0_f32;

        // 文長 (重み: 0.20)
        total_dist += 0.20 * (self.avg_sentences_per_paragraph
            - features.sentences_per_paragraph).abs().min(3.0) / 3.0;
        weight_sum += 0.20;

        // 送信時刻 (重み: 0.25)
        let hour = email.sent_hour as usize;
        let expected_hour_prob = self.send_hour_distribution[hour];
        total_dist += 0.25 * (1.0 - expected_hour_prob.min(1.0));
        weight_sum += 0.25;

        // フォーマリティ (重み: 0.30)
        total_dist += 0.30 * (self.formality_score - features.formality_score).abs();
        weight_sum += 0.30;

        // メール長 (重み: 0.15)
        let len_ratio = (features.email_length / self.avg_email_length.max(1.0)).ln().abs();
        total_dist += 0.15 * len_ratio.min(1.0);
        weight_sum += 0.15;

        // 句読点密度 (重み: 0.10)
        total_dist += 0.10 * (self.punctuation_density
            - features.punctuation_density).abs().min(1.0);
        weight_sum += 0.10;

        total_dist / weight_sum
    }
}
```

### UX

```
┌─────────────────────────────────────────────────────┐
│ ⚠️ この送信者の文体と異なります                       │
│                                                     │
│ 送信者: cfo@company.co.jp                           │
│                                                     │
│ 過去 47 通との比較:                                 │
│ • 送信時刻: 通常 9-12時 → 今回 22:47 ⚠️            │
│ • 文体: 通常は短文 → 今回は長文 ⚠️                 │
│ • 敬語: 普段使わない表現 ⚠️                         │
│                                                     │
│ スタイル距離スコア: 0.73 / 1.00                     │
│ (閾値 0.60 以上: 要注意)                            │
│                                                     │
│ AI 生成の「なりすまし」の可能性があります。         │
│                                                     │
│ [ 別経路で本人確認 ]  [ 無視して続行 ]              │
└─────────────────────────────────────────────────────┘
```

### 実装クレート: `kaname-ssa` (新規)

---

## 機能 #4: HTML Smuggling Detector

### 解決する脅威

<cite: Group-IB 2026, Trend Micro 2025>

HTML ファイル添付: JS を HTML 内に隠蔽し、ブラウザ内でデコード・実行。
Blob URI フィッシング: `blob:https://...` でフィッシングページをローカルに構築。

**なぜ Kaname が防げなければならないか**:
Superhuman CVE と類似の構造 — メールクライアントが「レンダリング」する時点で攻撃発動。

```rust
// kaname-render/src/html_smuggling.rs

pub struct HtmlSmugglingDetector;

impl HtmlSmugglingDetector {
    pub fn analyze(&self, html: &str) -> SmugglingScan {
        let mut signals = Vec::new();
        let lower = html.to_lowercase();

        // 1. Blob URI の生成コード
        if lower.contains("url.createobjecturl") || lower.contains("blob:") {
            signals.push(Signal::BlobUri);
        }

        // 2. Base64 デコード + 実行パターン
        if lower.contains("atob(") && (lower.contains("eval(") || lower.contains("exec")) {
            signals.push(Signal::Base64Eval);
        }

        // 3. 動的 <a> タグ生成 + 自動クリック
        if lower.contains("createelement(\"a\")") && lower.contains(".click()") {
            signals.push(Signal::AutoDownload);
        }

        // 4. 偽 CAPTCHA パターン
        if lower.contains("verify you are human") ||
           lower.contains("click the box") ||
           lower.contains("captcha") {
            signals.push(Signal::FakeCaptcha);
        }

        // 5. インメモリ Script 実行
        if lower.contains("mshta") || lower.contains("powershell") ||
           lower.contains("cmd.exe") {
            signals.push(Signal::InMemoryExecution);
        }

        SmugglingScan {
            signals: signals.clone(),
            risk: Self::signals_to_risk(&signals),
        }
    }
}
```

### 実装: `kaname-render/src/html_smuggling.rs`

---

## 機能 #5: Calendar Invite Guard

### 解決する脅威

カレンダー招待 (.ics 添付) に悪意ある URL を埋め込む攻撃。
「自然に見える会議招待」が実際は認証情報窃取への誘導。

```rust
// kaname-render/src/calendar_guard.rs

pub struct CalendarGuard {
    url_inspector: QuishingDefense,
}

impl CalendarGuard {
    pub fn analyze_ics(&self, ics_content: &str) -> CalendarScan {
        let mut risks = Vec::new();

        // 1. URL 抽出 (DESCRIPTION, URL, LOCATION フィールド)
        for url in extract_ics_urls(ics_content) {
            let rep = self.url_inspector.evaluate_url(&url);
            if rep != UrlReputation::Trusted && rep != UrlReputation::Neutral {
                risks.push(CalendarRisk::SuspiciousUrl { url, reputation: rep });
            }
        }

        // 2. 主催者ドメイン確認
        if let Some(organizer) = extract_organizer(ics_content) {
            if is_impersonation_attempt(&organizer) {
                risks.push(CalendarRisk::SuspiciousOrganizer { organizer });
            }
        }

        // 3. 緊急性の偽装
        let desc = extract_description(ics_content).unwrap_or_default().to_lowercase();
        let urgency = ["urgent", "verify now", "account suspended", "immediate action"]
            .iter().any(|kw| desc.contains(kw));
        if urgency {
            risks.push(CalendarRisk::UrgencyManipulation);
        }

        CalendarScan { risks }
    }
}
```

### 実装: `kaname-render/src/calendar_guard.rs`

---

## 採用しなかった候補

| 候補 | 却下理由 |
|---|---|
| 受信箱全体の AI スキャン | 北極星違反 (Q-LLM は 1 通のみ) |
| SMS/電話でのコード確認システム | OOBV (#1) で既に対応 |
| ブラウザ拡張機能 | 攻撃面拡大、ユーザー同意不明確 |
| IP ブロックリスト共有クラウド | プライバシー原則違反、データ送信 |
| フィッシングサイト自動報告 | ユーザー代理の外部通信は禁止 |

---

## 実装ロードマップ v0.3

### Phase 1 (v0.3.0) — 2026 Q3

| 機能 | クレート | 優先度 | 工数 |
|---|---|---|---|
| #1 AiTM Link Detector | kaname-bec/aitm | P0 | 2 週 |
| #2 Polymorphic Campaign Radar | kaname-radar (新規) | P1 | 4 週 |
| #3 Sender Style Auth | kaname-ssa (新規) | P1 | 4 週 |
| #4 HTML Smuggling Detector | kaname-render/html_smuggling | P2 | 2 週 |
| #5 Calendar Invite Guard | kaname-render/calendar_guard | P2 | 2 週 |

---

## 改訂履歴

| 日付 | 改訂者 | 内容 |
|---|---|---|
| 2026-05-12 | @kaname-app/security-lead | 初版 - Q1 2026 Deep Research 統合 |
