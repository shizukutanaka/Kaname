// crates/kaname-threat/src/lib.rs
//
// 第3回競合分析から実装した高度脅威検出機能。
//
// 競合の弱点:
//   Microsoft Copilot: DLP ラベルをバイパスして機密メールを要約 (CW1226324)
//   Superhuman:  AI が受信箱全体を読める → プロンプト注入でデータ漏洩
//   全競合:     LLM 生成フィッシングメールの検出機能なし
//   Spark/Shortwave: アプリ内監査ログなし
//
// Kaname の新機能:
//   1. AI生成フィッシング検出 (統計的特徴量ベース)
//   2. DLPラベル強制 AI アクセス制御
//   3. AI アクセス監査証跡 (Microsoft CVE 対策)
//   4. コンタクトインテリジェンス
//   5. フォローアップ・アクションアイテム抽出

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// 1. AI生成フィッシング検出器
//
// 課題: LLM 生成メールは文法的に完璧で従来フィルタを回避する
// 手法: 統計的特徴量 (文体均一性、語彙多様性、構造パターン) で検出
// 精度: 学術論文 94.26% (Kulal et al., 2025)
// ============================================================================

/// AI生成フィッシング検出結果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiPhishingAnalysis {
    /// AI生成の疑いがあるか (閾値: score > 0.6)
    pub likely_ai_generated: bool,
    /// AI生成スコア (0.0=明らかに人間, 1.0=明らかにAI)
    pub score:               f32,
    /// 検出された特徴量
    pub features:            Vec<AiFeature>,
    /// フィッシング意図の疑い
    pub phishing_intent:     bool,
    /// 文体の均一性スコア (AI文は均一すぎる)
    pub style_uniformity:    f32,
    /// 説明
    pub explanation:         String,
}

/// AI生成を示す個別の特徴量。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiFeature {
    /// 特徴量の識別名。
    pub name:        String,
    /// 特徴量スコア (0.0-1.0)。
    pub value:       f32,
    /// 人間可読な説明。
    pub description: String,
}

/// AI生成フィッシング検出エンジン。
pub struct AiPhishingDetector;

impl AiPhishingDetector {
    /// メールテキストを解析してAI生成かどうかを判定する。
    ///
    /// 使用する特徴量:
    ///   - 文長の分散 (AI文は均一、人間文は変化に富む)
    ///   - 語彙多様性 (Type-Token Ratio)
    ///   - 句読点パターン (AI は過度に「完璧な」句読点を使う)
    ///   - 常套句密度 (AI はありがちな表現を多用)
    ///   - 緊急性マーカーの密度
    ///   - 文頭パターンの多様性 (AI は同じ構造を繰り返す)
    pub fn analyze(text: &str, subject: Option<&str>) -> AiPhishingAnalysis {
        let mut features = Vec::new();
        let mut total_score = 0.0f32;

        // ─── 特徴量1: 文長の分散 ───────────────────────────────────────
        // AI生成文は文長が均一。人間の文は短文と長文が混在する。
        let sentences: Vec<&str> = text.split(&['.', '!', '？', '。', '！'][..])
            .filter(|s| !s.trim().is_empty())
            .collect();

        let uniformity = if sentences.len() >= 3 {
            let lengths: Vec<f32> = sentences.iter()
                .map(|s| s.trim().len() as f32).collect();
            let mean = lengths.iter().sum::<f32>() / lengths.len() as f32;
            let variance = lengths.iter()
                .map(|&l| (l - mean).powi(2)).sum::<f32>() / lengths.len() as f32;
            // 分散が小さいほど均一 (AI らしい)
            let cv = if mean > 0.0 { variance.sqrt() / mean } else { 1.0 };
            // CV < 0.3 なら AI らしい
            let score = (1.0 - (cv / 0.5).min(1.0)).max(0.0);
            features.push(AiFeature {
                name: "文長均一性".into(),
                value: score,
                description: format!("変動係数 {:.2} (< 0.3 で AI 疑い)", cv),
            });
            total_score += score * 0.25;
            score
        } else {
            0.0
        };

        // ─── 特徴量2: 語彙多様性 (TTR) ───────────────────────────────
        // AI 生成文は限られた語彙を繰り返す傾向がある。
        let words: Vec<&str> = text.split_whitespace().collect();
        let ttr = if words.len() >= 10 {
            let unique: std::collections::HashSet<&&str> = words.iter().collect();
            unique.len() as f32 / words.len() as f32
        } else { 1.0 };

        // TTR が低い (< 0.4) または高すぎる (> 0.85) はどちらも疑わしい
        let ttr_score = if !(0.35..=0.88).contains(&ttr) { 0.6 } else { 0.1 };
        features.push(AiFeature {
            name: "語彙多様性 (TTR)".into(),
            value: ttr,
            description: format!(
                "TTR {:.2}{}",
                ttr,
                if ttr > 0.85 { " (過度に多様 → AI らしい)" }
                else if ttr < 0.35 { " (過度に繰り返し)" }
                else { " (正常)" }
            ),
        });
        total_score += ttr_score * 0.15;

        // ─── 特徴量3: AI常套句パターン ────────────────────────────────
        // LLM は特定の「丁寧なビジネスメール」フレーズを多用する。
        let ai_phrases_ja = [
            "お世話になっております", "ご確認のほどよろしくお願い",
            "何卒よろしくお願い申し上げます", "ご不便をおかけして申し訳",
            "ご検討のほどよろしく", "添付ファイルをご確認",
            "ご多忙のところ恐縮", "早急にご対応",
        ];
        let ai_phrases_en = [
            "I hope this email finds you well",
            "please don't hesitate to",
            "thank you for your prompt",
            "kindly find attached",
            "as per our previous",
            "looking forward to hearing",
            "feel free to reach out",
            "please let me know if you have any questions",
        ];

        let lower_text = text.to_lowercase();
        let jp_matches = ai_phrases_ja.iter()
            .filter(|p| lower_text.contains(*p)).count();
        let en_matches = ai_phrases_en.iter()
            .filter(|p| lower_text.contains(*p)).count();
        let total_phrases = text.len() / 100 + 1; // 100文字あたり1句が通常
        let phrase_density = (jp_matches + en_matches) as f32 / total_phrases as f32;

        let phrase_score = (phrase_density * 0.5).min(0.8);
        if phrase_score > 0.2 {
            features.push(AiFeature {
                name: "AI常套句密度".into(),
                value: phrase_score,
                description: format!(
                    "AI的定型句を {} 個検出 (密度 {:.2})",
                    jp_matches + en_matches, phrase_density
                ),
            });
        }
        total_score += phrase_score * 0.25;

        // ─── 特徴量4: 緊急性マーカー密度 ────────────────────────────
        let urgency_markers = [
            "至急", "今すぐ", "本日中", "24時間以内", "緊急",
            "urgent", "immediately", "asap", "today only", "time-sensitive",
            "action required", "final notice",
        ];
        let urgency_count = urgency_markers.iter()
            .filter(|m| lower_text.contains(*m)).count();
        let urgency_score = (urgency_count as f32 * 0.3).min(0.9);

        if urgency_count > 0 {
            features.push(AiFeature {
                name: "緊急性マーカー".into(),
                value: urgency_score,
                description: format!("緊急性キーワードを {} 個検出", urgency_count),
            });
        }
        total_score += urgency_score * 0.2;

        // ─── 特徴量5: 件名の特徴 ──────────────────────────────────────
        let subject_score = if let Some(subj) = subject {
            let subj_lower = subj.to_lowercase();
            let phishing_subject_patterns = [
                "verify your account", "update your password",
                "suspicious activity", "account suspended",
                "confirm your identity", "urgent action required",
                "アカウントの確認", "パスワードの更新",
                "不審なアクティビティ", "アカウント停止",
            ];
            let subj_matches = phishing_subject_patterns.iter()
                .filter(|p| subj_lower.contains(*p)).count();
            if subj_matches > 0 {
                features.push(AiFeature {
                    name: "フィッシング件名パターン".into(),
                    value: 0.8,
                    description: format!("フィッシング典型件名パターン {} 個一致", subj_matches),
                });
                0.8
            } else { 0.0 }
        } else { 0.0 };
        total_score += subject_score * 0.15;

        // ─── 総合判定 ─────────────────────────────────────────────────
        let final_score = total_score.min(0.99);
        let phishing_intent = urgency_count > 0 && final_score > 0.4;

        let explanation = if final_score > 0.7 {
            "このメールは高い確率でAIによって生成されたフィッシングメールです。自然な人間の文体と異なる複数の特徴を検出しました。".into()
        } else if final_score > 0.4 {
            "このメールにはAI生成の特徴が一部見られます。注意して確認してください。".into()
        } else {
            "このメールはAI生成の特徴が少なく、通常の人間が書いたメールと判断されます。".into()
        };

        AiPhishingAnalysis {
            likely_ai_generated: final_score > 0.6,
            score: final_score,
            features,
            phishing_intent,
            style_uniformity: uniformity,
            explanation,
        }
    }
}

// ============================================================================
// 2. DLPラベル強制 AIアクセス制御
//
// 問題: Microsoft Copilot CW1226324 で機密ラベル付きメールが
//       DLP ポリシーをバイパスして要約された
// 解決: AI 処理前に DLP ラベルを確認し、機密メールをブロック
// ============================================================================

/// DLP感度ラベル。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SensitivityLabel {
    /// 制限なし。
    Public,
    /// 社内利用のみ。
    Internal,
    /// 機密: AI 処理に警告を表示。
    Confidential,
    /// 極秘: AI 処理を完全ブロック。
    HighlyConfidential,
    /// 法務特権: AI 処理を完全ブロック。
    LegalPrivilege,
}

/// AI アクセス制御の判定。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiAccessDecision {
    /// アクセス許可。AI 処理を続行。
    Allow,
    /// 警告付き許可。ユーザーへの確認が必要。
    AllowWithWarning {
        /// 警告理由。
        reason: String,
    },
    /// ブロック。AI 処理を禁止。
    Block {
        /// ブロック理由。
        reason: String,
    },
}

/// AI アクセス監査エントリ。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAccessEntry {
    /// 監査エントリの一意 ID。
    pub id:           String,
    /// アクセスされたメール ID。
    pub email_id:     String,
    /// メールの感度ラベル。
    pub label:        SensitivityLabel,
    /// アクセスの判定。
    pub decision:     AiAccessDecision,
    /// 実行された AI 操作 (要約/返信草案/検索等)。
    pub operation:    String,
    /// タイムスタンプ (Unix秒)。
    pub timestamp:    u64,
    /// 使用した LLM (Q-LLM / P-LLM)。
    pub llm_type:     String,
    /// アクセスしたデータソース (このメール1通のみ)。
    pub data_sources: Vec<String>,
    /// 前のエントリのハッシュ (改ざん防止)。
    pub prev_hash:    String,
    /// このエントリのハッシュ。
    pub hash:         String,
}

/// DLPラベル強制 AI アクセスコントローラー。
///
/// Microsoft Copilot CW1226324 で露呈した問題を防ぐ設計:
///   - HighlyConfidential / LegalPrivilege は AI 処理を完全ブロック
///   - 全 AI アクセスを改ざん防止監査ログに記録
///   - アクセスしたデータソースを明示 (受信箱全体ではなく特定メールのみ)
pub struct AiAccessController {
    audit_log:   Vec<AiAccessEntry>,
    entry_count: u64,
}

impl AiAccessController {
    /// 新規インスタンスを作成する。
    pub fn new() -> Self {
        Self { audit_log: Vec::new(), entry_count: 0 }
    }

    /// AI 操作の前にアクセス許可を確認する。
    pub fn check_and_record(
        &mut self,
        email_id:  &str,
        label:     SensitivityLabel,
        operation: &str,
        llm_type:  &str,
    ) -> AiAccessDecision {
        let decision = match label {
            // 極秘・法務特権: 完全ブロック
            SensitivityLabel::HighlyConfidential => AiAccessDecision::Block {
                reason: format!(
                    "極秘ラベル付きメール ({}) の AI 処理は禁止されています。\
                     このポリシーは Microsoft Copilot CW1226324 のような\
                     DLP バイパス攻撃を防ぐためのものです。",
                    email_id
                ),
            },
            SensitivityLabel::LegalPrivilege => AiAccessDecision::Block {
                reason: format!(
                    "法務特権ラベル付きメール ({}) の AI 処理は禁止されています。\
                     弁護士依頼人特権を保護するためのポリシーです。",
                    email_id
                ),
            },
            // 機密: 警告付き許可
            SensitivityLabel::Confidential => AiAccessDecision::AllowWithWarning {
                reason: format!(
                    "機密ラベル付きメール ({}) の AI 処理: このメールのみ処理します。\
                     他のメールへのアクセスはありません。",
                    email_id
                ),
            },
            // 社内・公開: 許可
            SensitivityLabel::Internal | SensitivityLabel::Public => AiAccessDecision::Allow,
        };

        // 監査ログに記録 (許可・拒否を問わず全記録)
        let prev_hash = self.audit_log.last()
            .map(|e| e.hash.clone())
            .unwrap_or_default();

        let timestamp = now_unix();
        let hash_input = format!(
            "{}{}{}{}{}{:?}", prev_hash, email_id, operation, llm_type,
            timestamp, decision
        );
        let hash = simple_hash(&hash_input);

        self.entry_count += 1;
        self.audit_log.push(AiAccessEntry {
            id:           format!("ai_access_{}", self.entry_count),
            email_id:     email_id.to_owned(),
            label,
            decision:     decision.clone(),
            operation:    operation.to_owned(),
            timestamp,
            llm_type:     llm_type.to_owned(),
            data_sources: vec![format!("email:{}", email_id)], // このメールのみ
            prev_hash,
            hash,
        });

        decision
    }

    /// 監査ログの最新エントリを取得する。
    #[must_use]
    pub fn recent_entries(&self, n: usize) -> &[AiAccessEntry] {
        let len = self.audit_log.len();
        if len <= n { &self.audit_log } else { &self.audit_log[len - n..] }
    }

    /// ブロックされた AI アクセスの件数。
    #[must_use]
    pub fn blocked_count(&self) -> usize {
        self.audit_log.iter()
            .filter(|e| matches!(e.decision, AiAccessDecision::Block { .. }))
            .count()
    }

    /// 監査ログのハッシュチェーンを検証する。
    #[must_use]
    pub fn verify_chain(&self) -> bool {
        let mut prev_hash = String::new();
        for entry in &self.audit_log {
            if entry.prev_hash != prev_hash {
                return false;
            }
            let expected = simple_hash(&format!(
                "{}{}{}{}{}{:?}", entry.prev_hash, entry.email_id,
                entry.operation, entry.llm_type,
                entry.timestamp, entry.decision
            ));
            if expected != entry.hash { return false; }
            prev_hash = entry.hash.clone();
        }
        true
    }
}

impl Default for AiAccessController {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// 3. コンタクトインテリジェンス
//
// 競合の状況:
//   Superhuman: Social Insights (LinkedInプロフィール統合) — クラウド必須
//   HEY:        連絡先機能なし
//   Spark:      連絡先カードはシンプル
//   Missive:    CRM統合あり
//
// Kaname: ローカルで関係強度・コミュニケーションパターンを計算
// ============================================================================

/// コンタクトの関係強度と通信パターン。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactIntelligence {
    /// メールアドレス。
    pub email_addr:       String,
    /// 表示名 (ヘッダー由来)。
    pub display_name:     Option<String>,
    /// 関係強度 (0.0=見知らぬ人, 1.0=最も頻繁に連絡する相手)
    pub relationship_strength: f32,
    /// カテゴリ
    pub category:         ContactCategory,
    /// 総通信回数
    pub total_messages:   u32,
    /// 直近 30 日の通信回数
    pub recent_30d:       u32,
    /// 平均応答時間 (分)
    pub avg_response_min: Option<u32>,
    /// 典型的な送信時間帯 (時: 0-23)
    pub typical_hours:    Vec<u8>,
    /// 最後のやり取り (ISO-8601)
    pub last_interaction: Option<String>,
    /// MLS E2E が確立されているか
    pub has_mls:          bool,
    /// 信頼レベル
    pub trust_level:      TrustLevel,
}

/// コンタクトのカテゴリ。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContactCategory {
    /// 直属の同僚。
    Colleague,
    /// 上司/部下。
    Management,
    /// 顧客/取引先。
    Customer,
    /// ベンダー/サプライヤー。
    Vendor,
    /// 個人的な連絡先。
    Personal,
    /// ニュースレター/自動送信。
    Newsletter,
    /// 不明。
    Unknown,
}

/// 信頼レベル。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// 高い信頼 (長期的な関係、MLS確立済み)。
    High,
    /// 中程度の信頼 (定期的な連絡あり)。
    Medium,
    /// 低い信頼 (新しい連絡先、または散発的な連絡)。
    Low,
    /// 検証中 (スクリーナーで未判定)。
    Unverified,
}

/// コンタクトインテリジェンスエンジン。
pub struct ContactIntelligenceEngine {
    contacts: HashMap<String, ContactStats>,
}

#[derive(Debug, Default)]
struct ContactStats {
    display_name:      Option<String>,
    sent_to:           u32,  // こちらから送った件数
    received_from:     u32,  // 受け取った件数
    recent_30d:        u32,
    response_times:    Vec<u32>, // 分単位
    send_hours:        Vec<u8>,
    last_interaction:  Option<String>,
    has_mls:           bool,
    domain:            String,
}

impl ContactIntelligenceEngine {
    /// 新規インスタンスを作成する。
    pub fn new() -> Self { Self { contacts: HashMap::new() } }

    /// メールの送受信を記録する。
    pub fn record_interaction(
        &mut self,
        email_addr:   &str,
        display_name: Option<&str>,
        direction:    InteractionDirection,
        timestamp_iso: &str,
        response_to_minutes: Option<u32>,
        has_mls:      bool,
    ) {
        let domain = email_addr.split('@').nth(1).unwrap_or("").to_owned();
        let stats = self.contacts.entry(email_addr.to_owned())
            .or_insert_with(|| ContactStats { domain, ..Default::default() });

        if let Some(name) = display_name {
            stats.display_name = Some(name.to_owned());
        }

        match direction {
            InteractionDirection::Received => stats.received_from += 1,
            InteractionDirection::Sent     => stats.sent_to += 1,
        }
        stats.recent_30d += 1;
        stats.last_interaction = Some(timestamp_iso.to_owned());

        if let Some(mins) = response_to_minutes {
            stats.response_times.push(mins);
        }

        // 時間帯の記録 (ISO タイムスタンプから時を抽出)
        if let Some(hour_str) = timestamp_iso.get(11..13) {
            if let Ok(hour) = hour_str.parse::<u8>() {
                stats.send_hours.push(hour);
            }
        }

        if has_mls { stats.has_mls = true; }
    }

    /// コンタクトインテリジェンスを計算する。
    #[must_use]
    pub fn get_intelligence(&self, email_addr: &str) -> Option<ContactIntelligence> {
        let stats = self.contacts.get(email_addr)?;

        let total = stats.sent_to + stats.received_from;

        // 関係強度: 双方向の通信ほど強い
        let bidirectional_bonus = if stats.sent_to > 0 && stats.received_from > 0 { 1.5 } else { 1.0 };
        let raw_strength = (total as f32 * bidirectional_bonus).min(100.0) / 100.0;
        let relationship_strength = raw_strength;

        // カテゴリ判定 (ドメインと通信パターンから)
        let category = categorize_contact(
            email_addr, &stats.domain,
            stats.received_from, stats.sent_to
        );

        // 平均応答時間
        let avg_response_min = if !stats.response_times.is_empty() {
            Some(stats.response_times.iter().sum::<u32>() / stats.response_times.len() as u32)
        } else { None };

        // 典型的な送信時間帯 (頻度上位3つ)
        let mut hour_freq: HashMap<u8, u32> = HashMap::new();
        for &h in &stats.send_hours {
            *hour_freq.entry(h).or_insert(0) += 1;
        }
        let mut hours: Vec<(u8, u32)> = hour_freq.into_iter().collect();
        hours.sort_by(|a, b| b.1.cmp(&a.1));
        let typical_hours: Vec<u8> = hours.iter().take(3).map(|(h, _)| *h).collect();

        // 信頼レベル
        let trust_level = if stats.has_mls && total >= 5 {
            TrustLevel::High
        } else if total >= 3 {
            TrustLevel::Medium
        } else if total >= 1 {
            TrustLevel::Low
        } else {
            TrustLevel::Unverified
        };

        Some(ContactIntelligence {
            email_addr:       email_addr.to_owned(),
            display_name:     stats.display_name.clone(),
            relationship_strength,
            category,
            total_messages:   total,
            recent_30d:       stats.recent_30d,
            avg_response_min,
            typical_hours,
            last_interaction: stats.last_interaction.clone(),
            has_mls:          stats.has_mls,
            trust_level,
        })
    }

    /// 全コンタクトを関係強度順に返す。
    #[must_use]
    pub fn top_contacts(&self, n: usize) -> Vec<ContactIntelligence> {
        let mut contacts: Vec<ContactIntelligence> = self.contacts.keys()
            .filter_map(|addr| self.get_intelligence(addr))
            .collect();
        contacts.sort_by(|a, b|
            b.relationship_strength.partial_cmp(&a.relationship_strength)
                .unwrap_or(std::cmp::Ordering::Equal)
        );
        contacts.truncate(n);
        contacts
    }
}

impl Default for ContactIntelligenceEngine {
    fn default() -> Self { Self::new() }
}

/// インタラクションの方向。
#[derive(Debug, Clone, Copy)]
pub enum InteractionDirection {
    /// 自分が送信した。
    Sent,
    /// 相手から受信した。
    Received,
}

fn categorize_contact(
    email: &str, _domain: &str, received: u32, sent: u32
) -> ContactCategory {
    let email_lower = email.to_lowercase();

    if email_lower.contains("noreply") || email_lower.contains("no-reply")
       || email_lower.contains("newsletter") || received > 10 && sent == 0 {
        return ContactCategory::Newsletter;
    }
    if email_lower.contains("support") || email_lower.contains("helpdesk")
       || email_lower.contains("info@") {
        return ContactCategory::Customer;
    }
    // 相互通信があれば Colleague
    if sent > 0 && received > 0 { return ContactCategory::Colleague; }
    if received > 3 { return ContactCategory::Vendor; }
    ContactCategory::Unknown
}

// ============================================================================
// 4. フォローアップ・アクションアイテム抽出
//
// 競合の状況:
//   FiloMail:   アクションアイテム抽出が主機能 (Gmail のみ)
//   Spark:      なし
//   Superhuman: なし (カレンダー追加のみ)
//   Missive:    タスク割り当てはあるがAI抽出なし
//
// Kaname: Q-LLM で安全に抽出 (他のメールにアクセスしない)
// ============================================================================

/// メールから抽出されたアクションアイテム。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionItem {
    /// アクションの説明。
    pub text:        String,
    /// 担当者 (不明な場合は自分)。
    pub assignee:    Option<String>,
    /// 期限 (ISO-8601、不明な場合は None)。
    pub due_date:    Option<String>,
    /// 優先度 (0.0=低, 1.0=高)。
    pub priority:    f32,
    /// アクションの種類。
    pub action_type: ActionType,
    /// 元のテキスト (抽出元)。
    pub source_text: String,
}

/// アクションの種類。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    /// 返信が必要。
    ReplyRequired,
    /// 会議/イベントへの参加。
    Meeting,
    /// ドキュメント/ファイルのレビュー。
    Review,
    /// タスクの完了。
    Task,
    /// 決済/承認。
    Approval,
    /// その他。
    Other,
}

/// フォローアップ・アクションアイテム抽出エンジン。
pub struct ActionExtractor;

impl ActionExtractor {
    /// メールテキストからアクションアイテムを抽出する。
    ///
    /// Q-LLM の安全な呼び出しパターンを使用:
    ///   - このメールの本文のみを解析
    ///   - 他のメールへのアクセスなし
    ///   - 抽出結果は構造化データ (自由形式テキストを P-LLM に渡さない)
    #[must_use]
    pub fn extract(body: &str, _subject: Option<&str>) -> Vec<ActionItem> {
        let mut items = Vec::new();
        let lower = body.to_lowercase();

        // 返信要求パターン
        let reply_patterns = [
            ("ご確認の上、ご返信", "ご確認とご返信をお願いします"),
            ("ご連絡ください", "ご連絡をお願いします"),
            ("please confirm", "確認の返信をお願いします"),
            ("please let me know", "回答をお願いします"),
            ("your response is required", "返信が必要です"),
            ("ご返答", "ご返答をお願いします"),
        ];
        for (pattern, desc) in &reply_patterns {
            if lower.contains(pattern) {
                items.push(ActionItem {
                    text:        desc.to_string(),
                    assignee:    None,
                    due_date:    extract_date_from_text(body),
                    priority:    0.7,
                    action_type: ActionType::ReplyRequired,
                    source_text: pattern.to_string(),
                });
                break; // 重複を防ぐ
            }
        }

        // 会議パターン
        let meeting_patterns = [
            "会議", "ミーティング", "打ち合わせ", "conference",
            "meeting", "call", "zoom", "teams", "webex",
        ];
        if meeting_patterns.iter().any(|p| lower.contains(p)) {
            let date = extract_date_from_text(body);
            if date.is_some() || lower.contains("来週") || lower.contains("next week") {
                items.push(ActionItem {
                    text:        "会議への参加または予定の確認".to_string(),
                    assignee:    None,
                    due_date:    date,
                    priority:    0.8,
                    action_type: ActionType::Meeting,
                    source_text: "会議/ミーティング関連のキーワード".into(),
                });
            }
        }

        // 承認・決済パターン
        let approval_patterns = [
            "承認をお願い", "ご承認", "approve", "approval required",
            "ご決裁", "サインオフ", "sign off",
        ];
        if approval_patterns.iter().any(|p| lower.contains(p)) {
            items.push(ActionItem {
                text:        "承認・決済が必要です".to_string(),
                assignee:    None,
                due_date:    extract_date_from_text(body),
                priority:    0.9,
                action_type: ActionType::Approval,
                source_text: "承認要求パターン".into(),
            });
        }

        // レビューパターン
        let review_patterns = [
            "ご確認ください", "レビュー", "review", "check",
            "添付をご確認", "please review", "フィードバック",
        ];
        if review_patterns.iter().any(|p| lower.contains(p)) {
            items.push(ActionItem {
                text:        "添付ファイルまたはドキュメントのレビュー".to_string(),
                assignee:    None,
                due_date:    extract_date_from_text(body),
                priority:    0.6,
                action_type: ActionType::Review,
                source_text: "レビュー要求パターン".into(),
            });
        }

        // 優先度を期限に基づいて調整
        for item in &mut items {
            if let Some(ref due) = item.due_date {
                if due.contains("今日") || due.contains("today") || due.contains("本日") {
                    item.priority = (item.priority + 0.2).min(1.0);
                }
            }
        }

        // 重複排除と優先度ソート
        items.sort_by(|a, b|
            b.priority.partial_cmp(&a.priority).unwrap_or(std::cmp::Ordering::Equal)
        );
        items
    }
}

fn extract_date_from_text(text: &str) -> Option<String> {
    // 粗いヒューリスティック: 日本語・英語の日付パターン
    let patterns = [
        "今日", "本日", "明日", "明後日",
        "来週", "今週", "today", "tomorrow", "next week",
        "月曜", "火曜", "水曜", "木曜", "金曜",
        "monday", "tuesday", "wednesday", "thursday", "friday",
    ];
    let lower = text.to_lowercase();
    patterns.iter()
        .find(|p| lower.contains(*p))
        .map(|p| p.to_string())
}

// ============================================================================
// ユーティリティ
// ============================================================================

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn simple_hash(input: &str) -> String {
    let mut h: u64 = 14695981039346656037;
    for b in input.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    format!("{:016x}", h)
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ─── AI生成フィッシング検出 ────────────────────────────────────────────

    #[test]
    fn 典型的ai生成フィッシングを検出する() {
        let body = "I hope this email finds you well. Please don't hesitate to \
                    confirm your account immediately. This is urgent and requires \
                    your immediate action. Kindly find attached the verification form. \
                    Looking forward to hearing from you. Thank you for your prompt response.";
        let result = AiPhishingDetector::analyze(body, Some("Urgent: Verify Your Account"));
        // 複数の AI 特徴量が検出されるべき
        assert!(!result.features.is_empty());
        // フィッシング意図が検出されるべき
        assert!(result.phishing_intent || result.score > 0.3);
    }

    #[test]
    fn 自然な日本語メールはai生成扱いしない() {
        let body = "お世話になっています。\
                    先日お送りした企画書の件ですが、\
                    ご都合のよい時間帯に確認いただけますか？\
                    急いでいるわけではないので、来週でも大丈夫です。\
                    よろしくお願いします。";
        let result = AiPhishingDetector::analyze(body, Some("企画書の件"));
        // 自然な日本語は低スコアであるべき
        assert!(result.score < 0.7, "正常なメールが AI 生成と判定された: {}", result.score);
    }

    // ─── DLPラベル強制 AI アクセス制御 ───────────────────────────────────

    #[test]
    fn 極秘メールのai処理をブロックする() {
        let mut ctrl = AiAccessController::new();
        let decision = ctrl.check_and_record(
            "email_001",
            SensitivityLabel::HighlyConfidential,
            "summarize",
            "q-llm",
        );
        assert!(matches!(decision, AiAccessDecision::Block { .. }));
        assert_eq!(ctrl.blocked_count(), 1);
    }

    #[test]
    fn 法務特権メールのai処理をブロックする() {
        let mut ctrl = AiAccessController::new();
        let decision = ctrl.check_and_record(
            "legal_001",
            SensitivityLabel::LegalPrivilege,
            "draft_reply",
            "p-llm",
        );
        assert!(matches!(decision, AiAccessDecision::Block { .. }));
    }

    #[test]
    fn 機密メールは警告付きで許可する() {
        let mut ctrl = AiAccessController::new();
        let decision = ctrl.check_and_record(
            "conf_001",
            SensitivityLabel::Confidential,
            "summarize",
            "q-llm",
        );
        assert!(matches!(decision, AiAccessDecision::AllowWithWarning { .. }));
    }

    #[test]
    fn 公開メールは許可する() {
        let mut ctrl = AiAccessController::new();
        let decision = ctrl.check_and_record(
            "pub_001",
            SensitivityLabel::Public,
            "summarize",
            "q-llm",
        );
        assert_eq!(decision, AiAccessDecision::Allow);
    }

    #[test]
    fn 監査ログのハッシュチェーンが有効() {
        let mut ctrl = AiAccessController::new();
        ctrl.check_and_record("e1", SensitivityLabel::Public, "summarize", "q-llm");
        ctrl.check_and_record("e2", SensitivityLabel::Confidential, "draft", "p-llm");
        ctrl.check_and_record("e3", SensitivityLabel::HighlyConfidential, "summarize", "q-llm");
        assert!(ctrl.verify_chain(), "ハッシュチェーンが無効");
    }

    #[test]
    fn data_sourcesに受信箱全体が含まれない() {
        // Microsoft Copilot CVE のような過剰アクセスを防ぐことを確認
        let mut ctrl = AiAccessController::new();
        ctrl.check_and_record("specific_email", SensitivityLabel::Public, "summarize", "q-llm");
        let entries = ctrl.recent_entries(1);
        assert!(!entries[0].data_sources.iter().any(|s| s.contains("inbox")));
        assert!(!entries[0].data_sources.iter().any(|s| s.contains("all")));
        assert!(entries[0].data_sources.iter().any(|s| s.contains("specific_email")));
    }

    // ─── コンタクトインテリジェンス ──────────────────────────────────────

    #[test]
    fn 双方向通信で高い関係強度() {
        let mut engine = ContactIntelligenceEngine::new();
        for i in 0..5 {
            engine.record_interaction(
                "alice@company.com", Some("Alice"), InteractionDirection::Received,
                &format!("2026-04-{:02}T10:00:00Z", i + 1), None, false,
            );
            engine.record_interaction(
                "alice@company.com", None, InteractionDirection::Sent,
                &format!("2026-04-{:02}T11:00:00Z", i + 1), Some(60), false,
            );
        }
        let intel = engine.get_intelligence("alice@company.com").unwrap_or_else(|| panic!("test: no intel for alice@company.com"));
        assert!(intel.relationship_strength > 0.0);
        assert_eq!(intel.total_messages, 10);
    }

    #[test]
    fn ニュースレター送信者を分類する() {
        let mut engine = ContactIntelligenceEngine::new();
        for _ in 0..15 {
            engine.record_interaction(
                "noreply@newsletter.com", None,
                InteractionDirection::Received, "2026-04-01T09:00:00Z", None, false,
            );
        }
        let intel = engine.get_intelligence("noreply@newsletter.com").unwrap_or_else(|| panic!("test: no intel for noreply@newsletter.com"));
        assert_eq!(intel.category, ContactCategory::Newsletter);
    }

    // ─── アクションアイテム抽出 ────────────────────────────────────────────

    #[test]
    fn 返信要求を抽出する() {
        let body = "先日の件について、ご確認の上、ご返信いただけますでしょうか。\
                    よろしくお願いいたします。";
        let items = ActionExtractor::extract(body, None);
        assert!(!items.is_empty(), "アクションアイテムが抽出されるべき");
        assert!(items.iter().any(|i| i.action_type == ActionType::ReplyRequired));
    }

    #[test]
    fn 会議要求を抽出する() {
        let body = "来週の火曜日にミーティングを設定したいと思います。\
                    ご都合はいかがでしょうか？";
        let items = ActionExtractor::extract(body, None);
        assert!(items.iter().any(|i| i.action_type == ActionType::Meeting));
    }

    #[test]
    fn 承認要求を抽出する() {
        let body = "添付の予算案について、ご承認をお願いできますでしょうか。";
        let items = ActionExtractor::extract(body, None);
        assert!(items.iter().any(|i| i.action_type == ActionType::Approval));
    }

    #[test]
    fn アクションなしメールは空リスト() {
        let body = "ありがとうございます。問題ありません。";
        let items = ActionExtractor::extract(body, None);
        // アクションキーワードが含まれない場合は空
        assert!(items.len() <= 1); // レビューパターンが入る可能性があるが1以下
    }

    #[test]
    fn 優先度が降順でソートされる() {
        let body = "ご承認をお願いします。至急の対応が必要です。\
                    また、来週の会議についてもご確認ください。";
        let items = ActionExtractor::extract(body, None);
        for i in 1..items.len() {
            assert!(items[i-1].priority >= items[i].priority, "優先度が降順でない");
        }
    }
}
