//! Tauri コマンドハンドラー。
//! フロントエンドの invoke() が呼ぶ全関数を実装。
//!
//! Tauri マクロを使わずに純粋な async fn として定義し、
//! src-tauri で `#[tauri::command]` を付けて登録する。

use serde::{Deserialize, Serialize};
use tracing::{error, info, instrument, warn};

// ── レスポンス型 ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub version: String,
}

/// `.eml` 取り込みで読み込む1ファイルの最大サイズ。
/// 巨大ファイルの `fs::read` によるメモリ使い果たしを防ぐ
/// (一般的なメールは数百KB 程度; 添付込みでも 50MB を超える正規利用は稀)。
const MAX_EML_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Debug, Serialize, Clone)]
pub struct EmailRow {
    pub id: String,
    pub from_name: Option<String>,
    pub from_addr: String,
    pub subject: Option<String>,
    pub preview: Option<String>,
    pub received_at: Option<String>,
    pub is_read: bool,
    pub is_starred: bool,
    pub bec_verdict: String,
    pub is_mls: bool,
    pub triage: String,
}

#[derive(Debug, Serialize)]
pub struct MailSummary {
    pub unread: u32,
    pub bec_alerts: u32,
    pub total: u32,
}

#[derive(Debug, Serialize)]
pub struct PhishingAnalysis {
    pub likely_ai_generated: bool,
    pub score: f32,
    pub phishing_intent: bool,
    pub explanation: String,
}

// ── コマンド実装 ──────────────────────────────────────────────────────────────

#[instrument]
pub async fn health_check() -> Result<HealthResponse, String> {
    info!("health_check");
    Ok(HealthResponse {
        ok: true,
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

#[instrument]
/// 受信箱のサマリを返す。
///
/// 履歴 DB (`kaname-store`) に保存済みメールの件数を実集計する。
/// Store 未オープン・JMAP 未接続 (アカウント不明) なら 0 件 —
/// その場合ローカルに保存されたメールが存在しないので 0 が実態として正しい。
pub async fn mail_get_summary() -> Result<MailSummary, String> {
    // 履歴 DB が開いていてアカウントが特定できる場合は実数を返す。
    // 未接続 (Store 未オープン or JMAP 未接続) は空 = 0 件が実態として正しい。
    let account_id = current_account_id().await;
    if !account_id.is_empty() {
        if let Some(store) = store_slot().lock().await.clone() {
            let s = store
                .message_stats(&account_id)
                .await
                .map_err(|e| format!("サマリ集計に失敗しました: {e}"))?;
            return Ok(MailSummary {
                unread: s.unread,
                bec_alerts: s.bec_alerts,
                total: s.total,
            });
        }
    }
    Ok(MailSummary {
        unread: 0,
        bec_alerts: 0,
        total: 0,
    })
}

/// サニタイズ済み本文 (iframe 描画用)。
///
/// フロントエンド (`src/ui/Inbox.tsx` の `BodyDto`) が期待する形。
/// 従来このコマンドは生の `String` を返しており、フロントの型と**契約が
/// 一致していなかった** (`.srcdoc` / `.sandbox` へのアクセスが実行時に失敗する)。
#[derive(Debug, Serialize)]
pub struct BodyDto {
    /// `<iframe srcdoc="...">` にそのまま渡せる文字列。
    pub srcdoc: String,
    /// iframe の `sandbox` 属性値。
    pub sandbox: String,
    /// 併せて適用する CSP。
    pub csp: String,
    /// MLS で暗号化されたメールか。
    pub is_mls: bool,
    /// 本文に対するレンダリング系セキュリティ検出の結果 (人間可読)。
    ///
    /// `kaname-render` の各検出器 (HTML スマグリング / quishing / CSS
    /// exfiltration) は出荷バイナリに含まれていながら**一度も呼ばれて
    /// いなかった**ため、本文表示時に実行して結果をここへ載せる。
    pub render_risks: Vec<String>,
}

/// 受信箱のメール本文を取得する。
///
/// # サーバ未接続のため未実装
///
/// JMAP 受信が未配線 (D10) のため、受信箱には本物のメールが存在しない。
/// 従来はモックデータの preview をサニタイズして返していたが、
/// **実在しないメールの本文を表示するのは偽装**である。
///
/// サニタイズ経路自体は健在で、「ファイル解析」タブ (`mail_import_eml`) が
/// 実際の `.eml` に対して同じ `sanitize_html` → `to_srcdoc` を実行する。
/// サーバ上のメールを開き、**ローカル `.eml` と同じパイプライン**で解析する。
///
/// JMAP の `Email.blobId` は生 RFC 5322 全体を指す。これを `download_blob` で
/// 取得して `analyze_raw_email` に渡せば、本文サニタイズ・BEC スコア・
/// シグナル・添付検査・DLP・リンク評価がすべて得られる。
/// 「サーバのメールを開く」ために新しい解析コードは不要である。
pub async fn mail_open(email_id: String) -> Result<ImportedEmail, String> {
    let client = jmap_client().await?;
    let full = client
        .get_email_body(&email_id)
        .await
        .map_err(|e| format!("メールの取得に失敗しました: {e}"))?;
    let blob_id = full
        .blob_id
        .ok_or_else(|| "このメールには blobId がなく本文を取得できません".to_string())?;
    let bytes = client
        .download_blob(&blob_id, "message/rfc822", "message.eml")
        .await
        .map_err(|e| format!("メール本文の取得に失敗しました: {e}"))?;
    analyze_raw_email(&bytes).await
}

/// 受信トレイ UI 用のメールボックス行。
#[derive(Debug, serde::Serialize)]
pub struct MailboxRow {
    pub id: String,
    pub name: String,
    pub role: Option<String>,
    pub unread_emails: u32,
    pub total_emails: u32,
}

/// 接続中のサーバからメールボックス一覧を取得する。
pub async fn mail_get_mailboxes() -> Result<Vec<MailboxRow>, String> {
    let client = jmap_client().await?;
    let list = client
        .get_mailboxes()
        .await
        .map_err(|e| format!("メールボックス一覧の取得に失敗しました: {e}"))?;
    Ok(list
        .into_iter()
        .map(|m| MailboxRow {
            id: m.id,
            name: m.name,
            role: m.role,
            unread_emails: m.unread_emails,
            total_emails: m.total_emails,
        })
        .collect())
}

/// ローカルの `.eml` ファイルを解析した結果。
///
/// **本製品で初めて「実際のメール」がパイプラインを流れる経路**である。
#[derive(Debug, Serialize)]
pub struct ImportedEmail {
    /// 差出人 (表示名 + アドレス)。
    pub from: String,
    /// 件名。
    pub subject: String,
    /// 送信ドメイン認証の結果 (Authentication-Results ヘッダ由来)。
    pub auth: String,
    /// BEC 判定 (SAFE / ADVISORY / SUSPICIOUS / DANGEROUS)。
    pub bec_verdict: String,
    /// BEC スコア。
    pub bec_score: f32,
    /// 検出されたシグナルのラベル。
    pub bec_signals: Vec<String>,
    /// 添付ファイルの検査結果。
    ///
    /// 従来はファイル名の羅列のみで、`kaname-render` の添付検出器
    /// (MIME 偽装 / polyglot / 危険拡張子 / SVG スクリプト / メタデータ) は
    /// **一つも呼ばれていなかった**。`scan_attachments` で実際に検査する。
    pub attachments: Vec<kaname_render::AttachmentScan>,
    /// サニタイズ済み本文 (iframe 描画用)。
    pub body: BodyDto,
    /// 本文中に検出された機微情報 (DLP)。
    ///
    /// 受信メールに機微情報が含まれる場合、転送・返信時の漏洩リスクになる。
    /// `Direction::Inbound` で評価する。
    pub dlp_findings: Vec<String>,
    /// 帯域外検証 (OOBV) の推奨度。`OobvRecommender` の判定をそのまま返す。
    ///
    /// `oobv_recommend` コマンドは登録済みだったが呼び手がゼロだった
    /// (docs/gap-analysis.md D24)。本文を素のままフロントに渡して
    /// クライアント側で再計算させるより、既に本文を持っているここで
    /// 判定してしまう方が往復も本文の露出も増えない。
    pub oobv_level: String,
    /// 上記の人間可読メッセージ。
    ///
    /// `OobvRecommendResponse.message_i18n_key` に対応するカタログは
    /// 存在しない (kaname-i18n は 2026-09 に削除、
    /// docs/gap-analysis.md D19)。日本語の完成文をここで組み立てる。
    pub oobv_message: String,
    /// Deepfake (音声/動画添付 + 金融文脈) の警告判定。
    ///
    /// 添付一覧と本文はここで既に手元にあるため、解析経路で直接評価する
    /// (単独の `deepfake_evaluate` コマンドは呼び手ゼロのため E11 で削除済み)。
    pub deepfake_advisory: AdvisoryReport,
}

/// ローカルの `.eml` / `.mbox` ファイルを読み込み、**実際のメール**を
/// パイプライン全体に通す。
///
/// # なぜこれが重要か
///
/// 従来この製品には実メールの入口が存在せず、すべての検出器は
/// `mock_emails()` の固定データしか見ていなかった (D10)。JMAP サーバからの
/// 受信は `kaname-jmap` の配線が必要だが、**「メールはサーバから取得しな
/// ければならない」という要件自体を疑えば**、ローカルの `.eml` を開くだけで
/// 実メールを処理できる。ネットワークも認証情報も不要である。
///
/// 本コマンドは以下を実データで実行する:
/// 1. `kaname_render::parse()` による RFC 5322 / MIME 解析
/// 2. `Authentication-Results` ヘッダからの SPF/DKIM/DMARC 取り込み
/// 3. `BecDetector` による BEC 判定 (**実際の認証結果を使う**)
/// 4. `sanitize_html` → `to_srcdoc` によるサニタイズ
/// 5. レンダリング系検出器 (HTMLスマグリング / テキストQR / CSS外部参照)
pub async fn mail_import_eml(path: String) -> Result<ImportedEmail, String> {
    info!(path=%path, "mail_import_eml");

    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > MAX_EML_BYTES {
            return Err(format!(
                "ファイルが大きすぎます ({}MB > 50MB): {path}",
                meta.len() / (1024 * 1024)
            ));
        }
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("ファイルを読めません ({path}): {e}"))?;
    let imported = analyze_raw_email(&bytes).await?;
    audit_event(
        None,
        "MAIL_IMPORT",
        serde_json::json!({ "path": path, "verdict": imported.bec_verdict }),
    )
    .await;
    Ok(imported)
}

/// 生 RFC 5322 バイト列を直接解析する IPC コマンド。
///
/// オンボーディングのデモメールなど、ファイルパスを持たない入力を
/// `analyze_raw_email` に通すための経路。50MB 上限は `mail_import_eml`
/// と同じ。
#[instrument(skip(bytes))]
pub async fn mail_analyze_bytes(bytes: Vec<u8>) -> Result<ImportedEmail, String> {
    if bytes.len() > MAX_EML_BYTES as usize {
        return Err("メールが大きすぎます (50MB 超)".to_string());
    }
    analyze_raw_email(&bytes).await
}

/// 生 RFC 5322 バイト列を解析パイプライン全体に通す。
///
/// ローカル `.eml` (`mail_import_eml`)・サーバ上のメール (`mail_open`)・
/// デモ用バイト列 (`mail_analyze_bytes`) の**唯一の解析経路**。
/// 入口が複数あっても検出器は一つに集約する。
pub async fn analyze_raw_email(bytes: &[u8]) -> Result<ImportedEmail, String> {
    let env = kaname_render::parse(bytes).map_err(|e| format!("メールの解析に失敗: {e}"))?;

    // 差出人ヘッダを復元する。
    let from = env
        .from
        .first()
        .map(|a| match &a.display_name {
            Some(n) => format!("{n} <{}>", a.addr.as_string()),
            None => a.addr.as_string(),
        })
        .unwrap_or_default();

    let subject = env.subject.clone().unwrap_or_default();

    // 本文はプレーンテキストを優先し、無ければ空。
    // (HTML 本文は RawHtml のまま sanitize に渡すため別扱い)
    let body_text = env.text_body.clone().unwrap_or_default();

    // **実際の Authentication-Results をそのまま使う**。
    // モックでは None を渡していたが、ここでは実データが得られる。
    let auth = kaname_bec::AuthResults {
        spf: map_auth(env.auth_results.spf),
        dkim: map_auth(env.auth_results.dkim),
        dmarc: map_auth(env.auth_results.dmarc),
        arc: None,
    };
    let auth_desc = format!(
        "SPF={:?} DKIM={:?} DMARC={:?}",
        env.auth_results.spf, env.auth_results.dkim, env.auth_results.dmarc
    );

    // 本文からリンクを抽出し、bec の URL シグナルに供給する。
    // (従来は &[] を渡しており、実装済みの URL 評価が一度も発火していなかった)
    let urls = extract_urls_from_text(&body_text);

    // 自組織ドメイン (D44): 設定 `org_domain` → 接続中アカウントから導出。
    // 未設定・未接続なら空文字で、自己ドメインを前提とする検出は安全にスキップされる。
    let our = our_domain(&current_account_id().await, None).await;

    // 送信者の文体を評価する (アカウント乗っ取り検出)。
    // Date ヘッダから送信時刻 (UTC 時) を取り出す。無ければ評価しない。
    let send_hour = env
        .date
        .and_then(|ts| u8::try_from((ts.rem_euclid(86_400)) / 3_600).ok());
    let from_addr_only = env
        .from
        .first()
        .map(|a| a.addr.as_string())
        .unwrap_or_default();
    // 金銭要求の有無は BEC の判定材料と揃える (文体逸脱との複合で警告を上げる)。
    let has_financial = {
        // D45: 複数単語キーワード ("wire transfer") はゼロ幅文字を単語間に
        // 挿入されると削除版正規化では "wiretransfer" に結合されて
        // すり抜ける。スペース化版でも照合して捕捉する。
        let n = kaname_memory_guard::normalize_for_matching(&body_text);
        let n_spaced = kaname_memory_guard::normalize_for_matching_spaced(&body_text);
        [
            "振込",
            "送金",
            "支払",
            "invoice",
            "wire transfer",
            "payment",
        ]
        .iter()
        .any(|k| n.contains(k) || n_spaced.contains(k))
    };
    let style_risks =
        evaluate_sender_style(&from_addr_only, &body_text, send_hour, has_financial).await;

    // 連絡先ベースの詐称検出 (Reply-To 偽装・タイポスクワット) に使う。
    // Store 未接続の .eml 単体解析では空になり、そのシグナルはスキップされる。
    let contacts = lookup_contacts(&current_account_id().await).await;
    // Reply-To / Return-Path をヘッダ文字列として渡す (返信横取り検出)。
    let reply_to = env.reply_to.first().map(|a| match &a.display_name {
        Some(n) => format!("{n} <{}>", a.addr.as_string()),
        None => a.addr.as_string(),
    });
    let return_path = env.return_path.as_ref().map(|a| a.addr.as_string());
    // スレッド乗っ取り検出: In-Reply-To/References が指す既知メッセージを
    // Store から逆引きし、スレッド履歴を組み立てる。
    let account_id = current_account_id().await;
    let mut ref_ids = env.in_reply_to.clone();
    ref_ids.extend(env.references.iter().cloned());
    ref_ids.dedup();
    let (known_ids, thread_domains, prior_subject, prior_language, past_bodies) =
        build_thread_data(&account_id, None, &ref_ids).await;
    let current_domain = from_addr_only
        .rsplit('@')
        .next()
        .map(|d| d.to_lowercase())
        .unwrap_or_default();
    let body_snippet: String = body_text.chars().take(500).collect();
    let in_reply_to_first = env.in_reply_to.first();
    let thread_ctx = if known_ids.is_empty() && in_reply_to_first.is_none() {
        None
    } else {
        Some(kaname_bec::thread_hijack::ThreadContext {
            in_reply_to: in_reply_to_first.map(|s| s.as_str()),
            known_thread_message_ids: &known_ids,
            thread_sender_domains: &thread_domains,
            current_sender_domain: &current_domain,
            prior_subject: prior_subject.as_deref(),
            current_subject: &subject,
            prior_language,
            current_body_snippet: &body_snippet,
        })
    };
    let req = kaname_bec::AssessmentRequest {
        from_header: &from,
        return_path: return_path.as_deref(),
        subject: &subject,
        body_text: &body_text,
        auth,
        sender_history: None,
        our_domain: &our,
        known_contacts: &contacts,
        extracted_urls: &urls,
        reply_to: reply_to.as_deref(),
        thread_context: thread_ctx,
        past_thread_bodies: &past_bodies,
        dkim_signature_header: env.dkim_signature.as_deref(),
    };

    let assessment = kaname_bec::BecDetector::deterministic_only()
        .assess(req)
        .map_err(|e| format!("BEC 判定に失敗: {e}"))?;

    let oobv_level = kaname_oobv::OobvRecommender::new().recommend(&body_text);

    // 添付を一度だけ検査し、危険判定 (attachments フィールド) と
    // Deepfake 判定の両方に使い回す (filename/declared_mime だけで足りる)。
    let attachment_scans = kaname_render::scan_attachments(bytes);
    let deepfake_pairs: Vec<(String, String)> = attachment_scans
        .iter()
        .map(|a| (a.filename.clone(), a.declared_mime.clone()))
        .collect();
    let deepfake_advisory = DeepfakeAdvisory::new().evaluate(&deepfake_pairs, &body_text);

    let bec_verdict = match assessment.verdict {
        kaname_bec::Verdict::Safe => "SAFE",
        kaname_bec::Verdict::Advisory => "ADVISORY",
        kaname_bec::Verdict::Suspicious => "SUSPICIOUS",
        kaname_bec::Verdict::Dangerous => "DANGEROUS",
    }
    .to_string();

    // 本文をサニタイズする。HTML 本文があればそれを、無ければテキストを包む。
    let sanitized = match &env.html_body {
        Some(html) => kaname_render::sanitize_html(html),
        None => kaname_render::sanitize_html(&kaname_render::RawHtml::new(body_text.clone())),
    };
    let srcdoc = kaname_render::to_srcdoc(&sanitized, Some(&body_text));

    // 構造体にムーブする前に、from/subject を使う評価を先に済ませる。
    // 本文の構造リスクに加え、リンク先の評判判定も併記する。
    let mut render_risks = analyze_body_risks(&body_text);
    render_risks.extend(evaluate_link_risks(&urls));
    render_risks.extend(evaluate_saas_links(&urls, &from));
    render_risks.extend(style_risks);
    let dlp_findings = scan_dlp_inbound(&subject, &body_text, &our);

    Ok(ImportedEmail {
        from,
        subject,
        auth: auth_desc,
        bec_verdict,
        bec_score: assessment.score,
        bec_signals: assessment.signals.iter().map(|s| s.label.clone()).collect(),
        attachments: attachment_scans,
        body: BodyDto {
            srcdoc: srcdoc.content,
            sandbox: srcdoc.sandbox.to_string(),
            csp: srcdoc.csp.to_string(),
            is_mls: false,
            render_risks,
        },
        dlp_findings,
        oobv_level: match oobv_level {
            kaname_oobv::RecommendationLevel::None => "none",
            kaname_oobv::RecommendationLevel::Optional => "optional",
            kaname_oobv::RecommendationLevel::Strong => "strong",
        }
        .to_string(),
        oobv_message: match oobv_level {
            kaname_oobv::RecommendationLevel::None => String::new(),
            kaname_oobv::RecommendationLevel::Optional => {
                "念のため、電話や別の連絡手段で送信者に確認することをお勧めします。".to_string()
            }
            kaname_oobv::RecommendationLevel::Strong => {
                "送金・認証情報・重要な意思決定に関わる内容です。返信の前に、\
                 電話などメール以外の手段で送信者に必ず確認してください。"
                    .to_string()
            }
        },
        deepfake_advisory,
    })
}

/// 受信メール本文の機微情報を DLP で検出する。
///
/// # なぜ受信側でも検出するか
///
/// DLP は本来「送信時の情報漏洩を防ぐ」機能だが、**受信メールに機微情報が
/// 含まれている事実自体が重要な情報**である。そのまま転送・返信すれば
/// 漏洩に直結するため、解析時点で利用者に知らせる価値がある。
/// `Direction::Inbound` はまさにこの用途のために用意されている。
///
/// 送信経路 (`mail_send`) は未配線 (D10) のため、現時点で DLP を活かせる
/// のは受信側の解析のみである。
fn scan_dlp_inbound(subject: &str, body: &str, our_domain: &str) -> Vec<String> {
    let engine = kaname_dlp::DlpEngine::default_engine();
    let recipients: Vec<String> = Vec::new();
    let mimes: Vec<String> = Vec::new();
    let domains: Vec<String> = Vec::new();
    let edm: std::collections::HashMap<String, kaname_dlp::edm::EdmFingerprints> =
        std::collections::HashMap::new();

    let ctx = kaname_dlp::EvalCtx {
        body,
        subject,
        size_bytes: body.len() as u64,
        to: &recipients,
        from: "",
        attachment_mimes: &mimes,
        edm_sets: &edm,
        known_recipient_domains: &domains,
        our_domain,
    };

    let result = engine.evaluate(&ctx, kaname_dlp::Direction::Inbound);
    result
        .findings
        .iter()
        .map(|f| format!("{} ({:?})", f.rule_name, f.action))
        .collect()
}

/// フォルダ一括解析の結果。
#[derive(Debug, Serialize)]
pub struct FolderScanResult {
    /// 解析できたメール件数。
    pub analyzed: usize,
    /// 解析に失敗したファイル (パス, 理由)。握り潰さず返す。
    pub failed: Vec<(String, String)>,
    /// 判定ごとの件数 (SAFE / ADVISORY / SUSPICIOUS / DANGEROUS)。
    pub verdict_counts: Vec<(String, usize)>,
    /// 危険度の高い順に並べたメール一覧。
    pub emails: Vec<FolderScanEntry>,
    /// 複数メールを横断して検出されたキャンペーン。
    pub campaigns: Vec<CampaignSummary>,
}

/// フォルダ一括解析における 1 通分の結果。
#[derive(Debug, Serialize)]
pub struct FolderScanEntry {
    /// 元ファイル名。
    pub file: String,
    /// 差出人。
    pub from: String,
    /// 件名。
    pub subject: String,
    /// BEC 判定。
    pub verdict: String,
    /// BEC スコア。
    pub score: f32,
    /// 本文中に検出された機微情報 (DLP) の件数。
    pub dlp_count: usize,
    /// 危険と判定された添付ファイルの件数。
    pub attachment_risk_count: usize,
}

/// 検出されたキャンペーンの要約。
#[derive(Debug, Serialize)]
pub struct CampaignSummary {
    /// 共有インフラ (グルーピングの根拠)。
    pub shared_infrastructure: String,
    /// 所属メール数。
    pub email_count: usize,
    /// 脅威スコア。
    pub threat_score: f32,
}

/// フォルダ内の `.eml` を一括解析し、**複数メールを横断したキャンペーン検出**も行う。
///
/// # なぜ一括解析が必要か
///
/// `kaname-radar` (PCR: ポリモーフィック・キャンペーン検出) は
/// **複数のメールを見比べて初めて意味を持つ**検出器であり、1 通ずつの解析では
/// 動かせない。そのため出荷バイナリから到達不能なまま放置されていた。
/// フォルダ一括解析はこの検出器を実際に動かす唯一の現実的な入口である。
///
/// メールボックスのエクスポート (`.eml` の集合) を丸ごと投入して
/// トリアージする、という実運用にも合致する。
pub async fn mail_scan_folder(path: String) -> Result<FolderScanResult, String> {
    info!(path=%path, "mail_scan_folder");

    let dir =
        std::fs::read_dir(&path).map_err(|e| format!("フォルダを開けません ({path}): {e}"))?;

    let mut entries: Vec<FolderScanEntry> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut radar = kaname_radar::CampaignRadar::new();
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    // 自組織ドメイン (D44) は走査全体で1回だけ解決する。
    let our = our_domain(&current_account_id().await, None).await;

    for item in dir {
        let Ok(item) = item else { continue };
        let p = item.path();
        // .eml のみを対象にする (拡張子の大小は問わない)。
        let is_eml = p
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("eml"));
        if !is_eml {
            continue;
        }
        let file_name = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();

        let bytes = match std::fs::metadata(&p) {
            Ok(m) if m.len() > MAX_EML_BYTES => {
                failed.push((file_name, "ファイルが大きすぎます (50MB 超)".to_string()));
                continue;
            }
            _ => match std::fs::read(&p) {
                Ok(b) => b,
                Err(e) => {
                    failed.push((file_name, format!("読み込み失敗: {e}")));
                    continue;
                }
            },
        };
        let env = match kaname_render::parse(&bytes) {
            Ok(e) => e,
            Err(e) => {
                failed.push((file_name, format!("解析失敗: {e}")));
                continue;
            }
        };

        let from = env
            .from
            .first()
            .map(|a| a.addr.as_string())
            .unwrap_or_default();
        let from_domain = env
            .from
            .first()
            .map(|a| a.addr.domain.clone())
            .unwrap_or_default();
        let subject = env.subject.clone().unwrap_or_default();
        let body_text = env.text_body.clone().unwrap_or_default();

        let auth = kaname_bec::AuthResults {
            spf: map_auth(env.auth_results.spf),
            dkim: map_auth(env.auth_results.dkim),
            dmarc: map_auth(env.auth_results.dmarc),
            arc: None,
        };
        // 認証のいずれかが失敗していれば radar に伝える。
        let auth_partial_fail = matches!(
            (
                env.auth_results.spf,
                env.auth_results.dkim,
                env.auth_results.dmarc
            ),
            (kaname_render::AuthResult::Fail, _, _)
                | (_, kaname_render::AuthResult::Fail, _)
                | (_, _, kaname_render::AuthResult::Fail)
        );

        // 本文からリンクを抽出し、bec の URL シグナルとキャンペーン相関に供給する。
        let urls = extract_urls_from_text(&body_text);
        let link_domains: Vec<String> = urls.iter().filter_map(|u| url_host(u)).collect();

        let contacts = lookup_contacts(&current_account_id().await).await;
        let reply_to = env.reply_to.first().map(|a| a.addr.as_string());
        let return_path = env.return_path.as_ref().map(|a| a.addr.as_string());
        // スレッド乗っ取り検出: In-Reply-To/References が指す既知メッセージを
        // Store から逆引きし、スレッド履歴を組み立てる。
        let account_id = current_account_id().await;
        let mut ref_ids = env.in_reply_to.clone();
        ref_ids.extend(env.references.iter().cloned());
        ref_ids.dedup();
        let (known_ids, thread_domains, prior_subject, prior_language, past_bodies) =
            build_thread_data(&account_id, None, &ref_ids).await;
        let current_domain = from_domain.to_lowercase();
        let body_snippet: String = body_text.chars().take(500).collect();
        let in_reply_to_first = env.in_reply_to.first();
        let thread_ctx = if known_ids.is_empty() && in_reply_to_first.is_none() {
            None
        } else {
            Some(kaname_bec::thread_hijack::ThreadContext {
                in_reply_to: in_reply_to_first.map(|s| s.as_str()),
                known_thread_message_ids: &known_ids,
                thread_sender_domains: &thread_domains,
                current_sender_domain: &current_domain,
                prior_subject: prior_subject.as_deref(),
                current_subject: &subject,
                prior_language,
                current_body_snippet: &body_snippet,
            })
        };
        let req = kaname_bec::AssessmentRequest {
            from_header: &from,
            return_path: return_path.as_deref(),
            subject: &subject,
            body_text: &body_text,
            auth,
            sender_history: None,
            our_domain: &our,
            known_contacts: &contacts,
            extracted_urls: &urls,
            reply_to: reply_to.as_deref(),
            thread_context: thread_ctx,
            past_thread_bodies: &past_bodies,
            dkim_signature_header: env.dkim_signature.as_deref(),
        };

        let (verdict, score) = match kaname_bec::BecDetector::deterministic_only().assess(req) {
            Ok(a) => {
                let v = match a.verdict {
                    kaname_bec::Verdict::Safe => "SAFE",
                    kaname_bec::Verdict::Advisory => "ADVISORY",
                    kaname_bec::Verdict::Suspicious => "SUSPICIOUS",
                    kaname_bec::Verdict::Dangerous => "DANGEROUS",
                };
                (v.to_string(), a.score)
            }
            // 判定できなかったことを SAFE と偽らない。
            Err(e) => {
                failed.push((file_name.clone(), format!("BEC 判定失敗: {e}")));
                ("UNKNOWN".to_string(), 0.0)
            }
        };
        *counts.entry(verdict.clone()).or_insert(0) += 1;

        // キャンペーン検出へ投入する。
        let meta = kaname_radar::EmailMetadata {
            email_id: file_name.clone(),
            from_domain,
            return_path_domain: None,
            dkim_domain: None,
            link_domains,
            received_at: env.date.unwrap_or(0).max(0) as u64,
            subject_length_bucket: kaname_radar::SubjectLengthBucket::from_subject(&subject),
            auth_partial_fail,
        };
        let _ = radar.analyze(&meta);

        // 機微情報 (DLP) は件数のみ一覧に載せる (詳細は単体解析で確認する)。
        let dlp_count = scan_dlp_inbound(&subject, &body_text, &our).len();
        // 添付検査 (危険と判定された件数のみ一覧に載せる)。
        let attachment_risk_count = kaname_render::scan_attachments(&bytes)
            .iter()
            .filter(|a| a.is_dangerous)
            .count();

        entries.push(FolderScanEntry {
            file: file_name,
            from,
            subject,
            verdict,
            score,
            dlp_count,
            attachment_risk_count,
        });
    }

    // 危険度の高い順に並べる (トリアージのため)。
    entries.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let campaigns = radar
        .alertable_groups()
        .into_iter()
        .map(|g| CampaignSummary {
            shared_infrastructure: g.shared_infrastructure.clone(),
            email_count: g.email_ids.len(),
            threat_score: g.threat_score,
        })
        .collect();

    audit_event(
        None,
        "FOLDER_SCAN",
        serde_json::json!({
            "path": path,
            "analyzed": entries.len(),
            "failed": failed.len(),
        }),
    )
    .await;
    Ok(FolderScanResult {
        analyzed: entries.len(),
        failed,
        verdict_counts: counts.into_iter().collect(),
        emails: entries,
        campaigns,
    })
}

/// `kaname-render` の認証結果を `kaname-bec` の判定型へ写す。
///
/// `SoftFail` は「失敗寄りだが確定ではない」ため `Neutral` に写す
/// (`Fail` に倒すと過検出、`Pass` に倒すと危険側の見逃しになる)。
/// 本文から http/https の URL を抽出する。
///
/// # なぜこの関数が必要か
///
/// `kaname-bec` は URL 評価シグナル (フリーホスティング/危険 TLD 等) を
/// 実装済みで、`kaname-render::quishing::evaluate_url` も悪性ドメイン・
/// 短縮 URL・タイポスクワットを判定できる。しかし**本文から URL を取り出す
/// 関数がワークスペースに存在しなかった**ため、これらの実装済みシグナルは
/// 実データで一度も発火していなかった (`extracted_urls: &[]` を渡していた)。
///
/// XML/HTML パーサは使わず、他モジュールと同じ文字列走査方針を取る。
/// 上限 20 件は `kaname-bec` 側の MAX_URLS と整合させている。
fn extract_urls_from_text(text: &str) -> Vec<String> {
    const MAX_URLS: usize = 20;
    let mut out: Vec<String> = Vec::new();
    for token in
        text.split(|c: char| c.is_whitespace() || c == '<' || c == '>' || c == '"' || c == '\'')
    {
        let lower = token.to_ascii_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://")) {
            continue;
        }
        // 末尾に付きがちな句読点・括弧を落とす
        let trimmed = token.trim_end_matches(['.', ',', ')', ';', ']', '!', '?']);
        if trimmed.len() < 12 {
            // "http://a.b" 未満は URL として意味を成さない
            continue;
        }
        if !out.iter().any(|u| u == trimmed) {
            out.push(trimmed.to_string());
        }
        if out.len() >= MAX_URLS {
            break;
        }
    }
    out
}

/// URL のホスト部を取り出す (`https://host/path` → `host`)。
///
/// キャンペーン相関 (`EmailMetadata.link_domains`) 用の簡易抽出。
/// userinfo (`user@host`) やポートは落とす。
fn url_host(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let host_port = rest.split(['/', '?', '#']).next()?;
    // userinfo 混乱攻撃 (https://trusted.com@evil.com/) 対策: 最後の '@' 以降を採る
    let host = host_port.rsplit('@').next()?;
    let host = host.split(':').next()?.trim().to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// 本文に対してレンダリング系の検出器を実行し、人間可読なリスク一覧を返す。
///
/// `kaname-render` は既に `kaname-ui` の依存に入っており各検出器も実装済み
/// だが、**commands.rs から一度も呼ばれていなかった** (9 モジュールが
/// 到達可能なまま未使用)。ここで実際に実行する。
///
/// サニタイズ自体は `sanitize_html` が別途行う。本関数は「サニタイズでは
/// 落とせないが利用者に伝えるべき兆候」を報告する役割を持つ。
fn analyze_body_risks(body: &str) -> Vec<String> {
    let mut risks = Vec::new();

    // 0. トラッキングピクセル (README が「デフォルトでブロック」と謳う機能)。
    //    kaname-privacy は実装済みだが commands.rs から呼ばれていなかった。
    //    sanitize_html が実際の読み込みを止めるため、ここでは
    //    「何が仕込まれていたか」を利用者に伝える役割を持つ。
    let tracking = kaname_privacy::TrackingDetector::new().analyze_html(body);
    if tracking.was_tracked {
        let domains = if tracking.blocked_domains.is_empty() {
            String::new()
        } else {
            format!(" ({})", tracking.blocked_domains.join(", "))
        };
        risks.push(format!(
            "トラッキングピクセルを {} 件検出し読み込みを防ぎました{domains}。",
            tracking.tracker_count
        ));
    }

    // 1. HTML スマグリング (blob:/atob()/mshta 等による添付の密輸)
    let smuggling = kaname_render::html_smuggling::HtmlSmugglingDetector.analyze(body);
    if !matches!(
        smuggling.risk,
        kaname_render::html_smuggling::SmugglingRisk::Clean
    ) {
        risks.push(format!("HTMLスマグリングの疑い: {}", smuggling.message));
    }

    // 2. テキストで描かれた QR コード (画像スキャンを回避する quishing)
    let quishing = kaname_render::quishing::QuishingDefense::new();
    if quishing.detect_ascii_qr(body) {
        risks.push(
            "本文にテキストで描かれた QR コードがあります。\
             画像スキャンを回避する quishing の可能性があります。"
                .to_string(),
        );
    }

    // 3. CSS 外部参照 (EchoLeak 型の情報流出)
    let css = kaname_render::css_sanitizer::sanitize_css(body);
    if css.removed_count > 0 {
        risks.push(format!(
            "CSS の外部リソース参照を {} 件無効化しました (情報流出の防止)。",
            css.removed_count
        ));
    }

    risks
}

/// 本文リンクの SaaS 安全性を判定する。
///
/// `kaname-saas-guard` は偽 SaaS ドメイン (`notdocusign.com` 等)・
/// SaaS リンク経由のプロンプト注入・OAuth state 検証を実装済みだが、
/// **commands.rs から呼ばれておらず到達不能だった** (孤島クレート D13)。
/// 本文リンクは既に抽出しているため、そこへ載せる。
///
/// `SaasHistory` は 1 通の解析ごとに新規作成する。履歴を跨いだ学習
/// (この送信者から普段どの SaaS が来るか) は送信者履歴の永続化と同様に
/// Store 側の対応が要るため、現時点では単発評価に留める。
fn evaluate_saas_links(urls: &[String], sender: &str) -> Vec<String> {
    let inspector = kaname_saas_guard::SaasLinkInspector::new();
    let history = kaname_saas_guard::SaasHistory::new();
    let mut out = Vec::new();
    for url in urls {
        let Some(link) = inspector.evaluate(url, sender, &history) else {
            continue;
        };
        // Safe/Caution は通常の SaaS 通知でも出るため報告しない。
        // Warn 以上のみ利用者に伝える (警告疲れを避ける)。
        if matches!(
            link.risk,
            kaname_saas_guard::SaasLinkRisk::Warn
                | kaname_saas_guard::SaasLinkRisk::Suspicious
                | kaname_saas_guard::SaasLinkRisk::Block
        ) {
            out.push(format!(
                "SaaS リンクのリスク ({:?}): {} — {}",
                link.risk,
                link.url,
                link.reasons.join(" / ")
            ));
        }
    }
    out
}

/// 本文中のリンクを `quishing::evaluate_url` で判定し、人間可読の警告を返す。
///
/// QR 用に実装された評価器 (悪性ドメイン/短縮 URL/自由 TLD/タイポスクワット/
/// ブランド・サブドメイン偽装) を、本文リンクにもそのまま適用する。
fn evaluate_link_risks(urls: &[String]) -> Vec<String> {
    let defense = kaname_render::quishing::QuishingDefense::new();
    let mut risks = Vec::new();
    for url in urls {
        match defense.evaluate_url(url) {
            kaname_render::quishing::UrlReputation::Malicious => {
                risks.push(format!("リンク先が既知の悪性ドメインです: {url}"));
            }
            kaname_render::quishing::UrlReputation::Suspicious => {
                risks.push(format!(
                    "リンク先が疑わしいドメインです (短縮URL/自由TLD/タイポスクワット等): {url}"
                ));
            }
            kaname_render::quishing::UrlReputation::Trusted
            | kaname_render::quishing::UrlReputation::Neutral => {}
        }
    }
    risks
}

fn map_auth(r: kaname_render::AuthResult) -> kaname_bec::AuthVerdict {
    match r {
        kaname_render::AuthResult::Pass => kaname_bec::AuthVerdict::Pass,
        kaname_render::AuthResult::Fail => kaname_bec::AuthVerdict::Fail,
        kaname_render::AuthResult::Neutral => kaname_bec::AuthVerdict::Neutral,
        kaname_render::AuthResult::SoftFail => kaname_bec::AuthVerdict::Neutral,
        kaname_render::AuthResult::None => kaname_bec::AuthVerdict::None,
    }
}

/// 本文に対してレンダリング系の検出器を実行し、人間可読なリスク一覧を返す。
///
/// `kaname-render` は既に `kaname-ui` の依存に入っており各検出器も実装済み
/// だが、**commands.rs から一度も呼ばれていなかった** (9 モジュールが
/// 到達可能なまま未使用)。ここで実際に実行する。
///
/// サニタイズ自体は `sanitize_html` が別途行う。本関数は「サニタイズでは
/// 受信箱のメールにフィッシング解析を行う。
///
/// # サーバ未接続のため未実装
///
/// 受信箱に本物のメールが存在しないため解析対象がない。
/// 実際の BEC 判定は「ファイル解析」タブ (`mail_import_eml` /
/// `mail_scan_folder`) が `.eml` に対して実行する。
pub async fn ai_detect_phishing(email_id: String) -> Result<PhishingAnalysis, String> {
    let _ = email_id;
    Err("未配線: 受信箱はサーバに接続されていません。\
         実際のメールを解析するには「ファイル解析」タブをご利用ください"
        .to_string())
}

pub async fn log_error(message: String) -> Result<(), String> {
    error!(source = "frontend", %message);
    Ok(())
}

// ── モックデータ ──────────────────────────────────────────────────────────────

// ── テスト ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_returns_ok() -> Result<(), String> {
        let r = health_check().await.map_err(|e| e.to_string())?;
        assert!(r.ok);
        assert!(!r.version.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn summary_has_counts() -> Result<(), String> {
        let r = mail_get_summary().await.map_err(|e| e.to_string())?;
        assert!(r.unread <= r.total);
        Ok(())
    }

    #[tokio::test]
    async fn phishing_未接続時はエラーを返す() {
        // 偽データ経路削除後の正直な契約: 未配線の ai_detect_phishing は
        // パニックせず Err を返す (I5/I6: 未接続を silent にしない)。
        assert!(ai_detect_phishing("e1".into()).await.is_err());
    }

    #[tokio::test]
    async fn log_error_ok() {
        assert!(log_error("test".into()).await.is_ok());
    }

    // ── analyze_raw_email: mail_import_eml / mail_open 共通の解析経路 ──
    //
    // これまで一度もテストされていなかった (docs/gap-analysis.md の
    // static-check 強化 (D25) で発覚)。実データ (.eml バイト列) を渡して
    // BEC/OOBV/Deepfake/DLP/添付検査が実際に配線されていることを検証する。

    const SAFE_EML: &[u8] = b"From: alice@example.com\r\n\
        To: bob@example.com\r\n\
        Subject: Team lunch tomorrow\r\n\
        Date: Mon, 26 Apr 2026 10:00:00 +0900\r\n\
        Content-Type: text/plain; charset=utf-8\r\n\
        \r\n\
        Let's grab lunch tomorrow at noon.\r\n";

    const BEC_WIRE_EML: &[u8] = b"From: \"CEO\" <ceo@arnazon-billing.com>\r\n\
        To: you@example.com\r\n\
        Subject: URGENT wire transfer needed today\r\n\
        Date: Mon, 26 Apr 2026 10:15:00 +0900\r\n\
        Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=arnazon-billing.com; dkim=fail header.d=arnazon-billing.com; dmarc=fail header.from=arnazon-billing.com\r\n\
        Reply-To: ceo.private@gmail.com\r\n\
        Content-Type: text/plain; charset=utf-8\r\n\
        \r\n\
        I need you to process an urgent wire transfer immediately.\r\n\
        Our bank account has changed. Please send the payment today.\r\n\
        Do not discuss this with anyone. Confirm once complete.\r\n";

    #[tokio::test]
    async fn analyze_raw_email_safe_message_is_quiet() -> Result<(), String> {
        let r = analyze_raw_email(SAFE_EML).await?;
        assert_eq!(r.bec_verdict, "SAFE");
        assert_eq!(
            r.oobv_level, "none",
            "金融/緊急性の無い本文で OOBV を推奨してはいけない"
        );
        assert!(r.oobv_message.is_empty());
        assert_eq!(
            r.deepfake_advisory.severity,
            kaname_render::deepfake_advisory::AdvisorySeverity::None
        );
        assert!(r.attachments.is_empty());
        assert!(r.dlp_findings.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn analyze_raw_email_bec_wire_transfer_triggers_oobv() -> Result<(), String> {
        let r = analyze_raw_email(BEC_WIRE_EML).await?;
        assert_ne!(
            r.bec_verdict, "SAFE",
            "SPF/DKIM/DMARC 全滅 + 金融文脈は SAFE であってはならない"
        );
        assert!(!r.bec_signals.is_empty());
        assert_eq!(
            r.oobv_level, "strong",
            "送金要求 + 緊急性は OOBV を強く推奨すべき"
        );
        assert!(
            r.oobv_message.contains("電話"),
            "推奨理由が人間可読でなければならない"
        );
        Ok(())
    }

    #[tokio::test]
    async fn analyze_raw_email_deepfake_high_severity_for_financial_media_attachment(
    ) -> Result<(), String> {
        // 音声添付 + 金融/緊急性のある本文 → Deepfake 警告は High になるべき。
        let raw: &[u8] = b"From: cfo@example.com\r\n\
            To: you@example.com\r\n\
            Subject: Urgent voice message about payment\r\n\
            Date: Mon, 26 Apr 2026 10:00:00 +0900\r\n\
            Content-Type: multipart/mixed; boundary=\"b1\"\r\n\
            \r\n\
            --b1\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            Please listen to the attached urgent voice message about the wire payment.\r\n\
            --b1\r\n\
            Content-Type: audio/mpeg\r\n\
            Content-Disposition: attachment; filename=\"message.mp3\"\r\n\
            \r\n\
            fake-audio-bytes\r\n\
            --b1--\r\n";
        let r = analyze_raw_email(raw).await?;
        assert_eq!(
            r.deepfake_advisory.severity,
            kaname_render::deepfake_advisory::AdvisorySeverity::High,
            "音声添付 + 金融/緊急性の本文は High 警戒であるべき"
        );
        assert!(!r.deepfake_advisory.affected_attachments.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn analyze_raw_email_dangerous_attachment_is_flagged() -> Result<(), String> {
        // 二重拡張子 (.pdf.lnk) は危険拡張子として検出されるべき。
        let raw: &[u8] = b"From: alice@example.com\r\n\
            To: bob@example.com\r\n\
            Subject: Invoice attached\r\n\
            Date: Mon, 26 Apr 2026 10:00:00 +0900\r\n\
            Content-Type: multipart/mixed; boundary=\"b1\"\r\n\
            \r\n\
            --b1\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            See attached invoice.\r\n\
            --b1\r\n\
            Content-Type: application/octet-stream\r\n\
            Content-Disposition: attachment; filename=\"invoice.pdf.lnk\"\r\n\
            \r\n\
            fake-bytes\r\n\
            --b1--\r\n";
        let r = analyze_raw_email(raw).await?;
        assert!(
            r.attachments.iter().any(|a| a.is_dangerous),
            "二重拡張子の添付は危険と判定されるべき"
        );
        Ok(())
    }
}

// ============================================================================
// 新機能 v0.2 - 2026 年最新脅威対応コマンド群
// ============================================================================

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use kaname_oobv::{
    AuditRecord, CeremonyError, CeremonyState, OobvRecommender, RecommendationLevel,
    VerificationCeremony,
};
use kaname_render::deepfake_advisory::DeepfakeAdvisory;
// src-tauri 側のコマンドラッパーが戻り値型として名前を書けるよう再エクスポートする
// (src-tauri は kaname-render に直接依存していないため)。
pub use kaname_render::deepfake_advisory::AdvisoryReport;
// src-tauri 側のコマンドラッパーが戻り値型として名前を書けるよう再エクスポートする
// (src-tauri は kaname-store に直接依存していないため)。
pub use kaname_store::StoredMessage;

/// 新機能用の共有状態。
pub struct V02AppState {
    pub ceremonies: Mutex<HashMap<String, VerificationCeremony>>,
    pub audit_log: Mutex<Vec<AuditRecord>>,
}

impl V02AppState {
    /// 新規インスタンスを作成する。
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ceremonies: Mutex::new(HashMap::new()),
            audit_log: Mutex::new(Vec::new()),
        })
    }
}

// ── #1 OOBV ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct OobvStartRequest {
    pub email_id: String,
    pub sender: String,
}

#[derive(Debug, Serialize)]
pub struct OobvStartResponse {
    pub ceremony_id: String,
    pub phrase: Vec<String>,
    pub challenge_number: u8,
    pub expires_at_unix: u64,
}

/// OOBV を開始する。
pub async fn oobv_start(
    state: Arc<V02AppState>,
    req: OobvStartRequest,
) -> Result<OobvStartResponse, V02CommandError> {
    let ceremony = VerificationCeremony::new(&req.email_id, &req.sender);
    let response = OobvStartResponse {
        ceremony_id: ceremony.id.clone(),
        phrase: ceremony
            .display_phrase()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        challenge_number: ceremony.challenge_number(),
        expires_at_unix: ceremony.expires_at_unix,
    };
    state
        .ceremonies
        .lock()
        .await
        .insert(ceremony.id.clone(), ceremony);
    Ok(response)
}

#[derive(Debug, Deserialize)]
pub struct OobvVerifyRequest {
    pub ceremony_id: String,
    pub user_word: String,
}

#[derive(Debug, Serialize)]
pub struct OobvVerifyResponse {
    pub state: CeremonyState,
    pub message_i18n_key: String,
}

/// OOBV を検証する。
pub async fn oobv_verify(
    state: Arc<V02AppState>,
    req: OobvVerifyRequest,
) -> Result<OobvVerifyResponse, V02CommandError> {
    let mut ceremonies = state.ceremonies.lock().await;
    let ceremony = ceremonies
        .get_mut(&req.ceremony_id)
        .ok_or_else(|| V02CommandError::NotFound("セレモニーが見つかりません".into()))?;

    let result = ceremony
        .verify(&req.user_word)
        .map_err(V02CommandError::from)?;
    let audit = ceremony.audit_record();
    drop(ceremonies);

    state.audit_log.lock().await.push(audit);

    let key = match result {
        CeremonyState::Verified => "oobv.result.verified",
        CeremonyState::Mismatch => "oobv.result.mismatch",
        CeremonyState::Expired => "oobv.result.expired",
        CeremonyState::Pending => "oobv.result.pending",
        CeremonyState::Locked => "oobv.result.locked",
    };
    Ok(OobvVerifyResponse {
        state: result,
        message_i18n_key: key.into(),
    })
}

#[derive(Debug, Deserialize)]
pub struct OobvRecommendRequest {
    pub email_body: String,
}

#[derive(Debug, Serialize)]
pub struct OobvRecommendResponse {
    pub level: RecommendationLevel,
    pub message_i18n_key: String,
}

/// メール本文から OOBV 必要性を判定。
pub async fn oobv_recommend(
    req: OobvRecommendRequest,
) -> Result<OobvRecommendResponse, V02CommandError> {
    let level = OobvRecommender::new().recommend(&req.email_body);
    let key = match level {
        RecommendationLevel::None => "oobv.recommend.none",
        RecommendationLevel::Optional => "oobv.recommend.optional",
        RecommendationLevel::Strong => "oobv.recommend.strong",
    };
    Ok(OobvRecommendResponse {
        level,
        message_i18n_key: key.into(),
    })
}

// ── エラー ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, Serialize)]
pub enum V02CommandError {
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

impl From<CeremonyError> for V02CommandError {
    fn from(e: CeremonyError) -> Self {
        match e {
            CeremonyError::Expired => Self::InvalidState("expired".into()),
            CeremonyError::AlreadyCompleted(_) => Self::InvalidState("already_completed".into()),
            CeremonyError::TooManyAttempts => Self::InvalidState("locked".into()),
        }
    }
}

#[cfg(test)]
mod v02_tests {
    use super::*;

    #[tokio::test]
    async fn oobv_start_creates_ceremony() -> Result<(), String> {
        let state = V02AppState::new();
        let resp = oobv_start(
            state.clone(),
            OobvStartRequest {
                email_id: "e1".into(),
                sender: "a@b.com".into(),
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        assert_eq!(resp.phrase.len(), 6);
        assert!((1..=6).contains(&resp.challenge_number));
        Ok(())
    }

    #[tokio::test]
    async fn oobv_verify_correct_word() -> Result<(), String> {
        let state = V02AppState::new();
        let start = oobv_start(
            state.clone(),
            OobvStartRequest {
                email_id: "e1".into(),
                sender: "a@b.com".into(),
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        let correct = start.phrase[(start.challenge_number - 1) as usize].clone();
        let resp = oobv_verify(
            state,
            OobvVerifyRequest {
                ceremony_id: start.ceremony_id,
                user_word: correct,
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        assert_eq!(resp.state, CeremonyState::Verified);
        Ok(())
    }

    #[tokio::test]
    async fn oobv_recommend_strong() -> Result<(), String> {
        let resp = oobv_recommend(OobvRecommendRequest {
            email_body: "至急振込先変更".into(),
        })
        .await
        .map_err(|e| e.to_string())?;
        assert_eq!(resp.level, RecommendationLevel::Strong);
        Ok(())
    }
}

// ============================================================================
// JMAP サーバとの実接続 (受信・送信)
//
// 従来この製品は kaname-jmap に依存すらしておらず、出荷バイナリから
// サーバへ到達する経路がコンパイル時点で存在しなかった (gap-analysis D10)。
// kaname-jmap 自体は RFC 8621 準拠の実装が揃っていたため、
// **配線するコードを書くだけ**で受信・送信が動くようになる。
// ============================================================================

/// 接続中の JMAP セッション。
///
/// # 認証情報を永続化しない理由
///
/// Bearer トークンはプロセスのメモリ内にのみ保持し、ディスクへは書かない。
/// `kaname-store` の SQLCipher 鍵管理は現状 keyfile へのフォールバックを
/// 含んでおり (docs/maturity.md)、トークンを平文同然で置く危険がある。
/// **安全に保管できないものは保管しない**方針を採り、起動のたびに
/// 接続し直す。OS キーチェーン統合が入ったら永続化を検討する。
static JMAP_SESSION: std::sync::OnceLock<
    tokio::sync::Mutex<Option<std::sync::Arc<kaname_jmap::JmapClient>>>,
> = std::sync::OnceLock::new();

fn jmap_slot() -> &'static tokio::sync::Mutex<Option<std::sync::Arc<kaname_jmap::JmapClient>>> {
    JMAP_SESSION.get_or_init(|| tokio::sync::Mutex::new(None))
}

/// 接続済みクライアントを取り出す。未接続なら分かりやすいエラーを返す。
async fn jmap_client() -> Result<std::sync::Arc<kaname_jmap::JmapClient>, String> {
    jmap_slot()
        .lock()
        .await
        .clone()
        .ok_or_else(|| "未接続: 先に「アカウント接続」でサーバへ接続してください".to_string())
}

/// 接続結果。
#[derive(Debug, Serialize)]
pub struct ConnectResult {
    /// JMAP のアカウント ID。
    pub account_id: String,
    /// メールボックス一覧 (id, 名前, 未読数)。
    pub mailboxes: Vec<(String, String, u32)>,
    /// セッションから導出した組織ドメイン (D44)。取得できなければ None。
    pub org_domain: Option<String>,
}

/// JMAP サーバへ接続し、メールボックス一覧を取得する。
///
/// `base_url` は JMAP セッションリソース (例: `https://mail.example.com`)。
/// `token` は Bearer トークン。**メモリ内にのみ保持し永続化しない**。
pub async fn mail_connect(base_url: String, token: String) -> Result<ConnectResult, String> {
    // トークンはログに出さない (PII/認証情報の漏洩防止)。
    info!(base_url=%base_url, "mail_connect");

    let config = kaname_jmap::ClientConfig {
        bearer_token: token,
        connect_timeout: std::time::Duration::from_secs(10),
        request_timeout: std::time::Duration::from_secs(30),
        max_retries: 2,
        user_agent: concat!("Kaname/", env!("CARGO_PKG_VERSION")).to_string(),
    };

    let client = kaname_jmap::JmapClient::connect(&base_url, config)
        .await
        .map_err(|e| format!("接続に失敗しました: {e}"))?;

    let mailboxes = client
        .get_mailboxes()
        .await
        .map_err(|e| format!("メールボックスの取得に失敗しました: {e}"))?;

    let result = ConnectResult {
        account_id: client.account_id().to_string(),
        mailboxes: mailboxes
            .iter()
            .map(|m| (m.id.clone(), m.name.clone(), m.unread_emails))
            .collect(),
        org_domain: client.account_domain(),
    };

    *jmap_slot().lock().await = Some(std::sync::Arc::new(client));
    audit_event(
        Some(&result.account_id),
        "MAIL_CONNECT",
        serde_json::json!({"mailboxes": result.mailboxes.len()}),
    )
    .await;
    Ok(result)
}

/// 接続を破棄する (トークンをメモリから落とす)。
pub async fn mail_disconnect() -> Result<(), String> {
    let client = jmap_slot().lock().await.take();
    if let Some(c) = client {
        audit_event(
            Some(c.account_id()),
            "MAIL_DISCONNECT",
            serde_json::json!({}),
        )
        .await;
    }
    Ok(())
}

/// サーバからメール一覧を取得し、**各通に BEC 判定を付けて**返す。
///
/// 受信した実データが、ファイル解析と同じ検出器を通る。
/// 件名と送信者からトリアージ先を決める。
///
/// 判定本体は `kaname_core::ux_features::TriageEngine` にあり、
/// 実装済みでありながら出荷バイナリから到達不能だった (フロントエンドに
/// 同等ロジックが TypeScript で二重実装されていた)。単一の実装に寄せる。
fn triage_bucket(from_addr: &str, subject: &str, verdict: &str) -> String {
    use kaname_core::ux_features::{TriageBucket, TriageEngine};
    let bucket = TriageEngine::new().triage(from_addr, subject, Some(verdict));
    match bucket {
        TriageBucket::Important => "important",
        TriageBucket::Other => "other",
        TriageBucket::Feed => "feed",
        TriageBucket::PaperTrail => "paper_trail",
    }
    .to_string()
}

pub async fn mail_fetch(mailbox_id: String, limit: Option<u32>) -> Result<Vec<EmailRow>, String> {
    let client = jmap_client().await?;
    let account_id = client.account_id().to_string();
    let items = client
        .query_emails(&mailbox_id, 0, limit.unwrap_or(50))
        .await
        .map_err(|e| format!("メール一覧の取得に失敗しました: {e}"))?;

    // 自組織ドメイン (D44) は一覧全体で1回だけ解決する (行ごとの DB 参照を避ける)。
    let our = our_domain(&account_id, None).await;
    let mut rows = Vec::with_capacity(items.len());
    for it in &items {
        let from_addr = it
            .from
            .as_ref()
            .and_then(|v| v.first())
            .map(|a| a.email.clone())
            .unwrap_or_default();
        let from_name = it
            .from
            .as_ref()
            .and_then(|v| v.first())
            .and_then(|a| a.name.clone());
        let subject = it.subject.clone().unwrap_or_default();
        let preview = it.preview.clone().unwrap_or_default();
        let reply_to = it
            .reply_to
            .as_ref()
            .and_then(|v| v.first())
            .map(|a| a.email.clone());

        // スレッド情報は JMAP の messageId/inReplyTo/references/threadId、
        // 認証結果は header:Authentication-Results:asText から供給。
        let verdict = assess_listing(ListingInput {
            account_id: &account_id,
            from_name: &from_name,
            from_addr: &from_addr,
            subject: &subject,
            preview: &preview,
            our_domain: &our,
            reply_to: reply_to.as_deref(),
            thread_id: it.thread_id.as_deref(),
            in_reply_to: it.in_reply_to.as_deref().unwrap_or(&[]),
            references: it.references.as_deref().unwrap_or(&[]),
            dkim_signature: it.dkim_signature.as_deref(),
            auth_results: it.auth_results.as_deref(),
        })
        .await;

        // 受信を履歴に記録し、メール本体も保存する。
        // Store 未接続なら何もしない。失敗しても解析結果は返す
        // (保存できないことは表示できない理由にならない)。
        if let Some(store) = store_slot().lock().await.clone() {
            if let Err(e) = store
                .record_received(
                    &account_id,
                    &from_addr,
                    from_name.as_deref(),
                    it.subject.as_deref(),
                )
                .await
            {
                tracing::warn!(error=%e, "送信者履歴の記録に失敗");
            }

            let new_msg = kaname_store::NewMessage {
                jmap_id: it.id.clone(),
                // Message-ID は RFC 5322 の値 (JMAP messageId) を先頭のみ保持。
                message_id: it.message_id.as_ref().and_then(|v| v.first()).cloned(),
                thread_id: it.thread_id.clone(),
                from_addr: from_addr.clone(),
                from_name: from_name.clone(),
                to_addrs: it
                    .to
                    .as_ref()
                    .map(|addrs| addrs.iter().map(|a| a.email.clone()).collect())
                    .unwrap_or_default(),
                subject: it.subject.clone(),
                body_preview: it.preview.clone(),
                received_at: it.received_at.clone(),
                is_read: it.is_read(),
                bec_score: None,
                bec_verdict: Some(verdict.clone()),
            };
            if let Err(e) = store.save_message(&account_id, &mailbox_id, &new_msg).await {
                tracing::warn!(error=%e, "メールの保存に失敗");
            }
        }

        // 判定は決定論的で LLM 不要。
        let triage = triage_bucket(&from_addr, &subject, &verdict);

        rows.push(EmailRow {
            id: it.id.clone(),
            from_name,
            from_addr,
            subject: it.subject.clone(),
            preview: it.preview.clone(),
            received_at: it.received_at.clone(),
            is_read: it.is_read(),
            is_starred: it.is_starred(),
            bec_verdict: verdict,
            // EmailListItem は一覧用途のため body_structure を持たず、
            // MLS かどうかはここでは判別できない (is_mls_envelope は BodyPart
            // のメソッド)。判別不能を真と偽らず false にする。
            is_mls: false,
            triage,
        });
    }
    Ok(rows)
}

/// `assess_listing` への入力を束ねる。
/// JMAP `EmailListItem` のフィールド群 + 評価用の自組織ドメイン。
struct ListingInput<'a> {
    account_id: &'a str,
    from_name: &'a Option<String>,
    from_addr: &'a str,
    subject: &'a str,
    preview: &'a str,
    our_domain: &'a str,
    reply_to: Option<&'a str>,
    thread_id: Option<&'a str>,
    in_reply_to: &'a [String],
    references: &'a [String],
    dkim_signature: Option<&'a str>,
    /// Authentication-Results ヘッダーの生値 (未取得時は None)。
    auth_results: Option<&'a str>,
}

/// 一覧表示用の簡易 BEC 判定。
///
/// 一覧では本文全体もヘッダも持たないため、差出人・件名・プレビューのみで
/// 評価する。**判定できなかった場合に SAFE を返さない** (UNKNOWN を返す) のは
/// 他の経路と同じ方針で、判定不能を安全と偽らないため。
async fn assess_listing(input: ListingInput<'_>) -> String {
    let ListingInput {
        account_id,
        from_name,
        from_addr,
        subject,
        preview,
        our_domain,
        reply_to,
        thread_id,
        in_reply_to,
        references,
        dkim_signature,
        auth_results,
    } = input;
    let from_header = match from_name {
        Some(n) => format!("{n} <{from_addr}>"),
        None => from_addr.to_string(),
    };
    let urls = extract_urls_from_text(preview);
    let contacts = lookup_contacts(account_id).await;
    // 送信者履歴を引く。無ければ None のままで、BEC は履歴シグナルを
    // 評価しない (履歴が無いことを「初回連絡」と断定しない)。
    let history = lookup_sender_history(account_id, from_addr).await;

    // スレッド乗っ取り検出: JMAP threadId で既知スレッドを引き、
    // In-Reply-To/References の Message-ID 一致と照合する。
    let mut ref_ids: Vec<String> = in_reply_to.to_vec();
    ref_ids.extend(references.iter().cloned());
    ref_ids.dedup();
    let (known_ids, thread_domains, prior_subject, prior_language, past_bodies) =
        build_thread_data(account_id, thread_id, &ref_ids).await;
    let current_domain = from_addr
        .rsplit('@')
        .next()
        .map(|d| d.to_lowercase())
        .unwrap_or_default();
    let body_snippet: String = preview.chars().take(500).collect();
    let in_reply_to_first = in_reply_to.first();
    let thread_ctx = if known_ids.is_empty() && in_reply_to_first.is_none() {
        None
    } else {
        Some(kaname_bec::thread_hijack::ThreadContext {
            in_reply_to: in_reply_to_first.map(|s| s.as_str()),
            known_thread_message_ids: &known_ids,
            thread_sender_domains: &thread_domains,
            current_sender_domain: &current_domain,
            prior_subject: prior_subject.as_deref(),
            current_subject: subject,
            prior_language,
            current_body_snippet: &body_snippet,
        })
    };
    // 一覧でも Authentication-Results を取得していれば実値を使う。
    // ヘッダが無い経路では全て None — Pass と偽ると認証シグナルが
    // 不当に安全側へ倒れるため。
    let parsed_auth = auth_results
        .map(kaname_render::parse_auth_results_str)
        .unwrap_or_default();
    let req = kaname_bec::AssessmentRequest {
        from_header: &from_header,
        return_path: None,
        subject,
        body_text: preview,
        auth: kaname_bec::AuthResults {
            spf: map_auth(parsed_auth.spf),
            dkim: map_auth(parsed_auth.dkim),
            dmarc: map_auth(parsed_auth.dmarc),
            arc: None,
        },
        sender_history: history.as_ref(),
        our_domain,
        known_contacts: &contacts,
        extracted_urls: &urls,
        reply_to,
        thread_context: thread_ctx,
        past_thread_bodies: &past_bodies,
        dkim_signature_header: dkim_signature,
    };
    match kaname_bec::BecDetector::deterministic_only().assess(req) {
        Ok(a) => match a.verdict {
            kaname_bec::Verdict::Safe => "SAFE",
            kaname_bec::Verdict::Advisory => "ADVISORY",
            kaname_bec::Verdict::Suspicious => "SUSPICIOUS",
            kaname_bec::Verdict::Dangerous => "DANGEROUS",
        }
        .to_string(),
        Err(e) => {
            tracing::warn!(error=%e, "一覧の BEC 判定に失敗");
            "UNKNOWN".to_string()
        }
    }
}

/// メールを既読にする。
///
/// `src-tauri/main.rs` の同名コマンドから呼ばれる。JMAP サーバへ
/// `Email/set` で `$seen` キーワードを立てる。ローカル Store の `is_read`
/// は次回 `mail_fetch` の `ON CONFLICT` 更新で追随する。
pub async fn mail_mark_read(ids: Vec<String>) -> Result<(), String> {
    let client = jmap_client().await?;
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    client
        .mark_read(&refs)
        .await
        .map_err(|e| format!("既読化に失敗しました: {e}"))
}

/// メールをゴミ箱へ移動する。
///
/// `src-tauri/main.rs` の同名コマンドから呼ばれる。JMAP の
/// `role == "trash"` メールボックスへ移す。
pub async fn mail_trash(email_id: String) -> Result<(), String> {
    let client = jmap_client().await?;
    client
        .trash(&email_id)
        .await
        .map_err(|e| format!("削除に失敗しました: {e}"))
}

/// メールを送信する。
///
/// **送信前に DLP (`Direction::Outbound`) を実行し、Block 判定なら送信しない。**
/// これが DLP 本来の用途であり、受信側検査 (`scan_dlp_inbound`) と対になる。
pub async fn mail_send_real(
    from: String,
    to: Vec<String>,
    subject: String,
    body: String,
) -> Result<String, String> {
    let client = jmap_client().await?;

    // 送信前 DLP。ここで止めるのが情報漏洩防止の本丸。
    let engine = kaname_dlp::DlpEngine::default_engine();
    let mimes: Vec<String> = Vec::new();
    let domains: Vec<String> = Vec::new();
    let edm: std::collections::HashMap<String, kaname_dlp::edm::EdmFingerprints> =
        std::collections::HashMap::new();
    // 自組織ドメイン (D44): 送信者自身の `from` アドレスが最直接のヒント。
    let our = our_domain(client.account_id(), Some(&from)).await;
    let ctx = kaname_dlp::EvalCtx {
        body: &body,
        subject: &subject,
        size_bytes: body.len() as u64,
        to: &to,
        from: &from,
        attachment_mimes: &mimes,
        edm_sets: &edm,
        known_recipient_domains: &domains,
        our_domain: &our,
    };
    let dlp = engine.evaluate(&ctx, kaname_dlp::Direction::Outbound);
    if matches!(dlp.verdict, kaname_dlp::Action::Block) {
        let reasons: Vec<String> = dlp.findings.iter().map(|f| f.rule_name.clone()).collect();
        let reason_str = reasons.join(" / ");
        // 外部宛送信の阻止は最重要の証跡 — どのルールで止めたかを残す
        // (件名・本文・宛先は書かない)。
        audit_event(
            Some(client.account_id()),
            "DLP_BLOCK",
            serde_json::json!({ "to_count": to.len(), "rules": reasons }),
        )
        .await;
        return Err(format!(
            "DLP により送信をブロックしました: {reason_str}。機微情報が含まれていないか確認してください"
        ));
    }

    let to_refs: Vec<&str> = to.iter().map(String::as_str).collect();
    let result = client
        .send_email(&from, &to_refs, &subject, &body, None)
        .await
        .map_err(|e| format!("送信に失敗しました: {e}"))?;

    // 実際に送信が行われた出口イベント (件名・本文・宛先アドレスは書かない)。
    audit_event(
        Some(client.account_id()),
        "MAIL_SEND",
        serde_json::json!({ "to_count": to.len() }),
    )
    .await;

    Ok(result)
}

// ============================================================================
// 送信者履歴の永続化
//
// `kaname-bec` は送信者履歴シグナル (初回連絡 / 久しぶりの連絡 /
// 普段と違うトピック / ユーザーが検証済みか / 過去に悪意ありと報告したか) を
// 実装済みだが、`AssessmentRequest.sender_history` に常に `None` を渡して
// いたため**一度も発火していなかった**。
//
// `kaname-store` には SenderProfile の CRUD (`get_sender_profile` /
// `record_received` / `mark_sender_verified`) が実装済みで、
// BEC 側の `SenderHistory` と対応する形になっている。
// 両者を繋ぐコードが無いだけだった。
// ============================================================================

/// 開いている Store。未接続なら None。
static STORE: std::sync::OnceLock<tokio::sync::Mutex<Option<std::sync::Arc<kaname_store::Store>>>> =
    std::sync::OnceLock::new();

fn store_slot() -> &'static tokio::sync::Mutex<Option<std::sync::Arc<kaname_store::Store>>> {
    STORE.get_or_init(|| tokio::sync::Mutex::new(None))
}

/// 送信者履歴データベースを開く。
///
/// `key_hex` は SQLCipher の 64 桁 16 進鍵。**鍵は呼び出し側が管理する**
/// (本コマンドは保存しない)。認証トークンと同じく、安全に保管できる仕組みが
/// 入るまでアプリ側では永続化しない方針。
///
/// IPC コマンドとしては登録しない (呼び出し元の無い任意パスオープン面を
/// 公開しない)。`history_open_default` からのみ使われる内部ヘルパー。
async fn history_open(path: String, key_hex: String) -> Result<(), String> {
    let store = kaname_store::Store::open(std::path::Path::new(&path), &key_hex)
        .await
        .map_err(|e| format!("履歴データベースを開けません: {e}"))?;
    store
        .migrate()
        .await
        .map_err(|e| format!("スキーマ移行に失敗しました: {e}"))?;
    // 監査ログの改ざん検知: チェーン破損は致命的ではないため警告のみ。
    if let Ok(false) = store.verify_audit_chain().await {
        warn!("監査ログのハッシュチェーンが破損 — 改ざんの可能性があります");
    }
    if let Err(e) = store
        .audit(None, "STORE_OPEN", &serde_json::json!({}))
        .await
    {
        warn!(error=%e, "監査ログの書き込みに失敗");
    }
    *store_slot().lock().await = Some(std::sync::Arc::new(store));
    info!(path=%path, "history_open");
    Ok(())
}

/// 既定の場所に履歴データベースを開く (アプリ起動時に呼ぶ)。
///
/// # なぜ必要か
/// `history_open` はコマンドとして存在したが、**どの UI からも呼ばれていなかった**。
/// Store が開かれなければ永続化・検索・送信者履歴はすべて無言で無効になる
/// (「Store 未接続なら何もしない」設計のため、失敗すら表示されない)。
///
/// # 鍵の扱い (正直に)
/// SQLCipher の鍵は `<data_dir>/kaname/history.key` に 0600 で保存する
/// (初回起動時に OS の CSPRNG で 32 バイト生成)。OS キーチェーン統合は未実装
/// のため、**同一ユーザー権限で動くプロセスからは鍵を読める**。
/// これは「他ユーザー・ディスクの持ち出し」に対する保護であり、
/// 「同一アカウント上のマルウェア」に対する保護ではない。
pub async fn history_open_default() -> Result<String, String> {
    if store_slot().lock().await.is_some() {
        return Ok("already-open".to_string());
    }
    let base = dirs::data_dir()
        .ok_or_else(|| "データディレクトリを特定できません".to_string())?
        .join("kaname");
    std::fs::create_dir_all(&base)
        .map_err(|e| format!("データディレクトリを作成できません: {e}"))?;

    let key_path = base.join("history.key");
    let key_hex = match std::fs::read_to_string(&key_path) {
        Ok(k) if k.trim().len() == 64 => k.trim().to_string(),
        _ => {
            use rand::RngCore as _;
            let mut raw = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut raw);
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            std::fs::write(&key_path, &hex).map_err(|e| format!("鍵ファイルを書けません: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
            }
            hex
        }
    };

    let db_path = base.join("history.db");
    let shown = db_path.to_string_lossy().into_owned();
    history_open(shown.clone(), key_hex).await?;
    Ok(shown)
}

/// 監査ログ閲覧の応答。
#[derive(Debug, Serialize)]
pub struct AuditLogView {
    /// 監査エントリ (新しい順)。
    pub entries: Vec<kaname_store::AuditEntry>,
    /// ハッシュチェーンの検証結果 (true = 改ざんなし)。
    pub chain_valid: bool,
}

/// 監査証跡 (`audit_log` テーブル) を閲覧用に返す。
///
/// audit_log は append-only トリガー + ハッシュチェーンで書き込み側は
/// 保護されていたが、**読み出し経路が存在せず書き込み専用のままだった**。
/// このコマンドが SecurityDashboard の「監査証跡」セクションを駆動する。
/// Store 未オープンなら空 (DB が無ければ記録も無いため実態として正しい)。
#[instrument]
pub async fn security_audit_log(limit: Option<i64>) -> Result<AuditLogView, String> {
    let Some(store) = store_slot().lock().await.clone() else {
        return Ok(AuditLogView {
            entries: Vec::new(),
            chain_valid: true,
        });
    };
    let limit = limit.unwrap_or(100).clamp(1, 500);
    let entries = store
        .audit_entries(limit)
        .await
        .map_err(|e| format!("監査ログの読み出しに失敗しました: {e}"))?;
    // チェーン破損 (行ハッシュ不正) は Err、prev_hash 不連続は Ok(false)。
    let chain_valid = store.verify_audit_chain().await.unwrap_or(false);
    Ok(AuditLogView {
        entries,
        chain_valid,
    })
}

/// オンボーディングで選んだ設定を保存する。
///
/// 以前は `not_wired` を返すスタブで、そのために Onboarding 画面は
/// 意図的に未到達にしていた (D22)。`settings` テーブルに保存する。
/// アカウント接続前でも動くよう account_id は固定の "local" を使う。
pub async fn settings_save_onboarding(
    notifications: bool,
    telemetry: bool,
) -> Result<(), String> {
    let store = store_slot()
        .lock()
        .await
        .clone()
        .ok_or_else(|| "履歴データベースが開かれていません".to_string())?;
    for (k, v) in [
        ("notifications", notifications),
        ("telemetry", telemetry),
        ("onboarding_done", true),
    ] {
        store
            .set_setting("local", k, if v { "true" } else { "false" })
            .await
            .map_err(|e| format!("設定の保存に失敗しました: {e}"))?;
    }
    Ok(())
}

/// オンボーディング済みか。Store 未接続なら false (画面を出す側に倒す)。
pub async fn settings_is_onboarded() -> bool {
    let Some(store) = store_slot().lock().await.clone() else {
        return false;
    };
    matches!(
        store.get_setting("local", "onboarding_done").await,
        Ok(Some(v)) if v == "true"
    )
}

/// 送信者を「検証済み」としてマークする。
///
/// BEC の `user_verified` シグナルに反映され、以後この送信者は
/// 初回連絡扱いされなくなる。
/// 差出人を「確認済み」にマークする。
///
/// 他コマンド (`mail_open`/`mail_fetch`) と同様に `account_id` は
/// `current_account_id()` で内部解決する。以前はフロントエンドに
/// `account_id` を渡させていたが、どの UI もそれを持っておらず、
/// 呼び手ゼロのまま放置されていた (docs/gap-analysis.md D24)。
pub async fn history_mark_verified(email: String) -> Result<(), String> {
    let store = store_slot()
        .lock()
        .await
        .clone()
        .ok_or_else(|| "履歴データベースが開かれていません".to_string())?;
    let account_id = current_account_id().await;
    store
        .mark_sender_verified(&account_id, &email)
        .await
        .map_err(|e| format!("検証済みマークに失敗しました: {e}"))?;
    // 送信者の「確認済み」化は以後の BEC 判定 (user_verified シグナル) を
    // 変えるため、改ざん検知付きの監査ログに残す。
    audit_event(
        Some(&account_id),
        "SENDER_VERIFIED",
        serde_json::json!({"sender": email}),
    )
    .await;
    Ok(())
}

/// Store から連絡先一覧を引き、BEC の `known_contacts` に渡す。
///
/// Store が開かれていない・失敗した場合は空リストを返す
/// (連絡先ベースの詐称検出がスキップされるだけで、誤判定にはならない)。
async fn lookup_contacts(account_id: &str) -> Vec<String> {
    let Some(store) = store_slot().lock().await.clone() else {
        return Vec::new();
    };
    store.list_contacts(account_id).await.unwrap_or_else(|e| {
        tracing::warn!(error=%e, "連絡先一覧の取得に失敗");
        Vec::new()
    })
}

/// Store からスレッド内メッセージを引く。
///
/// `thread_id` (JMAP) があれば直接引き、無ければ `ref_message_ids`
/// (In-Reply-To / References が指す Message-ID) に一致する過去メールから
/// 逆引きする。Store 未接続・失敗・0件なら空 (そのシグナルはスキップ)。
async fn lookup_thread_messages(
    account_id: &str,
    thread_id: Option<&str>,
    ref_message_ids: &[String],
) -> Vec<kaname_store::StoredMessage> {
    let Some(store) = store_slot().lock().await.clone() else {
        return Vec::new();
    };
    if let Some(tid) = thread_id {
        match store.list_thread_messages(account_id, tid).await {
            Ok(v) if !v.is_empty() => return v,
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error=%e, "スレッド履歴の取得に失敗");
                return Vec::new();
            }
        }
    }
    if ref_message_ids.is_empty() {
        return Vec::new();
    }
    store
        .list_messages_by_message_ids(account_id, ref_message_ids)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error=%e, "Message-ID 検索に失敗");
            Vec::new()
        })
}

/// `ThreadContext`/`past_thread_bodies` に渡す所有データを組み立てる。
///
/// BEC の `ThreadContext<'a>` は参照型のため、所有側 (この戻り値) を
/// 評価ブロックスコープで保持してから借用する。
/// 返るタプル: (known_message_ids, sender_domains, prior_subject,
///              prior_language, past_bodies)
async fn build_thread_data(
    account_id: &str,
    thread_id: Option<&str>,
    ref_message_ids: &[String],
) -> (
    Vec<String>,
    Vec<String>,
    Option<String>,
    Option<kaname_bec::thread_hijack::ThreadLanguage>,
    Vec<String>,
) {
    let msgs = lookup_thread_messages(account_id, thread_id, ref_message_ids).await;
    if msgs.is_empty() {
        return (Vec::new(), Vec::new(), None, None, Vec::new());
    }
    let mut known_ids = Vec::with_capacity(msgs.len());
    let mut domains = Vec::new();
    let mut bodies = Vec::new();
    for m in &msgs {
        if let Some(id) = &m.message_id {
            known_ids.push(id.clone());
        }
        if let Some(dom) = m.from_addr.rsplit('@').next() {
            let d = dom.to_lowercase();
            if !domains.contains(&d) {
                domains.push(d);
            }
        }
        if let Some(b) = &m.body_preview {
            bodies.push(b.clone());
        }
    }
    // 直近メッセージの件名と言語を「スレッドの基準」として使う。
    let prior_subject = msgs.last().and_then(|m| m.subject.clone());
    let prior_language = msgs
        .last()
        .and_then(|m| m.body_preview.as_deref())
        .map(kaname_bec::thread_hijack::detect_language);
    (known_ids, domains, prior_subject, prior_language, bodies)
}

/// Store から送信者履歴を引き、BEC の `SenderHistory` に変換する。
///
/// Store が開かれていない、または該当プロファイルが無い場合は `None` を返す。
/// **その場合 BEC 側は履歴シグナルを評価しない** (履歴が無いことを
/// 「初回連絡」と断定しないため、これが正しい挙動)。
async fn lookup_sender_history(account_id: &str, email: &str) -> Option<kaname_bec::SenderHistory> {
    let store = store_slot().lock().await.clone()?;
    let profile = store.get_sender_profile(account_id, email).await.ok()??;

    // 最終受信からの経過日数を求める。パースできない場合は None にして
    // 「不明」を保つ (0 日と誤って扱うと「直前に連絡があった」ことになり
    //  久しぶりの連絡シグナルが不当に抑制される)。
    let days_since_last = profile.last_seen_at.as_deref().and_then(days_since_rfc3339);

    Some(kaname_bec::SenderHistory {
        prior_message_count: profile.message_count,
        days_since_last,
        typical_topic_summary: profile.topic_summary.clone(),
        user_verified: profile.user_verified,
        // Store 側に「悪意ありと報告」の列がまだ無いため false 固定。
        // ここを true と偽ると危険側の判定が不当に強まるため、
        // 列が追加されるまでは保守的に false を返す。
        user_reported_malicious: false,
    })
}

/// RFC 3339 形式の時刻から現在までの日数を求める。
///
/// `chrono` を使わずに済ませるため、`YYYY-MM-DD` 部分のみを使った
/// 概算とする (履歴シグナルは日単位の粗い粒度で足りる)。
/// 解析できない場合は `None` を返し「不明」を保つ。
fn days_since_rfc3339(ts: &str) -> Option<u32> {
    fn to_days(y: i64, m: i64, d: i64) -> i64 {
        // Howard Hinnant の days_from_civil アルゴリズム
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let mp = (m + 9) % 12;
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    let date = ts.get(..10)?;
    let mut it = date.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let today = now_secs / 86_400;
    let then = to_days(y, m, d);
    u32::try_from((today - then).max(0)).ok()
}

// ============================================================================
// 送信者文体認証 (SSA)
//
// `kaname-ssa` (1209 行) は文体プロファイルによるアカウント乗っ取り検出を
// 実装済みだが、**どこからも依存されない孤島クレート**だった
// (gap-analysis D12)。`EmailStyleFeatures::extract()` という抽出関数も
// 揃っており、繋ぐコードが無いだけだった。
//
// 文体は「同一送信者の複数通を見比べて初めて意味を持つ」ため、
// プロファイルを跨いで蓄積する必要がある。送信者履歴 (SQLCipher) と違い
// 文体プロファイルは数値ベクトルのみで本文を含まないため
// (kaname-ssa の設計方針)、メモリ内保持で足りる。
// ============================================================================

/// 送信者ごとの文体プロファイル。
///
/// 本文は保持せず数値特徴のみ (段落数・文長・句読点密度・formality 等)。
/// プロセス終了で失われるが、文体は同一セッション内の複数通を
/// 見比べるだけでも乗っ取り検出に寄与する。
static STYLE_PROFILES: std::sync::OnceLock<
    tokio::sync::Mutex<std::collections::HashMap<String, kaname_ssa::SenderStyleProfile>>,
> = std::sync::OnceLock::new();

fn style_profiles(
) -> &'static tokio::sync::Mutex<std::collections::HashMap<String, kaname_ssa::SenderStyleProfile>>
{
    STYLE_PROFILES.get_or_init(|| tokio::sync::Mutex::new(std::collections::HashMap::new()))
}

/// 本文の文体を評価し、必要なら警告を返す。プロファイルは同時に更新する。
///
/// 送信時刻が不明な場合は評価しない。`send_hour` を 0 で代用すると
/// 「深夜送信」という誤ったシグナルを生むため、推測しない。
///
/// 戻り値が空なのは「警告なし」または「学習データ不足」のいずれか。
/// **不足を「問題なし」と偽らない**ため、UI には警告のみを出す。
async fn evaluate_sender_style(
    sender: &str,
    body: &str,
    send_hour: Option<u8>,
    contains_financial_request: bool,
) -> Vec<String> {
    let Some(hour) = send_hour else {
        return Vec::new();
    };
    let features = kaname_ssa::EmailStyleFeatures::extract(body, hour);
    if !features.is_finite() {
        // NaN/Infinity を含む特徴量はプロファイルを汚染するため取り込まない。
        return Vec::new();
    }

    let mut profiles = style_profiles().lock().await;
    let profile = profiles
        .entry(sender.to_string())
        .or_insert_with(|| kaname_ssa::SenderStyleProfile::new(sender));

    // 判定してから取り込む。取り込んでから判定すると、
    // なりすましメール自身がプロファイルを引き寄せて検出が鈍る。
    let warning =
        kaname_ssa::assess_self_send_anomaly(profile, &features, contains_financial_request);
    profile.update(&features);

    match warning {
        kaname_ssa::StyleWarning::High => vec![format!(
            "文体が普段と大きく異なります (送信者: {sender})。\
             アカウント乗っ取りの可能性があります。"
        )],
        kaname_ssa::StyleWarning::Medium => {
            vec![format!("文体が普段と異なります (送信者: {sender})。")]
        }
        // Low は日常的な揺らぎでも出るため報告しない (警告疲れの回避)。
        // InsufficientData / None は警告を出さない。
        _ => Vec::new(),
    }
}

/// 保存済みメールを新しい順に返す (オフライン閲覧)。
///
/// `mail_fetch` が保存したメールを、サーバに接続せず読み出す。
/// 従来 `messages` テーブルへの SELECT は**ワークスペース全体でゼロ件**
/// だったため、取得したメールを再表示する手段が無かった (D10)。
pub async fn mail_list_stored(
    mailbox_id: String,
    limit: Option<u32>,
) -> Result<Vec<kaname_store::StoredMessage>, String> {
    let store = store_slot()
        .lock()
        .await
        .clone()
        .ok_or_else(|| "履歴データベースが開かれていません".to_string())?;
    let account_id = current_account_id().await;
    store
        .list_messages(&account_id, &mailbox_id, limit.unwrap_or(50))
        .await
        .map_err(|e| format!("保存済みメールの読み出しに失敗しました: {e}"))
}

/// 保存済みメールを検索する。
///
/// 件名・送信者・本文プレビューが対象。受信箱 UI の検索欄は
/// **ハンドラが未バインドのまま放置されていた** (D10) ため、
/// 検索機能そのものが存在しなかった。
pub async fn mail_search(
    query: String,
    limit: Option<u32>,
) -> Result<Vec<kaname_store::StoredMessage>, String> {
    if query.trim().is_empty() {
        return Ok(Vec::new());
    }
    let store = store_slot()
        .lock()
        .await
        .clone()
        .ok_or_else(|| "履歴データベースが開かれていません".to_string())?;
    let account_id = current_account_id().await;
    store
        .search_messages(&account_id, query.trim(), limit.unwrap_or(50))
        .await
        .map_err(|e| format!("検索に失敗しました: {e}"))
}

/// 現在の JMAP アカウント ID を返す。未接続なら空文字。
///
/// 保存・検索はサーバ未接続でも行えるべきだが、どのアカウントの
/// メールかを区別する必要があるため、接続時の ID を使う。
async fn current_account_id() -> String {
    match jmap_client().await {
        Ok(c) => c.account_id().to_string(),
        Err(_) => String::new(),
    }
}

/// 監査ログ (audit_log, ハッシュチェーン付き) への書き込み — best-effort。
///
/// Store が開かれていなければ記録しない。監査の失敗で本来の操作
/// (メール送受信・添付保存等) を失敗させない。ペイロードは最小限に
/// 留める — audit_log は messages/contacts と同じ暗号化 DB 内だが、
/// 不要な本文・トークン・パスは絶対に書かない。
async fn audit_event(account_id: Option<&str>, event_type: &str, payload: serde_json::Value) {
    if let Some(store) = store_slot().lock().await.clone() {
        if let Err(e) = store.audit(account_id, event_type, &payload).await {
            warn!(error=%e, "監査ログの書き込みに失敗");
        }
    }
}

/// メールアドレスからドメイン部を取り出す (小文字化)。
/// `"Name <a@b.com>"` のような表示名付きにも耐える。アドレス形でなければ None。
fn email_domain(addr: &str) -> Option<String> {
    let (_, domain) = addr.rsplit_once('@')?;
    let domain: String = domain
        .split(|c: char| c.is_whitespace() || matches!(c, '>' | ';' | ','))
        .next()?
        .to_lowercase();
    (!domain.is_empty()).then_some(domain)
}

/// 自組織ドメインを解決する (D44)。
///
/// 優先順位:
/// 1. 設定 `org_domain` (明示設定が最優先。アカウント固有 → "local" 共有の順)
/// 2. `hint` (呼び出し側が持つ自アドレスのドメイン — 例: `mail_send_real` の from)
/// 3. 接続中 JMAP アカウントのドメイン (session.username / account name から導出)
/// 4. 空文字 — 下流の検出器は空を「不明」として安全にスキップする
///    (`kaname-dlp` は `!our_domain.is_empty()` ガード、`kaname-bec` は
///    `levenshtein1(domain, "")` が成立しないため自己類似判定が発火しない)。
///
/// `"example.com"` のような実在ドメインの固定値は、他者ドメイン宛メールへの
/// 誤検知と自組織ドメインなりすましの見逃しを同時に招くため返さない。
async fn our_domain(account_id: &str, hint: Option<&str>) -> String {
    let store = store_slot().lock().await.clone();
    if let Some(store) = store {
        for acct in [account_id, "local"] {
            if let Ok(Some(v)) = store.get_setting(acct, "org_domain").await {
                let v = v.trim().to_lowercase();
                if !v.is_empty() {
                    return v;
                }
            }
        }
    }
    if let Some(d) = hint.and_then(email_domain) {
        return d;
    }
    if let Ok(client) = jmap_client().await {
        if let Some(d) = client.account_domain() {
            return d;
        }
    }
    String::new()
}

// ============================================================================
// 添付ファイルのダウンロード + 検査
//
// D10 の残る唯一の項目。従来 `download_url` は保持されるだけで参照ゼロ
// (blob download 未実装) だった。
//
// **安全側の設計**: ダウンロードしたバイトは必ず `scan_attachment_bytes` に
// かけ、危険と判定されたらディスクに書かない。kaname-sandbox が no-op の現状、
// 実行はさせず「検査して警告」に留める。
// ============================================================================

/// 添付ダウンロードの結果。
#[derive(Debug, serde::Serialize)]
pub struct AttachmentDownload {
    /// ファイル名。
    pub filename: String,
    /// MIME タイプ。
    pub mime: String,
    /// サイズ (bytes)。
    pub size_bytes: u64,
    /// 検出されたリスク (人間可読)。
    pub risks: Vec<String>,
    /// 実行リスクがあるか。
    pub is_dangerous: bool,
    /// 隔離ディレクトリへの保存先。危険な場合は書き込まないため None。
    pub saved_path: Option<String>,
}

/// サーバ上のメールが持つ添付の一覧 (ファイル名・blobId・MIME) を返す。
///
/// `mail_open` が返す添付検査結果 (`AttachmentScan`) はファイル名しか
/// 持たない (バイト列から検査するだけで JMAP を知らない)。ダウンロード
/// ボタンを表示するには `blobId` が要るため、この一覧を別途取得して
/// ファイル名で突き合わせる。
#[derive(Debug, serde::Serialize)]
pub struct AttachmentRef {
    pub filename: String,
    pub blob_id: String,
    pub mime: String,
}

pub async fn mail_list_attachment_blobs(email_id: String) -> Result<Vec<AttachmentRef>, String> {
    let client = jmap_client().await?;
    let full = client
        .get_email_body(&email_id)
        .await
        .map_err(|e| format!("メールの取得に失敗しました: {e}"))?;
    Ok(full
        .attachments
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| {
            let blob_id = p.blob_id?;
            Some(AttachmentRef {
                filename: p.name.unwrap_or_else(|| "unnamed".to_string()),
                blob_id,
                mime: p
                    .mime_type
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
            })
        })
        .collect())
}

/// メールの添付ファイルをダウンロードし、検査してから隔離保存する。
///
/// `blob_id` が空の添付 (インライン参照のみ等) は取得できないためエラー。
pub async fn mail_download_attachment(
    email_id: String,
    blob_id: String,
) -> Result<AttachmentDownload, String> {
    if blob_id.trim().is_empty() {
        return Err("この添付には blobId がなく取得できません".to_string());
    }
    let client = jmap_client().await?;

    // 対象メールの添付メタデータ (name / type) を得る。
    let full = client
        .get_email_body(&email_id)
        .await
        .map_err(|e| format!("メールの取得に失敗しました: {e}"))?;
    let part = full
        .attachments
        .unwrap_or_default()
        .into_iter()
        .find(|p| p.blob_id.as_deref() == Some(blob_id.as_str()))
        .ok_or_else(|| "指定された添付が見つかりません".to_string())?;

    let filename = part.name.clone().unwrap_or_else(|| "unnamed".to_string());
    let mime = part
        .mime_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());

    // blob を取得する。
    let bytes = client
        .download_blob(&blob_id, &mime, &filename)
        .await
        .map_err(|e| format!("添付のダウンロードに失敗しました: {e}"))?;

    // **ディスクに書く前に必ず検査する**。
    let scan = kaname_render::scan_attachment_bytes(&filename, &mime, &bytes);

    let saved_path = if scan.is_dangerous {
        // 危険な添付は書き出さない。利用者に理由を示すだけ。
        None
    } else {
        // 隔離ディレクトリ (アプリの一時領域) に書く。
        // ファイル名はサニタイズし、パストラバーサルを防ぐ。
        let safe_name = sanitize_filename(&filename);
        let dir = std::env::temp_dir().join("kaname-attachments");
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return Err(format!("保存先を作成できません: {e}"));
        }
        let path = dir.join(&safe_name);
        std::fs::write(&path, &bytes).map_err(|e| format!("保存に失敗しました: {e}"))?;
        Some(path.to_string_lossy().into_owned())
    };

    // 検査結果を attachments テーブルに記録する (フォレンジック証跡)。
    // メールが未保存なら何も書かない。記録の失敗でダウンロード自体を
    // 失敗させない。
    if let Some(store) = store_slot().lock().await.clone() {
        if let Err(e) = store
            .record_attachment_scan(
                client.account_id(),
                &kaname_store::AttachmentScanRecord {
                    jmap_id: &email_id,
                    filename: &filename,
                    declared_mime: &mime,
                    size_bytes: scan.size_bytes,
                    scan_verdict: if scan.is_dangerous {
                        "dangerous"
                    } else {
                        "scanned"
                    },
                    blob_path: saved_path.as_deref(),
                },
            )
            .await
        {
            warn!(error = %e, "添付検査結果の記録に失敗");
        }
    }

    // 添付のディスク書き出し/拒否はセキュリティ上重要な出口イベント。
    // 危険判定で拒否した場合こそ証跡が必要なため、拒否時も記録する。
    audit_event(
        Some(client.account_id()),
        "ATTACHMENT_DOWNLOAD",
        serde_json::json!({
            "email_id": email_id,
            "filename": filename,
            "is_dangerous": scan.is_dangerous,
            "saved": saved_path.is_some(),
        }),
    )
    .await;

    Ok(AttachmentDownload {
        filename,
        mime,
        size_bytes: scan.size_bytes,
        risks: scan.risks,
        is_dangerous: scan.is_dangerous,
        saved_path,
    })
}

/// ファイル名からパス区切り・親参照・制御文字を除去する。
///
/// 添付のファイル名は攻撃者が制御するため、そのまま `join` すると
/// `../../etc/passwd` のようなパストラバーサルを許す。ベース名のみを採り、
/// 危険な文字を `_` に置換する。
fn sanitize_filename(name: &str) -> String {
    // パス区切りの後ろ (ベース名) だけを採る。
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | ':' | '\0') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(['.', ' ']);
    if trimmed.is_empty() {
        "attachment".to_string()
    } else {
        trimmed.chars().take(200).collect()
    }
}
