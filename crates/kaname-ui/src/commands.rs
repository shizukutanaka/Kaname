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
}

#[derive(Debug, Serialize)]
pub struct MailSummary {
    pub unread: u32,
    pub bec_alerts: u32,
    pub total: u32,
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

/// サーバ上のメールを開き、**ローカル `.eml` と同じパイプライン**で解析する。
///
/// JMAP の `Email.blobId` は生 RFC 5322 全体を指す。これを `download_blob` で
/// 取得して `analyze_raw_email` に渡せば、本文サニタイズ・BEC スコア・
/// シグナル・添付検査・DLP・リンク評価がすべて得られる。
/// 「サーバのメールを開く」ために新しい解析コードは不要である。
///
/// (旧実装は「サーバ未接続のため未実装」でモック preview を返す設計だったが
/// D10 解消で実装に置き換えられた。)
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
    /// MLS E2E: メール内の `application/mls-envelope+cbor` パートを
    /// 処理した結果のイベント (人間可読) (D1 Phase 4)。
    ///
    /// 例: 「暗号メッセージを復号しました」「新しい会話に参加しました」。
    /// MLS 未初期化時は「初期化が必要」のイベントが入る。
    pub mls_events: Vec<String>,
    /// MLS E2E: 復号されたメール本文 (平文)。暗号化メールの内容は
    /// サーバ側 DLP/BEC では見えないため、復号後にローカルで解析する
    /// 設計判断は別途必要 (現状は表示のみ)。
    pub mls_plaintexts: Vec<String>,
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
    info!(path=%redact_path(&path), "mail_import_eml");

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

    let mut subject = env.subject.clone().unwrap_or_default();

    // 本文はプレーンテキストを優先し、無ければ空。
    // (HTML 本文は RawHtml のまま sanitize に渡すため別扱い)
    let body_text = env.text_body.clone().unwrap_or_default();

    // D160: HTML しか持たないメールでは text_body が空になり本文解析が
    // 全て素通りする — ユーザーが実際に見る側 (HTML) からもテキストを
    // 抽出して解析対象に併合する。multipart/alternative で text/plain に
    // デコイ・text/html に攻撃文を置くパート不一致回避も、両者を併合すれば
    // HTML 側の攻撃文がヒットする。hidden text salting (Cisco Talos 2025)
    // の非表示塩は html_to_text がサブツリーごと捨てる。
    let html_extract = env
        .html_body
        .as_ref()
        .map(|h| kaname_render::html_to_text(h.as_str()));
    let analysis_body = match &html_extract {
        Some(e) if !e.text.trim().is_empty() && !body_text.trim().is_empty() => {
            format!("{body_text}\n{}", e.text)
        }
        Some(e) if !e.text.trim().is_empty() => e.text.clone(),
        _ => body_text.clone(),
    };

    // MLS エンベロープを解析の「前」に処理する — 暗号メールでは実件名・
    // 実本文がエンベロープ内の `subject\x00body` ペイロードにあり、外側は
    // 固定カバー文 (「このメールは Kaname MLS で E2E 暗号化されています…」)。
    // 外側を採点すると全検出器がカバー文を解析してしまい、E2E メールが
    // 検査を完全にすり抜ける (D148)。認証・差出人は外側ヘッダ由来の
    // 配送層属性で正しいため、差し替えるのは件名と本文のみ。
    let mls_envelopes = kaname_render::extract_mls_envelopes(bytes);
    let (mut mls_events, mls_payloads) = process_mls_envelopes(&mls_envelopes);
    let mut mls_plaintexts: Vec<String> = Vec::with_capacity(mls_payloads.len());
    for payload in &mls_payloads {
        let (inner_subject, inner_body) = payload
            .split_once('\u{0}')
            .map_or(("", payload.as_str()), |(s, b)| (s, b));
        if !inner_subject.is_empty() {
            subject = inner_subject.to_string();
        }
        mls_plaintexts.push(inner_body.to_string());
    }
    // 解析対象本文: 復号内容があればそちら、無ければ外側本文。
    // 画面表示用の `body_text` / srcdoc は外側のまま残す (復号本文は
    // 別枠の `mls_plaintexts` で表示)。
    let decrypted_body = mls_plaintexts.join("\n");
    let analysis_text: &str = if mls_payloads.is_empty() {
        &analysis_body
    } else {
        &decrypted_body
    };

    // **実際の Authentication-Results をそのまま使う**。
    // モックでは None を渡していたが、ここでは実データが得られる。
    let auth = kaname_bec::AuthResults {
        spf: map_auth(env.auth_results.spf),
        dkim: map_auth(env.auth_results.dkim),
        dmarc: map_auth(env.auth_results.dmarc),
        arc: match env.auth_results.arc {
            kaname_render::AuthResult::None => None,
            r => Some(map_auth(r)),
        },
    };
    let auth_desc = format!(
        "SPF={:?} DKIM={:?} DMARC={:?} ARC={:?}",
        env.auth_results.spf, env.auth_results.dkim, env.auth_results.dmarc, env.auth_results.arc
    );

    // 本文からリンクを抽出し、bec の URL シグナルに供給する。
    // (従来は &[] を渡しており、実装済みの URL 評価が一度も発火していなかった)
    let mut urls = extract_urls_from_text(analysis_text);
    // D174: List-Unsubscribe ヘッダー内のリンクも評価対象にする —
    // 本文に現れない配信経路専用リンクは URL 抽出を通らなかった。
    if let Some(lu) = &env.list_unsubscribe {
        for part in lu.split(',') {
            let p = part.trim().trim_matches(|c: char| c == '<' || c == '>');
            if p.starts_with("http") && !urls.iter().any(|u| u == p) {
                urls.push(p.to_string());
            }
        }
    }
    // D173: URL スキーム難読化 (hxxp:// defanged、http:\\ バックスラッシュ、
    // Cyrillic 等の見せかけスキーム) — 評判判定には渡せない形のものは
    // 兆候として報告し、正規化できるものは URL 一覧にも追加する。
    let obfuscated_urls = kaname_render::find_obfuscated_url_tokens(analysis_text);
    for o in &obfuscated_urls {
        if let Some(n) = &o.normalized {
            if !urls.iter().any(|u| u == n) {
                urls.push(n.clone());
            }
        }
    }

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
        let n = kaname_memory_guard::normalize_for_matching(analysis_text);
        let n_spaced = kaname_memory_guard::normalize_for_matching_spaced(analysis_text);
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
        evaluate_sender_style(&from_addr_only, analysis_text, send_hour, has_financial).await;

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
    // 送信者履歴 (初回連絡・検証済み・悪意報告等) を引く。
    // 一覧評価 (assess_listing) と同じシグナル集合で判定しないと、
    // 一覧では「検証済み差出人」で減点されていたメールが詳細を
    // 開いた途端に DANGEROUS へ跳ねる (逆も同様) という食い違いが起きる。
    let sender_history = lookup_sender_history(&account_id, &from_addr_only).await;
    let current_domain = from_addr_only
        .rsplit('@')
        .next()
        .map(|d| d.to_lowercase())
        .unwrap_or_default();
    let body_snippet: String = analysis_text.chars().take(500).collect();
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
        body_text: analysis_text,
        auth,
        sender_history: sender_history.as_ref(),
        our_domain: &our,
        known_contacts: &contacts,
        extracted_urls: &urls,
        reply_to: reply_to.as_deref(),
        thread_context: thread_ctx,
        past_thread_bodies: &past_bodies,
        dkim_signature_header: env.dkim_signature.as_deref(),
    };

    let assessment = bec_detector()
        .assess(req)
        .map_err(|e| format!("BEC 判定に失敗: {e}"))?;

    let oobv_level = kaname_oobv::OobvRecommender::new().recommend(analysis_text);

    // 添付を一度だけ検査し、危険判定 (attachments フィールド) と
    // Deepfake 判定の両方に使い回す (filename/declared_mime だけで足りる)。
    let attachment_scans = kaname_render::scan_attachments(bytes);
    let deepfake_pairs: Vec<(String, String)> = attachment_scans
        .iter()
        .map(|a| (a.filename.clone(), a.declared_mime.clone()))
        .collect();
    let deepfake_advisory = DeepfakeAdvisory::new().evaluate(&deepfake_pairs, analysis_text);

    let bec_verdict = match assessment.verdict {
        kaname_bec::Verdict::Safe => "SAFE",
        kaname_bec::Verdict::Advisory => "ADVISORY",
        kaname_bec::Verdict::Suspicious => "SUSPICIOUS",
        kaname_bec::Verdict::Dangerous => "DANGEROUS",
    }
    .to_string();

    // 本文をサニタイズする。HTML 本文があればそれを使う。
    // text/plain 本文を RawHtml としてパースさせると、プレーンテキスト中の
    // `<a href>` 等が「本文として書かれた HTML」として解釈され、テキスト
    // メール内にクリック可能なリンク/装飾が出現する (D152 — 送信者は
    // text/plain で HTML を注入できる)。空サニタイズ結果にして
    // `to_srcdoc` の text_fallback (HTML エスケープ済み pre-wrap) に
    // フォールバックさせる。
    let sanitized = match &env.html_body {
        Some(html) => kaname_render::sanitize_html(html),
        None => kaname_render::sanitize_html(&kaname_render::RawHtml::new(String::new())),
    };
    let srcdoc = kaname_render::to_srcdoc(&sanitized, Some(&body_text));

    // 構造体にムーブする前に、from/subject を使う評価を先に済ませる。
    // 本文の構造リスクに加え、リンク先の評判判定も併記する。
    let mut render_risks = analyze_body_risks(analysis_text);
    // D160: 非表示テキスト混入 (hidden text salting) の兆候。
    if html_extract
        .as_ref()
        .is_some_and(|e| e.hidden_content)
    {
        render_risks.push(
            "HTML 本文に非表示テキスト (display:none 等の隠し文字列) — 検出回避の兆候".to_string(),
        );
    }
    // D162: 表示 URL と実リンク先のドメイン不一致 (URL 偽装)。
    if let Some(e) = &html_extract {
        for m in e.link_mismatches.iter().take(3) {
            render_risks.push(format!(
                "リンク表示先 ({}) と実際のリンク先 ({}) のドメインが異なります (URL 偽装の兆候)",
                m.shown_domain, m.href_domain
            ));
        }
    }
    // D173: URL スキーム難読化 (defanged / backslash / 見せかけスキーム)。
    if !obfuscated_urls.is_empty() {
        render_risks.push(
            "URL スキーム難読化 (hxxp://、http:\\\\、見せかけスキーム等) — フィルタ回避の兆候"
                .to_string(),
        );
    }
    // D164: 複数 From アドレス / Sender ヘッダ不整合の兆候。
    render_risks.extend(from_header_anomalies(&env));

    // D237: tel: リンク (BazaCall 型コールバックフィッシング)
    if html_text.tel_link {
        render_risks.push(
            "電話番号リンク (tel:) — 「クリック不要・電話をかけさせる」誘導経路の可能性があります"
                .to_string(),
        );
    }

    // D238: Content-Disposition: inline で危険拡張子
    if env.inline_dangerous_attachment {
        render_risks.push(
            "Content-Disposition: inline で実行形式の添付 — 「表示」の体裁で実行される偽装の可能性があります"
                .to_string(),
        );
    }

    // D279: boundary= パラメータ欠落
    if env.missing_boundary_param {
        render_risks.push(
            "multipart 宣言なのに boundary= パラメータがありません — 解析不能な手作り生成品の兆候です"
                .to_string(),
        );
    }

    // D280: Content-Type 欠落
    if env.missing_content_type {
        render_risks.push(
            "Content-Type: ヘッダがありません — 型を名乗らない手作り生成品の兆候です".to_string(),
        );
    }

    // D281: Return-Path の不正値
    if env.malformed_return_path {
        render_risks.push(
            "Return-Path: が <> 形でない不正値です — RFC 5321 の形を欠く手作り生成品の兆候です"
                .to_string(),
        );
    }

    // D327: abuse 報告先自称
    if env.abuse_headers {
        render_risks.push(
            "Complaints-To/X-Report-Abuse 等 — 「監視あり」の体裁を自署する兆候です"
                .to_string(),
        );
    }

    // D328: X-MS-Has-Attach 添付存在自称
    if env.has_attach_claim {
        render_risks.push(
            "X-MS-Has-Attach/X-Has-Attach — 輸送系が付ける添付印を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D329: Feedback-ID 自称
    if env.feedback_id {
        render_risks.push(
            "Feedback-ID/X-Feedback-ID — ISP 苦情ループ登録の体裁を自署する兆候です"
                .to_string(),
        );
    }

    // D363: SA 詳細判定値自称
    if env.spam_detail_marks {
        render_risks.push(
            "X-Spam-Report/X-Spam-Details 等 — SA 判定の内訳値を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D364: DCC チェックサム印自称
    if env.dcc_marks {
        render_risks.push(
            "X-DCC-* — 分散検査基盤のチェックサム印を送信側が自称する兆候です".to_string(),
        );
    }

    // D365: 自動生成印自称
    if env.autogen_marks {
        render_risks.push(
            "X-Autogenerated*/X-Autoresponder 等 — 「自動生成である」表示を送信側が書く兆候です"
                .to_string(),
        );
    }

    // D378: ESP 印 (第二群) 自称
    if env.esp2_stamps {
        render_risks.push(
            "X-SparkPost-*/X-MSYS-API/X-SMTP2GO-* 等 — 配信基盤の印を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D379: abuse 情報印自称
    if env.abuseinfo_marks {
        render_risks.push(
            "X-Abuse-Info/X-Antiabuse/X-Complaints-Info 等 — 「監視窓口あり」体裁を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D380: 通知・状態印自称
    if env.notice_marks {
        render_risks.push(
            "X-Spam-Notice/X-Virus-Notice/X-Message-Status 等 — 判定機の通知・状態を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D408: アプライアンス印 (第三群) 自称
    if env.appliance3_marks {
        render_risks.push(
            "X-Barracuda-*/X-Fortimail-*/X-Securence-* 等 — 機器ブランドの記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D409: 最終宛先記録印自称
    if env.finalrcpt_marks {
        render_risks.push(
            "X-Final-Recipient/X-Intended-Recipient/X-Orig-Rcpt-* 等 — 配送機の宛先記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D410: 整合性・ハッシュ印自称
    if env.hash_marks {
        render_risks.push(
            "X-Hash-*/X-Checksum-*/X-MD5-*/X-SHA256-* 等 — 照合機の記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D414: バルク配信印自称
    if env.bulk_marks {
        render_risks.push(
            "X-MSFBL/X-Campaign-*/X-Newsletter-* 等 — バルク配信基盤の記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D415: フィルタ印 (第四群) 自称
    if env.filter4_marks {
        render_risks.push(
            "X-SmartFilter-*/X-ClearMail-*/X-MailControl-* 等 — フィルタ機の記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D416: 断片・継続印自称
    if env.frag_marks {
        render_risks.push(
            "X-Prev-*/X-Fragment-*/X-Partial-* 等 — 断片化機の記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D426: 日本プロバイダ印自称
    if env.jp_provider_marks {
        render_risks.push(
            "X-OCN-*/X-Biglobe-*/X-Nifty-*/X-DTI-* 等 — 国内プロバイダの判定記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D427: ARC/BIMI 印自称
    if env.arc_bimi_marks {
        render_risks.push(
            "ARC-Seal/ARC-Message-Signature/BIMI-Location 等 — 受領鎖・ブランド認証の印を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D428: 再送印自称
    if env.resent_marks {
        render_risks.push(
            "Resent-From/Resent-Sender/Resent-Date 等 — 再送者の経路記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D429: 中国・東アジア系プロバイダ印自称
    if env.cn_provider_marks {
        render_risks.push(
            "X-QQ-*/X-Coremail-*/X-CM-*/X-Alimail-* 等 — 中国系プロバイダの記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D430: AV・検査印 (第三群) 自称
    if env.av3_marks {
        render_risks.push(
            "X-KSMG-*/X-KLMS-*/X-DrWeb-*/X-NAI-* 等 — AV ベンダの検査記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D431: ウェブスクリプト発信印自称
    if env.webscript_marks {
        render_risks.push(
            "X-PHP-*/X-Source-*/X-Authenticated-Sender 等 — ウェブメール発信経路の記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D432: 欧州 ISP 印自称
    if env.eu_provider_marks {
        render_risks.push(
            "X-GMX-*/X-UI-*/X-me-*/X-ProXad-* 等 — 欧州プロバイダの判定記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D433: CIS・韓国系プロバイダ印自称
    if env.cis_provider_marks {
        render_risks.push(
            "X-Mras/X-Mru-*/X-Yandex-*/X-Naver-* 等 — CIS・韓国系プロバイダの判定記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D434: 自動応答・優先度印自称
    if env.autoreply_marks {
        render_risks.push(
            "Auto-Submitted/Precedence/X-Loop/X-Auto-Response-Suppress 等 — 応答機・配送機の記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D435: OSSスキャナ自称
    if env.oss_scan_marks {
        render_risks.push(
            "X-Rspamd-*/X-Spamd-*/X-Amavis-*/X-MailScanner-* 等 — OSS スキャナの検査記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D436: 統計フィルタ自称
    if env.stat_filter_marks {
        render_risks.push(
            "X-DSPAM-*/X-Bogosity/X-Razor*/X-Pyzor-*/X-Greylist*/X-Policy-* 等 — 統計・照合フィルタの記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D437: MTA製品自称
    if env.mta_product_marks {
        render_risks.push(
            "X-Original-To/X-Kerio-*/X-MDAV-*/X-IMSS-*/X-TM-AS-*/X-Domino-*/X-Zimbra-* 等 — MTA・メール製品の受信・検査記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D438: webmail内部印自称
    if env.webmail_internal_marks {
        render_risks.push(
            "X-Gm-*/X-Google-*/X-YMail-*/X-AOL-* 等 — クラウドメールの受信・配送記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D439: ストア状態印自称
    if env.store_status_marks {
        render_risks.push(
            "X-Status/X-UID/X-UIDL/X-Mozilla-Status/X-IMAPbase 等 — メールストアの状態記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D440: 分類ツール印自称
    if env.classifier_marks {
        render_risks.push(
            "X-SB*/X-Spambayes-*/X-Hammie-*/X-Text-Classification 等 — ローカル分類ツールの判定記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D441: MS EOP/Exchange 内部印自称
    if env.ms_eop_marks {
        render_risks.push(
            "X-EOP*/X-Microsoft-Antispam/X-MS-Exchange-*Loop/X-MS-GCC-* 等 — EOP/Exchange の処理記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D442: マーケESP印自称 (第二群)
    if env.marketing_marks {
        render_risks.push(
            "X-ELQ-*/X-MC-*/X-Mailjet-*/X-Pardot-*/X-Mandrill-*/X-Report-Abuse 等 — 配信プラットフォームの記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D443: 業務ツール印自称
    if env.enterprise_marks {
        render_risks.push(
            "X-SFDC-*/X-ServiceNow-*/X-iCIMS-*/X-Zendesk-*/X-Jira-*/X-Workday-* 等 — 業務システムの発信記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D444: エンベロープ配送記録印自称
    if env.envelope_trace_marks {
        render_risks.push(
            "X-Env-*/X-Envelope-*/X-Errors-To/X-VERP-*/X-Bounces-*/X-Redirect-* 等 — 配送経路・返送の記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D445: 送信元IP・認定印自称
    if env.source_ip_marks {
        render_risks.push(
            "X-Originating-IP/X-Client-IP/X-HELO-*/X-EIP/X-CSA-*/X-Lumos-* 等 — 送信元の IP・認定記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D446: 商用ゲートウェイ印自称 (第三群)
    if env.gateway_product_marks {
        render_risks.push(
            "X-GFIME-*/X-SA-Exim-*/X-SpamExperts-*/X-MailMarshal*/X-InterScan-*/X-MIMEsweeper-* 等 — 製品の検査記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D447: ML配信印自称
    if env.mailinglist_marks {
        render_risks.push(
            "X-ML-*/X-MLName/X-Mail-Count/X-Mailman-*/X-List-*/X-Sympa-* 等 — ML・リスト配送機の記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D448: SaaS通知印自称
    if env.saas_notify_marks {
        render_risks.push(
            "X-GitHub-*/X-GitLab-*/X-Jenkins-*/X-PayPal-*/X-DocuSign-*/X-Slack-* 等 — SaaS 通知システムの発信記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D449: アプライアンス印自称 (第四群)
    if env.appliance4_marks {
        render_risks.push(
            "X-Postini-*/X-MXLogic-*/X-PMX-*/X-WatchGuard-*/X-CTCH-*/X-FireEye-* 等 — 製品の検査記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D450: 認証結果印自称
    if env.auth_result_marks {
        render_risks.push(
            "X-Received-SPF/X-SPF-*/X-SID-*/X-DomainKeys-*/X-DKIM-Result 等 — 認証機の検証記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D451: アプライアンス印自称 (第五群)
    if env.appliance5_marks {
        render_risks.push(
            "X-AppRiver-*/X-MessageLabs-*/X-FrontBridge-*/X-FOPE-*/X-RedCondor-*/X-AVG-* 等 — 製品の検査記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D452: 追跡・監査印自称
    if env.tracking_marks {
        render_risks.push(
            "X-AuditID/X-Entity-Ref-ID/X-ASG-Debug-ID/X-CT-RefID/X-Failed-Recipients 等 — 監査・追跡機の記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D453: 欧州・豪州 ISP 印自称 (第二群)
    if env.eu_isp2_marks {
        render_risks.push(
            "X-Arcor-*/X-Strato-*/X-IONOS-*/X-Ziggo-*/X-KPN-*/X-Bluewin-*/X-Telia-*/X-Fastweb-* 等 — ISP の受信記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D454: ウイルススキャン印自称 (第六群)
    if env.virus_scan_marks {
        render_risks.push(
            "X-Virus-Status/X-Virus-Found/X-KAV-*/X-Norman-*/X-FProt-*/X-Malware-* 等 — スキャン機の検査記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D455: DMARC運用・フィッシング評価印自称
    if env.phish_eval_marks {
        render_risks.push(
            "X-Valimail-*/X-dmarcian-*/X-PhishMe-*/X-Cofense-*/X-GoPhish-*/X-PhishLabs-* 等 — 評価機の記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D456: フォーラム・課題管理印自称
    if env.forum_issue_marks {
        render_risks.push(
            "X-Bugzilla-*/X-Phabricator-*/X-Discourse-*/X-YouTrack-*/X-phpBB-*/X-XenForo-* 等 — フォーラム・課題機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D457: アーカイブ・コンプライアンス印自称
    if env.archive_marks {
        render_risks.push(
            "X-GlobalRelay-*/X-Smarsh-*/X-ZL-*/X-Mimosa-*/X-Jatheon-*/X-MailStore-* 等 — アーカイブ機の記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D458: 中国系セキュリティ製品印自称
    if env.cn_sec_marks {
        render_risks.push(
            "X-Sangfor-*/X-NSFOCUS-*/X-TopSec-*/X-Hillstone-*/X-Rising-*/X-Kingsoft-* 等 — 製品の検査記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D459: SNS・プラットフォーム通知印自称
    if env.sns_platform_marks {
        render_risks.push(
            "X-Facebook-*/X-Twitter-*/X-LinkedIn-*/X-Discord-*/X-Spotify-*/X-Meetup-* 等 — SNS 通知機の発信記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D460: 決済・金融サービス印自称
    if env.payment_marks {
        render_risks.push(
            "X-Square-*/X-Adyen-*/X-Klarna-*/X-Wise-*/X-Razorpay-*/X-Alipay-* 等 — 決済機の発信記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D461: 配信ESP・マーケ印自称 (第四群)
    if env.esp4_marks {
        render_risks.push(
            "X-PHPlist-*/X-Mautic-*/X-MoEngage-*/X-OneSignal-*/X-Urban-*/X-Netcore-* 等 — 配信機の記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D462: クラウド・ホスティング印自称
    if env.cloud_host_marks {
        render_risks.push(
            "X-Hetzner-*/X-Scaleway-*/X-Linode-*/X-Vultr-*/X-DigitalOcean-*/X-Heroku-* 等 — クラウド機の発信記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D463: 監視・インシデント・分析印自称
    if env.observability_marks {
        render_risks.push(
            "X-PagerDuty-*/X-Datadog-*/X-NewRelic-*/X-Bugsnag-*/X-Rollbar-*/X-Grafana-* 等 — 監視機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D464: 生産性・フォームサービス印自称
    if env.productivity_marks {
        render_risks.push(
            "X-Asana-*/X-Monday-*/X-Basecamp-*/X-Miro-*/X-Typeform-*/X-JotForm-* 等 — サービス通知機の発信記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D465: 日本系サービス印自称
    if env.jp_service_marks {
        render_risks.push(
            "X-Rakuten-*/X-Mercari-*/X-PayPay-*/X-Livedoor-*/X-Doorkeeper-*/X-AtCoder-* 等 — サービス通知機の発信記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D466: HR・採用印自称 (第二群)
    if env.hr_marks {
        render_risks.push(
            "X-Greenhouse-*/X-Lever-*/X-BambooHR-*/X-ADP-*/X-Gusto-*/X-Workable-* 等 — HR 機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D467: EC・マーケットプレイス印自称
    if env.ecommerce_marks {
        render_risks.push(
            "X-Shopify-*/X-Etsy-*/X-Squarespace-*/X-Magento-*/X-AliExpress-*/X-Zalando-* 等 — EC 機の発信記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D468: 旅行・運輸・フードデリバリー印自称
    if env.travel_marks {
        render_risks.push(
            "X-Uber-*/X-DoorDash-*/X-Grab-*/X-Booking-*/X-Airbnb-*/X-Zomato-* 等 — 旅行・配車・フード機の発信記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D469: CDN・エッジ・マネージドホスティング印自称
    if env.cdn_marks {
        render_risks.push(
            "X-Cloudflare-*/X-Fastly-*/X-Varnish:/X-Sucuri-*/X-WPEngine-*/X-Pantheon-* 等 — CDN・ホスティング機の経路記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D470: メディア・クリエイター・ニュースレター印自称
    if env.media_marks {
        render_risks.push(
            "X-Patreon-*/X-Substack-*/X-Beehiiv-*/X-Libsyn-*/X-Vimeo-*/X-Pixiv-* 等 — メディア機の発信記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D471: ネオバンク・フィンテック印自称 (第二群)
    if env.fintech_marks {
        render_risks.push(
            "X-Revolut-*/X-Plaid-*/X-Affirm-*/X-Venmo-*/X-Robinhood-*/X-Nubank-* 等 — 金融機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D472: 暗号資産・取引所印自称
    if env.crypto_marks {
        render_risks.push(
            "X-Coinbase-*/X-Binance-*/X-Kraken-*/X-Ledger-*/X-OpenSea-*/X-Etherscan-* 等 — 暗号資産機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D473: ゲーム・エンタメ印自称
    if env.gaming_marks {
        render_risks.push(
            "X-Xbox-*/X-Blizzard-*/X-Nintendo-*/X-Roblox-*/X-Steam-*/X-Wargaming-* 等 — ゲーム機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D474: 開発・ID・セキュリティ SaaS 印自称
    if env.enterprise_saas_marks {
        render_risks.push(
            "X-Okta-*/X-Auth0-*/X-CrowdStrike-*/X-Snyk-*/X-HashiCorp-*/X-Bitbucket-* 等 — 業務 SaaS 機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D475: 宅配・物流印自称
    if env.shipping_marks {
        render_risks.push(
            "X-FedEx-*/X-DHL-*/X-UPS-*/X-USPS-*/X-JapanPost-*/X-Yamato-* 等 — 配送機の発信記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D476: 通信 API・サポート印自称
    if env.comms_marks {
        render_risks.push(
            "X-Twilio-*/X-Sinch-*/X-RingCentral-*/X-Vonage-*/X-Infobip-*/X-Webex-* 等 — 通信機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D477: 教育・LMS 印自称
    if env.edu_marks {
        render_risks.push(
            "X-Coursera-*/X-Duolingo-*/X-HackerRank-*/X-Udemy-*/X-Canvas-*/X-Blackboard-* 等 — 教育機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D478: 電子署名・契約管理印自称
    if env.esign_marks {
        render_risks.push(
            "X-EchoSign-*/X-PandaDoc-*/X-HelloSign-*/X-OneSpan-*/X-Yousign-*/X-Ironclad-* 等 — 契約機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D479: クラウドファンディング・寄付印自称
    if env.donation_marks {
        render_risks.push(
            "X-GoFundMe-*/X-Kickstarter-*/X-Indiegogo-*/X-Ko-fi-*/X-JustGiving-*/X-Blackbaud-* 等 — 寄付機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D480: 不動産・ホームサービス印自称
    if env.realestate_marks {
        render_risks.push(
            "X-Zillow-*/X-Redfin-*/X-Rightmove-*/X-SUUMO-*/X-Idealista-*/X-Zoopla-* 等 — 不動産機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D481: ヘルスケア・薬局・DNA 検査印自称
    if env.health_marks {
        render_risks.push(
            "X-Zocdoc-*/X-GoodRx-*/X-Doximity-*/X-LabCorp-*/X-Ancestry-*/X-MyChart-* 等 — 医療機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D482: 求職・人材印自称
    if env.jobs_marks {
        render_risks.push(
            "X-Indeed-*/X-Glassdoor-*/X-ZipRecruiter-*/X-Wellfound-*/X-Mynavi-*/X-doda-* 等 — 人材機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D483: ファイル共有・クラウドストレージ印自称
    if env.storage_marks {
        render_risks.push(
            "X-OneDrive-*/X-SharePoint-*/X-GoogleDrive-*/X-Nextcloud-*/X-WeTransfer-*/X-Egnyte-* 等 — ストレージ機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D484: デザイン・クリエイティブ印自称
    if env.creative_marks {
        render_risks.push(
            "X-Framer-*/X-Zeplin-*/X-Sketch-*/X-Photoshop-*/X-Illustrator-*/X-DaVinci-* 等 — 制作機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D485: ナレッジ・タスク管理・CRM 印自称
    if env.project_marks {
        render_risks.push(
            "X-Qiita-*/X-Zenn-*/X-Backlog-*/X-Kibela-*/X-Taiga-*/X-Pipedrive-* 等 — 管理機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D486: チャット・会議印自称
    if env.meeting_marks {
        render_risks.push(
            "X-Telegram-*/X-WhatsApp-*/X-Mattermost-*/X-Element-*/X-Chatwoot-*/X-BlueJeans-* 等 — 会議機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D487: 予約・スケジューリング印自称
    if env.booking_marks {
        render_risks.push(
            "X-Doodle-*/X-Acuity-*/X-Mindbody-*/X-Vagaro-*/X-Fresha-*/X-Trainerize-* 等 — 予約機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D488: フィールドサービス・設備管理印自称
    if env.fieldservice_marks {
        render_risks.push(
            "X-ServiceTitan-*/X-Jobber-*/X-UpKeep-*/X-Housecall-*/X-MaintainX-*/X-Workiz-* 等 — 設備管理機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D489: 経費・精算印自称
    if env.expense_marks {
        render_risks.push(
            "X-Expensify-*/X-Ramp-*/X-Concur-*/X-Pleo-*/X-Navan-*/X-Dext-* 等 — 経費機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D490: 自動化・データパイプライン印自称
    if env.automation_marks {
        render_risks.push(
            "X-Zapier-*/X-n8n-*/X-Fivetran-*/X-IFTTT-*/X-Workato-*/X-Airbyte-* 等 — 自動化機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D491: 顧客体験・アンケート印自称
    if env.cx_marks {
        render_risks.push(
            "X-Hotjar-*/X-FullStory-*/X-Pendo-*/X-Survicate-*/X-WalkMe-*/X-Appcues-* 等 — 顧客体験機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D492: ドキュメント・静的サイト印自称
    if env.docsite_marks {
        render_risks.push(
            "X-GitBook-*/X-WordPress-*/X-Ghost-*/X-Replit-*/X-StackBlitz-*/X-Feedly-* 等 — 文書機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D493: ポッドキャスト・音楽印自称
    if env.music_marks {
        render_risks.push(
            "X-SoundCloud-*/X-Acast-*/X-DistroKid-*/X-Bandcamp-*/X-TuneCore-*/X-Deezer-* 等 — 音楽機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D494: EC・PC パーツ印自称
    if env.retail_marks {
        render_risks.push(
            "X-Walmart-*/X-Newegg-*/X-Logitech-*/X-Shopware-*/X-Medusa-*/X-Anker-* 等 — 販売機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D495: クラウドプラットフォーム印自称
    if env.cloudprovider_marks {
        render_risks.push(
            "X-AWS-*/X-Azure-*/X-GoogleCloud-*/X-Alibaba-*/X-Oracle-Cloud-*/X-IBMCloud-* 等 — クラウド機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D496: スマートフォン・家電メーカー印自称
    if env.device_marks {
        render_risks.push(
            "X-Samsung-*/X-Sony-*/X-Canon-*/X-Panasonic-*/X-Xiaomi-*/X-Nikon-* 等 — メーカーの通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D497: 音楽制作・オーディオ印自称
    if env.audio_marks {
        render_risks.push(
            "X-YAMAHA-*/X-Ableton-*/X-Steinberg-*/X-Roland-*/X-iZotope-*/X-Waves-* 等 — 音響機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D498: IoT・3D プリント・電子部品印自称
    if env.maker_marks {
        render_risks.push(
            "X-Arduino-*/X-Prusa-*/X-JLCPCB-*/X-Bambu-*/X-RaspberryPi-*/X-SparkFun-*/X-DigiKey-*/X-Mouser-* 等 — 製造機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D499: 監視・ログ基盤印自称
    if env.monitoring_marks {
        render_risks.push(
            "X-Nagios-*/X-Zabbix-*/X-Graylog-*/X-InfluxDB-*/X-Elasticsearch-*/X-SolarWinds-*/X-Checkmk-*/X-Fluentd-* 等 — 監視機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D500: IDE・エディタ・API・稼働監視ツール印自称
    if env.devtools_marks {
        render_risks.push(
            "X-Postman-*/X-VisualStudio-*/X-Statuspage-*/X-Xcode-*/X-IntelliJ-*/X-Neovim-*/X-OhDear-*/X-Eclipse-* 等 — ツール機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D501: DNS・ドメイン・DDNS 印自称
    if env.domain_marks {
        render_risks.push(
            "X-GoDaddy-*/X-Namecheap-*/X-DNSimple-*/X-Porkbun-*/X-Hover-*/X-Route53-*/X-easyDNS-*/X-AzureDNS-* 等 — 名簿機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D502: ウェブホスティング印自称
    if env.webhost_marks {
        render_risks.push(
            "X-DreamHost-*/X-Bluehost-*/X-HostGator-*/X-SiteGround-*/X-Hostinger-*/X-Cloudways-*/X-Nexcess-*/X-AccuWeb-* 等 — 宿機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D503: プライバシーメール印自称
    if env.mailprivacy_marks {
        render_risks.push(
            "X-Proton-*/X-Tutanota-*/X-Fastmail-*/X-Runbox-*/X-Migadu-*/X-StartMail-*/X-Disroot-*/X-Hey-* 等 — 秘匿機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D504: CI/CD・ビルド・バンドラ印自称
    if env.ci_marks {
        render_risks.push(
            "X-Drone-*/X-Concourse-*/X-Bazel-*/X-Gradle-*/X-AppVeyor-*/X-Webpack-*/X-Vite-*/X-ESLint-* 等 — 構築機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D505: コード品質・依存・コンテナセキュリティ印自称
    if env.codequality_marks {
        render_risks.push(
            "X-CodeQL-*/X-Dependabot-*/X-Trivy-*/X-Renovate-*/X-Semgrep-*/X-Wiz-*/X-Falco-*/X-Grype-* 等 — 検査機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D506: パッケージ・レジストリ印自称
    if env.package_marks {
        render_risks.push(
            "X-npmjs-*/X-PyPI-*/X-Docker-Hub-*/X-Homebrew-*/X-RubyGems-*/X-CocoaPods-*/X-GHCR-*/X-vcpkg-* 等 — 庫機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D507: ノート・執筆・PKM 印自称
    if env.notes_marks {
        render_risks.push(
            "X-Joplin-*/X-Logseq-*/X-HackMD-*/X-Typora-*/X-Anytype-*/X-Notability-*/X-DokuWiki-*/X-RemNote-* 等 — 筆記機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D508: 図解・ホワイトボード・マインドマップ印自称
    if env.diagram_marks {
        render_risks.push(
            "X-Excalidraw-*/X-Visio-*/X-MindMeister-*/X-tldraw-*/X-XMind-*/X-Creately-*/X-Padlet-*/X-Ayoa-* 等 — 図機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D509: ローコード・社内ツール・ヘッドレス CMS 印自称
    if env.lowcode_marks {
        render_risks.push(
            "X-Retool-*/X-Supabase-*/X-Strapi-*/X-Budibase-*/X-NocoDB-*/X-Appwrite-*/X-Contentful-*/X-Directus-* 等 — 内機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D510: AI・LLM・音声合成・会話インテリジェンス印自称
    if env.ai_marks {
        render_risks.push(
            "X-OpenAI-*/X-Anthropic-*/X-Cohere-*/X-HuggingFace-*/X-Mistral-*/X-Pinecone-*/X-LangChain-*/X-ElevenLabs-* 等 — 智機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D511: 通信キャリア・MVNO 印自称
    if env.telecom_marks {
        render_risks.push(
            "X-Docomo-*/X-KDDI-*/X-SoftBank-*/X-Verizon-*/X-TMobile-*/X-Vodafone-*/X-Telstra-*/X-Rogers-* 等 — 線機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D512: ブラウザ・検索エンジン印自称
    if env.browser_marks {
        render_risks.push(
            "X-Chrome-*/X-Firefox-*/X-Brave-*/X-DuckDuckGo-*/X-Safari-*/X-Kagi-*/X-TorBrowser-*/X-LibreWolf-* 等 — 覧機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D513: 航空・マイレージ印自称
    if env.airline_marks {
        render_risks.push(
            "X-ANA-*/X-JAL-*/X-United-*/X-Delta-*/X-Emirates-*/X-Qantas-*/X-Ryanair-*/X-Skymark-* 等 — 空機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D514: 伝統銀行・証券印自称
    if env.bank_marks {
        render_risks.push(
            "X-Chase-*/X-MUFG-*/X-SMBC-*/X-HSBC-*/X-WellsFargo-*/X-Barclays-*/X-RakutenBank-*/X-SonyBank-* 等 — 金機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D515: データベース・データウェアハウス印自称
    if env.database_marks {
        render_risks.push(
            "X-MongoDB-*/X-Redis-*/X-Snowflake-*/X-PlanetScale-*/X-Neon-*/X-ClickHouse-*/X-Firebase-*/X-Upstash-* 等 — 庫機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D516: 動画配信・OTT 印自称
    if env.streaming_marks {
        render_risks.push(
            "X-Netflix-*/X-Hulu-*/X-DisneyPlus-*/X-PrimeVideo-*/X-DAZN-*/X-TVer-*/X-Abema-*/X-Roku-* 等 — 映機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D517: パスワード管理・VPN・バックアップ印自称
    if env.consumer_security_marks {
        render_risks.push(
            "X-1Password-*/X-Bitwarden-*/X-NordVPN-*/X-Mullvad-*/X-Backblaze-*/X-Veeam-*/X-Tailscale-*/X-Dashlane-* 等 — 鑰機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D518: 政府・税務・公共機関印自称
    if env.government_marks {
        render_risks.push(
            "X-IRS-*/X-NTA-*/X-GovUK-*/X-SSA-*/X-TurboTax-*/X-HMRC-*/X-myGov-*/X-ATO-* 等 — 官機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D519: 保険会社印自称
    if env.insurance_marks {
        render_risks.push(
            "X-Geico-*/X-AXA-*/X-TokioMarine-*/X-StateFarm-*/X-MetLife-*/X-NipponLife-*/X-Chubb-*/X-Lemonade-* 等 — 保機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D520: 電力・ガス・水道等の公益事業印自称
    if env.utility_marks {
        render_risks.push(
            "X-PGE-*/X-TEPCO-*/X-TokyoGas-*/X-EDF-*/X-Veolia-*/X-DukeEnergy-*/X-KyushuElectric-*/X-HokkaidoElectric-* 等 — 灯機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D521: 自動車メーカー・レンタカー・カーシェア印自称
    if env.automotive_marks {
        render_risks.push(
            "X-Toyota-*/X-Honda-*/X-Hertz-*/X-Tesla-*/X-BMW-*/X-Volvo-*/X-Avis-*/X-Stellantis-* 等 — 車機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D522: 鉄道・公共交通印自称
    if env.rail_marks {
        render_risks.push(
            "X-JREast-*/X-Tokyu-*/X-Amtrak-*/X-DeutscheBahn-*/X-SNCF-*/X-Kintetsu-*/X-TokyoMetro-*/X-Odakyu-* 等 — 軌機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D523: 法務・法曹実務印自称
    if env.legal_marks {
        render_risks.push(
            "X-Clio-*/X-LegalZoom-*/X-Westlaw-*/X-PACER-*/X-Relativity-*/X-Nuix-*/X-Filevine-*/X-MyCase-* 等 — 法機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D524: 出会い系・マッチングアプリ印自称
    if env.dating_marks {
        render_risks.push(
            "X-Tinder-*/X-Bumble-*/X-Hinge-*/X-Pairs-*/X-Omiai-*/X-Match-*/X-Grindr-*/X-eHarmony-* 等 — 遇機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D525: 食料品・日用品・コンビニ・家電・アパレル・百貨店印自称
    if env.grocery_marks {
        render_risks.push(
            "X-Kroger-*/X-Tesco-*/X-AEON-*/X-Lawson-*/X-Uniqlo-*/X-Yodobashi-*/X-Macys-*/X-Coles-* 等 — 商機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D526: 家具・ホームセンター・インテリア印自称
    if env.furniture_marks {
        render_risks.push(
            "X-IKEA-*/X-Wayfair-*/X-Nitori-*/X-Muji-*/X-HomeDepot-*/X-Bunnings-*/X-HermanMiller-*/X-Donki-* 等 — 具機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D527: ドラッグストア・調剤・化粧品印自称
    if env.drugstore_marks {
        render_risks.push(
            "X-Boots-*/X-Matsukiyo-*/X-Welcia-*/X-Sephora-*/X-Tsuruha-*/X-iHerb-*/X-ChemistWarehouse-*/X-Ulta-* 等 — 薬機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D528: ファストフード・飲食チェーン印自称
    if env.restaurant_marks {
        render_risks.push(
            "X-McDonalds-*/X-Starbucks-*/X-Dominos-*/X-KFC-*/X-Sushiro-*/X-MosBurger-*/X-Sukiya-*/X-Wetherspoons-* 等 — 食機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D529: スポーツ・アウトドアブランド印自称
    if env.sports_marks {
        render_risks.push(
            "X-Nike-*/X-Adidas-*/X-Decathlon-*/X-Montbell-*/X-ASICS-*/X-Wilson-*/X-Xebio-*/X-TheNorthFace-* 等 — 武具機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D530: フィットネス・ウェアラブル・ジム印自称
    if env.fitness_marks {
        render_risks.push(
            "X-Fitbit-*/X-Garmin-*/X-Peloton-*/X-Strava-*/X-GoldGym-*/X-KonamiSports-*/X-Calm-*/X-AllTrails-* 等 — 健機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D531: 化粧品・スキンケア・MLM 美容印自称
    if env.beauty_marks {
        render_risks.push(
            "X-Shiseido-*/X-DHC-*/X-Amway-*/X-Fancl-*/X-Kose-*/X-HadaLabo-*/X-Nivea-*/X-CeraVe-* 等 — 美機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D532: 塾・語学・子供教育印自称
    if env.cram_marks {
        render_risks.push(
            "X-Kumon-*/X-Benesse-*/X-Shinkenzemi-*/X-Zkai-*/X-ECC-*/X-Berlitz-*/X-DMMeikaiwa-*/X-IXL-* 等 — 学習機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D533: 日用品・消費財・100 円ショップ・ペット用品印自称
    if env.fmcg_marks {
        render_risks.push(
            "X-Daiso-*/X-PG-*/X-Chewy-*/X-Seria-*/X-Unilever-*/X-Kao-*/X-Zooplus-*/X-AeonPet-* 等 — 日用品機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D534: チケット販売・プレイガイド印自称
    if env.ticket_marks {
        render_risks.push(
            "X-Ticketmaster-*/X-Eplus-*/X-LawsonTicket-*/X-StubHub-*/X-AXS-*/X-Eventim-*/X-CNPlayGuide-*/X-Dice-* 等 — 券機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D535: ホテル・宿泊予約印自称
    if env.hotel_marks {
        render_risks.push(
            "X-Marriott-*/X-Hilton-*/X-ToyokoInn-*/X-Hyatt-*/X-Jalan-*/X-APAHotel-*/X-RakutenTravel-*/X-DormyInn-* 等 — 宿機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D536: テーマパーク・公営競技・映画館・カラオケ・温浴印自称
    if env.leisure_marks {
        render_risks.push(
            "X-Disney-*/X-USJ-*/X-JRA-*/X-TOHO-*/X-Pachinko-*/X-JoySound-*/X-Round1-*/X-Gokurakuyu-* 等 — 娯楽機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D537: 半導体・ストレージ印自称
    if env.semiconductor_marks {
        render_risks.push(
            "X-Intel-*/X-NVIDIA-*/X-AMD-*/X-TSMC-*/X-MediaTek-*/X-Renesas-*/X-SKHynix-*/X-Kioxia-* 等 — 半導体機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D538: 産業機械・重工・建機印自称
    if env.industrial_marks {
        render_risks.push(
            "X-Siemens-*/X-Fanuc-*/X-Komatsu-*/X-ABB-*/X-Keyence-*/X-Yokogawa-*/X-Kubota-*/X-POSCO-* 等 — 産業機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D539: PC・オフィス機器・印刷・計測印自称
    if env.office_marks {
        render_risks.push(
            "X-Dell-*/X-Xerox-*/X-KonicaMinolta-*/X-HP-*/X-Lenovo-*/X-ASUS-*/X-Zebra-*/X-Mimaki-* 等 — 事務機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D540: 航空宇宙・防衛印自称
    if env.aerospace_marks {
        render_risks.push(
            "X-Boeing-*/X-SpaceX-*/X-JAXA-*/X-Airbus-*/X-Lockheed-*/X-MitsubishiHeavy-*/X-NASA-*/X-RocketLab-* 等 — 航機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D541: 地図・ナビ・カーオーディオ・ホームオーディオ印自称
    if env.navigation_marks {
        render_risks.push(
            "X-TomTom-*/X-Navitime-*/X-Pioneer-*/X-Zenrin-*/X-Bose-*/X-Mapbox-*/X-Kenwood-*/X-Sonos-* 等 — 図機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D542: 製薬・バイオ印自称
    if env.pharma_marks {
        render_risks.push(
            "X-Pfizer-*/X-Takeda-*/X-Eisai-*/X-Moderna-*/X-Novartis-*/X-Astellas-*/X-Shionogi-*/X-Gilead-* 等 — 製薬機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D543: 石油・鉱業・エネルギー資源印自称
    if env.energy_marks {
        render_risks.push(
            "X-Shell-*/X-ENEOS-*/X-SaudiAramco-*/X-BP-*/X-Chevron-*/X-Vitol-*/X-RioTinto-*/X-JERA-* 等 — 資機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D544: 医療機器・ライフサイエンス印自称
    if env.medtech_marks {
        render_risks.push(
            "X-Medtronic-*/X-Terumo-*/X-Sysmex-*/X-GEHealthcare-*/X-Shimadzu-*/X-Abbott-*/X-BD-*/X-OlympusMedical-* 等 — 医機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D545: 海運・貨物鉄道・フォワーダ印自称
    if env.freight_marks {
        render_risks.push(
            "X-Maersk-*/X-NYK-*/X-DBSchenker-*/X-CMACGM-*/X-KuehneNagel-*/X-BNSF-*/X-Seino-*/X-HapagLloyd-* 等 — 貨機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D546: 監査・コンサル・格付印自称
    if env.accounting_marks {
        render_risks.push(
            "X-Deloitte-*/X-KPMG-*/X-McKinsey-*/X-PwC-*/X-EY-*/X-Moodys-*/X-Gartner-*/X-Accenture-* 等 — 監機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D547: 賭博・ブックメーカー・カジノ印自称
    if env.gambling_marks {
        render_risks.push(
            "X-Bet365-*/X-toto-*/X-VeraJohn-*/X-DraftKings-*/X-PokerStars-*/X-Caesars-*/X-SBOBET-*/X-BIG-* 等 — 賭機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D548: 警備・清掃・施設管理・引越・ストレージ印自称
    if env.facility_marks {
        render_risks.push(
            "X-SECOM-*/X-ALSOK-*/X-Sakai-*/X-Rentokil-*/X-G4S-*/X-UHaul-*/X-PublicStorage-*/X-Duskin-* 等 — 施機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D549: 放送局・チャンネル印自称
    if env.broadcast_marks {
        render_risks.push(
            "X-NHK-*/X-BBC-*/X-ESPN-*/X-FujiTV-*/X-WOWOW-*/X-HBO-*/X-CNN-*/X-KBS-* 等 — 放機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D550: 新聞・通信社・経済・スポーツメディア印自称
    if env.newspaper_marks {
        render_risks.push(
            "X-Nikkei-*/X-Reuters-*/X-Kyodo-*/X-Yomiuri-*/X-WSJ-*/X-Bloomberg-*/X-AFP-*/X-ToyoKeizai-* 等 — 報機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D551: 食品・飲料・酒・菓子メーカー印自称
    if env.food_marks {
        render_risks.push(
            "X-Nestle-*/X-Suntory-*/X-Nissin-*/X-Ajinomoto-*/X-Heineken-*/X-CocaCola-*/X-Kikkoman-*/X-Glico-* 等 — 食機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D552: 宝飾・時計・高級ブランド印自称
    if env.luxury_marks {
        render_risks.push(
            "X-Rolex-*/X-Cartier-*/X-Hermes-*/X-Mikimoto-*/X-Omega-*/X-Tiffany-*/X-GrandSeiko-*/X-LouisVuitton-* 等 — 奢機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D553: 広告代理店・PR・芸能事務所印自称
    if env.advertising_marks {
        render_risks.push(
            "X-Dentsu-*/X-Hakuhodo-*/X-PRTIMES-*/X-WPP-*/X-CyberAgent-*/X-Avex-*/X-Yoshimoto-*/X-HoriPro-* 等 — 広機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D554: 地方銀行・信用金庫・労金・JA・政府系金融印自称
    if env.regional_bank_marks {
        render_risks.push(
            "X-YokohamaBank-*/X-Shinkin-*/X-JABank-*/X-ChibaBank-*/X-Norinchukin-*/X-77Bank-*/X-FukuokaBank-*/X-Rokin-* 等 — 地機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D555: ミールキット・食材宅配・グルメメディア印自称
    if env.mealkit_marks {
        render_risks.push(
            "X-HelloFresh-*/X-Oisix-*/X-Tabelog-*/X-BlueApron-*/X-Gurunavi-*/X-nosh-*/X-PalSystem-*/X-HotPepper-* 等 — 膳機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D556: 寄付・ふるさと納税・NPO 印自称
    if env.charity_marks {
        render_risks.push(
            "X-RedCross-*/X-Satofuru-*/X-UNICEF-*/X-Furunavi-*/X-WWF-*/X-Oxfam-*/X-RakutenFurusato-*/X-ICRC-* 等 — 善機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D557: 漫画・電子書籍・書店・出版社印自称
    if env.manga_marks {
        render_risks.push(
            "X-Piccoma-*/X-CMOA-*/X-Kodansha-*/X-Webtoon-*/X-Renta-*/X-Shueisha-*/X-Kinokuniya-*/X-BookLive-* 等 — 書機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D558: 玩具・フィギュア・TCG 印自称
    if env.toy_marks {
        render_risks.push(
            "X-LEGO-*/X-TakaraTomy-*/X-Bandai-*/X-GoodSmile-*/X-Kotobukiya-*/X-Tamiya-*/X-Tomica-*/X-Nendoroid-* 等 — 玩機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D559: ホビーショップ・同人・カードショップ・プライズ印自称
    if env.hobby_marks {
        render_risks.push(
            "X-Amiami-*/X-Surugaya-*/X-Mandarake-*/X-YellowSubmarine-*/X-Toranoana-*/X-Clove-*/X-Hareruya-*/X-Banpresto-* 等 — 趣機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D560: 百貨店・アウトレット・商業施設印自称
    if env.department_marks {
        render_risks.push(
            "X-Takashimaya-*/X-Mitsukoshi-*/X-Parco-*/X-Isetan-*/X-Daimaru-*/X-Lumine-*/X-Gotemba-*/X-RoppongiHills-* 等 — 商機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D561: ペット保険・ペットサービス印自称
    if env.pet_service_marks {
        render_risks.push(
            "X-Anicom-*/X-iPet-*/X-Rover-*/X-Trupanion-*/X-Banfield-*/X-FPC-*/X-Petplan-*/X-Figo-* 等 — 愛機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D562: 結婚式場・結婚相談所印自称
    if env.bridal_marks {
        render_risks.push(
            "X-Zexy-*/X-IBJ-*/X-Onet-*/X-Hanayume-*/X-WeddingPark-*/X-TGN-*/X-Marrish-*/X-PlanDoSee-* 等 — 婚機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D563: 動物園・水族館・牧場印自称
    if env.zoo_marks {
        render_risks.push(
            "X-UenoZoo-*/X-Kaiyukan-*/X-Churaumi-*/X-Asahiyama-*/X-TamaZoo-*/X-AdventureWorld-*/X-Sunshine-*/X-Enosui-* 等 — 園機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D564: プロスポーツチーム印自称
    if env.sports_team_marks {
        render_risks.push(
            "X-FMarinos-*/X-Dodgers-*/X-ManUnited-*/X-Gamba-*/X-RealMadrid-*/X-Bayern-*/X-Yankees-*/X-Antlers-* 等 — 球機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D565: 眼鏡・コンタクト・補聴器印自称
    if env.optical_marks {
        render_risks.push(
            "X-Zoff-*/X-JINS-*/X-OWNDAYS-*/X-WarbyParker-*/X-Specsavers-*/X-RayBan-*/X-Phonak-*/X-Oticon-* 等 — 眼機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D566: 気象・地震・防災印自称
    if env.disaster_marks {
        render_risks.push(
            "X-JMA-*/X-WeatherNews-*/X-Yurekuru-*/X-AccuWeather-*/X-NERV-*/X-TenkiJP-*/X-MetOffice-*/X-Windy-* 等 — 防機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D567: クレジットカード印自称
    if env.creditcard_marks {
        render_risks.push(
            "X-VISA-*/X-Mastercard-*/X-Amex-*/X-Saison-*/X-RakutenCard-*/X-Epos-*/X-JACCS-*/X-Orico-* 等 — 札機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D568: ポイント・交通系IC・QR決済印自称
    if env.pointcard_marks {
        render_risks.push(
            "X-TPoint-*/X-Suica-*/X-Ponta-*/X-DPoint-*/X-WAON-*/X-Nanaco-*/X-Merpay-*/X-ICOCA-* 等 — 点機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D569: eSIM・旅行SIM印自称
    if env.esim_marks {
        render_risks.push(
            "X-Airalo-*/X-Holafly-*/X-Ubigi-*/X-Saily-*/X-Nomad-*/X-GigSky-*/X-AloSIM-*/X-MayaMobile-* 等 — 仮機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D572: 車買取・中古車・カー用品印自称
    if env.cartrade_marks {
        render_risks.push(
            "X-Gulliver-*/X-Nextage-*/X-Autobacs-*/X-YellowHat-*/X-Carvana-*/X-CarMax-*/X-Webike-*/X-Kavak-* 等 — 売機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D573: 旅行代理店・ツアー催行印自称
    if env.tour_marks {
        render_risks.push(
            "X-JTB-*/X-HIS-*/X-KNT-*/X-ClubTourism-*/X-Trip-*/X-Viator-*/X-Klook-*/X-Relux-* 等 — 旅機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D574: 占い・電話占い・占星術アプリ印自称
    if env.fortune_marks {
        render_risks.push(
            "X-Vernis-*/X-Minden-*/X-Purely-*/X-Callis-*/X-Keen-*/X-CoStar-*/X-Shiitake-*/X-Getters-* 等 — 鑑機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D575: オンライン診療・健康アプリ印自称
    if env.telehealth_marks {
        render_risks.push(
            "X-Curon-*/X-MICIN-*/X-Medley-*/X-Teladoc-*/X-Doctolib-*/X-BetterHelp-*/X-EPARK-*/X-FiNC-* 等 — 診機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D576: 中古買取・リユース・個人間取引印自称
    if env.reuse_marks {
        render_risks.push(
            "X-Komehyo-*/X-Daikokuya-*/X-Nanboya-*/X-GOAT-*/X-Carousell-*/X-Leboncoin-*/X-SecondStreet-*/X-Buyma-* 等 — 買機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D577: 自転車・サイクル印自称
    if env.bicycle_marks {
        render_risks.push(
            "X-Giant-*/X-Trek-*/X-Specialized-*/X-Cannondale-*/X-Shimano-*/X-AsahiCycle-*/X-Luup-*/X-Brompton-* 等 — 輪機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D578: 宝くじ・ロト・懸賞当選印自称
    if env.lottery_marks {
        render_risks.push(
            "X-Takarakuji-*/X-Loto6-*/X-Loto7-*/X-Powerball-*/X-MegaMillions-*/X-EuroMillions-*/X-DreamJumbo-*/X-Lottery-* 等 — 宝機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D579: 住宅メーカー・リフォーム印自称
    if env.housing_marks {
        render_risks.push(
            "X-SekisuiHouse-*/X-DaiwaHouse-*/X-Lixil-*/X-Misawa-*/X-Tamahome-*/X-YKKAP-*/X-HomePro-*/X-MitsuiHome-* 等 — 宅機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D580: 葬儀・終活印自称
    if env.funeral_marks {
        render_risks.push(
            "X-IiSougi-*/X-KamakuraShinsho-*/X-SagamiSourei-*/X-Tear-*/X-AeonSousai-*/X-EndingPark-*/X-Hanasou-*/X-Farewell-* 等 — 葬機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D581: 消費者金融・カードローン印自称
    if env.consumerloan_marks {
        render_risks.push(
            "X-Acom-*/X-Promise-*/X-Aiful-*/X-Mobit-*/X-LakeALSA-*/X-Central-*/X-Futaba-*/X-SkyOffice-* 等 — 銭機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D582: ベビー・子育て印自称
    if env.baby_marks {
        render_risks.push(
            "X-Akachan-*/X-Nishimatsuya-*/X-Pigeon-*/X-Combi-*/X-Mikihouse-*/X-ToysRUs-*/X-Ergobaby-*/X-Babybjorn-* 等 — 児機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D583: 花・フラワーギフト印自称
    if env.flower_marks {
        render_risks.push(
            "X-Hibiya-*/X-Hanacupid-*/X-AoyamaFlower-*/X-Teleflora-*/X-Interflora-*/X-FTD-*/X-UrbanStems-*/X-1-800Flowers-* 等 — 花機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D584: 家事代行・ハウスクリーニング印自称
    if env.housekeeping_marks {
        render_risks.push(
            "X-Bears-*/X-CaSy-*/X-Minimaid-*/X-Pinai-*/X-Taskaji-*/X-Osoujihonpo-*/X-Kajita-*/X-Zehitomo-* 等 — 房機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D585: 通販・TVショッピング印自称
    if env.mailorder_marks {
        render_risks.push(
            "X-QVC-*/X-ShopChannel-*/X-Japanet-*/X-Bellemaison-*/X-Nissen-*/X-Cecile-*/X-Dinos-*/X-Felissimo-* 等 — 購機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D586: 債務整理・過払い金印自称
    if env.debtrelief_marks {
        render_risks.push(
            "X-AichiLaw-*/X-TokyoMinerva-*/X-NihonPlum-*/X-DaiichiSogo-*/X-HomeWon-*/X-Avance-*/X-Sugiyama-*/X-Kabarai-* 等 — 務機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D587: サプリメント・健康食品印自称
    if env.supplement_marks {
        render_risks.push(
            "X-Yazuya-*/X-Egao-*/X-Kyusai-*/X-NatureMade-*/X-Orihiro-*/X-SeedComs-*/X-AFC-*/X-USANA-* 等 — 滋機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D588: ウォーターサーバー・宅配水印自称
    if env.waterserver_marks {
        render_risks.push(
            "X-Crecla-*/X-AquaClara-*/X-CosmoWater-*/X-Frecious-*/X-PremiumWater-*/X-Urunon-*/X-Kirala-*/X-WaterStand-* 等 — 水機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D589: M&A・事業承継印自称
    if env.maadvisory_marks {
        render_risks.push(
            "X-NihonMA-*/X-StrikeMA-*/X-Batonz-*/X-Tranbi-*/X-Atracs-*/X-MASoken-*/X-Fundbook-*/X-RecofMA-* 等 — 継機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D590: 印刷・名刺通販印自称
    if env.printing_marks {
        render_risks.push(
            "X-Raksul-*/X-Printpac-*/X-Graphic-*/X-Banfu-*/X-Meishi21-*/X-Vistaprint-*/X-CanvaPrint-*/X-Shutterfly-* 等 — 刷機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D591: 介護・ケアサービス印自称
    if env.eldercare_marks {
        render_risks.push(
            "X-Tsukui-*/X-Care21-*/X-SentCare-*/X-Solasto-*/X-Kiracare-*/X-MagokoroKaigo-*/X-Hohoemi-*/X-NursingCare-* 等 — 介機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D592: 保険相談・保険比較印自称
    if env.insconsult_marks {
        render_risks.push(
            "X-HokenNoMadoguchi-*/X-HokenMinoshi-*/X-HokenClinic-*/X-ManeDoc-*/X-HokenIchiba-*/X-HokenTerrace-*/X-MitsubachiHoken-*/X-LifullHoken-* 等 — 保機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D593: ポイ活・お小遣いサイト印自称
    if env.pointkatsu_marks {
        render_risks.push(
            "X-Moppy-*/X-Hapitas-*/X-Gendama-*/X-Chobirich-*/X-PointTown-*/X-ECNavi-*/X-Warau-*/X-GetMoney-* 等 — 稼機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D594: マッサージ・整体・リラク印自称
    if env.massage_marks {
        render_risks.push(
            "X-Rirakuru-*/X-Raffine-*/X-Temomin-*/X-KaradaFactory-*/X-Manistare-*/X-Rafure-*/X-Bantomiere-*/X-Taraso-* 等 — 揉機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D595: 駐車場・コインパーキング印自称
    if env.parking_marks {
        render_risks.push(
            "X-TimesPark-*/X-Times24-*/X-MitsuRepark-*/X-NPC24H-*/X-ApplePark-*/X-CoinPark-*/X-SmartPark-*/X-MyParking-* 等 — 停機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D596: 神社仏閣・宗教印自称
    if env.shrine_marks {
        render_risks.push(
            "X-Isejingu-*/X-Meijijingu-*/X-IzumoTaisha-*/X-Sensoji-*/X-Kiyomizudera-*/X-Todaiji-*/X-Horyuji-*/X-Naritasan-* 等 — 社機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D597: コワーキング・貸会議室印自称
    if env.coworking_marks {
        render_risks.push(
            "X-WeWork-*/X-Regus-*/X-Servcorp-*/X-CompassOffice-*/X-BusinessAirport-*/X-TKP-*/X-HotDesk-*/X-MeetingHub-* 等 — 働機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D598: 会計ソフト・税務申告印自称
    if env.taxfiling_marks {
        render_risks.push(
            "X-Freee-*/X-MoneyForward-*/X-Yayoi-*/X-TKC-*/X-KakuteiShinkoku-*/X-Zeirishi-*/X-RefundTax-*/X-Misoca-* 等 — 税機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D599: ゴルフ場・練習場印自称
    if env.golfcourse_marks {
        render_risks.push(
            "X-PGM-*/X-Accordia-*/X-TaiheiyoClub-*/X-JumboGolf-*/X-GolfNow-*/X-NikiGolf-*/X-VictoriaGolf-*/X-CountryClub-* 等 — 場機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D600: 釣具・フィッシング印自称
    if env.fishing_marks {
        render_risks.push(
            "X-Joshuya-*/X-Casting-*/X-Tsurigu-*/X-DaiwaSeiko-*/X-Gamakatsu-*/X-Megabass-*/X-Varivas-*/X-FishingMaru-* 等 — 釣機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D601: クリーニング・宅配洗濯印自称
    if env.cleaning_marks {
        render_risks.push(
            "X-Hakuyosha-*/X-PonyCleaning-*/X-Sentakubin-*/X-Lenet-*/X-Kireina-*/X-CleanKing-*/X-FutonClean-*/X-RoyalClean-* 等 — 濯機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D602: ヨガ・ピラティス印自称
    if env.yoga_marks {
        render_risks.push(
            "X-Caldo-*/X-ZenPlace-*/X-Loive-*/X-HotYoga-*/X-StudioYoga-*/X-AloMoves-*/X-MoonYoga-*/X-PilatesK-* 等 — 瑜機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D603: 将棋・囲碁・ボードゲーム印自称
    if env.boardgame_marks {
        render_risks.push(
            "X-ShogiWars-*/X-ShogiClub24-*/X-IgoNet-*/X-NihonKiin-*/X-81Dojo-*/X-Pandanet-*/X-BGG-*/X-Wingspan-* 等 — 棋機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D604: 写真プリント・フォトブック印自称
    if env.photoprint_marks {
        render_risks.push(
            "X-Photoback-*/X-Albus-*/X-Dotti-*/X-Asukabook-*/X-PhotobookJP-*/X-Memolee-*/X-FotoKite-*/X-PhotoCanvas-* 等 — 像機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D605: 学習塾・予備校印自称
    if env.jyuku_marks {
        render_risks.push(
            "X-YotsuyaOhtsuka-*/X-Eikoh-*/X-Meikoh-*/X-TryJyuku-*/X-Nichinoken-*/X-Sapix-*/X-Ichishin-*/X-Rinkai-* 等 — 塾機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D606: 文房具・画材印自称
    if env.stationery_marks {
        render_risks.push(
            "X-Kokuyo-*/X-PlusStationery-*/X-SakuraCraypas-*/X-Pentel-*/X-MitsubishiPencil-*/X-PilotPen-*/X-Tombow-*/X-Staedtler-* 等 — 筆機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D607: 家計簿・資産管理アプリ印自称
    if env.budgetapp_marks {
        render_risks.push(
            "X-Zaim-*/X-Kakebo-*/X-WealthNavi-*/X-MoneyTree-*/X-DrWallet-*/X-Acorn-*/X-Finbee-*/X-Toraneko-* 等 — 簿機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D608: エステ・脱毛・美容クリニック印自称
    if env.esthe_marks {
        render_risks.push(
            "X-Musee-*/X-TBC-*/X-Kireimo-*/X-GinzaCalla-*/X-ShonanHiyou-*/X-GorillaClinic-*/X-DatsumouSalon-*/X-BiyoClinic-* 等 — 嬢機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D609: バイク・二輪印自称
    if env.bike_marks {
        render_risks.push(
            "X-BikeO-*/X-Harley-*/X-Ducati-*/X-KTMMoto-*/X-Vespa-*/X-Arai-*/X-Shoei-*/X-NirinKan-* 等 — 騎機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D610: 楽器・DTM印自称
    if env.instrument_marks {
        render_risks.push(
            "X-Fender-*/X-Gibson-*/X-Ibanez-*/X-ESPGuitars-*/X-Takamine-*/X-MartinGuitar-*/X-IkebeGakki-*/X-DrumShop-* 等 — 弦機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D611: 資格スクール・通信講座印自称
    if env.license_marks {
        render_risks.push(
            "X-UCan-*/X-TACShool-*/X-OharaSchool-*/X-LECShikaku-*/X-Studing-*/X-Agaroot-*/X-EikenKentei-*/X-MentalKentei-* 等 — 検機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D612: 留学・語学スクール印自称
    if env.abroad_marks {
        render_risks.push(
            "X-RyugakuJournal-*/X-SeikoRyugaku-*/X-RyugakuJohokan-*/X-Smaryu-*/X-WISHRyugaku-*/X-GlobalStudy-*/X-CebuRyugaku-*/X-CanadaRyugaku-* 等 — 留機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D613: 電動工具・DIY印自称
    if env.diytool_marks {
        render_risks.push(
            "X-Makita-*/X-HiKOKI-*/X-BoschTools-*/X-DeWalt-*/X-TruscoNakayama-*/X-SnapOn-*/X-Vessel-*/X-KyoceraTool-* 等 — 具機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D614: 鍵・錠前・防犯印自称
    if env.locksmith_marks {
        render_risks.push(
            "X-KagiKey-*/X-Kyukyu110-*/X-MiwaLock-*/X-GoalLock-*/X-WestLock-*/X-BouhanCamera-*/X-SmartLockShop-*/X-DigitalLock-* 等 — 錠機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D615: パソコン修理・データ復旧印自称
    if env.pcrepair_marks {
        render_risks.push(
            "X-Dospara-*/X-PcRepair-*/X-AosSos-*/X-Hdram-*/X-PcRescue-*/X-MacRepair-*/X-SsdRecovery-*/X-FileRecovery-* 等 — 修機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D616: キャンプ・登山・アウトドア印自称
    if env.camp_marks {
        render_risks.push(
            "X-Nappu-*/X-SnowPeak-*/X-Coleman-*/X-Logos-*/X-DODCamp-*/X-Yamap-*/X-TentRental-*/X-OutdoorGear-* 等 — 野機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D617: 水道・電気・ガス緊急修理印自称
    if env.emergency_marks {
        render_risks.push(
            "X-SuidouKyukyu-*/X-Mizumore-*/X-ToiletFix-*/X-DenkiKoji-*/X-Breaker110-*/X-LeakRescue-*/X-GasRepair-*/X-KyutoPro-* 等 — 配機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D618: プログラミング・ITスクール印自称
    if env.codingschool_marks {
        render_risks.push(
            "X-TechAcademy-*/X-DmmWebcamp-*/X-Potepan-*/X-SamuraiEngineer-*/X-Runteq-*/X-CodingBootcamp-*/X-AiSchool-*/X-EngineerDojo-* 等 — 算機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D619: 造園・剪定・伐採印自称
    if env.garden_marks {
        render_risks.push(
            "X-Zouen-*/X-Sakutei-*/X-Bassai-*/X-Niwashi-*/X-Gaikou-*/X-TreeCare-*/X-LawnCare-*/X-EngeiShop-* 等 — 樹機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D620: 害虫・害獣駆除印自称
    if env.pest_marks {
        render_risks.push(
            "X-Hachikujo-*/X-Shiroari-*/X-NezumiKujo-*/X-GaijuuKujo-*/X-PestControl24-*/X-KujoRescue-*/X-TermitePro-*/X-Hakubishin-* 等 — 駆機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D621: 霊園・墓石・仏壇印自称
    if env.cemetery_marks {
        render_risks.push(
            "X-Reien-*/X-Hakaishi-*/X-Butsudan-*/X-Kaimyou-*/X-Noukotsudou-*/X-EidaiKuyou-*/X-MemorialPark-*/X-GraveStone-* 等 — 墓機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D622: 太陽光・蓄電池・エネルギー設備印自称
    if env.solar_marks {
        render_risks.push(
            "X-Taiyoukou-*/X-Chikuden-*/X-Enefarm-*/X-Hems-*/X-SolarPro-*/X-PvPower-*/X-Uriden-*/X-EcoSolar-* 等 — 蓄機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D623: 骨董・美術品印自称
    if env.antique_marks {
        render_risks.push(
            "X-Kottou-*/X-Bijutsu-*/X-Antique-*/X-ArtDealer-*/X-ArtAuction-*/X-Kanteisho-*/X-UkiyoeShop-*/X-SwordShop-* 等 — 骨機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D624: 着物・和装印自称
    if env.kimono_marks {
        render_risks.push(
            "X-Kimono-*/X-Furisode-*/X-Hakama-*/X-Wasou-*/X-Gofuku-*/X-Kitsuke-*/X-YukataShop-*/X-ObiShop-* 等 — 装機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D625: カルチャー教室印自称
    if env.cultureschool_marks {
        render_risks.push(
            "X-Shodou-*/X-AbcCooking-*/X-BetterHome-*/X-CultureNavi-*/X-KotoSchool-*/X-IkebanaSchool-*/X-TeaClass-*/X-DanceSchool-* 等 — 箏機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D626: 家電・住宅設備修理印自称
    if env.appliancerepair_marks {
        render_risks.push(
            "X-AirConRepair-*/X-FridgeFix-*/X-KadenShuuri-*/X-ApplianceFix-*/X-AppliancePro-*/X-KadenDoctor-*/X-DaikinApp-*/X-MideaApp-* 等 — 家機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D627: ベビーシッター・保育・学童印自称
    if env.babysitter_marks {
        render_risks.push(
            "X-KidsLine-*/X-SmartSitter-*/X-PigeonSitter-*/X-BabysitterPro-*/X-HoikuenNavi-*/X-GakudouNavi-*/X-FamiSapo-*/X-Kodomoen-* 等 — 育機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D628: 翻訳・通訳印自称
    if env.translation_marks {
        render_risks.push(
            "X-Gengo-*/X-HonyakuPro-*/X-TuuyakuPro-*/X-TranslatePro-*/X-InterpreterNavi-*/X-TranslatorPro-*/X-Unbabel-*/X-Smartcat-* 等 — 訳機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D629: 接骨院・鍼灸・整体印自称
    if env.bonesetter_marks {
        render_risks.push(
            "X-Sekkotsuin-*/X-Seitai-*/X-Shinkyu-*/X-Bonesetter-*/X-Chirorin-*/X-Hari-*/X-KaradaNavi-*/X-Moxa-* 等 — 整機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D630: 動物病院・ペット医療印自称
    if env.animalhospital_marks {
        render_risks.push(
            "X-AnimalHospital-*/X-VetNavi-*/X-PetVet-*/X-JuiNavi-*/X-DobutsuNavi-*/X-AhbNavi-*/X-WanwanNavi-*/X-PetCareNavi-* 等 — 獣機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D631: 不用品回収・遺品整理・粗大ゴミ印自称
    if env.bulkwaste_marks {
        render_risks.push(
            "X-Fuyohin-*/X-IhinNavi-*/X-SoudaiNavi-*/X-KaishuunNavi-*/X-WasteNavi-*/X-JunkNavi-*/X-GomigoNavi-*/X-BenriyaNavi-* 等 — 廃機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D632: 寝具・マットレス印自称
    if env.bedding_marks {
        render_risks.push(
            "X-Nishikawa-*/X-Francebed-*/X-Airweave-*/X-BeddingPro-*/X-FutonNavi-*/X-MattressNavi-*/X-MakuraNavi-*/X-SleepNavi-* 等 — 寝機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D633: 手芸・毛糸・ミシン印自称
    if env.craft_marks {
        render_risks.push(
            "X-Hamanaka-*/X-Clovercraft-*/X-Yuzawaya-*/X-Okadaya-*/X-CraftNavi-*/X-KeitoNavi-*/X-ShugeiNavi-*/X-QuiltNavi-* 等 — 裁機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D634: 農業資材・種苗・肥料印自称
    if env.farm_marks {
        render_risks.push(
            "X-Kumiai-*/X-Takii-*/X-Sakata-*/X-FarmNavi-*/X-Noukasonavi-*/X-Syubyou-*/X-NougyouNavi-*/X-Zenno-* 等 — 農機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D635: 刃物・包丁・調理道具印自称
    if env.knife_marks {
        render_risks.push(
            "X-Sekimagoroku-*/X-Kaihocho-*/X-Globalknife-*/X-Henckels-*/X-KnifeNavi-*/X-HouchouNavi-*/X-Togishi-*/X-KitchentoolNavi-* 等 — 刃機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D636: 畳・襖・表具印自称
    if env.tatami_marks {
        render_risks.push(
            "X-TatamiNavi-*/X-TatamiCenter-*/X-FusumaNavi-*/X-ShoujiNavi-*/X-Hyouguya-*/X-IgusaNavi-*/X-WashitsuNavi-*/X-TatamiYa-* 等 — 畳機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D637: 温泉・銭湯・入浴印自称
    if env.onsen_marks {
        render_risks.push(
            "X-OnsenNavi-*/X-OnsenCenter-*/X-SentoNavi-*/X-YuNavi-*/X-NyuyokuNavi-*/X-HotspringNavi-*/X-RotenNavi-*/X-SaunaNavi-* 等 — 湯機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D638: 美術館・博物館印自称
    if env.museum_marks {
        render_risks.push(
            "X-MuseumNavi-*/X-Tokyokokuritsu-*/X-Moma-*/X-Louvremuseum-*/X-BijutsukanNavi-*/X-GalleryNavi-*/X-ExhibNavi-*/X-GhibliMuseum-* 等 — 博機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D639: 劇場・ミュージカル・歌舞伎印自称
    if env.theater_marks {
        render_risks.push(
            "X-Takarazuka-*/X-Shiki-*/X-Imperialtheatre-*/X-TheatreNavi-*/X-KabukiNavi-*/X-MusicalNavi-*/X-BalletNavi-*/X-OperaNavi-* 等 — 劇機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D640: アイドル・声優・ファンクラブ印自称
    if env.idol_marks {
        render_risks.push(
            "X-Johnnys-*/X-Sakamichi-*/X-Nogizaka-*/X-IdolNavi-*/X-SeiyuNavi-*/X-FanclubNavi-*/X-OshiNavi-*/X-ChekiNavi-* 等 — 推機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D641: 選挙・政党印自称
    if env.election_marks {
        render_risks.push(
            "X-Senkyo-*/X-ElectionNavi-*/X-Jimintou-*/X-Rikken-*/X-Koumei-*/X-Ishin-*/X-SeijiNavi-*/X-TouhyouNavi-* 等 — 選機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D642: 士業・職業団体・労働組合印自称
    if env.union_marks {
        render_risks.push(
            "X-Rengou-*/X-Zenroren-*/X-Ishikai-*/X-Bengoshi-*/X-UnionNavi-*/X-RodoKumiai-*/X-Zeirishikai-*/X-KyouShokai-* 等 — 士機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D643: 自動車教習所・免許印自称
    if env.drivingschool_marks {
        render_risks.push(
            "X-DrivingNavi-*/X-KyousyuujoNavi-*/X-GasshukuNavi-*/X-MenkyoNavi-*/X-JidoushaGakkouNavi-*/X-UntenshuuryoujoNavi-*/X-Kyourikimajo-*/X-Alcc-* 等 — 習機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D644: 建設・ゼネコン・工事印自称
    if env.construction_marks {
        render_risks.push(
            "X-Kashima-*/X-Obayashi-*/X-Shimizu-*/X-Zenekon-*/X-ZenekonNavi-*/X-KensetsuNavi-*/X-GenbaNavi-*/X-ShokuninNavi-* 等 — 建機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D645: レンタル・リース印自称
    if env.rental_marks {
        render_risks.push(
            "X-NipponRental-*/X-Nikken-*/X-RentalNavi-*/X-LeaseNavi-*/X-RentlareNavi-*/X-KenkireNavi-*/X-Aktio-*/X-Rentrun-* 等 — 貸機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D646: 倉庫・物流センター印自称
    if env.warehouse_marks {
        render_risks.push(
            "X-Souko-*/X-SoukoNavi-*/X-LogisticsNavi-*/X-RojiweedNavi-*/X-RojisuteidoNavi-*/X-OroukuriNavi-*/X-Trunkroom-*/X-HokanNavi-* 等 — 倉機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D647: 大学・専門学校・受験印自称
    if env.college_marks {
        render_risks.push(
            "X-DaigakuNavi-*/X-SenmonGakkouNavi-*/X-YobikouNavi-*/X-BenesseK-*/X-Juuken-*/X-CollegeNavi-*/X-UniversityNavi-*/X-NyuushiNavi-* 等 — 受機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D648: 防犯カメラ・監視印自称
    if env.securitycam_marks {
        render_risks.push(
            "X-BousanNavi-*/X-KanshiKamera-*/X-SecurityCamera-*/X-CameraNavi-*/X-MonitorNavi-*/X-Cctv-*/X-Hikvision-*/X-Dahua-* 等 — 録機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }

    // D649: フェリー・クルーズ・船舶印自称
    if env.ferry_marks {
        render_risks.push(
            "X-Ferry-*/X-FerryNavi-*/X-Cruise-*/X-CruiseNavi-*/X-Senpaku-*/X-KaijiNavi-*/X-ShinMoji-*/X-HankyuFerry-* 等 — 船機の通知記録を送信側が自称する兆候です"
                .to_string(),
        );
    }
    render_risks.extend(evaluate_link_risks(&urls));
    render_risks.extend(evaluate_saas_links(&urls, &from));
    render_risks.extend(style_risks);
    let dlp_findings = scan_dlp_inbound(&subject, analysis_text, &our);

    // `is_mls` バッジはエンベロープの有無で決める — メッセージ本体が
    // エンベロープ内にあるため外側パースでは内容が見えない。

    // MLS KeyPackage 添付の受信 (D1 Phase 3) — 検証して kp_cache に投入。
    // 送信者は外側の From アドレス (エンベロープ内ではなく配送層の属性)。
    let mls_key_packages = kaname_render::extract_mls_key_packages(bytes);
    process_mls_key_packages(&mls_key_packages, &from_addr_only, &mut mls_events);

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
            is_mls: kaname_render::is_mls_message(bytes),
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
        mls_events,
        mls_plaintexts,
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
    /// クラスタリングの根拠を示す表示用文字列 (共通送信ドメイン / 構造パターン)。
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
    info!(path=%redact_path(&path), "mail_scan_folder");

    let mut entries: Vec<FolderScanEntry> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut radar = kaname_radar::CampaignRadar::new();
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    // アカウント・自組織ドメイン (D44)・連絡先一覧は走査全体で1回だけ
    // 解決する (D108: 以前はファイルごとに contacts/account_id を引き直し、
    // N 件の走査で N 回の同一 SELECT/アカウント解決が走っていた)。
    let account_id = current_account_id().await;
    let our = our_domain(&account_id, None).await;
    let contacts = lookup_contacts(&account_id).await;

    // D149: エクスポートされたメールボックスは通常フォルダ単位で
    // ネストしているのに、走査は `read_dir` 一段のみでサブフォルダ内の
    // .eml を**黙って無視**していた — ユーザーが親フォルダを選ぶと
    // 大部分が未走査のまま「解析完了」と表示された。再帰走査に変更し、
    // 深度・件数の上限を明示 (上限超過分は failed に理由付きで表出)。
    const MAX_SCAN_DEPTH: usize = 8;
    const MAX_SCAN_FILES: usize = 5_000;

    let mut eml_paths: Vec<std::path::PathBuf> = Vec::new();
    let mut skipped_deep_dirs = 0usize;
    let mut truncated = false;
    let mut stack = vec![(std::path::PathBuf::from(&path), 0usize)];
    while let Some((dir_path, depth)) = stack.pop() {
        let dir = match std::fs::read_dir(&dir_path) {
            Ok(d) => d,
            Err(e) => {
                if depth == 0 {
                    return Err(format!("フォルダを開けません ({path}): {e}"));
                }
                failed.push((
                    dir_path.to_string_lossy().into_owned(),
                    format!("サブフォルダを開けません: {e}"),
                ));
                continue;
            }
        };
        for item in dir.flatten() {
            let p = item.path();
            match item.file_type() {
                // file_type はシンボリックリンクを辿らないため、
                // リンク先ディレクトリはここに来ずループしない。
                Ok(ft) if ft.is_dir() => {
                    if depth < MAX_SCAN_DEPTH {
                        stack.push((p, depth + 1));
                    } else {
                        skipped_deep_dirs += 1;
                    }
                }
                _ => {
                    // .eml のみを対象にする (拡張子の大小は問わない)。
                    if p.extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e.eq_ignore_ascii_case("eml"))
                    {
                        eml_paths.push(p);
                    }
                }
            }
            if eml_paths.len() >= MAX_SCAN_FILES {
                truncated = true;
                break;
            }
        }
        if truncated {
            break;
        }
    }
    if skipped_deep_dirs > 0 {
        failed.push((
            format!("深度{MAX_SCAN_DEPTH}超のサブフォルダ {skipped_deep_dirs} 件"),
            "走査深度の上限を超えたため未走査".to_string(),
        ));
    }
    if truncated {
        failed.push((
            format!("{MAX_SCAN_FILES} 件以降の .eml"),
            "走査件数の上限を超えたため残りは未走査".to_string(),
        ));
    }
    // read_dir の列挙順は OS 依存なので、結果の再現性のため整列する。
    eml_paths.sort();

    for p in eml_paths {
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
        let plain_text = env.text_body.clone().unwrap_or_default();
        // D160: HTML のみのメールでは text_body が空になり本文解析が
        // 全て素通りする — HTML 側の表示テキストも併合して解析する
        // (analyze_raw_email と同じく、パート不一致回避に備え両方を対象とする)。
        let body_text = match env.html_body.as_ref() {
            Some(h) => {
                let extracted = kaname_render::html_to_text(h.as_str());
                if extracted.text.trim().is_empty() {
                    plain_text
                } else if plain_text.trim().is_empty() {
                    extracted.text
                } else {
                    format!("{plain_text}\n{}", extracted.text)
                }
            }
            None => plain_text,
        };

        let auth = kaname_bec::AuthResults {
            spf: map_auth(env.auth_results.spf),
            dkim: map_auth(env.auth_results.dkim),
            dmarc: map_auth(env.auth_results.dmarc),
            arc: match env.auth_results.arc {
                kaname_render::AuthResult::None => None,
                r => Some(map_auth(r)),
            },
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

        // 本文からリンクを抽出し、bec の URL シグナルに供給する。
        let urls = extract_urls_from_text(&body_text);

        let reply_to = env.reply_to.first().map(|a| a.addr.as_string());
        let return_path = env.return_path.as_ref().map(|a| a.addr.as_string());
        // スレッド乗っ取り検出: In-Reply-To/References が指す既知メッセージを
        // Store から逆引きし、スレッド履歴を組み立てる。
        let mut ref_ids = env.in_reply_to.clone();
        ref_ids.extend(env.references.iter().cloned());
        ref_ids.dedup();
        let (known_ids, thread_domains, prior_subject, prior_language, past_bodies) =
            build_thread_data(&account_id, None, &ref_ids).await;
        // 送信者履歴 — analyze_raw_email / assess_listing と同じシグナル集合で
        // 判定しないと、フォルダ走査だけ判定が食い違う (D100)。
        let sender_history = lookup_sender_history(&account_id, &from).await;
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
            sender_history: sender_history.as_ref(),
            our_domain: &our,
            known_contacts: &contacts,
            extracted_urls: &urls,
            reply_to: reply_to.as_deref(),
            thread_context: thread_ctx,
            past_thread_bodies: &past_bodies,
            dkim_signature_header: env.dkim_signature.as_deref(),
        };

        let (verdict, score) = match bec_detector().assess(req) {
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
            shared_infrastructure: describe_campaign_key(&g.shared_infrastructure),
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
/// キャンペーングループの内部キーをユーザー向けの説明文に変換する。
///
/// `unknown:<domain>` → 同一送信ドメイン、`pattern:auth_fail:subject_<bucket>` →
/// 認証失敗と件名長の共通構造パターン。
fn describe_campaign_key(key: &str) -> String {
    if let Some(domain) = key.strip_prefix("unknown:") {
        return format!("同一送信ドメイン: {domain}");
    }
    if let Some(bucket) = key.strip_prefix("pattern:auth_fail:subject_") {
        return format!("認証失敗+件名の長さ ({bucket}) の共通パターン");
    }
    key.to_string()
}

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

/// D164: From ヘッダの複数アドレス / Sender ヘッダ不整合の兆候を返す。
///
/// RFC 5322 §3.6.2 — From が複数アドレスを持つ場合、実送信者を示す
/// `Sender:` が必須とされる。しかしメールクライアントは表示に複数
/// From のどのアドレスを採用するか実装ごとに差があり (あるパーサは
/// 先頭、別のパーサは末尾や全体連結を表示)、この差異を突く
/// 「parser differential」型のなりすましが知られている
/// (`From: ceo@corp.com, attacker@evil.xyz` でクライアントには
/// CEO と見せる)。検査側も `env.from.first()` で最初の 1 件だけを
/// 見ていたため、2 番目以降の混入アドレスは誰も評価していなかった。
///
/// 判定:
/// - 複数 From + `Sender:` なし → RFC 違反 (強い兆候)
/// - 複数 From + `Sender:` が From 群のいずれとも不一致 → RFC 違反
///   (Sender は From メールボックスの 1 つであるべき)
/// - 複数 From + `Sender:` が From 群に一致 → 規定準拠だが
///   表示パーサ差異のリスクは残る (軽い兆候)
/// - 単一 From + `Sender:` ドメイン不一致 → 「on behalf of」委任送信の
///   正常形なので報告しない (ESP 経由配信で頻出するため誤検出が多い)
fn from_header_anomalies(env: &kaname_render::Envelope) -> Vec<String> {
    if env.from.len() <= 1 {
        return Vec::new();
    }
    let addrs: Vec<String> = env
        .from
        .iter()
        .take(5)
        .map(|a| a.addr.as_string())
        .collect();
    let joined = addrs.join(", ");
    let more = if env.from.len() > 5 {
        format!(" 他 {} 件", env.from.len() - 5)
    } else {
        String::new()
    };
    match &env.sender {
        None => vec![format!(
            "From ヘッダに複数アドレスがあります ({joined}{more}) — Sender ヘッダがなく \
            RFC 5322 違反。クライアントにより表示される差出人が変わる、\
            なりすまし (parser differential) の兆候です"
        )],
        Some(s) => {
            let s_addr = s.addr.as_string();
            if env.from.iter().any(|a| a.addr.as_string() == s_addr) {
                vec![format!(
                    "From ヘッダに複数アドレスがあります ({joined}{more}) — \
                    クライアントにより表示される差出人が変わる可能性がある \
                    (parser differential) の兆候です"
                )]
            } else {
                vec![format!(
                    "From ヘッダに複数アドレス ({joined}{more}) があり、Sender \
                    ({s_addr}) がいずれとも一致しません — Sender は From の \
                    1 つであるべきという RFC 5322 違反。なりすましの兆候です"
                )]
            }
        }
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

/// ログ用にパスを葉名だけに落とす (I5: フルパスは `/Users/<name>` 等の
/// OS ユーザー名・ディレクトリ構造をログへ漏らすため) (D96)。
fn redact_path(p: &str) -> &str {
    std::path::Path::new(p)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<path>")
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

pub async fn log_error(message: String) -> Result<(), String> {
    error!(source = "frontend", %message);
    Ok(())
}

// ── モックデータ ──────────────────────────────────────────────────────────────

// ── テスト ────────────────────────────────────────────────────────────────────

// テスト間の直列化 (D115): `STORE`/`JMAP_SESSION`/`STYLE_PROFILES` は
// プロセス内共有の OnceLock グローバルのため、それらを触るテストが
// 並行実行されると互いの状態を踏んで不定失敗する (実際に
// `persist_org_domain_if_unset`/`文体プロファイル`/`outbound_dlp_eval`/
// `analyze_raw_email_uses_verified_sender_history` が競合で落ちた)。
// 全 `#[tokio::test]` は先頭でこのロックを取ること。
#[cfg(test)]
static TEST_SERIAL: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

#[cfg(test)]
async fn test_serial() -> tokio::sync::MutexGuard<'static, ()> {
    TEST_SERIAL
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

/// テストの決定的初期状態。直列化だけでは先行テストが残した
/// Store/JMAP/文体プロファイルが後続に漏れる (`if is_none()` ガードは
/// 「他テストの Store を流用する」ため却って汚染源になる)。
/// 各テストはロック取得直後にこれを呼び、必要なら自分の Store を開く。
#[cfg(test)]
async fn reset_globals() {
    *jmap_slot().lock().await = None;
    *store_slot().lock().await = None;
    style_profiles().lock().await.clear();
    *mls_slot().lock().unwrap_or_else(|e| e.into_inner()) = None;
    // Drop でワーカープロセスが終了する
    *llm_slot().lock().unwrap_or_else(|e| e.into_inner()) = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_returns_ok() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let r = health_check().await.map_err(|e| e.to_string())?;
        assert!(r.ok);
        assert!(!r.version.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn summary_has_counts() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let r = mail_get_summary().await.map_err(|e| e.to_string())?;
        assert!(r.unread <= r.total);
        Ok(())
    }

    #[tokio::test]
    async fn log_error_ok() {
        let _serial = test_serial().await;
        reset_globals().await;
        assert!(log_error("test".into()).await.is_ok());
    }

    #[test]
    fn redact_path_はフルパスを葉名に落とす() {
        // D96/I5: `/Users/<name>` のような OS ユーザー名を含む親パスが
        // ログに出ないことを固定する。
        assert_eq!(
            redact_path("/Users/alice/Library/Application Support/Kaname/history.db"),
            "history.db"
        );
        assert_eq!(redact_path("/home/bob/mail/田中さん.eml"), "田中さん.eml");
        assert_eq!(redact_path("history.db"), "history.db");
        assert_eq!(redact_path(""), "<path>");
        assert_eq!(redact_path("/"), "<path>");
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
        let _serial = test_serial().await;
        reset_globals().await;
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

    /// D152: text/plain メールを HTML としてパースすると、本文中の
    /// `<a href>` がクリック可能なリンクになる — プレーンテキストとして
    /// 届いたメールに送信者が HTML を注入できる。srcdoc に未エスケープの
    /// `<a ` タグが残らないことを固定する。
    #[tokio::test]
    async fn analyze_raw_email_はプレーン本文中のhtmlをリンク化しない() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let eml = b"From: mallory@evil.example\r\n\
            To: bob@example.com\r\n\
            Subject: plain text mail\r\n\
            Content-Type: text/plain; charset=utf-8\r\n\
            \r\n\
            See <a href=\"https://phish.example/login\">your invoice</a> here.\r\n";
        let r = analyze_raw_email(eml).await?;
        assert!(
            !r.body.srcdoc.contains("<a "),
            "text/plain 本文中の HTML が解釈されている: {}",
            &r.body.srcdoc[..r.body.srcdoc.len().min(500)]
        );
        assert!(
            r.body.srcdoc.contains("&lt;a "),
            "本文テキストはエスケープされて表示されるべき"
        );
        Ok(())
    }

    #[tokio::test]
    async fn analyze_raw_email_bec_wire_transfer_triggers_oobv() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
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

    /// D160: HTML のみのメール (text/plain パートなし) は `text_body` が空で
    /// あり、従来は本文解析が全て素通りしていた — BEC/キーワード/OOBV が
    /// 機能するためには HTML 側の表示テキストを解析対象に含める必要がある。
    /// ユーザーに実際に見える本文を採点することを固定する。
    const HTML_ONLY_BEC_EML: &[u8] = b"From: \"CEO\" <ceo@arnazon-billing.com>\r\n\
        To: you@example.com\r\n\
        Subject: URGENT wire transfer needed today\r\n\
        Date: Mon, 26 Apr 2026 10:15:00 +0900\r\n\
        Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=arnazon-billing.com; dkim=fail header.d=arnazon-billing.com; dmarc=fail header.from=arnazon-billing.com\r\n\
        Content-Type: text/html; charset=utf-8\r\n\
        \r\n\
        <html><body><p>I need you to process an <b>urgent wire transfer</b> immediately.</p>\r\n\
        <p>Our bank account has changed. Please send the payment today.</p>\r\n\
        <p>Do not discuss this with anyone.</p></body></html>\r\n";

    #[tokio::test]
    async fn analyze_raw_email_はhtmlのみメールの本文を解析する() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let r = analyze_raw_email(HTML_ONLY_BEC_EML).await?;
        assert_eq!(
            r.oobv_level, "strong",
            "HTML 本文中の送金要求+緊急性は OOBV を強く推奨すべき: {:?}",
            r.bec_signals
        );
        assert!(
            r.bec_signals.iter().any(|s| s.contains("送金") || s.contains("緊急")),
            "HTML 本文の金融/緊急キーワードがシグナル化されるべき: {:?}",
            r.bec_signals
        );
        Ok(())
    }

    /// D160: hidden text salting — 非表示 CSS で語を分断する塩を落とし、
    /// 可視テキストを復元してキーワード検出に載せる。大量の隠し文字列は
    /// 兆候として render_risks に報告されることも固定する。
    #[tokio::test]
    async fn analyze_raw_email_はhidden_text_saltingを落として検出する() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let salt = "Q".repeat(64);
        let eml = format!(
            "From: ceo@arnazon-billing.com\r\n\
             To: you@example.com\r\n\
             Subject: payment\r\n\
             Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=arnazon-billing.com; dkim=fail header.d=arnazon-billing.com; dmarc=fail header.from=arnazon-billing.com\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             \r\n\
             <html><body><p>urgent wi<span style=\"display:none\">{salt}</span>re \
             transfer</p></body></html>\r\n"
        );
        let r = analyze_raw_email(eml.as_bytes()).await?;
        assert!(
            r.bec_signals.iter().any(|s| s.contains("送金") || s.contains("緊急")),
            "salt で分断されたキーワードを復元して検出すべき: {:?}",
            r.bec_signals
        );
        assert!(
            r.render_risks.iter().any(|s| s.contains("非表示")),
            "大量の非表示テキストは兆候として報告されるべき: {:?}",
            r.render_risks
        );
        Ok(())
    }

    /// D160: multipart/alternative で text/plain に無害文・text/html に
    /// 攻撃文を置く「パート不一致」回避 — 両パートを併合解析すれば
    /// HTML 側の攻撃文がヒットする。
    #[tokio::test]
    async fn analyze_raw_email_はtext_html不一致もhtml側を解析する() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let eml = b"From: ceo@arnazon-billing.com\r\n\
            To: you@example.com\r\n\
            Subject: hello\r\n\
            Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=arnazon-billing.com; dkim=fail header.d=arnazon-billing.com; dmarc=fail header.from=arnazon-billing.com\r\n\
            Content-Type: multipart/alternative; boundary=\"alt\"\r\n\
            \r\n\
            --alt\r\n\
            Content-Type: text/plain; charset=utf-8\r\n\
            \r\n\
            Just checking in. Nothing to see here.\r\n\
            --alt\r\n\
            Content-Type: text/html; charset=utf-8\r\n\
            \r\n\
            <html><body><p>process an urgent wire transfer immediately</p></body></html>\r\n\
            --alt--\r\n";
        let r = analyze_raw_email(eml).await?;
        assert!(
            r.bec_signals.iter().any(|s| s.contains("送金") || s.contains("緊急")),
            "text/plain のデコイに関わらず HTML 側の攻撃文を検出すべき: {:?}",
            r.bec_signals
        );
        Ok(())
    }

    /// D162: アンカーテキストが URL 形で実リンク先とドメインが異なる
    /// (表示は正規サイト・実リンクは別ドメイン) — render_risks に
    /// URL 偽装の兆候を報告する。
    #[tokio::test]
    async fn analyze_raw_email_は表示urlと実リンクの不一致を検出する() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let eml = b"From: notice@arnazon-billing.com\r\n\
            To: you@example.com\r\n\
            Subject: Account verification\r\n\
            Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=arnazon-billing.com; dkim=fail header.d=arnazon-billing.com; dmarc=fail header.from=arnazon-billing.com\r\n\
            Content-Type: text/html; charset=utf-8\r\n\
            \r\n\
            <html><body><p>Verify your account: \
            <a href=\"https://evil-credential-harvest.example/login\">https://paypal.com/login</a>\
            </p></body></html>\r\n";
        let r = analyze_raw_email(eml).await?;
        assert!(
            r.render_risks.iter().any(|s| s.contains("URL 偽装")),
            "表示 URL と実リンク先のドメイン不一致は兆候として報告されるべき: {:?}",
            r.render_risks
        );
        Ok(())
    }

    /// D164: `From: a@x, b@y` (Sender なし) — RFC 5322 違反の複数
    /// From は表示側のパーサ差異を突くなりすまし。兆候として報告する。
    #[tokio::test]
    async fn analyze_raw_email_はsenderなし複数fromを検出する() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let eml = b"From: ceo@corp.example, attacker@evil.example\r\n\
            To: you@example.com\r\n\
            Subject: Urgent request\r\n\
            Content-Type: text/plain; charset=utf-8\r\n\
            \r\n\
            Please proceed.\r\n";
        let r = analyze_raw_email(eml).await?;
        assert!(
            r.render_risks
                .iter()
                .any(|s| s.contains("複数アドレス") && s.contains("Sender")),
            "Sender なし複数 From は RFC 違反として報告されるべき: {:?}",
            r.render_risks
        );
        Ok(())
    }

    /// D164: 複数 From + Sender が From 群に不一致 — RFC 5322 違反
    /// (Sender は From メールボックスの 1 つであるべき)。
    #[tokio::test]
    async fn analyze_raw_email_はfrom群にないsenderを検出する() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let eml = b"From: ceo@corp.example, attacker@evil.example\r\n\
            Sender: unrelated@third.example\r\n\
            To: you@example.com\r\n\
            Subject: Urgent request\r\n\
            Content-Type: text/plain; charset=utf-8\r\n\
            \r\n\
            Please proceed.\r\n";
        let r = analyze_raw_email(eml).await?;
        assert!(
            r.render_risks
                .iter()
                .any(|s| s.contains("一致しません")),
            "From 群にない Sender は RFC 違反として報告されるべき: {:?}",
            r.render_risks
        );
        Ok(())
    }

    /// D164: 複数 From + Sender が From 群に一致 — RFC 準拠だが
    /// parser differential の兆候は報告する。
    #[tokio::test]
    async fn analyze_raw_email_は正当sender付き複数fromを軽く報告する() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let eml = b"From: ceo@corp.example, pa@corp.example\r\n\
            Sender: pa@corp.example\r\n\
            To: you@example.com\r\n\
            Subject: Hello\r\n\
            Content-Type: text/plain; charset=utf-8\r\n\
            \r\n\
            Hello.\r\n";
        let r = analyze_raw_email(eml).await?;
        assert!(
            r.render_risks
                .iter()
                .any(|s| s.contains("parser differential")),
            "Sender 一致の複数 From でも兆候は報告されるべき: {:?}",
            r.render_risks
        );
        Ok(())
    }

    /// D164: 単一 From + Sender ドメイン不一致 — 「on behalf of」委任
    /// 送信の正常形 (ESP 経由配信) なので報告しない。
    #[tokio::test]
    async fn analyze_raw_email_は単一fromの委任senderを報告しない() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let eml = b"From: ceo@corp.example\r\n\
            Sender: bounce@esp-mail.example\r\n\
            To: you@example.com\r\n\
            Subject: Hello\r\n\
            Content-Type: text/plain; charset=utf-8\r\n\
            \r\n\
            Hello.\r\n";
        let r = analyze_raw_email(eml).await?;
        assert!(
            !r.render_risks
                .iter()
                .any(|s| s.contains("複数アドレス") || s.contains("Sender")),
            "単一 From の委任 Sender は報告すべきでない: {:?}",
            r.render_risks
        );
        Ok(())
    }

    /// D164: 単一 From 通常メールでは何も報告しない。
    #[tokio::test]
    async fn analyze_raw_email_は通常の単一fromで静か() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let eml = b"From: alice@example.com\r\n\
            To: you@example.com\r\n\
            Subject: Hello\r\n\
            Content-Type: text/plain; charset=utf-8\r\n\
            \r\n\
            Hello.\r\n";
        let r = analyze_raw_email(eml).await?;
        assert!(
            !r.render_risks
                .iter()
                .any(|s| s.contains("複数アドレス")),
            "通常メールで複数アドレス警告は出ないべき: {:?}",
            r.render_risks
        );
        Ok(())
    }

    #[tokio::test]
    async fn analyze_raw_email_deepfake_high_severity_for_financial_media_attachment(
    ) -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
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
        let _serial = test_serial().await;
        reset_globals().await;
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

    fn mls_test_identity(addr: &str) -> Result<kaname_mls::Identity, String> {
        Ok(kaname_mls::Identity {
            email: kaname_mls::EmailAddress::parse(addr).map_err(|e| format!("{e}"))?,
            display_name: None,
            default_ciphersuite: kaname_mls::Ciphersuite::KanameHybridPqc,
        })
    }

    /// テスト用 quoted-printable エンコーダ (CBOR の高バイトを =XX に逃がす)。
    /// base64 を依存に増やさないため、mail-parser がデコードできる QP を使う。
    fn qp_encode(bytes: &[u8]) -> String {
        let mut out = String::new();
        for &b in bytes {
            if (0x20..=0x7e).contains(&b) && b != b'=' {
                out.push(b as char);
            } else {
                out.push_str(&format!("={b:02X}"));
            }
        }
        out
    }

    fn mls_eml(envelope_cbor: &[u8]) -> String {
        format!(
            "From: alice@kaname.app\r\n\
             To: bob@kaname.app\r\n\
             Subject: mls\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"B\"\r\n\
             \r\n\
             --B\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             外側の本文\r\n\
             --B\r\n\
             Content-Type: application/mls-envelope+cbor\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n\
             \r\n\
             {}\r\n\
             --B--\r\n",
            qp_encode(envelope_cbor)
        )
    }

    /// D1 Phase 4: 受信メール内の MLS エンベロープが解析経路で実処理される
    /// ことを確認する (Welcome 参加 → 暗号メッセージの復号)。
    #[tokio::test]
    async fn analyze_raw_email_はmlsエンベロープを処理して復号する() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let mut alice = kaname_mls::MlsMailClient::try_new(mls_test_identity("alice@kaname.app")?)
            .map_err(|e| format!("{e}"))?;
        let bob = kaname_mls::MlsMailClient::try_new(mls_test_identity("bob@kaname.app")?)
            .map_err(|e| format!("{e}"))?;

        // alice が bob の KP で 1:1 会話を開始し、Welcome を生成
        let bob_kp = bob
            .generate_key_package()
            .ok_or("bob の KeyPackage 生成に失敗")?;
        let (mut conv, welcome) = alice
            .start_one_to_one(
                kaname_mls::EmailAddress::parse("bob@kaname.app").map_err(|e| format!("{e}"))?,
                bob_kp,
            )
            .map_err(|e| format!("{e}"))?;

        // bob 側クライアントをグローバルスロットに差し込み、受信経路を通す
        *mls_slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(bob);

        let r =
            analyze_raw_email(mls_eml(&welcome.to_cbor().map_err(|e| format!("{e}"))?).as_bytes())
                .await?;
        assert!(r.body.is_mls, "mls エンベロープで is_mls が立つべき");
        assert!(
            r.mls_events.iter().any(|e| e.contains("参加")),
            "WelcomeJoined イベントが必要: {:?}",
            r.mls_events
        );

        // alice → bob の暗号メッセージを受信経路で復号できるか
        let sealed = alice
            .encrypt_message(&mut conv, "これは暗号化された本文です".as_bytes())
            .map_err(|e| format!("{e}"))?;
        let r2 =
            analyze_raw_email(mls_eml(&sealed.to_cbor().map_err(|e| format!("{e}"))?).as_bytes())
                .await?;
        assert!(
            r2.mls_plaintexts
                .iter()
                .any(|p| p.contains("暗号化された本文")),
            "復号された本文が返るべき: {:?}",
            r2.mls_plaintexts
        );

        // D148: `subject\x00body` ペイロードは受信側で分割され、
        // 内側の件名・本文が表示名・解析対象になることを固定する。
        let payload = "内側の件名\u{0}緊急です。今すぐ振込先口座を変更してください";
        let sealed2 = alice
            .encrypt_message(&mut conv, payload.as_bytes())
            .map_err(|e| format!("{e}"))?;
        let r3 =
            analyze_raw_email(mls_eml(&sealed2.to_cbor().map_err(|e| format!("{e}"))?).as_bytes())
                .await?;
        assert_eq!(
            r3.subject, "内側の件名",
            "内側の件名が表示件名になるべき (外側カバー件名ではない)"
        );
        assert!(
            r3.mls_plaintexts
                .iter()
                .any(|p| p == "緊急です。今すぐ振込先口座を変更してください"),
            "ペイロードは \\x00 で分割された本文のみを返すべき: {:?}",
            r3.mls_plaintexts
        );
        assert!(
            r3.mls_plaintexts.iter().all(|p| !p.contains('\u{0}')),
            "生ペイロード (件名\\x00本文) がそのまま UI に出てはいけない"
        );
        // 解析対象は復号本文 — カバー文「このメールは Kaname MLS で…」ではない。
        // 振込要求を含む内側本文が oobv 推奨に届くことを確認する。
        assert_ne!(
            r3.oobv_level, "none",
            "復号本文の金銭要求が OOBV 推奨に反映されるべき (カバー文の採点ではない)"
        );

        // グローバル状態を掃除 — 後続テストへの影響を防ぐ
        *mls_slot().lock().unwrap_or_else(|e| e.into_inner()) = None;
        Ok(())
    }

    /// D1 Phase 3: `application/mls-key-package` 添付を受信経路で検証し
    /// `kp_cache` に取り込むこと、および取り込んだ KP で実際に会話を
    /// 開始して双方向の暗号化が成立すること (JMAP 送信を除く全経路)。
    #[tokio::test]
    async fn analyze_raw_email_はkeypackage添付を検証してkpキャッシュに入れる() -> Result<(), String>
    {
        let _serial = test_serial().await;
        reset_globals().await;
        let mut alice = kaname_mls::MlsMailClient::try_new(mls_test_identity("alice@kaname.app")?)
            .map_err(|e| format!("{e}"))?;
        let bob = kaname_mls::MlsMailClient::try_new(mls_test_identity("bob@kaname.app")?)
            .map_err(|e| format!("{e}"))?;

        // alice の KP を `application/mls-key-package` パートに載せた
        // メールを受信経路 (analyze_raw_email) に流す
        let alice_kp = alice
            .generate_key_package()
            .ok_or("alice の KeyPackage 生成に失敗")?;
        let raw = format!(
            "From: alice@kaname.app\r\n\
             To: bob@kaname.app\r\n\
             Subject: kp\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"K\"\r\n\
             \r\n\
             --K\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             KeyPackage を添付します\r\n\
             --K\r\n\
             Content-Type: application/mls-key-package\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n\
             \r\n\
             {}\r\n\
             --K--\r\n",
            qp_encode(&alice_kp.bytes)
        );
        *mls_slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(bob);
        let r = analyze_raw_email(raw.as_bytes()).await?;
        assert!(
            r.mls_events.iter().any(|e| e.contains("KeyPackage を受信")),
            "KP 取込イベントが必要: {:?}",
            r.mls_events
        );

        // KP がキャッシュされている → bob が alice との会話を開始できる
        // (mls_start_conversation の送信前までのライブラリ経路を直接確認)
        {
            let mut guard = mls_slot().lock().unwrap_or_else(|e| e.into_inner());
            let client = guard.as_mut().ok_or("mls スロットが空")?;
            let addr =
                kaname_mls::EmailAddress::parse("alice@kaname.app").map_err(|e| format!("{e}"))?;
            assert!(client.kp_cache().has(&addr), "KP がキャッシュされるべき");
            let kp = client.kp_cache().consume(&addr).ok_or("KP の消費に失敗")?;
            let (mut conv_bob, welcome) = client
                .start_one_to_one(addr, kp)
                .map_err(|e| format!("{e}"))?;
            // consume は 1 回限り — 二度目は取れない
            assert!(
                client
                    .kp_cache()
                    .consume(
                        &kaname_mls::EmailAddress::parse("alice@kaname.app")
                            .map_err(|e| format!("{e}"))?
                    )
                    .is_none(),
                "消費済み KP が再び取れてはいけない"
            );

            // alice (KP を生成した本体) が Welcome を処理し、
            // bob へ返信を暗号化できるか
            let msg = alice
                .process_incoming(&welcome)
                .map_err(|e| format!("{e}"))?;
            assert!(
                matches!(msg, kaname_mls::IncomingResult::WelcomeJoined(_)),
                "WelcomeJoined が返るべき: {msg:?}"
            );
            let mut conv_alice = alice
                .list_conversations()
                .into_iter()
                .next()
                .ok_or("alice に会話が作成されていない")?;
            let sealed = alice
                .encrypt_message(&mut conv_alice, "ok".as_bytes())
                .map_err(|e| format!("{e}"))?;
            let dec = client
                .process_incoming(&sealed)
                .map_err(|e| format!("{e}"))?;
            assert!(
                matches!(&dec, kaname_mls::IncomingResult::Application(b) if b == b"ok"),
                "alice→bob の復号が一致するべき: {dec:?}"
            );
            // bob → alice 方向も
            let sealed2 = client
                .encrypt_message(&mut conv_bob, "ack".as_bytes())
                .map_err(|e| format!("{e}"))?;
            let dec2 = alice
                .process_incoming(&sealed2)
                .map_err(|e| format!("{e}"))?;
            assert!(
                matches!(&dec2, kaname_mls::IncomingResult::Application(b) if b == b"ack"),
                "bob→alice の復号が一致するべき: {dec2:?}"
            );
        }
        *mls_slot().lock().unwrap_or_else(|e| e.into_inner()) = None;
        Ok(())
    }

    /// D1 Phase 3: 不正な KP 添付はイベントとして記録され、キャッシュされない。
    #[tokio::test]
    async fn analyze_raw_email_は不正なkeypackageをキャッシュしない() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let bob = kaname_mls::MlsMailClient::try_new(mls_test_identity("bob@kaname.app")?)
            .map_err(|e| format!("{e}"))?;
        let raw = "From: mallory@kaname.app\r\n\
            To: bob@kaname.app\r\n\
            Subject: kp\r\n\
            MIME-Version: 1.0\r\n\
            Content-Type: multipart/mixed; boundary=\"K\"\r\n\
            \r\n\
            --K\r\n\
            Content-Type: application/mls-key-package\r\n\
            \r\n\
            not-a-real-keypackage\r\n\
            --K--\r\n";
        *mls_slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(bob);
        let r = analyze_raw_email(raw.as_bytes()).await?;
        assert!(
            r.mls_events.iter().any(|e| e.contains("検証に失敗")),
            "検証失敗イベントが必要: {:?}",
            r.mls_events
        );
        let mut guard = mls_slot().lock().unwrap_or_else(|e| e.into_inner());
        let client = guard.as_mut().ok_or("mls スロットが空")?;
        assert!(
            !client.kp_cache().has(
                &kaname_mls::EmailAddress::parse("mallory@kaname.app")
                    .map_err(|e| format!("{e}"))?
            ),
            "不正 KP がキャッシュされてはいけない"
        );
        *guard = None;
        Ok(())
    }

    /// D1 Phase 3: `mls_conversations` は会話成立済みの相手のみ返す。
    #[tokio::test]
    async fn mls_conversations_は会話成立済みの相手を返す() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        assert!(
            mls_conversations().await.is_empty(),
            "未初期化では空列であるべき"
        );
        let mut bob = kaname_mls::MlsMailClient::try_new(mls_test_identity("bob@kaname.app")?)
            .map_err(|e| format!("{e}"))?;
        let alice = kaname_mls::MlsMailClient::try_new(mls_test_identity("alice@kaname.app")?)
            .map_err(|e| format!("{e}"))?;
        let alice_kp = alice
            .generate_key_package()
            .ok_or("alice の KP 生成に失敗")?;
        let _ = bob
            .start_one_to_one(
                kaname_mls::EmailAddress::parse("alice@kaname.app").map_err(|e| format!("{e}"))?,
                alice_kp,
            )
            .map_err(|e| format!("{e}"))?;
        *mls_slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(bob);
        let peers = mls_conversations().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].email, "alice@kaname.app");
        // Welcome コミットで epoch は 1 に進む
        assert_eq!(peers[0].epoch, 1);
        *mls_slot().lock().unwrap_or_else(|e| e.into_inner()) = None;
        Ok(())
    }

    /// D121: `ai_llm_start` はモデル未配置の場合にモック起動せず
    /// エラーを返す (spawn のモックフォールバックを Ready ゲートで抑止)。
    /// モデル配置済みの環境ではワーカー実起動になるため本テストは
    /// Missing のときのみ断言する。
    #[tokio::test]
    async fn ai_llm_start_はモデル未配置でエラーを返す() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let cfg = kaname_ai::llm_bridge::ModelConfig::quarantined();
        if !matches!(
            kaname_ai::llm_bridge::check_model(&cfg),
            kaname_ai::llm_bridge::ModelStatus::Missing { .. }
        ) {
            return Ok(()); // モデル配置済み環境では本テストの前提が成立しない
        }
        match ai_llm_start().await {
            Err(e) => assert!(e.contains("ダウンロード"), "未配置エラーであるべき: {e}"),
            Ok(_) => return Err("モデル未配置なのに起動成功してしまった".into()),
        }
        Ok(())
    }

    /// D1 Phase 5: 安全番号の照合記録が `mls_conversations` の
    /// verified/safety_changed に反映されること、および照合後に番号が
    /// 変わった会話が safety_changed で警告されること。
    #[tokio::test]
    async fn mls照合記録がverifiedと番号変更警告に反映される() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        // 照合記録の保存先 (history.db) を開く
        let dir = std::env::temp_dir().join(format!("kaname-d1p5-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        history_open(
            dir.join("history.db").to_string_lossy().to_string(),
            "0".repeat(64),
        )
        .await?;

        let mut bob = kaname_mls::MlsMailClient::try_new(mls_test_identity("bob@kaname.app")?)
            .map_err(|e| format!("{e}"))?;
        let alice = kaname_mls::MlsMailClient::try_new(mls_test_identity("alice@kaname.app")?)
            .map_err(|e| format!("{e}"))?;
        let alice_kp = alice
            .generate_key_package()
            .ok_or("alice の KP 生成に失敗")?;
        let (conv, _welcome) = bob
            .start_one_to_one(
                kaname_mls::EmailAddress::parse("alice@kaname.app").map_err(|e| format!("{e}"))?,
                alice_kp,
            )
            .map_err(|e| format!("{e}"))?;
        let conv_id = conv.id.as_hex();
        *mls_slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(bob);

        // 記録前: 未検証
        let peers = mls_conversations().await;
        assert_eq!(peers.len(), 1);
        assert!(!peers[0].verified);
        assert!(!peers[0].safety_changed);

        // 照合記録 → verified
        mls_mark_verified("alice@kaname.app".to_string()).await?;
        let peers = mls_conversations().await;
        assert!(peers[0].verified, "照合記録が verified に反映されるべき");
        assert!(!peers[0].safety_changed);

        // 番号が変わった (鍵変更・再参加・中間者) → safety_changed で警告。
        // ここでは記録値を直接書き換えて不一致状態を再現する
        let store = store_slot()
            .lock()
            .await
            .clone()
            .ok_or("store not opened")?;
        store
            .mls_mark_verified("local", &conv_id, "deadbeef-different-sn")
            .await
            .map_err(|e| e.to_string())?;
        let peers = mls_conversations().await;
        assert!(!peers[0].verified);
        assert!(peers[0].safety_changed, "番号不一致が検出されるべき");

        *mls_slot().lock().unwrap_or_else(|e| e.into_inner()) = None;
        *store_slot().lock().await = None;
        Ok(())
    }

    #[tokio::test]
    async fn analyze_raw_email_mls未初期化ではイベントのみ返す() -> Result<(), String> {
        // MLS スロットが空の状態で mls パートを含むメールを解析する。
        let _serial = test_serial().await;
        reset_globals().await;
        let raw: &[u8] = b"From: a@kaname.app\r\n\
            To: b@kaname.app\r\n\
            Subject: mls\r\n\
            MIME-Version: 1.0\r\n\
            Content-Type: multipart/mixed; boundary=\"B\"\r\n\
            \r\n\
            --B\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            body\r\n\
            --B\r\n\
            Content-Type: application/mls-envelope+cbor\r\n\
            \r\n\
            not-an-envelope\r\n\
            --B--\r\n";
        let r = analyze_raw_email(raw).await?;
        assert!(r.body.is_mls);
        assert!(
            r.mls_events.iter().any(|e| e.contains("初期化")),
            "未初期化イベントが必要: {:?}",
            r.mls_events
        );
        assert!(r.mls_plaintexts.is_empty());
        Ok(())
    }

    /// D112: 文体プロファイルは settings テーブルへ永続化され、
    /// プロセス内キャッシュ消去 (再起動相当) 後も復元される。
    #[tokio::test]
    async fn 文体プロファイルが再起動相当のキャッシュ消去後も復元される() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let dir = std::env::temp_dir().join(format!("kaname-d112-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        history_open(
            dir.join("history.db").to_string_lossy().into_owned(),
            "00".repeat(32),
        )
        .await?;
        let store = store_slot()
            .lock()
            .await
            .clone()
            .ok_or("store not opened")?;

        let sender = "persist-test@example.com";
        let key = format!("style_profile:{sender}");
        // 未接続時は account_id が "" になる (evaluate_sender_style と同じ経路)。
        let account_id = current_account_id().await;

        // 3 サンプル蓄積済みのプロファイルを仕込む。
        let seeded = kaname_ssa::SenderStyleProfile {
            sample_count: 3,
            ..kaname_ssa::SenderStyleProfile::new(sender)
        };
        store
            .set_setting(
                &account_id,
                &key,
                &serde_json::to_string(&seeded).map_err(|e| e.to_string())?,
            )
            .await
            .map_err(|e| e.to_string())?;

        // プロセス内キャッシュを消す (= アプリ再起動相当)。
        style_profiles().lock().await.remove(sender);

        // 1 通評価すると、永続化済みの 3 サンプルから再開されるべき。
        let _ = evaluate_sender_style(sender, "こんにちは。お元気ですか。", Some(10), false).await;

        let json = store
            .get_setting(&account_id, &key)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("プロファイルが永続化されていない")?;
        let p: kaname_ssa::SenderStyleProfile =
            serde_json::from_str(&json).map_err(|e| e.to_string())?;
        assert_eq!(
            p.sample_count, 4,
            "永続化済みの 3 サンプル + 今回の 1 サンプル = 4 であるべき (0 からの再学習ではない)"
        );
        Ok(())
    }

    /// D136: STYLE_PROFILES はユニーク送信者数に比例して増えるため
    /// 上限で打ち切る。上限到達後も既知送信者は更新可能であること、
    /// 新規送信者はプロファイルを作らず評価もしないことを固定する。
    #[tokio::test]
    async fn 文体プロファイルは送信者数の上限で打ち切る() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;

        // 既知送信者 1 名を先に作り、残りをダミーで上限まで埋める
        let known = "d136-known@example.test";
        let _ = evaluate_sender_style(known, "短い本文です。", Some(10), false).await;
        {
            let mut profiles = style_profiles().lock().await;
            for i in 0..999 {
                profiles.insert(
                    format!("d136-dummy-{i}@example.test"),
                    kaname_ssa::SenderStyleProfile::new("x"),
                );
            }
            assert_eq!(profiles.len(), 1_000);
        }

        // 上限到達後: 新規送信者はプロファイルを作らない (警告も出ない —
        // プロファイル非存在なので InsufficientData として評価不能)
        let warnings =
            evaluate_sender_style("d136-new@example.test", "本文です。", Some(10), false).await;
        assert!(warnings.is_empty(), "上限超過の新規送信者は評価しないべき");
        assert_eq!(style_profiles().lock().await.len(), 1_000);

        // 既知送信者は上限を超えても更新・評価が継続する
        let _ = evaluate_sender_style(known, "別の本文です。", Some(11), false).await;
        assert_eq!(style_profiles().lock().await.len(), 1_000);
        assert!(style_profiles().lock().await.contains_key(known));
        Ok(())
    }

    #[tokio::test]
    async fn analyze_raw_email_uses_verified_sender_history() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        // D100 回帰: 一覧評価 (assess_listing) にのみ送信者履歴が供給され、
        // 詳細解析 (analyze_raw_email) は sender_history=None 固定だった。
        // 「本人確認済み」の -0.20 寄与が詳細表示に効かず、同一メールで
        // 一覧と詳細の判定が食い違った。検証済み送信者のメールで
        // 「検証済み差出人」シグナルが出ることで配線を証明する。
        //
        // 注意: STORE はプロセス共有の OnceLock。先頭の `reset_globals()`
        // でスロットを空にしてから自分専用の Store を開くため、
        // 他テストの履歴が混ざることはない (D115)。
        let db = std::env::temp_dir().join(format!("kaname-d100-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&db);
        history_open(db.to_string_lossy().into_owned(), "0".repeat(64)).await?;
        let store = store_slot()
            .lock()
            .await
            .clone()
            .ok_or("テスト用 Store を開けませんでした")?;

        // 未接続時の current_account_id() は空文字。両送信者とも同じ
        // アカウントで種付けする。
        let account = "";
        let verified = "d100-verified@example.test";
        let control = "d100-control@example.test";
        store
            .record_received(account, verified, Some("Verified Sender"), None)
            .await
            .map_err(|e| e.to_string())?;
        store
            .mark_sender_verified(account, verified)
            .await
            .map_err(|e| e.to_string())?;

        let mk = |from: &str| -> Vec<u8> {
            format!(
                "From: {from}\r\n\
                 To: you@example.test\r\n\
                 Subject: wire transfer request\r\n\
                 Date: Mon, 26 Apr 2026 10:00:00 +0900\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\
                 \r\n\
                 Please process the wire transfer today.\r\n"
            )
            .into_bytes()
        };

        let v = analyze_raw_email(&mk(verified)).await?;
        let c = analyze_raw_email(&mk(control)).await?;
        assert!(
            v.bec_signals.iter().any(|s| s.contains("検証済み")),
            "詳細解析に送信者履歴が供給されていない (D100 回帰): {:?}",
            v.bec_signals
        );
        assert!(
            !c.bec_signals.iter().any(|s| s.contains("検証済み")),
            "履歴の無い対照送信者に検証済みシグナルが出てはいけない"
        );
        assert!(
            v.bec_score < c.bec_score,
            "検証済み送信者のスコアが対照より下がるべき ({} vs {})",
            v.bec_score,
            c.bec_score
        );
        Ok(())
    }

    /// D109: `org_domain` 設定は接続時の導出値で初めて実在する。
    /// 未設定なら小文字化して書き込み、既存値は上書きしないことを固定する。
    #[tokio::test]
    async fn persist_org_domain_if_unset_は未設定時のみ書き込む() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let dir = std::env::temp_dir().join(format!("kaname-d109-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let db = dir.join("history.db");
        let key = "00".repeat(32);
        history_open(db.to_string_lossy().into_owned(), key).await?;

        let account = "acct-d109";
        persist_org_domain_if_unset(account, "  Corp-Example.com  ").await;
        let store = store_slot()
            .lock()
            .await
            .clone()
            .ok_or("store not opened")?;
        let v = store
            .get_setting(account, "org_domain")
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(v.as_deref(), Some("corp-example.com"));

        // 既存値 (将来の手動上書きを含む) は保持する。
        persist_org_domain_if_unset(account, "other.example").await;
        let v2 = store
            .get_setting(account, "org_domain")
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(v2.as_deref(), Some("corp-example.com"));
        Ok(())
    }

    /// D111: `record_received` に `None` を渡した場合、
    /// `topic_summary` は設定されない (直前件名を「いつもの話題」と
    /// 偽って話題急変シグナルを誤発火させないため)。
    #[tokio::test]
    async fn record_received_に_none_を渡すと話題プロファイルが作られない() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let dir = std::env::temp_dir().join(format!("kaname-d111-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        history_open(
            dir.join("history.db").to_string_lossy().into_owned(),
            "00".repeat(32),
        )
        .await?;
        let store = store_slot()
            .lock()
            .await
            .clone()
            .ok_or("store not opened")?;
        for _ in 0..6 {
            store
                .record_received("acct-d111", "alice@example.com", None, None)
                .await
                .map_err(|e| e.to_string())?;
        }
        let profile = store
            .get_sender_profile("acct-d111", "alice@example.com")
            .await
            .map_err(|e| e.to_string())?
            .ok_or("profile not created")?;
        assert_eq!(profile.message_count, 6);
        assert!(
            profile.topic_summary.is_none(),
            "topic_summary は None のままであるべき (件名の流用は話題プロファイルではない)"
        );
        Ok(())
    }

    /// D149: `mail_scan_folder` はサブフォルダ内の .eml も走査する。
    /// 修正前は `read_dir` 一段のみで、ネストしたエクスポート構造の
    /// 大部分が「解析完了」表示の裏で黙って未走査だった。
    #[tokio::test]
    async fn mail_scan_folder_はネストしたフォルダ内のemlも解析する() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let dir = std::env::temp_dir().join(format!("kaname-d149-{}", std::process::id()));
        let nested = dir.join("INBOX").join("重要");
        std::fs::create_dir_all(&nested).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("top.eml"), SAFE_EML).map_err(|e| e.to_string())?;
        std::fs::write(nested.join("nested.eml"), SAFE_EML).map_err(|e| e.to_string())?;
        std::fs::write(nested.join("not-mail.txt"), "hello").map_err(|e| e.to_string())?;

        let r = mail_scan_folder(dir.to_string_lossy().into_owned()).await?;
        assert_eq!(
            r.analyzed, 2,
            "トップレベル + ネスト2段の .eml が両方解析されるべき (failed={:?})",
            r.failed
        );
        assert!(
            r.emails.iter().any(|e| e.file == "nested.eml"),
            "ネストしたファイルが結果に含まれるべき"
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
    CeremonyError, CeremonyState, OobvRecommender, RecommendationLevel, VerificationCeremony,
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
}

impl V02AppState {
    /// 新規インスタンスを作成する。
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ceremonies: Mutex::new(HashMap::new()),
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
    let mut ceremonies = state.ceremonies.lock().await;
    // セレモニーは一度も削除されず map が無限に育つため、上限で止める (D88)。
    // Pending 以外 (Verified/Expired/Locked) は verify が AlreadyCompleted を
    // 返すため二度と使えず、期限切れ Pending も verify できない — 追い出してよい。
    const MAX_CEREMONIES: usize = 256;
    if ceremonies.len() >= MAX_CEREMONIES {
        let now = now_unix_secs();
        ceremonies.retain(|_, c| c.state == CeremonyState::Pending && c.expires_at_unix > now);
    }
    if ceremonies.len() >= MAX_CEREMONIES {
        return Err(V02CommandError::InvalidState(
            "進行中の検証が多すぎます。少し待ってから再度お試しください".into(),
        ));
    }
    ceremonies.insert(ceremony.id.clone(), ceremony);
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

    // 帯域外検証の結果は改ざん検知付きの永続監査ログに残す
    // (以前は読み出し経路の無いインメモリ Vec のみで、プロセス終了で
    // 証跡が消えていた)。フレーズ自体はシークレットなので記録しない。
    let account_id = current_account_id().await;
    audit_event(
        Some(&account_id),
        "OOBV_VERIFY",
        serde_json::json!({
            "email_id": audit.target_email_id,
            "sender": audit.target_sender,
            "state": audit.state,
        }),
    )
    .await;

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
        let _serial = test_serial().await;
        reset_globals().await;
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
        let _serial = test_serial().await;
        reset_globals().await;
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
        let _serial = test_serial().await;
        reset_globals().await;
        let resp = oobv_recommend(OobvRecommendRequest {
            email_body: "至急振込先変更".into(),
        })
        .await
        .map_err(|e| e.to_string())?;
        assert_eq!(resp.level, RecommendationLevel::Strong);
        Ok(())
    }

    /// D87: 同名添付の連続保存で先のファイルが上書きされないことを固定。
    #[test]
    fn write_unique_は同名を別名で保存し既存を上書きしない() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("kaname-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let p1 = write_unique(&dir, "report.pdf", b"first").map_err(|e| e.to_string())?;
        let p2 = write_unique(&dir, "report.pdf", b"second").map_err(|e| e.to_string())?;
        assert_ne!(p1, p2, "同名なのに同じパスを返した");
        assert_eq!(std::fs::read(&p1).map_err(|e| e.to_string())?, b"first");
        assert_eq!(std::fs::read(&p2).map_err(|e| e.to_string())?, b"second");
        assert!(p2.to_string_lossy().contains("(1)"));
        // 拡張子なし・先頭ドットの名でも別名になる
        let p3 = write_unique(&dir, "noext", b"x").map_err(|e| e.to_string())?;
        let p4 = write_unique(&dir, "noext", b"y").map_err(|e| e.to_string())?;
        assert_ne!(p3, p4);
        Ok(())
    }

    /// D88: セレモニーが上限を超えるとき、終端のものは追い出され
    /// 有効な Pending が上限を超える場合のみエラーになることを固定。
    #[tokio::test]
    async fn oobv_start_は終端セレモニーを追い出し有効なものが満杯なら拒否する(
    ) -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let state = V02AppState::new();
        // 256件の終端セレモニーを詰める (Verified は二度と検証できないため
        // 追い出されてよい)
        {
            let mut map = state.ceremonies.lock().await;
            for i in 0..256 {
                let mut c = VerificationCeremony::new(format!("e{i}"), "a@b.com");
                c.state = CeremonyState::Verified;
                map.insert(c.id.clone(), c);
            }
        }
        // 終端だけが詰まっているので追い出されて成功するはず
        let resp = oobv_start(
            state.clone(),
            OobvStartRequest {
                email_id: "new".into(),
                sender: "a@b.com".into(),
            },
        )
        .await;
        assert!(resp.is_ok(), "終端セレモニーは追い出されるべき: {resp:?}");

        // 今度は有効な Pending 256件で埋める
        {
            let mut map = state.ceremonies.lock().await;
            map.clear();
            for i in 0..256 {
                let c = VerificationCeremony::new(format!("e{i}"), "a@b.com");
                map.insert(c.id.clone(), c);
            }
        }
        let resp = oobv_start(
            state.clone(),
            OobvStartRequest {
                email_id: "overflow".into(),
                sender: "a@b.com".into(),
            },
        )
        .await;
        assert!(
            matches!(resp, Err(V02CommandError::InvalidState(_))),
            "有効な Pending が上限を超えたら拒否すべき: {resp:?}"
        );
        Ok(())
    }

    /// D89: 鍵ファイルの生成・再読・破損ガードを固定。
    #[test]
    fn resolve_or_create_key_は生成と破損ガードを正しく行う() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("kaname-keytest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

        // 1. 新規: 64桁hex の鍵が作られ、再呼出しで同じ値を返す
        let k1 =
            resolve_or_create_key(&dir, "history.key", "history.db").map_err(|e| e.to_string())?;
        assert_eq!(k1.len(), 64);
        assert!(k1.chars().all(|c| c.is_ascii_hexdigit()));
        let k2 =
            resolve_or_create_key(&dir, "history.key", "history.db").map_err(|e| e.to_string())?;
        assert_eq!(k1, k2, "再呼出しで別鍵を生成してはいけない");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.join("history.key"))
                .map_err(|e| e.to_string())?
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "鍵は作成時から 0600 であるべき: {mode:o}"
            );
        }

        // 2. 鍵のみ破損 (DB なし) → 自己修復で再生成
        std::fs::write(dir.join("history.key"), b"corrupt").map_err(|e| e.to_string())?;
        let k3 =
            resolve_or_create_key(&dir, "history.key", "history.db").map_err(|e| e.to_string())?;
        assert_ne!(k3.len(), 0);
        assert_eq!(k3.len(), 64);

        // 3. DB が存在し鍵が壊れている → 再生成せずエラー (新鍵は旧DBを読めない)
        std::fs::write(
            dir.join("history.db"),
            b"\x00encrypted-bytes-not-sqlite-header",
        )
        .map_err(|e| e.to_string())?;
        std::fs::write(dir.join("history.key"), b"corrupt").map_err(|e| e.to_string())?;
        match resolve_or_create_key(&dir, "history.key", "history.db") {
            Err(e) => assert!(e.contains("鍵"), "破損鍵の旨を伝えるべき: {e}"),
            Ok(_) => panic!("DB があるのに鍵が壊れていたら再生成してはいけない"),
        }

        // 4. 平文 SQLite DB + 鍵なし → 「旧形式」と教える
        std::fs::remove_file(dir.join("history.key")).ok();
        std::fs::write(dir.join("history.db"), b"SQLite format 3\x00rest")
            .map_err(|e| e.to_string())?;
        match resolve_or_create_key(&dir, "history.key", "history.db") {
            Err(e) => assert!(e.contains("平文"), "平文 DB の旨を伝えるべき: {e}"),
            Ok(_) => panic!("平文 DB を鍵生成で上書きしてはいけない"),
        }

        // 5. 有効な鍵 + DB あり → そのまま返す
        std::fs::write(dir.join("history.key"), k3.as_bytes()).map_err(|e| e.to_string())?;
        let k4 =
            resolve_or_create_key(&dir, "history.key", "history.db").map_err(|e| e.to_string())?;
        assert_eq!(k4, k3);

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn dlp_precheck_は機密マーカーの_warn_所見を返す() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let resp = mail_dlp_precheck(DlpPrecheckRequest {
            from: "alice@corp.example".into(),
            to: vec!["bob@example.com".into()],
            subject: "資料送付".into(),
            body: "【社外秘】この資料は部外秘です。".into(),
        })
        .await?;
        assert!(
            resp.warnings.iter().any(|w| w.contains("機密")),
            "機密マーカーで警告が出るべき: {:?}",
            resp.warnings
        );
        Ok(())
    }

    #[tokio::test]
    async fn dlp_precheck_は平文メールで警告を返さない() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let resp = mail_dlp_precheck(DlpPrecheckRequest {
            from: "alice@corp.example".into(),
            to: vec!["bob@corp.example".into()],
            subject: "ランチ".into(),
            body: "12時に食堂で会いましょう。".into(),
        })
        .await?;
        assert!(resp.warnings.is_empty(), "{:?}", resp.warnings);
        Ok(())
    }

    // D104: 受信側 DLP (scan_dlp_inbound) は Direction::Inbound で評価するが、
    // Inbound ルールが0件だったため構造的に常に空を返していた。
    #[test]
    fn scan_dlp_inbound_は受信本文中のマイナンバーを検出する() {
        let findings = scan_dlp_inbound("件名", "マイナンバーは 123456789018 です", "corp.example");
        assert!(
            findings.iter().any(|f| f.contains("マイナンバー")),
            "受信メールの機微情報が検出されるべき: {findings:?}"
        );
    }

    #[test]
    fn scan_dlp_inbound_は平文本文で誤検出しない() {
        let findings = scan_dlp_inbound("ランチ", "12時に食堂で会いましょう", "corp.example");
        assert!(findings.is_empty(), "{findings:?}");
    }

    // D104: outbound_dlp_eval の known_recipient_domains が常に空で
    // タイポドメイン誤配検出が不発だった。連絡先ドメイン抽出の検査。
    #[test]
    fn contact_domain_は表示名付きと裸のアドレスからドメインを抽出する() {
        assert_eq!(
            contact_domain("\"田中 太郎\" <tanaka@Corp.Example>"),
            Some("corp.example".to_string())
        );
        assert_eq!(
            contact_domain("sato@Example.co.jp"),
            Some("example.co.jp".to_string())
        );
        assert_eq!(contact_domain("not-an-email"), None);
        assert_eq!(contact_domain("a@"), None);
    }

    // D104: 連絡先履歴が既知ドメインに供給され、タイポドメイン宛の
    // 機微メール送信が Block にエスカレートされることを端到端で検査。
    // (crop-partnr.com は連絡先の corp-partner.com と距離2のタイポ)
    #[tokio::test]
    async fn outbound_dlp_eval_は既知宛先のタイポドメインを疑う() -> Result<(), String> {
        let _serial = test_serial().await;
        reset_globals().await;
        let dir = std::env::temp_dir().join(format!("kaname-d104-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        history_open(
            dir.join("history.db").to_string_lossy().to_string(),
            "0".repeat(64),
        )
        .await?;
        let account = "acct-d104";
        let store = store_slot()
            .lock()
            .await
            .clone()
            .ok_or("store not opened")?;
        store
            .record_received(account, "alice@corp-partner.com", None, None)
            .await
            .map_err(|e| e.to_string())?;

        let res = outbound_dlp_eval(
            account,
            "me@us.example",
            &["x@corp-partnr.com".to_string()],
            "件名",
            "【社外秘】この資料を転送します",
            &[],
        )
        .await;
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "misdirected-recipient"),
            "タイポドメイン宛が疑われるべき: {:?}",
            res.findings
        );
        assert!(matches!(res.verdict, kaname_dlp::Action::Block));

        // 対照: 正しい既知ドメイン宛は誤配として疑われない
        let ok = outbound_dlp_eval(
            account,
            "me@us.example",
            &["x@corp-partner.com".to_string()],
            "件名",
            "【社外秘】この資料を転送します",
            &[],
        )
        .await;
        assert!(
            !ok.findings
                .iter()
                .any(|f| f.rule_id == "misdirected-recipient"),
            "既知ドメイン宛を誤配扱いしない: {:?}",
            ok.findings
        );
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
        bearer_token: zeroize::Zeroizing::new(token),
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
    // 導出した自組織ドメインを永続化し `our_domain` の設定経路を実効化する (D109)。
    // 未接続時のオフライン解析 (mail_import_eml / mail_scan_folder) でも
    // 自組織偽装系シグナルが効くようになる。
    if let Some(d) = &result.org_domain {
        persist_org_domain_if_unset(&result.account_id, d).await;
    }
    audit_event(
        Some(&result.account_id),
        "MAIL_CONNECT",
        serde_json::json!({"mailboxes": result.mailboxes.len()}),
    )
    .await;
    Ok(result)
}

/// `org_domain` 設定が未設定なら、接続時に導出したドメインを保存する。
///
/// `our_domain` の最優先経路は `settings.org_domain` だが書き込み経路が
/// どこにも存在せず常に空だった (D109)。既に値がある場合は上書きしない
/// (将来の手動設定・マルチドメイン組織の上書き余地を残す)。
/// 永続化の失敗で接続自体を失敗させない (best-effort)。
async fn persist_org_domain_if_unset(account_id: &str, domain: &str) {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() {
        return;
    }
    let Some(store) = store_slot().lock().await.clone() else {
        return;
    };
    match store.get_setting(account_id, "org_domain").await {
        Ok(Some(v)) if !v.trim().is_empty() => {}
        Ok(_) => {
            if let Err(e) = store.set_setting(account_id, "org_domain", &domain).await {
                tracing::warn!(error=%e, "org_domain の保存に失敗");
            }
        }
        Err(e) => tracing::warn!(error=%e, "org_domain の読み出しに失敗"),
    }
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
pub async fn mail_fetch(
    mailbox_id: String,
    limit: Option<u32>,
    offset: Option<u32>,
) -> Result<Vec<EmailRow>, String> {
    let client = jmap_client().await?;
    let account_id = client.account_id().to_string();
    let requested = limit.unwrap_or(50).min(500);
    let page = client
        .query_emails_page(&mailbox_id, offset.unwrap_or(0), requested)
        .await
        .map_err(|e| format!("メール一覧の取得に失敗しました: {e}"))?;
    let items = &page.items;

    // 自組織ドメイン (D44) と連絡先一覧は一覧全体で1回だけ解決する
    // (行ごとの DB 参照を避ける — D108: contacts の取得が
    //  assess_listing 内で行ごとに走り、50 件で 50 回の同一 SELECT
    //  になっていた)。
    let our = our_domain(&account_id, None).await;
    let contacts = lookup_contacts(&account_id).await;
    let mut rows = Vec::with_capacity(items.len());
    for it in items {
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
            return_path: it.return_path.as_deref(),
            known_contacts: &contacts,
        })
        .await;

        // 受信を履歴に記録し、メール本体も保存する。
        // Store 未接続なら何もしない。失敗しても解析結果は返す
        // (保存できないことは表示できない理由にならない)。
        if let Some(store) = store_slot().lock().await.clone() {
            // D111: `topic_summary` に当該メールの件名を渡すと
            // 「いつもの話題」が直前1通の件名に退化し、
            // `contains_unusual_topic` が「話題が毎回変わる普通の連絡先」に
            // 構造的に誤発火する (cosine < 0.15 → +0.15 「話題の急変」)。
            // 真の話題集計 (LLM 要約) が無い現状では、誤信号を供給するより
            // None を渡して話題シグナルをスキップするのが正直な挙動。
            if let Err(e) = store
                .record_received(&account_id, &from_addr, from_name.as_deref(), None)
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
        });
    }

    // サーバ側で消えたメールのローカル残存を tombstone 化する (D80)。
    // 「不在 = 削除」の推論はメールボックス全体を見た時のみ成立するため、
    // 先頭ページの取得件数が実効 limit 未満 (= これ以上ページが無い) のとき
    // だけ実行する。サーバが要求より小さい limit をエコーした場合は
    // そちらを上限として使う。
    let effective_limit = page
        .applied_limit
        .map(|l| l.min(requested as u64))
        .unwrap_or(requested as u64);
    if page.position == 0 && (page.items.len() as u64) < effective_limit {
        if let Some(store) = store_slot().lock().await.clone() {
            let live_ids: Vec<String> = page.items.iter().map(|i| i.id.clone()).collect();
            match store
                .reconcile_mailbox(&account_id, &mailbox_id, &live_ids)
                .await
            {
                Ok(n) if n > 0 => {
                    tracing::info!(
                        count = n,
                        "サーバで削除されたメールをローカルで tombstone 化"
                    );
                }
                Err(e) => tracing::warn!(error = %e, "ローカルメールの reconcile に失敗"),
                _ => {}
            }
        }
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
    /// Return-Path ヘッダーの生値 (未取得時は None)。
    /// From vs Return-Path 不一致検出に使用 (D106 で JMAP 経路に配線)。
    return_path: Option<&'a str>,
    /// 呼び出し側が一覧全体で1回だけ解決した連絡先一覧
    /// (kaname-bec の `known_contacts` 書式: `"Name <addr>"` または `addr`)。
    known_contacts: &'a [String],
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
        return_path,
        known_contacts,
    } = input;
    let from_header = match from_name {
        Some(n) => format!("{n} <{from_addr}>"),
        None => from_addr.to_string(),
    };
    let urls = extract_urls_from_text(preview);
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
        return_path,
        subject,
        body_text: preview,
        auth: kaname_bec::AuthResults {
            spf: map_auth(parsed_auth.spf),
            dkim: map_auth(parsed_auth.dkim),
            dmarc: map_auth(parsed_auth.dmarc),
            arc: match parsed_auth.arc {
                kaname_render::AuthResult::None => None,
                r => Some(map_auth(r)),
            },
        },
        sender_history: history.as_ref(),
        our_domain,
        known_contacts,
        extracted_urls: &urls,
        reply_to,
        thread_context: thread_ctx,
        past_thread_bodies: &past_bodies,
        dkim_signature_header: dkim_signature,
    };
    match bec_detector().assess(req) {
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
        .map_err(|e| format!("既読化に失敗しました: {e}"))?;

    // ローカル保存分も同期する。JMAP だけを更新していたため、保存済み一覧
    // (オフライン表示) とサマリの未読数が永遠に古いままだった (D77)。
    // Store 未接続・更新失敗でも既読化自体は成立しているため best-effort。
    if let Some(store) = store_slot().lock().await.clone() {
        let account_id = current_account_id().await;
        if let Err(e) = store.mark_messages_read(&account_id, &ids).await {
            warn!(error = %e, "ローカルの既読同期に失敗");
        }
    }
    Ok(())
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
        .map_err(|e| format!("削除に失敗しました: {e}"))?;

    // ローカル保存分も論理削除する。JMAP だけを更新していたため、
    // ゴミ箱へ移したメールが保存済み一覧・検索・サマリに出続けていた
    // (D77)。Store 未接続・更新失敗でも JMAP 側の移動は成立している
    // ため best-effort。
    if let Some(store) = store_slot().lock().await.clone() {
        let account_id = current_account_id().await;
        if let Err(e) = store.mark_message_deleted(&account_id, &email_id).await {
            warn!(error = %e, "ローカルの削除同期に失敗");
        }
    }
    Ok(())
}

/// メールを送信する。
///
/// **送信前に DLP (`Direction::Outbound`) を実行し、Block 判定なら送信しない。**
/// これが DLP 本来の用途であり、受信側検査 (`scan_dlp_inbound`) と対になる。
/// 送信方向の DLP 評価 (`mail_send_real` と `mail_dlp_precheck` で共有)。
/// 添付なし (Compose に添付 UI が無い)・既知宛先ドメイン履歴なし。
async fn outbound_dlp_eval(
    account_id: &str,
    from: &str,
    to: &[String],
    subject: &str,
    body: &str,
    attachment_mimes: &[String],
) -> kaname_dlp::DlpResult {
    let engine = kaname_dlp::DlpEngine::default_engine();
    let mimes: Vec<String> = attachment_mimes.to_vec();
    // D104: 誤配検出 (タイポドメイン照合) は「既知の宛先ドメイン」に対する
    // 類似度で判定するが、ここに常に空リストが渡されていたため
    // LookalikeDomain 検査が構造的に不発だった。連絡先履歴から供給する。
    let domains = lookup_known_domains(account_id).await;
    let edm: std::collections::HashMap<String, kaname_dlp::edm::EdmFingerprints> =
        std::collections::HashMap::new();
    let our = our_domain(account_id, Some(from)).await;
    let ctx = kaname_dlp::EvalCtx {
        body,
        subject,
        size_bytes: body.len() as u64,
        to,
        from,
        attachment_mimes: &mimes,
        edm_sets: &edm,
        known_recipient_domains: &domains,
        our_domain: &our,
    };
    engine.evaluate(&ctx, kaname_dlp::Direction::Outbound)
}

/// 送信共通経路: 送信前 DLP (Outbound) → JMAP `send_email` → 送信監査。
///
/// `dlp_target` は DLP に渡す実内容 — MLS 暗号化メールは外側が
/// プレースホルダのため、暗号化前の平文で評価する (E2E でも送信側
/// DLP は実効化される)。`audit_name` は送信イベント名
/// (MAIL_SEND / MLS_KEYPACKAGE_SEND / MLS_WELCOME_SEND / MLS_MESSAGE_SEND)。
async fn send_mail_core(
    from: &str,
    to: &[String],
    send_subject: &str,
    send_body: &str,
    attachments: &[kaname_jmap::OutgoingAttachment],
    // DLP 評価対象の (件名, 本文)。None のとき外側の件名・本文を評価する。
    // MLS 送信では実内容がエンベロープ内にのみあるため、ここに実件名・
    // 実本文を渡して暗号化前の内容で DLP を効かせる。
    dlp_target: Option<(&str, &str)>,
    audit_name: &str,
) -> Result<String, String> {
    let client = jmap_client().await?;

    // 送信前 DLP。ここで止めるのが情報漏洩防止の本丸。
    // 自組織ドメイン (D44): 送信者自身の `from` アドレスが最直接のヒント。
    let mimes: Vec<String> = attachments.iter().map(|a| a.mime_type.clone()).collect();
    let (dlp_subject, dlp_body) = dlp_target.unwrap_or((send_subject, send_body));
    let dlp = outbound_dlp_eval(client.account_id(), from, to, dlp_subject, dlp_body, &mimes).await;
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
        .send_email(from, &to_refs, send_subject, send_body, attachments)
        .await
        .map_err(|e| format!("送信に失敗しました: {e}"))?;

    // 実際に送信が行われた出口イベント (件名・本文・宛先アドレスは書かない)。
    audit_event(
        Some(client.account_id()),
        audit_name,
        serde_json::json!({ "to_count": to.len(), "attachments": attachments.len() }),
    )
    .await;

    Ok(result)
}

#[derive(Debug, Deserialize)]
pub struct DlpPrecheckRequest {
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
}

/// 送信前 DLP の警告レベル所見。
#[derive(Debug, Serialize)]
pub struct DlpPrecheckResponse {
    /// Allow 以外の所見のルール名 (日本語)。Block 相当の所見も含む —
    /// Block は `mail_send` が改めてハードブロックする (二重防御)。
    pub warnings: Vec<String>,
}

/// 送信前に DLP の Warn 所見を返す (アドバイザリ)。
///
/// `mail_send` は Block のみ止めて Warn を捨てていたため、機密マーカーや
/// 大容量メールの警告がユーザーに届かなかった。Compose が送信前に呼び、
/// 警告があれば確認ステップを挟む。オフラインでも評価可能
/// (自組織ドメインは settings / from アドレスから推定)。
pub async fn mail_dlp_precheck(req: DlpPrecheckRequest) -> Result<DlpPrecheckResponse, String> {
    let account_id = current_account_id().await;
    // 事前チェック時点では添付は存在しない (Compose に添付 UI が無い)。
    let dlp = outbound_dlp_eval(
        &account_id,
        &req.from,
        &req.to,
        &req.subject,
        &req.body,
        &[],
    )
    .await;
    let warnings = dlp
        .findings
        .iter()
        .filter(|f| !matches!(f.action, kaname_dlp::Action::Allow))
        .map(|f| f.rule_name.clone())
        .collect();
    Ok(DlpPrecheckResponse { warnings })
}

pub async fn mail_send_real(
    from: String,
    to: Vec<String>,
    subject: String,
    body: String,
) -> Result<String, String> {
    send_mail_core(&from, &to, &subject, &body, &[], None, "MAIL_SEND").await
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

// ============================================================================
// ローカル LLM (D2 Phase 5): Phi-4-mini の遅延ロードと BEC への配線
// ============================================================================

/// 起動済み Q-LLM サブプロセス。モデル未取得/未起動時は None。
///
/// 不信メール本文は `kaname-llm-runner` ワーカープロセスに送られる
/// (I1 の隔離境界をプロセス分離として実効化 — D121)。ワーカーは
/// macOS で `sandbox-exec`、Linux で seccomp 経由で起動される。
/// `Drop` でワーカーを終了させる。
///
/// `tokio::Mutex` ではなく `std::sync::Mutex` を使う理由: `kaname_bec::
/// LocalLlm` は同期 trait のためクロージャ内で await できない。ガードは
/// Arc クローンの瞬間だけ保持し、推論中の長いブロッキングでは保持しない
/// (stdin/stdout の直列化は `LlmSubprocess` 内部の Mutex が担う)。
static LLM_SUBPROCESS: std::sync::OnceLock<
    std::sync::Mutex<Option<std::sync::Arc<kaname_ai::subprocess::LlmSubprocess>>>,
> = std::sync::OnceLock::new();

fn llm_slot(
) -> &'static std::sync::Mutex<Option<std::sync::Arc<kaname_ai::subprocess::LlmSubprocess>>> {
    LLM_SUBPROCESS.get_or_init(|| std::sync::Mutex::new(None))
}

// ============================================================================
// MLS E2E 暗号化 (D1 Phase 4): クライアント初期化と受信エンベロープ処理
// ============================================================================

/// MLS クライアントスロット。`mls_init` で初期化される。
///
/// `tokio::Mutex` ではなく `std::sync::Mutex` の理由: `process_incoming` は
/// 同期 API でありガードを跨ぐ await がない。ポイズンされたら into_inner で
/// 復旧する (ロック保持中の panic でクライアントが失われないように)。
static MLS_CLIENT: std::sync::OnceLock<std::sync::Mutex<Option<kaname_mls::MlsMailClient>>> =
    std::sync::OnceLock::new();

fn mls_slot() -> &'static std::sync::Mutex<Option<kaname_mls::MlsMailClient>> {
    MLS_CLIENT.get_or_init(|| std::sync::Mutex::new(None))
}

/// MLS の状態。
#[derive(Debug, Serialize)]
pub struct MlsStatus {
    /// クライアントが初期化済みか。
    pub initialized: bool,
    /// 自身のメールアドレス (初期化済みの場合)。
    pub email: Option<String>,
    /// 参加/復元済みの会話数。
    pub conversations: usize,
}

/// MLS (E2E 暗号化) をこの端末で初期化する。
///
/// `email` はユーザー入力 — JMAP の Session/account 応答にはメール
/// アドレスが含まれないため自動導出できない。状態は
/// `<data_dir>/kaname/mls.db` (SQLCipher、鍵は `mls.key` — history.key と
/// 同じ 0600 ファイル運用) に永続化され、再起動後は同じ会話・署名鍵・
/// Welcome リプレイ帳簿が復元される (D1 Phase 2)。
///
/// 既定暗号スイートは `KanameHybridPqc` (X-Wing = ML-KEM-768 + X25519
/// ハイブリッド) — 製品が謳う耐量子 E2E の実体。
pub async fn mls_init(email: String) -> Result<MlsStatus, String> {
    let addr = kaname_mls::EmailAddress::parse(email.as_str())
        .map_err(|e| format!("メールアドレスが不正です: {e}"))?;
    let base = dirs::data_dir()
        .ok_or_else(|| "データディレクトリを特定できません".to_string())?
        .join("kaname");
    std::fs::create_dir_all(&base)
        .map_err(|e| format!("データディレクトリを作成できません: {e}"))?;
    let key_hex = resolve_or_create_key(&base, "mls.key", "mls.db")?;
    let client = kaname_mls::MlsMailClient::try_new_persistent(
        kaname_mls::Identity {
            email: addr,
            display_name: None,
            default_ciphersuite: kaname_mls::Ciphersuite::KanameHybridPqc,
        },
        &base.join("mls.db"),
        &key_hex,
    )
    .map_err(|e| format!("MLS の初期化に失敗: {e}"))?;
    let status = MlsStatus {
        initialized: true,
        email: Some(client.identity.email.as_str().to_string()),
        conversations: client.list_conversations().len(),
    };
    *mls_slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(client);
    Ok(status)
}

/// MLS の現在の状態を返す (未初期化でもエラーにしない)。
pub async fn mls_status() -> MlsStatus {
    let guard = mls_slot().lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(c) => MlsStatus {
            initialized: true,
            email: Some(c.identity.email.as_str().to_string()),
            conversations: c.list_conversations().len(),
        },
        None => MlsStatus {
            initialized: false,
            email: None,
            conversations: 0,
        },
    }
}

/// この端末の MLS KeyPackage を 16 進文字列で返す。
///
/// 相手の Kaname がこれを取り込むと自分を会話に招待できるようになる
/// (KeyPackage は公開情報 — 配布してよい)。手渡し向けの表示用で、
/// メール添付での送付は `mls_send_key_package` を使う (D1 Phase 3)。
pub async fn mls_key_package() -> Result<String, String> {
    let guard = mls_slot().lock().unwrap_or_else(|e| e.into_inner());
    let client = guard
        .as_ref()
        .ok_or_else(|| "MLS が初期化されていません (mls_init を先に呼んでください)".to_string())?;
    let kp = client
        .generate_key_package()
        .ok_or_else(|| "KeyPackage の生成に失敗しました".to_string())?;
    Ok(kp.bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// MLS 会話が成立している相手の情報 (Compose の暗号化表示用)。
#[derive(Debug, Serialize)]
pub struct MlsPeer {
    /// 相手のメールアドレス。
    pub email: String,
    /// 会話 ID (hex)。
    pub conversation_id: String,
    /// 現在の epoch。
    pub epoch: u64,
    /// 安全番号 — 電話等で相手と照合する値 (Phase 5 セレモニーの実体)。
    pub safety_number: Option<String>,
    /// 安全番号を相手と照合済みか (Phase 5: store の照合記録と現在値が一致)。
    pub verified: bool,
    /// 照合記録があるが現在の安全番号と一致しない = 鍵変更/再参加/中間者の
    /// 可能性 — UI は警告を出すべき。
    pub safety_changed: bool,
}

/// MLS 会話が成立している相手の一覧を返す (未初期化は空列)。
pub async fn mls_conversations() -> Vec<MlsPeer> {
    let (convs, own) = {
        let guard = mls_slot().lock().unwrap_or_else(|e| e.into_inner());
        let Some(client) = guard.as_ref() else {
            return Vec::new();
        };
        (
            client.list_conversations(),
            client.identity.email.as_str().to_string(),
        )
    };
    // 照合記録は history 側 Store (history.db の mls_conversations 行)。
    // 未接続時は verified=false/safety_changed=false — 検証状態を偽らない。
    let store = store_slot().lock().await.clone();
    let mut out = Vec::new();
    for c in &convs {
        let conv_id = c.id.as_hex();
        let recorded = match &store {
            Some(s) => s.mls_verification_state(&conv_id).await.unwrap_or(None),
            None => None,
        };
        let (verified, safety_changed) = match (&recorded, &c.safety_number) {
            (Some((recorded_sn, _)), Some(current)) => {
                (recorded_sn == current, recorded_sn != current)
            }
            _ => (false, false),
        };
        for m in &c.members {
            if m.as_str() == own {
                continue;
            }
            out.push(MlsPeer {
                email: m.as_str().to_string(),
                conversation_id: conv_id.clone(),
                epoch: c.epoch,
                safety_number: c.safety_number.clone(),
                verified,
                safety_changed,
            });
        }
    }
    out
}

/// 相手と安全番号を対面照合した記録を store に残す (D1 Phase 5)。
///
/// 照合操作自体は利用者が別経路 (電話・対面等) で行う — ここで保存する
/// のは「この時点の番号で照合した」という記録であり、以後番号が変わった
/// 場合に `mls_conversations` の `safety_changed` で警告される。
/// Store 未接続では記録先が無いためエラー。
pub async fn mls_mark_verified(to: String) -> Result<String, String> {
    let to_addr = kaname_mls::EmailAddress::parse(to.clone())
        .map_err(|e| format!("宛先アドレスが不正です: {e}"))?;
    let (conv_id, sn) = {
        let guard = mls_slot().lock().unwrap_or_else(|e| e.into_inner());
        let client = guard.as_ref().ok_or_else(|| {
            "MLS が初期化されていません (mls_init を先に呼んでください)".to_string()
        })?;
        let conv = client
            .list_conversations()
            .into_iter()
            .find(|c| c.members.iter().any(|m| m.as_str() == to_addr.as_str()))
            .ok_or_else(|| format!("{} との MLS 会話がありません", to_addr.as_str()))?;
        let sn = conv
            .safety_number
            .clone()
            .ok_or_else(|| "安全番号がまだ計算されていません".to_string())?;
        (conv.id.as_hex(), sn)
    };
    let store = store_slot().lock().await.clone().ok_or_else(|| {
        "履歴ストアが開かれていません (先にアカウント接続してください)".to_string()
    })?;
    let account = jmap_client()
        .await
        .map(|c| c.account_id().to_string())
        .unwrap_or_else(|_| "local".to_string());
    store
        .mls_mark_verified(&account, &conv_id, &sn)
        .await
        .map_err(|e| format!("照合記録の保存に失敗しました: {e}"))?;
    audit_event(
        Some(account.as_str()),
        "MLS_SAFETY_VERIFIED",
        serde_json::json!({ "conversation_id": conv_id }),
    )
    .await;
    Ok(format!(
        "{} との安全番号を照合済みとして記録しました",
        to_addr.as_str()
    ))
}

/// この端末の KeyPackage を `application/mls-key-package` 添付として
/// 相手に送信する (D1 Phase 3 — KP 配送経路、添付ベース)。
///
/// KP は公開情報 (署名公開鍵を含む) で秘匿は不要だが、配送経路での
/// 差し替えは防げない — 会話成立後に安全番号を照合するのが本来の
/// 信頼確立 (Phase 5)。送信前 DLP と監査は通常メールと同じ経路を通る。
pub async fn mls_send_key_package(to: String) -> Result<String, String> {
    let to_addr = kaname_mls::EmailAddress::parse(to.clone())
        .map_err(|e| format!("宛先アドレスが不正です: {e}"))?;
    let (from, kp_bytes) = {
        let guard = mls_slot().lock().unwrap_or_else(|e| e.into_inner());
        let client = guard.as_ref().ok_or_else(|| {
            "MLS が初期化されていません (mls_init を先に呼んでください)".to_string()
        })?;
        let kp = client
            .generate_key_package()
            .ok_or_else(|| "KeyPackage の生成に失敗しました".to_string())?;
        (client.identity.email.as_str().to_string(), kp.bytes)
    };
    let cover = format!(
        "Kaname E2E 暗号化のための KeyPackage を添付しています (送信者: {from})。\
         受信側の Kaname が自動で取り込みます。"
    );
    let att = kaname_jmap::OutgoingAttachment {
        filename: "kaname-mls-key-package.bin".to_string(),
        mime_type: kaname_render::MLS_KEY_PACKAGE_MIME.to_string(),
        data: kp_bytes,
    };
    send_mail_core(
        &from,
        std::slice::from_ref(&to),
        "Kaname MLS KeyPackage",
        &cover,
        &[att],
        None,
        "MLS_KEYPACKAGE_SEND",
    )
    .await?;
    Ok(format!(
        "KeyPackage を {} に送信しました。相手が取り込んだ後、こちらで「会話を開始」を実行してください",
        to_addr.as_str()
    ))
}

/// 受信済みの相手 KeyPackage を消費して 1:1 会話を開始し、Welcome を
/// `application/mls-envelope+cbor` 添付で送信する (D1 Phase 3)。
///
/// KP は 1 回限りの消費 (`kp_cache.consume`) — 同じ KP で二度開始は
/// できない。相手が Welcome を処理すれば以後双方向の暗号化が有効。
pub async fn mls_start_conversation(to: String) -> Result<String, String> {
    let to_addr = kaname_mls::EmailAddress::parse(to.clone())
        .map_err(|e| format!("宛先アドレスが不正です: {e}"))?;
    // JMAP 未接続で KP を消費すると会話だけが残り Welcome が届かない
    // 中途半端な状態になるため、接続を先に確認する。
    jmap_client().await?;
    let (from, conv_id, cbor) = {
        let mut guard = mls_slot().lock().unwrap_or_else(|e| e.into_inner());
        let client = guard.as_mut().ok_or_else(|| {
            "MLS が初期化されていません (mls_init を先に呼んでください)".to_string()
        })?;
        let kp = client.kp_cache().consume(&to_addr).ok_or_else(|| {
            format!(
                "{} の KeyPackage を持っていません — 先に相手の KeyPackage 添付を受信してください",
                to_addr.as_str()
            )
        })?;
        let (conv, envelope) = client
            .start_one_to_one(to_addr.clone(), kp)
            .map_err(|e| format!("会話の開始に失敗しました: {e}"))?;
        let cbor = envelope
            .to_cbor()
            .map_err(|e| format!("エンベロープの符号化に失敗しました: {e}"))?;
        (
            client.identity.email.as_str().to_string(),
            conv.id.as_hex(),
            cbor,
        )
    };
    let cover = "Kaname MLS E2E 暗号化会話への招待です。受信側の Kaname が自動で参加処理します。";
    let att = kaname_jmap::OutgoingAttachment {
        filename: "kaname-mls-invite.cbor".to_string(),
        mime_type: kaname_mls::Envelope::MIME_TYPE.to_string(),
        data: cbor,
    };
    send_mail_core(
        &from,
        std::slice::from_ref(&to),
        "Kaname MLS 会話の招待",
        cover,
        &[att],
        None,
        "MLS_WELCOME_SEND",
    )
    .await?;
    Ok(format!("MLS 会話を開始しました (会話 ID: {conv_id})"))
}

/// 会話が成立している相手へ MLS 暗号化メッセージを送信する。
///
/// 件名・本文は `subject\x00body` のペイロードとしてエンベロープ内に
/// 封入される — 外側メールの件名・本文はプレースホルダのみで、実内容
/// はサーバ・配送経路には一切出ない。DLP は暗号化前の実件名/本文に
/// 対して評価されるため、E2E でも情報漏洩防止は実効化したまま。
pub async fn mls_send_encrypted(
    to: String,
    subject: String,
    body: String,
) -> Result<String, String> {
    let to_addr = kaname_mls::EmailAddress::parse(to.clone())
        .map_err(|e| format!("宛先アドレスが不正です: {e}"))?;
    let (from, cbor) = {
        let mut guard = mls_slot().lock().unwrap_or_else(|e| e.into_inner());
        let client = guard.as_mut().ok_or_else(|| {
            "MLS が初期化されていません (mls_init を先に呼んでください)".to_string()
        })?;
        let mut conv = client
            .list_conversations()
            .into_iter()
            .find(|c| c.members.iter().any(|m| m.as_str() == to_addr.as_str()))
            .ok_or_else(|| {
                format!(
                    "{} との MLS 会話がありません — 先に KeyPackage を交換して会話を開始してください",
                    to_addr.as_str()
                )
            })?;
        // ペイロード規約: `subject\x00body` (受信側で最初の \x00 で分割)。
        // 件名も秘匿対象のためエンベロープ内に入れる。
        let payload = format!("{subject}\u{0}{body}");
        let envelope = client
            .encrypt_message(&mut conv, payload.as_bytes())
            .map_err(|e| format!("暗号化に失敗しました: {e}"))?;
        let cbor = envelope
            .to_cbor()
            .map_err(|e| format!("エンベロープの符号化に失敗しました: {e}"))?;
        (client.identity.email.as_str().to_string(), cbor)
    };
    let outer_body = "このメールは Kaname MLS で E2E 暗号化されています。受信側の Kaname クライアントで開封してください。";
    let att = kaname_jmap::OutgoingAttachment {
        filename: "kaname-mls-message.cbor".to_string(),
        mime_type: kaname_mls::Envelope::MIME_TYPE.to_string(),
        data: cbor,
    };
    send_mail_core(
        &from,
        std::slice::from_ref(&to),
        "(暗号化メッセージ)",
        outer_body,
        &[att],
        Some((&subject, &body)),
        "MLS_MESSAGE_SEND",
    )
    .await
}

/// `analyze_raw_email` 内で呼ぶ MLS エンベロープ処理。
///
/// 返り値は `(イベント列, 復号された本文列)`。未初期化時はエラーを起こさず
/// 「初期化が必要」のイベントを返す — E2E はオプトイン機能であり、
/// 未設定ユーザーのメール表示を壊してはいけない。
fn process_mls_envelopes(envelopes: &[Vec<u8>]) -> (Vec<String>, Vec<String>) {
    let mut events = Vec::new();
    let mut plaintexts = Vec::new();
    let mut guard = mls_slot().lock().unwrap_or_else(|e| e.into_inner());
    let Some(client) = guard.as_mut() else {
        if !envelopes.is_empty() {
            events.push(
                "MLS エンベロープを検出しましたが、MLS が初期化されていません (設定から有効化してください)"
                    .to_string(),
            );
        }
        return (events, plaintexts);
    };
    for raw in envelopes {
        let envelope = match kaname_mls::Envelope::from_cbor(raw) {
            Ok(e) => e,
            Err(e) => {
                events.push(format!("MLS エンベロープの解析に失敗: {e}"));
                continue;
            }
        };
        match client.process_incoming(&envelope) {
            Ok(kaname_mls::IncomingResult::Application(bytes)) => {
                plaintexts.push(String::from_utf8_lossy(&bytes).into_owned());
                events.push("暗号メッセージを復号しました".to_string());
            }
            Ok(kaname_mls::IncomingResult::WelcomeJoined(conv)) => {
                events.push(format!(
                    "新しい会話に参加しました (メンバー {} 名{})",
                    conv.members.len(),
                    conv.safety_number
                        .map(|s| format!("、安全番号: {s}"))
                        .unwrap_or_default()
                ));
            }
            Ok(kaname_mls::IncomingResult::MembershipChange { added, removed, .. }) => {
                events.push(format!(
                    "メンバーシップが変更されました (追加 {} 名、削除 {} 名)",
                    added.len(),
                    removed.len()
                ));
            }
            Ok(kaname_mls::IncomingResult::Control) => {
                events.push("MLS 制御メッセージを処理しました".to_string());
            }
            Err(e) => events.push(format!("MLS メッセージを処理できません: {e}")),
        }
    }
    (events, plaintexts)
}

/// `analyze_raw_email` 内で呼ぶ KeyPackage 添付の処理 (D1 Phase 3 受信側)。
///
/// `mls_send_key_package` で送られた `application/mls-key-package` パートを
/// 検証して `kp_cache` に投入する — 以後 `mls_start_conversation` が使える。
/// From ヘッダのアドレスを KP の所有者として記録する。不正な KP は
/// 検証で弾き、イベントとして記録する (エラーにはしない — メール表示を
/// 壊さない)。KP の「本当に相手のものか」の確認は安全番号セレモニー
/// (Phase 5) で行う。
fn process_mls_key_packages(parts: &[Vec<u8>], from_addr: &str, events: &mut Vec<String>) {
    if parts.is_empty() {
        return;
    }
    let mut guard = mls_slot().lock().unwrap_or_else(|e| e.into_inner());
    let Some(client) = guard.as_mut() else {
        events.push(
            "MLS KeyPackage を検出しましたが、MLS が初期化されていません (設定から有効化してください)"
                .to_string(),
        );
        return;
    };
    let Ok(sender) = kaname_mls::EmailAddress::parse(from_addr) else {
        events.push(format!(
            "KeyPackage 添付を受信しましたが、送信者アドレスを解析できません ({from_addr:?})"
        ));
        return;
    };
    for bytes in parts {
        let kp = kaname_mls::KeyPackage {
            bytes: bytes.clone(),
        };
        match client.validate_key_package(&kp) {
            Ok(()) => {
                client.kp_cache().add(sender.clone(), kp);
                events.push(format!(
                    "{} の KeyPackage を受信しました — 「会話を開始」で E2E 暗号化を有効にできます (信頼の確認は安全番号で)",
                    sender.as_str()
                ));
            }
            Err(e) => {
                events.push(format!("KeyPackage 添付の検証に失敗しました: {e}"));
            }
        }
    }
}

/// `LocalLlm` の `score_bec` に渡す関数本体。
/// クロージャではなく fn 項目にするのは HRTB (全ライフタイムで Fn を
/// 満たす) 上の理由による — クロージャだと `Option<&str>` のライフタイムが
/// 具体化されて `for<'a>` を満たせない。
fn bec_llm_score(subject: &str, body: &str, context: Option<&str>) -> kaname_bec::LlmScore {
    let sp = llm_slot().lock().unwrap_or_else(|e| e.into_inner()).clone();
    match sp {
        Some(sp) => {
            // D147: 不信メールデータは `Content<Untrusted>` で LLM 境界に
            // 入る — llm_bridge の入口が `&str` のままだと D17 が警告した
            // 「型を迂回する最短経路」になるため、ここで provenance 付きに包む。
            // BEC の LocalLlm trait は汎用の &str を運ぶため、型付けは
            // kaname-ai の入口でのみ強制される (provenance id は
            // パイプライン経路のラベル — 実 email_id はここでは持たない)。
            let subject_u = kaname_ai::dual_llm::Content::from_network(subject, "mail_pipeline");
            let body_u = kaname_ai::dual_llm::Content::from_network(body, "mail_pipeline");
            let context_u =
                context.map(|c| kaname_ai::dual_llm::Content::from_network(c, "mail_pipeline"));
            let (probability, explanation) = kaname_ai::llm_bridge::bec_score_subprocess(
                &sp,
                &subject_u,
                &body_u,
                context_u.as_ref(),
            );
            kaname_bec::LlmScore {
                probability,
                explanation,
            }
        }
        None => kaname_bec::LlmScore {
            probability: 0.0,
            explanation: "意味解析は無効 (決定論的シグナルのみで判定)".to_string(),
        },
    }
}

/// BEC 検出器を構築する。
///
/// Q-LLM がロード済みなら意味解析シグナルも有効化し、未ロード (モデル未取得
/// または `ai_llm_start` 未実行) なら LLM 寄与 0 — 決定論的シグナルのみで
/// 判定する。LLM なしでも製品が動く設計を維持する (`NullLlm` と同じ失敗側)。
fn bec_detector() -> kaname_bec::BecDetector {
    kaname_bec::BecDetector::new(Box::new(bec_llm_score))
}

/// AI モデル状態の IPC 向け DTO (D2 Phase 5)。
#[derive(Debug, Clone, Serialize)]
pub struct AiModelStatus {
    /// `"loaded"` (推論可能) / `"ready"` (配置済み・未ロード) / `"missing"` (未取得)。
    pub state: &'static str,
    /// 配置済みファイルサイズ (bytes)。missing 時は None。
    pub size_bytes: Option<u64>,
    /// 配布元 URL (missing 時のみ Some)。
    pub download_url: Option<String>,
    /// 配布モデルの期待サイズ (missing 時のみ Some)。
    pub expected_size_bytes: Option<u64>,
}

/// ローカル AI モデルの状態を返す (D2 Phase 5)。
pub async fn ai_model_status() -> Result<AiModelStatus, String> {
    let cfg = kaname_ai::llm_bridge::ModelConfig::quarantined();
    let loaded = llm_slot()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_some();
    Ok(match kaname_ai::llm_bridge::check_model(&cfg) {
        kaname_ai::llm_bridge::ModelStatus::Ready { size_bytes } => AiModelStatus {
            state: if loaded { "loaded" } else { "ready" },
            size_bytes: Some(size_bytes),
            download_url: None,
            expected_size_bytes: None,
        },
        kaname_ai::llm_bridge::ModelStatus::Missing {
            download_url,
            size_bytes,
            ..
        } => AiModelStatus {
            state: "missing",
            size_bytes: None,
            download_url: Some(download_url),
            expected_size_bytes: Some(size_bytes),
        },
    })
}

/// Q-LLM ワーカープロセスを起動し BEC 意味解析を有効化する (D121)。
///
/// モデル未取得時はエラー — 先に `ai_model_download` を呼ぶこと。
/// ワーカーは `kaname-llm-runner` バイナリを `sandbox-exec` (macOS) /
/// seccomp (Linux) 経由で起動するため、不信本文はホストプロセスの
/// llama.cpp に入らない (I1)。ロード+応答確認がブロッキングのため
/// `spawn_blocking` 内で実行。タイムアウトは初回のモデルロードを
/// カバーするため長め (120 秒)。
pub async fn ai_llm_start() -> Result<&'static str, String> {
    {
        let slot = llm_slot().lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return Ok("already_loaded");
        }
    }
    let cfg = kaname_ai::llm_bridge::ModelConfig::quarantined();
    // モデル不在時に spawn するとモックモード (spawn_mock) に
    // フォールバックして「起動したが推論は固定応答」になるため、
    // Ready を先に確認しておく
    if !matches!(
        kaname_ai::llm_bridge::check_model(&cfg),
        kaname_ai::llm_bridge::ModelStatus::Ready { .. }
    ) {
        return Err("モデルが未配置です — 先にダウンロードしてください".to_string());
    }
    let sp = tokio::task::spawn_blocking(move || {
        let sp = kaname_ai::subprocess::LlmSubprocess::spawn(
            kaname_ai::subprocess::SubprocessMode::Quarantined,
            &cfg.model_path,
            std::time::Duration::from_secs(120),
        )
        .map_err(|e| format!("LLM ワーカーの起動に失敗: {e}"))?;
        // ワーカーはモデルロード後に stdin を読む — ウォームアップで
        // ロード完了を確認し、ロード失敗の即終了をここで検出する
        sp.healthcheck()
            .map_err(|e| format!("LLM ワーカーが応答しません (モデルロード失敗の可能性): {e}"))?;
        Ok::<_, String>(sp)
    })
    .await
    .map_err(|e| format!("ワーカー起動タスクの失敗: {e}"))??;
    *llm_slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(std::sync::Arc::new(sp));
    tracing::info!("Q-LLM ワーカー起動完了 — BEC 意味解析が有効化 (プロセス分離)");
    Ok("loaded")
}

/// Phi-4-mini モデルをダウンロードする (D2 Phase 5)。
///
/// `expected_sha256` はモデルファイルの公式 SHA-256 (64桁 hex) —
/// HF リポジトリがゲート済みのためコードにピン留めできず、配布元から
/// 発行されるハッシュ (リリースノート/社内 IT が検証した値) を渡す。
/// 完了後に `ai_llm_start` でロード可能になる。
///
/// 進捗イベントは送出しない — kaname-ui は Tauri に依存しない設計のため
/// AppHandle を持てない。UI は不確定プログレス (スピナ) を表示すること
/// (イベント配線は src-tauri 側の拡張事項)。
pub async fn ai_model_download(expected_sha256: String) -> Result<&'static str, String> {
    let cfg = kaname_ai::llm_bridge::ModelConfig::quarantined();
    kaname_ai::llm_bridge::download_model(&cfg, &expected_sha256, |done, total| {
        tracing::info!(done, total, "AI モデルダウンロード進捗");
    })
    .await
    .map_err(|e| format!("モデルのダウンロードに失敗: {e}"))?;
    Ok("downloaded")
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
    info!(path=%redact_path(&path), "history_open");
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

    let key_hex = resolve_or_create_key(&base, "history.key", "history.db")?;

    let db_path = base.join("history.db");
    let shown = db_path.to_string_lossy().into_owned();
    history_open(shown.clone(), key_hex).await?;
    Ok(shown)
}

/// 鍵ファイルを読むか、無ければ新規生成して返す (D89)。
///
/// - 書き込みは `<key>.tmp` → rename でアトミック
///   (クラッシュでの半書き残し = 無効鍵 = DB 全損を防ぐ)
/// - 作成時点で 0600 (write→chmod の窓を塞ぐ)
/// - DB が存在するのに鍵が無い/壊れている場合は再生成せずエラー
///   (新鍵は既存 DB を読めないため、勝手に作ると静かな全損になる)
/// - 平文 SQLite DB (D75 以前) には別メッセージを返す
fn resolve_or_create_key(
    base: &std::path::Path,
    key_name: &str,
    db_name: &str,
) -> Result<String, String> {
    let key_path = base.join(key_name);
    let db_path = base.join(db_name);
    let tmp_name = format!("{key_name}.tmp");
    match std::fs::read_to_string(&key_path) {
        Ok(k) if k.trim().len() == 64 && k.trim().chars().all(|c| c.is_ascii_hexdigit()) => {
            Ok(k.trim().to_string())
        }
        _ => {
            if db_path.exists() {
                // 平文 SQLite はヘッダが "SQLite format 3\0" で始まる。
                // 鍵が無いのに平文 DB なら「鍵紛失」ではなく「未移行の旧 DB」。
                let is_plaintext = std::fs::File::open(&db_path)
                    .and_then(|mut f| {
                        use std::io::Read as _;
                        let mut head = [0u8; 16];
                        f.read_exact(&mut head).map(|_| head)
                    })
                    .map(|h| h == *b"SQLite format 3\x00")
                    .unwrap_or(false);
                let msg = if is_plaintext {
                    format!(
                        "データベースは暗号化以前の平文形式です (D75)。\
                         読み取るには移行が必要ですが未実装のため、\
                         {db_name} を退避して新しい DB を作ってください"
                    )
                } else {
                    format!(
                        "データベースの鍵ファイルが壊れているか存在しません。\
                         自動で新しい鍵を作ると既存データが読めなくなるため、\
                         {key_name} を復旧するか {db_name} を退避してください"
                    )
                };
                return Err(msg.to_string());
            }
            use rand::RngCore as _;
            let mut raw = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut raw);
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            let tmp = base.join(&tmp_name);
            // 前回のクラッシュで tmp が残っていると create_new が永久に
            // 失敗するため、先に消す。
            let _ = std::fs::remove_file(&tmp);
            {
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    opts.mode(0o600);
                }
                let mut f = opts
                    .open(&tmp)
                    .map_err(|e| format!("鍵ファイルを作成できません: {e}"))?;
                use std::io::Write as _;
                f.write_all(hex.as_bytes())
                    .map_err(|e| format!("鍵ファイルを書けません: {e}"))?;
            }
            std::fs::rename(&tmp, &key_path)
                .map_err(|e| format!("鍵ファイルを確定できません: {e}"))?;
            Ok(hex)
        }
    }
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

/// オンボーディング完了を記録する。
///
/// 以前は `not_wired` を返すスタブで、そのために Onboarding 画面は
/// 意図的に未到達にしていた (D22)。`settings` テーブルに保存する。
/// アカウント接続前でも動くよう account_id は固定の "local" を使う。
pub async fn settings_save_onboarding() -> Result<(), String> {
    let store = store_slot()
        .lock()
        .await
        .clone()
        .ok_or_else(|| "履歴データベースが開かれていません".to_string())?;
    store
        .set_setting("local", "onboarding_done", "true")
        .await
        .map_err(|e| format!("設定の保存に失敗しました: {e}"))?;
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

/// 連絡先エントリ (`"表示名" <email>` または裸の `email`) からドメインを抽出する。
fn contact_domain(contact: &str) -> Option<String> {
    let addr = match contact.rfind('<') {
        Some(i) => contact[i + 1..].trim_end_matches('>').trim(),
        None => contact.trim(),
    };
    let at = addr.rfind('@')?;
    let domain = addr[at + 1..].trim();
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_lowercase())
    }
}

/// Store の連絡先履歴から既知宛先ドメインの一覧を返す (DLP の
/// タイポドメイン誤配検出用)。未接続・失敗・0件なら空で、
/// その検査がスキップされるだけ。
async fn lookup_known_domains(account_id: &str) -> Vec<String> {
    let contacts = lookup_contacts(account_id).await;
    let mut domains: Vec<String> = contacts.iter().filter_map(|c| contact_domain(c)).collect();
    domains.sort();
    domains.dedup();
    domains
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
    // 送信者不明のメールに文体プロファイルを帰属させられない。
    if sender.is_empty() {
        return Vec::new();
    }
    let Some(hour) = send_hour else {
        return Vec::new();
    };
    let features = kaname_ssa::EmailStyleFeatures::extract(body, hour);
    if !features.is_finite() {
        // NaN/Infinity を含む特徴量はプロファイルを汚染するため取り込まない。
        return Vec::new();
    }

    // D112: プロファイルをプロセス内 HashMap のみに保持していたため、
    // 警告に必要な 10 サンプルが再起動ごとに全消去され、実運用では
    // InsufficientData のまま永久に発火しない機能だった。
    // settings テーブル (暗号化 DB 内) に JSON で永続化し、
    // インメモリはキャッシュとして使う。
    let account_id = current_account_id().await;
    let store = store_slot().lock().await.clone();
    let style_key = format!("style_profile:{sender}");

    // D136: 送信者文字列は攻撃者制御 — ユニーク送信者の数だけ
    // HashMap と settings 行が増えるため、新規プロファイル数に上限を設ける。
    // 既知送信者の更新は上限を超えても継続する。
    const MAX_STYLE_PROFILES: usize = 1_000;
    let mut profiles = style_profiles().lock().await;
    if profiles.len() >= MAX_STYLE_PROFILES && !profiles.contains_key(sender) {
        return Vec::new();
    }
    if let std::collections::hash_map::Entry::Vacant(e) = profiles.entry(sender.to_string()) {
        let loaded = match &store {
            Some(s) => s
                .get_setting(&account_id, &style_key)
                .await
                .ok()
                .flatten()
                .and_then(|json| serde_json::from_str::<kaname_ssa::SenderStyleProfile>(&json).ok())
                .filter(|p| p.sender == sender),
            None => None,
        };
        e.insert(loaded.unwrap_or_else(|| kaname_ssa::SenderStyleProfile::new(sender)));
    }
    let Some(profile) = profiles.get_mut(sender) else {
        // 到達不能: 直前の Vacant 分岐で必ず挿入済み。
        return Vec::new();
    };

    // 判定してから取り込む。取り込んでから判定すると、
    // なりすましメール自身がプロファイルを引き寄せて検出が鈍る。
    let warning =
        kaname_ssa::assess_self_send_anomaly(profile, &features, contains_financial_request);
    profile.update(&features);

    // 永続化の失敗で警告自体を失わせない (best-effort)。
    if let Some(s) = &store {
        match serde_json::to_string(profile) {
            Ok(json) => {
                if let Err(e) = s.set_setting(&account_id, &style_key, &json).await {
                    tracing::warn!(error = %e, "文体プロファイルの保存に失敗");
                }
            }
            Err(e) => tracing::warn!(error = %e, "文体プロファイルのシリアライズに失敗"),
        }
    }

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
    offset: Option<u32>,
) -> Result<Vec<kaname_store::StoredMessage>, String> {
    let store = store_slot()
        .lock()
        .await
        .clone()
        .ok_or_else(|| "履歴データベースが開かれていません".to_string())?;
    let account_id = current_account_id().await;
    store
        .list_messages(
            &account_id,
            &mailbox_id,
            limit.unwrap_or(50),
            offset.unwrap_or(0),
        )
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
    offset: Option<u32>,
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
        .search_messages(
            &account_id,
            query.trim(),
            limit.unwrap_or(50),
            offset.unwrap_or(0),
        )
        .await
        .map_err(|e| format!("検索に失敗しました: {e}"))
}

/// 現在の JMAP アカウント ID を返す。
///
/// JMAP 未接続でも保存済みメールの一覧・検索が機能するよう、
/// 接続されていなければ履歴 DB に登録済みのアカウントへフォールバックする
/// (ローカルファースト: サーバが落ちても過去の受信メールは読めるべき)。
/// 両方とも無ければ空文字。
async fn current_account_id() -> String {
    if let Ok(c) = jmap_client().await {
        return c.account_id().to_string();
    }
    if let Some(store) = store_slot().lock().await.clone() {
        if let Ok(Some(id)) = store.primary_account_id().await {
            return id;
        }
    }
    String::new()
}

/// 監査ログ (audit_log, ハッシュチェーン付き) への書き込み — best-effort。
///
/// Store が開かれていなければ記録しない。監査の失敗で本来の操作
/// (メール送受信・添付保存等) を失敗させない。ペイロードは最小限に
/// 留める — audit_log は messages/contacts と同じ暗号化 DB 内だが、
/// 不要な本文・トークン・パスは絶対に書かない。
async fn audit_event(account_id: Option<&str>, event_type: &str, payload: serde_json::Value) {
    match store_slot().lock().await.clone() {
        Some(store) => {
            if let Err(e) = store.audit(account_id, event_type, &payload).await {
                warn!(error=%e, "監査ログの書き込みに失敗");
            }
        }
        // Store が開いていなくても監査イベントを握り潰さない。
        // DLP_BLOCK のような最重要証跡が無言で失われるのを防ぐ
        // (D23 の教訓: サイレント失敗は欠陥を隠す)。
        None => warn!(event_type, "Store 未接続のため監査イベントを破棄"),
    }
}

/// メールアドレスからドメイン部を取り出す (小文字化)。
/// `"Name <a@b.com>"` のような表示名付きにも耐える。アドレス形でなければ None。
/// 現在時刻の UNIX 秒 (セレモニー期限の比較用)。
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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
    /// JMAP bodyStructure の size。同名添付の区別に使う (D91)。
    pub size: u64,
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
                size: p.size.unwrap_or(0),
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
        let path = write_unique(&dir, &safe_name, &bytes)
            .map_err(|e| format!("保存に失敗しました: {e}"))?;
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

/// 既存ファイルを上書きせず、同名があれば `name (1).ext` の形で別名にする。
///
/// 別メール由来の同名添付で先に保存したファイルを黙って上書きしないため
/// (D87)。`create_new` のアトミック作成で exists-then-write の競合も避ける。
fn write_unique(
    dir: &std::path::Path,
    name: &str,
    bytes: &[u8],
) -> Result<std::path::PathBuf, std::io::Error> {
    use std::io::ErrorKind;
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (name.to_string(), String::new()),
    };
    for i in 0..1000u32 {
        let candidate = if i == 0 {
            dir.join(name)
        } else {
            dir.join(format!("{stem} ({i}){ext}"))
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut f) => {
                use std::io::Write as _;
                f.write_all(bytes)?;
                return Ok(candidate);
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(ErrorKind::AlreadyExists.into())
}
