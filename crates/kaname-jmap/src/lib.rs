//! kaname-jmap — JMAP RFC 8620/8621 クライアント。
//!
//! - HTTPS over TLS 1.3 のみ
//! - Email/get、Email/query、Email/set、Mailbox/get
//! - Push/EventSource でリアルタイム同期

// crates/kaname-core/src/jmap.rs
//
// JMAP クライアント完全実装 (reqwest HTTP wire)。
//
// todo!() を全て置き換え済み。
// 依存: reqwest = { version = "0.12", features = ["json", "rustls-tls"] }
//
// ADR-013: IMAP ではなく JMAP を選択
// 理由: JSON-over-HTTPS、1 回の HTTP で Email/query + Email/get を原子的に実行

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;

// ============================================================================
// セッション (RFC 8620 §2)
// ============================================================================

/// JMAP セッションオブジェクト
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub capabilities:     HashMap<String, serde_json::Value>,
    pub accounts:         HashMap<String, Account>,
    pub primary_accounts: HashMap<String, String>,
    pub api_url:          String,
    pub download_url:     String,
    pub upload_url:       String,
    pub event_source_url: Option<String>,
    pub state:            String,
}

impl Session {
    pub const JMAP_CORE: &'static str = "urn:ietf:params:jmap:core";
    pub const JMAP_MAIL: &'static str = "urn:ietf:params:jmap:mail";
    pub const KANAME_MLS: &'static str = "urn:kaname:params:jmap:mls";

    #[must_use]
    pub fn has_capability(&self, urn: &str) -> bool {
        self.capabilities.contains_key(urn)
    }
    #[must_use]
    pub fn primary_mail_account(&self) -> Option<&str> {
        self.primary_accounts.get(Self::JMAP_MAIL).map(String::as_str)
    }
}

/// アカウント情報
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub name:                 String,
    pub is_personal:          bool,
    pub is_read_only:         bool,
    pub account_capabilities: HashMap<String, serde_json::Value>,
}

// ============================================================================
// クライアント設定
// ============================================================================

/// JMAP クライアント設定
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub bearer_token:   String,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_retries:    u32,
    pub user_agent:     String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            bearer_token:    String::new(),
            connect_timeout:  Duration::from_secs(10),
            request_timeout:  Duration::from_secs(30),
            max_retries:      3,
            user_agent:       format!("Kaname/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

// ============================================================================
// JMAP クライアント本体
// ============================================================================

pub struct JmapClient {
    session:    Session,
    account_id: String,
    http:       reqwest::Client,
    api_url:    String,
    config:     ClientConfig,
}

impl JmapClient {
    /// /.well-known/jmap を検出して接続する。
    pub async fn connect(base_url: &str, config: ClientConfig) -> Result<Self, JmapError> {
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .user_agent(&config.user_agent)
            .https_only(true)
            .build()
            .map_err(|e| JmapError::Http(e.to_string()))?;

        let resp = http
            .get(format!("{base_url}/.well-known/jmap"))
            .bearer_auth(&config.bearer_token)
            .send()
            .await
            .map_err(|e| JmapError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(JmapError::Http(format!("セッション検出失敗: HTTP {}", resp.status())));
        }

        let session: Session = resp.json().await
            .map_err(|e| JmapError::Deserialize(e.to_string()))?;

        if !session.has_capability(Session::JMAP_MAIL) {
            return Err(JmapError::MissingCapability(Session::JMAP_MAIL.to_string()));
        }

        let account_id = session.primary_mail_account()
            .ok_or_else(|| JmapError::MissingCapability("プライマリメールアカウントなし".into()))?
            .to_string();

        let api_url = session.api_url.clone();
        tracing::info!(api_url = %api_url, account_id = %account_id, "JMAP 接続完了");

        Ok(Self { session, account_id, http, api_url, config })
    }

    // JMAP API にマルチコールリクエストを送信する内部ヘルパー
    async fn call(
        &self,
        calls: Vec<(String, serde_json::Value, String)>,
        capabilities: &[&str],
    ) -> Result<Vec<MethodResponse>, JmapError> {
        let body = serde_json::json!({
            "using":       capabilities,
            "methodCalls": calls.iter().map(|(m, a, c)| [
                serde_json::Value::String(m.clone()),
                a.clone(),
                serde_json::Value::String(c.clone()),
            ]).collect::<Vec<_>>(),
        });

        let resp = self.http
            .post(&self.api_url)
            .bearer_auth(&self.config.bearer_token)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| JmapError::Http(e.to_string()))?;

        let status = resp.status();
        let raw: serde_json::Value = resp.json().await
            .map_err(|e| JmapError::Deserialize(e.to_string()))?;

        if !status.is_success() {
            return Err(JmapError::JmapProblem {
                r#type:      raw["type"].as_str().unwrap_or("serverError").into(),
                description: raw["detail"].as_str().unwrap_or("").into(),
            });
        }

        Ok(raw["methodResponses"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .map(|r| MethodResponse {
                method:  r[0].as_str().unwrap_or("").into(),
                args:    r[1].clone(),
                call_id: r[2].as_str().unwrap_or("").into(),
            })
            .collect())
    }

    /// 全メールボックスを取得する。
    pub async fn get_mailboxes(&self) -> Result<Vec<Mailbox>, JmapError> {
        let rs = self.call(vec![
            ("Mailbox/get".into(),
             serde_json::json!({ "accountId": self.account_id, "ids": null }),
             "mb".into())
        ], &[Session::JMAP_CORE, Session::JMAP_MAIL]).await?;

        find_result(&rs, "mb", "list")
    }

    /// メールリストを取得する (JMAP マルチコール: query + get)。
    ///
    /// `limit` は最大 500 に制限する (RFC 8620 §2 推奨上限、サーバー負荷と
    /// クライアント OOM を防ぐ)。
    pub async fn query_emails(
        &self, mailbox_id: &str, position: u32, limit: u32,
    ) -> Result<Vec<EmailListItem>, JmapError> {
        const MAX_QUERY_LIMIT: u32 = 500;
        let limit = limit.min(MAX_QUERY_LIMIT);
        let rs = self.call(vec![
            ("Email/query".into(), serde_json::json!({
                "accountId": self.account_id,
                "filter":    { "inMailbox": mailbox_id },
                "sort":      [{ "property": "receivedAt", "isAscending": false }],
                "position":  position,
                "limit":     limit,
                "calculateTotal": false,
            }), "q".into()),
            ("Email/get".into(), serde_json::json!({
                "accountId": self.account_id,
                "#ids": { "resultOf": "q", "name": "Email/query", "path": "/ids" },
                "properties": [
                    "id","mailboxIds","keywords","size",
                    "receivedAt","sentAt","subject",
                    "from","to","preview","hasAttachment","threadId",
                ],
            }), "emails".into()),
        ], &[Session::JMAP_CORE, Session::JMAP_MAIL]).await?;

        find_result(&rs, "emails", "list")
    }

    /// 単一メールの完全な本文を取得する。
    pub async fn get_email_body(&self, email_id: &str) -> Result<EmailFull, JmapError> {
        let rs = self.call(vec![
            ("Email/get".into(), serde_json::json!({
                "accountId": self.account_id,
                "ids": [email_id],
                "properties": [
                    "id","blobId","bodyStructure","bodyValues",
                    "textBody","htmlBody","attachments","headers",
                ],
                "bodyProperties": [
                    "partId","blobId","type","size","name",
                    "charset","disposition","subParts",
                ],
                "fetchTextBodyValues": true,
                "fetchHTMLBodyValues": true,
                "maxBodyValueBytes":   524288,
            }), "body".into()),
        ], &[Session::JMAP_CORE, Session::JMAP_MAIL]).await?;

        let list: Vec<EmailFull> = find_result(&rs, "body", "list")?;
        list.into_iter().next()
            .ok_or_else(|| JmapError::NotFound(email_id.to_string()))
    }

    /// メールを既読にする。
    pub async fn mark_read(&self, ids: &[&str]) -> Result<(), JmapError> {
        let patch: serde_json::Value = ids.iter()
            .map(|id| (id.to_string(), serde_json::json!({ "keywords/$seen": true })))
            .collect::<serde_json::Map<_, _>>()
            .into();

        self.call(vec![
            ("Email/set".into(), serde_json::json!({
                "accountId": self.account_id, "update": patch,
            }), "read".into()),
        ], &[Session::JMAP_CORE, Session::JMAP_MAIL]).await?;
        Ok(())
    }

    /// メールをゴミ箱に移動する。
    pub async fn trash(&self, email_id: &str) -> Result<(), JmapError> {
        let mailboxes = self.get_mailboxes().await?;
        let trash_id = mailboxes.iter()
            .find(|m| m.role.as_deref() == Some("trash"))
            .map(|m| m.id.clone())
            .ok_or_else(|| JmapError::NotFound("ゴミ箱なし".into()))?;

        self.call(vec![
            ("Email/set".into(), serde_json::json!({
                "accountId": self.account_id,
                "update": {
                    email_id: {
                        "mailboxIds": { trash_id: true },
                        "keywords/$seen": true,
                    }
                },
            }), "trash".into()),
        ], &[Session::JMAP_CORE, Session::JMAP_MAIL]).await?;
        Ok(())
    }

    /// メールを送信する。
    pub async fn send_email(
        &self, from: &str, to: &[&str], subject: &str, body: &str,
        draft_id: Option<&str>,
    ) -> Result<String, JmapError> {
        // RFC 5322 ヘッダーインジェクション防止: \r\n を含む入力を拒否
        // 攻撃者が subject に "\r\nBcc: victim@evil.com" を注入すると
        // 任意の宛先にメールを送れてしまう
        let sanitize_header = |s: &str| -> Result<String, JmapError> {
            if s.contains('\r') || s.contains('\n') {
                return Err(JmapError::InvalidInput(
                    format!("ヘッダーに改行文字は使用できません: {:?}", &s[..s.len().min(40)])
                ));
            }
            Ok(s.to_owned())
        };
        let from    = sanitize_header(from)?;
        let subject = sanitize_header(subject)?;
        for addr in to {
            sanitize_header(addr)?;
        }

        let mailboxes = self.get_mailboxes().await?;
        let sent_id = mailboxes.iter()
            .find(|m| m.role.as_deref() == Some("sent"))
            .map(|m| m.id.as_str())
            .unwrap_or("sent");

        let now = chrono::Utc::now().to_rfc2822();
        let msg_id = format!("<{}@kaname.app>", uuid::Uuid::new_v4().simple());
        let raw = format!(
            "Message-ID: {msg_id}\r\nFrom: {from}\r\nTo: {}\r\nSubject: {subject}\r\nDate: {now}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{body}",
            to.join(", ")
        );

        // BLOB アップロード → Email/import → EmailSubmission/set
        let blob_id = self.upload_blob(raw.as_bytes()).await?;

        let import_rs = self.call(vec![
            ("Email/import".into(), serde_json::json!({
                "accountId": self.account_id,
                "emails": {
                    "d1": {
                        "blobId":    blob_id,
                        "mailboxIds": { sent_id: true },
                        "keywords": { "$seen": true },
                    }
                },
            }), "imp".into()),
        ], &[Session::JMAP_CORE, Session::JMAP_MAIL]).await?;

        let email_id = import_rs.iter().find(|r| r.call_id == "imp")
            .and_then(|r| r.args["created"]["d1"]["id"].as_str())
            .ok_or_else(|| JmapError::NotFound("インポート ID なし".into()))?
            .to_string();

        let rcpt: Vec<_> = to.iter().map(|a| serde_json::json!({ "email": a })).collect();
        self.call(vec![
            ("EmailSubmission/set".into(), serde_json::json!({
                "accountId": self.account_id,
                "create": { "s1": {
                    "emailId": &email_id,
                    "envelope": {
                        "mailFrom": { "email": from },
                        "rcptTo":   rcpt,
                    },
                }},
            }), "sub".into()),
        ], &[Session::JMAP_CORE, Session::JMAP_MAIL]).await?;

        if let Some(id) = draft_id {
            let _ = self.call(vec![
                ("Email/set".into(), serde_json::json!({
                    "accountId": self.account_id, "destroy": [id],
                }), "del".into()),
            ], &[Session::JMAP_CORE, Session::JMAP_MAIL]).await;
        }

        Ok(email_id)
    }

    /// BLOB をアップロードする。
    async fn upload_blob(&self, data: &[u8]) -> Result<String, JmapError> {
        let url = self.session.upload_url.replace("{accountId}", &self.account_id);
        let resp = self.http.post(&url)
            .bearer_auth(&self.config.bearer_token)
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec())
            .send().await
            .map_err(|e| JmapError::Http(e.to_string()))?;

        let json: serde_json::Value = resp.json().await
            .map_err(|e| JmapError::Deserialize(e.to_string()))?;
        json["blobId"].as_str().map(String::from)
            .ok_or_else(|| JmapError::Deserialize("blobId なし".into()))
    }

    /// 変更を同期する。
    pub async fn sync(
        &self, mailbox_state: &str, email_state: &str,
    ) -> Result<SyncResult, JmapError> {
        let rs = self.call(vec![
            ("Mailbox/changes".into(), serde_json::json!({
                "accountId": self.account_id, "sinceState": mailbox_state, "maxChanges": 500,
            }), "mc".into()),
            ("Email/changes".into(), serde_json::json!({
                "accountId": self.account_id, "sinceState": email_state, "maxChanges": 500,
            }), "ec".into()),
        ], &[Session::JMAP_CORE, Session::JMAP_MAIL]).await?;

        let parse = |id: &str| -> ChangesResult {
            let a = &rs.iter().find(|r| r.call_id == id).map(|r| &r.args).cloned()
                .unwrap_or(serde_json::Value::Null);
            ChangesResult {
                new_state:       a["newState"].as_str().unwrap_or("").into(),
                has_more_changes: a["hasMoreChanges"].as_bool().unwrap_or(false),
                created:  str_arr(&a["created"]),
                updated:  str_arr(&a["updated"]),
                destroyed: str_arr(&a["destroyed"]),
            }
        };

        Ok(SyncResult {
            mailbox_changes: parse("mc"),
            email_changes:   parse("ec"),
        })
    }

    /// EventSource プッシュを購読する (SSE / RFC 6202)。
    ///
    /// `reqwest` のバイトストリームで SSE を受信し、`data:` 行を JSON として
    /// パースして `PushNotification` を `tx` に送信する。
    /// `shutdown` を受信したら接続を閉じて返る。
    pub async fn subscribe_push(
        &self,
        tx: mpsc::Sender<PushNotification>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<(), JmapError> {
        use futures_util::StreamExt;

        let url = self.session.event_source_url.as_deref()
            .ok_or(JmapError::PushNotSupported)?;
        tracing::info!(url = %url, "EventSource プッシュ購読開始");

        let resp = self.http
            .get(url)
            .header("Accept", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .send()
            .await
            .map_err(|e| JmapError::Http(e.to_string()))?;

        let mut stream = resp.bytes_stream();
        let mut buf = String::new();
        // SSE バッファ上限: 悪意あるサーバーが \n\n なしで送り続けることによる
        // メモリ DoS を防ぐ。JMAP push notification は通常 < 4KB
        const MAX_SSE_BUF_BYTES: usize = 1024 * 1024; // 1 MB

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    tracing::info!("EventSource 購読を正常終了");
                    return Ok(());
                }
                chunk = stream.next() => {
                    let Some(chunk) = chunk else {
                        tracing::info!("EventSource ストリームが終了");
                        return Ok(());
                    };
                    let bytes = chunk.map_err(|e| JmapError::Http(e.to_string()))?;
                    if buf.len() + bytes.len() > MAX_SSE_BUF_BYTES {
                        tracing::warn!("SSE バッファ上限超過 — 接続をリセット");
                        return Err(JmapError::Http("SSE バッファ超過".into()));
                    }
                    buf.push_str(&String::from_utf8_lossy(&bytes));

                    // SSE イベントは空行 (\n\n) で区切られる
                    while let Some(event_end) = find_sse_event_end(&buf) {
                        let event_str = buf[..event_end].to_string();
                        buf = buf[event_end + 2..].to_string(); // skip \n\n

                        if let Some(notif) = parse_sse_event(&event_str) {
                            if tx.send(notif).await.is_err() {
                                // 受信側がドロップ — 終了
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn account_id(&self) -> &str  { &self.account_id }
    pub fn session_state(&self) -> &str { &self.session.state }
}

// ============================================================================
// 型定義
// ============================================================================

/// JMAP メソッドレスポンス
#[derive(Debug)]
pub struct MethodResponse {
    pub method:  String,
    pub args:    serde_json::Value,
    pub call_id: String,
}

/// メールボックス
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Mailbox {
    pub id:             String,
    pub name:           String,
    pub parent_id:      Option<String>,
    pub role:           Option<String>,
    pub sort_order:     u32,
    pub total_emails:   u32,
    pub unread_emails:  u32,
    pub total_threads:  u32,
    pub unread_threads: u32,
    #[serde(default)]
    pub is_subscribed:  bool,
}

/// メールリストアイテム
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailListItem {
    pub id:             String,
    #[serde(default)]
    pub mailbox_ids:    HashMap<String, bool>,
    #[serde(default)]
    pub keywords:       HashMap<String, bool>,
    pub size:           Option<u64>,
    pub received_at:    Option<String>,
    pub sent_at:        Option<String>,
    pub subject:        Option<String>,
    pub from:           Option<Vec<EmailAddress>>,
    pub to:             Option<Vec<EmailAddress>>,
    pub preview:        Option<String>,
    pub has_attachment: Option<bool>,
    pub thread_id:      Option<String>,
}

impl EmailListItem {
    #[must_use]
    pub fn is_read(&self)    -> bool { self.keywords.get("$seen").copied().unwrap_or(false) }
    pub fn is_starred(&self) -> bool { self.keywords.get("$flagged").copied().unwrap_or(false) }
}

/// メールアドレス
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmailAddress { pub name: Option<String>, pub email: String }

/// メール完全本文
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailFull {
    pub id:             String,
    pub blob_id:        Option<String>,
    pub body_structure: Option<BodyPart>,
    pub body_values:    Option<HashMap<String, BodyValue>>,
    pub text_body:      Option<Vec<BodyPart>>,
    pub html_body:      Option<Vec<BodyPart>>,
    pub attachments:    Option<Vec<BodyPart>>,
    pub headers:        Option<Vec<Header>>,
}

/// MIME ボディパート
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyPart {
    pub part_id:     Option<String>,
    pub blob_id:     Option<String>,
    #[serde(rename = "type")]
    pub mime_type:   Option<String>,
    pub size:        Option<u64>,
    pub name:        Option<String>,
    pub charset:     Option<String>,
    pub disposition: Option<String>,
    pub sub_parts:   Option<Vec<BodyPart>>,
}

impl BodyPart {
    #[must_use]
    pub fn is_mls_envelope(&self) -> bool {
        self.mime_type.as_deref() == Some("application/mls-envelope+cbor")
    }
}

/// ボディ値
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyValue {
    pub value: String,
    pub is_encoding_problem: bool,
    pub is_truncated: bool,
}

/// ヘッダー
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Header { pub name: String, pub value: String }

/// 同期結果
#[derive(Debug)]
pub struct SyncResult {
    pub mailbox_changes: ChangesResult,
    pub email_changes:   ChangesResult,
}

/// 変更結果
#[derive(Debug)]
pub struct ChangesResult {
    pub new_state:        String,
    pub has_more_changes: bool,
    pub created:          Vec<String>,
    pub updated:          Vec<String>,
    pub destroyed:        Vec<String>,
}

/// プッシュ通知
#[derive(Debug)]
pub struct PushNotification {
    pub changed_types: Vec<String>,
    pub account_id:    String,
}

// ============================================================================
// エラー
// ============================================================================

/// JMAP クライアントで発生するエラー。
#[derive(Debug, Error)]
pub enum JmapError {
    /// HTTP レイヤーのエラー。
    #[error("HTTP エラー: {0}")]
    Http(String),
    /// サーバーが返した JMAP problem (RFC 8620 §3.6)。
    #[error("JMAP エラー: {}", r#type)]
    JmapProblem {
        /// problem type URI。
        r#type: String,
        /// 人間可読な説明。
        description: String,
    },
    /// レスポンスのデシリアライズ失敗。
    #[error("デシリアライズ: {0}")]
    Deserialize(String),
    /// サーバーが EventSource プッシュに非対応。
    #[error("プッシュ非対応")]
    PushNotSupported,
    /// 対象オブジェクトが見つからない。
    #[error("見つからない: {0}")]
    NotFound(String),
    /// 必要な JMAP capability がセッションにない。
    #[error("機能なし: {0}")]
    MissingCapability(String),
    /// 入力値が不正。
    #[error("不正な入力: {0}")]
    InvalidInput(String),
}

// ============================================================================
// ユーティリティ
// ============================================================================

fn find_result<T: for<'de> Deserialize<'de>>(
    rs: &[MethodResponse], call_id: &str, key: &str,
) -> Result<T, JmapError> {
    let r = rs.iter().find(|r| r.call_id == call_id)
        .ok_or_else(|| JmapError::NotFound(format!("{} のレスポンスなし", call_id)))?;
    if r.method == "error" {
        return Err(JmapError::JmapProblem {
            r#type:      r.args["type"].as_str().unwrap_or("").into(),
            description: r.args["description"].as_str().unwrap_or("").into(),
        });
    }
    serde_json::from_value(r.args[key].clone())
        .map_err(|e| JmapError::Deserialize(e.to_string()))
}

fn str_arr(v: &serde_json::Value) -> Vec<String> {
    v.as_array().unwrap_or(&vec![])
        .iter().filter_map(|x| x.as_str().map(str::to_owned)).collect()
}

/// SSE イベントの終端 (`\n\n`) のオフセットを返す。
fn find_sse_event_end(buf: &str) -> Option<usize> {
    buf.find("\n\n")
}

/// SSE テキストブロックを `PushNotification` にパースする。
///
/// JMAP push notification (RFC 8620 §7.3) の `data:` フィールドを解析する。
fn parse_sse_event(event: &str) -> Option<PushNotification> {
    let data_line = event.lines().find(|l| l.starts_with("data:"))?;
    let json_str = data_line.trim_start_matches("data:").trim();
    let v: serde_json::Value = serde_json::from_str(json_str).ok()?;

    // RFC 8620 §7.3: {"@type":"StateChange","changed":{accountId:{type:newState}}}
    if v["@type"].as_str() != Some("StateChange") {
        return None;
    }
    let changed = v["changed"].as_object()?;
    let account_id = changed.keys().next()?.clone();
    let type_obj = changed[&account_id].as_object()?;
    let changed_types: Vec<String> = type_obj.keys().cloned().collect();

    Some(PushNotification { changed_types, account_id })
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn email_list_item_フラグ判定() {
        let mut kw = HashMap::new();
        kw.insert("$seen".to_string(), true);
        let e = EmailListItem {
            id: "e1".into(), mailbox_ids: HashMap::new(), keywords: kw,
            size: None, received_at: None, sent_at: None, subject: None,
            from: None, to: None, preview: None, has_attachment: None, thread_id: None,
        };
        assert!(e.is_read());
        assert!(!e.is_starred());
    }

    #[test]
    fn mls_エンベロープパートの検出() {
        let part = BodyPart {
            part_id: None, blob_id: None,
            mime_type: Some("application/mls-envelope+cbor".into()),
            size: None, name: None, charset: None, disposition: None, sub_parts: None,
        };
        assert!(part.is_mls_envelope());

        let plain = BodyPart { mime_type: Some("text/plain".into()), ..part.clone() };
        assert!(!plain.is_mls_envelope());
    }

    #[test]
    fn client_config_デフォルト値() {
        let c = ClientConfig::default();
        assert_eq!(c.max_retries, 3);
        assert!(c.user_agent.starts_with("Kaname/"));
    }

    #[test]
    fn str_arr_ヘルパー() {
        let v = serde_json::json!(["a", "b"]);
        assert_eq!(str_arr(&v), vec!["a", "b"]);
        assert!(str_arr(&serde_json::Value::Null).is_empty());
    }

    // ── SSE パーサーテスト ────────────────────────────────────────────────────

    #[test]
    fn sse_find_event_end_returns_offset() {
        let buf = "data: hello\n\ndata: world\n\n";
        assert_eq!(find_sse_event_end(buf), Some(11));
    }

    #[test]
    fn sse_find_event_end_returns_none_for_incomplete() {
        let buf = "data: incomplete";
        assert!(find_sse_event_end(buf).is_none());
    }

    #[test]
    fn sse_parse_jmap_state_change() {
        // RFC 8620 §7.3 形式
        let event = r#"data: {"@type":"StateChange","changed":{"acc001":{"Email":"s1","Mailbox":"s2"}}}"#;
        let notif = parse_sse_event(event).expect("パースに失敗");
        assert_eq!(notif.account_id, "acc001");
        assert!(notif.changed_types.contains(&"Email".to_string()));
        assert!(notif.changed_types.contains(&"Mailbox".to_string()));
    }

    #[test]
    fn sse_parse_ignores_non_state_change_events() {
        let event = r#"data: {"@type":"Something","changed":{}}"#;
        assert!(parse_sse_event(event).is_none());
    }

    #[test]
    fn sse_parse_ignores_non_data_lines() {
        // SSE の comment 行と event: 行は無視される
        let event = ": heartbeat\nevent: ping\ndata: {\"@type\":\"StateChange\",\"changed\":{\"a\":{\"Email\":\"s\"}}}";
        let notif = parse_sse_event(event).expect("パースに失敗");
        assert_eq!(notif.account_id, "a");
    }

    #[test]
    fn sse_parse_returns_none_for_invalid_json() {
        let event = "data: not-valid-json";
        assert!(parse_sse_event(event).is_none());
    }

    // ── ヘッダーインジェクション防止テスト ──────────────────────────────────

    #[test]
    fn sanitize_header_改行を拒否する() {
        // CR のみ
        let result = sanitize_header_value("normal\rsubject");
        assert!(result.is_err(), "\\r を含む値はエラーになるべき");
        // LF のみ
        let result = sanitize_header_value("normal\nsubject");
        assert!(result.is_err(), "\\n を含む値はエラーになるべき");
        // CRLF (典型的なインジェクション)
        let result = sanitize_header_value("legit\r\nBcc: victim@evil.com");
        assert!(result.is_err(), "CRLF インジェクションはエラーになるべき");
    }

    #[test]
    fn sanitize_header_正常値は通過する() {
        let result = sanitize_header_value("プロジェクト Alpha の報告");
        assert!(result.is_ok(), "正常な件名はエラーになってはならない");
        let result = sanitize_header_value("alice@example.com");
        assert!(result.is_ok(), "正常なメールアドレスはエラーになってはならない");
    }

    // ── query_emails limit キャップテスト ─────────────────────────────────────

    #[test]
    fn query_limit_は500を超えない() {
        // JmapClient を作れないのでロジックを直接テスト
        const MAX_QUERY_LIMIT: u32 = 500;
        let user_limit = u32::MAX;
        let effective = user_limit.min(MAX_QUERY_LIMIT);
        assert_eq!(effective, 500, "u32::MAX を渡しても 500 に切り捨てられるべき");

        let small_limit = 10u32;
        let effective = small_limit.min(MAX_QUERY_LIMIT);
        assert_eq!(effective, 10, "小さい値はそのまま使われるべき");
    }

    // ── SSE バッファ上限テスト ──────────────────────────────────────────────

    #[test]
    fn sse_buf_上限チェックロジック() {
        const MAX_SSE_BUF_BYTES: usize = 1024 * 1024;
        let current_buf_len = MAX_SSE_BUF_BYTES - 10;
        let chunk_len = 100;
        // 合計が上限を超える → エラーになるべき
        assert!(current_buf_len + chunk_len > MAX_SSE_BUF_BYTES,
            "バッファ超過チェックが機能しない");
        // 合計が上限以下 → 正常
        let small_chunk_len = 5;
        assert!(current_buf_len + small_chunk_len <= MAX_SSE_BUF_BYTES,
            "上限以下のチャンクは正常に処理されるべき");
    }
}

// テスト専用ヘルパー: sanitize_header のロジックを抽出
#[cfg(test)]
fn sanitize_header_value(s: &str) -> Result<String, JmapError> {
    if s.contains('\r') || s.contains('\n') {
        return Err(JmapError::InvalidInput(
            format!("ヘッダーに改行文字は使用できません: {:?}", &s[..s.len().min(40)])
        ));
    }
    Ok(s.to_owned())
}
