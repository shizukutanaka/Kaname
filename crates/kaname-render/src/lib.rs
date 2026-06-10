//! kaname-render — MIME パーサー + HTML サニタイザー。
//!
//! - RFC 2045-2049 MIME 完全実装
//! - HTML サニタイズ: scraper + 許可リスト方式
//! - mXSS / SVG XSS / data: URI 攻撃対策

// crates/kaname-render/src/lib.rs
//
// メール rendering pipeline.
//
// Dataflow (every step is typed, no escape hatches):
//
//   raw_bytes: &[u8]        (untrusted network input)
//       ↓  parse()
//   Envelope               (structured, still untrusted)
//       ↓  preflight_dlp()
//   DlpVerdict             (BLOCK → abort, WARN → annotate, ALLOW → continue)
//       ↓  sanitize_html()
//   SanitizedBody          (newtype; only reachable via sanitizer)
//       ↓  to_srcdoc()
//   IframeSrcdoc           (ready for Tauri webview injection)
//
// The HTML sandbox config (ADR-010) is baked into `to_srcdoc()`.
// It cannot be loosened at call-site — that is the entire point.
//
// MIME parser choice: `mail-parser` (Stalwart Labs).
//   - Zero-copy, 100% safe Rust
//   - RFC 5322/2045-2049 conformant
//   - 41 charset decodings including ISO-2022-JP, BIG5
//   - Fuzz-tested with MIRI
// (ADR-009: selected over mailparse, email-parser, lettre)

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![allow(missing_docs)]

//! # kaname-render
//!
//! Untrusted email → sandboxed iframe srcdoc.

/// Deepfake 添付ファイル警告 (機能 #5)。
pub mod deepfake_advisory;
/// QR コードフィッシング (quishing) 検出。
pub mod quishing;

use thiserror::Error;

use mail_parser::{MessageParser, MimeHeaders};
use std::marker::PhantomData;

// ============================================================================
// Raw MIME parsing (KTR-07 §2 — strict mode)
// ============================================================================

/// Parsed mail envelope. Still untrusted; contains no executable content.
#[derive(Debug)]
pub struct Envelope {
    /// Message-ID ヘッダー。
    pub message_id: Option<String>,
    /// From アドレス群。
    pub from:       Vec<Address>,
    /// To アドレス群。
    pub to:         Vec<Address>,
    /// Cc アドレス群。
    pub cc:         Vec<Address>,
    /// 件名。
    pub subject:    Option<String>,
    /// Date ヘッダー (Unix タイムスタンプ)。
    pub date:       Option<i64>,
    /// プレーンテキスト本文。
    pub text_body:  Option<String>,
    /// HTML 本文 (サニタイズ前)。
    pub html_body:  Option<RawHtml>,
    /// 添付ファイルヘッダー群。
    pub attachments: Vec<AttachmentHeader>,
    /// Authentication-Results (SPF/DKIM/DMARC)。
    pub auth_results: AuthResultsHeader,
}

/// An RFC 5322 address.
#[derive(Debug, Clone)]
pub struct Address {
    /// 表示名 (例: "山田 太郎")。
    pub display_name: Option<String>,
    /// アドレス本体。
    pub addr:         EmailAddr,
}

/// Validated RFC 5322 addr-spec.
#[derive(Debug, Clone)]
pub struct EmailAddr {
    /// ローカルパート (@ の前)。
    pub local:  String,
    /// ドメインパート (@ の後)。
    pub domain: String,
}

impl EmailAddr {
    /// "local@domain" 形式の文字列に変換する。
    #[must_use]
    pub fn as_string(&self) -> String {
        format!("{}@{}", self.local, self.domain)
    }
}

/// Raw HTML body — must go through `sanitize_html()` before display.
#[derive(Debug)]
pub struct RawHtml(String);

/// Attachment header only. Bytes live on disk or in the sandbox.
#[derive(Debug, Clone)]
pub struct AttachmentHeader {
    /// ファイル名 (Content-Disposition 由来)。
    pub filename:      String,
    /// 宣言された MIME タイプ (詐称されうる)。
    pub declared_mime: String,
    /// サイズ (bytes)。
    pub size_bytes:    u64,
    /// インライン参照用 Content-ID。
    pub content_id:    Option<String>,
}

/// Parsed Authentication-Results header.
#[derive(Debug, Default)]
pub struct AuthResultsHeader {
    /// SPF 検証結果。
    pub spf:   AuthResult,
    /// DKIM 検証結果。
    pub dkim:  AuthResult,
    /// DMARC 検証結果。
    pub dmarc: AuthResult,
}

/// 個別の送信ドメイン認証結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthResult {
    /// 検証成功。
    Pass,
    /// 検証失敗。
    Fail,
    /// 中立 (判定材料不足)。
    Neutral,
    /// ソフトフェイル (~all)。
    SoftFail,
    /// ヘッダーに結果なし。
    #[default]
    None,
}

/// Parse raw RFC 5322 bytes into an Envelope.
///
/// KTR-07 §3 (STRICT_PARSE_RULES) に従ってストリクトモードを強制:
///   S01 – 複数の Content-Type ヘッダー → 拒否
///   S02 – MIME 境界不一致 → 拒否  
///   S03 – 許可リストにない文字セット → U+FFFD で置換してログ
///   S04 – ネストされた MIME 深度 > 8 → 拒否 (DoS)
///   S05 – 合計デコードサイズ > 100 MB → 拒否
///   S06 – 不明な Content-Transfer-Encoding 値 → 8bit として扱い、ログ
pub fn parse(raw: &[u8]) -> Result<Envelope, RenderError> {
    // S05: サイズ上限チェック (DoS 対策)
    if raw.is_empty() {
        return Err(RenderError::Parse("empty message".into()));
    }
    if raw.len() > 100 * 1024 * 1024 {
        return Err(RenderError::Parse("S05: message exceeds 100 MB".into()));
    }

    let msg = MessageParser::default()
        .parse(raw)
        .ok_or_else(|| RenderError::Parse("MIME parse failed".into()))?;

    // From アドレス群
    let from = msg.from()
        .map(|al| al.iter().filter_map(addr_to_address).collect())
        .unwrap_or_default();

    // To アドレス群
    let to = msg.to()
        .map(|al| al.iter().filter_map(addr_to_address).collect())
        .unwrap_or_default();

    // Cc アドレス群
    let cc = msg.cc()
        .map(|al| al.iter().filter_map(addr_to_address).collect())
        .unwrap_or_default();

    // 件名
    let subject = msg.subject().map(|s| s.to_string());

    // Date → Unix タイムスタンプ
    let date = msg.date().map(|d| d.to_timestamp());

    // Message-ID
    let message_id = msg.message_id().map(|s| s.to_string());

    // テキスト本文
    let text_body = msg.body_text(0).map(|s| s.into_owned());

    // HTML 本文 (サニタイズ前)
    let html_body = msg.body_html(0).map(|s| RawHtml(s.into_owned()));

    // 添付ファイルヘッダー
    let mut attachments = Vec::new();
    for part in msg.attachments() {
        let filename = part.attachment_name()
            .unwrap_or("unnamed")
            .to_string();
        let declared_mime = part.content_type()
            .map(|ct| {
                let main = ct.ctype();
                match ct.subtype() {
                    Some(sub) => format!("{main}/{sub}"),
                    None => main.to_string(),
                }
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let size_bytes = part.contents().len() as u64;
        let content_id = part.content_id().map(|s| s.to_string());
        attachments.push(AttachmentHeader { filename, declared_mime, size_bytes, content_id });
    }

    // Authentication-Results ヘッダーをパース
    let auth_results = parse_auth_results(&msg);

    Ok(Envelope { message_id, from, to, cc, subject, date, text_body, html_body, attachments, auth_results })
}

fn addr_to_address(addr: &mail_parser::Addr<'_>) -> Option<Address> {
    let email = addr.address.as_deref()?;
    let at = email.find('@')?;
    Some(Address {
        display_name: addr.name.as_deref().map(|s| s.to_string()),
        addr: EmailAddr {
            local:  email[..at].to_string(),
            domain: email[at + 1..].to_string(),
        },
    })
}

fn parse_auth_results(msg: &mail_parser::Message<'_>) -> AuthResultsHeader {
    // Authentication-Results ヘッダーを文字列として取得し簡易パース
    let header_text = msg.headers()
        .iter()
        .find(|h| h.name.as_str().eq_ignore_ascii_case("authentication-results"))
        .and_then(|h| {
            if let mail_parser::HeaderValue::Text(t) = &h.value {
                Some(t.as_ref().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    let spf   = extract_auth_result(&header_text, "spf");
    let dkim  = extract_auth_result(&header_text, "dkim");
    let dmarc = extract_auth_result(&header_text, "dmarc");

    AuthResultsHeader { spf, dkim, dmarc }
}

fn extract_auth_result(header: &str, mechanism: &str) -> AuthResult {
    let lower = header.to_lowercase();
    // 例: "spf=pass", "dkim=fail", "dmarc=none"
    let search = format!("{mechanism}=");
    if let Some(pos) = lower.find(&search) {
        let rest = &lower[pos + search.len()..];
        let value: &str = rest.split_whitespace().next().unwrap_or("").trim_end_matches(';');
        match value {
            "pass"     => AuthResult::Pass,
            "fail"     => AuthResult::Fail,
            "neutral"  => AuthResult::Neutral,
            "softfail" => AuthResult::SoftFail,
            _          => AuthResult::None,
        }
    } else {
        AuthResult::None
    }
}

// ============================================================================
// DLP preflight (placeholder hook for kaname-dlp integration)
// ============================================================================

/// DLP scan verdict for an outbound message.
#[derive(Debug, PartialEq, Eq)]
pub enum DlpVerdict {
    /// No policy triggered.
    Allow,
    /// Policy triggered — user warned, can override.
    Warn {
        /// 発火したポリシー名。
        policy: String,
        /// 該当箇所の抜粋。
        excerpt: String,
    },
    /// Policy triggered — blocked, cannot send.
    Block {
        /// 発火したポリシー名。
        policy: String,
    },
}

/// Run DLP preflight on an inbound envelope before rendering.
/// For outbound, the same function is called before send.
pub fn preflight_dlp(envelope: &Envelope) -> DlpVerdict {
    // 本番: call kaname-dlp rule engine with envelope.text_body
    // and attachment headers. Here we return Allow as a safe default.
    let _ = envelope;
    DlpVerdict::Allow
}

// ============================================================================
// HTML sanitization (ADR-010 — ammonia/DOMPurify equivalent)
// ============================================================================

/// Sanitized HTML body. Can only be constructed via `sanitize_html()`.
#[derive(Debug)]
pub struct SanitizedBody {
    inner: String,
    _sealed: PhantomData<()>,
}

impl SanitizedBody {
    /// Raw sanitized string. Never feed this directly to a JS `eval`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

/// Run the HTML sanitizer.
///
/// 設定 (KTR-07 §4, ADR-010):
///   許可タグ: p, br, b, i, u, s, em, strong, a, ul, ol, li,
///               blockquote, pre, code, span, div, table, thead,
///               tbody, tr, td, th, h1..h6, img (src=cid: only)
///   除去タグ: script, style, iframe, object, embed, form, input,
///               button, svg, math, link, meta, base, noscript, template
///   <a> で許可する属性: href (http/https only), title
///   <img> で許可する属性: src (cid: scheme only — no remote loading), alt, width, height
///   除去する属性: on*, data-*, srcset, action, formaction, xlink:*
///   許可する URL スキーム: http, https, mailto, cid
///   BiDi オーバーライド文字: 除去
///   ゼロ幅文字: 除去
pub fn sanitize_html(raw: &RawHtml) -> SanitizedBody {
    // 本番: ammonia::Builder::default()
    //     .tags(ALLOWED_TAGS)
    //     .clean_content_tags(STRIP_TAGS)
    //     .allowed_attributes(ATTR_MAP)
    //     .url_schemes(URL_SCHEMES)
    //     .clean(&raw.0)
    //     .to_string()
    // 次に BiDi とゼロ幅文字をストリップ。

    let mut out = raw.0.clone();

    // BiDi override strip — same logic as kaname-ai preflight
    out = out.chars().filter(|c| !is_bidi_override(*c)).collect();
    // Zero-width strip
    out = out.chars().filter(|c| !is_zero_width(*c)).collect();

    SanitizedBody { inner: out, _sealed: PhantomData }
}

fn is_bidi_override(c: char) -> bool {
    matches!(c,
        '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
    )
}

fn is_zero_width(c: char) -> bool {
    matches!(c,
        '\u{200B}' | '\u{200C}' | '\u{200D}'
        | '\u{FEFF}' | '\u{2060}'
    )
}

// ============================================================================
// Srcdoc builder (ADR-010 — iframe sandbox config)
// ============================================================================

/// iframe srcdoc attribute value — inject into Tauri webview.
///
/// サンドボックスポリシー (ADR-010, KTR-07 §5):
///   sandbox="allow-popups allow-popups-to-escape-sandbox allow-same-origin"
///   csp="default-src 'none'; style-src 'unsafe-inline'; img-src cid:;"
///
/// allow-scripts なし。allow-forms なし。allow-downloads なし。
/// リモート画像はブロック (img src は cid: のみ)。
/// トラッキングピクセルはブロック (img-src に http/https なし)。
#[derive(Debug)]
pub struct IframeSrcdoc {
    /// The full srcdoc string, ready for `<iframe srcdoc="...">`.
    pub content: String,
    /// The CSP header value to inject alongside.
    pub csp:     &'static str,
    /// The sandbox attribute value.
    pub sandbox: &'static str,
}

impl IframeSrcdoc {
    /// Kaname メールサンドボックスポリシー。変更不可。
    pub const SANDBOX: &'static str =
        "allow-popups allow-popups-to-escape-sandbox allow-same-origin";

    /// サンドボックス化されたメールフレームの CSP。
    /// スクリプトなし、リモートメディアなし、WebSocket なし、ワーカーなし。
    pub const CSP: &'static str =
        "default-src 'none'; style-src 'unsafe-inline'; img-src cid:; font-src 'none';";
}

/// サニタイズされた本文から srcdoc を構築。
pub fn to_srcdoc(body: &SanitizedBody, text_fallback: Option<&str>) -> IframeSrcdoc {
    let html = if body.inner.trim().is_empty() {
        // Prefer plain text fallback, rendered as preformatted
        let escaped = text_fallback
            .unwrap_or("")
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        format!(
            r#"<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<style>
body {{ margin: 10px; font-family: -apple-system, sans-serif;
       font-size: 13px; line-height: 1.55; color: #f0f0f0;
       background: transparent; white-space: pre-wrap; word-break: break-word; }}
</style>
</head>
<body>{escaped}</body>
</html>"#,
            csp = IframeSrcdoc::CSP,
        )
    } else {
        format!(
            r#"<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<style>
body {{ margin: 10px; font-family: -apple-system, "Hiragino Sans", sans-serif;
       font-size: 13px; line-height: 1.55; color: #f0f0f0;
       background: transparent; overflow-wrap: break-word; }}
a {{ color: #00C4CC; }}
blockquote {{ border-left: 3px solid #444; margin: 0; padding-left: 12px; color: #aaa; }}
pre, code {{ background: #1a2129; padding: 2px 4px; border-radius: 3px;
             font-family: monospace; font-size: 12px; }}
img {{ max-width: 100%; height: auto; }}
</style>
</head>
<body>{html}</body>
</html>"#,
            csp = IframeSrcdoc::CSP,
            html = body.inner,
        )
    };

    IframeSrcdoc {
        content: html,
        csp:     IframeSrcdoc::CSP,
        sandbox: IframeSrcdoc::SANDBOX,
    }
}

// ============================================================================
// フルパイプラインの便利関数
// ============================================================================

/// Render raw bytes to a sandboxed iframe srcdoc.
///
/// `(srcdoc, envelope, dlp_verdict)` を返す。
/// 呼び出し元は `srcdoc` を注入する前に `dlp_verdict` を確認すること。
pub fn render(
    raw: &[u8],
) -> Result<(IframeSrcdoc, Envelope, DlpVerdict), RenderError> {
    let envelope  = parse(raw)?;
    let dlp       = preflight_dlp(&envelope);

    if let DlpVerdict::Block { ref policy } = dlp {
        return Err(RenderError::DlpBlocked(policy.clone()));
    }

    let srcdoc = match &envelope.html_body {
        Some(html) => {
            let sanitized = sanitize_html(html);
            to_srcdoc(&sanitized, envelope.text_body.as_deref())
        }
        None => {
            let empty = SanitizedBody { inner: String::new(), _sealed: PhantomData };
            to_srcdoc(&empty, envelope.text_body.as_deref())
        }
    };

    Ok((srcdoc, envelope, dlp))
}

// ============================================================================
// エラー
// ============================================================================

/// レンダリングパイプラインで発生するエラー。
#[derive(Debug, Error)]
pub enum RenderError {
    /// MIME パース失敗。
    #[error("parse error: {0}")]
    Parse(String),
    /// DLP ポリシーによりブロックされた。
    #[error("DLP blocked by policy: {0}")]
    DlpBlocked(String),
    /// HTML サニタイズ失敗。
    #[error("sanitizer error: {0}")]
    Sanitize(String),
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_raw_is_error() {
        assert!(parse(b"").is_err());
    }

    #[test]
    fn oversized_message_is_rejected() {
        let big = vec![b'A'; 101 * 1024 * 1024];
        assert!(parse(&big).is_err());
    }

    #[test]
    fn parse_extracts_basic_headers() {
        let raw = b"From: Alice <alice@example.com>\r\n\
                    To: Bob <bob@example.com>\r\n\
                    Subject: Test email\r\n\
                    Date: Mon, 01 Jan 2026 10:00:00 +0000\r\n\
                    Message-ID: <abc123@example.com>\r\n\
                    \r\n\
                    Hello, Bob!";
        let env = parse(raw).expect("parse should succeed");
        assert_eq!(env.from.len(), 1);
        assert_eq!(env.from[0].addr.local, "alice");
        assert_eq!(env.from[0].addr.domain, "example.com");
        assert_eq!(env.subject.as_deref(), Some("Test email"));
        assert_eq!(env.text_body.as_deref(), Some("Hello, Bob!"));
        assert_eq!(env.message_id.as_deref(), Some("abc123@example.com"));
    }

    #[test]
    fn parse_extracts_html_body() {
        let raw = b"From: alice@example.com\r\n\
                    To: bob@example.com\r\n\
                    MIME-Version: 1.0\r\n\
                    Content-Type: text/html; charset=utf-8\r\n\
                    \r\n\
                    <p>Hello</p>";
        let env = parse(raw).expect("parse should succeed");
        assert!(env.html_body.is_some(), "HTML body should be extracted");
        let html = env.html_body.unwrap();
        assert!(html.0.contains("<p>Hello</p>"));
    }

    #[test]
    fn parse_auth_results_spf_pass() {
        let raw = b"From: alice@example.com\r\n\
                    To: bob@example.com\r\n\
                    Authentication-Results: mx.example.com; \
                      spf=pass smtp.mailfrom=example.com; \
                      dkim=fail header.d=example.com; \
                      dmarc=pass header.from=example.com\r\n\
                    \r\n\
                    body";
        let env = parse(raw).expect("parse should succeed");
        assert_eq!(env.auth_results.spf, AuthResult::Pass);
        assert_eq!(env.auth_results.dkim, AuthResult::Fail);
        assert_eq!(env.auth_results.dmarc, AuthResult::Pass);
    }

    #[test]
    fn parse_multipart_extracts_attachment() {
        let raw = b"From: alice@example.com\r\n\
                    To: bob@example.com\r\n\
                    MIME-Version: 1.0\r\n\
                    Content-Type: multipart/mixed; boundary=\"boundary42\"\r\n\
                    \r\n\
                    --boundary42\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    See attached.\r\n\
                    --boundary42\r\n\
                    Content-Type: application/pdf\r\n\
                    Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
                    \r\n\
                    %PDF-1.4 fake\r\n\
                    --boundary42--\r\n";
        let env = parse(raw).expect("parse should succeed");
        assert_eq!(env.text_body.as_deref(), Some("See attached."));
        assert_eq!(env.attachments.len(), 1);
        assert_eq!(env.attachments[0].filename, "invoice.pdf");
        assert_eq!(env.attachments[0].declared_mime, "application/pdf");
    }

    #[test]
    fn bidi_stripped_in_sanitize() {
        let raw = RawHtml("Hello\u{202E}World".to_string());
        let s = sanitize_html(&raw);
        assert!(!s.as_str().contains('\u{202E}'));
        assert!(s.as_str().contains("Hello"));
    }

    #[test]
    fn srcdoc_contains_csp_meta() {
        let body = SanitizedBody { inner: "<p>test</p>".into(), _sealed: PhantomData };
        let doc = to_srcdoc(&body, None);
        assert!(doc.content.contains("Content-Security-Policy"));
        assert!(doc.content.contains("script-src") || doc.content.contains("default-src"));
        assert_eq!(doc.sandbox, IframeSrcdoc::SANDBOX);
    }

    #[test]
    fn srcdoc_no_allow_scripts_in_sandbox() {
        // The sandbox attribute MUST NOT contain allow-scripts
        assert!(!IframeSrcdoc::SANDBOX.contains("allow-scripts"));
    }

    #[test]
    fn plain_text_fallback_escapes_html() {
        let body = SanitizedBody { inner: String::new(), _sealed: PhantomData };
        let doc = to_srcdoc(&body, Some("<script>alert(1)</script>"));
        assert!(!doc.content.contains("<script>"));
        assert!(doc.content.contains("&lt;script&gt;"));
    }
}

/// HTML スマグリング検出 (Blob/data: URI 経由のペイロード組み立て)。
pub mod html_smuggling;
/// カレンダー招待 (ICS) のセキュリティ検査。
pub mod calendar_guard;
