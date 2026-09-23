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

use ammonia::Builder;
use thiserror::Error;

use mail_parser::{MessageParser, MimeHeaders};
use std::collections::HashMap;
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
    pub from: Vec<Address>,
    /// To アドレス群。
    pub to: Vec<Address>,
    /// Cc アドレス群。
    pub cc: Vec<Address>,
    /// 件名。
    pub subject: Option<String>,
    /// Date ヘッダー (Unix タイムスタンプ)。
    pub date: Option<i64>,
    /// プレーンテキスト本文。
    pub text_body: Option<String>,
    /// HTML 本文 (サニタイズ前)。
    pub html_body: Option<RawHtml>,
    /// 添付ファイルヘッダー群。
    pub attachments: Vec<AttachmentHeader>,
    /// Authentication-Results (SPF/DKIM/DMARC)。
    pub auth_results: AuthResultsHeader,
    /// Reply-To アドレス群 (BEC の返信横取り検出に使用)。
    pub reply_to: Vec<Address>,
    /// Return-Path ヘッダーのアドレス (MAIL FROM; なりすまし検出に使用)。
    pub return_path: Option<Address>,
    /// Sender ヘッダーのアドレス (RFC 5322 §3.6.2 — 実送信者)。
    ///
    /// From が複数アドレスを持つ場合に必須とされる「真の差出人」
    /// 宣言。複数 From + Sender 不在はプロトコル違反であり、
    /// 表示側がどのアドレスを採用するかパーサごとに差が出るため
    /// なりすましの手段となる (D164)。
    pub sender: Option<Address>,
    /// In-Reply-To が参照する Message-ID 群 (スレッド乗っ取り検出に使用)。
    pub in_reply_to: Vec<String>,
    /// References が参照する Message-ID 群 (スレッド乗っ取り検出に使用)。
    pub references: Vec<String>,
    /// DKIM-Signature ヘッダーの生値 (`l=` タグ乱用・リプレイ検出に使用)。
    /// 複数署名がある場合は先頭のみ保持する。
    pub dkim_signature: Option<String>,
    /// List-Unsubscribe ヘッダーの生値 (D174 — 配信経路専用リンクの
    /// 検査に使用)。本文に現れないリンクは本文 URL 抽出を通らない
    /// ため、ヘッダー由来のリンクを明示的に検査に回す。
    pub list_unsubscribe: Option<String>,
    /// `multipart/signed` 宣言があるのに署名パートが無いか —
    /// 「署名済み」の体裁を持つが検証対象が存在しない偽装の兆候 (D241)。
    pub incomplete_signed_structure: bool,
}

/// An RFC 5322 address.
#[derive(Debug, Clone)]
pub struct Address {
    /// 表示名 (例: "山田 太郎")。
    pub display_name: Option<String>,
    /// アドレス本体。
    pub addr: EmailAddr,
}

/// Validated RFC 5322 addr-spec.
#[derive(Debug, Clone)]
pub struct EmailAddr {
    /// ローカルパート (@ の前)。
    pub local: String,
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

impl RawHtml {
    /// 未サニタイズの HTML 文字列を包む。
    ///
    /// 本型は**サニタイズ前の untrusted 入力**を表すマーカーであり、
    /// 任意の文字列から構築できること自体が正しい (信頼を主張する型ではない)。
    /// 表示可能な形にするには必ず `sanitize_html()` を通す必要があり、
    /// `SanitizedBody` はサニタイザ経由でしか得られない。
    ///
    /// `parse()` が MIME から本文を取り出す通常経路に加え、
    /// 既に HTML 文字列を手元に持っている呼び出し側 (ストア済み本文の再表示等)
    /// が同じサニタイズ経路に載せられるようにするための入口。
    #[must_use]
    pub fn new(html: String) -> Self {
        Self(html)
    }

    /// 未サニタイズの HTML を文字列として参照する (解析用 — 表示には使わない)。
    ///
    /// 表示目的で中身を取り出す経路は `sanitize_html` のみ。本アクセサは
    /// `html_to_text` のような「ユーザーが見る本文から検査用テキストを
    /// 復元する」解析経路のための入口であり、返り値を iframe 等に
    /// そのまま描画してはならない。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Attachment header only. Bytes live on disk or in the sandbox.
#[derive(Debug, Clone)]
pub struct AttachmentHeader {
    /// ファイル名 (Content-Disposition 由来)。
    pub filename: String,
    /// 宣言された MIME タイプ (詐称されうる)。
    pub declared_mime: String,
    /// サイズ (bytes)。
    pub size_bytes: u64,
    /// インライン参照用 Content-ID。
    pub content_id: Option<String>,
}

/// Parsed Authentication-Results header.
#[derive(Debug, Default)]
pub struct AuthResultsHeader {
    /// SPF 検証結果。
    pub spf: AuthResult,
    /// DKIM 検証結果。
    pub dkim: AuthResult,
    /// DMARC 検証結果。
    pub dmarc: AuthResult,
    /// ARC 検証結果 (転送チェーンの真正性。RFC 8617)。
    /// メーリングリスト等の正当な転送で SPF/DKIM が崩れたときの
    /// 緩和シグナル、および転送経路での改ざんシグナルとして使う。
    pub arc: AuthResult,
    /// ヘッダを記述した MTA の識別子 (authserv-id, RFC 8601 §2.2)。
    ///
    /// RFC 8601 §7.1 は、MUA が信頼する authserv-id のリストと照合して
    /// 結果を受け入れることを要求する。Kaname は受信経路の MTA ドメインを
    /// まだ設定として持たない (docs/gap-analysis.md D44) ため、現時点では
    /// **検証ではなく露出のみ**行う — 下流・将来の信頼リスト照合が判別に
    /// 使えるよう記述元を保持する。ヘッダ値をそのまま信頼する前提は
    /// 変わらない (docs/threat-model.md §3.15b, gap-analysis D18)。
    pub authserv_id: Option<String>,
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
    let from = msg
        .from()
        .map(|al| al.iter().filter_map(addr_to_address).collect())
        .unwrap_or_default();

    // To アドレス群
    let to = msg
        .to()
        .map(|al| al.iter().filter_map(addr_to_address).collect())
        .unwrap_or_default();

    // Cc アドレス群
    let cc = msg
        .cc()
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
        let filename = part.attachment_name().unwrap_or("unnamed").to_string();
        let declared_mime = part
            .content_type()
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
        attachments.push(AttachmentHeader {
            filename,
            declared_mime,
            size_bytes,
            content_id,
        });
    }

    // Reply-To / Return-Path (BEC 判定に供給するため抽出する)
    let reply_to = msg
        .reply_to()
        .map(|al| al.iter().filter_map(addr_to_address).collect())
        .unwrap_or_default();
    let return_path = match msg.return_path() {
        mail_parser::HeaderValue::Address(a) => a.iter().next().and_then(addr_to_address),
        // Return-Path は空 (`<>`) が正常なので、他の形式は None として扱う
        _ => None,
    };

    // In-Reply-To / References (スレッド乗っ取り判定に供給するため抽出する)
    let in_reply_to = msg
        .in_reply_to()
        .as_text_list()
        .unwrap_or_default()
        .iter()
        .map(|s| s.to_string())
        .collect();
    let references = msg
        .references()
        .as_text_list()
        .unwrap_or_default()
        .iter()
        .map(|s| s.to_string())
        .collect();

    // Sender ヘッダー (RFC 5322 §3.6.2 — 複数 From の場合の実送信者宣言)。
    // 複数 From + Sender 不在はプロトコル違反のなりすまし兆候 (D164)。
    let sender = msg.header_values("Sender").find_map(|v| match v {
        mail_parser::HeaderValue::Address(a) => a.iter().next().and_then(addr_to_address),
        _ => None,
    });

    // DKIM-Signature ヘッダーの生値 (複数ある場合は先頭のみ — `l=` 検査用)
    let dkim_signature = msg
        .header_values("DKIM-Signature")
        .find_map(|v| v.as_text().map(|s| s.to_string()));

    // List-Unsubscribe ヘッダー (ワンクリック登録解除リンク。
    // メタスペースでの評判判定・ドメイン不一致検査に回すため保持)
    let list_unsubscribe = msg
        .header_values("List-Unsubscribe")
        .find_map(|v| v.as_text().map(|s| s.to_string()));

    // Authentication-Results ヘッダーをパース
    let auth_results = parse_auth_results(&msg);

    Ok(Envelope {
        message_id,
        from,
        to,
        cc,
        subject,
        date,
        text_body,
        html_body,
        attachments,
        auth_results,
        reply_to,
        return_path,
        sender,
        in_reply_to,
        references,
        dkim_signature,
        list_unsubscribe,
        incomplete_signed_structure: has_incomplete_signed_structure(raw),
    })
}

/// `multipart/signed` 宣言があるのに署名パートが無いか判定する (D241)。
///
/// `multipart/signed` は「本文 + 署名」の構造宣言 — 署名パート
/// (`application/pgp-signature`/`application/pkcs7-signature`/`pkcs7-mime`)
/// が無いなら「署名済み」の体裁を持ちながら検証対象が存在しない
/// 偽装であり、正当な構造では成立しない。生ヘッダ走査で判定。
fn has_incomplete_signed_structure(raw: &[u8]) -> bool {
    let text = String::from_utf8_lossy(raw);
    let lower = text.to_ascii_lowercase();
    if !lower.contains("content-type: multipart/signed") {
        return false;
    }
    let has_sig_part = lower.contains("content-type: application/pgp-signature")
        || lower.contains("content-type: application/pkcs7-signature")
        || lower.contains("content-type: application/pkcs7-mime")
        || lower.contains("content-type: application/x-pkcs7-signature")
        || lower.contains("content-type: application/x-pkcs7-mime");
    !has_sig_part
}

fn addr_to_address(addr: &mail_parser::Addr<'_>) -> Option<Address> {
    let email = addr.address.as_deref()?;
    // RFC 5321: quoted local parts can contain '@' (e.g. "ceo@corp"@attacker.com).
    // Use rfind to always split on the last '@', ensuring the domain is correct.
    let at = email.rfind('@')?;
    Some(Address {
        display_name: addr.name.as_deref().map(|s| s.to_string()),
        addr: EmailAddr {
            local: email[..at].to_string(),
            domain: email[at + 1..].to_string(),
        },
    })
}

fn parse_auth_results(msg: &mail_parser::Message<'_>) -> AuthResultsHeader {
    // Authentication-Results ヘッダーを文字列として取得し簡易パース
    let header_text = msg
        .headers()
        .iter()
        .find(|h| {
            h.name
                .as_str()
                .eq_ignore_ascii_case("authentication-results")
        })
        .and_then(|h| {
            if let mail_parser::HeaderValue::Text(t) = &h.value {
                Some(t.as_ref().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    parse_auth_results_str(&header_text)
}

/// Authentication-Results ヘッダーの**値**をパースする。
///
/// `.eml` 全文がある経路は `parse`/`Envelope` 経由で内部から呼ばれるが、
/// JMAP 一覧のようにヘッダ文字列だけが手元にある経路 (kaname-ui の
/// `header:Authentication-Results:asText` 取得) でも同じ解釈を再利用するため
/// 公開する。解釈ルールは RFC 8601 — 機構結果として認めるのは各部の
/// `mechanism=result` トークンのみで、プロパティ値内の擬似トークンは
/// 機構結果と誤読しない (gap-analysis D18)。
#[must_use]
pub fn parse_auth_results_str(header_text: &str) -> AuthResultsHeader {
    // authserv-id は最初の `;` の前にある先頭トークン (RFC 8601 §2.2)。
    // `=` を含まない先頭トークンがそれに相当する。
    let authserv_id = header_text
        .split(';')
        .next()
        .and_then(|head| head.split_whitespace().next())
        .filter(|tok| !tok.contains('='))
        .map(|tok| tok.to_string());

    let spf = extract_auth_result(header_text, "spf");
    let dkim = extract_auth_result(header_text, "dkim");
    let dmarc = extract_auth_result(header_text, "dmarc");
    let arc = extract_auth_result(header_text, "arc");

    AuthResultsHeader {
        spf,
        dkim,
        dmarc,
        arc,
        authserv_id,
    }
}

fn extract_auth_result(header: &str, mechanism: &str) -> AuthResult {
    // RFC 8601: ヘッダは `;` 区切りのメソッド部の並びで、各部は
    // `mechanism=result` で始まり、後続にプロパティ (`header.d=` /
    // `smtp.mailfrom=` 等) が続く。機構結果として認めるのは各部の
    // `mechanism=result` トークンのみ — プロパティ値に `dkim=pass` のような
    // 文字列が混入しても機構結果として誤読しない
    // (gap-analysis D18: 旧実装は `find("dkim=")` の最初の一致を取っており、
    // 攻撃者が影響しうる echo フィールド内の擬似トークンを機構結果と
    // 誤認しえた)。
    for part in header.split(';') {
        for token in part.split_whitespace() {
            let Some((key, value)) = token.split_once('=') else {
                continue;
            };
            if key.eq_ignore_ascii_case(mechanism) {
                return match value.to_lowercase().as_str() {
                    "pass" => AuthResult::Pass,
                    "fail" => AuthResult::Fail,
                    "neutral" => AuthResult::Neutral,
                    "softfail" => AuthResult::SoftFail,
                    _ => AuthResult::None,
                };
            }
        }
    }
    AuthResult::None
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

/// DLP スキャナーの抽象。kaname-dlp が `DlpEngine` 用に実装する。
///
/// render は dlp より下層のクレートなので、具体的なエンジンを参照できない。
/// この trait を経由して依存性を注入する (依存グラフの単方向性を維持)。
pub trait DlpScanner {
    /// Envelope を検査して判定を返す。
    fn scan(&self, envelope: &Envelope) -> DlpVerdict;
}

/// Run DLP preflight on an inbound envelope before rendering.
/// For outbound, the same function is called before send.
///
/// スキャナー未設定時のデフォルト動作 (Allow)。実際の DLP 統合には
/// `render_with_dlp` と kaname-dlp の `EnvelopeScanner` を使うこと。
pub fn preflight_dlp(envelope: &Envelope) -> DlpVerdict {
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
///   `<a>` で許可する属性: href (http/https only), title
///   `<img>` で許可する属性: src (cid: scheme only — no remote loading), alt, width, height
///   除去する属性: on*, data-*, srcset, action, formaction, xlink:*
///   許可する URL スキーム: http, https, mailto, cid
///   BiDi オーバーライド文字: 除去
///   ゼロ幅文字: 除去
pub fn sanitize_html(raw: &RawHtml) -> SanitizedBody {
    // KTR-07 §4 / ADR-010 準拠の HTML サニタイザー。
    // ammonia (html5ever ベース) で許可リスト方式のタグ・属性フィルタリング。
    use std::collections::HashSet;

    // 許可タグ (明示リスト以外はすべて除去)
    let allowed_tags: HashSet<&str> = [
        "p",
        "br",
        "b",
        "i",
        "u",
        "s",
        "em",
        "strong",
        "a",
        "ul",
        "ol",
        "li",
        "blockquote",
        "pre",
        "code",
        "span",
        "div",
        "table",
        "thead",
        "tbody",
        "tr",
        "td",
        "th",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "img",
    ]
    .iter()
    .copied()
    .collect();

    // タグごとの許可属性 (ammonia はデフォルト全除去)
    let mut tag_attr_map: HashMap<&str, HashSet<&str>> = HashMap::new();
    tag_attr_map.insert("a", ["href", "title"].iter().copied().collect());
    tag_attr_map.insert(
        "img",
        ["src", "alt", "width", "height"].iter().copied().collect(),
    );
    tag_attr_map.insert("td", ["colspan", "rowspan"].iter().copied().collect());
    tag_attr_map.insert(
        "th",
        ["colspan", "rowspan", "scope"].iter().copied().collect(),
    );
    tag_attr_map.insert("ol", ["type", "start"].iter().copied().collect());
    tag_attr_map.insert("ul", ["type"].iter().copied().collect());
    tag_attr_map.insert("span", ["lang"].iter().copied().collect());
    tag_attr_map.insert("div", ["lang"].iter().copied().collect());
    tag_attr_map.insert("blockquote", ["cite"].iter().copied().collect());
    tag_attr_map.insert("pre", ["class"].iter().copied().collect());
    tag_attr_map.insert("code", ["class"].iter().copied().collect());

    // script, style, iframe など有害タグのコンテンツごと除去
    let strip_content_tags: HashSet<&str> = [
        "script", "style", "iframe", "object", "embed", "form", "input", "button", "svg", "math",
        "link", "meta", "base", "noscript", "template",
    ]
    .iter()
    .copied()
    .collect();

    // URL スキーム許可 (javascript: / data: などを除外)
    // ammonia 4.x はグローバルな url_schemes で全 URL 属性を制御する
    let allowed_url_schemes: HashSet<&str> =
        ["http", "https", "mailto", "cid"].iter().copied().collect();

    let mut builder = Builder::default();
    builder
        .tags(allowed_tags)
        .tag_attributes(tag_attr_map)
        .clean_content_tags(strip_content_tags)
        .url_schemes(allowed_url_schemes)
        .link_rel(Some("noopener noreferrer"));

    let cleaned = builder.clean(&raw.0).to_string();

    // img src の追加検証: cid: 以外のスキームを持つ src 属性を除去する。
    // ammonia のグローバル url_schemes は href にも影響するため、
    // img src だけを cid: に限定するポストフィルタを適用する。
    let cleaned = strip_non_cid_img_src(&cleaned);

    // BiDi override とゼロ幅文字をストリップ (ammonia 通過後に追加フィルタ)
    let out: String = cleaned
        .chars()
        .filter(|c| !is_bidi_override(*c) && !is_zero_width(*c))
        .collect();

    SanitizedBody {
        inner: out,
        _sealed: PhantomData,
    }
}

/// `<img src="...">` または `<img src='...'>` の src が `cid:` で始まらない場合は除去する。
/// ammonia の url_schemes はグローバルなので img に限定した制限はポストフィルタで実施。
fn strip_non_cid_img_src(html: &str) -> String {
    // ダブルクォート版: src="..."
    let Ok(re_double) = regex::Regex::new(r#"\bsrc\s*=\s*"([^"]*)""#) else {
        return html.to_string();
    };
    // シングルクォート版: src='...'
    // 攻撃: シングルクォートを使うと旧 regex がマッチせず cid: 以外の src が残る
    let Ok(re_single) = regex::Regex::new(r#"\bsrc\s*=\s*'([^']*)'"#) else {
        return html.to_string();
    };

    let strip = |caps: &regex::Captures<'_>| {
        let src_val = caps.get(1).map_or("", |m| m.as_str());
        if src_val.starts_with("cid:") {
            caps[0].to_string()
        } else {
            String::new()
        }
    };

    let after_double = re_double.replace_all(html, strip).to_string();
    re_single.replace_all(&after_double, strip).to_string()
}

fn is_bidi_override(c: char) -> bool {
    matches!(c,
        '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
    )
}

fn is_zero_width(c: char) -> bool {
    matches!(c,
        '\u{00AD}'               // Soft Hyphen (不可視、テキスト分割悪用)
        | '\u{200B}'..='\u{200F}' // ZW Space, ZWNJ, ZWJ, LRM, RLM
        | '\u{2060}'..='\u{2064}' // Word Joiner, 数学用不可視演算子
        | '\u{FEFF}'             // BOM / ZWNBSP
    )
}

// ============================================================================
// HTML → 検査用テキスト抽出 (hidden text salting 対策)
// ============================================================================

/// `html_to_text` の抽出結果。
#[derive(Debug, Clone)]
pub struct ExtractedBodyText {
    /// タグ除去・エンティティ復号・空白正規化済みのテキスト。
    /// 末尾に `<a href>` の宛先 URL が別行として付加される (URL 検査経路へ供給)。
    pub text: String,
    /// CSS/属性による非表示コンテンツを一定量スキップしたか
    /// (hidden text salting の兆候 — シグナル化に使う)。
    pub hidden_content: bool,
    /// アンカーテキストが URL 形で、そのドメインが実際のリンク先と
    /// 異なるリンク (URL 偽装 — 表示は正規サイト・実リンクは別ドメイン)。
    pub link_mismatches: Vec<LinkMismatch>,
}

/// 表示テキストと実リンク先が一致しないリンク (D162)。
#[derive(Debug, Clone, PartialEq)]
pub struct LinkMismatch {
    /// アンカーテキスト (可視部分、80 字で打切り)。
    pub shown_text: String,
    /// `href` の生の値。
    pub href: String,
    /// アンカーテキスト内の URL 形ドメイン (小文字)。
    pub shown_domain: String,
    /// href のホスト名 (小文字)。
    pub href_domain: String,
}

/// HTML 本文から「ユーザーが見るテキスト」を復元する (解析用 — 表示には使わない)。
///
/// # なぜ必要か
///
/// `Envelope::text_body` は text/plain パートのみを返すため、HTML のみの
/// メール (BEC/フィッシングで一般的) では本文解析への入力が空になり、
/// キーワード系検出が全て素通りしていた。また multipart/alternative で
/// text/plain にデコイ文・text/html に攻撃文を置く「パート不一致」回避も
/// 同じ穴を使う — 解析対象は「ユーザーに実際に描画される側」を含める
/// 必要がある。
///
/// # hidden text salting
///
/// Cisco Talos「Too salty to handle」(2025-10、2024-03〜2025-07 観測) が
/// 報告する手法: `display:none`・`font-size:0`・`opacity:0`・`mso-hide:all`
/// 等で見えないランダム文字列を本文に撒き、キーワードフィルタの語結合を
/// 破壊する (例: `wi<s style="display:none">QX</s>re transfer` は単純な
/// タグ除去では "wiQXre transfer" となり "wire transfer" に一致しない)。
/// 本関数は非表示指定の要素をサブツリーごとスキップすることで、
/// 可視テキストだけを結合する。一定量以上スキップした場合は
/// `hidden_content = true` を立て、呼出側が兆候として報告できるようにする。
///
/// 完全な CSS 解釈 (クラス/継承) は行わない — インライン `style=` と
/// `hidden` 属性の代表的な隠蔽指定のみを扱うヒューリスティック。
/// 検出漏れ方向ではなく過剰検出方向に寄せるため、`color:transparent` や
/// 負の `text-indent` も隠蔽指定に含める。
#[must_use]
pub fn html_to_text(html: &str) -> ExtractedBodyText {
    /// コンテンツを持たないため閉タグ探索を要しない void 要素。
    const VOID_TAGS: &[&str] = &[
        "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
        "source", "track", "wbr",
    ];
    /// 内容を丸ごと捨てる要素 (実行・スタイル・非描画メタ情報)。
    const DROP_TAGS: &[&str] = &[
        "script", "style", "head", "title", "template", "noscript", "object", "iframe", "svg",
        "textarea",
    ];
    /// テキストを区切るブロック要素 (開・閉どちらのタグでも改行を挿入)。
    const BLOCK_TAGS: &[&str] = &[
        "p", "div", "br", "li", "tr", "td", "th", "table", "ul", "ol", "h1", "h2", "h3", "h4",
        "h5", "h6", "blockquote", "pre", "section", "article", "header", "footer", "hr",
    ];

    let bytes = html.as_bytes();
    let mut pos = 0usize;
    let mut text = String::with_capacity(html.len() / 2);
    let mut hrefs: Vec<&str> = Vec::new();
    let mut hidden_chars = 0usize;
    let mut link_mismatches: Vec<LinkMismatch> = Vec::new();
    // 可視 <a> の中では、アンカーテキストを別途バッファに集め、
    // 閉タグ時に「表示 URL と実リンク先のドメイン一致」を評価する (D162)。
    let mut current_anchor: Option<(&str, String)> = None;

    while pos < bytes.len() {
        // ---- テキスト部分 (& 実体参照を復号しつつ次の '<' まで採る) ----
        if bytes[pos] != b'<' {
            let start = pos;
            while pos < bytes.len() && bytes[pos] != b'<' {
                pos += 1;
            }
            if let Some((_, ref mut buf)) = current_anchor {
                // アンカー内は可視テキストを両方へ (表示分のみ — 非表示
                // サブツリーは既に skip_subtree で落とされている)。
                let mut tmp = String::new();
                decode_entities_into(&html[start..pos], &mut tmp);
                text.push_str(&tmp);
                buf.push_str(&tmp);
            } else {
                decode_entities_into(&html[start..pos], &mut text);
            }
            continue;
        }
        // ---- コメント / DOCTYPE / PI ----
        if html[pos..].starts_with("<!--") {
            pos = find_after(html, pos + 4, "-->", bytes.len());
            continue;
        }
        if html[pos..].starts_with("<!") || html[pos..].starts_with("<?") {
            pos = find_tag_end(html, pos + 2);
            continue;
        }
        // ---- タグ名 ----
        let (name, is_end, tag_start) = if bytes[pos + 1..].first() == Some(&b'/') {
            (read_tag_name(html, pos + 2), true, pos + 2)
        } else {
            (read_tag_name(html, pos + 1), false, pos + 1)
        };
        if name.is_empty() {
            // '<' がタグ開始でない (裸の不等号) — リテラルとして保持。
            text.push('<');
            pos += 1;
            continue;
        }
        let tag_end = find_tag_end(html, tag_start + name.len());
        let tag_inner = &html[tag_start..tag_end.min(bytes.len())];
        let lower = name.to_ascii_lowercase();
        let name = lower.as_str();

        if is_end {
            if name == "a" {
                if let Some((href, buf)) = current_anchor.take() {
                    record_link_mismatch(&buf, href, &mut link_mismatches);
                }
            }
            if BLOCK_TAGS.contains(&name) {
                text.push('\n');
                if let Some((_, ref mut buf)) = current_anchor {
                    buf.push('\n');
                }
            }
            pos = tag_end;
            continue;
        }

        // void 要素は閉タグを持たないため、隠蔽判定より先に処理する
        // (<img style="display:none"> をサブツリー探索すると EOF まで落ちる)。
        let self_closing = tag_inner.trim_end().ends_with('/');
        if VOID_TAGS.contains(&name) || self_closing {
            pos = tag_end;
            if name == "br" {
                text.push('\n');
            }
            continue;
        }
        // ---- 非表示指定 / DROP 要素のサブツリー捨て ----
        let hidden = has_hiding_marker(tag_inner);
        if DROP_TAGS.contains(&name) || hidden {
            let (skipped, end) = skip_subtree(html, tag_end, name);
            if hidden && !DROP_TAGS.contains(&name) {
                hidden_chars += skipped;
            }
            pos = end;
            continue;
        }
        if BLOCK_TAGS.contains(&name) {
            text.push('\n');
            if let Some((_, ref mut buf)) = current_anchor {
                buf.push('\n');
            }
        }
        // 可視 <a> の href は宛先 URL として末尾に付加する (リンク検査へ供給)。
        // 併せてアンカーテキストの収集を開始し、閉タグで表示 URL と
        // リンク先の一致を評価する (URL 偽装 — D162)。
        if name == "a" {
            if let Some(h) = attr_value(tag_inner, "href") {
                hrefs.push(h);
                if current_anchor.is_none() {
                    current_anchor = Some((h, String::new()));
                }
            }
        }
        pos = tag_end;
    }

    // 閉タグなしの未完了アンカーも評価対象にする。
    if let Some((href, buf)) = current_anchor.take() {
        record_link_mismatch(&buf, href, &mut link_mismatches);
    }

    for h in &hrefs {
        text.push('\n');
        text.push_str(h);
    }

    ExtractedBodyText {
        text: collapse_whitespace(&text),
        // ごく短い隠し要素 (装飾・スペース等) では兆候を立てない。
        hidden_content: hidden_chars >= 32,
        link_mismatches,
    }
}

/// 本文中の難読化 URL トークンの種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfuscatedUrlKind {
    /// `hxxp://` / `hxxps://` — フィッシングキットがフィルタを
    /// 避けるために使う defanged スキーム。ブラウザ補完で
    /// そのまま開かれることもある。
    DefangedScheme,
    /// `http:\evil.example` / `https:\\evil.example` —
    /// ブラウザは `\` を `/` として受理するため移動は成功
    /// するが、`http://` 始まりのトークン抽出を通らない。
    BackslashSeparator,
    /// `httр://` (Cyrillic р U+0440) 等、ASCII と見分けの
    /// つかないスキーム — ユーザーには http と見えるが
    /// スキームとしては無効/別物で抽出をすり抜ける。
    LookalikeScheme,
}

/// 難読化 URL トークン 1 件。
#[derive(Debug, Clone, PartialEq)]
pub struct ObfuscatedUrl {
    /// 本文に現れたトークンそのまま。
    pub token: String,
    /// 難読化の種別。
    pub kind: ObfuscatedUrlKind,
    /// 評判判定に使える正規化 URL (defanged/backslash のみ。
    /// LookalikeScheme は正当な URL に復元できないため None)。
    pub normalized: Option<String>,
}

/// 本文から `http://`/`https://` で始まらない URL 形難読化
/// トークンを抽出する (D173)。
///
/// 既存の URL 抽出は `http://`/`https://` 始まりのみを拾うため、
/// `hxxp://` (defanged)・`http:\\` (ブラウザは `\` を `/` と
/// して受理)・`httр://` (Cyrillic スキーム) の 3 系統は
/// 評判判定・不一致検査のどちらにも渡らなかった。
/// PhishLabs/Kaspersky 系で観測されるフィルタ回避の定形。
#[must_use]
pub fn find_obfuscated_url_tokens(text: &str) -> Vec<ObfuscatedUrl> {
    const MAX_TOKENS: usize = 20;
    let mut out: Vec<ObfuscatedUrl> = Vec::new();
    for token in
        text.split(|c: char| c.is_whitespace() || c == '<' || c == '>' || c == '"' || c == '\'')
    {
        if token.len() < 8 {
            continue;
        }
        let lower = token.to_ascii_lowercase();
        // hxxp(s) — defanged
        if lower.starts_with("hxxp://") || lower.starts_with("hxxps://") {
            let norm = if lower.starts_with("hxxps://") {
                format!("https://{}", &token["hxxps://".len()..])
            } else {
                format!("http://{}", &token["hxxp://".len()..])
            };
            out.push(ObfuscatedUrl {
                token: token.to_string(),
                kind: ObfuscatedUrlKind::DefangedScheme,
                normalized: Some(norm),
            });
        // `http:\` / `https:\` / `http:\\` / `https:\\` — バックスラッシュ
        } else if lower.starts_with("http:\\")
            || lower.starts_with("https:\\")
            || lower.starts_with("http:/\\")
            || lower.starts_with("https:/\\")
        {
            let scheme_end = lower.find(':').unwrap_or(0);
            let norm = format!(
                "{}://{}",
                &lower[..scheme_end],
                token[scheme_end + 1..]
                    .trim_start_matches(['\\', '/'])
                    .replace('\\', "/")
            );
            out.push(ObfuscatedUrl {
                token: token.to_string(),
                kind: ObfuscatedUrlKind::BackslashSeparator,
                normalized: Some(norm),
            });
        // スキーム自体が ASCII でない (Cyrillic 等の見せかけ)
        } else if !lower.is_ascii() {
            // ASCII に畳める Cyrillic 類似字でスキーム判定
            let folded: String = lower
                .chars()
                .map(|c| match c {
                    '\u{04bb}' => 'h', // һ
                    '\u{0442}' => 't', // т
                    '\u{0440}' => 'p', // р
                    '\u{0455}' => 's', // ѕ
                    '\u{0435}' => 'e', // е
                    '\u{0430}' => 'a', // а
                    '\u{0458}' => 'j', // ј
                    '\u{0445}' => 'x', // х
                    '\u{043e}' => 'o', // о
                    '\u{0441}' => 'c', // с
                    '\u{0456}' => 'i', // і
                    c => c,
                })
                .collect();
            if (folded.starts_with("http://") || folded.starts_with("https://"))
                && !lower.starts_with("http://")
                && !lower.starts_with("https://")
            {
                out.push(ObfuscatedUrl {
                    token: token.to_string(),
                    kind: ObfuscatedUrlKind::LookalikeScheme,
                    normalized: None,
                });
            }
        }
        if out.len() >= MAX_TOKENS {
            break;
        }
    }
    out
}

/// タグ名を読む (`<`/`</` の直後から。ASCII 英字で始まらなければ空)。
fn read_tag_name(html: &str, start: usize) -> &str {
    let bytes = html.as_bytes();
    let mut end = start;
    while end < bytes.len() {
        let b = bytes[end];
        if b.is_ascii_alphanumeric() || b == b'-' {
            end += 1;
        } else {
            break;
        }
    }
    if end == start || !bytes[start].is_ascii_alphabetic() {
        ""
    } else {
        &html[start..end]
    }
}

/// 開タグ/単独タグの終端 `>` の直後位置を返す。クォート内の `>` は無視。
/// 見つからなければ EOF。
fn find_tag_end(html: &str, from: usize) -> usize {
    let bytes = html.as_bytes();
    let mut i = from;
    let mut quote = 0u8;
    while i < bytes.len() {
        let b = bytes[i];
        if quote != 0 {
            if b == quote {
                quote = 0;
            }
        } else if b == b'"' || b == b'\'' {
            quote = b;
        } else if b == b'>' {
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

/// `needle` を `from` から探し、マッチ終端の位置を返す。見つからなければ `eof`。
fn find_after(html: &str, from: usize, needle: &str, eof: usize) -> usize {
    html[from..]
        .find(needle)
        .map_or(eof, |i| from + i + needle.len())
}

/// 同名閉タグまで要素をスキップし、(スキップしたテキスト量推定, 終了位置) を返す。
/// 同名の開タグがネストする場合は深度を数える。閉タグが無ければ EOF まで落とす。
fn skip_subtree(html: &str, from: usize, name: &str) -> (usize, usize) {
    let mut depth = 1usize;
    let mut i = from;
    let bytes = html.as_bytes();
    let mut skipped = 0usize;
    while i < bytes.len() {
        let lt = match html[i..].find('<') {
            Some(off) => i + off,
            None => break,
        };
        skipped += lt - i;
        i = lt;
        if html[i..].starts_with("<!--") {
            i = find_after(html, i + 4, "-->", bytes.len());
            continue;
        }
        let is_end = bytes[i + 1..].first() == Some(&b'/');
        let nstart = if is_end { i + 2 } else { i + 1 };
        let n = read_tag_name(html, nstart);
        if n.eq_ignore_ascii_case(name) {
            if is_end {
                depth -= 1;
                if depth == 0 {
                    return (skipped, find_tag_end(html, nstart + n.len()));
                }
            } else {
                depth += 1;
            }
        }
        i = find_tag_end(html, nstart + n.len());
    }
    (skipped, bytes.len())
}

/// 開始タグ断片 (`name ...` から `>` まで) に代表的な非表示指定があるか。
fn has_hiding_marker(tag_inner: &str) -> bool {
    // `hidden` 属性 (値なし含む)。トークン末尾の `>` を落として比較する。
    if tag_inner.split_whitespace().any(|t| {
        let t = t.trim_end_matches('>');
        t.eq_ignore_ascii_case("hidden") || t.to_ascii_lowercase().starts_with("hidden=")
    }) {
        return true;
    }
    let Some(style) = attr_value(tag_inner, "style") else {
        return false;
    };
    let s = style.to_ascii_lowercase();
    let s = s.replace(' ', "");
    [
        "display:none",
        "visibility:hidden",
        "font-size:0",
        "opacity:0",
        "max-height:0",
        "height:0",
        "width:0",
        "max-width:0",
        "line-height:0",
        "mso-hide:all",
        "color:transparent",
        "text-indent:-",
        // 注: `overflow:hidden`・`position:absolute` は単独では内容を隠さない
        // (レイアウト用途が多い) ため含めない。left:-9999px 系の画面外配置は
        // text-indent:- で代表して捕捉する。
    ]
    .iter()
    .any(|marker| s.contains(marker))
}

/// 開始タグ断片から `name="value"` / `name='value'` / `name=value` / `name = "v"` の値を取る。
/// 属性名の直前は空白またはクォートを要求する (`data-style` 等の誤マッチを防ぐ)。
fn attr_value<'a>(tag_inner: &'a str, name: &str) -> Option<&'a str> {
    let lower = tag_inner.to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(rel) = lower[search_from..].find(name) {
        let idx = search_from + rel;
        search_from = idx + 1;
        let bounded = lower[..idx]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_whitespace() || c == '/' || c == '"' || c == '\'');
        if !bounded {
            continue;
        }
        let after = &tag_inner[idx + name.len()..];
        let after = after.trim_start();
        let Some(v) = after.strip_prefix('=') else {
            continue;
        };
        let v = v.trim_start();
        return match v.as_bytes().first() {
            Some(&b'"') => v[1..].find('"').map(|e| &v[1..1 + e]),
            Some(&b'\'') => v[1..].find('\'').map(|e| &v[1..1 + e]),
            _ => {
                let e = v
                    .find(|c: char| c.is_whitespace() || c == '>')
                    .unwrap_or(v.len());
                if e == 0 {
                    None
                } else {
                    Some(&v[..e])
                }
            }
        };
    }
    None
}

/// `&amp;` `&lt;` `&gt;` `&quot;` `&apos;` `&nbsp;` と 10 進/16 進数値参照を復号する。
/// 数値参照によるキーワード難読化 (`w&#105;re`) は実体参照の形で撒かれる
/// (hidden text salting の一角 — Talos 2025)。
fn decode_entities_into(src: &str, out: &mut String) {
    let mut rest = src;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        let Some(semi) = tail.find(';') else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let entity = &tail[1..semi];
        let decoded: Option<char> = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            _ => {
                if let Some(num) = entity.strip_prefix('#') {
                    let cp = if let Some(hex) = num.strip_prefix(['x', 'X']) {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        num.parse::<u32>().ok()
                    };
                    cp.and_then(char::from_u32)
                } else {
                    None
                }
            }
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &tail[semi + 1..];
            }
            // 不明な実体参照はそのまま残す (& だけ消さない)。
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
}

/// 連続する空白を 1 つの半角空白に、行頭末の空白を除去する。
fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    let mut at_line_start = true;
    for c in s.chars() {
        if c == '\n' {
            pending_space = false;
            if !out.ends_with('\n') && !out.is_empty() {
                out.push('\n');
            }
            at_line_start = true;
        } else if c.is_whitespace() {
            pending_space = !at_line_start;
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(c);
            at_line_start = false;
        }
    }
    out.trim().to_string()
}

// ============================================================================
// URL 偽装リンク検出 (D162 — anchor text vs href domain mismatch)
// ============================================================================

/// アンカーテキストに URL 形のドメインがあり、その登録ドメインが href の
/// ホストと異なる場合に `LinkMismatch` を記録する。
///
/// `<a href="https://evil.example">https://paypal.com/login</a>` のような
/// 「表示は正規サイト・実リンクは別ドメイン」の偽装を検出する
/// (フィッシングの基礎手口 — APWG/セキュリティベンダ各社の観測で頻出。
/// メールクライアントは href 先をあまり目立たせないため、表示側の
/// URL 形テキストを装うだけで誤認を誘える)。
///
/// 上限 20 件 — 大量生成によるメモリ消費を抑える。
fn record_link_mismatch(anchor_text: &str, href: &str, out: &mut Vec<LinkMismatch>) {
    if out.len() >= 20 {
        return;
    }
    let Some(href_host) = url_host(href) else {
        return;
    };
    let href_base = registrable_domain(&href_host);
    for shown in url_shaped_domains(anchor_text) {
        if registrable_domain(&shown) != href_base {
            out.push(LinkMismatch {
                shown_text: anchor_text.trim().chars().take(80).collect(),
                href: href.to_string(),
                shown_domain: shown,
                href_domain: href_host,
            });
            return;
        }
    }
}

/// URL/URI 文字列からホスト名を小文字で取り出す。
/// http(s) 以外のスキーム・相対参照・アンカーは None。
/// userinfo (`https://a.com@b.com/` → `b.com`) とポートを除去する。
fn url_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority_end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    // userinfo を除去 (`https://paypal.com@evil.com/` → evil.com)
    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    let host = if host_port.starts_with('[') {
        // IPv6: [::1] or [::1]:443
        match host_port.find(']') {
            Some(close) => &host_port[1..close],
            None => host_port,
        }
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    let host = host.trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// ホストの「登録ドメイン」近似 — 末尾 2 ラベル、ただし既知の 2 階層
/// 接尾辞 (co.jp, or.jp, co.uk, com.au, ...) の下では末尾 3 ラベル。
/// IPv4/IPv6 らしきホストは全体をそのまま使う。
/// 完全な PSL (public suffix list) ではなく、メール検査で実害の多い
/// 主要 2 階層 ccTLD のみ扱うヒューリスティック。
fn registrable_domain(host: &str) -> String {
    // IPv4/IPv6 らしきものは全体をそのまま使う
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') || host.contains(':') {
        return host.to_string();
    }
    /// ラベルがさらに国コードを前置する代表的な第二階層 TLD。
    const TWO_LEVEL: &[&str] = &[
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ed.jp", "gr.jp", "lg.jp", "geo.jp",
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "edu.au",
        "com.br", "com.cn", "net.cn", "org.cn", "com.tw", "co.kr", "or.kr", "co.nz",
        "co.in", "firm.in", "net.in", "org.in", "gen.in", "ind.in", "com.sg", "com.hk",
        "com.mx", "com.ar", "com.tr", "co.za", "com.pl", "com.my", "com.ph", "com.vn",
        "co.th", "or.th", "co.id", "com.ua", "co.il", "com.pk", "com.bd", "com.np",
    ];
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host.to_string();
    }
    let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    if TWO_LEVEL.contains(&last_two.as_str()) && labels.len() >= 3 {
        labels[labels.len() - 3..].join(".")
    } else {
        last_two
    }
}

/// テキストから URL 形のドメイン候補を抽出する (小文字)。
/// `scheme://host`、`www.` 始まり、および裸の `domain.tld[/path]` 形を拾う。
/// アンカーテキスト内を想定 — メールアドレス形 (`@` 含む) は除外する。
fn url_shaped_domains(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | '"' | '\'' | '|' | '`'
            )
    }) {
        let token = token.trim_matches(|c: char| {
            matches!(c, '.' | ',' | '!' | '?' | ':' | ';' | '*' | '~' | '^')
        });
        if token.is_empty() || token.contains('@') {
            continue;
        }
        // 1. scheme://host
        if let Some(p) = token.find("://") {
            let scheme = &token[..p];
            let ok_scheme = scheme.len() >= 2
                && scheme
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.');
            if ok_scheme {
                if let Some(h) = url_host(token) {
                    if is_plausible_host(&h) {
                        out.push(h);
                        continue;
                    }
                }
            }
        }
        // 2. www. / 裸ドメイン — パス・クエリ前までをホストとして評価
        let host_part = token
            .find(['/', '?', '#'])
            .map_or(token, |i| &token[..i]);
        let host_part = host_part.trim_end_matches('.').to_lowercase();
        if host_part.starts_with("www.") && host_part.len() > 4 {
            let h = &host_part[4..];
            if is_plausible_host(h) {
                out.push(h.to_string());
                continue;
            }
        }
        if is_plausible_host(&host_part) {
            out.push(host_part);
        }
    }
    out
}

/// `label(.label)+` 形で、TLD が 2 字以上の英字 (または非 ASCII) の妥当な
/// ホストか。ラベルは Unicode 英数字・ハイフン — Cyrillic 埋め込み
/// (`payраl.com`) を拾えるよう Unicode に寛容にする。
/// IP リテラル (全数字・ドット) も妥当として通す。
fn is_plausible_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    // IPv4 リテラル
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return host.split('.').count() == 4;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels[..labels.len() - 1] {
        if label.is_empty()
            || label.len() > 63
            || !label.chars().all(|c| c.is_alphanumeric() || c == '-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return false;
        }
    }
    // TLD: 2 字以上、全て文字 (数字 TLD は存在しない)
    let tld = labels[labels.len() - 1];
    tld.len() >= 2 && tld.chars().all(|c| c.is_alphabetic())
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
    pub csp: &'static str,
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
        csp: IframeSrcdoc::CSP,
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
pub fn render(raw: &[u8]) -> Result<(IframeSrcdoc, Envelope, DlpVerdict), RenderError> {
    render_with_dlp(raw, None)
}

/// DLP スキャナーを注入してレンダリングする。
///
/// `scanner` が `Some` の場合、parse 直後に DLP 評価が走り、
/// `Block` ならレンダリングを中断して `RenderError::DlpBlocked` を返す。
pub fn render_with_dlp(
    raw: &[u8],
    scanner: Option<&dyn DlpScanner>,
) -> Result<(IframeSrcdoc, Envelope, DlpVerdict), RenderError> {
    let envelope = parse(raw)?;
    let dlp = match scanner {
        Some(s) => s.scan(&envelope),
        None => preflight_dlp(&envelope),
    };

    if let DlpVerdict::Block { ref policy } = dlp {
        return Err(RenderError::DlpBlocked(policy.clone()));
    }

    let srcdoc = match &envelope.html_body {
        Some(html) => {
            let sanitized = sanitize_html(html);
            to_srcdoc(&sanitized, envelope.text_body.as_deref())
        }
        None => {
            let empty = SanitizedBody {
                inner: String::new(),
                _sealed: PhantomData,
            };
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
    fn extract_mls_envelopes_はmlsパートを取り出す() {
        // base64("hello-mls")
        let raw = b"From: a@kaname.app\r\nTo: b@kaname.app\r\nSubject: x\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: application/mls-envelope+cbor\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8tbWxz\r\n--B--\r\n";
        let found = extract_mls_envelopes(raw);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], b"hello-mls");
    }

    #[test]
    fn extract_mls_envelopes_はmlsパート無しで空を返す() {
        let raw = b"From: a@kaname.app\r\nTo: b@kaname.app\r\nSubject: x\r\n\r\nplain body";
        assert!(extract_mls_envelopes(raw).is_empty());
    }

    #[test]
    fn extract_mls_key_packages_はkpパートを取り出す() {
        // base64("kp-bytes")
        let raw = b"From: a@kaname.app\r\nTo: b@kaname.app\r\nSubject: x\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: application/mls-key-package\r\nContent-Transfer-Encoding: base64\r\n\r\na3AtYnl0ZXM=\r\n--B--\r\n";
        let found = extract_mls_key_packages(raw);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], b"kp-bytes");
        // エンベロープ抽出には混ざらない
        assert!(extract_mls_envelopes(raw).is_empty());
    }

    #[test]
    fn extract_mls_envelopes_はパート数上限を強制する() {
        // D126: 1 通のメールに同種 MLS パートを大量に詰めても、
        // 収集は 32 個まで — 各エンベロープは実暗号処理
        // (into_group/復号) を呼ぶため無制限は CPU DoS になる。
        let mut raw = String::from(
            "From: a@kaname.app\r\nTo: b@kaname.app\r\nSubject: x\r\n\
             MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n",
        );
        for _ in 0..50 {
            raw.push_str(
                "--B\r\nContent-Type: application/mls-envelope+cbor\r\n\
                 Content-Transfer-Encoding: base64\r\n\r\naGVsbG8tbWxz\r\n",
            );
        }
        raw.push_str("--B--\r\n");
        let found = extract_mls_envelopes(raw.as_bytes());
        assert_eq!(found.len(), 32, "MLS パートは最大 32 個まで収集");
        // KeyPackage パートも同じ上限を共有する
        let mut raw2 = String::from(
            "From: a@kaname.app\r\nTo: b@kaname.app\r\nSubject: x\r\n\
             MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n",
        );
        for _ in 0..50 {
            raw2.push_str(
                "--B\r\nContent-Type: application/mls-key-package\r\n\
                 Content-Transfer-Encoding: base64\r\n\r\na3AtYnl0ZXM=\r\n",
            );
        }
        raw2.push_str("--B--\r\n");
        let found2 = extract_mls_key_packages(raw2.as_bytes());
        assert_eq!(found2.len(), 32, "KP パートも最大 32 個まで");
    }

    #[test]
    fn extract_mls_envelopes_は入れ子深度で打ち切る() {
        // D130: message/rfc822 を極端に深く入れ子にしたメールでも
        // 再帰深度 16 で打ち切り、スタックを使い切らない。
        // 浅い層 (depth 1) のパートは正常に抽出される。
        let inner_env = "Content-Type: application/mls-envelope+cbor\r\n\
             Content-Transfer-Encoding: base64\r\n\r\naGVsbG8tbWxz\r\n";
        // 100 段の message/rfc822 を構築 (最深部に MLS パートを入れる)
        let mut deep =
            format!("From: a@kaname.app\r\nTo: b@kaname.app\r\nSubject: x\r\n\r\n{inner_env}");
        for _ in 0..100 {
            deep = format!("From: a@kaname.app\r\nContent-Type: message/rfc822\r\n\r\n{deep}");
        }
        let raw = format!(
            "From: a@kaname.app\r\nTo: b@kaname.app\r\nSubject: x\r\n\
             MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
             --B\r\nContent-Type: application/mls-envelope+cbor\r\n\
             Content-Transfer-Encoding: base64\r\n\r\nc2hhbGxvdw==\r\n\
             --B\r\nContent-Type: message/rfc822\r\n\r\n{deep}\r\n--B--\r\n"
        );
        let found = extract_mls_envelopes(raw.as_bytes());
        // 浅い層のエンベロープは取れるが、深度 16 を超える内部の
        // エンベロープは収集されない (かつクラッシュしない)
        assert!(found.contains(&b"shallow".to_vec()));
        assert!(!found.contains(&b"hello-mls".to_vec()));
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
        assert_eq!(
            env.auth_results.authserv_id.as_deref(),
            Some("mx.example.com")
        );
    }

    // ── D164: Sender ヘッダ / 複数 From ──────────────────────────────────

    #[test]
    fn parse_extracts_sender_header() {
        let raw = b"From: ceo@corp.example, attacker@evil.example\r\n\
                    Sender: attacker@evil.example\r\n\
                    To: victim@target.example\r\n\
                    \r\n\
                    body";
        let env = parse(raw).expect("parse should succeed");
        assert_eq!(env.from.len(), 2);
        let sender = env.sender.expect("Sender should be parsed");
        assert_eq!(sender.addr.as_string(), "attacker@evil.example");
    }

    #[test]
    fn parse_sender_absent_is_none() {
        let raw = b"From: alice@example.com\r\n\
                    To: bob@example.com\r\n\
                    \r\n\
                    body";
        let env = parse(raw).expect("parse should succeed");
        assert!(env.sender.is_none());
        assert_eq!(env.from.len(), 1);
    }

    #[test]
    fn parse_multiple_from_without_sender() {
        // RFC 5322 違反形: Sender なしの複数 From — 両アドレスが保持されること
        let raw = b"From: ceo@corp.example, attacker@evil.example\r\n\
                    To: victim@target.example\r\n\
                    \r\n\
                    body";
        let env = parse(raw).expect("parse should succeed");
        assert_eq!(env.from.len(), 2);
        assert_eq!(env.from[1].addr.as_string(), "attacker@evil.example");
        assert!(env.sender.is_none());
    }

    /// `parse_auth_results_str` は JMAP 一覧経路 (`header:Authentication-Results:asText`)
    /// が使う公開入口。`Envelope` 経由と同一の解釈を返すことを固定する。
    #[test]
    fn parse_auth_results_str_はヘッダ値から同じ解釈を返す() {
        let h = parse_auth_results_str(
            "mx.example.com; spf=softfail smtp.mailfrom=x.test; dkim=pass header.d=x.test; dmarc=fail header.from=x.test",
        );
        assert_eq!(h.spf, AuthResult::SoftFail);
        assert_eq!(h.dkim, AuthResult::Pass);
        assert_eq!(h.dmarc, AuthResult::Fail);
        assert_eq!(h.authserv_id.as_deref(), Some("mx.example.com"));

        let empty = parse_auth_results_str("");
        assert_eq!(empty.spf, AuthResult::None);
        assert_eq!(empty.authserv_id, None);
    }

    /// ARC 結果も解析対象 — kaname-bec の ARC シグナル (転送チェーンの
    /// 改ざん/正当な崩れ) はここからしか供給されない。
    #[test]
    fn parse_auth_results_str_は_arc_も解析する() {
        let h = parse_auth_results_str(
            "mx.example.com; spf=pass smtp.mailfrom=x.test; dkim=fail header.d=x.test; \
             dmarc=pass header.from=x.test; arc=fail i=2",
        );
        assert_eq!(h.arc, AuthResult::Fail);

        let none = parse_auth_results_str("mx.example.com; spf=pass");
        assert_eq!(none.arc, AuthResult::None);
    }

    #[test]
    fn auth_results_ignores_mechanism_like_text_in_properties() {
        // D18 回帰: プロパティ値に混入した `dkim=pass` を機構結果と誤読しない。
        // 旧実装は `find("dkim=")` の最初の一致を採ったため、spf 部の
        // smtp.mailfrom 値に含まれる擬似トークンを dkim=pass と誤認した。
        let raw = b"From: alice@example.com\r\n\
                    To: bob@example.com\r\n\
                    Authentication-Results: mx.example.com; \
                      spf=fail smtp.mailfrom=dkim=pass@evil.example; \
                      dkim=temperror header.d=evil.example; \
                      dmarc=fail header.from=evil.example\r\n\
                    \r\n\
                    body";
        let env = parse(raw).expect("parse should succeed");
        assert_eq!(env.auth_results.spf, AuthResult::Fail);
        // `smtp.mailfrom=dkim=pass@evil.example` はプロパティであり、
        // 実際の dkim 結果は temperror (未知値) → None。
        assert_eq!(
            env.auth_results.dkim,
            AuthResult::None,
            "プロパティ内の擬似トークンを dkim 結果として拾ってはいけない"
        );
        assert_eq!(env.auth_results.dmarc, AuthResult::Fail);
        assert_eq!(
            env.auth_results.authserv_id.as_deref(),
            Some("mx.example.com")
        );
    }

    #[test]
    fn auth_results_missing_authserv_id_is_none() {
        // authserv-id を欠くヘッダ (送信者自身が埋め込んだ偽ヘッダ等) では
        // 機構結果のみ読み、authserv_id は None。
        let raw = b"From: alice@example.com\r\n\
                    To: bob@example.com\r\n\
                    Authentication-Results: dkim=pass header.d=evil.example\r\n\
                    \r\n\
                    body";
        let env = parse(raw).expect("parse should succeed");
        assert_eq!(env.auth_results.dkim, AuthResult::Pass);
        assert_eq!(env.auth_results.authserv_id, None);
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
    fn is_mls_message_detects_envelope_parts() {
        // multipart/mixed 中の MLS エンベロープ
        let with_mls = "From: a@example.com\r\n\
                        Subject: sealed\r\n\
                        MIME-Version: 1.0\r\n\
                        Content-Type: multipart/mixed; boundary=\"b1\"\r\n\
                        \r\n\
                        --b1\r\n\
                        Content-Type: text/plain\r\n\
                        \r\n\
                        encrypted\r\n\
                        --b1\r\n\
                        Content-Type: application/mls-envelope+cbor\r\n\
                        \r\n\
                        <opaque>\r\n\
                        --b1--\r\n";
        assert!(is_mls_message(with_mls.as_bytes()));

        // ルート自体が MLS エンベロープ (添付扱いされない経路)
        let root_mls = "From: a@example.com\r\n\
                        Subject: sealed\r\n\
                        MIME-Version: 1.0\r\n\
                        Content-Type: application/mls-envelope+cbor\r\n\
                        \r\n\
                        <opaque>\r\n";
        assert!(is_mls_message(root_mls.as_bytes()));

        // 平文メールは false
        let plain = "From: a@example.com\r\n\
                     Subject: hi\r\n\
                     \r\n\
                     hello\r\n";
        assert!(!is_mls_message(plain.as_bytes()));
        assert!(!is_mls_message(b""));
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
        let body = SanitizedBody {
            inner: "<p>test</p>".into(),
            _sealed: PhantomData,
        };
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
        let body = SanitizedBody {
            inner: String::new(),
            _sealed: PhantomData,
        };
        let doc = to_srcdoc(&body, Some("<script>alert(1)</script>"));
        assert!(!doc.content.contains("<script>"));
        assert!(doc.content.contains("&lt;script&gt;"));
    }

    // -----------------------------------------------------------------------
    // sanitize_html — ammonia 実装のテスト
    // -----------------------------------------------------------------------

    fn raw(s: &str) -> RawHtml {
        RawHtml(s.to_string())
    }

    #[test]
    fn xss_script_tag_removed() {
        let out = sanitize_html(&raw("<script>alert(1)</script>Hello"));
        assert!(
            !out.as_str().contains("<script>"),
            "script tag must be stripped"
        );
        assert!(
            !out.as_str().contains("alert(1)"),
            "script content must be stripped too"
        );
        assert!(out.as_str().contains("Hello"));
    }

    #[test]
    fn allowed_tags_survive() {
        let out = sanitize_html(&raw("<p>Hello <b>world</b></p>"));
        assert!(out.as_str().contains("<p>"));
        assert!(out.as_str().contains("<b>"));
    }

    #[test]
    fn on_event_attributes_stripped() {
        let out = sanitize_html(&raw(
            "<a href=\"https://ok.com\" onclick=\"evil()\">click</a>",
        ));
        assert!(!out.as_str().contains("onclick"), "onclick must be removed");
        assert!(out.as_str().contains("https://ok.com"), "href must survive");
    }

    #[test]
    fn external_img_src_blocked() {
        // src=https:// は許可スキームに含まれないので ammonia が除去する
        let out = sanitize_html(&raw(
            "<img src=\"https://tracker.evil.com/px.gif\" alt=\"x\">",
        ));
        assert!(
            !out.as_str().contains("https://tracker.evil.com"),
            "remote img src must be removed"
        );
        // cid: は許可
        let out2 = sanitize_html(&raw("<img src=\"cid:part1@msg.id\" alt=\"x\">"));
        assert!(
            out2.as_str().contains("cid:part1@msg.id"),
            "cid: src must survive"
        );
    }

    #[test]
    fn iframe_stripped() {
        let out = sanitize_html(&raw("<iframe src=\"https://evil.com\"></iframe>"));
        assert!(!out.as_str().contains("iframe"), "iframe must be removed");
    }

    #[test]
    fn bidi_override_stripped_after_ammonia() {
        // BiDi 文字は ammonia がタグを除去した後にも残るので追加フィルタが必要
        let out = sanitize_html(&raw("normal\u{202E}hidden"));
        assert!(!out.as_str().contains('\u{202E}'), "RLO must be stripped");
        assert!(out.as_str().contains("normal"));
    }

    #[test]
    fn lrm_rlm_stripped() {
        // U+200E (LRM) と U+200F (RLM) は以前フィルタから漏れていた
        let out = sanitize_html(&raw("safe\u{200E}lrm\u{200F}rlm"));
        assert!(!out.as_str().contains('\u{200E}'), "LRM must be stripped");
        assert!(!out.as_str().contains('\u{200F}'), "RLM must be stripped");
        assert!(out.as_str().contains("safe"));
    }

    #[test]
    fn soft_hyphen_stripped() {
        // U+00AD (Soft Hyphen) はフィッシャーがテキストを分割して見えにくくするために使用
        let out = sanitize_html(&raw("pay\u{00AD}pal.com"));
        assert!(
            !out.as_str().contains('\u{00AD}'),
            "Soft Hyphen must be stripped"
        );
    }

    #[test]
    fn math_invisible_operators_stripped() {
        // U+2061..U+2064 (数学用不可視演算子)
        let invisible: String = ('\u{2061}'..='\u{2064}').collect();
        let out = sanitize_html(&raw(&format!("text{invisible}more")));
        for c in '\u{2061}'..='\u{2064}' {
            assert!(
                !out.as_str().contains(c),
                "Math invisible op U+{:04X} must be stripped",
                c as u32
            );
        }
    }

    #[test]
    fn javascript_href_blocked() {
        let out = sanitize_html(&raw("<a href=\"javascript:alert(1)\">click</a>"));
        assert!(
            !out.as_str().contains("javascript:"),
            "javascript: href must be blocked"
        );
    }

    // ── quoted local part の @ バイパステスト ────────────────────────────

    #[test]
    fn addr_quoted_local_part_at_splits_on_last_at() {
        // "ceo@trusted.com"@attacker.com の場合、ドメインは attacker.com でなければならない
        let addr = mail_parser::Addr {
            name: None,
            address: Some(std::borrow::Cow::Borrowed(
                "\"ceo@trusted.com\"@attacker.com",
            )),
        };
        let result = addr_to_address(&addr);
        let result = result.expect("アドレス変換が成功するべき");
        assert_eq!(
            result.addr.domain, "attacker.com",
            "quoted local part を持つアドレスのドメインは最後の @ より後であるべき"
        );
        assert_eq!(
            result.addr.local, "\"ceo@trusted.com\"",
            "quoted local part は @ の前の部分全体であるべき"
        );
    }

    #[test]
    fn addr_normal_email_splits_correctly() {
        let addr = mail_parser::Addr {
            name: Some(std::borrow::Cow::Borrowed("Alice")),
            address: Some(std::borrow::Cow::Borrowed("alice@example.com")),
        };
        let result = addr_to_address(&addr).expect("通常アドレスは変換できるべき");
        assert_eq!(result.addr.local, "alice");
        assert_eq!(result.addr.domain, "example.com");
    }

    #[test]
    fn single_quoted_img_src_is_stripped() {
        // 攻撃: src='...' (シングルクォート) でトラッキングピクセルを埋め込む
        // 旧 regex はダブルクォートのみ対応だったため、シングルクォートが通過していた
        let out = sanitize_html(&raw("<img src='https://tracker.evil.com/px.gif' alt='x'>"));
        assert!(
            !out.as_str().contains("tracker.evil.com"),
            "シングルクォートの remote img src は除去されるべき: {}",
            out.as_str()
        );
    }

    #[test]
    fn single_quoted_cid_src_is_preserved() {
        let out = sanitize_html(&raw("<img src='cid:part1@msg.id' alt='x'>"));
        assert!(
            out.as_str().contains("cid:part1@msg.id"),
            "cid: のシングルクォートは保持されるべき"
        );
    }

    #[test]
    fn addr_no_at_sign_returns_none() {
        let addr = mail_parser::Addr {
            name: None,
            address: Some(std::borrow::Cow::Borrowed("invalid-no-at")),
        };
        assert!(
            addr_to_address(&addr).is_none(),
            "@ なしアドレスは None を返すべき"
        );
    }

    // ── D160: html_to_text (HTML のみメールの解析対象化 + hidden text salting) ──

    #[test]
    fn html_to_text_strips_basic_tags() {
        let e = html_to_text("<p>Hello <b>world</b></p>");
        assert_eq!(e.text, "Hello world");
        assert!(!e.hidden_content);
    }

    #[test]
    fn html_to_text_drops_script_style_head() {
        let e = html_to_text(
            "<html><head><style>body{color:red}</style><title>t</title></head>\
             <body>見える本文<script>alert(1)</script></body></html>",
        );
        assert_eq!(e.text, "見える本文", "{}", e.text);
    }

    #[test]
    fn html_to_text_recovers_visible_text_from_salting() {
        // Cisco Talos 型: 非表示スパンで語を分断する salt を捨てる
        let e = html_to_text(
            "<p>wi<span style=\"display:none\">QXJZ</span>re \
             <span style=\"font-size:0\">AAAA</span>transfer urgently</p>",
        );
        assert_eq!(e.text, "wire transfer urgently", "{}", e.text);
    }

    #[test]
    fn html_to_text_flags_bulk_hidden_content() {
        let html = format!(
            "<p>wi<span style=\"display:none\">{}</span>re transfer</p>",
            "x".repeat(40)
        );
        let e = html_to_text(&html);
        assert!(e.text.contains("wire transfer"), "{}", e.text);
        assert!(e.hidden_content, "大量の非表示テキストで hidden_content が立つべき");
    }

    #[test]
    fn html_to_text_drops_each_hiding_style() {
        for style in [
            "display:none",
            "visibility:hidden",
            "opacity:0",
            "mso-hide:all",
            "font-size:0px",
            "color:transparent",
            "text-indent:-9999px",
        ] {
            let html = format!("<p>a<span style=\"{style}\">hidden</span>b</p>");
            let e = html_to_text(&html);
            assert_eq!(e.text, "ab", "{style} の中身を落とすべき: {}", e.text);
        }
    }

    #[test]
    fn html_to_text_drops_hidden_attribute() {
        let e = html_to_text("<p>a<span hidden>gone</span>b</p>");
        assert_eq!(e.text, "ab");
    }

    #[test]
    fn html_to_text_skips_nested_same_name_hidden() {
        // display:none の div 内に同名 div がネストしても閉タグを取り違えない
        let e = html_to_text("<div style=\"display:none\">x<div>y</div>z</div><p>ok</p>");
        assert_eq!(e.text, "ok", "{}", e.text);
    }

    #[test]
    fn html_to_text_decodes_entities() {
        let e = html_to_text("<p>w&#105;re &amp; &#xA9; urgent&nbsp;invoice</p>");
        assert_eq!(e.text, "wire & © urgent invoice", "{}", e.text);
        assert_eq!(html_to_text("a&lt;b&gt;c&quot;").text, "a<b>c\"");
    }

    #[test]
    fn html_to_text_appends_visible_hrefs() {
        let e = html_to_text(
            "<a href=\"https://phish.example/x\">click</a> and \
             <a href='https://e2.jp'>here</a>",
        );
        assert!(e.text.contains("click"), "{}", e.text);
        assert!(e.text.contains("https://phish.example/x"), "{}", e.text);
        assert!(e.text.contains("https://e2.jp"), "{}", e.text);
    }

    #[test]
    fn html_to_text_skips_hrefs_inside_hidden_elements() {
        let e = html_to_text(
            "<span style=\"display:none\"><a href=\"https://bad.example\">x</a>\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</span><a href=\"https://ok.example\">y</a>",
        );
        assert!(!e.text.contains("bad.example"), "{}", e.text);
        assert!(e.text.contains("ok.example"), "{}", e.text);
    }

    #[test]
    fn html_to_text_void_hidden_element_does_not_swallow_document() {
        // 回帰: <img style="display:none"> は void — 閉タグを探して EOF まで
        // 落ちると後続本文が全て失われる
        let e = html_to_text("<img style=\"display:none\" src=\"x\">visible after");
        assert!(e.text.contains("visible after"), "{}", e.text);
    }

    #[test]
    fn html_to_text_handles_malformed_and_edge_cases() {
        // 閉じないタグ・裸の不等号・コメント・data-style 誤マッチ
        assert_eq!(html_to_text("<b>bold tail").text, "bold tail");
        assert_eq!(html_to_text("a<!-- salt -->b").text, "ab");
        assert_eq!(html_to_text("<span data-style=\"display:none\">keep</span>").text, "keep");
        assert!(html_to_text("a < b").text.contains("a < b"));
    }

    #[test]
    fn html_to_text_japanese_email_keywords_visible() {
        let e = html_to_text(
            "<html><body><p>至急、下記口座へ振込をお願いします。</p>\
             <p>みずほ銀行 本店 普通 1234567</p></body></html>",
        );
        assert!(e.text.contains("至急"), "{}", e.text);
        assert!(e.text.contains("振込"), "{}", e.text);
    }

    // ---- D162: リンク表示 vs 実リンク先のドメイン不一致 (URL 偽装) ----

    #[test]
    fn link_mismatch_basic_scheme_url_text() {
        let e = html_to_text(
            r#"<p><a href="https://evil.example/steal">https://paypal.com/login</a></p>"#,
        );
        assert_eq!(e.link_mismatches.len(), 1);
        let m = &e.link_mismatches[0];
        assert_eq!(m.shown_domain, "paypal.com");
        assert_eq!(m.href_domain, "evil.example");
    }

    #[test]
    fn link_mismatch_same_domain_is_clean() {
        let e = html_to_text(
            r#"<p><a href="https://paypal.com/login">https://paypal.com/login</a></p>"#,
        );
        assert!(e.link_mismatches.is_empty());
    }

    #[test]
    fn link_mismatch_subdomain_same_base_is_clean() {
        // 登録ドメインが同じならサブドメイン差は誤検出しない
        let e = html_to_text(
            r#"<p><a href="https://www.paypal.com/x">paypal.com</a></p>"#,
        );
        assert!(e.link_mismatches.is_empty());
    }

    #[test]
    fn link_mismatch_userinfo_confusion_flagged() {
        // href の userinfo 偽装: 表示は legit、実 host は attacker
        let e = html_to_text(
            r#"<p><a href="https://paypal.com@evil.example/">paypal.com</a></p>"#,
        );
        assert_eq!(e.link_mismatches.len(), 1);
        assert_eq!(e.link_mismatches[0].href_domain, "evil.example");
    }

    #[test]
    fn link_mismatch_www_prefixed_text() {
        let e = html_to_text(
            r#"<p><a href="https://evil.example">www.paypal.com</a></p>"#,
        );
        assert_eq!(e.link_mismatches.len(), 1);
        assert_eq!(e.link_mismatches[0].shown_domain, "paypal.com");
    }

    #[test]
    fn link_mismatch_bare_domain_text() {
        let e = html_to_text(
            r#"<p><a href="https://tracker.example/c?id=1">paypal.com/login</a></p>"#,
        );
        assert_eq!(e.link_mismatches.len(), 1);
        assert_eq!(e.link_mismatches[0].shown_domain, "paypal.com");
    }

    #[test]
    fn link_mismatch_non_url_text_no_flag() {
        let e = html_to_text(
            r#"<p><a href="https://evil.example">請求書はこちら</a></p>"#,
        );
        assert!(e.link_mismatches.is_empty());
    }

    #[test]
    fn link_mismatch_inside_hidden_anchor_not_reported() {
        // display:none のアンカーはユーザーに見えないので判定しない
        let e = html_to_text(
            r#"<p><a style="display:none" href="https://evil.example">https://paypal.com</a></p>"#,
        );
        assert!(e.link_mismatches.is_empty());
    }

    #[test]
    fn link_mismatch_hidden_span_inside_anchor_ignored() {
        // アンカー内の非表示塩は表示テキストから除外される
        let e = html_to_text(
            r#"<p><a href="https://paypal.com">pay<span style="display:none">QXJZ</span>pal.com</a></p>"#,
        );
        assert!(e.link_mismatches.is_empty());
    }

    #[test]
    fn link_mismatch_two_level_tld() {
        // co.jp 系: 登録ドメイン比較は末尾 3 ラベル
        let e = html_to_text(
            r#"<p><a href="https://evil.example">https://bank.co.jp/login</a></p>"#,
        );
        assert_eq!(e.link_mismatches.len(), 1);
        assert_eq!(e.link_mismatches[0].shown_domain, "bank.co.jp");
        // 同一登録ドメインの深いサブドメインは誤検出しない
        let e2 = html_to_text(
            r#"<p><a href="https://www.bank.co.jp/x">bank.co.jp</a></p>"#,
        );
        assert!(e2.link_mismatches.is_empty());
    }

    #[test]
    fn link_mismatch_ip_literal_href_flagged() {
        // 表示はドメイン形、実リンクは IP — 典型的な偽装
        let e = html_to_text(
            r#"<p><a href="http://203.0.113.9/x">https://paypal.com</a></p>"#,
        );
        assert_eq!(e.link_mismatches.len(), 1);
        assert_eq!(e.link_mismatches[0].href_domain, "203.0.113.9");
    }

    #[test]
    fn link_mismatch_non_http_href_skipped() {
        // mailto: 等は比較対象外 (URL 偽装の形でない)
        let e = html_to_text(
            r#"<p><a href="mailto:pay@paypal.com">https://paypal.com</a></p>"#,
        );
        assert!(e.link_mismatches.is_empty());
    }

    #[test]
    fn link_mismatch_unclosed_anchor_evaluated_at_eof() {
        let e = html_to_text(
            r#"<p><a href="https://evil.example">https://paypal.com"#,
        );
        assert_eq!(e.link_mismatches.len(), 1);
    }

    #[test]
    fn link_mismatch_cyrillic_domain_text() {
        // 表示テキストの Cyrillic 埋め込みドメインも不一致として捕捉
        // ("payраl.com" の 'а' は Cyrillic — raw 比較で href と不一致)
        let e = html_to_text(
            "<p><a href=\"https://evil.example\">pay\u{0440}al.com</a></p>",
        );
        assert_eq!(e.link_mismatches.len(), 1);
    }

    #[test]
    fn link_mismatch_shown_text_truncated() {
        // 長いアンカーテキストは 80 字で打切り (ログ・表示の安全性)
        let long_text = "x".repeat(200);
        let html = format!(
            "<p><a href=\"https://evil.example\">https://paypal.com/{}</a></p>",
            long_text
        );
        let e = html_to_text(&html);
        assert_eq!(e.link_mismatches.len(), 1);
        assert!(e.link_mismatches[0].shown_text.chars().count() <= 80);
    }

    // ---- D166: 添付の実行・コンテナ拡張子と RTLO ファイル名 ----

    #[test]
    fn scan_attachment_exe_is_dangerous() {
        // 回帰: .exe が危険拡張子リストに無くフラグされなかった
        let scan = scan_attachment_bytes(
            "update.exe",
            "application/octet-stream",
            b"MZ\x90\x00binary",
        );
        assert!(scan.is_dangerous);
        assert!(scan.risks.iter().any(|r| r.contains("拡張子")));
    }

    #[test]
    fn scan_attachment_iso_container_is_dangerous() {
        // MOTW bypass 配送経路: ISO 内のファイルは MOTW を継承しない
        let scan = scan_attachment_bytes(
            "files.iso",
            "application/octet-stream",
            b"\x00\x00iso container",
        );
        assert!(scan.is_dangerous);
    }

    #[test]
    fn scan_attachment_double_extension_is_dangerous() {
        let scan = scan_attachment_bytes(
            "請求書.pdf.exe",
            "application/octet-stream",
            b"MZ\x90\x00binary",
        );
        assert!(scan.is_dangerous);
        assert!(scan.risks.iter().any(|r| r.contains("拡張子")));
    }

    #[test]
    fn scan_attachment_rtlo_filename_is_dangerous() {
        // U+202E: 表示反転で .exe が .jpg に見える偽装
        let scan = scan_attachment_bytes(
            "invoice\u{202E}gpj.exe",
            "application/octet-stream",
            b"MZ\x90\x00binary",
        );
        assert!(scan.is_dangerous);
        assert!(scan
            .risks
            .iter()
            .any(|r| r.contains("RTLO") || r.contains("双方向")));
    }

    #[test]
    fn scan_attachment_safe_pdf_not_dangerous() {
        let scan = scan_attachment_bytes("report.pdf", "application/pdf", b"%PDF-1.5 data");
        assert!(!scan.is_dangerous);
    }

    // ---------- D173: URL スキーム難読化 ----------

    #[test]
    fn obfuscated_url_hxxp_detected() {
        let found = find_obfuscated_url_tokens("詳細は hxxp://phish.example/login へ");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, ObfuscatedUrlKind::DefangedScheme);
        assert_eq!(
            found[0].normalized.as_deref(),
            Some("http://phish.example/login")
        );
    }

    #[test]
    fn obfuscated_url_hxxps_detected() {
        let found = find_obfuscated_url_tokens("hxxps://evil.example/a");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, ObfuscatedUrlKind::DefangedScheme);
        assert_eq!(
            found[0].normalized.as_deref(),
            Some("https://evil.example/a")
        );
    }

    #[test]
    fn obfuscated_url_backslash_detected() {
        let found = find_obfuscated_url_tokens("https:\\\\evil.example\\path");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, ObfuscatedUrlKind::BackslashSeparator);
        assert_eq!(
            found[0].normalized.as_deref(),
            Some("https://evil.example/path")
        );
    }

    #[test]
    fn obfuscated_url_single_backslash_detected() {
        let found = find_obfuscated_url_tokens("http:\\evil.example");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, ObfuscatedUrlKind::BackslashSeparator);
        assert_eq!(found[0].normalized.as_deref(), Some("http://evil.example"));
    }

    #[test]
    fn obfuscated_url_cyrillic_scheme_detected() {
        // httр:// — р は Cyrillic U+0440。見た目は http と同一。
        let found = find_obfuscated_url_tokens("htt\u{440}://evil.example");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, ObfuscatedUrlKind::LookalikeScheme);
        assert!(found[0].normalized.is_none());
    }

    #[test]
    fn obfuscated_url_plain_https_not_flagged() {
        assert!(find_obfuscated_url_tokens("https://example.com").is_empty());
        assert!(find_obfuscated_url_tokens("http://example.com").is_empty());
        assert!(find_obfuscated_url_tokens("特にURLはありません").is_empty());
        assert!(find_obfuscated_url_tokens("ht").is_empty());
    }

    #[test]
    fn obfuscated_url_in_html_context_detected() {
        let found = find_obfuscated_url_tokens(
            "<a href=\"hxxp://x.example\">link</a> 詳しくは http:\\\\y.example",
        );
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn obfuscated_url_slash_backslash_detected() {
        let found = find_obfuscated_url_tokens("http:/\\evil.example");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, ObfuscatedUrlKind::BackslashSeparator);
        assert_eq!(found[0].normalized.as_deref(), Some("http://evil.example"));
    }

    #[test]
    fn obfuscated_url_in_angle_brackets_detected() {
        // <URL> 形式でもトークン分割が働き検出できる
        let found = find_obfuscated_url_tokens("解除は <hxxps://unsub.example/x> から");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, ObfuscatedUrlKind::DefangedScheme);
    }

    // ---------- D174: List-Unsubscribe ヘッダー ----------

    #[test]
    fn parse_extracts_list_unsubscribe() {
        let raw = b"From: a@example.com\r\n\
                    List-Unsubscribe: <https://unsub.example.com/u?id=1>, <mailto:u@example.com>\r\n\
                    Subject: x\r\n\
                    \r\n\
                    body";
        let env = parse(raw).expect("parse");
        assert_eq!(
            env.list_unsubscribe.as_deref(),
            Some("<https://unsub.example.com/u?id=1>, <mailto:u@example.com>")
        );
    }

    #[test]
    fn parse_no_list_unsubscribe_is_none() {
        let raw = b"From: a@example.com\r\nSubject: x\r\n\r\nbody";
        let env = parse(raw).expect("parse");
        assert!(env.list_unsubscribe.is_none());
    }

    #[test]
    fn scan_は未完了multipart_signed構造を検出する() {
        let bad = b"Content-Type: multipart/signed; boundary=\"b\"\r\n\r\nbody";
        assert!(has_incomplete_signed_structure(bad));
        let good = b"Content-Type: multipart/signed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nx\r\n--b\r\nContent-Type: application/pgp-signature\r\n\r\nsig\r\n--b--";
        assert!(!has_incomplete_signed_structure(good));
        let good2 = b"Content-Type: multipart/signed\r\n\r\nx\r\nContent-Type: application/pkcs7-signature\r\n\r\ns";
        assert!(!has_incomplete_signed_structure(good2));
        let other = b"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\nx";
        assert!(!has_incomplete_signed_structure(other));
        assert!(!has_incomplete_signed_structure(b""));
    }
}

/// カレンダー招待 (ICS) のセキュリティ検査。
pub mod calendar_guard;
pub mod css_sanitizer;
/// HTML スマグリング検出 (Blob/data: URI 経由のペイロード組み立て)。
pub mod html_smuggling;
/// ZIP Slip 攻撃防止 (Zenn Round5 P0)。
/// ファイルマジックバイト検証 — 拡張子偽装検出 (Qiita/Zenn Round5 P2)。
pub mod magic_bytes;
/// 添付ファイルメタデータ漏洩検出 (Round7 P1)。
pub mod metadata_check;
/// SVG 添付攻撃の検出 (2025-2026 に急増した主要ベクタ)。
pub mod svg_guard;

// ============================================================================
// 添付ファイル検査
// ============================================================================

/// 添付ファイル 1 件の検査結果。
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttachmentScan {
    /// ファイル名 (Content-Disposition 由来)。
    pub filename: String,
    /// 宣言された MIME タイプ (詐称されうる)。
    pub declared_mime: String,
    /// サイズ (bytes)。
    pub size_bytes: u64,
    /// 検出されたリスク (人間可読)。
    pub risks: Vec<String>,
    /// 実行リスクがあるか。
    ///
    /// 危険拡張子 / MIME 偽装 / polyglot / SVG のスクリプト実行のいずれか。
    /// **メタデータ検出のみの場合は false** — 作成者情報や GPS はプライバシー
    /// 上の通知であって、開いた瞬間にコードが走るわけではないため。
    pub is_dangerous: bool,
}

/// メール全体から添付を取り出し、実装済みの各検出器にかける。
///
/// # なぜこの関数が必要か
///
/// `kaname-render` には添付検査が揃っている
/// (`magic_bytes::check_mime_mismatch` / `detect_polyglot` /
/// `is_dangerous_windows_attachment`、`metadata_check::detect_metadata_risks`、
/// `svg_guard::scan_svg`)。しかし `parse()` が構築する `AttachmentHeader` は
/// **バイト列を保持しておらず** (`part.contents().len()` でサイズだけ取って
/// 中身を捨てている)、これらの検出器に渡す経路が存在しなかった。
/// 結果として添付検査は一つも動いていなかった。
///
/// `AttachmentHeader` にバイト列を足す設計は採らない。全添付をメモリに
/// 常駐させることになり大きな添付で不利なため、**バイトはこのクレート内で
/// 完結させ**、検査結果だけを返す。
///
/// 生 RFC5322 メールから MLS エンベロープパート
/// (`Content-Type: application/mls-envelope+cbor`) の復号済みボディを
/// すべて取り出す (D1 Phase 4 — 受信経路)。
///
/// `Content-Disposition: attachment` に限らず全 MIME パートを走査する —
/// 相手クライアントがインラインで挿入する可能性があるため。
/// `mail-parser` は `msg.parts` に全パートをフラットに持ち、入れ子の
/// message/rfc822 は `PartType::Message` として現れるため再帰で潜る。
/// transfer-encoding は復号済みの `contents()` を返す。
#[must_use]
pub fn extract_mls_envelopes(raw: &[u8]) -> Vec<Vec<u8>> {
    extract_parts_by_media_type(raw, "application", "mls-envelope+cbor")
}

/// MLS KeyPackage 添付の Content-Type (D1 Phase 3)。
/// 自分の KeyPackage を相手に手渡しする際の MIME タイプ —
/// エンベロープ (`application/mls-envelope+cbor`) は CBOR だが、
/// KeyPackage は TLS シリアライズ済みのためサフィックスを付けない。
pub const MLS_KEY_PACKAGE_MIME: &str = "application/mls-key-package";

/// `application/mls-key-package` パートの内容を取り出す。
///
/// 相手の KeyPackage が添付で届いた際 (Phase 3 配送経路)、
/// `kp_cache` 投入のために抽出する。転送符号化はデコード済み。
#[must_use]
pub fn extract_mls_key_packages(raw: &[u8]) -> Vec<Vec<u8>> {
    extract_parts_by_media_type(raw, "application", "mls-key-package")
}

/// 指定 Content-Type のパート内容を multipart を再帰走査して取り出す
/// (入れ子 `message/rfc822` を含む)。`Content-Disposition` を問わず
/// 全パートを検査するため、インライン挿入にも対応する。
fn extract_parts_by_media_type(raw: &[u8], ctype: &str, subtype: &str) -> Vec<Vec<u8>> {
    let Some(msg) = MessageParser::default().parse(raw) else {
        return Vec::new();
    };
    // 1 通のメールに収集する同種パート数の上限 (D126)。
    // 各エンベロープは MLS の into_group / 復号という実暗号処理を呼び、
    // 各 KeyPackage は TLS デシリアライズ + 署名検証を呼ぶため、
    // 無制限だと 1 通のメールで大量の暗号演算を強制できる (CPU DoS)。
    // 正規のメールで同種 MLS パートが 32 を超えることはない。
    const MAX_MATCHING_PARTS: usize = 32;
    // message/rfc822 の入れ子深度の上限 — パーサ自体の制限に依存せず
    // 自前で再帰深度を止めておかないと、極端に深い入れ子メールで
    // スタックを使い切り得る (D130)。正規の転送入れ子は数段まで。
    const MAX_NESTED_DEPTH: usize = 16;
    fn collect(
        part: &mail_parser::MessagePart<'_>,
        ctype: &str,
        subtype: &str,
        out: &mut Vec<Vec<u8>>,
        depth: usize,
    ) {
        if out.len() >= MAX_MATCHING_PARTS || depth > MAX_NESTED_DEPTH {
            return;
        }
        let matched = part
            .content_type()
            .map(|ct| {
                ct.ctype().eq_ignore_ascii_case(ctype)
                    && ct
                        .subtype()
                        .is_some_and(|s| s.eq_ignore_ascii_case(subtype))
            })
            .unwrap_or(false);
        if matched {
            out.push(part.contents().to_vec());
        }
        if let mail_parser::PartType::Message(sub) = &part.body {
            for p in &sub.parts {
                collect(p, ctype, subtype, out, depth + 1);
            }
        }
    }
    let mut out = Vec::new();
    for part in &msg.parts {
        collect(part, ctype, subtype, &mut out, 0);
    }
    out
}

/// # DoS 対策
///
/// 1 添付あたり検査するのは先頭 10 MB まで。それを超える部分は読まない。
#[must_use]
pub fn scan_attachments(raw: &[u8]) -> Vec<AttachmentScan> {
    let Some(msg) = MessageParser::default().parse(raw) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for part in msg.attachments() {
        let filename = part.attachment_name().unwrap_or("unnamed").to_string();
        let declared_mime = part
            .content_type()
            .map(|ct| {
                let main = ct.ctype();
                match ct.subtype() {
                    Some(sub) => format!("{main}/{sub}"),
                    None => main.to_string(),
                }
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());

        out.push(scan_attachment_bytes(
            &filename,
            &declared_mime,
            part.contents(),
        ));
    }
    out
}

/// メール全体が MLS エンベロープ (`application/mls-envelope+cbor`) を
/// 含むかを判定する。ルートパートを含む全 MIME パートを検査するため、
/// 添付扱いされない本文直下のエンベロープも検出できる。
/// `kaname-jmap::BodyPart::is_mls_envelope` と同じ判定基準。
#[must_use]
pub fn is_mls_message(raw: &[u8]) -> bool {
    const MLS_MIME: &str = "application/mls-envelope+cbor";
    let Some(msg) = MessageParser::default().parse(raw) else {
        return false;
    };
    msg.parts.iter().any(|part| {
        part.content_type().is_some_and(|ct| {
            format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or_default())
                .eq_ignore_ascii_case(MLS_MIME)
        })
    })
}

/// 1 添付分のバイト列を各検出器にかける。
///
/// `scan_attachments` (メール全体) と、JMAP でダウンロードした単一 blob の
/// 両方から使える共通ロジック。検査は先頭 10 MB まで (DoS 対策)。
#[must_use]
pub fn scan_attachment_bytes(filename: &str, declared_mime: &str, full: &[u8]) -> AttachmentScan {
    const MAX_SCAN_BYTES: usize = 10 * 1024 * 1024;
    let size_bytes = full.len() as u64;
    let bytes = &full[..full.len().min(MAX_SCAN_BYTES)];

    let mut risks = Vec::new();
    let mut is_dangerous = false;

    // 1. Windows で危険な拡張子 (.lnk / .docm / .scr / .exe 等) と
    //    双方向制御文字 (RTLO) を使った拡張子表示反転 (D166)
    if magic_bytes::is_dangerous_windows_attachment(filename) {
        risks.push(format!("危険な拡張子です: {filename}"));
        is_dangerous = true;
    }
    if magic_bytes::has_bidi_override_filename(filename) {
        risks.push(
            "ファイル名に双方向テキスト制御文字 (RTLO 等) が含まれており、拡張子の表示が反転して実際の形式を隠している可能性があります"
                .to_string(),
        );
        is_dangerous = true;
    }

    // 2. 宣言 MIME と実体の不一致 (実行ファイルを画像等に偽装)
    if let Some(mismatch) = magic_bytes::check_mime_mismatch(declared_mime, bytes) {
        risks.push(format!(
            "MIME 偽装の疑い: {} と宣言されていますが実体は {} です",
            mismatch.declared, mismatch.detected
        ));
        is_dangerous = true;
    }

    // 3. Polyglot (画像/PDF としても ZIP としても有効)
    if let Some((a, b)) = magic_bytes::detect_polyglot(bytes) {
        risks.push(format!(
            "Polyglot ファイルです ({a} と {b} の両方として有効)"
        ));
        is_dangerous = true;
    }

    // 4. SVG のスクリプト実行 / XXE / プロンプト注入
    if let Ok(text) = std::str::from_utf8(bytes) {
        if svg_guard::looks_like_svg(text) {
            let scan = svg_guard::scan_svg(text);
            if !scan.safe_as_attachment {
                for r in &scan.risks {
                    risks.push(format!("SVG のリスク: {r:?}"));
                }
                is_dangerous = true;
            }
        }
    }

    // 5. カレンダー招待 (.ics) の検査 (CalPhishing)
    if let Ok(text) = std::str::from_utf8(bytes) {
        let is_ics = filename.to_ascii_lowercase().ends_with(".ics")
            || declared_mime.to_ascii_lowercase().contains("text/calendar")
            || text.contains("BEGIN:VCALENDAR");
        if is_ics {
            let scan = calendar_guard::CalendarGuard.analyze(text);
            if !matches!(scan.risk_level, calendar_guard::CalendarRiskLevel::Safe) {
                for r in &scan.risks {
                    risks.push(format!("カレンダー招待のリスク: {r:?}"));
                }
                // Danger のみ実行リスク扱い。Caution は注意喚起に留める。
                if matches!(scan.risk_level, calendar_guard::CalendarRiskLevel::Danger) {
                    is_dangerous = true;
                }
            }
        }
    }

    // 6. メタデータ (作成者/GPS 等)。プライバシー通知であり実行リスクではない。
    for r in metadata_check::detect_metadata_risks(filename, bytes) {
        risks.push(format!("メタデータが含まれます: {r:?}"));
    }

    AttachmentScan {
        filename: filename.to_string(),
        declared_mime: declared_mime.to_string(),
        size_bytes,
        risks,
        is_dangerous,
    }
}
