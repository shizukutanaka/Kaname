//! DKIM 署名の暗号的検証 (独立検証)。
//!
//! # 背景
//!
//! 従来の Kaname は SPF/DKIM/DMARC の判定を接続先サーバが付けた
//! `Authentication-Results` ヘッダの申告に依存していた (README および
//! `docs/threat-model.md` §3.15b / D18)。接続先サーバや中継経路が
//! 攻撃者に制御・偽装された場合、認証系シグナルは無条件に偽装されうる。
//!
//! 本モジュールは DKIM 署名を**受信側自身で**検証する:
//! 署名ドメインの DNS (`<selector>._domainkey.<domain>`) から公開鍵を
//! 取得し、正規化済みヘッダ列に対する RSA / Ed25519 署名と
//! 本文ハッシュ (`bh=`) を照合する (RFC 6376 / RFC 8463)。
//!
//! # 判定への組み込み方針
//!
//! - 暗号的に**無効**と確定した場合のみ `Fail` を返す
//!   (署名不一致・本文ハッシュ不一致・鍵失効・期限切れ等)。
//! - DNS 取得不能・未対応方式など**検証できない**場合は `Neutral` とし、
//!   既存のヘッダ申告ベースの判定を壊さない。
//! - DNS 参照は [`DkimKeyResolver`] トレイトで抽象化し、テストでは
//!   ネットワークなしに差し替えられる。本番用に標準ライブラリのみで
//!   実装した [`UdpDkimKeyResolver`] (UDP + EDNS0) を同梱する。
//!
//! # 対応範囲
//!
//! - 署名方式: `rsa-sha256`, `ed25519-sha256`
//!   (`rsa-sha1` は SHA-1 のため未対応として `Neutral` を返す)
//! - 正規化: ヘッダ・本文とも `simple` / `relaxed`
//! - RSA 公開鍵: PKCS#1 形式と SubjectPublicKeyInfo 形式の両方を受理

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

/// 検証する DKIM 署名の最大数 (DoS 防止)。
const MAX_SIGNATURES: usize = 5;

// ============================================================================
// DNS 抽象
// ============================================================================

/// DNS 参照の失敗種別。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DkimResolveError {
    /// レコードが存在しない (NXDOMAIN、または NOERROR だが TXT が無い)。
    #[error("DKIM 公開鍵レコードが存在しません")]
    NotFound,
    /// 一時的失敗 (タイムアウト / SERVFAIL / ネットワーク不達)。
    #[error("DNS 参照に一時的に失敗しました: {0}")]
    Temporary(String),
}

/// DKIM 公開鍵レコードの参照抽象。
///
/// テストではモックに差し替え、本番では [`UdpDkimKeyResolver`] を使う。
pub trait DkimKeyResolver: Send + Sync {
    /// `name` (例: `sel1._domainkey.example.com`) の TXT レコードを返す。
    ///
    /// 1 要素 = 1 TXT レコード。レコード内の複数の character-string は
    /// 連結済みの文字列として返すこと。
    fn lookup_txt(&self, name: &str) -> Result<Vec<String>, DkimResolveError>;
}

// ============================================================================
// 検証結果
// ============================================================================

/// DKIM 署名 1 件の暗号的検証の結末。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimVerificationStatus {
    /// 署名と本文ハッシュが DNS 公開鍵で検証できた。
    Pass,
    /// 暗号的に無効と確定した (改竄・失効・期限切れ等)。
    Fail,
    /// 検証できなかった (DNS 取得不能・未対応方式等)。判定は中立。
    Neutral,
}

/// DKIM 署名 1 件の検証結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimVerification {
    /// 結末。
    pub status: DkimVerificationStatus,
    /// 署名ドメイン (`d=`)。解析不能な場合は `None`。
    pub domain: Option<String>,
    /// セレクタ (`s=`)。解析不能な場合は `None`。
    pub selector: Option<String>,
    /// 人間可読な理由・要約 (UI 表示・監査用)。
    pub detail: String,
}

impl DkimVerification {
    fn with_status(
        status: DkimVerificationStatus,
        domain: Option<String>,
        selector: Option<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            status,
            domain,
            selector,
            detail: detail.into(),
        }
    }
}

// ============================================================================
// 検証エントリポイント
// ============================================================================

/// メッセージ全体 (RFC 5322 バイト列) に含まれる全 DKIM 署名を検証する。
///
/// `DKIM-Signature` ヘッダが無い場合は空のベクタを返す。署名が複数ある
/// 場合は出現順に最大 [`MAX_SIGNATURES`] 件まで検証する。
#[must_use]
pub fn verify_message(resolver: &dyn DkimKeyResolver, raw_message: &[u8]) -> Vec<DkimVerification> {
    let (head, body) = split_message(raw_message);
    let headers = parse_headers(head);
    let mut results = Vec::new();
    for (idx, header) in headers.iter().enumerate() {
        if header.name_lower == "dkim-signature" {
            results.push(verify_one(resolver, &headers, idx, body));
            if results.len() >= MAX_SIGNATURES {
                break;
            }
        }
    }
    results
}

/// 生メッセージをヘッダブロックと本文に分ける。
fn split_message(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        (&raw[..pos], &raw[pos + 4..])
    } else if let Some(pos) = find_subslice(raw, b"\n\n") {
        (&raw[..pos], &raw[pos + 2..])
    } else {
        (raw, &[])
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ============================================================================
// ヘッダ解析
// ============================================================================

/// 順序と折り返しを保持した生ヘッダ 1 件。
struct RawHeader {
    /// 小文字化したヘッダ名。
    name_lower: String,
    /// ヘッダ全体 (名前 + ':' + 値、折り返しの CRLF を含み、末尾 CRLF は含まない)。
    raw: Vec<u8>,
}

fn parse_headers(block: &[u8]) -> Vec<RawHeader> {
    let mut headers: Vec<RawHeader> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let flush = |cur: &mut Vec<u8>, headers: &mut Vec<RawHeader>| {
        if cur.is_empty() {
            return;
        }
        let name = cur
            .split(|&b| b == b':')
            .next()
            .map(|n| {
                String::from_utf8_lossy(n)
                    .trim()
                    .to_ascii_lowercase()
                    .to_string()
            })
            .unwrap_or_default();
        headers.push(RawHeader {
            name_lower: name,
            raw: std::mem::take(cur),
        });
    };
    for line in block.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if (line[0] == b' ' || line[0] == b'\t') && !cur.is_empty() {
            // 折り返し行: 直前のヘッダに CRLF 付きで連結する
            cur.extend_from_slice(b"\r\n");
            cur.extend_from_slice(line);
        } else {
            flush(&mut cur, &mut headers);
            cur = line.to_vec();
        }
    }
    flush(&mut cur, &mut headers);
    headers
}

/// タグ解析用にヘッダ値を取り出す (折り返しの CRLF を除いた文字列)。
fn header_value(raw: &[u8]) -> String {
    let Some(colon) = raw.iter().position(|&b| b == b':') else {
        return String::new();
    };
    let value: Vec<u8> = raw[colon + 1..]
        .iter()
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect();
    String::from_utf8_lossy(&value).into_owned()
}

/// `k=v; k=v; ...` 形式のタグリストをパースする (名前は小文字化)。
fn parse_tag_list(value: &str) -> Vec<(String, String)> {
    value
        .split(';')
        .filter_map(|part| {
            let (k, v) = part.split_once('=')?;
            Some((k.trim().to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect()
}

fn tag<'a>(tags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// DKIM の base64 値をデコードする (空白除去、不足パディングは補完)。
fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return Some(Vec::new());
    }
    let mut padded = cleaned;
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    BASE64.decode(padded.as_bytes()).ok()
}

// ============================================================================
// 署名ヘッダの解析
// ============================================================================

/// 正規化方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Canon {
    Simple,
    Relaxed,
}

fn parse_canon(value: Option<&str>) -> Result<(Canon, Canon), String> {
    let raw = value.unwrap_or("simple/simple").to_ascii_lowercase();
    let mut parts = raw.split('/');
    let header = match parts.next() {
        Some("simple") => Canon::Simple,
        Some("relaxed") => Canon::Relaxed,
        _ => return Err(format!("c= のヘッダ正規化方式が不明です: {raw}")),
    };
    let body = match parts.next() {
        Some("simple") | None => Canon::Simple,
        Some("relaxed") => Canon::Relaxed,
        _ => return Err(format!("c= の本文正規化方式が不明です: {raw}")),
    };
    Ok((header, body))
}

/// パース済みの DKIM-Signature。
struct ParsedSignature {
    /// 鍵種別 ("rsa" / "ed25519")。
    key_type: String,
    domain: String,
    selector: String,
    /// `i=` の完全な値 (無ければ `@<d=>` と同じ扱い)。
    identity: String,
    /// `i=` のドメイン部 (無ければ `d=` と同じ扱い)。
    identity_domain: String,
    header_canon: Canon,
    body_canon: Canon,
    /// `h=` の署名対象ヘッダ名 (小文字、順序保持)。
    signed_headers: Vec<String>,
    /// `bh=` をデコードした本文ハッシュ。
    body_hash: Vec<u8>,
    /// `b=` をデコードした署名値。
    signature: Vec<u8>,
    /// `l=` (本文長制限)。
    body_length: Option<u64>,
    /// `t=` (署名時刻)。
    timestamp: Option<u64>,
    /// `x=` (失効時刻)。
    expiration: Option<u64>,
}

enum SigParse {
    Ok(Box<ParsedSignature>),
    Fail(String),
    Neutral(String),
}

fn parse_signature(value: &str) -> SigParse {
    let tags = parse_tag_list(value);
    if let Some(v) = tag(&tags, "v") {
        if v != "1" {
            return SigParse::Fail(format!("v= が 1 ではありません: {v}"));
        }
    }
    let Some(a) = tag(&tags, "a") else {
        return SigParse::Fail("a= タグがありません".to_string());
    };
    let a_lower = a.to_ascii_lowercase();
    let Some((key_type, hash_name)) = a_lower.split_once('-') else {
        return SigParse::Fail(format!("a= の形式が不正です: {a}"));
    };
    match (key_type, hash_name) {
        ("rsa", "sha256") | ("ed25519", "sha256") => {}
        ("rsa", "sha1") => {
            return SigParse::Neutral("rsa-sha1 は SHA-1 のため未対応です".to_string());
        }
        _ => {
            return SigParse::Neutral(format!("署名方式 {a_lower} は未対応です"));
        }
    }
    if let Some(q) = tag(&tags, "q") {
        if !q.eq_ignore_ascii_case("dns/txt") {
            return SigParse::Neutral(format!("q= が dns/txt ではありません: {q}"));
        }
    }
    let Some(domain) = tag(&tags, "d") else {
        return SigParse::Fail("d= タグがありません".to_string());
    };
    let Some(selector) = tag(&tags, "s") else {
        return SigParse::Fail("s= タグがありません".to_string());
    };
    let Some(h) = tag(&tags, "h") else {
        return SigParse::Fail("h= タグがありません".to_string());
    };
    let signed_headers: Vec<String> = h
        .split(':')
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    let Some(bh_raw) = tag(&tags, "bh") else {
        return SigParse::Fail("bh= タグがありません".to_string());
    };
    let Some(body_hash) = decode_base64(bh_raw) else {
        return SigParse::Fail("bh= の base64 が不正です".to_string());
    };
    if body_hash.len() != 32 {
        return SigParse::Fail("bh= の長さが SHA-256 ではありません".to_string());
    }
    let Some(b_raw) = tag(&tags, "b") else {
        return SigParse::Fail("b= タグがありません".to_string());
    };
    let Some(signature) = decode_base64(b_raw) else {
        return SigParse::Fail("b= の base64 が不正です".to_string());
    };
    if signature.is_empty() {
        return SigParse::Fail("b= が空です".to_string());
    }
    let (header_canon, body_canon) = match parse_canon(tag(&tags, "c")) {
        Ok(pair) => pair,
        Err(e) => return SigParse::Fail(e),
    };
    let parse_u64 = |name: &str| -> Result<Option<u64>, String> {
        match tag(&tags, name) {
            None => Ok(None),
            Some(v) => v
                .parse::<u64>()
                .map(Some)
                .map_err(|_| format!("{name}= の値が数値ではありません: {v}")),
        }
    };
    let body_length = match parse_u64("l") {
        Ok(v) => v,
        Err(e) => return SigParse::Fail(e),
    };
    let timestamp = match parse_u64("t") {
        Ok(v) => v,
        Err(e) => return SigParse::Fail(e),
    };
    let expiration = match parse_u64("x") {
        Ok(v) => v,
        Err(e) => return SigParse::Fail(e),
    };
    // i= のドメイン部 (RFC 6376 §3.5: i= は [local "@"] domain の形)
    let identity = tag(&tags, "i")
        .map(str::to_string)
        .unwrap_or_else(|| format!("@{domain}"));
    let identity_domain = identity
        .rsplit('@')
        .next()
        .map(str::to_string)
        .unwrap_or_else(|| identity.clone());
    SigParse::Ok(Box::new(ParsedSignature {
        key_type: key_type.to_string(),
        domain: domain.to_string(),
        selector: selector.to_string(),
        identity,
        identity_domain,
        header_canon,
        body_canon,
        signed_headers,
        body_hash,
        signature,
        body_length,
        timestamp,
        expiration,
    }))
}

// ============================================================================
// 正規化 (RFC 6376 §3.4)
// ============================================================================

/// 本文を行に分解する (行末の CRLF / LF は除き、末尾の改行は行を生まない)。
fn body_lines(body: &[u8]) -> Vec<&[u8]> {
    let mut lines: Vec<&[u8]> = body
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .collect();
    if body.ends_with(b"\n") || body.is_empty() {
        lines.pop();
    }
    lines
}

/// 連続する WSP を 1 つの SP に畳み、末尾の WSP を落とす (relaxed 用)。
fn reduce_wsp(line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.len());
    let mut in_wsp = false;
    for &b in line {
        if b == b' ' || b == b'\t' {
            if !in_wsp {
                out.push(b' ');
            }
            in_wsp = true;
        } else {
            out.push(b);
            in_wsp = false;
        }
    }
    if out.last() == Some(&b' ') {
        out.pop();
    }
    out
}

/// 本文の正規化。末尾の空行は両方式とも無視され、
/// 空でない本文には末尾 CRLF を 1 つ付ける。
fn canonicalize_body(body: &[u8], mode: Canon) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = body_lines(body)
        .iter()
        .map(|l| match mode {
            Canon::Simple => l.to_vec(),
            Canon::Relaxed => reduce_wsp(l),
        })
        .collect();
    while matches!(lines.last(), Some(l) if l.is_empty()) {
        lines.pop();
    }
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(line);
    }
    if !lines.is_empty() {
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// ヘッダの正規化。
fn canonicalize_header(raw: &[u8], mode: Canon) -> Vec<u8> {
    match mode {
        Canon::Simple => raw.to_vec(),
        Canon::Relaxed => {
            let colon = raw.iter().position(|&b| b == b':').unwrap_or(raw.len());
            let name_raw = &raw[..colon];
            let name_start = name_raw
                .iter()
                .position(|&b| b != b' ' && b != b'\t')
                .unwrap_or(name_raw.len());
            let name_end = name_raw
                .iter()
                .rposition(|&b| b != b' ' && b != b'\t')
                .map_or(name_start, |p| p + 1);
            let mut out: Vec<u8> = name_raw[name_start..name_end]
                .iter()
                .map(|b| b.to_ascii_lowercase())
                .collect();
            out.push(b':');
            let value = if colon < raw.len() {
                &raw[colon + 1..]
            } else {
                &[]
            };
            let mut v: Vec<u8> = Vec::with_capacity(value.len());
            let mut in_wsp = false;
            for &b in value {
                if b == b'\r' || b == b'\n' {
                    continue;
                }
                if b == b' ' || b == b'\t' {
                    if !in_wsp {
                        v.push(b' ');
                    }
                    in_wsp = true;
                } else {
                    v.push(b);
                    in_wsp = false;
                }
            }
            let v_start = usize::from(v.first() == Some(&b' '));
            let v_end = if v.len() > v_start && v.last() == Some(&b' ') {
                v.len() - 1
            } else {
                v.len()
            };
            out.extend_from_slice(&v[v_start..v_end]);
            out
        }
    }
}

/// DKIM-Signature ヘッダの `b=` タグの値だけを空にした生バイト列を返す。
///
/// 署名計算時の入力は「`b=` の値が空の DKIM-Signature ヘッダ」であるため、
/// 検証時も同じ形に復元する。タグ区切り ';' は base64 の文字集合に
/// 含まれないため、バイト走査で安全に区切れる。
fn empty_b_tag_value(raw: &[u8]) -> Vec<u8> {
    let Some(colon) = raw.iter().position(|&b| b == b':') else {
        return raw.to_vec();
    };
    let mut seg_start = colon + 1;
    loop {
        let seg_end = raw[seg_start..]
            .iter()
            .position(|&b| b == b';')
            .map_or(raw.len(), |p| seg_start + p);
        let mut name_beg = seg_start;
        while name_beg < seg_end && matches!(raw[name_beg], b' ' | b'\t' | b'\r' | b'\n') {
            name_beg += 1;
        }
        if name_beg < seg_end && (raw[name_beg] == b'b' || raw[name_beg] == b'B') {
            let mut j = name_beg + 1;
            while j < seg_end && (raw[j] == b' ' || raw[j] == b'\t') {
                j += 1;
            }
            if j < seg_end && raw[j] == b'=' {
                let mut out = Vec::with_capacity(raw.len());
                out.extend_from_slice(&raw[..=j]);
                out.extend_from_slice(&raw[seg_end..]);
                return out;
            }
        }
        if seg_end >= raw.len() {
            break;
        }
        seg_start = seg_end + 1;
    }
    raw.to_vec()
}

/// 署名対象ヘッダ列のハッシュ入力を組み立てる (RFC 6376 §5.4)。
///
/// `h=` の順序どおり、各ヘッダ名について「未使用の中で最も下にある
/// (最後の) インスタンス」を選択する。最後に `b=` を空にした
/// DKIM-Signature 自身を末尾 CRLF なしで付ける。
fn header_hash_input(headers: &[RawHeader], sig_idx: usize, sig: &ParsedSignature) -> Vec<u8> {
    let mut used = vec![false; headers.len()];
    if sig_idx < used.len() {
        used[sig_idx] = true; // 検証対象の署名自身は選択から除外
    }
    let mut data = Vec::new();
    for name in &sig.signed_headers {
        for i in (0..headers.len()).rev() {
            if used[i] || headers[i].name_lower != *name {
                continue;
            }
            used[i] = true;
            data.extend_from_slice(&canonicalize_header(&headers[i].raw, sig.header_canon));
            data.extend_from_slice(b"\r\n");
            break;
        }
    }
    let sig_raw = empty_b_tag_value(&headers[sig_idx].raw);
    data.extend_from_slice(&canonicalize_header(&sig_raw, sig.header_canon));
    data
}

// ============================================================================
// 公開鍵レコードの解析と暗号検証
// ============================================================================

/// 検証に使える鍵素材。
enum KeyMaterial {
    Rsa { n: BigUint, e: BigUint },
    Ed25519 { key: [u8; 32] },
}

enum KeyRecordOutcome {
    /// 検証に使える鍵が得られた。
    Material(KeyMaterial),
    /// 鍵失効 (`p=` が空)。
    Revoked,
    /// このレコードは使えない (形式不正・方式不一致等)。
    Unusable,
}

fn parse_key_record(record: &str, sig: &ParsedSignature) -> KeyRecordOutcome {
    let tags = parse_tag_list(record);
    if let Some(v) = tag(&tags, "v") {
        if !v.starts_with("DKIM1") {
            return KeyRecordOutcome::Unusable;
        }
    }
    let k = tag(&tags, "k")
        .unwrap_or("rsa")
        .to_ascii_lowercase()
        .to_string();
    if k != sig.key_type {
        return KeyRecordOutcome::Unusable;
    }
    // g= (granularity): i= のローカルパートが一致しない鍵は適用外。
    if let Some(g) = tag(&tags, "g") {
        let local_part = sig.identity.split('@').next().unwrap_or("");
        if g != "*" && g != local_part {
            return KeyRecordOutcome::Unusable;
        }
    }
    // t= フラグの "s": i= ドメインが d= と完全一致しなければならない。
    if let Some(t) = tag(&tags, "t") {
        let flags: Vec<&str> = t.split(':').map(str::trim).collect();
        if flags.contains(&"s") && !sig.identity_domain.eq_ignore_ascii_case(&sig.domain) {
            return KeyRecordOutcome::Unusable;
        }
    }
    let Some(p_raw) = tag(&tags, "p") else {
        return KeyRecordOutcome::Unusable;
    };
    let p_clean: String = p_raw.chars().filter(|c| !c.is_whitespace()).collect();
    if p_clean.is_empty() {
        return KeyRecordOutcome::Revoked;
    }
    let Some(p_bytes) = decode_base64(&p_clean) else {
        return KeyRecordOutcome::Unusable;
    };
    match sig.key_type.as_str() {
        "rsa" => match parse_rsa_public_key(&p_bytes) {
            Some((n, e)) => KeyRecordOutcome::Material(KeyMaterial::Rsa { n, e }),
            None => KeyRecordOutcome::Unusable,
        },
        "ed25519" => {
            if p_bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&p_bytes);
                KeyRecordOutcome::Material(KeyMaterial::Ed25519 { key })
            } else {
                KeyRecordOutcome::Unusable
            }
        }
        _ => KeyRecordOutcome::Unusable,
    }
}

// --- 最小 DER リーダ (RSA 公開鍵の解析専用) ---

struct DerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// 期待タグの TLV を読み、内容バイト列を返す。
    fn read_tlv(&mut self, expected_tag: u8) -> Option<&'a [u8]> {
        let tag_byte = *self.buf.get(self.pos)?;
        if tag_byte != expected_tag {
            return None;
        }
        let len_byte = *self.buf.get(self.pos + 1)?;
        let (len, header_len) = if len_byte & 0x80 == 0 {
            (usize::from(len_byte), 2usize)
        } else {
            let n = usize::from(len_byte & 0x7f);
            if n == 0 || n > 4 {
                return None;
            }
            let mut len = 0usize;
            for k in 0..n {
                len = (len << 8) | usize::from(*self.buf.get(self.pos + 2 + k)?);
            }
            (len, 2 + n)
        };
        let start = self.pos.checked_add(header_len)?;
        let end = start.checked_add(len)?;
        if end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(&self.buf[start..end])
    }
}

/// PKCS#1 RSAPublicKey ::= SEQUENCE { modulus INTEGER, exponent INTEGER }
fn parse_rsa_pkcs1(der: &[u8]) -> Option<(BigUint, BigUint)> {
    let mut top = DerReader::new(der);
    let seq = top.read_tlv(0x30)?;
    let mut reader = DerReader::new(seq);
    let n = reader.read_tlv(0x02)?;
    let e = reader.read_tlv(0x02)?;
    Some((BigUint::from_bytes_be(n), BigUint::from_bytes_be(e)))
}

/// rsaEncryption の OID 内容バイト (1.2.840.113549.1.1.1)。
const RSA_ENCRYPTION_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
/// subjectPublicKey BIT STRING (中身は PKCS#1 形式) }
fn parse_rsa_spki(der: &[u8]) -> Option<(BigUint, BigUint)> {
    let mut top = DerReader::new(der);
    let seq = top.read_tlv(0x30)?;
    let mut reader = DerReader::new(seq);
    let alg_seq = reader.read_tlv(0x30)?;
    let mut alg_reader = DerReader::new(alg_seq);
    let oid = alg_reader.read_tlv(0x06)?;
    if oid != RSA_ENCRYPTION_OID {
        return None;
    }
    let bit_string = reader.read_tlv(0x03)?;
    if bit_string.first() != Some(&0) {
        return None; // unused-bits は 0 でなければならない
    }
    parse_rsa_pkcs1(&bit_string[1..])
}

fn parse_rsa_public_key(der: &[u8]) -> Option<(BigUint, BigUint)> {
    parse_rsa_pkcs1(der).or_else(|| parse_rsa_spki(der))
}

/// SHA-256 の DigestInfo 前置部 (RFC 8017 §9.2)。
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// RSA PKCS#1 v1.5 署名検証 (公開演算のみ。秘密情報は扱わない)。
fn rsa_verify(n: &BigUint, e: &BigUint, signature: &[u8], digest: &[u8]) -> bool {
    let k = n.bits().div_ceil(8) as usize;
    let tail_len = SHA256_DIGEST_INFO_PREFIX.len() + digest.len();
    if signature.len() != k || k < tail_len + 11 {
        return false;
    }
    let s = BigUint::from_bytes_be(signature);
    if s >= *n {
        return false;
    }
    let m = s.modpow(e, n);
    let m_bytes = m.to_bytes_be();
    if m_bytes.len() > k {
        return false;
    }
    let mut em = vec![0u8; k - m_bytes.len()];
    em.extend_from_slice(&m_bytes);
    // EM = 0x00 || 0x01 || PS(0xFF x>=8) || 0x00 || DigestInfo || H
    if em[0] != 0x00 || em[1] != 0x01 {
        return false;
    }
    let sep = k - tail_len - 1;
    if em[sep] != 0x00 {
        return false;
    }
    if em[2..sep].iter().any(|&b| b != 0xff) {
        return false;
    }
    if &em[sep + 1..sep + 1 + SHA256_DIGEST_INFO_PREFIX.len()] != SHA256_DIGEST_INFO_PREFIX {
        return false;
    }
    &em[k - digest.len()..] == digest
}

/// Ed25519 署名検証。DKIM では SHA-256 ハッシュ済みの値に署名する
/// (RFC 8463 §3) ため、`digest` (ヘッダハッシュ) をそのまま検証対象にする。
fn ed25519_verify(key: &[u8; 32], signature: &[u8], digest: &[u8]) -> bool {
    use ed25519_dalek::Verifier as _;
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(key) else {
        return false;
    };
    if signature.len() != 64 {
        return false;
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key.verify(digest, &sig).is_ok()
}

// ============================================================================
// 署名 1 件の検証
// ============================================================================

fn verify_one(
    resolver: &dyn DkimKeyResolver,
    headers: &[RawHeader],
    sig_idx: usize,
    body: &[u8],
) -> DkimVerification {
    let neutral = |detail: String| {
        DkimVerification::with_status(DkimVerificationStatus::Neutral, None, None, detail)
    };
    let sig = match parse_signature(&header_value(&headers[sig_idx].raw)) {
        SigParse::Ok(sig) => *sig,
        SigParse::Fail(detail) => {
            return DkimVerification::with_status(DkimVerificationStatus::Fail, None, None, detail);
        }
        SigParse::Neutral(detail) => return neutral(detail),
    };
    let domain = sig.domain.clone();
    let selector = sig.selector.clone();
    let wrap = |status: DkimVerificationStatus, detail: String| {
        DkimVerification::with_status(status, Some(domain.clone()), Some(selector.clone()), detail)
    };

    // i= のドメインは d= 自身かそのサブドメインでなければならない (§6.1.1)。
    let idomain = sig.identity_domain.to_ascii_lowercase();
    let d_lower = sig.domain.to_ascii_lowercase();
    if !(idomain == d_lower || idomain.ends_with(&format!(".{d_lower}"))) {
        return wrap(
            DkimVerificationStatus::Fail,
            format!("i= のドメイン ({idomain}) が d= ({d_lower}) の範囲外です"),
        );
    }

    // 時刻チェック (x= 失効 / t= 未来)。
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Some(x) = sig.expiration {
        if now > x {
            return wrap(
                DkimVerificationStatus::Fail,
                "署名の有効期限 (x=) を過ぎています".to_string(),
            );
        }
    }
    if let Some(t) = sig.timestamp {
        if t > now {
            return wrap(
                DkimVerificationStatus::Fail,
                "署名時刻 (t=) が未来です".to_string(),
            );
        }
        if let Some(x) = sig.expiration {
            if x < t {
                return wrap(
                    DkimVerificationStatus::Fail,
                    "x= が t= より前になっています".to_string(),
                );
            }
        }
    }

    // From は署名対象でなければならない (§5.4)。
    if !sig.signed_headers.iter().any(|h| h == "from") {
        return wrap(
            DkimVerificationStatus::Fail,
            "h= に From が含まれていません".to_string(),
        );
    }

    // 本文ハッシュ (bh=) の照合。l= がある場合は正規化済み本文の
    // 先頭 l バイトだけが対象 (残りは署名されていない)。
    let canon_body = canonicalize_body(body, sig.body_canon);
    let body_for_hash: &[u8] = match sig.body_length {
        Some(l) => {
            if l > canon_body.len() as u64 {
                return wrap(
                    DkimVerificationStatus::Fail,
                    "l= が正規化済み本文長を超えています".to_string(),
                );
            }
            &canon_body[..l as usize]
        }
        None => &canon_body,
    };
    let body_digest = Sha256::digest(body_for_hash);
    if body_digest.as_slice() != sig.body_hash.as_slice() {
        return wrap(
            DkimVerificationStatus::Fail,
            "本文ハッシュ (bh=) が一致しません。本文が改竄された可能性があります".to_string(),
        );
    }

    // DNS から公開鍵レコードを取得する。
    let query_name = format!("{}._domainkey.{}", sig.selector, sig.domain);
    let records = match resolver.lookup_txt(&query_name) {
        Ok(records) if !records.is_empty() => records,
        Ok(_) => {
            return wrap(
                DkimVerificationStatus::Neutral,
                format!("DNS に DKIM 公開鍵レコードがありません ({query_name})"),
            );
        }
        Err(DkimResolveError::NotFound) => {
            return wrap(
                DkimVerificationStatus::Neutral,
                format!("DNS に DKIM 公開鍵レコードがありません ({query_name})"),
            );
        }
        Err(DkimResolveError::Temporary(e)) => {
            return wrap(
                DkimVerificationStatus::Neutral,
                format!("DNS 参照に失敗したため検証できませんでした: {e}"),
            );
        }
    };

    // ヘッダ列のハッシュを計算し、各鍵レコードで署名を照合する。
    let data = header_hash_input(headers, sig_idx, &sig);
    let digest = Sha256::digest(&data);
    let mut saw_key = false;
    let mut saw_revoked = false;
    for record in &records {
        match parse_key_record(record, &sig) {
            KeyRecordOutcome::Revoked => saw_revoked = true,
            KeyRecordOutcome::Unusable => {}
            KeyRecordOutcome::Material(material) => {
                saw_key = true;
                let ok = match &material {
                    KeyMaterial::Rsa { n, e } => rsa_verify(n, e, &sig.signature, &digest),
                    KeyMaterial::Ed25519 { key } => ed25519_verify(key, &sig.signature, &digest),
                };
                if ok {
                    return wrap(
                        DkimVerificationStatus::Pass,
                        "DKIM 署名が DNS 公開鍵で検証できました".to_string(),
                    );
                }
            }
        }
    }
    if saw_key {
        wrap(
            DkimVerificationStatus::Fail,
            "署名が DNS 公開鍵と一致しません。署名対象ヘッダが改竄された可能性があります"
                .to_string(),
        )
    } else if saw_revoked {
        wrap(
            DkimVerificationStatus::Fail,
            "DKIM 公開鍵は失効しています (p= が空)".to_string(),
        )
    } else {
        wrap(
            DkimVerificationStatus::Neutral,
            "利用可能な DKIM 公開鍵レコードがありませんでした".to_string(),
        )
    }
}

// ============================================================================
// 本番用 DNS リゾルバ (標準ライブラリのみ: UDP + EDNS0)
// ============================================================================

/// 標準ライブラリだけで DNS TXT を引く本番用リゾルバ。
///
/// UDP で問い合わせ、EDNS0 で 1232 バイトまでの応答を受け付ける。
/// CNAME は 1 段だけ追う。TCP フォールバックは行わず、切り捨てられた
/// 応答は一時的失敗 ([`DkimResolveError::Temporary`]) として返す
/// (呼び出し側では中立判定になる)。
pub struct UdpDkimKeyResolver {
    servers: Vec<std::net::SocketAddr>,
    timeout: std::time::Duration,
}

impl UdpDkimKeyResolver {
    /// ネームサーバを明示して構築する。
    #[must_use]
    pub fn new(servers: Vec<std::net::SocketAddr>) -> Self {
        Self {
            servers,
            timeout: std::time::Duration::from_secs(3),
        }
    }

    /// `/etc/resolv.conf` からネームサーバを読む (Unix 系)。
    /// 読めない・1 件も無い場合は `None`。
    #[must_use]
    pub fn system() -> Option<Self> {
        let content = std::fs::read_to_string("/etc/resolv.conf").ok()?;
        let servers: Vec<std::net::SocketAddr> = content
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                if parts.next()? != "nameserver" {
                    return None;
                }
                let ip: std::net::IpAddr = parts.next()?.parse().ok()?;
                Some(std::net::SocketAddr::new(ip, 53))
            })
            .collect();
        if servers.is_empty() {
            None
        } else {
            Some(Self::new(servers))
        }
    }

    /// 問い合わせタイムアウトを変更する。
    #[must_use]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn query(
        &self,
        server: &std::net::SocketAddr,
        name: &str,
    ) -> Result<Vec<String>, DkimResolveError> {
        self.query_inner(server, name, 0)
    }

    fn query_inner(
        &self,
        server: &std::net::SocketAddr,
        name: &str,
        depth: u8,
    ) -> Result<Vec<String>, DkimResolveError> {
        let id = transaction_id();
        let packet = build_dns_query(name, id).ok_or_else(|| {
            DkimResolveError::Temporary(format!("DNS クエリ名が不正です: {name}"))
        })?;
        let bind_addr = if server.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = std::net::UdpSocket::bind(bind_addr)
            .map_err(|e| DkimResolveError::Temporary(format!("UDP ソケットを開けません: {e}")))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| DkimResolveError::Temporary(format!("タイムアウト設定に失敗: {e}")))?;
        socket
            .connect(server)
            .and_then(|()| socket.send(&packet))
            .map_err(|e| DkimResolveError::Temporary(format!("DNS へ送信できません: {e}")))?;
        let mut buf = [0u8; 4096];
        // トランザクション ID が一致する応答が来るまで数回まで読み直す。
        let mut answer: Option<DnsAnswer> = None;
        for _ in 0..3 {
            let n = socket.recv(&mut buf).map_err(|e| {
                DkimResolveError::Temporary(format!("DNS 応答を受信できません: {e}"))
            })?;
            match parse_dns_response(&buf[..n], id) {
                Ok(parsed) => {
                    answer = Some(parsed);
                    break;
                }
                Err(DkimResolveError::Temporary(detail)) if detail == ID_MISMATCH => {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        let answer = answer.ok_or_else(|| {
            DkimResolveError::Temporary("DNS 応答の ID が一致しません".to_string())
        })?;
        if !answer.texts.is_empty() {
            return Ok(answer.texts);
        }
        if let Some(target) = answer.cname {
            if depth == 0 {
                return self.query_inner(server, &target, depth + 1);
            }
        }
        Err(DkimResolveError::NotFound)
    }
}

impl DkimKeyResolver for UdpDkimKeyResolver {
    fn lookup_txt(&self, name: &str) -> Result<Vec<String>, DkimResolveError> {
        let mut last_err =
            DkimResolveError::Temporary("DNS サーバが設定されていません".to_string());
        for server in &self.servers {
            match self.query(server, name) {
                Ok(records) => return Ok(records),
                Err(DkimResolveError::NotFound) => return Err(DkimResolveError::NotFound),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}

const ID_MISMATCH: &str = "dns-id-mismatch";

/// トランザクション ID。署名検証自体は暗号で担保されるため、
/// 時刻と PID 由来の値で十分 (DNS 応答の取り違え防止が目的)。
fn transaction_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    ((nanos >> 8) ^ (std::process::id() << 4)) as u16
}

/// DNS TXT 問い合わせパケットを組み立てる (RD + EDNS0)。
fn build_dns_query(name: &str, id: u16) -> Option<Vec<u8>> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]); // RD
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT (EDNS OPT)
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&16u16.to_be_bytes()); // QTYPE = TXT
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
                                                // OPT pseudo-RR: name=root, type=41, class=受信バッファ 1232, ttl=0, rdlen=0
    pkt.push(0);
    pkt.extend_from_slice(&41u16.to_be_bytes());
    pkt.extend_from_slice(&1232u16.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    Some(pkt)
}

#[derive(Debug)]
struct DnsAnswer {
    texts: Vec<String>,
    cname: Option<String>,
}

/// DNS 応答をパースし、TXT レコード群と CNAME の転送先を返す。
fn parse_dns_response(pkt: &[u8], expect_id: u16) -> Result<DnsAnswer, DkimResolveError> {
    let temporary = |detail: &str| DkimResolveError::Temporary(detail.to_string());
    if pkt.len() < 12 {
        return Err(temporary("DNS 応答が短すぎます"));
    }
    if u16::from_be_bytes([pkt[0], pkt[1]]) != expect_id {
        return Err(temporary(ID_MISMATCH));
    }
    let rcode = pkt[3] & 0x0f;
    match rcode {
        0 => {}
        3 => return Err(DkimResolveError::NotFound),
        _ => return Err(temporary(&format!("DNS エラーコード {rcode}"))),
    }
    if pkt[2] & 0x02 != 0 {
        return Err(temporary("DNS 応答が切り捨てられました (TCP 未対応)"));
    }
    let qd = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
    let an = usize::from(u16::from_be_bytes([pkt[6], pkt[7]]));
    let mut pos = 12usize;
    for _ in 0..qd {
        let (_, next) = read_dns_name(pkt, pos).ok_or_else(|| temporary("質問部が不正です"))?;
        pos = next
            .checked_add(4)
            .ok_or_else(|| temporary("質問部が不正です"))?;
        if pos > pkt.len() {
            return Err(temporary("質問部が不正です"));
        }
    }
    let mut texts = Vec::new();
    let mut cname = None;
    for _ in 0..an {
        let (_, next) = read_dns_name(pkt, pos).ok_or_else(|| temporary("応答部が不正です"))?;
        pos = next;
        if pos + 10 > pkt.len() {
            return Err(temporary("応答部が不正です"));
        }
        let rtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        let rdlen = usize::from(u16::from_be_bytes([pkt[pos + 8], pkt[pos + 9]]));
        let rdata_start = pos + 10;
        let rdata_end = rdata_start
            .checked_add(rdlen)
            .filter(|&end| end <= pkt.len())
            .ok_or_else(|| temporary("応答部が不正です"))?;
        let rdata = &pkt[rdata_start..rdata_end];
        match rtype {
            16 => {
                // TXT: <len><bytes> の列を連結する
                let mut joined = Vec::new();
                let mut i = 0usize;
                while i < rdata.len() {
                    let len = usize::from(rdata[i]);
                    i += 1;
                    if i + len > rdata.len() {
                        return Err(temporary("TXT レコードが不正です"));
                    }
                    joined.extend_from_slice(&rdata[i..i + len]);
                    i += len;
                }
                texts.push(String::from_utf8_lossy(&joined).into_owned());
            }
            5 => {
                if let Some((target, _)) = read_dns_name(pkt, rdata_start) {
                    cname = Some(target);
                }
            }
            _ => {}
        }
        pos = rdata_end;
    }
    Ok(DnsAnswer { texts, cname })
}

/// 圧縮ポインタ対応で DNS 名を読む。戻り値は (名前, 読み進めた位置)。
fn read_dns_name(pkt: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut next: Option<usize> = None;
    let mut jumps = 0u8;
    loop {
        let len = *pkt.get(pos)?;
        if len == 0 {
            if next.is_none() {
                next = Some(pos + 1);
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            let second = *pkt.get(pos + 1)?;
            let pointer = (usize::from(len & 0x3f) << 8) | usize::from(second);
            if next.is_none() {
                next = Some(pos + 2);
            }
            pos = pointer;
            jumps += 1;
            if jumps > 10 {
                return None;
            }
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let label_len = usize::from(len);
        let label_start = pos + 1;
        let label_end = label_start.checked_add(label_len)?;
        if label_end > pkt.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&pkt[label_start..label_end]).into_owned());
        pos = label_end;
    }
    Some((labels.join("."), next?))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// テスト用モックリゾルバ。
    #[derive(Default)]
    struct MockResolver {
        records: HashMap<String, Result<Vec<String>, DkimResolveError>>,
    }

    impl MockResolver {
        fn with_record(name: &str, record: &str) -> Self {
            let mut m = Self::default();
            m.records
                .insert(name.to_string(), Ok(vec![record.to_string()]));
            m
        }
        fn failing(error: DkimResolveError) -> Self {
            let mut m = Self::default();
            m.records.insert("*".to_string(), Err(error));
            m
        }
    }

    impl DkimKeyResolver for MockResolver {
        fn lookup_txt(&self, name: &str) -> Result<Vec<String>, DkimResolveError> {
            if let Some(result) = self.records.get(name) {
                return result.clone();
            }
            if let Some(result) = self.records.get("*") {
                return result.clone();
            }
            Err(DkimResolveError::NotFound)
        }
    }

    // --- フィクスチャ ---
    //
    // RFC 8463 付録 A のメッセージと鍵レコード (relaxed/relaxed,
    // ed25519 + rsa の 2 署名)。本文末尾の空行は正規化で無視される。

    const RFC8463_MESSAGE: &str = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;\r\n d=football.example.com; i=@football.example.com;\r\n q=dns/txt; s=brisbane; t=1528637909; h=from : to :\r\n subject : date : message-id : from : subject : date;\r\n bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus\r\n Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n d=football.example.com; i=@football.example.com;\r\n q=dns/txt; s=test; t=1528637909; h=from : to : subject :\r\n date : message-id : from : subject : date;\r\n bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3\r\n DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz\r\n dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=\r\nFrom: Joe SixPack <joe@football.example.com>\r\nTo: Suzie Q <suzie@shopping.example.net>\r\nSubject: Is dinner ready?\r\nDate: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\nMessage-ID: <20030712040037.46341.5F8J@football.example.com>\r\n\r\nHi.\r\n\r\nWe lost the game.  Are you hungry yet?\r\n\r\nJoe.\r\n\r\n";

    fn rfc8463_resolver() -> MockResolver {
        let mut m = MockResolver::default();
        m.records.insert(
            "brisbane._domainkey.football.example.com".to_string(),
            Ok(vec![
                "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".to_string(),
            ]),
        );
        m.records.insert(
            "test._domainkey.football.example.com".to_string(),
            Ok(vec![
                "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB".to_string(),
            ]),
        );
        m
    }

    #[test]
    fn rfc8463_both_signatures_pass() {
        let results = verify_message(&rfc8463_resolver(), RFC8463_MESSAGE.as_bytes());
        assert_eq!(results.len(), 2, "2 件の署名が対象になるべき: {results:?}");
        assert_eq!(
            results[0].status,
            DkimVerificationStatus::Pass,
            "ed25519 署名が Pass すべき: {:?}",
            results[0].detail
        );
        assert_eq!(results[0].selector.as_deref(), Some("brisbane"));
        assert_eq!(
            results[1].status,
            DkimVerificationStatus::Pass,
            "rsa 署名が Pass すべき: {:?}",
            results[1].detail
        );
        assert_eq!(results[1].selector.as_deref(), Some("test"));
    }

    #[test]
    fn rfc8463_tampered_body_fails_bh() {
        let tampered = RFC8463_MESSAGE.replace("We lost the game", "We won the game!");
        let results = verify_message(&rfc8463_resolver(), tampered.as_bytes());
        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(
                r.status,
                DkimVerificationStatus::Fail,
                "本文改竄は bh= 不一致で Fail すべき: {:?}",
                r.detail
            );
            assert!(
                r.detail.contains("bh="),
                "理由に bh= を含むべき: {}",
                r.detail
            );
        }
    }

    #[test]
    fn rfc8463_tampered_header_fails_signature() {
        let tampered = RFC8463_MESSAGE.replace("Is dinner ready?", "Send money now!!");
        let results = verify_message(&rfc8463_resolver(), tampered.as_bytes());
        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(
                r.status,
                DkimVerificationStatus::Fail,
                "署名対象ヘッダの改竄は署名不一致で Fail すべき: {:?}",
                r.detail
            );
        }
    }

    #[test]
    fn dns_temporary_error_is_neutral() {
        let resolver = MockResolver::failing(DkimResolveError::Temporary("timeout".to_string()));
        let results = verify_message(&resolver, RFC8463_MESSAGE.as_bytes());
        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(
                r.status,
                DkimVerificationStatus::Neutral,
                "DNS 一時失敗は中立であるべき: {:?}",
                r.detail
            );
        }
    }

    #[test]
    fn dns_not_found_is_neutral() {
        let resolver = MockResolver::default();
        let results = verify_message(&resolver, RFC8463_MESSAGE.as_bytes());
        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(r.status, DkimVerificationStatus::Neutral);
        }
    }

    // --- 自作フィクスチャ (独立実装の署名器 + openssl で生成) ---
    //
    // 鍵は RFC 6376 付録 C のサンプル鍵ペア (RSA 1024bit)。
    // 署名器は Python 標準ライブラリ + openssl で別途実装した。

    const EXAMPLE_RSA_RECORD: &str = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB";

    const RSA_SIMPLE_MESSAGE: &str = "DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=example.net; s=sel1; h=From:To:Subject:Date; bh=CM5DA7mjgVjBMs6vw8QrWX8tBNT9KxMWglc+fnb8K1I=; b=4xuq0HjEEeXDLA6iDCATxEh0pCgafS2ZHVPLiIbp5EponZwdJnCFfc63z\r\n VG1DqlJBdlkqmmNOQ6Lw1YCRyxAFJnwoI9PBTtcsB+6AtOfTvpcUlDlk/\r\n J+fUEWWzYjZ+2gHCUENCE51+FQhqzoQ3XeNTyerj9kiEdGAsoMSnovbL0\r\n =\r\nFrom: Alice <alice@example.net>\r\nTo: Bob <bob@example.org>\r\nSubject: Simple test\r\nDate: Mon, 10 Nov 2026 10:00:00 +0900\r\nMessage-ID: <simple1@example.net>\r\n\r\nHello, world.\r\n\r\nSecond line here.\r\n";

    const RSA_RELAXED_MESSAGE: &str = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.net; s=sel1; h=From:To:Subject:Date; bh=tKXrVtHUICRhb1trMfbIavk1m6+kJVTAeYriy4m/XiM=; b=h+YJghxy4iIH9kfaVt64pNdLwKF44LeTC0hV2wh8gsJnv0C45j0UQEOzC\r\n LUppAxSmX3+Y+sMVd0ThILlh4EYjGGAno8M96A5VdSwRoH2lqtxXB9r9M\r\n OrbFRCrCHphmyvnc9Vy+kuLy1lA0T+Fca5YFycgq8JoAQACxuYVfCORR8\r\n =\r\nFrom: Alice <alice@example.net>\r\nTo: Bob <bob@example.org>\r\nSubject: A folded\r\n\tsubject   with  spaces\r\nDate: Mon, 10 Nov 2026 10:00:00 +0900\r\nMessage-ID: <relaxed1@example.net>\r\n\r\nLine with trailing spaces   \r\nTab\there\r\n\r\n\r\n";

    const RSA_LENGTH_MESSAGE: &str = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.net; s=sel1; l=21; h=From:To:Subject; bh=PBr5aEecuuytAf+6t797jOdMSTdkTACtL8/+FQoLIXM=; b=t8XgBI8cJ20hY0eXNSypQO+Y91mqDPsJZMcGzxt88ancycQE8J1OGEgQW\r\n HycvGUJFu8Jy1jffgVCDYvJNKUMsXBu5hJ9PVmfVn9z294L4aCWCOwqGH\r\n DZPihYODWZ2w29LA8sEl/vpNTzU/Lm9gTA0bffa9dGYPJRqsaUBP+muUs\r\n =\r\nFrom: Alice <alice@example.net>\r\nTo: Bob <bob@example.org>\r\nSubject: Length tag\r\nDate: Mon, 10 Nov 2026 10:00:00 +0900\r\n\r\nSigned prefix body.\r\n";

    const ED25519_MESSAGE: &str = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.net; s=ed1; h=From:To:Subject:Date; bh=2zoAk6Uf9Ie8Ty38yuUY831bp9Zksbnhldr4u9H0TLk=; b=MI80vxWslTGJ9U3//Fi0Ae00WwU9RFTG/wm6eaCr5ydzCgK7edGKxAwRM\r\n nnWD5dFB4koWjxp+snZrTzYhVB9Ag==\r\nFrom: Carol <carol@example.net>\r\nTo: Dave <dave@example.org>\r\nSubject: Ed25519 test\r\nDate: Mon, 10 Nov 2026 11:00:00 +0900\r\n\r\nEd25519 signed body.\r\n";

    const ED25519_RECORD: &str =
        "v=DKIM1; k=ed25519; p=bWxlb9oft6QBR2Zek1A33mEVklKHxKII2yqCR+tejJc=";

    #[test]
    fn rsa_simple_signature_passes() {
        let resolver = MockResolver::with_record("sel1._domainkey.example.net", EXAMPLE_RSA_RECORD);
        let results = verify_message(&resolver, RSA_SIMPLE_MESSAGE.as_bytes());
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].status,
            DkimVerificationStatus::Pass,
            "simple/simple の RSA 署名が Pass すべき: {:?}",
            results[0].detail
        );
    }

    #[test]
    fn rsa_relaxed_signature_passes() {
        let resolver = MockResolver::with_record("sel1._domainkey.example.net", EXAMPLE_RSA_RECORD);
        let results = verify_message(&resolver, RSA_RELAXED_MESSAGE.as_bytes());
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].status,
            DkimVerificationStatus::Pass,
            "relaxed/relaxed の RSA 署名が Pass すべき: {:?}",
            results[0].detail
        );
    }

    #[test]
    fn length_tagged_signature_tolerates_appended_body() {
        // l= で署名範囲が本文先頭 21 バイトに限られるため、末尾への追記では
        // 検証は Pass のままになる (濫用リスク自体は dkim_check 側の
        // l= シグナルが別途警告する)。
        let resolver = MockResolver::with_record("sel1._domainkey.example.net", EXAMPLE_RSA_RECORD);
        let appended = format!("{RSA_LENGTH_MESSAGE}Appended junk line.\r\n");
        let results = verify_message(&resolver, appended.as_bytes());
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].status,
            DkimVerificationStatus::Pass,
            "l= の範囲外への追記では Pass のままであるべき: {:?}",
            results[0].detail
        );
    }

    #[test]
    fn ed25519_signature_passes() {
        let resolver = MockResolver::with_record("ed1._domainkey.example.net", ED25519_RECORD);
        let results = verify_message(&resolver, ED25519_MESSAGE.as_bytes());
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].status,
            DkimVerificationStatus::Pass,
            "Ed25519 署名が Pass すべき: {:?}",
            results[0].detail
        );
    }

    #[test]
    fn wrong_key_in_dns_fails() {
        // 別の RSA 鍵 (RFC 8463 の test セレクタの鍵) を返すと署名不一致で Fail。
        let resolver = MockResolver::with_record(
            "sel1._domainkey.example.net",
            "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB",
        );
        let results = verify_message(&resolver, RSA_SIMPLE_MESSAGE.as_bytes());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, DkimVerificationStatus::Fail);
    }

    #[test]
    fn revoked_key_fails() {
        let resolver =
            MockResolver::with_record("sel1._domainkey.example.net", "v=DKIM1; k=rsa; p=");
        let results = verify_message(&resolver, RSA_SIMPLE_MESSAGE.as_bytes());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, DkimVerificationStatus::Fail);
        assert!(
            results[0].detail.contains("失効"),
            "失効が理由であるべき: {}",
            results[0].detail
        );
    }

    #[test]
    fn message_without_signature_returns_empty() {
        let resolver = MockResolver::default();
        let msg = "From: a@example.com\r\n\r\nbody\r\n";
        assert!(verify_message(&resolver, msg.as_bytes()).is_empty());
    }

    // --- 正規化の単体テスト ---

    #[test]
    fn body_simple_canonicalization() {
        assert_eq!(canonicalize_body(b"", Canon::Simple), b"");
        assert_eq!(canonicalize_body(b"abc", Canon::Simple), b"abc\r\n");
        assert_eq!(canonicalize_body(b"abc\r\n", Canon::Simple), b"abc\r\n");
        assert_eq!(
            canonicalize_body(b"abc\r\n\r\n\r\n", Canon::Simple),
            b"abc\r\n",
            "末尾の空行は無視される"
        );
        assert_eq!(
            canonicalize_body(b"a\r\n\r\nb\r\n", Canon::Simple),
            b"a\r\n\r\nb\r\n",
            "中間の空行は残る"
        );
        assert_eq!(
            canonicalize_body(b"a  \r\n", Canon::Simple),
            b"a  \r\n",
            "simple は行末空白を保持する"
        );
    }

    #[test]
    fn body_relaxed_canonicalization() {
        assert_eq!(
            canonicalize_body(b"a  \t b \r\n", Canon::Relaxed),
            b"a b\r\n",
            "WSP は 1 つの SP に畳まれ行末 WSP は落ちる"
        );
        assert_eq!(canonicalize_body(b"", Canon::Relaxed), b"");
    }

    #[test]
    fn header_relaxed_canonicalization() {
        let raw = b"Subject:  A folded\r\n\tsubject   with  spaces";
        assert_eq!(
            canonicalize_header(raw, Canon::Relaxed),
            b"subject:A folded subject with spaces"
        );
        let raw_simple = b"Subject:  Keep  As-Is ";
        assert_eq!(canonicalize_header(raw_simple, Canon::Simple), raw_simple);
    }

    #[test]
    fn empty_b_tag_value_strips_only_signature() {
        let raw = b"DKIM-Signature: v=1; a=rsa-sha256; bh=AbC=;\r\n b=XYZ\r\n ABC==; d=example.com";
        let emptied = empty_b_tag_value(raw);
        assert_eq!(
            emptied, b"DKIM-Signature: v=1; a=rsa-sha256; bh=AbC=;\r\n b=; d=example.com",
            "bh= には触れず b= の値だけを空にすべき"
        );
    }

    #[test]
    fn dns_query_builds() {
        let pkt = build_dns_query("sel1._domainkey.example.com", 0x1234).unwrap();
        assert_eq!(&pkt[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 1, "QDCOUNT");
        assert_eq!(u16::from_be_bytes([pkt[10], pkt[11]]), 1, "ARCOUNT (EDNS)");
        // ラベル長プレフィクス: "sel1"=4
        assert_eq!(pkt[12], 4);
        assert_eq!(&pkt[13..17], b"sel1");
    }

    #[test]
    fn dns_response_parses_txt() {
        // 最小の応答パケットを手組みする: 質問 1 件 + TXT 応答 1 件 (圧縮ポインタ使用)。
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        pkt.extend_from_slice(&[0x81, 0x80]); // flags: QR+RD / RA
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QD
        pkt.extend_from_slice(&1u16.to_be_bytes()); // AN
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NS
        pkt.extend_from_slice(&0u16.to_be_bytes()); // AR
        let question_at = pkt.len();
        for label in ["sel1", "_domainkey", "example", "com"] {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&16u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        // 応答: 名前は質問へのポインタ
        pkt.extend_from_slice(&[0xc0, question_at as u8]);
        pkt.extend_from_slice(&16u16.to_be_bytes()); // TXT
        pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
        pkt.extend_from_slice(&300u32.to_be_bytes()); // TTL
        let record = b"v=DKIM1; p=ABC";
        pkt.extend_from_slice(&(record.len() as u16 + 1).to_be_bytes());
        pkt.push(record.len() as u8);
        pkt.extend_from_slice(record);
        let answer = parse_dns_response(&pkt, 0x1234).unwrap();
        assert_eq!(answer.texts, vec!["v=DKIM1; p=ABC".to_string()]);
        assert!(answer.cname.is_none());
    }

    #[test]
    fn dns_response_nxdomain_is_not_found() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x1234u16.to_be_bytes());
        pkt.extend_from_slice(&[0x81, 0x83]); // QR+RD / RA + NXDOMAIN(3)
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        let err = parse_dns_response(&pkt, 0x1234).unwrap_err();
        assert_eq!(err, DkimResolveError::NotFound);
    }
}
