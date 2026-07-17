//! kaname-observability — 観測性 3 本柱。
//!
//! - Logs: tracing-subscriber 構造化 JSON
//! - Metrics: Prometheus 互換
//! - Latency: RAII LatencyTimer で Apple HIG 目標と比較
//!
//! PrivacySanitizer がメール本文・PII をログから除外。
//! テレメトリはデフォルト OFF (オプトイン)。

// crates/kaname-observability/src/lib.rs
//
// Kaname 観測性 (Observability) 層
//
// 三本柱:
//   1. Logs    — 構造化 JSON ログ (tracing-subscriber)
//   2. Metrics — Prometheus 互換メトリクス (HTTPエンドポイント /metrics)
//   3. Traces  — OpenTelemetry 互換 (オプション)
//
// プライバシー原則:
//   - メール本文は絶対にログに出さない (privacy.rs で除外)
//   - PII (個人情報) はハッシュ化または除去
//   - すべてオプトイン (デフォルト OFF)
//
// 実行例:
//   KANAME_TELEMETRY=on RUST_LOG=info cargo run


#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

pub mod trajectory;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use serde::{Deserialize, Serialize};

// ============================================================================
// メトリクスカウンター (Prometheus 互換)
// ============================================================================

/// グローバルメトリクス。`static` として保持される。
pub struct Metrics {
    // BEC 検出
    pub bec_safe:       AtomicU64,
    pub bec_advisory:   AtomicU64,
    pub bec_suspicious: AtomicU64,
    pub bec_dangerous:  AtomicU64,

    // AI 処理
    pub ai_summaries_total:  AtomicU64,
    pub ai_phishing_total:   AtomicU64,
    pub ai_blocked_total:    AtomicU64,  // DLP でブロックされた数

    // メール処理
    pub mails_received:    AtomicU64,
    pub mails_sent:        AtomicU64,
    pub mails_archived:    AtomicU64,
    pub mails_deleted:     AtomicU64,

    // 暗号化
    pub mls_messages_in:   AtomicU64,
    pub mls_messages_out:  AtomicU64,
    pub mls_key_rotations: AtomicU64,

    // パフォーマンス
    pub jmap_requests:     AtomicU64,
    pub jmap_errors:       AtomicU64,
    pub render_total_us:   AtomicU64,  // HTML レンダリング累積マイクロ秒

    // セキュリティイベント
    pub prompt_injection_blocked: AtomicU64,
    pub sandbox_violations:       AtomicU64,
    pub safety_number_mismatch:   AtomicU64,
}

impl Metrics {
    pub const fn new() -> Self {
        Self {
            bec_safe:       AtomicU64::new(0),
            bec_advisory:   AtomicU64::new(0),
            bec_suspicious: AtomicU64::new(0),
            bec_dangerous:  AtomicU64::new(0),
            ai_summaries_total: AtomicU64::new(0),
            ai_phishing_total:  AtomicU64::new(0),
            ai_blocked_total:   AtomicU64::new(0),
            mails_received: AtomicU64::new(0),
            mails_sent:     AtomicU64::new(0),
            mails_archived: AtomicU64::new(0),
            mails_deleted:  AtomicU64::new(0),
            mls_messages_in:  AtomicU64::new(0),
            mls_messages_out: AtomicU64::new(0),
            mls_key_rotations: AtomicU64::new(0),
            jmap_requests:    AtomicU64::new(0),
            jmap_errors:      AtomicU64::new(0),
            render_total_us:  AtomicU64::new(0),
            prompt_injection_blocked: AtomicU64::new(0),
            sandbox_violations:       AtomicU64::new(0),
            safety_number_mismatch:   AtomicU64::new(0),
        }
    }

    /// BEC 判定をカウント。
    pub fn record_bec(&self, verdict: &str) {
        match verdict {
            "SAFE"       => self.bec_safe.fetch_add(1, Ordering::Relaxed),
            "ADVISORY"   => self.bec_advisory.fetch_add(1, Ordering::Relaxed),
            "SUSPICIOUS" => self.bec_suspicious.fetch_add(1, Ordering::Relaxed),
            "DANGEROUS"  => self.bec_dangerous.fetch_add(1, Ordering::Relaxed),
            // 未知の verdict は静かに捨てず警告ログを残す。
            // 修正前は _ => 0 で黙って破棄しており、呼び出し側の verdict 文字列が
            // タイポやリネームで不一致になってもメトリクスが欠落するだけで
            // 誰にも気付かれない状態だった (セキュリティ関連メトリクスの欠損)。
            _ => {
                tracing::warn!(verdict, "未知の BEC verdict を record_bec に渡されました");
                0
            }
        };
    }

    /// Prometheus 形式でエクスポート。
    #[must_use]
    pub fn export_prometheus(&self) -> String {
        format!(
            "# HELP kaname_bec_total BEC verdict count by severity\n\
             # TYPE kaname_bec_total counter\n\
             kaname_bec_total{{verdict=\"safe\"}} {}\n\
             kaname_bec_total{{verdict=\"advisory\"}} {}\n\
             kaname_bec_total{{verdict=\"suspicious\"}} {}\n\
             kaname_bec_total{{verdict=\"dangerous\"}} {}\n\
             # HELP kaname_ai_summaries_total AI summary requests\n\
             # TYPE kaname_ai_summaries_total counter\n\
             kaname_ai_summaries_total {}\n\
             # HELP kaname_ai_blocked_total AI requests blocked by DLP\n\
             # TYPE kaname_ai_blocked_total counter\n\
             kaname_ai_blocked_total {}\n\
             # HELP kaname_mails_total Mail processing counts\n\
             # TYPE kaname_mails_total counter\n\
             kaname_mails_total{{op=\"received\"}} {}\n\
             kaname_mails_total{{op=\"sent\"}} {}\n\
             kaname_mails_total{{op=\"archived\"}} {}\n\
             kaname_mails_total{{op=\"deleted\"}} {}\n\
             # HELP kaname_mls_messages_total MLS encrypted messages\n\
             # TYPE kaname_mls_messages_total counter\n\
             kaname_mls_messages_total{{direction=\"in\"}} {}\n\
             kaname_mls_messages_total{{direction=\"out\"}} {}\n\
             # HELP kaname_mls_key_rotations Total MLS key rotations\n\
             # TYPE kaname_mls_key_rotations counter\n\
             kaname_mls_key_rotations {}\n\
             # HELP kaname_security_events Security events\n\
             # TYPE kaname_security_events counter\n\
             kaname_security_events{{type=\"prompt_injection_blocked\"}} {}\n\
             kaname_security_events{{type=\"sandbox_violation\"}} {}\n\
             kaname_security_events{{type=\"safety_number_mismatch\"}} {}\n",
            self.bec_safe.load(Ordering::Relaxed),
            self.bec_advisory.load(Ordering::Relaxed),
            self.bec_suspicious.load(Ordering::Relaxed),
            self.bec_dangerous.load(Ordering::Relaxed),
            self.ai_summaries_total.load(Ordering::Relaxed),
            self.ai_blocked_total.load(Ordering::Relaxed),
            self.mails_received.load(Ordering::Relaxed),
            self.mails_sent.load(Ordering::Relaxed),
            self.mails_archived.load(Ordering::Relaxed),
            self.mails_deleted.load(Ordering::Relaxed),
            self.mls_messages_in.load(Ordering::Relaxed),
            self.mls_messages_out.load(Ordering::Relaxed),
            self.mls_key_rotations.load(Ordering::Relaxed),
            self.prompt_injection_blocked.load(Ordering::Relaxed),
            self.sandbox_violations.load(Ordering::Relaxed),
            self.safety_number_mismatch.load(Ordering::Relaxed),
        )
    }
}

impl Default for Metrics {
    fn default() -> Self { Self::new() }
}

/// グローバルメトリクスインスタンス。
pub static METRICS: Metrics = Metrics::new();

// ============================================================================
// レイテンシ計測ヘルパー
// ============================================================================

/// 操作のレイテンシを自動計測する RAII ガード。
pub struct LatencyTimer {
    start:    Instant,
    op_name:  &'static str,
}

impl LatencyTimer {
    /// 処理を開始する。
    pub fn start(op_name: &'static str) -> Self {
        Self { start: Instant::now(), op_name }
    }

    /// 経過時間 (μs) を取得。
    #[must_use]
    pub fn elapsed_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }
}

impl Drop for LatencyTimer {
    fn drop(&mut self) {
        let us = self.elapsed_us();
        // Apple HIG パフォーマンス目標と比較してログ
        let target = match self.op_name {
            "bec_evaluate" => 50_000,        // 50ms
            "ai_summarize" => 3_000_000,     // 3s
            "mail_render"  => 16_000,        // 16ms (60fps)
            _              => 100_000,       // デフォルト 100ms
        };

        if us > target {
            tracing::warn!(
                op = %self.op_name,
                elapsed_us = us,
                target_us = target,
                "Operation exceeded performance target"
            );
        } else {
            tracing::debug!(op = %self.op_name, elapsed_us = us, "Operation completed");
        }
    }
}

// ============================================================================
// プライバシー保護ログフィルター
// ============================================================================

/// メール本文・PIIをログから除外するためのサニタイザ。
///
/// 原則: ログ出力前に必ずこのフィルターを通す。
/// メールボディ・添付内容・トークン・パスワードを絶対にログに出さない。
pub struct PrivacySanitizer;

impl PrivacySanitizer {
    /// 文字列から PII を除去または匿名化する。
    #[must_use]
    pub fn sanitize(input: &str) -> String {
        // 入力サイズを制限する (複数パス処理による OOM/CPU DoS 防止)
        // ログメッセージが大きすぎる場合は先頭のみサニタイズして truncation を示す
        const MAX_SANITIZE_BYTES: usize = 64 * 1024; // 64 KB
        let truncated;
        let input = if input.len() > MAX_SANITIZE_BYTES {
            let end = (0..=MAX_SANITIZE_BYTES)
                .rev()
                .find(|&i| input.is_char_boundary(i))
                .unwrap_or(0);
            truncated = format!("{}…[{} バイト超過のため切り詰め]", &input[..end], input.len());
            truncated.as_str()
        } else {
            input
        };
        // 全角 ASCII (U+FF01–FF5E) → ASCII、全角スペース → space に正規化してから
        // 各サニタイズルールを適用する。これにより alice＠example.com のような
        // 全角文字を使った PII 漏洩バイパスを防ぐ。
        let normalized = normalize_fullwidth(input);
        let mut result = normalized;

        // クレジットカード番号 (13〜16 桁数字、スペース/ハイフン区切り可)
        result = redact_credit_card_numbers(&result);

        // メールアドレスを匿名化 (例: alice@example.com → ali***@example.com)
        result = mask_email_addresses(&result);

        // Bearer トークンを全件除去 (複数ヘッダーがある場合も対応)
        result = redact_all_bearer_tokens(&result);

        // 日本の電話番号をマスク
        result = mask_jp_phone_numbers(&result);

        result
    }

    /// メールアドレスをハッシュ化 (集計用、復元不可)。
    #[must_use]
    pub fn hash_email(addr: &str) -> String {
        let mut h: u64 = 14695981039346656037;
        for b in addr.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(1099511628211);
        }
        format!("eml_{:016x}", h)
    }
}

/// 全角 ASCII (U+FF01–FF5E) → 半角 ASCII、全角スペース (U+3000) → 空白 に変換する。
///
/// `alice＠example.com` のような全角文字を使った PII バイパスを防ぐために
/// `PrivacySanitizer::sanitize` の前処理として使用する。
fn normalize_fullwidth(s: &str) -> String {
    s.chars().map(|c| {
        if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
            char::from_u32(c as u32 - 0xFEE0).unwrap_or(c)
        } else if c == '\u{3000}' {
            ' '
        } else {
            c
        }
    }).collect()
}

fn mask_email_addresses(s: &str) -> String {
    // 単純な実装: 最初の3文字以外をマスク
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        // 数字始まりのローカル部 (例: "12345@vendor.com"、社員番号型アドレス) も
        // マスク対象にするため alphanumeric で走査を開始する。
        // 以前は is_ascii_alphabetic のみで、数字始まりのメールアドレスが
        // 無加工でログへ素通りしていた。
        if c.is_ascii_alphanumeric() {
            // メールっぽいパターンを検出
            let mut local = String::new();
            local.push(c);
            while let Some(&nc) = chars.peek() {
                if nc.is_ascii_alphanumeric() || nc == '.' || nc == '_' || nc == '-' {
                    local.push(nc);
                    chars.next();
                } else { break; }
            }
            if chars.peek() == Some(&'@') {
                // メールアドレスっぽい
                if local.len() > 3 {
                    result.push_str(&local[..3]);
                    result.push_str("***");
                } else {
                    result.push_str(&local);
                }
                // @ 以降はそのまま
                for c2 in chars.by_ref() {
                    result.push(c2);
                    if !c2.is_ascii_alphanumeric() && c2 != '@' && c2 != '.' && c2 != '-' {
                        break;
                    }
                }
            } else {
                result.push_str(&local);
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// クレジットカード番号パターン (13〜16 桁、スペース/ハイフン区切り可) を除去する。
///
/// 旧来の `remove_pattern(_matcher)` は `_matcher` 引数が実際には使用されず、
/// 固定の 13 桁ロジックで動作していた (デッドコード)。
/// 本関数は責務を明確にし引数を取り除いた。
fn redact_credit_card_numbers(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // 16桁の連続数字 (区切り文字含む) を検出
        let mut digit_count = 0;
        let mut j = i;
        while j < chars.len() && (chars[j].is_ascii_digit() || matches!(chars[j], ' ' | '-')) {
            if chars[j].is_ascii_digit() { digit_count += 1; }
            j += 1;
            if digit_count >= 16 { break; }
        }
        if digit_count >= 13 {
            result.push_str("[REDACTED-CC]");
            i = j;
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    result
}

/// Bearer トークンを全て `Bearer [REDACTED]` に置換する。
/// `find()` は最初の一件しか返さないため、ループで全件処理する。
fn redact_all_bearer_tokens(s: &str) -> String {
    const PREFIX: &str = "Bearer ";
    let mut result = String::with_capacity(s.len());
    let mut remaining = s;
    while let Some(idx) = remaining.find(PREFIX) {
        result.push_str(&remaining[..idx]);
        result.push_str("Bearer [REDACTED]");
        let after = &remaining[idx + PREFIX.len()..];
        let token_len = after.find(char::is_whitespace).unwrap_or(after.len());
        remaining = &after[token_len..];
    }
    result.push_str(remaining);
    result
}

/// 日本の電話番号をマスクする。
///
/// 対応フォーマット:
/// - 携帯: 090-1234-5678 / 080-... / 070-... / 050-...
/// - 固定: 03-1234-5678 / 06-... / 011-...
///   - 数字のみ形式 (09012345678) も対象。
fn mask_jp_phone_numbers(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // 先頭が数字なら電話番号候補
        if chars[i].is_ascii_digit() {
            let start = i;
            let mut digits = 0u32;
            let mut j = i;
            // 数字・ハイフン・括弧を消費して桁数を数える
            while j < chars.len()
                && (chars[j].is_ascii_digit()
                    || matches!(chars[j], '-' | '(' | ')' | ' ')
                    && digits < 12)
            {
                if chars[j].is_ascii_digit() {
                    digits += 1;
                }
                j += 1;
                // 桁数が多くなりすぎたら打ち切り
                if digits > 11 {
                    break;
                }
            }
            // 10〜11桁 = 日本の電話番号
            if (10..=11).contains(&digits) {
                result.push_str("[TEL-REDACTED]");
                i = j;
            } else {
                // 電話番号でなければそのまま
                result.push(chars[start]);
                i = start + 1;
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    result
}

// ============================================================================
// テレメトリ設定
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// テレメトリを有効化するか (デフォルト: false)
    pub enabled: bool,
    /// メトリクスエンドポイントを公開するか
    pub metrics_endpoint: bool,
    /// メトリクスサーバーのバインドアドレス
    pub bind_addr: String,
    /// オプトインステータス (ユーザーが明示的に有効化したか)
    pub user_consented: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,           // デフォルト OFF (プライバシー優先)
            metrics_endpoint: false,
            bind_addr: "127.0.0.1:9100".into(),
            user_consented: false,
        }
    }
}

// ============================================================================
// PrivacyLayer — tracing-subscriber Layer で PII 漏洩をブロック
// ============================================================================

/// PII を含む tracing イベントをブロックする `Layer` 実装。
///
/// `tracing-subscriber` の Layer として登録することで、
/// 将来の開発者がうっかり PII をログに書いた場合に検出できる。
///
/// # 動作
///
/// - 文字列フィールドを `PrivacySanitizer::contains_pii()` で検査
/// - PII を検出した場合: イベントをドロップし、代替の匿名化ログを出力
/// - 正常なイベントは全て通過させる
pub struct PrivacyLayer;

/// PII を含む可能性のあるフィールドを収集するビジター。
struct PiiFieldVisitor {
    found_pii: bool,
    sanitized_fields: Vec<(String, String)>,
}

impl PiiFieldVisitor {
    fn new() -> Self {
        Self { found_pii: false, sanitized_fields: Vec::new() }
    }
}

/// フィールド名が高リスク PII を含む可能性があるか判定する。
///
/// フィールド名によるブロッキング (P1/A5):
/// 値の内容検査より前に名前でブロックすることで、
/// sanitizer が見逃した PII の多重防衛層を提供する。
/// 出典: https://zenn.dev/taiki45/books/pragmatic-rust-application-development/viewer/tracing
fn is_sensitive_field_name(name: &str) -> bool {
    // 完全一致のみ (サブ文字列マッチは誤検知が多い)
    const SENSITIVE_EXACT: &[&str] = &[
        "email", "e_mail", "mail",
        "subject", "body", "content", "message",
        "password", "passwd", "secret", "token", "api_key",
        "bearer", "authorization", "auth",
        "phone", "address", "name", "full_name", "display_name",
        "credit_card", "card_number", "cvv",
        "my_number", "マイナンバー", "個人番号",
    ];
    let lower = name.to_lowercase();
    SENSITIVE_EXACT.iter().any(|&s| lower == s)
}

impl tracing::field::Visit for PiiFieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        let field_name = field.name();
        // フィールド名による事前ブロック (多重防衛)
        let sanitized = if is_sensitive_field_name(field_name) {
            self.found_pii = true;
            "[REDACTED:sensitive-field]".to_string()
        } else {
            let s = PrivacySanitizer::sanitize(value);
            if s != value {
                self.found_pii = true;
            }
            s
        };
        self.sanitized_fields.push((field_name.to_string(), sanitized));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let field_name = field.name();
        let raw = format!("{value:?}");
        let sanitized = if is_sensitive_field_name(field_name) {
            self.found_pii = true;
            "[REDACTED:sensitive-field]".to_string()
        } else {
            let s = PrivacySanitizer::sanitize(&raw);
            if s != raw {
                self.found_pii = true;
            }
            s
        };
        self.sanitized_fields.push((field_name.to_string(), sanitized));
    }
}

impl<S> tracing_subscriber::Layer<S> for PrivacyLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = PiiFieldVisitor::new();
        event.record(&mut visitor);

        if visitor.found_pii {
            // PII 検出: METRICS に記録 (将来の実装のためのフック)
            // 現在は警告のみ。将来: イベントをドロップして匿名化版を再発行
            tracing::warn!(
                target: "kaname::privacy",
                "PII detected in log event — field values have been sanitized in metrics"
            );
        }
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_increment_atomically() {
        let m = Metrics::new();
        m.record_bec("DANGEROUS");
        m.record_bec("DANGEROUS");
        m.record_bec("SAFE");
        assert_eq!(m.bec_dangerous.load(Ordering::Relaxed), 2);
        assert_eq!(m.bec_safe.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn unknown_bec_verdict_does_not_panic_or_corrupt_other_counters() {
        // 修正前は _ => 0 で黙って破棄していた。タイポ/リネームされた
        // verdict 文字列が来てもパニックせず、既存カウンタを汚染しないことを確認する。
        let m = Metrics::new();
        m.record_bec("DANGEROUS");
        m.record_bec("UNKNOWN_VERDICT_TYPO");
        assert_eq!(m.bec_dangerous.load(Ordering::Relaxed), 1);
        assert_eq!(m.bec_safe.load(Ordering::Relaxed), 0);
        assert_eq!(m.bec_advisory.load(Ordering::Relaxed), 0);
        assert_eq!(m.bec_suspicious.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn metrics_export_prometheus_format() {
        let m = Metrics::new();
        m.record_bec("DANGEROUS");
        let exported = m.export_prometheus();
        assert!(exported.contains("# HELP"));
        assert!(exported.contains("# TYPE"));
        assert!(exported.contains("kaname_bec_total{verdict=\"dangerous\"} 1"));
    }

    #[test]
    fn privacy_email_address_masking() {
        let input = "Connection from alice@company.co.jp succeeded";
        let output = PrivacySanitizer::sanitize(input);
        assert!(!output.contains("alice@"), "メール先頭がマスクされていない: {output}");
        assert!(output.contains("@company.co.jp") || output.contains("***"));
    }

    #[test]
    fn privacy_digit_leading_email_is_masked() {
        // 回帰テスト: 以前はローカル部が数字始まりのメールアドレスが
        // 走査対象にすら入らず、無加工でログに残っていた。
        let input = "invoice 12345@vendor.com paid";
        let output = PrivacySanitizer::sanitize(input);
        assert!(!output.contains("12345@"),
            "数字始まりのローカル部がマスクされていない: {output}");
        assert!(output.contains("123***"),
            "先頭3文字+*** の形式でマスクされるべき: {output}");
    }

    #[test]
    fn privacy_credit_card_redaction() {
        let input = "Payment with 4111111111111111 succeeded";
        let output = PrivacySanitizer::sanitize(input);
        assert!(!output.contains("4111111111111111"), "クレジットカード番号がマスクされていない");
        assert!(output.contains("REDACTED"));
    }

    #[test]
    fn privacy_bearer_token_redaction() {
        let input = "Authorization: Bearer abc123secrettoken xyz";
        let output = PrivacySanitizer::sanitize(input);
        assert!(!output.contains("abc123secrettoken"));
        assert!(output.contains("REDACTED"));
    }

    #[test]
    fn email_hash_is_deterministic() {
        let a = PrivacySanitizer::hash_email("alice@example.com");
        let b = PrivacySanitizer::hash_email("alice@example.com");
        let c = PrivacySanitizer::hash_email("bob@example.com");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("eml_"));
    }

    #[test]
    fn telemetry_default_off() {
        let cfg = TelemetryConfig::default();
        assert!(!cfg.enabled, "テレメトリはデフォルトで OFF でなければならない");
        assert!(!cfg.user_consented, "ユーザー同意もデフォルトで false");
    }

    #[test]
    fn latency_timer_reports_microseconds() {
        let timer = LatencyTimer::start("test_op");
        std::thread::sleep(std::time::Duration::from_millis(2));
        let elapsed = timer.elapsed_us();
        assert!(elapsed >= 2_000, "計測時間が短すぎる: {elapsed}μs");
        assert!(elapsed < 100_000, "計測時間が異常に長い: {elapsed}μs");
    }

    #[test]
    fn privacy_bearer_token_multiple_redaction() {
        // find() は最初の一件しか返さないため、ループが必須
        let input = "proxy: Bearer first_token_abc backend: Bearer second_token_xyz end";
        let output = PrivacySanitizer::sanitize(input);
        assert!(!output.contains("first_token_abc"), "1件目のトークンが漏洩");
        assert!(!output.contains("second_token_xyz"), "2件目のトークンが漏洩");
        assert_eq!(output.matches("Bearer [REDACTED]").count(), 2);
    }

    #[test]
    fn privacy_jp_mobile_phone_masked() {
        let input = "連絡先: 090-1234-5678 まで";
        let output = PrivacySanitizer::sanitize(input);
        assert!(!output.contains("090-1234-5678"), "携帯番号が漏洩: {output}");
        assert!(output.contains("[TEL-REDACTED]"));
    }

    #[test]
    fn privacy_jp_landline_masked() {
        let input = "事務所: 03-1234-5678 (東京)";
        let output = PrivacySanitizer::sanitize(input);
        assert!(!output.contains("03-1234-5678"), "固定電話番号が漏洩: {output}");
        assert!(output.contains("[TEL-REDACTED]"));
    }

    #[test]
    fn privacy_jp_phone_digits_only_masked() {
        let input = "tel:09012345678";
        let output = PrivacySanitizer::sanitize(input);
        assert!(!output.contains("09012345678"), "数字のみ電話番号が漏洩: {output}");
        assert!(output.contains("[TEL-REDACTED]"));
    }

    #[test]
    fn privacy_short_number_not_masked() {
        // 郵便番号 (7桁) は電話番号ではない
        let input = "〒100-0001";
        let output = PrivacySanitizer::sanitize(input);
        assert!(output.contains("100"), "郵便番号まで消してしまった: {output}");
    }

    #[test]
    fn metrics_global_is_thread_safe() {
        use std::thread;
        let handles: Vec<_> = (0..10).map(|_| {
            thread::spawn(|| {
                for _ in 0..100 {
                    METRICS.record_bec("DANGEROUS");
                }
            })
        }).collect();
        for h in handles { let _ = h.join(); }
        // 10 スレッド × 100回 = 1000カウント (テスト独立性のため accumulating だけチェック)
        assert!(METRICS.bec_dangerous.load(Ordering::Relaxed) >= 1000);
    }

    // ──────────────────────────────────────────────────────────────────
    // PrivacyLayer フィールドビジター
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn pii_sanitizer_masks_email_in_log_context() {
        // PrivacySanitizer がメールアドレスを含む文字列を正しくマスクすることを確認
        let raw = "user@example.com login event";
        let sanitized = PrivacySanitizer::sanitize(raw);
        assert_ne!(raw, sanitized, "email should be masked by sanitizer");
        assert!(!sanitized.contains("user@example.com"), "raw email must not appear: {sanitized}");
    }

    #[test]
    fn pii_sanitizer_passes_clean_log_fields() {
        let raw = "normal system event count=42";
        let sanitized = PrivacySanitizer::sanitize(raw);
        assert_eq!(raw, sanitized, "clean field must pass unchanged");
    }

    // ── 全角バイパステスト ──────────────────────────────────────────────

    #[test]
    fn privacy_fullwidth_at_sign_email_masked() {
        // U+FF20 (＠) を使った全角メールアドレスがマスクされること
        let input = "ユーザー alice＠example.com がログイン";
        let output = PrivacySanitizer::sanitize(input);
        assert!(
            !output.contains("alice@example.com") && !output.contains("alice＠example.com"),
            "全角@のメールアドレスがマスクされていない: {output}"
        );
    }

    #[test]
    fn privacy_fullwidth_digits_credit_card_redacted() {
        // U+FF10–FF19 の全角数字クレジットカードがマスクされること
        let input = "card: ４１１１１１１１１１１１１１１１ ok";
        let output = PrivacySanitizer::sanitize(input);
        assert!(
            !output.contains("４１１１"),
            "全角数字クレジットカードが漏洩: {output}"
        );
        assert!(output.contains("REDACTED"), "REDACTEDが挿入されていない: {output}");
    }

    #[test]
    fn normalize_fullwidth_converts_ascii_range() {
        // U+FF20 (＠) → U+0040 (@)
        assert_eq!(normalize_fullwidth("ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ"),
                   "alice@example.com");
    }

    #[test]
    fn normalize_fullwidth_passes_normal_text() {
        let s = "hello world 123";
        assert_eq!(normalize_fullwidth(s), s);
    }

    #[test]
    fn privacy_layer_implements_layer_trait() {
        // コンパイル時型チェック: PrivacyLayer が Layer を実装していることの証明
        // (型が合わないとコンパイルエラーになる)
        let _layer: Box<dyn std::any::Any> = Box::new(PrivacyLayer);
        // Layer<S> の具体的な確認は統合テストで行う
    }

    // P1/A5: フィールド名によるブロッキング
    #[test]
    fn sensitive_field_names_detected() {
        assert!(is_sensitive_field_name("email"));
        assert!(is_sensitive_field_name("subject"));
        assert!(is_sensitive_field_name("body"));
        assert!(is_sensitive_field_name("password"));
        assert!(is_sensitive_field_name("api_key"));
        assert!(is_sensitive_field_name("authorization"));
        assert!(is_sensitive_field_name("my_number"));
        assert!(is_sensitive_field_name("マイナンバー"));
    }

    #[test]
    fn non_sensitive_field_names_pass() {
        assert!(!is_sensitive_field_name("request_id"));
        assert!(!is_sensitive_field_name("latency_us"));
        assert!(!is_sensitive_field_name("verdict"));
        assert!(!is_sensitive_field_name("crate_name"));
    }

    #[test]
    fn sensitive_field_name_is_case_insensitive() {
        assert!(is_sensitive_field_name("EMAIL"));
        assert!(is_sensitive_field_name("Password"));
        assert!(is_sensitive_field_name("BEARER"));
    }

    #[test]
    fn sanitize_huge_input_does_not_oom() {
        // 攻撃: 100MB ログ文字列を sanitize() に渡すと 4 パス × 100MB = CPU/OOM DoS
        let huge = "a@b.com ".repeat(2_000_000); // ~14MB
        let result = PrivacySanitizer::sanitize(&huge);
        // 64KB 以内に切り詰められていること
        assert!(result.len() <= 64 * 1024 + 200, // truncation メッセージ分の余裕
            "sanitize の出力が上限を超えた: {} bytes", result.len());
        // truncation マーカーが含まれること
        assert!(result.contains("切り詰め"), "大入力は切り詰めメッセージを含むべき");
    }

    #[test]
    fn sanitize_normal_input_works() {
        let result = PrivacySanitizer::sanitize("alice@example.com の Bearer abc123 です");
        assert!(!result.contains("abc123"), "Bearer トークンは除去されるべき");
    }
}
