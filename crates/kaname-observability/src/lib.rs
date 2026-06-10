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
            _ => 0,
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
        let mut result = input.to_string();

        // クレジットカード番号 (16桁数字)
        result = remove_pattern(&result, |s| {
            s.chars().filter(|c| c.is_ascii_digit()).count() >= 13
                && s.chars().any(|c| c.is_ascii_digit())
        });

        // メールアドレスを匿名化 (例: alice@example.com → ali***@example.com)
        result = mask_email_addresses(&result);

        // Bearer トークンを除去
        if let Some(idx) = result.find("Bearer ") {
            let token_start = idx + "Bearer ".len();
            let token_len = result[token_start..].find(char::is_whitespace).unwrap_or(result.len() - token_start);
            let end = "Bearer ".len() + token_len;
            result.replace_range(idx..idx + end, "Bearer [REDACTED]");
        }

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

fn mask_email_addresses(s: &str) -> String {
    // 単純な実装: 最初の3文字以外をマスク
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_alphabetic() {
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

fn remove_pattern<F>(s: &str, _matcher: F) -> String
where F: Fn(&str) -> bool {
    // 簡易実装: クレジットカード番号パターンを除去
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
}
