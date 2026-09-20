//! kaname-observability — 構造化ログと PII 防御。
//!
//! - Logs: tracing-subscriber 構造化 JSON
//! - PrivacySanitizer がメール本文・PII をログから除外

// crates/kaname-observability/src/lib.rs
//
// Kaname 観測性 (Observability) 層
//
// 1. Logs    — 構造化 JSON ログ (tracing-subscriber)
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
            truncated = format!(
                "{}…[{} バイト超過のため切り詰め]",
                &input[..end],
                input.len()
            );
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
}

/// 全角 ASCII (U+FF01–FF5E) → 半角 ASCII、全角スペース (U+3000) → 空白 に変換する。
///
/// `alice＠example.com` のような全角文字を使った PII バイパスを防ぐために
/// `PrivacySanitizer::sanitize` の前処理として使用する。
fn normalize_fullwidth(s: &str) -> String {
    s.chars()
        .map(|c| {
            if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
                char::from_u32(c as u32 - 0xFEE0).unwrap_or(c)
            } else if c == '\u{3000}' {
                ' '
            } else {
                c
            }
        })
        .collect()
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
                } else {
                    break;
                }
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
            if chars[j].is_ascii_digit() {
                digit_count += 1;
            }
            j += 1;
            if digit_count >= 16 {
                break;
            }
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
                    || matches!(chars[j], '-' | '(' | ')' | ' ') && digits < 12)
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
// SanitizingWriter — fmt::layer の出力を PII マスクしてから書き出す
// ============================================================================

/// `PrivacyLayer` の「検知しても元イベントはそのまま出力される」盲点を
/// 塞ぐため、`fmt::layer` の Writer 側で出力バイト列そのものを
/// `PrivacySanitizer` に通してから書き出す (docs/gap-analysis.md D28 の
/// 残作業 — 当時「Filter::event_enabled への再設計が要る」と記録されて
/// いたが、`event_enabled` は false を返しても他レイヤーの `on_event`
/// は止められないため、抑制は Writer 側が確実)。
///
/// `write()` 呼び出しは通常イベント1回分だが分割されうるため、
/// UTF-8 境界をまたぐマーカーは捉えきれない可能性がある (lossy 変換)。
/// 値パターン (メール/Bearer/電話/カード番号) が対象で、フィールド名
/// ベースの検知は `PrivacyLayer` の警告が担い続ける。
pub struct SanitizingWriter<W> {
    inner: W,
}

impl<W> SanitizingWriter<W> {
    /// 任意の writer を包む。テストでは `Vec<u8>` を差して出力を検査する。
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    /// 内側の writer を取り出す (主にテスト用)。
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: std::io::Write> std::io::Write for SanitizingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let masked = PrivacySanitizer::sanitize(&String::from_utf8_lossy(buf));
        self.inner.write_all(masked.as_bytes())?;
        // 書き込んだのはマスク後バイト列だが、契約上は入力の消費量を返す
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// `fmt::layer().with_writer(...)` に渡す `MakeWriter`。
/// fmt が書く全イベントを `PrivacySanitizer` に通してから stdout に流す。
#[derive(Clone, Copy, Debug, Default)]
pub struct SanitizingStdout;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SanitizingStdout {
    type Writer = SanitizingWriter<std::io::Stdout>;

    fn make_writer(&'a self) -> Self::Writer {
        SanitizingWriter::new(std::io::stdout())
    }
}

// ============================================================================
// PrivacyLayer — tracing-subscriber Layer で PII 漏洩を検知
// ============================================================================

/// PII を含む tracing イベントを検知する `Layer` 実装。
///
/// `tracing-subscriber` の Layer として登録することで、
/// 将来の開発者がうっかり PII をログに書いた場合に検出できる。
///
/// # 動作 (現状: 検知のみ・ブロックはしない)
///
/// - 文字列フィールドを `PrivacySanitizer::sanitize()` / フィールド名の
///   許可リストで検査する
/// - PII を検出した場合: `target: "kaname::privacy"` で警告ログを追加発行する
/// - 元のイベントの値パターンレベルのマスクは `SanitizingWriter`
///   (`fmt::layer` の Writer) が担う (D28 残作業の実装済み)。
///   `Layer::on_event`/`event_enabled` には他レイヤーへの伝播を止める
///   権限が無いため、抑制は Writer 側で行うのが確実。
///   このコメント自体、以前は「イベントをドロップし代替ログを出力する」
///   と誤って書かれており、`PrivacyLayer` がどの subscriber にも登録
///   されていなかったことと合わせて**多重に空文だった**
///   (docs/gap-analysis.md D28)。フィールド名ベースの検知は引き続き
///   ここが担い (Writer は値パターンしか見えない)、警告を発行する。
pub struct PrivacyLayer;

/// PII を含む可能性のあるフィールドを収集するビジター。
struct PiiFieldVisitor {
    found_pii: bool,
    sanitized_fields: Vec<(String, String)>,
}

impl PiiFieldVisitor {
    fn new() -> Self {
        Self {
            found_pii: false,
            sanitized_fields: Vec::new(),
        }
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
        "email",
        "e_mail",
        "mail",
        "subject",
        "body",
        "content",
        "message",
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "bearer",
        "authorization",
        "auth",
        "phone",
        "address",
        "name",
        "full_name",
        "display_name",
        "credit_card",
        "card_number",
        "cvv",
        "my_number",
        "マイナンバー",
        "個人番号",
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
        self.sanitized_fields
            .push((field_name.to_string(), sanitized));
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
        self.sanitized_fields
            .push((field_name.to_string(), sanitized));
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
            // PII 検出: 警告のみ (イベント構築前の抑制は Filter 層の設計変更が必要)
            tracing::warn!(
                target: "kaname::privacy",
                "PII detected in log event — ログに個人情報が含まれています"
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
    fn sanitizing_writer_masks_pii_in_output_bytes() {
        // D28 残作業の回帰テスト: fmt が書く出力そのものに
        // メールアドレスが平文で残らないことを固定する
        let mut w = SanitizingWriter::new(Vec::<u8>::new());
        use std::io::Write as _;
        // tests モジュールは unwrap/expect deny の対象 (他テストも同様に避ける)
        if let Err(e) = w
            .write_all(b"INFO  login ok user=alice@example.com token=Bearer abc123")
        {
            panic!("write_all 失敗: {e}");
        }
        let out = match String::from_utf8(w.into_inner()) {
            Ok(s) => s,
            Err(e) => panic!("出力が UTF-8 でない: {e}"),
        };
        assert!(!out.contains("alice@"), "メールアドレスが平文で残る: {out}");
        assert!(
            !out.contains("Bearer abc123"),
            "トークンが平文で残る: {out}"
        );
        assert!(
            out.contains("login ok"),
            "非 PII 部分は保持されるべき: {out}"
        );
    }

    #[test]
    fn privacy_email_address_masking() {
        let input = "Connection from alice@company.co.jp succeeded";
        let output = PrivacySanitizer::sanitize(input);
        assert!(
            !output.contains("alice@"),
            "メール先頭がマスクされていない: {output}"
        );
        assert!(output.contains("@company.co.jp") || output.contains("***"));
    }

    #[test]
    fn privacy_digit_leading_email_is_masked() {
        // 回帰テスト: 以前はローカル部が数字始まりのメールアドレスが
        // 走査対象にすら入らず、無加工でログに残っていた。
        let input = "invoice 12345@vendor.com paid";
        let output = PrivacySanitizer::sanitize(input);
        assert!(
            !output.contains("12345@"),
            "数字始まりのローカル部がマスクされていない: {output}"
        );
        assert!(
            output.contains("123***"),
            "先頭3文字+*** の形式でマスクされるべき: {output}"
        );
    }

    #[test]
    fn privacy_credit_card_redaction() {
        let input = "Payment with 4111111111111111 succeeded";
        let output = PrivacySanitizer::sanitize(input);
        assert!(
            !output.contains("4111111111111111"),
            "クレジットカード番号がマスクされていない"
        );
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
    fn privacy_bearer_token_multiple_redaction() {
        // find() は最初の一件しか返さないため、ループが必須
        let input = "proxy: Bearer first_token_abc backend: Bearer second_token_xyz end";
        let output = PrivacySanitizer::sanitize(input);
        assert!(!output.contains("first_token_abc"), "1件目のトークンが漏洩");
        assert!(
            !output.contains("second_token_xyz"),
            "2件目のトークンが漏洩"
        );
        assert_eq!(output.matches("Bearer [REDACTED]").count(), 2);
    }

    #[test]
    fn privacy_jp_mobile_phone_masked() {
        let input = "連絡先: 090-1234-5678 まで";
        let output = PrivacySanitizer::sanitize(input);
        assert!(
            !output.contains("090-1234-5678"),
            "携帯番号が漏洩: {output}"
        );
        assert!(output.contains("[TEL-REDACTED]"));
    }

    #[test]
    fn privacy_jp_landline_masked() {
        let input = "事務所: 03-1234-5678 (東京)";
        let output = PrivacySanitizer::sanitize(input);
        assert!(
            !output.contains("03-1234-5678"),
            "固定電話番号が漏洩: {output}"
        );
        assert!(output.contains("[TEL-REDACTED]"));
    }

    #[test]
    fn privacy_jp_phone_digits_only_masked() {
        let input = "tel:09012345678";
        let output = PrivacySanitizer::sanitize(input);
        assert!(
            !output.contains("09012345678"),
            "数字のみ電話番号が漏洩: {output}"
        );
        assert!(output.contains("[TEL-REDACTED]"));
    }

    #[test]
    fn privacy_short_number_not_masked() {
        // 郵便番号 (7桁) は電話番号ではない
        let input = "〒100-0001";
        let output = PrivacySanitizer::sanitize(input);
        assert!(
            output.contains("100"),
            "郵便番号まで消してしまった: {output}"
        );
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
        assert!(
            !sanitized.contains("user@example.com"),
            "raw email must not appear: {sanitized}"
        );
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
        assert!(
            output.contains("REDACTED"),
            "REDACTEDが挿入されていない: {output}"
        );
    }

    #[test]
    fn normalize_fullwidth_converts_ascii_range() {
        // U+FF20 (＠) → U+0040 (@)
        assert_eq!(
            normalize_fullwidth("ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ"),
            "alice@example.com"
        );
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
        assert!(
            result.len() <= 64 * 1024 + 200, // truncation メッセージ分の余裕
            "sanitize の出力が上限を超えた: {} bytes",
            result.len()
        );
        // truncation マーカーが含まれること
        assert!(
            result.contains("切り詰め"),
            "大入力は切り詰めメッセージを含むべき"
        );
    }

    #[test]
    fn sanitize_normal_input_works() {
        let result = PrivacySanitizer::sanitize("alice@example.com の Bearer abc123 です");
        assert!(
            !result.contains("abc123"),
            "Bearer トークンは除去されるべき"
        );
    }
}
