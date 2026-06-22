// crates/kaname-render/src/html_smuggling.rs
//
// HTML スマグリング検出器
//
// 2026 年急増中: HTML ファイル内に JavaScript を隠蔽し、
// ブラウザ内でデコード・実行して悪意あるペイロードを届ける攻撃。
//
// # 攻撃の仕組み
//
// ```text
// 攻撃者がメール添付で .html ファイルを送信
//   ↓
// ファイル内に Base64 エンコードされた実行可能ファイルを埋め込み
//   ↓
// ブラウザが開いた瞬間に atob() でデコード
//   ↓
// blob: URI を生成して <a> タグで自動ダウンロード
//   ↓
// ユーザーが気づかないうちに exe/ps1/bat が保存される
// ```
//
// # 検出アプローチ
//
// HTML 添付ファイルを開く前に、パターン解析でリスクを判定。
// Firecracker microVM 内での開封を推奨するバナーを表示。

use serde::{Deserialize, Serialize};

/// 検出されたシグナルの種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmugglingSignal {
    /// blob: URI の生成 — ダウンロードに使われる
    BlobUri,
    /// atob() + eval() — Base64 デコード後に即実行
    Base64Eval,
    /// createElement("a") + click() — 自動ダウンロード
    AutoDownload,
    /// 偽 CAPTCHA ページ — ユーザーを安心させる欺瞞
    FakeCaptcha,
    /// mshta / PowerShell / cmd 参照 — 実行コマンド埋め込み
    ShellReference,
    /// JavaScript を複数層で難読化
    MultiLayerObfuscation,
    /// データ URI に実行ファイルを埋め込み
    DataUriExecutable,
}

/// HTML スマグリングスキャン結果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmugglingScan {
    /// 検出されたシグナル
    pub signals: Vec<SmugglingSignal>,
    /// リスクレベル
    pub risk: SmugglingRisk,
    /// UI 表示用メッセージ
    pub message: String,
}

/// リスクレベル。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmugglingRisk {
    /// 問題なし
    Clean,
    /// 念のために確認推奨
    Caution,
    /// 高リスク — サンドボックスで開くことを推奨
    High,
    /// 非常に危険 — ブロック推奨
    Critical,
}

/// HTML スマグリング検出器。
pub struct HtmlSmugglingDetector;

impl HtmlSmugglingDetector {
    /// HTML 文字列を解析してスマグリングのシグナルを検出する。
    ///
    /// 入力サイズを 4 MB に制限する (to_lowercase() が全体を複製するため
    /// 100 MB 入力で 200 MB 確保される OOM DoS を防ぐ)。
    #[must_use]
    pub fn analyze(&self, html: &str) -> SmugglingScan {
        const MAX_HTML_BYTES: usize = 4 * 1024 * 1024;
        let html = if html.len() > MAX_HTML_BYTES {
            &html[..MAX_HTML_BYTES]
        } else {
            html
        };
        let lower = html.to_lowercase();
        let mut signals = Vec::new();

        // 1. Blob URI 生成 (最重要シグナル)
        if lower.contains("url.createobjecturl") || lower.contains("blob:") {
            signals.push(SmugglingSignal::BlobUri);
        }

        // 2. Base64 デコード (+ 即時実行や blob 結合も含む)
        // atob() に加え TextDecoder/Uint8Array ベースの現代的なデコードパターンも検出
        let b64_patterns = [
            "atob(",
            "frombase64",   // CryptoJS.enc.Base64.parse, Buffer.from(x,'base64') など
            "textdecoder",  // new TextDecoder().decode(Uint8Array.from(...))
            "uint8array.from",
        ];
        if b64_patterns.iter().any(|p| lower.contains(p)) {
            signals.push(SmugglingSignal::Base64Eval);
        }

        // 3. 自動ダウンロードトリガー
        // ダブル/シングルクォート/バックティックすべてを対象にする
        // 旧実装: "a" のみ → 'a' やバックティックでバイパス可能だった
        let has_create_a = lower.contains("createelement(\"a\")")
            || lower.contains("createelement('a')")
            || lower.contains("createelement(`a`)");
        // `.click()` の空白・改行バイパス対策: 空白を除去した文字列でも検出
        let lower_no_ws: String = lower.chars().filter(|c| !c.is_whitespace()).collect();
        if has_create_a && (lower_no_ws.contains(".click()")) {
            signals.push(SmugglingSignal::AutoDownload);
        }

        // 4. 偽 CAPTCHA (ユーザーを油断させる)
        let captcha_phrases = [
            "verify you are human",
            "i am not a robot",
            "click the box",
            "captcha",
            "ロボットではありません",
            "人間であることを確認",
        ];
        if captcha_phrases.iter().any(|p| lower.contains(p)) {
            signals.push(SmugglingSignal::FakeCaptcha);
        }

        // 5. Shell 参照 (mshta.exe, PowerShell, cmd.exe)
        let shell_refs = ["mshta", "powershell", "cmd.exe", "wscript", "cscript"];
        if shell_refs.iter().any(|r| lower.contains(r)) {
            signals.push(SmugglingSignal::ShellReference);
        }

        // 6. 多重難読化 (unescape + decodeURIComponent + eval の組み合わせ)
        let obfus_count = [
            "unescape(",
            "decodeuricomponent(",
            "string.fromcharcode(",
            "charcodeat(",
            r"\x",
            r"\u00",
        ]
        .iter()
        .filter(|p| lower.contains(*p))
        .count();

        if obfus_count >= 2 {
            signals.push(SmugglingSignal::MultiLayerObfuscation);
        }

        // 7. data: URI に実行ファイルを埋め込み
        let executable_types = [
            "data:application/x-msdownload",
            "data:application/octet-stream",
            "data:application/x-executable",
            "data:application/bat",
        ];
        if executable_types.iter().any(|t| lower.contains(t)) {
            signals.push(SmugglingSignal::DataUriExecutable);
        }

        let risk = Self::calculate_risk(&signals);
        let message = Self::build_message(&signals, risk);

        SmugglingScan { signals, risk, message }
    }

    fn calculate_risk(signals: &[SmugglingSignal]) -> SmugglingRisk {
        if signals.is_empty() {
            return SmugglingRisk::Clean;
        }

        // 致命的な組み合わせ
        let has_blob = signals.contains(&SmugglingSignal::BlobUri);
        let has_download = signals.contains(&SmugglingSignal::AutoDownload);
        let has_shell = signals.contains(&SmugglingSignal::ShellReference);
        let has_exe_uri = signals.contains(&SmugglingSignal::DataUriExecutable);

        if (has_blob && has_download) || has_shell || has_exe_uri {
            return SmugglingRisk::Critical;
        }

        if has_blob || signals.contains(&SmugglingSignal::Base64Eval) {
            return SmugglingRisk::High;
        }

        if signals.len() >= 2 {
            return SmugglingRisk::High;
        }

        SmugglingRisk::Caution
    }

    fn build_message(signals: &[SmugglingSignal], risk: SmugglingRisk) -> String {
        match risk {
            SmugglingRisk::Clean => "HTML 添付は安全です。".into(),
            SmugglingRisk::Caution => format!(
                "HTML 添付に注意すべきコードが含まれています ({} シグナル)。サンドボックスで開くことを推奨します。",
                signals.len()
            ),
            SmugglingRisk::High => format!(
                "HTML スマグリングの疑い ({} シグナル検出)。ブラウザで直接開かないでください。",
                signals.len()
            ),
            SmugglingRisk::Critical => format!(
                "HTML スマグリング攻撃を検出 ({} シグナル)。この添付は悪意ある実行ファイルを配布しようとしています。ブロック推奨。",
                signals.len()
            ),
        }
    }
}

impl Default for HtmlSmugglingDetector {
    fn default() -> Self {
        Self
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> HtmlSmugglingDetector { HtmlSmugglingDetector }

    #[test]
    fn clean_html_no_signals() {
        let d = detector();
        let html = "<html><body><p>Hello, world!</p></body></html>";
        let s = d.analyze(html);
        assert_eq!(s.risk, SmugglingRisk::Clean);
        assert!(s.signals.is_empty());
    }

    #[test]
    fn detects_blob_uri() {
        let d = detector();
        let html = r#"<script>var u = URL.createObjectURL(blob);</script>"#;
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::BlobUri));
    }

    #[test]
    fn detects_base64_eval() {
        let d = detector();
        let html = "<script>eval(atob('aGVsbG8='));</script>";
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::Base64Eval));
    }

    #[test]
    fn detects_auto_download() {
        let d = detector();
        let html = r#"<script>
            var a = document.createElement("a");
            a.href = blobUrl;
            a.click();
        </script>"#;
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::AutoDownload));
    }

    #[test]
    fn detects_fake_captcha() {
        let d = detector();
        let html = "<div>Verify you are human before continuing</div>";
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::FakeCaptcha));
    }

    #[test]
    fn detects_fake_captcha_japanese() {
        let d = detector();
        let html = "<div>ロボットではありません</div>";
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::FakeCaptcha));
    }

    #[test]
    fn detects_shell_reference() {
        let d = detector();
        let html = r#"<script>var cmd = "mshta vbscript:execute";</script>"#;
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::ShellReference));
        assert_eq!(s.risk, SmugglingRisk::Critical);
    }

    #[test]
    fn detects_multi_layer_obfuscation() {
        let d = detector();
        let html = r#"<script>
            eval(unescape(decodeURIComponent('%60')));
            var x = "\x41\x42";
        </script>"#;
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::MultiLayerObfuscation));
    }

    #[test]
    fn detects_executable_data_uri() {
        let d = detector();
        let html = r#"<a href="data:application/x-msdownload;base64,TVqQ">download</a>"#;
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::DataUriExecutable));
        assert_eq!(s.risk, SmugglingRisk::Critical);
    }

    #[test]
    fn full_attack_chain_is_critical() {
        let d = detector();
        // 典型的な HTML スマグリング攻撃チェーン
        let html = r#"<script>
            var b64 = "TVqQAAMAAAAEAAAA//8AALg..."; // MZ ヘッダー (exe)
            var bytes = atob(b64);
            var blob = new Blob([bytes], {type: 'application/octet-stream'});
            var url = URL.createObjectURL(blob);
            var a = document.createElement("a");
            a.href = url;
            a.download = "update.exe";
            a.click();
        </script>"#;
        let s = d.analyze(html);
        assert_eq!(s.risk, SmugglingRisk::Critical);
        assert!(s.signals.len() >= 3);
    }

    #[test]
    fn risk_calculation_caution_single_signal() {
        let d = detector();
        // 偽 CAPTCHA のみ
        let html = "<p>Click the box to verify you are human</p>";
        let s = d.analyze(html);
        assert_eq!(s.risk, SmugglingRisk::Caution);
    }

    #[test]
    fn message_is_not_empty() {
        let d = detector();
        let cases = [
            "<html><body>safe</body></html>",
            "<script>URL.createObjectURL(b)</script>",
            "<script>mshta vbscript:close</script>",
        ];
        for html in &cases {
            let s = d.analyze(html);
            assert!(!s.message.is_empty(), "message が空: {html}");
        }
    }

    // ── シングルクォート/バックティックによる AutoDownload バイパステスト ─

    #[test]
    fn detects_auto_download_single_quote() {
        let d = detector();
        // シングルクォートで createElement をバイパスしようとする
        let html = r#"<script>
            var a = document.createElement('a');
            a.href = blobUrl;
            a.click();
        </script>"#;
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::AutoDownload),
            "シングルクォートの createElement('a') は検出されなければならない");
    }

    #[test]
    fn detects_auto_download_backtick() {
        let d = detector();
        // バックティックで createElement をバイパスしようとする
        let html = "<script>var a = document.createElement(`a`); a.click();</script>";
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::AutoDownload),
            "バックティックの createElement(`a`) は検出されなければならない");
    }

    // ── TextDecoder/Uint8Array パターンの検出テスト ─────────────────────────

    #[test]
    fn detects_textdecoder_pattern() {
        let d = detector();
        // atob() の代わりに TextDecoder を使った現代的なデコードパターン
        let html = r#"<script>
            var dec = new TextDecoder();
            var bytes = Uint8Array.from(encoded, c => c.charCodeAt(0));
            var exe = dec.decode(bytes);
        </script>"#;
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::Base64Eval),
            "TextDecoder パターンは Base64Eval シグナルを生成すべき");
    }

    // ── 入力サイズ制限テスト ──────────────────────────────────────────────

    #[test]
    fn analyze_サイズ超過入力でパニックしない() {
        let d = detector();
        // 4MB を超える入力 (OOM DoS の試み)
        let huge = "a".repeat(5 * 1024 * 1024);
        // パニックせず、正常な SmugglingScan を返すこと
        let s = d.analyze(&huge);
        assert_eq!(s.risk, SmugglingRisk::Clean, "通常文字の大量入力は Clean");
    }

    #[test]
    fn analyze_サイズ上限で悪意あるパターンを切り捨てる() {
        let d = detector();
        // 4MB の無害なパディング + 末尾に mshta
        let padding = "x".repeat(4 * 1024 * 1024);
        let attack = format!("{padding}mshta");
        let s = d.analyze(&attack);
        // 上限で切り捨てられるため mshta は検出されない (上限以内に収まらない)
        // これは設計上の制約: 超長 HTML は4MB以内のみ検査
        assert_eq!(s.risk, SmugglingRisk::Clean,
            "4MB 超の末尾に埋め込まれた攻撃は切り捨てられる (設計上の制約)");
    }

    // ── .click() 空白バイパステスト ──────────────────────────────────────────

    #[test]
    fn detects_auto_download_click_with_newline() {
        let d = detector();
        let html = "<script>var a = document.createElement(\"a\"); a\n.click\n();</script>";
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::AutoDownload),
            "改行入り .click() は検出されなければならない");
    }

    #[test]
    fn detects_auto_download_click_with_tab() {
        let d = detector();
        let html = "<script>var a = document.createElement(\"a\"); a.click\t();</script>";
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::AutoDownload),
            "タブ入り .click() は検出されなければならない");
    }
}
