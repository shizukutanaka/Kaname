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
    /// クリップボードへの書き込み — ClickFix/FileFix でコマンドをコピーさせる (D785)
    ClipboardWrite,
    /// 「Win+R」「貼り付け」「エクスプローラのアドレスバー」等の実行誘導文言 (D785)
    RunDialogLure,
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
    ///
    /// `MAX_HTML_BYTES` は生のバイトオフセットであり、日本語等のマルチバイト
    /// 文字の途中を指す可能性がある。`&html[..MAX_HTML_BYTES]` のように文字境界を
    /// 無視してスライスすると "byte index is not a char boundary" で **パニックする**
    /// (docs/gap-analysis.md D50)。DoS 対策自身が日本語 CJK 入力でクラッシュしては
    /// 本末転倒なため、直近の文字境界まで後退させてから切り詰める。
    #[must_use]
    pub fn analyze(&self, html: &str) -> SmugglingScan {
        const MAX_HTML_BYTES: usize = 4 * 1024 * 1024;
        let html = if html.len() > MAX_HTML_BYTES {
            let mut boundary = MAX_HTML_BYTES;
            while boundary > 0 && !html.is_char_boundary(boundary) {
                boundary -= 1;
            }
            &html[..boundary]
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
            "frombase64",  // CryptoJS.enc.Base64.parse, Buffer.from(x,'base64') など
            "textdecoder", // new TextDecoder().decode(Uint8Array.from(...))
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

        // 8. クリップボードへの書き込み (D785 — ClickFix/FileFix)
        // 2025 年の ClickFix キャンペーン (Microsoft Threat Intelligence 2025-08,
        // Storm-1607/DarkGate 等) と FileFix (Check Point 2025-07) は、
        // navigator.clipboard.writeText / execCommand('copy') で被害者の
        // クリップボードにコマンドを書き込み、偽の検証画面を通して
        // Win+R 実行や Explorer アドレスバーへの貼り付けを誘導する。
        // 本文ではなく添付 .html が主経路のため、scan_attachment_bytes 側にも
        // 同じ検出器を配線する。
        let clipboard_patterns = [
            "navigator.clipboard.write", // writeText も部分一致で捕捉
            "clipboarddata.setdata",     // IE 系 clipboardData オブジェクト
            "execcommand(\"copy\")",
            "execcommand('copy')",
            "execcommand(`copy`)",
        ];
        if clipboard_patterns.iter().any(|p| lower.contains(p)) {
            signals.push(SmugglingSignal::ClipboardWrite);
        }

        // 9. 実行ダイアログ/貼り付け誘導の文言 (D785 — ClickFix/FileFix)
        // コマンド文字列 (powershell 等) を書かず、被害者に「検証・修復」を
        // 装って実行手順を踏ませるのが ClickFix の本質。単独ヒットは正規の
        // 操作説明ページでもあり得るため Caution どまりだが、ClipboardWrite
        // や FakeCaptcha との複合で Critical になる (calculate_risk 参照)。
        let run_lure_phrases = [
            // Windows 実行ダイアログ誘導 (ClickFix 定番)
            "win+r", "win + r", "windows+r", "windows + r",
            "windows key", "press the windows", "run dialog", "open run",
            "ファイル名を指定して実行", "コマンドプロンプトを開", "ターミナルを開",
            // Explorer アドレスバーへの貼り付け誘導 (FileFix 定番)
            "address bar", "アドレスバー", "エクスプローラー",
            // コピー→貼り付けの実行手順
            "ctrl+v", "ctrl + v", "press ctrl", "paste into", "paste it in",
            "paste the copied", "copy-paste", "貼り付け",
            // 「検証・修復」を装う定型フレーズ
            "to verify", "verify yourself", "prove you are human",
            "fix this problem", "complete the verification",
        ];
        if run_lure_phrases.iter().any(|p| lower.contains(p)) {
            signals.push(SmugglingSignal::RunDialogLure);
        }

        let risk = Self::calculate_risk(&signals);
        let message = Self::build_message(&signals, risk);

        SmugglingScan {
            signals,
            risk,
            message,
        }
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
        let has_clip = signals.contains(&SmugglingSignal::ClipboardWrite);
        let has_lure = signals.contains(&SmugglingSignal::RunDialogLure);
        let has_captcha = signals.contains(&SmugglingSignal::FakeCaptcha);

        if (has_blob && has_download) || has_shell || has_exe_uri {
            return SmugglingRisk::Critical;
        }

        // ClickFix/FileFix の鎖 (D785):
        //   コマンドをクリップボードに書き込む + 実行手順を指示する
        //   (powershell 等の ShellReference を書かず Shell 検出を避ける型) か、
        //   偽 CAPTCHA + 実行手順の組み合わせは人を介してコマンド実行させる
        //   本体なので Critical。ClipboardWrite や誘導文言の単独ヒットは
        //   正規の「コードをコピー」UI でもあり得るため Caution に留める。
        if (has_clip && has_lure) || (has_lure && has_captcha) {
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
            SmugglingRisk::Critical
                if signals.contains(&SmugglingSignal::ClipboardWrite)
                    && signals.contains(&SmugglingSignal::RunDialogLure) =>
            {
                format!(
                    "ClickFix 型のソーシャルエンジニアリングを検出 ({} シグナル)。偽の検証・修復手順でクリップボードにコマンドを書き込み、実行ダイアログ等への貼り付けを誘導します。指示に従わないでください。",
                    signals.len()
                )
            }
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

    fn detector() -> HtmlSmugglingDetector {
        HtmlSmugglingDetector
    }

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
        // 偽 CAPTCHA のみ — "to verify" を含むと D785 の
        // RunDialogLure にも引っかかり captcha+lure → Critical になるため、
        // 誘導句を含まない文言で単一シグナルであることを固定する。
        let html = "<p>verify you are human</p>";
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
        assert!(
            s.signals.contains(&SmugglingSignal::AutoDownload),
            "シングルクォートの createElement('a') は検出されなければならない"
        );
    }

    #[test]
    fn detects_auto_download_backtick() {
        let d = detector();
        // バックティックで createElement をバイパスしようとする
        let html = "<script>var a = document.createElement(`a`); a.click();</script>";
        let s = d.analyze(html);
        assert!(
            s.signals.contains(&SmugglingSignal::AutoDownload),
            "バックティックの createElement(`a`) は検出されなければならない"
        );
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
        assert!(
            s.signals.contains(&SmugglingSignal::Base64Eval),
            "TextDecoder パターンは Base64Eval シグナルを生成すべき"
        );
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
        assert_eq!(
            s.risk,
            SmugglingRisk::Clean,
            "4MB 超の末尾に埋め込まれた攻撃は切り捨てられる (設計上の制約)"
        );
    }

    #[test]
    fn analyze_サイズ上限がマルチバイト文字境界をまたいでもパニックしない() {
        let d = detector();
        // 4MB ちょうどの境界に日本語 (3バイト UTF-8) を配置し、切り捨て位置が
        // 文字の途中に落ちるようにする (D50: 修正前は "byte index is not a
        // char boundary" でパニックしていた)。
        const MAX_HTML_BYTES: usize = 4 * 1024 * 1024;
        let mut html = "a".repeat(MAX_HTML_BYTES - 1);
        html.push('あ'); // 3バイト文字がちょうど境界をまたぐ
        html.push_str(&"b".repeat(1024));
        let s = d.analyze(&html);
        assert_eq!(s.risk, SmugglingRisk::Clean);
    }

    // ── .click() 空白バイパステスト ──────────────────────────────────────────

    #[test]
    fn detects_auto_download_click_with_newline() {
        let d = detector();
        let html = "<script>var a = document.createElement(\"a\"); a\n.click\n();</script>";
        let s = d.analyze(html);
        assert!(
            s.signals.contains(&SmugglingSignal::AutoDownload),
            "改行入り .click() は検出されなければならない"
        );
    }

    #[test]
    fn detects_auto_download_click_with_tab() {
        let d = detector();
        let html = "<script>var a = document.createElement(\"a\"); a.click\t();</script>";
        let s = d.analyze(html);
        assert!(
            s.signals.contains(&SmugglingSignal::AutoDownload),
            "タブ入り .click() は検出されなければならない"
        );
    }

    // ── D785: ClickFix / FileFix (クリップボード書込み + 実行誘導) ─────────

    #[test]
    fn detects_clipboard_write() {
        let d = detector();
        let html = r#"<script>navigator.clipboard.writeText("cmd /c calc");</script>"#;
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::ClipboardWrite));
    }

    #[test]
    fn detects_legacy_execcommand_copy() {
        let d = detector();
        // 偽 CAPTCHA 系 ClickFix で使われるレガシー API
        let html = "<script>document.execCommand('copy');</script>";
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::ClipboardWrite));
    }

    #[test]
    fn detects_run_dialog_lure() {
        let d = detector();
        let html = "<div>Press Win+R, paste the text and hit Enter</div>";
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::RunDialogLure));
    }

    #[test]
    fn detects_filefix_explorer_lure() {
        let d = detector();
        // FileFix (Check Point 2025-07): Explorer のアドレスバーへの貼り付け誘導
        let html = "<div>エクスプローラーのアドレスバーに貼り付けてください</div>";
        let s = d.analyze(html);
        assert!(s.signals.contains(&SmugglingSignal::RunDialogLure));
    }

    #[test]
    fn clickfix_full_chain_is_critical() {
        let d = detector();
        // ShellReference を書かず検出を避ける実際の ClickFix ページの構造:
        // 偽 CAPTCHA → clipboard.writeText(cmd) → Win+R 貼り付け指示
        let html = r#"<html><body>
            <div>Verify you are human</div>
            <script>
                navigator.clipboard.writeText("cmd /c start payload");
            </script>
            <p>1. Press Win+R</p>
            <p>2. Press Ctrl+V</p>
            <p>3. Press Enter</p>
        </body></html>"#;
        let s = d.analyze(html);
        assert_eq!(s.risk, SmugglingRisk::Critical);
        assert!(s.signals.contains(&SmugglingSignal::ClipboardWrite));
        assert!(s.signals.contains(&SmugglingSignal::RunDialogLure));
        assert!(s.message.contains("ClickFix"));
    }

    #[test]
    fn captcha_plus_lure_is_critical_without_clipboard_api() {
        let d = detector();
        // クリップボード API を使わず「選択してコピーしてください」だけの亜種:
        // 偽 CAPTCHA と実行誘導の組み合わせは同じく人を介して実行させる本体
        let html = "<div>I am not a robot</div><p>Press Win+R and paste into the box</p>";
        let s = d.analyze(html);
        assert_eq!(s.risk, SmugglingRisk::Critical);
    }

    #[test]
    fn lone_clipboard_write_is_caution() {
        let d = detector();
        // 「クーポンコードをコピー」系の正規 UI — 実行誘導がなければ警告どまり
        let html = r#"<script>navigator.clipboard.writeText(code);</script>"#;
        let s = d.analyze(html);
        assert_eq!(s.risk, SmugglingRisk::Caution);
    }

    #[test]
    fn lone_run_lure_is_caution() {
        let d = detector();
        // 単なる手順説明 (クリップボード API なし・偽検証なし) は警告どまり
        let html = "<p>詳細はファイル名を指定して実行から確認してください</p>";
        let s = d.analyze(html);
        assert_eq!(s.risk, SmugglingRisk::Caution);
    }
}
