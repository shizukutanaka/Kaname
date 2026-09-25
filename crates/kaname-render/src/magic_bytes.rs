//! ファイルマジックバイト検証 (Qiita/Zenn Round5 P2)。
//!
//! 拡張子偽装攻撃 (`.pdf` に `MZ` ヘッダーを持つ PE など) を検出する。

/// 検出された MIME タイプと宣言された MIME タイプの不一致。
#[derive(Debug, PartialEq, Eq)]
pub struct MimeMismatch {
    /// Content-Type ヘッダーで宣言された MIME。
    pub declared: String,
    /// マジックバイトから検出された MIME。
    pub detected: &'static str,
}

impl std::fmt::Display for MimeMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MIME 不一致: 宣言={:?}, 検出={:?}",
            self.declared, self.detected
        )
    }
}

/// 先頭バイトからファイル種別を検出する。
///
/// 戻り値: MIME タイプ文字列、または検出不能な場合 `None`。
#[must_use]
pub fn detect_mime_from_magic(bytes: &[u8]) -> Option<&'static str> {
    // PE 実行ファイル (MZ ヘッダー)
    if bytes.starts_with(b"MZ") {
        return Some("application/x-dosexec");
    }
    // ELF 実行ファイル
    if bytes.starts_with(b"\x7FELF") {
        return Some("application/x-elf");
    }
    // PDF
    if bytes.starts_with(b"%PDF") {
        return Some("application/pdf");
    }
    // ZIP (DOCX/XLSX/PPTX も ZIP ベース)
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        return Some("application/zip");
    }
    // OLE2 複合ドキュメント (古い .doc/.xls)
    if bytes.starts_with(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
        return Some("application/x-ole-storage");
    }
    // PNG
    if bytes.starts_with(b"\x89PNG\r\n\x1A\n") {
        return Some("image/png");
    }
    // JPEG
    if bytes.starts_with(b"\xFF\xD8\xFF") {
        return Some("image/jpeg");
    }
    // GIF
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    // WebP
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    // シェルスクリプト (shebang)
    if bytes.starts_with(b"#!/") || bytes.starts_with(b"#!") {
        return Some("text/x-shellscript");
    }
    // Mach-O ファット (Apple Universal Binary)
    if bytes.starts_with(b"\xCA\xFE\xBA\xBE") {
        return Some("application/x-mach-binary");
    }
    // Mach-O 64-bit
    if bytes.starts_with(b"\xCF\xFA\xED\xFE") || bytes.starts_with(b"\xCE\xFA\xED\xFE") {
        return Some("application/x-mach-binary");
    }
    // 7-Zip
    if bytes.starts_with(b"7z\xBC\xAF\x27\x1C") {
        return Some("application/x-7z-compressed");
    }
    // RAR
    if bytes.starts_with(b"Rar!\x1A\x07") {
        return Some("application/x-rar-compressed");
    }
    // GZIP
    if bytes.starts_with(b"\x1F\x8B") {
        return Some("application/gzip");
    }
    // SVG (XMLベース — <svg で始まる or <?xml の後に svg)
    //
    // 走査窓は 8 KB。従来の 256 バイトでは、長い XML 宣言・DOCTYPE・コメントで
    // `<svg` を押し下げるだけで検出を回避でき、その結果
    // `check_mime_mismatch` が「SVG を image/png と偽装した添付」を見逃していた。
    // (`svg_guard::looks_like_svg` と同じ窓幅に揃えている。)
    //
    // デコードは `from_utf8_lossy` を使う。`from_utf8` では窓の末尾で
    // マルチバイト文字が切れた瞬間に**文字列全体が空**になり、SVG 判定が
    // 丸ごと失われるため (窓を広げるほどこの確率は上がる)。
    //
    // なお本判定は関数末尾にあり、PNG/JPEG/PDF/ZIP/PE/ELF 等は先行する
    // マジックバイト判定で既に return 済みのため、ここへ到達するのは
    // 既知のバイナリ形式に該当しないファイルのみ。
    {
        const SVG_SCAN_BYTES: usize = 8 * 1024;
        let head = &bytes[..bytes.len().min(SVG_SCAN_BYTES)];
        let lower = String::from_utf8_lossy(head).to_ascii_lowercase();
        if lower.contains("<svg") || (lower.contains("<?xml") && lower.contains("svg")) {
            return Some("image/svg+xml");
        }
    }
    None
}

/// Windows の危険な添付ファイル拡張子か判定する。
///
/// `.lnk` (Shell Link) や `.url` (Internet Shortcut) は任意コマンド実行に使われる。
/// マクロ有効の Office 形式 (`.docm`, `.xlsm`, `.pptm`) も高リスク。
///
/// D166: `.exe`/`.com`/`.jar` 等の直接実行ファイルと、`.iso`/`.img`/
/// `.vhd`/`.vhdx` コンテナ形式を追加。コンテナは 2023 年以降 Microsoft が
/// Office マクロの既定ブロック化を進めた代替として急増した配送経路で、
/// コンテナ内のファイルは Mark-of-the-Web を継承しないため添付を展開
/// すると警告が減る (MOTW bypass — Mandiant/Sekoia の Qbot・Pikabot・
/// AgentTesla 各解析で報告される代表的な回避ベクトル)。
#[must_use]
pub fn is_dangerous_windows_attachment(filename: &str) -> bool {
    let lower = filename.to_ascii_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    matches!(
        ext,
        "exe"   // PE 実行ファイル — 最も基本的な直接実行形式
        | "com"   // 実行ファイル (DOS/Windows)
        | "jar"   // Java アーカイブ — java -jar で実行可能
        | "lnk"   // Windows Shell Link — 任意コマンド実行
        | "url"   // Internet Shortcut — UNC/SMB 漏洩
        | "scf"   // Shell Command File — NTLM hash 漏洩
        | "scr"   // Screen Saver — 実行可能
        | "pif"   // Program Information File — 実行可能
        | "application" // ClickOnce application
        | "gadget"
        | "msp"   // Windows Installer Patch
        | "msi"   // Windows Installer
        | "cmd"   // Command Script
        | "bat"   // Batch Script
        | "ps1"   // PowerShell
        | "vbs"   // VBScript
        | "js"    // JScript
        | "jse"   // JScript Encoded
        | "vbe"   // VBScript Encoded
        | "wsf"   // Windows Script File
        | "wsh"   // Windows Script Host
        | "hta"   // HTML Application
        | "docm"  // Office マクロ有効 Word
        | "xlsm"  // Office マクロ有効 Excel
        | "pptm"  // Office マクロ有効 PowerPoint
        | "xls"   // 古い Excel (VBA 埋め込み可能)
        | "doc"   // 古い Word (VBA 埋め込み可能)
        // コンテナ/イメージ形式 — MOTW bypass の配送経路 (D166)
        | "iso"   // ISO イメージ — 中身に MOTW が継承されない
        | "img"   // ディスクイメージ — 同上
        | "vhd"   // 仮想ハードディスク — 同上
        | "vhdx" // 仮想ハードディスク — 同上
        // ── D1250: マクロ有効の派生形式と代替配送形式 ──
        // docm/xlsm/pptm だけを列挙すると、同じ VBA を載せられる
        // テンプレート/アドイン/バイナリ形式が全て素通りになる。
        // 「docm は危険・dotm は安全」という利用者の拡張子読み替えも
        // 攻撃者に利用される (Microsoft のマクロ既定ブロック対象には
        // これら全形式が含まれる)。
        | "dotm"  // Word マクロ有効テンプレート
        | "xltm"  // Excel マクロ有効テンプレート
        | "potm"  // PowerPoint マクロ有効テンプレート
        | "ppsm"  // PowerPoint マクロ有効スライドショー — 開くだけで開始
        | "sldm"  // マクロ有効スライド
        | "ppam"  // PowerPoint アドイン (VBA)
        | "xlam"  // Excel アドイン (VBA)
        | "xla"   // 旧 Excel アドイン (VBA)
        | "xll"   // Excel DLL アドイン — ネイティブコード実行
        | "xlm"   // Excel 4.0 マクロシート — 検出回避で多用 (Qakbot/TrickBot)
        | "xlsb"  // Excel バイナリブック — VBA 埋め込み可
        | "docb"  // Word バイナリ文書 — VBA 埋め込み可
        | "vsdm"  // Visio マクロ有効図面
        | "mpa"   // Access プロジェクト/アドイン
        | "accde" // Access 実行専用 DB — VBA 埋め込み可
        // OneNote — 2023 年の Qakbot/IcedID/AsyncRAT 各キャンペーンで
        // 主流化した配送形式。添付内画像をクリックさせて HTA/スクリプトを起動。
        | "one"   // OneNote セクション
        | "onepkg" // OneNote パッケージ
        // スクリプト/設定経由の実行・漏洩形式
        | "chm"   // コンパイル HTML ヘルプ — hh.exe 経由で ActiveX/スクリプト実行
        | "reg"   // レジストリ結合 — Run キー等の永続化を一撃で書き込む
        | "sct"   // Windows スクリプトコンポーネント — scrobj.dll 経由実行
        | "wsc"   // Windows スクリプトコンポーネント — 同上
        | "slk"   // SYLK — Excel にマクロを実行させる旧形式
        | "iqy"   // Web クエリ — 外部取得して Excel に読込
        | "website" // サイトショートカット — UNC/SMB 参照で NTLM hash 漏洩可
        | "library-ms" // ライブラリ — SearchConnector 悪用で NTLM 漏洩可
        | "search-ms"  // 検索コネクタ — WebDAV/SMB 参照で漏洩・誘導可
        | "settingcontent-ms" // 設定ファイル — SpecterOps 報告の実行経路
        | "theme" // Windows テーマ — リモート参照で NTLM hash 漏洩可
        | "mht"   // MHTML — MSHTML 悪用 (CVE-2021-40444 系) と埋込ペイロード
        | "mhtml" // MHTML — 同上
        | "cpl"   // コントロールパネル項目 — DLL として読み込み実行
        | "msc"   // MMC スナップイン — 任意コンソール/コマンド実行
        | "inf"   // セットアップ情報 — DefaultInstall でコマンド実行可
        | "diagcab" // 診断パッケージ — msdt 悪用 (Follina 系) の配送形式
        | "xbap"  // XAML ブラウザアプリ — ブラウザ内 .NET 実行
        | "appref-ms" // ClickOnce 参照 — リモートからの配置実行
    )
}

/// 添付が「メールの中に入ったメール」(`.eml`/`.msg`/`message/rfc822`) か判定する。
///
/// 外側の件名・差出人とは無関係な内容を内側で提示できるため、ゲートウェイ
/// が外側だけを検査する隙を突く代表的な回避経路として観測されている
/// (Cofense/Barracuda 2023-2025 — 添付された .eml/.msg を開かせて
/// 請求書詐欺・フィッシング・マルウェア添付を表示する型)。
/// 危険拡張子としては扱わず、注意喚起のみ (正規の転送添付は日常に存在する)。
#[must_use]
pub fn is_nested_email_attachment(filename: &str, declared_mime: &str) -> bool {
    let lower = filename.to_ascii_lowercase();
    lower.ends_with(".eml")
        || lower.ends_with(".msg")
        || declared_mime.eq_ignore_ascii_case("message/rfc822")
        || declared_mime.eq_ignore_ascii_case("application/vnd.ms-outlook")
}

/// ZIP ベースのファイルか判定する (拡張子またはマジックバイト)。
///
/// DOCX/XLSX 等も ZIP ベースだが、暗号化フラグ検査は形式を問わず意味を持つため
/// ここでは「ZIP コンテナか」だけを見る。
#[must_use]
pub fn is_zip_file(filename: &str, bytes: &[u8]) -> bool {
    filename.to_ascii_lowercase().ends_with(".zip")
        || bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
}

/// ZIP のローカルファイルヘッダを走査し、暗号化フラグ (一般目的ビット 0)
/// が立つエントリがあるか判定する。
///
/// Emotet/Qakbot 型の「パスワード付き ZIP + 本文にパスワード記載」は、
/// ゲートウェイが中身を解凍・検査できないことを利用した定番の回避手口
/// (Sublime Security `body_encrypted_zip_password_attachment` 等)。
///
/// ローカルファイルヘッダ構造:
///   +0  シグネチャ   4B  `PK\x03\x04`
///   +6  フラグ       2B  — bit0 = encrypted
///   +18 圧縮サイズ   4B
///   +26 ファイル名長 2B
///   +28 拡張フィールド長 2B
///   +30 ファイル名…
///
/// 圧縮サイズが 0 のエントリ (ストリーミング作成・data descriptor 形式) は
/// 次エントリ位置を計算できないため、次の `PK\x03\x04` を線形探索で再同期する。
/// 厳密なパーサではなく寛容なスキャン — 検査用途では取りこぼしを嫌う。
#[must_use]
pub fn zip_has_encrypted_entries(bytes: &[u8]) -> bool {
    const SIG: &[u8; 4] = b"PK\x03\x04";
    const HEADER_LEN: usize = 30;
    let mut pos = 0usize;
    while pos + HEADER_LEN <= bytes.len() {
        if &bytes[pos..pos + 4] != SIG {
            // 次のシグネチャへ進む (SFX/前置データを許容)
            match bytes[pos..].windows(4).position(|w| w == SIG) {
                Some(off) => pos += off,
                None => return false,
            }
            continue;
        }
        let flags = u16::from_le_bytes([bytes[pos + 6], bytes[pos + 7]]);
        if flags & 0x1 != 0 {
            return true;
        }
        let comp_size = u32::from_le_bytes([
            bytes[pos + 18],
            bytes[pos + 19],
            bytes[pos + 20],
            bytes[pos + 21],
        ]) as usize;
        let name_len = u16::from_le_bytes([bytes[pos + 26], bytes[pos + 27]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[pos + 28], bytes[pos + 29]]) as usize;
        // 次エントリ位置 = ヘッダ + ファイル名 + 拡張 + 圧縮データ。
        // comp_size == 0 (data descriptor 形式) や範囲外なら再同期。
        let next = pos + HEADER_LEN + name_len + extra_len + comp_size;
        if comp_size == 0 || next <= pos || next > bytes.len() {
            match bytes[pos + 4..].windows(4).position(|w| w == SIG) {
                Some(off) => pos += 4 + off,
                None => return false,
            }
        } else {
            pos = next;
        }
    }
    false
}

/// バイト列が PDF ファイルか判定する (拡張子または `%PDF-` マジック)。
///
/// Securelist (2025-10) が報告する通り、PDF 添付は量産・標的型の両方で
/// 急増しており、QR コード埋め込みやパスワード保護での検査回避が
/// 確認されている。中身の検査を入口にするため判定自体は別関数に分ける。
#[must_use]
pub fn is_pdf_file(filename: &str, bytes: &[u8]) -> bool {
    filename.to_ascii_lowercase().ends_with(".pdf") || bytes.starts_with(b"%PDF-")
}

/// PDF の名前トークン (`/Name`) をバイト列内で検索する。
///
/// PDF の間接オブジェクトは圧縮されていなければ平文で現れるため
/// 単純走査で検出できる (オブジェクトストリーム圧縮された PDF では
/// 検出できない — ベストエフォートの静的検査)。
///
/// 後続バイトが ASCII 英字なら別トークンの接頭辞とみなして除外する
/// (`/JS` が `/JScript` 系の別名と衝突しないため)。なお `/Encrypt` の
/// 直後は数字 (`/Encrypt 12 0 R`)・空白・`[` が続くためこの条件で
/// 正しく拾える。
fn contains_pdf_token(bytes: &[u8], token: &[u8]) -> bool {
    let mut start = 0usize;
    while let Some(off) = bytes[start..].windows(token.len()).position(|w| w == token) {
        let pos = start + off;
        let next_ok = bytes
            .get(pos + token.len())
            .is_none_or(|&b| !b.is_ascii_alphabetic());
        if next_ok {
            return true;
        }
        start = pos + 1;
    }
    false
}

/// PDF が暗号化されているか (`/Encrypt` 辞書エントリ — パスワード保護)。
///
/// パスワード付き PDF は内容物のスキャンが不能になるため、本文に
/// パスワードを書く配布の定石と同じ構造 (Securelist 2025-10 の
/// 「PDF を暗号化して本文にパスワード」キャンペーンと同型)。
#[must_use]
pub fn pdf_is_encrypted(bytes: &[u8]) -> bool {
    contains_pdf_token(bytes, b"/Encrypt")
}

/// PDF の実行・自動起動系要素を検出する。
///
/// 開いた時点・対象オブジェクトの描画時点で動作する要素のみを拾う:
/// - `/JavaScript`, `/JS` — JavaScript アクション
/// - `/OpenAction` — 文書を開いた時点で発火
/// - `/AA` — 追加アクション (ページ描画・フォーカス等のイベント)
/// - `/Launch` — 外部プログラム起動アクション
#[must_use]
pub fn pdf_active_markers(bytes: &[u8]) -> Vec<&'static str> {
    let mut found = Vec::new();
    for marker in ["/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch"] {
        if contains_pdf_token(bytes, marker.as_bytes()) {
            found.push(marker);
        }
    }
    found
}

/// PDF のペイロード運搬・外部送信系要素を検出する (注意喚起どまり)。
///
/// - `/EmbeddedFile` — 別ファイルを内蔵 (二重梱包)
/// - `/RichMedia` — Flash/動的コンテンツ
/// - `/XFA` — 動的フォーム (フィッシング用入力欄)
/// - `/SubmitForm` — 入力内容の外部送信
/// - `/ImportData` — 外部データ取り込み
#[must_use]
pub fn pdf_embedded_markers(bytes: &[u8]) -> Vec<&'static str> {
    let mut found = Vec::new();
    for marker in ["/EmbeddedFile", "/RichMedia", "/XFA", "/SubmitForm", "/ImportData"] {
        if contains_pdf_token(bytes, marker.as_bytes()) {
            found.push(marker);
        }
    }
    found
}

/// ファイル名に双方向テキスト制御文字 (RTLO 等) が含まれるか判定する。
///
/// U+202E (RIGHT-TO-LEFT OVERRIDE) や U+2066..U+2069 (LRI/RLI/PDI 系) を
/// ファイル名に埋めると、OS の表示側はその後の文字を反転表示する —
/// `invoicegpj.exe` (gpj ← jpg の逆順) が「invoice.jpg.exe」ではなく
/// 「invoiceexe.jpg」のように見えるため、実行ファイルを安全な
/// 文書/画像に見せかける古典的ななりすまし手法 (RTLO 攻撃 — Symantec/
/// Bitdefender 2013〜現在まで継続観測、2024-2025 でも現役)。
/// 拡張子が安全側に「見える」ため拡張子チェックを素通りさせる
/// 補助手段として検出する (D166)。
#[must_use]
pub fn has_bidi_override_filename(filename: &str) -> bool {
    filename.chars().any(|c| {
        matches!(
            c,
            '\u{202A}' // LEFT-TO-RIGHT EMBEDDING
            | '\u{202B}' // RIGHT-TO-LEFT EMBEDDING
            | '\u{202C}' // POP DIRECTIONAL FORMATTING
            | '\u{202D}' // LEFT-TO-RIGHT OVERRIDE
            | '\u{202E}' // RIGHT-TO-LEFT OVERRIDE (RTLO)
            | '\u{2066}' // LEFT-TO-RIGHT ISOLATE
            | '\u{2067}' // RIGHT-TO-LEFT ISOLATE
            | '\u{2068}' // FIRST STRONG ISOLATE
            | '\u{2069}' // POP DIRECTIONAL ISOLATE
        )
    })
}

/// Windows LNK (Shell Link) ファイルか magic bytes で判定する。
///
/// LNK ファイルのヘッダー: `4C 00 00 00 01 14 02 00` (CLSID_ShellLink)
#[must_use]
pub fn is_lnk_file(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x4C\x00\x00\x00\x01\x14\x02\x00")
}

/// SVG ファイルか判定する (XSS リスクのため添付として拒否すべき)。
///
/// SVG は `<script>` や `onload` 等 JS 実行ベクターを含めるため、
/// メール添付として受信した場合は sandbox VM 外では展開を禁止する。
#[must_use]
pub fn is_svg(bytes: &[u8]) -> bool {
    detect_mime_from_magic(bytes) == Some("image/svg+xml")
}

/// Polyglot ファイルを検出する。
///
/// Polyglot ファイルは複数のフォーマットとして同時に有効な binary。
/// 例: JPEG+ZIP (先頭が \xFF\xD8 で有効 JPEG、末尾に ZIP central directory)
///
/// magic bytes 単体チェックを回避するため、両端のシグネチャを確認する。
#[must_use]
pub fn detect_polyglot(bytes: &[u8]) -> Option<(&'static str, &'static str)> {
    let head_mime = detect_mime_from_magic(bytes)?;

    // ZIP の中央ディレクトリは末尾付近にある (最後の 64 KB をチェック)
    let tail_offset = bytes.len().saturating_sub(65536);
    let tail = &bytes[tail_offset..];

    // JPEG + ZIP polyglot (JPEG EOI \xFF\xD9 の後に ZIP データ)
    if head_mime == "image/jpeg"
        && tail
            .windows(4)
            .any(|w| w == b"PK\x03\x04" || w == b"PK\x05\x06")
    {
        return Some(("image/jpeg", "application/zip"));
    }

    // PNG + ZIP polyglot (PNG IEND チャンクの後に ZIP データ)
    // JPEG 分岐と同じく、EOCD (PK\x05\x06) だけでなくローカルファイルヘッダ
    // (PK\x03\x04) も照合する。EOCD が 64KB 窓の外にある巨大 polyglot や
    // EOCD を細工した検体でも、埋め込みエントリの存在で検出できるようにする。
    if head_mime == "image/png"
        && tail
            .windows(4)
            .any(|w| w == b"PK\x03\x04" || w == b"PK\x05\x06")
    {
        return Some(("image/png", "application/zip"));
    }

    // PDF + ZIP polyglot (PDF %%EOF の後に ZIP)
    if head_mime == "application/pdf"
        && tail
            .windows(4)
            .any(|w| w == b"PK\x03\x04" || w == b"PK\x05\x06")
    {
        return Some(("application/pdf", "application/zip"));
    }

    None
}

/// 宣言された MIME とマジックバイト検出 MIME を比較し、
/// 危険な不一致を検出する。
///
/// 戻り値: 危険な不一致がある場合 `Some(MimeMismatch)`。
/// 不一致なし、または検出不能の場合は `None`。
#[must_use]
pub fn check_mime_mismatch(declared: &str, bytes: &[u8]) -> Option<MimeMismatch> {
    let detected = detect_mime_from_magic(bytes)?;
    if is_dangerous_mismatch(declared, detected) {
        Some(MimeMismatch {
            declared: declared.to_string(),
            detected,
        })
    } else {
        None
    }
}

/// 宣言と検出の組み合わせが危険かどうか判定する。
///
/// PE/ELF/シェルスクリプト/Mach-O を別の無害なタイプとして偽装する場合は危険。
fn is_dangerous_mismatch(declared: &str, detected: &str) -> bool {
    let dangerous_detected = matches!(
        detected,
        "application/x-dosexec"
            | "application/x-elf"
            | "application/x-mach-binary"
            | "text/x-shellscript"
    );
    if !dangerous_detected {
        return false;
    }
    // ZIP → ZIP 系 (DOCX/XLSX 等) は false positive 回避
    // OLE → OLE は一致扱い
    let declared_lower = declared.to_ascii_lowercase();
    !declared_lower.contains("dosexec")
        && !declared_lower.contains("x-elf")
        && !declared_lower.contains("mach-binary")
        && !declared_lower.contains("shellscript")
        && !declared_lower.contains("octet-stream") // binary/unknown は許可
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn pe_header_detected() {
        let bytes = b"MZ\x90\x00\x03\x00";
        assert_eq!(detect_mime_from_magic(bytes), Some("application/x-dosexec"));
    }

    #[test]
    fn pdf_detected() {
        let bytes = b"%PDF-1.4 hello";
        assert_eq!(detect_mime_from_magic(bytes), Some("application/pdf"));
    }

    #[test]
    fn zip_detected() {
        let bytes = b"PK\x03\x04\x14\x00";
        assert_eq!(detect_mime_from_magic(bytes), Some("application/zip"));
    }

    #[test]
    fn png_detected() {
        let bytes = b"\x89PNG\r\n\x1A\ndata";
        assert_eq!(detect_mime_from_magic(bytes), Some("image/png"));
    }

    #[test]
    fn unknown_returns_none() {
        let bytes = b"hello world plain text";
        assert_eq!(detect_mime_from_magic(bytes), None);
    }

    #[test]
    fn pe_disguised_as_pdf_is_dangerous() {
        let bytes = b"MZ\x90\x00";
        let mismatch = check_mime_mismatch("application/pdf", bytes);
        assert!(mismatch.is_some(), "PE disguised as PDF must be flagged");
        let m = mismatch.unwrap();
        assert_eq!(m.detected, "application/x-dosexec");
    }

    #[test]
    fn elf_disguised_as_image_is_dangerous() {
        let bytes = b"\x7FELF\x02\x01\x01\x00";
        let mismatch = check_mime_mismatch("image/jpeg", bytes);
        assert!(mismatch.is_some());
    }

    #[test]
    fn pdf_declared_and_detected_is_ok() {
        let bytes = b"%PDF-1.5";
        let mismatch = check_mime_mismatch("application/pdf", bytes);
        assert!(mismatch.is_none(), "PDF/PDF は不一致でない");
    }

    #[test]
    fn octet_stream_with_pe_is_allowed() {
        // application/octet-stream は汎用バイナリ — 危険と見なさない
        let bytes = b"MZ\x90\x00";
        let mismatch = check_mime_mismatch("application/octet-stream", bytes);
        assert!(mismatch.is_none(), "octet-stream は危険な不一致でない");
    }

    #[test]
    fn shell_script_disguised_as_text_is_dangerous() {
        let bytes = b"#!/bin/bash\nrm -rf /";
        let mismatch = check_mime_mismatch("text/plain", bytes);
        assert!(
            mismatch.is_some(),
            "シェルスクリプトを text/plain と偽装は危険"
        );
    }

    #[test]
    fn svg_detected_by_tag() {
        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><circle r=\"50\"/></svg>";
        assert_eq!(detect_mime_from_magic(svg), Some("image/svg+xml"));
        assert!(is_svg(svg));
    }

    #[test]
    fn svg_with_xml_declaration_detected() {
        let svg = b"<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"/>";
        assert!(is_svg(svg));
    }

    #[test]
    fn padded_svg_still_detected() {
        // 回帰: 従来の 256 バイト窓では、長いコメントで <svg> を押し下げるだけで
        // 検出を回避でき、SVG を image/png と偽装した添付が素通りしていた。
        let padding = format!("<!-- {} -->", "A".repeat(2000));
        let svg = format!("{padding}<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>");
        assert_eq!(
            detect_mime_from_magic(svg.as_bytes()),
            Some("image/svg+xml"),
            "パディングで押し下げられた <svg> が検出されない"
        );
        assert!(is_svg(svg.as_bytes()));
    }

    #[test]
    fn svg_after_long_doctype_detected() {
        // DOCTYPE で押し下げる亜種
        let doctype = format!(
            "<?xml version=\"1.0\"?>\n<!DOCTYPE svg [{}]>\n",
            " ".repeat(1500)
        );
        let svg = format!("{doctype}<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>");
        assert_eq!(
            detect_mime_from_magic(svg.as_bytes()),
            Some("image/svg+xml")
        );
    }

    #[test]
    fn invalid_utf8_tail_does_not_break_svg_detection() {
        // from_utf8 だと窓末尾でマルチバイト文字が切れた瞬間に全体が空になり
        // 判定が失われていた。from_utf8_lossy なら部分一致できる。
        let mut bytes = b"<svg xmlns=\"http://www.w3.org/2000/svg\">".to_vec();
        bytes.extend_from_slice(&[0xE3, 0x81]); // 不完全な UTF-8 シーケンス
        bytes.extend_from_slice(b"</svg>");
        assert_eq!(
            detect_mime_from_magic(&bytes),
            Some("image/svg+xml"),
            "不正な UTF-8 を含む SVG が検出されない"
        );
    }

    #[test]
    fn jpeg_is_not_svg() {
        let jpeg = b"\xFF\xD8\xFF\xE0";
        assert!(!is_svg(jpeg));
    }

    #[test]
    fn jpeg_zip_polyglot_detected() {
        let mut bytes = b"\xFF\xD8\xFF\xE0".to_vec(); // JPEG header
        bytes.extend(vec![0u8; 100]);
        bytes.extend_from_slice(b"PK\x05\x06"); // ZIP end-of-central-directory
        bytes.extend(vec![0u8; 18]);
        let result = detect_polyglot(&bytes);
        assert!(result.is_some(), "JPEG+ZIP polyglot should be detected");
        assert_eq!(result.unwrap().0, "image/jpeg");
    }

    #[test]
    fn png_zip_polyglot_with_local_header_detected() {
        // 回帰: PNG/PDF 分岐は EOCD (PK\x05\x06) のみ照合しており、
        // ローカルファイルヘッダ (PK\x03\x04) しか窓内に無い検体を見逃していた。
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec(); // PNG signature
        bytes.extend(vec![0u8; 100]);
        bytes.extend_from_slice(b"PK\x03\x04"); // ZIP local file header
        bytes.extend(vec![0u8; 20]);
        let result = detect_polyglot(&bytes);
        assert_eq!(
            result,
            Some(("image/png", "application/zip")),
            "PNG+ZIP (ローカルヘッダ) polyglot が検出されるべき"
        );
    }

    #[test]
    fn pdf_zip_polyglot_with_local_header_detected() {
        let mut bytes = b"%PDF-1.7\n".to_vec();
        bytes.extend(vec![0u8; 100]);
        bytes.extend_from_slice(b"PK\x03\x04");
        bytes.extend(vec![0u8; 20]);
        let result = detect_polyglot(&bytes);
        assert_eq!(
            result,
            Some(("application/pdf", "application/zip")),
            "PDF+ZIP (ローカルヘッダ) polyglot が検出されるべき"
        );
    }

    #[test]
    fn lnk_file_detected_by_extension() {
        assert!(is_dangerous_windows_attachment("invoice.lnk"));
        assert!(is_dangerous_windows_attachment("INVOICE.LNK"));
    }

    #[test]
    fn url_file_is_dangerous() {
        assert!(is_dangerous_windows_attachment("report.url"));
    }

    #[test]
    fn office_macro_extensions_dangerous() {
        assert!(is_dangerous_windows_attachment("doc.docm"));
        assert!(is_dangerous_windows_attachment("sheet.xlsm"));
        assert!(is_dangerous_windows_attachment("slide.pptm"));
    }

    #[test]
    fn script_extensions_dangerous() {
        assert!(is_dangerous_windows_attachment("evil.ps1"));
        assert!(is_dangerous_windows_attachment("evil.vbs"));
        assert!(is_dangerous_windows_attachment("evil.bat"));
    }

    #[test]
    fn safe_extensions_not_dangerous() {
        assert!(!is_dangerous_windows_attachment("report.pdf"));
        assert!(!is_dangerous_windows_attachment("photo.jpg"));
        assert!(!is_dangerous_windows_attachment("data.csv"));
    }

    #[test]
    fn lnk_magic_bytes_detected() {
        let lnk = b"\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00";
        assert!(is_lnk_file(lnk));
    }

    #[test]
    fn non_lnk_magic_bytes_not_detected() {
        assert!(!is_lnk_file(b"MZ\x90\x00"));
        assert!(!is_lnk_file(b"%PDF"));
    }

    #[test]
    fn clean_jpeg_is_not_polyglot() {
        let jpeg = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00";
        assert!(detect_polyglot(jpeg).is_none());
    }

    #[test]
    fn zip_as_docx_is_not_mismatch() {
        // DOCX は ZIP ベースなので application/zip 検出は正常
        let bytes = b"PK\x03\x04";
        // ZIP は dangerous_detected に含まれないので None
        let mismatch = check_mime_mismatch(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            bytes,
        );
        assert!(mismatch.is_none(), "DOCX(ZIP) は危険な不一致でない");
    }

    // ---- D166: 実行・コンテナ拡張子と RTLO ファイル名 ----

    #[test]
    fn exe_and_com_are_dangerous() {
        // 回帰: 最も基本的な直接実行形式がリストに欠けていた
        assert!(is_dangerous_windows_attachment("invoice.exe"));
        assert!(is_dangerous_windows_attachment("SETUP.EXE"));
        assert!(is_dangerous_windows_attachment("run.com"));
        assert!(is_dangerous_windows_attachment("app.jar"));
    }

    #[test]
    fn double_extension_executable_is_dangerous() {
        // 請求書.pdf.exe の二重拡張子偽装 — 末尾拡張子で判定
        assert!(is_dangerous_windows_attachment("請求書.pdf.exe"));
        assert!(is_dangerous_windows_attachment("report.docx.scr"));
    }

    #[test]
    fn container_image_extensions_are_dangerous() {
        // MOTW bypass: ISO/IMG/VHD 内のファイルは MOTW を継承しない
        assert!(is_dangerous_windows_attachment("payload.iso"));
        assert!(is_dangerous_windows_attachment("drive.img"));
        assert!(is_dangerous_windows_attachment("disk.vhd"));
        assert!(is_dangerous_windows_attachment("disk.vhdx"));
    }

    #[test]
    fn safe_archive_extensions_not_dangerous() {
        // zip/rar/7z は通常の配送手段 — コンテナ形式とは区別する
        assert!(!is_dangerous_windows_attachment("archive.zip"));
        assert!(!is_dangerous_windows_attachment("backup.rar"));
        assert!(!is_dangerous_windows_attachment("photos.tar"));
    }

    #[test]
    fn rtlo_filename_is_dangerous() {
        // U+202E で「invoicegpj.exe」→「invoiceexe.jpg」と表示反転
        let rtlo = "invoice\u{202E}gpj.exe";
        assert!(has_bidi_override_filename(rtlo));
    }

    #[test]
    fn isolate_controls_are_dangerous() {
        assert!(has_bidi_override_filename("file\u{2067}name.pdf"));
        assert!(has_bidi_override_filename("file\u{2068}name.pdf"));
        assert!(has_bidi_override_filename("file\u{2066}name.exe"));
        assert!(has_bidi_override_filename("file\u{2069}name.pdf"));
    }

    #[test]
    fn embedding_and_pop_are_dangerous() {
        assert!(has_bidi_override_filename("a\u{202A}b.txt"));
        assert!(has_bidi_override_filename("a\u{202B}b.txt"));
        assert!(has_bidi_override_filename("a\u{202C}b.txt"));
        assert!(has_bidi_override_filename("a\u{202D}b.txt"));
    }

    #[test]
    fn normal_filename_no_bidi() {
        assert!(!has_bidi_override_filename("invoice.pdf"));
        assert!(!has_bidi_override_filename("請求書_2025.pdf"));
        assert!(!has_bidi_override_filename("no ext"));
    }

    // ---- D1250: マクロ有効派生形式・代替配送形式・ネストメール・暗号化 ZIP ----

    #[test]
    fn macro_template_and_addin_extensions_dangerous() {
        // 回帰: docm だけではなく、同じ VBA を載せられる全形式を網羅する
        for f in [
            "t.dotm",
            "t.xltm",
            "t.potm",
            "show.ppsm",
            "s.sldm",
            "a.ppam",
            "a.xlam",
            "a.xla",
            "lib.xll",
            "macro.xlm",
            "book.xlsb",
            "doc.docb",
            "draw.vsdm",
            "db.mpa",
            "db.accde",
        ] {
            assert!(
                is_dangerous_windows_attachment(f),
                "{f} はマクロ/実行埋め込み可能な形式"
            );
        }
    }

    #[test]
    fn onenote_extensions_dangerous() {
        // 2023 年 Qakbot/IcedID キャンペーンで主流化した配送形式
        assert!(is_dangerous_windows_attachment("note.one"));
        assert!(is_dangerous_windows_attachment("pkg.onepkg"));
    }

    #[test]
    fn script_component_and_leak_extensions_dangerous() {
        for f in [
            "help.chm",
            "persist.reg",
            "x.sct",
            "x.wsc",
            "sheet.slk",
            "q.iqy",
            "site.website",
            "l.library-ms",
            "s.search-ms",
            "s.settingcontent-ms",
            "t.theme",
            "page.mht",
            "page.mhtml",
            "panel.cpl",
            "c.msc",
            "setup.inf",
            "d.diagcab",
            "app.xbap",
            "go.appref-ms",
        ] {
            assert!(
                is_dangerous_windows_attachment(f),
                "{f} は実行・認証情報漏洩に使える形式"
            );
        }
    }

    #[test]
    fn still_safe_extensions_not_dangerous() {
        // 誤検知ガード — ドキュメント/画像/アーカイブは従来どおり
        for f in [
            "report.docx",
            "sheet.xlsx",
            "slide.pptx",
            "memo.onetoc2",
            "photo.png",
            "data.zip",
            "note.txt",
        ] {
            assert!(
                !is_dangerous_windows_attachment(f),
                "{f} は誤検知してはいけない"
            );
        }
    }

    #[test]
    fn nested_email_attachments_detected() {
        assert!(is_nested_email_attachment("fwd.eml", "message/rfc822"));
        assert!(is_nested_email_attachment("outlook.msg", "application/octet-stream"));
        assert!(is_nested_email_attachment("inner", "message/rfc822"));
        assert!(is_nested_email_attachment(
            "inner",
            "application/vnd.ms-outlook"
        ));
        assert!(!is_nested_email_attachment("doc.pdf", "application/pdf"));
    }

    #[test]
    fn zip_magic_detects_zip() {
        assert!(is_zip_file("a.zip", b""));
        assert!(is_zip_file("noext", b"PK\x03\x04rest"));
        assert!(!is_zip_file("a.txt", b"plain"));
    }

    /// ZIP ローカルファイルヘッダを組み立てるヘルパ。
    fn make_zip_entry(name: &[u8], flags: u16, comp: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"PK\x03\x04"); // signature
        v.extend_from_slice(&20u16.to_le_bytes()); // version
        v.extend_from_slice(&flags.to_le_bytes()); // flags
        v.extend_from_slice(&8u16.to_le_bytes()); // method=deflate
        v.extend_from_slice(&0u32.to_le_bytes()); // time/date
        v.extend_from_slice(&0u32.to_le_bytes()); // crc
        v.extend_from_slice(&(comp.len() as u32).to_le_bytes()); // comp size
        v.extend_from_slice(&(comp.len() as u32).to_le_bytes()); // uncomp size
        v.extend_from_slice(&(name.len() as u16).to_le_bytes()); // name len
        v.extend_from_slice(&0u16.to_le_bytes()); // extra len
        v.extend_from_slice(name);
        v.extend_from_slice(comp);
        v
    }

    #[test]
    fn encrypted_zip_entry_detected() {
        let mut zip = make_zip_entry(b"evil.exe", 0x0001, b"\x01\x02\x03");
        // 後続に暗号化なしエントリがあっても先に検出できる
        let e2 = make_zip_entry(b"plain.txt", 0x0000, b"hi");
        zip.extend_from_slice(&e2);
        assert!(zip_has_encrypted_entries(&zip));
    }

    #[test]
    fn unencrypted_zip_not_detected() {
        let mut zip = make_zip_entry(b"a.txt", 0x0000, b"data1234");
        let e2 = make_zip_entry(b"b.bin", 0x0000, b"xy");
        zip.extend_from_slice(&e2);
        assert!(!zip_has_encrypted_entries(&zip));
        assert!(!zip_has_encrypted_entries(b"not a zip at all"));
        assert!(!zip_has_encrypted_entries(b"PK\x03\x04")); // 途中切り
    }

    // ── D1253: PDF 静的検査 ───────────────────────────────────────────────

    #[test]
    fn pdf_detected_by_ext_and_magic() {
        assert!(is_pdf_file("invoice.pdf", b""));
        assert!(is_pdf_file("noext.bin", b"%PDF-1.7 rest"));
        assert!(!is_pdf_file("doc.txt", b"plain text"));
        assert!(!is_pdf_file("report.docx", b"PK\x03\x04"));
    }

    #[test]
    fn encrypted_pdf_detected() {
        let pdf = b"%PDF-1.7\n1 0 obj << /Filter /Standard >> endobj\ntrailer << /Encrypt 2 0 R >>\n%%EOF";
        assert!(pdf_is_encrypted(pdf));
        // /EncryptMetadata 等の別名トークンは誤検しない
        let other = b"%PDF-1.7\ntrailer << /EncryptMetadata true >>\n%%EOF";
        assert!(!pdf_is_encrypted(other));
        let plain = b"%PDF-1.7\n1 0 obj << /Type /Page >> endobj\n%%EOF";
        assert!(!pdf_is_encrypted(plain));
    }

    #[test]
    fn pdf_active_markers_detected() {
        let pdf = b"%PDF-1.7\n1 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj\n%%EOF";
        let m = pdf_active_markers(pdf);
        assert!(m.contains(&"/JavaScript"));
        assert!(m.contains(&"/JS"));
        // /JS の接頭辞誤爆をしない: /JScript は別トークン
        let clean = b"%PDF-1.7\n<< /JScript none >>\n%%EOF";
        assert!(pdf_active_markers(clean).is_empty());
    }

    #[test]
    fn pdf_openaction_and_launch_detected() {
        let pdf = b"%PDF-1.7\ncatalog << /OpenAction 3 0 R /AA << /O 4 0 R >> /Launch (cmd.exe) >>\n%%EOF";
        let m = pdf_active_markers(pdf);
        assert!(m.contains(&"/OpenAction"));
        assert!(m.contains(&"/AA"));
        assert!(m.contains(&"/Launch"));
    }

    #[test]
    fn pdf_embedded_markers_detected() {
        let pdf = b"%PDF-1.7\n<< /EmbeddedFile 5 0 R /SubmitForm (https://evil.example) /XFA data >>\n%%EOF";
        let m = pdf_embedded_markers(pdf);
        assert!(m.contains(&"/EmbeddedFile"));
        assert!(m.contains(&"/SubmitForm"));
        assert!(m.contains(&"/XFA"));
        // 無害な PDF では発火しない
        let plain = b"%PDF-1.7\n1 0 obj << /Type /Page /MediaBox [0 0 612 792] >> endobj\n%%EOF";
        assert!(pdf_embedded_markers(plain).is_empty());
        assert!(pdf_active_markers(plain).is_empty());
    }
}
