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
    )
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
// D216: ZIP-slip — ZIP エントリ名のパストラバーサル
// ============================================================================

/// ZIP 内のエントリ名に `../`・絶対パス・ドライブ文字の
/// パストラバーサルが含まれるか判定する。
///
/// 解凍時に展開先ディレクトリの外へ書き込む "zip-slip" 攻撃
/// (Snyk 2018 報告)。ローカルファイルヘッダ (`PK\x03\x04`) を
/// 走査してファイル名フィールドを直接検査する (セントラル
/// ディレクトリを切り落として走査を回避する改造品にも対応)。
/// 上限 1024 エントリで打ち切る。
#[must_use]
pub fn zip_has_traversal_entry(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"PK\x03\x04") {
        return false;
    }
    let mut pos = 0usize;
    for _ in 0..1024 {
        // ローカルファイルヘッダ: sig(4) ver(2) flag(2) method(2)
        // time(2) date(2) crc(4) csize(4) usize(4) nlen(2) elen(2)
        if bytes.len() < pos + 30 || bytes[pos..pos + 4] != *b"PK\x03\x04" {
            // 次のヘッダを前方探索 (データ記述子のため csize 不明時)
            if bytes.len() < pos + 4 {
                break;
            }
            match find_subslice(&bytes[pos + 4..], b"PK\x03\x04") {
                Some(off) => {
                    pos += 4 + off;
                    continue;
                }
                None => break,
            }
        }
        let nlen = u16::from_le_bytes([bytes[pos + 26], bytes[pos + 27]]) as usize;
        let elen = u16::from_le_bytes([bytes[pos + 28], bytes[pos + 29]]) as usize;
        let name_end = pos + 30 + nlen;
        if name_end > bytes.len() {
            break;
        }
        let name = &bytes[pos + 30..name_end];
        if is_traversal_name(name) {
            return true;
        }
        pos = name_end + elen;
    }
    false
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// エントリ名がパストラバーサル形か判定する。
///
/// `../` (先頭・途中どちらも)、`/` ・ `\` 始まりの絶対パス、
/// `C:` 等のドライブレター絶対パスを捕捉。
fn is_traversal_name(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    // 絶対パス
    if name[0] == b'/' || name[0] == b'\\' {
        return true;
    }
    // ドライブレター "X:" (ASCII アルファベット + ':')
    if name.len() >= 2 && name[0].is_ascii_alphabetic() && name[1] == b':' {
        return true;
    }
    // "../" ・ "..\" を含む (正規化で `..` を残す形)
    name.windows(3).any(|w| w == b"../" || w == b"..\\")
        || name == b".."
        || name.ends_with(b"/..")
        || name.ends_with(b"\\..")
}

// ============================================================================
// D217: OOXML 外部リレーションシップ (NTLM 漏洩 / リモートテンプレート注入)
// ============================================================================

/// OOXML (ZIP) 内の `.rels` が `TargetMode="External"` +
/// ネットワーク/UNC 参照を持つか判定する。
///
/// 「External」リレーションで `Target="http://..."` ・
/// `"file://\\\\..."` ・ `"\\\\host\\share"` を参照する docx/xlsx は、
/// 開くだけで外部接続 (NTLM 認証漏洩・リモートテンプレート注入)
/// を引き起こす (Cubajufr/CrowdStrike の分析で報告)。
#[must_use]
pub fn ooxml_has_external_relationship(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"PK") {
        return false;
    }
    let has_external = find_subslice(bytes, b"TargetMode=\"External\"").is_some()
        || find_subslice(bytes, b"TargetMode='External'").is_some();
    if !has_external {
        return false;
    }
    find_subslice(bytes, b"Target=\"http").is_some()
        || find_subslice(bytes, b"Target='http").is_some()
        || find_subslice(bytes, b"Target=\"file:").is_some()
        || find_subslice(bytes, b"Target='file:").is_some()
        || find_subslice(bytes, b"Target=\"\\\\").is_some()
        || find_subslice(bytes, b"Target='\\\\").is_some()
}

// ============================================================================
// D218: PDF 埋め込みファイル (添付の PDF 内同梱)
// ============================================================================

/// PDF が `/EmbeddedFile` または `/Filespec` を持つか判定する。
///
/// PDF は添付ファイルを内部に同梱できる (ポートフォリオ/添付
/// コレクション機能) — 外側が「安全な PDF」に見えても、内側に
/// exe/iso 等を忍ばせられる (Mandiant の PDF 内同梱マルウェア
/// 分析で報告)。実体走査でキーワードを検出する。
#[must_use]
pub fn pdf_has_embedded_file(bytes: &[u8]) -> bool {
    bytes.starts_with(b"%PDF")
        && (find_subslice(bytes, b"/EmbeddedFile").is_some()
            || find_subslice(bytes, b"/Filespec").is_some())
}

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

    // ---------------------------------------------------------------
    // D216: ZIP-slip パストラバーサル
    // ---------------------------------------------------------------

    fn zip_entry(name: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"PK\x03\x04");
        v.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        v.extend_from_slice(&[0; 12]); // crc + csize + usize
        let nlen = name.len() as u16;
        v.extend_from_slice(&nlen.to_le_bytes());
        v.extend_from_slice(&[0, 0]); // elen
        v.extend_from_slice(name);
        v
    }

    #[test]
    fn zip_traversal_dotdot_detected() {
        assert!(zip_has_traversal_entry(&zip_entry(b"../../etc/passwd")));
        assert!(zip_has_traversal_entry(&zip_entry(b"safe/../../evil.exe")));
        assert!(zip_has_traversal_entry(&zip_entry(b"a\\b\\..\\..\\c")));
        assert!(zip_has_traversal_entry(&zip_entry(b"/etc/passwd")));
        assert!(zip_has_traversal_entry(&zip_entry(b"\\\\evil\\share")));
        assert!(zip_has_traversal_entry(&zip_entry(
            b"C:\\Windows\\evil.dll"
        )));
        assert!(zip_has_traversal_entry(&zip_entry(b"dir\\..\\..\\x")));
    }

    #[test]
    fn zip_safe_names_not_flagged() {
        assert!(!zip_has_traversal_entry(&zip_entry(b"document.docx")));
        assert!(!zip_has_traversal_entry(&zip_entry(b"dir/subdir/file.txt")));
        assert!(!zip_has_traversal_entry(&zip_entry(b"..data.txt")));
        assert!(!zip_has_traversal_entry(&zip_entry(b"a..b.txt")));
        // 非 ZIP 入力は対象外
        assert!(!zip_has_traversal_entry(b"not a zip at all"));
        assert!(!zip_has_traversal_entry(b""));
        // 通常名が複数連なっても検出しない
        let mut two = zip_entry(b"a.txt");
        two.extend_from_slice(&zip_entry(b"b.txt"));
        assert!(!zip_has_traversal_entry(&two));
    }

    #[test]
    fn zip_traversal_later_entry_detected() {
        // 先頭が正常でも後続エントリの traversal を見逃さない
        let mut data = zip_entry(b"safe.txt");
        data.extend_from_slice(&zip_entry(b"../../../evil.sh"));
        assert!(zip_has_traversal_entry(&data));
    }

    // ---------------------------------------------------------------
    // D217: OOXML 外部リレーションシップ
    // ---------------------------------------------------------------

    #[test]
    fn ooxml_external_relationship_detected() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(
            b"<Relationship TargetMode=\"External\"               Target=\"http://evil.example/t.dotm\"/>",
        );
        assert!(ooxml_has_external_relationship(&data));
        let mut data2 = b"PK\x03\x04".to_vec();
        data2.extend_from_slice(
            b"<Relationship TargetMode='External'               Target='file:///\\\\\\\\evil\\\\share'/>",
        );
        assert!(ooxml_has_external_relationship(&data2));
        let mut data3 = b"PK\x03\x04".to_vec();
        data3.extend_from_slice(b"<Relationship TargetMode=\"External\" Target=\"\\\\evil\\s\"/>");
        assert!(ooxml_has_external_relationship(&data3));
    }

    #[test]
    fn ooxml_internal_relationship_safe() {
        // External なし (内部 rels) は対象外
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(
            b"<Relationship Target=\"word/document.xml\"               Type=\"http://x/relationships/officeDocument\"/>",
        );
        assert!(!ooxml_has_external_relationship(&data));
        // External ありだが Target がネットワーク参照でない
        let mut data2 = b"PK\x03\x04".to_vec();
        data2.extend_from_slice(b"<Relationship TargetMode=\"External\" Target=\"mailto:a@b\"/>");
        assert!(!ooxml_has_external_relationship(&data2));
        // 非 ZIP 入力は対象外
        assert!(!ooxml_has_external_relationship(b"plain text"));
    }

    // ---------------------------------------------------------------
    // D218: PDF 埋め込みファイル
    // ---------------------------------------------------------------

    #[test]
    fn pdf_embedded_file_detected() {
        let mut data = b"%PDF-1.5".to_vec();
        data.extend_from_slice(b" obj <</Type /EmbeddedFile /EF <<>>>>");
        assert!(pdf_has_embedded_file(&data));
        let mut data2 = b"%PDF-1.7".to_vec();
        data2.extend_from_slice(b" obj <</Type /Filespec /F (evil.exe)>>");
        assert!(pdf_has_embedded_file(&data2));
        // 通常 PDF (埋め込みなし) は対象外
        assert!(!pdf_has_embedded_file(b"%PDF-1.5 plain document xref"));
        // 非 PDF 入力は対象外
        assert!(!pdf_has_embedded_file(b"not pdf /EmbeddedFile"));
        assert!(!pdf_has_embedded_file(b""));
    }
}
