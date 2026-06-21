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
        write!(f, "MIME 不一致: 宣言={:?}, 検出={:?}", self.declared, self.detected)
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
    {
        let head = &bytes[..bytes.len().min(256)];
        let head_str = std::str::from_utf8(head).unwrap_or("");
        let lower = head_str.to_ascii_lowercase();
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
#[must_use]
pub fn is_dangerous_windows_attachment(filename: &str) -> bool {
    let lower = filename.to_ascii_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    matches!(
        ext,
        "lnk"   // Windows Shell Link — 任意コマンド実行
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
    )
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
    if head_mime == "image/jpeg" && tail.windows(4).any(|w| w == b"PK\x03\x04" || w == b"PK\x05\x06") {
        return Some(("image/jpeg", "application/zip"));
    }

    // PNG + ZIP polyglot (PNG IEND チャンクの後に ZIP データ)
    if head_mime == "image/png" && tail.windows(4).any(|w| w == b"PK\x05\x06") {
        return Some(("image/png", "application/zip"));
    }

    // PDF + ZIP polyglot (PDF %%EOF の後に ZIP)
    if head_mime == "application/pdf" && tail.windows(4).any(|w| w == b"PK\x05\x06") {
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
        assert!(mismatch.is_some(), "シェルスクリプトを text/plain と偽装は危険");
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
}
