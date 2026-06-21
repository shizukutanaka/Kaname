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
