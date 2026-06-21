//! 添付ファイルメタデータ漏洩検出 (Round7 先行実装)。
//!
//! PDF の /Author, /Creator、JPEG の EXIF GPS 座標など、
//! 添付ファイルに埋め込まれたメタデータはプライバシーリスクを生む。
//! 送信前に警告するための検出モジュール。

/// 検出されたメタデータリスク。
#[derive(Debug, PartialEq, Eq)]
pub enum MetadataRisk {
    /// PDF に作成者/編集者情報が含まれている。
    PdfAuthorInfo {
        /// 検出された値の抜粋 (最大 64 バイト)。
        excerpt: String,
    },
    /// PDF に作成ソフトウェア情報が含まれている (バージョン情報漏洩)。
    PdfCreatorInfo {
        /// 検出された値の抜粋。
        excerpt: String,
    },
    /// JPEG/TIFF に GPS 座標が含まれている。
    ExifGpsCoordinates,
    /// JPEG/TIFF に機器情報が含まれている (カメラモデル等)。
    ExifDeviceInfo,
    /// Office XML に作成者情報が含まれている (OOXML /docProps/core.xml)。
    OoxmlAuthorInfo {
        /// 検出された値の抜粋。
        excerpt: String,
    },
}

impl std::fmt::Display for MetadataRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PdfAuthorInfo { excerpt } =>
                write!(f, "PDF 作成者情報: {excerpt:?}"),
            Self::PdfCreatorInfo { excerpt } =>
                write!(f, "PDF 作成ソフト情報: {excerpt:?}"),
            Self::ExifGpsCoordinates =>
                write!(f, "JPEG EXIF GPS 座標が含まれている"),
            Self::ExifDeviceInfo =>
                write!(f, "JPEG EXIF 機器情報が含まれている"),
            Self::OoxmlAuthorInfo { excerpt } =>
                write!(f, "Office ドキュメント作成者情報: {excerpt:?}"),
        }
    }
}

/// 添付ファイルのバイト列からメタデータリスクを検出する。
///
/// # 実装方針
///
/// バイト列のパターンマッチングで高速に検出する。
/// 完全な EXIF/PDF パースは行わず、典型的なタグ文字列を探す。
/// 誤検知よりも見逃しを優先する (送信前警告用途)。
#[must_use]
pub fn detect_metadata_risks(filename: &str, bytes: &[u8]) -> Vec<MetadataRisk> {
    let ext = filename.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "pdf" => detect_pdf_metadata(bytes),
        "jpg" | "jpeg" | "tif" | "tiff" | "heic" => detect_exif_metadata(bytes),
        "docx" | "xlsx" | "pptx" => detect_ooxml_metadata(bytes),
        _ => vec![],
    }
}

/// PDF メタデータ検出 (バイト列パターンマッチ)。
fn detect_pdf_metadata(bytes: &[u8]) -> Vec<MetadataRisk> {
    let mut risks = Vec::new();
    let text = std::str::from_utf8(bytes).unwrap_or("");

    // PDF の情報ディクショナリ: /Author, /Creator, /Producer
    if let Some(excerpt) = find_pdf_field(text, "/Author") {
        risks.push(MetadataRisk::PdfAuthorInfo { excerpt });
    }
    if let Some(excerpt) = find_pdf_field(text, "/Creator") {
        risks.push(MetadataRisk::PdfCreatorInfo { excerpt });
    }

    risks
}

/// PDF フィールド値を抽出する (簡易パーサー)。
fn find_pdf_field(text: &str, field: &str) -> Option<String> {
    let pos = text.find(field)?;
    let rest = &text[pos + field.len()..];
    // フィールド後の値: "(...)" または "<...>" 形式
    let rest = rest.trim_start();
    if rest.starts_with('(') {
        let end = rest.find(')')?;
        let value = &rest[1..end];
        if value.is_empty() {
            return None;
        }
        let excerpt = truncate_utf8(value, 64);
        Some(excerpt)
    } else {
        None
    }
}

/// JPEG/TIFF EXIF メタデータ検出。
fn detect_exif_metadata(bytes: &[u8]) -> Vec<MetadataRisk> {
    let mut risks = Vec::new();

    // EXIF マーカー: JPEG SOI (FFD8) + APP1 (FFE1) + "Exif\0\0"
    if !bytes.starts_with(b"\xFF\xD8") {
        return risks;
    }
    let has_exif = bytes.windows(6).any(|w| w == b"Exif\x00\x00");
    if !has_exif {
        return risks;
    }

    // GPS IFD タグ: 0x8825 (GPS Info)
    // バイト列中に GPS タグのバイナリパターンを探す
    let gps_tag = [0x88u8, 0x25];
    if bytes.windows(2).any(|w| w == gps_tag) {
        risks.push(MetadataRisk::ExifGpsCoordinates);
    }

    // 機器情報タグ: Make (0x010F) / Model (0x0110)
    let make_tag = [0x01u8, 0x0F];
    let model_tag = [0x01u8, 0x10];
    if bytes.windows(2).any(|w| w == make_tag) || bytes.windows(2).any(|w| w == model_tag) {
        risks.push(MetadataRisk::ExifDeviceInfo);
    }

    risks
}

/// OOXML (Office Open XML) メタデータ検出。
/// DOCX/XLSX/PPTX は ZIP で /docProps/core.xml に作成者情報が含まれる。
fn detect_ooxml_metadata(bytes: &[u8]) -> Vec<MetadataRisk> {
    // ZIP マジックバイトでなければスキップ
    if !bytes.starts_with(b"PK\x03\x04") {
        return vec![];
    }
    // ZIP 内の XML をバイト列として検索 (完全な ZIP 展開なし)
    // dc:creator タグを探す
    let creator_tag = b"dc:creator";
    if let Some(pos) = find_bytes(bytes, creator_tag) {
        let rest = &bytes[pos + creator_tag.len()..];
        // <dc:creator>値</dc:creator> の値部分を抽出
        if let Some(gt) = find_bytes(rest, b">") {
            let value_start = gt + 1;
            if let Some(lt) = find_bytes(&rest[value_start..], b"<") {
                let value = &rest[value_start..value_start + lt];
                if !value.is_empty() {
                    let excerpt = String::from_utf8_lossy(value).to_string();
                    let excerpt = truncate_utf8(&excerpt, 64);
                    return vec![MetadataRisk::OoxmlAuthorInfo { excerpt }];
                }
            }
        }
    }
    vec![]
}

/// バイト列中のパターンを探す。
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// UTF-8 文字境界を考慮した切り詰め。
fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let cut = (0..=max_bytes).rev().find(|&i| s.is_char_boundary(i)).unwrap_or(0);
    format!("{}…", &s[..cut])
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_author_detected() {
        let pdf = b"%PDF-1.4\n/Author (Alice Smith)\n/Creator (Microsoft Word 2019)\n";
        let risks = detect_pdf_metadata(pdf);
        assert!(risks.iter().any(|r| matches!(r, MetadataRisk::PdfAuthorInfo { .. })));
        assert!(risks.iter().any(|r| matches!(r, MetadataRisk::PdfCreatorInfo { .. })));
    }

    #[test]
    fn pdf_no_metadata_is_clean() {
        let pdf = b"%PDF-1.4\nThis PDF has no metadata.\n%%EOF";
        let risks = detect_pdf_metadata(pdf);
        assert!(risks.is_empty());
    }

    #[test]
    fn jpeg_with_exif_gps_detected() {
        // JPEG SOI + APP1 marker + Exif header + GPS tag bytes
        let mut jpeg = b"\xFF\xD8\xFF\xE1".to_vec();
        jpeg.extend_from_slice(b"Exif\x00\x00");
        jpeg.extend_from_slice(b"\x88\x25"); // GPS IFD tag
        let risks = detect_exif_metadata(&jpeg);
        assert!(risks.iter().any(|r| matches!(r, MetadataRisk::ExifGpsCoordinates)));
    }

    #[test]
    fn jpeg_without_exif_is_clean() {
        let jpeg = b"\xFF\xD8\xFF\xE0no-exif-data";
        let risks = detect_exif_metadata(jpeg);
        assert!(risks.is_empty(), "EXIF なし JPEG はリスクなし");
    }

    #[test]
    fn non_image_returns_empty() {
        let risks = detect_metadata_risks("document.txt", b"plain text");
        assert!(risks.is_empty());
    }

    #[test]
    fn truncate_utf8_preserves_boundary() {
        let s = "あいうえお"; // 15 bytes
        let result = truncate_utf8(s, 6);
        assert!(std::str::from_utf8(result.as_bytes()).is_ok());
    }

    #[test]
    fn ooxml_without_creator_is_clean() {
        // PK\x03\x04 ヘッダーのみで dc:creator なし
        let docx = b"PK\x03\x04some-zip-content-without-creator";
        let risks = detect_ooxml_metadata(docx);
        assert!(risks.is_empty());
    }

    #[test]
    fn ooxml_with_creator_detected() {
        let mut docx = b"PK\x03\x04".to_vec();
        docx.extend_from_slice(b"...some content...dc:creator>Alice Smith</dc:creator...");
        let risks = detect_ooxml_metadata(&docx);
        assert!(risks.iter().any(|r| matches!(r, MetadataRisk::OoxmlAuthorInfo { .. })));
    }

    #[test]
    fn pdf_field_excerpt_truncated_at_64_bytes() {
        let long_name = "A".repeat(200);
        let pdf = format!("%PDF-1.4\n/Author ({long_name})\n");
        let risks = detect_pdf_metadata(pdf.as_bytes());
        if let Some(MetadataRisk::PdfAuthorInfo { excerpt }) = risks.first() {
            assert!(excerpt.len() <= 70, "抜粋が長すぎる: {}", excerpt.len());
        }
    }
}
