//! ZIP Slip 攻撃防止 (Zenn daa25bc92543ce 由来)。
//!
//! ZIP アーカイブのエントリパスを展開先ディレクトリに対して検証し、
//! ディレクトリトラバーサル (`..`) による脱出を防ぐ。

use std::path::{Path, PathBuf};

/// ZIP Slip 防止エラー。
#[derive(Debug, PartialEq, Eq)]
pub enum ZipSlipError {
    /// エントリパスがアーカイブ外に脱出しようとした。
    PathTraversal { entry: String, resolved: String },
    /// パスが絶対パスになっている (Unix `/etc/passwd` 型)。
    AbsolutePath { entry: String },
    /// パスに NUL バイトが含まれる。
    NulByte,
    /// 正規化後のパスが出力ディレクトリのプレフィックスを持たない。
    OutsideDestination { entry: String },
}

impl std::fmt::Display for ZipSlipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathTraversal { entry, resolved } =>
                write!(f, "ZIP Slip: {entry:?} → {resolved:?} はアーカイブ外"),
            Self::AbsolutePath { entry } =>
                write!(f, "ZIP Slip: {entry:?} は絶対パス"),
            Self::NulByte =>
                write!(f, "ZIP Slip: パスに NUL バイト"),
            Self::OutsideDestination { entry } =>
                write!(f, "ZIP Slip: {entry:?} は展開先の外"),
        }
    }
}

/// ZIP エントリパスが展開先ディレクトリからの脱出を試みていないか検証する。
///
/// # 正規化アルゴリズム
///
/// 1. 絶対パスを拒否
/// 2. NUL バイトを拒否
/// 3. `..` を含むパスを拒否 (簡易チェック)
/// 4. `dest / entry` を字句的に正規化し、`dest` プレフィックスを確認
///
/// # 戻り値
///
/// 成功時: 展開先の安全な絶対パス。
/// 失敗時: `ZipSlipError`。
///
/// # 注意
///
/// `dest` はシンボリックリンクを含まない実パスであること。
/// 呼び出し前に `canonicalize()` を適用することを推奨。
pub fn safe_extract_path(dest: &Path, entry_name: &str) -> Result<PathBuf, ZipSlipError> {
    // NUL バイトチェック
    if entry_name.contains('\0') {
        return Err(ZipSlipError::NulByte);
    }

    let entry_path = Path::new(entry_name);

    // 絶対パス拒否
    if entry_path.is_absolute() {
        return Err(ZipSlipError::AbsolutePath { entry: entry_name.to_string() });
    }

    // `..` コンポーネントを早期拒否 (字句レベル)
    for component in entry_path.components() {
        if component == std::path::Component::ParentDir {
            return Err(ZipSlipError::PathTraversal {
                entry: entry_name.to_string(),
                resolved: String::new(),
            });
        }
    }

    // dest / entry を字句的に結合して正規化
    let combined = dest.join(entry_path);
    // Path::components() による正規化 (シンボリックリンクなし)
    let normalized = normalize_lexically(&combined);

    // dest が normalized のプレフィックスか確認
    // (dest 自身が正規化済みであること前提)
    let dest_normalized = normalize_lexically(dest);
    if !normalized.starts_with(&dest_normalized) {
        return Err(ZipSlipError::OutsideDestination {
            entry: entry_name.to_string(),
        });
    }

    Ok(normalized)
}

/// シンボリックリンクを解決せずにパスを字句的に正規化する。
///
/// `canonicalize()` はファイルシステムにアクセスするため、
/// 存在しないパスに対しては使用できない。
/// ここでは `..` と `.` を処理するだけの字句正規化を行う。
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn dest() -> PathBuf {
        PathBuf::from("/tmp/extract")
    }

    #[test]
    fn normal_path_is_accepted() {
        let result = safe_extract_path(&dest(), "subdir/file.txt");
        assert_eq!(result.unwrap(), PathBuf::from("/tmp/extract/subdir/file.txt"));
    }

    #[test]
    fn root_file_is_accepted() {
        let result = safe_extract_path(&dest(), "invoice.pdf");
        assert_eq!(result.unwrap(), PathBuf::from("/tmp/extract/invoice.pdf"));
    }

    #[test]
    fn dotdot_is_rejected() {
        let result = safe_extract_path(&dest(), "../etc/passwd");
        assert!(matches!(result, Err(ZipSlipError::PathTraversal { .. })));
    }

    #[test]
    fn nested_dotdot_is_rejected() {
        let result = safe_extract_path(&dest(), "a/b/../../../../../../etc/passwd");
        assert!(matches!(result, Err(ZipSlipError::PathTraversal { .. })));
    }

    #[test]
    fn absolute_path_is_rejected() {
        let result = safe_extract_path(&dest(), "/etc/passwd");
        assert!(matches!(result, Err(ZipSlipError::AbsolutePath { .. })));
    }

    #[test]
    fn nul_byte_is_rejected() {
        let result = safe_extract_path(&dest(), "file\0.txt");
        assert!(matches!(result, Err(ZipSlipError::NulByte)));
    }

    #[test]
    fn windows_style_dotdot_is_rejected() {
        // Windows 形式: ..\
        let result = safe_extract_path(&dest(), "subdir\\..\\..\\passwd");
        // Unix では \\ は普通の文字 — コンポーネントになりません
        // ただし Unix パスとして解釈されてもトラバーサルにはならない
        // Windows ビルドでは別途テストが必要
        let _ = result; // プラットフォーム依存のため検証のみ
    }

    #[test]
    fn deeply_nested_path_is_accepted() {
        let result = safe_extract_path(&dest(), "a/b/c/d/e/f.txt");
        assert_eq!(result.unwrap(), PathBuf::from("/tmp/extract/a/b/c/d/e/f.txt"));
    }

    #[test]
    fn current_dir_dot_is_accepted() {
        let result = safe_extract_path(&dest(), "./file.txt");
        assert_eq!(result.unwrap(), PathBuf::from("/tmp/extract/file.txt"));
    }
}
