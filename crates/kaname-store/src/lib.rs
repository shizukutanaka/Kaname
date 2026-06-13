//! kaname-store — SQLCipher 暗号化永続化層。
//!
//! - AES-256 で全データを暗号化
//! - OS Keychain でデータベースキー保管
//! - 監査ログのハッシュチェーン (SHA-256) で改ざん検出

// crates/kaname-store/src/lib.rs
//
// 暗号化ローカルストア。SQLite + SQLCipher (rusqlite)。
//
// todo!() をすべて実装済み。
// 依存: rusqlite = { version = "0.32", features = ["sqlcipher", "bundled-sqlcipher"] }
//
// 設計 (ADR-007):
//   - SQLCipher パラメータ: PAGE_SIZE=4096, KDF_ITER=256000, HMAC=SHA512
//   - DB キーは OS Keyring / Secure Enclave に保存 (ハンドルのみ保持)
//   - マイグレーション: 追加のみ (破壊的変更は shadow table + copy + rename)
//   - audit_log は BEFORE UPDATE/DELETE トリガーで不変

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![allow(missing_docs)]

use rusqlite::{Connection, params};
use sha2::{Sha256, Digest};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

// ============================================================================
// SQLCipher パラメータ (ADR-007 で固定)
// ============================================================================

/// SQLCipher 暗号化パラメータ (ADR-007 で固定。変更は承認フロー必須)。
pub struct SqlCipherParams;

impl SqlCipherParams {
    /// SQLCipher ページサイズ (bytes)。
    pub const PAGE_SIZE: u32    = 4096;
    /// PBKDF2 反復回数。
    pub const KDF_ITER:  u32    = 256_000;
    /// HMAC アルゴリズム。
    pub const HMAC_ALG:  &'static str = "HMAC_SHA512";
    /// KDF アルゴリズム。
    pub const KDF_ALG:   &'static str = "PBKDF2_HMAC_SHA512";
    /// プレーンテキストヘッダーサイズ (bytes)。
    pub const PLAINTEXT_HEADER_SIZE: u32 = 32;

    /// DB オープン直後に実行するプラグマシーケンス。
    pub fn apply(conn: &Connection, key_hex: &str) -> Result<(), rusqlite::Error> {
        conn.execute_batch(&format!(
            "PRAGMA key = \"x'{key_hex}'\";\
             PRAGMA cipher_page_size = {PAGE_SIZE};\
             PRAGMA kdf_iter = {KDF_ITER};\
             PRAGMA cipher_hmac_algorithm = {HMAC_ALG};\
             PRAGMA cipher_kdf_algorithm = {KDF_ALG};\
             PRAGMA cipher_plaintext_header_size = {HEADER};\
             PRAGMA cipher_memory_security = ON;\
             PRAGMA journal_mode = WAL;\
             PRAGMA synchronous = FULL;\
             PRAGMA foreign_keys = ON;",
            key_hex   = key_hex,
            PAGE_SIZE = Self::PAGE_SIZE,
            KDF_ITER  = Self::KDF_ITER,
            HMAC_ALG  = Self::HMAC_ALG,
            KDF_ALG   = Self::KDF_ALG,
            HEADER    = Self::PLAINTEXT_HEADER_SIZE,
        ))
    }
}

// ============================================================================
// スキーマ (全テーブル定義)
// ============================================================================

/// スキーマ V0: 初期テーブル定義。
pub const SCHEMA_V0: &str = r#"
CREATE TABLE IF NOT EXISTS accounts (
    id           TEXT PRIMARY KEY NOT NULL,
    email        TEXT UNIQUE NOT NULL,
    display_name TEXT,
    identity_fp  TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    deleted_at   TEXT
);
CREATE TABLE IF NOT EXISTS mailboxes (
    id            TEXT PRIMARY KEY NOT NULL,
    account_id    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    parent_id     TEXT REFERENCES mailboxes(id) ON DELETE SET NULL,
    role          TEXT,
    name          TEXT NOT NULL,
    sort_order    INTEGER NOT NULL DEFAULT 0,
    total_emails  INTEGER NOT NULL DEFAULT 0,
    unread_emails INTEGER NOT NULL DEFAULT 0,
    jmap_id       TEXT,
    jmap_state    TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_mailboxes_account ON mailboxes(account_id);
CREATE TABLE IF NOT EXISTS messages (
    id              TEXT PRIMARY KEY NOT NULL,
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    mailbox_id      TEXT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    message_id      TEXT,
    thread_id       TEXT,
    from_addr       TEXT NOT NULL,
    from_name       TEXT,
    to_addrs        TEXT NOT NULL,
    cc_addrs        TEXT,
    subject         TEXT,
    sent_at         TEXT,
    received_at     TEXT,
    is_read         INTEGER NOT NULL DEFAULT 0,
    is_starred      INTEGER NOT NULL DEFAULT 0,
    is_draft        INTEGER NOT NULL DEFAULT 0,
    is_deleted      INTEGER NOT NULL DEFAULT 0,
    spf_result      TEXT,
    dkim_result     TEXT,
    dmarc_result    TEXT,
    bec_score       REAL,
    bec_verdict     TEXT,
    body_encrypted  BLOB,
    body_preview    TEXT,
    mls_conv_id     TEXT,
    mls_epoch       INTEGER,
    mls_sender_verified INTEGER NOT NULL DEFAULT 0,
    jmap_id         TEXT,
    size_bytes      INTEGER,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_messages_mailbox ON messages(mailbox_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_thread  ON messages(thread_id);
CREATE INDEX IF NOT EXISTS idx_messages_unread  ON messages(account_id, is_read, received_at DESC);
CREATE TABLE IF NOT EXISTS attachments (
    id            TEXT PRIMARY KEY NOT NULL,
    message_id    TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    filename      TEXT NOT NULL,
    declared_mime TEXT NOT NULL,
    detected_mime TEXT,
    size_bytes    INTEGER NOT NULL,
    content_id    TEXT,
    scan_verdict  TEXT,
    scan_signature TEXT,
    blob_path     TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE TABLE IF NOT EXISTS mls_conversations (
    id              TEXT PRIMARY KEY NOT NULL,
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,
    current_epoch   INTEGER NOT NULL DEFAULT 0,
    group_state     BLOB NOT NULL,
    safety_number   TEXT,
    safety_number_verified_at TEXT,
    display_name    TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE TABLE IF NOT EXISTS contacts (
    id           TEXT PRIMARY KEY NOT NULL,
    account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email        TEXT NOT NULL,
    display_name TEXT,
    trust_level  TEXT NOT NULL DEFAULT 'unknown',
    known_fp     TEXT,
    fp_verified_at TEXT,
    first_seen_at TEXT,
    last_seen_at  TEXT,
    message_count INTEGER NOT NULL DEFAULT 0,
    topic_summary TEXT,
    UNIQUE(account_id, email)
);
CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(account_id, email);
CREATE TABLE IF NOT EXISTS dlp_rules (
    id             TEXT PRIMARY KEY NOT NULL,
    account_id     TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1,
    condition_json TEXT NOT NULL,
    action         TEXT NOT NULL,
    direction      TEXT NOT NULL DEFAULT 'OUTBOUND',
    priority       INTEGER NOT NULL DEFAULT 100,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE TABLE IF NOT EXISTS audit_log (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id   TEXT,
    event_type   TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    prev_hash    TEXT NOT NULL DEFAULT '',
    hash         TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
    BEFORE UPDATE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log は不変です'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
    BEFORE DELETE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log は不変です'); END;
CREATE TABLE IF NOT EXISTS jmap_state (
    account_id     TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    session_url    TEXT NOT NULL,
    mailbox_state  TEXT,
    email_state    TEXT,
    thread_state   TEXT,
    identity_state TEXT,
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE TABLE IF NOT EXISTS settings (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    PRIMARY KEY (account_id, key)
);
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
INSERT OR IGNORE INTO schema_migrations (version) VALUES (0);
"#;

// ============================================================================
// SenderProfile — BEC 判定用の送信者データ
// ============================================================================

/// BEC 評価に必要な送信者プロフィール。
///
/// `contacts` テーブルの一行を表す。`kaname-bec::SenderHistory` を
/// 組み立てるためのデータソース。
#[derive(Debug, Clone)]
pub struct SenderProfile {
    /// これまでに受信したメッセージ数。
    pub message_count: u32,
    /// 典型トピックのサマリ (BEC のトピック異常検出に使用)。
    pub topic_summary: Option<String>,
    /// ユーザーが「検証済み」とマークしたか。
    pub user_verified: bool,
    /// 初回受信時刻 (RFC 3339)。
    pub first_seen_at: Option<String>,
    /// 最終受信時刻 (RFC 3339)。
    pub last_seen_at: Option<String>,
}

// ============================================================================
// ストアハンドル
// ============================================================================

/// 暗号化ストアへの不透明ハンドル。
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    path: PathBuf,
}

impl Store {
    /// 暗号化ストアを開くか作成する。
    ///
    /// `key_hex` は 64 文字の hex 文字列 (32 バイト = 256 ビット)。
    pub async fn open(path: &Path, key_hex: &str) -> Result<Self, StoreError> {
        if key_hex.len() != 64 || !key_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(StoreError::InvalidKey);
        }

        let conn = Connection::open(path)
            .map_err(|e| StoreError::Db(e.to_string()))?;

        // SQLCipher パラメータを適用
        SqlCipherParams::apply(&conn, key_hex)
            .map_err(|e| StoreError::Db(format!("SQLCipher 設定失敗: {}", e)))?;

        // インテグリティチェック
        let ok: String = conn.query_row(
            "PRAGMA integrity_check;",
            [],
            |row| row.get(0),
        ).map_err(|e| StoreError::Db(e.to_string()))?;

        if ok != "ok" {
            return Err(StoreError::IntegrityCheckFailed);
        }

        tracing::info!(path = %path.display(), "ストア開通");

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path: path.to_owned(),
        })
    }

    /// 保留中の全マイグレーションを実行する。
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        // 現在のバージョンを確認
        let version: i64 = conn.query_row(
            "SELECT COALESCE(MAX(version), -1) FROM schema_migrations;",
            [],
            |row| row.get(0),
        ).unwrap_or(-1);

        if version < 0 {
            // V0 を適用
            conn.execute_batch(SCHEMA_V0)
                .map_err(|e| StoreError::Migration(0, e.to_string()))?;
            tracing::info!("マイグレーション V0 適用完了");
        }

        // 将来のマイグレーションはここに追加
        // if version < 1 { conn.execute_batch(SCHEMA_V1)?; }

        Ok(())
    }

    /// DB を新しいキーに再キー設定する (sqlcipher_export パターン)。
    pub async fn rekey(&self, new_key_hex: &str) -> Result<(), StoreError> {
        if new_key_hex.len() != 64 || !new_key_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(StoreError::InvalidKey);
        }

        let conn = self.conn.lock().map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        // tmpファイルにエクスポートしてから上書き
        let tmp_path = self.path.with_extension("kmdb.tmp");
        conn.execute_batch(&format!(
            "ATTACH DATABASE '{}' AS tmp KEY \"x'{}'\";\
             SELECT sqlcipher_export('tmp');\
             DETACH DATABASE tmp;",
            tmp_path.display(),
            new_key_hex,
        )).map_err(|e| StoreError::Db(e.to_string()))?;

        // tmp を本番ファイルに置き換え
        std::fs::rename(&tmp_path, &self.path)
            .map_err(StoreError::Io)?;

        tracing::info!("DB 再キー設定完了");
        Ok(())
    }

    /// 不変の監査ログにエントリを追加する。
    pub async fn audit(
        &self,
        account_id:  Option<&str>,
        event_type:  &str,
        payload:     &serde_json::Value,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        // 前のエントリのハッシュを取得
        let prev_hash: String = conn.query_row(
            "SELECT COALESCE(hash, '') FROM audit_log ORDER BY seq DESC LIMIT 1;",
            [],
            |row| row.get(0),
        ).unwrap_or_default();

        let payload_json = serde_json::to_string(payload)
            .map_err(|e| StoreError::Db(e.to_string()))?;

        // ハッシュ計算: SHA-256(prev_hash || event_type || payload_json)
        let hash_input = format!("{}{}{}", prev_hash, event_type, payload_json);
        let hash = sha256_hex(hash_input.as_bytes());

        conn.execute(
            "INSERT INTO audit_log (account_id, event_type, payload_json, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5);",
            params![account_id, event_type, payload_json, prev_hash, hash],
        ).map_err(|e| StoreError::Db(e.to_string()))?;

        Ok(())
    }

    /// 監査ログのハッシュチェーンを検証する。
    pub async fn verify_audit_chain(&self) -> Result<bool, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        let mut stmt = conn.prepare(
            "SELECT seq, event_type, payload_json, prev_hash, hash FROM audit_log ORDER BY seq;"
        ).map_err(|e| StoreError::Db(e.to_string()))?;

        let mut prev_hash = String::new();
        let mut valid = true;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        }).map_err(|e| StoreError::Db(e.to_string()))?;

        for row in rows {
            let (seq, event_type, payload_json, stored_prev, stored_hash) =
                row.map_err(|e| StoreError::Db(e.to_string()))?;

            if stored_prev != prev_hash {
                tracing::error!(seq, "監査ログのハッシュチェーンが破損 (prev_hash 不一致)");
                valid = false;
                break;
            }

            let expected = sha256_hex(format!("{}{}{}", prev_hash, event_type, payload_json).as_bytes());
            if expected != stored_hash {
                tracing::error!(seq, "監査ログのハッシュが不正");
                return Err(StoreError::AuditChainBroken(seq));
            }

            prev_hash = stored_hash;
        }

        Ok(valid)
    }

    /// 設定値を取得する。
    pub async fn get_setting(
        &self, account_id: &str, key: &str,
    ) -> Result<Option<String>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        let result = conn.query_row(
            "SELECT value FROM settings WHERE account_id = ?1 AND key = ?2;",
            params![account_id, key],
            |row| row.get::<_, String>(0),
        );

        match result {
            Ok(v)                                    => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e)                                    => Err(StoreError::Db(e.to_string())),
        }
    }

    /// 設定値を保存する。
    pub async fn set_setting(
        &self, account_id: &str, key: &str, value: &str,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        conn.execute(
            "INSERT INTO settings (account_id, key, value, updated_at)
             VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
             ON CONFLICT (account_id, key) DO UPDATE SET value = ?3, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now');",
            params![account_id, key, value],
        ).map_err(|e| StoreError::Db(e.to_string()))?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // SenderProfile — BEC 判定用の送信者プロフィール
    // -----------------------------------------------------------------------

    /// 送信者プロフィールを取得する。
    ///
    /// `contacts` テーブルから BEC 評価に必要なフィールドを返す。
    /// 存在しない場合は `Ok(None)`。
    pub async fn get_sender_profile(
        &self,
        account_id: &str,
        email: &str,
    ) -> Result<Option<SenderProfile>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        let result = conn.query_row(
            "SELECT message_count, topic_summary, \
                    (CASE trust_level WHEN 'verified' THEN 1 ELSE 0 END) AS user_verified, \
                    first_seen_at, last_seen_at \
             FROM contacts \
             WHERE account_id = ?1 AND email = ?2;",
            params![account_id, email],
            |row| {
                Ok(SenderProfile {
                    message_count: row.get::<_, u32>(0)?,
                    topic_summary: row.get::<_, Option<String>>(1)?,
                    user_verified: row.get::<_, bool>(2)?,
                    first_seen_at: row.get::<_, Option<String>>(3)?,
                    last_seen_at:  row.get::<_, Option<String>>(4)?,
                })
            },
        );

        match result {
            Ok(p)                                    => Ok(Some(p)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e)                                    => Err(StoreError::Db(e.to_string())),
        }
    }

    /// 受信メールを記録して送信者プロフィールを更新する。
    ///
    /// - 初回受信: 新規レコードを INSERT
    /// - 以降: `message_count++`、`last_seen_at` 更新
    /// - `new_topic_summary` を渡した場合は `topic_summary` を上書き
    ///
    /// 「受信箱全体を読む」ことなく `topic_summary` を呼び出し元が
    /// 管理できる (北極星 I1 を維持)。
    pub async fn record_received(
        &self,
        account_id:        &str,
        email:             &str,
        display_name:      Option<&str>,
        new_topic_summary: Option<&str>,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        let id = sha256_hex(format!("{account_id}:{email}").as_bytes());

        conn.execute(
            "INSERT INTO contacts \
                (id, account_id, email, display_name, message_count, topic_summary, \
                 first_seen_at, last_seen_at) \
             VALUES (?1, ?2, ?3, ?4, 1, ?5, \
                     strftime('%Y-%m-%dT%H:%M:%SZ','now'), \
                     strftime('%Y-%m-%dT%H:%M:%SZ','now')) \
             ON CONFLICT (account_id, email) DO UPDATE SET \
                message_count = message_count + 1, \
                last_seen_at  = strftime('%Y-%m-%dT%H:%M:%SZ','now'), \
                topic_summary = COALESCE(?5, topic_summary), \
                display_name  = COALESCE(?4, display_name);",
            params![id, account_id, email, display_name, new_topic_summary],
        ).map_err(|e| StoreError::Db(e.to_string()))?;

        Ok(())
    }

    /// 送信者を「検証済み」としてマークする。
    ///
    /// BEC リスクスコアを `-0.20` 押し下げる `user_verified` フラグを設定。
    pub async fn mark_sender_verified(
        &self,
        account_id: &str,
        email:      &str,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        let rows = conn.execute(
            "UPDATE contacts SET trust_level = 'verified' \
             WHERE account_id = ?1 AND email = ?2;",
            params![account_id, email],
        ).map_err(|e| StoreError::Db(e.to_string()))?;

        if rows == 0 {
            return Err(StoreError::Db(format!("送信者が見つかりません: {email}")));
        }

        Ok(())
    }

    /// JMAP 同期状態を更新する。
    pub async fn update_jmap_state(
        &self,
        account_id:    &str,
        session_url:   &str,
        mailbox_state: Option<&str>,
        email_state:   Option<&str>,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        conn.execute(
            "INSERT INTO jmap_state (account_id, session_url, mailbox_state, email_state, updated_at)
             VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
             ON CONFLICT (account_id) DO UPDATE SET
               session_url   = ?2,
               mailbox_state = COALESCE(?3, mailbox_state),
               email_state   = COALESCE(?4, email_state),
               updated_at    = strftime('%Y-%m-%dT%H:%M:%SZ','now');",
            params![account_id, session_url, mailbox_state, email_state],
        ).map_err(|e| StoreError::Db(e.to_string()))?;

        Ok(())
    }
}

// ============================================================================
// SHA-256 プレースホルダー (本番: ring クレートを使用)
// ============================================================================

fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

// ============================================================================
// エラー
// ============================================================================

/// ストレージ層で発生するエラー。
#[derive(Debug, Error)]
pub enum StoreError {
    /// 暗号化キーが 64 文字の hex 文字列でない。
    #[error("無効なキー: 64 文字の hex が必要")]
    InvalidKey,

    /// SQLite / SQLCipher の操作エラー。
    #[error("DB エラー: {0}")]
    Db(String),

    /// スキーママイグレーション失敗。
    #[error("マイグレーション失敗 (V{0}): {1}")]
    Migration(u32, String),

    /// PRAGMA integrity_check が FAIL を返した。
    #[error("インテグリティチェック失敗")]
    IntegrityCheckFailed,

    /// 監査ログの SHA-256 ハッシュチェーンが破損している。
    #[error("監査ログのハッシュチェーン破損 (seq={0})")]
    AuditChainBroken(i64),

    /// ファイル I/O エラー。
    #[error("IO エラー: {0}")]
    Io(#[from] std::io::Error),
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn sqlcipher_パラメータが固定値を持つ() {
        assert_eq!(SqlCipherParams::PAGE_SIZE, 4096);
        assert_eq!(SqlCipherParams::KDF_ITER,  256_000);
        assert_eq!(SqlCipherParams::HMAC_ALG,  "HMAC_SHA512");
    }

    #[test]
    fn スキーマが全テーブルを含む() {
        for t in &[
            "accounts", "mailboxes", "messages", "attachments",
            "mls_conversations", "contacts", "dlp_rules",
            "audit_log", "jmap_state", "settings", "schema_migrations",
        ] {
            assert!(
                SCHEMA_V0.contains(&format!("CREATE TABLE IF NOT EXISTS {}", t)),
                "テーブル {} が SCHEMA_V0 に存在しない", t
            );
        }
    }

    #[test]
    fn 監査ログ不変トリガーが存在する() {
        assert!(SCHEMA_V0.contains("audit_log_no_update"));
        assert!(SCHEMA_V0.contains("audit_log_no_delete"));
        assert!(SCHEMA_V0.contains("audit_log は不変です"));
    }

    #[tokio::test]
    async fn 無効なキーを拒否する() {
        let r = Store::open(Path::new("/tmp/test.kmdb"), "too-short").await;
        assert!(matches!(r, Err(StoreError::InvalidKey)));

        // 非 hex 文字
        let r2 = Store::open(Path::new("/tmp/test.kmdb"), &"G".repeat(64)).await;
        assert!(matches!(r2, Err(StoreError::InvalidKey)));
    }

    #[test]
    fn sha256_hex_が32バイトを返す() {
        let h = sha256_hex(b"test");
        assert_eq!(h.len(), 64); // 32 バイト = 64 hex 文字
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha256_hex_が決定論的() {
        assert_eq!(sha256_hex(b"hello"), sha256_hex(b"hello"));
        assert_ne!(sha256_hex(b"hello"), sha256_hex(b"world"));
    }

    #[test]
    fn sha256_hex_既知値() {
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(sha256_hex(b"abc"), expected);
    }

    // -----------------------------------------------------------------------
    // SenderProfile テスト
    // -----------------------------------------------------------------------

    /// テスト用アカウントを contacts FK 制約のために作成する。
    async fn seed_account(store: &Store, account_id: &str) {
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO accounts (id, email, identity_fp) \
             VALUES (?1, ?1 || '@test.invalid', 'fp');",
            params![account_id],
        ).unwrap();
    }

    #[tokio::test]
    async fn sender_profile_初回受信で作成される() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64)).await.unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        store.record_received("acct1", "alice@corp.com", Some("Alice"), None).await.unwrap();

        let p = store.get_sender_profile("acct1", "alice@corp.com").await.unwrap();
        let p = p.expect("レコードが存在するはず");
        assert_eq!(p.message_count, 1);
        assert!(!p.user_verified);
        assert!(p.topic_summary.is_none());
    }

    #[tokio::test]
    async fn sender_profile_受信回数が累積される() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64)).await.unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        for _ in 0..5 {
            store.record_received("acct1", "bob@corp.com", None, None).await.unwrap();
        }

        let p = store.get_sender_profile("acct1", "bob@corp.com").await.unwrap().unwrap();
        assert_eq!(p.message_count, 5);
    }

    #[tokio::test]
    async fn sender_profile_topic_summaryを更新できる() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64)).await.unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        store.record_received("acct1", "cfo@corp.com", None, None).await.unwrap();
        store.record_received("acct1", "cfo@corp.com", None, Some("財務 予算 請求書")).await.unwrap();

        let p = store.get_sender_profile("acct1", "cfo@corp.com").await.unwrap().unwrap();
        assert_eq!(p.topic_summary.as_deref(), Some("財務 予算 請求書"));
        assert_eq!(p.message_count, 2);
    }

    #[tokio::test]
    async fn sender_profile_verified_markで信頼済みになる() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64)).await.unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        store.record_received("acct1", "dave@corp.com", None, None).await.unwrap();
        store.mark_sender_verified("acct1", "dave@corp.com").await.unwrap();

        let p = store.get_sender_profile("acct1", "dave@corp.com").await.unwrap().unwrap();
        assert!(p.user_verified);
    }

    #[tokio::test]
    async fn sender_profile_存在しない場合none() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64)).await.unwrap();
        store.migrate().await.unwrap();

        let p = store.get_sender_profile("acct1", "nobody@corp.com").await.unwrap();
        assert!(p.is_none());
    }

    #[tokio::test]
    async fn sender_profile_アカウント分離() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64)).await.unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;
        seed_account(&store, "acct2").await;

        store.record_received("acct1", "shared@corp.com", None, None).await.unwrap();
        store.record_received("acct2", "shared@corp.com", None, None).await.unwrap();
        store.record_received("acct2", "shared@corp.com", None, None).await.unwrap();

        let p1 = store.get_sender_profile("acct1", "shared@corp.com").await.unwrap().unwrap();
        let p2 = store.get_sender_profile("acct2", "shared@corp.com").await.unwrap().unwrap();
        assert_eq!(p1.message_count, 1);
        assert_eq!(p2.message_count, 2);
    }
}
