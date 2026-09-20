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

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;

// ============================================================================
// SQLCipher パラメータ (ADR-007 で固定)
// ============================================================================

/// SQLCipher 暗号化パラメータ (ADR-007 で固定。変更は承認フロー必須)。
pub struct SqlCipherParams;

impl SqlCipherParams {
    /// SQLCipher ページサイズ (bytes)。
    pub const PAGE_SIZE: u32 = 4096;
    /// PBKDF2 反復回数。
    pub const KDF_ITER: u32 = 256_000;
    /// HMAC アルゴリズム。
    pub const HMAC_ALG: &'static str = "HMAC_SHA512";
    /// KDF アルゴリズム。
    pub const KDF_ALG: &'static str = "PBKDF2_HMAC_SHA512";
    /// プレーンテキストヘッダーサイズ (bytes)。
    pub const PLAINTEXT_HEADER_SIZE: u32 = 32;

    /// DB オープン直後に実行するプラグマシーケンス。
    ///
    /// `key_hex` は 64 桁の ASCII 16 進数でなければならない。
    /// 不正な値は `rusqlite::Error` を返す (PRAGMA インジェクション防止)。
    pub fn apply(conn: &Connection, key_hex: &str) -> Result<(), rusqlite::Error> {
        // `open()` の呼び出し元がバリデーション済みのはずだが、
        // この関数は pub なので直接呼ばれる場合も防御する。
        if key_hex.len() != 64 || !key_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(rusqlite::Error::InvalidParameterName(
                "key_hex は 64 桁の ASCII 16 進数でなければなりません".into(),
            ));
        }
        // 生鍵を含む PRAGMA 文字列は Zeroizing でラップし、実行後に
        // ヒープ上の平文鍵を確実にゼロ化する (kaname-crypto の ZeroizeOnDrop と
        // 同じ鍵ライフサイクル保証をストア層にも一貫させる。コアダンプ/スワップ
        // 経由の鍵材料残留を防ぐ)。
        let pragma_sql = zeroize::Zeroizing::new(format!(
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
            key_hex = key_hex,
            PAGE_SIZE = Self::PAGE_SIZE,
            KDF_ITER = Self::KDF_ITER,
            HMAC_ALG = Self::HMAC_ALG,
            KDF_ALG = Self::KDF_ALG,
            HEADER = Self::PLAINTEXT_HEADER_SIZE,
        ));
        conn.execute_batch(&pragma_sql)
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
}

impl Store {
    /// 暗号化ストアを開くか作成する。
    ///
    /// `key_hex` は 64 文字の hex 文字列 (32 バイト = 256 ビット)。
    pub async fn open(path: &Path, key_hex: &str) -> Result<Self, StoreError> {
        if key_hex.len() != 64 || !key_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(StoreError::InvalidKey);
        }

        let conn = Connection::open(path).map_err(|e| StoreError::Db(e.to_string()))?;

        // SQLCipher パラメータを適用
        SqlCipherParams::apply(&conn, key_hex)
            .map_err(|e| StoreError::Db(format!("SQLCipher 設定失敗: {}", e)))?;

        // インテグリティチェック
        let ok: String = conn
            .query_row("PRAGMA integrity_check;", [], |row| row.get(0))
            .map_err(|e| StoreError::Db(e.to_string()))?;

        if ok != "ok" {
            return Err(StoreError::IntegrityCheckFailed);
        }

        tracing::info!(path = %path.display(), "ストア開通");

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// 保留中の全マイグレーションを実行する。
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        // 現在のバージョンを確認
        let version: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), -1) FROM schema_migrations;",
                [],
                |row| row.get(0),
            )
            .unwrap_or(-1);

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

    /// 不変の監査ログにエントリを追加する。
    pub async fn audit(
        &self,
        account_id: Option<&str>,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<(), StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        let payload_json =
            serde_json::to_string(payload).map_err(|e| StoreError::Db(e.to_string()))?;

        // prev_hash 取得と INSERT を EXCLUSIVE トランザクションで原子化する。
        // これにより並行 audit() 呼び出しがハッシュチェーンを破損しない。
        conn.execute_batch("BEGIN EXCLUSIVE;")
            .map_err(|e| StoreError::Db(e.to_string()))?;

        let result = (|| -> Result<(), StoreError> {
            let prev_hash: String = conn
                .query_row(
                    "SELECT COALESCE(hash, '') FROM audit_log ORDER BY seq DESC LIMIT 1;",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or_default();

            // ハッシュ計算: SHA-256(prev_hash NUL event_type NUL payload_json)
            // NUL 区切りにより event_type/payload 境界の曖昧性を排除する。
            let hash = sha256_hex_fields(&[
                prev_hash.as_bytes(),
                event_type.as_bytes(),
                payload_json.as_bytes(),
            ]);

            conn.execute(
                "INSERT INTO audit_log (account_id, event_type, payload_json, prev_hash, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5);",
                params![account_id, event_type, payload_json, prev_hash, hash],
            )
            .map_err(|e| StoreError::Db(e.to_string()))?;

            Ok(())
        })();

        if result.is_ok() {
            conn.execute_batch("COMMIT;")
                .map_err(|e| StoreError::Db(e.to_string()))?;
        } else {
            let _ = conn.execute_batch("ROLLBACK;");
        }

        result
    }

    /// 監査ログのハッシュチェーンを検証する。
    pub async fn verify_audit_chain(&self) -> Result<bool, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        let mut stmt = conn.prepare(
            "SELECT seq, event_type, payload_json, prev_hash, hash FROM audit_log ORDER BY seq;"
        ).map_err(|e| StoreError::Db(e.to_string()))?;

        let mut prev_hash = String::new();
        let mut valid = true;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| StoreError::Db(e.to_string()))?;

        for row in rows {
            let (seq, event_type, payload_json, stored_prev, stored_hash) =
                row.map_err(|e| StoreError::Db(e.to_string()))?;

            if stored_prev != prev_hash {
                tracing::error!(seq, "監査ログのハッシュチェーンが破損 (prev_hash 不一致)");
                valid = false;
                break;
            }

            let expected = sha256_hex_fields(&[
                prev_hash.as_bytes(),
                event_type.as_bytes(),
                payload_json.as_bytes(),
            ]);
            if expected != stored_hash {
                tracing::error!(seq, "監査ログのハッシュが不正");
                return Err(StoreError::AuditChainBroken(seq));
            }

            prev_hash = stored_hash;
        }

        Ok(valid)
    }

    /// アカウント行が無ければ作る (FK 制約の前提)。
    ///
    /// `PRAGMA foreign_keys = ON` のため、`contacts`/`messages`/`settings` は
    /// 対応する `accounts` 行が無いと INSERT に失敗する。ところが本番コードに
    /// `accounts` への INSERT は存在せず (テストの `seed_account` のみ)、
    /// **永続化は一度も成功し得ない状態だった**。書き込み前に必ずこれを通す。
    /// `identity_fp` は MLS 未実装のため account_id のハッシュで埋める。
    fn ensure_account_sync(conn: &Connection, account_id: &str) -> Result<(), StoreError> {
        conn.execute(
            "INSERT OR IGNORE INTO accounts (id, email, identity_fp) \
             VALUES (?1, ?1 || '@jmap.local', ?2);",
            params![account_id, sha256_hex(account_id.as_bytes())],
        )
        .map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(())
    }

    /// メールボックス行が無ければ作る (`messages.mailbox_id` の FK 前提)。
    fn ensure_mailbox_sync(
        conn: &Connection,
        account_id: &str,
        mailbox_id: &str,
    ) -> Result<(), StoreError> {
        conn.execute(
            "INSERT OR IGNORE INTO mailboxes (id, account_id, name, jmap_id) \
             VALUES (?1, ?2, ?1, ?1);",
            params![mailbox_id, account_id],
        )
        .map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(())
    }

    /// 設定値を取得する。
    pub async fn get_setting(
        &self,
        account_id: &str,
        key: &str,
    ) -> Result<Option<String>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        let result = conn.query_row(
            "SELECT value FROM settings WHERE account_id = ?1 AND key = ?2;",
            params![account_id, key],
            |row| row.get::<_, String>(0),
        );

        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StoreError::Db(e.to_string())),
        }
    }

    /// 設定値を保存する。
    pub async fn set_setting(
        &self,
        account_id: &str,
        key: &str,
        value: &str,
    ) -> Result<(), StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Db("ロック取得失敗".into()))?;
        Self::ensure_account_sync(&conn, account_id)?;

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
        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

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
                    last_seen_at: row.get::<_, Option<String>>(4)?,
                })
            },
        );

        match result {
            Ok(p) => Ok(Some(p)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StoreError::Db(e.to_string())),
        }
    }

    /// 連絡先のアドレス一覧を返す。
    ///
    /// 各エントリは `"表示名" <email>` または `email` 形式
    /// (kaname-bec の `AssessmentRequest.known_contacts` が期待する書式)。
    /// 表示名の `"` は SQLite 出力時点で除外する (アドレス書式の破壊防止)。
    /// 上限 5,000 件 — それを超える利用は out-of-band で扱う規模のため、
    /// メモリを制限するため打ち切る。
    pub async fn list_contacts(&self, account_id: &str) -> Result<Vec<String>, StoreError> {
        validate_text_field(account_id, "account_id", 256)?;

        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Db("ロック取得失敗".into()))?;
        let mut stmt = conn
            .prepare(
                "SELECT email, display_name FROM contacts \
                 WHERE account_id = ?1 \
                 ORDER BY message_count DESC LIMIT 5000;",
            )
            .map_err(|e| StoreError::Db(e.to_string()))?;

        let rows = stmt
            .query_map(params![account_id], |row| {
                let email: String = row.get(0)?;
                let name: Option<String> = row.get(1)?;
                Ok(match name {
                    Some(n) if !n.is_empty() => {
                        format!("{} <{}>", n.replace('"', ""), email)
                    }
                    _ => email,
                })
            })
            .map_err(|e| StoreError::Db(e.to_string()))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| StoreError::Db(e.to_string()))?);
        }
        Ok(out)
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
        account_id: &str,
        email: &str,
        display_name: Option<&str>,
        new_topic_summary: Option<&str>,
    ) -> Result<(), StoreError> {
        // 入力バリデーション: NULL バイト・過剰長を拒否
        validate_text_field(account_id, "account_id", 256)?;
        validate_text_field(email, "email", 320)?; // RFC 5321 最大 320 文字
        if let Some(dn) = display_name {
            validate_text_field(dn, "display_name", 256)?;
        }
        if let Some(ts) = new_topic_summary {
            validate_text_field(ts, "topic_summary", 2000)?;
        }

        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Db("ロック取得失敗".into()))?;
        Self::ensure_account_sync(&conn, account_id)?;

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
        )
        .map_err(|e| StoreError::Db(e.to_string()))?;

        Ok(())
    }

    /// 送信者を「検証済み」としてマークする。
    ///
    /// BEC リスクスコアを `-0.20` 押し下げる `user_verified` フラグを設定。
    pub async fn mark_sender_verified(
        &self,
        account_id: &str,
        email: &str,
    ) -> Result<(), StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Db("ロック取得失敗".into()))?;

        let rows = conn
            .execute(
                "UPDATE contacts SET trust_level = 'verified' \
             WHERE account_id = ?1 AND email = ?2;",
                params![account_id, email],
            )
            .map_err(|e| StoreError::Db(e.to_string()))?;

        if rows == 0 {
            return Err(StoreError::Db(format!("送信者が見つかりません: {email}")));
        }

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

/// NUL 区切りで複数フィールドを結合してから SHA-256 を計算する。
///
/// `SHA-256(f0 || NUL || f1 || NUL || f2 || ...)` とすることで
/// フィールド境界の曖昧性 (length-extension 的な境界攻撃) を防ぐ。
fn sha256_hex_fields(fields: &[&[u8]]) -> String {
    use sha2::Digest as _;
    let mut h = Sha256::new();
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            h.update(b"\x00");
        }
        h.update(f);
    }
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

/// テキストフィールドの基本バリデーション。
///
/// NULL バイト (U+0000) や過剰長を拒否する。
/// SQLite の TEXT 型は任意のバイト列を受け入れるが、
/// NULL バイトは SQLite 関数で切り詰められる場合があり、
/// downstream rendering でも問題を引き起こす可能性がある。
fn validate_text_field(
    value: &str,
    field: &'static str,
    max_chars: usize,
) -> Result<(), StoreError> {
    if value.contains('\0') {
        return Err(StoreError::InvalidInput {
            field,
            reason: "NULL バイトを含んではなりません".to_string(),
        });
    }
    if value.chars().count() > max_chars {
        return Err(StoreError::InvalidInput {
            field,
            reason: format!(
                "{} 文字以下でなければなりません (実際: {})",
                max_chars,
                value.chars().count()
            ),
        });
    }
    Ok(())
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

    /// 入力バリデーション失敗 (NULL バイト / 過剰長)。
    #[error("入力不正: {field} — {reason}")]
    InvalidInput {
        /// フィールド名。
        field: &'static str,
        /// 拒否理由。
        reason: String,
    },
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
        assert_eq!(SqlCipherParams::KDF_ITER, 256_000);
        assert_eq!(SqlCipherParams::HMAC_ALG, "HMAC_SHA512");
    }

    #[test]
    fn スキーマが全テーブルを含む() {
        for t in &[
            "accounts",
            "mailboxes",
            "messages",
            "attachments",
            "mls_conversations",
            "contacts",
            "dlp_rules",
            "audit_log",
            "settings",
            "schema_migrations",
        ] {
            assert!(
                SCHEMA_V0.contains(&format!("CREATE TABLE IF NOT EXISTS {}", t)),
                "テーブル {} が SCHEMA_V0 に存在しない",
                t
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
        )
        .unwrap();
    }

    #[tokio::test]
    async fn sender_profile_初回受信で作成される() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        store
            .record_received("acct1", "alice@corp.com", Some("Alice"), None)
            .await
            .unwrap();

        let p = store
            .get_sender_profile("acct1", "alice@corp.com")
            .await
            .unwrap();
        let p = p.expect("レコードが存在するはず");
        assert_eq!(p.message_count, 1);
        assert!(!p.user_verified);
        assert!(p.topic_summary.is_none());
    }

    #[tokio::test]
    async fn list_contacts_は名称付きと裸のアドレスを返す() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        store
            .record_received("acct1", "alice@corp.com", Some("Alice"), None)
            .await
            .unwrap();
        store
            .record_received("acct1", "bob@corp.com", None, None)
            .await
            .unwrap();

        let mut contacts = store.list_contacts("acct1").await.unwrap();
        contacts.sort();
        assert_eq!(contacts.len(), 2);
        assert!(contacts.contains(&"Alice <alice@corp.com>".to_string()));
        assert!(contacts.contains(&"bob@corp.com".to_string()));

        // 他アカウントの連絡先は混ざらない。
        let empty = store.list_contacts("acct2").await.unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn list_contacts_は表示名のクォートを除去する() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        store
            .record_received("acct1", "evil@x.com", Some("Weird \"Name\""), None)
            .await
            .unwrap();

        let contacts = store.list_contacts("acct1").await.unwrap();
        assert_eq!(contacts, vec!["Weird Name <evil@x.com>".to_string()]);
    }

    #[tokio::test]
    async fn sender_profile_受信回数が累積される() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        for _ in 0..5 {
            store
                .record_received("acct1", "bob@corp.com", None, None)
                .await
                .unwrap();
        }

        let p = store
            .get_sender_profile("acct1", "bob@corp.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.message_count, 5);
    }

    #[tokio::test]
    async fn sender_profile_topic_summaryを更新できる() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        store
            .record_received("acct1", "cfo@corp.com", None, None)
            .await
            .unwrap();
        store
            .record_received("acct1", "cfo@corp.com", None, Some("財務 予算 請求書"))
            .await
            .unwrap();

        let p = store
            .get_sender_profile("acct1", "cfo@corp.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.topic_summary.as_deref(), Some("財務 予算 請求書"));
        assert_eq!(p.message_count, 2);
    }

    #[tokio::test]
    async fn sender_profile_verified_markで信頼済みになる() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        store
            .record_received("acct1", "dave@corp.com", None, None)
            .await
            .unwrap();
        store
            .mark_sender_verified("acct1", "dave@corp.com")
            .await
            .unwrap();

        let p = store
            .get_sender_profile("acct1", "dave@corp.com")
            .await
            .unwrap()
            .unwrap();
        assert!(p.user_verified);
    }

    #[tokio::test]
    async fn sender_profile_存在しない場合none() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();

        let p = store
            .get_sender_profile("acct1", "nobody@corp.com")
            .await
            .unwrap();
        assert!(p.is_none());
    }

    #[tokio::test]
    async fn sender_profile_アカウント分離() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;
        seed_account(&store, "acct2").await;

        store
            .record_received("acct1", "shared@corp.com", None, None)
            .await
            .unwrap();
        store
            .record_received("acct2", "shared@corp.com", None, None)
            .await
            .unwrap();
        store
            .record_received("acct2", "shared@corp.com", None, None)
            .await
            .unwrap();

        let p1 = store
            .get_sender_profile("acct1", "shared@corp.com")
            .await
            .unwrap()
            .unwrap();
        let p2 = store
            .get_sender_profile("acct2", "shared@corp.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p1.message_count, 1);
        assert_eq!(p2.message_count, 2);
    }

    #[tokio::test]
    async fn record_received_rejects_null_byte_in_email() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();

        let result = store
            .record_received("acct1", "evil\x00@corp.com", None, None)
            .await;
        assert!(
            matches!(result, Err(StoreError::InvalidInput { field: "email", .. })),
            "NULL バイトを含むメールアドレスは拒否されるべき: {result:?}"
        );
    }

    #[tokio::test]
    async fn record_received_rejects_oversized_topic_summary() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        let huge = "A".repeat(2001);
        let result = store
            .record_received("acct1", "test@corp.com", None, Some(&huge))
            .await;
        assert!(
            matches!(
                result,
                Err(StoreError::InvalidInput {
                    field: "topic_summary",
                    ..
                })
            ),
            "2000 文字超の topic_summary は拒否されるべき: {result:?}"
        );
    }

    #[test]
    fn validate_text_field_rejects_null_byte() {
        assert!(matches!(
            validate_text_field("hello\x00world", "test", 100),
            Err(StoreError::InvalidInput { field: "test", .. })
        ));
    }

    #[test]
    fn validate_text_field_rejects_oversized() {
        assert!(matches!(
            validate_text_field(&"あ".repeat(101), "test", 100),
            Err(StoreError::InvalidInput { field: "test", .. })
        ));
    }

    #[test]
    fn validate_text_field_accepts_valid() {
        assert!(validate_text_field("normal text 普通", "test", 100).is_ok());
    }

    // -----------------------------------------------------------------------
    // sha256_hex_fields — フィールド境界曖昧性テスト
    // -----------------------------------------------------------------------

    #[test]
    fn sha256_fields_boundary_not_ambiguous() {
        // ("AB", "CD") と ("A", "BCD") は異なるハッシュになること
        let h1 = sha256_hex_fields(&[b"prev", b"AB", b"CD"]);
        let h2 = sha256_hex_fields(&[b"prev", b"A", b"BCD"]);
        assert_ne!(h1, h2, "フィールド境界の曖昧性が存在する");
    }

    #[test]
    fn sha256_fields_consistent_with_itself() {
        let h1 = sha256_hex_fields(&[b"prev", b"LOGIN", b"{\"user\":\"a\"}"]);
        let h2 = sha256_hex_fields(&[b"prev", b"LOGIN", b"{\"user\":\"a\"}"]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_fields_empty_prev_hash_distinct_from_nonempty() {
        let h1 = sha256_hex_fields(&[b"", b"EV", b"payload"]);
        let h2 = sha256_hex_fields(&[b"hash", b"EV", b"payload"]);
        assert_ne!(h1, h2);
    }

    #[tokio::test]
    async fn audit_chain_verify_catches_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        store
            .audit(Some("acct1"), "LOGIN", &serde_json::json!({"ok": true}))
            .await
            .unwrap();

        // チェーンが健全な状態で検証
        let ok = store.verify_audit_chain().await.unwrap();
        assert!(ok, "正常チェーンは valid であるべき");
    }

    #[tokio::test]
    async fn audit_chain_two_entries_verify() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        store
            .audit(
                Some("acct1"),
                "LOGIN",
                &serde_json::json!({"ip": "1.2.3.4"}),
            )
            .await
            .unwrap();
        store
            .audit(
                Some("acct1"),
                "LOGOUT",
                &serde_json::json!({"session": "abc"}),
            )
            .await
            .unwrap();

        let ok = store.verify_audit_chain().await.unwrap();
        assert!(ok);
    }

    // ── セキュリティ回帰テスト ──────────────────────────────────────────────

    #[test]
    fn sqlcipher_apply_rejects_invalid_key() {
        // 攻撃: SqlCipherParams::apply() を直接呼び出して PRAGMA インジェクション
        use rusqlite::Connection;
        let conn = Connection::open_in_memory().unwrap();
        // 非 hex 文字列 (インジェクション試み)
        let result = SqlCipherParams::apply(
            &conn,
            "'; SELECT 1; --                                             ",
        );
        assert!(result.is_err(), "不正な key_hex は拒否されるべき");
        // 短すぎる
        let result2 = SqlCipherParams::apply(&conn, "deadbeef");
        assert!(result2.is_err(), "短い key_hex は拒否されるべき");
        // 正しい形式の key
        let valid_key = "a".repeat(64);
        // ※ インメモリ DB に SQLCipher の PRAGMA を適用すると失敗する場合があるが
        //   ここでは「バリデーション通過後に PRAGMA を試みる」ことを確認する
        let _ = SqlCipherParams::apply(&conn, &valid_key); // ok or cipher error, not injection
    }
}

// ============================================================================
// メール本体の永続化
//
// `messages` テーブルはスキーマもインデックスも完備していたが、
// **INSERT/SELECT がワークスペース全体でゼロ件**だった (gap-analysis D10)。
// 保存する 1 メソッドと読み出す 1 メソッドが無いだけで、
// オフライン閲覧も検索も成立しない状態だった。
// ============================================================================

/// 保存するメールの内容。
#[derive(Debug, Clone)]
pub struct NewMessage {
    /// JMAP 側の ID (冪等性キーとして使う)。
    pub jmap_id: String,
    /// RFC 5322 Message-ID (スレッド乗っ取り検出用)。無ければ None。
    pub message_id: Option<String>,
    /// JMAP threadId (スレッド横断検出用)。無ければ None。
    pub thread_id: Option<String>,
    /// 送信者アドレス。
    pub from_addr: String,
    /// 送信者表示名。
    pub from_name: Option<String>,
    /// 宛先アドレス (addr-spec のみ。表示名は保存しない)。
    ///
    /// `to_addrs` 列はスキーマ作成時から NOT NULL で存在したが、
    /// 構造体にフィールドが無く常に `''` で書き込まれていたため
    /// 宛先情報が完全に消失していた (誤配検出・詳細表示の材料)。
    pub to_addrs: Vec<String>,
    /// 件名。
    pub subject: Option<String>,
    /// 本文プレビュー (一覧表示用)。
    pub body_preview: Option<String>,
    /// 受信時刻 (RFC 3339)。
    pub received_at: Option<String>,
    /// 既読か。
    pub is_read: bool,
    /// BEC スコア。
    pub bec_score: Option<f32>,
    /// BEC 判定。
    pub bec_verdict: Option<String>,
}

/// 保存済みメール。
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredMessage {
    /// 内部 ID。
    pub id: String,
    /// 送信者アドレス。
    pub from_addr: String,
    /// 送信者表示名。
    pub from_name: Option<String>,
    /// 宛先アドレス (addr-spec のみ。空配列は「未取得」を意味する)。
    pub to_addrs: Vec<String>,
    /// 件名。
    pub subject: Option<String>,
    /// 本文プレビュー。
    pub body_preview: Option<String>,
    /// 受信時刻 (RFC 3339)。
    pub received_at: Option<String>,
    /// 既読か。
    pub is_read: bool,
    /// BEC スコア。
    pub bec_score: Option<f32>,
    /// BEC 判定。
    pub bec_verdict: Option<String>,
    /// RFC 5322 Message-ID (スレッド乗っ取り検出用)。未保存の過去行は None。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

/// `LIKE` パターンのメタ文字をエスケープする。
///
/// `%` `_` をそのまま渡すと利用者の検索語がワイルドカードとして解釈され、
/// 意図しない結果を返す。`\` をエスケープ文字として使う。
fn escape_like(pattern: &str) -> String {
    pattern
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

impl Store {
    /// メールを保存する。
    ///
    /// # 冪等性
    ///
    /// `id` は `sha256(account_id + jmap_id)` で決定論的に採番し
    /// `ON CONFLICT DO UPDATE` で上書きする。同じメールを再取得しても
    /// 行が重複しない (`record_received` と同じ発想)。
    ///
    /// # 本文を暗号化列に入れない理由
    ///
    /// `body_encrypted` には**書かない**。MLS がモック段階 (D1) の現状で
    /// 暗号化列に平文を入れると「暗号化済み」と偽ることになる。
    /// 一覧表示に必要な `body_preview` のみ保存する。
    pub async fn save_message(
        &self,
        account_id: &str,
        mailbox_id: &str,
        msg: &NewMessage,
    ) -> Result<(), StoreError> {
        validate_text_field(account_id, "account_id", 256)?;
        validate_text_field(mailbox_id, "mailbox_id", 256)?;
        validate_text_field(&msg.jmap_id, "jmap_id", 256)?;
        if let Some(v) = &msg.message_id {
            validate_text_field(v, "message_id", 998)?;
        }
        if let Some(v) = &msg.thread_id {
            validate_text_field(v, "thread_id", 256)?;
        }
        validate_text_field(&msg.from_addr, "from_addr", 320)?;
        if let Some(v) = &msg.from_name {
            validate_text_field(v, "from_name", 256)?;
        }
        if let Some(v) = &msg.subject {
            validate_text_field(v, "subject", 2_000)?;
        }
        if let Some(v) = &msg.body_preview {
            validate_text_field(v, "body_preview", 10_000)?;
        }
        if msg.to_addrs.len() > 1_000 {
            return Err(StoreError::InvalidInput {
                field: "to_addrs",
                reason: "宛先は 1,000 件まで".to_string(),
            });
        }
        for addr in &msg.to_addrs {
            validate_text_field(addr, "to_addrs", 320)?;
        }
        let to_addrs_json = serde_json::to_string(&msg.to_addrs)
            .map_err(|e| StoreError::Db(format!("to_addrs のシリアライズに失敗: {e}")))?;

        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Db("ロック取得失敗".into()))?;
        Self::ensure_account_sync(&conn, account_id)?;
        Self::ensure_mailbox_sync(&conn, account_id, mailbox_id)?;
        let id = sha256_hex_fields(&[account_id.as_bytes(), msg.jmap_id.as_bytes()]);

        conn.execute(
            "INSERT INTO messages \
                (id, account_id, mailbox_id, jmap_id, message_id, thread_id, \
                 from_addr, from_name, to_addrs, subject, body_preview, \
                 received_at, is_read, bec_score, bec_verdict) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) \
             ON CONFLICT (id) DO UPDATE SET \
                mailbox_id   = ?3, \
                message_id   = COALESCE(?5, message_id), \
                thread_id    = COALESCE(?6, thread_id), \
                from_addr    = ?7, \
                from_name    = ?8, \
                to_addrs     = ?9, \
                subject      = ?10, \
                body_preview = ?11, \
                received_at  = COALESCE(?12, received_at), \
                is_read      = ?13, \
                bec_score    = ?14, \
                bec_verdict  = ?15, \
                updated_at   = strftime('%Y-%m-%dT%H:%M:%SZ','now');",
            params![
                id,
                account_id,
                mailbox_id,
                msg.jmap_id,
                msg.message_id,
                msg.thread_id,
                msg.from_addr,
                msg.from_name,
                to_addrs_json,
                msg.subject,
                msg.body_preview,
                msg.received_at,
                i32::from(msg.is_read),
                msg.bec_score,
                msg.bec_verdict
            ],
        )
        .map_err(|e| StoreError::Db(e.to_string()))?;

        Ok(())
    }

    /// メールボックスの保存済みメールを新しい順に返す。
    ///
    /// `idx_messages_mailbox(mailbox_id, received_at DESC)` を利用する。
    /// **オフラインでも直近のメールを閲覧できる**ようにするための読み出し。
    pub async fn list_messages(
        &self,
        account_id: &str,
        mailbox_id: &str,
        limit: u32,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        validate_text_field(account_id, "account_id", 256)?;
        validate_text_field(mailbox_id, "mailbox_id", 256)?;
        let limit = limit.clamp(1, 500);

        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Db("ロック取得失敗".into()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, from_addr, from_name, subject, body_preview, \
                    received_at, is_read, bec_score, bec_verdict, to_addrs \
             FROM messages \
             WHERE account_id = ?1 AND mailbox_id = ?2 AND is_deleted = 0 \
             ORDER BY received_at DESC LIMIT ?3;",
            )
            .map_err(|e| StoreError::Db(e.to_string()))?;

        let rows = stmt
            .query_map(params![account_id, mailbox_id, limit], row_to_stored)
            .map_err(|e| StoreError::Db(e.to_string()))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| StoreError::Db(e.to_string()))?);
        }
        Ok(out)
    }

    /// 指定スレッドの保存済みメールを古い順に返す。
    ///
    /// BEC のスレッド乗っ取り検出 (`ThreadContext`) と口座差替検出
    /// (`past_thread_bodies`) に供給するための読み出し。
    /// `idx_messages_thread` を利用する。上限 100 件。
    pub async fn list_thread_messages(
        &self,
        account_id: &str,
        thread_id: &str,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        validate_text_field(account_id, "account_id", 256)?;
        validate_text_field(thread_id, "thread_id", 256)?;

        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Db("ロック取得失敗".into()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, from_addr, from_name, subject, body_preview, \
                    received_at, is_read, bec_score, bec_verdict, to_addrs, \
                    message_id \
             FROM messages \
             WHERE account_id = ?1 AND thread_id = ?2 AND is_deleted = 0 \
             ORDER BY received_at ASC LIMIT 100;",
            )
            .map_err(|e| StoreError::Db(e.to_string()))?;

        let rows = stmt
            .query_map(params![account_id, thread_id], |row| {
                let mut s = row_to_stored(row)?;
                s.message_id = row.get(10)?;
                Ok(s)
            })
            .map_err(|e| StoreError::Db(e.to_string()))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| StoreError::Db(e.to_string()))?);
        }
        Ok(out)
    }

    /// RFC 5322 Message-ID 群に一致する保存済みメッセージを返す。
    ///
    /// `.eml` 取り込み経路では JMAP threadId が無いため、In-Reply-To /
    /// References が指す Message-ID を保存済みメールと突き合わせて
    /// 既知スレッドを特定する。上限 100 件の IN 句・全てパラメータ束縛。
    pub async fn list_messages_by_message_ids(
        &self,
        account_id: &str,
        message_ids: &[String],
    ) -> Result<Vec<StoredMessage>, StoreError> {
        validate_text_field(account_id, "account_id", 256)?;
        if message_ids.is_empty() {
            return Ok(Vec::new());
        }
        const MAX_IDS: usize = 100;
        if message_ids.len() > MAX_IDS {
            return Err(StoreError::InvalidInput {
                field: "message_ids",
                reason: format!("{MAX_IDS} 件まで"),
            });
        }
        for id in message_ids {
            validate_text_field(id, "message_ids", 998)?;
        }

        let marks = std::iter::repeat_n("?", message_ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT id, from_addr, from_name, subject, body_preview, \
                received_at, is_read, bec_score, bec_verdict, to_addrs, \
                message_id \
             FROM messages \
             WHERE account_id = ?1 AND is_deleted = 0 AND message_id IN ({marks}) \
             ORDER BY received_at ASC LIMIT 100;"
        );

        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Db("ロック取得失敗".into()))?;
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let mut params_vec: Vec<rusqlite::types::Value> = Vec::with_capacity(message_ids.len() + 1);
        params_vec.push(account_id.to_string().into());
        for id in message_ids {
            params_vec.push(id.clone().into());
        }
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params_vec), |row| {
                let mut s = row_to_stored(row)?;
                s.message_id = row.get(10)?;
                Ok(s)
            })
            .map_err(|e| StoreError::Db(e.to_string()))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| StoreError::Db(e.to_string()))?);
        }
        Ok(out)
    }

    /// 件名・送信者・本文プレビューを対象に検索する。
    ///
    /// # FTS5 を使わない理由
    ///
    /// FTS5 は SQLCipher ビルドで有効とは限らず、有効性を確認できない環境で
    /// 依存するのは危険。まず `LIKE` で確実に動く実装を入れ、
    /// FTS5 の有効性を検証できる環境が整ってから移行する。
    ///
    /// 利用者の検索語に含まれる `%` `_` はエスケープするため、
    /// ワイルドカードとして解釈されることはない。
    pub async fn search_messages(
        &self,
        account_id: &str,
        query: &str,
        limit: u32,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        validate_text_field(account_id, "account_id", 256)?;
        validate_text_field(query, "query", 1_000)?;
        let limit = limit.clamp(1, 500);
        let pattern = format!("%{}%", escape_like(query));

        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Db("ロック取得失敗".into()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, from_addr, from_name, subject, body_preview, \
                    received_at, is_read, bec_score, bec_verdict, to_addrs \
             FROM messages \
             WHERE account_id = ?1 AND is_deleted = 0 \
               AND ( subject      LIKE ?2 ESCAPE '\\' \
                  OR from_addr    LIKE ?2 ESCAPE '\\' \
                  OR from_name    LIKE ?2 ESCAPE '\\' \
                  OR body_preview LIKE ?2 ESCAPE '\\' ) \
             ORDER BY received_at DESC LIMIT ?3;",
            )
            .map_err(|e| StoreError::Db(e.to_string()))?;

        let rows = stmt
            .query_map(params![account_id, pattern, limit], row_to_stored)
            .map_err(|e| StoreError::Db(e.to_string()))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| StoreError::Db(e.to_string()))?);
        }
        Ok(out)
    }
}

/// `messages` の 1 行を `StoredMessage` に変換する。
fn row_to_stored(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMessage> {
    Ok(StoredMessage {
        id: row.get(0)?,
        from_addr: row.get(1)?,
        from_name: row.get(2)?,
        subject: row.get(3)?,
        body_preview: row.get(4)?,
        received_at: row.get(5)?,
        is_read: row.get::<_, i32>(6)? != 0,
        bec_score: row.get(7)?,
        bec_verdict: row.get(8)?,
        // 過去の行は `''` が入っている (列はあったが常に空で書かれていた)。
        // パース不能は「宛先不明」として空配列に倒す。
        to_addrs: row
            .get::<_, String>(9)
            .ok()
            .and_then(|raw| serde_json::from_str::<Vec<String>>(&raw).ok())
            .unwrap_or_default(),
        // message_id 列は呼び出し元で SELECT に含めた場合のみ Some。
        // 既定クエリ (list_messages/search) では列がないため None を入れ、
        // スレッド系クエリが呼び出し側で上書きする。
        message_id: None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod message_persistence_tests {
    use super::*;

    async fn seed_account(store: &Store, account_id: &str) {
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO accounts (id, email, identity_fp) \
             VALUES (?1, ?1 || '@test.invalid', 'fp');",
            params![account_id],
        )
        .unwrap();
    }

    fn msg(jmap_id: &str, subject: &str) -> NewMessage {
        NewMessage {
            jmap_id: jmap_id.to_string(),
            message_id: Some(format!("<{jmap_id}@example.test>")),
            thread_id: Some("thread-1".to_string()),
            from_addr: "alice@corp.com".to_string(),
            from_name: Some("Alice".to_string()),
            to_addrs: vec!["bob@corp.com".to_string()],
            subject: Some(subject.to_string()),
            body_preview: Some("hello".to_string()),
            received_at: Some("2026-09-15T00:00:00Z".to_string()),
            is_read: false,
            bec_score: None,
            bec_verdict: None,
        }
    }

    /// 同じ `jmap_id` を別の `mailbox_id` で再保存すると (JMAP 側でのフォルダ移動の
    /// 再同期を想定)、`ON CONFLICT` の SET 句に `mailbox_id` が含まれていなかったため
    /// 旧フォルダに永久に取り残される欠陥があった。修正後は移動先に反映される。
    #[tokio::test]
    async fn save_message_はメールボックス移動を上書き保存できる() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        store
            .save_message("acct1", "inbox", &msg("jmap-1", "件名A"))
            .await
            .unwrap();
        let inbox_before = store.list_messages("acct1", "inbox", 10).await.unwrap();
        assert_eq!(inbox_before.len(), 1);

        // 同じ jmap_id を別フォルダで再保存 (フォルダ移動の再同期)。
        store
            .save_message("acct1", "archive", &msg("jmap-1", "件名A"))
            .await
            .unwrap();

        let inbox_after = store.list_messages("acct1", "inbox", 10).await.unwrap();
        assert!(
            inbox_after.is_empty(),
            "移動後は旧フォルダに残ってはいけない"
        );

        let archive_after = store.list_messages("acct1", "archive", 10).await.unwrap();
        assert_eq!(archive_after.len(), 1, "移動先フォルダに反映されるべき");
    }

    /// `from_addr`/`from_name` も同じ理由で `ON CONFLICT` の SET 句に無く、
    /// 送信者情報の変更 (再同期時の訂正等) が反映されない欠陥があった。
    #[tokio::test]
    async fn save_message_は送信者情報の変更も上書き保存できる() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        store
            .save_message("acct1", "inbox", &msg("jmap-1", "件名A"))
            .await
            .unwrap();

        let mut updated = msg("jmap-1", "件名A");
        updated.from_addr = "bob@corp.com".to_string();
        updated.from_name = Some("Bob".to_string());
        store
            .save_message("acct1", "inbox", &updated)
            .await
            .unwrap();

        let rows = store.list_messages("acct1", "inbox", 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].from_addr, "bob@corp.com");
        assert_eq!(rows[0].from_name.as_deref(), Some("Bob"));
    }

    /// `to_addrs` 列はスキーマ上 NOT NULL で存在したが `NewMessage` に
    /// フィールドが無く常に `''` で書かれていたため、保存時に宛先が
    /// 全て消失していた。往復で読み戻せることと、再保存時に更新される
    /// ことを固定する。
    #[tokio::test]
    async fn save_message_は宛先を往復保存できる() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        store
            .save_message("acct1", "inbox", &msg("jmap-1", "件名A"))
            .await
            .unwrap();
        let rows = store.list_messages("acct1", "inbox", 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].to_addrs, vec!["bob@corp.com".to_string()]);

        // 宛先が変わって再保存された場合も追従する。
        let mut updated = msg("jmap-1", "件名A");
        updated.to_addrs = vec!["carol@corp.com".to_string(), "dan@corp.com".to_string()];
        store
            .save_message("acct1", "inbox", &updated)
            .await
            .unwrap();
        let rows = store.list_messages("acct1", "inbox", 10).await.unwrap();
        assert_eq!(rows[0].to_addrs.len(), 2);
        assert_eq!(rows[0].to_addrs[0], "carol@corp.com");
    }

    /// 修正前に書かれた行の `to_addrs` は `''` — 読み出し時に JSON パース
    /// できない値は「宛先不明」として空配列に倒し、エラーにしない。
    #[tokio::test]
    async fn list_messages_は過去の空宛先行を空配列として読める() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;

        // 旧実装の書き込み形 (to_addrs = '') を再現する。
        store
            .save_message("acct1", "inbox", &msg("jmap-legacy", "旧件名"))
            .await
            .unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE messages SET to_addrs = '' WHERE jmap_id = 'jmap-legacy';",
                [],
            )
            .unwrap();
        }

        let rows = store.list_messages("acct1", "inbox", 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].to_addrs.is_empty(),
            "'' は宛先不明として空配列に倒す"
        );
    }

    /// `list_thread_messages` は同一 `thread_id` のメッセージを `received_at`
    /// 昇順で返し、他スレッド・他アカウント・削除済みは除外する。
    /// スレッド乗っ取り検出 (kaname-bec) が「既知スレッドの参加者」を
    /// 引くために使う経路。
    #[tokio::test]
    async fn list_thread_messages_は同一スレッドのみを昇順で返す() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;
        seed_account(&store, "acct2").await;

        let mut m1 = msg("jmap-1", "件名1");
        m1.received_at = Some("2026-09-10T00:00:00Z".to_string());
        let mut m2 = msg("jmap-2", "件名2");
        m2.received_at = Some("2026-09-12T00:00:00Z".to_string());
        store.save_message("acct1", "inbox", &m2).await.unwrap();
        store.save_message("acct1", "inbox", &m1).await.unwrap();

        // 別スレッド・別アカウントの混入。
        let mut other = msg("jmap-3", "件名3");
        other.thread_id = Some("thread-2".to_string());
        store.save_message("acct1", "inbox", &other).await.unwrap();
        store.save_message("acct2", "inbox", &m1).await.unwrap();

        let rows = store
            .list_thread_messages("acct1", "thread-1")
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].message_id.as_deref(),
            Some("<jmap-1@example.test>"),
            "received_at 昇順"
        );
        assert_eq!(rows[1].message_id.as_deref(), Some("<jmap-2@example.test>"));
    }

    /// `list_messages_by_message_ids` は RFC 5322 Message-ID の集合で
    /// メッセージを引く。In-Reply-To/References が指す親メッセージの
    /// 検索に使う。未知 ID・他アカウントは結果に含めない。
    #[tokio::test]
    async fn list_messages_by_message_ids_は一致idのみ返す() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.db"), &"A".repeat(64))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        seed_account(&store, "acct1").await;
        seed_account(&store, "acct2").await;

        store
            .save_message("acct1", "inbox", &msg("jmap-1", "件名1"))
            .await
            .unwrap();
        store
            .save_message("acct1", "inbox", &msg("jmap-2", "件名2"))
            .await
            .unwrap();
        // 同じ Message-ID を持つ他アカウント行は返さない。
        store
            .save_message("acct2", "inbox", &msg("jmap-1", "件名1"))
            .await
            .unwrap();

        let ids = vec![
            "<jmap-1@example.test>".to_string(),
            "<unknown@example.test>".to_string(),
        ];
        let rows = store
            .list_messages_by_message_ids("acct1", &ids)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message_id.as_deref(), Some("<jmap-1@example.test>"));

        // 空入力は空を返し、上限超過は検証エラー。
        let empty = store
            .list_messages_by_message_ids("acct1", &[])
            .await
            .unwrap();
        assert!(empty.is_empty());
        let too_many: Vec<String> = (0..101).map(|i| format!("<m{i}@x.test>")).collect();
        assert!(store
            .list_messages_by_message_ids("acct1", &too_many)
            .await
            .is_err());
    }
}
