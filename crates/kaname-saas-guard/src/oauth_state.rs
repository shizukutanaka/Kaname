//! OAuth 2.0 CSRF state トークン管理 (セッション固定攻撃防止)。
//!
//! # 脅威
//!
//! セッション固定攻撃: 攻撃者が事前に `state` パラメータを知っていれば、
//! 被害者の認証コードを自身のアカウントに紐付けられる。
//!
//! # 防御
//!
//! - `state` は CSPRNG で生成した 32 バイト (256 bit) のランダム値。
//! - シングルユース: 検証後にトークンを削除。リプレイ攻撃不可。
//! - 有効期限: 10 分。長時間放置されたフローをクリーンアップ。
//! - 定数時間比較: タイミングサイドチャネルを防ぐ。

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use rand::RngCore;
use thiserror::Error;

/// OAuth state トークンエラー。
#[derive(Debug, Error)]
pub enum OAuthStateError {
    /// トークンが存在しない (発行済みでない or 期限切れ or 消費済み)。
    #[error("state トークンが無効または期限切れです")]
    InvalidOrExpired,
    /// RNG の取得に失敗。
    #[error("乱数生成に失敗しました")]
    RngFailure,
    /// ロック取得に失敗。
    #[error("内部ロック取得に失敗しました")]
    LockPoisoned,
}

/// 発行済みトークンのエントリ。
struct Entry {
    token: [u8; 32],
    issued_at: Instant,
}

/// OAuth state トークンのストア。
///
/// スレッドセーフ。複数の認証フローを並行処理可能。
#[derive(Clone)]
pub struct OAuthStateStore {
    inner: Arc<RwLock<HashMap<String, Entry>>>,
    ttl: Duration,
}

impl OAuthStateStore {
    /// デフォルト TTL (10 分) でストアを作成。
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(600))
    }

    /// カスタム TTL でストアを作成。
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    /// 新しい state トークンを発行し、hex 文字列として返す。
    ///
    /// `flow_id` は認証フローを識別するキー (セッション ID など)。
    ///
    /// # Errors
    ///
    /// RNG 失敗またはロック取得失敗時に `Err` を返す。
    pub fn issue(&self, flow_id: &str) -> Result<String, OAuthStateError> {
        let mut token = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token);

        let hex = hex_encode(&token);
        let entry = Entry {
            token,
            issued_at: Instant::now(),
        };

        let mut map = self.inner.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        // 期限切れエントリを同時にクリーンアップ
        let ttl = self.ttl;
        map.retain(|_, v| v.issued_at.elapsed() < ttl);
        map.insert(flow_id.to_string(), entry);

        Ok(hex)
    }

    /// `state` トークンを検証し、消費する (シングルユース)。
    ///
    /// 成功すれば `Ok(())`。失敗すれば `Err(InvalidOrExpired)`。
    ///
    /// # Errors
    ///
    /// トークンが無効・期限切れ・未発行の場合に `Err` を返す。
    pub fn consume(&self, flow_id: &str, state: &str) -> Result<(), OAuthStateError> {
        let mut map = self.inner.write().unwrap_or_else(std::sync::PoisonError::into_inner);

        let entry = map.remove(flow_id).ok_or(OAuthStateError::InvalidOrExpired)?;

        // 有効期限チェック
        if entry.issued_at.elapsed() >= self.ttl {
            return Err(OAuthStateError::InvalidOrExpired);
        }

        // 定数時間比較
        let expected_hex = hex_encode(&entry.token);
        if !ct_eq_str(&expected_hex, state) {
            return Err(OAuthStateError::InvalidOrExpired);
        }

        Ok(())
    }
}

impl Default for OAuthStateStore {
    fn default() -> Self {
        Self::new()
    }
}

/// 定数時間文字列比較 (タイミングサイドチャネル防止)。
fn ct_eq_str(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// バイト配列を小文字 hex 文字列に変換。
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unwrap_used)]
    #[test]
    fn issue_and_consume_success() {
        let store = OAuthStateStore::new();
        let token = store.issue("flow-1").unwrap();
        assert_eq!(token.len(), 64, "32バイト → hex 64文字");
        store.consume("flow-1", &token).unwrap();
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn single_use_replay_rejected() {
        let store = OAuthStateStore::new();
        let token = store.issue("flow-2").unwrap();
        store.consume("flow-2", &token).unwrap();
        // 2回目は拒否
        assert!(store.consume("flow-2", &token).is_err());
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn wrong_token_rejected() {
        let store = OAuthStateStore::new();
        store.issue("flow-3").unwrap();
        assert!(store.consume("flow-3", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_err());
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn unknown_flow_id_rejected() {
        let store = OAuthStateStore::new();
        assert!(store.consume("no-such-flow", "deadbeef").is_err());
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn expired_token_rejected() {
        let store = OAuthStateStore::with_ttl(Duration::from_millis(1));
        let token = store.issue("flow-4").unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(store.consume("flow-4", &token).is_err());
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn different_flows_independent() {
        let store = OAuthStateStore::new();
        let t1 = store.issue("flow-a").unwrap();
        let t2 = store.issue("flow-b").unwrap();
        // 正しいトークンでそれぞれのフローが独立して消費できる
        store.consume("flow-a", &t1).unwrap();
        store.consume("flow-b", &t2).unwrap();
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn token_is_unique_per_issue() {
        let store = OAuthStateStore::new();
        let t1 = store.issue("flow-x").unwrap();
        let t2 = store.issue("flow-x").unwrap();
        // 再発行で新しいトークン
        assert_ne!(t1, t2);
        // 最新トークン (t2) のみ有効; 古い t1 は上書きされて無効
        store.consume("flow-x", &t2).unwrap();
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn wrong_token_consumes_entry() {
        // セキュリティ設計: 間違ったトークンでも試行でエントリが消費される (ブルートフォース防止)
        let store = OAuthStateStore::new();
        let correct = store.issue("flow-bf").unwrap();
        assert!(store.consume("flow-bf", "wrong").is_err());
        // エントリは消費済みなので正しいトークンでも失敗
        assert!(store.consume("flow-bf", &correct).is_err());
    }

    #[test]
    fn ct_eq_str_same() {
        assert!(ct_eq_str("hello", "hello"));
    }

    #[test]
    fn ct_eq_str_different() {
        assert!(!ct_eq_str("hello", "world"));
    }

    #[test]
    fn ct_eq_str_length_mismatch() {
        assert!(!ct_eq_str("abc", "abcd"));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn hex_encode_32_bytes() {
        let bytes = [0xabu8; 32];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "ab".repeat(32));
    }
}
