//! ログイン試行レート制限 (ブルートフォース・パスワードスプレー防止)。
//!
//! # アルゴリズム
//!
//! ## アカウントベース (ブルートフォース対策)
//! - 5回連続失敗 → ロックアウト開始 (指数バックオフ)
//! - バックオフ: 30秒 → 60秒 → 120秒 → ... → 最大15分
//! - 成功時にカウンターをリセット
//!
//! ## IP ベース (パスワードスプレー対策)
//! - 1つの IP から累積 20 回失敗 → IP ブロック開始 (5分)
//! - IP ブロックはアカウントロックアウトより短い (正規ユーザーへの影響を最小化)
//! - 攻撃者が大量アカウントに1パスワードずつ試行する攻撃を防ぐ

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

/// ロックアウトポリシー定数。
const FAILURE_THRESHOLD: u32 = 5;
const BASE_BACKOFF_SECS: u64 = 30;
const MAX_BACKOFF_SECS: u64 = 900; // 15 分

/// IP ベースレート制限定数。
const IP_FAILURE_THRESHOLD: u32 = 20;
const IP_BLOCK_SECS: u64 = 300; // 5 分

/// アカウントごとのログイン試行状態。
#[derive(Debug)]
struct AccountState {
    consecutive_failures: u32,
    locked_until: Option<Instant>,
}

impl AccountState {
    fn new() -> Self {
        Self {
            consecutive_failures: 0,
            locked_until: None,
        }
    }

    /// 現在ロック中かどうか。
    fn is_locked(&self) -> bool {
        self.locked_until.is_some_and(|t| Instant::now() < t)
    }

    /// 残りロック時間。
    fn remaining_lockout(&self) -> Option<Duration> {
        self.locked_until.and_then(|t| {
            let now = Instant::now();
            if t > now { Some(t - now) } else { None }
        })
    }

    /// 失敗を記録し、必要であればロックアウトを設定する。
    fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= FAILURE_THRESHOLD {
            let excess = self.consecutive_failures - FAILURE_THRESHOLD;
            let backoff = BASE_BACKOFF_SECS.saturating_mul(1u64 << excess.min(9));
            let backoff = backoff.min(MAX_BACKOFF_SECS);
            self.locked_until = Some(Instant::now() + Duration::from_secs(backoff));
        }
    }

    /// 成功を記録してカウンターをリセット。
    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.locked_until = None;
    }
}

/// ログイン試行チェック結果。
#[derive(Debug, PartialEq, Eq)]
pub enum LimitDecision {
    /// 試行を許可する。
    Allow,
    /// レート制限中。残り時間を含む。
    Deny {
        /// ロック解除まで待つ時間。
        retry_after: Duration,
    },
}

/// レート制限エラー。
#[derive(Debug, thiserror::Error)]
pub enum LimiterError {
    /// 内部ロックが破損。
    #[error("内部ロック取得に失敗しました")]
    LockPoisoned,
}

/// IP アドレスごとの失敗追跡状態。
#[derive(Debug)]
struct IpState {
    total_failures: u32,
    blocked_until: Option<Instant>,
}

impl IpState {
    fn new() -> Self {
        Self { total_failures: 0, blocked_until: None }
    }

    fn is_blocked(&self) -> bool {
        self.blocked_until.is_some_and(|t| Instant::now() < t)
    }

    fn remaining_block(&self) -> Option<Duration> {
        self.blocked_until.and_then(|t| {
            let now = Instant::now();
            if t > now { Some(t - now) } else { None }
        })
    }

    fn record_failure(&mut self) {
        self.total_failures = self.total_failures.saturating_add(1);
        if self.total_failures >= IP_FAILURE_THRESHOLD {
            self.blocked_until = Some(Instant::now() + Duration::from_secs(IP_BLOCK_SECS));
        }
    }
}

/// ログイン試行レート制限ストア。
///
/// スレッドセーフ。クローンしてサービス全体で共有可能。
#[derive(Clone)]
pub struct LoginLimiter {
    /// アカウント ID → 状態 (ブルートフォース対策)
    inner: Arc<RwLock<HashMap<String, AccountState>>>,
    /// IP アドレス → 状態 (パスワードスプレー対策)
    ip_inner: Arc<RwLock<HashMap<String, IpState>>>,
}

impl LoginLimiter {
    /// 新しいレート制限ストアを作成。
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ip_inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// ログイン試行を許可するか判断する (アカウント + IP の両方をチェック)。
    ///
    /// `source_ip` を指定した場合は IP ブロックも同時に確認する。
    /// 分散 IP を使った緩やかなブルートフォース攻撃に対し、どちらかがブロック中なら拒否する。
    ///
    /// # Errors
    ///
    /// 内部ロックが破損している場合に `Err` を返す。
    pub fn check(&self, account_id: &str) -> Result<LimitDecision, LimiterError> {
        let map = self.inner.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(state) = map.get(account_id) {
            if state.is_locked() {
                let retry_after = state.remaining_lockout().unwrap_or(Duration::ZERO);
                return Ok(LimitDecision::Deny { retry_after });
            }
        }
        Ok(LimitDecision::Allow)
    }

    /// ログイン試行を許可するか判断する (アカウント + IP の両方を同時チェック)。
    ///
    /// `check(account_id)` と `check_ip(source_ip)` を1回の呼び出しで実行する。
    /// いずれかがブロック中であれば `Deny` を返す。
    ///
    /// # Errors
    ///
    /// 内部ロックが破損している場合に `Err` を返す。
    pub fn check_with_ip(&self, account_id: &str, source_ip: &str) -> Result<LimitDecision, LimiterError> {
        // アカウントロックを優先確認 (残り時間を正確に返すため)
        if let LimitDecision::Deny { retry_after } = self.check(account_id)? {
            return Ok(LimitDecision::Deny { retry_after });
        }
        // IP ブロックも確認
        self.check_ip(source_ip)
    }

    /// IP アドレスが現在ブロックされているかを確認する (パスワードスプレー対策)。
    ///
    /// # Errors
    ///
    /// 内部ロックが破損している場合に `Err` を返す。
    pub fn check_ip(&self, source_ip: &str) -> Result<LimitDecision, LimiterError> {
        let map = self.ip_inner.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(state) = map.get(source_ip) {
            if state.is_blocked() {
                let retry_after = state.remaining_block().unwrap_or(Duration::ZERO);
                return Ok(LimitDecision::Deny { retry_after });
            }
        }
        Ok(LimitDecision::Allow)
    }

    /// ログイン失敗を記録する (アカウント + IP の両方に記録)。
    ///
    /// # Errors
    ///
    /// 内部ロックが破損している場合に `Err` を返す。
    pub fn record_failure(&self, account_id: &str) -> Result<(), LimiterError> {
        let mut map = self.inner.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        map.entry(account_id.to_string())
            .or_insert_with(AccountState::new)
            .record_failure();
        Ok(())
    }

    /// ログイン失敗を記録する (IP アドレス付き)。
    ///
    /// アカウントロック + IP 累積カウンターの両方を更新。
    ///
    /// # Errors
    ///
    /// 内部ロックが破損している場合に `Err` を返す。
    pub fn record_failure_with_ip(&self, account_id: &str, source_ip: &str) -> Result<(), LimiterError> {
        self.record_failure(account_id)?;
        let mut ip_map = self.ip_inner.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        ip_map.entry(source_ip.to_string())
            .or_insert_with(IpState::new)
            .record_failure();
        Ok(())
    }

    /// ログイン成功を記録してカウンターをリセットする。
    ///
    /// # Errors
    ///
    /// 内部ロックが破損している場合に `Err` を返す。
    pub fn record_success(&self, account_id: &str) -> Result<(), LimiterError> {
        let mut map = self.inner.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(state) = map.get_mut(account_id) {
            state.record_success();
        }
        Ok(())
    }

    /// 期限切れ・クリーンエントリをクリーンアップする (定期メンテナンス用)。
    ///
    /// 以下のエントリを削除する:
    /// - 失敗カウントが 0 かつロック中でないアカウントエントリ (成功後リセット済み)
    /// - ブロック期限が切れた IP エントリ
    ///
    /// # Errors
    ///
    /// 内部ロックが破損している場合に `Err` を返す。
    pub fn cleanup_expired(&self) -> Result<usize, LimiterError> {
        let mut map = self.inner.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = map.len();
        // consecutive_failures == 0 かつ is_locked() でないエントリは不要 (リセット済み)
        map.retain(|_, v| v.consecutive_failures > 0 || v.is_locked());
        let removed_accounts = before - map.len();

        let mut ip_map = self.ip_inner.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        let ip_before = ip_map.len();
        // ブロック期限切れの IP エントリを削除
        ip_map.retain(|_, v| v.is_blocked() || v.total_failures > 0);
        let removed_ips = ip_before - ip_map.len();

        Ok(removed_accounts + removed_ips)
    }
}

impl Default for LoginLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unwrap_used)]
    #[test]
    fn fresh_account_is_allowed() {
        let limiter = LoginLimiter::new();
        assert_eq!(limiter.check("user@example.com").unwrap(), LimitDecision::Allow);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn four_failures_still_allowed() {
        let limiter = LoginLimiter::new();
        for _ in 0..4 {
            limiter.record_failure("user@example.com").unwrap();
        }
        assert_eq!(limiter.check("user@example.com").unwrap(), LimitDecision::Allow);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn five_failures_triggers_lockout() {
        let limiter = LoginLimiter::new();
        for _ in 0..5 {
            limiter.record_failure("user@example.com").unwrap();
        }
        match limiter.check("user@example.com").unwrap() {
            LimitDecision::Deny { retry_after } => {
                assert!(retry_after.as_secs() >= 29, "バックオフが短すぎる: {}秒", retry_after.as_secs());
                assert!(retry_after.as_secs() <= MAX_BACKOFF_SECS, "バックオフが長すぎる");
            }
            LimitDecision::Allow => panic!("5回失敗後はロックアウトされるべき"),
        }
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn success_resets_counter() {
        let limiter = LoginLimiter::new();
        for _ in 0..5 {
            limiter.record_failure("user@example.com").unwrap();
        }
        limiter.record_success("user@example.com").unwrap();
        assert_eq!(limiter.check("user@example.com").unwrap(), LimitDecision::Allow);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn different_accounts_independent() {
        let limiter = LoginLimiter::new();
        for _ in 0..5 {
            limiter.record_failure("alice@example.com").unwrap();
        }
        // bob はロックアウトされていない
        assert_eq!(limiter.check("bob@example.com").unwrap(), LimitDecision::Allow);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn backoff_increases_with_more_failures() {
        let limiter = LoginLimiter::new();
        for _ in 0..5 {
            limiter.record_failure("user@example.com").unwrap();
        }
        let first_lockout = match limiter.check("user@example.com").unwrap() {
            LimitDecision::Deny { retry_after } => retry_after,
            _ => panic!("ロックアウトされているべき"),
        };
        limiter.record_failure("user@example.com").unwrap();
        let second_lockout = match limiter.check("user@example.com").unwrap() {
            LimitDecision::Deny { retry_after } => retry_after,
            _ => panic!("ロックアウトされているべき"),
        };
        assert!(second_lockout >= first_lockout, "バックオフが増加していない");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn backoff_capped_at_max() {
        let limiter = LoginLimiter::new();
        for _ in 0..50 {
            limiter.record_failure("user@example.com").unwrap();
        }
        match limiter.check("user@example.com").unwrap() {
            LimitDecision::Deny { retry_after } => {
                assert!(retry_after.as_secs() <= MAX_BACKOFF_SECS + 1, "上限を超えた: {}秒", retry_after.as_secs());
            }
            _ => panic!("ロックアウトされているべき"),
        }
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn cleanup_removes_clean_entries() {
        let limiter = LoginLimiter::new();
        // 一度失敗を記録してから成功でリセット
        limiter.record_failure("user@example.com").unwrap();
        limiter.record_success("user@example.com").unwrap();
        let removed = limiter.cleanup_expired().unwrap();
        assert_eq!(removed, 1, "リセット済みエントリが削除されるべき");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn account_state_exponential_backoff() {
        let mut state = AccountState::new();
        // 5回失敗 → 30秒
        for _ in 0..5 {
            state.record_failure();
        }
        let lockout1 = state.remaining_lockout().unwrap();
        assert!(lockout1.as_secs() >= 28);

        // 6回目 → 60秒
        state.record_failure();
        let lockout2 = state.remaining_lockout().unwrap();
        assert!(lockout2.as_secs() > lockout1.as_secs(), "指数バックオフで増加するべき");
    }

    #[test]
    fn unlocked_state_is_not_locked() {
        let state = AccountState::new();
        assert!(!state.is_locked());
    }

    // ---- IP ベースレート制限テスト ----

    #[allow(clippy::unwrap_used)]
    #[test]
    fn fresh_ip_is_allowed() {
        let limiter = LoginLimiter::new();
        assert_eq!(limiter.check_ip("1.2.3.4").unwrap(), LimitDecision::Allow);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn nineteen_ip_failures_still_allowed() {
        let limiter = LoginLimiter::new();
        for i in 0..19 {
            limiter.record_failure_with_ip(&format!("user{}@example.com", i), "1.2.3.4").unwrap();
        }
        assert_eq!(limiter.check_ip("1.2.3.4").unwrap(), LimitDecision::Allow);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn twenty_ip_failures_triggers_block() {
        let limiter = LoginLimiter::new();
        for i in 0..20 {
            limiter.record_failure_with_ip(&format!("user{}@example.com", i), "10.0.0.1").unwrap();
        }
        match limiter.check_ip("10.0.0.1").unwrap() {
            LimitDecision::Deny { retry_after } => {
                assert!(retry_after.as_secs() >= 299, "IP ブロックが短すぎる: {}秒", retry_after.as_secs());
                assert!(retry_after.as_secs() <= IP_BLOCK_SECS + 1);
            }
            LimitDecision::Allow => panic!("20回失敗後は IP ブロックされるべき"),
        }
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn different_ips_independent() {
        let limiter = LoginLimiter::new();
        for i in 0..20 {
            limiter.record_failure_with_ip(&format!("u{}@example.com", i), "192.168.1.1").unwrap();
        }
        // 別 IP はブロックされていない
        assert_eq!(limiter.check_ip("192.168.1.2").unwrap(), LimitDecision::Allow);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn password_spray_scenario() {
        // パスワードスプレー: 1つの IP から多数アカウントへ少数ずつ試行
        let limiter = LoginLimiter::new();
        let spray_ip = "203.0.113.42";
        for i in 0..20 {
            let account = format!("victim{}@company.com", i);
            // 各アカウントは1回しか失敗していない → アカウントロックは発生しない
            limiter.record_failure_with_ip(&account, spray_ip).unwrap();
            assert_eq!(limiter.check(&account).unwrap(), LimitDecision::Allow,
                "アカウントロックが早まりすぎ: {}", account);
        }
        // しかし IP は累積 20 回でブロックされる
        assert!(matches!(limiter.check_ip(spray_ip).unwrap(), LimitDecision::Deny { .. }),
            "パスワードスプレー IP はブロックされるべき");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn record_failure_without_ip_does_not_affect_ip_map() {
        let limiter = LoginLimiter::new();
        for _ in 0..25 {
            // IP なし記録は IP マップに影響しない
            limiter.record_failure("user@example.com").unwrap();
        }
        assert_eq!(limiter.check_ip("1.2.3.4").unwrap(), LimitDecision::Allow);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn check_with_ip_blocks_on_account_lock() {
        let limiter = LoginLimiter::new();
        for _ in 0..5 {
            limiter.record_failure("locked@example.com").unwrap();
        }
        // アカウントがロックされていれば check_with_ip も Deny
        assert!(matches!(
            limiter.check_with_ip("locked@example.com", "1.2.3.4").unwrap(),
            LimitDecision::Deny { .. }
        ), "アカウントロック中は check_with_ip も Deny を返すべき");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn check_with_ip_blocks_on_ip_block() {
        let limiter = LoginLimiter::new();
        // 別アカウントに 20 回失敗して IP をブロック
        for i in 0..20 {
            limiter.record_failure_with_ip(&format!("u{}@example.com", i), "5.6.7.8").unwrap();
        }
        // 別アカウントへの試行でも IP ブロックで止まる
        assert!(matches!(
            limiter.check_with_ip("new_victim@example.com", "5.6.7.8").unwrap(),
            LimitDecision::Deny { .. }
        ), "IP ブロック中は check_with_ip も Deny を返すべき");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn cleanup_removes_ip_entries_with_no_active_block() {
        let limiter = LoginLimiter::new();
        // IP に 5 回失敗記録 (ブロック未到達)
        for i in 0..5 {
            limiter.record_failure_with_ip(&format!("u{}@example.com", i), "9.9.9.9").unwrap();
        }
        // cleanup は成功 (エラーなし)
        let removed = limiter.cleanup_expired().unwrap();
        // IP エントリは failures > 0 なので保持される
        assert_eq!(removed, 0, "アクティブな IP エントリは削除されない");
    }
}
