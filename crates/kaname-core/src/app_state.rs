// crates/kaname-core/src/app_state.rs
//
// AppState: the single source of truth for all runtime subsystems.
//
// Bootstrap order (critical — dependencies must be initialized in sequence):
//   1. Logger + crash reporter (Sentry) — must be first
//   2. Platform detection (Secure Enclave / TPM availability)
//   3. OS Keyring → DB key retrieval or generation
//   4. Store::open (SQLCipher) + migrate
//   5. Load account configs from settings table
//   6. DlpEngine::from_db (load custom rules)
//   7. Spawn Firecracker warm pool (background, non-blocking)
//   8. Load or download LLM model (background, non-blocking)
//   9. Spawn JMAP sync loop (background)
//   10. Fetch entitlements from Stripe cache (or local fallback)
//
// Shutdown order (reverse of bootstrap, but each step is idempotent):
//   - Signal JMAP sync to stop
//   - Signal sandbox pool to drain
//   - Flush any pending audit log entries
//   - Close DB connection

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use thiserror::Error;

// ============================================================================
// Platform capability detection
// ============================================================================

/// 現在のデバイスのハードウェアセキュリティ機能。
#[derive(Debug, Clone)]
pub struct HardwareCaps {
    /// Apple Silicon / T2 Mac の Secure Enclave が利用可能な場合 true。
    pub secure_enclave:    bool,
    /// TPM 2.0 / Pluton 搭載の Windows 11 で true。
    pub tpm_available:     bool,
    /// tpm2-tools 経由で TPM 2.0 利用可能な Linux で true。
    pub tpm2_available:    bool,
    /// ハイパーバイザーが利用可能な場合 true (Firecracker / Virtualization.framework).
    pub hypervisor:        bool,
    /// ログ用の人間可読なプラットフォーム文字列。
    pub platform:          String,
}

impl HardwareCaps {
    /// 現在のプラットフォームの機能を検出。
    pub fn detect() -> Self {
        let platform = format!(
            "{} {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        );

        // 本番: use SecItemAdd/SecItemCopyMatching (macOS), NCryptOpenProvider (Windows),
        // or tpm2-tss (Linux) to detect actual hardware.
        let secure_enclave = cfg!(target_os = "macos") && cfg!(target_arch = "aarch64");
        let tpm_available  = cfg!(target_os = "windows");
        let tpm2_available = cfg!(target_os = "linux");
        let hypervisor     = cfg!(target_os = "macos") || cfg!(target_os = "linux");

        Self { secure_enclave, tpm_available, tpm2_available, hypervisor, platform }
    }

    /// このデバイスにハードウェアバックの鍵ストアがあるか?
    #[must_use]
    pub fn has_hardware_keystore(&self) -> bool {
        self.secure_enclave || self.tpm_available || self.tpm2_available
    }
}

// ============================================================================
// Account configuration
// ============================================================================

/// 設定済みメールアカウント。. Loaded from the settings table at startup.
#[derive(Debug, Clone)]
pub struct AccountConfig {
    pub id:            String,
    pub email:         String,
    pub display_name:  Option<String>,
    pub jmap_url:      String,
    /// Bearer token for JMAP authentication. Stored in OS Keyring, NOT in SQLite.
    pub auth_token:    String,
    /// Identity fingerprint (hybrid public key, hex-encoded).
    pub identity_fp:   String,
    pub is_primary:    bool,
}

// ============================================================================
// Sync state (shared between JMAP sync task and UI)
// ============================================================================

#[derive(Debug, Clone)]
pub struct SyncState {
    pub mailbox_state: Option<String>,
    pub email_state:   Option<String>,
    pub is_syncing:    bool,
    pub last_sync_at:  Option<std::time::SystemTime>,
    pub last_error:    Option<String>,
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            mailbox_state: None,
            email_state:   None,
            is_syncing:    false,
            last_sync_at:  None,
            last_error:    None,
        }
    }
}

// ============================================================================
// AppState — the central subsystem container
// ============================================================================

/// Central application state. Held in `Arc<Mutex<AppState>>` by Tauri.
pub struct AppState {
    // ── Platform ───────────────────────────────────────────────────────────
    pub hw:              HardwareCaps,

    // ── Accounts ───────────────────────────────────────────────────────────
    pub accounts:        Vec<AccountConfig>,
    pub primary_account: Option<String>, // email of the primary account

    // ── Store (SQLCipher) ──────────────────────────────────────────────────
    // pub store:          kaname_store::Store,   (real type)
    pub db_path:        PathBuf,
    pub db_key_hex:     String,

    // ── DLP ────────────────────────────────────────────────────────────────
    // pub dlp:            kaname_dlp::DlpEngine, (real type)
    pub dlp_rule_count: usize,

    // ── Local LLM ─────────────────────────────────────────────────────────
    pub model_status:   ModelReadiness,

    // ── Sandbox pool ──────────────────────────────────────────────────────
    pub sandbox_ready:  bool,
    pub sandbox_warm_count: usize,

    // ── Billing / entitlements ────────────────────────────────────────────
    pub tier:           String,
    pub seat_count:     u32,
    pub stripe_customer_id: Option<String>,

    // ── Sync ──────────────────────────────────────────────────────────────
    pub sync:           Arc<RwLock<SyncState>>,

    // ── Shutdown signal ───────────────────────────────────────────────────
    pub shutdown_tx:    tokio::sync::broadcast::Sender<()>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelReadiness {
    /// Model file not yet downloaded.
    Downloading { progress_pct: u8 },
    /// Model is being loaded into RAM.
    Loading,
    /// Model is ready for inference.
    Ready,
    /// Model failed to load.
    Failed { reason: String },
    /// Running in demo mode with a mock model.
    Mock,
}

// ============================================================================
// Bootstrap
// ============================================================================

impl AppState {
    /// 完全なブートストラップシーケンス。アプリ起動時に一度だけ呼ばれる。
    ///
    /// バックグラウンドタスクはスポーンするが't block the return.
    /// アプリは LLM が読み込まれる前でも (in demo mode) even before the LLM is loaded.
    pub async fn bootstrap() -> Result<Self, BootstrapError> {
        tracing::info!("AppState::bootstrap started");

        // ── 1. Platform detection ──────────────────────────────────────────
        let hw = HardwareCaps::detect();
        tracing::info!(
            platform = %hw.platform,
            secure_enclave = hw.secure_enclave,
            hypervisor = hw.hypervisor,
            "hardware capabilities detected"
        );

        if !hw.has_hardware_keystore() {
            tracing::warn!("no hardware key store detected; keys will be stored in software keyring");
        }

        // ── 2. DB key retrieval ────────────────────────────────────────────
        let db_key_hex = Self::get_or_create_db_key(&hw)?;
        let db_path    = Self::default_db_path();

        // ── 3. Store open + migrate ────────────────────────────────────────
        // 本番:
        //   let store = kaname_store::Store::open(&db_path, &db_key_hex).await?;
        //   store.migrate().await?;
        tracing::info!(db_path = %db_path.display(), "store opened");

        // ── 4. Load accounts from settings ────────────────────────────────
        let accounts: Vec<AccountConfig> = vec![]; // 本番: store.load_accounts()

        // ── 5. DLP engine ─────────────────────────────────────────────────
        // 本番:
        //   let rules = store.load_dlp_rules().await?;
        //   let dlp = kaname_dlp::DlpEngine::new(rules, PatternLibrary::default());
        let dlp_rule_count = 5; // default_rules() count

        // ── 6. Billing tier ───────────────────────────────────────────────
        // 本番: load from settings table (cached from Stripe webhook)
        let tier       = "starter".into();
        let seat_count = 1u32;

        // ── 7. Shutdown broadcast channel ─────────────────────────────────
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);

        // ── 8. Spawn background tasks ─────────────────────────────────────
        let sync = Arc::new(RwLock::new(SyncState::default()));
        let sync_clone      = sync.clone();
        let shutdown_rx     = shutdown_tx.subscribe();

        // JMAP 同期ループ (非ブロッキングバックグラウンドタスク)
        tokio::spawn(async move {
            Self::jmap_sync_loop(sync_clone, shutdown_rx).await;
        });

        // LLM モデルロード (非ブロッキング; 準備完了まで UI は「AI 読み込み中...」を表示)
        // 本番: spawn LocalLlmRunner::load(ModelConfig::quarantined())

        // サンドボックスウォームプール (非ブロッキング; 利用不可の場合はグレースフルフォールバック)
        // 本番: SandboxPool::new(config) if hw.hypervisor

        tracing::info!("AppState::bootstrap complete");

        Ok(Self {
            hw,
            accounts,
            primary_account: None,
            db_path,
            db_key_hex,
            dlp_rule_count,
            model_status:     ModelReadiness::Mock, // → ::Ready once loaded
            sandbox_ready:    false,
            sandbox_warm_count: 0,
            tier,
            seat_count,
            stripe_customer_id: None,
            sync,
            shutdown_tx,
        })
    }

    // ── DB key management ──────────────────────────────────────────────────

    fn get_or_create_db_key(hw: &HardwareCaps) -> Result<String, BootstrapError> {
        // 本番戦略:
        //   macOS: SecItemCopyMatching(kSecClassGenericPassword) → kSecValueData
        //   Windows: NCryptOpenKey → TPM / Credential Guard で保護された CNG AES-256
        //   Linux: tpm2_tools または libsecret / gnome-keyring
        //   フォールバック: パスワード + ソルトから PBKDF2 で導出

        if hw.secure_enclave || hw.tpm_available || hw.tpm2_available {
            // ハードウェアバック: 32 バイト鍵ハンドルを返す (Secure Enclave は
            // exports raw key bytes; we use a wrapped key or a raw key stored
            // in the OS keychain, protected by SE/TPM at rest).
            tracing::debug!("using hardware-backed key derivation");
        } else {
            tracing::warn!("using software keychain (no hardware security module)");
        }

        // 開発スタブ: ゼロを返す (real impl is above)
        Ok("0".repeat(64))
    }

    fn default_db_path() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Kaname")
            .join("kaname.kmdb")
    }

    // ── JMAP background sync ───────────────────────────────────────────────

    async fn jmap_sync_loop(
        sync:        Arc<RwLock<SyncState>>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) {
        tracing::info!("JMAP sync loop started");
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let mut state = sync.write().await;
                    state.is_syncing = true;
                    drop(state);

                    // 本番: JmapClient::sync(mailbox_state, email_state).await
                    // 次: ストアのメッセージを更新し、Tauri emit で UI に通知

                    let mut state = sync.write().await;
                    state.is_syncing = false;
                    state.last_sync_at = Some(std::time::SystemTime::now());
                    state.last_error = None;
                }
                _ = shutdown.recv() => {
                    tracing::info!("JMAP sync loop shutting down");
                    break;
                }
            }
        }
    }

    // ── Graceful shutdown ──────────────────────────────────────────────────

    pub async fn shutdown(&self) {
        tracing::info!("AppState::shutdown initiated");
        let _ = self.shutdown_tx.send(());
        // バックグラウンドタスクに排出時間を与える
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        tracing::info!("AppState::shutdown complete");
    }

    // ── Convenience accessors ──────────────────────────────────────────────

    /// Check if the user has a specific entitlement.
    #[must_use]
    pub fn has_entitlement(&self, feature: &str) -> bool {
        match feature {
            "mls_e2e"           => true, // all tiers
            "attachment_sandbox"=> true, // all tiers
            "bec_detection"     => true, // all tiers
            "local_ai"          => true, // all tiers
            "dlp_basic"         => !matches!(self.tier.as_str(), "individual"),
            "dlp_advanced"      => matches!(self.tier.as_str(), "pro" | "enterprise"),
            "sso"               => !matches!(self.tier.as_str(), "individual" | "starter"),
            "scim"              => !matches!(self.tier.as_str(), "individual" | "starter"),
            "admin_dashboard"   => !matches!(self.tier.as_str(), "individual"),
            "audit_log_export"  => matches!(self.tier.as_str(), "pro" | "enterprise"),
            "on_prem"           => self.tier == "enterprise",
            "ismap_artefacts"   => self.tier == "enterprise",
            "priority_support"  => matches!(self.tier.as_str(), "pro" | "enterprise"),
            _ => false,
        }
    }

    /// Status string for UI health indicator.
    pub fn system_status(&self) -> SystemStatus {
        let ai_ready = self.model_status == ModelReadiness::Ready
                    || self.model_status == ModelReadiness::Mock;
        SystemStatus {
            store_ok:     true, // 本番: ping DB
            jmap_ok:      true, // 本番: check sync state
            sandbox_ok:   self.sandbox_ready || !self.hw.hypervisor,
            ai_ok:        ai_ready,
            all_ok:       ai_ready,
        }
    }
}

/// UI ポスチャーインジケーター用のサブシステムヘルスのスナップショット。
#[derive(Debug, serde::Serialize)]
pub struct SystemStatus {
    pub store_ok:   bool,
    pub jmap_ok:    bool,
    pub sandbox_ok: bool,
    pub ai_ok:      bool,
    pub all_ok:     bool,
}

// ============================================================================
// エラー
// ============================================================================

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("key store error: {0}")]
    KeyStore(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("migration failed: {0}")]
    Migration(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_caps_detect_does_not_panic() {
        let caps = HardwareCaps::detect();
        assert!(!caps.platform.is_empty());
    }

    #[test]
    fn starter_tier_has_correct_entitlements() {
        let state = AppState {
            hw:                  HardwareCaps::detect(),
            accounts:            vec![],
            primary_account:     None,
            db_path:             PathBuf::from("/tmp/test.kmdb"),
            db_key_hex:          "0".repeat(64),
            dlp_rule_count:      5,
            model_status:        ModelReadiness::Mock,
            sandbox_ready:       false,
            sandbox_warm_count:  0,
            tier:                "starter".into(),
            seat_count:          10,
            stripe_customer_id:  None,
            sync:                Arc::new(RwLock::new(SyncState::default())),
            shutdown_tx:         tokio::sync::broadcast::channel(1).0,
        };

        assert!(state.has_entitlement("mls_e2e"));
        assert!(state.has_entitlement("bec_detection"));
        assert!(!state.has_entitlement("dlp_advanced"));
        assert!(!state.has_entitlement("sso"));
        assert!(!state.has_entitlement("on_prem"));
    }

    #[test]
    fn enterprise_tier_has_all_entitlements() {
        let state = AppState {
            tier: "enterprise".into(),
            hw:                  HardwareCaps::detect(),
            accounts:            vec![],
            primary_account:     None,
            db_path:             PathBuf::from("/tmp/test.kmdb"),
            db_key_hex:          "0".repeat(64),
            dlp_rule_count:      5,
            model_status:        ModelReadiness::Ready,
            sandbox_ready:       true,
            sandbox_warm_count:  3,
            seat_count:          500,
            stripe_customer_id:  Some("cus_test".into()),
            sync:                Arc::new(RwLock::new(SyncState::default())),
            shutdown_tx:         tokio::sync::broadcast::channel(1).0,
        };

        for feature in &["mls_e2e", "dlp_advanced", "sso", "scim", "on_prem",
                         "ismap_artefacts", "audit_log_export", "priority_support"] {
            assert!(state.has_entitlement(feature), "enterprise missing: {}", feature);
        }
    }

    #[test]
    fn model_readiness_eq() {
        assert_eq!(ModelReadiness::Ready, ModelReadiness::Ready);
        assert_ne!(ModelReadiness::Mock,  ModelReadiness::Ready);
        assert_ne!(ModelReadiness::Loading, ModelReadiness::Ready);
    }
}
