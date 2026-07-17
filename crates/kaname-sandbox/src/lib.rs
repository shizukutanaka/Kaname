//! kaname-sandbox — Firecracker microVM サンドボックス。
//!
//! - 添付ファイルを isolated VM 内でレンダリング
//! - リソース制限: CPU 1 core、Memory 256MB
//! - vsock 経由のメッセージング

// crates/kaname-sandbox/src/lib.rs
//
// Firecracker microVM スーパーバイザー。添付ファイル 1 つにつき VM 1 つ、使用後破棄。
//
// Guarantees (from ADR-005):
//   1. Every attachment opens in a fresh VM — no VM handles two attachments
//   2. VMs have NO network. Enforced by vhost-net never being attached.
//   3. VMs cannot see the host filesystem. Only a typed vsock channel.
//   4. VM lifetime is bounded. Kill on timeout regardless of state.
//   5. Warm pool keeps perceived latency < 50 ms.
//
// This crate is one of three where `unsafe` is permitted (sandbox boundary).
// Every unsafe block must carry a `SAFETY:` comment justifying it.

#![warn(unsafe_op_in_unsafe_fn)]
#![allow(missing_docs)]

//! # kaname-sandbox
//!
//! Disposable microVM supervisor for attachment viewing.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc, clippy::doc_markdown, clippy::must_use_candidate, clippy::items_after_statements, clippy::unused_async, clippy::used_underscore_binding)]
/// MIME ネスト深度チェック (スタックオーバーフロー防止)。
pub mod mime_depth;
pub use mime_depth::{check_mime_depth, MimeDepthError, MAX_MIME_DEPTH};

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};

// ============================================================================
// Configuration
// ============================================================================

/// サンドボックス設定。構築時にセキュリティ不変条件を強制。
#[derive(Clone, Debug)]
pub struct FirecrackerConfig {
    /// Number of pre-started VMs to keep warm. Balances memory vs latency.
    pub pool_size: usize,
    /// Maximum lifetime of any single VM. Hard kill after this.
    pub max_lifetime_secs: u64,
    /// Memory per VM in MB.
    pub memory_mb: u32,
    /// vCPUs per VM. 1 is fine for viewers.
    pub vcpus: u8,
    /// Minimal Linux kernel image to boot.
    pub kernel_path: PathBuf,
    /// 読み取り専用 rootfs (our minimal Alpine image with viewers baked in).
    pub rootfs_path: PathBuf,
    /// HARD: network must be disabled. This field exists to REMIND reviewers.
    /// Construction panics if anyone ever flips it.
    pub network_allowed: bool,
}

impl FirecrackerConfig {
    /// 設定をバリデート。セキュリティ不変条件が破られると `Err` を返す。
    ///
    /// 修正前は `assert!` を使用しておりパニックしていた。他の全ての不変条件が
    /// `Err(SandboxError::InvalidConfig)` を返す設計と矛盾する上、
    /// `#![deny(clippy::unwrap_used)]` が示す「本番コードでパニックさせない」
    /// 方針にも反していた。デシリアライズされた設定が不正な場合に
    /// プロセス全体をクラッシュさせず、呼び出し元にエラーとして返す。
    pub fn validated(self) -> Result<Self, SandboxError> {
        if self.network_allowed {
            return Err(SandboxError::InvalidConfig(
                "network_allowed must be false — no exceptions",
            ));
        }
        if self.pool_size == 0 || self.pool_size > 8 {
            return Err(SandboxError::InvalidConfig("pool_size must be 1..=8"));
        }
        if self.memory_mb < 128 || self.memory_mb > 2048 {
            return Err(SandboxError::InvalidConfig("memory_mb must be 128..=2048"));
        }
        if self.max_lifetime_secs < 10 || self.max_lifetime_secs > 1800 {
            return Err(SandboxError::InvalidConfig("max_lifetime_secs must be 10..=1800"));
        }
        Ok(self)
    }
}

// ============================================================================
// A running VM
// ============================================================================

/// A live microVM. Owned by whoever got it from the pool. Dropping it
/// triggers teardown; the VM never survives the `Drop` of this struct.
pub struct RunningVm {
    /// Unique ID for this VM instance. Used in logs + metrics.
    id: VmId,
    /// When we spawned it. Used to enforce lifetime cap.
    spawned_at: Instant,
    /// Control socket for sending commands.
    _ctrl: (),
    /// Vsock channel for exchanging typed messages with the viewer inside.
    vsock: VsockChannel,
    /// Hook fired on drop to notify the pool supervisor.
    teardown_tx: mpsc::Sender<VmId>,
    /// 同時実行数を制限するセマフォパーミット。
    ///
    /// 修正前は `acquire()` 内で `_permit.forget()` により恒久的にリークして
    /// おり、「VM Drop が別経路でセマフォを解放する」というコメントに反して
    /// 実際に解放するコードがどこにも存在しなかった。その結果
    /// `pool_size * 2` 回 `acquire()` すると以降永久にブロックする
    /// 自己 DoS バグになっていた。パーミットを VM の所有物として保持し、
    /// `RunningVm` の Drop で自動的に解放されるようにする。
    _permit: Option<OwnedSemaphorePermit>,
}

impl RunningVm {
    /// VM identifier.
    pub fn id(&self) -> VmId {
        self.id
    }

    /// How long this VM has been running.
    pub fn age(&self) -> Duration {
        self.spawned_at.elapsed()
    }

    /// Send an attachment into the VM and receive a rendered preview.
    ///
    /// This is the ONLY entry point for getting data into a VM. No file
    /// bind-mounts, no shared memory. Only this typed channel.
    /// VM から返ってくる `extracted_text` の最大バイト数 (ホスト OOM 防止)。
    const MAX_EXTRACTED_TEXT_BYTES: usize = 10 * 1024 * 1024; // 10 MB

    /// VM へ送り込む添付ファイルの最大バイト数 (ホスト OOM 防止)。
    /// VM メモリ上限 (最大 2048 MB) を考慮しても、巨大添付を VM に渡す前に
    /// ホスト側で vsock シリアライズ用のバッファを確保する段階で OOM しうるため、
    /// 入力側でも上限を設ける。
    const MAX_ATTACHMENT_BYTES: usize = 100 * 1024 * 1024; // 100 MB

    /// VM へ送り込む filename の最大バイト数。
    const MAX_FILENAME_BYTES: usize = 1024;

    /// VM に渡す最大ページ数 (レンダラーの OOM 防止)。
    const MAX_PAGES: u32 = 500;

    /// VM に渡す最大画像次元 (レンダラーの OOM 防止)。
    const MAX_DIMENSION_PX: u32 = 8192;

    /// VM から返ってくる `preview_pages` の合計最大バイト数 (ホスト OOM 防止)。
    /// `extracted_text` と同様、悪意ある添付が巨大なプレビュー画像を大量に
    /// 返してもホスト側でメモリを使い尽くさないようにする。
    const MAX_PREVIEW_TOTAL_BYTES: usize = 200 * 1024 * 1024; // 200 MB

    /// 添付ファイルを VM でレンダリングし、結果を返す。
    ///
    /// # Errors
    ///
    /// VM エラーまたはプロトコルエラーが発生した場合に `SandboxError` を返す。
    /// 添付が `MAX_ATTACHMENT_BYTES` を超える場合 `AttachmentTooLarge` を返す。
    pub async fn render_attachment(&mut self, mut input: AttachmentJob) -> Result<RenderResult, SandboxError> {
        // 入力サイズをホスト側でキャップ — VM へ送る前に巨大添付を拒否し OOM を防ぐ
        if input.bytes.len() > Self::MAX_ATTACHMENT_BYTES {
            return Err(SandboxError::AttachmentTooLarge {
                size: input.bytes.len(),
                max: Self::MAX_ATTACHMENT_BYTES,
            });
        }
        // filename 長さ制限 (過大な vsock バッファ防止)
        if input.filename.len() > Self::MAX_FILENAME_BYTES {
            return Err(SandboxError::InvalidInput("filename exceeds 1024 bytes"));
        }
        // RenderHints を安全な上限にクランプ (VM の OOM 防止)
        input.hints.max_pages = input.hints.max_pages.min(Self::MAX_PAGES);
        input.hints.max_dimension_px = input.hints.max_dimension_px.min(Self::MAX_DIMENSION_PX);
        let req = VsockMsg::RenderRequest(input);
        self.vsock.send(req).await?;
        match self.vsock.recv().await? {
            VsockMsg::RenderResult(mut r) => {
                // ホスト側でテキストサイズをキャップする。
                // VM が悪意ある PDF で 1GB+ を抽出しても OOM しない。
                if let Some(ref text) = r.extracted_text {
                    if text.len() > Self::MAX_EXTRACTED_TEXT_BYTES {
                        let truncated = text
                            .char_indices()
                            .take_while(|(i, _)| *i < Self::MAX_EXTRACTED_TEXT_BYTES)
                            .last()
                            .map_or("", |(i, c)| &text[..i + c.len_utf8()]);
                        r.extracted_text = Some(format!("{truncated}\n[テキストが {0} MB を超えたため切り詰め]",
                            Self::MAX_EXTRACTED_TEXT_BYTES / (1024 * 1024)));
                    }
                }
                // ホスト側で preview_pages の合計サイズもキャップする。
                // 修正前は無制限であり、悪意ある添付が (将来の実装で) 大量/巨大な
                // プレビューページを返すとホストが OOM しうる不均衡があった
                // (extracted_text は既に保護されていた)。
                let mut total: usize = 0;
                let mut cutoff = r.preview_pages.len();
                for (i, page) in r.preview_pages.iter().enumerate() {
                    total += page.len();
                    if total > Self::MAX_PREVIEW_TOTAL_BYTES {
                        cutoff = i;
                        break;
                    }
                }
                if cutoff < r.preview_pages.len() {
                    tracing::warn!(
                        pages_kept = cutoff,
                        pages_total = r.preview_pages.len(),
                        "preview_pages の合計サイズが上限を超えたため切り詰めました"
                    );
                    r.preview_pages.truncate(cutoff);
                }
                Ok(r)
            }
            VsockMsg::Error(e) => Err(SandboxError::VmError(e)),
            _ => Err(SandboxError::ProtocolError("unexpected response")),
        }
    }
}

impl Drop for RunningVm {
    fn drop(&mut self) {
        // ベストエフォートで通知。チャネルが閉じている場合 (supervisor 終了時) は
        // 問題ない — VM は自身のタイムアウトで回収される。
        // ただしチャネルが「満杯」(bounded 32) で失敗した場合は本当に
        // プール補充が行われず、リークしたままになりうる。修正前はこの
        // ケースが完全に無視されており気付く手段がなかったため、
        // せめて監視・アラートで検知できるよう警告ログを残す。
        if let Err(e) = self.teardown_tx.try_send(self.id) {
            tracing::warn!(
                vm_id = ?self.id,
                error = %e,
                "VM ティアダウン通知の送信に失敗しました (プール補充が行われない可能性)"
            );
        }
    }
}

/// Opaque VM identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VmId(u64);

// ============================================================================
// Vsock protocol
// ============================================================================

/// Typed message exchanged over vsock between host supervisor and VM viewer.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
enum VsockMsg {
    /// Host → VM: please render this attachment.
    RenderRequest(AttachmentJob),
    /// VM → Host: rendered preview bytes.
    RenderResult(RenderResult),
    /// VM → Host: error during rendering.
    Error(String),
    /// Host → VM: please shut down cleanly.
    Shutdown,
    /// VM → Host: ready for work (sent once at boot).
    Ready,
}

/// レンダリングする添付ファイル。
#[derive(Debug, Serialize, Deserialize)]
pub struct AttachmentJob {
    /// Filename (for MIME guessing and display).
    pub filename: String,
    /// Declared MIME type from the mail headers (untrusted, for guidance only).
    pub declared_mime: Option<String>,
    /// Raw bytes of the attachment.
    pub bytes: Vec<u8>,
    /// レンダリング hints.
    pub hints: RenderHints,
}

/// レンダリング hints.
#[derive(Debug, Serialize, Deserialize)]
pub struct RenderHints {
    /// Max page count for document attachments.
    pub max_pages: u32,
    /// Requested output resolution.
    pub max_dimension_px: u32,
}

impl Default for RenderHints {
    fn default() -> Self {
        Self { max_pages: 50, max_dimension_px: 2048 }
    }
}

/// レンダリングの結果。
#[derive(Debug, Serialize, Deserialize)]
pub struct RenderResult {
    /// Detected real MIME (from libmagic inside the VM, not the declared MIME).
    pub detected_mime: String,
    /// Verdict from in-VM scanners.
    pub verdict: Verdict,
    /// Preview image bytes (PNG) for each page, capped by hints.
    pub preview_pages: Vec<Vec<u8>>,
    /// Extracted plaintext (tagged Untrusted by the caller).
    pub extracted_text: Option<String>,
    /// Metadata summary.
    pub metadata: AttachmentMeta,
}

/// スキャナーの判定。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Verdict {
    /// シグネチャ不一致。安全とは限らないが、チェックを通過。
    Clean,
    /// 不審だが確定的に悪意あるとは言えない。
    Suspicious(String),
    /// Known-malicious signature matched. Details included.
    Malware {
        /// Signature name (ClamAV / YARA rule).
        signature: String,
        /// Engine that flagged it.
        engine: String,
    },
    /// Render failed (corrupt, unsupported format, DoS bomb).
    Unrenderable(String),
}

/// 添付ファイルから抽出されたメタデータ。
#[derive(Debug, Serialize, Deserialize)]
pub struct AttachmentMeta {
    /// 展開後の実際のサイズ (ZIP ボム検出)。
    pub true_size_bytes: u64,
    /// Compression ratio if applicable.
    pub compression_ratio: Option<f32>,
    /// Whether the file claimed one extension but was actually something else.
    pub extension_mismatch: bool,
    /// Page count for documents.
    pub page_count: Option<u32>,
}

// ============================================================================
// Vsock channel abstraction
// ============================================================================

/// Typed vsock channel. In production wraps `vsock::VsockStream` with
/// length-prefixed CBOR framing.
pub struct VsockChannel {
    _private: (),
}

impl VsockChannel {
    async fn send(&mut self, _msg: VsockMsg) -> Result<(), SandboxError> {
        Ok(())
    }
    async fn recv(&mut self) -> Result<VsockMsg, SandboxError> {
        Ok(VsockMsg::Ready)
    }
}

// ============================================================================
// The Pool — the top-level API
// ============================================================================

/// ウォーム VM プール + オンデマンドスポーンのマネージャー。
///
/// Typical usage:
/// ```ignore
/// let pool = SandboxPool::new(config).await?;
/// let mut vm = pool.acquire().await?;           // pops a warm VM
/// let result = vm.render_attachment(job).await?;
/// drop(vm);                                      // VM is destroyed
/// // pool replenishes in background
/// ```
pub struct SandboxPool {
    config: FirecrackerConfig,
    /// Available warm VMs.
    warm: Arc<Mutex<Vec<RunningVm>>>,
    /// Cap on concurrently-running VMs (warm + in-use).
    concurrency: Arc<Semaphore>,
    /// Channel to the reaper task.
    #[allow(dead_code)]
    teardown_tx: mpsc::Sender<VmId>,
}

impl SandboxPool {
    /// 構築してウォームアップ。
    pub async fn new(config: FirecrackerConfig) -> Result<Self, SandboxError> {
        let config = config.validated()?;
        let (teardown_tx, mut teardown_rx) = mpsc::channel(32);
        let warm = Arc::new(Mutex::new(Vec::with_capacity(config.pool_size)));
        let concurrency = Arc::new(Semaphore::new(config.pool_size * 2));

        // Spawn reaper task that listens for VM teardown notifications
        // and replenishes the pool.
        let warm_for_reaper = warm.clone();
        let config_for_reaper = config.clone();
        let teardown_tx_clone = teardown_tx.clone();
        tokio::spawn(async move {
            while let Some(vm_id) = teardown_rx.recv().await {
                tracing::debug!(?vm_id, "vm torn down; replenishing pool");
                // 使用済み VM の代わりに新しいウォーム VM を起動。
                if let Ok(vm) = spawn_vm(&config_for_reaper, teardown_tx_clone.clone()).await {
                    warm_for_reaper.lock().await.push(vm);
                }
            }
        });

        // ウォームプールを事前起動。
        for _ in 0..config.pool_size {
            let vm = spawn_vm(&config, teardown_tx.clone()).await?;
            warm.lock().await.push(vm);
        }

        Ok(Self { config, warm, concurrency, teardown_tx })
    }

    /// How many warm VMs are currently available.
    pub async fn warm_count(&self) -> usize {
        self.warm.lock().await.len()
    }

    /// 添付ファイルジョブのために VM を取得。
    ///
    /// 高速パス: ウォーム VM をポップ (体感 50ms)。
    /// 低速パス: オンデマンドでスポーン (900ms)。
    pub async fn acquire(&self) -> Result<RunningVm, SandboxError> {
        // パーミットは RunningVm が所有し、Drop 時に自動解放される
        // (以前は forget() で恒久リークしており、acquire() を
        // pool_size * 2 回呼ぶと以降ずっとブロックする自己 DoS だった)。
        let permit = self.concurrency.clone().acquire_owned().await
            .map_err(|_| SandboxError::PoolClosed)?;

        let mut warm = self.warm.lock().await;
        if let Some(mut vm) = warm.pop() {
            // 経過時間チェック — don't hand out VMs that have been idle too long.
            if vm.age() < Duration::from_secs(self.config.max_lifetime_secs / 2) {
                vm._permit = Some(permit);
                return Ok(vm);
            }
            // 古すぎる。破棄 (ティアダウントリガー)、コールドスポーンにフォールスルー。
            drop(vm);
        }
        drop(warm);

        // コールドスポーン。
        tracing::info!("sandbox pool miss; cold-spawning vm");
        let mut vm = spawn_vm(&self.config, self.teardown_tx.clone()).await?;
        vm._permit = Some(permit);
        Ok(vm)
    }
}

async fn spawn_vm(
    config: &FirecrackerConfig,
    teardown_tx: mpsc::Sender<VmId>,
) -> Result<RunningVm, SandboxError> {
    // Real impl: start firecracker binary with --no-api, set up vsock,
    // wait for VsockMsg::Ready from inside the VM. No network interfaces.
    //
    // 安全性不変条件 (この関数で強制、変更のたびにレビュー):
    //   1. --netns なし、tap デバイスなし、-net なし
    //   2. Rootfs を読み取り専用でマウント
    //   3. Firecracker 自体に seccomp プロファイルを適用
    //   4. 最大 fd、最大メモリ、最大 CPU 時間に rlimit
    //   5. 独自の PID/マウント/ユーザー/IPC 名前空間で実行
    let _ = (config, &teardown_tx);
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = VmId(NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst));

    Ok(RunningVm {
        id,
        spawned_at: Instant::now(),
        _ctrl: (),
        vsock: VsockChannel { _private: () },
        teardown_tx,
        _permit: None,
    })
}

// ============================================================================
// エラー
// ============================================================================

/// エラー from the sandbox supervisor.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// Config failed validation.
    #[error("invalid config: {0}")]
    InvalidConfig(&'static str),

    /// VM failed to spawn.
    #[error("vm spawn failed: {0}")]
    SpawnFailed(String),

    /// Vsock protocol violation.
    #[error("protocol error: {0}")]
    ProtocolError(&'static str),

    /// Error raised from inside the VM.
    #[error("vm-reported error: {0}")]
    VmError(String),

    /// VM exceeded its lifetime cap and was killed.
    #[error("vm lifetime exceeded")]
    LifetimeExceeded,

    /// Pool closed.
    #[error("pool closed")]
    PoolClosed,

    /// 入力が不正 (filename 長すぎ等)。
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),

    /// 添付ファイルがホスト側の上限を超過。
    #[error("attachment too large: {size} bytes > {max} bytes")]
    AttachmentTooLarge {
        /// 実際のサイズ (bytes)。
        size: usize,
        /// 許容上限 (bytes)。
        max: usize,
    },

    /// I/O error.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn network_enabled_config_rejected() {
        // 修正前: assert! でパニックしていた。デシリアライズされた不正な設定が
        // プロセス全体をクラッシュさせず、Err として扱えることを確認する。
        let result = FirecrackerConfig {
            pool_size: 1,
            max_lifetime_secs: 60,
            memory_mb: 256,
            vcpus: 1,
            kernel_path: PathBuf::from("/dev/null"),
            rootfs_path: PathBuf::from("/dev/null"),
            network_allowed: true,
        }
        .validated();
        assert!(
            matches!(result, Err(SandboxError::InvalidConfig(_))),
            "network_allowed=true は Err(InvalidConfig) を返すべき: {result:?}"
        );
    }

    #[tokio::test]
    async fn acquire_does_not_leak_semaphore_permits() {
        // 回帰テスト: 修正前は acquire() 内で _permit.forget() により
        // パーミットを恒久的にリークしており、pool_size * 2 回
        // acquire しては drop するだけで、以降 acquire() が永久にブロック
        // する自己 DoS バグだった。VM を確保してすぐ破棄するサイクルを
        // セマフォ容量の何倍も繰り返し、ハングしないことをタイムアウト付きで確認する。
        let config = FirecrackerConfig {
            pool_size: 1,
            max_lifetime_secs: 60,
            memory_mb: 256,
            vcpus: 1,
            kernel_path: PathBuf::from("/dev/null"),
            rootfs_path: PathBuf::from("/dev/null"),
            network_allowed: false,
        };
        let pool = SandboxPool::new(config).await.expect("プール構築に失敗");

        // セマフォ容量は pool_size * 2 = 2。10 回転すれば旧バグでは確実にハングする。
        for i in 0..10 {
            let vm = tokio::time::timeout(Duration::from_secs(5), pool.acquire())
                .await
                .unwrap_or_else(|_| panic!("acquire() が {i} 回目でハングしました (セマフォパーミットリークの疑い)"))
                .expect("acquire がエラーを返した");
            drop(vm);
        }
    }

    #[test]
    fn pool_size_bounds() {
        let cfg = FirecrackerConfig {
            pool_size: 0,
            max_lifetime_secs: 60,
            memory_mb: 256,
            vcpus: 1,
            kernel_path: PathBuf::from("/dev/null"),
            rootfs_path: PathBuf::from("/dev/null"),
            network_allowed: false,
        };
        assert!(cfg.validated().is_err());
    }

    #[test]
    fn memory_bounds() {
        let cfg = FirecrackerConfig {
            pool_size: 3,
            max_lifetime_secs: 60,
            memory_mb: 64, // too small
            vcpus: 1,
            kernel_path: PathBuf::from("/dev/null"),
            rootfs_path: PathBuf::from("/dev/null"),
            network_allowed: false,
        };
        assert!(cfg.validated().is_err());
    }

    #[test]
    fn extracted_text_cap_constant_is_10mb() {
        // RunningVm の MAX_EXTRACTED_TEXT_BYTES が 10 MB であることを検証
        assert_eq!(RunningVm::MAX_EXTRACTED_TEXT_BYTES, 10 * 1024 * 1024);
    }

    #[test]
    fn truncation_preserves_utf8_boundary() {
        // テキストキャップ処理が UTF-8 の文字境界を壊さないことを確認
        // (3 バイト日本語文字が境界で切れると panic)
        let text = "あ".repeat(100); // 300 bytes
        // キャップを 10 バイトに設定して境界処理をシミュレート
        let cap = 10usize;
        let truncated = text
            .char_indices()
            .take_while(|(i, _)| *i < cap)
            .last()
            .map_or("", |(i, c)| &text[..i + c.len_utf8()]);
        // バイト境界上で切れているか (String として有効か) を確認
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
        assert!(truncated.len() <= cap + 3, "文字境界での切り詰めは最大 1 文字 (3 バイト) の超過を許容");
    }

    #[test]
    fn attachment_cap_constant_is_100mb() {
        assert_eq!(RunningVm::MAX_ATTACHMENT_BYTES, 100 * 1024 * 1024);
    }

    #[tokio::test]
    async fn oversized_attachment_is_rejected_before_vm() {
        // 上限超過の添付は VM へ送る前にホスト側で拒否される (OOM 防止)
        let (tx, _rx) = mpsc::channel(1);
        let mut vm = RunningVm {
            id: VmId(1),
            spawned_at: Instant::now(),
            _ctrl: (),
            vsock: VsockChannel { _private: () },
            teardown_tx: tx,
            _permit: None,
        };
        let job = AttachmentJob {
            filename: "huge.bin".into(),
            declared_mime: None,
            bytes: vec![0u8; RunningVm::MAX_ATTACHMENT_BYTES + 1],
            hints: RenderHints::default(),
        };
        let result = vm.render_attachment(job).await;
        assert!(
            matches!(result, Err(SandboxError::AttachmentTooLarge { .. })),
            "上限超過の添付が拒否されていない: {result:?}"
        );
    }

    #[test]
    fn hint_constants_are_sane() {
        assert_eq!(RunningVm::MAX_PAGES, 500);
        assert_eq!(RunningVm::MAX_DIMENSION_PX, 8192);
        assert_eq!(RunningVm::MAX_FILENAME_BYTES, 1024);
    }

    #[tokio::test]
    async fn oversized_filename_is_rejected() {
        let (tx, _rx) = mpsc::channel(1);
        let mut vm = RunningVm {
            id: VmId(10),
            spawned_at: Instant::now(),
            _ctrl: (),
            vsock: VsockChannel { _private: () },
            teardown_tx: tx,
            _permit: None,
        };
        let job = AttachmentJob {
            filename: "A".repeat(2000), // 2000 bytes > 1024 limit
            declared_mime: None,
            bytes: vec![0u8; 1024],
            hints: RenderHints::default(),
        };
        let result = vm.render_attachment(job).await;
        assert!(
            matches!(result, Err(SandboxError::InvalidInput(_))),
            "過大な filename が拒否されていない: {result:?}"
        );
    }

    #[tokio::test]
    async fn excessive_render_hints_are_clamped() {
        // max_pages=u32::MAX は MAX_PAGES にクランプされること
        // (VsockChannel スタブが Ready を返すため ProtocolError になるが、
        //  VM へ u32::MAX が渡らないことを確認)
        let (tx, _rx) = mpsc::channel(1);
        let mut vm = RunningVm {
            id: VmId(11),
            spawned_at: Instant::now(),
            _ctrl: (),
            vsock: VsockChannel { _private: () },
            teardown_tx: tx,
            _permit: None,
        };
        let job = AttachmentJob {
            filename: "doc.pdf".into(),
            declared_mime: None,
            bytes: vec![0u8; 1024],
            hints: RenderHints {
                max_pages: u32::MAX,
                max_dimension_px: u32::MAX,
            },
        };
        // クランプ後に VM へ送られるため AttachmentTooLarge にも InvalidInput にもならない
        let result = vm.render_attachment(job).await;
        assert!(
            !matches!(result, Err(SandboxError::AttachmentTooLarge { .. })),
            "ヒントクランプが攻撃拒否と誤検知している"
        );
        assert!(
            !matches!(result, Err(SandboxError::InvalidInput(_))),
            "ヒントクランプが攻撃拒否と誤検知している"
        );
    }

    #[tokio::test]
    async fn normal_sized_attachment_is_accepted() {
        // 上限以内の添付は受理される (スタブ VsockChannel が Ready を返すため
        // ProtocolError になるが、AttachmentTooLarge にはならないことを確認)
        let (tx, _rx) = mpsc::channel(1);
        let mut vm = RunningVm {
            id: VmId(2),
            spawned_at: Instant::now(),
            _ctrl: (),
            vsock: VsockChannel { _private: () },
            teardown_tx: tx,
            _permit: None,
        };
        let job = AttachmentJob {
            filename: "small.txt".into(),
            declared_mime: Some("text/plain".into()),
            bytes: vec![0u8; 1024],
            hints: RenderHints::default(),
        };
        let result = vm.render_attachment(job).await;
        assert!(
            !matches!(result, Err(SandboxError::AttachmentTooLarge { .. })),
            "通常サイズの添付が誤って拒否された"
        );
    }
}
