//! kaname-ui — Tauri 層。
//! commands.rs に 12 個の API ハンドラーが純粋 async fn として実装されている。
//! src-tauri/main.rs が #[tauri::command] でラップする。
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

pub mod commands;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// アプリのロガーを初期化する。
///
/// `kaname_observability::PrivacyLayer` を明示的に登録する。以前は
/// `tracing_subscriber::fmt()...init()` だけで、`PrivacyLayer` は
/// `kaname-observability` に実装・テストされているにもかかわらず、
/// どの subscriber にも組み込まれておらず**一度も実行されていなかった**
/// (CLAUDE.md I5「ログに PII を含めない」を守るはずの唯一の多重防衛層が
/// 完全に無効だった)。`tracing_subscriber::registry()` を土台に
/// `PrivacyLayer` と `fmt::layer()` を両方積む構成に変更する。
pub fn run() {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("kaname=debug,warn"));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(kaname_observability::PrivacyLayer)
        .init();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "Kaname starting");
}
