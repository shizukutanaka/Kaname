//! kaname-ui — Tauri 層。
//! commands.rs に 12 個の API ハンドラーが純粋 async fn として実装されている。
//! src-tauri/main.rs が #[tauri::command] でラップする。
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

pub mod commands;

use tracing_subscriber::EnvFilter;

/// アプリのロガーを初期化する。
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("kaname=debug,warn"))
        )
        .init();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "Kaname starting");
}
