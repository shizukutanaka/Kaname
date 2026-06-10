//! Kaname — Tauri 2.x エントリポイント
//!
//! kaname-ui::commands の純粋 async 関数を Tauri コマンドとして登録する。
//! 全 invoke() ルートをここで結線する。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use kaname_ui::commands;
use tauri::Manager;
use tracing_subscriber::EnvFilter;

// ============================================================================
// Tauri コマンドラッパー
// kaname-ui の純粋関数に #[tauri::command] を付けて公開
// ============================================================================

#[tauri::command]
async fn health_check() -> Result<commands::HealthResponse, String> {
    commands::health_check().await
}

#[tauri::command]
async fn mail_get_summary() -> Result<commands::MailSummary, String> {
    commands::mail_get_summary().await
}

#[tauri::command]
async fn mail_list(mailbox: String, limit: Option<u32>) -> Result<Vec<commands::EmailRow>, String> {
    commands::mail_list(mailbox, limit).await
}

#[tauri::command]
async fn mail_get_body(email_id: String) -> Result<String, String> {
    commands::mail_get_body(email_id).await
}

#[tauri::command]
async fn mail_mark_read(ids: Vec<String>) -> Result<(), String> {
    commands::mail_mark_read(ids).await
}

#[tauri::command]
async fn mail_trash(email_id: String) -> Result<(), String> {
    commands::mail_trash(email_id).await
}

#[tauri::command]
async fn ai_detect_phishing(email_id: String) -> Result<commands::PhishingAnalysis, String> {
    commands::ai_detect_phishing(email_id).await
}

#[tauri::command]
async fn ai_summarize_email(email_id: String) -> Result<commands::SafeSummary, String> {
    commands::ai_summarize_email(email_id).await
}

#[tauri::command]
async fn ai_smart_reply(email_id: String) -> Result<Vec<commands::SmartReplyCandidate>, String> {
    commands::ai_smart_reply(email_id).await
}

#[tauri::command]
async fn settings_set(account_id: String, key: String, value: String) -> Result<(), String> {
    commands::settings_set(account_id, key, value).await
}

#[tauri::command]
async fn settings_get(account_id: String, key: String) -> Result<Option<String>, String> {
    commands::settings_get(account_id, key).await
}

#[tauri::command]
async fn log_error(message: String) -> Result<(), String> {
    commands::log_error(message).await
}

// ============================================================================
// メインエントリポイント
// ============================================================================

fn main() {
    // ── ログ初期化 ──
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("kaname=debug,warn"))
        )
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Kaname starting"
    );

    // ── Tauri アプリ構築 ──
    tauri::Builder::default()
        .setup(|app| {
            // ウィンドウ作成時の処理
            #[cfg(desktop)]
            {
                let _ = app.handle();
                tracing::info!("Application setup complete");
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            health_check,
            mail_get_summary,
            mail_list,
            mail_get_body,
            mail_mark_read,
            mail_trash,
            ai_detect_phishing,
            ai_summarize_email,
            ai_smart_reply,
            settings_set,
            settings_get,
            log_error,
        ])
        .run(tauri::generate_context!())
        .expect("Tauri アプリの起動に失敗しました");
}
