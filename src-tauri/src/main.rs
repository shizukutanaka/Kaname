// src-tauri/src/main.rs
//
// Tauri 2.x エントリポイント
//
// 設計:
//   - kaname-ui の純粋 async fn を #[tauri::command] でラップ
//   - 全コマンドを invoke_handler に登録
//   - tray_icon を初期化、左クリックでメインウィンドウをトグル
//   - macOS: ウィンドウを閉じてもアプリは終了しない (トレイから復帰可能)

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use kaname_ui::commands;
use tauri::{AppHandle, Manager, Emitter, RunEvent};
use tauri::tray::{TrayIconBuilder, MouseButton, MouseButtonState, TrayIconEvent};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};

// ============================================================================
// Tauri コマンドラッパー
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
// トレイアイコンセットアップ
// ============================================================================

#[cfg(desktop)]
fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let menu = Menu::with_items(app, &[
        &MenuItem::with_id(app, "open",     "受信トレイを開く", true, None::<&str>)?,
        &MenuItem::with_id(app, "compose",  "新規作成...",     true, Some("CmdOrCtrl+N"))?,
        &PredefinedMenuItem::separator(app)?,
        &MenuItem::with_id(app, "security", "セキュリティポスチャー...", true, None::<&str>)?,
        &MenuItem::with_id(app, "settings", "設定...",         true, Some("CmdOrCtrl+,"))?,
        &PredefinedMenuItem::separator(app)?,
        &MenuItem::with_id(app, "about",    "Kaname について",  true, None::<&str>)?,
        &MenuItem::with_id(app, "quit",     "Kaname を終了",   true, Some("CmdOrCtrl+Q"))?,
    ])?;

    let _tray = TrayIconBuilder::new()
        .menu(&menu)
        .menu_on_left_click(false)
        .icon(app.default_window_icon().cloned().unwrap())
        .icon_as_template(true) // macOS テンプレート画像
        .tooltip("Kaname")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "compose"  => { let _ = app.emit("menu:compose", ()); }
            "security" => { let _ = app.emit("menu:security", ()); }
            "settings" => { let _ = app.emit("menu:settings", ()); }
            "about"    => { let _ = app.emit("menu:about", ()); }
            "quit"     => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up, ..
            } = event {
                if let Some(window) = tray.app_handle().get_webview_window("main") {
                    if window.is_visible().unwrap_or(false) {
                        let _ = window.hide();
                    } else {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
            }
        })
        .build(app)?;

    Ok(())
}

// ============================================================================
// メイン
// ============================================================================

fn main() {
    // kaname-ui のロガーを初期化
    kaname_ui::run();

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            #[cfg(desktop)]
            setup_tray(app.handle())?;
            tracing::info!("Tauri ready");
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
        .build(tauri::generate_context!())
        .expect("Failed to build Tauri application");

    app.run(|_app_handle, event| {
        if let RunEvent::ExitRequested { api, .. } = event {
            // macOS: ウィンドウを閉じてもアプリは終了しない
            #[cfg(target_os = "macos")]
            api.prevent_exit();
            // (他プラットフォームでは通常通り終了)
            #[cfg(not(target_os = "macos"))]
            let _ = api;
        }
    });
}
