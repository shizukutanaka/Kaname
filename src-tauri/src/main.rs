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
async fn mail_get_body(email_id: String) -> Result<commands::BodyDto, String> {
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
// arxiv 研究ベースの防御コマンド (これまで未登録で到達不能だったもの)
//
// これらは kaname-ui に実装・テスト済みだが、`invoke_handler` に登録されて
// おらず、かつ commands.rs 側の `#[cfg_attr(feature = "tauri-app", ...)]` も
// src-tauri が `features = ["tauri-app"]` を指定していないため無効だった。
// 結果としてフロントエンドから一切呼び出せない「死蔵」状態だった。
// 既存コマンドと同じラッパー方式で登録し、実際に到達可能にする。
// ============================================================================

/// 入力スクリーニング (arxiv 2505.22852 §2.1)。
#[tauri::command]
async fn screen_user_input(input: String) -> Result<commands::ScreenResponse, String> {
    commands::screen_user_input(input).await
}

/// AI 出力監査 (arxiv 2505.22852 §2.2)。
#[tauri::command]
async fn audit_ai_output(output: String) -> Result<bool, String> {
    commands::audit_ai_output(output).await
}

/// Tiered-Risk アクセス制御 (arxiv 2505.22852 §3)。
#[tauri::command]
async fn check_action_risk(action_name: String, involves_untrusted: bool) -> Result<String, String> {
    commands::check_action_risk(action_name, involves_untrusted).await
}

/// メモリ汚染防御の信頼スコア (arxiv 2601.05504)。
#[tauri::command]
async fn check_memory_trust(source_kind: String, content_hint: String) -> Result<f32, String> {
    commands::check_memory_trust(source_kind, content_hint).await
}

/// Rule of Two 判定 (arxiv 2601.17548)。
#[tauri::command]
async fn check_rule_of_two(
    process_untrusted: bool,
    access_sensitive: bool,
    external_comm: bool,
) -> Result<String, String> {
    commands::check_rule_of_two(process_untrusted, access_sensitive, external_comm).await
}

/// ツール引数すり替え検証 (arxiv 2601.11893)。
#[tauri::command]
async fn validate_tool_argument(
    expected_recipient: String,
    actual_arg: String,
) -> Result<bool, String> {
    commands::validate_tool_argument(expected_recipient, actual_arg).await
}

/// エージェント行動履歴の記録 (トラジェクトリ監視)。
#[tauri::command]
async fn record_agent_step(
    action: String,
    touched_untrusted: bool,
    accessed_sensitive: bool,
    external_comm: bool,
    timestamp_ms: u64,
) -> Result<Vec<String>, String> {
    commands::record_agent_step(action, touched_untrusted, accessed_sensitive, external_comm, timestamp_ms).await
}

/// トラジェクトリのリセット。
#[tauri::command]
async fn reset_trajectory() -> Result<(), String> {
    commands::reset_trajectory().await
}

/// OOBV (電話確認) の必要性判定。
#[tauri::command]
async fn oobv_recommend(
    req: commands::OobvRecommendRequest,
) -> Result<commands::OobvRecommendResponse, commands::V02CommandError> {
    commands::oobv_recommend(req).await
}

/// Deepfake 添付の警告判定。
#[tauri::command]
async fn deepfake_evaluate(
    req: commands::DeepfakeEvaluateRequest,
) -> Result<commands::AdvisoryReport, commands::V02CommandError> {
    commands::deepfake_evaluate(req).await
}

// ============================================================================
// 未配線コマンド (フロントエンドが呼ぶが実装が存在しなかったもの)
//
// UI は以下を invoke するが Tauri 側に定義が無く、「コマンドが存在しない」と
// いう不可解なエラーで失敗していた (特に Inbox は起動時 mail_get_mailboxes の
// 失敗でメール一覧が永久に空になっていた)。
// 偽のデータを返すとデモの偽装を深めるため、**明示的な「未配線」エラー**を
// 返して失敗理由が UI に表示されるようにする。
// 実際の配線 (JMAP 受信・送信・永続化) は docs/gap-analysis.md D10 を参照。
// ============================================================================

/// バックエンド未配線を示す共通エラー文言。
fn not_wired(feature: &str) -> String {
    format!(
        "未配線: {feature} はまだバックエンドに接続されていません \
         (JMAP 受信・送信・永続化は未実装。docs/maturity.md / docs/gap-analysis.md D10 参照)"
    )
}

#[tauri::command]
async fn mail_send(req: serde_json::Value) -> Result<(), String> {
    let _ = req;
    Err(not_wired("メール送信"))
}

#[tauri::command]
async fn mail_get_mailboxes() -> Result<Vec<serde_json::Value>, String> {
    Err(not_wired("メールボックス取得"))
}

#[tauri::command]
async fn mail_query_emails(
    mailbox_id: String,
    position: Option<u32>,
    limit: Option<u32>,
) -> Result<Vec<serde_json::Value>, String> {
    let _ = (mailbox_id, position, limit);
    Err(not_wired("メール一覧取得"))
}

#[tauri::command]
async fn bec_get_score(email_id: String) -> Result<serde_json::Value, String> {
    let _ = email_id;
    Err(not_wired("BEC スコア取得"))
}

#[tauri::command]
async fn settings_save_onboarding(
    notifications: bool,
    continuity: bool,
    telemetry: bool,
) -> Result<(), String> {
    let _ = (notifications, continuity, telemetry);
    Err(not_wired("オンボーディング設定の保存"))
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

    let mut tray_builder = TrayIconBuilder::new()
        .menu(&menu)
        .show_menu_on_left_click(false)
        .icon_as_template(true) // macOS テンプレート画像
        .tooltip("Kaname");
    // デフォルトアイコンが取得できない場合でもトレイ自体は生成を継続する
    // (修正前は .unwrap() で取得失敗時にアプリ全体がクラッシュしていた)。
    if let Some(icon) = app.default_window_icon().cloned() {
        tray_builder = tray_builder.icon(icon);
    } else {
        tracing::warn!("デフォルトウィンドウアイコンが取得できませんでした (トレイアイコンは既定値を使用)");
    }
    let _tray = tray_builder
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
            // arxiv 研究ベースの防御コマンド (今回登録して到達可能化)
            screen_user_input,
            audit_ai_output,
            check_action_risk,
            check_memory_trust,
            check_rule_of_two,
            validate_tool_argument,
            record_agent_step,
            reset_trajectory,
            oobv_recommend,
            deepfake_evaluate,
            // 未配線であることを明示的に返すコマンド (UI の不可解な失敗を解消)
            mail_send,
            mail_get_mailboxes,
            mail_query_emails,
            bec_get_score,
            settings_save_onboarding,
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
