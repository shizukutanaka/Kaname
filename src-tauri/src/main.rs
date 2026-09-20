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
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, RunEvent};

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

/// メール件数変化後に `mail:summary_updated` を発行する。
///
/// フロントエンドはこのイベントでサイドバーの未読/BEC警戒バッジを
/// 更新する。発行側が無いと購読だけのデッドイベントになるため、
/// 件数が変わりうるコマンド (fetch/mark_read/trash) の成功時に呼ぶ。
async fn emit_summary_updated(app: &AppHandle) {
    if let Ok(s) = commands::mail_get_summary().await {
        let _ = app.emit(
            "mail:summary_updated",
            serde_json::json!({ "unread": s.unread, "bec": s.bec_alerts }),
        );
    }
}

#[tauri::command]
async fn mail_open(email_id: String) -> Result<commands::ImportedEmail, String> {
    commands::mail_open(email_id).await
}

#[tauri::command]
async fn mail_mark_read(app: AppHandle, ids: Vec<String>) -> Result<(), String> {
    commands::mail_mark_read(ids).await?;
    emit_summary_updated(&app).await;
    Ok(())
}

#[tauri::command]
async fn mail_trash(app: AppHandle, email_id: String) -> Result<(), String> {
    commands::mail_trash(email_id).await?;
    emit_summary_updated(&app).await;
    Ok(())
}

#[tauri::command]
async fn ai_detect_phishing(email_id: String) -> Result<commands::PhishingAnalysis, String> {
    commands::ai_detect_phishing(email_id).await
}

#[tauri::command]
async fn log_error(message: String) -> Result<(), String> {
    commands::log_error(message).await
}

/// OOBV (電話確認) の必要性判定。
#[tauri::command]
async fn oobv_recommend(
    req: commands::OobvRecommendRequest,
) -> Result<commands::OobvRecommendResponse, commands::V02CommandError> {
    commands::oobv_recommend(req).await
}

// ── V02AppState を共有するコマンド (D15 残件) ────────────────────────────────
//
// oobv_start / oobv_verify は `Arc<V02AppState>` を引数に取るため、
// `.manage()` でステートを登録し `tauri::State` として受け取る必要が
// あった。ここで配線して到達可能にする。

/// OOBV (Out-of-Band Verification) セレモニーを開始する。
#[tauri::command]
async fn oobv_start(
    state: tauri::State<'_, std::sync::Arc<commands::V02AppState>>,
    req: commands::OobvStartRequest,
) -> Result<commands::OobvStartResponse, commands::V02CommandError> {
    commands::oobv_start(state.inner().clone(), req).await
}

/// OOBV セレモニーを検証する (ユーザーの合い言葉を照合)。
#[tauri::command]
async fn oobv_verify(
    state: tauri::State<'_, std::sync::Arc<commands::V02AppState>>,
    req: commands::OobvVerifyRequest,
) -> Result<commands::OobvVerifyResponse, commands::V02CommandError> {
    commands::oobv_verify(state.inner().clone(), req).await
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

/// ローカルの `.eml` ファイルを読み込み、実際のメールをパイプライン全体に通す。
///
/// 本製品で**初めて実メールが検出器に流れる**経路。JMAP 受信 (D10) の配線を
/// 待たずに、解析・認証評価・BEC 判定・サニタイズを実データで動かせる。
#[tauri::command]
async fn mail_import_eml(path: String) -> Result<commands::ImportedEmail, String> {
    commands::mail_import_eml(path).await
}

/// フォルダ内の .eml を一括解析し、キャンペーン検出も行う。
///
/// `kaname-radar` (PCR) は複数メールを見比べて初めて機能するため、
/// 一括解析がこの検出器を動かす唯一の現実的な入口となる。
#[tauri::command]
async fn mail_scan_folder(path: String) -> Result<commands::FolderScanResult, String> {
    commands::mail_scan_folder(path).await
}

/// 送信前の DLP 警告を返す (Compose が送信クリック時に呼ぶ)。
/// mail_send は Block のみ止めるため、Warn 所見はここで表示する。
#[tauri::command]
async fn mail_dlp_precheck(
    req: commands::DlpPrecheckRequest,
) -> Result<commands::DlpPrecheckResponse, String> {
    commands::mail_dlp_precheck(req).await
}

/// メールを送信する (JMAP)。送信前に DLP (Outbound) を実行する。
#[tauri::command]
async fn mail_send(
    from: String,
    to: Vec<String>,
    subject: String,
    body: String,
) -> Result<String, String> {
    commands::mail_send_real(from, to, subject, body).await
}

/// JMAP サーバへ接続し、メールボックス一覧を取得する。
#[tauri::command]
async fn mail_connect(base_url: String, token: String) -> Result<commands::ConnectResult, String> {
    commands::mail_connect(base_url, token).await
}

/// 接続を破棄する (トークンをメモリから落とす)。
#[tauri::command]
async fn mail_disconnect() -> Result<(), String> {
    commands::mail_disconnect().await
}

/// 添付ファイルをダウンロードし、検査してから隔離保存する。
///
/// 危険と判定された添付はディスクに書かず、検査結果のみ返す。
#[tauri::command]
async fn mail_download_attachment(
    email_id: String,
    blob_id: String,
) -> Result<commands::AttachmentDownload, String> {
    commands::mail_download_attachment(email_id, blob_id).await
}

#[tauri::command]
async fn mail_list_attachment_blobs(
    email_id: String,
) -> Result<Vec<commands::AttachmentRef>, String> {
    commands::mail_list_attachment_blobs(email_id).await
}

/// 保存済みメールを新しい順に返す (オフライン閲覧)。
#[tauri::command]
async fn mail_list_stored(
    mailbox_id: String,
    limit: Option<u32>,
) -> Result<Vec<commands::StoredMessage>, String> {
    commands::mail_list_stored(mailbox_id, limit).await
}

/// 保存済みメールを検索する (件名・送信者・本文プレビュー)。
#[tauri::command]
async fn mail_search(
    query: String,
    limit: Option<u32>,
) -> Result<Vec<commands::StoredMessage>, String> {
    commands::mail_search(query, limit).await
}

/// 送信者を「検証済み」としてマークする。
#[tauri::command]
async fn history_mark_verified(email: String) -> Result<(), String> {
    commands::history_mark_verified(email).await
}

/// サーバからメール一覧を取得し、各通に BEC 判定を付けて返す。
#[tauri::command]
async fn mail_fetch(
    app: AppHandle,
    mailbox_id: String,
    limit: Option<u32>,
) -> Result<Vec<commands::EmailRow>, String> {
    let rows = commands::mail_fetch(mailbox_id, limit).await?;
    emit_summary_updated(&app).await;
    Ok(rows)
}

#[tauri::command]
async fn mail_get_mailboxes() -> Result<Vec<commands::MailboxRow>, String> {
    commands::mail_get_mailboxes().await
}

#[tauri::command]
async fn settings_save_onboarding(
    notifications: bool,
    continuity: bool,
    telemetry: bool,
) -> Result<(), String> {
    commands::settings_save_onboarding(notifications, continuity, telemetry).await
}

#[tauri::command]
async fn settings_is_onboarded() -> bool {
    commands::settings_is_onboarded().await
}

#[tauri::command]
async fn history_open_default() -> Result<String, String> {
    commands::history_open_default().await
}

#[tauri::command]
async fn security_audit_log(limit: Option<i64>) -> Result<commands::AuditLogView, String> {
    commands::security_audit_log(limit).await
}

// ============================================================================
// トレイアイコンセットアップ
// ============================================================================

#[cfg(desktop)]
fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let menu = Menu::with_items(
        app,
        &[
            &MenuItem::with_id(app, "open", "受信トレイを開く", true, None::<&str>)?,
            &MenuItem::with_id(app, "compose", "新規作成...", true, Some("CmdOrCtrl+N"))?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(
                app,
                "security",
                "セキュリティポスチャー...",
                true,
                None::<&str>,
            )?,
            // 「設定」「Kaname について」項目は対応する UI ビューが存在せず
            // emit 先が無いため削除 (押しても何も起きないデッドコントロール)。
            // ビューを実装する際に git 履歴から復元すること。
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "quit", "Kaname を終了", true, Some("CmdOrCtrl+Q"))?,
        ],
    )?;

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
        tracing::warn!(
            "デフォルトウィンドウアイコンが取得できませんでした (トレイアイコンは既定値を使用)"
        );
    }
    let _tray = tray_builder
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "compose" => {
                let _ = app.emit("menu:compose", ());
            }
            "security" => {
                let _ = app.emit("menu:security", ());
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
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
        // OOBV セレモニー / 監査ログの共有状態 (D15 残件)。
        // `oobv_start`/`oobv_verify` が tauri::State 経由で受け取る。
        .manage(commands::V02AppState::new())
        .setup(|app| {
            #[cfg(desktop)]
            setup_tray(app.handle())?;
            tracing::info!("Tauri ready");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            health_check,
            mail_get_summary,
            mail_open,
            mail_mark_read,
            mail_trash,
            ai_detect_phishing,
            log_error,
            oobv_recommend,
            // V02AppState を共有するコマンド (D15 残件、.manage() で配線)
            oobv_start,
            oobv_verify,
            // 実メールの入口 (ローカル .eml インポート)
            mail_import_eml,
            mail_scan_folder,
            // JMAP サーバとの実接続 (受信・送信)
            mail_connect,
            mail_disconnect,
            mail_fetch,
            // 送信者履歴 (BEC の履歴シグナルに供給)
            mail_download_attachment,
            mail_list_attachment_blobs,
            mail_list_stored,
            mail_search,
            history_mark_verified,
            // 未配線であることを明示的に返すコマンド (UI の不可解な失敗を解消)
            mail_dlp_precheck,
            mail_send,
            mail_get_mailboxes,
            settings_save_onboarding,
            settings_is_onboarded,
            history_open_default,
            security_audit_log,
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
