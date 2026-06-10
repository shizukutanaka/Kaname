//! kaname-tray — macOS メニューバー Extra。
//!
//! - 状態応じたアイコン: Normal / Alert / Focus / Offline
//! - 未読バッジ (99+ 対応)
//! - Apple Notification Center 統合
//! - StartupMetrics (FMP < 421ms 目標)

// crates/kaname-tray/src/lib.rs
//
// Kaname メニューバー Extra
//
// Apple HIG (macOS): メニューバー常駐アプリの設計原則
//   - 最小限の表示: アイコン + 未読バッジのみ
//   - クリックでポップオーバー (フルウィンドウを開かない)
//   - BEC 検出時はアイコン色を変えて注意を促す
//   - Apple Intelligence の Reduce Interruptions に連携
//
// 実装:
//   - tauri::tray::TrayIconBuilder でアイコン登録
//   - tray_icon::menu でコンテキストメニュー
//   - NSStatusBar アイコン (macOS)
//   - 未読数バッジ付き SVG を動的生成

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};

// ============================================================================
// トレイ状態
// ============================================================================

/// トレイに表示する状態。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrayState {
    /// 未読メール数。
    pub unread_count:     u32,
    /// BEC 検出数 (危険/疑わしいメールの件数)。
    pub bec_alert_count:  u32,
    /// アプリが Focus モード中かどうか。
    pub focus_active:     bool,
    /// Focus モードの名前 ("work" / "personal" / "sleep")。
    pub focus_mode:       Option<String>,
    /// JMAP サーバーへの接続状態。
    pub server_connected: bool,
    /// 最後の BEC 検出の概要。
    pub last_bec_summary: Option<String>,
}

/// トレイの表示モード。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayDisplayMode {
    /// 通常状態。
    Normal,
    /// BEC アラートあり。
    Alert,
    /// Focus モード中。
    Focus,
    /// サーバー切断中。
    Offline,
}

impl TrayState {
    /// `display_mode` を実行する。
    pub fn display_mode(&self) -> TrayDisplayMode {
        if !self.server_connected    { return TrayDisplayMode::Offline; }
        if self.bec_alert_count > 0  { return TrayDisplayMode::Alert; }
        if self.focus_active         { return TrayDisplayMode::Focus; }
        TrayDisplayMode::Normal
    }

    #[must_use]
    pub fn badge_text(&self) -> Option<String> {
        if self.unread_count == 0 { return None; }
        if self.unread_count > 99 { return Some("99+".into()); }
        Some(self.unread_count.to_string())
    }
}

// ============================================================================
// SVG アイコン動的生成
// ============================================================================

/// トレイアイコン SVG を状態に応じて生成する。
///
/// Apple HIG: メニューバーアイコンは 18×18pt。
/// テンプレートイメージ (monochromeカラー) を使うとダーク/ライトモード自動対応。
#[must_use]
pub fn render_tray_svg(state: &TrayState, dark_mode: bool) -> String {
    let mode = state.display_mode();
    let fg   = if dark_mode { "#FFFFFF" } else { "#000000" };
    let opacity = "0.85";

    // アイコン色: モード別
    let icon_color = match mode {
        TrayDisplayMode::Alert   => "#FF4444",  // BEC 警告: 赤
        TrayDisplayMode::Focus   => "#00C4CC",  // Focus: ブランドシアン
        TrayDisplayMode::Offline => "#888888",  // オフライン: グレー
        TrayDisplayMode::Normal  => fg,          // 通常: テンプレート色
    };

    let badge = if let Some(n) = state.badge_text() {
        let bw = if n.len() > 2 { 20 } else { 14 };
        format!(
            r#"
            <rect x="{rx}" y="-2" width="{bw}" height="12" rx="6"
                  fill="{fill}"/>
            <text x="{tx}" y="8" text-anchor="middle" font-size="8"
                  font-weight="bold" font-family="system-ui" fill="white">{n}</text>
            "#,
            rx   = 18 - bw,
            bw   = bw,
            fill = if mode == TrayDisplayMode::Alert { "#E5484D" } else { "#00C4CC" },
            tx   = 18 - bw / 2,
            n    = n,
        )
    } else {
        String::new()
    };

    // BEC アラートドット
    let alert_dot = if mode == TrayDisplayMode::Alert {
        r#"<circle cx="16" cy="2" r="3" fill="#E5484D"/>"#.into()
    } else if !state.server_connected {
        r#"<circle cx="16" cy="2" r="3" fill="#888888"/>"#.into()
    } else {
        String::new()
    };

    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18" width="18" height="18">
  <text x="9" y="14" text-anchor="middle" font-size="14"
        font-family="'Hiragino Mincho ProN','Yu Mincho',serif"
        fill="{icon_color}" opacity="{opacity}">要</text>
  {badge}
  {alert_dot}
</svg>"#,
        icon_color = icon_color,
        opacity    = opacity,
        badge      = badge,
        alert_dot  = alert_dot,
    )
}

// ============================================================================
// コンテキストメニュー項目
// ============================================================================

/// メニューバーのコンテキストメニュー項目。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrayMenuItem {
    pub id:      String,
    pub label:   String,
    pub enabled: bool,
    pub kind:    TrayMenuItemKind,
}

/// メニュー項目の種類。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrayMenuItemKind {
    /// 通常のアクション。
    Action,
    /// セパレーター。
    Separator,
    /// サブメニュー。
    Submenu { children: Vec<TrayMenuItem> },
    /// チェックボックス。
    Checkbox { checked: bool },
}

/// 現在の状態に応じたコンテキストメニューを生成する。
#[must_use]
pub fn build_tray_menu(state: &TrayState) -> Vec<TrayMenuItem> {
    let mut items = Vec::new();

    // ── ヘッダー情報 ──
    items.push(TrayMenuItem {
        id:      "header".into(),
        label:   format!(
            "Kaname{}",
            if !state.server_connected { " (オフライン)" } else { "" }
        ),
        enabled: false,
        kind:    TrayMenuItemKind::Action,
    });

    items.push(TrayMenuItem {
        id: "sep1".into(), label: "".into(), enabled: false,
        kind: TrayMenuItemKind::Separator,
    });

    // ── BEC アラート ──
    if state.bec_alert_count > 0 {
        items.push(TrayMenuItem {
            id:      "bec_alert".into(),
            label:   format!("⚠ BEC 検出: {} 件", state.bec_alert_count),
            enabled: true,
            kind:    TrayMenuItemKind::Action,
        });
        if let Some(ref summary) = state.last_bec_summary {
            items.push(TrayMenuItem {
                id:      "bec_detail".into(),
                label:   format!("  {}", &summary[..summary.len().min(40)]),
                enabled: true,
                kind:    TrayMenuItemKind::Action,
            });
        }
        items.push(TrayMenuItem {
            id: "sep_bec".into(), label: "".into(), enabled: false,
            kind: TrayMenuItemKind::Separator,
        });
    }

    // ── 受信トレイ ──
    items.push(TrayMenuItem {
        id:      "open_inbox".into(),
        label:   if state.unread_count > 0 {
            format!("受信トレイを開く ({} 件未読)", state.unread_count)
        } else {
            "受信トレイを開く".into()
        },
        enabled: true,
        kind:    TrayMenuItemKind::Action,
    });

    items.push(TrayMenuItem {
        id:      "compose".into(),
        label:   "新規作成...".into(),
        enabled: state.server_connected,
        kind:    TrayMenuItemKind::Action,
    });

    items.push(TrayMenuItem {
        id: "sep2".into(), label: "".into(), enabled: false,
        kind: TrayMenuItemKind::Separator,
    });

    // ── Focus モード ──
    items.push(TrayMenuItem {
        id:      "focus".into(),
        label:   if state.focus_active {
            format!("Focus: {} — 解除",
                state.focus_mode.as_deref().unwrap_or("有効"))
        } else {
            "Focus モードを有効にする".into()
        },
        enabled: true,
        kind:    TrayMenuItemKind::Checkbox {
            checked: state.focus_active,
        },
    });

    // ── セキュリティ ──
    items.push(TrayMenuItem {
        id:      "security".into(),
        label:   "セキュリティポスチャー...".into(),
        enabled: true,
        kind:    TrayMenuItemKind::Action,
    });

    items.push(TrayMenuItem {
        id: "sep3".into(), label: "".into(), enabled: false,
        kind: TrayMenuItemKind::Separator,
    });

    // ── 設定 ── 終了 ──
    items.push(TrayMenuItem {
        id: "preferences".into(), label: "設定...".into(),
        enabled: true, kind: TrayMenuItemKind::Action,
    });
    items.push(TrayMenuItem {
        id: "about".into(), label: "Kaname について".into(),
        enabled: true, kind: TrayMenuItemKind::Action,
    });

    items.push(TrayMenuItem {
        id: "sep4".into(), label: "".into(), enabled: false,
        kind: TrayMenuItemKind::Separator,
    });

    items.push(TrayMenuItem {
        id: "quit".into(), label: "Kaname を終了".into(),
        enabled: true, kind: TrayMenuItemKind::Action,
    });

    items
}

// ============================================================================
// Tauri コマンド (フロントエンドとの連携)
// ============================================================================

/// トレイ状態を更新する Tauri コマンド。
///
/// メール同期が新しいメールを受信するたびに呼ばれる。
///
/// # 使用例
/// ```typescript
/// await invoke("tray_update", {
///   state: {
///     unread_count: 5,
///     bec_alert_count: 1,
///     focus_active: false,
///     server_connected: true,
///   }
/// });
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct TrayUpdatePayload {
    pub state: TrayState,
}

/// トレイアイコンのクリックイベント。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrayClickEvent {
    /// クリックの種類 ("left" / "right" / "double")。
    pub click_type: String,
    /// クリック位置 (スクリーン座標)。
    pub x: f64,
    pub y: f64,
}

// ============================================================================
// 通知システム (Apple Notification Center 統合)
// ============================================================================

/// Kaname の通知種別。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    /// 新着メール (通常)。
    NewMail,
    /// BEC 危険検出。
    BecDangerous,
    /// BEC 疑わしい。
    BecSuspicious,
    /// MLS 安全番号変更。
    SafetyNumberChanged,
    /// JMAP サーバー切断。
    ServerDisconnected,
}

/// 通知リクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRequest {
    /// 通知の種別。
    pub kind:    NotificationKind,
    /// タイトル。
    pub title:   String,
    /// 本文。
    pub body:    String,
    /// 関連するメール ID (ない場合は None)。
    pub email_id: Option<String>,
    /// インタラクティブアクション (Apple HIG: inline reply)。
    pub actions: Vec<NotificationAction>,
}

/// 通知アクション (Apple HIG: インタラクティブ通知)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationAction {
    pub id:    String,
    pub title: String,
    /// 破壊的操作かどうか (Apple HIG: 赤色で表示)。
    pub is_destructive: bool,
}

/// 通知を Apple Notification Center 経由で表示する。
pub fn notification_request_for_bec(
    email_subject: &str,
    verdict: &str,
) -> NotificationRequest {
    NotificationRequest {
        kind:  NotificationKind::BecDangerous,
        title: "⚠ BEC 攻撃を検出".into(),
        body:  format!(
            "「{}」は {} の可能性があります。送信者の身元を別経路で確認してください。",
            &email_subject[..email_subject.len().min(30)],
            verdict,
        ),
        email_id: None,
        actions: vec![
            NotificationAction {
                id: "view_detail".into(),
                title: "詳細を見る".into(),
                is_destructive: false,
            },
            NotificationAction {
                id: "mark_safe".into(),
                title: "安全とマーク".into(),
                is_destructive: false,
            },
            NotificationAction {
                id: "delete".into(),
                title: "削除".into(),
                is_destructive: true,
            },
        ],
    }
}

/// 新着メール通知 (inline reply 対応)。
pub fn notification_request_for_new_mail(
    from_name: Option<&str>,
    subject: &str,
    preview: &str,
) -> NotificationRequest {
    NotificationRequest {
        kind:  NotificationKind::NewMail,
        title: from_name.unwrap_or("新着メール").into(),
        body:  format!("{}\n{}", subject, &preview[..preview.len().min(60)]),
        email_id: None,
        actions: vec![
            NotificationAction {
                id: "reply".into(),
                title: "返信".into(),
                is_destructive: false,
            },
            NotificationAction {
                id: "archive".into(),
                title: "アーカイブ".into(),
                is_destructive: false,
            },
            NotificationAction {
                id: "mark_read".into(),
                title: "既読にする".into(),
                is_destructive: false,
            },
        ],
    }
}

// ============================================================================
// パフォーマンス計測
// ============================================================================

/// コールドスタート時間を計測する。
///
/// Apple HIG: アプリ起動は < 400ms。Kaname の目標は < 421ms。
/// (Superhuman の起動時間を参考に設定)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupMetrics {
    /// プロセス起動 → first meaningful paint (ms)。
    pub time_to_fmp_ms:       u64,
    /// first meaningful paint → interactive (ms)。
    pub time_to_interactive_ms: u64,
    /// JMAP 初回同期完了 (ms)。
    pub time_to_first_mail_ms: u64,
    /// AI モデル読み込み完了 (ms)。
    pub time_to_ai_ready_ms:  u64,
}

impl StartupMetrics {
    /// 目標値を満たしているかを検証する。
    #[must_use]
    pub fn meets_targets(&self) -> bool {
        self.time_to_fmp_ms         <  421  // < 421ms
            && self.time_to_interactive_ms <  800  // < 800ms
            && self.time_to_first_mail_ms  < 2000  // < 2s
            && self.time_to_ai_ready_ms    < 4000  // < 4s (Phi-4-mini 量子化)
    }

    /// パフォーマンスレポートを文字列で返す。
    #[must_use]
    pub fn report(&self) -> String {
        let ok = if self.meets_targets() { "✓ PASS" } else { "✗ FAIL" };
        format!(
            "{ok}\n\
             FMP:          {}ms (目標 <421ms) {}\n\
             Interactive:  {}ms (目標 <800ms) {}\n\
             First mail:   {}ms (目標 <2000ms) {}\n\
             AI ready:     {}ms (目標 <4000ms) {}",
            self.time_to_fmp_ms,         if self.time_to_fmp_ms < 421 { "✓" } else { "✗" },
            self.time_to_interactive_ms, if self.time_to_interactive_ms < 800 { "✓" } else { "✗" },
            self.time_to_first_mail_ms,  if self.time_to_first_mail_ms < 2000 { "✓" } else { "✗" },
            self.time_to_ai_ready_ms,    if self.time_to_ai_ready_ms < 4000 { "✓" } else { "✗" },
        )
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 通常状態のバッジなし() {
        let state = TrayState { unread_count: 0, ..Default::default() };
        assert_eq!(state.badge_text(), None);
    }

    #[test]
    fn 未読99件以上は99プラス() {
        let state = TrayState { unread_count: 150, ..Default::default() };
        assert_eq!(state.badge_text(), Some("99+".into()));
    }

    #[test]
    fn bec_アラートはalertモード() {
        let state = TrayState {
            bec_alert_count:  1,
            server_connected: true,
            ..Default::default()
        };
        assert_eq!(state.display_mode(), TrayDisplayMode::Alert);
    }

    #[test]
    fn オフライン状態検出() {
        let state = TrayState { server_connected: false, ..Default::default() };
        assert_eq!(state.display_mode(), TrayDisplayMode::Offline);
    }

    #[test]
    fn svg生成が非空() {
        let state = TrayState {
            unread_count: 5, bec_alert_count: 1,
            server_connected: true, ..Default::default()
        };
        let svg = render_tray_svg(&state, true);
        assert!(!svg.is_empty());
        assert!(svg.contains("<svg"));
        assert!(svg.contains("要"));
    }

    #[test]
    fn bec通知リクエストが正しく生成される() {
        let req = notification_request_for_bec(
            "【至急】振込先変更のご連絡",
            "DANGEROUS",
        );
        assert_eq!(req.kind, NotificationKind::BecDangerous);
        assert_eq!(req.actions.len(), 3);
        assert!(req.actions.iter().any(|a| a.id == "delete" && a.is_destructive));
    }

    #[test]
    fn 新着メール通知にinline_replyアクション含む() {
        let req = notification_request_for_new_mail(
            Some("田中 花子"),
            "Q2予算会議のご案内",
            "来週火曜日に会議を設定しました",
        );
        assert_eq!(req.kind, NotificationKind::NewMail);
        assert!(req.actions.iter().any(|a| a.id == "reply"));
    }

    #[test]
    fn パフォーマンス目標値の検証ロジック() {
        let good = StartupMetrics {
            time_to_fmp_ms:         200,
            time_to_interactive_ms: 600,
            time_to_first_mail_ms:  1500,
            time_to_ai_ready_ms:    3000,
        };
        assert!(good.meets_targets());

        let slow = StartupMetrics {
            time_to_fmp_ms:         500,  // ✗ 目標超過
            time_to_interactive_ms: 600,
            time_to_first_mail_ms:  1500,
            time_to_ai_ready_ms:    3000,
        };
        assert!(!slow.meets_targets());
    }

    #[test]
    fn トレイメニューにbec項目が含まれる() {
        let state = TrayState {
            bec_alert_count:  2,
            server_connected: true,
            last_bec_summary: Some("至急: 振込先変更".into()),
            ..Default::default()
        };
        let menu = build_tray_menu(&state);
        assert!(menu.iter().any(|i| i.id == "bec_alert"));
    }

    #[test]
    fn オフライン状態でcomposeが無効() {
        let state = TrayState { server_connected: false, ..Default::default() };
        let menu  = build_tray_menu(&state);
        let compose = menu.iter().find(|i| i.id == "compose").unwrap();
        assert!(!compose.enabled);
    }

    #[test]
    fn focus中のメニューラベル確認() {
        let state = TrayState {
            focus_active: true,
            focus_mode:   Some("work".into()),
            server_connected: true,
            ..Default::default()
        };
        let menu = build_tray_menu(&state);
        let focus_item = menu.iter().find(|i| i.id == "focus").unwrap();
        assert!(focus_item.label.contains("解除"));
        assert!(matches!(focus_item.kind, TrayMenuItemKind::Checkbox { checked: true }));
    }
}
