//! kaname-mockserver — JMAP モックサーバー。
//!
//! - 開発環境: 実 JMAP なしでフロントエンド動作確認
//! - E2E テスト: 既知のフィクスチャで Playwright 実行
//! - 5 種のフィクスチャ: 通常 / BEC / AI フィッシング / ニュースレター / 領収書

// crates/kaname-mockserver/src/lib.rs
//
// JMAP モックサーバー
//
// 用途:
//   1. 開発環境: 実 JMAP サーバーなしでフロントエンドを動かす
//   2. E2E テスト: 既知のメールセットで Playwright テストを実行
//   3. ファジング: 異常な JMAP レスポンスを送ってクライアントの堅牢性確認
//
// 実行: cargo run -p kaname-mockserver --bin jmap-mock
// → http://127.0.0.1:8080 で JMAP-over-HTTP 互換 API を提供

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

// ============================================================================
// JMAP Email オブジェクト (簡略版)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JmapEmail {
    pub id:           String,
    pub mailbox_ids:  HashMap<String, bool>,
    pub keywords:     HashMap<String, bool>,
    pub from:         Vec<EmailAddress>,
    pub to:           Vec<EmailAddress>,
    pub subject:      Option<String>,
    pub received_at:  String,   // ISO-8601
    pub preview:      String,
    pub body_values:  HashMap<String, BodyValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAddress {
    pub name:  Option<String>,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyValue {
    pub value:        String,
    pub is_truncated: bool,
}

// ============================================================================
// テストフィクスチャ — 既知のメールセット
// ============================================================================

#[must_use]
pub fn fixture_emails() -> Vec<JmapEmail> {
    vec![
        // 通常メール
        JmapEmail {
            id: "fix-001".into(),
            mailbox_ids: hm(&[("inbox", true)]),
            keywords:    hm(&[]),
            from:        vec![EmailAddress {
                name: Some("田中 花子".into()),
                email: "hanako@company.co.jp".into(),
            }],
            to:           vec![EmailAddress { name: Some("自分".into()), email: "me@kaname.app".into() }],
            subject:      Some("Q2予算会議のご案内".into()),
            received_at:  "2026-04-26T09:00:00Z".into(),
            preview:      "来週火曜日に会議を設定しました".into(),
            body_values:  hm_body(&[("1", "<p>来週火曜日に会議を設定しました。参加可能でしょうか。</p>")]),
        },
        // BEC 攻撃
        JmapEmail {
            id: "fix-002".into(),
            mailbox_ids: hm(&[("inbox", true)]),
            keywords:    hm(&[]),
            from:        vec![EmailAddress {
                name: Some("CFO".into()),
                email: "cfo@arnazon-billing.com".into(), // 偽装ドメイン
            }],
            to:           vec![EmailAddress { name: None, email: "me@kaname.app".into() }],
            subject:      Some("【至急】振込先変更のご連絡".into()),
            received_at:  "2026-04-26T08:00:00Z".into(),
            preview:      "新しい銀行口座に200万円をご送金ください".into(),
            body_values:  hm_body(&[("1", "<p>至急、新しい口座にお振込お願いします。本日中に処理してください。</p>")]),
        },
        // AI 生成フィッシング
        JmapEmail {
            id: "fix-003".into(),
            mailbox_ids: hm(&[("inbox", true)]),
            keywords:    hm(&[]),
            from:        vec![EmailAddress {
                name: None,
                email: "support@amaz0n.co.jp".into(),  // typosquatting
            }],
            to:           vec![EmailAddress { name: None, email: "me@kaname.app".into() }],
            subject:      Some("Account Verification Required".into()),
            received_at:  "2026-04-26T07:00:00Z".into(),
            preview:      "I hope this email finds you well".into(),
            body_values:  hm_body(&[("1", "I hope this email finds you well. Please don't hesitate to verify your account immediately.")]),
        },
        // ニュースレター
        JmapEmail {
            id: "fix-004".into(),
            mailbox_ids: hm(&[("inbox", true)]),
            keywords:    hm(&[("$seen", true)]),
            from:        vec![EmailAddress { name: Some("TechCrunch Japan".into()), email: "newsletter@techcrunch.com".into() }],
            to:           vec![EmailAddress { name: None, email: "me@kaname.app".into() }],
            subject:      Some("週刊AIニュース".into()),
            received_at:  "2026-04-25T08:00:00Z".into(),
            preview:      "今週の注目ニュース".into(),
            body_values:  hm_body(&[("1", "<p>週刊ニュースレター</p>")]),
        },
        // 領収書
        JmapEmail {
            id: "fix-005".into(),
            mailbox_ids: hm(&[("inbox", true)]),
            keywords:    hm(&[("$seen", true)]),
            from:        vec![EmailAddress { name: Some("Amazon".into()), email: "no-reply@amazon.co.jp".into() }],
            to:           vec![EmailAddress { name: None, email: "me@kaname.app".into() }],
            subject:      Some("ご注文の確認 #123-456".into()),
            received_at:  "2026-04-24T15:00:00Z".into(),
            preview:      "ご注文ありがとうございます".into(),
            body_values:  hm_body(&[("1", "<p>ご注文ありがとうございます</p>")]),
        },
    ]
}

fn hm(pairs: &[(&str, bool)]) -> HashMap<String, bool> {
    pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

fn hm_body(pairs: &[(&str, &str)]) -> HashMap<String, BodyValue> {
    pairs.iter().map(|(k, v)| (
        k.to_string(),
        BodyValue { value: v.to_string(), is_truncated: false }
    )).collect()
}

// ============================================================================
// JMAP リクエスト処理
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct JmapRequest {
    pub using:        Vec<String>,
    pub method_calls: Vec<MethodCall>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MethodCall(pub String, pub serde_json::Value, pub String);

#[derive(Debug, Serialize)]
pub struct JmapResponse {
    pub method_responses: Vec<MethodCall>,
    pub session_state:    String,
}

/// モックサーバー本体。
pub struct MockServer {
    emails: Mutex<Vec<JmapEmail>>,
    state:  Mutex<u64>,
}

impl MockServer {
    /// 新規インスタンスを作成する。
    pub fn new() -> Self {
        Self {
            emails: Mutex::new(fixture_emails()),
            state:  Mutex::new(1),
        }
    }

    /// JMAP リクエストを処理する。
    pub fn handle(&self, req: JmapRequest) -> JmapResponse {
        let mut responses = Vec::new();

        for call in req.method_calls {
            let response = match call.0.as_str() {
                "Email/get"    => self.email_get(&call.1),
                "Email/query"  => self.email_query(&call.1),
                "Email/set"    => self.email_set(&call.1),
                "Mailbox/get"  => self.mailbox_get(&call.1),
                "Core/echo"    => call.1.clone(),
                _ => serde_json::json!({ "error": "method not supported" }),
            };
            // (メソッド名, 結果, リクエスト ID)
            responses.push(MethodCall(format!("{}/result", call.0), response, call.2));
        }

        JmapResponse {
            method_responses: responses,
            session_state:    self.state.lock().unwrap_or_else(|e| e.into_inner()).to_string(),
        }
    }

    fn email_get(&self, args: &serde_json::Value) -> serde_json::Value {
        let ids: Vec<String> = args.get("ids")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let emails = self.emails.lock().unwrap_or_else(|e| e.into_inner());
        let result: Vec<&JmapEmail> = if ids.is_empty() {
            emails.iter().collect()
        } else {
            emails.iter().filter(|e| ids.contains(&e.id)).collect()
        };

        serde_json::json!({
            "list": result,
            "not_found": [],
            "state": *self.state.lock(),
        })
    }

    fn email_query(&self, _args: &serde_json::Value) -> serde_json::Value {
        let emails = self.emails.lock().unwrap_or_else(|e| e.into_inner());
        let ids: Vec<&str> = emails.iter().map(|e| e.id.as_str()).collect();
        serde_json::json!({
            "ids": ids,
            "total": ids.len(),
            "position": 0,
            "state": *self.state.lock().unwrap_or_else(|e| e.into_inner()),
        })
    }

    fn email_set(&self, args: &serde_json::Value) -> serde_json::Value {
        // update / destroy をシミュレート
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let old_state = *state;
        *state += 1;
        serde_json::json!({
            "old_state": old_state.to_string(),
            "new_state": state.to_string(),
            "updated": args.get("update").cloned().unwrap_or(serde_json::Value::Null),
            "destroyed": args.get("destroy").cloned().unwrap_or(serde_json::Value::Null),
        })
    }

    fn mailbox_get(&self, _args: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "list": [
                { "id": "inbox",   "name": "受信トレイ", "role": "inbox", "total_emails": 5, "unread_emails": 3 },
                { "id": "sent",    "name": "送信済み",   "role": "sent",  "total_emails": 0, "unread_emails": 0 },
                { "id": "trash",   "name": "ゴミ箱",     "role": "trash", "total_emails": 0, "unread_emails": 0 },
                { "id": "archive", "name": "アーカイブ", "role": "archive", "total_emails": 0, "unread_emails": 0 },
            ],
            "state": *self.state.lock(),
        })
    }

    /// 新しいメール (BEC 攻撃) を注入する (E2E テスト用)。
    pub fn inject_email(&self, email: JmapEmail) {
        self.emails.lock().unwrap_or_else(|e| e.into_inner()).push(email);
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) += 1;
    }

    /// メール数を返す。
    #[must_use]
    pub fn email_count(&self) -> usize {
        self.emails.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for MockServer {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_has_diverse_emails() {
        let emails = fixture_emails();
        assert_eq!(emails.len(), 5, "5 通のフィクスチャがある");

        // 各カテゴリ存在確認
        assert!(emails.iter().any(|e| e.subject.as_deref() == Some("Q2予算会議のご案内")));
        // BEC
        assert!(emails.iter().any(|e| e.from.iter().any(|a| a.email.contains("arnazon"))));
        // ニュースレター
        assert!(emails.iter().any(|e| e.from.iter().any(|a| a.email.contains("newsletter"))));
        // 領収書
        assert!(emails.iter().any(|e| e.from.iter().any(|a| a.email.contains("no-reply"))));
    }

    #[test]
    fn email_query_returns_all() {
        let server = MockServer::new();
        let req = JmapRequest {
            using: vec![],
            method_calls: vec![MethodCall(
                "Email/query".into(),
                serde_json::json!({}),
                "0".into(),
            )],
        };
        let resp = server.handle(req);
        assert_eq!(resp.method_responses.len(), 1);
        let total = resp.method_responses[0].1.get("total").and_then(|v| v.as_u64()).unwrap();
        assert_eq!(total, 5);
    }

    #[test]
    fn email_get_by_id() {
        let server = MockServer::new();
        let req = JmapRequest {
            using: vec![],
            method_calls: vec![MethodCall(
                "Email/get".into(),
                serde_json::json!({ "ids": ["fix-002"] }),
                "0".into(),
            )],
        };
        let resp = server.handle(req);
        let list = resp.method_responses[0].1.get("list").and_then(|v| v.as_array()).unwrap();
        assert_eq!(list.len(), 1);
        // BEC メール
        assert!(list[0].get("subject").unwrap().as_str().unwrap().contains("至急"));
    }

    #[test]
    fn mailbox_list_includes_standard_folders() {
        let server = MockServer::new();
        let req = JmapRequest {
            using: vec![],
            method_calls: vec![MethodCall(
                "Mailbox/get".into(),
                serde_json::json!({}),
                "0".into(),
            )],
        };
        let resp = server.handle(req);
        let list = resp.method_responses[0].1.get("list").and_then(|v| v.as_array()).unwrap();
        let names: Vec<&str> = list.iter().filter_map(|m| m.get("role").and_then(|r| r.as_str())).collect();
        assert!(names.contains(&"inbox"));
        assert!(names.contains(&"sent"));
        assert!(names.contains(&"trash"));
    }

    #[test]
    fn email_set_increments_state() {
        let server = MockServer::new();
        let initial_state = *server.state.lock().unwrap_or_else(|e| e.into_inner());

        let req = JmapRequest {
            using: vec![],
            method_calls: vec![MethodCall(
                "Email/set".into(),
                serde_json::json!({ "update": {} }),
                "0".into(),
            )],
        };
        server.handle(req);
        assert!(*server.state.lock().unwrap_or_else(|e| e.into_inner()) > initial_state, "state がインクリメントされるべき");
    }

    #[test]
    fn inject_email_increases_count() {
        let server = MockServer::new();
        assert_eq!(server.email_count(), 5);

        let new_email = JmapEmail {
            id: "injected-1".into(),
            mailbox_ids: hm(&[("inbox", true)]),
            keywords: hm(&[]),
            from: vec![EmailAddress { name: None, email: "test@example.com".into() }],
            to: vec![],
            subject: Some("注入されたテストメール".into()),
            received_at: "2026-04-27T12:00:00Z".into(),
            preview: "test".into(),
            body_values: hm_body(&[]),
        };
        server.inject_email(new_email);
        assert_eq!(server.email_count(), 6);
    }
}
