//! kaname-billing — Stripe ライセンス検証層。
//!
//! - Webhook の HMAC-SHA256 署名検証
//! - エンタイトルメント (有効/無効、プラン、有効期限)
//! - ローカルキャッシュ (オフライン時の継続動作)

// crates/kaname-billing/src/lib.rs
//
// Stripe webhook handler + entitlement ledger.
//
// Architecture (from the billing playbook):
//   - Single consolidated webhook endpoint (16-endpoint hard limit)
//   - HMAC-SHA256 signature verification before any deserialization
//   - Redis dedup on event.id with 72h TTL (covers 3-day Stripe retry window)
//   - Per-resource version vectors to handle out-of-order delivery
//   - Entitlements persisted to kaname-store; Stripe is source-of-truth for money
//   - All mutations append to the billing ledger (hash chain, same design as audit_log)
//
// Tier mapping (Stripe → Kaname feature flags):
//   individual   → free tier, no seat billing
//   starter      → seats, MLS E2E, sandbox attachments
//   business     → starter + SSO + DLP basic + SCIM
//   pro          → business + DLP advanced + advanced admin + custom retention
//   enterprise   → pro + on-prem option + ISMAP-LIU compliance artefacts
//   government   → outside Stripe (NetSuite track)

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Stripe tier → entitlement mapping
// ============================================================================

/// Stripe Price lookup_keys からマップされた Kaname サブスクリプション層。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Individual,
    Starter,
    Business,
    Pro,
    Enterprise,
}

impl Tier {
    /// Stripe Price lookup_key からパース。
    #[must_use]
    pub fn from_lookup_key(key: &str) -> Option<Self> {
        match key {
            "kaname_individual_monthly" | "kaname_individual_annual" => Some(Self::Individual),
            "kaname_starter_monthly"   | "kaname_starter_annual"    => Some(Self::Starter),
            "kaname_business_monthly"  | "kaname_business_annual"   => Some(Self::Business),
            "kaname_pro_monthly"       | "kaname_pro_annual"        => Some(Self::Pro),
            "kaname_enterprise_monthly"| "kaname_enterprise_annual" => Some(Self::Enterprise),
            _ => None,
        }
    }

    /// 月額シート価格 (JPY) (used for display/validation only).
    #[must_use]
    pub fn monthly_jpy(self) -> u32 {
        match self {
            Self::Individual => 500,
            Self::Starter    => 800,
            Self::Business   => 1_200,
            Self::Pro        => 2_400,
            Self::Enterprise => 3_500,
        }
    }
}

/// 各層の機能フラグ。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlements {
    pub tier:                  Tier,
    pub seat_limit:            Option<u32>,   // None = unlimited (Enterprise)
    pub mls_e2e:               bool,
    pub attachment_sandbox:    bool,
    pub bec_detection:         bool,
    pub local_ai:              bool,
    pub dlp_basic:             bool,
    pub dlp_advanced:          bool,
    pub sso_saml_oidc:         bool,
    pub scim_provisioning:     bool,
    pub admin_dashboard:       bool,
    pub custom_retention_days: Option<u32>,   // None = default 90 days
    pub audit_log_export:      bool,
    pub on_prem_option:        bool,
    pub ismap_artefacts:       bool,
    pub priority_support:      bool,
}

impl Entitlements {
    /// 層のエンタイトルメントセットを構築。
    pub fn for_tier(tier: Tier, seat_count: u32) -> Self {
        let seat_limit = match tier {
            Tier::Individual => Some(1),
            Tier::Starter    => Some(seat_count.max(10)),
            Tier::Business   => Some(seat_count.max(50)),
            Tier::Pro        => Some(seat_count.max(500)),
            Tier::Enterprise => None,
        };

        Self {
            tier,
            seat_limit,
            mls_e2e:              tier != Tier::Individual,
            attachment_sandbox:   true,
            bec_detection:        true,
            local_ai:             true,
            dlp_basic:            matches!(tier, Tier::Business | Tier::Pro | Tier::Enterprise),
            dlp_advanced:         matches!(tier, Tier::Pro | Tier::Enterprise),
            sso_saml_oidc:        matches!(tier, Tier::Business | Tier::Pro | Tier::Enterprise),
            scim_provisioning:    matches!(tier, Tier::Business | Tier::Pro | Tier::Enterprise),
            admin_dashboard:      tier != Tier::Individual,
            custom_retention_days: match tier {
                Tier::Pro | Tier::Enterprise => Some(365),
                _ => None,
            },
            audit_log_export:     matches!(tier, Tier::Pro | Tier::Enterprise),
            on_prem_option:       tier == Tier::Enterprise,
            ismap_artefacts:      tier == Tier::Enterprise,
            priority_support:     matches!(tier, Tier::Pro | Tier::Enterprise),
        }
    }
}

// ============================================================================
// Webhook handler
// ============================================================================

/// Stripe webhook 署名の許容タイムウィンドウ (seconds).
const STRIPE_TIMESTAMP_TOLERANCE_SECS: u64 = 300; // 5 minutes

/// Verify the `Stripe-Signature` header.
///
/// フォーマット: `t=<unix_ts>,v1=<hmac_hex>`
/// 検証: HMAC-SHA256(webhook_secret, "<ts>.<raw_body>")
pub fn verify_signature(
    stripe_signature: &str,
    raw_body: &[u8],
    webhook_secret: &str,
    now_unix: u64,
) -> Result<(), BillingError> {
    let parts: std::collections::HashMap<&str, &str> = stripe_signature
        .split(',')
        .filter_map(|s| s.split_once('='))
        .collect();

    let ts_str = parts.get("t").ok_or(BillingError::MissingTimestamp)?;
    let v1     = parts.get("v1").ok_or(BillingError::MissingSignature)?;

    let ts: u64 = ts_str.parse().map_err(|_| BillingError::InvalidTimestamp)?;

    // Replay protection: reject if timestamp is outside tolerance window
    let age = now_unix.saturating_sub(ts);
    if age > STRIPE_TIMESTAMP_TOLERANCE_SECS {
        return Err(BillingError::SignatureExpired { age_secs: age });
    }

    // Compute expected HMAC
    let signed_payload = format!("{}.{}", ts_str, String::from_utf8_lossy(raw_body));
    let expected = hmac_sha256_hex(webhook_secret.as_bytes(), signed_payload.as_bytes());

    if !constant_time_eq(expected.as_bytes(), v1.as_bytes()) {
        return Err(BillingError::SignatureMismatch);
    }

    Ok(())
}

// ============================================================================
// Event deserialization
// ============================================================================

/// 最小限の Stripe イベント構造。アクションするものだけをデシリアライズ。
#[derive(Debug, Deserialize)]
pub struct StripeEvent {
    pub id:      String,
    #[serde(rename = "type")]
    pub kind:    String,
    pub created: u64,
    pub data:    StripeEventData,
}

#[derive(Debug, Deserialize)]
pub struct StripeEventData {
    pub object: serde_json::Value,
}

// ============================================================================
// Idempotency key store (in-process; production uses Redis SET NX)
// ============================================================================

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// In-memory dedup store. Production: Redis with 72h TTL.
#[derive(Clone, Default)]
pub struct DeduplicatorInMem {
    seen: Arc<Mutex<HashSet<String>>>,
}

impl DeduplicatorInMem {
    /// イベントが未処理の場合 true を返す (and records it).
    #[must_use]
    pub fn try_process(&self, event_id: &str) -> bool {
        let mut set = self.seen.lock().unwrap_or_default();
        set.insert(event_id.to_owned())
    }
}

// ============================================================================
// Event router
// ============================================================================

/// 課金ハンドラーがシステムの残りに実行を要求できるアクション。
#[derive(Debug)]
pub enum BillingAction {
    /// Provision or update a tenant's entitlements.
    UpsertEntitlements {
        tenant_id:    String,
        customer_id:  String,
        entitlements: Entitlements,
    },
    /// Suspend a tenant (payment failed or subscription cancelled).
    SuspendTenant {
        tenant_id:   String,
        customer_id: String,
        reason:      SuspensionReason,
    },
    /// Reinstate a previously suspended tenant.
    ReinstaTenant {
        tenant_id:   String,
        customer_id: String,
    },
    /// Invoice created — record for revenue recognition.
    RecordInvoice {
        tenant_id:   String,
        invoice_id:  String,
        amount_jpy:  i64,
        period_start: u64,
        period_end:   u64,
        status:      String,
    },
    /// A seat was added or removed mid-cycle.
    UpdateSeatCount {
        tenant_id:  String,
        new_seats:  u32,
        delta:      i32,
    },
    /// Unknown or irrelevant event — log and acknowledge.
    Noop { event_type: String },
}

#[derive(Debug)]
pub enum SuspensionReason {
    PaymentFailed { attempt: u32 },
    SubscriptionCancelled,
    InvoiceOverdue { days: u32 },
}

/// Stripe イベントを `BillingAction` にルーティング。
///
/// The caller:
///   1. Verifies the Stripe signature (verify_signature)
///   2. Deduplicates on event.id (DeduplicatorInMem or Redis)
///   3. Calls this function
///   4. Applies the returned BillingAction to the system
///   5. Appends a BilledgeLedgerEntry (below)
///   6. Returns HTTP 200 to Stripe
pub fn route_event(event: &StripeEvent) -> Result<BillingAction, BillingError> {
    // スナップショットを信頼するのではなく Stripe API から実際のオブジェクトを取得。
    // (課金プレイブック: 変更イベントには thin events + 新鮮な API フェッチを使用。)
    // スタブではライブ API がないためペイロードから処理。

    let obj = &event.data.object;

    match event.kind.as_str() {
        // ── Subscription lifecycle ──────────────────────────────────────────
        "customer.subscription.created"
        | "customer.subscription.updated" => {
            let customer_id  = str_field(obj, "customer")?;
            let tenant_id    = str_field(obj, &meta_key("tenant_id"))?;
            let status       = str_field(obj, "status")?;
            let seat_count: u32 = obj["items"]["data"][0]["quantity"]
                .as_u64().unwrap_or(1) as u32;
            let lookup_key = obj["items"]["data"][0]["price"]["lookup_key"]
                .as_str().unwrap_or("");
            let tier = Tier::from_lookup_key(lookup_key)
                .unwrap_or(Tier::Starter);

            if matches!(status.as_str(), "active" | "trialing") {
                Ok(BillingAction::UpsertEntitlements {
                    tenant_id,
                    customer_id,
                    entitlements: Entitlements::for_tier(tier, seat_count),
                })
            } else {
                Ok(BillingAction::SuspendTenant {
                    tenant_id,
                    customer_id,
                    reason: SuspensionReason::SubscriptionCancelled,
                })
            }
        }

        "customer.subscription.deleted" => {
            let customer_id = str_field(obj, "customer")?;
            let tenant_id   = str_field(obj, &meta_key("tenant_id"))?;
            Ok(BillingAction::SuspendTenant {
                tenant_id,
                customer_id,
                reason: SuspensionReason::SubscriptionCancelled,
            })
        }

        // ── Invoice / payment ───────────────────────────────────────────────
        "invoice.payment_failed" => {
            let customer_id  = str_field(obj, "customer")?;
            let tenant_id    = str_field(obj, &meta_key("tenant_id"))?;
            let attempt: u32 = obj["attempt_count"].as_u64().unwrap_or(1) as u32;
            // Grace: don't suspend until attempt 4 (Starter/Business) or 1 (Pro+, use human dunning)
            if attempt >= 4 {
                Ok(BillingAction::SuspendTenant {
                    tenant_id, customer_id,
                    reason: SuspensionReason::PaymentFailed { attempt },
                })
            } else {
                Ok(BillingAction::Noop { event_type: event.kind.clone() })
            }
        }

        "invoice.payment_succeeded" => {
            let customer_id  = str_field(obj, "customer")?;
            let tenant_id    = str_field(obj, &meta_key("tenant_id"))?;
            let invoice_id   = str_field(obj, "id")?;
            let amount_jpy   = obj["amount_paid"].as_i64().unwrap_or(0);
            let period_start = obj["period_start"].as_u64().unwrap_or(0);
            let period_end   = obj["period_end"].as_u64().unwrap_or(0);
            let status       = str_field(obj, "status").unwrap_or("paid".into());

            let _ = (customer_id, tenant_id.clone());
            Ok(BillingAction::RecordInvoice {
                tenant_id,
                invoice_id,
                amount_jpy,
                period_start,
                period_end,
                status,
            })
        }

        "invoice.marked_uncollectible" => {
            let customer_id = str_field(obj, "customer")?;
            let tenant_id   = str_field(obj, &meta_key("tenant_id"))?;
            Ok(BillingAction::SuspendTenant {
                tenant_id, customer_id,
                reason: SuspensionReason::InvoiceOverdue { days: 60 },
            })
        }

        // ── Seat changes ────────────────────────────────────────────────────
        "subscription_items.updated" => {
            let tenant_id  = str_field(obj, &meta_key("tenant_id"))?;
            let new_seats  = obj["quantity"].as_u64().unwrap_or(1) as u32;
            Ok(BillingAction::UpdateSeatCount {
                tenant_id, new_seats, delta: 0, // caller computes delta from current
            })
        }

        // ── Reinstate after payment recovery ───────────────────────────────
        "customer.subscription.resumed" => {
            let customer_id = str_field(obj, "customer")?;
            let tenant_id   = str_field(obj, &meta_key("tenant_id"))?;
            Ok(BillingAction::ReinstaTenant { tenant_id, customer_id })
        }

        _ => Ok(BillingAction::Noop { event_type: event.kind.clone() }),
    }
}

fn meta_key(k: &str) -> String {
    format!("metadata.{}", k)
}

fn str_field(obj: &serde_json::Value, path: &str) -> Result<String, BillingError> {
    let mut cur = obj;
    for part in path.split('.') {
        cur = &cur[part];
    }
    cur.as_str()
        .map(str::to_owned)
        .ok_or_else(|| BillingError::MissingField(path.to_owned()))
}

// ============================================================================
// Billing ledger (hash chain — same design as audit_log in kaname-store)
// ============================================================================

/// 改ざん防止課金台帳のエントリ。
#[derive(Debug, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub seq:            u64,
    pub tenant_id:      String,
    pub event_type:     String,
    pub event_id:       String,
    pub action_json:    String,
    pub prev_hash:      String,
    pub hash:           String,
    pub created_at:     String,
}

/// 新しい台帳エントリを計算。
///
/// hash = SHA-256(prev_hash || event_id || event_type || action_json)
pub fn make_ledger_entry(
    seq:         u64,
    tenant_id:   &str,
    event_type:  &str,
    event_id:    &str,
    action_json: &str,
    prev_hash:   &str,
) -> LedgerEntry {
    let input = format!("{}{}{}{}", prev_hash, event_id, event_type, action_json);
    let hash = sha256_hex(input.as_bytes());
    LedgerEntry {
        seq,
        tenant_id: tenant_id.to_owned(),
        event_type: event_type.to_owned(),
        event_id: event_id.to_owned(),
        action_json: action_json.to_owned(),
        prev_hash: prev_hash.to_owned(),
        hash,
        created_at: chrono_now_iso(),
    }
}

// ============================================================================
// Dunning tiers (per billing playbook §5)
// ============================================================================

/// 層ごとのダニング設定。
pub struct DunningPolicy {
    /// Tiers where Stripe Smart Retries handle recovery (no human intervention).
    pub auto_retry_tiers: &'static [Tier],
    /// After how many failed attempts to suspend.
    pub suspend_after_attempts: u32,
    /// After how many days of delinquency to mark uncollectible.
    pub uncollectible_after_days: u32,
    /// Tiers where AR team handles dunning (no automated email).
    pub human_dunning_tiers: &'static [Tier],
}

impl Default for DunningPolicy {
    fn default() -> Self {
        Self {
            auto_retry_tiers:         &[Tier::Individual, Tier::Starter, Tier::Business],
            suspend_after_attempts:   4,
            uncollectible_after_days: 60,
            human_dunning_tiers:      &[Tier::Pro, Tier::Enterprise],
        }
    }
}

// ============================================================================
// プレースホルダー crypto (production uses ring + blake3)
// ============================================================================

fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    // スタブ — real code uses ring::hmac
    let _ = (key, msg);
    "deadbeef".repeat(8)
}

fn sha256_hex(data: &[u8]) -> String {
    // スタブ — real code uses ring::digest
    let _ = data;
    "cafebabe".repeat(8)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn chrono_now_iso() -> String {
    // スタブ — real code uses chrono::Utc::now().to_rfc3339()
    "2026-04-24T00:00:00Z".to_owned()
}

// ============================================================================
// エラー
// ============================================================================

#[derive(Debug, Error)]
pub enum BillingError {
    #[error("missing Stripe-Signature timestamp")]
    MissingTimestamp,

    #[error("missing v1 signature")]
    MissingSignature,

    #[error("invalid timestamp")]
    InvalidTimestamp,

    #[error("signature expired: {age_secs}s > tolerance")]
    SignatureExpired { age_secs: u64 },

    #[error("signature mismatch")]
    SignatureMismatch,

    #[error("missing field in event object: {0}")]
    MissingField(String),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_lookup_keys_parse() {
        assert_eq!(Tier::from_lookup_key("kaname_starter_monthly"), Some(Tier::Starter));
        assert_eq!(Tier::from_lookup_key("kaname_enterprise_annual"), Some(Tier::Enterprise));
        assert_eq!(Tier::from_lookup_key("unknown_key"), None);
    }

    #[test]
    fn entitlements_individual_one_seat() {
        let e = Entitlements::for_tier(Tier::Individual, 1);
        assert_eq!(e.seat_limit, Some(1));
        assert!(!e.mls_e2e);
        assert!(!e.dlp_basic);
        assert!(!e.sso_saml_oidc);
    }

    #[test]
    fn entitlements_enterprise_unlimited_seats() {
        let e = Entitlements::for_tier(Tier::Enterprise, 10000);
        assert_eq!(e.seat_limit, None);
        assert!(e.on_prem_option);
        assert!(e.ismap_artefacts);
        assert!(e.dlp_advanced);
        assert!(e.audit_log_export);
    }

    #[test]
    fn entitlements_business_has_scim_no_onprem() {
        let e = Entitlements::for_tier(Tier::Business, 100);
        assert!(e.scim_provisioning);
        assert!(e.sso_saml_oidc);
        assert!(!e.on_prem_option);
        assert!(!e.dlp_advanced);
    }

    #[test]
    fn deduplicator_rejects_seen_event() {
        let ded = DeduplicatorInMem::default();
        assert!(ded.try_process("evt_123"));
        assert!(!ded.try_process("evt_123")); // duplicate
        assert!(ded.try_process("evt_456")); // new
    }

    #[test]
    fn signature_expired_is_rejected() {
        let result = verify_signature(
            "t=1000,v1=somesig",
            b"{}",
            "whsec_test",
            1000 + STRIPE_TIMESTAMP_TOLERANCE_SECS + 1,
        );
        assert!(matches!(result, Err(BillingError::SignatureExpired { .. })));
    }

    #[test]
    fn ledger_hash_chain_is_deterministic() {
        let e1 = make_ledger_entry(1, "tenant_1", "subscription.created", "evt_A", "{}", "");
        let e2 = make_ledger_entry(2, "tenant_1", "invoice.paid",         "evt_B", "{}", &e1.hash);
        assert_ne!(e1.hash, e2.hash);
        assert_eq!(e2.prev_hash, e1.hash);
    }

    #[test]
    fn constant_time_eq_is_length_sensitive() {
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
    }
}
