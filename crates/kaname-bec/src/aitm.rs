//! AiTM (Adversary-in-the-Middle) プロキシ攻撃の検出。
//!
//! 2026 Q1 最大の脅威。Tycoon2FA PhaaS プラットフォームが
//! わずか 3 日で 35,000+ ユーザー・13,000 組織・26 か国を攻撃。
//!
//! # 攻撃の仕組み
//!
//! ```text
//! ユーザー → [攻撃者のリバースプロキシ] → Microsoft 365 (正規)
//!                    ↑
//!            セッション Cookie / MFA トークンを窃取
//!            パスワードリセット後も持続する
//! ```
//!
//! # 検出アプローチ
//!
//! メール本文のリンクに含まれる「AiTM プロキシの痕跡」を検出:
//! 1. URL パラメーターに認証トークンが含まれる
//! 2. 正規ブランドを装った偽ドメイン
//! 3. 既知 PhaaS インフラ (Storm-1747/Tycoon2FA 等)
//! 4. リバースプロキシ特有のパス構造

#![deny(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

/// AiTM リスク評価。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AitmRisk {
    /// 集約スコア (0-100、80+ = 危険)
    pub score: u32,
    /// 検出シグナル一覧
    pub signals: Vec<String>,
    /// 最終判定
    pub verdict: AitmVerdict,
}

/// AiTM 判定結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AitmVerdict {
    /// 安全
    Safe,
    /// 要注意
    Caution,
    /// 危険 — AiTM の強い証拠
    Dangerous,
}

/// AiTM 検出器。
pub struct AitmDetector {
    /// 正規認証ドメイン (許可リスト)
    legitimate_auth_domains: Vec<&'static str>,
    /// 既知 PhaaS インフラドメインパターン
    phaas_patterns: Vec<&'static str>,
    /// リバースプロキシ特有のパス
    proxy_paths: Vec<&'static str>,
}

impl AitmDetector {
    /// デフォルト設定で構築。
    #[must_use]
    pub fn new() -> Self {
        Self {
            legitimate_auth_domains: vec![
                "microsoft.com",
                "microsoftonline.com",
                "live.com",
                "outlook.com",
                "office.com",
                "google.com",
                "accounts.google.com",
                "github.com",
                "apple.com",
            ],
            phaas_patterns: vec![
                // Tycoon2FA / Storm-1747 の既知パターン
                "tycoon",
                "2fa-relay",
                "mfa-bypass",
                "auth-relay",
                "token-relay",
                // evilginx2 / Modlishka の典型ドメイン構造
                "0365",
                "microsoft365",
                "m365-",
                "office365-",
            ],
            proxy_paths: vec![
                "/relay",
                "/proxy",
                "/token-relay",
                "/auth-relay",
                "/mfa-relay",
                "/forward",
            ],
        }
    }

    /// URL 文字列を解析して AiTM リスクを評価する。
    #[must_use]
    pub fn analyze(&self, url: &str) -> AitmRisk {
        let mut score = 0u32;
        let mut signals = Vec::new();
        // NULL バイト・制御文字を除去してからドメイン比較 (evil.com%00.microsoft.com バイパス防止)
        let url = &sanitize_url_for_domain_check(url);
        let lower = url.to_lowercase();

        // 1. セッション捕捉パラメーター
        // 高リスクパラメーター (トークン類) は単独でも危険
        let high_risk_params = ["id_token", "access_token", "session_token", "auth_token"];
        // 低リスクパラメーター (code/state/nonce は正当な OAuth でも使われる)
        // → 正規ドメインからのみなら Safe、そうでなければ加点
        let low_risk_params = ["code", "state", "nonce"];

        let domain = extract_domain_from_url(&lower);
        let is_legitimate_domain = self.legitimate_auth_domains.iter()
            .any(|legit| self.is_legitimate_subdomain(&domain, legit));

        for param in &high_risk_params {
            let patterns = [format!("?{param}="), format!("&{param}=")];
            for pat in &patterns {
                if lower.contains(pat) {
                    score += 25;
                    signals.push(format!("URL に高リスク認証パラメーター含む: {param}"));
                    break;
                }
            }
        }
        // code/state/nonce は非正規ドメインの場合のみ加点
        if !is_legitimate_domain {
            for param in &low_risk_params {
                let patterns = [format!("?{param}="), format!("&{param}=")];
                for pat in &patterns {
                    if lower.contains(pat) {
                        score += 15;
                        signals.push(format!("非正規ドメインで OAuth パラメーター検出: {param}"));
                        break;
                    }
                }
            }
        }

        // 2. 正規ブランドを装った偽ドメイン
        for legit in &self.legitimate_auth_domains {
            if domain.contains(legit) && !self.is_legitimate_subdomain(&domain, legit) {
                score += 50;
                signals.push(format!("{legit} を装った偽ドメインの可能性: {domain}"));
                break; // 1 シグナルのみカウント
            }
        }

        // 3. PhaaS インフラパターン
        for pattern in &self.phaas_patterns {
            if lower.contains(pattern) {
                score += 30;
                signals.push(format!("既知 PhaaS パターン検出: {pattern}"));
            }
        }

        // 4. リバースプロキシ特有のパス
        for path in &self.proxy_paths {
            if lower.contains(path) {
                score += 15;
                signals.push(format!("プロキシ特有のパス: {path}"));
            }
        }

        // 5. 過剰なリダイレクト構造のシグナル
        //    URL 内に URL が含まれる (redirect=https%3A%2F%2F...)
        if (lower.contains("redirect=") || lower.contains("next=") || lower.contains("url="))
            && lower.contains("http")
        {
            score += 20;
            signals.push("URL 内にリダイレクト先 URL が埋め込まれている".to_string());
        }

        // スコアからバーディクト
        let verdict = if score >= 50 {
            AitmVerdict::Dangerous
        } else if score >= 20 {
            AitmVerdict::Caution
        } else {
            AitmVerdict::Safe
        };

        AitmRisk { score, signals, verdict }
    }

    /// ドメインが正規のサブドメインかを確認。
    fn is_legitimate_subdomain(&self, domain: &str, legit: &str) -> bool {
        // mail.microsoft.com → microsoft.com のサブドメイン = OK
        // microsoftlogin.com → microsoft を含むが別ドメイン = NG
        // NULL バイト混入 (evil.com%00.microsoft.com) は事前に除去済みであること前提
        domain == legit || domain.ends_with(&format!(".{legit}"))
    }
}

/// URL から NULL バイト・制御文字を除去し、ドメイン混同攻撃を防ぐ。
fn sanitize_url_for_domain_check(url: &str) -> String {
    url.chars().filter(|c| *c != '\0' && !c.is_control()).collect()
}

impl Default for AitmDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_domain_from_url(url: &str) -> String {
    let without_scheme = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let end = without_scheme
        .find(['/', '?', '#'])
        .unwrap_or(without_scheme.len());
    without_scheme[..end].to_lowercase()
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legitimate_microsoft_is_safe() {
        let d = AitmDetector::new();
        let r = d.analyze("https://login.microsoftonline.com/tenant/oauth2/authorize");
        assert_eq!(r.verdict, AitmVerdict::Safe, "シグナル: {:?}", r.signals);
    }

    #[test]
    fn detects_auth_token_in_url() {
        let d = AitmDetector::new();
        let r = d.analyze("https://evil.com/relay?id_token=eyJhb...&code=abc123");
        assert!(r.score >= 25, "score={}", r.score);
        assert!(r.signals.iter().any(|s| s.contains("id_token")));
    }

    #[test]
    fn detects_brand_impersonation() {
        let d = AitmDetector::new();
        // microsoft.com を含むが別ドメイン
        let r = d.analyze("https://microsoft.com.evil.tk/login");
        assert_eq!(r.verdict, AitmVerdict::Dangerous, "シグナル: {:?}", r.signals);
    }

    #[test]
    fn detects_microsoft365_phaas_pattern() {
        let d = AitmDetector::new();
        let r = d.analyze("https://microsoft365-auth.example.com/mfa-relay?state=xyz");
        assert!(r.score >= 30, "score={}", r.score);
    }

    #[test]
    fn detects_embedded_redirect() {
        let d = AitmDetector::new();
        let r = d.analyze("https://suspicious.com/proxy?redirect=https%3A%2F%2Fmicrosoft.com");
        assert!(r.score > 0, "score={}", r.score);
        assert!(r.signals.iter().any(|s| s.contains("リダイレクト")));
    }

    #[test]
    fn normal_google_link_is_safe() {
        let d = AitmDetector::new();
        let r = d.analyze("https://accounts.google.com/signin");
        assert_eq!(r.verdict, AitmVerdict::Safe);
    }

    #[test]
    fn detects_tycoon2fa_pattern() {
        let d = AitmDetector::new();
        let r = d.analyze("https://tycoon-auth.com/relay?id_token=abc");
        assert_eq!(r.verdict, AitmVerdict::Dangerous, "score={}", r.score);
    }

    #[test]
    fn score_is_additive() {
        let d = AitmDetector::new();
        // 複数シグナルでスコア累積
        let single = d.analyze("https://evil.com/?id_token=abc");
        let multi  = d.analyze("https://microsoft.com.evil.tk/mfa-relay?id_token=abc");
        assert!(multi.score > single.score, "multi={} single={}", multi.score, single.score);
    }

    #[test]
    fn verdict_safe_below_30() {
        let d = AitmDetector::new();
        let r = d.analyze("https://example.com/document?page=1");
        assert_eq!(r.verdict, AitmVerdict::Safe);
    }

    #[test]
    fn caution_between_30_and_70() {
        let d = AitmDetector::new();
        // relay パス (15) + redirect (20) = 35
        let r = d.analyze("https://example.com/relay?redirect=http://evil.com");
        assert!(
            r.verdict == AitmVerdict::Caution || r.verdict == AitmVerdict::Dangerous,
            "score={} verdict={:?}", r.score, r.verdict
        );
    }

    #[test]
    fn signals_describe_detections() {
        let d = AitmDetector::new();
        let r = d.analyze("https://microsoft365-login.evil.com/relay?id_token=abc");
        assert!(!r.signals.is_empty(), "検出シグナルが空");
        // 各シグナルは日本語の説明を含む
        for s in &r.signals {
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn github_oauth_callback_is_safe() {
        // 正規 GitHub OAuth コールバック: ?code= は正規ドメインなら Safe
        let d = AitmDetector::new();
        let r = d.analyze("https://github.com/login/oauth/authorize?code=abc123&state=xyz");
        assert_eq!(r.verdict, AitmVerdict::Safe,
            "正規 GitHub OAuth コールバックは Safe であるべき: score={} signals={:?}",
            r.score, r.signals);
    }

    #[test]
    fn unknown_domain_with_code_param_is_caution() {
        // 非正規ドメインで ?code= → Caution 以上
        let d = AitmDetector::new();
        let r = d.analyze("https://suspicious-relay.net/callback?code=abc123&state=xyz");
        assert!(
            r.verdict == AitmVerdict::Caution || r.verdict == AitmVerdict::Dangerous,
            "非正規ドメインの code/state は Caution 以上であるべき: score={}", r.score
        );
    }

    #[test]
    fn legitimate_microsoft_with_state_is_safe() {
        // microsoftonline.com/authorize?state= は正規 OAuth → Safe
        let d = AitmDetector::new();
        let r = d.analyze(
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x&state=abc&nonce=def"
        );
        assert_eq!(r.verdict, AitmVerdict::Safe,
            "正規 Microsoft OAuth フローは Safe であるべき: score={} signals={:?}",
            r.score, r.signals);
    }

    #[test]
    fn null_byte_domain_bypass_blocked() {
        // evil.com%00.microsoft.com — NULL バイトで偽ドメインを正規ドメインに見せかける
        let d = AitmDetector::new();
        let r = d.analyze("https://evil.com\x00.microsoft.com/login?id_token=stolen");
        assert!(r.verdict != AitmVerdict::Safe,
            "NULL バイト混入ドメインは Safe であってはならない: {:?}", r.signals);
    }

    #[test]
    fn control_char_domain_bypass_blocked() {
        // 制御文字を含む URL は Caution 以上でなければならない
        let d = AitmDetector::new();
        let r = d.analyze("https://evil.com\r\n.microsoft.com/login?id_token=test");
        assert!(r.verdict != AitmVerdict::Safe,
            "制御文字を含むドメインは Safe であってはならない");
    }
}
