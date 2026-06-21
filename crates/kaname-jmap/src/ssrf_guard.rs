//! SSRF 防止 — DNS 解決後 IP ブロック (Qiita kawabe0201 / Zenn k41531 由来)。
//!
//! ホスト名のみのブロックでは DNS リバインディングで突破されるため、
//! DNS 解決後の IP アドレスを直接検証する。

use std::net::IpAddr;
use thiserror::Error;

/// SSRF ガードエラー。
#[derive(Debug, Error)]
pub enum SsrfError {
    /// URL の解析に失敗した。
    #[error("URL パース失敗: {0}")]
    InvalidUrl(String),

    /// ホスト名の DNS 解決に失敗した。
    #[error("DNS 解決失敗: {0}")]
    DnsResolutionFailed(String),

    /// 解決された IP がプライベート/ループバック/リンクローカルアドレス。
    #[error("SSRF ブロック: {url} → {ip} はプライベートアドレス")]
    PrivateAddress {
        /// 検査対象 URL。
        url: String,
        /// 解決された IP アドレス。
        ip: String,
    },

    /// HTTPS 以外のスキームは禁止。
    #[error("SSRF ブロック: HTTPS 以外のスキーム: {scheme}")]
    NonHttpsScheme {
        /// 使用されたスキーム。
        scheme: String,
    },
}

/// URL が SSRF のリスクを持つかを検証する。
///
/// # 検証手順
///
/// 1. `https://` スキームのみ許可
/// 2. ホスト名を DNS 解決 (複数 IP がある場合は全て検査)
/// 3. ループバック (`127.x.x.x`, `::1`) を拒否
/// 4. リンクローカル (`169.254.x.x`, `fe80::`) を拒否
/// 5. プライベートアドレス (`10.x`, `172.16-31.x`, `192.168.x`) を拒否
/// 6. IPv6 ユニークローカル (`fc00::/7`) を拒否
///
/// # 注意
///
/// DNS リバインディング (TOCTOU) 対策として、解決後のアドレスを検証するが、
/// 実際の接続は reqwest が行うため、解決と接続の間にタイムウィンドウが存在する。
/// 完全な防御には connect socket hook (OS レベル) が必要。
pub async fn check_url_for_ssrf(url: &str) -> Result<(), SsrfError> {
    // スキームチェック
    if !url.starts_with("https://") {
        let scheme = url.split("://").next().unwrap_or("unknown");
        return Err(SsrfError::NonHttpsScheme { scheme: scheme.to_string() });
    }

    let host = extract_host(url).ok_or_else(|| SsrfError::InvalidUrl(url.to_string()))?;

    // 数値 IP が直接指定された場合
    if let Ok(ip) = host.parse::<IpAddr>() {
        return check_ip(&ip, url);
    }

    // DNS 解決
    let addr_str = format!("{host}:443");
    let addrs: Vec<IpAddr> = tokio::net::lookup_host(&addr_str)
        .await
        .map_err(|e| SsrfError::DnsResolutionFailed(e.to_string()))?
        .map(|a| a.ip())
        .collect();

    if addrs.is_empty() {
        return Err(SsrfError::DnsResolutionFailed(format!("{host} → アドレスなし")));
    }

    for ip in &addrs {
        check_ip(ip, url)?;
    }

    Ok(())
}

/// 解決された IP が安全かを確認する。
fn check_ip(ip: &IpAddr, url: &str) -> Result<(), SsrfError> {
    if is_private_ip(ip) {
        return Err(SsrfError::PrivateAddress {
            url: url.to_string(),
            ip: ip.to_string(),
        });
    }
    Ok(())
}

/// IP がプライベート/ループバック/リンクローカル/ユニークローカルかを判定する。
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // ループバック: 127.0.0.0/8
            if octets[0] == 127 {
                return true;
            }
            // リンクローカル: 169.254.0.0/16
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            // プライベート: 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // プライベート: 172.16.0.0/12
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // プライベート: 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // IANA 予約: 0.0.0.0/8
            if octets[0] == 0 {
                return true;
            }
            // ブロードキャスト: 255.255.255.255
            if *v4 == std::net::Ipv4Addr::BROADCAST {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            // ループバック: ::1
            if v6.is_loopback() {
                return true;
            }
            // ユニークローカル: fc00::/7 (fc00:: と fd00::)
            let segments = v6.segments();
            if segments[0] & 0xfe00 == 0xfc00 {
                return true;
            }
            // リンクローカル: fe80::/10
            if segments[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            // IPv4-mapped: ::ffff:10.x.x.x 等 (IPv4 プライベートを IPv6 経由で迂回)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ip(&IpAddr::V4(v4));
            }
            false
        }
    }
}

/// URL からホスト名を抽出する (スキーム・ポート・パスを除去)。
fn extract_host(url: &str) -> Option<&str> {
    // "https://host:port/path" → "host"
    let after_scheme = url.strip_prefix("https://")?;
    let host_and_rest = after_scheme.split('/').next()?;
    // ポートを除去
    let host = host_and_rest.split(':').next()?;
    // IPv6 リテラル [::1] の処理
    if host.starts_with('[') {
        after_scheme.split('/').next()
            .and_then(|h| h.strip_prefix('['))
            .and_then(|h| h.split(']').next())
    } else {
        Some(host)
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn loopback_v4_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn link_local_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1));
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn private_10_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn private_172_16_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn private_172_31_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255));
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn private_172_15_is_public() {
        // 172.15.x.x は /12 範囲外なので公開アドレス
        let ip = IpAddr::V4(Ipv4Addr::new(172, 15, 0, 1));
        assert!(!is_private_ip(&ip));
    }

    #[test]
    fn private_192_168_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn public_ip_is_allowed() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!is_private_ip(&ip));
    }

    #[test]
    fn ipv6_loopback_blocked() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn ipv6_unique_local_blocked() {
        // fd00::/8 はユニークローカル
        let ip = IpAddr::V6("fd00::1".parse().unwrap());
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn ipv6_link_local_blocked() {
        let ip = IpAddr::V6("fe80::1".parse().unwrap());
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn http_scheme_rejected() {
        // extract_host は https:// のみ対応するため http:// は None
        assert!(extract_host("http://example.com").is_none());
    }

    #[test]
    fn host_extraction() {
        assert_eq!(extract_host("https://example.com/path"), Some("example.com"));
        assert_eq!(extract_host("https://example.com:8443/path"), Some("example.com"));
        assert_eq!(extract_host("https://example.com"), Some("example.com"));
        assert_eq!(extract_host("http://example.com"), None);
    }

    #[test]
    fn ipv6_mapped_v4_private_blocked() {
        // ::ffff:10.0.0.1 は IPv4-mapped で 10.x.x.x → ブロック
        let ip = IpAddr::V6("::ffff:10.0.0.1".parse().unwrap());
        assert!(is_private_ip(&ip));
    }
}
