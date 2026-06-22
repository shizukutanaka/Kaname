//! SSRF 防止 — DNS 解決後 IP ブロック (Qiita kawabe0201 / Zenn k41531 由来)。
//!
//! ホスト名のみのブロックでは DNS リバインディングで突破されるため、
//! DNS 解決後の IP アドレスを直接検証する。

use std::net::IpAddr;
use thiserror::Error;

/// リダイレクト最大ホップ数。
pub const MAX_REDIRECT_HOPS: usize = 3;

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

    // 難読化 IP 表記を拒否 (16進/8進/10進 integer 表記)
    // 例: 0x7f000001, 2130706433, 0177.0.0.1
    // Rust の標準パーサーは通常形式のみ受け付けるが、明示的に拒否しておく。
    if is_obfuscated_ip(host) {
        return Err(SsrfError::InvalidUrl(format!("難読化 IP 表記: {host}")));
    }

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
            // マルチキャスト: 224.0.0.0/4
            if octets[0] >= 224 && octets[0] <= 239 {
                return true;
            }
            // 予約済み: 240.0.0.0/4 (RFC 1112)
            if octets[0] >= 240 {
                return true;
            }
            // ドキュメント用 TEST-NET: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
            if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            {
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
            // 未指定アドレス: :: (0.0.0.0 に相当)
            if v6.is_unspecified() {
                return true;
            }
            // IPv4-mapped: ::ffff:10.x.x.x 等 (IPv4 プライベートを IPv6 経由で迂回)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ip(&IpAddr::V4(v4));
            }
            // IPv6 マルチキャスト: ff00::/8
            if segments[0] & 0xff00 == 0xff00 {
                return true;
            }
            // NAT64: 64:ff9b::/96 (RFC 6052) — IPv4 プライベートへのトンネル
            if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0 && segments[3] == 0 && segments[4] == 0 {
                let v4 = std::net::Ipv4Addr::new(
                    (segments[6] >> 8) as u8,
                    segments[6] as u8,
                    (segments[7] >> 8) as u8,
                    segments[7] as u8,
                );
                return is_private_ip(&IpAddr::V4(v4));
            }
            false
        }
    }
}

/// SSRF-safe な reqwest リダイレクトポリシーを返す。
///
/// 各リダイレクト先の IP アドレスを検証し、プライベートアドレスへの誘導を防ぐ。
/// ホップ数は [`MAX_REDIRECT_HOPS`] に制限。
///
/// # 使い方
///
/// ```no_run
/// let client = reqwest::Client::builder()
///     .redirect(kaname_jmap::ssrf_guard::safe_redirect_policy())
///     .build()
///     .unwrap();
/// ```
#[must_use]
pub fn safe_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        // ホップ数制限
        if attempt.previous().len() >= MAX_REDIRECT_HOPS {
            return attempt.stop();
        }

        let url = attempt.url();

        // HTTPS のみ許可
        if url.scheme() != "https" {
            return attempt.stop();
        }

        // IP リテラルの場合は即時検証
        if let Some(host) = url.host_str() {
            // 難読化 IP を拒否
            if is_obfuscated_ip(host) {
                return attempt.stop();
            }

            if let Ok(ip) = host.parse::<IpAddr>() {
                if is_private_ip(&ip) {
                    return attempt.stop();
                }
            }
        } else {
            // ホスト名がない URL は不正
            return attempt.stop();
        }

        // DNS 解決後の検証は非同期のため行えないが、
        // 最終的な接続はコネクター層の SSRF ガードが担保する。
        attempt.follow()
    })
}

/// 難読化 IP 表記かどうかを検出する。
///
/// 以下の形式を検出:
/// - 16進整数: `0x7f000001`
/// - 10進整数: `2130706433` (127.0.0.1 の 32bit 表現)
/// - 8進オクテット: `0177.0.0.1`
fn is_obfuscated_ip(host: &str) -> bool {
    // 16進表記: 0x で始まる
    if host.to_ascii_lowercase().starts_with("0x") {
        return true;
    }
    // オクテット表記で先頭が 0 (8進): "0177.0.0.1"
    if host.starts_with('0') && host.contains('.') {
        return true;
    }
    // 純粋な 10 進整数 (ドットなし、数字のみ) — IPv4 の 32bit 表現
    if host.bytes().all(|b| b.is_ascii_digit()) && !host.is_empty() {
        return true;
    }
    false
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

    #[test]
    fn ipv6_unspecified_blocked() {
        // :: は未指定アドレス → ブロック
        let ip = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn nat64_private_blocked() {
        // 64:ff9b::10.0.0.1 (NAT64) → 10.0.0.1 → ブロック
        let ip: IpAddr = "64:ff9b::a00:1".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn nat64_loopback_blocked() {
        // 64:ff9b::127.0.0.1 (NAT64) → ループバック → ブロック
        let ip: IpAddr = "64:ff9b::7f00:1".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn nat64_public_allowed() {
        // 64:ff9b::8.8.8.8 (NAT64 → 8.8.8.8) は公開 → 許可
        let ip: IpAddr = "64:ff9b::808:808".parse().unwrap();
        assert!(!is_private_ip(&ip));
    }

    #[test]
    fn obfuscated_hex_ip_rejected() {
        assert!(is_obfuscated_ip("0x7f000001"));
    }

    #[test]
    fn obfuscated_decimal_integer_ip_rejected() {
        // 2130706433 = 0x7F000001 = 127.0.0.1
        assert!(is_obfuscated_ip("2130706433"));
    }

    #[test]
    fn obfuscated_octal_ip_rejected() {
        // 0177.0.0.1 = 127.0.0.1 in octal first octet
        assert!(is_obfuscated_ip("0177.0.0.1"));
    }

    #[test]
    fn normal_ip_not_obfuscated() {
        assert!(!is_obfuscated_ip("127.0.0.1"));
        assert!(!is_obfuscated_ip("192.168.1.1"));
        assert!(!is_obfuscated_ip("8.8.8.8"));
    }

    #[test]
    fn hostname_not_obfuscated() {
        assert!(!is_obfuscated_ip("example.com"));
        assert!(!is_obfuscated_ip("localhost"));
    }

    #[test]
    fn hex_uppercase_obfuscated() {
        assert!(is_obfuscated_ip("0X7F000001"));
    }

    #[test]
    fn multicast_ipv4_blocked() {
        // 224.0.0.0/4 — マルチキャスト
        let ip: IpAddr = "224.0.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));
        let ip: IpAddr = "239.255.255.255".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn reserved_ipv4_blocked() {
        // 240.0.0.0/4 — 予約済み (RFC 1112)
        let ip: IpAddr = "240.0.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));
        let ip: IpAddr = "255.255.255.254".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_net_ipv4_blocked() {
        // ドキュメント用 TEST-NET (RFC 5737)
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(is_private_ip(&ip));
        let ip: IpAddr = "198.51.100.42".parse().unwrap();
        assert!(is_private_ip(&ip));
        let ip: IpAddr = "203.0.113.99".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn multicast_ipv6_blocked() {
        // ff02::1 — リンクローカルマルチキャスト
        let ip: IpAddr = "ff02::1".parse().unwrap();
        assert!(is_private_ip(&ip));
    }
}
