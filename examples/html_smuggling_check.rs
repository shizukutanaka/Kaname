//! HTML スマグリング検出のデモとテスト

fn main() {
    println!("=== HTML スマグリング検出デモ ===\n");

    let samples = [
        ("<html><body><p>安全なメール</p></body></html>", "safe"),
        ("<script>eval(atob('aGVsbG8='));</script>", "base64+eval"),
        ("<script>var u = URL.createObjectURL(blob);</script>", "blob URI"),
        ("<script>mshta vbscript:close</script>", "shell ref"),
    ];

    for (html, label) in &samples {
        let risk = detect_risk(html);
        println!("  [{label}] → {risk}");
    }

    println!("\n✓ 検出デモ完了");
}

fn detect_risk(html: &str) -> &'static str {
    let lower = html.to_lowercase();
    if lower.contains("mshta") || lower.contains("powershell") { return "Critical"; }
    let blob = lower.contains("url.createobjecturl") || lower.contains("blob:");
    let b64_eval = lower.contains("atob(") && lower.contains("eval(");
    let auto_dl = lower.contains("createelement") && lower.contains(".click()");
    if (blob && auto_dl) || b64_eval { return "High"; }
    if blob { return "Caution"; }
    "Clean"
}

#[cfg(test)]
mod tests {
    use super::detect_risk;

    #[test]
    fn clean_html_is_clean() {
        assert_eq!(detect_risk("<p>Hello</p>"), "Clean");
    }

    #[test]
    fn shell_reference_is_critical() {
        assert_eq!(detect_risk("<script>mshta vbscript:close</script>"), "Critical");
    }

    #[test]
    fn powershell_is_critical() {
        assert_eq!(detect_risk("powershell -enc abc"), "Critical");
    }

    #[test]
    fn base64_eval_is_high() {
        assert_eq!(detect_risk("atob('x'); eval(x);"), "High");
    }

    #[test]
    fn blob_only_is_caution() {
        assert_eq!(detect_risk("URL.createObjectURL(b)"), "Caution");
    }

    #[test]
    fn empty_is_clean() {
        assert_eq!(detect_risk(""), "Clean");
    }
}
