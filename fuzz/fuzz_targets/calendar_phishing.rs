// fuzz/fuzz_targets/calendar_phishing.rs
//
// カレンダー招待 (.ics) 検査器のファジングターゲット
//
// 目的:
//   - 任意のバイト列を CalendarGuard::analyze に食わせてパニック検出
//   - risk_level と risks 一覧の整合性 (リスクゼロなのに警戒レベルが
//     上がる、またはリスク有りで Safe、の両方向を監視)
//
// 実行:
//   cargo +nightly fuzz run calendar_phishing
//
// シード: fuzz/corpus/calendar_phishing/ (正当 ICS / フィッシング ICS)

#![no_main]

use kaname_render::calendar_guard::{CalendarGuard, CalendarRiskLevel};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let ics = String::from_utf8_lossy(data);
    let scan = CalendarGuard.analyze(&ics);

    // リスク一覧が空なら Safe であるべき (根拠の無い警戒は誤検知)。
    if scan.risks.is_empty() {
        assert_eq!(
            scan.risk_level,
            CalendarRiskLevel::Safe,
            "リスクが無いのに警戒レベルが上昇"
        );
    }
    // Danger 以上なら検出済みリスクがあるべき (無言の Danger 不可)。
    if scan.risk_level == CalendarRiskLevel::Danger {
        assert!(!scan.risks.is_empty(), "根拠の無い Danger 判定");
    }
});
