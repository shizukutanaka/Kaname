// fuzz/fuzz_targets/aitm_urls.rs
//
// AiTM (Adversary-in-the-Middle) URL 検出器のファジングターゲット
//
// 目的:
//   - 任意の URL 文字列でパニックしないこと
//   - AitmRisk.score がドキュメント契約 0-100 に収まること
//     (修正前は加算スコアが無上限で、高リスクパラメータ多重 +
//      PhaaS パターンの入力で 100 を超えていた — D102)
//
// 実行:
//   cargo +nightly fuzz run aitm_urls
//
// シード: fuzz/corpus/aitm_urls/ (Storm-1747 / Tycoon2FA 等の実観測キット)

#![no_main]

use kaname_bec::aitm::{AitmDetector, AitmVerdict};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let url = String::from_utf8_lossy(data);
    let risk = AitmDetector::new().analyze(&url);

    // スコアは契約上 0-100。
    assert!(risk.score <= 100, "score が契約上限を超過: {}", risk.score);

    // バーディクトはスコアの単調関数であること (実装: >=50 Dangerous,
    // >=20 Caution)。判定とスコアの不整合は契約違反。
    match risk.verdict {
        AitmVerdict::Dangerous => assert!(risk.score >= 50),
        AitmVerdict::Caution => assert!((20..50).contains(&risk.score)),
        AitmVerdict::Safe => assert!(risk.score < 20),
    }

    // シグナルが無いのに Caution/Dangerous になってはいけない
    // (根拠の無い警戒は誤検知)。
    if risk.signals.is_empty() {
        assert_eq!(risk.verdict, AitmVerdict::Safe);
    }
});
