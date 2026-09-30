// fuzz/fuzz_targets/ssa_bypass.rs
//
// 送信者文体認証 (kaname-ssa) のファジングターゲット
//
// 目的:
//   - 任意の本文・時刻で EmailStyleFeatures::extract がパニックしないこと
//   - extract の出力が is_finite() 契約を守ること (NaN/Infinity は
//     プロファイルを汚染するため呼び出し側が取り込み拒否する前提)
//   - extract した特徴量をプロファイルへ取り込み → assess での
//     パニック検出 (文体バイパス攻撃入力への堅牢性)
//
// 実行:
//   cargo +nightly fuzz run ssa_bypass
//
// シード: fuzz/corpus/ssa_bypass/ (AI生成フォーマル文・通常同僚文)

#![no_main]

use kaname_ssa::{EmailStyleFeatures, SenderStyleProfile, assess_self_send_anomaly};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 先頭バイトを送信時刻 (そのまま渡し extract 内の %24 正規化を試す)、
    // 残りを本文として解釈する。
    let (hour, body) = match data.split_first() {
        Some((h, rest)) => (*h, String::from_utf8_lossy(rest)),
        None => (0, String::from_utf8_lossy(data)),
    };

    let features = EmailStyleFeatures::extract(&body, hour);
    // send_hour は常に 0-23 に正規化される契約。
    assert!(features.send_hour <= 23);

    // 有限性は呼び出し側が is_finite() で検査する前提。
    // ここでは「有限なら評価経路がパニックしない」ことを保証する。
    if features.is_finite() {
        let mut profile = SenderStyleProfile::new("fuzz@example.test");
        // 複数回取り込んでプロファイルを「信頼済み」にしてから評価。
        profile.update(&features);
        profile.update(&features);
        let _ = assess_self_send_anomaly(&profile, &features, data.len() % 2 == 0);
    }
});
