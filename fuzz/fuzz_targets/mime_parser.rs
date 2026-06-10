// fuzz/fuzz_targets/mime_parser.rs
//
// MIME パーサーのファジングターゲット
//
// 目的:
//   - 任意のバイト列を MIME パーサーに食わせてクラッシュを検出
//   - メモリ安全性の保証 (Rust の所有権モデルでも parser ロジックの誤りは捕捉可能)
//   - 攻撃メールに対する堅牢性 (実環境で観測される malformed MIME)
//
// 実行:
//   cargo +nightly fuzz run mime_parser
//   cargo +nightly fuzz run mime_parser -- -max_total_time=300  # 5分間
//
// CI 統合: fuzz/Cargo.toml で workspace から exclude し、別ジョブで実行

#![no_main]

use libfuzzer_sys::fuzz_target;
use kaname_render::mime;

fuzz_target!(|data: &[u8]| {
    // パニックしないことを保証
    // どんな入力でも以下のいずれかで終わるべき:
    //   1. 正常にパース成功
    //   2. parse error (Result::Err) を返す
    //   3. マルチパートの再帰深度制限に達する (DoS 防止)
    let _ = mime::parse_message(data);
});

// 派生ファジング: 既知の攻撃パターンをシード
//
// fuzz/corpus/mime_parser/ にシードを配置:
//   - boundary_attack.eml      (境界文字列の攻撃)
//   - infinite_recursion.eml   (無限ネスト multipart)
//   - oversized_header.eml     (16MB のヘッダー)
//   - utf16_subject.eml        (BOM 付き UTF-16 件名)
//   - mixed_encoding.eml       (Quoted-Printable + Base64 混在)
//   - rfc2047_overflow.eml     (=?charset?B?...?=) でバッファオーバーラン狙い
//
// libFuzzer がシードを変異させて新しいクラッシュケースを発見する。
